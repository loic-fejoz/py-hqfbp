try:
    import gzip
except ImportError:
    gzip = None
try:
    import lzma
except ImportError:
    lzma = None
try:
    import brotli
except ImportError:
    brotli = None
import cbor2
from collections import deque
from typing import Dict, Any, Tuple, Optional, List, Union, Deque

from hqfbp import (
    unpack,
    merge_headers,
    HQFBP_CBOR_KEYS,
    verify_and_strip_crc,
    COAP_CONTENT_FORMATS,
    RS_RE,
    rs_decode,
    RQ_RE,
    RQ_DYN_RE,
    RQ_DYN_PERC_RE,
    rq_decode,
    LT_RE,
    LT_DYN_RE,
    lt_decode,
    CONV_RE,
    conv_decode,
    SCR_RE,
    scr_xor,
    GOLAY_RE,
    golay_decode,
    CHUNK_RE,
    REPEAT_RE,
    POST_ASM_RE,
    post_asm_decode,
)


class PDUEvent:
    def __init__(self, header: Dict[int, Any], payload: bytes):
        self.header = header
        self.payload = payload

    def __repr__(self):
        return f"PDUEvent(msg_id={self.header.get(0)}, p_len={len(self.payload)})"


class MessageEvent:
    def __init__(self, header: Dict[int, Any], payload: bytes):
        self.header = header
        self.payload = payload

    def __repr__(self):
        return f"MessageEvent(msg_id={self.header.get(0)}, p_len={len(self.payload)})"


class Deframer:
    def __init__(self):
        self._events: Deque[Union[PDUEvent, MessageEvent]] = deque()
        self._sessions: Dict[Tuple[Optional[str], int], Dict[str, Any]] = {}
        self._announcements: Dict[Tuple[Optional[str], int], List[Union[int, str]]] = {}
        self._not_yet_decoded_pdus: List[bytes] = []

    def _is_fragmented(self, header: Dict[int, Any], payload_len: int) -> bool:
        ce = header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
        if not ce:
            return False
        pre, post, has_h = self._split_encodings(ce)
        if not has_h:
            return False
        has_reassembly = any(
            isinstance(e, str) and (CHUNK_RE.match(e) or REPEAT_RE.match(e))
            for e in post
        )
        if has_reassembly:
            expected = header.get(HQFBP_CBOR_KEYS["Payload-Size"])
            if expected is not None:
                return payload_len < expected
        return False

    def _apply_pdu_level_decodings(
        self, header: Dict[int, Any], payload: bytes
    ) -> Tuple[bytes, int]:
        ce = header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
        if not ce:
            return payload, 0
        pre, _, _ = self._split_encodings(ce)
        lsi = -1
        for i, e in enumerate(pre):
            if isinstance(e, str) and (
                CHUNK_RE.match(e)
                or REPEAT_RE.match(e)
                or RQ_RE.match(e)
                or RQ_DYN_RE.match(e)
                or RQ_DYN_PERC_RE.match(e)
                or LT_RE.match(e)
                or LT_DYN_RE.match(e)
                or RS_RE.match(e)
                or GOLAY_RE.match(e)
            ):
                lsi = i
        to_apply = pre[lsi + 1 :] if lsi != -1 else pre
        if to_apply:
            expected_size = header.get(HQFBP_CBOR_KEYS["Payload-Size"])
            data, q = self._apply_decoding_list(payload, to_apply, True, expected_size)
            if expected_size is not None:
                data = data[:expected_size]
            return data, q
        return payload, 0

    def receive_bytes(self, data: bytes):
        header, payload = None, None
        msg_id, src_callsign = None, None
        pdu_quality = 0
        decoded_pdu_level = False

        try:
            h_peek, p_peek = unpack(data)
            src_c = h_peek.get(HQFBP_CBOR_KEYS["Src-Callsign"])
            m_id = h_peek.get(HQFBP_CBOR_KEYS["Message-Id"])
            orig_id = h_peek.get(HQFBP_CBOR_KEYS["Original-Message-Id"], m_id)
            
            # 1a. Determine the encoding list to use
            ce_list = self._announcements.get((src_c, orig_id))
            if ce_list is None:
                ce_list = h_peek.get(HQFBP_CBOR_KEYS["Content-Encoding"])
            
            pre, post, has_h = self._split_encodings(ce_list)
            
            h_final, p_final = h_peek, p_peek
            q_pdu = 0
            
            if has_h and post:
                # Try to strip post-boundary encodings from the whole PDU
                try:
                    stripped, q_pdu = self._strip_post_boundary_encodings(data, ce_list)
                    h_final, p_final = unpack(stripped)
                except Exception:
                    pass
            
            if not self._is_fragmented(h_final, len(p_final)):
                header, payload = h_final, p_final
                payload, q_gain = self._apply_pdu_level_decodings(header, payload)
                pdu_quality = q_pdu + q_gain
                src_callsign, msg_id = (
                    header.get(HQFBP_CBOR_KEYS["Src-Callsign"]),
                    header.get(HQFBP_CBOR_KEYS["Message-Id"]),
                )
                decoded_pdu_level = True
        except Exception:
            pass

        if header is None or msg_id is None:
            for ann_encs in self._announcements.values():
                try_list = [*self._not_yet_decoded_pdus, data]
                try:
                    stripped, q = self._strip_post_boundary_encodings(
                        try_list, ann_encs
                    )
                    h2, p2 = unpack(stripped)
                    if self._is_fragmented(h2, len(p2)):
                        continue
                    p2, q_gain = self._apply_pdu_level_decodings(h2, p2)
                    header, payload, pdu_quality = h2, p2, q + q_gain
                    src_callsign, msg_id = (
                        header.get(HQFBP_CBOR_KEYS["Src-Callsign"]),
                        header.get(HQFBP_CBOR_KEYS["Message-Id"]),
                    )
                    if msg_id is not None:
                        decoded_pdu_level = True
                        break  # Still break the list of announcements if we found one?
                        # Wait, if we matched ONE announcement, we might still want to match others?
                        # In HQFBP, one PDU usually belongs to one message.
                        # But in Phase 2, we might have reassembled ONE chunk.
                        # We should probably keep other PDUs for OTHER chunks.
                except Exception:
                    continue

        if header is None or msg_id is None:
            if data not in self._not_yet_decoded_pdus:
                self._not_yet_decoded_pdus.append(data)
            return

        cont_type = header.get(HQFBP_CBOR_KEYS["Content-Type"])
        cont_fmt = header.get(HQFBP_CBOR_KEYS["Content-Format"])
        is_ann = (
            cont_type is not None and cont_type == "application/vnd.hqfbp+cbor"
        ) or (
            cont_fmt is not None
            and cont_fmt == COAP_CONTENT_FORMATS.get("application/vnd.hqfbp+cbor")
        )

        if is_ann:
            a_p = payload
            if not decoded_pdu_level:
                ae = header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
                if ae:
                    a_p, _ = self._apply_decoding_list(
                        a_p, self._split_encodings(ae)[0], True
                    )
            self._handle_announcement(src_callsign, a_p)
            return

        self._events.append(PDUEvent(header, payload))
        orig_id = header.get(HQFBP_CBOR_KEYS["Original-Message-Id"], msg_id)
        session_key = (src_callsign, orig_id)
        if session_key not in self._sessions:
            self._sessions[session_key] = {
                "chunks": {},
                "headers": [],
                "total_chunks": header.get(HQFBP_CBOR_KEYS["Total-Chunks"], 1),
            }
        session = self._sessions[session_key]
        chunk_id = header.get(HQFBP_CBOR_KEYS["Chunk-Id"], 0)
        existing = session["chunks"].get(chunk_id)
        if existing is None or pdu_quality >= existing[1]:
            session["chunks"][chunk_id] = (payload, pdu_quality)
            session["headers"].append(header)

        completed = False
        if len(session["chunks"]) == session["total_chunks"]:
            completed = self._complete_message(session_key)
        else:
            rq = self._get_rq_info(session["headers"])
            if rq and len(session["chunks"]) >= ((rq[0] + rq[1] - 1) // rq[1]):
                completed = self._complete_message(session_key)

        if completed:
            self._announcements.pop((src_callsign, msg_id), None)
            if orig_id != msg_id:
                self._announcements.pop((src_callsign, orig_id), None)

    def next_event(self) -> Optional[Union[PDUEvent, MessageEvent]]:
        return self._events.popleft() if self._events else None

    def rescan_pending(self):
        """Try to process all PDUs that were stored because of missing announcements."""
        to_process = self._not_yet_decoded_pdus
        self._not_yet_decoded_pdus = []
        for data in to_process:
            self.receive_bytes(data)

    def _handle_announcement(self, src_callsign: Optional[str], payload: bytes):
        try:
            ann_data = cbor2.loads(payload)
            tid, tce = (
                ann_data.get(HQFBP_CBOR_KEYS["Message-Id"]),
                ann_data.get(HQFBP_CBOR_KEYS["Content-Encoding"]),
            )
            if tid is not None:
                self._announcements[(src_callsign, tid)] = (
                    tce if isinstance(tce, list) else [tce]
                )
                self.rescan_pending()
        except Exception:
            pass

    def _apply_decoding_list(
        self,
        data: Union[bytes, List[bytes]],
        encodings: List[Union[int, str]],
        pre_boundary: bool,
        expected_size: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        quality = 0
        for enc in reversed(encodings):
            # Combiners (they handle List[bytes] themselves)
            m_rq = RQ_RE.match(enc) if isinstance(enc, str) else None
            m_rq_dyn = RQ_DYN_RE.match(enc) if isinstance(enc, str) else None
            m_rq_dp = RQ_DYN_PERC_RE.match(enc) if isinstance(enc, str) else None
            m_lt = LT_RE.match(enc) if isinstance(enc, str) else None
            m_lt_dyn = LT_DYN_RE.match(enc) if isinstance(enc, str) else None
            m_chunk = CHUNK_RE.match(enc) if isinstance(enc, str) else None
            m_rep = REPEAT_RE.match(enc) if isinstance(enc, str) else None

            if m_rq or m_rq_dyn or m_rq_dp or m_lt or m_lt_dyn or m_chunk or m_rep:
                # These are combiners, they expect List[bytes] or will handle bytes themselves
                if m_rq:
                    rq_len, mtu, _ = map(int, m_rq.groups())
                    if not isinstance(data, list):
                        data = [data[i:i+mtu+4] for i in range(0, len(data), mtu+4)]
                    data = rq_decode(data, rq_len, mtu)
                    quality += 10
                elif m_rq_dyn:
                    mtu, _ = map(int, m_rq_dyn.groups())
                    if not isinstance(data, list):
                        data = [data[i:i+mtu+4] for i in range(0, len(data), mtu+4)]
                    rq_len = expected_size if expected_size is not None else (len(data)*mtu)
                    data = rq_decode(data, rq_len, mtu)
                    quality += 10
                elif m_rq_dp:
                    mtu, percent = map(int, m_rq_dp.groups())
                    if not isinstance(data, list):
                        data = [data[i:i+mtu+4] for i in range(0, len(data), mtu+4)]
                    rq_len = expected_size if expected_size is not None else (len(data)*mtu*100//(100+percent))
                    data = rq_decode(data, rq_len, mtu)
                    quality += 10
                elif m_lt:
                    lt_len, mtu, _ = map(int, m_lt.groups())
                    if not isinstance(data, list):
                        data = [data[i:i+mtu+4] for i in range(0, len(data), mtu+4)]
                    data = lt_decode(data, lt_len, mtu)
                    quality += 10
                elif m_lt_dyn:
                    mtu, _ = map(int, m_lt_dyn.groups())
                    if not isinstance(data, list):
                        data = [data[i:i+mtu+4] for i in range(0, len(data), mtu+4)]
                    lt_len = expected_size if expected_size is not None else (len(data)*mtu)
                    data = lt_decode(data, lt_len, mtu)
                    quality += 10
                elif m_chunk:
                    if isinstance(data, list):
                        data = b"".join(data)
                elif m_rep:
                    count = int(m_rep.group(1))
                    if isinstance(data, list):
                        data = data[::count]
            else:
                # These are PDU-level or stream-level. 
                # If data is a list, map over it.
                if isinstance(data, list):
                    if enc in (1, "gzip", 2, "deflate", 3, "br", 4, "lzma"):
                        # Compression usually applies to the joined stream
                        data = b"".join(data)
                        if enc in (1, "gzip"):
                            data = gzip.decompress(data)
                        elif enc in (3, "br"):
                            data = brotli.decompress(data)
                        elif enc in (4, "lzma"):
                            data = lzma.decompress(data)
                    else:
                        # Map over each segment (RS, CRC, Scrambler, Conv, Golay)
                        next_data = []
                        for segment in data:
                            res, q = self._apply_decoding_list(segment, [enc], pre_boundary, expected_size)
                            next_data.append(res)
                            quality += q
                        data = next_data
                else:
                    # Single bytes case (standard)
                    if enc in (1, "gzip", 2, "deflate", 3, "br", 4, "lzma", 5, 6, "crc16", "crc32"):
                        if enc in (1, "gzip"):
                            data = gzip.decompress(data)
                        elif enc in (3, "br"):
                            data = brotli.decompress(data)
                        elif enc in (4, "lzma"):
                            data = lzma.decompress(data)
                        else:
                            # CRC logic (including sliding window)
                            try:
                                data, ok = verify_and_strip_crc(data, enc)
                                if ok:
                                    quality += 1000
                            except ValueError:
                                # ... sliding window logic ...
                                from hqfbp import crc16_ccitt, crc32 as hq_crc32
                                crc_size = 4 if enc in ("crc32", 6) else 2
                                if len(data) > crc_size:
                                    test_len = len(data) - 1
                                    min_len = max(crc_size, len(data) - 256)
                                    found_vl = None
                                    while test_len >= min_len:
                                        payload = data[:test_len-crc_size]
                                        expected = data[test_len-crc_size:test_len]
                                        actual = hq_crc32(payload) if crc_size == 4 else crc16_ccitt(payload)
                                        if actual == expected:
                                            found_vl = test_len - crc_size
                                            break
                                        test_len -= 1
                                    if found_vl is not None:
                                        data = data[:found_vl]
                                        quality += 1000
                                    else:
                                        raise ValueError("CRC mismatch")
                                else:
                                    raise ValueError("CRC mismatch")
                    else:
                        # Other string-based encodings (RS, Conv, Scrambler, Golay)
                        m_rs = RS_RE.match(enc) if isinstance(enc, str) else None
                        m_conv = CONV_RE.match(enc) if isinstance(enc, str) else None
                        m_scr = SCR_RE.match(enc) if isinstance(enc, str) else None
                        m_golay = GOLAY_RE.match(enc) if isinstance(enc, str) else None
                        
                        if m_rs:
                            n, k = map(int, m_rs.groups())
                            data, errs = rs_decode(data, n, k)
                            quality += (n - k) // 2 - errs
                        elif m_conv:
                            k_v, r = m_conv.groups()
                            data, met = conv_decode(data, int(k_v), r)
                            quality += len(data)*8 - met
                        elif m_scr:
                            groups = m_scr.groups()
                            poly = int(groups[0], 0)
                            seed = int(groups[1], 0) if groups[1] else None
                            data = scr_xor(data, poly, seed)
                        elif m_golay:
                            data, errs = golay_decode(data)
                            quality += errs
                        elif m := POST_ASM_RE.match(enc):
                            sync_word_str = m.group(1)
                            if sync_word_str.startswith("0x"):
                                sync_word = bytes.fromhex(sync_word_str[2:])
                            else:
                                sync_word = int(sync_word_str).to_bytes(
                                    (int(sync_word_str).bit_length() + 7) // 8, "big"
                                )
                            data = post_asm_decode(data, sync_word)
        if isinstance(data, list):
            data = b"".join(data)
        return data, quality

    def _strip_post_boundary_encodings(
        self, data: Union[bytes, List[bytes]], encodings: List[Union[int, str]]
    ) -> Tuple[Union[bytes, List[bytes]], int]:
        _, post, _ = self._split_encodings(encodings)
        return self._apply_decoding_list(data, post, False)

    def _complete_message(self, session_key: Tuple[Optional[str], int]) -> bool:
        session = self._sessions[session_key]
        chunks = [
            session["chunks"].get(i)[0]
            for i in range(session["total_chunks"])
            if session["chunks"].get(i)
        ]
        merged_header = merge_headers(session["headers"])
        full_payload = chunks
        try:
            pre, _, _ = self._split_encodings(
                merged_header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
            )
            lsi = -1
            lsi = -1
            for i, e in enumerate(pre):
                if isinstance(e, str) and (
                    CHUNK_RE.match(e)
                    or REPEAT_RE.match(e)
                    or RQ_RE.match(e)
                    or RQ_DYN_RE.match(e)
                    or RQ_DYN_PERC_RE.match(e)
                    or LT_RE.match(e)
                    or LT_DYN_RE.match(e)
                    or RS_RE.match(e)
                    or GOLAY_RE.match(e)
                ):
                    lsi = i
            msg_encs = pre[: lsi + 1] if lsi != -1 else []
            if msg_encs:
                expected_size = merged_header.get(HQFBP_CBOR_KEYS["File-Size"])
                full_payload, _ = self._apply_decoding_list(
                    full_payload, msg_encs, True, expected_size
                )
            if isinstance(full_payload, list):
                full_payload = b"".join(full_payload)

            # Cleanup final header: remove reassembly markers and 'h'
            ce_key = HQFBP_CBOR_KEYS["Content-Encoding"]
            if ce_key in merged_header:
                cur_ce = merged_header[ce_key]
                cur_list = cur_ce if isinstance(cur_ce, list) else [cur_ce]
                new_ce = []
                for idx, e in enumerate(cur_list):
                    # Skip 'h' and everything up to split point
                    if e in (-1, "h"):
                        continue
                    if lsi != -1 and idx <= lsi:
                        continue
                    new_ce.append(e)
                if not new_ce:
                    del merged_header[ce_key]
                elif len(new_ce) == 1:
                    merged_header[ce_key] = new_ce[0]
                else:
                    merged_header[ce_key] = new_ce

            try:
                h_i, p_i = unpack(full_payload)
                if h_i and h_i.get(HQFBP_CBOR_KEYS["Message-Id"]) is not None:
                    pre_i, _, _ = self._split_encodings(
                        h_i.get(HQFBP_CBOR_KEYS["Content-Encoding"])
                    )
                    if pre_i:
                        ex_sz = h_i.get(HQFBP_CBOR_KEYS["Payload-Size"])
                        p_i, _ = self._apply_decoding_list(p_i, pre_i, True, ex_sz)
                    merged_header, full_payload = h_i, p_i
            except Exception:
                pass
            sz = merged_header.get(HQFBP_CBOR_KEYS["File-Size"])
            if sz is not None:
                full_payload = full_payload[:sz]
            self._events.append(MessageEvent(merged_header, full_payload))
            self._sessions.pop(session_key)
            return True
        except Exception as e:
            import traceback
            traceback.print_exc()
            return False

    def _split_encodings(
        self, encodings: Union[int, str, List[Union[int, str]]]
    ) -> Tuple[List[Union[int, str]], List[Union[int, str]], bool]:
        if encodings is None:
            return [], [], False
        encs = encodings if isinstance(encodings, list) else [encodings]
        for i, e in enumerate(encs):
            if e in (-1, "h"):
                return encs[:i], encs[i + 1 :], True
        return encs, [], False

    def _get_rq_info(
        self, headers: List[Dict[int, Any]]
    ) -> Optional[Tuple[int, int, int]]:
        for h in headers:
            ce = h.get(HQFBP_CBOR_KEYS["Content-Encoding"])
            if ce:
                for e in ce if isinstance(ce, list) else [ce]:
                    if isinstance(e, str):
                        m = RQ_RE.match(e)
                        if m:
                            rq_len, mtu, _ = map(int, m.groups())
                            return rq_len, mtu, 0
                        m = RQ_DYN_RE.match(e)
                        if m:
                            mtu, _ = map(int, m.groups())
                            # For early reassembly, we might need a guess for rq_len if not in header
                            file_size = h.get(HQFBP_CBOR_KEYS["File-Size"])
                            rq_len = file_size if file_size is not None else 0
                            return rq_len, mtu, 0
                        m = RQ_DYN_PERC_RE.match(e)
                        if m:
                            mtu, percent = map(int, m.groups())
                            file_size = h.get(HQFBP_CBOR_KEYS["File-Size"])
                            rq_len = file_size if file_size is not None else 0
                            return rq_len, mtu, 0
                        m = LT_RE.match(e)
                        if m:
                            lt_len, mtu, _ = map(int, m.groups())
                            return lt_len, mtu, 0
                        m = LT_DYN_RE.match(e)
                        if m:
                            mtu, _ = map(int, m.groups())
                            file_size = h.get(HQFBP_CBOR_KEYS["File-Size"])
                            lt_len = file_size if file_size is not None else 0
                            return lt_len, mtu, 0
        return None
