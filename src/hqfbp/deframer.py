import gzip
import lzma
import brotli
import cbor2
import io
import re
import traceback
from collections import deque
from typing import Dict, Any, Tuple, Optional, List, Union, Deque

from hqfbp import (
    unpack, 
    merge_headers, 
    HQFBP_CBOR_KEYS, 
    verify_and_strip_crc,
    ENCODING_REGISTRY,
    COAP_CONTENT_FORMATS,
    RS_RE,
    rs_decode,
    RQ_RE,
    rq_decode,
    CONV_RE,
    conv_decode,
    SCR_RE,
    scr_xor,
    CHUNK_RE,
    REPEAT_RE
)

class PDUEvent:
    def __init__(self, header: Dict[int, Any], payload: bytes):
        self.header = header
        self.payload = payload

    def __repr__(self):
        return f"PDUEvent(header={self.header}, payload_len={len(self.payload)})"

class MessageEvent:
    def __init__(self, header: Dict[int, Any], payload: bytes):
        self.header = header
        self.payload = payload

    def __repr__(self):
        return f"MessageEvent(header={self.header}, payload_len={len(self.payload)})"

class Deframer:
    """
    Sans-I/O Deframer for HQFBP.
    Handles PDU reception, multi-sender reassembly, and announcement-based decoding.
    Supports Hybrid ARQ (Best-of-N) and Stack-Aware Reassembly.
    """

    def __init__(self):
        self._events: Deque[Union[PDUEvent, MessageEvent]] = deque()
        # Mapping (src_callsign, original_msg_id) -> {chunk_id: (payload, quality), 'headers': [header1, ...]}
        self._sessions: Dict[Tuple[Optional[str], int], Dict[str, Any]] = {}
        # Mapping (src_callsign, upcoming_msg_id) -> encodings
        self._announcements: Dict[Tuple[Optional[str], int], List[Union[int, str]]] = {}
        self._not_yet_decoded_pdus: List[bytes] = []

    def receive_bytes(self, data: bytes):
        """Accept raw PDU bytes and process them into events."""
        # 1. Try to peek into the header to get src/msg_id
        try:
            peek_header, _ = unpack(data)
            header_unpacked_directly = True
        except Exception:
            header_unpacked_directly = False

        header = None
        payload = None
        encodings = None
        src_callsign = None
        msg_id = None
        pdu_quality = 0
        
        if header_unpacked_directly and isinstance(peek_header, dict):
            src_callsign = peek_header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
            msg_id = peek_header.get(HQFBP_CBOR_KEYS["Message-Id"])
            msg_id = peek_header.get(HQFBP_CBOR_KEYS["Original-Message-Id"], msg_id)
            if msg_id is not None:
                encodings = self._announcements.get((src_callsign, msg_id))
                if encodings:
                    try:
                        data, pdu_quality = self._strip_post_boundary_encodings(data, encodings)
                        header, payload = unpack(data)
                        # CRITICAL: Re-extract identifiers after recovery!
                        src_callsign = header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
                        msg_id = header.get(HQFBP_CBOR_KEYS["Message-Id"])
                        msg_id = header.get(HQFBP_CBOR_KEYS["Original-Message-Id"], msg_id)
                    except Exception:
                        return # Inconsistent
                else:
                    encodings = peek_header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
                    header, payload = peek_header, _
                    if encodings:
                        try:
                            # Strip post-boundary encodings from the FULL data
                            data, pdu_quality = self._strip_post_boundary_encodings(data, encodings)
                            header, payload = unpack(data)
                            # CRITICAL: Re-extract identifiers after recovery!
                            src_callsign = header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
                            msg_id = header.get(HQFBP_CBOR_KEYS["Message-Id"])
                            msg_id = header.get(HQFBP_CBOR_KEYS["Original-Message-Id"], msg_id)
                        except Exception:
                            return # Inconsistent
        else:
            # Heuristic: Try announcements
            for announcement_encodings in self._announcements.values():
                if announcement_encodings is not None:
                    if self._raptorq_is_post_boundary(announcement_encodings):
                        try_data = b"".join(self._not_yet_decoded_pdus) + data
                    else:
                        try_data = data
                    try:
                        try_data, try_quality = self._strip_post_boundary_encodings(try_data, announcement_encodings)
                        header, payload = unpack(try_data)
                        src_callsign = header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
                        msg_id = header.get(HQFBP_CBOR_KEYS["Message-Id"])
                        if msg_id is not None:
                            data = try_data
                            encodings = announcement_encodings
                            pdu_quality = try_quality
                            break
                    except Exception:
                        continue

        if header is None or msg_id is None:
            # print(f"DEBUG: Header or Msg-Id missing. Header directly: {header_unpacked_directly}")
            self._not_yet_decoded_pdus.append(data)
            return

        # 4. Handle Announcement
        content_type = header.get(HQFBP_CBOR_KEYS["Content-Type"])
        content_format = header.get(HQFBP_CBOR_KEYS["Content-Format"])
        
        is_announcement = (
            (content_type is not None and content_type == "application/vnd.hqfbp+cbor") or 
            (content_format is not None and content_format == COAP_CONTENT_FORMATS.get("application/vnd.hqfbp+cbor"))
        )

        if is_announcement:
            ann_encs = header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
            if ann_encs:
                payload, quality = self._apply_pre_boundary_decodings(payload, ann_encs)
            
            self._handle_announcement(src_callsign, payload)
            self._events.append(PDUEvent(header, payload))
            return

        self._events.append(PDUEvent(header, payload))

        # 5. Handle Reassembly
        orig_msg_id = header.get(HQFBP_CBOR_KEYS["Original-Message-Id"], msg_id)
        session_key = (src_callsign, orig_msg_id)
        
        total_chunks = header.get(HQFBP_CBOR_KEYS["Total-Chunks"], 1)
        chunk_id = header.get(HQFBP_CBOR_KEYS["Chunk-Id"], 0)
        
        if session_key not in self._sessions:
            self._sessions[session_key] = {
                'chunks': {},
                'headers': [],
                'total_chunks': total_chunks
            }
        
        session = self._sessions[session_key]

        # STACK-AWARE REASSEMBLY:
        # If there are pre-boundary encodings after a chunk()/repeat()/rq marker,
        # they must be applied to each PDU payload before storage.
        pre_encs, _, _ = self._split_encodings(header.get(HQFBP_CBOR_KEYS["Content-Encoding"]))
        if pre_encs:
            # Identify the split point: everything AFTER the last chunk/repeat/rq marker is per-PDU
            last_split_idx = -1
            for i, e in enumerate(pre_encs):
                if isinstance(e, str) and (CHUNK_RE.match(e) or REPEAT_RE.match(e) or RQ_RE.match(e)):
                    last_split_idx = i
            
            # Decodings to apply now (per-PDU) are those after the last split
            per_pdu_encs = pre_encs[last_split_idx + 1 :]
            if per_pdu_encs:
                try:
                    payload, quality_gain = self._apply_decoding_list(payload, per_pdu_encs, pre_boundary=True)
                    pdu_quality += quality_gain
                except Exception:
                    # Don't crash, just proceed with raw payload and 0 quality
                    pdu_quality = 0

        # QUALITY-AWARE STORAGE (Best-of-N)
        existing_pdu = session['chunks'].get(chunk_id)
        if existing_pdu is None or pdu_quality >= existing_pdu[1]:
            session['chunks'][chunk_id] = (payload, pdu_quality)
            session['headers'].append(header)

        # 6. Check for Completion
        completed = False
        if len(session['chunks']) == session['total_chunks']:
            completed = self._complete_message(session_key)
        else:
            rq_info = self._get_rq_info(session['headers'])
            if rq_info:
                import math
                rq_len, mtu, _ = rq_info
                k = math.ceil(rq_len / mtu)
                if len(session['chunks']) >= k:
                    completed = self._complete_message(session_key)
        
        if completed:
            self._announcements.pop((src_callsign, msg_id), None)
            if orig_msg_id != msg_id:
                self._announcements.pop((src_callsign, orig_msg_id), None)

    def next_event(self) -> Optional[Union[PDUEvent, MessageEvent]]:
        """Return the next available event, or None if queue is empty."""
        return self._events.popleft() if self._events else None

    def _handle_announcement(self, src_callsign: Optional[str], payload: bytes):
        """Parse announcement payload and store encoding info."""
        try:
            ann_data = cbor2.loads(payload)
            upcoming_msg_id = ann_data.get(HQFBP_CBOR_KEYS["Message-Id"])
            upcoming_encodings = ann_data.get(HQFBP_CBOR_KEYS["Content-Encoding"])
            if upcoming_msg_id is not None:
                self._announcements[(src_callsign, upcoming_msg_id)] = upcoming_encodings
        except Exception:
            pass

    def _apply_decoding_list(self, data: Union[bytes, List[bytes]], encodings: List[Union[int, str]], pre_boundary: bool) -> Tuple[Union[bytes, List[bytes]], int]:
        """Apply a list of decodings in reverse order (LIFO). Returns (data, quality)."""
        quality = 0
        for enc in reversed(encodings):
            if enc in (1, "gzip"):
                if isinstance(data, list): data = b"".join(data)
                data = gzip.decompress(data)
            elif enc in (3, "br"):
                if isinstance(data, list): data = b"".join(data)
                data = brotli.decompress(data)
            elif enc in (4, "lzma"):
                if isinstance(data, list): data = b"".join(data)
                data = lzma.decompress(data)
            elif enc in (5, 6, "crc16", "crc32"):
                if isinstance(data, list): data = b"".join(data)
                data, success = verify_and_strip_crc(data, enc)
                if success:
                    quality += 1000
            elif isinstance(enc, str):
                if CHUNK_RE.match(enc):
                    continue
                m = RS_RE.match(enc)
                if m:
                    if isinstance(data, list): data = b"".join(data)
                    n, k = map(int, m.groups())
                    data, err_count = rs_decode(data, n, k)
                    num_blocks = len(data) // k
                    max_correctable = ((n - k) // 2) * num_blocks
                    quality += (max_correctable - err_count)
                else:
                    m = RQ_RE.match(enc)
                    if m:
                        rq_len, mtu, _ = map(int, m.groups())
                        if not isinstance(data, list):
                            data = [data[i:i+mtu+4] for i in range(0, len(data), mtu+4)]
                        data = rq_decode(data, rq_len, mtu)
                        quality += 10
                    else:
                        m = CONV_RE.match(enc)
                        if m:
                            k_val, rate = m.groups()
                            if isinstance(data, list): data = b"".join(data)
                            data, metric = conv_decode(data, int(k_val), rate)
                            quality += (len(data) * 8 - metric)
                        else:
                            m = SCR_RE.match(enc)
                            if m:
                                poly = int(m.group(1), 0)
                                if isinstance(data, list): data = b"".join(data)
                                data = scr_xor(data, poly)
        return data, quality

    def _strip_post_boundary_encodings(self, data: bytes, encodings: Union[int, str, List[Union[int, str]]]) -> Tuple[bytes, int]:
        """Strip encodings found after the 'h' boundary. Returns (data, quality)."""
        _, post_encs, _ = self._split_encodings(encodings)
        return self._apply_decoding_list(data, post_encs, pre_boundary=False)

    def _complete_message(self, session_key: Tuple[Optional[str], int]) -> bool:
        """Assemble chunks, merge headers, and dekrunk pre-boundary encodings."""
        session = self._sessions[session_key]
        total_possible = session['total_chunks']
        chunks_with_quality = [session['chunks'].get(i) for i in range(total_possible)]
        chunks = [c[0] if c else None for c in chunks_with_quality]
        
        merged_header = merge_headers(session['headers'])
        encodings = merged_header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
        try:
            available_chunks = [c for c in chunks if c is not None]
            full_payload = available_chunks
            
            pre_encs, _, _ = self._split_encodings(encodings)
            last_split_idx = -1
            for i, e in enumerate(pre_encs):
                if isinstance(e, str) and (CHUNK_RE.match(e) or REPEAT_RE.match(e) or RQ_RE.match(e)):
                    last_split_idx = i
            
            # Message-level encodings are those INCLUDING the last split point and everything before it
            # except that rq and chunk are handled by the reassembly logic or in decoding list.
            # Actually, the decoding list handles rq and chunk gracefully.
            if last_split_idx != -1:
                message_level_encs = pre_encs[:last_split_idx + 1]
            else:
                # If no split marker, but we HAVE multiple chunks, it might be a single PDU message
                # or a bug. But if there's no split marker, ALL pre_encs are potentially per-PDU.
                # HOWEVER, if we are in _complete_message, we want to apply any remaining pre_encs
                # that were NOT applied in receive_bytes.
                # In our tiered logic, receive_bytes applies pre_encs[last_split_idx+1:].
                # So here we apply pre_encs[:last_split_idx+1].
                # If last_split_idx is -1, then pre_encs[:0] is empty. Correct.
                message_level_encs = []
            if message_level_encs:
                full_payload, _ = self._apply_decoding_list(full_payload, message_level_encs, pre_boundary=True)
            
            if isinstance(full_payload, list):
                full_payload = b"".join(full_payload)
            
            file_size = merged_header.get(HQFBP_CBOR_KEYS["File-Size"])
            if file_size is not None:
                full_payload = full_payload[:file_size]

            # Strip reassembly markers and boundary from final header
            ce_key = HQFBP_CBOR_KEYS["Content-Encoding"]
            if ce_key in merged_header:
                ce = merged_header[ce_key]
                if isinstance(ce, list):
                    new_ce = []
                    for e in ce:
                        if e in (-1, "h"): continue
                        if isinstance(e, str) and (CHUNK_RE.match(e) or REPEAT_RE.match(e)): continue
                        new_ce.append(e)
                    if not new_ce: del merged_header[ce_key]
                    elif len(new_ce) == 1: merged_header[ce_key] = new_ce[0]
                    else: merged_header[ce_key] = new_ce
                elif ce in (-1, "h") or (isinstance(ce, str) and (CHUNK_RE.match(ce) or REPEAT_RE.match(ce))):
                    del merged_header[ce_key]

            self._events.append(MessageEvent(merged_header, full_payload))
            self._sessions.pop(session_key)
            return True
        except Exception:
            return False

    def _split_encodings(self, encodings: Union[int, str, List[Union[int, str]]]) -> Tuple[List[Union[int, str]], List[Union[int, str]], bool]:
        """Split encodings into (pre_boundary, post_boundary, has_boundary)."""
        if encodings is None:
            return [], [], False
        encs = encodings if isinstance(encodings, list) else [encodings]
        for i, e in enumerate(encs):
            if e in (-1, "h"):
                return encs[:i], encs[i+1:], True
        return encs, [], False

    def _apply_pre_boundary_decodings(self, data: List[bytes], encodings: Union[int, str, List[Union[int, str]]]) -> Tuple[List[bytes], int]:
        """Legacy wrapper for pre-boundary decodings."""
        pre_encs, _, _ = self._split_encodings(encodings)
        return self._apply_decoding_list(data, pre_encs, pre_boundary=True)

    def _get_rq_info(self, headers: List[Dict[int, Any]]) -> Optional[Tuple[int, int, int]]:
        """Extract RaptorQ parameters from headers."""
        for h in headers:
            ce = h.get(HQFBP_CBOR_KEYS["Content-Encoding"])
            if not ce: continue
            encs = ce if isinstance(ce, list) else [ce]
            for enc in encs:
                if isinstance(enc, str):
                    m = RQ_RE.match(enc)
                    if m: return tuple(map(int, m.groups()))
        return None

    def _raptorq_is_post_boundary(self, encodings: Union[int, str, List[Union[int, str]]]) -> bool:
        """Return True if encodings contains RaptorQ after the boundary marker."""
        _, post_encs, _ = self._split_encodings(encodings)
        for enc in post_encs:
            if isinstance(enc, str) and RQ_RE.match(enc): return True
        return False
