import gzip
import lzma
import brotli
import cbor2
import re
from typing import Dict, Any, Optional, List, Union, Generator, Tuple
from hqfbp import pack, HQFBP_CBOR_KEYS, crc16_ccitt, crc32, RS_RE, rs_encode, RQ_RE, rq_encode, LT_RE, lt_encode, CONV_RE, conv_encode, SCR_RE, scr_xor, CHUNK_RE, REPEAT_RE, _REV_ENCODING_REGISTRY


class PDUGenerator:
    """
    Helper class to generate HQFBP PDUs, supporting common fields and automatic chunking.
    Supports data compression (gzip, br, lzma) and pre/post boundary encodings (crc16, crc32).
    """
    
    def __init__(
        self,
        src_callsign: Optional[str] = None,
        dst_callsign: Optional[str] = None,
        max_payload_size: Optional[int] = None,
        encodings: Optional[Union[str, List[Union[str, int]]]] = None,
        announcement_encodings: Optional[Union[str, List[Union[str, int]]]] = None,
        initial_msg_id: int = 1
    ):
        self.src_callsign = src_callsign
        self.dst_callsign = dst_callsign
        self.max_payload_size = max_payload_size
        self.encodings = encodings
        if announcement_encodings:
            self.announcement_encoder = PDUGenerator(
                src_callsign=src_callsign,
                dst_callsign=dst_callsign,
                max_payload_size=None, # Announcements typically shouldn't be chunked
                encodings=announcement_encodings,
                initial_msg_id=initial_msg_id
            )
        else:
            self.announcement_encoder = None
        self._next_msg_id = initial_msg_id

    def set_callsigns(self, src: Optional[str] = None, dst: Optional[str] = None):
        """Configure source and destination callsigns."""
        if src is not None:
            self.src_callsign = src
        if dst is not None:
            self.dst_callsign = dst

    def set_encodings(self, encodings: Union[str, List[Union[str, int]]]):
        """Configure content encodings."""
        self.encodings = encodings

    def set_max_payload_size(self, size: Optional[int]):
        """Set the maximum payload size for chunking."""
        self.max_payload_size = size

    def _get_next_msg_id(self) -> int:
        msg_id = self._next_msg_id
        self._next_msg_id += 1
        return msg_id

    def _apply_encodings(self, data: bytes, encodings: List[Union[str, int]]) -> Union[bytes, List[bytes]]:
        """Apply a list of encodings to the data."""
        for enc in encodings:
            if enc in (1, "gzip"):
                data = gzip.compress(data)
            elif enc in (3, "br"):
                data = brotli.compress(data)
            elif enc in (4, "lzma"):
                data = lzma.compress(data)
            elif enc in (5, "crc16"):
                data += crc16_ccitt(data)
            elif enc in (6, "crc32"):
                data += crc32(data)
            elif isinstance(enc, str):
                if CHUNK_RE.match(enc):
                    continue # Skip chunk markers here
                m = RS_RE.match(enc)
                if m:
                    n, k = map(int, m.groups())
                    data = rs_encode(data, n, k)
                elif RQ_RE.match(enc):
                    m = RQ_RE.match(enc)
                    rq_len, mtu, repair_count = map(int, m.groups())
                    # RaptorQ is special: it returns a LIST of chunks
                    return rq_encode(data, rq_len, mtu, repair_count)
                elif LT_RE.match(enc):
                    m = LT_RE.match(enc)
                    lt_len, mtu, repair_count = m.groups()
                    return lt_encode(data, int(lt_len), int(mtu), int(repair_count))
                elif CONV_RE.match(enc):
                    m = CONV_RE.match(enc)
                    k_val, rate = m.groups()
                    data = conv_encode(data, int(k_val), rate)
                elif SCR_RE.match(enc):
                    m = SCR_RE.match(enc)
                    poly_str = m.group(1)
                    poly = int(poly_str, 0)
                    data = scr_xor(data, poly)
        return data

    def _parse_encodings(self, val: Union[str, List[Union[str, int]], None]) -> Tuple[List[Union[str, int]], List[Union[str, int]], bool]:
        """Split encodings into (pre, post, has_boundary). Used by tests."""
        if val is None: return [], [], False
        
        raw_list = []
        if isinstance(val, str):
            raw_list = [val]
        else:
            raw_list = list(val)
        
        # Split strings inside the list, respecting parentheses
        encs = []
        for item in raw_list:
            if isinstance(item, str):
                # Manual splitting to handle balanced parentheses
                res = []
                current = []
                depth = 0
                for char in item:
                    if char == '(': depth += 1
                    elif char == ')': depth -= 1
                    if char == ',' and depth == 0:
                        res.append("".join(current).strip())
                        current = []
                    else:
                        current.append(char)
                if current:
                    res.append("".join(current).strip())
                encs.extend(res)
            else:
                encs.append(item)

        # Convert numeric strings to ints if they match registry
        encs = [int(e) if isinstance(e, str) and e.isdigit() else e for e in encs]
        
        for i, e in enumerate(encs):
            if e in (-1, "h"):
                return encs[:i], encs[i+1:], True
        return encs, [], False

    def _resolve_encodings(self) -> List[Union[str, int]]:
        """Unify self.encodings and self.max_payload_size into a single sequence."""
        pre, post, has_boundary = self._parse_encodings(self.encodings)
        encs = pre + ([-1] if has_boundary else []) + post
        
        # Ensure a boundary marker is present
        if not (-1 in encs or "h" in encs):
            encs.append(-1)
        
        # Automatic FEC Alignment: pre-boundary RS or RQ should trigger chunking
        # Find boundary
        try:
            boundary_idx = encs.index(-1)
        except ValueError:
            boundary_idx = encs.index("h")
            
        pre = encs[:boundary_idx]
        has_chunk = any(isinstance(e, str) and CHUNK_RE.match(e) for e in pre)
        
        if not has_chunk:
            for i, e in enumerate(pre):
                if isinstance(e, str):
                    rs_m = RS_RE.match(e)
                    if rs_m:
                        # Insert chunk(k) BEFORE the RS encoding
                        encs.insert(i, f"chunk({rs_m.group(2)})")
                        has_chunk = True
                        break
                    rq_m = RQ_RE.match(e)
                    if rq_m:
                        # RaptorQ handles its own segmentation, no chunk() needed
                        has_chunk = True # Mark as handled to avoid max_payload_size chunking
                        break
        
        if not has_chunk and self.max_payload_size is not None:
            # Find boundary index again in case it shifted
            try:
                b_idx = encs.index(-1)
            except ValueError:
                b_idx = encs.index("h")
            encs.insert(b_idx, f"chunk({self.max_payload_size})")

        return encs

    def _clean_encodings(self, encodings: List[Union[str, int]]) -> List[Union[str, int]]:
        """Convert 'h' to -1 and keep markers."""
        return [_REV_ENCODING_REGISTRY.get(e, e) if e == "h" else e for e in encodings]

    def _parse_split(self, val: List[Union[str, int]]) -> Tuple[List[Union[str, int]], List[Union[str, int]], bool]:
        """Split into pre and post boundary."""
        for i, e in enumerate(val):
            if e in (-1, "h"):
                return val[:i], val[i+1:], True
        return val, [], False

    def generate(self, data: bytes, content_type: Optional[str] = None) -> Generator[bytes, None, None]:
        """
        Generate HQFBP PDUs for the given data using an iterative approach.
        """
        file_size = len(data)
        full_encs = self._resolve_encodings()
        
        current_chunks = [data]
        
        ann_msg_id = None
        data_orig_id = None
        
        if self.announcement_encoder:
            ann_msg_id = self._get_next_msg_id()
        data_orig_id = self._next_msg_id

        header_template = {
            HQFBP_CBOR_KEYS['File-Size']: file_size,
        }
        if self.src_callsign:
            header_template[HQFBP_CBOR_KEYS['Src-Callsign']] = self.src_callsign
        if self.dst_callsign:
            header_template[HQFBP_CBOR_KEYS['Dst-Callsign']] = self.dst_callsign
        if content_type:
            header_template[HQFBP_CBOR_KEYS['Content-Type']] = content_type

        for enc_idx, enc in enumerate(full_encs):
            if enc in (-1, "h"):
                # Boundary marker: Pack everything into PDUs
                total_chunks = len(current_chunks)
                new_chunks = []
                for i, chunk_data in enumerate(current_chunks):
                    header = header_template.copy()
                    
                    # Message-Id management
                    if i == 0:
                        msg_id = data_orig_id
                        if self._next_msg_id == msg_id: self._next_msg_id += 1
                    else:
                        msg_id = self._get_next_msg_id()

                    if total_chunks > 1:
                        header[HQFBP_CBOR_KEYS['Total-Chunks']] = total_chunks
                        header[HQFBP_CBOR_KEYS['Chunk-Id']] = i
                        header[HQFBP_CBOR_KEYS['Original-Message-Id']] = data_orig_id
                    
                    header[HQFBP_CBOR_KEYS['Message-Id']] = msg_id
                    
                    if i > 0 and HQFBP_CBOR_KEYS['Content-Type'] in header:
                        del header[HQFBP_CBOR_KEYS['Content-Type']]
                    
                    # Set Content-Encoding for THIS PDU
                    # It should include EVERYTHING in full_encs
                    header[HQFBP_CBOR_KEYS['Content-Encoding']] = self._clean_encodings(full_encs)
                        
                    new_chunks.append(pack(header, chunk_data))
                current_chunks = new_chunks
            elif isinstance(enc, str) and CHUNK_RE.match(enc):
                m = CHUNK_RE.match(enc)
                size = int(m.group(1))
                new_chunks = []
                for chunk in current_chunks:
                    for j in range(0, len(chunk), size):
                        new_chunks.append(chunk[j : j + size])
                current_chunks = new_chunks
            elif isinstance(enc, str) and REPEAT_RE.match(enc):
                m = REPEAT_RE.match(enc)
                count = int(m.group(1))
                new_chunks = []
                for chunk in current_chunks:
                    for _ in range(count):
                        new_chunks.append(chunk)
                current_chunks = new_chunks
            else:
                # Transformation
                new_chunks = []
                for c in current_chunks:
                    # Update RaptorQ/LT dynamic length if needed
                    if isinstance(enc, str):
                        if enc.startswith("rq(dlen,"):
                            enc = enc.replace("rq(dlen,", "rq(" + str(int(len(c))) + ",")
                            full_encs[enc_idx] = enc
                        elif enc.startswith("lt(dlen,"):
                            enc = enc.replace("lt(dlen,", "lt(" + str(int(len(c))) + ",")
                            full_encs[enc_idx] = enc
                    
                    chunks = self._apply_encodings(c, [enc])
                    if isinstance(chunks, bytes):
                        new_chunks.append(chunks)
                    elif isinstance(chunks, list):
                        new_chunks.extend(chunks)
                    else:
                        raise TypeError(f"Unexpected return type from _apply_encodings: {type(chunks)}")
                current_chunks = new_chunks

        # Yield Announcement if requested
        if self.announcement_encoder:
            self.announcement_encoder._next_msg_id = ann_msg_id
            ann_payload_dict = {
                HQFBP_CBOR_KEYS['Message-Id']: data_orig_id,
            }
            ann_payload_dict[HQFBP_CBOR_KEYS['Content-Encoding']] = self._clean_encodings(full_encs)
            
            for pdu in self.announcement_encoder.generate(
                pack(ann_payload_dict, b""),
                content_type="application/vnd.hqfbp+cbor"
            ):
                yield pdu

        # Yield Data PDUs
        for chunk in current_chunks:
            yield chunk
