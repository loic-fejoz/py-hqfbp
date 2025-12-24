import gzip
import lzma
import brotli
import cbor2
from typing import Dict, Any, Optional, List, Union, Generator, Tuple
from hqfbp import pack, HQFBP_CBOR_KEYS, crc16_ccitt, crc32, RS_RE, rs_encode, RQ_RE, rq_encode
import re

CHUNK_RE = re.compile(r"chunk\((\d+)\)")

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
        announcement_encodings: Optional[Union[str, List[Union[str, int]]]] = None
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
                encodings=announcement_encodings
            )
        else:
            self.announcement_encoder = None
        self._next_msg_id = 1

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

    def _apply_encodings(self, data: bytes, encodings: List[Union[str, int]]) -> bytes:
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
                else:
                    m = RQ_RE.match(enc)
                    if m:
                        mtu, repair_count = map(int, m.groups())
                        data = rq_encode(data, mtu, repair_count)
            # Add other encodings here (deflate, etc.) if needed
        return data

    def _resolve_encodings(self) -> List[Union[str, int]]:
        """
        Unify self.encodings and self.max_payload_size into a single sequence.
        If max_payload_size is set but no chunk() is in encodings, 
        insert chunk(size) right before the 'h' boundary.
        """
        encs = self.encodings if isinstance(self.encodings, list) else ([self.encodings] if self.encodings else [])
        
        # Check if we already have an explicit chunking
        has_chunk = any(isinstance(e, str) and CHUNK_RE.match(e) for e in encs)
        
        if not has_chunk and self.max_payload_size is not None:
            # Find boundary 'h' (-1)
            boundary_idx = -1
            if "h" in encs:
                boundary_idx = encs.index("h")
            elif -1 in encs:
                boundary_idx = encs.index(-1)

            if boundary_idx != -1:
                encs.insert(boundary_idx, f"chunk({self.max_payload_size})")
            else:
                # No boundary, just append it
                encs.append(f"chunk({self.max_payload_size})")
        
        return encs

    def _parse_encodings(self, val: Optional[Union[str, List[Union[str, int]]]]) -> Tuple[List[Union[str, int]], List[Union[str, int]], bool]:
        if not val:
            return [], [], False
        encs = val if isinstance(val, list) else [val]
        for i, e in enumerate(encs):
            if e in (-1, "h"):
                return encs[:i], encs[i+1:], True
        return encs, [], False

    def _split_encodings(self) -> Tuple[List[Union[str, int]], List[Union[str, int]]]:
        """Split encodings into pre-boundary and post-boundary."""
        resolved = self._resolve_encodings()
        pre, post, _ = self._parse_encodings(resolved)
        return pre, post

    def _split_announcement_encodings(self) -> List[Union[str, int]]:
        """Return the post-boundary encodings for the announcement PDU."""
        pre, post, found = self._parse_encodings(self.announcement_encodings)
        return post if found else pre

    def generate(self, data: bytes, content_type: Optional[str] = None) -> Generator[bytes, None, None]:
        """
        Generate HQFBP PDUs for the given data.
        
        The encoding sequence dictates the flow:
        1. All encodings before first chunk(size) are applied to the whole message.
        2. chunk(size) splits the message into parts.
        3. All encodings after last chunk(size) but before 'h' are applied to each chunk.
        4. packing (CBOR) is performed.
        5. All encodings after 'h' are applied to the whole packed PDU.
        """
        file_size = len(data)
        full_encs = self._resolve_encodings()
        
        # Determine splits
        # message-wide pre-boundary | chunk(size) | chunk-wide pre-boundary | h | post-boundary
        pre_h, post_h, _ = self._parse_encodings(full_encs)
        
        chunk_idx = -1
        target_max_payload = None
        for i, e in enumerate(pre_h):
            if isinstance(e, str):
                m = CHUNK_RE.match(e)
                if m:
                    chunk_idx = i
                    target_max_payload = int(m.group(1))
                    break # We take the first chunk(size) as the split point
        
        if chunk_idx != -1:
            msg_pre = pre_h[:chunk_idx]
            chunk_pre = pre_h[chunk_idx + 1:]
        else:
            msg_pre = pre_h
            chunk_pre = []
            target_max_payload = None

        # 1. Apply message-wide pre-boundary encodings
        encoded_data = self._apply_encodings(data, msg_pre)
        encoded_size = len(encoded_data)
        
        if self.announcement_encoder:
            # Announcements use the full resolved encodings of the data message
            self.announcement_encoder._next_msg_id = self._next_msg_id
            upcoming_msg_id = self._next_msg_id + 1
            
            ann_payload_dict = {
                HQFBP_CBOR_KEYS['Message-Id']: upcoming_msg_id,
            }
            if full_encs:
                ann_payload_dict[HQFBP_CBOR_KEYS['Content-Encoding']] = full_encs
            
            for pdu in self.announcement_encoder.generate(
                pack(ann_payload_dict, b""),
                content_type="application/vnd.hqfbp+cbor"
            ):
                yield pdu
            self._next_msg_id = self.announcement_encoder._next_msg_id

        # 2. Chunking
        if target_max_payload and encoded_size > target_max_payload:
            total_chunks = (encoded_size + target_max_payload - 1) // target_max_payload
            original_msg_id = self._get_next_msg_id()
            
            for i in range(total_chunks):
                start = i * target_max_payload
                end = min(start + target_max_payload, encoded_size)
                chunk_payload = encoded_data[start:end]
                
                # 3. Apply chunk-wide pre-boundary encodings (e.g. per-chunk compression)
                final_chunk_payload = self._apply_encodings(chunk_payload, chunk_pre)
                
                header = {
                    HQFBP_CBOR_KEYS['Message-Id']: self._get_next_msg_id() if i > 0 else original_msg_id,
                    HQFBP_CBOR_KEYS['Original-Message-Id']: original_msg_id,
                    HQFBP_CBOR_KEYS['Chunk-Id']: i,
                    HQFBP_CBOR_KEYS['Total-Chunks']: total_chunks,
                    HQFBP_CBOR_KEYS['File-Size']: file_size,
                }
                
                if self.src_callsign:
                    header[HQFBP_CBOR_KEYS['Src-Callsign']] = self.src_callsign
                if self.dst_callsign:
                    header[HQFBP_CBOR_KEYS['Dst-Callsign']] = self.dst_callsign
                if full_encs:
                    header[HQFBP_CBOR_KEYS['Content-Encoding']] = full_encs
                if content_type and i == 0:
                    header[HQFBP_CBOR_KEYS['Content-Type']] = content_type
                
                pdu = pack(header, final_chunk_payload)
                # 4. Apply post-boundary encodings (e.g. FEC) to the whole PDU
                yield self._apply_encodings(pdu, post_h)
        else:
            # Single PDU (even if chunk_pre exists, we apply it once)
            final_payload = self._apply_encodings(encoded_data, chunk_pre)
            header = {
                HQFBP_CBOR_KEYS['Message-Id']: self._get_next_msg_id(),
                HQFBP_CBOR_KEYS['File-Size']: file_size,
            }
            if self.src_callsign:
                header[HQFBP_CBOR_KEYS['Src-Callsign']] = self.src_callsign
            if self.dst_callsign:
                header[HQFBP_CBOR_KEYS['Dst-Callsign']] = self.dst_callsign
            if full_encs:
                header[HQFBP_CBOR_KEYS['Content-Encoding']] = full_encs
            if content_type:
                header[HQFBP_CBOR_KEYS['Content-Type']] = content_type
            
            pdu = pack(header, final_payload)
            yield self._apply_encodings(pdu, post_h)
