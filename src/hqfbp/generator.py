import gzip
import lzma
import brotli
import cbor2
from typing import Dict, Any, Optional, List, Union, Generator, Tuple
from hqfbp import pack, HQFBP_CBOR_KEYS, crc16_ccitt, crc32, RS_RE, rs_encode, RQ_RE, rq_encode, CONV_RE, conv_encode, CHUNK_RE, REPEAT_RE
import re


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
                else:
                    m = RQ_RE.match(enc)
                    if m:
                        rq_len, mtu, repair_count = map(int, m.groups())
                        data = rq_encode(data, rq_len, mtu, repair_count)
                    else:
                        m = CONV_RE.match(enc)
                        if m:
                            k, rate = m.groups()
                            data = conv_encode(data, int(k), rate)
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
        
        # Ensure 'chunk(k)' before 'rs(n, k)'
        new_encs = []
        for e in encs:
            if isinstance(e, str):
                m = RS_RE.match(e)
                if m:
                    k = int(m.group(2))
                    chunk_marker = f"chunk({k})"
                    if not (new_encs and new_encs[-1] == chunk_marker):
                        new_encs.append(chunk_marker)
            new_encs.append(e)
        encs = new_encs

        # Ensure a boundary marker is present
        if not (-1 in encs or "h" in encs):
            encs.append(-1)
        
        return encs

    def _clean_encodings(self, encodings: List[Union[str, int]]) -> List[Union[str, int]]:
        """
        Remove all encodings that shall not be transmitted on air,
        eg chunk(n), repeat(m), etc.
        Keep boundary marker 'h'/-1 as it defines pre/post boundary split.
        """
        return [e for e in encodings if not isinstance(e, str) or (not CHUNK_RE.match(e) and not REPEAT_RE.match(e))]


    def _parse_encodings(self, val: Optional[Union[str, List[Union[str, int]]]]) -> Tuple[List[Union[str, int]], List[Union[str, int]], bool]:
        if not val:
            return [], [], False
        encs = val if isinstance(val, list) else [val]
        for i, e in enumerate(encs):
            if e in (-1, "h"):
                return encs[:i], encs[i+1:], True
        return encs, [], False

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
        if full_encs:
            header_template[HQFBP_CBOR_KEYS['Content-Encoding']] = self._clean_encodings(full_encs)
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
                        if self._next_msg_id == msg_id:
                            self._next_msg_id += 1
                    else:
                        msg_id = self._get_next_msg_id()

                    if total_chunks > 1:
                        header[HQFBP_CBOR_KEYS['Total-Chunks']] = total_chunks
                        header[HQFBP_CBOR_KEYS['Chunk-Id']] = i
                        header[HQFBP_CBOR_KEYS['Original-Message-Id']] = data_orig_id
                        header[HQFBP_CBOR_KEYS['Message-Id']] = msg_id
                    else:
                        header[HQFBP_CBOR_KEYS['Message-Id']] = msg_id
                    
                    if i > 0 and HQFBP_CBOR_KEYS['Content-Type'] in header:
                        del header[HQFBP_CBOR_KEYS['Content-Type']]
                        
                    new_chunks.append(pack(header, chunk_data))
                current_chunks = new_chunks
            elif isinstance(enc, str) and CHUNK_RE.match(enc):
                # Chunking
                m = CHUNK_RE.match(enc)
                size = int(m.group(1))
                new_chunks = []
                for chunk in current_chunks:
                    for j in range(0, len(chunk), size):
                        new_chunks.append(chunk[j : j + size])
                current_chunks = new_chunks
            elif isinstance(enc, str) and REPEAT_RE.match(enc):
                # Duplication
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
                    if enc.startswith("rq(dlen,"):
                        enc = enc.replace("rq(dlen,", "rq(" + str(int(len(c))) + ",")
                        full_encs[enc_idx] = enc
                        header_template[HQFBP_CBOR_KEYS['Content-Encoding']] = self._clean_encodings(full_encs)
                    chunks = self._apply_encodings(c, [enc])
                    if isinstance(chunks, bytes):
                        new_chunks.append(chunks)
                    else:
                        new_chunks.extend(chunks)
                current_chunks = new_chunks

        # Yield Announcement if requested
        if self.announcement_encoder:
            self.announcement_encoder._next_msg_id = ann_msg_id
            
            ann_payload_dict = {
                HQFBP_CBOR_KEYS['Message-Id']: data_orig_id,
            }
            if full_encs:
                ann_payload_dict[HQFBP_CBOR_KEYS['Content-Encoding']] = self._clean_encodings(full_encs)
            
            for pdu in self.announcement_encoder.generate(
                pack(ann_payload_dict, b""),
                content_type="application/vnd.hqfbp+cbor"
            ):
                yield pdu

        # Yield Data PDUs
        for chunk in current_chunks:
            yield chunk
