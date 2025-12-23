import gzip
import lzma
import brotli
from typing import Dict, Any, Optional, List, Union, Generator, Tuple
from hqfbp import pack, HQFBP_CBOR_KEYS

class PDUGenerator:
    """
    Helper class to generate HQFBP PDUs, supporting common fields and automatic chunking.
    Supports data compression (gzip, lzma) and pre/post boundary encodings.
    """
    
    def __init__(
        self,
        src_callsign: Optional[str] = None,
        dst_callsign: Optional[str] = None,
        max_payload_size: Optional[int] = None,
        encodings: Optional[Union[str, List[Union[str, int]]]] = None
    ):
        self.src_callsign = src_callsign
        self.dst_callsign = dst_callsign
        self.max_payload_size = max_payload_size
        self.encodings = encodings
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
            # Add other encodings here (deflate, etc.) if needed
        return data

    def _split_encodings(self) -> Tuple[List[Union[str, int]], List[Union[str, int]]]:
        """Split encodings into pre-boundary and post-boundary."""
        if not self.encodings:
            return [], []
        
        encs = self.encodings if isinstance(self.encodings, list) else [self.encodings]
        
        try:
            # -1 or "h" is the boundary
            idx = -1
            for i, e in enumerate(encs):
                if e == -1 or e == "h":
                    idx = i
                    break
            
            if idx == -1:
                # No boundary, all are pre-boundary
                return encs, []
            else:
                return encs[:idx], encs[idx+1:]
        except (ValueError, TypeError):
            return encs, []

    def generate(self, data: bytes, content_type: Optional[str] = None) -> Generator[bytes, None, None]:
        """
        Generate HQFBP PDUs for the given data.
        
        Applies pre-boundary encodings (e.g. compression) to the entire data first.
        Then chunks the result if max_payload_size is set.
        Finally applies post-boundary encodings to each packed PDU.
        """
        file_size = len(data)
        pre_enc, post_enc = self._split_encodings()
        
        # Apply pre-boundary encodings (e.g. compression)
        encoded_data = self._apply_encodings(data, pre_enc)
        encoded_size = len(encoded_data)
        
        # Determine if we need to chunk
        if self.max_payload_size and encoded_size > self.max_payload_size:
            # Chunked transmission
            total_chunks = (encoded_size + self.max_payload_size - 1) // self.max_payload_size
            original_msg_id = self._get_next_msg_id()
            
            for i in range(total_chunks):
                start = i * self.max_payload_size
                end = min(start + self.max_payload_size, encoded_size)
                chunk_payload = encoded_data[start:end]
                
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
                if self.encodings:
                    header[HQFBP_CBOR_KEYS['Content-Encoding']] = self.encodings
                if content_type and i == 0: # Content-Type usually in the first chunk
                    header[HQFBP_CBOR_KEYS['Content-Type']] = content_type
                
                pdu = pack(header, chunk_payload)
                # Apply post-boundary encodings (e.g. FEC) to the whole PDU
                yield self._apply_encodings(pdu, post_enc)
        else:
            # Single PDU
            header = {
                HQFBP_CBOR_KEYS['Message-Id']: self._get_next_msg_id(),
                HQFBP_CBOR_KEYS['File-Size']: file_size,
            }
            if self.src_callsign:
                header[HQFBP_CBOR_KEYS['Src-Callsign']] = self.src_callsign
            if self.dst_callsign:
                header[HQFBP_CBOR_KEYS['Dst-Callsign']] = self.dst_callsign
            if self.encodings:
                header[HQFBP_CBOR_KEYS['Content-Encoding']] = self.encodings
            if content_type:
                header[HQFBP_CBOR_KEYS['Content-Type']] = content_type
            
            pdu = pack(header, encoded_data)
            # Apply post-boundary encodings to the whole PDU
            yield self._apply_encodings(pdu, post_enc)
