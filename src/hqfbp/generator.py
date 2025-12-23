from typing import Dict, Any, Optional, List, Union, Generator
from hqfbp import pack, HQFBP_CBOR_KEYS

class PDUGenerator:
    """
    Helper class to generate HQFBP PDUs, supporting common fields and automatic chunking.
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

    def generate(self, data: bytes, content_type: Optional[str] = None) -> Generator[bytes, None, None]:
        """
        Generate HQFBP PDUs for the given data.
        
        If max_payload_size is set and data exceeds it, yields multiple chunks.
        Otherwise, yields a single PDU.
        """
        file_size = len(data)
        
        # Determine if we need to chunk
        if self.max_payload_size and file_size > self.max_payload_size:
            # Chunked transmission
            total_chunks = (file_size + self.max_payload_size - 1) // self.max_payload_size
            original_msg_id = self._get_next_msg_id()
            
            for i in range(total_chunks):
                start = i * self.max_payload_size
                end = min(start + self.max_payload_size, file_size)
                chunk_payload = data[start:end]
                
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
                
                yield pack(header, chunk_payload)
        else:
            # Single PDU
            header = {
                HQFBP_CBOR_KEYS['Message-Id']: self._get_next_msg_id(),
            }
            if self.src_callsign:
                header[HQFBP_CBOR_KEYS['Src-Callsign']] = self.src_callsign
            if self.dst_callsign:
                header[HQFBP_CBOR_KEYS['Dst-Callsign']] = self.dst_callsign
            if self.encodings:
                header[HQFBP_CBOR_KEYS['Content-Encoding']] = self.encodings
            if content_type:
                header[HQFBP_CBOR_KEYS['Content-Type']] = content_type
            
            yield pack(header, data)
