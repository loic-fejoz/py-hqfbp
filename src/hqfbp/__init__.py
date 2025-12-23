import io
import cbor2
from typing import Any, Dict, Tuple, Optional, Union

# HQFBP Static Key Mapping as per RFC Section 4
HQFBP_CBOR_KEYS = {
    # Core Message Identification
    "Message-Id": 0,

    # Addressing
    "Src-Callsign": 1,
    "Dst-Callsign": 2,

    # Content Description
    "Content-Format": 3,
    "Content-Type": 4,

    # Encoding and Integrity
    "Content-Encoding": 5,
    "Repr-Digest": 6,
    "Content-Digest": 7,

    # Chunking and File Grouping
    "File-Size": 8,
    "Chunk-Id": 9,
    "Original-Message-Id": 10,
    "Total-Chunks": 11,
}

# Inverse mapping for easy lookup
_REV_KEYS = {v: k for k, v in HQFBP_CBOR_KEYS.items()}

# Common CoAP Content-Format IDs (RFC 7252, RFC 9176)
# See https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats
COAP_CONTENT_FORMATS = {
    # Text and Standard Web Formats
    "text/plain;charset=utf-8": 0,
    "application/link-format": 40,
    "application/xml": 41,
    "application/octet-stream": 42,
    "application/json": 50,
    "application/cbor": 60,

    # SenML (Sensor Measurement Lists)
    "application/senml+json": 110,
    "application/senml-exi": 111,
    "application/senml+cbor": 112,
    "application/sensml+json": 113,
    "application/sensml-exi": 114,
    "application/sensml+cbor": 115,

    # Image Formats
    "image/gif": 21,
    "image/jpeg": 22,
    "image/png": 23,
    "image/tiff": 24,
    "image/svg+xml": 30,

    # Other Useful IoT Formats
    "application/cose-key": 101,
    "application/cose-key-set": 102,
    "application/or-tecap": 116, # SenML Etch
}

def pack(header: Dict[Union[int, str], Any], payload: bytes) -> bytes:
    """
    Pack an HQFBP PDU.
    
    Args:
        header: Dictionary containing metadata. Keys can be integers or field names.
        payload: Binary data content.
        
    Returns:
        bytes: Encapsulated HQFBP PDU (CBOR header + payload).
    """
    cbor_header = {}
    for k, v in header.items():
        if isinstance(k, str):
            key_id = HQFBP_CBOR_KEYS.get(k)
            if key_id is not None:
                cbor_header[key_id] = v
            else:
                # Custom/extended keys as strings are allowed by CBOR
                cbor_header[k] = v
        else:
            cbor_header[k] = v
            
    # Ensure Message-Id is present as per RFC (MANDATORY)
    if 0 not in cbor_header:
        raise ValueError("Message-Id (key 0) is mandatory in HQFBP header")
        
    return cbor_2_dumps(cbor_header) + payload

def unpack(data: bytes) -> Tuple[Dict[int, Any], bytes]:
    """
    Unpack an HQFBP PDU.
    
    Args:
        data: Binary HQFBP PDU.
        
    Returns:
        tuple: (header_dict, payload_bytes)
    """
    fp = io.BytesIO(data)
    header = cbor2.load(fp)
    payload = fp.read()
    return header, payload

def cbor_2_dumps(obj: Any) -> bytes:
    """Helper to dump CBOR using cbor2."""
    return cbor2.dumps(obj)

def get_coap_id(mimetype: str) -> Optional[int]:
    """Returns the CoAP Content-Format ID for a given MIME type."""
    return COAP_CONTENT_FORMATS.get(mimetype.lower().replace(" ", ""))

def merge_headers(headers: list[Dict[int, Any]]) -> Dict[int, Any]:
    """
    Merge header fields from multiple chunks as per RFC Section 5.2.
    """
    if not headers:
        return {}
        
    # Start with the first received header
    merged = headers[0].copy()
    
    # Core chunking parameters that should not be merged/replicated in the final result
    # according to RFC 5.2 (except for verification)
    # 0: Msg-Id, 9: Chunk-Id, 10: Original-Msg-Id, 11: Total-Chunks, 8: File-Size (sometimes kept)
    exclude_keys = {0, 9, 10, 11}
    
    for h in headers[1:]:
        for k, v in h.items():
            if k in exclude_keys:
                continue
            if k not in merged:
                merged[k] = v
            elif merged[k] != v:
                # Consistency check (RFC 5.2 Rule 1)
                # Typically Src-Callsign (1), Repr-Digest (6), File-Size (8)
                if k in {1, 6, 8}:
                    raise ValueError(f"Inconsistent header field {k}: {merged[k]} vs {v}")
    
    # Cleanup excluded keys from the merged result (they might have been in headers[0])
    for k in exclude_keys:
        merged.pop(k, None)

    return merged
