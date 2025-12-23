import io
import cbor2
import binascii
import struct
from typing import Any, Dict, Tuple, Optional, Union, List

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

# Inverse mapping for human_readable_json
_REV_COAP_CONTENT_FORMATS = {v: k for k, v in COAP_CONTENT_FORMATS.items()}

# Well-Known Encoding Registry (RFC 6.1.1)
ENCODING_REGISTRY = {
    -1: "h", # Boundary
    0: "identity",
    1: "gzip",
    2: "deflate",
    3: "br",
    4: "lzma",
    5: "crc16",
    6: "crc32",
}

# Inverse mapping for encoding lookup
_REV_ENCODING_REGISTRY = {v: k for k, v in ENCODING_REGISTRY.items()}

def pack(header: Dict[Union[int, str], Any], payload: bytes) -> bytes:
    """
    Pack an HQFBP PDU. Supports human-readable keys and values,
    optimizing for minimal byte size.
    
    Args:
        header: Dictionary containing metadata. Keys can be integers or field names.
        payload: Binary data content.
        
    Returns:
        bytes: Encapsulated HQFBP PDU (CBOR header + payload).
    """
    cbor_header = {}
    
    # 1. Map string keys to integer IDs and copy values
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
            
    # 2. Optimize Content-Type (4) to Content-Format (3) if possible
    ct = cbor_header.get(4)
    if isinstance(ct, str):
        coap_id = get_coap_id(ct)
        if coap_id is not None:
            cbor_header[3] = coap_id
            del cbor_header[4]
            
    # 3. Omit default Content-Format (0) or Content-Type (text/plain;charset=utf-8)
    if cbor_header.get(3) == 0:
        del cbor_header[3]
        
    # 4. Optimize Content-Encoding (5) from strings to integers
    ce = cbor_header.get(5)
    if ce is not None:
        if isinstance(ce, list):
            ce = [_REV_ENCODING_REGISTRY.get(i, i) if isinstance(i, str) else i for i in ce]
            # Strip trailing boundary marker (-1 / "h") as per user request
            while ce and ce[-1] == -1:
                ce.pop()
            
            if not ce:
                del cbor_header[5]
            elif len(ce) == 1:
                cbor_header[5] = ce[0]
            else:
                cbor_header[5] = ce
        elif isinstance(ce, str):
            val = _REV_ENCODING_REGISTRY.get(ce, ce)
            if val == -1: # "h" alone is redundant
                del cbor_header[5]
            else:
                cbor_header[5] = val
        elif ce == -1: # redundant
            del cbor_header[5]

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

def human_readable_json(header: Dict[int, Any]) -> Dict[str, Any]:
    """
    Convert integer encoded values/keys back to textual ones for human readability.
    
    - Converts integer keys back to field names.
    - Converts Content-Format (3) back to Content-Type (4) textual value.
    - Converts integer Encodings (5) back to string names.
    """
    readable = {}
    
    # Track if we found a Content-Format to merge it into Content-Type
    content_type_val = header.get(4) # Content-Type
    content_format_val = header.get(3) # Content-Format
    
    if content_format_val is not None:
        content_type_val = _REV_COAP_CONTENT_FORMATS.get(content_format_val, f"unknown/coap-{content_format_val}")

    for k, v in header.items():
        if k == 3: # Skip Content-Format, handled above
            continue
        if k == 4: # Skip Content-Type, handled above
            continue
            
        key_name = _REV_KEYS.get(k, str(k))
        
        if k == 5: # Content-Encoding
            if isinstance(v, list):
                readable[key_name] = [ENCODING_REGISTRY.get(i, str(i)) if isinstance(i, int) else i for i in v]
            elif isinstance(v, int):
                readable[key_name] = ENCODING_REGISTRY.get(v, str(v))
            else:
                readable[key_name] = v
        else:
            readable[key_name] = v
            
    if content_type_val is not None:
        readable["Content-Type"] = content_type_val
        
    return readable

def crc16_ccitt(data: bytes) -> bytes:
    """
    Calculate CRC16-CCITT (XMODEM variant, poly 0x1021, init 0xFFFF).
    Returns 2 bytes in big-endian.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return struct.pack(">H", crc)

def crc32(data: bytes) -> bytes:
    """
    Calculate CRC32.
    Returns 4 bytes in big-endian.
    """
    return struct.pack(">I", binascii.crc32(data) & 0xFFFFFFFF)

def verify_and_strip_crc(data: bytes, algorithm: Union[int, str]) -> bytes:
    """
    Verify the CRC at the end of data and return data without CRC.
    algorithm can be 5/"crc16" or 6/"crc32".
    Raises ValueError if verification fails.
    """
    if algorithm in (5, "crc16"):
        if len(data) < 2:
            raise ValueError("Data too short for CRC16")
        payload = data[:-2]
        expected = data[-2:]
        if crc16_ccitt(payload) != expected:
            raise ValueError("CRC16 verification failed")
        return payload
    elif algorithm in (6, "crc32"):
        if len(data) < 4:
            raise ValueError("Data too short for CRC32")
        payload = data[:-4]
        expected = data[-4:]
        if crc32(payload) != expected:
            raise ValueError("CRC32 verification failed")
        return payload
    else:
        raise ValueError(f"Unknown CRC algorithm: {algorithm}")
