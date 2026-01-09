import io
import cbor2
import binascii
import struct
import re
import reedsolo
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
    "Payload-Size": 12,
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

RS_RE = re.compile(r"rs\((\d+),\s*(\d+)\)")
RQ_RE = re.compile(r"rq\((\d+),\s*(\d+),\s*(\d+)\)")
CONV_RE = re.compile(r"conv\((\d+),\s*(\d+/\d+)\)")
SCR_RE = re.compile(r"scr\((0x[0-9a-fA-F]+|\d+)\)")
CHUNK_RE = re.compile(r"chunk\((\d+)\)")
REPEAT_RE = re.compile(r"repeat\((\d+)\)")

def rs_encode(data: bytes, n: int, k: int) -> bytes:
    """Encode data using Reed-Solomon(n, k). Chunks data into k bytes blocks."""
    rs = reedsolo.RSCodec(n - k)
    encoded = bytearray()
    for i in range(0, len(data), k):
        chunk = data[i:i+k]
        if len(chunk) < k:
            chunk = chunk.ljust(k, b'\x00')
        encoded.extend(rs.encode(chunk))
    return bytes(encoded)

def rs_decode(data: bytes, n: int, k: int) -> Tuple[bytes, int]:
    """
    Decode data using Reed-Solomon(n, k). Data should be multiple of n bytes.
    Returns (decoded_data, total_errors_corrected).
    """
    rs = reedsolo.RSCodec(n - k)
    decoded = bytearray()
    total_errors = 0
    for i in range(0, len(data), n):
        chunk = data[i:i+n]
        if len(chunk) < n:
            chunk = chunk.ljust(n, b'\x00')
        # rs.decode returns (decoded_msg, decoded_msgecc, err_ata_pos)
        # but we need to know how many errors were corrected.
        try:
            msg, _, err_pos = rs.decode(chunk)
            decoded.extend(msg)
            total_errors += len(err_pos)
        except reedsolo.ReedSolomonError:
            # If we can't decode one block, the whole thing is failed for now
            # but in Hybrid ARQ we might want to be more granular.
            # For now, raise ValueError to match existing logic.
            raise ValueError("Reed-Solomon decoding failed")
    return bytes(decoded), total_errors

def rq_encode(data: bytes, original_count: int, mtu: int, repair_count: int) -> bytes:
    """
    Encode data using RaptorQ (RFC 6330).
    
    Args:
        data: Binary data to encode.
        original_count: expected length of the data in bytes. Will be padded or trunked.
        mtu: Maximum transmission unit for packets.
        repair_count: Number of repair packets to encode.
    
    Returns:
        bytes: Encoded data.
    """
    import raptorq
    data = data.ljust(original_count, b'\x00')
    assert len(data) == original_count
    encoder = raptorq.Encoder.with_defaults(data, mtu)
    return encoder.get_encoded_packets(repair_count)

def rq_decode(data: List[bytes], original_count: int, mtu: int) -> bytes:
    """
    Decode data using RaptorQ (RFC 6330).
    
    Args:
        data: List of encoded packets.
        original_count: expected length of the data in bytes. Will be padded or trunked.
        mtu: Maximum transmission unit for packets.
    
    Returns:
        bytes: Decoded data.
    """
    import raptorq

    decoder = raptorq.Decoder.with_defaults(original_count, mtu)
    for packet in data:
        try:
            res = decoder.decode(packet)
        except:
            raise ValueError(f"RaptorQ decoding failed: insufficient buffer size ({len(packet)}) or other errors")
        if res:
            return bytes(res)
            
    raise ValueError("RaptorQ decoding failed: insufficient symbols")

def conv_encode(data: bytes, k: int = 7, rate: str = "1/2") -> bytes:
    """
    Convolutional encoding (hardcoded to NASA polynomials for K=7, R=1/2).
    G1 = 133 (oct), G2 = 171 (oct)
    """
    if k != 7 or rate != "1/2":
        raise ValueError(f"Only conv(7, 1/2) is currently supported, got conv({k}, {rate})")
    
    # NASA polynomials
    g1 = 0o133
    g2 = 0o171
    
    state = 0
    bits = []
    
    # Convert bytes to bits and add K-1 zeros to flush
    input_bits = []
    for b in data:
        for i in range(7, -1, -1):
            input_bits.append((b >> i) & 1)
    for _ in range(k - 1):
        input_bits.append(0)
        
    for bit in input_bits:
        state = (state << 1) | bit
        # K=7 means state has 7 bits. We use 1 parity bit + 6 shift register bits
        # But we can just use the state directly against the polynomial
        
        p1 = 0
        p2 = 0
        for i in range(k):
            if (g1 >> i) & 1:
                p1 ^= (state >> i) & 1
            if (g2 >> i) & 1:
                p2 ^= (state >> i) & 1
        
        bits.append(p1)
        bits.append(p2)
        state &= 0x3F # Keep only 6 bits for next iteration (constraint length 7 needs 6 bits of memory)
        
    # Convert bits back to bytes
    res = bytearray()
    for i in range(0, len(bits), 8):
        byte_val = 0
        chunk = bits[i:i+8]
        for idx, b in enumerate(chunk):
            byte_val |= (b << (7 - idx))
        res.append(byte_val)
    return bytes(res)

def conv_decode(data: bytes, k: int = 7, rate: str = "1/2") -> Tuple[bytes, int]:
    """
    Viterbi decoding for conv(7, 1/2) with NASA polynomials.
    Returns (decoded_data, min_path_metric).
    Lower path metric means higher quality (fewer bit flips corrected).
    """
    if k != 7 or rate != "1/2":
        raise ValueError(f"Only conv(7, 1/2) is currently supported")

    g1 = 0o133
    g2 = 0o171
    num_states = 1 << (k - 1) # 64 states
    
    # Pre-calculate state transitions and outputs
    # transitions[state][input_bit] = (next_state, p1, p2)
    transitions = []
    for s in range(num_states):
        t = []
        for bit in [0, 1]:
            new_full_state = (s << 1) | bit
            p1 = 0
            p2 = 0
            for i in range(k):
                if (g1 >> i) & 1:
                    p1 ^= (new_full_state >> i) & 1
                if (g2 >> i) & 1:
                    p2 ^= (new_full_state >> i) & 1
            t.append((new_full_state & (num_states - 1), p1, p2))
        transitions.append(t)

    # Viterbi state
    metrics = [float('inf')] * num_states
    metrics[0] = 0
    paths = [bytearray() for _ in range(num_states)]
    
    # Extract bits from data
    input_bits = []
    for b in data:
        for i in range(7, -1, -1):
            input_bits.append((b >> i) & 1)
            
    # Process pairs of bits (Rate 1/2)
    for i in range(0, len(input_bits) - 1, 2):
        r1 = input_bits[i]
        r2 = input_bits[i+1]
        
        new_metrics = [float('inf')] * num_states
        new_paths = [None] * num_states
        
        for s in range(num_states):
            if metrics[s] == float('inf'):
                continue
            
            for bit in [0, 1]:
                next_s, p1, p2 = transitions[s][bit]
                dist = (r1 ^ p1) + (r2 ^ p2)
                new_dist = metrics[s] + dist
                
                if new_dist < new_metrics[next_s]:
                    new_metrics[next_s] = new_dist
                    new_paths[next_s] = paths[s] + bytearray([bit])
        
        metrics = new_metrics
        paths = new_paths

    # Pick the best path (should end at state 0 because of the flush)
    best_state = 0
    min_m = metrics[0]
    for s in range(num_states):
        if metrics[s] < min_m:
            min_m = metrics[s]
            best_state = s
            
    decoded_bits = paths[best_state]
    # Remove the K-1 flush bits
    decoded_bits = decoded_bits[:-(k-1)]
    
    # Convert back to bytes
    res = bytearray()
    for i in range(0, len(decoded_bits), 8):
        byte_val = 0
        chunk = decoded_bits[i:i+8]
        if len(chunk) < 8: break # Should be multiple of 8
        for idx, b in enumerate(chunk):
            byte_val |= (b << (7 - idx))
        res.append(byte_val)
    return bytes(res), int(min_m)

def scr_xor(data: bytes, poly_mask: int) -> bytes:
    """
    Additive scrambler using an LFSR.
    Since it's XOR-based, scrambling and descrambling are the same operation.
    
    Args:
        data: Input bytes.
        poly_mask: LFSR feedback polynomial.
        
    Returns:
        bytes: Scrambled/descrambled result.
    """
    if poly_mask == 0:
        return data
        
    # Determine LFSR width from polynomial
    width = poly_mask.bit_length()
    mask = (1 << width) - 1
    
    # Use a fixed seed for repeatability
    state = mask
    
    res = bytearray()
    for b in data:
        out_byte = 0
        for i in range(8):
            # Feedback bit (usually XOR of bits at tap positions)
            # Standard additive scrambler: feedback = parity(state & poly)
            feedback = 0
            temp = state & poly_mask
            while temp:
                feedback ^= (temp & 1)
                temp >>= 1
                
            # Most scramblers output one of the state bits
            # We'll output the feedback bit to simplify
            bit = (b >> (7 - i)) & 1
            scr_bit = bit ^ feedback
            out_byte = (out_byte << 1) | scr_bit
            
            # Shift LFSR
            state = ((state << 1) | feedback) & mask
            if state == 0: state = mask # Avoid zero lockup
            
        res.append(out_byte)
    return bytes(res)

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
            
            if not ce:
                del cbor_header[5]
            elif len(ce) == 1:
                cbor_header[5] = ce[0]
            else:
                cbor_header[5] = ce
        elif isinstance(ce, str):
            val = _REV_ENCODING_REGISTRY.get(ce, ce)
            cbor_header[5] = val
        elif ce == -1: # redundant but keep if specifically asked
            cbor_header[5] = -1

    # Ensure Message-Id is present as per RFC (MANDATORY)
    if 0 not in cbor_header:
        raise ValueError("Message-Id (key 0) is mandatory in HQFBP header")
    
    # Update Payload-Size (key 12)
    cbor_header[12] = len(payload)
        
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
    
    # Use Payload-Size (key 12) to trim padding added by FEC if present
    payload_size = header.get(12)
    if payload_size is not None:
        payload = payload[:payload_size]
        
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
    
    # Standardize Content-Encoding (5) if present
    ce_key = HQFBP_CBOR_KEYS["Content-Encoding"]
    if ce_key in merged:
        ce = merged[ce_key]
        if isinstance(ce, list):
            merged[ce_key] = [_REV_ENCODING_REGISTRY.get(e, e) if isinstance(e, str) else e for e in ce]
        elif isinstance(ce, str):
            merged[ce_key] = _REV_ENCODING_REGISTRY.get(ce, ce)

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

def verify_and_strip_crc(data: bytes, algorithm: Union[int, str]) -> Tuple[bytes, bool]:
    """
    Verify the CRC at the end of data and return (data_without_crc, Success).
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
        return payload, True
    elif algorithm in (6, "crc32"):
        if len(data) < 4:
            raise ValueError("Data too short for CRC32")
        payload = data[:-4]
        expected = data[-4:]
        if crc32(payload) != expected:
            raise ValueError("CRC32 verification failed")
        return payload, True
    else:
        raise ValueError(f"Unknown CRC algorithm: {algorithm}")
