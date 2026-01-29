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
    "application/or-tecap": 116,  # SenML Etch
}

# Inverse mapping for human_readable_json
_REV_COAP_CONTENT_FORMATS = {v: k for k, v in COAP_CONTENT_FORMATS.items()}

# Well-Known Encoding Registry (RFC 6.1.1)
ENCODING_REGISTRY = {
    -1: "h",  # Boundary
    0: "identity",
    1: "gzip",
    2: "deflate",
    3: "br",
    4: "lzma",
    5: "crc16",
    6: "crc32",
    7: "rs",
    8: "rq",
    9: "conv",
    10: "scr",
    11: "chunk",
    12: "repeat",
    15: "golay",
    56: "post_asm",
}

# Inverse mapping for encoding lookup
_REV_ENCODING_REGISTRY = {v: k for k, v in ENCODING_REGISTRY.items()}

RS_RE = re.compile(r"rs\((\d+),\s*(\d+)\)")
RQ_RE = re.compile(r"rq\((\d+),\s*(\d+),\s*(\d+)\)")
RQ_DYN_RE = re.compile(r"rq\(dlen,\s*(\d+),\s*(\d+)\)")
RQ_DYN_PERC_RE = re.compile(r"rq\(dlen,\s*(\d+),\s*(\d+)%\)")
LT_RE = re.compile(r"lt\((\d+),\s*(\d+),\s*(\d+)\)")
LT_DYN_RE = re.compile(r"lt\(dlen,\s*(\d+),\s*(\d+)\)")
CONV_RE = re.compile(r"conv\((\d+),\s*(\d+/\d+)\)")
SCR_RE = re.compile(r"scr\((0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(0x[0-9a-fA-F]+|\d+))?\)")
GOLAY_RE = re.compile(r"golay(?:\((\d+),\s*(\d+)\))?")
CHUNK_RE = re.compile(r"chunk\((\d+)\)")
REPEAT_RE = re.compile(r"repeat\((\d+)\)")
POST_ASM_RE = re.compile(r"post_asm\((0x[0-9a-fA-F]+|\d+)\)")


def rs_encode(data: bytes, n: int, k: int) -> bytes:
    """Encode data using Reed-Solomon(n, k). Chunks data into k bytes blocks."""
    rs = reedsolo.RSCodec(n - k)
    encoded = bytearray()
    for i in range(0, len(data), k):
        chunk = data[i : i + k]
        if len(chunk) < k:
            chunk = chunk.ljust(k, b"\x00")
        encoded.extend(rs.encode(chunk))
    return bytes(encoded)


def rs_decode(
    data: Union[bytes, List[bytes]], n: int, k: int
) -> Tuple[bytes, int]:
    if isinstance(data, list):
        data = b"".join(data)

    """
    Decode data using Reed-Solomon(n, k). Data should be multiple of n bytes.
    Returns (decoded_data, total_errors_corrected).
    """
    rs = reedsolo.RSCodec(n - k)
    decoded = bytearray()
    total_errors = 0
    for i in range(0, len(data), n):
        chunk = data[i : i + n]
        if len(chunk) < n:
            chunk = chunk.ljust(n, b"\x00")
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

    data = data.ljust(original_count, b"\x00")
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
        except Exception:
            raise ValueError(
                f"RaptorQ decoding failed: insufficient buffer size ({len(packet)}) or other errors"
            )
        if res:
            return bytes(res)

    raise ValueError("RaptorQ decoding failed: insufficient symbols")


def lt_encode(
    data: bytes, original_count: int, mtu: int, repair_count: int
) -> List[bytes]:
    """
    Encode data using Luby Transform (LT) codes.

    Args:
        data: Binary data to encode.
        original_count: expected length of the data in bytes.
        mtu: Maximum transmission unit (symbol size).
        repair_count: Number of repair packets to encode (beyond K).

    Returns:
        List[bytes]: List of encoded packets (chunks).
    """
    from hqfbp.lt import LTEncoder

    if len(data) < original_count:
        data = data.ljust(original_count, b"\x00")

    encoder = LTEncoder(data, mtu)
    return list(encoder.encode(repair_count))


def lt_decode(packets: List[bytes], original_count: int, mtu: int) -> bytes:
    """
    Decode data using Luby Transform (LT) codes.

    Args:
        packets: List of encoded packets.
        original_count: expected length.
        mtu: symbol size.

    Returns:
        bytes: Decoded data.
    """
    from hqfbp.lt import LTDecoder

    decoder = LTDecoder(original_count, mtu)
    for p in packets:
        decoder.decode(p)

    res = decoder.get_result()
    if res:
        return res
    raise ValueError("LT decoding failed: insufficient symbols")


def conv_encode(data: bytes, k: int = 7, rate: str = "1/2") -> bytes:
    """
    Convolutional encoding (hardcoded to NASA polynomials for K=7, R=1/2).
    G1 = 133 (oct), G2 = 171 (oct)
    """
    if k != 7 or rate != "1/2":
        raise ValueError(
            f"Only conv(7, 1/2) is currently supported, got conv({k}, {rate})"
        )

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
        state &= 0x3F  # Keep only 6 bits for next iteration (constraint length 7 needs 6 bits of memory)

    # Convert bits back to bytes
    res = bytearray()
    for i in range(0, len(bits), 8):
        byte_val = 0
        chunk = bits[i : i + 8]
        for idx, b in enumerate(chunk):
            byte_val |= b << (7 - idx)
        res.append(byte_val)
    return bytes(res)


def conv_decode(
    data: Union[bytes, List[bytes]], k: int = 7, rate: str = "1/2"
) -> Tuple[bytes, int]:
    if isinstance(data, list):
        data = b"".join(data)

    """
    Viterbi decoding for conv(7, 1/2) with NASA polynomials.
    Returns (decoded_data, min_path_metric).
    Lower path metric means higher quality (fewer bit flips corrected).
    Optimized to O(N) using backtracking.
    """
    if k != 7 or rate != "1/2":
        raise ValueError("Only conv(7, 1/2) is currently supported")

    g1 = 0o133
    g2 = 0o171
    num_states = 1 << (k - 1)  # 64 states

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
    metrics = [float("inf")] * num_states
    metrics[0] = 0
    
    # predecessor_states[step][state] = (prev_state << 1) | bit
    num_steps = len(data) * 4 # 8 bits per byte / 2 bits per step
    if num_steps == 0:
        return b"", 0
        
    predecessor_states = [None] * num_steps

    # Extract bits from data
    input_bits = []
    for b in data:
        for i in range(7, -1, -1):
            input_bits.append((b >> i) & 1)

    # Process pairs of bits (Rate 1/2)
    for i in range(0, len(input_bits) - 1, 2):
        step = i // 2
        r1 = input_bits[i]
        r2 = input_bits[i + 1]

        new_metrics = [float("inf")] * num_states
        predecessors = [0] * num_states

        for s in range(num_states):
            curr_metric = metrics[s]
            if curr_metric == float("inf"):
                continue

            for bit in [0, 1]:
                next_s, p1, p2 = transitions[s][bit]
                dist = (r1 ^ p1) + (r2 ^ p2)
                new_dist = curr_metric + dist

                if new_dist < new_metrics[next_s]:
                    new_metrics[next_s] = new_dist
                    predecessors[next_s] = (s << 1) | bit

        metrics = new_metrics
        predecessor_states[step] = predecessors

    # Pick the best ending state
    best_state = 0
    min_m = metrics[0]
    for s in range(num_states):
        if metrics[s] < min_m:
            min_m = metrics[s]
            best_state = s

    # Backtrack
    decoded_bits = [0] * num_steps
    curr_s = best_state
    for step in range(num_steps - 1, -1, -1):
        prev_info = predecessor_states[step][curr_s]
        prev_s = prev_info >> 1
        bit = prev_info & 1
        decoded_bits[step] = bit
        curr_s = prev_s

    # Remove the K-1 flush bits
    if len(decoded_bits) >= (k - 1):
        decoded_bits = decoded_bits[: -(k - 1)]
    else:
        decoded_bits = []

    # Convert back to bytes
    res = bytearray()
    for i in range(0, len(decoded_bits), 8):
        byte_val = 0
        chunk = decoded_bits[i : i + 8]
        if len(chunk) < 8:
            break
        for idx, b in enumerate(chunk):
            byte_val |= b << (7 - idx)
        res.append(byte_val)
    return bytes(res), int(min_m)


# Golay(24,12) Implementation
GOLAY_B = [
    0x8ED, 0x1DB, 0x3B6, 0x76C, 0xED8, 0xDB5, 0xB6B, 0x6D7, 0xDAE, 0xB5D, 0x6BA, 0xD74,
]

def golay_encode_codeword(data: int) -> int:
    parity = 0
    for i in range(12):
        if (data >> (11 - i)) & 1:
            parity ^= GOLAY_B[i]
    return (data << 12) | parity

def golay_weight12(n: int) -> int:
    return bin(n & 0xFFF).count('1')

def golay_decode_codeword(received: int) -> Tuple[int, int]:
    data = (received >> 12) & 0xFFF
    parity = received & 0xFFF
    
    expected_parity = 0
    for i in range(12):
        if (data >> (11 - i)) & 1:
            expected_parity ^= GOLAY_B[i]
    
    s = parity ^ expected_parity
    if s == 0:
        return data, 0
        
    if golay_weight12(s) <= 3:
        corrected = received ^ s
        return (corrected >> 12) & 0xFFF, golay_weight12(s)
        
    for i in range(12):
        si = s ^ GOLAY_B[i]
        if golay_weight12(si) <= 2:
            error_pattern = si | (1 << (23 - i))
            corrected = received ^ error_pattern
            return (corrected >> 12) & 0xFFF, golay_weight12(si) + 1
            
    # Try s * B
    s_prime = 0
    for i in range(12):
        row_sum = 0
        for j in range(12):
            if (s & (1 << (11 - j))) and (GOLAY_B[j] & (1 << (11 - i))):
                row_sum ^= 1
        if row_sum:
            s_prime |= (1 << (11 - i))
            
    if golay_weight12(s_prime) <= 3:
        error_pattern = s_prime << 12
        corrected = received ^ error_pattern
        return (corrected >> 12) & 0xFFF, golay_weight12(s_prime)
        
    for i in range(12):
        s_prime_i = s_prime ^ GOLAY_B[i]
        if golay_weight12(s_prime_i) <= 2:
            error_pattern = (s_prime_i << 12) | (1 << (11 - i))
            corrected = received ^ error_pattern
            return (corrected >> 12) & 0xFFF, golay_weight12(s_prime_i) + 1
            
    return data, 0

def golay_encode(data: bytes) -> bytes:
    encoded = bytearray()
    for i in range(0, len(data), 3):
        b1 = data[i]
        b2 = data[i+1] if i + 1 < len(data) else 0
        b3 = data[i+2] if i + 2 < len(data) else 0
        
        w1 = (b1 << 4) | (b2 >> 4)
        w2 = ((b2 & 0x0F) << 8) | b3
        
        c1 = golay_encode_codeword(w1)
        c2 = golay_encode_codeword(w2)
        
        encoded.extend(struct.pack(">I", c1)[1:])
        encoded.extend(struct.pack(">I", c2)[1:])
    return bytes(encoded)

def golay_decode(data: Union[bytes, List[bytes]]) -> Tuple[bytes, int]:
    if isinstance(data, list):
        data = b"".join(data)

    if len(data) % 6 != 0:
        raise ValueError("Invalid Golay data length: must be multiple of 6 bytes")
        
    decoded = bytearray()
    total_corrected = 0
    for i in range(0, len(data), 6):
        c1 = struct.unpack(">I", b"\x00" + data[i:i+3])[0]
        c2 = struct.unpack(">I", b"\x00" + data[i+3:i+6])[0]
        
        w1, n1 = golay_decode_codeword(c1)
        w2, n2 = golay_decode_codeword(c2)
        
        total_corrected += n1 + n2
        
        b1 = (w1 >> 4) & 0xFF
        b2 = ((w1 & 0xF) << 4) | ((w2 >> 8) & 0xF)
        b3 = w2 & 0xFF
        
        decoded.append(b1)
        decoded.append(b2)
        decoded.append(b3)
    return bytes(decoded), total_corrected


def scr_xor(
    data: Union[bytes, List[bytes]], poly_mask: int, seed: Optional[int] = None
) -> bytes:
    if isinstance(data, list):
        data = b"".join(data)

    """
    Additive scrambler using an LFSR.
    Since it's XOR-based, scrambling and descrambling are the same operation.

    Args:
        data: Input bytes.
        poly_mask: LFSR feedback polynomial.
        seed: Optional LFSR initial state. Defaults to all ones if None.

    Returns:
        bytes: Scrambled/descrambled result.
    """
    if poly_mask == 0:
        return data

    # Determine LFSR width from polynomial
    width = poly_mask.bit_length()
    mask = (1 << width) - 1

    # Use a fixed seed for repeatability
    state = seed if seed is not None else mask

    res = bytearray()
    for b in data:
        out_byte = 0
        for i in range(8):
            # Feedback bit (usually XOR of bits at tap positions)
            # Standard additive scrambler: feedback = parity(state & poly)
            feedback = 0
            temp = state & poly_mask
            while temp:
                feedback ^= temp & 1
                temp >>= 1

            # Most scramblers output one of the state bits
            # We'll output the feedback bit to simplify
            bit = (b >> (7 - i)) & 1
            scr_bit = bit ^ feedback
            out_byte = (out_byte << 1) | scr_bit

            # Shift LFSR
            state = ((state << 1) | feedback) & mask
            if state == 0:
                state = mask  # Avoid zero lockup

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
            ce = [
                _REV_ENCODING_REGISTRY.get(i, i) if isinstance(i, str) else i
                for i in ce
            ]

            if not ce:
                del cbor_header[5]
            elif len(ce) == 1:
                cbor_header[5] = ce[0]
            else:
                cbor_header[5] = ce
        elif isinstance(ce, str):
            val = _REV_ENCODING_REGISTRY.get(ce, ce)
            cbor_header[5] = val
        elif ce == -1:  # redundant but keep if specifically asked
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
                    raise ValueError(
                        f"Inconsistent header field {k}: {merged[k]} vs {v}"
                    )

    # Cleanup excluded keys from the merged result (they might have been in headers[0])
    for k in exclude_keys:
        merged.pop(k, None)

    # Standardize Content-Encoding (5) if present
    ce_key = HQFBP_CBOR_KEYS["Content-Encoding"]
    if ce_key in merged:
        ce = merged[ce_key]
        if isinstance(ce, list):
            merged[ce_key] = [
                _REV_ENCODING_REGISTRY.get(e, e) if isinstance(e, str) else e
                for e in ce
            ]
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
    content_type_val = header.get(4)  # Content-Type
    content_format_val = header.get(3)  # Content-Format

    if content_format_val is not None:
        content_type_val = _REV_COAP_CONTENT_FORMATS.get(
            content_format_val, f"unknown/coap-{content_format_val}"
        )

    for k, v in header.items():
        if k == 3:  # Skip Content-Format, handled above
            continue
        if k == 4:  # Skip Content-Type, handled above
            continue

        key_name = _REV_KEYS.get(k, str(k))

        if k == 5:  # Content-Encoding
            if isinstance(v, list):
                readable[key_name] = [
                    ENCODING_REGISTRY.get(i, str(i)) if isinstance(i, int) else i
                    for i in v
                ]
            elif isinstance(v, int):
                readable[key_name] = ENCODING_REGISTRY.get(v, str(v))
            else:
                readable[key_name] = v
        else:
            readable[key_name] = v

    if content_type_val is not None:
        readable["Content-Type"] = content_type_val

    return readable


def post_asm_encode(data: bytes, sync_word: bytes) -> bytes:
    """Append a sync word (Post-ASM) at the end of the data."""
    return data + sync_word


def post_asm_decode(data: bytes, sync_word: bytes) -> bytes:
    """Verify and strip a sync word (Post-ASM) from the end of the data."""
    if not data.endswith(sync_word):
        raise ValueError(f"Post-ASM sync word mismatch: expected {sync_word.hex()}")
    return data[: -len(sync_word)]


def crc16_ccitt(data: bytes) -> bytes:
    """
    Calculate CRC16-CCITT (XMODEM variant, poly 0x1021, init 0xFFFF).
    Returns 2 bytes in big-endian.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
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
