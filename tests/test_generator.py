import gzip
import lzma
import brotli
import pytest
from hqfbp.generator import PDUGenerator
from hqfbp import unpack, HQFBP_CBOR_KEYS, verify_and_strip_crc

def test_generator_single_pdu():
    gen = PDUGenerator(src_callsign="F4JXQ-1")
    data = b"Hello World"
    
    pdus = list(gen.generate(data, content_type="text/plain;charset=utf-8"))
    
    assert len(pdus) == 1
    header, payload = unpack(pdus[0])
    
    assert header[HQFBP_CBOR_KEYS['Message-Id']] == 1
    assert header[HQFBP_CBOR_KEYS['Src-Callsign']] == "F4JXQ-1"
    # Wait, text/plain;charset=utf-8 is ID 0 and thus optional.
    assert HQFBP_CBOR_KEYS['Content-Type'] not in header
    assert HQFBP_CBOR_KEYS['Content-Format'] not in header
    # No encoding
    assert HQFBP_CBOR_KEYS['Content-Encoding'] not in header
    assert payload == data
    assert payload == data

def test_generator_initial_msg_id():
    initial_id = 42
    gen = PDUGenerator(src_callsign="F4JXQ-1", initial_msg_id=initial_id)
    data = b"Initial ID test"
    
    pdus = list(gen.generate(data))
    
    assert len(pdus) == 1
    header, _ = unpack(pdus[0])
    assert header[HQFBP_CBOR_KEYS['Message-Id']] == initial_id

def test_generator_single_gzip_pdu():
    gen = PDUGenerator(src_callsign="F4JXQ-1", encodings=["gzip"])
    data = b"Hello World"
    
    pdus = list(gen.generate(data, content_type="text/plain;charset=utf-8"))
    
    assert len(pdus) == 1
    header, payload = unpack(pdus[0])
    
    assert header[HQFBP_CBOR_KEYS['Message-Id']] == 1
    assert header[HQFBP_CBOR_KEYS['Src-Callsign']] == "F4JXQ-1"
    # The payload should be gzipped
    assert payload == gzip.compress(data)


def test_generator_single_lzma_pdu():
    gen = PDUGenerator(src_callsign="F4JXQ-1", encodings=["lzma"])
    data = b"Hello World with enough data to be worth lzma compressing" * 10
    
    pdus = list(gen.generate(data))
    
    assert len(pdus) == 1
    header, payload = unpack(pdus[0])
    
    assert header[HQFBP_CBOR_KEYS['Content-Encoding']] == 4 # lzma
    assert payload == lzma.compress(data)

def test_generator_single_brotli_pdu():
    gen = PDUGenerator(src_callsign="F4JXQ-1", encodings=["br"])
    data = b"Hello World with enough data to be worth brotli compressing" * 10
    
    pdus = list(gen.generate(data))
    
    assert len(pdus) == 1
    header, payload = unpack(pdus[0])
    
    assert header[HQFBP_CBOR_KEYS['Content-Encoding']] == 3 # br
    assert payload == brotli.compress(data)

def test_generator_gzip_before_chunking():
    # Test that compression happens BEFORE chunking
    # Original data 100 bytes, max_payload 50.
    # If we compress first, it might fit in 1 chunk if it compresses well.
    # If we chunk first, it would be 2 chunks.
    data = b"A" * 100
    compressed_data = gzip.compress(data)
    # len(compressed_data) is much less than 100, likely around 20-30 bytes.
    
    gen = PDUGenerator(src_callsign="F4JXQ", encodings=["gzip"], max_payload_size=50)
    pdus = list(gen.generate(data))
    
    # It should compress to < 50 bytes and thus yield ONLY 1 chunk (if it's not chunked by original size)
    # Wait, my implementation chunks the ENCODED data.
    assert len(pdus) == 1
    header, payload = unpack(pdus[0])
    assert payload == compressed_data
    assert header[HQFBP_CBOR_KEYS['File-Size']] == 100 # Original size

def test_generator_chunking():
    gen = PDUGenerator(src_callsign="F4JXQ", max_payload_size=10)
    data = b"This is a longer piece of data that should be chunked."
    # data length is 54
    assert len(data) == 54
    # max_payload_size = 10 -> 6 chunks
    assert len(data) // 10 == 5
    assert len(data) % 10 > 0
    pdus = list(gen.generate(data))
    assert len(pdus) == 6
    
    first_msg_id = None
    prev_msg_id = None
    
    for i, pdu in enumerate(pdus):
        header, payload = unpack(pdu)
        
        # Check sequential Chunk-Id
        assert header[HQFBP_CBOR_KEYS['Chunk-Id']] == i
        
        # Check Total-Chunks consistency
        assert header[HQFBP_CBOR_KEYS['Total-Chunks']] == 6
        
        # Check Message-Id monotonicity (increases by 1)
        curr_msg_id = header[HQFBP_CBOR_KEYS['Message-Id']]
        if prev_msg_id is not None:
            assert curr_msg_id == prev_msg_id + 1
        prev_msg_id = curr_msg_id
        
        # Check Original-Message-Id consistency
        if first_msg_id is None:
            first_msg_id = curr_msg_id
        assert header[HQFBP_CBOR_KEYS['Original-Message-Id']] == first_msg_id
        
        # Check Src-Callsign consistency
        assert header[HQFBP_CBOR_KEYS['Src-Callsign']] == "F4JXQ"
        
        # Check payload length
        if i < 5:
            assert len(payload) == 10
        else:
            assert len(payload) == 4 # 54 % 10

def test_generator_config():
    gen = PDUGenerator()
    gen.set_callsigns(src="N0CALL", dst="QST")
    gen.set_encodings(["gzip", "h"])
    gen.set_max_payload_size(100)
    
    pdus = list(gen.generate(b"short"))
    assert len(pdus) == 1
    header, _ = unpack(pdus[0])
    
    assert header[HQFBP_CBOR_KEYS['Src-Callsign']] == "N0CALL"
    assert header[HQFBP_CBOR_KEYS['Dst-Callsign']] == "QST"
    # ["gzip", "h"] with chunk(100) becomes [1, "chunk(100)"] but chunk(100) is stripped in pack()
    # So it should be just 1 (gzip)
    assert header[HQFBP_CBOR_KEYS['Content-Encoding']] == 1

def test_generator_crc_payload_only():
    # Pre-boundary CRC (payload only)
    gen = PDUGenerator(encodings=["crc32"])
    data = b"payload test"
    pdus = list(gen.generate(data))
    
    _, payload = unpack(pdus[0])
    # The whole payload should have CRC at the end
    from hqfbp import verify_and_strip_crc
    assert verify_and_strip_crc(payload, "crc32") == data

def test_generator_crc_covering_header():
    # Post-boundary CRC (covering header + payload)
    gen = PDUGenerator(encodings=["h", "crc32"])
    data = b"covered test"
    pdus = list(gen.generate(data))
    
    # The whole PDU should have CRC at the end
    pdu = pdus[0]
    from hqfbp import verify_and_strip_crc
    pdu_no_crc = verify_and_strip_crc(pdu, "crc32")
    
    # Now unpack the PDU without CRC
    header, payload = unpack(pdu_no_crc)
    assert payload == data
    assert header[HQFBP_CBOR_KEYS['Content-Encoding']] == [-1, 6] # h, crc32

def test_generator_announcement():
    data = b"Some data"
    # encodings: gzip payload, then crc32 the whole message
    # announcement: crc16 the announcement pdu
    gen = PDUGenerator(
        src_callsign="F4JXQ",
        encodings=["gzip", "h", "crc32"], # Not realistic as CRC32 is still transparent but test the principle
        announcement_encodings=["h", "crc16"]
    )
    
    pdus = list(gen.generate(data))
    
    # We expect 2 PDUs: Announcement + One Data PDU
    assert len(pdus) == 2
    
    # 1. Verify Announcement PDU
    ann_pdu = pdus[0]
    # It should have CRC16 at the end (post-boundary for announcement)
    from hqfbp import verify_and_strip_crc
    ann_pdu_no_crc = verify_and_strip_crc(ann_pdu, "crc16")
    
    ann_h, ann_p_bytes = unpack(ann_pdu_no_crc)
    assert ann_h[HQFBP_CBOR_KEYS['Content-Type']] == "application/vnd.hqfbp+cbor"
    
    # Decode announcement payload
    import cbor2
    ann_p = cbor2.loads(ann_p_bytes)
    # Announcement is 1, data is 2
    assert ann_p[HQFBP_CBOR_KEYS['Message-Id']] == 2 
    # [1, -1, 6]
    assert ann_p[HQFBP_CBOR_KEYS['Content-Encoding']] == [1, -1, 6]
    
    # 2. Verify Data PDU
    data_pdu = pdus[1]
    data_pdu_no_crc = verify_and_strip_crc(data_pdu, "crc32")
    data_h, data_p = unpack(data_pdu_no_crc)
    
    assert data_h[HQFBP_CBOR_KEYS['Message-Id']] == 2
    import gzip
    assert gzip.decompress(data_p) == data

def test_generator_parse_encodings():
    gen = PDUGenerator()
    
    # Empty/None input
    assert gen._parse_encodings(None) == ([], [], False)
    assert gen._parse_encodings([]) == ([], [], False)
    
    # Single encoding (no boundary)
    assert gen._parse_encodings("gzip") == (["gzip"], [], False)
    assert gen._parse_encodings(["gzip"]) == (["gzip"], [], False)
    assert gen._parse_encodings(["gzip", "h"]) == (["gzip"], [], True)
    
    # List without boundary
    assert gen._parse_encodings(["gzip", "crc32"]) == (["gzip", "crc32"], [], False)
    
    # Boundary at the very start
    assert gen._parse_encodings(["h", "crc32"]) == ([], ["crc32"], True)
    assert gen._parse_encodings([-1, "crc32"]) == ([], ["crc32"], True)
    
    # Boundary in the middle
    assert gen._parse_encodings(["gzip", "h", "crc32"]) == (["gzip"], ["crc32"], True)
    assert gen._parse_encodings(["gzip", -1, "crc32"]) == (["gzip"], ["crc32"], True)
    
    # Boundary at the very end
    assert gen._parse_encodings(["gzip", "h"]) == (["gzip"], [], True)
    assert gen._parse_encodings(["gzip", -1]) == (["gzip"], [], True)
    
    # Multiple elements after boundary
    assert gen._parse_encodings(["gzip", "h", "aes", "crc32"]) == (["gzip"], ["aes", "crc32"], True)
    
    # Unique value as list then boundary
    assert gen._parse_encodings([1, "h", 6]) == ([1], [6], True)

def test_generator_rs_chunk_size():
    # To ensure RS(255,233) chunks are exactly 255 bytes:
    # 1. We must use post-boundary encoding ["h", "rs(255,233)"]
    # 2. Each chunk (header + payload) must be exactly 233 bytes BEFORE RS encoding.
    # 3. PDUGenerator will chunk the content into max_payload_size.
    # 4. We need to account for the header size in each chunk.
    
    # Let's try to target a specific header size.
    # Header: {0: msg_id, 10: orig_id, 9: chunk_id, 11: total, 8: file_size, 1: "CALLSIGN", 5: [-1, "rs(255,233)"]}
    # This header is ~30-40 bytes.
    # If we set max_payload_size = 185, the header + payload will be < 233.
    # rs_encode will pad the 233 block if it's shorter.
    
    gen = PDUGenerator(
        src_callsign="F4JXQ", 
        max_payload_size=185, 
        encodings=["h", "rs(255,233)"]
    )
    
    # 500 bytes of data -> 3 chunks (500 / 180 = 2.77)
    data = b"R" * 500
    pdus = list(gen.generate(data))
    
    assert len(pdus) == 3
    for i, pdu in enumerate(pdus):
        # Each PDU must be N (255)
        assert len(pdu) == 255
        
        # Verify it decodes correctly
        from hqfbp import rs_decode
        dec = rs_decode(pdu, 255, 233)
        assert len(dec) == 233
        
        # The first 233 bytes should be the CBOR header + payload
        # Unpack should work on these 233 bytes because they are not corrupted
        header, payload = unpack(dec)
        assert header[HQFBP_CBOR_KEYS['Chunk-Id']] == i

def test_generator_explicit_chunk_encoding():
    # Test that encodings=["gzip", "chunk(10)", "h"] works even with max_payload_size=None
    gen = PDUGenerator(src_callsign="F4JXQ", encodings=["gzip", "chunk(10)", "h"])
    # 25 bytes of sequential data
    data = bytes([i % 256 for i in range(25)])
    
    pdus = list(gen.generate(data))
    assert len(pdus) > 1
    
    header, _ = unpack(pdus[0])
    # [1, "chunk(10)"] -> "chunk(10)" is stripped in pack() -> just 1
    assert header[HQFBP_CBOR_KEYS['Content-Encoding']] == 1

def test_generator_chunk_position():
    # Case 1: ["gzip", "chunk(10)", "h"] -> gzip applied to WHOLE message
    data = b"ABCDE" * 10 # 50 bytes
    gen1 = PDUGenerator(encodings=["gzip", "chunk(10)", "h"])
    pdus1 = list(gen1.generate(data))
    
    # Case 2: ["chunk(10)", "gzip", "h"] -> gzip applied to EACH chunk
    gen2 = PDUGenerator(encodings=["chunk(10)", "gzip", "h"])
    pdus2 = list(gen2.generate(data))
    
    # Case 1 compresses whole 50 bytes once. Case 2 compresses 10 byte segments.
    assert len(pdus1) < len(pdus2)
    
    h1, p1 = unpack(pdus1[0])
    h2, p2 = unpack(pdus2[0])
    
    assert p1 != p2


def test_generator_repeat():
    # Test that repeat(3) duplicates the data
    gen = PDUGenerator(src_callsign="F4JXQ", encodings=["repeat(3)", "h"])
    data = b"RepeatMe"
    
    pdus = list(gen.generate(data))
    
    # We expect 3 PDUs, each with the same content
    assert len(pdus) == 3
    for pdu in pdus:
        header, payload = unpack(pdu)
        assert payload == data
        # repeat(3) and h should be stripped from the header
        ce = header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
        assert ce is None


def test_generator_h_repeat():
    # Test that repeat(3) duplicates the data
    gen = PDUGenerator(src_callsign="F4JXQ", encodings=["h", "repeat(3)"])
    data = b"RepeatTheFrameWithSameMsgId"
    
    pdus = list(gen.generate(data))
    
    # We expect 3 PDUs, each with the same content AND header
    assert len(pdus) == 3
    for pdu in pdus:
        assert pdu == pdus[0]

def test_generator_rq_encoding():
    # RaptorQ as pre-boundary encoding
    data = b"RaptorQ pre-boundary test"
    mtu = len(data)
    repair_count = 2
    gen = PDUGenerator(src_callsign="F4JXQ", encodings=[f"rq({len(data)}, {mtu}, {repair_count}),h"])
    pdus = list(gen.generate(data))
    
    assert len(pdus) == 3
    header, payload = unpack(pdus[0])
    assert header[HQFBP_CBOR_KEYS['Content-Encoding']] == f"rq({len(data)}, {mtu}, {repair_count}),h"

    packets = []
    for pdu in pdus:
        _, payload = unpack(pdu)
        packets.append(payload)
    
    from hqfbp import rq_decode
    assert rq_decode(packets, len(data), mtu) == data

def test_generator_rq_post_boundary():
    # RaptorQ as post-boundary encoding
    data = b"RaptorQ post-boundary test data"
    rq_len = 80 # must be greater than len(data) + CBOR header
    mtu = rq_len
    repair_count = 4
    gen = PDUGenerator(src_callsign="F4JXQ", encodings=["h", f"rq({rq_len},{mtu},{repair_count})"])
    
    pdus = list(gen.generate(data))
    
    assert mtu >= rq_len
    assert len(pdus) == 1 + repair_count
    
    from hqfbp import rq_decode
    pdu_decompressed = rq_decode(pdus, rq_len, mtu)
    print(pdu_decompressed)
    header, payload = unpack(pdu_decompressed)

    assert header[HQFBP_CBOR_KEYS['Content-Encoding']] == [-1, f"rq({rq_len},{mtu},{repair_count})"]
    assert payload[:len(data)] == data

def test_merge_headers_strips_chunk():
    from hqfbp import merge_headers
    h1 = {
        HQFBP_CBOR_KEYS["Message-Id"]: 1,
        HQFBP_CBOR_KEYS["Content-Encoding"]: ["gzip", "chunk(100)", "h", "crc32"]
    }
    h2 = {
        HQFBP_CBOR_KEYS["Message-Id"]: 2,
        HQFBP_CBOR_KEYS["Original-Message-Id"]: 1,
        HQFBP_CBOR_KEYS["Chunk-Id"]: 1,
        HQFBP_CBOR_KEYS["Content-Encoding"]: ["gzip", "chunk(100)", "h", "crc32"]
    }
    
    merged = merge_headers([h1, h2])
    # Should exclude 0, 9, 10, 11
    assert HQFBP_CBOR_KEYS["Message-Id"] not in merged
    assert HQFBP_CBOR_KEYS["Chunk-Id"] not in merged
    assert HQFBP_CBOR_KEYS["Original-Message-Id"] not in merged
    
    # Should strip chunk(100) but keep the rest
    # Expected: ["gzip", "h", "crc32"]
    assert merged[HQFBP_CBOR_KEYS["Content-Encoding"]] == ["gzip", "h", "crc32"]

def test_generator_rs_alignment():
    # Verify that rs(n, k) automatically triggers chunk(k)
    gen = PDUGenerator(encodings=["rs(255, 233)", "h"])
    data = b"A" * 500
    pdus = list(gen.generate(data))
    
    # Header should contain ["chunk(233)", "rs(255, 233)", "h"] (resolved)
    # But chunk(233) and h are stripped in pack()
    # Wait, rs(n, k) is post-boundary if h is after it. 
    # Let's check _resolve_encodings result
    encs = gen._resolve_encodings()
    assert encs == ["chunk(233)", "rs(255, 233)", "h"]
    
    # In the PDU header, only "rs(255, 233)" (as int if in registry) should remain if it's considered packed
    from hqfbp import unpack, HQFBP_CBOR_KEYS
    header, _ = unpack(pdus[0])
    ce = header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
    # "rs(255, 233)" is likely not in the integer registry yet or it is. 
    # Let's just check it doesn't have chunk(233)
    from hqfbp import CHUNK_RE
    if isinstance(ce, list):
        assert not any(isinstance(e, str) and CHUNK_RE.match(e) for e in ce)
    elif isinstance(ce, str):
        assert not CHUNK_RE.match(ce)
