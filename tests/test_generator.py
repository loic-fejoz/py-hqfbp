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
    
    # Check first chunk
    h0, p0 = unpack(pdus[0])
    assert h0[HQFBP_CBOR_KEYS['Chunk-Id']] == 0
    assert h0[HQFBP_CBOR_KEYS['Total-Chunks']] == 6
    assert h0[HQFBP_CBOR_KEYS['Original-Message-Id']] == h0[HQFBP_CBOR_KEYS['Message-Id']]
    assert len(p0) == 10
    
    # Check last chunk
    h5, p5 = unpack(pdus[5])
    assert h5[HQFBP_CBOR_KEYS['Chunk-Id']] == 5
    assert h5[HQFBP_CBOR_KEYS['Message-Id']] > h0[HQFBP_CBOR_KEYS['Message-Id']]
    assert h5[HQFBP_CBOR_KEYS['Original-Message-Id']] == h0[HQFBP_CBOR_KEYS['Message-Id']]
    assert len(p5) == 4 # 54 % 10

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
    assert header[HQFBP_CBOR_KEYS['Content-Encoding']] == 1 # ["gzip", "h"] optimized to 1

def test_generator_crc_payload_only():
    # Pre-boundary CRC (payload only)
    gen = PDUGenerator(encodings=["crc32"])
    data = b"payload test"
    pdus = list(gen.generate(data))
    
    _, payload = unpack(pdus[0])
    # The whole payload should have CRC at the end
    assert verify_and_strip_crc(payload, "crc32") == data

def test_generator_crc_covering_header():
    # Post-boundary CRC (covering header + payload)
    gen = PDUGenerator(encodings=["h", "crc32"])
    data = b"covered test"
    pdus = list(gen.generate(data))
    
    # The whole PDU should have CRC at the end
    pdu = pdus[0]
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
        encodings=["gzip", "h", "crc32"],
        announcement_encodings=["crc16"]
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
    # It should announce the next message ID and its encodings
    assert ann_p[HQFBP_CBOR_KEYS['Message-Id']] == 2 # Announcement is 1, data is 2
    assert ann_p[HQFBP_CBOR_KEYS['Content-Encoding']] == [1, -1, 6]
    
    # 2. Verify Data PDU
    data_pdu = pdus[1]
    data_pdu_no_crc = verify_and_strip_crc(data_pdu, "crc32")
    data_h, data_p = unpack(data_pdu_no_crc)
    
    assert data_h[HQFBP_CBOR_KEYS['Message-Id']] == 2
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
