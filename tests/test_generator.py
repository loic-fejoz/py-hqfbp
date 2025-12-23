import gzip
import pytest
from hqfbp.generator import PDUGenerator
from hqfbp import unpack, HQFBP_CBOR_KEYS

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

# def test_generator_single_gzip_pdu():
#     gen = PDUGenerator(src_callsign="F4JXQ-1", encodings=["gzip"])
#     data = b"Hello World"
    
#     pdus = list(gen.generate(data, content_type="text/plain;charset=utf-8"))
    
#     assert len(pdus) == 1
#     header, payload = unpack(pdus[0])
    
#     assert header[HQFBP_CBOR_KEYS['Message-Id']] == 1
#     assert header[HQFBP_CBOR_KEYS['Src-Callsign']] == "F4JXQ-1"
#     assert payload == gzip.compress(data)

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
