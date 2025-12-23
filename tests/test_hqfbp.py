import pytest
import gzip
import lzma
from hqfbp import pack, unpack, merge_headers, get_coap_id

def test_simple_pack_unpack():
    # Example 1 style
    src_callsign = "FOSM-1"
    content = "Autour de la terre, je pense aux élèves scrutant l'horizon.".encode('utf-8')
    header = {
        "Message-Id": 1,
        "Src-Callsign": src_callsign
    }
    
    pdu = pack(header, content)
    
    decoded_header, decoded_payload = unpack(pdu)
    
    assert decoded_header[0] == 1
    assert decoded_header[1] == src_callsign
    assert decoded_payload == content

def test_mandatory_msg_id():
    with pytest.raises(ValueError, match="Message-Id.*mandatory"):
        pack({"Src-Callsign": "N0CALL"}, b"data")

def test_chunking_and_merging():
    # Example 2 style
    lorem = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    chunk1_data = lorem[:len(lorem)//2]
    chunk2_data = lorem[len(lorem)//2:]
    
    h1 = {
        "Message-Id": 1001,
        "Original-Message-Id": 1001,
        "Chunk-Id": 0,
        "Total-Chunks": 2,
        "File-Size": len(lorem),
        "Content-Type": "text/plain"
    }
    
    h2 = {
        "Message-Id": 1002,
        "Original-Message-Id": 1001,
        "Chunk-Id": 1,
        "Total-Chunks": 2,
        "Repr-Digest": b"somehash"
    }
    
    pdu1 = pack(h1, chunk1_data)
    pdu2 = pack(h2, chunk2_data)
    
    dec_h1, _ = unpack(pdu1)
    dec_h2, _ = unpack(pdu2)
    
    merged = merge_headers([dec_h1, dec_h2])
    
    assert merged[4] == "text/plain"  # Content-Type from h1
    assert merged[6] == b"somehash"   # Repr-Digest from h2
    assert merged[8] == len(lorem)   # File-Size from h1
    # Chunking params should be excluded from final merged global header
    assert 9 not in merged
    assert 10 not in merged

def test_content_encoding():
    # Example 3.a/b style
    content = b"Compressed data"
    compressed = gzip.compress(content)
    
    header = {
        0: 1,
        5: "gzip"
    }
    
    pdu = pack(header, compressed)
    dec_h, dec_p = unpack(pdu)
    
    assert dec_h[5] == 1 # Optimized from "gzip"
    assert gzip.decompress(dec_p) == content

def test_coap_id():
    assert get_coap_id("image/png") == 23
    assert get_coap_id("text/plain;charset=utf-8") == 0
    assert get_coap_id("unknown/type") is None

def test_inconsistent_merge():
    h1 = {0: 1, 1: "CALL-1", 9: 0}
    h2 = {0: 2, 1: "CALL-2", 9: 1} # Different SRC
    
    with pytest.raises(ValueError, match="Inconsistent"):
        merge_headers([h1, h2])

def test_human_readable_json():
    from hqfbp import human_readable_json
    
    header = {
        0: 1001,
        1: "FOSM-1",
        3: 23, # image/png
        5: [1, -1, "rs(255,233)"], # gzip, boundary, custom string
        8: 4032
    }
    
    readable = human_readable_json(header)
    
    assert readable["Message-Id"] == 1001
    assert readable["Src-Callsign"] == "FOSM-1"
    assert readable["Content-Type"] == "image/png"
    assert "Content-Format" not in readable
    assert readable["Content-Encoding"] == ["gzip", "h", "rs(255,233)"]
    assert readable["File-Size"] == 4032

def test_human_readable_json_content_type():
    from hqfbp import human_readable_json
    # Test that Content-Type (4) is also handled if present
    h1 = {0: 1, 4: "text/markdown"}
    r1 = human_readable_json(h1)
    assert r1["Content-Type"] == "text/markdown"
    
    # Test precedence or merge (Content-Format 3 should probably win or handle both)
    # In my implementation, I check 3 and if it exists it replaces current content_type_val
    h2 = {0: 1, 3: 50} # application/json
    r2 = human_readable_json(h2)
    assert r2["Content-Type"] == "application/json"

def test_pack_optimization():
    from hqfbp import pack, unpack
    
    # Test 1: Content-Type string to CoAP ID (png -> 23)
    p1 = pack({0: 1, "Content-Type": "image/png"}, b"pngdata")
    h1, _ = unpack(p1)
    assert 4 not in h1
    assert h1[3] == 23
    
    # Test 2: Content-Encoding strings to IDs (strips trailing 'h')
    p2 = pack({0: 2, "Content-Encoding": ["gzip", "h"]}, b"gzdata")
    h2, _ = unpack(p2)
    assert h2[5] == 1
    
    # Test 3: Omit default Content-Format 0 / text/plain
    p3 = pack({0: 3, "Content-Type": "text/plain;charset=utf-8"}, b"text")
    h3, _ = unpack(p3)
    assert 3 not in h3
    assert 4 not in h3
    
    # Test 4: Single string encoding
    p4 = pack({0: 4, "Content-Encoding": "lzma"}, b"lzmadata")
    h4, _ = unpack(p4)
    assert h4[5] == 4

def test_pack_trailing_h():
    from hqfbp import pack, unpack
    
    # Test case 1: ["gzip", "h"] -> should be 1
    p1 = pack({0: 1, "Content-Encoding": ["gzip", "h"]}, b"data")
    h1, _ = unpack(p1)
    assert h1[5] == 1
    
    # Test case 2: ["h"] -> should be removed
    p2 = pack({0: 2, "Content-Encoding": ["h"]}, b"data")
    h2, _ = unpack(p2)
    assert 5 not in h2
    
    # Test case 3: ["gzip", "h", "crc32"] -> should remain [1, -1, 6]
    p3 = pack({0: 3, "Content-Encoding": ["gzip", "h", "crc32"]}, b"data")
    h3, _ = unpack(p3)
    assert h3[5] == [1, -1, 6]
    
    # Test case 4: multiple trailing h -> strip all
    p4 = pack({0: 4, "Content-Encoding": ["gzip", "h", "h"]}, b"data")
    h4, _ = unpack(p4)
    assert h4[5] == 1
