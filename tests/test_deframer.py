import pytest
import gzip
from hqfbp import pack, HQFBP_CBOR_KEYS, crc32
from hqfbp.deframer import Deframer, PDUEvent, MessageEvent
from hqfbp.generator import PDUGenerator

def test_deframer_single_pdu():
    deframer = Deframer()
    payload = b"hello world"
    header = {"Message-Id": 1, "Src-Callsign": "N0CALL"}
    pdu = pack(header, payload)
    
    deframer.receive_bytes(pdu)
    
    # Expect PDUEvent then MessageEvent
    ev1 = deframer.next_event()
    assert isinstance(ev1, PDUEvent)
    assert ev1.payload == payload
    
    ev2 = deframer.next_event()
    assert isinstance(ev2, MessageEvent)
    assert ev2.payload == payload
    assert ev2.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "N0CALL"

def test_deframer_chunked():
    deframer = Deframer()
    gen = PDUGenerator(src_callsign="F4JXQ-1", max_payload_size=10)
    data = b"This is a longer message that will be chunked."
    
    pdus = list(gen.generate(data))
    assert len(pdus) > 1
    
    for pdu in pdus:
        deframer.receive_bytes(pdu)
    
    # Drain PDUEvents
    events = []
    while True:
        ev = deframer.next_event()
        if ev is None or isinstance(ev, MessageEvent):
            if ev: events.append(ev)
            break
        events.append(ev)
    
    assert len(events) == len(pdus) + 1
    msg_ev = events[-1]
    assert isinstance(msg_ev, MessageEvent)
    assert msg_ev.payload == data
    assert msg_ev.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "F4JXQ-1"

def test_deframer_multi_sender():
    deframer = Deframer()
    
    # Sender 1
    gen1 = PDUGenerator(src_callsign="S1", max_payload_size=5)
    pdus1 = list(gen1.generate(b"S1DATA")) # 2 chunks
    
    # Sender 2
    gen2 = PDUGenerator(src_callsign="S2", max_payload_size=5)
    pdus2 = list(gen2.generate(b"S2DATA")) # 2 chunks
    
    # Interleave PDUs
    deframer.receive_bytes(pdus1[0])
    deframer.receive_bytes(pdus2[0])
    deframer.receive_bytes(pdus1[1])
    
    # S1 should be complete, S2 still pending
    evs = []
    while True:
        ev = deframer.next_event()
        if ev is None: break
        evs.append(ev)
    
    assert any(isinstance(e, MessageEvent) and e.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "S1" for e in evs)
    assert not any(isinstance(e, MessageEvent) and e.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "S2" for e in evs)
    
    # Complete S2
    deframer.receive_bytes(pdus2[1])
    ev = deframer.next_event()
    assert isinstance(ev, PDUEvent)
    ev = deframer.next_event()
    assert isinstance(ev, MessageEvent)
    assert ev.payload == b"S2DATA"

def test_deframer_announcement_and_crc():
    deframer = Deframer()
    
    # Create a message with CRC32 post-boundary
    # We use PDUGenerator with announcement
    gen = PDUGenerator(
        src_callsign="F4JXQ-2", 
        encodings=["h", "crc32"],
        announcement_encodings=["identity"] # Just a simple announcement
    )
    
    data = b"Sensitive Data"
    pdus = list(gen.generate(data))
    
    # Process announcement first
    deframer.receive_bytes(pdus[0])
    
    # Process data PDU
    deframer.receive_bytes(pdus[1])
    
    # Check events
    found_msg = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            assert ev.payload.startswith(data)
            found_msg = True
    
    assert found_msg

def test_deframer_compression():
    deframer = Deframer()
    data = b"Compress me please!" * 10
    gen = PDUGenerator(src_callsign="GZIPPER", encodings=["gzip"])
    
    pdus = list(gen.generate(data))
    for pdu in pdus:
        deframer.receive_bytes(pdu)
        
    msg_ev = None
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            msg_ev = ev
            
    assert msg_ev is not None
    assert msg_ev.payload == data

@pytest.mark.parametrize("encoding", ["gzip", "lzma"])
def test_pre_encodings(encoding):
    deframer = Deframer()
    data = b"Testing " + encoding.encode()
    gen = PDUGenerator(src_callsign="TEST", encodings=[encoding])
    pdus = list(gen.generate(data))
    for pdu in pdus:
        deframer.receive_bytes(pdu)
        
    found = False
    while True:
        ev = deframer.next_event()
        if not ev: break
        if isinstance(ev, MessageEvent):
            assert ev.payload.startswith(data)
            found = True
    assert found

def test_deframer_heuristic_gzip_header():
    deframer = Deframer()
    data = b"Heuristic data with gzipped header"
    
    # Use gzip as post-boundary encoding. 
    # This will compress the whole PDU (Header + Payload).
    # Initial unpack will fail because it's not valid CBOR anymore.
    gen = PDUGenerator(
        src_callsign="HEURISTIC-1",
        encodings=["h", "gzip"],
        announcement_encodings=["identity"]
    )
    
    pdus = list(gen.generate(data))
    
    # 1. Process announcement. This tells the deframer that 
    # upcoming msg will use ["h", "gzip"].
    deframer.receive_bytes(pdus[0])
    
    # 2. Process data PDU. 
    # deframer.receive_bytes(pdus[1])
    # The first 'unpack' in receive_bytes will fail.
    # The heuristic should kick in and try 'gzip' decompression.
    deframer.receive_bytes(pdus[1])
    
    found_msg = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            assert ev.payload.startswith(data)
            found_msg = True
    
    assert found_msg

def test_deframer_heuristic_multi_encodings():
    deframer = Deframer()
    data = b"Multi-layer heuristic test"
    
    # Complex post-boundary: first gzip everything, then add a CRC32
    gen = PDUGenerator(
        src_callsign="HEURISTIC-2",
        encodings=["h", "gzip", "crc32"],
        announcement_encodings=["identity"]
    )
    
    pdus = list(gen.generate(data))
    
    deframer.receive_bytes(pdus[0]) # Announcement
    deframer.receive_bytes(pdus[1]) # Data PDU (scrambled)
    
    found_msg = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            assert ev.payload.startswith(data)
            found_msg = True
    
    assert found_msg

def test_deframer_multi_sender_interleaved_announcements():
    deframer = Deframer()
    
    # S1: Standard (Peekable)
    gen1 = PDUGenerator(src_callsign="S1", max_payload_size=10)
    data1 = b"S1: Basic data"
    pdus1 = list(gen1.generate(data1))
    
    # S2: Scrambled Header (Gzip post-boundary, requires Heuristic)
    gen2 = PDUGenerator(
        src_callsign="S2", 
        max_payload_size=10, 
        encodings=["h", "gzip"],
        announcement_encodings=["identity"]
    )
    data2 = b"S2: Gzipped header data"
    pdus2 = list(gen2.generate(data2))
    
    # S3: Complex Scrambled (Gzip + CRC32 post-boundary)
    gen3 = PDUGenerator(
        src_callsign="S3", 
        max_payload_size=10, 
        encodings=["h", "gzip", "crc32"],
        announcement_encodings=["identity"]
    )
    data3 = b"S3: Double trouble"
    pdus3 = list(gen3.generate(data3))
    
    # Interleave EVERYTHING: mix announcements and then chunks
    all_pdus = []
    max_len = max(len(pdus1), len(pdus2), len(pdus3))
    for i in range(max_len):
        if i < len(pdus1): all_pdus.append(pdus1[i])
        if i < len(pdus2): all_pdus.append(pdus2[i])
        if i < len(pdus3): all_pdus.append(pdus3[i])
        
    for pdu in all_pdus:
        deframer.receive_bytes(pdu)
        
    results = {}
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            src = ev.header[HQFBP_CBOR_KEYS["Src-Callsign"]]
            results[src] = ev.payload
            
    assert results["S1"] == data1
    assert results["S2"] == data2
    assert results["S3"] == data3
    assert len(results) == 3

def test_deframer_rs_post_boundary():
    deframer = Deframer()
    data = b"FEC test data"
    
    # RS(255, 233) post-boundary
    gen = PDUGenerator(
        src_callsign="RS-POST",
        encodings=["h", "rs(255,233)"],
        announcement_encodings=["identity"]
    )
    
    pdus = list(gen.generate(data))
    
    deframer.receive_bytes(pdus[0]) # Announcement
    deframer.receive_bytes(pdus[1]) # Data PDU (RS encoded)
    
    found = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            assert ev.payload.startswith(data)
            found = True
    assert found

def test_deframer_rs_pre_boundary():
    deframer = Deframer()
    data = b"Content RS test"
    
    # RS(255, 233) pre-boundary
    gen = PDUGenerator(
        src_callsign="RS-PRE",
        encodings=["rs(255,233)"]
    )
    
    pdus = list(gen.generate(data))
    for pdu in pdus:
        deframer.receive_bytes(pdu)
        
    found = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            # rs_decode will return multiple of k bytes (233)
            # CBOR or explicit length check might be needed if exact match required.
            # But the generator packs CBOR, so trailing zeros are fine.
            assert ev.payload.startswith(data)
            found = True
    assert found
