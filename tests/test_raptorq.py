import math
import pytest
from hqfbp import rq_encode, rq_decode, pack, unpack, HQFBP_CBOR_KEYS
from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent, PDUEvent

def test_rq_basic_encode_decode():
    data = b"Hello RaptorQ! " * 10 # 150 bytes
    mtu = 10
    repair = 2
    
    encoded = rq_encode(data, len(data), mtu, repair)
    decoded = rq_decode(encoded, len(data), mtu)
    
    assert decoded == data

def test_rq_with_loss():
    data = b"Resilient Data Transmission" * 5 # 135 bytes
    mtu = 10
    repair = 5
    
    packets = rq_encode(data, len(data), mtu, repair)
 
    # We should have ceil(135/10) = 14 source packets + 5 repair = 19 packets
    assert len(packets) == 19
    
    # Simulate losing 3 packets (we still have 16, which is > 14)
    del packets[2]
    del packets[5]
    del packets[10]
    
    # Decoding should still work
    decoded = rq_decode(packets, len(data), mtu)
    assert decoded == data

def test_generator_deframer_rq_post_boundary():
    data = b"End-to-end RaptorQ test data" * 1
    rq_len = len(data) + 45 # Must be greater than len(data + CBOR header)
    mtu = rq_len+60
    repair_count = 5
    gen = PDUGenerator(
        src_callsign="F4JXQ",
        encodings=["h", f"rq({rq_len}, {mtu}, {repair_count})"],
        announcement_encodings=["identity"]
    )
    
    pdus = list(gen.generate(data))
    
    assert len(pdus) > 1 + repair_count # Announcement + repair packets
    
    deframer = Deframer()
    for pdu in pdus:
        deframer.receive_bytes(pdu)
    
    found = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            assert ev.payload.startswith(data)
            found = True
    assert found, "Message not deframed"

def test_rq_decode_insufficient_symbols():
    data = b"Limited redundancy"
    mtu = 4
    repair = 1
    
    packets = rq_encode(data, len(data), mtu, repair)
    
    # Need 5 source packets. We have 5+1=6. Lose 2.
    del packets[0]
    del packets[1]
    
    with pytest.raises(ValueError, match="insufficient symbols"):
        rq_decode(packets, len(data), mtu)
