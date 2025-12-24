import pytest
from hqfbp import rq_encode, rq_decode, pack, unpack, HQFBP_CBOR_KEYS
from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent, PDUEvent

def test_rq_basic_encode_decode():
    data = b"Hello RaptorQ! " * 10 # 150 bytes
    mtu = 10
    repair = 2
    
    encoded = rq_encode(data, mtu, repair)
    decoded = rq_decode(encoded, mtu, repair)
    
    assert decoded == data

def test_rq_with_loss():
    data = b"Resilient Data Transmission" * 5 # 135 bytes
    mtu = 10
    repair = 5
    
    encoded = rq_encode(data, mtu, repair)
    
    # Prepend 4 bytes length overhead
    length_overhead = encoded[:4]
    payload = encoded[4:]
    packet_size = mtu + 4
    
    packets = [payload[i:i+packet_size] for i in range(0, len(payload), packet_size)]
    
    # We should have ceil(135/10) = 14 source packets + 5 repair = 19 packets
    assert len(packets) == 19
    
    # Simulate losing 3 packets (we still have 16, which is > 14)
    del packets[2]
    del packets[5]
    del packets[10]
    
    corrupted_encoded = length_overhead + b"".join(packets)
    
    # Decoding should still work
    decoded = rq_decode(corrupted_encoded, mtu, repair)
    assert decoded == data

def test_generator_deframer_rq():
    data = b"End-to-end RaptorQ test data" * 10
    gen = PDUGenerator(
        src_callsign="F4JXQ",
        encodings=["h", "rq(20, 5)"], # 20 bytes MTU, 5 repair packets
        announcement_encodings=["identity"]
    )
    
    pdus = list(gen.generate(data))
    
    assert len(pdus) == 2
    
    deframer = Deframer()
    for pdu in pdus:
        deframer.receive_bytes(pdu)
    
    found = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found

def test_rq_decode_insufficient_symbols():
    data = b"Limited redundancy"
    mtu = 4
    repair = 1
    
    encoded = rq_encode(data, mtu, repair)
    
    # Lose too many packets
    length_overhead = encoded[:4]
    payload = encoded[4:]
    packet_size = mtu + 4
    packets = [payload[i:i+packet_size] for i in range(0, len(payload), packet_size)]
    
    # Need 5 source packets. We have 5+1=6. Lose 2.
    del packets[0]
    del packets[1]
    
    corrupted = length_overhead + b"".join(packets)
    
    with pytest.raises(ValueError, match="insufficient symbols"):
        rq_decode(corrupted, mtu, repair)
