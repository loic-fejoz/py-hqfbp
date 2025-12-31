import pytest
from hqfbp import scr_xor
from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent

def test_scrambler_roundtrip():
    data = b"Scrambler test data with some zeros: \x00\x00\x00\x00"
    poly = 0x1FF # NASA-like 9-bit polynomial
    
    encoded = scr_xor(data, poly)
    assert encoded != data
    
    decoded = scr_xor(encoded, poly)
    assert decoded == data

def test_scrambler_whitening():
    # Long string of zeros should become high-entropy with a good polynomial
    data = b"\x00" * 100
    # PRBS-9: x^9 + x^5 + 1 -> binary 100010000 (bits 8 and 4 set) -> 0x110
    poly = 0x110
    
    encoded = scr_xor(data, poly)
    
    # Check that we don't have too many zeros
    zero_count = encoded.count(0)
    # Statically, should be around 50/100.
    assert zero_count < 70
    # And it should have many different values
    assert len(set(encoded)) > 10

def test_generator_deframer_scrambler_integration():
    deframer = Deframer()
    data = b"End-to-end scrambling test"
    # G3RUH-like: x^17 + x^12 + 1 -> 0x10800
    poly = 0x10800
    
    gen = PDUGenerator(
        src_callsign="SCR-TEST",
        encodings=[f"scr({hex(poly)})", "h"],
        announcement_encodings=["identity"]
    )
    
    pdus = list(gen.generate(data))
    
    # Feed announcement
    deframer.receive_bytes(pdus[0])
    
    # Feed data PDU
    deframer.receive_bytes(pdus[1])
    
    found = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found

def test_scrambler_different_polynomials():
    data = b"Testing different polynomials"
    # Use two different primitive polynomials
    p1 = 0x110 # x^9 + x^5 + 1
    p2 = 0x10800 # x^17 + x^12 + 1
    
    e1 = scr_xor(data, p1)
    e2 = scr_xor(data, p2)
    
    assert e1 != e2
    assert scr_xor(e1, p1) == data
    assert scr_xor(e2, p2) == data
