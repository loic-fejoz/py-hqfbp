import pytest
from hqfbp import conv_encode, conv_decode
from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent
import random

def test_conv_roundtrip():
    data = b"Hello Convolutional World!"
    encoded = conv_encode(data, k=7, rate="1/2")
    # conv(7, 1/2) adds K-1=6 bits of flush, result should be roughly twice the size
    # data: 26 bytes = 208 bits. 208 + 6 = 214 bits in. 214 * 2 = 428 bits out.
    # 428 bits = 53.5 bytes -> 54 bytes.
    assert len(encoded) >= len(data) * 2
    
    decoded, _ = conv_decode(encoded, k=7, rate="1/2")
    assert decoded == data

def test_conv_error_correction():
    data = b"FEC test"
    encoded = bytearray(conv_encode(data, k=7, rate="1/2"))
    
    # Flip one bit and see if it recovers
    # (Viterbi with K=7 is quite robust)
    encoded[5] ^= 0x01
    
    decoded, _ = conv_decode(bytes(encoded), k=7, rate="1/2")
    assert decoded == data

def test_conv_multiple_errors():
    data = b"More errors to handle"
    encoded = bytearray(conv_encode(data, k=7, rate="1/2"))
    
    # Flip several bits at different positions
    # K=7 can handle multiple errors if they are sparse
    encoded[2] ^= 0x40
    encoded[10] ^= 0x02
    encoded[20] ^= 0x80
    
    decoded, _ = conv_decode(bytes(encoded), k=7, rate="1/2")
    assert decoded == data

def test_generator_deframer_conv_integration():
    deframer = Deframer()
    data = b"End-to-end convolutional test"
    
    gen = PDUGenerator(
        src_callsign="CONV-TEST",
        encodings=["conv(7,1/2)", "h"],
        announcement_encodings=["identity"]
    )
    
    pdus = list(gen.generate(data))
    
    # Feed announcement
    deframer.receive_bytes(pdus[0])
    
    # Feed data PDU (with some noise)
    pdu_with_noise = bytearray(pdus[1])
    # Flip a bit in the payload (header is likely OK if we don't hit it, 
    # but Viterbi covers everything after the boundary if applied as such)
    # Actually PDUGenerator applies it to the whole chunk before packing? 
    # Let's check generator code.
    # In generate: chunks = self._apply_encodings(c, [enc])
    # The output of conv_encode is binary.
    
    pdu_with_noise[len(pdu_with_noise)//2] ^= 0x01
    
    deframer.receive_bytes(bytes(pdu_with_noise))
    
    found = False
    while True:
        ev = deframer.next_event()
        if ev is None: break
        if isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found
