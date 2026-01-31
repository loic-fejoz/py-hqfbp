from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent
from hqfbp import HQFBP_CBOR_KEYS

def test_post_asm_roundtrip():
    sync_word = b"\x1A\xCF\xFC\x1D"
    sync_word_hex = "0x1acfvc1d" 
    # The hex for 1A CF FC 1D
    sync_word_hex = "0x1acffc1d"
    
    gen = PDUGenerator(src_callsign="F4JXQ", encodings=["h", f"post_asm({sync_word_hex})"])
    data = b"Hello with Post-ASM"
    
    pdus = list(gen.generate(data))
    assert len(pdus) == 1
    
    # Verify the sync word is at the end of the PDU
    pdu = pdus[0]
    assert pdu.endswith(sync_word)
    
    # Deframe
    deframer = Deframer()
    deframer.receive_bytes(pdu)
    
    events = []
    while True:
        e = deframer.next_event()
        if not e:
            break
        events.append(e)
    
    assert any(isinstance(e, MessageEvent) for e in events)
    msg_ev = next(e for e in events if isinstance(e, MessageEvent))
    assert msg_ev.payload == data
    
    # Check header
    header = msg_ev.header
    # post_asm should be in content-encoding
    ce = header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
    assert f"post_asm({sync_word_hex})" in str(ce)

def test_post_asm_integer():
    # Test with integer sync word
    sync_word_int = 0xAA55
    sync_word = b"\xaa\x55"
    
    gen = PDUGenerator(src_callsign="F4JXQ", encodings=["h", f"post_asm({sync_word_int})"])
    data = b"Hello with Integer Post-ASM"
    
    pdus = list(gen.generate(data))
    assert len(pdus) == 1
    assert pdus[0].endswith(sync_word)
    
    deframer = Deframer()
    deframer.receive_bytes(pdus[0])
    
    events = []
    while True:
        e = deframer.next_event()
        if not e:
            break
        events.append(e)
        
    assert any(isinstance(e, MessageEvent) for e in events)
    msg_ev = next(e for e in events if isinstance(e, MessageEvent))
    assert msg_ev.payload == data
