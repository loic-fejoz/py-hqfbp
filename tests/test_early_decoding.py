from hqfbp.deframer import Deframer, MessageEvent
from hqfbp.generator import PDUGenerator


def test_deframer_early_rq_decoding():
    deframer = Deframer()
    data = b"Early RaptorQ decoding test data" * 10  # ~300 bytes

    # Using RQ with 30 bytes MTU and 20 repair packets
    # Source packets: ceil(300 / 30) = 10
    # Total packets: 10 source + 20 repair = 30
    mtu = 30
    repair = 20
    dlen = len(data)

    gen = PDUGenerator(
        src_callsign="EARLY-RQ",
        encodings=[f"rq({dlen}, {mtu}, {repair}),h"],
        announcement_encodings=["identity"],
    )

    pdus = list(gen.generate(data))

    # pdus[0] is announcement
    # pdus[1:11] are source packets
    # pdus[11:] are repair packets

    # 1. Feed announcement
    deframer.receive_bytes(pdus[0])

    # 2. Feed only K source packets (11)
    for pdu in pdus[1:12]:
        deframer.receive_bytes(pdu)

    # Check if decoded early
    found = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found, "Message should be decoded after 11 packets"


def test_deframer_early_rq_with_loss():
    deframer = Deframer()
    data = b"RaptorQ early decoding with loss" * 5
    mtu = 20
    repair = 10
    dlen = len(data)

    gen = PDUGenerator(
        src_callsign="RQ-LOSS",
        encodings=[f"rq({dlen}, {mtu}, {repair}),h"],
        announcement_encodings=["identity"],
    )

    pdus = list(gen.generate(data))
    # K = ceil(160 / 20) = 8

    deframer.receive_bytes(pdus[0])

    # Lose some source packets but keep enough total
    # Receive packets 1, 3, 5, 7, 9, 11, 13, 15 (8 packets total)
    for i in [1, 3, 5, 7, 9, 11, 13, 15]:
        deframer.receive_bytes(pdus[i])

    found = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found, "Should decode with 8 symbols even if some source packets are missing"


def test_deframer_rq_wait_for_enough_symbols():
    deframer = Deframer()
    data = b"Wait for symbols" * 10
    mtu = 50
    repair = 5
    dlen = len(data)
    # K = ceil(160 / 50) = 4

    gen = PDUGenerator(
        src_callsign="RQ-WAIT",
        encodings=[f"rq({dlen}, {mtu}, {repair}),h"],
        announcement_encodings=["identity"],
    )

    pdus = list(gen.generate(data))
    deframer.receive_bytes(pdus[0])

    # Feed 3 packets (not enough)
    for pdu in pdus[1:4]:
        deframer.receive_bytes(pdu)

    # No MessageEvent yet
    while deframer.next_event():
        pass
    assert len(deframer._sessions) == 1

    # Feed 4th packet
    deframer.receive_bytes(pdus[4])

    found = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found
    assert len(deframer._sessions) == 0
