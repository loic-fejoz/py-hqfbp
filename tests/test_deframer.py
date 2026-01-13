import pytest
from hqfbp import pack, unpack, HQFBP_CBOR_KEYS
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

    pdu_events = []
    msg_ev = None
    processed_pdus = 0

    prev_msg_id = None
    first_orig_msg_id = None

    for i, pdu in enumerate(pdus):
        deframer.receive_bytes(pdu)
        processed_pdus += 1

        # Check that we get exactly one PDUEvent per receive_bytes
        ev = deframer.next_event()
        assert isinstance(ev, PDUEvent)
        h, p = unpack(pdu)
        assert ev.payload == p

        # Check Message-Id monotonicity in PDUs
        curr_msg_id = ev.header[HQFBP_CBOR_KEYS["Message-Id"]]
        if prev_msg_id is not None:
            assert curr_msg_id == prev_msg_id + 1
        prev_msg_id = curr_msg_id

        # Check Original-Message-Id consistency
        orig_id = ev.header[HQFBP_CBOR_KEYS["Original-Message-Id"]]
        if first_orig_msg_id is None:
            first_orig_msg_id = orig_id
        assert orig_id == first_orig_msg_id

        pdu_events.append(ev)

        # Check that MessageEvent is NOT emitted until the last chunk
        msg_ev = deframer.next_event()
        if i < len(pdus) - 1:
            assert msg_ev is None
        else:
            assert isinstance(msg_ev, MessageEvent)

    assert len(pdu_events) == len(pdus)
    assert msg_ev.payload == data
    assert msg_ev.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "F4JXQ-1"
    # Message-Id, Chunk-Id, Original-Message-Id, Total-Chunks are excluded from merged header
    assert HQFBP_CBOR_KEYS["Message-Id"] not in msg_ev.header
    assert HQFBP_CBOR_KEYS["Chunk-Id"] not in msg_ev.header
    assert HQFBP_CBOR_KEYS["Original-Message-Id"] not in msg_ev.header
    assert HQFBP_CBOR_KEYS["Total-Chunks"] not in msg_ev.header

    # Content-Encoding should NOT contain any chunk(size) markers
    if HQFBP_CBOR_KEYS["Content-Encoding"] in msg_ev.header:
        ce = msg_ev.header[HQFBP_CBOR_KEYS["Content-Encoding"]]
        from hqfbp import CHUNK_RE

        if isinstance(ce, list):
            assert not any(isinstance(e, str) and CHUNK_RE.match(e) for e in ce)
        elif isinstance(ce, str):
            assert not CHUNK_RE.match(ce)


def test_deframer_multi_sender():
    deframer = Deframer()

    # Sender 1
    gen1 = PDUGenerator(src_callsign="S1", max_payload_size=5)
    pdus1 = list(gen1.generate(b"S1DATA"))  # 2 chunks

    # Sender 2
    gen2 = PDUGenerator(src_callsign="S2", max_payload_size=5)
    pdus2 = list(gen2.generate(b"S2DATA"))  # 2 chunks

    # Interleave PDUs
    deframer.receive_bytes(pdus1[0])
    deframer.receive_bytes(pdus2[0])
    deframer.receive_bytes(pdus1[1])

    # Drain events
    events = []
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        events.append(ev)

    # S1 should be complete (PDU, PDU, PDU, Message) - wait
    # pdus1[0] -> PDUEvent
    # pdus2[0] -> PDUEvent
    # pdus1[1] -> PDUEvent, MessageEvent (S1)

    # Verify S1 completion
    s1_messages = [
        e
        for e in events
        if isinstance(e, MessageEvent)
        and e.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "S1"
    ]
    assert len(s1_messages) == 1
    assert s1_messages[0].payload == b"S1DATA"

    # Verify S2 NOT complete
    s2_messages = [
        e
        for e in events
        if isinstance(e, MessageEvent)
        and e.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "S2"
    ]
    assert len(s2_messages) == 0

    # Complete S2
    deframer.receive_bytes(pdus2[1])
    ev_pdu = deframer.next_event()
    assert isinstance(ev_pdu, PDUEvent)
    ev_msg = deframer.next_event()
    assert isinstance(ev_msg, MessageEvent)
    assert ev_msg.payload == b"S2DATA"
    assert ev_msg.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "S2"


def test_deframer_announcement_and_crc():
    deframer = Deframer()

    # Create a message with CRC32 post-boundary
    # We use PDUGenerator with announcement
    gen = PDUGenerator(
        src_callsign="F4JXQ-2",
        encodings=["h", "crc32"],
        announcement_encodings=["identity"],  # Just a simple announcement
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
        if ev is None:
            break
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
        if ev is None:
            break
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
        if not ev:
            break
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
        announcement_encodings=["identity"],
    )

    pdus = list(gen.generate(data))

    # 1. Process announcement. This tells the deframer that
    # upcoming msg will use ["h", "gzip"].
    deframer.receive_bytes(pdus[0])

    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, PDUEvent):
            assert ev.header[HQFBP_CBOR_KEYS["Src-Callsign"]] == "HEURISTIC-1"

    # 2. Process data PDU.
    # deframer.receive_bytes(pdus[1])
    # The first 'unpack' in receive_bytes will fail.
    # The heuristic should kick in and try 'gzip' decompression.
    deframer.receive_bytes(pdus[1])

    found_msg = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
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
        announcement_encodings=["identity"],
    )

    pdus = list(gen.generate(data))

    deframer.receive_bytes(pdus[0])  # Announcement
    deframer.receive_bytes(pdus[1])  # Data PDU (scrambled)

    found_msg = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
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
        announcement_encodings=["identity"],
    )
    data2 = b"S2: Gzipped header data"
    pdus2 = list(gen2.generate(data2))

    # S3: Complex Scrambled (Gzip + CRC32 post-boundary)
    gen3 = PDUGenerator(
        src_callsign="S3",
        max_payload_size=10,
        encodings=["h", "gzip", "crc32"],
        announcement_encodings=["identity"],
    )
    data3 = b"S3: Double trouble"
    pdus3 = list(gen3.generate(data3))

    # Interleave EVERYTHING: mix announcements and then chunks
    all_pdus = []
    max_len = max(len(pdus1), len(pdus2), len(pdus3))
    for i in range(max_len):
        if i < len(pdus1):
            all_pdus.append(pdus1[i])
        if i < len(pdus2):
            all_pdus.append(pdus2[i])
        if i < len(pdus3):
            all_pdus.append(pdus3[i])

    for pdu in all_pdus:
        deframer.receive_bytes(pdu)

    results = {}
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
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
        announcement_encodings=["identity"],
    )

    pdus = list(gen.generate(data))

    announcement_pdu = pdus[0]
    data_pdu = bytearray(pdus[1])

    # Intentionally corrupt the data PDU
    # RS(255, 233) can correct (255-233)/2 = 11 errors.
    # Let's corrupt 5 bytes.
    for i in range(5):
        data_pdu[i + 10] ^= 0xFF

    deframer.receive_bytes(announcement_pdu)  # Announcement
    deframer.receive_bytes(bytes(data_pdu))  # Corrupted Data PDU (RS encoded)

    found = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, MessageEvent):
            assert ev.payload.startswith(data)
            found = True
    assert found


def test_deframer_rs_pre_boundary():
    deframer = Deframer()
    data = b"Content RS test"

    # RS(255, 233) pre-boundary
    gen = PDUGenerator(src_callsign="RS-PRE", encodings=["rs(255,233)"])

    pdus = list(gen.generate(data))
    for pdu in pdus:
        deframer.receive_bytes(pdu)

    found = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, MessageEvent):
            # rs_decode will return multiple of k bytes (233)
            # CBOR or explicit length check might be needed if exact match required.
            # But the generator packs CBOR, so trailing zeros are fine.
            assert ev.payload.startswith(data)
            found = True
    assert found


def test_deframer_rq_post_boundary():
    deframer = Deframer()
    data = b"RaptorQ resilience test"
    rq_len = len(data) + 60  # Increased to accommodate larger PDU header
    mtu = 255
    repair_count = 10

    gen = PDUGenerator(
        src_callsign="RQ-POST",
        encodings=["h", f"rq({rq_len}, {mtu}, {repair_count})"],
        announcement_encodings=["identity"],
    )

    pdus = list(gen.generate(data))

    announcement_pdu = pdus[0]

    # Lose some packets
    if len(pdus) > 5:
        del pdus[1]
        del pdus[3]

    deframer.receive_bytes(announcement_pdu)
    for pdu in pdus:
        deframer.receive_bytes(pdu)

    found = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found


def test_deframer_rq_pre_boundary():
    deframer = Deframer()
    data = b"RaptorQ content encoding test"
    rq_len = len(data)
    mtu = 220
    repair_count = 3

    gen = PDUGenerator(
        src_callsign="RQ-PRE", encodings=[f"rq({rq_len}, {mtu}, {repair_count})"]
    )

    pdus = list(gen.generate(data))
    assert len(pdus) == repair_count + 1

    for pdu in pdus:
        deframer.receive_bytes(pdu)

    found = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found


def test_deframer_rq_post_boundary_pdu():
    deframer = Deframer()
    data = b"RaptorQ content encoding/decoding test post-boundary"
    mtu = 15
    repair_count = 3

    gen = PDUGenerator(
        src_callsign="RQ-POST",
        encodings=["h", f"rq(dlen,{mtu},{repair_count})"],
        announcement_encodings=["identity"],
    )

    pdus = list(gen.generate(data))
    assert len(pdus) == 10

    for pdu in pdus:
        deframer.receive_bytes(pdu)

    found = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        if isinstance(ev, PDUEvent):
            print(ev)
        elif isinstance(ev, MessageEvent):
            assert ev.payload == data
            found = True
    assert found
