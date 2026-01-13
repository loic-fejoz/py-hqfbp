from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent


def test_repro_crc32_multi_chunk():
    # Setup generator to match user's report
    # --encodings "gzip,h,crc32"
    # --announcement-encodings "crc16,h"
    # --max-payload-size 255
    # --msg-id 10
    gen = PDUGenerator(
        src_callsign="F4JXQ",
        encodings=["gzip", "h", "crc32"],
        announcement_encodings=["crc16", "h"],
        max_payload_size=255,
        initial_msg_id=10,
    )

    # 1024 bytes of uncompressible data to ensure multiple chunks
    import os

    data = os.urandom(1024)
    pdus = list(gen.generate(data, content_type="text/plain"))

    # We expect: 1 Announcement + 3 Data PDUs (since 512 / 255 is ~2.x)
    assert len(pdus) >= 3

    deframer = Deframer()

    # Process Announcement
    deframer.receive_bytes(pdus[0])

    # Process Data PDUs
    for i, pdu in enumerate(pdus[1:]):
        print(f"Feeding PDU {i + 1}/{len(pdus) - 1}, size={len(pdu)}")
        deframer.receive_bytes(pdu)

    # Check for reassembled message
    events = []
    while True:
        ev = deframer.next_event()
        if ev is None:
            break
        events.append(ev)

    messages = [e for e in events if isinstance(e, MessageEvent)]
    assert len(messages) == 1
    assert messages[0].payload == data


if __name__ == "__main__":
    test_repro_crc32_multi_chunk()
