import sys
import os

# Add src to path
sys.path.append(os.path.abspath("src"))

from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent


def test_reassembly_padding_trim():
    print("Testing reassembly padding trimming...")

    # 1. Setup source data
    # Use a size that will definitely be padded by RS(10, 5)
    source_data = b"Padding Test"  # 12 bytes
    file_size = len(source_data)
    print(f"Source data size: {file_size} bytes")

    # 2. Configuration with post-boundary RS
    # RS(10, 5) pads to multiple of 5 bytes.
    # But post-boundary RS applies to (CBOR Header + Payload).
    # We MUST use announcement encodings so the Deframer knows how to decode.
    encodings = ["h", "rs(10,5)"]
    ann_encs = ["h"]  # Identity announcement

    gen = PDUGenerator(
        src_callsign="TEST", encodings=encodings, announcement_encodings=ann_encs
    )

    # Generator will yield an announcement PDU first, then the data PDU(s)
    pdus = list(gen.generate(source_data))
    print(f"Generated {len(pdus)} PDU(s)")

    # 3. Deframer reassembly
    deframer = Deframer()
    for pdu in pdus:
        deframer.receive_bytes(pdu)

    # 4. Check results
    found_message = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break

        if isinstance(ev, MessageEvent):
            found_message = True
            print(f"Reassembled payload size: {len(ev.payload)} bytes")
            if ev.payload == source_data:
                print("SUCCESS: Payload exactly matches source data (no padding).")
            else:
                print(
                    f"FAIL: Payload size mismatch. Expected {file_size}, got {len(ev.payload)}"
                )
                print(f"Payload: {ev.payload.hex()}")
                print(f"Expected: {source_data.hex()}")

    if not found_message:
        print("FAIL: No message event generated. Reassembly failed.")
        # Debugging session state
        print(f"Registered announcements: {list(deframer._announcements.keys())}")
        print(f"Registered sessions: {list(deframer._sessions.keys())}")


if __name__ == "__main__":
    test_reassembly_padding_trim()
