import sys
import os

# Add src to path
sys.path.append(os.path.abspath("src"))

from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent
from hqfbp import unpack
import random


def reproduce_padding():
    print("Reproducing Interleaved Padding Gaps...")

    # Configuration that definitely causes gaps due to RS(120, 100) and small chunks
    # 1. chunk(100) splits 1024 bytes into 11 chunks.
    # 2. crc32 makes them 104 bytes.
    # 3. RS(120,100) on a PDU (header + 104 bytes) will likely take 2-3 RS blocks.
    #    The second/third block will be mostly padding.

    source_data = random.randbytes(1024)
    encodings = ["chunk(100)", "crc32", "h", "rs(120,100)"]
    ann_encs = ["h"]  # Identity announcement

    gen = PDUGenerator(
        src_callsign="TEST", encodings=encodings, announcement_encodings=ann_encs
    )

    pdus = list(gen.generate(source_data))
    print(f"Generated {len(pdus)} PDU(s) (including announcement)")
    if len(pdus) > 1:
        # PDU 0 is announcement, PDU 1 is first data
        h, p = unpack(pdus[1])
        print(f"DEBUG: First Data PDU Header: {h}")
        print(f"DEBUG: First Data PDU Total Size: {len(pdus[1])}")
        print(f"DEBUG: First Data PDU Payload Size: {len(p)}")

    deframer = Deframer()
    for pdu in pdus:
        deframer.receive_bytes(pdu)

    found_message = False
    while True:
        ev = deframer.next_event()
        if ev is None:
            break

        if isinstance(ev, MessageEvent):
            found_message = True
            print(f"Reassembled payload size: {len(ev.payload)} bytes")
            if ev.payload == source_data:
                print("SUCCESS: Payload exactly matches source data.")
            else:
                print(
                    f"FAIL: Payload mismatch. Size difference: {len(ev.payload) - len(source_data)}"
                )
                # Check first few bytes
                if ev.payload[:100] == source_data[:100]:
                    print("First 100 bytes match. Issue is likely interleaved padding.")
                else:
                    print("First 100 bytes MISMATCH. Corruption is severe.")

    if not found_message:
        print("FAIL: No message event generated.")


if __name__ == "__main__":
    reproduce_padding()
