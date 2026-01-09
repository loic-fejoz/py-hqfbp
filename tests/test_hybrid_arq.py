import sys
import os

# Add src to path
sys.path.append(os.path.abspath("src"))

from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent
from hqfbp import pack, HQFBP_CBOR_KEYS, unpack, human_readable_json
import random

def test_best_of_n():
    print("Testing Best-of-N selection...")
    
    # Use a larger file and small max_payload_size to ensure multiple chunks
    source_data = random.randbytes(100)
    
    # Configuration with CRC and RS
    encodings = ["rs(255,223)", "h", "crc32"]
    gen = PDUGenerator(src_callsign="TEST", encodings=encodings, max_payload_size=50)
    
    pdus = list(gen.generate(source_data))
    print(f"Generated {len(pdus)} chunks with FEC")
    
    # Identity PDUs (Quality 0)
    identity_gen = PDUGenerator(src_callsign="TEST", encodings=["h"], max_payload_size=50)
    identity_pdus = list(identity_gen.generate(source_data))
    print(f"Generated {len(identity_pdus)} chunks without FEC")
    
    deframer = Deframer()
    
    # Send only the first chunk of identity
    print("Sending identity chunk 0 (Quality 0)...")
    deframer.receive_bytes(identity_pdus[0])
    
    # msg_id for the first chunk is orig_msg_id
    h, _ = unpack(identity_pdus[0])
    orig_msg_id = h.get(0)
    session_key = ("TEST", orig_msg_id)
    
    session = deframer._sessions.get(session_key)
    if not session:
         print(f"FAIL: Session {session_key} not found after identity PDU")
         return
         
    chunk_payload, quality = session['chunks'][0]
    print(f"Initial quality for chunk 0: {quality}")
    
    # Send the first chunk of FEC protected data
    print("Sending FEC chunk 0 (Quality > 0)...")
    deframer.receive_bytes(pdus[0])
    
    chunk_payload, quality = session['chunks'][0]
    print(f"New quality for chunk 0: {quality}")
    
    if quality > 0:
        print("SUCCESS: Quality improved after better PDU")
    else:
        print("FAIL: Quality did not improve")

    # Send a worse PDU again
    print("Sending identity chunk 0 again (Quality 0)...")
    deframer.receive_bytes(identity_pdus[0])
    _, final_quality = session['chunks'][0]
    print(f"Final quality for chunk 0: {final_quality}")
    
    if final_quality == quality:
        print("SUCCESS: Worse PDU did not overwrite better one")
    else:
        print("FAIL: Worse PDU overwrote better one!")

if __name__ == "__main__":
    test_best_of_n()
