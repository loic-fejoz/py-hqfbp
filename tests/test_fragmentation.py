import unittest
from hqfbp.generator import PDUGenerator
from hqfbp import pack, HQFBP_CBOR_KEYS
from hqfbp.deframer import Deframer, MessageEvent

class TestFragmentation(unittest.TestCase) :
    def test_chunk_rs_after_h(self):
        """Test reassembly when chunk and rs are applied after the 'h' boundary."""
        # 1. Setup Generator with fragmentation-inducing encodings
        generator = PDUGenerator(
            src_callsign="TEST",
            encodings=["gzip", "h", "chunk(223)", "rs(255,223)", "repeat(2)"],
            announcement_encodings=["crc16"]
        )
        
        # 500 bytes of data
        data = bytes([i % 256 for i in range(500)])
        
        # 2. Generate PDUs
        pdus = list(generator.generate(data))
        
        # 3. Process PDUs with Deframer
        deframer = Deframer()
        recovered_messages = []
        for pdu in pdus:
            deframer.receive_bytes(pdu)
            while True:
                ev = deframer.next_event()
                if not ev: break
                if isinstance(ev, MessageEvent):
                    recovered_messages.append(ev)
        
        # 4. Assertions
        self.assertEqual(len(recovered_messages), 1)
        recovered = recovered_messages[0]
        self.assertEqual(len(recovered.payload), 500)
        self.assertEqual(recovered.payload, data)
        self.assertEqual(recovered.header.get(HQFBP_CBOR_KEYS["Src-Callsign"]), "TEST")
        # Header should be clean (no chunk, rs, repeat, or h)
        ce = recovered.header.get(HQFBP_CBOR_KEYS["Content-Encoding"])
        # ce could be "gzip" or 1
        if isinstance(ce, list):
            self.assertNotIn("h", ce)
            self.assertNotIn(-1, ce)
        else:
            self.assertNotEqual(ce, "h")
            self.assertNotEqual(ce, -1)

if __name__ == "__main__":
    unittest.main()
