import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import datetime
import cbor2
from hqfbp.send_udp import main as send_main
from hqfbp.receive_udp import main as receive_main
from hqfbp.deframer import MessageEvent, PDUEvent
from hqfbp import HQFBP_CBOR_KEYS

class TestCLIUDP(unittest.TestCase):
    # --- Sender Tests ---
    @patch("hqfbp.send_udp.PDUGenerator")
    @patch("hqfbp.send_udp.socket.socket")
    @patch("mimetypes.guess_type")
    @patch("builtins.open", new_callable=mock_open, read_data=b"test data")
    @patch("os.path.isfile")
    def test_send_success(self, mock_isfile, mock_file, mock_guess, mock_socket, mock_gen):
        mock_isfile.return_value = True
        mock_guess.return_value = ("text/plain", None)
        
        mock_gen_instance = mock_gen.return_value
        mock_gen_instance.generate.return_value = [b"pdu1", b"pdu2"]
        
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        
        test_args = [
            "hqfbp-send-udp",
            "test.txt",
            "127.0.0.1",
            "1234",
            "--src-callsign", "F4JXQ",
            "--encodings", "gzip,h",
            "--max-payload-size", "100"
        ]
        
        with patch.object(sys, 'argv', test_args):
            with patch('sys.stdout', new_callable=MagicMock()):
                send_main()
                
                mock_gen.assert_called_once_with(
                    src_callsign="F4JXQ",
                    max_payload_size=100,
                    encodings=["gzip", "h"],
                    announcement_encodings=None,
                    initial_msg_id=1
                )
                self.assertEqual(mock_sock_instance.sendto.call_count, 2)

    # --- Receiver Tests ---
    @patch("hqfbp.receive_udp.socket.socket")
    @patch("hqfbp.receive_udp.Deframer")
    @patch("os.path.exists")
    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    @patch("hqfbp.receive_udp.datetime")
    def test_receive_success(self, mock_datetime, mock_file, mock_makedirs, mock_exists, mock_deframer, mock_socket):
        mock_exists.return_value = False
        
        # Setup mock socket behavior
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        # Simulate receiving one PDU then KeyboardInterrupt
        mock_sock_instance.recvfrom.side_effect = [(b"raw_pdu", ("127.0.0.1", 1234)), KeyboardInterrupt]
        
        # Setup mock deframer behavior
        mock_deframer_instance = mock_deframer.return_value
        # ev1: PDUEvent (Announcement), ev2: MessageEvent, ev3: None (break loop)
        ann_payload_dict = {0: 123, 5: ["gzip"]}
        mock_pdu_ev = PDUEvent(
            header={HQFBP_CBOR_KEYS["Content-Type"]: "application/vnd.hqfbp+cbor"}, 
            payload=cbor2.dumps(ann_payload_dict)
        )
        mock_msg_ev = MessageEvent(header={HQFBP_CBOR_KEYS["Src-Callsign"]: "F4JXQ", HQFBP_CBOR_KEYS["Content-Type"]: "text/plain"}, payload=b"full message")
        mock_deframer_instance.next_event.side_effect = [mock_pdu_ev, mock_msg_ev, None, None]
        
        # Fixed time for filename
        fixed_now = datetime.datetime(2024, 12, 24, 16, 0, 0, tzinfo=datetime.UTC)
        mock_datetime.datetime.now.return_value = fixed_now
        mock_datetime.UTC = datetime.UTC
        
        test_args = ["hqfbp-receive-udp", "0.0.0.0", "1234", "output_dir"]
        
        with patch.object(sys, 'argv', test_args):
            with patch('sys.stdout', new_callable=MagicMock()) as mock_stdout:
                receive_main()
                
                # Check for announcement log in stdout
                found_ann = any("📢 Announcement for Msg-Id 123" in str(call) for call in mock_stdout.method_calls)
                self.assertTrue(found_ann, "Announcement log not found in stdout")
        
        # Assertions
        mock_makedirs.assert_called_once_with("output_dir")
        mock_sock_instance.bind.assert_called_once_with(("0.0.0.0", 1234))
        mock_deframer_instance.receive_bytes.assert_called_once_with(b"raw_pdu")
        
        # Filename check: 2024-12-24-160000-UTC-F4JXQ.txt
        expected_filename = "2024-12-24-160000-UTC-F4JXQ.txt"
        expected_path = os.path.join("output_dir", expected_filename)
        mock_file.assert_any_call(expected_path, "wb")
        mock_file().write.assert_called_once_with(b"full message")

if __name__ == "__main__":
    unittest.main()
