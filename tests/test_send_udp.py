import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
from hqfbp.send_udp import main

class TestCLI(unittest.TestCase):
    @patch("hqfbp.send_udp.PDUGenerator")
    @patch("hqfbp.send_udp.socket.socket")
    @patch("mimetypes.guess_type")
    @patch("builtins.open", new_callable=mock_open, read_data=b"test data")
    @patch("os.path.isfile")
    def test_main_success(self, mock_isfile, mock_file, mock_guess, mock_socket, mock_gen):
        # Setup
        mock_isfile.return_value = True
        mock_guess.return_value = ("text/plain", None)
        
        mock_gen_instance = mock_gen.return_value
        mock_gen_instance.generate.return_value = [b"pdu1", b"pdu2"]
        
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        
        # Arguments
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
            with patch('sys.stdout', new_callable=MagicMock()) as mock_stdout:
                main()
                
                # Assertions
                mock_gen.assert_called_once_with(
                    src_callsign="F4JXQ",
                    max_payload_size=100,
                    encodings=["gzip", "h"],
                    announcement_encodings=None,
                    initial_msg_id=1
                )
                mock_gen_instance.generate.assert_called_once_with(b"test data", content_type="text/plain")
                self.assertEqual(mock_sock_instance.sendto.call_count, 2)
                mock_sock_instance.sendto.assert_any_call(b"pdu1", ("127.0.0.1", 1234))
                mock_sock_instance.sendto.assert_any_call(b"pdu2", ("127.0.0.1", 1234))
                mock_sock_instance.close.assert_called_once()

    @patch("os.path.isfile")
    def test_main_file_not_found(self, mock_isfile):
        mock_isfile.return_value = False
        test_args = ["hqfbp-send-udp", "nonexistent.txt", "127.0.0.1", "1234", "--src-callsign", "F4JXQ"]
        
        with patch.object(sys, 'argv', test_args):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 1)

    @patch("hqfbp.send_udp.PDUGenerator")
    @patch("hqfbp.send_udp.socket.socket")
    @patch("mimetypes.guess_type")
    @patch("builtins.open", new_callable=mock_open, read_data=b"rs test")
    @patch("os.path.isfile")
    def test_main_rs_encoding(self, mock_isfile, mock_file, mock_guess, mock_socket, mock_gen):
        mock_isfile.return_value = True
        mock_guess.return_value = (None, None)
        mock_gen_instance = mock_gen.return_value
        mock_gen_instance.generate.return_value = [b"pdu"]
        
        test_args = [
            "hqfbp-send-udp",
            "test.bin",
            "127.0.0.1",
            "1234",
            "--src-callsign", "F4JXQ",
            "--encodings", "h,rs(255,233)"
        ]
        
        with patch.object(sys, 'argv', test_args):
            with patch('sys.stdout', new_callable=MagicMock()):
                main()
                
                # Verify that gen was called with correctly split encodings
                mock_gen.assert_called_once_with(
                    src_callsign="F4JXQ",
                    max_payload_size=None,
                    encodings=["h", "rs(255,233)"],
                    announcement_encodings=None,
                    initial_msg_id=1
                )

    @patch("hqfbp.send_udp.PDUGenerator")
    @patch("hqfbp.send_udp.socket.socket")
    @patch("mimetypes.guess_type")
    @patch("builtins.open", new_callable=mock_open, read_data=b"msg id test")
    @patch("os.path.isfile")
    def test_main_msg_id(self, mock_isfile, mock_file, mock_guess, mock_socket, mock_gen):
        mock_isfile.return_value = True
        mock_guess.return_value = (None, None)
        mock_gen_instance = mock_gen.return_value
        mock_gen_instance.generate.return_value = [b"pdu"]
        
        test_args = [
            "hqfbp-send-udp",
            "test.bin",
            "127.0.0.1",
            "1234",
            "--src-callsign", "F4JXQ",
            "--msg-id", "123"
        ]
        
        with patch.object(sys, 'argv', test_args):
            with patch('sys.stdout', new_callable=MagicMock()):
                main()
                
                mock_gen.assert_called_once_with(
                    src_callsign="F4JXQ",
                    max_payload_size=None,
                    encodings=None,
                    announcement_encodings=None,
                    initial_msg_id=123
                )

if __name__ == "__main__":
    unittest.main()
