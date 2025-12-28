import os
import pytest
import tomlkit
from unittest.mock import patch, MagicMock
from hqfbp.send_udp import main

@pytest.fixture
def temp_config(tmp_path):
    config_path = tmp_path / "config.toml"
    doc = tomlkit.document()
    callsigns = tomlkit.table()
    f4jxq = tomlkit.table()
    f4jxq["encodings"] = "gzip,h"
    f4jxq["last_msg_id"] = 100
    callsigns["F4JXQ"] = f4jxq
    doc["callsigns"] = callsigns
    config_path.write_text(tomlkit.dumps(doc))
    return str(config_path)

@patch("socket.socket")
@patch("hqfbp.send_udp.PDUGenerator")
def test_main_with_config(mock_gen_class, mock_socket, temp_config, tmp_path):
    # Setup test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")
    
    mock_gen = MagicMock()
    mock_gen_class.return_value = mock_gen
    mock_gen.generate.return_value = [b"pdu1"]
    mock_gen._next_msg_id = 101 # Simulate increment
    
    # Run main with --config
    with patch("sys.argv", ["hqfbp-send-udp", str(test_file), "127.0.0.1", "1234", "--src-callsign", "F4JXQ", "--config", temp_config]):
        main()
    
    # Verify PDUGenerator was called with config values
    mock_gen_class.assert_called_once()
    args, kwargs = mock_gen_class.call_args
    assert kwargs["encodings"] == ["gzip", "h"]
    assert kwargs["initial_msg_id"] == 100
    
    # Verify config was updated
    with open(temp_config, "r") as f:
        updated_doc = tomlkit.load(f)
    assert updated_doc["callsigns"]["F4JXQ"]["last_msg_id"] == 101

@patch("socket.socket")
@patch("hqfbp.send_udp.PDUGenerator")
def test_main_cli_override(mock_gen_class, mock_socket, temp_config, tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")
    
    mock_gen = MagicMock()
    mock_gen_class.return_value = mock_gen
    mock_gen.generate.return_value = [b"pdu1"]
    mock_gen._next_msg_id = 1
    
    # Run main with --config AND --encodings (CLI should override)
    with patch("sys.argv", ["hqfbp-send-udp", str(test_file), "127.0.0.1", "1234", "--src-callsign", "F4JXQ", "--config", temp_config, "--encodings", "h,crc32"]):
        main()
    
    mock_gen_class.assert_called_once()
    args, kwargs = mock_gen_class.call_args
    assert kwargs["encodings"] == ["h", "crc32"]
