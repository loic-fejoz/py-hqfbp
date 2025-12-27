import pytest
from hqfbp.simulate import simulate, BitErrorChannel

def test_simulator_zero_ber():
    # With zero BER, all files should be recovered
    limit = 5
    file_size = 512
    metrics = simulate(ber=0.0, encodings="gzip,h", ann_encodings=None, file_size=file_size, limit=limit)
    
    assert metrics.files_attempted == limit
    assert metrics.files_recovered == limit
    assert metrics.pdus_lost == 0
    # Efficiency should be positive but < 100 because of headers
    assert 0 < metrics.total_payload_bits / metrics.total_bits_sent < 1.0

def test_bit_error_channel():
    channel = BitErrorChannel(ber=0.5) # Extremely high BER
    data = b"\x00" * 100
    noisy = channel.process(data)
    # With BER=0.5, on average half of the bits should flip
    # This might fail due to randomness but very unlikely for 100 bytes
    assert noisy != data

def test_simulator_high_ber():
    # With very high BER, files should likely be lost
    limit = 2
    file_size = 512
    metrics = simulate(ber=0.1, encodings="h", ann_encodings=None, file_size=file_size, limit=limit)
    
    # We expect some losses
    assert metrics.pdus_lost > 0

def test_report_formats():
    limit = 1
    file_size = 100
    metrics = simulate(ber=0.0, encodings="h", ann_encodings=None, file_size=file_size, limit=limit)
    
    # Markdown
    md = metrics.report(format="markdown")
    assert "| Metric" in md
    
    # JSON
    js = metrics.report(format="json")
    import json
    data = json.loads(js)
    assert "Total Bytes Sent" in data
    assert "Residual Bit Error Rate" in data
    
    # CSV
    csv_out = metrics.report(format="csv")
    assert "Total Bytes Sent," in csv_out or "Total Bytes Sent\r\n" in csv_out
