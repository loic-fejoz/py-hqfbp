from hqfbp import golay_encode, golay_decode

def test_golay_basic():
    data = b"Hello Golay!"
    encoded = golay_encode(data)
    # 3 bytes -> 6 bytes (2 codewords)
    # 12 bytes -> (12/3)*6 = 24 bytes
    assert len(encoded) == 24
    
    decoded, errs = golay_decode(encoded)
    assert decoded.startswith(data)
    assert errs == 0

def test_golay_correction():
    data = b"XYZ" # 3 bytes = 2 codewords
    encoded = bytearray(golay_encode(data))
    
    # Codeword 1 is encoded[0:3]
    # Codeword 2 is encoded[3:6]
    
    # Flip 1 bit in codeword 1
    encoded[0] ^= 0x01
    # Flip 2 bits in codeword 2
    encoded[3] ^= 0x01
    encoded[4] ^= 0x02
    
    decoded, errs = golay_decode(bytes(encoded))
    assert decoded.startswith(data)
    assert errs == 3

def test_golay_max_correction():
    # Golay(24,12) can correct up to 3 errors per codeword
    data = b"ABC"
    encoded = bytearray(golay_encode(data))
    
    # 3 errors in first codeword
    encoded[0] ^= 0x01
    encoded[1] ^= 0x02
    encoded[2] ^= 0x04
    
    decoded, errs = golay_decode(bytes(encoded))
    assert decoded.startswith(data)
    assert errs == 3
