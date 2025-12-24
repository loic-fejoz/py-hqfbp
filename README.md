# py-hqfbp

Python module to pack and unpack Protocol Data Units (PDUs) for the **Hamradio Quick File Broadcasting Protocol (HQFBP)**.

## About HQFBP

The Hamradio Quick File Broadcasting Protocol (HQFBP) is designed for efficient, robust, and asynchronous file and data broadcasting over radio communication links. It is particularly suited for challenging environments like satellite downlinks.

Key features include:
- **Low Overhead**: Uses CBOR indexing to minimize header size.
- **Error Tolerance**: Supports asynchronous delivery and reassembly.
- **File Broadcasting**: Efficient for one-to-many transmissions.
- **Chunking**: Mandatory support for large file split into smaller PDUs.

For more details, refer to the [HQFBP RFC](https://github.com/loic-fejoz/hqfbp/blob/main/rfc.md) (local version @[../hqfbp/rfc.md]).

## Installation

```bash
pip install hqfbp
```

## Usage

```python
from hqfbp import HQFBP_CBOR_KEYS
from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent

# 1. Initialize Generator with complex encodings
# - gzip: compress the message content (pre-boundary)
# - h: boundary marker
# - rs(255,233): apply Reed-Solomon FEC to the whole PDU (post-boundary)
# - announcement_encodings: used for the preliminary metadata PDU
gen = PDUGenerator(
    src_callsign="F4JXQ",
    encodings=["gzip", "h", "rs(255,233)"],
    announcement_encodings=["h", "crc32"]
)

data = b"Hello, this is a robust message!"
pdus = list(gen.generate(data))

# 2. Initialize Deframer
deframer = Deframer()

# 3. Process PDUs
# The first PDU in this case is the Announcement PDU that helps 
# the Deframer understand upcoming scrambled data.
for pdu in pdus:
    deframer.receive_bytes(pdu)

# 4. Handle resulting events
while True:
    ev = deframer.next_event()
    if ev is None:
        break
    if isinstance(ev, MessageEvent):
        src = ev.header.get(HQFBP_CBOR_KEYS["Src-Callsign"])
        print(f"Received from {src}: {ev.payload.decode()}")
```
