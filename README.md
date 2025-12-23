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

*Documentation coming soon.*
