# Architecture: HQFBP Python Reference

This project defines the normative behavior of the HQFBP protocol.

## 1. The Generator Pipeline
`PDUGenerator` ([src/hqfbp/generator.py](file:///home/loic/projets/py-hqfbp/src/hqfbp/generator.py)) manages the conversion of objects into PDUs.

- **Encodings Registry:** All supported transforms are registered in `CONTENT_ENCODINGS` ([src/hqfbp/__init__.py](file:///home/loic/projets/py-hqfbp/src/hqfbp/__init__.py)).
- **Pre-Boundary Transforms:** Applied sequentially to the message data before chunking.
- **Post-Boundary Transforms:** Applied to each individual PDU after chunking. This is where FEC (Reed-Solomon, RaptorQ) and Scrambling occur.
- **PDU Wrapping:** Python uses a dynamic header creation logic that ensures MTU/`max_payload_size` constraints are respected after post-boundary expansion.

## 2. The Deframer Engine
`Deframer` ([src/hqfbp/deframer.py](file:///home/loic/projets/py-hqfbp/src/hqfbp/deframer.py)) is the reassembly engine.

- **Heuristic Phase 0:** Identifies PDU boundaries and extracts headers using `CBOR`.
- **Session Management:** Groups received chunks by `message_id`.
- **Quality Metrics:** Tracked via `pdu_quality` (often bit-error counts or probability scores). Better chunks always overwrite inferior ones.
- **Multi-PDU Recovery:** Collects RaptorQ symbols or RS blocks until mathematical recovery is possible.

## 3. Reference Design Patterns
- **Serialization:** Heavy reliance on `cbor2` for compact header representation.
- **Inter-layer Communication:** Uses a `PDUEvent` and `MessageEvent` system to notify the application of progress.
- **Heuristic Tolerance:** Phase 1 and 2 heuristics allow the deframer to "guess" missing metadata from previous announcements or partial headers.

> [!NOTE]
> The Python implementation prioritizes clarity and specification accuracy over raw performance. It serves as the primary source of truth for the protocol's state machine.
