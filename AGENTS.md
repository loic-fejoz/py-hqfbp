# Agent Guidance System: py-hqfbp

## Mission
To provide the **official reference implementation** of the **Hamradio Quick File Broadcasting Protocol (HQFBP)**. This project serves as the master specification and bit-accuracy benchmark for all other implementations (including `hqfbp-rs`).

## Critical Commands
- **Install (Dev):** `uv sync`
- **Test:** `pytest` (Run this ALWAYS before submitting changes)
- **Lint:** `ruff check` (Run `ruff format` to fix)
- **Simulate:** `python -m hqfbp.simulate`

## Project Map
- `src/hqfbp/__init__.py`: Protocol constants, `Header` model, and codec registry.
- `src/hqfbp/generator.py`: `PDUGenerator` implementation.
- `src/hqfbp/deframer.py`: `Deframer` implementation.
- `src/hqfbp/pack.py` / `unpack.py`: KISS framing and raw PDU serialization.
- `src/hqfbp/simulate.py`: Heuristic performance simulation under noise.
- `tests/`: Extensive pytest suite verifying protocol edge cases.

## Documentation Index
Read these specialized docs in `agent_docs/` before starting specific tasks:
1. **[Architecture](file:///home/loic/projets/py-hqfbp/agent_docs/architecture.md):** The core transformation pipeline and session management logic.
2. **[Testing Guidelines](file:///home/loic/projets/py-hqfbp/agent_docs/testing_guidelines.md):** How to use pytest, simulation tools, and cross-compatibility scripts with Rust.
3. **[Conventions](file:///home/loic/projets/py-hqfbp/agent_docs/conventions.md):** Python-specific patterns and protocol invariants.

> [!IMPORTANT]
> **Interoperability Requirement:** Since this is the reference implementation, any logic changes MUST be verified for backward compatibility and bit-accuracy against [hqfbp-rs](https://github.com/loic-fejoz/hqfbp-rs/). Use the `test_roundtrip.sh` and cross-test scripts in the parent directory.
