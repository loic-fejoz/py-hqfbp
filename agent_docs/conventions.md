# Conventions & Patterns

Python-specific conventions for the HQFBP reference implementation.

## 1. Modular Logic
- **Codecs:** Transformations are modular. When adding a new encoding, add it to `CONTENT_ENCODINGS` in `src/hqfbp/__init__.py` and ensure it handles both bytes-in and bytes-out.
- **Generator/Deframer Separation:** The Generator should be purely functional where possible, while the Deframer manages mutable session state.

## 2. PDU Handling & State
- **Attribute Access:** Use `@property` for calculated header fields to ensure consistency.
- **CBOR Dictionaries:** In headers, prefer integer keys (defined in `__init__.py`) over strings to minimize PDU size.
- **Quality State:** Quality should be handled as a numerical value where higher = better parity/certainty.

## 3. Error Handling
- Use custom exceptions defined in `src/hqfbp/__init__.py` for protocol-level errors.
- The `Deframer` should be "forgiving" of invalid individual PDUs to allow recovery of others in the same stream.

## 4. Dependencies
- Keep the dependency list lean. Prefer standard library solutions (like `zlib` for Gzip) unless a specialized library is strictly required (like `reedsolo`).
- Use `tomlkit` for configuration files to preserve comments and formatting.

## 5. Coding Style
- Follow **PEP 8** standards.
- Use type hints (`typing` module) for all public functions to improve agent clarity.
- Run `ruff format` to maintain consistent style.

> [!NOTE]
> **Reference Status:** Because this is the master implementation, readability and documentation are prioritized over hyper-optimization. Code should read like the protocol specification.
