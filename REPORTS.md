# HQFBP Simulation Report

This report summarizes experiments conducted to optimize the [Hamradio Quick File Broadcast Protocol (HQFBP)](https://github.com/loic-fejoz/hqfbp/blob/main/rfc.md) performance under noisy channel conditions (Bit Error Rate = 0.001).

## Experiment Results (BER 0.001)

| Configuration (Data, Announcement) | Air BER | Packet Loss | File Loss | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `h` / None | 9.80e-04 | 4.0% | 100% | Baseline; everything fails. |
| `rs(255,127),h`, `h,repeat(10)` | 9.93e-04 | 9.21% | 90.5% | **Fragile**: Pre-boundary RS doesn't protect headers. |
| `rs(255,127),h,repeat(3)`, `h,repeat(10)` | 1.00e-03 | 11.34% | 51.0% | **Hybrid ARQ**: Redundancy helps but headers remain a weak point. |
| `chunk(100),crc32,h,rs(120,100)`, `h,repeat(10)` | 1.00e-03 | 6.55% | 23.9% | **Robust**: Stack-aware reassembly + Padding fix. |
| `rs(255,223),h,crc32,repeat(5)`, `h,repeat(10)` | 1.00e-03 | 67.03% | 98.3% | **Degraded**: Large repetitive headers increase collision probability. |
| `gzip,h,rs(120,100),repeat(2)`, `h,crc32,repeat(10)` | 1.00e-03 | 43.79% | 0.2% | **Winner**: gzip + RS(120,100) + 2x repeat is very robust. |

## Recommendations

For a target File Loss Rate < 1% at BER 0.001:

1. **Protocol Configuration for Reliability**:
   - **Announcements**: MUST use `h,crc32,repeat(k)` (e.g. $k=10$) for high discovery probability.
   - **Data**: Use `gzip,h,rs(120,100),repeat(2)` as the reliable winner configuration.
   - **Integrity**: Always include post-boundary `rs` or `crc32` to enable the Deframer's "Best-of-N" selection logic.

2. **MTU Selection**: Keep packets medium-sized (~128-256 bytes) to balance header overhead against burst error probability.

## Critical Review: HQFBP Protocol & Implementation

### 1. The "Announcement Deadlock"
Current state: The `Deframer` needs an announcement to know how to decode a PDU. If the announcement itself is lost or corrupt, discovery fails.
**Improvement**: Standardize a "Discovery Encoding" (identity or fixed-rate RS) that all receivers MUST try on unknown PDUs.

### 3. Stack-Aware Reassembly Success
- **Padding Gaps**: [FIXED] Post-boundary encodings (like RS) result in padded blocks. The `Deframer` now uses the `File-Size` header field to strictly trim reassembled files.
- **Tiered Decoding**: [IMPLEMENTED] The Deframer correctly separates per-PDU layers (e.g. `rs`, `repeat`) from message-level layers (e.g. `gzip`), enabling robust reassembly.

### 4. Next Steps
- [x] **Integrate Hybrid ARQ logic**: The Deframer now does "Best-of-N" selection for repeated packets by tracking quality metrics.
- [x] **Header Protection & Robustness**: Improved via standardized mapping to integer IDs and robust post-boundary FEC.
- [x] **RaptorQ Stability & Padding Fix**: All tests pass, including early decoding and symbolic separation.
- **Forward Error Correction Interleaving**: Investigate time-domain interleaving for burst error resilience.
