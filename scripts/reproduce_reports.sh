#!/bin/bash
set -e

RESULTS_FILE="simulation_results_py.md"
echo "# Python Simulation Results" > $RESULTS_FILE
echo "Generated at $(date)" >> $RESULTS_FILE
echo "" >> $RESULTS_FILE

# Function to run simulation
run_sim() {
    NAME=$1
    ARGS=$2
    echo "Running: $NAME"
    echo "## $NAME" >> $RESULTS_FILE
    echo "\`simulate.py $ARGS\`" >> $RESULTS_FILE
    echo "" >> $RESULTS_FILE
    # Using uv run to ensure dependencies like 'cbor2' are available
    uv run python3 src/hqfbp/simulate.py $ARGS --format markdown >> $RESULTS_FILE 2>/dev/null
    echo "" >> $RESULTS_FILE
}

# --- Standard Report Scenarios ---

# Comparison Base Size
FILE_SIZE=10240
LIMIT=50

# 1. Baseline
run_sim "py-hqfbp Baseline" "--ber 0.001 --encodings h --file-size $FILE_SIZE --limit $LIMIT"

# 2. Fragile
run_sim "py-hqfbp Fragile" "--ber 0.001 --encodings rs(255,127),h --ann-encodings h,repeat(10) --file-size $FILE_SIZE --limit $LIMIT"

# 3. Hybrid ARQ
run_sim "py-hqfbp Hybrid ARQ" "--ber 0.001 --encodings rs(255,127),h,repeat(3) --ann-encodings h,repeat(10) --file-size $FILE_SIZE --limit $LIMIT"

# 4. Robust (Chunked)
run_sim "py-hqfbp Robust" "--ber 0.001 --encodings chunk(100),crc32,h,rs(120,100) --ann-encodings h,repeat(10) --file-size 1000 --limit $LIMIT"

# 5. Degraded
run_sim "py-hqfbp Degraded" "--ber 0.001 --encodings rs(255,223),h,crc32,repeat(5) --ann-encodings h,repeat(10) --file-size $FILE_SIZE --limit $LIMIT"

# 6. Winner (Gzip)
run_sim "py-hqfbp Winner" "--ber 0.001 --encodings gzip,h,rs(120,100),repeat(2) --ann-encodings h,crc32,repeat(10) --file-size $FILE_SIZE --limit $LIMIT"

# --- hqfbp-rs Cross-Validation Scenarios ---

# Small Files (< 150B)
run_sim "hqfbp-rs Small Files" "--ber 0.001 --encodings h,rs(255,191),repeat(3) --ann-encodings h,crc32,repeat(10) --file-size 140 --limit 100"

# User Request: Dynamic RQ
# Config: gzip,h,rq(dlen,255,240)
# Announcement: h,rs(255,191),repeat(3)
run_sim "hqfbp-rs User Request (Dynamic RQ)" "--ber 0.001 --encodings gzip,h,rq(dlen,255,240) --ann-encodings h,rs(255,191),repeat(3) --file-size 122880 --limit 20"

echo "Simulations complete. Results saved to $RESULTS_FILE"
