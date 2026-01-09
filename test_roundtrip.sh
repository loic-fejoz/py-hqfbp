#!/bin/bash
set -e

# Configuration
INPUT_FILE="test_payload.bin"
KISS_FILE="output.kiss"
OUTPUT_DIR="unpacked_output"
FILE_SIZE=10240

# Cleanup
echo "Cleaning up..."
rm -f "$INPUT_FILE" "$KISS_FILE"
rm -rf "$OUTPUT_DIR"

# Generate random input file
echo "Generating random payload ($FILE_SIZE bytes)..."
dd if=/dev/urandom of="$INPUT_FILE" bs=1 count="$FILE_SIZE" status=none

# Pack
echo "Packing with pack.py..."
uv run python src/hqfbp/pack.py "$INPUT_FILE" 0.0.0.0 0 \
    --src-callsign "TEST-ROUNDTRIP" \
    --encodings "gzip,h,crc32" \
    --output "$KISS_FILE"

# Unpack
echo "Unpacking with unpack.py to $OUTPUT_DIR..."
uv run python src/hqfbp/unpack.py "$OUTPUT_DIR" "$KISS_FILE"

# Find output file (timestamped name unknown)
# We look for the newest file in the output directory
if [ -z "$(ls -A "$OUTPUT_DIR")" ]; then
   echo "Error: Output directory is empty!"
   exit 1
fi

UNPACKED_FILE=$(ls -t "$OUTPUT_DIR"/* | head -1)
echo "Found unpacked file: $UNPACKED_FILE"

# Compare
echo "Comparing SHA256 checksums..."
ORIG_HASH=$(sha256sum "$INPUT_FILE" | awk '{print $1}')
NEW_HASH=$(sha256sum "$UNPACKED_FILE" | awk '{print $1}')

echo "Original: $ORIG_HASH"
echo "Unpacked: $NEW_HASH"

if [ "$ORIG_HASH" == "$NEW_HASH" ]; then
    echo "✅ SUCCESS: Roundtrip verification passed!"
    exit 0
else
    echo "❌ FAILURE: Checksums do not match!"
    exit 1
fi
