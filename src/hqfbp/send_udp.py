import argparse
import socket
import mimetypes
import os
import sys
import re
from hqfbp.generator import PDUGenerator

def main():
    parser = argparse.ArgumentParser(description="Send a file over UDP using the HQFBP protocol.")
    parser.add_argument("filepath", help="Path to the file to send")
    parser.add_argument("ip", help="Destination IP address")
    parser.add_argument("port", type=int, help="Destination UDP port")
    parser.add_argument("--src-callsign", required=True, help="Source callsign")
    parser.add_argument("--encodings", help="Comma-separated list of encodings (e.g., 'gzip,h,crc32')")
    parser.add_argument("--announcement-encodings", help="Comma-separated list of announcement encodings")
    parser.add_argument("--max-payload-size", type=int, help="Maximum payload size for chunking")

    args = parser.parse_args()

    if not os.path.isfile(args.filepath):
        print(f"Error: File not found: {args.filepath}", file=sys.stderr)
        sys.exit(1)

    # Guess mimetype
    ctype, _ = mimetypes.guess_type(args.filepath)
    if ctype is None:
        ctype = "application/octet-stream"
    
    def parse_encs(s):
        if not s:
            return None
        # Split by comma but NOT inside parentheses
        return [part.strip() for part in re.split(r",(?![^\(]*\))", s)]

    # Parse encodings
    encodings = parse_encs(args.encodings)
    ann_encs = parse_encs(args.announcement_encodings)

    # Read data
    with open(args.filepath, "rb") as f:
        data = f.read()

    # Initialize generator
    generator = PDUGenerator(
        src_callsign=args.src_callsign,
        max_payload_size=args.max_payload_size,
        encodings=encodings,
        announcement_encodings=ann_encs
    )

    # Setup UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    # Generate and send PDUs
    try:
        count = 0
        for pdu in generator.generate(data, content_type=ctype):
            sock.sendto(pdu, (args.ip, args.port))
            count += 1
        print(f"Successfully sent {count} PDUs of {args.filepath} to {args.ip}:{args.port}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
