import argparse
import socket
import mimetypes
import os
import sys
import re
import tomllib
import tomlkit
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
    parser.add_argument("--msg-id", type=int, help="Starting message ID")
    parser.add_argument("--config", help="Path to TOML configuration file")

    args = parser.parse_args()

    # Load config if present
    config_data = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, "rb") as f:
            config_data = tomllib.load(f)

    # Resolve parameters: CLI > Config > Default
    callsign = args.src_callsign
    callsign_config = config_data.get("callsigns", {}).get(callsign, {})

    encodings_str = args.encodings or callsign_config.get("encodings")
    ann_encodings_str = args.announcement_encodings or callsign_config.get("announcement_encodings")
    max_payload_size = args.max_payload_size or callsign_config.get("max_payload_size")
    starting_msg_id = args.msg_id or callsign_config.get("last_msg_id", 1)

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
    encodings = parse_encs(encodings_str)
    ann_encs = parse_encs(ann_encodings_str)

    # Read data
    with open(args.filepath, "rb") as f:
        data = f.read()

    # Initialize generator
    generator = PDUGenerator(
        src_callsign=callsign,
        max_payload_size=max_payload_size,
        encodings=encodings,
        announcement_encodings=ann_encs,
        initial_msg_id=starting_msg_id
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

        # Update and save config
        if args.config:
            # Use tomlkit to preserve comments/formatting
            if os.path.exists(args.config):
                with open(args.config, "r") as f:
                    doc = tomlkit.load(f)
            else:
                doc = tomlkit.document()

            if "callsigns" not in doc:
                doc["callsigns"] = tomlkit.table()
            
            if callsign not in doc["callsigns"]:
                doc["callsigns"][callsign] = tomlkit.table()
            
            doc["callsigns"][callsign]["last_msg_id"] = generator._next_msg_id
            
            with open(args.config, "w") as f:
                f.write(tomlkit.dumps(doc))
    finally:
        sock.close()

if __name__ == "__main__":
    main()
