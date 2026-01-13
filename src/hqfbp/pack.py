import argparse
import mimetypes
import os
import sys
import re
import socket
import tomllib
import tomlkit
from hqfbp.generator import PDUGenerator

# KISS Constants
FEND  = b'\xC0'
FESC  = b'\xDB'
TFEND = b'\xDC'
TFESC = b'\xDD'

def encode_kiss_frame(pdu: bytes) -> bytes:
    """Encodes a PDU into a KISS frame."""
    frame = bytearray()
    frame.extend(FEND)
    frame.append(0x00) # Command Byte: Data frame, Port 0
    
    for byte in pdu:
        if byte == FEND[0]:
            frame.extend(FESC)
            frame.extend(TFEND)
        elif byte == FESC[0]:
            frame.extend(FESC)
            frame.extend(TFESC)
        else:
            frame.append(byte)
            
    frame.extend(FEND)
    return bytes(frame)

def main():
    parser = argparse.ArgumentParser(description="Pack a file into KISS frames using the HQFBP protocol.")
    # Standard pack arguments
    parser.add_argument("filepath", help="Path to the file to send")
    parser.add_argument("--src-callsign", required=True, help="Source callsign")
    parser.add_argument("--encodings", help="Comma-separated list of encodings (e.g., 'gzip,h,crc32')")
    parser.add_argument("--announcement-encodings", help="Comma-separated list of announcement encodings")
    parser.add_argument("--max-payload-size", type=int, help="Maximum payload size for chunking")
    parser.add_argument("--msg-id", type=int, help="Starting message ID")
    parser.add_argument("--config", help="Path to TOML configuration file")
    
    # Specific arguments for packing/TCP
    parser.add_argument("--output", help="Output KISS file path (default: <filepath>.kiss)")
    parser.add_argument("--tcp", help="KISS-over-TCP server address (e.g., localhost:8001)")

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

    # Determine output mode
    out_f = None
    if args.tcp:
        try:
            host, port = args.tcp.rsplit(":", 1)
            # Remove brackets if present (e.g. [::1])
            host = host.strip("[]")
            out_f = socket.create_connection((host, int(port)))
        except Exception as e:
            print(f"Error connecting to TCP server: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        output_path = args.output or f"{args.filepath}.kiss"
        print(f"Writing to KISS file {output_path}...")
        out_f = open(output_path, "wb")
    
    # Generate and write frames
    try:
        count = 0
        with out_f:
            for pdu in generator.generate(data, content_type=ctype):
                kiss_frame = encode_kiss_frame(pdu)
                if hasattr(out_f, "sendall"):
                    out_f.sendall(kiss_frame)
                else:
                    out_f.write(kiss_frame)
                count += 1
        
        print(f"Successfully sent/packed {count} frames.")

        # Update and save config logic is usually not needed for a packer, 
        # unless we want to increment message IDs for the 'next' run.
        # Keeping it for full parity.
        if args.config:
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

    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
