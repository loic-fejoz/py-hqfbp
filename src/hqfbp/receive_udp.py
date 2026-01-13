import argparse
import socket
import mimetypes
import os
import sys
import datetime
import cbor2
from hqfbp.deframer import Deframer, PDUEvent, MessageEvent
from hqfbp import HQFBP_CBOR_KEYS, human_readable_json


def main():
    parser = argparse.ArgumentParser(
        description="Receive files over UDP using the HQFBP protocol."
    )
    parser.add_argument("ip", help="IP address to listen on (e.g., 0.0.0.0)")
    parser.add_argument("port", type=int, help="UDP port to listen on")
    parser.add_argument("output", help="Output folder to save received files")

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    if not os.path.exists(args.output):
        try:
            os.makedirs(args.output)
        except Exception as e:
            print(f"Error creating output directory: {e}", file=sys.stderr)
            sys.exit(1)

    # Setup UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.ip, args.port))
        print(f"Listening for HQFBP PDUs on {args.ip}:{args.port}...")
        print(f"Saving files to: {os.path.abspath(args.output)}")
    except Exception as e:
        print(f"Error binding to {args.ip}:{args.port}: {e}", file=sys.stderr)
        sys.exit(1)

    deframer = Deframer()

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                deframer.receive_bytes(data)
                print(".", end="", flush=True)
            except Exception as e:
                print(f"Error processing PDU from {addr}: {e}", file=sys.stderr)
                continue

            # Process events
            while True:
                ev = deframer.next_event()
                if ev is None:
                    break

                if isinstance(ev, PDUEvent):
                    # Log chunk header to stdout
                    print(f"Received PDU: {human_readable_json(ev.header)}")

                    # Detect and display announcement details
                    if (
                        ev.header.get(HQFBP_CBOR_KEYS["Content-Type"])
                        == "application/vnd.hqfbp+cbor"
                    ):
                        try:
                            ann_header = cbor2.loads(ev.payload)
                            print(
                                f"  📢 Announcement for Msg-Id {ann_header.get(0)}: {human_readable_json(ann_header)}"
                            )
                        except Exception as e:
                            print(
                                f"  ⚠️ Failed to decode announcement: {e}",
                                file=sys.stderr,
                            )

                elif isinstance(ev, MessageEvent):
                    # Reassembled message
                    callsign = ev.header.get(HQFBP_CBOR_KEYS["Src-Callsign"], "UNKNOWN")
                    content_type = ev.header.get(HQFBP_CBOR_KEYS["Content-Type"])

                    # Determine extension
                    ext = ".bin"
                    if content_type:
                        guessed_ext = mimetypes.guess_extension(content_type)
                        if guessed_ext:
                            ext = guessed_ext

                    # Generate filename: YYYY-MM-DD-HHMMSS-UTC-CALLSIGN.ext
                    now = datetime.datetime.now(datetime.UTC)
                    timestamp = now.strftime("%Y-%m-%d-%H%M%S-UTC")
                    filename = f"{timestamp}-{callsign}{ext}"
                    filepath = os.path.join(args.output, filename)

                    try:
                        with open(filepath, "wb") as f:
                            f.write(ev.payload)
                        print(
                            f" ✅ Successfully reassembled message from {callsign}: {filepath} ({len(ev.payload)} bytes)"
                        )
                        print(f"  Header: {human_readable_json(ev.header)}")
                    except Exception as e:
                        print(f"Error writing file {filepath}: {e}", file=sys.stderr)

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
