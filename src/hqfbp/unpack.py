import argparse
import sys
import os
import mimetypes
import datetime
import socket
import cbor2
from hqfbp.deframer import Deframer, PDUEvent, MessageEvent
from hqfbp import HQFBP_CBOR_KEYS, human_readable_json

# KISS Constants
FEND  = 0xC0
FESC  = 0xDB
TFEND = 0xDC
TFESC = 0xDD

class KISSDeFramer:
    def __init__(self):
        self.in_frame = False
        self.escaped = False
        self.buffer = bytearray()
    
    def process_byte(self, byte):
        """Standard KISS State Machine. Returns a frame bytes if a frame is completed."""
        if self.in_frame:
            if byte == FEND:
                # Frame complete
                if len(self.buffer) > 0:
                    frame = bytes(self.buffer)
                    self.buffer.clear()
                    self.in_frame = False # Wait for next FEND to start? No, FEND also starts
                    # Actually FEND delimits frames. Two FENDs means empty frame.
                    # Standard says: FEND ends the frame.
                    # Optimization: FEND also starts a new frame implicitly if we were not in frame?
                    # Let's stick to standard: FEND is a delimiter.
                    return frame
                else:
                    return None # Empty frame (e.g. back-to-back FEND)
            elif byte == FESC:
                self.escaped = True
            else:
                if self.escaped:
                    if byte == TFEND:
                        self.buffer.append(FEND)
                    elif byte == TFESC:
                        self.buffer.append(FESC)
                    else:
                        # Protocol violation, but just append
                        self.buffer.append(byte)
                    self.escaped = False
                else:
                    self.buffer.append(byte)
        else:
            if byte == FEND:
                self.in_frame = True
                self.buffer.clear()
                self.escaped = False
        return None

def main():
    parser = argparse.ArgumentParser(description="Unpack KISS frames containing HQFBP PDUs.")
    parser.add_argument("output", help="Output folder to save received files")
    parser.add_argument("--input", default="-", help="Input KISS file (default: stdin)")
    parser.add_argument("--tcp", help="KISS-over-TCP server address (e.g., localhost:8001)")
    
    args = parser.parse_args()

    # Create output directory
    if not os.path.exists(args.output):
        try:
            os.makedirs(args.output)
        except Exception as e:
            print(f"Error creating output directory: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"Reading from: {'stdin' if args.input == '-' else args.input}")
    print(f"Saving files to: {os.path.abspath(args.output)}")

    deframer = Deframer()
    kiss_decoder = KISSDeFramer()

    try:
        if args.tcp:
            try:
                host, port = args.tcp.rsplit(":", 1)
                host = host.strip("[]")
                print(f"Connecting to KISS-over-TCP server at {host}:{port}...")
                f_in = socket.create_connection((host, int(port)))
            except Exception as e:
                print(f"Error connecting to TCP server: {e}", file=sys.stderr)
                sys.exit(1)
        elif args.input == "-":
            f_in = sys.stdin.buffer
        else:
            f_in = open(args.input, "rb")
        
        with f_in:
            while True:
                if hasattr(f_in, "recv"):
                    chunk = f_in.recv(4096)
                else:
                    chunk = f_in.read(4096)
                
                if not chunk:
                    break
                
                for byte in chunk:
                    frame = kiss_decoder.process_byte(byte)
                    if frame:
                        # KISS Frame: [Cmd][Data...]
                        # We only care about command 0x00 (Data)
                        if len(frame) > 1 and frame[0] == 0x00:
                            pdu = frame[1:]
                            try:
                                deframer.receive_bytes(pdu)
                                print(".", end="", flush=True)
                            except Exception as e:
                                print(f"x", end="", flush=True)
                                continue

                            # Check for events immediately after each PDU
                            while True:
                                ev = deframer.next_event()
                                if ev is None:
                                    break
                                
                                if isinstance(ev, PDUEvent):
                                    pass # Verbose: print(f"PDU: {human_readable_json(ev.header)}")
                                elif isinstance(ev, MessageEvent):
                                    print() # Newline after dots
                                    
                                    callsign = ev.header.get(HQFBP_CBOR_KEYS["Src-Callsign"], "UNKNOWN")
                                    content_type = ev.header.get(HQFBP_CBOR_KEYS["Content-Type"])
                                    
                                    ext = ".bin"
                                    if content_type:
                                        guessed_ext = mimetypes.guess_extension(content_type)
                                        if guessed_ext:
                                            ext = guessed_ext
                                    
                                    now = datetime.datetime.now(datetime.UTC)
                                    timestamp = now.strftime("%Y-%m-%d-%H%M%S-UTC")
                                    filename = f"{timestamp}-{callsign}{ext}"
                                    filepath = os.path.join(args.output, filename)
                                    
                                    try:
                                        with open(filepath, "wb") as f_out:
                                            f_out.write(ev.payload)
                                        print(f"✅ Received {filename} ({len(ev.payload)} bytes)")
                                    except Exception as e:
                                        print(f"\nError writing {filename}: {e}", file=sys.stderr)

    except KeyboardInterrupt:
        print("\nStopping...")
    except Exception as e:
        print(f"\nCritical error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
