import argparse
import random
import json
import csv
import sys
import io
from typing import List, Dict, Any, Optional
from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent
from hqfbp import HQFBP_CBOR_KEYS

class BitErrorChannel:
    def __init__(self, ber: float):
        self.ber = ber

    def process(self, data: bytes) -> bytes:
        if self.ber <= 0:
            return data
        
        ba = bytearray(data)
        for i in range(len(ba)):
            # Quick check if any bit in byte might flip
            # Probability that AT LEAST one bit flips in a byte: 1 - (1-ber)^8
            byte_error_prob = 1 - (1 - self.ber) ** 8
            if random.random() < byte_error_prob:
                # One or more bits flip. Flip each bit individually.
                for bit in range(8):
                    if random.random() < self.ber:
                        ba[i] ^= (1 << bit)
        return bytes(ba)

class SimulationMetrics:
    def __init__(self):
        self.total_bits_sent = 0
        self.total_pdus_sent = 0
        self.pdus_lost = 0
        self.files_attempted = 0
        self.files_recovered = 0
        self.total_payload_bits = 0
        self.header_bits = 0
        self.padding_bits = 0
        self.current_burst_loss = 0
        self.max_burst_loss = 0
        self.total_bit_errors_introduced = 0 # Not directly measurable by protocol but known by sim

    def add_pdu(self, pdu_bytes: bytes, lost: bool):
        self.total_pdus_sent += 1
        bits = len(pdu_bytes) * 8
        self.total_bits_sent += bits
        
        # Approximate overhead (this is simplified as we don't unpack every PDU for metrics)
        # In a real sim we'd track actual header/payload split
        # For now we'll use a heuristic or let the simulator pass details
        
        if lost:
            self.pdus_lost += 1
            self.current_burst_loss += 1
            self.max_burst_loss = max(self.max_burst_loss, self.current_burst_loss)
        else:
            self.current_burst_loss = 0

    def report(self, format="markdown") -> str:
        efficiency = (self.total_payload_bits / self.total_bits_sent * 100) if self.total_bits_sent > 0 else 0
        packet_loss_rate = (self.pdus_lost / self.total_pdus_sent * 100) if self.total_pdus_sent > 0 else 0
        file_loss_rate = ((self.files_attempted - self.files_recovered) / self.files_attempted * 100) if self.files_attempted > 0 else 0
        overhead = ((self.header_bits + self.padding_bits) / self.total_bits_sent * 100) if self.total_bits_sent > 0 else 0
        fec_recovery = (self.files_recovered / self.files_attempted * 100) if self.files_attempted > 0 else 0

        data = {
            "Total Bytes Sent": self.total_bits_sent // 8,
            "Packet Loss Rate (%)": round(packet_loss_rate, 2),
            "File Loss Rate (%)": round(file_loss_rate, 2),
            "FEC Recovery Rate (%)": round(fec_recovery, 2),
            "Transmission Efficiency (%)": round(efficiency, 2),
            "Max Burst Loss": self.max_burst_loss,
            "Protocol Overhead (%)": round(overhead, 2),
        }

        if format == "json":
            return json.dumps(data, indent=2)
        elif format == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=data.keys())
            writer.writeheader()
            writer.writerow(data)
            return output.getvalue()
        else:
            # Aligned Markdown for terminal
            keys = list(data.keys())
            vals = [str(v) for v in data.values()]
            
            k_width = max(len(k) for k in (keys + ["Metric"]))
            v_width = max(len(v) for v in (vals + ["Value"]))
            
            header = f"| {'Metric'.ljust(k_width)} | {'Value'.ljust(v_width)} |"
            sep = f"| {'-' * k_width} | {'-' * v_width} |"
            
            lines = [header, sep]
            for k, v in data.items():
                lines.append(f"| {str(k).ljust(k_width)} | {str(v).ljust(v_width)} |")
            return "\n".join(lines)

def simulate(ber: float, encodings: str, ann_encodings: Optional[str], file_size: int, limit: int):
    channel = BitErrorChannel(ber)
    metrics = SimulationMetrics()
    
    # Simple data for simulation
    source_data = bytes([random.getrandbits(8) for _ in range(file_size)])
    
    for _ in range(limit):
        metrics.files_attempted += 1
        gen = PDUGenerator(
            src_callsign="SIMUL",
            encodings=encodings,
            announcement_encodings=ann_encodings,
            max_payload_size=255
        )
        
        deframer = Deframer()
        pdus = list(gen.generate(source_data))
        
        for pdu in pdus:
            # In simulation, we track overhead by looking at the PDU structure
            # This is a bit of a hack to get "Protocol Overhead"
            try:
                from hqfbp import unpack
                header, payload = unpack(pdu)
                header_packed, _ = unpack(pdu) # Actually just packing/unpacking to estimate
                # We'll just estimate header as total - payload
                h_size = len(pdu) - len(payload)
                metrics.header_bits += h_size * 8
            except:
                pass

            noisy_pdu = channel.process(pdu)
            is_lost = False
            try:
                deframer.receive_bytes(noisy_pdu)
                # If receive_bytes doesn't crash but no event is produced for THIS PDU
                # it might be dropped internally (e.g. CRC failure)
                if not deframer._events:
                    is_lost = True
            except:
                is_lost = True
            
            metrics.add_pdu(pdu, is_lost)
            
            # Clear PDU events to track drops per PDU
            while deframer.next_event():
                pass

        # Check if file was recovered
        # We need to process all events to see if MessageEvent appeared
        # Deframer.next_event() might have been called above, so we should check reassembly state
        # Actually session cleanup happens in _complete_message which adds to _events
        # So we should have seen it.
        # Let's check session status or similar.
        # Simpler: just check if ANY MessageEvent was emitted during this file's PDUs
        # Note: My loop above clears events. I should track if MessageEvent was seen.
        
        # Redo loop with recovery check
        deframer = Deframer()
        recovered = False
        for pdu in pdus:
            noisy_pdu = channel.process(pdu)
            try:
                deframer.receive_bytes(noisy_pdu)
                while True:
                    ev = deframer.next_event()
                    if ev is None: break
                    if isinstance(ev, MessageEvent):
                        if ev.payload == source_data:
                            recovered = True
            except:
                pass
        
        if recovered:
            metrics.files_recovered += 1
            metrics.total_payload_bits += len(source_data) * 8

    return metrics

def main():
    parser = argparse.ArgumentParser(description="HQFBP Simulation Engine")
    parser.add_argument("--ber", type=float, default=0.0, help="Bit Error Rate")
    parser.add_argument("--encodings", type=str, default="h", help="Content encodings (e.g. gzip,h,crc32)")
    parser.add_argument("--ann-encodings", type=str, default=None, help="Announcement encodings")
    parser.add_argument("--file-size", type=int, default=1024, help="File size in bytes")
    parser.add_argument("--limit", type=int, default=10, help="Number of files to transmit")
    parser.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown", help="Output format")
    
    args = parser.parse_args()
    
    metrics = simulate(args.ber, args.encodings, args.ann_encodings, args.file_size, args.limit)
    print(metrics.report(format=args.format))

if __name__ == "__main__":
    main()
