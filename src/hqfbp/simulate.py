import argparse
import random
import json
import csv
import sys
import io
from typing import List, Dict, Any, Optional
from hqfbp.generator import PDUGenerator
from hqfbp.deframer import Deframer, MessageEvent, PDUEvent
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
        self.total_bit_errors_introduced = 0
        self.total_residual_bit_errors = 0
        self.total_bits_evaluated = 0

    def add_pdu(self, pdu_bytes: bytes, lost: bool):
        self.total_pdus_sent += 1
        bits = len(pdu_bytes) * 8
        self.total_bits_sent += bits
        
        if lost:
            self.pdus_lost += 1
            self.current_burst_loss += 1
            self.max_burst_loss = max(self.max_burst_loss, self.current_burst_loss)
        else:
            self.current_burst_loss = 0

    def add_residual_errors(self, original_payload: bytes, decoded_payload: bytes):
        length = min(len(original_payload), len(decoded_payload))
        self.total_bits_evaluated += length * 8
        for i in range(length):
            diff = original_payload[i] ^ decoded_payload[i]
            # Count set bits (bit errors)
            self.total_residual_bit_errors += bin(diff).count('1')
        # Also count length differences as bit errors (simplified)
        self.total_residual_bit_errors += abs(len(original_payload) - len(decoded_payload)) * 8

    def report(self, format="markdown") -> str:
        efficiency = (self.total_payload_bits / self.total_bits_sent * 100) if self.total_bits_sent > 0 else 0
        packet_loss_rate = (self.pdus_lost / self.total_pdus_sent * 100) if self.total_pdus_sent > 0 else 0
        file_loss_rate = ((self.files_attempted - self.files_recovered) / self.files_attempted * 100) if self.files_attempted > 0 else 0
        overhead = ((self.header_bits + self.padding_bits) / self.total_bits_sent * 100) if self.total_bits_sent > 0 else 0
        fec_recovery = (self.files_recovered / self.files_attempted * 100) if self.files_attempted > 0 else 0
        rber = (self.total_residual_bit_errors / self.total_bits_evaluated) if self.total_bits_evaluated > 0 else 0

        data = {
            "Total Bytes Sent": self.total_bits_sent // 8,
            "Packet Loss Rate (%)": round(packet_loss_rate, 2),
            "File Loss Rate (%)": round(file_loss_rate, 2),
            "Residual Bit Error Rate": f"{rber:.2e}",
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
        
        # 1. Generate clean PDUs and extract their expected payloads using a clean deframer
        clean_pdus_info = []
        clean_deframer = Deframer()
        for pdu in gen.generate(source_data):
            try:
                clean_deframer.receive_bytes(pdu)
                while True:
                    ev = clean_deframer.next_event()
                    if ev is None: break
                    if isinstance(ev, PDUEvent):
                        clean_pdus_info.append((pdu, ev.payload))
                        h_size = len(pdu) - len(ev.payload)
                        metrics.header_bits += h_size * 8
            except Exception:
                pass

        if not clean_pdus_info:
            continue

        noisy_deframer = Deframer()
        recovered = False
        
        for clean_pdu, expected_payload in clean_pdus_info:
            noisy_pdu = channel.process(clean_pdu)
            
            try:
                noisy_deframer.receive_bytes(noisy_pdu)
                
                # Check events
                pdu_accepted = False
                while True:
                    ev = noisy_deframer.next_event()
                    if ev is None: break
                    
                    if isinstance(ev, PDUEvent):
                        pdu_accepted = True
                        metrics.add_residual_errors(expected_payload, ev.payload)
                    elif isinstance(ev, MessageEvent):
                        if ev.payload == source_data:
                            recovered = True
                
                metrics.add_pdu(clean_pdu, lost=not pdu_accepted)
                    
            except Exception:
                metrics.add_pdu(clean_pdu, lost=True)
        
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
    parser.add_argument("--debug", action="store_true", help="Enable debug prints")
    
    args = parser.parse_args()
    
    # We can inject a debug flag into simulate if needed, or just let main handle it
    # For now, let's just make simulate more verbose if we want, but better keep it clean.
    
    metrics = simulate(args.ber, args.encodings, args.ann_encodings, args.file_size, args.limit)
    print(metrics.report(format=args.format))

if __name__ == "__main__":
    main()
