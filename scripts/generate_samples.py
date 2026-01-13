import os
import subprocess
import json
import sys

# Define test cases: (name, encodings, announcement_encodings, max_payload_size)
TEST_CASES = [
    ("basic", "h,crc32", "", 1024),
    ("compressed", "gzip,h,crc32", "", 1024),
    ("fec_rs", "h,rs(255,223)", "h,crc32,repeat(3)", 223),
    ("fec_rs_crc32", "h,rs(255,223),crc32", "h,crc32,repeat(3)", 223),
    ("fec_rq", "h,rq(dlen,512,0)", "h,crc32,repeat(3)", 1024),
    ("complex", "gzip,h,rs(255,223),crc32", "h,crc32", 223),
    ("scrambled", "scr(0x1234),h,crc32", "", 1024),
    ("chunked_large", "gzip,h,crc32", "", 256),
    ("repeat", "h,repeat(3),crc16", "h,crc16", 512),
    ("fec_lt", "h,lt(dlen,512,10)", "h,crc32,repeat(3)", 6000),
]

def generate_payload(size=1024):
    """Generate a stable pseudo-random payload."""
    import hashlib
    content = b"HQFBP Test Payload"
    while len(content) < size:
        content += hashlib.sha256(content).digest()
    return content[:size]

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    samples_dir = os.path.join(project_root, "samples")
    
    os.makedirs(samples_dir, exist_ok=True)
    
    payload_path = os.path.join(samples_dir, "test_payload.bin")
    payload_data = generate_payload(5120)
    with open(payload_path, "wb") as f:
        f.write(payload_data)

    print(f"Generating samples in {samples_dir}...")

    for name, encs, ann_encs, max_payload in TEST_CASES:
        output_kiss = os.path.join(samples_dir, f"{name}.kiss")
        output_json = os.path.join(samples_dir, f"{name}.json")
        
        cmd = [
            "python3", "src/hqfbp/pack.py",
            payload_path,
            "--src-callsign", "TEST-GEN",
            "--output", output_kiss
        ]
        
        if encs:
            cmd.extend(["--encodings", encs])
        if ann_encs:
            cmd.extend(["--announcement-encodings", ann_encs])
        if max_payload:
            cmd.extend(["--max-payload-size", str(max_payload)])

        print(f"  Generating {name}...")
        try:
            subprocess.run(cmd, cwd=project_root, check=True, capture_output=True, text=True)
            
            # Save arguments to JSON
            args_info = {
                "name": name,
                "filepath": "test_payload.bin",
                "src_callsign": "TEST-GEN",
                "encodings": encs,
                "announcement_encodings": ann_encs,
                "max_payload_size": max_payload,
                "output": f"{name}.kiss"
            }
            with open(output_json, "w") as f:
                json.dump(args_info, f, indent=2)
                
        except subprocess.CalledProcessError as e:
            print(f"Error generating {name}: {e.stderr}", file=sys.stderr)

    print("Done.")

if __name__ == "__main__":
    main()
