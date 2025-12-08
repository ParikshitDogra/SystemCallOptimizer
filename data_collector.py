import subprocess
import re
import csv
import sys
import time
import signal

# Configuration
OUTPUT_FILE = "syscall_dataset.csv"
TARGET_SCRIPT = "dummy_app.py"

# Regex to parse strace output
# Example line: read(3, "data", 1024) = 1024 <0.000050>
# Captures: (syscall_name), (arguments), (return_value), (execution_time)
STRACE_REGEX = re.compile(r'^(\w+)\((.*)\)\s+=\s+([-0-9a-fx\?]+).*\s+<([0-9\.]+)>')

def parse_strace_line(line):
    """Parses a single line of strace output into a dictionary."""
    match = STRACE_REGEX.search(line)
    if match:
        return {
            "timestamp": time.time(),
            "syscall": match.group(1),
            "args": match.group(2)[:50], # Truncate args to keep CSV clean
            "result": match.group(3),
            "latency": float(match.group(4))
        }
    return None

def main():
    print("--- AI System Call Optimization: Phase 1 ---")
    print(f"[*] Starting {TARGET_SCRIPT} under strace...")
    
    # Open CSV for writing
    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'syscall', 'args', 'result', 'latency']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Start the dummy app wrapped in strace
        # -T: Measure time spent in system calls
        # -e trace=all: Trace all system calls
        # -o /dev/stdout: strace writes to stderr by default, pipe to stdout for easier reading
        cmd = ["strace", "-T", "-e", "trace=all", "python3", TARGET_SCRIPT]
        
        # We pipe stderr because strace writes there by default
        process = subprocess.Popen(
            cmd, 
            stderr=subprocess.PIPE, 
            universal_newlines=True,
            bufsize=1
        )

        print(f"[*] Collection started. Data writing to {OUTPUT_FILE}")
        print("[*] Press Ctrl+C to stop collection.")

        try:
            line_count = 0
            # Read stderr line by line
            for line in iter(process.stderr.readline, ''):
                data = parse_strace_line(line.strip())
                
                if data:
                    writer.writerow(data)
                    line_count += 1
                    if line_count % 50 == 0:
                        print(f"\rCaptured {line_count} calls...", end="")
                        
        except KeyboardInterrupt:
            print("\n[*] Stopping data collection...")
        finally:
            process.terminate()
            print(f"\n[+] Done. Dataset saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()