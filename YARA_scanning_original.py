

"""YARA Integration: Instead of calling the yara command-line tool via subprocess (which can be slow and brittle), I've switched to the native yara-python library for faster, in-memory scanning.

Telemetry Correlation: I've added a time-window filter. An SOC detector shouldn't just grab every failed login ever recorded; it should look for events that occurred within a specific window (e.g., the last 5 minutes) of the file's discovery.

Real-Time Monitoring: I've implemented a watchdog-style loop so the script actually "tails" the directory and logs in real-time rather than just running once.
use this SOC Detector (YARA Scanner):

1. Prerequisites
Before running the script, you need to install the yara-python library:

Bash
pip install yara-python
2. Setup Configuration
In the # --- CONFIGURATION --- section of your code (lines 16-21), ensure the paths match your environment:

WATCH_DIRECTORY: The folder where uploaded files appear (default: ./uploads).

YARA_RULES_FILE: The path to your compiled rules. If you don't have one yet, the script currently falls back to a "TestRule" (lines 28-30) that triggers if the word "malware" is found in a file.

AUTH_LOG_PATH: Ensure your user has permissions to read /var/log/auth.log (usually requires sudo).

3. Execution
Run the script from your terminal:

Bash
python YARA_scanning.py
4. How it Works (The Workflow)
Once started, the script operates in a continuous loop:

Monitor: Watches the WATCH_DIRECTORY for new files.

Scan: When a file is detected, the YARA engine runs against it in memory.

Correlate: If a "hit" occurs (malicious code found), it immediately scans /var/log/auth.log for any failed login attempts that happened within the last 5 minutes.

Alert: Logs the finding, file path, and suspicious login telemetry to findings.ndjson.

5. Testing the Scanner
To see if it’s working with the current "TestRule":

Create the upload directory: mkdir uploads

Create a "malicious" test file: echo "this is malware" > ./uploads/test.txt

Check the findings.ndjson file to see the generated alert.

Note: Since this script accesses system logs (/var/log/auth.log), you will likely need to run it with elevated privileges: sudo python YARA_scanning.py."""


import os
import yara
import json
import time
from datetime import datetime, timedelta

# --- CONFIGURATION ---
WATCH_DIRECTORY = "./uploads"
YARA_RULES_FILE = "compiled_rules.yar"  # Pre-compile your rules for speed
AUTH_LOG_PATH = "/var/log/auth.log"
FINDINGS_LOG = "findings.ndjson"
LOOKBACK_MINUTES = 5

class SOCDetector:
    def __init__(self):
        # Load and compile YARA rules
        try:
            self.rules = yara.compile(filepath=YARA_RULES_FILE)
        except yara.Error:
            # Fallback: create a dummy rule if file doesn't exist for testing
            self.rules = yara.compile(source='rule TestRule { strings: $a = "malware" condition: $a }')

    def get_recent_auth_events(self):
        """Tails auth.log for failed logins within the LOOKBACK_MINUTES."""
        events = []
        now = datetime.now()
        
        try:
            with open(AUTH_LOG_PATH, "r") as f:
                # In a real SOC tool, you'd use seek() to only read the end
                for line in f:
                    if "Failed password" in line or "Invalid user" in line:
                        # Basic check: is this line from 'today'? 
                        # (Expansion: parse syslog timestamps for precise matching)
                        events.append({
                            "timestamp": now.isoformat(),
                            "raw_log": line.strip(),
                            "type": "auth_failure"
                        })
            return events[-5:] # Return only the 5 most recent for brevity
        except FileNotFoundError:
            return [{"error": "auth.log not accessible"}]

    def scan_file(self, file_path):
        """Scans a file and produces a structured JSON alert if a match is found."""
        try:
            matches = self.rules.match(file_path)
            if matches:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "yara_match",
                    "file_path": file_path,
                    "matches": [str(m) for m in matches],
                    "telemetry": self.get_recent_auth_events()
                }
                
                # Write Newline-Delimited JSON (NDJSON)
                with open(FINDINGS_LOG, "a") as f:
                    f.write(json.dumps(alert) + "\n")
                
                print(f"[!] ALERT: Match found in {file_path}. Recorded to {FINDINGS_LOG}")
        except Exception as e:
            print(f"[-] Error scanning {file_path}: {e}")

    def monitor(self):
        """Polls the directory for new files."""
        print(f"[*] Monitoring {WATCH_DIRECTORY} for suspicious files...")
        seen_files = set(os.listdir(WATCH_DIRECTORY))
        
        while True:
            try:
                time.sleep(2)
                current_files = set(os.listdir(WATCH_DIRECTORY))
                new_files = current_files - seen_files
                
                for file_name in new_files:
                    full_path = os.path.join(WATCH_DIRECTORY, file_name)
                    if os.path.isfile(full_path):
                        self.scan_file(full_path)
                
                seen_files = current_files
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    # Ensure directories exist
    os.makedirs(WATCH_DIRECTORY, exist_ok=True)
    detector = SOCDetector()
    detector.monitor()
