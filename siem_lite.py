import re
import sys
import json
import os
from datetime import datetime
from collections import defaultdict


# Validate CLI arguments

if len(sys.argv) < 3:
    print("Usage: python siem_lite.py <logfile> <threshold>")
    sys.exit(1)

log_file = sys.argv[1]

try:
    threshold = int(sys.argv[2])
except ValueError:
    print("Threshold must be numeric")
    sys.exit(1)

if not os.path.exists(log_file):
    print("Log file not found")
    sys.exit(1)


# Strict IP validation (0–255)

ip_pattern = (
    r"\b(?:"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)


# Data structures

failed_attempts = defaultdict(list)
successful_logins = defaultdict(list)


# Parse logs (STRUCTURED)

def parse_line(line):
    timestamp_match = re.match(r"^(\w+\s+\d+\s+\d+:\d+:\d+)", line)
    ip_match = re.search(ip_pattern, line)

    if not timestamp_match or not ip_match:
        return None, None

    try:
        timestamp_str = timestamp_match.group(1) + " 2026"
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
    except:
        return None, None

    return timestamp, ip_match.group()


# Read file safely

with open(log_file, "r") as file:
    for line in file:
        line = line.strip()

        if len(line) > 1000:  # defence against malicious logs
            continue

        timestamp, ip = parse_line(line)

        if not ip:
            continue

        if "Failed password" in line:
            failed_attempts[ip].append(timestamp)
        elif "Accepted password" in line:
            successful_logins[ip].append(timestamp)


# OPTIMISED sliding window detection (O(n))

TIME_WINDOW = 60

def detect_bruteforce(attempts):
    attempts.sort()
    left = 0
    max_count = 0

    for right in range(len(attempts)):
        while (attempts[right] - attempts[left]).total_seconds() > TIME_WINDOW:
            left += 1

        window_size = right - left + 1
        max_count = max(max_count, window_size)

    return max_count


# Analysis + Multi-attack detection

results = []

for ip, attempts in failed_attempts.items():

    count = detect_bruteforce(attempts)
    total_attempts = len(attempts)
    success_after_fail = ip in successful_logins

   
    # Attack classification logic


    if count >= threshold:
        attack_type = "Brute Force Attack"
        risk = "HIGH"

    elif total_attempts >= threshold:
        attack_type = "Slow Brute Force"
        risk = "MEDIUM"

    elif total_attempts > 1:
        attack_type = "Suspicious Activity"
        risk = "LOW"

    else:
        attack_type = "Normal Behaviour"
        risk = "LOW"


    # Build result
    
    results.append({
        "ip": ip,
        "failed_attempts": total_attempts,
        "burst_attempts": count,
        "successful_login": success_after_fail,
        "attack_type": attack_type,
        "risk_level": risk
    })


# Export results

output_file = "siem_results.json"

with open(output_file, "w") as f:
    json.dump(results, f, indent=4)

print("\nSIEM Analysis Complete")
print(f"Results saved to {output_file}")