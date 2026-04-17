# Secure Computing Systems – Security Tools Portfolio

## Overview
This repository contains three custom-built command-line security tools developed as part of the 7018SCN Secure Computing Systems coursework. The tools demonstrate practical implementation of secure software development, threat detection, and malware analysis.

## Tools Included

### 1. Secure Authentication System (auth_system.py)
This tool provides a secure user authentication mechanism.

Features:
- Password hashing using PBKDF2 (SHA-256)
- 16-byte random salt for each user
- Strong password policy enforcement:
  - Minimum 12 characters
  - At least one number
  - At least one special character
- Protection against brute-force attacks using login delay
- Secure storage using JSON (no plaintext passwords)

### 2. SIEM Lite – Log Analysis Tool (siem_lite.py)
This tool simulates a basic Security Information and Event Management (SIEM) system.

Features:
- Parses log files (e.g., auth.log or CSV)
- Uses regular expressions to extract IP addresses
- Detects repeated failed login attempts
- Accepts dynamic alert threshold via command-line argument
- Outputs malicious IPs into a structured JSON file

### 3. Malware Analysis & Forensics Tool (malware_scanner.py)
This tool performs safe static analysis of files.

Features:
- SHA-256 hashing using chunk-based reading (4096 bytes)
- Detection of known malicious file signatures
- Safe quarantine of malicious files using shutil
- Directory scanning using os.walk
- Basic whitelist protection for system directories
- EXIF metadata extraction (including GPS data) from image files using Pillow

## How to Run

Use a terminal whose **current working directory** is this project folder (the directory that contains the Python scripts). Output files such as `users.json`, `auth.log`, `siem_results.json`, `malware_report.json`, and `malware_scan.log` are created **in that same directory** unless you change the scripts.

If your project path contains spaces (for example `...\copy 1`), quote the path when changing directory:

```powershell
cd "C:\path\to\this-project-folder"
```

### 1. Secure Authentication System — `auth_system.py`

Runs an **interactive** menu: Register, Login, or Exit. Follow the prompts on screen.

```bash
python auth_system.py
```

**Outputs (project folder):**

- `users.json` — stored password hashes and account state (created after registration or login attempts)
- `auth.log` — audit-style events from the application

---

### 2. SIEM Lite — `siem_lite.py`

Requires **two arguments**: path to a log file, then a **numeric threshold** for alerting. Results are written to **`siem_results.json`** in the current directory.

**Syntax:**

```bash
python siem_lite.py <logfile> <threshold>
```

**Example** (using `sample_log.txt` in this project):

```bash
python siem_lite.py sample_log.txt 3
```

---

### 3. Malware Scanner — `malware_scanner.py`

Runs interactively: when asked for a directory, type a path to scan (relative paths are relative to your current directory).

```bash
python malware_scanner.py
```

**Examples at the prompt:**

- `.` — scan the current project folder  
- `scan_safe` — scan only the `scan_safe` subfolder (safer for quick tests)

**Outputs (project folder):**

- `malware_report.json` — scan summary per file  
- `malware_scan.log` — scan log  
- `QUARANTINE_VAULT/` — destination for quarantined files (created automatically)

## Requirements

Install required library:
pip install pillow

## Example Files

- sample_log.txt - Used for testing SIEM tool  
- users.json - Automatically created for storing user credentials  
- QUARANTINE_VAULT/ - Stores detected malicious files  

## Security Concepts Implemented

- Secure password hashing (PBKDF2)
- Salting to prevent rainbow table attacks
- Regex-based input validation
- Brute-force attack mitigation
- Log-based intrusion detection
- Malware signature matching
- Digital forensics (EXIF metadata extraction)

## Real-World Relevance

- Authentication system reflects secure login implementations used in modern applications
- SIEM Lite simulates security monitoring in Security Operations Centres (SOC)
- Malware scanner demonstrates basic antivirus and forensic analysis techniques

## Disclaimer

This project is developed for educational purposes only. The tools should only be used in controlled environments and with proper authorization.

## Author

Student Name:  
Module: 7018SCN Secure Computing Systems