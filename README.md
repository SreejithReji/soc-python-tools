# SOC Python Tools 🛡️

A growing collection of Python scripts built for SOC analyst workflows.
Developed as part of my transition into an L1 SOC analyst role.

## About Me
Cybersecurity professional with an MSc in Cyber Security, CEH, and Security+.
Currently building Python scripting skills applied to real SOC use cases.

---

## Tools

### 🔍 ioc_checker.py
Bulk IP enrichment tool using the VirusTotal API.

**What it does:**
- Takes a list of suspicious IP addresses
- Queries each one against 70+ security vendors via VirusTotal
- Flags malicious and suspicious IPs with a clear verdict
- Respects free API rate limits automatically

**SOC use case:** Rapid triage of IPs from firewall alerts or SIEM events
without manually copying each one into VirusTotal.

**Requirements:**
