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

pip install requests python-dotenv

**Usage:**
1. Add your VirusTotal API key to a `.env` file
2. Edit the `ip_list` in the script with your suspicious IPs
3. Run the script

---

## Setup
pip install requests python-dotenv

Create a `.env` file in the same folder:

VT_API_KEY=your_virustotal_api_key_here

---

## Roadmap — coming soon
- 📄 Log parser — detect brute force attempts from Windows event logs
- 📊 Alert triage — pattern detection across SIEM exports
- 📝 Report generator — auto-generate shift handover reports
- 🔔 Notification system — Slack/email alerts for watchlist hits

---

## Certifications
- MSc Cyber Security
- Certified Ethical Hacker (CEH)
- CompTIA Security+
