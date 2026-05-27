# SOC Python Tools 🛡️🐍

> A growing arsenal of Python scripts built for real SOC analyst workflows.
> Every tool in this repository was built to automate something a SOC analyst does manually every single shift.

**Author:** Sreejith Reji | MSc Cyber Security | CEH | CompTIA Security+
**Role:** SOC Analyst (L1)

---

## Why This Repository Exists

Most SOC analysts spend significant time on repetitive manual tasks — copying IPs into VirusTotal one by one, grepping through log files, writing the same incident ticket fields over and over, and producing end-of-shift reports by hand.

This repository is the answer to that. Each script here replaces a manual task with an automated one, freeing up analyst time for the work that actually requires human judgement.

---

## Tools

---

### 🔍 ioc_checker.py
**Bulk IP enrichment via the VirusTotal API**

Manually checking IPs in VirusTotal one at a time is one of the most common time sinks in L1 SOC work. This script takes a list of IPs, queries each one against 70+ security vendors automatically, and prints a clear verdict for each one.

```
=== SOC IOC Checker — VirusTotal ===

[+] IP: 185.220.101.45
    Malicious  : 18
    Suspicious : 4
    Harmless   : 52
    ⚠️  FLAGGED AS MALICIOUS

[+] IP: 8.8.8.8
    Malicious  : 0
    Suspicious : 0
    Harmless   : 94
    ✅ Clean

=== Scan complete ===
```

**SOC use case:** Rapid triage of IPs extracted from firewall alerts, SIEM events, or phishing emails — without opening a browser.

**Requirements:** `requests` `python-dotenv`

**Setup:**
```bash
pip install requests python-dotenv
```
Create a `.env` file:
```
VT_API_KEY=your_virustotal_api_key_here
```
Edit `ip_list` in the script and run:
```bash
python ioc_checker.py
```

**API:** [VirusTotal](https://www.virustotal.com) — free account gives 4 requests/min

---

### 📄 log_analyser.py *(in progress)*
**Automated firewall log parser with alert report generation**

Reads a firewall log file line by line, extracts all relevant fields, scores severity, decides whether to escalate, and generates a formatted SOC alert report for every suspicious entry — automatically.

```
========================================
  SOC ALERT REPORT — ID #1001
========================================
Timestamp     : 2024-01-15 08:22:47
Source IP     : 185.220.101.45
Destination   : 10.0.0.15:4444
Protocol      : TCP
Username      : administrator
Alert type    : Brute Force Attempt
Action        : BLOCK
Failed logins : 47
Severity      : 9.5/10
Blocked       : True
Escalate      : True
========================================
```

**SOC use case:** Process an entire shift's worth of firewall logs in seconds rather than reading line by line manually.

**Compatible log formats:** Firewall logs, syslog, custom formats *(regex patterns configurable)*

**Requirements:** `os` `re` *(standard library — no install needed)*

---

### 📊 alert_triage.py *(planned)*
**Severity scoring and auto-classification from SIEM alert exports**

Takes a CSV export of SIEM alerts, scores each one by severity based on configurable rules, classifies by attack type, and outputs a prioritised triage list — so you always work the most critical alerts first.

**SOC use case:** Start of shift triage — instantly know which alerts need immediate action and which can wait.

---

### 📝 report_generator.py *(planned)*
**Automated shift handover report**

Reads the day's alert data and auto-generates a professional shift handover report — alert counts by severity, top source IPs, notable incidents, and outstanding actions. Outputs as a formatted text file or HTML.

**SOC use case:** End of shift — no more manually writing up what happened. Run the script, review the output, send it.

---

### 👁️ log_monitor.py *(planned)*
**Real-time log monitoring with rule-based alerting**

Tails a live log file, applies configurable detection rules, and triggers an alert the moment a rule fires — printed to terminal or sent via Slack/email.

**SOC use case:** Continuous monitoring during quiet periods — get notified immediately when something suspicious appears rather than polling manually.

---

### 🤖 mini_soar.py *(planned)*
**End-to-end SOC automation — enrich, investigate, ticket**

The capstone tool. Takes an alert, enriches all IOCs against VirusTotal and AbuseIPDB, scores severity, makes an escalation decision, and automatically creates an incident ticket via the Jira or ServiceNow API. One command replaces 20 minutes of manual work.

**SOC use case:** Full alert-to-ticket pipeline with zero manual steps for clear-cut cases.

---

## Repository Structure

```
soc-python-tools/
│
├── ioc_checker.py          ✅ Complete
├── log_analyser.py         🔨 In progress
├── alert_triage.py         📋 Planned
├── report_generator.py     📋 Planned
├── log_monitor.py          📋 Planned
├── mini_soar.py            📋 Planned
│
├── sample_logs/            Sample log files for testing
│   └── → see soc-sample-logs repository
│
├── .env.example            API key template
├── requirements.txt        All dependencies
└── README.md
```

---

## Getting Started

**1. Clone the repository**
```bash
git clone https://github.com/SreejithReji/soc-python-tools.git
cd soc-python-tools
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Set up your API keys**
```bash
cp .env.example .env
```
Edit `.env` and add your keys:
```
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

**4. Run a tool**
```bash
python ioc_checker.py
```

---

## Free API Keys Used

| Service | What it provides | Free tier |
|---|---|---|
| [VirusTotal](https://www.virustotal.com) | IP, hash, domain reputation | 4 requests/min |
| [AbuseIPDB](https://www.abuseipdb.com) | IP abuse reports | 1,000 requests/day |
| [Shodan](https://www.shodan.io) | IP open ports and services | 100 results/month |

All tools are built around free API tiers — no paid subscriptions required.

---

## Sample Log Files

Realistic sample log files for testing these tools are maintained in a separate repository:

👉 **[soc-sample-logs](https://github.com/SreejithReji/soc-sample-logs)**

500-line log files covering firewall, Windows Event, web access, DNS, and IDS — simulating a full attack lifecycle from quiet baseline through breach and exfiltration.

---

## Skills Demonstrated

| Skill | Where used |
|---|---|
| Python scripting | All tools |
| REST API integration | `ioc_checker.py`, `mini_soar.py` |
| JSON parsing | `ioc_checker.py` |
| File I/O and log parsing | `log_analyser.py`, `log_monitor.py` |
| Regex | `log_analyser.py` |
| Error handling | All tools |
| Environment variable management | All tools with API keys |
| Security automation | `mini_soar.py` |
| Git and version control | This repository |

---

## Related Repositories

| Repository | Description |
|---|---|
| [soc-sample-logs](https://github.com/SreejithReji/soc-sample-logs) | Sample log files for testing |
| [kql-soc-queries](https://github.com/SreejithReji/kql-soc-queries) | KQL query library for Microsoft Sentinel |
| [spl-soc-queries](https://github.com/SreejithReji/spl-soc-queries) | SPL query library for Splunk |
| [cybersecurity-portfolio](https://github.com/SreejithReji/cybersecurity-portfolio) | Full portfolio overview |

---

*Tools are added as they are built. This repository is actively developed alongside a structured Python SOC learning plan.*
