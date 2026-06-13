# SOC Python Tools 🛡️🐍

> A growing arsenal of Python scripts built for real SOC analyst workflows.
> Every tool in this repository was built to automate something a SOC analyst does manually every single shift.

**Author:** Sreejith Reji | MSc Cyber Security | CEH | CompTIA Security+
**Role:** ITOC Network Support Engineer — incoming SOC Analyst (L1)

---

## Why This Repository Exists

Most SOC analysts spend significant time on repetitive manual tasks — copying IPs into VirusTotal one by one, grepping through log files, writing the same incident ticket fields over and over, and producing end-of-shift reports by hand.

This repository is the answer to that. Each script here replaces a manual task with an automated one, freeing up analyst time for the work that actually requires human judgement.

---

## Tools

---

### 🔍 ioc_checker.py ✅
**Bulk IP enrichment via the VirusTotal API**

Manually checking IPs in VirusTotal one at a time is one of the most common time sinks in L1 SOC work. This script takes a list of IPs, queries each one against 70+ security vendors automatically, and prints a clear verdict for each one.
The code has been updated to dynamically enter the IP's to be scanned while running the code rather than hard-coding the IP.

```
=== SOC IOC Checker — VirusTotal ===

[+] IP: 185.220.101.45
    Reputation : -21
    Country    : DE
    Tags       : tor
    Malicious  : 17
    Suspicious : 4
    Harmless   : 42
    ⚠️  FLAGGED AS MALICIOUS

[+] IP: 8.8.8.8
    Reputation : 544
    Country    : US
    Tags       :
    Malicious  : 0
    Suspicious : 0
    Harmless   : 55
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

### ⚡ alert_triage.py ✅
**Real-time log line triage with watchlist checking and priority scoring**

Paste a raw log line directly into the terminal. The script extracts all key fields using regex, checks the source IP against a configurable watchlist of known bad IPs, and instantly assigns a priority — Critical, High, Medium, or Low — based on layered triage logic.

```
========================================
  SOC ALERT TRIAGE SUMMARY
========================================
  Source IP        : 185.220.101.45
  Destination IP   : 10.0.0.15
  Username         : administrator
  Failed attempts  : 47
  Destination port : 4444
  Known bad IP     : True
========================================
  Priority         : 🔴 CRITICAL
========================================
```

**Triage logic applied:**
- Known bad IP + administrator account → **Critical**
- Known bad IP only → **High**
- 5+ failed attempts + administrator → **High**
- 5+ failed attempts → **Medium**
- Suspicious port (4444, 1337, 9001, 31337) → **Medium**
- Everything else → **Low**

**SOC use case:** Live alert investigation — paste a log line during triage and get an instant priority verdict without manually checking each field.

**Requirements:** `re` *(standard library — no install needed)*

**Run:**
```bash
python alert_triage.py
```

**Test with this log line:**
```
2024-01-15 08:22:47 BLOCK TCP src=185.220.101.45 dst=10.0.0.15 port=4444 user=administrator failed=47
```

---

### 🔥 log_analyser_ttp.py ✅
**Firewall log analyser with threat intel cross-referencing and MITRE ATT&CK mapping**

Reads a firewall log and a JSON threat intelligence feed, cross-references every blocked connection against known malicious IPs, identifies the top offending host, and produces a structured detection report — with a live MITRE ATT&CK reference embedded directly in the output.

```
================================================
         FIREWALL DETECTION REPORT
================================================
MITRE Technique  : T1110 - Brute Force
Tactic           : Lateral Movement / C2
Reference        : https://attack.mitre.org/techniques/T1110/
------------------------------------------------
Total DENY events     : 9
------------------------------------------------
TOP OFFENDER
Source IP    : 10.0.0.5
Block count  : 7
------------------------------------------------
THREAT INTEL MATCHES
2024-01-15 08:13:01 DENY TCP 10.0.0.5 -> 185.220.101.45:22
  ↳ Risk Score: 95 | Country: Germany | Tags: tor-exit, malicious
2024-01-15 08:14:02 DENY TCP 10.0.0.5 -> 185.220.101.45:22
  ↳ Risk Score: 95 | Country: Germany | Tags: tor-exit, malicious
------------------------------------------------
ASSESSMENT
Confirmed T1110 Brute Force activity detected.
Host 10.0.0.5 generated 7 blocked attempts.
2 connections matched known malicious IPs.
Recommend isolating host and reviewing endpoint logs.
================================================
```

**MITRE ATT&CK coverage:**

| Technique ID | Name | Tactic |
|---|---|---|
| T1110 | Brute Force | Credential Access |
| T1110.001 | Password Guessing | Credential Access |
| T1071 | Application Layer Protocol | Command & Control |

**SOC use case:** End-of-shift or incident investigation — feed in a firewall log and threat intel export, get a detection report ready to attach to a ticket or escalate to L2. Identifies compromised internal hosts attempting lateral movement or C2 communication.

**Requirements:** `json` `os` `collections` *(all standard library — no install needed)*

**Run:**
```bash
python log_analyser_ttp.py
```
When prompted:
```
Enter the name of the firewall log file: firewall.log
Enter the name of the threat intelligence file: threat_intel.json
```

**Input files required:**
- `firewall.log` — standard firewall log with ALLOW/DENY entries
- `threat_intel.json` — JSON array of known malicious IPs with risk scores and tags

---
### 🔎 bulk_ioc_enricher ✅
**Multi-source IP enrichment with automatic MITRE ATT&CK mapping**

Takes multiple IPs, queries both VirusTotal and AbuseIPDB simultaneously, 
cross-references results, and automatically maps detected TTPs to the 
MITRE ATT&CK framework — no hardcoding required.    

=== SOC Bulk IOC Enricher ===

========================================
IP: 185.220.101.45
========================================
[VirusTotal]
  Reputation       : -21
  Country          : DE
  Tags             : tor
  Malicious        : 17
  Suspicious       : 4
  Harmless         : 41

[AbuseIPDB]
  Confidence Score : 100
  Total Reports    : 121
  Whitelisted      : False
  Usage Type       : Commercial
  Country Code     : DE

[MITRE ATT&CK]
  T1071  : Application Layer Protocol
  Tactic : command-and-control
  Ref    : https://attack.mitre.org/techniques/T1071/

  T1590  : Gather Victim Network Information
  Tactic : reconnaissance
  Ref    : https://attack.mitre.org/techniques/T1590/

Verdict: 🔴 CONFIRMED MALICIOUS — flagged by both sources

========================================
IP: 8.8.8.8
========================================
[VirusTotal]
  Reputation       : 544
  Country          : US
  Tags             :
  Malicious        : 0
  Suspicious       : 0
  Harmless         : 55

[AbuseIPDB]
  Confidence Score : 0
  Total Reports    : 135
  Whitelisted      : True
  Usage Type       : Content Delivery Network
  Country Code     : US

Verdict: 🟢 CLEAN

=== Scan complete ===
---

### 📝 report_generator.py *(trial version available)*
**Professional SOC report generation — three report types**

Asks the analyst a series of questions and automatically generates a formatted professional report. Supports three report types covering the most common L1 documentation tasks.

**Report types:**
- **Escalation report** — structured L1 to L2 handoff with full investigation summary
- **False positive report** — documented justification for closing an alert
- **Shift handover report** — end of shift summary for the incoming analyst

**SOC use case:** Stop writing the same report fields from scratch every time. Run the script, answer the questions, get a professional formatted report ready to attach to a ticket or send to your team lead.


**Requirements:** `datetime` *(standard library — no install needed)*

---

### 📊 csv_triage.py *(planned)*
**Bulk SIEM alert triage from CSV export**

Takes a CSV export of SIEM alerts, scores each one by severity based on configurable rules, classifies by attack type, and outputs a prioritised triage list — so you always work the most critical alerts first.

**SOC use case:** Start of shift bulk triage — feed in the overnight alert export and instantly know which alerts need immediate action and which can wait.

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
├── alert_triage.py         ✅ Complete
├── log_analyser_ttp.py     ✅ Complete
├── bulk_ioc_enricher/      ✅ Complete
├── report_generator.py     📋 Planned
├── csv_triage.py           📋 Planned
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
python alert_triage.py
python log_analyser_ttp.py
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

## MITRE ATT&CK Coverage

All detection tools in this repository are mapped to MITRE ATT&CK techniques. Each script embeds the relevant technique ID, tactic, and reference URL directly in its output.

| Tool | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| log_analyser_ttp.py | T1110 | Brute Force | Credential Access |
| log_analyser_ttp.py | T1110.001 | Password Guessing | Credential Access |
| log_analyser_ttp.py | T1071 | Application Layer Protocol | Command & Control |
| mini_soar.py *(planned)* | T1078 | Valid Accounts | Persistence |

---

## Skills Demonstrated

| Skill | Where used |
|---|---|
| Python scripting | All tools |
| Regex | `alert_triage.py`, `log_analyser_ttp.py` |
| REST API integration | `ioc_checker.py`, `mini_soar.py` |
| JSON parsing | `ioc_checker.py`, `log_analyser_ttp.py` |
| File I/O and log parsing | `log_analyser_ttp.py`, `log_monitor.py` |
| Error handling | All tools |
| Threat intel cross-referencing | `log_analyser_ttp.py` |
| Multi-source threat intel correlation | bulk_ioc_enricher |
| Modular Python architecture | bulk_ioc_enricher, enrichment.py, ttp_mapper.py |
| MITRE ATT&CK TTP mapping | `log_analyser_ttp.py` |
| If/else triage logic | `alert_triage.py` |
| Dictionary and set operations | `log_analyser_ttp.py` |
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
