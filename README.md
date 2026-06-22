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

Manually checking IPs in VirusTotal one at a time is one of the most common time sinks in L1 SOC work. This script takes a list of IPs, queries each one against 70+ security vendors automatically, and prints a clear verdict for each one. The code has been updated to dynamically enter the IPs to be scanned while running the code rather than hard-coding them.

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

Run:
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

**SOC use case:** End-of-shift or incident investigation — feed in a firewall log and threat intel export, get a detection report ready to attach to a ticket or escalate to L2.

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

Takes multiple IPs, queries both VirusTotal and AbuseIPDB, cross-references results, and automatically maps detected TTPs to the MITRE ATT&CK framework — no hardcoding required. Built as a modular three-file tool: `bulk_ioc_enricher.py`, `enrichment.py`, and `ttp_mapper.py`.

```
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
```

**SOC use case:** Multi-source IOC triage — query two threat intelligence feeds simultaneously, get a combined verdict, and see the relevant MITRE ATT&CK techniques automatically pulled from the live framework data.

**Requirements:** `requests` `python-dotenv`

**Setup:**
```bash
pip install requests python-dotenv
```

Create a `.env` file:
```
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_KEY=your_abuseipdb_key_here
```

Run:
```bash
python bulk_ioc_enricher.py
```

**APIs:** [VirusTotal](https://www.virustotal.com) · [AbuseIPDB](https://www.abuseipdb.com) · [MITRE ATT&CK](https://attack.mitre.org)

---

### 📊 csv_triage.py ✅
**Bulk SIEM alert triage from CSV export**

Takes a CSV export of SIEM alerts, scores each one by severity based on rule logic (alert type, failed attempt count, destination port), sorts the full list by priority rank, and outputs a clean triage view — critical alerts always surface first regardless of their order in the original file.

```
🔴 Critical | 103.45.67.12   | brute_force
🔴 Critical | 203.0.113.45   | sql_injection
🟠 High     | 185.220.101.45 | brute_force
🟡 Medium   | 45.33.32.156   | port_scan
🟡 Medium   | 89.248.167.131 | port_scan
🟢 Low      | 8.8.8.8        | dns_query
🟢 Low      | 1.1.1.1        | dns_query
🟢 Low      | 192.168.1.50   | failed_login
```

**SOC use case:** Start of shift bulk triage — feed in the overnight alert export and instantly know which alerts need immediate action and which can wait.

**Requirements:** `csv` *(standard library — no install needed)*

**Run:**
```bash
python csv_triage.py
```

**Input file required:**
- `siem_alerts.csv` — columns: `timestamp, source_ip, dest_ip, alert_type, failed_attempts, port`

---

### 👁️ log_monitor.py ✅
**Real-time log monitoring with rotation handling and rule-based alerting**

Tails a live log file the same way production log shippers do — processes existing content once, then watches continuously for new lines using file position tracking. Detects log rotation (file truncated or replaced) via inode and size comparison and reopens automatically without losing alerts. Applies keyword-based detection rules and extracts the source IP from each suspicious line via regex.

```
🔴 Possible brute force attempt — IP: 185.220.101.45 — Failed password for root from 185.220.101.45 port 51422 ssh2
🟠 Unknown user login attempt — IP: 103.45.67.12 — Invalid user admin from 103.45.67.12 port 39281 ssh2
🟡 Authentication issue — IP: 89.248.167.131 — pam_unix(sshd:auth): authentication failure rhost=89.248.167.131
```

**SOC use case:** Continuous monitoring during quiet periods — get notified immediately when something suspicious appears in a live log, without manually polling, and without losing visibility if the log file gets rotated mid-shift.

**Requirements:** `re`, `os`, `time` *(all standard library — no install needed)*

**Run:**
```bash
python log_monitor.py
```

**Input file required:**
- `live.log` — any line-based log file (tested against SSH auth log format)

---

### 🤖 mini_soar.py ✅
**End-to-end SOC automation — detect, enrich, score, ticket, notify**

The capstone tool. Tails a live log file, detects suspicious activity, enriches the source IP against VirusTotal and AbuseIPDB, automatically maps the alert to its MITRE ATT&CK technique, scores severity based on detected behaviour, generates a styled HTML incident ticket, saves it to disk, and emails it — fully automatically, with zero manual steps for clear-cut cases.

Built as six independent modules orchestrated by one main script:

| Module | Responsibility |
|---|---|
| `alert_rules.py` | Detects suspicious log patterns, extracts source IP via regex |
| `severity.py` | Scores severity from detected behaviour — independent of external data |
| `enrichment.py` | VirusTotal + AbuseIPDB lookups |
| `ttp_mapper.py` | Live MITRE ATT&CK technique lookup |
| `ticket_generator.py` | Builds severity-coded HTML incident tickets, saves to disk |
| `notifier.py` | Sends the ticket via email |
| `mini_soar.py` | Orchestrates the full pipeline, deduplication, private-IP handling |

**Key design decisions:**
- **Severity is behaviour-based, not enrichment-dependent** — a detected brute force attempt is scored the same whether or not external threat intel is available, since internal/private IPs have no public reputation data
- **Private IP detection** — automatically skips VirusTotal/AbuseIPDB enrichment for internal/private IPs (common in home lab environments) and notes this clearly on the ticket rather than failing or returning meaningless data
- **Alert deduplication** — a 5-minute cooldown per source IP prevents a single sustained attack (e.g. repeated brute force attempts) from generating a flood of duplicate tickets and emails

```
SOC Incident Alert                                    [CRITICAL]
----------------------------------------------------------------
Ticket ID     : CRIT-20260620143205
Timestamp     : 2026-06-20 14:32:05
Source IP     : 185.220.101.45
Country       : DE

[VirusTotal]
Malicious     : 17 engines
Reputation    : -21
Tags          : tor

[AbuseIPDB]
Confidence    : 100%
Total reports : 121
Usage type    : Commercial

[MITRE ATT&CK]
Technique     : T1110
Name          : Brute Force
Tactic        : credential-access

Recommendation: Investigate source IP, review related logs,
                consider blocking if confirmed malicious.
```

**SOC use case:** Full alert-to-ticket pipeline with zero manual steps for clear-cut cases — built and tested against a home SOC lab (Raspberry Pi target, Kali attacker, Wazuh SIEM).

**Requirements:** `requests`, `python-dotenv`, `smtplib` *(standard library for email)*

**Setup:**
```bash
pip install requests python-dotenv
```

Create a `.env` file:
```
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_KEY=your_abuseipdb_key_here
ALERT_EMAIL=your_alerting_gmail_address
ALERT_EMAIL_PASSWORD=your_gmail_app_password
```

Run:
```bash
python mini_soar.py
```

**APIs:** [VirusTotal](https://www.virustotal.com) · [AbuseIPDB](https://www.abuseipdb.com) · [MITRE ATT&CK](https://attack.mitre.org)

---

### 📝 report_generator.py ✅ *(trial version)*
**Professional SOC report generation — three report types**

Asks the analyst a series of questions and automatically generates a formatted professional report. Supports three report types covering the most common L1 documentation tasks.

**Report types:**
- **Escalation report** — structured L1 to L2 handoff with full investigation summary
- **False positive report** — documented justification for closing an alert
- **Shift handover report** — end of shift summary for the incoming analyst

**SOC use case:** Stop writing the same report fields from scratch every time. Run the script, answer the questions, get a professional formatted report ready to attach to a ticket or send to your team lead.

**Requirements:** `datetime` *(standard library — no install needed)*

---

## Repository Structure

```
soc-python-tools/
│
├── alert_triage/           ✅ Complete
├── bulk_ioc_enricher/      ✅ Complete
│   ├── bulk_ioc_enricher.py
│   ├── enrichment.py
│   └── ttp_mapper.py
├── ioc_checker/            ✅ Complete
├── log_analyser_ttp/       ✅ Complete
├── csv_triage/             ✅ Complete
├── log_monitor/            ✅ Complete
├── mini_soar/              ✅ Complete
│   ├── mini_soar.py
│   ├── alert_rules.py
│   ├── severity.py
│   ├── enrichment.py
│   ├── ttp_mapper.py
│   ├── ticket_generator.py
│   └── notifier.py
└── report_generator/       🔨 Trial version available
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

Create a `.env` file in the tool folder you want to run:
```
VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_KEY=your_abuseipdb_key_here
ALERT_EMAIL=your_alerting_gmail_address
ALERT_EMAIL_PASSWORD=your_gmail_app_password
```

**4. Run a tool**
```bash
python ioc_checker/ioc_checker.py
python alert_triage/alert_triage.py
python bulk_ioc_enricher/bulk_ioc_enricher.py
python csv_triage/csv_triage.py
python log_monitor/log_monitor.py
python mini_soar/mini_soar.py
```

---

## Free API Keys Used

| Service | What it provides | Free tier |
|---|---|---|
| [VirusTotal](https://www.virustotal.com) | IP, hash, domain reputation | 4 requests/min |
| [AbuseIPDB](https://www.abuseipdb.com) | IP abuse reports | 1,000 requests/day |
| [MITRE ATT&CK](https://attack.mitre.org) | Threat intelligence framework | Free |

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
| bulk_ioc_enricher | T1071 | Application Layer Protocol | Command & Control |
| bulk_ioc_enricher | T1590 | Gather Victim Network Information | Reconnaissance |
| mini_soar.py | T1110 | Brute Force | Credential Access |

---

## Skills Demonstrated

| Skill | Where used |
|---|---|
| Python scripting | All tools |
| Regex | `alert_triage.py`, `log_analyser_ttp.py`, `log_monitor.py`, `mini_soar.py` |
| REST API integration | `ioc_checker.py`, `bulk_ioc_enricher`, `mini_soar.py` |
| JSON parsing | `ioc_checker.py`, `log_analyser_ttp.py`, `bulk_ioc_enricher`, `mini_soar.py` |
| File I/O and log parsing | `log_analyser_ttp.py`, `log_monitor.py`, `mini_soar.py` |
| Live log tailing and file rotation handling | `log_monitor.py`, `mini_soar.py` |
| CSV parsing and sorting | `csv_triage.py` |
| Error handling | All tools |
| Threat intel cross-referencing | `log_analyser_ttp.py`, `bulk_ioc_enricher`, `mini_soar.py` |
| Multi-source threat intel correlation | `bulk_ioc_enricher`, `mini_soar.py` |
| Modular Python architecture | `bulk_ioc_enricher`, `mini_soar` (6 modules) |
| MITRE ATT&CK TTP mapping | `log_analyser_ttp.py`, `bulk_ioc_enricher`, `mini_soar.py` |
| If/else triage logic | `alert_triage.py`, `csv_triage.py`, `severity.py` |
| Dictionary and set operations | `log_analyser_ttp.py` |
| Environment variable management | All tools with API keys |
| Security automation | `mini_soar.py` |
| Alert deduplication / rate limiting logic | `mini_soar.py` |
| Email automation (smtplib, HTML formatting) | `mini_soar.py` |
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
