# ================================================
#   SOC Alert Triage Tool — by Sreejith Reji
#   Parses a raw log line and assigns priority
#
#   Test with:
#   2024-01-15 08:22:47 BLOCK TCP src=185.220.101.45
#   dst=10.0.0.15 port=4444 user=administrator failed=47
# ================================================

import re

# Known bad IPs — update this watchlist as needed
watchlist = [
    "185.220.101.47",
    "45.33.32.156",
    "10.0.0.22"
]

# ── Get log line from analyst ────────────────────
log = input("Paste log entry: ").strip()

# ── Extract fields using regex ───────────────────
def extract_field(pattern, text, field_name, cast=str):
    match = re.search(pattern, text)
    if not match:
        print(f"Error: Could not extract {field_name} from log entry")
        exit()
    return cast(match.group(1))

src_ip          = extract_field(r"src=(\S+)",     log, "source IP")
dst_ip          = extract_field(r"dst=(\S+)",     log, "destination IP")
username        = extract_field(r"user=(\w+)",    log, "username")
failed_attempts = extract_field(r"failed=(\d+)",  log, "failed attempts", int)
dst_port        = extract_field(r"port=(\d+)",    log, "destination port", int)

# ── Check against watchlist ──────────────────────
def check_ip(ip):
    return ip in watchlist

is_known_bad = check_ip(src_ip)

# ── Assign triage priority ───────────────────────
def triage(is_known_bad, username, failed_attempts, dst_port):
    if is_known_bad and username == "administrator":
        return "CRITICAL"
    elif is_known_bad:
        return "HIGH"
    elif failed_attempts > 5 and username == "administrator":
        return "HIGH"
    elif failed_attempts > 5:
        return "MEDIUM"
    elif dst_port in [4444, 1337, 9001, 31337]:
        return "MEDIUM"
    else:
        return "LOW"

priority = triage(is_known_bad, username, failed_attempts, dst_port)

# ── Severity emoji ───────────────────────────────
icons = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢"
}

# ── Print report ─────────────────────────────────
print(f"""
{'='*40}
  SOC ALERT TRIAGE SUMMARY
{'='*40}
  Source IP       : {src_ip}
  Destination IP  : {dst_ip}
  Username        : {username}
  Failed attempts : {failed_attempts}
  Destination port: {dst_port}
  Known bad IP    : {is_known_bad}
{'='*40}
  Priority        : {icons[priority]} {priority}
{'='*40}
""")

input("\nPress Enter to exit...")