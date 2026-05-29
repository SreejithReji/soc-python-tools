import requests
import time
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
# ────────────────────────────────────────────────────────────

# List of IPs you want to check (edit these)
ip_list = [
    "8.8.8.8",
    "1.1.1.1",
    "185.220.101.1"
]

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]
        harmless  = stats["harmless"]
        print(f"\n[+] IP: {ip}")
        print(f"    Malicious  : {malicious}")
        print(f"    Suspicious : {suspicious}")
        print(f"    Harmless   : {harmless}")
        if malicious > 0:
            print(f"    ⚠️  FLAGGED AS MALICIOUS")
        else:
            print(f"    ✅ Clean")
    else:
        print(f"\n[-] Failed to query {ip} — status code {response.status_code}")

# Run the checker
print("=== SOC IOC Checker — VirusTotal ===")
for ip in ip_list:
    check_ip(ip)
    time.sleep(15)  # free API allows 4 requests/min — this keeps you under the limit

print("\n=== Scan complete ===")