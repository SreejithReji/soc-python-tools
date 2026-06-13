import requests
import time
from dotenv import load_dotenv
import os

load_dotenv(r"D:\Python\IOC Checker\.env")
API_KEY = os.getenv("VT_API_KEY")
print(f"Key loaded: {API_KEY}")
# ────────────────────────────────────────────────────────────

# List of IPs you want to check (edit these)
ip_list = input("Enter IP addresses to check (comma-separated): ").split(",")
ip_list = [ip.strip() for ip in ip_list]

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attr = data["data"]["attributes"]
        stats = data["data"]["attributes"]["last_analysis_stats"]
        reputation = attr.get("reputation","unknown")
        country = attr.get("country","unknown")
        tags = attr.get("tags", [])
        malicious = stats.get("malicious","unknown")
        suspicious = stats.get("suspicious","unknown")
        harmless  = stats.get("harmless","unknown")
        print(f"\n[+] IP: {ip}")
        print(f"    Reputation: {reputation}")
        print(f"    Country: {country}")
        print(f"    Tags: {','.join(tags)}")
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