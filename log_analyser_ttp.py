import json
import os

try:

    firewall_log = input("Enter the name of the firewall log file: ")
    threat_intel = input("Enter the name of the threat intelligence file: ")
except:
    print("Error: Invalid input. Please enter valid file names.")
    exit(1)

# Check if the files exist and extract destination IPs from the firewall log    
try:
    with open(firewall_log, 'r') as f:
        deny_lines = []
        dst_ips = []
        src_ips = []
        for line in f:
            line = line.strip()
            if "DENY" in line:
                deny_lines.append(line)
                src_ip = line.split()[4]        # source IP
                src_ips.append(src_ip)
                dst_ip = line.split("->")[1].strip().split(":")[0]
                dst_ips.append(dst_ip)
                
    print(f"Number of DENY entries: {len(deny_lines)}")
    print(f"DENY entries: {deny_lines}")
    print(f"Number of Destination IPs: {len(dst_ips)}")
    print(f"Destination IPs: {dst_ips}")
except FileNotFoundError:
    print(f"Error: File '{firewall_log}' not found.")
    exit(1)
except Exception as e:
    print(f"Error reading firewall log: {e}")
    exit(1)

# Make a dictionary of the threat intelligence data with IPs as keys and TTPs as values

try:
    with open(threat_intel, 'r') as f:
        data = json.load(f)
        threat_dict = {}
        for item in data:
            if item.get("risk_score") >= 75:
                ip = item.get("ip")
                if ip:
                    threat_dict[ip] = item
    print(f"Threat intel loaded: {len(threat_dict)} IPs")
except FileNotFoundError:
    print(f"Error: File '{threat_intel}' not found.")
    exit(1)

# Compare the destination IPs from the firewall log with the IPs in the threat intelligence data

if threat_dict:
    matching_ips = set(dst_ips) & set(threat_dict)
    print(f"Number of Matching IPs: {len(matching_ips)}")
    print(f"Matching IPs: {matching_ips}") 
else:
    print("No IPs found in threat intelligence data.")

# finding top offenders by counting the frequency of destination IPs in the firewall log

from collections import Counter
ip_counts = Counter(src_ips)
top_ip, top_count = ip_counts.most_common(1)[0]
for ip in threat_dict:
    count = dst_ips.count(ip)
    if count > 0:
        print(f"IP: {ip}, Count: {count}")

print(f"Top Offender: {top_ip} with {top_count} occurrences")

with open("detection_report.txt", "w", encoding="utf-8") as f:
    f.write("=" * 48 + "\n")
    f.write("         FIREWALL DETECTION REPORT\n")
    f.write("=" * 48 + "\n")
    f.write("MITRE Technique  : T1110 - Brute Force\n")
    f.write("Tactic           : Lateral Movement / C2\n")
    f.write("Reference        : https://attack.mitre.org/techniques/T1110/\n")
    f.write("-" * 48 + "\n")
    f.write(f"Total DENY events     : {len(deny_lines)}\n")
    f.write("-" * 48 + "\n")
    f.write("TOP OFFENDER\n")
    f.write(f"Source IP    : {top_ip}\n")
    f.write(f"Block count  : {top_count}\n")
    f.write("-" * 48 + "\n")
    f.write("THREAT INTEL MATCHES\n")
    for line in deny_lines:
        dst_ip = line.split("->")[1].strip().split(":")[0]
        if dst_ip in threat_dict:
            intel = threat_dict[dst_ip]
            tags = ", ".join(intel.get("tags", []))
            f.write(f"{line}\n")
            f.write(f"  ↳ Risk Score: {intel['risk_score']} | Country: {intel['country']} | Tags: {tags}\n")
    f.write("-" * 48 + "\n")
    f.write("ASSESSMENT\n")
    f.write(f"Confirmed T1110 Brute Force activity detected.\n")
    f.write(f"Host {top_ip} generated {top_count} blocked attempts.\n")
    f.write(f"{len(matching_ips)} connections matched known malicious IPs.\n")
    f.write("Recommend isolating host and reviewing endpoint logs.\n")
    f.write("=" * 48 + "\n")

print("Detection report written to detection_report.txt")