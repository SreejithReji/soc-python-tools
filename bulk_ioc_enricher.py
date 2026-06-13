import enrichment
import ttp_mapper
import time

from enrichment import check_ip_vt, check_ip_ab
from ttp_mapper import lookup_ttp

ip_list = input("Enter IP addresses to check (comma-separated): ").split(",")
ip_list = [ip.strip() for ip in ip_list]

t1071 = lookup_ttp("T1071")
t1590 = lookup_ttp("T1590")
for ip in ip_list:

    vt_result = check_ip_vt(ip)
    reputation = vt_result["reputation"]
    country = vt_result["country"]
    tags = vt_result["tags"]
    malicious = vt_result["malicious"]
    suspicious = vt_result["suspicious"]
    harmless = vt_result["harmless"]
    ab_result = check_ip_ab(ip)
    confidence_score = ab_result["confidence_score"]
    total_reports = ab_result["total_reports"]
    whitelisted = ab_result["whitelisted"]
    usage_type = ab_result["usage_type"]
    country_code = ab_result["country_code"]

    print("=======VirusTotal Results=======")
    print(f"for the IP: {ip}")
    print(f"Reputation: {reputation}")
    print(f"Country: {country}")
    print(f"Tags: {','.join(tags)}")
    print(f"Malicious: {malicious}")
    print(f"Suspicious: {suspicious}")
    print(f"Harmless: {harmless}")
    print("=======Abuse IPDBResults=======")
    print (f"For the IP: {ip}")
    print (f"Abuse Confidence Score: {confidence_score}")
    print (f"Total Reports: {total_reports}")
    print (f"Whitelisted: {whitelisted}")
    print (f"Usage Type: {usage_type}")
    print (f"Country Code: {country_code}")



    if malicious > 0 and confidence_score > 50:
        print("=======MITRE ATT&CK=======")
        print(f"T1071  : {t1071['name']}")
        print(f"Tactic : {t1071['tactic']}")
        print(f"Ref    : {t1071['url']}")
        print(f"T1590  : {t1590['name']}")
        print(f"Tactic : {t1590['tactic']}")
        print(f"Ref    : {t1590['url']}")
        print("Verdict: 🔴 CONFIRMED MALICIOUS — flagged by both sources")
    elif malicious > 0 or confidence_score > 50:
        print("=======MITRE ATT&CK=======")
        print(f"T1071  : {t1071['name']}")
        print(f"Tactic : {t1071['tactic']}")
        print(f"Ref    : {t1071['url']}")
        print(f"T1590  : {t1590['name']}")
        print(f"Tactic : {t1590['tactic']}")
        print(f"Ref    : {t1590['url']}")
        print("Verdict: 🟡 SUSPICIOUS — flagged by one source")
    else:
        print("Verdict: 🟢 CLEAN")

    time.sleep(15)  # free API allows 4 requests/min — this keeps you under the limit