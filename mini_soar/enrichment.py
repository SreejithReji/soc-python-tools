import os
import requests
from dotenv import load_dotenv

load_dotenv(r"D:\Python\mini_soar\.env")
api_key_vt = os.getenv("VT_API_KEY")
api_key_ab = os.getenv("ABUSEIPDB_KEY")

def check_ip_vt(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key_vt}
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
        return {
        "reputation": reputation,
        "country": country,
        "tags": tags,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless
        }
    elif response.status_code == 401:
        print("Authentication Failed: Check your API key.")
    elif response.status_code == 429:
        print("Rate Limit Exceeded")
    else:
        print("Unexpected Error:", response.status_code)



def check_ip_ab(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
    "Key": api_key_ab,
    "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        confidence_score = data["data"].get("abuseConfidenceScore", "Unknown")
        total_reports = data["data"].get("totalReports", "Unknown")
        whitelisted = data["data"].get("isWhitelisted", "Unknown")
        usage_type = data["data"].get("usageType", "Unknown")
        country_code = data["data"].get("countryCode", "Unknown")   
        return {
        "confidence_score": confidence_score,
        "total_reports": total_reports,
        "whitelisted": whitelisted,
        "usage_type": usage_type,
        "country_code": country_code
        }

    elif response.status_code == 401:
        print("Authentication Failed: Check your API key.")
    elif response.status_code == 429:
        print("Rate Limit Exceeded")
    else:
        print("Unexpected Error:", response.status_code)




