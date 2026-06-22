import re

def check_alert(line):
    line = line.strip()
    ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
    ip = ip_match.group() if ip_match else None

    if "Failed password" in line:
        return "🔴 Possible brute force attempt", ip
    elif "Invalid user" in line:
        return "🟠 Unknown user login attempt", ip
    elif "authentication failure" in line:
        return "🟡 Authentication issue", ip
    else:
        return None, None