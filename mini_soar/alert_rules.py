import json

def level_to_icon(level):
    if level >= 12:
        return "🔴"
    elif level >= 8:
        return "🟠"
    elif level >= 5:
        return "🟡"
    else:
        return "🟢"

def check_alert(line):
    try:
        alert = json.loads(line)
    except json.JSONDecodeError:
        return None, None, None

    level = alert["rule"]["level"]

    if level < 5:
        return None, None, None
    
    description = alert["rule"]["description"]
    icon = level_to_icon(level)
    message = f"{icon} {description}"

    ip = alert.get("data", {}).get("srcip")
    mitre_id = alert.get("rule", {}).get("mitre", {}).get("id", [None])[0]
    return message, ip, mitre_id

