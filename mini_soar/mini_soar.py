from enrichment import check_ip_vt, check_ip_ab
from ttp_mapper import lookup_ttp
from alert_rules import check_alert
from severity import score_severity
from ticket_generator import build_html_ticket, save_ticket
from notifier import send_email

import time
import os
import ipaddress
from datetime import datetime, timedelta
import re

TICKET_PREFIX = {
    "Critical": "CRIT",
    "High": "HIGH",
    "Medium": "MED",
    "Low": "LOW"
}

last_alerted = {}
COOLDOWN_MINUTES = 5

def should_alert(ip):
    now = datetime.now()
    
    if ip in last_alerted:
        time_since_last = now - last_alerted[ip]
        if time_since_last < timedelta(minutes=COOLDOWN_MINUTES):
            return False
    
    last_alerted[ip] = now
    return True

def is_private_ip (ip):
    if ip is None:
        return True
    else:
        return ipaddress.ip_address(ip).is_private

def get_file_id(filepath):
    stat = os.stat(filepath)
    return stat.st_ino, stat.st_size

def process_alert(message, ip):
    if not should_alert(ip):
        return

    severity = score_severity(message)

    if is_private_ip(ip):
        vt_data = None
        ab_data = None
    else:
        vt_data = check_ip_vt(ip)
        ab_data = check_ip_ab(ip)

    ttp_id = "T1110"
    ttp = lookup_ttp(ttp_id)

    if vt_data:
        vt_malicious = vt_data.get("malicious", "N/A")
        reputation = vt_data.get("reputation", "N/A")
        tags = vt_data.get("tags", [])
        country = vt_data.get("country", "N/A")
    else:
        vt_malicious = "N/A"
        reputation = "N/A"
        tags = []
        country = "Private/Internal"

    if ab_data: 
        confidence_score = ab_data.get("confidence_score", "N/A")
        total_reports = ab_data.get("total_reports","N/A")
        usage_type = ab_data.get("usage_type","N/A")
        country_code = ab_data.get("country_code", "N/A")

    else:
        confidence_score = "N/A"
        total_reports = "N/A"
        usage_type = "N/A"
        country_code = "N/A"

    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prefix = TICKET_PREFIX.get(severity, "SOC")
    ticket_id = f"{prefix}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    recommendation = "Investigate source IP, review related logs, consider blocking if confirmed malicious."

    alert_data = {
        "ticket_id": ticket_id,
        "timestamp": timestamp,
        "ip": ip,
        "country": country,
        "vt_malicious": vt_malicious,
        "reputation": reputation,
        "tags": ", ".join(tags) if tags else "none",
        "confidence_score": confidence_score,
        "total_reports": total_reports,
        "usage_type": usage_type,
        "ttp_id": ttp_id,
        "ttp_name": ttp["name"],
        "tactic": ttp["tactic"],
        "ttp_url": ttp["url"],
        "severity": severity,
        "recommendation": recommendation,
    }

    html_ticket = build_html_ticket(alert_data)
    save_ticket(alert_data, html_ticket)

    send_email(
        subject=f"SOC Alert: {severity} — {ip} — {timestamp}",
        html_body=html_ticket,
        to_address="wazuhsiemalertreceiver@gmail.com",
    )

filepath = "live.log"

with open(filepath, "r") as file:
    for line in file:
            message,ip = check_alert(line)
            if message:
                process_alert(message,ip)

    file.seek(0, 2)
    last_inode, last_size = get_file_id(filepath)

    while True:
        line = file.readline()

        if not line:
            current_inode, current_size = get_file_id(filepath)

            if current_inode != last_inode or current_size < file.tell():
                print("Log rotation detected — reopening file")
                file.close()
                file = open(filepath, "r")
                last_inode, last_size = get_file_id(filepath)
                continue

            time.sleep(1)
            continue
        message,ip = check_alert(line)
        if message:
            process_alert(message,ip)       

