import os


SEVERITY_COLORS = {
    "Critical": ("#dc2626", "#dc2626"),
    "High": ("#f97316", "#f97316"),
    "Medium": ("#eab308", "#a16207"),
    "Low": ("#16a34a", "#16a34a"),
}



def build_html_ticket(alert_data):
    header_color, badge_text_color = SEVERITY_COLORS.get(alert_data["severity"], ("#374151", "#374151"))

    html = f"""
<div style="background:#f4f4f4;padding:24px 0;font-family:Arial,sans-serif;">
<div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e0e0e0;">

<div style="background:{header_color};padding:20px 24px;">
<table style="width:100%;border-collapse:collapse;"><tr>
<td style="font-size:18px;font-weight:bold;color:#ffffff;">SOC Incident Alert</td>
<td style="text-align:right;"><span style="background:#ffffff;color:{badge_text_color};font-size:12px;font-weight:bold;padding:4px 10px;border-radius:12px;">{alert_data['severity'].upper()}</span></td>
</tr></table>
</div>

<div style="padding:24px;">

<table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
<tr><td style="font-size:13px;color:#6b6b6b;padding:4px 0;">Ticket ID</td><td style="font-size:13px;color:#1a1a1a;text-align:right;font-weight:bold;">{alert_data['ticket_id']}</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:4px 0;">Timestamp</td><td style="font-size:13px;color:#1a1a1a;text-align:right;">{alert_data['timestamp']}</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:4px 0;">Source IP</td><td style="font-size:13px;color:#1a1a1a;text-align:right;font-family:monospace;">{alert_data['ip']}</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:4px 0;">Country</td><td style="font-size:13px;color:#1a1a1a;text-align:right;">{alert_data['country']}</td></tr>
</table>

<div style="background:#f8f8f6;border-radius:6px;padding:14px 16px;margin-bottom:12px;">
<div style="font-size:12px;font-weight:bold;color:#6b6b6b;letter-spacing:0.5px;margin-bottom:10px;">VIRUSTOTAL</div>
<table style="width:100%;border-collapse:collapse;">
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Malicious</td><td style="font-size:13px;text-align:right;color:#a32d2d;font-weight:bold;">{alert_data['vt_malicious']} engines</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Reputation</td><td style="font-size:13px;text-align:right;color:#1a1a1a;">{alert_data['reputation']}</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Tags</td><td style="font-size:13px;text-align:right;color:#1a1a1a;">{alert_data['tags']}</td></tr>
</table>
</div>

<div style="background:#f8f8f6;border-radius:6px;padding:14px 16px;margin-bottom:12px;">
<div style="font-size:12px;font-weight:bold;color:#6b6b6b;letter-spacing:0.5px;margin-bottom:10px;">ABUSEIPDB</div>
<table style="width:100%;border-collapse:collapse;">
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Confidence</td><td style="font-size:13px;text-align:right;color:#a32d2d;font-weight:bold;">{alert_data['confidence_score']}%</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Total reports</td><td style="font-size:13px;text-align:right;color:#1a1a1a;">{alert_data['total_reports']}</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Usage type</td><td style="font-size:13px;text-align:right;color:#1a1a1a;">{alert_data['usage_type']}</td></tr>
</table>
</div>

<div style="background:#fdf6ec;border-radius:6px;padding:14px 16px;margin-bottom:20px;">
<div style="font-size:12px;font-weight:bold;color:#85510b;letter-spacing:0.5px;margin-bottom:10px;">MITRE ATT&amp;CK</div>
<table style="width:100%;border-collapse:collapse;">
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Technique</td><td style="font-size:13px;text-align:right;color:#1a1a1a;">{alert_data['ttp_id']}</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Name</td><td style="font-size:13px;text-align:right;color:#1a1a1a;">{alert_data['ttp_name']}</td></tr>
<tr><td style="font-size:13px;color:#6b6b6b;padding:2px 0;">Tactic</td><td style="font-size:13px;text-align:right;color:#1a1a1a;">{alert_data['tactic']}</td></tr>
</table>
</div>

<div style="border-left:4px solid #a32d2d;background:#fcebeb;padding:12px 16px;border-radius:0 6px 6px 0;">
<div style="font-size:12px;font-weight:bold;color:#7f1d1d;margin-bottom:4px;">RECOMMENDATION</div>
<div style="font-size:13px;color:#501313;">{alert_data['recommendation']}</div>
</div>

</div>

<div style="background:#f8f8f6;padding:14px 24px;text-align:center;border-top:1px solid #e0e0e0;">
<span style="font-size:11px;color:#9b9b9b;">Generated automatically by mini_soar.py &mdash; built by Sreejith</span>
</div>

</div>
</div>
"""
    return html

def save_ticket(alert_data, html_content):
    os.makedirs("tickets", exist_ok=True)
    filename = f"tickets/ticket_{alert_data['ticket_id']}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)




