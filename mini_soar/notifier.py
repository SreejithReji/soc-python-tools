import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv


load_dotenv(r"D:\Python\mini_soar\.env")

def send_email(subject, html_body, to_address):
    sender_email = os.getenv("ALERT_EMAIL")
    sender_password = os.getenv("ALERT_EMAIL_PASSWORD")

    msg = MIMEText(html_body, "html")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_address

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)


