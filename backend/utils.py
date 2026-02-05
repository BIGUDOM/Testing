from functools import wraps
from flask import session, redirect
import traceback
import mysql.connector
from flask import (
     jsonify
)
from typing import Optional
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import smtplib
import json
import requests
import base64
from dotenv import load_dotenv

load_dotenv()



CONFIG_FILE = "config.json"

conn = mysql.connector.connect(
        host = os.getenv("DB_HOST"),
        user =  os.getenv("DB_USER"),
        password =  os.getenv("DB_PASSWORD"),
        database =  os.getenv("DB_NAME"), 
        port =  os.getenv("DB_PORT"),
)
cursor = conn.cursor()

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped_view




# CONFIG_FILE = "config.json"

# def load_config() -> dict:
#     if not os.path.exists(CONFIG_FILE):
#         template = {
#             "smtp_server": "smtp.gmail.com",
#             "smtp_port": 587,
#             "sender_email": "codis1723@gmail.com",
#             "sender_password": "hkdzlilwcqbbvmjo",
#             "admin_code": "admin123"
#         }
#         try:
#             with open(CONFIG_FILE, "w", encoding="utf-8") as f:
#                 json.dump(template, f, indent=4)
#             print(f"⚠️ config.json created. Please edit it to add SMTP creds and set a secure admin_code.")
#         except Exception as e:
#             print(f"Could not create config file: {e}")

#     try:
#         with open(CONFIG_FILE, "r", encoding="utf-8") as f:
#             cfg = json.load(f)
#     except Exception:
#         cfg = {}

#     fixed_cfg = {
#         "smtp_server": cfg.get("smtp_server", "smtp.gmail.com"),
#         "smtp_port": cfg.get("smtp_port", 587),
#         "sender_email": cfg.get("sender_email", "codis1723@gmail.com"),
#         "sender_password": cfg.get("sender_password", "hkdzlilwcqbbvmjo"),
#         "admin_code": cfg.get("admin_code", "admin123")
#     }

#     return fixed_cfg

# # ======== EMAIL ========
# def send_email(recipient: str, subject: str, body: str, html: bool=False, attachments: Optional[list]=None) -> bool:
#     try:
#         cfg = load_config()
#         if not cfg["sender_email"] or not cfg["sender_password"]:
#             print(f"Email not configured. Skipping sending to {recipient}.")
#             return False

#         msg = MIMEMultipart()
#         msg["From"] = cfg["sender_email"]
#         msg["To"] = recipient
#         msg["Subject"] = subject

#         if html:
#             msg.attach(MIMEText(body, "html"))
#         else:
#             msg.attach(MIMEText(body, "plain"))

#         # Attach files if any
#         if attachments:
#             for path in attachments:
#                 try:
#                     if os.path.exists(path):
#                         with open(path, "rb") as f:
#                             part = MIMEApplication(f.read(), Name=os.path.basename(path))
#                             part["Content-Disposition"] = f'attachment; filename="{os.path.basename(path)}"'
#                             msg.attach(part)
#                     else:
#                         print(f"Attachment not found, skipping: {path}")
#                 except Exception as e:
#                     print(f"Failed to attach {path}: {e}")

#         # Send email using configured SMTP server
#         with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
#             server.starttls()
#             server.login(cfg["sender_email"], cfg["sender_password"])
#             server.send_message(msg)

   
#         return True

#     except Exception as e:
#         print(f"⚠️ Email failed: {e}")
#         traceback.print_exc()
#         return False


def send_email(
    recipient: str,
    subject: str,
    body: str,
    html: bool = False,
    attachments: Optional[list] = None
) -> bool:
    try:
        api_key = os.getenv("RESEND_API_KEY")
        sender = os.getenv("SENDER_EMAIL")

        if not api_key or not sender:
            print("⚠️ Email not configured")
            return False

        files = []
        if attachments:
            for path in attachments:
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        files.append({
                            "filename": os.path.basename(path),
                            "content": base64.b64encode(f.read()).decode()
                        })
                else:
                    print(f"Attachment not found: {path}")

        payload = {
            "from": sender,
            "to": [recipient],
            "subject": subject,
            "html": body if html else None,
            "text": body if not html else None,
            "attachments": files if files else None
        }

        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=10,
        )

        if response.status_code >= 400:
            print("⚠️ Email error:", response.text)
            return False

        return True

    except Exception as e:
        print("⚠️ Email failed:", e)
        traceback.print_exc()
        return False


import threading

def send_email_async(recipient: str, subject: str, body: str, html: bool=False, attachments: Optional[list]=None):
    """Send email in a separate thread to avoid blocking requests."""
    def _send():
        try:
            success = send_email(recipient, subject, body, html, attachments)
            if not success:
                print(f"Failed to send email to {recipient}")
        except Exception as e:
            print(f"EMAIL THREAD ERROR: {e}")

    thread = threading.Thread(target=_send, daemon=True)
    thread.start()

    
def get_user_id(username):
    cursor.execute("SELECT user_id, username FROM user_base WHERE username=%s", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({
            "status": "error",
            "message": "User not found"
        }), 400
    
    
    user_id = user[0]

    return user_id