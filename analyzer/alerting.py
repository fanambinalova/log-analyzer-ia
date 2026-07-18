"""Envoie des alertes vers Slack (webhook) et par e-mail (SMTP)."""

import smtplib
import requests
from email.mime.text import MIMEText
from config import Config

SEVERITIES_TO_ALERT = {"high", "critical"}


def send_slack_alert(explanation: dict) -> None:
    if not Config.SLACK_WEBHOOK_URL:
        return

    text = (
        f"*[{explanation['severity'].upper()}]* {explanation['summary']}\n"
        f"Cause probable : {explanation['probable_cause']}\n"
        f"Action recommandee : {explanation['recommended_action']}"
    )
    requests.post(Config.SLACK_WEBHOOK_URL, json={"text": text}, timeout=10)


def send_email_alert(explanation: dict) -> None:
    if not (Config.SMTP_HOST and Config.ALERT_EMAIL_TO):
        return

    body = (
        f"Severite : {explanation['severity']}\n"
        f"Resume : {explanation['summary']}\n"
        f"Cause probable : {explanation['probable_cause']}\n"
        f"Action recommandee : {explanation['recommended_action']}"
    )
    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = f"[Log Analyzer] Alerte {explanation['severity'].upper()}"
    msg["From"] = Config.SMTP_USER
    msg["To"] = Config.ALERT_EMAIL_TO

    with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as server:
        server.starttls()
        server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
        server.send_message(msg)


def dispatch_alert(explanation: dict) -> None:
    """Envoie l'alerte uniquement si la severite le justifie."""
    if explanation.get("severity") in SEVERITIES_TO_ALERT:
        send_slack_alert(explanation)
        send_email_alert(explanation)
