"""Configuration centralisee de l'analyseur, lue depuis les variables d'environnement."""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")

    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    AI_MODEL = os.getenv("AI_MODEL", "claude-sonnet-5")

    SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "60"))
    SSH_FAILED_THRESHOLD = int(os.getenv("SSH_FAILED_THRESHOLD", "5"))
    # Doit rester nettement > SCAN_INTERVAL pour ne jamais rater un evenement
    # ingere juste avant un cycle de detection.
    DETECTION_WINDOW_MINUTES = int(os.getenv("DETECTION_WINDOW_MINUTES", "15"))

    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")
