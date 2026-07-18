"""Interroge Loki via LogQL et detecte les evenements interessants.

Deux familles de detection pour demarrer :
- erreurs applicatives / HTTP 5xx
- activite suspecte (ex: bruteforce SSH via echecs d'authentification repetes)

A enrichir au fil du projet (regles supplementaires, seuils dynamiques, etc.)
"""

import re
import time
import requests
from collections import defaultdict
from config import Config

# Couvre les deux formats les plus courants dans /var/log/auth.log :
#   "Failed password for root from 203.0.113.42 port 22 ssh2"
#   "Failed password for invalid user admin from 203.0.113.42 port 51515 ssh2"
SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def query_loki(logql_query: str, minutes: int = 5) -> list[dict]:
    """Execute une requete LogQL sur la plage des `minutes` dernieres minutes."""
    end = time.time_ns()
    start = end - minutes * 60 * 1_000_000_000

    params = {
        "query": logql_query,
        "start": start,
        "end": end,
        "limit": 1000,
    }
    resp = requests.get(f"{Config.LOKI_URL}/loki/api/v1/query_range", params=params, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    entries = []
    for stream in data.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        for ts, line in stream.get("values", []):
            entries.append({"timestamp": ts, "line": line, "labels": labels})
    return entries


def detect_errors() -> list[dict]:
    """Erreurs applicatives et HTTP 5xx."""
    query = '{job=~"nginx|syslog"} |~ "(?i)error|5[0-9]{2}"'
    return query_loki(query, minutes=Config.DETECTION_WINDOW_MINUTES)


def detect_ssh_bruteforce() -> list[dict]:
    """Regroupe les echecs SSH par IP source et signale les depassements de seuil.

    Pour chaque IP on garde :
    - le nombre de tentatives
    - les usernames essayes (utile pour l'explication IA : un seul compte cible
      vs balayage de plusieurs comptes ne raconte pas la meme histoire)
    - le timestamp de la premiere et de la derniere tentative (fenetre d'attaque)
    """
    query = '{job="auth"} |~ "Failed password"'
    entries = query_loki(query, minutes=Config.DETECTION_WINDOW_MINUTES)

    # ip -> {"attempts": int, "users": set, "first_seen": ts, "last_seen": ts}
    stats: dict[str, dict] = defaultdict(
        lambda: {"attempts": 0, "users": set(), "first_seen": None, "last_seen": None}
    )

    for entry in entries:
        match = SSH_FAILED_RE.search(entry["line"])
        if not match:
            continue

        ip = match.group("ip")
        user = match.group("user")
        ts = entry["timestamp"]

        record = stats[ip]
        record["attempts"] += 1
        record["users"].add(user)
        if record["first_seen"] is None or ts < record["first_seen"]:
            record["first_seen"] = ts
        if record["last_seen"] is None or ts > record["last_seen"]:
            record["last_seen"] = ts

    suspects = [
        {
            "type": "ssh_bruteforce",
            "ip": ip,
            "attempts": record["attempts"],
            "targeted_users": sorted(record["users"]),
            "first_seen": record["first_seen"],
            "last_seen": record["last_seen"],
        }
        for ip, record in stats.items()
        if record["attempts"] >= Config.SSH_FAILED_THRESHOLD
    ]
    return suspects


def run_detection_cycle() -> dict:
    """Un cycle complet de detection, appele periodiquement par main.py."""
    return {
        "errors": detect_errors(),
        "ssh_bruteforce": detect_ssh_bruteforce(),
    }
