"""Test manuel de l'alerting (Slack + e-mail) sans passer par l'API Claude.

Usage:
    docker compose exec analyzer python test_alerting.py
"""

from alerting import dispatch_alert

fake_explanation = {
    "summary": "Ceci est un test manuel du systeme d'alerting",
    "severity": "critical",
    "probable_cause": "Test volontaire depuis test_alerting.py",
    "recommended_action": "Aucune action requise, c'est un test",
}

print("Envoi d'une alerte de test (severite: critical)...")
dispatch_alert(fake_explanation)
print("Termine. Verifie ton canal Slack et/ou ta boite mail.")
