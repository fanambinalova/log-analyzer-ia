"""Genere une explication humaine et une severite pour chaque evenement detecte,
en s'appuyant sur l'API Claude.
"""

import json
from anthropic import Anthropic
from config import Config

client = Anthropic(api_key=Config.ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """Tu es un assistant SRE/DevOps expert en analyse de logs Linux.
Pour chaque evenement fourni, reponds UNIQUEMENT en JSON valide avec ce schema :
{
  "summary": "resume en une phrase de ce qui se passe",
  "severity": "low|medium|high|critical",
  "probable_cause": "cause probable",
  "recommended_action": "action recommandee"
}
Pas de texte hors du JSON."""


def explain_event(event: dict) -> dict:
    """Envoie un evenement detecte a Claude et retourne une explication structuree."""
    message = client.messages.create(
        model=Config.AI_MODEL,
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": json.dumps(event, ensure_ascii=False)}
        ],
    )

    raw_text = message.content[0].text

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        # Filet de securite si le modele devie du format attendu
        return {
            "summary": raw_text[:200],
            "severity": "unknown",
            "probable_cause": "non determinee",
            "recommended_action": "verifier manuellement",
        }
