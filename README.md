# 🔍 Analyseur intelligent de logs (IA + Observabilité)

Pipeline d'observabilité qui collecte des logs Linux, détecte automatiquement les
erreurs et activités suspectes, génère des explications en langage naturel via
l'API Claude, et déclenche des alertes Slack / e-mail.

## 🏗️ Architecture

```
Serveurs Linux → Promtail → Loki → Grafana (dashboard)
                                ↓
                          Analyseur IA (Python)
                                ↓
                       Alertes Slack / Email
```

- 📥 **Promtail** collecte les logs (`auth.log`, `syslog`, logs nginx)
- 🗄️ **Loki** stocke et indexe les logs
- 📊 **Grafana** affiche les dashboards temps réel
- 🤖 **Analyseur** (`analyzer/`) interroge Loki via LogQL, détecte les événements
  intéressants (erreurs 5xx, bruteforce SSH, ...), les fait expliquer par
  Claude, et alerte si la sévérité le justifie

## 🔒 Sécurité

- `.env` contient tous les secrets (clé API Anthropic, webhook Slack, identifiants SMTP) et est exclu du dépôt via `.gitignore` — ne jamais le committer
- Le pipeline CI (`.github/workflows/ci.yml`) exécute :
  - **gitleaks** : détecte toute clé/mot de passe accidentellement committé, y compris dans l'historique Git
  - **Trivy** : scanne l'image Docker de l'analyseur contre les vulnérabilités connues (CVE)
- **Dependabot** ouvre automatiquement une PR chaque semaine si une dépendance Python, une image Docker ou une action GitHub a une mise à jour de sécurité disponible
- Le mot de passe SMTP utilisé n'est pas le mot de passe du compte e-mail, mais un **mot de passe d'application** dédié (scopé, révocable indépendamment) généré via les paramètres de sécurité du fournisseur de messagerie
- En cas d'automatisation future (déploiement, push d'image), les secrets doivent être stockés dans **GitHub Secrets** (`Settings → Secrets and variables → Actions`), jamais en clair dans les workflows

## 🚀 Démarrage rapide

### Cloner le projet

```bash
git clone https://github.com/fanambinalova/log-analyzer-ia.git
cd log-analyzer-ia
```

### Configurer et lancer

```bash
cp .env.example .env
# Renseigner ANTHROPIC_API_KEY, SLACK_WEBHOOK_URL, etc.

docker compose up -d
```

- 📊 Grafana : http://localhost:3000 (admin/admin)
- 🗄️ Loki : http://localhost:3100

## 📁 Structure du projet

```
.
├── docker-compose.yml
├── loki/                    # Config Loki
├── promtail/                 # Config Promtail (sources de logs)
├── grafana/provisioning/     # Datasource + dashboards auto-provisionnés
├── analyzer/                  # Service Python (détection + IA + alerting)
│   ├── main.py
│   ├── detector.py
│   ├── ai_explainer.py
│   ├── alerting.py
│   └── config.py
└── .github/workflows/ci.yml  # Lint + scan gitleaks + build + scan Trivy
```

## ✅ Roadmap du projet

- [x] Squelette du repo et stack Docker Compose
- [x] Détection d'erreurs applicatives et HTTP 5xx
- [x] Détection de bruteforce SSH (extraction IP, seuils)
- [ ] Intégration API Claude pour les explications (en attente de crédits API)
- [x] Alerting Slack
- [x] Alerting e-mail
- [x] Dashboards Grafana (volumes, incidents expliqués)
- [ ] Documentation + captures d'écran

## 🛠️ Stack technique

Docker · Docker Compose · Grafana Loki · Promtail · Grafana · Python · API
Anthropic Claude · GitHub Actions · Trivy · Gitleaks · Dependabot
