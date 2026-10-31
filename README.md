# SIEM Home Lab

> Stack ELK de détection de menaces, montée chez moi pour comprendre toute la chaîne Blue Team :
> collecte → parsing → détection → alerte.

![ELK](https://img.shields.io/badge/ELK-8.12.0-blue?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=flat-square&logo=docker)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

📄 **Write-up complet du scénario de test : [docs/WRITEUP.md](docs/WRITEUP.md)**

---

## Architecture

```
 auth.log / syslog
        │  scripts/ingest_logs.py  (JSON sur TCP :5000)
        ▼
   Logstash        ← parsing grok + classification (ssh_failed, root_login, su_failed…)
        │
        ▼
 Elasticsearch     ← index siem-logs-*        ◄──┐
        │                                        │ requêtes
        ▼                                        │
     Kibana        ← exploration (Discover)   scripts/detect.py  ← règles rules/*.yml
                                                 │
                                                 ├─► index siem-alerts (visible dans Kibana)
                                                 └─► webhook Slack / Discord / Teams
```

| Service | Port | Rôle |
|---|---|---|
| Elasticsearch | 9200 | Stockage et recherche |
| Logstash | 5000 (TCP/UDP) | Ingestion et parsing |
| Kibana | 5601 | Visualisation |
| setup | — | Conteneur one-shot qui configure le compte `kibana_system` |

---

## Démarrage rapide

Prérequis : Docker Desktop (4 Go de RAM alloués), Python 3.10+.

```bash
git clone https://github.com/bonberoww/siem-home-lab.git
cd siem-home-lab

cp .env.example .env          # puis remplacer les mots de passe
docker compose up -d          # ~2 min au premier lancement

python -m venv .venv && .venv/bin/pip install -r requirements.txt   # Windows : .venv\Scripts\pip
```

Démo de bout en bout :

```bash
python scripts/simulate_attack.py --send   # génère un auth.log d'attaque et l'envoie à Logstash
python scripts/detect.py                   # exécute les règles sur les 15 dernières minutes
python scripts/setup_kibana.py             # crée les vues "SIEM — Événements" et "SIEM — Alertes"
```

Kibana : **http://localhost:5601** (utilisateur `elastic`, mot de passe de `.env`).

Résultat attendu de `detect.py` :

```
[HIGH    ] SSH-001 — Brute force SSH : 12 échecs en 60s depuis 203.0.113.45 (utilisateur ciblé : root)
[CRITICAL] AUTH-002 — Connexion suspecte (root_login) : root depuis 203.0.113.45
[MEDIUM  ] AUTH-002 — Connexion suspecte (new_ip_login) : alessandro depuis 192.168.56.10
[MEDIUM  ] AUTH-002 — Connexion suspecte (new_ip_login) : root depuis 203.0.113.45
```

(La 3ᵉ alerte est un faux positif attendu au premier lancement : voir [Limites connues](#limites-connues).)

---

## Utilisation

| Commande | Effet |
|---|---|
| `python scripts/ingest_logs.py /var/log/auth.log` | Envoie un vrai fichier de log |
| `python scripts/detect.py --lookback 1h` | Analyse la dernière heure |
| `python scripts/detect.py --watch 30` | Surveillance continue (toutes les 30 s) |
| `python scripts/alert_webhook.py` | Envoie une alerte de test sur les webhooks configurés |

---

## Règles de détection

| ID | Nom | Type | Déclencheur | MITRE ATT&CK |
|---|---|---|---|---|
| SSH-001 | SSH Brute Force | seuil | > 5 échecs SSH en 60 s (fenêtre glissante) depuis la même IP | T1110.001 |
| AUTH-002 | Suspicious Login | correspondance | Connexion root réussie · connexion entre 22h et 6h · IP jamais vue | T1078.003 |

Les règles sont décrites en YAML dans `rules/` et exécutées par `scripts/detect.py`. Pour en ajouter une, il suffit de créer un fichier avec un bloc `detection` de type `threshold` ou `match`.

---

## Structure

```
siem-home-lab/
├── docker-compose.yml
├── .env.example              # modèle de configuration (le .env n'est jamais commité)
├── elk/
│   ├── elasticsearch.yml
│   ├── logstash.conf         # pipeline : grok + classification + geoip
│   └── kibana.yml
├── rules/
│   ├── ssh_bruteforce.yml
│   └── suspicious_login.yml
├── scripts/
│   ├── ingest_logs.py        # fichier log → Logstash
│   ├── simulate_attack.py    # génère un scénario d'attaque réaliste
│   ├── detect.py             # moteur de détection
│   ├── alert_webhook.py      # Slack / Discord / Teams
│   └── setup_kibana.py       # vues de données Kibana
├── samples/                  # logs d'exemple (IP de documentation RFC 5737)
└── docs/WRITEUP.md
```

---

## Limites connues

- `@timestamp` correspond à l'heure d'ingestion, pas à l'heure écrite dans la ligne de log (gardée dans `log_timestamp`). C'est voulu pour la détection en temps réel, mais rejouer un vieux log le date à aujourd'hui.
- La condition `new_ip_login` lève une alerte pour chaque IP au premier lancement, tant qu'il n'y a pas d'historique.
- Juste après `docker compose up`, Logstash met environ 1 minute à ouvrir le port 5000 : attendre `Pipelines running` dans `docker logs logstash` avant d'ingérer.
- Lab mono-nœud, sans TLS. Les ports sont liés à `127.0.0.1` : le lab n'est pas joignable depuis le réseau.

---

## Avertissement légal

Projet éducatif. Les IP d'attaque des exemples appartiennent aux plages réservées à la documentation.

---

## Auteur

Alessandro Peys — [@bonberoww](https://github.com/bonberoww) · Master Cybersécurité, Sup de Vinci
