# SIEM Home Lab

Un petit SIEM monté chez moi avec la stack ELK (Elasticsearch, Logstash, Kibana) sous Docker. Il reçoit des logs d'authentification Linux, les analyse et lève des alertes quand il repère un brute force SSH ou une connexion root suspecte.

Le compte rendu d'un test complet est dans [docs/WRITEUP.md](docs/WRITEUP.md).

## Comment ça marche

```
auth.log  ->  Logstash (parsing)  ->  Elasticsearch  ->  Kibana
                                            |
                                  scripts/detect.py  ->  alertes
```

- **Logstash** découpe chaque ligne de log en champs (`src_ip`, `username`…) avec grok.
- **Elasticsearch** stocke les événements.
- **detect.py** lit les règles du dossier `rules/` et cherche les attaques dans Elasticsearch.
- **Kibana** sert à explorer les événements et les alertes.

## Lancer le lab

Il faut Docker (4 Go de RAM) et Python 3.10 ou plus.

```bash
cp .env.example .env        # puis changer les mots de passe
docker compose up -d
python -m venv .venv && .venv/bin/pip install -r requirements.txt   # Windows : .venv\Scripts\pip
```

Attendre environ une minute que Logstash démarre (`docker logs logstash` doit afficher `Pipelines running`), puis :

```bash
python scripts/simulate_attack.py --send   # envoie un scénario d'attaque
python scripts/detect.py                   # lance les règles
python scripts/setup_kibana.py             # crée les vues dans Kibana
```

Kibana est sur http://localhost:5601 (utilisateur `elastic`, mot de passe du `.env`).

Résultat attendu :

```
[HIGH    ] SSH-001 - Brute force SSH : 12 échecs en 60s depuis 203.0.113.45
[CRITICAL] AUTH-002 - Connexion suspecte (root_login) : root depuis 203.0.113.45
```

## Les règles

| Règle | Détecte | Technique MITRE |
|---|---|---|
| SSH-001 | Plus de 5 échecs SSH en 60 s depuis la même IP | T1110.001 |
| AUTH-002 | Connexion root, connexion entre 22h et 6h, IP jamais vue | T1078.003 |

Elles sont écrites en YAML dans `rules/`.

## Limites

- Au premier lancement, la règle « IP jamais vue » alerte sur toutes les IP (pas encore d'historique).
- L'heure de l'événement est l'heure d'ingestion. L'heure d'origine de la ligne est gardée dans `log_timestamp`.
- Lab mono-nœud, sans TLS, accessible seulement depuis la machine locale.

## Auteur

Alessandro Peys, Master Cybersécurité (Sup de Vinci). Projet personnel, licence MIT.
