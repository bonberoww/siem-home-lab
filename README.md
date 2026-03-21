# siem-home-lab
Stack ELK pour la détection de menaces — lab perso Blue Team
# SIEM Home Lab

> Stack ELK complète pour la détection de menaces — lab perso Blue Team.  
> Elasticsearch + Logstash + Kibana déployés via Docker en une commande.

![ELK](https://img.shields.io/badge/ELK-8.12.0-blue?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-required-blue?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-En%20développement-orange?style=flat-square)

---

## Architecture
```
Logs (Linux/Windows)
       │
       ▼
   Logstash :5000        ← ingestion & parsing
       │
       ▼
 Elasticsearch :9200     ← stockage & indexation
       │
       ▼
   Kibana :5601          ← visualisation & alertes
```

---

## Prérequis

- Docker Desktop installé
- 4 Go de RAM minimum alloués à Docker
- Python 3.8+ pour les scripts d'ingestion

---

## Installation
```bash
git clone https://github.com/bonberoww/siem-home-lab.git
cd siem-home-lab

# Copier et configurer les variables d'environnement
cp .env.example .env

# Lancer la stack ELK
docker-compose up -d

# Vérifier que les conteneurs tournent
docker-compose ps
```

Accède à Kibana : **http://localhost:5601**  
Login : `elastic` / mot de passe défini dans `.env`

---

## Structure
```
siem-home-lab/
│
├── docker-compose.yml
├── .env                      # Variables d'environnement (non commité)
├── .gitignore
│
├── elk/
│   ├── elasticsearch.yml     # Config Elasticsearch
│   ├── logstash.conf         # Pipeline d'ingestion
│   └── kibana.yml            # Config Kibana
│
├── rules/
│   ├── ssh_bruteforce.yml    # Détection brute force SSH
│   └── suspicious_login.yml  # Détection connexions suspectes
│
└── scripts/
    ├── ingest_logs.py        # Envoi de logs vers Logstash
    └── alert_webhook.py      # Alertes Slack / Discord / Teams
```

---

## Utilisation

Ingérer un fichier log :
```bash
python scripts/ingest_logs.py /var/log/auth.log
```

Tester les alertes webhook :
```bash
python scripts/alert_webhook.py
```

---

## Règles de détection

| ID | Nom | Sévérité | Déclencheur |
|---|---|---|---|
| SSH-001 | SSH Brute Force | HIGH | 5 échecs SSH en 60s depuis la même IP |
| AUTH-002 | Suspicious Login | CRITICAL | Connexion root / hors heures / IP inconnue |

---

## Avertissement légal

Ce projet est développé à des fins éducatives et de recherche.  
Usage sur des systèmes sans autorisation explicite est illégal.

---

## Auteur

Alessandro Peys — [@bonberoww](https://github.com/bonberoww)  
Etudiant Master Cybersécurité — Sup de Vinci 