# Write-up — Détecter un brute force SSH suivi d'une compromission root

**Projet :** SIEM Home Lab · **Domaine :** Blue Team / détection · **Date du test :** 31/10/2026
**Stack :** Elasticsearch, Logstash, Kibana 8.12 (Docker Compose), Python

---

## 1. Objectif

Vérifier que le lab détecte de bout en bout un scénario d'attaque classique sur un serveur Linux :
reconnaissance, brute force SSH, connexion root réussie, puis tentative d'élévation de privilèges.

La question à laquelle je voulais répondre : **si ça arrivait sur un vrai serveur, est-ce que mon SIEM me préviendrait, et avec quel niveau de détail ?**

## 2. Environnement

| Élément | Valeur |
|---|---|
| Serveur simulé | `srv-lab01` |
| Poste admin légitime | `192.168.56.10` |
| IP de reconnaissance | `198.51.100.23` (plage de documentation RFC 5737) |
| IP d'attaque | `203.0.113.45` (plage de documentation RFC 5737) |
| Générateur | `scripts/simulate_attack.py` |
| Moteur de détection | `scripts/detect.py` + règles `rules/*.yml` |

Les logs sont générés au format `auth.log` Debian/Ubuntu, avec des IP réservées à la documentation : aucun système réel n'est visé.

## 3. Scénario

| # | Étape | Lignes de log | Technique MITRE |
|---|---|---|---|
| 1 | L'admin se connecte par clé et lance un `sudo apt update` | 2 | — (activité normale) |
| 2 | Reconnaissance : 4 comptes inexistants testés (`admin`, `test`, `oracle`, `postgres`) | 4 | T1110.003 |
| 3 | Brute force du compte `root` : 12 échecs en ~10 secondes | 12 | T1110.001 |
| 4 | Connexion root réussie depuis l'IP d'attaque | 1 | T1078.003 |
| 5 | `su` échoué depuis le compte `www-data` | 1 | T1548 |

```bash
python scripts/simulate_attack.py --send
```

## 4. Ingestion et parsing

Les 20 lignes arrivent dans l'index `siem-logs-*`. Logstash les découpe avec grok et leur attribue un type :

| alert_type | Nombre | Sévérité |
|---|---|---|
| `ssh_failed` | 12 | HIGH |
| `ssh_invalid_user` | 4 | MEDIUM |
| `root_login` | 1 | CRITICAL |
| `ssh_success` | 1 | INFO |
| `su_failed` | 1 | CRITICAL |
| `sudo` | 1 | MEDIUM |
| **Lignes non parsées** | **0** | |

Exemple d'événement après parsing (connexion root) :

```json
{
  "message": "Oct 31 21:06:58 srv-lab01 sshd[6308]: Accepted password for root from 203.0.113.45 port 44428 ssh2",
  "hostname": "srv-lab01",
  "username": "root",
  "src_ip": "203.0.113.45",
  "src_port": "44428",
  "auth_method": "password",
  "alert_type": "root_login",
  "severity": "CRITICAL",
  "tags": ["_geoip_lookup_failure"]
}
```

Le tag `_geoip_lookup_failure` est normal : les plages de documentation n'ont pas de géolocalisation.

## 5. Détection

```bash
python scripts/detect.py --lookback 10m
```

```
[*] 2 règle(s) chargée(s) : SSH-001, AUTH-002 — fenêtre 10m

  [HIGH    ] SSH-001 — Brute force SSH : 12 échecs en 60s depuis 203.0.113.45 (utilisateur ciblé : root)
  [CRITICAL] AUTH-002 — Connexion suspecte (root_login) : root depuis 203.0.113.45
  [MEDIUM  ] AUTH-002 — Connexion suspecte (new_ip_login) : alessandro depuis 192.168.56.10
  [MEDIUM  ] AUTH-002 — Connexion suspecte (new_ip_login) : root depuis 203.0.113.45

[+] 4 alerte(s) levée(s)
```

Les 4 alertes sont aussi écrites dans l'index `siem-alerts`, consultable dans Kibana (vue « SIEM — Alertes »).

**Lecture analyste :** la combinaison *SSH-001 puis AUTH-002/root_login sur la même IP* raconte toute l'histoire : un mot de passe root a été deviné. Sur un vrai serveur, je bloquerais `203.0.113.45`, je couperais la session, je changerais le mot de passe root et je désactiverais `PermitRootLogin`.

## 6. Analyse des résultats

| Étape | Détectée ? | Commentaire |
|---|---|---|
| Activité admin | Non (normal) | Mais elle déclenche `new_ip_login` au premier lancement |
| Reconnaissance (invalid users) | **Non** | Parsée, mais aucune règle ne la couvre |
| Brute force | **Oui** | SSH-001, seuil franchi largement (12 > 5) |
| Connexion root | **Oui** | AUTH-002 / root_login, CRITICAL |
| `su` échoué | **Non** | Parsé en CRITICAL, mais aucune règle ne lève d'alerte |

**Faux positif :** `new_ip_login` sur `192.168.56.10`, l'IP de l'admin. Il n'y a pas encore d'historique, donc toutes les IP sont « nouvelles ». Il faudrait une période d'apprentissage (baseline) ou une liste d'IP connues.

Vérification : en relançant le même scénario quelques minutes plus tard, seules SSH-001 et root_login se déclenchent. `new_ip_login` se tait, car les deux IP sont maintenant dans l'historique.

## 7. Problèmes rencontrés et corrections

La première version du lab ne fonctionnait pas de bout en bout. Ce que j'ai trouvé en testant :

| Problème | Cause | Correction |
|---|---|---|
| Aucun log n'arrivait dans Elasticsearch | Le script envoyait en TCP sur le port 5000, mais `docker-compose` n'exposait que `5000/udp` | Port exposé en TCP et UDP, codec `json_lines` |
| Kibana refusait de démarrer | Le mot de passe du compte `kibana_system` n'était jamais défini | Conteneur `setup` one-shot qui le configure via l'API |
| Les règles ne trouvaient rien | Le script d'ingestion classait en `ssh_failed`, Logstash et les règles attendaient `ssh_bruteforce` | Parsing centralisé dans Logstash, un seul vocabulaire partout |
| Les règles YAML ne servaient à rien | Aucun composant ne les lisait | Écriture de `detect.py`, qui charge et exécute les règles |
| Mot de passe en clair dans `kibana.yml` | Valeur codée en dur | Secrets uniquement dans `.env` (ignoré par git), `.env.example` fourni |
| Elasticsearch, Logstash et Kibana publiés sur toutes les interfaces | Comportement par défaut de Docker (`0.0.0.0`) | Ports liés à `127.0.0.1`, vérifié avec le scanner du Cyber Automation Toolkit : 0 port ouvert depuis l'IP LAN, 3 en local |

## 8. Améliorations prévues

- [ ] Règle **RECON-003** : plus de 3 `Invalid user` depuis la même IP en 5 minutes (T1110.003)
- [ ] Règle **PRIV-004** : alerte sur chaque `su_failed` (T1548)
- [ ] Corrélation : brute force **suivi** d'un succès sur la même IP → une seule alerte CRITICAL
- [ ] Baseline des IP connues pour supprimer le faux positif `new_ip_login`
- [ ] Ingestion de vrais logs avec Filebeat depuis une VM Ubuntu
- [ ] Dashboard Kibana (top IP sources, échecs par minute)

## 9. Captures

> À ajouter : vue Discover filtrée sur `alert_type : ssh_failed`, vue « SIEM — Alertes ».
> Dossier : `docs/img/`

## 10. Ce que j'en retiens

- Un SIEM ne vaut que par son **parsing** : sans champs propres (`src_ip`, `username`), aucune règle n'est possible.
- Tester avec un scénario connu est le seul moyen de savoir ce qui est réellement détecté. Ici, 2 étapes sur 5 passaient inaperçues.
- Les faux positifs arrivent dès la première exécution : il faut prévoir le tuning dès la conception de la règle.
