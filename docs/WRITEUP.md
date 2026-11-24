# Write-up : détecter un brute force SSH

Test du SIEM Home Lab le 31/10/2026, avec la stack Elasticsearch, Logstash et Kibana 8.12 sous Docker.

## Ce que je voulais vérifier

Que le lab détecte une attaque classique sur un serveur Linux : un brute force SSH sur le compte root, suivi d'une connexion réussie. Autrement dit : si ça arrivait vraiment, est-ce que le SIEM me préviendrait ?

## Le scénario

Le script `scripts/simulate_attack.py` génère 20 lignes d'`auth.log` pour un serveur fictif, `srv-lab01`. Les adresses IP viennent des plages réservées à la documentation (RFC 5737) : aucun vrai système n'est visé.

1. L'admin se connecte avec sa clé et lance un `sudo`.
2. Quatre comptes inexistants sont testés (`admin`, `test`, `oracle`, `postgres`).
3. 12 échecs de mot de passe sur `root` en une dizaine de secondes.
4. Une connexion root réussit, depuis la même IP.
5. Un `su` échoue depuis le compte `www-data`.

```bash
python scripts/simulate_attack.py --send
python scripts/detect.py --lookback 10m
```

## Ce qui arrive dans Elasticsearch

Les 20 lignes sont toutes parsées par Logstash : aucune ligne n'est restée brute. Chacune reçoit un type (`ssh_failed`, `root_login`, `su_failed`…) et une sévérité, avec les champs `src_ip`, `username` et `hostname` extraits.

## Les alertes

```
[HIGH    ] SSH-001 - Brute force SSH : 12 échecs en 60s depuis 203.0.113.45 (utilisateur ciblé : root)
[CRITICAL] AUTH-002 - Connexion suspecte (root_login) : root depuis 203.0.113.45
[MEDIUM  ] AUTH-002 - Connexion suspecte (new_ip_login) : alessandro depuis 192.168.56.10
[MEDIUM  ] AUTH-002 - Connexion suspecte (new_ip_login) : root depuis 203.0.113.45
```

Les alertes sont aussi écrites dans l'index `siem-alerts`, visible dans Kibana.

Les deux premières racontent l'attaque : un mot de passe root a été deviné. Sur un vrai serveur, je bloquerais l'IP, je couperais la session, je changerais le mot de passe et je désactiverais la connexion root en SSH.

## Ce qui est détecté, et ce qui ne l'est pas

- Le brute force et la connexion root sont bien détectés.
- Les comptes inexistants et le `su` raté sont parsés mais ne déclenchent aucune règle : 2 étapes sur 5 passent inaperçues.
- L'alerte `new_ip_login` sur l'IP de l'admin est un faux positif. Au premier lancement, il n'y a pas d'historique donc toutes les IP sont nouvelles. En relançant le scénario quelques minutes plus tard, elle ne se déclenche plus.

## Problèmes rencontrés

La première version ne marchait pas de bout en bout :

- Les logs n'arrivaient pas : le port TCP 5000 n'était pas publié par Docker, seulement l'UDP.
- Kibana ne démarrait pas : le mot de passe du compte `kibana_system` n'était pas défini.
- Les règles ne trouvaient rien : le script d'envoi et les règles n'utilisaient pas les mêmes noms d'événements. J'ai centralisé le parsing dans Logstash.
- Les règles YAML n'étaient lues par rien : j'ai écrit `detect.py`.
- Un mot de passe était écrit en dur dans `kibana.yml` : il est maintenant dans le fichier `.env`, qui n'est pas versionné.
- Les services étaient accessibles depuis tout le réseau : les ports sont liés à `127.0.0.1`. Je l'ai vérifié avec mon [toolkit](https://github.com/bonberoww/cyber-automation-toolkit) : aucun port ouvert depuis l'adresse réseau de la machine.

## Pour la suite

- Une règle pour les comptes inexistants testés depuis la même IP (T1110.003).
- Une règle pour chaque `su` raté (T1548).
- Une seule alerte critique quand un brute force est suivi d'un succès sur la même IP.
- Une liste d'IP connues pour supprimer le faux positif.
- Des vrais logs, avec Filebeat depuis une VM Ubuntu, et un tableau de bord Kibana.

## Ce que j'en retiens

Sans parsing propre, aucune règle n'est possible. Et il faut tester avec un scénario dont on connaît la réponse : c'est comme ça que j'ai vu que 2 étapes sur 5 n'étaient pas détectées.
