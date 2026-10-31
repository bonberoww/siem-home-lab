# ─── Script : Simulation d'attaque SSH ───────────────────────────────────────
# Génère un auth.log réaliste (activité normale + brute force + connexion root)
# pour tester la chaîne complète : ingestion → parsing → détection → alerte.
# Les IP d'attaque sont dans des plages réservées à la documentation (RFC 5737).
# Author : bonberoww
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import datetime
import os
import random

HOST     = "srv-lab01"
ADMIN_IP = "192.168.56.10"   # poste d'admin légitime
ATTACKER = "203.0.113.45"    # IP de test (TEST-NET-3)
SCANNER  = "198.51.100.23"   # IP de test (TEST-NET-2)


def syslog_ts(t: datetime.datetime) -> str:
    return t.strftime("%b ") + f"{t.day:>2}" + t.strftime(" %H:%M:%S")


def build_scenario(start: datetime.datetime) -> list:
    """Retourne la liste des lignes du scénario, dans l'ordre chronologique."""
    lines, t, pid = [], start, random.randint(2000, 9000)

    def add(program: str, msg: str, step: float = 1.0):
        nonlocal t, pid
        t += datetime.timedelta(seconds=step)
        pid += 1
        lines.append(f"{syslog_ts(t)} {HOST} {program}[{pid}]: {msg}")

    # 1. Activité normale de l'admin
    add("sshd", f"Accepted publickey for alessandro from {ADMIN_IP} port 52114 ssh2")
    add("sudo", "alessandro : TTY=pts/0 ; PWD=/home/alessandro ; USER=root ; COMMAND=/usr/bin/apt update", 4)

    # 2. Reconnaissance : utilisateurs inexistants
    for user in ["admin", "test", "oracle", "postgres"]:
        add("sshd", f"Invalid user {user} from {SCANNER} port {random.randint(40000, 60000)}", 0.8)

    # 3. Brute force sur root (12 échecs en ~10 secondes)
    for _ in range(12):
        add("sshd", f"Failed password for root from {ATTACKER} port {random.randint(40000, 60000)} ssh2", 0.8)

    # 4. Le mot de passe finit par passer : connexion root réussie
    add("sshd", f"Accepted password for root from {ATTACKER} port {random.randint(40000, 60000)} ssh2", 2)

    # 5. Tentative d'élévation ratée sur le serveur
    add("su", "FAILED SU (to root) www-data on pts/1", 5)
    return lines


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Génère un auth.log de test")
    parser.add_argument("-o", "--output", default="samples/auth_attack.log")
    parser.add_argument("--send", action="store_true", help="envoie directement le fichier à Logstash")
    args = parser.parse_args()

    lines = build_scenario(datetime.datetime.now())
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] {len(lines)} lignes écrites dans {args.output}")

    if args.send:
        from ingest_logs import ingest_file
        ingest_file(args.output)
