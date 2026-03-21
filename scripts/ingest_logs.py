# ─── Script : Log Ingestion → Logstash ───────────────────────────────────────
# Envoie des fichiers logs vers Logstash via TCP (port 5000)
# Author : bonberoww
# ─────────────────────────────────────────────────────────────────────────────

import socket
import json
import os
import re
import datetime
import time
from colorama import Fore, Style, init

init(autoreset=True)

# ── Config ──
LOGSTASH_HOST = "localhost"
LOGSTASH_PORT = 5000
BATCH_SIZE    = 100
SLEEP_BETWEEN = 0.05  # secondes entre chaque envoi

# ── Patterns de parsing ──
PATTERNS = {
    "ssh_failed"  : r"Failed password for (?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)",
    "ssh_accepted": r"Accepted password for (?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)",
    "ssh_invalid" : r"Invalid user (?P<username>\S+) from (?P<src_ip>\S+)",
    "sudo"        : r"sudo:.+COMMAND=(?P<command>.+)",
    "su_failed"   : r"su: FAILED SU",
}


def parse_line(line: str) -> dict:
    """Parse une ligne de log et retourne un dict structuré."""
    event = {
        "raw"       : line.strip(),
        "timestamp" : datetime.datetime.utcnow().isoformat(),
        "source"    : "ingest_logs.py",
        "alert_type": "generic",
        "severity"  : "INFO",
    }

    for event_type, pattern in PATTERNS.items():
        match = re.search(pattern, line)
        if match:
            event.update(match.groupdict())
            event["alert_type"] = event_type
            event["severity"]   = get_severity(event_type)
            break

    return event


def get_severity(event_type: str) -> str:
    mapping = {
        "ssh_failed"  : "HIGH",
        "ssh_accepted": "INFO",
        "ssh_invalid" : "MEDIUM",
        "sudo"        : "MEDIUM",
        "su_failed"   : "CRITICAL",
    }
    return mapping.get(event_type, "INFO")


def send_to_logstash(events: list, host: str, port: int) -> int:
    """Envoie une liste d'événements vers Logstash via TCP."""
    sent = 0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            for event in events:
                payload = json.dumps(event) + "\n"
                s.sendall(payload.encode("utf-8"))
                sent += 1
                time.sleep(SLEEP_BETWEEN)
    except ConnectionRefusedError:
        print(f"{Fore.RED}[!] Impossible de se connecter à Logstash {host}:{port}")
        print(f"    Vérifiez que la stack ELK tourne : docker-compose up -d{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erreur : {e}{Style.RESET_ALL}")
    return sent


def ingest_file(filepath: str) -> None:
    """Lit un fichier log et envoie les événements par batch vers Logstash."""
    if not os.path.exists(filepath):
        print(f"{Fore.RED}[!] Fichier introuvable : {filepath}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[*] Ingestion de : {filepath}{Style.RESET_ALL}")

    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    total   = len(lines)
    batches = [lines[i:i+BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]
    sent    = 0

    print(f"{Fore.CYAN}[*] {total} lignes — {len(batches)} batch(s) → Logstash {LOGSTASH_HOST}:{LOGSTASH_PORT}{Style.RESET_ALL}\n")

    for i, batch in enumerate(batches, 1):
        events  = [parse_line(line) for line in batch if line.strip()]
        result  = send_to_logstash(events, LOGSTASH_HOST, LOGSTASH_PORT)
        sent   += result

        pct = int((i / len(batches)) * 40)
        bar = f"{'█' * pct}{'░' * (40 - pct)}"
        print(f"\r  {Fore.GREEN}[{bar}] {i}/{len(batches)} batches — {sent} événements envoyés{Style.RESET_ALL}", end="")

    print(f"\n\n{Fore.GREEN}[+] Ingestion terminée — {sent}/{total} lignes envoyées à Logstash{Style.RESET_ALL}\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"\n{Fore.CYAN}Usage : python scripts/ingest_logs.py <chemin_log>{Style.RESET_ALL}")
        print(f"Exemple : python scripts/ingest_logs.py /var/log/auth.log\n")
        sys.exit(1)
    ingest_file(sys.argv[1])