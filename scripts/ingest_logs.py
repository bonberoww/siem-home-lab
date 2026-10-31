# ─── Script : Log Ingestion → Logstash ───────────────────────────────────────
# Envoie les lignes d'un fichier log brut vers Logstash via TCP (port 5000).
# Le parsing et la classification sont faits côté Logstash (elk/logstash.conf).
# Author : bonberoww
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import json
import os
import socket
import time
from colorama import Fore, Style, init

init(autoreset=True)

# ── Config ──
LOGSTASH_HOST = "localhost"
LOGSTASH_PORT = 5000
SLEEP_BETWEEN = 0.01  # secondes entre chaque envoi


def build_event(line: str, log_file: str, log_type: str) -> dict:
    """Construit l'événement JSON envoyé à Logstash."""
    return {
        "message" : line.rstrip("\r\n"),
        "log_type": log_type,
        "log_file": log_file,
        "shipper" : "ingest_logs.py",
    }


def ingest_file(filepath: str, host: str = LOGSTASH_HOST, port: int = LOGSTASH_PORT,
                log_type: str = "auth") -> int:
    """Lit un fichier log et envoie chaque ligne vers Logstash. Retourne le nombre envoyé."""
    if not os.path.exists(filepath):
        print(f"{Fore.RED}[!] Fichier introuvable : {filepath}{Style.RESET_ALL}")
        return 0

    with open(filepath, "r", errors="ignore") as f:
        lines = [line for line in f if line.strip()]

    total = len(lines)
    print(f"\n{Fore.CYAN}[*] Ingestion de : {filepath}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] {total} lignes → Logstash {host}:{port}{Style.RESET_ALL}\n")

    sent = 0
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            for line in lines:
                event = build_event(line, os.path.basename(filepath), log_type)
                s.sendall((json.dumps(event) + "\n").encode("utf-8"))
                sent += 1
                pct = int((sent / total) * 40)
                print(f"\r  {Fore.GREEN}[{'█' * pct}{'░' * (40 - pct)}] {sent}/{total}{Style.RESET_ALL}", end="")
                time.sleep(SLEEP_BETWEEN)
    except (ConnectionRefusedError, socket.timeout):
        print(f"{Fore.RED}[!] Impossible de se connecter à Logstash {host}:{port}")
        print(f"    Vérifiez que la stack tourne : docker compose up -d{Style.RESET_ALL}")
        return sent
    except Exception as e:
        print(f"{Fore.RED}[!] Erreur : {e}{Style.RESET_ALL}")
        return sent

    print(f"\n\n{Fore.GREEN}[+] Ingestion terminée — {sent}/{total} lignes envoyées{Style.RESET_ALL}\n")
    return sent


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Envoie un fichier log vers Logstash")
    parser.add_argument("logfile", help="ex: /var/log/auth.log ou samples/auth_attack.log")
    parser.add_argument("--host", default=LOGSTASH_HOST)
    parser.add_argument("--port", type=int, default=LOGSTASH_PORT)
    parser.add_argument("--type", default="auth", dest="log_type", help="type de log (défaut : auth)")
    args = parser.parse_args()
    ingest_file(args.logfile, args.host, args.port, args.log_type)
