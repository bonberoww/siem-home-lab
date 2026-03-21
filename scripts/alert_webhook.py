# ─── Script : Alertes Webhook ─────────────────────────────────────────────────
# Envoie des alertes SIEM vers Slack, Discord ou Teams
# Author : bonberoww
# ─────────────────────────────────────────────────────────────────────────────

import requests
import json
import datetime
import os
from colorama import Fore, Style, init

init(autoreset=True)

# ── Config webhooks ──
# Remplace par tes vraies URLs dans .env
WEBHOOKS = {
    "slack"  : os.getenv("SLACK_WEBHOOK_URL", ""),
    "discord": os.getenv("DISCORD_WEBHOOK_URL", ""),
    "teams"  : os.getenv("TEAMS_WEBHOOK_URL", ""),
}

# ── Couleurs par sévérité ──
SEVERITY_COLORS = {
    "CRITICAL": 0xFF0000,  # Rouge
    "HIGH"    : 0xFF8C00,  # Orange
    "MEDIUM"  : 0xFFD700,  # Jaune
    "INFO"    : 0x00BFFF,  # Bleu
}

SEVERITY_EMOJI = {
    "CRITICAL": "[CRITICAL]",
    "HIGH"    : "[HIGH]",
    "MEDIUM"  : "[MEDIUM]",
    "INFO"    : "[INFO]",
}


def send_slack(alert: dict, webhook_url: str) -> bool:
    """Envoie une alerte formatée vers Slack."""
    severity = alert.get("severity", "INFO")
    payload  = {
        "attachments": [{
            "color"  : f"#{SEVERITY_COLORS.get(severity, 0x00BFFF):06X}",
            "title"  : f"{SEVERITY_EMOJI.get(severity)} {alert.get('rule_name', 'Alerte SIEM')}",
            "fields" : [
                {"title": "Règle",      "value": alert.get("rule_id", "N/A"),       "short": True},
                {"title": "Sévérité",   "value": severity,                           "short": True},
                {"title": "IP source",  "value": alert.get("src_ip", "N/A"),        "short": True},
                {"title": "Utilisateur","value": alert.get("username", "N/A"),       "short": True},
                {"title": "Pays",       "value": alert.get("country", "N/A"),        "short": True},
                {"title": "Timestamp",  "value": alert.get("timestamp", "N/A"),      "short": True},
                {"title": "Détail",     "value": alert.get("message", "N/A"),        "short": False},
            ],
            "footer": "SIEM Home Lab — bonberoww",
        }]
    }
    return _post(webhook_url, payload)


def send_discord(alert: dict, webhook_url: str) -> bool:
    """Envoie une alerte formatée vers Discord."""
    severity = alert.get("severity", "INFO")
    payload  = {
        "embeds": [{
            "title"      : f"{SEVERITY_EMOJI.get(severity)} {alert.get('rule_name', 'Alerte SIEM')}",
            "color"      : SEVERITY_COLORS.get(severity, 0x00BFFF),
            "description": alert.get("message", ""),
            "fields"     : [
                {"name": "Règle",       "value": alert.get("rule_id", "N/A"),  "inline": True},
                {"name": "Sévérité",    "value": severity,                      "inline": True},
                {"name": "IP source",   "value": alert.get("src_ip", "N/A"),   "inline": True},
                {"name": "Utilisateur", "value": alert.get("username", "N/A"), "inline": True},
            ],
            "footer"    : {"text": "SIEM Home Lab — bonberoww"},
            "timestamp" : datetime.datetime.utcnow().isoformat(),
        }]
    }
    return _post(webhook_url, payload)


def send_teams(alert: dict, webhook_url: str) -> bool:
    """Envoie une alerte formatée vers Microsoft Teams."""
    severity = alert.get("severity", "INFO")
    payload  = {
        "@type"   : "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary" : alert.get("rule_name", "Alerte SIEM"),
        "title"   : f"{SEVERITY_EMOJI.get(severity)} {alert.get('rule_name', 'Alerte SIEM')}",
        "sections": [{
            "facts": [
                {"name": "Règle",       "value": alert.get("rule_id", "N/A")},
                {"name": "Sévérité",    "value": severity},
                {"name": "IP source",   "value": alert.get("src_ip", "N/A")},
                {"name": "Utilisateur", "value": alert.get("username", "N/A")},
                {"name": "Timestamp",   "value": alert.get("timestamp", "N/A")},
                {"name": "Détail",      "value": alert.get("message", "N/A")},
            ]
        }]
    }
    return _post(webhook_url, payload)


def _post(url: str, payload: dict) -> bool:
    """Envoie la requête HTTP POST."""
    if not url:
        print(f"{Fore.YELLOW}[!] URL webhook non configurée{Style.RESET_ALL}")
        return False
    try:
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code in [200, 204]:
            print(f"{Fore.GREEN}[+] Alerte envoyée ({r.status_code}){Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!] Erreur HTTP {r.status_code} : {r.text}{Style.RESET_ALL}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[!] Connexion impossible — vérifie l'URL webhook{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}[!] Erreur : {e}{Style.RESET_ALL}")
        return False


def dispatch_alert(alert: dict, channels: list = None) -> None:
    """
    Dispatche une alerte vers un ou plusieurs canaux.
    channels : ["slack", "discord", "teams"] ou None pour tous
    """
    if channels is None:
        channels = [k for k, v in WEBHOOKS.items() if v]

    print(f"\n{Fore.CYAN}[*] Dispatch alerte — {alert.get('rule_id')} [{alert.get('severity')}]{Style.RESET_ALL}")

    for channel in channels:
        url = WEBHOOKS.get(channel, "")
        if not url:
            print(f"{Fore.YELLOW}  [!] {channel} — webhook non configuré, skip{Style.RESET_ALL}")
            continue

        print(f"  {Fore.CYAN}→ Envoi vers {channel}...{Style.RESET_ALL}", end=" ")
        if channel == "slack":
            send_slack(alert, url)
        elif channel == "discord":
            send_discord(alert, url)
        elif channel == "teams":
            send_teams(alert, url)


# ── Exemple d'utilisation ──
if __name__ == "__main__":
    test_alert = {
        "rule_id"  : "SSH-001",
        "rule_name": "SSH Brute Force Detected",
        "severity" : "HIGH",
        "src_ip"   : "192.168.1.100",
        "username" : "root",
        "country"  : "Russia",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "message"  : "5 tentatives SSH échouées en 30 secondes depuis 192.168.1.100",
    }
    dispatch_alert(test_alert)