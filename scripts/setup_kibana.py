# ─── Script : Préparation de Kibana ──────────────────────────────────────────
# Crée les vues de données (data views) siem-logs-* et siem-alerts
# pour explorer les événements et les alertes dans Discover.
# Author : bonberoww
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detect import ES_AUTH  # noqa: E402  (charge aussi le .env)

KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")

DATA_VIEWS = [
    {"id": "siem-logs", "title": "siem-logs-*", "name": "SIEM — Événements"},
    {"id": "siem-alerts", "title": "siem-alerts", "name": "SIEM — Alertes"},
]


def create_data_view(view: dict) -> None:
    r = requests.post(
        f"{KIBANA_URL}/api/data_views/data_view",
        auth=ES_AUTH,
        headers={"kbn-xsrf": "true"},
        json={"data_view": {**view, "timeFieldName": "@timestamp"}, "override": True},
        timeout=15,
    )
    status = "OK" if r.ok else f"erreur {r.status_code} : {r.text[:200]}"
    print(f"[*] Data view {view['title']:<12} → {status}")


if __name__ == "__main__":
    try:
        for view in DATA_VIEWS:
            create_data_view(view)
    except requests.exceptions.ConnectionError:
        print(f"[!] Kibana injoignable sur {KIBANA_URL} (il met ~1 min à démarrer)")
        sys.exit(1)
    print(f"[+] Ouvre {KIBANA_URL}/app/discover et choisis une vue SIEM")
