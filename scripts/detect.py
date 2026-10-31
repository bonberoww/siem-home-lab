# ─── Script : Moteur de détection ────────────────────────────────────────────
# Charge les règles de rules/*.yml, interroge Elasticsearch et lève les alertes :
#   - affichage console
#   - indexation dans l'index siem-alerts (visible dans Kibana)
#   - envoi webhook (Slack / Discord / Teams) si configuré dans .env
# Author : bonberoww
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import datetime
import glob
import os
import sys
import time

import requests
import yaml
from colorama import Fore, Style, init

init(autoreset=True)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env(path: str = os.path.join(ROOT, ".env")) -> None:
    """Charge le .env dans os.environ (sans écraser l'existant)."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())


load_env()
from alert_webhook import dispatch_alert  # noqa: E402  (lit les webhooks depuis l'env)

ES_URL  = os.getenv("ES_URL", "http://localhost:9200")
ES_AUTH = ("elastic", os.getenv("ELASTIC_PASSWORD", ""))

SEVERITY_COLORS = {"CRITICAL": Fore.RED, "HIGH": Fore.YELLOW, "MEDIUM": Fore.MAGENTA, "INFO": Fore.CYAN}


# ── Elasticsearch ──

def es_search(index: str, query: dict, size: int = 10000) -> list:
    r = requests.post(f"{ES_URL}/{index}/_search", auth=ES_AUTH, timeout=10,
                      json={"size": size, "query": query, "sort": [{"@timestamp": "asc"}]})
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return [hit["_source"] for hit in r.json()["hits"]["hits"]]


def es_count(index: str, query: dict) -> int:
    r = requests.post(f"{ES_URL}/{index}/_count", auth=ES_AUTH, timeout=10, json={"query": query})
    if r.status_code == 404:
        return 0
    r.raise_for_status()
    return r.json()["count"]


def build_query(filters: dict, gte: str = None, lt: str = None) -> dict:
    must = []
    for field, value in filters.items():
        values = value if isinstance(value, list) else [value]
        must.append({"terms": {f"{field}.keyword": values}})
    if gte or lt:
        rng = {}
        if gte: rng["gte"] = gte
        if lt:  rng["lt"]  = lt
        must.append({"range": {"@timestamp": rng}})
    return {"bool": {"filter": must}}


def parse_ts(value: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


# ── Évaluation des règles ──

def eval_threshold(rule: dict, det: dict, since: str) -> list:
    events = es_search(det["index"], build_query(det["filter"], gte=since))
    window = datetime.timedelta(seconds=det["timeframe"])
    groups = {}
    for ev in events:
        groups.setdefault(ev.get(det["group_by"], "?"), []).append(ev)

    alerts = []
    for key, evs in groups.items():
        times = [parse_ts(e["@timestamp"]) for e in evs]
        start, best = 0, (0, 0, 0)
        for end in range(len(times)):  # fenêtre glissante
            while times[end] - times[start] > window:
                start += 1
            if end - start + 1 > best[0]:
                best = (end - start + 1, start, end)
        count, s, e = best
        if count > det["threshold"]:
            alerts.append({
                "condition_id": "threshold",
                "severity"    : rule["rule"]["severity"],
                det["group_by"]: key,
                "username"    : evs[e].get("username", "N/A"),
                "count"       : count,
                "timeframe"   : det["timeframe"],
                "first_seen"  : evs[s]["@timestamp"],
                "timestamp"   : evs[e]["@timestamp"],
            })
    return alerts


def eval_match(rule: dict, det: dict, since: str) -> list:
    alerts = []
    for cond in det["conditions"]:
        for ev in es_search(det["index"], build_query(cond["filter"], gte=since)):
            if "hours" in cond:
                hour = parse_ts(ev["@timestamp"]).astimezone().hour
                start, end = cond["hours"]["start"], cond["hours"]["end"]
                in_range = (hour >= start or hour < end) if start > end else (start <= hour < end)
                if not in_range:
                    continue
            if "first_seen" in cond:
                field = cond["first_seen"]
                seen_before = es_count(det["index"], {"bool": {"filter": [
                    {"term": {f"{field}.keyword": ev.get(field, "")}},
                    {"terms": {"alert_type.keyword": ["ssh_success", "root_login"]}},
                    {"range": {"@timestamp": {"lt": since}}},
                ]}})
                if seen_before:
                    continue
            alerts.append({
                "condition_id": cond["id"],
                "severity"    : cond.get("severity", rule["rule"]["severity"]),
                "src_ip"      : ev.get("src_ip", "N/A"),
                "username"    : ev.get("username", "N/A"),
                "timestamp"   : ev["@timestamp"],
            })
    return alerts


EVALUATORS = {"threshold": eval_threshold, "match": eval_match}


def alert_key(rule_id: str, alert: dict) -> tuple:
    return (rule_id, alert["condition_id"], alert.get("src_ip"), alert.get("username"),
            alert["timestamp"] if alert["condition_id"] != "threshold" else alert["first_seen"])


def raise_alert(rule: dict, alert: dict) -> None:
    meta = rule["rule"]
    doc = {
        "@timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rule_id"   : meta["id"],
        "rule_name" : meta["name"],
        "mitre"     : rule.get("mitre_attack", {}).get("subtechnique", ""),
        "message"   : rule.get("response", {}).get("message", meta["name"]).format_map(
                          {**alert, "src_ip": alert.get("src_ip", "N/A")}),
        **alert,
    }
    color = SEVERITY_COLORS.get(doc["severity"], Fore.WHITE)
    print(f"  {color}[{doc['severity']:<8}] {doc['rule_id']} — {doc['message']}{Style.RESET_ALL}")

    requests.post(f"{ES_URL}/siem-alerts/_doc", auth=ES_AUTH, json=doc, timeout=10)
    dispatch_alert(doc)


def run(rules: list, lookback: str, seen: set) -> int:
    since = f"now-{lookback}"
    raised = 0
    for rule in rules:
        det = rule["detection"]
        for alert in EVALUATORS[det["type"]](rule, det, since):
            key = alert_key(rule["rule"]["id"], alert)
            if key in seen:
                continue
            seen.add(key)
            raise_alert(rule, alert)
            raised += 1
    return raised


def load_rules(directory: str) -> list:
    rules = []
    for path in sorted(glob.glob(os.path.join(directory, "*.yml"))):
        with open(path, encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        if rule.get("detection", {}).get("type") in EVALUATORS:
            rules.append(rule)
    return rules


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exécute les règles de détection sur Elasticsearch")
    parser.add_argument("--lookback", default="15m", help="fenêtre analysée (ex: 15m, 1h, 1d)")
    parser.add_argument("--watch", type=int, metavar="SEC", help="relance toutes les SEC secondes")
    parser.add_argument("--rules", default=os.path.join(ROOT, "rules"))
    args = parser.parse_args()

    rules = load_rules(args.rules)
    print(f"\n{Fore.CYAN}[*] {len(rules)} règle(s) chargée(s) : "
          f"{', '.join(r['rule']['id'] for r in rules)} — fenêtre {args.lookback}{Style.RESET_ALL}\n")

    seen = set()
    try:
        while True:
            try:
                count = run(rules, args.lookback, seen)
            except requests.exceptions.ConnectionError:
                print(f"{Fore.RED}[!] Elasticsearch injoignable sur {ES_URL}{Style.RESET_ALL}")
                sys.exit(1)
            if not args.watch:
                print(f"\n{Fore.GREEN}[+] {count} alerte(s) levée(s){Style.RESET_ALL}\n")
                break
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}[*] Arrêt du moteur de détection{Style.RESET_ALL}")
