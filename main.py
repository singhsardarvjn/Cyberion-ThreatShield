"""Cyberion ThreatShield - run detections, validate, hunt, assess coverage.

Usage:
    python generate_logs.py      # create sample logs (once)
    python main.py               # run everything
    python main.py --logs path/to/your_events.json
"""
import argparse
import csv
import json
from pathlib import Path

import coverage
import hunts
from engine import load_rules, run_detections

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def validate(rules, events, alerts):
    """Compare alerts with ground truth (_expected) injected by the attack simulation."""
    expected = {e["_expected"] for e in events if e.get("_expected")}
    detected_ok = {t for a in alerts if a["expected"] for t in a["techniques"] if t == a["expected"]
                   } | {a["expected"] for a in alerts if a["expected"] and a["expected"] in a["techniques"]}
    missed = sorted(expected - detected_ok)
    false_pos = [a for a in alerts if not a["expected"]]
    n_mal = sum(1 for e in events if e.get("_expected"))
    tp_events = sum(1 for a in alerts if a["expected"])
    return {"simulated_techniques": sorted(expected), "detected": sorted(detected_ok), "missed": missed,
            "false_positives": false_pos, "malicious_events": n_mal, "tp_alerts": tp_events}


def write_report(path, rules, events, alerts, val, hunt_results, rows, pct):
    L = []
    L.append("# Cyberion ThreatShield - Detection Report\n")
    L.append(f"- Events analysed: **{len(events)}**\n- Sigma rules loaded: **{len(rules)}**\n- Alerts raised: **{len(alerts)}**\n")
    L.append("\n## 1. Alerts by rule\n\n| Rule | Level | Technique | Alerts |\n|---|---|---|---|")
    counts = {}
    for a in alerts:
        counts[a["rule_id"]] = counts.get(a["rule_id"], 0) + 1
    for r in sorted(rules, key=lambda r: LEVEL_ORDER.get(r["level"], 9)):
        from engine import technique_ids
        L.append(f'| {r["title"]} | {r["level"]} | {", ".join(technique_ids(r))} | {counts.get(r["id"], 0)} |')
    L.append("\n## 2. Validation against simulated attack\n")
    L.append(f'- Simulated techniques: {len(val["simulated_techniques"])}\n'
             f'- Detected: {len(val["detected"])}\n- Missed: {val["missed"] or "none"}\n'
             f'- False-positive alerts: {len(val["false_positives"])}')
    for a in val["false_positives"]:
        L.append(f'  - {a["time"]} {a["host"]} {a["rule_title"]} -> `{a["command_line"] or a["image"]}`')
    L.append("\n## 3. Threat hunts\n")
    for h in hunt_results:
        L.append(f'### {h["id"]}: {h["hypothesis"]}\n- Data: {h["data"]}\n- Hits: {len(h["hits"])}')
        for e in h["hits"][:8]:
            L.append(f'  - {e["UtcTime"]} {e["Computer"]} `{e.get("Image")}`')
        L.append("")
    L.append("## 4. Incident timeline (alerts grouped by host)\n")
    by_host = {}
    for a in alerts:
        by_host.setdefault(a["host"], []).append(a)
    for host, al in sorted(by_host.items(), key=lambda kv: -len(kv[1])):
        L.append(f"### {host} ({len(al)} alerts)\n\n| Time | Tactic | Technique | Rule |\n|---|---|---|---|")
        for a in al:
            L.append(f'| {a["time"]} | {", ".join(a["tactics"])} | {", ".join(a["techniques"])} | {a["rule_title"]} |')
        L.append("")
    L.append(f"## 5. ATT&CK coverage ({pct:.0f}% of priority techniques)\n\n| Technique | Name | Rules | Status |\n|---|---|---|---|")
    for r in rows:
        L.append(f'| {r["technique"]} | {r["name"]} | {", ".join(r["rules"]) or "-"} | {r["status"]} |')
    Path(path).write_text("\n".join(L), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="logs/sysmon_events.json")
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--out", default="output")
    args = ap.parse_args()

    Path(args.out).mkdir(exist_ok=True)
    events = json.loads(Path(args.logs).read_text(encoding="utf-8"))
    rules = load_rules(args.rules)
    alerts = run_detections(rules, events)
    alerts.sort(key=lambda a: (a["time"], LEVEL_ORDER.get(a["level"], 9)))

    print(f"[+] {len(events)} events | {len(rules)} rules | {len(alerts)} alerts\n")
    print(f'{"TIME":<20}{"HOST":<12}{"LEVEL":<10}{"TECH":<12}RULE')
    for a in alerts:
        print(f'{a["time"]:<20}{a["host"]:<12}{a["level"]:<10}{",".join(a["techniques"][:1]):<12}{a["rule_title"]}')

    val = validate(rules, events, alerts)
    print(f'\n[Validation] simulated={len(val["simulated_techniques"])} detected={len(val["detected"])} '
          f'missed={val["missed"] or "none"} false_positives={len(val["false_positives"])}')

    hunt_results = hunts.run_all(events)
    for h in hunt_results:
        print(f'[Hunt {h["id"]}] {len(h["hits"])} hits - {h["hypothesis"]}')

    rows, pct = coverage.build_coverage(rules, set(val["detected"]))
    print(f"[Coverage] {pct:.0f}% of priority techniques covered")

    out = Path(args.out)
    (out / "alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    with open(out / "alerts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["time", "host", "user", "level", "rule_id", "rule_title",
                                          "techniques", "tactics", "event_id", "image", "command_line"],
                           extrasaction="ignore")
        w.writeheader()
        for a in alerts:
            row = dict(a, techniques=";".join(a["techniques"]), tactics=";".join(a["tactics"]))
            w.writerow(row)
    coverage.navigator_layer(rows, out / "navigator_layer.json")
    write_report(out / "report.md", rules, events, alerts, val, hunt_results, rows, pct)
    print(f"\n[+] Wrote alerts.json, alerts.csv, navigator_layer.json, report.md to {out}/")


if __name__ == "__main__":
    main()
