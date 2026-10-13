"""Cyberion ThreatShield - web dashboard.

Run:  python app.py      then open  http://127.0.0.1:5000
"""
import csv
import json
import os
from pathlib import Path

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)  # works no matter which folder the terminal is in

from flask import Flask, jsonify, render_template, request, send_from_directory

import coverage
import engine
import generate_logs
import hunts
from main import LEVEL_ORDER, validate, write_report

app = Flask(__name__)
LOG_FILE = Path("logs/sysmon_events.json")


def ensure_logs():
    os.makedirs("logs", exist_ok=True)
    if not LOG_FILE.exists():
        generate_logs.main()


def count_by(items, key):
    out = {}
    for it in items:
        vals = it[key] if isinstance(it[key], list) else [it[key]]
        for v in vals:
            out[v] = out.get(v, 0) + 1
    return out


def write_csv(path, alerts):
    cols = ["time", "host", "user", "level", "rule_id", "rule_title", "techniques",
            "tactics", "event_id", "image", "command_line"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for a in alerts:
            w.writerow(dict(a, techniques=";".join(a["techniques"]), tactics=";".join(a["tactics"])))


def analyze(events):
    rules = engine.load_rules("rules")
    alerts = engine.run_detections(rules, events)
    alerts.sort(key=lambda a: (a["time"], LEVEL_ORDER.get(a["level"], 9)))
    val = validate(rules, events, alerts)
    hunt_results = hunts.run_all(events)
    rows, pct = coverage.build_coverage(rules, set(val["detected"]))

    os.makedirs("output", exist_ok=True)
    write_report("output/report.md", rules, events, alerts, val, hunt_results, rows, pct)
    write_csv("output/alerts.csv", alerts)
    coverage.navigator_layer(rows, "output/navigator_layer.json")
    Path("output/alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")

    has_truth = bool(val["simulated_techniques"])
    n_sim = len(val["simulated_techniques"])
    counts = count_by(alerts, "rule_id")
    rule_info = []
    for r in rules:
        rule_info.append({
            "id": r["id"], "title": r["title"], "level": r.get("level"),
            "description": r.get("description"), "techniques": engine.technique_ids(r),
            "tactics": engine.tactic_names(r), "falsepositives": r.get("falsepositives", []),
            "alerts": counts.get(r["id"], 0),
            "yaml": Path("rules", r["_file"]).read_text(encoding="utf-8"),
        })
    return {
        "summary": {
            "events": len(events), "rules": len(rules), "alerts": len(alerts),
            "critical_high": sum(1 for a in alerts if a["level"] in ("critical", "high")),
            "hosts": len({a["host"] for a in alerts}),
            "has_ground_truth": has_truth,
            "detection_rate": round(100 * len(val["detected"]) / n_sim) if n_sim else None,
            "false_positives": len(val["false_positives"]) if has_truth else None,
            "coverage_pct": round(pct),
        },
        "by_level": count_by(alerts, "level"),
        "by_tactic": count_by(alerts, "tactics"),
        "by_host": count_by(alerts, "host"),
        "alerts": alerts,
        "validation": {k: val[k] for k in ("simulated_techniques", "detected", "missed")},
        "hunts": [{"id": h["id"], "hypothesis": h["hypothesis"], "data": h["data"],
                   "hits": [{"time": e["UtcTime"], "host": e["Computer"], "image": e.get("Image"),
                             "command_line": e.get("CommandLine")} for e in h["hits"]]}
                  for h in hunt_results],
        "coverage": rows,
        "rules": rule_info,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    upload = request.files.get("logs")
    try:
        if upload and upload.filename:
            events = json.load(upload.stream)
        else:
            ensure_logs()
            events = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        if not isinstance(events, list):
            raise ValueError("Log file must be a JSON list of events")
        return jsonify(analyze(events))
    except Exception as exc:  # show a friendly error in the UI
        return jsonify({"error": str(exc)}), 400


@app.route("/api/playbooks")
def api_playbooks():
    pb = []
    for p in sorted(Path("playbooks").glob("*.md")):
        text = p.read_text(encoding="utf-8")
        pb.append({"name": text.splitlines()[0].lstrip("# ").strip(), "text": text})
    return jsonify(pb)


@app.route("/download/<name>")
def download(name):
    if name not in ("report.md", "alerts.csv", "alerts.json", "navigator_layer.json"):
        return "Not found", 404
    return send_from_directory("output", name, as_attachment=True)


if __name__ == "__main__":
    ensure_logs()
    print("\n  Cyberion ThreatShield dashboard -> http://127.0.0.1:5000\n")
    app.run(debug=False, port=5000)
