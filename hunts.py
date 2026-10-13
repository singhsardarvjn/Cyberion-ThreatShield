"""Hypothesis-driven threat hunts over the same log set (no rules needed)."""
from collections import defaultdict
from datetime import datetime

FMT = "%Y-%m-%d %H:%M:%S"


def hunt_user_writable_exec(events):
    """H1: Attackers run payloads from user-writable paths (Public, Temp, AppData)."""
    bad = ("\\users\\public\\", "\\temp\\", "\\appdata\\")
    hits = [e for e in events if e["EventID"] in (1, 10) and
            any(b in (e.get("Image") or "").lower() for b in bad)]
    return {"id": "H1", "hypothesis": "Payloads execute from user-writable directories (T1204 / T1036)",
            "data": "Sysmon EID 1/10 - Image", "hits": hits}


def hunt_discovery_burst(events, window=600, threshold=3):
    """H2: Many discovery commands on one host in a short window indicates hands-on-keyboard activity."""
    disc = ("whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe")
    per_host = defaultdict(list)
    for e in events:
        if e["EventID"] == 1 and (e.get("Image") or "").lower().endswith(disc):
            per_host[e["Computer"]].append(e)
    hits = []
    for host, evs in per_host.items():
        times = [datetime.strptime(e["UtcTime"], FMT) for e in evs]
        for i in range(len(evs)):
            group = [evs[j] for j in range(i, len(evs)) if (times[j] - times[i]).total_seconds() <= window]
            if len(group) >= threshold:
                hits.extend(group)
                break
    return {"id": "H2", "hypothesis": f">= {threshold} discovery commands within {window//60} min on one host (T1087/T1033)",
            "data": "Sysmon EID 1 - Image, UtcTime", "hits": hits}


def hunt_rare_parent_child(events):
    """H3: Parent->child process pairs seen only once in the environment (stack counting)."""
    pairs = defaultdict(list)
    for e in events:
        if e["EventID"] == 1:
            key = ((e.get("ParentImage") or "").split("\\")[-1].lower(),
                   (e.get("Image") or "").split("\\")[-1].lower())
            pairs[key].append(e)
    hits = [v[0] for k, v in pairs.items() if len(v) == 1]
    return {"id": "H3", "hypothesis": "Rare parent-child process pairs (long-tail analysis) reveal anomalies",
            "data": "Sysmon EID 1 - ParentImage, Image", "hits": hits}


def run_all(events):
    return [hunt_user_writable_exec(events), hunt_discovery_burst(events), hunt_rare_parent_child(events)]
