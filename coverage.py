"""ATT&CK coverage assessment + Navigator layer."""
import json

# Priority techniques the SOC wants covered (extend this list as the project grows)
PRIORITY = {
    "T1059.001": "PowerShell", "T1204.002": "Malicious File", "T1053.005": "Scheduled Task",
    "T1547.001": "Registry Run Keys", "T1070.001": "Clear Windows Event Logs",
    "T1562.001": "Disable or Modify Tools", "T1003.001": "LSASS Memory",
    "T1087.001": "Local Account Discovery", "T1033": "System Owner/User Discovery",
    "T1021.002": "SMB/Admin Shares", "T1105": "Ingress Tool Transfer",
    "T1566.001": "Spearphishing Attachment", "T1078": "Valid Accounts",
    "T1110": "Brute Force", "T1486": "Data Encrypted for Impact",
    "T1055": "Process Injection", "T1218": "System Binary Proxy Execution",
    "T1021.001": "Remote Desktop Protocol", "T1490": "Inhibit System Recovery",
    "T1136.001": "Create Local Account",
}


def build_coverage(rules, validated):
    """validated: set of technique IDs whose simulation was detected."""
    rows = []
    covered = {}
    for r in rules:
        for t in r_techniques(r):
            covered.setdefault(t, []).append(r["id"])
    for tid, name in PRIORITY.items():
        if tid in covered:
            status = "Covered + validated" if tid in validated else "Covered (not validated)"
        else:
            status = "GAP"
        rows.append({"technique": tid, "name": name, "rules": covered.get(tid, []), "status": status})
    pct = 100 * sum(1 for r in rows if r["status"] != "GAP") / len(rows)
    return rows, pct


def r_techniques(rule):
    from engine import technique_ids
    return technique_ids(rule)


def navigator_layer(rows, path):
    color = {"Covered + validated": "#2e7d32", "Covered (not validated)": "#f9a825", "GAP": "#c62828"}
    layer = {
        "name": "Cyberion ThreatShield Coverage", "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Green = validated, Yellow = covered not validated, Red = gap",
        "techniques": [{"techniqueID": r["technique"], "color": color[r["status"]],
                        "comment": f'{r["status"]} {", ".join(r["rules"])}'} for r in rows],
    }
    with open(path, "w") as f:
        json.dump(layer, f, indent=2)
