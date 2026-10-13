# Cyberion ThreatShield: Detection Engineering and Threat Hunting
**Name:** ____  **Date:** ____

## 1. Introduction
Purpose, SOC context, objectives (detection, hunting, response, coverage).

## 2. Lab setup
Tools: Python, Sigma rules, MITRE ATT&CK, Sysmon-style logs (synthetic). Describe the project structure.

## 3. Log analysis
Log source, key fields (EventID 1, 10, 13; Image, CommandLine, ParentImage), sample events.

## 4. Sigma detection library
Table: Rule ID, title, technique, tactic, level, false positives (see `rules/`).

## 5. Attack simulation and validation
Attack chain steps (generate_logs.py), detected vs missed, false positives and tuning (output/report.md section 2).

## 6. Threat hunting
Hypotheses H1-H3, data used, findings.

## 7. Incident investigation
Timeline from output/report.md section 4 (WS-FIN-01 to SRV-APP-01), IOCs, root cause, impact.

## 8. Incident response playbooks
Summaries of the three playbooks in playbooks/.

## 9. Detection coverage assessment
Navigator screenshot, coverage %, gaps (T1566.001, T1078, T1110, T1486, T1055, ...), next priorities.

## 10. Conclusion and future work
Real telemetry, more rules, SIEM integration, automated tests.
