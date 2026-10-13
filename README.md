# 🛡️ Cyberion ThreatShield
### Detection Engineering & Threat Hunting Framework

**Cyberion ThreatShield** is a cybersecurity project designed to analyse security logs, detect suspicious activities, and support threat hunting using Sigma-style detection rules and MITRE ATT&CK mapping.

The framework demonstrates how security events can be investigated, detection rules can be validated, and potential threats can be documented through structured reports.

## 🚀 Features

- **Security Log Analysis:** Analyse Sysmon-style security event logs.
- **Detection Engine:** Apply Sigma-style YAML rules to identify suspicious activities.
- **MITRE ATT&CK Mapping:** Map selected detections to relevant ATT&CK techniques.
- **Threat Hunting:** Hunt for suspicious execution paths, command discovery bursts, and rare parent-child process relationships.
- **Alert Generation:** Generate detection alerts in CSV and JSON formats.
- **Coverage Assessment:** Identify covered, validated, and unvalidated detection techniques.
- **Reporting:** Generate a Markdown report and an ATT&CK Navigator layer.
- **Web Dashboard:** View detection results and security analysis through a Flask-based interface.

## 🧰 Technologies Used

- Python
- Flask
- YAML / PyYAML
- HTML and CSS (for the web interface, if included)
- Sigma-style detection rules
- MITRE ATT&CK Framework

## 📂 Project Structure

```text
Cyberion-ThreatShield/
├── app.py
├── main.py
├── engine.py
├── coverage.py
├── hunts.py
├── generate_logs.py
├── requirements.txt
├── README.md
├── rules/
├── templates/
├── playbooks/
└── output/
```

*Note: The actual folder structure may vary depending on the files included in your repository.*

## ⚙️ Installation

1. Clone the repository:

   ```bash
   git clone YOUR_GITHUB_REPOSITORY_URL
   ```

2. Open the project directory:

   ```bash
   cd Cyberion-ThreatShield
   ```

3. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## ▶️ How to Run

### Web Dashboard

Run:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

### Command-Line Analysis

Run:

```bash
python main.py
```

Use the workflow and input files configured in the project.

## 📊 Output

Depending on the configured workflow, the framework can generate:

- `output/report.md` — Detection analysis report
- `output/alerts.csv` — Alerts in CSV format
- `output/alerts.json` — Alerts in JSON format
- `output/navigator_layer.json` — MITRE ATT&CK Navigator layer

## 🧪 Testing and Validation

The project uses synthetic Sysmon-style logs and controlled simulated activity to demonstrate detection logic. Results depend on the available rules, configured input logs, and validation workflow.

**Important:** This project is an educational demonstration. Synthetic log results do not represent confirmed attacks or detections from a live production environment.

## 🔐 Ethical Use

This framework is intended for educational, defensive security, detection engineering, and authorised security testing purposes only.

## 👨‍💻 Author

**Ashmeet Singh**

Cybersecurity Learner | Detection Engineering | Threat Hunting

## ⭐ Project Goal

To demonstrate practical skills in security log analysis, detection rule development, threat hunting, incident investigation, and MITRE ATT&CK-based detection coverage assessment.
