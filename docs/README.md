# TomcatShield — Enterprise Web Application Security Automation Platform

TomcatShield is a CI-native application security automation platform for web 
applications running on Apache Tomcat. It provides continuous security assurance 
through automated DAST scanning, Tomcat hardening checks, and CI/CD pipeline gates.

## Quickstart

### Prerequisites
- Python 3.12+
- Java 17+
- OWASP ZAP 2.17.0

### Installation
```bash
git clone <your-repo-url>
cd Secude-Security-Tool
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Run Tomcat Hardening Scan
```bash
python -m securitytool.cli --target http://your-target.com --tomcat
```

### Run DAST Scan
```bash
python -m securitytool.cli --target http://your-target.com --dast
```

### Run Both
```bash
python -m securitytool.cli --target http://your-target.com --tomcat --dast
```

### Use Config File
```bash
python -m securitytool.cli --config configs/dev.json
```

## CLI Reference

| Flag | Description |
|------|-------------|
| --target | Base URL of target application |
| --config | Path to JSON/YAML config file |
| --scan-mode | quick or deep |
| --threshold | Severity threshold for CI gate (default: High) |
| --output-dir | Output directory for reports (default: artifacts/) |
| --non-destructive | Enable safe mode |
| --tomcat | Run Tomcat hardening checks |
| --dast | Run DAST scan via ZAP |

## Reports
All reports are saved to the `artifacts/` directory:
- `tomcat_hardening_<timestamp>.json` — Machine readable
- `tomcat_hardening_<timestamp>.html` — Human readable
- `tomcat_hardening_<timestamp>.csv` — Management summary