# SECUDE Security Automation Tool

This project is being developed as part of a client-requested security automation initiative at SECUDE.

The goal of this tool is to perform controlled, safe, and repeatable security checks against an approved application environment, while maintaining strict boundaries around data safety, system stability, and organizational trust.

This repository is intentionally built step by step, with a focus on clarity, explainability, and responsible security practices.
8) Suggested Tool Architecture (Example)
security-tool/
├─ securitytool/
│  ├─ cli.py                 # entry point & argparse
│  ├─ config.py              # load/validate YAML/JSON
│  ├─ # 🛡️ AYSAL SHIELD

### Enterprise Web Application Security Automation Platform

**v0.1.0** | Developed by Neeraj Mudunuru

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![ZAP](https://img.shields.io/badge/OWASP%20ZAP-2.17.0-red?style=for-the-badge)](https://zaproxy.org)
[![Java](https://img.shields.io/badge/Java-17%2B-orange?style=for-the-badge&logo=openjdk)](https://adoptium.net)
[![License](https://img.shields.io/badge/License-Proprietary-darkred?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge)](https://github.com)

---

*A repeatable, policy-driven security pipeline — not a one-time scan tool.*

---

##  What is Aysal Shield?

Aysal Shield is a **CI-native application security automation platform** that provides continuous security assurance for web applications running on Apache Tomcat infrastructure.

It orchestrates the full **Dynamic Application Security Testing (DAST)** lifecycle:

- ✅ Authenticated and unauthenticated crawling
- ✅ OWASP Top 10 attack coverage via ZAP
- ✅ Apache Tomcat hardening benchmarks
- ✅ Result normalization and deduplication
- ✅ Multi-format reporting (JSON, HTML, CSV)
- ✅ CI/CD pipeline gates (fail on High/Critical)

> **Built for:** Security engineers, DevSecOps teams, and platform teams who need automated, evidence-backed security gates on every code push — without relying on manual pentests.

---

##  Quick Start

### Prerequisites

| Requirement | Version | Download |
|-------------|---------|----------|
| Python | 3.10+ | https://python.org |
| Java | 17+ | https://adoptium.net |
| OWASP ZAP | 2.17.0 | https://zaproxy.org/download |
| Git | Any | https://git-scm.com |

### Windows (Powershell)

```powershell
git clone <your-repo-url>
cd Aysal_Shield
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

$env:ZAP_HOME="C:\Program Files\ZAP\Zed Attack Proxy"
$env:TEST_USER="your_test_username"
$env:TEST_PASS="your_test_password"

python -m securitytool.cli --help
```

### Linux

```bash
git clone <your-repo-url>
cd Security-Tool-V1.1
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export ZAP_HOME="/path/to/ZAP_2.17.0"
export TEST_USER="your_test_username"
export TEST_PASS="your_test_password"

python -m securitytool.cli --help
```

---

## CLI Preview

### Interactive Mode

```powershell
python -m securitytool.cli
```

![Aysal Shield Interactive Menu](docs/images/cli-menu.png)

### Help Output

```powershell
python -m securitytool.cli --help
```

![Aysal Shield CLI Help](docs/images/cli-help.png)

---

## Running Scans

### Tomcat Hardening Only *(no ZAP required)*

```powershell
python -m securitytool.cli --target https://your-target.com --tomcat --output-dir artifacts
```

### DAST Scan — Quick *(for PR checks)*

```powershell
python -m securitytool.cli `
  --target https://your-target.com `
  --dast `
  --scan-mode quick `
  --threshold High `
  --output-dir artifacts
```

### DAST Scan — Deep *(for nightly runs)*

```powershell
python -m securitytool.cli `
  --target https://your-target.com `
  --dast `
  --scan-mode deep `
  --threshold High `
  --max-high 0 `
  --max-medium 3 `
  --output-dir artifacts
```

### Full Scan *(Tomcat + DAST + Discovery)*

```powershell
python -m securitytool.cli `
  --target https://your-target.com `
  --tomcat `
  --dast `
  --discover `
  --output-dir artifacts
```

### Using a Config File

```powershell
python -m securitytool.cli --config configs/deep_scan.json --tomcat --dast
```

---

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | Base URL of the target application | — |
| `--config` | Path to JSON/YAML config file | — |
| `--scan-mode` | `quick` (PR checks) or `deep` (nightly) | `quick` |
| `--threshold` | Minimum severity for CI gate failure | `High` |
| `--fail-on` | Alias for `--threshold` | — |
| `--max-high` | Max High findings allowed (0 = none) | `0` |
| `--max-medium` | Max Medium findings (-1 = unlimited) | `-1` |
| `--max-duration-minutes` | ZAP active scan time limit | `30` |
| `--non-destructive` | Safe mode — low aggression payloads | `true` |
| `--output-dir` | Report output directory | `artifacts` |
| `--report-format` | Comma-separated: `json,html,csv` | `json,html,csv` |
| `--tomcat` | Run Tomcat hardening checks | off |
| `--dast` | Run DAST scan via ZAP | off |
| `--discover` | Run endpoint discovery crawl | off |
| `--include` | URL patterns to include in scan scope | — |
| `--exclude` | URL patterns to exclude from scan scope | — |
| `--auth-type` | Auth method: `form`, `token`, `basic` | — |
| `--auth-login-url` | Login URL for form-based auth | — |
| `--auth-username-field` | Login form username field name | `username` |
| `--auth-password-field` | Login form password field name | `password` |

---

## Architecture

Aysal Shield is a modular Python CLI platform. Each module is independently testable and replaceable.

```
Security-Tool-V1.1/
├── .github/
│   └── workflows/
│       └── security-scan.yml       ← GitHub Actions pipeline
├── artifacts/                      ← scan reports (git ignored, auto-created)
├── configs/
│   ├── dev.json                    ← quick scan config
│   └── deep_scan.json              ← deep scan config
├── docs/
│   ├── README.md
│   ├── RUNBOOK.md
│   ├── ARCHITECTURE.md
│   ├── AUTH_SETUP.md
│   ├── CONFIG_REFERENCE.md
│   ├── EXTENSIBILITY.md
│   └── KNOWN_LIMITATIONS.md
├── securitytool/
│   ├── cli.py                      ← entry point & argument parsing
│   ├── config.py                   ← config load/validate (YAML/JSON)
│   ├── utils.py                    ← PII redaction, logging utilities
│   ├── interactive.py              ← interactive menu
│   ├── ci/
│   │   └── thresholds.py           ← CI gate: fail conditions & exit codes
│   ├── dast/
│   │   ├── zaprunner.py            ← ZAP daemon lifecycle & scan execution
│   │   └── parsers.py              ← normalize ZAP output → internal schema
│   ├── discovery/
│   │   ├── crawler.py              ← unauthenticated + authenticated crawl
│   │   └── inventory.py            ← endpoint inventory builder
│   ├── reporting/
│   │   ├── jsonreport.py           ← machine-readable JSON report
│   │   ├── htmlreport.py           ← human-readable HTML report
│   │   └── csvexport.py            ← management summary CSV
│   └── tomcat/
│       ├── headerscheck.py         ← HTTP security headers
│       ├── baselinecheck.py        ← default apps, TRACE, TLS, banners
│       └── webxmlcheck.py          ← session timeout, security constraints
├── requirements.txt
├── README.md
├── .pre-commit-config..yml
├── azure-pipelines.yml
├── pyproject.toml
└── gitlab-ci.yml
```

### Data Flow

```
Target URL
    │
    ▼
┌─────────────┐      ┌──────────────┐      ┌──────────────────┐
│  Discovery  │────▶│  DAST Runner │────▶│ Parser/Normalize │
│  Crawler    │      │  (ZAP)       │      │ Dedup + Severity │
└─────────────┘      └──────────────┘      └─────────┬────────┘
                                                    │
┌─────────────┐                                     ▼
│   Tomcat    │                           ┌──────────────────┐
│  Hardening  │─────────────────────────▶│   Reporting      │
│  Scanner    │                           │ JSON / HTML / CSV│
└─────────────┘                           └────────┬─────────┘
                                                   │
                                                   ▼
                                         ┌─────────────────┐
                                         │   CI/CD Gate    │
                                         │ Pass / Fail ≥ X │
                                         └─────────────────┘
```
---

## Reports

All reports are written to `artifacts/` (auto-created at runtime):

| File | Format | Audience |
|------|--------|----------|
| `security_report_<timestamp>.html` | HTML | Developers, security engineers |
| `security_report_<timestamp>.json` | JSON | SIEM, downstream tooling |
| `security_report_<timestamp>.csv` | CSV with executive summary | Management, compliance |
| `discovery_inventory_<timestamp>.json` | JSON | Security engineers |

### Severity Levels

| Level | Meaning | CI Gate Action |
|-------|---------|----------------|
| 🔴 Critical | Confirmed high-impact (SQLi, RCE) | Fail immediately |
| 🟠 High | High-risk finding | Fail pipeline |
| 🟡 Medium | Medium-risk finding | Warning (configurable) |
| 🔵 Low | Low-risk finding | Informational |
| ⚪ Informational | No direct risk | No action |

---

## What Gets Tested

### DAST Coverage (via OWASP ZAP)
- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Path Traversal
- Server-Side Request Forgery (SSRF)
- Open Redirect
- Sensitive Information Disclosure

### Tomcat Hardening Checks
- HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Default application exposure (`/manager`, `/host-manager`)
- Server banner suppression
- TRACE method disabled
- TLS version and cipher suite validation
- Session cookie flags (HttpOnly, Secure)
- Security constraints and transport guarantee
- Error page information disclosure

---

## CI/CD Integration

### GitHub Actions

The pipeline runs automatically on every PR (quick scan) and nightly on main (deep scan).

```yaml
# .github/workflows/security-scan.yml
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 2 * * *'   # nightly at 2AM
```

Pipeline behavior:
- **PR** → quick scan, fails on any High/Critical finding
- **Nightly** → deep scan, full OWASP policy, artifact upload

### GitLab CI

```yaml
# gitlab-ci.yml included in repo root
```

### Azure DevOps

```yaml
# azure-pipelines.yml included in repo root
```

---

## Security & Compliance

| Rule | Enforcement |
|------|-------------|
| Only scan authorized environments | Config-level scope enforcement |
| Never use production credentials | Pre-commit hook blocks plaintext passwords |
| Secrets via environment variables | `${TEST_USER}` / `${TEST_PASS}` substitution |
| PII redacted from all reports | `redact_pii()` applied to all outputs |
| Critical/High findings → security channel | Threshold gate + non-zero exit code |
| Reports are internal-confidential | Access controls apply |

---

## Documentation

| Document | Description |
|----------|-------------|
| [SETUP.md](SETUP.md) | Installation and setup for Windows & Linux |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Operational runbook — scanning, troubleshooting |
| [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md) | All config parameters, types, and defaults |
| [docs/AUTH_SETUP.md](docs/AUTH_SETUP.md) | Authentication setup (form, token, basic) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module architecture and data flow |
| [docs/EXTENSIBILITY.md](docs/EXTENSIBILITY.md) | How to add new checks, parsers, and formats |
| [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) | Known limitations and workarounds |

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ZAP not found` | ZAP_HOME not set | Set `$env:ZAP_HOME` (Windows) or `export ZAP_HOME` (Linux) |
| `ZAP not ready` after 24 retries | Stale `.homelock` file | Delete `.homelock` from your ZAP home directory |
| `Environment variable not set` | TEST_USER or TEST_PASS missing | Set env vars before running any scan |
| `Got unexpected extra argument` | Space in URL | Wrap URL in quotes: `--target "https://..."` |
| `ModuleNotFoundError` | venv not activated | Run `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Linux) |
| `Spider stuck at 0%` | Target unreachable | Check network connectivity to the target |

---

## Out of Scope

The following are **not** covered by Aysal Shield unless explicitly configured:

- Full Static Application Security Testing (SAST)
- Malware and binary scanning
- Infrastructure or network penetration testing
- Destructive or availability-impacting testing
- Production environment scanning *(requires separate written sign-off)*

---

**Aysal Shield** — Enterprise Web Application Security Automation Platform

v0.1.0 | Developed by Neeraj Mudunuru | Confidentialdiscovery/
│  │  ├─ crawler.py          # unauth + auth crawl
│  │  └─ inventory.py        # endpoints, params, roles
│  ├─ tomcat/
│  │  ├─ headerscheck.py    # security headers
│  │  ├─ baselinecheck.py   # default apps, TRACE, TLS, banners
│  │  └─ webxmlcheck.py     # session timeout, constraints (if accessible)
│  ├─ dast/
│  │  ├─ zaprunner.py       # start daemon, context, scan policies
│  │  └─ parsers.py          # normalize ZAP output → internal schema
│  ├─ reporting/
│  │  ├─ jsonreport.py
│  │  ├─ htmlreport.py
│  │  └─ csvexport.py
│  └─ ci/
│     └─ thresholds.py       # fail conditions
├─ configs/
│  ├─ dev.json
│  └─ deep_scan.json
├─ docs/
│  ├─ README.md
│  ├─ RUNBOOK.md
│  └─ ARCHITECTURE.md
└─ .github/workflows/security-scan.yml
________________________________________
