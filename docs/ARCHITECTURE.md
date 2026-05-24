# Aysal Shield — Architecture Reference

## 1. Overview

Aysal Shield is a modular Python CLI platform. Each module is independently testable
and replaceable. The tool orchestrates the full DAST lifecycle: authenticated crawl →
Tomcat hardening → active scan → normalization → reporting → CI gate.

## 2. Module Responsibilities

| Module | File | Responsibility |
|--------|------|---------------|
| CLI Entry Point | `cli.py` | Argument parsing, config merging, module orchestration, exit codes |
| Config Loader | `config.py` | JSON/YAML loading, env var resolution (`${VAR}`), required field validation |
| Crawler | `discovery/crawler.py` | BFS crawl, form/basic/token auth, CSRF-aware login, session maintenance |
| Inventory | `discovery/inventory.py` | Endpoint aggregation, auth status tagging, JSON persistence |
| Headers Check | `tomcat/headerscheck.py` | HTTP security header presence checks (5 headers) |
| Baseline Check | `tomcat/baselinecheck.py` | Default apps, TRACE, server banner, TLS, dangerous HTTP methods |
| Web.xml Check | `tomcat/webxmlcheck.py` | Session cookies, security constraints, transport guarantee, error pages, functional sanity tests |
| ZAP Runner | `dast/zaprunner.py` | ZAP daemon lifecycle, context config, auth setup, spider, active scan, time-boxing |
| Parsers | `dast/parsers.py` | Alert normalization, deduplication, severity promotion, OWASP enrichment, risk scoring |
| JSON Report | `reporting/jsonreport.py` | Machine-readable output with PII redaction |
| HTML Report | `reporting/htmlreport.py` | Human-readable Jinja2 report with executive summary and risk score |
| CSV Export | `reporting/csvexport.py` | Management summary with dual-section structure |
| Thresholds | `ci/thresholds.py` | Severity count evaluation, breach detection, sys.exit(1) gate |
| Interactive TUI | `interactive.py` | Rich terminal UI for non-CLI usage |

## 3. Data Flow
```
CLI Input (flags / config file)
        │
        ▼
Config Load & Validation (config.py)
   - Resolve ${ENV_VAR} substitutions
   - Validate required fields
        │
        ├──► Tomcat Hardening (--tomcat flag)
        │       ├── headerscheck.py   → HTTP GET → header presence
        │       ├── baselinecheck.py  → HTTP GET/TRACE/TLS socket → pass/fail
        │       └── webxmlcheck.py    → HTTP GET/POST → cookie, constraint, functional tests
        │
        ├──► Discovery Crawl (--discover flag)
        │       ├── crawler.py        → BFS crawl → endpoint list
        │       └── inventory.py      → aggregate → discovery_inventory_*.json
        │
        └──► DAST Scan (--dast flag)
                ├── zaprunner.py      → start ZAP daemon
                │                     → create context (include/exclude)
                │                     → configure form auth
                │                     → spider → active scan → alerts[]
                └── parsers.py        → normalize → deduplicate → enrich
                                      → group_findings() → calculate_risk_score()

All results → Unified Report Dict
        │
        ├── jsonreport.py  → artifacts/security_report_*.json
        ├── htmlreport.py  → artifacts/security_report_*.html
        └── csvexport.py   → artifacts/security_report_*.csv
                │
                ▼
        thresholds.py → severity_counts → breaches? → sys.exit(1)
        
``` 
## 4. Interface Contracts

### CLI → Module interface
Every module entry function receives primitive types only (str, bool, int, dict).
No module imports from another module except parsers.py (imported by htmlreport + csvexport).

### Internal finding schema (parsers.py → reporters)
name:        str   — vulnerability name
severity:    str   — Informational | Low | Medium | High | Critical
url:         str   — affected URL
parameter:   str   — affected parameter or header
evidence:    str   — raw snippet from HTTP response
description: str   — full description
solution:    str   — remediation advice
reference:   str   — ZAP reference text + OWASP link (newline-separated)
owasp_link:  str   — direct OWASP Top 10 2021 URL
cweid:       str   — CWE identifier
wascid:      str   — WASC identifier
plugin_id:   str   — ZAP plugin ID
confidence:  str   — ZAP confidence level

### Tomcat hardening result schema (all three tomcat modules → reporters)
check:        str   — human-readable check name
status:       str   — PASS | FAIL | SKIP | N/A | ERROR
evidence:     str   — HTTP evidence (headers, status codes, cookie values)
remediation:  str   — fix guidance (optional; shown in HTML report)

### Threshold result schema (thresholds.py → cli.py)
passed:          bool        — True if no breaches
severity_counts: dict        — {Informational, Low, Medium, High, Critical: int}
breaches:        list[str]   — human-readable breach descriptions

## 5. Error Handling Strategy

| Failure mode | Handling |
|-------------|----------|
| Config file not found | FileNotFoundError → logged → sys.exit(1) |
| Missing env var in config | ValueError → logged → sys.exit(1) |
| Target unreachable (connection error) | Caught per-check → status: ERROR with evidence |
| Request timeout | Caught per-check → status: ERROR with evidence |
| ZAP fails to start | Returns `{"error": "...", "results": []}` → logged → scan skipped |
| ZAP startup timeout (>4 min) | `wait_for_zap()` returns False → ZAP process terminated |
| Active scan exceeds max_duration | `zap.ascan.stop()` called → results collected from completed portion |
| ZAP API exception mid-scan | Caught in outer try/except → error logged → ZAP shut down in finally |
| Report write failure | Exception propagates → logged → non-zero exit |

## 6. Security Guardrails

- **Secrets**: All credentials sourced from environment variables. `config.py` resolves `${VAR}` at load time. Pre-commit hook (detect-secrets) blocks hardcoded credentials.
- **PII redaction**: `utils.redact_pii()` applied to all string values before writing any log or report output.
- **Scope enforcement**: Include/exclude URL patterns enforced at ZAP context level. Out-of-scope URLs not spidered or scanned.
- **Non-destructive default**: `non_destructive=True` sets ZAP attack strength to LOW. Destructive payloads require explicit `--destructive` override.
- **Production guard**: `configs/` only contains Dev/QA targets. Production scanning requires separate config with explicit sign-off.