# Aysal Shield — Extensibility Guide

This guide explains how to add new scan checks, parsers, and report formats without modifying core modules.

---

## Adding a new Tomcat hardening check

All Tomcat checks live in `securitytool/tomcat/`. Each check function returns a list of result dicts with these keys:

```python
{
    "check": str,          # Human-readable check name
    "status": str,         # "PASS" | "FAIL" | "SKIP" | "N/A" | "ERROR"
    "evidence": str,       # What was observed (HTTP response, header value, etc.)
    "remediation": str,    # How to fix it (shown in HTML report)
}
```

### Step 1 — Write the check function

Create or edit a file in `securitytool/tomcat/`. Example — adding a check for the `X-Permitted-Cross-Domain-Policies` header:

```python
# securitytool/tomcat/headerscheck.py

def check_cross_domain_policy(target: str) -> dict:
    try:
        response = requests.get(target, timeout=10, verify=False)
        header = response.headers.get("X-Permitted-Cross-Domain-Policies", "")
        present = bool(header)
        return {
            "check": "X-Permitted-Cross-Domain-Policies Header",
            "status": "PASS" if present else "FAIL",
            "evidence": header or "Header not present",
            "remediation": (
                "Add to Tomcat's web.xml filter or application response:\n"
                "X-Permitted-Cross-Domain-Policies: none"
            ),
        }
    except requests.exceptions.RequestException as e:
        return {"check": "X-Permitted-Cross-Domain-Policies", "status": "ERROR", "evidence": str(e), "remediation": ""}
```

### Step 2 — Register it in the module runner

Add the call inside `run_baseline_checks()` or `check_security_headers()` in the relevant file:

```python
# headerscheck.py — in check_security_headers()
results.append(check_cross_domain_policy(target))
```

### Step 3 — Test it

```bash
python -m securitytool.cli --target http://localhost:8080 --tomcat --output-dir artifacts
cat artifacts/security_report_*.json | python -m json.tool | grep "X-Permitted"
```

---

## Adding a new DAST scan policy

DAST scan policies map human-readable names to ZAP plugin IDs. They live in `securitytool/dast/zaprunner.py`:

```python
OWASP_SCAN_POLICIES = {
    "xss":            ["40012", "40014", "40016", "40017", "40018"],
    "sqli":           ["40018", "40019", "40020", "40021", "40022"],
    # Add your new policy here:
    "xxe":            ["90023"],   # XML External Entity Injection
    "deserialization": ["90001"],  # Insecure Deserialization
}
```

Find ZAP plugin IDs at: https://www.zaproxy.org/docs/alerts/

Once added, reference the policy key in your config:
```json
"scan": {
  "policies": ["xss", "sqli", "xxe", "deserialization"]
}
```

---

## Adding a new parser / normalizer

If you integrate a new scan engine alongside ZAP, add a normalizer in `securitytool/dast/parsers.py`.

Your normalizer must return a list of dicts matching the internal finding schema:

```python
def normalize_my_tool_output(raw_output: list) -> list:
    findings = []
    for item in raw_output:
        findings.append({
            "name":        item["title"],
            "severity":    map_severity(item["severity"]),  # must be Informational/Low/Medium/High/Critical
            "url":         item["url"],
            "parameter":   item.get("parameter", ""),
            "evidence":    item.get("evidence", ""),
            "description": item.get("description", "").strip(),
            "solution":    item.get("solution", "").strip(),
            "reference":   item.get("reference", ""),
            "owasp_link":  "",
            "cweid":       item.get("cwe", ""),
            "wascid":      "",
            "plugin_id":   item.get("rule_id", ""),
            "confidence":  item.get("confidence", ""),
        })
    return findings
```

Then call it from `cli.py` in the DAST section alongside `normalize_alerts()`.

---

## Adding a new report format

Report writers live in `securitytool/reporting/`. To add a new format (e.g. SARIF for GitHub Security):

### Step 1 — Create the writer

```python
# securitytool/reporting/sarifreport.py
import json, os
from datetime import datetime

def save_sarif_report(data: dict, output_dir: str = "artifacts") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"security_report_{timestamp}.sarif")

    findings = data.get("dast_scan", {}).get("findings", [])
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AysalShield", "version": "1.0.0", "rules": []}},
            "results": [
                {
                    "ruleId": f.get("plugin_id", "unknown"),
                    "message": {"text": f.get("description", "")},
                    "level": _sarif_level(f.get("severity", "Informational")),
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("url", "")}}}],
                }
                for f in findings
            ],
        }],
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    return filepath


def _sarif_level(severity: str) -> str:
    return {"Critical": "error", "High": "error", "Medium": "warning",
            "Low": "note", "Informational": "none"}.get(severity, "none")
```

### Step 2 — Register it in cli.py

```python
# In the reporting section of main():
if "sarif" in requested_formats:
    from securitytool.reporting.sarifreport import save_sarif_report
    saved["sarif"] = save_sarif_report(unified, effective_output_dir)
```

### Step 3 — Add "sarif" to --report-format help text in cli.py

```python
@click.option("--report-format", default="json,html,csv",
              help="Output formats (comma-separated): json, html, csv, sarif")
```

---

## Internal data schemas

### Finding schema (normalized DAST output)
```
name: str          — vulnerability name
severity: str      — Informational | Low | Medium | High | Critical
url: str           — affected URL
parameter: str     — affected parameter / header
evidence: str      — raw evidence snippet from the response
description: str   — full vulnerability description
solution: str      — remediation advice from ZAP
reference: str     — raw ZAP reference text + OWASP link
owasp_link: str    — direct OWASP Top 10 URL
cweid: str         — CWE identifier
wascid: str        — WASC identifier
plugin_id: str     — ZAP plugin / scanner ID
confidence: str    — ZAP confidence level
```

### Tomcat hardening result schema
```
check: str         — check name
status: str        — PASS | FAIL | SKIP | N/A | ERROR
evidence: str      — HTTP evidence (headers, status codes)
remediation: str   — how to fix (optional, shown in HTML report)
```
