# Severity tiers: Informational / Low / Medium / High / Critical
# ZAP riskcode:  0=Informational, 1=Low, 2=Medium, 3=High
# Critical is promoted post-processing for confirmed high-confidence, high-impact findings.

SEVERITY_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",  # reserved for future ZAP versions or manual promotion
}

# Plugin IDs whose confirmed findings are promoted to Critical severity
CRITICAL_PLUGIN_IDS = {
    "90019",  # Server Side Code Injection
    "40018",  # SQL Injection
    "20018",  # Remote OS Command Injection
    "90020",  # Remote File Inclusion
    "40014",  # Cross Site Scripting (Persistent)
}

# Name-based severity override — ZAP sometimes returns riskcode 0 for confirmed
# high-severity findings due to alertthreshold filtering or internal ZAP behaviour.
# This map ensures correct severity is assigned regardless of riskcode returned.
# Rule: only UPGRADE severity, never downgrade.
NAME_SEVERITY_OVERRIDE = {
    "sql injection": "High",
    "blind sql injection": "High",
    "sql injection - mysql": "High",
    "sql injection - sqlite": "High",
    "sql injection - hypersonic sql": "High",
    "sql injection - mssql": "High",
    "sql injection - postgresql": "High",
    "cross site scripting (reflected)": "High",
    "cross site scripting (persistent)": "High",
    "cross site scripting (stored)": "High",
    "cross site scripting (dom based)": "High",
    "persistent cross-site scripting": "High",
    "remote os command injection": "Critical",
    "remote code execution": "Critical",
    "server side code injection": "Critical",
    "server side template injection": "Critical",
    "path traversal": "High",
    "directory traversal": "High",
    "remote file inclusion": "Critical",
    "local file inclusion": "High",
    "server side request forgery": "High",
    "ssrf": "High",
    "xml external entity injection": "High",
    "xxe injection": "High",
    "open redirect": "Medium",
    "external redirect": "Medium",
    "cross-site request forgery": "Medium",
    "absence of anti-csrf tokens": "Medium",
    "csrf": "Medium",
    "directory browsing": "Medium",
    "source code disclosure": "Medium",
    "information disclosure - database error messages": "Medium",
    "heartbleed openssl vulnerability": "Critical",
    "padding oracle": "High",
    "integer overflow error": "Medium",
    "insecure deserialization": "High",
    "ldap injection": "High",
    "xpath injection": "High",
    "http response splitting": "Medium",
    "http parameter pollution": "Medium",
}

# OWASP Top 10 (2021) reference base URL
OWASP_REFERENCE_BASE = "https://owasp.org/Top10/"

# CWE-to-OWASP-category rough mapping for enrichment
CWE_TO_OWASP = {
    "79": "A03_2021-Injection",
    "89": "A03_2021-Injection",
    "78": "A03_2021-Injection",
    "22": "A01_2021-Broken_Access_Control",
    "285": "A01_2021-Broken_Access_Control",
    "918": "A10_2021-Server-Side_Request_Forgery",
    "601": "A01_2021-Broken_Access_Control",
    "200": "A02_2021-Cryptographic_Failures",
    "311": "A02_2021-Cryptographic_Failures",
    "326": "A02_2021-Cryptographic_Failures",
    "16": "A05_2021-Security_Misconfiguration",
    "693": "A05_2021-Security_Misconfiguration",
}

# Severity order used for comparisons throughout this module
SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


def _owasp_link(cweid: str) -> str:
    """Return a clean OWASP Top 10 URL for a given CWE ID, or empty string."""
    category = CWE_TO_OWASP.get(str(cweid), "")
    if category:
        return f"{OWASP_REFERENCE_BASE}{category}/"
    return ""


def _apply_name_override(alert_name: str, current_severity: str) -> str:
    """
    Check the alert name against NAME_SEVERITY_OVERRIDE and upgrade severity
    if the override is higher. Never downgrades.
    """
    name_lower = alert_name.lower()
    for known_name, override_sev in NAME_SEVERITY_OVERRIDE.items():
        if known_name in name_lower:
            current_idx = SEVERITY_ORDER.index(current_severity) if current_severity in SEVERITY_ORDER else 0
            override_idx = SEVERITY_ORDER.index(override_sev) if override_sev in SEVERITY_ORDER else 0
            if override_idx > current_idx:
                return override_sev
            break
    return current_severity


def _promote_severity(alert: dict, mapped_severity: str) -> str:
    """Promote High findings to Critical for specific high-confidence plugin IDs."""
    if mapped_severity == "High":
        plugin_id = str(alert.get("pluginId", alert.get("sourceid", "")))
        confidence = str(alert.get("confidence", "")).lower()
        if plugin_id in CRITICAL_PLUGIN_IDS and confidence in ("high", "confirmed"):
            return "Critical"
    return mapped_severity


def normalize_alerts(raw_alerts: list) -> list:
    """
    Normalize raw ZAP alert dicts into the internal finding schema.
    Deduplicates by (url, param, pluginId).
    Enriches with OWASP reference links and Critical promotion.

    Severity resolution order:
      1. Map riskcode via SEVERITY_MAP
      2. Apply name-based override (only upgrades)
      3. Apply Critical promotion for confirmed high-impact plugin IDs
    """
    seen = set()
    normalized = []

    for alert in raw_alerts:
        key = (
            alert.get("url", ""),
            alert.get("param", ""),
            alert.get("pluginId", alert.get("sourceid", "")),
        )
        if key in seen:
            continue
        seen.add(key)

        # Step 1: riskcode → severity
        raw_severity = str(alert.get("riskcode", "0"))
        severity = SEVERITY_MAP.get(raw_severity, "Informational")

        # Step 2: name-based override (fixes ZAP returning riskcode 0 for
        # confirmed SQLi/XSS due to alertthreshold or internal ZAP behaviour)
        alert_name = alert.get("name", "")
        severity = _apply_name_override(alert_name, severity)

        # Step 3: Critical promotion for confirmed high-impact plugin IDs
        severity = _promote_severity(alert, severity)

        cweid = str(alert.get("cweid", ""))
        owasp_link = _owasp_link(cweid)

        # Build enriched reference: ZAP reference text + OWASP link
        raw_ref = alert.get("reference", "").strip()
        references = [r for r in [raw_ref, owasp_link] if r]

        normalized.append({
            "name": alert_name,
            "severity": severity,
            "url": alert.get("url", ""),
            "parameter": alert.get("param", ""),
            "evidence": alert.get("evidence", ""),
            "description": alert.get("desc", "").strip(),
            "solution": alert.get("solution", "").strip(),
            "reference": "\n".join(references),
            "owasp_link": owasp_link,
            "cweid": cweid,
            "wascid": str(alert.get("wascid", "")),
            "plugin_id": str(alert.get("pluginId", alert.get("sourceid", ""))),
            "confidence": alert.get("confidence", ""),
        })

    return normalized


def group_findings(findings: list) -> list:
    """Group deduplicated findings by vulnerability name, sorted by severity."""
    groups = {}

    for finding in findings:
        name = finding["name"]
        if name not in groups:
            groups[name] = {
                "name": name,
                "severity": finding["severity"],
                "description": finding["description"],
                "solution": finding["solution"],
                "reference": finding["reference"],
                "owasp_link": finding.get("owasp_link", ""),
                "cweid": finding.get("cweid", ""),
                "affected_urls": [],
                "count": 0,
            }
        groups[name]["affected_urls"].append({
            "url": finding["url"],
            "parameter": finding["parameter"],
            "evidence": finding["evidence"],
        })
        groups[name]["count"] += 1

    return sorted(
        list(groups.values()),
        key=lambda x: SEVERITY_ORDER.index(x["severity"]) if x["severity"] in SEVERITY_ORDER else 99,
        reverse=True,
    )


def calculate_risk_score(findings: list) -> dict:
    severity_weights = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1,
        "Informational": 0,
    }

    counts = {s: 0 for s in severity_weights}

    for f in findings:
        severity = f.get("severity", "Informational")
        if severity in counts:
            counts[severity] += 1

    total_weight = sum(severity_weights[s] * counts[s] for s in counts)
    max_possible = len(findings) * 10 if findings else 1
    risk_score = round((total_weight / max_possible) * 10, 1) if findings else 0.0

    return {
        "counts": counts,
        "risk_score": risk_score,
        "total_unique": len(findings),
    }