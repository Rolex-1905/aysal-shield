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


def _owasp_link(cweid: str) -> str:
    """Return a clean OWASP Top 10 URL for a given CWE ID, or empty string."""
    category = CWE_TO_OWASP.get(str(cweid), "")
    if category:
        return f"{OWASP_REFERENCE_BASE}{category}/"
    return ""


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

        raw_severity = str(alert.get("riskcode", "0"))
        severity = SEVERITY_MAP.get(raw_severity, "Informational")
        severity = _promote_severity(alert, severity)

        cweid = str(alert.get("cweid", ""))
        owasp_link = _owasp_link(cweid)

        # Build enriched reference: ZAP reference text + OWASP link
        raw_ref = alert.get("reference", "").strip()
        references = [r for r in [raw_ref, owasp_link] if r]

        normalized.append({
            "name": alert.get("name", ""),
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

    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    return sorted(
        list(groups.values()),
        key=lambda x: severity_order.index(x["severity"]) if x["severity"] in severity_order else 99
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
