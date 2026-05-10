SEVERITY_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High"
}

def normalize_alerts(raw_alerts: list) -> list:
    seen = set()
    normalized = []

    for alert in raw_alerts:
        key = (
            alert.get("url", ""),
            alert.get("param", ""),
            alert.get("pluginId", "")
        )
        if key in seen:
            continue
        seen.add(key)

        normalized.append({
            "name": alert.get("name", ""),
            "severity": SEVERITY_MAP.get(str(alert.get("riskcode", "0")), "Informational"),
            "url": alert.get("url", ""),
            "parameter": alert.get("param", ""),
            "evidence": alert.get("evidence", ""),
            "description": alert.get("desc", "").strip(),
            "solution": alert.get("solution", "").strip(),
            "reference": alert.get("reference", ""),
            "cweid": alert.get("cweid", ""),
            "wascid": alert.get("wascid", "")
        })

    return normalized


def group_findings(findings: list) -> list:
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
                "cweid": finding.get("cweid", ""),
                "affected_urls": [],
                "count": 0
            }
        groups[name]["affected_urls"].append({
            "url": finding["url"],
            "parameter": finding["parameter"],
            "evidence": finding["evidence"]
        })
        groups[name]["count"] += 1

    return sorted(
        list(groups.values()),
        key=lambda x: ["Critical", "High", "Medium", "Low", "Informational"].index(x["severity"])
    )


def calculate_risk_score(findings: list) -> dict:
    severity_weights = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1,
        "Informational": 0
    }

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    for f in findings:
        severity = f.get("severity", "Informational")
        if severity in counts:
            counts[severity] += 1

    total_weight = sum(
        severity_weights[sev] * count
        for sev, count in counts.items()
    )

    max_possible = len(findings) * 10 if findings else 1
    risk_score = round((total_weight / max_possible) * 10, 1) if findings else 0.0

    return {
        "counts": counts,
        "risk_score": risk_score,
        "total_unique": len(findings)
    }