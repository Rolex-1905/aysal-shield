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
            "description": alert.get("desc", ""),
            "solution": alert.get("solution", ""),
            "reference": alert.get("reference", "")
        })

    return normalized