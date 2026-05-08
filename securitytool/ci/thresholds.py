import logging

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

def check_thresholds(findings: list, fail_on: str = "High", max_high: int = 0, max_medium: int = -1) -> dict:
    severity_counts = {
        "Informational": 0,
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")
        if severity in severity_counts:
            severity_counts[severity] += 1

    breaches = []

    fail_on_index = SEVERITY_ORDER.index(fail_on) if fail_on in SEVERITY_ORDER else 3
    for severity in SEVERITY_ORDER[fail_on_index:]:
        if severity_counts[severity] > 0:
            breaches.append(f"{severity_counts[severity]} {severity} finding(s) found")

    if max_high >= 0 and severity_counts["High"] > max_high:
        breaches.append(f"High findings {severity_counts['High']} exceeds max allowed {max_high}")

    if max_medium >= 0 and severity_counts["Medium"] > max_medium:
        breaches.append(f"Medium findings {severity_counts['Medium']} exceeds max allowed {max_medium}")

    passed = len(breaches) == 0

    logger.info("Threshold check", extra={
        "passed": passed,
        "counts": severity_counts,
        "breaches": breaches
    })

    return {
        "passed": passed,
        "severity_counts": severity_counts,
        "breaches": breaches
    }