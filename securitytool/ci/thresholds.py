import logging
import sys

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


def check_thresholds(
    findings: list,
    fail_on: str = "High",
    max_high: int = 0,
    max_medium: int = -1,
    max_critical: int = 0,
) -> dict:
    """
    Evaluate findings against configured thresholds.

    Args:
        findings:     List of normalized finding dicts.
        fail_on:      Minimum severity that triggers a failure (e.g. "High").
        max_high:     Maximum allowed High findings (0 = none allowed; -1 = unlimited).
        max_medium:   Maximum allowed Medium findings (-1 = unlimited).
        max_critical: Maximum allowed Critical findings (0 = none allowed; -1 = unlimited).

    Returns:
        dict with keys: passed (bool), severity_counts (dict), breaches (list[str])
    """
    severity_counts = {s: 0 for s in SEVERITY_ORDER}

    for finding in findings:
        severity = finding.get("severity", "Informational")
        if severity in severity_counts:
            severity_counts[severity] += 1

    breaches = []

    # fail_on: anything at or above this severity level triggers failure
    if fail_on in SEVERITY_ORDER:
        fail_index = SEVERITY_ORDER.index(fail_on)
        for severity in SEVERITY_ORDER[fail_index:]:
            count = severity_counts[severity]
            if count > 0:
                breaches.append(f"{count} {severity} finding(s) detected (threshold: fail_on={fail_on})")

    # Explicit count caps
    if max_critical >= 0 and severity_counts["Critical"] > max_critical:
        breaches.append(
            f"Critical count {severity_counts['Critical']} exceeds max_critical={max_critical}"
        )
    if max_high >= 0 and severity_counts["High"] > max_high:
        breaches.append(
            f"High count {severity_counts['High']} exceeds max_high={max_high}"
        )
    if max_medium >= 0 and severity_counts["Medium"] > max_medium:
        breaches.append(
            f"Medium count {severity_counts['Medium']} exceeds max_medium={max_medium}"
        )

    # Deduplicate breach messages
    breaches = list(dict.fromkeys(breaches))
    passed = len(breaches) == 0

    logger.info("Threshold evaluation", extra={
        "passed": passed,
        "counts": severity_counts,
        "breaches": breaches,
        "config": {
            "fail_on": fail_on,
            "max_critical": max_critical,
            "max_high": max_high,
            "max_medium": max_medium,
        },
    })

    return {
        "passed": passed,
        "severity_counts": severity_counts,
        "breaches": breaches,
    }


def enforce_thresholds(threshold_result: dict):
    """Call sys.exit(1) if thresholds were breached. Used as a convenience wrapper."""
    if not threshold_result["passed"]:
        for breach in threshold_result["breaches"]:
            logger.error(f"BREACH: {breach}")
        sys.exit(1)
