"""
CSV export — management-facing summary report.

Produces two sections in a single file:
  1. Executive summary row with severity counts and risk score
  2. Per-finding detail rows (Tomcat hardening checks + DAST findings)

Spec §3.6: CSV export: management-facing summary with severity counts.
"""

import csv
import os
from datetime import datetime

from securitytool.dast.parsers import calculate_risk_score


def save_csv_report(data: dict, output_dir: str = "artifacts") -> str:
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)

    # -----------------------------------------------------------------------
    # Collect all detail rows
    # -----------------------------------------------------------------------
    detail_rows = []

    for module in data.get("tomcat_hardening", []):
        for result in module.get("results", []):
            detail_rows.append({
                "section": "Tomcat Hardening",
                "module": module.get("module", "unknown"),
                "check_name": result.get("check", ""),
                "status": result.get("status", ""),
                "severity": _status_to_severity(result.get("status", "")),
                "url": module.get("target", ""),
                "parameter": "",
                "evidence": result.get("evidence", ""),
                "remediation": result.get("remediation", ""),
                "owasp_link": "",
                "cwe_id": "",
            })

    dast_findings = data.get("dast_scan", {}).get("findings", [])
    for finding in dast_findings:
        detail_rows.append({
            "section": "DAST Finding",
            "module": "dast_scan",
            "check_name": finding.get("name", ""),
            "status": "",
            "severity": finding.get("severity", ""),
            "url": finding.get("url", ""),
            "parameter": finding.get("parameter", ""),
            "evidence": finding.get("evidence", ""),
            "remediation": finding.get("solution", ""),
            "owasp_link": finding.get("owasp_link", ""),
            "cwe_id": finding.get("cweid", ""),
        })

    # -----------------------------------------------------------------------
    # Build executive summary
    # -----------------------------------------------------------------------
    risk = calculate_risk_score(dast_findings) if dast_findings else None
    dast_counts = risk["counts"] if risk else {s: 0 for s in ["Critical", "High", "Medium", "Low", "Informational"]}

    tomcat_passed  = sum(1 for r in detail_rows if r["section"] == "Tomcat Hardening" and r["status"] == "PASS")
    tomcat_failed  = sum(1 for r in detail_rows if r["section"] == "Tomcat Hardening" and r["status"] == "FAIL")
    tomcat_total   = sum(1 for r in detail_rows if r["section"] == "Tomcat Hardening")

    fieldnames = [
        "section", "module", "check_name", "status", "severity",
        "url", "parameter", "evidence", "remediation", "owasp_link", "cwe_id",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # -- Executive summary block --
        writer.writerow(["# AysalShield Security Report — Executive Summary"])
        writer.writerow(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow([])
        writer.writerow(["## DAST Finding Counts"])
        writer.writerow(["Critical", "High", "Medium", "Low", "Informational", "Risk Score (/10)"])
        writer.writerow([
            dast_counts.get("Critical", 0),
            dast_counts.get("High", 0),
            dast_counts.get("Medium", 0),
            dast_counts.get("Low", 0),
            dast_counts.get("Informational", 0),
            risk["risk_score"] if risk else "N/A",
        ])
        writer.writerow([])
        writer.writerow(["## Tomcat Hardening Summary"])
        writer.writerow(["Passed", "Failed", "Total Checks"])
        writer.writerow([tomcat_passed, tomcat_failed, tomcat_total])
        writer.writerow([])
        writer.writerow(["## Detail"])

        # -- Detail rows --
        detail_writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        detail_writer.writeheader()
        detail_writer.writerows(detail_rows)

    return filepath


def _status_to_severity(status: str) -> str:
    """Map Tomcat check pass/fail status to an approximate severity for the CSV."""
    return {"FAIL": "Medium", "PASS": "", "ERROR": "Low", "SKIP": "", "N/A": ""}.get(status, "")
