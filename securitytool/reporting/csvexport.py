import csv
import os
from datetime import datetime

def save_csv_report(data: dict, output_dir: str = "artifacts") -> str:
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)

    rows = []

    for module in data.get("tomcat_hardening", []):
        for result in module.get("results", []):
            rows.append({
                "type": "Tomcat Hardening",
                "module": module.get("module", "unknown"),
                "check": result.get("check", ""),
                "status": result.get("status", ""),
                "severity": "",
                "url": module.get("target", ""),
                "evidence": result.get("evidence", "")
            })

    for finding in data.get("dast_scan", {}).get("findings", []):
        rows.append({
            "type": "DAST Finding",
            "module": "dast_scan",
            "check": finding.get("name", ""),
            "status": "",
            "severity": finding.get("severity", ""),
            "url": finding.get("url", ""),
            "evidence": finding.get("evidence", "")
        })

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "type", "module", "check", "status", "severity", "url", "evidence"
        ])
        writer.writeheader()
        writer.writerows(rows)

    return filepath