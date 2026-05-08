import csv
import os
from datetime import datetime

def save_csv_report(data: dict, output_dir: str = "artifacts") -> str:
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"tomcat_hardening_{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)

    rows = []
    for module in data.get("tomcat_hardening", []):
        if module.get("error"):
            rows.append({
                "module": "unknown",
                "check": "Connection",
                "status": "ERROR",
                "evidence": module["error"]
            })
        else:
            for result in module.get("results", []):
                rows.append({
                    "module": module.get("module", "unknown"),
                    "check": result.get("check", ""),
                    "status": result.get("status", ""),
                    "evidence": result.get("evidence", "")
                })

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["module", "check", "status", "evidence"])
        writer.writeheader()
        writer.writerows(rows)

    return filepath