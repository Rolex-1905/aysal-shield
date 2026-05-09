import json
import os
from datetime import datetime

def save_json_report(data: dict, output_dir: str = "artifacts") -> str:
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if "dast_scan" in data and "tomcat_hardening" in data:
        prefix = "security_report"
    elif "dast_scan" in data:
        prefix = "dast_report"
    else:
        prefix = "tomcat_hardening"

    filename = f"{prefix}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    report = {
        "tool": "TomcatShield",
        "version": "1.0.0",
        "generated_at": datetime.now().isoformat(),
        "report": data
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)

    return filepath