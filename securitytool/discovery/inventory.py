import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def build_inventory(endpoints: list) -> dict:
    inventory = {
        "total": len(endpoints),
        "authenticated": [],
        "unauthenticated": [],
        "forms_found": 0,
        "parameters_found": 0,
        "status_codes": {}
    }

    for ep in endpoints:
        status = str(ep.get("status_code", "unknown"))
        inventory["status_codes"][status] = inventory["status_codes"].get(status, 0) + 1
        inventory["forms_found"] += len(ep.get("forms", []))
        inventory["parameters_found"] += len(ep.get("parameters", []))

        if ep.get("auth_required") or ep.get("authenticated"):
            inventory["authenticated"].append(ep)
        else:
            inventory["unauthenticated"].append(ep)

    logger.info("Inventory built", extra={
        "total": inventory["total"],
        "unauthenticated": len(inventory["unauthenticated"]),
        "authenticated": len(inventory["authenticated"]),
        "forms": inventory["forms_found"]
    })

    return inventory


def save_inventory(inventory: dict, output_dir: str = "artifacts") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"discovery_inventory_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump({
            "tool": "Aysal_Shield",
            "generated_at": datetime.now().isoformat(),
            "inventory": inventory
        }, f, indent=2)

    logger.info("Inventory saved", extra={"path": filepath})
    return filepath