import logging

logger = logging.getLogger(__name__)

def build_inventory(endpoints: list) -> dict:
    inventory = {
        "total": len(endpoints),
        "authenticated": [],
        "unauthenticated": []
    }

    for ep in endpoints:
        if ep.get("auth_required"):
            inventory["authenticated"].append(ep)
        else:
            inventory["unauthenticated"].append(ep)

    logger.info("Inventory built", extra={
        "total": inventory["total"],
        "unauthenticated": len(inventory["unauthenticated"]),
        "authenticated": len(inventory["authenticated"])
    })

    return inventory