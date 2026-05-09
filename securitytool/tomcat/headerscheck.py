import requests
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

REQUIRED_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def check_security_headers(target: str) -> dict:
    results = []

    try:
        response = requests.get(target, timeout=10, verify=False)
        headers = response.headers

        for header in REQUIRED_HEADERS:
            present = header in headers
            result = {
                "check": f"Security Header: {header}",
                "status": "PASS" if present else "FAIL",
                "evidence": headers.get(header, "Header not present")
            }
            results.append(result)
            logger.info(f"Header check", extra=result)

    except requests.exceptions.ConnectionError:
        logger.error("Connection failed", extra={"target": target})
        return {"error": "Could not connect to target", "results": []}
    except requests.exceptions.Timeout:
        logger.error("Request timed out", extra={"target": target})
        return {"error": "Request timed out", "results": []}

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    return {
        "module": "headers_check",
        "target": target,
        "summary": {"passed": passed, "failed": failed, "total": len(results)},
        "results": results
    }