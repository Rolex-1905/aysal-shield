import requests
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

INSECURE_ERROR_PAGES = ["/error", "/500", "/404"]

def check_session_timeout(target: str) -> dict:
    """
    Attempts to infer session timeout by checking session-related headers.
    In a real environment this would parse web.xml directly if accessible.
    """
    try:
        response = requests.get(target, timeout=10, verify=False)
        cookie_header = response.headers.get("Set-Cookie", "")

        has_timeout = "Max-Age" in cookie_header or "Expires" in cookie_header
        has_httponly = "HttpOnly" in cookie_header
        has_secure = "Secure" in cookie_header

        results = [
            {
                "check": "Session Cookie HttpOnly Flag",
                "status": "PASS" if has_httponly else "FAIL",
                "evidence": cookie_header or "No Set-Cookie header found"
            },
            {
                "check": "Session Cookie Secure Flag",
                "status": "PASS" if has_secure else "FAIL",
                "evidence": cookie_header or "No Set-Cookie header found"
            },
            {
                "check": "Session Cookie Timeout Configured",
                "status": "PASS" if has_timeout else "FAIL",
                "evidence": cookie_header or "No Set-Cookie header found"
            }
        ]

        return results

    except requests.exceptions.RequestException as e:
        return [{
            "check": "Session Configuration",
            "status": "ERROR",
            "evidence": str(e)
        }]


def check_error_handling(target: str) -> list:
    results = []

    for path in INSECURE_ERROR_PAGES:
        url = target.rstrip("/") + path
        try:
            response = requests.get(url, timeout=10, verify=False)
            body = response.text.lower()

            exposes_info = any(keyword in body for keyword in [
                "stack trace", "exception", "tomcat", "java.", "at org.", "at com."
            ])

            results.append({
                "check": f"Error Page Info Disclosure: {path}",
                "status": "FAIL" if exposes_info else "PASS",
                "evidence": f"HTTP {response.status_code} — {'Stack trace or server info detected' if exposes_info else 'No sensitive info detected'}"
            })

        except requests.exceptions.RequestException as e:
            results.append({
                "check": f"Error Page Info Disclosure: {path}",
                "status": "ERROR",
                "evidence": str(e)
            })

    return results


def run_webxml_checks(target: str) -> dict:
    results = []

    results.extend(check_session_timeout(target))
    results.extend(check_error_handling(target))

    for r in results:
        logger.info("Web.xml check", extra=r)

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    return {
        "module": "webxml_check",
        "target": target,
        "summary": {"passed": passed, "failed": failed, "total": len(results)},
        "results": results
    }