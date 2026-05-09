import requests
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

DEFAULT_APPS = ["/manager", "/host-manager"]

def check_default_apps(target: str) -> list:
    results = []

    for path in DEFAULT_APPS:
        url = target.rstrip("/") + path
        try:
            response = requests.get(url, timeout=10, verify=False)
            accessible = response.status_code not in [404, 403]
            results.append({
                "check": f"Default App: {path}",
                "status": "FAIL" if accessible else "PASS",
                "evidence": f"HTTP {response.status_code} at {url}"
            })
        except requests.exceptions.RequestException as e:
            results.append({
                "check": f"Default App: {path}",
                "status": "ERROR",
                "evidence": str(e)
            })

    return results


def check_trace_method(target: str) -> dict:
    try:
        response = requests.request("TRACE", target, timeout=10, verify=False)
        enabled = response.status_code == 200
        return {
            "check": "TRACE Method Disabled",
            "status": "FAIL" if enabled else "PASS",
            "evidence": f"HTTP {response.status_code}"
        }
    except requests.exceptions.RequestException as e:
        return {
            "check": "TRACE Method Disabled",
            "status": "ERROR",
            "evidence": str(e)
        }


def check_server_banner(target: str) -> dict:
    try:
        response = requests.get(target, timeout=10, verify=False)
        server_header = response.headers.get("Server", "")
        exposed = any(keyword in server_header.lower() 
                     for keyword in ["tomcat", "apache", "version"])
        return {
            "check": "Server Banner Suppression",
            "status": "FAIL" if exposed else "PASS",
            "evidence": f"Server header: {server_header or 'Not present'}"
        }
    except requests.exceptions.RequestException as e:
        return {
            "check": "Server Banner Suppression",
            "status": "ERROR",
            "evidence": str(e)
        }


def run_baseline_checks(target: str) -> dict:
    results = []

    results.extend(check_default_apps(target))
    results.append(check_trace_method(target))
    results.append(check_server_banner(target))

    for r in results:
        logger.info("Baseline check", extra=r)

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    return {
        "module": "baseline_check",
        "target": target,
        "summary": {"passed": passed, "failed": failed, "total": len(results)},
        "results": results
    }