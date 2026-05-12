import requests
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import ssl
import socket

def detect_tomcat(target: str) -> dict:
    tomcat_indicators = []
    is_tomcat = False

    try:
        response = requests.get(target, timeout=10, verify=False)
        server_header = response.headers.get("Server", "").lower()
        powered_by = response.headers.get("X-Powered-By", "").lower()
        body = response.text.lower()

        if "tomcat" in server_header:
            tomcat_indicators.append(f"Server header: {server_header}")
            is_tomcat = True

        if "tomcat" in powered_by:
            tomcat_indicators.append(f"X-Powered-By: {powered_by}")
            is_tomcat = True

        if "apache tomcat" in body or "tomcat" in body:
            tomcat_indicators.append("Tomcat references found in page body")
            is_tomcat = True

        manager_response = requests.get(
            target.rstrip("/") + "/manager",
            timeout=5, verify=False
        )
        if manager_response.status_code in [200, 401, 403]:
            tomcat_indicators.append(f"Tomcat manager endpoint responded: HTTP {manager_response.status_code}")
            is_tomcat = True

    except requests.exceptions.RequestException:
        pass

    return {
        "is_tomcat": is_tomcat,
        "confidence": "High" if len(tomcat_indicators) > 1 else "Low" if tomcat_indicators else "None",
        "indicators": tomcat_indicators
    }

def check_tls(target: str) -> dict:
    if not target.startswith("https://"):
        return {
            "check": "TLS Configuration",
            "status": "SKIP",
            "evidence": "Target is not HTTPS — TLS check skipped"
        }

    try:
        hostname = target.replace("https://", "").split("/")[0]
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

                weak_versions = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
                is_weak = tls_version in weak_versions

                return {
                    "check": "TLS Configuration",
                    "status": "FAIL" if is_weak else "PASS",
                    "evidence": f"Protocol: {tls_version} | Cipher: {cipher[0]} | Strength: {cipher[2]} bits"
                }

    except ssl.SSLError as e:
        return {
            "check": "tls_configuration",
            "status": "FAIL",
            "evidence": f"SSL Error: {str(e)}"
        }
    except Exception as e:
        return {
            "check": "TLS Configuration",
            "status": "ERROR",
            "evidence": str(e)
        }

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

    tomcat_detection = detect_tomcat(target)
    logger.info("Tomcat detection", extra={
        "is_tomcat": tomcat_detection["is_tomcat"],
        "confidence": tomcat_detection["confidence"],
        "indicators": tomcat_detection["indicators"]
    })

    results.append({
        "check": "Tomcat Detection",
        "status": "PASS" if tomcat_detection["is_tomcat"] else "INFO",
        "evidence": f"Confidence: {tomcat_detection['confidence']} | Indicators: {', '.join(tomcat_detection['indicators']) if tomcat_detection['indicators'] else 'No Tomcat indicators found — checks may not apply'}"
    })

    results.extend(check_default_apps(target))
    results.append(check_trace_method(target))
    results.append(check_server_banner(target))
    results.append(check_tls(target))

    for r in results:
        logger.info("Baseline check", extra=r)

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")

    return {
        "module": "baseline_check",
        "target": target,
        "tomcat_detected": tomcat_detection["is_tomcat"],
        "tomcat_confidence": tomcat_detection["confidence"],
        "summary": {"passed": passed, "failed": failed, "total": len(results)},
        "results": results
    }