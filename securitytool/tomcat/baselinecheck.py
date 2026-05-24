import requests
import logging
import urllib3
import ssl
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

DEFAULT_APPS = ["/manager", "/host-manager", "/manager/html", "/manager/status"]

# Weak TLS versions
WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

# Weak ciphers (partial match check)
WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "NULL", "EXPORT", "ADH", "ANON", "MD5"]


def detect_tomcat(target: str) -> dict:
    indicators = []
    is_tomcat = False

    try:
        response = requests.get(target, timeout=10, verify=False)
        server_header = response.headers.get("Server", "").lower()
        powered_by = response.headers.get("X-Powered-By", "").lower()
        body = response.text.lower()

        if "tomcat" in server_header:
            indicators.append(f"Server header: {server_header}")
            is_tomcat = True
        if "tomcat" in powered_by:
            indicators.append(f"X-Powered-By: {powered_by}")
            is_tomcat = True
        if "apache tomcat" in body:
            indicators.append("Tomcat default page content found")
            is_tomcat = True

        # Check manager endpoint
        manager_resp = requests.get(
            target.rstrip("/") + "/manager",
            timeout=5, verify=False, allow_redirects=False
        )
        if manager_resp.status_code in (200, 401, 403):
            indicators.append(f"/manager endpoint responded: HTTP {manager_resp.status_code}")
            is_tomcat = True

    except requests.exceptions.RequestException:
        pass

    return {
        "is_tomcat": is_tomcat,
        "confidence": "High" if len(indicators) > 1 else ("Low" if indicators else "None"),
        "indicators": indicators,
    }


def check_tls(target: str) -> dict:
    if not target.startswith("https://"):
        return {
            "check": "TLS Configuration",
            "status": "SKIP",
            "evidence": "Target is not HTTPS — TLS check skipped",
        }

    try:
        parsed = target.replace("https://", "").split("/")[0]
        hostname, _, port_str = parsed.partition(":")
        port = int(port_str) if port_str else 443

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else ""
                cipher_bits = cipher[2] if cipher else 0

                issues = []
                if tls_version in WEAK_TLS_VERSIONS:
                    issues.append(f"Weak TLS version: {tls_version}")
                for keyword in WEAK_CIPHER_KEYWORDS:
                    if keyword in cipher_name.upper():
                        issues.append(f"Weak cipher: {cipher_name}")
                        break
                if cipher_bits and cipher_bits < 128:
                    issues.append(f"Cipher strength too low: {cipher_bits} bits")

                status = "FAIL" if issues else "PASS"
                evidence = (
                    f"Protocol: {tls_version} | Cipher: {cipher_name} | "
                    f"Strength: {cipher_bits} bits"
                )
                if issues:
                    evidence += " | Issues: " + "; ".join(issues)

                return {"check": "TLS Configuration", "status": status, "evidence": evidence}

    except ssl.SSLError as e:
        return {"check": "TLS Configuration", "status": "FAIL", "evidence": f"SSL Error: {e}"}
    except Exception as e:
        return {"check": "TLS Configuration", "status": "ERROR", "evidence": str(e)}


def check_default_apps(target: str) -> list:
    results = []
    for path in DEFAULT_APPS:
        url = target.rstrip("/") + path
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=False)
            # 404 / 403 = good (absent or access-controlled)
            accessible = response.status_code not in (404, 403, 401)
            results.append({
                "check": f"Default App: {path}",
                "status": "FAIL" if accessible else "PASS",
                "evidence": f"HTTP {response.status_code} at {url}",
            })
        except requests.exceptions.RequestException as e:
            results.append({"check": f"Default App: {path}", "status": "ERROR", "evidence": str(e)})
    return results


def check_trace_method(target: str) -> dict:
    try:
        response = requests.request("TRACE", target, timeout=10, verify=False)
        enabled = response.status_code == 200
        return {
            "check": "TRACE Method Disabled",
            "status": "FAIL" if enabled else "PASS",
            "evidence": f"HTTP {response.status_code}",
        }
    except requests.exceptions.RequestException as e:
        return {"check": "TRACE Method Disabled", "status": "ERROR", "evidence": str(e)}


def check_server_banner(target: str) -> dict:
    try:
        response = requests.get(target, timeout=10, verify=False)
        server_header = response.headers.get("Server", "")
        exposed = any(
            kw in server_header.lower()
            for kw in ("tomcat", "apache", "coyote", "jboss", "jetty", "version", "/")
        )
        return {
            "check": "Server Banner Suppression",
            "status": "FAIL" if exposed else "PASS",
            "evidence": f"Server: {server_header or 'Not present'}",
        }
    except requests.exceptions.RequestException as e:
        return {"check": "Server Banner Suppression", "status": "ERROR", "evidence": str(e)}


def check_http_methods(target: str) -> list:
    """Check for enabled dangerous HTTP methods beyond TRACE."""
    results = []
    dangerous_methods = ["PUT", "DELETE", "CONNECT", "PATCH"]
    for method in dangerous_methods:
        try:
            response = requests.request(method, target, timeout=10, verify=False)
            # 405 = method not allowed (good); 200/201/204 = method allowed (bad)
            allowed = response.status_code not in (405, 501, 403, 404, 400) 
            results.append({
                "check": f"HTTP Method {method} Disabled",
                "status": "FAIL" if allowed else "PASS",
                "evidence": f"HTTP {response.status_code}",
            })
        except requests.exceptions.RequestException as e:
            results.append({
                "check": f"HTTP Method {method} Disabled",
                "status": "ERROR",
                "evidence": str(e),
            })
    return results


def run_baseline_checks(target: str) -> dict:
    results = []

    tomcat_detection = detect_tomcat(target)
    logger.info("Tomcat detection", extra={
        "is_tomcat": tomcat_detection["is_tomcat"],
        "confidence": tomcat_detection["confidence"],
    })

    results.append({
        "check": "Tomcat Detection",
        "status": "PASS" if tomcat_detection["is_tomcat"] else "INFO",
        "evidence": (
            f"Confidence: {tomcat_detection['confidence']} | "
            f"Indicators: {', '.join(tomcat_detection['indicators']) or 'None found'}"
        ),
    })

    results.extend(check_default_apps(target))
    results.append(check_trace_method(target))
    results.append(check_server_banner(target))
    results.append(check_tls(target))
    results.extend(check_http_methods(target))

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
        "results": results,
    }
