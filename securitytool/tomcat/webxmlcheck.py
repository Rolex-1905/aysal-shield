import requests
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

INSECURE_ERROR_PAGES = ["/error", "/500", "/404"]

# Paths that should require authentication (security-constraint proxies)
PROTECTED_PATHS = ["/admin", "/manager", "/dashboard", "/api/admin", "/actuator"]


def check_session_timeout(target: str) -> list:
    try:
        response = requests.get(target, timeout=10, verify=False)
        cookie_header = response.headers.get("Set-Cookie", "")

        if not cookie_header:
            return [
                {
                    "check": "Session Cookie HttpOnly Flag",
                    "status": "N/A",
                    "evidence": "No Set-Cookie header found — session cookies not detected",
                    "remediation": "Ensure JSESSIONID is set with HttpOnly flag in web.xml or server.xml",
                },
                {
                    "check": "Session Cookie Secure Flag",
                    "status": "N/A",
                    "evidence": "No Set-Cookie header found — session cookies not detected",
                    "remediation": "Ensure JSESSIONID is set with Secure flag when using HTTPS",
                },
                {
                    "check": "Session Cookie Timeout Configured",
                    "status": "N/A",
                    "evidence": "No Set-Cookie header found — session cookies not detected",
                    "remediation": "Set <session-timeout> in web.xml to a finite value (e.g. 30 minutes)",
                },
            ]

        has_timeout = "Max-Age" in cookie_header or "Expires" in cookie_header
        has_httponly = "HttpOnly" in cookie_header
        has_secure = "Secure" in cookie_header

        return [
            {
                "check": "Session Cookie HttpOnly Flag",
                "status": "PASS" if has_httponly else "FAIL",
                "evidence": cookie_header,
                "remediation": "Add HttpOnly attribute to JSESSIONID in web.xml: <cookie-config><http-only>true</http-only></cookie-config>",
            },
            {
                "check": "Session Cookie Secure Flag",
                "status": "PASS" if has_secure else "FAIL",
                "evidence": cookie_header,
                "remediation": "Add Secure attribute to JSESSIONID in web.xml: <cookie-config><secure>true</secure></cookie-config>",
            },
            {
                "check": "Session Cookie Timeout Configured",
                "status": "PASS" if has_timeout else "FAIL",
                "evidence": cookie_header,
                "remediation": "Set finite session timeout in web.xml: <session-timeout>30</session-timeout>",
            },
        ]

    except requests.exceptions.RequestException as e:
        return [
            {
                "check": "Session Configuration",
                "status": "ERROR",
                "evidence": str(e),
                "remediation": "Ensure the target application is reachable",
            }
        ]


def check_security_constraints(target: str) -> list:
    """
    Check whether protected paths require authentication.
    Approximates <security-constraint> enforcement from web.xml —
    paths returning HTTP 200 without credentials are flagged as unprotected.
    Spec §3.4: web.xml security constraints and session timeout review.
    """
    results = []

    for path in PROTECTED_PATHS:
        url = target.rstrip("/") + path
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            status = response.status_code

            if status == 404:
                results.append({
                    "check": f"Security Constraint: {path}",
                    "status": "SKIP",
                    "evidence": f"HTTP {status} — path not found, constraint check N/A",
                    "remediation": "No action required (path does not exist)",
                })
            elif status in (401, 403):
                results.append({
                    "check": f"Security Constraint: {path}",
                    "status": "PASS",
                    "evidence": f"HTTP {status} — access control enforced at {url}",
                    "remediation": "",
                })
            else:
                body_lower = response.text.lower()
                redirected_to_login = (
                    "login" in response.url.lower()
                    or "sign-in" in response.url.lower()
                    or 'type="password"' in body_lower
                    or "type='password'" in body_lower
                )
                if redirected_to_login:
                    results.append({
                        "check": f"Security Constraint: {path}",
                        "status": "PASS",
                        "evidence": f"HTTP {status} — redirected to login page (auth enforced)",
                        "remediation": "",
                    })
                else:
                    results.append({
                        "check": f"Security Constraint: {path}",
                        "status": "FAIL",
                        "evidence": (
                            f"HTTP {status} at {url} — path accessible without authentication. "
                            "Add <security-constraint> with <auth-constraint> in web.xml."
                        ),
                        "remediation": (
                            "Add to web.xml:\n"
                            "<security-constraint>\n"
                            f"  <web-resource-collection><url-pattern>{path}/*</url-pattern></web-resource-collection>\n"
                            "  <auth-constraint><role-name>admin</role-name></auth-constraint>\n"
                            "  <user-data-constraint><transport-guarantee>CONFIDENTIAL</transport-guarantee></user-data-constraint>\n"
                            "</security-constraint>"
                        ),
                    })

        except requests.exceptions.RequestException as e:
            results.append({
                "check": f"Security Constraint: {path}",
                "status": "ERROR",
                "evidence": str(e),
                "remediation": "Check network connectivity to target",
            })

    return results


def check_transport_security(target: str) -> list:
    """
    Verify the application enforces HTTPS (transport-guarantee CONFIDENTIAL).
    """
    if target.startswith("https://"):
        http_url = target.replace("https://", "http://", 1)
    else:
        return [
            {
                "check": "Transport Guarantee (HTTPS)",
                "status": "FAIL",
                "evidence": "Target is HTTP — no transport guarantee enforced",
                "remediation": (
                    "Deploy over HTTPS and add to web.xml:\n"
                    "<user-data-constraint><transport-guarantee>CONFIDENTIAL</transport-guarantee></user-data-constraint>"
                ),
            }
        ]

    try:
        response = requests.get(http_url, timeout=10, verify=False, allow_redirects=False)
        if response.status_code in (301, 302, 307, 308):
            location = response.headers.get("Location", "")
            if location.startswith("https://"):
                return [
                    {
                        "check": "Transport Guarantee (HTTPS)",
                        "status": "PASS",
                        "evidence": f"HTTP {response.status_code} redirects to HTTPS ({location})",
                        "remediation": "",
                    }
                ]
        return [
            {
                "check": "Transport Guarantee (HTTPS)",
                "status": "FAIL",
                "evidence": f"HTTP endpoint returns {response.status_code} without redirecting to HTTPS",
                "remediation": "Configure HTTP-to-HTTPS redirect in server.xml or add transport-guarantee CONFIDENTIAL in web.xml",
            }
        ]
    except requests.exceptions.RequestException:
        return [
            {
                "check": "Transport Guarantee (HTTPS)",
                "status": "PASS",
                "evidence": "HTTP endpoint not reachable — HTTPS-only deployment inferred",
                "remediation": "",
            }
        ]


def check_error_handling(target: str) -> list:
    results = []

    for path in INSECURE_ERROR_PAGES:
        url = target.rstrip("/") + path
        try:
            response = requests.get(url, timeout=10, verify=False)
            body = response.text.lower()

            exposes_info = any(keyword in body for keyword in [
                "stack trace", "exception", "tomcat", "java.", "at org.", "at com.",
                "caused by", "classnotfound", "nullpointerexception",
            ])

            results.append({
                "check": f"Error Page Info Disclosure: {path}",
                "status": "FAIL" if exposes_info else "PASS",
                "evidence": (
                    f"HTTP {response.status_code} — "
                    f"{'Stack trace / server info detected' if exposes_info else 'No sensitive info detected'}"
                ),
                "remediation": (
                    "Define custom error pages in web.xml:\n"
                    "<error-page><error-code>500</error-code><location>/error.html</location></error-page>"
                ) if exposes_info else "",
            })

        except requests.exceptions.RequestException as e:
            results.append({
                "check": f"Error Page Info Disclosure: {path}",
                "status": "ERROR",
                "evidence": str(e),
                "remediation": "Check target reachability",
            })

    return results


def run_webxml_checks(target: str) -> dict:
    results = []

    results.extend(check_session_timeout(target))
    results.extend(check_security_constraints(target))
    results.extend(check_transport_security(target))
    results.extend(check_error_handling(target))

    for r in results:
        logger.info("Web.xml check", extra={k: v for k, v in r.items() if k != "remediation"})

    passed  = sum(1 for r in results if r["status"] == "PASS")
    failed  = sum(1 for r in results if r["status"] == "FAIL")
    skipped = sum(1 for r in results if r["status"] in ("SKIP", "N/A", "ERROR"))

    return {
        "module": "webxml_check",
        "target": target,
        "summary": {"passed": passed, "failed": failed, "skipped": skipped, "total": len(results)},
        "results": results,
    }
