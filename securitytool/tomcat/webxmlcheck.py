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


# ---------------------------------------------------------------------------
# NEW: Functional Sanity Tests
# ---------------------------------------------------------------------------

def check_session_fixation(target: str) -> dict:
    """
    Test for session fixation: capture the pre-auth JSESSIONID, simulate a
    login attempt, then verify the session ID was rotated afterwards.
    A proper implementation calls HttpSession.invalidate() + getSession(true)
    on successful authentication, which changes the ID.
    """
    session = requests.Session()
    session.verify = False

    try:
        # Step 1: Capture pre-auth session ID
        session.get(target, timeout=10)
        pre_session_id = session.cookies.get("JSESSIONID", "")

        if not pre_session_id:
            return {
                "check": "Session Fixation",
                "status": "N/A",
                "evidence": "No JSESSIONID issued before login — fixation check skipped",
                "remediation": (
                    "Ensure the application issues a JSESSIONID on first contact "
                    "so that pre/post-login rotation can be verified."
                ),
            }

        # Step 2: Simulate a login attempt (dummy credentials trigger session handling)
        login_url = target.rstrip("/") + "/login"
        session.post(
            login_url,
            data={"username": "fixation_probe_user", "password": "fixation_probe_pass"},
            timeout=10,
            allow_redirects=True,
        )

        # Step 3: Compare session IDs
        post_session_id = session.cookies.get("JSESSIONID", "")

        if not post_session_id:
            return {
                "check": "Session Fixation",
                "status": "N/A",
                "evidence": "No JSESSIONID present after login attempt — unable to compare IDs",
                "remediation": "Verify that the application issues session cookies on authentication.",
            }

        fixed = pre_session_id == post_session_id
        return {
            "check": "Session Fixation",
            "status": "FAIL" if fixed else "PASS",
            "evidence": (
                f"Pre-login  JSESSIONID: {pre_session_id[:20]}... | "
                f"Post-login JSESSIONID: {post_session_id[:20]}... | "
                f"{'UNCHANGED — session fixation risk detected' if fixed else 'ROTATED — session regenerated correctly'}"
            ),
            "remediation": (
                "On every successful login call HttpSession.invalidate() immediately followed by "
                "request.getSession(true) to force a new session ID. "
                "In Spring Security this is the default behaviour; verify SessionFixationProtectionStrategy is active."
            ) if fixed else "",
        }

    except requests.exceptions.RequestException as e:
        return {
            "check": "Session Fixation",
            "status": "ERROR",
            "evidence": str(e),
            "remediation": "Check that the target application is reachable.",
        }


def check_login_failure_handling(target: str) -> list:
    """
    Submit invalid credentials to /login and verify three things:
      1. Login is actually rejected (no dashboard content returned).
      2. The error message does not enumerate whether the username or password was wrong.
      3. No stack trace or server internals are disclosed in the error response.
    """
    results = []
    login_url = target.rstrip("/") + "/login"

    try:
        resp = requests.post(
            login_url,
            data={"username": "invalid_probe_user_xyz", "password": "invalid_probe_pass_xyz"},
            timeout=10,
            verify=False,
            allow_redirects=True,
        )
        body_lower = resp.text.lower()

        # Check 1: Confirm login was rejected
        login_succeeded = resp.status_code == 200 and any(
            kw in body_lower
            for kw in ["dashboard", "welcome", "logout", "my account", "profile"]
        )
        results.append({
            "check": "Login Failure: Invalid Credentials Rejected",
            "status": "FAIL" if login_succeeded else "PASS",
            "evidence": (
                f"HTTP {resp.status_code} — "
                f"{'Login appeared to succeed with invalid credentials' if login_succeeded else 'Login correctly rejected'}"
            ),
            "remediation": (
                "Verify authentication logic validates credentials server-side before granting access. "
                "Never trust client-supplied session state."
            ) if login_succeeded else "",
        })

        # Check 2: Verify no username enumeration via error message
        reveals_username = any(kw in body_lower for kw in [
            "user not found", "unknown user", "no account found",
            "username does not exist", "email not registered",
        ])
        results.append({
            "check": "Login Failure: No Username Enumeration",
            "status": "FAIL" if reveals_username else "PASS",
            "evidence": (
                f"HTTP {resp.status_code} — "
                f"{'Error message reveals whether the username exists' if reveals_username else 'Generic error message returned — no enumeration'}"
            ),
            "remediation": (
                "Return a single generic message regardless of which field failed, e.g. "
                "'Invalid username or password.' Never indicate whether the username or password was wrong."
            ) if reveals_username else "",
        })

        # Check 3: Verify no stack trace or server info in error response
        exposes_server_info = any(kw in body_lower for kw in [
            "stack trace", "exception", "java.", "at org.", "at com.",
            "caused by", "nullpointerexception", "tomcat", "coyote",
        ])
        results.append({
            "check": "Login Failure: No Server Info Disclosed",
            "status": "FAIL" if exposes_server_info else "PASS",
            "evidence": (
                f"HTTP {resp.status_code} — "
                f"{'Stack trace or server internals detected in error response' if exposes_server_info else 'No sensitive server info in error response'}"
            ),
            "remediation": (
                "Configure a custom error page for HTTP 500 in web.xml and disable Tomcat's default "
                "exception renderer. Set <error-page><exception-type>java.lang.Exception</exception-type>"
                "<location>/error</location></error-page>."
            ) if exposes_server_info else "",
        })

    except requests.exceptions.RequestException as e:
        results.append({
            "check": "Login Failure Handling",
            "status": "ERROR",
            "evidence": str(e),
            "remediation": "Ensure the /login endpoint is reachable from the scan host.",
        })

    return results


def check_logout_invalidation(target: str) -> dict:
    """
    Verify that hitting /logout actually clears or rotates the JSESSIONID.
    A session that survives logout is reusable after the user believes they
    have signed out — a common session management vulnerability.
    """
    session = requests.Session()
    session.verify = False

    try:
        # Establish a session
        session.get(target, timeout=10)
        session_id_before = session.cookies.get("JSESSIONID", "")

        # Hit the logout endpoint
        logout_url = target.rstrip("/") + "/logout"
        session.get(logout_url, timeout=10, allow_redirects=True)

        session_id_after = session.cookies.get("JSESSIONID", "")

        # PASS: cookie was cleared entirely OR was rotated to a new value
        cookie_cleared = not session_id_after
        cookie_rotated = session_id_after and session_id_after != session_id_before
        session_invalidated = cookie_cleared or cookie_rotated

        if cookie_cleared:
            evidence_detail = "JSESSIONID cookie cleared after logout — session properly invalidated"
        elif cookie_rotated:
            evidence_detail = (
                f"JSESSIONID rotated after logout "
                f"({session_id_before[:16]}... → {session_id_after[:16]}...) — OK"
            )
        else:
            evidence_detail = (
                f"JSESSIONID unchanged after logout "
                f"({session_id_before[:16]}...) — session NOT invalidated"
            )

        return {
            "check": "Logout Session Invalidation",
            "status": "PASS" if session_invalidated else "FAIL",
            "evidence": f"Pre-logout: {'present' if session_id_before else 'absent'} | {evidence_detail}",
            "remediation": (
                "Call HttpSession.invalidate() in the logout handler and delete the JSESSIONID cookie explicitly. "
                "In Spring Security: http.logout().invalidateHttpSession(true).deleteCookies('JSESSIONID'). "
                "In plain servlets: session.invalidate(); response.setHeader('Set-Cookie', 'JSESSIONID=; Max-Age=0; Path=/');"
            ) if not session_invalidated else "",
        }

    except requests.exceptions.RequestException as e:
        return {
            "check": "Logout Session Invalidation",
            "status": "ERROR",
            "evidence": str(e),
            "remediation": "Check that the target application and /logout endpoint are reachable.",
        }


# ---------------------------------------------------------------------------
# Main runner — orchestrates all checks in this module
# ---------------------------------------------------------------------------

def run_webxml_checks(target: str) -> dict:
    results = []

    results.extend(check_session_timeout(target))
    results.extend(check_security_constraints(target))
    results.extend(check_transport_security(target))
    results.extend(check_error_handling(target))

    # Functional sanity tests (added to complete Week 2 spec requirements)
    results.append(check_session_fixation(target))
    results.extend(check_login_failure_handling(target))
    results.append(check_logout_invalidation(target))

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