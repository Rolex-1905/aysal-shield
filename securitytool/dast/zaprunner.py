import subprocess
import time
import logging
import os
import shutil
import platform
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)

ZAP_PORT = int(os.environ.get("ZAP_PORT", "8090"))
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "tomcatshield")

# OWASP Top 10 scan policy scan IDs (ZAP plugin IDs)
OWASP_SCAN_POLICIES = {
    "xss": ["40012", "40014", "40016", "40017", "40018"],          # XSS
    "sqli": ["40018", "40019", "40020", "40021", "40022"],          # SQL Injection
    "path_traversal": ["6"],                                         # Path Traversal
    "ssrf": ["40046"],                                               # SSRF
    "open_redirect": ["20019"],                                      # Open Redirect
    "sensitive_info": ["10045", "10095", "10096", "10097", "10098"] # Sensitive Disclosure
}


def find_zap_home() -> str:
    """
    Resolve ZAP home directory. Priority:
      1. ZAP_HOME env var
      2. ZAP_PATH env var (used by GitHub Actions step that sets path to zap.sh)
      3. Common install paths per platform
    """
    # Explicit overrides
    zap_home = os.environ.get("ZAP_HOME", "")
    if zap_home and os.path.isdir(zap_home):
        return zap_home

    zap_path = os.environ.get("ZAP_PATH", "")
    if zap_path:
        parent = os.path.dirname(zap_path)
        if os.path.isdir(parent):
            return parent

    # Auto-detect by platform
    system = platform.system()
    if system == "Windows":
        candidates = [
            os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "ZAP", "Zed Attack Proxy"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "ZAP"),
        ]
    elif system == "Darwin":
        candidates = [
            "/Applications/ZAP.app/Contents/Java",
            os.path.expanduser("~/ZAP"),
        ]
    else:  # Linux / CI
        candidates = [
            "/opt/zaproxy",
            os.path.expanduser("~/ZAP_2.17.0"),
            os.path.expanduser("~/zaproxy"),
            # GitHub Actions downloads to CWD
            os.path.join(os.getcwd(), "ZAP_2.17.0"),
        ]

    for path in candidates:
        if path and os.path.isdir(path):
            logger.info("ZAP home auto-detected", extra={"path": path})
            return path

    raise EnvironmentError(
        "ZAP home directory not found. Set ZAP_HOME env var to the ZAP installation directory."
    )


def find_zap_executable(zap_home: str) -> str:
    """Return the path to the ZAP startup script/jar for this platform."""
    system = platform.system()
    if system == "Windows":
        candidates = ["zap.bat", "zap-2.17.0.jar"]
    else:
        candidates = ["zap.sh", "zap-2.17.0.jar"]

    for name in candidates:
        path = os.path.join(zap_home, name)
        if os.path.exists(path):
            return path

    # Fallback: any .jar in zap_home
    for f in os.listdir(zap_home):
        if f.endswith(".jar") and "zap" in f.lower():
            return os.path.join(zap_home, f)

    raise FileNotFoundError(f"ZAP executable not found in {zap_home}")


def delete_zap_lock(zap_home: str):
    lock_file = os.path.join(zap_home, ".homelock")
    try:
        if os.path.exists(lock_file):
            os.remove(lock_file)
            logger.info("Deleted ZAP home lock file")
    except Exception as e:
        logger.warning(f"Could not delete lock file: {e}")


def start_zap(zap_home: str) -> subprocess.Popen:
    """Start ZAP in headless daemon mode. Works on Linux, macOS, and Windows."""
    delete_zap_lock(zap_home)
    exe = find_zap_executable(zap_home)
    system = platform.system()

    if exe.endswith(".jar"):
        cmd = [
            "java", "-Xmx512m", "-jar", exe,
            "-daemon", "-port", str(ZAP_PORT),
            "-config", f"api.key={ZAP_API_KEY}",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ]
    elif system == "Windows":
        cmd = [exe, "-daemon", "-port", str(ZAP_PORT), "-config", f"api.key={ZAP_API_KEY}"]
    else:
        cmd = [exe, "-daemon", "-port", str(ZAP_PORT), "-config", f"api.key={ZAP_API_KEY}"]

    logger.info("Starting ZAP daemon", extra={"cmd": " ".join(cmd)})
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=zap_home,
    )
    return proc


def wait_for_zap(zap, retries=24, delay=10) -> bool:
    logger.info("Waiting for ZAP to be ready...")
    for i in range(retries):
        try:
            version = zap.core.version
            logger.info("ZAP is ready", extra={"version": version})
            return True
        except Exception:
            logger.info(f"ZAP not ready yet ({i+1}/{retries}), retrying in {delay}s")
            time.sleep(delay)
    return False


def configure_scan_policies(zap, policies: list) -> str:
    """
    Create a named scan policy in ZAP with only the requested OWASP plugin IDs enabled.
    Returns the policy name.
    """
    policy_name = "AysalShield_Policy"
    try:
        # Remove if already exists (idempotent)
        existing = zap.ascan.scan_policy_names
        if policy_name in existing:
            zap.ascan.remove_scan_policy(policy_name)

        zap.ascan.add_scan_policy(policy_name, alertthreshold="MEDIUM", attackstrength="MEDIUM")

        # Collect all plugin IDs for the requested policies
        enabled_ids = set()
        for policy_key in (policies or list(OWASP_SCAN_POLICIES.keys())):
            ids = OWASP_SCAN_POLICIES.get(policy_key, [])
            enabled_ids.update(ids)

        if enabled_ids:
            # Disable all scanners first, then enable only ours
            zap.ascan.disable_all_scanners(scanpolicyname=policy_name)
            for plugin_id in enabled_ids:
                zap.ascan.enable_scanners(plugin_id, scanpolicyname=policy_name)

        logger.info("Scan policy configured", extra={
            "policy": policy_name,
            "enabled_plugins": list(enabled_ids)
        })
        return policy_name

    except Exception as e:
        logger.warning(f"Could not configure custom policy, using default: {e}")
        return None


def setup_form_auth(zap, context_id: str, context_name: str, target: str, auth_config: dict):
    """
    Configure form-based authentication in ZAP and return the user ID.
    This is called before spidering so the spider runs authenticated.
    """
    try:
        login_url = auth_config.get("login_url", f"{target}/login")
        username = os.environ.get("TEST_USER") or auth_config.get("username", "")
        password = os.environ.get("TEST_PASS") or auth_config.get("password", "")
        username_field = auth_config.get("username_field", "username")
        password_field = auth_config.get("password_field", "password")

        auth_method_config = (
            f"loginUrl={login_url}&"
            f"loginRequestData={username_field}%3D%7B%25username%25%7D%26"
            f"{password_field}%3D%7B%25password%25%7D"
        )

        zap.authentication.set_authentication_method(
            context_id, "formBasedAuthentication", auth_method_config
        )

        # Logged-in indicator — ZAP needs this to know a session is valid
        logged_in_indicator = auth_config.get("logged_in_indicator", "logout")
        logged_out_indicator = auth_config.get("logged_out_indicator", "login")
        zap.authentication.set_logged_in_indicator(context_id, f"\\Q{logged_in_indicator}\\E")
        zap.authentication.set_logged_out_indicator(context_id, f"\\Q{logged_out_indicator}\\E")

        user_id = zap.users.new_user(context_id, "test_user")
        zap.users.set_authentication_credentials(
            context_id, user_id,
            f"username={username}&password={password}"
        )
        zap.users.set_user_enabled(context_id, user_id, True)
        zap.forcedUser.set_forced_user(context_id, user_id)
        zap.forcedUser.set_forced_user_mode_enabled(True)

        logger.info("Form-based auth configured in ZAP", extra={
            "login_url": login_url,
            "username_field": username_field
        })
        return user_id

    except Exception as e:
        logger.error("ZAP auth setup failed", extra={"error": str(e)})
        return None


def run_zap_scan(target: str, non_destructive: bool = True, max_duration: int = 30,
                 scan_mode: str = "quick", include_patterns: list = None,
                 exclude_patterns: list = None, auth_config: dict = None,
                 scan_policies: list = None) -> dict:
    """
    Full ZAP scan lifecycle:
      1. Start daemon
      2. Create context with include/exclude patterns
      3. Configure auth (if provided)
      4. Spider
      5. Active scan (quick = lightweight policy; deep = full policy; non_destructive only affects payload aggressiveness)
      6. Collect and return alerts
    """
    zap_home = None
    zap_proc = None

    try:
        zap_home = find_zap_home()
    except EnvironmentError as e:
        return {"error": str(e), "results": []}

    try:
        zap_proc = start_zap(zap_home)
    except Exception as e:
        return {"error": f"Failed to start ZAP: {e}", "results": []}

    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http": f"http://127.0.0.1:{ZAP_PORT}",
            "https": f"http://127.0.0.1:{ZAP_PORT}"
        }
    )

    ready = wait_for_zap(zap, retries=24, delay=10)
    if not ready:
        if zap_proc:
            zap_proc.terminate()
        return {"error": "ZAP failed to start within timeout.", "results": []}

    try:
        # --- Context setup ---
        context_name = "AysalShield_context"
        context_id = zap.context.new_context(context_name)
        logger.info("ZAP context created", extra={"context_id": context_id})

        if include_patterns:
            for pattern in include_patterns:
                zap.context.include_in_context(context_name, pattern)
        else:
            zap.context.include_in_context(context_name, f"{target}.*")

        if exclude_patterns:
            for pattern in exclude_patterns:
                zap.context.exclude_from_context(context_name, pattern)

        # --- Authentication ---
        user_id = None
        if auth_config and auth_config.get("type") == "form":
            user_id = setup_form_auth(zap, context_id, context_name, target, auth_config)

        # --- Scan policy ---
        # quick mode: lightweight (passive + fast active); deep: full active
        effective_policies = scan_policies
        if scan_mode == "quick" and not scan_policies:
            # quick mode uses XSS + SQLi only for speed
            effective_policies = ["xss", "sqli", "open_redirect"]

        policy_name = configure_scan_policies(zap, effective_policies)

        # Set attack strength: non_destructive limits to LOW, otherwise MEDIUM/HIGH
        if policy_name:
            strength = "LOW" if non_destructive else "HIGH"
            zap.ascan.set_policy_attack_strength(policy_name, strength)
            zap.ascan.set_policy_alert_threshold(policy_name, "MEDIUM")

        # --- Spider ---
        logger.info("Starting ZAP spider", extra={"target": target, "authenticated": user_id is not None})
        if user_id:
            scan_id = zap.spider.scan_as_user(context_id, user_id, target)
        else:
            scan_id = zap.spider.scan(target, contextname=context_name)

        time.sleep(2)
        while int(zap.spider.status(scan_id)) < 100:
            logger.info("Spider progress", extra={"progress": zap.spider.status(scan_id)})
            time.sleep(5)
        logger.info("Spider complete", extra={"urls": len(zap.spider.results(scan_id))})

        # --- Active scan ---
        # Runs in BOTH quick and deep modes.
        # non_destructive controls payload aggressiveness (LOW vs HIGH), not whether to scan.
        logger.info("Starting active scan", extra={
            "target": target,
            "scan_mode": scan_mode,
            "non_destructive": non_destructive,
            "policy": policy_name
        })

        ascan_kwargs = {"contextid": context_id}
        if policy_name:
            ascan_kwargs["scanpolicyname"] = policy_name
        if user_id:
            ascan_kwargs["userid"] = user_id

        active_scan_id = zap.ascan.scan(target, **ascan_kwargs)
        start_time = time.time()

        while int(zap.ascan.status(active_scan_id)) < 100:
            elapsed = int((time.time() - start_time) / 60)
            if elapsed >= max_duration:
                logger.info("Max scan duration reached, stopping active scan", extra={"elapsed_min": elapsed})
                zap.ascan.stop(active_scan_id)
                break
            logger.info("Active scan progress", extra={
                "progress": zap.ascan.status(active_scan_id),
                "elapsed_min": elapsed
            })
            time.sleep(10)

        logger.info("Active scan complete")

        alerts = zap.core.alerts(baseurl=target)
        logger.info("Alerts collected", extra={"count": len(alerts)})
        return {"results": alerts}

    except Exception as e:
        logger.error("ZAP scan error", extra={"error": str(e)})
        return {"error": str(e), "results": []}

    finally:
        logger.info("Shutting down ZAP daemon")
        try:
            zap.core.shutdown()
        except Exception:
            pass
        if zap_proc:
            try:
                zap_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                zap_proc.kill()
