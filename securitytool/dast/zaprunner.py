import subprocess
import time
import logging
import os
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)

ZAP_PORT = 8090
ZAP_API_KEY = "tomcatshield"
ZAP_HOME = "C:\\Users\\lenovo\\ZAP"


def delete_zap_lock():
    lock_file = os.path.join(ZAP_HOME, ".homelock")
    try:
        if os.path.exists(lock_file):
            os.remove(lock_file)
            logger.info("Deleted ZAP home lock file")
    except Exception as e:
        logger.warning(f"Could not delete lock file: {e}")


def start_zap_in_new_terminal():
    delete_zap_lock()

    bat_content = (
        '@echo off\n'
        'echo Starting ZAP for TomcatShield...\n'
        'cd /d "C:\\Program Files\\ZAP\\Zed Attack Proxy"\n'
        f'java -Xmx512m -jar zap-2.17.0.jar -daemon -port {ZAP_PORT} -config api.key={ZAP_API_KEY}\n'
        'pause\n'
    )

    bat_path = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "run_zap.bat")
    with open(bat_path, "w") as f:
        f.write(bat_content)

    subprocess.Popen(f'start cmd /k "{bat_path}"', shell=True)
    logger.info("ZAP started in new terminal window — waiting for it to be ready")


def wait_for_zap(zap, retries=18, delay=10):
    logger.info("Waiting for ZAP to be ready...")
    for i in range(retries):
        try:
            version = zap.core.version
            logger.info("ZAP is ready", extra={"version": version})
            return True
        except Exception:
            logger.info(f"ZAP not ready yet, attempt {i+1}/{retries}")
            time.sleep(delay)
    return False


def setup_form_auth(zap, context_id: str, context_name: str, target: str, auth_config: dict):
    try:
        login_url = auth_config.get("login_url", f"{target}/login")
        username = os.environ.get("TEST_USER", auth_config.get("username", ""))
        password = os.environ.get("TEST_PASS", auth_config.get("password", ""))
        username_field = auth_config.get("username_field", "username")
        password_field = auth_config.get("password_field", "password")

        # Set form-based authentication
        auth_method_config = (
            f"loginUrl={login_url}&"
            f"loginRequestData={username_field}%3D%7B%25username%25%7D%26"
            f"{password_field}%3D%7B%25password%25%7D"
        )

        zap.authentication.set_authentication_method(
            context_id,
            "formBasedAuthentication",
            auth_method_config
        )

        # Create user
        user_id = zap.users.new_user(context_id, "test_user")
        zap.users.set_authentication_credentials(
            context_id,
            user_id,
            f"username={username}&password={password}"
        )
        zap.users.set_user_enabled(context_id, user_id, True)
        zap.forcedUser.set_forced_user(context_id, user_id)
        zap.forcedUser.set_forced_user_mode_enabled(True)

        logger.info("Form-based auth configured", extra={
            "login_url": login_url,
            "username_field": username_field
        })

        return user_id

    except Exception as e:
        logger.error("Auth setup failed", extra={"error": str(e)})
        return None

def run_zap_scan(target: str, non_destructive: bool = True, max_duration: int = 30,
                 scan_mode: str = "quick", include_patterns: list = None,
                 exclude_patterns: list = None, auth_config: dict = None) -> dict:

    start_zap_in_new_terminal()

    zap = ZAPv2(apikey=ZAP_API_KEY,
                proxies={"http": f"http://127.0.0.1:{ZAP_PORT}",
                         "https": f"http://127.0.0.1:{ZAP_PORT}"})

    ready = wait_for_zap(zap, retries=18, delay=10)
    if not ready:
        return {
            "error": "ZAP failed to start. Check the ZAP terminal window.",
            "results": []
        }

    try:
        # Set up scan context
        context_name = "tomcatshield_context"
        context_id = zap.context.new_context(context_name)
        logger.info("Created ZAP context", extra={"context_id": context_id})

        # Include patterns
        if include_patterns:
            for pattern in include_patterns:
                zap.context.include_in_context(context_name, pattern)
                logger.info("Include pattern added", extra={"pattern": pattern})
        else:
            zap.context.include_in_context(context_name, f"{target}.*")

        # Exclude patterns
        if exclude_patterns:
            for pattern in exclude_patterns:
                zap.context.exclude_from_context(context_name, pattern)
                logger.info("Exclude pattern added", extra={"pattern": pattern})

        logger.info("Starting spider", extra={"target": target})
        scan_id = zap.spider.scan(target, contextname=context_name)
        time.sleep(2)

        while int(zap.spider.status(scan_id)) < 100:
            logger.info("Spider progress", extra={"progress": zap.spider.status(scan_id)})
            time.sleep(5)

        logger.info("Spider complete")

        if scan_mode == "deep" and not non_destructive:
            logger.info("Starting active scan", extra={"target": target})
            scan_id = zap.ascan.scan(target, contextid=context_id)

            start_time = time.time()
            while int(zap.ascan.status(scan_id)) < 100:
                elapsed = int((time.time() - start_time) / 60)
                if elapsed >= max_duration:
                    logger.info("Max duration reached, stopping scan")
                    zap.ascan.stop(scan_id)
                    break
                logger.info("Active scan progress", extra={"progress": zap.ascan.status(scan_id)})
                time.sleep(10)

        elif scan_mode == "deep" and non_destructive:
            logger.info("Deep mode requested but safe mode is ON — skipping active scan")

        alerts = zap.core.alerts(baseurl=target)
        logger.info("Scan complete", extra={"alerts": len(alerts)})
        return {"results": alerts}

    except Exception as e:
        logger.error("ZAP scan error", extra={"error": str(e)})
        return {"error": str(e), "results": []}

    finally:
        logger.info("Shutting down ZAP")
        try:
            zap.core.shutdown()
        except Exception:
            pass