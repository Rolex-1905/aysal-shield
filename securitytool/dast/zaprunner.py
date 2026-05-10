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


def run_zap_scan(target: str, non_destructive: bool = True, max_duration: int = 30, scan_mode: str = "quick") -> dict:
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
        logger.info("Starting spider", extra={"target": target})
        scan_id = zap.spider.scan(target)
        time.sleep(2)

        while int(zap.spider.status(scan_id)) < 100:
            logger.info("Spider progress", extra={"progress": zap.spider.status(scan_id)})
            time.sleep(5)

        logger.info("Spider complete")

        if scan_mode == "deep" and not non_destructive:
            logger.info("Starting active scan", extra={"target": target})
        elif scan_mode == "deep" and non_destructive:
            logger.info("Deep mode requested but safe mode is ON — skipping active scan")
            scan_id = zap.ascan.scan(target)

            start_time = time.time()
            while int(zap.ascan.status(scan_id)) < 100:
                elapsed = int((time.time() - start_time) / 60)
                if elapsed >= max_duration:
                    logger.info("Max duration reached, stopping scan")
                    zap.ascan.stop(scan_id)
                    break
                logger.info("Active scan progress", extra={"progress": zap.ascan.status(scan_id)})
                time.sleep(10)

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