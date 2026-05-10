import subprocess
import time
import logging
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)

ZAP_PATH = "C:\\Program Files\\ZAP\\Zed Attack Proxy\\zap.bat"
ZAP_PORT = 8090
ZAP_API_KEY = "tomcatshield"


def kill_existing_zap():
    try:
        subprocess.run(
            ["taskkill", "/F", "/IM", "java.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)
        logger.info("Killed existing ZAP/Java process")
    except Exception:
        pass


def start_zap():
    kill_existing_zap()
    logger.info("Starting ZAP daemon", extra={"port": ZAP_PORT})
    process = subprocess.Popen(
        [ZAP_PATH, "-daemon",
         "-port", str(ZAP_PORT),
         "-config", f"api.key={ZAP_API_KEY}",
         "-config", "api.addrs.addr.name=.*",
         "-config", "api.addrs.addr.regex=true"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="C:\\Program Files\\ZAP\\Zed Attack Proxy"
    )
    return process


def wait_for_zap(zap, retries=12, delay=10):
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


def run_zap_scan(target: str, non_destructive: bool = True, max_duration: int = 30) -> dict:
    process = start_zap()

    zap = ZAPv2(apikey=ZAP_API_KEY,
                proxies={"http": f"http://127.0.0.1:{ZAP_PORT}",
                         "https": f"http://127.0.0.1:{ZAP_PORT}"})

    logger.info("Waiting for ZAP to initialize...")
    time.sleep(60)
    ready = wait_for_zap(zap, retries=12, delay=10)
    if not ready:
        process.terminate()
        return {"error": "ZAP failed to start", "results": []}

    try:
        logger.info("Starting spider", extra={"target": target})
        scan_id = zap.spider.scan(target)
        time.sleep(2)

        while int(zap.spider.status(scan_id)) < 100:
            logger.info("Spider progress", extra={"progress": zap.spider.status(scan_id)})
            time.sleep(5)

        logger.info("Spider complete")

        if not non_destructive:
            logger.info("Starting active scan", extra={"target": target})
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
        time.sleep(2)
        process.terminate()