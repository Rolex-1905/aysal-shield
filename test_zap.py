import subprocess
import time

process = subprocess.Popen(
    ["C:\\Program Files\\ZAP\\Zed Attack Proxy\\zap.bat", "-daemon",
     "-port", "8090",
     "-config", "api.key=tomcatshield"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd="C:\\Program Files\\ZAP\\Zed Attack Proxy"
)

time.sleep(5)
print("Return code:", process.poll())
out, err = process.communicate(timeout=5)
print("STDOUT:", out[:500])
print("STDERR:", err[:500])