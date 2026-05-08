# TomcatShield Runbook

## Starting a Scan

### Prerequisites
1. Ensure you have written authorization to scan the target
2. Use only Dev/QA/Staging environments
3. Never use production credentials

### Running a Tomcat Hardening Scan
```bash
python -m securitytool.cli --target http://your-target.com --tomcat --output-dir artifacts
```

### Running a DAST Scan
Start ZAP manually first:
```bash
cd "C:\Program Files\ZAP\Zed Attack Proxy"
.\zap.bat -daemon -port 8090 -config api.key=tomcatshield
```
Then run:
```bash
python -m securitytool.cli --target http://your-target.com --dast
```

## Interpreting Results

### Severity Levels
- **Critical** — Immediate action required
- **High** — Fix before next release
- **Medium** — Fix within sprint
- **Low** — Fix in backlog
- **Informational** — Review only

### CI Gate
The pipeline fails with exit code 1 if any High or Critical findings are found.
This is controlled by the `--threshold` flag.

## Troubleshooting

### ZAP fails to start
- Ensure Java 17+ is installed: `java -version`
- Ensure ZAP is installed at the correct path
- Increase wait time in `zaprunner.py` if on a slow machine

### Connection timeout on target
- Verify target is reachable: `curl http://your-target.com`
- Check network/firewall rules
- Confirm you have authorization to scan

### No findings returned
- Confirm ZAP started successfully
- Check artifacts/ folder for report files
- Try running with a known vulnerable target first

## Security Guidelines
- Never scan production without written sign-off
- Rotate test credentials after each engagement
- All reports are internal-confidential
- Critical/High findings must be reported to security channel immediately