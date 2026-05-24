# Aysal Shield — Operational Runbook

---

## Prerequisites

Before running any scan:

1. **Written authorization** — you must have explicit written authorization to scan the target environment
2. **Dedicated test environment** — only scan Dev/QA/Staging; production requires separate written sign-off
3. **Test accounts** — provision dedicated test accounts; never use production credentials
4. **Network access** — confirm the scan host can reach the target URL

---

## Installation

```bash
git clone https://github.com/Rolex-1905/aysal-shield.git
cd aysal-shield

# Python environment
python -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\activate           # Windows

pip install -r requirements.txt

# Install pre-commit hooks (blocks credential leaks)
pip install pre-commit
pre-commit install
```

### ZAP installation (required for DAST)

```bash
# Linux / CI
wget https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz
tar -xzf ZAP_2.17.0_Linux.tar.gz
export ZAP_HOME="$(pwd)/ZAP_2.17.0"

# macOS
brew install zaproxy   # or download from zaproxy.org
export ZAP_HOME="/Applications/ZAP.app/Contents/Java"

# Windows
# Download ZAP_2.17.0_Windows.exe from zaproxy.org
# Set ZAP_HOME="C:\Program Files\ZAP\Zed Attack Proxy"
```

---

## Running scans

### Tomcat hardening only (no ZAP required)

```bash
python -m securitytool.cli \
  --target https://dev.example.com \
  --tomcat \
  --output-dir artifacts
```

### DAST scan (quick — for PR checks)

```bash
export TEST_USER="test_account"
export TEST_PASS="test_password"

python -m securitytool.cli \
  --target https://dev.example.com \
  --dast \
  --scan-mode quick \
  --threshold High \
  --output-dir artifacts
```

### DAST scan (deep — for nightly runs)

```bash
python -m securitytool.cli \
  --target https://dev.example.com \
  --dast \
  --scan-mode deep \
  --threshold High \
  --max-high 0 \
  --max-medium 3 \
  --max-duration-minutes 60 \
  --output-dir artifacts
```

### Full scan (Tomcat + DAST + Discovery)

```bash
python -m securitytool.cli \
  --config configs/deep_scan.json \
  --tomcat \
  --dast \
  --discover \
  --output-dir artifacts
```

### Using a config file

```bash
python -m securitytool.cli --config configs/dev.json --tomcat --dast
```

See [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md) for all config parameters.

---

## Interpreting results

### Severity levels

| Level | Meaning | Response time |
|-------|---------|---------------|
| **Critical** | Confirmed, high-impact vulnerability (RCE, SQLi) | Immediate — report to security channel now |
| **High** | High-risk finding — fail pipeline | Fix before next release |
| **Medium** | Medium-risk — pipeline warning | Fix within current sprint |
| **Low** | Low-risk — informational | Add to backlog |
| **Informational** | No direct risk | Review at next security review |

### Report files

After a scan, `artifacts/` contains:

| File | Purpose |
|------|---------|
| `security_report_<timestamp>.html` | Human-readable — share with dev and security teams |
| `security_report_<timestamp>.json` | Machine-readable — for SIEM / downstream tooling |
| `security_report_<timestamp>.csv` | Management summary — severity counts and risk score |
| `discovery_inventory_<timestamp>.json` | Endpoint inventory from crawl |

### CI gate behaviour

The pipeline exits with code 1 (failure) if:
- Any finding at or above `--threshold` severity exists, OR
- `--max-high` count is exceeded, OR
- `--max-medium` count is exceeded

---

## Troubleshooting

### ZAP fails to start

```bash
java -version          # Must be Java 17+
echo $ZAP_HOME         # Must point to ZAP directory
ls $ZAP_HOME/*.sh      # Linux/macOS: zap.sh must exist
ls $ZAP_HOME/*.bat     # Windows: zap.bat must exist
```

If ZAP was already running, a stale lock file may block startup:
```bash
rm -f "$ZAP_HOME/.homelock"
```

### Connection timeout on target

```bash
curl -v https://your-target.com        # Test connectivity
curl -v http://your-target.com         # Test HTTP
```

Common causes: VPN required, firewall rule, wrong URL.

### No DAST findings returned

1. Confirm ZAP started: look for `"ZAP is ready"` in log output
2. Check `artifacts/` — JSON report is written even if findings list is empty
3. Confirm scan mode: in `quick` mode only XSS, SQLi, open_redirect policies run
4. Test with a known-vulnerable target (e.g. OWASP WebGoat) to confirm ZAP is functioning

### Authentication not working

See [AUTH_SETUP.md](AUTH_SETUP.md) — check `logged_in_indicator` and verify session cookies are set.

### PII appearing in reports

Check `utils.py` PII patterns. If a new credential pattern is leaking, add a regex to `PII_PATTERNS` in `securitytool/utils.py`.

---

## Security guidelines

- **Never scan production** without a signed-off change request
- **Rotate test credentials** after each engagement — update CI secrets, not config files
- **All reports are internal-confidential** — do not share outside the security/dev teams
- **Critical and High findings** must be logged to the security Slack channel immediately
- **Rate limits** — agree time-boxing constraints with the target team before deep scans

---

## Post-scan checklist

- [ ] Reports reviewed by security engineer
- [ ] Critical/High findings filed in the vulnerability management system
- [ ] Test credentials rotated
- [ ] Scan artifacts archived or deleted per data retention policy
- [ ] `artifacts/` directory cleared from CI runner (handled by CI retention-days config)
