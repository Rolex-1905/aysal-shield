# Aysal Shield — Authentication Setup Guide

This guide covers all supported authentication methods and how to configure them for both the discovery crawler and the ZAP DAST engine.

---

## Overview

Aysal Shield supports three authentication modes:

| Type | Config value | Use case |
|------|-------------|----------|
| Form-based | `form` | Standard HTML login form (most common) |
| Token-based | `token` | Bearer token / API key in header |
| HTTP Basic | `basic` | RFC 7235 Basic authentication |

> **Security rule:** Test credentials must use dedicated test accounts. Production credentials must never be used. All secrets must come from environment variables or CI secret stores.

---

## 1. Form-based authentication (most common)

### How it works
Aysal Shield POSTs the username and password to the login URL, then maintains the session cookie for all subsequent requests. ZAP is configured to use the same form-auth method so its spider and active scan run as an authenticated user.

### Config
```json
"auth": {
  "type": "form",
  "login_url": "https://dev.example.com/login",
  "username": "${TEST_USER}",
  "password": "${TEST_PASS}",
  "username_field": "user",
  "password_field": "pass",
  "logged_in_indicator": "logout",
  "logged_out_indicator": "login"
}
```

### Finding your field names
Inspect the login form HTML to find the `name` attributes:
```html
<input type="text" name="user" />       <!-- username_field = "user" -->
<input type="password" name="pass" />   <!-- password_field = "pass" -->
```

### Setting credentials via environment variables
```bash
export TEST_USER="your_test_account"
export TEST_PASS="your_test_password"
python -m securitytool.cli --config configs/dev.json --dast
```

### In CI (GitHub Actions)
```yaml
env:
  TEST_USER: ${{ secrets.TEST_USER }}
  TEST_PASS: ${{ secrets.TEST_PASS }}
```

### Troubleshooting form auth
- **Login fails silently:** Check `logged_in_indicator` — if the authenticated page doesn't contain the word "logout", ZAP will treat every response as unauthenticated. Set it to a string that only appears when logged in.
- **CSRF tokens:** If the login form has a CSRF token field, ZAP's form-based auth handles this automatically via its pre-login request.
- **Multi-step login (OTP, captcha):** Use the script-driven approach below.

---

## 2. Token-based authentication

### How it works
For APIs that accept a Bearer token or API key, set the token as an environment variable and pass it via the `--auth-type token` CLI flag.

### CLI usage
```bash
export API_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
python -m securitytool.cli \
  --target https://dev.example.com \
  --auth-type token \
  --dast
```

### Config
```json
"auth": {
  "type": "token",
  "token": "${API_TOKEN}",
  "header_name": "Authorization",
  "header_prefix": "Bearer"
}
```

> Note: Token auth injects the `Authorization: Bearer <token>` header into ZAP's HTTP sender via a script. The token is read from the environment variable at scan time and is never written to disk or logs.

---

## 3. HTTP Basic authentication

### How it works
Standard RFC 7235 Basic auth — credentials are Base64-encoded and sent in the `Authorization` header on every request.

### CLI usage
```bash
export TEST_USER="admin"
export TEST_PASS="testpassword"
python -m securitytool.cli \
  --target https://dev.example.com \
  --auth-type basic \
  --dast
```

### Config
```json
"auth": {
  "type": "basic",
  "username": "${TEST_USER}",
  "password": "${TEST_PASS}"
}
```

---

## Verifying authentication is working

After running a scan with authentication, check the discovery inventory:
```bash
cat artifacts/discovery_inventory_*.json | python -m json.tool | grep '"authenticated"'
```

Authenticated endpoints will show `"authenticated": true`. If all endpoints show `false`, authentication failed — check your credentials and `logged_in_indicator`.

---

## Multi-role scanning

To scan different user roles (admin vs regular user), run separate scans with different credentials and different output directories:

```bash
# Scan as regular user
export TEST_USER=user@example.com TEST_PASS=userpass
python -m securitytool.cli --config configs/dev.json --dast --output-dir artifacts/user

# Scan as admin
export TEST_USER=admin@example.com TEST_PASS=adminpass
python -m securitytool.cli --config configs/dev.json --dast --output-dir artifacts/admin
```

---

## Security checklist

- [ ] Use dedicated test accounts — never production accounts
- [ ] Store credentials in `.env` file or CI secrets — never in config files
- [ ] Rotate test credentials after each engagement (see RUNBOOK.md)
- [ ] Verify `.env` is in `.gitignore` before running any scan
- [ ] Set `logged_in_indicator` to confirm sessions are established
