# Aysal Shield — Configuration Reference

All parameters, types, defaults, and descriptions for the `configs/*.json` and `configs/*.yaml` configuration files.

---

## Top-level fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target` | string | **Yes** | — | Base URL of the target application (e.g. `https://dev.example.com`) |
| `auth` | object | No | — | Authentication configuration (see [Auth block](#auth-block)) |
| `include` | string[] | No | `["<target>.*"]` | URL patterns to include in scan scope |
| `exclude` | string[] | No | `[]` | URL patterns to exclude from scan scope |
| `scan` | object | No | — | DAST scan settings (see [Scan block](#scan-block)) |
| `tomcat` | object | No | — | Tomcat hardening check toggles (see [Tomcat block](#tomcat-block)) |
| `report` | object | **Yes** | — | Report output settings (see [Report block](#report-block)) |
| `threshold` | object | No | — | CI gate thresholds (see [Threshold block](#threshold-block)) |

---

## Auth block

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

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | string | Yes | — | Auth method: `form`, `token`, `basic` |
| `login_url` | string | Yes (form) | `<target>/login` | URL of the login page |
| `username` | string | Yes | — | Username. **Use `${TEST_USER}` env var substitution — never hardcode.** |
| `password` | string | Yes | — | Password. **Use `${TEST_PASS}` env var substitution — never hardcode.** |
| `username_field` | string | No | `username` | HTML `name` attribute of the username input |
| `password_field` | string | No | `password` | HTML `name` attribute of the password input |
| `logged_in_indicator` | string | No | `logout` | Text/pattern that proves a session is authenticated (ZAP uses this) |
| `logged_out_indicator` | string | No | `login` | Text/pattern that proves a session is unauthenticated |

> **Security:** credentials must come from environment variables or CI secret stores. Plain-text values in config files will be rejected by the pre-commit hook.

---

## Scan block

```json
"scan": {
  "policies": ["xss", "sqli", "path_traversal", "ssrf", "open_redirect"],
  "max_duration_minutes": 30,
  "non_destructive": true
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policies` | string[] | all policies | Subset of OWASP scan policies to enable. Valid values: `xss`, `sqli`, `path_traversal`, `ssrf`, `open_redirect`, `sensitive_info` |
| `max_duration_minutes` | integer | `30` | Hard time limit on the ZAP active scan. Scan is aborted when exceeded. |
| `non_destructive` | boolean | `true` | When `true`, ZAP uses LOW attack strength (no destructive payloads). Set `false` only in dedicated test environments with explicit sign-off. |

---

## Tomcat block

```json
"tomcat": {
  "check_headers": true,
  "check_default_apps": true,
  "check_tls": true
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `check_headers` | boolean | `true` | Run HTTP security header checks (CSP, HSTS, X-Frame-Options, etc.) |
| `check_default_apps` | boolean | `true` | Check whether `/manager` and `/host-manager` are exposed |
| `check_tls` | boolean | `true` | Validate TLS version and cipher suite (HTTPS targets only) |

---

## Report block

```json
"report": {
  "formats": ["json", "html", "csv"],
  "output_dir": "artifacts"
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `formats` | string[] | Yes | — | Report formats to produce. Any combination of `json`, `html`, `csv`. |
| `output_dir` | string | No | `artifacts` | Directory where report files are written. Created if it does not exist. |

---

## Threshold block

```json
"threshold": {
  "fail_on": "High",
  "max_high": 0,
  "max_medium": 3
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fail_on` | string | `High` | Minimum severity that triggers a pipeline failure. One of: `Informational`, `Low`, `Medium`, `High`, `Critical`. |
| `max_high` | integer | `0` | Maximum number of High findings allowed before the pipeline fails. `-1` disables the cap. |
| `max_medium` | integer | `-1` | Maximum number of Medium findings allowed. `-1` disables the cap. |
| `max_critical` | integer | `0` | Maximum number of Critical findings allowed. `-1` disables the cap. |

---

## Environment variable substitution

Any string value in the config can reference an environment variable using `${VAR_NAME}` syntax:

```json
"username": "${TEST_USER}",
"password": "${TEST_PASS}"
```

If the referenced variable is not set at runtime, `load_config()` raises an error and the scan is aborted.

---

## Complete example

See [`configs/deep_scan.json`](../configs/deep_scan.json) for a full production-ready configuration.
