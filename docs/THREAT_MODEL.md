# Aysal Shield — Threat Model

## 1. Assumptions

- Target environment is a **Dev/QA Apache Tomcat instance** — never production.
- Explicit written authorization to scan has been obtained before any scan run.
- Test credentials use dedicated test accounts with no access to real customer data.
- The scan host is network-adjacent to the target (no WAF blocking scan traffic in test env).
- Destructive payloads are disabled by default (`non_destructive: true`).

## 2. Assets Under Protection

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| User credentials (JSESSIONID, passwords) | High | HTTP cookies, POST bodies |
| Application business logic endpoints | High | /api/*, /account/*, /admin/* |
| Tomcat manager interface | Critical | /manager, /host-manager |
| Server configuration details | Medium | HTTP response headers, error pages |
| User PII in responses | High | Any authenticated endpoint |

## 3. Entry Points

| Entry Point | Attack Vectors | OWASP Category |
|-------------|---------------|----------------|
| Login form (`/login`) | Brute force, SQLi, session fixation | A07, A03 |
| Search / filter params | SQLi, XSS, path traversal | A03 |
| File upload endpoints | Path traversal, RCE via upload | A01, A03 |
| API endpoints (`/api/*`) | SSRF, broken object-level auth, injection | A10, A01, A03 |
| HTTP headers | Response splitting, open redirect | A01 |
| Error pages | Info disclosure (stack traces) | A05 |
| Tomcat management (`/manager`) | Default credential abuse, RCE | A05, A07 |

## 4. OWASP Top 10 Risk Mapping

| OWASP 2021 | Risk | Tool Coverage |
|------------|------|---------------|
| A01 Broken Access Control | Unprotected admin paths, forced browsing | webxmlcheck security constraints |
| A02 Cryptographic Failures | Weak TLS, missing HSTS, session over HTTP | baselinecheck TLS + headerscheck |
| A03 Injection (XSS, SQLi) | Reflected/stored XSS, SQL injection | ZAP active scan policies |
| A05 Security Misconfiguration | Default apps exposed, TRACE enabled, banners | baselinecheck, headerscheck |
| A07 Identification & Auth Failures | Session fixation, no logout invalidation | webxmlcheck functional tests |
| A10 SSRF | Backend requests to internal services | ZAP ssrf policy |

## 5. Mitigations Built Into the Tool

| Risk | Mitigation |
|------|-----------|
| Scanning production accidentally | Config enforces target URL; only Dev/QA in `configs/` |
| Credential leakage | Credentials sourced from env vars only; pre-commit hook blocks hardcoded secrets |
| PII in reports | `utils.redact_pii()` applied to all log and report outputs |
| Destructive payloads | `--non-destructive` is the default; requires explicit override |
| Scan overload on target | `--max-duration-minutes` hard time-box; rate limits configurable |
| Session token exposure in logs | Bearer token and password patterns regex-redacted in `PII_PATTERNS` |

## 6. Test Data Plan

- **Credentials**: Stored in `.env` file (gitignored) or CI secret store. Rotated after each engagement.
- **Test accounts**: Provisioned with role separation — one regular user, one admin user, no production roles.
- **Seed data**: Test application seeded with synthetic data only. No real names, emails, or payment info.
- **Scan artifacts**: Classified internal-confidential. Deleted from CI runner after 30-day retention window.
- **Excluded paths**: `/logout`, `/static/`, `/assets/*` excluded from active scan to avoid disruption.