# Aysal Shield — Known Limitations

---

## DAST / ZAP limitations

### False positives
ZAP active scanning can produce false positives on certain patterns:
- **Reflected input without XSS context**: ZAP flags any reflected user input even when it's inside an attribute with proper encoding
- **SQL error messages from valid queries**: some ORMs produce stack trace-like output on valid edge-case queries
- **SSRF on outbound call endpoints**: legitimate webhooks and callback URLs may be flagged

**Mitigation:** Review all High/Critical findings manually before escalating. Use `--non-destructive` mode for lower noise.

### Dynamic / JavaScript-rendered content
The ZAP spider does not execute JavaScript. Single-page applications (React, Vue, Angular) that render routes client-side will have incomplete crawl coverage. The `--discover` crawler uses BeautifulSoup for static HTML only.

**Mitigation:** For SPAs, use ZAP's Ajax Spider (not yet integrated) or supplement with manual URL injection via ZAP's `includeInContext`.

### Authenticated scan session expiry
If a session expires mid-scan (short-lived tokens, session timeouts < scan duration), ZAP will continue scanning as unauthenticated without warning.

**Mitigation:** Ensure `--max-duration-minutes` is set to less than the application's session timeout. Set `logged_out_indicator` so ZAP can detect session expiry.

### WebSocket and GraphQL endpoints
Aysal Shield does not scan WebSocket connections or perform GraphQL-specific testing.

---

## Tomcat hardening limitations

### web.xml access
The `webxmlcheck.py` module infers `web.xml` configuration from HTTP responses (cookie flags, redirect behaviour, error pages). It cannot read the actual `web.xml` file — that would require filesystem access or the Tomcat Manager API.

For a full `web.xml` audit, use a configuration management tool (Ansible, Chef) or manually review the file.

### TLS cipher assessment
TLS cipher check validates the negotiated cipher suite for the tool's connection. It does not enumerate all supported ciphers (which requires a full TLS handshake scanner like testssl.sh or nmap ssl-enum-ciphers).

---

## Coverage

### Endpoint coverage < 80% in large applications
The `--discover` crawl starts from the target URL and follows anchor tags. It will not discover:
- Endpoints only reachable via JavaScript navigation
- API endpoints not linked from any HTML page
- Admin areas not reachable from the crawl start URL

For comprehensive coverage, supplement with a swagger/OpenAPI spec import (not yet implemented).

### Rate limiting on the target
If the target application rate-limits or blocks the scan host's IP, coverage will be incomplete and ZAP may produce false negatives. Use `--max-duration-minutes` and allow-list the scan host IP in the target environment's WAF/firewall.

---

## CI/CD

### ZAP startup time on slow CI runners
ZAP requires 1–3 minutes to start on resource-constrained CI runners. If `wait_for_zap()` times out (default 24 retries × 10s = 4 minutes), increase the `ZAP_STARTUP_RETRIES` environment variable.

### GitLab CI artifact size
Full deep scans can produce HTML reports > 10MB. GitLab's free tier has artifact size limits. Use `--report-format json,csv` for size-sensitive pipelines.
