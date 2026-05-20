import click
import json
import logging
import sys
from pythonjsonlogger import jsonlogger
from securitytool.config import load_config
from securitytool.tomcat.headerscheck import check_security_headers
from securitytool.tomcat.baselinecheck import run_baseline_checks
from securitytool.tomcat.webxmlcheck import run_webxml_checks
from securitytool.dast.zaprunner import run_zap_scan
from securitytool.dast.parsers import normalize_alerts


def setup_logger():
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


@click.command()
@click.option("--target", default=None, help="Base URL of the target application")
@click.option("--config", "config_path", default=None, help="Path to config file (JSON or YAML)")
@click.option("--scan-mode", default="quick", type=click.Choice(["quick", "deep"]), help="Scan mode: quick (PR) or deep (nightly)")
@click.option("--report-format", default="json,html,csv", help="Output formats (comma-separated): json, html, csv")
@click.option("--threshold", default="High", help="Severity threshold for CI gate (e.g. High, Critical)")
@click.option("--fail-on", default=None, help="Alias for --threshold (overrides if set)")
@click.option("--max-high", default=0, type=int, help="Max allowed High findings before pipeline fails (0 = none)")
@click.option("--max-medium", default=-1, type=int, help="Max allowed Medium findings (-1 = unlimited)")
@click.option("--max-duration-minutes", default=30, type=int, help="Maximum active scan duration in minutes")
@click.option("--non-destructive/--destructive", default=True, help="Safe mode: limit payload aggressiveness")
@click.option("--output-dir", default="artifacts", help="Output directory for reports")
@click.option("--tomcat", "run_tomcat", is_flag=True, default=False, help="Run Tomcat hardening checks")
@click.option("--dast", "run_dast", is_flag=True, default=False, help="Run DAST scan via ZAP")
@click.option("--discover", "run_discover", is_flag=True, default=False, help="Run discovery crawl and endpoint inventory")
@click.option("--include", "include_patterns", multiple=True, help="URL patterns to include in scan scope")
@click.option("--exclude", "exclude_patterns", multiple=True, help="URL patterns to exclude from scan scope")
@click.option("--auth-type", default=None, help="Auth method: form, token, basic")
@click.option("--auth-login-url", default=None, help="Login URL for form-based auth")
@click.option("--auth-username", default=None, help="Auth username (prefer env var TEST_USER)")
@click.option("--auth-password", default=None, help="Auth password (prefer env var TEST_PASS)")
@click.option("--auth-username-field", default="username", help="Login form username field name")
@click.option("--auth-password-field", default="password", help="Login form password field name")
def main(
    target, config_path, scan_mode, report_format, threshold, fail_on,
    max_high, max_medium, max_duration_minutes, non_destructive, output_dir,
    run_tomcat, run_dast, run_discover, include_patterns, exclude_patterns,
    auth_type, auth_login_url, auth_username, auth_password,
    auth_username_field, auth_password_field,
):
    """Aysal Shield — Enterprise Web Application Security Automation Platform"""

    logger = setup_logger()

    # No args → interactive mode
    if not target and not config_path:
        logging.disable(logging.CRITICAL)
        from securitytool.interactive import run_interactive
        run_interactive()
        return

    logger.info("Aysal Shield starting", extra={"version": "0.1.0"})

    config = {}

    if config_path:
        try:
            config = load_config(config_path)
            logger.info("Config loaded", extra={"path": config_path})
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)

    # CLI flags override config file values
    if target:
        config["target"] = target

    if "target" not in config:
        logger.error("No target specified. Use --target or provide in config file.")
        sys.exit(1)

    # Build auth config from CLI flags if --auth-type given
    if auth_type:
        config["auth"] = {
            "type": auth_type,
            "login_url": auth_login_url or f"{config['target']}/login",
            "username": auth_username or "",
            "password": auth_password or "",
            "username_field": auth_username_field,
            "password_field": auth_password_field,
        }

    # --fail-on overrides --threshold if provided
    effective_threshold = fail_on if fail_on else threshold

    # resolve max_duration from config if not overridden on CLI
    effective_max_duration = max_duration_minutes
    if config.get("scan", {}).get("max_duration_minutes"):
        effective_max_duration = config["scan"]["max_duration_minutes"]

    # resolve formats
    requested_formats = {f.strip().lower() for f in report_format.split(",")}
    if config.get("report", {}).get("formats"):
        requested_formats = set(config["report"]["formats"])

    # effective output dir
    effective_output_dir = output_dir
    if config.get("report", {}).get("output_dir"):
        effective_output_dir = config["report"]["output_dir"]

    logger.info("Configuration ready", extra={
        "target": config["target"],
        "scan_mode": scan_mode,
        "threshold": effective_threshold,
        "non_destructive": non_destructive,
        "formats": list(requested_formats),
    })

    full_report = {}
    dast_report = {}
    threshold_result = None
    raw_results = {}

    # -----------------------------------------------------------------------
    # Tomcat hardening
    # -----------------------------------------------------------------------
    if run_tomcat:
        target_url = config["target"]
        logger.info("Starting Tomcat hardening checks", extra={"target": target_url})

        headers_result = check_security_headers(target_url)
        baseline_result = run_baseline_checks(target_url)
        webxml_result = run_webxml_checks(target_url)

        full_report = {
            "tomcat_hardening": [headers_result, baseline_result, webxml_result]
        }
        logger.info("Tomcat hardening complete")

    # -----------------------------------------------------------------------
    # Discovery / crawl
    # -----------------------------------------------------------------------
    if run_discover:
        from securitytool.discovery.crawler import crawl_unauthenticated, crawl_authenticated
        from securitytool.discovery.inventory import build_inventory, save_inventory

        target_url = config["target"]
        logger.info("Starting discovery crawl", extra={"target": target_url})

        auth_config = config.get("auth")
        if auth_config and auth_config.get("type") == "form":
            endpoints = crawl_authenticated(target_url, auth_config)
        else:
            endpoints = crawl_unauthenticated(target_url)

        inventory = build_inventory(endpoints)
        saved_path = save_inventory(inventory, effective_output_dir)

        logger.info("Discovery complete", extra={
            "total_endpoints": inventory["total"],
            "forms_found": inventory["forms_found"],
            "path": saved_path,
        })

    # -----------------------------------------------------------------------
    # DAST scan
    # -----------------------------------------------------------------------
    if run_dast:
        target_url = config["target"]
        logger.info("Starting DAST scan", extra={"target": target_url, "mode": scan_mode})

        scan_policies = config.get("scan", {}).get("policies")
        effective_non_destructive = non_destructive
        if config.get("scan", {}).get("non_destructive") is not None:
            effective_non_destructive = config["scan"]["non_destructive"]

        raw_results = run_zap_scan(
            target=target_url,
            non_destructive=effective_non_destructive,
            max_duration=effective_max_duration,
            scan_mode=scan_mode,
            include_patterns=list(include_patterns) if include_patterns else config.get("include"),
            exclude_patterns=list(exclude_patterns) if exclude_patterns else config.get("exclude"),
            auth_config=config.get("auth"),
            scan_policies=scan_policies,
        )

        if "error" in raw_results:
            logger.error("DAST scan failed", extra={"error": raw_results["error"]})
        else:
            normalized = normalize_alerts(raw_results["results"])
            dast_report = {
                "dast_scan": {
                    "target": target_url,
                    "scan_mode": scan_mode,
                    "total_findings": len(normalized),
                    "findings": normalized,
                }
            }
            logger.info("DAST scan complete", extra={"findings": len(normalized)})

            from securitytool.ci.thresholds import check_thresholds
            threshold_result = check_thresholds(
                findings=normalized,
                fail_on=effective_threshold,
                max_high=max_high,
                max_medium=max_medium,
            )

    # -----------------------------------------------------------------------
    # Reporting
    # -----------------------------------------------------------------------
    if run_tomcat or run_dast:
        from securitytool.reporting.htmlreport import save_html_report
        from securitytool.reporting.jsonreport import save_json_report
        from securitytool.reporting.csvexport import save_csv_report

        unified = {
            "tomcat_hardening": full_report.get("tomcat_hardening", []),
            "dast_scan": dast_report.get("dast_scan", {}),
        }

        has_tomcat = bool(unified["tomcat_hardening"])
        has_dast = bool(unified["dast_scan"].get("findings"))

        if has_tomcat or has_dast:
            saved = {}
            if "json" in requested_formats:
                saved["json"] = save_json_report(unified, effective_output_dir)
            if "html" in requested_formats:
                saved["html"] = save_html_report(unified, effective_output_dir)
            if "csv" in requested_formats:
                saved["csv"] = save_csv_report(unified, effective_output_dir)

            logger.info("Reports saved", extra=saved)
            combined = {**full_report, **dast_report}
            print(json.dumps(combined, indent=2))
        else:
            logger.warning("No scan results to report — skipping report generation")

    # -----------------------------------------------------------------------
    # CI threshold gate
    # -----------------------------------------------------------------------
    if run_dast and "error" not in raw_results and threshold_result:
        if not threshold_result["passed"]:
            logger.error("Threshold breached — pipeline gate FAILED", extra={
                "breaches": threshold_result["breaches"],
                "counts": threshold_result["severity_counts"],
            })
            sys.exit(1)
        else:
            logger.info("Threshold check passed — pipeline gate OK", extra={
                "counts": threshold_result["severity_counts"],
            })


if __name__ == "__main__":
    main()
