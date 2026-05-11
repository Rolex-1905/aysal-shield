import click
import json
import logging
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
@click.option("--config", "config_path", default=None, help="Path to config file")
@click.option("--scan-mode", default="quick", type=click.Choice(["quick", "deep"]), help="Scan mode profile")
@click.option("--report-format", default="json", help="Output formats: json, html, csv")
@click.option("--threshold", default="High", help="Severity threshold for CI gate")
@click.option("--non-destructive", is_flag=True, default=True, help="Enable safe mode")
@click.option("--output-dir", default="artifacts", help="Output directory for reports")
@click.option("--tomcat", "run_tomcat", is_flag=True, default=False, help="Run Tomcat hardening checks")
@click.option("--dast", "run_dast", is_flag=True, default=False, help="Run DAST scan via ZAP")
@click.option("--include", "include_patterns", multiple=True, help="URL patterns to include in scan scope")
@click.option("--exclude", "exclude_patterns", multiple=True, help="URL patterns to exclude from scan scope")
@click.option("--discover", "run_discover", is_flag=True, default=False, help="Run discovery crawl and endpoint inventory")

def main(target, config_path, scan_mode, report_format, threshold, non_destructive, output_dir, run_tomcat, run_dast, include_patterns, exclude_patterns, run_discover):
    """TomcatShield — Enterprise Web Application Security Automation Platform"""

    logger = setup_logger()

    if not target and not config_path:
        import logging
        logging.disable(logging.CRITICAL)
        from securitytool.interactive import run_interactive
        run_interactive()
        return

    logger.info("AYSAL Shield starting", extra={"version": "1.0.0"})

    config = {}

    if config_path:
        try:
            config = load_config(config_path)
            logger.info("Config loaded", extra={"path": config_path})
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise SystemExit(1)

    if target:
        config["target"] = target
    if "target" not in config:
        logger.error("No target specified. Use --target or provide in config file.")
        raise SystemExit(1)

    logger.info("Configuration ready", extra={
        "target": config.get("target"),
        "scan_mode": scan_mode,
        "threshold": threshold,
        "non_destructive": non_destructive
    })

    full_report = {}
    dast_report = {}
    threshold_result = None
    raw_results = {}

    if run_tomcat:
        target_url = config["target"]
        logger.info("Starting Tomcat hardening checks", extra={"target": target_url})

        headers_result = check_security_headers(target_url)
        baseline_result = run_baseline_checks(target_url)
        webxml_result = run_webxml_checks(target_url)

        full_report = {
            "tomcat_hardening": [
                headers_result,
                baseline_result,
                webxml_result
            ]
        }
        logger.info("Tomcat scan complete")

    if run_discover:
        from securitytool.discovery.crawler import crawl_unauthenticated, crawl_authenticated
        from securitytool.discovery.inventory import build_inventory, save_inventory

        target_url = config["target"]
        logger.info("Starting discovery crawl", extra={"target": target_url})

        auth_config = config.get("auth", None)
        if auth_config and auth_config.get("type") == "form":
            endpoints = crawl_authenticated(target_url, auth_config)
        else:
            endpoints = crawl_unauthenticated(target_url)

        inventory = build_inventory(endpoints)
        saved_path = save_inventory(inventory, output_dir)

        logger.info("Discovery complete", extra={
            "total_endpoints": inventory["total"],
            "forms_found": inventory["forms_found"],
            "path": saved_path
        })

    if run_dast:
        target_url = config["target"]
        logger.info("Starting DAST scan", extra={"target": target_url})

        raw_results = run_zap_scan(
            target=target_url,
            non_destructive=non_destructive,
            max_duration=30,
            scan_mode=scan_mode,
            include_patterns=list(include_patterns) if include_patterns else config.get("include", None),
            exclude_patterns=list(exclude_patterns) if exclude_patterns else config.get("exclude", None),
            auth_config=config.get("auth", None)
        )

        if "error" in raw_results:
            logger.error("DAST scan failed", extra={"error": raw_results["error"]})
        else:
            normalized = normalize_alerts(raw_results["results"])
            dast_report = {
                "dast_scan": {
                    "target": target_url,
                    "total_findings": len(normalized),
                    "findings": normalized
                }
            }
            logger.info("DAST scan complete", extra={"findings": len(normalized)})

            from securitytool.ci.thresholds import check_thresholds
            threshold_result = check_thresholds(
                findings=normalized,
                fail_on=threshold,
                max_high=0,
                max_medium=-1
            )

    if run_tomcat or run_dast:
        from securitytool.reporting.htmlreport import save_html_report
        from securitytool.reporting.jsonreport import save_json_report
        from securitytool.reporting.csvexport import save_csv_report

        unified = {
            "tomcat_hardening": full_report.get("tomcat_hardening", []),
            "dast_scan": dast_report.get("dast_scan", {})
        }

        has_tomcat = len(unified["tomcat_hardening"]) > 0
        has_dast = len(unified["dast_scan"].get("findings", [])) > 0

        if has_tomcat or has_dast:
            saved_html = save_html_report(unified, output_dir)
            saved_json = save_json_report(unified, output_dir)
            saved_csv = save_csv_report(unified, output_dir)
            logger.info("Reports saved", extra={
                "html": saved_html,
                "json": saved_json,
                "csv": saved_csv
            })
            combined = {**full_report, **dast_report}
            print(json.dumps(combined, indent=2))
        else:
            logger.warning("No scan results to save - skipping report generation")

    if run_dast and "error" not in raw_results and threshold_result:
        if not threshold_result["passed"]:
            logger.error("Threshold breached - pipeline gate FAILED", extra={
                "breaches": threshold_result["breaches"],
                "counts": threshold_result["severity_counts"]
            })
            raise SystemExit(1)
        else:
            logger.info("Threshold check passed - pipeline gate OK", extra={
                "counts": threshold_result["severity_counts"]
            })

if __name__ == "__main__":
    main()