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
def main(target, config_path, scan_mode, report_format, threshold, non_destructive, output_dir, run_tomcat, run_dast):
    """TomcatShield — Enterprise Web Application Security Automation Platform"""

    logger = setup_logger()
    logger.info("TomcatShield starting", extra={"version": "1.0.0"})

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

        from securitytool.reporting.jsonreport import save_json_report
        from securitytool.reporting.htmlreport import save_html_report
        from securitytool.reporting.csvexport import save_csv_report
        saved_json = save_json_report(full_report, output_dir)
        saved_html = save_html_report(full_report, output_dir)
        saved_csv = save_csv_report(full_report, output_dir)
        logger.info("Reports saved", extra={
            "json": saved_json,
            "html": saved_html,
            "csv": saved_csv
        })
        print(json.dumps(full_report, indent=2))

    if run_dast:
        target_url = config["target"]
        logger.info("Starting DAST scan", extra={"target": target_url})

        raw_results = run_zap_scan(
            target=target_url,
            non_destructive=non_destructive,
            max_duration=30
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
            from securitytool.reporting.jsonreport import save_json_report
            saved_path = save_json_report(dast_report, output_dir)
            logger.info("DAST report saved", extra={
                "path": saved_path,
                "findings": len(normalized)
            })
            print(json.dumps(dast_report, indent=2))

if __name__ == "__main__":
    main()