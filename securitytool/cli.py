import click
import logging
from pythonjsonlogger import jsonlogger
from securitytool.config import load_config

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
def main(target, config_path, scan_mode, report_format, threshold, non_destructive, output_dir):
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

    # CLI flags override config file values
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

if __name__ == "__main__":
    main()