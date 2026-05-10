import json
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box

console = Console()

def print_banner():
    console.clear()
    banner = Text()
    banner.append(" █████╗ ██╗   ██╗███████╗ █████╗ ██╗         ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ \n", style="bold red")
    banner.append("██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗██║         ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗\n", style="bold red")
    banner.append("███████║ ╚████╔╝ ███████╗███████║██║         ███████╗███████║██║█████╗  ██║     ██║  ██║\n", style="bold red")
    banner.append("██╔══██║  ╚██╔╝  ╚════██║██╔══██║██║         ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║\n", style="bold red")
    banner.append("██║  ██║   ██║   ███████║██║  ██║███████╗    ███████║██║  ██║██║███████╗███████╗██████╔╝\n", style="bold red")
    banner.append("╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ \n", style="bold red")
    banner.append("                                        SHIELD\n", style="bold white")
    banner.append("                     Enterprise Web Application Security Platform\n", style="dim white")
    banner.append("                                         v1.0.0\n", style="dim white")
    banner.append("                             Developed by Neeraj Mudunuru\n", style="bold cyan")
    console.print(Panel(banner, border_style="red", padding=(1, 4)))


def print_menu():
    table = Table(box=box.ROUNDED, border_style="blue", show_header=False, padding=(0, 2))
    table.add_column("Option", style="bold yellow", width=6)
    table.add_column("Description", style="white")
    table.add_row("[1]", "Run Tomcat Hardening Scan")
    table.add_row("[2]", "Run DAST Scan (ZAP)")
    table.add_row("[3]", "Run Full Scan (Tomcat + DAST)")
    table.add_row("[4]", "View Last Report")
    table.add_row("[5]", "Configure Target")
    table.add_row("[0]", "Exit")
    console.print(Panel(table, title="[bold blue]Main Menu[/bold blue]", border_style="blue"))


def configure_target(config: dict) -> dict:
    console.print(Panel("[bold]Target Configuration[/bold]", border_style="yellow"))
    target = Prompt.ask("Enter target URL", default=config.get("target", "http://"))
    config["target"] = target
    use_auth = Confirm.ask("Does the target require authentication?", default=False)
    if use_auth:
        auth_type = Prompt.ask("Auth type", choices=["form", "basic", "token"], default="form")
        config["auth"] = {"type": auth_type}
        console.print("[yellow]Credentials will be loaded from environment variables TEST_USER and TEST_PASS[/yellow]")
    threshold = Prompt.ask("Severity threshold for CI gate",
                           choices=["Informational", "Low", "Medium", "High", "Critical"],
                           default="High")
    config["threshold"] = threshold
    console.print(f"\n[green]✓ Target configured: {target}[/green]")
    return config


def display_tomcat_results(report: dict):
    console.print(Panel("[bold]Tomcat Hardening Results[/bold]", border_style="green"))
    for module in report.get("tomcat_hardening", []):
        if module.get("error"):
            console.print(f"[red]✗ {module['error']}[/red]")
            continue
        module_name = module.get("module", "unknown").replace("_", " ").title()
        summary = module.get("summary", {})
        table = Table(
            title=f"{module_name}  |  Passed: {summary.get('passed', 0)}  Failed: {summary.get('failed', 0)}",
            box=box.SIMPLE,
            border_style="dim"
        )
        table.add_column("Status", width=8)
        table.add_column("Check", style="white")
        table.add_column("Evidence", style="dim", max_width=60)
        for result in module.get("results", []):
            status = result.get("status", "")
            if status == "PASS":
                status_text = "[green]PASS[/green]"
            elif status == "FAIL":
                status_text = "[red]FAIL[/red]"
            else:
                status_text = "[yellow]ERROR[/yellow]"
            table.add_row(status_text, result.get("check", ""), result.get("evidence", "")[:80])
        console.print(table)


def display_dast_results(report: dict):
    console.print(Panel("[bold]DAST Scan Results[/bold]", border_style="red"))
    dast = report.get("dast_scan", {})
    total = dast.get("total_findings", 0)
    console.print(f"[bold]Total Findings: {total}[/bold]\n")
    table = Table(box=box.ROUNDED, border_style="dim")
    table.add_column("Severity", width=14)
    table.add_column("Finding", style="white")
    table.add_column("URL", style="dim", max_width=50)
    severity_styles = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "blue",
        "Informational": "dim"
    }
    for finding in dast.get("findings", []):
        severity = finding.get("severity", "Informational")
        style = severity_styles.get(severity, "white")
        table.add_row(
            f"[{style}]{severity}[/{style}]",
            finding.get("name", ""),
            finding.get("url", "")[:60]
        )
    console.print(table)


def view_last_report(output_dir: str = "artifacts"):
    if not os.path.exists(output_dir):
        console.print("[yellow]No artifacts directory found. Run a scan first.[/yellow]")
        return
    files = [f for f in os.listdir(output_dir) if f.endswith(".json")]
    if not files:
        console.print("[yellow]No reports found. Run a scan first.[/yellow]")
        return
    latest = sorted(files)[-1]
    filepath = os.path.join(output_dir, latest)
    with open(filepath) as f:
        report = json.load(f)
    console.print(f"[dim]Loading: {filepath}[/dim]\n")
    if "tomcat_hardening" in report.get("report", {}):
        display_tomcat_results(report["report"])
    elif "dast_scan" in report.get("report", {}):
        display_dast_results(report["report"])
    else:
        console.print_json(json.dumps(report, indent=2))


def run_interactive():
    from securitytool.config import load_config

    config = {}
    try:
        config = load_config("configs/dev.json")
    except Exception:
        pass

    while True:
        print_banner()
        print_menu()

        choice = Prompt.ask("[bold yellow]Select option[/bold yellow]",
                            choices=["0", "1", "2", "3", "4", "5"])

        if choice == "0":
            console.print("\n[bold red]Exiting AYSAL Shield. Goodbye.[/bold red]\n")
            break

        elif choice == "5":
            config = configure_target(config)
            Prompt.ask("\nPress Enter to continue")

        elif choice in ["1", "2", "3"]:
            console.print(Panel("[bold]Scan Configuration[/bold]", border_style="yellow"))

            target = Prompt.ask("Enter target URL", default=config.get("target", "http://"))
            config["target"] = target

            output_dir = Prompt.ask("Output directory for reports", default="artifacts")

            threshold = Prompt.ask(
                "Severity threshold for CI gate",
                choices=["Informational", "Low", "Medium", "High", "Critical"],
                default="High"
            )

            scan_mode = Prompt.ask("Scan mode", choices=["quick", "deep"], default="quick")

            non_destructive = Confirm.ask("Enable safe mode (non-destructive)?", default=True)

            if choice in ["2", "3"]:
                max_duration = int(Prompt.ask("Maximum scan duration (minutes)", default="30"))
            else:
                max_duration = 30

            console.print(f"\n[dim]Target: {target}[/dim]")
            console.print(f"[dim]Mode: {scan_mode} | Threshold: {threshold} | Safe mode: {non_destructive}[/dim]\n")

            confirm = Confirm.ask("Start scan?", default=True)
            if not confirm:
                Prompt.ask("\nPress Enter to continue")
                continue

            if choice in ["1", "3"]:
                from securitytool.tomcat.headerscheck import check_security_headers
                from securitytool.tomcat.baselinecheck import run_baseline_checks
                from securitytool.tomcat.webxmlcheck import run_webxml_checks
                from securitytool.reporting.jsonreport import save_json_report
                from securitytool.reporting.htmlreport import save_html_report
                from securitytool.reporting.csvexport import save_csv_report

                with console.status("[bold green]Running Tomcat hardening checks...[/bold green]"):
                    headers_result = check_security_headers(target)
                    baseline_result = run_baseline_checks(target)
                    webxml_result = run_webxml_checks(target)

                full_report = {
                    "tomcat_hardening": [headers_result, baseline_result, webxml_result]
                }

                save_json_report(full_report, output_dir)
                save_html_report(full_report, output_dir)
                save_csv_report(full_report, output_dir)
                display_tomcat_results(full_report)

            if choice in ["2", "3"]:
                from securitytool.dast.zaprunner import run_zap_scan
                from securitytool.dast.parsers import normalize_alerts
                from securitytool.reporting.jsonreport import save_json_report
                from securitytool.ci.thresholds import check_thresholds

                with console.status("[bold red]Running DAST scan via ZAP...[/bold red]"):
                    raw_results = run_zap_scan(
                        target=target,
                        non_destructive=non_destructive,
                        max_duration=max_duration
                    )

                if "error" in raw_results:
                    console.print(f"[red]DAST scan failed: {raw_results['error']}[/red]")
                else:
                    normalized = normalize_alerts(raw_results["results"])
                    dast_report = {
                        "dast_scan": {
                            "target": target,
                            "total_findings": len(normalized),
                            "findings": normalized
                        }
                    }
                    save_json_report(dast_report, output_dir)
                    display_dast_results(dast_report)

                    threshold_result = check_thresholds(normalized, fail_on=threshold)
                    if not threshold_result["passed"]:
                        console.print(f"\n[bold red]⚠ THRESHOLD BREACHED — Pipeline gate FAILED[/bold red]")
                        for breach in threshold_result["breaches"]:
                            console.print(f"[red]  • {breach}[/red]")
                    else:
                        console.print(f"\n[bold green]✓ Threshold check passed — Pipeline gate OK[/bold green]")

            Prompt.ask("\nPress Enter to continue")

        elif choice == "4":
            view_last_report()
            Prompt.ask("\nPress Enter to continue")