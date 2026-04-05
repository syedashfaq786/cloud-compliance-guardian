"""
CLI Interface — Rich terminal output for the Invecto Compliance Guard auditor.

Usage:
    python -m auditor scan ./terraform-directory
    python -m auditor scan ./terraform-directory --json
    python -m auditor scan ./terraform-directory --severity critical,high
"""

import argparse
import json
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box

from .audit import run_audit, AuditReport


console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def _print_banner():
    banner = Text()
    banner.append("☁️  Invecto Compliance Guard", style="bold cyan")
    banner.append("\n   CIS Benchmark Auditor powered by Cisco Sec-8B", style="dim")
    console.print(Panel(banner, border_style="cyan", padding=(1, 2)))


def _print_scorecard(report: AuditReport):
    score = report.compliance_score
    if score >= 90:
        score_style = "bold green"
        grade = "A"
    elif score >= 75:
        score_style = "bold yellow"
        grade = "B"
    elif score >= 60:
        score_style = "bold orange1"
        grade = "C"
    else:
        score_style = "bold red"
        grade = "F"

    score_text = Text()
    score_text.append(f"  Grade: {grade}  ", style=score_style)
    score_text.append(f"  Score: {score}%  ", style=score_style)

    stats = Table(show_header=False, box=None, padding=(0, 2))
    stats.add_column("label", style="dim")
    stats.add_column("value", style="bold")
    stats.add_row("Files Scanned", str(report.files_scanned))
    stats.add_row("Resources Scanned", str(report.resources_scanned))
    stats.add_row("Total Findings", str(report.total_findings))

    severity_row = Text()
    for sev, count in report.severity_counts.items():
        if count > 0:
            severity_row.append(f" {SEVERITY_ICONS.get(sev, '⬜')} {sev}: {count} ", style=SEVERITY_COLORS.get(sev, ""))
            severity_row.append("  ")

    console.print()
    console.print(Panel(
        Columns([score_text, stats]),
        title="[bold]Compliance Scorecard[/bold]",
        border_style="cyan",
    ))
    if severity_row:
        console.print(severity_row)
    console.print()


def _print_findings_table(report: AuditReport):
    if not report.findings:
        console.print("  [green]✅ No violations found! All resources are compliant.[/green]\n")
        return

    table = Table(
        title="Findings",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("CIS Rule", style="bold", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Resource", style="cyan", width=30)
    table.add_column("Description", width=50)
    table.add_column("File", style="dim", width=25)

    for i, finding in enumerate(report.findings, 1):
        sev = finding.get("severity", "MEDIUM")
        sev_text = Text(f"{SEVERITY_ICONS.get(sev, '⬜')} {sev}", style=SEVERITY_COLORS.get(sev, ""))
        table.add_row(
            str(i),
            f"CIS {finding.get('rule_id', '?')}",
            sev_text,
            finding.get("resource_address", "?"),
            finding.get("description", "")[:80],
            finding.get("file_path", "?"),
        )

    console.print(table)
    console.print()


def _print_remediations(report: AuditReport):
    remediation_findings = [f for f in report.findings if f.get("remediation_hcl")]
    if not remediation_findings:
        return

    console.print("[bold]Remediation Snippets:[/bold]\n")
    for finding in remediation_findings:
        rule_id = finding.get("rule_id", "?")
        resource = finding.get("resource_address", "?")
        hcl_code = finding.get("remediation_hcl", "")

        console.print(f"  [bold cyan]CIS {rule_id}[/bold cyan] — {resource}")
        console.print(Panel(
            hcl_code,
            title="Fix (HCL)",
            border_style="green",
            padding=(0, 1),
        ))
        console.print()


def _print_errors(report: AuditReport):
    if not report.parse_errors:
        return
    console.print("[yellow]⚠️  Parse Errors:[/yellow]")
    for err in report.parse_errors:
        console.print(f"  • {err['file']}: {err['error']}")
    console.print()


def cmd_scan(args):
    """Execute the scan command."""
    _print_banner()
    console.print(f"  [dim]Scanning:[/dim] {args.directory}")
    console.print(f"  [dim]Endpoint:[/dim] {args.endpoint or 'http://localhost:11434'}")
    console.print()

    with console.status("[cyan]Analyzing Terraform resources with Sec-8B...[/cyan]"):
        report = run_audit(
            directory=args.directory,
            endpoint=args.endpoint,
            model=args.model,
            backend=args.backend,
            triggered_by="cli",
            store_results=not args.no_store,
        )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    _print_scorecard(report)
    _print_findings_table(report)
    _print_remediations(report)
    _print_errors(report)

    # Exit code based on findings
    if args.fail_on and report.has_critical:
        console.print("[red]❌ CRITICAL violations found — failing.[/red]")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="☁️  Invecto Compliance Guard — AI-powered Terraform CIS Benchmark auditor",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan command ──────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan a Terraform directory for CIS violations")
    scan_parser.add_argument("directory", help="Path to Terraform files")
    scan_parser.add_argument("--endpoint", help="Sec-8B model endpoint URL")
    scan_parser.add_argument("--model", help="Model name (default: cisco-sec-8b)")
    scan_parser.add_argument("--backend", choices=["ollama", "vllm"], help="Inference backend")
    scan_parser.add_argument("--json", action="store_true", help="Output results as JSON")
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium"], help="Exit code 1 if findings at this severity or above")
    scan_parser.add_argument("--no-store", action="store_true", help="Don't persist results to database")
    scan_parser.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
