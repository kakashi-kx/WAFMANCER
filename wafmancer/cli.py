"""
WAFMANCER Command-Line Interface.
Research-grade WAF evasion framework.
"""

import asyncio
import sys
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wafmancer.config import config
from wafmancer.logging_config import setup_logging
from wafmancer.core.oracle import ResponseOracle
from wafmancer.utils.helpers import normalize_target_url

console = Console()

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  ██╗    ██╗ █████╗ ███████╗███╗   ███╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗  ║
║  ██║    ██║██╔══██╗██╔════╝████╗ ████║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗ ║
║  ██║ █╗ ██║███████║█████╗  ██╔████╔██║███████║██╔██╗ ██║██║     █████╗  ██████╔╝ ║
║  ██║███╗██║██╔══██║██╔══╝  ██║╚██╔╝██║██╔══██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗ ║
║  ╚███╔███╔╝██║  ██║██║     ██║ ╚═╝ ██║██║  ██║██║ ╚████║╚██████╗███████╗██║  ██║ ║
║   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ║
║                                                                           v2.0.0 ║
║                    Next-Gen WAF Evasion Research Framework                      ║
║                         Response Oracle Technology                              ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""


@click.group()
@click.version_option(version="2.0.0-dev")
def main():
    """WAFMANCER — Advanced WAF Evasion Research Framework."""
    pass


@main.command()
@click.option("-t", "--target", required=True, help="Target URL to analyze")
@click.option("--probes", default=None, type=int, help="Maximum number of probes")
@click.option("--concurrency", default=None, type=int, help="Maximum concurrent probes")
@click.option("--output", "-o", default=None, help="Output file for research report")
def oracle(target, probes, concurrency, output):
    """
    Run the Response Oracle against a target.

    Maps WAF decision boundaries through systematic probing.
    Produces a comprehensive research report of all findings.
    """
    console.print(BANNER)
    console.print(f"[bold cyan]🎯 Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]🔬 Mode:[/bold cyan] Response Oracle Research Engine\n")

    # Normalize target
    target_url = normalize_target_url(target)

    # Override config with CLI options
    if probes:
        config._config["oracle"]["max_probes"] = probes
    if concurrency:
        config._config["oracle"]["concurrency"] = concurrency

    # Run oracle
    oracle_engine = ResponseOracle(target_url)

    async def run_oracle():
        session = await oracle_engine.run()
        return session

    try:
        session = asyncio.run(run_oracle())

        # Display results
        stats = session.statistics
        results_table = Table(title="Oracle Research Results")
        results_table.add_column("Metric", style="cyan")
        results_table.add_column("Value", style="green")

        results_table.add_row("Total Probes", str(stats["total_probes"]))
        results_table.add_row("Anomalies Detected", str(stats["anomalies_found"]))
        results_table.add_row("Anomaly Rate", f"{stats['anomaly_rate']:.1%}")
        results_table.add_row("Bypass Candidates", str(stats["bypass_count"]))
        results_table.add_row("High/Critical Findings", str(stats["high_severity_count"]))

        console.print(results_table)

        if session.anomalies:
            console.print("\n[bold yellow]⚠️  Anomalies Found:[/bold yellow]")
            for anomaly in session.anomalies:
                severity_color = {
                    "CRITICAL": "red",
                    "HIGH": "yellow",
                    "MEDIUM": "blue",
                    "LOW": "green",
                    "NONE": "white",
                }.get(anomaly.severity.name, "white")

                console.print(Panel(
                    "\n".join(f"• {a}" for a in anomaly.anomalies),
                    title=f"[{severity_color}]{anomaly.severity.name}[/{severity_color}]",
                    border_style=severity_color,
                ))

        # Generate and save report
        report = oracle_engine.generate_report()
        if output:
            with open(output, "w") as f:
                f.write(report)
            console.print(f"\n📄 Report saved to: [bold]{output}[/bold]")
        else:
            console.print("\n" + report)

    except Exception as e:
        console.print(f"[bold red]❌ Error:[/bold red] {e}")
        sys.exit(1)


@main.command()
def info():
    """Display framework information and configuration."""
    console.print(BANNER)
    console.print("[bold cyan]Current Configuration:[/bold cyan]")
    conf = config.to_dict()
    console.print_json(data=conf)


@main.command()
def modules():
    """List available research modules."""
    console.print(BANNER)
    console.print("[bold cyan]Available Research Modules:[/bold cyan]\n")

    modules_table = Table(title="WAFMANCER Modules")
    modules_table.add_column("Module", style="cyan")
    modules_table.add_column("Status", style="yellow")
    modules_table.add_column("Description", style="white")

    modules_table.add_row(
        "Response Oracle",
        "✅ Active",
        "WAF decision boundary mapping engine"
    )
    modules_table.add_row(
        "Advanced Fuzzer",
        "✅ Active",
        "Differential fuzzing with anomaly detection"
    )
    modules_table.add_row(
        "Neuro-Camouflage",
        "🔜 Phase 3",
        "AI-powered payload mutation and evasion"
    )
    modules_table.add_row(
        "QUIC-Strike",
        "🔜 Phase 3",
        "HTTP/3 0-RTT smuggling exploitation"
    )

    console.print(modules_table)


if __name__ == "__main__":
    main()
