"""
WAFMANCER Command-Line Interface.
Research-grade WAF evasion framework with Response Oracle Technology.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from wafmancer.config import config
from wafmancer.logging_config import setup_logging
from wafmancer.core.oracle import ResponseOracle
from wafmancer.core.research_store import ResearchStore
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
@click.option("--no-save", is_flag=True, help="Don't save results to research database")
def oracle(target, probes, concurrency, output, no_save):
    """
    Run the Response Oracle against a target.

    Maps WAF decision boundaries through systematic probing.
    Produces a comprehensive research report of all findings.
    Automatically saves results to the research database.
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
        with console.status("[bold green]Oracle analyzing target...[/bold green]", spinner="dots"):
            session = asyncio.run(run_oracle())

        # Display results
        stats = session.statistics

        # --- WAF Fingerprint Panel ---
        if session.waf_fingerprint:
            waf_color = "green" if session.waf_fingerprint.vendor.value != "No WAF Detected" else "yellow"
            fingerprint_text = (
                f"Vendor: {session.waf_fingerprint.vendor.value}\n"
                f"Confidence: {session.waf_fingerprint.confidence:.1%}\n"
                f"Evidence: {len(session.waf_fingerprint.evidence)} indicators"
            )
            console.print(Panel(
                fingerprint_text,
                title=f"[bold {waf_color}]🔍 WAF Fingerprint[/bold {waf_color}]",
                border_style=waf_color,
            ))

        # --- Statistics Table ---
        results_table = Table(title="Oracle Research Results")
        results_table.add_column("Metric", style="cyan")
        results_table.add_column("Value", style="green")

        results_table.add_row("Total Probes", str(stats["total_probes"]))
        results_table.add_row("Anomalies Detected", str(stats["anomalies_found"]))
        results_table.add_row("Anomaly Rate", f"{stats['anomaly_rate']:.1%}")
        results_table.add_row("Bypass Candidates", str(stats["bypass_count"]))
        results_table.add_row("High/Critical Findings", str(stats["high_severity_count"]))

        console.print(results_table)

        # --- Anomaly Details ---
        if session.anomalies:
            console.print("\n[bold yellow]⚠️  Anomalies Found:[/bold yellow]")
            for i, anomaly in enumerate(session.anomalies[:15], 1):  # Show up to 15
                severity_color = {
                    "CRITICAL": "red",
                    "HIGH": "yellow",
                    "MEDIUM": "blue",
                    "LOW": "green",
                    "NONE": "white",
                }.get(anomaly.severity.name, "white")

                anomaly_text = "\n".join(f"• {a}" for a in anomaly.anomalies)
                if anomaly.research_notes:
                    anomaly_text += "\n\n" + "\n".join(f"📝 {n}" for n in anomaly.research_notes)

                if anomaly.is_exploitable:
                    anomaly_text = f"🔥 [bold]POTENTIALLY EXPLOITABLE[/bold] 🔥\n\n{anomaly_text}"

                console.print(Panel(
                    anomaly_text,
                    title=f"[{severity_color}]Finding #{i}: {anomaly.severity.name}[/{severity_color}]",
                    border_style=severity_color,
                ))

            if len(session.anomalies) > 15:
                console.print(f"\n[yellow]... and {len(session.anomalies) - 15} more anomalies. Use --output for full report.[/yellow]")

        # --- WAF-Specific Bypass Suggestions ---
        if session.waf_fingerprint and session.waf_fingerprint.suggested_mutations:
            console.print("\n[bold cyan]💡 Suggested Bypass Techniques for this WAF:[/bold cyan]")
            for mutation in session.waf_fingerprint.suggested_mutations:
                console.print(f"  🧬 {mutation}")

        # --- Known Vulnerabilities ---
        if session.waf_fingerprint and session.waf_fingerprint.known_vulnerabilities:
            console.print("\n[bold cyan]📚 Known Bypass Vectors:[/bold cyan]")
            for vuln in session.waf_fingerprint.known_vulnerabilities:
                console.print(f"  ⚡ {vuln}")

        # --- Generate Report ---
        report = oracle_engine.generate_report()
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report)
            console.print(f"\n📄 Report saved to: [bold]{output}[/bold]")
        else:
            # Save report to default location
            report_dir = Path(config.get("output", "research_dir", default="research"))
            report_dir.mkdir(parents=True, exist_ok=True)
            timestamp = session.start_time.replace(":", "-").replace("T", "_")[:19]
            report_path = report_dir / f"report_{session.target.replace('://', '_').replace('/', '_')}_{timestamp}.md"
            report_path.write_text(report)
            console.print(f"\n📄 Report saved to: [bold]{report_path}[/bold]")

        # --- Save to Research Database ---
        if not no_save:
            try:
                store = ResearchStore()
                session_id = store.save_session(session)
                console.print(f"💾 [bold green]Session saved to research database (ID: {session_id})[/bold green]")
                store.close()
            except Exception as e:
                console.print(f"[yellow]⚠️  Could not save to database: {e}[/yellow]")

    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}")
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
        "WAF decision boundary mapping engine with WAF fingerprinting"
    )
    modules_table.add_row(
        "Smart Mutation Engine",
        "✅ Active",
        "WAF-specific targeted mutation generation"
    )
    modules_table.add_row(
        "Research Store",
        "✅ Active",
        "Persistent findings database with export capabilities"
    )
    modules_table.add_row(
        "Advanced Fuzzer",
        "✅ Active",
        "Differential fuzzing with anomaly detection"
    )
    modules_table.add_row(
        "WAF Fingerprinter",
        "✅ Active",
        "Passive WAF detection through multi-vector analysis"
    )
    modules_table.add_row(
        "Neuro-Camouflage",
        "🔜 Phase 4",
        "AI-powered payload mutation and evasion"
    )
    modules_table.add_row(
        "QUIC-Strike",
        "🔜 Phase 4",
        "HTTP/3 0-RTT smuggling exploitation"
    )

    console.print(modules_table)


@main.command()
@click.option("-t", "--target", default=None, help="Filter by target URL")
@click.option("--limit", default=50, type=int, help="Maximum sessions to display")
def history(target, limit):
    """View research session history."""
    console.print(BANNER)
    console.print("[bold cyan]📋 Research Session History[/bold cyan]\n")

    store = ResearchStore()
    sessions = store.get_session_history(target)

    if not sessions:
        console.print("[yellow]No research sessions found. Run 'wafmancer oracle' first![/yellow]")
        store.close()
        return

    # Limit results
    sessions = sessions[:limit]

    # Create results table
    title = f"Research Session History{' for ' + target if target else ''} (Showing {len(sessions)} of {len(store.get_session_history(target))} total)"
    table = Table(title=title)
    table.add_column("ID", style="cyan", width=6)
    table.add_column("Target", style="white", width=45)
    table.add_column("Date", style="blue", width=20)
    table.add_column("WAF", style="yellow", width=22)
    table.add_column("Probes", style="green", width=8)
    table.add_column("Anomalies", style="red", width=10)
    table.add_column("Bypasses", style="bold red", width=10)

    for session in sessions:
        # Truncate long targets
        target_display = session["target"]
        if len(target_display) > 42:
            target_display = target_display[:39] + "..."

        # Format date
        date_display = "N/A"
        if session.get("start_time"):
            date_display = session["start_time"][:19].replace("T", " ")

        # Color code WAF column
        waf = session.get("waf_vendor") or "Unknown"
        if waf == "No WAF Detected":
            waf_color = "green"
        elif waf == "Unknown":
            waf_color = "white"
        else:
            waf_color = "yellow"

        table.add_row(
            str(session["id"]),
            target_display,
            date_display,
            f"[{waf_color}]{waf[:20]}[/{waf_color}]",
            str(session.get("total_probes", 0)),
            str(session.get("anomalies_found", 0)),
            str(session.get("bypass_count", 0)),
        )

    console.print(table)

    # Quick stats
    total_anomalies = sum(s.get("anomalies_found", 0) for s in sessions)
    total_bypasses = sum(s.get("bypass_count", 0) for s in sessions)
    console.print(f"\n[bold]Summary:[/bold] {total_anomalies} anomalies, {total_bypasses} bypass candidates across {len(sessions)} sessions")

    store.close()


@main.command()
@click.option("--format", "fmt", type=click.Choice(["markdown", "json"]), default="markdown",
              help="Export format")
@click.option("-o", "--output", default=None, help="Output file path")
@click.option("--severity", default=None, 
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              help="Filter by severity")
@click.option("--vendor", default=None, help="Filter by WAF vendor")
@click.option("--exploitable-only", is_flag=True, help="Only export exploitable findings")
@click.option("--cve-candidates", is_flag=True, help="Only export CVE candidates")
def export(fmt, output, severity, vendor, exploitable_only, cve_candidates):
    """Export research findings for publication."""
    console.print(BANNER)
    console.print("[bold cyan]📊 Exporting Research Findings[/bold cyan]\n")

    store = ResearchStore()

    # Show quick stats first
    stats = store.get_statistics()
    stats_table = Table(title="Research Database Statistics")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")

    stats_table.add_row("Total Sessions", str(stats["total_sessions"]))
    stats_table.add_row("Total Probes", str(stats["total_probes"]))
    stats_table.add_row("Exploitable Findings", str(stats["exploitable_findings"]))
    stats_table.add_row("CVE Candidates", str(stats["cve_candidates"]))

    total_findings = sum(stats.get("findings_by_severity", {}).values())
    stats_table.add_row("Total Findings", str(total_findings))

    console.print(stats_table)

    # Show severity breakdown
    if stats.get("findings_by_severity"):
        console.print("\n[bold]Findings by Severity:[/bold]")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats["findings_by_severity"].get(sev, 0)
            if count > 0:
                color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}[sev]
                bar = "█" * min(count, 50)
                console.print(f"  [{color}]{sev:10s}[/{color}] {count:4d} {bar}")

    if fmt == "markdown":
        output_path = Path(output) if output else Path(
            config.get("output", "research_dir", default="research")
        ) / "findings_export.md"

        store.export_findings_markdown(output_path)
        console.print(f"\n✅ [bold green]Findings exported to: {output_path}[/bold green]")
        console.print(f"   [dim]Open in any Markdown viewer for publication-ready formatting[/dim]")

    elif fmt == "json":
        import json
        findings = store.query_findings(
            severity=severity,
            vendor=vendor,
            exploitable_only=exploitable_only,
            cve_candidates_only=cve_candidates,
        )

        output_path = Path(output) if output else Path(
            config.get("output", "research_dir", default="research")
        ) / "findings_export.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(findings, indent=2, default=str))

        console.print(f"\n✅ [bold green]Findings exported to: {output_path}[/bold green]")

    store.close()


@main.command()
def stats():
    """Display research database statistics."""
    console.print(BANNER)
    console.print("[bold cyan]📈 Research Database Statistics[/bold cyan]\n")

    store = ResearchStore()
    stats_data = store.get_statistics()

    # --- Overview Panel ---
    overview_text = (
        f"[bold]Total Research Sessions:[/bold]     {stats_data['total_sessions']}\n"
        f"[bold]Total Probes Fired:[/bold]        {stats_data['total_probes']}\n"
        f"[bold]Exploitable Findings:[/bold]      {stats_data['exploitable_findings']}\n"
        f"[bold]CVE Candidates:[/bold]            {stats_data['cve_candidates']}\n"
        f"[bold]Unique WAFs Encountered:[/bold]   {len(stats_data.get('top_wafs', {}))}"
    )
    console.print(Panel(
        overview_text,
        title="Research Overview",
        border_style="cyan",
    ))

    # --- Top WAFs ---
    if stats_data.get("top_wafs"):
        console.print("\n[bold]🎯 Top WAFs Encountered:[/bold]")
        waf_table = Table()
        waf_table.add_column("WAF Vendor", style="yellow")
        waf_table.add_column("Sessions", style="green")
        waf_table.add_column("Frequency", style="blue")

        max_sessions = max(stats_data["top_wafs"].values()) if stats_data["top_wafs"] else 1
        for waf, count in stats_data["top_wafs"].items():
            bar_len = int(30 * count / max_sessions)
            bar = "█" * bar_len + "░" * (30 - bar_len)
            waf_table.add_row(waf, str(count), f"[blue]{bar}[/blue]")

        console.print(waf_table)

    # --- Findings Distribution ---
    if stats_data.get("findings_by_severity"):
        console.print("\n[bold]📊 Findings by Severity:[/bold]")
        sev_table = Table()
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", style="green")
        sev_table.add_column("Distribution", style="blue")

        total = sum(stats_data["findings_by_severity"].values())
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats_data["findings_by_severity"].get(severity, 0)
            if count > 0:
                color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}[severity]
                pct = count / total * 100 if total > 0 else 0
                bar_len = int(30 * count / total) if total > 0 else 0
                bar = "█" * bar_len + "░" * (30 - bar_len)
                sev_table.add_row(
                    f"[{color}]{severity}[/{color}]",
                    str(count),
                    f"[blue]{bar}[/blue] {pct:.1f}%"
                )

        console.print(sev_table)

    # --- Top Targets ---
    sessions = store.get_session_history()
    if sessions:
        from collections import Counter
        target_counter = Counter(s["target"] for s in sessions)
        console.print("\n[bold]🎯 Top Targets:[/bold]")
        target_table = Table()
        target_table.add_column("Target", style="cyan")
        target_table.add_column("Sessions", style="green")
        for target_url, count in target_counter.most_common(5):
            display_target = target_url[:60] + "..." if len(target_url) > 60 else target_url
            target_table.add_row(display_target, str(count))
        console.print(target_table)

    store.close()


@main.command()
@click.argument("session_id", type=int)
def view(session_id):
    """View details of a specific research session."""
    console.print(BANNER)
    console.print(f"[bold cyan]🔍 Viewing Session #{session_id}[/bold cyan]\n")

    store = ResearchStore()
    
    # Query session details
    conn = store._get_connection()
    
    # Get session info
    cursor = conn.execute(
        "SELECT * FROM sessions WHERE id = ?",
        (session_id,)
    )
    session = cursor.fetchone()
    
    if not session:
        console.print(f"[red]Session #{session_id} not found.[/red]")
        store.close()
        return
    
    session = dict(session)
    
    # Display session details
    console.print(f"[bold]Target:[/bold] {session['target']}")
    console.print(f"[bold]Date:[/bold] {session.get('start_time', 'N/A')}")
    console.print(f"[bold]WAF Detected:[/bold] {session.get('waf_vendor', 'Unknown')}")
    console.print(f"[bold]Confidence:[/bold] {session.get('waf_confidence', 'N/A')}")
    console.print(f"[bold]Total Probes:[/bold] {session.get('total_probes', 0)}")
    console.print(f"[bold]Anomalies Found:[/bold] {session.get('anomalies_found', 0)}")
    console.print(f"[bold]Bypass Candidates:[/bold] {session.get('bypass_count', 0)}")
    console.print(f"[bold]High/Critical:[/bold] {session.get('high_severity_count', 0)}")
    
    # Get associated findings
    cursor = conn.execute(
        """SELECT * FROM findings 
           WHERE session_id = ? 
           ORDER BY 
             CASE severity 
               WHEN 'CRITICAL' THEN 1 
               WHEN 'HIGH' THEN 2 
               WHEN 'MEDIUM' THEN 3 
               WHEN 'LOW' THEN 4 
             END""",
        (session_id,)
    )
    findings = [dict(row) for row in cursor.fetchall()]
    
    if findings:
        console.print(f"\n[bold]Findings ({len(findings)}):[/bold]")
        for finding in findings:
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "LOW": "green",
            }.get(finding["severity"], "white")
            
            finding_text = (
                f"Type: {finding['finding_type']}\n"
                f"Description: {finding['description'][:200]}\n"
                f"Exploitable: {'Yes ⚠️' if finding['is_exploitable'] else 'No'}\n"
                f"CVE Candidate: {'Yes 🔥' if finding['cve_candidate'] else 'No'}"
            )
            
            console.print(Panel(
                finding_text,
                title=f"[{severity_color}]{finding['severity']}[/{severity_color}]",
                border_style=severity_color,
            ))
    
    store.close()


if __name__ == "__main__":
    main()
