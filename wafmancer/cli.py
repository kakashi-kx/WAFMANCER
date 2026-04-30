"""
WAFMANCER Command-Line Interface.
Research-grade WAF evasion framework with Response Oracle Technology.

crafted by :: kakashi4kx / kakashi-kx
"""

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.box import ROUNDED, HEAVY
from rich.columns import Columns

from wafmancer.config import config
from wafmancer.core.oracle import ResponseOracle
from wafmancer.core.research_store import ResearchStore
from wafmancer.utils.helpers import normalize_target_url
from wafmancer.core.neural_exploit import NeuralExploitSynthesis
from wafmancer.core.trust_corruptor import TrustCorruptor

console = Console()

# ═══════════════════════════════════════════════════════════════
# ░▒▓█  WAFMANCER — TERMINAL COLOR SYSTEM  █▓▒░
# ═══════════════════════════════════════════════════════════════

class C:
    """Cyberpunk terminal color palette."""
    RED      = "#ff2d55"
    BLUE     = "#0a84ff"
    PURPLE   = "#bf5af2"
    GREEN    = "#30d158"
    ORANGE   = "#ff9f0a"
    TEAL     = "#64d2ff"
    PINK     = "#ff375f"
    GOLD     = "#ffd60a"
    SILVER   = "#e5e5ea"
    DIM      = "#636366"
    DARK     = "#1c1c1e"
    WHITE    = "#ffffff"
    GRADIENT = "bold #bf5af2"

# ═══════════════════════════════════════════════════════════════
# ░▒▓█  SIGNATURE BANNER  █▓▒░
# ═══════════════════════════════════════════════════════════════

def display_banner():
    """Display the signature WAFMANCER banner."""
    console.print()
    
    # Top decorative line
    console.print(Align.center(
        Text("▂▃▅▇█▓▒░  W A F M A N C E R  ░▒▓█▇▅▃▂", 
             style=f"bold {C.PURPLE}")
    ))
    
    # Main title
    title_lines = [
        "   ╭──────────────────────────────────────────────────╮",
        "   │                                                  │",
        "   │   ░░      ░░  ░░░░░  ░░░░░░░  ░░   ░░  ░░░░░  ░░   ░░  ░░░░░░ ░░░░░░░ ░░░░░░  │",
        "   │   ░░      ░░ ░░   ░░ ░░       ░░░ ░░░ ░░   ░░ ░░░  ░░ ░░      ░░      ░░   ░░ │",
        "   │   ░░  ░░  ░░ ░░░░░░░ ░░░░░    ░░ ░░ ░ ░░░░░░░ ░░ ░░ ░ ░░      ░░░░░   ░░░░░░  │",
        "   │   ░░ ░░░ ░░ ░░   ░░ ░░       ░░  ░  ░ ░░   ░░ ░░  ░ ░ ░░      ░░      ░░   ░░ │",
        "   │    ░░░ ░░░  ░░   ░░ ░░       ░░     ░ ░░   ░░ ░░   ░░ ░░░░░░ ░░░░░░░ ░░   ░░ │",
        "   │    ░   ░                                                               ░   ░  │",
        "   │                                                  │",
        "   │          ◆  Response Oracle Technology  ◆        │",
        "   │          v2.0.0  ::  Zero-Day Engine             │",
        "   │                                                  │",
        "   ╰──────────────────────────────────────────────────╯",
    ]
    
    for line in title_lines:
        if "◆" in line:
            console.print(Align.center(Text(line, style=f"bold {C.TEAL}")))
        elif "v2.0.0" in line:
            console.print(Align.center(Text(line, style=f"{C.DIM}")))
        else:
            console.print(Align.center(Text(line, style=f"{C.SILVER}")))

    console.print()
    
    # GitHub-style badges row
    badges = [
        f"[{C.DARK} bg:{C.PURPLE}] ◈ ORACLE ENGINE [/]",
        f"[{C.DARK} bg:{C.BLUE}] ◆ SMART MUTATIONS [/]",
        f"[{C.DARK} bg:{C.GREEN}] ◈ WAF FINGERPRINT [/]",
        f"[{C.DARK} bg:{C.ORANGE}] ◆ ZERO-DAY HUNT [/]",
        f"[{C.DARK} bg:{C.RED}] ◈ CVE READY [/]",
    ]
    console.print(Align.center(Text("  ".join(badges))))
    
    console.print()
    
    # Stats bar
    stats_bar = (
        f"[{C.DIM}]╔{'═'*60}╗[/{C.DIM}]\n"
        f"[{C.DIM}]║[/{C.DIM}]  "
        f"[{C.SILVER}]Target:[/{C.SILVER}] [bold {C.WHITE}]RESPONSE ORACLE[/]  "
        f"[{C.DIM}]│[/{C.DIM}]  "
        f"[{C.SILVER}]Proto:[/{C.SILVER}] [bold {C.GREEN}]HTTP/2 + HTTP/3[/]  "
        f"[{C.DIM}]│[/{C.DIM}]  "
        f"[{C.SILVER}]Auth:[/{C.SILVER}] [bold {C.PINK}]kakashi4kx[/]  "
        f"[{C.DIM}]║[/{C.DIM}]\n"
        f"[{C.DIM}]╚{'═'*60}╝[/{C.DIM}]"
    )
    console.print(Align.center(Text.from_markup(stats_bar)))
    
    console.print()


def display_scan_header(target: str, probes: int):
    """Display scan initiation header."""
    console.print()
    console.print(Panel(
        Text.from_markup(
            f"[{C.TEAL}]► TARGET:[/]  [{C.WHITE}]{target}[/]\n"
            f"[{C.TEAL}]► MODE:[/]    [{C.PURPLE}]Response Oracle Research Engine[/]\n"
            f"[{C.TEAL}]► PROBES:[/]  [{C.GREEN}]{probes} mutations[/]\n"
            f"[{C.TEAL}]► TIME:[/]    [{C.DIM}]{datetime.now().strftime('%H:%M:%S UTC')}[/]"
        ),
        border_style=C.PURPLE,
        box=HEAVY,
        padding=(1, 3),
        title="[bold]◈ SCAN SEQUENCE INITIATED ◈[/]",
        title_align="center",
    ))
    console.print()


def display_waf_fingerprint(fingerprint):
    """Display WAF fingerprint with signature styling."""
    if not fingerprint:
        return
    
    is_waf = fingerprint.vendor.value != "No WAF Detected"
    
    if is_waf:
        accent = C.RED
        icon = "◈"
        label = "WAF DETECTED"
    else:
        accent = C.GREEN
        icon = "◆"
        label = "NO WAF"
    
    # Confidence bar
    confidence_pct = int(fingerprint.confidence * 100)
    bar_filled = "█" * (confidence_pct // 5)
    bar_empty = "░" * (20 - confidence_pct // 5)
    
    panel_content = Text.from_markup(
        f"[{C.SILVER}]▸ Vendor:[/]       [bold {C.WHITE}]{fingerprint.vendor.value}[/]\n"
        f"[{C.SILVER}]▸ Confidence:[/]   [{accent}]{bar_filled}{bar_empty}[/] {confidence_pct}%\n"
        f"[{C.SILVER}]▸ Indicators:[/]   [{C.ORANGE}]{len(fingerprint.evidence)} signatures matched[/]\n"
        f"[{C.SILVER}]▸ Known Vectors:[/] [{C.TEAL}]{len(fingerprint.known_vulnerabilities)} bypass techniques available[/]"
    )
    
    console.print(Panel(
        panel_content,
        border_style=accent,
        box=ROUNDED,
        padding=(1, 3),
        title=f"[bold {accent}]{icon} {label} {icon}[/]",
        title_align="center",
    ))
    console.print()


def display_results_table(stats):
    """Display results with signature table styling."""
    console.print()
    
    total = stats["total_probes"]
    anomalies = stats["anomalies_found"]
    bypasses = stats["bypass_count"]
    high_sev = stats["high_severity_count"]
    rate = stats["anomaly_rate"]
    
    # Create results table
    table = Table(
        box=ROUNDED,
        border_style=C.DIM,
        show_header=True,
        header_style=f"bold {C.GOLD}",
        title=f"[bold {C.GOLD}]◆ SCAN RESULTS ◆[/]",
        title_justify="center",
        padding=(0, 2),
    )
    
    table.add_column("Metric", style=C.SILVER, width=28)
    table.add_column("Result", justify="center", width=22)
    table.add_column("Indicator", justify="center", width=20)
    
    # Probes row
    probe_status = "✓ COMPLETE" if total > 0 else "✗ FAILED"
    probe_color = C.GREEN if total > 0 else C.RED
    table.add_row(
        "▸ Total Probes Fired",
        f"[bold {C.WHITE}]{total}[/]",
        f"[{probe_color}]{probe_status}[/]"
    )
    
    # Anomalies row
    if anomalies > 0:
        anomaly_bar = "▰" * min(anomalies, 10) + "▱" * max(10 - anomalies, 0)
        table.add_row(
            "▸ Anomalies Detected",
            f"[bold {C.RED}]{anomalies}[/]",
            f"[{C.RED}]{anomaly_bar}[/]"
        )
    else:
        table.add_row(
            "▸ Anomalies Detected",
            f"[{C.DIM}]{anomalies}[/]",
            f"[{C.DIM}]—[/]"
        )
    
    # Anomaly Rate
    if rate > 0.5:
        rate_color = C.RED
        rate_label = "CRITICAL"
    elif rate > 0.2:
        rate_color = C.ORANGE
        rate_label = "ELEVATED"
    else:
        rate_color = C.GREEN
        rate_label = "NORMAL"
    
    table.add_row(
        "▸ Anomaly Rate",
        f"[bold {rate_color}]{rate:.1%}[/]",
        f"[{rate_color}]{rate_label}[/]"
    )
    
    # Bypass row
    if bypasses > 0:
        table.add_row(
            "▸ Bypass Candidates",
            f"[bold {C.RED}]◈ {bypasses} ◈[/]",
            f"[bold {C.RED}]⚠ EXPLOITABLE[/]"
        )
    else:
        table.add_row(
            "▸ Bypass Candidates",
            f"[{C.DIM}]{bypasses}[/]",
            f"[{C.DIM}]—[/]"
        )
    
    # High Severity
    if high_sev > 0:
        sev_bar = "◆" * min(high_sev, 5)
        table.add_row(
            "▸ High/Critical Findings",
            f"[bold {C.RED}]{high_sev}[/]",
            f"[{C.RED}]{sev_bar}[/]"
        )
    else:
        table.add_row(
            "▸ High/Critical Findings",
            f"[{C.DIM}]{high_sev}[/]",
            f"[{C.DIM}]—[/]"
        )
    
    console.print(Align.center(table))
    console.print()


def display_anomaly_details(anomalies, waf_bypass_suggestions=None, known_vulns=None):
    """Display anomaly findings with signature styling."""
    if not anomalies:
        return
    
    severity_config = {
        "CRITICAL": (C.RED, "◈", "CRITICAL BYPASS"),
        "HIGH": (C.ORANGE, "◆", "HIGH SEVERITY"),
        "MEDIUM": (C.BLUE, "◇", "MEDIUM SEVERITY"),
        "LOW": (C.DIM, "○", "LOW SEVERITY"),
    }
    
    console.print()
    console.print(Align.center(
        Text(f"▂▃▅▇█▓▒░  FINDINGS  ░▒▓█▇▅▃▂", style=f"bold {C.GOLD}")
    ))
    console.print()
    
    for i, anomaly in enumerate(anomalies[:15], 1):
        sev = anomaly.severity.name
        color, icon, label = severity_config.get(sev, (C.DIM, "○", sev))
        
        # Build readable anomaly text
        anomaly_lines = []
        for a in anomaly.anomalies[:6]:
            anomaly_lines.append(f"  {icon} {a}")
        
        if anomaly.is_exploitable:
            anomaly_lines.append(f"")
            anomaly_lines.append(f"  ◈ [bold {C.RED}]POTENTIALLY EXPLOITABLE[/]")
        
        if anomaly.research_notes:
            for note in anomaly.research_notes:
                anomaly_lines.append(f"  ▸ [{C.TEAL}]{note}[/]")
        
        console.print(Panel(
            Text.from_markup("\n".join(anomaly_lines)),
            border_style=color,
            box=ROUNDED,
            padding=(1, 2),
            title=f"[bold {color}]{icon} FINDING #{i} : {label} {icon}[/]",
            title_align="left",
        ))
    
    if len(anomalies) > 15:
        console.print(
            Text(f"  ... and {len(anomalies) - 15} more anomalies", style=C.DIM)
        )
    
    # Display bypass suggestions if available
    if waf_bypass_suggestions:
        console.print()
        console.print(Panel(
            Text.from_markup(
                "\n".join(f"[{C.TEAL}]▸[/] [{C.SILVER}]{s}[/]" for s in waf_bypass_suggestions)
            ),
            border_style=C.TEAL,
            box=ROUNDED,
            padding=(1, 2),
            title=f"[bold {C.TEAL}]◆ SUGGESTED BYPASS TECHNIQUES ◆[/]",
            title_align="left",
        ))
    
    if known_vulns:
        console.print()
        console.print(Panel(
            Text.from_markup(
                "\n".join(f"[{C.PURPLE}]▸[/] [{C.SILVER}]{v}[/]" for v in known_vulns)
            ),
            border_style=C.PURPLE,
            box=ROUNDED,
            padding=(1, 2),
            title=f"[bold {C.PURPLE}]◇ KNOWN BYPASS VECTORS ◇[/]",
            title_align="left",
        ))


def display_save_confirmation(session_id: int, report_path: str):
    """Display save confirmation."""
    console.print()
    console.print(Align.center(
        Text.from_markup(
            f"[{C.GREEN}]✓[/] Session [{C.GOLD}]#{session_id}[/] archived  "
            f"[{C.DIM}]│[/]  "
            f"[{C.GREEN}]✓[/] Report: [{C.DIM}]{report_path}[/]"
        )
    ))


def display_bounty_header(target_file: str, target_count: int, probes: int):
    """Display bounty mode header."""
    console.print()
    console.print(Panel(
        Text.from_markup(
            f"[{C.TEAL}]► TARGET FILE:[/] [{C.WHITE}]{target_file}[/]\n"
            f"[{C.TEAL}]► TARGETS:[/]     [{C.GREEN}]{target_count} URLs loaded[/]\n"
            f"[{C.TEAL}]► PROBES/EACH:[/] [{C.ORANGE}]{probes} mutations[/]\n"
            f"[{C.TEAL}]► MODE:[/]        [{C.PURPLE}]Automated Bounty Hunter[/]"
        ),
        border_style=C.PURPLE,
        box=HEAVY,
        padding=(1, 3),
        title="[bold]◈ BOUNTY MODE ACTIVE ◈[/]",
        title_align="center",
    ))
    console.print()


def display_bounty_summary(results):
    """Display bounty mode results summary."""
    if not results:
        console.print(Text(" No results.", style=C.DIM))
        return
    
    total = len(results)
    successful = sum(1 for r in results if r.get("error") is None)
    total_bypasses = sum(r.get("bypass_count", 0) for r in results)
    total_anomalies = sum(r.get("anomalies_found", 0) for r in results)
    
    console.print()
    console.print(Panel(
        Text.from_markup(
            f"[{C.SILVER}]▸ Targets Scanned:[/]  [{C.WHITE}]{total}[/]\n"
            f"[{C.SILVER}]▸ Successful:[/]      [{C.GREEN}]{successful}[/]\n"
            f"[{C.SILVER}]▸ Total Anomalies:[/]  [{C.ORANGE}]{total_anomalies}[/]\n"
            f"[{C.SILVER}]▸ Bypasses Found:[/]   [{C.RED}]{total_bypasses}[/]"
        ),
        border_style=C.GOLD,
        box=ROUNDED,
        padding=(1, 3),
        title=f"[bold {C.GOLD}]◆ BOUNTY SCAN COMPLETE ◆[/]",
        title_align="center",
    ))
    
    # Show targets with bypasses
    bypass_targets = [r for r in results if r.get("bypass_count", 0) > 0]
    if bypass_targets:
        console.print()
        bypass_targets.sort(key=lambda x: x.get("bypass_count", 0), reverse=True)
        for r in bypass_targets:
            console.print(
                Text.from_markup(
                    f"  [{C.RED}]◈[/] [{C.WHITE}]{r['target']}[/] "
                    f"[{C.DIM}]→[/] [{C.RED}]{r['bypass_count']} bypass(es)[/] "
                    f"[{C.DIM}]| [{r.get('waf_vendor', 'Unknown')}][/]"
                )
            )


def display_footer():
    """Display signature footer."""
    console.print()
    console.print(Align.center(
        Text(
            "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄",
            style=f"dim {C.PURPLE}"
        )
    ))
    console.print(Align.center(
        Text("✦ crafted by kakashi4kx / kakashi-kx ✦", style=f"italic {C.PINK}")
    ))
    console.print(Align.center(
        Text("[ WAFMANCER v2.0.0 — Response Oracle Technology ]", style=C.DIM)
    ))
    console.print()


# ═══════════════════════════════════════════════════════════════
# ░▒▓█  CLI COMMANDS  █▓▒░
# ═══════════════════════════════════════════════════════════════

@click.group()
@click.version_option(version="2.0.0", prog_name="WAFMANCER")
def main():
    """
    \b
    WAFMANCER — Next-Gen WAF Evasion Research Framework
    Response Oracle Technology | Smart Mutations | Zero-Day Engine
    crafted by kakashi4kx / kakashi-kx
    """
    pass


@main.command()
@click.option("-p", "--payload", required=True, help="Malicious payload to camouflage")
@click.option("--population", default=30, type=int, help="Population size per generation")
@click.option("--generations", default=50, type=int, help="Maximum generations")
@click.option("--mutation-rate", default=0.3, type=float, help="Mutation rate (0.0-1.0)")
@click.option("--target-score", default=0.15, type=float, help="Target detection score")
@click.option("-o", "--output", default=None, help="Output file for report")
def neuro(payload, population, generations, mutation_rate, target_score, output):
    """
    Neuro-Camouflage — AI-powered payload evasion.
    
    Evolves a malicious payload through genetic algorithms and
    benign token injection to bypass ML-based WAF detection.
    """
    display_banner()
    
    neuro_engine = NeuralExploitSynthesis(waf_vendor=None)
    
    console.print(Panel(
        Text.from_markup(
            f"[{C.TEAL}]► Payload:[/] [{C.WHITE}]{payload[:80]}{'...' if len(payload) > 80 else ''}[/]\n"
            f"[{C.TEAL}]► Population:[/] [{C.GREEN}]{population}[/]\n"
            f"[{C.TEAL}]► Generations:[/] [{C.ORANGE}]{generations}[/]\n"
            f"[{C.TEAL}]► Mutation Rate:[/] [{C.PURPLE}]{mutation_rate:.0%}[/]\n"
            f"[{C.TEAL}]► Target Score:[/] [{C.RED}]≤{target_score:.2f}[/]"
        ),
        border_style=C.PURPLE,
        box=HEAVY,
        padding=(1, 3),
        title="[bold]🧠 NEURO-CAMOUFLAGE ACTIVE[/]",
        title_align="center",
    ))
    
    async def run_neuro():
        return await neuro_engine.camouflage(payload)
    
    try:
        with console.status(f"[{C.PURPLE}]🧠 Evolving payload...[/]", spinner="dots"):
            results = asyncio.run(run_neuro())
        
        # Display results
        original_score = results["original_detection_score"]
        best_score = results["best_score"]
        improvement = results["improvement_percent"]
        
        # Score comparison
        console.print()
        console.print(Panel(
            Text.from_markup(
                f"[{C.SILVER}]▸ Original Score:[/]   [{C.RED}]{original_score:.3f}[/]\n"
                f"[{C.SILVER}]▸ Best Score:[/]       [{C.GREEN}]{best_score:.3f}[/]\n"
                f"[{C.SILVER}]▸ Improvement:[/]      [{C.GOLD}]{improvement:.1f}%[/]"
            ),
            border_style=C.GREEN if improvement > 50 else C.ORANGE,
            box=ROUNDED,
            padding=(1, 3),
            title=f"[bold {C.GREEN}]◆ EVASION RESULTS ◆[/]",
            title_align="center",
        ))
        
        # Show best payload
        if results.get("best_payload"):
            console.print()
            console.print(Panel(
                Text(results["best_payload"][:500], style=C.WHITE),
                border_style=C.TEAL,
                box=ROUNDED,
                padding=(1, 2),
                title=f"[bold {C.TEAL}]◇ BEST CAMOUFLAGED PAYLOAD ◇[/]",
                title_align="left",
            ))
        
        # Evolution stats
        if results.get("evolution_result"):
            evo = results["evolution_result"]
            console.print()
            console.print(Panel(
                Text.from_markup(
                    f"[{C.SILVER}]▸ Generations:[/]   [{C.GREEN}]{evo['generations']}[/]\n"
                    f"[{C.SILVER}]▸ Mutations:[/]     [{C.ORANGE}]{evo['total_mutations']}[/]\n"
                    f"[{C.SILVER}]▸ Time:[/]          [{C.DIM}]{evo['time_elapsed']:.2f}s[/]"
                ),
                border_style=C.PURPLE,
                box=ROUNDED,
                padding=(1, 2),
                title=f"[bold {C.PURPLE}]◇ EVOLUTION STATS ◇[/]",
                title_align="left",
            ))
        
        # Generate and save report
        report = neuro_engine.generate_report(results)
        if output:
            Path(output).write_text(report)
            console.print(f"\n[{C.GREEN}]◈ Report saved:[/] [{C.DIM}]{output}[/]")
        
    except Exception as e:
        console.print(f"\n[{C.RED}]◈ Error:[/] {e}")
    
    display_footer()


@main.command()
def info():
    """Display framework information and configuration."""
    display_banner()
    conf = config.to_dict()
    console.print_json(data=conf)
    display_footer()


@main.command()
def modules():
    """List available research modules."""
    display_banner()
    
    modules_data = [
        ("Response Oracle", C.PURPLE, "◈ ACTIVE", "WAF decision boundary mapping engine"),
        ("Smart Mutations", C.BLUE, "◆ ACTIVE", "WAF-specific targeted mutation generation (50+ payloads)"),
        ("WAF Fingerprinter", C.GREEN, "◈ ACTIVE", "Passive WAF detection via multi-vector analysis"),
        ("Research Database", C.ORANGE, "◆ ACTIVE", "Persistent findings storage with export capabilities"),
        ("Bug Bounty Mode", C.TEAL, "◈ ACTIVE", "Automated multi-target scanning"),
        ("Neuro-Camouflage", C.PINK, "◇ PLANNED", "AI-powered adversarial payload mutation"),
        ("QUIC-Strike", C.RED, "◇ PLANNED", "HTTP/3 0-RTT smuggling exploitation"),
    ]
    
    table = Table(
        box=ROUNDED,
        border_style=C.DIM,
        show_header=True,
        header_style=f"bold {C.GOLD}",
        title=f"[bold {C.GOLD}]◆ ACTIVE MODULES ◆[/]",
        title_justify="center",
        padding=(0, 2),
    )
    
    table.add_column("Module", style=C.SILVER, width=22)
    table.add_column("Status", justify="center", width=16)
    table.add_column("Description", style=C.DIM, width=45)
    
    for name, color, status, desc in modules_data:
        table.add_row(
            f"[{color}]▸[/] {name}",
            f"[{color}]{status}[/]",
            desc,
        )
    
    console.print(Align.center(table))
    display_footer()


@main.command()
@click.option("-t", "--target", default=None, help="Filter by target URL")
@click.option("--limit", default=50, type=int, help="Maximum sessions to display")
def history(target, limit):
    """View research session history."""
    display_banner()
    
    store = ResearchStore()
    sessions = store.get_session_history(target)
    sessions = sessions[:limit]
    
    if not sessions:
        console.print(Text("  No sessions found. Run 'wafmancer oracle' first.", style=C.DIM))
        store.close()
        display_footer()
        return
    
    table = Table(
        box=ROUNDED,
        border_style=C.DIM,
        show_header=True,
        header_style=f"bold {C.GOLD}",
        title=f"[bold {C.GOLD}]◆ SESSION HISTORY ◆[/]",
        title_justify="center",
        padding=(0, 1),
    )
    
    table.add_column("ID", style=C.DIM, width=5)
    table.add_column("Target", style=C.SILVER, width=40)
    table.add_column("Date", style=C.DIM, width=18)
    table.add_column("WAF", style=C.TEAL, width=18)
    table.add_column("Probes", style=C.GREEN, width=7)
    table.add_column("Anomalies", style=C.ORANGE, width=9)
    table.add_column("Bypasses", style=C.RED, width=8)
    
    for s in sessions:
        target_display = s["target"][:38] + ".." if len(s["target"]) > 40 else s["target"]
        date_display = (s.get("start_time") or "N/A")[:16].replace("T", " ")
        waf = s.get("waf_vendor") or "—"
        bypasses = s.get("bypass_count", 0)
        
        table.add_row(
            str(s["id"]),
            target_display,
            date_display,
            waf,
            str(s.get("total_probes", 0)),
            str(s.get("anomalies_found", 0)),
            f"[bold {C.RED}]{bypasses}[/]" if bypasses > 0 else str(bypasses),
        )
    
    console.print(Align.center(table))
    
    total_bypasses = sum(s.get("bypass_count", 0) for s in sessions)
    total_anomalies = sum(s.get("anomalies_found", 0) for s in sessions)
    console.print(
        Text.from_markup(
            f"  [{C.DIM}]Total:[/] [{C.ORANGE}]{total_anomalies} anomalies[/]  "
            f"[{C.DIM}]│[/]  [{C.RED}]{total_bypasses} bypasses[/]  "
            f"[{C.DIM}]│[/]  [{C.DIM}]{len(sessions)} sessions[/]"
        )
    )
    
    store.close()
    display_footer()


@main.command()
def stats():
    """Display research database statistics."""
    display_banner()
    
    store = ResearchStore()
    data = store.get_statistics()
    
    # Overview
    console.print(Panel(
        Text.from_markup(
            f"[{C.SILVER}]▸ Sessions:[/]       [{C.WHITE}]{data['total_sessions']}[/]\n"
            f"[{C.SILVER}]▸ Total Probes:[/]    [{C.WHITE}]{data['total_probes']}[/]\n"
            f"[{C.SILVER}]▸ Exploitable:[/]     [{C.RED}]{data['exploitable_findings']}[/]\n"
            f"[{C.SILVER}]▸ CVE Candidates:[/]  [{C.GOLD}]{data['cve_candidates']}[/]"
        ),
        border_style=C.PURPLE,
        box=ROUNDED,
        padding=(1, 3),
        title=f"[bold {C.PURPLE}]◆ RESEARCH OVERVIEW ◆[/]",
        title_align="center",
    ))
    
    # Top WAFs
    if data.get("top_wafs"):
        console.print()
        waf_lines = []
        for waf, count in data["top_wafs"].items():
            line = f"[{C.TEAL}]▸[/] [{C.SILVER}]{waf}[/] " + f"[{C.DIM}]-- {count} sessions[/]"
            waf_lines.append(line)
        
        console.print(Panel(
            Text.from_markup("\n".join(waf_lines)),
            border_style=C.BLUE,
            box=ROUNDED,
            padding=(1, 2),
            title=f"[bold {C.BLUE}]◇ WAFS ENCOUNTERED ◇[/]",
            title_align="left",
        ))
    
    # Severity distribution
    if data.get("findings_by_severity"):
        console.print()
        sev_lines = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = data["findings_by_severity"].get(sev, 0)
            if count > 0:
                color = {"CRITICAL": C.RED, "HIGH": C.ORANGE, "MEDIUM": C.BLUE, "LOW": C.DIM}[sev]
                bar = "▰" * min(count, 30) + "▱" * max(30 - count, 0)
                sev_lines.append(f"[{color}]▸ {sev:9}[/] [{C.WHITE}]{count:3}[/] [{color}]{bar}[/]")
        
        console.print(Panel(
            Text.from_markup("\n".join(sev_lines)),
            border_style=C.ORANGE,
            box=ROUNDED,
            padding=(1, 2),
            title=f"[bold {C.ORANGE}]◇ SEVERITY DISTRIBUTION ◇[/]",
            title_align="left",
        ))
    
    store.close()
    display_footer()


@main.command()
@click.option("--format", "fmt", type=click.Choice(["markdown", "json"]), default="markdown")
@click.option("-o", "--output", default=None)
@click.option("--severity", default=None)
@click.option("--vendor", default=None)
@click.option("--exploitable-only", is_flag=True)
@click.option("--cve-candidates", is_flag=True)
def export(fmt, output, severity, vendor, exploitable_only, cve_candidates):
    """Export research findings for publication."""
    display_banner()
    
    store = ResearchStore()
    data = store.get_statistics()
    
    console.print(Text.from_markup(
        f"[{C.DIM}]Exporting {sum(data.get('findings_by_severity', {}).values())} findings...[/]"
    ))
    
    if fmt == "markdown":
        output_path = Path(output) if output else Path("research") / "findings_export.md"
        store.export_findings_markdown(output_path)
        console.print(f"[{C.GREEN}]◈ Exported to:[/] [{C.SILVER}]{output_path}[/]")
    
    store.close()
    display_footer()


@main.command()
@click.option("-f", "--file", "target_file", required=True, help="Target list file")
@click.option("--probes", default=20, type=int)
@click.option("--concurrency", default=5, type=int)
@click.option("--delay", default=2.0, type=float)
@click.option("-o", "--output", default=None)
def bounty(target_file, probes, concurrency, delay, output):
    """Bug Bounty Mode — scan multiple targets automatically."""
    from wafmancer.core.bounty_mode import BountyScanner, load_targets_from_file
    
    display_banner()
    
    try:
        targets = load_targets_from_file(target_file)
    except FileNotFoundError as e:
        console.print(f"[{C.RED}]◈ Error:[/] {e}")
        return
    
    if not targets:
        console.print(f"[{C.ORANGE}]◈ No targets found.[/]")
        return
    
    display_bounty_header(target_file, len(targets), probes)
    
    if not click.confirm(f"\n  [{C.ORANGE}]Proceed with scan?[/]"):
        console.print(f"[{C.DIM}]  Cancelled.[/]")
        display_footer()
        return
    
    scanner = BountyScanner(
        targets=targets,
        probes_per_target=probes,
        concurrency=concurrency,
        delay_between_targets=delay,
    )
    
    async def run_bounty():
        return await scanner.scan_all()
    
    try:
        results = asyncio.run(run_bounty())
        display_bounty_summary(results)
        
        saved_path = scanner.save_results(Path(output) if output else None)
        console.print(f"\n[{C.GREEN}]◈ Results:[/] [{C.DIM}]{saved_path}[/]")
        
    except KeyboardInterrupt:
        console.print(f"\n[{C.ORANGE}]◈ Interrupted.[/]")
    except Exception as e:
        console.print(f"\n[{C.RED}]◈ Error:[/] {e}")
    finally:
        scanner.close()
    
    display_footer()

@main.command()
@click.option("-p", "--payload", required=True, help="Payload or attack intent")
@click.option("--waf", default=None, help="Target WAF vendor (Cloudflare, AWS WAF, etc.)")
@click.option("-s", "--surface", default=None, 
              type=click.Choice(["html_injection", "javascript_execution", "sql_query", 
                                 "file_path", "system_command"]),
              help="Attack surface")
@click.option("-o", "--output", default=None, help="Output file for report")
def neural(payload, waf, surface, output):
    """
    Neural Exploit Synthesis — AI-powered payload generation.
    
    Synthesizes novel attack payloads using WAF-specific
    multi-vector chaining and ML blindspot exploitation.
    """
    display_banner()
    
    engine = NeuralExploitSynthesis(waf_vendor=waf)
    
    console.print(Panel(
        Text.from_markup(
            f"[{C.TEAL}]► Payload:[/] [{C.WHITE}]{payload[:80]}[/]\n"
            f"[{C.TEAL}]► WAF Target:[/] [{C.RED}]{waf or 'Generic'}[/]\n"
            f"[{C.TEAL}]► Surface:[/] [{C.PURPLE}]{surface or 'Auto-detect'}[/]"
        ),
        border_style=C.PURPLE,
        box=HEAVY,
        padding=(1, 3),
        title="[bold]🧠 NEURAL EXPLOIT SYNTHESIS[/]",
        title_align="center",
    ))
    
    try:
        with console.status(f"[{C.PURPLE}]Synthesizing payloads...[/]", spinner="dots"):
            results = engine.synthesize(payload, surface)
        
        console.print()
        console.print(Panel(
            Text.from_markup(
                f"[{C.SILVER}]▸ Best Score:[/] [{C.GREEN}]{results['best_score']:.3f}[/]\n"
                f"[{C.SILVER}]▸ Bypass Probability:[/] [{C.GREEN}]{results['best_bypass_probability']:.1%}[/]\n"
                f"[{C.SILVER}]▸ Techniques:[/] [{C.TEAL}]{', '.join(results['techniques_used'])}[/]"
            ),
            border_style=C.GREEN,
            box=ROUNDED,
            padding=(1, 3),
            title="[bold]◆ SYNTHESIS RESULTS ◆[/]",
            title_align="center",
        ))
        
        if results.get("best_payload"):
            console.print()
            console.print(Panel(
                Text(results["best_payload"][:500], style=C.WHITE),
                border_style=C.TEAL,
                box=ROUNDED,
                padding=(1, 2),
                title="[bold]◇ BEST SYNTHESIZED PAYLOAD ◇[/]",
                title_align="left",
            ))
        
        console.print()
        gen_table = Table(title="All Generations", border_style=C.DIM, box=ROUNDED)
        gen_table.add_column("#", style=C.DIM)
        gen_table.add_column("Score", style=C.RED)
        gen_table.add_column("Bypass %", style=C.GREEN)
        gen_table.add_column("Techniques", style=C.TEAL)
        
        for gen in results["generations"]:
            gen_table.add_row(
                str(gen["id"]),
                f"{gen['confidence_score']:.3f}",
                f"{gen['bypass_probability']:.1%}",
                ", ".join(gen["techniques"][:3]),
            )
        
        console.print(gen_table)
        
        report = engine.generate_report(results)
        if output:
            Path(output).write_text(report)
            console.print(f"\n[{C.GREEN}]◈ Report saved:[/] [{C.DIM}]{output}[/]")
        
    except Exception as e:
        console.print(f"\n[{C.RED}]◈ Error:[/] {e}")
    
    display_footer()

@main.command()
@click.option("-t", "--target", required=True, help="Target URL")
@click.option("-p", "--payload", required=True, help="Malicious payload to deliver")
@click.option("--waf", default=None, help="Target WAF vendor (auto-detect if not specified)")
@click.option("--requests", default=20, type=int, help="Max benign requests for trust building")
@click.option("--no-synthesize", is_flag=True, help="Skip neural payload synthesis")
@click.option("-o", "--output", default=None, help="Output file for full report")
def corrupt(target, payload, waf, requests, no_synthesize, output):
    """
    Trust Corruptor — Deliver payloads at peak WAF trust.
    
    Maps WAF reputation decay curve, builds trust through
    benign requests, and injects payload at optimal trust window.
    Generates PoC code and tactical intelligence report.
    """
    display_banner()
    
    console.print(Panel(
        Text.from_markup(
            f"[{C.TEAL}]► Target:[/] [{C.WHITE}]{target}[/]\n"
            f"[{C.TEAL}]► Payload:[/] [{C.RED}]{payload[:60]}...[/]\n"
            f"[{C.TEAL}]► WAF:[/] [{C.ORANGE}]{waf or 'Auto-detect'}[/]\n"
            f"[{C.TEAL}]► Trust Requests:[/] [{C.GREEN}]{requests}[/]\n"
            f"[{C.TEAL}]► Synthesize:[/] [{C.GREEN if not no_synthesize else C.RED}]{'Yes' if not no_synthesize else 'No'}[/]"
        ),
        border_style=C.PURPLE,
        box=HEAVY,
        padding=(1, 3),
        title="[bold]🔥 TRUST CORRUPTOR ACTIVE[/]",
        title_align="center",
    ))
    
    corruptor = TrustCorruptor(target, waf_vendor=waf)
    
    async def run_corrupt():
        return await corruptor.corrupt(
            payload,
            max_benign_requests=requests,
            synthesize_first=not no_synthesize,
        )
    
    try:
        with console.status(f"[{C.PURPLE}]Mapping trust decay curve...[/]", spinner="dots"):
            results = asyncio.run(run_corrupt())
        
        # WAF Profile
        if results.get("tactical_profile"):
            profile = results["tactical_profile"]
            console.print()
            console.print(Panel(
                Text.from_markup(
                    f"[{C.SILVER}]▸ Vendor:[/] [{C.RED}]{profile.get('vendor', 'Unknown')}[/]\n"
                    f"[{C.SILVER}]▸ Mode:[/] [{C.ORANGE}]{profile.get('mode', 'unknown').upper()}[/]\n"
                    f"[{C.SILVER}]▸ Reputation:[/] [{'green' if profile.get('reputation_based') else 'red'}]{'YES' if profile.get('reputation_based') else 'NO'}[/]\n"
                    f"[{C.SILVER}]▸ Difficulty:[/] [{C.RED}]{profile.get('bypass_difficulty', 'Unknown')}[/]"
                ),
                border_style=C.RED,
                box=ROUNDED,
                padding=(1, 3),
                title="[bold]🎯 WAF TACTICAL PROFILE[/]",
                title_align="center",
            ))
        
        # Trust Curve
        if results.get("trust_curve"):
            curve = results["trust_curve"]
            console.print()
            console.print(Panel(
                Text.from_markup(
                    f"[{C.SILVER}]▸ Trust Threshold:[/] [{C.GREEN}]Request #{curve.trust_threshold}[/]\n"
                    f"[{C.SILVER}]▸ Peak Trust:[/] [{C.GREEN}]{curve.peak_trust_score:.2f}[/]\n"
                    f"[{C.SILVER}]▸ Injection Point:[/] [{C.GOLD}]Request #{curve.recommended_injection_point}[/]\n"
                    f"[{C.SILVER}]▸ Time to Trust:[/] [{C.DIM}]{curve.time_to_trust:.1f}s[/]"
                ),
                border_style=C.BLUE,
                box=ROUNDED,
                padding=(1, 3),
                title="[bold]📊 TRUST DECAY CURVE[/]",
                title_align="center",
            ))
        
        # Injection Result
        if results.get("injection_result"):
            inj = results["injection_result"]
            bypass = inj["bypass_successful"]
            result_color = C.GREEN if bypass else C.RED
            result_text = "✅ BYPASS SUCCESSFUL" if bypass else "❌ BLOCKED"
            
            console.print()
            console.print(Panel(
                Text.from_markup(
                    f"[{C.SILVER}]▸ Status:[/] [{result_color}]{inj['status_code']} — {result_text}[/]\n"
                    f"[{C.SILVER}]▸ Response Length:[/] [{C.WHITE}]{inj['response_length']} bytes[/]\n"
                    f"[{C.SILVER}]▸ Response Time:[/] [{C.WHITE}]{inj['response_time']:.3f}s[/]\n"
                    f"[{C.SILVER}]▸ Trust at Injection:[/] [{C.GREEN}]{inj['trust_score_at_injection']:.2f}[/]"
                ),
                border_style=result_color,
                box=ROUNDED,
                padding=(1, 3),
                title=f"[bold {result_color}]💉 INJECTION RESULT[/]",
                title_align="center",
            ))
        
        # Advantages & Disadvantages
        if results.get("advantages") or results.get("disadvantages"):
            console.print()
            adv_dis = ""
            if results.get("advantages"):
                adv_dis += f"[{C.GREEN}]◆ ADVANTAGES:[/]\n"
                for adv in results["advantages"][:3]:
                    adv_dis += f"  [{C.GREEN}]✓[/] [{C.SILVER}]{adv}[/]\n"
            if results.get("disadvantages"):
                adv_dis += f"\n[{C.RED}]◆ DISADVANTAGES:[/]\n"
                for dis in results["disadvantages"][:3]:
                    adv_dis += f"  [{C.RED}]✗[/] [{C.SILVER}]{dis}[/]\n"
            
            console.print(Panel(
                Text.from_markup(adv_dis),
                border_style=C.ORANGE,
                box=ROUNDED,
                padding=(1, 2),
                title="[bold]⚖️ TACTICAL ASSESSMENT[/]",
                title_align="left",
            ))
        
        # WAF Config Notes
        if results.get("waf_config_notes"):
            console.print()
            console.print(Panel(
                Text.from_markup(results["waf_config_notes"][:500]),
                border_style=C.PURPLE,
                box=ROUNDED,
                padding=(1, 2),
                title="[bold]🔧 WAF CONFIGURATION INTEL[/]",
                title_align="left",
            ))
        
        # Steps to Reproduce
        if results.get("steps_to_reproduce"):
            console.print()
            steps_text = "\n".join(results["steps_to_reproduce"][:20])
            console.print(Panel(
                Text(steps_text, style=C.SILVER),
                border_style=C.TEAL,
                box=ROUNDED,
                padding=(1, 2),
                title="[bold]📋 STEPS TO REPRODUCE[/]",
                title_align="left",
            ))
        
        # Save full report
        full_report = corruptor.generate_full_report(results)
        report_path = Path(output) if output else Path("research") / f"trust_corruptor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(full_report)
        
        # Save PoC
        if results.get("poc_code"):
            poc_path = report_path.with_suffix(".py")
            poc_path.write_text(results["poc_code"])
            console.print(f"\n[{C.GREEN}]◈ Full Report:[/] [{C.DIM}]{report_path}[/]")
            console.print(f"[{C.GREEN}]◈ PoC Script:[/] [{C.DIM}]{poc_path}[/]")
        
    except Exception as e:
        console.print(f"\n[{C.RED}]◈ Error:[/] {e}")
    
    display_footer()

if __name__ == "__main__":
    main()
