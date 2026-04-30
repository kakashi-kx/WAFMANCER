"""
Bug Bounty Mode
===============
Automated target scanning for bug bounty research.
Feed WAFMANCER a list of targets and it will scan them all,
saving results to the research database for later analysis.

Run it before bed, wake up to bypass findings.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from wafmancer.core.oracle import ResponseOracle, OracleSession
from wafmancer.core.research_store import ResearchStore
from wafmancer.utils.helpers import normalize_target_url

logger = structlog.get_logger(__name__)
console = Console()


class BountyScanner:
    """
    Automated bounty scanning engine.
    Scans multiple targets sequentially or from a file.
    """

    def __init__(
        self,
        targets: List[str],
        probes_per_target: int = 20,
        concurrency: int = 5,
        delay_between_targets: float = 2.0,
    ) -> None:
        """
        Initialize the bounty scanner.

        Args:
            targets: List of target URLs
            probes_per_target: Number of probes per target
            concurrency: Concurrent probes per target
            delay_between_targets: Delay between targets (be polite!)
        """
        self.targets = [normalize_target_url(t) for t in targets]
        self.probes_per_target = probes_per_target
        self.concurrency = concurrency
        self.delay_between_targets = delay_between_targets
        self.store = ResearchStore()
        self.results: List[Dict[str, Any]] = []

        logger.info(
            "bounty_scanner_initialized",
            targets=len(self.targets),
            probes_per_target=probes_per_target,
        )

    async def scan_target(self, target: str) -> OracleSession:
        """
        Scan a single target with the Oracle.

        Args:
            target: Target URL

        Returns:
            OracleSession with results
        """
        oracle = ResponseOracle(
            target,
            max_probes=self.probes_per_target,
            concurrency=self.concurrency,
        )

        session = await oracle.run()
        return session

    async def scan_all(self) -> List[Dict[str, Any]]:
        """
        Scan all targets and collect results.

        Returns:
            List of result dictionaries
        """
        results = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            overall_task = progress.add_task(
                "[cyan]Scanning all targets...", total=len(self.targets)
            )

            for i, target in enumerate(self.targets):
                target_display = target[:50] + "..." if len(target) > 50 else target
                progress.update(overall_task, description=f"[cyan]Scanning: {target_display}")

                try:
                    session = await self.scan_target(target)

                    # Save to database
                    session_id = self.store.save_session(session)

                    # Collect result summary
                    result = {
                        "target": target,
                        "session_id": session_id,
                        "waf_vendor": session.statistics.get("waf_vendor", "Unknown"),
                        "waf_confidence": session.statistics.get("waf_confidence", "N/A"),
                        "total_probes": session.statistics["total_probes"],
                        "anomalies_found": session.statistics["anomalies_found"],
                        "bypass_count": session.statistics["bypass_count"],
                        "high_severity_count": session.statistics["high_severity_count"],
                        "error": None,
                    }

                    if session.statistics["bypass_count"] > 0:
                        progress.console.log(
                            f"[bold red]🔥 BYPASS FOUND: {target} "
                            f"({session.statistics['bypass_count']} bypasses)[/bold red]"
                        )

                    results.append(result)

                except Exception as e:
                    logger.error("target_scan_failed", target=target, error=str(e))
                    results.append({
                        "target": target,
                        "session_id": None,
                        "waf_vendor": None,
                        "waf_confidence": None,
                        "total_probes": 0,
                        "anomalies_found": 0,
                        "bypass_count": 0,
                        "high_severity_count": 0,
                        "error": str(e),
                    })

                progress.update(overall_task, advance=1)

                # Polite delay between targets
                if i < len(self.targets) - 1:
                    await asyncio.sleep(self.delay_between_targets)

        self.results = results
        return results

    def generate_summary(self) -> str:
        """
        Generate a summary of bounty scan results.

        Returns:
            Formatted summary string
        """
        if not self.results:
            return "No results to display."

        total_targets = len(self.results)
        successful = sum(1 for r in self.results if r["error"] is None)
        failed = total_targets - successful
        total_bypasses = sum(r["bypass_count"] for r in self.results)
        total_anomalies = sum(r["anomalies_found"] for r in self.results)
        wafs_found = set(
            r["waf_vendor"] for r in self.results
            if r["waf_vendor"] and r["waf_vendor"] != "No WAF Detected"
        )

        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║              WAFMANCER BOUNTY SCAN SUMMARY                   ║
╠══════════════════════════════════════════════════════════════╣
║  Targets Scanned:     {total_targets:<40}║
║  Successful:          {successful:<40}║
║  Failed:              {failed:<40}║
║  Total Probes:        {sum(r['total_probes'] for r in self.results):<40}║
║  Anomalies Found:     {total_anomalies:<40}║
║  🔥 Bypasses Found:   {total_bypasses:<40}║
║  WAFs Detected:       {len(wafs_found):<40}║
╚══════════════════════════════════════════════════════════════╝
"""

        if wafs_found:
            summary += f"\n🎯 WAFs Detected: {', '.join(wafs_found)}\n"

        # Top bypass findings
        bypass_results = [r for r in self.results if r["bypass_count"] > 0]
        if bypass_results:
            summary += "\n🔥 TARGETS WITH BYPASSES:\n"
            bypass_results.sort(key=lambda x: x["bypass_count"], reverse=True)
            for r in bypass_results:
                summary += f"  • {r['target']} — {r['bypass_count']} bypass(es) [{r['waf_vendor']}]\n"

        return summary

    def save_results(self, output_path: Optional[Path] = None) -> Path:
        """
        Save bounty scan results to JSON.

        Args:
            output_path: Path for output file

        Returns:
            Path to saved file
        """
        if output_path is None:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path("research") / f"bounty_scan_{timestamp}.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        export_data = {
            "scan_summary": {
                "total_targets": len(self.results),
                "successful_scans": sum(1 for r in self.results if r["error"] is None),
                "failed_scans": sum(1 for r in self.results if r["error"] is not None),
                "total_anomalies": sum(r["anomalies_found"] for r in self.results),
                "total_bypasses": sum(r["bypass_count"] for r in self.results),
            },
            "results": self.results,
        }

        output_path.write_text(json.dumps(export_data, indent=2))
        logger.info("bounty_results_saved", path=str(output_path))

        return output_path

    def close(self) -> None:
        """Close connections."""
        self.store.close()


def load_targets_from_file(filepath: str) -> List[str]:
    """
    Load targets from a file (one URL per line).

    Args:
        filepath: Path to target list file

    Returns:
        List of target URLs
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {filepath}")

    targets = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

    logger.info("targets_loaded", count=len(targets), file=filepath)
    return targets
