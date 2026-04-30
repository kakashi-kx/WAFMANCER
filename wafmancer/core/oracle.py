"""
THE RESPONSE ORACLE ENGINE
===========================
WAFMANCER's core innovation: systematically maps WAF decision boundaries
through intelligent probing, not just binary bypass testing.

Now with WAF fingerprinting and targeted mutation generation.
Instead of asking "Does payload X bypass the WAF?", the Oracle asks:
"Where exactly is the line between allowed and blocked?
 What WAF are we dealing with?
 What are its known weaknesses?
 Can we map the WAF's entire rule logic?"
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import structlog
import yaml

from wafmancer.config import config
from wafmancer.core.diff_engine import AdvancedDiffEngine, AnomalySeverity, DiffResult
from wafmancer.core.http_client import AsyncResearchClient, ResearchRequest, ResearchResponse
from wafmancer.core.fingerprinter import WAFFingerprinter, WAFSignature
from wafmancer.core.mutation_engine import SmartMutationEngine
from wafmancer.exceptions import OracleError
from wafmancer.utils.helpers import timestamp_now

logger = structlog.get_logger(__name__)


@dataclass
class ProbeResult:
    """Single probe result for Oracle analysis."""
    request: ResearchRequest
    response: ResearchResponse
    diff: Optional[DiffResult] = None

    @property
    def is_anomaly(self) -> bool:
        """Whether this probe produced an anomaly."""
        return self.diff is not None and bool(self.diff)

    @property
    def is_bypass(self) -> bool:
        """Whether this probe appears to bypass WAF protection."""
        return self.diff is not None and self.diff.is_exploitable


@dataclass
class OracleSession:
    """Complete Oracle research session with all findings."""
    target: str
    start_time: str = field(default_factory=timestamp_now)
    baseline: Optional[ProbeResult] = None
    waf_fingerprint: Optional[WAFSignature] = None
    probes: List[ProbeResult] = field(default_factory=list)
    boundary_points: List[Dict[str, Any]] = field(default_factory=list)
    anomalies: List[DiffResult] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)

    def anomaly_rate(self) -> float:
        """Percentage of probes that produced anomalies."""
        if not self.probes:
            return 0.0
        return sum(1 for p in self.probes if p.is_anomaly) / len(self.probes)

    def bypass_count(self) -> int:
        """Number of probes that achieved WAF bypass."""
        return sum(1 for p in self.probes if p.is_bypass)


class ResponseOracle:
    """
    THE RESPONSE ORACLE — Core research engine.

    Systematically probes the WAF's decision boundary by:
    1. Establishing a clean baseline
    2. Fingerprinting the WAF vendor
    3. Generating WAF-specific targeted mutations
    4. Detecting the exact point where behavior changes
    5. Mapping the complete WAF rule boundary
    """

    def __init__(
        self,
        target: str,
        *,
        max_probes: Optional[int] = None,
        concurrency: Optional[int] = None,
    ) -> None:
        self.target = target
        self.max_probes = max_probes or config.get("oracle", "max_probes", default=1000)
        self.concurrency = concurrency or config.get("oracle", "concurrency", default=10)
        self.diff_engine = AdvancedDiffEngine()
        self.fingerprinter = WAFFingerprinter()
        self.waf_signature: Optional[WAFSignature] = None
        self.mutation_engine: Optional[SmartMutationEngine] = None
        self.session = OracleSession(target=target)

        logger.info(
            "oracle_initialized",
            target=target,
            max_probes=self.max_probes,
            concurrency=self.concurrency,
        )

    async def establish_baseline(self, client: AsyncResearchClient) -> ProbeResult:
        """Send a baseline probe to establish normal WAF behavior."""
        headers = {"Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}
        request, response = await client.probe(self.target, method="GET", headers=headers)
        baseline = ProbeResult(request=request, response=response)
        logger.info("baseline_established", status=response.status_code, 
                   length=response.body_length, server=response.server_header)
        return baseline

    async def probe_boundary(
        self,
        client: AsyncResearchClient,
        mutation: str,
        headers: Dict[str, str],
        body: Optional[bytes] = None,
        url_suffix: Optional[str] = None,
    ) -> ProbeResult:
        """Send a mutated probe and compare against the baseline."""
        target_url = self.target
        if url_suffix:
            target_url = target_url.rstrip("/") + url_suffix

        method = "GET" if not body else "POST"
        request, response = await client.probe(target_url, method=method, headers=headers, body=body)
        result = ProbeResult(request=request, response=response)

        if self.session.baseline:
            result.diff = self.diff_engine.compare(self.session.baseline.response, response)

        return result

    async def map_decision_boundary(
        self,
        client: AsyncResearchClient,
        mutations: List[Tuple[str, Dict[str, str]]],
        bodies: Optional[List[Optional[bytes]]] = None,
        url_suffixes: Optional[List[Optional[str]]] = None,
    ) -> List[ProbeResult]:
        """Systematically map the WAF's decision boundary using multiple mutations."""
        semaphore = asyncio.Semaphore(self.concurrency)
        results: List[ProbeResult] = []

        async def bounded_probe(
            name: str,
            headers: Dict[str, str],
            body: Optional[bytes] = None,
            url_suffix: Optional[str] = None,
        ) -> None:
            async with semaphore:
                try:
                    result = await self.probe_boundary(client, name, headers, body, url_suffix)
                    results.append(result)
                    if result.is_anomaly:
                        logger.warning("boundary_anomaly_detected", mutation=name,
                                     severity=result.diff.severity.name if result.diff else "UNKNOWN")
                        self.session.anomalies.append(result.diff)
                    if result.is_bypass:
                        logger.critical("potential_bypass_detected", mutation=name,
                                      details=result.diff.research_notes if result.diff else [])
                except Exception as e:
                    logger.error("probe_failed", mutation=name, error=str(e))

        # Build tasks based on what we have
        tasks = []
        for i, (name, headers) in enumerate(mutations):
            body = bodies[i] if bodies and i < len(bodies) else None
            url_suffix = url_suffixes[i] if url_suffixes and i < len(url_suffixes) else None
            tasks.append(bounded_probe(name, headers, body, url_suffix))

        await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def run(self) -> OracleSession:
        """Execute a complete Oracle analysis session."""
        logger.info("oracle_session_started", target=self.target)

        async with AsyncResearchClient(http2=True) as client:
            # Phase 1: Baseline
            logger.info("phase_1_establishing_baseline")
            self.session.baseline = await self.establish_baseline(client)

            # Phase 2: Fingerprint WAF
            logger.info("phase_2_fingerprinting_waf")
            self.waf_signature = await self.fingerprinter.fingerprint(self.session.baseline.response)
            self.session.waf_fingerprint = self.waf_signature
            logger.info("waf_identified", vendor=self.waf_signature.vendor.value,
                       confidence=f"{self.waf_signature.confidence:.1%}")

            # Phase 3: Generate mutations
            logger.info("phase_3_generating_mutations")
            self.mutation_engine = SmartMutationEngine(self.waf_signature)
            priority_mutations = self.mutation_engine.generate_priority_mutations(limit=self.max_probes)

            # Unpack 5-tuple: (name, headers, body, priority, url_suffix)
            mutations = []
            bodies = []
            url_suffixes = []
            
            for item in priority_mutations:
                name = item[0]
                headers = item[1]
                body = item[2] if len(item) > 2 else None
                # item[3] is priority score - skip
                url_suffix = item[4] if len(item) > 4 else None
                
                mutations.append((name, headers))
                bodies.append(body)
                url_suffixes.append(url_suffix)

            logger.info("mutations_prepared", total=len(mutations),
                       targeted=self.waf_signature.vendor.value != "Unknown WAF")

            # Phase 4: Map boundary
            logger.info("phase_4_mapping_decision_boundary")
            self.session.probes = await self.map_decision_boundary(
                client, mutations, bodies, url_suffixes
            )

        # Phase 5: Statistics
        self.session.statistics = {
            "total_probes": len(self.session.probes),
            "anomalies_found": len(self.session.anomalies),
            "anomaly_rate": self.session.anomaly_rate(),
            "bypass_count": self.session.bypass_count(),
            "high_severity_count": sum(
                1 for a in self.session.anomalies
                if a.severity in (AnomalySeverity.HIGH, AnomalySeverity.CRITICAL)
            ),
            "waf_vendor": self.waf_signature.vendor.value if self.waf_signature else "Unknown",
            "waf_confidence": f"{self.waf_signature.confidence:.1%}" if self.waf_signature else "N/A",
        }

        logger.info("oracle_session_complete", **self.session.statistics)
        return self.session

    def generate_report(self) -> str:
        """Generate a comprehensive research report."""
        stats = self.session.statistics

        report = f"""# WAFMANCER Response Oracle — Research Report

## Target Information
- **URL:** `{self.session.target}`
- **Analysis Time:** {self.session.start_time}
- **WAF Detected:** {stats.get('waf_vendor', 'Unknown')}
- **Detection Confidence:** {stats.get('waf_confidence', 'N/A')}

## Baseline Response
- **Status:** {self.session.baseline.response.status_code if self.session.baseline else 'N/A'}
- **Length:** {self.session.baseline.response.body_length if self.session.baseline else 'N/A'} bytes
- **Server:** `{self.session.baseline.response.server_header if self.session.baseline else 'N/A'}`

## WAF Fingerprint
"""

        if self.waf_signature and self.waf_signature.vendor.value != "No WAF Detected":
            report += f"""
- **Vendor:** {self.waf_signature.vendor.value}
- **Confidence:** {self.waf_signature.confidence:.1%}
- **Detection Evidence:**
"""
            for evidence in self.waf_signature.evidence:
                report += f"  - {evidence}\n"
            if self.waf_signature.known_vulnerabilities:
                report += "\n- **Known Bypass Vectors:**\n"
                for vuln in self.waf_signature.known_vulnerabilities:
                    report += f"  - {vuln}\n"
            if self.waf_signature.suggested_mutations:
                report += "\n- **Suggested Mutations:**\n"
                for mutation in self.waf_signature.suggested_mutations:
                    report += f"  - {mutation}\n"
        else:
            report += "\nNo WAF detected on this target.\n"

        report += f"""
## Probe Results
- **Total Probes:** {stats['total_probes']}
- **Anomalies Found:** {stats['anomalies_found']}
- **Anomaly Rate:** {stats['anomaly_rate']:.1%}
- **Bypass Candidates:** {stats['bypass_count']}
- **High/Critical Findings:** {stats['high_severity_count']}
"""

        if self.session.anomalies:
            report += "\n## Anomaly Details\n\n"
            for anomaly in self.session.anomalies[:10]:
                report += f"### Severity: {anomaly.severity.name}\n"
                for a in anomaly.anomalies:
                    report += f"- {a}\n"
                if anomaly.research_notes:
                    for note in anomaly.research_notes:
                        report += f"  📝 *{note}*\n"
                report += "\n"

        return report
