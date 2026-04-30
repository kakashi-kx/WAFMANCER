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
        """
        Initialize the Oracle for a target.

        Args:
            target: The target URL to analyze
            max_probes: Maximum number of probes to send
            concurrency: Maximum concurrent probes
        """
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
        """
        Send a baseline probe to establish normal WAF behavior.
        This is the control against which all mutations are compared.
        """
        headers = {"Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}

        request, response = await client.probe(
            self.target,
            method="GET",
            headers=headers,
        )

        baseline = ProbeResult(request=request, response=response)

        logger.info(
            "baseline_established",
            status=response.status_code,
            length=response.body_length,
            server=response.server_header,
        )

        return baseline

    async def probe_boundary(
        self,
        client: AsyncResearchClient,
        mutation: str,
        headers: Dict[str, str],
        body: Optional[bytes] = None,
    ) -> ProbeResult:
        """
        Send a mutated probe and compare against the baseline.

        Args:
            client: HTTP client
            mutation: Description of the mutation being tested
            headers: Mutated headers to test
            body: Optional request body

        Returns:
            Complete ProbeResult with diff analysis
        """
        request, response = await client.probe(
            self.target,
            method="GET" if not body else "POST",
            headers=headers,
            body=body,
        )

        result = ProbeResult(request=request, response=response)

        if self.session.baseline:
            result.diff = self.diff_engine.compare(
                self.session.baseline.response,
                response,
            )

        return result

    async def map_decision_boundary(
        self,
        client: AsyncResearchClient,
        mutations: List[Tuple[str, Dict[str, str]]],
        bodies: Optional[List[Optional[bytes]]] = None,
    ) -> List[ProbeResult]:
        """
        Systematically map the WAF's decision boundary using multiple mutations.

        This is the core Oracle operation — it doesn't just test payloads,
        it learns the WAF's behavior patterns.

        Args:
            client: HTTP client
            mutations: List of (name, headers) mutation pairs
            bodies: Optional list of request bodies corresponding to mutations

        Returns:
            Complete list of probe results
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        results: List[ProbeResult] = []

        async def bounded_probe(
            name: str,
            headers: Dict[str, str],
            body: Optional[bytes] = None,
        ) -> None:
            async with semaphore:
                try:
                    result = await self.probe_boundary(client, name, headers, body)
                    results.append(result)

                    if result.is_anomaly:
                        logger.warning(
                            "boundary_anomaly_detected",
                            mutation=name,
                            severity=result.diff.severity.name if result.diff else "UNKNOWN",
                        )
                        self.session.anomalies.append(result.diff)

                    if result.is_bypass:
                        logger.critical(
                            "potential_bypass_detected",
                            mutation=name,
                            details=result.diff.research_notes if result.diff else [],
                        )
                except Exception as e:
                    logger.error("probe_failed", mutation=name, error=str(e))

        # Run all probes concurrently (limited by semaphore)
        if bodies:
            tasks = [
                bounded_probe(name, headers, body)
                for (name, headers), body in zip(mutations, bodies)
            ]
        else:
            tasks = [bounded_probe(name, headers) for name, headers in mutations]

        await asyncio.gather(*tasks)

        return results

    async def run(self) -> OracleSession:
        """
        Execute a complete Oracle analysis session with WAF fingerprinting
        and targeted mutation generation.

        Returns:
            Complete OracleSession with all findings
        """
        logger.info("oracle_session_started", target=self.target)

        async with AsyncResearchClient(http2=True) as client:
            # Phase 1: Establish baseline
            logger.info("phase_1_establishing_baseline")
            self.session.baseline = await self.establish_baseline(client)

            # Phase 2: Fingerprint the WAF
            logger.info("phase_2_fingerprinting_waf")
            self.waf_signature = await self.fingerprinter.fingerprint(
                self.session.baseline.response
            )
            self.session.waf_fingerprint = self.waf_signature

            # Display fingerprint results
            logger.info(
                "waf_identified",
                vendor=self.waf_signature.vendor.value,
                confidence=f"{self.waf_signature.confidence:.1%}",
            )

            # Phase 3: Generate targeted mutations
            logger.info("phase_3_generating_mutations")
            self.mutation_engine = SmartMutationEngine(self.waf_signature)

            # Get priority mutations with bodies
            priority_mutations = self.mutation_engine.generate_priority_mutations(
                limit=self.max_probes
            )

            # Extract mutations and bodies
            mutations = [(name, headers) for name, headers, _, _ in priority_mutations]
            bodies = [body for _, _, body, _ in priority_mutations]

            logger.info(
                "mutations_prepared",
                total=len(mutations),
                targeted=self.waf_signature.vendor.value != "Unknown WAF",
            )

            # Phase 4: Map decision boundary with targeted mutations
            logger.info("phase_4_mapping_decision_boundary")
            self.session.probes = await self.map_decision_boundary(
                client, mutations, bodies
            )

        # Phase 5: Compute statistics
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

        logger.info(
            "oracle_session_complete",
            **self.session.statistics,
        )

        return self.session

    def _generate_research_mutations(self) -> List[Tuple[str, Dict[str, str]]]:
        """
        Generate a research-grade set of mutations designed to probe
        the WAF's decision boundary at multiple points.

        This is the fallback method when no WAF fingerprint is available.
        For fingerprinted WAFs, use the SmartMutationEngine instead.

        Returns:
            List of (mutation_name, headers_dict) tuples
        """
        benign_headers = {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        mutations = [
            # HTTP Verb Tampering
            ("verb_override_xhttpmethod",
             {**benign_headers, "X-HTTP-Method-Override": "POST"}),
            ("verb_override_xmethod",
             {**benign_headers, "X-Method-Override": "DELETE"}),

            # Content-Type Boundary Tests
            ("content_type_xml",
             {**benign_headers, "Content-Type": "application/xml"}),
            ("content_type_json_unicode",
             {**benign_headers, "Content-Type": "application/json; charset=utf-16"}),

            # Path Traversal Indicators
            ("path_traversal_enc_dot",
             {**benign_headers, "X-Original-URL": "/../../etc/passwd"}),
            ("path_traversal_url_enc",
             {**benign_headers, "X-Rewrite-URL": "%2e%2e%2f%2e%2e%2f"}),

            # Hop-by-Hop Header Injection (Smuggling Vector)
            ("hop_byhop_connection",
             {**benign_headers, "Connection": "keep-alive, X-Bypass"}),

            # Unicode Normalization Boundary
            ("unicode_nfd",
             {**benign_headers, "X-Test": "caf\\u00e9"}),
            ("unicode_nfkc",
             {**benign_headers, "X-Test": "①\\u2460"}),

            # Smuggling Header Variants
            ("smug_transfer_encoding",
             {**benign_headers, "Transfer-Encoding": "chunked"}),
            ("smug_content_length_deviation",
             {**benign_headers, "Content-Length": "0", "Transfer-Encoding": "identity"}),

            # Header Injection Attempts
            ("header_injection_crlf",
             {**benign_headers, "X-Injected": "test\\r\\nInjected: true"}),
            ("header_injection_newline",
             {**benign_headers, "X-Injected": "test\\nInjected: true"}),

            # Protocol Boundary
            ("scheme_relative",
             {**benign_headers, "X-Forwarded-Proto": "file"}),

            # SQL Injection Indicator (to trigger WAF)
            ("sqli_simple",
             {**benign_headers, "X-Query": "' OR 1=1 --"}),
            ("sqli_encoded",
             {**benign_headers, "X-Query": "%27%20OR%201%3D1"}),

            # XSS Indicator (to trigger WAF)
            ("xss_basic",
             {**benign_headers, "X-Input": "<script>alert(1)</script>"}),
        ]

        logger.info("mutations_generated", count=len(mutations))
        return mutations[:self.max_probes]

    def generate_report(self) -> str:
        """
        Generate a comprehensive research report from the Oracle session.

        Returns:
            Markdown-formatted research report
        """
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

        # Add WAF fingerprint details if available
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
            for anomaly in self.session.anomalies[:10]:  # Top 10
                report += f"### Severity: {anomaly.severity.name}\n"
                for a in anomaly.anomalies:
                    report += f"- {a}\n"
                if anomaly.research_notes:
                    for note in anomaly.research_notes:
                        report += f"  📝 *{note}*\n"
                report += "\n"

        return report


# Simple test function for development
async def quick_test(target: str = "https://httpbin.org/get"):
    """Quick test function for Oracle development."""
    oracle = ResponseOracle(target, max_probes=5)
    session = await oracle.run()
    print(oracle.generate_report())
    return session


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://httpbin.org/get"
    asyncio.run(quick_test(target))
