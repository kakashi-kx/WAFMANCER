"""
Advanced response differential analysis engine.
Compares HTTP responses at multiple levels to detect WAF behavior.
"""

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

from wafmancer.core.http_client import ResearchResponse
from wafmancer.utils.helpers import calculate_entropy, is_likely_waf_block

logger = structlog.get_logger(__name__)


class AnomalySeverity(Enum):
    """Severity classification for detected anomalies."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class DiffResult:
    """Complete differential analysis result between two responses."""
    # Status comparison
    status_match: bool = True
    status_baseline: int = 0
    status_probe: int = 0

    # Length comparison
    length_match: bool = True
    length_baseline: int = 0
    length_probe: int = 0
    length_difference: int = 0

    # Header comparison
    headers_match: bool = True
    headers_only_in_baseline: Set[str] = field(default_factory=set)
    headers_only_in_probe: Set[str] = field(default_factory=set)
    headers_changed: Dict[str, Tuple[str, str]] = field(default_factory=dict)

    # Body comparison
    body_hash_match: bool = True
    body_hash_baseline: str = ""
    body_hash_probe: str = ""

    # Content analysis
    entropy_baseline: float = 0.0
    entropy_probe: float = 0.0
    entropy_difference: float = 0.0

    # Timing
    timing_baseline: float = 0.0
    timing_probe: float = 0.0
    timing_difference: float = 0.0

    # WAF detection
    baseline_waf_block: bool = False
    probe_waf_block: bool = False

    # Anomaly assessment
    severity: AnomalySeverity = AnomalySeverity.NONE
    anomalies: List[str] = field(default_factory=list)
    is_exploitable: bool = False
    research_notes: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        """True if an anomaly was detected."""
        return self.severity != AnomalySeverity.NONE


class AdvancedDiffEngine:
    """
    Multi-dimensional HTTP response comparison engine.
    Designed for research-grade WAF behavior analysis.
    """

    def __init__(self, sensitivity: float = 1.0) -> None:
        """
        Initialize the diff engine.

        Args:
            sensitivity: How sensitive the engine is to differences (0.0 to 2.0)
                        1.0 is default, higher means more false positives
        """
        self.sensitivity = max(0.1, min(2.0, sensitivity))
        logger.info("diff_engine_initialized", sensitivity=self.sensitivity)

    def compare(
        self,
        baseline: ResearchResponse,
        probe: ResearchResponse,
    ) -> DiffResult:
        """
        Perform comprehensive differential analysis between two responses.

        Args:
            baseline: The baseline (control) response
            probe: The probe (mutated) response

        Returns:
            Complete DiffResult with anomaly analysis
        """
        result = DiffResult()

        # --- Status Code Comparison ---
        self._compare_status(baseline, probe, result)

        # --- Response Length Comparison ---
        self._compare_length(baseline, probe, result)

        # --- Header Comparison ---
        self._compare_headers(baseline, probe, result)

        # --- Body Hash Comparison ---
        self._compare_body_hash(baseline, probe, result)

        # --- Entropy Analysis ---
        self._compare_entropy(baseline, probe, result)

        # --- Timing Analysis ---
        self._compare_timing(baseline, probe, result)

        # --- WAF Block Detection ---
        self._detect_waf_blocks(baseline, probe, result)

        # --- Assess Overall Severity ---
        self._assess_severity(result)

        return result

    def _compare_status(
        self,
        baseline: ResearchResponse,
        probe: ResearchResponse,
        result: DiffResult,
    ) -> None:
        """Compare HTTP status codes."""
        result.status_baseline = baseline.status_code
        result.status_probe = probe.status_code
        result.status_match = baseline.status_code == probe.status_code

        if not result.status_match:
            result.anomalies.append(
                f"Status code mismatch: {baseline.status_code} vs {probe.status_code}"
            )

    def _compare_length(
        self,
        baseline: ResearchResponse,
        probe: ResearchResponse,
        result: DiffResult,
    ) -> None:
        """Compare response body lengths."""
        result.length_baseline = baseline.body_length
        result.length_probe = probe.body_length
        result.length_difference = abs(baseline.body_length - probe.body_length)
        result.length_match = baseline.body_length == probe.body_length

        if not result.length_match:
            result.anomalies.append(
                f"Content length mismatch: {baseline.body_length} vs {probe.body_length} "
                f"(Δ{result.length_difference})"
            )

    def _compare_headers(
        self,
        baseline: ResearchResponse,
        probe: ResearchResponse,
        result: DiffResult,
    ) -> None:
        """Compare response headers in detail."""
        baseline_header_names = set(k.lower() for k in baseline.headers)
        probe_header_names = set(k.lower() for k in probe.headers)

        # Headers only in baseline
        result.headers_only_in_baseline = baseline_header_names - probe_header_names

        # Headers only in probe
        result.headers_only_in_probe = probe_header_names - baseline_header_names

        # Headers with different values
        common_headers = baseline_header_names & probe_header_names
        for header in common_headers:
            baseline_val = baseline.headers.get(
                header, ""
            ) or baseline.headers.get(header.capitalize(), "")
            probe_val = probe.headers.get(
                header, ""
            ) or probe.headers.get(header.capitalize(), "")

            if baseline_val != probe_val:
                result.headers_changed[header] = (str(baseline_val), str(probe_val))

        result.headers_match = (
            not result.headers_only_in_baseline
            and not result.headers_only_in_probe
            and not result.headers_changed
        )

        if not result.headers_match:
            if result.headers_only_in_baseline:
                result.anomalies.append(
                    f"Headers missing from probe: {result.headers_only_in_baseline}"
                )
            if result.headers_only_in_probe:
                result.anomalies.append(
                    f"New headers in probe: {result.headers_only_in_probe}"
                    )
            if result.headers_changed:
                result.anomalies.append(
                    f"Modified headers: {list(result.headers_changed.keys())}"
                )

    def _compare_body_hash(
        self,
        baseline: ResearchResponse,
        probe: ResearchResponse,
        result: DiffResult,
    ) -> None:
        """Compare body content via SHA-256 hashes."""
        result.body_hash_baseline = hashlib.sha256(baseline.body).hexdigest()
        result.body_hash_probe = hashlib.sha256(probe.body).hexdigest()
        result.body_hash_match = result.body_hash_baseline == result.body_hash_probe

        if not result.body_hash_match:
            result.anomalies.append("Response body content differs")

    def _compare_entropy(
        self,
        baseline: ResearchResponse,
        probe: ResearchResponse,
        result: DiffResult,
    ) -> None:
        """Compare Shannon entropy of response bodies."""
        result.entropy_baseline = calculate_entropy(baseline.body)
        result.entropy_probe = calculate_entropy(probe.body)
        result.entropy_difference = abs(
            result.entropy_baseline - result.entropy_probe
        )

        # Significant entropy difference often indicates different response types
        if result.entropy_difference > 1.5 * self.sensitivity:
            result.anomalies.append(
                f"Significant entropy difference: Δ{result.entropy_difference:.2f}"
            )

    def _compare_timing(
        self,
        baseline: ResearchResponse,
        probe: ResearchResponse,
        result: DiffResult,
    ) -> None:
        """Compare response timing — timing discrepancies can indicate WAF processing."""
        result.timing_baseline = baseline.elapsed_seconds
        result.timing_probe = probe.elapsed_seconds
        result.timing_difference = abs(
            result.timing_baseline - result.timing_probe
        )

        # Significant timing differences (>50% deviation) often reveal WAF analysis
        if baseline.elapsed_seconds > 0:
            ratio = result.timing_difference / baseline.elapsed_seconds
            if ratio > 0.5:
                result.anomalies.append(
                    f"Timing anomaly: {result.timing_baseline:.3f}s vs "
                    f"{result.timing_probe:.3f}s ({ratio:.0%} deviation)"
                )

    def _detect_waf_blocks(
        self,
        baseline: ResearchResponse,
        probe: ResearchResponse,
        result: DiffResult,
    ) -> None:
        """Detect if either response is a WAF block page."""
        result.baseline_waf_block = is_likely_waf_block(baseline.body_text)
        result.probe_waf_block = is_likely_waf_block(probe.body_text)

        if not result.baseline_waf_block and result.probe_waf_block:
            result.anomalies.append("Probe triggered WAF block (baseline passed)")
            result.research_notes.append(
                "This mutation successfully triggered WAF blocking behavior"
            )

        if result.baseline_waf_block and not result.probe_waf_block:
            result.anomalies.append("Probe bypassed WAF block (baseline was blocked)")
            result.research_notes.append(
                "POTENTIAL BYPASS: Probe was not blocked while baseline was"
            )
            result.is_exploitable = True

    def _assess_severity(self, result: DiffResult) -> None:
        """
        Assess the overall severity of detected anomalies.

        Scoring logic (research-focused):
        - Status code change: +2 severity points
        - Content change with WAF block: +3 points (potential bypass)
        - Significant timing/entropy difference: +1 point
        - Header anomalies: +1 point per type
        """
        severity_score = 0

        if not result.status_match:
            severity_score += 2
        if not result.body_hash_match:
            severity_score += 1
            if result.probe_waf_block != result.baseline_waf_block:
                severity_score += 2  # WAF interaction detected
        if result.entropy_difference > 1.5:
            severity_score += 1
        if result.timing_difference > 0:
            severity_score += 1 if result.timing_difference > 0.5 else 0
        if not result.headers_match:
            header_anomaly_count = (
                len(result.headers_only_in_baseline)
                + len(result.headers_only_in_probe)
                + len(result.headers_changed)
            )
            severity_score += min(header_anomaly_count, 2)

        # Map score to severity
        if severity_score == 0:
            result.severity = AnomalySeverity.NONE
        elif severity_score <= 2:
            result.severity = AnomalySeverity.LOW
        elif severity_score <= 4:
            result.severity = AnomalySeverity.MEDIUM
        elif severity_score <= 6:
            result.severity = AnomalySeverity.HIGH
        else:
            result.severity = AnomalySeverity.CRITICAL

        if severity_score >= 5:
            result.is_exploitable = True

    def generate_research_summary(self, result: DiffResult) -> str:
        """Generate a human-readable research summary."""
        lines = [
            "=" * 60,
            "WAFMANCER — Differential Analysis Report",
            "=" * 60,
            f"Severity: {result.severity.name}",
            f"Exploitable: {'YES ⚠️' if result.is_exploitable else 'No'}",
            "",
            "--- Status ---",
            f"  Baseline: {result.status_baseline}",
            f"  Probe:    {result.status_probe}",
            f"  Match:    {result.status_match}",
            "",
            "--- Content ---",
            f"  Baseline Length: {result.length_baseline}",
            f"  Probe Length:    {result.length_probe}",
            f"  Body Hash Match: {result.body_hash_match}",
            f"  Entropy (Base):  {result.entropy_baseline:.2f}",
            f"  Entropy (Probe): {result.entropy_probe:.2f}",
            "",
            "--- WAF Detection ---",
            f"  Baseline Block: {result.baseline_waf_block}",
            f"  Probe Block:    {result.probe_waf_block}",
            "",
            "--- Anomalies Found ---",
        ]

        if result.anomalies:
            for anomaly in result.anomalies:
                lines.append(f"  • {anomaly}")
        else:
            lines.append("  No anomalies detected")

        if result.research_notes:
            lines.append("")
            lines.append("--- Research Notes ---")
            for note in result.research_notes:
                lines.append(f"  📝 {note}")

        lines.append("=" * 60)
        return "\n".join(lines)
