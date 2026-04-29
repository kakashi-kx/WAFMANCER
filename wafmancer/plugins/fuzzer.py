"""
Advanced Fuzzer Plugin — Rebuilt on top of the Response Oracle.

This is NOT the original basic fuzzer. It now uses the Oracle engine
to perform intelligent, research-grade differential fuzzing with
decision boundary mapping.
"""

from typing import Any, Dict

import structlog

from wafmancer.core.oracle import ResponseOracle
from wafmancer.plugins.base import WafmancerPlugin

logger = structlog.get_logger(__name__)


class AdvancedFuzzerPlugin(WafmancerPlugin):
    """
    Intelligent differential fuzzer powered by the Response Oracle.
    Maps WAF decision boundaries through systematic header mutation probing.
    """

    async def run(self, target: str) -> Dict[str, Any]:
        """
        Execute advanced fuzzing against the target.

        Args:
            target: Target URL

        Returns:
            Research findings dictionary
        """
        logger.info("advanced_fuzzer_started", target=target)

        oracle = ResponseOracle(
            target,
            max_probes=self.config.get("max_probes", 100),
            concurrency=self.config.get("concurrency", 10),
        )

        session = await oracle.run()

        findings = {
            "plugin": self.name,
            "target": target,
            "statistics": session.statistics,
            "anomaly_count": len(session.anomalies),
            "bypass_count": session.bypass_count(),
            "severity_distribution": self._count_severities(session.anomalies),
            "report": oracle.generate_report(),
        }

        logger.info(
            "advanced_fuzzer_complete",
            anomalies=findings["anomaly_count"],
            bypasses=findings["bypass_count"],
        )

        return findings

    def description(self) -> str:
        return (
            "Research-grade differential fuzzer using Response Oracle technology "
            "to map WAF decision boundaries through systematic header mutation"
        )

    @staticmethod
    def _count_severities(anomalies) -> Dict[str, int]:
        """Count anomalies by severity level."""
        from collections import Counter
        from wafmancer.core.diff_engine import AnomalySeverity

        counter = Counter(a.severity.name for a in anomalies)
        return dict(counter)
