"""
WAFMANCER Core Engine.
Contains the Response Oracle, HTTP client, differential analysis engine,
WAF fingerprinting, and smart mutation generation.
"""

from wafmancer.core.oracle import ResponseOracle, OracleSession, ProbeResult
from wafmancer.core.diff_engine import AdvancedDiffEngine, DiffResult, AnomalySeverity
from wafmancer.core.http_client import AsyncResearchClient, ResearchRequest, ResearchResponse
from wafmancer.core.fingerprinter import WAFFingerprinter, WAFSignature, WAFVendor
from wafmancer.core.mutation_engine import SmartMutationEngine

__all__ = [
    "ResponseOracle",
    "OracleSession",
    "ProbeResult",
    "AdvancedDiffEngine",
    "DiffResult",
    "AnomalySeverity",
    "AsyncResearchClient",
    "ResearchRequest",
    "ResearchResponse",
    "WAFFingerprinter",
    "WAFSignature",
    "WAFVendor",
    "SmartMutationEngine",
]
