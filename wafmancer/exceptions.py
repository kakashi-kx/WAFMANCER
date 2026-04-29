"""
Custom exception hierarchy for WAFMANCER.
Enables precise error handling and research-grade failure analysis.
"""

from typing import Optional


class WafmancerError(Exception):
    """Base exception for all WAFMANCER errors."""
    def __init__(self, message: str, *, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.details = details or {}


class ConnectionError(WafmancerError):
    """Target unreachable or connection failed."""
    pass


class TimeoutError(WafmancerError):
    """Request or analysis timed out."""
    pass


class WAFDetectionError(WafmancerError):
    """Failed to detect or fingerprint the WAF."""
    pass


class OracleError(WafmancerError):
    """The Response Oracle encountered an unexpected state."""
    pass


class MutationError(WafmancerError):
    """Payload mutation generation failed."""
    pass


class ConfigurationError(WafmancerError):
    """Invalid configuration detected."""
    pass


class PluginError(WafmancerError):
    """Plugin loading or execution failure."""
    pass


class ResearchDataError(WafmancerError):
    """Error saving or loading research data."""
    pass
