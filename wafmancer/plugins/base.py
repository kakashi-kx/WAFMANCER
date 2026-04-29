"""
Abstract plugin interface for WAFMANCER.
All research modules must implement this base class.
"""

import abc
from typing import Any, Dict, Optional

import structlog

logger = structlog.get_logger(__name__)


class WafmancerPlugin(abc.ABC):
    """
    Abstract base class for all WAFMANCER research plugins.

    Plugins receive a target and configuration, and produce
    research findings in a standardized format.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the plugin.

        Args:
            config: Plugin-specific configuration dictionary
        """
        self.config = config or {}
        self.name = self.__class__.__name__

    @abc.abstractmethod
    async def run(self, target: str) -> Dict[str, Any]:
        """
        Execute the plugin's research operation.

        Args:
            target: The target URL to analyze

        Returns:
            Dictionary of research findings
        """
        ...

    @abc.abstractmethod
    def description(self) -> str:
        """Return a human-readable description of the plugin's purpose."""
        ...

    def __repr__(self) -> str:
        return f"<{self.name}: {self.description()[:50]}...>"
