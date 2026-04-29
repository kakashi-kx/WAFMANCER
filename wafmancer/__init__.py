"""
WAFMANCER — Next-Generation WAF Evasion Research Framework

A research-grade tool for mapping Web Application Firewall decision boundaries,
discovering novel bypass techniques, and producing publication-ready findings.
"""

__version__ = "1.0.0-dev"
__author__ = "Your Name"
__description__ = "WAF Evasion Research Framework with Response Oracle Technology"

# Public API
from wafmancer.config import WafmancerConfig
from wafmancer.exceptions import WafmancerError

__all__ = ["__version__", "WafmancerConfig", "WafmancerError"]
