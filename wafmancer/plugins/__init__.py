"""
WAFMANCER Plugin System.
All research modules are dynamically loaded from this package.
"""

from wafmancer.plugins.fuzzer import AdvancedFuzzerPlugin

__all__ = ["AdvancedFuzzerPlugin"]
