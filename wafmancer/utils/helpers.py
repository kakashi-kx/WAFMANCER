"""
Utility functions for WAFMANCER.
"""

import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse


def normalize_target_url(url: str) -> str:
    """
    Normalize a target URL to ensure consistent format.

    Args:
        url: Raw URL input

    Returns:
        Normalized URL with scheme and without trailing slash
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path.rstrip("/") or "/",
        parsed.params,
        parsed.query,
        "",  # Remove fragment
    ))

    return normalized


def generate_request_id(
    method: str,
    url: str,
    timestamp: Optional[float] = None,
) -> str:
    """
    Generate a unique research ID for each probe request.
    This enables tracking individual probes across the system.

    Args:
        method: HTTP method used
        url: Target URL
        timestamp: Optional timestamp for reproducibility

    Returns:
        Unique request identifier
    """
    ts = timestamp or time.time()
    content = f"{method}:{url}:{ts}".encode()
    return hashlib.sha256(content).hexdigest()[:16]


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data.
    Useful for detecting WAF responses vs normal responses.

    Args:
        data: Byte data to analyze

    Returns:
        Entropy value (0.0 to 8.0 for bytes)
    """
    if not data:
        return 0.0

    from collections import Counter

    length = len(data)
    counter = Counter(data)

    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * (probability.bit_length() - 1)

    return min(entropy, 8.0)


def is_likely_waf_block(content: str) -> bool:
    """
    Heuristic check if response content indicates a WAF block.

    Args:
        content: Response body text

    Returns:
        True if the response appears to be a WAF block
    """
    waf_indicators = [
        "Access Denied",
        "Request Blocked",
        "Security Policy",
        "Cloudflare",
        "ModSecurity",
        "AWS WAF",
        "Firewall",
        "403 Forbidden",
        "Web Application Firewall",
    ]

    content_lower = content.lower()
    matches = sum(1 for indicator in waf_indicators
                  if indicator.lower() in content_lower)

    return matches >= 2


def timestamp_now() -> str:
    """Get ISO 8601 timestamp for research logging."""
    return datetime.now(timezone.utc).isoformat()
