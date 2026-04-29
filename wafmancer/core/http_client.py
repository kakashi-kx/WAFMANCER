"""
Async HTTP client wrapper optimized for security research.
Supports HTTP/1.1 and HTTP/2 with detailed request/response tracking.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx
import structlog

from wafmancer.exceptions import ConnectionError, TimeoutError
from wafmancer.utils.helpers import generate_request_id

logger = structlog.get_logger(__name__)


@dataclass
class ResearchRequest:
    """Complete record of an HTTP request for research analysis."""
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    request_id: str = ""
    timestamp: float = 0.0
    http_version: str = ""


@dataclass
class ResearchResponse:
    """Complete record of an HTTP response for research analysis."""
    status_code: int
    headers: Dict[str, List[str]] = field(default_factory=dict)
    body: bytes = b""
    body_text: str = ""
    body_length: int = 0
    elapsed_seconds: float = 0.0
    http_version: str = ""
    server_header: str = ""
    request_id: str = ""
    is_waf_block: bool = False
    entropy: float = 0.0
    raw_response: Optional[Any] = None


class AsyncResearchClient:
    """
    Async HTTP client designed for WAF research.
    Captures complete request/response data for later analysis.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        max_redirects: int = 5,
        user_agent: str = "Wafmancer-Research/1.0",
        http2: bool = True,
    ) -> None:
        """
        Initialize the research HTTP client.

        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            max_redirects: Maximum redirects to follow
            user_agent: User-Agent string for requests
            http2: Enable HTTP/2 support
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.http2 = http2

        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "AsyncResearchClient":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            verify=self.verify_ssl,
            follow_redirects=True,
            max_redirects=self.max_redirects,
            http2=self.http2,
            headers={"User-Agent": self.user_agent},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()

    async def probe(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Tuple[ResearchRequest, ResearchResponse]:
        """
        Send a research probe to the target.

        Args:
            url: Target URL
            method: HTTP method
            headers: Custom headers (merged with defaults)
            body: Request body for POST/PUT

        Returns:
            Tuple of (ResearchRequest, ResearchResponse) for complete analysis

        Raises:
            ConnectionError: If target is unreachable
            TimeoutError: If request times out
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        request_id = generate_request_id(method, url)
        request_headers = headers or {}

        # Build research request record
        research_request = ResearchRequest(
            method=method,
            url=url,
            headers=request_headers,
            body=body,
            request_id=request_id,
            timestamp=time.time(),
            http_version="",
        )

        start_time = time.monotonic()

        try:
            response = await self._client.request(
                method=method,
                url=url,
                headers=request_headers,
                content=body,
            )
        except httpx.ConnectError as e:
            logger.error("connection_failed", url=url, error=str(e))
            raise ConnectionError(f"Failed to connect to {url}: {e}")
        except httpx.TimeoutException as e:
            logger.error("request_timeout", url=url, error=str(e))
            raise TimeoutError(f"Request to {url} timed out after {self.timeout}s")
        except Exception as e:
            logger.error("request_failed", url=url, error=str(e))
            raise ConnectionError(f"Request failed: {e}")

        elapsed = time.monotonic() - start_time

        # Build research response record
        body_bytes = response.content
        body_text = response.text

        research_response = ResearchResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body_bytes,
            body_text=body_text,
            body_length=len(body_bytes),
            elapsed_seconds=elapsed,
            http_version=response.http_version,
            server_header=response.headers.get("server", ""),
            request_id=request_id,
            raw_response=response,
        )

        # Update request with actual HTTP version used
        research_request.http_version = response.http_version

        logger.debug(
            "probe_complete",
            request_id=request_id,
            status=response.status_code,
            length=len(body_bytes),
            elapsed=f"{elapsed:.3f}s",
            http_version=response.http_version,
        )

        return research_request, research_response

    async def close(self) -> None:
        """Explicitly close the client."""
        if self._client:
            await self._client.aclose()
            self._client = None
