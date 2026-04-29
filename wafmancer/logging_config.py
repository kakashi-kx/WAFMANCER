"""
Structured logging configuration for WAFMANCER.
Produces machine-readable JSON logs for research analysis.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import structlog


class ResearchJSONRenderer:
    """Custom structlog renderer that outputs research-friendly JSON."""

    def __call__(self, logger, method_name, event_dict):
        """Format the log entry."""
        # Add timestamp
        event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
        event_dict["logger"] = logger.name
        event_dict["level"] = method_name.upper()

        return json.dumps(event_dict, default=str)


def setup_logging(
    log_level: str = "INFO",
    output_dir: str = "logs",
    save_requests: bool = True,
    save_responses: bool = True,
) -> None:
    """
    Configure structured logging for WAFMANCER.

    Args:
        log_level: Minimum log level to display
        output_dir: Directory for log file output
        save_requests: Whether to log full request data
        save_responses: Whether to log full response data
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Console output — human-readable for development
    console_processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.dev.ConsoleRenderer(colors=True),
    ]

    # File output — structured JSON for research
    file_processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        ResearchJSONRenderer(),
    ]

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Set up handlers
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer(colors=True)
        )
    )

    # File handler for research logs
    log_filename = f"wafmancer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    file_handler = logging.FileHandler(output_path / log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(processor=ResearchJSONRenderer())
    )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Silence noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("hpack").setLevel(logging.WARNING)
    logging.getLogger("aioquic").setLevel(logging.WARNING)

    logger = structlog.get_logger(__name__)
    logger.info(
        "logging_configured",
        log_level=log_level,
        output_dir=str(output_path),
        log_file=log_filename,
    )
