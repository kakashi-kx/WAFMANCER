"""
Configuration management for WAFMANCER.
Supports YAML configuration files with environment variable overrides.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import structlog
import yaml

from wafmancer.exceptions import ConfigurationError

logger = structlog.get_logger(__name__)

DEFAULT_CONFIG_PATH = Path("config.yaml")

DEFAULT_CONFIG: Dict[str, Any] = {
    "target": {
        "timeout": 10.0,
        "max_redirects": 5,
        "verify_ssl": True,
        "user_agent": "Wafmancer-Research/1.0",
    },
    "oracle": {
        "max_probes": 1000,
        "concurrency": 10,
        "probe_delay": 0.1,
        "decision_threshold": 0.95,
        "research_mode": True,  # Save all request/response pairs
    },
    "logging": {
        "level": "INFO",
        "format": "json",  # structured or json
        "output_dir": "logs",
        "save_requests": True,
        "save_responses": True,
    },
    "plugins": {
        "enabled": ["fuzzer"],  # Start with fuzzer only
        "load_paths": ["wafmancer.plugins"],
    },
    "output": {
        "research_dir": "research",
        "data_dir": "data",
        "report_format": "markdown",
    },
}


class WafmancerConfig:
    """
    Unified configuration manager with layered resolution:
    1. Default values
    2. YAML config file
    3. Environment variables (prefixed with WAFMANCER_)
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self._config = DEFAULT_CONFIG.copy()
        self.config_path = config_path or DEFAULT_CONFIG_PATH

        # Layer 2: Load YAML if exists
        if self.config_path.exists():
            self._load_yaml()

        # Layer 3: Environment variable overrides
        self._apply_env_overrides()

        logger.info("configuration_loaded", config_path=str(self.config_path))

    def _load_yaml(self) -> None:
        """Load and merge YAML configuration."""
        try:
            with open(self.config_path, "r") as f:
                yaml_config = yaml.safe_load(f)
            if yaml_config:
                self._deep_merge(self._config, yaml_config)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {self.config_path}: {e}")

    def _apply_env_overrides(self) -> None:
        """Override configuration with WAFMANCER_* environment variables."""
        prefix = "WAFMANCER_"
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()
                keys = config_key.split("__")

                # Navigate to nested location
                target = self._config
                for k in keys[:-1]:
                    if k not in target:
                        target[k] = {}
                    target = target[k]

                # Set the value with type conversion
                target[keys[-1]] = self._convert_env_value(value)

    @staticmethod
    def _convert_env_value(value: str) -> Any:
        """Convert environment variable string to appropriate type."""
        # Boolean
        if value.lower() in ("true", "false"):
            return value.lower() == "true"
        # Integer
        try:
            return int(value)
        except ValueError:
            pass
        # Float
        try:
            return float(value)
        except ValueError:
            pass
        # String (default)
        return value

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> None:
        """Recursively merge override dict into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                WafmancerConfig._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, *keys: str, default: Any = None) -> Any:
        """Safely access nested configuration values."""
        current = self._config
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return default
            if current is None:
                return default
        return current

    def __getitem__(self, key: str) -> Any:
        return self._config[key]

    def __contains__(self, key: str) -> bool:
        return key in self._config

    def to_dict(self) -> Dict[str, Any]:
        """Return complete configuration as dictionary."""
        return self._config.copy()


# Global configuration instance
config = WafmancerConfig()
