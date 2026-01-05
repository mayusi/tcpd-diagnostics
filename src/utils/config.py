"""Configuration loader for PC Diagnostics Tool."""
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class Config:
    """Configuration manager for the diagnostic tool."""

    _instance: Optional["Config"] = None
    _config: Dict[str, Any] = {}
    _thresholds: Dict[str, Any] = {}

    def __new__(cls):
        """Singleton pattern - only one config instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_configs()
        return cls._instance

    def _get_config_dir(self) -> Path:
        """Get the config directory path."""
        # Check if running as PyInstaller bundle
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            base_path = Path(sys._MEIPASS)
        else:
            # Running as script
            base_path = Path(__file__).parent.parent.parent

        return base_path / "config"

    def _load_configs(self):
        """Load configuration files."""
        config_dir = self._get_config_dir()

        # Load default config
        default_path = config_dir / "default.yaml"
        if default_path.exists():
            try:
                with open(default_path, "r") as f:
                    self._config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Could not load default config: {e}")
                self._config = {}
        else:
            self._config = {}

        # Load thresholds
        thresholds_path = config_dir / "thresholds.yaml"
        if thresholds_path.exists():
            try:
                with open(thresholds_path, "r") as f:
                    self._thresholds = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Could not load thresholds config: {e}")
                self._thresholds = {}
        else:
            self._thresholds = {}

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value by dot-notation key."""
        keys = key.split(".")
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def get_threshold(self, category: str, level: str) -> Optional[int]:
        """Get a threshold value.

        Args:
            category: The category (e.g., 'disk', 'memory', 'cpu_temp')
            level: The level ('warning' or 'critical')

        Returns:
            The threshold value or None if not found
        """
        if category in self._thresholds:
            cat_config = self._thresholds[category]
            if isinstance(cat_config, dict) and level in cat_config:
                return cat_config[level]
        return None

    @property
    def disk_warning(self) -> int:
        """Disk usage warning threshold (percentage)."""
        return self.get_threshold("disk", "warning") or 85

    @property
    def disk_critical(self) -> int:
        """Disk usage critical threshold (percentage)."""
        return self.get_threshold("disk", "critical") or 95

    @property
    def memory_warning(self) -> int:
        """Memory usage warning threshold (percentage)."""
        return self.get_threshold("memory", "warning") or 80

    @property
    def memory_critical(self) -> int:
        """Memory usage critical threshold (percentage)."""
        return self.get_threshold("memory", "critical") or 90

    @property
    def cpu_temp_warning(self) -> int:
        """CPU temperature warning threshold (Celsius)."""
        return self.get_threshold("cpu_temp", "warning") or 75

    @property
    def cpu_temp_critical(self) -> int:
        """CPU temperature critical threshold (Celsius)."""
        return self.get_threshold("cpu_temp", "critical") or 85

    @property
    def gpu_temp_warning(self) -> int:
        """GPU temperature warning threshold (Celsius)."""
        return self.get_threshold("gpu_temp", "warning") or 80

    @property
    def gpu_temp_critical(self) -> int:
        """GPU temperature critical threshold (Celsius)."""
        return self.get_threshold("gpu_temp", "critical") or 90

    @property
    def battery_wear_warning(self) -> int:
        """Battery wear warning threshold (percentage)."""
        return self.get_threshold("battery_wear", "warning") or 20

    @property
    def battery_wear_critical(self) -> int:
        """Battery wear critical threshold (percentage)."""
        return self.get_threshold("battery_wear", "critical") or 40

    @property
    def auto_elevate(self) -> bool:
        """Whether to auto-elevate to admin."""
        return self.get("admin.auto_elevate", True)

    @property
    def default_scan_mode(self) -> str:
        """Default scan mode."""
        return self.get("scan.default_mode", "quick")

    @property
    def scan_timeout(self) -> int:
        """Scan timeout in seconds."""
        return self.get("scan.timeout_seconds", 300)


# Global config instance
config = Config()


def get_config() -> Config:
    """Get the global config instance."""
    return config
