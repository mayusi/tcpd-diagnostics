"""WMI query helper with fallbacks."""
import subprocess
import json
from typing import Any, Dict, List, Optional
from functools import lru_cache


class WMIHelper:
    """Helper class for Windows Management Instrumentation queries."""

    def __init__(self):
        self._wmi = None
        self._wmi_available = self._check_wmi()

    def _check_wmi(self) -> bool:
        """Check if WMI module is available."""
        try:
            import wmi
            self._wmi = wmi.WMI()
            return True
        except ImportError:
            return False
        except Exception:
            return False

    @lru_cache(maxsize=50)
    def query(self, wmi_class: str, namespace: str = "root\\cimv2") -> List[Dict[str, Any]]:
        """
        Query a WMI class and return results as list of dictionaries.

        Args:
            wmi_class: WMI class name (e.g., "Win32_Processor")
            namespace: WMI namespace (default: root\\cimv2)

        Returns:
            List of dictionaries with WMI object properties
        """
        if self._wmi_available:
            return self._query_wmi(wmi_class, namespace)
        else:
            return self._query_powershell(wmi_class)

    def _query_wmi(self, wmi_class: str, namespace: str) -> List[Dict[str, Any]]:
        """Query using Python WMI module."""
        try:
            import wmi
            if namespace != "root\\cimv2":
                c = wmi.WMI(namespace=namespace)
            else:
                c = self._wmi

            results = []
            for item in getattr(c, wmi_class)():
                obj_dict = {}
                for prop in item.properties:
                    try:
                        obj_dict[prop] = getattr(item, prop)
                    except Exception:
                        obj_dict[prop] = None
                results.append(obj_dict)
            return results
        except Exception as e:
            return []

    def _query_powershell(self, wmi_class: str) -> List[Dict[str, Any]]:
        """Fallback: Query using PowerShell."""
        try:
            cmd = f'Get-CimInstance -ClassName {wmi_class} | ConvertTo-Json -Depth 3'
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', cmd],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                # Ensure it's always a list
                if isinstance(data, dict):
                    return [data]
                return data
            return []
        except Exception:
            return []

    def query_single(self, wmi_class: str, namespace: str = "root\\cimv2") -> Optional[Dict[str, Any]]:
        """Query and return first result only."""
        results = self.query(wmi_class, namespace)
        return results[0] if results else None

    def get_property(self, wmi_class: str, property_name: str, default: Any = None) -> Any:
        """Get a single property from first WMI result."""
        result = self.query_single(wmi_class)
        if result:
            return result.get(property_name, default)
        return default


# Convenience functions
_helper = None


def get_wmi_helper() -> WMIHelper:
    """Get singleton WMI helper instance."""
    global _helper
    if _helper is None:
        _helper = WMIHelper()
    return _helper


def wmi_query(wmi_class: str, namespace: str = "root\\cimv2") -> List[Dict[str, Any]]:
    """Convenience function for WMI queries."""
    return get_wmi_helper().query(wmi_class, namespace)


def wmi_get(wmi_class: str, property_name: str, default: Any = None) -> Any:
    """Convenience function to get single WMI property."""
    return get_wmi_helper().get_property(wmi_class, property_name, default)
