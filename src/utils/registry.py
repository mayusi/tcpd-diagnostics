"""Windows Registry access utilities."""
import winreg
from typing import Any, Dict, List, Optional, Tuple


# Registry hive mappings
HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS,
    "HKCC": winreg.HKEY_CURRENT_CONFIG,
}


def parse_key_path(path: str) -> Tuple[int, str]:
    """
    Parse registry path into hive and subkey.

    Args:
        path: Full registry path (e.g., "HKLM\\SOFTWARE\\Microsoft")

    Returns:
        Tuple of (hive_constant, subkey_path)
    """
    parts = path.split("\\", 1)
    hive_name = parts[0].upper()
    subkey = parts[1] if len(parts) > 1 else ""

    hive = HIVES.get(hive_name)
    if hive is None:
        raise ValueError(f"Unknown registry hive: {hive_name}")

    return hive, subkey


def read_value(path: str, value_name: str, default: Any = None) -> Any:
    """
    Read a single registry value.

    Args:
        path: Registry key path (e.g., "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
        value_name: Name of the value to read
        default: Default value if not found

    Returns:
        The registry value or default
    """
    try:
        hive, subkey = parse_key_path(path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value
    except (FileNotFoundError, OSError, PermissionError):
        return default


def read_all_values(path: str) -> Dict[str, Any]:
    """
    Read all values from a registry key.

    Args:
        path: Registry key path

    Returns:
        Dictionary of value_name: value pairs
    """
    result = {}
    try:
        hive, subkey = parse_key_path(path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    result[name] = value
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, OSError, PermissionError):
        pass
    return result


def list_subkeys(path: str) -> List[str]:
    """
    List all subkeys under a registry key.

    Args:
        path: Registry key path

    Returns:
        List of subkey names
    """
    result = []
    try:
        hive, subkey = parse_key_path(path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(key, i)
                    result.append(name)
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, OSError, PermissionError):
        pass
    return result


def key_exists(path: str) -> bool:
    """Check if a registry key exists."""
    try:
        hive, subkey = parse_key_path(path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ):
            return True
    except (FileNotFoundError, OSError, PermissionError):
        return False


def value_exists(path: str, value_name: str) -> bool:
    """Check if a registry value exists."""
    try:
        hive, subkey = parse_key_path(path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, value_name)
            return True
    except (FileNotFoundError, OSError, PermissionError):
        return False


# Common registry paths
class RegistryPaths:
    """Common Windows registry paths."""

    # System info
    WINDOWS_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    COMPUTER_NAME = r"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"

    # Startup locations
    RUN_MACHINE = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    RUN_USER = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    RUNONCE_MACHINE = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    RUNONCE_USER = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

    # Services
    SERVICES = r"HKLM\SYSTEM\CurrentControlSet\Services"

    # Uninstall (installed programs)
    UNINSTALL_64 = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    UNINSTALL_32 = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    UNINSTALL_USER = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    # Security
    WINDOWS_DEFENDER = r"HKLM\SOFTWARE\Microsoft\Windows Defender"
    UAC = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


def get_startup_entries() -> List[Dict[str, str]]:
    """Get all startup entries from common registry locations."""
    entries = []

    startup_paths = [
        (RegistryPaths.RUN_MACHINE, "Machine"),
        (RegistryPaths.RUN_USER, "User"),
        (RegistryPaths.RUNONCE_MACHINE, "Machine (RunOnce)"),
        (RegistryPaths.RUNONCE_USER, "User (RunOnce)"),
    ]

    for path, location in startup_paths:
        values = read_all_values(path)
        for name, command in values.items():
            entries.append({
                "name": name,
                "command": str(command),
                "location": location,
                "registry_path": path
            })

    return entries
