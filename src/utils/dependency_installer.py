"""Dependency installer for PC Diagnostics Tool."""
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple, Optional


# Map of import names to pip package names
REQUIRED_PACKAGES = {
    'psutil': 'psutil',
    'wmi': 'wmi',
    'win32api': 'pywin32',
    'win32com': 'pywin32',
    'cpuinfo': 'py-cpuinfo',
    'pynvml': 'pynvml',
    'GPUtil': 'GPUtil',
    'typer': 'typer[all]',
    'rich': 'rich',
    'questionary': 'questionary',
    'yaml': 'pyyaml',
    'pydantic': 'pydantic',
}


def check_package(import_name: str) -> bool:
    """Check if a package can be imported."""
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def check_missing_dependencies() -> List[Tuple[str, str]]:
    """
    Check for missing Python dependencies.

    Returns:
        List of tuples (import_name, pip_package_name) for missing packages
    """
    missing = []
    for import_name, pip_name in REQUIRED_PACKAGES.items():
        if not check_package(import_name):
            missing.append((import_name, pip_name))
    return missing


def get_installed_packages() -> List[Tuple[str, str]]:
    """
    Get list of packages that are successfully installed.

    Returns:
        List of tuples (import_name, pip_package_name) for installed packages
    """
    installed = []
    for import_name, pip_name in REQUIRED_PACKAGES.items():
        if check_package(import_name):
            installed.append((import_name, pip_name))
    return installed


def install_package(pip_name: str) -> Tuple[bool, str]:
    """
    Install a single package using pip.

    Args:
        pip_name: The pip package name to install

    Returns:
        Tuple of (success, message)
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pip_name],
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout per package
        )
        if result.returncode == 0:
            return True, f"Successfully installed {pip_name}"
        else:
            return False, f"Failed to install {pip_name}: {result.stderr}"
    except subprocess.TimeoutExpired:
        return False, f"Timeout installing {pip_name}"
    except Exception as e:
        return False, f"Error installing {pip_name}: {str(e)}"


def install_packages(packages: List[str]) -> List[Tuple[str, bool, str]]:
    """
    Install multiple packages.

    Args:
        packages: List of pip package names to install

    Returns:
        List of tuples (package_name, success, message)
    """
    results = []
    for pkg in packages:
        success, msg = install_package(pkg)
        results.append((pkg, success, msg))
    return results


def install_all_requirements() -> Tuple[bool, str]:
    """
    Install all requirements from requirements.txt.

    Returns:
        Tuple of (success, message)
    """
    # Find requirements.txt
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller bundle
        base_path = Path(sys.executable).parent
    else:
        # Running as script
        base_path = Path(__file__).parent.parent.parent

    req_file = base_path / "requirements.txt"

    if not req_file.exists():
        return False, f"requirements.txt not found at {req_file}"

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout for all packages
        )
        if result.returncode == 0:
            return True, "All dependencies installed successfully"
        else:
            return False, f"Some packages failed to install: {result.stderr}"
    except subprocess.TimeoutExpired:
        return False, "Timeout installing dependencies"
    except Exception as e:
        return False, f"Error installing dependencies: {str(e)}"


def upgrade_pip() -> Tuple[bool, str]:
    """Upgrade pip to latest version."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            return True, "pip upgraded successfully"
        else:
            return False, f"Failed to upgrade pip: {result.stderr}"
    except Exception as e:
        return False, f"Error upgrading pip: {str(e)}"


def get_dependency_status() -> dict:
    """
    Get complete status of all dependencies.

    Returns:
        Dict with 'installed', 'missing', and 'total' counts
    """
    missing = check_missing_dependencies()
    installed = get_installed_packages()

    return {
        'installed': len(installed),
        'missing': len(missing),
        'total': len(REQUIRED_PACKAGES),
        'installed_list': installed,
        'missing_list': missing
    }
