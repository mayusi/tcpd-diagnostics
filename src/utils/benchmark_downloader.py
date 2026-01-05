"""Benchmark tool downloader for PC Diagnostics Tool."""
import os
import sys
import subprocess
import zipfile
import shutil
from pathlib import Path
from typing import Optional, Callable, Dict, List
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


# Benchmark tools configuration
BENCHMARK_TOOLS: Dict[str, dict] = {
    "furmark": {
        "name": "FurMark 2",
        "description": "GPU stress test & burn-in",
        "url": "https://geeks3d.com/dl/get/815",
        "filename": "FurMark2_Setup.exe",
        "category": "gpu",
        "portable": False,
        "size_mb": 25,
        "executable": "FurMark2_Setup.exe"
    },
    "gpu-z": {
        "name": "GPU-Z",
        "description": "GPU info & monitoring",
        "url": "https://us1-dl.techpowerup.com/files/GPU-Z.2.57.0.exe",
        "filename": "GPU-Z.exe",
        "category": "gpu",
        "portable": True,
        "size_mb": 9,
        "executable": "GPU-Z.exe"
    },
    "cinebench": {
        "name": "Cinebench R23",
        "description": "CPU rendering benchmark",
        "url": "https://installer.maxon.net/cinebench/CinebenchR23.zip",
        "filename": "CinebenchR23.zip",
        "category": "cpu",
        "portable": True,
        "size_mb": 300,
        "executable": "Cinebench.exe"
    },
    "prime95": {
        "name": "Prime95",
        "description": "CPU stress test",
        "url": "https://www.mersenne.org/ftp_root/gimps/p95v3019b13.win64.zip",
        "filename": "p95v3019b13.win64.zip",
        "category": "cpu",
        "portable": True,
        "size_mb": 10,
        "executable": "prime95.exe"
    },
    "cpu-z": {
        "name": "CPU-Z",
        "description": "CPU info & monitoring",
        "url": "https://download.cpuid.com/cpu-z/cpu-z_2.09-en.zip",
        "filename": "cpu-z_2.09-en.zip",
        "category": "cpu",
        "portable": True,
        "size_mb": 2,
        "executable": "cpuz_x64.exe"
    }
}


def get_tools_folder() -> Path:
    """
    Get or create the tools folder.

    Returns:
        Path to the tools folder
    """
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller bundle - use folder next to exe
        base_path = Path(sys.executable).parent
    else:
        # Running as script - use project root
        base_path = Path(__file__).parent.parent.parent

    tools_folder = base_path / "tools"
    tools_folder.mkdir(exist_ok=True)

    return tools_folder


def list_available_tools() -> Dict[str, dict]:
    """Return all available benchmark tools."""
    return BENCHMARK_TOOLS.copy()


def get_tools_by_category(category: str) -> Dict[str, dict]:
    """Get tools filtered by category (gpu, cpu)."""
    return {k: v for k, v in BENCHMARK_TOOLS.items() if v['category'] == category}


def is_tool_downloaded(tool_id: str) -> bool:
    """Check if a tool has already been downloaded AND the executable exists."""
    if tool_id not in BENCHMARK_TOOLS:
        return False

    # Actually check if we can find the executable
    tool_path = get_tool_path(tool_id)
    return tool_path is not None and tool_path.exists()


def get_tool_path(tool_id: str) -> Optional[Path]:
    """Get the path to a downloaded tool's executable."""
    if tool_id not in BENCHMARK_TOOLS:
        return None

    tool = BENCHMARK_TOOLS[tool_id]
    tools_folder = get_tools_folder()

    # Check for extracted folder
    tool_folder = tools_folder / tool_id
    if tool_folder.exists():
        # Look for executable in folder
        exe = tool_folder / tool['executable']
        if exe.exists():
            return exe
        # Search for any exe
        for f in tool_folder.rglob("*.exe"):
            if tool['executable'].lower() in f.name.lower():
                return f
        # Return first exe found
        for f in tool_folder.rglob("*.exe"):
            return f

    # Check for direct download
    direct_file = tools_folder / tool['filename']
    if direct_file.exists() and direct_file.suffix.lower() == '.exe':
        return direct_file

    return None


def download_file(
    url: str,
    dest: Path,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> bool:
    """
    Download a file from URL with progress reporting.

    Args:
        url: URL to download from
        dest: Destination file path
        progress_callback: Optional callback(downloaded_bytes, total_bytes)

    Returns:
        True if successful, False otherwise
    """
    try:
        # Create request with user agent
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        request = Request(url, headers=headers)

        with urlopen(request, timeout=30) as response:
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            chunk_size = 8192

            with open(dest, 'wb') as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback(downloaded, total_size)

        return True

    except (URLError, HTTPError) as e:
        # Clean up partial download
        if dest.exists():
            dest.unlink()
        return False
    except Exception as e:
        if dest.exists():
            dest.unlink()
        return False


def extract_zip(zip_path: Path, dest_folder: Path) -> Optional[Path]:
    """
    Extract a ZIP file.

    Args:
        zip_path: Path to ZIP file
        dest_folder: Destination folder

    Returns:
        Path to extracted folder, or None on failure
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(dest_folder)

        # Clean up ZIP after extraction
        zip_path.unlink()

        return dest_folder

    except Exception as e:
        return None


def download_tool(
    tool_id: str,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> Optional[Path]:
    """
    Download and extract a benchmark tool.

    Args:
        tool_id: Tool identifier (e.g., 'furmark', 'cpu-z')
        progress_callback: Optional progress callback(downloaded, total)

    Returns:
        Path to the tool executable, or None on failure
    """
    if tool_id not in BENCHMARK_TOOLS:
        return None

    tool = BENCHMARK_TOOLS[tool_id]
    tools_folder = get_tools_folder()

    # Create tool-specific folder
    tool_folder = tools_folder / tool_id
    tool_folder.mkdir(exist_ok=True)

    # Download the file
    download_path = tool_folder / tool['filename']
    success = download_file(tool['url'], download_path, progress_callback)

    if not success:
        # Clean up empty folder
        if tool_folder.exists() and not any(tool_folder.iterdir()):
            tool_folder.rmdir()
        return None

    # Extract if ZIP file
    if download_path.suffix.lower() == '.zip':
        extract_zip(download_path, tool_folder)

    # Find and return executable path
    return get_tool_path(tool_id)


def run_tool(tool_path: Path) -> tuple:
    """
    Launch a downloaded tool.

    Args:
        tool_path: Path to the tool executable

    Returns:
        Tuple of (success, error_message)
    """
    if not tool_path:
        return False, "Tool path is None"

    if not tool_path.exists():
        return False, f"File not found: {tool_path}"

    try:
        # Use os.startfile on Windows - handles installers and permissions better
        if os.name == 'nt':
            os.startfile(str(tool_path))
        else:
            subprocess.Popen(
                [str(tool_path)],
                cwd=str(tool_path.parent),
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
        return True, None
    except OSError as e:
        return False, f"OS Error: {e}"
    except Exception as e:
        return False, f"Error: {e}"


def delete_tool(tool_id: str) -> bool:
    """
    Delete a downloaded tool.

    Args:
        tool_id: Tool identifier

    Returns:
        True if deleted successfully
    """
    if tool_id not in BENCHMARK_TOOLS:
        return False

    tools_folder = get_tools_folder()
    tool_folder = tools_folder / tool_id

    try:
        if tool_folder.exists():
            shutil.rmtree(tool_folder)
            return True
    except Exception:
        pass

    return False


def get_download_status() -> Dict[str, bool]:
    """Get download status of all tools."""
    return {tool_id: is_tool_downloaded(tool_id) for tool_id in BENCHMARK_TOOLS}


def get_total_download_size(tool_ids: List[str]) -> int:
    """Get total download size in MB for a list of tools."""
    total = 0
    for tool_id in tool_ids:
        if tool_id in BENCHMARK_TOOLS and not is_tool_downloaded(tool_id):
            total += BENCHMARK_TOOLS[tool_id]['size_mb']
    return total
