"""Admin privilege detection and elevation utilities."""
import ctypes
import sys
import os


def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_elevation():
    """
    Request UAC elevation by re-launching the script as admin.

    This will trigger a UAC prompt and restart the application
    with elevated privileges.
    """
    if is_admin():
        return True  # Already admin

    try:
        # Get the current script/executable path
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            script = sys.executable
        else:
            # Running as script
            script = os.path.abspath(sys.argv[0])

        # Re-run with elevated privileges
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])

        result = ctypes.windll.shell32.ShellExecuteW(
            None,           # hwnd
            "runas",        # Operation (run as admin)
            sys.executable, # Executable
            f'"{script}" {params}',  # Parameters
            None,           # Working directory
            1               # Show window
        )

        # ShellExecuteW returns > 32 on success
        if result > 32:
            sys.exit(0)  # Exit current non-elevated process
        else:
            return False  # Elevation failed or was cancelled

    except Exception:
        return False


def get_elevation_status() -> dict:
    """Get detailed elevation status information."""
    return {
        "is_admin": is_admin(),
        "can_elevate": sys.platform == "win32",
        "platform": sys.platform
    }


def run_with_admin_check(require_admin: bool = False):
    """
    Decorator/function to check admin status before running.

    If require_admin is True and not running as admin,
    will attempt to elevate.
    """
    if require_admin and not is_admin():
        print("This operation requires administrator privileges.")
        print("Requesting elevation...")
        if not request_elevation():
            print("Failed to obtain administrator privileges.")
            print("Some features may be limited.")
            return False
    return True


# Quick check when module is imported
RUNNING_AS_ADMIN = is_admin()
