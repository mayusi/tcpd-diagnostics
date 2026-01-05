#!/usr/bin/env python3
"""
Build script for TCPD - Tester's Comprehensive PC Diagnostics

Usage:
    python build/build.py

This creates a portable executable in the dist/ folder.
"""

import subprocess
import shutil
from pathlib import Path
import sys


def main():
    # Get paths
    project_root = Path(__file__).parent.parent
    spec_file = project_root / "build" / "pyinstaller.spec"
    dist_dir = project_root / "dist"

    print("=" * 60)
    print("TCPD - Build Script")
    print("=" * 60)

    # Check for PyInstaller
    try:
        import PyInstaller
        print(f"[OK] PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[ERROR] PyInstaller not found. Install with: pip install pyinstaller")
        sys.exit(1)

    # Clean previous builds
    print("\n[1/3] Cleaning previous builds...")
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    build_dir = project_root / "build" / "tcpd"
    if build_dir.exists():
        shutil.rmtree(build_dir)

    # Run PyInstaller
    print("\n[2/3] Building executable...")
    result = subprocess.run(
        [
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "--noconfirm",
            str(spec_file)
        ],
        cwd=str(project_root)
    )

    if result.returncode != 0:
        print("\n[ERROR] Build failed!")
        sys.exit(1)

    # Verify output
    print("\n[3/3] Verifying build...")
    exe_path = dist_dir / "tcpd.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n[SUCCESS] Build complete!")
        print(f"  Location: {exe_path}")
        print(f"  Size: {size_mb:.1f} MB")
        print("\nYou can now copy tcpd.exe to a USB drive and run it on any Windows 10/11 PC.")
    else:
        print("\n[ERROR] Executable not found!")
        sys.exit(1)


if __name__ == "__main__":
    main()
