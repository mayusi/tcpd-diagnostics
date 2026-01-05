#!/usr/bin/env python3
"""
TCPD - Tester's Comprehensive PC Diagnostics

A portable CLI tool for diagnosing PC hardware, security, and system health.
Run from USB drive without installation.

Usage:
    python diagnostics.py scan --mode quick
    python diagnostics.py scan --mode full --output report.json
    python diagnostics.py hardware
    python diagnostics.py security
"""

import sys
import os

# Ensure we can import from src
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


if __name__ == "__main__":
    try:
        # Fix sys.argv for PyInstaller - when double-clicked, only keep the exe name
        # Filter out any arguments that look like the exe path itself
        if len(sys.argv) > 1:
            filtered_args = [sys.argv[0]]
            for arg in sys.argv[1:]:
                # Skip if arg is the exe path (happens with some PyInstaller builds)
                if not (arg.endswith('.exe') and os.path.isfile(arg)):
                    filtered_args.append(arg)
            sys.argv = filtered_args

        from src.cli.app import main
        main()
    except Exception as e:
        import traceback
        print("\n" + "=" * 60)
        print("TCPD ERROR - Please report this issue")
        print("=" * 60)
        traceback.print_exc()
        print("=" * 60)
        input("\nPress Enter to exit...")
        sys.exit(1)
