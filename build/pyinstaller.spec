# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for TCPD - Tester's Comprehensive PC Diagnostics

Build command:
    pyinstaller build/pyinstaller.spec

This creates a single portable executable.
"""

import sys
from pathlib import Path

# Project root
project_root = Path(SPECPATH).parent

block_cipher = None

a = Analysis(
    [str(project_root / 'diagnostics.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(project_root / 'config'), 'config'),
    ],
    hiddenimports=[
        # Core dependencies
        'wmi',
        'win32com.client',
        'win32api',
        'win32security',
        'win32process',
        'pythoncom',
        'pywintypes',
        # Scanner dependencies
        'psutil',
        'cpuinfo',
        'pynvml',
        'GPUtil',
        'numpy',
        # CLI
        'typer',
        'rich',
        'click',
        'yaml',
        'pydantic',
        'questionary',
        # Our modules
        'src',
        'src.cli',
        'src.cli.app',
        'src.cli.interactive',
        'src.cli.ui',
        'src.cli.ui.console',
        'src.cli.ui.export',
        'src.core',
        'src.core.engine',
        'src.core.scanner',
        'src.core.result',
        'src.scanners',
        'src.scanners.hardware',
        'src.scanners.hardware.cpu',
        'src.scanners.hardware.gpu',
        'src.scanners.hardware.memory',
        'src.scanners.hardware.storage',
        'src.scanners.hardware.battery',
        'src.scanners.hardware.motherboard',
        'src.scanners.hardware.network_adapters',
        'src.scanners.hardware.peripherals',
        'src.scanners.security',
        'src.scanners.security.antivirus',
        'src.scanners.security.firewall',
        'src.scanners.security.windows_update',
        'src.scanners.security.ports',
        'src.scanners.security.processes',
        'src.scanners.security.startup',
        'src.scanners.security.services',
        'src.scanners.security.users',
        'src.scanners.security.bitlocker',
        'src.scanners.security.secure_boot',
        'src.scanners.security.uac',
        'src.scanners.security.password_policy',
        'src.scanners.security.event_log',
        'src.scanners.network',
        'src.scanners.network.connectivity',
        'src.scanners.network.wifi',
        'src.scanners.network.dns',
        'src.scanners.network.speed_test',
        'src.scanners.system',
        'src.scanners.system.os_info',
        'src.stress',
        'src.stress.cpu_stress',
        'src.stress.gpu_stress',
        'src.stress.memory_stress',
        'src.monitor',
        'src.info',
        'src.reports',
        'src.utils',
        'src.utils.admin',
        'src.utils.wmi_helper',
        'src.utils.registry',
        'src.utils.dependency_installer',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'pandas',
        'scipy',
        'tkinter',
        'unittest',
        'test',
        'tests',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='tcpd',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon path here if you have one
    uac_admin=False,  # Don't require admin by default, we request it at runtime
    version=None,
)
