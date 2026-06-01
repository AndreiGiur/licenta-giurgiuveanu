# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec pentru VulnWatchAgent.

Build:
    pyinstaller --clean agent/VulnWatchAgent.spec

Output:
    dist/VulnWatchAgent.exe   (Windows, --onefile)

Detalii:
- console=False  → fara consola la dublu-click (GUI mode).
- hiddenimports  → asigura ca PyInstaller include subpachetele psutil
                   pentru platforma curenta si plumbingul pystray.
"""
import sys
from pathlib import Path

block_cipher = None
_win = sys.platform == "win32"

repo_root = Path.cwd()
agent_dir = repo_root / "agent"

a = Analysis(
    [str(agent_dir / "scan.py")],
    pathex=[str(repo_root)],
    binaries=[],
    datas=[
        # Scriptul NSE custom — deployed la startup in NSE scripts dir al nmap.
        (str(agent_dir / "nse" / "vulnwatch-audit.nse"), "nse"),
    ],
    hiddenimports=(
        [
            "agent",
            "agent.core",
            "agent.gui",
            "agent.autostart",
            "agent.tray",
            "agent.service",
            "agent.ipc",
            "agent.nmap_runner",
            "agent.nmap_parser",
            "agent.single_instance",
            # pystray backend-uri cross-platform + PIL
            "pystray._gtk",
            "pystray._darwin",
            "pystray._dummy",
            "PIL.Image",
            "PIL.ImageDraw",
        ]
        # pywin32 + backend pystray Windows — DOAR pe Windows (nu exista pe Linux)
        + ([
            "win32serviceutil",
            "win32service",
            "win32event",
            "win32api",
            "winerror",
            "servicemanager",
            "pywintypes",
            "pystray._win32",
        ] if _win else [])
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # excludem toolkit-uri pe care nu le folosim — reduce dimensiunea
        "matplotlib", "numpy", "PyQt5", "PyQt6", "PySide2", "PySide6",
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
    name="VulnWatchAgent" if _win else "vulnwatch-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # fara consola → GUI/tray pur
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
