# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for iKuai Router 4.0 Automation Tool (Single File with Browser)
"""

import os
import sys

# Get the project root directory
project_root = r'c:\Users\51355\Desktop\4.0前端UI自动化测试'

# Playwright browser path
playwright_browsers_path = r'C:\Users\51355\AppData\Local\ms-playwright'

a = Analysis(
    [os.path.join(project_root, 'main.py')],
    pathex=[project_root],
    binaries=[],
    datas=[
        # Configuration files (embedded in exe)
        (os.path.join(project_root, 'config', 'settings.yaml'), 'config'),
        # Python packages (for pytest imports)
        (os.path.join(project_root, 'pages'), 'pages'),
        (os.path.join(project_root, 'utils'), 'utils'),
        (os.path.join(project_root, 'tests'), 'tests'),
        # GUI resources
        (os.path.join(project_root, 'gui', 'gui_resources'), 'gui/gui_resources'),
        # Report templates
        (os.path.join(project_root, 'reports', 'templates'), 'reports/templates'),
        # Test data imports
        (os.path.join(project_root, 'test_data', 'imports'), 'test_data/imports'),
        # Playwright chromium browser (full version, needed for headed mode)
        (os.path.join(playwright_browsers_path, 'chromium-1208'), 'playwright/chromium-1208'),
        # Playwright driver (from system Python)
        (r'C:\Users\51355\AppData\Local\Programs\Python\Python313\Lib\site-packages\playwright\driver', 'playwright/driver'),
    ],
    hiddenimports=[
        # PySide6
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        # Playwright
        'playwright',
        'playwright.sync_api',
        'playwright._impl',
        # pytest-playwright plugin
        'pytest_playwright',
        'pytest_playwright.pytest_playwright',
        'pytest_playwright._repo_version',
        # Paramiko (SSH)
        'paramiko',
        'cryptography',
        # Other dependencies
        'yaml',
        'jinja2',
        'pytest',
        '_pytest',
        'apscheduler',
        'apscheduler.schedulers.background',
        'colorlog',
        'greenlet',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'scipy',
        'PIL',
        'cv2',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='iKuai自动化测试工具',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Enable console for pytest output (GUI still works)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
