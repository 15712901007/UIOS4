# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for iKuai Router 4.0 Automation Tool
"""

import json
import os
import sys

import playwright
from PyInstaller.utils.hooks import collect_submodules

# Resolve paths from the spec location so the build is not tied to one machine.
project_root = os.path.abspath(os.path.join(SPECPATH, os.pardir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


def _playwright_browser_datas():
    """Bundle the browser revisions required by the installed Playwright."""
    if os.environ.get("IKUAI_SKIP_PLAYWRIGHT_BROWSERS") == "1":
        return []

    cache_root = os.environ.get(
        "PLAYWRIGHT_BROWSERS_PATH",
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "ms-playwright"),
    )
    manifest = os.path.join(
        os.path.dirname(playwright.__file__), "driver", "package", "browsers.json"
    )
    with open(manifest, encoding="utf-8") as stream:
        browser_manifest = json.load(stream)

    datas = []
    required_names = {"chromium", "chromium-headless-shell", "ffmpeg"}
    for browser in browser_manifest.get("browsers", []):
        name = browser.get("name")
        if name not in required_names or not browser.get("installByDefault", False):
            continue
        folder_name = f"{name.replace('-', '_')}-{browser['revision']}"
        source = os.path.join(cache_root, folder_name)
        if not os.path.isdir(source):
            raise FileNotFoundError(
                f"Required Playwright browser is missing: {source}. "
                "Run `python -m playwright install chromium` before packaging."
            )
        datas.append((source, os.path.join("playwright", folder_name)))
    return datas


# pytest loads project tests and helpers dynamically at runtime. Explicitly
# collect their module graphs so imports used only by a selected GUI test are
# still frozen into the executable.
dynamic_hiddenimports = []
for package_name in (
    "pages",
    "utils",
    "tests",
    "playwright",
    "_pytest",
    "paramiko",
    "jinja2",
    "yaml",
):
    dynamic_hiddenimports.extend(collect_submodules(package_name))

datas = [
    # Configuration files
    (os.path.join(project_root, 'config', 'settings.yaml'), 'config'),
    (os.path.join(project_root, 'pytest.ini'), '.'),
    # Python sources collected dynamically by pytest in the packaged GUI.
    (os.path.join(project_root, 'pages'), 'pages'),
    (os.path.join(project_root, 'utils'), 'utils'),
    (os.path.join(project_root, 'tests'), 'tests'),
    # GUI resources
    (os.path.join(project_root, 'gui', 'gui_resources'), 'gui/gui_resources'),
    # Report templates
    (os.path.join(project_root, 'reports', 'templates'), 'reports/templates'),
    # Test data imports
    (os.path.join(project_root, 'test_data', 'imports'), 'test_data/imports'),
]
datas.extend(_playwright_browser_datas())

a = Analysis(
    [os.path.join(project_root, 'main.py')],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=sorted(set([
        # PySide6
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        # Playwright
        'playwright',
        'playwright.sync_api',
        'playwright._impl',
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
    ] + dynamic_hiddenimports)),
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
    [],
    exclude_binaries=True,
    name='iKuai自动化测试工具',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # GUI application, no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name='iKuai自动化测试工具',
)
