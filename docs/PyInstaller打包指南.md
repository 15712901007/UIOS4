# PyInstaller 单文件打包指南

## 概述

本文档记录了将iKuai路由器自动化测试工具打包为单个EXE文件的完整流程和关键注意事项。

## 打包命令

```bash
cd "项目根目录"
python -m PyInstaller build/ikuai_test_onefile.spec --noconfirm --clean
```

## 关键配置文件

### 1. spec文件配置 (`build/ikuai_test_onefile.spec`)

```python
# -*- mode: python ; coding: utf-8 -*-
import os

project_root = r'项目根目录路径'
playwright_browsers_path = r'C:\Users\用户名\AppData\Local\ms-playwright'

a = Analysis(
    [os.path.join(project_root, 'main.py')],
    pathex=[project_root],
    binaries=[],
    datas=[
        # Python包（pytest需要这些模块）
        (os.path.join(project_root, 'pages'), 'pages'),
        (os.path.join(project_root, 'utils'), 'utils'),
        (os.path.join(project_root, 'tests'), 'tests'),
        # 配置和资源文件
        (os.path.join(project_root, 'config', 'settings.yaml'), 'config'),
        (os.path.join(project_root, 'gui', 'gui_resources'), 'gui/gui_resources'),
        (os.path.join(project_root, 'reports', 'templates'), 'reports/templates'),
        (os.path.join(project_root, 'test_data', 'imports'), 'test_data/imports'),
        # Playwright完整chromium浏览器（不是headless_shell！）
        (os.path.join(playwright_browsers_path, 'chromium-1208'), 'playwright/chromium-1208'),
        # Playwright driver
        (r'Python路径\Lib\site-packages\playwright\driver', 'playwright/driver'),
    ],
    hiddenimports=[
        'PySide6', 'PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets',
        'playwright', 'playwright.sync_api', 'playwright._impl',
        'pytest_playwright', 'pytest_playwright.pytest_playwright',
        'paramiko', 'cryptography',
        'yaml', 'jinja2', 'pytest', '_pytest',
        'apscheduler', 'apscheduler.schedulers.background',
        'colorlog', 'greenlet',
    ],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'PIL', 'cv2'],
)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='iKuai自动化测试工具',
    console=True,  # 必须为True，否则pytest输出无法显示
)
```

## 关键问题及解决方案

### 问题1：pytest-playwright的page fixture找不到

**原因**：PyInstaller打包后，pytest无法通过entry_points自动发现pytest-playwright插件。

**解决方案**：在`tests/conftest.py`中直接定义fixtures：

```python
from playwright.sync_api import Page, Browser, BrowserContext, Playwright, sync_playwright

@pytest.fixture(scope="session")
def playwright() -> Generator[Playwright, None, None]:
    pw = sync_playwright().start()
    yield pw
    pw.stop()

@pytest.fixture(scope="session")
def browser_name() -> str:
    return "chromium"

@pytest.fixture(scope="session")
def browser_type(playwright: Playwright, browser_name: str):
    return getattr(playwright, browser_name)

@pytest.fixture(scope="session")
def browser_type_launch_args() -> Dict:
    headless = os.environ.get("HEADLESS", "true").lower() == "true"
    return {"headless": headless}

@pytest.fixture(scope="session")
def browser(browser_type, browser_type_launch_args: Dict) -> Generator[Browser, None, None]:
    browser = browser_type.launch(**browser_type_launch_args)
    yield browser
    browser.close()

@pytest.fixture(scope="session")
def browser_context_args() -> Dict:
    return {}

@pytest.fixture(scope="function")
def context(browser: Browser, browser_context_args: Dict) -> Generator[BrowserContext, None, None]:
    context = browser.new_context(**browser_context_args)
    yield context
    context.close()

@pytest.fixture(scope="function")
def page(context: BrowserContext) -> Generator[Page, None, None]:
    page = context.new_page()
    yield page
    page.close()
```

### 问题2：浏览器找不到

**原因**：打包了`chromium_headless_shell`但Playwright查找`chromium`。

**解决方案**：打包完整的chromium浏览器，不是chromium_headless_shell：
```python
# 正确
(os.path.join(playwright_browsers_path, 'chromium-1208'), 'playwright/chromium-1208'),
# 错误
(os.path.join(playwright_browsers_path, 'chromium_headless_shell-1208'), 'playwright/chromium_headless_shell-1208'),
```

### 问题3：实时日志不显示（已解决）

**原因**：PyInstaller打包后，通过subprocess启动子进程时，stdout管道的缓冲行为与源码模式不同，导致日志被缓冲无法实时显示。

**解决方案**：放弃subprocess，在打包模式下直接在GUI线程中调用`pytest.main()`：

```python
# gui/test_runner.py

class RealtimeStdoutCapture:
    """实时stdout捕获器 - 捕获输出并通过Qt信号实时发送到GUI"""

    def __init__(self, log_callback, parse_callback=None):
        self.log_callback = log_callback
        self.parse_callback = parse_callback
        self._buffer = io.StringIO()
        self._encoding = 'utf-8'
        self._closed = False

    def write(self, text):
        if self._closed or not text:
            return 0
        self._buffer.write(text)
        text_stripped = text.rstrip('\n\r')
        if text_stripped:
            self.log_callback("INFO", text_stripped)
            if self.parse_callback:
                self.parse_callback(text_stripped)
        return len(text)

    def isatty(self):
        return False  # 关键：pytest会检查此方法

    def readable(self): return False
    def writable(self): return True
    def seekable(self): return False

    @property
    def encoding(self): return self._encoding

    @property
    def closed(self): return self._closed


def _run_pytest_in_process(self, report_dir: str):
    """在当前进程中直接运行pytest（打包模式）"""
    import pytest

    capture = RealtimeStdoutCapture(
        log_callback=lambda level, msg: self.log_signal.emit(level, msg),
        parse_callback=self._parse_output
    )

    with capture:
        pytest.main(self._build_pytest_args())
```

**关键点**：
- `RealtimeStdoutCapture` 必须实现 `isatty()` 方法，否则pytest会报错
- 使用上下文管理器临时替换 `sys.stdout` 和 `sys.stderr`
- 源码模式仍使用subprocess（避免潜在问题）

### 问题4：Playwright浏览器路径

**原因**：打包后Playwright需要在`_MEIPASS`中查找浏览器。

**解决方案**：在`main.py`开头设置环境变量：

```python
if getattr(sys, 'frozen', False):
    playwright_browsers_path = os.path.join(sys._MEIPASS, 'playwright')
    os.environ['PLAYWRIGHT_BROWSERS_PATH'] = playwright_browsers_path
    os.environ['PLAYWRIGHT_DRIVER_PATH'] = os.path.join(playwright_browsers_path, 'driver')
```

### 问题5：pytest.ini中的allure配置报错

**原因**：allure插件未打包，但pytest.ini中有相关配置。

**解决方案**：在命令行中覆盖配置：
```python
pytest_args.extend(['-p', 'no:allure', '-o', 'addopts='])
```

## 文件大小参考

| 组件 | 大小 |
|------|------|
| chromium-1208 | ~394MB |
| playwright driver | ~90MB |
| Python运行时 + 依赖 | ~50MB |
| 项目代码 | ~5MB |
| **最终EXE** | ~266MB（UPX压缩后） |

## 注意事项

1. **console必须为True**：否则pytest输出无法显示，且会导致I/O错误
2. **打包完整chromium**：不要用chromium_headless_shell，Playwright不识别
3. **手动定义fixtures**：pytest-playwright的fixtures需要在conftest.py中手动定义
4. **清理缓存**：重新打包前删除`build/`目录确保使用最新代码
5. **工作目录**：打包后工作目录是exe所在目录，不是项目根目录

## 常见错误排查

| 错误信息 | 原因 | 解决方案 |
|---------|------|---------|
| `fixture 'page' not found` | pytest-playwright未加载 | 手动定义fixtures |
| `Executable doesn't exist` | 浏览器路径错误 | 打包完整chromium |
| `I/O operation on closed file` | console=False | 设置console=True |
| `ModuleNotFoundError: No module named 'pages'` | _MEIPASS未加入sys.path | 在main.py开头添加 |
| GUI测试连接失败 | GUI未设置浏览器路径 | 在launch时指定executable_path |
| `'RealtimeStdoutCapture' object has no attribute 'isatty'` | 缺少isatty方法 | 添加isatty()方法返回False |

## GUI测试连接浏览器修复

GUI的"测试连接"功能也需要指定浏览器路径：

```python
# gui/main_window.py
launch_args = {"headless": True}
if getattr(sys, 'frozen', False):
    import os
    browser_path = os.path.join(sys._MEIPASS, 'playwright', 'chromium-1208', 'chrome-win64', 'chrome.exe')
    if os.path.exists(browser_path):
        launch_args["executable_path"] = browser_path

browser = p.chromium.launch(**launch_args)
```

## 实时日志显示（已解决）

打包模式下使用`RealtimeStdoutCapture`类直接捕获pytest输出，通过Qt信号实时发送到GUI：

```python
# 打包模式：直接在GUI线程中运行pytest
if is_frozen():
    self._run_pytest_in_process(report_dir)
else:
    self._run_pytest_subprocess(report_dir)
```

**技术原理**：通过替换`sys.stdout`和`sys.stderr`，每次pytest输出时立即通过Qt信号发送到GUI，完全绕过PyInstaller的stdout管道缓冲问题。

## 预期行为（非问题）

| 现象 | 原因 | 说明 |
|------|------|------|
| 启动慢（10-20秒） | 单文件模式解压 | PyInstaller需要将266MB解压到临时目录，首次启动较慢 |
| 日志实时显示 | 进程内pytest调用 | 已解决，操作和日志同步显示 |

---
版本: 1.1.0
更新日期: 2026-03-26
