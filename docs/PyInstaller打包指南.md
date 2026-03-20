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

### 问题3：点击"开始测试"打开新GUI窗口

**原因**：`sys.executable`在打包后指向exe本身，`subprocess`调用会启动新GUI。

**解决方案**：在`main.py`中添加`--run-tests`入口点：

```python
def run_pytest_mode():
    """PyInstaller打包后的pytest运行模式"""
    import pytest

    # 修复I/O问题
    if sys.stdout is None or sys.stdout.closed:
        sys.stdout = open(os.devnull, 'w', encoding='utf-8')

    # 设置测试目录
    if getattr(sys, 'frozen', False):
        sys.path.insert(0, sys._MEIPASS)
        pytest_args.append(os.path.join(sys._MEIPASS, 'tests'))

    pytest_args.extend(['--capture=no', '-p', 'no:allure', '-o', 'addopts='])
    sys.exit(pytest.main(pytest_args))

def main():
    if '--run-tests' in sys.argv:
        run_pytest_mode()
        return
    # ... 正常GUI启动
```

在`gui/test_runner.py`中使用：
```python
if is_frozen():
    cmd = [sys.executable, "--run-tests", "-v", "-s", "--tb=short", ...]
else:
    cmd = [sys.executable, "-m", "pytest", "-v", "-s", ...]
```

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
| 打开新GUI窗口 | subprocess调用exe | 使用--run-tests入口点 |
| GUI测试连接失败 | GUI未设置浏览器路径 | 在launch时指定executable_path |

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

## 实时日志显示

subprocess需要设置`bufsize=1`（行缓冲）才能实时显示输出：

```python
process = subprocess.Popen(
    pytest_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,  # 行缓冲，实现实时输出
    env=env,
)
```

**注意**: 即使设置了`bufsize=1`和`PYTHONUNBUFFERED=1`，打包后日志仍可能批量显示而非逐行实时显示。这可能是pytest内部缓冲或Windows管道特性导致，待进一步调查。

## 预期行为（非问题）

| 现象 | 原因 | 说明 |
|------|------|------|
| 启动慢（10-20秒） | 单文件模式解压 | PyInstaller需要将266MB解压到临时目录，首次启动较慢 |
| 日志批量显示 | pytest设计特性 | pytest运行时收集输出，测试结束后统一显示 |

如果需要更快的启动速度，可以使用文件夹模式（onedir），但需要分发整个文件夹。

---
版本: 1.0.0
更新日期: 2026-03-20
