"""
爱快路由器4.0自动化测试工具 - GUI入口

启动图形界面
"""
import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# PyInstaller打包后设置
if getattr(sys, 'frozen', False):
    # 添加_MEIPASS根目录到sys.path（用于导入pages, utils, config等模块）
    if sys._MEIPASS not in sys.path:
        sys.path.insert(0, sys._MEIPASS)
    # 设置Playwright浏览器路径
    playwright_browsers_path = os.path.join(sys._MEIPASS, 'playwright')
    os.environ['PLAYWRIGHT_BROWSERS_PATH'] = playwright_browsers_path
    # 设置Playwright driver路径
    os.environ['PLAYWRIGHT_DRIVER_PATH'] = os.path.join(playwright_browsers_path, 'driver')

from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow


def run_pytest_mode():
    """PyInstaller打包后的pytest运行模式

    当使用 --run-tests 参数启动时，直接运行pytest而不是启动GUI。
    这解决了打包后 sys.executable 指向exe导致 subprocess 调用会启动新GUI的问题。
    """
    import pytest

    # 修复PyInstaller打包后的I/O问题
    # 在某些情况下，sys.stdout/stderr可能被关闭或为None
    if sys.stdout is None or sys.stdout.closed:
        sys.stdout = open(os.devnull, 'w', encoding='utf-8')
    if sys.stderr is None or sys.stderr.closed:
        sys.stderr = open(os.devnull, 'w', encoding='utf-8')
    if sys.stdin is None or sys.stdin.closed:
        sys.stdin = open(os.devnull, 'r', encoding='utf-8')

    # 在打包环境中，测试文件在_MEIPASS目录中
    if getattr(sys, 'frozen', False):
        # 添加_MEIPASS根目录到sys.path（用于导入pages, utils, config等模块）
        if sys._MEIPASS not in sys.path:
            sys.path.insert(0, sys._MEIPASS)
        tests_dir = os.path.join(sys._MEIPASS, 'tests')
        # 添加测试目录到sys.path
        if tests_dir not in sys.path:
            sys.path.insert(0, tests_dir)

    # 移除 --run-tests 参数，保留其余参数传给pytest
    pytest_args = [arg for arg in sys.argv[1:] if arg != '--run-tests']

    # 如果没有指定测试路径，使用默认的tests目录
    has_test_path = any(not arg.startswith('-') for arg in pytest_args)
    if not has_test_path:
        if getattr(sys, 'frozen', False):
            pytest_args.append(os.path.join(sys._MEIPASS, 'tests'))
        else:
            pytest_args.append('tests')

    # 禁用pytest的capture功能，避免I/O问题
    pytest_args.extend(['--capture=no', '-p', 'no:allure', '-o', 'addopts='])

    # 运行pytest
    sys.exit(pytest.main(pytest_args))


def main():
    """主函数"""
    # 检查是否是pytest运行模式（打包后使用）
    if '--run-tests' in sys.argv:
        run_pytest_mode()
        return

    # 高DPI支持 (PySide6 默认启用，无需手动设置)

    app = QApplication(sys.argv)
    app.setApplicationName("爱快路由器4.0自动化测试工具")
    app.setApplicationVersion("1.0.0")

    # 设置样式
    app.setStyle("Fusion")

    # 加载样式表（如果存在）
    style_path = os.path.join(os.path.dirname(__file__), "gui", "gui_resources", "styles.qss")
    if os.path.exists(style_path):
        with open(style_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())

    # 创建并显示主窗口
    window = MainWindow()
    window.show()

    # 运行应用
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
