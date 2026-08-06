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


def _dispatch_packaged_basic_setting_smoke() -> None:
    """Run the frozen basic-setting collect entry before GUI initialization."""
    if not getattr(sys, "frozen", False):
        return
    if "--collect-basic-setting-smoke" not in sys.argv:
        return

    from gui.test_runner import run_packaged_basic_setting_collect_smoke

    raise SystemExit(run_packaged_basic_setting_collect_smoke())


_dispatch_packaged_basic_setting_smoke()


def _dispatch_packaged_alg_setting_smoke() -> None:
    """Run the frozen ALG-setting collect entry before GUI initialization."""
    if not getattr(sys, "frozen", False):
        return
    if "--collect-alg-setting-smoke" not in sys.argv:
        return

    from gui.test_runner import run_packaged_alg_setting_collect_smoke

    raise SystemExit(run_packaged_alg_setting_collect_smoke())


_dispatch_packaged_alg_setting_smoke()


def _dispatch_packaged_protocol_control_smoke() -> None:
    """Run the frozen protocol-control collect entry before GUI initialization."""
    if not getattr(sys, "frozen", False):
        return
    if "--collect-protocol-control-smoke" not in sys.argv:
        return

    from gui.test_runner import run_packaged_protocol_control_collect_smoke

    raise SystemExit(run_packaged_protocol_control_collect_smoke())


_dispatch_packaged_protocol_control_smoke()


def _dispatch_packaged_kernel_setting_smoke() -> None:
    """Run the frozen kernel-setting collect entry before GUI initialization."""
    if not getattr(sys, "frozen", False):
        return
    if "--collect-kernel-setting-smoke" not in sys.argv:
        return

    from gui.test_runner import run_packaged_kernel_setting_collect_smoke

    raise SystemExit(run_packaged_kernel_setting_collect_smoke())


_dispatch_packaged_kernel_setting_smoke()


def _dispatch_packaged_account_setting_smoke() -> None:
    """Run the frozen account-setting collect entry before GUI initialization."""
    if not getattr(sys, "frozen", False):
        return
    if "--collect-account-setting-smoke" not in sys.argv:
        return

    from gui.test_runner import run_packaged_account_setting_collect_smoke

    raise SystemExit(run_packaged_account_setting_collect_smoke())


_dispatch_packaged_account_setting_smoke()


def _dispatch_packaged_ospf_smoke() -> None:
    """Run the frozen OSPF collect entry before GUI initialization."""
    if not getattr(sys, "frozen", False):
        return
    if "--collect-ospf-smoke" not in sys.argv:
        return
    from gui.test_runner import run_packaged_ospf_collect_smoke
    raise SystemExit(run_packaged_ospf_collect_smoke())


_dispatch_packaged_ospf_smoke()


def _dispatch_packaged_ipsec_smoke() -> None:
    """Run the frozen IPsec VPN collect entry before GUI initialization."""
    if not getattr(sys, "frozen", False):
        return
    if "--collect-ipsec-smoke" not in sys.argv:
        return
    from gui.test_runner import run_packaged_ipsec_collect_smoke
    raise SystemExit(run_packaged_ipsec_collect_smoke())


_dispatch_packaged_ipsec_smoke()

from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow


def main():
    """主函数"""
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
