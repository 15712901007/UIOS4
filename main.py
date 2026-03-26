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
