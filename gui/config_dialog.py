"""
配置对话框

设备、浏览器、报告、定时任务等配置界面
"""
import os
import sys
from datetime import datetime

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QSpinBox, QComboBox, QCheckBox,
    QPushButton, QGroupBox, QFileDialog, QTabWidget,
    QWidget, QListWidget, QListWidgetItem, QMessageBox,
    QLabel, QTimeEdit
)
from PySide6.QtCore import Qt, QTime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.config import Config, DeviceConfig, BrowserConfig, ReportConfig, SSHConfig, SSHHostConfig


class ConfigDialog(QDialog):
    """配置对话框"""

    def __init__(self, parent=None, config: Config = None, current_tab: str = "device"):
        super().__init__(parent)
        self.config = config or Config()
        self.current_tab = current_tab

        self.setWindowTitle("设置")
        self.setMinimumSize(600, 500)

        self._init_ui()
        self._load_config()

    def _init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout(self)

        # 标签页
        self.tab_widget = QTabWidget()

        # 设备配置标签页
        device_tab = self._create_device_tab()
        self.tab_widget.addTab(device_tab, "设备配置")

        # 浏览器配置标签页
        browser_tab = self._create_browser_tab()
        self.tab_widget.addTab(browser_tab, "浏览器设置")

        # 报告配置标签页
        report_tab = self._create_report_tab()
        self.tab_widget.addTab(report_tab, "报告设置")

        # SSH配置标签页
        ssh_tab = self._create_ssh_tab()
        self.tab_widget.addTab(ssh_tab, "SSH配置")

        # 定时任务标签页
        schedule_tab = self._create_schedule_tab()
        self.tab_widget.addTab(schedule_tab, "定时任务")

        layout.addWidget(self.tab_widget)

        # 设置当前标签页
        tab_index = {"device": 0, "browser": 1, "report": 2, "ssh": 3, "schedule": 4}
        self.tab_widget.setCurrentIndex(tab_index.get(self.current_tab, 0))

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self._save_and_accept)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def _create_device_tab(self) -> QWidget:
        """创建设备配置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 设备信息
        device_group = QGroupBox("设备信息")
        form_layout = QFormLayout(device_group)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("如: 10.66.0.150")
        form_layout.addRow("IP地址:", self.ip_input)

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(80)
        form_layout.addRow("端口:", self.port_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("默认: admin")
        form_layout.addRow("用户名:", self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("密码:", self.password_input)

        layout.addWidget(device_group)

        # 超时设置
        timeout_group = QGroupBox("超时设置")
        form_layout = QFormLayout(timeout_group)

        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1000, 120000)
        self.timeout_input.setValue(30000)
        self.timeout_input.setSuffix(" ms")
        form_layout.addRow("默认超时:", self.timeout_input)

        layout.addWidget(timeout_group)
        layout.addStretch()

        return widget

    def _create_browser_tab(self) -> QWidget:
        """创建浏览器配置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 浏览器设置
        browser_group = QGroupBox("浏览器设置")
        form_layout = QFormLayout(browser_group)

        self.browser_combo = QComboBox()
        self.browser_combo.addItems(["chromium", "firefox", "webkit"])
        form_layout.addRow("浏览器:", self.browser_combo)

        self.headless_check = QCheckBox("无头模式（后台运行，不显示浏览器窗口）")
        form_layout.addRow("", self.headless_check)

        self.slow_mo_input = QSpinBox()
        self.slow_mo_input.setRange(0, 5000)
        self.slow_mo_input.setValue(0)
        self.slow_mo_input.setSuffix(" ms")
        form_layout.addRow("操作延迟:", self.slow_mo_input)

        self.browser_timeout_input = QSpinBox()
        self.browser_timeout_input.setRange(1000, 120000)
        self.browser_timeout_input.setValue(30000)
        self.browser_timeout_input.setSuffix(" ms")
        form_layout.addRow("超时时间:", self.browser_timeout_input)

        layout.addWidget(browser_group)

        # 截图和视频
        capture_group = QGroupBox("截图和视频")
        form_layout = QFormLayout(capture_group)

        self.screenshot_check = QCheckBox("失败时自动截图")
        self.screenshot_check.setChecked(True)
        form_layout.addRow("", self.screenshot_check)

        self.video_check = QCheckBox("失败时录制视频")
        form_layout.addRow("", self.video_check)

        layout.addWidget(capture_group)
        layout.addStretch()

        return widget

    def _create_report_tab(self) -> QWidget:
        """创建报告配置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 报告路径
        path_group = QGroupBox("报告路径")
        form_layout = QFormLayout(path_group)

        # 输出目录
        output_layout = QHBoxLayout()
        self.output_dir_input = QLineEdit()
        output_layout.addWidget(self.output_dir_input)
        output_btn = QPushButton("浏览...")
        output_btn.clicked.connect(self._browse_output_dir)
        output_layout.addWidget(output_btn)
        form_layout.addRow("输出目录:", output_layout)

        # 截图目录
        screenshot_layout = QHBoxLayout()
        self.screenshot_dir_input = QLineEdit()
        screenshot_layout.addWidget(self.screenshot_dir_input)
        screenshot_btn = QPushButton("浏览...")
        screenshot_btn.clicked.connect(self._browse_screenshot_dir)
        screenshot_layout.addWidget(screenshot_btn)
        form_layout.addRow("截图目录:", screenshot_layout)

        # 报告前缀
        self.report_prefix_input = QLineEdit()
        self.report_prefix_input.setPlaceholderText("如: test_report")
        form_layout.addRow("报告前缀:", self.report_prefix_input)

        layout.addWidget(path_group)
        layout.addStretch()

        return widget

    def _create_ssh_tab(self) -> QWidget:
        """创建SSH配置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 路由器SSH配置
        router_group = QGroupBox("路由器SSH")
        form_layout = QFormLayout(router_group)

        self.ssh_router_host = QLineEdit()
        self.ssh_router_host.setPlaceholderText("如: 10.66.0.150")
        form_layout.addRow("主机地址:", self.ssh_router_host)

        self.ssh_router_username = QLineEdit()
        self.ssh_router_username.setPlaceholderText("如: sshd")
        form_layout.addRow("用户名:", self.ssh_router_username)

        self.ssh_router_password = QLineEdit()
        self.ssh_router_password.setEchoMode(QLineEdit.Password)
        form_layout.addRow("密码:", self.ssh_router_password)

        self.ssh_router_port = QSpinBox()
        self.ssh_router_port.setRange(1, 65535)
        self.ssh_router_port.setValue(22)
        form_layout.addRow("端口:", self.ssh_router_port)

        # 控制台登录凭据（当控制台密码开启时使用）
        self.ssh_router_console_username = QLineEdit()
        self.ssh_router_console_username.setPlaceholderText("控制台登录账号（如: whoami）")
        self.ssh_router_console_username.setText("whoami")  # 默认值
        form_layout.addRow("控制台账号:", self.ssh_router_console_username)

        self.ssh_router_console_password = QLineEdit()
        self.ssh_router_console_password.setEchoMode(QLineEdit.Password)
        self.ssh_router_console_password.setPlaceholderText("控制台登录密码")
        self.ssh_router_console_password.setText("haohao!!xuexi@@tiantian##xiangshang")  # 默认值
        form_layout.addRow("控制台密码:", self.ssh_router_console_password)

        layout.addWidget(router_group)

        # 测试客户端SSH配置
        client_group = QGroupBox("测试客户端SSH")
        form_layout = QFormLayout(client_group)

        self.ssh_client_host = QLineEdit()
        self.ssh_client_host.setPlaceholderText("如: 10.66.0.18")
        form_layout.addRow("主机地址:", self.ssh_client_host)

        self.ssh_client_username = QLineEdit()
        self.ssh_client_username.setPlaceholderText("如: iktest")
        form_layout.addRow("用户名:", self.ssh_client_username)

        self.ssh_client_password = QLineEdit()
        self.ssh_client_password.setEchoMode(QLineEdit.Password)
        form_layout.addRow("密码:", self.ssh_client_password)

        self.ssh_client_port = QSpinBox()
        self.ssh_client_port.setRange(1, 65535)
        self.ssh_client_port.setValue(22)
        form_layout.addRow("端口:", self.ssh_client_port)

        layout.addWidget(client_group)

        # iperf3配置
        iperf_group = QGroupBox("iperf3测速配置")
        form_layout = QFormLayout(iperf_group)

        self.iperf3_server = QLineEdit()
        self.iperf3_server.setPlaceholderText("如: 10.66.0.40")
        form_layout.addRow("iperf3服务端:", self.iperf3_server)

        self.iperf3_duration = QSpinBox()
        self.iperf3_duration.setRange(1, 300)
        self.iperf3_duration.setValue(10)
        self.iperf3_duration.setSuffix(" 秒")
        form_layout.addRow("测速时长:", self.iperf3_duration)

        self.iperf3_tolerance = QSpinBox()
        self.iperf3_tolerance.setRange(1, 100)
        self.iperf3_tolerance.setValue(20)
        self.iperf3_tolerance.setSuffix(" %")
        form_layout.addRow("允许误差:", self.iperf3_tolerance)

        layout.addWidget(iperf_group)
        layout.addStretch()

        return widget

    def _create_schedule_tab(self) -> QWidget:
        """创建定时任务配置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 启用定时任务
        self.enable_schedule_check = QCheckBox("启用定时执行")
        layout.addWidget(self.enable_schedule_check)

        # 执行频率
        freq_group = QGroupBox("执行频率")
        form_layout = QFormLayout(freq_group)

        self.freq_combo = QComboBox()
        self.freq_combo.addItems(["每天", "每周", "每小时", "自定义Cron"])
        self.freq_combo.currentTextChanged.connect(self._on_freq_changed)
        form_layout.addRow("频率:", self.freq_combo)

        # 时间设置
        self.time_edit = QTimeEdit()
        self.time_edit.setTime(QTime(2, 0))
        form_layout.addRow("执行时间:", self.time_edit)

        # 星期选择
        self.weekday_combo = QComboBox()
        self.weekday_combo.addItems(["周一", "周二", "周三", "周四", "周五", "周六", "周日"])
        form_layout.addRow("星期:", self.weekday_combo)

        # Cron表达式
        self.cron_input = QLineEdit("0 2 * * *")
        self.cron_input.setPlaceholderText("Cron表达式，如: 0 2 * * *")
        form_layout.addRow("Cron表达式:", self.cron_input)

        layout.addWidget(freq_group)

        # 定时任务列表
        list_group = QGroupBox("已配置的定时任务")
        list_layout = QVBoxLayout(list_group)

        self.schedule_list = QListWidget()
        list_layout.addWidget(self.schedule_list)

        btn_layout = QHBoxLayout()
        add_btn = QPushButton("添加")
        add_btn.clicked.connect(self._add_schedule)
        edit_btn = QPushButton("编辑")
        del_btn = QPushButton("删除")
        del_btn.clicked.connect(self._delete_schedule)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(edit_btn)
        btn_layout.addWidget(del_btn)
        list_layout.addLayout(btn_layout)

        layout.addWidget(list_group)

        # 初始化状态
        self._on_freq_changed("每天")

        return widget

    def _load_config(self):
        """加载配置到界面"""
        # 设备配置
        self.ip_input.setText(self.config.device.ip)
        self.port_input.setValue(self.config.device.port)
        self.username_input.setText(self.config.device.username)
        self.password_input.setText(self.config.device.password)
        self.timeout_input.setValue(self.config.device.timeout)

        # 浏览器配置
        index = self.browser_combo.findText(self.config.browser.browser_type)
        if index >= 0:
            self.browser_combo.setCurrentIndex(index)
        self.headless_check.setChecked(self.config.browser.headless)
        self.slow_mo_input.setValue(self.config.browser.slow_mo)
        self.browser_timeout_input.setValue(self.config.browser.timeout)
        self.screenshot_check.setChecked(self.config.browser.screenshot_on_failure)
        self.video_check.setChecked(self.config.browser.video_on_failure)

        # 报告配置
        self.output_dir_input.setText(self.config.report.output_dir)
        self.screenshot_dir_input.setText(self.config.report.screenshot_dir)
        self.report_prefix_input.setText(self.config.report.report_name_prefix)

        # SSH配置
        self.ssh_router_host.setText(self.config.ssh.router.host)
        self.ssh_router_username.setText(self.config.ssh.router.username)
        self.ssh_router_password.setText(self.config.ssh.router.password)
        self.ssh_router_port.setValue(self.config.ssh.router.port)
        self.ssh_router_console_username.setText(getattr(self.config.ssh.router, 'console_username', ''))
        self.ssh_router_console_password.setText(getattr(self.config.ssh.router, 'console_password', ''))

        self.ssh_client_host.setText(self.config.ssh.client.host)
        self.ssh_client_username.setText(self.config.ssh.client.username)
        self.ssh_client_password.setText(self.config.ssh.client.password)
        self.ssh_client_port.setValue(self.config.ssh.client.port)

        self.iperf3_server.setText(self.config.ssh.iperf3_server)
        self.iperf3_duration.setValue(self.config.ssh.iperf3_duration)
        self.iperf3_tolerance.setValue(int(self.config.ssh.iperf3_tolerance * 100))

    def _save_and_accept(self):
        """保存配置并接受"""
        # 设备配置
        self.config.device.ip = self.ip_input.text()
        self.config.device.port = self.port_input.value()
        self.config.device.username = self.username_input.text()
        self.config.device.password = self.password_input.text()
        self.config.device.timeout = self.timeout_input.value()

        # 浏览器配置
        self.config.browser.browser_type = self.browser_combo.currentText()
        self.config.browser.headless = self.headless_check.isChecked()
        self.config.browser.slow_mo = self.slow_mo_input.value()
        self.config.browser.timeout = self.browser_timeout_input.value()
        self.config.browser.screenshot_on_failure = self.screenshot_check.isChecked()
        self.config.browser.video_on_failure = self.video_check.isChecked()

        # 报告配置
        self.config.report.output_dir = self.output_dir_input.text()
        self.config.report.screenshot_dir = self.screenshot_dir_input.text()
        self.config.report.report_name_prefix = self.report_prefix_input.text()

        # SSH配置
        self.config.ssh.router.host = self.ssh_router_host.text()
        self.config.ssh.router.username = self.ssh_router_username.text()
        self.config.ssh.router.password = self.ssh_router_password.text()
        self.config.ssh.router.port = self.ssh_router_port.value()
        self.config.ssh.router.console_username = self.ssh_router_console_username.text()
        self.config.ssh.router.console_password = self.ssh_router_console_password.text()

        self.config.ssh.client.host = self.ssh_client_host.text()
        self.config.ssh.client.username = self.ssh_client_username.text()
        self.config.ssh.client.password = self.ssh_client_password.text()
        self.config.ssh.client.port = self.ssh_client_port.value()

        self.config.ssh.iperf3_server = self.iperf3_server.text()
        self.config.ssh.iperf3_duration = self.iperf3_duration.value()
        self.config.ssh.iperf3_tolerance = self.iperf3_tolerance.value() / 100.0

        self.accept()

    def get_config(self) -> Config:
        """获取配置"""
        return self.config

    def _browse_output_dir(self):
        """浏览输出目录"""
        dir_path = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if dir_path:
            self.output_dir_input.setText(dir_path)

    def _browse_screenshot_dir(self):
        """浏览截图目录"""
        dir_path = QFileDialog.getExistingDirectory(self, "选择截图目录")
        if dir_path:
            self.screenshot_dir_input.setText(dir_path)

    def _on_freq_changed(self, freq):
        """频率变化"""
        # 根据频率显示/隐藏相关控件
        show_time = freq in ["每天", "每周"]
        show_weekday = freq == "每周"
        show_cron = freq == "自定义Cron"

        self.time_edit.setVisible(show_time)
        self.weekday_combo.setVisible(show_weekday)
        self.cron_input.setVisible(show_cron)

    def _add_schedule(self):
        """添加定时任务"""
        # TODO: 实现添加定时任务
        QMessageBox.information(self, "提示", "添加定时任务功能开发中...")

    def _delete_schedule(self):
        """删除定时任务"""
        current = self.schedule_list.currentItem()
        if current:
            self.schedule_list.takeItem(self.schedule_list.row(current))
