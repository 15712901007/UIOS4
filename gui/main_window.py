"""
GUI主窗口

爱快路由器4.0自动化测试工具主界面
"""
import sys
import os
from datetime import datetime

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLineEdit, QPushButton, QLabel, QTreeWidget,
    QTreeWidgetItem, QListWidget, QListWidgetItem, QTextEdit, QProgressBar,
    QStatusBar, QMenuBar, QToolBar, QMessageBox, QSplitter,
    QCheckBox, QComboBox, QFrame, QScrollArea, QApplication,
    QDialog
)
from PySide6.QtCore import Qt, QThread, Signal, QSize, QTimer
from PySide6.QtGui import QAction, QIcon, QFont, QColor, QPalette

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.config import get_config, Config
from gui.test_runner import TestRunner
from gui.config_dialog import ConfigDialog


class MainWindow(QMainWindow):
    """主窗口类"""

    # 信号定义
    test_started = Signal()
    test_finished = Signal(bool)

    def __init__(self):
        super().__init__()

        # 初始化配置
        self.config = get_config()

        # 测试运行器
        self.test_runner = None

        # 测试用例数据
        self.test_modules = self._load_test_modules()

        # 计时器
        self.test_start_time = None
        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.timeout.connect(self._update_elapsed_time)

        # 初始化UI
        self._init_ui()
        self._init_connections()

        # 加载配置到界面
        self._load_config_to_ui()

    def _init_ui(self):
        """初始化UI"""
        self.setWindowTitle("爱快路由器4.0自动化测试工具")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1200, 800)

        # 设置窗口图标（如果有）
        # self.setWindowIcon(QIcon("gui/resources/icon.png"))

        # 初始化菜单栏
        self._init_menubar()

        # 初始化工具栏
        self._init_toolbar()

        # 初始化中心部件
        self._init_central_widget()

        # 初始化状态栏
        self._init_statusbar()

    def _init_menubar(self):
        """初始化菜单栏"""
        menubar = self.menuBar()

        # 文件菜单
        file_menu = menubar.addMenu("文件(&F)")

        open_config_action = QAction("打开配置", self)
        open_config_action.setShortcut("Ctrl+O")
        open_config_action.triggered.connect(self._open_config)
        file_menu.addAction(open_config_action)

        save_config_action = QAction("保存配置", self)
        save_config_action.setShortcut("Ctrl+S")
        save_config_action.triggered.connect(self._save_config)
        file_menu.addAction(save_config_action)

        file_menu.addSeparator()

        exit_action = QAction("退出", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # 设置菜单
        settings_menu = menubar.addMenu("设置(&S)")

        device_config_action = QAction("设备配置", self)
        device_config_action.triggered.connect(self._show_config_dialog)
        settings_menu.addAction(device_config_action)

        report_config_action = QAction("报告设置", self)
        report_config_action.triggered.connect(lambda: self._show_config_dialog("report"))
        settings_menu.addAction(report_config_action)

        schedule_config_action = QAction("定时任务", self)
        schedule_config_action.triggered.connect(lambda: self._show_config_dialog("schedule"))
        settings_menu.addAction(schedule_config_action)

        # 帮助菜单
        help_menu = menubar.addMenu("帮助(&H)")

        usage_action = QAction("使用说明", self)
        usage_action.setShortcut("F1")
        usage_action.triggered.connect(self._show_help)
        help_menu.addAction(usage_action)

        about_action = QAction("关于", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _init_toolbar(self):
        """初始化工具栏"""
        toolbar = QToolBar("主工具栏")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        # 连接设备按钮
        self.connect_action = QAction("连接设备", self)
        self.connect_action.triggered.connect(self._test_connection)
        toolbar.addAction(self.connect_action)

        toolbar.addSeparator()

        # 开始测试按钮
        self.start_action = QAction("开始测试", self)
        self.start_action.triggered.connect(self._start_tests)
        toolbar.addAction(self.start_action)

        # 停止测试按钮
        self.stop_action = QAction("停止", self)
        self.stop_action.setEnabled(False)
        self.stop_action.triggered.connect(self._stop_tests)
        toolbar.addAction(self.stop_action)

        toolbar.addSeparator()

        # 查看报告按钮
        report_action = QAction("查看报告", self)
        report_action.triggered.connect(lambda: self._open_report(None))
        toolbar.addAction(report_action)

        # 设置按钮
        settings_action = QAction("设置", self)
        settings_action.triggered.connect(self._show_config_dialog)
        toolbar.addAction(settings_action)

    def _init_central_widget(self):
        """初始化中心部件"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # 使用分割器分割左右面板
        splitter = QSplitter(Qt.Horizontal)

        # 左侧面板
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)

        # 右侧面板
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)

        # 设置分割比例
        splitter.setSizes([450, 850])

        main_layout.addWidget(splitter)

    def _create_left_panel(self) -> QWidget:
        """创建左侧面板"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(10)

        # 设备配置区
        device_group = self._create_device_group()
        layout.addWidget(device_group)

        # 测试模块区
        module_group = self._create_module_group()
        layout.addWidget(module_group, 1)  # 可扩展

        # 测试用例区
        testcase_group = self._create_testcase_group()
        layout.addWidget(testcase_group, 1)  # 可扩展

        return panel

    def _create_device_group(self) -> QGroupBox:
        """创建设备配置区"""
        group = QGroupBox("设备配置")
        layout = QVBoxLayout(group)

        # IP地址
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP地址:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("如: 10.66.0.150")
        ip_layout.addWidget(self.ip_input)
        layout.addLayout(ip_layout)

        # 用户名
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("用户名:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("默认: admin")
        user_layout.addWidget(self.username_input)
        layout.addLayout(user_layout)

        # 密码
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("密  码:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("输入密码")
        pwd_layout.addWidget(self.password_input)
        layout.addLayout(pwd_layout)

        # 测试人员
        tester_layout = QHBoxLayout()
        tester_layout.addWidget(QLabel("测试人员:"))
        self.tester_input = QLineEdit()
        self.tester_input.setPlaceholderText("输入测试人员姓名")
        tester_layout.addWidget(self.tester_input)
        layout.addLayout(tester_layout)

        # 测试版本
        version_layout = QHBoxLayout()
        version_layout.addWidget(QLabel("测试版本:"))
        self.version_input = QLineEdit()
        self.version_input.setPlaceholderText("如: v4.0.1")
        version_layout.addWidget(self.version_input)
        layout.addLayout(version_layout)

        # 浏览器分辨率
        resolution_layout = QHBoxLayout()
        resolution_layout.addWidget(QLabel("浏览器分辨率:"))
        self.width_input = QLineEdit()
        self.width_input.setPlaceholderText("宽度")
        self.width_input.setMaximumWidth(80)
        resolution_layout.addWidget(self.width_input)
        resolution_layout.addWidget(QLabel("×"))
        self.height_input = QLineEdit()
        self.height_input.setPlaceholderText("高度")
        self.height_input.setMaximumWidth(80)
        resolution_layout.addWidget(self.height_input)
        resolution_layout.addStretch()
        layout.addLayout(resolution_layout)

        # 自适应屏幕模式
        auto_adapt_layout = QHBoxLayout()
        self.auto_adapt_checkbox = QCheckBox("自适应屏幕（推荐）")
        self.auto_adapt_checkbox.setToolTip("启用后浏览器会像原生浏览器一样自动适应屏幕大小和DPI缩放\n关闭后使用固定分辨率设置")
        self.auto_adapt_checkbox.stateChanged.connect(self._on_auto_adapt_changed)
        auto_adapt_layout.addWidget(self.auto_adapt_checkbox)
        auto_adapt_layout.addStretch()
        layout.addLayout(auto_adapt_layout)

        # 连接按钮和状态
        btn_layout = QHBoxLayout()
        self.connect_btn = QPushButton("连接测试")
        self.connect_btn.clicked.connect(self._test_connection)
        btn_layout.addWidget(self.connect_btn)

        self.connection_status = QLabel("● 未连接")
        self.connection_status.setStyleSheet("color: gray;")
        btn_layout.addWidget(self.connection_status)
        btn_layout.addStretch()

        layout.addLayout(btn_layout)

        return group

    def _create_module_group(self) -> QGroupBox:
        """创建测试模块区"""
        group = QGroupBox("测试模块")
        layout = QVBoxLayout(group)

        # 全选复选框
        select_layout = QHBoxLayout()
        self.select_all_modules = QCheckBox("全选")
        self.select_all_modules.stateChanged.connect(self._toggle_all_modules)
        select_layout.addWidget(self.select_all_modules)
        select_layout.addStretch()
        layout.addLayout(select_layout)

        # 模块树
        self.module_tree = QTreeWidget()
        self.module_tree.setHeaderHidden(True)
        self.module_tree.itemChanged.connect(self._on_module_changed)

        # 加载测试模块
        self._populate_module_tree()

        layout.addWidget(self.module_tree)

        return group

    def _create_testcase_group(self) -> QGroupBox:
        """创建测试用例区"""
        group = QGroupBox("测试用例")
        layout = QVBoxLayout(group)

        # 全选复选框
        select_layout = QHBoxLayout()
        self.select_all_testcases = QCheckBox("全选")
        self.select_all_testcases.stateChanged.connect(self._toggle_all_testcases)
        select_layout.addWidget(self.select_all_testcases)

        # 用例数量标签
        self.testcase_count_label = QLabel("已选: 0")
        select_layout.addWidget(self.testcase_count_label)
        select_layout.addStretch()
        layout.addLayout(select_layout)

        # 用例列表
        self.testcase_list = QListWidget()
        self.testcase_list.setSelectionMode(QListWidget.MultiSelection)
        self.testcase_list.itemChanged.connect(self._update_testcase_count)
        layout.addWidget(self.testcase_list)

        return group

    def _create_right_panel(self) -> QWidget:
        """创建右侧面板"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(10)

        # 上部：进度和统计
        progress_group = self._create_progress_group()
        layout.addWidget(progress_group)

        # 下部：日志
        log_group = self._create_log_group()
        layout.addWidget(log_group, 1)  # 可扩展

        return panel

    def _create_progress_group(self) -> QGroupBox:
        """创建进度区域"""
        group = QGroupBox("测试进度")
        layout = QVBoxLayout(group)

        # 统计信息行
        stats_layout = QHBoxLayout()

        # 总计
        total_layout = QVBoxLayout()
        self.total_label = QLabel("0")
        self.total_label.setAlignment(Qt.AlignCenter)
        self.total_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        total_title = QLabel("总计")
        total_title.setAlignment(Qt.AlignCenter)
        total_layout.addWidget(self.total_label)
        total_layout.addWidget(total_title)
        stats_layout.addLayout(total_layout)

        # 通过
        passed_layout = QVBoxLayout()
        self.passed_label = QLabel("0")
        self.passed_label.setAlignment(Qt.AlignCenter)
        self.passed_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #52c41a;")
        passed_title = QLabel("通过")
        passed_title.setAlignment(Qt.AlignCenter)
        passed_layout.addWidget(self.passed_label)
        passed_layout.addWidget(passed_title)
        stats_layout.addLayout(passed_layout)

        # 失败
        failed_layout = QVBoxLayout()
        self.failed_label = QLabel("0")
        self.failed_label.setAlignment(Qt.AlignCenter)
        self.failed_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #ff4d4f;")
        failed_title = QLabel("失败")
        failed_title.setAlignment(Qt.AlignCenter)
        failed_layout.addWidget(self.failed_label)
        failed_layout.addWidget(failed_title)
        stats_layout.addLayout(failed_layout)

        # 跳过
        skipped_layout = QVBoxLayout()
        self.skipped_label = QLabel("0")
        self.skipped_label.setAlignment(Qt.AlignCenter)
        self.skipped_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #faad14;")
        skipped_title = QLabel("跳过")
        skipped_title.setAlignment(Qt.AlignCenter)
        skipped_layout.addWidget(self.skipped_label)
        skipped_layout.addWidget(skipped_title)
        stats_layout.addLayout(skipped_layout)

        stats_layout.addStretch()
        layout.addLayout(stats_layout)

        # 进度条
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% (%v/%m)")
        progress_layout.addWidget(self.progress_bar)

        # 用时标签
        self.time_label = QLabel("用时: 00:00:00")
        progress_layout.addWidget(self.time_label)

        layout.addLayout(progress_layout)

        return group

    def _create_log_group(self) -> QGroupBox:
        """创建日志区域"""
        group = QGroupBox("执行日志")
        layout = QVBoxLayout(group)

        # 日志级别过滤
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("日志级别:"))

        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["全部", "INFO", "WARNING", "ERROR"])
        self.log_level_combo.currentTextChanged.connect(self._filter_logs)
        filter_layout.addWidget(self.log_level_combo)

        # 清空日志按钮
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self._clear_logs)
        filter_layout.addWidget(clear_btn)

        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # 日志文本框
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: Consolas, Monaco, monospace;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.log_text)

        return group

    def _init_statusbar(self):
        """初始化状态栏"""
        self.statusbar = self.statusBar()

        self.status_label = QLabel("就绪")
        self.statusbar.addWidget(self.status_label)

        self.statusbar.addPermanentWidget(QLabel(f"设备: {self.config.device.ip}"))

        self.memory_label = QLabel("内存: -- MB")
        self.statusbar.addPermanentWidget(self.memory_label)

    def _init_connections(self):
        """初始化信号连接"""
        # 模块树选择变化时更新用例列表
        self.module_tree.itemClicked.connect(self._update_testcase_list)

    def _load_test_modules(self) -> dict:
        """加载测试模块数据

        测试用例格式: "文件名::类名::方法名" 或 "文件名::方法名" (无类)
        """
        return {
            "网络配置": {
                "children": {
                    "VLAN设置": {
                        "testcases": [
                            # 综合测试（推荐）- 一次测试覆盖所有功能，效率最高
                            # 包含：添加8条、编辑、停用、启用、删除、搜索、导出CSV/TXT、
                            # 异常测试(MAC/IP/名称/ID/扩展IP/ID冲突)、批量停用/启用/删除、导入CSV/TXT、清理
                            "test_vlan_comprehensive.py::TestVlanComprehensive::test_comprehensive_flow",
                        ],
                        # 分组信息（用于UI显示）
                        "groups": {
                            "综合测试（推荐）": [
                                "test_vlan_comprehensive.py::TestVlanComprehensive::test_comprehensive_flow",
                            ],
                        }
                    },
                    "终端限速": {
                        "children": {
                            "IP限速": {
                                "testcases": [
                                    # IP限速综合测试
                                    "test_ip_rate_limit_comprehensive.py::TestIpRateLimitComprehensive::test_ip_rate_limit_comprehensive",
                                ],
                                "groups": {
                                    "综合测试（推荐）": [
                                        "test_ip_rate_limit_comprehensive.py::TestIpRateLimitComprehensive::test_ip_rate_limit_comprehensive",
                                    ],
                                }
                            },
                            "MAC限速": {
                                "testcases": [
                                    # MAC限速综合测试
                                    "test_mac_rate_limit_comprehensive.py::TestMacRateLimitComprehensive::test_mac_rate_limit_comprehensive",
                                ],
                                "groups": {
                                    "综合测试（推荐）": [
                                        "test_mac_rate_limit_comprehensive.py::TestMacRateLimitComprehensive::test_mac_rate_limit_comprehensive",
                                    ],
                                }
                            },
                        }
                    },
                    "内外网设置": {
                        "testcases": []
                    },
                    "智能流控": {
                        "testcases": []
                    },
                }
            },
            "监控中心": {
                "children": {
                    "线路监控": {
                        "testcases": []
                    },
                }
            },
            "安全中心": {
                "children": {
                    "ACL规则": {
                        "testcases": []
                    },
                }
            },
        }

    def _populate_module_tree(self):
        """填充模块树"""
        self.module_tree.clear()
        self.module_tree.blockSignals(True)

        for module_name, module_data in self.test_modules.items():
            parent_item = QTreeWidgetItem(self.module_tree, [module_name])
            parent_item.setFlags(parent_item.flags() | Qt.ItemIsUserCheckable)
            parent_item.setCheckState(0, Qt.Unchecked)

            if "children" in module_data:
                for child_name, child_data in module_data["children"].items():
                    child_item = QTreeWidgetItem(parent_item, [child_name])
                    child_item.setFlags(child_item.flags() | Qt.ItemIsUserCheckable)
                    child_item.setCheckState(0, Qt.Unchecked)

                    # 检查是否有更深层次的嵌套（如终端限速 -> IP限速/MAC限速）
                    if "children" in child_data:
                        # 第三层嵌套
                        for sub_child_name, sub_child_data in child_data["children"].items():
                            sub_child_item = QTreeWidgetItem(child_item, [sub_child_name])
                            sub_child_item.setFlags(sub_child_item.flags() | Qt.ItemIsUserCheckable)
                            sub_child_item.setCheckState(0, Qt.Unchecked)
                            sub_child_item.setData(0, Qt.UserRole, sub_child_data.get("testcases", []))
                    else:
                        # 第二层直接有testcases
                        child_item.setData(0, Qt.UserRole, child_data.get("testcases", []))

        self.module_tree.expandAll()
        self.module_tree.blockSignals(False)

    def _load_config_to_ui(self):
        """加载配置到界面"""
        self.ip_input.setText(self.config.device.ip)
        self.username_input.setText(self.config.device.username)
        self.password_input.setText(self.config.device.password)
        # 加载测试人员和版本（如果配置中有的话）
        if hasattr(self.config, 'report'):
            if hasattr(self.config.report, 'tester'):
                self.tester_input.setText(self.config.report.tester)
            if hasattr(self.config.report, 'version'):
                self.version_input.setText(self.config.report.version)
        # 加载浏览器配置
        if hasattr(self.config, 'browser'):
            if hasattr(self.config.browser, 'viewport_width'):
                self.width_input.setText(str(self.config.browser.viewport_width))
            if hasattr(self.config.browser, 'viewport_height'):
                self.height_input.setText(str(self.config.browser.viewport_height))
            # 加载自适应屏幕设置
            auto_adapt = getattr(self.config.browser, 'auto_adapt_screen', True)
            self.auto_adapt_checkbox.setChecked(auto_adapt)
            # 根据自适应设置启用/禁用分辨率输入框
            self._on_auto_adapt_changed(Qt.Checked if auto_adapt else Qt.Unchecked)

    def _toggle_all_modules(self, state):
        """全选/取消全选模块"""
        self.module_tree.blockSignals(True)
        for i in range(self.module_tree.topLevelItemCount()):
            item = self.module_tree.topLevelItem(i)
            item.setCheckState(0, Qt.Checked if state else Qt.Unchecked)
            for j in range(item.childCount()):
                child = item.child(j)
                child.setCheckState(0, Qt.Checked if state else Qt.Unchecked)
        self.module_tree.blockSignals(False)
        self._update_testcase_list()

    def _on_auto_adapt_changed(self, state):
        """自适应屏幕模式状态改变"""
        auto_adapt = state == Qt.Checked
        # 启用/禁用分辨率输入框
        self.width_input.setEnabled(not auto_adapt)
        self.height_input.setEnabled(not auto_adapt)
        # 更新样式提示
        if auto_adapt:
            self.width_input.setStyleSheet("color: gray;")
            self.height_input.setStyleSheet("color: gray;")
        else:
            self.width_input.setStyleSheet("")
            self.height_input.setStyleSheet("")

    def _toggle_all_testcases(self, state):
        """全选/取消全选用例"""
        for i in range(self.testcase_list.count()):
            item = self.testcase_list.item(i)
            item.setCheckState(Qt.Checked if state else Qt.Unchecked)
        self._update_testcase_count()

    def _on_module_changed(self, item, column):
        """模块选择变化"""
        self._update_testcase_list()

    def _update_testcase_list(self):
        """更新测试用例列表"""
        self.testcase_list.clear()
        selected_testcases = []

        for i in range(self.module_tree.topLevelItemCount()):
            parent = self.module_tree.topLevelItem(i)
            for j in range(parent.childCount()):
                child = parent.child(j)
                if child.checkState(0) == Qt.Checked:
                    testcases = child.data(0, Qt.UserRole)
                    if testcases:
                        selected_testcases.extend(testcases)
                # 检查第三层嵌套
                for k in range(child.childCount()):
                    sub_child = child.child(k)
                    if sub_child.checkState(0) == Qt.Checked:
                        testcases = sub_child.data(0, Qt.UserRole)
                        if testcases:
                            selected_testcases.extend(testcases)

        for testcase in selected_testcases:
            item = QListWidgetItem(testcase)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)
            self.testcase_list.addItem(item)

        self._update_testcase_count()

    def _update_testcase_count(self):
        """更新选中用例数量"""
        count = sum(1 for i in range(self.testcase_list.count())
                    if self.testcase_list.item(i).checkState() == Qt.Checked)
        self.testcase_count_label.setText(f"已选: {count}")
        self.total_label.setText(str(count))
        self.progress_bar.setMaximum(count)

    def _test_connection(self):
        """测试设备连接"""
        self.status_label.setText("正在连接...")
        self.connect_btn.setEnabled(False)

        # 更新配置
        self.config.device.ip = self.ip_input.text()
        self.config.device.username = self.username_input.text()
        self.config.device.password = self.password_input.text()

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(f"http://{self.config.device.ip}", timeout=10000)

                # 检查页面标题
                title = page.title()
                browser.close()

                self.connection_status.setText("● 已连接")
                self.connection_status.setStyleSheet("color: green;")
                self.status_label.setText(f"连接成功 - {title}")
                self._log("INFO", f"成功连接到设备 {self.config.device.ip}")

        except Exception as e:
            self.connection_status.setText("● 连接失败")
            self.connection_status.setStyleSheet("color: red;")
            self.status_label.setText("连接失败")
            self._log("ERROR", f"连接失败: {str(e)}")
            QMessageBox.warning(self, "连接失败", f"无法连接到设备:\n{str(e)}")

        finally:
            self.connect_btn.setEnabled(True)

    def _start_tests(self):
        """开始测试"""
        # 获取选中的测试用例
        selected_testcases = []
        for i in range(self.testcase_list.count()):
            item = self.testcase_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_testcases.append(item.text())

        if not selected_testcases:
            QMessageBox.warning(self, "警告", "请先选择要执行的测试用例")
            return

        # 更新UI状态
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self._reset_statistics()

        # 启动计时器
        self.test_start_time = datetime.now()
        self.elapsed_timer.start(1000)  # 每秒更新一次

        # 保存配置
        self.config.device.ip = self.ip_input.text()
        self.config.device.username = self.username_input.text()
        self.config.device.password = self.password_input.text()

        # 保存测试人员和版本到报告配置
        if not hasattr(self.config, 'report'):
            from config.config import ReportConfig
            self.config.report = ReportConfig()
        self.config.report.tester = self.tester_input.text() or "自动化测试"
        self.config.report.version = self.version_input.text() or "v4.0"

        # 保存浏览器分辨率配置
        try:
            width = int(self.width_input.text()) if self.width_input.text() else 1400
            height = int(self.height_input.text()) if self.height_input.text() else 850
        except ValueError:
            width, height = 1400, 850
        self.config.browser.viewport_width = width
        self.config.browser.viewport_height = height
        # 保存自适应屏幕设置
        self.config.browser.auto_adapt_screen = self.auto_adapt_checkbox.isChecked()

        # 创建并启动测试运行器
        self.test_runner = TestRunner(selected_testcases, self.config)
        self.test_runner.log_signal.connect(self._log)
        self.test_runner.progress_signal.connect(self._update_progress)
        self.test_runner.finished_signal.connect(self._on_tests_finished)
        self.test_runner.start()

        self.status_label.setText("测试执行中...")
        self._log("INFO", f"开始执行 {len(selected_testcases)} 个测试用例")

    def _stop_tests(self):
        """停止测试"""
        if self.test_runner and self.test_runner.isRunning():
            self.test_runner.stop()
            self.elapsed_timer.stop()  # 停止计时器
            self._log("WARNING", "正在停止测试...")
            # 等待线程结束，然后恢复UI状态
            self.test_runner.wait(3000)  # 最多等待3秒
            # 恢复按钮状态
            self.start_action.setEnabled(True)
            self.stop_action.setEnabled(False)
            self.status_label.setText("测试已停止")

    def _reset_statistics(self):
        """重置统计信息"""
        self.passed_label.setText("0")
        self.failed_label.setText("0")
        self.skipped_label.setText("0")
        self.progress_bar.setValue(0)
        self.time_label.setText("用时: 00:00:00")

    def _update_elapsed_time(self):
        """更新已用时间显示"""
        if self.test_start_time:
            elapsed = datetime.now() - self.test_start_time
            # 格式化为 HH:MM:SS
            total_seconds = int(elapsed.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_label.setText(f"用时: {hours:02d}:{minutes:02d}:{seconds:02d}")

    def _update_progress(self, total, passed, failed, skipped):
        """更新进度"""
        self.total_label.setText(str(total))
        self.passed_label.setText(str(passed))
        self.failed_label.setText(str(failed))
        self.skipped_label.setText(str(skipped))
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(passed + failed + skipped)

    def _on_tests_finished(self, report_path):
        """测试完成"""
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.status_label.setText("测试完成")

        # 停止计时器
        self.elapsed_timer.stop()
        self._update_elapsed_time()  # 更新最终时间

        self._log("INFO", f"测试完成，报告目录: {report_path}")

        # 询问是否打开报告
        reply = QMessageBox.question(
            self, "测试完成",
            "测试执行完成，是否打开报告?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            # 传递None让_open_report自动查找最新报告
            self._open_report(None)

    def _log(self, level, message):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")

        # 根据级别设置颜色
        colors = {
            "INFO": "#52c41a",
            "WARNING": "#faad14",
            "ERROR": "#ff4d4f",
            "DEBUG": "#1890ff"
        }
        color = colors.get(level, "#d4d4d4")

        # 构建日志条目
        log_entry = (
            f'<span style="color: #888;">[{timestamp}]</span> '
            f'<span style="color: {color};">[{level}]</span> '
            f'{message}'
        )

        # 存储日志（用于过滤）
        if not hasattr(self, '_log_entries'):
            self._log_entries = []
        self._log_entries.append((level, log_entry))

        # 根据当前过滤级别决定是否显示
        current_filter = self.log_level_combo.currentText()
        if self._should_show_log(level, current_filter):
            self.log_text.append(log_entry)

    def _should_show_log(self, level, filter_level):
        """判断日志是否应该显示"""
        if filter_level == "全部":
            return True
        # 定义级别优先级：ERROR > WARNING > INFO > DEBUG
        level_priority = {"ERROR": 3, "WARNING": 2, "INFO": 1, "DEBUG": 0}
        return level_priority.get(level, 0) >= level_priority.get(filter_level, 0)

    def _clear_logs(self):
        """清空日志"""
        self.log_text.clear()
        self._log_entries = []

    def _filter_logs(self, level):
        """过滤日志"""
        if not hasattr(self, '_log_entries'):
            return

        # 清空当前显示
        self.log_text.clear()

        # 根据过滤级别重新显示日志
        for log_level, log_entry in self._log_entries:
            if self._should_show_log(log_level, level):
                self.log_text.append(log_entry)

    def _open_config(self):
        """打开配置文件"""
        from PySide6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开配置文件", "", "YAML Files (*.yaml *.yml)"
        )
        if file_path:
            self.config = Config.from_yaml(file_path)
            self._load_config_to_ui()

    def _save_config(self):
        """保存配置文件"""
        from PySide6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存配置文件", "settings.yaml", "YAML Files (*.yaml *.yml)"
        )
        if file_path:
            self.config.device.ip = self.ip_input.text()
            self.config.device.username = self.username_input.text()
            self.config.device.password = self.password_input.text()
            self.config.to_yaml(file_path)
            self._log("INFO", f"配置已保存到: {file_path}")

    def _show_config_dialog(self, tab="device"):
        """显示配置对话框"""
        dialog = ConfigDialog(self, self.config, tab)
        if dialog.exec() == QDialog.Accepted:
            self.config = dialog.get_config()
            self._load_config_to_ui()

    def _open_report(self, report_path=None):
        """打开测试报告"""
        import webbrowser
        import glob

        # 获取项目根目录（用于转换相对路径）
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        if report_path is None:
            # 查找最新的报告
            report_dir = self.config.report.output_dir
            # 转换为绝对路径
            if not os.path.isabs(report_dir):
                report_dir = os.path.join(project_root, report_dir)

            self._log("INFO", f"查找报告目录: {report_dir}")

            if not os.path.exists(report_dir):
                # 尝试创建目录
                try:
                    os.makedirs(report_dir, exist_ok=True)
                    self._log("INFO", f"已创建报告目录: {report_dir}")
                except Exception as e:
                    self._log("ERROR", f"无法创建报告目录: {str(e)}")
                    QMessageBox.information(self, "提示", f"报告目录不存在且无法创建\n目录: {report_dir}\n错误: {str(e)}")
                    return

            # 查找所有HTML报告
            try:
                reports = glob.glob(os.path.join(report_dir, "*.html"))
                self._log("INFO", f"找到 {len(reports)} 个报告文件")
            except Exception as e:
                self._log("ERROR", f"查找报告文件失败: {str(e)}")
                reports = []

            if reports:
                # 按修改时间排序，获取最新的
                report_path = max(reports, key=os.path.getctime)
                self._log("INFO", f"最新报告: {report_path}")
            else:
                # 列出目录内容帮助调试
                try:
                    all_files = os.listdir(report_dir)
                    self._log("DEBUG", f"目录内容: {all_files}")
                except:
                    pass
                QMessageBox.information(self, "提示", f"报告目录中没有找到测试报告\n\n目录: {report_dir}\n\n请先运行测试生成报告。")
                return

        # 确保是绝对路径
        if not os.path.isabs(report_path):
            report_path = os.path.join(project_root, report_path)

        # 检查文件是否存在
        if not os.path.exists(report_path):
            self._log("ERROR", f"报告文件不存在: {report_path}")
            QMessageBox.warning(self, "错误", f"报告文件不存在:\n{report_path}")
            return

        # 打开报告
        try:
            abs_path = os.path.abspath(report_path)
            self._log("INFO", f"正在打开报告: {abs_path}")

            if os.name == 'nt':
                # Windows系统 - 使用os.startfile更可靠
                os.startfile(abs_path)
            else:
                # 其他系统使用webbrowser
                file_url = f"file://{abs_path}"
                webbrowser.open(file_url)

            self._log("INFO", f"已打开报告: {abs_path}")

        except Exception as e:
            error_msg = str(e)
            self._log("ERROR", f"打开报告失败: {error_msg}")

            # 尝试备用方法
            try:
                import subprocess
                if os.name == 'nt':
                    subprocess.run(['cmd', '/c', 'start', '', abs_path], check=True)
                    self._log("INFO", "使用备用方法打开报告成功")
                    return
            except Exception as e2:
                error_msg = f"{error_msg}\n备用方法也失败: {str(e2)}"

            QMessageBox.warning(self, "错误", f"无法打开报告:\n{error_msg}\n\n报告路径: {abs_path}\n\n您可以手动打开此文件。")

    def _show_help(self):
        """显示帮助"""
        help_text = """
爱快路由器4.0自动化测试工具

使用说明:
1. 配置设备IP、用户名、密码
2. 点击"连接测试"验证连接
3. 在左侧选择测试模块和用例
4. 点击"开始测试"执行
5. 查看日志和报告

快捷键:
- Ctrl+O: 打开配置
- Ctrl+S: 保存配置
- Ctrl+Q: 退出
- F1: 帮助
        """
        QMessageBox.information(self, "使用说明", help_text)

    def _show_about(self):
        """显示关于"""
        about_text = """
爱快路由器4.0自动化测试工具

版本: 1.0.0

基于 Playwright + Pytest + PySide6 开发

© 2026 爱快测试团队
        """
        QMessageBox.about(self, "关于", about_text)

    def closeEvent(self, event):
        """窗口关闭事件"""
        if self.test_runner and self.test_runner.isRunning():
            reply = QMessageBox.question(
                self, "确认退出",
                "测试正在执行中，确定要退出吗?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            self.test_runner.stop()
            self.test_runner.wait()

        event.accept()
