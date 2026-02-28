# 爱快路由器4.0自动化测试框架 - VLAN设置模块测试计划

## 一、项目背景

爱快路由器升级到4.0版本，需要进行全面的UI自动化测试。本项目旨在构建一个完整的自动化测试框架，支持：
- 基于Playwright的Web UI自动化测试
- Pytest测试框架 + Jinja2美化测试报告
- PySide6 GUI界面管理测试执行

## 二、测试目标模块：网络配置 - VLAN设置

### 2.1 功能分析

通过Playwright探索，VLAN设置页面包含以下功能：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| VLAN ID | 文本框 | 是 | 范围: 1-4090 |
| VLAN名称 | 文本框 | 是 | **必须以vlan开头**，只支持数字、字母和'_'，长度不超过15位 |
| MAC | 文本框 | 否 | MAC地址 |
| IP | 文本框 | 否 | IP地址 |
| 子网掩码 | 下拉框 | 否 | 255.255.255.255 ~ 255.255.252.0 |
| 线路 | 下拉框 | 否 | 选择关联线路(如lan1) |
| 扩展IP | 动态添加 | 否 | 可添加多个扩展IP |
| 备注 | 文本框 | 否 | 备注信息 |

**VLAN状态图标说明：**
- `play-circle` 图标：启用状态
- `minus-circle` 图标：停用状态

### 2.2 页面操作
- 添加：新增VLAN配置
- 导入：批量导入VLAN配置
- 导出：导出当前VLAN配置
- 搜索：按条件搜索VLAN
- 编辑：修改已有VLAN配置
- 删除：删除VLAN配置
- 启用/停用：单个或批量切换VLAN状态

## 三、测试用例设计

### 3.1 添加VLAN测试用例

#### 3.1.1 正常值测试
| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_ADD_001 | 添加最小VLAN ID | 输入VLAN ID=1, 名称="test_vlan" | 添加成功，列表显示新记录 |
| VLAN_ADD_002 | 添加最大VLAN ID | 输入VLAN ID=4090, 名称="test_vlan" | 添加成功，列表显示新记录 |
| VLAN_ADD_003 | 添加中间值VLAN ID | 输入VLAN ID=100, 名称="test_vlan" | 添加成功，列表显示新记录 |
| VLAN_ADD_004 | 添加完整信息VLAN | 填写所有字段 | 添加成功，所有信息正确显示 |
| VLAN_ADD_005 | 添加扩展IP | 添加VLAN并配置多个扩展IP | 扩展IP正确保存和显示 |

#### 3.1.2 边界值测试
| 用例ID | 用例名称 | 测试数据 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_ADD_BV_001 | VLAN ID下边界-1 | VLAN ID=0 | 提示错误，添加失败 |
| VLAN_ADD_BV_002 | VLAN ID上边界+1 | VLAN ID=4091 | 提示错误，添加失败 |
| VLAN_ADD_BV_003 | VLAN ID负数 | VLAN ID=-1 | 提示错误，添加失败 |
| VLAN_ADD_BV_004 | VLAN名称最大长度 | 输入超长名称 | 验证长度限制 |
| VLAN_ADD_BV_005 | 子网掩码边界 | 选择各子网掩码选项 | 均可正常保存 |

#### 3.1.3 异常/报错测试
| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_ADD_ERR_001 | 必填项为空-VLAN ID | 不输入VLAN ID，点击保存 | 提示"请输入vlanID" |
| VLAN_ADD_ERR_002 | 必填项为空-名称 | 不输入名称，点击保存 | 提示"请输入vlan名称" |
| VLAN_ADD_ERR_003 | VLAN ID非数字 | 输入"abc"作为VLAN ID | 提示格式错误 |
| VLAN_ADD_ERR_004 | VLAN ID重复 | 输入已存在的VLAN ID | 提示VLAN ID已存在 |
| VLAN_ADD_ERR_005 | MAC格式错误 | 输入错误MAC地址格式 | 提示MAC格式错误 |
| VLAN_ADD_ERR_006 | IP格式错误 | 输入错误IP地址格式 | 提示IP格式错误 |
| VLAN_ADD_ERR_007 | 特殊字符测试 | 名称包含特殊字符 | 验证字符限制 |

### 3.2 编辑VLAN测试用例

| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_EDIT_001 | 修改VLAN名称 | 修改已有VLAN的名称 | 修改成功 |
| VLAN_EDIT_002 | 修改IP地址 | 修改已有VLAN的IP | 修改成功 |
| VLAN_EDIT_003 | 修改子网掩码 | 切换子网掩码选项 | 修改成功 |
| VLAN_EDIT_004 | 添加扩展IP | 为已有VLAN添加扩展IP | 添加成功 |
| VLAN_EDIT_005 | 清空可选字段 | 清空MAC、IP等字段 | 保存成功 |

### 3.3 删除VLAN测试用例

| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_DEL_001 | 删除单个VLAN | 删除一条VLAN记录 | 删除成功，列表不再显示 |
| VLAN_DEL_002 | 批量删除VLAN | 勾选多条记录删除 | 批量删除成功 |
| VLAN_DEL_003 | 删除后验证 | 删除后刷新页面 | 记录确实被删除 |
| VLAN_DEL_004 | 取消删除 | 点击删除后取消 | 记录保留 |

### 3.4 搜索/查询测试用例

| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_SEARCH_001 | 按VLAN名称搜索 | 输入名称关键字 | 正确过滤结果 |
| VLAN_SEARCH_002 | 按IP地址搜索 | 输入IP地址 | 正确过滤结果 |
| VLAN_SEARCH_003 | 模糊搜索 | 输入部分关键字 | 正确匹配结果 |
| VLAN_SEARCH_004 | 搜索不存在数据 | 输入不存在的内容 | 显示空列表 |

### 3.5 导入/导出测试用例

**测试策略优化：** 导入测试采用"导出→删除→导入→验证"流程，提高测试效率

| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_EXPORT_001 | 导出VLAN配置 | 添加3条VLAN，点击导出按钮 | 下载正确格式CSV文件 |
| VLAN_EXPORT_002 | 导出空数据 | 无数据时导出 | 验证导出结果（空文件或提示） |
| VLAN_IMPORT_001 | 导入-完整流程 | 1.先添加5条VLAN<br>2.导出CSV<br>3.批量删除所有VLAN<br>4.导入刚才导出的CSV<br>5.验证5条数据全部恢复 | 5条VLAN全部恢复，数据正确 |
| VLAN_IMPORT_002 | 导入有效CSV文件 | 使用预置的有效CSV文件导入 | 导入成功，列表显示新记录 |
| VLAN_IMPORT_003 | 导入无效格式文件 | 上传错误格式文件（如.txt） | 提示格式错误 |
| VLAN_IMPORT_004 | 导入包含重复VLAN ID | 上传含已存在VLAN ID的CSV | 提示VLAN ID重复或覆盖 |
| VLAN_IMPORT_005 | 导入空文件 | 上传空CSV文件 | 提示文件为空或无数据 |
| VLAN_IMPORT_006 | 导入部分有效数据 | CSV中包含有效和无效数据 | 有效数据导入，无效数据提示 |
| VLAN_IMPORT_007 | 大批量导入 | 导入50条VLAN数据 | 全部导入成功，验证性能 |
| VLAN_IO_001 | 导出导入数据一致性 | 导出→删除→导入→对比 | 数据完全一致 |

### 3.6 启用/停用测试用例

| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_STATUS_001 | 单个停用VLAN | 点击已启用VLAN的停用按钮，确认 | 状态变为停用，图标变为minus-circle |
| VLAN_STATUS_002 | 单个启用VLAN | 点击已停用VLAN的启用按钮，确认 | 状态变为启用，图标变为play-circle |
| VLAN_STATUS_003 | 批量启用VLAN | 勾选多条停用的VLAN，点击批量启用 | 全部变为启用状态 |
| VLAN_STATUS_004 | 批量停用VLAN | 勾选多条启用的VLAN，点击批量停用 | 全部变为停用状态 |
| VLAN_STATUS_005 | 取消启用/停用 | 点击停用/启用后，在确认框点击取消 | 状态保持不变 |
| VLAN_STATUS_006 | 混合状态批量操作 | 勾选启用和停用混合的VLAN，批量启用 | 所有选中的变为启用 |
| VLAN_STATUS_007 | 批量启用-全部已启用 | 勾选已启用的VLAN，点击批量启用 | 提示已经是启用状态或操作无变化 |
| VLAN_STATUS_008 | 批量停用-全部已停用 | 勾选已停用的VLAN，点击批量停用 | 提示已经是停用状态或操作无变化 |
| VLAN_STATUS_009 | 批量启用-取消确认 | 批量启用时点击取消 | 状态保持不变 |
| VLAN_STATUS_010 | 批量停用-取消确认 | 批量停用时点击取消 | 状态保持不变 |
| VLAN_STATUS_011 | 未选择时批量操作 | 不勾选任何VLAN，点击批量启用/停用 | 按钮不可点击或提示请选择数据 |

### 3.7 扩展IP测试用例

| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_EXTIP_001 | 添加单个扩展IP | 添加VLAN时点击扩展IP的添加按钮，填写IP | 扩展IP添加成功 |
| VLAN_EXTIP_002 | 添加多个扩展IP | 添加VLAN时添加3个扩展IP | 所有扩展IP正确保存 |
| VLAN_EXTIP_003 | 扩展IP格式验证 | 输入错误格式的IP | 提示IP格式错误 |
| VLAN_EXTIP_004 | 删除扩展IP | 添加扩展IP后点击删除 | 扩展IP被删除 |
| VLAN_EXTIP_005 | 编辑时添加扩展IP | 编辑已有VLAN，添加扩展IP | 修改成功 |
| VLAN_EXTIP_006 | 编辑时删除扩展IP | 编辑已有VLAN，删除扩展IP | 修改成功 |
| VLAN_EXTIP_007 | 扩展IP重复验证 | 添加重复的扩展IP | 提示IP重复 |
| VLAN_EXTIP_008 | 扩展IP与主IP相同 | 扩展IP与主IP地址相同 | 提示IP冲突或允许保存 |

### 3.8 批量删除测试用例

| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_DEL_BATCH_001 | 批量删除2条VLAN | 勾选2条VLAN，点击批量删除，确认 | 2条全部删除成功 |
| VLAN_DEL_BATCH_002 | 批量删除5条VLAN | 勾选5条VLAN，点击批量删除，确认 | 5条全部删除成功 |
| VLAN_DEL_BATCH_003 | 批量删除-取消确认 | 勾选多条VLAN，点击删除后取消 | 记录保留 |
| VLAN_DEL_BATCH_004 | 全选后批量删除 | 点击全选，批量删除所有VLAN | 所有VLAN被删除 |
| VLAN_DEL_BATCH_005 | 未选择时批量删除 | 不勾选任何VLAN，点击批量删除 | 按钮不可点击或提示请选择数据 |
| VLAN_DEL_BATCH_006 | 删除后验证列表 | 批量删除后刷新页面 | 确认记录已被删除 |

### 3.9 多条数据测试

| 用例ID | 用例名称 | 测试步骤 | 预期结果 |
|--------|----------|----------|----------|
| VLAN_MULTI_001 | 添加10条数据 | 批量添加10条VLAN | 全部添加成功 |
| VLAN_MULTI_002 | 添加50条数据 | 批量添加50条VLAN | 验证性能和显示 |
| VLAN_MULTI_003 | 分页功能 | 添加超过分页数量 | 分页正常工作 |
| VLAN_MULTI_004 | 全选操作 | 点击全选复选框 | 所有记录被选中 |
| VLAN_MULTI_005 | 跨页全选 | 多页数据时全选 | 验证全选范围 |

## 四、项目结构设计

```
4.0前端UI自动化测试/
├── config/                     # 配置文件
│   ├── __init__.py
│   ├── config.py              # 全局配置(IP、账号、密码)
│   └── settings.yaml          # YAML配置文件
├── pages/                      # 页面对象模型(POM)
│   ├── __init__.py
│   ├── base_page.py           # 基础页面类
│   ├── login_page.py          # 登录页面
│   └── network/               # 网络配置模块
│       ├── __init__.py
│       └── vlan_page.py       # VLAN设置页面
├── tests/                      # 测试用例
│   ├── __init__.py
│   ├── conftest.py            # pytest fixtures
│   └── network/               # 网络配置测试
│       ├── __init__.py
│       └── test_vlan.py       # VLAN设置测试
├── utils/                      # 工具类
│   ├── __init__.py
│   ├── browser.py             # 浏览器管理
│   ├── logger.py              # 日志工具
│   ├── screenshot.py          # 截图工具
│   └── data_generator.py      # 测试数据生成
├── reports/                    # 测试报告
│   ├── templates/             # Jinja2模板
│   │   └── report.html        # 报告模板
│   └── output/                # 报告输出目录
├── gui/                        # GUI界面
│   ├── __init__.py
│   ├── main_window.py         # 主窗口
│   ├── config_dialog.py       # 配置对话框
│   ├── test_runner.py         # 测试执行器
│   └── resources/             # 资源文件
│       └── styles.qss         # 样式表
├── test_data/                  # 测试数据
│   └── vlan/                  # VLAN测试数据
│       ├── import_valid.csv   # 有效导入数据
│       └── import_invalid.csv # 无效导入数据
├── requirements.txt            # 依赖包
├── pytest.ini                 # pytest配置
├── run_tests.py               # 命令行运行入口
└── main.py                    # GUI启动入口
```

## 五、技术栈

| 组件 | 技术选型 | 说明 |
|------|----------|------|
| 自动化框架 | Playwright (sync_api) | 现代Web自动化框架 |
| 测试框架 | pytest | Python主流测试框架 |
| 报告模板 | pytest-html + Jinja2 | 美化测试报告 |
| GUI框架 | PySide6 | Qt官方Python绑定 |
| 配置管理 | PyYAML | YAML配置文件解析 |
| 日志 | logging | Python标准库 |
| 数据处理 | pandas | CSV导入导出处理 |

## 六、GUI界面详细设计 (PySide6)

### 6.1 主窗口布局

```
+------------------------------------------------------------------+
|  爱快路由器4.0自动化测试工具                           [_][□][X] |
+------------------------------------------------------------------+
| 菜单栏: [文件] [设置] [工具] [帮助]                                |
+------------------------------------------------------------------+
| 工具栏: [连接设备] [开始测试] [停止] [查看报告] [设置]             |
+------------------------------------------------------------------+
|                                        |                          |
|  +--设备配置---------------------+    |  +--测试进度-----------+ |
|  | IP地址: [10.66.0.150    ]     |    |  | 总计: 50            | |
|  | 用户名: [admin          ]     |    |  | 通过: 45  ✓         | |
|  | 密  码: [********        ]     |    |  | 失败: 3   ✗         | |
|  | [连接测试]  状态: ●已连接      |    |  | 跳过: 2   ○         | |
|  +--------------------------------+    |  | [================]  | |
|                                        |  | 进度: 80%           | |
|  +--测试模块---------------------+    |  +----------------------+ |
|  | □ 全选                        |    |                          |
|  | ☑ 网络配置                    |    |  +--执行日志-----------+ |
|  |   ☑ VLAN设置                  |    |  | [INFO] 开始测试...   | |
|  |   ☑ 内外网设置                |    |  | [PASS] test_add_vlan | |
|  |   ☐ 智能流控                  |    |  | [FAIL] test_del_vlan | |
|  |   ☐ 终端限速                  |    |  | [INFO] 错误截图已保存| |
|  | ☐ 监控中心                    |    |  | ...                  | |
|  | ☐ 安全中心                    |    |  |                      | |
|  | ☐ 无线服务                    |    |  +----------------------+ |
|  +--------------------------------+    |                          |
|                                        |                          |
|  +--测试用例---------------------+    |                          |
|  | □ 全选                        |    |                          |
|  | ☑ VLAN_ADD_001 添加最小ID     |    |                          |
|  | ☑ VLAN_ADD_002 添加最大ID     |    |                          |
|  | ☑ VLAN_STATUS_001 停用测试    |    |                          |
|  | ☐ VLAN_DEL_001 删除测试       |    |                          |
|  | ...                           |    |                          |
|  +--------------------------------+    |                          |
+------------------------------------------------------------------+
| 状态栏: 就绪 | 设备: 10.66.0.150 | 用时: 00:05:30 | 内存: 256MB   |
+------------------------------------------------------------------+
```

### 6.2 主要类设计

```python
# gui/main_window.py
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLineEdit, QPushButton, QLabel, QTreeWidget,
    QListWidget, QTextEdit, QProgressBar, QStatusBar, QMenuBar,
    QToolBar, QMessageBox, QSplitter
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QAction


class MainWindow(QMainWindow):
    """主窗口类"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("爱快路由器4.0自动化测试工具")
        self.setGeometry(100, 100, 1200, 800)

        # 初始化UI
        self._init_menubar()
        self._init_toolbar()
        self._init_central_widget()
        self._init_statusbar()

    def _init_menubar(self):
        """初始化菜单栏"""
        menubar = self.menuBar()

        # 文件菜单
        file_menu = menubar.addMenu("文件(&F)")
        file_menu.addAction(QAction("打开配置", self))
        file_menu.addAction(QAction("保存配置", self))
        file_menu.addSeparator()
        file_menu.addAction(QAction("退出", self))

        # 设置菜单
        settings_menu = menubar.addMenu("设置(&S)")
        settings_menu.addAction(QAction("设备配置", self))
        settings_menu.addAction(QAction("报告设置", self))

        # 帮助菜单
        help_menu = menubar.addMenu("帮助(&H)")
        help_menu.addAction(QAction("使用说明", self))
        help_menu.addAction(QAction("关于", self))

    def _init_central_widget(self):
        """初始化中心部件"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)

        # 左侧面板（设备配置 + 模块选择 + 用例选择）
        left_panel = self._create_left_panel()

        # 右侧面板（进度 + 日志）
        right_panel = self._create_right_panel()

        # 使用分割器
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 600])

        main_layout.addWidget(splitter)

    def _create_left_panel(self) -> QWidget:
        """创建左侧面板"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # 设备配置区
        device_group = self._create_device_group()
        layout.addWidget(device_group)

        # 测试模块区
        module_group = self._create_module_group()
        layout.addWidget(module_group)

        # 测试用例区
        testcase_group = self._create_testcase_group()
        layout.addWidget(testcase_group)

        return panel

    def _create_device_group(self) -> QGroupBox:
        """创建设备配置区"""
        group = QGroupBox("设备配置")
        layout = QVBoxLayout(group)

        # IP地址
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP地址:"))
        self.ip_input = QLineEdit("10.66.0.150")
        ip_layout.addWidget(self.ip_input)
        layout.addLayout(ip_layout)

        # 用户名
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("用户名:"))
        self.user_input = QLineEdit("admin")
        user_layout.addWidget(self.user_input)
        layout.addLayout(user_layout)

        # 密码
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(QLabel("密  码:"))
        self.pwd_input = QLineEdit("admin123")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        pwd_layout.addWidget(self.pwd_input)
        layout.addLayout(pwd_layout)

        # 连接按钮和状态
        btn_layout = QHBoxLayout()
        self.connect_btn = QPushButton("连接测试")
        self.connect_btn.clicked.connect(self._test_connection)
        btn_layout.addWidget(self.connect_btn)

        self.status_label = QLabel("状态: 未连接")
        btn_layout.addWidget(self.status_label)
        btn_layout.addStretch()

        layout.addLayout(btn_layout)

        return group
```

### 6.3 配置对话框

```python
# gui/config_dialog.py
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QSpinBox, QComboBox, QCheckBox,
    QPushButton, QGroupBox, QFileDialog, QTabWidget
)


class ConfigDialog(QDialog):
    """配置对话框"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置")
        self.setMinimumWidth(500)

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # 使用标签页
        tab_widget = QTabWidget()

        # 设备配置标签页
        device_tab = self._create_device_tab()
        tab_widget.addTab(device_tab, "设备配置")

        # 报告配置标签页
        report_tab = self._create_report_tab()
        tab_widget.addTab(report_tab, "报告设置")

        # 浏览器配置标签页
        browser_tab = self._create_browser_tab()
        tab_widget.addTab(browser_tab, "浏览器设置")

        # 定时任务标签页
        schedule_tab = self._create_schedule_tab()
        tab_widget.addTab(schedule_tab, "定时任务")

        layout.addWidget(tab_widget)

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def _create_browser_tab(self) -> QWidget:
        """创建浏览器配置标签页"""
        widget = QWidget()
        layout = QFormLayout(widget)

        # 浏览器选择
        self.browser_combo = QComboBox()
        self.browser_combo.addItems(["Chromium", "Firefox", "WebKit"])
        layout.addRow("浏览器:", self.browser_combo)

        # 无头模式
        self.headless_check = QCheckBox("无头模式（后台运行）")
        layout.addRow("", self.headless_check)

        # 超时设置
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1000, 60000)
        self.timeout_spin.setValue(30000)
        self.timeout_spin.setSuffix(" ms")
        layout.addRow("默认超时:", self.timeout_spin)

        # 截图路径
        screenshot_layout = QHBoxLayout()
        self.screenshot_path = QLineEdit("reports/screenshots")
        browse_btn = QPushButton("浏览...")
        browse_btn.clicked.connect(self._browse_screenshot_path)
        screenshot_layout.addWidget(self.screenshot_path)
        screenshot_layout.addWidget(browse_btn)
        layout.addRow("截图保存路径:", screenshot_layout)

        return widget

    def _create_schedule_tab(self) -> QWidget:
        """创建定时任务配置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 启用定时任务
        self.enable_schedule = QCheckBox("启用定时执行")
        layout.addWidget(self.enable_schedule)

        # 执行频率
        freq_group = QGroupBox("执行频率")
        freq_layout = QFormLayout(freq_group)

        self.freq_combo = QComboBox()
        self.freq_combo.addItems(["每天", "每周", "每小时", "自定义Cron表达式"])
        freq_layout.addRow("频率:", self.freq_combo)

        # 时间设置
        self.time_edit = QTimeEdit()
        self.time_edit.setTime(QTime(2, 0))  # 默认凌晨2点
        freq_layout.addRow("执行时间:", self.time_edit)

        # 星期选择（每周时使用）
        self.weekday_combo = QComboBox()
        self.weekday_combo.addItems(["周一", "周二", "周三", "周四", "周五", "周六", "周日"])
        freq_layout.addRow("星期:", self.weekday_combo)

        # Cron表达式（自定义时使用）
        self.cron_input = QLineEdit("0 2 * * *")
        self.cron_input.setPlaceholderText("Cron表达式，如: 0 2 * * *")
        freq_layout.addRow("Cron表达式:", self.cron_input)

        layout.addWidget(freq_group)

        # 定时任务列表
        list_group = QGroupBox("已配置的定时任务")
        list_layout = QVBoxLayout(list_group)

        self.schedule_list = QListWidget()
        self.schedule_list.addItem("每天 02:00 - 全部测试")
        list_layout.addWidget(self.schedule_list)

        btn_layout = QHBoxLayout()
        add_btn = QPushButton("添加任务")
        edit_btn = QPushButton("编辑")
        del_btn = QPushButton("删除")
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(edit_btn)
        btn_layout.addWidget(del_btn)
        list_layout.addLayout(btn_layout)

        layout.addWidget(list_group)

        # 测试模块选择（用于定时任务）
        module_group = QGroupBox("定时执行模块")
        module_layout = QVBoxLayout(module_group)

        self.schedule_modules = QListWidget()
        self.schedule_modules.addItems([
            "网络配置 - VLAN设置",
            "网络配置 - 内外网设置",
            "网络配置 - 智能流控",
            "监控中心 - 线路监控",
            "安全中心 - ACL规则"
        ])
        self.schedule_modules.setSelectionMode(QListWidget.MultiSelection)
        module_layout.addWidget(self.schedule_modules)

        layout.addWidget(module_group)

        return widget
```

### 6.5 定时执行管理器

```python
# gui/scheduler.py
from PySide6.QtCore import QObject, Signal, QTimer, QDateTime
from apscheduler.schedulers.qt import QtScheduler
from apscheduler.triggers.cron import CronTrigger
from typing import Dict, List, Callable
import json


class ScheduleManager(QObject):
    """定时任务管理器"""

    task_started = Signal(str)  # 任务开始信号
    task_finished = Signal(str, bool)  # 任务完成信号(任务名, 是否成功)
    task_log = Signal(str, str)  # 日志信号(任务名, 日志内容)

    def __init__(self):
        super().__init__()
        self.scheduler = QtScheduler()
        self.tasks: Dict[str, dict] = {}  # 任务配置
        self.test_runner = None  # 当前执行的测试运行器

    def start(self):
        """启动调度器"""
        self.scheduler.start()

    def shutdown(self):
        """关闭调度器"""
        self.scheduler.shutdown()

    def add_task(self, task_name: str, cron_expr: str,
                 testcases: List[str], config: dict):
        """
        添加定时任务

        Args:
            task_name: 任务名称
            cron_expr: Cron表达式 (如 "0 2 * * *" 表示每天凌晨2点)
            testcases: 要执行的测试用例列表
            config: 测试配置
        """
        # 创建Cron触发器
        trigger = CronTrigger.from_crontab(cron_expr)

        # 添加任务
        job = self.scheduler.add_job(
            self._execute_task,
            trigger,
            id=task_name,
            args=[task_name, testcases, config],
            name=task_name
        )

        # 保存任务配置
        self.tasks[task_name] = {
            "cron_expr": cron_expr,
            "testcases": testcases,
            "config": config,
            "job": job,
            "last_run": None,
            "next_run": str(job.next_run_time)
        }

        return True

    def remove_task(self, task_name: str):
        """移除定时任务"""
        if task_name in self.tasks:
            self.scheduler.remove_job(task_name)
            del self.tasks[task_name]

    def _execute_task(self, task_name: str, testcases: List[str], config: dict):
        """执行定时任务"""
        self.task_started.emit(task_name)
        self.task_log.emit(task_name, f"开始执行定时任务: {task_name}")

        try:
            # 创建测试运行器
            from gui.test_runner import TestRunner
            self.test_runner = TestRunner(testcases, config)

            # 连接信号
            self.test_runner.log_signal.connect(
                lambda level, msg: self.task_log.emit(task_name, msg)
            )
            self.test_runner.finished_signal.connect(
                lambda report: self._on_task_finished(task_name, True, report)
            )
            self.test_runner.error_signal.connect(
                lambda err: self._on_task_finished(task_name, False, err)
            )

            # 执行测试
            self.test_runner.start()

        except Exception as e:
            self.task_log.emit(task_name, f"任务执行失败: {str(e)}")
            self.task_finished.emit(task_name, False)

    def _on_task_finished(self, task_name: str, success: bool, result: str):
        """任务完成回调"""
        if success:
            self.task_log.emit(task_name, f"任务执行完成，报告: {result}")
        else:
            self.task_log.emit(task_name, f"任务执行失败: {result}")

        self.task_finished.emit(task_name, success)

        # 更新任务状态
        if task_name in self.tasks:
            self.tasks[task_name]["last_run"] = QDateTime.currentDateTime().toString()
            job = self.tasks[task_name]["job"]
            self.tasks[task_name]["next_run"] = str(job.next_run_time)

    def get_task_list(self) -> List[dict]:
        """获取所有任务列表"""
        result = []
        for name, task in self.tasks.items():
            result.append({
                "name": name,
                "cron_expr": task["cron_expr"],
                "testcases": task["testcases"],
                "last_run": task.get("last_run", "从未执行"),
                "next_run": task.get("next_run", "")
            })
        return result

    def save_tasks(self, filepath: str):
        """保存任务配置到文件"""
        data = []
        for name, task in self.tasks.items():
            data.append({
                "name": name,
                "cron_expr": task["cron_expr"],
                "testcases": task["testcases"],
                "config": task["config"]
            })
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load_tasks(self, filepath: str):
        """从文件加载任务配置"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for task in data:
                self.add_task(
                    task["name"],
                    task["cron_expr"],
                    task["testcases"],
                    task["config"]
                )
        except FileNotFoundError:
            pass  # 文件不存在时忽略
```

### 6.4 测试执行器（多线程）

```python
# gui/test_runner.py
from PySide6.QtCore import QThread, Signal
import subprocess
import json


class TestRunner(QThread):
    """测试执行线程"""

    # 信号定义
    log_signal = Signal(str, str)  # (日志级别, 日志内容)
    progress_signal = Signal(int, int, int, int)  # (总数, 通过, 失败, 跳过)
    finished_signal = Signal(str)  # 报告路径
    error_signal = Signal(str)  # 错误信息

    def __init__(self, testcases: list, config: dict):
        super().__init__()
        self.testcases = testcases
        self.config = config
        self._is_running = True

    def run(self):
        """执行测试"""
        self.log_signal.emit("INFO", f"开始执行 {len(self.testcases)} 个测试用例...")

        # 构建pytest命令
        pytest_cmd = [
            "pytest",
            "-v",
            "--tb=short",
            f"--html=reports/output/report_{self._get_timestamp()}.html",
            "--self-contained-html",
        ]

        # 添加选中的测试用例
        for tc in self.testcases:
            pytest_cmd.append(tc)

        try:
            # 执行pytest
            process = subprocess.Popen(
                pytest_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # 实时读取输出
            for line in process.stdout:
                if not self._is_running:
                    process.terminate()
                    break

                self._parse_output(line)
                self.log_signal.emit("INFO", line.strip())

            process.wait()

            # 测试完成
            self.log_signal.emit("INFO", "测试执行完成")
            self.finished_signal.emit("reports/output/report_xxx.html")

        except Exception as e:
            self.error_signal.emit(str(e))

    def stop(self):
        """停止测试"""
        self._is_running = False

    def _parse_output(self, line: str):
        """解析pytest输出，更新进度"""
        # 解析 PASSED, FAILED, SKIPPED
        pass
```

## 七、测试报告详细设计

### 7.1 报告模板结构 (Jinja2)

```html
<!-- reports/templates/report.html -->
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>爱快路由器4.0自动化测试报告</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary-color: #1890ff;
            --success-color: #52c41a;
            --error-color: #ff4d4f;
            --warning-color: #faad14;
        }
        body { background-color: #f5f5f5; }
        .report-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 0;
            margin-bottom: 30px;
        }
        .stat-card {
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-card.passed { border-left: 4px solid var(--success-color); }
        .stat-card.failed { border-left: 4px solid var(--error-color); }
        .stat-card.skipped { border-left: 4px solid var(--warning-color); }
        .test-step {
            border-left: 3px solid #ddd;
            padding-left: 15px;
            margin: 10px 0;
        }
        .test-step.success { border-left-color: var(--success-color); }
        .test-step.failed { border-left-color: var(--error-color); }
        .screenshot {
            max-width: 100%;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin: 10px 0;
        }
        .module-section {
            margin-bottom: 30px;
        }
        .testcase-item {
            background: white;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .testcase-header {
            padding: 15px;
            border-bottom: 1px solid #eee;
            cursor: pointer;
        }
        .testcase-body {
            padding: 15px;
            display: none;
        }
        .testcase-body.show { display: block; }
    </style>
</head>
<body>
    <!-- 报告头部 -->
    <div class="report-header">
        <div class="container">
            <h1>爱快路由器4.0 自动化测试报告</h1>
            <p class="mb-0">生成时间: {{ report_time }}</p>
        </div>
    </div>

    <div class="container">
        <!-- 测试概要 -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="card-body text-center">
                        <h3>{{ summary.total }}</h3>
                        <small class="text-muted">总计用例</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card passed">
                    <div class="card-body text-center">
                        <h3 class="text-success">{{ summary.passed }}</h3>
                        <small class="text-muted">通过</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card failed">
                    <div class="card-body text-center">
                        <h3 class="text-danger">{{ summary.failed }}</h3>
                        <small class="text-muted">失败</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card skipped">
                    <div class="card-body text-center">
                        <h3 class="text-warning">{{ summary.skipped }}</h3>
                        <small class="text-muted">跳过</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- 设备信息 -->
        <div class="card mb-4">
            <div class="card-header">测试环境</div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>设备IP:</strong> {{ device.ip }}</p>
                        <p><strong>用户名:</strong> {{ device.username }}</p>
                        <p><strong>系统版本:</strong> {{ device.version }}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>开始时间:</strong> {{ start_time }}</p>
                        <p><strong>结束时间:</strong> {{ end_time }}</p>
                        <p><strong>执行耗时:</strong> {{ duration }}</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- 图表统计 -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">测试结果分布</div>
                    <div class="card-body">
                        <canvas id="resultChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">各模块通过率</div>
                    <div class="card-body">
                        <canvas id="moduleChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- 测试详情 -->
        <div class="card">
            <div class="card-header">
                <h4 class="mb-0">测试用例详情</h4>
            </div>
            <div class="card-body">
                {% for module in modules %}
                <div class="module-section">
                    <h5 class="mb-3">
                        <span class="badge bg-primary">{{ module.name }}</span>
                        <small class="text-muted ms-2">
                            通过: {{ module.passed }}/{{ module.total }}
                        </small>
                    </h5>

                    {% for testcase in module.testcases %}
                    <div class="testcase-item">
                        <div class="testcase-header"
                             onclick="toggleTestcase('{{ testcase.id }}')">
                            <span class="badge
                                {% if testcase.status == 'passed' %}bg-success
                                {% elif testcase.status == 'failed' %}bg-danger
                                {% else %}bg-warning{% endif %}">
                                {{ testcase.status|upper }}
                            </span>
                            <span class="ms-2">{{ testcase.name }}</span>
                            <span class="float-end text-muted">
                                {{ testcase.duration }}s
                            </span>
                        </div>
                        <div class="testcase-body" id="{{ testcase.id }}">
                            <!-- 测试步骤 -->
                            <h6>测试步骤:</h6>
                            {% for step in testcase.steps %}
                            <div class="test-step {{ step.status }}">
                                <strong>步骤 {{ loop.index }}:</strong> {{ step.action }}
                                <br>
                                <small class="text-muted">
                                    预期: {{ step.expected }} |
                                    实际: {{ step.actual }}
                                </small>
                            </div>
                            {% endfor %}

                            <!-- 失败信息 -->
                            {% if testcase.status == 'failed' %}
                            <div class="alert alert-danger mt-3">
                                <strong>错误信息:</strong><br>
                                <pre>{{ testcase.error_message }}</pre>
                            </div>

                            <!-- 截图 -->
                            {% if testcase.screenshot %}
                            <div class="mt-3">
                                <h6>失败截图:</h6>
                                <img src="{{ testcase.screenshot }}"
                                     class="screenshot"
                                     alt="失败截图">
                            </div>
                            {% endif %}
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% endfor %}
            </div>
        </div>
    </div>

    <script>
        // 结果分布饼图
        new Chart(document.getElementById('resultChart'), {
            type: 'doughnut',
            data: {
                labels: ['通过', '失败', '跳过'],
                datasets: [{
                    data: [{{ summary.passed }}, {{ summary.failed }}, {{ summary.skipped }}],
                    backgroundColor: ['#52c41a', '#ff4d4f', '#faad14']
                }]
            }
        });

        // 模块通过率柱状图
        new Chart(document.getElementById('moduleChart'), {
            type: 'bar',
            data: {
                labels: [{% for m in modules %}'{{ m.name }}'{% if not loop.last %},{% endif %}{% endfor %}],
                datasets: [{
                    label: '通过率 %',
                    data: [{% for m in modules %}{{ m.pass_rate }}{% if not loop.last %},{% endif %}{% endfor %}],
                    backgroundColor: '#1890ff'
                }]
            },
            options: {
                scales: { y: { beginAtZero: true, max: 100 } }
            }
        });

        function toggleTestcase(id) {
            document.getElementById(id).classList.toggle('show');
        }
    </script>
</body>
</html>
```

### 7.2 报告生成器

```python
# utils/report_generator.py
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from typing import Dict, List, Any
import json


class ReportGenerator:
    """测试报告生成器"""

    def __init__(self, template_dir: str = "reports/templates"):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate(self, test_results: Dict[str, Any], output_path: str):
        """
        生成测试报告

        Args:
            test_results: 测试结果数据
            output_path: 输出文件路径
        """
        template = self.env.get_template("report.html")

        # 准备模板数据
        context = {
            "report_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": test_results.get("summary", {}),
            "device": test_results.get("device", {}),
            "start_time": test_results.get("start_time", ""),
            "end_time": test_results.get("end_time", ""),
            "duration": test_results.get("duration", ""),
            "modules": test_results.get("modules", [])
        }

        # 渲染模板
        html_content = template.render(**context)

        # 写入文件
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path


# pytest钩子函数收集测试数据
# conftest.py
import pytest
from utils.report_generator import ReportGenerator


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """收集每个测试用例的结果"""
    outcome = yield
    report = outcome.get_result()

    if call.when == "call":
        # 记录测试步骤和结果
        test_data = {
            "name": item.name,
            "status": "passed" if report.passed else "failed" if report.failed else "skipped",
            "duration": call.duration,
            "steps": getattr(item, "_test_steps", []),
            "error_message": str(call.excinfo.value) if call.excinfo else None
        }

        # 失败时截图
        if report.failed:
            page = item.funcargs.get("page")
            if page:
                screenshot_path = f"reports/screenshots/{item.name}.png"
                page.screenshot(path=screenshot_path)
                test_data["screenshot"] = screenshot_path

        # 保存到item对象
        item._test_data = test_data


def pytest_sessionfinish(session, exitstatus):
    """测试会话结束时生成报告"""
    # 收集所有测试数据并生成报告
    pass
```

### 7.3 测试步骤装饰器

```python
# utils/test_step.py
from functools import wraps
from typing import Callable, List


def step(description: str):
    """
    测试步骤装饰器，记录每个步骤的执行情况

    用法:
        @step("登录系统")
        def login(page, username, password):
            page.fill("#username", username)
            page.fill("#password", password)
            page.click("#login")
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            step_data = {
                "action": description,
                "status": "pending",
                "expected": "",
                "actual": "",
                "error": None
            }

            try:
                result = func(*args, **kwargs)
                step_data["status"] = "success"
                return result
            except Exception as e:
                step_data["status"] = "failed"
                step_data["error"] = str(e)
                raise
            finally:
                # 记录步骤到当前测试
                if args and hasattr(args[0], '_current_steps'):
                    args[0]._current_steps.append(step_data)

        return wrapper
    return decorator


# 使用示例
class TestVlan:
    _current_steps = []

    @step("导航到VLAN设置页面")
    def navigate_to_vlan(self, page):
        page.get_by_role("menuitem", name="网络配置").click()
        page.get_by_role("menuitem", name="VLAN设置").click()

    @step("添加VLAN配置")
    def add_vlan(self, page, vlan_id, vlan_name):
        page.get_by_role("button", name="添加").click()
        page.get_by_role("textbox", name="vlanID *").fill(vlan_id)
        page.get_by_role("textbox", name="vlan名称 *").fill(vlan_name)
        page.get_by_role("button", name="保存").click()

    def test_add_vlan_success(self, page):
        """测试添加VLAN成功"""
        self.navigate_to_vlan(page)
        self.add_vlan(page, "100", "vlan_test_100")

        # 验证VLAN存在
        assert page.locator("text=vlan_test_100").is_visible()
```

## 八、实现步骤

### Phase 1: 基础框架搭建
1. 创建项目目录结构
2. 编写配置管理模块
3. 实现基础页面类
4. 实现登录页面和测试

### Phase 2: VLAN测试实现
1. 实现VLAN页面类
2. 编写所有VLAN测试用例
3. 准备测试数据文件
4. 调试测试用例

### Phase 3: 报告系统
1. 设计Jinja2报告模板
2. 实现报告生成器
3. 集成截图功能
4. 添加图表统计

### Phase 4: GUI开发
1. 实现主窗口界面
2. 实现配置对话框
3. 实现测试执行器(多线程)
4. 实现日志实时显示
5. 实现报告查看功能

### Phase 5: 整合测试
1. GUI与测试框架集成
2. 端到端测试
3. 优化和Bug修复

## 九、验证方案

1. **单元测试验证**: 运行单个测试用例，验证通过
2. **模块测试验证**: 运行VLAN模块所有测试用例
3. **GUI验证**: 通过GUI选择测试用例并执行
4. **报告验证**: 检查生成的测试报告内容完整性

## 十、代码生成策略

### 10.1 Playwright操作录制方案

采用边操作边生成Python代码的方式：

1. **手动操作录制**
   - 通过MCP Playwright操作路由器页面
   - 同步记录每个操作步骤
   - 将操作转换为Page Object模式的Python代码

2. **代码生成规则**
   - 每个页面操作封装成方法
   - 使用明确的定位器(by role, by text)
   - 添加等待机制确保稳定性
   - 添加注释说明操作目的

3. **示例：添加VLAN操作转换**

Playwright操作记录:
```js
await page.getByRole('button', { name: '添加' }).click();
await page.getByRole('textbox', { name: 'vlanID *' }).fill('100');
await page.getByRole('textbox', { name: 'vlan名称 *' }).fill('test_vlan');
await page.getByRole('button', { name: '保存' }).click();
```

转换后的Python代码 (pages/network/vlan_page.py):
```python
class VlanPage(BasePage):
    def add_vlan(self, vlan_id: str, vlan_name: str, **kwargs):
        """添加VLAN配置"""
        self.page.get_by_role("button", name="添加").click()
        self.page.get_by_role("textbox", name="vlanID *").fill(vlan_id)
        self.page.get_by_role("textbox", name="vlan名称 *").fill(vlan_name)
        # 可选字段
        if "mac" in kwargs:
            self.page.get_by_role("textbox", name="MAC").fill(kwargs["mac"])
        if "ip" in kwargs:
            self.page.get_by_role("textbox", name="IP").fill(kwargs["ip"])
        self.page.get_by_role("button", name="保存").click()
        return self
```

### 10.2 完整的VLAN页面操作代码示例

基于Playwright操作记录转换的Python代码：

```python
# pages/network/vlan_page.py
from playwright.sync_api import Page, Locator
from typing import Optional, List


class VlanPage:
    """VLAN设置页面操作类"""

    def __init__(self, page: Page):
        self.page = page

    # ==================== 导航 ====================
    def navigate_to_vlan_settings(self):
        """导航到VLAN设置页面"""
        self.page.get_by_role("menuitem", name="网络配置").click()
        self.page.get_by_role("menuitem", name="VLAN设置").click()
        return self

    # ==================== 添加VLAN ====================
    def click_add_button(self):
        """点击添加按钮"""
        self.page.get_by_role("button", name="添加").click()
        return self

    def fill_vlan_id(self, vlan_id: str):
        """填写VLAN ID"""
        self.page.get_by_role("textbox", name="vlanID *").fill(vlan_id)
        return self

    def fill_vlan_name(self, name: str):
        """填写VLAN名称（必须以vlan开头）"""
        self.page.get_by_role("textbox", name="vlan名称 *").fill(name)
        return self

    def fill_mac(self, mac: str):
        """填写MAC地址"""
        self.page.get_by_role("textbox", name="MAC").fill(mac)
        return self

    def fill_ip(self, ip: str):
        """填写IP地址"""
        self.page.get_by_role("textbox", name="IP").fill(ip)
        return self

    def select_subnet_mask(self, mask: str):
        """选择子网掩码"""
        self.page.locator("div").filter(has_text="子网掩码").first.click()
        self.page.get_by_text(mask).click()
        return self

    def fill_remark(self, remark: str):
        """填写备注"""
        self.page.get_by_role("textbox", name="备注").fill(remark)
        return self

    def click_save(self):
        """点击保存按钮"""
        self.page.get_by_role("button", name="保存").click()
        return self

    def click_cancel(self):
        """点击取消按钮"""
        self.page.get_by_role("button", name="取消").click()
        return self

    def add_vlan(self, vlan_id: str, vlan_name: str,
                 mac: Optional[str] = None,
                 ip: Optional[str] = None,
                 subnet_mask: Optional[str] = None,
                 remark: Optional[str] = None) -> bool:
        """
        添加VLAN的完整流程

        Args:
            vlan_id: VLAN ID (1-4090)
            vlan_name: VLAN名称（必须以vlan开头）
            mac: MAC地址（可选）
            ip: IP地址（可选）
            subnet_mask: 子网掩码（可选）
            remark: 备注（可选）

        Returns:
            是否添加成功
        """
        self.click_add_button()
        self.fill_vlan_id(vlan_id)
        self.fill_vlan_name(vlan_name)

        if mac:
            self.fill_mac(mac)
        if ip:
            self.fill_ip(ip)
        if subnet_mask:
            self.select_subnet_mask(subnet_mask)
        if remark:
            self.fill_remark(remark)

        self.click_save()

        # 等待成功提示或错误提示
        try:
            self.page.wait_for_selector("text=操作成功", timeout=5000)
            return True
        except:
            return False

    # ==================== 启用/停用VLAN ====================
    def disable_vlan(self, vlan_name: str) -> bool:
        """停用指定VLAN"""
        # 找到对应VLAN行的停用按钮
        row = self.page.locator("tr").filter(has_text=vlan_name)
        row.get_by_role("button", name="停用").click()

        # 确认停用
        self.page.get_by_role("button", name="确定").click()

        # 等待成功提示
        try:
            self.page.wait_for_selector("text=停用成功", timeout=5000)
            return True
        except:
            return False

    def enable_vlan(self, vlan_name: str) -> bool:
        """启用指定VLAN"""
        row = self.page.locator("tr").filter(has_text=vlan_name)
        row.get_by_role("button", name="启用").click()

        self.page.get_by_role("button", name="确定").click()

        try:
            self.page.wait_for_selector("text=启用成功", timeout=5000)
            return True
        except:
            return False

    # ==================== 批量操作 ====================
    def select_vlan(self, vlan_name: str):
        """勾选指定VLAN"""
        row = self.page.locator("tr").filter(has_text=vlan_name)
        row.locator("input[type='checkbox']").click()
        return self

    def select_all_vlans(self):
        """全选所有VLAN"""
        self.page.get_by_role("checkbox", name="Select all").click()
        return self

    def batch_enable(self):
        """批量启用选中的VLAN"""
        self.page.get_by_role("button", name="启用").first.click()
        self.page.get_by_role("button", name="确定").click()
        return self

    def batch_disable(self):
        """批量停用选中的VLAN"""
        self.page.get_by_role("button", name="停用").first.click()
        self.page.get_by_role("button", name="确定").click()
        return self

    def batch_delete(self):
        """批量删除选中的VLAN"""
        self.page.get_by_role("button", name="删除").first.click()
        self.page.get_by_role("button", name="确定").click()
        return self

    # ==================== 编辑/删除 ====================
    def edit_vlan(self, vlan_name: str):
        """点击编辑指定VLAN"""
        row = self.page.locator("tr").filter(has_text=vlan_name)
        row.get_by_role("button", name="编辑").click()
        return self

    def delete_vlan(self, vlan_name: str) -> bool:
        """删除指定VLAN"""
        row = self.page.locator("tr").filter(has_text=vlan_name)
        row.get_by_role("button", name="删除").click()

        # 确认删除
        self.page.get_by_role("button", name="确定").click()

        try:
            self.page.wait_for_selector("text=删除成功", timeout=5000)
            return True
        except:
            return False

    # ==================== 搜索/查询 ====================
    def search_vlan(self, keyword: str):
        """搜索VLAN"""
        self.page.get_by_role("textbox", name="请输入搜索内容").fill(keyword)
        self.page.locator("img").filter(has_text="search").click()
        return self

    def clear_search(self):
        """清空搜索"""
        self.page.get_by_role("textbox", name="请输入搜索内容").clear()
        return self

    # ==================== 导入/导出 ====================
    def click_import(self):
        """点击导入按钮"""
        self.page.get_by_role("button", name="导入").click()
        return self

    def click_export(self):
        """点击导出按钮"""
        self.page.get_by_role("button", name="导出").click()
        return self

    def upload_import_file(self, file_path: str):
        """上传导入文件"""
        self.click_import()
        # 处理文件上传对话框
        with self.page.expect_file_chooser() as fc_info:
            self.page.click("input[type='file']")
        file_chooser = fc_info.value
        file_chooser.set_files(file_path)
        return self

    # ==================== 状态验证 ====================
    def is_vlan_enabled(self, vlan_name: str) -> bool:
        """检查VLAN是否启用"""
        row = self.page.locator("tr").filter(has_text=vlan_name)
        # 启用状态有play-circle图标
        return row.locator("img[alt='play-circle']").count() > 0

    def is_vlan_disabled(self, vlan_name: str) -> bool:
        """检查VLAN是否停用"""
        row = self.page.locator("tr").filter(has_text=vlan_name)
        # 停用状态有minus-circle图标
        return row.locator("img[alt='minus-circle']").count() > 0

    def vlan_exists(self, vlan_name: str) -> bool:
        """检查VLAN是否存在"""
        return self.page.locator(f"text={vlan_name}").count() > 0

    def get_vlan_count(self) -> int:
        """获取VLAN数量"""
        count_text = self.page.locator("text=/共 \\d+ 条/").inner_text()
        return int(count_text.replace("共 ", "").replace(" 条", ""))

    # ==================== 扩展IP操作 ====================
    def add_extended_ip(self, ip: str, subnet_mask: str = "255.255.255.0"):
        """
        添加扩展IP（在添加/编辑VLAN页面）

        Args:
            ip: 扩展IP地址
            subnet_mask: 子网掩码
        """
        # 点击扩展IP区域的添加按钮
        self.page.get_by_role("button", name="添加").nth(1).click()  # 第二个添加按钮是扩展IP

        # 填写扩展IP
        ip_inputs = self.page.locator("input[placeholder*='IP']")
        last_ip_input = ip_inputs.last
        last_ip_input.fill(ip)

        return self

    def remove_extended_ip(self, index: int):
        """
        删除指定索引的扩展IP

        Args:
            index: 扩展IP索引（从0开始）
        """
        ext_ip_rows = self.page.locator(".extended-ip-item")  # 假设扩展IP行的类名
        if index < ext_ip_rows.count():
            ext_ip_rows.nth(index).locator("button").click()
        return self

    def get_extended_ip_count(self) -> int:
        """获取扩展IP数量"""
        return self.page.locator(".extended-ip-item").count()

    # ==================== 批量操作增强 ====================
    def batch_enable_with_confirm(self, vlan_names: List[str]):
        """
        批量启用指定名称的VLAN

        Args:
            vlan_names: VLAN名称列表
        """
        for name in vlan_names:
            self.select_vlan(name)

        # 点击批量启用按钮
        self.page.get_by_role("button", name="启用").first.click()

        # 确认操作
        self.page.get_by_role("button", name="确定").click()

        return self

    def batch_disable_with_confirm(self, vlan_names: List[str]):
        """
        批量停用指定名称的VLAN

        Args:
            vlan_names: VLAN名称列表
        """
        for name in vlan_names:
            self.select_vlan(name)

        self.page.get_by_role("button", name="停用").first.click()
        self.page.get_by_role("button", name="确定").click()

        return self

    def batch_delete_with_confirm(self, vlan_names: List[str]):
        """
        批量删除指定名称的VLAN

        Args:
            vlan_names: VLAN名称列表
        """
        for name in vlan_names:
            self.select_vlan(name)

        self.page.get_by_role("button", name="删除").first.click()
        self.page.get_by_role("button", name="确定").click()

        return self

    def get_selected_count(self) -> int:
        """获取当前选中的VLAN数量"""
        selected_text = self.page.locator("text=/已选 \\d+ 条/")
        if selected_text.count() > 0:
            text = selected_text.first.inner_text()
            return int(text.replace("已选 ", "").replace(" 条", ""))
        return 0
```

## 十一、持续开发策略(解决上下文超出问题)

### 11.1 项目文档体系

为确保长期开发时能快速恢复上下文，建立以下文档体系：

```
4.0前端UI自动化测试/
├── docs/                           # 项目文档
│   ├── README.md                   # 项目总览和快速开始
│   ├── CHANGELOG.md                # 开发日志(每日更新)
│   ├── PROGRESS.md                 # 开发进度追踪
│   ├── ARCHITECTURE.md             # 架构设计文档
│   └── MODULES/                    # 模块文档
│       ├── vlan.md                 # VLAN模块测试文档
│       └── ...
└── .context/                       # 上下文恢复文件
    ├── current_task.md             # 当前任务描述
    ├── next_steps.md               # 下一步计划
    └── session_summary.md          # 会话摘要模板
```

### 11.2 每次开发结束前记录

在每次开发会话结束前，更新以下文件：

**CHANGELOG.md 格式:**
```markdown
## 2024-XX-XX
### 完成
- [x] 实现VLAN添加功能测试
- [x] 完成VlanPage页面对象类

### 进行中
- [ ] VLAN编辑功能测试(50%)

### 问题
- 发现VLAN ID重复时提示信息需要验证

### 下次继续
- 完成VLAN删除测试
- 开始导入导出测试
```

### 11.3 新会话恢复流程

每次开始新会话时：
1. 读取 `docs/PROGRESS.md` 了解整体进度
2. 读取 `docs/CHANGELOG.md` 了解最近变更
3. 读取 `.context/current_task.md` 了解当前任务
4. 继续开发

### 11.4 代码自文档化

1. **详细的docstring**: 每个类和方法都有完整说明
2. **类型注解**: 使用Python类型提示
3. **内联注释**: 复杂逻辑添加解释
4. **测试步骤记录**: 每个测试用例记录操作步骤

### 11.5 会话摘要模板

```markdown
# 会话摘要 - YYYY-MM-DD

## 本次完成的工作
1.
2.

## 代码变更文件
- `pages/network/vlan_page.py`: 新增XX方法
- `tests/network/test_vlan.py`: 新增XX测试用例

## 遗留问题
1.
2.

## 下次计划
1.
2.
```

## 十二、项目目录(最终确认)

```
C:\Users\51355\Desktop\4.0前端UI自动化测试\
├── config/                     # 配置文件
├── pages/                      # 页面对象模型
├── tests/                      # 测试用例
├── utils/                      # 工具类
├── reports/                    # 测试报告
├── gui/                        # GUI界面
├── test_data/                  # 测试数据
├── docs/                       # 项目文档(上下文恢复)
│   ├── README.md
│   ├── CHANGELOG.md
│   ├── PROGRESS.md
│   └── MODULES/
├── .context/                   # 上下文文件
└── requirements.txt
```

## 十三、已确认的问题

1. ~~VLAN设置页面是否有"启用/停用"功能？~~ **已确认：有此功能，添加数据后操作列显示启用/停用按钮**
2. ~~是否需要测试VLAN与线路的关联关系？~~ **需要测试**
3. ~~测试报告是否需要支持历史记录对比？~~ **暂不需要**
4. ~~GUI是否需要支持定时执行测试？~~ **已添加定时任务功能**
5. ~~测试数据是否需要在测试前备份、测试后恢复？~~ **不需要备份恢复**
6. ~~上下文恢复策略是否满足需求？~~ **已建立文档体系**

## 十四、待确认问题

1. 是否需要支持远程执行(通过SSH连接设备执行)？
2. 是否需要测试VLAN与线路的关联关系（选择不同线路进行测试）？
