# 爱快路由器4.0自动化测试框架

基于Playwright + Pytest + PySide6的UI自动化测试框架

## 项目结构

```
4.0前端UI自动化测试/
├── config/                     # 配置文件
│   ├── config.py              # 配置类定义
│   └── settings.yaml          # 配置文件
├── pages/                      # 页面对象模型(POM)
│   ├── base_page.py           # 基础页面类
│   ├── login_page.py          # 登录页面
│   └── network/               # 网络配置模块
│       └── vlan_page.py       # VLAN设置页面
├── tests/                      # 测试用例
│   ├── conftest.py            # pytest fixtures
│   └── network/               # 网络配置测试
│       ├── test_vlan.py       # VLAN基础测试
│       └── test_vlan_comprehensive.py  # VLAN综合测试
├── utils/                      # 工具类
│   └── logger.py              # 日志工具
├── reports/                    # 测试报告
├── gui/                        # GUI界面
│   ├── main_window.py         # 主窗口
│   ├── config_dialog.py       # 配置对话框
│   ├── test_runner.py         # 测试执行器
│   └── scheduler.py           # 定时任务
├── test_data/                  # 测试数据
│   └── exports/               # 导出文件目录
│       └── vlan/              # VLAN导出文件
├── docs/                       # 项目文档
│   ├── README.md              # 项目说明
│   ├── PLAN.md                # 测试计划
│   ├── CHANGELOG.md           # 开发日志
│   └── PROGRESS.md            # 开发进度
├── requirements.txt            # 依赖包
├── pytest.ini                 # pytest配置
├── run_tests.py               # 命令行运行入口
└── main.py                    # GUI入口
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
playwright install chromium
```

### 2. 配置设备

编辑 `config/settings.yaml`:

```yaml
device:
  ip: "10.66.0.150"
  username: "admin"
  password: "admin123"
```

### 3. 运行测试

```bash
# 运行VLAN综合测试（推荐）
pytest tests/network/test_vlan_comprehensive.py -v

# 运行所有VLAN测试
pytest tests/network/test_vlan.py -v

# 运行单个测试
pytest tests/network/test_vlan.py::TestVlanAdd::test_add_min_vlan_id -v

# 运行带标记的测试
pytest -m vlan -v
```

## 测试用例

### VLAN设置模块

#### 综合测试 (test_vlan_comprehensive.py)
一次测试覆盖所有VLAN功能：
- **添加VLAN**: 8种数据组合场景
  - 普通ID + 最少信息
  - 最大ID (4090) + 最少信息
  - 有MAC无IP
  - 无MAC有IP
  - MAC + IP
  - MAC + IP + 备注
  - MAC + IP + 扩展IP
  - 完整信息
- **编辑VLAN**: 修改名称
- **停用/启用**: 单个操作
- **删除VLAN**: 单个删除
- **搜索测试**: 存在/不存在/清空
- **导出测试**: CSV和TXT两种格式
- **异常测试**:
  - MAC地址格式验证
  - IP地址格式验证
  - VLAN名称格式验证
  - VLAN ID范围验证
  - VLAN ID冲突检测
  - 扩展IP格式验证
- **批量操作**: 批量停用、批量启用、批量删除
- **导入测试**: CSV导入、TXT导入（带清空选项）

详细测试用例见 `docs/PLAN.md`

## 开发指南

### 添加新的页面对象

1. 在 `pages/` 下创建新的页面类
2. 继承 `BasePage`
3. 封装页面操作方法

### 添加新的测试用例

1. 在 `tests/` 下创建测试文件
2. 使用 `pytest` 标记
3. 使用 `conftest.py` 中的 fixtures

## 文档

- [PLAN.md](PLAN.md) - 完整测试计划
- [CHANGELOG.md](CHANGELOG.md) - 开发日志
- [PROGRESS.md](PROGRESS.md) - 开发进度

## 许可

内部测试项目
