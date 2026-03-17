# 爱快路由器4.0自动化测试框架

基于 Playwright + Pytest + PySide6 的UI自动化测试框架，支持SSH后台验证的全链路测试。

## 项目结构

```
4.0前端UI自动化测试/
├── config/                     # 配置管理
│   ├── config.py              # 配置数据类（DeviceConfig, BrowserConfig, SSHConfig等）
│   └── settings.yaml          # YAML配置文件
├── pages/                      # 页面对象模型(POM)
│   ├── base_page.py           # 基础页面类（导航、等待、Toast检测、帮助测试）
│   ├── login_page.py          # 登录页面
│   └── network/               # 网络配置模块
│       ├── vlan_page.py       # VLAN设置页面
│       ├── ip_rate_limit_page.py   # IP限速页面
│       └── mac_rate_limit_page.py  # MAC限速页面
├── tests/                      # 测试用例
│   ├── conftest.py            # pytest fixtures（登录、SSH、报告、步骤记录）
│   └── network/               # 网络配置测试
│       ├── test_vlan.py                    # VLAN基础测试
│       ├── test_vlan_comprehensive.py      # VLAN综合测试（16步）
│       ├── test_ip_rate_limit_comprehensive.py   # IP限速综合测试（18步+SSH验证）
│       ├── test_ip_rate_limit_full_chain.py      # IP限速全链路测试（UI+SSH+iperf3）
│       └── test_mac_rate_limit_comprehensive.py  # MAC限速综合测试（18步+SSH验证）
├── utils/                      # 工具类
│   ├── backend_verifier.py    # SSH后台验证器（L1-L5多层验证）
│   ├── step_recorder.py       # 测试步骤记录器
│   ├── report_generator.py    # Jinja2中文HTML报告生成器
│   └── logger.py              # 日志工具
├── gui/                        # PySide6 桌面GUI
│   ├── main_window.py         # 主窗口（设备配置、模块选择、环境健康检查）
│   ├── config_dialog.py       # 配置对话框（含SSH配置Tab）
│   ├── test_runner.py         # 多线程测试执行器（SSH环境变量传递）
│   ├── scheduler.py           # APScheduler定时任务
│   └── gui_resources/
│       └── styles.qss         # Qt样式表
├── test_data/                  # 测试数据
│   ├── exports/               # 导出文件
│   │   ├── vlan/              # VLAN导出(CSV/TXT)
│   │   ├── ip_rate_limit/     # IP限速导出(CSV/TXT)
│   │   └── mac_rate_limit/    # MAC限速导出(CSV/TXT)
│   └── vlan/                  # VLAN导入数据
├── reports/                    # 测试报告
│   ├── templates/
│   │   └── report_template.html  # Jinja2报告模板
│   ├── output/                # HTML报告输出
│   └── allure-results/        # Allure报告数据
├── docs/                       # 项目文档
│   ├── README.md              # 项目说明（本文件）
│   ├── PLAN.md                # 测试计划
│   ├── CHANGELOG.md           # 开发日志
│   ├── PROGRESS.md            # 开发进度
│   ├── 终端限速测试用例.md      # 终端限速详细用例
│   └── AI赋能测试效率提升方案.md # AI赋能测试方案
├── requirements.txt            # Python依赖
├── pytest.ini                 # pytest配置
├── run_tests.py               # 命令行运行入口
└── main.py                    # GUI入口
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
playwright install chromium

# SSH后台验证（可选）
pip install paramiko
```

### 2. 配置设备

编辑 `config/settings.yaml`:

```yaml
device:
  ip: "10.66.0.150"
  username: "admin"
  password: "admin123"

ssh:
  host: "10.66.0.150"
  port: 22
  username: "sshd"
  password: "ikuai8.com"
```

### 3. 运行测试

```bash
# 运行IP限速综合测试（含SSH后台验证）
pytest tests/network/test_ip_rate_limit_comprehensive.py -v

# 运行MAC限速综合测试
pytest tests/network/test_mac_rate_limit_comprehensive.py -v

# 运行VLAN综合测试
pytest tests/network/test_vlan_comprehensive.py -v

# 运行IP限速全链路测试（UI + SSH + iperf3）
pytest tests/network/test_ip_rate_limit_full_chain.py -v

# 运行所有网络模块测试
pytest tests/network/ -v

# 指定SSH配置运行（环境变量方式）
SSH_HOST=10.66.0.150 SSH_USERNAME=sshd SSH_PASSWORD=ikuai8.com pytest tests/network/test_ip_rate_limit_comprehensive.py -v
```

### 4. 启动GUI

```bash
python main.py
```

## 测试模块

### VLAN设置 (test_vlan_comprehensive.py)
16步综合测试 + SSH后台验证：
- 添加8条VLAN → 编辑 → 停用 → 启用 → 删除 → 搜索 → 排序 → 导出 → 异常输入 → 批量停用 → 批量启用 → 批量删除 → 导入 → 帮助
- SSH三级验证：L1数据库(`vlan show`) → L2网络接口(`ip link show`) → L3 proc(`/proc/net/vlan/config`)

### IP限速 (test_ip_rate_limit_comprehensive.py)
18步综合测试 + SSH后台验证：
- 添加8条规则（覆盖单IP/IP段/CIDR/多IP/时间计划/协议端口等场景）
- 每条规则添加后自动SSH验证：L1数据库 → L2 iptables → L3 ipset → L4内核
- 编辑/停用/启用/删除后SSH验证数据库状态一致性
- 搜索/排序/导出/异常输入/批量操作/导入/帮助

### MAC限速 (test_mac_rate_limit_comprehensive.py)
18步综合测试 + SSH后台验证：
- 添加8条规则（覆盖单MAC/多MAC/时间计划/协议端口等场景）
- SSH后台验证（兼容mac_qos和dt_mac_qos两种表结构）
- 同IP限速的完整操作覆盖

### IP限速全链路 (test_ip_rate_limit_full_chain.py)
前端UI + SSH后台 + iperf3实测的端到端验证

## SSH后台验证架构

```
BackendVerifier (utils/backend_verifier.py)
├── IP限速/MAC限速验证
│   ├── L1: verify_qos_database()      # 数据库字段验证
│   ├── L2: verify_iptables_rules()    # iptables规则验证(IP_QOS/MAC_QOS链)
│   ├── L3: verify_ipset_membership()  # ipset IP成员验证
│   ├── L4: verify_kernel_module()     # ik_core内核模块+dmesg
│   └── L5: verify_bandwidth()         # iperf3带宽实测
├── VLAN验证
│   ├── L1: verify_vlan_database()     # 数据库字段验证(vlan show)
│   ├── L2: verify_vlan_interface()    # 网络接口验证(ip link show)
│   └── L3: verify_vlan_proc()         # proc验证(/proc/net/vlan/config)
└── SSH连接管理
    ├── 自动重连(transport.is_active()检查)
    └── exec重试(失败重连后重试一次)
```

设计原则：
- **优雅降级**：未安装paramiko或SSH连接失败时，自动跳过SSH验证
- **选择性断言**：关键验证点（L1数据库、L4内核、停用/启用/删除/批量操作）使用`must_pass=True`，失败收集到`ssh_failures`列表，测试末尾统一`assert`
- **不中断UI流程**：SSH验证失败不会中断测试执行，所有UI步骤完成后再统一判定
- **动态fixture注入**：`request.getfixturevalue('backend_verifier')` 按需获取
- **三模块统一SSH验证**：VLAN、IP限速、MAC限速使用相同的SSH验证模式

### SSH注意事项

- iKuai固件升级会重置`/etc/passwd`中sshd的shell为`/etc/setup/rc`（交互式菜单），导致SSH exec_command超时
- 已部署持久化修复脚本：`/etc/mnt/ikuai/fix_sshd_shell.sh`（位于`/dev/sda3`独立分区，升级后保留）
- Cron每分钟自动检查并修复，固件升级后最多1分钟自动恢复SSH
- 如升级后cron也被重置，需手动执行一次：`bash /etc/mnt/ikuai/fix_sshd_shell.sh`

## 测试环境

### 网络拓扑
```
路由器(10.66.0.150) ← Web: admin/admin123, SSH: sshd/ikuai8.com (root权限)
    ├── LAN1(ens11) → Ubuntu客户端(外网10.66.0.18, 内网192.168.148.2) SSH: iktest/iktest
    └── WAN → iperf3 Server(10.66.0.40:5201)
```

### 设备账号信息

| 设备 | IP | 协议 | 用户名 | 密码 | 备注 |
|------|------|------|------|------|------|
| 路由器 | 10.66.0.150 | Web | admin | admin123 | 管理后台 |
| 路由器 | 10.66.0.150 | SSH(22) | sshd | ikuai8.com | root权限(uid=0) |
| Ubuntu客户端 | 10.66.0.18 | SSH(22) | iktest | iktest | 内网IP: 192.168.148.2 |
| iperf3服务端 | 10.66.0.40 | iperf3(5201) | - | - | 测速服务器 |

## 开发指南

### 添加新模块测试

1. 在 `pages/network/` 下创建Page Object类，继承 `BasePage`
2. 在 `tests/network/` 下创建综合测试文件，参考14步测试模式
3. 在 `test_data/exports/<module>/` 下准备导入导出测试数据
4. （可选）在测试中集成SSH后台验证

### 14步综合测试模式

```
Step 1-8:  新增8条规则（不同参数组合覆盖）
Step 9:    编辑规则
Step 10:   停用规则
Step 11:   启用规则
Step 12:   删除单条
Step 13:   搜索测试
Step 14:   排序测试
Step 15:   导出测试（CSV/TXT）
Step 16:   异常输入测试
Step 17:   批量停用
Step 18:   批量启用
Step 19:   批量删除
Step 20:   导入测试（CSV/TXT）
Step 21:   帮助功能
```

## 技术栈

| 组件 | 技术 | 版本 |
|------|------|------|
| Web自动化 | Playwright | >= 1.40.0 |
| 测试框架 | pytest | >= 7.4.0 |
| GUI | PySide6 | >= 6.6.0 |
| SSH验证 | paramiko | (可选) |
| 报告 | Jinja2 | >= 3.1.0 |
| 定时任务 | APScheduler | >= 3.10.0 |
| 数据处理 | pandas | >= 2.1.0 |

## 文档

- [PLAN.md](PLAN.md) - 完整测试计划
- [CHANGELOG.md](CHANGELOG.md) - 开发日志
- [PROGRESS.md](PROGRESS.md) - 开发进度
- [终端限速测试用例.md](终端限速测试用例.md) - 终端限速详细用例
- [AI赋能测试效率提升方案.md](AI赋能测试效率提升方案.md) - AI辅助测试方案

## 许可

内部测试项目
