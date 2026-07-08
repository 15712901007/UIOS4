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
│   ├── ikuai_table_page.py    # 表格CRUD基类（行操作/批量/导入导出/搜索排序）
│   ├── login_page.py          # 登录页面
│   ├── network/               # 网络配置模块(20+模块)
│   │   ├── vlan_page.py       # VLAN设置页面
│   │   ├── ip_rate_limit_page.py   # IP限速页面
│   │   ├── interface_settings_page.py  # 内外网设置页面(5种接入+混合子接入)
│   │   └── ...                # 静态路由/跨三层/多线负载/分流/UPnP/NAT/DMZ/组播/DNS/DHCP/自定义协议/IPv6/VPN客户端等
│   └── security/              # 安全中心模块
│       ├── acl_page.py        # ACL规则页面(继承IkuaiTablePage)
│       ├── conn_limit_page.py # 连接数限制页面(继承AclPage)
│       ├── mac_access_control_page.py  # MAC访问控制页面(继承AclPage, 黑/白名单两模式)
│       └── app_protocol_page.py  # 应用协议控制页面(继承AclPage, L7 DPI, 协议树dialog)
├── tests/                      # 测试用例
│   ├── conftest.py            # pytest fixtures（登录、SSH、报告、步骤记录、中文用例名映射）
│   ├── network/               # 网络配置测试(20+模块综合测试)
│   └── security/              # 安全中心测试
│       ├── test_acl_comprehensive.py              # ACL规则综合测试（21步+SSH全链路）
│       ├── test_conn_limit_comprehensive.py        # 连接数限制综合测试（20步+SSH）
│       ├── test_mac_access_control_comprehensive.py # MAC访问控制综合测试（15步+SSH, 黑白名单两模式）
│       └── test_app_protocol_comprehensive.py      # 应用协议控制综合测试（15步+SSH+功能打流, L7 DPI）
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
│   │   ├── mac_rate_limit/    # MAC限速导出(CSV/TXT)
│   │   ├── cross_layer_service/  # 跨三层服务导出(CSV/TXT)
│   │   ├── multi_wan_lb/      # 多线负载导出(CSV/TXT)
│   │   └── protocol_route/    # 协议分流导出(CSV/TXT)
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

# 运行所有网络模块测试
pytest tests/network/ -v

# 运行安全中心模块测试（ACL规则/连接数限制/MAC访问控制）
pytest tests/security/ -v
pytest tests/security/test_acl_comprehensive.py -v                  # ACL规则(21步)
pytest tests/security/test_conn_limit_comprehensive.py -v            # 连接数限制(20步)
pytest tests/security/test_mac_access_control_comprehensive.py -v    # MAC访问控制(15步, 黑白名单两模式)
pytest tests/security/test_app_protocol_comprehensive.py -v          # 应用协议控制(15步+功能打流, L7 DPI)

# 指定SSH配置运行（环境变量方式）
SSH_HOST=10.66.0.150 SSH_USERNAME=sshd SSH_PASSWORD=ikuai8.com pytest tests/network/test_ip_rate_limit_comprehensive.py -v
```

### 4. 启动GUI

```bash
python main.py
```

## 测试模块

### VLAN设置 (test_vlan_comprehensive.py)
18步综合测试 + SSH后台验证 + 功能验证：
- 添加8条VLAN → 编辑 → 停用 → 启用 → 删除 → 搜索 → 排序 → 导出 → 异常输入 → 批量停用 → 批量启用 → 批量删除 → 导入 → 帮助
- SSH三级验证：L1数据库(`vlan show`) → L2网络接口(`ip link show`) → L3 proc(`/proc/net/vlan/config`)
- **功能验证(步骤17/18)**: 普通VLAN(client ens11.54 ping路由器VLAN接口IP) + QINQ(client ens11.54.55双层tag ping内层VLAN接口IP, 默认802.1Q即可)

### IP限速 (test_ip_rate_limit_comprehensive.py)
18步综合测试 + SSH后台验证：
- 添加8条规则（覆盖单IP/IP段/CIDR/多IP/时间计划/协议端口等场景）
- 每条规则添加后自动SSH验证：L1数据库 → L2 iptables → L3 ipset → L4内核
- 编辑/停用/启用/删除后SSH验证数据库状态一致性
- 搜索/排序/导出/异常输入/批量操作/导入/帮助

### MAC限速 (test_mac_rate_limit_comprehensive.py)
20步综合测试 + SSH后台验证 + 功能验证：
- 添加8条规则（覆盖单MAC/多MAC/时间计划/协议端口等场景）
- SSH后台验证（兼容mac_qos和dt_mac_qos两种表结构）
- 同IP限速的完整操作覆盖
- **功能验证(步骤17.5/22)**: 步骤17.5检测删除后iptables残留; 步骤22 iperf3实测(上行生效/下行软记录-产品bug下载不限速), 建规则前flush清残留
- ⚠️ 2个产品bug(报禅道): ①删除规则iptables MAC_QOS间歇残留 ②下载方向不限速(内核6.12, iptables pkts=0未命中)

### 功能验证(打流实测, client 10.66.0.18)
参照全链路验证模式，给限速/VLAN/ACL 补端到端实测(配置真实生效，非仅静态SSH验证)：
- **IP限速**(综合测试步骤22): 动态获取client IP → 建规则 → iperf3打流 → 验证上下行带宽达标(L5)，上下行限速都生效
- **MAC限速**(综合测试步骤22+17.5): iperf3实测(上行生效/下行软记录-产品bug下载不限速)；步骤17.5检测删除后iptables残留；建规则前 flush_mac_qos_chain 清残留
- **VLAN**(综合测试步骤17/18): 普通VLAN(client ens11.54 ping路由器VLAN接口IP) + QINQ(client ens11.54.55双层tag ping内层VLAN接口IP)，默认802.1Q即可
- **ACL**(独立 `TestAclFlowVerification`): acl_flow_env干净环境，drop规则→iperf3验证阻断 + accept规则→验证放行(verify_acl_flow全栈L5)。不并入综合测试(22步状态干扰add_rule)
  - 跑法：`pytest tests/security/test_acl_comprehensive.py::TestAclFlowVerification -s`(只功能验证~1.5min) / `::TestAclComprehensive`(22步CRUD，不含功能验证)
- 环境不通(iperf3 server不可达/SSH不通)时软记录跳过，不阻断测试。详见topic mac-qos-product-bugs/vlan-func-verify/acl-func-verify

### 静态路由 (test_static_route_comprehensive.py)
19步综合测试 + SSH后台验证：
- 添加8条路由（覆盖不同协议栈/线路/子网掩码/网关组合）
- 复制功能测试
- SSH两级验证：L1数据库(`static_rt show`) + L2内核路由(`ip route show`)

### 跨三层服务 (test_cross_layer_service_comprehensive.py)
21步综合测试 + SSH后台验证：
- V2/V3双版本SNMP规则全覆盖
- 频率设置与异常值测试（字母/负数/小数/超大值）
- IP分组功能（创建+引用+截断名称匹配）
- 批量删除重试机制
- SSH验证：L1数据库(`netsnmpc show`) + L4内核模块

### 多线负载 (test_multi_wan_lb_comprehensive.py)
19步综合测试 + SSH后台验证：
- 全部7种负载模式（新建连接数/源IP/源IP+目的IP/按比例/备用/源地址/目的地址）
- 自定义运营商功能（添加+删除+CIDR格式验证）
- SSH四级验证：L1数据库(`lb_pcc show`) + L2策略路由(`ip rule`) + L3/L4内核模块

### 协议分流 (test_protocol_route_comprehensive.py)
20步综合测试 + SSH后台验证：
- 8条规则覆盖3种负载模式 + 线路绑定 + 生效时间 + IP/MAC分组
- 复制功能测试
- 5项扩展功能：线路绑定/生效时间(3种模式)/IP/MAC分组/复制/协议分组
- SSH四级验证：L1数据库(`stream_layer7 show`) + L2 iptables(mangle链) + L3策略路由 + L4内核
- 扩展字段验证：`iface_band`(线路绑定)、`time`(生效时间)、`src_addr`(IP/MAC分组)

### 安全中心模块 (tests/security/)

#### ACL规则 (test_acl_comprehensive.py)
21步综合测试 + SSH全链路（首个安全中心模块）：
- 10规则场景全覆盖（源IP单/网段/目的IP/源+目的/TCP/UDP/ICMP/动作drop/方向input/备注+优先级+ctdir）
- 每场景SSH验证：L1 acl表(src_addr/dst_addr明文JSON) + L2 iptables(FIREWALL/INPUT_ACL链 -j ACCEPT/DROP /* {id}_{comment} */) + L3 ipset(acl_src_/acl_dst_)
- 复制功能 + CRUD + 异常(空名/非法IP) + 导出CSV/TXT + 导入不清空/清空 + 批量

#### 连接数限制 (test_conn_limit_comprehensive.py)
20步综合测试 + SSH全链路：
- 8规则场景（内网IP单/网段/多地址/协议any,tcp,udp,icmp/连接数大10000,小10/备注）
- SSH验证：L1 conn_limit表 + L2 iptables **raw表CONNLIMIT链**(-m peerconns --peerconns-above N -j DROP, 无--comment用conn_limit_time_{id}定位) + L3 ipset
- ConnLimitPage继承AclPage + 复制功能

#### MAC访问控制 (test_mac_access_control_comprehensive.py)
15步综合测试 + SSH全链路（**黑/白名单两模式**）：
- 黑名单模式(acl_mac_black表 + ACL_MAC链 -j DROP) + 白名单模式(acl_mac_white表 + -j RETURN)
- 模式切换(global_config.acl_mac=0黑/1白, ⚠️radio click不调API仅改前端state, 用backend set_mac_mode切换)
- SSH验证：L1 acl_mac_black/white表(mac小写) + L2 ACL_MAC链(DROP黑/RETURN白, 无--comment用acl_mac_{id}+acl_mac_time_{id}定位) + L3 ipset + 模式验证
- 行操作无复制（编辑/停用/删除）; 配置页字段名称/终端名称/MAC/周期/备注

#### 应用协议控制 (test_app_protocol_comprehensive.py)
20步综合测试（**L7 DPI, 安全中心第4模块**）：8场景批量+每条SSH L1/L2+排序+异常分类+导入导出+批量+帮助按钮+功能打流
- 协议字段是**modal树形dialog**（非dropdown）: 13大类(网络协议/网络游戏/社交通讯/传输下载/休闲娱乐/...), 点`.ant-tree-checkbox`勾选+点确定
- ⚠️**不走iptables/ipset**, 走 `ik_cntl new_tc app_rule` 内核(acl_l7表). 验证金矿: ik_summary的`ID:<id>`规则状态行(active/action/appset/match) + dpi_cache appid + **match增量(命中铁证)**
- **功能打流**(步骤20): 建drop百度规则→curl百度(**命中match+4**)+curl qq.com(**精确不命中match=0**)+连通性探测; 命中+精确性证规则识别+匹配逻辑正确, new_tc不可用户态启用致drop未执行(连通,环境限制,企业版可验真阻断)
- 关键踩坑: **user_dpi必须enable**(默认disable→match恒0); new_tc disable(drop不执行,match增量作铁证); time必须""; app_proto custom放应用名非appid
- AppProtocolPage继承AclPage + select_protocol树dialog核心 + 覆写save_and_wait/_mark_area_block

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
├── 静态路由验证
│   ├── L1: verify_static_route_database()  # 数据库字段验证(static_rt show)
│   └── L2: verify_static_route_kernel()    # 内核路由验证(ip route show)
├── 跨三层服务验证
│   ├── L1: verify_netsnmpc_database()      # 数据库字段验证(netsnmpc show)
│   └── L4: verify_netsnmpc_kernel()        # 内核模块验证(ik_core+dmesg)
├── 多线负载验证
│   ├── L1: verify_lb_pcc_database()        # 数据库字段验证(lb_pcc show)
│   ├── L2: verify_lb_policy_routing()      # 策略路由验证(ip rule fwmark)
│   └── L3/L4: verify_lb_kernel()           # 内核验证(ik_core+dmesg [LB])
├── 协议分流验证
│   ├── L1: verify_stream_layer7_database()       # 数据库字段验证(stream_layer7 show)
│   ├── L2: verify_stream_layer7_iptables()       # iptables验证(mangle/STREAM_LAYER7_NEW链)
│   ├── L3: verify_stream_layer7_policy_routing()  # 策略路由验证(ip rule fwmark)
│   └── L4: verify_stream_layer7_kernel()          # 内核验证(ik_core模块)
├── 安全中心-ACL规则验证
│   ├── L1: verify_acl_database()       # acl表(src_addr/dst_addr明文JSON非base64)
│   ├── L2: verify_acl_iptables()       # FIREWALL/INPUT_ACL链(-j ACCEPT/DROP /* {id}_{comment} */)
│   └── L3: verify_acl_ipset()          # acl_src_{id}/acl_dst_{id}
├── 安全中心-连接数限制验证
│   ├── L1: verify_conn_limit_database() # conn_limit表(limits连接数)
│   ├── L2: verify_conn_limit_iptables() # raw表CONNLIMIT链(-m peerconns --peerconns-above N -j DROP, 无--comment)
│   └── L3: verify_conn_limit_ipset()    # conn_limit_src_{id}
├── 安全中心-MAC访问控制验证
│   ├── L1: verify_mac_ctrl_database()  # acl_mac_black/white表(mode+mac小写)
│   ├── L2: verify_mac_ctrl_iptables()  # filter表ACL_MAC链(DROP黑/RETURN白, 无--comment)
│   ├── L3: verify_mac_ctrl_ipset()     # acl_mac_{id}
│   └── 模式: verify_mac_ctrl_mode()/set_mac_mode() # global_config.acl_mac=0黑/1白(radio不调API用backend切换)
├── 安全中心-应用协议控制验证 (⚠️不走iptables, 走ik_cntl new_tc内核)
│   ├── L1: verify_app_protocol_database()    # acl_l7表(app_proto JSON: custom应用名/object gid; time必须"")
│   ├── L2: verify_app_protocol_kernel_rule() # ik_summary的ID:<id>行(active/action:Drop|Accept/appset/match)
│   ├── L3: verify_app_protocol_match/dpi()   # match计数增量(命中铁证) + dpi_cache appid + host_active_apps
│   ├── L4: verify_app_protocol_flow()        # 功能打流curl baidu(match增量硬验+连通性探测, 自动开/恢复user_dpi)
│   └── 辅助: add_app_protocol_rule_via_ssh()/cleanup_app_protocol_test() # SQL建规则+ik_cntl del残留清理
└── SSH连接管理
    ├── 自动重连(transport.is_active()检查)
    ├── exec重试(失败重连后重试一次)
    └── 控制台密码智能登录(交互式菜单自动登录)
```

设计原则：
- **优雅降级**：未安装paramiko或SSH连接失败时，自动跳过SSH验证
- **选择性断言**：关键验证点（L1数据库、L4内核、停用/启用/删除/批量操作）使用`must_pass=True`，失败收集到`ssh_failures`列表，测试末尾统一`assert`
- **不中断UI流程**：SSH验证失败不会中断测试执行，所有UI步骤完成后再统一判定
- **动态fixture注入**：`request.getfixturevalue('backend_verifier')` 按需获取
- **多模块统一SSH验证**：VLAN/IP限速/MAC限速/静态路由/跨三层/多线负载/分流/UPnP/NAT/DMZ/组播/DNS/DHCP/自定义协议/IPv6/VPN客户端/内外网 + 安全中心(ACL规则/连接数限制/MAC访问控制/应用协议控制)等 **24+模块** 使用相同的SSH验证模式

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

1. 在 `pages/network/`(网络配置)或 `pages/security/`(安全中心)下创建Page Object类，继承 `IkuaiTablePage`(或安全中心模块继承 `AclPage` 复用_select_by_label/地址添加/CRUD/复制/导入导出等通用方法)
2. 在 `tests/network/`或 `tests/security/`下创建综合测试文件，参考20步测试模式
3. 在 `test_data/exports/<module>/` 下准备导入导出测试数据
4. （可选）在测试中集成SSH后台验证（`request.getfixturevalue('backend_verifier')` 软注入）
5. 在 `utils/backend_verifier.py` 中添加对应模块的验证方法（verify_xxx_database/iptables/ipset）
6. 在 `tests/conftest.py` 加fixture + TEST_NAME_MAPPING中文映射；`gui/main_window.py` 注册模块树节点；`config/settings.yaml` 加module；`pytest.ini` 加mark

### 20步综合测试模式

```
Step 1:    检查并清理环境
Step 2:    二次检查测试数据
Step 3:    批量添加规则（覆盖各种参数组合）
Step 4:    SSH后台数据验证（L1+L2+L3+L4）
Step 5:    编辑规则
Step 5.5:  复制规则（部分模块）
Step 6:    停用规则
Step 7:    启用规则
Step 8:    删除规则
Step 9:    搜索测试
Step 10:   导出测试（CSV/TXT）
Step 11:   异常输入测试
Step 12:   排序测试
Step 13:   批量停用
Step 14:   批量启用
Step 15:   批量删除
Step 16:   导入测试（追加）
Step 17:   导入测试（清空现有）
Step 18:   清理环境
Step 19:   帮助功能
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
