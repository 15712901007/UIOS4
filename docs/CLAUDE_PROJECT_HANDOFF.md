# 爱快路由器 4.0 前端 UI 自动化测试 — 项目交接文档

> 本文档供下一位 AI 助手或开发人员接手使用。所有结论按来源标注:
> - 【已由代码确认】— 本次交接时直接阅读源码核实
> - 【来自历史记忆】— 来源于过往会话沉淀的记忆档案(机制与方向可信,具体 BUG 是否仍存在需复核)
> - 【待进一步确认】— 需要运行环境或人工核实的点
>
> 凭据类信息一律不写明文,只说明读取位置与环境变量。

---

## 1. 项目目标与测试范围

### 1.1 项目解决什么问题 【已由代码确认】

对爱快路由器 OS 4.0 的 Web 管理后台做**端到端自动化测试**,核心特点是不停留在"UI 能点通",而是把**前端 UI 操作**与**路由器底层 SSH 后端验证**绑定在一起,验证"用户在页面上配置的功能在内核/数据库/数据面真的生效"。

- 技术栈:Playwright(sync_api)+ pytest + PySide6(GUI)+ paramiko(SSH)+ Jinja2(报告)+ pandas/openpyxl(Excel 导出)。依赖见 [requirements.txt](../requirements.txt)。【已由代码确认】
- 规模:`pages/` 约 50 个页面对象,`tests/` 约 35 个综合测试文件;`utils/backend_verifier.py` 是项目最大的单文件(L5 方法 `cleanup_ftp_test` 定义在 L13661 附近,可推断文件超过 1.3 万行,含 4 个顶层类、数百个验证方法)。【已由代码确认】

### 1.2 Web UI、SSH 后端验证、测试客户端、GUI、报告之间的关系 【已由代码确认】

```
PySide6 GUI (gui/)  ──选中 nodeid──▶  TestRunner (gui/test_runner.py)
        │                                  │ 设置环境变量 + 调 pytest
        │                                  ▼
        │                          pytest (tests/conftest.py + tests/**)
        │                                  │ 注入 fixtures
        │                                  ▼
        │                   Page Object (pages/**)  ──Playwright──▶  路由器 Web 后台
        │                                  │
        │                   BackendVerifier (utils/backend_verifier.py)
        │                                  │ SSH(paramiko)
        │                                  ▼
        │                   路由器 SSH(sshd) + 测试客户端 SSH(打流用)
        │                                  │
        └── 读 test_results.json ◀── conftest hook 落盘
                        │
                        ▼
            HTML(report_template.html) + JSON(test_results.json)
                        │
                        ▼
            Excel(test_results_to_excel.py) — GUI"导出测试结果"
```

- **Page Object** 负责 UI 操作;**BackendVerifier** 负责 SSH 后端验证;两者在同一测试函数内通过 `rec.step()` + `ssh_verify()` 串联。【已由代码确认】
- **测试客户端**(Ubuntu)只用于 L5 打流/连通性实测,通过 SSH 被 BackendVerifier 驱动跑 `iperf3`/`curl`/`ping`。【已由代码确认】
- **GUI** 不直接执行验证,它只选中 nodeid、注入环境变量、调起 pytest、读取报告。【已由代码确认】

### 1.3 L1–L5 在本项目中的准确含义 【已由代码确认】

这是本项目最重要的约定,`VerifyResult.level` 字段即用这些标签:

| 层级 | 含义 | 典型手段 | 代表方法 |
|---|---|---|---|
| **L1** | 数据库层 | `sqlite3 -line` 直查 `/etc/ikuai/config.db` | `verify_qos_database` / `verify_acl_database` / `verify_vlan_database` |
| **L2** | 下发层 | iptables 链 / 策略路由 / 内核路由 / 网络接口 / 进程端口 | `verify_iptables_rule` / `verify_lb_pcc_policy_routing` / `verify_static_route_kernel` |
| **L3** | 底层集合 | ipset 成员 / proc / conntrack / mangle 计数 / cflow | `verify_ipset_member` / `read_mangle_counter` / `conntrack_egress` |
| **L4** | 内核/运行时 | ik_core 内核模块 + dmesg / 脚本 init 重建一致性 | `verify_kernel` / `verify_module_kernel_consistency` |
| **L5** | 真实数据面实测 | iperf3 打流 / curl / ping / FTP LIST 上传下载 / conntrack DNAT | `run_iperf3` / `verify_connectivity` / `verify_dnat_conntrack` |

注意:**L1–L5 不是"每个层级一个 rec.step"**,而是"一个 `rec.step` 内可连续调用多次 `ssh_verify`,label 里带 `L1/L2/...` 前缀"。【已由代码确认】

---

## 2. 环境拓扑

### 2.1 角色与访问关系 【已由代码确认】+【来自历史记忆】

| 角色 | 地址 | 用途 | 凭据读取位置(不含明文) |
|---|---|---|---|
| 被测路由器 | `10.66.0.150` | Web 被测后台 + SSH 后端验证目标 | `config/settings.yaml`: `device.*`(Web)、`ssh.router.*`(SSH) |
| 测试客户端(Ubuntu) | 外网 `10.66.0.18` / 内网 `192.168.148.2`(网卡 `ens11`) | L5 打流/连通性实测,经路由器收发 | `config/settings.yaml`: `ssh.client.*` |
| iperf3 / VPN 服务端 | `10.66.0.40:5201` | iperf3 打流服务端 + VPN 拨号服务端 | `config/settings.yaml`: `ssh.iperf3_server` |
| Web 访问入口 | `http://<device.ip>` (`/login#/` 或 `/#/` 前缀,见 §4.3) | Playwright 驱动 | `config.get_base_url()` |

- 客户端经路由器收发是**限速/分流/ACL 等 L5 验证生效的前提**:BackendVerifier 用 `add_route_via_router()` 在客户端加一条经路由器 LAN 口(`192.168.148.1`)的路由,否则客户端流量绕开路由器→规则永不命中。【已由代码确认】
- 客户端打流强制经指定网卡:`iperf3 --interface ens11` / `curl --interface ens11`,避免走默认路由绕过。【来自历史记忆】

### 2.2 LAN/WAN 拓扑 【来自历史记忆】

- LAN1(`ens11`)→ Ubuntu 客户端(外 `10.66.0.18` / 内 `192.168.148.2`)。
- 3 条 WAN,策略路由 fwmark:`0x2711/2712/2713` → wan1/wan2/wan3。多线负载/分流 L5 用 fwmark 同行检查作铁证。
- ⚠️ `wan2` 为孤立网段,作上行/打流目标不可靠;上下行分离实测用 wan1(上行)+ wan3(下行)。【来自历史记忆】

### 2.3 凭据读取方式(脱敏说明) 【已由代码确认】

凭据**明文存储于 `config/settings.yaml`**(已被 git 跟踪——见 §8.3 风险提示),结构如下,运行时由 [config/config.py](../config/config.py) 的 `Config.from_yaml()` 加载:

- Web 登录:`device.username` / `device.password` / `device.ip` / `device.port`
- 路由器 SSH:`ssh.router.host/username/password/port`
- 路由器控制台交互式菜单登录(SSH 进入菜单时自动登录):`ssh.router.console_username` / `ssh.router.console_password`
- 测试客户端 SSH:`ssh.client.host/username/password/port`
- iperf3:`ssh.iperf3_server` / `ssh.iperf3_duration` / `ssh.iperf3_tolerance`

**环境变量覆盖**(优先级高于 yaml,GUI 即通过此传参),见 `apply_env_overrides()`:`DEVICE_IP/USERNAME/PASSWORD/PORT`、`SSH_ROUTER_HOST/USERNAME/PASSWORD/PORT`、`SSH_CONSOLE_USERNAME/PASSWORD`、`SSH_CLIENT_HOST/USERNAME/PASSWORD/PORT`、`IPERF3_SERVER/DURATION/TOLERANCE`、`TESTER/TEST_VERSION`、`HEADLESS`、`AUTO_ADAPT_SCREEN`、`VIEWPORT_WIDTH/HEIGHT`。

> ⚠️ 交接重点:`settings.yaml` 当前处于 git 跟踪状态(§8)。如需对外分享仓库,必须先做脱敏(改为模板 + `.gitignore`)。文档与代码中**绝不再二次写入任何明文口令**。

### 2.4 固定环境服务,禁止误杀或修改 【来自历史记忆】

- 路由器侧已部署 SSH 防重置脚本 `/etc/mnt/ikuai/fix_sshd_shell.sh`(位于 `/dev/sda3` 独立分区,固件升级后保留),cron 每分钟自检修复 `/etc/passwd` 中 sshd 的 shell。**勿触发"其他选项→技术维护通道"**,否则 SSH 22 端口会被关闭且不可恢复。
- iperf3 服务端(10.66.0.40:5201)、VPN 服务端(PPTP/L2TP/OpenVPN/IKEv2)是**固定环境**,测试 teardown 只清理客户端进程(`pkill -f 'iperf3 -c'`)与客户端侧路由,不得重启/重配服务端。
- 测试客户端的 `ens11` 由 `systemd-networkd` 管理,**勿用 `dhclient`**(ISC 4.4.1 与 networkd 冲突,DHCP L5 用 `ip link down/up` 触发 DISCOVER)。

---

## 3. 仓库结构

### 3.1 目录职责 【已由代码确认】

| 目录 | 职责 |
|---|---|
| [config/](../config/) | `config.py`(dataclass 配置 + yaml 加载 + 环境变量覆盖 + PyInstaller 路径兼容)、`settings.yaml`(实际配置,含凭据) |
| [pages/](../pages/) | Page Object。`base_page.py`(Playwright 原语基类)、`ikuai_table_page.py`(表格 CRUD 中间基类,**所有表格页的真正父类**)、`login_page.py`、`network/`(网络配置)、`security/`(安全中心)、`advanced_service/`(高级服务) |
| [tests/](../tests/) | `conftest.py`(fixture/marker/hook/中文名映射/报告落盘的中枢)、`network/`、`security/`、`advanced_service/` 综合测试;`network/vpn_test_helper.py`(6 个 VPN 模块的数据驱动公共流程) |
| [utils/](../utils/) | `backend_verifier.py`(SSH 后端验证核心)、`verify_helper.py`(ssh_verify/kernel_check 工厂)、`step_recorder.py`(步骤记录器)、`report_generator.py`(Jinja2 HTML 报告)、`test_results_to_excel.py`(Excel 导出)、`logger.py` |
| [gui/](../gui/) | `main_window.py`(主窗口+硬编码执行树)、`test_runner.py`(pytest 调度)、`config_dialog.py`(配置对话框)、`scheduler.py`(APScheduler 定时,后端已写但前端入口未通)、`gui_resources/styles.qss` |
| [reports/](../reports/) | `templates/report_template.html`(Jinja2 模板);`output/`、`screenshots/`、`allure-results/` 为生成物(已 gitignore) |
| [test_data/](../test_data/) | `exports/`(各模块导出基准 txt/csv,已 gitignore)、`imports/`(导入测试数据,随包)、`vlan/`(VLAN 导入 csv)、`acl/protocol_cases.yaml`、`vpn/openvpn_ca.pem` |
| [build/](../build/) | `ikuai_test.spec`、`ikuai_test_onefile.spec`(PyInstaller,版本化)、`build.bat`/`build_portable.bat`;`build/*` 其余为生成物(已 gitignore) |
| [docs/](../docs/) | `PLAN.md`(**早期 VLAN 设计草案,部分已过时,勿当事实**)、`README.md`(较新总览)、`CLAUDE_PROJECT_HANDOFF.md`(本文件) |

### 3.2 Page Object / fixture / StepRecorder / BackendVerifier 调用关系 【已由代码确认】

**继承层次(重要修正,勿搞错)**:

```
BasePage (pages/base_page.py)               ← 仅 Playwright 原语 + 帮助功能,无业务 helper
  └─ IkuaiTablePage (pages/ikuai_table_page.py)  ← 表格 CRUD/确认弹窗/导入导出/行操作/批量/搜索排序的主力 helper
       ├─ VlanPage / AclPage / FtpServerPage / DhcpServerPage ...   ← 各业务页
       └─ VpnClientBasePage (pages/network/vpn_client_base.py)      ← VPN 中间基类(含 _detect_enterprise_block)
            └─ PptpClientPage / L2tpClientPage / OpenvpnClientPage / IkeClientPage / WireguardPage / IpsecVpnPage
```

- `LoginPage` 是**唯一直接继承 BasePage**(不走 IkuaiTablePage)的页面。【已由代码确认】
- 易混淆点:`_click_visible_confirm`(确认弹窗)、`click_add_button`、`import_rules`/`export_rules`、`_click_rule_button`、`sort_by_column` 等 helper **都在 `IkuaiTablePage`,不在 BasePage**;`_detect_enterprise_block` **在 `VpnClientBasePage`**;`_read_save_result` **不是公共方法**,只在 `ipv6_wan_page.py`/`ipv6_lan_page.py` 各自私有实现。【已由代码确认】

**调用链(以一次综合测试为例)**:

1. pytest 收集测试 → [tests/conftest.py](../tests/conftest.py) 注入 `xxx_page_logged_in` fixture(登录 + 导航到模块)、`step_recorder`(function 级,每次 `clear()`)、`backend_verifier`(session 级,无 paramiko 时 yield None)。
2. 测试函数内 `backend_verifier = request.getfixturevalue('backend_verifier')`(软注入,兼容无 SSH 环境;FTP 例外——None 即 `pytest.fail`)。
3. `ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)`(标准)或 `attach_cmd_recording_to_closure(...)`(特化闭包)。
4. UI 操作走 Page Object;每个关键动作包在 `with rec.step("步骤名"):` 内,SSH 验证用 `ssh_verify("L1-数据库", verify_xxx_database, ..., must_pass=True)`。
5. `finally` 内 `page.clean_test_rules(PREFIX)` + `backend_verifier.cleanup_xxx_test(PREFIX)` + `kernel_check("清理后")` 残留检测。
6. 测试末尾 `assert not (ssh_failures + ui_failures)` 聚合硬断言。

### 3.3 配置加载及环境变量覆盖机制 【已由代码确认】

- 入口:`get_config()` 单例 → `get_config_path()` → 优先 `<用户数据目录>/config/settings.yaml`,回退内置默认。
- 路径兼容(PyInstaller):`get_base_path()`(打包返回 `sys._MEIPASS`,源码返回项目根)、`get_user_data_path()`(打包返回 exe 所在目录)。
- GUI/CLI 传参:`get_config_with_env()` = `get_config()` + `apply_env_overrides()`(环境变量优先级最高)。
- GUI 配置**不自动落盘**:ConfigDialog 只改内存 Config 对象;持久化仅"文件→保存配置(Ctrl+S)"→ `Config.to_yaml()`。【已由代码确认】

---

## 4. 自动化开发规范

### 4.1 综合测试文件标准结构 【已由代码确认】

参考范本:[tests/network/test_vlan_comprehensive.py](../tests/network/test_vlan_comprehensive.py)、[tests/security/test_acl_comprehensive.py](../tests/security/test_acl_comprehensive.py)、[tests/advanced_service/test_ftp_server_comprehensive.py](../tests/advanced_service/test_ftp_server_comprehensive.py)。

- **测试类**:`Test<Module>Comprehensive`(如 `TestVlanComprehensive`、`TestFtpServerComprehensive`);功能验证衍生类如 `TestAclFlowVerification`、`TestVlanImportExport`。
- **测试函数**:`test_<module>_comprehensive`;功能验证用 `test_<module>_flow[_verification]`。
- **Marker**:模块级 `pytestmark = [pytest.mark.security, pytest.mark.acl]` 或类级装饰器堆叠 `@pytest.mark.vlan @pytest.mark.network`。
- **Fixture 三件套 + request**:`<module>_page_logged_in`、`step_recorder: StepRecorder`、`request`。
- **步骤骨架**(README 归纳的 ~20 步模式):清理环境 → 二次校验数据 → 批量添加(覆盖参数组合)→ SSH L1+L2+L3+L4 验证 → 编辑 → 复制(部分模块)→ 停用/启用 → 删除 → 搜索 → 导出(CSV/TXT)→ 异常输入 → 排序 → 批量停用/启用/删除 → 导入(追加)→ 导入(清空)→ 清理 → 帮助;L5 功能验证常作独立类或后置步骤。

### 4.2 Page Object 标准结构 【已由代码确认】

- **类名**:`<Module>Page`(VPN 子类用领域名如 `WireguardPage`)。
- **`__init__(self, page, base_url="")`** → `super().__init__(page, base_url)`(继承 IkuaiTablePage 两参签名)。
- **类常量**:`MODULE_NAME`(必填,小写下划线,用于导出文件命名)、URL 常量(命名不统一,见 §4.3)。
- **导航方法**:`navigate_to_<module>()`,`return self` 支持链式。
- **CRUD 命名**:`add_rule`/`delete_rule`/`edit_rule`/`copy_rule`(基类提供后三者默认实现,子类按需覆盖);异常用 `try_add_rule_invalid`;清理用 `clean_test_rules(prefix)`。
- **返回值约定**:配置型页返回 `dict {"success","error"}`;列表型返回 `bool`。新模块(FTP)同时提供领域别名(`add_user`)和框架兼容别名(`add_rule = add_user`)。

### 4.3 交互实现规范(Ant Design 踩坑沉淀) 【已由代码确认】

| 交互 | 规范做法 | 不可靠做法 |
|---|---|---|
| **select 下拉** | Playwright **真实 `.click()`** 打开 dropdown;option 按 `title` 属性优先 / label 文本**精确 `===`** 匹配(避免"协议"误中"协议栈") | JS `mousedown` 不触发 React;`get_by_role` 子串匹配 |
| **Ant Form 填写** | React 表单用**原生 setter**(`HTMLInputElement.prototype.value.set`) + `dispatchEvent('input'/'change')`;或 `type(value, delay=20)` | 裸 `fill()` 不触发 onChange |
| **时间/数字字段** | `click` → `press("Control+a")` → `type(str, delay=...)`(先全选再输入) | 直接 fill 覆盖不全 |
| **tab 切换** | JS 遍历 `.ant-tabs-tab/[role=tab]/.ant-segmented-item`,**精确 `textContent===name`** 才点;确认 `.ant-tabs-tab-active` | 子串匹配 |
| **确认弹窗** | 统一走 `_click_visible_confirm()`(`:visible` + 短超时 4s,规避 `.ant-modal-confirm` 常驻隐藏根节点的 strict-mode violation) | 直接 `get_by_role("确定")` 会命中隐藏残留节点卡 30s |
| **虚拟滚动表格** | headless 用大 viewport(默认 1920×1080)避免 Ant Table 漏行;headed 用 `no_viewport=True` | 小 viewport 导致 >10 条只渲染 8 条 |

**URL 前缀新旧差异(加新模块必看)**:旧模块(network/security)用 `/login#` 前缀(如 `VLAN_URL="/login#/VLAN_setting"`);新模块(advanced_service/FTP)用 `/#/` 前缀(如 `LIST_URL="/#/advancedService/localService"`),且显式建模 `ADD_URL` + `EDIT_FRAGMENT` 双常量。【已由代码确认】

### 4.4 marker / 中文名 / GUI nodeid 注册位置 【已由代码确认】

新增模块必须**同步修改 5 处**(README 明确列出):

1. [pytest.ini](../pytest.ini) `markers` 段 + [tests/conftest.py](../tests/conftest.py) `pytest_configure()` 的 `config.addinivalue_line("markers", ...)`(两处都要,否则 `-m` 筛选告警)。
2. `tests/conftest.py` `TEST_NAME_MAPPING` 加英文 test 名→中文映射(否则报告显示英文 test ID)。
3. `tests/conftest.py` 加 `<module>_page_logged_in` fixture(登录 + 导航)。
4. [gui/main_window.py](../gui/main_window.py) `_load_test_modules()` 的**硬编码字典**加节点(叶子带 `"testcases": [<nodeid>]`)——⚠️ 这是 ~520 行硬编码字典,**不自动扫描 tests 目录,新用例不手改就不会出现在 GUI 执行树**。
5. [config/settings.yaml](../config/settings.yaml) `test_data.modules.<module>` 加 `export_filename`/`import_filename`。

nodeid 格式:`文件名::类名::方法名`,子目录带前缀(如 `security/test_acl_comprehensive.py::TestAclComprehensive::test_acl_comprehensive`)。

### 4.5 UI 断言、SSH 验证、硬前置、软断言、finally 恢复 【已由代码确认】

- **UI 断言**:用 `wait_for_success_message()`(IkuaiTablePage 简化版扫 `.ant-message-success`)或 `save_and_wait()`(轮询 URL 离开配置页=成功)+ `has_form_error()` 查 `.ant-form-item-explain-error`。**不要只信 toast**,批量/异步操作要回读列表 + SSH 计数复核(历史教训:批量假成功)。
- **SSH 验证**:`ssh_verify(label, verify_func, *args, must_pass=None, **kwargs)`。
  - `must_pass=True` 且失败/异常 → `failures.append(...)`,测试末尾聚合 `assert` 硬失败。
  - `must_pass=False`(默认)→ 仅 `rec.add_detail` 软记录。
  - 典型:L1 数据库 `must_pass=True`;L2 iptables 在已知产品 BUG 模块上 `must_pass=False`(软记录,避免误红)。
- **硬前置**:`acl_flow_env`/`stream_control_flow_env`/`app_proto_flow_env` 等 function 级 fixture 在 yield 前做 iperf3/连通探活,失败 `pytest.skip`(不 FAIL);FTP 用 `require_ui`/`require_ssh`,失败 `pytest.fail`(FTP 必须 SSH)。
- **软断言(VPN 专用)**:`make_ssh_verify(..., soft_assert=True)`,FAIL 显示 `[软断言]` 而非 `[FAIL]`,且 `raw_output` 内 `[FAIL]`→`[软断言]` 替换——**关键**:conftest 的 `pytest_runtest_logreport` 会扫描步骤 details,含 `FAIL`/`✗` 即强制把该步标 `failed`,裸 `[FAIL]` 泄漏会导致用例级误判。
- **finally 恢复**:`try/finally` 内务必:前端 `clean_test_rules(PREFIX)` + 后端 `cleanup_<module>_test(PREFIX)`(SQL + 脚本兜底)+ `kernel_check("清理后")` 残留检测 + 恢复环境快照(FTP 的 `restore_ftp_global`)。

### 4.6 测试数据命名、唯一前缀、安全清理 【已由代码确认】+【来自历史记忆】

- **唯一前缀**:每个模块用固定前缀隔离命名空间(如 ACL 综合 `acl_t_`、ACL 功能验证 `acl_pm_`、FTP 随机 `ftp_t_<hex>_`)。
- **⚠️ iKuai tagname/名称限 15 字符(通用坑)**:超限后端**静默截断不报错** → find/delete 按完整名查不到,误判建规则失败。前缀要短(如 `acl_pm_` 6 字符)。诊断铁证 = `sqlite3` 全表看 tagname。【来自历史记忆】
- **安全清理**:`cleanup_<module>_test(PREFIX)` 只删本前缀规则,**绝不全表 DELETE / 绝不 `ipset destroy` 清非本测试数据**;清理顺序先父后子(ipset 父→子)。
- **残留哲学(重要)**:`kernel_check` 检测到"删不干净"残留 = **真产品 BUG,报禅道**,绝**不**在后台强清掩盖让测试假绿。`cleanup_xxx_test` 仅作 finally 环境兜底,不作"通过条件"。【来自历史记忆】
- **select_all 只选当前页**:>10 条分页时全选漏选,批量验证要翻页或控制条数。【来自历史记忆】

### 4.7 导入、导出、批量、异常测试的安全约束 【已由代码确认】+【来自历史记忆】

- **导出**:导出 txt + csv 双格式;`MODULE_NAME` 决定导出文件命名;`test_data/exports/` 已 gitignore(每次重新生成,JSON key 顺序不确定)。
- **导入**:`IMPORT_REQUIRES_CLEAR_GUARD` 守卫 + 多文案"清空现有配置" checkbox 匹配;**FTP 导入安全筛选**(`_build_safe_import`)只留 1 个测试用户,**绝不勾"清空现有配置"**。
- **端口映射导入已知 BUG**:导入后 DSTNAT 不生效/残留不同步;cleanup 须 `find("-A DSTNAT")` 因规则带 `[fastid:N]` 前缀。【来自历史记忆】
- **批量操作**:footer 按钮用 `textContent` 精确匹配 + SSH 计数复核 + 3 次重试(历史教训:批量假成功);`select_all_rules` 带 `_wait_selection_active` 验证"已选 X 条"。【已由代码确认】
- **异常输入**:用 `try_add_rule_invalid`,预期失败的用 `rec.step(..., expect_error=True)`。

### 4.8 密码及敏感文件脱敏规则 【已由代码确认】+【待进一步确认】

- **FTP 测试一次性密码**:`_one_time_password` 用 `secrets` 生成,**绝不写常量、绝不输出到报告/断言、测试结束即失效**。【已由代码确认】
- **VPN CA 证书**:`test_data/vpn/openvpn_ca.pem` 随包(测试用)。
- **凭据明文风险**:`config/settings.yaml` 含明文凭据且被 git 跟踪(§8.3)。【待进一步确认:是否应改为 `.example` 模板 + gitignore】
- 文档/日志脱敏:Windows GBK 控制台避免 emoji,用 `[OK]`/`[FAIL]`;报告不写明文口令。【来自历史记忆】

---

## 5. 报告和 GUI 链路

### 5.1 pytest → HTML / JSON / Excel 数据流 【已由代码确认】

```
测试执行
  │  rec.step / add_detail 记录步骤;ssh_verify 写 SSH 结果进 details
  ▼
conftest.pytest_runtest_logreport   (收集每个用例, details 扫 'FAIL'/'✗' 强制标 failed)
  ▼
conftest.pytest_sessionfinish
  ├─ ReportGenerator.generate_report() → reports/output/test_report_<ts>.html (读 report_template.html)
  └─ _dump_test_results_json()         → reports/output/test_results.json (截图只存路径不存 base64)
  ▼
GUI"导出测试结果" / CLI  utils/test_results_to_excel.py
  └─ export_results_to_excel(json_path, output_path) → 2 个 sheet("汇总" + "测试结果明细" 8 列)
```

- **HTML 报告内容**:报告头(标题/时间/耗时/设备/版本/测试人)、统计卡片(total/passed/failed/skipped/total_steps)、用例列表(每条含步骤/SSH 验证输出/验证命令/失败截图 base64)、**失败自动归因** `_analyze_failure()`(磁盘满 2006/添加按钮超时/xt_set 内核 BUG 等分类 + suggestion)。【已由代码确认】
- **SSH 验证命令进报告**:`verify_helper` 的工厂闭包在 finally 用 `mark_cmd_start()`/`collect_cmds_since_mark()` 差量捕获本次实际执行的 SSH 命令(录制咽喉点 = `SSHClient.exec` 的 `_cmd_log.append`),带 `[router]`/`[client]` 前缀显示进 details,**复制即可 SSH 重跑**。【已由代码确认】
- **Excel 明细列**:`["模块","测试项","前提条件","测试场景","测试步骤","预期结果","测试结果","备注"]`;步骤列渲染 `[✓/✗] 标题(用时)` + details;备注列放失败截图路径。【已由代码确认】

### 5.2 GUI 如何选择并运行 nodeid 【已由代码确认】

- **执行树数据源 = 硬编码字典** `MainWindow._load_test_modules()`(~520 行),结构 `顶层模块 → children → 叶子{"testcases":[nodeid], "groups":[...]}`,最多 3 层。**不扫描 tests 目录**。
- 选中后 `_start_tests()` → `TestRunner(selected_testcases, config)`。
- **两条执行路径**:
  - 打包后(`sys.frozen`):`_run_pytest_in_process()` → 同进程 `pytest.main(args)`,用 `RealtimeStdoutCapture` 捕获输出。
  - 源码模式:`_run_pytest_subprocess()` → `subprocess.Popen([python, "-m", "pytest", ...])`。
- **nodeid 传递**:直接把 nodeid 字符串作为路径参数追加(不用 `-k`/`-m`);含 `::` 且文件部分含 `/` → `tests/<tc>`,否则默认 `tests/network/<tc>`。
- **环境变量**:`_setup_env_variables()` 注入 §2.3 全套变量;SSH 主机会被同步成 `config.device.ip`。
- ⚠️ **遗留死代码**:`_build_pytest_command` 里 frozen 分支的 `python_exe + "--run-tests"` 与 `run()` 的 dispatch 不一致,实际未被触发。【已由代码确认】

### 5.3 打包版如何发现 pages/tests/utils 【已由代码确认】

PyInstaller spec([build/ikuai_test.spec](../build/ikuai_test.spec)、[build/ikuai_test_onefile.spec](../build/ikuai_test_onefile.spec))四者配合,**非单一 conftest import-all**:

1. **`datas=` 把目录以纯数据打进 `_MEIPASS`**:`pages`/`utils`/`tests`/`config/settings.yaml`/`gui/gui_resources`/`reports/templates`/`test_data/imports`;onefile 额外打包 Playwright `chromium-1208` 全量浏览器 + `playwright/driver`。
2. **conftest 路径注入**:`tests/conftest.py` 开头 `sys.path.insert(0, 项目根)`(frozen 时项目根即 `_MEIPASS`)→ `pages`/`utils` 可 import。
3. **conftest 重建 playwright fixtures**:打包后 `pytest-playwright` 无法经 entry_points 自动加载,conftest 直接定义 `playwright`/`browser`/`context`/`page` fixtures。
4. **`hiddenimports`**:显式声明 PySide6 子模块、playwright、`pytest_playwright`、paramiko、cryptography、yaml、jinja2、pytest、_pytest、apscheduler、colorlog 等。
5. `main.py` 入口设置 `PLAYWRIGHT_BROWSERS_PATH`/`PLAYWRIGHT_DRIVER_PATH` 指向 `_MEIPASS/playwright`。

### 5.4 已知报告累计 / 旧 JSON / setup 失败问题及当前解决方式 【已由代码确认】

- **报告累计(读到旧报告)**:`TestRunner` 运行前 `_snapshot_result_json_state()` 记录候选 JSON 的 `(mtime_ns, ctime_ns, size)`,运行后只保留状态变化的"新鲜"文件,再 `max(key=getmtime)` 取最新;无新鲜文件发 WARNING 并保留实时计数。HTML 用 `glob *.html` + `getctime` 取最新。
- **统计翻倍**:实时正则匹配 `PASSED/FAILED/...` 整行,进入 "short test summary info" 段后停计;权威值由 `_read_final_stats()` 读 `test_results.json` 顶层覆盖实时计数。
- **setup 失败也记录**:`pytest_runtest_logreport` 的 `collect_result` 条件含 `setup` 的 failed/skipped(无 call 时也生成本次报告条目)。
- **打包 GUI 同进程重复调用**:`pytest_configure` 每次 `_test_results.clear()` 全量清零。
- **截图路径**:`_find_screenshot_path()` 按用例名前缀 + `_failure.png` 后缀在截图目录倒序取最新。

---

## 6. 已开发模块清单

> 后端验证深度标注:**L1**=DB / **L2**=iptables·策略路由 / **L3**=ipset·proc·conntrack / **L4**=内核·运行时 / **L5**=打流·连通实测。"GUI 注册"= 是否进了 main_window 执行树(多数已进)。"成熟度"综合代码完整度与历史记忆。

### 6.1 网络配置模块(pages/network/, tests/network/) 【已由代码确认】+【来自历史记忆】

| 模块 | Page Object | 综合测试 | 后端深度 | 成熟度 | 备注/技术债 |
|---|---|---|---|---|---|
| VLAN 设置 | `VlanPage` | `test_vlan_comprehensive` | L1+L2+L3+L5 | 高 | L5=client `ens11.{vid}` 子接口 ping 路由器 VLAN IP;QINQ 双层 tag |
| IP 限速 | `IpRateLimitPage` | `test_ip_rate_limit_comprehensive` + flow | L1+L2+L3+L4+L5 | 高 | L5 iperf3 上下行;走 ik_core simple_qos |
| MAC 限速 | `MacRateLimitPage` | `test_mac_rate_limit_comprehensive` | L1+L2+L3+L4+L5 | 高(2 产品 BUG) | ⚠️删后 iptables MAC_QOS 间歇残留 + 下载方向不限速(报禅道)【来自历史记忆】 |
| 静态路由 | `StaticRoutePage` | `test_static_route_comprehensive` + flow | L1+L2+L5 | 高 | L5=client lo 环回 10.99.99.1 作目标 |
| 跨三层服务 | `CrossLayerServicePage` | `test_cross_layer_service_comprehensive` | L1+L4 | 高 | SNMP V2/V3 |
| 多线负载 | `MultiWanLbPage` | `test_multi_wan_lb_comprehensive` + flow | L1+L2+L3+L4+L5 | 高 | L5 fwmark + conntrack 分布铁证 |
| 协议分流 | `ProtocolRoutePage` | `test_protocol_route_comprehensive` + flow | L1+L2+L3+L4+L5 | 中(6.12 BUG) | ⚠️6.12 DPI 坏不识别(报禅道)【来自历史记忆】 |
| 端口分流 | `PortRoutePage` | `test_port_route_comprehensive` + flow | L1+L2+L3+L4+L5 | 高 | 选路铁证=client 连接 mark |
| 域名分流 | `DomainRoutePage` | `test_domain_route_comprehensive` + flow | L1+L2+L3+L5 | 中(6.12 BUG) | ⚠️依赖 DNS 加速开 + client DNS 指向路由器;6.12 url_route mark=0 不选路(报禅道)【来自历史记忆】 |
| 上下行分离 | `UpdownRoutePage` | `test_updown_route_comprehensive` + flow | L1+L3(conntrack)+L5 | 高 | 走 ik_cntl wans-snat 内核模块(非 iptables);wan1 上/wan3 下 |
| UPnP/NAT 设置 | `UpnpSettingPage` | `test_upnp_setting_comprehensive` | L1+L2+L3 | 高 | 全链路依赖开关;marker `/tmp/iktmp/upnpd_enabled` |
| NAT 规则 | `NatRulePage` | `test_nat_rule_comprehensive` + flow | L1+L2+L5 | 高 | ⚠️6.12 xt_set 间歇损坏(动态探测 `is_xt_set_broken`)【来自历史记忆】 |
| 端口映射 | `PortMapPage` | `test_port_map_comprehensive` + flow | L1+L2+L5 | 高 | L5 `verify_dnat_conntrack`;⚠️导入 DSTNAT BUG(报禅道)【来自历史记忆】 |
| DMZ 主机 | `DmzHostPage` | `test_dmz_host_comprehensive` + flow | L1+L2+L5 | 高 | NETMAP 打流;✅重启失效 BUG 已修 |
| IGMP 代理 | `IgmpProxyPage` | `test_igmp_proxy_comprehensive` | L1+L2 | 高 | — |
| IPTV 透传 | `IptvPage` | `test_iptv_comprehensive` | L1+L2 | 高 | — |
| UDPXY 设置 | `UdpProxyPage` | `test_udp_proxy_comprehensive` | L1+L2 | 高 | ⚠️进程残留 BUG(报禅道);多实例按 listen_port 查 |
| DNS 加速 | `DnsAcceleratePage` | `test_dns_accelerate_comprehensive` + flow | L1+L2+L5 | 高 | L5 dig 解析 |
| 多线路 DNS | `DnsMultiLinePage` | `test_dns_multi_line_comprehensive` + flow | L1+L2+L5 | 高 | L5 dig 解析 |
| 智能流控 | `StreamControlPage` | `test_stream_control_comprehensive` | L1+L2+L3+L4+L5 | 中(脚本 BUG) | ⚠️alone_limit 限速不生效(qos.sh jq 解析失败,报禅道);layer7 关流控 ipset 残留(真 BUG)【来自历史记忆】 |
| 自定义协议 L4 | `CustomProtocolPage` | `test_custom_protocol_comprehensive` | L1+L2 | 高 | 缺批量 + L3 |
| 高级自定义协议 L7 | `AdvancedCustomProtocolPage` | `test_advanced_custom_protocol_comprehensive` | L1+L2 | 高 | — |
| 路由对象(6 分组) | `IpGroupPage`/`MacGroupPage`/`PortGroupPage`/`DomainGroupPage`/`TimePlanPage`/`ProtocolGroupPage` | `test_<x>_group_comprehensive` | L1+L2 | 高 | 导出 txt 格式 |
| DHCP 服务端 | `DhcpServerPage` | `test_dhcp_server_comprehensive` + flow | L1+L2+L3+L5 | 高 | L5=client `ens11` down/up 触发 networkd(不用 dhclient) |
| DHCP 静态分配 | `DhcpStaticPage` | `test_dhcp_static_comprehensive` + flow | L1+L2+L3+L5 | 高 | L5=edit 既有绑定 + down/rm leases/up |
| DHCP 客户端 | `DhcpLeasePage` | `test_dhcp_lease_comprehensive` | L1 | 高 | — |
| DHCP 黑白名单 | `DhcpAclMacPage` | `test_dhcp_acl_mac_comprehensive` + flow | L1+L2+L3+L5 | 高 | mode 0黑/1白/2同步MAC;只拦 DISCOVER |
| IPv6 前缀静态 | `Ipv6StaticPage` | `test_ipv6_static_comprehensive` | L1+L2 | 高 | — |
| IPv6 外网设置 | `Ipv6WanPage` | `test_ipv6_wan_comprehensive` | L1+L2+L3+L4 | 高 | ⚠️ipset ipv6_prefix 清理不同步(删不干净 BUG,报禅道);含私有 `_read_save_result` |
| IPv6 内网设置 | `Ipv6LanPage` | `test_ipv6_lan_comprehensive` | L1+L2+L3+L4 | 高 | 含私有 `_read_save_result` |
| 内外网设置 | `InterfaceSettingsPage` | `test_interface_settings_comprehensive` | L1+L2 | 高 | 5 接入 + 混合子接入;编辑型无导入导出 |
| VPN 客户端(6) | `VpnClientBasePage` + 6 子类 | `test_<vpn>_comprehensive` | L1+L2(软断言) | 高 | 数据驱动 `vpn_test_helper`;企业版专属(IKE/WG)→ `_detect_enterprise_block`+skip |

### 6.2 安全中心模块(pages/security/, tests/security/) 【已由代码确认】+【来自历史记忆】

继承链:`AclPage(IkuaiTablePage)` ← `ConnLimitPage(AclPage)` / `MacAccessControlPage(AclPage)` / `AppProtocolPage(AclPage)`;`ArpSettingPage`/`AdvancedPage`/`OtherControlPage` 独立。

| 模块 | Page Object | 综合测试 | 后端深度 | 成熟度 | 备注/技术债 |
|---|---|---|---|---|---|
| ACL 规则 | `AclPage` | `test_acl_comprehensive` + `test_acl_flow_verification` | L1+L2+L3+L5 | 高 | tagname 前缀 `acl_pm_` 避 15 字符截断;独立 `TestAclFlowVerification` |
| 连接数限制 | `ConnLimitPage` | `test_conn_limit_comprehensive` + concurrent_drop | L1+L2+L3 | 高 | ✅peerconns 6.12 宕机(固件 10002 已修复);转全局规则绕 xt_set |
| MAC 访问控制 | `MacAccessControlPage` | `test_mac_access_control_comprehensive` | L1+L2+L3 | 高 | 黑/白名单两模式;radio 不调 API 用 backend `set_mac_mode` |
| ARP 设置 | `ArpSettingPage` | `test_arp_setting_comprehensive` | L1+L2+L3+L5 | 高 | arp_filter 白名单 + dhcpd_arp 兼容;L5 三段式 |
| 应用协议控制 | `AppProtocolPage` | `test_app_protocol_comprehensive` + flow | L1+L2(ik_cntl)+L3(match)+L5 | 高 | ⚠️不走 iptables 走 ik_cntl new_tc;停用不生效 BUG(报禅道);L7 DPI 协议树 dialog |
| 高级设置 | `AdvancedPage` | `test_advanced_comprehensive` | L1+L2+L3+L5 | 高 | ⚠️3 产品 BUG:init() 不清旧规则累积/limit_tcp2p 未实现/tcp_mss 范围不一致(报禅道)【来自历史记忆】 |
| 其他控制(网络分享) | `OtherControlPage` | `test_other_control_comprehensive` | L1+L2+L3+L5 | 高 | nol2rt + TTL 夹制 + 时间门控;✅6.12 禁止时间门控已验 |

### 6.3 高级服务模块(pages/advanced_service/, tests/advanced_service/) 【已由代码确认】

| 模块 | Page Object | 综合测试 | 后端深度 | 成熟度 | 备注 |
|---|---|---|---|---|---|
| FTP 服务(本地服务) | `FtpServerPage` | `test_ftp_server_comprehensive` | L1+L2+L4+L5 | 高(新模块) | `/#/` URL 前缀;强制 backend_verifier;一次性密码 + 全环境快照恢复;3 个 L5(LAN FTP/WAN 限制/总开关);⚠️**当前为未跟踪新文件(§8)** |

### 6.4 可复用模式与差异小结 【已由代码确认】+【来自历史记忆】

- **列表型范式(VLAN)**:标准列表页 + drawer 表单,最简。单一 URL 常量,`wait_for_success_message()` 返回 bool。
- **配置型范式(ACL/FTP/VPN)**:独立配置页 + 复杂区域 block(`_mark_area_block`)+ label 定位 + `data-tmp-*` JS 标记;`save_and_wait` 轮询 URL 跳转;返回 `dict`。
- **数据驱动范式(VPN)**:`VpnClientBasePage` + `vpn_test_helper.run_vpn_comprehensive_test()`,6 模块共用流程,子类只设常量 + 实现 `add_rule`;企业版 skip。
- **DHCP 系列差异**:client `ens11` 由 networkd 管,L5 用 down/up 触发 DISCOVER(非 dhclient);黑白名单只拦 DISCOVER(续约 REQUEST 单播绕过)。
- **DNS 系列差异**:域名分流 L5 依赖 DNS 加速开 + client DNS 指向路由器,否则 SNI 识别域名但不选路。
- **分流系列铁证**:端口/多线=`client 连接 mark == 规则 set-mark`;上下行=conntrack `remote_if`/`emark`;协议/域名 6.12 有 BUG。

---

## 7. 关键历史问题与踩坑记录

### 7.1 真实失败原因(已定位根因) 【来自历史记忆】+ 部分【已由代码确认】

- **iperf3 "server is busy"**:`_exec_with_retry` 首次 10s 短超时(控制台探测)< iperf3 `-t 10` 实际 ~12s → 超时中断 iperf3 → SSH 重连 → 远程变孤儿占用单会话 → 重发撞自己造的孤儿。**修复**:`run_iperf3` 传 `probe_console=False`(两 attempt 都用完整 timeout)。【已由代码确认 SSHClient.exec/`_exec_with_retry` 的 probe_console 参数 + run_iperf3 调用处】
- **批量假成功**:footer 按钮子串匹配误中 + UI 只信 toast。**修复**:textContent 精确匹配 + SSH 计数复核 + 3 次重试。【来自历史记忆】
- **GUI"全通过"假象**:flow 类(打流验证)测试没挂 GUI 执行树 → 不跑自然全过。**修复**:补挂 main_window 执行树。【来自历史记忆】
- **基线误 skip**:单域名(baidu)凌晨抖动 http_code=000 → retries 不够直 skip。**修复**:`verify_connectivity`/`concurrent_curl` 加 `fallback_domains` 多域名冗余 + `diagnose_baseline_block` 区分"残留挡流 FAIL" vs "环境 skip"。【已由代码确认方法签名】
- **save 报 code 2006 "写入数据失败"=磁盘满**:`ik_dhcpd` 向 leases.db version 表裸 INSERT 累积撑满 `/etc/mnt`。排查 `df -h /etc/mnt`,清理 `sqlite3 DELETE FROM version; VACUUM`。【来自历史记忆】
- **conn_limit peerconns 6.12 宕机**:固件 10002 已修复;脚本转全局规则绕 xt_set。【来自历史记忆】

### 7.2 不可靠的选择器 / 异步保存重启 / Ant Design 弹窗 【已由代码确认】+【来自历史记忆】

- **不可靠选择器**:select `title="{接口名}({备注})"` 精确匹配 `[title="wan2"]` 失效 → 拆括号 parts 匹配;Ant Select 单选有组合值(如"HTTP+PING+网关")必须精确 `===` 非 `includes`。
- **异步保存/独立页表单**:`_read_save_result` 轮询 6s;`open_add_page` 直接 goto ADD_URL 最可靠;`save_and_wait` 轮询 URL 离开配置页。
- **Ant Design 弹窗**:`.ant-modal-confirm` 常驻隐藏根节点 → strict-mode violation;统一 `_click_visible_confirm`(`:visible` + 短超时)。
- **长跑 SPA**(端口/域名分流):headed 长跑会 "Target crashed" → 用 headless。
- **虚拟滚动**:headless 默认小 viewport → >10 条只渲染 8 条;用 1920×1080。
- **Ant Form 不触发 onChange**:React 原生 setter + dispatch,或 `type(delay)`。

### 7.3 SQLite / Shell / 前缀清理 / 进程端口 / ipset / 导入清空安全风险 【来自历史记忆】+ 部分【已由代码确认】

- **路由器 grep = BusyBox**(v1.23.2):禁 `-P`/`-oP`/`\K`(支持 `-E`/`-oE`/`-w`/`-c`/`-q`/`-v`)。给路由器的 SSH 复核命令只用 BusyBox 子集(去前缀用 `sed 's/pfx//'` 非 `\K`);客户端(10.66.0.18)= GNU grep 支持 `-oP\K`。**判目标看 `self._router.exec`(路由器) vs `bv._client.exec`(客户端)**。backend_verifier 全项目 grep 无一处 `-P`/`\K`,MAC kernel_check 链路 `_read_ipset_ids` 靠 PC 端 Python re 提取不碰路由器 grep。【已由代码确认】
- **ipset hash:mac 存大写**须 `.lower()`。
- **iptables `-D` 对 fastid/`!` 报 "No chain/target"**:cleanup 用 `iptables-save | grep -v | iptables-restore`。
- **DB 明文 JSON 写入冲突**:`UPDATE` 写 JSON 双引号冲突 → base64 编码整 SQL 经 stdin 喂 sqlite3。
- **进程/端口归属**:UDPXY 多实例按 `listen_port` 查非进程名;服务关闭后保留 conf 只停进程(看 `enabled=no` + 进程停,别期望 conf 不存在)。
- **导入清空风险**:FTP `_build_safe_import` 绝不勾"清空现有配置";端口映射导入 DSTNAT BUG。
- **前缀清理误删**:`cleanup_xxx_test(PREFIX)` 只删本前缀,绝不全表 DELETE / `ipset destroy` 非本测试数据。

### 7.4 已证明不可用的做法 vs 推荐做法 【来自历史记忆】

| 不可用做法 | 推荐做法 |
|---|---|
| dhclient 触发 DHCP 获取 | `ip link down/up` 触发 networkd DISCOVER + 轮询 IP |
| 残留检测后台强清掩盖假绿 | 检测到残留=真 BUG 报禅道,`cleanup` 仅 finally 兜底 |
| count_overflow 对上下行 1:2 模块判残留(1 DB=2 iptables 误判) | 改用 `iptables_regex_ids` 按规则 id 去重(上下行同 id 算 1) |
| `curl --interface` 强制路由(只 bind 源 IP) | `ip route add via 路由器 LAN 口` |
| 裸 `fill()` 填 React 表单 | 原生 setter + dispatch / `type(delay)` |
| `[title="wan2"]` 精确匹配 select | 拆括号 parts 匹配 |
| headed 长跑端口/域名分流 | headless |
| 只信 UI toast 判批量成功 | textContent 精确匹配 + SSH 计数 + 重试 |

---

## 8. 当前仓库状态

> ⚠️ 接手者:不要执行 commit / reset / checkout / 清理工作树。以下仅为只读状态说明。

### 8.1 当前 HEAD 背景 【已由代码确认】

- HEAD = `e318ed1` `feat(安全中心): ARP设置/高级设置/其他控制三模块+分流L5修复`。
- 近期提交主线:安全中心 4 模块 → 分流 5 模块 L5 → 限速残留检测 → SSH 验证命令进报告 + iptables 链累加检测 → DHCP 静态 L5 → ACL 功能验证合并。

### 8.2 尚未提交的任务相关修改(git status) 【已由代码确认】

**已修改(未提交)**:
- `.gitignore`、`config/config.py`、`config/settings.yaml`
- `gui/main_window.py`、`gui/test_runner.py`
- `pages/ikuai_table_page.py`
- `pytest.ini`、`tests/conftest.py`
- `utils/backend_verifier.py`、`utils/test_results_to_excel.py`

**未跟踪(新文件)**:
- `build/ikuai_test.spec`(第二份打包 spec)
- `pages/advanced_service/`(FTP 页面对象)
- `tests/advanced_service/`(FTP 综合测试)

> 这些未提交改动主题应为:**新增高级服务-FTP 模块** + 打包 spec + 报告/Excel/GUI 配套调整。接手前应先 `git diff` 理解这些改动的完整意图,再决定是否协助提交。【待进一步确认:用户尚未授权提交】

### 8.3 被 gitignore 的生成文件 【已由代码确认】

`reports/output/`、`reports/screenshots/`、`reports/allure-results/`、`test_data/exports/`、`build/*`(保留两个 `.spec`)、`pages/downloads/`(导出落盘)、各类 `__pycache__`/venv/IDE。

### 8.4 ⚠️ 不允许回退或覆盖的用户修改 【待确认】

- `config/settings.yaml` 含实际环境凭据与 IP,**勿回退或用模板覆盖**(会丢环境配置)。
- 未提交的 `utils/backend_verifier.py`/`tests/conftest.py`/`gui/*` 改动可能是 FTP 模块正在进行的对接,**勿 `git checkout --` 丢弃**。
- 路由器侧 `/etc/mnt/ikuai/fix_sshd_shell.sh` 是环境关键脚本,勿删。

---

## 9. 常用验证命令

> 以下命令在项目根目录 `c:\Users\51355\Desktop\4.0前端UI自动化测试` 执行。Windows 用 Git Bash。

### 9.1 语法/收集检查(不连设备)

```bash
# 1. 语法编译全量 py 文件(快速发现拼写/import 错误)
python -m compileall -q pages tests utils gui config

# 2. pytest 只收集不运行(验证 fixture/marker/nodeid 正确,不连路由器)
python -m pytest --collect-only -q

# 3. 收集单个模块
python -m pytest tests/security/test_acl_comprehensive.py --collect-only -q
```

### 9.2 单模块真实运行(需连设备)

```bash
# headless 跑单模块综合测试(默认 HEADLESS=true)
python -m pytest tests/network/test_vlan_comprehensive.py -s

# 跑安全中心 ACL(综合 CRUD)
python -m pytest tests/security/test_acl_comprehensive.py::TestAclComprehensive -s

# 只跑 ACL 功能验证(打流,~1.5min)
python -m pytest tests/security/test_acl_comprehensive.py::TestAclFlowVerification -s

# 新模块 FTP(强制 SSH)
python -m pytest tests/advanced_service/test_ftp_server_comprehensive.py -s
```

> ⚠️ 部分模块(domain_route/nat_rule/port_map/port_route/updown)在 headless 下可能假 FAIL → 改 headed:`HEADLESS=false python -m pytest <file> -s`。【来自历史记忆】

### 9.3 marker 筛选

```bash
python -m pytest -m acl -s              # 所有 ACL 标记
python -m pytest -m security -s         # 整个安全中心
python -m pytest -m "p0 and not slow"   # P0 冒烟且非慢速
python -m pytest -m ftp_server -s       # FTP 模块
```

### 9.4 HTML / JSON / Excel 检查

```bash
# 最新 HTML 报告(按生成时间)
ls -t reports/output/test_report_*.html | head -1

# 本次测试结果 JSON(GUI/Excel 的数据源)
cat reports/output/test_results.json | python -m json.tool | head -40

# 导出 Excel(读 test_results.json)
python utils/test_results_to_excel.py -i reports/output/test_results.json -o reports/output/test_results.xlsx
```

### 9.5 GUI / 打包检查

```bash
# 启动 GUI(源码模式)
python main.py

# 命令行入口
python run_tests.py tests/network/ -m vlan -v

# 打包(PyInstaller,详见 build/build.bat)
cd build && ./build.bat          # 或 build_portable.bat
```

### 9.6 测试完成后的设备残留审计 【来自历史记忆】+【已由代码确认】

```bash
# 经 SSH 登路由器(sshd),审计本测试前缀残留(以 acl_t_ 为例,路由器 BusyBox grep)
sqlite3 /etc/ikuai/config.db "select * from acl where comment like 'acl_t_%'" -line
iptables -t filter -L FIREWALL -n -v | grep -E 'acl_t_'      # 注意:comment 可能被截断
ipset list | grep -E 'acl_(src|dst)_'                        # ipset 残留

# 客户端(10.66.0.18, GNU grep)审计路由/进程残留
ip route show | grep -E '192.168.148|10.66.0.40'
pgrep -af 'iperf3 -c'
```

> 残留审计目的:确认测试 teardown 干净。发现"删不干净"= 真 BUG 报禅道,**不要后台强清掩盖**。

---

## 10. 给下一位接手者的建议

### 10.1 开始新模块前应先读的文件 【已由代码确认】

按顺序读,建立全局观:

1. 本文件(交接文档)+ [docs/README.md](README.md)(模块总览 + SSH 验证架构图)。
2. [tests/conftest.py](../tests/conftest.py):fixture/marker/中文名映射/报告 hook(项目中枢,~1745 行)。
3. [pages/ikuai_table_page.py](../pages/ikuai_table_page.py):表格 CRUD 中间基类(所有 helper 主力)。
4. [utils/verify_helper.py](../utils/verify_helper.py):`make_ssh_verify`/`make_kernel_check` 工厂(短小精悍,140 行)。
5. 一个**最接近你新模块的范本**:列表型读 `test_vlan_comprehensive.py`+`vlan_page.py`;配置型读 `test_acl_comprehensive.py`+`acl_page.py`;新式服务型读 `test_ftp_server_comprehensive.py`+`ftp_server_page.py`;多子模块数据驱动读 `vpn_test_helper.py`+`vpn_client_base.py`。
6. [config/config.py](../config/config.py):配置/环境变量/打包路径机制。
7. ⚠️ **不要**把 [docs/PLAN.md](PLAN.md) 当事实——它是早期 VLAN 设计草案,部分(如 `utils/browser.py`、报告模板名 `report.html`、`generate()` 方法签名)已与现状不符。

### 10.2 必须先侦察的真实页面和底层脚本 【来自历史记忆】

- **真实 Web 页面**:用 Playwright 或浏览器打开 `http://10.66.0.150/#/<module>`,确认:URL 前缀(`/login#` vs `/#/`)、表单字段名/label、select option 组合值、是否有企业版限制提示、tab 结构。**绝不能凭记忆/旧代码假设选择器**。
- **底层脚本**:SSH 登路由器,看模块对应的 `.sh`(如 `arp.sh`/`acl_l2route.sh`/`stream_updown.sh`/`qos.sh`),理清:DB 表名、iptables 链名、ipset 命名、是否走 ik_cntl 内核(非 iptables)、是否有 time 门控。
- **数据库表**:`sqlite3 /etc/ikuai/config.db ".tables"` + `.schema <表>` 确认字段(JSON 字段是否 base64/明文)。
- **路由器 grep 限制**:复核命令只用 BusyBox 子集(§7.3)。

### 10.3 如何判断测试真正完成(而非只有 UI PASS) 【已由代码确认】

一个模块测试"真正完成"的最低标准:

1. **UI 全链路**:增/删/改/查/启停/批量/搜索/排序/导入/导出/异常输入都覆盖且无遗留 modal。
2. **SSH 后端验证**:至少 L1(DB)+ L2(iptables/进程)硬验证(`must_pass=True`)通过;关键动作(停用/启用/删除/批量)后 `kernel_check` 残留检测通过或暴露真 BUG。
3. **L5 数据面实测**(限速/分流/ACL/DHCP/FTP 等生效类):iperf3/curl/ping/FTP 实测验证"配置真的生效",而非仅静态 SSH 验证。环境不通时软记录 skip,不阻断。
4. **报告可读**:HTML 报告步骤清晰、SSH 验证命令进 details(可复制重跑)、失败用例有截图 + 自动归因;中文名映射正确。
5. **teardown 干净**:finally 清理后无本前缀残留(或残留=已报禅道的真 BUG)。
6. **GUI 注册**:进了 `main_window` 执行树 + conftest fixture + TEST_NAME_MAPPING + settings.yaml module。

> ⚠️ **只有 UI 点通 ≠ 完成**。历史教训:flow 类测试没挂 GUI 执行树 → "全通过"假象。

### 10.4 哪些操作必须先快照再变更 【已由代码确认】+【来自历史记忆】

- **全局配置类模块**(高级设置/其他控制/智能流控总开关/FTP 全局):变更前 `get_<module>_environment_snapshot()`,变更后 `restore_<module>_global()` 原样恢复。
- **模式切换类**(MAC 访问控制黑白名单/DHCP acl mode):切换前记录原 mode,finally 切回。
- **DNS 加速/client DNS**(域名分流 L5 前提):开 DNS 加速 + 改 client DNS 前 snapshot,finally `restore_dns_accel`/`restore_client_dns`。
- **导入测试**:导入前确认"清空现有配置"选项状态;FTP 用 `_build_safe_import` 绝不勾清空。
- **任何会改 iptables/ipset/路由的 SSH 操作**:`mark_cmd_start()` 打标记,便于 `collect_cmds_since_mark()` 审计与回溯。
- **测试数据**:用唯一前缀(PREFIX)隔离,`cleanup_<module>_test(PREFIX)` 只删本前缀。

---

## 附:交接自检清单(本文档生成时已逐项核对)

- [x] 无明文账号/密码/Token/Cookie/私钥(凭据仅说明读取位置与环境变量)
- [x] 路径与代码名称(类名/fixture/函数/marker/nodeid)真实存在,经源码核实
- [x] "历史记忆"与"代码确认"已用标注区分,推测未写成事实
- [x] Markdown 结构完整(10 章 + 附录,UTF-8 中文)
- [x] 未粘贴大段源码(仅引用签名/方法名/行号区间)
- [x] 未修改任何代码/配置/测试数据/报告(仅创建本文件)
