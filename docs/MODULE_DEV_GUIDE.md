# iKuai 4.0 前端UI自动化测试 — 新模块开发指南（Codex 版）

> 本文档面向 AI 编程助手（Codex），描述如何为本项目开发**一个新模块的自动化测试**。所有模式均提炼自已完成的真实模块（ARP设置/MAC访问控制/ACL/限速/分流/DHCP等40+模块）。读完本文 + 参照 [`tests/security/test_arp_setting_comprehensive.py`](../tests/security/test_arp_setting_comprehensive.py) 范本，即可开发任意新模块。

---

## 1. 项目是什么

为 iKuai 路由器 OS 4.0 的 **Web 前端**（Ant Design SPA）做端到端自动化测试。每个功能模块（VLAN/DHCP/ACL/ARP/分流/限速...）写一套 **L1-L5 五层验证**测试：

| 层级 | 验证内容 | 手段 |
|---|---|---|
| **L1** | 数据库 | SSH `sqlite3 /etc/mnt/ikuai/config.db` |
| **L2** | iptables / 静态ARP / 进程 | SSH `iptables -L`、`cat /proc/net/arp` |
| **L3** | ipset / 内核表 | SSH `ipset list`、`cat /proc/ikuai/stats/*` |
| **L4** | 内核模块一致性 | 残留检测（DB vs 底层载体） |
| **L5** | 真实流量打流 | client `curl`/`iperf3 --interface ens11` 经路由器 |

**技术栈**：Python 3.13 + Playwright（驱动浏览器）+ pytest + paramiko（SSH）+ SQLite 解析 + 自研 HTML 报告 + PyQt5 GUI。

**核心思想**：UI 操作（增删改查）→ SSH 到路由器验证底层是否真正生效（不是只看 UI 绿了）。防止"UI 假成功"。

---

## 2. 测试环境（⚠️整套环境稳定不动，勿改路由器配置）

### 2.1 三台设备

#### ① 被测路由 `10.66.0.150`（iKuai 免费版，测试主体）
| 项 | 值 |
|---|---|
| Web 管理 | `http://10.66.0.150` 账号 `admin / admin123` |
| SSH | `sshd / ikuai8.com`（**bash 直连 root**，非交互菜单） |
| 加密控制台后台 | 进入后 `whoami` → 口令 `ik?%.,tudouwumaoqianyijin.,.`（SSHClient 自动交互登录 + 自动部署 `fix_sshd_shell.sh` 防重置） |
| 内核 | `6.12.87`（`uname -r` 确认；⚠️6.12 有回归 bug，见下） |
| 固件 | `10002`（2026-07-09，修复 peerconns 宕机） |
| LAN1 | 接测试 client（网段 `192.168.148.0/24`，网关 `192.168.148.1`） |
| 3 条 WAN | `wan1=10.66.0.150` / `wan2=192.168.112.108` / `wan3=10.66.0.27`（动态，`ip -4 addr show wan3`） |
| 策略路由 fwmark | `0x2711 → wan1` / `0x2712 → wan2` / `0x2713 → wan3` |
| 底层脚本 | `/usr/ikuai/script/<模块>.sh`（每功能一脚本，DB→iptables/ipset/内核下发） |
| 配置库 | `/etc/mnt/ikuai/config.db`（SQLite，`sqlite3 -line` 查） |

⚠️ **勿触发"其他选项→技术维护通道"**，会导致 SSH 22 关闭不可恢复。

#### ② 测试 client `10.66.0.18`（Ubuntu，打流发起方）
| 项 | 值 |
|---|---|
| 外网网卡 | `enp2s0` = `10.66.0.18`（管理网，SSH 走此，**不经路由器**） |
| 内网网卡 | `ens11` = `192.168.148.2`（接路由器 LAN1，**打流走此**） |
| SSH | `iktest / iktest` |
| 打流命令 | `curl --interface ens11 <url>` / `iperf3 --interface ens11 -c <server>`（强制流量经路由器） |

#### ③ iperf3 / VPN 服务端 `10.66.0.40`（企业版，打流目标 + VPN 对端）
| 项 | 值 |
|---|---|
| Web | `admin / admin123` |
| SSH | `sshd / ikuai8.com`（bash 直连 root） |
| iperf3 服务端 | 端口 `5201` |
| VPN 服务端 | PPTP / L2TP / OpenVPN / IKEv2，账号 `test / test` |
| 用途 | 被测路由 `10.66.0.150` 做 VPN 客户端连此；iperf3 打流目标 |

### 2.2 网络拓扑
```
[client 10.66.0.18]                    [服务端 10.66.0.40]
   外 enp2s0(管理SSH)                       iperf3:5201 / VPN服务端
   内 ens11=192.168.148.2                   |
        | LAN1                              | WAN
        v                                   v
        +------>[被测路由 10.66.0.150]<------+
                   WAN1=10.66.0.150 / WAN2=192.168.112.108 / WAN3=10.66.0.27
```
client 的 `ens11` 流量 → 路由器 LAN1 → 路由器转发/限速/分流/VPN → WAN → 外网或 10.66.0.40。所有 L5 打流经此路径验证规则是否生效。

### 2.3 关键注意事项
- **client 经路由器打流**：必须 `--interface ens11`（默认走 enp2s0 管理网会绕过路由器，测试失效）。
- **路由器是 BusyBox**（v1.23.2）：grep **禁** `-P`/`-oP`/`\K`，只支持 `-E -o -w -c -q -v`。给路由器写的 SSH 命令只用 BusyBox 子集（去前缀用 `sed 's/pfx//'` 非 `\K`）；复杂正则解析放 PC 端 Python `re`。client（10.66.0.18）是 GNU grep，支持 `-oP`/`\K`。**判目标看前缀**：`self._router.exec`（路由器）vs `bv._client.exec`（client）。
- **Windows 控制台 GBK**：日志/报告避免 emoji（`✓` 等会 `UnicodeEncodeError`），用 `[OK]`/`[FAIL]`。从 JSON 报告提取详情时设 `PYTHONIOENCODING=utf-8`。
- **6.12 内核回归**（踩坑前先 `uname -r`）：`xt_set` 间歇损坏（iptables `-m set` 报 `errno=22`），影响 ACL/MAC访问控制/ARP/conn_limit 等依赖 ipset 的功能 → `is_xt_set_broken()` 动态探测降级。peerconns 宕机已由固件 10002 修复。
- **环境稳定不动**：3 台设备 IP/网卡/凭据固定，勿改路由器 WAN/LAN 配置，避免影响其他模块测试。

### 2.4 配置文件 `config/settings.yaml`
设备/SSH/浏览器配置在此（`config/config.py` 的 `Config.from_yaml` 加载）。也支持环境变量覆盖（`DEVICE_IP`/`SSH_ROUTER_HOST`/`SSH_CONSOLE_PASSWORD` 等，GUI 传参用）。默认值即上述环境。

---

## 3. 目录结构

```
4.0前端UI自动化测试/
├── pages/                  # Page Object（UI 操作封装）
│   ├── base_page.py        # BasePage：Playwright 原语 + 帮助方法
│   ├── ikuai_table_page.py # IkuaiTablePage：表格 CRUD 通用（行操作/批量/导入导出/确认弹窗）
│   ├── network/            # 网络配置模块 page
│   └── security/           # 安全中心模块 page（acl_page.py / mac_access_control_page.py / arp_setting_page.py ...）
├── tests/
│   ├── conftest.py         # ⭐ 全局 fixture（page/browser/logged_in/backend_verifier）+ TEST_NAME_MAPPING + marker
│   ├── network/            # 网络模块 test
│   └── security/           # 安全模块 test
├── utils/
│   ├── backend_verifier.py # ⭐⭐ SSH 后端验证器（L1-L5 全在这里，2万+行，按模块分块）
│   ├── step_recorder.py    # 步骤记录器（rec.step / add_detail → HTML 报告卡片）
│   ├── verify_helper.py    # ssh_verify/kernel_check 闭包工厂 + 命令录制
│   └── report_generator.py # HTML 报告生成
├── config/
│   ├── config.py           # 配置数据类（Device/Browser/SSH/Report）
│   └── settings.yaml       # 设备 IP/凭据/headless 等
├── pytest.ini              # marker 注册
├── reports/output/         # 测试报告（HTML + test_results.json）
└── test_data/exports/<module>/  # 导出的 csv/txt（导入测试用）
```

---

## 4. 开发新模块：4 个文件（标准流程）

以"安全中心 > XXX"模块为例。**先 SSH 看底层脚本 + Playwright 探索 UI，再写代码。**

### 探索阶段（必做，勿跳）
1. **SSH 读底层脚本**：`cat /usr/ikuai/script/<module>.sh`。重点看：DB 表名/字段、iptables/ipset 下发逻辑、`register_module_urls`（API 路径）、`init()`/`add()`/`del()`/`seting()`。
2. **Playwright 探索 UI**：登录 `http://10.66.0.150/login#/login`，点菜单找模块，记录：URL hash、Tab、表格列、表单字段（input id/placeholder、select 选项）、特殊按钮（设置弹窗/清空/绑定）。
3. **SSH 看现状**：`sqlite3 DB ".schema <表>"` + `select * from <表>` + `ipset list -n | grep <模块>` + `iptables -L <链>`，确认空态/默认值。

### 文件 1：Page Object（`pages/<分组>/<module>_page.py`）

**继承选择**：
- 有表格 CRUD（增删改查/批量/导入导出）→ 继承 `AclPage`（它继承 `IkuaiTablePage`，复用最多）
- 简单表单（无表格）→ 继承 `BasePage`

**范本**：[`pages/security/arp_setting_page.py`](../pages/security/arp_setting_page.py)（最全，含 Tab/设置弹窗/特有操作）。最小骨架：

```python
from typing import Optional, List, Dict
from playwright.sync_api import Page
from pages.security.acl_page import AclPage

class XxxPage(AclPage):
    MODULE_NAME = "xxx"
    LIST_URL = "/login#/securityCenter/xxx"
    ADD_URL = "/login#/securityCenter/xxx/add"   # 独立配置页路由

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    def navigate_to_xxx(self):
        """导航到列表页"""
        try: self._dismiss_all_modals()   # ⭐ 清残留 modal，避免遮挡 Tab
        except: pass
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try: self.page.wait_for_load_state("networkidle", timeout=15000)
        except: pass
        self.page.wait_for_timeout(2500)
        return self

    def open_add_page(self) -> bool:
        """直接 goto 配置页（最可靠，避开列表点添加的时序竞争）"""
        try: self._dismiss_all_modals()
        except: pass
        try:
            self.page.evaluate(f"location.hash='{self.LIST_URL.split('#')[1]}'")  # 先回列表清 SPA 残留
            self.page.wait_for_timeout(1200)
        except: pass
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        try: self.page.wait_for_load_state("networkidle", timeout=15000)
        except: pass
        self.page.wait_for_timeout(2500)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        return "xxx/add" in self.page.url or "xxx/edit" in self.page.url

    def is_still_on_config_page(self) -> bool:
        return "xxx/add" in self.page.url or "xxx/edit" in self.page.url

    def save_and_wait(self, timeout: int = 8000) -> dict:
        """⭐ 重写：成功=URL 离开配置页(跳回列表)。AclPage 版硬编码 aclRulesConfig，必须重写"""
        result = {"success": False, "error": ""}
        try:
            self.click_save()
            for _ in range(int(timeout / 400)):
                self.page.wait_for_timeout(400)
                err = self.has_form_error()
                if err:
                    result["error"] = err; return result
                if not self.is_still_on_config_page():
                    result["success"] = True; return result
            result["error"] = "保存后仍在配置页"
        except Exception as e:
            result["error"] = str(e)[:80]
        return result

    def add_rule(self, name, **kwargs) -> dict:
        """完整添加流程，返回 {success, error}"""
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"; return result
            self.fill_name(name)
            # ...填其他字段...
            sv = self.save_and_wait()
            result["success"] = sv["success"]
            result["error"] = sv["error"]
        except Exception as e:
            result["error"] = str(e)[:120]
        return result
```

**AclPage 可直接复用的方法**（不用重写）：
- `fill_name(name)` — placeholder=请输入名称
- `fill_remark(text)` — textarea 备注（label 关联定位）
- `_select_by_label(label, option)` — ⭐ select 通用（按 form-item-label 精确匹配，Playwright click 打开 dropdown + 点 option）
- `click_save()` / `has_form_error()` / `_dismiss_all_modals()` / `_click_visible_confirm()`
- `delete_rule(name)` / `edit_rule(name)` / `disable_rule` / `enable_rule` — 行操作（div.ant-table-row + ant-modal 确认）
- `rule_exists(name)` / `get_rule_count()` / `get_rule_names()` / `clean_test_rules(prefix)`
- `export_rules(export_format)` / `import_rules(file, clear_existing)` / `search_rule(kw)` / `select_all_rules()` / `batch_delete()`

**IkuaiTablePage 的 `_click_visible_confirm`**：用 `.ant-btn-primary:visible`（CSS 类，不依赖按钮文案），所以删除/批量确认都能点到。**但特殊确认按钮**（如 ARP 清空的"确认清空"）需显式定位。

### 文件 2：backend_verifier 扩展（`utils/backend_verifier.py`）

在文件中找到对应模块分区（如 MAC访问控制方法块后），新增 `verify_xxx_*` 方法。**范本**：ARP 方法块（搜索 `# ==================== ARP设置`）。

```python
# ==================== XXX模块 (安全中心 > XXX) ====================
# 注释写清: DB表/字段, iptables/ipset机制, 关键坑
def find_xxx_rule(self, key) -> Optional[Dict]:
    """按名称/关键字查"""
    return self._sqlite_query_line(f"SELECT * FROM <表> WHERE tagname='{key}'")

def verify_xxx_database(self, tagname, expected_fields=None, **kw) -> VerifyResult:
    """L1: DB存在+字段正确"""
    rule = self.find_xxx_rule(tagname)
    if rule is None:
        return VerifyResult(level="L1-数据库", passed=False, message=f"规则未找到: {tagname}")
    mismatches = {}
    if expected_fields:
        for k, exp in expected_fields.items():
            if str(rule.get(k, "")) != str(exp):
                mismatches[k] = {"expected": exp, "actual": rule.get(k)}
    if mismatches:
        return VerifyResult(level="L1-数据库", passed=False, message=f"字段不匹配: {mismatches}",
                            raw_output=json.dumps(rule, ensure_ascii=False)[:300])
    return VerifyResult(level="L1-数据库", passed=True, message=f"规则存在且字段正确 (id={rule.get('id')})",
                        details={"rule": rule}, raw_output=json.dumps(rule, ensure_ascii=False)[:300])

def verify_xxx_not_exists(self, key) -> VerifyResult:
    """L1: 已删除"""
    return VerifyResult(level="L1-删除验证", passed=self.find_xxx_rule(key) is None,
                        message=f"{'已删除' if self.find_xxx_rule(key) is None else '仍存在'}: {key}")

def verify_xxx_count(self, prefix=None) -> VerifyResult:
    """L1: 计数"""
    if prefix:
        rows = self._sqlite_query_list(f"SELECT tagname FROM <表> WHERE tagname LIKE '{prefix}%'")
        n = len(rows)
    else:
        row = self._sqlite_query_line("SELECT count(*) as cnt FROM <表>")
        n = int(row.get("cnt", 0)) if row else 0
    return VerifyResult(level="L1-计数", passed=True, message=f"数量: {n}")

def cleanup_xxx_test(self, prefix="xxx_t_") -> str:
    """清理: DELETE prefix + 恢复全局开关 + <脚本>.sh init 重建底层"""
    self.connect_router()
    try:
        rows = self._sqlite_query_list(f"SELECT tagname FROM <表> WHERE tagname LIKE '{prefix}%'")
        self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM <表> WHERE tagname LIKE '{prefix}%'\"")
        self._router.exec("/usr/ikuai/script/<module>.sh init 2>/dev/null")
        return f"deleted {len(rows)} rules"
    except Exception as e:
        return f"error: {e}"
```

**L5 不用新增**：直接复用 `verify_connectivity(src_iface="ens11", dst_domain=, dst_ip=, retries=, fallback_domains=)` 和 `is_xt_set_broken()`。

**关键基础方法**：
- `_sqlite_query_line(sql)` → dict（`key = value` 解析）
- `_sqlite_query_list(sql)` → List[dict]（空行分隔记录）
- `VerifyResult(level, passed, message, details={}, raw_output="")` — 所有 verify 方法返回它
- `DNS_DB = "/etc/mnt/ikuai/config.db"`（类属性）
- `connect_router()` / `connect_client()` / `is_xt_set_broken()` / `xt_set_degrade_result()`

### 文件 3：Test 文件（`tests/<分组>/test_<module>_comprehensive.py`）

**范本**：[`tests/security/test_arp_setting_comprehensive.py`](../tests/security/test_arp_setting_comprehensive.py)。结构固定：

```python
import os, pytest
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure

pytestmark = [pytest.mark.security, pytest.mark.<module>]   # 文件级 marker

PREFIX = "xxx_t_"      # ⭐ 测试数据隔离前缀（只清理自己创建的）
# 测试数据常量（ip/mac/name）

class TestXxxComprehensive:
    def test_xxx_comprehensive(self, xxx_page_logged_in, step_recorder: StepRecorder, request):
        page = xxx_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')   # ⭐ try/except 兼容无SSH
        except Exception:
            backend_verifier = None

        ui_failures = []
        ssh_failures = []

        # ===== 闭包1: SSH 验证（软收集，失败进 ssh_failures）=====
        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            if backend_verifier is None:
                rec.add_detail(f"[SSH-{label}] 跳过(无SSH验证器)"); return None
            try:
                result = verify_func(*args, **kwargs)
                status = 'PASS' if result.passed else 'FAIL'
                rec.add_detail(f"[SSH-{label}] {status}: {result.message}")
                rec.add_detail(f"    后端数据: {(result.raw_output or '')[:180]}")
                if not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
                ssh_failures.append(f"SSH-{label}异常: {str(e)[:80]}")
                return None
        ssh_verify = attach_cmd_recording_to_closure(backend_verifier, rec, ssh_verify)

        # ===== 闭包2: UI 检查 =====
        def ui_check(label, cond, detail=""):
            if cond:
                rec.add_detail(f"[UI] {label}: 成功")
            else:
                rec.add_detail(f"[UI] {label}: 失败 - {detail}")
                ui_failures.append(f"{label}: {detail}")

        # ===== 闭包3: 底层残留检测（可选）=====
        def kernel_check(label, ...):
            ...   # 调 verify_module_kernel_consistency 或 verify_xxx_ipset(expect_present=False)

        try:
            with rec.step("步骤1: 环境快照+清理", "清xxx_t_残留+确认初始态"):
                if backend_verifier:
                    backend_verifier.cleanup_xxx_test(PREFIX)
                page.navigate_to_xxx()
                page.clean_test_rules(PREFIX)

            with rec.step("步骤2: 场景1 ...", "添加+SSH L1/L2/L3"):
                res = page.add_rule(...)
                ui_check("添加", res["success"], res.get("error", ""))
                ssh_verify("L1数据库", backend_verifier.verify_xxx_database, ...)
                ssh_verify("L2 iptables", backend_verifier.verify_xxx_iptables, ...)
                ssh_verify("L3 ipset", backend_verifier.verify_xxx_ipset, ...)

            # ... 步骤3-N ...

            with rec.step("步骤N: L5功能验证", "基线→建规则→效果→恢复"):
                if backend_verifier is None:
                    rec.add_detail("[L5] 跳过")
                else:
                    backend_verifier.connect_client()
                    base = backend_verifier.verify_connectivity(dst_domain="www.baidu.com", retries=2,
                                                                fallback_domains=["www.qq.com", "cn.bing.com"])
                    # 建规则...
                    blk = backend_verifier.verify_connectivity(dst_domain="www.baidu.com")  # ⚠️不传retries,否则掩盖效果
                    if not blk["connected"]:
                        rec.add_detail("✓ 规则生效")
                    else:
                        ui_failures.append(f"步骤N: 规则未生效: {blk['detail']}")
                    # 恢复...
        finally:
            # ⭐ finally 兜底清理（前端 + SSH + 残留检测）
            try:
                page.navigate_to_xxx()
                page.clean_test_rules(PREFIX)
            except Exception as e:
                rec.add_detail(f"[finally清理异常] {str(e)[:60]}")
            if backend_verifier:
                backend_verifier.cleanup_xxx_test(PREFIX)

        # ⭐ 末尾硬断言
        all_failures = ssh_failures + ui_failures
        assert not all_failures, f"XXX验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
```

**步骤设计原则**（参照 MAC访问控制16步 / ARP 18步）：
1. 环境快照+清理 → 2-4. CRUD 场景(单条/多条/全字段) L1-L3 → 5.计数 → 6.搜索 → 7.编辑 → 8-9.模块特有操作 → 10.删除+残留检测 → 11.模式/类型切换 → 12-13.设置开关 → 14.异常输入 → 15.导出 → 16.导入 → 17.只读子页 → 18.L5打流。

### 文件 4：注册（`tests/conftest.py` + `pytest.ini`）

**conftest.py 改 3 处**（参照 mac_access_control）：
```python
# 1. import（顶部）
from pages.security.xxx_page import XxxPage

# 2. TEST_NAME_MAPPING 字典（报告中文显示名）
'test_xxx_comprehensive': '安全中心-XXX综合测试',

# 3. fixture（参照 mac_access_control_page，~930行）
@pytest.fixture(scope="function")
def xxx_page(page: Page, config: Config) -> XxxPage:
    return XxxPage(page, config.get_base_url())

@pytest.fixture(scope="function")
def xxx_page_logged_in(logged_in_page: Page, config: Config) -> XxxPage:
    pg = XxxPage(logged_in_page, config.get_base_url())
    pg.navigate_to_xxx()
    return pg
```

**pytest.ini**：`markers` 段加 `xxx: XXX模块测试`。

---

## 5. 关键模式

### 5.1 Page Object 继承链
```
BasePage (Playwright 原语 + screenshot/wait_for_*)
  └─ IkuaiTablePage (表格 CRUD: _click_rule_button/delete/edit/batch/export/import/search/select_all + _click_visible_confirm)
       └─ AclPage (form 字段: _select_by_label/fill_name/fill_remark/click_save/save_and_wait/open_add_page + _dismiss_all_modals)
            └─ 具体模块 Page (特有字段/Tab/弹窗)
```
**优先复用父类**，只写模块特有的。`save_and_wait` 几乎总要重写（判断 URL 是否离开配置页，每模块 URL 不同）。

### 5.2 test 闭包三件套
- `ssh_verify(label, func, *args)` — 软收集 SSH 验证结果，PASS/FAIL 进报告，失败累积到 `ssh_failures`（不立即抛异常，跑完全部步骤再统一断言）。
- `ui_check(label, cond, detail)` — UI 断言同上，进 `ui_failures`。
- `kernel_check(label)` — 底层残留检测（删不干净=产品 bug，硬 FAIL + 报禅道）。
- 末尾 `assert not (ssh_failures + ui_failures)` — 全部步骤跑完后统一断言。

### 5.3 步骤记录
`with rec.step("步骤N: 标题", "副标题"):` 是上下文管理器，自动管理报告卡片。块内 `rec.add_detail("...")` 加详情。异常自动标记 failed。

### 5.4 数据隔离
`PREFIX = "xxx_t_"`。所有测试创建的规则用此前缀，`clean_test_rules(PREFIX)` 和 `cleanup_xxx_test(PREFIX)` 只清理自己的，不误删用户已有规则。

---

## 6. UI 踩坑大全（Ant Design + iKuai，用 MCP Playwright 实测确认）

1. **select 匹配**：选项常是"{备注}({接口名})"格式。`_select_by_label` 精确匹配 label，option 用精确 `===`（组合值用 includes 会误中，如"HTTP+PING+网关"）。多选 select 用 mousedown；虚拟滚动用 JS scrollIntoView。
2. **React 表单不触发 onChange**：用 `type(text, delay=30)` 或 React 原生 setter + dispatch Event。`fill()` 可能不触发。
3. **必填校验**：label 带 `*`/`ant-form-item-required`。但**有些非必填字段空值也报错**（如 ARP 终端名称"字段验证错误终端名称"，后端/API 校验）→ 实测确认，必要时默认填值。
4. **modal 遮挡**：`.ant-modal-wrap` 残留会遮挡 Tab/按钮点击（intercepts pointer events，30s 超时）。导航前 `_dismiss_all_modals()`。
5. **确认弹窗按钮文案不固定**：删除通常是"确定"，但清空可能是"确认清空"。`_click_visible_confirm` 用 `.ant-btn-primary` 兜底；特殊按钮显式定位。
6. **独立页表单异步跳转**：保存后 URL 异步变化，`save_and_wait` 轮询 6-8s。`open_add_page` 直接 goto 配置页最可靠（避开列表点添加的时序竞争）。
7. **tagname/名称限 15 字符**：超限后端静默截断不报错 → find/delete 按完整名查不到误判失败。PREFIX 用短前缀。
8. **搜索框字段限制**：某些列表搜索不查名称字段（如 ARP 只查 IP/MAC/网卡）→ 搜索测试用能命中的字段（IP）。
9. **tab 切换**：`.ant-tabs-tab:has-text('名称')` + `.ant-tabs-tab-active` 确认。Segmented 点 `label.ant-segmented-item`。
10. **checkbox**：点 `.ant-checkbox-wrapper`（不是 input）。读状态用 `input.checked` 或 `.ant-checkbox-checked`。
11. **虚拟滚动表格**：行是 `div.ant-table-row`（非 `tr`）。`_click_rule_button` 用"文本锚点+JS 向上找 button"。用 `.ant-table-cell` 结构化读列（innerText split 易错位）。
12. **企业版专属功能**（IKE/WG 等）：免费版不渲染添加按钮 → `_detect_enterprise_block` + skip。
13. **长跑 SPA**（端口/域名分流）：用 headed，headless 长跑会 "Target crashed"。

---

## 7. 后端验证模式（SSH）

- **SSHClient**（`utils/backend_verifier.py` 顶部）：`sshd=bash 直连 root`；`exec(cmd, timeout)` 执行。控制台登录用 `console_username/password`（交互式菜单）。
- **SQLite**：`sqlite3 DB -line "SQL"` → `_sqlite_query_line/list` 解析 `key = value`。**勿在 SQL 里拼用户输入做 production，但测试固定数据 OK**。
- **iptables**：用 `-L <链> -n -v`（**非 `-S`**，iKuai `-S` 对部分链返回空）。comment 格式 `/* {id}_{tagname} */`，正则 `/\*\s*(\d+)(?:_|\s*\*/)` 提 id。
- **ipset**：`ipset list <name>` 看成员。`hash:mac` 存**小写**（比对前 `.lower()`）。
- **xt_set 6.12 间歇 bug**：iptables `-m set` 偶发 `errno=22`。`is_xt_set_broken()` 探测（session 缓存），坏时 `xt_set_degrade_result()` 返回软记录（passed=True 不阻断，报禅道），内核修复后自动恢复硬验证。
- **/proc/net/arp 列序**：`[0]IP [1]HWtype(0x1) [2]Flags(0x6静/0x2动) [3]MAC [4]Mask [5]Device`。flags = **MAC 前一个 0x 字段**（避开 HWtype=0x1）。
- **残留检测哲学**：web 还原 → 检测底层残留 → 有残留=产品 bug（删不干净），**硬 FAIL + 报禅道，绝不后台强清掩盖**（早期 finally 强清是错的）。

---

## 8. L5 打流验证模式

**三段式**（以"阻断/放行"类规则为例）：
```python
# 1. 基线（期望通）：传 retries + fallback，抗外网抖动
base = bv.verify_connectivity(dst_domain="www.baidu.com", retries=2,
                              fallback_domains=["www.qq.com", "cn.bing.com"])
# 2. 建规则后（期望不通）：⚠️不传 retries/fallback，否则掩盖规则效果
blk = bv.verify_connectivity(dst_domain="www.baidu.com")
if blk["connected"]:   # 该不通却通=规则未生效
    ui_failures.append(...)
# 3. 删规则恢复（期望通）
restore = bv.verify_connectivity(dst_domain="www.baidu.com", retries=2, fallback_domains=[...])
```

**白名单机制**（如 ARP arp_filter）：基线通 → 开白名单+未绑定不通 → 绑定后通 → 关闭恢复。

**关键**：
- `dst_domain` 用 curl（HTTP），`dst_ip` 用 ping（ICMP）。上游禁 ICMP 时用 curl。
- 单域名抖动（baidu 凌晨 http=000）→ fallback 多域名。
- iperf3 测速用 `run_iperf3(direction, server_ip, bind_ip, duration, probe_console=False)`（⚠️长命令必须 `probe_console=False` 绕过控制台探测短超时，否则 iperf3 变孤儿占服务端→"server is busy"）。

---

## 9. 调试流程

1. **MCP Playwright 探索**：`browser_navigate` → `browser_snapshot`/`browser_evaluate`（提取 DOM 结构：label/placeholder/select选项/按钮）。`browser_take_screenshot` + `analyze_image` 看视觉。
2. **SSH 验证假设**：`ssh_exec` 看脚本/DB/iptables/ipset，确认机制。
3. **写代码** → `python -m py_compile <files>` 检查语法。
4. **`pytest tests/.../test_xxx_comprehensive.py --collect-only`** 确认 import/fixture/marker 无误。
5. **`pytest tests/.../test_xxx_comprehensive.py -s`** 跑（headed，涉打流/弹窗时勿 headless）。看 stdout 的 `[SSH-xxx] PASS/FAIL` + 末尾断言。
6. **看报告**：`reports/output/test_report_*.html`（步骤卡片+详情）+ `test_results.json`（结构化，用 python 提取步骤详情）。
7. **失败定位**：从断言的 failures 列表逐项排查。UI 失败→Playwright 复现；SSH 失败→手动 SSH 复核命令（路由器用 BusyBox grep 子集）。
8. **环境清理**：测试 finally 应自清理；手动清理用 `sqlite3 DELETE + <脚本>.sh init`。

**常见失败根因**（按频次）：
- 终端名称/某字段空值校验 → 默认填值
- select 选项格式/匹配 → Playwright 实测选项文本
- modal 遮挡 → 导航前 `_dismiss_all_modals`
- 解析列错位（/proc/net/arp 等）→ 用字段特征匹配非固定索引
- 搜索不查某字段 → 换搜索关键字

---

## 10. 完整范本：ARP 设置（最新最全，照抄结构）

- 探索：2 Tab（ARP绑定/邻居列表）+ 设置弹窗 2 复选框（arp_filter/dhcpd_arp）+ ARP特有清空/绑定操作
- 机制纠正：`arp.sh` 的 `arp -s` 在 `if bind_type==1` 块**外** → bind_type 0/1 都建静态 ARP
- 18 步全 PASS，L5 三段式实测（http 200→000→200）
- 文件：[`pages/security/arp_setting_page.py`](../pages/security/arp_setting_page.py) / [`tests/security/test_arp_setting_comprehensive.py`](../tests/security/test_arp_setting_comprehensive.py) / backend_verifier ARP 方法块

其他范本：MAC访问控制（黑白名单radio+L5阻断）、ACL（select最多+地址block）、智能流控（QoS机制）、分流策略（5子模块+选路铁证）。

---

## 11. 约定速查

| 项 | 约定 |
|---|---|
| 文件命名 | `test_<module>_comprehensive.py` / `<module>_page.py` |
| 测试类 | `Test<Module>Comprehensive`，单方法 `test_<module>_comprehensive` |
| 数据前缀 | `PREFIX = "<module>_t_"`（短，避 15 字符截断） |
| marker | `pytestmark = [pytest.mark.security/network, pytest.mark.<module>]` |
| 报告名 | conftest `TEST_NAME_MAPPING` 映射中文 |
| 失败处理 | 软收集到 `*_failures`，末尾统一 `assert` |
| 清理 | finally：前端 `clean_test_rules` + SSH `cleanup_xxx_test` + 残留检测 |
| 日志 | 中文，避免 emoji（GBK），用 `[OK]`/`[FAIL]` |
| 路由器 grep | BusyBox，禁 `-P`/`\K`；复杂解析放 PC 端 Python |
| 跑法 | `pytest tests/.../test_xxx_comprehensive.py -s`（headed） |

---

**开发新模块 Checklist**：
- [ ] SSH 读 `/usr/ikuai/script/<module>.sh`，记 DB表/字段/iptables/ipset 机制
- [ ] Playwright 探索 UI，记 URL/Tab/表单字段/特殊按钮
- [ ] 写 page object（继承 AclPage，重写 save_and_wait）
- [ ] 扩展 backend_verifier（find/verify L1-L3/cleanup）
- [ ] 写 test（ssh_verify/ui_check 闭包 + 18步 + finally + assert）
- [ ] 注册 conftest fixture + TEST_NAME_MAPPING + pytest.ini marker
- [ ] py_compile → collect-only → pytest -s 跑通
- [ ] 看报告确认 L1-L5 全 PASS，翻 [WARN]/SSH-[FAIL]
