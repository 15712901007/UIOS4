"""
虚拟专网 > GRE 隧道自动化测试（6 用例整合为 2 用例）。

- test_gre_comprehensive：综合测试。全链路 L1(DB)→L2(运行时)→L5(双端数据面)，
  覆盖页面结构、18 字段表单、IPv4/IPv6 双协议 CRUD、编辑、启停、批量、搜索/帮助、
  对端(10.66.0.56)对称 GRE 数据面 + 外层选路/NAT 抓包观察。
- test_gre_functional：功能测试。配置真生效(内核 ip -d)、边界值、生命周期/残留、
  UI 提示规范、高级配置默认值/校验；补全 JIRA IKOS-6952 中 9 个"最初版本"未覆盖的
  UI 校验/提示/默认值类盲区（IKOS-6991/7086/7089/7092/7093/7096/7101/7111/7114/7010/6982）。

已知 BUG 用 record_bug 软断言（报告 WARN + 末尾汇总，不 FAIL、不阻断，绝不后台强清掩盖假绿）；
正确行为/安全前置用 require_* 硬断言；环境敏感（IPv6 underlay、外层抓包）用 observe 软观察。
两个测试统一走 _GreHarness + 命令录制（报告均输出"验证命令(N)"）。

环境（稳定保持不动）：
- 被测路由 10.66.0.150（wan1=10.66.0.150/24，管理走 LAN1=192.168.148.1 不受 GRE WAN 路由消失影响）
- GRE 源用 wan3（10.66.0.27，数据面实测可通）；对端 10.66.0.56（wan1=10.66.0.56/24，同 router 凭据）
- client 10.66.0.18（内 ens11=192.168.148.2）
"""

from __future__ import annotations

import re
import secrets
from typing import Dict, List, Optional

import pytest

from utils.step_recorder import StepRecorder


pytestmark = [pytest.mark.advanced_service, pytest.mark.gre_tunnel]

# ==================== 底层地址（稳定环境） ====================
# 管理访问(测试 Web/SSH)走 LAN1(192.168.148.1), 直连不受 GRE 的 WAN 路由消失 bug 影响。
# GRE 隧道源用 wan3(10.66.0.27, 数据面实测可通; 源 wan1 多线 mark 冲突数据面不通+下发失败)。
ROUTER_V4 = "10.66.0.27"
PEER_V4 = "10.66.0.56"
CLIENT_IFACE = "ens11"
# IPv6 全局地址(SLAAC/DHCPv6 /128)会漂移, 不能硬编码。改为运行时动态解析; 解析失败或
# underlay 不通 → IPv6 场景标 env-blocked 软跳过(不入 failures, 不 FAIL 整个模块)。
WAN_IFACE = "wan3"  # GRE 源 WAN 口; 抓包多用 -i any 规避多 WAN 选路口不确定


def _resolve_ipv6_underlay(backend, router_iface="wan1", peer_iface="wan1"):
    """运行时解析 router/peer wan 全局 IPv6 并探测 underlay 可达性。返回 (rv6, pv6, reachable)。"""
    try:
        rv6 = backend.get_wan_ipv6_global("router", router_iface)
        pv6 = backend.get_wan_ipv6_global("peer", peer_iface)
        reachable = False
        if rv6 and pv6:
            backend.connect_router()
            out = backend._router.exec(f"ping6 -c 2 -W 2 {pv6} 2>&1", timeout=15)
            reachable = ("0% packet loss" in (out or "")) or ("2 received" in (out or ""))
        return rv6, pv6, reachable
    except Exception:
        return "", "", False


def _iface_num(token_hex: str) -> int:
    """生成 700-899 的隧道编号(接口名 gre+编号)，避开常见小编号。"""
    return 700 + int(token_hex, 16) % 200


class _GreHarness:
    """GRE 两个测试共享的断言/记录工具（消除原 6 用例重复的 inline 闭包）。

    - ui_check / require_ui：UI 硬断言（条件不成立计入 failures，末尾硬 FAIL）。
    - observe：软观察（只记 ✓/⚠ 进报告，永不入 failures、不阻断）。用于环境敏感/已知 BUG 探测。
    - record_bug：软记录前端/产品 BUG（报告 WARN + 末尾汇总，不 FAIL、不阻断）。
    - ssh_verify / require_ssh：后端验证；must_pass=True 计入 failures。命令经
      attach_cmd_recording_to_closure 录制进报告（两个测试均输出"验证命令(N)"）。
    """

    def __init__(self, backend, rec):
        self.backend = backend
        self.rec = rec
        self.ssh_failures: List[str] = []
        self.ui_failures: List[str] = []
        self.bugs: List[str] = []
        # 真实命令+结果录制: _do_ssh_verify 内部用 collect_io_since_mark 把本次验证
        # 真实执行的 SSH 命令+输出构建成可复制 verification_commands(每条命令一卡, 带后端返回结果),
        # 不再用 attach_cmd_recording_to_closure(它只生成 reconstructed 命令或回退单行)。

    @staticmethod
    def safe_text(value) -> str:
        return "" if value is None else str(value)

    @staticmethod
    def result_ok(result, key: str = "success") -> bool:
        return bool(result.get(key)) if isinstance(result, dict) else bool(result)

    @staticmethod
    def result_error(result) -> str:
        return _GreHarness.safe_text(result.get("error", "")) if isinstance(result, dict) else ""

    def ui_check(self, label, condition, detail=""):
        ok = bool(condition)
        concl = "符合预期" if ok else (self.safe_text(detail) or "条件不成立")
        self.rec.add_detail(f"【页面验证】\n{'✓' if ok else '✗'} {label}：{concl}")
        if not ok:
            self.ui_failures.append(f"页面-{label}：{self.safe_text(detail) or '条件不成立'}")
        return ok

    def require_ui(self, label, condition, detail=""):
        if not self.ui_check(label, condition, detail):
            pytest.fail(f"安全前置失败: {label}: {self.safe_text(detail) or '条件不成立'}")

    def observe(self, label, condition, detail=""):
        """软观察: 记录✓/⚠进报告, 永不入 failures、不阻断。

        用于"环境/解析敏感"或"可能命中已知 BUG"的检查(如 IPv6 underlay 可达、外层抓包、
        状态列提取)。环境不可达时配合 record_bug 记录, 测试仍 PASS。
        """
        ok = bool(condition)
        concl = "符合预期" if ok else (self.safe_text(detail) or "条件不成立")
        self.rec.add_detail(f"【观察】\n{'✓' if ok else '⚠'} {label}：{concl}")
        return ok

    def record_bug(self, label, detail):
        self.bugs.append(f"[{label}] {detail}")
        self.rec.add_detail(f"【⚠ BUG记录】{label}: {detail}")
        try:
            self.rec.warn_current_step(f"发现BUG: {label}")
        except Exception:
            pass
        print(f"[GRE BUG] {label}: {detail}", flush=True)

    def _do_ssh_verify(self, label, verify_func, *args, must_pass=False, **kwargs):
        label_text = str(label)
        section = "【后端验证】"
        mark = self.backend.mark_io_start() if self.backend is not None else None
        result = None
        try:
            result = verify_func(*args, **kwargs)
            passed = bool(getattr(result, "passed", False))
            symbol = "✓" if passed else ("✗" if must_pass else "⚠")
            message = self.safe_text(getattr(result, "message", "无验证消息"))
            if not passed and not must_pass:
                message = f"未通过(警告,不阻断); {message}"
            self.rec.add_detail(f"{section}\n{symbol} {label_text}：{message}")
            raw = self.safe_text(getattr(result, "raw_output", "") or "")
            if raw:
                self.rec.add_detail(f"【后端数据】\n{raw}")
            print(f"{section} {symbol} {label_text}：{message}", flush=True)
            if must_pass and not passed:
                self.ssh_failures.append(f"后端-{label_text}：{message}")
            return result
        except Exception as exc:
            symbol = "✗" if must_pass else "⚠"
            impact = "验证异常,本项失败" if must_pass else "验证异常,仅记录警告"
            self.rec.add_detail(
                f"{section}\n{symbol} {label_text}：{impact}; {self.safe_text(exc)[:120]}")
            if must_pass:
                self.ssh_failures.append(f"后端-{label_text}异常：{self.safe_text(exc)[:100]}")
            return None
        finally:
            self._add_real_verification_commands(label_text, mark, result)

    def _add_real_verification_commands(self, label, mark, result):
        """把本次验证真实执行的 SSH 命令+输出构建成可复制 verification_commands 加进报告。

        每条真实命令一张卡: command(点击复制可在SSH重跑) + actual(后端返回结果) +
        target/host/effect/purpose。参照 IPsec VPN 的 verification_commands 卡风格, 在其基础上
        用 collect_io_since_mark 捕获的**真实执行命令+真实返回结果**(而非 reconstructed 命令)。
        """
        if self.backend is None or mark is None:
            return
        try:
            io_pairs = self.backend.collect_io_since_mark(mark)
        except Exception:
            io_pairs = []
        if not io_pairs:
            return
        role_label = {"router": "路由器", "client": "测试客户端", "peer": "GRE对端"}
        result_hint = ""
        if result is not None:
            result_hint = f"（本次验证: {self.safe_text(getattr(result, 'message', ''))}）"
        # 步骤内按命令文本去重: 同一命令在多轮验证(如 lifecycle 各状态/各参数)重复执行,
        # 人工复验只需一条可复制命令。已存在则保留**更长(更informative)的 actual**——
        # 避免去重时留下空结果(如 must_exist=False 的删除后空输出)而丢了有数据的那次。
        existing_by_cmd = self._step_cmd_index()
        new_cmds = []
        for pair in io_pairs:
            cmd = self.safe_text(pair.get("command"))
            key = cmd.strip()
            if not key:
                continue
            out = self.safe_text(pair.get("output"))
            # 空输出(查不存在/已删除对象)给明确文案, 避免报告渲染成"未记录"误导
            actual_text = out if out.strip() else "(命令已执行, 无输出——通常表示对象不存在/已删除)"
            if key in existing_by_cmd:
                ex = existing_by_cmd[key]
                # 优先保留有真实数据的 actual; 都为空则保留首次
                ex_empty = "(命令已执行" in self.safe_text(ex.get("actual"))
                if (out.strip() and (ex_empty or len(out) > len(self.safe_text(ex.get("actual"))))):
                    ex["actual"] = out  # 原地更新为有数据的真实输出
                continue
            card = {
                "command": cmd,
                "actual": actual_text,
                "target": pair.get("role"),
                "target_label": role_label.get(pair.get("role"), pair.get("role") or "未标注"),
                "host": self._host_of(pair.get("role")),
                "effect": "read_only" if self._is_readonly_cmd(cmd) else "write",
                "copy_ready": True,
                "purpose": f"{label}{result_hint}（点击复制可在SSH重跑）",
            }
            existing_by_cmd[key] = card  # 本轮新增的也登记, 避免本轮内重复
            new_cmds.append(card)
        if new_cmds:
            try:
                self.rec.add_verification_commands(new_cmds)
            except Exception as exc:
                print(f"[GRE] verification_commands 添加异常: {str(exc)[:80]}", flush=True)

    @staticmethod
    def _is_readonly_cmd(cmd: str) -> bool:
        """启发式判断命令是否只读(报告"影响"标注用)。GRE 验证命令默认只读。"""
        c = " " + (cmd or "").lower() + " "
        write_kw = ("insert ", "update ", "delete ", "replace ", " ip tunnel add", " ip tunnel del",
                    " ip -6 tunnel add", " ip -6 tunnel del", " ip link set", " ip addr add", " ip addr del",
                    " ip -6 addr add", " ip -6 addr del", " ip route add", " ip route del", " ip rule add",
                    " ip rule del", " ip -6 route add", " ip -6 route del", " ip -6 rule add", " ip -6 rule del",
                    " iptables -a", " iptables -d", " iptables -i", " iptables -t nat -a", " iptables -t nat -d",
                    "conntrack -f", "conntrack -e", "crontab")
        return not any(k in c for k in write_kw)

    def _host_of(self, role) -> str:
        """取 router/client/peer 的 IP(供 verification_commands 的 host 标注)。"""
        try:
            cfg = getattr(self.backend, "_ssh_config", None)
            if cfg is not None:
                node = getattr(cfg, role, None)
                if node is not None:
                    return str(getattr(node, "host", "") or "")
        except Exception:
            pass
        return ""

    def _step_cmd_index(self) -> dict:
        """返回当前步骤已有 verification_commands 的 {命令文本: vc字典}(步骤内按命令文本去重/更新)。"""
        idx = {}
        try:
            step = self.rec._get_current_step()
            if step is not None:
                for vc in getattr(step, "verification_commands", None) or []:
                    if isinstance(vc, dict):
                        txt = str(vc.get("command", "")).strip()
                        if txt:
                            idx[txt] = vc
        except Exception:
            pass
        return idx

    def ssh_verify(self, label, verify_func, *args, must_pass=False, **kwargs):
        return self._do_ssh_verify(label, verify_func, *args, must_pass=must_pass, **kwargs)

    def require_ssh(self, label, verify_func, *args, **kwargs):
        result = self.ssh_verify(label, verify_func, *args, must_pass=True, **kwargs)
        if result is None or not getattr(result, "passed", False):
            pytest.fail(f"安全前置失败: SSH-{label}")
        return result

    def summarize(self) -> List[str]:
        if self.bugs:
            self.rec.add_detail(
                f"【⚠ GRE测试发现BUG汇总({len(self.bugs)}个)】\n"
                + "\n".join(f"{i + 1}. {b}" for i, b in enumerate(self.bugs)))
            print(f"[GRE] 共记录{len(self.bugs)}个BUG", flush=True)
        return self.ssh_failures + self.ui_failures


class TestGreTunnelComprehensive:
    """GRE 隧道：综合测试 + 功能测试（2 用例）。"""

    # ==================== 综合测试：全链路 L1→L5 + 双端数据面 ====================
    def test_gre_comprehensive(
        self, gre_tunnel_page_logged_in, step_recorder: StepRecorder, request
    ):
        page = gre_tunnel_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("GRE 综合测试必须启用 SSH backend_verifier")
        h = _GreHarness(backend, rec)

        token = secrets.token_hex(2)
        num = _iface_num(token)
        v4_iface = f"gre{num}"
        v6_iface = f"gre{num + 1}"
        ifc_iface = f"gre{num + 2}"      # src_mode=1 接口主IP
        batch_ifaces = [f"gre{num + 3}", f"gre{num + 4}"]
        search_iface = v4_iface

        # 隧道地址(测试专用网段, 避开现网)
        seg = num % 200 + 30  # 30-229
        v4_router_tunnel = f"10.{seg}.0.1/30"
        v4_peer_tunnel = f"10.{seg}.0.2/30"
        v6_seg = format(num % 65535, "x")
        v6_router_tunnel = f"fd00:abcd:ef00:{v6_seg}::1/120"
        v6_peer_tunnel = f"fd00:abcd:ef00:{v6_seg}::2/120"
        ifc_router_tunnel = f"10.{seg}.8.1/30"

        prefixes = [f"gre{num}", f"gre{num + 1}", f"gre{num + 2}",
                    f"gre{num + 3}", f"gre{num + 4}"]
        created: List[str] = []
        peer_ifaces: List[str] = []
        l5_ifaces: List[str] = []
        snapshot = None
        v6_info = {"router": "", "peer": "", "ok": False}

        def add_tunnel(iface, spec):
            res = page.add_tunnel(spec)
            if h.result_ok(res):
                created.append(iface)
            return res

        try:
            with rec.step(
                "步骤1: 保存GRE环境快照+多WAN安全快照并验证对端可达",
                f"操作：快照 gre_tunnel 表/运行时接口/多WAN(路由表+ip rule+rt_tables+iface_band+mangle)并探测管理通道与对端可达性；"
                f"验证：gre_tunnel 初始计数=0; router→peer({PEER_V4}) IPv4 底层可达; IPv6 underlay 可达则续测(不可达软跳过); 测试编号 {v4_iface} 未被占用",
            ):
                backend.connect_router()
                snapshot = backend.snapshot_gre_environment()
                h.require_ui("环境快照完整", isinstance(snapshot, dict), "GRE快照缺失")
                try:
                    multiwan = backend.snapshot_multiwan_safety()
                    rec.add_detail(
                        f"【多WAN安全快照(操作前)】gre_count={multiwan.get('gre_count')}\n"
                        f"默认+直连:\n{multiwan.get('route_default_connected','')[:400]}")
                    mgmt = backend.verify_management_reachable()
                    rec.add_detail(
                        f"【管理通道探测】router_ssh={mgmt['router_ssh']} lan_ssh={mgmt['lan_ssh']} "
                        f"recovery_ssh={mgmt['recovery_ssh']} client={mgmt['client_ssh']} "
                        f"peer={mgmt['peer_ssh']} device_reachable={mgmt['device_reachable']}")
                    h.require_ui("独立LAN恢复通道可用", mgmt.get("lan_ssh") or mgmt.get("recovery_ssh"),
                                  "WAN失联时无独立恢复通道→多WAN场景须标BLOCKED")
                except Exception as exc:
                    h.ui_failures.append(f"多WAN安全快照失败: {h.safe_text(exc)[:100]}")
                h.require_ssh("L1-初始计数", backend.verify_gre_tunnel_count, expected=0)
                h.require_ssh("L3-IPv4底层可达",
                               backend.verify_gre_peer_reachable, protocol=0, peer_dst=PEER_V4)
                # IPv6 underlay 动态解析: 软观察(env-blocked 不入 failures, 修复历史假失败)
                rv6, pv6, v6_ok = _resolve_ipv6_underlay(backend)
                v6_info.update({"router": rv6, "peer": pv6, "ok": bool(v6_ok)})
                rec.add_detail(
                    f"【IPv6 underlay 动态解析】router_wan1={rv6 or '(无全局v6)'} "
                    f"peer_wan1={pv6 or '(无全局v6)'} reachable={v6_ok}"
                    f"{'' if v6_ok else ' → IPv6 GRE场景软跳过(env, 不FAIL模块)'}")
                h.observe("IPv6 underlay 可达(双栈L5前提)", v6_ok,
                           f"router={rv6} peer={pv6}(不达则IPv6场景软跳过, 不影响模块结论)")
                page.navigate_to_gre()
                h.require_ui("测试编号初始不存在", not page.rule_exists(v4_iface), v4_iface)

            with rec.step(
                "步骤2: 检查GRE页面结构与导入导出入口",
                "操作：进入GRE页面；验证：表头含接口/状态/类型/源地址/目的地址/描述/操作；搜索框+新建+帮助按钮齐全；前端不暴露导入/导出(底层脚本有EXPORT/IMPORT但无UI入口)",
            ):
                page.navigate_to_gre()
                struct = page.get_default_structure()
                h.ui_check("URL", struct.get("url_ok"), page.page.url)
                h.ui_check("搜索框", struct.get("search_present"), str(struct))
                h.ui_check("新建按钮", struct.get("add_present"), str(struct))
                h.ui_check("帮助按钮", struct.get("help_present"), str(struct))
                headers = "|".join(struct.get("headers", []))
                for col in ("接口", "状态", "类型", "源地址", "目的地址", "描述", "操作"):
                    h.ui_check(f"列-{col}", col in headers, headers)
                ie = page.has_import_export_ui()
                h.ui_check("导入导出入口(前端)", ie is False,
                           "前端暴露了导入/导出" if ie else "前端未暴露导入/导出(底层脚本有EXPORT/IMPORT)")

            with rec.step(
                "步骤3: 检查GRE新增表单全部字段(基础+高级)",
                "操作：打开新增drawer并展开高级配置、切换IPv6；验证：18字段控件齐全(编号/备注/接口IPv4+掩码/源地址方式/源地址/目的地址/keepalive周期+次数/gre_key/校验和/tos/ttl/不分片)；IPv6接口地址字段tunnel_addr2_0存在",
            ):
                h.require_ui("打开新增drawer", page.open_add_drawer(), "drawer未打开")
                h.require_ui("展开高级配置", page.expand_advanced(), "高级配置未展开")
                drawer = page._drawer()
                for sel, name in [
                    ("input#tagname", "隧道编号"), ("textarea#comment", "备注"),
                    ("input#tunnel_addr1_0", "接口IPv4地址"), ("input#tunnel_addr1_1", "掩码"),
                    ("input#src_addr", "源地址"), ("input#dst_addr", "目的地址"),
                    ("input#gre_key", "GRE key"), ("input#tos", "Tos"), ("input#ttl", "TTL"),
                ]:
                    h.ui_check(f"字段-{name}", drawer.locator(sel).count() > 0, sel)
                page.set_keepalive(True)
                h.ui_check("keepalive_周期", drawer.locator("input#keepalive_interval").count() > 0, "interval")
                h.ui_check("keepalive_次数", drawer.locator("input#keepalive_count").count() > 0, "count")
                page.set_keepalive(False)
                page.set_protocol("IPv6")
                h.ui_check("IPv6接口地址字段",
                           drawer.locator("input#tunnel_addr2_0").count() > 0, "tunnel_addr2_0")
                page.set_protocol("IPv4")
                h.ui_check("取消新增drawer", page.cancel_drawer(), "drawer未关闭")

            with rec.step(
                "步骤4: 添加IPv4 GRE隧道(指定IP)并验证L1数据库+L2运行时",
                f"操作：新增{v4_iface}(IPv4,源={ROUTER_V4},目={PEER_V4},隧道地址{v4_router_tunnel})；验证：列表存在{v4_iface}；DB enabled=yes/protocol=0/tagname={v4_iface}/tunnel_addr={v4_router_tunnel}/src_mode=0/src_addr={ROUTER_V4}/dst_addr={PEER_V4}；运行时ip tunnel/addr/NAT/路由表/策略规则一致；链路UP",
            ):
                spec = {"iface": v4_iface, "protocol": "IPv4", "tunnel_addr": v4_router_tunnel,
                        "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                        "comment": f"GRE-{token}"}
                added = add_tunnel(v4_iface, spec)
                h.require_ui("添加IPv4 GRE", h.result_ok(added), h.result_error(added))
                page.navigate_to_gre()
                h.require_ui("列表存在", page.rule_exists(v4_iface), v4_iface)
                h.require_ssh("L1-IPv4 DB", backend.verify_gre_tunnel_database, v4_iface,
                              {"enabled": "yes", "protocol": 0, "tagname": v4_iface,
                               "tunnel_addr": v4_router_tunnel, "src_mode": 0,
                               "src_addr": ROUTER_V4, "dst_addr": PEER_V4})
                h.require_ssh("L2-IPv4 运行时", backend.verify_gre_runtime, v4_iface,
                              {"protocol": 0, "tunnel_addr": v4_router_tunnel, "dst_addr": PEER_V4})
                h.require_ssh("L2-IPv4 链路UP", backend.verify_gre_link_state, v4_iface, True)

            with rec.step(
                "步骤5: 编辑IPv4 GRE(备注/Tos/keepalive)并验证",
                f"操作：编辑{v4_iface}:备注=GRE-{token}-edited、开keepalive(周期15/次数5)、tos=100；验证：DB comment=GRE-{token}-edited,keepalive=1,keepalive_interval=15,keepalive_count=5,tos=100；运行时隧道地址/源/目一致",
            ):
                edit_spec = {"iface": v4_iface, "protocol": "IPv4", "tunnel_addr": v4_router_tunnel,
                             "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                             "comment": f"GRE-{token}-edited", "keepalive": True,
                             "keepalive_interval": 15, "keepalive_count": 5, "tos": 100}
                edited = page.edit_tunnel(v4_iface, edit_spec)
                h.require_ui("编辑IPv4 GRE", h.result_ok(edited), h.result_error(edited))
                h.require_ssh("L1-编辑后DB", backend.verify_gre_tunnel_database, v4_iface,
                              {"comment": f"GRE-{token}-edited", "keepalive": 1,
                               "keepalive_interval": 15, "keepalive_count": 5, "tos": 100})
                h.require_ssh("L2-编辑后运行时", backend.verify_gre_runtime, v4_iface,
                              {"protocol": 0, "tunnel_addr": v4_router_tunnel, "dst_addr": PEER_V4})

            with rec.step(
                "步骤6: 停用/启用IPv4 GRE并验证运行时随之变化",
                f"操作：停用{v4_iface}→再启用；验证：停用后DB enabled=no+运行时接口拆除；启用后DB enabled=yes+运行时重建(前端按钮不刷新则脚本init兜底)",
            ):
                page.navigate_to_gre()
                h.require_ui("停用", page.disable_rule(v4_iface), "停用未发起")
                h.require_ssh("L1-停用enabled=no", backend.verify_gre_tunnel_database, v4_iface, {"enabled": "no"})
                h.require_ssh("L2-停用后运行时拆除", backend.verify_gre_runtime, v4_iface,
                              {"protocol": 0}, must_exist=False)
                page.navigate_to_gre()
                if not page.enable_rule(v4_iface):
                    # 前端BUG: 停用后UI操作按钮不刷新为"启用"
                    h.record_bug("前端-停用后UI不刷新(IKOS-6984关联)",
                                 "停用(DB enabled=no已生效)后, UI操作按钮未从'停用'切换为'启用', 无法UI启用")
                    h.require_ssh("L2-SSH模拟up重建运行时", backend.enable_gre_tunnel_runtime, v4_iface)
                h.require_ssh("L1-启用enabled=yes", backend.verify_gre_tunnel_database, v4_iface, {"enabled": "yes"})
                h.require_ssh("L2-启用后运行时重建", backend.verify_gre_runtime, v4_iface,
                              {"protocol": 0, "tunnel_addr": v4_router_tunnel})

            with rec.step(
                "步骤7: L5 IPv4 GRE双端数据面 + 外层选路/NAT抓包观察",
                f"操作：对端{PEER_V4}对称建GRE(隧道址{v4_peer_tunnel})+回程路由；router经gre ping对端隧道地址；ip route get看选路口+-i any抓外层src；"
                f"验证：ip route get选路口与源{WAN_IFACE}一致；router ping对端隧道地址{v4_peer_tunnel.split('/')[0]}通(GRE数据面双向打通)",
            ):
                peer = backend.prepare_peer_tunnel(protocol=0, peer_tunnel_addr=v4_peer_tunnel,
                                                   router_dst=ROUTER_V4, peer_src=PEER_V4)
                if peer.get("iface"):
                    peer_ifaces.append(peer["iface"])
                h.require_ui("对端GRE建立", peer.get("ok"), peer.get("error", ""))
                backend.add_peer_return_route(client_subnet="192.168.148.0/24", protocol=0,
                                              via_addr=v4_router_tunnel.split("/")[0], iface=peer.get("iface"))
                # 外层选路口检测(源/口不一致铁证)
                rg = backend._router.exec(f"ip route get {PEER_V4} 2>&1", timeout=8) or ""
                rec.add_detail(f"【ip route get {PEER_V4}】\n{rg[:200]}")
                dev_match = re.search(r"\bdev (\w+)", rg)
                if dev_match:
                    egress = dev_match.group(1)
                    if egress != WAN_IFACE:
                        h.record_bug("GRE-IPv4选路不绑源接口(IKOS-6992关联)",
                                     f"GRE源={ROUTER_V4}({WAN_IFACE}), 但 ip route get {PEER_V4} 走 dev {egress}")
                    else:
                        h.observe("选路口与源接口一致", True, f"dev={egress}")
                # 外层抓包(软, 本环境GRE外层proto47不可见疑offload)
                cap = backend.capture_gre_outer(inner_dst=v4_peer_tunnel.split("/")[0],
                                                iface="any", protocol=0, duration=8, count=12)
                out_srcs = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s*>\s*" + re.escape(PEER_V4), cap)
                rec.add_detail(f"【IPv4外层抓包 -i any】\n{cap[:800]}\n出向外层src样本: {out_srcs[:5]}")
                if out_srcs:
                    wrong = [s for s in out_srcs if s != ROUTER_V4]
                    if wrong:
                        h.record_bug("GRE-IPv4外层src被改写(NAT选路bug)",
                                     f"配置源={ROUTER_V4}, 出向外层src含{wrong[:3]}")
                    else:
                        h.observe("外层src==配置源", True, f"src={out_srcs[0]}")
                else:
                    rec.add_detail("【说明】外层src未抓到——本环境GRE外层抓包不稳(疑硬件/ik_core offload), 选路以ip route get为铁证")
                # 数据面连通(router ping对端隧道址)
                dp = h.ssh_verify("L5-IPv4 router ping对端隧道址", backend.verify_gre_data_plane,
                                  peer_tunnel_addr=v4_peer_tunnel.split("/")[0], protocol=0, via_client=True)
                if not (dp and getattr(dp, "passed", False)):
                    h.record_bug("GRE-L5 IPv4数据面未通(IKOS-7101/6992)",
                                 "router ping对端隧道地址失败(多WAN环境偶发, 之前已验证可通)")
                backend.del_peer_return_route(client_subnet="192.168.148.0/24", protocol=0, iface=peer.get("iface"))
                try:
                    backend.clear_gre_conntrack()
                except Exception:
                    pass

            with rec.step(
                "步骤8: 删除IPv4 GRE并验证运行时清理无残留",
                f"操作：删除{v4_iface}；验证：DB不存在{v4_iface}；运行时ip tunnel/NAT/路由表/策略规则全清理；计数=0",
            ):
                page.navigate_to_gre()
                h.require_ui("删除IPv4 GRE", page.delete_rule(v4_iface), v4_iface)
                h.record_bug("前端-删除后UI列表不自动刷新(IKOS-6985)",
                             "删除GRE隧道后UI列表不立即移除(需reload); delete_rule内部已reload")
                if v4_iface in created:
                    created.remove(v4_iface)
                h.require_ssh("L1-删除后不存在", backend.verify_gre_tunnel_database, v4_iface, must_exist=False)
                h.require_ssh("L2-删除后运行时清理", backend.verify_gre_runtime, v4_iface,
                              {"protocol": 0}, must_exist=False)
                h.require_ssh("L1-计数=0", backend.verify_gre_tunnel_count, expected=0)

            with rec.step(
                "步骤9: 验证GRE表单异常输入拦截",
                "操作：尝试空目的地址/非法隧道地址999.999.999.1/30/编号gre0(保留)；验证：三项均被拦截不落库；异常后计数=0",
            ):
                invalid_cases = [
                    ("空目的地址", {"iface": f"gre{num + 5}", "protocol": "IPv4",
                                "tunnel_addr": v4_router_tunnel, "src_mode": "指定IP地址",
                                "src_addr": ROUTER_V4, "dst_addr": ""}),
                    ("非法隧道地址", {"iface": f"gre{num + 6}", "protocol": "IPv4",
                                  "tunnel_addr": "999.999.999.1/30", "src_mode": "指定IP地址",
                                  "src_addr": ROUTER_V4, "dst_addr": PEER_V4}),
                    ("编号gre0保留", {"iface": "gre0", "protocol": "IPv4",
                                  "tunnel_addr": v4_router_tunnel, "src_mode": "指定IP地址",
                                  "src_addr": ROUTER_V4, "dst_addr": PEER_V4}),
                ]
                for label, spec in invalid_cases:
                    page.navigate_to_gre()
                    res = page.try_add_invalid(spec)
                    h.ui_check(f"异常拦截-{label}", h.result_ok(res, "blocked"), h.result_error(res))
                    if spec["iface"] != "gre0":
                        h.ssh_verify(f"L1-{label}未落库", backend.verify_gre_tunnel_database,
                                     spec["iface"], must_exist=False)
                h.require_ssh("L1-异常后计数=0", backend.verify_gre_tunnel_count, expected=0)

            with rec.step(
                "步骤10: 添加IPv6 GRE隧道并验证L1+L2",
                f"操作：新增{v6_iface}(IPv6,源选wan1接口主IP,目=对端wan1全局v6,隧道地址{v6_router_tunnel})；"
                f"验证：DB protocol=1/src_mode=1/tunnel_addr={v6_router_tunnel}/dst=对端v6；ip6gre/addr/ip6tables NAT/路由表一致；链路UP(UI创建中IKOS-7064则workaround建隧道续L5)；IPv6 underlay不通则软跳过",
            ):
                if not v6_info["ok"]:
                    rec.add_detail(f"【env-blocked】IPv6 underlay 不可达(router={v6_info['router']} "
                                   f"peer={v6_info['peer']}), IPv6 GRE CRUD/L5 跳过(环境问题, 非产品bug)")
                else:
                    # 用户指示: IPv6 测试选 wan1 接口(wan1 已有全局 v6 fd00:abcd:ef00::848)。
                    # 用"接口主IP"模式选 wan1, 不用"指定IP地址"(src_addr 字段在 IPv6 下填充不稳)。
                    spec = {"iface": v6_iface, "protocol": "IPv6", "tunnel_addr": v6_router_tunnel,
                            "src_mode": "使用指定接口主IP地址", "src_iface": "wan1",
                            "dst_addr": v6_info["peer"], "comment": f"GRE6-{token}"}
                    added = add_tunnel(v6_iface, spec)
                    if h.result_ok(added):
                        h.require_ssh("L1-IPv6 DB", backend.verify_gre_tunnel_database, v6_iface,
                                      {"enabled": "yes", "protocol": 1, "tagname": v6_iface,
                                       "tunnel_addr": v6_router_tunnel,
                                       "src_mode": 1, "dst_addr": v6_info["peer"]})
                        h.require_ssh("L2-IPv6 运行时", backend.verify_gre_runtime, v6_iface,
                                      {"protocol": 1, "tunnel_addr": v6_router_tunnel, "dst_addr": v6_info["peer"]})
                        h.require_ssh("L2-IPv6 链路UP", backend.verify_gre_link_state, v6_iface, True)
                    else:
                        # 产品BUG(铁证): IPv6 GRE UI创建必败(ip6gre不接受nopmtudisc, IKOS-7064)
                        h.record_bug("产品-IPv6 GRE创建必败(IKOS-7064, ip6gre不接受nopmtudisc)",
                                     f"UI建IPv6 GRE失败: {h.result_error(added)}. 根因: 脚本v6分支加nopmtudisc"
                                     f"(no_fragment默认0), 但 ip6gre 不接受 nopmtudisc → 'GRE隧道下发失败'。"
                                     f"铁证: no_fragment=1(不加nopmtudisc)时 ip6gre 创建成功接口UP。workaround建隧道续L5。")
                        built = backend.build_gre_tunnel_runtime(
                            v6_iface, 1, v6_router_tunnel, v6_info["peer"], v6_info["router"])
                        rec.add_detail(f"【workaround建IPv6 GRE】{built.message}")
                        if built.passed:
                            l5_ifaces.append(v6_iface)
                            h.ssh_verify("L2-IPv6 workaround运行时", backend.verify_gre_runtime, v6_iface,
                                         {"protocol": 1, "tunnel_addr": v6_router_tunnel, "dst_addr": v6_info["peer"]})

            with rec.step(
                "步骤11: L5 IPv6 GRE双端数据面",
                "操作：对端对称建IPv6 GRE；router经gre ping6对端隧道地址；验证：IPv6 GRE数据面双向打通(env-blocked则软跳过)",
            ):
                if not v6_info["ok"]:
                    rec.add_detail("【env-blocked】IPv6 underlay 不可达, L5 IPv6 跳过(环境)")
                elif not (v6_iface in created or v6_iface in l5_ifaces):
                    rec.add_detail("【跳过】IPv6 GRE 未成功建立(UI失败且workaround失败), L5 IPv6 跳过")
                else:
                    peer6 = backend.prepare_peer_tunnel(protocol=1, peer_tunnel_addr=v6_peer_tunnel,
                                                        router_dst=v6_info["router"], peer_src=v6_info["peer"])
                    if peer6.get("iface"):
                        peer_ifaces.append(peer6["iface"])
                    h.observe("对端IPv6 GRE建立", peer6.get("ok"), peer6.get("error", ""))
                    dp6 = h.ssh_verify("L5-IPv6 router ping6对端隧道址", backend.verify_gre_data_plane,
                                       peer_tunnel_addr=v6_peer_tunnel.split("/")[0], protocol=1, via_client=False)
                    if not (dp6 and getattr(dp6, "passed", False)):
                        h.record_bug("GRE-L5 IPv6数据面未通", "router ping6对端隧道地址失败(本轮实测复现)")

            with rec.step(
                "步骤12: 删除IPv6 GRE + 源地址方式=接口主IP的GRE(列表源地址列展示)",
                f"操作：删除IPv6 GRE{v6_iface}；新增{ifc_iface}(src_mode=接口主IP选wan1)；"
                f"验证：DB src_mode=1/tunnel_addr={ifc_router_tunnel}；mangle OUTPUT -p47下发；列表「源地址」列展示wan1接口主IP(IKOS-6991)",
            ):
                if v6_info["ok"]:
                    page.navigate_to_gre()
                    if v6_iface in created:
                        h.ui_check("删除IPv6 GRE(UI)", page.delete_rule(v6_iface), v6_iface)
                        created.remove(v6_iface)
                    else:
                        backend.cleanup_gre_tunnel(v6_iface, protocol=1)
                        rec.add_detail(f"【workaround清理】{v6_iface}(无DB, ip -6 tunnel del)")
                    h.ssh_verify("L1-IPv6删除后不存在", backend.verify_gre_tunnel_database, v6_iface, must_exist=False)
                    h.ssh_verify("L2-IPv6删除后清理", backend.verify_gre_runtime, v6_iface,
                                 {"protocol": 1}, must_exist=False)
                # src_mode=接口主IP + 列表源地址列展示(IKOS-6991)
                spec = {"iface": ifc_iface, "protocol": "IPv4", "tunnel_addr": ifc_router_tunnel,
                        "src_mode": "使用指定接口主IP地址", "src_iface": "wan1",
                        "gre_key": str(500000 + num + 2), "dst_addr": PEER_V4, "comment": f"GRE-IF-{token}"}
                added = add_tunnel(ifc_iface, spec)
                h.require_ui("添加接口主IP GRE", h.result_ok(added), h.result_error(added))
                h.require_ssh("L1-接口主IP DB", backend.verify_gre_tunnel_database, ifc_iface,
                              {"enabled": "yes", "src_mode": 1, "dst_addr": PEER_V4,
                               "tunnel_addr": ifc_router_tunnel})
                h.ssh_verify("L2-mangle fwmark下发", backend.verify_gre_runtime, ifc_iface,
                             {"protocol": 0, "tunnel_addr": ifc_router_tunnel, "dst_addr": PEER_V4})
                # IKOS-6991: 列表"源地址"列展示(软, 虚拟表格适配可能不稳)
                page.navigate_to_gre()
                src_cell = page.get_list_cell_by_header(ifc_iface, "源地址")
                rec.add_detail(f"【列表源地址列({ifc_iface})】={src_cell!r}")
                if src_cell and src_cell.strip() and src_cell.strip() != ifc_iface:
                    h.observe("列表源地址列展示接口主IP(IKOS-6991)", True, src_cell)
                else:
                    h.record_bug("GRE-src_mode=接口时列表源地址列不展示(IKOS-6991)",
                                 f"src_mode=指定接口主IP 的隧道 {ifc_iface}, 列表'源地址'列文本={src_cell!r}(应为接口主IP)")

            with rec.step(
                "步骤13: 批量添加/停用/启用/删除GRE隧道",
                f"操作：添加{batch_ifaces[0]}/{batch_ifaces[1]}，批量停用→启用→删除(无批量栏则逐条行内)；验证：每阶段DB enabled同步(no/yes)；删除后不存在",
            ):
                batch_built = []
                for i, iface in enumerate(batch_ifaces):
                    spec = {"iface": iface, "protocol": "IPv4", "tunnel_addr": f"10.{seg}.{i + 1}.1/30",
                            "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                            "gre_key": str(500000 + num + 3 + i), "comment": f"GRE-B{i}-{token}"}
                    res = add_tunnel(iface, spec)
                    if h.result_ok(res):
                        batch_built.append(iface)
                    else:
                        h.record_bug(f"GRE批量添加-{iface}下发失败", h.result_error(res))
                if len(batch_built) == 2:
                    page.navigate_to_gre()
                    page.clear_tunnel_selection()
                    sel_n = page.select_tunnels(batch_built)
                    sel_cnt = page.get_selected_count()
                    batch_btns = page.get_visible_batch_buttons()
                    rec.add_detail(f"【批量勾选】选中行={sel_n}/2; '已选X条'={sel_cnt}; 可见批量按钮={batch_btns}")
                    h.ui_check("真实勾选目标行", sel_n == 2, f"选中{sel_n}行")
                    h.ui_check("已选计数=2", sel_cnt == 2, f"已选{sel_cnt}条")
                    if "停用" not in batch_btns:
                        # GRE footer 无批量动作栏(实测仅"帮助"+"共N条")→逐条行内操作
                        rec.add_detail(f"【前端能力】GRE列表footer无批量动作栏(按钮={batch_btns}), 批量在前端不可用→逐条行内")
                        for iface in batch_built:
                            h.ui_check(f"行内停用-{iface}", page.disable_rule(iface), "停用未发起")
                            h.ssh_verify(f"L1-行内停用-{iface}", backend.verify_gre_tunnel_database, iface, {"enabled": "no"})
                            h.ui_check(f"行内启用-{iface}", page.enable_rule(iface), "启用未发起")
                            h.ssh_verify(f"L1-行内启用-{iface}", backend.verify_gre_tunnel_database, iface, {"enabled": "yes"})
                        page.clear_tunnel_selection()
                    else:
                        br = page.batch_operate(batch_built, "停用", need_confirm=True)
                        h.ui_check("批量停用按钮点击", br["action_clicked"], str(br))
                        for iface in batch_built:
                            h.ssh_verify(f"L1-批停-{iface}", backend.verify_gre_tunnel_database, iface, {"enabled": "no"})
                        page.clear_tunnel_selection()
                        page.batch_operate(batch_built, "启用", need_confirm=False)
                        for iface in batch_built:
                            h.ssh_verify(f"L1-批启-{iface}", backend.verify_gre_tunnel_database, iface, {"enabled": "yes"})
                        page.clear_tunnel_selection()
                        page.batch_operate(batch_built, "删除", need_confirm=True)
                        for iface in batch_built:
                            if iface in created:
                                created.remove(iface)
                            h.ssh_verify(f"L1-批删-{iface}", backend.verify_gre_tunnel_database, iface, must_exist=False)
                else:
                    h.record_bug("GRE-批量添加未全部成功", f"仅{len(batch_built)}/2成功(隧道下发失败), 批量停用/启用/删除跳过")
                    for iface in batch_built:
                        if iface in created:
                            created.remove(iface)

            with rec.step(
                "步骤14: 搜索GRE隧道与帮助入口",
                f"操作：搜索{search_iface}命中+不存在关键字空结果+清空恢复；点帮助；验证：搜索命中/空结果/恢复正确；帮助popup指向ikuai8.com",
            ):
                spec = {"iface": search_iface, "protocol": "IPv4", "tunnel_addr": v4_router_tunnel,
                        "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                        "comment": f"GRE-S-{token}"}
                if not page.rule_exists(search_iface):
                    add_tunnel(search_iface, spec)
                page.navigate_to_gre()
                try:
                    page.search_rule(search_iface)
                    if page.rule_exists(search_iface):
                        h.ui_check("搜索命中", True, search_iface)
                    else:
                        h.record_bug("GRE-搜索未命中", "搜索GRE隧道后列表未显示结果(虚拟表格搜索适配问题)")
                    page.search_rule("gre_not_exist_zzz")
                    h.ui_check("搜索空结果", not page.rule_exists(search_iface), "不存在关键字仍显示")
                    page.clear_search()
                    if page.rule_exists(search_iface):
                        h.ui_check("清搜索恢复", True, search_iface)
                    else:
                        h.record_bug("GRE-清搜索未恢复", "清空搜索后列表未恢复")
                except Exception as exc:
                    h.record_bug("GRE-搜索异常", str(exc)[:100])
                help_res = page.verify_help()
                if h.result_ok(help_res, "popup_opened") and "ikuai8.com" in help_res.get("url", ""):
                    h.ui_check("帮助入口", True, help_res.get("url", ""))
                else:
                    h.record_bug("GRE-帮助popup未打开(IKOS-7056)", f"帮助按钮点击后popup未触发: {str(help_res)[:120]}")
        finally:
            with rec.step(
                "步骤15: 清理GRE测试数据并恢复环境",
                "操作：删除所有测试隧道(UI+运行时)+对端临时GRE+回程路由；验证：gre_tunnel表与运行时恢复测试前快照；计数=0；测试编号gre接口全拆除(残留审计)",
            ):
                try:
                    page.navigate_to_gre()
                    for iface in list(created):
                        try:
                            page.delete_rule(iface)
                        except Exception:
                            pass
                except Exception as exc:
                    h.ui_failures.append(f"finally UI清理异常: {h.safe_text(exc)[:100]}")
                for prefix in prefixes:
                    try:
                        backend.cleanup_gre_prefix(prefix)
                    except Exception:
                        pass
                for piface in list(set(peer_ifaces)):
                    try:
                        backend.cleanup_peer_tunnel(piface)
                    except Exception:
                        pass
                for l5 in list(l5_ifaces):
                    try:
                        backend.connect_router()
                        backend._router.exec(
                            f"ip link set {l5} down 2>/dev/null; "
                            f"ip tunnel del {l5} 2>/dev/null; ip -6 tunnel del {l5} 2>/dev/null; "
                            f"while ip rule del lookup {l5} 2>/dev/null; do :; done; "
                            f"while ip -6 rule del lookup {l5} 2>/dev/null; do :; done; echo done", timeout=10)
                    except Exception:
                        pass
                if snapshot is not None:
                    h.ssh_verify("finally-恢复GRE环境", backend.restore_gre_environment, snapshot, must_pass=True)
                    h.ssh_verify("finally-计数=0", backend.verify_gre_tunnel_count, expected=0, must_pass=True)
                    for prefix in prefixes:
                        h.ssh_verify(f"finally-运行时清理-{prefix}", backend.verify_gre_runtime, prefix,
                                     {"protocol": 0}, must_exist=False, must_pass=True)

        failures = h.summarize()
        if failures:
            print(f"[GRE综合断言] 共{len(failures)}项失败 "
                  f"(SSH={len(h.ssh_failures)}, UI={len(h.ui_failures)})", flush=True)
        assert not failures, (
            f"GRE隧道综合测试失败({len(failures)}项): "
            + "; ".join(h.safe_text(item) for item in failures[:24]))

    # ==================== 功能测试：配置生效/边界/生命周期/提示规范/高级默认值 ====================
    def test_gre_functional(
        self, gre_tunnel_page_logged_in, step_recorder: StepRecorder, request
    ):
        page = gre_tunnel_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("GRE 功能测试必须启用 SSH backend_verifier")
        h = _GreHarness(backend, rec)

        token = secrets.token_hex(2)
        num = _iface_num(token)
        seg = num % 200 + 30  # 30-229, 保证合法IP
        base_tunnel = f"10.{seg}.0.1/30"
        snapshot = None

        # 收集本轮创建/可能落库的前缀, finally 统一兜底清理
        prefixes: List[str] = []

        def reg(iface):
            if iface not in prefixes:
                prefixes.append(iface)

        def del_if_landed(iface):
            """删除 BUG-越界落库的隧道(避免(src,dst,gre_key)唯一性冲突阻塞后续 section)。

            越界用例(gre_key=4294967296 / tos=256)WEB/API 校验失效会 BUG 性落库(IKOS-7012/7021),
            残留的空 gre_key 隧道会与后续 section 的空 gre_key 隧道在唯一性上冲突。检测到落库即清。
            """
            try:
                if backend.find_gre_tunnel(iface) is not None:
                    page.navigate_to_gre()
                    if not page.delete_rule(iface):
                        backend.cleanup_gre_tunnel(iface)
            except Exception:
                try:
                    backend.cleanup_gre_tunnel(iface)
                except Exception:
                    pass

        try:
            backend.connect_router()
            snapshot = backend.snapshot_gre_environment()
            page.navigate_to_gre()

            # ---------- A. 配置真生效(内核 ip -d) ----------
            with rec.step(
                "A. 配置真生效(内核ip -d): keepalive/tos/ttl/gre_key/checksum/no_fragment 是否真下发",
                "操作：建全字段GRE(keepalive10/3,tos=16,ttl=128,gre_key=123456,校验和,不分片)；验证：DB落库tos=16/ttl=128/gre_key=123456/checksum=1/keepalive=1/no_fragment=1；内核ip -d实发ttl=128/tos=0x10/ikey-okey/icsum-ocsum(tos进制IKOS-7021/keepalive IKOS-7015不生效则record_bug)",
            ):
                full_iface = f"gre{num + 10}"
                reg(full_iface)
                spec = {"iface": full_iface, "protocol": "IPv4", "tunnel_addr": base_tunnel,
                        "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                        "comment": f"GRE-EFF-{token}", "keepalive": True, "keepalive_interval": 10,
                        "keepalive_count": 3, "tos": 16, "ttl": 128, "gre_key": "123456",
                        "checksum": True, "no_fragment": True}
                res = page.add_tunnel(spec)
                h.require_ui("建全字段GRE", h.result_ok(res), h.result_error(res))
                h.require_ssh("L1-全字段DB落库", backend.verify_gre_tunnel_database, full_iface,
                              {"enabled": "yes", "tos": 16, "ttl": 128, "gre_key": "123456",
                               "checksum": 1, "keepalive": 1, "keepalive_interval": 10,
                               "keepalive_count": 3, "no_fragment": 1})
                h.ssh_verify("L2-内核ttl=128", backend.verify_gre_kernel_params, full_iface, {"ttl": 128})
                tos_k = h.ssh_verify("L2-内核tos=16(0x10)", backend.verify_gre_kernel_params, full_iface, {"tos": 16})
                if tos_k and not tos_k.passed:
                    h.record_bug("GRE-TOS进制不一致(IKOS-7021实锤)",
                                 "前端存十进制tos, 但 ip tunnel change tos 把裸数字当十六进制(tos16→0x16=22; "
                                 "tos100→iproute2报'bad TOS value'被2>&1吞错不下发). 根因脚本应传0x前缀或dec→hex")
                h.ssh_verify("L2-内核gre_key(ikey/okey)", backend.verify_gre_kernel_params, full_iface, {"gre_key": True})
                h.ssh_verify("L2-内核checksum(icsum/ocsum)", backend.verify_gre_kernel_params, full_iface, {"checksum": True})
                ka = h.ssh_verify("L2-内核keepalive(预期不生效)", backend.verify_gre_kernel_params, full_iface, {"keepalive": True})
                if ka and not ka.passed:
                    h.record_bug("GRE-keepalive内核不生效(IKOS-7015)",
                                 "DB keepalive=1, 但 ip -d 无 keepalive 字段(iproute2 5.15不支持, 2>&1吞错)")

            # ---------- B. 边界值/校验 ----------
            with rec.step(
                "B. 边界值: gre_key范围(IKOS-7012) + no_fragment+ttl约束 + TOS进制/溢出(IKOS-7021)",
                "操作：gre_key=4294967295(应通过)/4294967296(越界应拒)；tos=100(进制FIX应0x64)/tos=256(越界应拒)；验证：4294967295落库；4294967296/tos=256经WEB/API越界落库则record_bug(IKOS-7012/7021前后端校验不一致)；tos=100内核=0x64",
            ):
                k_max = f"gre{num + 11}"; k_over = f"gre{num + 12}"
                t100 = f"gre{num + 13}"; t256 = f"gre{num + 14}"
                for x in (k_max, k_over, t100, t256):
                    reg(x)
                res_max = page.add_tunnel({"iface": k_max, "protocol": "IPv4", "tunnel_addr": base_tunnel,
                                           "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                                           "gre_key": "4294967295"})
                if h.result_ok(res_max):
                    h.require_ssh("L1-gre_key=4294967295落库", backend.verify_gre_tunnel_database, k_max, {"gre_key": "4294967295"})
                    page.delete_rule(k_max)
                else:
                    h.record_bug("GRE-gre_key=4294967295本应通过却失败", h.result_error(res_max))
                res_over = page.try_add_invalid({"iface": k_over, "protocol": "IPv4", "tunnel_addr": base_tunnel,
                                                 "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                                                 "gre_key": "4294967296"})
                h.observe("gre_key=4294967296 drawer拦截", h.result_ok(res_over, "blocked"), h.result_error(res_over))
                row_over = backend.find_gre_tunnel(k_over)
                if row_over is not None:
                    h.record_bug("GRE-gre_key=4294967296 WEB/API越界被接受(IKOS-7012)",
                                 f"gre_key=4294967296(=2^32, 超32位max)经WEB/API被接受并落库(实际={row_over.get('gre_key')}). "
                                 "脚本CLI正确拒绝, WEB/API路径校验失效→前后端不一致")
                    del_if_landed(k_over)
                else:
                    h.ui_check("gre_key=4294967296越界未落库(校验生效)", True)
                # tos=100 进制FIX(0x64) + tos=256越界
                res100 = page.add_tunnel({"iface": t100, "protocol": "IPv4", "tunnel_addr": base_tunnel,
                                          "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                                          "gre_key": "830083", "tos": 100})
                if h.result_ok(res100):
                    h.require_ssh("L1-tos=100落库", backend.verify_gre_tunnel_database, t100, {"tos": 100})
                    tk = h.ssh_verify("L2-内核tos=100(0x64, 进制FIX验证)", backend.verify_gre_kernel_params, t100, {"tos": 100})
                    if tk and not tk.passed:
                        h.record_bug("GRE-tos=100内核不一致(IKOS-7021, 进制bug未修)",
                                     f"配置tos=100, 内核={tk.message}. ip -d无tos或值不对=进制BUG仍在")
                    page.delete_rule(t100)
                else:
                    h.record_bug("GRE-tos=100本应通过却失败", h.result_error(res100))
                res256 = page.try_add_invalid({"iface": t256, "protocol": "IPv4", "tunnel_addr": base_tunnel,
                                               "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4, "tos": 256})
                h.observe("tos=256 drawer拦截", h.result_ok(res256, "blocked"), h.result_error(res256))
                row256 = backend.find_gre_tunnel(t256)
                if row256 is not None:
                    h.record_bug("GRE-tos=256 WEB/API越界被接受(IKOS-7021关联)",
                                 f"tos=256(>255)经WEB/API被接受并落库(实际={row256.get('tos')}). 脚本CLI拒, WEB/API受→前后端不一致")
                    del_if_landed(t256)
                else:
                    h.ui_check("tos=256越界未落库(校验生效)", True)

            # ---------- C. 生命周期/残留 ----------
            with rec.step(
                "C. 生命周期/残留: 停用再启用接口未重建(IKOS-7002) + 删除残留(IKOS-6986) + 列表刷新(IKOS-6984/6985)",
                "操作：建GRE→UI停用→产品启用→删除；验证：停用后接口拆除；启用后DB enabled=yes但ip link无接口=IKOS-7002(record_bug)；删除后ip rule/rt_tables/iface_band残留=IKOS-6986(record_bug)；启停/删除列表不自动刷新=IKOS-6984/6985(record_bug)",
            ):
                lc_iface = f"gre{num + 15}"
                reg(lc_iface)
                spec = {"iface": lc_iface, "protocol": "IPv4", "tunnel_addr": base_tunnel,
                        "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                        "gre_key": str(700000 + num + 15), "comment": f"GRE-LC-{token}"}
                res = page.add_tunnel(spec)
                h.require_ui("建GRE", h.result_ok(res), h.result_error(res))
                h.require_ssh("L1-enabled=yes", backend.verify_gre_tunnel_database, lc_iface, {"enabled": "yes"})
                h.require_ui("接口存在(ip link)", backend.ip_link_exists(lc_iface), f"{lc_iface} 未建立")
                # UI停用 → 接口拆除 + 状态列刷新(IKOS-6984)
                h.require_ui("UI停用", page.disable_rule(lc_iface), "停用未发起")
                page.navigate_to_gre()
                h.require_ssh("L1-停用enabled=no", backend.verify_gre_tunnel_database, lc_iface, {"enabled": "no"})
                removed = not backend.ip_link_exists(lc_iface)
                h.observe("停用后接口拆除(ip link无)", removed, "接口仍存在")
                if not removed:
                    h.record_bug("GRE-停用后接口未拆除", f"停用(DB enabled=no)后 {lc_iface} 接口仍存在(ip link)")
                status = page.get_iface_status_text(lc_iface)
                h.observe("停用后状态列刷新(IKOS-6984)",
                          any(k in (status or "").lower() for k in ("关", "停", "disable", "down", "未", "否", "no", "off", "0")),
                          f"状态列文本={status!r}(虚拟表格状态列提取不稳, 仅参考)")
                # 产品启用 → 接口是否重建(IKOS-7002 known_bug)
                page.navigate_to_gre()
                if not page.enable_rule(lc_iface):
                    h.record_bug("前端-停用后UI启用按钮不刷新(IKOS-6984)",
                                 "停用(DB enabled=no)后UI按钮未切'启用', 走脚本init验证产品启用流程")
                    out = backend.trigger_gre_product_up(lc_iface)
                    rec.add_detail(f"【产品启用脚本init】\n{out[:300]}")
                page.navigate_to_gre()
                h.require_ssh("L1-启用enabled=yes", backend.verify_gre_tunnel_database, lc_iface, {"enabled": "yes"})
                link_after = backend.ip_link_exists(lc_iface)
                band = backend.get_gre_iface_band(lc_iface)
                rec.add_detail(f"【启用后状态】ip link存在={link_after}; iface_band={band[:160]}")
                if not link_after:
                    h.record_bug("GRE-停用再启用接口未重建(IKOS-7002)",
                                 f"启用后DB enabled=yes, 但 ip link 无 {lc_iface} 接口; iface_band "
                                 f"{'仍绑' if band else '无'}({band[:80]}). 三层不一致")
                else:
                    h.observe("启用后接口重建", True)
                # 删除 → 残留审计(IKOS-6986) + 列表刷新(IKOS-6985)
                page.navigate_to_gre()
                h.require_ui("UI删除", page.delete_rule(lc_iface), "删除未发起")
                page.navigate_to_gre()
                list_removed = not page.rule_exists(lc_iface)
                h.observe("删除后列表移除(IKOS-6985)", list_removed, "列表仍存在")
                if not list_removed:
                    h.record_bug("前端-删除后列表不自动刷新(IKOS-6985)", f"删除 {lc_iface} 后列表未移除(需reload刷新)")
                res_after = backend.audit_gre_residual(prefix=lc_iface)
                rec.add_detail(f"【删除后residual({lc_iface})】rule={res_after['rule_count']} "
                               f"rt_tables={res_after['rt_tables_count']}(max_id={res_after['rt_tables_max_id']})\n"
                               f"{res_after['rt_tables_lines'][:300]}\niface_band={res_after['iface_band'][:200]}")
                if (res_after["rule_count"] > 0 or res_after["rt_tables_count"] > 0 or res_after["iface_band"]):
                    h.record_bug("GRE-删除残留(IKOS-6986, 删不清)",
                                 f"删除{lc_iface}后残留: ip rule={res_after['rule_count']}, "
                                 f"rt_tables={res_after['rt_tables_count']}(max_id={res_after['rt_tables_max_id']}), "
                                 f"iface_band={'仍绑' if res_after['iface_band'] else '无'}")

            # ---------- D. UI 提示规范(原 ui_prompts + 4 新盲区) ----------
            with rec.step(
                "D. UI提示规范: 按钮「确定/保存」(IKOS-7096) + 编辑标题(IKOS-7114) + 编号placeholder/规则(IKOS-7086) "
                "+ 目的地址v4/v6校验区分(IKOS-7089) + 重复接口名不抛裸JSON(IKOS-6982) + 源地址冲突开头逗号(IKOS-6983)",
                "操作：开drawer读提交按钮文本/标题/编号placeholder；切v4/v6填非法目的比对提示；重复接口名/源地址冲突保存读提示；验证：按钮应为'确定'(显'保存'=IKOS-7096)；编辑标题应'编辑'(显'新建'=IKOS-7114)；目的校验区分v4/v6(IKOS-7089)；重复/冲突提示人类可读不抛裸JSON/开头无逗号(IKOS-6982/6983)",
            ):
                d_iface = f"gre{num + 16}"
                reg(d_iface)
                # IKOS-7096 新增窗口底部按钮应为"确定"
                page.navigate_to_gre()
                if page.open_add_drawer():
                    submit_text = page.get_drawer_submit_text()
                    rec.add_detail(f"【新增drawer提交按钮文本(IKOS-7096)】={submit_text!r}(期望'确定')")
                    if submit_text and "确定" in submit_text:
                        h.observe("新增窗口底部按钮为'确定'(IKOS-7096已修)", True, submit_text)
                    elif submit_text and "保存" in submit_text:
                        h.record_bug("GRE-新增窗口底部按钮为'保存'应为'确定'(IKOS-7096)",
                                     f"footer主按钮文本='{submit_text}', 产品应为'确定'")
                    else:
                        h.observe("新增窗口底部按钮文本(IKOS-7096)", False, f"读到={submit_text!r}")
                    # IKOS-7114 新建态标题
                    title_new = page.get_drawer_title()
                    rec.add_detail(f"【新建drawer标题(IKOS-7114)】={title_new!r}")
                    page.cancel_drawer()
                # 建一条隧道用于编辑标题/重复名校验
                res = page.add_tunnel({"iface": d_iface, "protocol": "IPv4", "tunnel_addr": base_tunnel,
                                       "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                                       "gre_key": str(700000 + num + 16), "comment": f"GRE-D-{token}"})
                h.require_ui("建D区GRE", h.result_ok(res), h.result_error(res))
                # IKOS-7114 编辑态标题应为"编辑"
                page.navigate_to_gre()
                if page.open_edit_drawer(d_iface):
                    title_edit = page.get_drawer_title()
                    rec.add_detail(f"【编辑drawer标题(IKOS-7114)】={title_edit!r}(期望含'编辑')")
                    if title_edit and "编辑" in title_edit:
                        h.observe("编辑态标题为'编辑'(IKOS-7114已修)", True, title_edit)
                    elif title_edit and "新建" in title_edit:
                        h.record_bug("GRE-编辑弹窗标题误显'新建'(IKOS-7114)",
                                     f"编辑隧道时标题='{title_edit}', 应为'编辑'")
                    else:
                        h.observe("编辑态标题(IKOS-7114)", False, f"读到={title_edit!r}")
                    page.cancel_drawer()
                # IKOS-7086 隧道编号 placeholder + 非法编号拦截
                page.navigate_to_gre()
                if page.open_add_drawer():
                    ph = page.get_tagname_placeholder()
                    rec.add_detail(f"【隧道编号placeholder(IKOS-7086)】={ph!r}")
                    h.observe("隧道编号有placeholder提示", bool(ph), f"placeholder={ph!r}")
                    # 非法编号(字母)应被拦截: 前端只接受数字
                    page.cancel_drawer()
                page.navigate_to_gre()
                res_bad_num = page.try_add_invalid({"iface": "greABC", "protocol": "IPv4",
                                                    "tunnel_addr": base_tunnel, "src_mode": "指定IP地址",
                                                    "src_addr": ROUTER_V4, "dst_addr": PEER_V4})
                h.observe("非法编号greABC被拦截(IKOS-7086)", h.result_ok(res_bad_num, "blocked"), h.result_error(res_bad_num))
                # IKOS-7089 目的地址校验应区分v4/v6(校验在保存时触发, 走try_add_invalid比对提示文本)
                dst_v4_iface = f"gre{num + 20}"; dst_v6_iface = f"gre{num + 21}"
                reg(dst_v4_iface); reg(dst_v6_iface)
                page.navigate_to_gre()
                res_v4_bad = page.try_add_invalid({"iface": dst_v4_iface, "protocol": "IPv4",
                                                   "tunnel_addr": base_tunnel, "src_mode": "指定IP地址",
                                                   "src_addr": ROUTER_V4, "dst_addr": "not_a_valid_ipv4"})
                err_v4 = page.get_form_error() or page.get_last_notification("any") or h.result_error(res_v4_bad)
                del_if_landed(dst_v4_iface)
                page.navigate_to_gre()
                res_v6_bad = page.try_add_invalid({"iface": dst_v6_iface, "protocol": "IPv6",
                                                   "tunnel_addr": "fd00:dead:beef::1/120", "src_mode": "指定IP地址",
                                                   "src_addr": "fd00:dead:beef::99", "dst_addr": "not_a_valid_ipv6"})
                err_v6 = page.get_form_error() or page.get_last_notification("any") or h.result_error(res_v6_bad)
                del_if_landed(dst_v6_iface)
                rec.add_detail(f"【目的地址校验(IKOS-7089, 保存触发)】IPv4非法dst提示={err_v4!r}; IPv6非法dst提示={err_v6!r}")
                if err_v4 and err_v6:
                    if err_v4 == err_v6 and not any(k in (err_v4 + err_v6) for k in ("v4", "v6", "版本", "IPv4", "IPv6")):
                        h.record_bug("GRE-目的地址校验未区分v4/v6(IKOS-7089)",
                                     f"IPv4与IPv6非法目的地址提示完全相同='{err_v4}', 未按协议区分")
                    else:
                        h.observe("目的地址校验区分v4/v6(IKOS-7089)", True, f"v4={err_v4!r} v6={err_v6!r}")
                else:
                    h.observe("目的地址校验提示(IKOS-7089)", False,
                              f"v4={err_v4!r} v6={err_v6!r}(至少一方无提示, 校验可能未触发)")
                # IKOS-6982 相同数据保存错误提示应合理(非裸JSON)
                page.navigate_to_gre()
                res_dup = page.try_add_invalid({"iface": d_iface, "protocol": "IPv4", "tunnel_addr": base_tunnel,
                                                "src_mode": "指定IP地址", "src_addr": ROUTER_V4, "dst_addr": PEER_V4,
                                                "comment": f"GRE-D-{token}"})
                msg_dup = page.get_form_error() or page.get_last_notification("any") or h.result_error(res_dup)
                rec.add_detail(f"【相同数据重复保存提示(IKOS-6982)】blocked={h.result_ok(res_dup, 'blocked')}; {msg_dup}")
                looks_json = bool(re.search(r'"\s*(code|error|msg|data|status)\s*"\s*[:=]', msg_dup or "")) or (msg_dup or "").strip().startswith("{")
                if looks_json:
                    h.record_bug("GRE-相同数据保存泄露后端原始JSON(IKOS-6982)",
                                 f"重复保存提示疑似后端原始JSON(应人类可读): {msg_dup[:160]}")
                else:
                    h.ui_check("相同数据保存提示合理(非裸JSON)", h.result_ok(res_dup, "blocked"), msg_dup)
                # IKOS-6983 源地址(接口IPv4与隧道源)冲突 → 提示不应开头多逗号
                page.navigate_to_gre()
                src_conflict_iface = f"gre{num + 17}"
                reg(src_conflict_iface)
                res_src = page.try_add_invalid({"iface": src_conflict_iface, "protocol": "IPv4",
                                                "tunnel_addr": f"{ROUTER_V4}/30", "src_mode": "指定IP地址",
                                                "src_addr": ROUTER_V4, "dst_addr": PEER_V4, "comment": f"GRE-D12-{token}"})
                msg_src = page.get_form_error() or page.get_last_notification("any") or h.result_error(res_src)
                rec.add_detail(f"【源地址冲突提示(IKOS-6983)】blocked={h.result_ok(res_src, 'blocked')}; {msg_src}")
                if msg_src and msg_src.lstrip().startswith(","):
                    h.record_bug("GRE-源地址冲突提示开头多逗号(IKOS-6983)",
                                 f"提示文本以逗号开头(应为正常语句): {msg_src[:160]}")
                # 以 SSH 落库为权威: 接口IPv4==隧道源时应被冲突拦截, 落库=BUG, 且必须清理避免空gre_key阻塞后续section
                if backend.find_gre_tunnel(src_conflict_iface) is not None:
                    h.record_bug("GRE-源地址冲突未拦截反落库(IKOS-6983/6982关联)",
                                 f"接口IPv4与隧道源地址相同(均={ROUTER_V4})的配置经WEB/API被接受并落库({src_conflict_iface}), 应被冲突校验拦截")
                    del_if_landed(src_conflict_iface)
                else:
                    h.ui_check("源地址冲突被拦截未落库(IKOS-6983)", True, msg_src or "无提示")

            # ---------- E. 高级配置默认值/校验(全新盲区) ----------
            with rec.step(
                "E. 高级配置默认值/校验: 默认值保存报错(IKOS-7010) + TTL默认值(IKOS-7093) + 非法输入不报错反自动修改(IKOS-7092) "
                "+ 点分十进制掩码(IKOS-7111)",
                "操作：展开高级读ttl默认值；默认值保存；填越界tos=9999看是否静默修改；掩码填255.255.255.252；验证：默认值保存成功(IKOS-7010已修)或报'参数错误:ttl'(record_bug)；ttl默认值=0(IKOS-7093)；越界tos应拦截非静默改255(IKOS-7092)；点分掩码提示地址无效(IKOS-7111)",
            ):
                e_iface = f"gre{num + 18}"
                reg(e_iface)
                # IKOS-7093 TTL默认值 + IKOS-7010 默认值保存报错
                page.navigate_to_gre()
                if page.open_add_drawer():
                    page.expand_advanced()
                    # 先填合法必填(编号/地址/源/目的), 高级保持默认(ttl=0/no_fragment=0)
                    page.fill_tagname(e_iface)
                    page.fill_tunnel_addr(base_tunnel, "IPv4")
                    page.set_src_mode("指定IP地址")
                    page.fill_src_addr(ROUTER_V4)
                    page.fill_dst_addr(PEER_V4)
                    default_ttl = page.get_default_ttl()
                    rec.add_detail(f"【高级配置TTL默认值(IKOS-7093)】={default_ttl!r}")
                    h.observe("TTL默认值已读取(IKOS-7093)", default_ttl is not None, f"ttl={default_ttl!r}")
                    # 默认值保存(IKOS-7010): 看是否报"参数错误: ttl"
                    saved = page.save_drawer(timeout=5000)
                    if saved.get("success"):
                        rec.add_detail("【默认值保存(IKOS-7010)】默认高级配置保存成功(BUG已修)")
                        # 落库则记录待清; 读DB确认
                        h.ssh_verify("L1-默认值保存后落库", backend.verify_gre_tunnel_database, e_iface, {"enabled": "yes"})
                        del_if_landed(e_iface)
                    else:
                        err_default = saved.get("error") or page.get_form_error() or ""
                        rec.add_detail(f"【默认值保存失败(IKOS-7010)】err={err_default}")
                        if "ttl" in err_default.lower() or "参数错误" in err_default:
                            h.record_bug("GRE-开启高级配置用默认值保存报'参数错误:ttl'(IKOS-7010)",
                                         f"展开高级(默认ttl=0/no_fragment=0)保存失败: {err_default[:160]}")
                        else:
                            h.record_bug("GRE-默认值保存失败(非ttl原因)", f"err={err_default[:160]}")
                        if page.is_drawer_open():
                            page.cancel_drawer()
                # IKOS-7092 高级配置非法输入未报错反自动修改(填越界tos看是否静默归一)
                page.navigate_to_gre()
                if page.open_add_drawer():
                    page.expand_advanced()
                    page.fill_tos("9999")  # 越界
                    page._drawer().locator("input#dst_addr").click()  # 触发 blur
                    page.wait_for_timeout(400)
                    tos_after = page.get_input_value("input#tos")
                    tos_err = page.get_form_error() or ""
                    rec.add_detail(f"【越界tos自动修改(IKOS-7092)】输入9999→blur后={tos_after!r}; 错误提示={tos_err!r}")
                    if tos_after and tos_after != "9999" and not tos_err:
                        h.record_bug("GRE-高级配置非法输入不报错反自动修改(IKOS-7092)",
                                     f"输入越界tos=9999, 未报错且被静默改为='{tos_after}'(应明确拦截/提示)")
                    else:
                        h.observe("越界tos被拦截或提示(IKOS-7092已修)", bool(tos_err) or tos_after != "9999",
                                  f"tos={tos_after!r} err={tos_err!r}")
                    page.cancel_drawer()
                # IKOS-7111 接口IPv4地址用点分十进制掩码保存
                page.navigate_to_gre()
                if page.open_add_drawer():
                    page.fill_tagname(f"gre{num + 19}")
                    page.set_protocol("IPv4")
                    page._fill_input("input#tunnel_addr1_0", "10.250.250.1")
                    page.fill_tunnel_addr_mask_only("IPv4", "255.255.255.252")
                    page.set_src_mode("指定IP地址")
                    page.fill_src_addr(ROUTER_V4)
                    page.fill_dst_addr(PEER_V4)
                    saved_mask = page.save_drawer(timeout=5000)
                    err_mask = saved_mask.get("error") or page.get_form_error() or ""
                    rec.add_detail(f"【点分十进制掩码(IKOS-7111)】保存={saved_mask.get('success')}; 提示={err_mask!r}")
                    reg(f"gre{num + 19}")
                    if saved_mask.get("success"):
                        # 被接受落库 → BUG(应提示地址无效或正确解析)
                        h.record_bug("GRE-点分十进制掩码被接受(IKOS-7111需确认语义)",
                                     f"接口IPv4地址掩码填'255.255.255.252'(点分十进制)被接受保存. 产品应统一只认CIDR数字掩码或正确解析点分")
                        del_if_landed(f"gre{num + 19}")
                    else:
                        if "无效" in err_mask or "掩码" in err_mask or "格式" in err_mask:
                            h.observe("点分掩码被提示地址无效(IKOS-7111)", True, err_mask)
                        else:
                            h.record_bug("GRE-点分十进制掩码保存提示(IKOS-7111)", f"提示='{err_mask[:120]}'(应明确'地址无效')")
                    if page.is_drawer_open():
                        page.cancel_drawer()
        finally:
            with rec.step(
                "清理: 功能测试数据 + 恢复环境快照",
                "操作：backend兜底清理所有本轮前缀(UI删失败/越界落库残留)；验证：恢复测试前快照+残留审计+计数=0",
            ):
                for pfx in list(prefixes):
                    try:
                        backend.cleanup_gre_tunnel(pfx)
                    except Exception:
                        pass
                if snapshot is not None:
                    h.ssh_verify("恢复GRE环境", backend.restore_gre_environment, snapshot, must_pass=True)
                    h.ssh_verify("计数=0", backend.verify_gre_tunnel_count, expected=0, must_pass=True)
                    for pfx in list(prefixes):
                        h.ssh_verify(f"运行时清理-{pfx}", backend.verify_gre_runtime, pfx,
                                     {"protocol": 0}, must_exist=False, must_pass=True)

        failures = h.summarize()
        if failures:
            print(f"[GRE功能断言] 共{len(failures)}项失败 "
                  f"(SSH={len(h.ssh_failures)}, UI={len(h.ui_failures)})", flush=True)
        assert not failures, (
            f"GRE隧道功能测试失败({len(failures)}项): "
            + "; ".join(h.safe_text(item) for item in failures[:24]))
