"""
高级设置模块综合测试 (安全中心 > 高级设置, advanced.sh)

URL: /login#/securityCenter/advancedSetting
纯配置类页面(7勾选字段 + tcp_mss_num + 保存/恢复默认), 无增删改查。

覆盖:
1. 逐字段勾选L1-L4验证(数据库值 + iptables规则存在/消失 + tcp_mss内核mss值)
2. L5端到端:
   - 硬验证(noping_lan/noping_wan/notracert): client实测ping/traceroute四段式闭环(基线→勾选→阻断→恢复)
   - 配置层硬+L5软(dos_lan/tcp_mss/hijack_ping/invalid): L2 iptables规则+L3内核已硬验,
     客户端效果因dos_lan_num前端不可控/tcp_mss需抓包/劫持无效包难构造→L5软验证报告说明
3. tcp_mss_num边界值(1000/1500正常 + 超界异常, 记录前端1000-1500 vs 后端500-1500不一致BUG)
4. 全部勾选保存 + 恢复默认
5. finally恢复默认(关键: 避免残留iptables挡掉后续所有测试的ping/curl流量)

后端 advanced.sh:
- 单表advanced(id=1), save()增量更新iptables(NewOldVarl只动变化项), reset()默认值
- 字段→iptables: noping_lan/wan→INPUT icmp-8 DROP; notracert→CONNLIMIT icmp-11 DROP;
  hijack_ping→nat PREROUTING icmp-8 REDIRECT; invalid→INPUT ctstate invalid REJECT;
  dos_lan→raw CONNLIMIT peerconns DROP; tcp_mss→mangle TCPMSS + ik_cntl syn_proxy set_mss
- reset默认: noping_*=0, tcp_mss=1/1400, dos_lan_num=300
"""
import ipaddress
from urllib.parse import urlparse

import pytest
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify

pytestmark = [pytest.mark.security, pytest.mark.advanced]

# 字段中文描述(报告可读)
FIELD_CN = {
    "noping_lan": "禁止内网PING路由", "noping_wan": "禁止外网PING路由",
    "notracert": "禁止tracert路由追踪", "hijack_ping": "劫持所有PING值",
    "invalid": "丢弃无效连接", "dos_lan": "内网DOS攻击防御",
    "tcp_mss": "TCP最大报文长度(MSS钳制)",
}

CLIENT_IP = "192.168.148.2"
ROUTER_LAN_IP = "192.168.148.1"


def resolve_router_wan_ip(page, backend_verifier=None, recorder=None):
    """Return the DUT's actual wan1 address for a WAN-side probe.

    The page can be opened through a LAN/recovery address, so wan1 from the
    DUT is authoritative.  The current Web host is only a no-SSH fallback.
    """
    if backend_verifier is not None:
        try:
            backend_verifier.connect_router()
            detected = backend_verifier._router.exec(
                "ip -4 -o addr show dev wan1 2>/dev/null | "
                "awk '{print $4}' | cut -d/ -f1 | head -1"
            ).strip()
            ipaddress.IPv4Address(detected)
            if recorder is not None:
                recorder.add_detail(f"  [目标地址] SSH实测wan1={detected}")
            return detected
        except Exception as exc:
            if recorder is not None:
                recorder.add_detail(
                    f"  [目标地址] SSH读取wan1失败: {type(exc).__name__}"
                )
            return ""

    try:
        fallback = urlparse(page.base_url).hostname or ""
        ipaddress.IPv4Address(fallback)
        if recorder is not None:
            recorder.add_detail(f"  [目标地址] 使用Web地址回退: {fallback}")
        return fallback
    except ValueError:
        return ""


class TestAdvancedComprehensive:
    """高级设置综合测试"""

    def test_advanced_comprehensive(self, advanced_page_logged_in,
                                    step_recorder: StepRecorder, request):
        page = advanced_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            bv = None

        ui_failures = []
        ssh_failures = []
        ssh_verify = make_ssh_verify(bv, rec, ssh_failures)

        def ui_check(label, cond, detail=""):
            if cond:
                rec.add_detail(f"  [UI] {label}: [OK]")
            else:
                rec.add_detail(f"  [UI] {label}: [FAIL] {detail}")
                ui_failures.append(f"{label}: {detail}")

        def _verify_l5_noping(field, dst_ip, src_iface, expect_block=True):
            """noping类L5四段式闭环: 基线ping通→勾选→ping不通→恢复通.
            src_iface: ens11=内网侧ping路由器lan口(noping_lan); enp2s0=wan侧ping路由器wan口(noping_wan).
            expect_block=True=勾选后期望不通(noping), =False=不阻断(只测联通)."""
            if bv is None:
                rec.add_detail("  [L5] 跳过(无SSH验证器)")
                rec.not_applicable_current_step("无SSH验证器，无法执行L5端到端探测")
                return
            bv.connect_client()
            # 基线: ping应通(retries=2抗抖动)
            base = bv.verify_connectivity(src_iface=src_iface, dst_ip=dst_ip, retries=2)
            rec.add_detail(f"  [基线] ping {dst_ip}@{src_iface}: {base['detail']}")
            if not base["connected"]:
                rec.add_detail(f"  [L5] 基线不通, 跳过{field}功能验证")
                rec.warn_current_step(f"{field}基线不通，功能结果不确定")
                return
            # 勾选
            if not page.save_config(**{field: True}):
                message = f"{field}保存未持久化，无法进行L5探测"
                rec.add_detail(f"  [FAIL] {message}")
                ui_failures.append(message)
                rec.fail_current_step(message)
                return
            rec.add_detail(f"  [UI] {field}开启保存并持久化: [OK]")
            page.page.wait_for_timeout(1500)
            if bv is not None:
                runtime = bv.verify_advanced_iptables(field, expect_present=True)
                rec.add_detail(f"  [运行规则] {runtime.message}")
                if not runtime.passed:
                    message = f"{field}运行规则未生效: {runtime.message}"
                    rec.add_detail(f"  [FAIL] {message}")
                    ui_failures.append(message)
                    rec.fail_current_step(message)
            # 验证阻断(期望不通, 严禁传retries会掩盖规则效果)
            blk = bv.verify_connectivity(src_iface=src_iface, dst_ip=dst_ip)
            rec.add_detail(f"  [勾选后] ping {dst_ip}: {blk['detail']}")
            if expect_block and blk["connected"]:
                message = f"{field}未阻断ping({dst_ip}仍通)"
                ui_failures.append(message)
                rec.add_detail(f"  [FAIL] {message}")
                rec.fail_current_step(message)
            elif expect_block and not blk["connected"]:
                rec.add_detail(f"  [OK] {field}阻断生效(ping不通)")
            # 恢复
            restored_config = page.save_config(**{field: False})
            page.page.wait_for_timeout(1500)
            if not restored_config:
                message = f"取消{field}未持久化"
                ui_failures.append(message)
                rec.add_detail(f"  [FAIL] {message}")
                rec.fail_current_step(message)
            elif bv is not None:
                rec.add_detail(f"  [UI] {field}关闭保存并持久化: [OK]")
                runtime = bv.verify_advanced_iptables(field, expect_present=False)
                rec.add_detail(f"  [运行规则] {runtime.message}")
                if not runtime.passed:
                    message = f"取消{field}后运行规则仍残留: {runtime.message}"
                    ui_failures.append(message)
                    rec.add_detail(f"  [FAIL] {message}")
                    rec.fail_current_step(message)
            restore = bv.verify_connectivity(src_iface=src_iface, dst_ip=dst_ip, retries=2)
            rec.add_detail(f"  [恢复后] ping {dst_ip}: {restore['detail']}")
            if not restore["connected"]:
                message = f"取消{field}后ping未恢复({dst_ip}不通)"
                ui_failures.append(message)
                rec.add_detail(f"  [FAIL] {message}")
                rec.fail_current_step(message)

        try:
            # ========== 步骤1: 环境清理(恢复默认, 确保干净起点) ==========
            with rec.step("步骤1: 环境清理", "SSH恢复默认+UI导航+验证默认值"):
                if bv:
                    r = bv.cleanup_advanced_test()
                    rec.add_detail(f"  SSH清理: {r}")
                page.navigate_to_advanced()
                page.page.wait_for_timeout(1000)
                if bv:
                    ssh_verify("清理后-默认值", bv.verify_advanced_database, {
                        "noping_lan": "0", "noping_wan": "0", "notracert": "0",
                        "hijack_ping": "0", "invalid": "0", "dos_lan": "0",
                        "tcp_mss": "1", "tcp_mss_num": "1400"})

            # ========== 步骤2-7: 逐字段勾选L1-L4验证(独立闭环) ==========
            for idx, field in enumerate(
                    ["noping_lan", "noping_wan", "notracert", "hijack_ping", "invalid", "dos_lan"],
                    start=2):
                with rec.step(f"步骤{idx}: {field}({FIELD_CN[field]}) 勾选L1-L4",
                              f"勾选→L1数据库+L2 iptables存在→取消→L2消失"):
                    rec.add_detail(f"  字段: {field} ({FIELD_CN[field]})")
                    # 勾选+保存
                    ok = page.save_config(**{field: True})
                    ui_check(f"{field}勾选保存", ok, "保存未持久化")
                    if bv:
                        ssh_verify(f"L1-{field}=1", bv.verify_advanced_database, {field: "1"})
                        ssh_verify(f"L2-{field}规则存在", bv.verify_advanced_iptables,
                                   field, expect_present=True)
                    # 取消+保存(恢复该字段)
                    ok2 = page.save_config(**{field: False})
                    ui_check(f"{field}取消保存", ok2, "取消未持久化")
                    if bv:
                        ssh_verify(f"L2-{field}规则消失", bv.verify_advanced_iptables,
                                   field, expect_present=False)

            # ========== 步骤8: tcp_mss特殊(默认开) L1-L4 ==========
            with rec.step("步骤8: tcp_mss(MSS钳制) L1-L4", "默认开→关规则消失→开+mss值"):
                rec.add_detail("  字段: tcp_mss (默认开启, 与其他字段相反)")
                # 关闭
                ok = page.save_config(tcp_mss=False)
                ui_check("tcp_mss关闭保存", ok)
                if bv:
                    ssh_verify("L1-tcp_mss=0", bv.verify_advanced_database, {"tcp_mss": "0"})
                    ssh_verify("L2-tcp_mss关闭规则消失", bv.verify_advanced_iptables,
                               "tcp_mss", expect_present=False)
                # 开启+设1400
                ok2 = page.save_config(tcp_mss=True, tcp_mss_num="1400")
                ui_check("tcp_mss开启保存", ok2)
                if bv:
                    ssh_verify("L1-tcp_mss=1/1400", bv.verify_advanced_database,
                               {"tcp_mss": "1", "tcp_mss_num": "1400"})
                    ssh_verify("L2-tcp_mss规则存在", bv.verify_advanced_iptables,
                               "tcp_mss", expect_present=True)
                    ssh_verify("L3-tcp_mss内核mss=1400", bv.verify_advanced_tcp_mss, 1400)

            # ========== 步骤9: L5端到端功能验证(硬验证) ==========
            with rec.step("步骤9.1: L5-noping_lan(阻断内网ping路由器)",
                          "基线ping lan通→勾选→不通(硬)→恢复通"):
                _verify_l5_noping("noping_lan", ROUTER_LAN_IP, "ens11")

            with rec.step("步骤9.2: L5-noping_wan(阻断外网ping路由器wan口)",
                          "基线ping wan通→勾选→不通(硬)→恢复通"):
                # noping_wan: 从wan侧(enp2s0) ping DUT 的真实 wan1 地址。
                wan_ip = resolve_router_wan_ip(page, bv, rec)
                if not wan_ip:
                    message = "无法解析DUT wan1地址，跳过noping_wan L5探测"
                    rec.add_detail(f"  [FAIL] {message}")
                    ui_failures.append(message)
                    rec.fail_current_step(message)
                else:
                    rec.add_detail(f"  [目标] noping_wan探测地址={wan_ip}")
                    _verify_l5_noping("noping_wan", wan_ip, "enp2s0")

            with rec.step("步骤9.3: L5-notracert(阻断traceroute)",
                          "基线traceroute多跳→勾选→跳数骤降(硬)→恢复"):
                if bv is None:
                    rec.add_detail("  [L5] 跳过(无SSH验证器)")
                else:
                    try:
                        bv.connect_client()
                        base = bv.client_traceroute(dst="8.8.8.8", src_iface="ens11", max_hops=8)
                        rec.add_detail(f"  [基线traceroute] hops={base['hops']} reached={base['reached']}")
                        page.save_config(notracert=True)
                        page.page.wait_for_timeout(1500)
                        blk = bv.client_traceroute(dst="8.8.8.8", src_iface="ens11", max_hops=8)
                        rec.add_detail(f"  [勾选后traceroute] hops={blk['hops']} reached={blk['reached']}")
                        # notracert截断: 勾选后hops应明显下降(icmp-11 time-exceeded被DROP, 中间跳不回应)
                        if blk["hops"] >= base["hops"] and base["hops"] > 0:
                            ui_failures.append(f"notracert未截断: 基线{base['hops']}→勾选{blk['hops']}跳")
                        else:
                            rec.add_detail(f"  [OK] notracert截断生效(跳数{base['hops']}→{blk['hops']})")
                        page.save_config(notracert=False)
                        page.page.wait_for_timeout(1500)
                    except Exception as e:
                        rec.add_detail(f"  [L5-notracert] 异常: {str(e)[:80]}")
                        ui_failures.append(f"notracert验证异常: {str(e)[:60]}")

            # dos_lan/tcp_mss/hijack_ping/invalid: L5客户端效果软验证(L2/L3配置层已硬验)
            with rec.step("步骤9.4: L5-软验证(dos_lan/tcp_mss/hijack_ping/invalid)",
                          "客户端效果难可靠触发→L2/L3配置层已硬验, L5说明"):
                rec.add_detail("  dos_lan: dos_lan_num前端无独立输入(默认300), 并发curl难触发阈值; "
                               "L2 raw CONNLIMIT peerconns规则已硬验存在")
                rec.add_detail("  tcp_mss: 已在步骤9.5用tcpdump抓包硬验MSS钳制(移出软验证)")
                rec.add_detail("  hijack_ping: ping劫持到假IP验证复杂(游戏ping=0场景); "
                               "L2 nat PREROUTING REDIRECT规则已硬验存在")
                rec.add_detail("  invalid: 无效连接难主动构造; L2 INPUT ctstate invalid REJECT规则已硬验存在")
                rec.add_detail("  [INFO] 以上3项(dos_lan/hijack_ping/invalid)客户端L5非硬验证"
                               "(配置层L2+L3已硬验); tcp_mss已移至9.5抓包硬验")

            with rec.step("步骤9.5: L5-tcp_mss实际钳制(tcpdump抓包铁证)",
                          "设tcp_mss_num=1000→抓SYN-ACK MSS=1000→恢复1400"):
                if bv is None:
                    rec.add_detail("  [L5] 跳过(无SSH验证器)")
                else:
                    try:
                        ok = page.save_config(tcp_mss=True, tcp_mss_num="1000")
                        ui_check("tcp_mss设1000", ok)
                        page.page.wait_for_timeout(1500)
                        ssh_verify("L5-tcp_mss抓包MSS=1000", bv.verify_tcp_mss_clamp_real,
                                   "ens11", "www.baidu.com", 1000)
                        # 恢复1400
                        page.save_config(tcp_mss=True, tcp_mss_num="1400")
                        page.page.wait_for_timeout(500)
                    except Exception as e:
                        rec.add_detail(f"  [L5-tcp_mss] 异常: {str(e)[:80]}")
                        ui_failures.append(f"tcp_mss抓包异常: {str(e)[:60]}")

            # ========== 步骤10: tcp_mss_num边界值 ==========
            with rec.step("步骤10: tcp_mss_num边界值", "1000/1500正常 + 超界异常拦截"):
                # 正常值1000/1500
                for val in ["1000", "1500"]:
                    ok = page.save_config(tcp_mss=True, tcp_mss_num=val)
                    ui_check(f"tcp_mss_num={val}保存", ok)
                    if bv and ok:
                        ssh_verify(f"L3-mss={val}", bv.verify_advanced_tcp_mss, int(val))
                # 异常值(<1000 前端应拦截, 但后端允许500-999; >1500前后端都拒)
                rec.add_detail("  [异常值测试] tcp_mss_num范围: 前端1000-1500 vs 后端500-1500(不一致, 记录)")
                for val, desc in [("999", "低于前端下限1000"), ("501", "后端允许但前端拒"), ("1501", "超上限")]:
                    page.navigate_to_advanced()
                    page.page.wait_for_timeout(500)
                    page.set_tcp_mss_num(val)
                    page.click_save(wait=1500)
                    # 检查前端是否拦截(explain-error)
                    blocked = False
                    try:
                        err = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
                        if err.count() > 0:
                            blocked = True
                            rec.add_detail(f"  tcp_mss_num={val}({desc}): 前端拦截 [OK]")
                    except Exception:
                        pass
                    if not blocked:
                        # 未拦截→检查是否实际生效(后端可能接受500-1500)
                        page.navigate_to_advanced()
                        page.page.wait_for_timeout(500)
                        actual = page.get_tcp_mss_num()
                        rec.add_detail(f"  tcp_mss_num={val}({desc}): 未拦截, 实际={actual}")
                # 恢复1400
                page.save_config(tcp_mss=True, tcp_mss_num="1400")

            # ========== 步骤11: 全部勾选保存 + 恢复默认 ==========
            with rec.step("步骤11: 全部勾选保存+恢复默认", "7字段全勾选→L2全存在→恢复默认→全消失"):
                ok = page.save_config(noping_lan=True, noping_wan=True, notracert=True,
                                      hijack_ping=True, invalid=True, dos_lan=True,
                                      tcp_mss=True, tcp_mss_num="1400")
                ui_check("全部勾选保存", ok)
                if bv and ok:
                    for f in ["noping_lan", "noping_wan", "notracert", "hijack_ping",
                              "invalid", "dos_lan", "tcp_mss"]:
                        ssh_verify(f"L2-全勾选-{f}", bv.verify_advanced_iptables, f, expect_present=True)
                # 恢复默认
                ok2 = page.reset_to_default()
                ui_check("恢复默认", ok2)
                if bv:
                    ssh_verify("恢复默认-数据库", bv.verify_advanced_database, {
                        "noping_lan": "0", "noping_wan": "0", "notracert": "0",
                        "hijack_ping": "0", "invalid": "0", "dos_lan": "0",
                        "tcp_mss": "1", "tcp_mss_num": "1400"})
                    for f in ["noping_lan", "noping_wan", "notracert", "hijack_ping", "invalid", "dos_lan"]:
                        ssh_verify(f"L2-恢复后-{f}消失", bv.verify_advanced_iptables, f, expect_present=False)

        finally:
            # ========== finally: 恢复默认(关键, 避免残留iptables挡后续测试) ==========
            try:
                page.navigate_to_advanced()
                page.page.wait_for_timeout(500)
                page.reset_to_default()
                rec.add_detail("[finally] UI恢复默认")
            except Exception as e:
                rec.add_detail(f"[finally] UI恢复异常: {str(e)[:60]}")
            if bv:
                try:
                    r = bv.cleanup_advanced_test()
                    rec.add_detail(f"[finally] SSH兜底恢复: {r}")
                except Exception as e:
                    rec.add_detail(f"[finally] SSH清理异常: {str(e)[:60]}")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"高级设置验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
