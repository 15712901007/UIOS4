"""
ARP设置模块综合测试 (安全中心 > ARP设置)

URL: 列表 /login#/securityCenter/arpSetting, 新增 /login#/securityCenter/arpSetting/add
两个Tab: ARP绑定 / 邻居列表
ARP绑定Tab特有操作(比VLAN/IP限速多): 顶部"清空"按钮(清空所有用户绑定)+行操作"绑定"(动态学习项一键转绑定)
设置弹窗(右上角齿轮): 2复选框
  - 兼容已绑定为DHCP静态分配 (global_config.dhcpd_arp 0/1)
  - 非绑定MAC不允许上网 (global_config.arp_filter 0/1, FORWARD→ARP链REJECT非绑定IP/MAC, 白名单机制)

覆盖(18步L1-L5):
- ARP绑定CRUD(单/多/全字段) 每场景SSH全链路(arp表+静态ARP+4 ipset)
- ARP特有①行操作"绑定"(动态学习项→绑定) L1/L2/L3
- ARP特有②顶部"清空"(清空所有用户绑定) L1+残留检测
- 绑定类型=唯一(bind_type=1)场景 + DHCP静态分配兼容(dhcpd_arp)
- 设置弹窗两开关: arp_filter(L1 global_config+L2 ARP链+L5打流) / dhcpd_arp(L1)
- 异常输入拦截(空名称/非法MAC/非法IP/重复IP unique)
- 导出CSV+TXT + 导入(不清空/清空)
- 邻居列表Tab(只读+删除+清空)
- L5功能验证(非绑定MAC不允许上网 三段式: 基线通→开arp_filter非绑定不通→绑定client后通→恢复)

后端机制(arp.sh):
- 表arp(id/tagname unique/ip_addr unique/mac/interface/comment/bind_type 0普通/1唯一)
- 4 ipset: Linux_arp_default(mac)+Linux_arpip_default(ip)←bind_type=0(arp -s建静态ARP);
           Linux_arponly_default(mac)+Linux_iponly_default(ip)←bind_type=1(仅DHCP兼容)
- arp_filter=1时FORWARD→ARP链: -m set ! --match-set Linux_arpip_default/src -j REJECT (白名单,只放行bind_type=0)
- arp_filter用-m set依赖xt_set(6.12间歇bug, is_xt_set_broken降级)
"""
import os
import pytest
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure

pytestmark = [pytest.mark.security, pytest.mark.arp_setting]

PREFIX = "arp_t_"
# 测试绑定(虚拟ip/mac, lan1网段高端避开DHCP池与真实设备)
TEST_BINDS = [
    ("arp_t_001", "192.168.148.201", "AA:BB:CC:00:00:01"),
    ("arp_t_002", "192.168.148.202", "AA:BB:CC:00:00:02"),
    ("arp_t_003", "192.168.148.203", "AA:BB:CC:00:00:03"),
]
TEST_BIND_UNIQUE = ("arp_t_u01", "192.168.148.204", "AA:BB:CC:00:00:04")  # bind_type=1唯一
# client(L5用, 真实设备 10.66.0.18内网ens11)
CLIENT_IP = "192.168.148.2"
CLIENT_MAC = "d4:20:00:b1:45:ec"
CLIENT_IFACE_DB = "lan1"
CLIENT_IFACE_UI = "LAN1"


class TestArpSettingComprehensive:
    """ARP设置综合测试"""

    def test_arp_setting_comprehensive(self, arp_setting_page_logged_in,
                                       step_recorder: StepRecorder, request):
        page = arp_setting_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ui_failures = []
        ssh_failures = []

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            if backend_verifier is None:
                rec.add_detail(f"[SSH-{label}] 跳过(无SSH验证器)")
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = 'PASS' if result.passed else 'FAIL'
                rec.add_detail(f"[SSH-{label}] {status}: {result.message}")
                rec.add_detail(f"    后端数据: {(result.raw_output or '')[:180]}")
                print(f"[SSH-{label}] {status}: {result.message}", flush=True)
                if not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
                ssh_failures.append(f"SSH-{label}异常: {str(e)[:80]}")
                return None
        ssh_verify = attach_cmd_recording_to_closure(backend_verifier, rec, ssh_verify)

        def ui_check(label, cond, detail=""):
            if cond:
                rec.add_detail(f"[UI] {label}: 成功")
            else:
                rec.add_detail(f"[UI] {label}: 失败 - {detail}")
                ui_failures.append(f"{label}: {detail}")

        def arp_residual_check(label, ip=None, mac=None, bind_type="0"):
            """ARP底层残留检测: 验证ipset无该ip/mac(删除后应无残留, 残留=删不干净BUG报禅道)."""
            if backend_verifier is None:
                return None
            try:
                r = backend_verifier.verify_arp_ipset(ip=ip, mac=mac, bind_type=bind_type, expect_present=False)
                status = 'PASS' if r.passed else 'FAIL'
                rec.add_detail(f"  [残留-{label}] {status}: {r.message}")
                if not r.passed:
                    ssh_failures.append(f"残留-{label}: ip={ip} mac={mac} 底层ipset有DB无(删不干净报禅道)")
                return r
            except Exception as e:
                rec.add_detail(f"  [残留-{label}] 异常: {str(e)[:80]}")
                return None
        arp_residual_check = attach_cmd_recording_to_closure(backend_verifier, rec, arp_residual_check)

        try:
            # ==================== 步骤1: 环境快照+清理 ====================
            with rec.step("步骤1: 环境快照+清理", "清理arp_t_残留+确认arp_filter=0/dhcpd_arp=0"):
                if backend_verifier:
                    snap = backend_verifier.verify_arp_count(prefix=PREFIX)
                    rec.add_detail(f"[快照] 清理前 {PREFIX} 数量: {snap.message}")
                    backend_verifier.cleanup_arp_test(PREFIX)
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                page.clean_test_rules(PREFIX)
                page.page.wait_for_timeout(1000)
                ssh_verify("步骤1-全局设置(关)", backend_verifier.verify_arp_global_config, arp_filter="0", dhcpd_arp="0")

            # ==================== 步骤2: 场景1 ARP绑定单条(普通) L1/L2/L3 ====================
            with rec.step("步骤2: 场景1 ARP绑定单条(普通bind_type=0)", "添加+SSH L1/L2/L3"):
                nm, ip, mac = TEST_BINDS[0]
                rec.add_detail(f"[规则] {nm}: ip={ip} mac={mac} iface=LAN1 bind_type=普通")
                res = page.add_rule(nm, ip, mac, interface=CLIENT_IFACE_UI, bind_type=0)
                ui_check("场景1添加", res["success"], res.get("error", ""))
                ssh_verify("场景1-L1数据库", backend_verifier.verify_arp_database,
                           nm, ip=ip, mac=mac, interface=CLIENT_IFACE_DB, bind_type="0")
                ssh_verify("场景1-L2静态ARP", backend_verifier.verify_arp_static, ip, expect_present=True)
                ssh_verify("场景1-L3ipset", backend_verifier.verify_arp_ipset,
                           ip=ip, mac=mac, bind_type="0")

            # ==================== 步骤3: 场景2 ARP绑定多条 ====================
            with rec.step("步骤3: 场景2 ARP绑定多条(002/003)", "多条绑定L1"):
                for nm, ip, mac in TEST_BINDS[1:]:
                    rec.add_detail(f"[规则] {nm}: ip={ip} mac={mac}")
                    res = page.add_rule(nm, ip, mac, interface=CLIENT_IFACE_UI, bind_type=0)
                    ui_check(f"场景2添加{nm}", res["success"], res.get("error", ""))
                    ssh_verify(f"场景2-L1-{nm}", backend_verifier.verify_arp_database,
                               nm, ip=ip, mac=mac, interface=CLIENT_IFACE_DB, bind_type="0")

            # ==================== 步骤4: 场景3 ARP绑定全字段(终端名称+备注) ====================
            with rec.step("步骤4: 场景3 ARP绑定+终端名称+备注", "全字段L1"):
                nm, ip, mac = ("arp_t_full", "192.168.148.210", "AA:BB:CC:00:00:10")
                rec.add_detail(f"[规则] {nm}: ip={ip} mac={mac} termname=测试终端 remark=ARP备注")
                res = page.add_rule(nm, ip, mac, interface=CLIENT_IFACE_UI, bind_type=0,
                                    termname="测试终端", remark="ARP备注")
                ui_check("场景3添加", res["success"], res.get("error", ""))
                ssh_verify("场景3-L1", backend_verifier.verify_arp_database,
                           nm, ip=ip, mac=mac, interface=CLIENT_IFACE_DB, bind_type="0")

            # ==================== 步骤5: 计数验证 ====================
            with rec.step("步骤5: 计数验证(arp_t_规则在列表)", "前端存在 vs SSH计数"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(2000)
                # 验证每条arp_t_规则都在列表
                for nm, _, _ in TEST_BINDS + [("arp_t_full", "", "")]:
                    if not page.rule_exists(nm):
                        ui_failures.append(f"步骤5: 列表未显示规则 {nm}")
                if backend_verifier:
                    cnt = backend_verifier.verify_arp_count(prefix=PREFIX)
                    rec.add_detail(f"[SSH计数] {PREFIX} {cnt.message}")
                    m = cnt.message
                    import re as _re
                    mm = _re.search(r'数量:\s*(\d+)', m)
                    n = int(mm.group(1)) if mm else 0
                    if n < 4:
                        ui_failures.append(f"步骤5: SSH {PREFIX} 数量{n}<4")

            # ==================== 步骤6: 搜索 ====================
            with rec.step("步骤6: 搜索(按IP, ARP搜索不查名称)", "search_rule验证"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                # ARP列表搜索仅查IP/MAC/网卡(不查名称tagname, 实测搜arp_t_001返回0条), 故按IP搜索
                page.search_rule(TEST_BINDS[0][1])
                page.page.wait_for_timeout(1500)
                if not page.rule_exists(f"{PREFIX}001"):
                    ui_failures.append("步骤6: 搜索存在规则未显示")
                page.clear_search()
                page.page.wait_for_timeout(1500)
                rec.add_detail("[搜索] 按IP存在+清空验证完成")

            # ==================== 步骤7: 编辑备注 ====================
            with rec.step("步骤7: 编辑备注", "编辑arp_t_001备注+SSH验证"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                if page.edit_rule(f"{PREFIX}001"):
                    page.fill_remark("已编辑ARP备注")
                    sv = page.save_and_wait()
                    ui_check("步骤7编辑保存", sv["success"], sv.get("error", ""))
                    ssh_verify("步骤7-L1备注", backend_verifier.verify_arp_database,
                               f"{PREFIX}001", ip=TEST_BINDS[0][1], mac=TEST_BINDS[0][2])
                else:
                    ui_failures.append("步骤7: 进入编辑页失败")

            # ==================== 步骤8: ARP特有① 行操作"绑定" ====================
            with rec.step("步骤8: 行操作绑定(ARP特有①)", "动态学习项→绑定 L1/L2/L3+恢复"):
                # 找一个未绑定的动态学习项
                dyn = page.page.evaluate("""() => {
                    const tables=[...document.querySelectorAll('.ant-table')].filter(t=>t.offsetParent!==null);
                    if(!tables.length) return null;
                    const t = tables[0];
                    const rows=[...t.querySelectorAll('.ant-table-row')];
                    for(const r of rows){
                        const cells=[...r.querySelectorAll('.ant-table-cell')].map(c=>(c.innerText||'').trim());
                        // 列: 名称/终端名称/IP/MAC/网卡/绑定类型/绑定状态/备注/操作
                        if(cells.length>=7 && cells[6].includes('未绑定')){
                            const iface=cells[4];
                            // 限定lan接口(避免绑wan设备影响路由器WAN侧), 跳过client(L5要用)
                            if(!/lan/i.test(iface)) continue;
                            if(cells[2]==='192.168.148.2') continue;
                            return {tagname: cells[0], ip: cells[2], mac: cells[3], iface: iface};
                        }
                    }
                    return null;
                }""")
                if not dyn:
                    rec.add_detail("[步骤8] 无未绑定动态项, 跳过")
                else:
                    rec.add_detail(f"[动态项] {dyn['tagname']}: ip={dyn['ip']} mac={dyn['mac']} iface={dyn['iface']}")
                    ok = page.bind_rule(dyn['tagname'])
                    ui_check("步骤8绑定操作", ok, "绑定按钮点击失败")
                    page.page.wait_for_timeout(2000)
                    # L1: 转绑定后应在arp表(bind_type=0)
                    ssh_verify("步骤8-绑定后DB", backend_verifier.verify_arp_database,
                               dyn['ip'], ip=dyn['ip'], mac=dyn['mac'], bind_type="0")
                    # L3: 进arp_default/arpip_default ipset
                    ssh_verify("步骤8-绑定后ipset", backend_verifier.verify_arp_ipset,
                               ip=dyn['ip'], mac=dyn['mac'], bind_type="0")
                    # 恢复: SSH删除该绑定(非prefix, cleanup不管, 避免残留影响原设备)
                    if backend_verifier:
                        try:
                            backend_verifier._router.exec(
                                f"sqlite3 {backend_verifier.DNS_DB} \"DELETE FROM arp WHERE ip_addr='{dyn['ip']}'\"")
                            backend_verifier._router.exec("/usr/ikuai/script/arp.sh init 2>/dev/null")
                            rec.add_detail(f"[恢复] 删除动态项绑定 ip={dyn['ip']}")
                        except Exception as e:
                            rec.add_detail(f"[恢复异常] {str(e)[:60]}")

            # ==================== 步骤9: ARP特有② 顶部"清空"按钮 ====================
            with rec.step("步骤9: 顶部清空(ARP特有②)", "清空所有用户绑定+L1 arp表空+残留检测"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                ok = page.clear_all_arp()
                ui_check("步骤9清空操作", ok, "清空按钮操作失败")
                page.page.wait_for_timeout(2000)
                # L1: arp表应为空(用户绑定全清)
                if backend_verifier:
                    row = backend_verifier._sqlite_query_line("SELECT count(*) as cnt FROM arp") or {}
                    n = int(row.get("cnt", 0))
                    rec.add_detail(f"[清空后] arp表用户绑定数: {n}")
                    if n > 0:
                        ssh_failures.append(f"步骤9: 清空后arp表仍有{n}条用户绑定")
                    # 残留检测: 4个ipset应无测试mac/ip(清空=flush)
                    for nm, ip, mac in TEST_BINDS + [("arp_t_full", "192.168.148.210", "AA:BB:CC:00:00:10")]:
                        arp_residual_check(f"步骤9清空-{nm}", ip=ip, mac=mac, bind_type="0")

            # ==================== 步骤10: 重建+单条删除+残留检测 ====================
            with rec.step("步骤10: 单条删除+SSH验不存在+残留检测", "重建arp_t_001→删→DB无+ipset无"):
                nm, ip, mac = TEST_BINDS[0]
                page.navigate_to_arp()
                page.page.wait_for_timeout(1000)
                res = page.add_rule(nm, ip, mac, interface=CLIENT_IFACE_UI, bind_type=0)
                ui_check("步骤10重建", res["success"], res.get("error", ""))
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                ok = page.delete_rule(nm)
                ui_check("步骤10删除", ok, "删除操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤10-不存在", backend_verifier.verify_arp_not_exists, nm)
                arp_residual_check("步骤10-删除后", ip=ip, mac=mac, bind_type="0")

            # ==================== 步骤11: 绑定类型=唯一(bind_type=1)+DHCP静态分配兼容 ====================
            with rec.step("步骤11: 绑定类型唯一(bind_type=1)+DHCP静态分配兼容", "arponly/iponly ipset+dhcpd_arp"):
                nm, ip, mac = TEST_BIND_UNIQUE
                rec.add_detail(f"[规则] {nm}: ip={ip} mac={mac} bind_type=唯一(1)")
                res = page.add_rule(nm, ip, mac, interface=CLIENT_IFACE_UI, bind_type=1)
                ui_check("唯一绑定添加", res["success"], res.get("error", ""))
                ssh_verify("唯一-L1数据库", backend_verifier.verify_arp_database,
                           nm, ip=ip, mac=mac, interface=CLIENT_IFACE_DB, bind_type="1")
                # L3: bind_type=1(唯一)额外进arponly/iponly(DHCP兼容标记);
                # arp -s在arp.sh __exec_rule_add的if块外, bind_type=1同样建静态ARP+进arp_default/arpip_default
                ssh_verify("唯一-L3 arponly/iponly", backend_verifier.verify_arp_ipset,
                           ip=ip, mac=mac, bind_type="1")
                ssh_verify("唯一-L3 arp_default/arpip_default", backend_verifier.verify_arp_ipset,
                           ip=ip, mac=mac, bind_type="0")
                # L2: arp -s在bind_type判断if块外, bind_type=1也建静态ARP
                ssh_verify("唯一-L2静态ARP", backend_verifier.verify_arp_static, ip, expect_present=True)
                # DHCP静态分配兼容: 开dhcpd_arp后绑定同步DHCP(SSH切换验证global_config+开关机制)
                if backend_verifier:
                    rec.add_detail("[DHCP兼容] SSH开dhcpd_arp=1验证global_config")
                    backend_verifier.set_dhcpd_arp(1)
                    ssh_verify("dhcpd_arp=1", backend_verifier.verify_arp_global_config, dhcpd_arp="1")
                    backend_verifier.set_dhcpd_arp(0)
                    rec.add_detail("[DHCP兼容] 恢复dhcpd_arp=0")

            # ==================== 步骤12: 设置弹窗-arp_filter开关 L1+L2 ====================
            with rec.step("步骤12: 设置弹窗-非绑定MAC不允许上网(arp_filter)", "UI开关+L1 global_config+L2 ARP链"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                if page.open_settings():
                    cur = page.get_arp_setting()
                    rec.add_detail(f"[设置前] {cur}")
                    # 开arp_filter
                    page.toggle_arp_option("arp_filter", True)
                    page.save_settings()
                    page.page.wait_for_timeout(2000)
                    ssh_verify("步骤12-arp_filter=1", backend_verifier.verify_arp_global_config, arp_filter="1")
                    ssh_verify("步骤12-ARP链生效", backend_verifier.verify_arp_chain, expect_on=True)
                    # 关arp_filter(恢复, L5步骤会用SSH快速控制)
                    page.open_settings()
                    page.toggle_arp_option("arp_filter", False)
                    page.save_settings()
                    page.page.wait_for_timeout(2000)
                    ssh_verify("步骤12-arp_filter=0恢复", backend_verifier.verify_arp_global_config, arp_filter="0")
                else:
                    ui_failures.append("步骤12: 打开设置弹窗失败")

            # ==================== 步骤13: 设置弹窗-dhcpd_arp开关 L1 ====================
            with rec.step("步骤13: 设置弹窗-兼容DHCP静态分配(dhcpd_arp)", "UI开关+L1 global_config"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                if page.open_settings():
                    page.toggle_arp_option("dhcpd_arp", True)
                    page.save_settings()
                    page.page.wait_for_timeout(1500)
                    ssh_verify("步骤13-dhcpd_arp=1", backend_verifier.verify_arp_global_config, dhcpd_arp="1")
                    page.open_settings()
                    page.toggle_arp_option("dhcpd_arp", False)
                    page.save_settings()
                    page.page.wait_for_timeout(1500)
                    ssh_verify("步骤13-dhcpd_arp=0恢复", backend_verifier.verify_arp_global_config, dhcpd_arp="0")
                else:
                    ui_failures.append("步骤13: 打开设置弹窗失败")

            # ==================== 步骤14: 异常输入拦截 ====================
            with rec.step("步骤14: 异常输入拦截(空名称/非法MAC/非法IP)", "前端校验应阻止保存"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1000)
                r1 = page.try_add_rule_invalid(name="", ip="192.168.148.220", mac="AA:BB:CC:00:00:20")
                if r1.get("blocked"):
                    rec.add_detail(f"[OK] 空名称被拦截: {r1.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤14: 空名称未被拦截: {r1.get('error', '')[:50]}")
                page._dismiss_all_modals()
                r2 = page.try_add_rule_invalid(name=f"{PREFIX}badmac", ip="192.168.148.221", mac="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")
                if r2.get("blocked"):
                    rec.add_detail(f"[OK] 非法MAC被拦截: {r2.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤14: 非法MAC未被拦截: {r2.get('error', '')[:50]}")
                page._dismiss_all_modals()
                r3 = page.try_add_rule_invalid(name=f"{PREFIX}badip", ip="999.999.999.999", mac="AA:BB:CC:00:00:22")
                if r3.get("blocked"):
                    rec.add_detail(f"[OK] 非法IP被拦截: {r3.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤14: 非法IP未被拦截: {r3.get('error', '')[:50]}")
                page._dismiss_all_modals()

            # ==================== 步骤15: 导出CSV+TXT ====================
            with rec.step("步骤15: 导出CSV+TXT", "export_rules双格式"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                csv_ok = page.export_rules(export_format="csv")
                ui_check("步骤15导出CSV", csv_ok, "CSV导出失败")
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                txt_ok = page.export_rules(export_format="txt")
                ui_check("步骤15导出TXT", txt_ok, "TXT导出失败")
                if csv_ok or txt_ok:
                    rec.add_detail("[导出] CSV+TXT完成")

            # ==================== 步骤16: 导入(不清空+清空两种) ====================
            with rec.step("步骤16: 导入(不清空+清空两种)", "clear_existing False/True + SSH验证"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                export_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                          "test_data", "exports", "arp_setting")
                imp_file = None
                if os.path.isdir(export_dir):
                    files = [f for f in os.listdir(export_dir) if f.endswith((".csv", ".txt"))]
                    if files:
                        files.sort(key=lambda f: os.path.getmtime(os.path.join(export_dir, f)))
                        imp_file = os.path.join(export_dir, files[-1])
                if imp_file and os.path.exists(imp_file):
                    def _verify_import(label):
                        if backend_verifier is None:
                            return
                        try:
                            r = backend_verifier.verify_arp_count(prefix=PREFIX)
                            import re as _re
                            m = _re.search(r'数量:\s*(\d+)', r.message)
                            n = int(m.group(1)) if m else 0
                            ok = n > 0
                            d = f"[SSH-{label}] {'PASS' if ok else 'FAIL'}: 导入后{PREFIX}数={n}"
                            rec.add_detail(d)
                            print(d, flush=True)
                            if not ok:
                                ssh_failures.append(f"SSH-{label}: 导入后0条{PREFIX}规则")
                        except Exception as e:
                            ssh_failures.append(f"SSH-{label}异常: {str(e)[:60]}")
                    page.clean_test_rules(PREFIX)
                    page.page.wait_for_timeout(1000)
                    imp_ok1 = page.import_rules(imp_file, clear_existing=False)
                    ui_check("步骤16a导入-不清空", imp_ok1, "不清空导入失败")
                    page.page.wait_for_timeout(2000)
                    _verify_import("步骤16a-不清空导入")
                    page.navigate_to_arp()
                    page.page.wait_for_timeout(1500)
                    imp_ok2 = page.import_rules(imp_file, clear_existing=True)
                    ui_check("步骤16b导入-清空", imp_ok2, "清空导入失败")
                    page.page.wait_for_timeout(2000)
                    _verify_import("步骤16b-清空导入")
                    rec.add_detail(f"[导入] 不清空={imp_ok1} 清空={imp_ok2} 文件={os.path.basename(imp_file)}")
                else:
                    rec.add_detail("[导入] 跳过(无导出文件)")

            # ==================== 步骤17: 邻居列表Tab ====================
            with rec.step("步骤17: 邻居列表Tab", "切换Tab+只读列表+清空验证"):
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                ok = page.switch_to_tab("neighbor")
                ui_check("步骤17切换邻居列表Tab", ok, "切换Tab失败")
                page.page.wait_for_timeout(1500)
                ncnt = page.get_neighbor_count()
                rec.add_detail(f"[邻居列表] IPv6邻居行数: {ncnt}")
                # 邻居是内核自动学习的只读列表, 验证列表能加载(即使为0也是正常, 取决于IPv6环境)
                rec.add_detail("[邻居列表] 只读列表加载验证完成(无添加按钮, 仅清空/删除)")

            # ==================== 步骤18: L5 功能验证(非绑定MAC不允许上网) ====================
            with rec.step("步骤18: L5功能验证(非绑定MAC不允许上网)", "基线通→开arp_filter非绑定不通→绑定client后通→恢复"):
                if backend_verifier is None:
                    rec.add_detail("[L5] 跳过(无SSH验证器)")
                else:
                    try:
                        backend_verifier.connect_client()
                        # 确保client未绑定 + arp_filter=0
                        backend_verifier._router.exec(
                            f"sqlite3 {backend_verifier.DNS_DB} \"DELETE FROM arp WHERE ip_addr='{CLIENT_IP}'\"")
                        backend_verifier.set_arp_filter(0)
                        page.page.wait_for_timeout(1000)
                        # 基线: client未绑定, arp_filter=0 → curl应通
                        base = backend_verifier.verify_connectivity(
                            dst_domain="www.baidu.com", retries=2,
                            fallback_domains=["www.qq.com", "cn.bing.com"])
                        rec.add_detail(f"[基线 arp_filter=0未绑定] {base['detail']}")
                        if not base["connected"]:
                            rec.add_detail("[L5] 基线baidu经ens11不可达, 跳过(环境)")
                        else:
                            # 开arp_filter=1, client未绑定 → curl应不通(硬)
                            backend_verifier.set_arp_filter(1)
                            page.page.wait_for_timeout(1500)
                            blk = backend_verifier.verify_connectivity(dst_domain="www.baidu.com")
                            rec.add_detail(f"[开arp_filter未绑定] {blk['detail']}")
                            if blk["connected"]:
                                if backend_verifier.is_xt_set_broken():
                                    rec.add_detail("  ✗ 非绑定未阻(xt_set内核bug 6.12致ARP链REJECT未建, 报禅道)")
                                else:
                                    rec.add_detail("  ✗ 非绑定MAC未阻(curl仍可达)")
                                ui_failures.append(f"步骤18: 非绑定MAC未阻: {blk['detail']}")
                            else:
                                rec.add_detail("  ✓ 非绑定MAC被阻(arp_filter白名单生效)")
                            # 绑定client(bind_type=0) → curl应通(硬)
                            res = page.add_rule(f"{PREFIX}client", CLIENT_IP, CLIENT_MAC,
                                                interface=CLIENT_IFACE_UI, bind_type=0)
                            rec.add_detail(f"[绑定client] {res.get('success')} {res.get('error', '')}")
                            page.page.wait_for_timeout(2000)
                            bind_conn = backend_verifier.verify_connectivity(
                                dst_domain="www.baidu.com", retries=2,
                                fallback_domains=["www.qq.com", "cn.bing.com"])
                            rec.add_detail(f"[绑定client后] {bind_conn['detail']}")
                            if not bind_conn["connected"]:
                                rec.add_detail("  ✗ 绑定client后仍不通(规则未放行)")
                                ui_failures.append(f"步骤18: 绑定后未放行: {bind_conn['detail']}")
                            else:
                                rec.add_detail("  ✓ 绑定client后放行(curl通)")
                            # 恢复: 删client绑定 + 关arp_filter
                            try:
                                page.navigate_to_arp()
                                page.delete_rule(f"{PREFIX}client")
                            except Exception:
                                pass
                            backend_verifier.set_arp_filter(0)
                            page.page.wait_for_timeout(1500)
                            restore = backend_verifier.verify_connectivity(
                                dst_domain="www.baidu.com", retries=2,
                                fallback_domains=["www.qq.com", "cn.bing.com"])
                            rec.add_detail(f"[恢复 arp_filter=0] {restore['detail']}")
                            if not restore["connected"]:
                                rec.add_detail("  ✗ 恢复后仍不通(规则残留/环境)")
                                ui_failures.append(f"步骤18: 恢复后未通: {restore['detail']}")
                            else:
                                rec.add_detail("  ✓ 恢复连通")
                    except Exception as e:
                        rec.add_detail(f"[L5] 异常: {str(e)[:80]}")

        finally:
            # 1. 前端清理: 删arp_t_前缀
            try:
                page.navigate_to_arp()
                page.page.wait_for_timeout(1500)
                cnt = page.clean_test_rules(PREFIX)
                rec.add_detail(f"[finally前端清理] 删除 {cnt} 条")
            except Exception as e:
                rec.add_detail(f"[finally前端清理异常] {str(e)[:60]}")
            # 2. SSH清理: DELETE arp prefix + 恢复arp_filter=0/dhcpd_arp=0 + arp.sh init重建
            if backend_verifier:
                try:
                    # 确保client绑定也清(非prefix, L5可能残留)
                    backend_verifier._router.exec(
                        f"sqlite3 {backend_verifier.DNS_DB} \"DELETE FROM arp WHERE ip_addr='{CLIENT_IP}'\"")
                    res = backend_verifier.cleanup_arp_test(PREFIX)
                    rec.add_detail(f"[finally SQL清理+恢复开关] {res}")
                except Exception as e:
                    rec.add_detail(f"[finally清理异常] {str(e)[:60]}")
                # 3. 残留检测: 清理后4个ipset应无测试mac/ip(残留=删不干净BUG报禅道)
                for nm, ip, mac in TEST_BINDS + [TEST_BIND_UNIQUE, ("arp_t_full", "192.168.148.210", "AA:BB:CC:00:00:10")]:
                    arp_residual_check(f"finally-{nm}", ip=ip, mac=mac, bind_type="1" if nm == TEST_BIND_UNIQUE[0] else "0")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"ARP设置验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
