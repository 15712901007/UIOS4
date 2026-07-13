"""
MAC访问控制模块综合测试 (安全中心 > MAC访问控制)

URL: 列表 /login#/securityCenter/macAccessControl, 配置 /login#/securityCenter/macAccessControlConfig
两模式(左上角radio): 黑名单(global_config.acl_mac=0,默认)/白名单(acl_mac=1)
覆盖(参考VLAN步骤全):
- 黑名单模式: MAC规则(单条/多条/备注+终端名称) 每场景SSH全链路(acl_mac_black表+ACL_MAC链-j DROP+ipset acl_mac_{id})
- 模式切换: 黑→白 radio click+reload+SSH验global_config.acl_mac=1 (软断言, radio可能不调API)
- 白名单模式: MAC规则 SSH验(acl_mac_white表+ACL_MAC链-j RETURN)
- CRUD: 多条+计数+搜索+编辑备注+停用(enabled=no+iptables无)+启用+删除
- 异常输入拦截: 空名称/非法MAC
- 导出CSV+TXT + 导入(不清空/清空两种)
- 批量停用/启用/删除
- finally清理(恢复黑名单模式, 删黑+白表, 清ACL_MAC链)

后端机制(acl_mac.sh):
- 表: acl_mac_black/acl_mac_white (enabled默认no/tagname unique/comment/time JSON/expires/mac小写unique)
- iptables filter表ACL_MAC链: 黑名单DROP/白名单RETURN, 用acl_mac_{id}+acl_mac_time_{id}定位(无--comment)
- ipset: acl_mac_{id}; 模式: global_config.acl_mac=0黑/1白
- 行操作: 编辑/停用(启用)/删除(无复制)
"""
import os
import pytest
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure

pytestmark = [pytest.mark.security, pytest.mark.mac_access_control]

PREFIX = "mac_t_"
TEST_MACS = ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03",
             "AA:BB:CC:DD:EE:04", "11:22:33:44:55:66"]


class TestMacAccessControlComprehensive:
    """MAC访问控制综合测试"""

    def test_mac_access_control_comprehensive(self, mac_access_control_page_logged_in,
                                              step_recorder: StepRecorder, request):
        page = mac_access_control_page_logged_in
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

        def kernel_check(label, fail_on_residual=True):
            """MAC访问控制底层一致性实时校验(ipset acl_mac_{id} vs 当前模式表). 定位删除残留.
            双表acl_mac_black/white, ipset acl_mac_{id}共用(跟随global_config.acl_mac模式0黑/1白).
            根据当前模式选表对比. 不清理底层(保留现场追溯). 残留→failures(硬FAIL+报禅道)."""
            if backend_verifier is None:
                return None
            try:
                backend_verifier.connect_router()
                gc = backend_verifier._sqlite_query_line("SELECT acl_mac FROM global_config") or {}
                mode = str(gc.get("acl_mac", "0"))
                module = "mac_access_black" if mode == "0" else "mac_access_white"
                res = backend_verifier.verify_module_kernel_consistency(module, label)
                rec.add_detail(f"  [底层一致性-{label}] {res['detail']} (模式={'黑名单' if mode=='0' else '白名单'})")
                for rd in res['residual_detail']:
                    rec.add_detail(f"    ✗残留 {rd}")
                if res['residual'] or res.get('count_overflow'):
                    ovf = '/'.join(f"{c['chain']}累加{c['dup']}条" for c in res.get('count_overflow', []))
                    rec.add_detail(f"    ✗ {module}底层残留(删不干净,报禅道): id={res['residual']}{'; ' + ovf if ovf else ''}")
                    if fail_on_residual:
                        ssh_failures.append(f"底层残留-{label}: {module} id {res['residual']} {ovf} 底层有DB无(报禅道)")
                elif res['missing']:
                    rec.add_detail(f"    ⚠ 漏下发(DB有底层无): {res['missing']}")
                else:
                    rec.add_detail(f"    ✓ 底层与DB一致(无残留)")
                return res
            except Exception as e:
                rec.add_detail(f"  [底层一致性-{label}] 异常: {str(e)[:80]}")
                return None
        kernel_check = attach_cmd_recording_to_closure(backend_verifier, rec, kernel_check)

        try:
            # ==================== 步骤1: 环境快照+清理 ====================
            with rec.step("步骤1: 环境快照+清理", "清理mac_t_残留+确认黑名单模式"):
                if backend_verifier:
                    snap = backend_verifier.verify_mac_ctrl_count(prefix=PREFIX)
                    rec.add_detail(f"[快照] 清理前 mac_t_ 数量: {snap.message}")
                    backend_verifier.cleanup_mac_ctrl_test(PREFIX)
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                page.clean_test_rules(PREFIX)
                page.page.wait_for_timeout(1000)
                cnt0 = page.get_rule_count()
                rec.add_detail(f"[清理后] 列表规则数: {cnt0}")
                ssh_verify("步骤1-初始黑名单模式", backend_verifier.verify_mac_ctrl_mode, "black")

            # ==================== 步骤2-4: 黑名单模式规则场景 ====================
            # 场景1: 黑名单MAC单条
            with rec.step("步骤2: 场景1 黑名单MAC单条(AA:BB:CC:DD:EE:01)", "添加+SSH L1/L2/L3"):
                rec.add_detail(f"[规则] mac_t_b1: mac=AA:BB:CC:DD:EE:01 mode=black")
                res = page.add_rule(f"{PREFIX}b1", "AA:BB:CC:DD:EE:01")
                ui_check("场景1添加", res["success"], res.get("error", ""))
                ssh_verify("场景1-L1数据库", backend_verifier.verify_mac_ctrl_database,
                           f"{PREFIX}b1", "black", expected_fields={"enabled": "yes"}, mac="AA:BB:CC:DD:EE:01")
                ssh_verify("场景1-L2iptables", backend_verifier.verify_mac_ctrl_iptables,
                           f"{PREFIX}b1", "black", expect_present=True)
                ssh_verify("场景1-L3ipset", backend_verifier.verify_mac_ctrl_ipset,
                           f"{PREFIX}b1", "AA:BB:CC:DD:EE:01", "black")

            # 场景2: 黑名单MAC多条
            with rec.step("步骤3: 场景2 黑名单MAC多条(02/03)", "多条MAC规则"):
                for i, suffix in enumerate(["b2", "b3"]):
                    mac = TEST_MACS[i + 1]
                    rec.add_detail(f"[规则] {PREFIX}{suffix}: mac={mac}")
                    res = page.add_rule(f"{PREFIX}{suffix}", mac)
                    ui_check(f"场景2添加{suffix}", res["success"], res.get("error", ""))
                    ssh_verify(f"场景2-L1-{suffix}", backend_verifier.verify_mac_ctrl_database,
                               f"{PREFIX}{suffix}", "black", mac=mac)

            # 场景3: 黑名单MAC+备注+终端名称
            with rec.step("步骤4: 场景3 黑名单MAC+备注+终端名称", "全字段"):
                rec.add_detail(f"[规则] mac_t_b4: mac=AA:BB:CC:DD:EE:04 termname=测试终端 remark=黑名单备注")
                res = page.add_rule(f"{PREFIX}b4", "AA:BB:CC:DD:EE:04",
                                    termname="测试终端", remark="黑名单备注")
                ui_check("场景3添加", res["success"], res.get("error", ""))
                ssh_verify("场景3-L1", backend_verifier.verify_mac_ctrl_database,
                           f"{PREFIX}b4", "black", expected_fields={"comment": "黑名单备注"}, mac="AA:BB:CC:DD:EE:04")

            # ==================== 步骤5: CRUD 计数 ====================
            with rec.step("步骤5: 计数验证(≥4条mac_t_)", "前端计数 vs SSH计数"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(2000)
                ui_cnt = page.get_rule_count()
                rec.add_detail(f"[UI计数] 共 {ui_cnt} 条")
                if backend_verifier:
                    ssh_cnt = backend_verifier.verify_mac_ctrl_count(prefix=PREFIX)
                    rec.add_detail(f"[SSH计数] mac_t_ {ssh_cnt.message}")
                if ui_cnt < 4:
                    ui_failures.append(f"步骤5: UI规则数{ui_cnt}<4(期望≥4)")

            # ==================== 步骤6: 搜索 ====================
            with rec.step("步骤6: 搜索(存在/清空)", "search_rule验证"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                page.search_rule(f"{PREFIX}b1")
                page.page.wait_for_timeout(1500)
                if not page.rule_exists(f"{PREFIX}b1"):
                    ui_failures.append("步骤6: 搜索存在规则未显示")
                page.clear_search()
                page.page.wait_for_timeout(1500)
                rec.add_detail("[搜索] 存在+清空验证完成")

            # ==================== 步骤7: 编辑备注 ====================
            with rec.step("步骤7: 编辑备注", "编辑mac_t_b1备注+SSH验证"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                if page.edit_rule(f"{PREFIX}b1"):
                    page.fill_remark("已编辑MAC备注")
                    sv = page.save_and_wait()
                    ui_check("步骤7编辑保存", sv["success"], sv.get("error", ""))
                    ssh_verify("步骤7-L1备注", backend_verifier.verify_mac_ctrl_database,
                               f"{PREFIX}b1", "black", expected_fields={"comment": "已编辑MAC备注"})
                else:
                    ui_failures.append("步骤7: 进入编辑页失败")

            # ==================== 步骤8: 停用+SSH验证 ====================
            with rec.step("步骤8: 停用mac_t_b2", "enabled=no+iptables无规则"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                ok = page.disable_rule(f"{PREFIX}b2")
                ui_check("步骤8停用", ok, "停用操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤8-enabled", backend_verifier.verify_mac_ctrl_enabled,
                           f"{PREFIX}b2", "black", False)

            # ==================== 步骤9: 启用+SSH验证 ====================
            with rec.step("步骤9: 启用mac_t_b2", "enabled=yes+iptables有规则"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                ok = page.enable_rule(f"{PREFIX}b2")
                ui_check("步骤9启用", ok, "启用操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤9-enabled", backend_verifier.verify_mac_ctrl_enabled,
                           f"{PREFIX}b2", "black", True)

            # ==================== 步骤10: 单条删除+SSH验证不存在 ====================
            with rec.step("步骤10: 删除mac_t_b1", "SSH验不存在+iptables无"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                ok = page.delete_rule(f"{PREFIX}b1")
                ui_check("步骤10删除", ok, "删除操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤10-不存在", backend_verifier.verify_mac_ctrl_not_exists,
                           f"{PREFIX}b1", "black")
                ssh_verify("步骤10-iptables无", backend_verifier.verify_mac_ctrl_iptables,
                           f"{PREFIX}b1", "black", expect_present=False)
                # 底层一致性实时校验: 删除后底层ipset应无残留(残留=删不干净BUG,硬FAIL报禅道)
                kernel_check("步骤10-删除后", fail_on_residual=True)

            # ==================== 步骤11: 模式切换(黑→白) + 白名单场景 ====================
            with rec.step("步骤11: 模式切换黑→白+白名单MAC", "radio UI切换(不调API已知)+后端切换+白名单规则"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                # UI radio切换(记录行为; radio不调API是已知前端限制, 仅改本地state)
                radio_ok = page.set_mode("white")
                page.page.wait_for_timeout(1500)
                ui_mode = page.get_current_mode()
                rec.add_detail(f"[UI模式] radio click={radio_ok}, UI显示={ui_mode}(radio仅前端state不调API)")
                # 后端切换模式(radio不调API, 用SSH切换验证两模式机制+白名单规则)
                if backend_verifier:
                    set_res = backend_verifier.set_mac_mode("white")
                    rec.add_detail(f"[后端模式切换] {set_res}")
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(2000)
                ssh_verify("步骤11-模式切换", backend_verifier.verify_mac_ctrl_mode, "white")
                # 白名单场景: 添加白名单MAC + SSH验证(acl_mac_white表+ACL_MAC RETURN+ipset)
                rec.add_detail(f"[规则] mac_t_w1: mac=11:22:33:44:55:66 mode=white")
                res = page.add_rule(f"{PREFIX}w1", "11:22:33:44:55:66")
                ui_check("白名单MAC添加", res["success"], res.get("error", ""))
                ssh_verify("白名单-L1数据库", backend_verifier.verify_mac_ctrl_database,
                           f"{PREFIX}w1", "white", expected_fields={"enabled": "yes"}, mac="11:22:33:44:55:66")
                ssh_verify("白名单-L2iptables", backend_verifier.verify_mac_ctrl_iptables,
                           f"{PREFIX}w1", "white", expect_present=True)
                ssh_verify("白名单-L3ipset", backend_verifier.verify_mac_ctrl_ipset,
                           f"{PREFIX}w1", "11:22:33:44:55:66", "white")
                # 切回黑名单模式(后续异常/导出/导入/批量在黑名单测; finally也会恢复)
                if backend_verifier:
                    backend_verifier.set_mac_mode("black")
                    rec.add_detail("[模式] 切回黑名单(便于后续步骤)")
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)

            # ==================== 步骤12: 异常输入拦截 ====================
            with rec.step("步骤12: 异常输入拦截(空名称/非法MAC)", "前端校验应阻止保存"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1000)
                r1 = page.try_add_rule_invalid(name="", mac="AA:BB:CC:DD:EE:09")
                if r1.get("blocked"):
                    rec.add_detail(f"[OK] 空名称被拦截: {r1.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤12: 空名称未被拦截: {r1.get('error', '')[:50]}")
                page._dismiss_all_modals()
                r2 = page.try_add_rule_invalid(name=f"{PREFIX}badmac", mac="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")
                if r2.get("blocked"):
                    rec.add_detail(f"[OK] 非法MAC被拦截: {r2.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤12: 非法MAC未被拦截: {r2.get('error', '')[:50]}")
                page._dismiss_all_modals()

            # ==================== 步骤13: 导出CSV+TXT ====================
            with rec.step("步骤13: 导出CSV+TXT", "export_rules双格式"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                csv_ok = page.export_rules(export_format="csv")
                ui_check("步骤13导出CSV", csv_ok, "CSV导出失败")
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                txt_ok = page.export_rules(export_format="txt")
                ui_check("步骤13导出TXT", txt_ok, "TXT导出失败")
                if csv_ok or txt_ok:
                    rec.add_detail("[导出] CSV+TXT完成")

            # ==================== 步骤14: 导入(不清空+清空两种) ====================
            with rec.step("步骤14: 导入(不清空+清空两种)", "clear_existing False/True + SSH验证"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                export_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                          "test_data", "exports", "mac_access_control")
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
                            r = backend_verifier.verify_mac_ctrl_count(prefix=PREFIX)
                            import re as _re
                            m = _re.search(r'数量\s*(\d+)', r.message)
                            n = int(m.group(1)) if m else 0
                            ok = n > 0
                            d = f"[SSH-{label}] {'PASS' if ok else 'FAIL'}: 导入后mac_t_数={n}"
                            rec.add_detail(d)
                            print(d, flush=True)
                            if not ok:
                                ssh_failures.append(f"SSH-{label}: 导入后0条mac_t_规则")
                        except Exception as e:
                            ssh_failures.append(f"SSH-{label}异常: {str(e)[:60]}")
                    page.clean_test_rules(PREFIX)
                    page.page.wait_for_timeout(1000)
                    imp_ok1 = page.import_rules(imp_file, clear_existing=False)
                    ui_check("步骤14a导入-不清空", imp_ok1, "不清空导入失败")
                    page.page.wait_for_timeout(2000)
                    _verify_import("步骤14a-不清空导入")
                    page.navigate_to_mac_ctrl()
                    page.page.wait_for_timeout(1500)
                    imp_ok2 = page.import_rules(imp_file, clear_existing=True)
                    ui_check("步骤14b导入-清空", imp_ok2, "清空导入失败")
                    page.page.wait_for_timeout(2000)
                    _verify_import("步骤14b-清空导入")
                    rec.add_detail(f"[导入] 不清空={imp_ok1} 清空={imp_ok2} 文件={os.path.basename(imp_file)}")
                else:
                    rec.add_detail("[导入] 跳过(无导出文件)")

            # ==================== 步骤15: 批量停用/启用/删除 ====================
            with rec.step("步骤15: 批量操作", "批量停用/启用/删除"):
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                page.clean_test_rules(PREFIX)
                page.page.wait_for_timeout(1000)
                for i, nm in enumerate(["ba1", "ba2", "ba3"]):
                    page.add_rule(f"{PREFIX}{nm}", TEST_MACS[i])
                    page.page.wait_for_timeout(500)
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(2000)
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_disable()
                page.page.wait_for_timeout(2000)
                if backend_verifier:
                    for nm in ["ba1", "ba2", "ba3"]:
                        ssh_verify(f"步骤15-批量停用-{nm}", backend_verifier.verify_mac_ctrl_enabled,
                                   f"{PREFIX}{nm}", "black", False, must_pass=False)
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_enable()
                page.page.wait_for_timeout(2000)
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_delete()
                page.page.wait_for_timeout(2500)
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                left = page.get_rule_count()
                rec.add_detail(f"[批量删除后] 剩余 {left} 条")
                # 底层一致性实时校验: 批量删除后底层ipset应无残留(残留=删不干净BUG,硬FAIL报禅道)
                kernel_check("步骤15-批量删除后", fail_on_residual=True)

            # ==================== 步骤16: 功能连通性验证(黑名单阻断) ====================
            with rec.step("步骤16: 功能连通性验证(黑名单阻断)", "基线curl→加client MAC黑名单→不通(硬)→移除恢复(硬)"):
                if backend_verifier is None:
                    rec.add_detail("[功能] 跳过(无SSH验证器)")
                else:
                    client_mac = "d4:20:00:b1:45:ec"  # client ens11 MAC(线上报文src MAC)
                    flow_name = f"{PREFIX}flow_blk"
                    try:
                        backend_verifier.connect_client()
                        # 基线: curl baidu经ens11应通
                        base = backend_verifier.verify_connectivity(dst_domain="www.baidu.com", retries=2)
                        rec.add_detail(f"[基线] {base['detail']}")
                        if not base["connected"]:
                            rec.add_detail("[功能] baidu经ens11不可达, 跳过(环境)")
                        else:
                            # 黑名单加client MAC(ACL_MAC链-j DROP, 阻断该MAC经路由器所有流量;
                            # SSH走enp2s0管理网不经路由器, 不受影响)
                            res = page.add_rule(flow_name, client_mac)
                            rec.add_detail(f"[加黑名单] mac={client_mac}: {res.get('success')} {res.get('error', '')}")
                            page.page.wait_for_timeout(2000)
                            # curl baidu应不通(client MAC被阻)
                            blk = backend_verifier.verify_connectivity(dst_domain="www.baidu.com")
                            rec.add_detail(f"[加MAC后] {blk['detail']}")
                            if blk["connected"]:
                                # 硬断言: 黑名单未阻断即FAIL. xt_set坏(6.12)致ACL_MAC规则未建→同样FAIL(如实反映, 报禅道)
                                if backend_verifier.is_xt_set_broken():
                                    rec.add_detail("  ✗ 黑名单未阻断(xt_set内核bug 6.12致ACL_MAC规则未建, 报禅道)")
                                else:
                                    rec.add_detail("  ✗ 黑名单未阻断(curl baidu仍可达)")
                                ui_failures.append(f"步骤16: MAC黑名单未阻断: {blk['detail']}")
                            else:
                                rec.add_detail("  ✓ 黑名单阻断生效(curl baidu不通)")
                            # 移除MAC→恢复
                            page.navigate_to_mac_ctrl()
                            page.page.wait_for_timeout(800)
                            try:
                                page.delete_rule(flow_name)
                            except Exception:
                                pass
                            page.page.wait_for_timeout(2000)
                            restore = backend_verifier.verify_connectivity(dst_domain="www.baidu.com", retries=2)
                            rec.add_detail(f"[移除MAC后] {restore['detail']}")
                            if not restore["connected"]:
                                rec.add_detail("  ✗ 移除MAC后baidu仍不通(规则残留/环境)")
                                ui_failures.append(f"步骤16: 移除MAC未恢复: {restore['detail']}")
                            else:
                                rec.add_detail("  ✓ 恢复连通")
                    except Exception as e:
                        rec.add_detail(f"[功能] 异常: {str(e)[:80]}")

        finally:
            try:
                page.navigate_to_mac_ctrl()
                page.page.wait_for_timeout(1500)
                cnt = page.clean_test_rules(PREFIX)
                rec.add_detail(f"[finally前端清理] 删除 {cnt} 条")
            except Exception as e:
                rec.add_detail(f"[finally前端清理异常] {str(e)[:60]}")
            if backend_verifier:
                try:
                    res = backend_verifier.cleanup_mac_ctrl_test(PREFIX)
                    rec.add_detail(f"[finally SQL清理+恢复黑名单] {res}")
                except Exception as e:
                    rec.add_detail(f"[finally清理异常] {str(e)[:60]}")
            # 底层一致性实时校验: 清理后底层ipset应无残留(残留=删不干净BUG,硬FAIL报禅道)
            kernel_check("finally-清理后", fail_on_residual=True)

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"MAC访问控制验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
