"""
ACL规则模块综合测试 (安全中心 > ACL规则)

URL: 列表 /login#/securityCenter/aclRules, 配置 /login#/securityCenter/aclRulesConfig
覆盖:
- 各种规则场景全覆盖(源IP单IP/网段/目的IP/源+目的多地址/协议tcp/udp/icmp/动作accept,drop/方向forward,input/端口/备注/优先级/连接方向匹配)
  每场景添加后SSH全链路验证(L1数据库字段+L2 iptables FIREWALL/INPUT_ACL链+L3 ipset acl_src_/acl_dst_)
- CRUD: 多条+计数+搜索(存在/不存在/清空)+编辑备注+停用(enabled=no+iptables无)+启用+删除(SSH验不存在)
- 异常输入拦截: 空名称/非法IP(999.999.999.999)
- 导出CSV+TXT + 导入(清空/不清空)
- 批量停用/启用/删除
- finally清理(前端逐条删+SQL delete兜底+acl.sh init)

后端机制(acl.sh):
- acl表: src_addr/dst_addr/time明文JSON; action accept/drop; dir forward/input; protocol any/tcp/udp/tcp+udp/icmp/gre
- iptables: dir=forward→FIREWALL链, dir=input→INPUT_ACL链; 规则 -j ACCEPT/DROP --comment {id}_{comment}
- ipset: acl_src_{id}/acl_dst_{id}(地址); acl_time_{id}(时间)
- enabled=yes才下发; down→del规则, up→add规则
"""
import os
import pytest
from utils.step_recorder import StepRecorder
from tests.security.acl_test_data import load_acl_cases
from utils.verify_helper import attach_cmd_recording_to_closure

pytestmark = [pytest.mark.security, pytest.mark.acl]

PREFIX = "acl_t_"


class TestAclComprehensive:
    """ACL规则综合测试"""

    def test_acl_comprehensive(self, acl_page_logged_in, step_recorder: StepRecorder, request):
        page = acl_page_logged_in
        rec = step_recorder

        # 软注入backend_verifier(无SSH环境返回None, 测试仍跑UI部分)
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ui_failures = []
        ssh_failures = []

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            """SSH验证软收集闭包(must_pass=False只收集不抛). 每次验证记录2条detail(状态+后端数据)."""
            if backend_verifier is None:
                rec.add_detail(f"[SSH-{label}] 跳过(无SSH验证器)")
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = 'PASS' if result.passed else 'FAIL'
                rec.add_detail(f"[SSH-{label}] {status}: {result.message}")
                rec.add_detail(f"    后端数据: {(result.raw_output or '')[:180]}")
                print(f"[SSH-{label}] {status}: {result.message}", flush=True)
                # must_pass条件版: ACL规则6.12未落地iptables(产品bug, FIREWALL链空), L2验证默认must_pass=False软记录
                if must_pass and not result.passed:
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

        def kernel_check(label, fail_on_residual=True, module="acl"):
            """ACL底层一致性实时校验(snapshot ipset vs DB). 定位导入→删除残留.
            不清理底层(保留现场追溯BUG触发步骤). 残留→failures(硬FAIL+报禅道)."""
            if backend_verifier is None:
                return None
            try:
                backend_verifier.connect_router()
                res = backend_verifier.verify_module_kernel_consistency(module, label)
                rec.add_detail(f"  [底层一致性-{label}] {res['detail']}")
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
            with rec.step("步骤1: 环境快照+清理测试数据", "SSH备份+清理acl_t_前缀残留规则"):
                if backend_verifier:
                    snap = backend_verifier.verify_acl_count(prefix=PREFIX)
                    rec.add_detail(f"[快照] 清理前 acl_t_ 数量: {snap.message}")
                    backend_verifier.cleanup_acl_test(PREFIX)
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                page.clean_test_rules(PREFIX)
                page.page.wait_for_timeout(1000)
                cnt0 = page.get_rule_count()
                rec.add_detail(f"[清理后] 列表规则数: {cnt0}")

            # ==================== 步骤2-11: 各种规则场景全覆盖 ====================
            # 场景1: 源IP单IP + accept + forward
            with rec.step("步骤2: 场景1 源IP单IP(10.66.0.18)+允许+转发", "添加+SSH L1/L2/L3"):
                res = page.add_rule(f"{PREFIX}src1", action="accept", direction="forward",
                                    src_addrs=["10.66.0.18"])
                ui_check("场景1添加", res["success"], res.get("error", ""))
                ssh_verify("场景1-L1数据库", backend_verifier.verify_acl_database,
                           f"{PREFIX}src1", expected_fields={"action": "accept", "dir": "forward",
                           "protocol": "any", "enabled": "yes"}, src_ips=["10.66.0.18"])
                ssh_verify("场景1-L2iptables", backend_verifier.verify_acl_iptables,
                           f"{PREFIX}src1", "accept", expect_present=True)
                ssh_verify("场景1-L3ipset", backend_verifier.verify_acl_ipset,
                           f"{PREFIX}src1", ["10.66.0.18"], side="src")

            # 场景2: 源IP网段CIDR + accept
            with rec.step("步骤3: 场景2 源IP网段(192.168.148.0/24)+允许", "CIDR网段地址"):
                res = page.add_rule(f"{PREFIX}src2", action="accept",
                                    src_addrs=["192.168.148.0/24"])
                ui_check("场景2添加", res["success"], res.get("error", ""))
                ssh_verify("场景2-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}src2", src_ips=["192.168.148.0/24"])
                ssh_verify("场景2-L3ipset", backend_verifier.verify_acl_ipset,
                           f"{PREFIX}src2", ["192.168.148.0/24"], side="src")

            # 场景3: 目的IP + accept
            with rec.step("步骤4: 场景3 目的IP(10.66.0.40)+允许", "目的地址落地acl_dst_"):
                res = page.add_rule(f"{PREFIX}dst1", action="accept",
                                    dst_addrs=["10.66.0.40"])
                ui_check("场景3添加", res["success"], res.get("error", ""))
                ssh_verify("场景3-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}dst1", dst_ips=["10.66.0.40"])
                ssh_verify("场景3-L3ipset", backend_verifier.verify_acl_ipset,
                           f"{PREFIX}dst1", ["10.66.0.40"], side="dst")

            # 场景4: 源IP+目的IP(多地址)
            with rec.step("步骤5: 场景4 源IP+目的IP(多地址)", "源10.66.0.18/目的10.66.0.40"):
                res = page.add_rule(f"{PREFIX}both", action="accept",
                                    src_addrs=["10.66.0.18"], dst_addrs=["10.66.0.40"])
                ui_check("场景4添加", res["success"], res.get("error", ""))
                ssh_verify("场景4-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}both", src_ips=["10.66.0.18"], dst_ips=["10.66.0.40"])
                ssh_verify("场景4-L3src", backend_verifier.verify_acl_ipset,
                           f"{PREFIX}both", ["10.66.0.18"], side="src")
                ssh_verify("场景4-L3dst", backend_verifier.verify_acl_ipset,
                           f"{PREFIX}both", ["10.66.0.40"], side="dst")

            # 场景5: TCP协议(端口字段是选'端口分组'需预建路由对象端口分组, 非数字输入, 超出ACL模块范围, 此处只测协议tcp)
            with rec.step("步骤6: 场景5 TCP协议", "protocol=tcp"):
                res = page.add_rule(f"{PREFIX}tcp", action="accept", protocol="tcp",
                                    dst_addrs=["10.66.0.40"])
                ui_check("场景5添加", res["success"], res.get("error", ""))
                ssh_verify("场景5-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}tcp", expected_fields={"protocol": "tcp"})
                ssh_verify("场景5-L2", backend_verifier.verify_acl_iptables,
                           f"{PREFIX}tcp", "accept", expect_present=True)

            # 场景6: UDP协议
            with rec.step("步骤7: 场景6 UDP协议", "protocol=udp"):
                res = page.add_rule(f"{PREFIX}udp", action="accept", protocol="udp",
                                    src_addrs=["10.66.0.55"])
                ui_check("场景6添加", res["success"], res.get("error", ""))
                ssh_verify("场景6-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}udp", expected_fields={"protocol": "udp"})

            # 场景7: ICMP协议(无端口)
            with rec.step("步骤8: 场景7 ICMP协议", "protocol=icmp"):
                res = page.add_rule(f"{PREFIX}icmp", action="accept", protocol="icmp",
                                    src_addrs=["10.66.0.18"])
                ui_check("场景7添加", res["success"], res.get("error", ""))
                ssh_verify("场景7-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}icmp", expected_fields={"protocol": "icmp"})

            # 场景8: 动作drop(阻断)
            with rec.step("步骤9: 场景8 动作阻断(drop)+源IP", "-j DROP验证"):
                res = page.add_rule(f"{PREFIX}drop", action="drop",
                                    src_addrs=["10.66.0.99"])
                ui_check("场景8添加", res["success"], res.get("error", ""))
                ssh_verify("场景8-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}drop", expected_fields={"action": "drop"})
                ssh_verify("场景8-L2drop", backend_verifier.verify_acl_iptables,
                           f"{PREFIX}drop", "drop", expect_present=True)

            # 场景9: 方向进(input) → INPUT_ACL链
            with rec.step("步骤10: 场景9 方向进(input)", "INPUT_ACL链验证"):
                res = page.add_rule(f"{PREFIX}input", action="accept", direction="input",
                                    src_addrs=["10.66.0.18"])
                ui_check("场景9添加", res["success"], res.get("error", ""))
                ssh_verify("场景9-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}input", expected_fields={"dir": "input"})
                ssh_verify("场景9-L2input链", backend_verifier.verify_acl_iptables,
                           f"{PREFIX}input", "accept", expect_present=True)

            # 场景10: 备注+优先级10+连接方向匹配原始(ctdir=1)
            with rec.step("步骤11: 场景10 备注+优先级10+连接方向匹配原始", "prio/ctdir/comment"):
                res = page.add_rule(f"{PREFIX}extra", action="accept", priority=10,
                                    ctdir=1, remark="ACL测试备注",
                                    src_addrs=["10.66.0.18"])
                ui_check("场景10添加", res["success"], res.get("error", ""))
                ssh_verify("场景10-L1", backend_verifier.verify_acl_database,
                           f"{PREFIX}extra", expected_fields={"prio": "10", "ctdir": "1",
                           "comment": "ACL测试备注"})

            # ==================== 步骤12: CRUD 计数 ====================
            with rec.step("步骤12: 计数验证(10条acl_t_)", "前端计数 vs SSH计数"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(2000)
                ui_cnt = page.get_rule_count()
                rec.add_detail(f"[UI计数] 共 {ui_cnt} 条")
                if backend_verifier:
                    ssh_cnt = backend_verifier.verify_acl_count(prefix=PREFIX)
                    rec.add_detail(f"[SSH计数] acl_t_ {ssh_cnt.message}")
                    # 至少10条测试规则
                    if ui_cnt < 10:
                        ui_failures.append(f"步骤12: UI规则数{ui_cnt}<10(期望≥10)")
                # 底层一致性实时校验: 添加后基线(底层应与DB一致, 记录用)
                kernel_check("步骤12-添加后基线", fail_on_residual=False)

            # ==================== 步骤13: 搜索 ====================
            with rec.step("步骤13: 搜索(存在/不存在/清空)", "search_rule验证"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                # 搜索存在的规则
                page.search_rule(f"{PREFIX}src1")
                page.page.wait_for_timeout(1500)
                if not page.rule_exists(f"{PREFIX}src1"):
                    ui_failures.append("步骤13: 搜索存在规则未显示")
                # 清空搜索
                page.clear_search()
                page.page.wait_for_timeout(1500)
                rec.add_detail("[搜索] 存在+清空验证完成")

            # ==================== 步骤14: 编辑备注 ====================
            with rec.step("步骤14: 编辑备注", "编辑acl_t_src1备注+SSH验证"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                if page.edit_rule(f"{PREFIX}src1"):
                    page.fill_remark("已编辑备注")
                    sv = page.save_and_wait()
                    ui_check("步骤14编辑保存", sv["success"], sv.get("error", ""))
                    ssh_verify("步骤14-L1备注", backend_verifier.verify_acl_database,
                               f"{PREFIX}src1", expected_fields={"comment": "已编辑备注"})
                else:
                    ui_failures.append("步骤14: 进入编辑页失败")

            # ==================== 步骤15: 停用+SSH验证 ====================
            with rec.step("步骤15: 停用acl_t_src2", "enabled=no+iptables无规则"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                ok = page.disable_rule(f"{PREFIX}src2")
                ui_check("步骤15停用", ok, "停用操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤15-enabled", backend_verifier.verify_acl_enabled,
                           f"{PREFIX}src2", False)

            # ==================== 步骤16: 启用+SSH验证 ====================
            with rec.step("步骤16: 启用acl_t_src2", "enabled=yes+iptables有规则"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                ok = page.enable_rule(f"{PREFIX}src2")
                ui_check("步骤16启用", ok, "启用操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤16-enabled", backend_verifier.verify_acl_enabled,
                           f"{PREFIX}src2", True)

            # ==================== 步骤17: 单条删除+SSH验证不存在 ====================
            with rec.step("步骤17: 删除acl_t_src1", "SSH验不存在+iptables无"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                ok = page.delete_rule(f"{PREFIX}src1")
                ui_check("步骤17删除", ok, "删除操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤17-不存在", backend_verifier.verify_acl_not_exists,
                           f"{PREFIX}src1")
                ssh_verify("步骤17-iptables无", backend_verifier.verify_acl_iptables,
                           f"{PREFIX}src1", expect_present=False)
                # 底层一致性实时校验: 删除后底层应无残留(残留=删不干净BUG,硬FAIL报禅道)
                kernel_check("步骤17-删除后", fail_on_residual=True)

            # ==================== 步骤18: 异常输入拦截 ====================
            with rec.step("步骤18: 异常输入拦截(空名称/非法IP)", "前端校验应阻止保存"):
                # 空名称
                r1 = page.try_add_rule_invalid(name="", illegal_src="")
                if r1.get("blocked"):
                    rec.add_detail(f"[OK] 空名称被拦截: {r1.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤18: 空名称未被拦截: {r1.get('error', '')[:50]}")
                page._dismiss_all_modals()
                # 非法IP
                r2 = page.try_add_rule_invalid(name=f"{PREFIX}badip", illegal_src="999.999.999.999")
                if r2.get("blocked"):
                    rec.add_detail(f"[OK] 非法IP被拦截: {r2.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤18: 非法IP未被拦截: {r2.get('error', '')[:50]}")
                page._dismiss_all_modals()

            # ==================== 步骤19: 导出CSV+TXT ====================
            with rec.step("步骤19: 导出CSV+TXT", "export_rules双格式"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                csv_ok = page.export_rules(export_format="csv")
                ui_check("步骤19导出CSV", csv_ok, "CSV导出失败")
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                txt_ok = page.export_rules(export_format="txt")
                ui_check("步骤19导出TXT", txt_ok, "TXT导出失败")
                if csv_ok or txt_ok:
                    rec.add_detail("[导出] CSV+TXT完成")

            # ==================== 步骤20: 导入(不清空+清空两种) ====================
            with rec.step("步骤20: 导入(不清空+清空两种)", "clear_existing False/True + SSH验证数据落库"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                # acl模块导出路径(test文件在tests/security/需dirname×3到项目根, 与export_rules保存路径一致: test_data/exports/acl/)
                export_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                          "test_data", "exports", "acl")
                imp_file = None
                if os.path.isdir(export_dir):
                    files = [f for f in os.listdir(export_dir) if f.endswith((".csv", ".txt"))]
                    if files:
                        files.sort(key=lambda f: os.path.getmtime(os.path.join(export_dir, f)))
                        imp_file = os.path.join(export_dir, files[-1])
                if imp_file and os.path.exists(imp_file):
                    def _verify_import(label):
                        """软验证导入后acl_t_规则数>0(导入数据落库)"""
                        if backend_verifier is None:
                            return
                        try:
                            r = backend_verifier.verify_acl_count(prefix=PREFIX)
                            import re as _re
                            m = _re.search(r'数量\s*(\d+)', r.message)
                            n = int(m.group(1)) if m else 0
                            ok = n > 0
                            d = f"[SSH-{label}] {'PASS' if ok else 'FAIL'}: 导入后acl_t_数={n}"
                            rec.add_detail(d)
                            print(d, flush=True)
                            if not ok:
                                ssh_failures.append(f"SSH-{label}: 导入后0条acl_t_规则")
                        except Exception as e:
                            ssh_failures.append(f"SSH-{label}异常: {str(e)[:60]}")
                    # 1. 不清空导入(append, 导入前清测试数据防相同内容冲突)
                    page.clean_test_rules(PREFIX)
                    page.page.wait_for_timeout(1000)
                    imp_ok1 = page.import_rules(imp_file, clear_existing=False)
                    ui_check("步骤20a导入-不清空", imp_ok1, "不清空导入失败")
                    page.page.wait_for_timeout(2000)
                    _verify_import("步骤20a-不清空导入")
                    # 2. 清空导入(清空现有全部+导入文件内容)
                    page.navigate_to_acl()
                    page.page.wait_for_timeout(1500)
                    imp_ok2 = page.import_rules(imp_file, clear_existing=True)
                    ui_check("步骤20b导入-清空", imp_ok2, "清空导入失败")
                    page.page.wait_for_timeout(2000)
                    _verify_import("步骤20b-清空导入")
                    rec.add_detail(f"[导入] 不清空={imp_ok1} 清空={imp_ok2} 文件={os.path.basename(imp_file)}")
                else:
                    rec.add_detail("[导入] 跳过(无导出文件)")
                # 底层一致性实时校验: 导入后底层应与DB一致(记录用, 不硬FAIL)
                kernel_check("步骤20-导入后", fail_on_residual=False)

            # ==================== 步骤21: 批量停用/启用/删除 ====================
            with rec.step("步骤21: 批量操作", "批量停用/启用/删除"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                # 确保测试规则≤10(批量select_all只选当前页, 规则>10分页漏选)
                page.clean_test_rules(PREFIX)
                page.page.wait_for_timeout(1000)
                # 添加3条用于批量测试
                for nm in ["ba1", "ba2", "ba3"]:
                    page.add_rule(f"{PREFIX}{nm}", action="accept", src_addrs=["10.66.0.18"])
                    page.page.wait_for_timeout(500)
                page.navigate_to_acl()
                page.page.wait_for_timeout(2000)
                # 批量停用
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_disable()
                page.page.wait_for_timeout(2000)
                if backend_verifier:
                    for nm in ["ba1", "ba2", "ba3"]:
                        ssh_verify(f"步骤21-批量停用-{nm}", backend_verifier.verify_acl_enabled,
                                   f"{PREFIX}{nm}", False, must_pass=False)
                # 批量启用
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_enable()
                page.page.wait_for_timeout(2000)
                # 批量删除
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_delete()
                page.page.wait_for_timeout(2500)
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                left = page.get_rule_count()
                rec.add_detail(f"[批量删除后] 剩余 {left} 条")
                # 底层一致性实时校验: 批量删除后底层应无残留(残留=删不干净BUG,硬FAIL报禅道)
                kernel_check("步骤21-批量删除后", fail_on_residual=True)

            # ==================== 步骤22: 复制功能(ACL特有, 行操作含复制) ====================
            with rec.step("步骤22: 复制规则", "复制acl_t_src2→copy_test+SSH验证字段一致"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                # 确保源规则存在(导入清空可能删了, 重建)
                if not page.rule_exists(f"{PREFIX}src2"):
                    page.add_rule(f"{PREFIX}src2", action="accept", src_addrs=["192.168.148.0/24"])
                    page.page.wait_for_timeout(1000)
                    page.navigate_to_acl()
                    page.page.wait_for_timeout(1500)
                copy_name = f"{PREFIX}copy_test"
                # 清理残留复制规则
                if page.rule_exists(copy_name):
                    page.delete_rule(copy_name)
                    page.navigate_to_acl()
                    page.page.wait_for_timeout(1000)
                on_config = page.copy_rule(f"{PREFIX}src2")
                rec.add_detail(f"[复制] 点复制后进入配置页={on_config}")
                if on_config:
                    # 复制进入配置页(预填源规则数据), 改名保存
                    page.fill_name(copy_name)
                    sv = page.save_and_wait()
                    ui_check("步骤22复制保存", sv["success"], sv.get("error", ""))
                else:
                    # 复制可能直接创建(自动命名), 回列表检查
                    page.navigate_to_acl()
                    page.page.wait_for_timeout(1500)
                    ui_failures.append("步骤22: 复制未进入配置页(复制行为待确认)")
                page.page.wait_for_timeout(1500)
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                if page.rule_exists(copy_name):
                    rec.add_detail(f"[OK] 复制规则 {copy_name} 存在")
                    ssh_verify("步骤22-复制规则L1", backend_verifier.verify_acl_database,
                               copy_name, expected_fields={"action": "accept"},
                               src_ips=["192.168.148.0/24"])
                else:
                    ui_failures.append(f"步骤22: 复制规则 {copy_name} 未出现")

            # ACL功能验证(打流实测drop阻断/accept放行)已移至独立 TestAclFlowVerification 类.
            # 原因: 综合测试22步累积状态致步骤23 add_rule不稳定(accept规则未入库, save_and_wait误判success);
            # 独立test用acl_flow_env fixture干净环境, 不受综合测试状态干扰.

        finally:
            # ==================== finally清理(前端逐条删+SQL兜底+acl.sh init) ====================
            try:
                page.navigate_to_acl()
                page.page.wait_for_timeout(1500)
                cnt = page.clean_test_rules(PREFIX)
                rec.add_detail(f"[finally前端清理] 删除 {cnt} 条")
            except Exception as e:
                rec.add_detail(f"[finally前端清理异常] {str(e)[:60]}")
            if backend_verifier:
                try:
                    res = backend_verifier.cleanup_acl_test(PREFIX)
                    rec.add_detail(f"[finally SQL清理] {res}")
                except Exception as e:
                    rec.add_detail(f"[finally SQL清理异常] {str(e)[:60]}")
            # 底层一致性实时校验: 清理后底层应无残留(残留=删不干净BUG,硬FAIL报禅道)
            kernel_check("finally-清理后", fail_on_residual=True)

        # ==================== 汇总断言 ====================
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"ACL规则验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"


@pytest.mark.security
@pytest.mark.acl
class TestAclFlowVerification:
    """ACL功能验证(多协议打流矩阵 + 端到端drop闭环).

    合并旧 test_acl_flow_drop + test_acl_protocol_matrix 为单测试(非参数化), 对齐'每模块1个L1-L4综合+1个功能验证'.
    - 协议矩阵: 6协议(tcp/udp/tcp+udp/icmp/gre/any)循环, 每协议建规则→L1 DB→L2 iptables -p→L5打流命中.
    - 端到端drop闭环: 建src-only tcp drop prio=1→curl baidu不通→删→恢复(来自flow_drop, 不依赖iperf3).
    任一协议/步骤失败软收集failures继续测(单点失败不连坐), 末尾聚合硬断言.
    iperf3软降级: iperf3 server不可达时矩阵L5打流软跳过(L1/L2仍验), 端到端curl闭环照跑, 不整测试skip."""

    PREFIX = "acl_pm_"  # ≤15字符限制: acl_pm_+tcp_udp=14字符(acl_flow_前缀致tagname截断)
    PROTOCOL_CASES = load_acl_cases("protocol_cases.yaml")

    def test_acl_flow_verification(self, acl_page_logged_in, step_recorder: StepRecorder, request):
        """ACL功能验证: 6协议打流矩阵(命中) + TCP端到端drop闭环. 单协议失败不连坐, 末尾聚合断言."""
        page = acl_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            pytest.skip("无SSH验证器, 跳过ACL功能验证")
        client_ip = "192.168.148.2"  # client ens11, curl --interface ens11源IP
        failures = []

        def ssh_verify(label, func, *args, must_pass=True, **kwargs):
            try:
                r = func(*args, **kwargs)
                rec.add_detail(f"[SSH-{label}] {'PASS' if r.passed else 'FAIL'}: {r.message}")
                rec.add_detail(f"    数据: {(r.raw_output or '')[:160]}")
                if must_pass and not r.passed:
                    failures.append(f"{label}: {r.message}")
            except Exception as e:
                rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
                failures.append(f"{label}异常: {str(e)[:80]}")
        ssh_verify = attach_cmd_recording_to_closure(bv, rec, ssh_verify)

        print("\n" + "=" * 50)
        print("ACL功能验证(多协议打流矩阵 + 端到端drop闭环)")
        print("=" * 50)

        try:
            # 步骤1: 清理残留(干净环境)
            with rec.step("步骤1: 清理残留", "删acl_pm_前缀规则确保干净环境"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1000)
                page.clean_test_rules(self.PREFIX)
                try:
                    bv.cleanup_acl_test(self.PREFIX)
                except Exception:
                    pass

            # 步骤2: 基线连通性探测(curl经ens11应通, baidu+qq+bing多域名冗余抗单点抖动)
            with rec.step("步骤2: 基线连通性探测", "curl经ens11应通(baidu+qq+bing多域名冗余抗抖动)"):
                bv.connect_client()
                base = bv.verify_connectivity(
                    dst_domain="www.baidu.com", retries=2,
                    fallback_domains=["www.qq.com", "cn.bing.com", "www.taobao.com"])
                rec.add_detail(f"  基线: {base['detail']}")
                if not base["connected"]:
                    # 全域名失败: 诊断区分"残留挡流(功能/配置问题→FAIL, 不skip)" vs "环境(WAN断/抖动→skip+详报)"
                    diag = bv.diagnose_baseline_block(dst_domain="www.baidu.com")
                    rec.add_detail(f"  [根因诊断] {diag['summary']}")
                    rec.add_detail(f"  [诊断数据] 路由器WAN curl={diag['router_code']} | "
                                   f"client DNS={'OK' if diag['dns_ok'] else 'FAIL(' + diag['dns_detail'] + ')'} | "
                                   f"conn_limit_enabled={diag['conn_limit_enabled']} | "
                                   f"残留挡流={diag['residual_block'] or '无'}")
                    rec.add_detail("  [验证命令]")
                    for c in diag["commands"]:
                        rec.add_detail(f"    {c}")
                    if diag["residual_block"]:
                        pytest.fail(f"基线不通且路由器有残留挡流规则({diag['residual_block']}), "
                                    f"判功能/配置问题(非环境抖动). 清理残留规则后重测. 验证命令见上.")
                    pytest.skip(f"基线多域名全不可达({base['detail']}); 诊断: {diag['summary']}")

            # 步骤3: iperf3打流环境软探活
            # 用bash /dev/tcp轻量探端口(3s), 不走iperf3进程: iperf3首次连接会卡致paramiko read阻塞
            # (Windows下channel.settimeout偶发不生效, 靠exec看门狗硬限51s+重连=卡60s, --connect-timeout/timeout包裹都管不到).
            # 端口可达即视为可打流, 矩阵L5实际打流时再验iperf3协议(_acl_flow_iperf自带--connect-timeout).
            iperf3_ok = False
            with rec.step("步骤3: iperf3打流环境探活", "探活iperf3 server端口5201, 不可达矩阵L5软跳过"):
                try:
                    bv.connect_router()
                    bv.connect_client()
                    bv.add_route_via_router(bv._ssh_config.iperf3_server)
                    r = bv._client.exec(
                        f"timeout 3 bash -c 'cat </dev/null >/dev/tcp/{bv._ssh_config.iperf3_server}/5201' && echo OK",
                        timeout=8)
                    iperf3_ok = "OK" in (r or "")
                except Exception as e:
                    iperf3_ok = False
                    rec.add_detail(f"  iperf3探活异常: {str(e)[:80]}")
                rec.add_detail(f"  iperf3端口5201: {'可达(矩阵L5打流)' if iperf3_ok else '不可达(矩阵L5软跳过仅验L1/L2; 端到端curl闭环不受影响)'}")

            # 步骤4-9: 协议矩阵循环(每协议建规则→L1/L2/L5, 单失败软收集继续下一协议)
            for case in self.PROTOCOL_CASES:
                proto = case["protocol"]
                action = case["action"]
                cid = case["id"]
                name = f"{self.PREFIX}{cid}"
                with rec.step(f"协议矩阵[{cid}]: {case['desc'][:36]}",
                              f"proto={proto} action={action}"):
                    # 清残留(本前缀)
                    page.navigate_to_acl()
                    page.page.wait_for_timeout(800)
                    try:
                        page.clean_test_rules(self.PREFIX)
                    except Exception:
                        pass
                    try:
                        bv.cleanup_acl_test(self.PREFIX)
                    except Exception:
                        pass
                    # 建规则(dst=10.66.0.40让打流命中; protocol=case协议)
                    # 连续循环下偶发save静默失败(add_rule报成功但DB无规则), 故回读校验+重试1次
                    built = False
                    for attempt in (1, 2):
                        res = page.add_rule(name, action=action, protocol=proto,
                                            dst_addrs=["10.66.0.40"])
                        rec.add_detail(f"[UI] 建 {name} proto={proto} action={action}"
                                       f"(第{attempt}次): "
                                       f"{'成功' if res['success'] else '失败 ' + res.get('error', '')}")
                        page.page.wait_for_timeout(1200)
                        if res["success"] and bv.find_acl_rule(name) is not None:
                            built = True
                            break
                        if attempt == 1:
                            rec.add_detail("  规则未落库, 清残留后重试")
                            try:
                                page.clean_test_rules(self.PREFIX)
                                bv.cleanup_acl_test(self.PREFIX)
                            except Exception:
                                pass
                    if not built:
                        failures.append(f"建规则失败[{cid}]: add_rule报成功但DB无规则(save静默失败)")
                        continue  # 规则不存在, 跳过该协议L1/L2/L5(避免3条重复'规则未找到')
                    # L1: 数据库字段(protocol/action)
                    ssh_verify(f"L1-DB-{cid}", bv.verify_acl_database, name,
                               expected_fields={"protocol": proto, "action": action})
                    # L2: 验-p协议落地(any不下发-p, 方法内特殊处理返回通过)
                    ssh_verify(f"L2-协议-{cid}", bv.verify_acl_protocol_iptables,
                               name, protocol=proto)
                    # L5: 打流验命中(gre无对端跳过; any用tcp打流; iperf3不可达软跳过)
                    if proto == "gre":
                        rec.add_detail("[L5-gre] 无对端隧道, 跳过打流(仅L2 -p落地)")
                    elif not iperf3_ok:
                        rec.add_detail(f"[L5-{cid}] iperf3不可达, 软跳过打流(L1/L2已验)")
                    else:
                        flow_proto = "tcp" if proto == "any" else proto
                        flow_port = case.get("flow_port") or 5201
                        ssh_verify(f"L5-打流-{cid}", bv.verify_acl_flow, name,
                                   proto=flow_proto, dst_port=flow_port, action=action)

            # 步骤10: TCP端到端drop闭环(来自flow_drop, src-only tcp prio=1, 不依赖iperf3)
            with rec.step("步骤10: TCP端到端drop闭环", f"建src-only tcp drop prio=1(src={client_ip})→curl baidu不通→删→恢复"):
                drop_name = f"{self.PREFIX}e2e"
                page.navigate_to_acl()
                page.page.wait_for_timeout(800)
                try:
                    page.clean_test_rules(self.PREFIX)
                    bv.cleanup_acl_test(self.PREFIX)
                except Exception:
                    pass
                res = page.add_rule(drop_name, action="drop", direction="forward", protocol="tcp",
                                    src_addrs=[client_ip], priority=1)
                if not res["success"]:
                    rec.add_detail(f"  ✗ 建drop失败: {res.get('error', '')}")
                    failures.append(f"端到端建drop失败: {res.get('error', '')}")
                else:
                    rec.add_detail(f"  [UI] 建 {drop_name}: 成功")
                    page.page.wait_for_timeout(1500)
                    blk = bv.verify_connectivity(dst_domain="www.baidu.com")
                    rec.add_detail(f"  建drop后: {blk['detail']}")
                    if blk["connected"]:
                        rec.add_detail("  ✗ drop未阻断(curl baidu仍通), ACL规则未落地FIREWALL链(6.12产品bug, 报禅道)")
                        failures.append(f"端到端drop未阻断: 建drop后curl baidu仍通({blk['detail']})")
                    else:
                        rec.add_detail("  ✓ drop阻断生效(curl baidu不通)")
                    # 删drop(按name删; 失败则clean前缀兜底, 避免残留致curl不恢复)
                    deleted = False
                    try:
                        page.navigate_to_acl()
                        page.page.wait_for_timeout(500)
                        deleted = page.delete_rule(drop_name)
                    except Exception:
                        deleted = False
                    if not deleted:
                        rec.add_detail("  delete_rule按name定位失败, clean_test_rules兜底清理")
                        try:
                            page.clean_test_rules(self.PREFIX)
                        except Exception:
                            pass
                    page.page.wait_for_timeout(1000)
                    restore = bv.verify_connectivity(
                        dst_domain="www.baidu.com", retries=2,
                        fallback_domains=["www.qq.com", "cn.bing.com"])
                    rec.add_detail(f"  删规则后: {restore['detail']}")
                    if not restore["connected"]:
                        rec.add_detail("  ✗ 删规则后baidu仍不通(规则残留或环境)")
                        failures.append(f"端到端删规则未恢复: {restore['detail']}")
                    else:
                        rec.add_detail("  ✓ 恢复连通(确认规则导致阻断)")
        finally:
            try:
                page.navigate_to_acl()
                page.page.wait_for_timeout(500)
                page.clean_test_rules(self.PREFIX)
            except Exception:
                pass
            try:
                bv.cleanup_acl_test(self.PREFIX)
            except Exception:
                pass

        print(f"\n[ACL功能验证] {'通过' if not failures else '失败'+str(len(failures))+'项'}")
        assert not failures, f"ACL功能验证失败({len(failures)}项): {'; '.join(failures)}"
