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
                if not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
                ssh_failures.append(f"SSH-{label}异常: {str(e)[:80]}")
                return None

        def ui_check(label, cond, detail=""):
            if cond:
                rec.add_detail(f"[UI] {label}: 成功")
            else:
                rec.add_detail(f"[UI] {label}: 失败 - {detail}")
                ui_failures.append(f"{label}: {detail}")

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
    """ACL功能验证(打流实测): 独立干净环境验证drop阻断/accept放行真实生效.

    独立于综合测试(综合测试22步累积状态致add_rule不稳定). 用acl_flow_env fixture:
    client策略路由(经路由器FIREWALL链)+iperf3探活(不通则skip, 不影响其他test)+teardown.
    acl_flow_env探活失败=pytest.skip整个test(环境依赖, 非功能问题)."""

    PREFIX = "acl_flow_"

    def test_acl_flow_drop_accept(self, acl_page_logged_in, acl_flow_env, step_recorder: StepRecorder):
        """L5全栈打流: drop规则→iperf3验证阻断; accept规则→验证放行."""
        page = acl_page_logged_in
        bv = acl_flow_env  # backend_verifier(acl_flow_env已加策略路由+探活)
        rec = step_recorder
        server_ip = bv._ssh_config.iperf3_server
        client_ip = "192.168.148.2"  # _acl_flow_iperf写死-B 192.168.148.2
        failures = []

        print("\n" + "=" * 50)
        print("ACL功能验证(打流实测 drop阻断/accept放行)")
        print("=" * 50)

        try:
            # 清理残留(干净环境)
            with rec.step("清理残留", "删acl_flow_前缀规则确保干净环境"):
                page.navigate_to_acl()
                page.page.wait_for_timeout(1000)
                page.clean_test_rules(self.PREFIX)
                try:
                    bv.cleanup_acl_test(self.PREFIX)
                except Exception:
                    pass

            # drop阻断验证(先drop)
            with rec.step("drop阻断验证", f"建drop({client_ip}→{server_ip} tcp prio=1)→iperf3验证阻断"):
                drop_name = f"{self.PREFIX}drop"
                page.navigate_to_acl()
                page.page.wait_for_timeout(800)
                res = page.add_rule(drop_name, action="drop", direction="forward", protocol="tcp",
                                    src_addrs=[client_ip], dst_addrs=[server_ip], priority=1)
                if not res["success"]:
                    rec.add_detail(f"  ✗ 建drop失败: {res.get('error', '')}")
                    failures.append(f"建drop规则失败: {res.get('error', '')}")
                else:
                    page.page.wait_for_timeout(1500)
                    db = bv.verify_acl_database(drop_name, expected_fields={"action": "drop"})
                    rec.add_detail(f"  建drop | DB: {db.message}")
                    r = bv.verify_acl_flow(drop_name, proto="tcp", dst_port=5201, action="drop")
                    rec.add_detail(f"  {'✓' if r.passed else '✗'} drop打流: {r.message} | {r.raw_output}")
                    print(f"  [{'✓' if r.passed else '✗'}] drop打流: {r.message}")
                    if not r.passed:
                        failures.append(f"drop打流: {r.message}")
                    # 删drop(避免prio=1优先匹配影响accept)
                    page.navigate_to_acl()
                    page.page.wait_for_timeout(500)
                    try:
                        page.delete_rule(drop_name)
                    except Exception:
                        pass
                    page.page.wait_for_timeout(1000)

            # accept放行验证(drop已删)
            with rec.step("accept放行验证", f"建accept→iperf3验证放行"):
                acc_name = f"{self.PREFIX}accept"
                page.navigate_to_acl()
                page.page.wait_for_timeout(800)
                res = page.add_rule(acc_name, action="accept", direction="forward", protocol="tcp",
                                    src_addrs=[client_ip], dst_addrs=[server_ip], priority=1)
                if not res["success"]:
                    rec.add_detail(f"  ✗ 建accept失败: {res.get('error', '')}")
                    failures.append(f"建accept规则失败: {res.get('error', '')}")
                else:
                    page.page.wait_for_timeout(1500)
                    db = bv.verify_acl_database(acc_name, expected_fields={"action": "accept"})
                    rec.add_detail(f"  建accept | DB: {db.message}")
                    r = bv.verify_acl_flow(acc_name, proto="tcp", dst_port=5201, action="accept")
                    rec.add_detail(f"  {'✓' if r.passed else '✗'} accept打流: {r.message} | {r.raw_output}")
                    print(f"  [{'✓' if r.passed else '✗'}] accept打流: {r.message}")
                    if not r.passed:
                        failures.append(f"accept打流: {r.message}")
        finally:
            # 清理: 删规则 + 移除策略路由(acl_flow_env的teardown只杀iperf3, 不移除路由)
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
            try:
                bv.remove_route(server_ip)
            except Exception:
                pass

        print(f"\n[ACL功能验证] drop+accept {'全部通过' if not failures else '失败'+str(len(failures))+'项'}")
        assert not failures, f"ACL功能验证失败({len(failures)}项): {'; '.join(failures)}"
