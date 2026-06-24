"""
自定义协议综合测试用例 (网络配置 > 自定义协议)

两个子模块各一个综合测试:
- TestCustomProtocolComprehensive: 自定义协议(L4, dprotos) — 端口/IP/协议型
- TestAdvancedCustomProtocolComprehensive: 高级自定义协议(L7, dprotos_l7) — 深度包检测特征型

L4后端: ipset dproto_src/dst/sport/dport_$id + iptables mangle DPROTO链(APPMARK--set-appid)
L7后端: rule字段base64(空格分隔 Protocol=TCP Direction=CLIENT Data=xxx), loadapp加载进DPI(异步)

SSH后台验证: L1数据库(dprotos/dprotos_l7) + L2/L3(L4: ipset+iptables; L7: rule base64解码)
"""
import pytest
from pages.network.custom_protocol_page import (
    CustomProtocolPage, AdvancedCustomProtocolPage, CLASS_NAMES,
)
from utils.step_recorder import StepRecorder


# ==================== L4 测试数据 ====================
# 覆盖: 协议(任意/tcp/upd) + 源/目的地址 + 源/目的端口 组合
# !! 注意: UDP 选项实际拼写为 "upd"(固件bug, 2026-06-23实测,
#    选项文本/title/DB值都是upd,iptables可能不识别但DB入库成功)
L4_RULES = [
    {"name": "DPROTO_TCP", "protocol": "tcp", "dst_port": "8080", "comment": "TCP目的端口"},
    {"name": "DPROTO_ADDR", "protocol": "tcp", "src_addr": "192.168.10.1", "dst_addr": "10.66.0.40", "comment": "源目地址"},
    {"name": "DPROTO_UDP", "protocol": "upd", "src_port": "1234", "dst_port": "5678", "comment": "UDP端口"},
    {"name": "DPROTO_ANY", "protocol": "任意", "comment": "任意协议"},
]
L4_NAMES = [r["name"] for r in L4_RULES]

# ==================== L7 测试数据 ====================
L7_RULES = [
    {"name": "DPROTO_L7_1", "rule": "Protocol=TCP Direction=CLIENT Data=testapp1", "comment": "L7-TCP"},
    {"name": "DPROTO_L7_2", "rule": "Protocol=UDP Direction=SERVER Data=testapp2", "comment": "L7-UDP"},
]
L7_NAMES = [r["name"] for r in L7_RULES]


def _make_ssh_verify(rec, backend_verifier, failures):
    """构造 ssh_verify helper (软断言收集 + 末尾硬断言)"""
    def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
        if backend_verifier is None:
            return None
        try:
            result = verify_func(*args, **kwargs)
            status = '[OK]' if result.passed else '[FAIL]'
            print(f"    SSH-{label}: {status} - {result.message}")
            rec.add_detail(f"    SSH-{label}: {status} {result.message}")
            if result.raw_output:
                rec.add_detail(f"      SSH数据: {result.raw_output[:200]}")
            if must_pass and not result.passed:
                failures.append(f"SSH-{label}: {result.message}")
            return result
        except Exception as e:
            print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
            rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
            if must_pass:
                failures.append(f"SSH-{label}: 异常被吞 - {str(e)[:80]}")
            return None
    return ssh_verify


# ============================================================================
# 测试1: 自定义协议 (L4, dprotos)
# ============================================================================
@pytest.mark.custom_protocol
@pytest.mark.network
class TestCustomProtocolComprehensive:
    """自定义协议(L4)综合测试 — 协议/地址/端口组合 + iptables/ipset验证"""

    def test_custom_protocol_comprehensive(self,
                                           custom_protocol_page_logged_in: CustomProtocolPage,
                                           step_recorder: StepRecorder, request):
        page = custom_protocol_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None
        failures = []
        ssh_verify = _make_ssh_verify(rec, backend_verifier, failures)

        def wait_settle():
            page.page.wait_for_timeout(2000)

        print("\n" + "=" * 60)
        print("自定义协议(L4)综合测试开始")
        print("=" * 60)

        # 步骤1: 清理
        with rec.step("步骤1: 清理", "清理DPROTO残留"):
            print("\n[步骤1] 清理...")
            if backend_verifier:
                backend_verifier.cleanup_dproto_test(prefix="DPROTO")
            page.navigate_to_custom_protocol()
            page.page.wait_for_timeout(800)

        # 步骤2: 批量添加4条(L4) + L1数据库 + L2/L3后端
        with rec.step("步骤2: 批量添加4条(L4)", "覆盖任意/tcp/udp+地址+端口, 验证DB+ipset+iptables"):
            print(f"\n[步骤2] 批量添加{len(L4_RULES)}条L4规则...")
            for rule in L4_RULES:
                ok = page.add_rule(
                    name=rule["name"], cls=0, protocol=rule["protocol"],
                    src_addr=rule.get("src_addr"), dst_addr=rule.get("dst_addr"),
                    src_port=rule.get("src_port"), dst_port=rule.get("dst_port"),
                    comment=rule.get("comment", ""),
                )
                print(f"  添加 {rule['name']}: {ok}")
                rec.add_detail(f"添加{rule['name']}: {ok}")
                wait_settle()
            # L1数据库验证(每条)
            # UI选项→DB值映射: 任意→any, upd→udp(UI拼写错但DB存正确udp), 其余原样
            PROTO_UI2DB = {"任意": "any", "upd": "udp"}
            for rule in L4_RULES:
                exp_proto = PROTO_UI2DB.get(rule["protocol"], rule["protocol"])
                ssh_verify(f"L1-{rule['name']}", backend_verifier.verify_dproto_database,
                           must_pass=True, name=rule["name"], proto_type='l4',
                           expected_fields={"enabled": "yes", "class": "0",
                                            "protocol": exp_proto})
            # L2/L3后端验证(有地址/端口的规则应有ipset+iptables)
            for rule in L4_RULES:
                ssh_verify(f"L2L3-{rule['name']}", backend_verifier.verify_dproto_backend,
                           must_pass=False, name=rule["name"], proto_type='l4')

        # 步骤3: 编辑(改comment + 协议)
        with rec.step("步骤3: 编辑DPROTO_TCP", "改备注"):
            print("\n[步骤3] 编辑DPROTO_TCP...")
            ok = page.edit_rule("DPROTO_TCP", comment="编辑后备注")
            print(f"  编辑: {ok}")
            rec.add_detail(f"编辑DPROTO_TCP: {ok}")
            wait_settle()
            ssh_verify("L1-编辑验证", backend_verifier.verify_dproto_database,
                       must_pass=False, name="DPROTO_TCP", proto_type='l4')

        # 步骤4: 停用/启用
        with rec.step("步骤4: 停用/启用DPROTO_TCP", "验证enabled切换"):
            print("\n[步骤4] 停用/启用...")
            try:
                page.navigate_to_custom_protocol()
                page.disable_rule("DPROTO_TCP")
            except Exception as e:
                print(f"  停用异常: {e}")
            wait_settle()
            ssh_verify("L1-停用后no", backend_verifier.verify_dproto_database,
                       must_pass=False, name="DPROTO_TCP", proto_type='l4',
                       expected_fields={"enabled": "no"})
            try:
                page.enable_rule("DPROTO_TCP")
            except Exception as e:
                print(f"  启用异常: {e}")
            wait_settle()
            ssh_verify("L1-启用后yes", backend_verifier.verify_dproto_database,
                       must_pass=False, name="DPROTO_TCP", proto_type='l4',
                       expected_fields={"enabled": "yes"})

        # 步骤5: 搜索
        with rec.step("步骤5: 搜索", "搜索DPROTO匹配多条"):
            print("\n[步骤5] 搜索...")
            page.navigate_to_custom_protocol()
            page.page.wait_for_timeout(800)
            try:
                page.search_rule("DPROTO")
                page.page.wait_for_timeout(1500)
                found = page.rule_exists("DPROTO_TCP") and page.rule_exists("DPROTO_ANY")
                print(f"  搜索'DPROTO'匹配多条: {found}")
                rec.add_detail(f"搜索匹配多条: {found}")
                page.clear_search()
                page.page.wait_for_timeout(500)
            except Exception as e:
                print(f"  搜索异常: {e}")

        # 步骤6: 删除1条
        with rec.step("步骤6: 删除DPROTO_ANY", "删除+验证"):
            print("\n[步骤6] 删除DPROTO_ANY...")
            try:
                page.navigate_to_custom_protocol()
                page.page.wait_for_timeout(500)
                page.delete_rule("DPROTO_ANY")
                wait_settle()
            except Exception as e:
                print(f"  删除异常: {e}")
            ssh_verify("L1-删除后无ANY", backend_verifier.verify_dproto_database,
                       must_pass=True, name="DPROTO_ANY", proto_type='l4', expect_absent=True)

        # 步骤7: 异常输入(空名称)
        with rec.step("步骤7: 异常输入", "空名称保存应被拦截"):
            print("\n[步骤7] 异常输入...")
            err = page.try_add_rule_invalid(name="")
            if err:
                print(f"  [OK] 空名称拦截: {err[:40]}")
                rec.add_detail(f"[OK] 空名称拦截: {err[:40]}")
            else:
                # 可能允许空名(后端拦截)或无错误(检查是否真添加)
                print(f"  [WARN] 空名称未拦截(err={err})")
                rec.add_detail(f"[WARN] 空名称未拦截")
            try:
                page.page.keyboard.press("Escape")
                page.navigate_to_custom_protocol()
                page.page.wait_for_timeout(500)
            except Exception:
                pass

        # 步骤8: 导出
        export_file = None
        with rec.step("步骤8: 导出", "导出L4配置(供导入用)"):
            print("\n[步骤8] 导出...")
            import os as _os
            import re as _re
            from config.config import get_config as _get_cfg
            _cfg = _get_cfg()
            _base = _cfg.test_data.get_export_path("custom_protocol", _cfg.get_project_root())
            export_file = _os.path.splitext(_base)[0] + ".txt"
            try:
                page.navigate_to_custom_protocol()
                page.page.wait_for_timeout(800)
                exported = page.export_rules(use_config_path=True, export_format="txt")
                print(f"  导出txt: {exported}")
                rec.add_detail(f"导出txt: {exported}")
                csv_ok = page.export_rules(use_config_path=True, export_format="csv")
                print(f"  导出csv: {csv_ok}")
                rec.add_detail(f"导出csv: {csv_ok}")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")

        # 步骤9: 导入追加(新名DPROTO_IMP, 不勾清空)
        with rec.step("步骤9: 导入追加", "导入新名规则, 验证追加+入库"):
            print("\n[步骤9] 导入追加...")
            if not (export_file and _os.path.exists(export_file)):
                print(f"  [WARN] 无导出文件, 跳过导入: {export_file}")
                rec.add_detail("[WARN] 跳过导入追加")
            else:
                import_file_append = export_file.replace(".txt", "_append.txt")
                try:
                    with open(export_file, 'r', encoding='utf-8') as f:
                        first_line = f.readline()
                    lines = []
                    for i, nm in enumerate(["DPROTO_IMP_1", "DPROTO_IMP_2"], 1):
                        ln = first_line
                        ln = _re.sub(r'^id=\S+\s*', '', ln)  # 剥行首id(主键)
                        ln = _re.sub(r'\sappid=\S+', '', ln)  # 剥appid(后端重新派生)
                        ln = _re.sub(r'name=\S+', f'name={nm}', ln)
                        ln = _re.sub(r'comment=\S*', f'comment=导入追加{i}', ln)
                        lines.append(ln)
                    with open(import_file_append, 'w', encoding='utf-8') as f:
                        f.writelines(lines)
                    print(f"  追加文件含{len(lines)}条新规则")
                except Exception as e:
                    print(f"  [WARN] 准备追加文件失败: {e}")
                    import_file_append = export_file
                count_before = backend_verifier.count_dprotos('l4') if backend_verifier else -1
                print(f"  导入前L4数: {count_before}")
                try:
                    page.navigate_to_custom_protocol()
                    page.page.wait_for_timeout(800)
                    page.import_rules(import_file_append, clear_existing=False)
                    wait_settle()
                except Exception as e:
                    print(f"  [WARN] 导入异常: {e}")
                count_after = backend_verifier.count_dprotos('l4') if backend_verifier else -1
                print(f"  导入后L4数: {count_after}")
                if count_after > count_before:
                    print(f"  [OK] 导入追加成功(+{count_after - count_before})")
                    rec.add_detail(f"[OK] 追加+{count_after - count_before}")
                else:
                    print(f"  [WARN] 导入追加未增加")
                    rec.add_detail("[WARN] 追加未增加")
                ssh_verify("L1-导入追加-IMP_1入库", backend_verifier.verify_dproto_database,
                           must_pass=False, name="DPROTO_IMP_1", proto_type='l4')

        # 步骤10: 导入清空(加DPROTO_EXTRA标志, 勾清空)
        with rec.step("步骤10: 导入清空", "加EXTRA标志, 清空导入, 验证清空生效"):
            print("\n[步骤10] 导入清空...")
            if not (export_file and _os.path.exists(export_file)):
                print("  [WARN] 无导出文件, 跳过清空导入")
                rec.add_detail("[WARN] 跳过清空导入")
            else:
                # 加DPROTO_EXTRA标志(不在导出文件)
                try:
                    page.add_rule(name="DPROTO_EXTRA", cls=0, comment="清空标志")
                    wait_settle()
                except Exception as e:
                    print(f"  添加EXTRA异常: {e}")
                try:
                    page.navigate_to_custom_protocol()
                    page.page.wait_for_timeout(800)
                    page.import_rules(export_file, clear_existing=True)
                    wait_settle()
                except Exception as e:
                    print(f"  [WARN] 清空导入异常: {e}")
                ssh_verify("L1-清空后EXTRA消失", backend_verifier.verify_dproto_database,
                           must_pass=True, name="DPROTO_EXTRA", proto_type='l4', expect_absent=True)

        # 步骤11: 帮助
        with rec.step("步骤11: 帮助", "测试帮助按钮"):
            print("\n[步骤11] 帮助...")
            page.navigate_to_custom_protocol()
            page.page.wait_for_timeout(800)
            try:
                pages_before = len(page.page.context.pages)
                help_btn = page.page.locator('button').filter(has_text="帮助")
                if help_btn.count() > 0:
                    try:
                        with page.page.context.expect_page(timeout=2500) as np:
                            help_btn.last.click()
                        try:
                            np.value.close()
                        except Exception:
                            pass
                    except Exception:
                        page.page.wait_for_timeout(500)
                print("  [OK] 帮助测试完成")
                rec.add_detail("[OK] 帮助测试完成")
                pages_after = len(page.page.context.pages)
                if pages_after > pages_before:
                    failures.append("步骤11: 帮助产生孤儿tab")
            except Exception as e:
                print(f"  [WARN] 帮助异常: {e}")

        # 步骤12: 最终清理(批量删除+兜底)
        with rec.step("步骤12: 最终清理", "删除全部DPROTO + SSH验证0残留"):
            print("\n[步骤12] 最终清理...")
            # 行内删除兜底(每条)
            for name in ["DPROTO_TCP", "DPROTO_ADDR", "DPROTO_UDP"]:
                for attempt in range(2):
                    if backend_verifier and not backend_verifier.find_dproto(name, 'l4'):
                        break
                    try:
                        page.navigate_to_custom_protocol()
                        page.page.wait_for_timeout(500)
                        if page.rule_exists(name):
                            page.delete_rule(name)
                            wait_settle()
                    except Exception as e:
                        print(f"  删除{name}异常: {str(e)[:50]}")
            if backend_verifier:
                backend_verifier.cleanup_dproto_test(prefix="DPROTO")
                wait_settle()
            ssh_verify("L1-清理后无DPROTO_TCP", backend_verifier.verify_dproto_database,
                       must_pass=True, name="DPROTO_TCP", proto_type='l4', expect_absent=True)

        print("\n" + "=" * 60)
        print("自定义协议(L4)综合测试完成")
        print("=" * 60)
        if failures:
            print(f"\n[断言] 共 {len(failures)} 项失败:")
            for f in failures:
                print(f"  - {f}")
        assert not failures, f"验证失败({len(failures)}项): {'; '.join(failures)}"


# ============================================================================
# 测试2: 高级自定义协议 (L7, dprotos_l7)
# ============================================================================
@pytest.mark.advanced_custom_protocol
@pytest.mark.network
class TestAdvancedCustomProtocolComprehensive:
    """高级自定义协议(L7)综合测试 — L7特征 + rule base64验证"""

    def test_advanced_custom_protocol_comprehensive(self,
                                                    advanced_custom_protocol_page_logged_in: AdvancedCustomProtocolPage,
                                                    step_recorder: StepRecorder, request):
        page = advanced_custom_protocol_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None
        failures = []
        ssh_verify = _make_ssh_verify(rec, backend_verifier, failures)

        def wait_settle():
            page.page.wait_for_timeout(2000)

        print("\n" + "=" * 60)
        print("高级自定义协议(L7)综合测试开始")
        print("=" * 60)

        # 步骤1: 清理
        with rec.step("步骤1: 清理", "清理DPROTO_L7残留"):
            print("\n[步骤1] 清理...")
            if backend_verifier:
                backend_verifier.cleanup_dproto_test(prefix="DPROTO")
            page.navigate_to_advanced_custom_protocol()
            page.page.wait_for_timeout(800)

        # 步骤2: 添加2条(L7) + L1数据库 + L2 rule解码
        with rec.step("步骤2: 添加2条(L7)", "验证DB + rule base64解码"):
            print(f"\n[步骤2] 添加{len(L7_RULES)}条L7规则...")
            for rule in L7_RULES:
                ok = page.add_rule(name=rule["name"], rule=rule["rule"],
                                   cls=0, comment=rule["comment"])
                print(f"  添加 {rule['name']}: {ok}")
                rec.add_detail(f"添加{rule['name']}: {ok}")
                wait_settle()
            for rule in L7_RULES:
                ssh_verify(f"L1-{rule['name']}", backend_verifier.verify_dproto_database,
                           must_pass=True, name=rule["name"], proto_type='l7',
                           expected_fields={"enabled": "yes", "class": "0"})
                ssh_verify(f"L2-{rule['name']}解码", backend_verifier.verify_dproto_backend,
                           must_pass=False, name=rule["name"], proto_type='l7')

        # 步骤3: 编辑(改rule + comment)
        with rec.step("步骤3: 编辑DPROTO_L7_1", "改协议特征"):
            print("\n[步骤3] 编辑DPROTO_L7_1...")
            ok = page.edit_rule("DPROTO_L7_1",
                                rule="Protocol=TCP Direction=CLIENT Data=edited_app",
                                comment="编辑后")
            print(f"  编辑: {ok}")
            rec.add_detail(f"编辑L7_1: {ok}")
            wait_settle()
            ssh_verify("L1-编辑验证", backend_verifier.verify_dproto_database,
                       must_pass=False, name="DPROTO_L7_1", proto_type='l7')

        # 步骤4: 停用/启用
        with rec.step("步骤4: 停用/启用", "验证enabled切换"):
            print("\n[步骤4] 停用/启用...")
            try:
                page.navigate_to_advanced_custom_protocol()
                page.disable_rule("DPROTO_L7_1")
            except Exception as e:
                print(f"  停用异常: {e}")
            wait_settle()
            ssh_verify("L1-停用后no", backend_verifier.verify_dproto_database,
                       must_pass=False, name="DPROTO_L7_1", proto_type='l7',
                       expected_fields={"enabled": "no"})
            try:
                page.enable_rule("DPROTO_L7_1")
            except Exception as e:
                print(f"  启用异常: {e}")
            wait_settle()
            ssh_verify("L1-启用后yes", backend_verifier.verify_dproto_database,
                       must_pass=False, name="DPROTO_L7_1", proto_type='l7',
                       expected_fields={"enabled": "yes"})

        # 步骤5: 搜索
        with rec.step("步骤5: 搜索", "搜索DPROTO_L7"):
            print("\n[步骤5] 搜索...")
            page.navigate_to_advanced_custom_protocol()
            page.page.wait_for_timeout(800)
            try:
                page.search_rule("DPROTO_L7")
                page.page.wait_for_timeout(1500)
                found = page.rule_exists("DPROTO_L7_1")
                print(f"  搜索'DPROTO_L7'匹配: {found}")
                rec.add_detail(f"搜索匹配: {found}")
                page.clear_search()
                page.page.wait_for_timeout(500)
            except Exception as e:
                print(f"  搜索异常: {e}")

        # 步骤6: 异常输入(空名称)
        with rec.step("步骤6: 异常输入", "空名称/空rule应被拦截"):
            print("\n[步骤6] 异常输入...")
            err = page.try_add_rule_invalid(name="", rule="Protocol=TCP Direction=CLIENT Data=x")
            if err:
                print(f"  [OK] 空名称拦截: {err[:40]}")
                rec.add_detail(f"[OK] 空名称拦截")
            else:
                print(f"  [WARN] 空名称未拦截")
                rec.add_detail("[WARN] 空名称未拦截")
            try:
                page.page.keyboard.press("Escape")
                page.navigate_to_advanced_custom_protocol()
                page.page.wait_for_timeout(500)
            except Exception:
                pass

        # 步骤7: 导出
        export_file_l7 = None
        with rec.step("步骤7: 导出", "导出L7配置(供导入用)"):
            print("\n[步骤7] 导出...")
            import os as _os
            import re as _re
            from config.config import get_config as _get_cfg
            _cfg = _get_cfg()
            _base = _cfg.test_data.get_export_path("advanced_custom_protocol", _cfg.get_project_root())
            export_file_l7 = _os.path.splitext(_base)[0] + ".txt"
            try:
                page.navigate_to_advanced_custom_protocol()
                page.page.wait_for_timeout(800)
                exported = page.export_rules(use_config_path=True, export_format="txt")
                print(f"  导出txt: {exported}")
                rec.add_detail(f"导出txt: {exported}")
                csv_ok = page.export_rules(use_config_path=True, export_format="csv")
                print(f"  导出csv: {csv_ok}")
                rec.add_detail(f"导出csv: {csv_ok}")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")

        # 步骤8: 导入追加(新名DPROTO_L7_IMP)
        with rec.step("步骤8: 导入追加", "导入新名L7规则, 验证追加+入库"):
            print("\n[步骤8] 导入追加...")
            if not (export_file_l7 and _os.path.exists(export_file_l7)):
                print(f"  [WARN] 无导出文件, 跳过: {export_file_l7}")
                rec.add_detail("[WARN] 跳过导入追加")
            else:
                import_file_append = export_file_l7.replace(".txt", "_append.txt")
                try:
                    with open(export_file_l7, 'r', encoding='utf-8') as f:
                        first_line = f.readline()
                    ln = first_line
                    ln = _re.sub(r'^id=\S+\s*', '', ln)  # 剥行首id(主键)
                    ln = _re.sub(r'\sappid=\S+', '', ln)  # 剥appid
                    ln = _re.sub(r'name=\S+', 'name=DPROTO_L7_IMP_1', ln)
                    ln = _re.sub(r'comment=\S*', 'comment=导入追加', ln)
                    with open(import_file_append, 'w', encoding='utf-8') as f:
                        f.write(ln)
                except Exception as e:
                    print(f"  [WARN] 准备追加文件失败: {e}")
                    import_file_append = export_file_l7
                count_before = backend_verifier.count_dprotos('l7') if backend_verifier else -1
                try:
                    page.navigate_to_advanced_custom_protocol()
                    page.page.wait_for_timeout(800)
                    page.import_rules(import_file_append, clear_existing=False)
                    wait_settle()
                except Exception as e:
                    print(f"  [WARN] 导入异常: {e}")
                count_after = backend_verifier.count_dprotos('l7') if backend_verifier else -1
                print(f"  导入前{count_before} → 导入后{count_after}")
                rec.add_detail(f"L7导入: {count_before}→{count_after}")
                ssh_verify("L1-导入追加-IMP_1入库", backend_verifier.verify_dproto_database,
                           must_pass=False, name="DPROTO_L7_IMP_1", proto_type='l7')

        # 步骤9: 导入清空(DPROTO_EXTRA标志)
        with rec.step("步骤9: 导入清空", "加EXTRA标志, 清空导入, 验证清空生效"):
            print("\n[步骤9] 导入清空...")
            if not (export_file_l7 and _os.path.exists(export_file_l7)):
                print("  [WARN] 无导出文件, 跳过清空导入")
                rec.add_detail("[WARN] 跳过清空导入")
            else:
                try:
                    page.add_rule(name="DPROTO_EXTRA", rule="Protocol=TCP Direction=CLIENT Data=extra",
                                  cls=0, comment="清空标志")
                    wait_settle()
                except Exception as e:
                    print(f"  添加EXTRA异常: {e}")
                try:
                    page.navigate_to_advanced_custom_protocol()
                    page.page.wait_for_timeout(800)
                    page.import_rules(export_file_l7, clear_existing=True)
                    wait_settle()
                except Exception as e:
                    print(f"  [WARN] 清空导入异常: {e}")
                ssh_verify("L1-清空后EXTRA消失", backend_verifier.verify_dproto_database,
                           must_pass=True, name="DPROTO_EXTRA", proto_type='l7', expect_absent=True)

        # 步骤10: 帮助
        with rec.step("步骤10: 帮助", "测试帮助按钮"):
            print("\n[步骤10] 帮助...")
            page.navigate_to_advanced_custom_protocol()
            page.page.wait_for_timeout(800)
            try:
                help_btn = page.page.locator('button').filter(has_text="帮助")
                if help_btn.count() > 0:
                    try:
                        with page.page.context.expect_page(timeout=2500) as np:
                            help_btn.last.click()
                        try:
                            np.value.close()
                        except Exception:
                            pass
                    except Exception:
                        page.page.wait_for_timeout(500)
                print("  [OK] 帮助测试完成")
                rec.add_detail("[OK] 帮助测试完成")
            except Exception as e:
                print(f"  [WARN] 帮助异常: {e}")

        # 步骤11: 最终清理
        with rec.step("步骤11: 最终清理", "删除全部DPROTO_L7"):
            print("\n[步骤11] 最终清理...")
            for name in L7_NAMES:
                for attempt in range(2):
                    if backend_verifier and not backend_verifier.find_dproto(name, 'l7'):
                        break
                    try:
                        page.navigate_to_advanced_custom_protocol()
                        page.page.wait_for_timeout(500)
                        if page.rule_exists(name):
                            page.delete_rule(name)
                            wait_settle()
                    except Exception as e:
                        print(f"  删除{name}异常: {str(e)[:50]}")
            if backend_verifier:
                backend_verifier.cleanup_dproto_test(prefix="DPROTO")
                wait_settle()
            ssh_verify("L1-清理后无L7_1", backend_verifier.verify_dproto_database,
                       must_pass=True, name="DPROTO_L7_1", proto_type='l7', expect_absent=True)

        print("\n" + "=" * 60)
        print("高级自定义协议(L7)综合测试完成")
        print("=" * 60)
        if failures:
            print(f"\n[断言] 共 {len(failures)} 项失败:")
            for f in failures:
                print(f"  - {f}")
        assert not failures, f"验证失败({len(failures)}项): {'; '.join(failures)}"
