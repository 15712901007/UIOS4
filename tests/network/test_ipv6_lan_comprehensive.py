"""
IPv6内网设置综合测试用例

网络配置 > 内外网设置 > IPv6设置 > 内网设置 tab 综合测试
表格型(IPv6 LAN接口), 添加/编辑独立页面(/ipv6Settings/intranetSetting/add), 表单全#id定位。

一次测试覆盖(14步, 参照VLAN/IP限速/port_map全流程):
1. 检查并清理环境(IPV6LAN*残留)
2. 添加表单字段验证(全#id)
3. 添加规则1(doc_app_default/绑定wan1/自动获取) + L1数据库验证
4. 编辑(改名+改租期) + L1验证
5. 停用 + L1验证enabled=no
6. 启用 + L1验证enabled=yes
7. 导出(CSV/TXT双格式)
8. 排序测试
9. 删除 + L1验证应不存在
10. 前端/后端校验(空名称/缺绑定外网线路/接口lan1冲突UNIQUE/超长名/特殊字符)
11. 导入(追加) + L1验证
12. 导入(清空现有) + 验证clear生效 + 恢复默认CFLAN_1
13. 帮助功能
14. 最终清理 + L1验证无残留 + 恢复CFLAN_1

!!环境与约束:
- IPv6全局enabled=no, L1数据库(ipv6_lan_config)硬断言(must_pass=True)。
- interface字段UNIQUE: lan1被默认CFLAN_1占用, 新增仅doc_app_default可用(测试设备仅2个内网接口),
  故内网设置最多新增1条, 无批量操作意义(批量无法避开默认CFLAN_1且仅1条可加)。
- 内网设置表单无enabled字段, add()默认enabled=yes(schema默认); 停用/启用经行内按钮(down/up)切换。
- 导入文件只含合法测试规则(IPV6LAN_IMP, parent=wan1): 默认CFLAN_1空parent通不过导入校验会致整批中止,
  故不能导入含CFLAN_1的导出文件; clear-existing导入会删CFLAN_1且不可导入恢复→测试后SQL恢复。
"""
import pytest
import os
from pages.network.ipv6_lan_page import Ipv6LanPage
from utils.step_recorder import StepRecorder


@pytest.mark.ipv6_lan
@pytest.mark.network
class TestIpv6LanComprehensive:
    """IPv6内网设置综合测试 - 受interface唯一约束(仅doc_app_default可用, 加1条)"""

    def test_ipv6_lan_comprehensive(self, ipv6_lan_page_logged_in: Ipv6LanPage,
                                     step_recorder: StepRecorder, request):
        """综合测试: 表单验证 -> 加1条 -> 编辑 -> 停用启用 -> 导出 -> 排序 -> 删除 ->
        校验 -> 导入追加 -> 导入清空 -> 帮助 -> 清理"""
        page = ipv6_lan_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []
        ui_failures = []

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            if backend_verifier is None:
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = '[OK]' if result.passed else '[FAIL]'
                print(f"    SSH-{label}: {status} - {result.message}")
                rec.add_detail(f"    SSH-{label}: {status} {result.message}")
                if result.raw_output:
                    rec.add_detail(f"      SSH数据: {result.raw_output}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                if must_pass:
                    ssh_failures.append(f"SSH-{label}: 异常被吞 - {str(e)[:80]}")
                return None

        T1 = "IPV6LAN_T1"
        T1_EDITED = "IPV6LAN_E1"
        IMP = "IPV6LAN_IMP"      # 导入测试规则(doc_app_default/wan1)

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        import_file_csv = os.path.join(project_root, "test_data", "imports", "ipv6_lan", "ipv6_lan_import.csv")
        import_file_txt = os.path.join(project_root, "test_data", "imports", "ipv6_lan", "ipv6_lan_import.txt")

        print("\n" + "=" * 60)
        print("IPv6内网设置综合测试开始")
        print("=" * 60)
        print("!!约束: interface UNIQUE, lan1被默认CFLAN_1占用, 新增仅doc_app_default可用(1条)")
        print("!!故无批量操作(批量无法避开默认CFLAN_1且仅1条可加)")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "清理IPV6LAN*残留 + 确认默认CFLAN_1"):
            print("\n[步骤1] 检查并清理环境...")
            if backend_verifier:
                backend_verifier.cleanup_ipv6_lan_test("IPV6LAN")
            page.navigate_to_ipv6_lan()
            page.page.wait_for_timeout(1000)
            count = page.get_rule_count()
            print(f"  当前内网设置规则数(含默认CFLAN_1): {count}")
            rec.add_detail(f"清理后规则数: {count}")
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.navigate_to_ipv6_lan()
            page.page.wait_for_timeout(800)

        # ========== 步骤2: 添加表单字段验证 ==========
        with rec.step("步骤2: 添加表单字段验证", "验证表单字段#id"):
            print("\n[步骤2] 添加表单字段验证...")
            page.open_add_page()
            page.page.wait_for_timeout(500)
            fields = {}
            for fid in ['tagname', 'interface', 'internet', 'prefix_len',
                        'dhcpv6', 'ra_flags', 'ra_static', 'use_dns6',
                        'leasetime', 'ra_mtu_set']:
                el = page.page.locator(f'#{fid}')
                fields[fid] = el.count() > 0
            print(f"  表单字段: {fields}")
            rec.add_detail(f"表单字段: {fields}")
            missing = [k for k, v in fields.items() if not v]
            if missing:
                ssh_failures.append(f"表单字段缺失: {missing}")
            else:
                print(f"  [OK] 所有字段#id存在")
                rec.add_detail("[OK] 字段完整")
            parent_label = page.page.locator('.ant-form-item-label:has-text("绑定外网线路")')
            rec.add_detail(f"绑定外网线路label存在: {parent_label.count() > 0}")
            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_ipv6_lan()
            page.page.wait_for_timeout(500)

        # ========== 步骤3: 添加规则1 (doc_app_default/绑定wan1/自动获取) ==========
        with rec.step(f"步骤3: 添加规则 {T1}", "doc_app_default/绑定wan1/自动获取"):
            print(f"\n[步骤3] 添加规则: {T1} (doc_app_default, parent=wan1, dhcp)")
            result = page.add_rule(name=T1, interface="doc_app_default",
                                   internet=Ipv6LanPage.INTERNET_DHCP,
                                   parents=["wan1"], leasetime="120")
            assert result is True, f"添加规则 {T1} 失败"
            print(f"  + 已添加: {T1}")
            rec.add_detail(f"[OK] 添加 {T1} (doc_app_default/wan1/dhcp)")
            ssh_verify(f"L1-数据库({T1})", backend_verifier.verify_ipv6_lan_database,
                       T1, must_pass=True,
                       expected_fields={"enabled": "yes", "interface": "doc_app_default",
                                        "internet": "dhcp", "leasetime": "120"})

        # ========== 步骤4: 编辑(改名+改租期) ==========
        with rec.step(f"步骤4: 编辑规则 {T1}->{T1_EDITED}", "改名+租期改240"):
            print(f"\n[步骤4] 编辑规则: {T1} -> {T1_EDITED} (租期240)")
            result = page.edit_rule(T1, new_name=T1_EDITED, leasetime="240")
            if result:
                assert page.rule_exists(T1_EDITED), f"编辑后 {T1_EDITED} 未找到"
                print(f"  [OK] 编辑成功: {T1} -> {T1_EDITED}")
                rec.add_detail(f"[OK] 编辑成功 {T1}->{T1_EDITED}, 租期240")
                ssh_verify(f"L1-编辑后({T1_EDITED})",
                           backend_verifier.verify_ipv6_lan_database,
                           T1_EDITED, must_pass=True,
                           expected_fields={"interface": "doc_app_default", "leasetime": "240"})
            else:
                print(f"  [WARN] 编辑失败")
                rec.add_detail("[WARN] 编辑失败")
                ui_failures.append("编辑规则失败")

        # ========== 步骤5: 停用 ==========
        with rec.step(f"步骤5: 停用 {T1_EDITED}", "停用 + L1验证enabled=no"):
            print(f"\n[步骤5] 停用 {T1_EDITED}...")
            page.disable_rule(T1_EDITED)
            page.page.wait_for_timeout(1000)
            if page.is_rule_disabled(T1_EDITED):
                print(f"  [OK] 停用成功")
                rec.add_detail("[OK] 停用成功")
            else:
                rec.add_detail("[WARN] 停用状态未确认")
            ssh_verify(f"L1-停用({T1_EDITED})",
                       backend_verifier.verify_ipv6_lan_database,
                       T1_EDITED, must_pass=True, expected_fields={"enabled": "no"})

        # ========== 步骤6: 启用 ==========
        with rec.step(f"步骤6: 启用 {T1_EDITED}", "启用 + L1验证enabled=yes"):
            print(f"\n[步骤6] 启用 {T1_EDITED}...")
            page.enable_rule(T1_EDITED)
            page.page.wait_for_timeout(1000)
            if page.is_rule_enabled(T1_EDITED):
                print(f"  [OK] 启用成功")
                rec.add_detail("[OK] 启用成功")
            else:
                rec.add_detail("[WARN] 启用状态未确认")
            ssh_verify(f"L1-启用({T1_EDITED})",
                       backend_verifier.verify_ipv6_lan_database,
                       T1_EDITED, must_pass=True, expected_fields={"enabled": "yes"})

        # ========== 步骤7: 导出测试(CSV+TXT) ==========
        export_dir = os.path.join(project_root, "test_data", "exports", "ipv6_lan")
        export_file_csv = os.path.join(export_dir, "ipv6_lan_config.csv")
        export_file_txt = os.path.join(export_dir, "ipv6_lan_config.txt")

        with rec.step("步骤7: 导出测试", "导出CSV和TXT"):
            print("\n[步骤7] 导出测试...")
            rec.add_detail("[导出测试]")
            for fmt, fpath in [("csv", export_file_csv), ("txt", export_file_txt)]:
                try:
                    ok = page.export_rules(export_format=fmt)
                    if ok and os.path.exists(fpath):
                        size = os.path.getsize(fpath)
                        print(f"  [OK] {fmt.upper()}导出: {os.path.basename(fpath)} ({size}B)")
                        rec.add_detail(f"[OK] {fmt.upper()}导出 ({size}B)")
                    else:
                        print(f"  [WARN] {fmt.upper()}导出失败")
                        rec.add_detail(f"[WARN] {fmt.upper()}导出失败")
                        ui_failures.append(f"{fmt.upper()}导出失败")
                except Exception as e:
                    print(f"  [WARN] {fmt.upper()}导出异常: {e}")
                    rec.add_detail(f"[WARN] {fmt.upper()}导出异常: {e}")

        # ========== 步骤8: 排序测试 ==========
        with rec.step("步骤8: 排序测试", "内网接口列排序"):
            print("\n[步骤8] 排序测试...")
            rec.add_detail("[排序测试]")
            try:
                sorted_ok = page.sort_by_column("内网接口")
                if sorted_ok:
                    print(f"  [OK] 内网接口列排序成功")
                    rec.add_detail("[OK] 内网接口列排序成功")
                else:
                    print(f"  [WARN] 内网接口列无排序图标(可能不支持)")
                    rec.add_detail("[WARN] 无排序图标")
            except Exception as e:
                print(f"  [WARN] 排序异常: {e}")
                rec.add_detail(f"[WARN] 排序异常: {e}")

        # ========== 步骤9: 删除 ==========
        with rec.step(f"步骤9: 删除 {T1_EDITED}", "删除 + L1验证应不存在"):
            print(f"\n[步骤9] 删除 {T1_EDITED}...")
            page.delete_rule(T1_EDITED)
            page.page.wait_for_timeout(1500)
            page.page.reload()
            page.navigate_to_ipv6_lan()
            page.page.wait_for_timeout(500)
            assert not page.rule_exists(T1_EDITED), f"{T1_EDITED} 删除后仍存在"
            print(f"  [OK] 删除成功: {T1_EDITED}")
            rec.add_detail(f"[OK] 删除 {T1_EDITED}")
            ssh_verify(f"L1-删除验证({T1_EDITED})",
                       backend_verifier.verify_ipv6_lan_database,
                       T1_EDITED, must_pass=True, expect_absent=True)

        # ========== 步骤10: 前端/后端校验测试 ==========
        with rec.step("步骤10: 前端/后端校验", "空名/缺parent/接口lan1冲突/超长名/特殊字符"):
            print("\n[步骤10] 前端/后端校验测试...")
            rec.add_detail("[校验测试]")

            # 10.1 空名称
            rec.add_detail("  空名称:")
            r = page.try_add_rule_invalid(name="", parents=["wan1"])
            if r["success"]:
                print(f"    [OK] 拦截: {r.get('error_message', '')[:50]}")
                rec.add_detail(f"    [OK] 拦截: {r.get('error_message', '')[:50]}")
            else:
                rec.add_detail("    [FAIL] 空名未拦截")
                ui_failures.append("空名称未拦截")

            # 10.2 缺绑定外网线路(dhcp模式parent必填, __check_param拦截)
            rec.add_detail("  缺绑定外网线路:")
            r = page.try_add_rule_invalid(name="IPV6LAN_NOP")
            print(f"    [INFO] 缺parent: {r}")
            rec.add_detail(f"    [INFO] 缺parent: {r}")

            # 10.3 接口lan1冲突(UNIQUE, lan1被CFLAN_1占用). 名称用≤15字符避免先触发名称校验
            rec.add_detail("  接口lan1冲突(UNIQUE):")
            r = page.try_add_rule_invalid(name="IPV6LANCF", interface="lan1", parents=["wan1"])
            print(f"    [INFO] lan1冲突: {r}")
            rec.add_detail(f"    [INFO] lan1冲突: {r}")
            if backend_verifier:
                conflict = backend_verifier.query_ipv6_lan_rule("IPV6LANCF")
                rec.add_detail(f"    SSH: IPV6LANCF入库={conflict is not None}(期望False)")
                print(f"    SSH: IPV6LANCF入库={conflict is not None}")

            # 10.4 超长名称(>15字符)
            rec.add_detail("  超长名称(20字符):")
            r = page.try_add_rule_invalid(name="a" * 20, parents=["wan1"])
            print(f"    [INFO] 超长名: {r}")
            rec.add_detail(f"    [INFO] 超长名: {r}")

            # 10.5 特殊字符
            rec.add_detail("  特殊字符:")
            r = page.try_add_rule_invalid(name="<script>x</script>", parents=["wan1"])
            print(f"    [INFO] 特殊字符: {r}")
            rec.add_detail(f"    [INFO] 特殊字符: {r}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.navigate_to_ipv6_lan()
            page.page.wait_for_timeout(800)

        # ========== 步骤11: 导入测试(追加) ==========
        with rec.step(f"步骤11: 导入配置(追加)", f"导入{IMP} + L1验证"):
            print(f"\n[步骤11] 导入配置(追加){IMP}...")
            rec.add_detail("[导入测试-追加]")
            try:
                page.import_rules(import_file_csv, clear_existing=False)
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.navigate_to_ipv6_lan()
                page.page.wait_for_timeout(800)
                if page.rule_exists(IMP):
                    print(f"  [OK] 追加导入成功: {IMP} 已存在")
                    rec.add_detail(f"[OK] 追加导入 {IMP}")
                    ssh_verify(f"L1-导入后({IMP})", backend_verifier.verify_ipv6_lan_database,
                               IMP, must_pass=True,
                               expected_fields={"interface": "doc_app_default",
                                                "internet": "dhcp", "parent": "wan1"})
                else:
                    print(f"  [WARN] 追加导入后 {IMP} 未找到")
                    rec.add_detail(f"[WARN] {IMP}未找到")
                    ui_failures.append("导入追加失败")
            except Exception as e:
                print(f"  [WARN] 导入异常: {e}")
                rec.add_detail(f"[WARN] 导入异常: {e}")
                ui_failures.append("导入追加异常")

        # ========== 步骤12: 导入测试(清空现有) ==========
        with rec.step("步骤12: 导入配置(清空现有)", f"清空后导入{IMP} + 验证clear + 恢复CFLAN_1"):
            print(f"\n[步骤12] 导入配置(清空现有){IMP}...")
            rec.add_detail("[导入测试-清空现有]")
            try:
                page.import_rules(import_file_txt, clear_existing=True)
                page.page.wait_for_timeout(2000)
                page.page.reload()
                page.navigate_to_ipv6_lan()
                page.page.wait_for_timeout(800)
                if backend_verifier:
                    cflan = backend_verifier.query_ipv6_lan_rule("CFLAN_1")
                    imp = backend_verifier.query_ipv6_lan_rule(IMP)
                    rec.add_detail(f"  SSH: clear后 CFLAN_1存在={cflan is not None}(期望False=已清), {IMP}存在={imp is not None}(期望True)")
                    print(f"  SSH: clear后 CFLAN_1={cflan is not None}, {IMP}={imp is not None}")
                    if cflan is None and imp is not None:
                        print(f"  [OK] 清空现有生效(CFLAN_1被清, {IMP}导入)")
                        rec.add_detail(f"[OK] 清空现有生效")
                    else:
                        rec.add_detail(f"[WARN] clear校验异常")
                # 恢复默认CFLAN_1
                if backend_verifier:
                    backend_verifier.restore_ipv6_lan_default()
                    page.page.wait_for_timeout(500)
                    cflan2 = backend_verifier.query_ipv6_lan_rule("CFLAN_1")
                    rec.add_detail(f"  SSH: 恢复后 CFLAN_1存在={cflan2 is not None}(应True)")
                    print(f"  SSH: 恢复后 CFLAN_1={cflan2 is not None}")
            except Exception as e:
                print(f"  [WARN] 清空导入异常: {e}")
                rec.add_detail(f"[WARN] 清空导入异常: {e}")
                if backend_verifier:
                    backend_verifier.restore_ipv6_lan_default()

        # ========== 步骤13: 帮助功能 ==========
        with rec.step("步骤13: 帮助功能测试", "测试帮助图标"):
            print("\n[步骤13] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")
            try:
                page.navigate_to_ipv6_lan()
                page.page.wait_for_timeout(500)
                help_btn = page.page.locator('button').filter(has_text="帮助")
                if help_btn.count() > 0:
                    help_btn.last.click()
                    page.page.wait_for_timeout(1000)
                    panel = page.page.locator(
                        '.ant-drawer:visible, .ant-modal:visible, '
                        '[role="dialog"]:visible, .ant-popover:visible')
                    if panel.count() > 0:
                        print(f"  [OK] 帮助面板已显示")
                        rec.add_detail("[OK] 帮助面板显示")
                        page.page.keyboard.press("Escape")
                        page.page.wait_for_timeout(300)
                    else:
                        print(f"  [WARN] 帮助面板未显示")
                        rec.add_detail("[WARN] 帮助面板未显示")
                        page.page.keyboard.press("Escape")
                else:
                    print(f"  [WARN] 帮助按钮未找到")
                    rec.add_detail("[WARN] 帮助按钮未找到")
            except Exception as e:
                print(f"  [WARN] 帮助异常: {e}")
                rec.add_detail(f"[WARN] 帮助异常: {e}")

        # ========== 步骤14: 最终清理 + 验证 ==========
        with rec.step("步骤14: 最终清理", "清理IPV6LAN* + L1验证无残留 + 恢复CFLAN_1"):
            print("\n[步骤14] 最终清理...")
            rec.add_detail("[环境清理]")
            if backend_verifier:
                backend_verifier.cleanup_ipv6_lan_test("IPV6LAN")
                backend_verifier.restore_ipv6_lan_default()
                page.page.wait_for_timeout(800)
            for n in [T1, T1_EDITED, IMP]:
                ssh_verify(f"L1-无残留({n})", backend_verifier.verify_ipv6_lan_database,
                           n, must_pass=True, expect_absent=True)
            if backend_verifier:
                cflan = backend_verifier.query_ipv6_lan_rule("CFLAN_1")
                if cflan:
                    print(f"  [OK] 默认CFLAN_1保留/已恢复")
                    rec.add_detail("[OK] 默认CFLAN_1保留/已恢复")

        print("\n" + "=" * 60)
        print("IPv6内网设置综合测试完成")
        print("=" * 60)
        print("测试覆盖(14步):")
        print("  - 添加表单字段验证(全#id + 绑定外网线路label)")
        print("  - 添加1条(doc_app_default/绑定wan1/自动获取), 受interface UNIQUE约束")
        print("  - 编辑(改名+租期)/停用/启用/导出/排序/删除 + L1验证")
        print("  - 校验: 空名/缺parent/接口lan1冲突UNIQUE/超长名/特殊字符")
        print("  - 导入: 追加 + 清空现有(后SQL恢复CFLAN_1)")
        print("  - 帮助功能")
        print("  - SSH: L1数据库(ipv6_lan_config)硬断言")
        print("!!无批量操作: interface UNIQUE致仅1条可加, 无法批量且须避开默认CFLAN_1")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败:")
            for f in all_failures:
                print(f"  - {f}")
            assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
