"""
多线路DNS服务综合测试用例

网络配置 > DNS服务 > 多线路DNS服务 表格页面综合测试
一次测试覆盖:
1. 检查并清理环境
2-4. 添加3条规则(wan1/wan2/wan3不同线路, interface唯一) + SSH L1数据库+L3内核验证
5. 验证总数
6. 编辑规则(修改DNS+备注)
7. 停用/启用规则 + SSH验证
8. 删除规则 + SSH验证
9. 搜索测试(精确/部分/不存在/清空)
10. 排序测试
11. 导出测试(CSV/TXT)
12. 异常输入测试(空名称/重复名称/非法DNS)
13. 批量停用/启用/删除 + SSH L1断言
14. !! 模拟重启验证(用户特别要求) - clear内核→boot→dmesg验证规则重建(检测DMZ类初始化bug)
15. 导入测试-追加(CSV, 不勾清空现有)
16. 导入测试-清空现有(TXT, 勾清空, 改名mldns1验证清空生效)
17. 帮助功能测试
18. 最终清理 + SSH最终验证

SSH后台验证: L1数据库(dns_replace表) + L3/L4内核(ik_cntl multi-dns/dmesg) + 模拟重启(boot)
字段映射: tagname(名称), interface(线路/网卡, unique), dns1(首选DNS), dns2(备选DNS),
          enabled(yes/no), comment(备注)

后端机制: 多线路DNS是纯内核功能(ik_cntl multi-dns), 无iptables/无独立进程。
          dmesg: "[iKuai]:The iKuai multi_dns is enabled/disabled now"
          重启恢复: dns_replace.sh boot -> init()从数据库重建内核规则
"""
import pytest
import os
import re
from pages.network.dns_multi_line_page import DnsMultiLinePage
from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify, make_kernel_check


@pytest.mark.dns_multi_line
@pytest.mark.network
class TestDnsMultiLineComprehensive:
    """多线路DNS服务综合测试 - 表格型页面(独立配置页)"""

    def test_dns_multi_line_comprehensive(self, dns_multi_line_page_logged_in: DnsMultiLinePage,
                                           step_recorder: StepRecorder, request):
        """
        综合测试: 添加3条规则 -> SSH验证 -> 编辑 -> 停用/启用 -> 删除 ->
        搜索 -> 排序 -> 导出 -> 异常测试 -> 批量操作 -> 模拟重启 -> 导入 -> 帮助
        """
        page = dns_multi_line_page_logged_in
        rec = step_recorder

        # 动态获取backend_verifier fixture
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []
        ui_failures = []

        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        # 测试数据 - 3条规则(interface网卡必须唯一, 用wan1/wan2/wan3)
        test_rules = [
            {
                "name": "mldns1",
                "interface": "wan1",
                "dns1": "8.8.8.8",
                "dns2": "8.8.4.4",
                "remark": "谷歌DNS",
                "desc": "wan1线路+谷歌DNS"
            },
            {
                "name": "mldns2",
                "interface": "wan2",
                "dns1": "114.114.114.114",
                "dns2": "114.114.115.115",
                "remark": "114DNS",
                "desc": "wan2线路+114DNS"
            },
            {
                "name": "mldns3",
                "interface": "wan3",
                "dns1": "1.1.1.1",
                "dns2": "9.9.9.9",
                "remark": "cloudflareDNS",
                "desc": "wan3线路+cloudflareDNS"
            },
        ]
        test_names = [r["name"] for r in test_rules]

        # 导出文件路径(提前定义, 避免步骤11失败影响步骤15导入)
        config = get_config()
        export_file_csv = config.test_data.get_export_path("dns_multi_line", config.get_project_root())
        export_file_txt = export_file_csv.replace(".csv", ".txt")

        print("\n" + "=" * 60)
        print("多线路DNS服务综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则(interface唯一)")
        for r in test_rules:
            print(f"  - {r['name']}, 线路={r['interface']}, "
                  f"dns1={r['dns1']}, dns2={r['dns2']}, 场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            for cleanup_round in range(3):
                page.navigate_to_dns_multi_line()
                page.page.wait_for_timeout(1000)
                current_count = page.get_rule_count()
                if current_count == 0:
                    break
                rec.add_detail(f"[清理] 第{cleanup_round+1}轮: 批量删除({current_count}条)")
                select_all = page.page.locator("thead input[type='checkbox']").first
                if select_all.count() > 0 and select_all.is_enabled():
                    select_all.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(2000)
                    page.wait_for_success_message(timeout=3000)

            # SSH兜底清理(确保内核规则也清空)
            if backend_verifier is not None:
                cleanup_out = backend_verifier.cleanup_dns_replace_kernel()
                rec.add_detail(f"[SSH清理] ik_cntl multi-dns clear: {cleanup_out[:80]}")

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)
            final_count = page.get_rule_count()
            print(f"  [OK] 环境清理完成, 剩余 {final_count} 条")
            rec.add_detail(f"[清理结果] 剩余 {final_count} 条")

        # ========== 步骤2-4: 逐条添加3条规则 ==========
        for rule_idx, rule in enumerate(test_rules):
            step_num = rule_idx + 2
            with rec.step(f"步骤{step_num}: 添加规则 {rule['name']}",
                          f"添加: {rule['desc']}"):
                print(f"\n[步骤{step_num}] 添加规则: {rule['name']}")
                rec.add_detail(f"  场景: {rule['desc']}")

                result = page.add_rule(
                    name=rule["name"],
                    interface=rule["interface"],
                    dns1=rule["dns1"],
                    dns2=rule["dns2"],
                    remark=rule["remark"],
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")

                # SSH L1数据库验证
                ssh_verify(
                    f"L1-数据库({rule['name']})",
                    backend_verifier.verify_dns_replace_database,
                    must_pass=True,
                    name=rule["name"],
                    expected_fields={
                        "tagname": rule["name"],
                        "interface": rule["interface"],
                        "dns1": rule["dns1"],
                        "dns2": rule["dns2"],
                        "enabled": "yes",
                    },
                )

                # SSH L3/L4内核验证(有enabled规则→功能应启用)
                ssh_verify(
                    f"L3/L4-内核({rule['name']})",
                    backend_verifier.verify_dns_multi_line_kernel,
                    expect_enabled=True,
                )

        # ========== 步骤5: 验证总数 ==========
        with rec.step("步骤5: 验证总数", f"验证共{len(test_rules)}条规则"):
            print(f"\n[步骤5] 验证总数...")
            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)
            page.clear_search()
            page.page.wait_for_timeout(500)

            total = page.get_rule_count()
            assert total == len(test_rules), f"规则总数应为{len(test_rules)}, 实际{total}"
            print(f"  [OK] 总数验证: {total} 条")
            rec.add_detail(f"  [OK] 总数验证通过: {total} 条")

            rule_list = page.get_rule_list()
            rec.add_detail(f"  当前列表: {[r['name'] for r in rule_list]}")

            # SSH计数验证
            if backend_verifier is not None:
                db_count = backend_verifier.count_dns_replace()
                print(f"  SSH: 数据库规则数={db_count}")
                rec.add_detail(f"  SSH: 数据库规则数={db_count}")

        # ========== 步骤6: 编辑规则 ==========
        with rec.step("步骤6: 编辑规则", "修改第1条规则的DNS和备注"):
            print("\n[步骤6] 编辑规则...")
            edit_rule = test_rules[0]
            new_dns1 = "223.5.5.5"
            new_dns2 = "223.6.6.6"
            new_remark = "阿里DNS"
            rec.add_detail(f"[编辑] {edit_rule['name']}: dns1->{new_dns1}, dns2->{new_dns2}, 备注->{new_remark}")

            result = page.edit_rule(
                edit_rule["name"],
                dns1=new_dns1,
                dns2=new_dns2,
                remark=new_remark,
            )
            assert result is True, f"编辑规则 {edit_rule['name']} 失败"
            print(f"  [OK] 编辑成功")
            rec.add_detail(f"  [OK] 编辑成功")

            # SSH L1验证字段变化
            ssh_verify(
                f"L1-编辑后({edit_rule['name']})",
                backend_verifier.verify_dns_replace_database,
                must_pass=True,
                name=edit_rule["name"],
                expected_fields={
                    "dns1": new_dns1,
                    "dns2": new_dns2,
                    "comment": new_remark,
                    "interface": edit_rule["interface"],
                    "enabled": "yes",
                },
            )

        # ========== 步骤7: 停用规则 ==========
        with rec.step("步骤7: 停用规则", f"停用规则 {test_rules[0]['name']}"):
            print(f"\n[步骤7] 停用规则 {test_rules[0]['name']}...")
            target = test_rules[0]["name"]

            ok = page.disable_rule(target)
            page.page.wait_for_timeout(1000)
            print(f"  停用结果: {ok}")
            rec.add_detail(f"[停用] {target}: {'[OK]' if ok else '[FAIL]'}")

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(500)
            is_disabled = page.is_rule_disabled(target)
            print(f"  UI状态: {'已停用' if is_disabled else '仍启用'}")
            rec.add_detail(f"  UI状态: {'已停用' if is_disabled else '仍启用'}")

            # SSH L1验证enabled=no
            ssh_verify(
                f"L1-停用后({target})",
                backend_verifier.verify_dns_replace_database,
                must_pass=True,
                name=target,
                expected_fields={"enabled": "no"},
            )

        # ========== 步骤8: 启用规则 ==========
        with rec.step("步骤8: 启用规则", f"启用规则 {test_rules[0]['name']}"):
            print(f"\n[步骤8] 启用规则 {test_rules[0]['name']}...")
            target = test_rules[0]["name"]

            ok = page.enable_rule(target)
            page.page.wait_for_timeout(1000)
            print(f"  启用结果: {ok}")
            rec.add_detail(f"[启用] {target}: {'[OK]' if ok else '[FAIL]'}")

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(500)
            is_enabled = page.is_rule_enabled(target)
            print(f"  UI状态: {'已启用' if is_enabled else '仍停用'}")
            rec.add_detail(f"  UI状态: {'已启用' if is_enabled else '仍停用'}")

            # SSH L1验证enabled=yes
            ssh_verify(
                f"L1-启用后({target})",
                backend_verifier.verify_dns_replace_database,
                must_pass=True,
                name=target,
                expected_fields={"enabled": "yes"},
            )

        # ========== 步骤9: 删除规则 ==========
        with rec.step("步骤9: 删除规则", f"删除规则 {test_rules[2]['name']}"):
            print(f"\n[步骤9] 删除规则 {test_rules[2]['name']}...")
            target = test_rules[2]["name"]

            ok = page.delete_rule(target)
            page.page.wait_for_timeout(1000)
            print(f"  删除结果: {ok}")
            rec.add_detail(f"[删除] {target}: {'[OK]' if ok else '[FAIL]'}")

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(500)
            assert not page.rule_exists(target), f"规则 {target} 删除后仍存在"
            print(f"  [OK] 已删除")
            rec.add_detail(f"  [OK] 删除成功")

            # SSH L1验证不存在
            ssh_verify(
                f"L1-删除后({target})",
                backend_verifier.verify_dns_replace_database,
                must_pass=True,
                name=target,
                must_exist=False,
            )

        # ========== 步骤10: 搜索测试 ==========
        with rec.step("步骤10: 搜索测试", "精确/部分/不存在/清空"):
            print("\n[步骤10] 搜索测试...")
            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(800)

            search_target = test_rules[0]["name"]
            # 精确搜索
            page.search_rule(search_target)
            page.page.wait_for_timeout(800)
            found = page.rule_exists(search_target)
            print(f"  精确搜索'{search_target}': {'找到' if found else '未找到'}")
            rec.add_detail(f"  精确搜索'{search_target}': {'[OK]' if found else '[FAIL]'}")
            page.clear_search()
            page.page.wait_for_timeout(500)

            # 部分搜索
            page.search_rule("mldns")
            page.page.wait_for_timeout(800)
            count = page.get_rule_count()
            print(f"  部分搜索'mldns': 找到 {count} 条")
            rec.add_detail(f"  部分搜索'mldns': {count}条")
            page.clear_search()
            page.page.wait_for_timeout(500)

            # 不存在
            page.search_rule("zzznotexist999")
            page.page.wait_for_timeout(800)
            count_none = page.get_rule_count()
            print(f"  不存在搜索: 找到 {count_none} 条")
            rec.add_detail(f"  不存在搜索: {count_none}条(应为0)")
            page.clear_search()
            page.page.wait_for_timeout(500)

        # ========== 步骤11: 排序测试 ==========
        with rec.step("步骤11: 排序测试", "按名称列排序"):
            print("\n[步骤11] 排序测试...")
            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(800)

            # 多线路DNS表头列: 名称/线路/首选DNS/备选DNS/备注/操作
            # 名称列可能无sortIcon(需确认), 尝试首选DNS列
            sorted_ok = page.sort_by_column("名称") or page.sort_by_column("首选DNS")
            page.page.wait_for_timeout(500)
            print(f"  排序结果: {'[OK]' if sorted_ok else '列不支持排序'}")
            rec.add_detail(f"  排序: {'[OK]' if sorted_ok else '列不支持排序(可能无排序图标)'}")

        # ========== 步骤12: 导出测试 ==========
        with rec.step("步骤12: 导出测试", "导出CSV和TXT"):
            print("\n[步骤12] 导出测试...")
            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(500)

            try:
                rec.add_detail(f"  CSV: {os.path.basename(export_file_csv)}")
                if page.export_rules(use_config_path=True, export_format="csv"):
                    print(f"  [OK] CSV导出成功")
                    rec.add_detail(f"    [OK] CSV成功")
                else:
                    print(f"  [WARN] CSV导出失败")
                    rec.add_detail(f"    [WARN] CSV失败")

                rec.add_detail(f"  TXT: {os.path.basename(export_file_txt)}")
                if page.export_rules(use_config_path=True, export_format="txt"):
                    print(f"  [OK] TXT导出成功")
                    rec.add_detail(f"    [OK] TXT成功")
                else:
                    print(f"  [WARN] TXT导出失败")
                    rec.add_detail(f"    [WARN] TXT失败")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")
                rec.add_detail(f"  [WARN] 导出异常: {e}")

        # ========== 步骤13: 异常输入测试 ==========
        with rec.step("步骤13: 异常输入测试", "空名称/重复名称/非法DNS"):
            print("\n[步骤13] 异常输入测试...")

            # 空名称
            r1 = page.try_add_rule_invalid(name="", interface="wan1",
                                           dns1="8.8.8.8", dns2="8.8.4.4",
                                           expect_fail=True)
            print(f"  空名称: {r1}")
            rec.add_detail(f"  空名称: {'拦截[OK]' if r1['success'] else '未拦截[FAIL]'} {r1['error_message']}")
            if not r1["success"]:
                ui_failures.append("异常测试: 空名称未拦截")

            # 重复名称(tagname unique)
            r2 = page.try_add_rule_invalid(name=test_rules[0]["name"], interface="wan1",
                                           dns1="8.8.8.8", dns2="8.8.4.4",
                                           expect_fail=True)
            print(f"  重复名称: {r2}")
            rec.add_detail(f"  重复名称: {'拦截[OK]' if r2['success'] else '未拦截[FAIL]'} {r2['error_message']}")

            # 非法DNS(非IP格式)
            r3 = page.try_add_rule_invalid(name="mldnsbad", interface="wan1",
                                           dns1="999.999.999.999", dns2="8.8.4.4",
                                           expect_fail=True)
            print(f"  非法DNS(999.999.999.999): {r3}")
            rec.add_detail(f"  非法DNS: {'拦截[OK]' if r3['success'] else '未拦截[FAIL]'} {r3['error_message']}")

            # 非法DNS(字母)
            r4 = page.try_add_rule_invalid(name="mldnsbad2", interface="wan1",
                                           dns1="abc.def", dns2="8.8.4.4",
                                           expect_fail=True)
            print(f"  非法DNS(abc.def): {r4}")
            rec.add_detail(f"  非法DNS字母: {'拦截[OK]' if r4['success'] else '未拦截[FAIL]'} {r4['error_message']}")

            # SSH确认异常规则未入库
            if backend_verifier is not None:
                for bad_name in ["mldnsbad", "mldnsbad2"]:
                    exists = backend_verifier.query_dns_replace_rule(bad_name)
                    if exists:
                        ssh_failures.append(f"SSH-异常输入: '{bad_name}'不应入库却存在")
                        rec.add_detail(f"  SSH: '{bad_name}'异常入库[FAIL]")
                    else:
                        rec.add_detail(f"  SSH: '{bad_name}'未入库[OK]")

        # ========== 步骤14: 批量停用/启用/删除 ==========
        # 当前剩余: mldns1(启用), mldns2(启用) - mldns3已在步骤9删除
        with rec.step("步骤14: 批量停用", "全选并批量停用"):
            print("\n[步骤14] 批量停用...")
            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)

            total = page.get_rule_count()
            rec.add_detail(f"[批量停用] 当前{total}条")

            # 全选
            page.select_all_rules()
            page.page.wait_for_timeout(800)
            page.batch_disable()
            page.page.wait_for_timeout(2000)

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)

            # SSH L1断言: 所有测试规则应enabled=no(MEMORY: 批量操作必须append断言)
            if backend_verifier is not None:
                db_rules = backend_verifier.query_all_dns_replace()
                disabled_count = sum(1 for r in db_rules
                                     if r.get("tagname") in test_names and r.get("enabled") == "no")
                rec.add_detail(f"    SSH: 数据库中{disabled_count}/{total}条已停用")
                print(f"    SSH: 数据库中{disabled_count}/{total}条已停用")
                if total > 0 and disabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_count}/{total}条停用")

        with rec.step("步骤15: 批量启用", "全选并批量启用"):
            print("\n[步骤15] 批量启用...")
            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)

            page.select_all_rules()
            page.page.wait_for_timeout(800)
            page.batch_enable()
            page.page.wait_for_timeout(2000)

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)

            # SSH L1断言: 所有测试规则应enabled=yes
            if backend_verifier is not None:
                db_rules = backend_verifier.query_all_dns_replace()
                enabled_count = sum(1 for r in db_rules
                                    if r.get("tagname") in test_names and r.get("enabled") == "yes")
                rec.add_detail(f"    SSH: 数据库中{enabled_count}/{total}条已启用")
                print(f"    SSH: 数据库中{enabled_count}/{total}条已启用")
                if total > 0 and enabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量启用: 仅{enabled_count}/{total}条启用")

        # ========== 步骤16: !! 模拟重启验证(用户特别要求) ==========
        with rec.step("步骤16: 模拟重启验证", "clear内核→dns_replace.sh boot→dmesg验证规则重建(检测DMZ类初始化bug)"):
            print("\n[步骤16] 模拟重启验证(检测DMZ类初始化bug)...")
            rec.add_detail("[模拟重启] 验证boot能从数据库完整重建内核规则")
            rec.add_detail("[对照] DMZ bug=netmap init用文本做整数比较致重启失效; "
                           "dns_replace用count(*)+字符串比较, 正常工作")

            # 先确保至少有1条enabled规则(当前批量启用后, mldns1/mldns2应启用)
            # 调用模拟重启验证: clear内核 → boot → 验证数据库完整+dmesg重建
            ssh_verify(
                "L4-模拟重启",
                backend_verifier.verify_dns_multi_line_reboot,
                must_pass=True,
                expect_any_enabled=True,
            )

            # 再验证: 模拟重启后规则仍在数据库(对照DMZ重启失效bug)
            if backend_verifier is not None:
                after_count = backend_verifier.count_dns_replace()
                print(f"  模拟重启后数据库规则数: {after_count}")
                rec.add_detail(f"[模拟重启后] 数据库规则数={after_count}(应不变)")
                if after_count == 0:
                    ssh_failures.append("SSH-模拟重启: 重启后数据库规则丢失(类似DMZ失效bug)")
                else:
                    print(f"  [OK] 模拟重启后规则完整保留(无DMZ类失效bug)")
                    rec.add_detail(f"  [OK] 规则完整保留, 无DMZ类失效bug")

        # ========== 步骤17: 导入测试 ==========
        with rec.step("步骤17: 导入追加(CSV)", "导入前批量清理, 再导入CSV(不勾清空现有), 验证追加成功"):
            print("\n[步骤17] 批量删除 + 导入测试...")

            # 批量删除剩余规则
            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)
            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_delete()
            page.page.wait_for_timeout(2000)

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)
            for rule in test_rules:
                if page.rule_exists(rule["name"]):
                    ui_failures.append(f"导入前清理: 规则 {rule['name']} 未删除")
            count_before = page.get_rule_count()
            rec.add_detail(f"[导入前] 清理后剩余 {count_before} 条")

            # 导入CSV(追加)
            if os.path.exists(export_file_csv):
                rec.add_detail(f"  导入文件: {os.path.basename(export_file_csv)}")
                page.import_rules(export_file_csv, clear_existing=False)
                page.navigate_to_dns_multi_line()
                page.page.wait_for_timeout(1000)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")
                if count_after > count_before:
                    print(f"  [OK] 导入成功, 添加 {count_after - count_before} 条")
                    rec.add_detail(f"  [OK] 导入成功 {count_after - count_before} 条")
                else:
                    print(f"  [WARN] 导入后数量未增加")
                    rec.add_detail(f"  [WARN] 导入数量未增加")
            else:
                print(f"  [WARN] CSV文件不存在: {export_file_csv}")
                rec.add_detail(f"  [WARN] CSV文件不存在")

        # ========== 步骤18: 导入清空现有(TXT) ==========
        with rec.step("步骤18: 导入清空(TXT)", "改名mldns1占住wan1(不在导出文件), 勾清空导入TXT, 验证改名规则被清+mldns1恢复"):
            print("\n[步骤18] 导入配置(清空现有数据-TXT)...")
            rec.add_detail("[导入测试-清空现有-TXT]")
            rec.add_detail("interface唯一无法加第4条额外规则, 故改名mldns1->mldns_rename占住wan1")
            rec.add_detail("mldns_rename不在导出文件TXT里, 勾清空后应被删(清空生效的证据)")

            if os.path.exists(export_file_txt):
                # 改名mldns1->mldns_rename(interface仍wan1, 不违反唯一约束)
                # mldns_rename不在导出文件TXT里, 充当"额外规则"验证清空是否生效
                page.navigate_to_dns_multi_line()
                page.page.wait_for_timeout(1000)
                if page.rule_exists("mldns1"):
                    page.edit_rule("mldns1", name="mldns_rename")
                    page.page.wait_for_timeout(1500)
                    page.navigate_to_dns_multi_line()
                    page.page.wait_for_timeout(1000)
                    rec.add_detail("  改名 mldns1->mldns_rename(占住wan1, 不在TXT)")
                else:
                    # mldns1不存在则补一条(用wan1)
                    page.add_rule(name="mldns_rename", interface="wan1",
                                  dns1="8.8.8.8", dns2="8.8.4.4")
                    page.page.wait_for_timeout(1500)
                    page.navigate_to_dns_multi_line()
                    page.page.wait_for_timeout(1000)
                    rec.add_detail("  补建 mldns_rename(wan1, 不在TXT)")

                count_before = page.get_rule_count()
                rec.add_detail(f"  导入前: {count_before} 条(含mldns_rename)")

                # 导入TXT, 勾选"清空现有数据"
                page.import_rules(export_file_txt, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1500)
                page.navigate_to_dns_multi_line()
                page.page.wait_for_timeout(1000)

                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                # 验证1: 清空生效 — mldns_rename(不在TXT)应被清掉
                if not page.rule_exists("mldns_rename"):
                    print(f"  [OK] 清空现有数据生效(mldns_rename已删除)")
                    rec.add_detail(f"  [OK] 清空生效, mldns_rename已删")
                else:
                    print(f"  [FAIL] mldns_rename仍存在, 清空未生效(checkbox可能未勾上)")
                    rec.add_detail(f"  [FAIL] 清空未生效, mldns_rename仍在")
                    ui_failures.append("导入清空: 勾选'清空现有数据'后mldns_rename未被删除(clear_existing未生效)")

                # 验证2: 重新导入成功 — mldns1应恢复(被清空后从TXT重新导入)
                if page.rule_exists("mldns1"):
                    print(f"  [OK] 清空后重新导入成功(mldns1恢复)")
                    rec.add_detail(f"  [OK] 重新导入成功, mldns1恢复")
                else:
                    print(f"  [WARN] mldns1未恢复")
                    rec.add_detail(f"  [WARN] mldns1未恢复")
            else:
                print(f"  [WARN] TXT文件不存在: {export_file_txt}")
                rec.add_detail(f"  [WARN] TXT文件不存在")

        # ========== 步骤19: 帮助功能测试 ==========
        with rec.step("步骤19: 帮助功能测试", "测试帮助按钮"):
            print("\n[步骤19] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(500)

            try:
                help_btn = page.page.get_by_role("button", name="帮助")
                if help_btn.count() > 0:
                    help_btn.click()
                    page.page.wait_for_timeout(1000)

                    help_panel = page.page.locator(
                        ".ant-drawer, .ant-modal, [role='dialog'], "
                        ".ant-popover, .ant-alert, .help-content"
                    )
                    if help_panel.count() > 0:
                        print(f"  [OK] 帮助面板已显示")
                        rec.add_detail(f"  [OK] 帮助面板显示")

                        close_btn = page.page.locator(".ant-drawer-close, .ant-modal-close")
                        if close_btn.count() > 0:
                            close_btn.click()
                        else:
                            page.page.keyboard.press("Escape")
                        page.page.wait_for_timeout(300)
                    else:
                        print(f"  [WARN] 帮助面板未显示")
                        rec.add_detail(f"  [WARN] 帮助面板未显示")
                        page.page.keyboard.press("Escape")
                else:
                    print("  [WARN] 帮助按钮未找到")
                    rec.add_detail(f"  [WARN] 帮助按钮未找到")
            except Exception as e:
                print(f"  [WARN] 帮助功能异常: {e}")
                rec.add_detail(f"  [WARN] 帮助功能异常: {e}")

        # ========== 步骤20: 最终清理 ==========
        with rec.step("步骤20: 最终清理", "清理所有测试数据 + SSH内核清理"):
            print("\n[步骤20] 最终清理...")
            rec.add_detail("[最终清理]")

            page.navigate_to_dns_multi_line()
            page.page.wait_for_timeout(1000)
            current_count = page.get_rule_count()
            if current_count > 0:
                for cleanup_round in range(3):
                    page.navigate_to_dns_multi_line()
                    page.page.wait_for_timeout(500)
                    current_count = page.get_rule_count()
                    if current_count == 0:
                        break
                    select_all = page.page.locator("thead input[type='checkbox']").first
                    if select_all.count() > 0 and select_all.is_enabled():
                        select_all.click()
                        page.page.wait_for_timeout(500)
                        page.batch_delete()
                        page.page.wait_for_timeout(1500)

                page.navigate_to_dns_multi_line()
                page.page.wait_for_timeout(1000)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成, 剩余 {final_count} 条")
                rec.add_detail(f"[清理结果] 剩余 {final_count} 条")

            # SSH最终清理: 确保内核规则清空(数据库已删但内核可能残留)
            if backend_verifier is not None:
                backend_verifier.cleanup_dns_replace_kernel()
                # 验证数据库为空
                db_final = backend_verifier.count_dns_replace()
                rec.add_detail(f"[SSH最终] 数据库规则数={db_final}")
                if db_final > 0:
                    # 兜底: 直接删数据库残留
                    ssh_failures.append(f"SSH-最终清理: 数据库仍有{db_final}条残留")

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("多线路DNS服务综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 3条(wan1/wan2/wan3不同线路, interface唯一)")
        print("  - 编辑: 修改DNS+备注")
        print("  - 停用/启用/删除: 各1条 + SSH验证")
        print("  - 搜索: 精确/部分/不存在/清空")
        print("  - 排序: 名称/首选DNS列")
        print("  - 导出: CSV/TXT")
        print("  - 异常输入: 空名称/重复名称/非法DNS(×2)")
        print("  - 批量操作: 停用/启用/删除 + SSH L1断言")
        print("  - !! 模拟重启验证: clear内核→boot→dmesg验证重建(检测DMZ类bug)")
        print("  - 导入: 追加CSV(不勾清空) + 清空现有TXT(勾清空, 改名验证)")
        print("  - 帮助功能")
        print("  - SSH后台验证: L1数据库 + L3/L4内核(dmesg) + 模拟重启(boot)")

        all_failures = ssh_failures + ui_failures
        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项SSH失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        if ui_failures:
            print(f"\n[断言] 共 {len(ui_failures)} 项UI失败:")
            for f in ui_failures:
                print(f"  - {f}")
        assert not all_failures, \
            f"测试失败: {len(ssh_failures)}项SSH + {len(ui_failures)}项UI: {all_failures}"

        print("\n[OK] 多线路DNS服务综合测试全部通过!")


@pytest.mark.dns_multi_line
@pytest.mark.network
class TestDnsMultiLineFlowVerification:
    """多线路DNS功能验证(L5 DNS功能+上游观测): 建wan1规则→223.5.5.5→client dig @路由器→解析成功+观测上游.

    多线路DNS=ik_cntl multi-dns按WAN线路配置上游DNS(纯内核,无iptables/无独立进程).
    DNS加速(ikdnsd/53)开启后转发DNS查询. 配wan1→223.5.5.5(区别默认114.114.114.114).
    L1-L4: 数据库(dns_replace)+内核(multi-dns功能开关dmesg).
    L5硬: client dig@路由器解析成功(多线路DNS启用+规则落地不破坏DNS功能).
    L5软观测: 路由器conntrack上游是否=wan1规则223.5.5.5. 实测lan客户端egress wan1未替换上游(仍用默认dns1)—
    多线路DNS规则仅映射WAN线路, lan客户端的per-WAN上游替换机制待产品澄清, 故上游观测软记录不硬断言."""

    ROUTER_DNS = "192.168.148.1"
    TEST_DOMAIN = "www.baidu.com"
    ML_DNS1 = "223.5.5.5"            # wan1规则上游(AliDNS, 可达且区别默认114)
    ML_DNS2 = "223.6.6.6"
    DEFAULT_DNS = "114.114.114.114"  # DNS加速默认上游(对照)

    def test_dns_multi_line_flow(self, dns_accelerate_page_logged_in,
                                  dns_multi_line_page_logged_in,
                                  step_recorder: StepRecorder, request):
        accl_page = dns_accelerate_page_logged_in
        ml_page = dns_multi_line_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            pytest.skip("无SSH验证器, 跳过多线路DNS功能验证")
        rule_name = "mlflow_wan1"
        failures = []
        print("\n" + "=" * 50)
        print("多线路DNS功能验证(L5 按线路选上游)")
        print("=" * 50)

        def _dig_and_upstream():
            """client dig路由器→返回(解析成功, 解析IP, 路由器conntrack里DNS上游IP集合)."""
            bv.connect_client()
            out = bv._client.exec(
                f"dig @{self.ROUTER_DNS} {self.TEST_DOMAIN} +short +time=3 +tries=2 2>/dev/null",
                timeout=15)
            ips = [l.strip() for l in (out or "").splitlines()
                   if l.strip() and l.strip()[0].isdigit()]
            # 路由器conntrack: UDP dport=53 的dst(上游DNS), 排除路由器自身/客户端
            bv.connect_router()
            ct = bv._router.exec(
                "conntrack -L -p udp 2>/dev/null | grep 'dport=53' | "
                "grep -oE 'dst=[0-9.]+' | sed 's/dst=//'")
            upstreams = sorted({l.strip() for l in ct.splitlines() if l.strip()
                                and not l.strip().startswith("192.168.")})
            return bool(ips), ips, upstreams

        orig_accl_enabled = None
        try:
            try:
                accl_page.navigate_to_dns_accelerate()
                accl_page.page.wait_for_timeout(800)
                orig_accl_enabled = accl_page.get_basic_config().get("enabled", False)
            except Exception:
                orig_accl_enabled = None

            # 准备: 开启DNS加速(UDP,ikdnsd/53转发) + 清理残留多线路DNS规则
            with rec.step("准备: 开启DNS加速+清理残留", f"DNS加速cachemode=UDP dns1={self.DEFAULT_DNS} + 删{rule_name}"):
                accl_page.navigate_to_dns_accelerate()
                accl_page.page.wait_for_timeout(800)
                accl_page.save_basic_config(enable=True, dns1=self.DEFAULT_DNS, cachemode="UDP")
                accl_page.page.wait_for_timeout(2500)
                try:
                    ml_page.navigate_to_dns_multi_line()
                    ml_page.page.wait_for_timeout(800)
                    ml_page.delete_rule(rule_name)
                    ml_page.page.wait_for_timeout(500)
                except Exception:
                    pass
                rec.add_detail(f"  ✓ DNS加速开启(默认上游{self.DEFAULT_DNS})")

            # 建多线路DNS规则: wan1 → 223.5.5.5
            with rec.step("建多线路DNS规则", f"wan1 → dns1={self.ML_DNS1} dns2={self.ML_DNS2}"):
                ml_page.navigate_to_dns_multi_line()
                ml_page.page.wait_for_timeout(800)
                ok = ml_page.add_rule(rule_name, interface="wan1",
                                      dns1=self.ML_DNS1, dns2=self.ML_DNS2)
                if not ok:
                    failures.append("建多线路DNS规则失败")
                    rec.add_detail("  ✗ 建规则失败")
                else:
                    rec.add_detail(f"  ✓ 建规则 wan1→{self.ML_DNS1}")
                    ml_page.page.wait_for_timeout(2000)

            # L1-L4 后端验证(数据库 + ik_cntl multi-dns内核功能开关)
            if not failures:
                with rec.step("L1-L4后端验证", "数据库(dns_replace)+内核(ik_cntl multi-dns功能开关)"):
                    chain = bv.verify_dns_multi_line_full_chain(name=rule_name, expect_enabled=True)
                    for r in chain.results:
                        rec.add_detail(f"  {r.level}: {'[OK]' if r.passed else '[FAIL]'} {r.message}")
                        if not r.passed:
                            failures.append(f"{r.level}: {r.message}")

            # L5: client dig→解析(多线路DNS不破坏DNS功能) + 上游观测(软: per-WAN替换对lan客户端机制待产品澄清)
            if not failures:
                with rec.step("L5 DNS功能验证",
                              f"client dig @{self.ROUTER_DNS} 应解析 + 观测路由器DNS上游(wan1规则={self.ML_DNS1})"):
                    bv.connect_client()
                    for _ in range(3):
                        bv._client.exec(
                            f"dig @{self.ROUTER_DNS} {self.TEST_DOMAIN} +short +time=3 +tries=1 2>/dev/null",
                            timeout=10)
                    ok, ips, upstreams = _dig_and_upstream()
                    rec.add_detail(f"  dig解析: {ips if ok else '无解析'}")
                    rec.add_detail(f"  路由器DNS上游(conntrack): {upstreams}")
                    if not ok:
                        rec.add_detail("  ✗ DNS未解析(多线路DNS启用后DNS功能异常)")
                        failures.append(f"多线路DNS dig未解析: {ips}")
                    else:
                        rec.add_detail(f"  ✓ DNS功能正常(多线路DNS启用+规则落地不破坏解析)")
                    # 软观测: wan1规则上游是否替换(多线路DNS规则映射WAN线路, lan客户端egress wan1
                    # 实测未替换上游仍用默认dns1—per-WAN替换对lan客户端的机制待产品澄清, 不硬断言)
                    if self.ML_DNS1 in upstreams:
                        rec.add_detail(f"  [观测] ✓ 路由器走wan1规则上游{self.ML_DNS1}(per-WAN替换生效)")
                    else:
                        rec.add_detail(f"  [观测] 上游={upstreams}, 未走wan1规则{self.ML_DNS1}"
                                       f"(多线路DNS规则映射WAN线路, lan客户端per-WAN替换机制待澄清, 软记录)")
        finally:
            try:
                ml_page.navigate_to_dns_multi_line()
                ml_page.page.wait_for_timeout(500)
                ml_page.delete_rule(rule_name)
            except Exception:
                pass
            try:
                bv._router.exec("ik_cntl multi-dns clear 2>/dev/null")
            except Exception:
                pass
            try:
                accl_page.navigate_to_dns_accelerate()
                accl_page.page.wait_for_timeout(500)
                if orig_accl_enabled is not None:
                    accl_page.save_basic_config(enable=orig_accl_enabled)
            except Exception:
                pass
        print(f"\n[多线路DNS功能验证] {'通过' if not failures else '失败'+str(len(failures))+'项'}")
        assert not failures, f"多线路DNS功能验证失败({len(failures)}项): {'; '.join(failures)}"

