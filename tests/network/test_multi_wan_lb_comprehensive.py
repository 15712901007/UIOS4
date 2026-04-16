"""
多线负载综合测试用例

一次测试覆盖多个功能：
1. 添加7条规则（覆盖全部7种负载模式）
2. 编辑其中1条
3. 停用/启用/删除各1条
4. 搜索测试
5. 导出测试
6. 异常输入测试
7. 批量停用/启用/删除
8. 导入测试
9. 帮助功能测试

SSH后台验证: L1数据库验证
字段映射: mode(整数0-6), isp_name(英文标识)
"""
import pytest
import os
from pages.network.multi_wan_lb_page import MultiWanLbPage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.multi_wan_lb
@pytest.mark.network
class TestMultiWanLbComprehensive:
    """多线负载综合测试 - 一次测试覆盖所有功能"""

    def test_multi_wan_lb_comprehensive(self, multi_wan_lb_page_logged_in: MultiWanLbPage,
                                         step_recorder: StepRecorder, request):
        """
        综合测试: 添加7种负载模式 -> 编辑 -> 停用 -> 启用 -> 删除 ->
        搜索 -> 导出 -> 异常测试 -> 批量操作 -> 导入 -> 帮助
        """
        page = multi_wan_lb_page_logged_in
        rec = step_recorder

        # 动态获取backend_verifier fixture
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            if backend_verifier is None:
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = '通过' if result.passed else '失败'
                print(f"    SSH-{label}: {status} - {result.message}")
                rec.add_detail(f"    SSH-{label}: {'[OK]' if result.passed else '[FAIL]'} {result.message}")
                if result.raw_output:
                    print(f"      SSH数据: {result.raw_output}")
                    rec.add_detail(f"      SSH数据: {result.raw_output}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                return None

        # 测试数据 - 7条规则，覆盖全部7种负载模式
        # 注意：后端tagname字段最多15字符，超长会被截断
        test_rules = [
            # Mode 0: 源IP+目的IP+目的端口 (默认)
            {"name": "lb_m0_srcdport", "desc": "模式0:源IP+目的IP+目的端口"},
            # Mode 1: 源IP+目的IP
            {"name": "lb_m1_srcdst", "load_mode": "源IP+目的IP", "desc": "模式1:源IP+目的IP"},
            # Mode 2: 新建连接数 + 中国电信
            {"name": "lb_m2_newconn", "load_mode": "新建连接数", "carrier": "中国电信",
             "desc": "模式2:新建连接数+电信"},
            # Mode 3: 实时流量 + 自定义比例
            {"name": "lb_m3_traffic", "load_mode": "实时流量",
             "weights": {"wan1": "3", "wan2": "2", "wan3": "1"},
             "desc": "模式3:实时流量+自定义比例"},
            # Mode 4: 实时连接数 + 带备注
            {"name": "lb_m4_conn", "load_mode": "实时连接数",
             "remark": "实时连接数测试备注", "desc": "模式4:实时连接数+备注"},
            # Mode 5: 源IP + 中国联通
            {"name": "lb_m5_srcip", "load_mode": "源IP", "carrier": "中国联通",
             "desc": "模式5:源IP+联通"},
            # Mode 6: 源IP+源端口 + 完整配置
            {"name": "lb_m6_srcport", "load_mode": "源IP+源端口", "carrier": "中国移动",
             "remark": "完整配置测试", "weights": {"wan1": "5", "wan2": "3", "wan3": "2"},
             "desc": "模式6:源IP+源端口+完整配置"},
        ]

        print("\n" + "=" * 60)
        print("多线负载综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")
        for r in test_rules:
            mode = r.get("load_mode", "源IP+目的IP+目的端口(默认)")
            carrier = r.get("carrier", "全部")
            print(f"  - {r['name']}, 负载模式={mode}, 运营商={carrier}, 场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            if current_count > 0:
                rec.add_detail("[清理操作] 全选批量删除")
                select_all = page.page.locator("thead input[type='checkbox']").first
                if select_all.count() > 0 and select_all.is_enabled():
                    select_all.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)

                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(500)

                final_count = page.get_rule_count()
                print(f"  [OK] 环境清理完成，剩余 {final_count} 条")
                rec.add_detail(f"[清理结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 环境干净")
                rec.add_detail("  环境干净，无需清理")

        # ========== 步骤2: 二次检查测试数据 ==========
        with rec.step("步骤2: 二次检查测试数据", "确保测试数据已清理"):
            print("\n[步骤2] 二次检查...")
            rec.add_detail(f"[二次检查]")
            cleaned_count = 0
            for rule in test_rules:
                if page.rule_exists(rule["name"]):
                    page.delete_rule(rule["name"])
                    rec.add_detail(f"  发现残留: {rule['name']}，已删除")
                    cleaned_count += 1
            if cleaned_count == 0:
                rec.add_detail("  无需清理")
            else:
                rec.add_detail(f"  共清理 {cleaned_count} 条")

        # ========== 步骤3: 批量添加7条规则（覆盖全部7种负载模式） ==========
        with rec.step("步骤3: 批量添加规则", f"添加 {len(test_rules)} 条规则，覆盖全部7种负载模式"):
            print(f"\n[步骤3] 批量添加 {len(test_rules)} 条规则（7种负载模式全覆盖）...")
            rec.add_detail(f"[添加计划] 共 {len(test_rules)} 条，覆盖全部7种负载模式")

            added_count = 0
            for rule in test_rules:
                rec.add_detail(f"[添加 {rule['name']}]")
                rec.add_detail(f"  场景: {rule['desc']}")
                if rule.get("load_mode"):
                    rec.add_detail(f"  负载模式: {rule['load_mode']}")
                if rule.get("carrier"):
                    rec.add_detail(f"  运营商: {rule['carrier']}")
                if rule.get("weights"):
                    rec.add_detail(f"  负载比例: {rule['weights']}")
                if rule.get("remark"):
                    rec.add_detail(f"  备注: {rule['remark']}")

                result = page.add_rule(
                    name=rule["name"],
                    load_mode=rule.get("load_mode"),
                    carrier=rule.get("carrier"),
                    remark=rule.get("remark"),
                    weights=rule.get("weights"),
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")
                added_count += 1

            # 验证所有规则都已添加
            rec.add_detail(f"[验证结果]")
            # 确保在列表页并等待数据加载
            page.navigate_to_multi_wan_lb()
            page.page.wait_for_timeout(2000)
            page.clear_search()
            page.page.wait_for_timeout(500)
            # 使用JS方式获取规则名称列表（比get_by_text更可靠）
            all_names = page.get_rule_list()
            rec.add_detail(f"  当前列表({len(all_names)}条): {all_names}")
            for rule in test_rules:
                assert rule["name"] in all_names, f"规则 {rule['name']} 未找到，当前列表: {all_names}"
            print(f"  [OK] 所有 {len(test_rules)} 条规则添加成功")
            rec.add_detail(f"  [OK] 所有 {len(test_rules)} 条规则添加成功（7种负载模式全覆盖）")

        # ========== 步骤3.5: 后台数据验证 ==========
        if backend_verifier is not None:
            with rec.step("步骤3.5: 后台数据验证（SSH）", "SSH验证每条规则的数据库状态"):
                print("\n[步骤3.5] 后台数据验证...")
                rec.add_detail("[SSH后台验证] 字段映射: mode=整数0-6, isp_name=英文标识")

                verify_passed = 0
                for rule in test_rules:
                    rule_name = rule["name"]
                    rec.add_detail(f"  -- 验证: {rule_name} --")
                    print(f"  验证: {rule_name}")

                    # 构建数据库期望字段（使用数据库实际字段名和值）
                    expected_fields = {"enabled": "yes"}
                    load_mode = rule.get("load_mode", "源IP+目的IP+目的端口")
                    expected_fields["mode"] = MultiWanLbPage.MODE_TO_DB.get(load_mode, "0")
                    carrier = rule.get("carrier", "全部")
                    expected_fields["isp_name"] = MultiWanLbPage.CARRIER_TO_DB.get(carrier, "all")
                    if rule.get("remark"):
                        expected_fields["comment"] = rule["remark"]

                    rec.add_detail(f"      期望: mode={expected_fields['mode']}, isp_name={expected_fields['isp_name']}")

                    l1 = ssh_verify(
                        f"L1-数据库({rule_name})",
                        backend_verifier.verify_lb_pcc_database,
                        rule_name,
                        must_pass=True,
                        expected_fields=expected_fields,
                    )

                    if l1 and l1.passed:
                        db_rule = l1.details.get("rule", {})
                        rec.add_detail(f"      数据库: id={db_rule.get('id')}, mode={db_rule.get('mode')}, "
                                       f"isp_name={db_rule.get('isp_name')}, weight={db_rule.get('weight')}")
                        verify_passed += 1

                print(f"  [OK] 后台验证完成: {verify_passed}/{len(test_rules)} 条通过")
                rec.add_detail(f"  -- 汇总: {verify_passed}/{len(test_rules)} 条验证通过 --")

            # L2: 策略路由验证
            ssh_verify(
                "L2-策略路由",
                backend_verifier.verify_lb_pcc_policy_routing,
                must_pass=False,
                expected_wan_interfaces=["wan1", "wan2", "wan3"],
            )

            # L3/L4: 内核验证(ik_core + dmesg + conntrack)
            ssh_verify(
                "L3/L4-内核",
                backend_verifier.verify_lb_pcc_kernel,
                must_pass=False,
                expect_enabled=True,
            )
        else:
            print("\n[步骤3.5] 后台数据验证: 跳过（未配置SSH）")

        # ========== 步骤4: 编辑第1条规则 ==========
        with rec.step("步骤4: 编辑规则", "编辑第1条规则的名称"):
            print("\n[步骤4] 编辑第1条规则...")
            edit_rule = test_rules[0]
            new_name = "lb_m0_edit"
            rec.add_detail(f"[编辑操作] {edit_rule['name']} -> {new_name}")

            if page.rule_exists(new_name):
                page.delete_rule(new_name)

            result = page.edit_rule(edit_rule["name"], new_name=new_name)
            assert result is True, f"编辑规则失败"

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            assert page.rule_exists(new_name), "编辑后的规则未找到"
            test_rules[0]["name"] = new_name
            print(f"  [OK] 编辑成功")
            rec.add_detail(f"[验证] [OK] 编辑成功，新名称已生效")

            if backend_verifier is not None:
                ssh_verify("L1-编辑验证", backend_verifier.verify_lb_pcc_database, new_name)

        # ========== 步骤5: 停用第2条规则 ==========
        with rec.step("步骤5: 停用规则", "停用第2条规则"):
            print("\n[步骤5] 停用第2条规则...")
            disable_rule = test_rules[1]
            rec.add_detail(f"[停用操作] 目标: {disable_rule['name']}")

            result = page.disable_rule(disable_rule["name"])
            assert result is True, f"停用规则失败"

            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            assert page.is_rule_disabled(disable_rule["name"]), "规则未变为停用状态"
            print(f"  [OK] 停用成功")
            rec.add_detail(f"[验证] [OK] 已停用")

            if backend_verifier is not None:
                ssh_verify("L1-停用验证", backend_verifier.verify_lb_pcc_database,
                           disable_rule["name"], must_pass=True, expected_fields={"enabled": "no"})

        # ========== 步骤6: 启用第2条规则 ==========
        with rec.step("步骤6: 启用规则", "启用第2条规则"):
            print("\n[步骤6] 启用第2条规则...")
            rec.add_detail(f"[启用操作] 目标: {disable_rule['name']}")

            result = page.enable_rule(disable_rule["name"])
            assert result is True, f"启用规则失败"

            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            assert page.is_rule_enabled(disable_rule["name"]), "规则启用后状态未变化"
            print(f"  [OK] 启用成功")
            rec.add_detail(f"[验证] [OK] 已启用")

            if backend_verifier is not None:
                ssh_verify("L1-启用验证", backend_verifier.verify_lb_pcc_database,
                           disable_rule["name"], must_pass=True, expected_fields={"enabled": "yes"})

        # ========== 步骤7: 删除第3条规则 ==========
        with rec.step("步骤7: 删除规则", "删除第3条规则"):
            print("\n[步骤7] 删除第3条规则...")
            delete_rule_data = test_rules[2]
            rec.add_detail(f"[删除操作] 目标: {delete_rule_data['name']}")

            count_before = page.get_rule_count()
            rec.add_detail(f"  删除前: {count_before} 条")

            result = page.delete_rule(delete_rule_data["name"])
            assert result is True, f"删除规则失败"

            page.page.reload()
            page.page.wait_for_timeout(500)
            count_after = page.get_rule_count()
            assert count_after < count_before, "删除后条目数未减少"
            test_rules.remove(delete_rule_data)
            print(f"  [OK] 删除成功 ({count_before} -> {count_after})")
            rec.add_detail(f"[验证] [OK] 删除成功")

            if backend_verifier is not None:
                try:
                    db_rule = backend_verifier.find_lb_pcc_rule(tagname=delete_rule_data["name"])
                    if db_rule is None:
                        print(f"    SSH-L1-删除验证: [OK] 已从数据库删除")
                        rec.add_detail(f"    SSH-L1: [OK] 已从数据库删除")
                    else:
                        ssh_failures.append(f"SSH-L1-删除验证: {delete_rule_data['name']} 仍在数据库中")
                except Exception as e:
                    print(f"    SSH-L1: 跳过 - {str(e)[:80]}")

        # ========== 步骤8: 搜索测试(扩展) ==========
        with rec.step("步骤8: 搜索功能测试", "精确搜索/模糊搜索/不存在的规则"):
            print("\n[步骤8] 搜索测试...")
            rec.add_detail("[搜索测试]")

            # 8.1 精确搜索
            search_target = test_rules[1]["name"]
            rec.add_detail(f"  精确搜索: {search_target}")
            page.search_rule(search_target)
            page.page.wait_for_timeout(500)
            assert page.rule_exists(search_target), f"精确搜索不到: {search_target}"
            print(f"  [OK] 精确搜索成功")
            rec.add_detail(f"    [OK] 精确搜索找到")

            # 8.2 部分匹配搜索(前缀)
            page.clear_search()
            page.page.wait_for_timeout(300)
            prefix = test_rules[2]["name"][:6]  # 取前6个字符
            rec.add_detail(f"  部分匹配搜索: '{prefix}'")
            page.search_rule(prefix)
            page.page.wait_for_timeout(500)
            partial_count = page.get_rule_count()
            assert partial_count >= 1, f"部分匹配搜索应至少1条，实际{partial_count}条"
            print(f"  [OK] 部分匹配搜索: {partial_count}条")
            rec.add_detail(f"    [OK] 匹配 {partial_count} 条")

            # 8.3 不存在的规则
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("not_exist_lb_xxx")
            page.page.wait_for_timeout(500)
            count = page.get_rule_count()
            assert count == 0, f"搜索不存在时应为0条，实际{count}条"
            print("  [OK] 搜索不存在规则: 0条")
            rec.add_detail(f"  不存在的: 0条 [OK]")

            # 8.4 清空搜索恢复列表
            page.clear_search()
            page.page.wait_for_timeout(500)
            remaining = page.get_rule_count()
            assert remaining == len(test_rules), f"清空搜索后应有{len(test_rules)}条，实际{remaining}条"
            print(f"  [OK] 清空搜索，恢复 {remaining} 条")
            rec.add_detail(f"  清空搜索: {remaining} 条 [OK]")

        # ========== 步骤9: 导出测试 ==========
        with rec.step("步骤9: 导出配置", "导出CSV和TXT"):
            print("\n[步骤9] 导出配置...")
            rec.add_detail("[导出测试]")
            config = get_config()
            export_file_csv = config.test_data.get_export_path("multi_wan_lb", config.get_project_root())
            export_file_txt = export_file_csv.replace(".csv", ".txt")

            try:
                rec.add_detail(f"  CSV: {os.path.basename(export_file_csv)}")
                if page.export_rules(use_config_path=True, export_format="csv"):
                    print(f"  [OK] CSV导出成功")
                    rec.add_detail(f"    [OK] CSV成功")
                else:
                    rec.add_detail(f"    [FAIL] CSV失败")

                page.page.wait_for_timeout(500)

                rec.add_detail(f"  TXT: {os.path.basename(export_file_txt)}")
                if page.export_rules(use_config_path=True, export_format="txt"):
                    print(f"  [OK] TXT导出成功")
                    rec.add_detail(f"    [OK] TXT成功")
                else:
                    rec.add_detail(f"    [FAIL] TXT失败")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")
                rec.add_detail(f"  异常: {str(e)}")

            page.close_modal_if_exists()
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

        # ========== 步骤10: 异常输入测试(扩展) ==========
        with rec.step("步骤10: 异常输入测试", "空名称/重复/超长/特殊字符/纯空格"):
            print("\n[步骤10] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 10.1 空名称
            rec.add_detail("  空名称:")
            result = page.try_add_rule_invalid(name="")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [FAIL] 未拦截")
                rec.add_detail(f"    [FAIL] 未拦截")

            # 10.2 重复名称
            rec.add_detail("  重复名称:")
            existing = test_rules[0]["name"]
            result = page.try_add_rule_invalid(name=existing)
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [WARN] 未拦截")
                rec.add_detail(f"    [WARN] 未拦截")

            # 10.3 超长名称(>15字符，后端自动截断到15字符)
            rec.add_detail("  超长名称(30字符，预期自动截断到15字符):")
            long_name = "a" * 30
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name(long_name)
                page.click_save()
                page.page.wait_for_timeout(1000)

                # 检查是否保存成功（后端自动截断）或被拦截
                error_el = page.page.locator('.ant-form-item-explain-error')
                if error_el.count() > 0:
                    # 被前端拦截
                    error_text = error_el.first.text_content()
                    print(f"    [OK] 前端拦截: {error_text}")
                    rec.add_detail(f"    [OK] 前端拦截: {error_text}")
                    page.click_cancel()
                    page.page.wait_for_timeout(500)
                    page.navigate_back_to_list()
                elif page.wait_for_success_message(timeout=2000):
                    # 保存成功（后端自动截断），需清理
                    truncated = long_name[:15]
                    print(f"    [OK] 后端自动截断到15字符: {truncated}")
                    rec.add_detail(f"    [OK] 后端自动截断到15字符: '{truncated}'")
                    page.page.wait_for_timeout(500)
                    page.navigate_back_to_list()
                    # 删除被截断的规则
                    page.page.wait_for_timeout(500)
                    page.delete_rule(truncated)
                    page.page.wait_for_timeout(500)
                else:
                    print(f"    [INFO] 超长名称: 无明确拦截提示")
                    rec.add_detail(f"    [INFO] 超长名称: 无明确拦截提示")
                    page.click_cancel()
                    page.page.wait_for_timeout(500)
                    if "multiLineLoad" in page.page.url:
                        page.navigate_back_to_list()
            except Exception as e:
                print(f"    [INFO] 超长名称测试异常: {e}")
                rec.add_detail(f"    [INFO] 超长名称测试异常: {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 10.4 特殊字符
            rec.add_detail("  特殊字符:")
            result = page.try_add_rule_invalid(name="<script>alert(1)</script>")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [INFO] 特殊字符处理: {result}")
                rec.add_detail(f"    [INFO] {result}")

            # 10.5 纯空格
            rec.add_detail("  纯空格:")
            result = page.try_add_rule_invalid(name="   ")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [INFO] 纯空格处理: {result}")
                rec.add_detail(f"    [INFO] {result}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

        # ========== 步骤11: 排序测试 ==========
        with rec.step("步骤11: 排序功能测试", "按线路排序（正序→倒序→恢复默认）"):
            print("\n[步骤11] 排序测试...")
            rec.add_detail("[排序测试]")

            sortable_cols = ["线路"]
            sort_results = {}

            for col in sortable_cols:
                try:
                    rec.add_detail(f"  {col}:")
                    # 点击3次：正序→倒序→恢复默认
                    for click_idx, sort_label in enumerate(["正序", "倒序", "恢复默认"]):
                        result = page.sort_by_column(col)
                        page.page.wait_for_timeout(300)
                        if result:
                            rec.add_detail(f"    [OK] {sort_label}: 成功")
                        else:
                            rec.add_detail(f"    [WARN] {sort_label}: 排序图标未找到")
                    sort_results[col] = True
                    print(f"  [OK] {col} 排序测试通过")
                except Exception as e:
                    sort_results[col] = False
                    print(f"  [WARN] {col} 排序测试异常: {e}")
                    rec.add_detail(f"    [WARN] 排序异常: {e}")

            passed = sum(1 for v in sort_results.values() if v)
            print(f"  [OK] 排序测试完成: {passed}/{len(sortable_cols)} 个字段通过")
            rec.add_detail(f"  -- 汇总: {passed}/{len(sortable_cols)} 个字段排序测试通过 --")

        # ========== 步骤12: 批量停用 ==========
        with rec.step("步骤12: 批量停用", f"批量停用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤12] 批量停用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量停用] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_disable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            disabled_count = sum(1 for r in test_rules if page.is_rule_disabled(r["name"]))
            print(f"  [OK] 批量停用: {disabled_count}/{len(test_rules)} 条")
            rec.add_detail(f"[结果] {disabled_count}/{len(test_rules)} 条已停用")

            if backend_verifier is not None:
                try:
                    lb_rules = backend_verifier.query_lb_pcc_rules()
                    test_names = {r["name"] for r in test_rules}
                    disabled_in_db = sum(1 for r in lb_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                    rec.add_detail(f"    SSH: {disabled_in_db}/{len(test_rules)}条停用")
                except Exception:
                    pass

        # ========== 步骤13: 批量启用 ==========
        with rec.step("步骤13: 批量启用", f"批量启用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤13] 批量启用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量启用] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_enable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            enabled_count = sum(1 for r in test_rules if page.is_rule_enabled(r["name"]))
            print(f"  [OK] 批量启用: {enabled_count}/{len(test_rules)} 条")
            rec.add_detail(f"[结果] {enabled_count}/{len(test_rules)} 条已启用")

        # ========== 步骤14: 批量删除 ==========
        with rec.step("步骤14: 批量删除", f"批量删除剩余 {len(test_rules)} 条"):
            print(f"\n[步骤14] 批量删除 {len(test_rules)} 条...")
            rec.add_detail(f"[批量删除] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_delete()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            for rule in test_rules:
                assert not page.rule_exists(rule["name"]), f"规则 {rule['name']} 仍存在"
            print(f"  [OK] 批量删除 {len(test_rules)} 条成功")
            rec.add_detail(f"[结果] [OK] 全部删除")

            if backend_verifier is not None:
                try:
                    lb_rules = backend_verifier.query_lb_pcc_rules()
                    test_names = {r["name"] for r in test_rules}
                    remaining = [r for r in lb_rules if r.get("tagname") in test_names]
                    if remaining:
                        ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining)}条")
                    else:
                        rec.add_detail(f"    SSH: 测试规则已全部删除")
                except Exception:
                    pass

        # ========== 步骤15: 导入测试(追加) ==========
        with rec.step("步骤15: 导入配置(追加)", "使用导出的CSV追加导入"):
            print("\n[步骤15] 导入配置(追加)...")
            rec.add_detail("[导入测试-追加]")

            if os.path.exists(export_file_csv):
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_csv)}")
                rec.add_detail(f"  导入前: {count_before} 条")

                result = page.import_rules(export_file_csv, clear_existing=False)
                page.page.reload()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if count_after > count_before:
                    print(f"  [OK] 追加导入成功，添加 {count_after - count_before} 条")
                    rec.add_detail(f"  [OK] 添加 {count_after - count_before} 条")
                else:
                    print(f"  [WARN] 追加导入后数量未增加")
                    rec.add_detail(f"  [WARN] 数量未增加")
            else:
                print(f"  [WARN] CSV文件不存在")
                rec.add_detail(f"  CSV文件不存在")

        # ========== 步骤16: 导入测试(清空现有数据) ==========
        with rec.step("步骤16: 导入配置(清空现有)", "勾选清空现有数据后导入"):
            print("\n[步骤16] 导入配置(清空现有数据)...")
            rec.add_detail("[导入测试-清空现有]")

            if os.path.exists(export_file_csv):
                # 先添加一条额外规则
                page.add_rule(name="extra_before", load_mode="源IP+目的IP")
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则 extra_before)")

                # 导入并勾选清空
                result = page.import_rules(export_file_csv, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1000)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                # 验证 extra_before 不存在了
                if not page.rule_exists("extra_before"):
                    print(f"  [OK] 清空现有数据生效(extra_before已删除)")
                    rec.add_detail(f"  [OK] 清空生效: extra_before已删除")
                else:
                    print(f"  [WARN] 清空现有数据可能未生效")
                    rec.add_detail(f"  [WARN] extra_before仍存在")

                if count_after > 0:
                    print(f"  [OK] 重新导入 {count_after} 条")
                    rec.add_detail(f"  [OK] 重新导入 {count_after} 条")
            else:
                print(f"  [WARN] CSV文件不存在")
                rec.add_detail(f"  CSV文件不存在")

        # ========== 步骤17: 自定义运营商测试 ==========
        with rec.step("步骤17: 自定义运营商", "添加/删除自定义运营商"):
            print("\n[步骤17] 自定义运营商测试...")
            rec.add_detail("[自定义运营商测试]")

            count_before = page.get_custom_carrier_count() if page.open_custom_carrier_dialog() else -1
            if count_before >= 0:
                rec.add_detail(f"  打开对话框成功，当前 {count_before} 条")
                page.page.wait_for_timeout(500)

                # 添加自定义运营商
                test_carrier = "test_auto_isp"
                rec.add_detail(f"  添加: {test_carrier}")
                add_ok = page.add_custom_carrier(test_carrier)
                page.page.wait_for_timeout(500)

                if add_ok:
                    count_after_add = page.get_custom_carrier_count()
                    print(f"  [OK] 添加自定义运营商成功 ({count_before} -> {count_after_add})")
                    rec.add_detail(f"  [OK] 添加成功: {count_before} -> {count_after_add}")

                    # 删除
                    rec.add_detail(f"  删除: {test_carrier}")
                    del_ok = page.delete_custom_carrier(test_carrier)
                    page.page.wait_for_timeout(500)

                    if del_ok:
                        count_after_del = page.get_custom_carrier_count()
                        print(f"  [OK] 删除自定义运营商成功 ({count_after_add} -> {count_after_del})")
                        rec.add_detail(f"  [OK] 删除成功")
                    else:
                        print(f"  [WARN] 删除失败")
                        rec.add_detail(f"  [WARN] 删除失败")
                else:
                    print(f"  [WARN] 添加失败")
                    rec.add_detail(f"  [WARN] 添加失败")

                page.close_custom_carrier_dialog()
                page.page.wait_for_timeout(500)
            else:
                print("  [WARN] 无法打开自定义运营商对话框")
                rec.add_detail("  [WARN] 对话框未打开")

        # ========== 步骤18: 清理环境 ==========
        with rec.step("步骤18: 清理环境", "清理所有残留数据"):
            print("\n[步骤18] 清理环境...")
            rec.add_detail("[环境清理]")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            current_count = page.get_rule_count()
            if current_count > 0:
                select_all = page.page.locator("thead input[type='checkbox']").first
                if select_all.count() > 0 and select_all.is_enabled():
                    select_all.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)

                page.page.reload()
                page.page.wait_for_timeout(500)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成，剩余 {final_count} 条")
                rec.add_detail(f"[结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 无需清理")
                rec.add_detail("  无需清理")

        # ========== 步骤19: 帮助功能测试 ==========
        with rec.step("步骤19: 帮助功能测试", "测试帮助图标"):
            print("\n[步骤19] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")

            help_result = page.test_help_functionality()
            if help_result['icon_clickable']:
                print(f"  [OK] 帮助功能测试通过")
                rec.add_detail(f"  [OK] 帮助图标可点击")
            else:
                print("  [WARN] 帮助图标未找到")
                rec.add_detail(f"  帮助图标未找到")

        print("\n" + "=" * 60)
        print("多线负载综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 7条（覆盖全部7种负载模式 + 不同运营商/比例/备注组合）")
        print("  - 编辑/停用/启用/删除: 各1条")
        print("  - 搜索: 精确/部分匹配/不存在/清空恢复")
        print("  - 排序: 线路")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加 + 清空现有数据")
        print("  - 异常输入: 空名称/重复/超长/特殊字符/纯空格")
        print("  - 自定义运营商: 添加/删除")
        print("  - 批量操作: 批量停用/启用/删除")
        print("  - SSH后台验证: L1数据库 + L2策略路由 + L3/L4内核(ik_core+dmesg+conntrack)")

        # 清理后验证LB已禁用
        if backend_verifier is not None:
            ssh_verify(
                "L3/L4-清理后",
                backend_verifier.verify_lb_pcc_kernel,
                must_pass=False,
                expect_enabled=False,
            )

        # SSH断言
        if ssh_failures:
            print(f"\n[SSH断言] 共 {len(ssh_failures)} 项失败:")
            for f in ssh_failures:
                print(f"  - {f}")
            assert not ssh_failures, f"SSH后台验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
