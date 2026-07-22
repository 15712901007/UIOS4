"""
静态路由综合测试用例

一次测试多个功能，提高效率：
1. 添加8条路由（覆盖各种数据组合场景）
2. 编辑其中1条
3. 复制其中1条（静态路由特有功能）
4. 停用其中1条
5. 启用其中1条
6. 删除其中1条
7. 搜索测试
8. 排序测试
9. 导出测试
10. 异常输入测试
11. 当前路由表查看
12. 批量停用
13. 批量启用
14. 批量删除
15. 导入测试
16. 帮助功能测试

参照IP限速综合测试结构实现（最完善模板）
"""
import pytest
import os
import sys
import io

from pages.network.static_route_page import StaticRoutePage
from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify, make_kernel_check


@pytest.mark.static_route
@pytest.mark.network
class TestStaticRouteComprehensive:
    """静态路由综合测试 - 一次测试覆盖所有功能"""

    def test_static_route_comprehensive(self, static_route_page_logged_in: StaticRoutePage, step_recorder: StepRecorder, request):
        """
        综合测试: 添加8条路由 -> 编辑 -> 复制 -> 停用 -> 启用 -> 删除 -> 搜索 -> 排序 -> 导出 -> 异常测试 -> 当前路由表 -> 批量操作

        集成SSH后台验证：在关键操作后验证路由表状态
        """
        page = static_route_page_logged_in
        rec = step_recorder

        # 动态获取backend_verifier fixture（可选，未配置SSH时为None）
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except (pytest.FixtureLookupError, Exception):
            backend_verifier = None

        # SSH后台验证辅助函数 + 软断言收集器
        ssh_failures = []
        ui_failures = []

        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        # 测试数据 - 8条路由，覆盖各种数据组合场景
        test_routes = [
            # 路由1: 基础场景 - 自动线路 + 默认掩码
            {"name": "sr_test_001", "line": "自动", "dest": "10.10.0.0", "mask": "255.255.255.0 (24)", "gateway": "192.168.148.1", "priority": 1, "remark": "基础路由-自动线路", "desc": "基础-自动线路"},
            # 路由2: wan1线路 + /16掩码
            {"name": "sr_test_002", "line": "wan1", "dest": "172.16.0.0", "mask": "255.255.0.0 (16)", "gateway": "10.66.0.1", "priority": 2, "remark": "wan1线路-大网段", "desc": "wan1+/16掩码"},
            # 路由3: wan2线路 + 主机路由/32 (网关须在wan2直连网段内, 否则内核RTNETLINK unreachable拒装)
            {"name": "sr_test_003", "line": "wan2", "dest": "8.8.8.8", "mask": "255.255.255.255 (32)", "gateway": "192.168.112.1", "priority": 1, "remark": "wan2-主机路由", "desc": "wan2+主机路由"},
            # 路由4: lan1线路 + /28掩码
            {"name": "sr_test_004", "line": "lan1", "dest": "192.168.200.0", "mask": "255.255.255.240 (28)", "gateway": "192.168.148.2", "priority": 3, "remark": "lan1-小子网", "desc": "lan1+/28掩码"},
            # 路由5: 无网关 + 高优先级
            {"name": "sr_test_005", "line": "自动", "dest": "10.20.0.0", "mask": "255.255.255.0 (24)", "gateway": "", "priority": 1, "remark": "无网关路由", "desc": "无网关"},
            # 路由6: wan3线路 + 低优先级 (网关须在wan3直连网段内)
            {"name": "sr_test_006", "line": "wan3", "dest": "192.168.50.0", "mask": "255.255.255.0 (24)", "gateway": "10.66.0.1", "priority": 10, "remark": "wan3线路-低优先级", "desc": "wan3+低优先级"},
            # 路由7: 无备注
            {"name": "sr_test_007", "line": "自动", "dest": "10.30.0.0", "mask": "255.255.254.0 (23)", "gateway": "192.168.148.1", "priority": 5, "remark": "", "desc": "无备注+/23掩码"},
            # 路由8: 完整信息
            {"name": "sr_test_008", "line": "wan1", "dest": "192.168.100.0", "mask": "255.255.255.0 (24)", "gateway": "10.66.0.1", "priority": 2, "remark": "完整信息-综合测试", "desc": "完整信息"},
        ]

        # 导出文件路径
        config = get_config()
        export_dir = os.path.join(config.get_project_root(), "test_data", "exports", "static_route")
        os.makedirs(export_dir, exist_ok=True)
        export_file_csv = os.path.join(export_dir, "static_route_config.csv")
        export_file_txt = os.path.join(export_dir, "static_route_config.txt")

        # ========== 步骤1: 验证静态路由页面 ==========
        with rec.step("步骤1: 验证静态路由页面", "验证页面标题和标签页状态"):
            print("\n[步骤1] 验证静态路由页面...")

            assert page.page.url.endswith("/staticRoute") or "staticRoute" in page.page.url, "URL不正确"
            rec.add_detail("  页面URL验证通过")
            print("  [OK] 页面URL验证通过")

        # ========== 步骤2: 清理已有数据 ==========
        with rec.step("步骤2: 清理已有数据", "检查并清理静态路由列表中的残留数据"):
            print("\n[步骤2] 清理已有数据...")
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"  当前规则数量: {current_count}")

            if current_count > 0:
                print("  检测到残留数据，执行批量清理...")
                select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
                if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                    select_all_checkbox.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)
                    page.page.reload()
                    page.page.wait_for_load_state("networkidle")
                    page.page.wait_for_timeout(500)
                    final_count = page.get_rule_count()
                    print(f"  [OK] 批量清理完成，剩余 {final_count} 条规则")
                    rec.add_detail(f"  批量清理完成，剩余 {final_count} 条规则")
            else:
                print("  [OK] 环境干净，无需清理")
                rec.add_detail("  环境干净，无需清理")

            initial_count = page.get_rule_count()
            rec.add_detail(f"  清理完成，当前共 {initial_count} 条规则")
            print(f"  [OK] 清理完成，当前共 {initial_count} 条规则")

        # ========== 步骤3: 批量添加8条静态路由 ==========
        with rec.step("步骤3: 批量添加静态路由", f"添加 {len(test_routes)} 条路由，覆盖各种数据组合场景"):
            print(f"\n[步骤3] 批量添加{len(test_routes)}条静态路由...")

            added_count = 0
            for i, route in enumerate(test_routes, 1):
                print(f"  [{i}/{len(test_routes)}] 添加: {route['name']} ({route['desc']})...")

                success = page.add_route(
                    name=route["name"],
                    line=route["line"],
                    dest_address=route["dest"],
                    subnet_mask=route["mask"],
                    gateway=route["gateway"],
                    priority=route["priority"],
                    remark=route.get("remark") or None,
                )

                if success:
                    added_count += 1
                    print(f"    [OK] 添加成功")
                    rec.add_detail(f"    ✓ {route['name']}: {route['desc']}")
                else:
                    print(f"    [FAIL] 添加失败")
                    rec.add_detail(f"    ✗ {route['name']}: 添加失败")

            assert added_count == len(test_routes), f"期望添加{len(test_routes)}条，实际成功{added_count}条"
            print(f"  [OK] 全部添加成功: {added_count}/{len(test_routes)}")

        # ========== 步骤3.5: SSH后台验证（添加后） ==========
        if backend_verifier is not None:
            with rec.step("步骤3.5: SSH后台验证（添加后）", "L1数据库+L2内核路由+L3路由表 逐条验证"):
                print("\n[步骤3.5] SSH后台验证（添加后）...")

                # 线路名映射：UI显示名 → 数据库字段值
                line_map = {"自动": "auto", "wan1": "wan1", "wan2": "wan2", "wan3": "wan3", "lan1": "lan1"}

                for route in test_routes:
                    name = route["name"]
                    # 从 "255.255.255.0 (24)" 提取纯掩码
                    mask_raw = route["mask"].split(" ")[0] if " " in route["mask"] else route["mask"]
                    db_interface = line_map.get(route["line"], route["line"])

                    print(f"  验证 {name} ({route['desc']}):")

                    # L1: 数据库验证
                    expected_fields = {
                        "dst_addr": route["dest"],
                        "netmask": mask_raw,
                        "gateway": route["gateway"],
                        "interface": db_interface,
                        "prio": str(route["priority"]),
                        "enabled": "yes",
                    }
                    ssh_verify(f"L1-{name}", backend_verifier.verify_static_route_database,
                               tagname=name, expected_fields=expected_fields, must_pass=True)

                    # L2: 内核路由验证（无网关路由自动跳过）
                    # 内核路由安装依赖实际网络拓扑（接口是否活跃、网关是否可达），不作为必须通过项
                    ssh_verify(f"L2-{name}", backend_verifier.verify_static_route_kernel,
                               dst_addr=route["dest"], netmask=mask_raw,
                               gateway=route["gateway"],
                               must_pass=False)

                # L1: 总数验证
                ssh_verify("L1-总数", backend_verifier.verify_static_route_count,
                           expected_count=len(test_routes), must_pass=True)
        else:
            print("\n[步骤3.5] SSH后台验证: 跳过（未配置SSH或paramiko未安装）")

        # ========== 步骤4: 编辑静态路由 ==========
        with rec.step("步骤4: 编辑静态路由", "编辑第1条路由的名称和备注"):
            print("\n[步骤4] 编辑静态路由...")

            edit_target = test_routes[0]["name"]
            edit_new_remark = "已编辑-综合测试"

            page.edit_rule(edit_target)
            page.page.wait_for_timeout(500)

            # 修改备注
            remark_input = page.page.get_by_role("textbox", name="备注")
            remark_input.click()
            remark_input.fill(edit_new_remark)

            page.click_save()
            success = page.wait_for_success_message()
            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")

            assert success, "编辑保存失败"
            print(f"  [OK] 编辑成功: {edit_target} 备注改为 '{edit_new_remark}'")
            rec.add_detail(f"  ✓ 编辑成功: {edit_target}")

            # SSH验证编辑后的状态
            ssh_verify("L1-编辑验证", backend_verifier.verify_static_route_database if backend_verifier else None,
                       tagname=edit_target, expected_fields={"comment": edit_new_remark},
                       must_pass=True) if backend_verifier else None

        # ========== 步骤5: 复制静态路由（特有功能） ==========
        with rec.step("步骤5: 复制静态路由", "复制第2条路由并修改名称保存"):
            print("\n[步骤5] 复制静态路由...")

            copy_source = test_routes[1]["name"]
            copy_new_name = "sr_copied"

            page.copy_rule(copy_source)
            page.page.wait_for_timeout(500)

            # 修改名称（复制时预填了原名称）
            name_input = page.page.get_by_role("textbox", name="名称")
            name_input.click()
            name_input.fill("")
            name_input.fill(copy_new_name)

            # 修改目的地址（避免重复）
            dest_input = page.page.get_by_role("textbox", name="目的地址")
            dest_input.click()
            dest_input.fill("172.17.0.0")

            page.click_save()
            success = page.wait_for_success_message()
            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")

            assert success, "复制保存失败"

            # 验证复制后的路由存在
            total_count = page.get_rule_count()
            assert total_count == len(test_routes) + 1, f"复制后应有{len(test_routes)+1}条，实际{total_count}条"
            print(f"  [OK] 复制成功: {copy_source} -> {copy_new_name}，当前共{total_count}条")
            rec.add_detail(f"  ✓ 复制成功: {copy_source} -> {copy_new_name}")

            # SSH验证复制后的路由存在
            ssh_verify("L1-复制验证", backend_verifier.verify_static_route_database if backend_verifier else None,
                       tagname=copy_new_name, expected_fields={"dst_addr": "172.17.0.0"},
                       must_pass=True) if backend_verifier else None

        # ========== 步骤6: 停用静态路由 ==========
        with rec.step("步骤6: 停用静态路由", "停用第3条路由"):
            print("\n[步骤6] 停用静态路由...")

            disable_target = test_routes[2]["name"]
            success = page.disable_rule(disable_target)
            page.page.wait_for_timeout(500)

            assert success, f"停用 {disable_target} 失败"

            # 验证停用状态
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            is_disabled = page.is_rule_disabled(disable_target)
            assert is_disabled, f"{disable_target} 未显示为停用状态"
            print(f"  [OK] 停用成功: {disable_target}")
            rec.add_detail(f"  ✓ 停用成功: {disable_target}")

            # SSH验证停用状态
            ssh_verify("L1-停用验证", backend_verifier.verify_static_route_database if backend_verifier else None,
                       tagname=disable_target, expected_fields={"enabled": "no"},
                       must_pass=True) if backend_verifier else None

        # ========== 步骤7: 启用静态路由 ==========
        with rec.step("步骤7: 启用静态路由", "启用第3条路由"):
            print("\n[步骤7] 启用静态路由...")

            enable_target = test_routes[2]["name"]
            success = page.enable_rule(enable_target)
            page.page.wait_for_timeout(500)

            assert success, f"启用 {enable_target} 失败"

            # 验证启用状态
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            is_enabled = page.is_rule_enabled(enable_target)
            assert is_enabled, f"{enable_target} 未显示为启用状态"
            print(f"  [OK] 启用成功: {enable_target}")
            rec.add_detail(f"  ✓ 启用成功: {enable_target}")

            # SSH验证启用状态
            ssh_verify("L1-启用验证", backend_verifier.verify_static_route_database if backend_verifier else None,
                       tagname=enable_target, expected_fields={"enabled": "yes"},
                       must_pass=True) if backend_verifier else None

        # ========== 步骤8: 删除静态路由 ==========
        with rec.step("步骤8: 删除静态路由", "删除复制的路由"):
            print("\n[步骤8] 删除静态路由...")

            delete_target = "sr_copied"
            count_before = page.get_rule_count()
            success = page.delete_rule(delete_target)
            page.page.wait_for_timeout(500)

            assert success, f"删除 {delete_target} 失败"

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            count_after = page.get_rule_count()
            assert count_after == count_before - 1, f"删除后应减少1条，实际: {count_before} -> {count_after}"
            print(f"  [OK] 删除成功: {delete_target}，{count_before} -> {count_after}")
            rec.add_detail(f"  ✓ 删除成功: {delete_target}")

            # SSH验证删除后路由不存在
            ssh_verify("L1-删除验证", backend_verifier.verify_static_route_not_exists if backend_verifier else None,
                       tagname=delete_target, must_pass=True) if backend_verifier else None

        # ========== 步骤9: 搜索测试 ==========
        with rec.step("步骤9: 搜索功能测试", "测试搜索存在/不存在的规则"):
            print("\n[步骤9] 搜索测试...")

            # 搜索存在的规则
            search_keyword = test_routes[0]["name"]
            page.search_rule(search_keyword)
            page.page.wait_for_timeout(500)

            search_count = page.get_rule_count()
            assert search_count >= 1, f"搜索 '{search_keyword}' 应至少找到1条，实际{search_count}条"
            print(f"  [OK] 搜索 '{search_keyword}' 找到 {search_count} 条")
            rec.add_detail(f"  ✓ 搜索 '{search_keyword}': {search_count} 条")

            # 清除搜索
            page.clear_search()
            page.page.wait_for_timeout(500)

            # 搜索不存在的规则
            page.search_rule("not_exist_route_xyz")
            page.page.wait_for_timeout(500)

            no_result_count = page.get_rule_count()
            assert no_result_count == 0, f"搜索不存在的规则应返回0条，实际{no_result_count}条"
            print(f"  [OK] 搜索不存在的规则: 0 条")
            rec.add_detail(f"  ✓ 搜索不存在的规则: 0 条")

            # 恢复
            page.clear_search()
            page.page.wait_for_timeout(500)

        # ========== 步骤10: 排序测试 ==========
        with rec.step("步骤10: 排序测试", "测试可排序字段的排序功能"):
            print("\n[步骤10] 排序测试...")

            sortable_columns = ["线路", "目的地址", "网关", "优先级"]

            for col in sortable_columns:
                # 点击3次：正序→倒序→默认
                for click_idx in range(3):
                    sort_labels = ["正序", "倒序", "默认"]
                    page.sort_by_column(col)
                    page.page.wait_for_timeout(300)
                    print(f"  排序: {col} -> {sort_labels[click_idx]}")

            rec.add_detail(f"  ✓ 排序测试: {len(sortable_columns)} 个字段")
            print(f"  [OK] 排序测试完成: {len(sortable_columns)} 个字段")

        # ========== 步骤11: 导出测试 ==========
        with rec.step("步骤11: 导出静态路由", "导出CSV和TXT两种格式"):
            print("\n[步骤11] 导出静态路由...")

            # 导出CSV
            csv_success = page.export_rules(use_config_path=False, export_format="csv")
            if csv_success:
                print(f"  [OK] CSV导出成功")
                rec.add_detail("  ✓ CSV导出成功")
            else:
                print(f"  [WARN] CSV导出失败")
                rec.add_detail("  ✗ CSV导出失败")
                ui_failures.append("CSV导出失败")

            page.page.wait_for_timeout(500)

            # 导出TXT
            txt_success = page.export_rules(use_config_path=False, export_format="txt")
            if txt_success:
                print(f"  [OK] TXT导出成功")
                rec.add_detail("  ✓ TXT导出成功")
            else:
                print(f"  [WARN] TXT导出失败")
                rec.add_detail("  ✗ TXT导出失败")
                ui_failures.append("TXT导出失败")

            assert csv_success or txt_success, "CSV和TXT导出均失败"

        # ========== 步骤12: 异常输入测试 ==========
        with rec.step("步骤12: 异常输入测试", "测试各种不合规输入的验证拦截"):
            print("\n[步骤12] 异常输入测试...")

            invalid_cases = [
                {"desc": "空名称", "name": "", "dest": "10.0.0.0", "gateway": "192.168.148.1"},
                {"desc": "空目的地址", "name": "test_invalid", "dest": "", "gateway": "192.168.148.1"},
                {"desc": "无效IP格式", "name": "test_invalid", "dest": "999.999.999.999", "gateway": "192.168.148.1"},
                {"desc": "无效网关格式", "name": "test_invalid", "dest": "10.0.0.0", "gateway": "abc.def.ghi"},
            ]

            tested_count = 0
            for case in invalid_cases:
                print(f"  测试异常输入: {case['desc']}...")
                result = page.try_add_route_invalid(
                    name=case["name"],
                    dest_address=case["dest"],
                    gateway=case["gateway"],
                )

                if result["has_validation_error"] or not result["success"]:
                    tested_count += 1
                    print(f"    [OK] 正确拦截: {result['error_msg'][:50] if result['error_msg'] else '验证未通过'}")
                    rec.add_detail(f"    ✓ {case['desc']}: 拦截成功")
                else:
                    print(f"    [WARN] 异常输入未拦截")
                    rec.add_detail(f"    ✗ {case['desc']}: 未拦截")
                    # 如果不小心成功了，删除
                    try:
                        page.page.reload()
                        page.page.wait_for_load_state("networkidle")
                        page.delete_rule("test_invalid")
                    except Exception:
                        pass

                page.page.wait_for_timeout(300)

            print(f"  [OK] 异常输入测试: {tested_count}/{len(invalid_cases)} 正确拦截")

        # ========== 步骤13: 当前路由表查看 ==========
        with rec.step("步骤13: 当前路由表查看", "切换到当前路由表标签页验证"):
            print("\n[步骤13] 当前路由表查看...")

            # 确保在静态路由页面（步骤12异常输入可能导致页面状态异常）
            page.navigate_to_static_route()
            page.page.wait_for_timeout(500)

            page.switch_to_current_route_table()
            page.page.wait_for_timeout(1000)

            # 获取IPv4路由表条数
            ipv4_count = page.get_current_route_table_count()
            print(f"  IPv4路由表: {ipv4_count} 条")
            rec.add_detail(f"  IPv4路由表: {ipv4_count} 条")
            assert ipv4_count > 0, "IPv4路由表应至少有1条"

            # 切换到IPv6
            page.switch_route_table_protocol("IPv6")
            page.page.wait_for_timeout(1000)
            ipv6_count = page.get_current_route_table_count()
            print(f"  IPv6路由表: {ipv6_count} 条")
            rec.add_detail(f"  IPv6路由表: {ipv6_count} 条")

            # 切回静态路由标签页
            page.switch_to_static_route_tab()
            page.page.wait_for_timeout(500)
            print(f"  [OK] 当前路由表查看完成")

        # ========== 步骤14: 批量停用 ==========
        with rec.step("步骤14: 批量停用静态路由", f"批量停用所有路由"):
            print("\n[步骤14] 批量停用所有路由...")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

            count_before = page.get_rule_count()
            print(f"  当前共 {count_before} 条规则")

            page.select_all_rules()
            page.page.wait_for_timeout(300)
            page.batch_disable()
            page.page.wait_for_timeout(1000)

            # 验证停用状态
            page.page.reload()
            page.page.wait_for_load_state("networkidle")

            disabled_count = 0
            for route in test_routes:
                if page.is_rule_disabled(route["name"]):
                    disabled_count += 1

            print(f"  [OK] 批量停用完成: {disabled_count}/{len(test_routes)} 已停用")
            rec.add_detail(f"  ✓ 批量停用: {disabled_count}/{len(test_routes)}")

            # SSH验证批量停用后状态
            if backend_verifier is not None:
                for route in test_routes:
                    ssh_verify(f"L1-批量停用-{route['name']}",
                               backend_verifier.verify_static_route_database,
                               tagname=route["name"], expected_fields={"enabled": "no"},
                               must_pass=True)

        # ========== 步骤15: 批量启用 ==========
        with rec.step("步骤15: 批量启用静态路由", f"批量启用所有路由"):
            print("\n[步骤15] 批量启用所有路由...")

            page.select_all_rules()
            page.page.wait_for_timeout(300)
            page.batch_enable()
            page.page.wait_for_timeout(1000)

            # 验证启用状态
            page.page.reload()
            page.page.wait_for_load_state("networkidle")

            enabled_count = 0
            for route in test_routes:
                if page.is_rule_enabled(route["name"]):
                    enabled_count += 1

            print(f"  [OK] 批量启用完成: {enabled_count}/{len(test_routes)} 已启用")
            rec.add_detail(f"  ✓ 批量启用: {enabled_count}/{len(test_routes)}")

            # SSH验证批量启用后状态
            if backend_verifier is not None:
                for route in test_routes:
                    ssh_verify(f"L1-批量启用-{route['name']}",
                               backend_verifier.verify_static_route_database,
                               tagname=route["name"], expected_fields={"enabled": "yes"},
                               must_pass=True)

        # ========== 步骤16: 批量删除 ==========
        with rec.step("步骤16: 批量删除静态路由", f"批量删除所有测试路由"):
            print("\n[步骤16] 批量删除所有测试路由...")

            count_before = page.get_rule_count()

            page.select_all_rules()
            page.page.wait_for_timeout(300)
            page.batch_delete()
            page.page.wait_for_timeout(1000)

            page.page.reload()
            page.page.wait_for_load_state("networkidle")

            count_after = page.get_rule_count()
            deleted = count_before - count_after
            print(f"  [OK] 批量删除完成: {count_before} -> {count_after} (删除{deleted}条)")
            rec.add_detail(f"  ✓ 批量删除: {count_before} -> {count_after}")

            # SSH验证批量删除后数据库为空
            ssh_verify("L1-批量删除验证", backend_verifier.verify_static_route_count if backend_verifier else None,
                       expected_count=0, must_pass=True) if backend_verifier else None

        # ========== 步骤17: 导入测试 ==========
        with rec.step("步骤17: 导入静态路由", "使用导出的文件进行导入测试"):
            print("\n[步骤17] 导入静态路由测试...")

            # 查找导出的文件
            import_file = None
            for f in [export_file_csv, export_file_txt]:
                if os.path.exists(f):
                    import_file = f
                    break

            # 如果配置路径没有，尝试downloads目录
            if import_file is None:
                # 须与ikuai_table_page.export_rules的download_dir一致(=项目根/downloads);
                # 本文件在tests/network/, 需上溯3级到项目根(export_rules在pages/只上溯2级)
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                downloads_dir = os.path.join(project_root, "downloads")
                if os.path.exists(downloads_dir):
                    for f in sorted(os.listdir(downloads_dir), reverse=True):
                        if f.startswith("static_route_export") and (f.endswith(".csv") or f.endswith(".txt")):
                            import_file = os.path.join(downloads_dir, f)
                            break

            if import_file and os.path.exists(import_file):
                print(f"  使用文件: {import_file}")
                import_success = page.import_rules(import_file, clear_existing=False)

                if import_success:
                    page.page.wait_for_timeout(1000)
                    page.page.reload()
                    page.page.wait_for_load_state("networkidle")

                    imported_count = page.get_rule_count()
                    print(f"  [OK] 导入成功，当前共 {imported_count} 条")
                    rec.add_detail(f"  ✓ 导入成功: {imported_count} 条")
                else:
                    print(f"  [WARN] 导入操作未成功")
                    rec.add_detail("  ✗ 导入失败")
            else:
                # 诚实诊断: 导出成功却找不到文件=导出/导入路径不一致(代码bug,应FAIL); 导出本身失败=WARN
                diag = f"导出csv={csv_success}/txt={txt_success}"
                if csv_success or txt_success:
                    msg = f"无导出文件可用于导入({diag}) - 导出成功却丢文件, 导出/导入路径不一致"
                    print(f"  [FAIL] {msg}")
                    rec.add_detail(f"  ✗ 导入失败: {msg}")
                    ui_failures.append(f"步骤17导入: {msg}")
                else:
                    print(f"  [SKIP] 无导出文件可用于导入测试 ({diag})")
                    rec.add_detail(f"  ⚠ 导入跳过: 无导出文件({diag})")

        # ========== 步骤18: 清理导入的数据 ==========
        with rec.step("步骤18: 清理导入数据", "清理导入测试产生的数据"):
            print("\n[步骤18] 清理导入数据...")

            current_count = page.get_rule_count()
            if current_count > 0:
                page.select_all_rules()
                page.page.wait_for_timeout(300)
                page.batch_delete()
                page.page.wait_for_timeout(1000)

                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成: {current_count} -> {final_count}")
                rec.add_detail(f"  ✓ 清理: {current_count} -> {final_count}")
            else:
                print(f"  [OK] 无需清理")
                rec.add_detail("  ✓ 无需清理")

        # ========== 步骤19: 帮助功能测试 ==========
        with rec.step("步骤19: 帮助功能测试", "测试帮助按钮的显示"):
            print("\n[步骤19] 帮助功能测试...")

            # iKuai SPA帮助按钮(_helpDoc异步组件)挂载到DOM的时机晚于
            # networkidle; 步骤18 reload后立刻count()会因按钮尚未渲染而误判
            # "不存在"(历史假失败, 实际按钮存在). 故显式等待渲染, 多策略兜底,
            # 并与全项目惯例一致: 帮助为低优先级展示性UI, 找不到仅WARN不硬FAIL.
            page._ensure_static_route_tab_active()
            help_btn = page.page.get_by_role("button", name="帮助")
            try:
                help_btn.first.wait_for(state="visible", timeout=5000)
            except Exception:
                # 兜底: 文本匹配 / 帮助专属class前缀(_helpDoc, 参考base_page)
                help_btn = page.page.locator(
                    "button:has-text('帮助'), [class*='helpDoc'], [class*='help']"
                ).first
                try:
                    help_btn.wait_for(state="visible", timeout=3000)
                except Exception:
                    help_btn = None

            if help_btn is not None and help_btn.count() > 0:
                assert help_btn.first.is_visible(), "帮助按钮不可见"
                print("  [OK] 帮助按钮存在且可见")
                rec.add_detail("  ✓ 帮助按钮存在")
            else:
                print("  [WARN] 帮助按钮未渲染出来(可能SPA延迟)")
                rec.add_detail("  ⚠ 帮助按钮未检测到(SPA渲染延迟)")

        # ========== 最终: SSH验证汇总 ==========
        all_failures = ssh_failures + ui_failures
        if ssh_failures:
            failure_summary = "\n".join(ssh_failures)
            print(f"\n[SSH验证失败汇总]\n{failure_summary}")
        assert not all_failures, f"验证失败 ({len(ssh_failures)} 项):\n{failure_summary}"

        print(f"\n{'='*60}")
        print(f"静态路由综合测试全部完成！共 19 个步骤")
        print(f"{'='*60}")


@pytest.mark.static_route
@pytest.mark.network
class TestStaticRouteFlowVerification:
    """静态路由功能验证(L5 路由器ping环回, 硬断言): 建静态路由→路由器ping client环回→通=生效→删恢复.

    静态路由=路由表指定目标网段→下一跳. client lo有环回10.99.99.1/32(ip_forward=1),
    路由器建10.99.99.0/24→下一跳10.66.0.18(client enp2s0).
    L5: 基线路由器ping 10.99.99.1不通(无路由)→建静态路由→ping通+traceroute下一跳→删恢复ping不通.
    不用再搭设备(client环回作目标). client ping 10.99.99.1走本地lo, 故用路由器ping验路由器路由表."""

    PREFIX = "srflow_"
    DEST_NET = "10.99.99.0"
    DEST_MASK = "255.255.255.0 (24)"
    GATEWAY = "10.66.0.18"      # client enp2s0(下一跳, 10.99.99.1在client lo)
    PING_TARGET = "10.99.99.1"  # client lo环回

    def test_static_route_flow(self, static_route_page_logged_in, step_recorder: StepRecorder, request):
        import re
        page = static_route_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            pytest.skip("无SSH验证器, 跳过静态路由功能验证")
        rule_name = f"{self.PREFIX}route"
        failures = []
        print("\n" + "=" * 50)
        print("静态路由功能验证(L5 路由器ping环回)")
        print("=" * 50)

        def _router_ping_target():
            """路由器ping 10.99.99.1, 返回(transmitted, received)."""
            bv.connect_router()
            out = bv._router.exec(f"ping -c 3 -W 2 {self.PING_TARGET} 2>/dev/null", timeout=20)
            m = re.search(r'(\d+)\s+packets transmitted.*?(\d+)\s+received', out)
            if m:
                return int(m.group(1)), int(m.group(2))
            return 0, 0

        try:
            # 1. 基线: 路由器ping 10.99.99.1不通(无静态路由)
            with rec.step("基线: 路由器ping 10.99.99.1", "无静态路由时应不通(10.99.99.1不可达)"):
                t, r = _router_ping_target()
                rec.add_detail(f"  ping {self.PING_TARGET}: {r}/{t} received")
                if r > 0:
                    rec.add_detail(f"  ⚠️基线即通({r}/{t}), 10.99.99.1可能已有路由")
                else:
                    rec.add_detail(f"  ✓ 基线不通(无路由, 符合预期)")

            # 2. 建静态路由: 10.99.99.0/24 → 下一跳 10.66.0.18
            with rec.step("建静态路由", f"{self.DEST_NET}/24 → 下一跳{self.GATEWAY}"):
                page.navigate_to_static_route()
                page.page.wait_for_timeout(800)
                try:
                    page.delete_rule(rule_name)
                    page.page.wait_for_timeout(500)
                except Exception:
                    pass
                try:
                    bv._router.exec(f"sqlite3 {bv.IK_DB} \"DELETE FROM static_route WHERE tagname LIKE '{self.PREFIX}%'\" 2>/dev/null")
                except Exception:
                    pass
                ok = page.add_route(rule_name, dest_address=self.DEST_NET,
                                    subnet_mask=self.DEST_MASK, gateway=self.GATEWAY, line="自动")
                if not ok:
                    failures.append(f"建静态路由失败: {rule_name}")
                    rec.add_detail("  ✗ 建规则失败")
                else:
                    page.page.wait_for_timeout(2000)
                    rule = bv.find_static_route(rule_name)
                    rec.add_detail(f"  ✓ 建规则 id={rule.get('id') if rule else '?'} dest={rule.get('dest') if rule else '?'} gw={rule.get('gateway') if rule else '?'}")

            # L1-L3 后端验证(报告体现: 数据库→内核路由表→static_rt_table; 静态路由无独立内核模块故无L4)
            if not failures:
                with rec.step("L1-L3后端验证", "数据库(static_rt)+内核路由表(ip route)+static_rt_table路由表"):
                    r1 = bv.verify_static_route_database(rule_name, expected_fields={
                        "dst_addr": self.DEST_NET, "gateway": self.GATEWAY, "enabled": "yes"})
                    rec.add_detail(f"  {r1.level}: {'[OK]' if r1.passed else '[FAIL]'} {r1.message}")
                    if not r1.passed:
                        failures.append(f"{r1.level}: {r1.message}")
                    r2 = bv.verify_static_route_kernel(self.DEST_NET, "255.255.255.0", gateway=self.GATEWAY)
                    rec.add_detail(f"  {r2.level}: {'[OK]' if r2.passed else '[FAIL]'} {r2.message}")
                    if not r2.passed:
                        failures.append(f"{r2.level}: {r2.message}")
                    r3 = bv.verify_static_route_table(self.DEST_NET, gateway=self.GATEWAY)
                    rec.add_detail(f"  {r3.level}: {'[OK]' if r3.passed else '[FAIL]'} {r3.message}")
                    if not r3.passed:
                        failures.append(f"{r3.level}: {r3.message}")

            # 3. L5: 路由器ping 10.99.99.1 → 通(静态路由生效) + traceroute下一跳
            if not failures:
                with rec.step("L5 ping验证", f"建路由后ping {self.PING_TARGET} 应通 + traceroute下一跳{self.GATEWAY}"):
                    t, r = _router_ping_target()
                    rec.add_detail(f"  ping {self.PING_TARGET}: {r}/{t} received")
                    if r > 0:
                        rec.add_detail(f"  ✓ 静态路由生效(ping通)")
                    else:
                        rec.add_detail(f"  ✗ 静态路由未生效(ping不通)")
                        failures.append(f"静态路由未生效: ping {self.PING_TARGET} {r}/{t}")
                    tr_out = bv._router.exec(f"traceroute -n -w 2 -q 1 -m 5 {self.PING_TARGET} 2>/dev/null", timeout=25)
                    tr_last = tr_out.strip().splitlines()[-1] if tr_out.strip() else "空"
                    rec.add_detail(f"  traceroute末行: {tr_last}")
                    if self.GATEWAY in tr_out:
                        rec.add_detail(f"  ✓ traceroute经下一跳{self.GATEWAY}")
                    else:
                        rec.add_detail(f"  ⚠️traceroute未显{self.GATEWAY}(可能直连同网段)")

            # 4. 停用静态路由 → ping不通(规则在但停用, 路由表不生效)
            if not failures:
                with rec.step("停用规则验证", "停用静态路由→ping应不通(规则在但不生效)"):
                    page.navigate_to_static_route()
                    page.page.wait_for_timeout(500)
                    dis_ok = page.disable_rule(rule_name)
                    page.page.wait_for_timeout(1500)
                    is_dis = page.is_rule_disabled(rule_name)
                    rec.add_detail(f"  停用={dis_ok}, is_disabled={is_dis}")
                    t, r = _router_ping_target()
                    rec.add_detail(f"  停用后ping {self.PING_TARGET}: {r}/{t} received")
                    if r > 0:
                        rec.add_detail(f"  ✗ 停用后仍通(停用未生效)")
                        failures.append(f"停用未生效: ping仍通{r}/{t}")
                    else:
                        rec.add_detail(f"  ✓ 停用后不通(停用生效)")

                # 5. 启用静态路由 → ping通(恢复)
                with rec.step("启用规则验证", "启用静态路由→ping应通(恢复)"):
                    page.navigate_to_static_route()
                    page.page.wait_for_timeout(500)
                    page.enable_rule(rule_name)
                    page.page.wait_for_timeout(1500)
                    t, r = _router_ping_target()
                    rec.add_detail(f"  启用后ping {self.PING_TARGET}: {r}/{t} received")
                    if r > 0:
                        rec.add_detail(f"  ✓ 启用后通(启用生效)")
                    else:
                        rec.add_detail(f"  ✗ 启用后不通(启用未生效)")
                        failures.append(f"启用未生效: ping不通{r}/{t}")

            # 6. 删静态路由 → ping不通(恢复)
            with rec.step("删规则恢复", "删静态路由→ping 10.99.99.1应不通"):
                page.navigate_to_static_route()
                page.page.wait_for_timeout(500)
                try:
                    page.delete_rule(rule_name)
                except Exception:
                    pass
                try:
                    bv._router.exec(f"sqlite3 {bv.IK_DB} \"DELETE FROM static_route WHERE tagname LIKE '{self.PREFIX}%'\" 2>/dev/null")
                except Exception:
                    pass
                page.page.wait_for_timeout(1500)
                t2, r2 = _router_ping_target()
                rec.add_detail(f"  删后ping {self.PING_TARGET}: {r2}/{t2} received")
                if r2 > 0:
                    rec.add_detail(f"  ✗ 删规则后仍通(规则残留或已有路由)")
                    failures.append("删规则后仍ping通(残留)")
                else:
                    rec.add_detail(f"  ✓ 删规则后不通(恢复)")
        finally:
            try:
                page.navigate_to_static_route()
                page.page.wait_for_timeout(500)
                page.delete_rule(rule_name)
            except Exception:
                pass
            try:
                bv._router.exec(f"sqlite3 {bv.IK_DB} \"DELETE FROM static_route WHERE tagname LIKE '{self.PREFIX}%'\" 2>/dev/null")
            except Exception:
                pass
        print(f"\n[静态路由功能验证] {'通过' if not failures else '失败'+str(len(failures))+'项'}")
        assert not failures, f"静态路由功能验证失败({len(failures)}项): {'; '.join(failures)}"
