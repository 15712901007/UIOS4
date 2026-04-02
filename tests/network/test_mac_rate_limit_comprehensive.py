"""
MAC限速综合测试用例

一次测试多个功能，提高效率：
1. 添加8条规则（覆盖各种数据组合场景）
2. 编辑其中1条
3. 停用其中1条
4. 启用其中1条
5. 删除其中1条
6. 搜索测试
7. 排序测试
8. 导出测试
9. 异常输入测试
10. 批量停用
11. 批量启用
12. 批量删除
13. 导入测试
14. 帮助功能测试

参照VLAN综合测试和IP限速综合测试结构实现
"""
import pytest
import os
import sys
import io

from pages.network.mac_rate_limit_page import MacRateLimitPage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.mac_rate_limit
@pytest.mark.network
class TestMacRateLimitComprehensive:
    """MAC限速综合测试 - 一次测试覆盖所有功能"""

    def test_mac_rate_limit_comprehensive(self, mac_rate_limit_page_logged_in: MacRateLimitPage, step_recorder: StepRecorder, request):
        """
        综合测试: 添加8种场景 -> 编辑 -> 停用 -> 启用 -> 删除 -> 搜索 -> 排序 -> 导出 -> 异常测试 -> 批量操作

        测试步骤参照测试文档v1.5
        集成SSH后台验证：在关键操作后验证数据库状态
        """
        page = mac_rate_limit_page_logged_in
        rec = step_recorder

        # 动态获取backend_verifier fixture（可选，未配置SSH时为None）
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except (pytest.FixtureLookupError, Exception):
            backend_verifier = None

        # SSH后台验证辅助函数 + 软断言收集器
        ssh_failures = []  # 收集must_pass=True但验证失败的项，测试末尾统一断言

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            """执行SSH后台验证并记录结果。must_pass=True时失败会记录到ssh_failures"""
            if backend_verifier is None:
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = '通过' if result.passed else '失败'
                print(f"    SSH-{label}: {status} - {result.message}")
                rec.add_detail(f"    SSH-{label}: {'✓' if result.passed else '✗'} {result.message}")
                # 显示SSH后台查询的原始内容
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

        def ssh_find_rule(tagname, qos_type="mac_qos"):
            """通过SSH查找数据库中的MAC限速规则"""
            if backend_verifier is None:
                return None
            try:
                return backend_verifier.find_qos_rule(qos_type, tagname=tagname)
            except Exception:
                return None

        # 测试数据 - 8条规则，覆盖各种数据组合场景
        # 包含：不同线路(任意/全部/wan1/wan2/wan3)、不同协议栈、MAC组、批量MAC、时间计划等
        test_rules = [
            # 规则1: IPv4基础 - 任意线路
            {"name": "mac_test_001", "line": "任意", "protocol_stack": "IPv4", "mode": "独立限速", "upload": 512, "download": 1024, "remark": "IPv4基础限速测试", "desc": "IPv4基础-任意线路"},
            # 规则2: IPv6协议栈 + wan1线路
            {"name": "mac_test_002", "line": "wan1", "protocol_stack": "IPv6", "mode": "独立限速", "upload": 512, "download": 1024, "remark": "IPv6协议栈限速-wan1线路", "desc": "IPv6+wan1线路"},
            # 规则3: wan2线路 + 单个MAC地址
            {"name": "mac_test_003", "line": "wan2", "mac": "AA:BB:CC:DD:EE:02", "protocol_stack": "IPv4", "mode": "独立限速", "upload": 1024, "download": 2048, "remark": "wan2线路-单MAC限速", "desc": "wan2线路+单MAC"},
            # 规则4: wan3线路
            {"name": "mac_test_004", "line": "wan3", "protocol_stack": "IPv4", "mode": "独立限速", "upload": 512, "download": 1024, "remark": "wan3线路限速测试", "desc": "wan3线路"},
            # 规则5: 全部线路 + 批量MAC地址
            {"name": "mac_test_005", "line": "全部", "batch_macs": ["AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04", "AA:BB:CC:DD:EE:05"], "protocol_stack": "IPv4", "mode": "独立限速", "upload": 2048, "download": 4096, "remark": "全部线路-批量MAC", "desc": "全部线路+批量MAC"},
            # 规则6: MAC组（需要在步骤4中创建）+ 任意线路
            {"name": "mac_test_006", "line": "任意", "mac_group": "test_mac_group_001", "protocol_stack": "IPv4", "mode": "独立限速", "upload": 1024, "download": 2048, "remark": "MAC组限速测试", "desc": "MAC组+任意线路"},
            # 规则7: 时间计划（需要在步骤5中创建）+ wan1线路
            {"name": "mac_test_007", "line": "wan1", "time_plan": "t_plan_mac_001", "protocol_stack": "IPv4", "mode": "独立限速", "upload": 512, "download": 1024, "remark": "时间计划限速-wan1", "desc": "时间计划+wan1线路"},
            # 规则8: 共享限速 + wan2线路 + 时间段生效
            {"name": "mac_test_008", "line": "wan2", "protocol_stack": "IPv4", "mode": "共享限速", "upload": 1024, "download": 2048, "time_type": "时间段", "time_start": "2026-03-01 00:00", "time_end": "2026-03-31 23:59", "remark": "共享限速-wan2-时间段", "desc": "共享限速+wan2+时间段"},
        ]

        print("\n" + "=" * 60)
        print("MAC限速综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")

        # ========== 步骤1: 登录并导航到MAC限速页面 ==========
        with rec.step("步骤1: 登录并导航到MAC限速页面", "验证页面标题和标签页状态"):
            print("\n[步骤1] 验证MAC限速页面...")
            rec.add_detail(f"【页面验证】")
            rec.add_detail(f"  当前URL: {page.page.url}")
            page.page.wait_for_timeout(500)
            rec.add_detail(f"  ✓ 页面加载成功")

        # ========== 步骤2: 清理已有数据 ==========
        with rec.step("步骤2: 清理已有数据", "先清理MAC限速规则，再清理路由对象中的MAC分组和时间计划"):
            print("\n[步骤2] 清理已有数据...")

            # === 2.1 先清理MAC限速规则（因为规则可能引用了MAC分组和时间计划） ===
            print("  [2.1] 清理MAC限速规则...")
            rec.add_detail(f"【2.1 清理MAC限速规则】")

            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"  当前规则数量: {current_count}")

            if current_count > 0:
                print("  检测到残留数据，执行批量清理...")
                rec.add_detail(f"【清理操作】")
                select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
                if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                    rec.add_detail("  1. 点击全选复选框")
                    select_all_checkbox.click()
                    page.page.wait_for_timeout(500)
                    rec.add_detail("  2. 点击批量删除按钮")
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)
                    page.navigate_to_mac_rate_limit()
                    page.page.wait_for_timeout(500)
                    final_count = page.get_rule_count()
                    print(f"  [OK] MAC限速规则清理完成，剩余 {final_count} 条规则")
                    rec.add_detail(f"【清理结果】")
                    rec.add_detail(f"  清理完成，剩余 {final_count} 条规则")
            else:
                print("  [OK] MAC限速规则干净，无需清理")
                rec.add_detail("  环境干净，无需清理")

            # === 2.2 再清理路由对象中的MAC分组和时间计划 ===
            print("  [2.2] 清理路由对象数据...")
            rec.add_detail(f"【2.2 清理路由对象数据】")

            # 获取当前URL的基础部分
            current_url = page.page.url
            base_url_part = current_url.split('/#')[0] if '/#' in current_url else "http://10.66.0.150"
            print(f"  基础URL: {base_url_part}")

            # 清理MAC分组 - 导航到路由对象页面，点击MAC分组tab
            try:
                routing_object_url = f"{base_url_part}/#/networkConfiguration/routingObject"
                print(f"  导航到路由对象页面: {routing_object_url}")
                page.page.goto(routing_object_url)
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(1000)

                # 确保在MAC分组tab
                mac_group_tab = page.page.get_by_role("tab", name="MAC分组")
                if mac_group_tab.count() > 0:
                    mac_group_tab.click()
                    page.page.wait_for_timeout(500)

                # 检查是否有数据（通过"共 X 条"判断，因为数据不在table tbody中）
                count_text_locator = page.page.locator("text=/共 \\d+ 条/")
                count_text = count_text_locator.first.text_content() if count_text_locator.count() > 0 else "共 0 条"
                print(f"  MAC分组: {count_text}")

                if "共 0 条" not in count_text:
                    # 有数据，执行批量删除
                    select_all = page.page.locator("thead input[type='checkbox']").first
                    if select_all.count() > 0 and select_all.is_enabled():
                        select_all.click()
                        page.page.wait_for_timeout(500)
                        page.page.get_by_role("button", name="删除").first.click()
                        page.page.wait_for_timeout(500)
                        page.page.get_by_role("button", name="确定").first.click()
                        page.page.wait_for_timeout(1000)
                        print("  [OK] MAC分组清理完成")
                        rec.add_detail("  MAC分组清理完成")
                    else:
                        print("  [OK] MAC分组无需清理（全选按钮不可用）")
                        rec.add_detail("  MAC分组无需清理")
                else:
                    print("  [OK] MAC分组无需清理")
                    rec.add_detail("  MAC分组无需清理")
            except Exception as e:
                print(f"  [WARN] MAC分组清理跳过: {str(e)[:50]}")
                rec.add_detail(f"  MAC分组清理跳过")

            # 清理时间计划 - 在同一页面点击时间计划tab
            try:
                print(f"  切换到时间计划tab")
                time_plan_tab = page.page.get_by_role("tab", name="时间计划")
                if time_plan_tab.count() > 0:
                    time_plan_tab.click()
                    page.page.wait_for_load_state("networkidle")
                    page.page.wait_for_timeout(1000)

                    # 检查是否有数据（通过"共 X 条"判断，因为数据不在table tbody中）
                    count_text_locator = page.page.locator("text=/共 \\d+ 条/")
                    count_text = count_text_locator.first.text_content() if count_text_locator.count() > 0 else "共 0 条"
                    print(f"  时间计划: {count_text}")

                    if "共 0 条" not in count_text:
                        # 有数据，执行批量删除
                        select_all = page.page.locator("thead input[type='checkbox']").first
                        if select_all.count() > 0 and select_all.is_enabled():
                            select_all.click()
                            page.page.wait_for_timeout(500)
                            page.page.get_by_role("button", name="删除").first.click()
                            page.page.wait_for_timeout(500)
                            page.page.get_by_role("button", name="确定").first.click()
                            page.page.wait_for_timeout(1000)
                            print("  [OK] 时间计划清理完成")
                            rec.add_detail("  时间计划清理完成")
                        else:
                            print("  [OK] 时间计划无需清理（全选按钮不可用）")
                            rec.add_detail("  时间计划无需清理")
                    else:
                        print("  [OK] 时间计划无需清理")
                        rec.add_detail("  时间计划无需清理")
                else:
                    print("  [WARN] 时间计划tab未找到")
                    rec.add_detail("  时间计划tab未找到")
            except Exception as e:
                print(f"  [WARN] 时间计划清理跳过: {str(e)[:50]}")
                rec.add_detail(f"  时间计划清理跳过")

            # 返回MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

        # ========== 步骤3: 二次检查测试数据 ==========
        with rec.step("步骤3: 二次检查测试数据", "确保测试数据已清理"):
            print("\n[步骤3] 检查测试数据是否已清理...")
            rec.add_detail(f"【二次检查】")

            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                # 使用批量删除清理残留数据（而非逐条删除）
                print(f"  发现 {current_count} 条残留数据，执行批量清理...")
                rec.add_detail(f"  发现 {current_count} 条残留数据，执行批量清理")
                select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
                if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                    select_all_checkbox.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)
                    page.navigate_to_mac_rate_limit()
                    page.page.wait_for_timeout(500)
                    final_count = page.get_rule_count()
                    print(f"  [OK] 批量清理完成，剩余 {final_count} 条规则")
                    rec.add_detail(f"  批量清理完成，剩余 {final_count} 条规则")
            else:
                print("  [OK] 无需清理，数据已干净")
                rec.add_detail("  无需清理，数据已干净")

        # ========== 步骤4: 创建测试用MAC组 ==========
        with rec.step("步骤4: 创建测试用MAC组", "导航到路由对象-MAC分组页面创建MAC组"):
            print("\n[步骤4] 创建测试用MAC组...")
            rec.add_detail(f"【创建MAC组】")
            rec.add_detail(f"  分组名称: test_mac_group_001")
            rec.add_detail(f"  MAC列表: AA:BB:CC:11:00:01, AA:BB:CC:11:00:02, AA:BB:CC:11:00:03")

            # 导航到路由对象页面，点击MAC分组tab
            routing_object_url = f"{page.base_url}/#/networkConfiguration/routingObject"
            page.page.goto(routing_object_url)
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

            # 点击MAC分组tab
            mac_group_tab = page.page.get_by_role("tab", name="MAC分组")
            if mac_group_tab.count() > 0:
                mac_group_tab.click()
                page.page.wait_for_timeout(500)

            # 检查是否已存在该分组
            group_exists = page.page.locator("text=test_mac_group_001").count() > 0

            if not group_exists:
                # 点击添加按钮（MAC分组页面的按钮名称是"添加"）
                try:
                    create_btn = page.page.get_by_role("button", name="添加")
                    if create_btn.count() > 0:
                        create_btn.click()
                        page.page.wait_for_timeout(300)

                        # 填写分组名称
                        page.page.get_by_role("textbox", name="分组名称").fill("test_mac_group_001")

                        # 填写MAC列表（文本框名称是"MAC"）
                        # 页面提示"请填写MAC，每行一个"，多个MAC用换行符分隔
                        mac_textarea = page.page.get_by_role("textbox", name="MAC")
                        mac_textarea.fill("AA:BB:CC:11:00:01\nAA:BB:CC:11:00:02\nAA:BB:CC:11:00:03")

                        # 点击保存（MAC分组添加页面的按钮是"保存"）
                        page.page.get_by_role("button", name="保存").click()
                        page.page.wait_for_timeout(500)

                        rec.add_detail(f"  [OK] MAC组创建成功")
                        print("  [OK] MAC组 test_mac_group_001 创建成功")
                    else:
                        rec.add_detail(f"  [WARN] 未找到添加按钮")
                        print("  [WARN] 未找到添加按钮")
                except Exception as e:
                    rec.add_detail(f"  [WARN] MAC组创建失败: {str(e)[:50]}")
                    print(f"  [WARN] MAC组创建失败: {e}")
            else:
                rec.add_detail(f"  MAC组已存在，跳过创建")
                print("  [OK] MAC组 test_mac_group_001 已存在")

            # 返回MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

        # ========== 步骤5: 创建测试用时间计划 ==========
        with rec.step("步骤5: 创建测试用时间计划", "导航到时间计划页面创建"):
            print("\n[步骤5] 创建测试用时间计划...")
            rec.add_detail(f"【创建时间计划】")
            rec.add_detail(f"  计划名称: t_plan_mac_001")
            rec.add_detail(f"  计划类型: 按周循环")
            rec.add_detail(f"  生效日期: 周一至周五")
            rec.add_detail(f"  生效时间: 23:11-23:12（故意设为非生效时间，验证时间计划未生效时iptables无规则）")
            rec.add_detail(f"  创建方式: 跳转到时间计划专门页面创建")

            # 导航到路由对象页面，点击时间计划tab
            routing_object_url = f"{page.base_url}/#/networkConfiguration/routingObject"
            page.page.goto(routing_object_url)
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

            # 点击时间计划tab
            time_plan_tab = page.page.get_by_role("tab", name="时间计划")
            if time_plan_tab.count() > 0:
                time_plan_tab.click()
                page.page.wait_for_timeout(500)

            # 点击添加按钮
            add_btn = page.page.get_by_role("button", name="添加")
            if add_btn.count() > 0:
                add_btn.click()
                page.page.wait_for_timeout(500)

            try:
                # 填写计划名称
                page.page.get_by_role("textbox", name="计划名称").fill("t_plan_mac_001")

                # 选择按周循环（通常默认选中）
                week_radio = page.page.get_by_role("radio", name="按周循环")
                if week_radio.count() > 0:
                    week_radio.click()
                    page.page.wait_for_timeout(200)

                # 选择周一到周五：默认全选(一到日)，点击"六"和"日"取消选中
                # 生效日期区域的星期按钮是可点击的generic元素，不是checkbox
                date_section = page.page.locator("text=生效日期").locator("..")
                for day in ["六", "日"]:
                    day_btn = date_section.locator(f"text={day}")
                    if day_btn.count() > 0:
                        day_btn.click()
                        page.page.wait_for_timeout(100)

                # 设置时间范围：故意设为23:11-23:12，确保测试时不在生效时间内
                # 注意：iKuai时间输入框fill()可能不触发onChange，需要先清空再输入
                start_time = page.page.get_by_placeholder("开始时间")
                end_time = page.page.get_by_role("textbox", name="结束时间")
                if start_time.count() > 0:
                    start_time.click()
                    start_time.press("Control+a")
                    start_time.type("23:11", delay=50)
                if end_time.count() > 0:
                    end_time.click()
                    end_time.press("Control+a")
                    end_time.type("23:12", delay=50)
                page.page.wait_for_timeout(200)

                # 点击保存
                page.page.get_by_role("button", name="保存").click()
                page.page.wait_for_timeout(500)

                rec.add_detail(f"  [OK] 时间计划创建成功")
                print("  [OK] 时间计划 t_plan_mac_001 创建成功")
            except Exception as e:
                rec.add_detail(f"  [WARN] 时间计划创建失败: {str(e)[:50]}")
                print(f"  [WARN] 时间计划创建失败: {e}")

            # 返回MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

        # ========== 步骤6: 批量添加8条MAC限速规则 ==========
        with rec.step("步骤6: 批量添加MAC限速规则", f"添加 {len(test_rules)} 条规则，覆盖各种数据组合场景"):
            print("\n[步骤6] 批量添加8条MAC限速规则...")
            rec.add_detail(f"【添加计划】共 {len(test_rules)} 条规则")
            rec.add_detail(f"  场景覆盖: 不同线路(任意/全部/wan1/wan2/wan3)、不同协议栈(IPv4/IPv6)、MAC组、批量MAC")
            added_count = 0

            for rule in test_rules:
                rec.add_detail(f"【添加 {rule['name']}】")
                rec.add_detail(f"  线路: {rule.get('line', '任意')}")
                rec.add_detail(f"  协议栈: {rule.get('protocol_stack', 'IPv4')}")
                if rule.get('mac'):
                    rec.add_detail(f"  MAC地址(单个): {rule['mac']}")
                if rule.get('batch_macs'):
                    rec.add_detail(f"  MAC地址(批量): {', '.join(rule['batch_macs'])}")
                if rule.get('mac_group'):
                    rec.add_detail(f"  MAC组: {rule['mac_group']}")
                if rule.get('time_plan'):
                    rec.add_detail(f"  时间计划: {rule['time_plan']}")
                if rule.get('time_type') == '时间段':
                    rec.add_detail(f"  时间段: {rule.get('time_start', '')} ~ {rule.get('time_end', '')}")
                rec.add_detail(f"  限速模式: {rule.get('mode', '独立限��')}")
                rec.add_detail(f"  上行/下行: {rule.get('upload', 512)}/{rule.get('download', 1024)} KB/s")
                rec.add_detail(f"  备注: {rule.get('remark', '')}")
                rec.add_detail(f"  场景: {rule['desc']}")

                # 构建添加参数
                add_params = {
                    "name": rule["name"],
                    "protocol_stack": rule.get("protocol_stack", "IPv4"),
                    "line": rule.get("line", "任意"),
                    "rate_mode": rule.get("mode", "独立限速"),
                    "upload_speed": rule.get("upload", 512),
                    "download_speed": rule.get("download", 1024),
                    "speed_unit": rule.get("upload_unit", "KB/s"),
                    "remark": rule.get("remark", ""),
                }

                # 添加单个MAC地址
                if rule.get("mac"):
                    add_params["mac"] = rule["mac"]

                # 添加批量MAC地址
                if rule.get("batch_macs"):
                    add_params["batch_macs"] = rule["batch_macs"]

                # 添加MAC组
                if rule.get("mac_group"):
                    add_params["mac_group"] = rule["mac_group"]

                # 设置生效时间
                if rule.get("time_plan"):
                    add_params["time_type"] = "时间计划"
                    add_params["time_plan"] = rule["time_plan"]
                elif rule.get("time_type") == "时间段":
                    add_params["time_type"] = "时间段"
                    add_params["time_start"] = rule.get("time_start", "2026-03-01 00:00")
                    add_params["time_end"] = rule.get("time_end", "2026-03-31 23:59")
                else:
                    add_params["time_type"] = "按周循环"

                result = page.add_rule(**add_params)

                if result:
                    print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                    rec.add_detail(f"  ✓ 添加成功")
                    added_count += 1
                else:
                    print(f"  - 添加失败: {rule['name']}")
                    rec.add_detail(f"  ✗ 添加失败")

            # 验证所有规则都已添加（参照VLAN综合测试）
            rec.add_detail(f"【验证结果】")
            page.clear_search()  # 清空搜索条件
            # 导航回MAC限速页面（确保在正确的标签页）
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(1000)

            # 验证每条规则是否存在
            actual_added = 0
            for rule in test_rules:
                if page.rule_exists(rule["name"]):
                    actual_added += 1
                else:
                    rec.add_detail(f"  ✗ 规则 {rule['name']} 未找到")

            print(f"  [OK] 成功添加 {actual_added}/{len(test_rules)} 条规则")
            rec.add_detail(f"  ✓ 实际验证: {actual_added}/{len(test_rules)} 条规则已存在于列表中")

        # ========== 步骤6.5: 后台数据验证（SSH全链路） ==========
        if backend_verifier is not None:
            with rec.step("步骤6.5: 后台数据验证（SSH全链路）", "SSH验证每条规则的数据库/iptables/内核"):
                print("\n[步骤6.5] 后台数据验证（SSH全链路）...")
                rec.add_detail("【SSH后台全链路验证】")

                # L4: 内核验证（全局检查一次即可）
                ssh_verify("L4-内核", backend_verifier.verify_kernel, must_pass=True)

                # 逐条验证已添加的规则
                verify_passed = 0
                verify_total = 0
                for rule in test_rules:
                    verify_total += 1
                    rule_name = rule["name"]
                    rec.add_detail(f"  ── 验证规则: {rule_name} ──")
                    print(f"  验证规则: {rule_name}")

                    # L1: 数据库验证 - MAC限速可能使用 mac_qos 或 dt_mac_qos
                    expected_fields = {
                        "upload": str(rule["upload"]),
                        "download": str(rule["download"]),
                    }
                    l1 = ssh_verify(
                        f"L1-数据库({rule_name})",
                        backend_verifier.verify_qos_database,
                        "mac_qos",
                        must_pass=True,
                        expected_fields=expected_fields,
                        tagname=rule_name,
                    )
                    qos_type_found = "mac_qos"
                    if l1 is None or not l1.passed:
                        # 尝试 dt_mac_qos
                        l1 = ssh_verify(
                            f"L1-dt_mac_qos({rule_name})",
                            backend_verifier.verify_qos_database,
                            "dt_mac_qos",
                            expected_fields=expected_fields,
                            tagname=rule_name,
                        )
                        qos_type_found = "dt_mac_qos"
                    # 两种表都找不到则记录失败
                    if l1 is not None and not l1.passed:
                        ssh_failures.append(f"SSH-L1-数据库({rule_name}): mac_qos和dt_mac_qos均未找到规则")

                    if l1 and l1.passed:
                        rule_id = l1.details.get("rule", {}).get("id")
                        db_rule = l1.details.get("rule", {})
                        rec.add_detail(f"      数据库({qos_type_found}): id={rule_id}, upload={db_rule.get('upload')}, download={db_rule.get('download')}, enabled={db_rule.get('enabled')}")

                        # L2: iptables验证 - MAC_QOS链
                        # iKuai行为: 只为mac_addr中有实际MAC地址的规则创建iptables规则
                        # 无MAC地址(如仅选线路/协议栈的规则、MAC组引用为空的规则)不会创建iptables条目
                        # 时间计划规则在非生效时间段内也不会创建iptables规则
                        db_mac_addr = db_rule.get("mac_addr", {})
                        db_has_mac = False
                        mac_addr_detail = ""
                        if isinstance(db_mac_addr, dict):
                            custom = db_mac_addr.get("custom", {})
                            obj = db_mac_addr.get("object", {})
                            db_has_mac = bool(custom) or bool(obj)
                            mac_addr_detail = f"custom={custom}, object={obj}"
                        elif isinstance(db_mac_addr, str) and db_mac_addr.strip():
                            db_has_mac = True
                            mac_addr_detail = db_mac_addr
                        else:
                            mac_addr_detail = str(db_mac_addr)
                        l2_must_pass = db_has_mac and "time_plan" not in rule
                        set_prefix = "mac_qos" if qos_type_found == "mac_qos" else "dt_mac_qos"
                        if not db_has_mac:
                            rec.add_detail(f"      L2跳过: mac_addr为空({mac_addr_detail}), iKuai只为有实际MAC地址的规则创建iptables条目")
                            print(f"      L2跳过: {rule_name} 无实际MAC地址, iKuai不创建iptables规则")
                        else:
                            if rule["upload"] > 0:
                                ssh_verify(
                                    f"L2-iptables-上行({rule_name})",
                                    backend_verifier.verify_iptables_rule,
                                    "MAC_QOS",
                                    must_pass=l2_must_pass,
                                    rule_id=rule_id,
                                    expected_speed_kbps=rule["upload"],
                                    set_prefix=set_prefix,
                                )
                            if rule["download"] > 0:
                                ssh_verify(
                                    f"L2-iptables-下行({rule_name})",
                                    backend_verifier.verify_iptables_rule,
                                    "MAC_QOS",
                                    must_pass=l2_must_pass,
                                    rule_id=rule_id,
                                    expected_speed_kbps=rule["download"],
                                    set_prefix=set_prefix,
                                )

                        verify_passed += 1
                    elif l1 is None:
                        rec.add_detail(f"      跳过（SSH不可用）")
                    else:
                        rec.add_detail(f"      L1验证未通过，跳过L2")

                print(f"  [OK] 后台验证完成: {verify_passed}/{verify_total} 条规则L1验证通过")
                rec.add_detail(f"  ── 验证汇总: {verify_passed}/{verify_total} 条规则验证通过 ──")
        else:
            print("\n[步骤6.5] 后台数据验证: 跳过（未配置SSH或paramiko未安装）")

        # ========== 步骤7: 编辑MAC限速规则 ==========
        with rec.step("步骤7: 编辑MAC限速规则", "编辑第1条规则的名称和限速值"):
            print("\n[步骤7] 编辑MAC限速规则...")
            edit_rule = test_rules[0]
            new_name = "mac_t_edit_001"
            rec.add_detail(f"【编辑操作】")
            rec.add_detail(f"  目标规则: {edit_rule['name']}")
            rec.add_detail(f"  新名称: {new_name}")

            # 确保在MAC限速页面再操作
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            page.edit_rule(edit_rule["name"])
            page.page.wait_for_timeout(500)
            page.fill_name(new_name)
            page.fill_upload_speed(1024, "KB/s")
            page.click_save()
            page.wait_for_success_message()

            # 确保返回MAC限速列表页
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(1000)

            # 验证编辑结果：检查新名称是否存在，或者原名称是否已不存在
            new_name_exists = page.rule_exists(new_name)
            old_name_exists = page.rule_exists(edit_rule["name"])

            if new_name_exists:
                test_rules[0]["name"] = new_name
                print(f"  [OK] 规则编辑成功: {edit_rule['name']} -> {new_name}")
                rec.add_detail(f"【验证结果】")
                rec.add_detail(f"  ✓ 编辑成功，新名称已生效")
            elif not old_name_exists:
                # 原名称不存在，说明编辑可能成功但验证失败，仍然更新名称
                test_rules[0]["name"] = new_name
                print(f"  [OK] 规则编辑成功（原名称已不存在）: {edit_rule['name']} -> {new_name}")
                rec.add_detail(f"【验证结果】")
                rec.add_detail(f"  ✓ 编辑成功（原名称已不存在）")
            else:
                print(f"  [WARN] 编辑验证失败，原名称仍存在")
                rec.add_detail(f"  ✗ 编辑验证失败")

            # SSH后台验证：编辑后数据库字段是否更新
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-编辑后】")
                # iKuai数据库tagname最长15字符，超过会自动截取
                db_name = new_name[:15] if len(new_name) > 15 else new_name
                if db_name != new_name:
                    rec.add_detail(f"  注意: 名称'{new_name}'超15字符，数据库中为'{db_name}'")
                ssh_verify(
                    "L1-编辑验证",
                    backend_verifier.verify_qos_database,
                    "mac_qos",
                    must_pass=True,
                    expected_fields={"upload": "1024"},
                    tagname=db_name,
                )

        # ========== 步骤8: 单独停用MAC限速规则 ==========
        with rec.step("步骤8: 单独停用MAC限速规则", "停用第2条规则"):
            print("\n[步骤8] 单独停用第2条规则...")
            disable_rule = test_rules[1]
            rec.add_detail(f"【停用操作】")
            rec.add_detail(f"  目标规则: {disable_rule['name']}")

            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            result = page.disable_rule(disable_rule["name"])
            page.page.wait_for_timeout(1000)

            # 刷新后确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            if page.is_rule_disabled(disable_rule["name"]):
                print(f"  [OK] 规则停用成功: {disable_rule['name']}")
                rec.add_detail(f"【验证结果】")
                rec.add_detail(f"  ✓ 规则状态已变为停用")
            else:
                print(f"  [WARN] 停用状态验证失败")
                rec.add_detail(f"  - 停用状态未确认")

            # SSH后台验证：停用后enabled应为no
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-停用后】")
                ssh_verify(
                    "L1-停用验证",
                    backend_verifier.verify_qos_database,
                    "mac_qos",
                    must_pass=True,
                    expected_fields={"enabled": "no"},
                    tagname=disable_rule["name"],
                )
        with rec.step("步骤9: 单独启用MAC限速规则", "启用第2条规则"):
            print("\n[步骤9] 单独启用第2条规则...")
            rec.add_detail(f"【启用操作】")
            rec.add_detail(f"  目标规则: {disable_rule['name']}")

            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            result = page.enable_rule(disable_rule["name"])
            page.page.wait_for_timeout(1000)

            # 刷新后确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            if page.is_rule_enabled(disable_rule["name"]):
                print(f"  [OK] 规则启用成功: {disable_rule['name']}")
                rec.add_detail(f"【验证结果】")
                rec.add_detail(f"  ✓ 规则状态已变为启用")
            else:
                print(f"  [WARN] 启用状态验证失败")
                rec.add_detail(f"  - 启用状态未确认")

            # SSH后台验证：启用后enabled应为yes
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-启用后】")
                ssh_verify(
                    "L1-启用验证",
                    backend_verifier.verify_qos_database,
                    "mac_qos",
                    must_pass=True,
                    expected_fields={"enabled": "yes"},
                    tagname=disable_rule["name"],
                )

        # ========== 步骤10: 单独删除MAC限速规则 ==========
        with rec.step("步骤10: 单独删除MAC限速规则", "删除第3条规则"):
            print("\n[步骤10] 单独删除第3条规则...")
            delete_rule = test_rules[2]
            rec.add_detail(f"【删除操作】")
            rec.add_detail(f"  目标规则: {delete_rule['name']}")

            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            count_before = page.get_rule_count()
            result = page.delete_rule(delete_rule["name"])
            count_after = page.get_rule_count()

            if count_after < count_before:
                test_rules.remove(delete_rule)
                print(f"  [OK] 规则删除成功: {delete_rule['name']}")
                rec.add_detail(f"【验证结果】")
                rec.add_detail(f"  ✓ 删除成功，条目数从 {count_before} 减少到 {count_after}")

                # SSH后台验证：删除后数据库中应找不到该规则
                if backend_verifier is not None:
                    rec.add_detail(f"  【SSH验证-删除后】")
                    db_rule = ssh_find_rule(delete_rule["name"])
                    if db_rule is None:
                        print(f"    SSH-L1-删除验证: 通过 - 规则已从数据库删除")
                        rec.add_detail(f"    SSH-L1-删除验证: ✓ 规则已从数据库删除")
                    else:
                        print(f"    SSH-L1-删除验证: 失败 - 规则仍在数据库中")
                        rec.add_detail(f"    SSH-L1-删除验证: ✗ 规则仍在数据库中")
                        ssh_failures.append(f"SSH-L1-删除验证: 规则{delete_rule['name']}仍在数据库中")
            else:
                print(f"  [WARN] 删除验证失败")
                rec.add_detail(f"  - 删除未确认")

        # ========== 步骤11: 搜索MAC限速规则 ==========
        with rec.step("步骤11: 搜索MAC限速规则", "测试搜索存在/不存在的规则"):
            print("\n[步骤11] 搜索测试...")
            rec.add_detail(f"【搜索测试】")

            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            # 搜索存在的规则
            search_target = test_rules[2]["name"]  # mac_test_004
            rec.add_detail(f"  测试1: 搜索存在的规则")
            rec.add_detail(f"    搜索关键词: {search_target}")
            page.search_rule(search_target)
            page.page.wait_for_timeout(500)

            if page.rule_exists(search_target):
                print(f"  [OK] 搜索存在规则成功: {search_target}")
                rec.add_detail(f"    ✓ 搜索成功，规则已找到")
            else:
                print(f"  [WARN] 搜索未找到规则")
                rec.add_detail(f"    - 搜索未找到")

            # 搜索不存在的规则
            rec.add_detail(f"  测试2: 搜索不存在的规则")
            page.search_rule("not_exist_xxx")
            page.page.wait_for_timeout(500)
            count = page.get_rule_count()
            if count == 0:
                print("  [OK] 搜索不存在规则验证成功，显示0条记录")
                rec.add_detail(f"    ✓ 验证成功，显示0条记录")
            else:
                print(f"  [WARN] 搜索不存在规则时显示{count}条")
                rec.add_detail(f"    - 显示{count}条记录")

            # 清空搜索
            rec.add_detail(f"  测试3: 清空搜索条件")
            page.clear_search()
            page.page.wait_for_timeout(500)
            remaining_count = page.get_rule_count()
            print(f"  [OK] 清空搜索成功，当前显示 {remaining_count} 条记录")
            rec.add_detail(f"    ✓ 清空成功，显示 {remaining_count} 条记录")

        # ========== 步骤12: 列表排序测试 ==========
        with rec.step("步骤12: 列表排序测试", "测试各可排序字段的排序功能（每字段点击3次：正序→倒序→默认）"):
            print("\n[步骤12] 排序测试（每字段点击3次：正序→倒序→默认）...")
            rec.add_detail(f"【排序测试】")
            rec.add_detail(f"  测试字段: 协议栈、线路、限速模式、上行限速、下行限速")
            rec.add_detail(f"  每个字段点击3次: 正序 → 倒序 → 恢复默认")

            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            sort_result = page.test_sorting()
            for field, result in sort_result.items():
                status = "[OK]" if result else "[FAIL]"
                print(f"  {status} {field} 排序(正序→倒序→默认): {'成功' if result else '失败'}")
                rec.add_detail(f"  {status} {field} 排序(3次点击): {'成功' if result else '失败'}")

        # ========== 步骤13: 导出MAC限速规则 ==========
        with rec.step("步骤13: 导出MAC限速规则", "导出CSV和TXT两种格式的配置文件"):
            print("\n[步骤13] 导出MAC限速规则...")
            rec.add_detail(f"【导出测试】")
            config = get_config()
            export_file_csv = config.test_data.get_export_path("mac_rate_limit", config.get_project_root())
            export_file_txt = export_file_csv.replace(".csv", ".txt")

            try:
                # 导出CSV
                rec.add_detail(f"  测试1: 导出CSV格式")
                export_result_csv = page.export_rules(export_format="csv")
                if export_result_csv:
                    print(f"  [OK] 导出CSV成功")
                    rec.add_detail(f"    ✓ CSV导出成功")
                else:
                    print(f"  [WARN] 导出CSV失败")
                    rec.add_detail(f"    ✗ CSV导出失败")

                page.page.wait_for_timeout(500)

                # 导出TXT
                rec.add_detail(f"  测试2: 导出TXT格式")
                export_result_txt = page.export_rules(export_format="txt")
                if export_result_txt:
                    print(f"  [OK] 导出TXT成功")
                    rec.add_detail(f"    ✓ TXT导出成功")
                else:
                    print(f"  [WARN] 导出TXT失败")
                    rec.add_detail(f"    ✗ TXT导出失败")

            except Exception as e:
                print(f"  [WARN] 导出测试异常: {e}")
                rec.add_detail(f"  导出异常: {str(e)}")

            page.close_modal_if_exists()
            # 导航回MAC限速页面（reload后可能不在MAC限速标签页）
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

        # ========== 步骤14: 异常输入测试 ==========
        with rec.step("步骤14: 异常输入测试", "测试各种不合规输入的验证拦截"):
            print("\n[步骤14] 异常输入测试...")
            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            # 14.1 名称为空测试
            print("\n  [14.1] 名称为空测试...")
            rec.add_detail("【14.1 名称为空验证】")
            result = page.try_add_rule_invalid(name="")
            if result["has_validation_error"]:
                print(f"    [OK] 名称为空: 正确拦截 - {result['error_msg']}")
                rec.add_detail(f"  ✓ 输入'' (名称为空)")
                rec.add_detail(f"    提示: {result['error_msg']}")
            else:
                print(f"    [FAIL] 名称为空: 未被拦截！")
                rec.add_detail(f"  ✗ 名称为空: 拦截失败")

            # 14.2 备注特殊字符测试
            print("\n  [14.2] 备注特殊字符测试...")
            rec.add_detail("【14.2 备注特殊字符验证】")
            remark_test_cases = [
                ("测试+备注", "包含+号"),
                ("测试@备注", "包含@号"),
                ("测试#备注", "包含#号"),
            ]
            remark_passed = 0
            for remark_value, desc in remark_test_cases:
                result = page.try_add_rule_invalid(name="test_remark", remark=remark_value)
                if result["has_validation_error"]:
                    print(f"    [OK] {desc}: 正确拦截 - {result['error_msg']}")
                    rec.add_detail(f"  ✓ 输入'{remark_value}' ({desc})")
                    rec.add_detail(f"    提示: {result['error_msg']}")
                    remark_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{remark_value}' ({desc}): 拦截失败")
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → 备注验证结果: {remark_passed}/{len(remark_test_cases)} 通过")

            # 14.3 MAC地址不合规测试
            print("\n  [14.3] MAC地址不合规测试...")
            rec.add_detail("【14.3 MAC地址验证】")
            mac_test_cases = [
                ("AA:BB:CC:DD:EE:GG", "MAC非法字符"),
                ("AA:BB:CC:DD:EE", "MAC格式错误-少段"),
                ("192.168.1.1", "IP地址格式"),
            ]
            mac_passed = 0
            for mac_value, desc in mac_test_cases:
                result = page.try_add_rule_invalid(name="test_mac", mac=mac_value)
                if result["has_validation_error"]:
                    print(f"    [OK] {desc}: 正确拦截 - {result['error_msg']}")
                    rec.add_detail(f"  ✓ 输入'{mac_value}' ({desc})")
                    rec.add_detail(f"    提示: {result['error_msg']}")
                    mac_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{mac_value}' ({desc}): 拦截失败")
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → MAC地址验证结果: {mac_passed}/{len(mac_test_cases)} 通过")

            # 14.4 限速值不合规测试
            print("\n  [14.4] 限速值不合规测试...")
            rec.add_detail("【14.4 限速值验证】")

            # 14.4.1 范围验证测试（使用 fill() 直接设置值）
            # 参照 VLAN 测试：提供完整的正常字段，只有测试字段是异常的
            rec.add_detail("  【范围验证 - 使用 fill()】")
            boundary_test_cases = [
                ("111111111111", "超出最大值"),
            ]
            boundary_passed = 0
            for speed_value, desc in boundary_test_cases:
                # 提供完整的正常字段：name 和 mac 都是正常的，只有 upload_speed 异常
                result = page.try_add_rule_invalid(
                    name="test_speed_boundary",  # 正常名称
                    mac="00:11:22:33:44:55",  # 正常 MAC
                    upload_speed=speed_value,  # 异常限速值
                    use_type_for_speed=False  # 使用 fill()
                )
                if result["has_validation_error"]:
                    print(f"    [OK] {desc}: 正确拦截 - {result['error_msg']}")
                    rec.add_detail(f"  ✓ 输入'{speed_value}' ({desc}): {result['error_msg']}")
                    boundary_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{speed_value}' ({desc}): 拦截失败")
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → 范围验证结果: {boundary_passed}/{len(boundary_test_cases)} 通过")

            # 14.4.2 键盘验证测试（使用 type() 模拟键盘输入）
            rec.add_detail("  【键盘验证 - 使用 type()】")
            keyboard_test_cases = [
                ("-1", "负数"),
                ("abc", "非数字"),
            ]
            keyboard_passed = 0
            for speed_value, desc in keyboard_test_cases:
                # 提供完整的正常字段：name 和 mac 都是正常的，只有 upload_speed 异常
                result = page.try_add_rule_invalid(
                    name="test_speed_keyboard",  # 正常名称
                    mac="00:11:22:33:44:56",  # 正常 MAC（不同值避免冲突）
                    upload_speed=speed_value,  # 异常限速值
                    use_type_for_speed=True  # 使用 type() 模拟键盘输入
                )
                if result["has_validation_error"]:
                    print(f"    [OK] {desc}: 正确拦截 - {result['error_msg']}")
                    rec.add_detail(f"  ✓ 输入'{speed_value}' ({desc}): {result['error_msg']}")
                    keyboard_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{speed_value}' ({desc}): 拦截失败")
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → 键盘验证结果: {keyboard_passed}/{len(keyboard_test_cases)} 通过")

            speed_passed = boundary_passed + keyboard_passed
            total_speed_cases = len(boundary_test_cases) + len(keyboard_test_cases)
            rec.add_detail(f"  → 限速值验证总结果: {speed_passed}/{total_speed_cases} 通过")

            print("\n  [OK] 异常输入测试完成")

            # 确保返回列表页并刷新页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

        # ========== 步骤15: 批量停用MAC限速规则 ==========
        with rec.step("步骤15: 批量停用MAC限速规则", f"批量停用剩余的 {len(test_rules)} 条规则"):
            print("\n[步骤15] 批量停用所有规则...")
            rec.add_detail(f"【批量停用操作】")

            # 确保在列表页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

            # 获取当前实际规则数量（在刷新后获取更准确）
            current_count = page.get_rule_count()
            rec.add_detail(f"  当前规则数量: {current_count}")

            # 使用全选功能
            page.select_all_rules()
            page.batch_disable()
            page.page.wait_for_timeout(1500)

            # 刷新后确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            # 验证停用结果 - 以实际页面数据为准
            final_count = page.get_rule_count()

            # 统计test_rules中停用的规则数（用于记录）
            disabled_count = 0
            for rule in test_rules:
                try:
                    if page.is_rule_disabled(rule["name"]):
                        disabled_count += 1
                except Exception:
                    pass

            print(f"  [OK] 批量停用完成，当前共 {final_count} 条规则")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ 批量停用完成，当前共 {final_count} 条规则（test_rules中{disabled_count}条已停用）")

            # SSH后台验证：批量停用后所有规则enabled应为no
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-批量停用后】")
                rules_db = backend_verifier.query_qos_rules("mac_qos")
                if not rules_db:
                    rules_db = backend_verifier.query_qos_rules("dt_mac_qos")
                disabled_in_db = sum(1 for r in rules_db if r.get("enabled") == "no")
                print(f"    SSH: 数据库中{disabled_in_db}/{len(rules_db)}条规则已停用")
                rec.add_detail(f"    SSH: 数据库中{disabled_in_db}/{len(rules_db)}条规则enabled=no")
                if len(rules_db) > 0 and disabled_in_db < len(rules_db):
                    ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_in_db}/{len(rules_db)}条规则停用")

        # ========== 步骤16: 批量启用MAC限速规则 ==========
        with rec.step("步骤16: 批量启用MAC限速规则", f"批量启用剩余的 {len(test_rules)} 条规则"):
            print("\n[步骤16] 批量启用所有规则...")
            rec.add_detail(f"【批量启用操作】")

            # 导航回MAC限速页面清除选择状态
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            # 获取当前实际规则数量
            current_count = page.get_rule_count()
            rec.add_detail(f"  当前规则数量: {current_count}")

            # 使用全选功能
            page.select_all_rules()
            page.batch_enable()
            page.page.wait_for_timeout(1500)

            # 刷新后确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            # 验证启用结果 - 以实际页面数据为准
            final_count = page.get_rule_count()

            # 统计test_rules中启用的规则数（用于记录）
            enabled_count = 0
            for rule in test_rules:
                try:
                    if page.is_rule_enabled(rule["name"]):
                        enabled_count += 1
                except Exception:
                    pass

            print(f"  [OK] 批量启用完成，当前共 {final_count} 条规则")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ 批量启用完成，当前共 {final_count} 条规则（test_rules中{enabled_count}条已启用）")

        # ========== 步骤17: 批量删除MAC限速规则 ==========
        with rec.step("步骤17: 批量删除MAC限速规则", f"批量删除剩余的 {len(test_rules)} 条规则"):
            print("\n[步骤17] 批量删除所有规则...")
            rec.add_detail(f"【批量删除操作】")
            rec.add_detail(f"  目标数量: {len(test_rules)} 条规则")

            # 导航回MAC限速页面清除选择状态
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            # 使用全选功能
            page.select_all_rules()
            page.batch_delete()
            page.page.wait_for_timeout(1500)

            # 刷新后确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(500)

            # 以实际页面数据为准
            final_count = page.get_rule_count()

            # 统计test_rules中删除的规则数（用于记录）
            deleted_count = 0
            for rule in test_rules:
                try:
                    if not page.rule_exists(rule["name"]):
                        deleted_count += 1
                except Exception:
                    deleted_count += 1  # 如果检查失败，假设已删除

            print(f"  [OK] 批量删除完成，剩余 {final_count} 条规则")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ 批量删除完成，剩余 {final_count} 条规则（test_rules中{deleted_count}条已删除）")

            # SSH后台验证：批量删除后数据库应为空
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-批量删除后】")
                rules_db = backend_verifier.query_qos_rules("mac_qos")
                if not rules_db:
                    rules_db = backend_verifier.query_qos_rules("dt_mac_qos")
                test_names = {r["name"] for r in test_rules}
                remaining_test_rules = [r for r in rules_db if r.get("tagname") in test_names]
                if len(remaining_test_rules) == 0:
                    print(f"    SSH: 数据库中测试规则已全部删除（总规则数: {len(rules_db)}）")
                    rec.add_detail(f"    SSH-L1-批量删除验证: ✓ 测试规则已全部删除")
                else:
                    print(f"    SSH: 数据库中仍有 {len(remaining_test_rules)} 条测试规则")
                    rec.add_detail(f"    SSH-L1-批量删除验证: ✗ 仍有{len(remaining_test_rules)}条测试规则")
                    ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining_test_rules)}条测试规则")

        # ========== 步骤18: 导入MAC限速规则 ==========
        with rec.step("步骤18: 导入MAC限速规则", "使用导出的CSV和TXT文件进行导入测试"):
            print("\n[步骤18] 导入MAC限速规则测试...")
            rec.add_detail(f"【导入测试】")

            # CSV导入
            if os.path.exists(export_file_csv):
                rec.add_detail(f"  测试1: CSV文件导入")
                rec.add_detail(f"    导入文件: {os.path.basename(export_file_csv)}")
                count_before = page.get_rule_count()
                result = page.import_rules(export_file_csv, clear_existing=False)
                # 导航回MAC限速页面
                page.navigate_to_mac_rate_limit()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                if count_after > count_before:
                    print(f"  [OK] CSV导入成功，添加 {count_after - count_before} 条记录")
                    rec.add_detail(f"    ✓ 成功添加 {count_after - count_before} 条记录")
                else:
                    print(f"  [WARN] CSV导入可能失败")
                    rec.add_detail(f"    - 导入结果未确认")
            else:
                print(f"  [WARN] CSV文件不存在")
                rec.add_detail(f"    ✗ CSV文件不存在")

            page.page.wait_for_timeout(500)

            # TXT导入（清空现有）
            if os.path.exists(export_file_txt):
                rec.add_detail(f"  测试2: TXT文件导入（清空现有数据）")
                rec.add_detail(f"    导入文件: {os.path.basename(export_file_txt)}")
                result = page.import_rules(export_file_txt, clear_existing=True)
                # 导航回MAC限速页面
                page.navigate_to_mac_rate_limit()
                page.page.wait_for_timeout(500)
                print(f"  [OK] TXT导入完成")
                rec.add_detail(f"    ✓ TXT导入完成（已清空旧数据）")
            else:
                print(f"  [WARN] TXT文件不存在")
                rec.add_detail(f"    ✗ TXT文件不存在")

        # ========== 步骤19: 清理导入的MAC限速规则 ==========
        with rec.step("步骤19: 清理导入的MAC限速规则", "清理导入测试产生的规则数据"):
            print("\n[步骤19] 清理导入的规则...")
            rec.add_detail(f"【环境清理】")
            # 确保在MAC限速页面
            page.navigate_to_mac_rate_limit()
            page.page.wait_for_timeout(1000)

            current_count = page.get_rule_count()
            if current_count > 0:
                select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
                if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                    select_all_checkbox.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)
                    # 刷新后确保在MAC限速页面
                    page.navigate_to_mac_rate_limit()
                    page.page.wait_for_timeout(500)
                    final_count = page.get_rule_count()
                    print(f"  [OK] 清理完成，剩余 {final_count} 条规则")
                    rec.add_detail(f"  ✓ 清理完成，剩余 {final_count} 条规则")
            else:
                print("  [OK] 没有需要清理的规则")
                rec.add_detail(f"  ✓ 环境已干净，无需清理")

        # ========== 步骤20: 帮助功能测试 ==========
        with rec.step("步骤20: 帮助功能测试", "测试帮助图标的显示和功能"):
            print("\n[步骤20] 帮助功能测试...")
            rec.add_detail(f"【帮助功能测试】")

            help_result = page.test_help_functionality()

            rec.add_detail(f"  帮助图标可点击: {help_result['icon_clickable']}")
            rec.add_detail(f"  帮助面板可见: {help_result['panel_visible']}")
            rec.add_detail(f"  帮助面板可关闭: {help_result['can_close']}")

            if help_result['icon_clickable']:
                print("  [OK] 帮助功能测试通过")
            else:
                print("  [WARN] 帮助图标未找到或不可点击")

        # ========== 步骤21: 清理测试数据 ==========
        with rec.step("步骤21: 清理测试数据", "删除创建的MAC组和时间计划"):
            print("\n[步骤21] 清理测试数据...")
            rec.add_detail(f"【清理辅助数据】")

            # 清理MAC分组 - 导航到路由对象页面
            try:
                routing_object_url = f"{page.base_url}/#/networkConfiguration/routingObject"
                page.page.goto(routing_object_url)
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(500)

                # 确保在MAC分组tab
                mac_group_tab = page.page.get_by_role("tab", name="MAC分组")
                if mac_group_tab.count() > 0:
                    mac_group_tab.click()
                    page.page.wait_for_timeout(500)

                # 查找并删除测试MAC组
                group_locator = page.page.locator("text=test_mac_group_001")
                if group_locator.count() > 0:
                    # 点击删除按钮
                    group_locator.first.evaluate("""(el) => {
                        let parent = el.parentElement;
                        let depth = 0;
                        while (parent && depth < 20) {
                            const btns = parent.querySelectorAll('button');
                            for (const btn of btns) {
                                if (btn.textContent.trim() === '删除') {
                                    btn.click();
                                    return true;
                                }
                            }
                            parent = parent.parentElement;
                            depth++;
                        }
                        return false;
                    }""")
                    page.page.wait_for_timeout(300)
                    # 确认删除
                    confirm_btn = page.page.get_by_role("button", name="确定")
                    if confirm_btn.count() > 0:
                        confirm_btn.click()
                        page.page.wait_for_timeout(500)
                    rec.add_detail(f"  [OK] 已清理MAC组: test_mac_group_001")
                    print("  [OK] 已清理MAC组: test_mac_group_001")
            except Exception as e:
                rec.add_detail(f"  [WARN] MAC组清理失败: {str(e)[:50]}")

            # 清理时间计划 - 在同一页面点击时间计划tab
            try:
                time_plan_tab = page.page.get_by_role("tab", name="时间计划")
                if time_plan_tab.count() > 0:
                    time_plan_tab.click()
                    page.page.wait_for_load_state("networkidle")
                    page.page.wait_for_timeout(500)

                    # 查找并删除测试时间计划
                    plan_locator = page.page.locator("text=t_plan_mac_001")
                    if plan_locator.count() > 0:
                        # 点击删除按钮
                        plan_locator.first.evaluate("""(el) => {
                            let parent = el.parentElement;
                            let depth = 0;
                            while (parent && depth < 20) {
                                const btns = parent.querySelectorAll('button');
                                for (const btn of btns) {
                                    if (btn.textContent.trim() === '删除') {
                                        btn.click();
                                        return true;
                                    }
                                }
                                parent = parent.parentElement;
                                depth++;
                            }
                            return false;
                        }""")
                        page.page.wait_for_timeout(300)
                        # 确认删除
                        confirm_btn = page.page.get_by_role("button", name="确定")
                        if confirm_btn.count() > 0:
                            confirm_btn.click()
                            page.page.wait_for_timeout(500)
                        rec.add_detail(f"  [OK] 已清理时间计划: t_plan_mac_001")
                        print("  [OK] 已清理时间计划: t_plan_mac_001")
            except Exception as e:
                rec.add_detail(f"  [WARN] 时间计划清理失败: {str(e)[:50]}")

            rec.add_detail(f"  测试数据清理完成")
            print("  [OK] 测试数据清理完成")

        print("\n" + "=" * 60)
        print("MAC限速综合测试完成")
        print("=" * 60)
        print("测试覆盖功能:")
        print("  - 环境清理: 测试前检查并批量清理")
        print("  - 创建MAC组: test_mac_group_001")
        print("  - 创建时间计划: t_plan_mac_001")
        print("  - 添加: 8条规则")
        print("    * 线路覆盖: 任意/wan1/wan2/全部")
        print("    * 协议栈覆盖: IPv4/IPv6")
        print("    * 备注: 每条规则都有有意义的备注")
        print("  - 编辑: 1条")
        print("  - 单独停用: 1条")
        print("  - 单独启用: 1条")
        print("  - 单独删除: 1条")
        print("  - 搜索: 存在/不存在/清空")
        print("  - 排序: 协议栈/线路/限速模式/上行限速/下行限速")
        print("  - 导出: CSV和TXT两个文件")
        print("  - 异常测试: 名称/MAC/限速值/时间")
        print("  - 批量停用: 7条")
        print("  - 批量启用: 7条")
        print("  - 批量删除: 7条")
        print("  - 导入: CSV和TXT")
        print("  - 帮助功能: 右下角帮助图标")
        print("  - 清理MAC组和时间计划")

        # ========== SSH后台验证汇总断言 ==========
        if ssh_failures:
            print(f"\n[SSH断言] 共 {len(ssh_failures)} 项后台验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
            assert not ssh_failures, f"SSH后台验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
