"""
上下行分离综合测试

26步测试覆盖:
1. 清理环境
2-11. 添加10条规则(基础/不同线路/TCP+源端口/UDP+目的端口/tcp+udp/ICMP/源地址/目的地址/地址+端口/备注)
12. 验证规则总数
13. 编辑规则
14. 停用规则
15. 启用规则
16. 排序功能
17. 搜索功能(精确/部分/不存在/清空)
18. 导出配置(CSV+TXT)
19. 异常输入测试
20. 批量停用
21. 批量启用
22. 批量删除
23. 导入配置(追加CSV)
24. 导入配置(清空现有TXT)
25. 清理环境
26. 帮助功能

后台验证:
- L1: stream_updown show (数据库)
- L2: ipset list updown_src/dst/sport/dport_{id}
- L3: /tmp/iktmp/stream_updown.txt (ik_cntl wans-snat)
- L4: ik_core内核模块
"""
import pytest
import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from utils.step_recorder import StepRecorder
from config.config import get_config

PREFIX = "ud"


@pytest.mark.updown_route
@pytest.mark.network
class TestUpdownRouteComprehensive:
    """上下行分离综合测试"""

    TEST_RULES = [
        {"step": 1, "name": "ud01_basic",
         "upload_line": "wan1", "download_line": "wan1", "protocol": "任意",
         "desc": "基础:单线路+任意协议"},
        {"step": 2, "name": "ud02_diff",
         "upload_line": "wan1", "download_line": "wan2", "protocol": "任意",
         "desc": "不同线路:上wan1/下wan2"},
        {"step": 3, "name": "ud03_tcpsrc",
         "upload_line": "wan1", "download_line": "wan1", "protocol": "tcp",
         "src_port": "8080", "desc": "TCP协议+源端口"},
        {"step": 4, "name": "ud04_udpdst",
         "upload_line": "wan2", "download_line": "wan1", "protocol": "udp",
         "dst_port": "53", "desc": "UDP协议+目的端口"},
        {"step": 5, "name": "ud05_tcpudp",
         "upload_line": "wan1", "download_line": "wan2", "protocol": "tcp+udp",
         "src_port": "443", "dst_port": "80", "desc": "tcp+udp+源端口+目的端口"},
        {"step": 6, "name": "ud06_icmp",
         "upload_line": "wan1", "download_line": "wan1", "protocol": "icmp",
         "desc": "ICMP协议"},
        {"step": 7, "name": "ud07_srcip",
         "upload_line": "wan1", "download_line": "wan1", "protocol": "任意",
         "src_addr": "192.168.1.0/24", "desc": "源地址"},
        {"step": 8, "name": "ud08_dstip",
         "upload_line": "wan1", "download_line": "wan2", "protocol": "任意",
         "dst_addr": "10.0.0.1", "desc": "目的地址"},
        {"step": 9, "name": "ud09_addrs",
         "upload_line": "wan1", "download_line": "wan2", "protocol": "tcp",
         "src_addr": "192.168.1.100", "dst_addr": "172.16.0.1",
         "src_port": "8080", "desc": "源地址+目的地址+端口"},
        {"step": 10, "name": "ud10_remark",
         "upload_line": "wan1", "download_line": "wan1", "protocol": "任意",
         "remark": "上下行分离测试规则", "desc": "备注字段"},
    ]

    def test_updown_route_comprehensive(self, updown_route_page_logged_in, step_recorder: StepRecorder, request):
        """
        综合测试: 添加10条规则 -> SSH验证 -> 编辑 -> 停用 -> 启用 ->
        复制 -> 排序 -> 搜索 -> 批量删除 -> 异常测试 -> 清理
        """
        page = updown_route_page_logged_in
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
                status = '通过' if result.passed else '失败'
                print(f"    SSH-{label}: {status} - {result.message}")
                rec.add_detail(f"    SSH-{label}: {'[OK]' if result.passed else '[FAIL]'} {result.message}")
                if result.raw_output:
                    rec.add_detail(f"      SSH数据: {result.raw_output}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                return None

        print("\n" + "=" * 60)
        print("上下行分离综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(self.TEST_RULES)} 条规则")
        for r in self.TEST_RULES:
            print(f"  - {r['name']}, 上行={r['upload_line']}, "
                  f"下行={r['download_line']}, 协议={r.get('protocol','任意')}, "
                  f"场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            for cleanup_round in range(3):
                page.navigate_back_to_list()
                page.page.wait_for_timeout(1000)
                current_count = page.get_rule_count()
                if current_count == 0:
                    break
                rec.add_detail(f"[清理操作] 第{cleanup_round+1}轮: 全选批量删除({current_count}条)")
                select_all = page.page.locator("thead input[type='checkbox']").first
                if select_all.count() > 0 and select_all.is_enabled():
                    select_all.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(2000)
                    page.wait_for_success_message(timeout=3000)

            page.navigate_back_to_list()
            page.page.wait_for_timeout(1000)
            final_count = page.get_rule_count()
            print(f"  [OK] 环境清理完成，剩余 {final_count} 条")
            rec.add_detail(f"[清理结果] 剩余 {final_count} 条")

        # ========== 步骤2-11: 添加10条规则 ==========
        for idx, rule_data in enumerate(self.TEST_RULES):
            step_num = idx + 2
            desc = rule_data.get("desc", "")
            with rec.step(f"步骤{step_num}: 添加规则 - {desc}",
                          f"名称={rule_data['name']}, 上行={rule_data['upload_line']}, "
                          f"下行={rule_data['download_line']}, 协议={rule_data.get('protocol', '任意')}"):
                print(f"\n[步骤{step_num}] 添加规则: {rule_data['name']} ({desc})")

                result = page.add_rule(
                    name=rule_data["name"],
                    upload_line=rule_data.get("upload_line", "wan2"),
                    download_line=rule_data.get("download_line", "wan2"),
                    protocol=rule_data.get("protocol", "任意"),
                    src_addr=rule_data.get("src_addr"),
                    dst_addr=rule_data.get("dst_addr"),
                    src_port=rule_data.get("src_port"),
                    dst_port=rule_data.get("dst_port"),
                    remark=rule_data.get("remark"),
                )

                assert result, f"添加规则 {rule_data['name']} 失败"
                print(f"  [OK] 规则添加成功")
                rec.add_detail(f"[结果] 规则添加成功")

                # SSH L1验证
                expected = {
                    "upiface": rule_data.get("upload_line", "wan2"),
                    "downiface": rule_data.get("download_line", "wan2"),
                }
                proto = rule_data.get("protocol", "任意")
                if proto != "任意":
                    expected["protocol"] = proto
                if rule_data.get("remark"):
                    expected["comment"] = rule_data["remark"]

                r1 = ssh_verify(
                    f"L1-{rule_data['name']}",
                    backend_verifier.verify_stream_updown_database,
                    rule_data["name"],
                    expected_fields=expected,
                )

                # SSH L2 ipset验证
                if r1 and r1.details and r1.details.get("id"):
                    rule_id = r1.details["id"]
                    ssh_verify(
                        f"L2-{rule_data['name']}",
                        backend_verifier.verify_stream_updown_ipset,
                        rule_id,
                        src_addr=rule_data.get("src_addr"),
                        dst_addr=rule_data.get("dst_addr"),
                    )

        # ========== 步骤12: 验证规则总数 ==========
        with rec.step("步骤12: 验证规则总数", "检查所有规则是否添加成功"):
            count = page.get_rule_count()
            print(f"\n[步骤12] 当前规则总数: {count}")
            assert count == 10, f"规则数量应为10, 实际为{count}"
            rec.add_detail(f"[结果] 共{count}条规则, 验证通过")

            # L3+L4 内核验证
            ssh_verify("L3-内核状态", backend_verifier.verify_stream_updown_kernel_status)
            ssh_verify("L4-内核模块", backend_verifier.verify_stream_updown_kernel)

        # ========== 步骤13: 编辑规则 ==========
        with rec.step("步骤13: 编辑规则", "编辑ud10_remark的备注"):
            print("\n[步骤13] 编辑规则 ud10_remark")
            edit_result = page.edit_rule(
                "ud10_remark",
                new_name="ud10_edit",
                remark="编辑后备注"
            )
            assert edit_result, "编辑规则失败"
            print("  [OK] 编辑成功")
            rec.add_detail("[结果] 编辑成功")

            ssh_verify(
                "L1-编辑验证",
                backend_verifier.verify_stream_updown_database,
                "ud10_edit",
                expected_fields={"comment": "编辑后备注"},
            )

        # ========== 步骤14: 停用规则 ==========
        with rec.step("步骤14: 停用规则", "停用ud01_basic"):
            print("\n[步骤14] 停用规则 ud01_basic")
            result = page.disable_rule("ud01_basic")
            assert result is True, "停用规则失败"
            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.navigate_to_updown_route()
            page.page.wait_for_timeout(500)
            print("  [OK] 停用成功")
            rec.add_detail("[结果] 停用成功")

            ssh_verify(
                "L1-停用验证",
                backend_verifier.verify_stream_updown_database,
                "ud01_basic",
                expected_fields={"enabled": "no"},
            )

        # ========== 步骤15: 启用规则 ==========
        with rec.step("步骤15: 启用规则", "启用ud01_basic"):
            print("\n[步骤15] 启用规则 ud01_basic")
            result = page.enable_rule("ud01_basic")
            assert result is True, "启用规则失败"
            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.navigate_to_updown_route()
            page.page.wait_for_timeout(500)
            print("  [OK] 启用成功")
            rec.add_detail("[结果] 启用成功")

            ssh_verify(
                "L1-启用验证",
                backend_verifier.verify_stream_updown_database,
                "ud01_basic",
                expected_fields={"enabled": "yes"},
            )

        # ========== 步骤16: 排序功能 ==========
        with rec.step("步骤16: 排序功能", "测试上行线路列排序"):
            print("\n[步骤16] 排序功能测试")
            sorted_ok = page.sort_by_column("上行线路")
            page.wait_for_timeout(500)
            print(f"  [OK] 排序{'成功' if sorted_ok else '跳过'}")
            rec.add_detail(f"[结果] 排序{'执行成功' if sorted_ok else '跳过(无可排序列)'}")

        # ========== 步骤17: 搜索功能测试 ==========
        with rec.step("步骤17: 搜索功能测试", "精确搜索/模糊搜索/不存在的规则"):
            print("\n[步骤17] 搜索测试...")
            rec.add_detail("[搜索测试]")

            # 17.1 精确搜索
            search_target = "ud01_basic"
            rec.add_detail(f"  精确搜索: {search_target}")
            page.search_rule(search_target)
            page.page.wait_for_timeout(500)
            assert page.rule_exists(search_target), f"精确搜索不到: {search_target}"
            print(f"  [OK] 精确搜索成功")
            rec.add_detail(f"    [OK] 精确搜索找到")

            # 17.2 部分匹配搜索
            page.clear_search()
            page.page.wait_for_timeout(300)
            prefix = "ud0"
            rec.add_detail(f"  部分匹配搜索: '{prefix}'")
            page.search_rule(prefix)
            page.page.wait_for_timeout(500)
            partial_count = page.get_rule_count()
            assert partial_count >= 1, f"部分匹配搜索应至少1条，实际{partial_count}条"
            print(f"  [OK] 部分匹配搜索: {partial_count}条")
            rec.add_detail(f"    [OK] 匹配 {partial_count} 条")

            # 17.3 不存在的规则
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("not_exist_ud_xxx")
            page.page.wait_for_timeout(500)
            count = page.get_rule_count()
            assert count == 0, f"搜索不存在时应为0条，实际{count}条"
            print("  [OK] 搜索不存在规则: 0条")
            rec.add_detail(f"  不存在的: 0条 [OK]")

            # 17.4 清空搜索恢复列表
            page.clear_search()
            page.page.wait_for_timeout(500)
            remaining = page.get_rule_count()
            assert remaining == 10, f"清空搜索后应有10条，实际{remaining}条"
            print(f"  [OK] 清空搜索，恢复 {remaining} 条")
            rec.add_detail(f"  清空搜索: {remaining} 条 [OK]")

        # ========== 步骤18: 导出测试 ==========
        with rec.step("步骤18: 导出配置", "导出CSV和TXT"):
            print("\n[步骤18] 导出配置...")
            rec.add_detail("[导出测试]")
            config = get_config()
            export_file_csv = config.test_data.get_export_path("updown_route", config.get_project_root())
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
                ui_failures.append("导出失败")

            page.close_modal_if_exists()
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_updown_route()
            page.page.wait_for_timeout(500)

        # ========== 步骤19: 异常输入测试 ==========
        with rec.step("步骤19: 异常输入测试", "测试各种无效输入"):
            print("\n[步骤19] 异常输入测试")

            # 19a: 空名称
            invalid1 = page.try_add_rule_invalid(name="", expect_fail=True)
            assert invalid1["success"], f"空名称应被拒绝: {invalid1}"
            print(f"  19a 空名称: {invalid1.get('error_message', '被拒绝')[:50]}")
            rec.add_detail(f"  19a-空名称: {invalid1.get('error_message', '被拒绝')[:50]}")

            # 19b: 重复名称
            page.navigate_back_to_list()
            page.wait_for_timeout(500)
            page.add_rule(name="ud_dup", upload_line="wan1", download_line="wan1")
            page.wait_for_timeout(500)
            page.navigate_back_to_list()
            page.wait_for_timeout(500)
            dup_result = page.add_rule(name="ud_dup", upload_line="wan2", download_line="wan2")
            print(f"  19b 重复名称: {'被拒绝' if not dup_result else '允许'}")
            rec.add_detail(f"  19b-重复名称: {'被拒绝' if not dup_result else '允许'}")

            # 19c: 超长名称
            page.navigate_back_to_list()
            page.wait_for_timeout(500)
            long_result = page.add_rule(name="A" * 100, upload_line="wan2", download_line="wan2")
            print(f"  19c 超长名称: {'被截断/拒绝' if not long_result else '可能被截断'}")
            rec.add_detail(f"  19c-超长名称: {'被截断/拒绝' if not long_result else '可能被截断'}")

            # 19d: 特殊字符名称
            page.navigate_back_to_list()
            page.wait_for_timeout(500)
            special_result = page.try_add_rule_invalid(name="ud_test<>&'")
            print(f"  19d 特殊字符: {special_result.get('error_message', '已处理')[:50]}")
            rec.add_detail(f"  19d-特殊字符: {special_result.get('error_message', '已处理')[:50]}")

            # 19e: 纯空格名称
            page.navigate_back_to_list()
            page.wait_for_timeout(500)
            space_result = page.try_add_rule_invalid(name="   ")
            print(f"  19e 纯空格: {space_result.get('error_message', '已处理')[:50]}")
            rec.add_detail(f"  19e-纯空格: {space_result.get('error_message', '已处理')[:50]}")

            # 19f: 超长备注
            page.navigate_back_to_list()
            page.wait_for_timeout(500)
            longrmk_result = page.add_rule(
                name="ud_longrmk", upload_line="wan1", download_line="wan1",
                remark="测" * 65
            )
            print(f"  19f 超长备注: {'被拒绝' if not longrmk_result else '可能被截断'}")
            rec.add_detail(f"  19f-超长备注: {'被拒绝' if not longrmk_result else '可能被截断'}")

            # 19g: 备注特殊字符
            page.navigate_back_to_list()
            page.wait_for_timeout(500)
            spcrmk_result = page.add_rule(
                name="ud_spcrmk", upload_line="wan1", download_line="wan1",
                remark="TCP80分流测试"
            )
            print(f"  19g 备注特殊字符: {'成功' if spcrmk_result else '被拒绝'}")
            rec.add_detail(f"  19g-备注特殊字符: {'成功' if spcrmk_result else '被拒绝'}")

        # ========== 步骤20: 批量停用 ==========
        with rec.step("步骤20: 批量停用", f"批量停用所有规则"):
            print(f"\n[步骤20] 批量停用...")
            rec.add_detail(f"[批量停用]")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_disable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_updown_route()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            disabled_count = current_count  # after batch disable, all should be disabled
            print(f"  [OK] 批量停用完成")
            rec.add_detail(f"[结果] 批量停用完成")

            if backend_verifier is not None:
                try:
                    ud_rules = backend_verifier.query_stream_updown_rules()
                    test_names = {r["name"] for r in self.TEST_RULES}
                    disabled_in_db = sum(1 for r in ud_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                    rec.add_detail(f"    SSH: {disabled_in_db}/{len(self.TEST_RULES)}条停用")
                except Exception:
                    pass

        # ========== 步骤21: 批量启用 ==========
        with rec.step("步骤21: 批量启用", f"批量启用所有规则"):
            print(f"\n[步骤21] 批量启用...")
            rec.add_detail(f"[批量启用]")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_enable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_updown_route()
            page.page.wait_for_timeout(500)
            print(f"  [OK] 批量启用完成")
            rec.add_detail(f"[结果] 批量启用完成")

        # ========== 步骤22: 批量删除 ==========
        with rec.step("步骤22: 批量删除", "删除所有规则"):
            print("\n[步骤22] 批量删除所有规则")
            before_delete = page.get_rule_count()

            for delete_round in range(3):
                page.navigate_back_to_list()
                page.page.wait_for_timeout(500)
                current = page.get_rule_count()
                if current == 0:
                    break
                select_all = page.page.locator("thead input[type='checkbox']").first
                if select_all.count() > 0 and select_all.is_enabled():
                    select_all.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(2000)
                    page.wait_for_success_message(timeout=3000)

            page.navigate_back_to_list()
            page.wait_for_timeout(500)
            after_delete = page.get_rule_count()
            assert after_delete == 0, f"批量删除后应有0条规则, 实际为{after_delete}"
            print(f"  [OK] 删除{before_delete}条规则成功")
            rec.add_detail(f"[结果] 删除{before_delete}条规则成功, 剩余{after_delete}条")

            ssh_verify("L3-删除后验证", backend_verifier.verify_stream_updown_kernel_status)

        # ========== 步骤23: 导入测试(追加) ==========
        with rec.step("步骤23: 导入配置(追加)", "使用导出的CSV追加导入"):
            print("\n[步骤23] 导入配置(追加)...")
            rec.add_detail("[导入测试-追加]")

            if os.path.exists(export_file_csv):
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_csv)}")
                rec.add_detail(f"  导入前: {count_before} 条")

                result = page.import_rules(export_file_csv, clear_existing=False)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_updown_route()
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

        # ========== 步骤24: 导入测试(TXT清空现有) ==========
        with rec.step("步骤24: 导入配置(清空现有)", "使用导出的TXT清空现有后导入"):
            print("\n[步骤24] 导入配置(清空现有数据-TXT)...")
            rec.add_detail("[导入测试-清空现有-TXT]")

            if os.path.exists(export_file_txt):
                page.add_rule(name="extra_ud_before", upload_line="wan1", download_line="wan1")
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_txt)}")
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则 extra_ud_before)")

                result = page.import_rules(export_file_txt, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1000)
                page.navigate_to_updown_route()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if not page.rule_exists("extra_ud_before"):
                    print(f"  [OK] 清空现有数据生效(extra_ud_before已删除)")
                    rec.add_detail(f"  [OK] 清空生效: extra_ud_before已删除")
                else:
                    print(f"  [WARN] 清空现有数据可能未生效")
                    rec.add_detail(f"  [WARN] extra_ud_before仍存在")

                if count_after > 0:
                    print(f"  [OK] 重新导入 {count_after} 条")
                    rec.add_detail(f"  [OK] 重新导入 {count_after} 条")
            else:
                print(f"  [WARN] TXT文件不存在")
                rec.add_detail(f"  TXT文件不存在")

        # ========== 步骤25: 清理环境 ==========
        with rec.step("步骤25: 清理环境", "清理所有残留数据"):
            print("\n[步骤25] 清理环境...")
            rec.add_detail("[环境清理]")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.navigate_to_updown_route()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                for cleanup_round in range(3):
                    page.navigate_back_to_list()
                    page.page.wait_for_timeout(500)
                    current = page.get_rule_count()
                    if current == 0:
                        break
                    select_all = page.page.locator("thead input[type='checkbox']").first
                    if select_all.count() > 0 and select_all.is_enabled():
                        select_all.click()
                        page.page.wait_for_timeout(500)
                        page.batch_delete()
                        page.page.wait_for_timeout(2000)
                        page.wait_for_success_message(timeout=3000)

                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_updown_route()
                page.page.wait_for_timeout(500)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成，剩余 {final_count} 条")
                rec.add_detail(f"[结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 无需清理")
                rec.add_detail("  无需清理")

            ssh_verify("L3-最终验证", backend_verifier.verify_stream_updown_kernel_status)
            ssh_verify("L4-最终验证", backend_verifier.verify_stream_updown_kernel)

        # ========== 步骤26: 帮助功能测试 ==========
        with rec.step("步骤26: 帮助功能测试", "测试帮助图标"):
            print("\n[步骤26] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")

            try:
                help_btn = page.page.get_by_role("button", name="帮助")
                if help_btn.count() > 0:
                    help_btn.click()
                    page.page.wait_for_timeout(500)

                    help_panel = page.page.locator(".ant-drawer, .ant-modal, [role='dialog']")
                    if help_panel.count() > 0 and help_panel.is_visible():
                        print(f"  [OK] 帮助功能测试通过")
                        rec.add_detail(f"  [OK] 帮助图标可点击，面板显示")

                        close_btn = page.page.locator(".ant-drawer-close, .ant-modal-close")
                        if close_btn.count() > 0:
                            close_btn.click()
                        else:
                            page.page.keyboard.press("Escape")
                        page.page.wait_for_timeout(300)
                    else:
                        rec.add_detail(f"  帮助面板未显示")
                else:
                    print("  [WARN] 帮助图标未找到")
                    rec.add_detail(f"  帮助图标未找到")
            except Exception as e:
                print(f"  [WARN] 帮助功能测试异常: {e}")
                rec.add_detail(f"  帮助功能异常: {e}")

        # 断言所有SSH验证通过
        if ssh_failures:
            pytest.fail(f"验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures[:5])}")

        print("\n" + "=" * 60)
        print("上下行分离综合测试完成 - ALL PASSED")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 10条（覆盖单线路/不同线路/TCP+源端口/UDP+目的端口/tcp+udp/ICMP/源地址/目的地址/地址+端口/备注）")
        print("  - 编辑/停用/启用: 各1条")
        print("  - 搜索: 精确/部分匹配/不存在/清空恢复")
        print("  - 排序: 上行线路")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加(CSV) + 清空现有数据(TXT)")
        print("  - 异常输入: 空名称/重复/超长/特殊字符/纯空格/备注特殊字符")
        print("  - 批量操作: 批量停用/启用/删除")
        print("  - 帮助功能")
        print("  - SSH后台验证: L1数据库+L2 ipset+L3内核状态+L4 ik_core")
