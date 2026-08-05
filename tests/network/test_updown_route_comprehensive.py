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
import ipaddress
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from utils.step_recorder import StepRecorder
from config.config import get_config
from utils.verify_helper import make_ssh_verify, make_kernel_check

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

        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)
        kernel_check = make_kernel_check(backend_verifier, rec, ssh_failures, default_module="stream_updown")

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
                    must_pass=True,
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
            # 底层一致性基线(添加后): 记录snapshot, 作为后续删除/导入残留对比基准
            kernel_check("步骤12-添加后基线", fail_on_residual=False)

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
                must_pass=True,
            )

            # 编辑把ud10_remark改名为ud10_edit, 后续步骤(清理脏规则/批量停用启用统计)的规则名集合需同步,
            # 否则ud10_edit不被统计且会被"删除非TEST_RULES"清理逻辑误删→9/10误报(2026-06-17实测定位, 非分页问题)
            edited_names = {"ud10_remark": "ud10_edit"}

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
                must_pass=True,
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
                must_pass=True,
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
            if dup_result:
                ui_failures.append("19b-重复名称未被拒绝(后端tagname应保证唯一)")

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

            # 步骤19产生的脏规则(ud_dup/超长名截断为15A/ud_longrmk/ud_spcrmk)会使总规则达14>10,
            # 触发Ant Design分页, 步骤20/21 select_all只选当前页漏选第二页→批量操作不完整(2026-06-17实测9/10)。
            # 测试设计缺陷: 异常测试不应污染批量操作数据集。清理脏规则使步骤20操作干净的10条TEST_RULES(恰好1页)。
            # 注: SQL delete不触发iptables重载, 但步骤20/21的UI批量操作会触发重载重建iptables状态, 顺带清除残留。
            if backend_verifier is not None:
                # BackendVerifier组合SSHClient(self._router), 自身无exec方法(第一次修复误用backend_verifier.exec
                # 抛AttributeError被except吞→cleaned=0→脏规则未删→分页漏选依旧)。改用_router.exec。
                # 通用清理: 删除所有非TEST_RULES的updown规则(不依赖脏规则tagname猜测, 超长名截断长度未知)
                test_names = {edited_names.get(r["name"], r["name"]) for r in self.TEST_RULES}
                cleaned = 0
                dirty_tags = []
                try:
                    all_rules = backend_verifier.query_stream_updown_rules() or []  # 内部connect_router
                    dirty = [r for r in all_rules if (r.get("tagname") or "") not in test_names]
                    dirty_tags = [r.get("tagname") for r in dirty]
                    for r in dirty:
                        tn = (r.get("tagname") or "").replace("'", "''")  # 转义SQL单引号
                        try:
                            backend_verifier._router.exec(
                                f'sqlite3 /etc/mnt/ikuai/config.db '
                                f'"delete from stream_updown where tagname=\'{tn}\'"'
                            )
                            cleaned += 1
                        except Exception as e:
                            print(f"  [清理] 删除'{r.get('tagname')}'失败: {str(e)[:60]}")
                    print(f"  [清理] 步骤19脏规则: 删除{cleaned}/{len(dirty)}条 {dirty_tags}")
                except Exception as e:
                    print(f"  [清理] 查询/删除脏规则失败: {str(e)[:60]}")
                page.navigate_back_to_list()
                page.wait_for_timeout(800)
                rec.add_detail(f"  [清理] 步骤19脏规则{dirty_tags}(避免污染步骤20/21批量操作数据集触发分页漏选)")

        # ========== 步骤20: 批量停用 ==========
        with rec.step("步骤20: 批量停用", f"批量停用所有规则"):
            print(f"\n[步骤20] 批量停用...")
            rec.add_detail(f"[批量停用]")

            # 批量停用带重试 + SSH验证(参照跨三层, 原实现 disabled_count=current_count 硬编码无真实验证)
            test_names = {edited_names.get(r["name"], r["name"]) for r in self.TEST_RULES}
            total = len(self.TEST_RULES)
            disable_success = False
            disabled_count = 0
            for attempt in range(3):
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_disable()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_updown_route()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_stream_updown_rules() or []
                    disabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                else:
                    disabled_count = sum(1 for r in self.TEST_RULES if page.is_rule_disabled(edited_names.get(r["name"], r["name"])))

                if total == 0 or disabled_count >= total:
                    disable_success = True
                    break
                print(f"  第{attempt + 1}次批量停用后 {disabled_count}/{total} 条已停用，重试...")
                rec.add_detail(f"  第{attempt + 1}次停用: {disabled_count}/{total}条，重试")

            if disable_success:
                print(f"  [OK] 批量停用完成: {disabled_count}/{total} 条已停用")
                rec.add_detail(f"[结果] 批量停用: {disabled_count}/{total} 条已停用")
            else:
                print(f"  [WARN] 批量停用未完全生效: {disabled_count}/{total} 条")
                rec.add_detail(f"[结果] 批量停用未完全生效: {disabled_count}/{total} 条")
                ui_failures.append(f"批量停用仅{disabled_count}/{total}条规则停用")

            # SSH验证(补断言: 防止批量停用失败却报告通过)
            if backend_verifier is not None:
                db_rules = backend_verifier.query_stream_updown_rules() or []
                disabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                rec.add_detail(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                print(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                if total > 0 and disabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_count}/{total}条规则停用")

        # ========== 步骤21: 批量启用 ==========
        with rec.step("步骤21: 批量启用", f"批量启用所有规则"):
            print(f"\n[步骤21] 批量启用...")
            rec.add_detail(f"[批量启用]")

            # 批量启用带重试 + SSH验证(参照跨三层, 原实现无验证, 批量启用失败无法发现)
            test_names = {edited_names.get(r["name"], r["name"]) for r in self.TEST_RULES}
            total = len(self.TEST_RULES)
            enable_success = False
            enabled_count = 0
            for attempt in range(3):
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_enable()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_updown_route()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_stream_updown_rules() or []
                    enabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "yes")
                else:
                    enabled_count = sum(1 for r in self.TEST_RULES if page.is_rule_enabled(edited_names.get(r["name"], r["name"])))

                if total == 0 or enabled_count >= total:
                    enable_success = True
                    break
                print(f"  第{attempt + 1}次批量启用后 {enabled_count}/{total} 条已启用，重试...")
                rec.add_detail(f"  第{attempt + 1}次启用: {enabled_count}/{total}条，重试")

            if enable_success:
                print(f"  [OK] 批量启用完成: {enabled_count}/{total} 条已启用")
                rec.add_detail(f"[结果] 批量启用: {enabled_count}/{total} 条已启用")
            else:
                print(f"  [WARN] 批量启用未完全生效: {enabled_count}/{total} 条")
                rec.add_detail(f"[结果] 批量启用未完全生效: {enabled_count}/{total} 条")
                ui_failures.append(f"批量启用仅{enabled_count}/{total}条规则启用")

            # SSH验证(补断言)
            if backend_verifier is not None:
                db_rules = backend_verifier.query_stream_updown_rules() or []
                enabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "yes")
                rec.add_detail(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                print(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                if total > 0 and enabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量启用: 仅{enabled_count}/{total}条规则启用")

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
            # 底层一致性实时校验: 批量删除后底层应无残留
            kernel_check("步骤22-批量删除后", fail_on_residual=True)

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
            # 底层一致性实时校验: 追加导入后底层应与DB一致
            kernel_check("步骤23-导入追加后", fail_on_residual=False)

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
            # 底层一致性实时校验: 清空导入后底层应与DB一致
            kernel_check("步骤24-导入清空后", fail_on_residual=False)

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
            # 底层一致性实时校验: 清理后底层应彻底无残留(硬FAIL)
            kernel_check("步骤25-清理后", fail_on_residual=True)

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

        # 断言所有验证通过(SSH + UI; 修复ui_failures死代码: 原只查ssh_failures, ui_failures写了从未assert)
        all_failures = ssh_failures + ui_failures
        if all_failures:
            pytest.fail(f"验证失败({len(all_failures)}项): {'; '.join(all_failures[:5])}")

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


@pytest.mark.updown_route
@pytest.mark.network
class TestUpdownRouteFlowVerification:
    """上下行分流启用/停用对照验证。

    4.0固件可能不直接提供rev_remote_if，因此下行证据必须同时保留reply tuple
    的SNAT目的地址和WAN地址映射来源。用固定公网HTTP目标、精确五元组过滤及
    无规则/停用态对照，避免把客户端后台连接或默认WAN误判为规则命中。
    """

    PREFIX = "udflow_"
    PROBE_DOMAIN = "www.baidu.com"
    PROBE_PORT = 80

    @staticmethod
    def _wait_rule_state(bv, rule_name, enabled, attempts=8):
        for _ in range(attempts):
            rule = bv.find_stream_updown_rule(rule_name)
            if rule and str(rule.get("enabled")) == enabled:
                return rule
            time.sleep(0.5)
        return bv.find_stream_updown_rule(rule_name)

    @classmethod
    def curl_probe_command(cls, probe_ip, client_iface):
        probe_ip = str(ipaddress.ip_address(probe_ip))
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", str(client_iface)):
            raise ValueError(f"非法客户端接口名: {client_iface!r}")
        return (
            f"curl -4 -sS -o /dev/null --interface {client_iface} "
            "--connect-timeout 5 -m 12 "
            f"--resolve {cls.PROBE_DOMAIN}:{cls.PROBE_PORT}:{probe_ip} "
            "-w 'http_code=%{http_code} remote_ip=%{remote_ip} "
            "local_ip=%{local_ip} local_port=%{local_port} "
            "size_download=%{size_download} speed_download=%{speed_download}' "
            f"http://{cls.PROBE_DOMAIN}/; printf ' curl_rc=%s\\n' \"$?\""
        )

    def test_updown_route_flow(self, updown_route_page_logged_in, step_recorder, request):
        page = updown_route_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            pytest.skip("无SSH验证器, 跳过上下行分流功能验证")
        bv.connect_router()
        bv.connect_client()
        client_info = bv.get_client_lan_info()
        client_ip = client_info.get("ip") or "192.168.148.2"
        client_iface = client_info.get("iface") or "ens11"
        probe_ip = ""
        up_wan, down_wan = "wan1", "wan3"
        rule_name = f"{self.PREFIX}sep"
        failures = []
        rule = None
        rule_id = None
        baseline = None
        active = None
        disabled = None
        reenabled = None
        print("\n" + "=" * 50)
        print("上下行分流功能验证(启用/停用对照)")
        print("=" * 50)

        def _add_failure(message):
            if message not in failures:
                failures.append(message)
            rec.add_detail(f"  ✗ {message}")

        def _cleanup_test_rules():
            try:
                return bv.cleanup_stream_updown_test(self.PREFIX)
            except Exception as exc:
                _add_failure(f"测试规则清理异常: {str(exc)[:120]}")
                return None

        def _record_probe_commands(label, flow):
            rec.add_verification_command(
                flow.get("command", ""),
                target_label="测试客户端",
                target=bv._ssh_config.client.host,
                shell="bash",
                purpose=f"{label}: 产生固定公网目标并回读实际源端口的真实HTTP响应流量",
                expected="curl_rc=0、http_code非000、remote_ip为固定探针IP",
                effect="traffic_probe",
                actual=flow.get("curl_output", ""),
            )
            rec.add_verification_command(
                "conntrack -L -o extended 2>/dev/null | "
                f"grep -F 'src={client_ip} ' | grep -F 'dst={probe_ip} ' | "
                f"grep -F 'sport={flow.get('local_port')} ' | "
                f"grep -F 'dport={self.PROBE_PORT} '",
                target_label="被测路由器",
                target=bv._ssh_config.router.host,
                shell="bash",
                purpose=f"{label}: 复核精确目标连接的上下行证据",
                expected=(
                    f"remote_if={flow.get('expected_up', '?')}; reply tuple目的地址映射到"
                    f"{flow.get('expected_down', '?')}"
                ),
                effect="read_only",
                actual=flow.get("egress", {}).get("raw", "")[:1200],
            )

        def _probe(label, expected_up, expected_down):
            bv.clear_client_conntrack(client_ip)
            command = self.curl_probe_command(
                probe_ip, client_iface
            )
            curl_output = bv._client.exec(command, timeout=20).strip()
            observed = dict(re.findall(
                r"\b(http_code|remote_ip|local_ip|local_port|size_download|"
                r"speed_download|curl_rc)=([^\s]+)",
                curl_output,
            ))
            http_ok = (
                observed.get("curl_rc") == "0"
                and observed.get("http_code", "000") != "000"
                and observed.get("remote_ip") == probe_ip
            )
            if not http_ok:
                _add_failure(f"{label} HTTP探针失败: {curl_output[:240]}")
            try:
                local_port = int(observed.get("local_port", ""))
            except ValueError:
                local_port = 0
                _add_failure(f"{label}未回读到curl实际源端口")
            egress = (
                bv.conntrack_egress(
                    client_ip,
                    proto="tcp",
                    dst_ip=probe_ip,
                    src_port=local_port,
                    dst_port=self.PROBE_PORT,
                )
                if local_port else
                {"found": False, "remote_if": "", "rev_remote_if": "",
                 "down_iface_source": "", "reply_dst_ip": "", "raw": ""}
            )
            flow = {
                "command": command,
                "curl_output": curl_output,
                "http": observed,
                "local_port": local_port,
                "expected_up": expected_up,
                "expected_down": expected_down,
                "egress": egress,
            }
            rec.add_detail(
                f"  {label}: http={observed.get('http_code', '无')}; "
                f"bytes={observed.get('size_download', '无')}; "
                f"speed={observed.get('speed_download', '无')} B/s; "
                f"remote_if={egress.get('remote_if') or '无'}; "
                f"down_if={egress.get('rev_remote_if') or '无'}; "
                f"reply_snat_ip={egress.get('reply_dst_ip') or '无'}; "
                f"down证据来源={egress.get('down_iface_source') or '无'}"
            )
            if egress.get("raw"):
                rec.add_detail(f"  原始conntrack: {egress['raw']}")
            if not egress.get("found"):
                _add_failure(f"{label}未找到精确HTTP conntrack")
            elif (egress.get("remote_if") != expected_up or
                  egress.get("rev_remote_if") != expected_down):
                _add_failure(
                    f"{label}路径不符: 实际{egress.get('remote_if')}/"
                    f"{egress.get('rev_remote_if')},期望{expected_up}/{expected_down}"
                )
            if not egress.get("down_iface_source"):
                _add_failure(f"{label}缺少可审计的下行线路证据来源")
            _record_probe_commands(label, flow)
            return flow

        try:
            with rec.step("环境与无规则基线", "固定公网HTTP目标并回读实际源端口; 无规则应为wan1/wan1"):
                cleanup = _cleanup_test_rules()
                if cleanup and not cleanup.passed:
                    _add_failure(cleanup.message)

                wan_ip_map = bv._wan_ip_to_iface()
                iface_to_ip = {iface: ip for ip, iface in wan_ip_map.items()}
                if up_wan not in iface_to_ip or down_wan not in iface_to_ip:
                    _add_failure(
                        f"环境缺少目标WAN地址: 已发现{sorted(iface_to_ip)}"
                    )
                elif iface_to_ip[up_wan] == iface_to_ip[down_wan]:
                    _add_failure("wan1与wan3地址相同, 无法区分下行SNAT证据")

                foreign_rules = [
                    item for item in bv.query_stream_updown_rules()
                    if not str(item.get("tagname", "")).startswith(self.PREFIX)
                ]
                resolved = bv._client.exec(
                    f"getent ahostsv4 {self.PROBE_DOMAIN} | "
                    "awk '$2==\"STREAM\"{print $1; exit}'"
                ).strip()
                try:
                    probe_ip = str(ipaddress.ip_address(resolved))
                except ValueError:
                    _add_failure(
                        f"公网探针域名未解析出单一IPv4: {resolved or '空'}"
                    )
                rec.add_detail(
                    f"  client={client_ip}/{client_iface}; "
                    f"probe={self.PROBE_DOMAIN}->{probe_ip or '无'}:{self.PROBE_PORT}; "
                    f"WAN地址={iface_to_ip}; "
                    f"非测试规则={len(foreign_rules)}条"
                )

                if probe_ip:
                    baseline = _probe("无规则基线", up_wan, up_wan)
                    rec.set_actual(
                        f"基线{baseline['egress'].get('remote_if')}/"
                        f"{baseline['egress'].get('rev_remote_if')}, "
                        f"HTTP {baseline['http'].get('http_code', '无')}, "
                        f"{baseline['http'].get('size_download', '无')} bytes"
                    )

            with rec.step("创建规则并校验页面结果",
                          f"upload={up_wan}/download={down_wan}/tcp/src={client_ip}"):
                page.navigate_to_updown_route()
                page.page.wait_for_timeout(800)
                ok = page.add_rule(rule_name, upload_line=up_wan, download_line=down_wan,
                                   protocol="tcp", src_addr=client_ip)
                if not ok:
                    _add_failure(f"建规则失败: {rule_name}")
                else:
                    rule = self._wait_rule_state(bv, rule_name, "yes")
                    rule_id = int(rule["id"]) if rule and rule.get("id") else None
                    if rule_id is None:
                        _add_failure("页面提示成功但后台未找到规则")
                    rec.add_detail(f"  页面添加成功; 后台rule_id={rule_id or '无'}")
                    rec.set_actual(
                        f"页面保存成功，后台规则ID={rule_id or '未找到'}"
                    )

            if rule_id is not None:
                with rec.step("L1-L4精确落地验证",
                              "数据库字段+源地址ipset+本规则wans-snat+ik_core"):
                    r1 = bv.verify_stream_updown_database(
                        rule_name,
                        expected_fields={
                            "enabled": "yes",
                            "upiface": up_wan,
                            "downiface": down_wan,
                            "protocol": "tcp",
                        },
                    )
                    rec.add_detail(f"  L1-数据库: {'[OK]' if r1.passed else '[FAIL]'} {r1.message}")
                    if r1.raw_output:
                        rec.add_detail(f"    数据库原始行: {r1.raw_output}")
                    if not r1.passed:
                        _add_failure(f"L1数据库: {r1.message}")
                    r2 = bv.verify_stream_updown_ipset(rule_id, src_addr=client_ip)
                    rec.add_detail(f"  L2-ipset: {'[OK]' if r2.passed else '[FAIL]'} {r2.message}")
                    if r2.raw_output:
                        rec.add_detail(f"    {r2.raw_output}")
                    if not r2.passed:
                        _add_failure(f"L2 ipset: {r2.message}")
                    r3 = bv.verify_stream_updown_kernel_status(
                        rule_id,
                        expected_upiface=up_wan,
                        expected_downiface=down_wan,
                        expected_present=True,
                    )
                    rec.add_detail(f"  L3-内核状态: {'[OK]' if r3.passed else '[FAIL]'} {r3.message}")
                    if r3.raw_output:
                        rec.add_detail(f"    运行时原始行: {r3.raw_output}")
                    if not r3.passed:
                        _add_failure(f"L3内核状态: {r3.message}")
                    r4 = bv.verify_stream_updown_kernel()
                    rec.add_detail(f"  L4-内核模块: {'[OK]' if r4.passed else '[FAIL]'} {r4.message}")
                    if not r4.passed:
                        _add_failure(f"L4内核模块: {r4.message}")
                    rec.add_verification_command(
                        "cat /tmp/iktmp/stream_updown.txt 2>/dev/null",
                        target_label="被测路由器",
                        target=bv._ssh_config.router.host,
                        shell="bash",
                        purpose="复核本规则的wans-snat上下行落地",
                        expected=f"id={rule_id}: out={up_wan}, in={down_wan}",
                        effect="read_only",
                        actual=r3.raw_output,
                    )

                with rec.step("L5启用态真实下行流",
                              f"固定{probe_ip}:{self.PROBE_PORT}; 期望{up_wan}/{down_wan}"):
                    active = _probe("启用态", up_wan, down_wan)
                    if baseline and (
                            active["egress"].get("reply_dst_ip") ==
                            baseline["egress"].get("reply_dst_ip")):
                        _add_failure("启用规则后reply SNAT地址未相对基线变化")
                    rec.set_actual(
                        f"启用态{active['egress'].get('remote_if')}/"
                        f"{active['egress'].get('rev_remote_if')}, "
                        f"HTTP {active['http'].get('http_code', '无')}, "
                        f"{active['http'].get('size_download', '无')} bytes"
                    )

                with rec.step("停用态负向对照",
                              f"停用同一规则后应从{up_wan}/{down_wan}回到基线{up_wan}/{up_wan}"):
                    if not page.disable_rule(rule_name):
                        _add_failure("页面未能发起停用操作")
                    stopped = self._wait_rule_state(bv, rule_name, "no")
                    if not stopped or str(stopped.get("enabled")) != "no":
                        _add_failure("停用后数据库enabled未变为no")
                    r3_off = bv.verify_stream_updown_kernel_status(
                        rule_id, expected_present=False
                    )
                    rec.add_detail(
                        f"  L3-停用: {'[OK]' if r3_off.passed else '[FAIL]'} "
                        f"{r3_off.message}"
                    )
                    if not r3_off.passed:
                        _add_failure(f"停用后运行时仍有规则: {r3_off.message}")
                    disabled = _probe("停用态", up_wan, up_wan)
                    if baseline:
                        base_sig = (
                            baseline["egress"].get("remote_if"),
                            baseline["egress"].get("rev_remote_if"),
                            baseline["egress"].get("reply_dst_ip"),
                        )
                        off_sig = (
                            disabled["egress"].get("remote_if"),
                            disabled["egress"].get("rev_remote_if"),
                            disabled["egress"].get("reply_dst_ip"),
                        )
                        if off_sig != base_sig:
                            _add_failure(
                                f"停用态未恢复无规则基线: 实际{off_sig},基线{base_sig}"
                            )
                    rec.set_actual(
                        f"停用态{disabled['egress'].get('remote_if')}/"
                        f"{disabled['egress'].get('rev_remote_if')}, "
                        f"HTTP {disabled['http'].get('http_code', '无')}, "
                        f"{disabled['http'].get('size_download', '无')} bytes"
                    )

                with rec.step("重新启用复现",
                              f"再次启用后应稳定恢复{up_wan}/{down_wan}"):
                    page.navigate_to_updown_route()
                    if not page.enable_rule(rule_name):
                        _add_failure("页面未能发起重新启用操作")
                    started = self._wait_rule_state(bv, rule_name, "yes")
                    if not started or str(started.get("enabled")) != "yes":
                        _add_failure("重新启用后数据库enabled未变为yes")
                    r3_on = bv.verify_stream_updown_kernel_status(
                        rule_id,
                        expected_upiface=up_wan,
                        expected_downiface=down_wan,
                        expected_present=True,
                    )
                    rec.add_detail(
                        f"  L3-重启用: {'[OK]' if r3_on.passed else '[FAIL]'} "
                        f"{r3_on.message}"
                    )
                    if not r3_on.passed:
                        _add_failure(f"重新启用运行时未恢复: {r3_on.message}")
                    reenabled = _probe("重新启用态", up_wan, down_wan)
                    if active:
                        active_sig = (
                            active["egress"].get("remote_if"),
                            active["egress"].get("rev_remote_if"),
                            active["egress"].get("reply_dst_ip"),
                        )
                        again_sig = (
                            reenabled["egress"].get("remote_if"),
                            reenabled["egress"].get("rev_remote_if"),
                            reenabled["egress"].get("reply_dst_ip"),
                        )
                        if again_sig != active_sig:
                            _add_failure(
                                f"重新启用结果不可重复: 首次{active_sig},再次{again_sig}"
                            )
                    rec.set_actual(
                        f"重启用{reenabled['egress'].get('remote_if')}/"
                        f"{reenabled['egress'].get('rev_remote_if')}, "
                        f"HTTP {reenabled['http'].get('http_code', '无')}, "
                        f"{reenabled['http'].get('size_download', '无')} bytes"
                    )
        except Exception as exc:
            _add_failure(f"未处理异常: {type(exc).__name__}: {str(exc)[:180]}")
        finally:
            with rec.step("清理与残留检查", "正式API删除测试规则; 检查DB、运行时和有效ipset"):
                cleanup = _cleanup_test_rules()
                if cleanup:
                    rec.add_detail(f"  {cleanup.message}")
                    if not cleanup.passed:
                        _add_failure(cleanup.message)
                rec.set_actual(
                    f"有效规则/运行时残留={'无' if cleanup and cleanup.passed else '需检查'}; "
                    f"空父集合={cleanup.details.get('empty_carrier_ipsets', []) if cleanup else '未知'}"
                )
        print(f"\n[上下行分流功能验证] {'通过' if not failures else '失败'+str(len(failures))+'项'}")
        assert not failures, f"上下行分流功能验证失败({len(failures)}项): {'; '.join(failures)}"
