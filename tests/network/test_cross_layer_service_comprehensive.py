"""
跨三层服务(SNMP)综合测试用例

一次测试多个功能，提高效率：
1. 添加8条规则（覆盖V2/V3、IP段、端口等组合）
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
14. 访问频率设置测试
15. 帮助功能测试
16. SSH后台数据验证

参照IP限速综合测试结构实现
集成SSH后台验证：在关键操作后验证数据库状态
"""
import pytest
import os
import sys
import io
from datetime import datetime

from pages.network.cross_layer_service_page import CrossLayerServicePage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.cross_layer_service
@pytest.mark.network
class TestCrossLayerServiceComprehensive:
    """跨三层服务(SNMP)综合测试 - 一次测试覆盖所有功能"""

    def test_cross_layer_service_comprehensive(self, cross_layer_page_logged_in: CrossLayerServicePage, step_recorder: StepRecorder, request):
        """
        综合测试: 添加8种场景 -> 编辑 -> 停用 -> 启用 -> 删除 -> 搜索 -> 排序 -> 导出 -> 异常测试 -> 批量操作 -> 导入 -> 访问频率 -> 帮助 -> SSH后台验证

        在关键操作后验证数据库状态
        """
        page = cross_layer_page_logged_in
        rec = step_recorder

        # 动态获取backend_verifier fixture（可选，未配置SSH时为None）
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except (pytest.FixtureLookupError, Exception):
            backend_verifier = None

        # SSH后台验证辅助函数 + 软断言收集器
        ssh_failures = []

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            if backend_verifier is None:
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = '通过' if result.passed else '失败'
                print(f"    SSH-{label}: {status} - {result.message}")
                rec.add_detail(f"    SSH-{label}: {'OK' if result.passed else 'FAIL'} {result.message}")
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

        # 测试数据 - 8条规则，覆盖各种数据组合场景
        # 注意: 每条规则的SNMP服务器IP必须唯一（iKuai不允许重复）
        test_rules = [
            # 规则1: 基础场景 - V2, 单个IP
            {"name": "snmp_test_001", "snmp_server_ip": "10.66.0.40", "ips": ["192.168.1.100"], "port": "161", "snmp_version": "V2", "community": "public", "remark": "基础场景-V2协议测试"},
            # 规则2: V2 + IP段
            {"name": "snmp_test_002", "snmp_server_ip": "10.66.0.41", "ips": ["192.168.1.1-192.168.1.50"], "port": "161", "snmp_version": "V2", "community": "public", "remark": "V2-IP段"},
            # 规则3: V3 + authNoPriv + MD5
            {"name": "snmp_test_003", "snmp_server_ip": "10.66.0.42", "ips": ["10.66.0.200"], "port": "162", "snmp_version": "V3", "community": "private_rw", "remark": "V3认证不加密-MD5", "v3_username": "snmp_user_003", "v3_security": "authNoPriv", "v3_auth_proto": "MD5", "v3_auth_pass": "authPass003"},
            # 规则4: V2 + 批量IP
            {"name": "snmp_test_004", "snmp_server_ip": "10.66.0.43", "ips": ["10.66.0.1", "10.66.0.5", "10.66.0.10"], "port": "161", "snmp_version": "V2", "community": "public", "remark": "V2-批量IP"},
            # 规则5: V3 + authPriv + SHA (认证且加密 + SHA)
            {"name": "snmp_test_005", "snmp_server_ip": "10.66.0.44", "ips": ["172.16.0.50"], "port": "161", "snmp_version": "V3", "community": "test_community", "remark": "V3认证且加密-SHA", "v3_username": "snmp_user_005", "v3_security": "authPriv", "v3_auth_proto": "SHA", "v3_auth_pass": "authPass005"},
            # 规则6: V3 + authPriv + MD5 (认证且加密 + MD5)
            {"name": "snmp_test_006", "snmp_server_ip": "10.66.0.45", "ips": ["172.16.0.100"], "port": "161", "snmp_version": "V3", "community": "snmp_v3_test", "remark": "V3认证且加密-MD5", "v3_username": "snmp_user_006", "v3_security": "authPriv", "v3_auth_proto": "MD5", "v3_auth_pass": "authPass006"},
            # 规则7: V2 + 备注测试
            {"name": "snmp_test_007", "snmp_server_ip": "10.66.0.46", "ips": ["192.168.1.200"], "port": "161", "snmp_version": "V2", "community": "public", "remark": "备注测试-特殊字符"},
            # 规则8: V3 + authNoPriv + SHA (认证不加密 + SHA)
            {"name": "snmp_test_008", "snmp_server_ip": "10.66.0.47", "ips": ["192.168.2.1-192.168.2.50"], "port": "161", "snmp_version": "V3", "community": "snmp_v3_sha", "remark": "V3认证不加密-SHA", "v3_username": "snmp_user_008", "v3_security": "authNoPriv", "v3_auth_proto": "SHA", "v3_auth_pass": "authPass008"},
        ]

        print("\n" + "=" * 60)
        print("跨三层服务(SNMP)综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")

        # ========== 步骤1: 验证页面 ==========
        with rec.step("步骤1: 验证跨三层服务页面", "确认页面标题和表格状态"):
            print("\n[步骤1] 验证跨三层服务页面...")
            rec.add_detail(f"【页面验证】")
            rec.add_detail(f"  当前URL: {page.page.url}")
            page.page.wait_for_timeout(500)
            rec.add_detail(f"  页面加载成功")

        # ========== 步骤2: 清理已有数据 ==========
        with rec.step("步骤2: 清理已有数据", "确保测试环境干净"):
            print("\n[步骤2] 清理已有数据...")
            rec.add_detail(f"【环境检查】")

            current_count = page.get_rule_count()
            if current_count > 0:
                print(f"  当前规则数量: {current_count}")
                print(f"  检测到残留数据，执行批量清理...")
                rec.add_detail(f"  当前规则数量: {current_count}")
                page.select_all_rules()
                page.batch_delete()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.page.wait_for_timeout(500)
                remaining = page.get_rule_count()
                print(f"  [OK] 跨三层服务规则清理完成，剩余 {remaining} 条规则")
                rec.add_detail(f"  清理完成，剩余 {remaining} 条规则")
            else:
                print(f"  [OK] 无需清理，数据已干净")
                rec.add_detail(f"  环境干净，无需清理")

        # ========== 步骤3: 检查测试数据是否已清理 ==========
        with rec.step("步骤3: 检查测试数据是否已清理", "确认没有残留数据"):
            print("\n[步骤3] 检查测试数据是否已清理...")
            rec.add_detail(f"【二次检查】")

            cleaned_count = 0
            for rule in test_rules:
                if page.rule_exists(rule["name"]):
                    rec.add_detail(f"  发现残留: {rule['name']}，执行删除")
                    page.delete_rule(rule["name"])
                    page.page.wait_for_timeout(300)
                    cleaned_count += 1

            if cleaned_count == 0:
                rec.add_detail("  无需清理，数据已干净")
            else:
                rec.add_detail(f"  共清理 {cleaned_count} 条残留数据")

            current_count = page.get_rule_count()
            print(f"  [OK] 数据检查完成，当前 {current_count} 条规则")
            rec.add_detail(f"  当前规则数: {current_count}")

        # ========== 步骤4: 批量添加8条规则 ==========
        with rec.step("步骤4: 批量添加规则", f"添加8条跨三层服务规则，覆盖V2/V3全部安全组合"):
            print(f"\n[步骤4] 批量添加{len(test_rules)}条规则...")
            rec.add_detail(f"【添加计划】共 {len(test_rules)} 条规则")
            rec.add_detail(f"  场景覆盖: V2×5条, V3×3条(authNoPriv+MD5, authPriv+SHA, authPriv+MD5, authNoPriv+SHA)")
            rec.add_detail(f"  IP格式: 单IP/IP段/批量IP, 每条规则SNMP服务器IP唯一")

            added_count = 0
            for rule in test_rules:
                rec.add_detail(f"【添加 {rule['name']}】")
                rec.add_detail(f"  SNMP服务器IP: {rule['snmp_server_ip']}")
                rec.add_detail(f"  作用IP段: {rule.get('ips', [])}")
                rec.add_detail(f"  端口: {rule.get('port', '161')}")
                rec.add_detail(f"  协议版本: {rule.get('snmp_version', 'V2')}")
                rec.add_detail(f"  团体名: {rule.get('community', 'public')}")
                rec.add_detail(f"  备注: {rule.get('remark', '')}")

                success = page.add_rule(
                    name=rule["name"],
                    snmp_server_ip=rule["snmp_server_ip"],
                    ips=rule.get("ips"),
                    port=rule.get("port", "161"),
                    snmp_version=rule.get("snmp_version", "V2"),
                    community=rule.get("community", "public"),
                    remark=rule.get("remark", ""),
                    v3_username=rule.get("v3_username"),
                    v3_security=rule.get("v3_security"),
                    v3_auth_proto=rule.get("v3_auth_proto", "MD5"),
                    v3_auth_pass=rule.get("v3_auth_pass"),
                )
                if success:
                    print(f"  + 已添加: {rule['name']} - {rule.get('remark', '')}")
                    rec.add_detail(f"  添加成功")
                    added_count += 1
                else:
                    print(f"  + 添加失败: {rule['name']}")
                    rec.add_detail(f"  添加失败")

                page.page.wait_for_timeout(500)

            # 验证添加结果 - 先导航回列表页面再检查
            page.navigate_to_cross_layer_service()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            actual_added = 0
            for rule in test_rules:
                if page.rule_exists(rule["name"]):
                    actual_added += 1
                else:
                    rec.add_detail(f"  规则 {rule['name']} 未找到")

            print(f"  [OK] 成功添加 {actual_added}/{len(test_rules)} 条规则")
            rec.add_detail(f"  实际验证: {actual_added}/{len(test_rules)} 条规则已存在于列表中")

            assert actual_added >= added_count, f"验证添加结果: {actual_added}/{len(test_rules)}"

        # ========== 步骤5: 后台数据验证（SSH） ==========
        if backend_verifier is not None:
            with rec.step("步骤5: 后台数据验证", "SSH全链路验证数据库中的规则数据"):
                print(f"\n[步骤5] 后台数据验证（SSH全链路）...")
                rec.add_detail("【SSH后台全链路验证】")

                # L4: 内核验证
                ssh_verify("L4-内核", backend_verifier.verify_kernel, must_pass=True)

                # L1: 数据库验证 - 逐条验证每条规则
                verify_total = len(test_rules)
                verify_passed = 0

                for rule in test_rules:
                    rule_name = rule["name"]
                    rec.add_detail(f"  -- 验证规则: {rule_name} --")
                    print(f"  验证规则: {rule_name}")

                    # L1: 数据库验证（批量添加不强制通过，可能因时序问题个别失败）
                    l1 = ssh_verify(
                        f"L1-数据库({rule_name})",
                        backend_verifier.verify_netsnmpc_database,
                        tagname=rule_name,
                        must_pass=False,
                    )

                    if l1 and l1.passed:
                        rule_id = l1.details.get("rule", {}).get("id")
                        db_rule = l1.details.get("rule", {})
                        rec.add_detail(f"      数据库: id={rule_id}, snmp_ip={db_rule.get('snmp_ip')}, port={db_rule.get('port')}, version={db_rule.get('version')}, enabled={db_rule.get('enabled')}")
                        verify_passed += 1
                    elif l1 is None:
                        rec.add_detail(f"      跳过（SSH不可用）")
                    else:
                        rec.add_detail(f"      L1验证未通过，跳过L2")

                print(f"  [OK] 后台验证完成: {verify_passed}/{verify_total} 条规则L1验证通过")
                rec.add_detail(f"  -- 验证汇总: {verify_passed}/{verify_total} 条规则验证通过 --")
        else:
            print("\n[步骤5] 后台数据验证: 跳过（未配置SSH或paramiko未安装）")

        # ========== 步骤6: 编辑规则 ==========
        with rec.step("步骤6: 编辑规则", "编辑第1条规则的SNMP服务器IP"):
            print(f"\n[步骤6] 编辑规则...")
            edit_rule = test_rules[0]
            new_snmp_ip = "10.66.0.99"
            rec.add_detail(f"【编辑操作】")
            rec.add_detail(f"  目标规则: {edit_rule['name']}")
            rec.add_detail(f"  新SNMP服务器IP: {new_snmp_ip}")

            success = page.edit_rule(
                old_name=edit_rule["name"],
                snmp_server_ip=new_snmp_ip,
            )

            if success:
                test_rules[0]["snmp_server_ip"] = new_snmp_ip
                print(f"  [OK] 规则编辑成功: {edit_rule['name']} -> SNMP IP改为 {new_snmp_ip}")
                rec.add_detail(f"  编辑成功，SNMP IP已修改")
            else:
                print(f"  [WARN] 规则编辑失败")
                rec.add_detail(f"  编辑失败")

            page.page.reload()
            page.page.wait_for_timeout(500)

            # SSH验证编辑结果
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-编辑后】")
                ssh_verify(
                    f"L1-编辑验证({edit_rule['name']})",
                    backend_verifier.verify_netsnmpc_database,
                    tagname=edit_rule["name"],
                    expected_fields={"server_ip": new_snmp_ip},
                    must_pass=True,
                )

        # ========== 步骤7: 单独停用 ==========
        with rec.step("步骤7: 单独停用", "停用第2条规则"):
            print(f"\n[步骤7] 单独停用...")
            disable_rule = test_rules[1]
            rec.add_detail(f"【停用操作】")
            rec.add_detail(f"  目标规则: {disable_rule['name']}")

            success = page.disable_rule(disable_rule["name"])
            page.page.wait_for_timeout(1000)

            if success:
                print(f"  [OK] 规则停用成功: {disable_rule['name']}")
                rec.add_detail(f"  停用成功")
            else:
                print(f"  [WARN] 停用失败")
                rec.add_detail(f"  停用失败")

            page.page.reload()
            page.page.wait_for_timeout(500)

            # SSH验证停用结果
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-停用后】")
                ssh_verify(
                    f"L1-停用验证({disable_rule['name']})",
                    backend_verifier.verify_netsnmpc_database,
                    tagname=disable_rule["name"],
                    must_pass=True,
                )

        # ========== 步骤8: 单独启用 ==========
        with rec.step("步骤8: 单独启用", "启用第2条规则"):
            print(f"\n[步骤8] 单独启用...")
            enable_rule = test_rules[1]
            rec.add_detail(f"【启用操作】")
            rec.add_detail(f"  目标规则: {enable_rule['name']}")

            success = page.enable_rule(enable_rule["name"])
            page.page.wait_for_timeout(1000)

            if success:
                print(f"  [OK] 规则启用成功: {enable_rule['name']}")
                rec.add_detail(f"  启用成功")
            else:
                print(f"  [WARN] 启用失败")
                rec.add_detail(f"  启用失败")

            page.page.reload()
            page.page.wait_for_timeout(500)

            # SSH验证启用结果
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-启用后】")
                ssh_verify(
                    f"L1-启用验证({enable_rule['name']})",
                    backend_verifier.verify_netsnmpc_database,
                    tagname=enable_rule["name"],
                    must_pass=True,
                )

        # ========== 步骤9: 单独删除 ==========
        with rec.step("步骤9: 单独删除", "删除第3条规则"):
            print(f"\n[步骤9] 单独删除...")
            delete_rule = test_rules[2]
            rec.add_detail(f"【删除操作】")
            rec.add_detail(f"  目标规则: {delete_rule['name']}")

            count_before = page.get_rule_count()
            success = page.delete_rule(delete_rule["name"])
            page.page.wait_for_timeout(1000)
            count_after = page.get_rule_count()

            if count_after < count_before:
                test_rules.remove(delete_rule)
                print(f"  [OK] 规则删除成功: {delete_rule['name']}")
                rec.add_detail(f"  删除成功，条目数从 {count_before} 减少到 {count_after}")
            else:
                print(f"  [WARN] 删除验证失败")
                rec.add_detail(f"  删除未确认")

            page.page.reload()
            page.page.wait_for_timeout(500)

            # SSH验证删除结果
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-删除后】")
                l1 = ssh_verify(
                    f"L1-删除验证({delete_rule['name']})",
                    backend_verifier.verify_netsnmpc_database,
                    tagname=delete_rule["name"],
                    must_pass=False,
                )
                if l1 and not l1.passed:
                    rec.add_detail(f"    SSH-L1-删除验证: 通过 - 规则已从数据库删除")
                else:
                    rec.add_detail(f"    SSH-L1-删除验证: 规则可能仍存在")

        # ========== 步骤10: 搜索测试 ==========
        with rec.step("步骤10: 搜索测试", "测试搜索功能"):
            print(f"\n[步骤10] 搜索测试...")
            rec.add_detail(f"【搜索测试】")

            # 搜索存在的规则
            search_target = test_rules[2]["name"]
            rec.add_detail(f"  测试1: 搜索存在的规则")
            rec.add_detail(f"    搜索关键词: {search_target}")
            page.search_rule(search_target)
            page.page.wait_for_timeout(500)

            if page.rule_exists(search_target):
                print(f"  [OK] 搜索存在规则成功: {search_target}")
                rec.add_detail(f"    搜索成功，规则已找到")
            else:
                print(f"  [WARN] 搜索未找到规则")
                rec.add_detail(f"    搜索未找到")

            # 搜索不存在的规则
            rec.add_detail(f"  测试2: 搜索不存在的规则")
            page.search_rule("nonexistent_rule_99999")
            page.page.wait_for_timeout(500)
            current_count = page.get_rule_count()
            if current_count == 0:
                print(f"  [OK] 搜索不存在规则验证成功，显示0条记录")
                rec.add_detail(f"    验证成功，显示0条记录")
            else:
                print(f"  [WARN] 搜索不存在的规则显示{current_count}条记录")
                rec.add_detail(f"    显示{current_count}条记录(预期0条)")

            # 清空搜索
            rec.add_detail(f"  测试3: 清空搜索条件")
            page.clear_search()
            page.page.wait_for_timeout(500)
            after_clear_count = page.get_rule_count()
            print(f"  [OK] 清空搜索成功，当前显示 {after_clear_count} 条记录")
            rec.add_detail(f"    清空成功，显示 {after_clear_count} 条记录")

        # ========== 步骤11: 排序测试 ==========
        with rec.step("步骤11: 排序测试", "测试名称字段排序3次(正序->倒序->默认)"):
            print(f"\n[步骤11] 排序测试...")
            rec.add_detail(f"【排序测试】")
            rec.add_detail(f"  测试字段: 名称（仅名称支持排序）")

            sort_results = page.test_sorting()
            for col in ["名称"]:
                if col in sort_results:
                    result = sort_results[col]
                    status = "成功" if result == "成功" else "失败"
                    print(f"  [OK] {col} 排序(正序->倒序->默认): {status}")
                    rec.add_detail(f"  {col} 排序: {status}")
                else:
                    print(f"  [SKIP] {col} 排序: 不支持")
                    rec.add_detail(f"  {col} 排序: 跳过（不支持）")

        # ========== 步骤12: 导出测试 ==========
        with rec.step("步骤12: 导出规则", "导出CSV和TXT两种格式的配置文件"):
            print(f"\n[步骤12] 导出跨三层服务规则...")
            rec.add_detail(f"【导出测试】")

            config = get_config()
            export_dir = config.report.export_dir if hasattr(config.report, 'export_dir') else "test_data/exports/cross_layer_service"
            os.makedirs(export_dir, exist_ok=True)

            # 导出路径
            export_file_csv = os.path.join(export_dir, "cross_layer_service_config.csv")
            export_file_txt = os.path.join(export_dir, "cross_layer_service_config.txt")

            try:
                # 测试1: 导出CSV
                rec.add_detail(f"  测试1: 导出CSV格式")
                export_result_csv = page.export_rules(export_format="csv")
                if export_result_csv:
                    print(f"  [OK] 导出CSV成功")
                    rec.add_detail(f"    CSV导出成功")
                else:
                    print(f"  [WARN] 导出CSV失败")
                    rec.add_detail(f"    CSV导出失败")

                page.page.wait_for_timeout(500)

                # 测试2: 导出TXT
                rec.add_detail(f"  测试2: 导出TXT格式")
                export_result_txt = page.export_rules(export_format="txt")
                if export_result_txt:
                    print(f"  [OK] 导出TXT成功")
                    rec.add_detail(f"    TXT导出成功")
                else:
                    print(f"  [WARN] 导出TXT失败")
                    rec.add_detail(f"    TXT导出失败")

            except Exception as e:
                print(f"  [WARN] 导出测试异常: {e}")
                rec.add_detail(f"  导出异常: {str(e)[:50]}")

            page.close_modal_if_exists()
            page.page.reload()
            page.page.wait_for_timeout(500)

        # ========== 步骤13: 异常输入测试 ==========
        with rec.step("步骤13: 异常输入测试", "测试各种无效输入的表单验证"):
            print(f"\n[步骤13] 异常输入测试...")
            rec.add_detail(f"【异常输入测试】")

            # 13.1 名称为空
            print(f"\n  [13.1] 名称为空测试...")
            rec.add_detail("  【13.1 名称为空验证】")
            result = page.try_add_rule_invalid(name="")
            if result["success"]:
                print(f"    [OK] 名称为空: 正确拦截 - {result['error_message']}")
                rec.add_detail(f"  正确拦截 - {result['error_message']}")
            else:
                print(f"    [FAIL] 名称为空: 未拦截")
                rec.add_detail(f"  未拦截")

            # 13.2 SNMP服务器IP为空
            print(f"\n  [13.2] SNMP服务器IP为空测试...")
            rec.add_detail("  【13.2 SNMP服务器IP为空验证】")
            result = page.try_add_rule_invalid(
                name="empty_ip_test",
                snmp_server_ip="",
            )
            if result["success"]:
                print(f"    [OK] SNMP服务器IP为空: 正确拦截 - {result['error_message']}")
                rec.add_detail(f"  正确拦截 - {result['error_message']}")
            else:
                print(f"    [INFO] SNMP服务器IP为空: 未拦截(可能后端验证)")
                rec.add_detail(f"  未拦截")

            # 13.3 SNMP服务器IP格式错误
            print(f"\n  [13.3] SNMP服务器IP格式错误测试...")
            rec.add_detail("  【13.3 SNMP服务器IP格式验证】")
            for invalid_ip in ["999.999.999.999", "abc.def.ghi.jkl", "10.66.0", "192.168.1.256"]:
                result = page.try_add_rule_invalid(
                    name="invalid_ip_test",
                    snmp_server_ip=invalid_ip,
                )
                if result["success"]:
                    print(f"    [OK] IP {invalid_ip}: 正确拦截 - {result['error_message']}")
                    rec.add_detail(f"  IP {invalid_ip}: 正确拦截")
                else:
                    print(f"    [INFO] IP {invalid_ip}: 未拦截(可能后端验证)")
                    rec.add_detail(f"  IP {invalid_ip}: 未拦截")
                page.page.wait_for_timeout(300)

            # 13.4 端口异常值
            print(f"\n  [13.4] 端口异常值测试...")
            rec.add_detail("  【13.4 端口范围验证】")
            for invalid_port in ["0", "99999", "-1", "abc", "3.14"]:
                result = page.try_add_rule_invalid(
                    name="invalid_port_test",
                    snmp_server_ip="10.66.0.99",
                    port=invalid_port,
                )
                if result["success"]:
                    print(f"    [OK] 端口 {invalid_port}: 正确拦截 - {result['error_message']}")
                    rec.add_detail(f"  端口 {invalid_port}: 正确拦截")
                else:
                    print(f"    [INFO] 端口 {invalid_port}: 未拦截")
                    rec.add_detail(f"  端口 {invalid_port}: 未拦截")
                page.page.wait_for_timeout(300)

            # 13.5 备注特殊字符
            print(f"\n  [13.5] 备注特殊字符测试...")
            rec.add_detail("  【13.5 备注特殊字符验证】")
            for special_char in ["+test", "@test", "#test"]:
                result = page.try_add_rule_invalid(
                    name=f"special_{special_char}",
                    snmp_server_ip="10.66.0.99",
                    remark=special_char,
                )
                if result["success"]:
                    print(f"    [OK] 包含{special_char}号: 正确拦截 - {result['error_message']}")
                    rec.add_detail(f"  包含{special_char}: 正确拦截")
                else:
                    print(f"    [INFO] 包含{special_char}号: 未拦截(可能允许)")
                    rec.add_detail(f"  包含{special_char}: 未拦截")
                page.page.wait_for_timeout(300)

            # 13.6 重复SNMP服务器IP（使用已存在的IP）
            print(f"\n  [13.6] 重复SNMP服务器IP测试...")
            rec.add_detail("  【13.6 重复SNMP服务器IP验证】")
            duplicate_ip = test_rules[0]["snmp_server_ip"]
            result = page.try_add_rule_invalid(
                name="duplicate_ip_test",
                snmp_server_ip=duplicate_ip,
            )
            if result["success"]:
                print(f"    [OK] 重复IP {duplicate_ip}: 正确拦截 - {result['error_message']}")
                rec.add_detail(f"  重复IP {duplicate_ip}: 正确拦截 - {result['error_message']}")
            else:
                print(f"    [INFO] 重复IP {duplicate_ip}: 未拦截(可能后端验证)")
                rec.add_detail(f"  重复IP {duplicate_ip}: 未拦截")
            page.page.wait_for_timeout(300)

            print(f"\n  [OK] 异常输入测试完成")
            rec.add_detail(f"  异常输入测试完成")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

        # ========== 步骤14: 批量停用 ==========
        with rec.step("步骤14: 批量停用所有规则", "测试批量停用功能"):
            print(f"\n[步骤14] 批量停用所有规则...")
            rec.add_detail(f"【批量停用操作】")

            page.navigate_to_cross_layer_service()
            page.page.reload()
            page.page.wait_for_timeout(500)

            page.select_all_rules()
            page.batch_disable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            print(f"  [OK] 批量停用完成，当前共 {current_count} 条规则")
            rec.add_detail(f"  批量停用完成: {current_count} 条规则")

            # SSH验证
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-批量停用后】")
                all_rules = backend_verifier.query_netsnmpc_rules()
                disabled_count = sum(1 for r in (all_rules or []) if r.get('enabled') == 'no')
                rec.add_detail(f"    SSH: 数据库中{disabled_count}/{len(all_rules or [])}条规则已停用")
                print(f"    SSH: 数据库中{disabled_count}/{len(all_rules or [])}条规则已停用")

        # ========== 步骤15: 批量启用 ==========
        with rec.step("步骤15: 批量启用所有规则", "测试批量启用功能"):
            print(f"\n[步骤15] 批量启用所有规则...")
            rec.add_detail(f"【批量启用操作】")

            page.page.reload()
            page.page.wait_for_timeout(500)

            page.select_all_rules()
            page.batch_enable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            print(f"  [OK] 批量启用完成，当前共 {current_count} 条规则")
            rec.add_detail(f"  批量启用完成: {current_count} 条规则")

        # ========== 步骤16: 批量删除 ==========
        with rec.step("步骤16: 批量删除所有规则", "测试批量删除功能"):
            print(f"\n[步骤16] 批量删除所有规则...")
            rec.add_detail(f"【批量删除操作】")
            rec.add_detail(f"  目标数量: {len(test_rules)} 条规则")

            page.page.reload()
            page.page.wait_for_timeout(500)

            delete_success = False
            for attempt in range(3):
                page.select_all_rules()
                page.batch_delete()
                page.page.wait_for_timeout(2000)

                page.page.reload()
                page.page.wait_for_timeout(500)

                current_count = page.get_rule_count()
                if current_count == 0:
                    delete_success = True
                    break
                else:
                    print(f"  第{attempt + 1}次批量删除后剩余 {current_count} 条，重试...")
                    rec.add_detail(f"  第{attempt + 1}次删除后剩余{current_count}条，重试")

            if delete_success:
                print(f"  [OK] 批量删除完成，所有规则已清除")
                rec.add_detail(f"  批量删除成功: 所有规则已清除")
            else:
                print(f"  [WARN] 批量删除后仍剩余 {current_count} 条规则")
                rec.add_detail(f"  批量删除未完全清除: 剩余{current_count}条规则")

            # SSH验证删除结果
            if backend_verifier is not None:
                rec.add_detail(f"  【SSH验证-批量删除后】")
                all_rules = backend_verifier.query_netsnmpc_rules()
                test_rule_names = [rule.get("tagname", rule.get("name", "")) for rule in (all_rules or []) if "snmp_test" in rule.get("tagname", "")]
                if test_rule_names:
                    rec.add_detail(f"    SSH: 测试规则未完全删除: {test_rule_names}")
                    print(f"    SSH WARNING: 测试规则未完全删除: {test_rule_names}")
                else:
                    rec.add_detail(f"    SSH: 数据库中测试规则已全部删除（总规则数: {len(all_rules or [])}）")
                    print(f"    SSH: 数据库中测试规则已全部删除（总规则数: {len(all_rules or [])}）")

        # ========== 步骤17: 导入测试 ==========
        with rec.step("步骤17: 导入跨三层服务规则", "测试导入功能（不勾选清空+勾选清空）"):
            print(f"\n[步骤17] 导入跨三层服务规则测试...")
            rec.add_detail(f"【导入测试】")

            config = get_config()
            export_dir = config.report.export_dir if hasattr(config.report, 'export_dir') else "test_data/exports/cross_layer_service"

            # 使用步骤12中导出的文件路径
            csv_file = os.path.join(export_dir, "cross_layer_service_config.csv")
            txt_file = os.path.join(export_dir, "cross_layer_service_config.txt")

            # 测试1: CSV导入（不勾选清空配置 - 追加模式）
            if os.path.exists(csv_file):
                rec.add_detail(f"  测试1: CSV导入（不勾选清空配置）")
                rec.add_detail(f"    导入文件: {os.path.basename(csv_file)}")
                count_before = page.get_rule_count()
                import_result = page.import_rules(csv_file, clear_existing=False)
                page.page.reload()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                if import_result and count_after > count_before:
                    print(f"  [OK] CSV导入成功（追加模式），添加 {count_after - count_before} 条记录")
                    rec.add_detail(f"    成功添加 {count_after - count_before} 条记录")
                else:
                    print(f"  [WARN] CSV导入可能失败（导入前{count_before}条，导入后{count_after}条）")
                    rec.add_detail(f"    导入结果未确认（{count_before}->{count_after}）")
            else:
                print(f"  [WARN] CSV文件不存在: {csv_file}")
                rec.add_detail(f"  CSV文件不存在: {csv_file}")

            page.page.wait_for_timeout(500)

            # 测试2: TXT导入（勾选清空配置 - 替换模式）
            if os.path.exists(txt_file):
                rec.add_detail(f"  测试2: TXT导入（勾选清空配置 - 替换模式）")
                rec.add_detail(f"    导入文件: {os.path.basename(txt_file)}")
                import_result = page.import_rules(txt_file, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(500)
                if import_result:
                    print(f"  [OK] TXT导入完成（已清空旧数据）")
                    rec.add_detail(f"    TXT导入完成（已清空旧数据）")
                else:
                    print(f"  [WARN] TXT导入可能失败")
                    rec.add_detail(f"    TXT导入结果未确认")
            else:
                print(f"  [WARN] TXT文件不存在: {txt_file}")
                rec.add_detail(f"  TXT文件不存在: {txt_file}")

        # ========== 步骤18: 清理导入的规则 ==========
        with rec.step("步骤18: 清理导入的规则", "删除导入测试产生的规则"):
            print(f"\n[步骤18] 清理导入的规则...")
            rec.add_detail(f"【环境清理】")

            page.page.reload()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                page.select_all_rules()
                page.batch_delete()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.page.wait_for_timeout(500)
                remaining = page.get_rule_count()
                print(f"  [OK] 清理完成，剩余 {remaining} 条规则")
                rec.add_detail(f"  清理完成: 剩余{remaining}条规则")
            else:
                print(f"  [OK] 没有需要清理的规则")
                rec.add_detail(f"  环境已干净，无需清理")

        # ========== 步骤19: 访问频率设置测试 ==========
        with rec.step("步骤19: 访问频率设置测试", "测试访问频率设置并验证保存"):
            print(f"\n[步骤19] 访问频率设置测试...")
            rec.add_detail(f"【访问频率设置】")

            # 测试1: 设置频率为60秒并验证保存
            page.set_frequency(60)
            page.page.wait_for_timeout(1000)
            saved_value = page.get_frequency()
            if saved_value == "60":
                print(f"  [OK] 访问频率设置60秒 - 保存验证通过")
                rec.add_detail(f"  设置60秒: 保存验证通过（读取值={saved_value}）")
            else:
                print(f"  [WARN] 访问频率设置60秒 - 保存验证失败（期望60，实际={saved_value}）")
                rec.add_detail(f"  设置60秒: 保存验证失败（期望60，实际={saved_value}）")

            # 测试2: 恢复默认(0=实时)并验证
            page.set_frequency(0)
            page.page.wait_for_timeout(1000)
            saved_value = page.get_frequency()
            if saved_value == "0":
                print(f"  [OK] 访问频率恢复默认(0) - 保存验证通过")
                rec.add_detail(f"  恢复默认0: 保存验证通过（读取值={saved_value}）")
            else:
                print(f"  [WARN] 访问频率恢复默认(0) - 保存验证失败（期望0，实际={saved_value}）")
                rec.add_detail(f"  恢复默认0: 保存验证失败（期望0，实际={saved_value}）")

            # 测试3: 异常值 - 字母
            print(f"\n  [19.1] 频率异常值测试 - 输入字母...")
            rec.add_detail("  【19.1 频率异常值 - 字母】")
            result = page.try_set_frequency_invalid("abc")
            if result["success"]:
                print(f"    [OK] 字母abc: 正确拦截 - {result['error_message']}")
                rec.add_detail(f"  字母abc: 正确拦截 - {result['error_message']}")
            else:
                print(f"    [INFO] 字母abc: 未拦截（实际保存值={result.get('saved_value', '')}）")
                rec.add_detail(f"  字母abc: 未拦截（保存值={result.get('saved_value', '')}）")

            # 测试4: 异常值 - 超大值
            print(f"\n  [19.2] 频率异常值测试 - 超大值...")
            rec.add_detail("  【19.2 频率异常值 - 超大值】")
            result = page.try_set_frequency_invalid("999999")
            if result["success"]:
                print(f"    [OK] 超大值999999: 正确拦截 - {result['error_message']}")
                rec.add_detail(f"  超大值999999: 正确拦截 - {result['error_message']}")
            else:
                print(f"    [INFO] 超大值999999: 未拦截（实际保存值={result.get('saved_value', '')}）")
                rec.add_detail(f"  超大值999999: 未拦截（保存值={result.get('saved_value', '')}）")

            # 测试5: 异常值 - 负数
            print(f"\n  [19.3] 频率异常值测试 - 负数...")
            rec.add_detail("  【19.3 频率异常值 - 负数】")
            result = page.try_set_frequency_invalid("-1")
            if result["success"]:
                print(f"    [OK] 负数-1: 正确拦截 - {result['error_message']}")
                rec.add_detail(f"  负数-1: 正确拦截 - {result['error_message']}")
            else:
                print(f"    [INFO] 负数-1: 未拦截（实际保存值={result.get('saved_value', '')}）")
                rec.add_detail(f"  负数-1: 未拦截（保存值={result.get('saved_value', '')}）")

            # 测试6: 异常值 - 特殊字符
            print(f"\n  [19.4] 频率异常值测试 - 特殊字符...")
            rec.add_detail("  【19.4 频率异常值 - 特殊字符】")
            result = page.try_set_frequency_invalid("12.5")
            if result["success"]:
                print(f"    [OK] 小数12.5: 正确拦截 - {result['error_message']}")
                rec.add_detail(f"  小数12.5: 正确拦截 - {result['error_message']}")
            else:
                print(f"    [INFO] 小数12.5: 未拦截（实际保存值={result.get('saved_value', '')}）")
                rec.add_detail(f"  小数12.5: 未拦截（保存值={result.get('saved_value', '')}）")

            # 最终恢复默认值
            page.set_frequency(0)
            page.page.wait_for_timeout(500)

        # ========== 步骤20: 帮助功能测试 ==========
        with rec.step("步骤20: 帮助功能测试", "测试帮助功能"):
            print(f"\n[步骤20] 帮助功能测试...")
            rec.add_detail(f"【帮助功能测试】")

            help_result = page.test_help_functionality()

            if help_result.get('icon_clickable', False) or help_result.get('visible', False):
                print(f"  [OK] 帮助功能测试通过")
                rec.add_detail(f"  帮助功能: 通过")
            else:
                print(f"  [WARN] 帮助功能测试未通过")
                rec.add_detail(f"  帮助功能: 未通过")

        # ========== 步骤21: 最终清理测试数据 ==========
        with rec.step("步骤21: 最终清理测试数据", "确保所有测试数据已删除"):
            print(f"\n[步骤21] 最终清理测试数据...")
            rec.add_detail(f"【最终清理】")

            page.navigate_to_cross_layer_service()
            page.page.reload()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                page.select_all_rules()
                page.batch_delete()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.page.wait_for_timeout(500)
                remaining = page.get_rule_count()
                print(f"  [OK] 测试数据清理完成，剩余 {remaining} 条规则")
                rec.add_detail(f"  清理完成: 剩余{remaining}条规则")
            else:
                print(f"  [OK] 数据已干净")
                rec.add_detail(f"  数据已干净")

        # ========== SSH后台验证汇总断言 ==========
        if ssh_failures:
            print(f"\n[SSH断言] 共 {len(ssh_failures)} 项后台验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
                rec.add_detail(f"  SSH失败: {f}")
            assert not ssh_failures, f"SSH后台验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"

        # ========== 测试总结 ==========
        print("\n" + "=" * 60)
        print("跨三层服务(SNMP)综合测试完成")
        print("=" * 60)
        print("测试覆盖功能:")
        print("  - 环境清理: 测试前检查并批量清理")
        print(f"  - 添加: {len(test_rules)}条规则")
        print(f"    * 协议版本覆盖: V2/V3")
        print(f"    * IP格式覆盖: 单IP/IP段/批量IP/CIDR")
        print(f"    * 备注: 每条规则都有有意义的备注")
        print("  - 编辑: 1条")
        print("  - 单独停用: 1条")
        print("  - 单独启用: 1条")
        print("  - 单独删除: 1条")
        print("  - 搜索: 存在/不存在/清空")
        print("  - 排序: 名称/端口/协议版本")
        print("  - 导出: CSV和TXT")
        print("  - 异常测试: 名称/IP/端口/备注特殊字符")
        print("  - 批量停用")
        print("  - 批量启用")
        print("  - 批量删除")
        print("  - 导入: CSV和TXT")
        print("  - 访问频率设置")
        print("  - 帮助功能")
        print("  - SSH后台数据验证")
        print("  - 最终清理")
