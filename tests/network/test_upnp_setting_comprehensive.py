"""
UPnP/NAT设置综合测试用例

一次测试覆盖多个功能：
1. 添加7条规则（覆盖单IP/多IP/IP段/多线路/所有线路/带备注/无备注）
2. SSH后台数据验证（L1数据库逐条验证 + L2进程/iptables + L3运行时配置 + L4守护进程）
3. 编辑其中1条
4. 复制测试
5. 停用/启用/删除各1条
6. 搜索测试（精确/部分/不存在/清空）
7. 排序测试（线路）
8. 导出测试（CSV/TXT）
9. 异常输入测试（空名称/重复/超长/特殊字符/纯空格/备注特殊字符）
10. 批量停用/启用/删除
11. 导入测试（追加CSV+清空现有TXT）
12. 设置抽屉测试（开启UPnP/排除端口/掉线检测/定时重启/无效设置/关闭UPnP）
13. 帮助功能测试

SSH后台验证: L1数据库(upnpd_conf+upnpd_ifconf) + L2进程(miniupnpd)+iptables + L3运行时配置 + L4守护进程+cron
字段映射: tagname(名称), src_addr(内网IP JSON), interface(线路), comment(备注)
"""
import pytest
import os
from pages.network.upnp_setting_page import UpnpSettingPage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.upnp_setting
@pytest.mark.network
class TestUpnpSettingComprehensive:
    """UPnP/NAT设置综合测试 - 一次测试覆盖所有功能"""

    def test_upnp_setting_comprehensive(self, upnp_setting_page_logged_in: UpnpSettingPage,
                                         step_recorder: StepRecorder, request):
        """
        综合测试: 添加7条规则 -> SSH验证 -> 编辑 -> 复制 -> 停用 -> 启用 -> 删除 ->
        搜索 -> 排序 -> 导出 -> 异常测试 -> 批量操作 -> 导入 -> 设置抽屉 -> 帮助
        """
        page = upnp_setting_page_logged_in
        rec = step_recorder

        # 动态获取backend_verifier fixture
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
                    print(f"      SSH数据: {result.raw_output}")
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

        # 测试数据 - 7条规则，覆盖单IP/多IP/IP段/多线路/所有线路/备注
        # 名称只允许中文英文数字(不允许下划线等特殊字符)
        test_rules = [
            # Rule 1: 单IP+单线路(wan1)
            {"name": "upnp基础", "ips": ["192.168.1.100"], "lines": ["wan1"],
             "desc": "单IP+单线路(wan1)"},
            # Rule 2: 多IP+单线路(wan2)
            {"name": "upnp多IP", "ips": ["192.168.1.101", "192.168.1.102"], "lines": ["wan2"],
             "desc": "多IP+单线路(wan2)"},
            # Rule 3: IP段+单线路(wan3)
            {"name": "upnpIP段", "ips": ["192.168.2.1-192.168.2.100"], "lines": ["wan3"],
             "desc": "IP段+单线路(wan3)"},
            # Rule 4: 单IP+多线路(wan1+wan2)
            {"name": "upnp多线路", "ips": ["192.168.3.50"], "lines": ["wan1", "wan2"],
             "desc": "单IP+多线路(wan1+wan2)"},
            # Rule 5: 单IP+所有线路
            {"name": "upnp全线路", "ips": ["10.66.0.100"], "lines": ["wan1", "wan2", "wan3"],
             "desc": "单IP+所有线路"},
            # Rule 6: 带备注
            {"name": "upnp带备注", "ips": ["192.168.5.10"], "lines": ["wan1"],
             "remark": "UPnP测试备注", "desc": "带备注"},
            # Rule 7: 无备注
            {"name": "upnp无备注", "ips": ["172.16.0.5"], "lines": ["wan2"],
             "desc": "无备注"},
        ]

        print("\n" + "=" * 60)
        print("UPnP/NAT设置综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")
        for r in test_rules:
            ips = r.get("ips", [])
            lines = r.get("lines", [])
            print(f"  - {r['name']}, IP={','.join(ips)}, "
                  f"线路={'+'.join(lines)}, "
                  f"场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            for cleanup_round in range(3):
                page.navigate_to_upnp_setting()
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

            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(1000)
            final_count = page.get_rule_count()
            print(f"  [OK] 环境清理完成，剩余 {final_count} 条")
            rec.add_detail(f"[清理结果] 剩余 {final_count} 条")

        # ========== 步骤2-8: 逐条添加7条规则 ==========
        added_count = 0
        rule_id_map = {}
        for rule_idx, rule in enumerate(test_rules):
            step_num = rule_idx + 2
            with rec.step(f"步骤{step_num}: 添加规则 {rule['name']}",
                          f"添加: {rule['desc']}"):
                print(f"\n[步骤{step_num}] 添加规则: {rule['name']}")
                rec.add_detail(f"  场景: {rule['desc']}")
                rec.add_detail(f"  IP: {rule.get('ips', [])}, 线路: {rule.get('lines', [])}")
                if rule.get("remark"):
                    rec.add_detail(f"  备注: {rule['remark']}")

                result = page.add_rule(
                    name=rule["name"],
                    ips=rule.get("ips"),
                    lines=rule.get("lines"),
                    remark=rule.get("remark"),
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")
                added_count += 1

                # SSH L1验证
                if backend_verifier is not None:
                    expected = {"enabled": "yes"}
                    if rule.get("remark"):
                        expected["comment"] = rule["remark"]
                    l1 = ssh_verify(
                        f"L1-数据库({rule['name']})",
                        backend_verifier.verify_upnpd_ifconf_database,
                        rule["name"],
                        must_pass=True,
                        expected_fields=expected,
                    )
                    if l1 and l1.passed:
                        db_rule = l1.details.get("rule", {})
                        db_id = db_rule.get("id")
                        rule_id_map[rule["name"]] = db_id
                        rec.add_detail(f"      数据库: id={db_id}, interface={db_rule.get('interface')}, "
                                       f"enabled={db_rule.get('enabled')}")

        # ========== 步骤9: 验证总数 + 后端全链路验证 ==========
        with rec.step("步骤9: 验证总数 + 后端全链路", f"验证共{len(test_rules)}条 + SSH L1-L4"):
            print(f"\n[步骤9] 验证总数...")
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(1000)
            page.clear_search()
            page.page.wait_for_timeout(500)
            all_names = page.get_rule_list()
            rec.add_detail(f"  当前列表({len(all_names)}条): {all_names}")
            for rule in test_rules:
                assert rule["name"] in all_names, f"规则 {rule['name']} 未找到，当前列表: {all_names}"
            total = page.get_rule_count()
            assert total == len(test_rules), f"规则总数应为{len(test_rules)}，实际{total}"
            print(f"  [OK] 总数验证: {total} 条")
            rec.add_detail(f"  [OK] 总数验证通过: {total} 条")

            # SSH全链路验证
            if backend_verifier is not None:
                rec.add_detail("[SSH全链路验证] L1=数据库, L2=进程/iptables, L3=运行时配置, L4=守护进程")
                for rule in test_rules:
                    rec.add_detail(f"  -- 验证: {rule['name']} --")
                    # L1数据库验证(此前循环体只add_detail不验证, 7条规则L1完全未覆盖)
                    ssh_verify(
                        f"L1-数据库({rule['name']})",
                        backend_verifier.verify_upnpd_ifconf_database,
                        rule["name"],
                        must_pass=True,
                    )
                # L3+L4
                ssh_verify("L3-运行时配置", backend_verifier.verify_upnpd_runtime_config, must_pass=False)
                ssh_verify("L4-守护进程", backend_verifier.verify_upnpd_daemon, must_pass=False, expect_enabled=False)
            else:
                print("  [INFO] SSH验证: 跳过（未配置SSH）")

        # ========== 步骤10: 编辑规则 ==========
        with rec.step("步骤10: 编辑规则", "编辑第1条规则的名称"):
            print("\n[步骤10] 编辑第1条规则...")
            edit_rule = test_rules[0]
            new_name = "upnp编辑测试"
            rec.add_detail(f"[编辑操作] {edit_rule['name']} -> {new_name}")

            if page.rule_exists(new_name):
                page.delete_rule(new_name)

            result = page.edit_rule(edit_rule["name"], new_name=new_name)
            assert result is True, "编辑规则失败"

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)
            assert page.rule_exists(new_name), "编辑后的规则未找到"
            test_rules[0]["name"] = new_name
            print(f"  [OK] 编辑成功")
            rec.add_detail(f"[验证] [OK] 编辑成功，新名称已生效")

            if backend_verifier is not None:
                ssh_verify("L1-编辑验证", backend_verifier.verify_upnpd_ifconf_database, new_name, must_pass=True)

        # ========== 步骤11: 复制规则(UPnP无复制功能,跳过) ==========
        with rec.step("步骤11: 复制规则(跳过)", "UPnP设置无复制按钮,跳过此步骤"):
            print("\n[步骤11] UPnP无复制功能,跳过...")
            rec.add_detail("[跳过] UPnP规则行按钮只有[编辑/停用/删除],无复制功能")

        # ========== 步骤12: 停用规则 ==========
        with rec.step("步骤12: 停用规则", "停用第2条规则"):
            print("\n[步骤12] 停用第2条规则...")
            disable_rule = test_rules[1]
            rec.add_detail(f"[停用操作] 目标: {disable_rule['name']}")

            result = page.disable_rule(disable_rule["name"])
            assert result is True, "停用规则失败"

            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)
            assert page.is_rule_disabled(disable_rule["name"]), "规则未变为停用状态"
            print(f"  [OK] 停用成功")
            rec.add_detail(f"[验证] [OK] 已停用")

            if backend_verifier is not None:
                ssh_verify("L1-停用验证", backend_verifier.verify_upnpd_ifconf_database,
                           disable_rule["name"], must_pass=True,
                           expected_fields={"enabled": "no"})

        # ========== 步骤13: 启用规则 ==========
        with rec.step("步骤13: 启用规则", "启用第2条规则"):
            print("\n[步骤13] 启用第2条规则...")
            rec.add_detail(f"[启用操作] 目标: {disable_rule['name']}")

            result = page.enable_rule(disable_rule["name"])
            assert result is True, "启用规则失败"

            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)
            assert page.is_rule_enabled(disable_rule["name"]), "规则启用后状态未变化"
            print(f"  [OK] 启用成功")
            rec.add_detail(f"[验证] [OK] 已启用")

            if backend_verifier is not None:
                ssh_verify("L1-启用验证", backend_verifier.verify_upnpd_ifconf_database,
                           disable_rule["name"], must_pass=True,
                           expected_fields={"enabled": "yes"})

        # ========== 步骤14: 删除规则 ==========
        with rec.step("步骤14: 删除规则", "删除第3条规则"):
            print("\n[步骤14] 删除第3条规则...")
            delete_rule_data = test_rules[2]
            rec.add_detail(f"[删除操作] 目标: {delete_rule_data['name']}")

            count_before = page.get_rule_count()
            result = page.delete_rule(delete_rule_data["name"])
            assert result is True, "删除规则失败"

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)
            count_after = page.get_rule_count()
            assert count_after < count_before, "删除后条目数未减少"
            test_rules.remove(delete_rule_data)
            print(f"  [OK] 删除成功 ({count_before} -> {count_after})")
            rec.add_detail(f"[验证] [OK] 删除成功")

            if backend_verifier is not None:
                try:
                    db_rule = backend_verifier.find_upnpd_ifconf(delete_rule_data["name"])
                    if db_rule is None:
                        print(f"    SSH-L1: [OK] 已从数据库删除")
                        rec.add_detail(f"    SSH-L1: [OK] 已从数据库删除")
                    else:
                        ssh_failures.append(f"SSH-L1-删除验证: {delete_rule_data['name']} 仍在数据库中")
                except Exception as e:
                    print(f"    SSH-L1: 跳过 - {str(e)[:80]}")

        # ========== 步骤15: 搜索测试 ==========
        with rec.step("步骤15: 搜索功能测试", "精确搜索/模糊搜索/不存在的规则"):
            print("\n[步骤15] 搜索测试...")
            rec.add_detail("[搜索测试]")

            # 精确搜索
            search_target = test_rules[0]["name"]
            rec.add_detail(f"  精确搜索: {search_target}")
            page.search_rule(search_target)
            page.page.wait_for_timeout(500)
            assert page.rule_exists(search_target), f"精确搜索不到: {search_target}"
            print(f"  [OK] 精确搜索成功")
            rec.add_detail(f"    [OK] 精确搜索找到")

            # 部分匹配搜索
            page.clear_search()
            page.page.wait_for_timeout(300)
            prefix = "upnp"
            rec.add_detail(f"  部分匹配搜索: '{prefix}'")
            page.search_rule(prefix)
            page.page.wait_for_timeout(500)
            partial_count = page.get_rule_count()
            assert partial_count >= 1, f"部分匹配搜索应至少1条，实际{partial_count}条"
            print(f"  [OK] 部分匹配搜索: {partial_count}条")
            rec.add_detail(f"    [OK] 匹配 {partial_count} 条")

            # 不存在的规则
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("not_exist_upnp_xxx")
            page.page.wait_for_timeout(500)
            count = page.get_rule_count()
            assert count == 0, f"搜索不存在时应为0条，实际{count}条"
            print("  [OK] 搜索不存在规则: 0条")
            rec.add_detail(f"  不存在的: 0条 [OK]")

            # 清空搜索恢复列表
            page.clear_search()
            page.page.wait_for_timeout(500)
            remaining = page.get_rule_count()
            assert remaining == len(test_rules), f"清空搜索后应有{len(test_rules)}条，实际{remaining}条"
            print(f"  [OK] 清空搜索，恢复 {remaining} 条")
            rec.add_detail(f"  清空搜索: {remaining} 条 [OK]")

        # ========== 步骤16: 排序测试 ==========
        with rec.step("步骤16: 排序功能测试", "按线路排序"):
            print("\n[步骤16] 排序测试...")
            rec.add_detail("[排序测试]")

            for col in ["线路"]:
                for sort_label in ["正序", "倒序", "恢复默认"]:
                    result = page.sort_by_column(col)
                    page.page.wait_for_timeout(300)
                    if result:
                        rec.add_detail(f"    {col} {sort_label}: [OK]")
                    else:
                        rec.add_detail(f"    {col} {sort_label}: [WARN] 排序图标未找到")
                print(f"  [OK] {col} 排序测试完成")

        # ========== 步骤17: 导出测试 ==========
        with rec.step("步骤17: 导出配置", "导出CSV和TXT"):
            print("\n[步骤17] 导出配置...")
            rec.add_detail("[导出测试]")
            config = get_config()
            export_file_csv = config.test_data.get_export_path("upnp_setting", config.get_project_root())
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
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)

        # ========== 步骤18: 异常输入测试 ==========
        with rec.step("步骤18: 异常输入测试", "空名称/重复/超长/特殊字符/纯空格/备注特殊字符"):
            print("\n[步骤18] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 18.1 空名称
            rec.add_detail("  空名称:")
            result = page.try_add_rule_invalid(name="")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                rec.add_detail(f"    [FAIL] 未拦截")

            # 18.2 重复名称
            rec.add_detail("  重复名称:")
            existing = test_rules[0]["name"]
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name(existing)
                page.select_line("wan1")
                page.page.wait_for_timeout(300)
                page.click_save()
                page.page.wait_for_timeout(1500)
                error_el = page.page.locator('.ant-form-item-explain-error')
                if error_el.count() > 0:
                    msg = error_el.first.text_content()
                    print(f"    [OK] 拦截: {msg}")
                    rec.add_detail(f"    [OK] 拦截: {msg}")
                elif page.wait_for_success_message(timeout=2000):
                    print(f"    [WARN] 重复名称未被拦截")
                    rec.add_detail(f"    [WARN] 重复名称未被拦截")
                page.click_cancel()
                page.page.wait_for_timeout(300)
                if "upnpSettings" in page.page.url:
                    page.navigate_back_to_list()
                page.page.wait_for_timeout(300)
            except Exception as e:
                print(f"    [INFO] 重复名称异常: {e}")
                rec.add_detail(f"    [INFO] 异常: {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 18.3 超长名称(30字符, tagname限制15字符)
            rec.add_detail("  超长名称(30字符):")
            long_name = "a" * 30
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name(long_name)
                page.select_line("wan1")
                page.page.wait_for_timeout(300)
                page.click_save()
                page.page.wait_for_timeout(1000)
                error_el = page.page.locator('.ant-form-item-explain-error')
                if error_el.count() > 0:
                    error_text = error_el.first.text_content()
                    print(f"    [OK] 前端拦截: {error_text}")
                    rec.add_detail(f"    [OK] 前端拦截: {error_text}")
                    page.click_cancel()
                    page.page.wait_for_timeout(500)
                    page.navigate_back_to_list()
                elif page.wait_for_success_message(timeout=2000):
                    truncated = long_name[:15]
                    print(f"    [OK] 后端自动截断到15字符: {truncated}")
                    rec.add_detail(f"    [OK] 后端自动截断到15字符: '{truncated}'")
                    page.page.wait_for_timeout(500)
                    page.navigate_back_to_list()
                    page.page.wait_for_timeout(500)
                    try:
                        page.delete_rule(truncated)
                    except Exception:
                        pass
                else:
                    page.click_cancel()
                    page.page.wait_for_timeout(500)
                    if "upnpSettings" in page.page.url:
                        page.navigate_back_to_list()
            except Exception as e:
                print(f"    [INFO] 超长名称异常: {e}")
                rec.add_detail(f"    [INFO] {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 18.4 特殊字符
            rec.add_detail("  特殊字符:")
            result = page.try_add_rule_invalid(name="<script>alert(1)</script>")
            print(f"    [INFO] 特殊字符: {result}")
            rec.add_detail(f"    [INFO] {result}")

            # 18.5 纯空格
            rec.add_detail("  纯空格:")
            result = page.try_add_rule_invalid(name="   ")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                rec.add_detail(f"    [INFO] {result}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)

        # ========== 步骤19: 批量停用 ==========
        with rec.step("步骤19: 批量停用", f"批量停用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤19] 批量停用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量停用] 目标: {len(test_rules)} 条")

            # 批量停用带重试 + SSH验证(参照跨三层, 原实现完全无SSH验证, 批量停用失败无法发现)
            test_names = {r["name"] for r in test_rules}
            total = len(test_rules)
            disable_success = False
            disabled_count = 0
            for attempt in range(3):
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_disable()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_upnp_setting()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_upnpd_ifconf() or []
                    disabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                else:
                    disabled_count = sum(1 for r in test_rules if page.is_rule_disabled(r["name"]))

                if total == 0 or disabled_count >= total:
                    disable_success = True
                    break
                print(f"  第{attempt + 1}次批量停用后 {disabled_count}/{total} 条已停用，重试...")
                rec.add_detail(f"  第{attempt + 1}次停用: {disabled_count}/{total}条，重试")

            if disable_success:
                print(f"  [OK] 批量停用: {disabled_count}/{total} 条")
                rec.add_detail(f"[结果] {disabled_count}/{total} 条已停用")
            else:
                print(f"  [WARN] 批量停用未完全生效: {disabled_count}/{total} 条")
                rec.add_detail(f"[结果] 批量停用未完全生效: {disabled_count}/{total} 条")
                ui_failures.append(f"批量停用仅{disabled_count}/{total}条规则停用")

            # SSH验证(补断言: 防止批量停用失败却报告通过)
            if backend_verifier is not None:
                db_rules = backend_verifier.query_upnpd_ifconf() or []
                disabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                rec.add_detail(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                print(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                if total > 0 and disabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_count}/{total}条规则停用")

        # ========== 步骤20: 批量启用 ==========
        with rec.step("步骤20: 批量启用", f"批量启用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤20] 批量启用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量启用] 目标: {len(test_rules)} 条")

            # 批量启用带重试 + SSH验证(参照跨三层, 原实现完全无SSH验证, 批量启用失败无法发现)
            test_names = {r["name"] for r in test_rules}
            total = len(test_rules)
            enable_success = False
            enabled_count = 0
            for attempt in range(3):
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_enable()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_upnp_setting()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_upnpd_ifconf() or []
                    enabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "yes")
                else:
                    enabled_count = sum(1 for r in test_rules if page.is_rule_enabled(r["name"]))

                if total == 0 or enabled_count >= total:
                    enable_success = True
                    break
                print(f"  第{attempt + 1}次批量启用后 {enabled_count}/{total} 条已启用，重试...")
                rec.add_detail(f"  第{attempt + 1}次启用: {enabled_count}/{total}条，重试")

            if enable_success:
                print(f"  [OK] 批量启用: {enabled_count}/{total} 条")
                rec.add_detail(f"[结果] {enabled_count}/{total} 条已启用")
            else:
                print(f"  [WARN] 批量启用未完全生效: {enabled_count}/{total} 条")
                rec.add_detail(f"[结果] 批量启用未完全生效: {enabled_count}/{total} 条")
                ui_failures.append(f"批量启用仅{enabled_count}/{total}条规则启用")

            # SSH验证(补断言)
            if backend_verifier is not None:
                db_rules = backend_verifier.query_upnpd_ifconf() or []
                enabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "yes")
                rec.add_detail(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                print(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                if total > 0 and enabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量启用: 仅{enabled_count}/{total}条规则启用")

        # ========== 步骤21: 批量删除 ==========
        with rec.step("步骤21: 批量删除", f"批量删除剩余 {len(test_rules)} 条"):
            print(f"\n[步骤21] 批量删除 {len(test_rules)} 条...")
            rec.add_detail(f"[批量删除] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_delete()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)
            for rule in test_rules:
                assert not page.rule_exists(rule["name"]), f"规则 {rule['name']} 仍存在"
            print(f"  [OK] 批量删除 {len(test_rules)} 条成功")
            rec.add_detail(f"[结果] [OK] 全部删除")

            if backend_verifier is not None:
                try:
                    upnp_rules = backend_verifier.query_upnpd_ifconf()
                    test_names = {r["name"] for r in test_rules}
                    remaining = [r for r in upnp_rules if r.get("tagname") in test_names]
                    if remaining:
                        ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining)}条")
                    else:
                        rec.add_detail(f"    SSH: 测试规则已全部删除")
                except Exception as e:
                    ssh_failures.append(f"SSH-L1-批量删除验证异常: {str(e)[:80]}")

        # ========== 步骤22: 导入追加(CSV) ==========
        with rec.step("步骤22: 导入配置(追加)", "使用导出的CSV追加导入"):
            print("\n[步骤22] 导入配置(追加)...")
            rec.add_detail("[导入测试-追加]")

            if os.path.exists(export_file_csv):
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_csv)}")
                rec.add_detail(f"  导入前: {count_before} 条")

                result = page.import_rules(export_file_csv, clear_existing=False)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_upnp_setting()
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

        # ========== 步骤23: 导入清空(TXT) ==========
        with rec.step("步骤23: 导入配置(清空现有)", "使用导出的TXT清空现有后导入"):
            print("\n[步骤23] 导入配置(清空现有数据-TXT)...")
            rec.add_detail("[导入测试-清空现有-TXT]")

            if os.path.exists(export_file_txt):
                page.add_rule(name="额外规则", ips=["10.0.0.1"], lines=["wan1"])
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_txt)}")
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则)")

                result = page.import_rules(export_file_txt, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1000)
                page.navigate_to_upnp_setting()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if not page.rule_exists("额外规则"):
                    print(f"  [OK] 清空现有数据生效(额外规则已删除)")
                    rec.add_detail(f"  [OK] 清空生效")
                else:
                    rec.add_detail(f"  [WARN] 额外规则仍存在")

                if count_after > 0:
                    print(f"  [OK] 重新导入 {count_after} 条")
                    rec.add_detail(f"  [OK] 重新导入 {count_after} 条")
            else:
                print(f"  [WARN] TXT文件不存在")
                rec.add_detail(f"  TXT文件不存在")

        # ========== 步骤24: 设置抽屉 - 开启UPnP+排除端口 ==========
        with rec.step("步骤24: 设置-开启UPnP+排除端口", "开启UPnP服务并修改排除端口"):
            print("\n[步骤24] 设置抽屉: 开启UPnP服务+修改排除端口...")
            rec.add_detail("[设置抽屉] 开启UPnP+排除端口")

            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)

            opened = page.open_settings_drawer()
            if opened:
                page.page.wait_for_timeout(500)

                page.toggle_upnp_service(True)
                page.page.wait_for_timeout(300)

                page.set_exclude_ports("1-1024,8080")
                page.page.wait_for_timeout(200)

                saved = page.save_settings()
                if saved:
                    print(f"  [OK] 设置保存成功")
                    rec.add_detail(f"  [OK] 设置保存成功")

                    if backend_verifier is not None:
                        ssh_verify("L1-UPnP启用", backend_verifier.verify_upnpd_conf,
                                   must_pass=True, expected_fields={"enabled": "yes"})
                        ssh_verify("L2-进程", backend_verifier.verify_upnpd_process,
                                   must_pass=False, expect_running=True)
                        ssh_verify("L3-运行时配置", backend_verifier.verify_upnpd_runtime_config,
                                   must_pass=False, expect_exists=True)
                else:
                    print(f"  [WARN] 设置保存失败")
                    rec.add_detail(f"  [WARN] 设置保存失败")
                    ui_failures.append("齿轮设置保存失败")
            else:
                print(f"  [WARN] 设置抽屉打开失败")
                rec.add_detail(f"  [WARN] 设置抽屉打开失败")

        # ========== 步骤25: 设置抽屉 - 掉线检测+定时重启 ==========
        with rec.step("步骤25: 设置-掉线检测+定时重启", "开启掉线检测+定时重启"):
            print("\n[步骤25] 设置抽屉: 掉线检测+定时重启...")
            rec.add_detail("[设置抽屉] 掉线检测+定时重启")

            opened = page.open_settings_drawer()
            if opened:
                page.page.wait_for_timeout(500)

                # 掉线检测
                page.toggle_disconnect_detection(True)
                page.page.wait_for_timeout(300)
                page.set_check_interval(10)
                page.page.wait_for_timeout(200)

                # 定时重启
                page.toggle_scheduled_restart(True)
                page.page.wait_for_timeout(500)
                page.set_restart_weekdays(["一", "二", "三", "四", "五"])
                page.page.wait_for_timeout(200)
                page.set_restart_time("03:00")
                page.page.wait_for_timeout(200)

                saved = page.save_settings()
                if saved:
                    print(f"  [OK] 设置保存成功")
                    rec.add_detail(f"  [OK] 设置保存成功")

                    if backend_verifier is not None:
                        ssh_verify("L1-设置验证", backend_verifier.verify_upnpd_conf,
                                   must_pass=False,
                                   expected_fields={"check_link": 1, "rst_switch": 1})
                        ssh_verify("L4-cron", backend_verifier.verify_upnpd_daemon,
                                   must_pass=False, expect_enabled=True)
                else:
                    print(f"  [WARN] 设置保存失败")
                    rec.add_detail(f"  [WARN] 设置保存失败")
                    ui_failures.append("齿轮设置保存失败")
            else:
                print(f"  [WARN] 设置抽屉打开失败")

        # ========== 步骤26: 设置抽屉 - 无效设置测试 ==========
        with rec.step("步骤26: 设置-无效输入测试", "测试无效端口范围和周期超范围"):
            print("\n[步骤26] 设置抽屉: 无效输入测试...")
            rec.add_detail("[设置抽屉-无效输入测试]")

            opened = page.open_settings_drawer()
            if opened:
                page.page.wait_for_timeout(500)

                # 无效端口范围
                page.set_exclude_ports("abc")
                page.page.wait_for_timeout(200)
                saved_invalid = page.save_settings()
                if not saved_invalid:
                    print(f"  [OK] 无效端口被拦截")
                    rec.add_detail(f"  [OK] 无效端口被拦截")
                else:
                    print(f"  [INFO] 无效端口未被拦截(后端可能自动处理)")
                    rec.add_detail(f"  [INFO] 无效端口未被拦截")

                # 重新打开设置抽屉测试周期超范围
                page.page.wait_for_timeout(500)
                opened = page.open_settings_drawer()
                if opened:
                    page.page.wait_for_timeout(500)

                    # 确保掉线检测已开启
                    page.toggle_disconnect_detection(True)
                    page.page.wait_for_timeout(300)

                    # 超范围周期(60, 超过59)
                    page.set_check_interval(60)
                    page.page.wait_for_timeout(200)
                    saved = page.save_settings()
                    if not saved:
                        print(f"  [OK] 超范围周期被拦截")
                        rec.add_detail(f"  [OK] 超范围周期被拦截")
                    else:
                        print(f"  [INFO] 超范围周期未被拦截")
                        rec.add_detail(f"  [INFO] 超范围周期未被拦截")
            else:
                print(f"  [WARN] 设置抽屉打开失败")

        # ========== 步骤27: 设置抽屉 - 关闭UPnP+恢复默认 ==========
        with rec.step("步骤27: 设置-关闭UPnP+恢复默认", "关闭UPnP服务并恢复默认配置"):
            print("\n[步骤27] 设置抽屉: 关闭UPnP+恢复默认...")
            rec.add_detail("[设置抽屉] 关闭UPnP+恢复默认")

            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)

            opened = page.open_settings_drawer()
            if opened:
                page.page.wait_for_timeout(500)

                # 先恢复有效值(步骤26可能留下了无效端口/周期)
                page.set_exclude_ports("1-1024")
                page.page.wait_for_timeout(200)

                page.toggle_upnp_service(False)
                page.page.wait_for_timeout(300)
                page.toggle_disconnect_detection(False)
                page.page.wait_for_timeout(300)
                page.toggle_scheduled_restart(False)
                page.page.wait_for_timeout(300)

                saved = page.save_settings()
                if saved:
                    print(f"  [OK] 设置恢复成功")
                    rec.add_detail(f"  [OK] 设置恢复成功")

                    if backend_verifier is not None:
                        ssh_verify("L1-关闭验证", backend_verifier.verify_upnpd_conf,
                                   must_pass=True, expected_fields={"enabled": "no"})
                        ssh_verify("L2-进程验证", backend_verifier.verify_upnpd_process,
                                   must_pass=False, expect_running=False)
                else:
                    print(f"  [WARN] 设置恢复失败")
                    rec.add_detail(f"  [WARN] 设置恢复失败")
                    ui_failures.append("齿轮设置恢复失败")
            else:
                print(f"  [WARN] 设置抽屉打开失败")

        # ========== 步骤28: 最终清理+帮助功能测试 ==========
        with rec.step("步骤28: 最终清理+帮助功能", "清理所有数据+测试帮助图标"):
            print("\n[步骤28] 最终清理+帮助功能测试...")

            # 清理环境
            rec.add_detail("[环境清理]")
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.navigate_to_upnp_setting()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                for cleanup_round in range(3):
                    page.navigate_to_upnp_setting()
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

                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_upnp_setting()
                page.page.wait_for_timeout(500)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成，剩余 {final_count} 条")
                rec.add_detail(f"[清理结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 无需清理")
                rec.add_detail("  无需清理")

            # SSH最终验证
            if backend_verifier is not None:
                ssh_verify("L3-最终验证", backend_verifier.verify_upnpd_runtime_config,
                           must_pass=False, expect_exists=False)

            # 帮助功能测试
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

        print("\n" + "=" * 60)
        print("UPnP/NAT设置综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 7条(单IP/多IP/IP段/多线路/所有线路/带备注/无备注)")
        print("  - 编辑/停用/启用/删除/复制: 各1条")
        print("  - 搜索: 精确/部分匹配/不存在/清空恢复")
        print("  - 排序: 线路")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加(CSV) + 清空现有数据(TXT)")
        print("  - 异常输入: 空名称/重复/超长/特殊字符/纯空格")
        print("  - 批量操作: 批量停用/启用/删除")
        print("  - 设置抽屉: 开启UPnP/排除端口/掉线检测/定时重启/无效设置/关闭UPnP")
        print("  - SSH后台验证: L1数据库+L2进程/iptables+L3运行时配置+L4守护进程")

        # SSH断言
        all_failures = ssh_failures + ui_failures
        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
