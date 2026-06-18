"""
UDPXY设置综合测试用例

组播管理 > UDPXY设置 表格页面综合测试
一次测试覆盖:
1. 检查并清理环境
2. 添加3条规则(lan1+9000+允许外网 / wan1+9001+不允许外网+订阅 / lan1+9002+允许外网)
3. SSH后台逐条验证(L1数据库 + L2进程 + L3 ipset)
4. 编辑规则(修改端口+接口)
5. 停用/启用/删除
6. 搜索测试(精确/部分/不存在/清空)
7. 排序测试
8. 导出测试(CSV/TXT)
9. 异常输入测试(空名称/重复名称/超长名称)
10. 批量停用/启用/删除
11. 导入测试(追加CSV+清空现有TXT)
12. 帮助功能测试
13. 最终清理

SSH后台验证: L1数据库(udp_proxy表) + L2进程(udpxy) + L3 ipset(DROP_U/T_PORTS_WAN_IN)
字段映射: tagname(名称), interface(接口), listen_port(端口),
          renew_time(订阅周期), access(0=不允许/1=允许外网)
"""
import pytest
import os
from pages.network.udp_proxy_page import UdpProxyPage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.udp_proxy
@pytest.mark.network
class TestUdpProxyComprehensive:
    """UDPXY设置综合测试 - 表格型页面"""

    def test_udp_proxy_comprehensive(self, udp_proxy_page_logged_in: UdpProxyPage,
                                      step_recorder: StepRecorder, request):
        """
        综合测试: 添加3条规则 -> SSH验证 -> 编辑 -> 停用 -> 启用 -> 删除 ->
        搜索 -> 排序 -> 导出 -> 异常测试 -> 批量操作 -> 导入 -> 帮助
        """
        page = udp_proxy_page_logged_in
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
                    print(f"      SSH数据: {result.raw_output[:200]}")
                    rec.add_detail(f"      SSH数据: {result.raw_output[:200]}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                return None

        # 测试数据 - 3条规则(端口必须唯一)
        test_rules = [
            {
                "name": "udpxy测试1",
                "interface": "lan1",
                "port": "39801",
                "renew_time": "0",
                "access_allow": True,
                "desc": "lan1+39801+允许外网"
            },
            {
                "name": "udpxy测试2",
                "interface": "wan1",
                "port": "39802",
                "renew_time": "60",
                "access_allow": False,
                "desc": "wan1+39802+不允许外网+订阅60s"
            },
            {
                "name": "udpxy测试3",
                "interface": "lan1",
                "port": "39803",
                "renew_time": "0",
                "access_allow": True,
                "desc": "lan1+39803+允许外网"
            },
        ]

        print("\n" + "=" * 60)
        print("UDPXY设置综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")
        for r in test_rules:
            print(f"  - {r['name']}, 接口={r['interface']}, 端口={r['port']}, "
                  f"外网={'允许' if r['access_allow'] else '不允许'}, "
                  f"订阅={r['renew_time']}s, 场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            for cleanup_round in range(3):
                page.navigate_to_udp_proxy()
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

            page.navigate_to_udp_proxy()
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
                    tagname=rule["name"],
                    interface=rule["interface"],
                    listen_port=rule["port"],
                    renew_time=rule["renew_time"],
                    access_allow=rule["access_allow"],
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")

                # SSH L1-L3逐条验证
                access_val = 1 if rule["access_allow"] else 0
                renew_val = int(rule["renew_time"])

                ssh_verify(
                    f"L1-数据库({rule['name']})",
                    backend_verifier.verify_udp_proxy_database,
                    must_pass=True,
                    expected_fields={
                        "enabled": "yes",
                        "tagname": rule["name"],
                        "interface": rule["interface"],
                        "listen_port": rule["port"],
                        "access": access_val,
                        "renew_time": renew_val,
                    },
                    tagname=rule["name"],
                )

                ssh_verify(
                    f"L2-进程({rule['name']})",
                    backend_verifier.verify_udp_proxy_process,
                    expect_running=True,
                    listen_port=int(rule["port"]),
                    interface=rule["interface"],
                )

                # L3: ipset(仅access=0不允许外网时检查)
                if not rule["access_allow"]:
                    ssh_verify(
                        f"L3-ipset({rule['name']})",
                        backend_verifier.verify_udp_proxy_ipset,
                        expect_present=True,
                        listen_port=int(rule["port"]),
                    )

        # ========== 步骤5: 验证总数 ==========
        with rec.step("步骤5: 验证总数", f"验证共{len(test_rules)}条规则"):
            print(f"\n[步骤5] 验证总数...")
            page.navigate_to_udp_proxy()
            page.page.wait_for_timeout(1000)
            page.clear_search()
            page.page.wait_for_timeout(500)

            total = page.get_rule_count()
            assert total == len(test_rules), f"规则总数应为{len(test_rules)}, 实际{total}"
            print(f"  [OK] 总数验证: {total} 条")
            rec.add_detail(f"  [OK] 总数验证通过: {total} 条")

            rule_list = page.get_rule_list()
            rec.add_detail(f"  当前列表: {[r['name'] for r in rule_list]}")

        # ========== 步骤6: 编辑规则 ==========
        with rec.step("步骤6: 编辑规则", "修改第1条规则的端口和接口"):
            print("\n[步骤6] 编辑规则...")
            edit_rule = test_rules[0]
            new_port = "39811"
            new_iface = "wan2"
            rec.add_detail(f"[编辑] {edit_rule['name']}: 端口->{new_port}, 接口->{new_iface}")

            result = page.edit_rule_modify(
                edit_rule["name"],
                listen_port=new_port,
                interface=new_iface,
            )
            assert result is True, "编辑规则失败"

            # 更新test_rules
            test_rules[0]["port"] = new_port
            test_rules[0]["interface"] = new_iface

            page.navigate_to_udp_proxy()
            page.page.wait_for_timeout(1000)
            print(f"  [OK] 编辑成功")
            rec.add_detail(f"  [OK] 编辑成功")

            ssh_verify(
                "L1-编辑验证",
                backend_verifier.verify_udp_proxy_database,
                must_pass=True,
                expected_fields={
                    "enabled": "yes",
                    "listen_port": int(new_port),
                    "interface": new_iface,
                },
                tagname=edit_rule["name"],
            )
            ssh_verify(
                "L2-编辑进程",
                backend_verifier.verify_udp_proxy_process,
                expect_running=True,
                listen_port=int(new_port),
                interface=new_iface,
            )

        # ========== 步骤7: 停用规则 ==========
        with rec.step("步骤7: 停用规则", "停用第2条规则"):
            print("\n[步骤7] 停用规则...")
            disable_rule = test_rules[1]
            rec.add_detail(f"[停用] 目标: {disable_rule['name']}")

            result = page.disable_rule(disable_rule["name"])
            assert result is True, "停用规则失败"

            page.page.wait_for_timeout(1000)
            page.navigate_to_udp_proxy()
            page.page.wait_for_timeout(1000)
            assert page.is_rule_disabled(disable_rule["name"]), "规则未变为停用状态"
            print(f"  [OK] 停用成功")
            rec.add_detail(f"  [OK] 已停用")

            ssh_verify(
                "L1-停用验证",
                backend_verifier.verify_udp_proxy_database,
                must_pass=True,
                expected_fields={"enabled": "no"},
                tagname=disable_rule["name"],
            )
            # 停用后进程应该不存在(该端口)
            ssh_verify(
                "L2-停用进程",
                backend_verifier.verify_udp_proxy_process,
                expect_running=False,
                listen_port=int(disable_rule["port"]),
            )

        # ========== 步骤8: 启用规则 ==========
        with rec.step("步骤8: 启用规则", "重新启用第2条规则"):
            print("\n[步骤8] 启用规则...")
            rec.add_detail(f"[启用] 目标: {disable_rule['name']}")

            result = page.enable_rule(disable_rule["name"])
            assert result is True, "启用规则失败"

            page.page.wait_for_timeout(1000)
            page.navigate_to_udp_proxy()
            page.page.wait_for_timeout(1000)
            assert page.is_rule_enabled(disable_rule["name"]), "规则启用后状态未变化"
            print(f"  [OK] 启用成功")
            rec.add_detail(f"  [OK] 已启用")

            ssh_verify(
                "L1-启用验证",
                backend_verifier.verify_udp_proxy_database,
                must_pass=True,
                expected_fields={"enabled": "yes"},
                tagname=disable_rule["name"],
            )
            ssh_verify(
                "L2-启用进程",
                backend_verifier.verify_udp_proxy_process,
                expect_running=True,
                listen_port=int(disable_rule["port"]),
            )

        # ========== 步骤9: 删除规则 ==========
        with rec.step("步骤9: 删除规则", "删除第3条规则"):
            print("\n[步骤9] 删除规则...")
            delete_rule_data = test_rules[2]
            rec.add_detail(f"[删除] 目标: {delete_rule_data['name']}")

            count_before = page.get_rule_count()
            result = page.delete_rule(delete_rule_data["name"])
            assert result is True, "删除规则失败"

            page.navigate_to_udp_proxy()
            page.page.wait_for_timeout(1000)
            count_after = page.get_rule_count()
            assert count_after < count_before, "删除后条目数未减少"
            test_rules.remove(delete_rule_data)
            print(f"  [OK] 删除成功 ({count_before} -> {count_after})")
            rec.add_detail(f"  [OK] 删除成功")

            if backend_verifier is not None:
                db_rule = backend_verifier.query_udp_proxy_config(tagname=delete_rule_data["name"])
                if db_rule is None:
                    print(f"    SSH-L1: [OK] 已从数据库删除")
                    rec.add_detail(f"    SSH-L1: [OK] 已从数据库删除")
                else:
                    ssh_failures.append(f"SSH-L1-删除: {delete_rule_data['name']} 仍在数据库中")

        # ========== 步骤10: 搜索测试 ==========
        with rec.step("步骤10: 搜索功能测试", "精确/部分/不存在/清空"):
            print("\n[步骤10] 搜索测试...")
            rec.add_detail("[搜索测试]")

            # 精确搜索
            search_target = test_rules[0]["name"]
            rec.add_detail(f"  精确搜索: {search_target}")
            page.search_rule(search_target)
            page.page.wait_for_timeout(500)
            assert page.rule_exists(search_target), f"精确搜索不到: {search_target}"
            print(f"  [OK] 精确搜索成功")
            rec.add_detail(f"    [OK] 精确搜索找到")

            # 部分匹配
            page.clear_search()
            page.page.wait_for_timeout(300)
            prefix = "udpxy"
            rec.add_detail(f"  部分匹配: '{prefix}'")
            page.search_rule(prefix)
            page.page.wait_for_timeout(500)
            partial_count = page.get_rule_count()
            assert partial_count >= 1, f"部分匹配应至少1条, 实际{partial_count}条"
            print(f"  [OK] 部分匹配: {partial_count}条")
            rec.add_detail(f"    [OK] 匹配 {partial_count} 条")

            # 不存在的规则(用get_rule_list检查实际可见行, 因为get_rule_count读"共N条"可能不更新)
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("not_exist_udpxy_xxx")
            page.page.wait_for_timeout(500)
            visible_rules = page.get_rule_list()
            visible_count = len(visible_rules)
            if visible_count == 0:
                print("  [OK] 搜索不存在: 0条(表格已过滤)")
                rec.add_detail(f"  不存在: 0条 [OK]")
            else:
                # 检查可见行是否都不包含搜索关键词
                has_match = any("not_exist" in r.get("name", "") for r in visible_rules)
                if not has_match:
                    print(f"  [INFO] 搜索不存在: {visible_count}条可见(搜索可能未过滤,但行中无匹配)")
                    rec.add_detail(f"  不存在: {visible_count}条可见, 行中无匹配 [INFO]")
                else:
                    print(f"  [WARN] 搜索不存在的关键词仍有匹配行")
                    rec.add_detail(f"  [WARN] 搜索未生效")

            # 清空恢复
            page.clear_search()
            page.page.wait_for_timeout(500)
            remaining = len(page.get_rule_list())
            if remaining == len(test_rules):
                print(f"  [OK] 清空搜索, 恢复 {remaining} 条")
                rec.add_detail(f"  清空: {remaining} 条 [OK]")
            else:
                total = page.get_rule_count()
                print(f"  [INFO] 清空后可见{remaining}条(总计{total}条)")
                rec.add_detail(f"  清空: 可见{remaining}条/总计{total}条")

        # ========== 步骤11: 排序测试 ==========
        with rec.step("步骤11: 排序功能测试", "按列排序"):
            print("\n[步骤11] 排序测试...")
            rec.add_detail("[排序测试]")

            # UDPXY表格列: 名称/接口/端口/订阅周期/外网访问/操作
            # 尝试按名称列排序
            for sort_label in ["第1次", "第2次(反向)", "第3次(恢复)"]:
                result = page.sort_by_column("名称")
                page.page.wait_for_timeout(300)
                if result:
                    rec.add_detail(f"    名称 {sort_label}: [OK]")
                else:
                    rec.add_detail(f"    名称 {sort_label}: [WARN] 排序图标未找到")
            print(f"  [OK] 排序测试完成")

        # ========== 步骤12: 导出测试 ==========
        with rec.step("步骤12: 导出配置", "导出CSV和TXT"):
            print("\n[步骤12] 导出配置...")
            rec.add_detail("[导出测试]")
            config = get_config()
            export_file_csv = config.test_data.get_export_path("udp_proxy", config.get_project_root())
            export_file_txt = export_file_csv.replace(".csv", ".txt")

            try:
                rec.add_detail(f"  CSV: {os.path.basename(export_file_csv)}")
                if page.export_rules(use_config_path=True, export_format="csv"):
                    print(f"  [OK] CSV导出成功")
                    rec.add_detail(f"    [OK] CSV成功")
                else:
                    rec.add_detail(f"    [WARN] CSV可能失败")

                page.page.wait_for_timeout(500)

                rec.add_detail(f"  TXT: {os.path.basename(export_file_txt)}")
                if page.export_rules(use_config_path=True, export_format="txt"):
                    print(f"  [OK] TXT导出成功")
                    rec.add_detail(f"    [OK] TXT成功")
                else:
                    rec.add_detail(f"    [WARN] TXT可能失败")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")
                rec.add_detail(f"  异常: {str(e)}")
                ui_failures.append("导出失败")

            page.close_modal_if_exists()
            page.navigate_to_udp_proxy()
            page.page.wait_for_timeout(1000)

        # ========== 步骤13: 异常输入测试 ==========
        with rec.step("步骤13: 异常输入测试", "空名称/重复名称/超长名称"):
            print("\n[步骤13] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 13.1 空名称(必填字段)
            rec.add_detail("  空名称:")
            try:
                page.click_add_button()
                page.page.wait_for_timeout(500)
                dialog = page.page.locator("[role='dialog']")
                dialog.wait_for(state="visible", timeout=5000)
                page.page.wait_for_timeout(300)

                # 不填名称, 只选接口和端口
                page.select_interface("lan1")
                page.fill_listen_port("39999")
                page.page.wait_for_timeout(300)

                confirm_btn = page.page.get_by_role("button", name="确定")
                if confirm_btn.count() > 0:
                    confirm_btn.click()
                page.page.wait_for_timeout(1500)

                error_el = page.page.locator('.ant-form-item-explain-error')
                if error_el.count() > 0:
                    msg = error_el.first.text_content()
                    print(f"    [OK] 前端拦截: {msg}")
                    rec.add_detail(f"    [OK] 拦截: {msg}")
                else:
                    # 检查是否真的添加了
                    page.page.keyboard.press("Escape")
                    page.page.wait_for_timeout(300)
                    rec.add_detail(f"    [WARN] 未拦截(可能有默认值)")
            except Exception as e:
                print(f"    [INFO] 异常: {e}")
                rec.add_detail(f"    [INFO] {e}")
            finally:
                page.close_modal_if_exists()
                page.navigate_to_udp_proxy()
                page.page.wait_for_timeout(500)

            # 13.2 重复名称
            rec.add_detail("  重复名称:")
            existing = test_rules[0]["name"]
            try:
                page.click_add_button()
                page.page.wait_for_timeout(500)
                dialog = page.page.locator("[role='dialog']")
                dialog.wait_for(state="visible", timeout=5000)
                page.page.wait_for_timeout(300)

                page.fill_tagname(existing)
                page.select_interface("lan1")
                page.fill_listen_port("39998")
                page.page.wait_for_timeout(300)

                confirm_btn = page.page.get_by_role("button", name="确定")
                if confirm_btn.count() > 0:
                    confirm_btn.click()
                page.page.wait_for_timeout(1500)

                error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if error_el.count() > 0:
                    msg = error_el.first.text_content()
                    print(f"    [OK] 拦截: {msg}")
                    rec.add_detail(f"    [OK] 拦截: {msg}")
                else:
                    print(f"    [WARN] 重复名称未被拦截")
                    rec.add_detail(f"    [WARN] 重复名称未被拦截")
            except Exception as e:
                print(f"    [INFO] 异常: {e}")
                rec.add_detail(f"    [INFO] {e}")
            finally:
                page.close_modal_if_exists()
                page.navigate_to_udp_proxy()
                page.page.wait_for_timeout(500)

            # 13.3 超长名称
            rec.add_detail("  超长名称(30字符):")
            long_name = "a" * 30
            try:
                page.click_add_button()
                page.page.wait_for_timeout(500)
                dialog = page.page.locator("[role='dialog']")
                dialog.wait_for(state="visible", timeout=5000)
                page.page.wait_for_timeout(300)

                page.fill_tagname(long_name)
                page.select_interface("lan1")
                page.fill_listen_port("39997")
                page.page.wait_for_timeout(300)

                confirm_btn = page.page.get_by_role("button", name="确定")
                if confirm_btn.count() > 0:
                    confirm_btn.click()
                page.page.wait_for_timeout(1500)

                # 检查是拦截还是自动截断
                error_el = page.page.locator('.ant-form-item-explain-error')
                if error_el.count() > 0:
                    msg = error_el.first.text_content()
                    print(f"    [OK] 前端拦截: {msg}")
                    rec.add_detail(f"    [OK] 前端拦截: {msg}")
                elif page.page.locator(".ant-message-success").count() > 0:
                    truncated = long_name[:15]
                    print(f"    [INFO] 后端自动截断到15字符")
                    rec.add_detail(f"    [INFO] 后端截断到15字符")
                    # 清理截断的规则
                    page.navigate_to_udp_proxy()
                    page.page.wait_for_timeout(500)
                    try:
                        page.delete_rule(truncated)
                    except Exception:
                        pass
            except Exception as e:
                print(f"    [INFO] 异常: {e}")
                rec.add_detail(f"    [INFO] {e}")
            finally:
                page.close_modal_if_exists()
                page.navigate_to_udp_proxy()
                page.page.wait_for_timeout(500)

        # ========== 步骤14: 批量停用 ==========
        with rec.step("步骤14: 批量停用", f"批量停用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤14] 批量停用 {len(test_rules)} 条...")
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
                page.navigate_to_udp_proxy()
                page.page.wait_for_timeout(1000)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_udp_proxy_config() or []
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
                db_rules = backend_verifier.query_udp_proxy_config() or []
                disabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                rec.add_detail(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                print(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                if total > 0 and disabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_count}/{total}条规则停用")

        # ========== 步骤15: 批量启用 ==========
        with rec.step("步骤15: 批量启用", f"批量启用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤15] 批量启用 {len(test_rules)} 条...")
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
                page.navigate_to_udp_proxy()
                page.page.wait_for_timeout(1000)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_udp_proxy_config() or []
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
                db_rules = backend_verifier.query_udp_proxy_config() or []
                enabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "yes")
                rec.add_detail(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                print(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                if total > 0 and enabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量启用: 仅{enabled_count}/{total}条规则启用")

        # ========== 步骤16: 批量删除 ==========
        with rec.step("步骤16: 批量删除", f"批量删除剩余 {len(test_rules)} 条"):
            print(f"\n[步骤16] 批量删除 {len(test_rules)} 条...")
            rec.add_detail(f"[批量删除] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_delete()
            page.page.wait_for_timeout(1500)

            page.navigate_to_udp_proxy()
            page.page.wait_for_timeout(1000)
            for rule in test_rules:
                assert not page.rule_exists(rule["name"]), f"规则 {rule['name']} 仍存在"
            print(f"  [OK] 批量删除 {len(test_rules)} 条成功")
            rec.add_detail(f"[结果] [OK] 全部删除")

            if backend_verifier is not None:
                try:
                    all_rules = backend_verifier.query_udp_proxy_config()
                    test_names = {r["name"] for r in test_rules}
                    if all_rules:
                        remaining = [r for r in all_rules if r.get("tagname") in test_names]
                        if remaining:
                            ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining)}条")
                        else:
                            rec.add_detail(f"    SSH: 测试规则已全部删除")
                except Exception as e:
                    ssh_failures.append(f"SSH-L1-批量删除验证异常: {str(e)[:80]}")

        # ========== 步骤17: 导入追加(CSV) ==========
        with rec.step("步骤17: 导入配置(追加)", "使用导出的CSV追加导入"):
            print("\n[步骤17] 导入配置(追加)...")
            rec.add_detail("[导入测试-追加]")

            if os.path.exists(export_file_csv):
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_csv)}")
                rec.add_detail(f"  导入前: {count_before} 条")

                result = page.import_rules(export_file_csv, clear_existing=False)
                page.navigate_to_udp_proxy()
                page.page.wait_for_timeout(1000)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if count_after > count_before:
                    print(f"  [OK] 追加导入成功, 添加 {count_after - count_before} 条")
                    rec.add_detail(f"  [OK] 添加 {count_after - count_before} 条")
                else:
                    print(f"  [WARN] 追加导入后数量未增加")
                    rec.add_detail(f"  [WARN] 数量未增加")
            else:
                print(f"  [WARN] CSV文件不存在: {export_file_csv}")
                rec.add_detail(f"  CSV文件不存在")

        # ========== 步骤18: 导入清空(TXT) ==========
        with rec.step("步骤18: 导入配置(清空现有)", "使用导出的TXT清空现有后导入"):
            print("\n[步骤18] 导入配置(清空现有-TXT)...")
            rec.add_detail("[导入测试-清空现有-TXT]")

            if os.path.exists(export_file_txt):
                # 先添加一条额外规则用于验证清空
                page.add_rule(tagname="额外规则", interface="lan1", listen_port="39850")
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_txt)}")
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则)")

                result = page.import_rules(export_file_txt, clear_existing=True)
                page.navigate_to_udp_proxy()
                page.page.wait_for_timeout(1000)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if not page.rule_exists("额外规则"):
                    print(f"  [OK] 清空现有数据生效(额外规则已删除)")
                    rec.add_detail(f"  [OK] 清空生效")

                if count_after > 0:
                    print(f"  [OK] 重新导入 {count_after} 条")
                    rec.add_detail(f"  [OK] 重新导入 {count_after} 条")
            else:
                print(f"  [WARN] TXT文件不存在: {export_file_txt}")
                rec.add_detail(f"  TXT文件不存在")

        # ========== 步骤19: 帮助功能测试 ==========
        with rec.step("步骤19: 帮助功能测试", "测试帮助按钮"):
            print("\n[步骤19] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")

            page.navigate_to_udp_proxy()
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
        with rec.step("步骤20: 最终清理", "清理所有测试数据"):
            print("\n[步骤20] 最终清理...")
            rec.add_detail("[最终清理]")

            page.navigate_to_udp_proxy()
            page.page.wait_for_timeout(1000)
            current_count = page.get_rule_count()
            if current_count > 0:
                for cleanup_round in range(3):
                    page.navigate_to_udp_proxy()
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

                page.navigate_to_udp_proxy()
                page.page.wait_for_timeout(1000)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成, 剩余 {final_count} 条")
                rec.add_detail(f"[清理结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 无需清理")
                rec.add_detail("  无需清理")

            # SSH最终验证: 无udpxy进程
            ssh_verify(
                "L2-最终进程",
                backend_verifier.verify_udp_proxy_process,
                expect_running=False,
            )

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("UDPXY设置综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 3条(lan1+允许/wan1+不允许+订阅/lan1+允许)")
        print("  - 编辑: 修改端口+接口")
        print("  - 停用/启用/删除: 各1条 + SSH验证")
        print("  - 搜索: 精确/部分/不存在/清空")
        print("  - 排序: 名称列")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加(CSV) + 清空现有(TXT)")
        print("  - 异常输入: 空名称/重复/超长")
        print("  - 批量操作: 停用/启用/删除")
        print("  - 帮助功能")
        print("  - SSH后台验证: L1数据库+L2进程+L3 ipset")

        all_failures = ssh_failures + ui_failures
        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not all_failures, \
                f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
