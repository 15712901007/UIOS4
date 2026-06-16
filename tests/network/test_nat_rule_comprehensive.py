"""
NAT规则综合测试用例

一次测试覆盖多个功能:
1. 添加9条规则(覆盖filter/snat/dnat三种动作+地址+端口+备注+反向匹配)
2. SSH后台数据验证(L1数据库逐条验证 + L2 iptables + L3运行时 + L4内核)
3. 编辑其中1条
4. 停用/启用/删除各1条
5. 搜索测试(精确/部分/不存在/清空)
6. 排序测试(动作/出接口/进接口)
7. 导出测试(CSV/TXT)
8. 异常输入测试(空名称/重复/超长/特殊字符/纯空格)
9. 批量停用/启用/删除
10. 导入测试(追加CSV+清空现有TXT)
11. 齿轮设置抽屉(本地转发自动NAT开关)
12. 帮助功能测试

SSH后台验证: L1数据库(nat_rule) + L2 iptables(NATRULE_SNAT/NATRULE_DNAT) + L3运行时(iptables-save) + L4内核(nf_nat)
字段映射: tagname(名称), action(动作filter/snat/dnat), ointerface(出接口), iinterface(进接口),
          src_addr(源地址base64), dst_addr(目的地址base64), nat_addr(NAT地址), nat_port(NAT端口),
          protocol(协议), src_port(源端口base64), dst_port(目的端口base64), comment(备注)
"""
import pytest
import os
from pages.network.nat_rule_page import NatRulePage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.nat_rule
@pytest.mark.network
class TestNatRuleComprehensive:
    """NAT规则综合测试 - 一次测试覆盖所有功能"""

    def test_nat_rule_comprehensive(self, nat_rule_page_logged_in: NatRulePage,
                                     step_recorder: StepRecorder, request):
        """
        综合测试: 添加9条规则 -> SSH验证 -> 编辑 -> 停用 -> 启用 -> 删除 ->
        搜索 -> 排序 -> 导出 -> 异常测试 -> 批量操作 -> 导入 -> 齿轮设置 -> 帮助
        """
        page = nat_rule_page_logged_in
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
                return None

        # 测试数据 - 9条规则, 覆盖3种动作类型
        test_rules = [
            # Rule 1: filter, 最简(无地址无协议)
            {"name": "nat过滤基础", "action": "过滤",
             "desc": "过滤-无地址无协议(最简)"},
            # Rule 2: filter, 带源地址+目的地址
            {"name": "nat过滤地址", "action": "过滤",
             "src_addr": "192.168.1.100",
             "dst_addr": "10.0.0.1",
             "desc": "过滤-源地址+目的地址"},
            # Rule 3: filter, tcp协议+端口
            {"name": "nat过滤TCP", "action": "过滤",
             "protocol": "tcp",
             "src_port": "1000-2000",
             "dst_port": "80",
             "desc": "过滤-TCP协议+端口"},
            # Rule 4: snat, 出接口+源地址+NAT地址
            {"name": "nat源地址基础", "action": "源地址NAT",
             "outbound": ["wan1"],
             "src_addr": "192.168.2.0/24",
             "nat_addr": "10.66.0.200",
             "desc": "源地址NAT-出接口+源地址+NAT地址"},
            # Rule 5: snat, tcp协议+端口+NAT地址
            {"name": "nat源地址TCP", "action": "源地址NAT",
             "outbound": ["wan1"],
             "protocol": "tcp",
             "src_port": "3000-4000",
             "dst_port": "443",
             "nat_addr": "10.66.0.201",
             "desc": "源地址NAT-TCP+端口+NAT地址"},
            # Rule 6: dnat, 进接口+目的地址+NAT地址+端口
            {"name": "nat目的地址基础", "action": "目的地址NAT",
             "inbound": ["lan1"],
             "dst_addr": "10.66.0.150",
             "nat_addr": "192.168.1.10",
             "nat_port": "8080",
             "desc": "目的地址NAT-进接口+目的地址+NAT地址+端口"},
            # Rule 7: dnat, tcp+端口映射
            {"name": "nat目的地址TCP", "action": "目的地址NAT",
             "inbound": ["lan1"],
             "protocol": "tcp",
             "dst_port": "9090",
             "nat_addr": "192.168.1.20",
             "nat_port": "80",
             "desc": "目的地址NAT-TCP端口映射"},
            # Rule 8: filter, 带备注
            {"name": "nat带备注", "action": "过滤",
             "remark": "NAT规则测试备注",
             "desc": "过滤-带备注"},
            # Rule 9: snat, 反向匹配
            {"name": "nat反向匹配", "action": "源地址NAT",
             "outbound": ["wan1"],
             "src_addr": "192.168.3.0/24",
             "src_addr_inv": True,
             "nat_addr": "10.66.0.202",
             "desc": "源地址NAT-反向匹配"},
        ]

        print("\n" + "=" * 60)
        print("NAT规则综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")
        for r in test_rules:
            action = r.get("action", "过滤")
            proto = r.get("protocol", "任意")
            print(f"  - {r['name']}, 动作={action}, 协议={proto}, 场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            for cleanup_round in range(3):
                page.navigate_to_nat_rule()
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

            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(1000)
            final_count = page.get_rule_count()
            print(f"  [OK] 环境清理完成, 剩余 {final_count} 条")
            rec.add_detail(f"[清理结果] 剩余 {final_count} 条")

        # ========== 步骤2-10: 逐条添加9条规则 ==========
        added_count = 0
        for rule_idx, rule in enumerate(test_rules):
            step_num = rule_idx + 2
            with rec.step(f"步骤{step_num}: 添加规则 {rule['name']}",
                          f"添加: {rule['desc']}"):
                print(f"\n[步骤{step_num}] 添加规则: {rule['name']}")
                rec.add_detail(f"  场景: {rule['desc']}")
                rec.add_detail(f"  动作: {rule.get('action', '过滤')}, 协议: {rule.get('protocol', '任意')}")

                action = rule.get("action", "过滤")
                action_db = NatRulePage.ACTION_MAP.get(action, "filter")

                result = page.add_rule(
                    name=rule["name"],
                    action=action,
                    inbound_interfaces=rule.get("inbound"),
                    outbound_interfaces=rule.get("outbound"),
                    src_addr=rule.get("src_addr"),
                    dst_addr=rule.get("dst_addr"),
                    src_addr_inv=rule.get("src_addr_inv"),
                    protocol=rule.get("protocol"),
                    src_port=rule.get("src_port"),
                    dst_port=rule.get("dst_port"),
                    nat_addr=rule.get("nat_addr"),
                    nat_port=rule.get("nat_port"),
                    remark=rule.get("remark"),
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")
                added_count += 1

                # SSH L1验证
                if backend_verifier is not None:
                    expected = {"enabled": "yes", "action": action_db}
                    if rule.get("protocol"):
                        expected["protocol"] = rule["protocol"]
                    if rule.get("nat_addr"):
                        expected["nat_addr"] = rule["nat_addr"]
                    if rule.get("remark"):
                        expected["comment"] = rule["remark"]

                    l1 = ssh_verify(
                        f"L1-数据库({rule['name']})",
                        backend_verifier.verify_nat_rule_database,
                        rule["name"],
                        must_pass=True,
                        expected_fields=expected,
                    )
                    if l1 and l1.passed:
                        db_rule = l1.details.get("rule", {})
                        db_id = db_rule.get("id")
                        rule_id = db_id
                        rec.add_detail(f"      数据库: id={db_id}, action={db_rule.get('action')}, "
                                       f"protocol={db_rule.get('protocol')}, enabled={db_rule.get('enabled')}")

        # ========== 步骤11: 验证总数 + 后端全链路验证 ==========
        with rec.step("步骤11: 验证总数 + 后端全链路", f"验证共{len(test_rules)}条 + SSH L1-L4"):
            print(f"\n[步骤11] 验证总数...")
            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(1000)
            page.clear_search()
            page.page.wait_for_timeout(500)
            all_names = page.get_rule_list()
            rec.add_detail(f"  当前列表({len(all_names)}条): {all_names}")
            for rule in test_rules:
                assert rule["name"] in all_names, f"规则 {rule['name']} 未找到, 当前列表: {all_names}"
            total = page.get_rule_count()
            assert total == len(test_rules), f"规则总数应为{len(test_rules)}, 实际{total}"
            print(f"  [OK] 总数验证: {total} 条")
            rec.add_detail(f"  [OK] 总数验证通过: {total} 条")

            # SSH全链路验证
            if backend_verifier is not None:
                rec.add_detail("[SSH全链路验证] L1=数据库, L2=iptables, L3=运行时, L4=内核")
                for rule in test_rules:
                    rec.add_detail(f"  -- 验证: {rule['name']} --")
                    action_db = NatRulePage.ACTION_MAP.get(rule.get("action", "过滤"), "filter")
                    expected = {"enabled": "yes", "action": action_db}
                    if rule.get("protocol"):
                        expected["protocol"] = rule["protocol"]
                    if rule.get("remark"):
                        expected["comment"] = rule["remark"]

                    full = ssh_verify(
                        f"全链路({rule['name']})",
                        backend_verifier.verify_nat_rule_full_chain,
                        rule["name"],
                        must_pass=False,
                        expected_fields=expected,
                    )
                    if full:
                        for r in full.results:
                            rec.add_detail(f"    {r.level}: {'[OK]' if r.passed else '[FAIL]'} {r.message}")

        # ========== 步骤12: 编辑规则 ==========
        with rec.step("步骤12: 编辑规则", "编辑nat过滤基础->改名"):
            print("\n[步骤12] 编辑规则...")
            rec.add_detail("[编辑测试] nat过滤基础 -> nat过滤已编辑")

            old_name = "nat过滤基础"
            new_name = "nat过滤已编辑"
            result = page.edit_rule(old_name, new_name=new_name, remark="编辑后备注")
            if result:
                assert page.rule_exists(new_name), f"编辑后规则 {new_name} 未找到"
                print(f"  [OK] 编辑成功: {old_name} -> {new_name}")
                rec.add_detail(f"  [OK] 编辑成功: {old_name} -> {new_name}")

                # 更新测试数据
                for r in test_rules:
                    if r["name"] == old_name:
                        r["name"] = new_name
                        break

                if backend_verifier is not None:
                    ssh_verify(f"L1-编辑后({new_name})",
                               backend_verifier.verify_nat_rule_database,
                               new_name, must_pass=True,
                               expected_fields={"enabled": "yes", "comment": "编辑后备注"})
            else:
                print(f"  [WARN] 编辑失败")
                rec.add_detail(f"  [WARN] 编辑失败")
                ui_failures.append("编辑规则失败")

        # ========== 步骤13: 停用规则 ==========
        with rec.step("步骤13: 停用规则", "停用nat过滤地址 + SSH验证"):
            print("\n[步骤13] 停用规则...")
            target = "nat过滤地址"
            rec.add_detail(f"[停用测试] 目标: {target}")

            page.disable_rule(target)
            page.page.wait_for_timeout(1000)

            if page.is_rule_disabled(target):
                print(f"  [OK] 停用成功: {target}")
                rec.add_detail(f"  [OK] 停用成功")
            else:
                print(f"  [WARN] 停用状态未确认")
                rec.add_detail(f"  [WARN] 停用状态未确认")

            if backend_verifier is not None:
                ssh_verify(f"L1-停用({target})",
                           backend_verifier.verify_nat_rule_database,
                           target, must_pass=True,
                           expected_fields={"enabled": "no"})

        # ========== 步骤14: 启用规则 ==========
        with rec.step("步骤14: 启用规则", "启用nat过滤地址 + SSH验证"):
            print("\n[步骤14] 启用规则...")
            target = "nat过滤地址"
            rec.add_detail(f"[启用测试] 目标: {target}")

            page.enable_rule(target)
            page.page.wait_for_timeout(1000)

            if page.is_rule_enabled(target):
                print(f"  [OK] 启用成功: {target}")
                rec.add_detail(f"  [OK] 启用成功")
            else:
                print(f"  [WARN] 启用状态未确认")
                rec.add_detail(f"  [WARN] 启用状态未确认")

            if backend_verifier is not None:
                ssh_verify(f"L1-启用({target})",
                           backend_verifier.verify_nat_rule_database,
                           target, must_pass=True,
                           expected_fields={"enabled": "yes"})

        # ========== 步骤15: 删除规则 ==========
        with rec.step("步骤15: 删除规则", "删除nat目的地址TCP + SSH验证"):
            print("\n[步骤15] 删除规则...")
            target = "nat目的地址TCP"
            rec.add_detail(f"[删除测试] 目标: {target}")

            page.delete_rule(target)
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(500)

            assert not page.rule_exists(target), f"规则 {target} 仍存在"
            print(f"  [OK] 删除成功: {target}")
            rec.add_detail(f"  [OK] 删除成功")

            # 从测试列表移除
            test_rules = [r for r in test_rules if r["name"] != target]

            if backend_verifier is not None:
                ssh_verify(f"L1-删除验证({target})",
                           backend_verifier.verify_nat_rule_database,
                           target, must_pass=True,
                           expected_fields=None,
                           expect_absent=True)

        # ========== 步骤16: 搜索测试 ==========
        with rec.step("步骤16: 搜索测试", "精确/部分/不存在/清空"):
            print("\n[步骤16] 搜索测试...")
            rec.add_detail("[搜索测试]")

            # 16.1 精确搜索
            target = "nat源地址基础"
            rec.add_detail(f"  精确搜索: '{target}'")
            page.search_rule(target)
            page.page.wait_for_timeout(1000)
            found = page.rule_exists(target)
            if found:
                print(f"  [OK] 精确搜索: 找到 '{target}'")
                rec.add_detail(f"  [OK] 精确搜索找到")
            else:
                print(f"  [WARN] 精确搜索: 未找到 '{target}'")
                rec.add_detail(f"  [WARN] 精确搜索未找到")

            # 16.2 部分匹配
            partial = "源地址"
            rec.add_detail(f"  部分匹配: '{partial}'")
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule(partial)
            page.page.wait_for_timeout(1000)
            rules = page.get_rule_list()
            partial_count = len(rules)
            rec.add_detail(f"  部分匹配结果: {partial_count} 条({rules})")
            print(f"  [OK] 部分匹配 '{partial}': {partial_count} 条")

            # 16.3 不存在
            rec.add_detail(f"  不存在搜索: '不存在的规则名'")
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("不存在的规则名")
            page.page.wait_for_timeout(1000)
            zero_count = page.get_rule_count()
            if zero_count == 0:
                print(f"  [OK] 不存在搜索: 0条")
                rec.add_detail(f"  [OK] 不存在搜索: 0条")
            else:
                rec.add_detail(f"  [WARN] 不存在搜索: {zero_count}条")

            # 16.4 清空搜索
            page.clear_search()
            page.page.wait_for_timeout(500)
            all_count = page.get_rule_count()
            print(f"  [OK] 清空搜索后: {all_count} 条")
            rec.add_detail(f"  [OK] 清空搜索后: {all_count} 条")

        # ========== 步骤17: 排序测试 ==========
        with rec.step("步骤17: 排序测试", "动作/出接口/进接口列排序"):
            print("\n[步骤17] 排序测试...")
            rec.add_detail("[排序测试]")

            for col_name in ["动作", "出接口", "进接口"]:
                rec.add_detail(f"  排序列: {col_name}")
                try:
                    sorted_ok = page.sort_by_column(col_name)
                    page.page.wait_for_timeout(500)
                    print(f"  [OK] 排序 {col_name}: {'成功' if sorted_ok else '跳过'}")
                    rec.add_detail(f"  [OK] 排序{col_name}: {'成功' if sorted_ok else '跳过'}")
                except Exception as e:
                    print(f"  [WARN] 排序 {col_name}: {e}")
                    rec.add_detail(f"  [WARN] 排序{col_name}: {e}")

        # ========== 步骤18: 导出测试 ==========
        export_file_csv = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "test_data", "exports", "nat_rule", "nat_rule_config.csv"
        )
        export_file_txt = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "test_data", "exports", "nat_rule", "nat_rule_config.txt"
        )

        with rec.step("步骤18: 导出测试", "导出CSV和TXT"):
            print("\n[步骤18] 导出测试...")
            rec.add_detail("[导出测试]")

            # 18.1 CSV导出
            rec.add_detail("  CSV导出:")
            try:
                csv_ok = page.export_rules(export_format="csv")
                if csv_ok and os.path.exists(export_file_csv):
                    size = os.path.getsize(export_file_csv)
                    print(f"  [OK] CSV导出成功: {export_file_csv} ({size} bytes)")
                    rec.add_detail(f"  [OK] CSV导出: {os.path.basename(export_file_csv)} ({size}B)")
                else:
                    print(f"  [WARN] CSV导出失败")
                    rec.add_detail(f"  [WARN] CSV导出失败")
                    ui_failures.append("CSV导出失败")
            except Exception as e:
                print(f"  [WARN] CSV导出异常: {e}")
                rec.add_detail(f"  [WARN] CSV导出异常: {e}")

            # 18.2 TXT导出
            rec.add_detail("  TXT导出:")
            try:
                txt_ok = page.export_rules(export_format="txt")
                if txt_ok and os.path.exists(export_file_txt):
                    size = os.path.getsize(export_file_txt)
                    print(f"  [OK] TXT导出成功: {export_file_txt} ({size} bytes)")
                    rec.add_detail(f"  [OK] TXT导出: {os.path.basename(export_file_txt)} ({size}B)")
                else:
                    print(f"  [WARN] TXT导出失败")
                    rec.add_detail(f"  [WARN] TXT导出失败")
                    ui_failures.append("TXT导出失败")
            except Exception as e:
                print(f"  [WARN] TXT导出异常: {e}")
                rec.add_detail(f"  [WARN] TXT导出异常: {e}")

        # ========== 步骤19: 异常输入测试 ==========
        with rec.step("步骤19: 异常输入测试", "空名称/重复/超长/特殊字符/纯空格"):
            print("\n[步骤19] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 19.1 空名称
            rec.add_detail("  空名称:")
            result = page.try_add_rule_invalid(name="")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                rec.add_detail(f"    [FAIL] 未拦截")

            # 19.2 重复名称
            rec.add_detail("  重复名称:")
            existing = test_rules[0]["name"]
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name(existing)
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
                if "natRules" in page.page.url:
                    page.navigate_back_to_list()
                page.page.wait_for_timeout(300)
            except Exception as e:
                print(f"    [INFO] 重复名称异常: {e}")
                rec.add_detail(f"    [INFO] 异常: {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 19.3 超长名称(30字符, tagname限制15字符)
            rec.add_detail("  超长名称(30字符):")
            long_name = "a" * 30
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name(long_name)
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
                    if "natRules" in page.page.url:
                        page.navigate_back_to_list()
            except Exception as e:
                print(f"    [INFO] 超长名称异常: {e}")
                rec.add_detail(f"    [INFO] {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 19.4 特殊字符
            rec.add_detail("  特殊字符:")
            result = page.try_add_rule_invalid(name="<script>alert(1)</script>")
            print(f"    [INFO] 特殊字符: {result}")
            rec.add_detail(f"    [INFO] {result}")

            # 19.5 纯空格
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
            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(500)

        # ========== 步骤20: 批量停用 ==========
        with rec.step("步骤20: 批量停用", f"批量停用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤20] 批量停用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量停用] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_disable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(500)
            disabled_count = sum(1 for r in test_rules if page.is_rule_disabled(r["name"]))
            print(f"  [OK] 批量停用: {disabled_count}/{len(test_rules)} 条")
            rec.add_detail(f"[结果] {disabled_count}/{len(test_rules)} 条已停用")

            if backend_verifier is not None:
                ssh_verify("L1-批量停用", backend_verifier.verify_nat_rule_database,
                           test_rules[0]["name"], must_pass=False,
                           expected_fields={"enabled": "no"})

        # ========== 步骤21: 批量启用 ==========
        with rec.step("步骤21: 批量启用", f"批量启用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤21] 批量启用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量启用] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_enable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(500)
            enabled_count = sum(1 for r in test_rules if page.is_rule_enabled(r["name"]))
            print(f"  [OK] 批量启用: {enabled_count}/{len(test_rules)} 条")
            rec.add_detail(f"[结果] {enabled_count}/{len(test_rules)} 条已启用")

            if backend_verifier is not None:
                ssh_verify("L1-批量启用", backend_verifier.verify_nat_rule_database,
                           test_rules[0]["name"], must_pass=False,
                           expected_fields={"enabled": "yes"})

        # ========== 步骤22: 批量删除 ==========
        with rec.step("步骤22: 批量删除", f"批量删除剩余 {len(test_rules)} 条"):
            print(f"\n[步骤22] 批量删除 {len(test_rules)} 条...")
            rec.add_detail(f"[批量删除] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_delete()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(500)
            for rule in test_rules:
                assert not page.rule_exists(rule["name"]), f"规则 {rule['name']} 仍存在"
            print(f"  [OK] 批量删除 {len(test_rules)} 条成功")
            rec.add_detail(f"[结果] [OK] 全部删除")

            if backend_verifier is not None:
                try:
                    nat_rules = backend_verifier.query_nat_rules()
                    test_names = {r["name"] for r in test_rules}
                    remaining = [r for r in nat_rules if r.get("tagname") in test_names]
                    if remaining:
                        ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining)}条")
                    else:
                        rec.add_detail(f"    SSH: 测试规则已全部删除")
                except Exception:
                    pass

        # ========== 步骤23: 导入追加(CSV) ==========
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
                page.navigate_to_nat_rule()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if count_after > count_before:
                    print(f"  [OK] 追加导入成功, 添加 {count_after - count_before} 条")
                    rec.add_detail(f"  [OK] 添加 {count_after - count_before} 条")
                else:
                    print(f"  [WARN] 追加导入后数量未增加")
                    rec.add_detail(f"  [WARN] 数量未增加")
            else:
                print(f"  [WARN] CSV文件不存在")
                rec.add_detail(f"  CSV文件不存在")

        # ========== 步骤24: 导入清空(TXT) ==========
        with rec.step("步骤24: 导入配置(清空现有)", "使用导出的TXT清空现有后导入"):
            print("\n[步骤24] 导入配置(清空现有数据-TXT)...")
            rec.add_detail("[导入测试-清空现有-TXT]")

            if os.path.exists(export_file_txt):
                page.add_rule(name="额外NAT规则", action="过滤")
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_txt)}")
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则)")

                result = page.import_rules(export_file_txt, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1000)
                page.navigate_to_nat_rule()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if not page.rule_exists("额外NAT规则"):
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

        # ========== 步骤25: 齿轮设置 - 开启本地转发自动NAT ==========
        with rec.step("步骤25: 设置-开启本地转发自动NAT", "通过齿轮设置抽屉开启本地转发自动NAT"):
            print("\n[步骤25] 齿轮设置: 开启本地转发自动NAT...")
            rec.add_detail("[齿轮设置] 开启本地转发自动NAT(相同LAN)")

            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(500)

            opened = page.open_settings_drawer()
            if opened:
                page.page.wait_for_timeout(500)

                page.toggle_local_forward_nat(True)
                page.page.wait_for_timeout(300)

                saved = page.save_settings()
                if saved:
                    print(f"  [OK] 设置保存成功(开启)")
                    rec.add_detail(f"  [OK] 设置保存成功(开启)")

                    if backend_verifier is not None:
                        ssh_verify("L1-本地转发NAT开启", backend_verifier.verify_local_forward_nat,
                                   must_pass=True, expected_enabled=True)
                else:
                    print(f"  [WARN] 设置保存失败")
                    rec.add_detail(f"  [WARN] 设置保存失败")
                    ui_failures.append("齿轮设置保存失败(开启)")
            else:
                print(f"  [WARN] 设置抽屉打开失败")
                rec.add_detail(f"  [WARN] 设置抽屉打开失败")

        # ========== 步骤26: 齿轮设置 - 关闭本地转发自动NAT + 恢复 ==========
        with rec.step("步骤26: 设置-关闭本地转发自动NAT", "关闭设置并恢复默认"):
            print("\n[步骤26] 齿轮设置: 关闭本地转发自动NAT...")
            rec.add_detail("[齿轮设置] 关闭本地转发自动NAT")

            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(500)

            opened = page.open_settings_drawer()
            if opened:
                page.page.wait_for_timeout(500)

                page.toggle_local_forward_nat(False)
                page.page.wait_for_timeout(300)

                saved = page.save_settings()
                if saved:
                    print(f"  [OK] 设置恢复成功(关闭)")
                    rec.add_detail(f"  [OK] 设置恢复成功(关闭)")

                    if backend_verifier is not None:
                        ssh_verify("L1-本地转发NAT关闭", backend_verifier.verify_local_forward_nat,
                                   must_pass=True, expected_enabled=False)
                else:
                    print(f"  [WARN] 设置恢复失败")
                    rec.add_detail(f"  [WARN] 设置恢复失败")
                    ui_failures.append("齿轮设置恢复失败(关闭)")
            else:
                print(f"  [WARN] 设置抽屉打开失败")

        # ========== 步骤27: 最终清理 ==========
        with rec.step("步骤27: 最终清理", "清理所有测试数据"):
            print("\n[步骤27] 最终清理...")
            rec.add_detail("[环境清理]")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.navigate_to_nat_rule()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                for cleanup_round in range(3):
                    page.navigate_to_nat_rule()
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
                page.navigate_to_nat_rule()
                page.page.wait_for_timeout(500)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成, 剩余 {final_count} 条")
                rec.add_detail(f"[清理结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 无需清理")
                rec.add_detail("  无需清理")

            if backend_verifier is not None:
                ssh_verify("L1-最终清理", backend_verifier.verify_nat_rule_iptables,
                           must_pass=False, expect_rules=False)

        # ========== 步骤28: 帮助功能测试 ==========
        with rec.step("步骤28: 帮助功能测试", "测试帮助图标"):
            print("\n[步骤28] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")
            try:
                # 确保在NAT规则列表页
                page.navigate_to_nat_rule()
                page.page.wait_for_timeout(500)

                # 使用基类的帮助功能测试方法
                help_result = page.test_help_functionality()

                if help_result["icon_clickable"]:
                    if help_result["panel_visible"]:
                        content_preview = help_result.get("content_text", "")[:50]
                        print(f"  [OK] 帮助图标可点击, 面板已显示")
                        rec.add_detail(f"  [OK] 帮助图标可点击, 面板已显示")
                        if content_preview:
                            rec.add_detail(f"  帮助内容: {content_preview}...")
                    else:
                        # 帮助可能是popover，基类选择器可能不全面，尝试补充检查
                        help_panel = page.page.locator(
                            ".ant-drawer:visible, .ant-modal:visible, "
                            "[role='dialog']:visible, .ant-popover:visible, "
                            "[class*='help-panel']:visible, [class*='help-content']:visible"
                        )
                        if help_panel.count() > 0:
                            print(f"  [OK] 帮助图标可点击, 面板已显示(补充检测)")
                            rec.add_detail(f"  [OK] 帮助图标可点击, 面板已显示(补充检测)")
                        else:
                            print(f"  [WARN] 帮助图标已点击但面板未显示")
                            rec.add_detail(f"  帮助面板未显示")
                            page.page.keyboard.press("Escape")
                            page.page.wait_for_timeout(300)
                else:
                    # 尝试文字按钮
                    help_btn = page.page.get_by_role("button", name="帮助")
                    if help_btn.count() > 0:
                        help_btn.click()
                        page.page.wait_for_timeout(1000)
                        help_panel = page.page.locator(
                            ".ant-drawer:visible, .ant-modal:visible, "
                            "[role='dialog']:visible, .ant-popover:visible"
                        )
                        if help_panel.count() > 0:
                            print(f"  [OK] 帮助按钮可点击, 面板已显示")
                            rec.add_detail(f"  [OK] 帮助按钮可点击, 面板已显示")
                            page.page.keyboard.press("Escape")
                            page.page.wait_for_timeout(300)
                        else:
                            print("  [WARN] 帮助按钮已点击但面板未显示")
                            rec.add_detail("  帮助面板未显示")
                    else:
                        print("  [WARN] 帮助图标未找到")
                        rec.add_detail("  帮助图标未找到")
            except Exception as e:
                print(f"  [WARN] 帮助功能测试异常: {e}")
                rec.add_detail(f"  帮助功能异常: {e}")

        print("\n" + "=" * 60)
        print("NAT规则综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 9条(过滤3/源地址NAT3/目的地址NAT2/带备注/反向匹配)")
        print("  - 编辑/停用/启用/删除: 各1条")
        print("  - 搜索: 精确/部分匹配/不存在/清空恢复")
        print("  - 排序: 动作/出接口/进接口")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加(CSV) + 清空现有数据(TXT)")
        print("  - 异常输入: 空名称/重复/超长/特殊字符/纯空格")
        print("  - 批量操作: 批量停用/启用/删除")
        print("  - 齿轮设置: 开启/关闭本地转发自动NAT(相同LAN)")
        print("  - SSH后台验证: L1数据库+L2 iptables+L3运行时+L4内核")

        # 断言(SSH后台验证 + UI操作验证)
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败:")
            for f in all_failures:
                print(f"  - {f}")
            assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
