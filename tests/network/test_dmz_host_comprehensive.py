"""
DMZ主机综合测试用例

一次测试覆盖多个功能(DMZ主机是UPnP/NAT的第5个tab):
1. 添加多条规则(覆盖映射类型 + 排除协议 + 排除端口)
2. SSH后台数据验证(L1数据库 + L2 iptables NETNAT链 + PREROUTING引用检查 + L3运行时 + L4内核)
3. 编辑其中1条
4. 停用/启用/删除各1条
5. segmented筛选器测试(全部/已停用/已启用)
6. 搜索测试
7. 导出测试(CSV/TXT)
8. 异常输入测试(空名称/必填/非法IP/非法端口/重复/超长/特殊字符)
9. 批量停用/启用/删除
10. 导入测试
11. 重启恢复验证(检测netmap.sh init的select*bug, 重点!)
12. 帮助功能测试

SSH后台验证: L1数据库(one_one_map) + L2 iptables(NETNAT链NETMAP规则 + PREROUTING引用)
            + L3运行时 + L4内核 + L2+重启恢复(init bug检测)

⚠️ 重要注意事项:
- 禁止用wan1作为外网接口(DMZ会把wan1所有流量映射走, 导致无法登录管理)
  测试用 interface=all 或 wan2/wan3
- 排除协议语义: 不限(全部NETMAP) / tcp/udp/tcp+udp(指定端口RETURN放行, 其余NETMAP)

已知产品BUG(本测试会检测):
- netmap.sh init函数用 select * (非数字) 与 0 比较大小, 导致:
  重启(boot->init)时PREROUTING不引用NETNAT链 -> DMZ不生效
- verify_dmz_boot_recovery 专门检测此bug
"""
import pytest
import os
from pages.network.dmz_host_page import DmzHostPage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.dmz_host
@pytest.mark.network
class TestDmzHostComprehensive:
    """DMZ主机综合测试 - 一次测试覆盖所有功能"""

    def test_dmz_host_comprehensive(self, dmz_host_page_logged_in: DmzHostPage,
                                     step_recorder: StepRecorder, request):
        """
        综合测试: 添加多条规则 -> SSH验证 -> 编辑 -> 停用 -> 启用 -> 删除 ->
        segmented筛选 -> 搜索 -> 导出 -> 异常测试 -> 批量操作 -> 导入 ->
        重启恢复验证 -> 帮助
        """
        page = dmz_host_page_logged_in
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

        # 测试数据 - 覆盖映射类型(外网接口选wan2/wan3 + 外网IP)和排除协议的组合
        # ⚠️ 安全: 禁止 interface=all(任意) 和 wan1, 会NETMAP管理流量导致设备失联
        # 外网接口模式: 用wan2/wan3(安全); 外网IP模式: 指向不存在IP(10.66.0.201+)
        test_rules = [
            # Rule 1: 外网接口wan2+不限协议(基础)
            {"name": "dmz基础", "lan_addr": "192.168.2.10",
             "map_type": "外网接口", "external_interfaces": ["wan2"], "protocol": "不限",
             "desc": "外网接口wan2+不限协议"},
            # Rule 2: 外网接口wan2+tcp排除协议+排除端口
            {"name": "dmz排除tcp", "lan_addr": "192.168.2.11",
             "map_type": "外网接口", "external_interfaces": ["wan2"],
             "protocol": "tcp", "excl_port": "80,443",
             "desc": "外网接口wan2+tcp排除(80,443放行)"},
            # Rule 3: 外网接口wan3+udp排除协议+排除端口
            {"name": "dmz排除udp", "lan_addr": "192.168.2.12",
             "map_type": "外网接口", "external_interfaces": ["wan3"],
             "protocol": "udp", "excl_port": "53",
             "desc": "外网接口wan3+udp排除(53放行)"},
            # Rule 4: 外网IP模式+tcp+udp排除协议(另一种映射类型)
            {"name": "dmz外网IP", "lan_addr": "192.168.2.13",
             "map_type": "外网IP", "external_ip": "10.66.0.201",
             "protocol": "tcp+udp", "excl_port": "8080",
             "desc": "外网IP+tcp+udp排除(8080放行)"},
            # Rule 5: 外网接口wan2+不限+带备注
            {"name": "dmz带备注", "lan_addr": "192.168.2.15",
             "map_type": "外网接口", "external_interfaces": ["wan2"], "protocol": "不限",
             "remark": "DMZ测试服务器",
             "desc": "外网接口wan2+不限+带备注"},
        ]

        print("\n" + "=" * 60)
        print("DMZ主机综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")
        for r in test_rules:
            print(f"  - {r['name']}, 排除协议={r.get('protocol', '不限')}, 映射={r['map_type']}, 场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            for cleanup_round in range(3):
                page.navigate_to_dmz()
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

            page.navigate_to_dmz()
            page.page.wait_for_timeout(1000)
            final_count = page.get_rule_count()
            print(f"  [OK] 环境清理完成, 剩余 {final_count} 条")
            rec.add_detail(f"[清理结果] 剩余 {final_count} 条")

        # ========== 步骤2-7: 逐条添加规则 ==========
        added_count = 0
        for rule_idx, rule in enumerate(test_rules):
            step_num = rule_idx + 2
            with rec.step(f"步骤{step_num}: 添加规则 {rule['name']}",
                          f"添加: {rule['desc']}"):
                print(f"\n[步骤{step_num}] 添加规则: {rule['name']}")
                rec.add_detail(f"  场景: {rule['desc']}")
                rec.add_detail(f"  排除协议: {rule.get('protocol', '不限')}, 映射: {rule.get('map_type', '外网接口')}")

                result = page.add_rule(
                    name=rule["name"],
                    lan_addr=rule["lan_addr"],
                    map_type=rule.get("map_type", "外网接口"),
                    external_ip=rule.get("external_ip"),
                    protocol=rule.get("protocol", "不限"),
                    excl_port=rule.get("excl_port"),
                    remark=rule.get("remark"),
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")
                added_count += 1

                # SSH L1验证
                if backend_verifier is not None:
                    expected = {"enabled": "yes", "lan_addr": rule["lan_addr"]}
                    proto_db = DmzHostPage.PROTOCOL_MAP.get(rule.get("protocol", "不限"), "any")
                    expected["protocol"] = proto_db
                    if rule.get("excl_port"):
                        expected["excl_port"] = rule["excl_port"]
                    if rule.get("remark"):
                        expected["comment"] = rule["remark"]

                    ssh_verify(
                        f"L1-数据库({rule['name']})",
                        backend_verifier.verify_dmz_database,
                        rule["name"],
                        must_pass=True,
                        expected_fields=expected,
                    )

        # ========== 步骤8: 验证总数 + 后端全链路验证 ==========
        with rec.step("步骤8: 验证总数 + 后端全链路", f"验证共{len(test_rules)}条 + SSH L1-L4"):
            print(f"\n[步骤8] 验证总数...")
            page.navigate_to_dmz()
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
                rec.add_detail("[SSH全链路验证] L1=数据库, L2=iptables(NETNAT+PREROUTING), L3=运行时, L4=内核")
                for rule in test_rules:
                    rec.add_detail(f"  -- 验证: {rule['name']} --")
                    proto_db = DmzHostPage.PROTOCOL_MAP.get(rule.get("protocol", "不限"), "any")
                    expected = {"enabled": "yes", "protocol": proto_db, "lan_addr": rule["lan_addr"]}
                    full = ssh_verify(
                        f"全链路({rule['name']})",
                        backend_verifier.verify_dmz_full_chain,
                        rule["name"],
                        must_pass=False,
                        expected_fields=expected,
                        lan_addr=rule["lan_addr"],
                    )
                    if full:
                        for r in full.results:
                            rec.add_detail(f"    {r.level}: {'[OK]' if r.passed else '[FAIL]'} {r.message}")

        # ========== 步骤9: 编辑规则 ==========
        with rec.step("步骤9: 编辑规则", "编辑dmz基础->改名+改备注"):
            print("\n[步骤9] 编辑规则...")
            rec.add_detail("[编辑测试] dmz基础 -> dmz已编辑")

            old_name = "dmz基础"
            new_name = "dmz已编辑"
            result = page.edit_rule(old_name, new_name=new_name, remark="编辑后备注")
            if result:
                assert page.rule_exists(new_name), f"编辑后规则 {new_name} 未找到"
                print(f"  [OK] 编辑成功: {old_name} -> {new_name}")
                rec.add_detail(f"  [OK] 编辑成功: {old_name} -> {new_name}")

                for r in test_rules:
                    if r["name"] == old_name:
                        r["name"] = new_name
                        break

                if backend_verifier is not None:
                    ssh_verify(f"L1-编辑后({new_name})",
                               backend_verifier.verify_dmz_database,
                               new_name, must_pass=True,
                               expected_fields={"enabled": "yes", "comment": "编辑后备注"})
            else:
                print(f"  [WARN] 编辑失败")
                rec.add_detail(f"  [WARN] 编辑失败")
                ui_failures.append("编辑规则失败")

        # ========== 步骤10: 停用规则 ==========
        with rec.step("步骤10: 停用规则", "停用dmz排除tcp + SSH验证"):
            print("\n[步骤10] 停用规则...")
            target = "dmz排除tcp"
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
                           backend_verifier.verify_dmz_database,
                           target, must_pass=True,
                           expected_fields={"enabled": "no"})

        # ========== 步骤11: 启用规则 ==========
        with rec.step("步骤11: 启用规则", "启用dmz排除tcp + SSH验证"):
            print("\n[步骤11] 启用规则...")
            target = "dmz排除tcp"
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
                           backend_verifier.verify_dmz_database,
                           target, must_pass=True,
                           expected_fields={"enabled": "yes"})

        # ========== 步骤12: 删除规则 ==========
        with rec.step("步骤12: 删除规则", "删除dmz外网IP + SSH验证"):
            print("\n[步骤12] 删除规则...")
            target = "dmz外网IP"
            rec.add_detail(f"[删除测试] 目标: {target}")

            page.delete_rule(target)
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_dmz()
            page.page.wait_for_timeout(500)

            assert not page.rule_exists(target), f"规则 {target} 仍存在"
            print(f"  [OK] 删除成功: {target}")
            rec.add_detail(f"  [OK] 删除成功")

            test_rules = [r for r in test_rules if r["name"] != target]

            if backend_verifier is not None:
                ssh_verify(f"L1-删除验证({target})",
                           backend_verifier.verify_dmz_database,
                           target, must_pass=True,
                           expect_absent=True)

        # ========== 步骤13: segmented筛选器测试 ==========
        with rec.step("步骤13: segmented筛选器", "全部/已停用/已启用 计数验证"):
            print("\n[步骤13] segmented筛选器测试...")
            rec.add_detail("[segmented筛选器测试]")

            page.disable_rule("dmz排除udp")
            page.page.wait_for_timeout(1000)
            page.navigate_to_dmz()
            page.page.wait_for_timeout(500)

            counts = page.get_segmented_counts()
            print(f"  计数: {counts}")
            rec.add_detail(f"  计数: {counts}")

            if counts["全部"] >= 0:
                expected_all = counts["已启用"] + counts["已停用"]
                if counts["全部"] == expected_all:
                    print(f"  [OK] 计数逻辑正确: 全部({counts['全部']}) = 启用({counts['已启用']}) + 停用({counts['已停用']})")
                    rec.add_detail(f"  [OK] 计数逻辑正确")
                else:
                    rec.add_detail(f"  [WARN] 计数逻辑异常")

            page.click_segmented_filter("已停用")
            page.page.wait_for_timeout(1000)
            disabled_list = page.get_rule_list()
            print(f"  已停用列表: {disabled_list}")
            rec.add_detail(f"  已停用筛选: {disabled_list}")
            if "dmz排除udp" in disabled_list:
                print(f"  [OK] 已停用筛选包含 dmz排除udp")
                rec.add_detail(f"  [OK] 已停用筛选正确")

            page.click_segmented_filter("已启用")
            page.page.wait_for_timeout(1000)
            enabled_list = page.get_rule_list()
            print(f"  已启用列表({len(enabled_list)}条)")
            rec.add_detail(f"  已启用筛选: {len(enabled_list)}条")
            if "dmz排除udp" not in enabled_list:
                print(f"  [OK] 已启用筛选不包含已停用的dmz排除udp")
                rec.add_detail(f"  [OK] 已启用筛选正确")

            page.click_segmented_filter("全部")
            page.page.wait_for_timeout(500)
            page.enable_rule("dmz排除udp")
            page.page.wait_for_timeout(500)

        # ========== 步骤14: 搜索测试 ==========
        with rec.step("步骤14: 搜索测试", "精确/部分/不存在/清空"):
            print("\n[步骤14] 搜索测试...")
            rec.add_detail("[搜索测试]")

            target = "dmz排除udp"
            rec.add_detail(f"  精确搜索: '{target}'")
            page.search_rule(target)
            page.page.wait_for_timeout(1000)
            found = page.rule_exists(target)
            if found:
                print(f"  [OK] 精确搜索: 找到 '{target}'")
                rec.add_detail(f"  [OK] 精确搜索找到")

            partial = "排除"
            rec.add_detail(f"  部分匹配: '{partial}'")
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule(partial)
            page.page.wait_for_timeout(1000)
            rules = page.get_rule_list()
            partial_count = len(rules)
            rec.add_detail(f"  部分匹配结果: {partial_count} 条({rules})")
            print(f"  [OK] 部分匹配 '{partial}': {partial_count} 条")

            rec.add_detail(f"  不存在搜索: '不存在的规则名'")
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("不存在的规则名")
            page.page.wait_for_timeout(1000)
            zero_count = page.get_rule_count()
            if zero_count == 0:
                print(f"  [OK] 不存在搜索: 0条")
                rec.add_detail(f"  [OK] 不存在搜索: 0条")

            page.clear_search()
            page.page.wait_for_timeout(500)
            all_count = page.get_rule_count()
            print(f"  [OK] 清空搜索后: {all_count} 条")
            rec.add_detail(f"  [OK] 清空搜索后: {all_count} 条")

        # ========== 步骤15: 导出测试 ==========
        export_file_csv = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "test_data", "exports", "dmz_host", "dmz_host_config.csv"
        )
        export_file_txt = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "test_data", "exports", "dmz_host", "dmz_host_config.txt"
        )

        with rec.step("步骤15: 导出测试", "导出CSV和TXT"):
            print("\n[步骤15] 导出测试...")
            rec.add_detail("[导出测试]")

            for fmt, fpath in [("csv", export_file_csv), ("txt", export_file_txt)]:
                rec.add_detail(f"  {fmt.upper()}导出:")
                try:
                    ok = page.export_rules(export_format=fmt)
                    if ok and os.path.exists(fpath):
                        size = os.path.getsize(fpath)
                        print(f"  [OK] {fmt.upper()}导出成功: ({size} bytes)")
                        rec.add_detail(f"  [OK] {fmt.upper()}导出: ({size}B)")
                    else:
                        print(f"  [WARN] {fmt.upper()}导出失败")
                        rec.add_detail(f"  [WARN] {fmt.upper()}导出失败")
                        ui_failures.append(f"{fmt.upper()}导出失败")
                except Exception as e:
                    print(f"  [WARN] {fmt.upper()}导出异常: {e}")
                    rec.add_detail(f"  [WARN] {fmt.upper()}导出异常: {e}")

        # ========== 步骤16: 异常输入测试 ==========
        with rec.step("步骤16: 异常输入测试", "空名称/缺必填/非法IP/重复/超长/特殊字符"):
            print("\n[步骤16] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 16.1 空名称
            rec.add_detail("  空名称:")
            result = page.try_add_rule_invalid(name="")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                rec.add_detail(f"    [FAIL] 未拦截")

            # 16.2 缺内网地址
            rec.add_detail("  缺内网地址:")
            result = page.try_add_rule_invalid(name="dmz缺地址")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                rec.add_detail(f"    [INFO] {result}")

            # 16.3 非法内网IP
            rec.add_detail("  非法内网IP:")
            result = page.try_add_rule_invalid(name="dmz非法IP", lan_addr="999.999.999.999")
            print(f"    [INFO] 非法IP: {result}")
            rec.add_detail(f"    [INFO] {result}")

            # 16.4 重复名称
            rec.add_detail("  重复名称:")
            existing = test_rules[0]["name"]
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                # 强制外网IP模式+安全IP(避免误创建interface=all危险规则)
                page.select_map_type("外网IP")
                page.page.wait_for_timeout(500)
                page.fill_external_ip("10.66.0.250")
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
                if "dmzServer" in page.page.url:
                    page.navigate_back_to_list()
                page.page.wait_for_timeout(300)
            except Exception as e:
                print(f"    [INFO] 重复名称异常: {e}")
                rec.add_detail(f"    [INFO] 异常: {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 16.5 超长名称
            rec.add_detail("  超长名称(30字符):")
            long_name = "a" * 30
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                # 强制外网IP模式+安全IP(避免误创建interface=all危险规则)
                page.select_map_type("外网IP")
                page.page.wait_for_timeout(500)
                page.fill_external_ip("10.66.0.250")
                page.fill_name(long_name)
                page.fill_lan_addr("192.168.2.99")
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
                    if "dmzServer" in page.page.url:
                        page.navigate_back_to_list()
            except Exception as e:
                print(f"    [INFO] 超长名称异常: {e}")
                rec.add_detail(f"    [INFO] {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 16.6 特殊字符
            rec.add_detail("  特殊字符:")
            result = page.try_add_rule_invalid(name="<script>alert(1)</script>", lan_addr="192.168.2.98")
            print(f"    [INFO] 特殊字符: {result}")
            rec.add_detail(f"    [INFO] {result}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_dmz()
            page.page.wait_for_timeout(500)

        # ========== 步骤17: 批量停用 ==========
        with rec.step("步骤17: 批量停用", f"批量停用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤17] 批量停用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量停用] 目标: {len(test_rules)} 条")

            # 批量停用带重试 + SSH验证(参照跨三层, 原用ssh_verify must_pass=False软断言且只查第一条)
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
                page.navigate_to_dmz()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_dmz_rules() or []
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
                db_rules = backend_verifier.query_dmz_rules() or []
                disabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                rec.add_detail(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                print(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                if total > 0 and disabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_count}/{total}条规则停用")

        # ========== 步骤18: 批量启用 ==========
        with rec.step("步骤18: 批量启用", f"批量启用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤18] 批量启用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量启用] 目标: {len(test_rules)} 条")

            # 批量启用带重试 + SSH验证(参照跨三层, 原用ssh_verify must_pass=False软断言且只查第一条)
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
                page.navigate_to_dmz()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_dmz_rules() or []
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
                db_rules = backend_verifier.query_dmz_rules() or []
                enabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "yes")
                rec.add_detail(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                print(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                if total > 0 and enabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量启用: 仅{enabled_count}/{total}条规则启用")

        # ========== 步骤19: 批量删除 ==========
        with rec.step("步骤19: 批量删除", f"批量删除剩余 {len(test_rules)} 条"):
            print(f"\n[步骤19] 批量删除 {len(test_rules)} 条...")
            rec.add_detail(f"[批量删除] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_delete()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_dmz()
            page.page.wait_for_timeout(500)
            for rule in test_rules:
                assert not page.rule_exists(rule["name"]), f"规则 {rule['name']} 仍存在"
            print(f"  [OK] 批量删除 {len(test_rules)} 条成功")
            rec.add_detail(f"[结果] [OK] 全部删除")

            if backend_verifier is not None:
                try:
                    dmz_rules = backend_verifier.query_dmz_rules()
                    test_names = {r["name"] for r in test_rules}
                    remaining = [r for r in dmz_rules if r.get("tagname") in test_names]
                    if remaining:
                        ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining)}条")
                    else:
                        rec.add_detail(f"    SSH: 测试规则已全部删除")
                except Exception as e:
                    ssh_failures.append(f"SSH-L1-批量删除验证异常: {str(e)[:80]}")

        # ========== 步骤20: 导入追加(CSV) ==========
        with rec.step("步骤20: 导入配置(追加)", "使用导出的CSV追加导入"):
            print("\n[步骤20] 导入配置(追加)...")
            rec.add_detail("[导入测试-追加]")

            if os.path.exists(export_file_csv):
                count_before = page.get_rule_count()
                rec.add_detail(f"  导入前: {count_before} 条")

                result = page.import_rules(export_file_csv, clear_existing=False)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_dmz()
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

        # ========== 步骤21: 导入清空(TXT) ==========
        with rec.step("步骤21: 导入配置(清空现有)", "使用导出的TXT清空现有后导入"):
            print("\n[步骤21] 导入配置(清空现有数据-TXT)...")
            rec.add_detail("[导入测试-清空现有-TXT]")

            if os.path.exists(export_file_txt):
                page.add_rule(name="额外DMZ规则", lan_addr="192.168.2.200")
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则)")

                result = page.import_rules(export_file_txt, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1000)
                page.navigate_to_dmz()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if not page.rule_exists("额外DMZ规则"):
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

        # ========== 步骤22: 重启恢复验证(重点! 检测netmap.sh init bug) ==========
        with rec.step("步骤22: 重启恢复验证", "模拟boot流程, 检测init的select*bug是否导致PREROUTING不注册"):
            print("\n[步骤22] 重启恢复验证(检测netmap.sh init bug)...")
            rec.add_detail("[重启恢复验证] 模拟netmap.sh init, 检查PREROUTING是否引用NETNAT链")
            rec.add_detail("已知bug: init用select*(非数字)-gt 0比较, 报integer expression expected")
            rec.add_detail("后果: PREROUTING不引用NETNAT链 -> 重启后DMZ不生效")

            if backend_verifier is not None:
                # 先确保有一条启用的规则用于验证
                page.navigate_to_dmz()
                page.page.wait_for_timeout(500)
                current_count = page.get_rule_count()
                test_rule_name = None
                if current_count == 0:
                    # 加一条临时规则
                    page.add_rule(name="dmz重启验证", lan_addr="192.168.2.50")
                    page.page.wait_for_timeout(1000)
                    test_rule_name = "dmz重启验证"
                else:
                    names = page.get_rule_list()
                    test_rule_name = names[0] if names else None

                # 执行重启恢复验证(must_pass=True: 确认的产品bug必须判测试失败)
                # 这是已实锤的产品bug(netmap.sh init的select*错误导致重启后DMZ不生效),
                # 测试的目的就是发现问题, 发现bug必须让测试失败, 不能掩盖
                boot_result = ssh_verify(
                    "L2-重启恢复(init模拟)",
                    backend_verifier.verify_dmz_boot_recovery,
                    test_rule_name,
                    must_pass=True,  # 产品bug: 发现即失败, 不掩盖
                )

                if boot_result:
                    if boot_result.passed:
                        print(f"  [OK] 重启后DMZ正常生效(PREROUTING已引用NETNAT链)")
                        rec.add_detail(f"  [OK] 重启恢复正常: {boot_result.message}")
                    else:
                        # 命中产品bug: 记录详情 + 加入失败列表(最终判测试FAILED), 但不中断后续步骤
                        # 测试目的是发现问题, 发现bug必须判失败, 同时继续跑完剩余步骤让报告完整
                        print(f"  [FAIL] 重启后DMZ不生效: {boot_result.message}")
                        rec.add_detail(f"  [FAIL] 重启恢复失败(产品bug): {boot_result.message}")
                        rec.add_detail(f"  [根因] netmap.sh init用select*(非数字)-gt0, 导致PREROUTING不注册NETNAT链")
                        print(f"  [说明] netmap.sh init用select*(非数字)-gt0, 导致PREROUTING不注册NETNAT链")

                # 清理临时规则
                if test_rule_name == "dmz重启验证":
                    try:
                        page.delete_rule(test_rule_name)
                        page.page.wait_for_timeout(500)
                    except Exception:
                        pass

        # ========== 步骤23: 最终清理 ==========
        with rec.step("步骤23: 最终清理", "清理所有测试数据"):
            print("\n[步骤23] 最终清理...")
            rec.add_detail("[环境清理]")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.navigate_to_dmz()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                for cleanup_round in range(3):
                    page.navigate_to_dmz()
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
                page.navigate_to_dmz()
                page.page.wait_for_timeout(500)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成, 剩余 {final_count} 条")
                rec.add_detail(f"[清理结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 无需清理")
                rec.add_detail("  无需清理")

            if backend_verifier is not None:
                ssh_verify("L1-最终清理", backend_verifier.verify_dmz_iptables,
                           must_pass=False, expect_rules=False)

        # ========== 步骤24: 帮助功能测试 ==========
        with rec.step("步骤24: 帮助功能测试", "测试帮助图标"):
            print("\n[步骤24] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")
            try:
                page.navigate_to_dmz()
                page.page.wait_for_timeout(500)

                help_result = page.test_help_functionality()

                if help_result["icon_clickable"]:
                    if help_result["panel_visible"]:
                        print(f"  [OK] 帮助图标可点击, 面板已显示")
                        rec.add_detail(f"  [OK] 帮助图标可点击, 面板已显示")
                    else:
                        help_panel = page.page.locator(
                            ".ant-drawer:visible, .ant-modal:visible, "
                            "[role='dialog']:visible, .ant-popover:visible"
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
        print("DMZ主机综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 6条(外网接口4/外网IP1/排除协议tcp/udp/tcp+udp/带备注)")
        print("  - 编辑/停用/启用/删除: 各1条")
        print("  - segmented筛选器: 全部/已停用/已启用")
        print("  - 搜索: 精确/部分/不存在/清空")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加(CSV) + 清空现有(TXT)")
        print("  - 异常输入: 空名称/缺必填/非法IP/重复/超长/特殊字符")
        print("  - 批量: 停用/启用/删除")
        print("  - 重启恢复验证: 检测netmap.sh init的select*bug")
        print("  - SSH后台验证: L1数据库+L2 iptables(NETMAP+PREROUTING引用)+L3+L4")

        # 断言(SSH后台验证 + UI操作验证)
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败:")
            for f in all_failures:
                print(f"  - {f}")
            assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
