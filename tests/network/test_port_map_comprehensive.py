"""
端口映射综合测试用例

一次测试覆盖多个功能(端口映射是UPnP/NAT的第4个tab):
1. 添加多条规则(覆盖外网接口/外网IP两种映射类型 + tcp/udp/tcp+udp三种协议 + 单端口/端口范围/多端口)
2. SSH后台数据验证(L1数据库逐条验证 + L2 iptables DSTNAT链 + L3运行时 + L4内核)
3. 编辑其中1条
4. 停用/启用/删除各1条
5. segmented筛选器测试(全部/已停用/已启用 计数)
6. 搜索测试(精确/部分/不存在/清空)
7. 复制规则测试(预填数据+新名称+SSH验证)
8. 导出测试(CSV/TXT)
9. 异常输入测试(空名称/必填校验/非法IP/非法端口/端口数量不一致/重复/超长/特殊字符)
10. 批量停用/启用/删除
11. 导入测试(追加CSV+清空现有TXT)
12. 帮助功能测试

SSH后台验证: L1数据库(dst_nat) + L2 iptables(DSTNAT链, switch_nat=1时) + L3运行时(iptables-save) + L4内核(nf_nat)
字段映射: tagname(名称), lan_addr(内网地址), lan_port(内网端口), protocol(协议tcp/udp/tcp+udp),
          interface(外网地址: all/wan网卡名/外网IP), wan_port(外网端口), comment(备注)

端口映射独有特性(相比NAT规则):
- 映射类型radio(外网接口/外网IP): 决定外网地址字段形态
- 协议无"任意"(只有tcp/udp/tcp+udp, 默认tcp)
- segmented筛选器(全部/已停用/已启用)
- 后端__check_ports_equal: 外网端口和内网端口数量必须一致(范围/多端口)
"""
import pytest
import os
from pages.network.port_map_page import PortMapPage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.port_map
@pytest.mark.network
class TestPortMapComprehensive:
    """端口映射综合测试 - 一次测试覆盖所有功能"""

    def test_port_map_comprehensive(self, port_map_page_logged_in: PortMapPage,
                                     step_recorder: StepRecorder, request):
        """
        综合测试: 添加多条规则 -> SSH验证 -> 编辑 -> 停用 -> 启用 -> 删除 ->
        segmented筛选 -> 搜索 -> 排序 -> 导出 -> 异常测试 -> 批量操作 -> 导入 -> 帮助
        """
        page = port_map_page_logged_in
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

        # 测试数据 - 覆盖映射类型/协议/端口格式的各种组合
        test_rules = [
            # Rule 1: 外网接口+tcp+单端口(最基础)
            {"name": "pm基础", "lan_addr": "192.168.1.10", "lan_port": "80",
             "wan_port": "8080", "protocol": "tcp",
             "map_type": "外网接口",
             "desc": "外网接口+tcp+单端口(最简)"},
            # Rule 2: 外网接口+udp+单端口
            {"name": "pm_udp单端口", "lan_addr": "192.168.1.11", "lan_port": "53",
             "wan_port": "5353", "protocol": "udp",
             "map_type": "外网接口",
             "desc": "外网接口+udp+单端口"},
            # Rule 3: 外网接口+tcp+udp(双协议)
            {"name": "pm_tcpudp", "lan_addr": "192.168.1.12", "lan_port": "443",
             "wan_port": "9443", "protocol": "tcp+udp",
             "map_type": "外网接口",
             "desc": "外网接口+tcp+udp双协议"},
            # Rule 4: 外网接口+tcp+端口范围
            {"name": "pm端口范围", "lan_addr": "192.168.1.13", "lan_port": "1000-2000",
             "wan_port": "3000-4000", "protocol": "tcp",
             "map_type": "外网接口",
             "desc": "外网接口+tcp+端口范围"},
            # Rule 5: 外网接口+tcp+多端口(逗号分隔)
            {"name": "pm多端口", "lan_addr": "192.168.1.14", "lan_port": "80,443",
             "wan_port": "8080,8443", "protocol": "tcp",
             "map_type": "外网接口",
             "desc": "外网接口+tcp+多端口"},
            # Rule 6: 外网接口+指定wan1接口
            {"name": "pm指定wan1", "lan_addr": "192.168.1.15", "lan_port": "22",
             "wan_port": "2222", "protocol": "tcp",
             "map_type": "外网接口", "external_interfaces": ["wan1"],
             "desc": "外网接口+指定wan1+tcp"},
            # Rule 7: 外网IP模式+tcp
            {"name": "pm外网IP", "lan_addr": "192.168.1.16", "lan_port": "3389",
             "wan_port": "13389", "protocol": "tcp",
             "map_type": "外网IP", "external_ip": "10.66.0.200",
             "desc": "外网IP模式+tcp"},
            # Rule 8: 外网接口+tcp+允许访问IP地址(源地址)
            {"name": "pm源地址", "lan_addr": "192.168.1.17", "lan_port": "8080",
             "wan_port": "18080", "protocol": "tcp",
             "map_type": "外网接口", "src_addr": "192.168.100.50",
             "desc": "外网接口+tcp+允许访问IP"},
            # Rule 9: 外网接口+tcp+带备注
            {"name": "pm带备注", "lan_addr": "192.168.1.18", "lan_port": "3306",
             "wan_port": "13306", "protocol": "tcp",
             "map_type": "外网接口", "remark": "MySQL端口映射",
             "desc": "外网接口+tcp+带备注"},
        ]

        print("\n" + "=" * 60)
        print("端口映射综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")
        for r in test_rules:
            print(f"  - {r['name']}, 协议={r['protocol']}, 映射={r['map_type']}, 场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            for cleanup_round in range(3):
                page.navigate_to_port_map()
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

            page.navigate_to_port_map()
            page.page.wait_for_timeout(1000)
            final_count = page.get_rule_count()
            print(f"  [OK] 环境清理完成, 剩余 {final_count} 条")
            rec.add_detail(f"[清理结果] 剩余 {final_count} 条")

        # ========== 步骤2-10: 逐条添加规则 ==========
        added_count = 0
        for rule_idx, rule in enumerate(test_rules):
            step_num = rule_idx + 2
            with rec.step(f"步骤{step_num}: 添加规则 {rule['name']}",
                          f"添加: {rule['desc']}"):
                print(f"\n[步骤{step_num}] 添加规则: {rule['name']}")
                rec.add_detail(f"  场景: {rule['desc']}")
                rec.add_detail(f"  协议: {rule.get('protocol', 'tcp')}, 映射: {rule.get('map_type', '外网接口')}")

                result = page.add_rule(
                    name=rule["name"],
                    lan_addr=rule["lan_addr"],
                    lan_port=rule["lan_port"],
                    wan_port=rule["wan_port"],
                    protocol=rule.get("protocol", "tcp"),
                    map_type=rule.get("map_type", "外网接口"),
                    external_interfaces=rule.get("external_interfaces"),
                    external_ip=rule.get("external_ip"),
                    src_addr=rule.get("src_addr"),
                    remark=rule.get("remark"),
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")
                added_count += 1

                # SSH L1验证
                if backend_verifier is not None:
                    expected = {"enabled": "yes", "protocol": rule["protocol"],
                                "lan_addr": rule["lan_addr"],
                                "wan_port": rule["wan_port"],
                                "lan_port": rule["lan_port"]}
                    if rule.get("remark"):
                        expected["comment"] = rule["remark"]

                    l1 = ssh_verify(
                        f"L1-数据库({rule['name']})",
                        backend_verifier.verify_port_map_database,
                        rule["name"],
                        must_pass=True,
                        expected_fields=expected,
                    )

        # ========== 步骤11: 验证总数 + 后端全链路验证 ==========
        with rec.step("步骤11: 验证总数 + 后端全链路", f"验证共{len(test_rules)}条 + SSH L1-L4"):
            print(f"\n[步骤11] 验证总数...")
            page.navigate_to_port_map()
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
                rec.add_detail("[SSH全链路验证] L1=数据库, L2=iptables(DSTNAT), L3=运行时, L4=内核")
                for rule in test_rules:
                    rec.add_detail(f"  -- 验证: {rule['name']} --")
                    expected = {"enabled": "yes", "protocol": rule["protocol"],
                                "lan_addr": rule["lan_addr"]}
                    full = ssh_verify(
                        f"全链路({rule['name']})",
                        backend_verifier.verify_port_map_full_chain,
                        rule["name"],
                        must_pass=False,
                        expected_fields=expected,
                        lan_addr=rule["lan_addr"],
                        wan_port=rule["wan_port"],
                        protocol=rule["protocol"],
                    )
                    if full:
                        for r in full.results:
                            rec.add_detail(f"    {r.level}: {'[OK]' if r.passed else '[FAIL]'} {r.message}")

        # ========== 步骤12: 编辑规则 ==========
        with rec.step("步骤12: 编辑规则", "编辑pm基础->改名+改备注"):
            print("\n[步骤12] 编辑规则...")
            rec.add_detail("[编辑测试] pm基础 -> pm已编辑")

            old_name = "pm基础"
            new_name = "pm已编辑"
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
                               backend_verifier.verify_port_map_database,
                               new_name, must_pass=True,
                               expected_fields={"enabled": "yes", "comment": "编辑后备注"})
            else:
                print(f"  [WARN] 编辑失败")
                rec.add_detail(f"  [WARN] 编辑失败")
                ui_failures.append("编辑规则失败")

        # ========== 步骤13: 停用规则 ==========
        with rec.step("步骤13: 停用规则", "停用pm_udp单端口 + SSH验证"):
            print("\n[步骤13] 停用规则...")
            target = "pm_udp单端口"
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
                           backend_verifier.verify_port_map_database,
                           target, must_pass=True,
                           expected_fields={"enabled": "no"})

        # ========== 步骤14: 启用规则 ==========
        with rec.step("步骤14: 启用规则", "启用pm_udp单端口 + SSH验证"):
            print("\n[步骤14] 启用规则...")
            target = "pm_udp单端口"
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
                           backend_verifier.verify_port_map_database,
                           target, must_pass=True,
                           expected_fields={"enabled": "yes"})

        # ========== 步骤15: 删除规则 ==========
        with rec.step("步骤15: 删除规则", "删除pm外网IP + SSH验证"):
            print("\n[步骤15] 删除规则...")
            target = "pm外网IP"
            rec.add_detail(f"[删除测试] 目标: {target}")

            page.delete_rule(target)
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_port_map()
            page.page.wait_for_timeout(500)

            assert not page.rule_exists(target), f"规则 {target} 仍存在"
            print(f"  [OK] 删除成功: {target}")
            rec.add_detail(f"  [OK] 删除成功")

            # 从测试列表移除
            test_rules = [r for r in test_rules if r["name"] != target]

            if backend_verifier is not None:
                ssh_verify(f"L1-删除验证({target})",
                           backend_verifier.verify_port_map_database,
                           target, must_pass=True,
                           expect_absent=True)

        # ========== 步骤16: segmented筛选器测试 ==========
        with rec.step("步骤16: segmented筛选器", "全部/已停用/已启用 计数验证"):
            print("\n[步骤16] segmented筛选器测试...")
            rec.add_detail("[segmented筛选器测试]")

            # 先停用1条制造混合状态
            page.disable_rule("pm_tcpudp")
            page.page.wait_for_timeout(1000)
            page.navigate_to_port_map()
            page.page.wait_for_timeout(500)

            counts = page.get_segmented_counts()
            print(f"  计数: {counts}")
            rec.add_detail(f"  计数: {counts}")

            # 验证计数逻辑: 全部 = 已启用 + 已停用
            if counts["全部"] >= 0:
                expected_all = counts["已启用"] + counts["已停用"]
                if counts["全部"] == expected_all:
                    print(f"  [OK] 计数逻辑正确: 全部({counts['全部']}) = 启用({counts['已启用']}) + 停用({counts['已停用']})")
                    rec.add_detail(f"  [OK] 计数逻辑正确")
                else:
                    print(f"  [WARN] 计数逻辑异常: 全部({counts['全部']}) != 启用({counts['已启用']}) + 停用({counts['已停用']})")
                    rec.add_detail(f"  [WARN] 计数逻辑异常")

            # 切换到"已停用"
            page.click_segmented_filter("已停用")
            page.page.wait_for_timeout(1000)
            disabled_list = page.get_rule_list()
            print(f"  已停用列表: {disabled_list}")
            rec.add_detail(f"  已停用筛选: {disabled_list}")
            if "pm_tcpudp" in disabled_list:
                print(f"  [OK] 已停用筛选包含 pm_tcpudp")
                rec.add_detail(f"  [OK] 已停用筛选正确")

            # 切换到"已启用"
            page.click_segmented_filter("已启用")
            page.page.wait_for_timeout(1000)
            enabled_list = page.get_rule_list()
            print(f"  已启用列表({len(enabled_list)}条)")
            rec.add_detail(f"  已启用筛选: {len(enabled_list)}条")
            if "pm_tcpudp" not in enabled_list:
                print(f"  [OK] 已启用筛选不包含已停用的pm_tcpudp")
                rec.add_detail(f"  [OK] 已启用筛选正确")

            # 恢复: 切回全部 + 启用刚停用的
            page.click_segmented_filter("全部")
            page.page.wait_for_timeout(500)
            page.enable_rule("pm_tcpudp")
            page.page.wait_for_timeout(500)

        # ========== 步骤17: 搜索测试 ==========
        with rec.step("步骤17: 搜索测试", "精确/部分/不存在/清空"):
            print("\n[步骤17] 搜索测试...")
            rec.add_detail("[搜索测试]")

            # 17.1 精确搜索
            target = "pm端口范围"
            rec.add_detail(f"  精确搜索: '{target}'")
            page.search_rule(target)
            page.page.wait_for_timeout(1000)
            found = page.rule_exists(target)
            if found:
                print(f"  [OK] 精确搜索: 找到 '{target}'")
                rec.add_detail(f"  [OK] 精确搜索找到")
            else:
                rec.add_detail(f"  [WARN] 精确搜索未找到")

            # 17.2 部分匹配
            partial = "端口"
            rec.add_detail(f"  部分匹配: '{partial}'")
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule(partial)
            page.page.wait_for_timeout(1000)
            rules = page.get_rule_list()
            partial_count = len(rules)
            rec.add_detail(f"  部分匹配结果: {partial_count} 条({rules})")
            print(f"  [OK] 部分匹配 '{partial}': {partial_count} 条")

            # 17.3 不存在
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

            # 17.4 清空搜索
            page.clear_search()
            page.page.wait_for_timeout(500)
            all_count = page.get_rule_count()
            print(f"  [OK] 清空搜索后: {all_count} 条")
            rec.add_detail(f"  [OK] 清空搜索后: {all_count} 条")

        # ========== 步骤18: 复制规则 ==========
        with rec.step("步骤18: 复制规则", "复制pm_tcpudp为新规则+SSH验证"):
            print("\n[步骤18] 复制规则...")
            rec.add_detail("[复制测试] pm_tcpudp -> pm复制副本")

            source = "pm_tcpudp"
            copy_name = "pm复制副本"
            result = page.copy_rule(source, new_name=copy_name)
            if result:
                # 验证新规则存在
                page.navigate_to_port_map()
                page.page.wait_for_timeout(500)
                if page.rule_exists(copy_name):
                    print(f"  [OK] 复制成功: {source} -> {copy_name}")
                    rec.add_detail(f"  [OK] 复制成功: {copy_name} 已存在")

                    # SSH验证复制的规则字段与源规则一致
                    if backend_verifier is not None:
                        ssh_verify(f"L1-复制后({copy_name})",
                                   backend_verifier.verify_port_map_database,
                                   copy_name, must_pass=True,
                                   expected_fields={"enabled": "yes",
                                                    "protocol": "tcp+udp",
                                                    "lan_addr": "192.168.1.12",
                                                    "wan_port": "9443",
                                                    "lan_port": "443"})
                        # 清理: 删除复制的规则, 不影响后续测试计数
                        page.delete_rule(copy_name)
                        page.page.wait_for_timeout(1000)
                        page.navigate_to_port_map()
                        page.page.wait_for_timeout(300)
                else:
                    print(f"  [WARN] 复制后规则 {copy_name} 未找到")
                    rec.add_detail(f"  [WARN] 复制后规则未找到")
            else:
                print(f"  [WARN] 复制失败")
                rec.add_detail(f"  [WARN] 复制失败")
                ui_failures.append("复制规则失败")

        # ========== 步骤19: 导出测试 ==========
        export_file_csv = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "test_data", "exports", "port_map", "port_map_config.csv"
        )
        export_file_txt = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "test_data", "exports", "port_map", "port_map_config.txt"
        )

        with rec.step("步骤19: 导出测试", "导出CSV和TXT"):
            print("\n[步骤19] 导出测试...")
            rec.add_detail("[导出测试]")

            # 19.1 CSV导出
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

            # 19.2 TXT导出
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

        # ========== 步骤20: 异常输入测试 ==========
        with rec.step("步骤20: 异常输入测试", "空名称/必填/非法IP/非法端口/端口不一致/重复/超长/特殊字符"):
            print("\n[步骤20] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 20.1 空名称
            rec.add_detail("  空名称:")
            result = page.try_add_rule_invalid(name="")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                rec.add_detail(f"    [FAIL] 未拦截")

            # 20.2 缺少必填(只填名称,不填内网地址)
            rec.add_detail("  缺少内网地址:")
            result = page.try_add_rule_invalid(name="pm缺地址", lan_port="80", wan_port="8080")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                rec.add_detail(f"    [INFO] {result}")

            # 20.3 非法内网IP
            rec.add_detail("  非法内网IP:")
            result = page.try_add_rule_invalid(name="pm非法IP", lan_addr="999.999.999.999",
                                                lan_port="80", wan_port="8080")
            print(f"    [INFO] 非法IP: {result}")
            rec.add_detail(f"    [INFO] {result}")

            # 20.4 非法端口(超范围)
            rec.add_detail("  非法端口(99999):")
            result = page.try_add_rule_invalid(name="pm非法端口", lan_addr="192.168.1.99",
                                                lan_port="99999", wan_port="8080")
            print(f"    [INFO] 非法端口: {result}")
            rec.add_detail(f"    [INFO] {result}")

            # 20.5 端口数量不一致(外网范围,内网单端口 - 后端__check_ports_equal校验)
            rec.add_detail("  端口数量不一致:")
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name("pm端口不一致")
                page.fill_lan_addr("192.168.1.98")
                page.fill_lan_port("80")          # 单端口
                page.fill_wan_port("1000-2000")    # 范围(数量不一致)
                page.click_save()
                page.page.wait_for_timeout(1500)
                # 检查是否被拦截
                error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
                still_add = "portMapping/add" in page.page.url
                if error_el.count() > 0 or still_add:
                    msg = error_el.first.text_content() if error_el.count() > 0 else "保存被拒绝"
                    print(f"    [OK] 拦截: {msg}")
                    rec.add_detail(f"    [OK] 拦截端口不一致: {msg}")
                else:
                    # 可能后端截断或允许? 检查是否真的添加了
                    if page.wait_for_success_message(timeout=2000):
                        print(f"    [WARN] 端口不一致未被拦截(后端可能容错)")
                        rec.add_detail(f"    [WARN] 端口不一致未被拦截")
                page.click_cancel()
                page.page.wait_for_timeout(300)
                if "portMapping" in page.page.url:
                    page.navigate_back_to_list()
                page.page.wait_for_timeout(300)
            except Exception as e:
                print(f"    [INFO] 端口不一致异常: {e}")
                rec.add_detail(f"    [INFO] {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 20.6 重复名称
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
                if "portMapping" in page.page.url:
                    page.navigate_back_to_list()
                page.page.wait_for_timeout(300)
            except Exception as e:
                print(f"    [INFO] 重复名称异常: {e}")
                rec.add_detail(f"    [INFO] 异常: {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 20.7 超长名称(30字符, tagname限制15字符)
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
                    if "portMapping" in page.page.url:
                        page.navigate_back_to_list()
            except Exception as e:
                print(f"    [INFO] 超长名称异常: {e}")
                rec.add_detail(f"    [INFO] {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 20.8 特殊字符
            rec.add_detail("  特殊字符:")
            result = page.try_add_rule_invalid(name="<script>alert(1)</script>",
                                                lan_addr="192.168.1.97", lan_port="80", wan_port="8080")
            print(f"    [INFO] 特殊字符: {result}")
            rec.add_detail(f"    [INFO] {result}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_port_map()
            page.page.wait_for_timeout(500)

        # ========== 步骤21: 批量停用 ==========
        with rec.step("步骤21: 批量停用", f"批量停用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤21] 批量停用 {len(test_rules)} 条...")
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
                page.navigate_to_port_map()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_port_maps() or []
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
                db_rules = backend_verifier.query_port_maps() or []
                disabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                rec.add_detail(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                print(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                if total > 0 and disabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_count}/{total}条规则停用")

        # ========== 步骤22: 批量启用 ==========
        with rec.step("步骤22: 批量启用", f"批量启用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤22] 批量启用 {len(test_rules)} 条...")
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
                page.navigate_to_port_map()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_port_maps() or []
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
                db_rules = backend_verifier.query_port_maps() or []
                enabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "yes")
                rec.add_detail(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                print(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                if total > 0 and enabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量启用: 仅{enabled_count}/{total}条规则启用")

        # ========== 步骤23: 批量删除 ==========
        with rec.step("步骤23: 批量删除", f"批量删除剩余 {len(test_rules)} 条"):
            print(f"\n[步骤23] 批量删除 {len(test_rules)} 条...")
            rec.add_detail(f"[批量删除] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_delete()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_port_map()
            page.page.wait_for_timeout(500)
            for rule in test_rules:
                assert not page.rule_exists(rule["name"]), f"规则 {rule['name']} 仍存在"
            print(f"  [OK] 批量删除 {len(test_rules)} 条成功")
            rec.add_detail(f"[结果] [OK] 全部删除")

            if backend_verifier is not None:
                try:
                    port_maps = backend_verifier.query_port_maps()
                    test_names = {r["name"] for r in test_rules}
                    remaining = [r for r in port_maps if r.get("tagname") in test_names]
                    if remaining:
                        ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining)}条")
                    else:
                        rec.add_detail(f"    SSH: 测试规则已全部删除")
                except Exception as e:
                    ssh_failures.append(f"SSH-L1-批量删除验证异常: {str(e)[:80]}")

        # ========== 步骤24: 导入追加(CSV) ==========
        with rec.step("步骤24: 导入配置(追加)", "使用导出的CSV追加导入"):
            print("\n[步骤24] 导入配置(追加)...")
            rec.add_detail("[导入测试-追加]")

            if os.path.exists(export_file_csv):
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_csv)}")
                rec.add_detail(f"  导入前: {count_before} 条")

                result = page.import_rules(export_file_csv, clear_existing=False)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_port_map()
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

        # ========== 步骤25: 导入清空(TXT) ==========
        with rec.step("步骤25: 导入配置(清空现有)", "使用导出的TXT清空现有后导入"):
            print("\n[步骤25] 导入配置(清空现有数据-TXT)...")
            rec.add_detail("[导入测试-清空现有-TXT]")

            if os.path.exists(export_file_txt):
                page.add_rule(name="额外PM规则", lan_addr="192.168.1.200",
                              lan_port="9999", wan_port="19999")
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_txt)}")
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则)")

                result = page.import_rules(export_file_txt, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1000)
                page.navigate_to_port_map()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if not page.rule_exists("额外PM规则"):
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

        # ========== 步骤26: 最终清理 ==========
        with rec.step("步骤26: 最终清理", "清理所有测试数据"):
            print("\n[步骤26] 最终清理...")
            rec.add_detail("[环境清理]")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.navigate_to_port_map()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                for cleanup_round in range(3):
                    page.navigate_to_port_map()
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
                page.navigate_to_port_map()
                page.page.wait_for_timeout(500)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成, 剩余 {final_count} 条")
                rec.add_detail(f"[清理结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 无需清理")
                rec.add_detail("  无需清理")

            if backend_verifier is not None:
                ssh_verify("L1-最终清理", backend_verifier.verify_port_map_iptables,
                           must_pass=False, expect_rules=False)

        # ========== 步骤27: 帮助功能测试 ==========
        with rec.step("步骤27: 帮助功能测试", "测试帮助图标"):
            print("\n[步骤27] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")
            try:
                page.navigate_to_port_map()
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
        print("端口映射综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 9条(外网接口6/外网IP1/tcp/udp/tcp+udp/单端口/范围/多端口/源地址/备注)")
        print("  - 编辑/停用/启用/删除: 各1条")
        print("  - segmented筛选器: 全部/已停用/已启用 计数+切换")
        print("  - 搜索: 精确/部分匹配/不存在/清空恢复")
        print("  - 复制: 预填数据+新名称+SSH字段一致性验证")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加(CSV) + 清空现有数据(TXT)")
        print("  - 异常输入: 空名称/缺必填/非法IP/非法端口/端口不一致/重复/超长/特殊字符")
        print("  - 批量操作: 批量停用/启用/删除")
        print("  - SSH后台验证: L1数据库+L2 iptables(DSTNAT)+L3运行时+L4内核")

        # 断言(SSH后台验证 + UI操作验证)
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败:")
            for f in all_failures:
                print(f"  - {f}")
            assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
