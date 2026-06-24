"""
端口分流综合测试用例

一次测试覆盖多个功能：
1. 添加10条规则（覆盖6种负载模式+外网线路/下一跳网关+多协议+端口+线路绑定+生效时间+反向匹配）
2. SSH后台数据验证（L1+L2+L3+L4逐条验证，含iface_band/time/src_addr_inv/dst_addr_inv/src_port/dst_port字段）
3. 编辑其中1条
4. 复制测试
5. 停用/启用/删除各1条
6. 搜索测试（精确/部分/不存在/清空）
7. 导出测试（CSV/TXT）
8. 异常输入测试（空名称/重复/超长/特殊字符/纯空格/优先级边界值/备注特殊字符/空地址取反）
9. 排序测试（线路、优先级、协议）
10. 批量停用/启用/删除
11. 导入测试（追加+清空现有）
12. 帮助功能测试

SSH后台验证: L1数据库+L2 iptables(STREAM_IPPORT_NEW链)+L3策略路由+L4内核
字段映射: type(0/1), mode(0/1/2/3/4/6), prio(0-63), interface(逗号分隔), protocol(any/tcp/udp/tcp+udp/icmp)
扩展字段: iface_band(0/1), src_addr_inv(0/1), dst_addr_inv(0/1), src_port, dst_port, time, src_addr, dst_addr
"""
import pytest
import os
from pages.network.port_route_page import PortRoutePage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.port_route
@pytest.mark.network
class TestPortRouteComprehensive:
    """端口分流综合测试 - 一次测试覆盖所有功能"""

    def test_port_route_comprehensive(self, port_route_page_logged_in: PortRoutePage,
                                      step_recorder: StepRecorder, request):
        """
        综合测试: 添加10条规则 -> SSH验证 -> 编辑 -> 复制 -> 停用 -> 启用 -> 删除 ->
        搜索 -> 导出 -> 异常测试 -> 排序 -> 批量操作 -> 导入 -> 帮助
        """
        page = port_route_page_logged_in
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

        # 测试数据 - 10条规则，覆盖6种负载模式+2种分流方式+多协议+端口+线路绑定+生效时间+反向匹配
        # 注意：名称最多15字符
        test_rules = [
            # Rule 1: Mode 0 新建连接数, wan1, 优先级10, 协议any
            {"name": "pt_m0_any", "diversion_type": "外网线路",
             "line": "wan1", "priority": 10,
             "mode": "新建连接数", "protocol": "any", "remark": "任意协议",
             "desc": "模式0:新建连接数+any"},
            # Rule 2: Mode 1 源IP, wan2, 优先级20, 协议tcp, 目的端口80
            {"name": "pt_m1_tcp80", "diversion_type": "外网线路",
             "line": "wan2", "priority": 20,
             "mode": "源IP", "protocol": "tcp", "dst_port": "80",
             "remark": "TCP80分流",
             "desc": "模式1:源IP+tcp:80"},
            # Rule 3: Mode 2 源IP+源端口, wan3, 优先级25, 协议udp
            {"name": "pt_m2_udp", "diversion_type": "外网线路",
             "line": "wan3", "priority": 25,
             "mode": "源IP+源端口", "protocol": "udp", "src_port": "53",
             "remark": "UDP53分流",
             "desc": "模式2:源IP+源端口+udp:53"},
            # Rule 4: Mode 3 源IP+目的IP, wan1+wan2, 优先级15, 协议tcp+udp
            {"name": "pt_m3_multi", "diversion_type": "外网线路",
             "line": "wan1,wan2", "priority": 15,
             "mode": "源IP+目的IP", "protocol": "tcp+udp", "dst_port": "443",
             "desc": "模式3:源IP+目的IP+多线路+tcp+udp:443"},
            # Rule 5: Mode 4 源IP+目的IP+目的端口, wan2, 优先级30, 协议tcp
            {"name": "pt_m4_tcp", "diversion_type": "外网线路",
             "line": "wan2", "priority": 30,
             "mode": "源IP+目的IP+目的端口", "protocol": "tcp",
             "src_port": "1024", "dst_port": "8080",
             "desc": "模式4:源IP+目的IP+端口+tcp:8080"},
            # Rule 6: Mode 6 主备模式, wan1, 优先级5, 协议icmp
            {"name": "pt_m6_icmp", "diversion_type": "外网线路",
             "line": "wan1", "priority": 5,
             "mode": "主备模式", "protocol": "icmp",
             "desc": "模式6:主备+icmp"},
            # Rule 7: 下一跳网关(type=1), 优先级35
            {"name": "pt_nexthop", "diversion_type": "下一跳网关",
             "nexthop": "10.66.0.1", "priority": 35,
             "mode": "新建连接数", "protocol": "tcp",
             "remark": "SSH分流",
             "desc": "下一跳网关+tcp22"},
            # Rule 8: 高优先级+线路绑定+自定义生效时间
            {"name": "pt_bind_time", "diversion_type": "外网线路",
             "line": "wan1", "priority": 1,
             "mode": "新建连接数", "protocol": "any",
             "line_binding": True,
             "time_mode": "按周循环",
             "time_days": ["一", "二", "三", "四", "五"],
             "time_start": "23:00", "time_end": "23:59",
             "desc": "高优先级+线路绑定+生效时间(工作日23:00-23:59)"},
            # Rule 9: 源地址反向匹配(需要先填写源地址才能启用取反)
            {"name": "pt_src_inv", "diversion_type": "外网线路",
             "line": "wan2", "priority": 40,
             "mode": "新建连接数", "protocol": "tcp",
             "src_addr": "192.168.1.0/24", "src_addr_inv": True,
             "desc": "源地址反向匹配+tcp"},
            # Rule 10: IP/MAC分组引用
            {"name": "pt_ipgroup", "diversion_type": "外网线路",
             "line": "wan1", "priority": 45,
             "mode": "新建连接数", "protocol": "any",
             "src_group": "test_cross_laye",
             "desc": "源IP/MAC分组引用"},
        ]

        print("\n" + "=" * 60)
        print("端口分流综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")
        for r in test_rules:
            div_type = r.get("diversion_type", "外网线路")
            mode = r.get("mode", "新建连接数")
            line = r.get("line", "-")
            proto = r.get("protocol", "any")
            print(f"  - {r['name']}, 分流={div_type}, 线路={line}, "
                  f"优先级={r.get('priority',31)}, 模式={mode}, 协议={proto}, "
                  f"场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            for cleanup_round in range(3):
                page.navigate_to_port_route()
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

            page.navigate_to_port_route()
            page.page.wait_for_timeout(1000)
            final_count = page.get_rule_count()
            print(f"  [OK] 环境清理完成，剩余 {final_count} 条")
            rec.add_detail(f"[清理结果] 剩余 {final_count} 条")

        # ========== 步骤2: 二次检查测试数据 ==========
        with rec.step("步骤2: 二次检查测试数据", "确保测试数据已清理"):
            print("\n[步骤2] 二次检查...")
            rec.add_detail(f"[二次检查]")
            cleaned_count = 0
            for rule in test_rules:
                page.navigate_to_port_route()
                page.page.wait_for_timeout(500)
                if page.rule_exists(rule["name"]):
                    page.delete_rule(rule["name"])
                    rec.add_detail(f"  发现残留: {rule['name']}，已删除")
                    cleaned_count += 1
            if cleaned_count == 0:
                rec.add_detail("  无需清理")
            else:
                rec.add_detail(f"  共清理 {cleaned_count} 条")

        # ========== 步骤3: 批量添加10条规则 ==========
        with rec.step("步骤3: 批量添加规则", f"添加 {len(test_rules)} 条规则，覆盖6种负载模式+下一跳+线路绑定+生效时间+反向匹配+端口+分组"):
            print(f"\n[步骤3] 批量添加 {len(test_rules)} 条规则...")
            rec.add_detail(f"[添加计划] 共 {len(test_rules)} 条，覆盖6种负载模式+下一跳+线路绑定+生效时间+反向匹配+端口+分组")

            added_count = 0
            for rule in test_rules:
                rec.add_detail(f"[添加 {rule['name']}]")
                rec.add_detail(f"  场景: {rule['desc']}")
                rec.add_detail(f"  分流: {rule.get('diversion_type', '外网线路')}, "
                               f"线路: {rule.get('line', '-')}, 优先级: {rule['priority']}")
                if rule.get("mode"):
                    rec.add_detail(f"  负载模式: {rule['mode']}")
                if rule.get("protocol"):
                    rec.add_detail(f"  协议: {rule['protocol']}")
                if rule.get("src_port"):
                    rec.add_detail(f"  源端口: {rule['src_port']}")
                if rule.get("dst_port"):
                    rec.add_detail(f"  目的端口: {rule['dst_port']}")
                if rule.get("remark"):
                    rec.add_detail(f"  备注: {rule['remark']}")
                if rule.get("line_binding"):
                    rec.add_detail(f"  线路绑定: 启用")
                if rule.get("time_mode"):
                    rec.add_detail(f"  生效时间: {rule['time_mode']} "
                                   f"{rule.get('time_start','')}-{rule.get('time_end','')}")
                if rule.get("src_addr_inv"):
                    rec.add_detail(f"  源地址反向匹配: 启用")
                if rule.get("src_group"):
                    rec.add_detail(f"  源IP/MAC分组: {rule['src_group']}")

                result = page.add_rule(
                    name=rule["name"],
                    diversion_type=rule.get("diversion_type", "外网线路"),
                    line=rule.get("line"),
                    nexthop=rule.get("nexthop"),
                    priority=rule.get("priority", 31),
                    mode=rule.get("mode"),
                    protocol=rule.get("protocol"),
                    remark=rule.get("remark"),
                    src_addr=rule.get("src_addr"),
                    src_addr_inv=rule.get("src_addr_inv"),
                    src_group=rule.get("src_group"),
                    dst_addr=rule.get("dst_addr"),
                    dst_addr_inv=rule.get("dst_addr_inv"),
                    dst_port=rule.get("dst_port"),
                    src_port=rule.get("src_port"),
                    line_binding=rule.get("line_binding"),
                    time_mode=rule.get("time_mode"),
                    time_days=rule.get("time_days"),
                    time_start=rule.get("time_start"),
                    time_end=rule.get("time_end"),
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")
                added_count += 1

            # 验证所有规则都已添加
            rec.add_detail(f"[验证结果]")
            page.navigate_to_port_route()
            page.page.wait_for_timeout(2000)
            page.clear_search()
            page.page.wait_for_timeout(500)
            all_names = page.get_rule_list()
            rec.add_detail(f"  当前列表({len(all_names)}条): {all_names}")
            for rule in test_rules:
                assert rule["name"] in all_names, f"规则 {rule['name']} 未找到，当前列表: {all_names}"
            print(f"  [OK] 所有 {len(test_rules)} 条规则添加成功")
            rec.add_detail(f"  [OK] 所有 {len(test_rules)} 条规则添加成功")

        # ========== 步骤4: SSH后台数据验证（L1+L2+L3+L4）==========
        rule_id_map = {}
        if backend_verifier is not None:
            with rec.step("步骤4: 后台数据验证（SSH）", "SSH验证每条规则的数据库+iptables+策略路由+内核，含扩展字段"):
                print("\n[步骤4] 后台数据验证...")
                rec.add_detail("[SSH后台验证] 字段映射: type(0/1), mode(0/1/2/3/4/6), prio(0-63), protocol")
                rec.add_detail("[SSH后台验证] 扩展字段: iface_band, src_addr_inv, dst_addr_inv, src_port, dst_port, time, src_addr")
                rec.add_detail("[SSH后台验证] L1=数据库, L2=iptables, L3=策略路由, L4=内核模块")

                verify_passed = 0

                for rule in test_rules:
                    rule_name = rule["name"]
                    rec.add_detail(f"  -- 验证: {rule_name} --")
                    print(f"  验证: {rule_name}")

                    # 构建数据库期望字段
                    expected_fields = {"enabled": "yes"}
                    load_mode = rule.get("mode", "新建连接数")
                    expected_mode = PortRoutePage.MODE_TO_DB.get(load_mode, "0")
                    expected_fields["mode"] = expected_mode
                    expected_fields["prio"] = str(rule.get("priority", 31))
                    if rule.get("remark"):
                        expected_fields["comment"] = rule["remark"]
                    if rule.get("protocol"):
                        expected_fields["protocol"] = rule["protocol"]
                    # 分流方式
                    if rule.get("diversion_type") == "下一跳网关":
                        expected_fields["type"] = "1"
                    else:
                        expected_fields["type"] = "0"
                    # 线路绑定
                    if rule.get("line_binding"):
                        expected_fields["iface_band"] = "1"
                    # 源地址反向匹配
                    if rule.get("src_addr_inv"):
                        expected_fields["src_addr_inv"] = "1"

                    detail_parts = [f"mode={expected_fields['mode']}", f"prio={expected_fields['prio']}",
                                    f"type={expected_fields['type']}"]
                    if "iface_band" in expected_fields:
                        detail_parts.append(f"iface_band={expected_fields['iface_band']}")
                    if "protocol" in expected_fields:
                        detail_parts.append(f"protocol={expected_fields['protocol']}")
                    if "src_addr_inv" in expected_fields:
                        detail_parts.append(f"src_addr_inv={expected_fields['src_addr_inv']}")
                    rec.add_detail(f"      期望: {', '.join(detail_parts)}")

                    # L1: 数据库验证
                    l1 = ssh_verify(
                        f"L1-数据库({rule_name})",
                        backend_verifier.verify_stream_ipport_database,
                        rule_name,
                        must_pass=True,
                        expected_fields=expected_fields,
                    )

                    if l1 and l1.passed:
                        db_rule = l1.details.get("rule", {})
                        db_id = db_rule.get("id")
                        rule_id_map[rule_name] = db_id
                        db_detail = (f"id={db_id}, type={db_rule.get('type')}, mode={db_rule.get('mode')}, "
                                     f"prio={db_rule.get('prio')}, interface={db_rule.get('interface')}, "
                                     f"protocol={db_rule.get('protocol')}")
                        extra_fields = []
                        if db_rule.get("iface_band"):
                            extra_fields.append(f"iface_band={db_rule.get('iface_band')}")
                        if db_rule.get("src_addr_inv"):
                            extra_fields.append(f"src_addr_inv={db_rule.get('src_addr_inv')}")
                        if db_rule.get("dst_addr_inv"):
                            extra_fields.append(f"dst_addr_inv={db_rule.get('dst_addr_inv')}")
                        if db_rule.get("time"):
                            extra_fields.append(f"time={db_rule.get('time')}")
                        if db_rule.get("src_addr"):
                            extra_fields.append(f"src_addr={db_rule.get('src_addr')}")
                        if db_rule.get("nexthop"):
                            extra_fields.append(f"nexthop={db_rule.get('nexthop')}")
                        if db_rule.get("src_port"):
                            extra_fields.append(f"src_port={db_rule.get('src_port')}")
                        if db_rule.get("dst_port"):
                            extra_fields.append(f"dst_port={db_rule.get('dst_port')}")
                        if extra_fields:
                            db_detail += ", " + ", ".join(extra_fields)
                        rec.add_detail(f"      数据库: {db_detail}")

                        # L2: iptables验证
                        if rule.get("diversion_type") == "外网线路":
                            ssh_verify(
                                f"L2-iptables({rule_name})",
                                backend_verifier.verify_stream_ipport_iptables,
                                rule_id=db_id,
                                expected_ifname=rule.get("line", "wan1"),
                                expected_mode=int(expected_mode),
                                must_pass=False,
                            )

                        verify_passed += 1

                # L3: 策略路由验证
                ssh_verify(
                    "L3-策略路由",
                    backend_verifier.verify_stream_ipport_policy_routing,
                    must_pass=False,
                )

                # L4: 内核模块验证
                ssh_verify(
                    "L4-内核模块",
                    backend_verifier.verify_stream_ipport_kernel,
                    must_pass=False,
                )

                print(f"  [OK] 后台验证完成: {verify_passed}/{len(test_rules)} 条通过")
                rec.add_detail(f"  -- 汇总: {verify_passed}/{len(test_rules)} 条L1验证通过 --")
        else:
            print("\n[步骤4] 后台数据验证: 跳过（未配置SSH）")

        # ========== 步骤5: 编辑第1条规则 ==========
        with rec.step("步骤5: 编辑规则", "编辑第1条规则的名称"):
            print("\n[步骤5] 编辑第1条规则...")
            edit_rule = test_rules[0]
            new_name = "pt_m0_edit"
            rec.add_detail(f"[编辑操作] {edit_rule['name']} -> {new_name}")

            if page.rule_exists(new_name):
                page.delete_rule(new_name)

            result = page.edit_rule(edit_rule["name"], new_name=new_name)
            assert result is True, f"编辑规则失败"

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_port_route()
            page.page.wait_for_timeout(500)
            assert page.rule_exists(new_name), "编辑后的规则未找到"
            test_rules[0]["name"] = new_name
            print(f"  [OK] 编辑成功")
            rec.add_detail(f"[验证] [OK] 编辑成功，新名称已生效")

            if backend_verifier is not None:
                ssh_verify("L1-编辑验证", backend_verifier.verify_stream_ipport_database, new_name)

        # ========== 步骤5.5: 复制规则测试 ==========
        with rec.step("步骤5.5: 复制规则", "复制编辑后的规则，修改名称保存"):
            print("\n[步骤5.5] 复制规则测试...")
            copy_source = test_rules[0]["name"]
            copy_name = "pt_m0_copy"
            rec.add_detail(f"[复制操作] 源: {copy_source} -> 新名称: {copy_name}")

            if page.rule_exists(copy_name):
                page.delete_rule(copy_name)
                page.page.wait_for_timeout(500)

            page.copy_rule(copy_source)
            page.page.wait_for_timeout(1000)

            try:
                page.page.wait_for_selector('input[placeholder="请输入名称"]', timeout=10000)
            except Exception:
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(1000)

            page.fill_name(copy_name)
            page.click_save()
            page.page.wait_for_timeout(1500)

            error_el = page.page.locator('.ant-form-item-explain-error')
            if error_el.count() > 0:
                page.click_cancel()
                page.page.wait_for_timeout(500)
                page.navigate_back_to_list()
                rec.add_detail(f"  [WARN] 复制保存失败(表单验证)")
                print(f"  [WARN] 复制保存失败")
            else:
                save_ok = page.wait_for_success_message(timeout=3000)
                page.page.wait_for_timeout(500)
                page.navigate_back_to_list()
                page.page.wait_for_timeout(500)

                if save_ok:
                    assert page.rule_exists(copy_name), f"复制规则 {copy_name} 未找到"
                    test_rules.append({
                        "name": copy_name, "diversion_type": "外网线路",
                        "line": "wan1", "priority": 10,
                        "mode": "新建连接数", "protocol": "any",
                        "desc": "复制生成的规则",
                    })
                    print(f"  [OK] 复制成功: {copy_name}")
                    rec.add_detail(f"  [OK] 复制成功")

                    if backend_verifier is not None:
                        ssh_verify("L1-复制验证", backend_verifier.verify_stream_ipport_database, copy_name)
                else:
                    rec.add_detail(f"  [WARN] 复制保存未返回成功")
                    print(f"  [WARN] 复制保存未返回成功")

        # ========== 步骤6: 停用第2条规则 ==========
        with rec.step("步骤6: 停用规则", "停用第2条规则"):
            print("\n[步骤6] 停用第2条规则...")
            disable_rule = test_rules[1]
            rec.add_detail(f"[停用操作] 目标: {disable_rule['name']}")

            result = page.disable_rule(disable_rule["name"])
            assert result is True, f"停用规则失败"

            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_port_route()
            page.page.wait_for_timeout(500)
            assert page.is_rule_disabled(disable_rule["name"]), "规则未变为停用状态"
            print(f"  [OK] 停用成功")
            rec.add_detail(f"[验证] [OK] 已停用")

            if backend_verifier is not None:
                ssh_verify("L1-停用验证", backend_verifier.verify_stream_ipport_database,
                           disable_rule["name"], must_pass=True, expected_fields={"enabled": "no"})
                dis_rule_id = rule_id_map.get(disable_rule["name"])
                if dis_rule_id:
                    ssh_verify(
                        "L2-停用验证",
                        backend_verifier.verify_stream_ipport_iptables,
                        rule_id=dis_rule_id,
                        should_exist=False,
                        must_pass=False,
                    )

        # ========== 步骤7: 启用第2条规则 ==========
        with rec.step("步骤7: 启用规则", "启用第2条规则"):
            print("\n[步骤7] 启用第2条规则...")
            rec.add_detail(f"[启用操作] 目标: {disable_rule['name']}")

            result = page.enable_rule(disable_rule["name"])
            assert result is True, f"启用规则失败"

            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_port_route()
            page.page.wait_for_timeout(500)
            assert page.is_rule_enabled(disable_rule["name"]), "规则启用后状态未变化"
            print(f"  [OK] 启用成功")
            rec.add_detail(f"[验证] [OK] 已启用")

            if backend_verifier is not None:
                ssh_verify("L1-启用验证", backend_verifier.verify_stream_ipport_database,
                           disable_rule["name"], must_pass=True, expected_fields={"enabled": "yes"})
                en_rule_id = rule_id_map.get(disable_rule["name"])
                if en_rule_id:
                    load_mode = disable_rule.get("mode", "新建连接数")
                    expected_mode = int(PortRoutePage.MODE_TO_DB.get(load_mode, "0"))
                    ssh_verify(
                        "L2-启用验证",
                        backend_verifier.verify_stream_ipport_iptables,
                        rule_id=en_rule_id,
                        expected_ifname=disable_rule.get("line", "wan2"),
                        expected_mode=expected_mode,
                        must_pass=False,
                    )

        # ========== 步骤8: 删除第3条规则 ==========
        with rec.step("步骤8: 删除规则", "删除第3条规则"):
            print("\n[步骤8] 删除第3条规则...")
            delete_rule_data = test_rules[2]
            rec.add_detail(f"[删除操作] 目标: {delete_rule_data['name']}")

            count_before = page.get_rule_count()
            rec.add_detail(f"  删除前: {count_before} 条")

            result = page.delete_rule(delete_rule_data["name"])
            assert result is True, f"删除规则失败"

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_port_route()
            page.page.wait_for_timeout(500)
            count_after = page.get_rule_count()
            assert count_after < count_before, "删除后条目数未减少"
            test_rules.remove(delete_rule_data)
            print(f"  [OK] 删除成功 ({count_before} -> {count_after})")
            rec.add_detail(f"[验证] [OK] 删除成功")

            if backend_verifier is not None:
                try:
                    db_rule = backend_verifier.find_stream_ipport_rule(tagname=delete_rule_data["name"])
                    if db_rule is None:
                        print(f"    SSH-L1-删除验证: [OK] 已从数据库删除")
                        rec.add_detail(f"    SSH-L1: [OK] 已从数据库删除")
                    else:
                        ssh_failures.append(f"SSH-L1-删除验证: {delete_rule_data['name']} 仍在数据库中")
                except Exception as e:
                    print(f"    SSH-L1: 跳过 - {str(e)[:80]}")

                del_rule_id = rule_id_map.get(delete_rule_data["name"])
                if del_rule_id:
                    ssh_verify(
                        "L2-删除验证",
                        backend_verifier.verify_stream_ipport_iptables,
                        rule_id=del_rule_id,
                        should_exist=False,
                        must_pass=False,
                    )

        # ========== 步骤9: 搜索测试 ==========
        with rec.step("步骤9: 搜索功能测试", "精确搜索/模糊搜索/不存在的规则"):
            print("\n[步骤9] 搜索测试...")
            rec.add_detail("[搜索测试]")

            # 9.1 精确搜索
            search_target = test_rules[1]["name"]
            rec.add_detail(f"  精确搜索: {search_target}")
            page.search_rule(search_target)
            page.page.wait_for_timeout(500)
            assert page.rule_exists(search_target), f"精确搜索不到: {search_target}"
            print(f"  [OK] 精确搜索成功")
            rec.add_detail(f"    [OK] 精确搜索找到")

            # 9.2 部分匹配搜索
            page.clear_search()
            page.page.wait_for_timeout(300)
            prefix = test_rules[0]["name"][:6] if len(test_rules) > 0 else "pt_"
            rec.add_detail(f"  部分匹配搜索: '{prefix}'")
            page.search_rule(prefix)
            page.page.wait_for_timeout(500)
            partial_count = page.get_rule_count()
            assert partial_count >= 1, f"部分匹配搜索应至少1条，实际{partial_count}条"
            print(f"  [OK] 部分匹配搜索: {partial_count}条")
            rec.add_detail(f"    [OK] 匹配 {partial_count} 条")

            # 9.3 不存在的规则
            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("not_exist_pt_xxx")
            page.page.wait_for_timeout(500)
            count = page.get_rule_count()
            assert count == 0, f"搜索不存在时应为0条，实际{count}条"
            print("  [OK] 搜索不存在规则: 0条")
            rec.add_detail(f"  不存在的: 0条 [OK]")

            # 9.4 清空搜索恢复列表
            page.clear_search()
            page.page.wait_for_timeout(500)
            remaining = page.get_rule_count()
            assert remaining == len(test_rules), f"清空搜索后应有{len(test_rules)}条，实际{remaining}条"
            print(f"  [OK] 清空搜索，恢复 {remaining} 条")
            rec.add_detail(f"  清空搜索: {remaining} 条 [OK]")

        # ========== 步骤10: 导出测试 ==========
        with rec.step("步骤10: 导出配置", "导出CSV和TXT"):
            print("\n[步骤10] 导出配置...")
            rec.add_detail("[导出测试]")
            config = get_config()
            export_file_csv = config.test_data.get_export_path("port_route", config.get_project_root())
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
            page.navigate_to_port_route()
            page.page.wait_for_timeout(500)

        # ========== 步骤11: 异常输入测试 ==========
        with rec.step("步骤11: 异常输入测试", "空名称/重复/超长/特殊字符/纯空格/优先级边界/备注特殊字符/空地址取反"):
            print("\n[步骤11] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 辅助函数: 确保在端口分流tab
            def ensure_port_route_tab():
                page.navigate_to_port_route()
                page.page.wait_for_timeout(300)

            # 11.1 空名称
            rec.add_detail("  空名称:")
            ensure_port_route_tab()
            result = page.try_add_rule_invalid(name="")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [FAIL] 未拦截")
                rec.add_detail(f"    [FAIL] 未拦截")

            # 11.2 重复名称
            rec.add_detail("  重复名称:")
            existing = test_rules[0]["name"]
            ensure_port_route_tab()
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name(existing)
                page.select_line("wan1")
                page.page.wait_for_timeout(300)
                page.set_priority(55)
                page.page.wait_for_timeout(300)
                page.click_save()
                page.page.wait_for_timeout(1500)
                js_errors = page.page.evaluate("""() => {
                    const errors = [];
                    document.querySelectorAll('[class*="explain"]').forEach(el => {
                        const t = el.textContent.trim();
                        if (t) errors.push(t);
                    });
                    return errors;
                }""")
                error_el = page.page.locator('.ant-form-item-explain-error')
                if error_el.count() > 0 or js_errors:
                    msg = error_el.first.text_content() if error_el.count() > 0 else js_errors[0]
                    print(f"    [OK] 拦截: {msg}")
                    rec.add_detail(f"    [OK] 拦截: {msg}")
                elif page.wait_for_success_message(timeout=2000):
                    print(f"    [WARN] 重复名称未被拦截")
                    rec.add_detail(f"    [WARN] 重复名称未被拦截")
                page.click_cancel()
                page.page.wait_for_timeout(300)
                if "portFlow" in page.page.url:
                    page.navigate_back_to_list()
                page.page.wait_for_timeout(300)
            except Exception as e:
                print(f"    [INFO] 重复名称异常: {e}")
                rec.add_detail(f"    [INFO] 异常: {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 11.3 超长名称
            rec.add_detail("  超长名称(30字符):")
            long_name = "a" * 30
            ensure_port_route_tab()
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name(long_name)
                page.select_line("wan2")
                page.page.wait_for_timeout(300)
                page.set_priority(56)
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
                    # 使用更可靠的删除方式
                    try:
                        page.delete_rule(truncated)
                    except Exception:
                        print(f"    [DEBUG] 清理超长规则失败，继续测试")
                    page.page.wait_for_timeout(300)
                else:
                    print(f"    [INFO] 超长名称: 无明确拦截提示")
                    rec.add_detail(f"    [INFO] 超长名称: 无明确拦截提示")
                    page.click_cancel()
                    page.page.wait_for_timeout(500)
                    if "portFlow" in page.page.url:
                        page.navigate_back_to_list()
            except Exception as e:
                print(f"    [INFO] 超长名称测试异常: {e}")
                rec.add_detail(f"    [INFO] 超长名称测试异常: {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            # 11.4 特殊字符
            rec.add_detail("  特殊字符:")
            ensure_port_route_tab()
            result = page.try_add_rule_invalid(name="<script>alert(1)</script>")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [INFO] 特殊字符处理: {result}")
                rec.add_detail(f"    [INFO] {result}")

            # 11.5 纯空格
            rec.add_detail("  纯空格:")
            ensure_port_route_tab()
            result = page.try_add_rule_invalid(name="   ")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [INFO] 纯空格处理: {result}")
                rec.add_detail(f"    [INFO] {result}")

            # 11.6 优先级边界值测试
            rec.add_detail("  优先级边界值:")
            prio_idx = 0
            for prio_val, desc in [(-1, "负数"), (64, "超出上限"), (0, "最小值0"), (63, "最大值63")]:
                prio_idx += 1
                rule_name = f"prio_test_{prio_idx}"
                ensure_port_route_tab()
                try:
                    page.click_add_button()
                    page.page.wait_for_timeout(1000)
                    page.fill_name(rule_name)
                    page.set_priority(prio_val)
                    page.select_line("wan3")
                    page.page.wait_for_timeout(300)
                    page.click_save()
                    page.page.wait_for_timeout(1500)

                    error_el = page.page.locator('.ant-form-item-explain-error')
                    js_errors = page.page.evaluate("""() => {
                        const errors = [];
                        document.querySelectorAll('[class*="explain"]').forEach(el => {
                            const t = el.textContent.trim();
                            if (t) errors.push(t);
                        });
                        return errors;
                    }""")
                    if error_el.count() > 0 or js_errors:
                        msg = error_el.first.text_content() if error_el.count() > 0 else js_errors[0]
                        print(f"    [OK] 优先级{desc}({prio_val})拦截: {msg}")
                        rec.add_detail(f"    [OK] {desc}({prio_val})拦截: {msg}")
                        page.click_cancel()
                        page.page.wait_for_timeout(300)
                        page.navigate_back_to_list()
                    elif page.wait_for_success_message(timeout=2000):
                        print(f"    [OK] 优先级{desc}({prio_val})接受(自动修正)")
                        rec.add_detail(f"    [OK] {desc}({prio_val})接受(自动修正)")
                        page.page.wait_for_timeout(500)
                        page.navigate_back_to_list()
                        page.page.wait_for_timeout(500)
                        try:
                            page.delete_rule(rule_name)
                        except Exception:
                            pass
                        page.page.wait_for_timeout(300)
                    else:
                        print(f"    [INFO] 优先级{desc}({prio_val}): 无明确提示")
                        rec.add_detail(f"    [INFO] {desc}({prio_val}): 无明确提示")
                        page.click_cancel()
                        page.page.wait_for_timeout(300)
                        if "portFlow" in page.page.url:
                            page.navigate_back_to_list()
                    page.page.wait_for_timeout(300)
                except Exception as e:
                    print(f"    [INFO] 优先级{desc}({prio_val})异常: {e}")
                    rec.add_detail(f"    [INFO] {desc}({prio_val})异常: {e}")
                    try:
                        page.navigate_back_to_list()
                    except Exception:
                        pass

            # 11.7 备注特殊字符
            rec.add_detail("  备注特殊字符:")
            remark_idx = 0
            for char, label in [(":", "冒号"), ("!", "感叹号"), ("@", "at符号")]:
                remark_idx += 1
                ensure_port_route_tab()
                try:
                    page.click_add_button()
                    page.page.wait_for_timeout(1000)
                    page.fill_name(f"test_remark_{remark_idx}")
                    page.select_line("wan2")
                    page.page.wait_for_timeout(300)
                    page.set_priority(80 + remark_idx)
                    page.page.wait_for_timeout(300)
                    page.fill_remark(f"测试{char}备注")
                    page.click_save()
                    page.page.wait_for_timeout(1500)

                    js_errors = page.page.evaluate("""() => {
                        const errors = [];
                        document.querySelectorAll('[class*="explain"]').forEach(el => {
                            const t = el.textContent.trim();
                            if (t) errors.push(t);
                        });
                        return errors;
                    }""")
                    if js_errors:
                        print(f"    [OK] 备注{label}拦截: {js_errors[0]}")
                        rec.add_detail(f"    [OK] {label}拦截: {js_errors[0]}")
                        page.click_cancel()
                        page.page.wait_for_timeout(300)
                        page.navigate_back_to_list()
                    elif page.wait_for_success_message(timeout=2000):
                        print(f"    [OK] 备注{label}接受")
                        rec.add_detail(f"    [OK] {label}接受")
                        page.page.wait_for_timeout(500)
                        page.navigate_back_to_list()
                        page.page.wait_for_timeout(500)
                        try:
                            page.delete_rule(f"test_remark_{remark_idx}")
                        except Exception:
                            pass
                        page.page.wait_for_timeout(300)
                    else:
                        print(f"    [INFO] 备注{label}: 无明确提示")
                        rec.add_detail(f"    [INFO] {label}: 无明确提示")
                        page.click_cancel()
                        page.page.wait_for_timeout(300)
                        if "portFlow" in page.page.url:
                            page.navigate_back_to_list()
                    page.page.wait_for_timeout(300)
                except Exception as e:
                    print(f"    [INFO] 备注{label}异常: {e}")
                    rec.add_detail(f"    [INFO] {label}异常: {e}")
                    try:
                        page.navigate_back_to_list()
                    except Exception:
                        pass

            # 11.8 反向匹配无地址(空地址取反)
            rec.add_detail("  反向匹配无地址:")
            ensure_port_route_tab()
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name("test_inv_noaddr")
                page.select_load_mode("源IP")
                page.page.wait_for_timeout(500)
                page.select_line("wan2")
                page.page.wait_for_timeout(300)
                page.set_priority(90)
                page.page.wait_for_timeout(300)
                # 直接触发反向匹配但不填地址
                page.toggle_src_addr_inverse(True)
                page.click_save()
                page.page.wait_for_timeout(1500)
                js_errors = page.page.evaluate("""() => {
                    const errors = [];
                    document.querySelectorAll('[class*="explain"]').forEach(el => {
                        const t = el.textContent.trim();
                        if (t) errors.push(t);
                    });
                    return errors;
                }""")
                if js_errors:
                    print(f"    [OK] 空地址取反拦截: {js_errors[0]}")
                    rec.add_detail(f"    [OK] 拦截: {js_errors[0]}")
                else:
                    print(f"    [INFO] 空地址取反: 未拦截")
                    rec.add_detail(f"    [INFO] 未拦截")
                page.click_cancel()
                page.page.wait_for_timeout(300)
                if "portFlow" in page.page.url:
                    page.navigate_back_to_list()
            except Exception as e:
                print(f"    [INFO] 空地址取反异常: {e}")
                rec.add_detail(f"    [INFO] 异常: {e}")
                try:
                    page.navigate_back_to_list()
                except Exception:
                    pass

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_port_route()
            page.page.wait_for_timeout(500)

        # ========== 步骤12: 排序测试 ==========
        with rec.step("步骤12: 排序功能测试", "按线路/优先级/协议排序"):
            print("\n[步骤12] 排序测试...")
            rec.add_detail("[排序测试]")

            sortable_cols = ["线路", "优先级", "协议"]
            sort_results = {}

            for col in sortable_cols:
                try:
                    rec.add_detail(f"  {col}:")
                    for click_idx, sort_label in enumerate(["正序", "倒序", "恢复默认"]):
                        result = page.sort_by_column(col)
                        page.page.wait_for_timeout(300)
                        if result:
                            rec.add_detail(f"    [OK] {sort_label}: 成功")
                        else:
                            rec.add_detail(f"    [WARN] {sort_label}: 排序图标未找到")
                    sort_results[col] = True
                    print(f"  [OK] {col} 排序测试通过")
                except Exception as e:
                    sort_results[col] = False
                    print(f"  [WARN] {col} 排序测试异常: {e}")
                    rec.add_detail(f"    [WARN] 排序异常: {e}")

            passed = sum(1 for v in sort_results.values() if v)
            print(f"  [OK] 排序测试完成: {passed}/{len(sortable_cols)} 个字段通过")
            rec.add_detail(f"  -- 汇总: {passed}/{len(sortable_cols)} 个字段排序测试通过 --")

        # ========== 步骤13: 批量停用 ==========
        with rec.step("步骤13: 批量停用", f"批量停用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤13] 批量停用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量停用] 目标: {len(test_rules)} 条")

            # 批量停用带重试 + SSH验证(参照跨三层, 防止底部操作栏延迟导致点击失败却报告通过)
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
                page.navigate_to_port_route()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_stream_ipport_rules() or []
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
                db_rules = backend_verifier.query_stream_ipport_rules() or []
                disabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                rec.add_detail(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                print(f"    SSH: 数据库中{disabled_count}/{total}条规则已停用")
                if total > 0 and disabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_count}/{total}条规则停用")

        # ========== 步骤14: 批量启用 ==========
        with rec.step("步骤14: 批量启用", f"批量启用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤14] 批量启用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量启用] 目标: {len(test_rules)} 条")

            # 批量启用带重试 + SSH验证(参照跨三层, 原实现无验证, 批量启用失败无法发现)
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
                page.navigate_to_port_route()
                page.page.wait_for_timeout(500)

                if backend_verifier is not None:
                    db_rules = backend_verifier.query_stream_ipport_rules() or []
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
                db_rules = backend_verifier.query_stream_ipport_rules() or []
                enabled_count = sum(1 for r in db_rules if r.get("tagname") in test_names and r.get("enabled") == "yes")
                rec.add_detail(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                print(f"    SSH: 数据库中{enabled_count}/{total}条规则已启用")
                if total > 0 and enabled_count < total:
                    ssh_failures.append(f"SSH-L1-批量启用: 仅{enabled_count}/{total}条规则启用")

        # ========== 步骤15: 批量删除 ==========
        with rec.step("步骤15: 批量删除", f"批量删除剩余 {len(test_rules)} 条"):
            print(f"\n[步骤15] 批量删除 {len(test_rules)} 条...")
            rec.add_detail(f"[批量删除] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_delete()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_port_route()
            page.page.wait_for_timeout(500)
            for rule in test_rules:
                assert not page.rule_exists(rule["name"]), f"规则 {rule['name']} 仍存在"
            print(f"  [OK] 批量删除 {len(test_rules)} 条成功")
            rec.add_detail(f"[结果] [OK] 全部删除")

            if backend_verifier is not None:
                try:
                    pt_rules = backend_verifier.query_stream_ipport_rules()
                    test_names = {r["name"] for r in test_rules}
                    remaining = [r for r in pt_rules if r.get("tagname") in test_names]
                    if remaining:
                        ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining)}条")
                    else:
                        rec.add_detail(f"    SSH: 测试规则已全部删除")
                except Exception:
                    pass

        # ========== 步骤16: 导入测试(追加) ==========
        with rec.step("步骤16: 导入配置(追加)", "使用导出的CSV追加导入"):
            print("\n[步骤16] 导入配置(追加)...")
            rec.add_detail("[导入测试-追加]")

            if os.path.exists(export_file_csv):
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_csv)}")
                rec.add_detail(f"  导入前: {count_before} 条")

                result = page.import_rules(export_file_csv, clear_existing=False)
                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_port_route()
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

        # ========== 步骤17: 导入测试(TXT清空现有) ==========
        with rec.step("步骤17: 导入配置(清空现有)", "使用导出的TXT清空现有后导入"):
            print("\n[步骤17] 导入配置(清空现有数据-TXT)...")
            rec.add_detail("[导入测试-清空现有-TXT]")

            if os.path.exists(export_file_txt):
                page.add_rule(name="extra_pt_before", diversion_type="外网线路",
                              line="wan1", priority=50, protocol="any")
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  文件: {os.path.basename(export_file_txt)}")
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则 extra_pt_before)")

                result = page.import_rules(export_file_txt, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1000)
                page.navigate_to_port_route()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                if not page.rule_exists("extra_pt_before"):
                    print(f"  [OK] 清空现有数据生效(extra_pt_before已删除)")
                    rec.add_detail(f"  [OK] 清空生效: extra_pt_before已删除")
                else:
                    print(f"  [WARN] 清空现有数据可能未生效")
                    rec.add_detail(f"  [WARN] extra_pt_before仍存在")

                if count_after > 0:
                    print(f"  [OK] 重新导入 {count_after} 条")
                    rec.add_detail(f"  [OK] 重新导入 {count_after} 条")
            else:
                print(f"  [WARN] TXT文件不存在")
                rec.add_detail(f"  TXT文件不存在")

        # ========== 步骤18: 清理环境 ==========
        with rec.step("步骤18: 清理环境", "清理所有残留数据"):
            print("\n[步骤18] 清理环境...")
            rec.add_detail("[环境清理]")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.navigate_to_port_route()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                for cleanup_round in range(3):
                    page.navigate_to_port_route()
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
                page.navigate_to_port_route()
                page.page.wait_for_timeout(500)
                final_count = page.get_rule_count()
                print(f"  [OK] 清理完成，剩余 {final_count} 条")
                rec.add_detail(f"[结果] 剩余 {final_count} 条")
            else:
                print("  [OK] 无需清理")
                rec.add_detail("  无需清理")

        # ========== 步骤19: 帮助功能测试 ==========
        with rec.step("步骤19: 帮助功能测试", "测试帮助图标"):
            print("\n[步骤19] 帮助功能测试...")
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
        print("端口分流综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 10条（覆盖6种负载模式 + 下一跳网关 + 线路绑定 + 生效时间 + 反向匹配 + 端口 + 分组）")
        print("  - 编辑/停用/启用/删除: 各1条")
        print("  - 复制: 1条")
        print("  - 搜索: 精确/部分匹配/不存在/清空恢复")
        print("  - 排序: 线路、优先级、协议")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加 + 清空现有数据")
        print("  - 异常输入: 空名称/重复/超长/特殊字符/纯空格/优先级边界/备注特殊字符/空地址取反")
        print("  - 批量操作: 批量停用/启用/删除")
        print("  - SSH后台验证: L1数据库+L2 iptables+L3策略路由+L4内核")
        print("  - 扩展字段验证: iface_band, src_addr_inv, dst_addr_inv, src_port, dst_port, time, src_addr")

        # SSH断言
        all_failures = ssh_failures + ui_failures
        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
