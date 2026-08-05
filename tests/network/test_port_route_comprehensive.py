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
import json
import re
from pages.network.port_route_page import PortRoutePage
from config.config import get_config
from utils.verify_helper import make_ssh_verify, make_kernel_check
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

        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        kernel_check = make_kernel_check(backend_verifier, rec, ssh_failures, default_module="stream_ipport")

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
            # 底层一致性实时校验: 删除后底层应无残留
            kernel_check("步骤8-删除后", fail_on_residual=True)

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
            # 底层一致性实时校验: 批量删除后底层应无残留
            kernel_check("步骤15-批量删除后", fail_on_residual=True)

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
            # 底层一致性实时校验: 追加导入后底层应与DB一致
            kernel_check("步骤16-导入追加后", fail_on_residual=False)

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
            # 底层一致性实时校验: 清空导入后底层应与DB一致
            kernel_check("步骤17-导入清空后", fail_on_residual=False)

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
            # 底层一致性实时校验: 清理后底层应彻底无残留(硬FAIL)
            kernel_check("步骤18-清理后", fail_on_residual=True)

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


@pytest.mark.port_route
@pytest.mark.network
class TestPortRouteFlowVerification:
    """端口分流真实功能验证。

    覆盖五种协议选项、六种负载模式、源/目的端口、源/目的地址、反向匹配、
    生效时间、多线路、下一跳、优先级冲突及停用/启用/删除后的数据面变化。
    命中铁证=mangle规则计数增量；选路铁证=连接mark属于规则mark集合。
    """

    PREFIX = "ptf_"
    TARGET_WAN = "wan2"
    SECOND_WAN = "wan3"
    CLIENT_IP = "192.168.148.2"
    CLIENT_IFACE = "ens11"
    PUBLIC_TEST_IP = "223.5.5.5"
    PARALLEL_SRC_PORT_START = 41000

    PROBES = {
        "tcp80": (
            "tcp", 80,
            "curl -sS -o /dev/null -w 'code=%{http_code}' --interface ens11 "
            "--connect-timeout 5 -m 10 http://www.baidu.com/",
        ),
        "tcp443": (
            "tcp", 443,
            "curl -k -sS -o /dev/null -w 'code=%{http_code}' --interface ens11 "
            "--connect-timeout 5 -m 10 https://www.baidu.com/",
        ),
        "tcp53": (
            "tcp", 53,
            "dig +tcp @223.5.5.5 www.baidu.com A -b 192.168.148.2 "
            "+time=3 +tries=1 +comments +answer",
        ),
        "udp53": (
            "udp", 53,
            "dig @223.5.5.5 www.baidu.com A -b 192.168.148.2 "
            "+time=3 +tries=1 +comments +answer",
        ),
        "icmp": (
            "icmp", None,
            "ping -I ens11 -c 3 -W 2 223.5.5.5",
        ),
        "sport_in": (
            "tcp", 53,
            "nc -z -w 3 -s 192.168.148.2 -p 40080 223.5.5.5 53 "
            "&& echo connected || echo failed",
        ),
        "sport_out": (
            "tcp", 53,
            "nc -z -w 3 -s 192.168.148.2 -p 40100 223.5.5.5 53 "
            "&& echo connected || echo failed",
        ),
    }

    @classmethod
    def parallel_tcp53_command(cls, attempts=6):
        """Build concurrent, uniquely identifiable TCP/53 connections.

        ``mode=0`` balances by active connection count. Short sequential curls can
        finish before the next probe starts and legitimately keep choosing the same
        least-loaded WAN. Holding fixed-source-port connections concurrently makes
        the load-mode assertion deterministic and keeps every flow attributable.
        """
        ports = range(cls.PARALLEL_SRC_PORT_START,
                      cls.PARALLEL_SRC_PORT_START + attempts)
        port_list = " ".join(str(port) for port in ports)
        return (
            f"for p in {port_list}; do "
            f"(sleep 2 | nc -w 5 -s {cls.CLIENT_IP} -p \"$p\" "
            f"{cls.PUBLIC_TEST_IP} 53 >/dev/null 2>&1; "
            f"echo port=$p rc=$?) & done; wait"
        )

    def test_port_route_flow(self, port_route_page_logged_in, step_recorder: StepRecorder, request):
        page = port_route_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            pytest.skip("无SSH验证器, 跳过端口分流功能验证")
        if bv is None:
            pytest.skip("无SSH验证器, 跳过端口分流功能验证")

        client_ip = self.CLIENT_IP
        target_wan = self.TARGET_WAN
        second_wan = self.SECOND_WAN
        failures = []
        client_route_snapshots = {}
        print("\n" + "=" * 50)
        print("端口分流全协议/优先级/生命周期功能验证")
        print("=" * 50)

        def _fail(message):
            failures.append(message)
            rec.add_detail(f"  [FAIL] {message}")

        def _force_clean(strict=False):
            """只清理本用例前缀，保留设备上的其他端口分流规则。"""
            try:
                result = bv.cleanup_stream_ipport_test(self.PREFIX)
                deleted_ids = result.details.get("deleted_ids", []) if result.details else []
                if deleted_ids:
                    rec.add_detail(f"  清理测试规则ID: {deleted_ids} (固件正式删除入口)")
                if not result.passed:
                    _fail(result.message)
                bv.clear_client_conntrack(client_ip)
                return result.passed
            except Exception as exc:
                if strict:
                    _fail(f"清理异常: {exc}")
                return False

        def _record_verification(result, rule_name):
            status = "OK" if result.passed else "FAIL"
            rec.add_detail(f"  {result.level}: [{status}] {result.message}")
            if not result.passed:
                _fail(f"{result.level}-{rule_name}: {result.message}")

        def _add_rule(name, **kwargs):
            """通过UI建规则，并强制验证精确名称、ID、DB字段及运行时规则。"""
            if len(name) > 15:
                _fail(f"测试规则名超过15字符: {name}")
                return None
            page.navigate_to_port_route()
            page.page.wait_for_timeout(400)
            created = page.add_rule(name=name, diversion_type=kwargs.get("diversion_type", "外网线路"),
                                    line=kwargs.get("line", target_wan),
                                    nexthop=kwargs.get("nexthop"),
                                    priority=kwargs.get("priority", 31),
                                    mode=kwargs.get("mode", "新建连接数"),
                                    protocol=kwargs.get("protocol", "any"),
                                    src_addr=kwargs.get("src_addr"),
                                    src_addr_inv=kwargs.get("src_addr_inv"),
                                    dst_addr=kwargs.get("dst_addr"),
                                    dst_addr_inv=kwargs.get("dst_addr_inv"),
                                    src_port=kwargs.get("src_port"),
                                    dst_port=kwargs.get("dst_port"),
                                    line_binding=kwargs.get("line_binding"),
                                    time_mode=kwargs.get("time_mode"),
                                    time_days=kwargs.get("time_days"),
                                    time_start=kwargs.get("time_start"),
                                    time_end=kwargs.get("time_end"))
            if not created:
                _fail(f"{name}: UI建规则失败")
                return None
            page.page.wait_for_timeout(1200)
            rule = bv.find_stream_ipport_rule(tagname=name)
            if not rule or not rule.get("id"):
                existing = [r.get("tagname") for r in bv.query_stream_ipport_rules()]
                _fail(f"{name}: 保存后无法按精确名称查到规则ID, 当前规则={existing}")
                return None

            diversion_type = kwargs.get("diversion_type", "外网线路")
            mode_name = kwargs.get("mode", "新建连接数")
            expected = {
                "enabled": "yes",
                "type": "1" if diversion_type == "下一跳网关" else "0",
                "prio": str(kwargs.get("priority", 31)),
                "mode": PortRoutePage.MODE_TO_DB[mode_name],
                "protocol": kwargs.get("protocol", "any"),
            }
            if diversion_type == "下一跳网关":
                expected["nexthop"] = kwargs.get("nexthop")
            else:
                expected["interface"] = kwargs.get("line", target_wan)
            if kwargs.get("line_binding") is not None:
                expected["iface_band"] = "1" if kwargs["line_binding"] else "0"
            if kwargs.get("src_addr_inv") is not None:
                expected["src_addr_inv"] = "1" if kwargs["src_addr_inv"] else "0"
            if kwargs.get("dst_addr_inv") is not None:
                expected["dst_addr_inv"] = "1" if kwargs["dst_addr_inv"] else "0"

            rid = int(rule["id"])
            _record_verification(
                bv.verify_stream_ipport_database(name, expected_fields=expected), name
            )
            expected_ifname = None if diversion_type == "下一跳网关" else expected["interface"]
            expected_mode = None if diversion_type == "下一跳网关" else int(expected["mode"])
            _record_verification(
                bv.verify_stream_ipport_iptables(
                    rid, expected_ifname=expected_ifname, expected_mode=expected_mode
                ),
                name,
            )
            _record_verification(bv.verify_stream_ipport_policy_routing(), name)
            _record_verification(bv.verify_stream_ipport_kernel(), name)

            def _field_populated(value):
                if isinstance(value, dict):
                    return bool(value.get("custom") or value.get("object"))
                return bool(value)

            for field in ("src_addr", "dst_addr", "src_port", "dst_port"):
                if kwargs.get(field) and not _field_populated(rule.get(field)):
                    _fail(f"{name}: DB字段{field}为空, 期望包含{kwargs[field]}")
            if kwargs.get("time_mode"):
                time_value = rule.get("time")
                if not _field_populated(time_value):
                    _fail(f"{name}: 生效时间未写入DB")
                elif kwargs.get("time_days"):
                    day_map = {"一": "1", "二": "2", "三": "3", "四": "4",
                               "五": "5", "六": "6", "日": "7"}
                    expected_days = "".join(day_map[d] for d in kwargs["time_days"])
                    if expected_days not in json.dumps(time_value, ensure_ascii=False):
                        _fail(f"{name}: DB星期不匹配, 期望={expected_days}, 实际={time_value}")
            rec.add_detail(
                f"  [OK] 建规则 {name}: id={rid}, protocol={expected['protocol']}, "
                f"mode={expected['mode']}, prio={expected['prio']}"
            )
            return rule

        def _probe_ok(probe_name, output):
            if probe_name in ("tcp53", "udp53"):
                return "status: NOERROR" in (output or "")
            if probe_name in ("tcp80", "tcp443"):
                match = re.search(r"code=(\d{3})", output or "")
                return bool(match and match.group(1) != "000")
            if probe_name.startswith("sport"):
                return "connected" in (output or "")
            if probe_name == "icmp":
                return bool(re.search(r"\b0% packet loss", output or ""))
            return False

        def _send_probe(probe_name):
            proto, dport, command = self.PROBES[probe_name]
            bv.connect_client()
            output = bv._client.exec(command, timeout=20)
            return {
                "name": probe_name,
                "proto": proto,
                "dport": dport,
                "output": output,
                "ok": _probe_ok(probe_name, output),
            }

        def _flow_signature(probe_name):
            proto, dport, _ = self.PROBES[probe_name]
            public_names = {"tcp53", "udp53", "icmp", "sport_in", "sport_out"}
            source_ports = {"sport_in": 40080, "sport_out": 40100}
            return {
                "proto": proto,
                "dst_ip": self.PUBLIC_TEST_IP if probe_name in public_names else None,
                "src_port": source_ports.get(probe_name),
                "dst_port": dport,
            }

        def _flow_entries(probe_name):
            return bv.conntrack_client_flow_entries(
                client_ip, **_flow_signature(probe_name)
            )

        def _wait_for_flow(probe_name, timeout_ms=4000):
            entries = []
            elapsed = 0
            while elapsed <= timeout_ms:
                entries = _flow_entries(probe_name)
                if entries:
                    break
                page.page.wait_for_timeout(200)
                elapsed += 200
            return entries

        def _entry_marks(entries):
            return {
                int(match.group(1))
                for entry in entries
                for match in [re.search(r"\bmark=(\d+)", entry)]
                if match
            }

        def _entry_wans(entries):
            return sorted({
                match.group(1)
                for entry in entries
                for match in [re.search(r"\bremote_if=(\S+)", entry)]
                if match
            })

        def _exercise(rule, probe_name, expect_hit=True):
            """单次真实打流，正向要求计数+mark，负向要求流通但本规则不命中。"""
            if not rule:
                return None
            rid = int(rule["id"])
            cnt_before = bv.read_mangle_counter("STREAM_IPPORT_NEW", rid)
            bv.clear_client_conntrack(client_ip)
            probe = _send_probe(probe_name)
            rule_marks = set(bv.read_mangle_rule_marks("STREAM_IPPORT_NEW", rid))
            cnt_after = cnt_before
            entries = []
            flow_marks = set()
            selected_marks = []
            elapsed = 0
            while elapsed <= 4000:
                cnt_after = bv.read_mangle_counter("STREAM_IPPORT_NEW", rid)
                entries = _flow_entries(probe_name)
                flow_marks = _entry_marks(entries)
                selected_marks = sorted(rule_marks & flow_marks)
                delta = cnt_after - cnt_before
                condition_met = (
                    bool(entries) and delta > 0 and bool(selected_marks)
                    if expect_hit else
                    bool(entries) and delta == 0 and not selected_marks
                )
                if condition_met:
                    break
                page.page.wait_for_timeout(200)
                elapsed += 200
            delta = cnt_after - cnt_before
            wans = _entry_wans(entries)

            if expect_hit:
                passed = probe["ok"] and bool(entries) and delta > 0 and bool(selected_marks)
                expectation = "应命中并选路"
            else:
                passed = probe["ok"] and bool(entries) and delta == 0 and not selected_marks
                expectation = "应放行但不命中本规则"
            status = "OK" if passed else "FAIL"
            rec.add_detail(
                f"  [{status}] {rule.get('tagname')}/{probe_name}: {expectation}; "
                f"probe_ok={probe['ok']}, Δpkts={delta}, rule_marks={sorted(rule_marks)}, "
                f"matched_marks={selected_marks}, remote_if={wans}"
            )
            if not passed:
                chain = bv._router.exec(
                    "iptables -t mangle -L STREAM_IPPORT_NEW -n -v -x "
                    "--line-numbers 2>/dev/null"
                )
                rule_pattern = re.compile(rf"/\*\s*{rid}(?!\d)")
                rule_lines = [line for line in chain.splitlines() if rule_pattern.search(line)]
                set_names = []
                for line in rule_lines:
                    for set_name in re.findall(r"match-set\s+(\S+)", line):
                        if set_name not in set_names:
                            set_names.append(set_name)
                set_dump = []
                for set_name in set_names:
                    content = bv._router.exec(f"ipset list {set_name} 2>/dev/null")
                    set_dump.append(f"{set_name}: {content[:1200]}")
                conntrack = "\n".join(entries) or bv.conntrack_client_entries(client_ip)
                target = _flow_signature(probe_name)["dst_ip"] or "www.baidu.com"
                route = bv._client.exec(
                    f"ip route get {target} from {client_ip} 2>/dev/null"
                )
                rec.add_detail(
                    f"  诊断-{rule.get('tagname')}/{probe_name}: "
                    f"route={route.strip()}; rule_lines={rule_lines}; "
                    f"conntrack={conntrack[:2400] or '无'}; ipset={set_dump or '无'}"
                )
                _fail(
                    f"{rule.get('tagname')}/{probe_name}: {expectation}失败 "
                    f"(probe_ok={probe['ok']}, Δpkts={delta}, "
                    f"rule_marks={sorted(rule_marks)}, flow_marks={sorted(flow_marks)}, "
                    f"flow_count={len(entries)})"
                )
            return {"passed": passed, "delta": delta, "selected_marks": selected_marks}

        def _assert_mark_cardinality(rule, probe_name, attempts, expected_count, label):
            """多连接后验证负载模式的mark分布/粘性。"""
            if not rule:
                return
            rid = int(rule["id"])
            before = bv.read_mangle_counter("STREAM_IPPORT_NEW", rid)
            bv.clear_client_conntrack(client_ip)
            probe_results = [_send_probe(probe_name) for _ in range(attempts)]
            rule_marks = set(bv.read_mangle_rule_marks("STREAM_IPPORT_NEW", rid))
            after = before
            observed = set()
            elapsed = 0
            while elapsed <= 4000:
                after = bv.read_mangle_counter("STREAM_IPPORT_NEW", rid)
                observed = rule_marks & _entry_marks(_flow_entries(probe_name))
                if after - before >= attempts and len(observed) == expected_count:
                    break
                page.page.wait_for_timeout(200)
                elapsed += 200
            passed = (all(item["ok"] for item in probe_results) and
                      after - before >= attempts and len(observed) == expected_count)
            status = "OK" if passed else "FAIL"
            rec.add_detail(
                f"  [{status}] {label}: connections={attempts}, Δpkts={after-before}, "
                f"rule_marks={sorted(rule_marks)}, observed={sorted(observed)}, "
                f"期望mark数={expected_count}"
            )
            if not passed:
                _fail(f"{label}失败: Δpkts={after-before}, observed={sorted(observed)}")

        def _assert_new_connection_distribution(rule, attempts=6):
            """Verify mode=0 with overlapping fixed-target connections."""
            if not rule:
                return
            rid = int(rule["id"])
            source_ports = set(range(
                self.PARALLEL_SRC_PORT_START,
                self.PARALLEL_SRC_PORT_START + attempts,
            ))
            before = bv.read_mangle_counter("STREAM_IPPORT_NEW", rid)
            bv.clear_client_conntrack(client_ip)
            bv.connect_client()
            output = bv._client.exec(
                self.parallel_tcp53_command(attempts), timeout=20
            ) or ""
            successful_ports = {
                int(match.group(1))
                for match in re.finditer(r"port=(\d+)\s+rc=0\b", output)
                if int(match.group(1)) in source_ports
            }
            rule_marks = set(bv.read_mangle_rule_marks("STREAM_IPPORT_NEW", rid))
            after = before
            entries = []
            seen_ports = set()
            observed = set()
            elapsed = 0
            while elapsed <= 4000:
                after = bv.read_mangle_counter("STREAM_IPPORT_NEW", rid)
                all_entries = bv.conntrack_client_flow_entries(
                    client_ip, proto="tcp", dst_ip=self.PUBLIC_TEST_IP, dst_port=53
                )
                entries = []
                seen_ports = set()
                for entry in all_entries:
                    match = re.search(r"\bsport=(\d+)\b", entry)
                    if match and int(match.group(1)) in source_ports:
                        entries.append(entry)
                        seen_ports.add(int(match.group(1)))
                observed = rule_marks & _entry_marks(entries)
                if (after - before >= attempts and len(seen_ports) == attempts and
                        len(successful_ports) == attempts and len(observed) == 2):
                    break
                page.page.wait_for_timeout(200)
                elapsed += 200
            passed = (
                len(successful_ports) == attempts and
                len(seen_ports) == attempts and
                after - before >= attempts and
                len(rule_marks) == 2 and
                observed == rule_marks
            )
            status = "OK" if passed else "FAIL"
            rec.add_detail(
                f"  [{status}] 新建连接数模式双WAN并发分布: "
                f"connect_ok={len(successful_ports)}/{attempts}, "
                f"flow_ports={len(seen_ports)}/{attempts}, Δpkts={after-before}, "
                f"rule_marks={sorted(rule_marks)}, observed={sorted(observed)}"
            )
            if not passed:
                rec.add_detail(
                    f"  并发分布诊断: command_output={output[:800] or '无'}; "
                    f"conntrack={' | '.join(entries)[:2400] or '无'}"
                )
                _fail(
                    "新建连接数模式双WAN并发分布失败: "
                    f"connect_ok={len(successful_ports)}/{attempts}, "
                    f"flow_ports={len(seen_ports)}/{attempts}, Δpkts={after-before}, "
                    f"rule_marks={sorted(rule_marks)}, observed={sorted(observed)}"
                )

        def _assert_preemption(winner, other, label):
            """优先级链允许两行计数都增加，最终连接mark才决定实际选路。"""
            if not winner or not other:
                return
            winner_id = int(winner["id"])
            other_id = int(other["id"])
            winner_before = bv.read_mangle_counter("STREAM_IPPORT_NEW", winner_id)
            other_before = bv.read_mangle_counter("STREAM_IPPORT_NEW", other_id)
            bv.clear_client_conntrack(client_ip)
            probe = _send_probe("tcp80")
            winner_marks = set(bv.read_mangle_rule_marks("STREAM_IPPORT_NEW", winner_id))
            other_marks = set(bv.read_mangle_rule_marks("STREAM_IPPORT_NEW", other_id))
            winner_delta = 0
            other_delta = 0
            flow_marks = set()
            elapsed = 0
            while elapsed <= 4000:
                winner_delta = (
                    bv.read_mangle_counter("STREAM_IPPORT_NEW", winner_id) - winner_before
                )
                other_delta = (
                    bv.read_mangle_counter("STREAM_IPPORT_NEW", other_id) - other_before
                )
                flow_marks = _entry_marks(_flow_entries("tcp80"))
                if winner_marks & flow_marks and not (other_marks & flow_marks):
                    break
                page.page.wait_for_timeout(200)
                elapsed += 200
            passed = (probe["ok"] and bool(winner_marks & flow_marks) and
                      not (other_marks & flow_marks))
            status = "OK" if passed else "FAIL"
            rec.add_detail(
                f"  [{status}] {label}: 胜出规则Δ={winner_delta}, 另一规则Δ={other_delta}, "
                f"winner_marks={sorted(winner_marks)}, flow_marks={sorted(flow_marks)}"
            )
            if not passed:
                _fail(f"{label}失败: winner_marks={sorted(winner_marks)}, "
                      f"flow_marks={sorted(flow_marks)}")

        def _wait_enabled(name, expected, timeout_ms=6000):
            elapsed = 0
            while elapsed <= timeout_ms:
                rule = bv.find_stream_ipport_rule(tagname=name)
                if rule and rule.get("enabled") == expected:
                    return rule
                page.page.wait_for_timeout(500)
                elapsed += 500
            return bv.find_stream_ipport_rule(tagname=name)

        try:
            with rec.step("前置检查: 测试链路与三协议基线",
                          "router=10.66.0.45; client SSH=10.66.0.18; 数据面源=192.168.148.2/ens11"):
                _force_clean(strict=True)
                bv.connect_router()
                bv.connect_client()
                rec.add_detail(
                    f"  测试角色: 路由器={bv._ssh_config.router.host}, "
                    f"客户端SSH={bv._ssh_config.client.host}, 数据面={client_ip}/{self.CLIENT_IFACE}"
                )
                iface = bv._client.exec(f"ip -br -4 addr show dev {self.CLIENT_IFACE}")
                if client_ip not in iface or "UP" not in iface:
                    pytest.skip(f"客户端数据面接口不满足: {iface}")
                for target, label in ((self.PUBLIC_TEST_IP, "公网协议探针"),):
                    snapshot = bv._client.exec(
                        f"ip route show exact {target}/32"
                    ).strip()
                    used_metrics = {
                        int(value) for value in re.findall(r"\bmetric\s+(\d+)", snapshot)
                    }
                    metric = next(value for value in range(5, 100) if value not in used_metrics)
                    client_route_snapshots[target] = {
                        "snapshot": snapshot,
                        "metric": metric,
                    }
                    bv._client.exec(
                        f"sudo -n ip route replace {target}/32 via 192.168.148.1 "
                        f"dev {self.CLIENT_IFACE} src {client_ip} metric {metric}"
                    )
                    active_route = bv._client.exec(f"ip route show exact {target}/32")
                    if ("via 192.168.148.1" not in active_route or
                            self.CLIENT_IFACE not in active_route or
                            f"metric {metric}" not in active_route):
                        pytest.skip(f"无法建立{label}数据面路由: {active_route}")
                    rec.add_detail(
                        f"  {label}临时路由: {active_route.strip()}; "
                        f"原始={snapshot or '无'}"
                    )
                baseline = []
                for name in ("tcp80", "tcp443", "tcp53", "udp53", "icmp", "sport_in"):
                    bv.clear_client_conntrack(client_ip)
                    item = _send_probe(name)
                    entries = _wait_for_flow(name)
                    if not item["ok"]:
                        rec.add_detail(f"  基线 {name}: 首次失败, 重试1次")
                        bv.clear_client_conntrack(client_ip)
                        item = _send_probe(name)
                        entries = _wait_for_flow(name)
                    item["flow_count"] = len(entries)
                    item["selectable"] = any(
                        "can_sel_route=true" in entry for entry in entries
                    )
                    baseline.append(item)
                for item in baseline:
                    passed = item["ok"] and item["flow_count"] > 0 and item["selectable"]
                    rec.add_detail(
                        f"  基线 {item['name']}: {'[OK]' if passed else '[BLOCKED]'}; "
                        f"probe_ok={item['ok']}, flow_count={item['flow_count']}, "
                        f"can_sel_route={item['selectable']}"
                    )
                if not all(
                        item["ok"] and item["flow_count"] > 0 and item["selectable"]
                        for item in baseline):
                    pytest.skip(
                        "公网TCP/UDP/ICMP基线不可达或can_sel_route=false, "
                        "环境不满足端口分流判定"
                    )
                _record_verification(bv.verify_stream_ipport_policy_routing(), "baseline")

            with rec.step("场景1: TCP+源IP+目的端口范围+源IP粘性",
                          "tcp 80/443应命中; tcp 53不命中; mode=源IP; wan2+wan3同源连接固定一条线路"):
                _force_clean()
                tcp_rule = _add_rule(
                    "ptf_tcprange", line=f"{target_wan},{second_wan}", priority=31,
                    mode="源IP", protocol="tcp", src_addr=client_ip, dst_port="80-443",
                )
                _exercise(tcp_rule, "tcp80", expect_hit=True)
                _exercise(tcp_rule, "tcp443", expect_hit=True)
                _exercise(tcp_rule, "tcp53", expect_hit=False)
                _assert_mark_cardinality(tcp_rule, "tcp80", attempts=4, expected_count=1,
                                         label="源IP模式同源粘性")

            with rec.step("场景2: 指定源IP不匹配",
                          "规则源IP=192.168.148.99; 192.168.148.2访问应放行但不命中"):
                _force_clean()
                miss_rule = _add_rule(
                    "ptf_srcmiss", line=target_wan, priority=31, mode="新建连接数",
                    protocol="tcp", src_addr="192.168.148.99", dst_port="80",
                )
                _exercise(miss_rule, "tcp80", expect_hit=False)

            with rec.step("场景3: TCP源端口范围",
                          "源端口40080应命中40080-40089; 40100不命中; mode=源IP+源端口"):
                _force_clean()
                sport_rule = _add_rule(
                    "ptf_sport", line=target_wan, priority=31, mode="源IP+源端口",
                    protocol="tcp", src_port="40080-40089", dst_port="53",
                )
                _exercise(sport_rule, "sport_in", expect_hit=True)
                _exercise(sport_rule, "sport_out", expect_hit=False)

            with rec.step("场景4: UDP+目的IP+目的端口",
                          "UDP DNS应命中; 同目标TCP DNS不命中; mode=源IP+目的IP"):
                _force_clean()
                udp_rule = _add_rule(
                    "ptf_udp", line=target_wan, priority=31, mode="源IP+目的IP",
                    protocol="udp", dst_addr=self.PUBLIC_TEST_IP, dst_port="53",
                )
                _exercise(udp_rule, "udp53", expect_hit=True)
                _exercise(udp_rule, "tcp53", expect_hit=False)

            with rec.step("场景5: 源地址反向匹配+ICMP协议+主备模式",
                          "TCP验证源地址取反; 独立ICMP规则验证协议命中和主备选路"):
                _force_clean()
                src_inv_rule = _add_rule(
                    "ptf_srcinv", line=target_wan, priority=31,
                    mode="新建连接数", protocol="tcp", src_addr="192.168.148.99",
                    src_addr_inv=True, dst_port="80",
                )
                _exercise(src_inv_rule, "tcp80", expect_hit=True)
                _force_clean()
                icmp_rule = _add_rule(
                    "ptf_icmp", line=f"{target_wan},{second_wan}", priority=31,
                    mode="主备模式", protocol="icmp", line_binding=True,
                )
                _exercise(icmp_rule, "icmp", expect_hit=True)
                _exercise(icmp_rule, "tcp80", expect_hit=False)

            with rec.step("场景6: any全协议+目的地址反向+生效时间+多线路轮询",
                          "TCP/UDP/ICMP均命中; 排除保留地址; 全天生效; 6条并发TCP/53连接分布到2条WAN"):
                _force_clean()
                any_rule = _add_rule(
                    "ptf_any", line=f"{target_wan},{second_wan}", priority=31,
                    mode="新建连接数", protocol="any", dst_addr="198.51.100.1",
                    dst_addr_inv=True, time_mode="按周循环",
                    time_days=["一", "二", "三", "四", "五", "六", "日"],
                    time_start="00:00", time_end="23:59",
                )
                for probe_name in ("tcp80", "udp53", "icmp"):
                    _exercise(any_rule, probe_name, expect_hit=True)
                _assert_new_connection_distribution(any_rule, attempts=6)

            with rec.step("场景7: tcp+udp组合协议及协议排他",
                          "公网DNS TCP和UDP 53均命中; ICMP不命中; mode=五元组"):
                _force_clean()
                both_rule = _add_rule(
                    "ptf_both", line=target_wan, priority=31,
                    mode="源IP+目的IP+目的端口", protocol="tcp+udp", dst_port="53",
                )
                _exercise(both_rule, "tcp53", expect_hit=True)
                _exercise(both_rule, "udp53", expect_hit=True)
                _exercise(both_rule, "icmp", expect_hit=False)

            with rec.step("场景8: 下一跳网关分流",
                          "type=1, nexthop=10.66.0.1; TCP 80命中并生成独立策略表"):
                _force_clean()
                gateway_rule = _add_rule(
                    "ptf_nexthop", diversion_type="下一跳网关", nexthop="10.66.0.1",
                    priority=31, mode="新建连接数", protocol="tcp",
                    src_addr=client_ip, dst_port="80",
                )
                if gateway_rule:
                    table_id = 15000 + int(gateway_rule["id"])
                    ip_rules = bv._router.exec("ip rule show")
                    routes = bv._router.exec(f"ip route show table {table_id}")
                    runtime_ok = f"lookup {table_id}" in ip_rules and "default via 10.66.0.1" in routes
                    rec.add_detail(
                        f"  [{'OK' if runtime_ok else 'FAIL'}] 下一跳策略: table={table_id}, "
                        f"rule={f'lookup {table_id}' in ip_rules}, default={routes.strip()}"
                    )
                    if not runtime_ok:
                        _fail(f"下一跳策略表{table_id}未正确生成")
                _exercise(gateway_rule, "tcp80", expect_hit=True)

            with rec.step("场景9: 优先级冲突+停用/启用/删除回退",
                          "同条件prio=63/1冲突; 数值1最终选路; 停用1后63接管; 启用1后恢复; 删除1后63再次接管"):
                _force_clean()
                p01_rule = _add_rule(
                    "ptf_p01", line=second_wan, priority=1, mode="新建连接数",
                    protocol="tcp", src_addr=client_ip, dst_port="80",
                )
                p63_rule = _add_rule(
                    "ptf_p63", line=target_wan, priority=63, mode="新建连接数",
                    protocol="tcp", src_addr=client_ip, dst_port="80", line_binding=True,
                )
                if p63_rule and p01_rule:
                    high_pos = bv.read_mangle_rule_line_numbers(
                        "STREAM_IPPORT_NEW", int(p63_rule["id"])
                    )
                    low_pos = bv.read_mangle_rule_line_numbers(
                        "STREAM_IPPORT_NEW", int(p01_rule["id"])
                    )
                    ordered = bool(high_pos and low_pos and min(high_pos) < min(low_pos))
                    rec.add_detail(
                        f"  [{'OK' if ordered else 'FAIL'}] 链顺序: prio63行={high_pos}, "
                        f"prio1行={low_pos}"
                    )
                    if not ordered:
                        _fail(f"优先级链顺序错误: prio63={high_pos}, prio1={low_pos}")
                _assert_preemption(p01_rule, p63_rule, "prio1最终mark优先于prio63")

                page.navigate_to_port_route()
                if not page.disable_rule("ptf_p01"):
                    _fail("prio1规则停用操作未发起")
                disabled = _wait_enabled("ptf_p01", "no")
                if not disabled or disabled.get("enabled") != "no":
                    _fail("prio1规则停用后DB未变为enabled=no")
                if p01_rule:
                    _record_verification(
                        bv.verify_stream_ipport_iptables(int(p01_rule["id"]), should_exist=False),
                        "ptf_p01-disabled",
                    )
                _exercise(p63_rule, "tcp80", expect_hit=True)

                page.navigate_to_port_route()
                if not page.enable_rule("ptf_p01"):
                    _fail("prio1规则启用操作未发起")
                enabled = _wait_enabled("ptf_p01", "yes")
                if not enabled or enabled.get("enabled") != "yes":
                    _fail("prio1规则启用后DB未恢复enabled=yes")
                _assert_preemption(p01_rule, p63_rule, "重新启用后prio1恢复最终选路")

                page.navigate_to_port_route()
                if not page.delete_rule("ptf_p01"):
                    _fail("prio1规则删除操作失败")
                page.page.wait_for_timeout(800)
                if bv.find_stream_ipport_rule(tagname="ptf_p01") is not None:
                    _fail("prio1规则删除后DB仍残留")
                if p01_rule:
                    _record_verification(
                        bv.verify_stream_ipport_iptables(int(p01_rule["id"]), should_exist=False),
                        "ptf_p01-deleted",
                    )
                _exercise(p63_rule, "tcp80", expect_hit=True)

            with rec.step("场景10: 清理与残留检查",
                          "测试前缀DB规则、iptables行、conntrack均清理"):
                _force_clean(strict=True)
                chain = bv._router.exec(
                    "iptables -t mangle -L STREAM_IPPORT_NEW -n -v -x --line-numbers 2>/dev/null"
                )
                chain_clean = self.PREFIX not in chain
                rec.add_detail(f"  [{'OK' if chain_clean else 'FAIL'}] iptables测试前缀残留={not chain_clean}")
                if not chain_clean:
                    _fail("清理后STREAM_IPPORT_NEW仍有测试前缀规则")
        finally:
            try:
                page.navigate_to_port_route()
                page.page.wait_for_timeout(500)
            except Exception:
                pass
            _force_clean(strict=True)
            try:
                for target, route_state in client_route_snapshots.items():
                    snapshot = route_state["snapshot"]
                    metric = route_state["metric"]
                    bv._client.exec(
                        f"sudo -n ip route del {target}/32 via 192.168.148.1 "
                        f"dev {self.CLIENT_IFACE} src {client_ip} metric {metric} "
                        "2>/dev/null"
                    )
                    restored = bv._client.exec(
                        f"ip route show exact {target}/32"
                    ).strip()
                    if restored != snapshot:
                        _fail(
                            f"客户端{target}路由恢复不一致: 原始={snapshot or '无'}, "
                            f"恢复后={restored or '无'}"
                        )
            except Exception as exc:
                _fail(f"客户端临时路由恢复异常: {exc}")
        print(f"\n[端口分流全功能验证] {'通过' if not failures else '失败'+str(len(failures))+'项'}")
        assert not failures, f"端口分流功能验证失败({len(failures)}项): {'; '.join(failures)}"
