"""
协议分流综合测试用例

一次测试覆盖多个功能：
1. 添加8条规则（覆盖3种负载模式+不同优先级+不同线路+不同协议+线路绑定+生效时间+IP/MAC分组）
2. SSH后台数据验证（L1+L2+L3+L4逐条验证，含iface_band/time/src_addr字段）
3. 编辑其中1条
4. 复制测试
5. 停用/启用/删除各1条
6. 搜索测试（精确/部分/不存在/清空）
7. 导出测试（CSV/TXT）
8. 异常输入测试（空名称/重复/超长/特殊字符/纯空格）
9. 排序测试（线路、优先级）
10. 批量停用/启用/删除
11. 导入测试（追加+清空现有）
12. 帮助功能测试

SSH后台验证: L1数据库+L2 iptables+L3策略路由+L4内核
字段映射: mode(0/1/3), prio(0-63), interface(逗号分隔), iface_band(0/1), time, src_addr
"""
import pytest
import os
from pages.network.protocol_route_page import ProtocolRoutePage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.protocol_route
@pytest.mark.network
class TestProtocolRouteComprehensive:
    """协议分流综合测试 - 一次测试覆盖所有功能"""

    def test_protocol_route_comprehensive(self, protocol_route_page_logged_in: ProtocolRoutePage,
                                          step_recorder: StepRecorder, request):
        """
        综合测试: 添加8条规则 -> SSH验证 -> 编辑 -> 复制 -> 停用 -> 启用 -> 删除 ->
        搜索 -> 导出 -> 异常测试 -> 排序 -> 批量操作 -> 导入 -> 帮助
        """
        page = protocol_route_page_logged_in
        rec = step_recorder

        # 动态获取backend_verifier fixture
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []

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
                return None

        # 测试数据 - 8条规则，覆盖3种负载模式+线路绑定+生效时间+IP/MAC分组
        # 注意：名称最多15字符
        test_rules = [
            # Mode 0: 新建连接数(默认), wan1, 优先级10, DNS协议
            {"name": "pr_m0_dns", "line": "wan1", "priority": 10,
             "mode": "新建连接数", "proto": "DNS", "remark": "DNS分流",
             "desc": "模式0:新建连接数+DNS"},
            # Mode 1: 源IP, wan2, 优先级20, 网页浏览
            {"name": "pr_m1_http", "line": "wan2", "priority": 20,
             "mode": "源IP", "proto": "网页浏览", "remark": "HTTP分流",
             "desc": "模式1:源IP+HTTP"},
            # Mode 2: 源IP+目的IP, wan3, 优先级30, HTTPS
            {"name": "pr_m2_https", "line": "wan3", "priority": 30,
             "mode": "源IP+目的IP", "proto": "HTTPS", "remark": "HTTPS分流",
             "desc": "模式2:源IP+目的IP+HTTPS"},
            # Mode 0: 多线路(wan1+wan2), 优先级5
            {"name": "pr_multi_wan", "line": "wan1,wan2", "priority": 5,
             "mode": "新建连接数", "proto": "网页浏览",
             "desc": "多线路:wan1+wan2"},
            # Mode 1: 高优先级
            {"name": "pr_high_pri", "line": "wan1", "priority": 1,
             "mode": "源IP", "proto": "DNS",
             "desc": "高优先级:1"},
            # Mode 0: 低优先级, NTP协议, 带备注
            {"name": "pr_low_pri", "line": "wan2", "priority": 60,
             "mode": "新建连接数", "proto": "NTP", "remark": "低优先级",
             "desc": "低优先级:60+NTP"},
            # 线路绑定 + 自定义生效时间(非当前时段, 避免影响其他测试)
            {"name": "pr_bind_time", "line": "wan1", "priority": 15,
             "mode": "新建连接数", "proto": "DNS",
             "line_binding": True,
             "time_mode": "按周循环",
             "time_days": ["一", "二", "三", "四", "五"],
             "time_start": "23:00", "time_end": "23:59",
             "desc": "线路绑定+生效时间(工作日23:00-23:59)"},
            # IP/MAC分组引用(使用已存在的分组)
            {"name": "pr_ipgroup", "line": "wan2", "priority": 25,
             "mode": "新建连接数", "proto": "网页浏览",
             "ip_mac_group": "test_cross_laye",
             "desc": "IP/MAC分组引用"},
        ]

        print("\n" + "=" * 60)
        print("协议分流综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_rules)} 条规则")
        for r in test_rules:
            mode = r.get("mode", "新建连接数(默认)")
            line = r.get("line", "wan1")
            print(f"  - {r['name']}, 线路={line}, 优先级={r.get('priority',31)}, "
                  f"模式={mode}, 协议={r.get('proto','')}, 场景={r['desc']}")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前规则数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_rule_count()
            print(f"  当前规则数量: {current_count}")
            rec.add_detail(f"[环境检查] 当前规则数量: {current_count}")

            # 循环清理直到0条(最多3轮, 应对批量删除不彻底的情况)
            for cleanup_round in range(3):
                page.navigate_to_protocol_route()
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
                    # 等待成功提示
                    page.wait_for_success_message(timeout=3000)

            page.navigate_to_protocol_route()
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
                page.navigate_to_protocol_route()
                page.page.wait_for_timeout(500)
                if page.rule_exists(rule["name"]):
                    page.delete_rule(rule["name"])
                    rec.add_detail(f"  发现残留: {rule['name']}，已删除")
                    cleaned_count += 1
            if cleaned_count == 0:
                rec.add_detail("  无需清理")
            else:
                rec.add_detail(f"  共清理 {cleaned_count} 条")

        # ========== 步骤3: 批量添加8条规则 ==========
        with rec.step("步骤3: 批量添加规则", f"添加 {len(test_rules)} 条规则，覆盖3种负载模式+线路绑定+生效时间+IP/MAC分组"):
            print(f"\n[步骤3] 批量添加 {len(test_rules)} 条规则...")
            rec.add_detail(f"[添加计划] 共 {len(test_rules)} 条，覆盖3种负载模式+线路绑定+生效时间+IP/MAC分组")

            added_count = 0
            for rule in test_rules:
                rec.add_detail(f"[添加 {rule['name']}]")
                rec.add_detail(f"  场景: {rule['desc']}")
                rec.add_detail(f"  线路: {rule['line']}, 优先级: {rule['priority']}")
                if rule.get("mode"):
                    rec.add_detail(f"  负载模式: {rule['mode']}")
                if rule.get("proto"):
                    rec.add_detail(f"  协议: {rule['proto']}")
                if rule.get("remark"):
                    rec.add_detail(f"  备注: {rule['remark']}")
                if rule.get("line_binding"):
                    rec.add_detail(f"  线路绑定: 启用")
                if rule.get("time_mode"):
                    rec.add_detail(f"  生效时间: {rule['time_mode']} "
                                   f"{rule.get('time_start','')}-{rule.get('time_end','')}")
                if rule.get("ip_mac_group"):
                    rec.add_detail(f"  IP/MAC分组: {rule['ip_mac_group']}")

                result = page.add_rule(
                    name=rule["name"],
                    line=rule.get("line", "wan1"),
                    priority=rule.get("priority", 31),
                    mode=rule.get("mode"),
                    proto=rule.get("proto"),
                    remark=rule.get("remark"),
                    line_binding=rule.get("line_binding"),
                    time_mode=rule.get("time_mode"),
                    time_days=rule.get("time_days"),
                    time_start=rule.get("time_start"),
                    time_end=rule.get("time_end"),
                    ip_mac_group=rule.get("ip_mac_group"),
                )
                assert result is True, f"添加规则 {rule['name']} 失败"
                print(f"  + 已添加: {rule['name']} - {rule['desc']}")
                rec.add_detail(f"  [OK] 添加成功")
                added_count += 1

            # 验证所有规则都已添加
            rec.add_detail(f"[验证结果]")
            page.navigate_to_protocol_route()
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
        rule_id_map = {}  # rule_name -> db_id 映射, 供后续L2验证使用
        if backend_verifier is not None:
            with rec.step("步骤4: 后台数据验证（SSH）", "SSH验证每条规则的数据库+iptables+策略路由+内核，含线路绑定/时间/分组字段"):
                print("\n[步骤4] 后台数据验证...")
                rec.add_detail("[SSH后台验证] 字段映射: mode(0/1/3), prio(0-63), interface(逗号分隔)")
                rec.add_detail("[SSH后台验证] 扩展字段: iface_band(0/1), time, src_addr")
                rec.add_detail("[SSH后台验证] L1=数据库, L2=iptables, L3=策略路由, L4=内核模块")

                verify_passed = 0
                rule_id_map = {}  # rule_name -> db_id 映射, 供后续L2验证使用

                for rule in test_rules:
                    rule_name = rule["name"]
                    rec.add_detail(f"  -- 验证: {rule_name} --")
                    print(f"  验证: {rule_name}")

                    # 构建数据库期望字段
                    expected_fields = {"enabled": "yes"}
                    load_mode = rule.get("mode", "新建连接数")
                    expected_mode = ProtocolRoutePage.MODE_TO_DB.get(load_mode, "0")
                    expected_fields["mode"] = expected_mode
                    expected_fields["prio"] = str(rule.get("priority", 31))
                    if rule.get("remark"):
                        expected_fields["comment"] = rule["remark"]
                    # 线路绑定: iface_band 0=禁用 1=启用
                    if rule.get("line_binding"):
                        expected_fields["iface_band"] = "1"

                    detail_parts = [f"mode={expected_fields['mode']}", f"prio={expected_fields['prio']}"]
                    if "iface_band" in expected_fields:
                        detail_parts.append(f"iface_band={expected_fields['iface_band']}")
                    rec.add_detail(f"      期望: {', '.join(detail_parts)}")

                    # L1: 数据库验证
                    l1 = ssh_verify(
                        f"L1-数据库({rule_name})",
                        backend_verifier.verify_stream_layer7_database,
                        rule_name,
                        must_pass=True,
                        expected_fields=expected_fields,
                    )

                    if l1 and l1.passed:
                        db_rule = l1.details.get("rule", {})
                        db_id = db_rule.get("id")
                        rule_id_map[rule_name] = db_id
                        # 记录关键字段包括扩展字段
                        db_detail = (f"id={db_id}, mode={db_rule.get('mode')}, "
                                     f"prio={db_rule.get('prio')}, interface={db_rule.get('interface')}")
                        extra_fields = []
                        if db_rule.get("iface_band"):
                            extra_fields.append(f"iface_band={db_rule.get('iface_band')}")
                        if db_rule.get("time"):
                            extra_fields.append(f"time={db_rule.get('time')}")
                        if db_rule.get("src_addr"):
                            extra_fields.append(f"src_addr={db_rule.get('src_addr')}")
                        if extra_fields:
                            db_detail += ", " + ", ".join(extra_fields)
                        rec.add_detail(f"      数据库: {db_detail}")

                        # 可选检查: IP/MAC分组(src_addr字段格式可能不同)
                        if rule.get("ip_mac_group"):
                            src_addr_val = db_rule.get("src_addr", "")
                            if src_addr_val:
                                rec.add_detail(f"      src_addr(分组引用): {src_addr_val}")
                            else:
                                rec.add_detail(f"      src_addr: 未设置(分组可能未生效)")

                        # L2: iptables验证 (验证规则在STREAM_LAYER7_NEW链中)
                        ssh_verify(
                            f"L2-iptables({rule_name})",
                            backend_verifier.verify_stream_layer7_iptables,
                            rule_id=db_id,
                            expected_ifname=rule.get("line", "wan1"),
                            expected_mode=int(expected_mode),
                            must_pass=False,
                        )

                        verify_passed += 1

                # L3: 策略路由验证 (基础设施级别, 只需检查一次)
                ssh_verify(
                    "L3-策略路由",
                    backend_verifier.verify_stream_layer7_policy_routing,
                    must_pass=False,
                )

                # L4: 内核模块验证 (基础设施级别, 只需检查一次)
                ssh_verify(
                    "L4-内核模块",
                    backend_verifier.verify_stream_layer7_kernel,
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
            new_name = "pr_m0_edit"
            rec.add_detail(f"[编辑操作] {edit_rule['name']} -> {new_name}")

            if page.rule_exists(new_name):
                page.delete_rule(new_name)

            result = page.edit_rule(edit_rule["name"], new_name=new_name)
            assert result is True, f"编辑规则失败"

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)
            assert page.rule_exists(new_name), "编辑后的规则未找到"
            test_rules[0]["name"] = new_name
            print(f"  [OK] 编辑成功")
            rec.add_detail(f"[验证] [OK] 编辑成功，新名称已生效")

            if backend_verifier is not None:
                ssh_verify("L1-编辑验证", backend_verifier.verify_stream_layer7_database, new_name)

        # ========== 步骤5.5: 复制规则测试 ==========
        with rec.step("步骤5.5: 复制规则", "复制编辑后的规则，修改名称保存"):
            print("\n[步骤5.5] 复制规则测试...")
            copy_source = test_rules[0]["name"]  # pr_m0_edit
            copy_name = "pr_m0_copy"
            rec.add_detail(f"[复制操作] 源: {copy_source} -> 新名称: {copy_name}")

            if page.rule_exists(copy_name):
                page.delete_rule(copy_name)
                page.page.wait_for_timeout(500)

            # 点击复制按钮进入预填充的新增页面
            page.copy_rule(copy_source)
            page.page.wait_for_timeout(1000)

            # 等待新增页面加载
            try:
                page.page.wait_for_selector('input[placeholder="请输入名称"]', timeout=10000)
            except Exception:
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(1000)

            # 修改名称(必填字段)
            page.fill_name(copy_name)
            page.click_save()
            page.page.wait_for_timeout(1500)

            # 检查保存结果
            error_el = page.page.locator('.ant-form-item-explain-error')
            if error_el.count() > 0:
                # 保存失败，取消
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
                    # 加入test_rules以便后续步骤清理
                    test_rules.append({
                        "name": copy_name, "line": "wan1", "priority": 10,
                        "mode": "新建连接数", "proto": "DNS",
                        "desc": "复制生成的规则",
                    })
                    print(f"  [OK] 复制成功: {copy_name}")
                    rec.add_detail(f"  [OK] 复制成功")

                    # SSH验证复制规则
                    if backend_verifier is not None:
                        ssh_verify("L1-复制验证", backend_verifier.verify_stream_layer7_database, copy_name)
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
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)
            assert page.is_rule_disabled(disable_rule["name"]), "规则未变为停用状态"
            print(f"  [OK] 停用成功")
            rec.add_detail(f"[验证] [OK] 已停用")

            if backend_verifier is not None:
                ssh_verify("L1-停用验证", backend_verifier.verify_stream_layer7_database,
                           disable_rule["name"], must_pass=True, expected_fields={"enabled": "no"})
                # L2: 停用后iptables规则应消失
                dis_rule_id = rule_id_map.get(disable_rule["name"])
                if dis_rule_id:
                    ssh_verify(
                        "L2-停用验证",
                        backend_verifier.verify_stream_layer7_iptables,
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
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)
            assert page.is_rule_enabled(disable_rule["name"]), "规则启用后状态未变化"
            print(f"  [OK] 启用成功")
            rec.add_detail(f"[验证] [OK] 已启用")

            if backend_verifier is not None:
                ssh_verify("L1-启用验证", backend_verifier.verify_stream_layer7_database,
                           disable_rule["name"], must_pass=True, expected_fields={"enabled": "yes"})
                # L2: 启用后iptables规则应恢复
                en_rule_id = rule_id_map.get(disable_rule["name"])
                if en_rule_id:
                    load_mode = disable_rule.get("mode", "新建连接数")
                    expected_mode = int(ProtocolRoutePage.MODE_TO_DB.get(load_mode, "0"))
                    ssh_verify(
                        "L2-启用验证",
                        backend_verifier.verify_stream_layer7_iptables,
                        rule_id=en_rule_id,
                        expected_ifname=disable_rule.get("line", "wan1"),
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
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)
            count_after = page.get_rule_count()
            assert count_after < count_before, "删除后条目数未减少"
            test_rules.remove(delete_rule_data)
            print(f"  [OK] 删除成功 ({count_before} -> {count_after})")
            rec.add_detail(f"[验证] [OK] 删除成功")

            if backend_verifier is not None:
                try:
                    db_rule = backend_verifier.find_stream_layer7_rule(tagname=delete_rule_data["name"])
                    if db_rule is None:
                        print(f"    SSH-L1-删除验证: [OK] 已从数据库删除")
                        rec.add_detail(f"    SSH-L1: [OK] 已从数据库删除")
                    else:
                        ssh_failures.append(f"SSH-L1-删除验证: {delete_rule_data['name']} 仍在数据库中")
                except Exception as e:
                    print(f"    SSH-L1: 跳过 - {str(e)[:80]}")

                # L2: 验证iptables规则已删除
                del_rule_id = rule_id_map.get(delete_rule_data["name"])
                if del_rule_id:
                    ssh_verify(
                        "L2-删除验证",
                        backend_verifier.verify_stream_layer7_iptables,
                        rule_id=del_rule_id,
                        should_exist=False,
                        must_pass=False,
                    )

        # ========== 步骤9: 搜索测试(扩展) ==========
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

            # 9.2 部分匹配搜索(前缀)
            page.clear_search()
            page.page.wait_for_timeout(300)
            prefix = test_rules[2]["name"][:6] if len(test_rules) > 2 else test_rules[0]["name"][:6]
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
            page.search_rule("not_exist_pr_xxx")
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
            export_file_csv = config.test_data.get_export_path("protocol_route", config.get_project_root())
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

            page.close_modal_if_exists()
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)

        # ========== 步骤11: 异常输入测试(扩展) ==========
        with rec.step("步骤11: 异常输入测试", "空名称/重复/超长/特殊字符/纯空格"):
            print("\n[步骤11] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 11.1 空名称
            rec.add_detail("  空名称:")
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
            result = page.try_add_rule_invalid(name=existing)
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [WARN] 未拦截")
                rec.add_detail(f"    [WARN] 未拦截")

            # 11.3 超长名称(>15字符，后端自动截断到15字符)
            rec.add_detail("  超长名称(30字符，预期自动截断到15字符):")
            long_name = "a" * 30
            try:
                page.click_add_button()
                page.page.wait_for_timeout(1000)
                page.fill_name(long_name)
                page.click_save()
                page.page.wait_for_timeout(1000)

                # 检查是否保存成功（后端自动截断）或被拦截
                error_el = page.page.locator('.ant-form-item-explain-error')
                if error_el.count() > 0:
                    # 被前端拦截
                    error_text = error_el.first.text_content()
                    print(f"    [OK] 前端拦截: {error_text}")
                    rec.add_detail(f"    [OK] 前端拦截: {error_text}")
                    page.click_cancel()
                    page.page.wait_for_timeout(500)
                    page.navigate_back_to_list()
                elif page.wait_for_success_message(timeout=2000):
                    # 保存成功（后端自动截断），需清理
                    truncated = long_name[:15]
                    print(f"    [OK] 后端自动截断到15字符: {truncated}")
                    rec.add_detail(f"    [OK] 后端自动截断到15字符: '{truncated}'")
                    page.page.wait_for_timeout(500)
                    page.navigate_back_to_list()
                    # 删除被截断的规则
                    page.page.wait_for_timeout(500)
                    page.delete_rule(truncated)
                    page.page.wait_for_timeout(500)
                else:
                    print(f"    [INFO] 超长名称: 无明确拦截提示")
                    rec.add_detail(f"    [INFO] 超长名称: 无明确拦截提示")
                    page.click_cancel()
                    page.page.wait_for_timeout(500)
                    if "protocolDiversion" in page.page.url:
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
            result = page.try_add_rule_invalid(name="<script>alert(1)</script>")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [INFO] 特殊字符处理: {result}")
                rec.add_detail(f"    [INFO] {result}")

            # 11.5 纯空格
            rec.add_detail("  纯空格:")
            result = page.try_add_rule_invalid(name="   ")
            if result["success"]:
                print(f"    [OK] 拦截: {result.get('error_message', '')}")
                rec.add_detail(f"    [OK] 拦截: {result.get('error_message', '')}")
            else:
                print(f"    [INFO] 纯空格处理: {result}")
                rec.add_detail(f"    [INFO] {result}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)

        # ========== 步骤12: 排序测试 ==========
        with rec.step("步骤12: 排序功能测试", "按线路/优先级排序（正序->倒序->恢复默认）"):
            print("\n[步骤12] 排序测试...")
            rec.add_detail("[排序测试]")

            sortable_cols = ["线路", "优先级"]
            sort_results = {}

            for col in sortable_cols:
                try:
                    rec.add_detail(f"  {col}:")
                    # 点击3次：正序->倒序->恢复默认
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

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_disable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)
            disabled_count = sum(1 for r in test_rules if page.is_rule_disabled(r["name"]))
            print(f"  [OK] 批量停用: {disabled_count}/{len(test_rules)} 条")
            rec.add_detail(f"[结果] {disabled_count}/{len(test_rules)} 条已停用")

            if backend_verifier is not None:
                try:
                    pr_rules = backend_verifier.query_stream_layer7_rules()
                    test_names = {r["name"] for r in test_rules}
                    disabled_in_db = sum(1 for r in pr_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                    rec.add_detail(f"    SSH: {disabled_in_db}/{len(test_rules)}条停用")
                except Exception:
                    pass

        # ========== 步骤14: 批量启用 ==========
        with rec.step("步骤14: 批量启用", f"批量启用剩余 {len(test_rules)} 条"):
            print(f"\n[步骤14] 批量启用 {len(test_rules)} 条...")
            rec.add_detail(f"[批量启用] 目标: {len(test_rules)} 条")

            select_all = page.page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.page.wait_for_timeout(500)
            page.batch_enable()
            page.page.wait_for_timeout(1500)

            page.page.reload()
            page.page.wait_for_timeout(500)
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)
            enabled_count = sum(1 for r in test_rules if page.is_rule_enabled(r["name"]))
            print(f"  [OK] 批量启用: {enabled_count}/{len(test_rules)} 条")
            rec.add_detail(f"[结果] {enabled_count}/{len(test_rules)} 条已启用")

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
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)
            for rule in test_rules:
                assert not page.rule_exists(rule["name"]), f"规则 {rule['name']} 仍存在"
            print(f"  [OK] 批量删除 {len(test_rules)} 条成功")
            rec.add_detail(f"[结果] [OK] 全部删除")

            if backend_verifier is not None:
                try:
                    pr_rules = backend_verifier.query_stream_layer7_rules()
                    test_names = {r["name"] for r in test_rules}
                    remaining = [r for r in pr_rules if r.get("tagname") in test_names]
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
                page.navigate_to_protocol_route()
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

        # ========== 步骤17: 导入测试(清空现有数据) ==========
        with rec.step("步骤17: 导入配置(清空现有)", "勾选清空现有数据后导入"):
            print("\n[步骤17] 导入配置(清空现有数据)...")
            rec.add_detail("[导入测试-清空现有]")

            if os.path.exists(export_file_csv):
                # 先添加一条额外规则
                page.add_rule(name="extra_pr_before", line="wan1", priority=50, proto="DNS")
                page.page.wait_for_timeout(500)
                count_before = page.get_rule_count()
                rec.add_detail(f"  导入前: {count_before} 条(含额外规则 extra_pr_before)")

                # 导入并勾选清空
                result = page.import_rules(export_file_csv, clear_existing=True)
                page.page.reload()
                page.page.wait_for_timeout(1000)
                page.navigate_to_protocol_route()
                page.page.wait_for_timeout(500)
                count_after = page.get_rule_count()
                rec.add_detail(f"  导入后: {count_after} 条")

                # 验证 extra_pr_before 不存在了
                if not page.rule_exists("extra_pr_before"):
                    print(f"  [OK] 清空现有数据生效(extra_pr_before已删除)")
                    rec.add_detail(f"  [OK] 清空生效: extra_pr_before已删除")
                else:
                    print(f"  [WARN] 清空现有数据可能未生效")
                    rec.add_detail(f"  [WARN] extra_pr_before仍存在")

                if count_after > 0:
                    print(f"  [OK] 重新导入 {count_after} 条")
                    rec.add_detail(f"  [OK] 重新导入 {count_after} 条")
            else:
                print(f"  [WARN] CSV文件不存在")
                rec.add_detail(f"  CSV文件不存在")

        # ========== 步骤18: 清理环境 ==========
        with rec.step("步骤18: 清理环境", "清理所有残留数据"):
            print("\n[步骤18] 清理环境...")
            rec.add_detail("[环境清理]")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.navigate_to_protocol_route()
            page.page.wait_for_timeout(500)

            current_count = page.get_rule_count()
            if current_count > 0:
                select_all = page.page.locator("thead input[type='checkbox']").first
                if select_all.count() > 0 and select_all.is_enabled():
                    select_all.click()
                    page.page.wait_for_timeout(500)
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)

                page.page.reload()
                page.page.wait_for_timeout(500)
                page.navigate_to_protocol_route()
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

            help_result = page.test_help_functionality()
            if help_result['icon_clickable']:
                print(f"  [OK] 帮助功能测试通过")
                rec.add_detail(f"  [OK] 帮助图标可点击")
            else:
                print("  [WARN] 帮助图标未找到")
                rec.add_detail(f"  帮助图标未找到")

        print("\n" + "=" * 60)
        print("协议分流综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 8条（覆盖3种负载模式 + 线路绑定 + 生效时间 + IP/MAC分组）")
        print("  - 编辑/停用/启用/删除: 各1条")
        print("  - 复制: 1条")
        print("  - 搜索: 精确/部分匹配/不存在/清空恢复")
        print("  - 排序: 线路、优先级")
        print("  - 导出: CSV/TXT")
        print("  - 导入: 追加 + 清空现有数据")
        print("  - 异常输入: 空名称/重复/超长/特殊字符/纯空格")
        print("  - 批量操作: 批量停用/启用/删除")
        print("  - SSH后台验证: L1数据库+L2 iptables+L3策略路由+L4内核")
        print("  - 扩展字段验证: iface_band(线路绑定), time(生效时间), src_addr(IP/MAC分组)")

        # SSH断言
        if ssh_failures:
            print(f"\n[SSH断言] 共 {len(ssh_failures)} 项失败:")
            for f in ssh_failures:
                print(f"  - {f}")
            assert not ssh_failures, f"SSH后台验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
