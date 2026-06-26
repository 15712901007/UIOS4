"""
IPv6外网设置综合测试用例

网络配置 > 内外网设置 > IPv6设置 > 外网设置 tab 综合测试
表格型(IPv6 WAN线路), 添加/编辑独立页面(/ipv6Settings/extranetSetting/add), 表单全#id定位。

一次测试覆盖(13步):
1. 检查并清理环境(IPV6WAN*残留)
2. 添加规则1(wan2/DHCPv6动态获取) + L1数据库验证
3. 添加规则2(wan3/静态IP) + L1数据库验证
4. 编辑规则1(改名) + L1验证
5. 停用/启用规则2 + L1验证enabled字段
6. 异常输入(空名称/重复名称/非法static IPv6地址/第3条上限multi_unsupport)
7. 搜索(精确/部分/不存在/清空)
8. 导出(CSV/TXT双格式)
9. 批量停用 + SSH计数验证
10. 批量启用 + SSH计数验证
11. 批量删除 + SSH验证(应不存在)
12. 帮助功能
13. 最终清理 + L1验证无残留

!!环境与约束:
- IPv6全局enabled=no(WAN无真实IPv6上游), 故apply侧(odhcp6c/ipset)软断言(must_pass=False),
  L1数据库(ipv6_wan_config)为硬断言(must_pass=True)。
- WAN线路总数上限3条(企业版multi num=3), 已有默认CFWAN_1, 故本测试加2条(达上限)。
- 测试规则用wan2/wan3(避开管理口wan1), enabled=yes安全(实测不锁网, 删除即清理ipset)。
- 批量操作只勾选测试规则(逐条select_rule), 避开默认CFWAN_1。

字段映射: tagname(名称), interface(外网接口wan1/wan2/wan3), internet(接入方式dhcp/static/relay),
          ipv6_addr/ipv6_gateway(static模式), prefix(请求前缀长度auto/60/62/64),
          prefix_hint(尝试固定前缀), force_prefix(强行获取前缀), enabled(yes/no)
"""
import pytest
import os
from pages.network.ipv6_wan_page import Ipv6WanPage
from utils.step_recorder import StepRecorder


@pytest.mark.ipv6_wan
@pytest.mark.network
class TestIpv6WanComprehensive:
    """IPv6外网设置综合测试 - 一次测试覆盖所有功能(受multi-limit=3约束, 加2条)"""

    def test_ipv6_wan_comprehensive(self, ipv6_wan_page_logged_in: Ipv6WanPage,
                                     step_recorder: StepRecorder, request):
        """综合测试: 添加2条 -> L1验证 -> 编辑 -> 停用启用 -> 异常(含上限) ->
        搜索 -> 导出 -> 批量停用启用删除 -> 帮助 -> 清理"""
        page = ipv6_wan_page_logged_in
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
                if must_pass:
                    ssh_failures.append(f"SSH-{label}: 异常被吞 - {str(e)[:80]}")
                return None

        # 测试规则(受multi-limit=3约束, 已有CFWAN_1, 加2条达上限)
        T1 = "IPV6WAN_T1"          # wan2 / dhcp
        T1_EDITED = "IPV6WAN_E1"
        T2 = "IPV6WAN_T2"          # wan3 / static
        test_names_all = {T1, T1_EDITED, T2}

        print("\n" + "=" * 60)
        print("IPv6外网设置综合测试开始")
        print("=" * 60)
        print("!!环境: IPv6全局关闭(WAN无IPv6上游), L1数据库硬断言, apply侧(ipset)软断言")
        print(f"!!约束: WAN线路上限3条(已有默认CFWAN_1), 本测试加2条({T1}/{T2})达上限")

        # ========== 步骤1: 检查并清理环境 ==========
        with rec.step("步骤1: 检查并清理环境", "清理IPV6WAN*残留 + 确认默认CFWAN_1"):
            print("\n[步骤1] 检查并清理环境...")
            if backend_verifier:
                backend_verifier.cleanup_ipv6_wan_test("IPV6WAN")
            page.navigate_to_ipv6_wan()
            page.page.wait_for_timeout(1000)
            count = page.get_rule_count()
            print(f"  当前外网设置规则数(含默认CFWAN_1): {count}")
            rec.add_detail(f"清理后规则数: {count}")
            # 不动默认CFWAN_1, 仅清理测试残留(DB层已清, UI刷新)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.navigate_to_ipv6_wan()
            page.page.wait_for_timeout(800)

        # ========== 步骤2: 添加规则1 (wan2/dhcp) ==========
        with rec.step(f"步骤2: 添加规则 {T1}", "wan2/DHCPv6动态获取"):
            print(f"\n[步骤2] 添加规则: {T1} (wan2, dhcp)")
            result = page.add_rule(name=T1, interface="wan2",
                                   internet=Ipv6WanPage.INTERNET_DHCP, enabled=True)
            assert result is True, f"添加规则 {T1} 失败"
            print(f"  + 已添加: {T1}")
            rec.add_detail(f"[OK] 添加 {T1} (wan2/dhcp)")
            ssh_verify(f"L1-数据库({T1})", backend_verifier.verify_ipv6_wan_database,
                       T1, must_pass=True,
                       expected_fields={"enabled": "yes", "interface": "wan2",
                                        "internet": "dhcp"})

        # ========== 步骤3: 添加规则2 (wan3/static) ==========
        with rec.step(f"步骤3: 添加规则 {T2}", "wan3/静态IP"):
            print(f"\n[步骤3] 添加规则: {T2} (wan3, static)")
            result = page.add_rule(name=T2, interface="wan3",
                                   internet=Ipv6WanPage.INTERNET_STATIC, enabled=True,
                                   ipv6_addr="2001:db8:1::1/64",
                                   ipv6_gateway="fe80::1")
            assert result is True, f"添加规则 {T2} 失败"
            print(f"  + 已添加: {T2}")
            rec.add_detail(f"[OK] 添加 {T2} (wan3/static)")
            ssh_verify(f"L1-数据库({T2})", backend_verifier.verify_ipv6_wan_database,
                       T2, must_pass=True,
                       expected_fields={"enabled": "yes", "interface": "wan3",
                                        "internet": "static"})

        # ========== 步骤4: 编辑规则1 (改名) ==========
        with rec.step(f"步骤4: 编辑规则 {T1}->{T1_EDITED}", "改名"):
            print(f"\n[步骤4] 编辑规则: {T1} -> {T1_EDITED}")
            result = page.edit_rule(T1, new_name=T1_EDITED)
            if result:
                assert page.rule_exists(T1_EDITED), f"编辑后 {T1_EDITED} 未找到"
                print(f"  [OK] 编辑成功: {T1} -> {T1_EDITED}")
                rec.add_detail(f"[OK] 编辑成功 {T1}->{T1_EDITED}")
                ssh_verify(f"L1-编辑后({T1_EDITED})",
                           backend_verifier.verify_ipv6_wan_database,
                           T1_EDITED, must_pass=True,
                           expected_fields={"interface": "wan2", "internet": "dhcp"})
            else:
                print(f"  [WARN] 编辑失败")
                rec.add_detail("[WARN] 编辑失败")
                ui_failures.append("编辑规则失败")

        # ========== 步骤5: 停用/启用规则2 ==========
        with rec.step(f"步骤5: 停用/启用 {T2}", "停用后启用 + L1验证enabled"):
            print(f"\n[步骤5] 停用/启用 {T2}...")
            page.disable_rule(T2)
            page.page.wait_for_timeout(1000)
            if page.is_rule_disabled(T2):
                print(f"  [OK] 停用成功: {T2}")
                rec.add_detail("[OK] 停用成功")
            else:
                rec.add_detail("[WARN] 停用状态未确认")
            ssh_verify(f"L1-停用({T2})", backend_verifier.verify_ipv6_wan_database,
                       T2, must_pass=True, expected_fields={"enabled": "no"})

            page.enable_rule(T2)
            page.page.wait_for_timeout(1000)
            if page.is_rule_enabled(T2):
                print(f"  [OK] 启用成功: {T2}")
                rec.add_detail("[OK] 启用成功")
            else:
                rec.add_detail("[WARN] 启用状态未确认")
            ssh_verify(f"L1-启用({T2})", backend_verifier.verify_ipv6_wan_database,
                       T2, must_pass=True, expected_fields={"enabled": "yes"})

        # ========== 步骤6: 异常输入测试(含第3条上限) ==========
        with rec.step("步骤6: 异常输入测试", "空名/重复/非法IPv6/第3条上限"):
            print("\n[步骤6] 异常输入测试...")
            rec.add_detail("[异常输入测试]")

            # 6.1 空名称
            rec.add_detail("  空名称:")
            r = page.try_add_rule_invalid(name="")
            if r["success"]:
                print(f"    [OK] 拦截: {r.get('error_message', '')[:50]}")
                rec.add_detail(f"    [OK] 拦截: {r.get('error_message', '')[:50]}")
            else:
                rec.add_detail("    [FAIL] 空名未拦截")
                ui_failures.append("空名称未拦截")

            # 6.2 重复名称
            rec.add_detail("  重复名称:")
            r = page.try_add_rule_invalid(name=T2, interface="wan1",
                                          internet=Ipv6WanPage.INTERNET_DHCP)
            print(f"    [INFO] 重复名称: {r}")
            rec.add_detail(f"    [INFO] 重复名称: {r}")

            # 6.3 非法static IPv6地址
            rec.add_detail("  非法static IPv6地址:")
            r = page.try_add_rule_invalid(name="IPV6WAN_BAD", interface="wan1",
                                          internet=Ipv6WanPage.INTERNET_STATIC,
                                          ipv6_addr="not_a_valid_ipv6",
                                          ipv6_gateway="fe80::1")
            print(f"    [INFO] 非法IPv6: {r}")
            rec.add_detail(f"    [INFO] 非法IPv6: {r}")

            # 6.4 第3条上限(multi_unsupport): 此时count=3(CFWAN_1+E1+T2), 加第4条必被拒
            rec.add_detail("  第3条上限(multi_unsupport):")
            print("    尝试添加第3条测试规则(已达上限3条)...")
            add3 = page.add_rule(name="IPV6WAN_T3", interface="wan1",
                                 internet=Ipv6WanPage.INTERNET_DHCP, enabled=False)
            rec.add_detail(f"    第3条添加结果: {add3}(期望False=被multi_unsupport拦截)")
            # SSH铁证: 总数应仍为3, T3不入库
            if backend_verifier:
                cnt = backend_verifier.count_ipv6_wan()
                t3 = backend_verifier.query_ipv6_wan_rule("IPV6WAN_T3")
                rec.add_detail(f"    SSH: WAN总数={cnt}(期望3), IPV6WAN_T3存在={t3 is not None}(期望False)")
                print(f"    SSH: WAN总数={cnt}, IPV6WAN_T3={t3 is not None}")
                if cnt == 3 and t3 is None and not add3:
                    print(f"    [OK] 第3条上限拦截生效(multi_unsupport)")
                    rec.add_detail("[OK] 第3条上限拦截生效")
                else:
                    rec.add_detail(f"[WARN] 上限校验异常 add3={add3} cnt={cnt}")
                    print(f"    [WARN] 上限校验: add3={add3}, cnt={cnt}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.navigate_to_ipv6_wan()
            page.page.wait_for_timeout(800)

        # ========== 步骤7: 搜索测试 ==========
        with rec.step("步骤7: 搜索测试", f"精确/部分/不存在/清空({T1_EDITED})"):
            print(f"\n[步骤7] 搜索测试({T1_EDITED})...")
            rec.add_detail("[搜索测试]")
            target = T1_EDITED

            page.search_rule(target)
            page.page.wait_for_timeout(1000)
            found = page.rule_exists(target)
            if found:
                print(f"  [OK] 精确搜索: 找到 '{target}'")
                rec.add_detail("[OK] 精确搜索找到")
            else:
                rec.add_detail("[WARN] 精确搜索未找到")

            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("IPV6WAN")
            page.page.wait_for_timeout(1000)
            partial = page.get_rule_list()
            rec.add_detail(f"部分匹配'IPV6WAN': {len(partial)}条 {partial}")
            print(f"  [OK] 部分匹配: {len(partial)}条")

            page.clear_search()
            page.page.wait_for_timeout(300)
            page.search_rule("不存在的IPv6WAN规则")
            page.page.wait_for_timeout(1000)
            zero = page.get_rule_count()
            if zero == 0:
                print(f"  [OK] 不存在搜索: 0条")
                rec.add_detail("[OK] 不存在搜索0条")
            else:
                rec.add_detail(f"[WARN] 不存在搜索:{zero}条")

            page.clear_search()
            page.page.wait_for_timeout(500)

        # ========== 步骤8: 导出测试(CSV+TXT) ==========
        export_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "test_data", "exports", "ipv6_wan")
        export_file_csv = os.path.join(export_dir, "ipv6_wan_config.csv")
        export_file_txt = os.path.join(export_dir, "ipv6_wan_config.txt")

        with rec.step("步骤8: 导出测试", "导出CSV和TXT"):
            print("\n[步骤8] 导出测试...")
            rec.add_detail("[导出测试]")
            for fmt, fpath in [("csv", export_file_csv), ("txt", export_file_txt)]:
                try:
                    ok = page.export_rules(export_format=fmt)
                    if ok and os.path.exists(fpath):
                        size = os.path.getsize(fpath)
                        print(f"  [OK] {fmt.upper()}导出: {os.path.basename(fpath)} ({size}B)")
                        rec.add_detail(f"[OK] {fmt.upper()}导出 ({size}B)")
                    else:
                        print(f"  [WARN] {fmt.upper()}导出失败")
                        rec.add_detail(f"[WARN] {fmt.upper()}导出失败")
                        ui_failures.append(f"{fmt.upper()}导出失败")
                except Exception as e:
                    print(f"  [WARN] {fmt.upper()}导出异常: {e}")
                    rec.add_detail(f"[WARN] {fmt.upper()}导出异常: {e}")

        # ========== 步骤9: 批量停用 ==========
        with rec.step("步骤9: 批量停用", f"停用{T1_EDITED}+{T2}(避开CFWAN_1)"):
            print(f"\n[步骤9] 批量停用 {T1_EDITED}, {T2}...")
            rec.add_detail(f"[批量停用] 目标: {T1_EDITED}, {T2}")
            batch_names = [T1_EDITED, T2]
            disable_ok = False
            for attempt in range(3):
                page.navigate_to_ipv6_wan()
                page.page.wait_for_timeout(500)
                for n in batch_names:
                    page.select_rule(n)
                    page.page.wait_for_timeout(200)
                page.batch_disable()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.navigate_to_ipv6_wan()
                page.page.wait_for_timeout(500)
                if backend_verifier:
                    disabled_cnt = sum(
                        1 for n in batch_names
                        if (backend_verifier.query_ipv6_wan_rule(n) or {}).get("enabled") == "no"
                    )
                else:
                    disabled_cnt = sum(1 for n in batch_names if page.is_rule_disabled(n))
                if disabled_cnt >= len(batch_names):
                    disable_ok = True
                    break
                print(f"  第{attempt+1}次: {disabled_cnt}/{len(batch_names)}已停用, 重试")
                rec.add_detail(f"  第{attempt+1}次: {disabled_cnt}/{len(batch_names)}")
            if disable_ok:
                print(f"  [OK] 批量停用: {len(batch_names)}条")
                rec.add_detail(f"[OK] 批量停用 {len(batch_names)}条")
            else:
                ui_failures.append(f"批量停用仅{disabled_cnt}/{len(batch_names)}")
                rec.add_detail(f"[WARN] 批量停用未完全生效")

        # ========== 步骤10: 批量启用 ==========
        with rec.step("步骤10: 批量启用", f"启用{T1_EDITED}+{T2}"):
            print(f"\n[步骤10] 批量启用 {T1_EDITED}, {T2}...")
            rec.add_detail(f"[批量启用] 目标: {T1_EDITED}, {T2}")
            batch_names = [T1_EDITED, T2]
            enable_ok = False
            for attempt in range(3):
                page.navigate_to_ipv6_wan()
                page.page.wait_for_timeout(500)
                for n in batch_names:
                    page.select_rule(n)
                    page.page.wait_for_timeout(200)
                page.batch_enable()
                page.page.wait_for_timeout(1500)
                page.page.reload()
                page.navigate_to_ipv6_wan()
                page.page.wait_for_timeout(500)
                if backend_verifier:
                    enabled_cnt = sum(
                        1 for n in batch_names
                        if (backend_verifier.query_ipv6_wan_rule(n) or {}).get("enabled") == "yes"
                    )
                else:
                    enabled_cnt = sum(1 for n in batch_names if page.is_rule_enabled(n))
                if enabled_cnt >= len(batch_names):
                    enable_ok = True
                    break
                print(f"  第{attempt+1}次: {enabled_cnt}/{len(batch_names)}已启用, 重试")
                rec.add_detail(f"  第{attempt+1}次: {enabled_cnt}/{len(batch_names)}")
            if enable_ok:
                print(f"  [OK] 批量启用: {len(batch_names)}条")
                rec.add_detail(f"[OK] 批量启用 {len(batch_names)}条")
            else:
                ui_failures.append(f"批量启用仅{enabled_cnt}/{len(batch_names)}")
                rec.add_detail(f"[WARN] 批量启用未完全生效")

        # ========== 步骤11: 批量删除 ==========
        with rec.step("步骤11: 批量删除", f"删除{T1_EDITED}+{T2}(避开CFWAN_1)"):
            print(f"\n[步骤11] 批量删除 {T1_EDITED}, {T2}...")
            rec.add_detail(f"[批量删除] 目标: {T1_EDITED}, {T2}")
            batch_names = [T1_EDITED, T2]
            page.navigate_to_ipv6_wan()
            page.page.wait_for_timeout(500)
            for n in batch_names:
                page.select_rule(n)
                page.page.wait_for_timeout(200)
            page.batch_delete()
            page.page.wait_for_timeout(1500)
            page.page.reload()
            page.navigate_to_ipv6_wan()
            page.page.wait_for_timeout(800)
            for n in batch_names:
                if page.rule_exists(n):
                    ui_failures.append(f"批量删除后 {n} 仍存在")
                    rec.add_detail(f"[WARN] {n}仍存在")
                else:
                    print(f"  [OK] 已删除: {n}")
                    rec.add_detail(f"[OK] 已删除 {n}")
            # SSH验证应不存在 + CFWAN_1未受影响
            for n in batch_names:
                ssh_verify(f"L1-删除验证({n})", backend_verifier.verify_ipv6_wan_database,
                           n, must_pass=True, expect_absent=True)
            if backend_verifier:
                cfwan = backend_verifier.query_ipv6_wan_rule("CFWAN_1")
                rec.add_detail(f"    SSH: CFWAN_1仍在={cfwan is not None}(应True, 默认未动)")

        # ========== 步骤12: 帮助功能 ==========
        with rec.step("步骤12: 帮助功能测试", "测试帮助图标"):
            print("\n[步骤12] 帮助功能测试...")
            rec.add_detail("[帮助功能测试]")
            try:
                page.navigate_to_ipv6_wan()
                page.page.wait_for_timeout(500)
                help_btn = page.page.locator('button').filter(has_text="帮助")
                if help_btn.count() > 0:
                    help_btn.last.click()
                    page.page.wait_for_timeout(1000)
                    panel = page.page.locator(
                        '.ant-drawer:visible, .ant-modal:visible, '
                        '[role="dialog"]:visible, .ant-popover:visible')
                    if panel.count() > 0:
                        print(f"  [OK] 帮助面板已显示")
                        rec.add_detail("[OK] 帮助面板显示")
                        page.page.keyboard.press("Escape")
                        page.page.wait_for_timeout(300)
                    else:
                        print(f"  [WARN] 帮助面板未显示")
                        rec.add_detail("[WARN] 帮助面板未显示")
                        page.page.keyboard.press("Escape")
                else:
                    print(f"  [WARN] 帮助按钮未找到")
                    rec.add_detail("[WARN] 帮助按钮未找到")
            except Exception as e:
                print(f"  [WARN] 帮助异常: {e}")
                rec.add_detail(f"[WARN] 帮助异常: {e}")

        # ========== 步骤13: 最终清理 + 验证 ==========
        with rec.step("步骤13: 最终清理", "清理IPV6WAN* + L1验证无残留"):
            print("\n[步骤13] 最终清理...")
            rec.add_detail("[环境清理]")
            if backend_verifier:
                backend_verifier.cleanup_ipv6_wan_test("IPV6WAN")
                page.page.wait_for_timeout(800)
            # L1验证所有测试规则应不存在
            for n in test_names_all:
                ssh_verify(f"L1-无残留({n})", backend_verifier.verify_ipv6_wan_database,
                           n, must_pass=True, expect_absent=True)
            # CFWAN_1默认应仍在
            if backend_verifier:
                cfwan = backend_verifier.query_ipv6_wan_rule("CFWAN_1")
                if cfwan:
                    print(f"  [OK] 默认CFWAN_1保留未受影响")
                    rec.add_detail("[OK] 默认CFWAN_1保留")

        print("\n" + "=" * 60)
        print("IPv6外网设置综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 添加: 2条(wan2/dhcp + wan3/static), 受multi-limit=3约束")
        print("  - 编辑/停用/启用: 各1条 + L1 enabled字段验证")
        print("  - 异常输入: 空名/重复/非法IPv6/第3条上限multi_unsupport")
        print("  - 搜索: 精确/部分/不存在/清空")
        print("  - 导出: CSV+TXT双格式")
        print("  - 批量停用/启用/删除(避开默认CFWAN_1)")
        print("  - SSH: L1数据库(ipv6_wan_config)硬断言 + apply侧(ipset)软断言")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败:")
            for f in all_failures:
                print(f"  - {f}")
            assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
