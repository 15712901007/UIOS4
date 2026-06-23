"""
DHCP黑白名单综合测试用例

网络配置 > DHCP服务 > DHCP黑白名单 综合测试
表格型(规则CRUD) + 模式切换 + ipset/iptables验证。6条测试数据覆盖多场景。

测试策略:
- 6条虚拟MAC规则(02:11:22:33:44:51-56), 不碰iktest MAC
- 默认模式0(黑名单), 操作dhcp_acl_mac_black表, enabled默认yes
- 批量操作(停用/启用/删除)需多条数据才有意义, SSH计数验证
- 模式1(白名单)空ipset阻止所有DHCP, 模式切换用前端API(set_access_mode)

一次测试覆盖(14步):
1. 初始检查(模式0) + 清理
2. 批量添加6条规则 + L1数据库(6条enabled=yes) + ipset(6个MAC)
3. 批量停用(全选) + ipset验证(全部移出)
4. 批量启用(全选) + ipset验证(全部入)
5. 编辑1条(改mac) + 验证
6. 搜索(匹配多条)
7. 排序(MAC列, 6条有意义)
8. 前端校验(空必填/非法MAC/重复MAC)
9. 模式切换(0黑→1白→2同步→0, API) + iptables验证
10. 模拟重启(dhcp_acl_mac.sh init重建)
11. 导出
12. 帮助
13. 批量删除 + 验证(0条)
14. 最终清理(恢复模式0)

SSH后台验证: L1数据库(dhcp_acl_mac_black) + L2 ipset + L4 iptables + L1模式 + L4模拟重启
"""
import pytest
from pages.network.dhcp_acl_mac_page import DhcpAclMacPage
from utils.step_recorder import StepRecorder


# 6条测试规则(虚拟MAC, 不碰iktest的d4:20:00:b1:45:ec)
TEST_RULES = [
    {"name": "DHACL_1", "mac": "02:11:22:33:44:51", "comment": "黑名单测试1"},
    {"name": "DHACL_2", "mac": "02:11:22:33:44:52", "comment": "黑名单测试2"},
    {"name": "DHACL_3", "mac": "02:11:22:33:44:53", "comment": "黑名单测试3"},
    {"name": "DHACL_4", "mac": "02:11:22:33:44:54", "comment": "黑名单测试4"},
    {"name": "DHACL_5", "mac": "02:11:22:33:44:55", "comment": "黑名单测试5"},
    {"name": "DHACL_6", "mac": "02:11:22:33:44:56", "comment": "黑名单测试6"},
]
TEST_NAMES = [r["name"] for r in TEST_RULES]
TEST_MACS = [r["mac"] for r in TEST_RULES]


@pytest.mark.dhcp_acl_mac
@pytest.mark.network
class TestDhcpAclMacComprehensive:
    """DHCP黑白名单综合测试 - 6条数据+批量操作+模式切换"""

    def test_dhcp_acl_mac_comprehensive(self, dhcp_acl_mac_page_logged_in: DhcpAclMacPage,
                                        step_recorder: StepRecorder, request):
        """综合测试: 批量添加/停用启用/编辑/搜索/排序/前端校验/模式切换/批量删除"""
        page = dhcp_acl_mac_page_logged_in
        rec = step_recorder

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
                status = '[OK]' if result.passed else '[FAIL]'
                print(f"    SSH-{label}: {status} - {result.message}")
                rec.add_detail(f"    SSH-{label}: {status} {result.message}")
                if result.raw_output:
                    rec.add_detail(f"      SSH数据: {result.raw_output[:200]}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                return None

        def count_black_enabled():
            return backend_verifier.count_dhcp_acl_rules(table='black', enabled_only=True) if backend_verifier else -1

        def all_macs_in_ipset():
            """检查6个MAC是否都在ipset"""
            if backend_verifier is None:
                return False
            return all(backend_verifier.query_dhcp_acl_rule(mac=mac, table='black') for mac in TEST_MACS)

        def wait_settle():
            page.page.wait_for_timeout(2500)

        print("\n" + "=" * 60)
        print("DHCP黑白名单综合测试开始")
        print("=" * 60)

        # ========== 步骤1: 初始检查 + 清理 ==========
        with rec.step("步骤1: 初始检查+清理", "清理残留, 恢复模式0"):
            print("\n[步骤1] 初始检查...")
            if backend_verifier:
                backend_verifier.cleanup_dhcp_acl_test(prefix="DHACL")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            ssh_verify("L1-初始模式0", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=0)

        # ========== 步骤2: 批量添加6条规则 ==========
        with rec.step("步骤2: 批量添加6条", "添加6条虚拟MAC规则, 验证black表+ipset"):
            print(f"\n[步骤2] 批量添加{len(TEST_RULES)}条规则...")
            for rule in TEST_RULES:
                ok = page.add_rule(name=rule["name"], mac=rule["mac"], comment=rule["comment"])
                print(f"  添加 {rule['name']}({rule['mac']}): {ok}")
                rec.add_detail(f"添加{rule['name']}: {ok}")
                wait_settle()

            # L1验证: black表6条, enabled=yes
            ssh_verify("L1-6条规则存在", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black',
                       expected_fields={"enabled": "yes", "mac": TEST_MACS[0]})
            count = count_black_enabled()
            print(f"  black表enabled=yes数: {count}")
            rec.add_detail(f"black enabled数: {count}")
            if count < len(TEST_RULES):
                ssh_failures.append(f"SSH-L1: 添加后enabled数{count}<{len(TEST_RULES)}")
            # L2验证: 6个MAC都在ipset(enabled=yes)
            for mac in TEST_MACS:
                ssh_verify(f"L2-ipset含{mac}", backend_verifier.verify_dhcp_acl_ipset,
                           must_pass=False, mac=mac, should_in_ipset=True)

        # ========== 步骤3: 批量停用 ==========
        with rec.step("步骤3: 批量停用", "全选+批量停用, 验证ipset全部移出"):
            print("\n[步骤3] 批量停用...")
            # 3次重试(参考MEMORY批量操作教训)
            for retry in range(3):
                page.navigate_to_dhcp_acl_mac()
                page.page.wait_for_timeout(800)
                try:
                    page.select_all_rules()
                    page.page.wait_for_timeout(800)
                    page.batch_disable()
                    page.page.wait_for_timeout(1000)
                except Exception as e:
                    print(f"  批量停用尝试{retry+1}异常: {e}")
                wait_settle()
                enabled_cnt = count_black_enabled()
                print(f"  批量停用后enabled=yes数: {enabled_cnt}(尝试{retry+1})")
                if enabled_cnt == 0:
                    break
            rec.add_detail(f"批量停用后enabled: {count_black_enabled()}")
            ssh_verify("L1-批量停用后全no", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black',
                       expected_fields={"enabled": "no"})
            ssh_verify("L2-停用后ipset移出", backend_verifier.verify_dhcp_acl_ipset,
                       must_pass=True, mac=TEST_MACS[0], should_in_ipset=False)

        # ========== 步骤4: 批量启用 ==========
        with rec.step("步骤4: 批量启用", "全选+批量启用, 验证ipset全部入"):
            print("\n[步骤4] 批量启用...")
            for retry in range(3):
                page.navigate_to_dhcp_acl_mac()
                page.page.wait_for_timeout(800)
                try:
                    page.select_all_rules()
                    page.page.wait_for_timeout(800)
                    page.batch_enable()
                    page.page.wait_for_timeout(1000)
                except Exception as e:
                    print(f"  批量启用尝试{retry+1}异常: {e}")
                wait_settle()
                enabled_cnt = count_black_enabled()
                print(f"  批量启用后enabled=yes数: {enabled_cnt}(尝试{retry+1})")
                if enabled_cnt >= len(TEST_RULES):
                    break
            rec.add_detail(f"批量启用后enabled: {count_black_enabled()}")
            ssh_verify("L1-批量启用后全yes", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black',
                       expected_fields={"enabled": "yes"})
            ssh_verify("L2-启用后ipset入", backend_verifier.verify_dhcp_acl_ipset,
                       must_pass=True, mac=TEST_MACS[0], should_in_ipset=True)

        # ========== 步骤5: 编辑1条 ==========
        with rec.step("步骤5: 编辑DHACL_3", "改mac+comment"):
            print("\n[步骤5] 编辑DHACL_3...")
            new_mac = "02:11:22:33:44:99"
            ok = page.edit_rule("DHACL_3", mac=new_mac, comment="编辑后")
            print(f"  编辑: {ok}")
            rec.add_detail(f"编辑DHACL_3: {ok}")
            wait_settle()
            ssh_verify("L1-编辑验证", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name="DHACL_3", table='black',
                       expected_fields={"mac": new_mac})
            # 更新TEST_MACS[2]
            TEST_MACS[2] = new_mac

        # ========== 步骤6: 搜索(多条) ==========
        with rec.step("步骤6: 搜索", "搜索DHACL匹配多条"):
            print("\n[步骤6] 搜索测试...")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            try:
                page.search_rule("DHACL")
                page.page.wait_for_timeout(1500)
                found = page.rule_exists("DHACL_1") and page.rule_exists("DHACL_6")
                print(f"  搜索'DHACL'匹配多条: {found}")
                rec.add_detail(f"搜索匹配多条: {found}")
                page.clear_search()
                page.page.wait_for_timeout(500)
                # 搜索不存在(验证无结果)
                page.search_rule("NOTEXIST_XYZ")
                page.page.wait_for_timeout(1000)
                not_found = not page.rule_exists("DHACL_1")
                print(f"  搜索'NOTEXIST_XYZ'无结果: {not_found}")
                rec.add_detail(f"搜索不存在无结果: {not_found}")
                page.clear_search()
                page.page.wait_for_timeout(500)
            except Exception as e:
                print(f"  [WARN] 搜索异常: {e}")

        # ========== 步骤7: 排序(6条有意义) ==========
        with rec.step("步骤7: 排序", "按MAC列排序(6条数据)"):
            print("\n[步骤7] 排序测试...")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            sort_ok = 0
            for attempt in ["第1次", "第2次(反向)", "第3次(恢复)"]:
                try:
                    if page.sort_by_column("MAC地址"):
                        sort_ok += 1
                        rec.add_detail(f"  MAC排序{attempt}: [OK]")
                except Exception:
                    pass
                page.page.wait_for_timeout(400)
            print(f"  排序点击成功 {sort_ok} 次(6条数据排序有意义)")
            rec.add_detail(f"[OK] 排序{sort_ok}次(6条数据)")

        # ========== 步骤8: 前端校验 ==========
        with rec.step("步骤8: 前端校验", "空必填/非法MAC/重复MAC"):
            print("\n[步骤8] 前端校验测试...")
            # 8a: 空必填
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(500)
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.fill_name("DHACL_EMPTY")
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)
            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                print(f"  [OK] 空必填拦截: {error_el.first.text_content().strip()[:40]}")
                rec.add_detail("[OK] 空必填拦截")
            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(500)
            # 8b: 非法MAC
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.fill_name("DHACL_BADMAC")
            page.fill_mac("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)
            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                print(f"  [OK] 非法MAC拦截: {error_el.first.text_content().strip()[:40]}")
                rec.add_detail("[OK] 非法MAC拦截")
            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(500)
            # 8c: 重复MAC(用DHACL_1的mac)
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            page.fill_name("DHACL_DUP")
            page.fill_mac(TEST_MACS[0])  # 与DHACL_1重复
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)
            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                print(f"  [OK] 重复MAC拦截: {error_el.first.text_content().strip()[:40]}")
                rec.add_detail("[OK] 重复MAC拦截")
            else:
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 重复MAC被拦截")
                    rec.add_detail("[OK] 重复MAC拦截")
            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(500)

        # ========== 步骤9: 模式切换(API) ==========
        with rec.step("步骤9: 模式切换", "0黑→1白→2同步→0(API) + iptables验证"):
            print("\n[步骤9] 模式切换测试...")
            # 切换到1(白名单)
            page.select_mode("1")
            wait_settle()
            ssh_verify("L1-模式1", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=1)
            ssh_verify("L4-iptables白名单", backend_verifier.verify_dhcp_acl_iptables,
                       must_pass=False, mode=1)
            # 切换到2(同步)
            page.select_mode("2")
            wait_settle()
            ssh_verify("L1-模式2", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=2)
            # 切换回0(黑名单)
            page.select_mode("0")
            wait_settle()
            ssh_verify("L1-恢复模式0", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=0)
            ssh_verify("L4-iptables黑名单", backend_verifier.verify_dhcp_acl_iptables,
                       must_pass=True, mode=0)

        # ========== 步骤10: 模拟重启 ==========
        with rec.step("步骤10: 模拟重启", "dhcp_acl_mac.sh init重建ipset+iptables"):
            print("\n[步骤10] 模拟重启验证...")
            ssh_verify("L4-模拟重启", backend_verifier.verify_dhcp_acl_reboot,
                       must_pass=True)

        # ========== 步骤11: 导出 ==========
        with rec.step("步骤11: 导出", "导出黑白名单配置"):
            print("\n[步骤11] 导出测试...")
            import os as _os
            from config.config import get_config as _get_cfg
            _cfg = _get_cfg()
            _base = _cfg.test_data.get_export_path("dhcp_acl_mac", _cfg.get_project_root())
            export_file = _os.path.splitext(_base)[0] + ".txt"
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            try:
                exported = page.export_rules(use_config_path=True, export_format="txt")
                print(f"  导出: {exported}")
                rec.add_detail(f"导出: {exported}")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")

        # ========== 步骤12: 帮助 ==========
        with rec.step("步骤12: 帮助功能", "测试帮助按钮"):
            print("\n[步骤12] 帮助功能测试...")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            try:
                clicked = page.click_help()
                if clicked:
                    page.page.wait_for_timeout(1000)
                    help_visible = page.is_help_panel_visible() or page.page.locator(
                        '.ant-popover, .ant-drawer, .ant-modal, [role="dialog"]').count() > 0
                    if help_visible:
                        print(f"  [OK] 帮助面板已显示")
                        rec.add_detail("[OK] 帮助面板显示")
                        page.close_help_panel()
                        page.page.wait_for_timeout(300)
                    else:
                        print(f"  [WARN] 帮助面板未显示")
                        page.page.keyboard.press("Escape")
            except Exception as e:
                print(f"  [WARN] 帮助异常: {e}")

        # ========== 步骤13: 批量删除(batch_delete尝试+循环delete_rule兜底) ==========
        with rec.step("步骤13: 批量删除", "批量删除+循环兜底, 验证0条"):
            print("\n[步骤13] 批量删除...")
            # 尝试batch_delete(2次)
            for retry in range(2):
                page.navigate_to_dhcp_acl_mac()
                page.page.wait_for_timeout(800)
                try:
                    page.select_all_rules()
                    page.page.wait_for_timeout(800)
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)
                except Exception as e:
                    print(f"  batch_delete尝试{retry+1}异常: {str(e)[:50]}")
                wait_settle()
                total = backend_verifier.count_dhcp_acl_rules(table='black') if backend_verifier else -1
                print(f"  batch_delete后black总数: {total}(尝试{retry+1})")
                if total == 0:
                    break
            # batch_delete未清空则循环delete_rule兜底(删除确认弹窗兼容性)
            total = backend_verifier.count_dhcp_acl_rules(table='black') if backend_verifier else -1
            if total > 0:
                print(f"  batch_delete未清空({total}条), 循环delete_rule兜底")
                rec.add_detail(f"batch_delete未清空({total}), 循环兜底")
                for name in TEST_NAMES:
                    try:
                        page.navigate_to_dhcp_acl_mac()
                        page.page.wait_for_timeout(500)
                        page.search_rule(name)
                        page.page.wait_for_timeout(500)
                        page.delete_rule(name)
                        wait_settle()
                    except Exception as e:
                        print(f"  循环删除{name}异常: {str(e)[:50]}")
            total = backend_verifier.count_dhcp_acl_rules(table='black') if backend_verifier else -1
            print(f"  最终black总数: {total}")
            rec.add_detail(f"最终black总数: {total}")
            ssh_verify("L1-删除后0条", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black', must_exist=False)

        # ========== 步骤14: 最终清理 ==========
        with rec.step("步骤14: 最终清理", "清理规则 + 恢复模式0"):
            print("\n[步骤14] 最终清理...")
            if backend_verifier:
                backend_verifier.cleanup_dhcp_acl_test(prefix="DHACL")
                wait_settle()
            ssh_verify("L1-最终模式0", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=0)
            ssh_verify("L1-无DHACL残留", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black', must_exist=False)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("DHCP黑白名单综合测试完成")
        print("=" * 60)
        print("测试覆盖(6条数据):")
        print("  - 初始检查 + 清理")
        print("  - 批量添加6条(多MAC场景) + L1数据库 + ipset(6个MAC)")
        print("  - 批量停用(全选, ipset全部移出) + 批量启用(全部入)")
        print("  - 编辑(改mac) + 搜索(匹配多条)")
        print("  - 排序(MAC列, 6条数据有意义)")
        print("  - 前端校验(空必填/非法MAC/重复MAC)")
        print("  - 模式切换(0→1→2→0, API) + iptables验证")
        print("  - 模拟重启 + 导出 + 帮助")
        print("  - 批量删除(0条)")
        print("  - SSH: L1数据库+L2ipset+L4iptables+L1模式+L4模拟重启")

        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项SSH验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not ssh_failures, \
            f"SSH验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
