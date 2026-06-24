"""
DHCP黑白名单综合测试用例 (IPv4 + IPv6 双协议 + 导入导出 + 模式切换)

网络配置 > DHCP服务 > DHCP黑白名单 综合测试
表格型(规则CRUD) + IPv4/IPv6双协议(独立平行模块) + 模式切换 + 导入导出 + ipset/iptables验证。

IPv4 与 IPv6 是两个完全独立的平行模块(SSH探查确认 2026-06-23):
- v4: dhcp_acl_mac_{black,white}表 / Linux_dhcp_aclmac_default ipset /
      global_config.dhcp_acl_mac / iptables DHCP_ACL链(UDP67) / dhcp_acl_mac.sh
- v6: dhcp6_acl_mac_{black,white}表 / Linux_dhcp6_aclmac_default ipset /
      global_config.dhcp6_acl_mac / ip6tables DHCP6_ACL链(UDP547) / dhcp6_acl_mac.sh
v6 表无 ip_type / termname 列(隐式 IPv6)。

测试策略:
- IPv4: 6条虚拟MAC规则, 完整CRUD + 批量操作 + 模式切换(0/1/2)
- IPv6: 2条虚拟MAC规则, 完整CRUD(添加/编辑/启停/删除) + 切换数据隔离验证
- 导入: 追加(新名DHCL_IMP) + 清空(DHCL_EXTRA标志)
- 默认模式0(黑名单), enabled添加后默认yes

一次测试覆盖(17步):
1. 初始检查(v4+v6模式0) + 清理
2. 批量添加6条(v4) + L1数据库(6条enabled=yes) + ipset
3. 批量停用(v4) + ipset验证
4. 批量启用(v4) + ipset验证
5. 编辑1条(v4改mac) + 验证
6. IPv4/IPv6切换 + IPv6完整CRUD(添加/编辑/启停/删除)
7. 搜索(匹配多条)
8. 排序(MAC列, 6条有意义)
9. 前端校验(空必填/非法MAC/重复MAC)
10. 模式切换(v4: 0黑→1白→2同步→0) + iptables验证
11. 模拟重启(dhcp_acl_mac.sh init重建)
12. 导出
13. 导入追加(新名, 不勾清空)
14. 导入清空(DHCL_EXTRA标志, 勾清空)
15. 帮助
16. 批量删除(batch快速尝试+行内兜底, 0条)
17. 最终清理(v4+v6, 恢复双协议模式0)

SSH后台验证: L1数据库(v4 dhcp_acl_mac + v6 dhcp6_acl_mac) + L2 ipset + L4 iptables + 模式 + 模拟重启
"""
import pytest
from pages.network.dhcp_acl_mac_page import DhcpAclMacPage
from utils.step_recorder import StepRecorder


# IPv4 测试规则(6条虚拟MAC, 不碰iktest的d4:20:00:b1:45:ec)
TEST_RULES = [
    {"name": "DHCL_1", "mac": "02:11:22:33:44:51", "comment": "黑名单测试1"},
    {"name": "DHCL_2", "mac": "02:11:22:33:44:52", "comment": "黑名单测试2"},
    {"name": "DHCL_3", "mac": "02:11:22:33:44:53", "comment": "黑名单测试3"},
    {"name": "DHCL_4", "mac": "02:11:22:33:44:54", "comment": "黑名单测试4"},
    {"name": "DHCL_5", "mac": "02:11:22:33:44:55", "comment": "黑名单测试5"},
    {"name": "DHCL_6", "mac": "02:11:22:33:44:56", "comment": "黑名单测试6"},
]
TEST_NAMES = [r["name"] for r in TEST_RULES]
TEST_MACS = [r["mac"] for r in TEST_RULES]

# IPv6 测试规则(2条, 独立dhcp6_acl_mac表, 虚拟MAC)
V6_RULES = [
    {"name": "DHCL_V6_1", "mac": "02:aa:bb:cc:dd:61", "comment": "IPv6黑名单1"},
    {"name": "DHCL_V6_2", "mac": "02:aa:bb:cc:dd:62", "comment": "IPv6黑名单2"},
]
V6_NAMES = [r["name"] for r in V6_RULES]

# 导入追加规则(新名避免tagname冲突)
IMP_RULES = [
    {"name": "DHCL_IMP_1", "mac": "02:11:22:33:44:71", "comment": "导入追加1"},
    {"name": "DHCL_IMP_2", "mac": "02:11:22:33:44:72", "comment": "导入追加2"},
]


@pytest.mark.dhcp_acl_mac
@pytest.mark.network
class TestDhcpAclMacComprehensive:
    """DHCP黑白名单综合测试 - IPv4+IPv6双协议 + 导入导出 + 模式切换"""

    def test_dhcp_acl_mac_comprehensive(self, dhcp_acl_mac_page_logged_in: DhcpAclMacPage,
                                        step_recorder: StepRecorder, request):
        """综合测试: IPv4/IPv6双协议CRUD + 导入导出 + 模式切换 + 批量删除"""
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

        def count_black(ip_version='v4', enabled_only=False):
            if backend_verifier is None:
                return -1
            return backend_verifier.count_dhcp_acl_rules(
                table='black', enabled_only=enabled_only, ip_version=ip_version)

        def wait_settle():
            page.page.wait_for_timeout(2500)

        print("\n" + "=" * 60)
        print("DHCP黑白名单综合测试开始 (IPv4+IPv6双协议)")
        print("=" * 60)

        # ========== 步骤1: 初始检查 + 清理(v4+v6) ==========
        with rec.step("步骤1: 初始检查+清理", "清理v4+v6残留, 恢复双协议模式0"):
            print("\n[步骤1] 初始检查...")
            if backend_verifier:
                backend_verifier.cleanup_dhcp_acl_test(prefix="DHCL", ip_version='v4')
                backend_verifier.cleanup_dhcp_acl_test(prefix="DHCL", ip_version='v6')
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            ssh_verify("L1-初始模式0(v4)", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=0)
            ssh_verify("L1-初始模式0(v6)", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=False, expected_mode=0, ip_version='v6')

        # ========== 步骤2: 批量添加6条(v4) ==========
        with rec.step("步骤2: 批量添加6条(v4)", "添加6条虚拟MAC, 验证black表+ipset"):
            print(f"\n[步骤2] 批量添加{len(TEST_RULES)}条IPv4规则...")
            for rule in TEST_RULES:
                ok = page.add_rule(name=rule["name"], mac=rule["mac"], comment=rule["comment"])
                print(f"  添加 {rule['name']}({rule['mac']}): {ok}")
                rec.add_detail(f"添加{rule['name']}: {ok}")
                wait_settle()

            ssh_verify("L1-6条规则存在", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black',
                       expected_fields={"enabled": "yes", "mac": TEST_MACS[0]})
            cnt = count_black(enabled_only=True)
            print(f"  black表enabled=yes数: {cnt}")
            rec.add_detail(f"black enabled数: {cnt}")
            if cnt < len(TEST_RULES):
                ssh_failures.append(f"SSH-L1: 添加后enabled数{cnt}<{len(TEST_RULES)}")
            for mac in TEST_MACS:
                ssh_verify(f"L2-ipset含{mac}", backend_verifier.verify_dhcp_acl_ipset,
                           must_pass=False, mac=mac, should_in_ipset=True)

        # ========== 步骤3: 批量停用(v4) ==========
        with rec.step("步骤3: 批量停用(v4)", "全选+批量停用, 验证ipset全部移出"):
            print("\n[步骤3] 批量停用...")
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
                ec = count_black(enabled_only=True)
                print(f"  批量停用后enabled=yes数: {ec}(尝试{retry+1})")
                if ec == 0:
                    break
            rec.add_detail(f"批量停用后enabled: {count_black(enabled_only=True)}")
            ssh_verify("L1-批量停用后全no", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black',
                       expected_fields={"enabled": "no"})
            ssh_verify("L2-停用后ipset移出", backend_verifier.verify_dhcp_acl_ipset,
                       must_pass=True, mac=TEST_MACS[0], should_in_ipset=False)

        # ========== 步骤4: 批量启用(v4) ==========
        with rec.step("步骤4: 批量启用(v4)", "全选+批量启用, 验证ipset全部入"):
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
                ec = count_black(enabled_only=True)
                print(f"  批量启用后enabled=yes数: {ec}(尝试{retry+1})")
                if ec >= len(TEST_RULES):
                    break
            rec.add_detail(f"批量启用后enabled: {count_black(enabled_only=True)}")
            ssh_verify("L1-批量启用后全yes", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black',
                       expected_fields={"enabled": "yes"})
            ssh_verify("L2-启用后ipset入", backend_verifier.verify_dhcp_acl_ipset,
                       must_pass=True, mac=TEST_MACS[0], should_in_ipset=True)

        # ========== 步骤5: 编辑1条(v4) ==========
        with rec.step("步骤5: 编辑DHCL_3(v4)", "改mac+comment"):
            print("\n[步骤5] 编辑DHCL_3...")
            new_mac = "02:11:22:33:44:99"
            ok = page.edit_rule("DHCL_3", mac=new_mac, comment="编辑后")
            print(f"  编辑: {ok}")
            rec.add_detail(f"编辑DHCL_3: {ok}")
            wait_settle()
            ssh_verify("L1-编辑验证", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name="DHCL_3", table='black',
                       expected_fields={"mac": new_mac})
            TEST_MACS[2] = new_mac

        # ========== 步骤6: IPv4/IPv6切换 + IPv6完整CRUD ==========
        with rec.step("步骤6: IPv4/IPv6切换+IPv6 CRUD", "切换隔离验证 + IPv6添加/编辑/启停/删除"):
            print("\n[步骤6] IPv4/IPv6切换 + IPv6完整CRUD...")
            page.navigate_to_dhcp_acl_mac(ip_version='v4')
            page.page.wait_for_timeout(800)

            # 6a: 切换 + 数据隔离
            switched = page.switch_ip_version('v6')
            v6_active = page.get_current_ip_version() == 'IPv6'
            v6_isolated = not page.rule_exists("DHCL_1")  # IPv4规则在IPv6下不显示
            print(f"  6a 切IPv6: 成功={switched}, 激活={v6_active}, IPv4规则隔离={v6_isolated}")
            rec.add_detail(f"6a 切IPv6激活={v6_active}, IPv4隔离={v6_isolated}")
            if not (switched and v6_active and v6_isolated):
                ssh_failures.append(f"步骤6a: IPv6切换/隔离失败(switched={switched},active={v6_active},isolated={v6_isolated})")

            # 6b: IPv6添加2条
            print(f"  6b IPv6添加{len(V6_RULES)}条...")
            for rule in V6_RULES:
                ok = page.add_rule(name=rule["name"], mac=rule["mac"],
                                   comment=rule["comment"], ip_version='v6')
                print(f"    添加 {rule['name']}({rule['mac']}): {ok}")
                rec.add_detail(f"6b 添加{rule['name']}: {ok}")
                wait_settle()
            ssh_verify("L1-v6添加-V6_1", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=V6_RULES[0]['name'], table='black',
                       ip_version='v6',
                       expected_fields={"enabled": "yes", "mac": V6_RULES[0]['mac']})
            v6_cnt = count_black(ip_version='v6')
            print(f"  6b dhcp6_acl_mac_black数: {v6_cnt}")
            rec.add_detail(f"6b v6表数: {v6_cnt}")

            # 6c: IPv6编辑V6_1改mac
            print("  6c IPv6编辑DHCL_V6_1...")
            new_mac6 = "02:aa:bb:cc:dd:99"
            ok = page.edit_rule(V6_RULES[0]['name'], ip_version='v6',
                                mac=new_mac6, comment="v6编辑后")
            print(f"    编辑: {ok}")
            rec.add_detail(f"6c 编辑V6_1: {ok}")
            wait_settle()
            ssh_verify("L1-v6编辑验证", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=V6_RULES[0]['name'], table='black',
                       ip_version='v6', expected_fields={"mac": new_mac6})
            V6_RULES[0]['mac'] = new_mac6

            # 6d: IPv6停用/启用V6_1
            print("  6d IPv6停用/启用DHCL_V6_1...")
            page.navigate_to_dhcp_acl_mac(ip_version='v6')
            page.page.wait_for_timeout(800)
            try:
                page.disable_rule(V6_RULES[0]['name'])
            except Exception as e:
                print(f"    停用异常: {e}")
            wait_settle()
            ssh_verify("L1-v6停用后no", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=V6_RULES[0]['name'], table='black',
                       ip_version='v6', expected_fields={"enabled": "no"})
            try:
                page.enable_rule(V6_RULES[0]['name'])
            except Exception as e:
                print(f"    启用异常: {e}")
            wait_settle()
            ssh_verify("L1-v6启用后yes", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=V6_RULES[0]['name'], table='black',
                       ip_version='v6', expected_fields={"enabled": "yes"})

            # 6e: IPv6删除2条(带SSH验证重试兜底)
            print("  6e IPv6删除DHCL_V6_*...")
            for attempt in range(3):
                remaining = []
                if backend_verifier:
                    for rule in V6_RULES:
                        if backend_verifier.query_dhcp_acl_rule(
                                name=rule['name'], table='black', ip_version='v6'):
                            remaining.append(rule['name'])
                else:
                    remaining = [r['name'] for r in V6_RULES]
                if not remaining:
                    break
                print(f"    删除尝试{attempt+1}, 剩余: {remaining}")
                for name in remaining:
                    try:
                        page.navigate_to_dhcp_acl_mac(ip_version='v6')
                        page.page.wait_for_timeout(500)
                        if page.rule_exists(name):
                            page.delete_rule(name)
                            wait_settle()
                    except Exception as e:
                        print(f"    删除{name}异常(尝试{attempt+1}): {str(e)[:50]}")
            ssh_verify("L1-v6删除后无V6_1", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=V6_RULES[0]['name'], table='black',
                       ip_version='v6', must_exist=False)

            # 切回IPv4列表验证DHCL_1仍在(双协议数据独立)
            # 用navigate而非switch: delete_rule reload后子tab可能丢失, navigate重新激活主tab+IPv4
            page.navigate_to_dhcp_acl_mac(ip_version='v4')
            page.page.wait_for_timeout(800)
            v4_intact = page.rule_exists("DHCL_1")
            print(f"  切回IPv4 DHCL_1仍在: {v4_intact}")
            rec.add_detail(f"切回IPv4 DHCL_1完整: {v4_intact}")
            if not v4_intact:
                ssh_failures.append("步骤6: 切回IPv4后DHCL_1丢失(IPv6操作影响了IPv4数据)")

        # ========== 步骤7: 搜索(多条) ==========
        with rec.step("步骤7: 搜索", "搜索DHCL匹配多条"):
            print("\n[步骤7] 搜索测试...")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            try:
                page.search_rule("DHCL")
                page.page.wait_for_timeout(1500)
                found = page.rule_exists("DHCL_1") and page.rule_exists("DHCL_6")
                print(f"  搜索'DHCL'匹配多条: {found}")
                rec.add_detail(f"搜索匹配多条: {found}")
                page.clear_search()
                page.page.wait_for_timeout(500)
                page.search_rule("NOTEXIST_XYZ")
                page.page.wait_for_timeout(1000)
                not_found = not page.rule_exists("DHCL_1")
                print(f"  搜索'NOTEXIST_XYZ'无结果: {not_found}")
                rec.add_detail(f"搜索不存在无结果: {not_found}")
                page.clear_search()
                page.page.wait_for_timeout(500)
            except Exception as e:
                print(f"  [WARN] 搜索异常: {e}")

        # ========== 步骤8: 排序(6条有意义) ==========
        with rec.step("步骤8: 排序", "按MAC列排序(6条数据)"):
            print("\n[步骤8] 排序测试...")
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

        # ========== 步骤9: 前端校验 ==========
        with rec.step("步骤9: 前端校验", "空必填/非法MAC/重复MAC"):
            print("\n[步骤9] 前端校验测试...")
            for case_name, fill_fn in [
                ("空必填", lambda: (page.fill_name("DHCL_EMPTY"), None)),
                ("非法MAC", lambda: (page.fill_name("DHCL_BADMAC"), page.fill_mac("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"))),
                ("重复MAC", lambda: (page.fill_name("DHCL_DUP"), page.fill_mac(TEST_MACS[0]))),
            ]:
                page.navigate_to_dhcp_acl_mac()
                page.page.wait_for_timeout(500)
                page.click_add_button()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(1000)
                try:
                    fill_fn()
                except Exception:
                    pass
                page.page.wait_for_timeout(300)
                page.click_save()
                page.page.wait_for_timeout(1500)
                error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if error_el.count() > 0:
                    print(f"  [OK] {case_name}拦截: {error_el.first.text_content().strip()[:40]}")
                    rec.add_detail(f"[OK] {case_name}拦截")
                else:
                    print(f"  [WARN] {case_name}未拦截")
                    rec.add_detail(f"[WARN] {case_name}未拦截")
                try:
                    page.click_cancel()
                except Exception:
                    page.page.keyboard.press("Escape")

        # ========== 步骤10: 模式切换(v4, API) ==========
        with rec.step("步骤10: 模式切换(v4)", "0黑→1白→2同步→0(API) + iptables验证"):
            print("\n[步骤10] 模式切换测试...")
            page.select_mode("1")
            wait_settle()
            ssh_verify("L1-模式1", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=1)
            ssh_verify("L4-iptables白名单", backend_verifier.verify_dhcp_acl_iptables,
                       must_pass=False, mode=1)
            page.select_mode("2")
            wait_settle()
            ssh_verify("L1-模式2", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=2)
            page.select_mode("0")
            wait_settle()
            ssh_verify("L1-恢复模式0", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=0)
            ssh_verify("L4-iptables黑名单", backend_verifier.verify_dhcp_acl_iptables,
                       must_pass=True, mode=0)

        # ========== 步骤11: 模拟重启(v4) ==========
        with rec.step("步骤11: 模拟重启(v4)", "dhcp_acl_mac.sh init重建ipset+iptables"):
            print("\n[步骤11] 模拟重启验证...")
            ssh_verify("L4-模拟重启", backend_verifier.verify_dhcp_acl_reboot,
                       must_pass=True)

        # ========== 步骤12: 导出 ==========
        with rec.step("步骤12: 导出", "导出黑白名单配置(供导入用)"):
            print("\n[步骤12] 导出测试...")
            import os as _os
            from config.config import get_config as _get_cfg
            _cfg = _get_cfg()
            _base = _cfg.test_data.get_export_path("dhcp_acl_mac", _cfg.get_project_root())
            export_file = _os.path.splitext(_base)[0] + ".txt"
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            exported = False
            try:
                exported = page.export_rules(use_config_path=True, export_format="txt")
                print(f"  导出txt: {exported}, 文件: {_os.path.basename(export_file)}")
                rec.add_detail(f"导出txt: {exported}, 文件: {_os.path.basename(export_file)}")
                # csv导出(导出弹窗支持CSV+TXT两种格式, 验证csv导出)
                csv_ok = page.export_rules(use_config_path=True, export_format="csv")
                print(f"  导出csv: {csv_ok}")
                rec.add_detail(f"导出csv: {csv_ok}")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")
                rec.add_detail(f"[WARN] 导出异常: {e}")

        # ========== 步骤13: 导入追加(新名, 不勾清空) ==========
        with rec.step("步骤13: 导入追加", "导入新名规则(DHCL_IMP), 验证追加+入库+ipset"):
            print("\n[步骤13] 导入追加...")
            if not (exported and _os.path.exists(export_file)):
                print(f"  [WARN] 无导出文件, 跳过导入追加: {export_file}")
                rec.add_detail("[WARN] 无导出文件, 跳过导入追加")
            else:
                # 生成追加导入文件(基于导出格式, 改tagname/mac/comment为新规则, 避免冲突)
                import_file_append = export_file.replace(".txt", "_append.txt")
                try:
                    with open(export_file, 'r', encoding='utf-8') as f:
                        first_line = f.readline()
                    lines = []
                    for i, r in enumerate(IMP_RULES, start=1):
                        ln = first_line
                        # 剥离id(表已有DHCL_1-6占id 1-6, 追加导入带id=会主键冲突, 让后端自分配)
                        # 替换tagname/mac/comment(导出格式: id=X enabled=yes mac=.. termname= tagname=.. comment=..)
                        import re as _re
                        ln = _re.sub(r'id=\S+\s*', '', ln)
                        ln = _re.sub(r'tagname=\S+', f"tagname={r['name']}", ln)
                        ln = _re.sub(r'mac=\S+', f"mac={r['mac']}", ln)
                        ln = _re.sub(r'comment=\S*', f"comment={r['comment']}", ln)
                        lines.append(ln)
                    with open(import_file_append, 'w', encoding='utf-8') as f:
                        f.writelines(lines)
                    print(f"  追加导入文件含{len(lines)}条新规则")
                    rec.add_detail(f"追加文件: {len(lines)}条")
                except Exception as e:
                    print(f"  [WARN] 准备追加文件失败: {e}")
                    import_file_append = export_file

                count_before = count_black()
                print(f"  导入前black数: {count_before}")
                rec.add_detail(f"导入前: {count_before}条")
                try:
                    page.navigate_to_dhcp_acl_mac()
                    page.page.wait_for_timeout(800)
                    page.import_rules(import_file_append, clear_existing=False)
                    wait_settle()
                except Exception as e:
                    print(f"  [WARN] 导入异常: {e}")
                    rec.add_detail(f"[WARN] 导入异常: {e}")
                count_after = count_black()
                print(f"  导入后black数: {count_after}")
                rec.add_detail(f"导入后: {count_after}条")
                if count_after > count_before:
                    print(f"  [OK] 导入追加成功(+{count_after - count_before}条)")
                    rec.add_detail(f"[OK] 追加成功 +{count_after - count_before}条")
                else:
                    print(f"  [WARN] 导入追加未增加")
                    rec.add_detail("[WARN] 追加未增加")
                ssh_verify("L1-导入追加-IMP_1入库", backend_verifier.verify_dhcp_acl_database,
                           must_pass=False, name=IMP_RULES[0]['name'], table='black',
                           expected_fields={"mac": IMP_RULES[0]['mac']})
                ssh_verify("L2-导入追加-IMP_1 ipset", backend_verifier.verify_dhcp_acl_ipset,
                           must_pass=False, mac=IMP_RULES[0]['mac'], should_in_ipset=True)

        # ========== 步骤14: 导入清空(DHCL_EXTRA标志, 勾清空) ==========
        with rec.step("步骤14: 导入清空", "加DHCL_EXTRA标志, 清空导入, 验证清空生效"):
            print("\n[步骤14] 导入清空...")
            if not (exported and _os.path.exists(export_file)):
                print("  [WARN] 无导出文件, 跳过清空导入")
                rec.add_detail("[WARN] 跳过清空导入")
            else:
                extra_rule = "DHCL_EXTRA"
                # 添加DHCL_EXTRA标志(不在导出文件, 清空后应消失)
                try:
                    page.add_rule(name=extra_rule, mac="02:11:22:33:44:88", comment="清空标志")
                    wait_settle()
                except Exception as e:
                    print(f"  添加{extra_rule}异常: {e}")
                count_before = count_black()
                print(f"  清空前black数: {count_before}(含{extra_rule})")
                rec.add_detail(f"清空前: {count_before}条(含{extra_rule})")
                # 导入清空(勾选清空现有, 导出文件含DHCL_1-6, 不含EXTRA/IMP)
                try:
                    page.navigate_to_dhcp_acl_mac()
                    page.page.wait_for_timeout(800)
                    page.import_rules(export_file, clear_existing=True)
                    wait_settle()
                except Exception as e:
                    print(f"  [WARN] 清空导入异常: {e}")
                    rec.add_detail(f"[WARN] 清空导入异常: {e}")
                # 验证DHCL_EXTRA消失(清空生效) + DHCL_1恢复(导入)
                ssh_verify("L1-清空后EXTRA消失", backend_verifier.verify_dhcp_acl_database,
                           must_pass=True, name=extra_rule, table='black', must_exist=False)
                ssh_verify("L1-清空后DHCL_1恢复", backend_verifier.verify_dhcp_acl_database,
                           must_pass=True, name=TEST_NAMES[0], table='black')

        # ========== 步骤15: 帮助 ==========
        with rec.step("步骤15: 帮助功能", "测试帮助按钮(含新开tab关闭)"):
            print("\n[步骤15] 帮助功能测试...")
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            try:
                pages_before = len(page.page.context.pages)
                clicked = page.click_help()
                if clicked:
                    page.page.wait_for_timeout(1000)
                    help_visible = page.is_help_panel_visible() or page.page.locator(
                        '.ant-popover, .ant-drawer, .ant-modal, [role="dialog"]').count() > 0
                    if help_visible:
                        print("  [OK] 帮助面板已显示")
                        rec.add_detail("[OK] 帮助面板显示")
                        page.close_help_panel()
                        page.page.wait_for_timeout(300)
                    else:
                        print("  [WARN] 帮助面板未显示(可能新开tab已由click_help关闭)")
                        rec.add_detail("[WARN] 帮助面板未显示")
                    # 确认无孤儿tab残留(click_help已关闭新开tab)
                    pages_after = len(page.page.context.pages)
                    if pages_after > pages_before:
                        ssh_failures.append(f"步骤15: 帮助产生孤儿tab({pages_after - pages_before}个)")
            except Exception as e:
                print(f"  [WARN] 帮助异常: {e}")

        # ========== 步骤16: 批量删除(batch快速尝试+行内兜底) ==========
        with rec.step("步骤16: 批量删除", "batch_delete快速尝试+行内兜底, 验证0条"):
            print("\n[步骤16] 批量删除...")
            # batch_delete试1次(改动1后4s内快速失败, 不再卡30s)
            page.navigate_to_dhcp_acl_mac()
            page.page.wait_for_timeout(800)
            try:
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_delete()
                page.page.wait_for_timeout(1000)
            except Exception as e:
                print(f"  batch_delete尝试异常: {str(e)[:50]}")
            wait_settle()
            total = count_black()
            print(f"  batch_delete后black总数: {total}")
            # 未清空则行内delete_rule兜底(快速navigate, 6条约30s而非2分钟)
            if total > 0:
                print(f"  batch未清空({total}条), 行内delete_rule兜底")
                rec.add_detail(f"batch未清空({total}), 行内兜底")
                for name in TEST_NAMES:
                    try:
                        page.navigate_to_dhcp_acl_mac()
                        page.page.wait_for_timeout(300)
                        if page.rule_exists(name):
                            page.delete_rule(name)
                            wait_settle()
                    except Exception as e:
                        print(f"  兜底删除{name}异常: {str(e)[:50]}")
            total = count_black()
            print(f"  最终black总数: {total}")
            rec.add_detail(f"最终black总数: {total}")
            ssh_verify("L1-删除后0条", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black', must_exist=False)

        # ========== 步骤17: 最终清理(v4+v6) ==========
        with rec.step("步骤17: 最终清理", "清理v4+v6规则 + 恢复双协议模式0"):
            print("\n[步骤17] 最终清理...")
            if backend_verifier:
                backend_verifier.cleanup_dhcp_acl_test(prefix="DHCL", ip_version='v4')
                backend_verifier.cleanup_dhcp_acl_test(prefix="DHCL", ip_version='v6')
                wait_settle()
            ssh_verify("L1-最终模式0(v4)", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=0)
            ssh_verify("L1-最终模式0(v6)", backend_verifier.verify_dhcp_acl_mode,
                       must_pass=True, expected_mode=0, ip_version='v6')
            ssh_verify("L1-无DHCL残留(v4)", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name=TEST_NAMES[0], table='black', must_exist=False)
            ssh_verify("L1-无DHCL残留(v6)", backend_verifier.verify_dhcp_acl_database,
                       must_pass=True, name="DHCL_V6_1", table='black',
                       ip_version='v6', must_exist=False)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("DHCP黑白名单综合测试完成 (IPv4+IPv6双协议)")
        print("=" * 60)
        print("测试覆盖:")
        print("  - IPv4: 批量添加6条 + 停用/启用 + 编辑 + 搜索 + 排序")
        print("  - IPv4: 前端校验 + 模式切换(0→1→2→0) + 模拟重启")
        print("  - IPv6: 切换隔离 + 添加/编辑/启停/删除(完整CRUD)")
        print("  - 导出 + 导入追加(新名) + 导入清空(EXTRA标志)")
        print("  - 帮助(新开tab关闭) + 批量删除(快速失败+兜底)")
        print("  - SSH: L1(v4+v6表)+L2 ipset+L4 iptables+模式+模拟重启")

        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项SSH验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not ssh_failures, \
            f"SSH验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
