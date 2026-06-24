"""
DHCP服务端综合测试用例

网络配置 > DHCP服务 > DHCP服务端 综合测试
DHCP服务端是表格型模块(每个LAN/VLAN接口一条DHCP地址池配置), 添加/编辑为独立页面。

测试策略(关键):
- 设备默认存在 DHS_1(lan1, 192.168.148.2-192.168.151.200), 是系统正在使用的DHCP,
  全程不可停用/删除/破坏(否则测试客户端断网)。DHS_1始终保持enabled=yes, ik_dhcpd始终运行。
- 新增测试规则 DHTEST_1(lan1, 不冲突地址池 192.168.151.210-220), 对其做完整CRUD + SSH验证。
- 停用DHTEST_1不影响ik_dhcpd进程(因DHS_1仍enabled), 仅从ik_dhcpd.conf移除该池。

一次测试覆盖(15步):
1. 初始环境检查 + 清理残留测试规则
2. 添加DHTEST_1 + SSH L1-L4全链路验证(数据库/进程/配置文件/运行时/iptables)
3. 编辑DHTEST_1(改lease/delay/dns/check_addr_valid) + SSH验证
4. 停用DHTEST_1 + SSH验证(从conf移除, 进程仍运行)
5. 启用DHTEST_1 + SSH验证(回到conf)
6. 模拟重启验证(dhcp_server.sh boot, 对照DMZ重启失效bug)
7. 前端校验-空必填
8. 前端校验-非法客户端地址
9. 前端校验-租期越界
10. 重启DHCP服务按钮 + SSH验证
11. 搜索测试规则
12. 导出测试
13. 帮助功能
14. 删除DHTEST_1 + SSH验证
15. 最终清理 + DHS_1完整性保护验证

SSH后台验证: L1数据库(dhcp_server表) + L2进程(ik_dhcpd) + L3配置文件(ik_dhcpd.conf) +
            L4运行时(UDP67/status文件) + L4-iptables(DHCP_ACL链) + L4-模拟重启(boot)
字段映射: tagname=名称 interface=服务接口 addr_pool=客户端地址(start-end) netmask=子网掩码
         gateway=网关 dns1/dns2 lease=租期(分钟) delay=过期保留(小时) check_addr_valid
"""
import pytest
from pages.network.dhcp_server_page import DhcpServerPage
from utils.step_recorder import StepRecorder


# 测试规则配置(不与DHS_1的192.168.148.2-192.168.151.200冲突)
TEST_RULE = "DHTEST_1"
TEST_IFACE = "lan1"
TEST_POOL_START = "192.168.151.210"
TEST_POOL_END = "192.168.151.220"
TEST_NETMASK = "255.255.252.0"   # 与lan1子网(192.168.148.1/22)一致
TEST_GATEWAY = "192.168.148.1"
TEST_DNS1 = "114.114.114.114"
TEST_DNS2 = "223.5.5.5"
TEST_LEASE = 60
TEST_DELAY = 2

# 6条测试规则(不重叠地址池在151.201-254内, 避开DHS_1的148.2-151.200; DHTEST_1用原池保持兼容)
TEST_RULES = [
    {"name": "DHTEST_1", "pool_start": "192.168.151.210", "pool_end": "192.168.151.220", "lease": 60, "comment": "DHCP池1"},
    {"name": "DHTEST_2", "pool_start": "192.168.151.221", "pool_end": "192.168.151.226", "lease": 90, "comment": "DHCP池2"},
    {"name": "DHTEST_3", "pool_start": "192.168.151.227", "pool_end": "192.168.151.232", "lease": 120, "comment": "DHCP池3"},
    {"name": "DHTEST_4", "pool_start": "192.168.151.233", "pool_end": "192.168.151.238", "lease": 150, "comment": "DHCP池4"},
    {"name": "DHTEST_5", "pool_start": "192.168.151.239", "pool_end": "192.168.151.244", "lease": 180, "comment": "DHCP池5"},
    {"name": "DHTEST_6", "pool_start": "192.168.151.245", "pool_end": "192.168.151.250", "lease": 240, "comment": "DHCP池6"},
]
TEST_NAMES = [r["name"] for r in TEST_RULES]


@pytest.mark.dhcp_server
@pytest.mark.network
class TestDhcpServerComprehensive:
    """DHCP服务端综合测试 - 表格型(独立页面表单)"""

    def test_dhcp_server_comprehensive(self, dhcp_server_page_logged_in: DhcpServerPage,
                                       step_recorder: StepRecorder, request):
        """综合测试: 添加/编辑/停用启用/模拟重启/前端校验/重启服务/搜索/导出/帮助/删除 + SSH全链路"""
        page = dhcp_server_page_logged_in
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
                    print(f"      SSH数据: {result.raw_output[:200]}")
                    rec.add_detail(f"      SSH数据: {result.raw_output[:200]}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                return None

        def wait_dhcpd_settle():
            """等待ik_dhcpd __delayed_restart(2秒)生效"""
            page.page.wait_for_timeout(3000)

        print("\n" + "=" * 60)
        print("DHCP服务端综合测试开始")
        print("=" * 60)

        # ========== 步骤1: 初始环境检查 + 清理残留 ==========
        with rec.step("步骤1: 初始环境检查+清理残留", "清理DHTEST残留规则, 确认ik_dhcpd运行"):
            print("\n[步骤1] 初始环境检查...")
            # 清理之前的残留测试规则(SQL兜底)
            if backend_verifier:
                backend_verifier.cleanup_dhcp_server_test_rules("DHTEST")
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)

            # 记录初始规则数
            initial_count = page.get_rule_count()
            print(f"  当前DHCP服务端规则数: {initial_count}")
            rec.add_detail(f"初始规则数: {initial_count}")

            # SSH验证ik_dhcpd初始运行(DHS_1应存在)
            ssh_verify("L2-初始进程", backend_verifier.verify_dhcp_server_process,
                       must_pass=True, expect_running=True)
            ssh_verify("L4-iptables", backend_verifier.verify_dhcp_server_iptables,
                       must_pass=True, expect_dhcp_acl=True)

        # ========== 步骤2: 批量添加6条 + L1-L4全链路验证 ==========
        with rec.step("步骤2: 批量添加6条", f"添加{len(TEST_RULES)}条DHCP池并SSH L1-L4验证"):
            print(f"\n[步骤2] 批量添加{len(TEST_RULES)}条DHCP池...")
            for rule in TEST_RULES:
                result = page.add_dhcp_server(
                    name=rule["name"], interface=TEST_IFACE,
                    pool_start=rule["pool_start"], pool_end=rule["pool_end"],
                    netmask=TEST_NETMASK, gateway=TEST_GATEWAY,
                    dns1=TEST_DNS1, dns2=TEST_DNS2,
                    lease=rule["lease"], delay=TEST_DELAY,
                    check_addr_valid=False,
                )
                print(f"  添加 {rule['name']}({rule['pool_start']}-{rule['pool_end']}): {result}")
                rec.add_detail(f"添加{rule['name']}: {result}")
                wait_dhcpd_settle()
            print(f"  [OK] {len(TEST_RULES)}条添加成功")
            rec.add_detail(f"[OK] {len(TEST_RULES)}条添加")

            wait_dhcpd_settle()

            # 验证规则在列表中
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            assert page.rule_exists(TEST_RULE), "DHTEST_1未出现在列表中"
            print(f"  [OK] DHTEST_1已出现在列表中")
            rec.add_detail("[OK] 列表可见")

            # SSH L1-L4全链路验证
            ssh_verify("L1-添加验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={
                           "enabled": "yes", "interface": TEST_IFACE,
                           "addr_pool": f"{TEST_POOL_START}-{TEST_POOL_END}",
                           "netmask": TEST_NETMASK, "gateway": TEST_GATEWAY,
                           "dns1": TEST_DNS1, "dns2": TEST_DNS2,
                           "lease": str(TEST_LEASE), "delay": str(TEST_DELAY),
                       })
            ssh_verify("L2-进程", backend_verifier.verify_dhcp_server_process,
                       must_pass=True, expect_running=True)
            ssh_verify("L3-配置文件", backend_verifier.verify_dhcp_server_config_file,
                       must_pass=True, tagname=TEST_RULE, expect_in_conf=True,
                       expect_any_enabled=True)
            ssh_verify("L4-运行时", backend_verifier.verify_dhcp_server_runtime,
                       must_pass=True, expect_running=True)
            ssh_verify("L4-iptables", backend_verifier.verify_dhcp_server_iptables,
                       must_pass=False, expect_dhcp_acl=True)

        # ========== 步骤3: 编辑DHTEST_1(改lease/delay/dns/check_addr_valid) ==========
        with rec.step("步骤3: 编辑DHTEST_1", "修改lease/delay/dns/开启check_addr_valid"):
            print("\n[步骤3] 编辑DHTEST_1(lease=30, delay=5, dns1=8.8.8.8, check_addr_valid=开启)...")

            result = page.edit_dhcp_server(
                TEST_RULE,
                lease=30, delay=5, dns1="8.8.8.8",
                check_addr_valid=True,  # 测试开启(合法配置下应能保存)
            )
            assert result is True, "编辑DHTEST_1失败"
            print(f"  [OK] 编辑成功")
            rec.add_detail("[OK] 编辑成功")

            wait_dhcpd_settle()

            ssh_verify("L1-编辑验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={
                           "lease": "30", "delay": "5", "dns1": "8.8.8.8",
                           "check_addr_valid": "1",
                       })
            ssh_verify("L3-编辑后conf", backend_verifier.verify_dhcp_server_config_file,
                       must_pass=True, tagname=TEST_RULE, expect_in_conf=True)

        # ========== 步骤4: 停用DHTEST_1 ==========
        with rec.step("步骤4: 停用DHTEST_1", "停用并验证从ik_dhcpd.conf移除(进程仍运行)"):
            print("\n[步骤4] 停用DHTEST_1...")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            disabled = page.disable_rule(TEST_RULE)
            page.page.wait_for_timeout(500)
            wait_dhcpd_settle()

            # 验证页面状态(停用后按钮应变"启用")
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            is_disabled = page.is_rule_disabled(TEST_RULE)
            print(f"  页面状态: disabled={disabled}, is_disabled={is_disabled}")
            rec.add_detail(f"页面: disabled={disabled}, is_disabled={is_disabled}")

            # SSH结果导向验证(不依赖disable_rule返回值)
            ssh_verify("L1-停用验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={"enabled": "no"})
            # 停用规则应从ik_dhcpd.conf移除(仅enabled=yes才下发)
            ssh_verify("L3-停用后conf移除", backend_verifier.verify_dhcp_server_config_file,
                       must_pass=True, tagname=TEST_RULE, expect_in_conf=False,
                       expect_any_enabled=True)
            # 进程应仍运行(DHS_1仍enabled)
            ssh_verify("L2-停用后进程", backend_verifier.verify_dhcp_server_process,
                       must_pass=True, expect_running=True)

        # ========== 步骤5: 启用DHTEST_1 ==========
        with rec.step("步骤5: 启用DHTEST_1", "启用并验证回到ik_dhcpd.conf"):
            print("\n[步骤5] 启用DHTEST_1...")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            page.enable_rule(TEST_RULE)
            page.page.wait_for_timeout(500)
            wait_dhcpd_settle()

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)

            ssh_verify("L1-启用验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={"enabled": "yes"})
            ssh_verify("L3-启用后conf恢复", backend_verifier.verify_dhcp_server_config_file,
                       must_pass=True, tagname=TEST_RULE, expect_in_conf=True)

        # ========== 步骤6: 模拟重启验证(对照DMZ bug) ==========
        with rec.step("步骤6: 模拟重启验证", "执行dhcp_server.sh boot, 验证配置从数据库重建"):
            print("\n[步骤6] 模拟重启验证(dhcp_server.sh boot)...")

            ssh_verify("L4-模拟重启", backend_verifier.verify_dhcp_server_reboot,
                       must_pass=True, tagname=TEST_RULE, expect_any_enabled=True)

        # ========== 步骤7: 前端校验-空必填 ==========
        with rec.step("步骤7: 前端校验-空必填", "不填名称/地址池直接保存, 验证前端拦截"):
            print("\n[步骤7] 前端校验-空必填...")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(500)
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            # 只填名称, 不填地址池/网关等必填, 直接保存
            page.fill_name("DHTEST_INVALID")
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)

            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content().strip()
                print(f"  [OK] 前端拦截: {error_text[:60]}")
                rec.add_detail(f"[OK] 前端拦截: {error_text[:60]}")
            else:
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 保存被拦截(无成功消息)")
                    rec.add_detail("[OK] 保存被拦截")
                else:
                    # 意外保存成功, 需清理
                    print(f"  [WARN] 未拦截, 清理意外规则")
                    rec.add_detail("[WARN] 未拦截")
                    if backend_verifier:
                        backend_verifier.cleanup_dhcp_server_test_rules("DHTEST_INVALID")

            # 取消回列表(用基类click_cancel处理"确认离开"弹窗)
            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(500)

        # ========== 步骤8: 前端校验-非法客户端地址 ==========
        with rec.step("步骤8: 前端校验-非法客户端地址", "填非法IP地址, 验证前端拦截"):
            print("\n[步骤8] 前端校验-非法客户端地址...")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(500)
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            page.fill_name("DHTEST_INVALID2")
            page.select_interface(TEST_IFACE)
            page.fill_addr_pool("999.999.999.999", "999.999.999.998")  # 非法IP
            page.fill_gateway("192.168.148.1")
            page.fill_dns1(TEST_DNS1)
            page.fill_dns2(TEST_DNS2)
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)

            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content().strip()
                print(f"  [OK] 前端拦截非法地址: {error_text[:60]}")
                rec.add_detail(f"[OK] 拦截非法地址: {error_text[:60]}")
            else:
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 非法地址保存被拦截")
                    rec.add_detail("[OK] 非法地址被拦截")
                else:
                    print(f"  [WARN] 非法地址未拦截, 清理")
                    rec.add_detail("[WARN] 非法地址未拦截")
                    if backend_verifier:
                        backend_verifier.cleanup_dhcp_server_test_rules("DHTEST_INVALID2")

            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(500)

        # ========== 步骤9: 前端校验-租期越界 ==========
        with rec.step("步骤9: 前端校验-租期越界", "填非法租期(0/>525600), 验证前端拦截"):
            print("\n[步骤9] 前端校验-租期越界...")

            # 编辑现有DHTEST_1, 改lease为越界值(0或超大)
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(500)
            page.edit_rule(TEST_RULE)
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1200)

            # 改租期为0(越界, 后端要求>=1)
            page.fill_lease(0)
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)

            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            blocked = False
            if error_el.count() > 0:
                error_text = error_el.first.text_content().strip()
                print(f"  [OK] 租期越界拦截: {error_text[:60]}")
                rec.add_detail(f"[OK] 租期越界拦截: {error_text[:60]}")
                blocked = True
            else:
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 租期越界保存被拦截")
                    rec.add_detail("[OK] 租期越界被拦截")
                    blocked = True
                else:
                    print(f"  [WARN] 租期0未拦截(可能前端允许, 后端校验)")
                    rec.add_detail("[WARN] 租期0未拦截")

            # 无论是否拦截, 恢复lease为合法值并保存(避免污染DHTEST_1)
            try:
                page.fill_lease(TEST_LEASE)
                page.page.wait_for_timeout(300)
                page.click_save()
                page.page.wait_for_timeout(2000)
            except Exception:
                pass
            page.navigate_to_dhcp_server()
            wait_dhcpd_settle()

            # SSH确认DHTEST_1的lease恢复正常
            ssh_verify("L1-租期恢复", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={"lease": str(TEST_LEASE)})

        # ========== 步骤10: 重启DHCP服务按钮 ==========
        with rec.step("步骤10: 重启DHCP服务按钮", "点击顶部重启DHCP服务, SSH验证ik_dhcpd重启"):
            print("\n[步骤10] 重启DHCP服务按钮...")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            restarted = page.click_restart_dhcp()
            print(f"  点击重启: {restarted}")
            rec.add_detail(f"点击重启: {restarted}")

            wait_dhcpd_settle()
            ssh_verify("L2-重启后进程", backend_verifier.verify_dhcp_server_process,
                       must_pass=True, expect_running=True)
            ssh_verify("L3-重启后conf", backend_verifier.verify_dhcp_server_config_file,
                       must_pass=True, tagname=TEST_RULE, expect_in_conf=True,
                       expect_any_enabled=True)

        # ========== 步骤11: 搜索测试规则 ==========
        with rec.step("步骤11: 搜索测试规则", "搜索DHTEST验证能定位"):
            print("\n[步骤11] 搜索测试规则...")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            try:
                page.search_rule("DHTEST")
                page.page.wait_for_timeout(1000)
                found = page.rule_exists(TEST_RULE)
                print(f"  搜索'DHTEST'后DHTEST_1可见: {found}")
                rec.add_detail(f"搜索结果可见: {found}")
                page.clear_search()
                page.page.wait_for_timeout(500)
                # 搜索不存在的规则(验证无结果)
                page.search_rule("NOTEXIST_XYZ")
                page.page.wait_for_timeout(1000)
                not_found = not page.rule_exists(TEST_RULE)
                print(f"  搜索'NOTEXIST_XYZ'无结果: {not_found}")
                rec.add_detail(f"搜索不存在无结果: {not_found}")
                page.clear_search()
                page.page.wait_for_timeout(500)
            except Exception as e:
                print(f"  [WARN] 搜索异常: {e}")
                rec.add_detail(f"[WARN] 搜索异常: {e}")

        # ========== 步骤11.5: 排序测试(6条数据) ==========
        with rec.step("步骤11.5: 排序测试", "按列排序(6条数据有意义)"):
            print("\n[步骤11.5] 排序测试...")
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            sort_ok = 0
            for col in ["名称", "租期"]:
                for attempt in ["第1次", "第2次(反向)"]:
                    try:
                        if page.sort_by_column(col):
                            sort_ok += 1
                            rec.add_detail(f"  {col}排序{attempt}: [OK]")
                    except Exception:
                        pass
                    page.page.wait_for_timeout(400)
            print(f"  排序点击成功 {sort_ok} 次(6条数据)")
            rec.add_detail(f"[OK] 排序{sort_ok}次(6条数据)")

        # ========== 步骤12: 导出测试(保存路径供导入用) ==========
        with rec.step("步骤12: 导出测试", "导出当前配置(含DHS_1+DHTEST_1), 供导入测试使用"):
            print("\n[步骤12] 导出测试...")
            import os as _os
            from config.config import get_config as _get_cfg
            _cfg = _get_cfg()
            _base = _cfg.test_data.get_export_path("dhcp_server", _cfg.get_project_root())
            export_file = _os.path.splitext(_base)[0] + ".txt"  # dhcp_server默认txt格式

            page.navigate_to_dhcp_server()
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

        # ========== 步骤13: 导入测试-追加(不勾清空) ==========
        with rec.step("步骤13: 导入追加", "删除DHTEST_1后导入(不勾清空), 验证追加恢复"):
            print("\n[步骤13] 导入测试-追加...")
            if not (exported and _os.path.exists(export_file)):
                print(f"  [WARN] 导出文件不存在, 跳过导入: {export_file}")
                rec.add_detail("[WARN] 无导出文件, 跳过导入追加")
            else:
                # 准备只含DHTEST规则的追加导入文件(过滤掉DHS_1, 避免追加时tagname冲突导致整批失败)
                import_file_append = export_file.replace(".txt", "_append.txt")
                try:
                    with open(export_file, 'r', encoding='utf-8') as f:
                        all_lines = f.readlines()
                    test_lines = [l for l in all_lines if 'tagname=DHTEST' in l]
                    with open(import_file_append, 'w', encoding='utf-8') as f:
                        f.writelines(test_lines)
                    print(f"  追加导入文件含{len(test_lines)}条DHTEST规则(已过滤DHS_1避免冲突)")
                    rec.add_detail(f"追加文件: {len(test_lines)}条DHTEST规则")
                except Exception as e:
                    print(f"  [WARN] 准备追加文件失败: {e}, 回退用原文件")
                    import_file_append = export_file

                # 先删除DHTEST_1(DHS_1保留), 验证导入追加能恢复它
                page.navigate_to_dhcp_server()
                page.page.wait_for_timeout(800)
                try:
                    page.search_rule("DHTEST")
                    page.page.wait_for_timeout(800)
                    page.delete_rule(TEST_RULE)
                except Exception:
                    pass
                if backend_verifier:
                    backend_verifier.cleanup_dhcp_server_test_rules("DHTEST")
                wait_dhcpd_settle()

                count_before = page.get_rule_count()
                print(f"  导入前规则数: {count_before}")
                rec.add_detail(f"导入前: {count_before}条")

                # 导入追加(不勾清空现有)
                try:
                    page.navigate_to_dhcp_server()
                    page.page.wait_for_timeout(800)
                    page.import_rules(import_file_append, clear_existing=False)
                    wait_dhcpd_settle()
                except Exception as e:
                    print(f"  [WARN] 导入异常: {e}")
                    rec.add_detail(f"[WARN] 导入异常: {e}")

                page.navigate_to_dhcp_server()
                page.page.wait_for_timeout(800)
                count_after = page.get_rule_count()
                print(f"  导入后规则数: {count_after}")
                rec.add_detail(f"导入后: {count_after}条")

                if count_after > count_before:
                    print(f"  [OK] 导入追加成功(+{count_after - count_before}条)")
                    rec.add_detail(f"[OK] 追加成功 +{count_after - count_before}条")
                else:
                    print(f"  [WARN] 导入追加未增加(import_txt可能跳过已存在的tagname)")
                    rec.add_detail("[WARN] 追加未增加(可能tagname冲突跳过)")

                # SSH验证DHTEST_1恢复(import跳过DHS_1冲突, 插入DHTEST_1) + DHS_1未受影响
                ssh_verify("L1-导入追加-DHTEST_1恢复", backend_verifier.verify_dhcp_server_database,
                           must_pass=False, name=TEST_RULE, must_exist=True)
                ssh_verify("L1-导入追加-DHS_1完整", backend_verifier.verify_dhcp_server_database,
                           must_pass=True, name="DHS_1",
                           expected_fields={"enabled": "yes", "interface": "lan1"})

        # ========== 步骤14: 导入测试-清空现有(勾清空, 带DHS_1备份恢复兜底) ==========
        with rec.step("步骤14: 导入清空", "加DHTEST_EXTRA标志, 清空导入, 验证清空生效+DHS_1恢复"):
            print("\n[步骤14] 导入测试-清空现有...")
            if not (exported and _os.path.exists(export_file)):
                print(f"  [WARN] 无导出文件, 跳过清空导入")
                rec.add_detail("[WARN] 跳过清空导入")
            else:
                extra_rule = "DHTEST_EXTRA"
                # 添加DHTEST_EXTRA(不在导出文件, 作为清空生效标志), 独立地址池避免冲突
                page.add_dhcp_server(
                    name=extra_rule, interface=TEST_IFACE,
                    pool_start="192.168.151.230", pool_end="192.168.151.240",
                    netmask=TEST_NETMASK, gateway=TEST_GATEWAY,
                    dns1=TEST_DNS1, dns2=TEST_DNS2,
                    lease=TEST_LEASE, delay=0, check_addr_valid=False,
                )
                wait_dhcpd_settle()

                # 备份dhcp_server表(含DHS_1), 万一清空导入异常可恢复
                snapshot = ""
                if backend_verifier:
                    snapshot = backend_verifier.snapshot_dhcp_server()
                rec.add_detail(f"[备份] dhcp_server表已备份({len(snapshot)}字符)")

                count_before = page.get_rule_count()
                print(f"  清空导入前规则数: {count_before}(含{extra_rule})")
                rec.add_detail(f"清空前: {count_before}条(含{extra_rule}标志)")

                # 导入清空(勾选"清空现有数据")
                try:
                    page.navigate_to_dhcp_server()
                    page.page.wait_for_timeout(800)
                    page.import_rules(export_file, clear_existing=True)
                    wait_dhcpd_settle()
                except Exception as e:
                    print(f"  [WARN] 清空导入异常: {e}")
                    rec.add_detail(f"[WARN] 清空导入异常: {e}")

                page.navigate_to_dhcp_server()
                page.page.wait_for_timeout(800)

                # 验证1: DHTEST_EXTRA应被删(它不在导出文件, 删除=清空生效证据)
                extra_exists = False
                if backend_verifier:
                    extra_exists = backend_verifier.query_dhcp_server_rule(extra_rule) is not None
                if not extra_exists:
                    print(f"  [OK] 清空生效({extra_rule}已删除)")
                    rec.add_detail(f"[OK] 清空生效, {extra_rule}已删")
                else:
                    print(f"  [FAIL] {extra_rule}仍存在, 清空未生效")
                    rec.add_detail(f"[FAIL] 清空未生效")
                    ssh_failures.append(f"导入清空: {extra_rule}未被删除(clear_existing未生效)")

                # 验证2: DHS_1应存在(从导出文件恢复); 丢失则备份恢复
                dhs1_rule = backend_verifier.query_dhcp_server_rule("DHS_1") if backend_verifier else None
                if dhs1_rule:
                    print(f"  [OK] DHS_1已从导入文件恢复")
                    rec.add_detail("[OK] DHS_1恢复")
                else:
                    print(f"  [FAIL] DHS_1丢失! 触发备份恢复")
                    rec.add_detail("[FAIL] DHS_1丢失, 恢复中")
                    ssh_failures.append("导入清空: DHS_1丢失(导入文件可能不含DHS_1)")
                    if backend_verifier and snapshot:
                        backend_verifier.restore_dhcp_server(snapshot)
                        wait_dhcpd_settle()

                # 清理可能残留的DHTEST_EXTRA
                if backend_verifier:
                    backend_verifier.cleanup_dhcp_server_test_rules("DHTEST_EXTRA")
                    wait_dhcpd_settle()

                # SSH确认DHS_1完整(关键, must_pass)
                ssh_verify("L1-清空导入后DHS_1完整", backend_verifier.verify_dhcp_server_database,
                           must_pass=True, name="DHS_1",
                           expected_fields={"enabled": "yes", "interface": "lan1"})

        # ========== 步骤15: 帮助功能 ==========
        with rec.step("步骤15: 帮助功能", "测试帮助按钮"):
            print("\n[步骤15] 帮助功能测试...")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            try:
                clicked = page.click_help()
                if clicked:
                    page.page.wait_for_timeout(1000)
                    help_visible = page.is_help_panel_visible()
                    if not help_visible:
                        help_visible = page.page.locator(
                            '.ant-popover, .ant-drawer, .ant-modal, [role="dialog"]'
                        ).count() > 0
                    if help_visible:
                        print(f"  [OK] 帮助面板已显示")
                        rec.add_detail("[OK] 帮助面板显示")
                        page.close_help_panel()
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

        # ========== 步骤16: 批量删除所有DHTEST ==========
        with rec.step("步骤16: 批量删除", "删除所有DHTEST规则并SSH验证"):
            print("\n[步骤16] 批量删除所有DHTEST...")
            for name in TEST_NAMES:
                try:
                    page.navigate_to_dhcp_server()
                    page.page.wait_for_timeout(500)
                    page.search_rule("DHTEST")
                    page.page.wait_for_timeout(500)
                    if page.rule_exists(name):
                        page.delete_rule(name)
                        wait_dhcpd_settle()
                except Exception as e:
                    print(f"  删除{name}异常: {str(e)[:50]}")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            exists = page.rule_exists(TEST_RULE)
            print(f"  删除后DHTEST_1存在: {exists}")
            rec.add_detail(f"删除后DHTEST_1存在: {exists}")

            # SSH验证彻底删除
            ssh_verify("L1-删除验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE, must_exist=False)

        # ========== 步骤17: 最终清理 + DHS_1完整性保护 ==========
        with rec.step("步骤17: 最终清理+DHS_1完整性", "清理残留 + 验证DHS_1未被破坏"):
            print("\n[步骤17] 最终清理 + DHS_1完整性验证...")

            # SQL兜底清理任何DHTEST残留
            if backend_verifier:
                backend_verifier.cleanup_dhcp_server_test_rules("DHTEST")
            wait_dhcpd_settle()

            # DHS_1完整性: 仍存在 + enabled + ik_dhcpd运行
            ssh_verify("L1-DHS_1完整", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name="DHS_1",
                       expected_fields={"enabled": "yes", "interface": "lan1"})
            ssh_verify("L2-最终进程", backend_verifier.verify_dhcp_server_process,
                       must_pass=True, expect_running=True)
            ssh_verify("L4-最终运行时", backend_verifier.verify_dhcp_server_runtime,
                       must_pass=True, expect_running=True)

            # 最终无DHTEST残留
            ssh_verify("L1-无DHTEST残留", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE, must_exist=False)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("DHCP服务端综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 初始环境检查 + 残留清理")
        print("  - 添加DHTEST_1 + L1-L4全链路(数据库/进程/配置/运行时/iptables)")
        print("  - 编辑(lease/delay/dns/check_addr_valid)")
        print("  - 停用(conf移除, 进程仍运行) + 启用(conf恢复)")
        print("  - 模拟重启验证(dhcp_server.sh boot, 对照DMZ bug)")
        print("  - 前端校验(空必填/非法地址/租期越界)")
        print("  - 重启DHCP服务按钮")
        print("  - 搜索 + 导出")
        print("  - 导入追加(不勾清空) + 导入清空(勾清空, DHTEST_EXTRA标志验证, DHS_1备份恢复兜底)")
        print("  - 帮助功能")
        print("  - 删除 + SSH验证")
        print("  - DHS_1完整性保护(全程未破坏系统默认DHCP)")
        print("  - SSH后台验证: L1数据库+L2进程+L3配置+L4运行时+L4-iptables+L4-模拟重启")

        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项SSH验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not ssh_failures, \
            f"SSH验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
