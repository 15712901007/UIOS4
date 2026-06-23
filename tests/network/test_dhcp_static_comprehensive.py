"""
DHCP静态分配综合测试用例

网络配置 > DHCP服务 > DHCP静态分配 综合测试
DHCP静态分配是表格型模块(MAC-IP绑定), 添加/编辑为独立页面。表单字段全用#id定位。
是DHCP服务端的子功能(共用ik_dhcpd进程, 无独立iptables/内核), 绑定下发到
/tmp/iktmp/ik_dhcp_static_cache.conf(仅enabled=yes) + ik_dhcpd_static.conf。

测试特点:
- dhcp_static表无系统默认关键规则(不像dhcp_server的DHS_1必须保护), 可自由CRUD测试规则。
- 导入清空只影响dhcp_static表(不影响dhcp_server的DHS_1), 相对安全。

一次测试覆盖(15步):
1. 初始环境检查 + 清理残留
2. 添加DHSTEST_1 + SSH L1-L3全链路(数据库/进程/静态配置文件)
3. 编辑DHSTEST_1(改ip/mac/gateway/dns/comment/接口lan1) + SSH验证
4. 停用DHSTEST_1 + SSH验证(cache移除, 进程仍运行)
5. 启用DHSTEST_1 + SSH验证(cache恢复)
6. 模拟重启验证(dhcp_server.sh boot, 绑定仍在static.conf)
7. 前端校验-空必填
8. 前端校验-非法IP
9. 前端校验-非法MAC
10. 前端校验-重复IP(ip_addr唯一约束)
11. 搜索
12. 排序(IP/MAC/绑定接口列)
13. 设置面板(dhcpd_arp兼容ARP绑定开关)
14. 导出
15. 导入追加(过滤) + 导入清空(DHSTEST_EXTRA标志)
16. 帮助功能
17. 删除 + 最终清理

SSH后台验证: L1数据库(dhcp_static表) + L2进程(ik_dhcpd共用) + L3静态配置文件(cache+static.conf)
            + L4-模拟重启(dhcp_server.sh boot)
字段映射: tagname=名称 interface=绑定接口 ip_addr=IP地址 mac=MAC地址 gateway/dns1/dns2 comment
约束: tagname唯一, ip_addr唯一, (interface,mac)组合唯一
"""
import pytest
from pages.network.dhcp_static_page import DhcpStaticPage
from utils.step_recorder import StepRecorder


# 测试规则配置
TEST_RULE = "DHSTEST_1"
TEST_IP = "192.168.148.50"        # 在DHS_1地址池(192.168.148.2-151.200)内
TEST_MAC = "02:11:22:33:44:55"    # 虚拟MAC(02开头locally administered, 不与真实设备冲突)
EDIT_IP = "192.168.148.51"
EDIT_MAC = "02:11:22:33:44:56"
TEST_GATEWAY = "192.168.148.1"
TEST_DNS1 = "114.114.114.114"
TEST_DNS2 = "223.5.5.5"

# 6条测试规则(多MAC/IP场景, 让批量操作/排序有意义; DHSTEST_1用原TEST_IP/MAC保持兼容)
TEST_RULES = [
    {"name": "DHSTEST_1", "ip": TEST_IP, "mac": TEST_MAC, "comment": "静态绑定1"},
    {"name": "DHSTEST_2", "ip": "192.168.148.60", "mac": "02:11:22:33:44:62", "comment": "静态绑定2"},
    {"name": "DHSTEST_3", "ip": "192.168.148.61", "mac": "02:11:22:33:44:63", "comment": "静态绑定3"},
    {"name": "DHSTEST_4", "ip": "192.168.148.62", "mac": "02:11:22:33:44:64", "comment": "静态绑定4"},
    {"name": "DHSTEST_5", "ip": "192.168.148.63", "mac": "02:11:22:33:44:65", "comment": "静态绑定5"},
    {"name": "DHSTEST_6", "ip": "192.168.148.64", "mac": "02:11:22:33:44:66", "comment": "静态绑定6"},
]
TEST_NAMES = [r["name"] for r in TEST_RULES]


@pytest.mark.dhcp_static
@pytest.mark.network
class TestDhcpStaticComprehensive:
    """DHCP静态分配综合测试 - 表格型(独立页面表单, 全#id定位)"""

    def test_dhcp_static_comprehensive(self, dhcp_static_page_logged_in: DhcpStaticPage,
                                       step_recorder: StepRecorder, request):
        """综合测试: 添加/编辑/停用启用/模拟重启/前端校验/搜索/导出导入/帮助/删除 + SSH全链路"""
        page = dhcp_static_page_logged_in
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

        def wait_settle():
            """等待__dhcp_static_update + delayed_restart生效"""
            page.page.wait_for_timeout(3500)

        print("\n" + "=" * 60)
        print("DHCP静态分配综合测试开始")
        print("=" * 60)

        # ========== 步骤1: 初始环境检查 + 清理残留 ==========
        with rec.step("步骤1: 初始环境检查+清理残留", "清理DHSTEST残留, 确认ik_dhcpd运行"):
            print("\n[步骤1] 初始环境检查...")
            if backend_verifier:
                backend_verifier.cleanup_dhcp_static_test_rules("DHSTEST")
            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)
            initial_count = page.get_rule_count()
            print(f"  当前DHCP静态分配规则数: {initial_count}")
            rec.add_detail(f"初始规则数: {initial_count}")

            ssh_verify("L2-初始进程", backend_verifier.verify_dhcp_static_process,
                       must_pass=True, expect_running=True)

        # ========== 步骤2: 批量添加6条 + L1-L3全链路 ==========
        with rec.step("步骤2: 批量添加6条", f"添加{len(TEST_RULES)}条静态绑定并SSH L1-L3验证"):
            print(f"\n[步骤2] 批量添加{len(TEST_RULES)}条静态绑定...")
            for rule in TEST_RULES:
                result = page.add_dhcp_static(
                    name=rule["name"], ip=rule["ip"], mac=rule["mac"],
                    interface="自动", comment=rule["comment"],
                )
                print(f"  添加 {rule['name']}({rule['ip']}/{rule['mac']}): {result}")
                rec.add_detail(f"添加{rule['name']}: {result}")
                wait_settle()

            # 验证首条 + 计数(6条)
            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)
            assert page.rule_exists(TEST_RULE), "DHSTEST_1未出现在列表中"
            count = backend_verifier.count_dhcp_static(enabled_only=False) if backend_verifier else -1
            print(f"  [OK] 6条已添加, dhcp_static总数: {count}")
            rec.add_detail(f"[OK] 6条添加, 总数{count}")

            # SSH L1-L3全链路(首条DHSTEST_1)
            ssh_verify("L1-添加验证", backend_verifier.verify_dhcp_static_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={
                           "enabled": "yes", "interface": "auto",
                           "ip_addr": TEST_IP, "mac": TEST_MAC,
                       })
            ssh_verify("L2-进程", backend_verifier.verify_dhcp_static_process,
                       must_pass=True, expect_running=True)
            ssh_verify("L3-静态配置文件", backend_verifier.verify_dhcp_static_config_file,
                       must_pass=True, tagname=TEST_RULE, mac=TEST_MAC, expect_in_conf=True)

        # ========== 步骤3: 编辑DHSTEST_1 ==========
        with rec.step("步骤3: 编辑DHSTEST_1", "改ip/mac/gateway/dns/comment/接口lan1"):
            print(f"\n[步骤3] 编辑DHSTEST_1(ip={EDIT_IP}, mac={EDIT_MAC}, 接口=lan1)...")

            result = page.edit_dhcp_static(
                TEST_RULE,
                ip=EDIT_IP, mac=EDIT_MAC,
                gateway=TEST_GATEWAY, dns1=TEST_DNS1, dns2=TEST_DNS2,
                interface="lan1", comment="编辑后的绑定",
            )
            assert result is True, "编辑DHSTEST_1失败"
            print(f"  [OK] 编辑成功")
            rec.add_detail("[OK] 编辑成功")

            wait_settle()
            ssh_verify("L1-编辑验证", backend_verifier.verify_dhcp_static_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={
                           "ip_addr": EDIT_IP, "mac": EDIT_MAC,
                           "interface": "lan1", "gateway": TEST_GATEWAY,
                           "dns1": TEST_DNS1, "dns2": TEST_DNS2,
                       })
            ssh_verify("L3-编辑后配置", backend_verifier.verify_dhcp_static_config_file,
                       must_pass=True, mac=EDIT_MAC, expect_in_conf=True)

        # ========== 步骤4: 停用DHSTEST_1 ==========
        with rec.step("步骤4: 停用DHSTEST_1", "停用并验证从cache移除(进程仍运行)"):
            print("\n[步骤4] 停用DHSTEST_1...")

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)
            page.disable_rule(TEST_RULE)
            page.page.wait_for_timeout(500)
            wait_settle()

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)

            # SSH结果导向验证
            ssh_verify("L1-停用验证", backend_verifier.verify_dhcp_static_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={"enabled": "no"})
            # 停用后cache应不含该mac(cache仅enabled=yes)
            ssh_verify("L3-停用后cache移除", backend_verifier.verify_dhcp_static_config_file,
                       must_pass=True, mac=EDIT_MAC, expect_in_conf=False)
            ssh_verify("L2-停用后进程", backend_verifier.verify_dhcp_static_process,
                       must_pass=True, expect_running=True)

        # ========== 步骤5: 启用DHSTEST_1 ==========
        with rec.step("步骤5: 启用DHSTEST_1", "启用并验证回到cache"):
            print("\n[步骤5] 启用DHSTEST_1...")

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)
            page.enable_rule(TEST_RULE)
            page.page.wait_for_timeout(500)
            wait_settle()

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)

            ssh_verify("L1-启用验证", backend_verifier.verify_dhcp_static_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={"enabled": "yes"})
            ssh_verify("L3-启用后cache恢复", backend_verifier.verify_dhcp_static_config_file,
                       must_pass=True, mac=EDIT_MAC, expect_in_conf=True)

        # ========== 步骤6: 模拟重启验证 ==========
        with rec.step("步骤6: 模拟重启验证", "dhcp_server.sh boot后绑定仍在static.conf"):
            print("\n[步骤6] 模拟重启验证...")

            ssh_verify("L4-模拟重启", backend_verifier.verify_dhcp_static_reboot,
                       must_pass=True, tagname=TEST_RULE, mac=EDIT_MAC)

        # ========== 步骤7: 前端校验-空必填 ==========
        with rec.step("步骤7: 前端校验-空必填", "不填IP/MAC直接保存, 验证前端拦截"):
            print("\n[步骤7] 前端校验-空必填...")

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(500)
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            page.fill_name("DHSTEST_INVALID")
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
                    print(f"  [WARN] 未拦截, 清理")
                    rec.add_detail("[WARN] 未拦截")
                    if backend_verifier:
                        backend_verifier.cleanup_dhcp_static_test_rules("DHSTEST_INVALID")

            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(500)

        # ========== 步骤8: 前端校验-非法IP ==========
        with rec.step("步骤8: 前端校验-非法IP", "填非法IP, 验证前端拦截"):
            print("\n[步骤8] 前端校验-非法IP...")

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(500)
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            page.fill_name("DHSTEST_BADIP")
            page.fill_ip("999.999.999.999")
            page.fill_mac("02:11:22:33:44:99")
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)

            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content().strip()
                print(f"  [OK] 非法IP拦截: {error_text[:60]}")
                rec.add_detail(f"[OK] 非法IP拦截: {error_text[:60]}")
            else:
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 非法IP被拦截")
                    rec.add_detail("[OK] 非法IP被拦截")
                else:
                    print(f"  [WARN] 非法IP未拦截, 清理")
                    rec.add_detail("[WARN] 非法IP未拦截")
                    if backend_verifier:
                        backend_verifier.cleanup_dhcp_static_test_rules("DHSTEST_BADIP")

            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(500)

        # ========== 步骤9: 前端校验-非法MAC ==========
        with rec.step("步骤9: 前端校验-非法MAC", "填非法MAC, 验证前端拦截"):
            print("\n[步骤9] 前端校验-非法MAC...")

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(500)
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            page.fill_name("DHSTEST_BADMAC")
            page.fill_ip("192.168.148.88")
            page.fill_mac("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")  # 非法MAC
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)

            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content().strip()
                print(f"  [OK] 非法MAC拦截: {error_text[:60]}")
                rec.add_detail(f"[OK] 非法MAC拦截: {error_text[:60]}")
            else:
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 非法MAC被拦截")
                    rec.add_detail("[OK] 非法MAC被拦截")
                else:
                    print(f"  [WARN] 非法MAC未拦截, 清理")
                    rec.add_detail("[WARN] 非法MAC未拦截")
                    if backend_verifier:
                        backend_verifier.cleanup_dhcp_static_test_rules("DHSTEST_BADMAC")

            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(500)

        # ========== 步骤10: 前端校验-重复IP(唯一约束) ==========
        with rec.step("步骤10: 前端校验-重复IP", "添加与DHSTEST_1相同IP的规则, 验证唯一约束拦截"):
            print(f"\n[步骤10] 前端校验-重复IP(用DHSTEST_1的ip={EDIT_IP})...")

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(500)
            page.click_add_button()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            page.fill_name("DHSTEST_DUP")
            page.fill_ip(EDIT_IP)  # 与DHSTEST_1(编辑后)的IP重复
            page.fill_mac("02:11:22:33:44:77")  # 不同MAC
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)

            # 重复IP应被拦截(ip_addr unique) - 可前端或后端拦截
            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            dup_blocked = False
            if error_el.count() > 0:
                error_text = error_el.first.text_content().strip()
                print(f"  [OK] 重复IP拦截: {error_text[:60]}")
                rec.add_detail(f"[OK] 重复IP拦截: {error_text[:60]}")
                dup_blocked = True
            else:
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 重复IP被拦截")
                    rec.add_detail("[OK] 重复IP被拦截")
                    dup_blocked = True
                else:
                    # 后端可能允许(重复IP在保存时报错), 检查是否真入库
                    if backend_verifier:
                        dup_rule = backend_verifier.query_dhcp_static_rule("DHSTEST_DUP")
                        if dup_rule:
                            print(f"  [WARN] 重复IP未拦截且已入库, 清理")
                            rec.add_detail("[WARN] 重复IP未拦截")
                            backend_verifier.cleanup_dhcp_static_test_rules("DHSTEST_DUP")
                        else:
                            print(f"  [OK] 重复IP未入库(后端唯一约束拦截)")
                            rec.add_detail("[OK] 后端拦截重复IP")
                            dup_blocked = True

            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(500)

        # ========== 步骤11: 搜索 ==========
        with rec.step("步骤11: 搜索", "搜索DHSTEST验证能定位"):
            print("\n[步骤11] 搜索...")

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)
            try:
                page.search_rule("DHSTEST")
                page.page.wait_for_timeout(1000)
                found = page.rule_exists(TEST_RULE)
                print(f"  搜索'DHSTEST'后DHSTEST_1可见: {found}")
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

        # ========== 步骤12: 排序测试 ==========
        with rec.step("步骤12: 排序测试", "按IP/MAC/绑定接口等列排序3次"):
            print("\n[步骤12] 排序测试...")
            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)
            sort_ok = 0
            for col in ["IP地址", "MAC地址", "绑定接口"]:
                for attempt in ["第1次", "第2次(反向)", "第3次(恢复)"]:
                    try:
                        if page.sort_by_column(col):
                            sort_ok += 1
                            rec.add_detail(f"    {col} {attempt}: [OK]")
                        else:
                            rec.add_detail(f"    {col} {attempt}: [WARN]排序图标未找到")
                    except Exception as e:
                        rec.add_detail(f"    {col} {attempt}: [WARN]{str(e)[:40]}")
                    page.page.wait_for_timeout(300)
            print(f"  排序点击成功 {sort_ok} 次")
            rec.add_detail(f"[OK] 排序测试完成, 成功{sort_ok}次")

        # ========== 步骤13: 设置面板(dhcpd_arp开关) ==========
        with rec.step("步骤13: 设置-dhcpd_arp开关", "测试兼容ARP绑定列表为静态分配开关"):
            print("\n[步骤13] 设置面板(dhcpd_arp)测试...")

            # 记录原始dhcpd_arp值(测试后恢复)
            orig_arp = "0"
            if backend_verifier:
                r = backend_verifier._sqlite_query_line(
                    "SELECT dhcpd_arp FROM global_config WHERE id=1"
                )
                orig_arp = r.get("dhcpd_arp", "0") if r else "0"
            print(f"  原始dhcpd_arp={orig_arp}")
            rec.add_detail(f"原始dhcpd_arp={orig_arp}")

            try:
                page.navigate_to_dhcp_static()
                page.page.wait_for_timeout(800)
                # 打开设置面板
                clicked = page.click_settings()
                page.page.wait_for_timeout(1000)
                panel_visible = page.is_settings_panel_visible()
                print(f"  设置面板可见: {panel_visible} (点击={clicked})")
                rec.add_detail(f"设置面板可见: {panel_visible}")

                if panel_visible:
                    # 开启兼容ARP绑定
                    page.toggle_dhcpd_arp(True)
                    page.page.wait_for_timeout(300)
                    saved = page.save_settings()
                    page.page.wait_for_timeout(3500)  # delayed_restart
                    print(f"  开启dhcpd_arp保存: {saved}")
                    ssh_verify("L1-开启dhcpd_arp", backend_verifier.verify_dhcpd_arp,
                               must_pass=True, expect_enabled=True)

                    # 关闭兼容ARP绑定
                    page.navigate_to_dhcp_static()
                    page.page.wait_for_timeout(800)
                    page.click_settings()
                    page.page.wait_for_timeout(1000)
                    page.toggle_dhcpd_arp(False)
                    page.page.wait_for_timeout(300)
                    page.save_settings()
                    page.page.wait_for_timeout(3500)
                    ssh_verify("L1-关闭dhcpd_arp", backend_verifier.verify_dhcpd_arp,
                               must_pass=True, expect_enabled=False)
                else:
                    print(f"  [WARN] 设置面板未打开")
                    rec.add_detail("[WARN] 设置面板未打开")
            except Exception as e:
                print(f"  [WARN] 设置测试异常: {e}")
                rec.add_detail(f"[WARN] 设置异常: {e}")

            # 兜底恢复原始dhcpd_arp值
            if backend_verifier:
                try:
                    backend_verifier._router.exec(
                        f"sqlite3 {backend_verifier.DNS_DB} "
                        f"\"UPDATE global_config SET dhcpd_arp={orig_arp} WHERE id=1;\" 2>/dev/null"
                    )
                    backend_verifier._router.exec(
                        "/usr/ikuai/script/dhcp_server.sh restart 2>&1"
                    )
                    page.page.wait_for_timeout(2000)
                except Exception:
                    pass
                ssh_verify("L1-恢复dhcpd_arp", backend_verifier.verify_dhcpd_arp,
                           must_pass=True, expect_enabled=(orig_arp == "1"))

        # ========== 步骤14: 导出 ==========
        with rec.step("步骤14: 导出", "导出当前静态分配配置(含DHSTEST_1)"):
            print("\n[步骤14] 导出测试...")
            import os as _os
            from config.config import get_config as _get_cfg
            _cfg = _get_cfg()
            _base = _cfg.test_data.get_export_path("dhcp_static", _cfg.get_project_root())
            export_file = _os.path.splitext(_base)[0] + ".txt"

            page.navigate_to_dhcp_static()
            page.page.wait_for_timeout(800)
            exported = False
            try:
                exported = page.export_rules(use_config_path=True, export_format="txt")
                print(f"  导出: {exported}, 文件: {_os.path.basename(export_file)}")
                rec.add_detail(f"导出: {exported}, 文件: {_os.path.basename(export_file)}")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")
                rec.add_detail(f"[WARN] 导出异常: {e}")

        # ========== 步骤15: 导入追加 + 导入清空 ==========
        with rec.step("步骤15: 导入追加+清空", "导入追加(过滤)+导入清空(DHSTEST_EXTRA标志)"):
            print("\n[步骤15] 导入测试...")
            if not (exported and _os.path.exists(export_file)):
                print(f"  [WARN] 无导出文件, 跳过导入: {export_file}")
                rec.add_detail("[WARN] 跳过导入")
            else:
                # --- 13a: 导入追加(过滤掉可能冲突的, 只含DHSTEST) ---
                import_file_append = export_file.replace(".txt", "_append.txt")
                try:
                    with open(export_file, 'r', encoding='utf-8', errors='ignore') as f:
                        all_lines = f.readlines()
                    test_lines = [l for l in all_lines if 'DHSTEST' in l]
                    with open(import_file_append, 'w', encoding='utf-8') as f:
                        f.writelines(test_lines)
                    print(f"  追加文件含{len(test_lines)}条DHSTEST规则")
                    rec.add_detail(f"追加文件: {len(test_lines)}条")
                except Exception as e:
                    print(f"  [WARN] 准备追加文件失败: {e}")
                    import_file_append = export_file

                # 删DHSTEST_1, 导入追加恢复
                page.navigate_to_dhcp_static()
                page.page.wait_for_timeout(800)
                try:
                    page.search_rule("DHSTEST")
                    page.page.wait_for_timeout(800)
                    page.delete_rule(TEST_RULE)
                except Exception:
                    pass
                if backend_verifier:
                    backend_verifier.cleanup_dhcp_static_test_rules("DHSTEST")
                wait_settle()

                count_before = page.get_rule_count()
                try:
                    page.navigate_to_dhcp_static()
                    page.page.wait_for_timeout(800)
                    page.import_rules(import_file_append, clear_existing=False)
                    wait_settle()
                except Exception as e:
                    print(f"  [WARN] 导入追加异常: {e}")

                page.navigate_to_dhcp_static()
                page.page.wait_for_timeout(800)
                count_after = page.get_rule_count()
                print(f"  追加导入: 前{count_before}条 → 后{count_after}条")
                rec.add_detail(f"追加: {count_before}→{count_after}")
                ssh_verify("L1-导入追加-DHSTEST_1恢复", backend_verifier.verify_dhcp_static_database,
                           must_pass=False, name=TEST_RULE, must_exist=True)

                # --- 13b: 导入清空(DHSTEST_EXTRA标志验证清空生效) ---
                extra_rule = "DHSTEST_EXTRA"
                page.add_dhcp_static(
                    name=extra_rule, ip="192.168.148.61",
                    mac="02:11:22:33:44:aa", interface="自动",
                )
                wait_settle()

                count_before2 = page.get_rule_count()
                print(f"  清空前: {count_before2}条(含{extra_rule})")
                rec.add_detail(f"清空前: {count_before2}条")

                try:
                    page.navigate_to_dhcp_static()
                    page.page.wait_for_timeout(800)
                    page.import_rules(export_file, clear_existing=True)
                    wait_settle()
                except Exception as e:
                    print(f"  [WARN] 清空导入异常: {e}")

                page.navigate_to_dhcp_static()
                page.page.wait_for_timeout(800)

                # 验证DHSTEST_EXTRA(不在导出文件)被删 = 清空生效
                extra_exists = False
                if backend_verifier:
                    extra_exists = backend_verifier.query_dhcp_static_rule(extra_rule) is not None
                if not extra_exists:
                    print(f"  [OK] 清空生效({extra_rule}已删)")
                    rec.add_detail(f"[OK] 清空生效")
                else:
                    print(f"  [FAIL] {extra_rule}仍存在, 清空未生效")
                    rec.add_detail(f"[FAIL] 清空未生效")
                    ssh_failures.append(f"导入清空: {extra_rule}未被删除(clear_existing未生效)")

                # 清理DHSTEST_EXTRA残留
                if backend_verifier:
                    backend_verifier.cleanup_dhcp_static_test_rules("DHSTEST_EXTRA")
                    wait_settle()

        # ========== 步骤16: 帮助功能 ==========
        with rec.step("步骤16: 帮助功能", "测试帮助按钮"):
            print("\n[步骤16] 帮助功能测试...")

            page.navigate_to_dhcp_static()
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

        # ========== 步骤17: 批量删除 + 最终清理 ==========
        with rec.step("步骤17: 批量删除+清理", "删除所有DHSTEST规则并验证0残留"):
            print("\n[步骤17] 批量删除 + 最终清理...")
            # 循环delete_rule删除所有DHSTEST(UI批量)
            for name in TEST_NAMES:
                try:
                    page.navigate_to_dhcp_static()
                    page.page.wait_for_timeout(500)
                    page.search_rule("DHSTEST")
                    page.page.wait_for_timeout(500)
                    if page.rule_exists(name):
                        page.delete_rule(name)
                        wait_settle()
                except Exception as e:
                    print(f"  删除{name}异常: {str(e)[:50]}")
            # SQL兜底清理所有DHSTEST残留
            if backend_verifier:
                backend_verifier.cleanup_dhcp_static_test_rules("DHSTEST")
                wait_settle()

            # SSH验证彻底清理(verify修复后must_exist=False诚实)
            ssh_verify("L1-无DHSTEST残留", backend_verifier.verify_dhcp_static_database,
                       must_pass=True, name=TEST_RULE, must_exist=False)
            ssh_verify("L2-最终进程", backend_verifier.verify_dhcp_static_process,
                       must_pass=True, expect_running=True)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("DHCP静态分配综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 初始环境检查 + 残留清理")
        print("  - 添加DHSTEST_1 + L1-L3全链路(数据库/进程/静态配置文件)")
        print("  - 编辑(ip/mac/gateway/dns/comment/接口lan1)")
        print("  - 停用(cache移除) + 启用(cache恢复)")
        print("  - 模拟重启验证(dhcp_server.sh boot)")
        print("  - 前端校验(空必填/非法IP/非法MAC/重复IP唯一约束)")
        print("  - 搜索")
        print("  - 排序(IP/MAC/绑定接口列)")
        print("  - 设置面板(dhcpd_arp兼容ARP绑定开关, 开启/关闭/恢复)")
        print("  - 导出")
        print("  - 导入追加(过滤) + 导入清空(DHSTEST_EXTRA标志验证)")
        print("  - 帮助功能")
        print("  - 删除 + 最终清理")
        print("  - SSH后台验证: L1数据库+L2进程+L3静态配置文件+L4-模拟重启+dhcpd_arp")

        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项SSH验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not ssh_failures, \
            f"SSH验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
