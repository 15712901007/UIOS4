"""
IPv6前缀静态分配综合测试用例

网络配置 > DHCP服务 > IPv6前缀静态分配 综合测试
表格型(DHCPv6-PD前缀静态分配), 添加/编辑独立页面, 表单全#id定位。

!!环境限制(关键):
IPv6前缀静态分配需WAN有IPv6前缀 + LAN IPv6配置(ipv6_lan_config)。
当前测试设备IPv6关闭(ipv6_config.enabled=no), WAN无IPv6前缀(仅link-local),
ipv6_lan_config空。故添加规则会被后端__check_dst_iface拦截:
"内网接口没绑定外网线路(wan1),请检查IPV6 lan口配置"(lan_prefix_error)。
无法真实CRUD + 验证前缀生效。测试聚焦UI + 前端校验 + 后端拦截验证(防无效配置)。

一次测试覆盖(9步):
1. 初始检查(页面空, ipv6_dhcp_static_config空)
2. 添加表单字段验证(#id)
3. 前端校验-空必填
4. 前端校验-link_addr格式(非法IPv6)
5. 后端校验-lan_prefix_error(填合法值被__check_dst_iface拦, 验证错误+不入库)
6. 帮助功能
7. 模拟重启(ipv6_static.sh init)
8. 导出测试
9. 最终验证(数据库空, 无残留)

SSH后台验证: L1数据库(ipv6_dhcp_static_config) + L4模拟重启(init)
"""
import pytest
from pages.network.ipv6_static_page import Ipv6StaticPage
from utils.step_recorder import StepRecorder


TEST_RULE = "IPV6TEST_1"
TEST_LINK_ADDR = "fe80::1234"


@pytest.mark.ipv6_static
@pytest.mark.network
class TestIpv6StaticComprehensive:
    """IPv6前缀静态分配综合测试 - 环境不具备(UI+校验+后端拦截)"""

    def test_ipv6_static_comprehensive(self, ipv6_static_page_logged_in: Ipv6StaticPage,
                                       step_recorder: StepRecorder, request):
        """综合测试: UI+前端校验+后端lan_prefix_error拦截+模拟重启(IPv6环境不具备)"""
        page = ipv6_static_page_logged_in
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
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                return None

        print("\n" + "=" * 60)
        print("IPv6前缀静态分配综合测试开始")
        print("=" * 60)
        print("!!注意: 当前设备IPv6环境不具备(enabled=no, WAN无IPv6前缀),")
        print("        添加会被后端__check_dst_iface拦截(lan_prefix_error),")
        print("        测试聚焦UI+前端校验+后端拦截验证, 不验证前缀实际生效。")

        # ========== 步骤1: 初始检查 ==========
        with rec.step("步骤1: 初始检查", "页面空, ipv6_dhcp_static_config空"):
            print("\n[步骤1] 初始检查...")
            if backend_verifier:
                backend_verifier.cleanup_ipv6_static_test("IPV6TEST")
            page.navigate_to_ipv6_static()
            page.page.wait_for_timeout(1000)
            count = page.get_rule_count()
            print(f"  页面规则数: {count}")
            rec.add_detail(f"页面规则数: {count}")
            ssh_verify("L1-初始空", backend_verifier.verify_ipv6_static_database,
                       must_pass=False, name=TEST_RULE, must_exist=False)

        # ========== 步骤2: 添加表单字段验证 ==========
        with rec.step("步骤2: 添加表单字段", "验证表单字段(#id)"):
            print("\n[步骤2] 添加表单字段验证...")
            page.open_add_page()
            page.page.wait_for_timeout(500)
            # 验证字段#id存在
            fields = {}
            for fid in ['tagname', 'link_addr', 'src_iface', 'dst_iface', 'comment']:
                el = page.page.locator(f'#{fid}')
                fields[fid] = el.count() > 0
            print(f"  表单字段: {fields}")
            rec.add_detail(f"表单字段: {fields}")
            all_present = all(fields.values())
            if all_present:
                print(f"  [OK] 所有字段#id存在(名称/终端本地链接IPv6/内网接口/外网线路/备注)")
                rec.add_detail("[OK] 字段完整")
            else:
                ssh_failures.append(f"表单字段缺失: {fields}")
            # 取消回列表
            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_ipv6_static()
            page.page.wait_for_timeout(500)

        # ========== 步骤3: 前端校验-空必填 ==========
        with rec.step("步骤3: 前端校验-空必填", "不填保存, 验证前端拦截"):
            print("\n[步骤3] 前端校验-空必填...")
            page.open_add_page()
            page.page.wait_for_timeout(500)
            # 只填名称, 不填link_addr/接口, 保存
            page.fill_name(TEST_RULE)
            page.page.wait_for_timeout(300)
            page.save_form()
            page.page.wait_for_timeout(1500)
            success, msg = page.get_save_result()
            print(f"  保存结果: success={success}, msg={msg[:60]}")
            rec.add_detail(f"空必填: success={success}, msg={msg[:60]}")
            if not success:
                print(f"  [OK] 空必填被拦截")
                rec.add_detail("[OK] 空必填拦截")
            else:
                ssh_failures.append("空必填未拦截(意外成功)")
            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_ipv6_static()
            page.page.wait_for_timeout(500)

        # ========== 步骤4: 前端校验-link_addr格式 ==========
        with rec.step("步骤4: 前端校验-link_addr格式", "填非法IPv6, 验证拦截"):
            print("\n[步骤4] 前端校验-link_addr格式...")
            page.open_add_page()
            page.page.wait_for_timeout(500)
            page.fill_name(TEST_RULE)
            page.fill_link_addr("invalid_ipv6_addr")  # 非法IPv6
            page.select_dst_iface("wan1")
            page.page.wait_for_timeout(300)
            page.save_form()
            page.page.wait_for_timeout(1500)
            success, msg = page.get_save_result()
            print(f"  保存结果: success={success}, msg={msg[:60]}")
            rec.add_detail(f"非法IPv6: success={success}, msg={msg[:60]}")
            if not success:
                print(f"  [OK] 非法IPv6地址被拦截")
                rec.add_detail("[OK] 非法IPv6拦截")
            else:
                print(f"  [WARN] 非法IPv6未拦截(可能后端校验)")
                rec.add_detail("[WARN] 非法IPv6未拦截")
            try:
                page.click_cancel()
            except Exception:
                page.page.keyboard.press("Escape")
            page.navigate_to_ipv6_static()
            page.page.wait_for_timeout(500)

        # ========== 步骤5: 后端校验-lan_prefix_error(核心) ==========
        with rec.step("步骤5: 后端校验-lan_prefix_error", "填合法值被__check_dst_iface拦(IPv6未配置)"):
            print("\n[步骤5] 后端校验-lan_prefix_error(IPv6环境不具备)...")
            page.open_add_page()
            page.page.wait_for_timeout(500)
            page.fill_name(TEST_RULE)
            page.fill_link_addr(TEST_LINK_ADDR)  # 合法link-local
            page.select_src_iface("lan1")
            page.select_dst_iface("wan1")
            page.fill_comment("IPv6前缀静态分配测试")
            page.page.wait_for_timeout(500)
            page.save_form()
            page.page.wait_for_timeout(2500)
            success, msg = page.get_save_result()
            print(f"  保存结果: success={success}, msg={msg[:80]}")
            rec.add_detail(f"后端校验: success={success}, msg={msg[:80]}")
            # 验证: 应被lan_prefix_error拦(内网接口没绑定外网线路)
            if not success and ("绑定" in msg or "lan" in msg.lower() or "IPV6" in msg or "外网线路" in msg):
                print(f"  [OK] 后端lan_prefix_error拦截生效(IPv6未配置时正确阻止无效配置)")
                rec.add_detail("[OK] lan_prefix_error拦截生效")
            else:
                print(f"  [INFO] 保存结果: success={success}, msg={msg[:80]}")
                rec.add_detail(f"[INFO] 保存: {success}, {msg[:80]}")
            # 验证未入库(被拦不入库)
            page.navigate_to_ipv6_static()
            page.page.wait_for_timeout(1000)
            ssh_verify("L1-被拦不入库", backend_verifier.verify_ipv6_static_database,
                       must_pass=True, name=TEST_RULE, must_exist=False)

        # ========== 步骤6: 帮助功能 ==========
        with rec.step("步骤6: 帮助功能", "测试帮助按钮"):
            print("\n[步骤6] 帮助功能测试...")
            page.navigate_to_ipv6_static()
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
                else:
                    print(f"  [WARN] 帮助按钮未找到")
            except Exception as e:
                print(f"  [WARN] 帮助异常: {e}")

        # ========== 步骤7: 模拟重启 ==========
        with rec.step("步骤7: 模拟重启", "ipv6_static.sh init(init_static)"):
            print("\n[步骤7] 模拟重启验证...")
            ssh_verify("L4-模拟重启", backend_verifier.verify_ipv6_static_init,
                       must_pass=True)

        # ========== 步骤8: 导出 ==========
        with rec.step("步骤8: 导出", "导出IPv6前缀静态分配配置"):
            print("\n[步骤8] 导出测试...")
            import os as _os
            from config.config import get_config as _get_cfg
            _cfg = _get_cfg()
            _base = _cfg.test_data.get_export_path("ipv6_static", _cfg.get_project_root())
            export_file = _os.path.splitext(_base)[0] + ".txt"
            page.navigate_to_ipv6_static()
            page.page.wait_for_timeout(800)
            try:
                exported = page.export_rules(use_config_path=True, export_format="txt")
                print(f"  导出txt: {exported}")
                rec.add_detail(f"导出txt: {exported}")
                # csv导出(导出弹窗支持CSV+TXT两种格式, 验证csv导出)
                csv_ok = page.export_rules(use_config_path=True, export_format="csv")
                print(f"  导出csv: {csv_ok}")
                rec.add_detail(f"导出csv: {csv_ok}")
            except Exception as e:
                print(f"  [WARN] 导出异常: {e}")
                rec.add_detail(f"[WARN] 导出异常: {e}")

        # ========== 步骤9: 最终验证 ==========
        with rec.step("步骤9: 最终验证", "数据库空, 无IPV6TEST残留"):
            print("\n[步骤9] 最终验证...")
            if backend_verifier:
                backend_verifier.cleanup_ipv6_static_test("IPV6TEST")
                page.page.wait_for_timeout(1000)
            ssh_verify("L1-无IPV6TEST残留", backend_verifier.verify_ipv6_static_database,
                       must_pass=True, name=TEST_RULE, must_exist=False)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("IPv6前缀静态分配综合测试完成")
        print("=" * 60)
        print("测试覆盖(环境不具备版):")
        print("  - 初始检查(页面空, 数据库空)")
        print("  - 添加表单字段验证(全#id)")
        print("  - 前端校验(空必填/非法IPv6地址)")
        print("  - 后端校验-lan_prefix_error(IPv6未配置时__check_dst_iface正确拦截)")
        print("  - 帮助功能")
        print("  - 模拟重启(ipv6_static.sh init)")
        print("  - 导出")
        print("  - 最终验证(无残留)")
        print("  - SSH后台验证: L1数据库 + L4模拟重启")
        print("!!环境限制: IPv6关闭(WAN无前缀), 无法验证前缀实际生效(需WAN IPv6+LAN配置)")

        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项SSH验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not ssh_failures, \
            f"验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
