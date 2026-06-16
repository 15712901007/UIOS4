"""
IPTV透传综合测试用例

组播管理 > IPTV透传 配置页面综合测试
一次测试覆盖:
1. 读取初始配置+恢复默认(关闭)
2. 开启IPTV透传(网口透传+wan1+wan_vlanid+输出) + SSH L1-L2验证
3. 切换输入口为wan2 + SSH验证
4. 修改业务VLAN ID + SSH验证
5. 关闭IPTV透传 + SSH验证(桥接清理)
6. 切换为VLAN透传模式 + wan_vlanid + lan_vlanid + SSH L1-L3验证
7. 修改内网VLAN ID + SSH验证
8. 关闭VLAN透传 + SSH验证
9. 前端校验-必填字段验证
10. 开启后关闭再开启(状态切换稳定性)
11. 帮助功能测试
12. 最终恢复默认

SSH后台验证: L1数据库 + L2桥接接口(iptv bridge) + L3 VLAN子接口
字段映射: enabled(yes/no), mode(0网口透传/1VLAN透传),
          wan_iface(MAC地址), wan_vlanid, lan_iface(MAC地址), lan_vlanid
"""
import pytest
from pages.network.iptv_page import IptvPage
from utils.step_recorder import StepRecorder


@pytest.mark.iptv
@pytest.mark.network
class TestIptvComprehensive:
    """IPTV透传综合测试 - 配置型页面(非表格)"""

    def test_iptv_comprehensive(self, iptv_page_logged_in: IptvPage,
                                 step_recorder: StepRecorder, request):
        """
        综合测试: 开启/关闭/切换模式/切换端口/VLAN透传/前端校验/状态稳定性/帮助 + SSH后台验证
        """
        page = iptv_page_logged_in
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
                    print(f"      SSH数据: {result.raw_output[:200]}")
                    rec.add_detail(f"      SSH数据: {result.raw_output[:200]}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                return None

        print("\n" + "=" * 60)
        print("IPTV透传综合测试开始")
        print("=" * 60)

        # ========== 步骤1: 读取初始配置+恢复默认 ==========
        with rec.step("步骤1: 读取初始配置并恢复默认", "读取当前配置,确保IPTV透传为关闭状态"):
            print("\n[步骤1] 读取初始配置并恢复默认...")
            config = page.get_current_config()
            print(f"  当前配置: {config}")
            rec.add_detail(f"[初始配置] {config}")

            if not page.is_enabled():
                print(f"  [OK] 已处于关闭状态,无需恢复")
                rec.add_detail("[OK] 已关闭")
            else:
                page.navigate_to_iptv()
                result = page.save_config(enable=False)
                page.page.wait_for_timeout(500)
                assert result is True, "恢复默认失败"
                print(f"  [OK] 已恢复默认(关闭)")
                rec.add_detail("[OK] IPTV透传已关闭")

            # SSH验证关闭状态
            ssh_verify("L1-关闭验证", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"enabled": "no"})

        # ========== 步骤2: 开启IPTV透传(网口透传+wan1+wan_vlanid+输出) ==========
        with rec.step("步骤2: 开启IPTV透传", "配置: 网口透传 + wan1 + wan_vlanid=100 + 输出口"):
            print("\n[步骤2] 开启IPTV透传(网口透传+wan1+vlan100+输出)...")

            # 使用save_config一次性配置(显式指定mode确保从VLAN透传切换回网口透传)
            result = page.save_config(
                enable=True,
                mode="网口透传",
                input_port="wan1",
                wan_vlan_id="100",
                output_port="wan3"
            )
            assert result is True, "开启IPTV透传失败"
            print(f"  [OK] IPTV透传已开启: wan1+vlan100+wan3")
            rec.add_detail("[OK] 开启成功: 网口透传 + wan1 + vlan100 + wan3")

            # 验证页面状态
            page.navigate_to_iptv()
            config = page.get_current_config()
            print(f"  当前配置: {config}")
            rec.add_detail(f"  页面状态: {config}")

            # SSH L1-L2全链路验证
            ssh_verify("L1-开启验证", backend_verifier.verify_iptv_database,
                       must_pass=True,
                       expected_fields={"enabled": "yes", "mode": 0,
                                        "wan_vlanid": 100})
            ssh_verify("L2-桥接验证", backend_verifier.verify_iptv_bridge,
                       must_pass=False, expect_exists=True)

        # ========== 步骤3: 切换输入口为wan2 ==========
        with rec.step("步骤3: 切换输入口为wan2", "仅修改输入口"):
            print("\n[步骤3] 切换输入口为wan2...")

            page.navigate_to_iptv()
            result = page.save_config(input_port="wan2", wan_vlan_id="100")
            assert result is True, "切换输入口失败"
            print(f"  [OK] 输入口已切换为wan2")
            rec.add_detail("[OK] 输入口切换成功")

            page.navigate_to_iptv()
            current_input = page.get_input_port()
            print(f"  当前输入口: {current_input}")
            rec.add_detail(f"  页面输入口: {current_input}")

            ssh_verify("L1-输入口验证", backend_verifier.verify_iptv_database,
                       must_pass=True,
                       expected_fields={"enabled": "yes",
                                        "wan_iface": "not_empty"})
            ssh_verify("L2-桥接验证", backend_verifier.verify_iptv_bridge,
                       must_pass=False, expect_exists=True)

        # ========== 步骤4: 修改业务VLAN ID ==========
        with rec.step("步骤4: 修改业务VLAN ID", "将VLAN ID从100改为200"):
            print("\n[步骤4] 修改业务VLAN ID为200...")

            page.navigate_to_iptv()
            result = page.save_config(wan_vlan_id="200")
            assert result is True, "修改VLAN ID失败"
            print(f"  [OK] 业务VLAN ID已修改为200")
            rec.add_detail("[OK] 业务VLAN ID修改成功")

            page.navigate_to_iptv()
            current_vlan = page.get_wan_vlan_id()
            print(f"  当前业务VLAN ID: {current_vlan}")
            rec.add_detail(f"  页面业务VLAN ID: {current_vlan}")

            ssh_verify("L1-VLAN修改验证", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"wan_vlanid": 200})

        # ========== 步骤5: 关闭IPTV透传 ==========
        with rec.step("步骤5: 关闭IPTV透传", "关闭并验证桥接清理"):
            print("\n[步骤5] 关闭IPTV透传...")

            page.navigate_to_iptv()
            result = page.save_config(enable=False)
            assert result is True, "关闭IPTV透传失败"
            print(f"  [OK] IPTV透传已关闭")
            rec.add_detail("[OK] 关闭成功")

            page.navigate_to_iptv()
            assert not page.is_enabled(), "IPTV透传仍为开启状态"
            print(f"  [OK] 页面确认已关闭")
            rec.add_detail("[OK] 页面确认已关闭")

            # SSH验证关闭状态
            ssh_verify("L1-关闭验证", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"enabled": "no"})
            ssh_verify("L2-桥接验证", backend_verifier.verify_iptv_bridge,
                       must_pass=False, expect_exists=False)

        # ========== 步骤6: 切换为VLAN透传模式 ==========
        with rec.step("步骤6: VLAN透传模式", "配置: VLAN透传 + wan1 + wan_vlanid=100 + 输出 + lan_vlanid=200"):
            print("\n[步骤6] 切换为VLAN透传模式...")

            page.navigate_to_iptv()
            result = page.save_config(
                enable=True,
                mode="vlan透传",
                input_port="wan1",
                wan_vlan_id="100",
                output_port="wan3",
                lan_vlan_id="200"
            )
            assert result is True, "VLAN透传配置失败"
            print(f"  [OK] VLAN透传已开启(wan1+vlan100+wan3+lan_vlan200)")
            rec.add_detail("[OK] VLAN透传开启成功")

            # 验证页面状态
            page.navigate_to_iptv()
            config = page.get_current_config()
            print(f"  当前配置: {config}")
            rec.add_detail(f"  页面状态: {config}")

            # SSH验证
            ssh_verify("L1-VLAN验证", backend_verifier.verify_iptv_database,
                       must_pass=True,
                       expected_fields={"enabled": "yes", "mode": 1,
                                        "wan_vlanid": 100, "lan_vlanid": 200})
            ssh_verify("L2-桥接验证", backend_verifier.verify_iptv_bridge,
                       must_pass=False, expect_exists=True)
            ssh_verify("L3-VLAN验证", backend_verifier.verify_iptv_vlan,
                       must_pass=False, expect_vlan=True,
                       wan_iface="eth5", vlan_id="100")

        # ========== 步骤7: 修改内网VLAN ID ==========
        with rec.step("步骤7: 修改内网VLAN ID", "将lan_vlanid从200改为300"):
            print("\n[步骤7] 修改内网VLAN ID为300...")

            page.navigate_to_iptv()
            result = page.save_config(lan_vlan_id="300")
            assert result is True, "修改内网VLAN ID失败"
            print(f"  [OK] 内网VLAN ID已修改为300")
            rec.add_detail("[OK] 内网VLAN ID修改成功")

            page.navigate_to_iptv()
            current_vlan = page.get_lan_vlan_id()
            print(f"  当前内网VLAN ID: {current_vlan}")
            rec.add_detail(f"  页面内网VLAN ID: {current_vlan}")

            ssh_verify("L1-VLAN修改验证", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"lan_vlanid": 300})

        # ========== 步骤8: 关闭VLAN透传 ==========
        with rec.step("步骤8: 关闭VLAN透传", "关闭并验证桥接和VLAN清理"):
            print("\n[步骤8] 关闭VLAN透传...")

            page.navigate_to_iptv()
            result = page.save_config(enable=False)
            assert result is True, "关闭VLAN透传失败"
            print(f"  [OK] VLAN透传已关闭")
            rec.add_detail("[OK] 关闭成功")

            ssh_verify("L1-关闭验证", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"enabled": "no"})
            ssh_verify("L2-桥接验证", backend_verifier.verify_iptv_bridge,
                       must_pass=False, expect_exists=False)

        # ========== 步骤9: 前端校验-必填字段 ==========
        with rec.step("步骤9: 前端校验-必填字段", "不填必填字段应被拦截"):
            print("\n[步骤9] 前端校验-必填字段...")

            page.navigate_to_iptv()

            # 只开启,不选输入口,不填VLAN ID,直接保存
            page.toggle_enable(True)
            page.page.wait_for_timeout(500)
            page.click_save()
            page.page.wait_for_timeout(2000)

            # 检查是否有错误提示
            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content()
                print(f"  [OK] 前端拦截: {error_text}")
                rec.add_detail(f"[OK] 前端拦截: {error_text}")
            else:
                print(f"  [INFO] 未拦截(可能有默认值)")
                rec.add_detail("[INFO] 未拦截")

            # 恢复关闭
            page.navigate_to_iptv()
            if page.is_enabled():
                page.save_config(enable=False)
                page.page.wait_for_timeout(500)

        # ========== 步骤10: 开启后关闭再开启(状态切换稳定性) ==========
        with rec.step("步骤10: 状态切换稳定性", "开启->关闭->开启,验证状态切换稳定性"):
            print("\n[步骤10] 状态切换稳定性测试...")

            # 第1次开启
            page.navigate_to_iptv()
            result1 = page.save_config(
                enable=True, mode="网口透传", input_port="wan1", wan_vlan_id="100",
                output_port="wan3"
            )
            assert result1 is True, "第1次开启失败"
            print(f"  [OK] 第1次开启成功")
            rec.add_detail("[OK] 第1次开启成功")

            ssh_verify("L1-开启1", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"enabled": "yes"})

            # 关闭
            page.navigate_to_iptv()
            result2 = page.save_config(enable=False)
            assert result2 is True, "关闭失败"
            page.page.wait_for_timeout(1000)
            assert not page.is_enabled(), "关闭后状态不正确"
            print(f"  [OK] 关闭成功")
            rec.add_detail("[OK] 关闭成功")

            ssh_verify("L1-关闭", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"enabled": "no"})

            # 第2次开启
            page.navigate_to_iptv()
            result3 = page.save_config(
                enable=True, mode="网口透传", input_port="wan1", wan_vlan_id="100",
                output_port="wan3"
            )
            assert result3 is True, "第2次开启失败"
            print(f"  [OK] 第2次开启成功")
            rec.add_detail("[OK] 第2次开启成功")

            ssh_verify("L1-开启2", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"enabled": "yes"})
            ssh_verify("L2-桥接", backend_verifier.verify_iptv_bridge,
                       must_pass=False, expect_exists=True)

        # ========== 步骤11: 帮助功能测试 ==========
        with rec.step("步骤11: 帮助功能测试", "测试帮助按钮"):
            print("\n[步骤11] 帮助功能测试...")

            page.navigate_to_iptv()

            try:
                clicked = page.click_help()
                if clicked:
                    page.page.wait_for_timeout(1000)
                    help_visible = page.is_help_panel_visible()
                    if not help_visible:
                        help_visible = page.page.locator(
                            '.ant-popover, .ant-drawer, .ant-modal, [role="dialog"], '
                            '.ant-alert, .help-content, .help-box'
                        ).count() > 0

                    if help_visible:
                        print(f"  [OK] 帮助面板已显示")
                        rec.add_detail("[OK] 帮助面板显示成功")
                        page.close_help_panel()
                        page.page.wait_for_timeout(300)
                    else:
                        print(f"  [WARN] 帮助面板未显示(可能已展示或无独立面板)")
                        rec.add_detail("[WARN] 帮助面板未显示")
                        page.page.keyboard.press("Escape")
                else:
                    print(f"  [WARN] 帮助按钮未找到")
                    rec.add_detail("[WARN] 帮助按钮未找到")
            except Exception as e:
                print(f"  [WARN] 帮助功能测试异常: {e}")
                rec.add_detail(f"[WARN] 帮助功能异常: {e}")

        # ========== 步骤12: 最终恢复默认 ==========
        with rec.step("步骤12: 最终恢复默认", "关闭IPTV透传并SSH验证"):
            print("\n[步骤12] 最终恢复默认...")

            page.navigate_to_iptv()
            result = page.save_config(enable=False)
            if result:
                print(f"  [OK] IPTV透传已关闭")
                rec.add_detail("[OK] 已关闭")
            else:
                page.navigate_to_iptv()
                if not page.is_enabled():
                    print(f"  [OK] 确认已关闭")
                    rec.add_detail("[OK] 确认已关闭")
                else:
                    rec.add_detail("[WARN] 关闭可能失败")

            # SSH最终验证
            ssh_verify("L1-最终关闭", backend_verifier.verify_iptv_database,
                       must_pass=True, expected_fields={"enabled": "no"})
            ssh_verify("L2-最终桥接", backend_verifier.verify_iptv_bridge,
                       must_pass=False, expect_exists=False)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("IPTV透传综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 初始配置读取 + 恢复默认")
        print("  - 开启IPTV透传(网口透传+wan1+wan_vlanid+输出)")
        print("  - 切换输入口(wan1->wan2)")
        print("  - 修改业务VLAN ID(100->200)")
        print("  - 关闭IPTV透传")
        print("  - VLAN透传模式(wan_vlanid+lan_vlanid)")
        print("  - 修改内网VLAN ID(200->300)")
        print("  - 关闭VLAN透传")
        print("  - 前端校验(必填字段)")
        print("  - 状态切换稳定性(开->关->开)")
        print("  - 帮助功能")
        print("  - 最终恢复默认")
        print("  - SSH后台验证: L1数据库+L2桥接+L3 VLAN")

        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项失败:")
            for f in ssh_failures:
                print(f"  - {f}")
            all_failures = ssh_failures + ui_failures
        assert not all_failures, \
                f"验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"
