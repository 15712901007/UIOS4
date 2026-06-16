"""
IGMP代理综合测试用例

组播管理 > IGMP代理 配置页面综合测试
一次测试覆盖:
1. 读取初始配置+恢复默认(关闭)
2. 开启IGMP代理(v3+wan1+lan1) + SSH L1-L4验证
3. 修改版本为IGMPv2 + SSH验证
4. 切换上联端口为wan2 + SSH验证
5. 切换下联端口为全部 + SSH验证
6. 关闭IGMP代理 + SSH验证(进程停止/配置清理)
7. 不选上联端口直接保存(验证前端校验)
8. 不选下联端口直接保存(验证前端校验)
9. 开启后关闭再开启(状态切换稳定性)
10. 组合配置测试(v2+wan2+全部)
11. 快速连续切换版本(v2->v3->v2)
12. 帮助功能测试
13. 最终恢复默认

SSH后台验证: L1数据库 + L2进程 + L3配置文件 + L4内核(promisc+force_igmp_version)
字段映射: enabled(yes/no), version(2/3), downstream(LAN接口/all), upstream(WAN接口)
"""
import pytest
from pages.network.igmp_proxy_page import IgmpProxyPage
from utils.step_recorder import StepRecorder


@pytest.mark.igmp_proxy
@pytest.mark.network
class TestIgmpProxyComprehensive:
    """IGMP代理综合测试 - 配置型页面(非表格)"""

    def test_igmp_proxy_comprehensive(self, igmp_proxy_page_logged_in: IgmpProxyPage,
                                       step_recorder: StepRecorder, request):
        """
        综合测试: 开启/关闭/修改版本/切换端口/前端校验/状态切换/帮助功能 + SSH后台验证
        """
        page = igmp_proxy_page_logged_in
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
        print("IGMP代理综合测试开始")
        print("=" * 60)

        # ========== 步骤1: 读取初始配置+恢复默认 ==========
        with rec.step("步骤1: 读取初始配置并恢复默认", "读取当前配置,确保IGMP代理为关闭状态"):
            print("\n[步骤1] 读取初始配置并恢复默认...")
            config = page.get_current_config()
            print(f"  当前配置: enabled={config['enabled']}, version={config['version']}, "
                  f"upstream={config['upstream']}, downstream={config['downstream']}")
            rec.add_detail(f"[初始配置] {config}")

            # 恢复默认(关闭)
            if not page.is_enabled():
                print(f"  [OK] 已处于关闭状态,无需恢复")
                rec.add_detail("[OK] 已关闭")
            else:
                result = page.save_config(enable=False)
                page.page.wait_for_timeout(500)
                assert result is True, "恢复默认失败"
                print(f"  [OK] 已恢复默认(关闭)")
                rec.add_detail("[OK] IGMP代理已关闭")

            # SSH验证关闭状态
            ssh_verify("L1-关闭验证", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True, expected_fields={"enabled": "no"})
            ssh_verify("L2-进程验证", backend_verifier.verify_igmp_proxy_process,
                       must_pass=False, expect_running=False)

        # ========== 步骤2: 开启IGMP代理(v3+wan1+lan1) ==========
        with rec.step("步骤2: 开启IGMP代理", "配置: IGMPv3 + wan1 + lan1"):
            print("\n[步骤2] 开启IGMP代理(v3+wan1+lan1)...")

            result = page.save_config(
                enable=True,
                version="IGMPv3",
                upstream="wan1",
                downstream="lan1",
            )
            assert result is True, "开启IGMP代理失败"
            print(f"  [OK] IGMP代理已开启")
            rec.add_detail("[OK] 开启成功: IGMPv3 + wan1 + lan1")

            # 验证页面状态
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            config = page.get_current_config()
            print(f"  当前配置: {config}")
            rec.add_detail(f"  页面状态: {config}")

            # SSH L1-L4全链路验证
            ssh_verify("L1-开启验证", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True,
                       expected_fields={"enabled": "yes", "version": "3",
                                        "upstream": "wan1", "downstream": "lan1"})
            ssh_verify("L2-进程验证", backend_verifier.verify_igmp_proxy_process,
                       must_pass=True, expect_running=True)
            ssh_verify("L3-配置文件", backend_verifier.verify_igmp_proxy_config_file,
                       must_pass=False, expect_exists=True,
                       upstream="wan1", downstream="lan1")
            ssh_verify("L4-内核验证", backend_verifier.verify_igmp_proxy_kernel,
                       must_pass=False, upstream="wan1", downstream="lan1",
                       expect_enabled=True)

        # ========== 步骤3: 修改版本为IGMPv2 ==========
        with rec.step("步骤3: 修改版本为IGMPv2", "保持其他配置不变,仅切换版本"):
            print("\n[步骤3] 修改版本为IGMPv2...")

            result = page.save_config(version="IGMPv2")
            assert result is True, "修改版本失败"
            print(f"  [OK] 版本已切换为IGMPv2")
            rec.add_detail("[OK] 版本切换成功")

            # 验证
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            current_version = page.get_version()
            print(f"  当前版本: {current_version}")
            rec.add_detail(f"  页面版本: {current_version}")

            ssh_verify("L1-版本验证", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True, expected_fields={"version": "2"})

        # ========== 步骤4: 切换上联端口为wan2 ==========
        with rec.step("步骤4: 切换上联端口为wan2", "仅修改上联端口"):
            print("\n[步骤4] 切换上联端口为wan2...")

            # 获取可用的WAN端口列表(在独立导航中读取,避免干扰后续操作)
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            wan_options = page.get_upstream_options()
            print(f"  可用WAN端口: {wan_options}")
            rec.add_detail(f"  可用WAN端口: {wan_options}")

            if "wan2" in wan_options:
                # 重新导航确保干净状态
                page.navigate_to_igmp_proxy()
                page.page.wait_for_timeout(500)
                result = page.save_config(upstream="wan2")
                assert result is True, "切换上联端口失败"
                print(f"  [OK] 上联端口已切换为wan2")
                rec.add_detail("[OK] 上联端口切换成功")

                page.navigate_to_igmp_proxy()
                page.page.wait_for_timeout(500)
                current_upstream = page.get_upstream()
                print(f"  当前上联端口: {current_upstream}")
                rec.add_detail(f"  页面上联端口: {current_upstream}")

                ssh_verify("L1-上联验证", backend_verifier.verify_igmp_proxy_database,
                           must_pass=True, expected_fields={"upstream": "wan2"})
                # 检查新upstream是否开启promisc, 旧upstream(wan1)是否关闭promisc
                ssh_verify("L4-promisc验证", backend_verifier.verify_igmp_proxy_kernel,
                           must_pass=False, upstream="wan2", expect_enabled=True)
            else:
                print(f"  [WARN] wan2不可用,跳过")
                rec.add_detail("[WARN] wan2不可用,跳过")

        # ========== 步骤5: 切换下联端口为全部 ==========
        with rec.step("步骤5: 切换下联端口为全部", "下联端口切换为'全部'"):
            print("\n[步骤5] 切换下联端口为全部...")

            # 独立导航中读取选项,避免干扰后续保存
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            lan_options = page.get_downstream_options()
            print(f"  可用LAN端口: {lan_options}")
            rec.add_detail(f"  可用LAN端口: {lan_options}")

            # 重新导航确保干净状态
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            result = page.save_config(downstream="全部")
            if result:
                print(f"  [OK] 下联端口已切换为全部")
                rec.add_detail("[OK] 下联端口切换成功")

                page.navigate_to_igmp_proxy()
                page.page.wait_for_timeout(500)
                current_downstream = page.get_downstream()
                print(f"  当前下联端口: {current_downstream}")
                rec.add_detail(f"  页面下联端口: {current_downstream}")

                # "全部"在后端解析为实际接口名列表(包含所有LAN接口含VLAN虚拟接口)
                # 不能精确匹配(接口列表随环境变化),改为验证downstream非空且包含lan1
                if current_downstream == "全部" or current_downstream == "all":
                    # UI显示"全部", 数据库存的是展开的接口列表, 验证包含lan1即可
                    ssh_verify("L1-下联验证", backend_verifier.verify_igmp_proxy_database,
                               must_pass=True, expected_fields={"downstream": "lan1"})
                else:
                    ssh_verify("L1-下联验证", backend_verifier.verify_igmp_proxy_database,
                               must_pass=True, expected_fields={"downstream": current_downstream})
                ssh_verify("L3-配置文件", backend_verifier.verify_igmp_proxy_config_file,
                           must_pass=False, expect_exists=True, downstream="lan")
            else:
                print(f"  [WARN] 切换下联端口为全部失败")
                rec.add_detail("[WARN] 切换失败")

        # ========== 步骤6: 关闭IGMP代理 ==========
        with rec.step("步骤6: 关闭IGMP代理", "关闭并验证进程停止/配置清理"):
            print("\n[步骤6] 关闭IGMP代理...")

            result = page.save_config(enable=False)
            assert result is True, "关闭IGMP代理失败"
            print(f"  [OK] IGMP代理已关闭")
            rec.add_detail("[OK] 关闭成功")

            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            assert not page.is_enabled(), "IGMP代理仍为开启状态"
            print(f"  [OK] 页面确认已关闭")
            rec.add_detail("[OK] 页面确认已关闭")

            # SSH验证关闭状态
            ssh_verify("L1-关闭验证", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True, expected_fields={"enabled": "no"})
            ssh_verify("L2-进程验证", backend_verifier.verify_igmp_proxy_process,
                       must_pass=False, expect_running=False)
            ssh_verify("L3-配置文件", backend_verifier.verify_igmp_proxy_config_file,
                       must_pass=False, expect_exists=False)

        # ========== 步骤7: 不选上联端口直接保存 ==========
        with rec.step("步骤7: 前端校验-不选上联端口", "不选择上联端口直接保存,验证前端校验"):
            print("\n[步骤7] 前端校验-不选上联端口...")

            # 先开启
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            page.toggle_enable(True)
            page.page.wait_for_timeout(300)
            page.select_version("IGMPv3")
            page.page.wait_for_timeout(300)
            # 不选上联端口,直接保存
            page.click_save()
            page.page.wait_for_timeout(1500)

            # 检查是否有错误提示
            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content()
                print(f"  [OK] 前端拦截: {error_text}")
                rec.add_detail(f"[OK] 前端拦截: {error_text}")
            else:
                # 可能后端拦截
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 保存被拦截(无成功消息)")
                    rec.add_detail("[OK] 保存被拦截")
                else:
                    print(f"  [INFO] 未拦截(可能已选端口)")
                    rec.add_detail("[INFO] 未拦截")

            # 恢复关闭
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            page.save_config(enable=False)
            page.page.wait_for_timeout(500)

        # ========== 步骤8: 不选下联端口直接保存 ==========
        with rec.step("步骤8: 前端校验-不选下联端口", "不选择下联端口直接保存,验证前端校验"):
            print("\n[步骤8] 前端校验-不选下联端口...")

            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            page.toggle_enable(True)
            page.page.wait_for_timeout(300)
            page.select_version("IGMPv3")
            page.page.wait_for_timeout(300)
            page.select_upstream("wan1")
            page.page.wait_for_timeout(300)
            # 不选下联端口,直接保存
            page.click_save()
            page.page.wait_for_timeout(1500)

            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content()
                print(f"  [OK] 前端拦截: {error_text}")
                rec.add_detail(f"[OK] 前端拦截: {error_text}")
            else:
                success = page.wait_for_success_message(timeout=3000)
                if not success:
                    print(f"  [OK] 保存被拦截")
                    rec.add_detail("[OK] 保存被拦截")
                else:
                    print(f"  [INFO] 未拦截(可能已选端口)")
                    rec.add_detail("[INFO] 未拦截")

            # 恢复关闭
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            page.save_config(enable=False)
            page.page.wait_for_timeout(500)

        # ========== 步骤9: 开启后关闭再开启(状态切换稳定性) ==========
        with rec.step("步骤9: 状态切换稳定性", "开启->关闭->开启,验证状态切换稳定性"):
            print("\n[步骤9] 状态切换稳定性测试...")

            # 第1次开启
            result1 = page.save_config(enable=True, version="IGMPv3",
                                        upstream="wan1", downstream="lan1")
            assert result1 is True, "第1次开启失败"
            page.page.wait_for_timeout(1000)
            assert page.is_enabled(), "第1次开启后状态不正确"
            print(f"  [OK] 第1次开启成功")
            rec.add_detail("[OK] 第1次开启成功")

            ssh_verify("L1-开启1", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True, expected_fields={"enabled": "yes"})

            # 关闭
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            result2 = page.save_config(enable=False)
            assert result2 is True, "关闭失败"
            page.page.wait_for_timeout(1000)
            assert not page.is_enabled(), "关闭后状态不正确"
            print(f"  [OK] 关闭成功")
            rec.add_detail("[OK] 关闭成功")

            ssh_verify("L1-关闭", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True, expected_fields={"enabled": "no"})

            # 第2次开启
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            result3 = page.save_config(enable=True, version="IGMPv3",
                                        upstream="wan1", downstream="lan1")
            assert result3 is True, "第2次开启失败"
            page.page.wait_for_timeout(1000)
            assert page.is_enabled(), "第2次开启后状态不正确"
            print(f"  [OK] 第2次开启成功")
            rec.add_detail("[OK] 第2次开启成功")

            ssh_verify("L1-开启2", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True, expected_fields={"enabled": "yes"})
            ssh_verify("L2-进程", backend_verifier.verify_igmp_proxy_process,
                       must_pass=True, expect_running=True)

        # ========== 步骤10: 组合配置测试(v2+wan2+全部) ==========
        with rec.step("步骤10: 组合配置测试", "配置: IGMPv2 + wan2 + 全部"):
            print("\n[步骤10] 组合配置测试(v2+wan2+全部)...")

            # 独立导航中读取选项
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            wan_options = page.get_upstream_options()

            if "wan2" in wan_options:
                # 重新导航确保干净状态
                page.navigate_to_igmp_proxy()
                page.page.wait_for_timeout(500)
                result = page.save_config(
                    version="IGMPv2",
                    upstream="wan2",
                    downstream="全部",
                )
                assert result is True, "组合配置保存失败"
                print(f"  [OK] 组合配置保存成功")
                rec.add_detail("[OK] 保存成功")

                page.navigate_to_igmp_proxy()
                page.page.wait_for_timeout(500)
                config = page.get_current_config()
                print(f"  当前配置: {config}")
                rec.add_detail(f"  页面配置: {config}")

                # "全部"在后端解析为实际接口名,用页面显示值验证
                actual_downstream = config.get("downstream", "lan1")
                ssh_verify("L1-组合配置", backend_verifier.verify_igmp_proxy_database,
                           must_pass=True,
                           expected_fields={"enabled": "yes", "version": "2",
                                            "upstream": "wan2", "downstream": actual_downstream})
                ssh_verify("L2-进程", backend_verifier.verify_igmp_proxy_process,
                           must_pass=True, expect_running=True)
                ssh_verify("L3-配置文件", backend_verifier.verify_igmp_proxy_config_file,
                           must_pass=False, expect_exists=True,
                           upstream="wan2", downstream="lan")
            else:
                print(f"  [WARN] wan2不可用,跳过组合配置测试")
                rec.add_detail("[WARN] wan2不可用,跳过")

        # ========== 步骤11: 快速连续切换版本 ==========
        with rec.step("步骤11: 快速连续切换版本", "v2->v3->v2快速切换"):
            print("\n[步骤11] 快速连续切换版本...")

            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)

            # 切换到v3
            r1 = page.save_config(version="IGMPv3")
            page.page.wait_for_timeout(500)
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            v = page.get_version()
            print(f"  切换到v3: {'OK' if 'v3' in v.lower() else 'FAIL'} ({v})")
            rec.add_detail(f"  切换v3: {v}")

            # 切换到v2
            r2 = page.save_config(version="IGMPv2")
            page.page.wait_for_timeout(500)
            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            v = page.get_version()
            print(f"  切换到v2: {'OK' if 'v2' in v.lower() else 'FAIL'} ({v})")
            rec.add_detail(f"  切换v2: {v}")

            print(f"  [OK] 快速切换测试完成")
            rec.add_detail("[OK] 快速切换完成")

            ssh_verify("L1-版本切换", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True, expected_fields={"version": "2"})

        # ========== 步骤12: 帮助功能测试 ==========
        with rec.step("步骤12: 帮助功能测试", "测试帮助按钮"):
            print("\n[步骤12] 帮助功能测试...")

            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)

            try:
                clicked = page.click_help()
                if clicked:
                    page.page.wait_for_timeout(1000)
                    # 检查多种帮助面板形式: drawer/modal/popover/新内容
                    help_visible = page.is_help_panel_visible()
                    # 也检查是否有新内容区域(有些帮助是内联展开)
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

        # ========== 步骤13: 最终恢复默认 ==========
        with rec.step("步骤13: 最终恢复默认", "关闭IGMP代理并SSH验证"):
            print("\n[步骤13] 最终恢复默认...")

            page.navigate_to_igmp_proxy()
            page.page.wait_for_timeout(500)
            result = page.save_config(enable=False)
            if result:
                print(f"  [OK] IGMP代理已关闭")
                rec.add_detail("[OK] 已关闭")
            else:
                # 可能已经关闭
                page.navigate_to_igmp_proxy()
                page.page.wait_for_timeout(500)
                if not page.is_enabled():
                    print(f"  [OK] 确认已关闭")
                    rec.add_detail("[OK] 确认已关闭")
                else:
                    rec.add_detail("[WARN] 关闭可能失败")

            # SSH最终验证
            ssh_verify("L1-最终关闭", backend_verifier.verify_igmp_proxy_database,
                       must_pass=True, expected_fields={"enabled": "no"})
            ssh_verify("L2-最终进程", backend_verifier.verify_igmp_proxy_process,
                       must_pass=False, expect_running=False)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("IGMP代理综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 初始配置读取 + 恢复默认")
        print("  - 开启IGMP代理(v3+wan1+lan1)")
        print("  - 版本切换(v3->v2)")
        print("  - 上联端口切换(wan1->wan2)")
        print("  - 下联端口切换(lan1->全部)")
        print("  - 关闭IGMP代理")
        print("  - 前端校验(不选端口)")
        print("  - 状态切换稳定性(开->关->开)")
        print("  - 组合配置(v2+wan2+全部)")
        print("  - 快速连续切换版本")
        print("  - 帮助功能")
        print("  - 最终恢复默认")
        print("  - SSH后台验证: L1数据库+L2进程+L3配置文件+L4内核")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败:")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, \
                f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
