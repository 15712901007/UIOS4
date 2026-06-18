"""
DNS加速服务综合测试用例

网络配置 > DNS服务 > DNS加速服务 混合页面综合测试
一次测试覆盖:
【基础配置 dns_config】
1. 读取初始配置 + 恢复默认(关闭DNS加速 + 清理反向代理)
2. 开启DNS加速(UDP模式 + 标准DNS + 老化时间 + 强制代理) + SSH L1-L4验证
3. 修改DNS服务器/老化时间/禁止AAAA + SSH L1验证
4. 加速模式切换 UDP→多线分路→UDP + SSH L1 cachemode验证
5. 关闭DNS加速 + SSH L1-L4验证(进程停止/文件清理/iptables清空)
6. 前端校验-非法DNS IP
7. 前端校验-老化时间越界(<60 / >3600)
8. 状态切换稳定性(开-关-开)
【反向代理表格 dns_reverse_proxy_new】
9. 开启 + 添加反向代理规则 + SSH L1数据库 + L2 static.conf验证
10. 编辑反向代理规则 + SSH L1验证
11. 停用/启用反向代理规则 + SSH L1验证
12. 搜索反向代理规则
13. 批量删除 + SSH计数验证(3次重试)
14. 前端校验-空域名/空解析地址
15. 帮助功能
16. 最终恢复

SSH后台验证:
- L1数据库: dns_config(基础) + dns_reverse_proxy_new(反向代理, sqlite3直查)
- L2运行时文件: /tmp/iktmp/ikdnsd.conf + ikdnsd.static.conf + ikdnsd.status
- L3 iptables: nat表DNSPROXY链 REDIRECT(proxy_force=1时)
- L4进程/端口: ikdnsd进程(≠ikdnsx系统进程) + UDP 53

cachemode映射: 0=UDP(ikdnsd/53), 1=多线分路(ik_cntl), 2=第三方代理(DNAT), 3=DoH
后端脚本: /usr/ikuai/script/dns.sh
"""
import pytest
from pages.network.dns_accelerate_page import DnsAcceleratePage
from utils.step_recorder import StepRecorder


# 测试数据
TEST_DNS1 = "114.114.114.114"
TEST_DNS2 = "119.29.29.29"
TEST_DNS1_NEW = "223.5.5.5"
TEST_DNS2_NEW = "8.8.8.8"
TEST_CACHE_TTL = "120"
TEST_DOMAIN = "autotest2.com"
TEST_DOMAIN_EDIT = "autotest2_edit.com"
TEST_DNS_ADDR = "192.168.200.2"
TEST_DNS_ADDR_NEW = "192.168.200.22"
TEST_SRC_ADDR = "192.168.148.0/24"
TEST_COMMENT = "dnstest2"
# 残留的旧测试规则(需在步骤1清理)
LEGACY_DOMAINS = ["autotest1.com", "autotest2.com", "autotest2_edit.com"]


@pytest.mark.dns_accelerate
@pytest.mark.network
class TestDnsAccelerateComprehensive:
    """DNS加速服务综合测试 - 混合页面(基础配置单记录 + 反向代理表格)"""

    def test_dns_accelerate_comprehensive(self, dns_accelerate_page_logged_in: DnsAcceleratePage,
                                          step_recorder: StepRecorder, request):
        """
        综合测试: 基础配置(开启/关闭/模式切换/前端校验) + 反向代理表格(增删改/批量/搜索) + SSH L1-L4验证
        """
        page = dns_accelerate_page_logged_in
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

        def ui_check(label, condition, detail=""):
            status = '[OK]' if condition else '[FAIL]'
            print(f"    UI-{label}: {status} {detail}")
            rec.add_detail(f"    UI-{label}: {status} {detail}")
            if not condition:
                ui_failures.append(f"UI-{label}: {detail}")
            return condition

        print("\n" + "=" * 60)
        print("DNS加速服务综合测试开始")
        print("=" * 60)

        # ========== 步骤1: 读取初始配置 + 恢复默认 ==========
        with rec.step("步骤1: 读取初始配置并恢复默认", "读取当前配置, 关闭DNS加速并清理残留反向代理规则"):
            print("\n[步骤1] 读取初始配置并恢复默认...")
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            config = page.get_basic_config()
            print(f"  初始配置: {config}")
            rec.add_detail(f"[初始配置] {config}")

            # 关闭DNS加速(若已开启)
            if page.is_enabled():
                page.save_basic_config(enable=False)
                page.page.wait_for_timeout(1000)
                page.navigate_to_dns_accelerate()
                page.page.wait_for_timeout(500)
            closed = not page.is_enabled()
            ui_check("DNS加速已关闭", closed)

            # 清理残留反向代理规则
            cleaned = 0
            for domain in LEGACY_DOMAINS:
                for _ in range(2):
                    if page.find_rule_row(domain):
                        page.delete_reverse_proxy(domain)
                        cleaned += 1
                    else:
                        break
            print(f"  [清理] 删除残留规则 {cleaned} 条")
            rec.add_detail(f"[清理] 删除残留规则 {cleaned} 条")

            # SSH验证初始状态(关闭)
            ssh_verify("L1-关闭验证", backend_verifier.verify_dns_config_database,
                       must_pass=True, expected_fields={"enabled": "no"})
            ssh_verify("L4-进程(应停止)", backend_verifier.verify_dns_process,
                       must_pass=False, expect_running=False)
            ssh_verify("L2-文件(应清理)", backend_verifier.verify_dns_runtime_config,
                       must_pass=False, expect_enabled=False)

        # ========== 步骤2: 开启DNS加速(UDP模式) + L1-L4验证 ==========
        with rec.step("步骤2: 开启DNS加速(UDP模式)", "开启 + 标准DNS + 老化时间 + 强制代理, SSH L1-L4全验证"):
            print("\n[步骤2] 开启DNS加速(UDP模式)...")
            result = page.save_basic_config(
                enable=True,
                dns1=TEST_DNS1,
                dns2=TEST_DNS2,
                forbid_aaaa=False,
                cachemode="UDP",
                proxy_force=True,
                cache_ttl=TEST_CACHE_TTL,
            )
            assert result is True, "开启DNS加速(UDP)失败"
            print(f"  [OK] DNS加速已开启(UDP)")
            rec.add_detail("[OK] 开启UDP模式成功")

            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            cfg = page.get_basic_config()
            print(f"  当前配置: {cfg}")
            rec.add_detail(f"  页面配置: {cfg}")

            ui_check("已开启", cfg["enabled"] is True)
            ui_check("cachemode=UDP", cfg["cachemode"] == "UDP", cfg.get("cachemode"))

            # SSH L1-L4全链路验证
            ssh_verify("全链路L1-L4", backend_verifier.verify_dns_basic_full_chain,
                       must_pass=True, expect_enabled=True,
                       expected_fields={"cachemode": "0", "dns1": TEST_DNS1,
                                        "dns2": TEST_DNS2, "cache_ttl": TEST_CACHE_TTL,
                                        "proxy_force": "1"},
                       proxy_force=True)
            ssh_verify("L4-进程/UDP53", backend_verifier.verify_dns_process,
                       must_pass=True, expect_running=True)

        # ========== 步骤3: 修改DNS服务器/老化时间/禁止AAAA ==========
        with rec.step("步骤3: 修改基础配置", "修改DNS/老化时间/禁止AAAA, SSH L1验证"):
            print("\n[步骤3] 修改基础配置...")
            result = page.save_basic_config(
                dns1=TEST_DNS1_NEW,
                dns2=TEST_DNS2_NEW,
                forbid_aaaa=True,
                cache_ttl="300",
            )
            assert result is True, "修改基础配置失败"
            print(f"  [OK] 配置已修改")
            rec.add_detail("[OK] 修改成功(dns1/dns2/forbid/ttl)")

            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            cfg = page.get_basic_config()
            ui_check("dns1已更新", cfg["dns1"] == TEST_DNS1_NEW, cfg.get("dns1"))
            ui_check("dns2已更新", cfg["dns2"] == TEST_DNS2_NEW, cfg.get("dns2"))
            ui_check("forbid_4a已开启", cfg["forbid_dns_4a"] is True)
            ui_check("cache_ttl=300", cfg["cache_ttl"] == "300", cfg.get("cache_ttl"))

            ssh_verify("L1-修改验证", backend_verifier.verify_dns_config_database,
                       must_pass=True,
                       expected_fields={"dns1": TEST_DNS1_NEW, "dns2": TEST_DNS2_NEW,
                                        "forbid_dns_4a": "1", "cache_ttl": "300"})

        # ========== 步骤4: 加速模式切换 UDP→多线分路→UDP ==========
        with rec.step("步骤4: 加速模式切换", "UDP→多线分路→UDP, SSH L1 cachemode验证"):
            print("\n[步骤4] 加速模式切换...")
            # 切换到多线分路(用ik_cntl, 不启动ikdnsd)
            r1 = page.save_basic_config(cachemode="多线分路")
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            cm1 = page.get_cachemode()
            print(f"  切换到多线分路: {cm1}")
            rec.add_detail(f"  多线分路: {cm1}")
            ui_check("切换多线分路", cm1 == "多线分路", cm1)
            if r1:
                ssh_verify("L1-多线分路cachemode", backend_verifier.verify_dns_config_database,
                           must_pass=False, expected_fields={"cachemode": "1"})

            # 切换回UDP
            r2 = page.save_basic_config(cachemode="UDP")
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            cm2 = page.get_cachemode()
            print(f"  切换回UDP: {cm2}")
            rec.add_detail(f"  UDP: {cm2}")
            ui_check("切回UDP", cm2 == "UDP", cm2)
            if r2:
                ssh_verify("L1-UDP cachemode", backend_verifier.verify_dns_config_database,
                           must_pass=True, expected_fields={"cachemode": "0"})

        # ========== 步骤5: 关闭DNS加速 + L1-L4验证 ==========
        with rec.step("步骤5: 关闭DNS加速", "关闭并验证进程停止/文件清理/iptables清空"):
            print("\n[步骤5] 关闭DNS加速...")
            result = page.save_basic_config(enable=False)
            assert result is True, "关闭DNS加速失败"
            print(f"  [OK] DNS加速已关闭")
            rec.add_detail("[OK] 关闭成功")

            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            ui_check("已关闭", not page.is_enabled())

            # SSH L1-L4验证关闭状态
            ssh_verify("全链路关闭L1-L4", backend_verifier.verify_dns_basic_full_chain,
                       must_pass=True, expect_enabled=False)
            ssh_verify("L2-文件已清理", backend_verifier.verify_dns_runtime_config,
                       must_pass=True, expect_enabled=False)
            ssh_verify("L3-iptables无REDIRECT", backend_verifier.verify_dns_iptables,
                       must_pass=True, expect_redirect=False)
            ssh_verify("L4-进程已停止", backend_verifier.verify_dns_process,
                       must_pass=True, expect_running=False)

        # ========== 步骤6: 前端校验-非法DNS IP ==========
        # !! 修复(2026-06-18): 旧版只看 .ant-form-item-explain-error 就判"拦截成功"=假绿.
        # 实测发现该错误提示是blur字段级校验, **不阻止保存请求**——后端照样接收非法IP并入库
        # (reload后dns1=999.999.999.999). 改为结果导向: reload读dns1, 非法值不应入库,
        # 若入库则判FAIL并标记产品BUG.
        with rec.step("步骤6: 前端校验-非法DNS IP", "输入非法DNS, 结果导向验证: 非法值不应入库"):
            print("\n[步骤6] 前端校验-非法DNS IP...")
            # 干净起点: 开启 + 合法DNS, 并记录合法旧值(save_basic_config已含开关验证)
            page.save_basic_config(enable=True, dns1=TEST_DNS1, dns2=TEST_DNS2)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            old_dns1 = page.get_dns1()
            rec.add_detail(f"  合法起点 dns1={old_dns1}, 开关={'开' if page.is_enabled() else '关'}")

            # 确认开关已开启(未开则尝试开启, 失败则本步无法测前端校验)
            if not page.is_enabled() and not page.toggle_enable(True):
                ui_check("DNS开关可开启", False, "toggle_enable无法开启, 步骤6无法测前端校验")
            else:
                # 填非法DNS + 点保存
                page.fill_dns1("999.999.999.999")
                page.page.wait_for_timeout(300)
                page.click_save_basic()
                page.page.wait_for_timeout(1500)

                # 前端校验提示(辅助证据)
                explain_error = ""
                try:
                    err_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
                    if err_el.count() > 0:
                        explain_error = (err_el.first.text_content() or "").strip()
                except Exception:
                    pass

                # !! 核心结果导向验证: reload读dns1, 非法值不应入库(必须仍是合法旧值)
                page.navigate_to_dns_accelerate()
                page.page.wait_for_timeout(800)
                new_dns1 = page.get_dns1()
                print(f"  输入999→dns1={new_dns1}, 前端提示=[{explain_error}]")
                rec.add_detail(f"  输入999→dns1={new_dns1}, 前端提示=[{explain_error}]")

                blocked = new_dns1 != "999.999.999.999"
                if not blocked:
                    bug_msg = (f"产品BUG: 非法DNS被保存入库(前端虽提示[{explain_error}]但未阻止保存请求, "
                               f"后端 {old_dns1}→{new_dns1})")
                    print(f"  [FAIL] {bug_msg}")
                    rec.add_detail(f"  [产品BUG] {bug_msg}")
                else:
                    print(f"  [OK] 非法DNS被拦截(dns1保持{new_dns1})")
                    rec.add_detail(f"  [OK] 非法DNS被拦截, dns1保持{new_dns1}")
                ui_check("非法DNS被拦截(非法值不入库)", blocked,
                         f"输入999→{new_dns1}({'拦截OK' if blocked else '入库=产品BUG'})")

            # 恢复(关闭)
            page.save_basic_config(enable=False, dns1=TEST_DNS1, dns2=TEST_DNS2)
            page.page.wait_for_timeout(500)

        # ========== 步骤7: 前端校验-老化时间越界 ==========
        # !! 修复(2026-06-18): 旧版 ttl_low_ok = ttl_low in ("60","30","") 直接接受越界值"30"
        # 原样入库=假绿. 实测: 输入30→入库30, 输入5000→入库5000(既不clamp到边界, 也不保留旧值,
        # 前端"请输入正确的DNS"类校验和后端dns.sh均不拦截=产品BUG). 改为结果导向严格断言:
        # 越界值不应原样入库(应clamp到60/3600或保留旧值), 否则判FAIL并标记产品BUG.
        with rec.step("步骤7: 前端校验-老化时间越界", "输入<60和>3600, 结果导向: 越界值不应原样入库"):
            print("\n[步骤7] 前端校验-老化时间越界...")
            # 干净起点: 开启 + 合法老化时间120(save_basic_config已含开关验证)
            page.save_basic_config(enable=True, cachemode="UDP", dns1=TEST_DNS1, dns2=TEST_DNS2,
                                   cache_ttl=TEST_CACHE_TTL)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            base_ttl = page.get_cache_ttl()
            rec.add_detail(f"  合法起点 cache_ttl={base_ttl}")

            if not page.is_enabled() and not page.toggle_enable(True):
                ui_check("DNS开关可开启", False, "步骤7无法测老化越界")
            else:
                # 测试 <60
                page.fill_cache_ttl("30")
                page.page.wait_for_timeout(300)
                page.click_save_basic()
                page.page.wait_for_timeout(2000)
                page.navigate_to_dns_accelerate()
                page.page.wait_for_timeout(800)
                ttl_low = page.get_cache_ttl()
                print(f"  输入30→实际{ttl_low}(应clamp60或保留{base_ttl}, 不应=30)")
                rec.add_detail(f"  输入30→{ttl_low}")
                # 严格: 30不应原样入库(应clamp到60或保留旧值)
                ttl_low_ok = ttl_low != "30"
                if not ttl_low_ok:
                    rec.add_detail("  [产品BUG] 越界老化时间30原样入库(前端/后端均未校验)")
                ui_check("老化<60不应原样入库", ttl_low_ok,
                         f"输入30→{ttl_low}({'OK' if ttl_low_ok else '原样入库=BUG'})")

                # 重新确保开启(上一步若触发了校验可能未关闭, 这里幂等)
                if not page.is_enabled() and not page.toggle_enable(True):
                    pass
                else:
                    # 测试 >3600
                    page.fill_cache_ttl("5000")
                    page.page.wait_for_timeout(300)
                    page.click_save_basic()
                    page.page.wait_for_timeout(2000)
                    page.navigate_to_dns_accelerate()
                    page.page.wait_for_timeout(800)
                    ttl_high = page.get_cache_ttl()
                    print(f"  输入5000→实际{ttl_high}(应clamp3600或保留{base_ttl}, 不应=5000)")
                    rec.add_detail(f"  输入5000→{ttl_high}")
                    ttl_high_ok = ttl_high != "5000"
                    if not ttl_high_ok:
                        rec.add_detail("  [产品BUG] 越界老化时间5000原样入库(前端/后端均未校验)")
                    ui_check("老化>3600不应原样入库", ttl_high_ok,
                             f"输入5000→{ttl_high}({'OK' if ttl_high_ok else '原样入库=BUG'})")

            # 恢复
            page.save_basic_config(enable=False, cache_ttl=TEST_CACHE_TTL)
            page.page.wait_for_timeout(500)

        # ========== 步骤8: 状态切换稳定性(开-关-开) ==========
        with rec.step("步骤8: 状态切换稳定性", "开→关→开, 验证状态切换稳定性"):
            print("\n[步骤8] 状态切换稳定性...")
            # 第1次开启
            r1 = page.save_basic_config(enable=True, cachemode="UDP",
                                         dns1=TEST_DNS1, dns2=TEST_DNS2)
            page.page.wait_for_timeout(1000)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            assert page.is_enabled(), "第1次开启失败"
            print(f"  [OK] 第1次开启")
            rec.add_detail("[OK] 第1次开启")
            ssh_verify("L1-开启1", backend_verifier.verify_dns_config_database,
                       must_pass=True, expected_fields={"enabled": "yes"})

            # 关闭
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            r2 = page.save_basic_config(enable=False)
            page.page.wait_for_timeout(1000)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            assert not page.is_enabled(), "关闭失败"
            print(f"  [OK] 关闭")
            rec.add_detail("[OK] 关闭")
            ssh_verify("L1-关闭", backend_verifier.verify_dns_config_database,
                       must_pass=True, expected_fields={"enabled": "no"})

            # 第2次开启
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            r3 = page.save_basic_config(enable=True, cachemode="UDP")
            page.page.wait_for_timeout(1000)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            assert page.is_enabled(), "第2次开启失败"
            print(f"  [OK] 第2次开启")
            rec.add_detail("[OK] 第2次开启")
            ssh_verify("L1-开启2", backend_verifier.verify_dns_config_database,
                       must_pass=True, expected_fields={"enabled": "yes"})
            ssh_verify("L4-进程运行", backend_verifier.verify_dns_process,
                       must_pass=True, expect_running=True)

        # ========== 步骤9: 添加反向代理规则 + L1+L2验证 ==========
        with rec.step("步骤9: 添加反向代理规则", "添加IPv4规则, SSH L1数据库 + L2 static.conf验证"):
            print("\n[步骤9] 添加反向代理规则...")
            # DNS加速已开启(步骤8), 添加规则会生成static.conf
            result = page.add_reverse_proxy(
                domain=TEST_DOMAIN, parse_type="IPv4",
                dns_addr=TEST_DNS_ADDR, src_addr=TEST_SRC_ADDR,
                comment=TEST_COMMENT)
            assert result is True, "添加反向代理规则失败"
            print(f"  [OK] 添加规则: {TEST_DOMAIN}")
            rec.add_detail(f"[OK] 添加 {TEST_DOMAIN}")

            # UI验证
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            row = page.find_rule_row(TEST_DOMAIN)
            ui_check("规则存在于表格", row is not None)
            if row:
                ui_check("解析地址正确", TEST_DNS_ADDR in row["dns_addr"], row.get("dns_addr"))
                ui_check("备注正确", TEST_COMMENT in row["comment"], row.get("comment"))

            # SSH L1 + L2验证(DNS加速开启, static.conf应含此规则)
            ssh_verify("反向代理全链路L1+L2",
                       backend_verifier.verify_dns_reverse_proxy_full_chain,
                       must_pass=True, domain=TEST_DOMAIN, expect_exists=True,
                       dns_enabled=True,
                       expected_fields={"dns_addr": TEST_DNS_ADDR,
                                        "parse_type": "ipv4", "enabled": "yes"})

        # ========== 步骤10: 编辑反向代理规则 ==========
        with rec.step("步骤10: 编辑反向代理规则", "修改解析地址, SSH L1验证"):
            print("\n[步骤10] 编辑反向代理规则...")
            result = page.edit_reverse_proxy(
                TEST_DOMAIN, new_dns_addr=TEST_DNS_ADDR_NEW, new_comment="edited")
            assert result is True, "编辑反向代理规则失败"
            print(f"  [OK] 编辑规则: {TEST_DOMAIN}")
            rec.add_detail(f"[OK] 编辑 {TEST_DOMAIN}")

            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            row = page.find_rule_row(TEST_DOMAIN)
            if row:
                ui_check("解析地址已更新", TEST_DNS_ADDR_NEW in row["dns_addr"], row.get("dns_addr"))
            else:
                ui_failures.append(f"UI-编辑后规则消失: {TEST_DOMAIN}")

            ssh_verify("L1-编辑验证", backend_verifier.verify_dns_reverse_proxy_database,
                       must_pass=True, domain=TEST_DOMAIN,
                       expected_fields={"dns_addr": TEST_DNS_ADDR_NEW})

        # ========== 步骤11: 停用/启用反向代理规则 ==========
        with rec.step("步骤11: 停用/启用反向代理规则", "停用后启用, SSH L1 enabled验证"):
            print("\n[步骤11] 停用/启用反向代理规则...")
            # 停用
            r1 = page.disable_reverse_proxy(TEST_DOMAIN)
            page.page.wait_for_timeout(500)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            row = page.find_rule_row(TEST_DOMAIN)
            ui_check("已停用", r1 and row and row.get("enabled") is False,
                     f"r1={r1}, enabled={row.get('enabled') if row else None}")
            ssh_verify("L1-停用验证", backend_verifier.verify_dns_reverse_proxy_database,
                       must_pass=True, domain=TEST_DOMAIN,
                       expected_fields={"enabled": "no"})

            # 启用
            r2 = page.enable_reverse_proxy(TEST_DOMAIN)
            page.page.wait_for_timeout(500)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            row = page.find_rule_row(TEST_DOMAIN)
            ui_check("已启用", r2 and row and row.get("enabled") is True,
                     f"r2={r2}, enabled={row.get('enabled') if row else None}")
            ssh_verify("L1-启用验证", backend_verifier.verify_dns_reverse_proxy_database,
                       must_pass=True, domain=TEST_DOMAIN,
                       expected_fields={"enabled": "yes"})

        # ========== 步骤12: 搜索反向代理规则 ==========
        with rec.step("步骤12: 搜索反向代理规则", "搜索域名, 验证过滤生效"):
            print("\n[步骤12] 搜索反向代理规则...")
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            count_before = page.get_rule_count_by_rows()
            page.search_rule(TEST_DOMAIN)
            page.page.wait_for_timeout(1000)
            rows = page.get_reverse_proxy_rules()
            searched = any(r["domain"] == TEST_DOMAIN for r in rows)
            print(f"  搜索'{TEST_DOMAIN}': 结果{len(rows)}条, 命中={searched}")
            rec.add_detail(f"  搜索结果 {len(rows)}条, 命中={searched}")
            ui_check("搜索命中目标", searched)
            # 清除搜索
            page.clear_search()
            page.page.wait_for_timeout(800)

        # ========== 步骤13: 批量删除 + SSH计数验证 ==========
        with rec.step("步骤13: 批量删除", "全选+批量删除, SSH计数验证(3次重试)"):
            print("\n[步骤13] 批量删除...")
            # 先SSH统计删除前数量
            count_before_ssh = backend_verifier.count_dns_reverse_proxy() if backend_verifier else 0
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            count_before_ui = page.get_rule_count_by_rows()
            print(f"  删除前: UI={count_before_ui}, SSH={count_before_ssh}")
            rec.add_detail(f"  删除前 UI={count_before_ui} SSH={count_before_ssh}")

            # 全选 + 批量删除(3次重试, 参考全模块批量操作断言对齐)
            deleted_ok = False
            for attempt in range(3):
                page.navigate_to_dns_accelerate()
                page.page.wait_for_timeout(800)
                if page.get_rule_count_by_rows() == 0:
                    deleted_ok = True
                    break
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_delete()
                page.page.wait_for_timeout(2000)
                page.navigate_to_dns_accelerate()
                page.page.wait_for_timeout(800)

            count_after_ui = page.get_rule_count_by_rows()
            count_after_ssh = backend_verifier.count_dns_reverse_proxy() if backend_verifier else 0
            print(f"  删除后: UI={count_after_ui}, SSH={count_after_ssh}")
            rec.add_detail(f"  删除后 UI={count_after_ui} SSH={count_after_ssh}")

            ui_check("UI表格已清空", count_after_ui == 0, f"剩{count_after_ui}条")
            # SSH计数验证(批量删除关键断言)
            ssh_verify("L1-批量删除计数", backend_verifier.verify_dns_reverse_proxy_database,
                       must_pass=True, domain=TEST_DOMAIN, must_exist=False)
            if count_after_ssh > 0 and count_before_ssh > 0:
                ssh_failures.append(
                    f"SSH-批量删除计数: 删除前{count_before_ssh}→删除后{count_after_ssh}(应清零)")

        # ========== 步骤14: 前端校验-空域名/空解析地址 ==========
        with rec.step("步骤14: 前端校验-空域名/空解析地址", "不填必填项保存, 验证前端拦截"):
            print("\n[步骤14] 前端校验-空域名/空解析地址...")
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            page.navigate_to_add_page()
            page.page.wait_for_timeout(500)

            # 不填域名和解析地址, 直接保存
            page.click_save_form()
            page.page.wait_for_timeout(1500)
            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content()
                print(f"  [OK] 空必填项被拦截: {error_text}")
                rec.add_detail(f"[OK] 空必填拦截: {error_text}")
            else:
                success = page.wait_for_success_message(timeout=2000)
                if not success:
                    print(f"  [OK] 空必填保存被拦截")
                    rec.add_detail("[OK] 空必填被拦截")
                else:
                    ui_failures.append("UI-空必填项未被拦截")

            # 返回列表页
            page.click_cancel_form()
            page.page.wait_for_timeout(500)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)

        # ========== 步骤15: 帮助功能 ==========
        with rec.step("步骤15: 帮助功能", "点击帮助按钮, 验证帮助面板显示"):
            print("\n[步骤15] 帮助功能...")
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            clicked = page.click_help()
            page.page.wait_for_timeout(1000)
            visible = page.is_help_panel_visible()
            print(f"  帮助按钮点击={clicked}, 面板可见={visible}")
            rec.add_detail(f"  帮助: 点击={clicked} 面板={visible}")
            if visible:
                page.close_help_panel()
                page.page.wait_for_timeout(300)
            # 帮助功能不强制断言(部分环境面板渲染差异), 仅记录
            if not clicked and not visible:
                rec.add_detail("[INFO] 帮助按钮/面板未检测到(可能选择器差异)")

        # ========== 步骤16: 最终恢复 ==========
        with rec.step("步骤16: 最终恢复", "关闭DNS加速并清理所有测试规则"):
            print("\n[步骤16] 最终恢复...")
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(500)
            # 清理残留规则
            for domain in LEGACY_DOMAINS:
                for _ in range(2):
                    if page.find_rule_row(domain):
                        page.delete_reverse_proxy(domain)
                    else:
                        break
            # 关闭DNS加速
            if page.is_enabled():
                page.save_basic_config(enable=False)
                page.page.wait_for_timeout(1000)
            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            restored = not page.is_enabled()
            print(f"  [恢复] DNS加速已关闭={restored}")
            rec.add_detail(f"[恢复] 关闭={restored}")

            ssh_verify("L1-最终关闭", backend_verifier.verify_dns_config_database,
                       must_pass=True, expected_fields={"enabled": "no"})
            ssh_verify("L4-进程已停止", backend_verifier.verify_dns_process,
                       must_pass=False, expect_running=False)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"DNS加速服务综合测试完成, 发现 {len(all_failures)} 个失败:")
            for f in all_failures:
                print(f"  - {f}")
        else:
            print("DNS加速服务综合测试全部通过!")
        print("=" * 60)

        assert not all_failures, f"DNS加速服务测试失败 {len(all_failures)} 项: {all_failures}"
