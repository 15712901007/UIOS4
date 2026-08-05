"""
DHCP服务端综合测试用例

网络配置 > DHCP服务 > DHCP服务端 综合测试
DHCP服务端是表格型模块(每个LAN/VLAN接口一条DHCP地址池配置), 添加/编辑为独立页面。

测试策略(关键):
- 从被测设备实时读取全部非DHTEST基线规则，自动选择有足够空闲地址的启用池。
- 在该规则的同一接口/同一子网内，从未被任何现有池占用的地址中动态生成测试池。
- 全程保护所有基线规则，不依赖固定名称、接口网段或默认池大小。
- 停用DHTEST_1不影响ik_dhcpd进程(基线规则仍enabled), 仅从ik_dhcpd.conf移除该池。

一次测试覆盖(17步):
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
15. 帮助功能
16. 批量删除 + SSH验证
17. 最终清理 + 全部基线规则完整性保护验证

SSH后台验证: L1数据库(dhcp_server表) + L2进程(ik_dhcpd) + L3配置文件(ik_dhcpd.conf) +
            L4运行时(UDP67/status文件) + L4-iptables(DHCP_ACL链) + L4-模拟重启(boot)
字段映射: tagname=名称 interface=服务接口 addr_pool=客户端地址(start-end) netmask=子网掩码
         gateway=网关 dns1/dns2 lease=租期(分钟) delay=过期保留(小时) check_addr_valid
"""
from dataclasses import dataclass
import ipaddress
from typing import Dict, List, Tuple

import pytest
from pages.network.dhcp_server_page import DhcpServerPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify


TEST_RULE = "DHTEST_1"
TEST_LEASE = 60
TEST_DELAY = 2
TEST_LEASES = [60, 90, 120, 150, 180, 240]
BASELINE_FIELDS = (
    "enabled", "tagname", "interface", "addr_pool", "netmask", "gateway",
    "dns1", "dns2", "lease", "phy_ifnames",
)


@dataclass(frozen=True)
class DhcpTestContext:
    interface: str
    netmask: str
    gateway: str
    dns1: str
    dns2: str
    baseline_rules: List[Dict[str, str]]
    test_rules: List[Dict[str, object]]
    extra_pool: Tuple[str, str]


def _pool_interval(rule: Dict[str, str]):
    try:
        start, end = str(rule.get("addr_pool", "")).split("-", 1)
        start_ip = ipaddress.ip_address(start.strip())
        end_ip = ipaddress.ip_address(end.strip())
        if start_ip.version != 4 or end_ip.version != 4 or start_ip > end_ip:
            return None
        return int(start_ip), int(end_ip)
    except (ValueError, TypeError):
        return None


def _free_intervals(network, gateway, rules, interface):
    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1
    occupied = [(int(gateway), int(gateway))]
    for rule in rules:
        if str(rule.get("interface", "")) != interface:
            continue
        interval = _pool_interval(rule)
        if not interval:
            continue
        start, end = max(first, interval[0]), min(last, interval[1])
        if start <= end:
            occupied.append((start, end))
    occupied.sort()
    merged = []
    for start, end in occupied:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    free, cursor = [], first
    for start, end in merged:
        if cursor < start:
            free.append((cursor, start - 1))
        cursor = max(cursor, end + 1)
    if cursor <= last:
        free.append((cursor, last))
    return free


def _allocate_test_pools(free_intervals, count=7):
    """从高地址向下分配小型连续池，避免占用正在使用的基线租约区。"""
    for pool_size in range(5, 1, -1):
        pools = []
        for start, end in reversed(free_intervals):
            cursor = end
            while cursor - pool_size + 1 >= start and len(pools) < count:
                pools.append((cursor - pool_size + 1, cursor))
                cursor -= pool_size
            if len(pools) == count:
                return list(reversed(pools))
    return []


def build_dhcp_test_context(rules: List[Dict[str, str]]) -> DhcpTestContext:
    """根据设备现有DHCP规则生成同网段且无冲突的测试数据。"""
    baseline = [dict(r) for r in rules if not str(r.get("tagname", "")).startswith("DHTEST")]
    candidates = []
    for rule in baseline:
        if str(rule.get("enabled", "")).lower() != "yes":
            continue
        try:
            gateway = ipaddress.ip_address(str(rule.get("gateway", "")))
            network = ipaddress.ip_network(
                f"{gateway}/{rule.get('netmask', '')}", strict=False)
        except ValueError:
            continue
        interface = str(rule.get("interface", ""))
        if gateway.version != 4 or not interface:
            continue
        free = _free_intervals(network, gateway, rules, interface)
        pools = _allocate_test_pools(free, count=7)
        if pools:
            free_count = sum(end - start + 1 for start, end in free)
            candidates.append((interface != "lan1", -free_count, rule, pools))
    if not candidates:
        raise ValueError("没有启用且至少有14个可用地址的DHCP基线子网")

    _, _, primary, pools = sorted(candidates, key=lambda item: item[:2])[0]
    test_rules = []
    for index, ((start, end), lease) in enumerate(zip(pools[:6], TEST_LEASES), start=1):
        test_rules.append({
            "name": f"DHTEST_{index}",
            "pool_start": str(ipaddress.ip_address(start)),
            "pool_end": str(ipaddress.ip_address(end)),
            "lease": lease,
        })
    return DhcpTestContext(
        interface=str(primary["interface"]),
        netmask=str(primary["netmask"]),
        gateway=str(primary["gateway"]),
        dns1=str(primary.get("dns1") or "114.114.114.114"),
        dns2=str(primary.get("dns2") or "223.5.5.5"),
        baseline_rules=baseline,
        test_rules=test_rules,
        extra_pool=(str(ipaddress.ip_address(pools[6][0])), str(ipaddress.ip_address(pools[6][1]))),
    )


def baseline_mismatches(expected_rules, actual_rules):
    """返回基线规则缺失或关键字段变化，忽略导入后可能变化的数据库id。"""
    actual_by_name = {str(r.get("tagname", "")): r for r in actual_rules}
    mismatches = []
    for expected in expected_rules:
        name = str(expected.get("tagname", ""))
        actual = actual_by_name.get(name)
        if actual is None:
            mismatches.append(f"{name}: 缺失")
            continue
        changes = [
            f"{field}={actual.get(field)!r}(期望{expected.get(field)!r})"
            for field in BASELINE_FIELDS
            if str(actual.get(field, "")) != str(expected.get(field, ""))
        ]
        if changes:
            mismatches.append(f"{name}: " + ", ".join(changes))
    return mismatches


def find_serving_rule(rules, client_ip):
    """按地址池优先、子网兜底，查找实际服务客户端的启用规则。"""
    try:
        address = ipaddress.ip_address(str(client_ip))
    except ValueError:
        return None
    subnet_match = None
    for rule in rules:
        if str(rule.get("enabled", "")).lower() != "yes":
            continue
        interval = _pool_interval(rule)
        if interval and interval[0] <= int(address) <= interval[1]:
            return rule
        try:
            gateway = ipaddress.ip_address(str(rule.get("gateway", "")))
            network = ipaddress.ip_network(
                f"{gateway}/{rule.get('netmask', '')}", strict=False
            )
            if address in network and subnet_match is None:
                subnet_match = rule
        except ValueError:
            continue
    return subnet_match


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

        if backend_verifier is None:
            pytest.skip("DHCP综合测试需要SSH验证器来生成安全的同网段测试池")

        ssh_failures = []
        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        def record_failure(message):
            ssh_failures.append(message)
            rec.add_detail(f"[FAIL] {message}")
            rec.fail_current_step(message)

        def wait_dhcpd_settle():
            """等待ik_dhcpd __delayed_restart(2秒)生效"""
            page.page.wait_for_timeout(3000)

        print("\n" + "=" * 60)
        print("DHCP服务端综合测试开始")
        print("=" * 60)

        # ========== 步骤1: 初始环境检查 + 清理残留 ==========
        with rec.step("步骤1: 初始环境检查+清理残留", "清理DHTEST残留规则, 确认ik_dhcpd运行"):
            print("\n[步骤1] 初始环境检查...")
            # 清理之前的残留测试规则(SQL兜底)，再从真实设备构造测试数据。
            backend_verifier.cleanup_dhcp_server_test_rules("DHTEST")
            current_rules = backend_verifier.query_all_dhcp_server() or []
            try:
                test_context = build_dhcp_test_context(current_rules)
            except ValueError as exc:
                pytest.fail(f"DHCP测试环境不可用: {exc}")
            initial_snapshot = backend_verifier.snapshot_dhcp_server()
            if not initial_snapshot.strip():
                pytest.fail("无法备份DHCP基线，拒绝执行导入清空测试")

            def cleanup_and_restore_baseline():
                """即使用例中途异常，也清理测试规则并恢复受影响的基线。"""
                try:
                    backend_verifier.cleanup_dhcp_server_test_rules("DHTEST")
                    actual = backend_verifier.query_all_dhcp_server() or []
                    if baseline_mismatches(test_context.baseline_rules, actual):
                        backend_verifier.restore_dhcp_server(initial_snapshot)
                except Exception:
                    pass

            request.addfinalizer(cleanup_and_restore_baseline)

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)

            initial_count = page.get_rule_count()
            database_count = len(current_rules)
            print(f"  当前DHCP服务端规则数: {initial_count}")
            rec.add_detail(f"初始规则数: 页面={initial_count}, 数据库={database_count}")
            rec.add_detail(
                f"动态测试基线: interface={test_context.interface}, "
                f"gateway={test_context.gateway}/{test_context.netmask}, "
                f"保护规则={[r.get('tagname') for r in test_context.baseline_rules]}"
            )
            rec.add_detail(
                "动态测试池: " + ", ".join(
                    f"{r['name']}={r['pool_start']}-{r['pool_end']}"
                    for r in test_context.test_rules
                )
            )
            if initial_count != database_count:
                record_failure(f"页面规则数{initial_count}与数据库{database_count}不一致")

            # SSH验证基线DHCP服务正常。
            ssh_verify("L2-初始进程", backend_verifier.verify_dhcp_server_process,
                       must_pass=True, expect_running=True)
            ssh_verify("L4-iptables", backend_verifier.verify_dhcp_server_iptables,
                       must_pass=True, expect_dhcp_acl=True)

        # ========== 步骤2: 批量添加6条 + L1-L4全链路验证 ==========
        test_rules = test_context.test_rules
        test_names = [rule["name"] for rule in test_rules]
        primary_rule = test_rules[0]
        with rec.step("步骤2: 批量添加6条", f"添加{len(test_rules)}条DHCP池并SSH L1-L4验证"):
            print(f"\n[步骤2] 批量添加{len(test_rules)}条DHCP池...")
            add_results = []
            for rule in test_rules:
                result = page.add_dhcp_server(
                    name=rule["name"], interface=test_context.interface,
                    pool_start=rule["pool_start"], pool_end=rule["pool_end"],
                    netmask=test_context.netmask, gateway=test_context.gateway,
                    dns1=test_context.dns1, dns2=test_context.dns2,
                    lease=rule["lease"], delay=TEST_DELAY,
                    check_addr_valid=False,
                )
                add_results.append(result)
                print(f"  添加 {rule['name']}({rule['pool_start']}-{rule['pool_end']}): {result}")
                rec.add_detail(f"添加{rule['name']}: {result}")
            if not all(add_results):
                record_failure(
                    "添加失败: " + ", ".join(
                        rule["name"] for rule, ok in zip(test_rules, add_results) if not ok
                    )
                )
            else:
                rec.add_detail(f"[OK] {len(test_rules)}条页面添加成功")

            wait_dhcpd_settle()

            # 验证规则在列表中
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            if page.rule_exists(TEST_RULE):
                rec.add_detail("[OK] DHTEST_1列表可见")
            else:
                record_failure("DHTEST_1未出现在列表中")

            actual_names = {
                str(rule.get("tagname", ""))
                for rule in (backend_verifier.query_all_dhcp_server() or [])
            }
            missing_names = [name for name in test_names if name not in actual_names]
            if missing_names:
                record_failure(f"批量添加后数据库缺少规则: {missing_names}")

            # SSH L1-L4全链路验证
            ssh_verify("L1-添加验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={
                           "enabled": "yes", "interface": test_context.interface,
                           "addr_pool": (
                               f"{primary_rule['pool_start']}-{primary_rule['pool_end']}"
                           ),
                           "netmask": test_context.netmask,
                           "gateway": test_context.gateway,
                           "dns1": test_context.dns1, "dns2": test_context.dns2,
                           "lease": str(TEST_LEASE), "delay": str(TEST_DELAY),
                           "check_addr_valid": "0", "status": "1",
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
            if result:
                rec.add_detail("[OK] 编辑成功")
            else:
                record_failure("编辑DHTEST_1失败")

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
            if not disabled or not is_disabled:
                record_failure(
                    f"页面停用状态异常: 操作返回={disabled}, 行状态={is_disabled}"
                )

            # SSH结果导向验证(不依赖disable_rule返回值)
            ssh_verify("L1-停用验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={"enabled": "no"})
            # 停用规则应从ik_dhcpd.conf移除(仅enabled=yes才下发)
            ssh_verify("L3-停用后conf移除", backend_verifier.verify_dhcp_server_config_file,
                       must_pass=True, tagname=TEST_RULE, expect_in_conf=False,
                       expect_any_enabled=True)
            # 进程应仍运行(设备基线规则仍enabled)
            ssh_verify("L2-停用后进程", backend_verifier.verify_dhcp_server_process,
                       must_pass=True, expect_running=True)

        # ========== 步骤5: 启用DHTEST_1 ==========
        with rec.step("步骤5: 启用DHTEST_1", "启用并验证回到ik_dhcpd.conf"):
            print("\n[步骤5] 启用DHTEST_1...")

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            enabled = page.enable_rule(TEST_RULE)
            page.page.wait_for_timeout(500)
            wait_dhcpd_settle()

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            is_enabled = page.is_rule_enabled(TEST_RULE)
            rec.add_detail(f"页面: enabled={enabled}, is_enabled={is_enabled}")
            if not enabled or not is_enabled:
                record_failure(
                    f"页面启用状态异常: 操作返回={enabled}, 行状态={is_enabled}"
                )

            ssh_verify("L1-启用验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE,
                       expected_fields={"enabled": "yes"})
            ssh_verify("L3-启用后conf恢复", backend_verifier.verify_dhcp_server_config_file,
                       must_pass=True, tagname=TEST_RULE, expect_in_conf=True)

        # ========== 步骤6: 模拟重启验证(对照DMZ bug) ==========
        with rec.step("步骤6: 模拟重启验证", "执行dhcp_server.sh boot, 验证配置从数据库重建"):
            print("\n[步骤6] 模拟重启验证(dhcp_server.sh boot)...")

            reboot_result = ssh_verify(
                "L4-模拟重启",
                backend_verifier.verify_dhcp_server_reboot,
                must_pass=True,
                tagname=TEST_RULE,
                expect_any_enabled=True,
            )
            reboot_output = str(getattr(reboot_result, "raw_output", "") or "")
            if reboot_result and reboot_result.passed and "Error:" in reboot_output:
                warning = (
                    "重复执行dhcp_server.sh boot时租约库导入打印冲突错误；"
                    "退出码和DHCP配置/进程状态正常，按环境警告记录"
                )
                rec.add_detail(f"[WARN] {warning}")
                rec.warn_current_step(warning)
            boot_baseline_errors = baseline_mismatches(
                test_context.baseline_rules,
                backend_verifier.query_all_dhcp_server() or [],
            )
            if boot_baseline_errors:
                record_failure(f"模拟重启后基线变化: {boot_baseline_errors}")

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
                record_failure("空必填提交后未显示前端校验错误")
            if backend_verifier.query_dhcp_server_rule("DHTEST_INVALID") is not None:
                record_failure("空必填配置被写入数据库")
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
            page.select_interface(test_context.interface)
            page.fill_addr_pool("999.999.999.999", "999.999.999.998")  # 非法IP
            page.fill_gateway(test_context.gateway)
            page.fill_dns1(test_context.dns1)
            page.fill_dns2(test_context.dns2)
            page.page.wait_for_timeout(300)
            page.click_save()
            page.page.wait_for_timeout(1500)

            error_el = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content().strip()
                print(f"  [OK] 前端拦截非法地址: {error_text[:60]}")
                rec.add_detail(f"[OK] 拦截非法地址: {error_text[:60]}")
            else:
                record_failure("非法客户端地址提交后未显示前端校验错误")
            if backend_verifier.query_dhcp_server_rule("DHTEST_INVALID2") is not None:
                record_failure("非法客户端地址配置被写入数据库")
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
            if error_el.count() > 0:
                error_text = error_el.first.text_content().strip()
                print(f"  [OK] 租期越界拦截: {error_text[:60]}")
                rec.add_detail(f"[OK] 租期越界拦截: {error_text[:60]}")
            else:
                record_failure("租期0提交后未显示前端校验错误")

            # 无论是否拦截, 恢复lease为合法值并保存(避免污染DHTEST_1)
            try:
                page.fill_lease(TEST_LEASE)
                page.page.wait_for_timeout(300)
                restored = page.save_form(expect_success=True)
                page.page.wait_for_timeout(2000)
                if not restored:
                    record_failure("租期越界测试后恢复合法租期保存失败")
            except Exception:
                record_failure("租期越界测试后恢复合法租期发生异常")
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
            backend_verifier.connect_router()
            pid_before = backend_verifier._router.exec("pidof ik_dhcpd 2>/dev/null").strip()
            restarted = page.click_restart_dhcp()
            print(f"  点击重启: {restarted}")
            rec.add_detail(f"点击重启: {restarted}")
            if not restarted:
                record_failure("重启DHCP服务按钮操作未成功")

            wait_dhcpd_settle()
            pid_after = backend_verifier._router.exec("pidof ik_dhcpd 2>/dev/null").strip()
            rec.add_detail(f"进程PID: 重启前={pid_before or '无'}, 重启后={pid_after or '无'}")
            if not pid_before or not pid_after or pid_before == pid_after:
                record_failure(
                    f"点击重启后ik_dhcpd PID未变化({pid_before or '无'}->{pid_after or '无'})"
                )
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
                if not found:
                    record_failure("搜索DHTEST未找到DHTEST_1")
                page.clear_search()
                page.page.wait_for_timeout(500)
                # 搜索不存在的规则(验证无结果)
                page.search_rule("NOTEXIST_XYZ")
                page.page.wait_for_timeout(1000)
                not_found = not page.rule_exists(TEST_RULE)
                print(f"  搜索'NOTEXIST_XYZ'无结果: {not_found}")
                rec.add_detail(f"搜索不存在无结果: {not_found}")
                if not not_found:
                    record_failure("搜索不存在关键字仍显示DHTEST_1")
                page.clear_search()
                page.page.wait_for_timeout(500)
            except Exception as e:
                record_failure(f"搜索功能异常: {e}")

        # ========== 步骤11.5: 排序测试(6条数据) ==========
        with rec.step("步骤11.5: 排序测试", "按列排序(6条数据有意义)"):
            print("\n[步骤11.5] 排序测试...")
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            sortable_columns = page.get_sortable_columns()
            if not sortable_columns:
                rec.add_detail("不适用: 当前DHCP服务端表头没有排序控件或aria-sort能力")
                rec.not_applicable_current_step("产品页面未提供排序功能")
            else:
                targets = [col for col in ["名称", "租期"] if col in sortable_columns]
                sort_ok = sum(
                    1 for col in targets for _ in range(2)
                    if page.sort_by_column(col)
                )
                rec.add_detail(f"排序能力列={sortable_columns}, 成功点击={sort_ok}")
                if not targets or sort_ok != len(targets) * 2:
                    record_failure("页面声明排序能力，但名称/租期双向排序未完整执行")

        # ========== 步骤12: 导出测试(保存路径供导入用) ==========
        with rec.step("步骤12: 导出测试", "导出当前配置(含设备基线+DHTEST), 供导入测试使用"):
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
                if not exported or not csv_ok:
                    record_failure(f"导出结果异常: txt={exported}, csv={csv_ok}")
                elif not _os.path.exists(export_file):
                    record_failure(f"TXT导出文件不存在: {export_file}")
                else:
                    with open(export_file, 'r', encoding='utf-8') as exported_handle:
                        exported_text = exported_handle.read()
                    expected_export_names = [
                        str(rule.get("tagname", ""))
                        for rule in test_context.baseline_rules
                    ] + test_names
                    missing_exports = [
                        name for name in expected_export_names
                        if f"tagname={name}" not in exported_text
                    ]
                    if missing_exports:
                        record_failure(f"TXT导出缺少规则: {missing_exports}")
            except Exception as e:
                exported = False
                record_failure(f"导出异常: {e}")

        # ========== 步骤13: 导入测试-追加(不勾清空) ==========
        with rec.step("步骤13: 导入追加", "删除DHTEST_1后导入(不勾清空), 验证追加恢复"):
            print("\n[步骤13] 导入测试-追加...")
            if not (exported and _os.path.exists(export_file)):
                record_failure(f"无有效导出文件，无法验证导入追加: {export_file}")
            else:
                # 只导入DHTEST规则，避免基线tagname冲突导致整批失败。
                import_file_append = export_file.replace(".txt", "_append.txt")
                try:
                    with open(export_file, 'r', encoding='utf-8') as f:
                        all_lines = f.readlines()
                    test_lines = [l for l in all_lines if 'tagname=DHTEST' in l]
                    with open(import_file_append, 'w', encoding='utf-8') as f:
                        f.writelines(test_lines)
                    print(f"  追加导入文件含{len(test_lines)}条DHTEST规则(已过滤设备基线)")
                    rec.add_detail(f"追加文件: {len(test_lines)}条DHTEST规则")
                    if len(test_lines) != len(test_rules):
                        record_failure(
                            f"追加导入文件规则数{len(test_lines)}，期望{len(test_rules)}"
                        )
                except Exception as e:
                    import_file_append = ""
                    test_lines = []
                    record_failure(f"准备追加导入文件失败: {e}")

                # 清理全部测试规则，保留设备基线，验证追加能恢复6条测试规则。
                backend_verifier.cleanup_dhcp_server_test_rules("DHTEST")
                wait_dhcpd_settle()

                count_before = len(backend_verifier.query_all_dhcp_server() or [])
                print(f"  导入前规则数: {count_before}")
                rec.add_detail(f"导入前数据库规则数: {count_before}")

                # 导入追加(不勾清空现有)
                try:
                    page.navigate_to_dhcp_server()
                    page.page.wait_for_timeout(800)
                    import_ok = bool(import_file_append) and page.import_rules(
                        import_file_append, clear_existing=False
                    )
                    if not import_ok:
                        record_failure("导入追加操作返回失败")
                    wait_dhcpd_settle()
                except Exception as e:
                    record_failure(f"导入追加异常: {e}")

                page.navigate_to_dhcp_server()
                page.page.wait_for_timeout(800)
                rules_after_append = backend_verifier.query_all_dhcp_server() or []
                count_after = len(rules_after_append)
                print(f"  导入后规则数: {count_after}")
                rec.add_detail(f"导入后数据库规则数: {count_after}")

                expected_after = count_before + len(test_rules)
                if count_after == expected_after:
                    rec.add_detail(f"[OK] 追加成功 +{len(test_rules)}条")
                else:
                    record_failure(
                        f"追加后数据库规则数{count_after}，期望{expected_after}"
                    )

                appended_names = {str(r.get("tagname", "")) for r in rules_after_append}
                missing_appended = [name for name in test_names if name not in appended_names]
                if missing_appended:
                    record_failure(f"追加导入缺少测试规则: {missing_appended}")
                append_baseline_errors = baseline_mismatches(
                    test_context.baseline_rules, rules_after_append
                )
                if append_baseline_errors:
                    record_failure(f"追加导入改变设备基线: {append_baseline_errors}")

                # SSH验证DHTEST_1恢复，全部基线由上方字段签名统一验证。
                ssh_verify("L1-导入追加-DHTEST_1恢复", backend_verifier.verify_dhcp_server_database,
                           must_pass=True, name=TEST_RULE, must_exist=True)

        # ========== 步骤14: 导入测试-清空现有(勾清空, 带基线备份恢复兜底) ==========
        with rec.step("步骤14: 导入清空", "加DHTEST_EXTRA标志, 清空导入, 验证清空生效+全部基线恢复"):
            print("\n[步骤14] 导入测试-清空现有...")
            if not (exported and _os.path.exists(export_file)):
                record_failure("无有效导出文件，无法验证清空导入")
            else:
                extra_rule = "DHTEST_EXTRA"
                # 添加DHTEST_EXTRA(不在导出文件, 作为清空生效标志), 独立地址池避免冲突
                extra_added = page.add_dhcp_server(
                    name=extra_rule, interface=test_context.interface,
                    pool_start=test_context.extra_pool[0],
                    pool_end=test_context.extra_pool[1],
                    netmask=test_context.netmask, gateway=test_context.gateway,
                    dns1=test_context.dns1, dns2=test_context.dns2,
                    lease=TEST_LEASE, delay=0, check_addr_valid=False,
                )
                if not extra_added:
                    record_failure(f"添加{extra_rule}清空标志失败")
                wait_dhcpd_settle()

                page.navigate_to_dhcp_server()
                page.page.wait_for_timeout(800)
                count_before = len(backend_verifier.query_all_dhcp_server() or [])
                print(f"  清空导入前规则数: {count_before}(含{extra_rule})")
                rec.add_detail(
                    f"清空前数据库规则数: {count_before}(含{extra_rule}标志); "
                    f"初始基线备份={len(initial_snapshot)}字符"
                )

                # 导入清空(勾选"清空现有数据")
                try:
                    page.navigate_to_dhcp_server()
                    page.page.wait_for_timeout(800)
                    clear_import_ok = page.import_rules(export_file, clear_existing=True)
                    if not clear_import_ok:
                        record_failure("清空导入操作返回失败")
                    wait_dhcpd_settle()
                except Exception as e:
                    record_failure(f"清空导入异常: {e}")

                page.navigate_to_dhcp_server()
                page.page.wait_for_timeout(800)

                # 验证1: DHTEST_EXTRA应被删(它不在导出文件, 删除=清空生效证据)
                rules_after_clear = backend_verifier.query_all_dhcp_server() or []
                extra_exists = backend_verifier.query_dhcp_server_rule(extra_rule) is not None
                if not extra_exists:
                    print(f"  [OK] 清空生效({extra_rule}已删除)")
                    rec.add_detail(f"[OK] 清空生效, {extra_rule}已删")
                else:
                    record_failure(f"导入清空后{extra_rule}仍存在")

                # 验证导出文件完整恢复了所有设备基线和6条测试规则。
                clear_baseline_errors = baseline_mismatches(
                    test_context.baseline_rules, rules_after_clear
                )
                clear_names = {str(r.get("tagname", "")) for r in rules_after_clear}
                missing_clear_tests = [name for name in test_names if name not in clear_names]
                if clear_baseline_errors:
                    record_failure(f"清空导入后基线异常: {clear_baseline_errors}")
                if missing_clear_tests:
                    record_failure(f"清空导入后缺少测试规则: {missing_clear_tests}")

                if clear_baseline_errors:
                    rec.add_detail("基线异常，使用测试前快照恢复")
                    if not backend_verifier.restore_dhcp_server(initial_snapshot):
                        record_failure("DHCP基线快照恢复操作失败")
                    wait_dhcpd_settle()

                # 清理可能残留的DHTEST_EXTRA
                backend_verifier.cleanup_dhcp_server_test_rules("DHTEST_EXTRA")
                wait_dhcpd_settle()

                primary_baseline = test_context.baseline_rules[0]
                ssh_verify(
                    "L1-清空导入后基线完整",
                    backend_verifier.verify_dhcp_server_database,
                    must_pass=True,
                    name=str(primary_baseline.get("tagname", "")),
                    expected_fields={
                        field: primary_baseline.get(field, "")
                        for field in BASELINE_FIELDS
                        if field not in {"tagname", "phy_ifnames"}
                    },
                )

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
                        record_failure("点击帮助后帮助面板未显示")
                        page.page.keyboard.press("Escape")
                else:
                    record_failure("帮助按钮未找到")
            except Exception as e:
                record_failure(f"帮助功能异常: {e}")

        # ========== 步骤16: 批量删除所有DHTEST ==========
        with rec.step("步骤16: 批量删除", "删除所有DHTEST规则并SSH验证"):
            print("\n[步骤16] 批量删除所有DHTEST...")
            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            existing_test_names = [
                name for name in test_names
                if backend_verifier.query_dhcp_server_rule(name) is not None
            ]
            if not existing_test_names:
                record_failure("批量删除前没有可选择的DHTEST规则")
            else:
                for name in existing_test_names:
                    page.select_rule(name)
                page.batch_delete()
                wait_dhcpd_settle()

            remaining = [
                name for name in test_names
                if backend_verifier.query_dhcp_server_rule(name) is not None
            ]
            if remaining:
                record_failure(f"页面批量删除后仍残留: {remaining}")
                backend_verifier.cleanup_dhcp_server_test_rules("DHTEST")
                wait_dhcpd_settle()

            page.navigate_to_dhcp_server()
            page.page.wait_for_timeout(800)
            exists = page.rule_exists(TEST_RULE)
            print(f"  删除后DHTEST_1存在: {exists}")
            rec.add_detail(f"删除后DHTEST_1存在: {exists}")

            # SSH验证彻底删除
            ssh_verify("L1-删除验证", backend_verifier.verify_dhcp_server_database,
                       must_pass=True, name=TEST_RULE, must_exist=False)

        # ========== 步骤17: 最终清理 + 全部基线完整性保护 ==========
        with rec.step("步骤17: 最终清理+基线完整性", "清理残留 + 验证全部设备基线未被破坏"):
            print("\n[步骤17] 最终清理 + 基线完整性验证...")

            # SQL兜底清理任何DHTEST残留
            backend_verifier.cleanup_dhcp_server_test_rules("DHTEST")
            wait_dhcpd_settle()

            final_rules = backend_verifier.query_all_dhcp_server() or []
            final_baseline_errors = baseline_mismatches(
                test_context.baseline_rules, final_rules
            )
            if final_baseline_errors:
                record_failure(f"最终设备基线异常: {final_baseline_errors}")
            if len(final_rules) != len(test_context.baseline_rules):
                record_failure(
                    f"最终规则数{len(final_rules)}，期望基线数{len(test_context.baseline_rules)}"
                )
            else:
                rec.add_detail(
                    f"[OK] 全部{len(test_context.baseline_rules)}条设备基线保持完整"
                )
            ssh_verify("L2-最终进程", backend_verifier.verify_dhcp_server_process,
                       must_pass=True, expect_running=True)
            ssh_verify("L4-最终运行时", backend_verifier.verify_dhcp_server_runtime,
                       must_pass=True, expect_running=True)

            final_test_names = [
                str(rule.get("tagname", "")) for rule in final_rules
                if str(rule.get("tagname", "")).startswith("DHTEST")
            ]
            if final_test_names:
                record_failure(f"最终仍有DHTEST残留: {final_test_names}")
            else:
                rec.add_detail("[OK] 最终无DHTEST残留")

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
        print("  - 导入追加 + 导入清空(DHTEST_EXTRA标志验证, 动态基线备份恢复兜底)")
        print("  - 帮助功能")
        print("  - 真实批量删除 + SSH验证")
        print("  - 全部设备基线完整性保护")
        print("  - SSH后台验证: L1数据库+L2进程+L3配置+L4运行时+L4-iptables+L4-模拟重启")

        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not ssh_failures, \
            f"DHCP综合验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"


@pytest.mark.dhcp_server
@pytest.mark.network
class TestDhcpServerFlowVerification:
    """DHCP服务端L5验证：动态识别服务池并强制客户端重新获取租约。"""

    def test_dhcp_server_flow(self, dhcp_server_page_logged_in, step_recorder: StepRecorder, request):
        _ = dhcp_server_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            pytest.skip("无SSH验证器, 跳过DHCP服务端功能验证")
        failures = []
        print("\n" + "=" * 50)
        print("DHCP服务端功能验证(L5 dhclient获取)")
        print("=" * 50)

        def flow_failure(message):
            failures.append(message)
            rec.add_detail(f"  [FAIL] {message}")
            rec.fail_current_step(message)

        def _release_renew(iface):
            """down/up网卡触发systemd-networkd重新DHCP，轮询返回首个IPv4。"""
            bv.connect_client()
            bv._client.exec(
                f"sudo ip link set {iface} down; sleep 2; sudo ip link set {iface} up",
                timeout=15,
            )
            for _ in range(10):
                bv._client.exec("sleep 2", timeout=5)
                out = bv._client.exec(
                    f"ip -4 addr show {iface} 2>/dev/null | "
                    "grep -oP 'inet \\K[0-9.]+' | head -1"
                )
                ip = out.strip()
                if ip:
                    return ip
            return ""

        client_iface = ""
        try:
            all_srv = bv.query_all_dhcp_server() or []
            serving_rule = None
            client_info = {}
            for srv in all_srv:
                if str(srv.get("enabled", "")).lower() != "yes" or not srv.get("gateway"):
                    continue
                candidate = bv.get_client_lan_info(gateway=str(srv["gateway"]))
                matched = find_serving_rule(all_srv, candidate.get("ip", ""))
                if matched and matched.get("tagname") == srv.get("tagname"):
                    serving_rule = srv
                    client_info = candidate
                    break

            client_iface = str(client_info.get("iface", ""))
            client_ip = str(client_info.get("ip", ""))
            client_mac = str(client_info.get("mac", ""))

            with rec.step("L1-L4后端验证", "数据库(dhcp_server)+ik_dhcpd进程+ik_dhcpd.conf+UDP67运行时"):
                rec.add_detail(
                    f"  client: iface={client_iface or '未找到'} "
                    f"ip={client_ip or '未找到'} mac={client_mac or '未找到'}"
                )
                rec.add_detail(
                    "  服务规则: " + (str(serving_rule) if serving_rule else "未找到")
                )
                if serving_rule and client_iface and client_mac:
                    chain = bv.verify_dhcp_server_full_chain(
                        name=str(serving_rule["tagname"]),
                        expect_in_conf=True,
                        expect_process_running=True,
                    )
                    for r in chain.results:
                        rec.add_detail(f"  {r.level}: {'[OK]' if r.passed else '[FAIL]'} {r.message}")
                        if not r.passed:
                            flow_failure(f"{r.level}: {r.message}")
                else:
                    flow_failure("无法将测试客户端映射到启用的DHCP服务规则")

            if serving_rule and client_iface and client_mac:
                with rec.step(
                    "L5 DHCP重新获取验证",
                    "重置客户端DHCP→验证精确地址池/网关/DNS/连通性/路由器租约",
                ):
                    new_ip = _release_renew(client_iface)
                    pool = _pool_interval(serving_rule)
                    try:
                        new_ip_value = int(ipaddress.ip_address(new_ip))
                    except ValueError:
                        new_ip_value = -1
                    in_pool = bool(pool and pool[0] <= new_ip_value <= pool[1])
                    rec.add_detail(
                        f"  获取地址={new_ip or '无'}, "
                        f"期望池={serving_rule.get('addr_pool')}, in_pool={in_pool}"
                    )
                    if not in_pool:
                        flow_failure(
                            f"DHCP获取地址不在服务池内: {new_ip or '无'} / "
                            f"{serving_rule.get('addr_pool')}"
                        )

                    gateway = str(serving_rule.get("gateway", ""))
                    route_out = bv._client.exec(
                        f"ip route show default dev {client_iface} 2>/dev/null"
                    )
                    rec.add_detail(f"  DHCP默认路由: {route_out.strip()}")
                    if f"via {gateway}" not in route_out or "proto dhcp" not in route_out:
                        flow_failure(
                            f"客户端接口{client_iface}缺少DHCP默认路由via {gateway}"
                        )

                    expected_dns = [
                        str(serving_rule.get(key, "")).strip()
                        for key in ("dns1", "dns2")
                        if str(serving_rule.get(key, "")).strip()
                    ]
                    dns_out = bv._client.exec(
                        f"resolvectl dns {client_iface} 2>/dev/null"
                    )
                    rec.add_detail(f"  接口DNS: {dns_out.strip()}")
                    missing_dns = [dns for dns in expected_dns if dns not in dns_out]
                    if missing_dns:
                        flow_failure(f"客户端缺少DHCP下发DNS: {missing_dns}")

                    ping_out = bv._client.exec(
                        f"ping -c 3 -W 2 -I {client_iface} {gateway} 2>/dev/null",
                        timeout=12,
                    )
                    rec.add_detail(f"  网关连通: {ping_out.strip()[-300:]}")
                    if "0% packet loss" not in ping_out:
                        flow_failure(f"客户端经{client_iface}无法连通DHCP网关{gateway}")

                    lease = bv.query_lease(mac=client_mac)
                    rec.add_detail(f"  路由器租约: {lease or '无'}")
                    if not lease:
                        flow_failure(f"路由器租约库无客户端MAC {client_mac}")
                    elif str(lease.get("ip_addr", "")) != new_ip:
                        flow_failure(
                            f"路由器租约IP={lease.get('ip_addr')}与客户端IP={new_ip}不一致"
                        )
        finally:
            # 与测试动作使用同一种networkd恢复路径，避免dhclient和networkd抢占接口。
            try:
                if client_iface:
                    _release_renew(client_iface)
            except Exception:
                pass
        print(f"\n[DHCP服务端功能验证] {'通过' if not failures else '失败'+str(len(failures))+'项'}")
        assert not failures, f"DHCP服务端功能验证失败({len(failures)}项): {'; '.join(failures)}"
