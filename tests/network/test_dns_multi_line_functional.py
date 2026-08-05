"""多线路DNS服务独立功能验证。

UI增删改查由综合用例覆盖。本脚本单独验证：
- L2: dns_replace数据库与ik_core的wan/wan_ad运行态映射一致。
- L3: 192.168.148.2经指定WAN发起真实DNS查询时，线路DNS映射实际生效；
  停用、重启用和删除后数据面随状态同步变化。
"""
import ipaddress
import os
import re
import time
from typing import Dict, List, Optional, Set

import pytest

from pages.network.dns_accelerate_page import DnsAcceleratePage
from pages.network.dns_multi_line_page import DnsMultiLinePage
from utils.step_recorder import StepRecorder


CLIENT_SSH_HOST = "10.66.0.18"
CLIENT_IFACE = os.environ.get("DNS_TEST_CLIENT_IFACE", "ens11")
CLIENT_IP = os.environ.get("DNS_TEST_CLIENT_IP", "192.168.148.2")
ROUTER_LAN = os.environ.get("DNS_TEST_ROUTER_DNS", "192.168.148.1")
TEST_LINE = os.environ.get("DNS_MULTI_TEST_LINE", "wan2")
ORIGINAL_DNS = os.environ.get("DNS_MULTI_ORIGINAL_DNS", "114.114.114.114")
LINE_DNS1 = os.environ.get("DNS_MULTI_LINE_DNS1", "223.5.5.5")
LINE_DNS2 = os.environ.get("DNS_MULTI_LINE_DNS2", "223.6.6.6")
RULE_NAME = "mldns_flow"
ROUTE_PROTOCOL = 186
TEST_DOMAINS = (
    "www.baidu.com",
    "www.qq.com",
    "www.taobao.com",
    "www.jd.com",
    "www.163.com",
)


def _ipv4_answers(output: str) -> List[str]:
    """从dig +short输出提取IPv4答案，忽略CNAME和诊断文本。"""
    answers = []
    for line in (output or "").splitlines():
        value = line.strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4:
            answers.append(value)
    return answers


def _dns_query_destinations(capture: str, domain: str) -> Set[str]:
    """提取tcpdump中指定A查询的WAN目标DNS地址。"""
    escaped_domain = re.escape(str(domain or "").rstrip("."))
    if not escaped_domain:
        return set()
    query_pattern = re.compile(rf"\bA\?\s+{escaped_domain}\.\s", re.IGNORECASE)
    destination_pattern = re.compile(
        r">\s+((?:\d{1,3}\.){3}\d{1,3})\.53:"
    )
    destinations = set()
    for line in (capture or "").splitlines():
        if not query_pattern.search(line):
            continue
        match = destination_pattern.search(line)
        if match:
            destinations.add(match.group(1))
    return destinations


def _remote_interfaces(conntrack: str) -> Set[str]:
    return set(re.findall(r"\bremote_if=(\S+)", conntrack or ""))


@pytest.mark.dns_multi_line
@pytest.mark.network
class TestDnsMultiLineFunctional:
    """多线路DNS L2运行态与L3数据面验证。"""

    def test_dns_multi_line_flow(
        self,
        dns_multi_line_page_logged_in: DnsMultiLinePage,
        dns_accelerate_page_logged_in: DnsAcceleratePage,
        step_recorder: StepRecorder,
        request,
    ):
        ml_page = dns_multi_line_page_logged_in
        accel_page = dns_accelerate_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue("backend_verifier")
        except Exception:
            bv = None
        if bv is None:
            pytest.skip("无SSH验证器，跳过多线路DNS功能验证")

        failures: List[str] = []
        capture_prefixes: List[str] = []
        original_accel_enabled: Optional[bool] = None
        client_routes = ""
        router_routes = ""
        test_gateway = ""
        suffix = int(time.time())

        def check(label: str, condition: bool, detail: str = "") -> bool:
            status = "[OK]" if condition else "[FAIL]"
            message = f"{label}: {status}{' ' + detail if detail else ''}"
            print(f"  {message}")
            rec.add_detail(f"  {message}")
            if not condition:
                failures.append(f"{label}: {detail or '不符合预期'}")
            return condition

        def client_exec(command: str, timeout: int = 15) -> str:
            bv.connect_client()
            return bv._client.exec(command, timeout=timeout) or ""

        def router_exec(command: str, timeout: int = 15) -> str:
            bv.connect_router()
            return bv._router.exec(command, timeout=timeout) or ""

        def record_result(label: str, result) -> bool:
            return check(label, bool(result.passed), result.message)

        def clear_dns_flows() -> None:
            router_exec(
                f"conntrack -D -s {CLIENT_IP} -p udp 2>/dev/null; "
                f"conntrack -D -d {CLIENT_IP} -p udp 2>/dev/null; true"
            )

        def start_capture(label: str) -> str:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", TEST_LINE):
                return ""
            prefix = f"/tmp/dns-multi-functional-{suffix}-{label}"
            bpf = (
                f"udp dst port 53 and (dst host {ORIGINAL_DNS} or "
                f"dst host {LINE_DNS1} or dst host {LINE_DNS2})"
            )
            pid = router_exec(
                f"rm -f {prefix}.log {prefix}.pid; "
                f"tcpdump -lni {TEST_LINE} -s 0 -vv '{bpf}' "
                f">{prefix}.log 2>&1 & echo $! >{prefix}.pid; "
                f"cat {prefix}.pid"
            ).strip()
            if pid.isdigit():
                capture_prefixes.append(prefix)
                return prefix
            return ""

        def stop_capture(prefix: str) -> str:
            if not prefix:
                return ""
            output = router_exec(
                f"test -f {prefix}.pid && kill $(cat {prefix}.pid) 2>/dev/null; "
                f"sleep 1; cat {prefix}.log 2>/dev/null; "
                f"rm -f {prefix}.log {prefix}.pid; true",
                timeout=12,
            )
            if prefix in capture_prefixes:
                capture_prefixes.remove(prefix)
            return output

        def probe(label: str, domain: str) -> Dict:
            clear_dns_flows()
            prefix = start_capture(label)
            ml_page.page.wait_for_timeout(700)
            command = (
                f"dig @{ORIGINAL_DNS} {domain} A +short +time=4 +tries=1 "
                f"-b {CLIENT_IP} 2>&1"
            )
            try:
                output = client_exec(command, timeout=15)
            finally:
                ml_page.page.wait_for_timeout(700)
                capture = stop_capture(prefix)
            conntrack_command = (
                "conntrack -L -p udp -o extended 2>/dev/null | "
                f"grep 'src={CLIENT_IP} ' | grep 'dport=53 ' | tail -10"
            )
            conntrack = router_exec(conntrack_command)
            answers = _ipv4_answers(output)
            destinations = _dns_query_destinations(capture, domain)
            interfaces = _remote_interfaces(conntrack)
            rec.add_detail(
                f"  {label}: answers={answers}, WAN目标={sorted(destinations)}, "
                f"remote_if={sorted(interfaces)}"
            )
            rec.add_verification_command(
                command,
                target_label="打流客户端",
                target="client",
                host=bv._ssh_config.client.host,
                shell="bash",
                purpose=f"从{CLIENT_IP}/{CLIENT_IFACE}发起DNS探针",
                expected="返回至少一个IPv4答案",
                actual=output[:1000],
            )
            rec.add_verification_command(
                f"tcpdump -ni {TEST_LINE} -vv '{'udp dst port 53'}'",
                target_label="被测路由器",
                target="router",
                host=bv._ssh_config.router.host,
                shell="bash",
                purpose=f"观察{domain}在{TEST_LINE}的真实DNS目标",
                expected=f"启用态目标属于{LINE_DNS1}/{LINE_DNS2}",
                actual=capture[:4000],
            )
            return {
                "answers": answers,
                "destinations": destinations,
                "interfaces": interfaces,
                "output": output,
                "capture": capture,
                "conntrack": conntrack,
            }

        def assert_passthrough(label: str, result: Dict) -> None:
            check(f"{label}-解析", bool(result["answers"]), result["output"][:500])
            check(
                f"{label}-原DNS透传",
                ORIGINAL_DNS in result["destinations"]
                and LINE_DNS1 not in result["destinations"]
                and LINE_DNS2 not in result["destinations"],
                f"WAN目标={sorted(result['destinations'])}",
            )
            check(
                f"{label}-出口",
                TEST_LINE in result["interfaces"],
                f"remote_if={sorted(result['interfaces'])}",
            )

        def assert_mapped(label: str, result: Dict) -> None:
            mapped = {LINE_DNS1, LINE_DNS2}
            check(f"{label}-解析", bool(result["answers"]), result["output"][:500])
            check(
                f"{label}-线路DNS改写",
                bool(mapped.intersection(result["destinations"]))
                and ORIGINAL_DNS not in result["destinations"],
                f"WAN目标={sorted(result['destinations'])}, 期望={sorted(mapped)}",
            )
            check(
                f"{label}-出口",
                TEST_LINE in result["interfaces"],
                f"remote_if={sorted(result['interfaces'])}",
            )

        def flush_route(host: str, sudo: bool = False) -> None:
            prefix = "sudo -n " if sudo else ""
            command = f"{prefix}ip route flush {host}/32 2>/dev/null; true"
            client_exec(command) if sudo else router_exec(command)

        def restore_routes(snapshot: str, client: bool) -> None:
            for line in (snapshot or "").splitlines():
                route = line.strip()
                if not route or not re.fullmatch(r"[A-Za-z0-9_.:/ -]+", route):
                    continue
                command = (
                    f"sudo -n ip route add {route} 2>/dev/null || true"
                    if client else f"ip route add {route} 2>/dev/null || true"
                )
                client_exec(command) if client else router_exec(command)

        def without_owned_routes(snapshot: str) -> str:
            """过滤上次异常中断遗留的本测试专用路由。"""
            marker = f"proto {ROUTE_PROTOCOL}"
            return "\n".join(
                line for line in (snapshot or "").splitlines()
                if marker not in line
            )

        def cleanup_stale_captures() -> None:
            router_exec(
                "for f in /tmp/dns-multi-functional-*.pid; do "
                "[ -f \"$f\" ] || continue; "
                "p=$(cat \"$f\" 2>/dev/null); "
                "case \"$p\" in (*[!0-9]*|'') ;; (*) kill \"$p\" 2>/dev/null ;; esac; "
                "done; rm -f /tmp/dns-multi-functional-*.pid "
                "/tmp/dns-multi-functional-*.log; true"
            )

        print("\n" + "=" * 60)
        print("多线路DNS服务独立功能验证(L2运行态 + L3真实流量)")
        print("=" * 60)

        try:
            with rec.step(
                "环境前置",
                f"router=10.66.0.45; client={CLIENT_SSH_HOST}/{CLIENT_IP}; line={TEST_LINE}",
            ):
                bv.connect_router()
                bv.connect_client()
                cleanup_stale_captures()
                foreign_rules = [
                    rule for rule in bv.query_all_dns_replace()
                    if rule.get("tagname") != RULE_NAME
                ]
                if foreign_rules:
                    pytest.skip(
                        "设备存在非本测试多线路DNS规则，无法建立隔离基线: "
                        f"{[rule.get('tagname') for rule in foreign_rules]}"
                    )
                residue = bv.query_dns_replace_rule(RULE_NAME)
                if residue:
                    router_exec(
                        f"/usr/ikuai/function/dns_replace del id={int(residue['id'])}"
                    )

                iface_state = client_exec(
                    f"ip -br -4 addr show dev {CLIENT_IFACE}; "
                    "sudo -n true >/dev/null 2>&1; echo SUDO=$?; "
                    "command -v dig; command -v tcpdump"
                )
                if CLIENT_IP not in iface_state or "SUDO=0" not in iface_state:
                    pytest.skip(f"客户端数据面环境不满足: {iface_state}")

                wan_state = router_exec(
                    f"ip -o -4 addr show dev {TEST_LINE}; "
                    f"ip route show default dev {TEST_LINE}"
                )
                gateway_match = re.search(r"\bdefault\s+via\s+([0-9.]+)", wan_state)
                test_gateway = gateway_match.group(1) if gateway_match else ""
                if not test_gateway:
                    pytest.skip(f"{TEST_LINE}无IPv4默认网关: {wan_state}")
                ipaddress.ip_address(test_gateway)

                accel_page.navigate_to_dns_accelerate()
                original_accel_enabled = bool(
                    accel_page.get_basic_config().get("enabled", False)
                )
                if original_accel_enabled:
                    disabled = accel_page.save_basic_config(enable=False)
                    if not disabled:
                        pytest.skip("无法临时关闭DNS加速，不能隔离多线路DNS数据面")

                client_routes = without_owned_routes(client_exec(
                    f"ip -4 route show {ORIGINAL_DNS}/32"
                ))
                router_routes = without_owned_routes(router_exec(
                    f"ip -4 route show {ORIGINAL_DNS}/32"
                ))
                flush_route(ORIGINAL_DNS, sudo=True)
                flush_route(ORIGINAL_DNS)
                client_exec(
                    f"sudo -n ip route add {ORIGINAL_DNS}/32 via {ROUTER_LAN} "
                    f"dev {CLIENT_IFACE} src {CLIENT_IP} metric 5 "
                    f"proto {ROUTE_PROTOCOL}"
                )
                router_exec(
                    f"ip route add {ORIGINAL_DNS}/32 via {test_gateway} "
                    f"dev {TEST_LINE} proto {ROUTE_PROTOCOL}"
                )
                route_state = client_exec(
                    f"ip route get {ORIGINAL_DNS} from {CLIENT_IP}"
                ) + router_exec(f"ip route get {ORIGINAL_DNS}")
                check(
                    "固定L3探针路径",
                    f"dev {CLIENT_IFACE}" in route_state
                    and f"dev {TEST_LINE}" in route_state,
                    route_state.strip(),
                )

            with rec.step(
                "L3基线",
                f"无多线规则时{ORIGINAL_DNS}应原样经{TEST_LINE}转发",
            ):
                assert_passthrough("基线", probe("baseline", TEST_DOMAINS[0]))

            with rec.step(
                "L2规则加载",
                f"UI创建{TEST_LINE}->{LINE_DNS1}/{LINE_DNS2}并验证DB+ik_core",
            ):
                ml_page.navigate_to_dns_multi_line()
                created = ml_page.add_rule(
                    RULE_NAME,
                    interface=TEST_LINE,
                    dns1=LINE_DNS1,
                    dns2=LINE_DNS2,
                    remark="多线DNS功能验证",
                )
                check("UI创建测试规则", bool(created))
                ml_page.page.wait_for_timeout(1500)
                record_result(
                    "L2-数据库",
                    bv.verify_dns_replace_database(
                        RULE_NAME,
                        expected_fields={
                            "interface": TEST_LINE,
                            "dns1": LINE_DNS1,
                            "dns2": LINE_DNS2,
                            "enabled": "yes",
                        },
                    ),
                )
                record_result(
                    "L2-ik_core映射",
                    bv.verify_dns_multi_line_runtime(
                        TEST_LINE,
                        LINE_DNS1,
                        LINE_DNS2,
                        should_exist=True,
                        expect_enabled=True,
                    ),
                )

            with rec.step(
                "L3启用态",
                f"WAN抓包目标必须由{ORIGINAL_DNS}改为线路DNS",
            ):
                assert_mapped("启用态", probe("enabled", TEST_DOMAINS[1]))

            with rec.step(
                "L2/L3停用态",
                "停用后DB=no、运行态映射撤销、数据面恢复原DNS",
            ):
                ml_page.navigate_to_dns_multi_line()
                check("UI停用测试规则", bool(ml_page.disable_rule(RULE_NAME)))
                ml_page.page.wait_for_timeout(1200)
                record_result(
                    "L2-停用数据库",
                    bv.verify_dns_replace_database(
                        RULE_NAME, expected_fields={"enabled": "no"}
                    ),
                )
                record_result(
                    "L2-停用运行态",
                    bv.verify_dns_multi_line_runtime(
                        TEST_LINE,
                        LINE_DNS1,
                        LINE_DNS2,
                        should_exist=False,
                        expect_enabled=False,
                    ),
                )
                assert_passthrough("停用态", probe("disabled", TEST_DOMAINS[2]))

            with rec.step(
                "L2/L3重启用",
                "重新启用后运行态映射和线路DNS改写必须恢复",
            ):
                ml_page.navigate_to_dns_multi_line()
                check("UI重启用测试规则", bool(ml_page.enable_rule(RULE_NAME)))
                ml_page.page.wait_for_timeout(1200)
                record_result(
                    "L2-重启用运行态",
                    bv.verify_dns_multi_line_runtime(
                        TEST_LINE,
                        LINE_DNS1,
                        LINE_DNS2,
                        should_exist=True,
                        expect_enabled=True,
                    ),
                )
                assert_mapped("重启用", probe("reenabled", TEST_DOMAINS[3]))

            with rec.step(
                "L2/L3删除态",
                "删除后数据库和运行态无残留，数据面恢复原DNS",
            ):
                ml_page.navigate_to_dns_multi_line()
                check("UI删除测试规则", bool(ml_page.delete_rule(RULE_NAME)))
                ml_page.page.wait_for_timeout(1200)
                record_result(
                    "L2-删除数据库",
                    bv.verify_dns_replace_database(RULE_NAME, must_exist=False),
                )
                record_result(
                    "L2-删除运行态",
                    bv.verify_dns_multi_line_runtime(
                        TEST_LINE,
                        LINE_DNS1,
                        LINE_DNS2,
                        should_exist=False,
                        expect_enabled=False,
                    ),
                )
                assert_passthrough("删除态", probe("deleted", TEST_DOMAINS[4]))
        finally:
            for prefix in list(capture_prefixes):
                try:
                    stop_capture(prefix)
                except Exception as exc:
                    failures.append(f"清理抓包进程失败: {exc}")
            try:
                residue = bv.query_dns_replace_rule(RULE_NAME)
                if residue:
                    router_exec(
                        f"/usr/ikuai/function/dns_replace del id={int(residue['id'])}"
                    )
            except Exception as exc:
                failures.append(f"清理多线路DNS测试规则失败: {exc}")
            try:
                flush_route(ORIGINAL_DNS, sudo=True)
                restore_routes(client_routes, client=True)
            except Exception as exc:
                failures.append(f"恢复客户端路由失败: {exc}")
            try:
                flush_route(ORIGINAL_DNS)
                restore_routes(router_routes, client=False)
            except Exception as exc:
                failures.append(f"恢复路由器路由失败: {exc}")
            if original_accel_enabled is not None:
                try:
                    accel_page.navigate_to_dns_accelerate()
                    current_enabled = bool(
                        accel_page.get_basic_config().get("enabled", False)
                    )
                    if current_enabled != original_accel_enabled:
                        restored = accel_page.save_basic_config(
                            enable=original_accel_enabled
                        )
                        if not restored:
                            failures.append("恢复原始DNS加速开关失败")
                except Exception as exc:
                    failures.append(f"恢复原始DNS加速状态异常: {exc}")

        print(
            f"\n[多线路DNS独立功能验证] "
            f"{'通过' if not failures else '失败' + str(len(failures)) + '项'}"
        )
        assert not failures, (
            f"多线路DNS功能验证失败({len(failures)}项): {'; '.join(failures)}"
        )
