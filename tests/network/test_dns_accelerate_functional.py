"""DNS加速服务全模式独立功能验证。

覆盖 UDP、DoH、多线分路、第三方代理，以及 IPv4/IPv6/代理三类反向
代理记录。控制面由页面对象配置，L2/L3由路由器SSH验证，数据面固定使用
10.66.0.18上的ens11/192.168.148.2。
"""
import ipaddress
import os
import re
import time
from typing import Dict, List, Optional, Tuple

import pytest

from config.config import Config
from pages.network.dns_accelerate_page import DnsAcceleratePage
from utils.step_recorder import StepRecorder


CLIENT_SSH_HOST = "10.66.0.18"
CLIENT_IFACE = os.environ.get("DNS_TEST_CLIENT_IFACE", "ens11")
CLIENT_IP = os.environ.get("DNS_TEST_CLIENT_IP", "192.168.148.2")
ROUTER_DNS = os.environ.get("DNS_TEST_ROUTER_DNS", "192.168.148.1")
BOGUS_DNS = os.environ.get("DNS_TEST_BOGUS_SERVER", "192.0.2.53")
MULTI_PROBE_DNS = os.environ.get("DNS_TEST_MULTI_SERVER", "180.76.76.76")
THIRD_PARTY_PROBE_DNS = os.environ.get(
    "DNS_TEST_THIRD_PARTY_SERVER", "8.8.8.8"
)
UPSTREAM_DNS1 = os.environ.get("DNS_TEST_UPSTREAM_DNS1", "114.114.114.114")
UPSTREAM_DNS2 = os.environ.get("DNS_TEST_UPSTREAM_DNS2", "223.5.5.5")
DOH_QUERY = os.environ.get("DNS_TEST_DOH_QUERY", "https://doh.pub/dns-query")
PUBLIC_DOMAIN = os.environ.get("DNS_TEST_PUBLIC_DOMAIN", "www.baidu.com")
PROXY_DNS_SERVERS = [
    MULTI_PROBE_DNS,
    UPSTREAM_DNS1,
    UPSTREAM_DNS2,
    "119.29.29.29",
]
STATIC_IPV4 = "198.51.100.123"
STATIC_IPV6 = "2001:db8::123"


def _ip_answers(output: str, version: int) -> List[str]:
    """从dig +short输出中提取指定版本的合法IP记录。"""
    answers = []
    for line in (output or "").splitlines():
        value = line.strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == version:
            answers.append(value)
    return answers


def _ipv4_answers(output: str) -> List[str]:
    return _ip_answers(output, 4)


def _ipv6_answers(output: str) -> List[str]:
    return _ip_answers(output, 6)


def _nat_packet_count(output: str, target: str) -> Optional[int]:
    """汇总DNSPROXY链指定target的UDP/53规则包计数。"""
    counters = []
    for line in (output or "").splitlines():
        if target not in line or "udp" not in line or "dpt:53" not in line:
            continue
        fields = line.split()
        if fields and fields[0].isdigit():
            counters.append(int(fields[0]))
    return sum(counters) if counters else None


def _redirect_packet_count(output: str) -> Optional[int]:
    return _nat_packet_count(output, "REDIRECT")


def _dnsproxy_jump_packet_count(output: str) -> Optional[int]:
    """读取PREROUTING跳转到DNSPROXY的UDP/53包计数。"""
    counters = []
    for line in (output or "").splitlines():
        if "DNSPROXY" not in line or "udp" not in line or "dpt:53" not in line:
            continue
        fields = line.split()
        if fields and fields[0].isdigit():
            counters.append(int(fields[0]))
    return sum(counters) if counters else None


def _dns_query_ids(output: str, domain: str) -> set:
    """提取tcpdump中指定A查询的DNS事务ID，用于关联LAN与WAN同一请求。"""
    escaped_domain = re.escape(str(domain or "").rstrip("."))
    if not escaped_domain:
        return set()
    pattern = re.compile(
        rf"\b(\d+)\+\s+(?:\[\d+au\]\s+)?A\?\s+{escaped_domain}\."
    )
    return {int(value) for value in pattern.findall(output or "")}


@pytest.mark.dns_accelerate
@pytest.mark.network
class TestDnsAccelerateFunctional:
    """DNS加速全模式L2/L3与客户端实流验证。"""

    def test_dns_accelerate_flow(
        self,
        dns_accelerate_page_logged_in: DnsAcceleratePage,
        step_recorder: StepRecorder,
        config: Config,
        request,
    ):
        page = dns_accelerate_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue("backend_verifier")
        except Exception:
            bv = None
        if bv is None:
            pytest.skip("无SSH验证器，跳过DNS加速功能验证")

        failures: List[str] = []
        original: Optional[Dict] = None
        original_db: Optional[Dict] = None
        suffix = int(time.time())
        ipv4_domain = f"dns-v4-{suffix}.invalid"
        ipv6_domain = f"dns-v6-{suffix}.invalid"
        proxy_domain = next(
            (
                domain for domain in (PUBLIC_DOMAIN, "www.qq.com", "www.taobao.com")
                if bv.query_dns_reverse_proxy(domain) is None
            ),
            None,
        )
        if proxy_domain is None:
            pytest.skip("候选公网域名均已有反向代理规则，无法安全验证代理类型")
        test_domains = [ipv4_domain, ipv6_domain, proxy_domain]
        created_domains: List[str] = []
        added_routes: List[str] = []
        capture_prefixes: List[str] = []

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

        def dig(server: str, domain: str, record_type: str = "A") -> Tuple[List[str], str]:
            output = client_exec(
                f"dig @{server} {domain} {record_type} +short +time=4 +tries=1 "
                f"-b {CLIENT_IP} 2>&1",
                timeout=18,
            )
            version = 6 if record_type.upper() == "AAAA" else 4
            return _ip_answers(output, version), output.strip()[:500]

        def chain_state(target: str) -> Tuple[Optional[int], str]:
            output = router_exec(
                "iptables -t nat -L DNSPROXY -n -v -x 2>/dev/null"
            )
            return _nat_packet_count(output, target), output.strip()[:1500]

        def prerouting_state() -> Tuple[Optional[int], str]:
            output = router_exec(
                "iptables -t nat -L PREROUTING -n -v -x 2>/dev/null"
            )
            return _dnsproxy_jump_packet_count(output), output.strip()[:1500]

        def route_iface(target: str) -> Tuple[str, str]:
            output = router_exec(f"ip route get {target} 2>/dev/null").strip()
            match = re.search(r"\bdev\s+([A-Za-z0-9_.:-]+)", output)
            return (match.group(1) if match else ""), output

        def start_capture(iface: str, bpf: str) -> str:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface or ""):
                return ""
            prefix = f"/tmp/dns-functional-{suffix}-{iface}"
            command = (
                f"rm -f {prefix}.log {prefix}.pid; "
                f"tcpdump -lni {iface} -s 0 -vv '{bpf}' "
                f"> {prefix}.log 2>&1 & echo $! > {prefix}.pid; "
                f"cat {prefix}.pid"
            )
            pid = router_exec(command, timeout=10).strip()
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
            return (output or "").strip()[:5000]

        def record_backend_result(label: str, result) -> bool:
            return check(label, bool(result.passed), result.message)

        def ensure_probe_route(target: str) -> bool:
            existing = client_exec(
                f"ip -4 route show {target}/32 2>/dev/null", timeout=10
            ).strip()
            if existing:
                return check(
                    f"已有路由-{target}",
                    f"via {ROUTER_DNS}" in existing and f"dev {CLIENT_IFACE}" in existing,
                    existing,
                )
            result = client_exec(
                f"sudo -n ip route replace {target}/32 via {ROUTER_DNS} "
                f"dev {CLIENT_IFACE} src {CLIENT_IP} metric 5 "
                "&& echo __ROUTE_OK__",
                timeout=10,
            )
            route = client_exec(
                f"ip route get {target} from {CLIENT_IP} 2>/dev/null", timeout=10
            )
            routed = (
                f"via {ROUTER_DNS}" in route and f"dev {CLIENT_IFACE}" in route
            )
            if routed:
                added_routes.append(target)
            return check(
                f"固定探针路由-{target}",
                "__ROUTE_OK__" in result and routed,
                route.strip() or result.strip() or "无路由",
            )

        def restore_original() -> bool:
            if not original or not original_db:
                return False
            mode = original.get("cachemode")
            if mode not in page.CACHEMODE_MAP:
                return False
            original_query = str(original_db.get("query") or "").strip()
            original_proxy_servers = [
                value.strip()
                for value in str(
                    original_db.get("proxy_force_dns") or ""
                ).split(",")
                if value.strip()
            ][:4]
            restored_parts = []

            # 页面只渲染当前模式字段，先在关闭态逐一恢复隐藏字段，再回到原模式。
            if mode != "DoH" and original_query:
                page.navigate_to_dns_accelerate()
                restored_parts.append(page.save_basic_config(
                    enable=False,
                    cachemode="DoH",
                    query=original_query,
                ))
            if mode != "第三方代理" and original_proxy_servers:
                page.navigate_to_dns_accelerate()
                restored_parts.append(page.save_basic_config(
                    enable=False,
                    cachemode="第三方代理",
                    proxy_dns_servers=original_proxy_servers,
                ))

            kwargs = {
                "enable": original.get("enabled"),
                "dns1": original.get("dns1"),
                "dns2": original.get("dns2"),
                "forbid_aaaa": original.get("forbid_dns_4a"),
                "cachemode": mode,
                "cache_ttl": original.get("cache_ttl"),
            }
            if mode in ("UDP", "DoH"):
                kwargs["proxy_force"] = original.get("proxy_force")
            if mode == "DoH":
                kwargs["query"] = original_query
            if mode == "第三方代理":
                kwargs["proxy_dns_servers"] = original_proxy_servers
            page.navigate_to_dns_accelerate()
            restored = page.save_basic_config(**kwargs)
            page.page.wait_for_timeout(1500)
            return bool(restored) and all(restored_parts)

        print("\n" + "=" * 64)
        print("DNS加速服务全模式功能验证（UDP/DoH/多线分路/第三方代理）")
        print("=" * 64)

        try:
            with rec.step("测试环境校验", "UI/SSH同设备，客户端固定使用ens11/192.168.148.2"):
                check(
                    "路由器目标一致",
                    config.device.ip == config.ssh.router.host,
                    f"UI={config.device.ip}, SSH={config.ssh.router.host}",
                )
                check(
                    "客户端SSH目标",
                    config.ssh.client.host == CLIENT_SSH_HOST,
                    f"实际={config.ssh.client.host}, 期望={CLIENT_SSH_HOST}",
                )
                addr_out = client_exec(
                    f"ip -4 -o addr show dev {CLIENT_IFACE} 2>/dev/null", timeout=10
                )
                check(
                    "客户端数据面地址",
                    bool(re.search(rf"\binet\s+{re.escape(CLIENT_IP)}/\d+\b", addr_out)),
                    addr_out.strip() or "无",
                )
                check(
                    "客户端dig工具",
                    bool(client_exec("command -v dig 2>/dev/null", timeout=10).strip()),
                )
                sudo_ok = "__SUDO_OK__" in client_exec(
                    "sudo -n true && echo __SUDO_OK__", timeout=10
                )
                check("客户端免密sudo", sudo_ok)

            page.navigate_to_dns_accelerate()
            page.page.wait_for_timeout(800)
            original = page.get_basic_config()
            original_db = bv.query_dns_config()
            rec.add_detail(
                "  已保存原配置："
                f"enabled={original.get('enabled')}, cachemode={original.get('cachemode')}, "
                f"proxy_force={original.get('proxy_force')}, "
                f"query={original_db.get('query')}, "
                f"proxy_force_dns={original_db.get('proxy_force_dns')}"
            )

            with rec.step("固定测试数据面", "各模式探针均经ens11进入被测路由器"):
                ensure_probe_route(BOGUS_DNS)
                ensure_probe_route(MULTI_PROBE_DNS)
                ensure_probe_route(THIRD_PARTY_PROBE_DNS)

            with rec.step("关闭态基线", "运行文件清理、DNSPROXY无改写、本地53无测试解析"):
                check("关闭DNS加速", page.save_basic_config(enable=False))
                page.page.wait_for_timeout(1500)
                record_backend_result(
                    "关闭态L2", bv.verify_dns_runtime_config(expect_enabled=False)
                )
                record_backend_result(
                    "关闭态L3", bv.verify_dns_iptables(expect_redirect=False)
                )
                answers, raw = dig(ROUTER_DNS, ipv4_domain)
                check("关闭态无测试解析", STATIC_IPV4 not in answers, raw or "无输出")

            with rec.step("创建三类反向代理记录", "IPv4、IPv6、代理均写入并启用"):
                rule_specs = [
                    (ipv4_domain, "IPv4", STATIC_IPV4),
                    (ipv6_domain, "IPv6", STATIC_IPV6),
                    (proxy_domain, "代理", MULTI_PROBE_DNS),
                ]
                for domain, parse_type, address in rule_specs:
                    page.navigate_to_dns_accelerate()
                    added = page.add_reverse_proxy(
                        domain=domain,
                        parse_type=parse_type,
                        dns_addr=address,
                        src_addr=CLIENT_IP,
                        comment=f"dns-functional-{parse_type}",
                    )
                    if added:
                        created_domains.append(domain)
                    check(f"添加{parse_type}记录", bool(added), f"{domain}->{address}")
                    record_backend_result(
                        f"{parse_type}记录L1",
                        bv.verify_dns_reverse_proxy_database(
                            domain,
                            expected_fields={
                                "dns_addr": address,
                                "parse_type": {
                                    "IPv4": "ipv4",
                                    "IPv6": "ipv6",
                                    "代理": "proxy",
                                }[parse_type],
                                "enabled": "yes",
                            },
                        ),
                    )

            with rec.step("UDP模式", "port53+REDIRECT+TTL+三类反向代理真实解析"):
                page.navigate_to_dns_accelerate()
                configured = page.save_basic_config(
                    enable=True,
                    dns1=UPSTREAM_DNS1,
                    dns2=UPSTREAM_DNS2,
                    forbid_aaaa=False,
                    cachemode="UDP",
                    proxy_force=True,
                    cache_ttl="120",
                )
                check("UDP配置保存", configured)
                record_backend_result(
                    "UDP-L1",
                    bv.verify_dns_config_database(expected_fields={
                        "enabled": "yes",
                        "cachemode": "0",
                        "proxy_force": "1",
                        "forbid_dns_4a": "0",
                        "cache_ttl": "120",
                    }),
                )
                record_backend_result(
                    "UDP-L2/L3",
                    bv.verify_dns_mode_runtime("UDP", proxy_force=True),
                )
                static_conf = router_exec(
                    "cat /tmp/iktmp/ikdnsd.static.conf 2>/dev/null"
                )
                for parse_type, domain, address in (
                    ("ipv4", ipv4_domain, STATIC_IPV4),
                    ("ipv6", ipv6_domain, STATIC_IPV6),
                    ("proxy", proxy_domain, MULTI_PROBE_DNS),
                ):
                    check(
                        f"UDP运行文件-{parse_type}",
                        all(v in static_conf for v in (parse_type, domain, address)),
                        static_conf[:800],
                    )
                check(
                    "UDP运行文件-TTL",
                    "cache_ttl = 120" in router_exec(
                        "cat /tmp/iktmp/ikdnsd.conf 2>/dev/null"
                    ),
                )

                a4, raw4 = dig(ROUTER_DNS, ipv4_domain)
                check("UDP-IPv4反向代理", STATIC_IPV4 in a4, raw4 or "无输出")
                a6, raw6 = dig(ROUTER_DNS, ipv6_domain, "AAAA")
                check("UDP-IPv6反向代理", STATIC_IPV6 in a6, raw6 or "无输出")
                ap, rawp = dig(ROUTER_DNS, proxy_domain)
                check("UDP-代理型反向代理", bool(ap), rawp or "无输出")

                before, _ = chain_state("REDIRECT")
                forced, forced_raw = dig(BOGUS_DNS, ipv4_domain)
                after, chain_raw = chain_state("REDIRECT")
                check("UDP-强制代理解析", STATIC_IPV4 in forced, forced_raw or "无输出")
                check(
                    "UDP-REDIRECT计数增长",
                    before is not None and after is not None and after > before,
                    f"before={before}, after={after}; {chain_raw}",
                )

            with rec.step("反向代理生命周期", "停用不生效，重新启用后恢复解析"):
                check("停用IPv4记录", page.disable_reverse_proxy(ipv4_domain))
                disabled_answers, disabled_raw = dig(ROUTER_DNS, ipv4_domain)
                check(
                    "停用后解析失效",
                    STATIC_IPV4 not in disabled_answers,
                    disabled_raw or "无输出",
                )
                check("启用IPv4记录", page.enable_reverse_proxy(ipv4_domain))
                enabled_answers, enabled_raw = dig(ROUTER_DNS, ipv4_domain)
                check(
                    "启用后解析恢复",
                    STATIC_IPV4 in enabled_answers,
                    enabled_raw or "无输出",
                )

            with rec.step("禁止AAAA功能", "开启时IPv6静态AAAA应被抑制，关闭后恢复"):
                page.navigate_to_dns_accelerate()
                check("开启禁止AAAA", page.save_basic_config(forbid_aaaa=True))
                blocked6, blocked_raw = dig(ROUTER_DNS, ipv6_domain, "AAAA")
                check("AAAA被禁止", STATIC_IPV6 not in blocked6, blocked_raw or "无输出")
                page.navigate_to_dns_accelerate()
                check("关闭禁止AAAA", page.save_basic_config(forbid_aaaa=False))
                restored6, restored_raw = dig(ROUTER_DNS, ipv6_domain, "AAAA")
                check("AAAA恢复", STATIC_IPV6 in restored6, restored_raw or "无输出")

            with rec.step("DoH模式", "query入库+doh_url运行态+客户端真实解析"):
                page.navigate_to_dns_accelerate()
                check(
                    "DoH配置保存",
                    page.save_basic_config(
                        enable=True,
                        cachemode="DoH",
                        query=DOH_QUERY,
                        proxy_force=True,
                        forbid_aaaa=False,
                    ),
                )
                record_backend_result(
                    "DoH-L1",
                    bv.verify_dns_config_database(expected_fields={
                        "enabled": "yes", "cachemode": "3", "query": DOH_QUERY,
                    }),
                )
                record_backend_result(
                    "DoH-L2/L3",
                    bv.verify_dns_mode_runtime(
                        "DoH", query=DOH_QUERY, proxy_force=True
                    ),
                )
                doh_answers, doh_raw = dig(ROUTER_DNS, PUBLIC_DOMAIN)
                check("DoH-路由器解析", bool(doh_answers), doh_raw or "无输出")
                before, _ = chain_state("REDIRECT")
                doh_forced, doh_forced_raw = dig(BOGUS_DNS, PUBLIC_DOMAIN)
                after, chain_raw = chain_state("REDIRECT")
                check("DoH-强制代理解析", bool(doh_forced), doh_forced_raw or "无输出")
                check(
                    "DoH-REDIRECT计数增长",
                    before is not None and after is not None and after > before,
                    f"before={before}, after={after}; {chain_raw}",
                )

            with rec.step("多线分路模式", "port0无改写，客户端上游DNS实流经过DNSPROXY入口"):
                page.navigate_to_dns_accelerate()
                check(
                    "多线分路配置保存",
                    page.save_basic_config(enable=True, cachemode="多线分路"),
                )
                record_backend_result(
                    "多线分路-L1",
                    bv.verify_dns_config_database(expected_fields={
                        "enabled": "yes", "cachemode": "1",
                    }),
                )
                record_backend_result(
                    "多线分路-L2/L3",
                    bv.verify_dns_mode_runtime("多线分路"),
                )
                local_answers, local_raw = dig(ROUTER_DNS, PUBLIC_DOMAIN)
                check(
                    "多线分路不监听本地53",
                    not local_answers,
                    local_raw or "无输出",
                )
                before, _ = prerouting_state()
                multi_answers, multi_raw = dig(MULTI_PROBE_DNS, PUBLIC_DOMAIN)
                after, pre_raw = prerouting_state()
                check("多线分路-上游DNS解析", bool(multi_answers), multi_raw or "无输出")
                check(
                    "多线分路-DNSPROXY入口计数增长",
                    before is not None and after is not None and after > before,
                    f"before={before}, after={after}; {pre_raw}",
                )

            with rec.step("第三方代理模式", "首选+3备选入库，DNAT非活动DNS并验证真实响应"):
                page.navigate_to_dns_accelerate()
                check(
                    "第三方代理配置保存",
                    page.save_basic_config(
                        enable=True,
                        cachemode="第三方代理",
                        proxy_dns_servers=PROXY_DNS_SERVERS,
                    ),
                )
                joined = ",".join(PROXY_DNS_SERVERS)
                record_backend_result(
                    "第三方代理-L1",
                    bv.verify_dns_config_database(expected_fields={
                        "enabled": "yes",
                        "cachemode": "2",
                        "proxy_force_dns": joined,
                    }),
                )
                record_backend_result(
                    "第三方代理-L2/L3",
                    bv.verify_dns_mode_runtime(
                        "第三方代理", proxy_dns_servers=PROXY_DNS_SERVERS
                    ),
                )
                dnslink = router_exec(
                    "cat /tmp/iktmp/dnslink.status 2>/dev/null"
                ).strip()
                active_match = re.search(r"\bproxy_ip=([^\s]+)", dnslink)
                active_dns = active_match.group(1) if active_match else ""
                check(
                    "第三方代理-首选DNS活动",
                    active_dns == PROXY_DNS_SERVERS[0],
                    dnslink or "dnslink.status无输出",
                )

                lan_iface, lan_route = route_iface(CLIENT_IP)
                wan_iface, wan_route = route_iface(active_dns)
                lan_capture = start_capture(
                    lan_iface, f"udp port 53 and host {CLIENT_IP}"
                )
                health_bpf = "udp port 53 and (" + " or ".join(
                    f"host {server}" for server in PROXY_DNS_SERVERS
                ) + ")"
                wan_capture = start_capture(
                    wan_iface, health_bpf
                )
                page.page.wait_for_timeout(500)
                before, _ = chain_state("DNAT")
                third_answers, third_raw = dig(
                    THIRD_PARTY_PROBE_DNS, PUBLIC_DOMAIN
                )
                after, chain_raw = chain_state("DNAT")
                conntrack = router_exec(
                    "conntrack -L -p udp -o extended 2>/dev/null | "
                    f"grep -F 'src={CLIENT_IP} ' | head -20"
                ).strip()
                lan_packets = stop_capture(lan_capture)
                wan_packets = stop_capture(wan_capture)
                lan_query_ids = _dns_query_ids(lan_packets, PUBLIC_DOMAIN)
                wan_query_ids = _dns_query_ids(wan_packets, PUBLIC_DOMAIN)
                forwarded_query_ids = lan_query_ids & wan_query_ids
                health_servers_seen = [
                    server for server in PROXY_DNS_SERVERS
                    if server in wan_packets
                ]
                check(
                    "第三方代理-主备DNS健康探测",
                    len(health_servers_seen) == len(PROXY_DNS_SERVERS),
                    f"已观察={health_servers_seen}, 期望={PROXY_DNS_SERVERS}",
                )
                if not third_answers:
                    diagnostic = (
                        f"探针={THIRD_PARTY_PROBE_DNS}, 活动DNS={active_dns}; "
                        f"LAN事务ID={sorted(lan_query_ids)}, "
                        f"WAN事务ID={sorted(wan_query_ids)}, "
                        f"同请求WAN转发={bool(forwarded_query_ids)}, "
                        f"客户端conntrack={bool(conntrack)}; "
                        f"LAN路由=[{lan_route}], WAN路由=[{wan_route}]"
                    )
                    rec.add_detail(f"  第三方代理失败诊断: {diagnostic}")
                    rec.add_detail(f"  [LAN抓包]\n{lan_packets or '无输出'}")
                    rec.add_detail(f"  [WAN抓包]\n{wan_packets or '无输出'}")
                    rec.add_detail(f"  [conntrack]\n{conntrack or '无客户端条目'}")
                else:
                    diagnostic = third_raw or "解析成功"
                check("第三方代理-DNAT解析", bool(third_answers), diagnostic)
                check(
                    "第三方代理-DNAT计数增长",
                    before is not None and after is not None and after > before,
                    f"before={before}, after={after}; {chain_raw}",
                )
        finally:
            for prefix in list(capture_prefixes):
                try:
                    stop_capture(prefix)
                except Exception as exc:
                    failures.append(f"清理抓包进程{prefix}异常: {exc}")
            for domain in test_domains:
                try:
                    page.navigate_to_dns_accelerate()
                    if page.find_rule_row(domain):
                        deleted = page.delete_reverse_proxy(domain)
                        check(f"清理临时规则-{domain}", bool(deleted))
                except Exception as exc:
                    failures.append(f"清理临时规则{domain}异常: {exc}")
                    rec.add_detail(f"  清理临时规则-{domain}: [FAIL] {exc}")
            try:
                remaining = [
                    domain for domain in test_domains
                    if bv.query_dns_reverse_proxy(domain) is not None
                ]
                if remaining:
                    record_backend_result(
                        "后端兜底清理临时规则",
                        bv.cleanup_dns_reverse_proxy_domains(remaining),
                    )
                    remaining = [
                        domain for domain in test_domains
                        if bv.query_dns_reverse_proxy(domain) is not None
                    ]
                check("临时规则残留审计", not remaining, str(remaining))
            except Exception as exc:
                failures.append(f"临时规则残留审计异常: {exc}")
            try:
                restored = restore_original()
                check("恢复原始DNS配置", restored)
            except Exception as exc:
                failures.append(f"恢复原始DNS配置异常: {exc}")
                rec.add_detail(f"  恢复原始DNS配置: [FAIL] {exc}")
            for target in reversed(added_routes):
                try:
                    cleanup = client_exec(
                        f"sudo -n ip route del {target}/32 "
                        "&& echo __ROUTE_DELETED__",
                        timeout=10,
                    )
                    check(
                        f"清理客户端路由-{target}",
                        "__ROUTE_DELETED__" in cleanup,
                        cleanup.strip() or "无输出",
                    )
                except Exception as exc:
                    failures.append(f"清理客户端路由{target}异常: {exc}")

        print(
            f"\n[DNS加速全模式功能验证] "
            f"{'通过' if not failures else '失败' + str(len(failures)) + '项'}"
        )
        assert not failures, (
            f"DNS加速全模式功能验证失败({len(failures)}项): {'; '.join(failures)}"
        )
