from tests.network.test_dns_accelerate_functional import (
    _dns_query_ids,
    _dnsproxy_jump_packet_count,
    _ipv4_answers,
    _ipv6_answers,
    _nat_packet_count,
    _redirect_packet_count,
)
from pages.network.dns_accelerate_page import DnsAcceleratePage
from utils.backend_verifier import BackendVerifier


def test_ipv4_answers_ignores_cname_ipv6_and_diagnostics():
    output = """www.a.shifen.com.
110.242.68.3
240e:ff:e020:966:0:ff:b042:f296
;; connection timed out
110.242.68.4
"""

    assert _ipv4_answers(output) == ["110.242.68.3", "110.242.68.4"]
    assert _ipv6_answers(output) == ["240e:ff:e020:966:0:ff:b042:f296"]


def test_redirect_packet_count_sums_only_udp_dns_redirect_rules():
    output = """Chain DNSPROXY (1 references)
    pkts      bytes target     prot opt in out source destination
       3        210 REDIRECT   udp  --  *  *  0.0.0.0/0 0.0.0.0/0 udp dpt:53 redir ports 53
       5        350 REDIRECT   udp  --  *  *  0.0.0.0/0 0.0.0.0/0 udp dpt:53 redir ports 53
       9        540 REDIRECT   tcp  --  *  *  0.0.0.0/0 0.0.0.0/0 tcp dpt:53 redir ports 53
"""

    assert _redirect_packet_count(output) == 8
    assert _nat_packet_count(output, "DNAT") is None
    assert _redirect_packet_count("Chain DNSPROXY (1 references)\n") is None


def test_dnsproxy_jump_count_only_sums_udp_53_jump():
    output = """Chain PREROUTING (policy ACCEPT)
      12 900 DNSPROXY udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:53
       8 480 DNSPROXY tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:53
       2 120 DNSPROXY udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:53
"""

    assert _dnsproxy_jump_packet_count(output) == 14


def test_dns_query_ids_correlate_same_query_across_lan_and_wan():
    lan = "192.168.148.2.39651 > 8.8.8.8.53: 16774+ [1au] A? www.baidu.com."
    wan = """10.66.0.45.32283 > 114.114.114.114.53: 14354+ A? www.baidu.com.
10.66.0.45.45678 > 180.76.76.76.53: 16774+ A? www.baidu.com.
"""

    lan_ids = _dns_query_ids(lan, "www.baidu.com")
    wan_ids = _dns_query_ids(wan, "www.baidu.com")
    assert lan_ids == {16774}
    assert wan_ids == {14354, 16774}
    assert lan_ids & wan_ids == {16774}


class _EmptyLocator:
    def count(self):
        return 0


class _SavePage:
    def wait_for_timeout(self, _milliseconds):
        return None

    def locator(self, _selector):
        return _EmptyLocator()


def test_save_switches_mode_before_toggling_service_state():
    page = DnsAcceleratePage.__new__(DnsAcceleratePage)
    page.page = _SavePage()
    calls = []
    page.select_cachemode = lambda mode: calls.append(("mode", mode))
    page.toggle_enable = lambda enabled: calls.append(("enable", enabled)) or True
    page.click_save_basic = lambda: True
    page.navigate_to_dns_accelerate = lambda: None
    page.get_basic_config = lambda: {"cachemode": "UDP", "enabled": False}

    assert page.save_basic_config(enable=False, cachemode="UDP")
    assert calls == [("mode", "UDP"), ("enable", False)]


class _DnsModeRouter:
    def __init__(self, *, conf, status="", dnslink="", process="", iptables=""):
        self.outputs = {
            "cat /tmp/iktmp/ikdnsd.conf": conf,
            "cat /tmp/iktmp/ikdnsd.status": status,
            "cat /tmp/iktmp/dnslink.status": dnslink,
            "ps | grep ikdnsd": process,
            "iptables -t nat -L DNSPROXY": iptables,
        }

    def exec(self, command, timeout=30):
        for prefix, output in self.outputs.items():
            if command.startswith(prefix):
                return output
        raise AssertionError(f"unexpected command: {command}")


def _mode_verifier(router):
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = router
    verifier.connect_router = lambda: None
    return verifier


def test_dns_mode_runtime_contracts_cover_all_four_modes():
    redirect = "1 80 REDIRECT udp -- * * 0/0 0/0 udp dpt:53 redir ports 53"
    running = "123 root ikdnsd -C /tmp/iktmp/ikdnsd.conf"

    udp = _mode_verifier(_DnsModeRouter(
        conf="port = 53\ncache_ttl = 120\n",
        status="ikdnsd -C /tmp/iktmp/ikdnsd.conf",
        process=running,
        iptables=redirect,
    )).verify_dns_mode_runtime("UDP", proxy_force=True)

    doh = _mode_verifier(_DnsModeRouter(
        conf="port = 53\ndoh_url = https://doh.pub/dns-query\n",
        status="ikdnsd -C /tmp/iktmp/ikdnsd.conf",
        process=running,
        iptables=redirect,
    )).verify_dns_mode_runtime(
        "DoH", query="https://doh.pub/dns-query", proxy_force=True
    )

    multi = _mode_verifier(_DnsModeRouter(
        conf="port = 0\ncache_ttl = 120\n",
        status="ikdnsd -C /tmp/iktmp/ikdnsd.conf",
        process=running,
    )).verify_dns_mode_runtime("多线分路")

    servers = ["114.114.114.114", "223.5.5.5"]
    third = _mode_verifier(_DnsModeRouter(
        conf="port = 53\n",
        dnslink=(
            "proxy_force_dns=114.114.114.114,223.5.5.5 "
            "proxy_ip=114.114.114.114"
        ),
        iptables=(
            "3 240 DNAT udp -- * * 0/0 0/0 udp dpt:53 "
            "to:114.114.114.114:53"
        ),
    )).verify_dns_mode_runtime("第三方代理", proxy_dns_servers=servers)

    assert udp.passed, udp.message
    assert doh.passed, doh.message
    assert multi.passed, multi.message
    assert third.passed, third.message


def test_third_party_runtime_rejects_dnat_target_different_from_active_dns():
    servers = ["114.114.114.114", "223.5.5.5"]
    result = _mode_verifier(_DnsModeRouter(
        conf="port = 53\n",
        dnslink=(
            "proxy_force_dns=114.114.114.114,223.5.5.5 "
            "proxy_ip=114.114.114.114"
        ),
        iptables=(
            "3 240 DNAT udp -- * * 0/0 0/0 udp dpt:53 "
            "to:223.5.5.5:53"
        ),
    )).verify_dns_mode_runtime("第三方代理", proxy_dns_servers=servers)

    assert not result.passed
    assert "目标匹配=False" in result.message
