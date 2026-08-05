from utils.backend_verifier import BackendVerifier
from tests.network.test_port_route_comprehensive import (
    TestPortRouteFlowVerification as _PortRouteFlowVerification,
)


IPTABLES_OUTPUT = """\
Chain STREAM_IPPORT_NEW (1 references)
num pkts bytes ccnt fcnt fastid target proto opt in out source destination
1 3 180 0 0 0 NTH_CONNMARK tcp -- * * 0.0.0.0/0 0.0.0.0/0 /* 7_tcp */ --set-mark 6000001,6000002 --set-ifname wan2,wan3
2 5 300 0 0 0 NTH_CONNMARK udp -- * * 0.0.0.0/0 0.0.0.0/0 /* 7_udp */ --set-mark 6000001,6000002 --set-ifname wan2,wan3
3 11 660 0 0 0 NTH_CONNMARK tcp -- * * 0.0.0.0/0 0.0.0.0/0 /* 70_other */ --set-mark 6000070 --set-ifname wan1
"""


class FakeRouter:
    def __init__(self, output=IPTABLES_OUTPUT):
        self.output = output
        self.commands = []

    def exec(self, command):
        self.commands.append(command)
        return self.output


def make_verifier(output=IPTABLES_OUTPUT):
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = FakeRouter(output)
    verifier.connect_router = lambda: None
    return verifier


def test_mangle_counter_sums_all_lines_for_the_same_database_rule():
    verifier = make_verifier()

    assert verifier.read_mangle_counter("STREAM_IPPORT_NEW", 7) == 8


def test_mangle_rule_id_match_does_not_include_longer_numeric_id():
    verifier = make_verifier()

    assert verifier.read_mangle_counter("STREAM_IPPORT_NEW", 70) == 11
    assert verifier.read_mangle_rule_line_numbers("STREAM_IPPORT_NEW", 7) == [1, 2]


def test_mangle_rule_parses_all_multi_wan_marks_and_keeps_legacy_first_mark():
    verifier = make_verifier()

    assert verifier.read_mangle_rule_marks("STREAM_IPPORT_NEW", 7) == [6000001, 6000002]
    assert verifier.read_mangle_rule_mark("STREAM_IPPORT_NEW", 7) == 6000001


def test_conntrack_mark_reader_uses_extended_rows_and_filters_client():
    output = """\
ipv4 2 tcp 6 10 src=192.168.148.2 dst=10.66.0.40 sport=40080 dport=5201 mark=6000001
ipv4 2 udp 17 10 src=192.168.148.99 dst=10.66.0.40 sport=50000 dport=53 mark=6000002
"""
    verifier = make_verifier(output)

    assert verifier.conntrack_client_marks("192.168.148.2") == {6000001}
    assert verifier._router.commands == ["conntrack -L -o extended 2>/dev/null"]


def test_conntrack_flow_filter_excludes_background_client_connections():
    output = """\
ipv4 2 tcp 6 10 src=192.168.148.2 dst=223.5.5.5 sport=40080 dport=53 mark=6000001 can_sel_route=true
ipv4 2 udp 17 10 src=192.168.148.2 dst=223.5.5.5 sport=50000 dport=53 mark=6000002 can_sel_route=true
ipv4 2 tcp 6 10 src=192.168.148.2 dst=110.242.70.57 sport=40100 dport=443 mark=6000003 can_sel_route=true
"""
    verifier = make_verifier(output)

    entries = verifier.conntrack_client_flow_entries(
        "192.168.148.2", proto="tcp", dst_ip="223.5.5.5",
        src_port=40080, dst_port=53,
    )

    assert len(entries) == 1
    assert verifier.conntrack_client_flow_marks(
        "192.168.148.2", proto="tcp", dst_ip="223.5.5.5",
        src_port=40080, dst_port=53,
    ) == {6000001}


def test_source_port_probes_bind_exact_ports_on_the_public_dns_target():
    in_probe = _PortRouteFlowVerification.PROBES["sport_in"]
    out_probe = _PortRouteFlowVerification.PROBES["sport_out"]

    assert in_probe[:2] == ("tcp", 53)
    assert "-p 40080 223.5.5.5 53" in in_probe[2]
    assert out_probe[:2] == ("tcp", 53)
    assert "-p 40100 223.5.5.5 53" in out_probe[2]


def test_tcp_udp_and_icmp_probes_share_the_selectable_public_target():
    probes = _PortRouteFlowVerification.PROBES

    assert "@223.5.5.5" in probes["tcp53"][2]
    assert "@223.5.5.5" in probes["udp53"][2]
    assert probes["icmp"][2].endswith("223.5.5.5")


def test_new_connection_distribution_uses_concurrent_fixed_public_flows():
    command = _PortRouteFlowVerification.parallel_tcp53_command(attempts=6)

    assert "for p in 41000 41001 41002 41003 41004 41005" in command
    assert "sleep 2 | nc" in command
    assert "-s 192.168.148.2 -p \"$p\" 223.5.5.5 53" in command
    assert command.endswith("& done; wait")
