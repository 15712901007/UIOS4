import json

import pytest

from utils.backend_verifier import BackendVerifier
from tests.network.test_domain_route_comprehensive import (
    TestDomainRouteFlowVerification as _DomainRouteFlowVerification,
)


EXTENDED_CONNTRACK = """\
tcp 6 117 src=192.168.148.2 dst=110.242.68.66 sport=45000 dport=80 src=110.242.68.66 dst=10.66.2.45 sport=80 dport=45000 mark=6000002 can_sel_route=true remote_if=wan2 rev_remote_if=lan1
tcp 6 117 src=192.168.148.2 dst=1.1.1.1 sport=45001 dport=443 src=1.1.1.1 dst=10.66.3.45 sport=443 dport=45001 mark=6000003 can_sel_route=true remote_if=wan3 rev_remote_if=lan1
tcp 6 117 src=192.168.148.99 dst=110.242.68.66 sport=45002 dport=80 src=110.242.68.66 dst=10.66.1.45 sport=80 dport=45002 mark=0 can_sel_route=true remote_if=wan1 rev_remote_if=lan1
"""


class FakeRouter:
    def __init__(self, conntrack_output=EXTENDED_CONNTRACK):
        self.conntrack_output = conntrack_output
        self.commands = []
        self.domain_rules = [
            {"id": "7", "tagname": "dmflow_unit", "enabled": "yes"},
            {"id": "8", "tagname": "user_rule", "enabled": "yes"},
        ]

    def exec(self, command):
        self.commands.append(command)
        if command == "conntrack -L -o extended 2>/dev/null":
            return self.conntrack_output
        if command.startswith("/usr/ikuai/function/stream_domain show"):
            return json.dumps({"total": len(self.domain_rules), "data": self.domain_rules})
        if command == "/usr/ikuai/function/stream_domain del id=7":
            self.domain_rules = [rule for rule in self.domain_rules if rule["id"] != "7"]
            return '{"Result":10000}'
        if command.startswith("cat /proc/ikuai/stats/ik_summary"):
            return "URL Route: enable\nURL_ROUTE_GROUP(GROUPID: 8)"
        if command.startswith("ipset list -n"):
            return "sdomain_src_8"
        return ""


def make_verifier(router=None):
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = router or FakeRouter()
    verifier.connect_router = lambda: None
    return verifier


def test_domain_wan_reader_uses_extended_conntrack_and_exact_target_filter():
    verifier = make_verifier()

    wans = verifier.conntrack_client_wans(
        "192.168.148.2", proto="tcp", dst_ip="110.242.68.66", dst_port=80
    )

    assert wans == ["wan2"]
    assert verifier._router.commands == ["conntrack -L -o extended 2>/dev/null"]
    assert all("/proc/net/nf_conntrack" not in command
               for command in verifier._router.commands)


def test_domain_cleanup_uses_firmware_delete_and_preserves_foreign_rules():
    router = FakeRouter()
    verifier = make_verifier(router)

    result = verifier.cleanup_stream_domain_test("dmflow_", max_wait_seconds=0)

    assert result.passed
    assert result.details["deleted_ids"] == [7]
    assert router.domain_rules == [
        {"id": "8", "tagname": "user_rule", "enabled": "yes"}
    ]
    assert "/usr/ikuai/function/stream_domain del id=7" in router.commands
    assert not any("DELETE FROM stream_domain" in command for command in router.commands)


def test_domain_probe_is_ipv4_single_connection_and_reports_remote_ip():
    command = _DomainRouteFlowVerification.curl_probe_command("www.baidu.com")

    assert "curl -4" in command
    assert "--interface ens11" in command
    assert "remote_ip=%{remote_ip}" in command
    assert command.endswith("http://www.baidu.com/")


def test_domain_probe_rejects_shell_metacharacters():
    with pytest.raises(ValueError):
        _DomainRouteFlowVerification.curl_probe_command("www.baidu.com;id")


def test_parallel_domain_probe_creates_distinct_background_connections():
    command = _DomainRouteFlowVerification.parallel_curl_probe_command(
        ["www.baidu.com", "www.qq.com"]
    )

    assert "probe=0 domain=www.baidu.com" in command
    assert "probe=1 domain=www.qq.com" in command
    assert command.count("curl -4") == 2
    assert command.count(") &") == 2
    assert command.endswith(" wait")


def test_route_object_cleanup_uses_firmware_entry_and_checks_runtime_residuals():
    router = FakeRouter()
    verifier = make_verifier(router)
    rows = [{
        "id": "11", "type": "0", "group_name": "DMFLOWIP",
        "group_id": "IPGP11",
    }]

    def query(sql):
        return list(rows)

    original_exec = router.exec

    def execute(command):
        if command == "/usr/ikuai/function/route_object del id=11":
            rows.clear()
            router.commands.append(command)
            return '{"Result":10000}'
        return original_exec(command)

    router.exec = execute
    verifier._sqlite_query_list = query
    verifier.get_object_ref_count = lambda group_id: 0

    result = verifier.cleanup_route_object_test(
        "DMFLOW", type_keys=("ip",), max_wait_seconds=0
    )

    assert result.passed
    assert result.details["deleted_ids"] == [11]
    assert "/usr/ikuai/function/route_object del id=11" in router.commands
    assert not any("DELETE FROM object_group" in command for command in router.commands)
