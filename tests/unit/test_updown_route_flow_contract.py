import json

from utils.backend_verifier import BackendVerifier
from tests.network.test_updown_route_comprehensive import (
    TestUpdownRouteFlowVerification as _UpdownFlowVerification,
)


CONNTRACK_ROWS = """\
ipv4 2 tcp 6 10 ESTABLISHED src=192.168.148.2 dst=223.5.5.5 sport=40100 dport=80 src=223.5.5.5 dst=10.66.0.45 sport=80 dport=40100 mark=0 remote_if=wan1
ipv4 2 tcp 6 10 ESTABLISHED src=192.168.148.2 dst=10.66.0.40 sport=40200 dport=5201 src=10.66.0.40 dst=10.66.0.49 sport=5201 dport=40200 mark=0 remote_if=wan1
"""


class FakeRouter:
    def __init__(self):
        self.commands = []
        self.conntrack = CONNTRACK_ROWS
        self.rules = [
            {
                "id": "7", "tagname": "udflow_sep", "enabled": "yes",
                "upiface": "wan1", "downiface": "wan3", "protocol": "tcp",
            },
            {"id": "8", "tagname": "user_rule", "enabled": "yes"},
        ]
        self.runtime = (
            '7 node { proto:"tcp" out:"wan1" in:"wan3" }\n'
            '8 node { proto:"" out:"wan2" in:"wan2" }\n'
        )
        self.ipsets = {
            "updown_src_7", "_updown_src_7", "updown_src_8",
        }

    def exec(self, command):
        self.commands.append(command)
        if command == "conntrack -L -o extended 2>/dev/null":
            return self.conntrack
        if command == "ip -4 -br a 2>/dev/null":
            return (
                "wan1 UP 10.66.0.45/24\n"
                "wan3 UP 10.66.0.49/24\n"
            )
        if command.startswith("/usr/ikuai/function/stream_updown show"):
            return json.dumps({"total": len(self.rules), "data": self.rules})
        if command == "/usr/ikuai/function/stream_updown del id=7":
            self.rules = [rule for rule in self.rules if rule["id"] != "7"]
            self.runtime = '8 node { proto:"" out:"wan2" in:"wan2" }\n'
            self.ipsets = {"updown_src_7", "updown_src_8"}
            return '{"Result":10000}'
        if command == "cat /tmp/iktmp/stream_updown.txt 2>/dev/null":
            return self.runtime
        if command == "ipset list -n 2>/dev/null":
            return "\n".join(sorted(self.ipsets))
        if command == "ipset list updown_src_7 2>/dev/null":
            return "References: 0\nNumber of entries: 0\nMembers:\n"
        return ""


def make_verifier(router=None):
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = router or FakeRouter()
    verifier.connect_router = lambda: None
    return verifier


def test_updown_egress_filters_exact_target_and_exposes_derived_down_evidence():
    verifier = make_verifier()

    result = verifier.conntrack_egress(
        "192.168.148.2", proto="tcp", dst_ip="10.66.0.40", dst_port=5201
    )

    assert result["found"]
    assert result["remote_if"] == "wan1"
    assert result["rev_remote_if"] == "wan3"
    assert result["reply_dst_ip"] == "10.66.0.49"
    assert result["down_iface_source"] == "reply_tuple_snat_ip"
    assert "dst=10.66.0.40" in result["raw"]


def test_conntrack_filter_does_not_match_the_reply_tuple_as_original_target():
    verifier = make_verifier()

    rows = verifier.conntrack_client_flow_entries(
        "192.168.148.2", proto="tcp", dst_ip="10.66.0.49", dst_port=40200
    )

    assert rows == []


def test_updown_runtime_check_is_rule_specific_and_validates_both_directions():
    verifier = make_verifier()

    active = verifier.verify_stream_updown_kernel_status(
        7, expected_upiface="wan1", expected_downiface="wan3"
    )
    wrong_down = verifier.verify_stream_updown_kernel_status(
        7, expected_upiface="wan1", expected_downiface="wan2"
    )
    absent = verifier.verify_stream_updown_kernel_status(
        99, expected_present=False
    )

    assert active.passed
    assert not wrong_down.passed
    assert absent.passed


def test_updown_cleanup_uses_firmware_delete_and_preserves_foreign_rules():
    router = FakeRouter()
    verifier = make_verifier(router)

    result = verifier.cleanup_stream_updown_test("udflow_", max_wait_seconds=0)

    assert result.passed
    assert result.details["deleted_ids"] == [7]
    assert result.details["empty_carrier_ipsets"] == ["updown_src_7"]
    assert router.rules == [
        {"id": "8", "tagname": "user_rule", "enabled": "yes"}
    ]
    assert "/usr/ikuai/function/stream_updown del id=7" in router.commands
    assert not any("DELETE FROM stream_updown" in command
                   for command in router.commands)


def test_updown_http_probe_has_fixed_ip_and_reports_actual_source_port():
    command = _UpdownFlowVerification.curl_probe_command(
        "110.242.70.57", "ens11"
    )

    assert "curl -4" in command
    assert "--interface ens11" in command
    assert "--resolve www.baidu.com:80:110.242.70.57" in command
    assert "remote_ip=%{remote_ip}" in command
    assert "local_port=%{local_port}" in command
    assert "size_download=%{size_download}" in command
