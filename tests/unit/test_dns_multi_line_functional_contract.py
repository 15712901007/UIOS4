from pages.network.dns_multi_line_page import DnsMultiLinePage
from tests.network.test_dns_multi_line_functional import (
    _dns_query_destinations,
    _ipv4_answers,
    _remote_interfaces,
)
from utils.backend_verifier import BackendVerifier


SUMMARY = """Multi Dns: enable
====================== Multi Dns Info ======================
1. wan2  223.5.5.5  223.6.6.6
2. wan2_ad  223.5.5.5  223.6.6.6

====================== Col Info ======================
"""


class _Router:
    def __init__(self, output):
        self.output = output

    def exec(self, command, timeout=30):
        assert command == "cat /proc/ikuai/stats/ik_summary"
        return self.output


def _verifier(output):
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = _Router(output)
    verifier.connect_router = lambda: None
    return verifier


def test_runtime_parser_reads_status_and_wan_ad_mapping():
    runtime = BackendVerifier._parse_dns_multi_line_runtime(SUMMARY)

    assert runtime["enabled"] is True
    assert runtime["entries"] == [
        {"interface": "wan2", "dns1": "223.5.5.5", "dns2": "223.6.6.6"},
        {"interface": "wan2_ad", "dns1": "223.5.5.5", "dns2": "223.6.6.6"},
    ]


def test_runtime_verifier_requires_both_wan_mappings():
    result = _verifier(SUMMARY).verify_dns_multi_line_runtime(
        "wan2", "223.5.5.5", "223.6.6.6",
        should_exist=True, expect_enabled=True,
    )
    missing_ad = _verifier(SUMMARY.replace(
        "2. wan2_ad  223.5.5.5  223.6.6.6\n", ""
    )).verify_dns_multi_line_runtime(
        "wan2", "223.5.5.5", "223.6.6.6",
        should_exist=True, expect_enabled=True,
    )

    assert result.passed, result.message
    assert not missing_ad.passed
    assert "wan2_ad" in missing_ad.message


def test_runtime_verifier_rejects_enabled_switch_after_last_mapping_removed():
    no_mappings_but_enabled = SUMMARY.replace(
        "1. wan2  223.5.5.5  223.6.6.6\n"
        "2. wan2_ad  223.5.5.5  223.6.6.6\n",
        "",
    )

    result = _verifier(no_mappings_but_enabled).verify_dns_multi_line_runtime(
        "wan2", "223.5.5.5", "223.6.6.6",
        should_exist=False, expect_enabled=False,
    )

    assert not result.passed
    assert "功能开关期望=disable" in result.message


def test_capture_parser_scopes_destination_to_requested_domain():
    capture = """10.0.0.2.40000 > 114.114.114.114.53: 1+ A? www.baidu.com. (42)
10.0.0.2.40001 > 223.5.5.5.53: 2+ A? www.qq.com. (39)
223.5.5.5.53 > 10.0.0.2.40001: 2 1/0/0 A 1.2.3.4 (55)
"""

    assert _dns_query_destinations(capture, "www.qq.com") == {"223.5.5.5"}
    assert _dns_query_destinations(capture, "www.baidu.com") == {
        "114.114.114.114"
    }


def test_answer_and_conntrack_parsers_ignore_non_evidence_text():
    dig = "www.example.com.\n198.51.100.8\n;; timed out\n"
    conntrack = "remote_if=wan2 mark=0 remote_if=wan2"

    assert _ipv4_answers(dig) == ["198.51.100.8"]
    assert _remote_interfaces(conntrack) == {"wan2"}


def test_page_object_remains_importable_for_functional_fixture_contract():
    assert DnsMultiLinePage.MODULE_NAME == "dns_multi_line"
