import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from utils.backend_verifier import BackendVerifier


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def make_verifier(tolerance=0.20):
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._ssh_config = SimpleNamespace(
        iperf3_tolerance=tolerance,
        iperf3_server="10.66.0.40",
        iperf3_duration=10,
    )
    verifier._client = None
    return verifier


def iperf_result(mbps):
    return {
        "end": {
            "sum_received": {"bits_per_second": mbps * 1_000_000},
            "sum_sent": {"bits_per_second": mbps * 1_000_000},
        }
    }


def test_report_example_below_lower_bound_must_fail(monkeypatch):
    verifier = make_verifier()
    monkeypatch.setattr(verifier, "run_iperf3", lambda **kwargs: iperf_result(18.14))

    result = verifier.verify_iperf3(
        "download",
        expected_kbps=4096,
        baseline_mbps=50.0,
    )

    assert not result.passed
    assert result.details["actual_mbps"] == 18.14
    assert result.details["lower_bound_mbps"] == pytest.approx(26.21, abs=0.01)


def test_throughput_inside_two_sided_tolerance_passes(monkeypatch):
    verifier = make_verifier()
    monkeypatch.setattr(verifier, "run_iperf3", lambda **kwargs: iperf_result(34.0))

    result = verifier.verify_iperf3(
        "download",
        expected_kbps=4096,
        baseline_mbps=50.0,
        parallel_streams=4,
    )

    assert result.passed
    assert result.details["parallel_streams"] == 4
    assert result.details["baseline_ok"] is True


def test_insufficient_unrestricted_baseline_must_fail(monkeypatch):
    verifier = make_verifier()
    monkeypatch.setattr(verifier, "run_iperf3", lambda **kwargs: iperf_result(32.8))

    result = verifier.verify_iperf3(
        "download",
        expected_kbps=4096,
        baseline_mbps=40.0,
    )

    assert not result.passed
    assert result.details["baseline_ok"] is False


@pytest.mark.parametrize("payload", [{}, {"end": {}}, iperf_result(0)])
def test_missing_or_zero_throughput_must_fail(monkeypatch, payload):
    verifier = make_verifier()
    monkeypatch.setattr(verifier, "run_iperf3", lambda **kwargs: payload)

    result = verifier.verify_iperf3("upload", expected_kbps=1024)

    assert not result.passed
    assert "有效" in result.message or "缺少" in result.message


def test_iptables_shared_and_independent_modes_are_not_interchangeable(monkeypatch):
    verifier = make_verifier()
    shared_line = (
        "DROP all -- * * 0.0.0.0/0 0.0.0.0/0 "
        "dir:out timeset simple_qos_time_7 bytesband 1024 simpleup7"
    )
    monkeypatch.setattr(verifier, "get_iptables_chain", lambda chain: shared_line)

    shared = verifier.verify_iptables_rule(
        "IP_QOS", rule_id=7, expected_speed_kbps=1024,
        direction="upload", rate_mode="shared",
    )
    independent = verifier.verify_iptables_rule(
        "IP_QOS", rule_id=7, expected_speed_kbps=1024,
        direction="upload", rate_mode="independent",
    )

    assert shared.passed
    assert not independent.passed


def test_iptables_direction_must_match_the_target_bucket(monkeypatch):
    verifier = make_verifier()
    output = (
        "DROP dir:out timeset simple_qos_time_3 limit: 512 kBps mode srcip\n"
        "DROP dir:in timeset simple_qos_time_3 limit: 1024 kBps mode dstip"
    )
    monkeypatch.setattr(verifier, "get_iptables_chain", lambda chain: output)

    upload = verifier.verify_iptables_rule(
        "IP_QOS", rule_id=3, expected_speed_kbps=512,
        direction="upload", rate_mode="independent",
    )
    download = verifier.verify_iptables_rule(
        "IP_QOS", rule_id=3, expected_speed_kbps=1024,
        direction="download", rate_mode="independent",
    )
    wrong_direction = verifier.verify_iptables_rule(
        "IP_QOS", rule_id=3, expected_speed_kbps=512,
        direction="download", rate_mode="independent",
    )

    assert upload.passed
    assert download.passed
    assert not wrong_direction.passed


def test_run_iperf3_passes_parallel_and_omit_options(monkeypatch):
    verifier = make_verifier()

    class FakeClient:
        def __init__(self):
            self.command = None

        def exec(self, command, **kwargs):
            self.command = command
            return json.dumps(iperf_result(12.0))

    client = FakeClient()
    verifier._client = client
    monkeypatch.setattr(verifier, "connect_client", lambda: None)

    result = verifier.run_iperf3(
        direction="download",
        bind_ip="192.168.148.2",
        duration=8,
        parallel_streams=4,
        omit_seconds=2,
        retries=0,
    )

    assert "error" not in result
    assert " -P 4" in client.command
    assert " -O 2" in client.command
    assert client.command.endswith(" -R")


def test_ip_and_mac_comprehensive_flows_cover_both_runtime_modes():
    for relative_path in (
        "tests/network/test_ip_rate_limit_comprehensive.py",
        "tests/network/test_mac_rate_limit_comprehensive.py",
    ):
        source = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        assert '"independent": {"label": "独立限速"' in source
        assert '"shared": {"label": "共享限速"' in source
        assert "parallel_streams=profile[\"streams\"]" in source
        assert "baseline_upload_mbps=profile[\"baseline\"][\"upload\"]" in source


def test_stream_control_also_uses_two_sided_rate_tolerance():
    source = (
        PROJECT_ROOT / "tests/network/test_stream_control_comprehensive.py"
    ).read_text(encoding="utf-8")

    assert "lower = limit_mbps * (1 - tolerance)" in source
    assert "lower <= up_mbps <= upper" in source
    assert "lower <= down_mbps <= upper" in source
    assert "上行过度限速" in source
    assert "下行过度限速" in source
