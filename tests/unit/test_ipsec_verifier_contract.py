from __future__ import annotations

import json
from pathlib import Path

from utils.ipsec_verifier import IpsecTopology, IpsecVerifier


class _Backend:
    def __init__(self):
        self.body = ""
        self.display = ""

    def _ftp_exec_secret_script(self, ssh, body, display_command, timeout):
        self.body = body
        self.display = display_command
        return ""


def _topology():
    return IpsecTopology(
        token="abc123",
        router_policy="ipsec_t_r_abc123",
        peer_policy="ipsec_t_p_abc123",
        router_proposal="ike_t_r_abc123",
        peer_proposal="ike_t_p_abc123",
        client_source="10.99.99.1",
        peer_service="198.18.1.2",
        client_iface="ens11",
        client_gateway="192.168.148.1",
        router_underlay="192.0.2.1",
        peer_underlay="192.0.2.2",
        router_interface="wan1",
        peer_interface="wan1",
    )


def test_sensitive_values_are_redacted_recursively():
    value = IpsecVerifier.sanitize_value({
        "secret": "runtime-only-secret",
        "nested": {"psk": "another-secret"},
        "line": "password=plaintext",
        "spi": "spi 0x1234abcd",
    })
    serialized = json.dumps(value, ensure_ascii=False)
    assert "runtime-only-secret" not in serialized
    assert "another-secret" not in serialized
    assert "plaintext" not in serialized
    assert "0x1234abcd" not in serialized
    assert value["secret"] == {"configured": True, "length": 19}


def test_secure_script_keeps_secret_out_of_display_command():
    backend = _Backend()
    verifier = IpsecVerifier(backend)
    secret = "runtime-only-psk"
    verifier._secure_script_call(
        object(), verifier.POLICY_SCRIPT, "add",
        {"tagname": "safe_name", "secret": secret}, "peer",
    )
    assert secret in backend.body
    assert secret not in backend.display
    assert "fields=secret,tagname" in backend.display


def test_policy_params_are_symmetric_and_secret_is_runtime_only():
    verifier = IpsecVerifier(_Backend())
    topology = _topology()
    secret = "runtime-only-psk"
    router = verifier._policy_params("router", topology, 7, secret)
    peer = verifier._policy_params("peer", topology, 9, secret)
    assert router["local_ip"] == peer["remote_addr"]
    assert router["remote_addr"] == peer["local_ip"]
    assert router["local_id"] == peer["remote_id"]
    assert router["remote_id"] == peer["local_id"]
    assert router["secret"] == peer["secret"] == secret
    router_traffic = json.loads(base64_decode(router["traffic"]))
    peer_traffic = json.loads(base64_decode(peer["traffic"]))
    assert router_traffic[0]["src"] == peer_traffic[0]["dst"]
    assert router_traffic[0]["dst"] == peer_traffic[0]["src"]


def base64_decode(value: str) -> str:
    import base64
    return base64.b64decode(value).decode()


def test_gui_has_exactly_one_new_ipsec_node_and_no_old_vpn_client_node():
    root = Path(__file__).resolve().parents[2]
    source = (root / "gui" / "main_window.py").read_text(encoding="utf-8")
    node = (
        "network/test_ipsec_vpn_comprehensive.py::"
        "TestIpsecVpnComprehensive::test_ipsec_vpn_comprehensive"
    )
    assert source.count(node) == 2
    assert '"IPsec VPN": {' in source
    assert '"IPSec VPN": {' not in source


def test_comprehensive_module_has_one_test_function():
    root = Path(__file__).resolve().parents[2]
    source = (
        root / "tests" / "network" / "test_ipsec_vpn_comprehensive.py"
    ).read_text(encoding="utf-8")
    assert source.count("def test_ipsec_vpn_comprehensive(") == 1
    assert "run_vpn_comprehensive_test" not in source


def test_ipsec_realtime_progress_is_one_line_flushed_and_secret_safe(monkeypatch):
    from tests.network.test_ipsec_vpn_comprehensive import _emit_ipsec_realtime

    calls = []

    def fake_print(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr("builtins.print", fake_print)
    private_value = "ipsec-realtime-private-value"
    _emit_ipsec_realtime(
        "步骤开始",
        f"步骤1\n验证实时日志 password={private_value}",
    )

    assert len(calls) == 1
    args, kwargs = calls[0]
    rendered = " ".join(str(item) for item in args)
    assert rendered.startswith("[IPsec][步骤开始] 步骤1 验证实时日志")
    assert "\n" not in rendered
    assert private_value not in rendered
    assert "[已隐藏]" in rendered
    assert kwargs["flush"] is True


def test_ipsec_comprehensive_wires_realtime_step_and_summary_events():
    root = Path(__file__).resolve().parents[2]
    source = (
        root / "tests" / "network" / "test_ipsec_vpn_comprehensive.py"
    ).read_text(encoding="utf-8")

    assert source.count("_emit_ipsec_realtime(") >= 7
    for event in ("开始", "步骤开始", "步骤说明", "步骤结束", "汇总"):
        assert f'"{event}"' in source
    assert '_emit_ipsec_realtime(status, f"{section} | {label}")' in source


def test_ipsec_realtime_stdout_smoke():
    from tests.network.test_ipsec_vpn_comprehensive import _emit_ipsec_realtime

    _emit_ipsec_realtime("步骤开始", "GUI实时日志链路烟测")
