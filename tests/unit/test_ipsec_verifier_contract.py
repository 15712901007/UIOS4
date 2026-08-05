from __future__ import annotations

import json
from pathlib import Path

import pytest

from pages.network.ipsec_vpn_page import IpsecVpnPage
from utils.backend_verifier import VerifyResult
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
        router_policy="iprabc123",
        peer_policy="ippabc123",
        router_proposal="ikerabc123",
        peer_proposal="ikepabc123",
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


def test_extended_topology_params_cover_ipv6_hub_and_transport_modes():
    verifier = IpsecVerifier(_Backend())
    topology = IpsecTopology(
        **{
            **_topology().__dict__,
            "addr_type": "v6",
            "protocol": "any",
            "router_role": "spoke",
            "peer_role": "hub",
            "encap_mode": "tunnel",
        }
    )
    params = verifier._policy_params("peer", topology, 9, "runtime-only-psk")
    assert params["addr_type"] == "v6"
    assert params["role"] == "hub"
    assert params["local_id_type"] == "IPV6"
    assert params["remote_addr"] == ""
    assert params["traffic"] == ""

    transport = IpsecTopology(
        **{
            **_topology().__dict__,
            "encap_mode": "transport",
            "protocol": "icmp",
        }
    )
    transport_params = verifier._policy_params(
        "router", transport, 7, "runtime-only-psk"
    )
    assert transport_params["encap_mode"] == "transport"
    assert json.loads(base64_decode(transport_params["traffic"]))[0]["src"] == (
        transport.router_selector
    )


def test_topology_selector_prefix_is_family_aware():
    base = _topology()
    v6 = IpsecTopology(**{**base.__dict__, "addr_type": "v6"})
    assert v6.router_selector.endswith("/128")
    assert v6.peer_selector.endswith("/128")
    assert v6.uses_loopback_data_plane


def test_multi_tunnel_observability_aggregates_all_rows(monkeypatch):
    verifier = IpsecVerifier(_Backend())

    class _Ssh:
        def exec(self, command, timeout=0):
            if "TYPE='list,list_total'" in command:
                return json.dumps({
                    "list_total": 2,
                    "list": [
                        {"policy_id": 7, "tunnel_key": "key-a",
                         "status": "established", "in_bytes": 12,
                         "out_bytes": 12},
                        {"policy_id": 9, "tunnel_key": "key-b",
                         "status": "established", "in_bytes": 16,
                         "out_bytes": 16},
                    ],
                })
            if "TYPE='detail'" in command:
                value = 12 if "key-a" in command else 16
                return json.dumps({"statistics": {"traffic_rate": {
                    "in_protected_bytes": value,
                    "out_protected_bytes": value,
                    "in_protected_packets": 1,
                    "out_protected_packets": 1,
                }}, "sa": {"esp": {"inbound": {}, "outbound": {}}}})
            if "TYPE='log'" in command:
                return json.dumps({"title": "ok"})
            if "swanctl --list-sas" in command:
                return ("ipsec2-spoke-7: #1, ESTABLISHED\n"
                        "  ipsec2-spoke-7-esp: INSTALLED\n"
                        "ipsec2-spoke-9: #2, ESTABLISHED\n"
                        "  ipsec2-spoke-9-esp: INSTALLED\n")
            raise AssertionError(command)

    monkeypatch.setattr(verifier, "_router", lambda: _Ssh())
    result = verifier.query_multi_tunnel_observability([7, 9], "router")
    assert result["matched_rows"] == 2
    assert result["distinct_tunnel_keys"] == 2
    assert result["aggregate_statistics"]["in_protected_bytes"] == 28
    assert result["child_inventory"]["total_installed"] == 2


def test_created_object_registry_enforces_current_tagname_limit():
    verifier = IpsecVerifier(_Backend())
    verifier.register_created_object("router", "policy", 7, "iprabc123")
    assert ("router", "policy", 7, "iprabc123") in verifier._created_objects
    with pytest.raises(ValueError, match="名称不符合"):
        verifier.register_created_object("router", "policy", 8, "p" * 16)


def test_cleanup_never_deletes_an_unowned_matching_name():
    backend = _Backend()
    verifier = IpsecVerifier(backend)
    result = verifier.cleanup(_topology())
    assert result.passed is True
    assert result.details["owned_object_count"] == 0
    assert backend.body == ""


def test_terminate_result_depends_on_final_sa_absence(monkeypatch):
    verifier = IpsecVerifier(_Backend())

    class _Ssh:
        def exec(self, command, timeout=0):
            return "terminate failed: peer already removed the IKE_SA"

    router = _Ssh()
    peer = _Ssh()
    listings = {id(router): 0, id(peer): 0}

    def sa_text(ssh):
        listings[id(ssh)] += 1
        policy_id = 7 if ssh is router else 9
        return (
            f"ipsec2-spoke-{policy_id}: #1, ESTABLISHED\n"
            if listings[id(ssh)] == 1 else ""
        )

    monkeypatch.setattr(verifier, "_router", lambda: router)
    monkeypatch.setattr(verifier, "_peer", lambda: peer)
    monkeypatch.setattr(verifier, "_sa_text", sa_text)
    monkeypatch.setattr(
        verifier,
        "wait_for_sa_absent",
        lambda *args, **kwargs: VerifyResult(
            "L4", True, "absent", details={"router_present": False,
                                             "peer_present": False},
        ),
    )

    result = verifier.terminate_test_sas(7, 9)

    assert result.passed is True
    assert len(result.details["terminate_diagnostics"]) == 2


def test_rekey_child_uses_requested_endpoint(monkeypatch):
    verifier = IpsecVerifier(_Backend())

    class _Ssh:
        command = ""

        def exec(self, command, timeout=0):
            self.command = command
            return "rekey completed successfully"

    router = _Ssh()
    monkeypatch.setattr(verifier, "_router", lambda: router)
    monkeypatch.setattr(
        verifier, "_peer",
        lambda: pytest.fail("router rekey must not contact peer endpoint"),
    )

    result = verifier.rekey_child("router", 7)

    assert result.passed is True
    assert result.details["initiator"] == "router"
    assert "ipsec2-spoke-7-esp" in router.command


def test_select_option_key_normalizes_fullwidth_display_punctuation():
    assert (
        IpsecVpnPage._option_key("MODP 2048（组14）")
        == IpsecVpnPage._option_key("MODP 2048(组14)")
    )
    assert (
        IpsecVpnPage._option_key("MODP 2048（组14）")
        != IpsecVpnPage._option_key("MODP 2048（组24）")
    )


def test_tunnel_observability_normalizes_nested_statistics_and_sa(monkeypatch):
    verifier = IpsecVerifier(_Backend())

    class _Ssh:
        def exec(self, command, timeout=0):
            if "TYPE='list,list_total'" in command:
                return json.dumps({
                    "list_total": 1,
                    "list": [{
                        "policy_id": 7, "tunnel_key": "safe-key",
                        "status": "established", "in_bytes": 672,
                        "out_bytes": 672,
                    }],
                })
            if "TYPE='detail'" in command:
                return json.dumps({
                    "statistics": {"traffic_rate": {
                        "in_protected_packets": 8,
                        "out_protected_packets": 8,
                        "in_protected_bytes": 672,
                        "out_protected_bytes": 672,
                    }},
                    "sa": {"esp": {
                        "inbound": {"ipsec_sa_lifetime_bytes": 1843200},
                        "outbound": {"ipsec_sa_lifetime_bytes": 1843200},
                    }},
                })
            if "TYPE='log'" in command:
                return json.dumps({"title": "ok", "diagnosis": {},
                                   "technical_logs": ["ok"]})
            raise AssertionError(command)

    monkeypatch.setattr(verifier, "_router", lambda: _Ssh())

    result = verifier.query_tunnel_observability(7, "router")

    assert result["detail"]["statistics"] == {
        "in_protected_packets": 8,
        "out_protected_packets": 8,
        "in_protected_bytes": 672,
        "out_protected_bytes": 672,
    }
    assert result["detail"]["sa"]["ipsec_sa_lifetime_bytes"] == 1843200


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
