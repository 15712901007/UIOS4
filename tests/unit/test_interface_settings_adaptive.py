from types import SimpleNamespace

from utils.backend_verifier import BackendVerifier, SSHClient, VerifyResult
from utils.interface_topology import (
    choose_reassignable_nics,
    extract_physical_nic_names,
    interface_rows_equal,
    split_interface_names,
)


def test_extract_physical_nics_keeps_eth_and_veth_exact():
    text = "VETH1 selected\nETH1 available\nVETH10\nwan2_12\nenp2s0"

    assert extract_physical_nic_names(text) == ["enp2s0", "ETH1", "VETH1", "VETH10"]
    assert split_interface_names("veth1, eth2,veth1") == ["veth1", "eth2"]


def test_choose_reassignable_nics_prefers_down_links_and_retains_one():
    names = ["eth0", "eth1", "eth2"]
    state = {
        "eth0": {"carrier": "0", "state": "DOWN"},
        "eth1": {"carrier": "1", "state": "UP", "flags": ["LOWER_UP"]},
        "eth2": {"carrier": "0", "state": "DOWN"},
    }

    selected = choose_reassignable_nics(names, state, count=5)

    assert selected == ["eth2"]
    assert "eth0" not in selected
    assert "eth1" not in selected
    assert len(selected) == 1


def test_choose_reassignable_nics_retains_first_and_only_live_member():
    names = ["eth0", "eth1"]
    state = {
        "eth0": {"carrier": "0", "state": "DOWN"},
        "eth1": {"carrier": "1", "state": "UP"},
    }

    assert choose_reassignable_nics(names, state, count=2) == []


def test_choose_reassignable_veth_supports_single_safe_reuse():
    names = ["veth1", "veth2"]
    state = {
        "veth1": {"carrier": "1", "state": "UP"},
        "veth2": {"carrier": "1", "state": "UP"},
    }

    assert choose_reassignable_nics(names, state, count=2) == ["veth2"]


def test_topology_prefers_unassigned_veths_and_excludes_backing_eth_alias():
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier.connect_router = lambda: None
    verifier.query_lan_config = lambda: [
        {"tagname": "lan1", "bandeth": "veth1"},
    ]
    verifier.query_wan_config = lambda: [
        {"tagname": "wan1", "bandeth": "veth5"},
        {"tagname": "wan2", "bandeth": "veth4"},
        {"tagname": "wan3", "bandeth": "veth3"},
    ]
    verifier._router = _Router(
        "eth0|up|1|00:11:22:33:44:01|UP,LOWER_UP\n"
        "veth1|up|1|00:11:22:33:44:01|UP,LOWER_UP\n"
        "veth2|up|1|00:11:22:33:44:02|UP,LOWER_UP\n"
        "veth3|up|1|00:11:22:33:44:03|UP,LOWER_UP\n"
        "veth4|up|1|00:11:22:33:44:04|UP,LOWER_UP\n"
        "veth5|up|1|00:11:22:33:44:05|UP,LOWER_UP\n"
        "veth6|up|1|00:11:22:33:44:06|UP,LOWER_UP\n"
    )

    topology = verifier.discover_interface_topology("lan1")

    assert topology["assigned_nics"] == ["veth1", "veth3", "veth4", "veth5"]
    assert topology["unassigned_nics"] == ["veth2", "veth6"]
    assert topology["duplicate_aliases"] == ["eth0"]


def test_select_test_nics_uses_free_nics_without_releasing_management_lan():
    verifier = BackendVerifier.__new__(BackendVerifier)
    topology = {
        "source_bound_nics": ["veth1"],
        "physical": {"veth1": {"carrier": "1", "state": "UP"}},
        "unassigned_nics": ["veth2", "veth6"],
    }
    verifier.discover_interface_topology = lambda source_lan: topology

    plan = verifier.select_test_nics("lan1", count=2)

    assert plan["test_nics"] == ["veth2", "veth6"]
    assert plan["free_nics"] == ["veth2", "veth6"]
    assert plan["released_nics"] == []


def test_interface_rows_equal_does_not_normalize_original_values():
    original = {"internet": "1", "username": "legacy", "passwd": "old"}

    assert interface_rows_equal(original, dict(original))
    assert not interface_rows_equal(original, {**original, "username": ""})


def test_database_field_contains_match_rejects_empty_actual_value():
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier.find_lan = lambda name: {"tagname": name, "ip_mask": ""}
    verifier.find_wan = lambda name: {"tagname": name, "ip_mask": ""}

    lan_result = verifier.verify_lan_database(
        "lan2", expected_fields={"ip_mask": "192.168.200.1"}
    )
    wan_result = verifier.verify_wan_database(
        "wan4", expected_fields={"ip_mask": "10.99.99.2"}
    )

    assert not lan_result.passed
    assert not wan_result.passed
    assert "ip_mask" in lan_result.message
    assert "ip_mask" in wan_result.message


def test_snapshot_restore_does_not_touch_wan_vlan_unless_snapshot_is_supplied():
    verifier = BackendVerifier.__new__(BackendVerifier)
    original = {"id": "2", "tagname": "wan2", "internet": "4"}
    verifier.find_wan = lambda name: dict(original)
    verifier.find_lan = lambda name: None
    verifier.query_hybrid_subif = lambda name: (_ for _ in ()).throw(
        AssertionError("wan_vlan must not be read or rewritten without an explicit snapshot")
    )

    result = verifier.restore_interface_snapshot(
        [("wan_config", "wan2", original)]
    )

    assert result.passed
    assert result.details["wan_vlan_expected_count"] == 0


def test_snapshot_restore_verifies_existing_wan_vlan_rows_exactly():
    verifier = BackendVerifier.__new__(BackendVerifier)
    original = {"id": "2", "tagname": "wan2", "internet": "4"}
    children = [{"id": "7", "interface": "wan2", "vlan_name": "adsl1", "passwd": "old"}]
    verifier.find_wan = lambda name: dict(original)
    verifier.find_lan = lambda name: None
    verifier.query_hybrid_subif = lambda name: [dict(children[0])]

    result = verifier.restore_interface_snapshot(
        [("wan_config", "wan2", original)], wan_vlan_rows=children
    )

    assert result.passed
    assert result.details["wan_vlan_expected_count"] == 1
    assert not result.details["wan_vlan_mismatch"]


class _Router:
    def __init__(self, output):
        self.output = output

    def exec(self, command, *args, **kwargs):
        return self.output


def test_policy_route_uses_actual_lookup_name_not_derived_fwmark():
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = _Router(
        "10000: from all fwmark 0x2713 lookup vwan112\n"
        "10000: from all fwmark 0x2714 lookup wan3\n"
    )
    verifier.connect_router = lambda: None

    result = verifier.verify_wan_policy_routing(3)

    assert result.passed
    assert "0x2714" in result.raw_output
    assert "lookup wan3" in result.raw_output


def test_pppoe_policy_route_accepts_rule_only_when_default_route_is_disabled():
    class Router:
        def exec(self, command, *args, **kwargs):
            if command.startswith("ip rule show"):
                return "10000: from all fwmark 0x2712 lookup wan2\n"
            if command.startswith("ip route show table wan2"):
                return ""
            raise AssertionError(command)

    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = Router()
    verifier.connect_router = lambda: None
    verifier.find_wan = lambda name: {"tagname": name, "default_route": "0"}

    result = verifier.verify_pppoe_policy_route("wan2")

    assert result.passed
    assert "关闭默认路由" in result.message


def test_pppoe_session_discovers_firmware_ad_runtime_alias():
    class Router:
        def exec(self, command, *args, **kwargs):
            if command.startswith("ps w"):
                return (
                    "123 root 3400 S /usr/sbin/pppd linkname wan3_ad "
                    "ifname wan3_ad plugin rp-pppoe.so nic-wan3\n"
                )
            if "addr show dev wan3_ad" in command:
                return "39: wan3_ad inet 10.1.1.47 peer 10.1.1.1/32 scope global wan3_ad"
            raise AssertionError(command)

    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = Router()
    verifier.connect_router = lambda: None

    result = verifier.verify_pppoe_session("wan3")

    assert result.passed
    assert result.details["runtime_interface"] == "wan3_ad"
    assert "wan3_ad" in result.message


def test_pppoe_full_chain_has_five_levels_and_redacts_password():
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier.find_wan = lambda name: {
        "tagname": name,
        "internet": "2",
        "username": "test",
        "passwd": "test",
    }
    verifier.verify_wan_physical_binding = lambda name: VerifyResult("L2", True, "ok")
    verifier.verify_pppoe_session = lambda name: VerifyResult("L3", True, "ok")
    verifier.verify_pppoe_policy_route = lambda name: VerifyResult("L4", True, "ok")
    verifier.verify_wan_reachability = lambda name, host: VerifyResult("L5", True, "ok")

    result = verifier.verify_pppoe_full_chain(
        "wan2", "test", "test", wait_seconds=0
    )

    assert result.all_passed
    assert len(result.results) == 5
    assert [item.level[:2] for item in result.results] == ["L1", "L2", "L3", "L4", "L5"]
    assert '"passwd": "[已隐藏]"' in result.results[0].raw_output
    assert '"passwd": "test"' not in result.results[0].raw_output


class _Transport:
    def is_active(self):
        return True


class _Stream:
    def __init__(self, value=b""):
        self.value = value
        self.channel = self

    def settimeout(self, timeout):
        return None

    def read(self):
        return self.value


class _BrokenParamikoClient:
    def get_transport(self):
        return _Transport()

    def exec_command(self, *args, **kwargs):
        raise AttributeError("'NoneType' object has no attribute 'open_session'")

    def close(self):
        return None


class _HealthyParamikoClient(_BrokenParamikoClient):
    def exec_command(self, *args, **kwargs):
        return None, _Stream(b"reconnected"), _Stream()


def test_ssh_exec_reconnects_after_open_session_attribute_error():
    config = SimpleNamespace(host="router", port=22, username="u", password="p")
    client = SSHClient(config)
    client._client = _BrokenParamikoClient()

    def connect():
        if client._client is None:
            client._client = _HealthyParamikoClient()

    client.connect = connect

    assert client._exec_with_retry("true") == "reconnected"
