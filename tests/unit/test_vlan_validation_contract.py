from __future__ import annotations

from pathlib import Path

from tests.network.test_vlan_comprehensive import (
    _assert_export_matches,
    _expected_vlan_fields,
    _read_vlan_export,
)
from utils.backend_verifier import BackendVerifier
from utils.replay_commands import build_verification_commands


class _FakeSSH:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.commands = []

    def exec(self, command, timeout=30):
        self.commands.append(command)
        response = self.responses.get(command, "")
        return response(command) if callable(response) else response


def _backend(router=None, client=None):
    backend = object.__new__(BackendVerifier)
    backend._router = router
    backend._client = client
    backend.connect_router = lambda: None
    backend.connect_client = lambda: None
    return backend


def test_expected_vlan_fields_covers_every_persisted_input():
    vlan = {
        "id": "106",
        "name": "vlan_complete",
        "line": "lan1",
        "mac": "00:11:22:33:44:06",
        "ip": "192.168.106.1",
        "subnet": "255.255.255.0",
        "remark": "完整信息测试",
        "ext_ip": "192.168.106.2",
    }
    assert _expected_vlan_fields(vlan) == {
        "enabled": "yes",
        "tagname": "vlan_complete",
        "vlan_name": "vlan_complete",
        "vlan_id": "106",
        "interface": "lan1",
        "mac": "00:11:22:33:44:06",
        "ip_addr": "192.168.106.1",
        "netmask": "255.255.255.0",
        "ip_mask": "192.168.106.2/255.255.255.0",
        "comment": "完整信息测试",
    }


def test_database_absence_never_treats_bad_json_as_empty():
    command = "/usr/ikuai/function/vlan show limit=0,500 TYPE=total,data"
    backend = _backend(router=_FakeSSH({command: "not-json"}))
    result = backend.verify_vlan_database_absent("vlan_test")
    assert not result.passed
    assert "无法确认" in result.message


def test_database_absence_reports_an_exact_residual():
    command = "/usr/ikuai/function/vlan show limit=0,500 TYPE=total,data"
    backend = _backend(router=_FakeSSH({
        command: '{"data":[{"tagname":"vlan_test","vlan_id":"100"}]}'
    }))
    result = backend.verify_vlan_database_absent("vlan_test")
    assert not result.passed
    assert result.details["rules"][0]["vlan_id"] == "100"


def test_proc_verifier_uses_exact_name_id_and_parent():
    proc = (
        "VLAN Dev name | VLAN ID | Bind Dev\n"
        "vlan_test_more | 101 | lan2\n"
        "vlan_test | 100 | lan1\n"
    )
    backend = _backend(router=_FakeSSH({"cat /proc/net/vlan/config 2>/dev/null": proc}))
    result = backend.verify_vlan_proc(
        "vlan_test", expected_vlan_id="100", expected_parent="lan1"
    )
    assert result.passed
    assert result.details["line"] == "vlan_test | 100 | lan1"

    mismatch = backend.verify_vlan_proc(
        "vlan_test", expected_vlan_id="100", expected_parent="lan2"
    )
    assert not mismatch.passed
    assert "父接口" in mismatch.message


def test_interface_verifier_requires_data_link_bridge_and_parent_up():
    data_link = (
        "22: _vlan_test@lan1: <BROADCAST,MULTICAST,UP,LOWER_UP> "
        "mtu 1492 state UP mode DEFAULT"
    )
    bridge_down = (
        "23: vlan_test: <BROADCAST,MULTICAST> mtu 1492 state DOWN mode DEFAULT"
    )
    backend = _backend(router=_FakeSSH({
        "ip link show _vlan_test 2>/dev/null": data_link,
        "ip link show vlan_test 2>/dev/null": bridge_down,
    }))
    result = backend.verify_vlan_interface("vlan_test", expected_parent="lan1")
    assert not result.passed
    assert "bridge未UP" in result.message


def test_disabled_interface_requires_explicit_down_and_correct_parent():
    down_link = (
        "22: _vlan_test@lan1: <BROADCAST,MULTICAST> "
        "mtu 1492 state DOWN mode DEFAULT"
    )
    unknown_link = (
        "22: _vlan_test@lan1: <BROADCAST,MULTICAST> "
        "mtu 1492 state UNKNOWN mode DEFAULT"
    )
    bridge_down = "23: vlan_test: <BROADCAST,MULTICAST> mtu 1492 state DOWN"
    router = _FakeSSH({
        "ip link show _vlan_test 2>/dev/null": down_link,
        "ip link show vlan_test 2>/dev/null": bridge_down,
    })
    backend = _backend(router=router)
    result = backend.verify_vlan_interface(
        "vlan_test", expected_state="DOWN", expected_parent="lan1"
    )
    assert result.passed

    wrong_parent = backend.verify_vlan_interface(
        "vlan_test", expected_state="DOWN", expected_parent="lan2"
    )
    assert not wrong_parent.passed
    assert "父接口" in wrong_parent.message

    router.responses["ip link show _vlan_test 2>/dev/null"] = unknown_link
    unknown = backend.verify_vlan_interface(
        "vlan_test", expected_state="DOWN", expected_parent="lan1"
    )
    assert not unknown.passed
    assert "未明确DOWN" in unknown.message


def test_client_qinq_verifier_checks_parent_vid_and_ip():
    iface = "ens11.54.55"
    backend = _backend(client=_FakeSSH({
        f"ip -d -o link show dev {iface} 2>/dev/null": (
            "31: ens11.54.55@ens11.54: <BROADCAST,MULTICAST,UP,LOWER_UP> "
            "mtu 1500 state UP vlan protocol 802.1Q id 55"
        ),
        f"ip -o -4 addr show dev {iface} 2>/dev/null": (
            "31: ens11.54.55 inet 192.168.155.100/24 scope global ens11.54.55"
        ),
    }))
    result = backend.verify_client_vlan_subinterface(
        iface, 55, "ens11.54", "192.168.155.100/24"
    )
    assert result.passed


def test_vlan_report_commands_are_structured_and_copy_ready():
    backend = _backend()
    commands = build_verification_commands(
        backend,
        backend.verify_vlan_database_absent,
        args=("vlan_test",),
    )
    assert commands
    assert all(item["copy_ready"] for item in commands)
    assert all(item["target"] == "router" for item in commands)
    assert "/usr/ikuai/function/vlan show" in commands[0]["command"]


def test_disabled_vlan_report_command_expects_down():
    backend = _backend()
    commands = build_verification_commands(
        backend,
        backend.verify_vlan_interface,
        args=("vlan_test",),
        kwargs={"expected_state": "DOWN", "expected_parent": "lan1"},
    )
    assert commands
    assert all("DOWN" in item["expected"] for item in commands)


def test_csv_and_txt_exports_are_parsed_and_compared(tmp_path: Path):
    expected = [{
        "id": "104", "name": "vlan_remark", "mac": "00:11:22:33:44:04",
        "ip": "192.168.104.1", "subnet": "255.255.255.0",
        "remark": "测试备注",
    }]
    csv_path = tmp_path / "vlan.csv"
    csv_path.write_text(
        "id,enabled,comment,vlan_id,vlan_name,mac,ip_addr,netmask,ip_mask,interface\n"
        '1,"yes","测试备注","104","vlan_remark","00:11:22:33:44:04",'
        '"192.168.104.1","255.255.255.0","","lan1"\n',
        encoding="utf-8",
    )
    txt_path = tmp_path / "vlan.txt"
    txt_path.write_text(
        "id=1 enabled=yes comment=测试备注 vlan_id=104 vlan_name=vlan_remark "
        "mac=00:11:22:33:44:04 ip_addr=192.168.104.1 "
        "netmask=255.255.255.0 ip_mask= interface=lan1\n",
        encoding="utf-8",
    )
    assert _read_vlan_export(str(csv_path))[0]["comment"] == "测试备注"
    assert _read_vlan_export(str(txt_path))[0]["vlan_name"] == "vlan_remark"
    _assert_export_matches(str(csv_path), expected)
    _assert_export_matches(str(txt_path), expected)


def test_comprehensive_flow_has_no_soft_vlan_backend_checks():
    source = Path("tests/network/test_vlan_comprehensive.py").read_text(encoding="utf-8")
    assert "must_pass=False" not in source
    assert "verify_vlan_disabled(vlan, \"批量停用\")" in source
    assert "verify_vlan_absent(delete_vlan[\"name\"], \"单条删除\")" in source
    assert "count_after_delete == count_before_delete - 1" in source
    assert "_assert_export_matches(export_file_csv, test_vlans)" in source
    disabled_block = source.split("def verify_vlan_disabled", 1)[1].split(
        "def verify_vlan_absent", 1
    )[0]
    assert "verify_vlan_interface_absent" not in disabled_block
    assert "verify_vlan_proc_absent" not in disabled_block
    assert 'expected_state="DOWN"' in disabled_block


def test_vlan_page_validation_uses_exact_table_rows():
    source = Path("pages/network/vlan_page.py").read_text(encoding="utf-8")
    assert "def _find_vlan_row" in source
    assert 'div.ant-table-cell#vlan_name' in source
    assert "== vlan_name" in source
    vlan_aliases = source.split("# ==================== 向后兼容别名", 1)[1]
    assert "return self.rule_exists(vlan_name)" in vlan_aliases
    assert "def edit_vlan(self, vlan_name: str) -> bool" in vlan_aliases


def test_vlan_form_selectors_do_not_silently_skip_masks_or_extended_ip():
    source = Path("pages/network/vlan_page.py").read_text(encoding="utf-8")
    assert '_select_combobox_value_by_id("netmask", mask)' in source
    assert "input[id^='ip_mask_'][id$='_ipAddress']" in source
    assert 'input_id.replace("_ipAddress", "_netmask")' in source
    assert "未能选中掩码" not in source
    assert 'not result["has_validation_error"] and not form_still_open' in source
    assert 'page.locator("dialog, [role=\'dialog\']")' not in source
