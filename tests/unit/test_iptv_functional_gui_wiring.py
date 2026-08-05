"""IPTV真实透传测试的GUI、报告和抓包契约回归。"""

import copy
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from config.config import get_config
from gui.main_window import MainWindow
from gui.test_runner import TestRunner
from tests import conftest as project_conftest
from tests.network.test_iptv_functional import (
    DEFAULT_DUT_INPUT,
    DEFAULT_INPUT_PORT,
    DEFAULT_RECEIVER_HOST,
    DEFAULT_RECEIVER_PARENT,
    DEFAULT_SOURCE_HOST,
    DEFAULT_SOURCE_PARENT,
    _expected_dut_management_ip,
    _single_bridge_member,
    _capture_contract,
    _capture_summary,
    _parse_probe_result,
)


IPTV_COMPREHENSIVE_NODE = (
    "test_iptv_comprehensive.py::"
    "TestIptvComprehensive::test_iptv_comprehensive"
)
IPTV_FUNCTIONAL_NODE = (
    "test_iptv_functional.py::"
    "TestIptvFunctional::test_iptv_real_passthrough"
)


def test_gui_iptv_selection_contains_comprehensive_and_functional_nodes():
    modules = MainWindow._load_test_modules(None)
    iptv = modules["网络配置"]["children"]["组播管理"]["children"]["IPTV透传"]

    assert iptv["testcases"] == [IPTV_COMPREHENSIVE_NODE, IPTV_FUNCTIONAL_NODE]
    assert iptv["groups"]["综合测试（推荐）"] == [IPTV_COMPREHENSIVE_NODE]
    assert iptv["groups"]["真实功能测试"] == [IPTV_FUNCTIONAL_NODE]


def test_gui_runner_targets_both_iptv_nodes():
    command = TestRunner(
        [IPTV_COMPREHENSIVE_NODE, IPTV_FUNCTIONAL_NODE], get_config()
    )._build_pytest_command()
    normalized = [item.replace("\\", "/") for item in command]

    assert any(
        item.endswith("tests/network/" + IPTV_COMPREHENSIVE_NODE)
        for item in normalized
    )
    assert any(
        item.endswith("tests/network/" + IPTV_FUNCTIONAL_NODE)
        for item in normalized
    )


def test_gui_runner_exports_selected_device_as_iptv_dut(monkeypatch):
    config = copy.deepcopy(get_config())
    config.device.ip = "10.66.0.150"
    runner = TestRunner([IPTV_FUNCTIONAL_NODE], config)

    monkeypatch.delenv("IPTV_DUT_MANAGEMENT_IP", raising=False)
    runner._setup_env_variables()

    assert os.environ["DEVICE_IP"] == "10.66.0.150"
    assert os.environ["SSH_ROUTER_HOST"] == "10.66.0.150"
    assert os.environ["IPTV_DUT_MANAGEMENT_IP"] == "10.66.0.150"


def test_iptv_functional_report_name_is_chinese():
    assert project_conftest._get_chinese_test_name(
        "test_iptv_real_passthrough[chromium]"
    ) == "IPTV网口与VLAN真实透传功能测试"


def test_iptv_functional_defaults_use_single_trunk_host_and_wan1_input():
    assert DEFAULT_SOURCE_HOST == DEFAULT_RECEIVER_HOST == "10.66.0.57"
    assert DEFAULT_SOURCE_PARENT == DEFAULT_RECEIVER_PARENT == "enp6s0"
    assert DEFAULT_INPUT_PORT == "veth5(wan1)"
    assert DEFAULT_DUT_INPUT == "veth5"


def test_iptv_functional_dut_target_requires_explicit_override(monkeypatch):
    monkeypatch.delenv("IPTV_DUT_MANAGEMENT_IP", raising=False)
    assert _expected_dut_management_ip() == "10.66.0.45"

    monkeypatch.setenv("IPTV_DUT_MANAGEMENT_IP", "10.66.0.150")
    assert _expected_dut_management_ip() == "10.66.0.150"


def test_iptv_functional_resolves_native_or_veth_bridge_member():
    assert _single_bridge_member("veth5\n", "wan1") == "veth5"
    assert _single_bridge_member("eth3\n", "wan3") == "eth3"


def test_receiver_result_and_capture_contracts():
    payload = json.dumps(
        {
            "received": True,
            "packets": 3,
            "sources": ["198.18.45.2"],
            "samples": ["TOKEN|sequence=0"],
            "group": "239.148.66.47",
            "port": 46347,
            "token": "TOKEN",
            "error": "",
        }
    )
    assert _parse_probe_result(payload)["packets"] == 3

    port_captures = {
        "veth5": "vlan 100 TOKEN",
        "veth5.100": "TOKEN",
        "veth3": "TOKEN",
    }
    assert _capture_contract("port", port_captures, "TOKEN")[0]

    vlan_captures = {
        "veth5": "vlan 100 TOKEN",
        "veth5.100": "TOKEN",
        "veth3": "802.1Q vlan 200 TOKEN",
        "veth3.200": "TOKEN",
    }
    assert _capture_contract("vlan", vlan_captures, "TOKEN")[0]
    assert "vlan 200" in _capture_summary(vlan_captures["veth3"], "TOKEN")
