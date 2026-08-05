"""UPnP真实功能测试的GUI与中文报告接线回归。"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from config.config import get_config
from gui.main_window import MainWindow
from gui.test_runner import TestRunner
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from tests import conftest as project_conftest
from tests.network.test_upnp_functional import _reports_disconnected_igd


UPNP_COMPREHENSIVE_NODE = (
    "test_upnp_setting_comprehensive.py::"
    "TestUpnpSettingComprehensive::test_upnp_setting_comprehensive"
)
UPNP_FUNCTIONAL_NODE = (
    "test_upnp_functional.py::"
    "TestUpnpFunctional::test_upnp_real_port_mapping"
)


def test_gui_upnp_selection_contains_comprehensive_and_functional_nodes():
    modules = MainWindow._load_test_modules(None)
    upnp = modules["网络配置"]["children"]["UPnP/NAT"]["children"]["UPnP设置"]

    assert upnp["testcases"] == [
        UPNP_COMPREHENSIVE_NODE,
        UPNP_FUNCTIONAL_NODE,
    ]
    assert upnp["groups"]["综合测试（推荐）"] == [UPNP_COMPREHENSIVE_NODE]
    assert upnp["groups"]["真实功能测试"] == [UPNP_FUNCTIONAL_NODE]


def test_gui_runner_targets_both_upnp_nodes():
    command = TestRunner(
        [UPNP_COMPREHENSIVE_NODE, UPNP_FUNCTIONAL_NODE], get_config()
    )._build_pytest_command()
    normalized = [item.replace("\\", "/") for item in command]

    assert any(
        item.endswith("tests/network/" + UPNP_COMPREHENSIVE_NODE)
        for item in normalized
    )
    assert any(
        item.endswith("tests/network/" + UPNP_FUNCTIONAL_NODE)
        for item in normalized
    )


def test_checking_upnp_setting_visibly_lists_two_scripts():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        network = next(
            window.module_tree.topLevelItem(index)
            for index in range(window.module_tree.topLevelItemCount())
            if window.module_tree.topLevelItem(index).text(0) == "网络配置"
        )
        upnp_nat = next(
            network.child(index)
            for index in range(network.childCount())
            if network.child(index).text(0) == "UPnP/NAT"
        )
        upnp_setting = next(
            upnp_nat.child(index)
            for index in range(upnp_nat.childCount())
            if upnp_nat.child(index).text(0) == "UPnP设置"
        )

        upnp_setting.setCheckState(0, Qt.Checked)
        app.processEvents()

        visible_scripts = [
            window.testcase_list.item(index).text()
            for index in range(window.testcase_list.count())
        ]
        assert visible_scripts == [UPNP_COMPREHENSIVE_NODE, UPNP_FUNCTIONAL_NODE]
        assert window.testcase_count_label.text() == "已选: 2"
    finally:
        window.close()


def test_upnp_functional_report_name_is_chinese():
    assert project_conftest._get_chinese_test_name(
        "test_upnp_real_port_mapping[chromium]"
    ) == "UPnP真实端口映射功能测试"


def test_miniupnpc_disconnected_outputs_are_recognized():
    assert _reports_disconnected_igd(
        "No valid UPNP Internet Gateway Device found.\n"
        "Found a (not connected?) IGD : http://192.168.148.1:1900/ctl/IPConn"
    )
    assert _reports_disconnected_igd("Status : Disconnected, uptime=123s")
    assert not _reports_disconnected_igd("Status : Connected, uptime=123s")
