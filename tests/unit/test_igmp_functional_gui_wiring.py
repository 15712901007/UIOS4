"""IGMP真实组播功能测试的GUI、命令和报告接线回归。"""

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from config.config import get_config
from gui.main_window import MainWindow
from gui.test_runner import TestRunner
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from tests import conftest as project_conftest
from tests.network.test_igmp_proxy_functional import (
    _capture_summary,
    _parse_probe_result,
)


IGMP_COMPREHENSIVE_NODE = (
    "test_igmp_proxy_comprehensive.py::"
    "TestIgmpProxyComprehensive::test_igmp_proxy_comprehensive"
)
IGMP_FUNCTIONAL_NODE = (
    "test_igmp_proxy_functional.py::"
    "TestIgmpProxyFunctional::test_igmp_proxy_real_multicast"
)


def test_gui_igmp_selection_contains_comprehensive_and_functional_nodes():
    modules = MainWindow._load_test_modules(None)
    igmp = modules["网络配置"]["children"]["组播管理"]["children"]["IGMP代理"]

    assert igmp["testcases"] == [IGMP_COMPREHENSIVE_NODE, IGMP_FUNCTIONAL_NODE]
    assert igmp["groups"]["综合测试（推荐）"] == [IGMP_COMPREHENSIVE_NODE]
    assert igmp["groups"]["真实功能测试"] == [IGMP_FUNCTIONAL_NODE]


def test_gui_runner_targets_both_igmp_nodes():
    command = TestRunner(
        [IGMP_COMPREHENSIVE_NODE, IGMP_FUNCTIONAL_NODE], get_config()
    )._build_pytest_command()
    normalized = [item.replace("\\", "/") for item in command]

    assert any(
        item.endswith("tests/network/" + IGMP_COMPREHENSIVE_NODE)
        for item in normalized
    )
    assert any(
        item.endswith("tests/network/" + IGMP_FUNCTIONAL_NODE)
        for item in normalized
    )


def test_checking_igmp_proxy_visibly_lists_two_scripts():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        network = next(
            window.module_tree.topLevelItem(index)
            for index in range(window.module_tree.topLevelItemCount())
            if window.module_tree.topLevelItem(index).text(0) == "网络配置"
        )
        multicast = next(
            network.child(index)
            for index in range(network.childCount())
            if network.child(index).text(0) == "组播管理"
        )
        igmp = next(
            multicast.child(index)
            for index in range(multicast.childCount())
            if multicast.child(index).text(0) == "IGMP代理"
        )

        igmp.setCheckState(0, Qt.Checked)
        app.processEvents()

        visible_scripts = [
            window.testcase_list.item(index).text()
            for index in range(window.testcase_list.count())
        ]
        assert visible_scripts == [IGMP_COMPREHENSIVE_NODE, IGMP_FUNCTIONAL_NODE]
        assert window.testcase_count_label.text() == "已选: 2"
    finally:
        window.close()


def test_igmp_functional_report_name_is_chinese():
    assert project_conftest._get_chinese_test_name(
        "test_igmp_proxy_real_multicast[chromium]"
    ) == "IGMP代理真实组播功能测试"


def test_receiver_result_contract_and_capture_summary():
    payload = json.dumps(
        {
            "received": True,
            "packets": 3,
            "sources": ["10.66.0.57"],
            "samples": ["TOKEN|sequence=0"],
            "group": "239.148.66.45",
            "port": 46145,
            "token": "TOKEN",
        }
    )
    assert _parse_probe_result(payload)["packets"] == 3

    capture = (
        "lan1 In IP igmp v3 report\n"
        "wan1 In IP 10.66.0.57 > 239.148.66.45.46145\n"
        "TOKEN|sequence=0\n"
        "4 packets captured\n"
    )
    summary = _capture_summary(capture, "TOKEN")
    assert "igmp v3 report" in summary
    assert "TOKEN|sequence=0" in summary
    assert "packets captured" in summary
