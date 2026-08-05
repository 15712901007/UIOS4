"""Cross-layer functional-test GUI, command, and report wiring regression."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from config.config import get_config
from gui.main_window import MainWindow
from gui.test_runner import TestRunner
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from tests import conftest as project_conftest
from tests.network.test_cross_layer_service_functional import (
    _capture_summary,
    _normalize_mac,
    _snmp_mac_for_ip,
)


CROSS_LAYER_COMPREHENSIVE_NODE = (
    "test_cross_layer_service_comprehensive.py::"
    "TestCrossLayerServiceComprehensive::test_cross_layer_service_comprehensive"
)
CROSS_LAYER_FUNCTIONAL_NODE = (
    "test_cross_layer_service_functional.py::"
    "TestCrossLayerServiceFunctional::"
    "test_cross_layer_service_real_snmp_mac_learning"
)


def test_gui_cross_layer_selection_contains_both_nodes():
    modules = MainWindow._load_test_modules(None)
    cross_layer = modules["网络配置"]["children"]["跨三层服务"]

    assert cross_layer["testcases"] == [
        CROSS_LAYER_COMPREHENSIVE_NODE,
        CROSS_LAYER_FUNCTIONAL_NODE,
    ]
    assert cross_layer["groups"]["综合测试（推荐）"] == [
        CROSS_LAYER_COMPREHENSIVE_NODE
    ]
    assert cross_layer["groups"]["真实功能测试"] == [
        CROSS_LAYER_FUNCTIONAL_NODE
    ]


def test_gui_runner_targets_both_cross_layer_nodes():
    command = TestRunner(
        [CROSS_LAYER_COMPREHENSIVE_NODE, CROSS_LAYER_FUNCTIONAL_NODE],
        get_config(),
    )._build_pytest_command()
    normalized = [item.replace("\\", "/") for item in command]

    assert any(
        item.endswith("tests/network/" + CROSS_LAYER_COMPREHENSIVE_NODE)
        for item in normalized
    )
    assert any(
        item.endswith("tests/network/" + CROSS_LAYER_FUNCTIONAL_NODE)
        for item in normalized
    )


def test_checking_cross_layer_visibly_lists_two_scripts():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        network = next(
            window.module_tree.topLevelItem(index)
            for index in range(window.module_tree.topLevelItemCount())
            if window.module_tree.topLevelItem(index).text(0) == "网络配置"
        )
        cross_layer = next(
            network.child(index)
            for index in range(network.childCount())
            if network.child(index).text(0) == "跨三层服务"
        )

        cross_layer.setCheckState(0, Qt.Checked)
        app.processEvents()

        visible_scripts = [
            window.testcase_list.item(index).text()
            for index in range(window.testcase_list.count())
        ]
        assert visible_scripts == [
            CROSS_LAYER_COMPREHENSIVE_NODE,
            CROSS_LAYER_FUNCTIONAL_NODE,
        ]
        assert window.testcase_count_label.text() == "已选: 2"
    finally:
        window.close()


def test_cross_layer_functional_report_name_is_chinese():
    assert project_conftest._get_chinese_test_name(
        "test_cross_layer_service_real_snmp_mac_learning[chromium]"
    ) == "跨三层服务真实SNMP MAC学习功能测试"


def test_snmp_mac_parser_normalizes_net_snmp_output():
    output = (
        ".1.3.6.1.2.1.4.22.1.2.49.192.168.148.2 = "
        "STRING: d4:20:0:b1:45:ec\n"
    )
    assert _snmp_mac_for_ip(output, "192.168.148.2") == (
        "d4:20:00:b1:45:ec"
    )
    assert _normalize_mac("D4 20 00 B1 45 EC") == "d4:20:00:b1:45:ec"


def test_capture_summary_keeps_snmp_endpoints_and_counters():
    output = (
        "IP 10.66.0.9.40000 > 10.66.0.57.4161: UDP, length 48\n"
        "IP 10.66.0.57.4161 > 10.66.0.9.40000: UDP, length 96\n"
        "4 packets captured\n"
    )
    summary = _capture_summary(output, "10.66.0.57", 4161)
    assert "10.66.0.57.4161" in summary
    assert "packets captured" in summary
