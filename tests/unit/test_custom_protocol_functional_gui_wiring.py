"""自定义协议真实功能测试的 GUI 接线回归。"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from config.config import get_config
from gui.main_window import MainWindow
from gui.test_runner import TestRunner as GuiTestRunner
from tests import conftest as project_conftest


CUSTOM_PROTOCOL_COMPREHENSIVE_NODE = (
    "test_custom_protocol_comprehensive.py::"
    "TestCustomProtocolComprehensive::test_custom_protocol_comprehensive"
)
CUSTOM_PROTOCOL_FUNCTIONAL_NODE = (
    "test_custom_protocol_functional.py::"
    "TestCustomProtocolFunctional::test_custom_protocol_real_tcp_flow"
)
ADVANCED_CUSTOM_PROTOCOL_COMPREHENSIVE_NODE = (
    "test_custom_protocol_comprehensive.py::"
    "TestAdvancedCustomProtocolComprehensive::test_advanced_custom_protocol_comprehensive"
)
ADVANCED_CUSTOM_PROTOCOL_FUNCTIONAL_NODE = (
    "test_custom_protocol_functional.py::"
    "TestAdvancedCustomProtocolFunctional::test_advanced_custom_protocol_real_l7_flow"
)


def _custom_protocol_leaf():
    modules = MainWindow._load_test_modules(None)
    return modules["网络配置"]["children"]["自定义协议"]["children"]["自定义协议"]


def _advanced_custom_protocol_leaf():
    modules = MainWindow._load_test_modules(None)
    return modules["网络配置"]["children"]["自定义协议"]["children"]["高级自定义协议"]


def test_custom_protocol_selection_contains_two_scripts():
    leaf = _custom_protocol_leaf()

    assert leaf["testcases"] == [
        CUSTOM_PROTOCOL_COMPREHENSIVE_NODE,
        CUSTOM_PROTOCOL_FUNCTIONAL_NODE,
    ]
    assert leaf["groups"]["综合测试（推荐）"] == [
        CUSTOM_PROTOCOL_COMPREHENSIVE_NODE,
    ]
    assert leaf["groups"]["真实功能测试"] == [
        CUSTOM_PROTOCOL_FUNCTIONAL_NODE,
    ]


def test_custom_protocol_runner_targets_both_scripts():
    command = GuiTestRunner(
        [CUSTOM_PROTOCOL_COMPREHENSIVE_NODE, CUSTOM_PROTOCOL_FUNCTIONAL_NODE],
        get_config(),
    )._build_pytest_command()
    normalized = [item.replace("\\", "/") for item in command]

    assert any(
        item.endswith("tests/network/" + CUSTOM_PROTOCOL_COMPREHENSIVE_NODE)
        for item in normalized
    )
    assert any(
        item.endswith("tests/network/" + CUSTOM_PROTOCOL_FUNCTIONAL_NODE)
        for item in normalized
    )


def test_checking_custom_protocol_visibly_lists_two_scripts():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        network = next(
            window.module_tree.topLevelItem(index)
            for index in range(window.module_tree.topLevelItemCount())
            if window.module_tree.topLevelItem(index).text(0) == "网络配置"
        )
        custom_protocol_group = next(
            network.child(index)
            for index in range(network.childCount())
            if network.child(index).text(0) == "自定义协议"
        )
        custom_protocol = next(
            custom_protocol_group.child(index)
            for index in range(custom_protocol_group.childCount())
            if custom_protocol_group.child(index).text(0) == "自定义协议"
        )

        custom_protocol.setCheckState(0, Qt.Checked)
        app.processEvents()

        visible_scripts = [
            window.testcase_list.item(index).text()
            for index in range(window.testcase_list.count())
        ]
        assert visible_scripts == [
            CUSTOM_PROTOCOL_COMPREHENSIVE_NODE,
            CUSTOM_PROTOCOL_FUNCTIONAL_NODE,
        ]
        assert window.testcase_count_label.text() == "已选: 2"
    finally:
        window.close()


def test_custom_protocol_functional_report_name_is_chinese():
    assert project_conftest._get_chinese_test_name(
        "test_custom_protocol_real_tcp_flow[chromium]"
    ) == "自定义协议功能验证(真实TCP流量命中)"


def test_advanced_custom_protocol_selection_contains_two_scripts():
    leaf = _advanced_custom_protocol_leaf()

    assert leaf["testcases"] == [
        ADVANCED_CUSTOM_PROTOCOL_COMPREHENSIVE_NODE,
        ADVANCED_CUSTOM_PROTOCOL_FUNCTIONAL_NODE,
    ]
    assert leaf["groups"]["综合测试（推荐）"] == [
        ADVANCED_CUSTOM_PROTOCOL_COMPREHENSIVE_NODE,
    ]
    assert leaf["groups"]["真实功能测试"] == [
        ADVANCED_CUSTOM_PROTOCOL_FUNCTIONAL_NODE,
    ]


def test_advanced_custom_protocol_runner_targets_both_scripts():
    command = GuiTestRunner(
        [
            ADVANCED_CUSTOM_PROTOCOL_COMPREHENSIVE_NODE,
            ADVANCED_CUSTOM_PROTOCOL_FUNCTIONAL_NODE,
        ],
        get_config(),
    )._build_pytest_command()
    normalized = [item.replace("\\", "/") for item in command]

    assert any(
        item.endswith("tests/network/" + ADVANCED_CUSTOM_PROTOCOL_COMPREHENSIVE_NODE)
        for item in normalized
    )
    assert any(
        item.endswith("tests/network/" + ADVANCED_CUSTOM_PROTOCOL_FUNCTIONAL_NODE)
        for item in normalized
    )


def test_checking_advanced_custom_protocol_visibly_lists_two_scripts():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        network = next(
            window.module_tree.topLevelItem(index)
            for index in range(window.module_tree.topLevelItemCount())
            if window.module_tree.topLevelItem(index).text(0) == "网络配置"
        )
        custom_protocol_group = next(
            network.child(index)
            for index in range(network.childCount())
            if network.child(index).text(0) == "自定义协议"
        )
        advanced_custom_protocol = next(
            custom_protocol_group.child(index)
            for index in range(custom_protocol_group.childCount())
            if custom_protocol_group.child(index).text(0) == "高级自定义协议"
        )

        advanced_custom_protocol.setCheckState(0, Qt.Checked)
        app.processEvents()

        visible_scripts = [
            window.testcase_list.item(index).text()
            for index in range(window.testcase_list.count())
        ]
        assert visible_scripts == [
            ADVANCED_CUSTOM_PROTOCOL_COMPREHENSIVE_NODE,
            ADVANCED_CUSTOM_PROTOCOL_FUNCTIONAL_NODE,
        ]
        assert window.testcase_count_label.text() == "已选: 2"
    finally:
        window.close()


def test_advanced_custom_protocol_functional_report_name_is_chinese():
    assert project_conftest._get_chinese_test_name(
        "test_advanced_custom_protocol_real_l7_flow[chromium]"
    ) == "高级自定义协议功能验证(真实L7载荷命中)"
