"""UDPXY真实功能测试的GUI、命令和报告接线回归。"""

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from config.config import get_config
from gui.main_window import MainWindow
from gui.test_runner import TestRunner
from tests import conftest as project_conftest
from tests.network.test_udp_proxy_functional import _parse_probe_result


UDPXY_COMPREHENSIVE_NODE = (
    "test_udp_proxy_comprehensive.py::"
    "TestUdpProxyComprehensive::test_udp_proxy_comprehensive"
)
UDPXY_FUNCTIONAL_NODE = (
    "test_udp_proxy_functional.py::"
    "TestUdpProxyFunctional::test_udpxy_real_multicast_to_http"
)


def test_gui_udpxy_selection_contains_comprehensive_and_functional_nodes():
    modules = MainWindow._load_test_modules(None)
    udpxy = modules["网络配置"]["children"]["组播管理"]["children"][
        "UDPXY设置"
    ]

    assert udpxy["testcases"] == [
        UDPXY_COMPREHENSIVE_NODE,
        UDPXY_FUNCTIONAL_NODE,
    ]
    assert udpxy["groups"]["综合测试（推荐）"] == [UDPXY_COMPREHENSIVE_NODE]
    assert udpxy["groups"]["真实功能测试"] == [UDPXY_FUNCTIONAL_NODE]


def test_gui_runner_targets_both_udpxy_nodes():
    command = TestRunner(
        [UDPXY_COMPREHENSIVE_NODE, UDPXY_FUNCTIONAL_NODE], get_config()
    )._build_pytest_command()
    normalized = [item.replace("\\", "/") for item in command]

    assert any(
        item.endswith("tests/network/" + UDPXY_COMPREHENSIVE_NODE)
        for item in normalized
    )
    assert any(
        item.endswith("tests/network/" + UDPXY_FUNCTIONAL_NODE)
        for item in normalized
    )


def test_udpxy_functional_report_name_is_chinese():
    assert project_conftest._get_chinese_test_name(
        "test_udpxy_real_multicast_to_http[chromium]"
    ) == "UDPXY真实组播转HTTP功能测试"


def test_http_probe_result_contract():
    payload = json.dumps(
        {
            "connected": True,
            "http_status": "HTTP/1.0 200 OK",
            "received": True,
            "token_count": 3,
            "bytes": 4096,
            "source_ip": "192.168.148.2",
            "target": "192.168.148.1",
            "proxy_port": 47001,
            "group": "239.148.66.46",
            "stream_port": 46246,
            "token": "TOKEN",
            "error": "",
        }
    )
    assert _parse_probe_result(payload)["token_count"] == 3
