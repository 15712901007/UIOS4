from __future__ import annotations

import json
from types import SimpleNamespace

from pages.security.threat_intelligence_page import ThreatIntelligencePage


def _page_with_probe(raw):
    """Build a no-browser page object for the report-boundary tests."""
    page = object.__new__(ThreatIntelligencePage)
    page.page = SimpleNamespace(
        url="http://192.0.2.10/login#/securityCenter/threatIntelligence?ioc=secret-value",
        evaluate=lambda _script: raw,
    )
    page.feature_state = lambda: {
        "state": "disabled",
        "enabled": False,
        "control_present": True,
        "evidence": "switch",
    }
    page._current_route_key = lambda: "threatMonitoring"
    return page


def test_page_structure_drops_dynamic_dom_text_and_url():
    raw = {
        "tabs": ["威胁监控", "evil.example/path"],
        "buttons": ["搜索", "删除 evil.example/hash=abc123"],
        "inputs": ["请输入 IOC 值", "user-provided-domain.example"],
        "headers": ["告警时间", "IOC abc123 sha256 deadbeef"],
        "switches": [{"checked": False}],
        "charts": 2,
        "main_text": (
            "活跃威胁 evil.example/path IOC=198.51.100.8 "
            "MAC=aa:bb:cc:dd:ee:ff log-body secret-token sha256=deadbeef"
        ),
    }

    result = _page_with_probe(raw).page_structure()
    serialized = json.dumps(result, ensure_ascii=False)

    assert "evil.example" not in serialized
    assert "secret-token" not in serialized
    assert "deadbeef" not in serialized
    assert "198.51.100.8" not in serialized
    assert "aa:bb:cc:dd:ee:ff" not in serialized
    assert result["url"] == "threat_intelligence"
    assert "活跃威胁" in result["main_text"]
    assert "告警时间" in result["headers"]
    assert "搜索" in result["buttons"]


def test_semantic_extractor_does_not_treat_input_id_as_ip_label():
    assert ThreatIntelligencePage._semantic_labels_from_text("input") == []
    assert ThreatIntelligencePage._semantic_labels_from_text("请输入 IP 地址") == [
        "请输入",
        "IP",
    ]


def test_page_structure_keeps_safe_generic_control_kind_only():
    raw = {
        "tabs": [],
        "buttons": [],
        "inputs": ["user-secret-domain.example", "textarea"],
        "headers": [],
        "switches": [],
        "charts": 0,
        "main_text": "user-secret-domain.example raw log body",
    }

    result = _page_with_probe(raw).page_structure()

    assert result["inputs"] == ["input", "textarea"]
    assert result["main_text"] == "input | textarea"


def test_page_structure_keeps_labels_required_by_comprehensive_checks():
    raw = {
        "tabs": ["威胁态势", "命中告警", "黑名单管理", "白名单管理", "外界日志中心"],
        "buttons": ["连接测试"],
        "inputs": [],
        "headers": ["告警时间", "等级", "告警信息", "状态", "情报类型", "监测", "阻断", "记录日志"],
        "switches": [],
        "charts": 4,
        "main_text": (
            "今日 7天 活跃威胁 威胁对象 黑名单管理 白名单管理 "
            "Syslog 日志服务器"
        ),
    }

    result = _page_with_probe(raw).page_structure()

    assert all(label in result["main_text"] for label in (
        "今日", "7天", "活跃威胁", "威胁对象", "黑名单管理",
        "白名单管理", "Syslog", "日志服务器",
    ))
    assert all(label in result["headers"] for label in (
        "告警时间", "等级", "告警信息", "状态",
        "情报类型", "监测", "阻断", "记录日志",
    ))


class _EmptyLocator:
    def locator(self, _selector):
        return self

    def filter(self, **_kwargs):
        return self

    def count(self):
        return 0

    def evaluate(self, _script, _arg):
        # Simulate a DOM event firing without any selected-state read-back.
        return True


def test_disabled_landing_is_not_misreported_as_active_situation_tab():
    page = object.__new__(ThreatIntelligencePage)
    page.page = SimpleNamespace(
        url="http://192.0.2.10/login#/securityCenter/threatIntelligence"
    )
    page._main_scope = lambda: _EmptyLocator()

    assert page.is_tab_active("threatSituation") is False


def test_dom_click_without_selected_readback_is_not_success():
    page = object.__new__(ThreatIntelligencePage)
    page._main_scope = lambda: _EmptyLocator()
    page._wait_settle = lambda **_kwargs: None
    page._selected_tab_has_text = lambda _labels: False

    assert page._click_ui_tab("威胁监控") is False
