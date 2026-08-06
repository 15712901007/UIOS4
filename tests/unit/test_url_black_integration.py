"""网址黑白名单页面、后端、GUI和统一报告离线回归。"""

import csv
import json
from pathlib import Path

import pytest

from pages.security.url_black_page import UrlBlackPage
from tests.security.test_url_black_comprehensive import (
    CLIENT_IP,
    DOMAIN,
    RULE_NAME,
    _assert_url_black_export_matches,
)
from utils.backend_verifier import BackendVerifier, VerifyResult
from utils.replay_commands import build_verification_commands
from utils.report_generator import ReportGenerator
from utils.step_recorder import StepRecorder
from utils.verify_helper import _format_ssh_json_evidence, make_ssh_verify


ROOT = Path(__file__).resolve().parents[2]
COMPREHENSIVE_NODE = (
    "security/test_url_black_comprehensive.py::"
    "TestUrlBlackComprehensive::test_url_black_comprehensive"
)
FUNCTIONAL_NODE = (
    "security/test_url_black_functional.py::"
    "TestUrlBlackFunctional::test_url_black_http_https_flow"
)


def test_url_black_page_and_backend_match_device_contract():
    assert UrlBlackPage.MODULE_NAME == "url_black"
    assert UrlBlackPage.IMPORT_REQUIRES_CLEAR_GUARD is True
    assert UrlBlackPage.HELP_ARTICLE_ID == "183"
    assert UrlBlackPage.LIST_URL.endswith("/securityCenter/urlAccessControl")
    assert UrlBlackPage.ADD_URL.endswith("/urlAccessControl/blackList/add")
    backend = BackendVerifier()
    for method in (
        "find_url_black_rule",
        "verify_url_black_database",
        "verify_url_black_rule_set",
        "verify_url_black_generated_rule",
        "verify_url_black_ipset",
        "verify_url_black_artifacts_absent",
        "verify_url_black_consistency",
        "verify_url_black_setting",
        "verify_url_black_flow",
        "cleanup_url_black_test",
        "cleanup_url_black_artifacts",
    ):
        assert callable(getattr(backend, method))


def test_url_black_comprehensive_covers_exact_help_contract():
    source = (
        ROOT / "tests" / "security" / "test_url_black_comprehensive.py"
    ).read_text(encoding="utf-8")
    page_source = (
        ROOT / "pages" / "security" / "url_black_page.py"
    ).read_text(encoding="utf-8")

    assert "右下角帮助文档" in source
    assert "帮助按钮存在且位于右下角" in source
    assert "帮助打开官方文章id=183" in source
    assert "帮助正文主题完整" in source
    assert "帮助标签关闭并返回列表" in source
    for keyword in (
        "网址黑白名单",
        "控制模式",
        "控制域名",
        "允许访问白名单列表中的外部链接",
        "HTTP",
        "HTTPS",
    ):
        assert keyword in page_source


def test_url_black_is_wired_to_fixture_marker_gui_and_report_names():
    conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    pytest_ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    gui = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    excel = (ROOT / "utils" / "test_results_to_excel.py").read_text(
        encoding="utf-8"
    )

    assert "def url_black_page_logged_in(" in conftest
    assert "test_url_black_comprehensive': '安全中心-网址浏览控制-网址黑白名单综合测试(L1-L4)'" in conftest
    assert "test_url_black_http_https_flow': '安全中心-网址黑白名单功能测试(HTTP/HTTPS与白名单外链开关L5)'" in conftest
    assert "url_black: 网址浏览控制-网址黑白名单模块测试" in pytest_ini
    assert gui.count(COMPREHENSIVE_NODE) == 3
    assert gui.count(FUNCTIONAL_NODE) == 3
    assert "综合测试（L1-L4）" in gui
    assert "功能测试（L5真实流量）" in gui
    assert "完整验证（推荐）" in gui
    assert '"url_black": "安全中心-网址浏览控制-网址黑白名单综合测试(L1-L4)"' in excel


def test_url_black_gui_tree_selects_both_real_test_nodes(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        security = next(
            window.module_tree.topLevelItem(index)
            for index in range(window.module_tree.topLevelItemCount())
            if window.module_tree.topLevelItem(index).text(0) == "安全中心"
        )
        node = next(
            security.child(index)
            for index in range(security.childCount())
            if security.child(index).text(0) == "网址浏览控制-网址黑白名单"
        )
        assert node.data(0, Qt.UserRole) == [
            COMPREHENSIVE_NODE,
            FUNCTIONAL_NODE,
        ]
        node.setCheckState(0, Qt.Checked)
        window._update_testcase_list()
        selected = [
            window.testcase_list.item(index).text()
            for index in range(window.testcase_list.count())
        ]
        assert selected == [COMPREHENSIVE_NODE, FUNCTIONAL_NODE]
    finally:
        window.close()
        app.processEvents()


def test_url_black_manual_commands_cover_l1_l5_and_are_copy_ready(monkeypatch):
    backend = BackendVerifier()
    monkeypatch.setattr(
        backend,
        "find_url_black_rule",
        lambda _tagname: {"id": 7, "mode": 0},
    )
    result = VerifyResult("L1-L5", True, "符合预期")
    calls = (
        (backend.verify_url_black_database, ("urlbw_t_main",), {}),
        (backend.verify_url_black_generated_rule, ("urlbw_t_main",), {}),
        (backend.verify_url_black_ipset, ("urlbw_t_main", "192.168.148.2"), {}),
        (backend.verify_url_black_consistency, ("urlbw_t_",), {}),
        (backend.verify_url_black_setting, (1,), {}),
        (
            backend.verify_url_black_flow,
            ("www.qq.com",),
            {
                "protocol": "http",
                "expect_allowed": True,
                "referer": "http://www.baidu.com/",
                "iface": "ens11",
            },
        ),
    )
    commands = []
    for verify_func, args, kwargs in calls:
        built = build_verification_commands(
            backend, verify_func, args=args, kwargs=kwargs, result=result
        )
        assert built
        commands.extend(built)

    text = "\n".join(item["command"] for item in commands)
    assert "FROM url_black" in text
    assert "05-02-url_black_white.txt" in text
    assert "ipset test _urlblack_src_7 192.168.148.2" in text
    assert "url_white_refer" in text
    assert "--interface ens11" in text
    assert "Referer: http://www.baidu.com/" in text
    assert all(item["copy_ready"] is True for item in commands)
    assert all(item["purpose"] and item["expected"] for item in commands)


def test_unified_report_renders_action_expected_actual_verdict_and_commands(tmp_path):
    recorder = StepRecorder()
    recorder.start_step(
        "白名单HTTP外链放行",
        "开启开关并从测试客户端发送带白名单Referer的HTTP请求",
        expected="HTTP请求成功，HTTPS负向边界仍被阻断",
    )
    recorder.add_verification_command({
        "target": "client",
        "target_label": "测试客户端",
        "host": "10.66.0.18",
        "shell": "sh",
        "effect": "read_only",
        "purpose": "复验HTTP外链",
        "command": "curl --interface ens11 http://www.qq.com/",
        "expected": "返回有效HTTP状态码",
        "actual": "__HTTP_CODE__=200\n__CURL_RC__=0",
        "copy_ready": True,
        "contains_secret": False,
        "verdict": True,
    })
    recorder.set_actual("HTTP=200，HTTPS握手被重置")
    recorder.end_step("passed")
    output = tmp_path / "url_black_report.html"
    ReportGenerator().generate_report({
        "total": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
        "duration": "0:00:01",
        "test_cases": [{
            "name": "网址黑白名单功能测试",
            "original_name": "test_url_black_http_https_flow",
            "status": "passed",
            "duration": "1.00s",
            "steps": recorder.get_steps(),
            "step_count": 1,
        }],
    }, str(output))
    html = output.read_text(encoding="utf-8")
    for label in ("测试项", "测试步骤", "预期结果", "实际结果", "测试结果"):
        assert label in html
    assert "HTTP请求成功，HTTPS负向边界仍被阻断" in html
    assert "HTTP=200，HTTPS握手被重置" in html
    assert "curl --interface ens11 http://www.qq.com/" in html
    assert "__HTTP_CODE__=200" in html
    assert "符合预期" in html
    assert 'class="copy-verification-command"' in html
    assert 'class="verification-command-output"' in html


def test_url_black_csv_and_txt_exports_are_parsed_structurally(tmp_path):
    nested_domain = {"custom": [DOMAIN], "object": {}}
    nested_source = {"custom": [CLIENT_IP], "object": {}}
    nested_time = {
        "custom": [{
            "type": "weekly",
            "weekdays": "1234567",
            "start_time": "00:00",
            "comment": "",
            "end_time": "23:59",
        }],
        "object": {},
    }
    row = {
        "id": "7",
        "enabled": "yes",
        "tagname": RULE_NAME,
        "comment": "",
        "domain": json.dumps(nested_domain, ensure_ascii=False, separators=(",", ":")),
        "src_addr": json.dumps(nested_source, ensure_ascii=False, separators=(",", ":")),
        "time": json.dumps(nested_time, ensure_ascii=False, separators=(",", ":")),
        "mode": "1",
    }
    csv_path = tmp_path / "url_black_config.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    txt_path = tmp_path / "url_black_config.txt"
    txt_path.write_text(
        " ".join(f"{field}={value}" for field, value in row.items()) + "\n",
        encoding="utf-8",
    )

    csv_row = _assert_url_black_export_matches(str(csv_path))
    txt_row = _assert_url_black_export_matches(str(txt_path))
    assert csv_row["domain"] == txt_row["domain"] == nested_domain
    assert csv_row["src_addr"] == txt_row["src_addr"] == nested_source
    assert csv_row["time"] == txt_row["time"] == nested_time


def test_ssh_evidence_decodes_nested_json_and_wraps_text_payloads():
    nested_raw = json.dumps({
        "id": 7,
        "domain": json.dumps({"custom": [DOMAIN], "object": {}}),
        "src_addr": json.dumps({"custom": [CLIENT_IP], "object": {}}),
        "time": json.dumps({"custom": [{"type": "weekly"}], "object": {}}),
    }, ensure_ascii=False)
    result = VerifyResult("L1-数据库", True, "数据库字段一致", raw_output=nested_raw)
    detail = _format_ssh_json_evidence("白名单DB", result, nested_raw)
    payload = json.loads(detail.split("【后端JSON】", 1)[1])

    assert payload["check"] == "白名单DB"
    assert payload["data"]["domain"] == {"custom": [DOMAIN], "object": {}}
    assert payload["data"]["src_addr"] == {"custom": [CLIENT_IP], "object": {}}
    assert payload["data"]["time"]["custom"][0]["type"] == "weekly"
    assert '\\"custom\\"' not in detail

    text_detail = _format_ssh_json_evidence(
        "L2-DPI", result, "DB=[]\nDPI_FILTERS=0\nIPSETS="
    )
    text_payload = json.loads(text_detail.split("【后端JSON】", 1)[1])
    assert text_payload["data"] == {
        "format": "text",
        "content": "DB=[]\nDPI_FILTERS=0\nIPSETS=",
    }


def test_url_black_report_prefers_actual_ssh_command_output_pairs(tmp_path):
    backend = BackendVerifier()
    backend._router = type("RecordedRouter", (), {
        "_cmd_log": ["old"],
        "_cmd_io_log": [{"command": "old", "output": "old-output"}],
    })()
    recorder = StepRecorder()
    failures = []
    verify = make_ssh_verify(
        backend, recorder, failures, must_pass_default=True
    )
    recorder.start_step("L1数据库", "读取规则", expected="字段一致")

    def fake_verify_url_black_database(tagname):
        command = (
            "sqlite3 /etc/mnt/ikuai/config.db -json "
            f"\"SELECT * FROM url_black WHERE tagname='{tagname}'\""
        )
        backend._router._cmd_log.append(command)
        backend._router._cmd_io_log.append({
            "command": command,
            "output": '[{"id":7,"tagname":"urlbw_t_main"}]',
        })
        return VerifyResult(
            "L1",
            True,
            "数据库字段一致",
            raw_output=json.dumps({
                "id": 7,
                "tagname": "urlbw_t_main",
                "domain": json.dumps({"custom": [DOMAIN], "object": {}}),
            }, ensure_ascii=False),
        )

    fake_verify_url_black_database.__name__ = "verify_url_black_database"
    result = verify("L1数据库", fake_verify_url_black_database, "urlbw_t_main")
    recorder.end_step("passed")

    assert result.passed and not failures
    commands = recorder.get_steps()[0]["verification_commands"]
    assert len(commands) == 1
    assert commands[0]["execution_source"] == "actual"
    assert "SELECT * FROM url_black" in commands[0]["command"]
    assert '"id":7' in commands[0]["actual"]
    assert commands[0]["copy_ready"] is True
    details = recorder.get_steps()[0]["details"]
    json_detail = next(item for item in details if "【后端JSON】" in item)
    assert '"domain": {' in json_detail
    assert '\\"custom\\"' not in json_detail

    output = tmp_path / "url_black_json_report.html"
    ReportGenerator().generate_report({
        "total": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
        "duration": "0:00:01",
        "test_cases": [{
            "name": "网址黑白名单JSON证据",
            "original_name": "test_url_black_json_evidence",
            "status": "passed",
            "duration": "1.00s",
            "steps": recorder.get_steps(),
            "step_count": 1,
        }],
    }, str(output))
    html = output.read_text(encoding="utf-8")
    assert "SSH结构化数据（JSON）" in html
    assert 'class="backend-data-content backend-json-content"' in html
    assert "&#34;domain&#34;: {" in html
