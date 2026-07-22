"""SNMP report DOM and GUI wiring regression tests (no router mutation)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from utils.report_generator import ReportGenerator


SNMP_NODE = (
    "advanced_service/test_snmp_server_comprehensive.py::"
    "TestSnmpServerComprehensive::test_snmp_server_comprehensive"
)


def _sample_report_data():
    sections = [
        "【测试操作】\n通过 执行只读安全复验",
        "【页面验证】\n通过 SNMP单例表单显示正确",
        "【后端验证】\n通过 snmp_conf字段一致",
        "【运行时验证】\n通过 双栈UDP监听正确",
        "【协议验证】\n通过 snmpget返回目标OID与值",
        "【清理结果】\n通过 无临时凭据或监听残留",
    ]
    commands = [
        {
            "target": "router",
            "target_label": "路由器",
            "host": "10.66.0.150",
            "shell": "sh",
            "purpose": "查看SNMP单例数量",
            "command": (
                'sqlite3 /etc/mnt/ikuai/config.db '
                '"SELECT count(*) AS row_count FROM snmp_conf"'
            ),
            "expected": "row_count=1",
            "actual": "row_count=1",
            "effect": "read_only",
            "copy_ready": True,
            "contains_secret": False,
            "interactive": False,
            "valid_when": "测试期间及清理后",
        },
        {
            "target": "client",
            "target_label": "测试客户端",
            "host": "10.66.0.18",
            "shell": "sh",
            "purpose": "交互式执行V3协议复验",
            "command": (
                "sudo -n /usr/local/sbin/ikuai-snmp-verify --mode v3-priv "
                "--operation get --host 192.168.148.1:2161 "
                "--oid 1.3.6.1.2.1.1.5.0 --auth-proto SHA --priv-proto AES"
            ),
            "expected": "终端交互输入凭据后返回OID与值",
            "actual": "真实协议已返回OID与值",
            "effect": "创建并清理客户端0600临时配置；SNMP只读查询",
            "copy_ready": True,
            "contains_secret": False,
            "interactive": True,
            "interactive_hint": "凭据只在终端中交互输入",
            "valid_when": "SNMP V3服务启用时",
        },
    ]
    return {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
        "total_steps": 1,
        "duration": "00:00:01",
        "start_time": "2026-07-15 00:00:00",
        "end_time": "2026-07-15 00:00:01",
        "test_cases": [{
            "name": "高级服务-本地服务-SNMP服务",
            "original_name": "test_snmp_server_comprehensive[chromium]",
            "status": "passed",
            "duration": "1.00s",
            "step_count": 1,
            "steps": [{
                "name": "操作：执行安全复验；验证：中文报告与复制按钮",
                "description": "不携带任何协议秘密",
                "status": "passed",
                "duration": "1.00s",
                "details": sections,
                "verification_commands": commands,
                "actual": "布局和复制路径均可用",
                "error_message": None,
            }],
            "error_message": None,
            "error_traceback": None,
        }],
    }


def _open_report(page, report_path: Path, width: int, height: int):
    page.set_viewport_size({"width": width, "height": height})
    page.goto(report_path.resolve().as_uri(), wait_until="load")
    page.evaluate("""() => {
        document.querySelectorAll('.test-case-details').forEach(
            element => element.classList.add('show'));
        document.querySelectorAll('details').forEach(element => element.open = true);
    }""")


def test_snmp_report_desktop_mobile_layout_and_every_copy_button(tmp_path):
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    report_path = tmp_path / "snmp_report.html"
    ReportGenerator().generate_report(
        _sample_report_data(), str(report_path), report_title="SNMP自动化测试报告"
    )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        page.add_init_script("""(() => {
            Object.defineProperty(window, 'isSecureContext', {
                configurable: true,
                value: true
            });
            Object.defineProperty(navigator, 'clipboard', {
                configurable: true,
                value: {writeText: text => {window.__copiedText = text; return Promise.resolve();}}
            });
        })()""")
        for width, height in ((1440, 900), (390, 844)):
            _open_report(page, report_path, width, height)
            layout = page.evaluate("""() => ({
                pageFits: document.documentElement.scrollWidth <= window.innerWidth + 1,
                cardsFit: [...document.querySelectorAll(
                    '.container,.test-case,.test-case-details,' +
                    '.verification-command-card,.copy-verification-command'
                )].every(el => {
                    const rect = el.getBoundingClientRect();
                    return rect.left >= -1 && rect.right <= window.innerWidth + 1;
                }),
                sections: ['测试操作','页面验证','后端验证','运行时验证','协议验证','清理结果']
                    .every(label => document.body.innerText.includes('【' + label + '】'))
            })""")
            assert layout == {"pageFits": True, "cardsFit": True, "sections": True}

        _open_report(page, report_path, 1440, 900)
        buttons = page.locator("button.copy-verification-command")
        assert buttons.count() == 2
        for index in range(buttons.count()):
            button = buttons.nth(index)
            code = button.locator(
                "xpath=ancestor::div[contains(@class,'verification-command-card')][1]//code"
            ).text_content()
            button.click()
            page.wait_for_function("text => window.__copiedText === text", arg=code)
            assert page.evaluate("window.__copiedText") == code

        context.close()

        fallback_context = browser.new_context()
        fallback_page = fallback_context.new_page()
        fallback_page.add_init_script("""(() => {
            Object.defineProperty(navigator, 'clipboard', {configurable: true, value: undefined});
            document.execCommand = command => {
                if (command !== 'copy') return false;
                const textarea = document.querySelector('textarea');
                window.__fallbackCopied = textarea ? textarea.value : '';
                return true;
            };
        })()""")
        _open_report(fallback_page, report_path, 1440, 900)
        fallback_button = fallback_page.locator("button.copy-verification-command").first
        expected = fallback_button.locator(
            "xpath=ancestor::div[contains(@class,'verification-command-card')][1]//code"
        ).text_content()
        fallback_button.click()
        fallback_page.wait_for_function("text => window.__fallbackCopied === text", arg=expected)
        assert fallback_button.text_content() == "已复制"
        fallback_context.close()
        browser.close()


def _find_tree_item(root, labels):
    current = root
    for label in labels:
        found = None
        for index in range(current.childCount()):
            child = current.child(index)
            if child.text(0) == label:
                found = child
                break
        if found is None:
            return None
        current = found
    return current


def test_snmp_gui_tree_run_target_and_persistent_report_path(monkeypatch, tmp_path):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
    import gui.main_window as main_window_module
    import utils.test_results_to_excel as excel_module

    app = QApplication.instance() or QApplication([])

    class SignalStub:
        def connect(self, callback):
            self.callback = callback

    started = {}

    class FakeRunner:
        def __init__(self, testcases, config):
            started["testcases"] = list(testcases)
            self.log_signal = SignalStub()
            self.progress_signal = SignalStub()
            self.finished_signal = SignalStub()

        def start(self):
            started["started"] = True

        def isRunning(self):
            return False

    monkeypatch.setattr(main_window_module, "TestRunner", FakeRunner)
    monkeypatch.setattr(main_window_module, "get_runtime_root", lambda: str(tmp_path))
    window = main_window_module.MainWindow()
    try:
        advanced = None
        for index in range(window.module_tree.topLevelItemCount()):
            item = window.module_tree.topLevelItem(index)
            if item.text(0) == "高级服务":
                advanced = item
                break
        assert advanced is not None
        snmp_item = _find_tree_item(advanced, ["本地服务", "SNMP服务"])
        assert snmp_item is not None
        assert snmp_item.data(0, Qt.UserRole) == [SNMP_NODE]
        snmp_item.setCheckState(0, Qt.Checked)
        window._update_testcase_list()
        assert window.testcase_list.count() == 1
        assert window.testcase_list.item(0).text() == SNMP_NODE
        window._start_tests()
        assert started == {"testcases": [SNMP_NODE], "started": True}

        report_dir = tmp_path / "reports" / "output"
        report_dir.mkdir(parents=True)
        report = report_dir / "snmp_latest.html"
        report.write_text("<html><title>SNMP</title></html>", encoding="utf-8")
        window.config.report.output_dir = "reports/output"
        opened = []
        monkeypatch.setattr(os, "startfile", lambda path: opened.append(path), raising=False)
        window._open_report(None)
        assert opened == [str(report.resolve())]

        result_json = report_dir / "test_results.json"
        result_json.write_text('{"total": 0, "test_cases": []}', encoding="utf-8")
        export_path = tmp_path / "snmp_export.xlsx"
        export_call = {}

        def choose_export_path(parent, title, default_path, file_filter):
            export_call["default_path"] = default_path
            return str(export_path), file_filter

        def export_results(json_path, output_path):
            export_call["json_path"] = json_path
            export_call["output_path"] = output_path
            return True, "导出成功"

        monkeypatch.setattr(QFileDialog, "getSaveFileName", choose_export_path)
        monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.No)
        monkeypatch.setattr(excel_module, "export_results_to_excel", export_results)
        window._export_test_results()
        assert Path(export_call["default_path"]).parent == tmp_path / "reports"
        assert Path(export_call["json_path"]).resolve() == result_json.resolve()
        assert Path(export_call["output_path"]).resolve() == export_path.resolve()
    finally:
        window.close()
        app.processEvents()


def test_source_gui_runner_uses_exact_snmp_node_and_isolated_pytest_options():
    from config.config import get_config
    from gui.test_runner import TestRunner

    runner = TestRunner([SNMP_NODE], get_config())
    command = runner._build_pytest_command()
    joined = " ".join(command)
    assert "-o addopts=" in joined
    assert "-p no:allure" in joined
    assert "test_snmp_server_comprehensive.py::TestSnmpServerComprehensive" in joined


def test_frozen_runtime_root_is_executable_directory(monkeypatch, tmp_path):
    from gui import test_runner

    executable = tmp_path / "iKuai-test.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    assert test_runner.get_runtime_root() == str(tmp_path)
