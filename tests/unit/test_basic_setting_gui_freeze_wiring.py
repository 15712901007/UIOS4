"""设备基础设置 GUI 与冻结 collect 接线回归（不访问被测设备）。"""

import importlib
import json
import os
import sys
from pathlib import Path

import pytest


BASIC_SETTING_NODE = (
    "device_setting/test_basic_setting_comprehensive.py::"
    "TestBasicSettingComprehensive::test_basic_setting_comprehensive"
)


def _find_top_level(window, label):
    for index in range(window.module_tree.topLevelItemCount()):
        item = window.module_tree.topLevelItem(index)
        if item.text(0) == label:
            return item
    return None


def _find_child(parent, label):
    for index in range(parent.childCount()):
        child = parent.child(index)
        if child.text(0) == label:
            return child
    return None


def test_basic_setting_gui_tree_run_report_open_and_excel_export(
    monkeypatch, tmp_path
):
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
        device_setting = _find_top_level(window, "设备设置")
        assert device_setting is not None
        basic_setting = _find_child(device_setting, "基础设置")
        assert basic_setting is not None
        assert basic_setting.data(0, Qt.UserRole) == [BASIC_SETTING_NODE]

        basic_setting.setCheckState(0, Qt.Checked)
        window._update_testcase_list()
        assert window.testcase_list.count() == 1
        assert window.testcase_list.item(0).text() == BASIC_SETTING_NODE

        window._start_tests()
        assert started == {"testcases": [BASIC_SETTING_NODE], "started": True}

        report_dir = tmp_path / "reports" / "output"
        report_dir.mkdir(parents=True)
        report = report_dir / "test_report_basic_setting.html"
        report.write_text("<html><title>基础设置</title></html>", encoding="utf-8")
        window.config.report.output_dir = "reports/output"
        opened = []
        monkeypatch.setattr(
            os, "startfile", lambda path: opened.append(path), raising=False
        )
        window._open_report(None)
        assert opened == [str(report.resolve())]

        result_json = report_dir / "test_results.json"
        result_json.write_text(
            '{"total": 1, "test_cases": []}', encoding="utf-8"
        )
        export_path = tmp_path / "basic_setting_export.xlsx"
        export_call = {}

        def choose_export_path(parent, title, default_path, file_filter):
            export_call["default_path"] = default_path
            return str(export_path), file_filter

        def export_results(json_path, output_path):
            export_call["json_path"] = json_path
            export_call["output_path"] = output_path
            return True, "导出成功"

        monkeypatch.setattr(QFileDialog, "getSaveFileName", choose_export_path)
        monkeypatch.setattr(
            QMessageBox,
            "question",
            lambda *args, **kwargs: QMessageBox.No,
        )
        monkeypatch.setattr(excel_module, "export_results_to_excel", export_results)
        window._export_test_results()
        assert Path(export_call["default_path"]).parent == tmp_path / "reports"
        assert Path(export_call["json_path"]).resolve() == result_json.resolve()
        assert Path(export_call["output_path"]).resolve() == export_path.resolve()
    finally:
        window.close()
        app.processEvents()


def test_basic_setting_runner_target_and_log_path_redaction(tmp_path):
    from config.config import get_config
    from gui.test_runner import TestRunner

    runner = TestRunner([BASIC_SETTING_NODE], get_config())
    command = runner._build_pytest_command()
    assert command[-1].replace("\\", "/").endswith(
        "tests/" + BASIC_SETTING_NODE
    )

    emitted = []
    runner.log_signal.connect(lambda level, message: emitted.append((level, message)))
    private_path = str(tmp_path / "reports" / "basic_setting.html")
    runner._emit_log("INFO", f"基础设置报告: {private_path}")
    assert emitted
    assert private_path not in emitted[-1][1]
    assert "基础设置报告" in emitted[-1][1]


def test_main_dispatches_basic_setting_smoke_before_gui(monkeypatch):
    import main
    from gui import test_runner

    called = []
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["iKuai-test.exe", "--collect-basic-setting-smoke"],
    )
    monkeypatch.setattr(
        test_runner,
        "run_packaged_basic_setting_collect_smoke",
        lambda: called.append(True) or 0,
    )

    with pytest.raises(SystemExit) as exc_info:
        main._dispatch_packaged_basic_setting_smoke()

    assert exc_info.value.code == 0
    assert called == [True]


def test_basic_setting_packaged_collect_is_exact_and_path_safe(
    monkeypatch, tmp_path
):
    import pytest as pytest_module
    from gui import test_runner

    bundle_root = tmp_path / "private-user-bundle"
    runtime_root = tmp_path / "private-user-runtime"
    test_file = (
        bundle_root
        / "tests"
        / "device_setting"
        / "test_basic_setting_comprehensive.py"
    )
    test_file.parent.mkdir(parents=True)
    test_file.write_text("# packaged collect fixture\n", encoding="utf-8")
    runtime_root.mkdir()
    result_path = runtime_root / "basic_setting_collect_smoke.json"

    monkeypatch.setattr(test_runner, "is_frozen", lambda: True)
    monkeypatch.setattr(test_runner, "get_bundle_root", lambda: str(bundle_root))
    monkeypatch.setattr(test_runner, "get_runtime_root", lambda: str(runtime_root))
    real_import_module = importlib.import_module
    smoke_dependencies = {
        "pytest",
        "playwright.sync_api",
        "paramiko",
        "jinja2",
        "yaml",
        "openpyxl",
        "pages.device_setting.basic_setting_page",
        "utils.backend_verifier",
    }

    def import_smoke_dependency(name, package=None):
        if name in smoke_dependencies:
            return object()
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", import_smoke_dependency)

    absolute_node = str(bundle_root / "tests" / "device_setting") + (
        "/test_basic_setting_comprehensive.py::"
        "TestBasicSettingComprehensive::test_basic_setting_comprehensive"
    )

    def fake_pytest_main(args, plugins):
        assert "--collect-only" in args
        assert os.path.normpath(args[-1].split("::", 1)[0]) == os.path.normpath(
            str(test_file)
        )
        session = type(
            "Session",
            (),
            {"items": [type("Item", (), {"nodeid": absolute_node})()]},
        )()
        plugins[0].pytest_collection_finish(session)
        print(f"rootdir: {bundle_root}")
        print(f"warning: cache at {bundle_root}")
        print("collected 1 item")
        return 0

    monkeypatch.setattr(pytest_module, "main", fake_pytest_main)

    assert test_runner.run_packaged_basic_setting_collect_smoke(
        str(result_path)
    ) == 0
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload, ensure_ascii=False)

    assert payload["service"] == "basic_setting"
    assert payload["pytest_exit_code"] == 0
    assert payload["collected"] == 1
    assert payload["expected_node_found"] is True
    assert payload["success"] is True
    assert payload["test_target"] == "tests/" + BASIC_SETTING_NODE
    assert payload["bundle_root"] is True
    assert payload["runtime_root"] is True
    assert payload["dependencies"]["pages.device_setting.basic_setting_page"] == "ok"
    assert payload["dependencies"]["utils.backend_verifier"] == "ok"
    assert payload["dependencies"]["openpyxl"] == "ok"
    assert "[包目录]" in payload["pytest_output"]
    assert "rootdir:" not in payload["pytest_output"]
    assert str(bundle_root) not in serialized
    assert str(runtime_root) not in serialized
    assert os.path.isabs(payload["test_target"]) is False
