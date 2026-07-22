"""基础设置报告四态与 Excel 安全边界的离线回归。"""

from __future__ import annotations

import json
import re
import zipfile

import pytest

from utils.report_generator import ReportGenerator
from utils.step_recorder import StepRecorder
from utils.test_results_to_excel import export_results_to_excel


def _record_forced_status(*statuses):
    recorder = StepRecorder()
    with recorder.step("操作：记录状态；验证：软状态优先级"):
        for status in statuses:
            recorder.mark_current_step(status, f"{status}-reason")
    return recorder.get_steps()[0]


def test_step_recorder_supports_four_states_and_keeps_skipped_compatible():
    assert _record_forced_status("not_applicable")["status"] == "not_applicable"
    assert _record_forced_status("skipped")["status"] == "skipped"
    assert _record_forced_status("not_applicable", "warning")["status"] == "warning"

    failed = _record_forced_status(
        "not_applicable", "warning", "failed", "not_applicable"
    )
    assert failed["status"] == "failed"
    assert failed["error_message"] == "failed-reason"

    with pytest.raises(ValueError, match="不支持的强制步骤状态"):
        _record_forced_status("passed")


def _status_report_data():
    statuses = ["passed", "failed", "warning", "not_applicable", "skipped"]
    names = ["通过场景", "失败场景", "警告场景", "明确不适用场景", "历史兼容场景"]
    cases = []
    for status, name in zip(statuses, names):
        cases.append({
            "name": name,
            "original_name": "test_basic_setting_comprehensive",
            "status": status,
            "duration": "0.01s",
            "step_count": 1,
            "steps": [{
                "name": f"操作：生成{name}；验证：四态中文显示",
                "description": "离线状态展示验证",
                "status": status,
                "duration": "0.01s",
                "details": ["【测试操作】\n通过：生成离线状态"],
                "verification_commands": [],
                "actual": name,
                "error_message": (
                    None if status == "passed" else f"{status}-reason"
                ),
            }],
            "error_message": "产品缺陷证据" if status == "failed" else None,
            "error_traceback": None,
            "screenshot_path": "",
        })
    return {
        "total": len(cases),
        "passed": 1,
        "failed": 1,
        "skipped": 2,
        "total_steps": len(cases),
        "duration": "00:00:01",
        "test_cases": cases,
    }


def test_html_distinguishes_four_states_and_renders_skipped_as_not_applicable(
    tmp_path,
):
    output = tmp_path / "basic-status.html"
    ReportGenerator().generate_report(_status_report_data(), str(output))
    html = output.read_text(encoding="utf-8")

    assert "警告用例" in html
    assert "不适用用例" in html
    assert "filterCases('warning'" in html
    assert "filterCases('not_applicable'" in html
    assert ".status-warning" in html
    assert ".status-not_applicable" in html
    assert ".step-status.warning" in html
    assert ".step-status.not_applicable" in html
    assert "跳过" not in html
    assert re.search(
        r'data-status="skipped".*?历史兼容场景.*?不适用', html, re.S
    )
    assert re.search(r'data-status="warning".*?警告场景.*?警告', html, re.S)
    assert "警告: warning-reason" in html
    assert "说明: skipped-reason" in html


def _formula_injection_data():
    return {
        "total": 1,
        "passed": 0,
        "failed": 0,
        "skipped": 1,
        "total_steps": 2,
        "duration": "=SUM(1,1)",
        "start_time": "+1+1",
        "end_time": "-1+1",
        "test_cases": [{
            "name": "=HYPERLINK(\"https://invalid.example\",\"case\")",
            "original_name": "test_basic_setting_comprehensive",
            "status": "skipped",
            "duration": "+2+2",
            "step_count": 2,
            "error_message": "@SUM(1,1)",
            "screenshot_path": "-cmd|' /C calc'!A0",
            "steps": [
                {
                    "name": "=1+1",
                    "description": "+2+2",
                    "status": "skipped",
                    "duration": "-3+3",
                    "details": ["@SUM(2,2)", "\t=4+4"],
                    "actual": "=5+5",
                    "error_message": "+6+6",
                    "verification_commands": [{
                        "target": "router",
                        "target_label": "=router-label",
                        "host": "+7+7",
                        "shell": "-sh",
                        "purpose": "@SUM(3,3)",
                        "valid_when": "\t=8+8",
                        "interactive": True,
                        "interactive_hint": "=terminal-input",
                        "command": "=9+9",
                        "expected": "+10+10",
                        "actual": "-11+11",
                        "effect": "read_only",
                        "copy_ready": True,
                        "contains_secret": False,
                    }],
                },
                {
                    "name": "@warning-step",
                    "description": "=warning-description",
                    "status": "warning",
                    "duration": "0.01s",
                    "details": [],
                    "actual": "",
                    "error_message": None,
                    "verification_commands": [],
                },
            ],
        }],
    }


def test_excel_uses_four_chinese_states_and_neutralizes_every_formula(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    json_path = tmp_path / "basic-status.json"
    xlsx_path = tmp_path / "basic-status.xlsx"
    json_path.write_text(
        json.dumps(_formula_injection_data(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    success, message = export_results_to_excel(str(json_path), str(xlsx_path))
    assert success, message

    workbook = openpyxl.load_workbook(xlsx_path, data_only=False)
    try:
        cells = [
            cell
            for worksheet in workbook.worksheets
            for row in worksheet.iter_rows()
            for cell in row
            if cell.value is not None
        ]
        assert not [cell.coordinate for cell in cells if cell.data_type == "f"]
        for cell in cells:
            if isinstance(cell.value, str):
                stripped = cell.value.lstrip("\t\r\n")
                if stripped.startswith(("=", "+", "-", "@")):
                    assert cell.data_type == "s", (
                        cell.parent.title,
                        cell.coordinate,
                        cell.value,
                    )
        values = [str(cell.value) for cell in cells]
        assert "=9+9" in values
        assert "\t=4+4" in values
        assert "警告" in values
        assert "不适用" in values
        assert "跳过" not in values
    finally:
        workbook.close()

    with zipfile.ZipFile(xlsx_path) as archive:
        worksheet_xml = b"".join(
            archive.read(name)
            for name in archive.namelist()
            if name.startswith("xl/worksheets/") and name.endswith(".xml")
        )
    assert b"<f" not in worksheet_xml
