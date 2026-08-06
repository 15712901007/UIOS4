"""OSPF 实时日志、报告可读性和 GUI 转发链路回归。"""
from __future__ import annotations

import builtins
import os
import re
import sys
from pathlib import Path

import pytest

from utils.ospf_verifier import OspfVerifier
from utils.report_generator import ReportGenerator
from utils.step_recorder import (
    clear_registered_sensitive_values,
    register_sensitive_value,
)


def test_ospf_realtime_is_one_line_flushed_and_secret_safe(monkeypatch):
    from tests.network.test_ospf_comprehensive import _emit_ospf_realtime

    captured = []
    secret = "ospf-runtime-secret-for-log"
    register_sensitive_value(secret)
    monkeypatch.setattr(
        builtins, "print",
        lambda *args, **kwargs: captured.append((args, kwargs)),
    )
    try:
        _emit_ospf_realtime("步骤开始", f"第一行\n第二行 password={secret}")
    finally:
        clear_registered_sensitive_values()

    assert len(captured) == 1
    args, kwargs = captured[0]
    rendered = str(args[0])
    assert rendered.startswith("[OSPF][步骤开始]")
    assert "\n" not in rendered and "\r" not in rendered
    assert secret not in rendered
    assert kwargs.get("flush") is True


def test_wait_neighbor_emits_five_second_observed_progress(monkeypatch):
    from utils import ospf_verifier as module

    clock = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    verifier = OspfVerifier(type("Backend", (), {})())
    monkeypatch.setattr(
        verifier, "neighbor_state",
        lambda *_args, **_kwargs: {
            "state": "Full/DR" if clock[0] >= 6.0 else "Init",
            "full": clock[0] >= 6.0,
        },
    )
    emitted = []
    result = verifier.wait_neighbor(
        "router", "ipv4", "198.18.0.1", timeout=10,
        progress=lambda event, message: emitted.append((event, message)),
    )

    assert result.passed
    assert emitted
    assert emitted[0][0] == "等待进度"
    assert "已等待=5.0s" in emitted[0][1]
    assert "最大等待=10s" in emitted[0][1]
    assert "当前状态=Init" in emitted[0][1]


def test_ospf_report_has_continuous_matching_numbers_and_plain_summary(tmp_path):
    steps = []
    for index in range(1, 13):
        failed = index == 10
        steps.append({
            "name": f"步骤{index} 操作：执行场景{index}；验证：得到预期结果{index}",
            "description": f"场景{index}",
            "status": "failed" if failed else "passed",
            "duration": "1.00s",
            "details": ["【后端验证】\n通过 检查：符合预期"],
            "verification_commands": [],
            "actual": "",
            "error_message": (
                "OSPFv3 区域和接口无法从页面保存并进入实际运行状态。"
                if failed else None
            ),
        })
    data = {
        "total": 1, "passed": 0, "failed": 1, "skipped": 0,
        "total_steps": 12, "duration": "0:00:12",
        "test_cases": [{
            "name": "网络配置-OSPF综合测试",
            "original_name": "test_ospf_comprehensive",
            "status": "failed", "duration": "12.00s",
            "error_message": (
                "OSPF综合测试失败：产品根因1项（失败步骤证据1项），"
                "自动化缺陷0项，辅助/恢复缺陷0项"
            ),
            "steps": steps, "step_count": 12,
        }],
    }
    output = tmp_path / "ospf.html"
    ReportGenerator().generate_report(data, str(output))
    html = output.read_text(encoding="utf-8")

    assert "<span class=\"failed-step-badge\">步骤 10</span>" in html
    assert "步骤10 操作：执行场景10；验证：得到预期结果10" in html
    summary = re.search(
        r'<div class="failed-step-error">(.*?)</div>', html, re.S
    ).group(1)
    assert "契约" not in summary
    assert "RIB/FIB" not in summary
    assert "daemon" not in summary
    assert "tagname" not in summary
    for label in ("操作：", "预期结果：", "实际现象：", "后端证据：", "人工复验命令："):
        assert label in html


def test_testrunner_pytest_subprocess_reaches_gui_log_box(monkeypatch, tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication
    from config.config import get_config
    from gui.main_window import MainWindow
    from gui.test_runner import TestRunner

    probe = tmp_path / "test_ospf_gui_log_probe.py"
    probe.write_text(
        "from tests.network.test_ospf_comprehensive import _emit_ospf_realtime\n"
        "def test_probe():\n"
        "    _emit_ospf_realtime('步骤开始', 'GUI链路探针')\n",
        encoding="utf-8",
    )
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    runner = TestRunner(["unused"], get_config())
    runner.log_signal.connect(window._log)
    monkeypatch.setattr(
        runner, "_build_pytest_command",
        lambda: [
            sys.executable, "-m", "pytest", "-q", "-s",
            "-o", "addopts=", "-p", "no:allure", str(probe),
        ],
    )
    monkeypatch.setattr(runner, "_read_final_stats", lambda _path: None)
    try:
        loop = QEventLoop()
        runner.finished_signal.connect(lambda _path: loop.quit())
        runner.error_signal.connect(lambda _message: loop.quit())
        QTimer.singleShot(30000, loop.quit)
        runner.start()
        loop.exec()
        assert runner.wait(5000)
        rendered = window.log_text.toPlainText()
        assert "[OSPF][步骤开始] GUI链路探针" in rendered
    finally:
        window.close()
        app.processEvents()
