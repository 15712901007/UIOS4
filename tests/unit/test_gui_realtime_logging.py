from pathlib import Path

from utils.step_recorder import StepRecorder


ROOT = Path(__file__).resolve().parents[2]


def test_step_recorder_emits_start_and_end_when_gui_live_logging_enabled(
    monkeypatch, capsys,
):
    monkeypatch.setenv("IKUAI_LIVE_STEPS", "1")
    recorder = StepRecorder()

    with recorder.step("步骤1 操作：运行长任务", "验证实时进度"):
        pass

    output = capsys.readouterr().out
    assert "[步骤 1] 开始 | 步骤1 操作：运行长任务" in output
    assert "[步骤 1] 通过 | 步骤1 操作：运行长任务" in output
    assert "用时" in output


def test_step_recorder_stays_quiet_outside_gui(monkeypatch, capsys):
    monkeypatch.delenv("IKUAI_LIVE_STEPS", raising=False)
    recorder = StepRecorder()

    with recorder.step("步骤1", "普通pytest运行"):
        pass

    assert capsys.readouterr().out == ""


def test_live_step_end_reflects_soft_product_failure(monkeypatch, capsys):
    monkeypatch.setenv("IKUAI_LIVE_STEPS", "1")
    recorder = StepRecorder()

    with recorder.step("步骤10", "批量行为"):
        recorder.add_detail("【页面验证】失败")

    output = capsys.readouterr().out
    assert "[步骤 1] 失败 | 步骤10" in output


def test_gui_log_pipeline_batches_escapes_and_keeps_liveness_contract():
    main_window = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    runner = (ROOT / "gui" / "test_runner.py").read_text(encoding="utf-8")

    assert "html.escape(line, quote=False)" in main_window
    assert "self._log_flush_timer.start(50)" in main_window
    assert "self.log_text.setLineWrapMode(QTextEdit.NoWrap)" in main_window
    assert 'env["IKUAI_LIVE_STEPS"] = "1"' in runner
    assert "测试仍在执行，当前操作尚未返回" in runner


def test_alg_gui_node_uses_the_realtime_runner_contract():
    main_window = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    runner = (ROOT / "gui" / "test_runner.py").read_text(encoding="utf-8")
    test_source = (
        ROOT / "tests" / "device_setting" / "test_alg_setting_comprehensive.py"
    ).read_text(encoding="utf-8")

    node = (
        "device_setting/test_alg_setting_comprehensive.py::"
        "TestAlgSettingComprehensive::test_alg_setting_comprehensive"
    )
    assert node in main_window
    assert "ALG_SETTING_TESTCASE = (" in runner
    assert '"device_setting/test_alg_setting_comprehensive.py::"' in runner
    assert '"TestAlgSettingComprehensive::test_alg_setting_comprehensive"' in runner
    assert 'env["IKUAI_LIVE_STEPS"] = "1"' in runner
    assert 'env["PYTHONUNBUFFERED"] = "1"' in runner
    assert 'print(f"    SSH-{label}' in test_source
    assert "with rec.step(" in test_source


def test_virtual_machine_flow_uses_four_concurrent_vms_and_real_batch_delete():
    page_source = (
        ROOT / "pages" / "advanced_service" / "virtual_machine_page.py"
    ).read_text(encoding="utf-8")
    source = (
        ROOT / "tests" / "advanced_service" /
        "test_virtual_machine_comprehensive.py"
    ).read_text(encoding="utf-8")

    assert 'batch_names = [f"{prefix}batch1", f"{prefix}batch2"]' in source
    assert 'simultaneous.get("rows") == 4' in source
    assert "page.batch_delete(batch_names)" in source
    assert "page.delete_vm(vm_name)" in source
    assert "selection_state[name] = checked" in page_source
    assert "if set(selected) != set(names)" in page_source
