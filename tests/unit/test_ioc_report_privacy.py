from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def project_conftest():
    spec = importlib.util.spec_from_file_location(
        "_ioc_privacy_project_conftest", ROOT / "tests" / "conftest.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _marker_item(marker: str | None = "threat_intelligence"):
    return SimpleNamespace(
        nodeid="tests/security/test_threat_intelligence_comprehensive.py::test_threat_intelligence_comprehensive[chromium]",
        name="test_threat_intelligence_comprehensive[chromium]",
        get_closest_marker=(
            lambda requested: object() if marker == requested else None
        ),
    )


def test_threat_marker_is_detected_without_affecting_other_tests(project_conftest):
    assert project_conftest._is_threat_intelligence_item(_marker_item())
    unrelated = SimpleNamespace(
        nodeid="tests/unit/test_other.py::test_other",
        name="test_other",
        get_closest_marker=lambda requested: None,
    )
    assert not project_conftest._is_threat_intelligence_item(unrelated)


def test_threat_failure_hook_never_captures_screenshot(project_conftest):
    screenshot_calls = []

    class PageStub:
        def is_closed(self):
            return False

        def screenshot(self, **kwargs):
            screenshot_calls.append(kwargs)

    item = _marker_item()
    item.funcargs = {
        "threat_intelligence_page_logged_in": SimpleNamespace(page=PageStub())
    }
    call = SimpleNamespace(when="call")
    report = SimpleNamespace(failed=True)
    outcome = SimpleNamespace(get_result=lambda: report)

    hook = project_conftest.pytest_runtest_makereport(item, call)
    next(hook)
    with pytest.raises(StopIteration):
        hook.send(outcome)

    assert screenshot_calls == []
    assert not hasattr(report, "extra")


def test_threat_artifact_guard_disables_and_restores_capture_options(project_conftest):
    options = SimpleNamespace(
        screenshot="only-on-failure", video="retain-on-failure", tracing="on"
    )
    request = SimpleNamespace(node=_marker_item(), config=SimpleNamespace(option=options))
    guard = project_conftest._threat_intelligence_artifact_guard.__wrapped__(request)

    next(guard)
    assert (options.screenshot, options.video, options.tracing) == (
        "off", "off", "off"
    )
    with pytest.raises(StopIteration):
        next(guard)
    assert (options.screenshot, options.video, options.tracing) == (
        "only-on-failure", "retain-on-failure", "on"
    )


def test_threat_context_strips_capture_arguments(project_conftest):
    captured = {}

    class ContextStub:
        def close(self):
            captured["closed"] = True

    class BrowserStub:
        def new_context(self, **kwargs):
            captured["kwargs"] = kwargs
            return ContextStub()

    args = {
        "viewport": {"width": 1280, "height": 720},
        "record_video_dir": "private-videos",
        "record_har_path": "private.har",
        "record_har_content": "attach",
    }
    request = SimpleNamespace(node=_marker_item())
    context_gen = project_conftest.context.__wrapped__(
        BrowserStub(), args, request
    )
    context = next(context_gen)
    assert context is not None
    assert captured["kwargs"] == {"viewport": {"width": 1280, "height": 720}}
    with pytest.raises(StopIteration):
        next(context_gen)
    assert captured["closed"] is True
    # The fixture must not mutate the session-level argument dictionary.
    assert "record_video_dir" in args and "record_har_path" in args


def test_threat_failure_report_replaces_raw_exception_and_attachments(project_conftest):
    original = copy.deepcopy(project_conftest._test_results)
    recorder = project_conftest.get_step_recorder()
    recorder.clear()
    project_conftest._test_results.clear()
    project_conftest._test_results.update({
        "total": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "total_steps": 0,
        "test_cases": [],
    })
    raw_ioc = "198.51.100.77 raw-syslog-secret"
    report = SimpleNamespace(
        when="call",
        failed=True,
        skipped=False,
        passed=False,
        outcome="failed",
        duration=0.1,
        nodeid="tests/security/test_threat_intelligence_comprehensive.py::test_threat_intelligence_comprehensive[chromium]",
        keywords={"threat_intelligence": True},
        longrepr=f"AssertionError: 页面原始日志 {raw_ioc}",
    )
    hook = project_conftest.pytest_runtest_logreport(report)
    next(hook)
    with pytest.raises(StopIteration):
        hook.send(None)

    try:
        case = project_conftest._test_results["test_cases"][0]
        assert raw_ioc not in str(case)
        assert "原始异常文本已隐藏" in case["error_message"]
        assert "截图、视频和 trace" in case["error_traceback"]
        assert case["screenshot"] is None
    finally:
        recorder.clear()
        project_conftest._test_results.clear()
        project_conftest._test_results.update(original)


def test_threat_report_boundary_drops_injected_artifact_fields(
    project_conftest, tmp_path
):
    screenshot_dir = tmp_path / "screenshots"
    output_dir = tmp_path / "output"
    screenshot_dir.mkdir()
    output_dir.mkdir()
    (screenshot_dir / "test_threat_intelligence_comprehensive_failure.png").write_bytes(
        b"not-safe"
    )
    results = {
        "total": 1,
        "passed": 0,
        "failed": 1,
        "skipped": 0,
        "test_cases": [{
            "name": "安全中心-威胁情报中心综合测试",
            "original_name": "test_threat_intelligence_comprehensive[chromium]",
            "status": "failed",
            "steps": [],
            "screenshot": "data:image/png;base64/raw-ioc",
            "screenshot_path": "private.png",
            "video_path": "private.webm",
            "trace_path": "private.zip",
            "extra": [{"type": "image", "content": "raw-ioc"}],
        }],
    }

    json_path = project_conftest._dump_test_results_json(
        results, str(output_dir), str(screenshot_dir), str(tmp_path)
    )
    serialized = Path(json_path).read_text(encoding="utf-8")
    assert "private.png" not in serialized
    assert "raw-ioc" not in serialized
    assert '"screenshot_path": ""' in serialized

    sanitized = project_conftest._sanitize_report_payload(results)
    case = sanitized["test_cases"][0]
    assert case["screenshot"] == ""
    assert case["video_path"] == ""
    assert case["trace_path"] == ""
    assert case["extra"] == []
