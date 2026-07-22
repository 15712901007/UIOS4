from __future__ import annotations

import importlib
import json
import os
import sys

import pytest


OSPF_NODE = (
    "network/test_ospf_comprehensive.py::"
    "TestOspfComprehensive::test_ospf_comprehensive"
)


def test_gui_tree_contains_one_exact_ospf_node():
    from gui.main_window import MainWindow
    modules = MainWindow._load_test_modules(None)
    ospf = modules["网络配置"]["children"]["OSPF"]
    assert ospf["testcases"] == ["test_ospf_comprehensive.py::TestOspfComprehensive::test_ospf_comprehensive"]
    assert ospf["groups"]["综合测试（推荐）"] == ospf["testcases"]


def test_main_dispatches_ospf_smoke_before_gui(monkeypatch):
    import main
    from gui import test_runner
    called = []
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", ["iKuai-test.exe", "--collect-ospf-smoke"])
    monkeypatch.setattr(
        test_runner, "run_packaged_ospf_collect_smoke",
        lambda: called.append(True) or 0,
    )
    with pytest.raises(SystemExit) as exc:
        main._dispatch_packaged_ospf_smoke()
    assert exc.value.code == 0
    assert called == [True]


def test_packaged_ospf_collect_is_exact(monkeypatch, tmp_path):
    import pytest as pytest_module
    from gui import test_runner
    bundle = tmp_path / "bundle"
    runtime = tmp_path / "runtime"
    test_file = bundle / "tests" / "network" / "test_ospf_comprehensive.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("# collect fixture\n", encoding="utf-8")
    runtime.mkdir()
    result_path = runtime / "ospf.json"
    monkeypatch.setattr(test_runner, "is_frozen", lambda: True)
    monkeypatch.setattr(test_runner, "get_bundle_root", lambda: str(bundle))
    monkeypatch.setattr(test_runner, "get_runtime_root", lambda: str(runtime))
    real_import = importlib.import_module

    def fake_import(name, package=None):
        if name in {
            "pytest", "playwright.sync_api", "paramiko", "jinja2", "yaml",
            "openpyxl", "pages.network.ospf_page", "utils.backend_verifier",
        }:
            return object()
        return real_import(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    absolute = str(bundle / "tests") + "/" + OSPF_NODE

    def fake_main(args, plugins):
        assert args[-1].replace("\\", "/").endswith("tests/" + OSPF_NODE)
        session = type("Session", (), {
            "items": [type("Item", (), {"nodeid": absolute})()]
        })()
        plugins[0].pytest_collection_finish(session)
        print("collected 1 item")
        return 0

    monkeypatch.setattr(pytest_module, "main", fake_main)
    assert test_runner.run_packaged_ospf_collect_smoke(str(result_path)) == 0
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    assert payload["service"] == "ospf"
    assert payload["collected"] == 1
    assert payload["pytest_exit_code"] == 0
    assert payload["expected_node_found"] is True
    assert payload["success"] is True
    assert payload["test_target"] == "tests/" + OSPF_NODE
