"""IPsec VPN GUI 与冻结 collect 接线回归（不访问被测设备）。"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest


IPSEC_NODE = (
    "network/test_ipsec_vpn_comprehensive.py::"
    "TestIpsecVpnComprehensive::test_ipsec_vpn_comprehensive"
)


def test_gui_tree_contains_one_exact_ipsec_node():
    from gui.main_window import MainWindow

    modules = MainWindow._load_test_modules(None)
    assert list(modules).count("虚拟专网") == 1
    vpn_children = modules["虚拟专网"]["children"]
    assert list(vpn_children).count("IPsec VPN") == 1
    ipsec = vpn_children["IPsec VPN"]
    expected = [
        "network/test_ipsec_vpn_comprehensive.py::"
        "TestIpsecVpnComprehensive::test_ipsec_vpn_comprehensive"
    ]
    assert ipsec["testcases"] == expected
    assert ipsec["groups"]["综合测试（推荐）"] == expected
    assert "VPN客户端" not in modules["网络配置"]["children"]


def test_ipsec_runner_targets_the_exact_node():
    from config.config import get_config
    from gui.test_runner import TestRunner

    command = TestRunner([IPSEC_NODE], get_config())._build_pytest_command()
    assert command[-1].replace("\\", "/").endswith("tests/" + IPSEC_NODE)
    assert sum(IPSEC_NODE in item.replace("\\", "/") for item in command) == 1


def test_main_dispatches_ipsec_smoke_before_gui(monkeypatch):
    import main
    from gui import test_runner

    source = Path(main.__file__).read_text(encoding="utf-8")
    assert source.index("\n_dispatch_packaged_ipsec_smoke()\n") < source.index(
        "from PySide6.QtWidgets import QApplication"
    )

    called = []
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", ["iKuai-test.exe", "--collect-ipsec-smoke"])
    monkeypatch.setattr(
        test_runner,
        "run_packaged_ipsec_collect_smoke",
        lambda: called.append(True) or 0,
    )

    with pytest.raises(SystemExit) as exc_info:
        main._dispatch_packaged_ipsec_smoke()

    assert exc_info.value.code == 0
    assert called == [True]


def test_packaged_ipsec_collect_is_exact_and_public_metadata_is_safe(
    monkeypatch, tmp_path
):
    import pytest as pytest_module
    from gui import test_runner

    bundle_root = tmp_path / "private-user-bundle"
    runtime_root = tmp_path / "private-user-runtime"
    test_file = bundle_root / "tests" / "network" / "test_ipsec_vpn_comprehensive.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("# packaged collect fixture\n", encoding="utf-8")
    runtime_root.mkdir()
    result_path = runtime_root / "ipsec_collect_smoke.json"

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
        "pages.network.ipsec_vpn_page",
        "utils.backend_verifier",
    }

    def import_smoke_dependency(name, package=None):
        if name in smoke_dependencies:
            return object()
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", import_smoke_dependency)
    absolute_node = str(bundle_root / "tests" / "network") + (
        "/test_ipsec_vpn_comprehensive.py::"
        "TestIpsecVpnComprehensive::test_ipsec_vpn_comprehensive"
    )
    fake_account = "ipsec-smoke-account-value"
    fake_password = "ipsec-smoke-private-value"

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
        print(f"warning cache at {bundle_root}")
        print(f"warning username={fake_account} password={fake_password}")
        print("collected 1 item")
        return 0

    monkeypatch.setattr(pytest_module, "main", fake_pytest_main)

    assert test_runner.run_packaged_ipsec_collect_smoke(str(result_path)) == 0
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload, ensure_ascii=False)

    assert payload["service"] == "ipsec"
    assert payload["pytest_exit_code"] == 0
    assert payload["collected"] == 1
    assert payload["expected_node_found"] is True
    assert payload["success"] is True
    assert payload["test_target"] == "tests/" + IPSEC_NODE
    assert payload["bundle_root"] is True
    assert payload["runtime_root"] is True
    assert payload["dependencies"]["pages.network.ipsec_vpn_page"] == "ok"
    assert payload["dependencies"]["utils.backend_verifier"] == "ok"
    assert "[包目录]" in payload["pytest_output"]
    assert "[已隐藏]" in payload["pytest_output"]
    assert str(bundle_root) not in serialized
    assert str(runtime_root) not in serialized
    assert fake_account not in serialized
    assert fake_password not in serialized
    assert os.path.isabs(payload["test_target"]) is False
