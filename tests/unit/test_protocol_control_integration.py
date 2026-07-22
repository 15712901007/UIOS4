import json
from pathlib import Path
from types import SimpleNamespace

from pages.device_setting.protocol_control_page import ProtocolControlPage
from utils.backend_verifier import BackendVerifier
from utils.replay_commands import build_verification_commands


ROOT = Path(__file__).resolve().parents[2]


def test_protocol_control_page_matches_real_singleton_contract():
    assert ProtocolControlPage.PAGE_URL == "/#/equipmentSetting/advancedManagement"
    assert ProtocolControlPage.FUNC_NAME == "core_control"
    assert ProtocolControlPage.BACKEND_SCRIPT == "/usr/ikuai/script/core_control.sh"
    assert ProtocolControlPage.MODE_PERFORMANCE == 0
    assert ProtocolControlPage.MODE_BALANCED == 1
    assert ProtocolControlPage.MODE_NAMES == {0: "性能模式", 1: "平衡模式"}


def test_protocol_control_is_wired_as_one_gui_node_and_chinese_name():
    conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    pytest_ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    gui = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    excel = (ROOT / "utils" / "test_results_to_excel.py").read_text(encoding="utf-8")
    node = (
        "device_setting/test_protocol_control_comprehensive.py::"
        "TestProtocolControlComprehensive::test_protocol_control_comprehensive"
    )

    assert "def protocol_control_page_logged_in(" in conftest
    assert "test_protocol_control_comprehensive': '设备设置-高级管理-协议控制'" in conftest
    assert "protocol_control: 设备设置-高级管理-协议控制模块测试" in pytest_ini
    assert gui.count(node) == 2
    assert '"protocol_control": "设备设置-高级管理-协议控制"' in excel


def test_protocol_control_backend_has_strict_l1_l5_and_exact_cleanup():
    source = (ROOT / "utils" / "backend_verifier.py").read_text(encoding="utf-8")
    block = source.split("# ==================== 设备设置 > 高级管理 > 协议控制", 1)[1]
    block = block.split("# ==================== 设备设置 > 高级管理 > ALG设置", 1)[0]

    assert "forward_mode_config" in block
    assert "readlink" in block
    assert "ik_cntl\\s+audit" in block
    assert '"audit": "enable" if expected_mode == 1 else "disable"' in block
    assert '"process.ik_url_auditd"' in block
    assert "def run_protocol_control_http_probe(" in block
    assert "sudo ip route replace" in block
    assert "audit_before_count" in block
    assert "audit_after_count" in block
    assert "dpi_cache" in block
    assert "snat_tuple_present" in block
    assert "kill -STOP" in block and "kill -CONT" in block
    assert "index($0,t)==0" in block
    assert "conntrack -D -s" in block


def test_protocol_control_gui_uses_realtime_step_output_contract():
    runner = (ROOT / "gui" / "test_runner.py").read_text(encoding="utf-8")
    gui = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    test_source = (
        ROOT / "tests" / "device_setting" /
        "test_protocol_control_comprehensive.py"
    ).read_text(encoding="utf-8")
    node = (
        "device_setting/test_protocol_control_comprehensive.py::"
        "TestProtocolControlComprehensive::test_protocol_control_comprehensive"
    )

    assert node in gui
    assert "PROTOCOL_CONTROL_TESTCASE = (" in runner
    assert 'env["IKUAI_LIVE_STEPS"] = "1"' in runner
    assert 'env["PYTHONUNBUFFERED"] = "1"' in runner
    assert 'print(f"    UI-{label}' in test_source
    assert 'print(f"    SSH-{label}' in test_source
    assert "with rec.step(" in test_source
    assert "finally-精确恢复协议控制快照" in test_source


def test_protocol_control_packaged_collect_smoke_is_wired():
    runner = (ROOT / "gui" / "test_runner.py").read_text(encoding="utf-8")
    main = (ROOT / "main.py").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "PyInstaller打包指南.md").read_text(encoding="utf-8")

    assert "--collect-protocol-control-smoke" in runner
    assert "IKUAI_PACKAGED_PROTOCOL_CONTROL_SMOKE_RESULT" in runner
    assert "pages.device_setting.protocol_control_page" in runner
    assert "run_packaged_protocol_control_collect_smoke" in main
    assert "--collect-protocol-control-smoke" in guide


def test_protocol_control_manual_commands_hide_mutations_and_are_copy_ready():
    backend = BackendVerifier()
    result = SimpleNamespace(
        passed=True,
        message="平衡模式HTTP闭环通过",
        details={
            "token": "IKPC_UNIT_123",
            "host": "ikpc_unit_123.example.test",
            "peer": "10.66.0.56",
            "port": 32123,
        },
        raw_output=json.dumps({"dpi_observed": True}, ensure_ascii=False),
    )
    commands = build_verification_commands(
        backend,
        backend.run_protocol_control_http_probe,
        args=(True,),
        result=result,
    )

    assert commands
    text = "\n".join(item["command"] for item in commands)
    assert "dpi_cache" in text
    assert "grep -aF ikpc_unit_123.example.test /etc/log/audit/stream/*" in text
    assert "conntrack -L" in text
    assert "start-stop-daemon" not in text
    assert "kill -STOP" not in text
    assert "kill -CONT" not in text
    assert " rm -f " not in text
    assert "ip route replace" not in text
    assert all(item["copy_ready"] for item in commands)
    assert all(item["contains_secret"] is False for item in commands)

    assert build_verification_commands(
        backend,
        backend.restore_protocol_control_environment,
        args=({"row": {"mode": 1}},),
        result=SimpleNamespace(passed=True, message="ok", details={}),
    ) == []
    assert build_verification_commands(
        backend,
        backend.repair_protocol_control_nat_runtime,
        result=SimpleNamespace(passed=True, message="ok", details={}),
    ) == []
