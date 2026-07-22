import json
from pathlib import Path
from types import SimpleNamespace

from pages.device_setting.alg_setting_page import AlgSettingPage
from utils.backend_verifier import BackendVerifier
from utils.replay_commands import build_verification_commands


ROOT = Path(__file__).resolve().parents[2]


def test_alg_page_contract_matches_real_singleton_ui():
    assert AlgSettingPage.PAGE_URL == "/#/equipmentSetting/advancedManagement"
    assert AlgSettingPage.FUNC_NAME == "alg"
    assert AlgSettingPage.BACKEND_SCRIPT == "/usr/ikuai/script/alg.sh"
    assert AlgSettingPage.BOOLEAN_FIELDS == (
        "support_ftp", "support_tftp", "support_sip", "support_h323"
    )
    assert AlgSettingPage.PORT_FIELDS == ("ftp_ports", "tftp_ports", "sip_ports")


def test_alg_is_wired_to_fixture_marker_gui_and_chinese_report_name():
    conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    pytest_ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    gui = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    excel = (ROOT / "utils" / "test_results_to_excel.py").read_text(encoding="utf-8")
    node = (
        "device_setting/test_alg_setting_comprehensive.py::"
        "TestAlgSettingComprehensive::test_alg_setting_comprehensive"
    )

    assert "def alg_setting_page_logged_in(" in conftest
    assert "test_alg_setting_comprehensive': '设备设置-高级管理-ALG设置'" in conftest
    assert "alg_setting: 设备设置-高级管理-ALG设置模块测试" in pytest_ini
    assert node in gui
    assert '"alg_setting": "设备设置-高级管理-ALG设置"' in excel


def test_alg_backend_contains_real_l5_positive_negative_and_exact_cleanup():
    source = (ROOT / "utils" / "backend_verifier.py").read_text(encoding="utf-8")
    block = source.split("    def run_alg_ftp_probe(", 1)[1]

    assert "sudo ip route replace" in block
    assert "PORT {client_ip.replace('.', ',')}" in block
    assert "helper=ftp-{control_port}" in block
    assert "conntrack -L expect" in block
    assert "active_data_delivered" in block
    assert "peer_host = peer_management_host" in block
    assert "data_send_rc=$?" in block
    assert "if expect_enabled:" in block
    assert "not observations[\"helper_attached\"]" in block
    assert "while iptables -C INPUT" in block
    assert "sudo ip route del" in block


def test_alg_flow_guards_and_repairs_lan_nat_after_runtime_changes():
    backend_source = (ROOT / "utils" / "backend_verifier.py").read_text(encoding="utf-8")
    test_source = (
        ROOT / "tests" / "device_setting" / "test_alg_setting_comprehensive.py"
    ).read_text(encoding="utf-8")

    assert "def verify_alg_nat_health(" in backend_source
    assert "def repair_alg_nat_runtime(" in backend_source
    assert "/usr/ikuai/script/basic.sh __set_ipt_nat" in backend_source
    assert "def guard_nat(" in test_source
    assert "guard_nat(f\"保存后-{label}\")" in test_source
    assert "guard_nat(\"alg.sh init后\")" in test_source
    assert "guard_nat(\"finally恢复后\", cleanup=True)" in test_source
    assert 'snapshot.get("nat_health_passed") is True' in test_source


def test_alg_manual_commands_are_copy_ready_and_hide_internal_probe_scripts():
    backend = BackendVerifier()
    result = SimpleNamespace(
        passed=True,
        message="FTP ALG真实功能闭环通过",
        details={},
        raw_output=json.dumps({"helper_attached": True}, ensure_ascii=False),
    )
    commands = build_verification_commands(
        backend,
        backend.run_alg_ftp_probe,
        args=(2121, 50000, True),
        result=result,
    )

    assert commands
    command_text = "\n".join(item["command"] for item in commands)
    assert "ip route get" in command_text
    assert "conntrack -L -p tcp" in command_text
    assert "conntrack -L expect" in command_text
    assert "tcpdump -ni wan1" in command_text
    assert "base64" not in command_text
    assert "socat TCP-LISTEN" not in command_text
    assert "iptables -I INPUT" not in command_text
    assert all(item["copy_ready"] for item in commands)
    assert all(item["contains_secret"] is False for item in commands)

    nat_commands = build_verification_commands(
        backend,
        backend.verify_alg_nat_health,
        result=SimpleNamespace(passed=True, message="ok", details={}),
    )
    assert nat_commands
    nat_text = "\n".join(item["command"] for item in nat_commands)
    assert "ping -I 192.168.148.2" in nat_text
    assert "conntrack -L -p icmp" in nat_text
    assert build_verification_commands(
        backend,
        backend.repair_alg_nat_runtime,
        result=SimpleNamespace(passed=True, message="ok", details={}),
    ) == []
