import json
from pathlib import Path
from types import SimpleNamespace

from pages.device_setting.kernel_setting_page import KernelSettingPage
from utils.backend_verifier import BackendVerifier
from utils.replay_commands import build_verification_commands


ROOT = Path(__file__).resolve().parents[2]


def test_kernel_setting_page_matches_real_singleton_contract():
    assert KernelSettingPage.PAGE_URL == "/#/equipmentSetting/advancedManagement"
    assert KernelSettingPage.FUNC_NAME == "ik_sysctl"
    assert KernelSettingPage.BACKEND_SCRIPT == "/usr/ikuai/script/ik_sysctl.sh"
    assert len(KernelSettingPage.TIMEOUT_FIELDS) == 11
    assert KernelSettingPage.BOOLEAN_FIELDS == ("bbr",)
    assert set(KernelSettingPage.FIELD_RANGES) == set(KernelSettingPage.TIMEOUT_FIELDS)
    assert KernelSettingPage.FIELD_RANGES["established_timeout"] == (600, 86400)
    assert KernelSettingPage.FIELD_RANGES["udp_stream_timeout"] == (30, 1800)


def test_kernel_setting_is_wired_to_fixture_gui_config_and_reports():
    conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    pytest_ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    gui = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    runner = (ROOT / "gui" / "test_runner.py").read_text(encoding="utf-8")
    config = (ROOT / "config" / "config.py").read_text(encoding="utf-8")
    dialog = (ROOT / "gui" / "config_dialog.py").read_text(encoding="utf-8")
    excel = (ROOT / "utils" / "test_results_to_excel.py").read_text(encoding="utf-8")
    node = (
        "device_setting/test_kernel_setting_comprehensive.py::"
        "TestKernelSettingComprehensive::test_kernel_setting_comprehensive"
    )

    assert "def kernel_setting_page_logged_in(" in conftest
    assert "test_kernel_setting_comprehensive': '设备设置-高级管理-内核设置'" in conftest
    assert "kernel_setting: 设备设置-高级管理-内核设置模块测试" in pytest_ini
    assert gui.count(node) == 2
    assert '"kernel_setting": "设备设置-高级管理-内核设置"' in excel
    assert 'env["SSH_KERNEL_PEER_HOST"]' in runner
    assert "kernel_peer_host" in config
    assert "内核设置L5对端" in dialog


def test_kernel_backend_has_all_proc_mappings_l5_and_exact_cleanup():
    source = (ROOT / "utils" / "backend_verifier.py").read_text(encoding="utf-8")
    block = source.split(
        "# ==================== 设备设置 > 高级管理 > 内核设置", 1
    )[1]

    for token in (
        "nf_conntrack_tcp_timeout_syn_recv",
        "nf_conntrack_tcp_timeout_syn_sent",
        "nf_conntrack_tcp_timeout_established",
        "nf_conntrack_tcp_timeout_fin_wait",
        "nf_conntrack_tcp_timeout_last_ack",
        "nf_conntrack_tcp_timeout_close_wait",
        "nf_conntrack_tcp_timeout_time_wait",
        "nf_conntrack_tcp_timeout_close",
        "nf_conntrack_udp_timeout",
        "nf_conntrack_udp_timeout_stream",
        "nf_conntrack_icmp_timeout",
        "tcp_congestion_control",
    ):
        assert token in block
    assert "def run_kernel_conntrack_probe(" in block
    assert "sudo ip route replace" in block
    assert '"tcp_established"' in block
    assert '"udp_one_way_expired"' in block
    assert '"udp_stream_timeout_uses_config"' in block
    assert '"icmp_expired"' in block
    assert "for index in range(4):" in block
    assert '"echo_count=4"' in block
    assert "probe_result.raw_output = json.dumps(details" in block
    assert "def restore_kernel_environment(" in block
    assert "def verify_kernel_environment_unchanged(" in block
    assert "rm -f /tmp/ikuai_kernel_*" in block


def test_kernel_manual_commands_are_read_only_copy_ready_and_hide_probe_scripts():
    backend = BackendVerifier()
    result = SimpleNamespace(
        passed=True,
        message="L5通过",
        details={
            "peer": "10.66.0.57",
            "ports": {
                "tcp_source": 31001,
                "udp_source": 31002,
                "udp_one_destination": 31003,
                "udp_echo_destination": 31004,
            },
        },
        raw_output=json.dumps({"checks": {"tcp_established": True}}),
    )
    commands = build_verification_commands(
        backend,
        backend.run_kernel_conntrack_probe,
        args=([31001, 31002, 31003, 31004],),
        result=result,
    )

    assert commands
    text = "\n".join(item["command"] for item in commands)
    assert "ip route get 10.66.0.57" in text
    assert "conntrack -L -p tcp" in text
    assert "conntrack -L -p udp" in text
    assert "conntrack -L -p icmp" in text
    assert "tcp_congestion_control" in text
    assert "base64" not in text
    assert "python3" not in text
    assert "ip route replace" not in text
    assert " rm -f " not in text
    assert all(item["copy_ready"] for item in commands)
    assert all(item["contains_secret"] is False for item in commands)

    assert build_verification_commands(
        backend,
        backend.restore_kernel_environment,
        args=({"row": {"id": 1}},),
        result=SimpleNamespace(passed=True, message="ok", details={}),
    ) == []


def test_kernel_packaged_collect_smoke_is_wired():
    runner = (ROOT / "gui" / "test_runner.py").read_text(encoding="utf-8")
    main = (ROOT / "main.py").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "PyInstaller打包指南.md").read_text(encoding="utf-8")

    assert "--collect-kernel-setting-smoke" in runner
    assert "IKUAI_PACKAGED_KERNEL_SETTING_SMOKE_RESULT" in runner
    assert "pages.device_setting.kernel_setting_page" in runner
    assert "run_packaged_kernel_setting_collect_smoke" in main
    assert "--collect-kernel-setting-smoke" in guide
