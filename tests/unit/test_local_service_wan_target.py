from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

from utils.backend_verifier import BackendVerifier


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOCAL_SERVICE_TESTS = (
    "test_ftp_server_comprehensive.py",
    "test_http_server_comprehensive.py",
    "test_samba_server_comprehensive.py",
    "test_snmp_server_comprehensive.py",
)


class _CommandStub:
    def __init__(self, responses):
        self.responses = responses
        self.commands = []

    def exec(self, command, timeout=30):
        self.commands.append(command)
        for marker, response in self.responses.items():
            if marker in command:
                return response
        raise AssertionError(f"unexpected command: {command}")


def _backend_with_route(route: str):
    backend = object.__new__(BackendVerifier)
    backend._router = _CommandStub({
        "addr show dev wan1": (
            "21: wan1    inet 10.66.0.45/24 brd 10.66.0.255 "
            "scope global wan1\n"
        ),
        "link show dev wan1": (
            "21: wan1: <BROADCAST,MULTICAST,UP,LOWER_UP> "
            "mtu 1500 state UP\n"
        ),
    })
    backend._client = _CommandStub({
        "link show dev enp2s0": (
            "4: enp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> "
            "mtu 1500 state UP\n"
        ),
        "route get 10.66.0.45": route,
    })
    backend.connect_router = lambda: None
    backend.connect_client = lambda: None
    return backend


def test_local_service_wan_target_uses_runtime_dut_wan1():
    backend = _backend_with_route(
        "10.66.0.45 dev enp2s0 src 10.66.0.18 uid 1000\n"
    )

    result = backend.verify_local_service_wan_target("enp2s0")

    assert result.passed is True
    assert result.details["host"] == "10.66.0.45"
    assert result.details["route_dev"] == "enp2s0"
    assert "10.66.0.150" not in result.raw_output


def test_local_service_wan_target_rejects_lan_route_mismatch():
    backend = _backend_with_route(
        "10.66.0.45 via 192.168.148.1 dev ens11 src 192.168.148.2\n"
    )

    result = backend.verify_local_service_wan_target("enp2s0")

    assert result.passed is False
    assert result.details["host"] == "10.66.0.45"
    assert result.details["checks"]["client_route_uses_expected_iface"] is False


def test_local_service_comprehensive_tests_have_no_stale_wan_target():
    base = PROJECT_ROOT / "tests" / "advanced_service"
    sources = {
        name: (base / name).read_text(encoding="utf-8")
        for name in LOCAL_SERVICE_TESTS
    }

    for source in sources.values():
        assert "10.66.0.150" not in source
        assert "WAN_HOST" not in source
        assert "verify_local_service_wan_target" in source

    assert "L5-WAN允许基线" in sources["test_ftp_server_comprehensive.py"]
    assert "L5-WAN允许基线" in sources["test_http_server_comprehensive.py"]
    assert "L5-WAN允许基线" in sources["test_samba_server_comprehensive.py"]

    assert "10.66.0.150" not in inspect.getsource(BackendVerifier.run_ftp_probe)
    assert "10.66.0.150" not in inspect.getsource(BackendVerifier.run_samba_probe)


def test_ftp_daemon_uses_exact_pid_when_busybox_ps_truncates_command():
    backend = object.__new__(BackendVerifier)
    backend._router = _CommandStub({
        "echo __FTP_PIDS__": (
            "PID USER COMMAND\n"
            "__FTP_PIDS__\n23143\n"
            "__FTP_FD_OWNER__\n"
            "lrwx------ 1 root root 64 0 -> socket:[7452981]\n"
            "__FTP_PROC_OWNER__\n"
            "1: 00000000000000000000000000000000:0849 "
            "00000000000000000000000000000000:0000 0A "
            "00000000:00000000 00:00000000 00000000 0 0 "
            "7452981 1 0000000000000000 100 0 0 10 0\n"
        ),
    })
    backend.connect_router = lambda: None
    backend.verify_ftp_listener = lambda *args, **kwargs: SimpleNamespace(
        passed=True,
        message="TCP/2121正在监听（期望监听）",
        details={"listening": True},
        raw_output="tcp/2121 LISTEN",
    )

    result = backend.verify_ftp_daemon(True, port=2121, wait_seconds=0)

    assert result.passed is True
    assert result.details["running"] is True
    assert result.details["pids"] == ["23143"]


def test_ftp_daemon_treats_pid_without_listener_as_draining_worker():
    backend = object.__new__(BackendVerifier)
    backend._router = _CommandStub({
        "echo __FTP_PIDS__": (
            "PID USER COMMAND\n"
            "__FTP_PIDS__\n23144\n"
            "__FTP_FD_OWNER__\n"
            "lrwx------ 1 root root 64 0 -> socket:[7452982]\n"
            "__FTP_PROC_OWNER__\n"
            "1: 0100007F:1234 0100007F:5678 01 00000000:00000000 "
            "00:00000000 00000000 0 0 7452982 1 0000000000000000\n"
        ),
    })
    backend.connect_router = lambda: None

    result = backend.verify_ftp_daemon(False, port=None, wait_seconds=0)

    assert result.passed is True
    assert result.details["running"] is False
    assert result.details["residual_pids_without_listener"] == ["23144"]
