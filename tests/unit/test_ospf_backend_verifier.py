from __future__ import annotations

from config.config import SSHConfig, SSHHostConfig
from utils.backend_verifier import BackendVerifier
from utils.ospf_verifier import OspfEnvironmentSnapshot, OspfVerifier


class _FakeSSH:
    instances = []

    def __init__(self, config):
        self.config = config
        self._cmd_log = []
        self.__class__.instances.append(self)

    def connect(self):
        return None

    def close(self):
        return None

    def exec(self, command, timeout=30):
        self._cmd_log.append(command)
        if command.startswith("ps -eo"):
            return ""
        return ""


def _config():
    return SSHConfig(
        router=SSHHostConfig(
            host="192.0.2.1", username="runtime-user", password="runtime-value",
            console_username="runtime-console", console_password="runtime-console-value",
        ),
        client=SSHHostConfig(host="192.0.2.2"),
        ospf_peer_host="192.0.2.3",
        ospf_peer_recovery_host="192.0.2.5",
        router_recovery_host="192.0.2.4",
        router_lan_management_host="192.0.2.6",
    )


def test_peer_and_recovery_inherit_router_runtime_credentials(monkeypatch):
    from utils import backend_verifier as module
    _FakeSSH.instances.clear()
    monkeypatch.setattr(module, "SSHClient", _FakeSSH)
    backend = BackendVerifier(_config())
    backend.connect_ospf_peer()
    backend.connect_router_recovery()
    backend.connect_ospf_peer_recovery()
    backend.connect_router_lan_management()
    peer, recovery, peer_recovery, lan_management = _FakeSSH.instances
    assert peer.config.host == "192.0.2.3"
    assert recovery.config.host == "192.0.2.4"
    assert peer_recovery.config.host == "192.0.2.5"
    assert lan_management.config.host == "192.0.2.6"
    for target in (peer.config, recovery.config, peer_recovery.config, lan_management.config):
        assert target.username == backend._ssh_config.router.username
        assert target.password == backend._ssh_config.router.password
        assert target.console_username == backend._ssh_config.router.console_username
        assert target.console_password == backend._ssh_config.router.console_password


def test_ospf_sanitizer_hides_auth_values_and_hardware_addresses():
    source = {
        "auth_key": "runtime-only-value",
        "nested": {"md5_key": "another-runtime-value"},
        "text": "neighbor aa:bb:cc:dd:ee:ff\n ip ospf authentication-key hidden",
    }
    safe = OspfVerifier.sanitize_value(source)
    rendered = str(safe)
    assert "runtime-only-value" not in rendered
    assert "another-runtime-value" not in rendered
    assert "aa:bb:cc:dd:ee:ff" not in rendered.lower()
    assert safe["auth_key"] == {"configured": True, "length": 18}


def test_default_runtime_restore_never_invokes_init(monkeypatch):
    backend = type("Backend", (), {})()
    backend._router = _FakeSSH(SSHHostConfig(host="192.0.2.1"))
    backend.connect_router = lambda: None
    verifier = OspfVerifier(backend)
    snapshot = OspfEnvironmentSnapshot(
        private_tables={}, private_config="", private_client_config="",
        public={"processes": {name: [] for name in verifier.DAEMONS}},
    )
    result = verifier.restore_empty_router_runtime(snapshot)
    assert result.passed
    assert result.details["init_invoked"] is False
    assert all("ospf.sh init" not in command for command in backend._router._cmd_log)


def test_runtime_restore_compares_daemon_counts_not_reloaded_pids(monkeypatch):
    backend = type("Backend", (), {})()
    backend._router = _FakeSSH(SSHHostConfig(host="192.0.2.1"))
    backend.connect_router = lambda: None
    verifier = OspfVerifier(backend)
    snapshot = OspfEnvironmentSnapshot(
        private_tables={}, private_config="", private_client_config="",
        public={
            "processes": {
                "watchfrr": [101], "zebra": [102], "ospfd": [],
                "ospf6d": [], "staticd": [103],
            }
        },
    )
    monkeypatch.setattr(verifier, "_processes", lambda _ssh: {
        "watchfrr": [201], "zebra": [202], "ospfd": [],
        "ospf6d": [], "staticd": [203],
    })
    result = verifier.restore_empty_router_runtime(snapshot)
    assert result.passed
    assert result.details["stopped"] == []
    assert all("kill -TERM" not in command for command in backend._router._cmd_log)
