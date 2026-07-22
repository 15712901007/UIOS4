"""基础设置后端验证器的离线安全回归。"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

from utils.backend_verifier import BackendVerifier


def _verifier_without_connections() -> BackendVerifier:
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._ssh_config = SimpleNamespace(iperf3_server="10.66.0.40")
    verifier._router = None
    verifier._client = None
    return verifier


def test_basic_public_row_never_contains_private_values():
    row = {field: 0 for field in BackendVerifier.BASIC_FIELDS}
    row.update({
        "id": 1,
        "hostname": "synthetic-private-host",
        "ntpserver_list": "synthetic.private.invalid",
        "time_zone_full": "0800",
        "listenport": "lan1",
        "backport": "wan1",
    })

    public = BackendVerifier._basic_public_row(row)
    serialized = json.dumps(public, ensure_ascii=False)

    assert "hostname" not in public
    assert "ntpserver_list" not in public
    assert "synthetic-private-host" not in serialized
    assert "synthetic.private.invalid" not in serialized
    assert public["hostname_length"] == len("synthetic-private-host")
    assert public["ntpserver_configured"] is True


def test_basic_schema_defaults_cover_every_singleton_field():
    assert set(BackendVerifier.BASIC_SCHEMA_DEFAULTS) == set(
        BackendVerifier.BASIC_FIELDS
    )


def test_basic_client_artifact_probe_does_not_match_its_own_shell():
    verifier = _verifier_without_connections()

    class FakeClient:
        def __init__(self):
            self.commands = []

        def exec(self, command, timeout=15):
            self.commands.append(command)
            if command.startswith("ip route show exact"):
                return ""
            if command.startswith("ip route get"):
                return "10.66.0.40 dev management0 src 10.66.0.18"
            return ""

    client = FakeClient()
    verifier._client = client
    verifier.connect_client = lambda: None

    state = verifier._basic_client_state("10.66.0.40")

    assert state["artifact_lines"] == []
    assert any("find /tmp" in command for command in client.commands)
    assert any("python3 /tmp/[i]kuai-basic-" in command for command in client.commands)


def test_get_client_lan_info_does_not_log_network_identifiers(caplog):
    verifier = _verifier_without_connections()
    private_iface = "synthetic-private-iface"
    private_ip = "192.0.2.91"
    private_hardware_address = "02:11:22:33:44:91"

    class FakeClient:
        def exec(self, command, timeout=15):
            if command.startswith("ip route get"):
                return f"192.0.2.1 dev {private_iface} src {private_ip}"
            if command.startswith("cat /sys/class/net/"):
                return private_hardware_address
            return ""

    verifier._client = FakeClient()
    verifier.connect_client = lambda: None

    with caplog.at_level(logging.INFO, logger="utils.backend_verifier"):
        info = verifier.get_client_lan_info("192.0.2.1")

    assert info == {
        "iface": private_iface,
        "ip": private_ip,
        "mac": private_hardware_address,
    }
    log_text = caplog.text
    assert private_iface not in log_text
    assert private_ip not in log_text
    assert private_hardware_address not in log_text
    assert "iface_present=True" in log_text
    assert "ip_present=True" in log_text
    assert "hardware_address_present=True" in log_text


def test_basic_environment_fingerprint_includes_singleton_and_router_routes():
    verifier = _verifier_without_connections()
    row = {field: 0 for field in BackendVerifier.BASIC_FIELDS}
    row.update({"id": 1, "hostname": "synthetic", "ntpserver_list": ""})
    files = {
        "cache_content": "safe=1", "tz": "UTC-0800",
        "hosts_hostname": "127.0.0.1 synthetic",
        "kernel_hostname": "synthetic", "localtime_link": "/tmp/tz",
    }
    iptables = {"autonat": "", "pre_fullcone": "", "post_fullcone": "",
                "nonat": "", "fastoffload": ""}
    process = {"processes": [{"pid": 1, "command": "openresty"}]}
    summary = {"sdwan_bypass": "off"}
    routes = {"main_routes": "default dev wan1", "policy_rules": "0: from all lookup local"}
    clock = {
        "router_epoch": 1000, "client_epoch": 1000,
        "router_client_offset": 0, "rtc_system_delta": 1,
        "rtc_client_offset": 1, "hardware_clock_available": True,
    }
    integrity = {"passwd": "a", "crontab": "b", "modules": "c", "ipsets": "d"}
    topology = {"management_iface": "wan1", "client_management_separate": True}
    client = {"server_ip": "10.66.0.40", "route": "", "route_get": "", "artifact_lines": []}
    snapshot = {
        "row": dict(row), "row_count": 1, "files": dict(files),
        "iptables": dict(iptables), "process": process, "summary": summary,
        "routes": dict(routes), "clock": dict(clock),
        "integrity": dict(integrity), "topology": dict(topology),
        "client": client,
    }
    verifier._basic_read_row = lambda: dict(row)
    verifier._basic_row_count = lambda: 1
    verifier._basic_file_state = lambda: dict(files)
    verifier._basic_iptables_state = lambda: dict(iptables)
    verifier._basic_process_state = lambda: process
    verifier._basic_summary_state = lambda: summary
    verifier._basic_route_state = lambda: dict(routes)
    verifier._basic_clock_state = lambda: dict(clock)
    verifier._basic_integrity_state = lambda: dict(integrity)
    verifier._basic_link_topology_state = lambda: dict(topology)
    verifier._basic_client_state = lambda _server: dict(client)

    assert verifier.verify_basic_environment_unchanged(snapshot).passed is True

    verifier._basic_route_state = lambda: {
        "main_routes": "default dev wan2", "policy_rules": routes["policy_rules"]
    }
    changed = verifier.verify_basic_environment_unchanged(snapshot)
    assert changed.passed is False
    assert changed.details["checks"]["router_routes"] is False


def test_nat4_fullcone_negative_cannot_pass_without_conntrack_mapping(monkeypatch):
    verifier = _verifier_without_connections()

    class FakeRemoteFile:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def write(self, _value):
            return None

    class FakeSftp:
        def file(self, _path, _mode):
            return FakeRemoteFile()

        def chmod(self, _path, _mode):
            return None

        def close(self):
            return None

    class FakeTransport:
        def open_sftp(self):
            return FakeSftp()

    class FakeClient:
        def __init__(self):
            self._client = FakeTransport()

        def exec(self, command, timeout=15):
            if command.startswith("nohup python3"):
                return "123"
            if command.startswith("cat /tmp/ikuai-basic-") and command.endswith("2>/dev/null"):
                return "ready"
            if command.startswith("ip route get"):
                return "10.66.0.150 dev management0 src 10.66.0.18"
            return ""

    class FakeRouter:
        def exec(self, _command, timeout=15):
            return ""

    verifier._client = FakeClient()
    verifier._router = FakeRouter()
    verifier.connect_client = lambda: None
    verifier.connect_router = lambda: None
    verifier.verify_basic_client_route = lambda *args, **kwargs: SimpleNamespace(
        passed=True
    )
    monkeypatch.setattr("utils.backend_verifier.time.sleep", lambda _seconds: None)

    result = verifier.run_basic_fullcone_probe(expect_fullcone=False)

    assert result.passed is False
    assert "conntrack" in result.message


def test_basic_client_route_requires_router_gateway_not_only_iface_and_source():
    verifier = _verifier_without_connections()

    class FakeClient:
        def __init__(self):
            self.output = (
                "10.66.0.40 via 192.168.148.1 dev ens11 src 192.168.148.2"
            )

        def exec(self, _command, timeout=15):
            return self.output

    client = FakeClient()
    verifier._client = client
    verifier.connect_client = lambda: None

    assert verifier.verify_basic_client_route().passed is True

    client.output = "10.66.0.40 dev ens11 src 192.168.148.2"
    result = verifier.verify_basic_client_route()
    assert result.passed is False
    assert result.details["gateway_matches"] is False


def test_basic_bypass_runtime_does_not_invent_ac_b_argument():
    verifier = _verifier_without_connections()

    class FakeRouter:
        def exec(self, command, timeout=15):
            assert "notify.d" in command
            return "0\n"

    verifier._router = FakeRouter()
    verifier.connect_router = lambda: None
    verifier._basic_summary_state = lambda: {
        "sdwan_bypass": "off",
        "bypass_marker": False,
        "auth_switch": False,
        "auto_auth": False,
    }
    verifier._basic_process_state = lambda: {
        "processes": [{"pid": 7, "command": "AC -c /tmp/ac.conf"}]
    }
    verifier._samba_sqlite_query_line = lambda _sql: {"ac_server": "1"}

    result = verifier.verify_basic_link_runtime(1)

    assert result.passed is True
    assert result.details["checks"]["ac_service_state"] is True
    assert result.details["checks"]["no_unmodeled_notify_handlers"] is True
    assert result.details["ac_link_mode_argument_applicable"] is False


def test_basic_acceleration_accepts_iptables_normalized_connbytes_spacing():
    verifier = _verifier_without_connections()

    class FakeRouter:
        def exec(self, command, timeout=15):
            if command.startswith("awk "):
                return (
                    '__set_fast_nat() {\niptables -w -t mangle -F FASTOFFLOAD\n'
                    'local hardware="--hw"\nlocal hardware=""\n'
                    'iptables -w -t mangle -A FASTOFFLOAD '
                    '--connbytes=50 -j FLOWOFFLOAD $hardware\n}\n'
                )
            return (
                "__FLOWOFFLOAD__=1\n__CONNBYTES__=1\n"
                "__IFACES__=1\n__MODULE__=1\n"
            )

    verifier._router = FakeRouter()
    verifier.connect_router = lambda: None
    verifier._basic_read_row = lambda: {"fast_nat": 1}
    verifier._basic_file_state = lambda: {"cache": {"fast_nat": "1"}}
    verifier._basic_iptables_state = lambda include_counters=False: {
        "fastoffload": (
            "-N FASTOFFLOAD\n"
            "-A FASTOFFLOAD -p tcp+udp -m connbytes --connbytes 50 "
            "--connbytes-dir both --connbytes-mode packets -j FLOWOFFLOAD"
        ),
        "fastoffload_packets": 12,
    }

    result = verifier.verify_basic_acceleration_runtime(1)

    assert result.passed is True
    assert result.details["checks"]["packet_threshold_50"] is True
    assert result.details["database_fast_nat"] == 1
    assert result.details["cache_fast_nat"] == 1


def test_basic_route_probe_waits_for_tcpdump_ready_before_traffic(monkeypatch):
    verifier = _verifier_without_connections()
    events = []

    class FakeRouter:
        def exec(self, command, timeout=15):
            if command.startswith("tcpdump "):
                events.append("capture_started")
                assert "2>" in command
                return "321\n"
            if "grep -q 'listening on'" in command:
                events.append("capture_ready")
                return "READY\n"
            if command.startswith("cat "):
                return (
                    "IP 192.168.148.2 > 10.66.0.40: "
                    "ICMP echo request, id 1, seq 1"
                )
            return ""

    class FakeClient:
        def exec(self, command, timeout=15):
            if command.startswith("ping "):
                events.append("traffic_sent")
            return ""

    verifier._router = FakeRouter()
    verifier._client = FakeClient()
    verifier.connect_router = lambda: None
    verifier.connect_client = lambda: None
    verifier.verify_basic_client_route = lambda *args, **kwargs: SimpleNamespace(
        passed=True
    )
    monkeypatch.setattr("utils.backend_verifier.time.sleep", lambda _seconds: None)

    result = verifier.run_basic_route_mode_probe()

    assert result.passed is True
    assert result.details["capture_ready"] is True
    assert events.index("capture_ready") < events.index("traffic_sent")


def _run_fullcone_capture_fake(monkeypatch, *, expect_fullcone, lan_forward,
                               fullcone_counter_after):
    verifier = _verifier_without_connections()

    class FakeRemoteFile:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def write(self, _value):
            return None

    class FakeSftp:
        def file(self, _path, _mode):
            return FakeRemoteFile()

        def chmod(self, _path, _mode):
            return None

        def close(self):
            return None

    class FakeTransport:
        def open_sftp(self):
            return FakeSftp()

    class FakeClient:
        def __init__(self):
            self._client = FakeTransport()

        def exec(self, command, timeout=15):
            if command.startswith("nohup python3"):
                return "123\n"
            if command.startswith("cat /tmp/ikuai-basic-"):
                return "ready\n"
            if command.startswith("ip route get"):
                return "10.66.0.150 dev management0 src 10.66.0.18"
            return ""

    class FakeRouter:
        def __init__(self):
            self.counter_reads = 0

        def exec(self, command, timeout=15):
            if command.startswith("conntrack -L"):
                return (
                    "udp 17 src=192.168.148.2 dst=10.66.0.40 "
                    "sport=45000 dport=5201 src=10.66.0.40 "
                    "dst=10.66.0.150 sport=5201 dport=47000"
                )
            if command.startswith("iptables -w -t nat -L PRE_FULLCONE"):
                self.counter_reads += 1
                count = 0 if self.counter_reads == 1 else fullcone_counter_after
                return (
                    f"{count} 120 FULLCONENAT udp -- * * 0.0.0.0/0 0.0.0.0/0\n"
                    if expect_fullcone else ""
                )
            if command.startswith("tcpdump "):
                return "456\n"
            if "grep -q 'listening on'" in command:
                return "READY\n"
            if command.startswith("cat ") and ".wan.log" in command:
                return "WAN probe packet\n"
            if command.startswith("cat ") and ".lan.log" in command:
                return "LAN translated packet\n" if lan_forward else ""
            return ""

    verifier._client = FakeClient()
    verifier._router = FakeRouter()
    verifier.connect_client = lambda: None
    verifier.connect_router = lambda: None
    verifier.verify_basic_client_route = lambda *args, **kwargs: SimpleNamespace(
        passed=True
    )
    monkeypatch.setattr("utils.backend_verifier.time.sleep", lambda _seconds: None)

    return verifier.run_basic_fullcone_probe(expect_fullcone=expect_fullcone)


def test_nat4_control_requires_wan_ingress_and_no_lan_forward(monkeypatch):
    result = _run_fullcone_capture_fake(
        monkeypatch,
        expect_fullcone=False,
        lan_forward=False,
        fullcone_counter_after=0,
    )

    assert result.passed is True
    assert result.details["external_probe_seen_on_wan"] is True
    assert result.details["translated_packet_seen_on_lan"] is False
    assert result.details["fullcone_counter_delta"] == 0


def test_nat1_requires_wan_ingress_lan_forward_and_counter_increment(monkeypatch):
    result = _run_fullcone_capture_fake(
        monkeypatch,
        expect_fullcone=True,
        lan_forward=True,
        fullcone_counter_after=3,
    )

    assert result.passed is True
    assert result.details["external_probe_seen_on_wan"] is True
    assert result.details["translated_packet_seen_on_lan"] is True
    assert result.details["fullcone_counter_delta"] == 3
    assert result.details["application_socket_applicable"] is False
    assert "不适用" in result.details["application_socket_observation"]
