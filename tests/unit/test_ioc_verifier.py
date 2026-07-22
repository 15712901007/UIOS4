from __future__ import annotations

import json

import pytest

from utils.ioc_verifier import IocEnvironmentSnapshot, IocVerifier


class _FakeSSH:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.commands = []

    def exec(self, command, timeout=20, probe_console=False):
        self.commands.append(command)
        for marker, output in self.outputs.items():
            if marker in command:
                return output
        return ""


class _FakeBackend:
    def __init__(self, ssh):
        self._router = ssh
        self.connect_calls = 0

    def connect_router(self):
        self.connect_calls += 1


def test_read_contract_is_allowlisted_and_redacts_identifiers():
    ssh = _FakeSSH({
        "ioc_syslog show TYPE=data": json.dumps({
            "data": [{
                "server": "192.0.2.10",
                "hostname": "sensor.example.invalid",
                "enabled": "0",
            }]
        }),
    })
    verifier = IocVerifier(_FakeBackend(ssh))

    result = verifier.read_contract("syslog")

    assert result["data"][0]["server"]["present"] is True
    assert result["data"][0]["hostname"]["present"] is True
    assert "192.0.2.10" not in str(result)
    assert "sensor.example.invalid" not in str(result)
    assert any("ioc_syslog" in command for command in ssh.commands)

    with pytest.raises(ValueError):
        verifier.read_contract("arbitrary")


def test_alert_total_is_a_separate_fixed_contract():
    function, args, required = IocVerifier.API_CONTRACTS["alert_total"]
    assert (function, args, required) == (
        "ioc_alert",
        "show TYPE=total",
        ("total",),
    )


def test_syslog_test_connection_uses_fixed_read_only_dispatch():
    ssh = _FakeSSH({
        "ioc_syslog show TYPE=test_connection": json.dumps({
            "conn_status": "not_configured"
        }),
    })
    verifier = IocVerifier(_FakeBackend(ssh))

    assert verifier.read_syslog_test_connection() == {
        "conn_status": "not_configured"
    }
    assert all(";" not in command for command in ssh.commands)


def test_public_table_helpers_return_redacted_rows_and_only_matching_ids(monkeypatch):
    ssh = _FakeSSH()
    verifier = IocVerifier(_FakeBackend(ssh))

    def fake_raw_query(_ssh, table):
        assert table == "ioc_blacklist"
        return [
            {"id": "7", "value": "198.51.100.7", "comment": "probe"},
            {"id": "8", "value": "198.51.100.7", "comment": "second"},
            {"id": "9", "value": "other.example.invalid", "comment": "other"},
        ]

    monkeypatch.setattr(verifier, "_raw_query", fake_raw_query)
    rows = verifier.read_table("ioc_blacklist")
    assert rows[0]["value"]["present"] is True
    assert "198.51.100.7" not in str(rows)
    assert verifier.find_list_entry_ids("blacklist", "198.51.100.7") == ["7", "8"]
    assert verifier.find_list_entry_ids("ioc_blacklist", "missing") == []
    assert verifier.find_list_entry_ids("blacklist", "") == []

    with pytest.raises(ValueError):
        verifier.read_table("not_a_table")
    with pytest.raises(ValueError):
        verifier.find_list_entry_ids("event_log", "x")


def test_snapshot_table_count_is_public_but_does_not_expose_private_rows():
    snapshot = IocEnvironmentSnapshot(
        public={"table_counts": {"ioc_search_history": 2}},
        private={"tables": {"ioc_search_history": [{"search_value": "secret"}]}},
    )
    assert IocVerifier.snapshot_table_count(snapshot, "ioc_search_history") == 2
    assert "secret" not in repr(snapshot)

    with pytest.raises(ValueError):
        IocVerifier.snapshot_table_count(snapshot, "unknown")
    with pytest.raises(TypeError):
        IocVerifier.snapshot_table_count({}, "ioc_search_history")
