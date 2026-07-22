"""Read-only backend verification for the IOC threat-intelligence feature.

The threat-intelligence package is deliberately kept separate from the large
``BackendVerifier`` module.  This verifier only reads the router state.  It
does not call ``toggle``, ``save``, ``add``, ``edit``, ``del`` or any export /
import action.  Raw table rows are retained only in a private snapshot so a
test can compare a baseline after cleanup; public result objects contain
counts, hashes and redacted semantics only.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING

from utils.backend_verifier import VerifyResult

if TYPE_CHECKING:  # pragma: no cover - imports are only for type checkers
    from utils.backend_verifier import BackendVerifier, SSHClient


IOC_DB = "/etc/log/ioc_threat/ioc.db"
IOC_FUNCTION_DIR = "/usr/ikuai/function"
IOC_PACKAGE_DIR = "/tmp/ikpkg/ioc_threat"

# Keep this allow-list explicit.  Apart from preventing accidental SQL
# injection, it makes firmware schema drift visible in ``verify_contract``.
IOC_TABLES: Tuple[str, ...] = (
    "ioc_config",
    "ioc_syslog_config",
    "ioc_category_policy",
    "ioc_blacklist",
    "ioc_whitelist",
    "ioc_event_log",
    "ioc_threat_record",
    "ioc_search_history",
)

IOC_SCRIPT_FUNCTIONS: Mapping[str, Tuple[str, ...]] = {
    "ioc_overview": ("show", "toggle"),
    "ioc_homepage": ("show",),
    "ioc_monitor": ("show",),
    "ioc_detail": (
        "show",
        "generate_event",
        "add_remark",
        "clear_search_history",
        "EXPORT_terminals",
        "EXPORT_logs",
    ),
    "ioc_syslog": ("show", "save", "__show_test_connection"),
    "ioc_alert": ("show", "star", "edit", "del", "log_only", "EXPORT"),
    "ioc_policy": ("boot", "init", "show", "save", "clear_counter"),
    "ioc_blacklist": ("show", "add", "del", "edit", "EXPORT", "IMPORT"),
    "ioc_whitelist": ("show", "add", "del", "edit", "EXPORT", "IMPORT"),
    "ioc_report": (
        "show",
        "EXPORT_threat_discovery",
        "EXPORT_security_disposition",
        "EXPORT_high_risk_terminal",
        "EXPORT_threat_trend",
    ),
}

# API reads used by the six frontend tabs.  Every command is fixed, so it is
# safe to execute during a contract audit and safe to expose as a replay
# command.  ``ioc_homepage`` is used by the threat-situation tab while
# ``ioc_monitor`` is used by the monitoring tab.
READ_API_CONTRACTS: Mapping[str, Tuple[str, str, Tuple[str, ...]]] = {
    "overview": (
        "ioc_overview",
        "show TYPE=overview",
        ("overview",),
    ),
    "homepage": (
        "ioc_homepage",
        "show TYPE=ranking,threat_list,threat_list_total,high_processed "
        "time_range=today limit=0,10 ORDER_BY=last_hit ORDER=desc "
        "FILTER1=risk_level,==,3 FILTER2=status,==,0",
        ("ranking", "threat_list", "total", "high_processed"),
    ),
    "monitor_stats": (
        "ioc_monitor",
        "show TYPE=stats time_range=today",
        ("stats",),
    ),
    "monitor_list": (
        "ioc_monitor",
        "show TYPE=threat_list,threat_list_total,processed ORDER=desc "
        "FILTER1=status,==,0 time_range=today limit=0,10 ORDER_BY=last_hit",
        ("threat_list", "total", "processed"),
    ),
    "search_history": (
        "ioc_detail",
        "show ORDER_BY=search_time TYPE=search_history ORDER=desc",
        ("search_history",),
    ),
    "syslog": (
        "ioc_syslog",
        "show TYPE=data",
        ("data",),
    ),
    "alert_trend": (
        "ioc_alert",
        "show TYPE=trend time_range=7d",
        ("trend",),
    ),
    "alert_data": (
        "ioc_alert",
        "show limit=0,10 ORDER_BY=event_time TYPE=total,data ORDER=desc",
        ("total", "data"),
    ),
    "alert_total": (
        "ioc_alert",
        "show TYPE=total",
        ("total",),
    ),
    "alert_stats": (
        "ioc_alert",
        "show TYPE=stats",
        ("stats",),
    ),
    "alert_status": (
        "ioc_alert",
        "show TYPE=status_count",
        ("status_count",),
    ),
    "policy": (
        "ioc_policy",
        "show TYPE=total,data,member_count_total limit=0,500",
        ("total", "data", "member_count_total"),
    ),
    "blacklist": (
        "ioc_blacklist",
        "show TYPE=total,data limit=0,10",
        ("total", "data"),
    ),
    "whitelist": (
        "ioc_whitelist",
        "show TYPE=total,data limit=0,10",
        ("total", "data"),
    ),
    "report_discovery": (
        "ioc_report",
        "show TYPE=threat_discovery time_range=7d",
        ("threat_discovery",),
    ),
    "report_disposition": (
        "ioc_report",
        "show TYPE=security_disposition time_range=7d",
        ("security_disposition",),
    ),
    "report_high_risk": (
        "ioc_report",
        "show TYPE=high_risk_terminal time_range=7d",
        ("high_risk_terminal",),
    ),
    "report_trend": (
        "ioc_report",
        "show TYPE=threat_trend time_range=7d",
        ("threat_trend",),
    ),
}

IOC_REQUIRED_COLUMNS: Mapping[str, Tuple[str, ...]] = {
    "ioc_config": ("key", "value"),
    "ioc_syslog_config": (
        "id",
        "enabled",
        "server",
        "port",
        "protocol",
        "format",
        "hostname",
    ),
    "ioc_category_policy": (
        "category",
        "name",
        "monitor",
        "block",
        "alert",
        "member_count",
        "counter_reset_at",
        "updated_at",
    ),
    "ioc_blacklist": (
        "id",
        "value",
        "ioc_type",
        "ioc_port",
        "source",
        "duration",
        "expire_time",
        "comment",
        "created_at",
    ),
    "ioc_whitelist": ("id", "value", "comment", "created_at"),
    "ioc_event_log": (
        "id",
        "event_time",
        "event_source",
        "ioc_value",
        "ioc_type",
        "category",
        "risk_level",
        "action_taken",
        "src_ip",
        "status",
        "starred",
        "handled_at",
        "remark",
    ),
    "ioc_threat_record": (
        "id",
        "day_start",
        "ioc_value",
        "ioc_type",
        "category",
        "src_ip",
        "risk_level",
        "hit_count",
        "first_hit",
        "last_hit",
        "status",
    ),
    "ioc_search_history": ("id", "account", "search_value", "search_time"),
}

# Values that can identify a network asset or threat object.  They are hashed
# before entering any public result.  Do not add generic ``name`` here: IOC
# category names are safe semantics and useful in reports.
IOC_VALUE_FIELDS = {
    "value",
    "ioc_value",
    "search_value",
    "src_ip",
    "dst_ip",
    "src_mac",
    "dst_mac",
    "domain",
    "hostname",
    "username",
    "account",
    "server",
    "src_iface",
    "termname",
    "malicious_family",
    "remark",
    "comment",
}
SECRET_FIELDS = {
    "password",
    "passwd",
    "secret",
    "psk",
    "token",
    "cookie",
    "encrypted_payload",
    "private_key",
}
MAC_RE = re.compile(r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
IPV6_RE = re.compile(
    r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])"
)
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>'\"]+")
DOMAIN_RE = re.compile(
    r"(?i)(?<![/A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)
SECRET_ASSIGN_RE = re.compile(
    r"(?i)((?:password|passwd|secret|psk|token|cookie)\s*[=:]\s*)(\S+)"
)


@dataclass
class IocEnvironmentSnapshot:
    """Private restore material plus a report-safe public view."""

    public: Dict[str, Any]
    private: Dict[str, Any] = field(default_factory=dict, repr=False)


# A few callers use the shorter name while others follow the OSPF/IPsec
# convention.  Keep both names stable.
IocSnapshot = IocEnvironmentSnapshot


class IocVerifier:
    """Read-only IOC backend verifier bound to a ``BackendVerifier``."""

    DB = IOC_DB
    FUNCTION_DIR = IOC_FUNCTION_DIR
    PACKAGE_DIR = IOC_PACKAGE_DIR
    TABLES = IOC_TABLES
    SCRIPTS = tuple(IOC_SCRIPT_FUNCTIONS)
    API_CONTRACTS = READ_API_CONTRACTS
    DAEMONS = ("ioc_hit_eventd",)

    def __init__(self, backend: "BackendVerifier"):
        self.backend = backend
        self._last_snapshot: Optional[IocEnvironmentSnapshot] = None

    # ------------------------------------------------------------------
    # Redaction and low-level transport helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _sha(value: Any, length: int = 16) -> str:
        return hashlib.sha256(str(value or "").encode("utf-8", "replace")).hexdigest()[:length]

    @classmethod
    def redact_identifier(cls, value: Any) -> Dict[str, Any]:
        """Return presence/length/hash metadata without the original value."""

        rendered = "" if value is None else str(value)
        return {
            "present": bool(rendered),
            "length": len(rendered),
            "sha256": cls._sha(rendered),
        }

    @classmethod
    def sanitize_text(cls, value: Any) -> str:
        """Scrub obvious secrets and address literals from arbitrary text."""

        text = "" if value is None else str(value)
        text = SECRET_ASSIGN_RE.sub(r"\1<redacted>", text)
        text = MAC_RE.sub("<hardware-address-redacted>", text)
        # This is intentionally conservative for free-form command output.
        # Structured IOC fields use ``redact_identifier`` and retain no text.
        text = IPV4_RE.sub("<address-redacted>", text)
        text = IPV6_RE.sub("<address-redacted>", text)
        text = URL_RE.sub("<url-redacted>", text)
        text = DOMAIN_RE.sub("<domain-redacted>", text)
        return text

    @classmethod
    def sanitize_value(cls, value: Any, key: str = "") -> Any:
        """Recursively redact IOC/secret fields for public details."""

        lowered = str(key).lower().replace("-", "_")
        if lowered in SECRET_FIELDS or any(token in lowered for token in ("password", "passwd", "psk", "token", "secret")):
            rendered = "" if value is None else str(value)
            return {"configured": bool(rendered), "length": len(rendered)}
        if lowered in IOC_VALUE_FIELDS:
            return cls.redact_identifier(value)
        if isinstance(value, Mapping):
            return {str(k): cls.sanitize_value(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [cls.sanitize_value(item, key) for item in value]
        if isinstance(value, str):
            return cls.sanitize_text(value)
        return value

    @staticmethod
    def _router(backend: "BackendVerifier") -> "SSHClient":
        connect = getattr(backend, "connect_router", None)
        if callable(connect):
            connect()
        router = getattr(backend, "_router", None)
        if router is None:
            raise RuntimeError("router SSH connection is unavailable")
        return router

    @classmethod
    def _exec(cls, ssh: "SSHClient", command: str, timeout: int = 20) -> str:
        """Execute a fixed read-only command, tolerating simple test doubles."""

        try:
            return str(ssh.exec(command, timeout=timeout, probe_console=False) or "")
        except TypeError:
            return str(ssh.exec(command, timeout=timeout) or "")

    @staticmethod
    def _parse_line_records(output: str) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for raw in str(output or "").splitlines():
            line = raw.rstrip("\r")
            if not line.strip():
                if current:
                    rows.append(current)
                    current = {}
                continue
            if " = " in line:
                key, value = line.split(" = ", 1)
            elif "=" in line:
                key, value = line.split("=", 1)
            else:
                continue
            current[key.strip()] = value.strip()
        if current:
            rows.append(current)
        return rows

    @staticmethod
    def _json_object(output: str) -> Dict[str, Any]:
        text = str(output or "").strip()
        # Direct function calls return JSON; tolerate a harmless banner or
        # trailing newline by selecting the outermost object.
        if not text.startswith("{"):
            start = text.find("{")
            if start >= 0:
                text = text[start:]
        try:
            value = json.loads(text)
        except (TypeError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    @classmethod
    def _raw_query(cls, ssh: "SSHClient", table: str, where: str = "") -> List[Dict[str, str]]:
        if table not in IOC_TABLES:
            raise ValueError(f"unsupported IOC table: {table}")
        # ``where`` is internal and only assembled from fixed strings.  Public
        # methods never accept arbitrary SQL.
        sql = f"SELECT * FROM {table}"
        if where:
            sql += f" WHERE {where}"
        sql += " ORDER BY 1"
        command = f"sqlite3 -line {shlex.quote(IOC_DB)} {shlex.quote(sql)} 2>&1"
        output = cls._exec(ssh, command)
        if "Error:" in output or "unable to open" in output.lower():
            raise RuntimeError(f"IOC database query failed: {table}")
        return cls._parse_line_records(output)

    @classmethod
    def _table_columns(cls, ssh: "SSHClient", table: str) -> List[str]:
        if table not in IOC_TABLES:
            raise ValueError(f"unsupported IOC table: {table}")
        sql = f"PRAGMA table_info({table})"
        output = cls._exec(ssh, f"sqlite3 -line {shlex.quote(IOC_DB)} {shlex.quote(sql)} 2>&1")
        rows = cls._parse_line_records(output)
        return [row.get("name", "") for row in rows if row.get("name")]

    @classmethod
    def _query_count(cls, ssh: "SSHClient", table: str) -> int:
        if table not in IOC_TABLES:
            raise ValueError(f"unsupported IOC table: {table}")
        sql = f"SELECT COUNT(*) AS row_count FROM {table}"
        rows = cls._parse_line_records(
            cls._exec(ssh, f"sqlite3 -line {shlex.quote(IOC_DB)} {shlex.quote(sql)} 2>&1")
        )
        try:
            return int(rows[0].get("row_count", 0)) if rows else 0
        except (TypeError, ValueError):
            return 0

    @classmethod
    def _api_call(cls, ssh: "SSHClient", function: str, args: str) -> Dict[str, Any]:
        if function not in IOC_SCRIPT_FUNCTIONS:
            raise ValueError(f"unsupported IOC function: {function}")
        # ``args`` comes exclusively from READ_API_CONTRACTS.  Quote each
        # token anyway to ensure a future contract addition cannot inject a
        # shell metacharacter.
        tokens = args.split()
        safe_args = " ".join(shlex.quote(token) for token in tokens)
        command = f"{shlex.quote(IOC_FUNCTION_DIR + '/' + function)} {safe_args}"
        return cls._json_object(cls._exec(ssh, command, timeout=30))

    # ------------------------------------------------------------------
    # Public read-only queries
    # ------------------------------------------------------------------
    def read_contract(self, name: str) -> Dict[str, Any]:
        """Execute one named read-only API contract and return redacted data.

        ``READ_API_CONTRACTS`` is the only source of function names and
        arguments.  Keeping this boundary public lets UI tests collect the
        real response shape without reaching into ``_router`` or
        ``_api_call`` (and without allowing arbitrary shell arguments).
        Values such as IOC indicators, addresses and host names are redacted
        before the response leaves the verifier.
        """

        if name not in READ_API_CONTRACTS:
            raise ValueError(f"unsupported IOC read contract: {name}")
        function, args, _required_keys = READ_API_CONTRACTS[name]
        payload = self._api_call(self._router(self.backend), function, args)
        return self.sanitize_value(payload)

    def read_syslog_test_connection(self) -> Dict[str, Any]:
        """Run the firmware's fixed, non-persistent Syslog connectivity probe."""

        payload = self._api_call(
            self._router(self.backend), "ioc_syslog", "show TYPE=test_connection"
        )
        return self.sanitize_value(payload)

    def read_table(self, table: str) -> List[Dict[str, Any]]:
        """Read one supported IOC table with all identifying values redacted."""

        if table not in IOC_TABLES:
            raise ValueError(f"unsupported IOC table: {table}")
        rows = self._raw_query(self._router(self.backend), table)
        return [self.sanitize_value(row) for row in rows]

    @staticmethod
    def snapshot_table_count(snapshot: IocEnvironmentSnapshot, table: str) -> int:
        """Return a baseline table count without exposing private snapshot rows."""

        if not isinstance(snapshot, IocEnvironmentSnapshot):
            raise TypeError("snapshot must be IocEnvironmentSnapshot")
        if table not in IOC_TABLES:
            raise ValueError(f"unsupported IOC table: {table}")
        counts = snapshot.public.get("table_counts", {})
        try:
            return int(counts.get(table, 0))
        except (TypeError, ValueError):
            return 0

    def find_list_entry_ids(self, list_name: str, value: Any) -> List[str]:
        """Find IDs for an exact blacklist/whitelist value, returning IDs only.

        The value is accepted solely for an in-memory equality check.  It is
        never included in the return value or a report detail.  Restricting
        this helper to the two list tables prevents callers from turning it
        into a general SQL lookup primitive.
        """

        aliases = {
            "blacklist": "ioc_blacklist",
            "black_list": "ioc_blacklist",
            "ioc_blacklist": "ioc_blacklist",
            "whitelist": "ioc_whitelist",
            "white_list": "ioc_whitelist",
            "ioc_whitelist": "ioc_whitelist",
        }
        table = aliases.get(str(list_name).strip().lower())
        if table is None:
            raise ValueError("list_name must be blacklist or whitelist")
        if value is None or str(value) == "":
            return []
        expected = str(value)
        rows = self._raw_query(self._router(self.backend), table)
        result = {
            str(row.get("id"))
            for row in rows
            if row.get("id") not in (None, "") and str(row.get("value", "")) == expected
        }
        return sorted(result)

    def query_ioc_config(self) -> List[Dict[str, Any]]:
        return self.read_table("ioc_config")

    def query_syslog(self) -> List[Dict[str, Any]]:
        return self.read_table("ioc_syslog_config")

    def query_policy(self) -> List[Dict[str, Any]]:
        return self.read_table("ioc_category_policy")

    def query_blacklist(self) -> List[Dict[str, Any]]:
        return self.read_table("ioc_blacklist")

    def query_whitelist(self) -> List[Dict[str, Any]]:
        return self.read_table("ioc_whitelist")

    def query_event_log(self) -> List[Dict[str, Any]]:
        return self.read_table("ioc_event_log")

    def query_threat_records(self) -> List[Dict[str, Any]]:
        return self.read_table("ioc_threat_record")

    def query_search_history(self) -> List[Dict[str, Any]]:
        return self.read_table("ioc_search_history")

    # ------------------------------------------------------------------
    # Runtime and public snapshot
    # ------------------------------------------------------------------
    def _runtime_snapshot(self, ssh: "SSHClient") -> Dict[str, Any]:
        process_output = self._exec(
            ssh,
            "ps w 2>/dev/null | grep '[i]oc_hit_eventd' || true",
            timeout=10,
        )
        pids = re.findall(r"(?m)^\s*(\d+)\s+", process_output)

        # Only counts and names are retained.  The raw iptables/ipset output is
        # intentionally never put into a result object because it may contain
        # source/destination addresses.
        iptables = self._exec(ssh, "iptables-save 2>/dev/null || true", timeout=15)
        iptable_lines = [line for line in iptables.splitlines() if line.strip()]
        ioc_iptables = [line for line in iptable_lines if "ioc" in line.lower()]
        chains = []
        for line in ioc_iptables:
            match = re.search(r"^-N\s+([^\s]+)", line)
            if match:
                chains.append(match.group(1))

        ipset_output = self._exec(ssh, "ipset list -n 2>/dev/null || true", timeout=15)
        ipsets = [line.strip() for line in ipset_output.splitlines() if line.strip()]
        ioc_ipsets = [name for name in ipsets if "ioc" in name.lower()]
        return {
            "processes": {
                "ioc_hit_eventd": {
                    "count": len(pids),
                    "running": bool(pids),
                }
            },
            "iptables": {
                "line_count": len(iptable_lines),
                "ioc_line_count": len(ioc_iptables),
                "ioc_chain_name_hashes": sorted({self._sha(name) for name in chains}),
            },
            "ipset": {
                "set_count": len(ipsets),
                "ioc_set_count": len(ioc_ipsets),
                "ioc_set_name_hashes": sorted({self._sha(name) for name in ioc_ipsets}),
            },
        }

    @staticmethod
    def _runtime_semantics(runtime: Mapping[str, Any]) -> Dict[str, Any]:
        """Return IOC-only runtime state, excluding unrelated global counts."""

        processes = runtime.get("processes", {}) if isinstance(runtime, Mapping) else {}
        iptables = runtime.get("iptables", {}) if isinstance(runtime, Mapping) else {}
        ipset = runtime.get("ipset", {}) if isinstance(runtime, Mapping) else {}
        return {
            "processes": processes,
            "iptables": {
                "ioc_line_count": iptables.get("ioc_line_count", 0),
                "ioc_chain_name_hashes": iptables.get("ioc_chain_name_hashes", []),
            },
            "ipset": {
                "ioc_set_count": ipset.get("ioc_set_count", 0),
                "ioc_set_name_hashes": ipset.get("ioc_set_name_hashes", []),
            },
        }

    @classmethod
    def _safe_policy_summary(cls, rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        categories: List[Dict[str, Any]] = []
        for row in rows:
            categories.append(
                {
                    "category": row.get("category", ""),
                    "name": row.get("name", ""),
                    "monitor": row.get("monitor", ""),
                    "block": row.get("block", ""),
                    "alert": row.get("alert", ""),
                    "member_count": row.get("member_count", ""),
                    "counter_reset_at": row.get("counter_reset_at", ""),
                    "updated_at": row.get("updated_at", ""),
                }
            )
        return {
            "count": len(categories),
            "categories": categories,
            "enabled_count": sum(
                str(item.get("monitor", "")) == "1" for item in categories
            ),
            "block_count": sum(
                str(item.get("block", "")) == "1" for item in categories
            ),
            "alert_count": sum(
                str(item.get("alert", "")) == "1" for item in categories
            ),
        }

    @classmethod
    def _safe_list_summary(cls, rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        type_counts: Dict[str, int] = {}
        source_counts: Dict[str, int] = {}
        for row in rows:
            ioc_type = str(row.get("ioc_type", ""))
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
            source = str(row.get("source", ""))
            if source:
                source_counts[source] = source_counts.get(source, 0) + 1
        return {
            "count": len(rows),
            "type_counts": dict(sorted(type_counts.items())),
            "source_counts": dict(sorted(source_counts.items())),
            "rows": [
                {
                    "id": row.get("id", ""),
                    "ioc_type": row.get("ioc_type", ""),
                    "ioc_port": row.get("ioc_port", ""),
                    "source": row.get("source", ""),
                    "duration": row.get("duration", ""),
                    "expire_time": row.get("expire_time", ""),
                    "value": cls.redact_identifier(row.get("value")),
                }
                for row in rows
            ],
        }

    @classmethod
    def _safe_syslog_summary(cls, rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        row = dict(rows[0]) if rows else {}
        return {
            "count": len(rows),
            "enabled": row.get("enabled", ""),
            "port": row.get("port", ""),
            "protocol": row.get("protocol", ""),
            "format": row.get("format", ""),
            "server": cls.redact_identifier(row.get("server")),
            "hostname": cls.redact_identifier(row.get("hostname")),
        }

    @classmethod
    def _public_table_summary(
        cls, tables: Mapping[str, Sequence[Mapping[str, Any]]]
    ) -> Dict[str, Any]:
        counts = {name: len(rows) for name, rows in tables.items()}
        hashes = {
            name: cls._sha(json.dumps(list(rows), sort_keys=True, ensure_ascii=False))
            for name, rows in tables.items()
        }
        config = {str(row.get("key")): str(row.get("value", "")) for row in tables.get("ioc_config", [])}
        return {
            "table_counts": counts,
            "table_hashes": hashes,
            "ioc_config": {
                "enabled": config.get("enabled", "no"),
                "enable_time": config.get("enable_time", "0"),
                "key_count": len(config),
            },
            "syslog": cls._safe_syslog_summary(tables.get("ioc_syslog_config", [])),
            "policy": cls._safe_policy_summary(tables.get("ioc_category_policy", [])),
            "blacklist": cls._safe_list_summary(tables.get("ioc_blacklist", [])),
            "whitelist": cls._safe_list_summary(tables.get("ioc_whitelist", [])),
            "event_log": {"count": len(tables.get("ioc_event_log", []))},
            "threat_records": {"count": len(tables.get("ioc_threat_record", []))},
            "search_history": {"count": len(tables.get("ioc_search_history", []))},
        }

    def snapshot(self) -> IocEnvironmentSnapshot:
        """Capture a read-only baseline for exact cleanup verification."""

        ssh = self._router(self.backend)
        tables: Dict[str, List[Dict[str, str]]] = {}
        errors: Dict[str, str] = {}
        for table in IOC_TABLES:
            try:
                tables[table] = self._raw_query(ssh, table)
            except Exception as exc:  # keep diagnostics usable on old firmware
                tables[table] = []
                errors[table] = type(exc).__name__
        runtime = self._runtime_snapshot(ssh)
        public = self._public_table_summary(tables)
        try:
            overview = self._api_call(ssh, "ioc_overview", "show TYPE=overview")
            overview_data = overview.get("overview", {})
            if not isinstance(overview_data, Mapping):
                overview_data = {}
            public["overview"] = {
                "enabled": str(overview_data.get("enabled", "")),
                "enable_time": str(overview_data.get("enable_time", "0")),
                "expiry_time": str(overview_data.get("expiry_time", "0")),
                "update_time": str(overview_data.get("update_time", "0")),
                "ioc_ver": str(overview_data.get("ioc_ver", "")),
            }
        except Exception as exc:
            public["overview"] = {"error_type": type(exc).__name__}
        public["runtime"] = runtime
        public["errors"] = errors
        public["enabled"] = public.get("ioc_config", {}).get("enabled", "no")
        # Hash the complete private baseline for a compact equality check.  A
        # hash is safe to publish even though the raw rows remain private.
        public["state_hash"] = self._sha(
            json.dumps(
                {"tables": tables, "runtime": self._runtime_semantics(runtime)},
                sort_keys=True,
                ensure_ascii=False,
            )
        )
        snap = IocEnvironmentSnapshot(public=public, private={"tables": tables, "runtime": runtime})
        self._last_snapshot = snap
        return snap

    snapshot_environment = snapshot

    # ------------------------------------------------------------------
    # State and contract verification
    # ------------------------------------------------------------------
    @staticmethod
    def _expected_enabled(value: Any) -> str:
        if isinstance(value, bool):
            return "yes" if value else "no"
        rendered = str(value or "").strip().lower()
        if rendered in {"1", "true", "on", "yes", "enabled"}:
            return "yes"
        if rendered in {"0", "false", "off", "no", "disabled"}:
            return "no"
        raise ValueError("expected enabled must be yes/no or bool")

    def verify_enabled(
        self,
        expected: Any = True,
        *,
        require_process: bool = True,
        expected_enabled: Any = None,
    ) -> VerifyResult:
        """Verify the feature switch and read-only overview contract."""

        if expected_enabled is not None:
            expected = expected_enabled
        expected_value = self._expected_enabled(expected)
        ssh = self._router(self.backend)
        config_rows = self._raw_query(ssh, "ioc_config")
        config = {str(row.get("key")): str(row.get("value", "")) for row in config_rows}
        overview = self._api_call(ssh, "ioc_overview", "show TYPE=overview")
        overview_data = overview.get("overview") if isinstance(overview, dict) else {}
        overview_data = overview_data if isinstance(overview_data, dict) else {}
        observed_config = config.get("enabled", "no")
        observed_api = str(overview_data.get("enabled", ""))
        runtime = self._runtime_snapshot(ssh)
        running = bool(runtime.get("processes", {}).get("ioc_hit_eventd", {}).get("running"))
        checks = {
            "config_enabled": observed_config == expected_value,
            "api_enabled": observed_api == expected_value,
        }
        if require_process:
            checks["process_running"] = running if expected_value == "yes" else not running
        passed = all(checks.values())
        details = {
            "expected": expected_value,
            "observed": {
                "config_enabled": observed_config,
                "api_enabled": observed_api,
                "process_running": running,
            },
            "checks": checks,
            "runtime": runtime,
        }
        return VerifyResult(
            level="L1-IOC功能开关",
            passed=passed,
            message=("IOC功能开关与概览API一致" if passed else "IOC功能开关与概览API不一致"),
            details=self.sanitize_value(details),
        )

    def verify_restored(self, snapshot: IocEnvironmentSnapshot) -> VerifyResult:
        """Compare current state with a private baseline without mutating it."""

        if not isinstance(snapshot, IocEnvironmentSnapshot):
            raise TypeError("snapshot must be IocEnvironmentSnapshot")
        current = self.snapshot()
        baseline_public = snapshot.public or {}
        current_public = current.public or {}
        mismatches: Dict[str, Any] = {}
        if baseline_public.get("state_hash") != current_public.get("state_hash"):
            # Report table-level differences only; never expose raw rows.
            before_tables = baseline_public.get("table_hashes", {})
            after_tables = current_public.get("table_hashes", {})
            for table in IOC_TABLES:
                if before_tables.get(table) != after_tables.get(table):
                    mismatches[f"table:{table}"] = {
                        "before_hash": before_tables.get(table, ""),
                        "after_hash": after_tables.get(table, ""),
                        "before_count": baseline_public.get("table_counts", {}).get(table, 0),
                        "after_count": current_public.get("table_counts", {}).get(table, 0),
                    }
            if self._runtime_semantics(baseline_public.get("runtime", {})) != self._runtime_semantics(
                current_public.get("runtime", {})
            ):
                # Runtime line counts may vary for unrelated rules.  Compare
                # only IOC process/set/chain semantics and redact names.
                mismatches["runtime"] = {
                    "before": self._runtime_semantics(baseline_public.get("runtime", {})),
                    "after": self._runtime_semantics(current_public.get("runtime", {})),
                }
        passed = not mismatches and not current_public.get("errors")
        return VerifyResult(
            level="清理-IOC精确残留审计",
            passed=passed,
            message=("IOC数据库、开关及运行时状态已恢复" if passed else "IOC状态存在残留或查询异常"),
            details=self.sanitize_value({"mismatches": mismatches, "current_errors": current_public.get("errors", {})}),
        )

    def verify_schema(self) -> VerifyResult:
        """Verify all IOC tables and the columns consumed by the scripts."""

        ssh = self._router(self.backend)
        schema = self._verify_schema(ssh)
        passed = not schema["missing_columns"] and len(schema["tables"]) == len(IOC_REQUIRED_COLUMNS)
        return VerifyResult(
            level="L1-IOC数据库Schema",
            passed=passed,
            message=("IOC相关表及关键字段完整" if passed else "IOC数据库表或关键字段缺失"),
            details=self.sanitize_value(
                {
                    "tables": schema["tables"],
                    "missing_columns": schema["missing_columns"],
                    "columns_hash": schema["columns_hash"],
                }
            ),
        )

    def verify_database(self) -> VerifyResult:
        """Read every supported table and report safe counts/hashes."""

        snap = self.snapshot()
        passed = not snap.public.get("errors")
        return VerifyResult(
            level="L1-IOC数据库状态",
            passed=passed,
            message=("IOC配置、策略、名单和事件表可读" if passed else "IOC数据库存在不可读表"),
            details=self.sanitize_value(
                {
                    "table_counts": snap.public.get("table_counts", {}),
                    "table_hashes": snap.public.get("table_hashes", {}),
                    "errors": snap.public.get("errors", {}),
                }
            ),
        )

    def verify_runtime(self, expected_enabled: Any = None) -> VerifyResult:
        """Verify process and IOC-specific firewall/set observations."""

        ssh = self._router(self.backend)
        runtime = self._runtime_snapshot(ssh)
        checks: Dict[str, bool] = {
            "process_probe": True,
            "iptables_probe": True,
            "ipset_probe": True,
        }
        if expected_enabled is not None:
            expected_value = self._expected_enabled(expected_enabled)
            running = bool(
                runtime.get("processes", {})
                .get("ioc_hit_eventd", {})
                .get("running")
            )
            checks["process_matches_switch"] = running == (expected_value == "yes")
        passed = all(checks.values())
        return VerifyResult(
            level="L2-IOC运行时/防火墙",
            passed=passed,
            message=("IOC进程、iptables/ipset只读探测完成" if passed else "IOC运行时状态与预期不一致"),
            details=self.sanitize_value({"checks": checks, "runtime": runtime}),
        )

    def management_health(self) -> VerifyResult:
        """Check only the router SSH and HTTP management listeners."""

        ssh = self._router(self.backend)
        listener_output = self._exec(
            ssh,
            "ss -lnt 2>/dev/null | awk '$4 ~ /:(80|443)$/ {n++} END {print n+0}'",
            timeout=10,
        ).strip()
        if listener_output in {"", "0"}:
            # Some iKuai images ship netstat but not ss.
            listener_output = self._exec(
                ssh,
                "netstat -lnt 2>/dev/null | grep -E ':(80|443)[[:space:]]' | wc -l",
                timeout=10,
            ).strip()
        checks = {
            "router_ssh": self._exec(ssh, "printf IOC_ROUTER_OK", timeout=8).strip() == "IOC_ROUTER_OK",
            "web_listener": listener_output not in {"", "0"},
        }
        passed = all(checks.values())
        return VerifyResult(
            level="环境-IOC管理通道",
            passed=passed,
            message=("IOC管理SSH/Web通道可用" if passed else "IOC管理通道探测失败"),
            details={"checks": checks},
        )

    @classmethod
    def _script_contract_command(cls, script: str, functions: Iterable[str]) -> str:
        path = f"{IOC_FUNCTION_DIR}/{script}"
        patterns = "|".join(re.escape(name) for name in functions)
        # ``grep`` only emits function declarations and a SHA; no script body
        # or potentially sensitive arguments enter the report.
        return (
            f"test -r {shlex.quote(path)}; sha256sum {shlex.quote(path)}; "
            f"grep -E '^({patterns})\\(\\)' {shlex.quote(path)} || true"
        )

    def _verify_schema(self, ssh: "SSHClient") -> Dict[str, Any]:
        schemas: Dict[str, List[str]] = {}
        missing: Dict[str, List[str]] = {}
        for table, required in IOC_REQUIRED_COLUMNS.items():
            try:
                columns = self._table_columns(ssh, table)
            except Exception:
                columns = []
            schemas[table] = columns
            absent = sorted(set(required) - set(columns))
            if absent:
                missing[table] = absent
        return {
            "tables": sorted(table for table, columns in schemas.items() if columns),
            "missing_columns": missing,
            "columns_hash": self._sha(json.dumps(schemas, sort_keys=True)),
            "schemas": schemas,
        }

    def verify_contract(self) -> VerifyResult:
        """Audit script declarations, database schema and read-only API shapes."""

        ssh = self._router(self.backend)
        script_details: Dict[str, Any] = {}
        scripts_ok = True
        for script, functions in IOC_SCRIPT_FUNCTIONS.items():
            output = self._exec(ssh, self._script_contract_command(script, functions), timeout=20)
            digest_match = re.search(r"(?m)^([0-9a-f]{64})\s+", output)
            declared = set(re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)", output))
            expected = set(functions)
            missing = sorted(expected - declared)
            readable = bool(digest_match)
            script_details[script] = {
                "readable": readable,
                "sha256": digest_match.group(1) if digest_match else "",
                "declared_count": len(declared),
                "missing_functions": missing,
            }
            scripts_ok = scripts_ok and readable and not missing

        api_details: Dict[str, Any] = {}
        api_ok = True
        for name, (function, args, required_keys) in READ_API_CONTRACTS.items():
            try:
                payload = self._api_call(ssh, function, args)
                # Direct function invocation returns the object itself; the
                # HTTP layer wraps it in ``results``.  Do not retain payload.
                missing = sorted(key for key in required_keys if key not in payload)
                valid = bool(payload) and not missing
                api_details[name] = {
                    "function": function,
                    "keys": sorted(str(key) for key in payload.keys()),
                    "missing_keys": missing,
                    "valid": valid,
                }
            except Exception as exc:
                api_details[name] = {
                    "function": function,
                    "keys": [],
                    "missing_keys": list(required_keys),
                    "valid": False,
                    "error_type": type(exc).__name__,
                }
                valid = False
            api_ok = api_ok and valid

        schema = self._verify_schema(ssh)
        schema_ok = not schema["missing_columns"] and len(schema["tables"]) == len(IOC_REQUIRED_COLUMNS)
        runtime = self._runtime_snapshot(ssh)
        details = {
            "scripts": script_details,
            "apis": api_details,
            "schema": {
                "tables": schema["tables"],
                "missing_columns": schema["missing_columns"],
                "columns_hash": schema["columns_hash"],
            },
            "runtime": runtime,
            "read_only": True,
        }
        passed = scripts_ok and api_ok and schema_ok
        return VerifyResult(
            level="L1/L2-IOC脚本与API契约",
            passed=passed,
            message=("IOC脚本、数据库结构和只读API契约完整" if passed else "IOC脚本、数据库结构或API契约存在缺失"),
            details=self.sanitize_value(details),
        )

    # Existing modules call this operation ``script_contract``; retain the
    # alias so generic report wiring can use either spelling.
    script_contract = verify_contract
    verify_script_contract = verify_contract

    # ------------------------------------------------------------------
    # Safe semantic replay commands
    # ------------------------------------------------------------------
    @classmethod
    def _replay_command(
        cls,
        purpose: str,
        command: str,
        expected: str,
        *,
        target: str = "router",
        valid_when: str = "对应步骤完成后、清理前",
    ) -> Dict[str, Any]:
        command = str(command).strip()
        # Internal assertions protect future additions from accidentally
        # turning a manual replay item into a mutating shell script.
        if not command or "\n" in command or "\r" in command:
            raise ValueError("replay command must be one line")
        if re.search(
            r"\$\(|\$\{|(?:^|[\s/])(?:rm|mv|cp|kill|reboot|shutdown|toggle|save|add|edit|del)(?:\s|$)",
            command,
            re.I,
        ):
            raise ValueError("replay command is not read-only")
        return {
            "target": target,
            "target_label": "路由器" if target == "router" else "测试客户端",
            "host": "",
            "shell": "sh",
            "purpose": purpose,
            "command": command,
            "expected": expected,
            "valid_when": valid_when,
            "actual": "待执行复验",
            "copy_ready": True,
            "contains_secret": False,
            "interactive": False,
            "interactive_hint": "",
            "effect": "read_only",
        }

    def build_verification_commands(self, result: Optional[VerifyResult] = None) -> List[Dict[str, Any]]:
        """Build copy-ready, read-only commands with semantic expectations."""

        db = shlex.quote(IOC_DB)
        commands: List[Dict[str, Any]] = []
        commands.append(self._replay_command(
            "读取IOC功能开关（仅显示enabled键）",
            f"sqlite3 -line {db} 'SELECT key,value FROM ioc_config WHERE key=\"enabled\"'",
            "输出enabled= yes或no；不显示授权载荷",
        ))
        commands.append(self._replay_command(
            "读取IOC概览API契约",
            f"{IOC_FUNCTION_DIR}/ioc_overview show 'TYPE=overview'",
            "返回overview对象且enabled与数据库一致",
        ))
        for table in IOC_TABLES:
            commands.append(self._replay_command(
                f"核对{table}记录数",
                f"sqlite3 -line {db} 'SELECT COUNT(*) AS row_count FROM {table}'",
                "返回单个row_count整数",
            ))
        commands.append(self._replay_command(
            "核对IOC脚本哈希（不输出脚本正文）",
            "sha256sum /usr/ikuai/function/ioc_overview /usr/ikuai/function/ioc_homepage /usr/ikuai/function/ioc_monitor /usr/ikuai/function/ioc_detail /usr/ikuai/function/ioc_syslog /usr/ikuai/function/ioc_alert /usr/ikuai/function/ioc_policy /usr/ikuai/function/ioc_blacklist /usr/ikuai/function/ioc_whitelist /usr/ikuai/function/ioc_report",
            "每个脚本返回64位SHA-256",
        ))
        commands.append(self._replay_command(
            "核对IOC事件进程",
            "ps w 2>/dev/null | grep '[i]oc_hit_eventd'",
            "返回事件进程行或空（仅判断运行状态）",
        ))
        commands.append(self._replay_command(
            "核对IOC防火墙规则计数",
            "iptables-save 2>/dev/null | grep -ic ioc",
            "返回IOC相关规则行数，不输出地址",
        ))
        commands.append(self._replay_command(
            "核对IOC ipset集合计数",
            "ipset list -n 2>/dev/null | grep -ic ioc",
            "返回IOC相关集合数量，不输出成员地址",
        ))
        # Keep the standard report metadata used by the other verifiers.  The
        # management host is not an IOC value; credentials and threat values
        # never enter this field.
        router_config = getattr(getattr(self.backend, "_ssh_config", None), "router", None)
        router_host = str(getattr(router_config, "host", "") or "")
        if router_host:
            for item in commands:
                item["host"] = router_host
        if result is not None:
            # Do not copy a verifier message into a manual command.  A caller
            # may have included an arbitrary IOC value in that message; the
            # command itself must remain semantic and value-free.
            actual = (
                "通过：只读契约验证结果已记录"
                if bool(getattr(result, "passed", False))
                else "失败：只读契约验证未通过，详情见报告"
            )
            for item in commands:
                item["actual"] = actual
        return commands

    # Names used by report/replay integrations in different modules.
    replay_commands = build_verification_commands
    verification_commands = build_verification_commands
    build_replay_commands = build_verification_commands


# Public aliases make discovery/imports predictable for callers that prefer a
# result type specific to this feature.
IocCheckResult = VerifyResult
IOCEnvironmentSnapshot = IocEnvironmentSnapshot

__all__ = [
    "IOC_DB",
    "IOC_TABLES",
    "IOC_SCRIPT_FUNCTIONS",
    "READ_API_CONTRACTS",
    "IocCheckResult",
    "IocEnvironmentSnapshot",
    "IOCEnvironmentSnapshot",
    "IocSnapshot",
    "IocVerifier",
]
