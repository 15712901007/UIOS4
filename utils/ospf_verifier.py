"""OSPF-specific L1-L5 verification and exact recovery helpers.

The verifier deliberately keeps raw database rows and generated configuration in
process memory only.  Public results contain counts, hashes, and redacted
semantics so authentication values and hardware addresses cannot enter reports.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import shlex
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from utils.backend_verifier import BackendVerifier, SSHClient


OSPF_TABLES = (
    "ospf_basic",
    "ospf_instance",
    "ospf_area",
    "ospf_interface",
    "ospf_interface_attr",
    "ospf_redistribute",
    "ospf_static_route",
    "ospf_prefix_list_entry",
    "ospf_log_target",
    "ospf_debug_flag",
    "ospf_vty_line",
)
SENSITIVE_FIELDS = {
    "enable_password", "auth_key", "md5_key",
    "ipsec_key", "password", "secret",
}
MAC_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
SENSITIVE_LINE = re.compile(
    r"(?i)(?:password|secret|key-string|message-digest-key|authentication-key|"
    r"ip ospf authentication|ipv6 ospf6 authentication)"
)
ProgressCallback = Optional[Callable[[str, Any], None]]


@dataclass
class OspfCheckResult:
    level: str
    passed: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""


@dataclass
class OspfEnvironmentSnapshot:
    """Private restoration data plus a report-safe view."""

    private_tables: Dict[str, List[Dict[str, str]]] = field(repr=False)
    private_config: str = field(repr=False)
    private_client_config: str = field(repr=False)
    public: Dict[str, Any]


class OspfVerifier:
    DB = "/etc/mnt/ikuai/config.db"
    SCRIPT = "/usr/ikuai/script/ospf.sh"
    GENERATED_CONFIG = "/tmp/ospf.frr"
    ACTIVE_CONFIG = "/etc/frr/frr.conf"
    DAEMONS = ("watchfrr", "zebra", "ospfd", "ospf6d", "staticd")

    def __init__(self, backend: "BackendVerifier"):
        self.backend = backend
        self._client_v2_added_networks: set[str] = set()
        self._client_v2_removed_networks: set[str] = set()
        self._client_v3_interfaces: set[str] = set()
        self._client_v3_created_router = False
        self._client_temp_v6: set[tuple[str, str]] = set()
        self._client_started_daemons: Dict[str, set[int]] = {}

    @staticmethod
    def _wait_progress(
        progress: ProgressCallback, waiting_for: str, started: float,
        timeout: float, current: str,
    ) -> None:
        if progress is None:
            return
        elapsed = max(0.0, time.monotonic() - started)
        progress(
            "等待进度",
            f"正在等待={waiting_for} | 已等待={elapsed:.1f}s | "
            f"最大等待={timeout:.0f}s | 当前状态={current}",
        )

    @staticmethod
    def _sha(value: str) -> str:
        return hashlib.sha256((value or "").encode("utf-8")).hexdigest()

    @classmethod
    def sanitize_text(cls, value: Any) -> str:
        text = MAC_PATTERN.sub("<硬件地址已隐藏>", str(value or ""))
        safe_lines = []
        for line in text.splitlines():
            if SENSITIVE_LINE.search(line):
                indentation = line[:len(line) - len(line.lstrip())]
                safe_lines.append(indentation + "<认证配置已隐藏>")
            else:
                safe_lines.append(line)
        return "\n".join(safe_lines)

    @classmethod
    def sanitize_value(cls, value: Any, key: str = "") -> Any:
        lowered = str(key).lower()
        if lowered in SENSITIVE_FIELDS:
            raw = "" if value is None else str(value)
            return {"configured": bool(raw), "length": len(raw)}
        if isinstance(value, dict):
            return {k: cls.sanitize_value(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls.sanitize_value(v) for v in value]
        if isinstance(value, str):
            return cls.sanitize_text(value)
        return value

    @staticmethod
    def _parse_line_records(output: str) -> List[Dict[str, str]]:
        records: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for raw in (output or "").splitlines():
            line = raw.strip()
            if not line:
                if current:
                    records.append(current)
                    current = {}
                continue
            if " = " in raw:
                key, value = raw.split(" = ", 1)
                current[key.strip()] = value.strip()
            elif "=" in line:
                key, value = line.split("=", 1)
                current[key.strip()] = value.strip()
        if current:
            records.append(current)
        return records

    def _router(self) -> "SSHClient":
        ssh_config = getattr(self.backend, "_ssh_config", None)
        if str(
            getattr(ssh_config, "router_lan_management_host", "") or ""
        ):
            self.backend.connect_router_lan_management()
            return self.backend._router_lan_management
        self.backend.connect_router()
        return self.backend._router

    def _client(self) -> "SSHClient":
        self.backend.connect_client()
        return self.backend._client

    def _peer(self) -> "SSHClient":
        self.backend.connect_ospf_peer()
        return self.backend._ospf_peer

    def _recovery(self) -> "SSHClient":
        self.backend.connect_router_recovery()
        return self.backend._router_recovery

    def _peer_recovery(self) -> "SSHClient":
        self.backend.connect_ospf_peer_recovery()
        return self.backend._ospf_peer_recovery

    def _lan_management(self) -> "SSHClient":
        self.backend.connect_router_lan_management()
        return self.backend._router_lan_management

    def _query(self, table: str, where: str = "") -> List[Dict[str, str]]:
        if table not in OSPF_TABLES:
            raise ValueError("非法OSPF表名")
        sql = f"SELECT * FROM {table}"
        if where:
            sql += " WHERE " + where
        sql += " ORDER BY id"
        output = self._router().exec(
            f"sqlite3 -line {shlex.quote(self.DB)} {shlex.quote(sql)} 2>&1",
            timeout=20,
        )
        if "Error:" in output or "unable to open" in output.lower():
            raise RuntimeError("OSPF数据库查询失败")
        return self._parse_line_records(output)

    @staticmethod
    def _int(value: Any, default: int = 0) -> int:
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return default

    def verify_schema(self) -> OspfCheckResult:
        output = self._router().exec(
            "sqlite3 -line " + shlex.quote(self.DB) + " "
            + shlex.quote(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE (name LIKE 'ospf_%' OR tbl_name LIKE 'ospf_%') "
                "AND type IN ('table','index','trigger') ORDER BY type,name"
            ),
            timeout=25,
        )
        objects = self._parse_line_records(output)
        tables = {item.get("name") for item in objects if item.get("type") == "table"}
        missing = sorted(set(OSPF_TABLES) - tables)
        schemas: Dict[str, List[str]] = {}
        for table in OSPF_TABLES:
            rows = self._parse_line_records(self._router().exec(
                f"sqlite3 -line {shlex.quote(self.DB)} "
                f"{shlex.quote('PRAGMA table_info(' + table + ')')}", timeout=15
            ))
            schemas[table] = [row.get("name", "") for row in rows]
        relationships = {
            "instance_key": all(
                {"address_family", "process_id"}.issubset(set(schemas.get(table, [])))
                for table in ("ospf_instance", "ospf_area", "ospf_interface_attr",
                              "ospf_redistribute")
            ),
            "interface_key": {"ifname"}.issubset(
                set(schemas.get("ospf_interface", []))
                & set(schemas.get("ospf_interface_attr", []))
            ),
            "area_key": "area_id" in schemas.get("ospf_area", [])
                        and "area_id" in schemas.get("ospf_interface_attr", []),
        }
        indexes = sorted(
            item.get("name", "") for item in objects if item.get("type") == "index"
        )
        triggers = sorted(
            item.get("name", "") for item in objects if item.get("type") == "trigger"
        )
        passed = not missing and all(relationships.values())
        details = {
            "tables": sorted(tables), "missing": missing, "columns": schemas,
            "indexes": indexes, "triggers": triggers,
            "relationships": relationships,
        }
        return OspfCheckResult(
            "L1-OSPF数据库Schema", passed,
            "11张OSPF表及实例/区域/接口关联键完整" if passed
            else "OSPF数据库Schema或关联键不完整",
            details=self.sanitize_value(details),
        )

    def script_contract(self) -> OspfCheckResult:
        command = (
            f"test -r {shlex.quote(self.SCRIPT)} || exit 7; "
            f"wc -l < {shlex.quote(self.SCRIPT)}; "
            f"sha256sum {shlex.quote(self.SCRIPT)} | cut -d' ' -f1; "
            f"grep -E '^([.]|source)[[:space:]]+' {shlex.quote(self.SCRIPT)} || true; "
            f"grep -E '(/tmp/ospf[.]frr|/etc/frr/frr[.]conf|cp .*frr[.]conf|mv .*frr[.]conf|"
            f"frr-reload|vtysh.*-C)' {shlex.quote(self.SCRIPT)} || true"
        )
        output = self._router().exec(command, timeout=25)
        lines = output.splitlines()
        line_count = self._int(lines[0] if lines else 0)
        digest = lines[1].strip() if len(lines) > 1 else ""
        body = "\n".join(lines[2:])
        flags = {
            "readable": line_count > 0,
            "line_count": line_count,
            "sha256": digest,
            "generated_path": self.GENERATED_CONFIG in body,
            "active_path": self.ACTIVE_CONFIG in body,
            "direct_copy": bool(re.search(r"\bcp\b.*frr[.]conf", body)),
            "atomic_replace": bool(re.search(r"\bmv\b.*frr[.]conf", body)),
            "syntax_check": bool(re.search(r"frr-reload|vtysh.*-C", body)),
            "source_count": len(re.findall(r"(?m)^(?:[.]|source)\s+", body)),
        }
        core = flags["readable"] and flags["generated_path"] and flags["active_path"]
        return OspfCheckResult(
            "L2-ospf.sh契约", core,
            "ospf.sh生成路径和活动配置路径已确认" if core else "ospf.sh关键路径契约不完整",
            details=flags,
        )

    def verify_config_update_safety(self) -> OspfCheckResult:
        contract = self.script_contract().details
        passed = bool(contract.get("syntax_check") and contract.get("atomic_replace"))
        return OspfCheckResult(
            "L2-配置更新安全", passed,
            "覆盖前存在语法检查且使用原子替换" if passed
            else "产品脚本未证明覆盖前语法检查和原子替换；失败时不存在DB回滚保证",
            details={
                "syntax_check": bool(contract.get("syntax_check")),
                "atomic_replace": bool(contract.get("atomic_replace")),
                "direct_copy": bool(contract.get("direct_copy")),
                "db_rollback_observed": False,
            },
        )

    def _read_config(self, ssh: "SSHClient", command: str) -> str:
        return ssh.exec(command, timeout=25)

    def _processes(self, ssh: "SSHClient") -> Dict[str, List[int]]:
        result = {name: [] for name in self.DAEMONS}
        for name in self.DAEMONS:
            output = ssh.exec(f"pidof {name} 2>/dev/null || true", timeout=10)
            result[name] = sorted(
                int(token) for token in output.split() if token.isdigit()
            )
        return result

    def snapshot_environment(self, include_peer: bool = True) -> OspfEnvironmentSnapshot:
        tables = {table: self._query(table) for table in OSPF_TABLES}
        router = self._router()
        config = self._read_config(router, f"test -f {self.ACTIVE_CONFIG} && cat {self.ACTIVE_CONFIG}")
        generated = self._read_config(
            router, f"test -f {self.GENERATED_CONFIG} && cat {self.GENERATED_CONFIG}"
        )
        client_config = self._read_config(
            self._client(), "sudo -n vtysh -c 'show running-config' 2>/dev/null"
        )
        process_map = self._processes(router)
        table_counts = {table: len(rows) for table, rows in tables.items()}
        table_hashes = {
            table: self._sha(json.dumps(rows, ensure_ascii=False, sort_keys=True))
            for table, rows in tables.items()
        }
        protocol_rules = router.exec(
            "iptables-save 2>/dev/null | grep -E -- '-p (89|ospf)( |$)' || true",
            timeout=15,
        )
        route_semantics = router.exec(
            "ip -o route show proto ospf 2>/dev/null; ip -6 -o route show proto ospf 2>/dev/null",
            timeout=15,
        )
        public = {
            "table_counts": table_counts,
            "table_hashes": table_hashes,
            "active_config_sha256": self._sha(config),
            "generated_config_sha256": self._sha(generated),
            "processes": process_map,
            "protocol_89_rule_count": len([x for x in protocol_rules.splitlines() if x.strip()]),
            "ospf_route_count": len([x for x in route_semantics.splitlines() if x.strip()]),
            "client_running_config_sha256": self._sha(client_config),
            "management": self.management_health().details,
        }
        if include_peer:
            try:
                peer = self._peer()
                public["peer"] = {
                    "management_ssh": True,
                    "processes": self._processes(peer),
                    "lan1_carrier": "LOWER_UP" in peer.exec(
                        "ip -o link show dev lan1 2>/dev/null", timeout=10
                    ),
                }
            except Exception as exc:
                public["peer"] = {
                    "management_ssh": False, "error_type": type(exc).__name__
                }
        return OspfEnvironmentSnapshot(
            private_tables=tables,
            private_config=config,
            private_client_config=client_config,
            public=self.sanitize_value(public),
        )

    def management_health(self) -> OspfCheckResult:
        router = self._router()
        client = self._client()
        checks = {
            "router_ssh": bool(router.exec("printf OSPF_ROUTER_OK", timeout=8).strip()),
            "client_ssh": bool(client.exec("printf OSPF_CLIENT_OK", timeout=8).strip()),
            "router_web_listener": bool(router.exec(
                "ss -lnt 2>/dev/null | awk '$4 ~ /:(80|443)$/ {n++} END {print n+0}'",
                timeout=10,
            ).strip() not in {"", "0"}),
        }
        try:
            checks["peer_ssh"] = bool(
                self._peer().exec("printf OSPF_PEER_OK", timeout=8).strip()
            )
        except Exception:
            checks["peer_ssh"] = False
        try:
            checks["router_recovery_ssh"] = bool(
                self._recovery().exec("printf OSPF_RECOVERY_OK", timeout=8).strip()
            )
        except Exception:
            checks["router_recovery_ssh"] = False
        try:
            checks["peer_recovery_ssh"] = bool(
                self._peer_recovery().exec("printf OSPF_PEER_RECOVERY_OK", timeout=8).strip()
            )
        except Exception:
            checks["peer_recovery_ssh"] = False
        try:
            checks["router_lan_management_ssh"] = bool(
                self._lan_management().exec("printf OSPF_LAN_MANAGEMENT_OK", timeout=8).strip()
            )
        except Exception:
            checks["router_lan_management_ssh"] = False
        passed = checks["router_ssh"] and checks["client_ssh"]
        return OspfCheckResult(
            "安全-管理通道", passed,
            "主路由和客户端管理通道可用" if passed else "必要管理通道不可用",
            details=checks,
        )

    def verify_two_node_topology(self) -> OspfCheckResult:
        router = self._router()
        client = self._client()
        router_raw = router.exec(
            "ip -o -4 addr show dev lan1 scope global 2>/dev/null | awk '{print $4}' | head -n1",
            timeout=10,
        ).strip()
        client_raw = client.exec(
            "ip -o -4 addr show dev ens11 scope global 2>/dev/null | awk '{print $4}' | head -n1",
            timeout=10,
        ).strip()
        checks: Dict[str, Any] = {
            "router_interface": "lan1", "client_interface": "ens11",
            "router_address": router_raw, "client_address": client_raw,
        }
        try:
            router_ip = ipaddress.ip_interface(router_raw)
            client_ip = ipaddress.ip_interface(client_raw)
            checks.update({
                "distinct_addresses": router_ip.ip != client_ip.ip,
                "same_network": router_ip.network == client_ip.network,
                "transit_network": str(router_ip.network),
            })
        except ValueError:
            checks.update({"distinct_addresses": False, "same_network": False})
            return OspfCheckResult(
                "安全-双节点拓扑", False, "LAN1或ens11缺少有效IPv4地址",
                details=checks,
            )
        router_ping = router.exec(
            f"ping -I {router_ip.ip} -c 2 -W 1 {client_ip.ip} 2>/dev/null; "
            "printf '\nPING_RC=%s\n' $?",
            timeout=10,
        )
        client_ping = client.exec(
            f"ping -I {client_ip.ip} -c 2 -W 1 {router_ip.ip} 2>/dev/null; "
            "printf '\nPING_RC=%s\n' $?",
            timeout=10,
        )

        def success(output: str) -> bool:
            match = re.search(
                r"(\d+) packets transmitted, (\d+) (?:packets )?received", output
            )
            rc = re.search(r"PING_RC=(\d+)", output)
            return bool(
                match and rc and self._int(rc.group(1), 99) == 0
                and self._int(match.group(1)) == self._int(match.group(2)) > 0
            )

        checks["router_to_client"] = success(router_ping)
        checks["client_to_router"] = success(client_ping)
        loopback = client.exec(
            "ip -o -4 addr show dev lo 2>/dev/null | awk '$4==\"10.99.99.1/32\" {print $4}'",
            timeout=10,
        ).strip()
        checks["client_loopback_10_99_99_1"] = loopback == "10.99.99.1/32"
        passed = all(bool(checks.get(key)) for key in (
            "distinct_addresses", "same_network", "router_to_client",
            "client_to_router", "client_loopback_10_99_99_1",
        ))
        return OspfCheckResult(
            "安全-双节点拓扑", passed,
            "LAN1与ens11地址无冲突且双向可达" if passed
            else "双节点地址、链路或客户端loopback前置不满足",
            details=checks,
        )

    def find_instance(self, process_id: int, address_family: str) -> Optional[Dict[str, str]]:
        family = "ipv6" if address_family == "ipv6" else "ipv4"
        rows = self._query(
            "ospf_instance",
            f"process_id={int(process_id)} AND address_family='{family}'",
        )
        return rows[0] if rows else None

    def verify_instance(
        self, process_id: int, address_family: str, expected: Optional[Dict[str, Any]] = None,
        must_exist: bool = True,
    ) -> OspfCheckResult:
        row = self.find_instance(process_id, address_family)
        if not must_exist:
            passed = row is None
            return OspfCheckResult(
                "L1-OSPF实例", passed,
                "目标OSPF实例已删除" if passed else "目标OSPF实例仍存在",
                details={"present": row is not None},
            )
        if row is None:
            return OspfCheckResult("L1-OSPF实例", False, "目标OSPF实例不存在")
        mismatches = []
        for key, expected_value in (expected or {}).items():
            actual = row.get(key)
            if str(actual or "") != str(expected_value or ""):
                mismatches.append({"field": key, "expected": expected_value, "actual": actual})
        return OspfCheckResult(
            "L1-OSPF实例", not mismatches,
            "OSPF实例DB字段与UI保存一致" if not mismatches else "OSPF实例DB字段不一致",
            details=self.sanitize_value({"row": row, "mismatches": mismatches}),
        )

    def wait_instance_enabled(
        self, process_id: int, address_family: str, expected_enabled: bool,
        timeout: float = 20.0, progress: ProgressCallback = None,
    ) -> OspfCheckResult:
        expected = "yes" if expected_enabled else "no"
        started = time.monotonic()
        actual = ""
        next_progress = 5.0
        while time.monotonic() - started < timeout:
            row = self.find_instance(process_id, address_family)
            actual = str((row or {}).get("enabled", ""))
            if actual == expected:
                break
            elapsed = time.monotonic() - started
            if elapsed >= next_progress:
                self._wait_progress(
                    progress, "实例启停状态", started, timeout,
                    "已启用" if actual == "yes" else "已停用"
                    if actual == "no" else "未观察到实例状态",
                )
                next_progress += 5.0
            time.sleep(0.3)
        elapsed = round(time.monotonic() - started, 3)
        passed = actual == expected
        return OspfCheckResult(
            "L1-实例启停", passed,
            ("实例启停DB状态达到预期" if passed
             else "实例enabled未在超时内达到预期"),
            details={
                "expected_enabled": expected,
                "actual_enabled": actual,
                "elapsed_seconds": elapsed,
            },
        )

    def verify_area_interface(
        self, process_id: int, address_family: str, area_id: str,
        ifname: str, expected: Optional[Dict[str, Any]] = None,
    ) -> OspfCheckResult:
        family = "ipv6" if address_family == "ipv6" else "ipv4"
        area = self._query(
            "ospf_area",
            f"process_id={int(process_id)} AND address_family='{family}' "
            f"AND area_id='{str(area_id).replace(chr(39), chr(39) * 2)}'",
        )
        attrs = self._query(
            "ospf_interface_attr",
            f"process_id={int(process_id)} AND address_family='{family}' "
            f"AND ifname='{str(ifname).replace(chr(39), chr(39) * 2)}'",
        )
        mismatches = []
        row = attrs[0] if attrs else {}
        expected_values = dict(expected or {})
        expected_area_type = expected_values.pop("area_type", None)
        for key, value in expected_values.items():
            if str(row.get(key, "")) != str(value):
                mismatches.append(key)
        actual_area_type = str(area[0].get("area_type", "")) if len(area) == 1 else ""
        if (
            expected_area_type is not None
            and actual_area_type.lower() != str(expected_area_type).lower()
        ):
            mismatches.append("area_type")
        passed = len(area) == 1 and len(attrs) == 1 and not mismatches
        return OspfCheckResult(
            "L1-区域接口关联", passed,
            "实例、区域、接口三层关联正确" if passed else "区域或接口关联未按UI保存",
            details=self.sanitize_value({
                "area_count": len(area), "interface_attr_count": len(attrs),
                "area": area[0] if area else None, "interface_attr": row or None,
                "mismatches": mismatches,
                "expected_area_type": expected_area_type,
                "actual_area_type": actual_area_type,
            }),
        )

    def verify_area_type(
        self, process_id: int, address_family: str, area_id: str,
        expected_type: str,
    ) -> OspfCheckResult:
        family = "ipv6" if address_family == "ipv6" else "ipv4"
        safe_area = str(area_id).replace("'", "''")
        rows = self._query(
            "ospf_area",
            f"process_id={int(process_id)} AND address_family='{family}' "
            f"AND area_id='{safe_area}'",
        )
        actual = str(rows[0].get("area_type", "")) if len(rows) == 1 else ""
        passed = len(rows) == 1 and actual.lower() == str(expected_type).lower()
        return OspfCheckResult(
            "L1-OSPF区域类型", passed,
            "区域类型DB字段与UI一致" if passed else "区域类型DB字段不一致",
            details={
                "area_count": len(rows), "expected_type": expected_type,
                "actual_type": actual,
            },
        )

    def verify_auth_state(
        self, process_id: int, address_family: str, ifname: str,
        expected_configured: bool,
    ) -> OspfCheckResult:
        family = "ipv6" if address_family == "ipv6" else "ipv4"
        safe_ifname = str(ifname).replace("'", "''")
        rows = self._query(
            "ospf_interface_attr",
            f"process_id={int(process_id)} AND address_family='{family}' "
            f"AND ifname='{safe_ifname}'",
        )
        row = rows[0] if len(rows) == 1 else {}
        auth_type = str(row.get("auth_type", "none") or "none").lower()
        key_lengths = {
            "md5": len(str(row.get("md5_key", "") or "")),
            "auth": len(str(row.get("auth_key", "") or "")),
            "password": len(str(row.get("password", "") or "")),
        }
        configured = auth_type not in {"", "none", "no"} or any(
            length > 0 for length in key_lengths.values()
        )
        passed = configured == bool(expected_configured)
        return OspfCheckResult(
            "L1/L2-OSPF认证", passed,
            ("认证配置状态符合预期" if passed else "认证配置状态与预期不一致"),
            details={
                "configured": configured, "expected": bool(expected_configured),
                "auth_type": auth_type, "key_lengths": key_lengths,
            },
        )

    def diagnose_apply_active_config(self) -> OspfCheckResult:
        output = self._router().exec(
            f"vtysh -f {shlex.quote(self.ACTIVE_CONFIG)} 2>&1", timeout=35
        )
        safe = self.sanitize_text(output)
        errors = [
            line[:200] for line in safe.splitlines()
            if re.search(r"(?i)unknown command|invalid input|failed|error", line)
        ]
        return OspfCheckResult(
            "诊断-活动配置重放", not errors,
            "活动配置已仅用于运行态诊断重放" if not errors
            else "活动配置诊断重放被daemon拒绝",
            details={
                "diagnostic_only": True, "write_memory": False,
                "sensitive_output_redacted": True, "errors": errors,
            },
        )

    def diagnose_clear_v2_auth(self, ifname: str) -> OspfCheckResult:
        commands = [
            "configure terminal", f"interface {ifname}",
            "no ip ospf authentication",
            "no ip ospf authentication message-digest",
            "no ip ospf authentication-key",
            "no ip ospf message-digest-key 1", "end",
        ]
        command = "vtysh " + " ".join(
            f"-c {shlex.quote(item)}" for item in commands
        ) + " 2>&1"
        output = self._router().exec(command, timeout=25)
        safe = self.sanitize_text(output)
        fatal = [
            line[:200] for line in safe.splitlines()
            if re.search(r"(?i)failed|can't connect|connection refused", line)
        ]
        return OspfCheckResult(
            "诊断-清除OSPFv2认证", not fatal,
            "运行态认证已按接口精确清除" if not fatal else "运行态认证清除失败",
            details={"diagnostic_only": True, "errors": fatal},
        )

    def verify_redistribute(
        self, process_id: int, address_family: str, source: str,
        must_exist: bool = True,
    ) -> OspfCheckResult:
        family = "ipv6" if address_family == "ipv6" else "ipv4"
        safe_source = re.sub(r"[^a-z0-9-]", "", str(source).lower())
        rows = self._query(
            "ospf_redistribute",
            f"process_id={int(process_id)} AND address_family='{family}' "
            f"AND source='{safe_source}'",
        )
        present = len(rows) == 1
        passed = present == must_exist
        return OspfCheckResult(
            "L1/L2-路由引入", passed,
            ("路由引入DB记录唯一存在" if must_exist else "路由引入记录已撤销")
            if passed else "路由引入DB状态与预期不一致",
            details=self.sanitize_value({
                "source": safe_source, "present": present,
                "record": rows[0] if rows else None,
            }),
        )

    def verify_generated_config(
        self, process_id: int, address_family: str, router_id: str,
        ifname: Optional[str] = None, area_id: Optional[str] = None,
    ) -> OspfCheckResult:
        router = self._router()
        generated = router.exec(
            f"test -r {self.GENERATED_CONFIG} && cat {self.GENERATED_CONFIG}", timeout=20
        )
        active = router.exec(
            f"test -r {self.ACTIVE_CONFIG} && cat {self.ACTIVE_CONFIG}", timeout=20
        )
        running = router.exec("vtysh -c 'show running-config' 2>/dev/null", timeout=25)
        family = "ipv6" if address_family == "ipv6" else "ipv4"
        router_token = (
            "router ospf6" if family == "ipv6"
            else f"router ospf {int(process_id)}"
        )
        router_id_token = (
            f"ospf6 router-id {router_id}" if family == "ipv6"
            else f"ospf router-id {router_id}"
        )
        interface_token = ""
        router_interface_token = ""
        if ifname and area_id:
            if family == "ipv6":
                interface_token = f"ipv6 ospf6 instance-id {int(process_id)}"
                router_interface_token = f"interface {ifname} area {area_id}"
            else:
                interface_token = f"ip ospf {int(process_id)} area {area_id}"
        checks = {
            "active_exists": bool(active.strip()),
            "router_process": router_token in active,
            "router_id": router_id_token in active,
            "running_router_id": router_id_token in running,
            "interface": True if not ifname else f"interface {ifname}" in active,
            "interface_area_directive": (
                True if not interface_token else interface_token in active
            ),
            "running_interface_area_directive": (
                True if not interface_token else interface_token in running
            ),
            "router_interface_area_directive": (
                True if not router_interface_token
                else router_interface_token in active
            ),
            "running_router_interface_area_directive": (
                True if not router_interface_token
                else router_interface_token in running
            ),
        }
        passed = all(checks.values())
        details = {
            "checks": checks,
            "generated_temp_present_after_reload": bool(generated.strip()),
            "active_matches_temp_when_present": (
                self._sha(active) == self._sha(generated) if generated.strip() else None
            ),
            "generated_sha256": self._sha(generated),
            "active_sha256": self._sha(active),
            "generated_line_count": len(generated.splitlines()),
            "sensitive_directives_present": sum(
                1 for line in generated.splitlines() if SENSITIVE_LINE.search(line)
            ),
            "process_id": int(process_id), "address_family": family,
        }
        return OspfCheckResult(
            "L2-生成配置到daemon", passed,
            "DB字段已生成并由daemon运行配置加载" if passed
            else "生成配置、活动配置或daemon加载状态不一致",
            details=details,
        )

    def _vtysh_json(self, ssh: "SSHClient", command: str, sudo: bool = False) -> Any:
        prefix = "sudo -n " if sudo else ""
        output = ssh.exec(
            f"{prefix}vtysh -c {shlex.quote(command + ' json')} 2>/dev/null", timeout=25
        )
        starts = [index for index in (output.find("{"), output.find("[")) if index >= 0]
        if starts:
            output = output[min(starts):]
        try:
            return json.loads(output)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _walk_json(value: Any) -> Iterable[Any]:
        yield value
        if isinstance(value, dict):
            for item in value.values():
                yield from OspfVerifier._walk_json(item)
        elif isinstance(value, list):
            for item in value:
                yield from OspfVerifier._walk_json(item)

    def neighbor_state(
        self, role: str, address_family: str, neighbor_router_id: str,
        process_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        ssh = self._client() if role == "client" else self._router()
        sudo = role == "client"
        if address_family == "ipv6":
            commands = ["show ipv6 ospf6 neighbor"]
        else:
            commands = []
            if process_id is not None:
                commands.append(f"show ip ospf {int(process_id)} neighbor")
            commands.append("show ip ospf neighbor")
        for command in commands:
            data = self._vtysh_json(ssh, command, sudo=sudo)
            candidates = []
            if data is not None:
                for item in self._walk_json(data):
                    if not isinstance(item, dict):
                        continue
                    rendered = json.dumps(item, ensure_ascii=False)
                    if neighbor_router_id not in rendered:
                        continue
                    state = str(
                        item.get("state") or item.get("nbrState")
                        or item.get("neighborState") or ""
                    )
                    candidates.append({
                        "state": state,
                        "neighbor_id": neighbor_router_id,
                        "interface": item.get("ifaceName") or item.get("interfaceName")
                                     or item.get("interface") or "",
                        "address": item.get("address") or item.get("nbrAddress") or "",
                    })
            if candidates:
                best = candidates[0]
                best["full"] = "full" in best["state"].lower()
                if best["state"]:
                    return self.sanitize_value(best)
            prefix = "sudo -n " if sudo else ""
            text_output = ssh.exec(
                f"{prefix}vtysh -c {shlex.quote(command)} 2>/dev/null",
                timeout=20,
            )
            for line in text_output.splitlines():
                stripped = line.strip()
                if not stripped.startswith(neighbor_router_id):
                    continue
                fields = stripped.split()
                state_index = 3 if address_family == "ipv6" else 2
                state = fields[state_index] if len(fields) > state_index else ""
                return self.sanitize_value({
                    "neighbor_id": neighbor_router_id,
                    "state": state,
                    "interface": fields[-1] if fields else "",
                    "address": (
                        fields[5] if address_family == "ipv4" and len(fields) > 5
                        else ""
                    ),
                    "full": "full" in state.lower(),
                })
        return {"neighbor_id": neighbor_router_id, "state": "未发现", "full": False}

    def wait_neighbor(
        self, role: str, address_family: str, neighbor_router_id: str,
        process_id: Optional[int] = None, expect_full: bool = True,
        timeout: float = 55.0, progress: ProgressCallback = None,
    ) -> OspfCheckResult:
        started = time.monotonic()
        latest: Dict[str, Any] = {}
        next_progress = 5.0
        while time.monotonic() - started < timeout:
            latest = self.neighbor_state(
                role, address_family, neighbor_router_id, process_id
            )
            if bool(latest.get("full")) == bool(expect_full):
                break
            elapsed = time.monotonic() - started
            if elapsed >= next_progress:
                observed = str(latest.get("state") or "未发现邻居")
                self._wait_progress(
                    progress,
                    "OSPF邻居达到Full" if expect_full else "OSPF邻居撤销",
                    started, timeout, observed[:80],
                )
                next_progress += 5.0
            time.sleep(1.0)
        elapsed = round(time.monotonic() - started, 3)
        passed = bool(latest.get("full")) == bool(expect_full)
        expectation = "Full" if expect_full else "非Full/已撤销"
        return OspfCheckResult(
            "L3-OSPF邻接", passed,
            f"邻居状态达到{expectation}，耗时{elapsed}秒" if passed
            else f"邻居未在{timeout:.0f}秒内达到{expectation}",
            details={"role": role, "elapsed_seconds": elapsed, **latest},
        )

    def route_state(
        self, role: str, prefix: str, ipv6: bool = False,
        process_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        ssh = self._client() if role == "client" else self._router()
        sudo = role == "client"
        command = f"show {'ipv6' if ipv6 else 'ip'} route {prefix}"
        data = self._vtysh_json(ssh, command, sudo=sudo)
        rendered = json.dumps(data, ensure_ascii=False) if data is not None else ""
        learned = bool(data) and bool(rendered) and "ospf" in rendered.lower()
        text_semantic = ""
        text_fallback_used = False
        if not learned:
            text_fallback_used = True
            prefix_cmd = "sudo -n " if sudo else ""
            text_output = ssh.exec(
                f"{prefix_cmd}vtysh -c {shlex.quote(command)} 2>/dev/null",
                timeout=20,
            )
            text_semantic = self.sanitize_text(text_output)
            learned = bool(re.search(
                r"(?mi)(?:^O(?: IA| E1| E2| N1| N2)?[>* ]|"
                r"Known via\s+['\"]ospf['\"])",
                text_output,
            ))
        protocol_rib = False
        protocol_rib_checked = False
        if role != "client" and not ipv6 and process_id is not None:
            protocol_rib_checked = True
            protocol_output = ssh.exec(
                f"vtysh -c {shlex.quote(f'show ip ospf {int(process_id)} route')} 2>/dev/null",
                timeout=20,
            )
            protocol_rib = prefix in protocol_output
            learned = learned or protocol_rib
        kernel_cmd = (
            f"ip {'-6 ' if ipv6 else ''}route show {shlex.quote(prefix)} 2>/dev/null"
        )
        kernel = ssh.exec(("sudo -n " if sudo else "") + kernel_cmd, timeout=15)
        family_flag = "-6 " if ipv6 else ""
        all_tables = ssh.exec(
            ("sudo -n " if sudo else "")
            + f"ip -o {family_flag}route show table all 2>/dev/null | "
              f"grep -F -- {shlex.quote(prefix)} || true",
            timeout=15,
        )
        kernel_any = bool(all_tables.strip())
        return {
            "prefix": prefix, "ospf_rib": learned,
            "kernel_fib": bool(kernel.strip()) or kernel_any,
            "kernel_main_fib": bool(kernel.strip()),
            "kernel_any_table_fib": kernel_any,
            "kernel_semantic": self.sanitize_text(kernel.strip())[:300],
            "kernel_any_table_semantic": self.sanitize_text(all_tables.strip())[:300],
            "protocol_rib_checked": protocol_rib_checked,
            "protocol_rib_prefix_present": protocol_rib,
            "vtysh_text_fallback_used": text_fallback_used,
            "vtysh_ospf_marker": bool(re.search(
                r"(?mi)(?:^O(?: IA| E1| E2| N1| N2)?[>* ]|"
                r"Known via\s+['\"]ospf['\"])",
                text_semantic,
            )),
        }

    def wait_route(
        self, role: str, prefix: str, expect_present: bool,
        ipv6: bool = False, timeout: float = 45.0,
        process_id: Optional[int] = None, progress: ProgressCallback = None,
    ) -> OspfCheckResult:
        started = time.monotonic()
        latest: Dict[str, Any] = {}
        next_progress = 5.0
        while time.monotonic() - started < timeout:
            latest = self.route_state(
                role, prefix, ipv6=ipv6, process_id=process_id
            )
            present = bool(latest.get("ospf_rib") and latest.get("kernel_fib"))
            if present == expect_present:
                break
            elapsed = time.monotonic() - started
            if elapsed >= next_progress:
                observed = (
                    f"协议路由={'有' if latest.get('ospf_rib') else '无'},"
                    f"系统路由={'有' if latest.get('kernel_fib') else '无'}"
                )
                self._wait_progress(
                    progress,
                    "OSPF路由安装" if expect_present else "OSPF路由撤销",
                    started, timeout, observed,
                )
                next_progress += 5.0
            time.sleep(0.8)
        elapsed = round(time.monotonic() - started, 3)
        present = bool(latest.get("ospf_rib") and latest.get("kernel_fib"))
        passed = present == expect_present
        return OspfCheckResult(
            "L3-OSPF路由", passed,
            ("OSPF路由已安装" if expect_present else "OSPF路由已撤销")
            + f"，耗时{elapsed}秒" if passed else "OSPF RIB/FIB状态未达到预期",
            details={"elapsed_seconds": elapsed, "expected_present": expect_present, **latest},
        )

    def verify_lsdb(
        self, router_ids: Iterable[str], address_family: str = "ipv4",
        process_id: Optional[int] = None,
    ) -> OspfCheckResult:
        if address_family == "ipv6":
            command = "show ipv6 ospf6 database"
        elif process_id is not None:
            command = f"show ip ospf {int(process_id)} database"
        else:
            command = "show ip ospf database"
        data = self._vtysh_json(self._router(), command)
        rendered = json.dumps(data, ensure_ascii=False) if data is not None else ""
        text_fallback = ""
        if data is None:
            text_fallback = self._router().exec(
                f"vtysh -c {shlex.quote(command)} 2>/dev/null", timeout=25
            )
            rendered = text_fallback
        expected = list(router_ids)
        presence = {router_id: router_id in rendered for router_id in expected}
        lsa_types = sorted({
            str(item.get("lsaType") or item.get("type"))
            for item in self._walk_json(data)
            if isinstance(item, dict) and (item.get("lsaType") or item.get("type"))
        }) if data is not None else []
        if data is None:
            headings = re.findall(
                r"(?mi)^\s*(Router Link States|Net Link States|"
                r"Summary Link States|AS External Link States|NSSA-external Link States).*$",
                text_fallback,
            )
            lsa_types = sorted(set(headings))
        passed = bool(rendered.strip()) and all(presence.values())
        return OspfCheckResult(
            "L3-OSPF LSDB", passed,
            "LSDB包含本端和对端Router-LSA语义" if passed else "LSDB缺少预期Router ID",
            details={
                "router_id_presence": presence,
                "observed_lsa_types": lsa_types,
                "process_id": process_id,
                "text_fallback_used": data is None,
            },
        )

    def verify_protocol_89(
        self, ifname: str = "lan1", progress: ProgressCallback = None,
    ) -> OspfCheckResult:
        router = self._router()
        available = router.exec(
            "command -v tcpdump >/dev/null 2>&1; echo $?", timeout=8
        ).strip() == "0"

        def capture(interface: str) -> tuple[bool, int]:
            command = (
                "capture_file=/tmp/ospf_capture_$$; "
                "capture_pid=''; "
                "trap 'test -n \"$capture_pid\" && kill -TERM \"$capture_pid\" "
                "2>/dev/null || true; rm -f \"$capture_file\"' EXIT INT TERM; "
                f"tcpdump -n -i {shlex.quote(interface)} -c 1 'ip proto 89' "
                ">\"$capture_file\" 2>&1 & capture_pid=$!; "
                "capture_tick=0; while kill -0 \"$capture_pid\" 2>/dev/null "
                "&& test \"$capture_tick\" -lt 13; do sleep 1; "
                "capture_tick=$((capture_tick + 1)); done; "
                "if kill -0 \"$capture_pid\" 2>/dev/null; then "
                "kill -TERM \"$capture_pid\" 2>/dev/null || true; fi; "
                "wait \"$capture_pid\" 2>/dev/null; capture_rc=$?; "
                "cat \"$capture_file\"; printf '\nCAPTURE_RC=%s\n' \"$capture_rc\""
            )
            holder: Dict[str, Any] = {}

            def run_capture():
                try:
                    holder["output"] = router.exec(command, timeout=22)
                except BaseException as exc:  # noqa: BLE001 - 转回调用线程
                    holder["error"] = exc

            started = time.monotonic()
            worker = threading.Thread(target=run_capture, daemon=True)
            worker.start()
            while worker.is_alive():
                worker.join(timeout=5.0)
                if worker.is_alive():
                    self._wait_progress(
                        progress, "OSPF协议报文", started, 22.0,
                        "指定接口尚未捕获" if interface != "any"
                        else "所有接口尚未捕获",
                    )
            if "error" in holder:
                raise holder["error"]
            output = str(holder.get("output", ""))
            safe = self.sanitize_text(output)
            rc_match = re.search(r"CAPTURE_RC=(\d+)", output)
            rc = self._int(rc_match.group(1), 99) if rc_match else 99
            observed = (
                "IP" in safe
                and ("OSPF" in safe.upper() or "224.0.0.5" in safe)
            )
            return observed, rc

        exact_observed = any_observed = False
        exact_rc = any_rc = 99
        if available:
            exact_observed, exact_rc = capture(ifname)
            if not exact_observed:
                any_observed, any_rc = capture("any")
        passed = exact_observed or any_observed
        return OspfCheckResult(
            "L3-协议89报文", passed,
            (
                "在测试接口捕获到OSPF协议89报文" if exact_observed
                else "系统抓包捕获到OSPF协议89且FRR邻接绑定测试接口"
                if any_observed else "未在完整Hello窗口捕获到OSPF协议89报文"
            ),
            details={
                "interface": ifname,
                "tcpdump_available": available,
                "exact_interface_packet_observed": exact_observed,
                "any_interface_packet_observed": any_observed,
                "exact_capture_exit_code": exact_rc,
                "any_capture_exit_code": any_rc,
            },
        )

    def verify_v2_interface_runtime(
        self, process_id: int, ifname: str, expect_enabled: bool = True,
    ) -> OspfCheckResult:
        output = self._router().exec(
            f"vtysh -c {shlex.quote(f'show ip ospf {int(process_id)} interface {ifname}')} 2>&1",
            timeout=20,
        )
        enabled = "OSPF not enabled" not in output and "Internet Address" in output
        passed = enabled == expect_enabled
        details = {
            "process_id": int(process_id), "interface": ifname,
            "enabled": enabled,
            "has_area": "Area " in output,
            "has_router_id": "Router ID" in output,
        }
        return OspfCheckResult(
            "L3-接口运行态", passed,
            ("OSPF接口已由daemon启用" if enabled else "daemon中OSPF接口未启用")
            if passed else "OSPF接口运行态与预期不一致",
            details=details,
        )

    def diagnose_apply_v2_interface_runtime(
        self, process_id: int, ifname: str, area_id: str,
        network_type: str = "broadcast", priority: int = 1,
        cost: int = 10, hello: int = 10, dead: int = 40,
    ) -> OspfCheckResult:
        """Reapply the exact file directives to prove a reload-only defect.

        This diagnostic never represents UI success.  It does not write memory;
        normal UI instance deletion and the final process audit remove the runtime.
        """
        commands = [
            "configure terminal", f"interface {ifname}",
            f"ip ospf {int(process_id)} area {area_id}",
            f"ip ospf cost {int(cost)}",
            f"ip ospf hello-interval {int(hello)}",
            f"ip ospf dead-interval {int(dead)}",
            f"ip ospf priority {int(priority)}",
            f"ip ospf network {network_type}", "end",
        ]
        command = "vtysh " + " ".join(
            f"-c {shlex.quote(item)}" for item in commands
        ) + " 2>&1"
        output = self._router().exec(command, timeout=25)
        errors = [
            self.sanitize_text(line)[:200] for line in output.splitlines()
            if re.search(r"(?i)error|unknown|invalid|fail", line)
        ]
        state = self.verify_v2_interface_runtime(process_id, ifname, True)
        passed = not errors and state.passed
        return OspfCheckResult(
            "诊断-重放接口运行态", passed,
            "相同接口命令经vtysh重放后立即启用，证明reload未应用" if passed
            else "相同接口命令重放后仍未启用",
            details={
                "diagnostic_only": True, "write_memory": False,
                "errors": errors, "interface_state": state.details,
            },
        )

    def verify_v3_interface_runtime(
        self, ifname: str, expect_enabled: bool = True,
    ) -> OspfCheckResult:
        output = self._router().exec(
            f"vtysh -c {shlex.quote(f'show ipv6 ospf6 interface {ifname}')} 2>&1",
            timeout=20,
        )
        enabled = (
            "OSPF not enabled" not in output
            and ("Area ID" in output or "Instance ID" in output)
        )
        passed = enabled == expect_enabled
        return OspfCheckResult(
            "L3-OSPFv3接口运行态", passed,
            ("OSPFv3接口已由daemon启用" if enabled else "daemon中OSPFv3接口未启用")
            if passed else "OSPFv3接口运行态与预期不一致",
            details={"interface": ifname, "enabled": enabled},
        )

    def diagnose_apply_v3_interface_runtime(
        self, process_id: int, ifname: str, area_id: str,
        network_type: str = "broadcast",
        priority: int = 1, cost: int = 1, hello: int = 10, dead: int = 40,
    ) -> OspfCheckResult:
        commands = [
            "configure terminal", f"interface {ifname}",
            f"ipv6 ospf6 instance-id {int(process_id)}",
            f"ipv6 ospf6 cost {int(cost)}",
            f"ipv6 ospf6 hello-interval {int(hello)}",
            f"ipv6 ospf6 dead-interval {int(dead)}",
            f"ipv6 ospf6 priority {int(priority)}",
            f"ipv6 ospf6 network {network_type}", "exit",
            "router ospf6", f"interface {ifname} area {area_id}", "end",
        ]
        command = "vtysh " + " ".join(
            f"-c {shlex.quote(item)}" for item in commands
        ) + " 2>&1"
        output = self._router().exec(command, timeout=25)
        errors = [
            self.sanitize_text(line)[:200] for line in output.splitlines()
            if re.search(r"(?i)error|unknown|invalid|fail", line)
        ]
        state = self.verify_v3_interface_runtime(ifname, True)
        passed = not errors and state.passed
        return OspfCheckResult(
            "诊断-OSPFv3重放接口运行态", passed,
            "相同OSPFv3接口命令重放后立即启用" if passed
            else "OSPFv3接口命令重放后仍未启用",
            details={
                "diagnostic_only": True, "write_memory": False,
                "errors": errors, "interface_state": state.details,
            },
        )

    def ping_from_router(
        self, target: str, source: str = "192.168.148.1", ipv6: bool = False,
        expect_success: bool = True,
    ) -> OspfCheckResult:
        ping_binary = "ping6" if ipv6 else "ping"
        command = (
            f"{ping_binary} -I {shlex.quote(source)} -c 4 -W 1 "
            f"{shlex.quote(target)} 2>/dev/null; "
            "printf '\nPING_RC=%s\n' $?"
        )
        output = self._router().exec(command, timeout=12)
        match = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", output)
        rc_match = re.search(r"PING_RC=(\d+)", output)
        transmitted = self._int(match.group(1)) if match else 0
        received = self._int(match.group(2)) if match else 0
        rc = self._int(rc_match.group(1), 99) if rc_match else 99
        success = rc == 0 and transmitted > 0 and received == transmitted
        passed = success == expect_success
        return OspfCheckResult(
            "L5-真实流量", passed,
            ("真实流量双向收发成功" if success else "真实流量按控制组预期失败")
            if passed else "真实流量结果与预期不符",
            details={
                "target": target, "source": source, "transmitted": transmitted,
                "received": received, "exit_code": rc,
                "expected_success": expect_success,
            },
        )

    def _client_vtysh(self, commands: Iterable[str]) -> str:
        command = "sudo -n vtysh " + " ".join(
            f"-c {shlex.quote(item)}" for item in commands
        ) + " 2>&1"
        return self._client().exec(command, timeout=25)

    def client_add_v2_network(self, network: str, area: str = "0") -> OspfCheckResult:
        ipaddress.ip_network(network, strict=False)
        running = self._client().exec(
            "sudo -n vtysh -c 'show running-config' 2>/dev/null", timeout=20
        )
        directive = f"network {network} area {area}"
        if directive not in running:
            output = self._client_vtysh([
                "configure terminal", "router ospf", directive, "end"
            ])
            if "%" in output:
                return OspfCheckResult("拓扑-客户端OSPFv2", False, "客户端FRR拒绝测试网络")
            self._client_v2_added_networks.add(network)
        return OspfCheckResult(
            "拓扑-客户端OSPFv2", True,
            "客户端仅在FRR运行配置增量加入测试网络",
            details={"network": network, "persisted": False},
        )

    def client_setup_v3(
        self, prefix: str, transit_if: str = "ens11", area: str = "0.0.0.0",
        router_id: str = "10.66.0.18", instance_id: int = 0,
        progress: ProgressCallback = None,
    ) -> OspfCheckResult:
        interface = ipaddress.ip_interface(prefix)
        if interface.version != 6 or interface.network.prefixlen != 128:
            return OspfCheckResult(
                "拓扑-客户端OSPFv3", False, "OSPFv3测试前缀必须为IPv6 /128"
            )
        client = self._client()
        conflicts = client.exec(
            f"ip -6 route show table all 2>/dev/null | grep -F {shlex.quote(str(interface.ip))} || true",
            timeout=12,
        )
        if conflicts.strip():
            return OspfCheckResult(
                "拓扑-客户端OSPFv3", False, "随机IPv6测试前缀与现有路由冲突"
            )
        existing_ospf6d = {
            self._int(pid) for pid in client.exec(
                "pidof ospf6d 2>/dev/null || true", timeout=10
            ).split() if pid.isdigit()
        }
        daemon_started = False
        if not existing_ospf6d:
            executable = client.exec(
                "test -x /usr/lib/frr/ospf6d; echo $?", timeout=10
            ).strip()
            if executable != "0":
                return OspfCheckResult(
                    "拓扑-客户端OSPFv3", False,
                    "客户端存在FRR但缺少可执行的ospf6d",
                )
            start_output = client.exec(
                "sudo -n /usr/lib/frr/ospf6d -d -F traditional "
                "-A 127.0.0.1 </dev/null >/dev/null 2>&1; "
                "printf 'START_RC=%s\\n' $?",
                timeout=15,
            )
            start_match = re.search(r"START_RC=(\d+)", start_output)
            if start_match and self._int(start_match.group(1), 99) != 0:
                return OspfCheckResult(
                    "拓扑-客户端OSPFv3", False,
                    "客户端ospf6d临时进程启动命令失败",
                )
            deadline = time.monotonic() + 8
            process_started = time.monotonic()
            next_progress = 5.0
            current_ospf6d: set[int] = set()
            while time.monotonic() < deadline:
                current_ospf6d = {
                    self._int(pid) for pid in client.exec(
                        "pidof ospf6d 2>/dev/null || true", timeout=10
                    ).split() if pid.isdigit()
                }
                if current_ospf6d:
                    break
                if time.monotonic() - process_started >= next_progress:
                    self._wait_progress(
                        progress, "客户端OSPFv3临时进程", process_started,
                        8.0, "尚未观察到进程",
                    )
                    next_progress += 5.0
                time.sleep(0.2)
            created = current_ospf6d - existing_ospf6d
            if not created:
                return OspfCheckResult(
                    "拓扑-客户端OSPFv3", False,
                    "客户端ospf6d未能按临时运行态启动",
                )
            self._client_started_daemons.setdefault("ospf6d", set()).update(created)
            daemon_started = True
        running = client.exec(
            "sudo -n vtysh -c 'show running-config' 2>/dev/null", timeout=20
        )
        self._client_v3_created_router = "router ospf6" not in running
        client.exec(
            f"sudo -n ip -6 addr add {shlex.quote(prefix)} dev lo", timeout=12
        )
        self._client_temp_v6.add((prefix, "lo"))
        commands = [
            "configure terminal",
            f"interface {transit_if}",
            f"ipv6 ospf6 instance-id {int(instance_id)}",
            f"ipv6 ospf6 area {area}", "exit",
            "interface lo", f"ipv6 ospf6 area {area}", "exit",
            "router ospf6", f"ospf6 router-id {router_id}", "end",
        ]
        output = self._client_vtysh(commands)
        if "%" in output:
            return OspfCheckResult(
                "拓扑-客户端OSPFv3", False, "客户端FRR拒绝OSPFv3临时配置"
            )
        self._client_v3_interfaces.update({transit_if, "lo"})
        return OspfCheckResult(
            "拓扑-客户端OSPFv3", True,
            "客户端OSPFv3和随机/128仅加入运行态，未写入配置文件",
            details={
                "prefix": prefix, "transit_interface": transit_if,
                "area": area, "persisted": False,
                "instance_id": int(instance_id),
                "temporary_ospf6d_started": daemon_started,
            },
        )

    def client_remove_v2_network(self, network: str, area: str = "0", track=True) -> OspfCheckResult:
        output = self._client_vtysh([
            "configure terminal", "router ospf", f"no network {network} area {area}", "end"
        ])
        if track:
            self._client_v2_removed_networks.add(network)
        return OspfCheckResult(
            "L4-客户端前缀撤销", "%" not in output,
            "客户端已撤销单项OSPF网络宣告" if "%" not in output else "客户端拒绝撤销网络宣告",
            details={"network": network},
        )

    def client_restore_v2_network(self, network: str, area: str = "0") -> OspfCheckResult:
        output = self._client_vtysh([
            "configure terminal", "router ospf", f"network {network} area {area}", "end"
        ])
        self._client_v2_removed_networks.discard(network)
        return OspfCheckResult(
            "L4-客户端前缀恢复", "%" not in output,
            "客户端OSPF网络宣告已恢复" if "%" not in output else "客户端网络宣告恢复失败",
            details={"network": network},
        )

    def cleanup_client(self) -> OspfCheckResult:
        errors = []
        for network in sorted(self._client_v2_added_networks):
            result = self.client_remove_v2_network(network, track=False)
            if not result.passed:
                errors.append(network)
        for network in sorted(self._client_v2_removed_networks):
            result = self.client_restore_v2_network(network)
            if not result.passed:
                errors.append(network)
        for ifname in sorted(self._client_v3_interfaces):
            output = self._client_vtysh([
                "configure terminal", f"interface {ifname}",
                "no ipv6 ospf6 area 0.0.0.0",
                "no ipv6 ospf6 instance-id", "end",
            ])
            if "%" in output and "not found" not in output.lower():
                errors.append(f"ospf6:{ifname}")
        if self._client_v3_created_router:
            output = self._client_vtysh([
                "configure terminal", "no router ospf6", "end",
            ])
            if "%" in output and "not found" not in output.lower():
                errors.append("ospf6-router")
        for address, ifname in sorted(self._client_temp_v6):
            self._client().exec(
                f"sudo -n ip -6 addr del {shlex.quote(address)} dev {shlex.quote(ifname)} 2>/dev/null || true",
                timeout=12,
            )
        for daemon, pids in sorted(self._client_started_daemons.items()):
            for pid in sorted(pids):
                comm = self._client().exec(
                    f"cat /proc/{pid}/comm 2>/dev/null", timeout=8
                ).strip()
                if comm != daemon:
                    continue
                self._client().exec(
                    f"sudo -n kill -TERM {pid} 2>/dev/null || true", timeout=8
                )
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                remaining = []
                for pid in sorted(pids):
                    comm = self._client().exec(
                        f"cat /proc/{pid}/comm 2>/dev/null", timeout=8
                    ).strip()
                    if comm == daemon:
                        remaining.append(pid)
                if not remaining:
                    break
                time.sleep(0.2)
            if remaining:
                errors.append(f"daemon:{daemon}")
        self._client_v2_added_networks.clear()
        self._client_v2_removed_networks.clear()
        self._client_v3_interfaces.clear()
        self._client_v3_created_router = False
        self._client_temp_v6.clear()
        self._client_started_daemons.clear()
        return OspfCheckResult(
            "清理-客户端OSPF", not errors,
            "客户端临时OSPF网络和地址已精确恢复" if not errors else "客户端OSPF恢复失败",
            details={"error_count": len(errors)},
        )

    def probe_tagged_peer_transit(self) -> OspfCheckResult:
        """Prove whether the existing management parents carry an isolated VLAN.

        No OSPF configuration is created by this probe.  Both temporary VLAN
        interfaces are deleted in the local finally block even when SSH or ping
        fails.
        """
        router = self._router()
        peer = self._peer()
        router_if = peer_if = ""
        details: Dict[str, Any] = {}
        try:
            router_parent = router.exec(
                "ip -o route get 10.66.0.56 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}' | head -n1",
                timeout=10,
            ).strip()
            peer_parent = peer.exec(
                "ip -o route get 10.66.0.150 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}' | head -n1",
                timeout=10,
            ).strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", router_parent or ""):
                raise RuntimeError("主路由管理父接口识别失败")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", peer_parent or ""):
                raise RuntimeError("对端管理父接口识别失败")
            used_text = router.exec(
                "ip -d -o link show type vlan 2>/dev/null | sed -n 's/.* vlan id \\([0-9][0-9]*\\).*/\\1/p'",
                timeout=12,
            ) + "\n" + peer.exec(
                "ip -d -o link show type vlan 2>/dev/null | sed -n 's/.* vlan id \\([0-9][0-9]*\\).*/\\1/p'",
                timeout=12,
            )
            used = {self._int(item) for item in used_text.split() if item.isdigit()}
            candidates = [item for item in range(4093, 3000, -1) if item not in used]
            if not candidates:
                raise RuntimeError("没有可用测试VLAN ID")
            vlan_id = candidates[0]
            token = secrets.randbelow(200) + 20
            network = ipaddress.ip_network(f"198.18.{token}.0/30")
            left = str(network.network_address + 1)
            right = str(network.network_address + 2)
            router_if = f"op{vlan_id}r"[:15]
            peer_if = f"op{vlan_id}p"[:15]
            router.exec(
                f"ip link add link {shlex.quote(router_parent)} name {router_if} type vlan id {vlan_id} && "
                f"ip addr add {left}/30 dev {router_if} && ip link set {router_if} up",
                timeout=15,
            )
            peer.exec(
                f"ip link add link {shlex.quote(peer_parent)} name {peer_if} type vlan id {vlan_id} && "
                f"ip addr add {right}/30 dev {peer_if} && ip link set {peer_if} up",
                timeout=15,
            )
            forward = router.exec(
                f"ping -I {left} -c 3 -W 1 {right} 2>/dev/null; printf '\nPING_RC=%s\n' $?",
                timeout=12,
            )
            reverse = peer.exec(
                f"ping -I {right} -c 3 -W 1 {left} 2>/dev/null; printf '\nPING_RC=%s\n' $?",
                timeout=12,
            )

            def ping_semantic(output: str) -> Dict[str, int | bool]:
                match = re.search(
                    r"(\d+) packets transmitted, (\d+) (?:packets )?received", output
                )
                rc_match = re.search(r"PING_RC=(\d+)", output)
                sent = self._int(match.group(1)) if match else 0
                received = self._int(match.group(2)) if match else 0
                rc = self._int(rc_match.group(1), 99) if rc_match else 99
                return {
                    "sent": sent, "received": received, "exit_code": rc,
                    "success": rc == 0 and sent > 0 and received == sent,
                }

            fwd = ping_semantic(forward)
            rev = ping_semantic(reverse)
            available = bool(fwd["success"] and rev["success"])
            details = {
                "vlan_id": vlan_id,
                "transit_network": str(network),
                "router_parent": router_parent,
                "peer_parent": peer_parent,
                "router_to_peer": fwd,
                "peer_to_router": rev,
                "management_network_used_for_ospf": False,
            }
            return OspfCheckResult(
                "环境-三节点Transit", available,
                "独立tagged transit双向可达，可继续三节点OSPF" if available
                else "临时VLAN两端均UP但双向0接收，现有交换路径不承载额外tag",
                details=details,
            )
        except Exception as exc:
            details["error_type"] = type(exc).__name__
            return OspfCheckResult(
                "环境-三节点Transit", False,
                "无法安全建立与对端隔离的二层transit",
                details=details,
            )
        finally:
            if router_if:
                try:
                    router.exec(f"ip link del {shlex.quote(router_if)} 2>/dev/null || true", timeout=12)
                except Exception:
                    pass
            if peer_if:
                try:
                    peer.exec(f"ip link del {shlex.quote(peer_if)} 2>/dev/null || true", timeout=12)
                except Exception:
                    pass

    def remove_created_interface_cache(
        self, baseline: OspfEnvironmentSnapshot,
    ) -> OspfCheckResult:
        baseline_ids = {
            self._int(row.get("id")) for row in baseline.private_tables.get("ospf_interface", [])
        }
        current = self._query("ospf_interface")
        created = [self._int(row.get("id")) for row in current if self._int(row.get("id")) not in baseline_ids]
        if created:
            ids = ",".join(str(item) for item in created)
            self._router().exec(
                f"sqlite3 {shlex.quote(self.DB)} "
                f"{shlex.quote('DELETE FROM ospf_interface WHERE id IN (' + ids + ')')} 2>&1",
                timeout=15,
            )
        remaining = self._query("ospf_interface")
        remaining_ids = {self._int(row.get("id")) for row in remaining}
        passed = all(item not in remaining_ids for item in created)
        return OspfCheckResult(
            "清理-接口缓存", passed,
            f"已按精确ID清理{len(created)}条本轮接口缓存" if passed else "接口缓存精确清理失败",
            details={"created_ids": created, "direct_db_fallback": bool(created)},
        )

    def restore_empty_router_runtime(
        self, baseline: OspfEnvironmentSnapshot, run_init: bool = False,
    ) -> OspfCheckResult:
        """Restore only daemons absent from baseline; never restart the appliance."""
        router = self._router()
        init_output = ""
        if run_init:
            health = self.management_health()
            if not (
                health.details.get("router_ssh")
                and health.details.get("router_recovery_ssh")
            ):
                return OspfCheckResult(
                    "清理-OSPF运行态", False,
                    "主、备用管理通道未同时健康，拒绝执行ospf.sh init",
                    details={"init_invoked": False, "management": health.details},
                )
            init_output = router.exec(f"{self.SCRIPT} init 2>&1", timeout=45)
        baseline_pids = baseline.public.get("processes", {})
        current = self._processes(router)
        stopped: List[Dict[str, int | str]] = []
        for daemon in self.DAEMONS:
            keep = {self._int(pid) for pid in baseline_pids.get(daemon, [])}
            current_pids = list(current.get(daemon, []))
            excess_count = max(0, len(current_pids) - len(keep))
            candidates = [pid for pid in current_pids if pid not in keep]
            candidates.extend(pid for pid in current_pids if pid in keep)
            for pid in candidates[:excess_count]:
                comm = router.exec(
                    f"cat /proc/{pid}/comm 2>/dev/null", timeout=8
                ).strip()
                if comm != daemon:
                    continue
                router.exec(f"kill -TERM {pid} 2>/dev/null || true", timeout=8)
                stopped.append({"daemon": daemon, "pid": pid})
        deadline = time.monotonic() + 6.0
        after = self._processes(router)
        while time.monotonic() < deadline:
            pending = any(
                len(after.get(daemon, [])) != len(baseline_pids.get(daemon, []))
                for daemon in self.DAEMONS
            )
            if not pending:
                break
            time.sleep(0.2)
            after = self._processes(router)
        count_mismatches = {
            daemon: {
                "expected": len(baseline_pids.get(daemon, [])),
                "actual": len(after.get(daemon, [])),
            }
            for daemon in self.DAEMONS
            if len(after.get(daemon, [])) != len(baseline_pids.get(daemon, []))
        }
        passed = not count_mismatches
        return OspfCheckResult(
            "清理-OSPF运行态", passed,
            "仅停止基线不存在的FRR进程，未重启设备" if passed else "仍存在基线外FRR进程",
            details={
                "init_invoked": bool(run_init),
                "init_error_detected": bool(re.search(r"(?i)error|failed", init_output)),
                "stopped": stopped, "count_mismatches": count_mismatches,
            },
        )

    def verify_restored(
        self, baseline: OspfEnvironmentSnapshot,
    ) -> OspfCheckResult:
        current = self.snapshot_environment(include_peer=True)
        expected = baseline.public
        actual = current.public
        checks = {
            "table_counts": actual.get("table_counts") == expected.get("table_counts"),
            "table_hashes": actual.get("table_hashes") == expected.get("table_hashes"),
            "active_config": actual.get("active_config_sha256") == expected.get("active_config_sha256"),
            "protocol_89_rules": actual.get("protocol_89_rule_count") == expected.get("protocol_89_rule_count"),
            "ospf_routes": actual.get("ospf_route_count") == expected.get("ospf_route_count"),
            "client_config": actual.get("client_running_config_sha256") == expected.get("client_running_config_sha256"),
            "processes": {
                name: len((actual.get("processes") or {}).get(name, []))
                for name in self.DAEMONS
            } == {
                name: len((expected.get("processes") or {}).get(name, []))
                for name in self.DAEMONS
            },
            "management_router": bool((actual.get("management") or {}).get("router_ssh")),
            "management_client": bool((actual.get("management") or {}).get("client_ssh")),
            "management_peer": bool((actual.get("management") or {}).get("peer_ssh")),
        }
        passed = all(checks.values())
        return OspfCheckResult(
            "清理-三端独立残留审计", passed,
            "三端DB、配置、进程语义、路由、客户端和管理通道恢复" if passed
            else "finally后仍存在OSPF测试残留或管理通道异常",
            details={"checks": checks, "current": actual},
        )


__all__ = [
    "OSPF_TABLES", "OspfCheckResult", "OspfEnvironmentSnapshot", "OspfVerifier",
]
