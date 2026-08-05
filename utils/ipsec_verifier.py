"""新版 IPsec VPN 双端 L1-L5 验证与精确恢复。

本模块只服务 ``虚拟专网 -> IPsec VPN``（ipsec2）。认证值仅在 Python 内存、
浏览器遮罩输入框和 SSH stdin 中短暂存在；公开结果永不返回 PSK、完整 secrets
配置、SPI、硬件地址或内部 peer 修改命令。
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utils.backend_verifier import BackendVerifier, SSHClient, VerifyResult
from utils.step_recorder import register_sensitive_value


_MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
_SPI_RE = re.compile(r"(?i)(\bspi\s+)(0x[0-9a-f]+)")
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)((?:password|passwd|secret|psk|token|cookie|private[_ -]?key)"
    r"\s*[=:]\s*)(\S+)"
)
# The current device-side ``check.tagname`` contract is 1-15 characters.
# Keep generated names inside that limit so a harness name cannot invalidate
# every protocol assertion that follows.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")
_SAFE_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_NET_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
_SAFE_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_SAFE_MARKER_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")


@dataclass
class IpsecEnvironmentSnapshot:
    """Private restore material plus public, report-safe baseline."""

    public: Dict[str, Any]
    private: Dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class IpsecTopology:
    token: str
    router_policy: str
    peer_policy: str
    router_proposal: str
    peer_proposal: str
    client_source: str
    peer_service: str
    client_iface: str
    client_gateway: str
    router_underlay: str
    peer_underlay: str
    router_interface: str
    peer_interface: str
    addr_type: str = "v4"
    protocol: str = "icmp"
    router_role: str = "spoke"
    peer_role: str = "spoke"
    encap_mode: str = "tunnel"
    router_remote_addr: str = ""
    peer_remote_addr: str = ""

    @property
    def prefix_length(self) -> int:
        return 128 if self.addr_type == "v6" else 32

    @property
    def client_selector(self) -> str:
        return f"{self.client_source}/{self.prefix_length}"

    @property
    def router_service(self) -> str:
        """Router-side isolated service address.

        ``client_source`` is retained in the dataclass for compatibility with
        archived tooling, but new IPsec runs place this address on the router
        loopback instead of using the Linux client at 10.66.0.18.
        """
        return self.client_source

    @property
    def router_selector(self) -> str:
        return self.client_selector

    @property
    def peer_selector(self) -> str:
        return f"{self.peer_service}/{self.prefix_length}"

    @property
    def router_remote_endpoint(self) -> str:
        return self.router_remote_addr or self.peer_underlay

    @property
    def peer_remote_endpoint(self) -> str:
        return self.peer_remote_addr or self.router_underlay

    @property
    def uses_loopback_data_plane(self) -> bool:
        return self.encap_mode != "transport"


class IpsecVerifier:
    DB = "/etc/mnt/ikuai/config.db"
    POLICY_SCRIPT = "/usr/ikuai/script/ipsec2_policy.sh"
    PROPOSAL_SCRIPT = "/usr/ikuai/script/ipsec2_proposal.sh"
    TUNNEL_SCRIPT = "/usr/ikuai/script/ipsec2_tunnel.sh"
    COMMON_SCRIPT = "/usr/ikuai/include/ipsec2_common.sh"
    CONFIG_GLOB = "/etc/swanctl/conf.d/ipsec2-*"
    SECRETS_GLOB = "/etc/swanctl/secrets.d/ipsec2-*"
    CACHE_DIR = "/tmp/iktmp/cache/ipsec2"
    RESOLVED_DIR = "/var/run/ipsec2/resolved"

    def __init__(self, backend: BackendVerifier):
        self.backend = backend
        self._runtime_secrets: set[str] = set()
        self._created_router_addrs: set[str] = set()
        self._created_peer_addrs: set[str] = set()
        self._created_client_routes: set[str] = set()
        self._created_router_routes: set[str] = set()
        self._created_objects: set[Tuple[str, str, int, str]] = set()
        self._created_host_entries: set[Tuple[str, str]] = set()
        self._known_host_markers: set[Tuple[str, str]] = set()
        self._created_firewall_rules: set[
            Tuple[str, str, str, str, str, str]
        ] = set()
        self._known_firewall_markers: set[Tuple[str, str, str]] = set()

    def register_created_object(
        self, target: str, kind: str, object_id: int, tagname: str
    ) -> None:
        """Mark a database object as owned by this verifier instance.

        Cleanup is intentionally limited to this registry. Merely finding an
        object with a matching name is not enough authority to delete it.
        """
        if target not in {"router", "peer"} or kind not in {"policy", "proposal"}:
            raise ValueError("IPsec测试对象所有权参数非法")
        if not _SAFE_NAME_RE.fullmatch(str(tagname)):
            raise ValueError("IPsec测试对象名称不符合实机规则")
        numeric_id = int(object_id)
        if numeric_id <= 0:
            raise ValueError("IPsec测试对象ID非法")
        self._created_objects.add((target, kind, numeric_id, str(tagname)))

    @classmethod
    def sanitize_text(cls, value: Any) -> str:
        text = "" if value is None else str(value)
        text = _MAC_RE.sub("<hardware-address-redacted>", text)
        text = _SPI_RE.sub(r"\1<redacted>", text)
        text = _SECRET_ASSIGN_RE.sub(r"\1<redacted>", text)
        return text

    @classmethod
    def sanitize_value(cls, value: Any, key: str = "") -> Any:
        normalized = key.lower().replace("-", "_")
        if normalized.endswith(("_state", "_length")):
            return value
        if any(token in normalized for token in (
            "secret", "password", "passwd", "psk", "private", "cookie", "token"
        )):
            rendered = "" if value is None else str(value)
            return {"configured": bool(rendered), "length": len(rendered)}
        if isinstance(value, dict):
            return {
                str(item_key): cls.sanitize_value(item, str(item_key))
                for item_key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [cls.sanitize_value(item, key) for item in value]
        if isinstance(value, str):
            return cls.sanitize_text(value)
        return value

    @staticmethod
    def _parse_line_records(output: str) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for line in str(output or "").splitlines():
            if not line.strip():
                if current:
                    rows.append(current)
                    current = {}
                continue
            match = re.match(r"\s*([^=]+?)\s*=\s?(.*)$", line)
            if match:
                current[match.group(1).strip()] = match.group(2)
        if current:
            rows.append(current)
        return rows

    def _router(self) -> SSHClient:
        self.backend.connect_router()
        return self.backend._router

    def _client(self) -> SSHClient:
        self.backend.connect_client()
        return self.backend._client

    def _peer(self) -> SSHClient:
        self.backend.connect_peer()
        return self.backend._peer

    def _peer_recovery(self) -> SSHClient:
        self.backend.connect_ospf_peer_recovery()
        return self.backend._ospf_peer_recovery

    def _router_recovery(self) -> SSHClient:
        self.backend.connect_router_recovery()
        return self.backend._router_recovery

    def _router_lan(self) -> SSHClient:
        self.backend.connect_router_lan_management()
        return self.backend._router_lan_management

    def _query(self, ssh: SSHClient, table: str, where: str = "",
               columns: str = "*") -> List[Dict[str, str]]:
        if table not in {"ipsec2_policy", "ipsec2_proposal"}:
            raise ValueError(f"不允许查询的IPsec表: {table}")
        output = ssh.exec(
            f"sqlite3 -line {self.DB} \"SELECT {columns} FROM {table} {where}\"",
            timeout=20,
        )
        return self._parse_line_records(output)

    def query_policies(self, target: str = "router") -> List[Dict[str, Any]]:
        ssh = self._router() if target == "router" else self._peer()
        columns = (
            "id,enabled,tagname,alias,comment,addr_type,role,interface,local_ip,"
            "remote_addr,ike_version,aggressive,ike_proposals,prf,auth_method,"
            "CASE WHEN length(COALESCE(secret,''))>0 THEN 'configured' ELSE 'empty' END "
            "AS secret_state,length(COALESCE(secret,'')) AS secret_length,"
            "local_id_type,local_id,remote_id_type,remote_id,encap_mode,"
            "security_proto,esp_enc,esp_auth,ah_auth,pfs_group,ipsec_sa_time,"
            "ipsec_sa_bytes,ipsec_sa_idle,dpd_enabled,dpd_interval,dpd_timeout,"
            "dpd_action,trigger_mode,traffic"
        )
        rows = self._query(ssh, "ipsec2_policy", columns=columns)
        return [self.sanitize_value(row) for row in rows]

    def query_proposals(self, target: str = "router") -> List[Dict[str, Any]]:
        ssh = self._router() if target == "router" else self._peer()
        rows = self._query(ssh, "ipsec2_proposal")
        return [self.sanitize_value(row) for row in rows]

    def find_policy(self, tagname: str, target: str = "router") -> Optional[Dict[str, Any]]:
        return next(
            (row for row in self.query_policies(target) if row.get("tagname") == tagname),
            None,
        )

    def find_proposal(self, tagname: str,
                      target: str = "router") -> Optional[Dict[str, Any]]:
        return next(
            (row for row in self.query_proposals(target) if row.get("tagname") == tagname),
            None,
        )

    def verify_schema(self) -> VerifyResult:
        router = self._router()
        output = router.exec(
            f"sqlite3 {self.DB} \".schema ipsec2_proposal\"; "
            f"sqlite3 {self.DB} \".schema ipsec2_policy\"",
            timeout=20,
        )
        required = {
            "ipsec2_proposal", "ipsec2_policy", "tagname", "ike_proposals",
            "auth_method", "secret", "security_proto", "traffic", "dpd_enabled",
        }
        missing = sorted(token for token in required if token not in output)
        return VerifyResult(
            level="L1-IPsec数据库结构",
            passed=not missing,
            message=("IPsec2两张表及关键字段存在" if not missing
                     else f"IPsec2数据库结构缺失: {missing}"),
            details={"missing": missing, "schema_hash": hashlib.sha256(
                output.encode("utf-8", errors="replace")
            ).hexdigest()[:16]},
        )

    def verify_script_contract(self) -> VerifyResult:
        router = self._router()
        output = router.exec(
            "for f in /usr/ikuai/script/ipsec2_policy.sh "
            "/usr/ikuai/script/ipsec2_proposal.sh /usr/ikuai/script/ipsec2_tunnel.sh "
            "/usr/ikuai/include/ipsec2_common.sh; do "
            "test -f $f || exit 9; sha256sum $f; "
            "grep -nE 'register_module_urls|name=ipsec2|__check_param_add|__exec_swanctl_up|"
            "__exec_swanctl_down|__exec_create_conf|swanctl --load-all|ip -s xfrm' $f; done",
            timeout=30,
        )
        required = (
            "name=ipsec2_policy", "name=ipsec2_proposal", "name=ipsec2_tunnel",
            "__check_param_add", "__exec_swanctl_up", "__exec_swanctl_down",
            "__exec_create_conf", "swanctl --load-all", "ip -s xfrm",
        )
        missing = [token for token in required if token not in output]
        direct_secret_write = (
            "> /etc/swanctl/secrets.d/ipsec2-" in router.exec(
                "sed -n '820,1060p' /usr/ikuai/include/ipsec2_common.sh", timeout=20
            )
        )
        details = {
            "missing": missing,
            "script_hashes": re.findall(r"(?m)^([0-9a-f]{64})\s+([^\r\n]+)$", output),
            "secret_file_direct_write_detected": direct_secret_write,
        }
        return VerifyResult(
            level="L2-IPsec脚本契约",
            passed=not missing,
            message=("新版IPsec拆分脚本及运行入口已确认" if not missing
                     else f"IPsec脚本契约缺失: {missing}"),
            details=details,
        )

    def management_health(self) -> VerifyResult:
        checks: Dict[str, bool] = {}
        for name, getter in (
            ("router_primary", self._router),
            ("router_recovery", self._router_recovery),
            ("router_lan", self._router_lan),
            ("peer_primary", self._peer),
            ("peer_recovery", self._peer_recovery),
        ):
            try:
                checks[name] = getter().exec("printf IPSEC_HEALTH_OK", timeout=8).strip() == "IPSEC_HEALTH_OK"
            except Exception:
                checks[name] = False
        passed = all(checks.values())
        return VerifyResult(
            level="环境-管理通道",
            passed=passed,
            message=("主路由、对端及三条恢复通道均可达"
                     if passed else "IPsec管理/恢复通道存在不可达项"),
            details=checks,
        )

    def runtime_health(self, target: str = "router") -> VerifyResult:
        """Check charon/VICI without exposing daemon output or credentials."""
        ssh = self._router() if target == "router" else self._peer()
        pid_present = bool(ssh.exec("pidof charon 2>/dev/null", timeout=10).strip())
        vici_ready = bool(ssh.exec(
            "swanctl --stats >/dev/null 2>&1 && echo READY", timeout=15
        ).strip())
        ports = ssh.exec(
            "netstat -ln 2>/dev/null | grep -E ':(500|4500)[[:space:]]'",
            timeout=10,
        )
        udp_500 = ":500" in ports
        udp_4500 = ":4500" in ports
        passed = pid_present and vici_ready and udp_500 and udp_4500
        return VerifyResult(
            level="L2-IPsec守护进程",
            passed=passed,
            message=(
                f"{target} charon、VICI及UDP 500/4500可用"
                if passed else f"{target} IPsec守护进程未完整就绪"
            ),
            details={
                "pid_present": pid_present,
                "vici_ready": vici_ready,
                "udp_500": udp_500,
                "udp_4500": udp_4500,
            },
        )

    def initialize_runtime(self, target: str = "peer") -> VerifyResult:
        """Initialize the selected endpoint for harness continuation.

        The product-facing test must call :meth:`runtime_health` before this
        method so an ``add`` request that silently failed to start charon is
        still reported as a product failure.
        """
        ssh = self._router() if target == "router" else self._peer()
        was_running = bool(ssh.exec("pidof charon 2>/dev/null", timeout=10).strip())
        if not was_running:
            ssh.exec(f"{self.POLICY_SCRIPT} init", timeout=45)
        health = self.runtime_health(target)
        health.details.update({
            "was_running": was_running,
            "started_for_harness": not was_running and health.passed,
        })
        return health

    def verify_policy_runtime_loaded(
        self, policy_id: int, target: str = "router"
    ) -> VerifyResult:
        ssh = self._router() if target == "router" else self._peer()
        policy_id = int(policy_id)
        role = ssh.exec(
            f"sqlite3 {self.DB} \"SELECT role FROM ipsec2_policy WHERE id={policy_id}\"",
            timeout=10,
        ).strip()
        conn_name = f"ipsec2-{role}-{policy_id}" if role in {"spoke", "hub"} else ""
        health = self.runtime_health(target)
        loaded = False
        if health.passed and conn_name:
            listing = ssh.exec("swanctl --list-conns 2>/dev/null", timeout=20)
            loaded = bool(re.search(rf"(?m)^{re.escape(conn_name)}:", listing))
        config_exists = bool(ssh.exec(
            f"test -f /etc/swanctl/conf.d/{conn_name}.conf && echo YES",
            timeout=10,
        ).strip()) if conn_name else False
        secret_exists = bool(ssh.exec(
            f"test -f /etc/swanctl/secrets.d/ipsec2-{policy_id}.conf && echo YES",
            timeout=10,
        ).strip())
        passed = health.passed and loaded and config_exists and secret_exists
        return VerifyResult(
            "L2-IPsec运行加载",
            passed,
            (f"{target}策略已生成并加载到charon" if passed
             else f"{target}策略虽可能入库，但运行加载未完成"),
            details={
                "daemon": health.details,
                "connection_loaded": loaded,
                "config_exists": config_exists,
                "secret_exists": secret_exists,
            },
        )

    def reload_current_credentials(self) -> VerifyResult:
        """Clear stale in-memory credentials and reload current files safely.

        This is a harness recovery for the observed product defect where
        deleting a policy file does not unload its PSK from a long-running
        charon process.  It refuses to run while any unrelated SA exists.
        """
        details: Dict[str, Any] = {}
        for target, ssh in (("router", self._router()), ("peer", self._peer())):
            sas = self._sa_text(ssh).strip()
            if sas:
                return VerifyResult(
                    "环境-IPsec凭据重载", False,
                    f"{target}存在活动SA，拒绝清空并重载凭据",
                    details={"blocked_target": target, "active_sa": True},
                )
            output = ssh.exec("swanctl --load-all --clear 2>&1", timeout=40)
            success = "successfully loaded" in output and "connecting to" not in output
            details[target] = {
                "success": success,
                "output_class": "empty" if not output.strip() else "nonempty",
            }
            if not success:
                return VerifyResult(
                    "环境-IPsec凭据重载", False,
                    f"{target}当前凭据重新加载失败", details=details,
                )
        return VerifyResult(
            "环境-IPsec凭据重载", True,
            "双端当前凭据已清理历史缓存并重新加载", details=details,
        )

    def _policy_role(self, target: str, policy_id: int) -> str:
        policy_id = int(policy_id)
        row = next(
            (item for item in self.query_policies(target)
             if int(item.get("id") or 0) == policy_id),
            None,
        )
        role = str((row or {}).get("role") or "spoke")
        return role if role in {"spoke", "hub"} else "spoke"

    def _connection_name(self, target: str, policy_id: int) -> str:
        return f"ipsec2-{self._policy_role(target, policy_id)}-{int(policy_id)}"

    def initiate_child(self, target: str, policy_id: int) -> VerifyResult:
        if target not in {"router", "peer"}:
            raise ValueError("IPsec发起端必须是router或peer")
        policy_id = int(policy_id)
        role = self._policy_role(target, policy_id)
        child = f"ipsec2-{role}-{policy_id}-esp"
        ssh = self._router() if target == "router" else self._peer()
        output = ssh.exec(
            f"swanctl --initiate --child {child} --timeout 20 2>&1",
            timeout=30,
        )
        passed = (
            "initiate completed successfully" in output
            and "CHILD_SA" in output
            and "established" in output
        )
        # Auto-triggered policies can establish the Child between the command
        # dispatch and swanctl's completion line. Treat that race as success
        # only when the selected endpoint already reports an installed Child;
        # explicit authentication/proposal failures remain failures.
        already_established = False
        if not passed:
            try:
                observed = self._sa_semantics(self._sa_text(ssh), policy_id)
                already_established = bool(
                    observed["ike_present"] and observed["child_installed"]
                )
                passed = already_established
            except Exception:
                already_established = False
        reason = ""
        for marker in (
            "AUTHENTICATION_FAILED", "NO_PROPOSAL_CHOSEN",
            "TS_UNACCEPTABLE", "CHILD_SA_NOT_FOUND",
        ):
            if marker in output:
                reason = marker
                break
        return VerifyResult(
            "L3-IPsec发起Child SA", passed,
            (f"{target}发起IKE/Child SA成功" if passed
             else f"{target}发起IKE/Child SA失败"),
            details={
                "initiator": target,
                "connection_role": role,
                "ike_established": "IKE_SA" in output and "established" in output,
                "child_established": "CHILD_SA" in output and "established" in output,
                "failure_class": (
                    "already_established" if already_established else
                    reason or ("none" if passed else "unknown")
                ),
                "output_class": "empty" if not output.strip() else "nonempty",
                "last_events": self.sanitize_text(output).strip().splitlines()[-10:],
            },
        )

    def initiate_child_from_peer(self, peer_policy_id: int) -> VerifyResult:
        """Initiate the test CHILD SA from the internal peer endpoint."""
        return self.initiate_child("peer", peer_policy_id)

    def initiate_child_from_router(self, router_policy_id: int) -> VerifyResult:
        return self.initiate_child("router", router_policy_id)

    def terminate_test_sas(
        self, router_policy_id: int, peer_policy_id: int
    ) -> VerifyResult:
        diagnostics: List[Dict[str, Any]] = []
        for target, ssh, policy_id in (
            ("router", self._router(), int(router_policy_id)),
            ("peer", self._peer(), int(peer_policy_id)),
        ):
            names = (
                f"ipsec2-spoke-{policy_id}", f"ipsec2-hub-{policy_id}"
            )
            for _ in range(3):
                listing = self._sa_text(ssh)
                unique_ids: List[str] = []
                for name in names:
                    unique_ids.extend(re.findall(
                        rf"(?m)^{re.escape(name)}:\s+#(\d+),", listing
                    ))
                if not unique_ids:
                    break
                for unique_id in unique_ids:
                    output = ssh.exec(
                        f"swanctl --terminate --ike-id {int(unique_id)} "
                        "--force 2>&1",
                        timeout=12,
                    )
                    if (
                        "failed" in output.lower()
                        and "not found" not in output.lower()
                    ):
                        diagnostics.append({
                            "target": target,
                            "ike_id": int(unique_id),
                            "last_events": self.sanitize_text(output)
                            .strip().splitlines()[-5:],
                        })
                time.sleep(0.2)
        absent = self.wait_for_sa_absent(
            int(router_policy_id), int(peer_policy_id), timeout=12
        )
        return VerifyResult(
            "L4-IPsec精确撤销SA", absent.passed,
            ("本次双端IKE/Child SA已撤销" if absent.passed
             else "本次双端SA未完全撤销"),
            details={
                "terminate_diagnostics": diagnostics,
                "absence": absent.details,
            },
        )

    def wait_for_sa_absent(
        self, router_policy_id: int, peer_policy_id: int, timeout: int = 20
    ) -> VerifyResult:
        deadline = time.monotonic() + timeout
        last = {"router_present": True, "peer_present": True}
        while time.monotonic() < deadline:
            last = {
                "router_present": self._sa_semantics(
                    self._sa_text(self._router()), int(router_policy_id)
                )["ike_present"],
                "peer_present": self._sa_semantics(
                    self._sa_text(self._peer()), int(peer_policy_id)
                )["ike_present"],
            }
            if not any(last.values()):
                return VerifyResult(
                    "L4-IPsec SA撤销", True,
                    "双端测试SA已撤销", details=last,
                )
            time.sleep(0.5)
        return VerifyResult(
            "L4-IPsec SA撤销", False,
            "超时后仍存在测试SA", details=last,
        )

    def wait_for_child_absent(
        self, router_policy_id: int, peer_policy_id: int, timeout: int = 12
    ) -> VerifyResult:
        deadline = time.monotonic() + timeout
        last = {"router_child": True, "peer_child": True}
        while time.monotonic() < deadline:
            router = self._sa_semantics(
                self._sa_text(self._router()), int(router_policy_id)
            )
            peer = self._sa_semantics(
                self._sa_text(self._peer()), int(peer_policy_id)
            )
            last = {
                "router_child": router["child_installed"],
                "peer_child": peer["child_installed"],
                "router_ike": router["ike_established"],
                "peer_ike": peer["ike_established"],
            }
            if not last["router_child"] and not last["peer_child"]:
                return VerifyResult(
                    "L3-IPsec Child SA未建立", True,
                    "双端均无已安装Child SA", details=last,
                )
            time.sleep(0.5)
        return VerifyResult(
            "L3-IPsec Child SA未建立", False,
            "不匹配场景仍安装了Child SA", details=last,
        )

    def verify_traffic_blocked(self, topology: IpsecTopology) -> VerifyResult:
        forward = self._traffic_once(topology, reverse=False)
        reverse = self._traffic_once(topology, reverse=True)
        passed = not forward["passed"] and not reverse["passed"]
        return VerifyResult(
            "L5-IPsec撤销后流量", passed,
            ("SA撤销后双向业务流量均失败" if passed
             else "SA撤销后仍存在替代流量路径"),
            details={"forward": forward, "reverse": reverse},
        )

    def rekey_child(self, target: str, policy_id: int) -> VerifyResult:
        if target not in {"router", "peer"}:
            raise ValueError("IPsec重协商目标必须是router或peer")
        role = self._policy_role(target, int(policy_id))
        child = f"ipsec2-{role}-{int(policy_id)}-esp"
        ssh = self._router() if target == "router" else self._peer()
        output = ssh.exec(
            f"swanctl --rekey --child {child} 2>&1", timeout=30,
        )
        passed = "rekey completed successfully" in output.lower()
        return VerifyResult(
            "L4-IPsec Child SA重协商", passed,
            ("Child SA rekey完成" if passed else "Child SA rekey失败"),
            details={
                "initiator": target,
                "connection_role": role,
                "output_class": "empty" if not output.strip() else "nonempty",
                "last_events": self.sanitize_text(output).strip().splitlines()[-10:],
            },
        )

    def rekey_child_from_peer(self, peer_policy_id: int) -> VerifyResult:
        """Compatibility wrapper for archived callers."""
        return self.rekey_child("peer", peer_policy_id)

    @staticmethod
    def _fingerprint(text: str) -> str:
        return hashlib.sha256(str(text or "").encode(
            "utf-8", errors="replace"
        )).hexdigest()[:20]

    @classmethod
    def _snapshot_lines(cls, text: str) -> List[str]:
        """Return stable, report-safe lines for an in-memory state delta."""
        return sorted({
            cls.sanitize_text(line.strip())
            for line in str(text or "").splitlines()
            if line.strip()
        })

    @classmethod
    def _state_delta(
        cls, before: Iterable[str], after: Iterable[str]
    ) -> Dict[str, Any]:
        before_set = {str(item) for item in before or ()}
        after_set = {str(item) for item in after or ()}
        added = sorted(after_set - before_set)
        removed = sorted(before_set - after_set)
        limit = 20
        return {
            "新增数量": len(added),
            "减少数量": len(removed),
            "新增条目": added[:limit],
            "减少条目": removed[:limit],
            "证据是否截断": len(added) > limit or len(removed) > limit,
        }

    def _snapshot_device(self, ssh: SSHClient, include_private: bool) -> Tuple[Dict, Dict]:
        route = ssh.exec("ip -4 route show table main 2>/dev/null", timeout=15)
        route6 = ssh.exec("ip -6 route show table main 2>/dev/null", timeout=15)
        rules = ssh.exec("ip rule show 2>/dev/null", timeout=15)
        addrs = ssh.exec(
            "ip -o -4 addr show 2>/dev/null | awk '{print $2,$3,$4}'",
            timeout=15,
        )
        addrs6 = ssh.exec(
            "ip -o -6 addr show 2>/dev/null | awk '{print $2,$3,$4}'",
            timeout=15,
        )
        hosts = ssh.exec("sed -n '1,400p' /etc/hosts 2>/dev/null", timeout=15)
        xfrm_state = ssh.exec("ip -s xfrm state 2>/dev/null", timeout=15)
        xfrm_policy = ssh.exec("ip -s xfrm policy 2>/dev/null", timeout=15)
        metadata = ssh.exec(
            "for f in /etc/swanctl/conf.d/ipsec2-* /etc/swanctl/secrets.d/ipsec2-* "
            "/tmp/iktmp/cache/ipsec2/* /var/run/ipsec2/resolved/ipsec2-*; do "
            "test -f $f && stat -c '%a %s %n' $f; done",
            timeout=20,
        )
        route_lines = self._snapshot_lines(route)
        route6_lines = self._snapshot_lines(route6)
        rule_lines = self._snapshot_lines(rules)
        address_lines = self._snapshot_lines(addrs)
        address6_lines = self._snapshot_lines(addrs6)
        hosts_lines = self._snapshot_lines(hosts)
        public = {
            "route_hash": self._fingerprint("\n".join(route_lines)),
            "route6_hash": self._fingerprint("\n".join(route6_lines)),
            "rule_hash": self._fingerprint("\n".join(rule_lines)),
            "address_hash": self._fingerprint("\n".join(address_lines)),
            "address6_hash": self._fingerprint("\n".join(address6_lines)),
            "hosts_hash": self._fingerprint("\n".join(hosts_lines)),
            "xfrm_state_count": len(re.findall(r"(?m)^src\s", xfrm_state)),
            "xfrm_policy_count": len(re.findall(r"(?m)^src\s", xfrm_policy)),
            "runtime_file_metadata": self.sanitize_text(metadata).splitlines(),
            "udp_500_4500": "500" in ssh.exec(
                "netstat -ln 2>/dev/null | grep -E ':(500|4500)[[:space:]]'", timeout=10
            ) and "4500" in ssh.exec(
                "netstat -ln 2>/dev/null | grep -E ':(500|4500)[[:space:]]'", timeout=10
            ),
        }
        private: Dict[str, Any] = {
            "route_lines": route_lines,
            "route6_lines": route6_lines,
            "rule_lines": rule_lines,
            "address_lines": address_lines,
            "address6_lines": address6_lines,
            "hosts_lines": hosts_lines,
        }
        if include_private:
            private.update({
                "policy_dump": ssh.exec(
                    f"sqlite3 {self.DB} \".dump ipsec2_policy\"", timeout=20
                ),
                "proposal_dump": ssh.exec(
                    f"sqlite3 {self.DB} \".dump ipsec2_proposal\"", timeout=20
                ),
            })
        return public, private

    def snapshot_environment(self) -> IpsecEnvironmentSnapshot:
        router_public, router_private = self._snapshot_device(
            self._router(), include_private=True
        )
        peer_public, peer_private = self._snapshot_device(
            self._peer(), include_private=True
        )
        public = {
            "router": router_public,
            "peer": peer_public,
            "router_policy_count": len(self.query_policies("router")),
            "router_proposal_count": len(self.query_proposals("router")),
            "peer_policy_count": len(self.query_policies("peer")),
            "peer_proposal_count": len(self.query_proposals("peer")),
        }
        return IpsecEnvironmentSnapshot(
            public=public,
            private={
                "router": router_private,
                "peer": peer_private,
            },
        )

    def _ipv6_underlay(self, target: str, interface: str) -> str:
        ssh = self._router() if target == "router" else self._peer()
        output = ssh.exec(
            f"ip -o -6 addr show dev {interface} scope global 2>/dev/null; "
            "ip -o -6 addr show scope global 2>/dev/null",
            timeout=15,
        )
        candidates: List[ipaddress.IPv6Address] = []
        for value in re.findall(r"\binet6\s+([0-9A-Fa-f:]+)/\d+", output):
            try:
                address = ipaddress.IPv6Address(value)
            except ValueError:
                continue
            if not address.is_link_local and address not in candidates:
                candidates.append(address)
        if not candidates:
            raise RuntimeError(f"{target}未找到可用的全局/ULA IPv6地址")
        return str(candidates[0])

    def choose_topology(
        self, *, addr_type: str = "v4", router_role: str = "spoke",
        peer_role: str = "spoke", encap_mode: str = "tunnel",
        protocol: Optional[str] = None,
    ) -> IpsecTopology:
        if addr_type not in {"v4", "v6"}:
            raise ValueError("IPsec地址类型必须是v4或v6")
        if router_role not in {"spoke", "hub"} or peer_role not in {"spoke", "hub"}:
            raise ValueError("IPsec节点角色必须是spoke或hub")
        if encap_mode not in {"tunnel", "transport"}:
            raise ValueError("IPsec封装模式必须是tunnel或transport")
        if encap_mode == "transport" and "hub" in {router_role, peer_role}:
            raise ValueError("IPsec传输模式不支持Hub角色")
        token = secrets.token_hex(3)
        router_interface = "wan1"
        peer_interface = "wan1"
        if addr_type == "v6":
            router_underlay = self._ipv6_underlay("router", router_interface)
            peer_underlay = self._ipv6_underlay("peer", peer_interface)
        else:
            router_underlay = str(self.backend._ssh_config.router.host)
            peer_underlay = str(self.backend._ssh_config.peer.host)

        if encap_mode == "transport":
            router_service, peer_service = router_underlay, peer_underlay
        elif addr_type == "v6":
            first, second = token[:3], token[3:]
            router_service = str(ipaddress.IPv6Address(
                f"fd42:6970:7365:{first}:{second}::1"
            ))
            peer_service = str(ipaddress.IPv6Address(
                f"fd42:6970:7365:{first}:{second}::2"
            ))
            occupied_v6 = "\n".join([
                self._router().exec(
                    "ip -o -6 addr show; ip -6 route show table all; ip -6 xfrm policy",
                    timeout=25,
                ),
                self._peer().exec(
                    "ip -o -6 addr show; ip -6 route show table all; ip -6 xfrm policy",
                    timeout=25,
                ),
                json.dumps(self.query_policies("router"), ensure_ascii=True),
                json.dumps(self.query_policies("peer"), ensure_ascii=True),
            ])
            if router_service in occupied_v6 or peer_service in occupied_v6:
                raise RuntimeError("动态IPv6测试地址已被占用，请重新生成拓扑")
        else:
            occupied_text = "\n".join([
                self._router().exec(
                    "ip -o -4 addr show; ip -4 route show table all; ip xfrm policy",
                    timeout=25,
                ),
                self._peer().exec(
                    "ip -o -4 addr show; ip -4 route show table all; ip xfrm policy",
                    timeout=25,
                ),
                json.dumps(self.query_policies("router"), ensure_ascii=True),
                json.dumps(self.query_policies("peer"), ensure_ascii=True),
            ])
            occupied: List[ipaddress._BaseNetwork] = []
            for item in re.findall(
                r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?",
                occupied_text,
            ):
                try:
                    network = ipaddress.ip_network(
                        item if "/" in item else item + "/32", strict=False
                    )
                    if network.prefixlen:
                        occupied.append(network)
                except ValueError:
                    continue
            service_addresses: List[str] = []
            seed = int(token, 16)
            benchmark = ipaddress.ip_network("198.18.0.0/15")
            for offset in range(32, 65000):
                candidate = benchmark.network_address + (
                    (seed + offset) % 130000 + 1
                )
                network = ipaddress.ip_network(f"{candidate}/32")
                if (
                    all(not network.overlaps(existing) for existing in occupied)
                    and str(candidate) not in service_addresses
                ):
                    service_addresses.append(str(candidate))
                if len(service_addresses) == 2:
                    break
            if len(service_addresses) != 2:
                raise RuntimeError("未找到两个无冲突的IPsec测试地址")
            router_service, peer_service = service_addresses
        return IpsecTopology(
            token=token,
            router_policy=f"ipr{token}",
            peer_policy=f"ipp{token}",
            router_proposal=f"iker{token}",
            peer_proposal=f"ikep{token}",
            client_source=router_service,
            peer_service=peer_service,
            client_iface="lo",
            client_gateway="",
            router_underlay=router_underlay,
            peer_underlay=peer_underlay,
            router_interface=router_interface,
            peer_interface=peer_interface,
            addr_type=addr_type,
            protocol=protocol or ("any" if addr_type == "v6" else "icmp"),
            router_role=router_role,
            peer_role=peer_role,
            encap_mode=encap_mode,
        )

    @staticmethod
    def generate_psk() -> str:
        value = "I" + secrets.token_hex(15) + "!"
        register_sensitive_value(value)
        return value

    @staticmethod
    def _shell_quote(value: Any) -> str:
        return "'" + str(value).replace("'", "'\"'\"'") + "'"

    def _secure_script_call(self, ssh: SSHClient, script: str, action: str,
                            params: Dict[str, Any], target: str) -> str:
        if script not in {self.POLICY_SCRIPT, self.PROPOSAL_SCRIPT}:
            raise ValueError("IPsec安全执行器拒绝未知脚本")
        if action not in {"add", "edit", "del", "up", "down", "restart"}:
            raise ValueError("IPsec安全执行器拒绝未知动作")
        args: List[str] = [action]
        for key, value in params.items():
            if not _SAFE_FIELD_RE.fullmatch(str(key)):
                raise ValueError(f"IPsec参数字段非法: {key}")
            rendered = "" if value is None else str(value)
            if "\n" in rendered or "\r" in rendered or "\x00" in rendered:
                raise ValueError(f"IPsec参数包含控制字符: {key}")
            args.append(f"{key}={self._shell_quote(rendered)}")
            if any(token in key.lower() for token in ("secret", "psk", "password")):
                register_sensitive_value(rendered)
                self._runtime_secrets.add(rendered)
        body = "set -eu\n" + script + " " + " ".join(args) + "\n"
        display = f"[{target}] {script.rsplit('/', 1)[-1]} {action} fields=" + ",".join(sorted(params))
        return self.backend._ftp_exec_secret_script(
            ssh, body, display_command=display, timeout=45
        )

    def add_proposal(self, target: str, tagname: str, *,
                     auth_alg: str = "sha256", enc_alg: str = "aes256",
                     dh_group: str = "modp2048", sa_lifetime: int = 86400) -> int:
        if not _SAFE_NAME_RE.fullmatch(tagname):
            raise ValueError("IKE提议名称不符合实机规则")
        ssh = self._router() if target == "router" else self._peer()
        output = self._secure_script_call(
            ssh, self.PROPOSAL_SCRIPT, "add",
            {
                "tagname": tagname,
                "priority": 1,
                "auth_alg": auth_alg,
                "enc_alg": enc_alg,
                "dh_group": dh_group,
                "sa_lifetime": sa_lifetime,
            },
            target,
        )
        row = self.find_proposal(tagname, target)
        if not row:
            raise RuntimeError(
                "IKE提议添加后数据库未出现: " + self.sanitize_text(output)[:160]
            )
        object_id = int(row["id"])
        self.register_created_object(target, "proposal", object_id, tagname)
        return object_id

    def edit_proposal(
        self, target: str, tagname: str, **updates: Any
    ) -> VerifyResult:
        row = self.find_proposal(tagname, target)
        if not row:
            return VerifyResult(
                "L4-IPsec提议编辑", False, f"{target} IKE提议不存在"
            )
        params = {
            "id": int(row["id"]),
            "tagname": tagname,
            "priority": int(row.get("priority") or 1),
            "auth_alg": row.get("auth_alg") or "sha256",
            "enc_alg": row.get("enc_alg") or "aes256",
            "dh_group": row.get("dh_group") or "modp2048",
            "sa_lifetime": int(row.get("sa_lifetime") or 86400),
        }
        params.update(updates)
        ssh = self._router() if target == "router" else self._peer()
        self._secure_script_call(
            ssh, self.PROPOSAL_SCRIPT, "edit", params, target
        )
        current = self.find_proposal(tagname, target)
        mismatches = {
            key: {"expected": str(value), "actual": str((current or {}).get(key, ""))}
            for key, value in updates.items()
            if str((current or {}).get(key, "")) != str(value)
        }
        passed = current is not None and not mismatches
        return VerifyResult(
            "L4-IPsec提议编辑", passed,
            (f"{target} IKE提议编辑完成" if passed
             else f"{target} IKE提议编辑未收敛"),
            details={"mismatches": mismatches},
        )

    def _policy_params(
        self, target: str, topology: IpsecTopology,
        proposal_id: int, secret: str,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        is_router = target == "router"
        tagname = topology.router_policy if is_router else topology.peer_policy
        local_underlay = topology.router_underlay if is_router else topology.peer_underlay
        remote_underlay = topology.peer_underlay if is_router else topology.router_underlay
        remote_endpoint = (
            topology.router_remote_endpoint if is_router
            else topology.peer_remote_endpoint
        )
        role = topology.router_role if is_router else topology.peer_role
        src = topology.router_selector if is_router else topology.peer_selector
        dst = topology.peer_selector if is_router else topology.router_selector
        traffic = ""
        if role != "hub":
            traffic = base64.b64encode(json.dumps([{
                "src": src,
                "dst": dst,
                "protocol": topology.protocol,
                "action": "permit",
                "src_port": "",
                "dst_port": "",
            }], separators=(",", ":")).encode()).decode()
        id_type = "IPV6" if topology.addr_type == "v6" else "IPV4"
        params: Dict[str, Any] = {
            "tagname": tagname,
            "alias": f"ipsec-test-{topology.token}",
            "comment": "automation",
            "enabled": "yes",
            "addr_type": topology.addr_type,
            "role": role,
            "interface": topology.router_interface if is_router else topology.peer_interface,
            "local_ip": local_underlay,
            "remote_addr": "" if role == "hub" else remote_endpoint,
            "ike_version": "ikev2",
            "aggressive": "0",
            "ike_proposals": proposal_id,
            "prf": "sha256",
            "auth_method": "psk",
            "secret": secret,
            "local_id_type": id_type,
            "local_id": local_underlay,
            "remote_id_type": id_type,
            "remote_id": "" if role == "hub" else remote_underlay,
            "encap_mode": topology.encap_mode,
            "security_proto": "esp",
            "esp_enc": "aes256",
            "esp_auth": "sha256",
            "ah_auth": "sha256",
            "pfs_group": "modp2048",
            "ipsec_sa_time": 600,
            "ipsec_sa_bytes": 0,
            "ipsec_sa_idle": 0,
            "dpd_enabled": "yes",
            "dpd_interval": 10,
            "dpd_timeout": 30,
            "dpd_action": "restart",
            "trigger_mode": "auto",
            "traffic": traffic,
        }
        params.update(overrides or {})
        return params

    def add_policy(self, target: str, topology: IpsecTopology,
                   proposal_id: int, secret: str,
                   overrides: Optional[Dict[str, Any]] = None) -> int:
        is_router = target == "router"
        tagname = topology.router_policy if is_router else topology.peer_policy
        ssh = self._router() if is_router else self._peer()
        output = self._secure_script_call(
            ssh, self.POLICY_SCRIPT, "add",
            self._policy_params(
                target, topology, proposal_id, secret, overrides
            ),
            target,
        )
        row = self.find_policy(tagname, target)
        if not row:
            raise RuntimeError(
                "IPsec策略添加后数据库未出现: " + self.sanitize_text(output)[:160]
            )
        object_id = int(row["id"])
        self.register_created_object(target, "policy", object_id, tagname)
        return object_id

    def edit_policy(
        self, target: str, topology: IpsecTopology,
        proposal_id: int, secret: str,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> VerifyResult:
        tagname = topology.router_policy if target == "router" else topology.peer_policy
        row = self.find_policy(tagname, target)
        if not row:
            return VerifyResult(
                "L4-IPsec策略编辑", False, f"{target} IPsec策略不存在"
            )
        params = self._policy_params(
            target, topology, proposal_id, secret, overrides
        )
        params["id"] = int(row["id"])
        ssh = self._router() if target == "router" else self._peer()
        self._secure_script_call(
            ssh, self.POLICY_SCRIPT, "edit", params, target
        )
        current = self.find_policy(tagname, target)
        expected = dict(overrides or {})
        mismatches: Dict[str, Any] = {}
        for key, value in expected.items():
            if key == "secret":
                continue
            actual = (current or {}).get(key, "")
            expected_value: Any = value
            if key == "traffic":
                try:
                    expected_value = json.loads(base64.b64decode(
                        str(value).encode()
                    ).decode())
                    actual_value = json.loads(str(actual))
                    equal = actual_value == expected_value
                except Exception:
                    equal = str(actual) == str(value)
            else:
                equal = str(actual) == str(value)
            if not equal:
                mismatches[key] = {
                    "expected": self.sanitize_value(expected_value, key),
                    "actual": self.sanitize_value(actual, key),
                }
        secret_ok = (
            current is not None
            and current.get("secret_state") == "configured"
            and int(current.get("secret_length") or 0) == len(secret)
        )
        passed = current is not None and not mismatches and secret_ok
        return VerifyResult(
            "L4-IPsec策略编辑", passed,
            (f"{target} IPsec策略编辑完成" if passed
             else f"{target} IPsec策略编辑未收敛"),
            details={"mismatches": mismatches, "secret_configured": secret_ok},
        )

    def prepare_data_plane(self, topology: IpsecTopology) -> VerifyResult:
        for value in (topology.router_service, topology.peer_service):
            if not _SAFE_NET_TOKEN_RE.fullmatch(value):
                return VerifyResult("环境-IPsec数据面", False, "IPsec拓扑参数不安全")
        if not topology.uses_loopback_data_plane:
            return VerifyResult(
                "环境-IPsec数据面", True,
                "传输模式使用真实外层主机地址，不新增loopback地址",
                details={
                    "data_plane": "underlay-host-to-host",
                    "router_prefix_created": False,
                    "peer_prefix_created": False,
                },
            )
        router = self._router()
        peer = self._peer()
        family = "-6" if topology.addr_type == "v6" else "-4"
        router_exists = router.exec(
            f"ip -o {family} addr show dev lo | grep -w '{topology.router_selector}'",
            timeout=10,
        ).strip()
        peer_exists = peer.exec(
            f"ip -o {family} addr show dev lo | grep -w '{topology.peer_selector}'",
            timeout=10,
        ).strip()
        if router_exists or peer_exists:
            return VerifyResult("环境-IPsec数据面", False, "双端测试地址已被占用")
        router.exec(f"ip {family} addr add {topology.router_selector} dev lo", timeout=15)
        self._created_router_addrs.add(topology.router_selector)
        peer.exec(
            f"ip {family} addr add {topology.peer_selector} dev lo", timeout=15
        )
        self._created_peer_addrs.add(topology.peer_selector)
        router_ok = bool(router.exec(
            f"ip -o {family} addr show dev lo | grep -w '{topology.router_selector}'",
            timeout=10,
        ).strip())
        peer_ok = bool(peer.exec(
            f"ip -o {family} addr show dev lo | grep -w '{topology.peer_selector}'",
            timeout=10,
        ).strip())
        return VerifyResult(
            level="环境-IPsec数据面",
            passed=router_ok and peer_ok,
            message=(f"主路由与对端的独立loopback /{topology.prefix_length}测试地址已建立"
                     if router_ok and peer_ok
                     else "IPsec隔离数据面准备失败"),
            details={
                "router_prefix_created": router_ok,
                "peer_prefix_created": peer_ok,
                "data_plane": "router-loopback-to-peer-loopback",
            },
        )

    def install_domain_alias(
        self, target: str, alias: str, address: str, marker: str
    ) -> VerifyResult:
        if target not in {"router", "peer"}:
            raise ValueError("IPsec域名映射目标必须是router或peer")
        if not _SAFE_HOSTNAME_RE.fullmatch(alias):
            raise ValueError("IPsec测试域名格式非法")
        if not _SAFE_MARKER_RE.fullmatch(marker):
            raise ValueError("IPsec hosts标记格式非法")
        normalized_address = str(ipaddress.ip_address(address))
        ssh = self._router() if target == "router" else self._peer()
        existing = ssh.exec(
            f"grep -F -- '# {marker}' /etc/hosts 2>/dev/null", timeout=10
        ).strip()
        if existing:
            return VerifyResult(
                "环境-IPsec域名映射", False, "测试hosts标记已存在",
                details={"target": target, "marker_collision": True},
            )
        entry = f"{normalized_address} {alias} # {marker}"
        self._created_host_entries.add((target, marker))
        self._known_host_markers.add((target, marker))
        ssh.exec(
            f"printf '%s\\n' {self._shell_quote(entry)} >> /etc/hosts",
            timeout=10,
        )
        resolved = ssh.exec(
            f"getent ahostsv4 {self._shell_quote(alias)} 2>/dev/null || "
            f"getent hosts {self._shell_quote(alias)} 2>/dev/null", timeout=12
        )
        installed = bool(ssh.exec(
            f"grep -F -- {self._shell_quote('# ' + marker)} /etc/hosts",
            timeout=10,
        ).strip())
        resolved_ok = normalized_address in resolved or bool(ssh.exec(
            f"grep -F -- {self._shell_quote(normalized_address + ' ' + alias)} "
            f"/etc/hosts",
            timeout=10,
        ).strip())
        return VerifyResult(
            "环境-IPsec域名映射", installed and resolved_ok,
            ("临时域名已精确写入并可解析" if installed and resolved_ok
             else "临时域名写入或解析失败"),
            details={
                "target": target,
                "installed": installed,
                "resolved_to_expected": resolved_ok,
            },
        )

    def remove_domain_alias(self, target: str, marker: str) -> VerifyResult:
        if target not in {"router", "peer"} or not _SAFE_MARKER_RE.fullmatch(marker):
            raise ValueError("IPsec hosts清理参数非法")
        ssh = self._router() if target == "router" else self._peer()
        expression = rf"\|# {marker}$|d"
        ssh.exec(
            f"sed -i {self._shell_quote(expression)} /etc/hosts",
            timeout=12,
        )
        absent = not bool(ssh.exec(
            f"grep -F -- {self._shell_quote('# ' + marker)} /etc/hosts",
            timeout=10,
        ).strip())
        if absent:
            self._created_host_entries.discard((target, marker))
        return VerifyResult(
            "清理-IPsec域名映射", absent,
            ("临时hosts映射已精确删除" if absent else "临时hosts映射仍残留"),
            details={"target": target, "absent": absent},
        )

    def verify_domain_policy_resolution(
        self, policy_id: int, alias: str, expected_address: str,
        target: str = "router",
    ) -> VerifyResult:
        if not _SAFE_HOSTNAME_RE.fullmatch(alias):
            raise ValueError("IPsec测试域名格式非法")
        expected_address = str(ipaddress.ip_address(expected_address))
        ssh = self._router() if target == "router" else self._peer()
        policy_id = int(policy_id)
        row = next(
            (item for item in self.query_policies(target)
             if int(item.get("id") or 0) == policy_id),
            None,
        )
        resolver = ssh.exec(
            f"getent ahostsv4 {self._shell_quote(alias)} 2>/dev/null || "
            f"getent hosts {self._shell_quote(alias)} 2>/dev/null", timeout=12
        )
        conn_name = self._connection_name(target, policy_id)
        runtime = ssh.exec(
            f"grep -E '^[[:space:]]*remote_addrs[[:space:]]*=' "
            f"/etc/swanctl/conf.d/{conn_name}.conf 2>/dev/null",
            timeout=12,
        )
        database_ok = bool(row) and str(row.get("remote_addr") or "") == alias
        resolver_ok = expected_address in resolver or bool(ssh.exec(
            f"grep -F -- {self._shell_quote(expected_address + ' ' + alias)} "
            f"/etc/hosts",
            timeout=10,
        ).strip())
        runtime_ok = expected_address in runtime
        passed = database_ok and resolver_ok and runtime_ok
        return VerifyResult(
            "L2-IPsec域名对端解析", passed,
            ("域名已落库、解析并以下发地址建立运行配置" if passed
             else "域名落库、解析或运行配置未形成闭环"),
            details={
                "database_uses_alias": database_ok,
                "resolver_matches": resolver_ok,
                "runtime_uses_resolved_address": runtime_ok,
            },
        )

    def verify_hub_runtime_contract(
        self, policy_id: int, target: str = "peer"
    ) -> VerifyResult:
        policy_id = int(policy_id)
        row = next(
            (item for item in self.query_policies(target)
             if int(item.get("id") or 0) == policy_id),
            None,
        )
        ssh = self._router() if target == "router" else self._peer()
        conn_name = f"ipsec2-hub-{policy_id}"
        config = ssh.exec(
            f"grep -E '^[[:space:]]*(remote_addrs|unique)[[:space:]]*=' "
            f"/etc/swanctl/conf.d/{conn_name}.conf 2>/dev/null",
            timeout=12,
        )
        remote_empty = bool(row) and not str(row.get("remote_addr") or "")
        traffic_empty = bool(row) and str(row.get("traffic") or "") in {"", "[]"}
        checks = {
            "role_hub": bool(row) and row.get("role") == "hub",
            "remote_address_empty": remote_empty,
            "traffic_empty": traffic_empty,
            "runtime_remote_any": bool(re.search(
                r"(?m)^\s*remote_addrs\s*=\s*%any\s*$", config
            )),
            "runtime_unique_never": bool(re.search(
                r"(?m)^\s*unique\s*=\s*never\s*$", config
            )),
        }
        passed = all(checks.values())
        return VerifyResult(
            "L2-IPsec Hub运行契约", passed,
            ("Hub策略使用%any、unique=never且不要求固定对端/流量" if passed
             else "Hub策略数据库或strongSwan运行契约不完整"),
            details=checks,
        )

    def verify_transport_runtime_contract(
        self, policy_id: int, topology: IpsecTopology,
        target: str = "router",
    ) -> VerifyResult:
        policy_id = int(policy_id)
        row = next(
            (item for item in self.query_policies(target)
             if int(item.get("id") or 0) == policy_id),
            None,
        )
        ssh = self._router() if target == "router" else self._peer()
        config = ssh.exec(
            f"sed -n '1,260p' /etc/swanctl/conf.d/"
            f"{self._connection_name(target, policy_id)}.conf 2>/dev/null",
            timeout=12,
        )
        traffic = []
        try:
            traffic = json.loads(str((row or {}).get("traffic") or "[]"))
        except Exception:
            traffic = []
        expected_src = (
            topology.router_selector if target == "router"
            else topology.peer_selector
        )
        expected_dst = (
            topology.peer_selector if target == "router"
            else topology.router_selector
        )
        traffic_ok = (
            len(traffic) == 1
            and str(traffic[0].get("src")) == expected_src
            and str(traffic[0].get("dst")) == expected_dst
        )
        checks = {
            "database_transport": bool(row) and row.get("encap_mode") == "transport",
            "single_host_to_host_traffic": traffic_ok,
            "runtime_transport": bool(re.search(
                r"(?m)^\s*mode\s*=\s*transport\s*$", config
            )),
            "runtime_local_selector": topology.router_service in config
                if target == "router" else topology.peer_service in config,
            "runtime_remote_selector": topology.peer_service in config
                if target == "router" else topology.router_service in config,
        }
        passed = all(checks.values())
        return VerifyResult(
            "L2-IPsec传输模式运行契约", passed,
            ("传输模式及单条host-to-host选择器已正确下发" if passed
             else "传输模式数据库或运行配置不完整"),
            details=checks,
        )

    def verify_control_failure(self, topology: IpsecTopology) -> VerifyResult:
        ping = "ping6" if topology.addr_type == "v6" else "ping"
        output = self._router().exec(
            f"{ping} -I {topology.router_service} -c 2 -W 1 {topology.peer_service} 2>&1",
            timeout=10,
        )
        failed = not re.search(r"\b[1-9][0-9]* packets received\b|\b[1-9][0-9]* received\b", output)
        return VerifyResult(
            level="L5-IPsec建连前控制组",
            passed=failed,
            message=("建隧道前双端loopback业务地址不可达，未发现管理网替代路径"
                     if failed else "建隧道前业务前缀已可达，存在替代路径"),
            details={"failed_before_tunnel": failed},
        )

    def _sa_text(self, ssh: SSHClient) -> str:
        return ssh.exec("swanctl --list-sas 2>/dev/null", timeout=12)

    def _xfrm_text(self, ssh: SSHClient) -> Tuple[str, str]:
        return (
            ssh.exec("ip -s xfrm state 2>/dev/null", timeout=20),
            ssh.exec("ip -s xfrm policy 2>/dev/null", timeout=20),
        )

    @staticmethod
    def _sa_semantics(text: str, policy_id: int) -> Dict[str, Any]:
        names = (f"ipsec2-spoke-{policy_id}", f"ipsec2-hub-{policy_id}")
        selected = [line for line in text.splitlines() if any(name in line for name in names)]
        established = any("ESTABLISHED" in line for line in selected)
        installed = any("INSTALLED" in line or "REKEYED" in line for line in selected)
        algorithms = sorted(set(re.findall(
            r"\b(?:AES_[A-Z0-9_]+|AES_CBC_[0-9]+|HMAC_[A-Z0-9_]+|PRF_[A-Z0-9_]+|MODP_[A-Z0-9_]+)\b",
            "\n".join(selected),
        )))
        byte_pairs = [tuple(map(int, item)) for item in re.findall(
            r"(\d+) bytes_i.*?(\d+) bytes_o", "\n".join(selected)
        )]
        return {
            "ike_present": bool(selected),
            "ike_established": established,
            "child_installed": installed,
            "algorithms": algorithms,
            "bytes_in": sum(item[0] for item in byte_pairs),
            "bytes_out": sum(item[1] for item in byte_pairs),
        }

    @staticmethod
    def _xfrm_semantics(state: str, policy: str,
                        topology: IpsecTopology) -> Dict[str, Any]:
        state_count = len(re.findall(r"(?m)^src\s", state))
        policy_count = len(re.findall(r"(?m)^src\s", policy))
        selectors = (
            topology.router_service in policy and topology.peer_service in policy
        )
        outer = (
            topology.router_underlay in state and topology.peer_underlay in state
        )
        current = [tuple(map(int, pair)) for pair in re.findall(
            r"(?m)^\s*(\d+)\(bytes\),\s*(\d+)\(packets\)", state
        )]
        return {
            "state_count": state_count,
            "policy_count": policy_count,
            "selectors_present": selectors,
            "outer_endpoints_present": outer,
            "bytes": sum(item[0] for item in current),
            "packets": sum(item[1] for item in current),
        }

    def wait_for_sa(self, topology: IpsecTopology, router_id: int,
                    peer_id: int, timeout: int = 35) -> VerifyResult:
        deadline = time.monotonic() + timeout
        last: Dict[str, Any] = {}
        while time.monotonic() < deadline:
            router_sa = self._sa_semantics(self._sa_text(self._router()), router_id)
            peer_sa = self._sa_semantics(self._sa_text(self._peer()), peer_id)
            router_state, router_policy = self._xfrm_text(self._router())
            peer_state, peer_policy = self._xfrm_text(self._peer())
            router_xfrm = self._xfrm_semantics(router_state, router_policy, topology)
            peer_xfrm = self._xfrm_semantics(peer_state, peer_policy, topology)
            last = {
                "router_sa": router_sa,
                "peer_sa": peer_sa,
                "router_xfrm": router_xfrm,
                "peer_xfrm": peer_xfrm,
            }
            if (
                router_sa["ike_established"] and router_sa["child_installed"]
                and peer_sa["ike_established"] and peer_sa["child_installed"]
                and router_xfrm["selectors_present"] and peer_xfrm["selectors_present"]
                and router_xfrm["state_count"] > 0 and peer_xfrm["state_count"] > 0
            ):
                return VerifyResult(
                    "L3-IPsec双端SA/XFRM", True,
                    "双端IKE SA、Child SA、XFRM state/policy已收敛",
                    details=last,
                )
            time.sleep(1)
        return VerifyResult(
            "L3-IPsec双端SA/XFRM", False,
            f"{timeout}秒内双端SA/XFRM未完整收敛", details=last,
        )

    def _traffic_once(self, topology: IpsecTopology, reverse: bool = False) -> Dict[str, Any]:
        ping = "ping6" if topology.addr_type == "v6" else "ping"
        if reverse:
            output = self._peer().exec(
                f"{ping} -I {topology.peer_service} -c 4 -W 2 {topology.router_service} 2>&1",
                timeout=18,
            )
        else:
            output = self._router().exec(
                f"{ping} -I {topology.router_service} -c 4 -W 2 {topology.peer_service} 2>&1",
                timeout=18,
            )
        received = 0
        match = re.search(
            r"(\d+)\s+packets transmitted,\s*(\d+)(?:\s+packets)?\s+received",
            output,
        )
        if not match:
            match = re.search(r"(\d+)\s+transmitted,\s*(\d+)\s+received", output)
        if match:
            received = int(match.group(2))
        return {"passed": received > 0, "received": received}

    def verify_bidirectional_traffic(self, topology: IpsecTopology) -> VerifyResult:
        before_router = self._xfrm_semantics(*self._xfrm_text(self._router()), topology)
        before_peer = self._xfrm_semantics(*self._xfrm_text(self._peer()), topology)
        forward = self._traffic_once(topology, reverse=False)
        reverse = self._traffic_once(topology, reverse=True)
        after_router = self._xfrm_semantics(*self._xfrm_text(self._router()), topology)
        after_peer = self._xfrm_semantics(*self._xfrm_text(self._peer()), topology)
        counters = (
            after_router["packets"] > before_router["packets"]
            and after_peer["packets"] > before_peer["packets"]
        )
        passed = forward["passed"] and reverse["passed"] and counters
        return VerifyResult(
            level="L5-IPsec双向加密流量",
            passed=passed,
            message=("主路由loopback与对端loopback双向流量通过，XFRM计数增长"
                     if passed else "IPsec双向流量或XFRM计数未形成闭环"),
            details={
                "forward": forward,
                "reverse": reverse,
                "router_packet_delta": after_router["packets"] - before_router["packets"],
                "peer_packet_delta": after_peer["packets"] - before_peer["packets"],
            },
        )

    def verify_database(self, tagname: str, expected: Dict[str, Any],
                        target: str = "router", absent: bool = False) -> VerifyResult:
        row = self.find_policy(tagname, target)
        if absent:
            return VerifyResult(
                "L1-IPsec数据库", row is None,
                f"{target}策略{tagname}{'已删除' if row is None else '仍存在'}",
            )
        if row is None:
            return VerifyResult("L1-IPsec数据库", False, f"{target}策略不存在")
        mismatches = {
            key: {"expected": str(value), "actual": str(row.get(key, ""))}
            for key, value in expected.items()
            if str(row.get(key, "")) != str(value)
        }
        secret_ok = row.get("secret_state") == "configured" and int(
            row.get("secret_length") or 0
        ) > 0
        passed = not mismatches and secret_ok
        return VerifyResult(
            "L1-IPsec数据库", passed,
            (f"{target}策略字段及认证存在性正确" if passed
             else f"{target}策略数据库不一致"),
            details={"mismatches": mismatches, "secret_configured": secret_ok},
        )

    def verify_secret_permissions(self, policy_id: int,
                                  target: str = "router") -> VerifyResult:
        ssh = self._router() if target == "router" else self._peer()
        output = ssh.exec(
            f"for f in /etc/swanctl/secrets.d/ipsec2-{policy_id}.conf "
            f"{self.CACHE_DIR}/{policy_id}; do test -f $f && stat -c '%a %s %n' $f; done",
            timeout=15,
        )
        records = []
        passed = True
        for line in output.splitlines():
            parts = line.split(maxsplit=2)
            if len(parts) != 3:
                continue
            mode, size, path = parts
            acceptable = mode in {"600", "400"}
            records.append({"path_kind": "secrets" if "secrets.d" in path else "cache",
                            "mode": mode, "size": int(size), "acceptable": acceptable})
            passed = passed and acceptable
        if len(records) < 2:
            passed = False
        return VerifyResult(
            "L2-IPsec认证文件权限", passed,
            ("认证配置与缓存权限均为最小权限" if passed
             else "认证配置或缓存文件权限过宽/缺失"),
            details={"files": records},
        )

    def verify_effective_dpd(
        self, policy_id: int, target: str = "router"
    ) -> VerifyResult:
        """Compare the saved DPD values with the generated strongSwan config."""
        ssh = self._router() if target == "router" else self._peer()
        policy_id = int(policy_id)
        row = next(
            (item for item in self.query_policies(target)
             if int(item.get("id") or 0) == policy_id),
            None,
        )
        if not row:
            return VerifyResult("L2-IPsec DPD生效值", False, "目标策略不存在")
        role = str(row.get("role") or "")
        conn_name = f"ipsec2-{role}-{policy_id}"
        text = ssh.exec(
            f"grep -E '^[[:space:]]*dpd_(delay|timeout|action)[[:space:]]*=' "
            f"/etc/swanctl/conf.d/{conn_name}.conf 2>/dev/null",
            timeout=12,
        )

        def number(field: str) -> Optional[int]:
            match = re.search(
                rf"(?m)^\s*{re.escape(field)}\s*=\s*(\d+)(?:s)?\s*$", text
            )
            return int(match.group(1)) if match else None

        action_match = re.search(r"(?m)^\s*dpd_action\s*=\s*([a-z_]+)\s*$", text)
        configured_interval = int(row.get("dpd_interval") or 0)
        configured_timeout = int(row.get("dpd_timeout") or 0)
        effective_interval = number("dpd_delay")
        effective_timeout = number("dpd_timeout")
        configured_action = str(row.get("dpd_action") or "")
        effective_action = action_match.group(1) if action_match else ""
        enabled = str(row.get("dpd_enabled") or "") == "yes"
        passed = (
            not enabled
            or (
                effective_interval == configured_interval
                and effective_timeout == configured_timeout
                and effective_action == configured_action
            )
        )
        return VerifyResult(
            "L2-IPsec DPD生效值",
            passed,
            ("页面保存值与strongSwan实际DPD配置一致" if passed
             else "页面保存值被静默改写或未完整下发"),
            details={
                "enabled": enabled,
                "configured": {
                    "interval": configured_interval,
                    "timeout": configured_timeout,
                    "action": configured_action,
                },
                "effective": {
                    "interval": effective_interval,
                    "timeout": effective_timeout,
                    "action": effective_action,
                },
            },
        )

    def install_dpd_blackhole(
        self, source_address: str, marker: str, target: str = "peer"
    ) -> VerifyResult:
        if target not in {"router", "peer"}:
            raise ValueError("DPD黑洞目标必须是router或peer")
        if not _SAFE_MARKER_RE.fullmatch(marker):
            raise ValueError("DPD黑洞标记格式非法")
        address = ipaddress.ip_address(source_address)
        if address.version != 4:
            raise ValueError("DPD黑洞当前只对IPv4 IKE/ESP注入规则")
        ssh = self._router() if target == "router" else self._peer()
        tool = "iptables"
        rules = (
            ("udp", "500"), ("udp", "4500"), ("esp", ""),
        )
        for protocol, port in rules:
            key = (target, tool, str(address), protocol, port, marker)
            self._created_firewall_rules.add(key)
            self._known_firewall_markers.add((target, tool, marker))
            port_arg = f" --dport {port}" if port else ""
            command = (
                f"{tool} -I INPUT 1 -s {self._shell_quote(address)} "
                f"-p {protocol}{port_arg} -m comment --comment "
                f"{self._shell_quote(marker)} -j DROP"
            )
            ssh.exec(command, timeout=12)
        count = self._firewall_marker_count(ssh, tool, marker)
        passed = count >= len(rules)
        return VerifyResult(
            "环境-IPsec DPD黑洞注入", passed,
            ("已注入仅针对测试对端的IKE/ESP丢弃规则" if passed
             else "DPD黑洞规则没有完整生效"),
            details={"rule_count": count, "expected": len(rules)},
        )

    @staticmethod
    def _firewall_marker_count(ssh: SSHClient, tool: str, marker: str) -> int:
        output = ssh.exec(
            f"{tool}-save 2>/dev/null | grep -F -- "
            f"{IpsecVerifier._shell_quote(marker)} || true",
            timeout=12,
        )
        return sum(1 for line in output.splitlines() if marker in line)

    def remove_dpd_blackhole(
        self, source_address: str, marker: str, target: str = "peer"
    ) -> VerifyResult:
        if target not in {"router", "peer"} or not _SAFE_MARKER_RE.fullmatch(marker):
            raise ValueError("DPD黑洞清理参数非法")
        address = ipaddress.ip_address(source_address)
        ssh = self._router() if target == "router" else self._peer()
        errors: List[str] = []
        for protocol, port in (("udp", "500"), ("udp", "4500"), ("esp", "")):
            port_arg = f" --dport {port}" if port else ""
            command = (
                f"iptables -D INPUT -s {self._shell_quote(address)} "
                f"-p {protocol}{port_arg} -m comment --comment "
                f"{self._shell_quote(marker)} -j DROP 2>&1 || true"
            )
            output = ssh.exec(command, timeout=12)
            if "No such rule" in output:
                continue
        remaining = self._firewall_marker_count(ssh, "iptables", marker)
        if remaining:
            errors.append("marker-still-present")
        for key in list(self._created_firewall_rules):
            if key[0] == target and key[-1] == marker:
                self._created_firewall_rules.discard(key)
        return VerifyResult(
            "清理-IPsec DPD黑洞", not errors,
            ("DPD黑洞规则已全部撤销" if not errors else "DPD黑洞规则仍有残留"),
            details={"remaining_rules": remaining, "errors": errors},
        )

    def verify_dpd_blackhole_detection(
        self, topology: IpsecTopology, router_policy_id: int,
        peer_policy_id: int, *, marker: str, max_wait: Optional[int] = None,
    ) -> VerifyResult:
        if topology.addr_type != "v4":
            return VerifyResult(
                "L5-IPsec长时间DPD黑洞", False,
                "当前长时间DPD黑洞夹具要求IPv4外层地址",
            )
        effective = self.verify_effective_dpd(router_policy_id, "router")
        configured = effective.details.get("configured", {})
        applied = effective.details.get("effective", {})
        interval = self._as_int(applied.get("interval") or configured.get("interval"))
        timeout = self._as_int(applied.get("timeout") or configured.get("timeout"))
        allowed = timeout + max(15, interval * 2)
        if max_wait is None:
            try:
                max_wait = int(os.getenv("IPSEC_DPD_MAX_WAIT", "230"))
            except ValueError:
                max_wait = 230
        max_wait = max(30, min(max_wait, 900))
        try:
            poll_seconds = float(os.getenv("IPSEC_DPD_POLL_SECONDS", "5"))
        except ValueError:
            poll_seconds = 5.0
        poll_seconds = max(1.0, min(poll_seconds, 30.0))
        started = time.monotonic()
        detected_at: Optional[float] = None
        states: List[Dict[str, Any]] = []
        baseline_router = self._sa_semantics(
            self._sa_text(self._router()), int(router_policy_id)
        )
        baseline_peer = self._sa_semantics(
            self._sa_text(self._peer()), int(peer_policy_id)
        )
        baseline_ok = (
            baseline_router["child_installed"]
            and baseline_peer["child_installed"]
        )
        if not baseline_ok:
            return VerifyResult(
                "L5-IPsec长时间DPD黑洞", False,
                "DPD黑洞夹具要求先存在双端已建立Child SA",
                details={"baseline_router": baseline_router,
                         "baseline_peer": baseline_peer},
            )
        inject = self.install_dpd_blackhole(
            topology.router_underlay, marker, target="peer"
        )
        if not inject.passed:
            self.remove_dpd_blackhole(topology.router_underlay, marker, "peer")
            return VerifyResult(
                "L5-IPsec长时间DPD黑洞", False,
                "DPD黑洞规则注入失败", details={"inject": inject.details},
            )
        try:
            deadline = started + max_wait
            last_state = None
            while time.monotonic() < deadline:
                router = self._sa_semantics(
                    self._sa_text(self._router()), int(router_policy_id)
                )
                peer = self._sa_semantics(
                    self._sa_text(self._peer()), int(peer_policy_id)
                )
                state = (
                    router["ike_present"], router["ike_established"],
                    router["child_installed"], peer["ike_present"],
                    peer["child_installed"],
                )
                elapsed = round(time.monotonic() - started, 1)
                if state != last_state:
                    states.append({"elapsed_seconds": elapsed, "state": state})
                    last_state = state
                if not router["ike_present"] or not router["child_installed"]:
                    detected_at = elapsed
                    break
                time.sleep(poll_seconds)
        finally:
            removed = self.remove_dpd_blackhole(
                topology.router_underlay, marker, target="peer"
            )
        passed = (
            detected_at is not None
            and detected_at <= allowed
            and removed.passed
        )
        return VerifyResult(
            "L5-IPsec长时间DPD黑洞", passed,
            ("DPD在生效超时容差内识别黑洞并撤销Child SA" if passed
             else "DPD黑洞识别超出实际超时容差或规则未清理"),
            details={
                "detected_seconds": detected_at,
                "allowed_seconds": allowed,
                "max_wait_seconds": max_wait,
                "configured": configured,
                "effective": applied,
                "baseline_established": baseline_ok,
                "state_timeline": states,
                "blackhole_removed": removed.passed,
            },
        )

    @staticmethod
    def _load_json_output(output: str) -> Dict[str, Any]:
        text = str(output or "").strip()
        try:
            payload = json.loads(text)
        except Exception as exc:
            raise RuntimeError("IPsec隧道接口没有返回有效JSON") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("IPsec隧道接口返回结构异常")
        return payload

    @staticmethod
    def _as_int(value: Any) -> int:
        try:
            return int(float(str(value or "0")))
        except (TypeError, ValueError):
            return 0

    def query_tunnel_observability(
        self, policy_id: int, target: str = "router", tunnel_key: str = ""
    ) -> Dict[str, Any]:
        """Return a secret-safe summary of list/detail/log tunnel APIs."""
        ssh = self._router() if target == "router" else self._peer()
        policy_id = int(policy_id)
        listing = self._load_json_output(ssh.exec(
            f"{self.TUNNEL_SCRIPT} show TYPE='list,list_total'", timeout=35
        ))
        rows = listing.get("list") if isinstance(listing.get("list"), list) else []
        row = next(
            (item for item in rows if isinstance(item, dict) and int(
                item.get("policy_id") or item.get("id") or 0
            ) == policy_id and (
                not tunnel_key or str(item.get("tunnel_key") or "") == tunnel_key
            )),
            None,
        )
        if not row:
            return {
                "row_found": False,
                "list_total": self._as_int(listing.get("list_total")),
            }
        selected_tunnel_key = str(row.get("tunnel_key") or "")
        if selected_tunnel_key and not re.fullmatch(
            r"[A-Za-z0-9_.:#-]{1,128}", selected_tunnel_key
        ):
            raise RuntimeError("IPsec隧道标识格式异常")
        key_arg = (
            f" tunnel_key={self._shell_quote(selected_tunnel_key)}"
            if selected_tunnel_key else ""
        )
        detail_payload = self._load_json_output(ssh.exec(
            f"{self.TUNNEL_SCRIPT} show TYPE='detail' id={policy_id}{key_arg}",
            timeout=35,
        ))
        log_payload = self._load_json_output(ssh.exec(
            f"{self.TUNNEL_SCRIPT} show TYPE='log' id={policy_id}{key_arg}",
            timeout=35,
        ))
        detail = detail_payload.get("detail", detail_payload)
        log = log_payload.get("log", log_payload)
        detail = detail if isinstance(detail, dict) else {}
        log = log if isinstance(log, dict) else {}
        statistics = detail.get("statistics")
        statistics = statistics if isinstance(statistics, dict) else {}
        traffic_rate = statistics.get("traffic_rate")
        traffic_rate = traffic_rate if isinstance(traffic_rate, dict) else statistics
        sa = detail.get("sa")
        sa = sa if isinstance(sa, dict) else {}
        esp = sa.get("esp")
        esp = esp if isinstance(esp, dict) else {}
        inbound_sa = esp.get("inbound")
        inbound_sa = inbound_sa if isinstance(inbound_sa, dict) else sa
        outbound_sa = esp.get("outbound")
        outbound_sa = outbound_sa if isinstance(outbound_sa, dict) else sa
        statistic_names = (
            "in_protected_packets", "out_protected_packets",
            "in_protected_bytes", "out_protected_bytes",
            "in_packet_rate", "out_packet_rate",
            "in_byte_rate", "out_byte_rate",
        )
        sa_names = (
            "ipsec_sa_lifetime", "ipsec_sa_lifetime_bytes",
            "remaining_ipsec_sa_lifetime",
            "remaining_ipsec_sa_lifetime_bytes",
        )
        return self.sanitize_value({
            "row_found": True,
            "policy_id": policy_id,
            "tunnel_key": selected_tunnel_key,
            "list_total": self._as_int(listing.get("list_total")),
            "list": {
                "status": row.get("status"),
                "in_bytes": self._as_int(row.get("in_bytes")),
                "out_bytes": self._as_int(row.get("out_bytes")),
                "field_names": sorted(row.keys()),
            },
            "detail": {
                "field_names": sorted(detail.keys()),
                "statistics": {
                    name: self._as_int(traffic_rate.get(name))
                    for name in statistic_names if name in traffic_rate
                },
                "statistics_field_names": sorted(statistics.keys()),
                "traffic_rate_field_names": sorted(traffic_rate.keys()),
                "sa": {
                    **{
                        name: inbound_sa.get(name)
                        for name in sa_names if name in inbound_sa
                    },
                    "inbound_ipsec_sa_lifetime_bytes": inbound_sa.get(
                        "ipsec_sa_lifetime_bytes"
                    ),
                    "outbound_ipsec_sa_lifetime_bytes": outbound_sa.get(
                        "ipsec_sa_lifetime_bytes"
                    ),
                },
                "sa_field_names": sorted(sa.keys()),
                "esp_field_names": sorted(esp.keys()),
                "inbound_sa_field_names": sorted(inbound_sa.keys()),
                "outbound_sa_field_names": sorted(outbound_sa.keys()),
            },
            "log": {
                "field_names": sorted(log.keys()),
                "has_title": bool(log.get("title")),
                "has_diagnosis": bool(log.get("diagnosis")),
                "has_technical_logs": bool(log.get("technical_logs")),
            },
        })

    def query_child_inventory(
        self, policy_ids: Iterable[int], target: str = "router"
    ) -> Dict[str, Any]:
        ssh = self._router() if target == "router" else self._peer()
        text = self._sa_text(ssh)
        per_policy: Dict[str, Any] = {}
        total_installed = 0
        for raw_id in policy_ids:
            policy_id = int(raw_id)
            child_pattern = re.compile(
                rf"(?m)^\s+ipsec2-(?:spoke|hub)-{policy_id}-esp:.*"
                rf"(?:INSTALLED|REKEYED).*$"
            )
            child_lines = child_pattern.findall(text)
            installed = len(child_lines)
            total_installed += installed
            semantics = self._sa_semantics(text, policy_id)
            per_policy[str(policy_id)] = {
                "installed_children": installed,
                "ike_established": semantics["ike_established"],
                "bytes_in": semantics["bytes_in"],
                "bytes_out": semantics["bytes_out"],
            }
        return {
            "target": target,
            "total_installed": total_installed,
            "per_policy": per_policy,
        }

    def query_multi_tunnel_observability(
        self, policy_ids: Iterable[int], target: str = "router"
    ) -> Dict[str, Any]:
        ids = sorted({int(value) for value in policy_ids})
        ssh = self._router() if target == "router" else self._peer()
        listing = self._load_json_output(ssh.exec(
            f"{self.TUNNEL_SCRIPT} show TYPE='list,list_total'", timeout=35
        ))
        rows = listing.get("list") if isinstance(listing.get("list"), list) else []
        selected_rows = [
            item for item in rows
            if isinstance(item, dict)
            and int(item.get("policy_id") or item.get("id") or 0) in ids
        ]
        observations: List[Dict[str, Any]] = []
        for row in selected_rows:
            policy_id = int(row.get("policy_id") or row.get("id") or 0)
            tunnel_key = str(row.get("tunnel_key") or "")
            observations.append(self.query_tunnel_observability(
                policy_id, target, tunnel_key=tunnel_key
            ))
        statistic_names = (
            "in_protected_packets", "out_protected_packets",
            "in_protected_bytes", "out_protected_bytes",
        )
        aggregate = {
            name: sum(
                self._as_int(item.get("detail", {}).get("statistics", {}).get(name))
                for item in observations
            )
            for name in statistic_names
        }
        keys = [
            str(item.get("tunnel_key") or "") for item in selected_rows
            if str(item.get("tunnel_key") or "")
        ]
        return self.sanitize_value({
            "requested_policy_ids": ids,
            "list_total": self._as_int(listing.get("list_total")),
            "matched_rows": len(selected_rows),
            "distinct_tunnel_keys": len(set(keys)),
            "per_tunnel": observations,
            "aggregate_statistics": aggregate,
            "child_inventory": self.query_child_inventory(ids, target),
        })

    def policy_action(self, target: str, action: str, policy_id: int) -> VerifyResult:
        ssh = self._router() if target == "router" else self._peer()
        output = self._secure_script_call(
            ssh, self.POLICY_SCRIPT, action, {"id": int(policy_id)}, target
        )
        row = next((r for r in self.query_policies(target)
                    if str(r.get("id")) == str(policy_id)), None)
        expected = {"up": "yes", "down": "no"}.get(action)
        passed = True
        if expected is not None:
            passed = bool(row) and row.get("enabled") == expected
        if action == "del":
            passed = row is None
        return VerifyResult(
            f"L4-IPsec-{action}", passed,
            f"{target}策略{action}{'完成' if passed else '未收敛'}",
            details={"row_present": row is not None,
                     "enabled": row.get("enabled") if row else None,
                     "output_class": "empty" if not output.strip() else "nonempty"},
        )

    def cleanup(self, topology: Optional[IpsecTopology] = None) -> VerifyResult:
        errors: List[str] = []
        owned_objects = sorted(self._created_objects)
        for target, kind, object_id, name in owned_objects:
            try:
                row = self.find_policy(name, target) if kind == "policy" else self.find_proposal(name, target)
                if not row:
                    self._created_objects.discard((target, kind, object_id, name))
                    continue
                if int(row.get("id") or 0) != object_id:
                    errors.append(f"{target}-{kind}-owner-mismatch")
                    continue
                ssh = self._router() if target == "router" else self._peer()
                script = self.POLICY_SCRIPT if kind == "policy" else self.PROPOSAL_SCRIPT
                self._secure_script_call(
                    ssh, script, "del", {"id": object_id}, target
                )
                self._created_objects.discard((target, kind, object_id, name))
            except Exception as exc:
                errors.append(f"{target}-{kind}-{type(exc).__name__}")
        for prefix in list(self._created_client_routes):
            try:
                self._client().exec(f"sudo -n ip route del {prefix}", timeout=15)
                self._created_client_routes.discard(prefix)
            except Exception as exc:
                errors.append(f"client-route-{type(exc).__name__}")
        for prefix in list(self._created_router_routes):
            try:
                self._router().exec(f"ip route del {prefix}", timeout=15)
                self._created_router_routes.discard(prefix)
            except Exception as exc:
                errors.append(f"router-route-{type(exc).__name__}")
        for prefix in list(self._created_peer_addrs):
            try:
                self._peer().exec(f"ip addr del {prefix} dev lo", timeout=15)
                self._created_peer_addrs.discard(prefix)
            except Exception as exc:
                errors.append(f"peer-addr-{type(exc).__name__}")
        for prefix in list(self._created_router_addrs):
            try:
                self._router().exec(f"ip addr del {prefix} dev lo", timeout=15)
                self._created_router_addrs.discard(prefix)
            except Exception as exc:
                errors.append(f"router-addr-{type(exc).__name__}")
        for target, marker in list(self._created_host_entries):
            try:
                removed = self.remove_domain_alias(target, marker)
                if not removed.passed:
                    errors.append(f"{target}-hosts-{marker}")
            except Exception as exc:
                errors.append(f"{target}-hosts-{type(exc).__name__}")
        firewall_groups: Dict[Tuple[str, str], str] = {}
        for target, _, source, _, _, marker in self._created_firewall_rules:
            firewall_groups[(target, marker)] = source
        for (target, marker), source in firewall_groups.items():
            try:
                removed = self.remove_dpd_blackhole(source, marker, target)
                if not removed.passed:
                    errors.append(f"{target}-firewall-{marker}")
            except Exception as exc:
                errors.append(f"{target}-firewall-{type(exc).__name__}")
        residual: List[str] = []
        if topology and owned_objects:
            for target, kind, _, name in owned_objects:
                row = (
                    self.find_policy(name, target)
                    if kind == "policy" else self.find_proposal(name, target)
                )
                if row:
                    residual.append(f"{target}-{kind}")
        passed = not errors and not residual
        return VerifyResult(
            "清理-IPsec精确恢复", passed,
            ("本次登记的策略、提议和双端临时地址已精确清理"
             if passed else "IPsec精确清理存在异常或残留"),
            details={
                "errors": errors,
                "residual": residual,
                "owned_object_count": len(owned_objects),
                "created_host_entry_count": len(self._created_host_entries),
                "created_firewall_rule_count": len(self._created_firewall_rules),
            },
        )

    def restore_daemon_state(
        self, snapshot: IpsecEnvironmentSnapshot
    ) -> VerifyResult:
        """Restore only charon runtime state changed by the test.

        Full route/address hashes remain the responsibility of
        :meth:`verify_restored`; this method deliberately does not touch
        unrelated GRE, OSPF, WAN or firewall state.
        """
        errors: List[str] = []
        details: Dict[str, Any] = {}
        for target, ssh in (("router", self._router()), ("peer", self._peer())):
            baseline = bool(
                snapshot.public.get(target, {}).get("udp_500_4500", False)
            )
            running = bool(ssh.exec("pidof charon 2>/dev/null", timeout=10).strip())
            if not baseline and running:
                policies = len(self.query_policies(target))
                sas = self._sa_text(ssh).strip()
                if policies or sas:
                    errors.append(f"{target}-daemon-stop-blocked")
                else:
                    ssh.exec("killall charon 2>/dev/null || true", timeout=10)
                    deadline = time.monotonic() + 6
                    while time.monotonic() < deadline:
                        if not ssh.exec("pidof charon 2>/dev/null", timeout=8).strip():
                            break
                        time.sleep(0.2)
            elif baseline and not running:
                ssh.exec(f"{self.POLICY_SCRIPT} init", timeout=45)

            current = bool(ssh.exec(
                "pidof charon >/dev/null 2>&1 && "
                "netstat -ln 2>/dev/null | grep -qE ':(500|4500)[[:space:]]' && "
                "echo READY",
                timeout=12,
            ).strip())
            if current != baseline:
                errors.append(f"{target}-daemon-state")
            details[target] = {
                "baseline_running": baseline,
                "current_running": current,
            }
        return VerifyResult(
            "清理-IPsec守护进程恢复", not errors,
            ("双端charon运行状态恢复到测试前" if not errors
             else "charon运行状态未完全恢复"),
            details={"errors": errors, "devices": details},
        )

    def exact_residual_audit(
        self, topology: Any,
        snapshot: Optional[IpsecEnvironmentSnapshot] = None,
    ) -> VerifyResult:
        topologies = (
            [topology] if isinstance(topology, IpsecTopology)
            else list(topology or [])
        )
        checks: Dict[str, bool] = {}
        for item in topologies:
            prefix = item.token
            checks[f"{prefix}_router_policy_absent"] = self.find_policy(
                item.router_policy, "router"
            ) is None
            checks[f"{prefix}_peer_policy_absent"] = self.find_policy(
                item.peer_policy, "peer"
            ) is None
            checks[f"{prefix}_router_proposal_absent"] = self.find_proposal(
                item.router_proposal, "router"
            ) is None
            checks[f"{prefix}_peer_proposal_absent"] = self.find_proposal(
                item.peer_proposal, "peer"
            ) is None
            if item.uses_loopback_data_plane:
                family = "-6" if item.addr_type == "v6" else "-4"
                checks[f"{prefix}_router_address_absent"] = not bool(
                    self._router().exec(
                        f"ip -o {family} addr show dev lo | "
                        f"grep -w '{item.router_selector}'",
                        timeout=10,
                    ).strip()
                )
                checks[f"{prefix}_peer_address_absent"] = not bool(
                    self._peer().exec(
                        f"ip -o {family} addr show dev lo | "
                        f"grep -w '{item.peer_selector}'",
                        timeout=10,
                    ).strip()
                )
        checks["owned_registry_empty"] = not self._created_objects
        checks["address_registry_empty"] = (
            not self._created_router_addrs and not self._created_peer_addrs
        )
        checks["hosts_registry_empty"] = not self._created_host_entries
        checks["firewall_registry_empty"] = not self._created_firewall_rules
        for target, marker in self._known_host_markers:
            ssh = self._router() if target == "router" else self._peer()
            checks[f"{target}_hosts_{marker}_absent"] = not bool(ssh.exec(
                f"grep -F -- {self._shell_quote('# ' + marker)} /etc/hosts",
                timeout=10,
            ).strip())
        for target, tool, marker in self._known_firewall_markers:
            ssh = self._router() if target == "router" else self._peer()
            checks[f"{target}_{tool}_{marker}_absent"] = (
                self._firewall_marker_count(ssh, tool, marker) == 0
            )
        if snapshot is not None:
            for target, ssh in (("router", self._router()), ("peer", self._peer())):
                baseline = bool(
                    snapshot.public.get(target, {}).get("udp_500_4500", False)
                )
                current = bool(ssh.exec(
                    "pidof charon 2>/dev/null", timeout=10
                ).strip())
                checks[f"{target}_daemon_restored"] = current == baseline
        health = self.management_health()
        checks["management_healthy"] = health.passed
        passed = all(checks.values())
        return VerifyResult(
            "清理-IPsec精确残留审计", passed,
            ("本次IPsec对象、路由、地址、守护进程和管理通道均已恢复"
             if passed else "IPsec精确残留审计发现异常"),
            details={"checks": checks, "management": health.details},
        )

    def verify_restored(self, snapshot: IpsecEnvironmentSnapshot) -> VerifyResult:
        current_snapshot = self.snapshot_environment()
        current = current_snapshot.public
        mismatches: Dict[str, Any] = {}
        device_labels = {
            "router": "主路由器",
            "peer": "对端设备",
            "client": "测试客户端",
        }
        state_labels = {
            "route_hash": ("路由表", "route_lines"),
            "route6_hash": ("IPv6路由表", "route6_lines"),
            "rule_hash": ("策略路由规则", "rule_lines"),
            "address_hash": ("IPv4地址", "address_lines"),
            "address6_hash": ("IPv6地址", "address6_lines"),
            "hosts_hash": ("hosts映射", "hosts_lines"),
        }

        def stable_lines(lines: Iterable[str]) -> List[str]:
            # GRE interfaces and DHCP/IPv6 lease expiry are maintained by
            # independent services while a long IPsec run is in progress.
            # They are not owned by this test and must not turn cleanup into a
            # false environment failure; exact IPsec artifacts are audited
            # separately below.
            return sorted({
                str(line) for line in lines
                if not re.search(r"gre[_A-Za-z0-9]*", str(line))
                and "expires" not in str(line)
                and "wan3" not in str(line)
                and "fwmark 0x10eff" not in str(line)
            })

        for device in ("router", "peer"):
            before = snapshot.public.get(device, {})
            after = current.get(device, {})
            for key, (state_label, line_key) in state_labels.items():
                before_lines = stable_lines(
                    snapshot.private.get(device, {}).get(line_key, [])
                )
                after_lines = stable_lines(
                    current_snapshot.private.get(device, {}).get(line_key, [])
                )
                before_fingerprint = self._fingerprint("\n".join(before_lines))
                after_fingerprint = self._fingerprint("\n".join(after_lines))
                if before_fingerprint != after_fingerprint:
                    if before_lines or after_lines:
                        evidence = self._state_delta(before_lines, after_lines)
                    else:
                        evidence = {
                            "测试前校验值": before.get(key),
                            "测试后校验值": after.get(key),
                            "说明": "旧版快照未保留逐行证据",
                        }
                    mismatches[
                        f"{device_labels[device]}{state_label}"
                    ] = evidence
        for key in (
            "router_policy_count", "router_proposal_count",
            "peer_policy_count", "peer_proposal_count",
        ):
            if snapshot.public.get(key) != current.get(key):
                mismatches[key] = {
                    "before": snapshot.public.get(key), "after": current.get(key)
                }
        health = self.management_health()
        passed = not mismatches and health.passed
        return VerifyResult(
            "清理-IPsec独立残留审计", passed,
            ("双端IPv4/IPv6地址、路由、hosts、IPsec计数与管理通道恢复到测试前"
             if passed else "测试期间双端全局环境发生变化，具体差异见新增/减少条目"),
            details={"mismatches": mismatches, "management": health.details},
        )
