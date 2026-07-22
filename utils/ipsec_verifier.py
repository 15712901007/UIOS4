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
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,46}$")
_SAFE_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_NET_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")


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

    @property
    def client_selector(self) -> str:
        return f"{self.client_source}/32"

    @property
    def peer_selector(self) -> str:
        return f"{self.peer_service}/32"


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
        self._created_peer_addrs: set[str] = set()
        self._created_client_routes: set[str] = set()
        self._created_router_routes: set[str] = set()

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
            ("client", self._client),
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
            message=("主路由、客户端、对端及三条恢复通道均可达"
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

    def initiate_child_from_peer(self, peer_policy_id: int) -> VerifyResult:
        """Initiate the test CHILD SA from the internal peer endpoint."""
        peer_policy_id = int(peer_policy_id)
        child = f"ipsec2-spoke-{peer_policy_id}-esp"
        output = self._peer().exec(
            f"swanctl --initiate --child {child} --timeout 20 2>&1",
            timeout=30,
        )
        passed = (
            "initiate completed successfully" in output
            and "CHILD_SA" in output
            and "established" in output
        )
        reason = ""
        for marker in (
            "AUTHENTICATION_FAILED", "NO_PROPOSAL_CHOSEN",
            "TS_UNACCEPTABLE", "CHILD_SA_NOT_FOUND",
        ):
            if marker in output:
                reason = marker
                break
        return VerifyResult(
            "L3-IPsec对端发起Child SA", passed,
            ("对端发起IKE/Child SA成功" if passed
             else "对端发起IKE/Child SA失败"),
            details={
                "initiator": "peer",
                "ike_established": "IKE_SA" in output and "established" in output,
                "child_established": "CHILD_SA" in output and "established" in output,
                "failure_class": reason or ("none" if passed else "unknown"),
                "output_class": "empty" if not output.strip() else "nonempty",
                "last_events": self.sanitize_text(output).strip().splitlines()[-10:],
            },
        )

    def initiate_child_from_router(self, router_policy_id: int) -> VerifyResult:
        router_policy_id = int(router_policy_id)
        child = f"ipsec2-spoke-{router_policy_id}-esp"
        output = self._router().exec(
            f"swanctl --initiate --child {child} --timeout 20 2>&1",
            timeout=30,
        )
        passed = (
            "initiate completed successfully" in output
            and "CHILD_SA" in output
            and "established" in output
        )
        reason = ""
        for marker in (
            "AUTHENTICATION_FAILED", "NO_PROPOSAL_CHOSEN",
            "TS_UNACCEPTABLE", "CHILD_SA_NOT_FOUND",
        ):
            if marker in output:
                reason = marker
                break
        return VerifyResult(
            "L3-IPsec主路由发起Child SA", passed,
            ("主路由发起IKE/Child SA成功" if passed
             else "主路由发起IKE/Child SA失败"),
            details={
                "initiator": "router",
                "failure_class": reason or "unknown",
                "output_class": "empty" if not output.strip() else "nonempty",
                "last_events": self.sanitize_text(output).strip().splitlines()[-10:],
            },
        )

    def terminate_test_sas(
        self, router_policy_id: int, peer_policy_id: int
    ) -> VerifyResult:
        errors: List[str] = []
        for target, ssh, policy_id in (
            ("router", self._router(), int(router_policy_id)),
            ("peer", self._peer(), int(peer_policy_id)),
        ):
            name = f"ipsec2-spoke-{policy_id}"
            for _ in range(3):
                listing = self._sa_text(ssh)
                unique_ids = re.findall(
                    rf"(?m)^{re.escape(name)}:\s+#(\d+),", listing
                )
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
                        errors.append(f"{target}-{unique_id}")
                time.sleep(0.2)
        absent = self.wait_for_sa_absent(
            int(router_policy_id), int(peer_policy_id), timeout=12
        )
        return VerifyResult(
            "L4-IPsec精确撤销SA", not errors and absent.passed,
            ("本次双端IKE/Child SA已撤销" if not errors and absent.passed
             else "本次双端SA未完全撤销"),
            details={"terminate_errors": errors, "absence": absent.details},
        )

    def wait_for_sa_absent(
        self, router_policy_id: int, peer_policy_id: int, timeout: int = 20
    ) -> VerifyResult:
        deadline = time.monotonic() + timeout
        names = {
            "router": f"ipsec2-spoke-{int(router_policy_id)}",
            "peer": f"ipsec2-spoke-{int(peer_policy_id)}",
        }
        last = {"router_present": True, "peer_present": True}
        while time.monotonic() < deadline:
            last = {
                "router_present": names["router"] in self._sa_text(self._router()),
                "peer_present": names["peer"] in self._sa_text(self._peer()),
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

    def rekey_child_from_peer(self, peer_policy_id: int) -> VerifyResult:
        child = f"ipsec2-spoke-{int(peer_policy_id)}-esp"
        output = self._peer().exec(
            f"swanctl --rekey --child {child} 2>&1", timeout=30,
        )
        passed = "rekey completed successfully" in output.lower()
        return VerifyResult(
            "L4-IPsec Child SA重协商", passed,
            ("Child SA rekey完成" if passed else "Child SA rekey失败"),
            details={
                "output_class": "empty" if not output.strip() else "nonempty",
                "last_events": self.sanitize_text(output).strip().splitlines()[-10:],
            },
        )

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
        rules = ssh.exec("ip rule show 2>/dev/null", timeout=15)
        addrs = ssh.exec(
            "ip -o -4 addr show 2>/dev/null | awk '{print $2,$3,$4}'",
            timeout=15,
        )
        xfrm_state = ssh.exec("ip -s xfrm state 2>/dev/null", timeout=15)
        xfrm_policy = ssh.exec("ip -s xfrm policy 2>/dev/null", timeout=15)
        metadata = ssh.exec(
            "for f in /etc/swanctl/conf.d/ipsec2-* /etc/swanctl/secrets.d/ipsec2-* "
            "/tmp/iktmp/cache/ipsec2/* /var/run/ipsec2/resolved/ipsec2-*; do "
            "test -f $f && stat -c '%a %s %n' $f; done",
            timeout=20,
        )
        route_lines = self._snapshot_lines(route)
        rule_lines = self._snapshot_lines(rules)
        address_lines = self._snapshot_lines(addrs)
        public = {
            "route_hash": self._fingerprint("\n".join(route_lines)),
            "rule_hash": self._fingerprint("\n".join(rule_lines)),
            "address_hash": self._fingerprint("\n".join(address_lines)),
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
            "rule_lines": rule_lines,
            "address_lines": address_lines,
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
        client_public, client_private = self._snapshot_device(
            self._client(), include_private=False
        )
        public = {
            "router": router_public,
            "peer": peer_public,
            "client": client_public,
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
                "client": client_private,
            },
        )

    def choose_topology(self) -> IpsecTopology:
        token = secrets.token_hex(3)
        occupied_text = "\n".join([
            self._router().exec("ip -o -4 addr show; ip -4 route show table all; ip xfrm policy", timeout=25),
            self._peer().exec("ip -o -4 addr show; ip -4 route show table all; ip xfrm policy", timeout=25),
            self._client().exec("ip -o -4 addr show; ip -4 route show table all", timeout=25),
            json.dumps(self.query_policies("router"), ensure_ascii=True),
            json.dumps(self.query_policies("peer"), ensure_ascii=True),
        ])
        occupied: List[ipaddress._BaseNetwork] = []
        for item in re.findall(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", occupied_text):
            try:
                network = ipaddress.ip_network(
                    item if "/" in item else item + "/32", strict=False
                )
                # Charon installs socket bypass policies for 0/0.  They are not
                # business selectors and must not make every candidate overlap.
                if network.prefixlen == 0:
                    continue
                occupied.append(network)
            except ValueError:
                continue
        peer_service = ""
        seed = int(token, 16)
        benchmark = ipaddress.ip_network("198.18.0.0/15")
        for offset in range(32, 65000):
            candidate = benchmark.network_address + ((seed + offset) % 130000 + 1)
            network = ipaddress.ip_network(f"{candidate}/32")
            if all(not network.overlaps(existing) for existing in occupied):
                peer_service = str(candidate)
                break
        if not peer_service:
            raise RuntimeError("未找到无冲突的IPsec远端测试地址")
        return IpsecTopology(
            token=token,
            router_policy=f"ipsec_t_r_{token}",
            peer_policy=f"ipsec_t_p_{token}",
            router_proposal=f"ike_t_r_{token}",
            peer_proposal=f"ike_t_p_{token}",
            client_source="10.99.99.1",
            peer_service=peer_service,
            client_iface="ens11",
            client_gateway="192.168.148.1",
            router_underlay=str(self.backend._ssh_config.router.host),
            peer_underlay=str(self.backend._ssh_config.peer.host),
            router_interface="wan1",
            peer_interface="wan1",
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
        return int(row["id"])

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
        src = topology.client_selector if is_router else topology.peer_selector
        dst = topology.peer_selector if is_router else topology.client_selector
        traffic = base64.b64encode(json.dumps([{
            "src": src,
            "dst": dst,
            "protocol": "icmp",
            "action": "permit",
            "src_port": "",
            "dst_port": "",
        }], separators=(",", ":")).encode()).decode()
        params: Dict[str, Any] = {
            "tagname": tagname,
            "alias": f"ipsec-test-{topology.token}",
            "comment": "automation",
            "enabled": "yes",
            "addr_type": "v4",
            "role": "spoke",
            "interface": topology.router_interface if is_router else topology.peer_interface,
            "local_ip": local_underlay,
            "remote_addr": remote_underlay,
            "ike_version": "ikev2",
            "aggressive": "0",
            "ike_proposals": proposal_id,
            "prf": "sha256",
            "auth_method": "psk",
            "secret": secret,
            "local_id_type": "IPV4",
            "local_id": local_underlay,
            "remote_id_type": "IPV4",
            "remote_id": remote_underlay,
            "encap_mode": "tunnel",
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
        return int(row["id"])

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
        for value in (
            topology.peer_service, topology.client_source, topology.client_gateway,
            topology.client_iface,
        ):
            if not _SAFE_NET_TOKEN_RE.fullmatch(value):
                return VerifyResult("环境-IPsec数据面", False, "IPsec拓扑参数不安全")
        peer = self._peer()
        client = self._client()
        peer_exists = peer.exec(
            f"ip -o -4 addr show dev lo | grep -w '{topology.peer_service}/32'",
            timeout=10,
        ).strip()
        if peer_exists:
            return VerifyResult("环境-IPsec数据面", False, "远端测试地址已被占用")
        route_exists = client.exec(
            f"ip -4 route show exact {topology.peer_selector}", timeout=10
        ).strip()
        if route_exists:
            return VerifyResult("环境-IPsec数据面", False, "客户端测试路由已存在")
        router_route_exists = self._router().exec(
            f"ip -4 route show exact {topology.client_selector}", timeout=10
        ).strip()
        if router_route_exists:
            return VerifyResult("环境-IPsec数据面", False, "主路由客户端返回路由已存在")
        peer.exec(
            f"ip addr add {topology.peer_selector} dev lo", timeout=15
        )
        self._created_peer_addrs.add(topology.peer_selector)
        client.exec(
            f"sudo -n ip route add {topology.peer_selector} via {topology.client_gateway} "
            f"dev {topology.client_iface} src {topology.client_source}",
            timeout=15,
        )
        self._created_client_routes.add(topology.peer_selector)
        self._router().exec(
            f"ip route add {topology.client_selector} via 192.168.148.2 dev lan1",
            timeout=15,
        )
        self._created_router_routes.add(topology.client_selector)
        peer_ok = bool(peer.exec(
            f"ip -o -4 addr show dev lo | grep -w '{topology.peer_service}/32'",
            timeout=10,
        ).strip())
        route = client.exec(
            f"ip route get {topology.peer_service} from {topology.client_source}",
            timeout=10,
        )
        route_ok = topology.client_iface in route and topology.client_gateway in route
        router_return = self._router().exec(
            f"ip route get {topology.client_source}",
            timeout=10,
        )
        router_return_ok = "lan1" in router_return and "192.168.148.2" in router_return
        return VerifyResult(
            level="环境-IPsec数据面",
            passed=peer_ok and route_ok and router_return_ok,
            message=("独立远端/32与客户端经LAN1精确路由已建立"
                     if peer_ok and route_ok and router_return_ok
                     else "IPsec隔离数据面准备失败"),
            details={
                "peer_prefix_created": peer_ok,
                "client_route_via_lan": route_ok,
                "router_return_route_via_lan": router_return_ok,
                "client_iface": topology.client_iface,
            },
        )

    def verify_control_failure(self, topology: IpsecTopology) -> VerifyResult:
        output = self._client().exec(
            f"ping -I {topology.client_source} -c 2 -W 1 {topology.peer_service} 2>&1",
            timeout=10,
        )
        failed = not re.search(r"\b[1-9][0-9]* packets received\b|\b[1-9][0-9]* received\b", output)
        return VerifyResult(
            level="L5-IPsec建连前控制组",
            passed=failed,
            message=("建隧道前独立业务前缀不可达，未发现管理网替代路径"
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
            topology.client_source in policy and topology.peer_service in policy
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
        if reverse:
            output = self._peer().exec(
                f"ping -I {topology.peer_service} -c 4 -W 2 {topology.client_source} 2>&1",
                timeout=18,
            )
        else:
            output = self._client().exec(
                f"ping -I {topology.client_source} -c 4 -W 2 {topology.peer_service} 2>&1",
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
            message=("client→router→peer与peer→router→client双向流量通过，XFRM计数增长"
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
        names: List[Tuple[str, str, str]] = []
        if topology:
            names = [
                ("router", "policy", topology.router_policy),
                ("peer", "policy", topology.peer_policy),
                ("router", "proposal", topology.router_proposal),
                ("peer", "proposal", topology.peer_proposal),
            ]
        for target, kind, name in names:
            try:
                row = self.find_policy(name, target) if kind == "policy" else self.find_proposal(name, target)
                if not row:
                    continue
                ssh = self._router() if target == "router" else self._peer()
                script = self.POLICY_SCRIPT if kind == "policy" else self.PROPOSAL_SCRIPT
                self._secure_script_call(
                    ssh, script, "del", {"id": int(row["id"])}, target
                )
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
        # A resumed process may not have the in-memory creation sets.  Delete only
        # the exact topology objects after verifying their expected owner/path.
        if topology:
            try:
                route = self._client().exec(
                    f"ip -4 route show exact {topology.peer_selector}", timeout=10
                )
                if route.strip():
                    if topology.client_iface in route and topology.client_gateway in route:
                        self._client().exec(
                            f"sudo -n ip route del {topology.peer_selector}", timeout=15
                        )
                    else:
                        errors.append("client-route-owner-mismatch")
            except Exception as exc:
                errors.append(f"client-route-audit-{type(exc).__name__}")
            try:
                route = self._router().exec(
                    f"ip -4 route show exact {topology.client_selector}", timeout=10
                )
                if route.strip():
                    if "lan1" in route and "192.168.148.2" in route:
                        self._router().exec(
                            f"ip route del {topology.client_selector}", timeout=15
                        )
                    else:
                        errors.append("router-route-owner-mismatch")
            except Exception as exc:
                errors.append(f"router-route-audit-{type(exc).__name__}")
            try:
                address = self._peer().exec(
                    f"ip -o -4 addr show dev lo | grep -w '{topology.peer_selector}'",
                    timeout=10,
                )
                if address.strip():
                    self._peer().exec(
                        f"ip addr del {topology.peer_selector} dev lo", timeout=15
                    )
            except Exception as exc:
                errors.append(f"peer-addr-audit-{type(exc).__name__}")
        residual: List[str] = []
        if topology:
            for target, kind, name in names:
                row = self.find_policy(name, target) if kind == "policy" else self.find_proposal(name, target)
                if row:
                    residual.append(f"{target}-{kind}")
        passed = not errors and not residual
        return VerifyResult(
            "清理-IPsec精确恢复", passed,
            ("本次策略、提议、客户端路由和对端临时地址已精确清理"
             if passed else "IPsec精确清理存在异常或残留"),
            details={"errors": errors, "residual": residual},
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
        self, topology: IpsecTopology,
        snapshot: Optional[IpsecEnvironmentSnapshot] = None,
    ) -> VerifyResult:
        checks = {
            "router_policy_absent": self.find_policy(
                topology.router_policy, "router"
            ) is None,
            "peer_policy_absent": self.find_policy(
                topology.peer_policy, "peer"
            ) is None,
            "router_proposal_absent": self.find_proposal(
                topology.router_proposal, "router"
            ) is None,
            "peer_proposal_absent": self.find_proposal(
                topology.peer_proposal, "peer"
            ) is None,
            "client_route_absent": not bool(self._client().exec(
                f"ip -4 route show exact {topology.peer_selector}", timeout=10
            ).strip()),
            "peer_address_absent": not bool(self._peer().exec(
                f"ip -o -4 addr show dev lo | grep -w '{topology.peer_selector}'",
                timeout=10,
            ).strip()),
            "router_route_absent": not bool(self._router().exec(
                f"ip -4 route show exact {topology.client_selector}", timeout=10
            ).strip()),
        }
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
            "rule_hash": ("策略路由规则", "rule_lines"),
            "address_hash": ("IPv4地址", "address_lines"),
        }
        for device in ("router", "peer", "client"):
            before = snapshot.public.get(device, {})
            after = current.get(device, {})
            for key, (state_label, line_key) in state_labels.items():
                if before.get(key) != after.get(key):
                    before_lines = (
                        snapshot.private.get(device, {}).get(line_key, [])
                    )
                    after_lines = (
                        current_snapshot.private.get(device, {}).get(line_key, [])
                    )
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
            ("三端地址/路由/rule、IPsec计数与管理通道恢复到测试前"
             if passed else "测试期间三端全局环境发生变化，具体差异见新增/减少条目"),
            details={"mismatches": mismatches, "management": health.details},
        )
