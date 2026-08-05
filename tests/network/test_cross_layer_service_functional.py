"""Cross-layer service real SNMP MAC-learning functional test.

The DUT polls ``IP-MIB::ipNetToMediaTable`` from a layer-3 device, filters
the returned rows by the configured IP scope, and feeds the learned IP/MAC
mapping into the cross-layer IP-auth cache.

Default topology::

    Ubuntu SNMP peer 10.66.0.57
        temporary IP-MIB row: 192.168.148.2 -> client ens11 MAC
                         |
                   DUT 10.66.0.45
                         |
        client host 10.66.0.18 / ens11 192.168.148.2

The Ubuntu peer uses a temporary veth and a dedicated high-port Net-SNMP
instance.  The test never changes the system SNMP service and removes the
temporary process, interface, files, and DUT rule in ``finally``.

Optional environment overrides:
    CROSS_LAYER_PEER_HOST / CROSS_LAYER_PEER_USERNAME
    CROSS_LAYER_PEER_PASSWORD / CROSS_LAYER_PEER_PORT
    CROSS_LAYER_PEER_IFACE / CROSS_LAYER_SNMP_PORT
    CROSS_LAYER_SNMP_ALLOWED_SOURCE / CROSS_LAYER_CLIENT_IFACE
    CROSS_LAYER_CLIENT_IP / CROSS_LAYER_ROUTER_LAN_IP
"""

import base64
import ipaddress
import json
import os
import re
import secrets
import shlex
import time
from typing import Callable, Dict, Optional, Tuple

import pytest

from config.config import Config, SSHHostConfig
from pages.network.cross_layer_service_page import CrossLayerServicePage
from utils.backend_verifier import BackendVerifier, SSHClient
from utils.step_recorder import StepRecorder


DUT_MANAGEMENT_IP = "10.66.0.45"
DEFAULT_CLIENT_HOST = "10.66.0.18"
DEFAULT_CLIENT_IFACE = "ens11"
DEFAULT_CLIENT_IP = "192.168.148.2"
DEFAULT_ROUTER_LAN_IP = "192.168.148.1"
DEFAULT_PEER_HOST = "10.66.0.57"
DEFAULT_PEER_IFACE = "enp6s0"
DEFAULT_ALLOWED_SOURCE = "10.66.0.0/24"
ARP_TABLE_OID = ".1.3.6.1.2.1.4.22.1"
TEST_OID = ".1.3.6.1.2.1.1.1.0"


class FunctionalAbort(RuntimeError):
    """Stop dependent stages while preserving environment restoration."""


def _exec_with_rc(
    ssh: SSHClient, command: str, timeout: int = 20
) -> Tuple[int, str]:
    """Execute a remote command and retain its shell return code."""
    marker = "__CROSS_LAYER_RC__="
    wrapped = (
        f"{command}\n"
        "__cross_layer_rc=$?\n"
        f"printf '\\n{marker}%s\\n' \"$__cross_layer_rc\""
    )
    output = ssh.exec(wrapped, timeout=timeout, probe_console=False) or ""
    matches = re.findall(rf"{re.escape(marker)}(\d+)", output)
    if not matches:
        return 255, output.strip()
    clean_output = re.sub(
        rf"\n?{re.escape(marker)}\d+\s*$", "", output
    ).strip()
    return int(matches[-1]), clean_output


def _wait_for(
    probe: Callable[[], Tuple[bool, str]],
    timeout: float = 15.0,
    interval: float = 1.0,
) -> Tuple[bool, str]:
    """Poll a condition and retain the last diagnostic detail."""
    deadline = time.monotonic() + timeout
    last_detail = ""
    while time.monotonic() < deadline:
        passed, last_detail = probe()
        if passed:
            return True, last_detail
        time.sleep(interval)
    return False, last_detail


def _upload_text(
    ssh: SSHClient, remote_path: str, content: str, timeout: int = 15
) -> Tuple[int, str]:
    """Upload a small UTF-8 text file through the existing SSH shell."""
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    parent = remote_path.rsplit("/", 1)[0]
    command = (
        f"mkdir -p {shlex.quote(parent)} && "
        f"printf %s {shlex.quote(encoded)} | base64 -d > "
        f"{shlex.quote(remote_path)}"
    )
    return _exec_with_rc(ssh, command, timeout=timeout)


def _normalize_mac(value: str) -> str:
    """Normalize Net-SNMP and Linux MAC renderings to lower-case pairs."""
    candidate = value.strip().lower().replace("-", ":")
    if ":" in candidate:
        parts = candidate.split(":")
    else:
        compact = re.sub(r"[^0-9a-f]", "", candidate)
        parts = [compact[index:index + 2] for index in range(0, len(compact), 2)]
    if len(parts) != 6 or any(not re.fullmatch(r"[0-9a-f]{1,2}", part) for part in parts):
        return ""
    return ":".join(part.zfill(2) for part in parts)


def _snmp_mac_for_ip(output: str, target_ip: str) -> str:
    """Extract an ipNetToMediaPhysAddress row from numeric snmpwalk output."""
    target_suffix = f".{target_ip} ="
    phys_address_oid = ".1.3.6.1.2.1.4.22.1.2."
    for line in output.splitlines():
        if phys_address_oid not in line or target_suffix not in line:
            continue
        value = line.split("=", 1)[-1]
        value = re.sub(r"^(?:STRING|Hex-STRING):\s*", "", value.strip())
        return _normalize_mac(value)
    return ""


def _capture_summary(output: str, peer_host: str, snmp_port: int) -> str:
    """Keep SNMP packet lines and counters compact for the report."""
    useful = []
    endpoint = f"{peer_host}.{snmp_port}"
    for line in output.splitlines():
        lowered = line.lower()
        if endpoint in line or "packets captured" in lowered:
            useful.append(line)
    return "\n".join(useful[-80:])[-6000:] if useful else output[-2500:]


@pytest.mark.cross_layer_service
@pytest.mark.network
@pytest.mark.p0
class TestCrossLayerServiceFunctional:
    """Validate real SNMP polling, IP filtering, cache learning, and lifecycle."""

    def test_cross_layer_service_real_snmp_mac_learning(
        self,
        cross_layer_page_logged_in: CrossLayerServicePage,
        step_recorder: StepRecorder,
        backend_verifier: Optional[BackendVerifier],
        config: Config,
    ):
        page = cross_layer_page_logged_in
        rec = step_recorder
        failures = []
        cleanup_failures = []
        suffix = secrets.token_hex(4)
        rule_name = f"clf_{suffix}"
        community = f"cl_{suffix}"

        client_iface = os.getenv(
            "CROSS_LAYER_CLIENT_IFACE", DEFAULT_CLIENT_IFACE
        ).strip()
        client_ip = os.getenv(
            "CROSS_LAYER_CLIENT_IP", DEFAULT_CLIENT_IP
        ).strip()
        router_lan_ip = os.getenv(
            "CROSS_LAYER_ROUTER_LAN_IP", DEFAULT_ROUTER_LAN_IP
        ).strip()
        peer_host = os.getenv(
            "CROSS_LAYER_PEER_HOST",
            config.ssh.kernel_peer_host or DEFAULT_PEER_HOST,
        ).strip()
        peer_username = os.getenv(
            "CROSS_LAYER_PEER_USERNAME", config.ssh.client.username
        )
        peer_password = os.getenv(
            "CROSS_LAYER_PEER_PASSWORD", config.ssh.client.password
        )
        peer_ssh_port = int(
            os.getenv(
                "CROSS_LAYER_PEER_PORT",
                str(config.ssh.kernel_peer_port or config.ssh.client.port),
            )
        )
        peer_iface = os.getenv(
            "CROSS_LAYER_PEER_IFACE", DEFAULT_PEER_IFACE
        ).strip()
        allowed_source = os.getenv(
            "CROSS_LAYER_SNMP_ALLOWED_SOURCE", DEFAULT_ALLOWED_SOURCE
        ).strip()
        requested_snmp_port = os.getenv(
            "CROSS_LAYER_SNMP_PORT", ""
        ).strip()

        remote_dir = f"/tmp/ikuai-cross-layer-{suffix}"
        snmp_conf = f"{remote_dir}/snmpd.conf"
        snmp_pid = f"{remote_dir}/snmpd.pid"
        snmp_log = f"{remote_dir}/snmpd.log"
        capture_pid = f"{remote_dir}/tcpdump.pid"
        capture_pcap = f"{remote_dir}/snmp.pcap"
        capture_log = f"{remote_dir}/tcpdump.log"
        veth_a = f"clsa{suffix[:6]}"
        veth_b = f"clsb{suffix[:6]}"

        client: Optional[SSHClient] = None
        peer: Optional[SSHClient] = None
        snmp_port: Optional[int] = None
        client_mac = ""
        capture_started = False
        original_interval: Optional[int] = None
        interval_changed = False

        def record(label: str, passed: bool, detail: str = "") -> bool:
            status = "[OK]" if passed else "[FAIL]"
            message = f"{label}: {status}"
            if detail:
                message += f" {detail}"
            print(f"  {message}")
            rec.add_detail(f"  {message}")
            if not passed:
                failures.append(f"{label}: {detail or '不符合预期'}")
            return passed

        def require(label: str, passed: bool, detail: str = ""):
            if not record(label, passed, detail):
                raise FunctionalAbort(f"{label}: {detail or '不符合预期'}")

        def observe(label: str, level: str, detail: str = ""):
            message = f"{label}: [{level}]"
            if detail:
                message += f" {detail}"
            print(f"  {message}")
            rec.add_detail(f"  {message}")

        def client_exec(command: str, timeout: int = 20) -> Tuple[int, str]:
            assert client is not None
            return _exec_with_rc(client, command, timeout)

        def peer_exec(command: str, timeout: int = 20) -> Tuple[int, str]:
            assert peer is not None
            return _exec_with_rc(peer, command, timeout)

        def router_exec(command: str, timeout: int = 20) -> str:
            assert backend_verifier is not None
            backend_verifier.connect_router()
            return backend_verifier._router.exec(
                command, timeout=timeout, probe_console=False
            ) or ""

        def find_test_rule() -> Optional[Dict]:
            if backend_verifier is None:
                return None
            rules = backend_verifier.query_netsnmpc_rules() or []
            exact = [item for item in rules if item.get("tagname") == rule_name]
            if len(exact) == 1:
                return exact[0]
            if snmp_port is None:
                return None
            by_endpoint = [
                item
                for item in rules
                if item.get("server_ip") == peer_host
                and int(item.get("listen_port", -1)) == snmp_port
                and str(item.get("tagname", "")).startswith("clf_")
            ]
            return by_endpoint[0] if len(by_endpoint) == 1 else None

        def actual_rule_name() -> str:
            current = find_test_rule()
            return str(current.get("tagname")) if current else rule_name

        def active_state_probe() -> Tuple[bool, str]:
            current = find_test_rule()
            if current is None:
                return False, "后台尚未找到本轮规则"
            rule_id = int(current["id"])
            output = router_exec(
                f"printf 'status='; cat /tmp/iktmp/cache/snmp_ipauth/status_{rule_id} "
                "2>/dev/null; echo; "
                f"printf 'config='; test -f /tmp/iktmp/cache/snmp_ipauth/config_{rule_id} "
                "&& echo yes || echo no; "
                f"echo 'arp_begin'; cat /tmp/iktmp/cache/snmp_ipauth/arp_{rule_id} "
                "2>/dev/null; echo 'arp_end'; "
                "ps w | grep '[i]k_switch_arp'",
                timeout=15,
            )
            arp_match = re.search(
                r"arp_begin\s*(.*?)\s*arp_end", output, re.DOTALL
            )
            arp_lines = [
                line.strip().lower()
                for line in (arp_match.group(1) if arp_match else "").splitlines()
                if line.strip()
            ]
            expected_mapping = f"{client_mac} {client_ip}"
            passed = (
                current.get("enabled") == "yes"
                and current.get("server_ip") == peer_host
                and int(current.get("listen_port", -1)) == snmp_port
                and int(current.get("version", -1)) == 2
                and "status=1" in output
                and "config=yes" in output
                and arp_lines == [expected_mapping]
                and "ik_switch_arp" in output
            )
            detail = (
                f"id={rule_id}, enabled={current.get('enabled')}, "
                f"status={'1' if 'status=1' in output else '非1'}, "
                f"ARP={arp_lines or '空'}, 期望={expected_mapping}"
            )
            return passed, detail

        def disabled_state_probe() -> Tuple[bool, str]:
            current = find_test_rule()
            if current is None:
                return False, "停用后规则意外消失"
            rule_id = int(current["id"])
            output = router_exec(
                f"for name in config status arp; do "
                f"test -e /tmp/iktmp/cache/snmp_ipauth/${{name}}_{rule_id} "
                "&& echo ${name}=present || echo ${name}=absent; done",
                timeout=10,
            )
            passed = (
                current.get("enabled") == "no"
                and "config=absent" in output
                and "status=absent" in output
                and "arp=absent" in output
            )
            return passed, (
                f"id={rule_id}, enabled={current.get('enabled')}; {output}"
            )

        def start_capture():
            nonlocal capture_started
            assert snmp_port is not None
            inner = (
                f"nohup tcpdump -U -nn -i {shlex.quote(peer_iface)} -s 0 "
                f"-c 300 -w {shlex.quote(capture_pcap)} "
                f"'udp port {snmp_port}' > {shlex.quote(capture_log)} "
                f"2>&1 < /dev/null & echo $! > {shlex.quote(capture_pid)}"
            )
            rc, output = peer_exec(
                f"sudo -n sh -c {shlex.quote(inner)}; sleep 1; "
                f"sudo -n kill -0 $(cat {shlex.quote(capture_pid)}) 2>/dev/null",
                timeout=12,
            )
            require("SNMP抓包启动", rc == 0, output)
            capture_started = True

        def stop_capture() -> str:
            nonlocal capture_started
            if peer is None or not capture_started:
                return ""
            _, output = peer_exec(
                f"test ! -f {shlex.quote(capture_pid)} || "
                f"sudo -n kill -INT $(cat {shlex.quote(capture_pid)}) "
                "2>/dev/null || true; sleep 1; "
                f"sudo -n tcpdump -nn -r {shlex.quote(capture_pcap)} "
                "2>&1 || true",
                timeout=15,
            )
            capture_started = False
            return output

        try:
            if backend_verifier is None:
                raise FunctionalAbort("SSH后台验证器不可用，无法执行真实功能测试")
            for env_name, value in (
                ("CROSS_LAYER_CLIENT_IP", client_ip),
                ("CROSS_LAYER_ROUTER_LAN_IP", router_lan_ip),
                ("CROSS_LAYER_PEER_HOST", peer_host),
            ):
                if ipaddress.ip_address(value).version != 4:
                    raise FunctionalAbort(f"{env_name}必须是IPv4地址: {value}")
            if ipaddress.ip_network(allowed_source, strict=False).version != 4:
                raise FunctionalAbort(
                    "CROSS_LAYER_SNMP_ALLOWED_SOURCE必须是IPv4网段"
                )
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", client_iface):
                raise FunctionalAbort(f"客户端接口名无效: {client_iface}")
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", peer_iface):
                raise FunctionalAbort(f"SNMP对端接口名无效: {peer_iface}")

            client = SSHClient(config.ssh.client)
            client.connect()
            peer = SSHClient(
                SSHHostConfig(
                    host=peer_host,
                    username=peer_username,
                    password=peer_password,
                    port=peer_ssh_port,
                )
            )
            peer.connect()
            backend_verifier.connect_router()

            with rec.step(
                "测试环境校验",
                "确认DUT、LAN客户端、Ubuntu SNMP对端和真实客户端MAC",
            ):
                require(
                    "UI与SSH目标一致",
                    config.device.ip == DUT_MANAGEMENT_IP
                    and config.ssh.router.host == DUT_MANAGEMENT_IP,
                    f"UI={config.device.ip}, SSH={config.ssh.router.host}",
                )
                require(
                    "LAN客户端SSH目标",
                    config.ssh.client.host == DEFAULT_CLIENT_HOST,
                    f"实际={config.ssh.client.host}, 期望={DEFAULT_CLIENT_HOST}",
                )
                require(
                    "SNMP对端独立于DUT和LAN客户端",
                    peer_host not in {DUT_MANAGEMENT_IP, config.ssh.client.host},
                    peer_host,
                )
                rc, client_state = client_exec(
                    f"ip -4 -o addr show dev {shlex.quote(client_iface)}; "
                    f"ip -o link show dev {shlex.quote(client_iface)}; "
                    f"ping -I {shlex.quote(client_ip)} -c 1 -W 2 "
                    f"{shlex.quote(router_lan_ip)}",
                    timeout=12,
                )
                mac_match = re.search(
                    r"link/ether\s+([0-9a-fA-F:]{17})", client_state
                )
                client_mac = _normalize_mac(
                    mac_match.group(1) if mac_match else ""
                )
                require(
                    "客户端真实IP/MAC与LAN链路",
                    rc == 0
                    and bool(
                        re.search(
                            rf"\binet\s+{re.escape(client_ip)}/\d+\b",
                            client_state,
                        )
                    )
                    and bool(client_mac),
                    f"IP={client_ip}, MAC={client_mac or '未获取'}",
                )
                rc, peer_state = peer_exec(
                    f"ip -4 -o addr show dev {shlex.quote(peer_iface)}; "
                    "command -v snmpd; command -v snmpwalk; "
                    "command -v tcpdump; command -v base64; "
                    "sudo -n true; echo SUDO=$?",
                    timeout=12,
                )
                require(
                    "Ubuntu SNMP对端地址、工具和sudo",
                    rc == 0
                    and peer_host in peer_state
                    and all(
                        tool in peer_state
                        for tool in ("snmpd", "snmpwalk", "tcpdump", "base64")
                    )
                    and "SUDO=0" in peer_state,
                    peer_state[-1600:],
                )

                used_ports = {
                    int(item.get("listen_port"))
                    for item in (backend_verifier.query_netsnmpc_rules() or [])
                    if item.get("server_ip") == peer_host
                    and str(item.get("listen_port", "")).isdigit()
                }
                if requested_snmp_port:
                    candidate_ports = [int(requested_snmp_port)]
                else:
                    candidate_ports = [
                        41000 + secrets.randbelow(1000) for _ in range(40)
                    ]
                for candidate in candidate_ports:
                    if not 1025 <= candidate <= 65535 or candidate in used_ports:
                        continue
                    rc, _ = peer_exec(
                        "ss -H -lun | awk '{print $5}' | "
                        f"grep -Eq '[:.]{candidate}$'",
                        timeout=8,
                    )
                    if rc != 0:
                        snmp_port = candidate
                        break
                require(
                    "找到独立SNMP测试端口",
                    snmp_port is not None,
                    requested_snmp_port or "41000-41999",
                )

                interval_output = router_exec(
                    "/usr/ikuai/function/netsnmpc show TYPE=interval"
                )
                try:
                    original_interval = int(
                        json.loads(interval_output).get("snmp_interval", 0)
                    )
                except (ValueError, TypeError, json.JSONDecodeError):
                    raise FunctionalAbort(
                        f"无法读取跨三层访问频率: {interval_output}"
                    )
                observe(
                    "本轮参数",
                    "INFO",
                    f"SNMP对端={peer_host}:{snmp_port}, "
                    f"客户端={client_ip}/{client_mac}, 原访问频率={original_interval}",
                )

            with rec.step(
                "构造真实SNMP三层设备",
                "Ubuntu临时发布包含客户端真实IP/MAC的IP-MIB ARP表",
            ):
                assert snmp_port is not None
                peer_gateway = str(
                    ipaddress.ip_network(f"{client_ip}/24", strict=False)[-2]
                )
                snmp_config = (
                    f"agentaddress udp:{peer_host}:{snmp_port}\n"
                    f"rocommunity {community} {allowed_source} .1\n"
                    f"sysName ikuai-cross-layer-{suffix}\n"
                    "sysLocation automation-lab\n"
                )
                rc, output = _upload_text(peer, snmp_conf, snmp_config)
                require("下发独立SNMP配置", rc == 0, output)
                rc, output = peer_exec(
                    f"sudo -n ip link add {shlex.quote(veth_a)} type veth "
                    f"peer name {shlex.quote(veth_b)} && "
                    f"sudo -n ip link set dev {shlex.quote(veth_b)} "
                    f"address {shlex.quote(client_mac)} && "
                    f"sudo -n ip addr add {shlex.quote(peer_gateway + '/24')} "
                    f"dev {shlex.quote(veth_a)} && "
                    f"sudo -n ip link set {shlex.quote(veth_a)} up && "
                    f"sudo -n ip link set {shlex.quote(veth_b)} up && "
                    f"sudo -n ip neigh replace {shlex.quote(client_ip)} "
                    f"lladdr {shlex.quote(client_mac)} nud permanent "
                    f"dev {shlex.quote(veth_a)}",
                    timeout=15,
                )
                require("构造三层设备ARP表", rc == 0, output)

                inner = (
                    "nohup env MIBS= /usr/sbin/snmpd -f -Lo -C "
                    f"-c {shlex.quote(snmp_conf)} -p {shlex.quote(snmp_pid)} "
                    f"> {shlex.quote(snmp_log)} 2>&1 < /dev/null &"
                )
                rc, output = peer_exec(
                    f"sudo -n sh -c {shlex.quote(inner)}",
                    timeout=10,
                )
                require("启动独立Net-SNMP实例", rc == 0, output)

                def peer_snmp_ready() -> Tuple[bool, str]:
                    rc, detail = peer_exec(
                        f"test -s {shlex.quote(snmp_pid)} && "
                        f"sudo -n kill -0 $(cat {shlex.quote(snmp_pid)}) && "
                        f"snmpget -On -t 2 -r 0 -v2c -c "
                        f"{shlex.quote(community)} "
                        f"{shlex.quote(peer_host + ':' + str(snmp_port))} "
                        f"{TEST_OID} 2>&1",
                        timeout=8,
                    )
                    return rc == 0, detail

                ready, detail = _wait_for(
                    peer_snmp_ready,
                    timeout=12,
                    interval=1,
                )
                require("独立SNMP实例可查询", ready, detail[-1400:])

                walk_output = router_exec(
                    f"snmpwalk -On -t 3 -r 1 -v2c -c "
                    f"{shlex.quote(community)} "
                    f"{shlex.quote(peer_host + ':' + str(snmp_port))} "
                    f"{ARP_TABLE_OID} 2>&1",
                    timeout=20,
                )
                mib_mac = _snmp_mac_for_ip(walk_output, client_ip)
                require(
                    "DUT读取到客户端IP/MAC MIB行",
                    mib_mac == client_mac,
                    f"MIB={client_ip}/{mib_mac or '未找到'}, 客户端MAC={client_mac}",
                )

            with rec.step(
                "UI创建并学习跨三层规则",
                "页面添加V2规则并验证UDP报文、在线状态和精确ARP缓存",
            ):
                if original_interval != 0:
                    page.navigate_to_cross_layer_service()
                    page.set_frequency(0)
                    interval_changed = True
                    current_interval = json.loads(
                        router_exec(
                            "/usr/ikuai/function/netsnmpc show TYPE=interval"
                        )
                    ).get("snmp_interval")
                    require(
                        "UI切换即时访问频率",
                        int(current_interval) == 0,
                        f"当前={current_interval}",
                    )

                start_capture()
                page.navigate_to_cross_layer_service()
                require(
                    "UI添加跨三层服务规则",
                    page.add_rule(
                        name=rule_name,
                        snmp_server_ip=peer_host,
                        ips=[client_ip],
                        port=str(snmp_port),
                        snmp_version="V2",
                        community=community,
                        remark="真实SNMP跨三层MAC学习",
                    ),
                )
                learned, detail = _wait_for(
                    active_state_probe, timeout=25, interval=1
                )
                require("跨三层MAC学习真实生效", learned, detail)

                capture_output = stop_capture()
                summary = _capture_summary(
                    capture_output, peer_host, snmp_port
                )
                endpoint = re.escape(f"{peer_host}.{snmp_port}")
                request_seen = bool(
                    re.search(rf">\s*{endpoint}:", capture_output)
                )
                response_seen = bool(
                    re.search(rf"{endpoint}\s*>", capture_output)
                )
                require(
                    "DUT与SNMP对端双向报文",
                    request_seen and response_seen,
                    summary,
                )

            with rec.step(
                "停用态清除",
                "UI停用规则并验证本规则配置、状态和ARP缓存均移除",
            ):
                page.navigate_to_cross_layer_service()
                require(
                    "UI停用跨三层规则",
                    page.disable_rule(actual_rule_name()),
                )
                disabled, detail = _wait_for(
                    disabled_state_probe, timeout=15, interval=1
                )
                require("停用态后台清除", disabled, detail)

            with rec.step(
                "重新启用恢复学习",
                "UI重新启用同一规则并再次学习目标IP/MAC",
            ):
                page.navigate_to_cross_layer_service()
                require(
                    "UI重新启用跨三层规则",
                    page.enable_rule(actual_rule_name()),
                )
                learned, detail = _wait_for(
                    active_state_probe, timeout=25, interval=1
                )
                require("重新启用后MAC学习恢复", learned, detail)

        except FunctionalAbort as exc:
            if not failures:
                failures.append(str(exc))
            rec.add_detail(f"  [中止后续步骤] {exc}")
        except Exception as exc:
            failures.append(f"未预期异常: {type(exc).__name__}: {exc}")
            rec.add_detail(
                f"  [FAIL] 未预期异常: {type(exc).__name__}: {exc}"
            )
        finally:
            with rec.step(
                "恢复测试环境",
                "删除本轮规则并恢复访问频率、SNMP进程、临时接口和文件",
            ):
                if peer is not None and capture_started:
                    try:
                        stop_capture()
                    except Exception as exc:
                        cleanup_failures.append(f"SNMP抓包清理异常: {exc}")

                if backend_verifier is not None:
                    try:
                        current = find_test_rule()
                        if current is not None:
                            page.navigate_to_cross_layer_service()
                            deleted = page.delete_rule(
                                str(current.get("tagname") or rule_name)
                            )
                            removed, detail = _wait_for(
                                lambda: (
                                    find_test_rule() is None,
                                    str(find_test_rule()),
                                ),
                                timeout=8,
                                interval=1,
                            )
                            if not deleted or not removed:
                                rule_id = int(current["id"])
                                router_exec(
                                    f"/usr/ikuai/function/netsnmpc del id={rule_id}",
                                    timeout=10,
                                )
                                removed, detail = _wait_for(
                                    lambda: (
                                        find_test_rule() is None,
                                        str(find_test_rule()),
                                    ),
                                    timeout=8,
                                    interval=1,
                                )
                            if not removed:
                                cleanup_failures.append(
                                    f"本轮跨三层规则未删除: {detail}"
                                )
                    except Exception as exc:
                        cleanup_failures.append(f"跨三层规则清理异常: {exc}")

                    if interval_changed and original_interval is not None:
                        try:
                            page.navigate_to_cross_layer_service()
                            page.set_frequency(original_interval)
                            restored = json.loads(
                                router_exec(
                                    "/usr/ikuai/function/netsnmpc show TYPE=interval"
                                )
                            ).get("snmp_interval")
                            if int(restored) != original_interval:
                                router_exec(
                                    "/usr/ikuai/function/netsnmpc seting "
                                    f"snmp_interval={original_interval}",
                                    timeout=10,
                                )
                                restored = json.loads(
                                    router_exec(
                                        "/usr/ikuai/function/netsnmpc show "
                                        "TYPE=interval"
                                    )
                                ).get("snmp_interval")
                            if int(restored) != original_interval:
                                cleanup_failures.append(
                                    "跨三层访问频率未恢复: "
                                    f"期望={original_interval}, 实际={restored}"
                                )
                        except Exception as exc:
                            cleanup_failures.append(
                                f"跨三层访问频率恢复异常: {exc}"
                            )

                if peer is not None:
                    try:
                        inner = (
                            f"if [ -s {shlex.quote(snmp_pid)} ]; then "
                            f"pid=$(cat {shlex.quote(snmp_pid)}); "
                            "if tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null "
                            f"| grep -Fq {shlex.quote(snmp_conf)}; then "
                            "kill -9 $pid 2>/dev/null || true; fi; fi; "
                            f"ip link del {shlex.quote(veth_a)} "
                            "2>/dev/null || true; "
                            f"rm -rf {shlex.quote(remote_dir)}"
                        )
                        rc, output = peer_exec(
                            f"sudo -n sh -c {shlex.quote(inner)}; "
                            f"test ! -e /sys/class/net/{shlex.quote(veth_a)}; "
                            f"test ! -e {shlex.quote(remote_dir)}",
                            timeout=15,
                        )
                        if rc != 0:
                            cleanup_failures.append(
                                f"Ubuntu临时SNMP环境清理失败: {output[-1200:]}"
                            )
                    except Exception as exc:
                        cleanup_failures.append(
                            f"Ubuntu临时SNMP环境清理异常: {exc}"
                        )

                if cleanup_failures:
                    for item in cleanup_failures:
                        rec.add_detail(f"  [FAIL] {item}")
                else:
                    rec.add_detail(
                        "  [OK] 本轮规则、频率和Ubuntu临时SNMP环境均已恢复"
                    )

            if peer is not None:
                peer.close()
            if client is not None:
                client.close()

        all_failures = failures + cleanup_failures
        assert not all_failures, "跨三层服务真实功能测试失败:\n- " + "\n- ".join(
            all_failures
        )
