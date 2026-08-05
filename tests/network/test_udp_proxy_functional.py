"""UDPXY real multicast-to-HTTP data-plane test.

Default topology::

    10.66.0.57/enp6s0 -- DUT wan1(10.66.0.45)
                                |
                         DUT lan1(192.168.148.1)
                                |
                  10.66.0.18/ens11(192.168.148.2)

The WAN host sends MPEG-TS-shaped multicast datagrams containing a unique
token.  The LAN client requests the stream through UDPXY over HTTP.  Finding
that token in the HTTP response proves real multicast-to-unicast forwarding.

Optional environment overrides:
    UDPXY_WAN_HOST / UDPXY_WAN_USERNAME / UDPXY_WAN_PASSWORD / UDPXY_WAN_PORT
    UDPXY_WAN_SOURCE_IP / UDPXY_CLIENT_IFACE / UDPXY_CLIENT_IP
    UDPXY_SOURCE_INTERFACE / UDPXY_GROUP / UDPXY_STREAM_PORT / UDPXY_PROXY_PORT
    UDPXY_LAN_TARGET / UDPXY_WAN_TARGET
"""

import base64
import ipaddress
import json
import os
import re
import secrets
import shlex
import textwrap
import time
from typing import Callable, Dict, Iterable, Optional, Tuple

import pytest

from config.config import Config, SSHHostConfig
from pages.network.udp_proxy_page import UdpProxyPage
from utils.backend_verifier import BackendVerifier, SSHClient
from utils.step_recorder import StepRecorder


DUT_MANAGEMENT_IP = "10.66.0.45"
DEFAULT_WAN_HOST = "10.66.0.57"
DEFAULT_WAN_SOURCE_IP = "10.66.0.57"
DEFAULT_CLIENT_HOST = "10.66.0.18"
DEFAULT_CLIENT_IFACE = "ens11"
DEFAULT_CLIENT_IP = "192.168.148.2"
DEFAULT_SOURCE_INTERFACE = "wan1"
DEFAULT_LAN_TARGET = "192.168.148.1"
DEFAULT_WAN_TARGET = "10.66.0.45"
DEFAULT_GROUP = "239.148.66.46"
DEFAULT_STREAM_PORT = 46246
MIN_TOKEN_PACKETS = 3


SENDER_SCRIPT = textwrap.dedent(
    r"""
    import argparse
    import socket
    import time

    parser = argparse.ArgumentParser()
    parser.add_argument("--group", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--count", type=int, default=180)
    parser.add_argument("--interval", type=float, default=0.08)
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_MULTICAST_IF,
        socket.inet_aton(args.source_ip),
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 8)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

    with open(args.ready_file, "w", encoding="ascii") as stream:
        stream.write("READY")

    time.sleep(0.5)
    for sequence in range(args.count):
        marker = f"{args.token}|sequence={sequence}|".encode("ascii")
        packets = []
        for packet_index in range(7):
            packet = bytearray(b"\xff" * 188)
            packet[0] = 0x47
            packet[1] = 0x40 if packet_index == 0 else 0x00
            packet[2] = packet_index
            packet[3] = 0x10 | (sequence & 0x0f)
            if packet_index == 0:
                packet[4:4 + len(marker)] = marker
            packets.append(packet)
        sock.sendto(b"".join(packets), (args.group, args.port))
        time.sleep(args.interval)
    sock.close()
    print(
        f"SENT={args.count} SOURCE={args.source_ip} "
        f"TARGET={args.group}:{args.port} TOKEN={args.token}",
        flush=True,
    )
    """
).strip()


HTTP_PROBE_SCRIPT = textwrap.dedent(
    r"""
    import argparse
    import json
    import socket
    import time

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--proxy-port", required=True, type=int)
    parser.add_argument("--group", required=True)
    parser.add_argument("--stream-port", required=True, type=int)
    parser.add_argument("--token", required=True)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--minimum", type=int, default=3)
    parser.add_argument("--result-file", required=True)
    args = parser.parse_args()

    result = {
        "connected": False,
        "http_status": "",
        "received": False,
        "token_count": 0,
        "bytes": 0,
        "source_ip": args.source_ip,
        "target": args.target,
        "proxy_port": args.proxy_port,
        "group": args.group,
        "stream_port": args.stream_port,
        "token": args.token,
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(min(args.timeout, 3.0))
    started = time.monotonic()
    received = bytearray()
    try:
        sock.bind((args.source_ip, 0))
        sock.connect((args.target, args.proxy_port))
        result["connected"] = True
        request = (
            f"GET /udp/{args.group}:{args.stream_port}/ HTTP/1.0\r\n"
            f"Host: {args.target}:{args.proxy_port}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        sock.settimeout(0.5)
        while time.monotonic() - started < args.timeout:
            try:
                chunk = sock.recv(65535)
            except socket.timeout:
                continue
            if not chunk:
                break
            received.extend(chunk)
            token_count = received.count(args.token.encode("ascii"))
            if token_count >= args.minimum:
                break
        header = bytes(received).partition(b"\r\n\r\n")[0]
        first_line = header.splitlines()[0] if header else b""
        result["http_status"] = first_line.decode("ascii", errors="replace")
        result["token_count"] = received.count(args.token.encode("ascii"))
        result["bytes"] = len(received)
        result["received"] = result["token_count"] >= args.minimum
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()

    with open(args.result_file, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=True, sort_keys=True)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    """
).strip()


class FunctionalAbort(RuntimeError):
    """Stop dependent stages while still restoring the environment."""


def _exec_with_rc(
    ssh: SSHClient, command: str, timeout: int = 20
) -> Tuple[int, str]:
    """Execute a remote command and retain its shell exit status."""
    marker = "__UDPXY_TEST_RC__="
    wrapped = (
        f"{command}\n"
        "__udpxy_test_rc=$?\n"
        f"printf '\\n{marker}%s\\n' \"$__udpxy_test_rc\""
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
    timeout: float = 10.0,
    interval: float = 0.5,
) -> Tuple[bool, str]:
    """Poll a condition and preserve the final diagnostic detail."""
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
    """Upload a small UTF-8 file through the existing SSH shell."""
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    parent = remote_path.rsplit("/", 1)[0]
    command = (
        f"mkdir -p {shlex.quote(parent)} && "
        f"printf %s {shlex.quote(encoded)} | base64 -d > "
        f"{shlex.quote(remote_path)}"
    )
    return _exec_with_rc(ssh, command, timeout=timeout)


def _parse_probe_result(output: str) -> Dict:
    """Parse the HTTP probe's final JSON line and validate its contract."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        raise ValueError("HTTP probe returned no output")
    data = json.loads(lines[-1])
    required = {
        "connected",
        "http_status",
        "received",
        "token_count",
        "bytes",
        "source_ip",
        "target",
        "proxy_port",
        "group",
        "stream_port",
        "token",
        "error",
    }
    missing = required.difference(data)
    if missing:
        raise ValueError(f"HTTP probe result missing fields: {sorted(missing)}")
    return data


def _capture_summary(output: str, token: str, proxy_port: int) -> str:
    """Keep useful UDPXY packets and tcpdump counters for the HTML report."""
    useful = []
    port_text = str(proxy_port)
    for line in output.splitlines():
        lowered = line.lower()
        if (
            token in line
            or port_text in line
            or "packets captured" in lowered
            or "flags [" in lowered
        ):
            useful.append(line)
    return "\n".join(useful[-100:])[-7000:] if useful else output[-3000:]


@pytest.mark.udp_proxy
@pytest.mark.network
@pytest.mark.p0
class TestUdpProxyFunctional:
    """Validate UDPXY payload forwarding, lifecycle, and WAN ACL behavior."""

    def test_udpxy_real_multicast_to_http(
        self,
        udp_proxy_page_logged_in: UdpProxyPage,
        step_recorder: StepRecorder,
        backend_verifier: Optional[BackendVerifier],
        config: Config,
    ):
        page = udp_proxy_page_logged_in
        rec = step_recorder
        failures = []
        cleanup_failures = []
        suffix = secrets.token_hex(4)
        # The backend silently truncates names after 15 characters.
        rule_name = f"uf-{suffix}"

        client_iface = os.getenv(
            "UDPXY_CLIENT_IFACE", DEFAULT_CLIENT_IFACE
        ).strip()
        client_ip = os.getenv("UDPXY_CLIENT_IP", DEFAULT_CLIENT_IP).strip()
        source_interface = os.getenv(
            "UDPXY_SOURCE_INTERFACE", DEFAULT_SOURCE_INTERFACE
        ).strip()
        group = os.getenv("UDPXY_GROUP", DEFAULT_GROUP).strip()
        stream_port = int(
            os.getenv("UDPXY_STREAM_PORT", str(DEFAULT_STREAM_PORT))
        )
        requested_proxy_port = os.getenv("UDPXY_PROXY_PORT", "").strip()
        lan_target = os.getenv("UDPXY_LAN_TARGET", DEFAULT_LAN_TARGET).strip()
        wan_target = os.getenv("UDPXY_WAN_TARGET", DEFAULT_WAN_TARGET).strip()
        wan_host = os.getenv("UDPXY_WAN_HOST", DEFAULT_WAN_HOST).strip()
        wan_source_ip = os.getenv(
            "UDPXY_WAN_SOURCE_IP", wan_host or DEFAULT_WAN_SOURCE_IP
        ).strip()
        wan_username = os.getenv(
            "UDPXY_WAN_USERNAME", config.ssh.client.username
        )
        wan_password = os.getenv(
            "UDPXY_WAN_PASSWORD", config.ssh.client.password
        )
        wan_port = int(os.getenv("UDPXY_WAN_PORT", str(config.ssh.client.port)))

        remote_dir = f"/tmp/ikuai-udpxy-{suffix}"
        capture_dir = f"/tmp/ikuai-udpxy-capture-{suffix}"
        sender_path = f"{remote_dir}/sender.py"
        probe_path = f"{remote_dir}/http_probe.py"

        client: Optional[SSHClient] = None
        wan_sender: Optional[SSHClient] = None
        proxy_port: Optional[int] = None

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

        def sender_exec(command: str, timeout: int = 20) -> Tuple[int, str]:
            assert wan_sender is not None
            return _exec_with_rc(wan_sender, command, timeout)

        def router_exec(command: str, timeout: int = 20) -> str:
            assert backend_verifier is not None
            backend_verifier.connect_router()
            return backend_verifier._router.exec(
                command, timeout=timeout, probe_console=False
            ) or ""

        def router_exec_rc(
            command: str, timeout: int = 20
        ) -> Tuple[int, str]:
            assert backend_verifier is not None
            backend_verifier.connect_router()
            return _exec_with_rc(backend_verifier._router, command, timeout)

        def find_test_rule() -> Optional[Dict]:
            """Find only this run's rule, tolerating backend name truncation."""
            rules = backend_verifier.query_udp_proxy_config() or []
            exact = [item for item in rules if item.get("tagname") == rule_name]
            if len(exact) == 1:
                return exact[0]
            if proxy_port is None:
                return None
            by_port = [
                item
                for item in rules
                if int(item.get("listen_port", -1)) == proxy_port
                and str(item.get("tagname", "")).startswith("uf-")
            ]
            return by_port[0] if len(by_port) == 1 else None

        def actual_rule_name() -> str:
            current = find_test_rule()
            return str(current.get("tagname")) if current else rule_name

        def start_capture(stage: str, interfaces: Iterable[str]):
            assert proxy_port is not None
            unique_interfaces = list(dict.fromkeys(interfaces))
            commands = [f"mkdir -p {shlex.quote(capture_dir)}"]
            pid_checks = []
            capture_filter = (
                f"(udp and dst host {group} and dst port {stream_port}) "
                f"or (tcp port {proxy_port})"
            )
            for interface in unique_interfaces:
                pid_path = f"{capture_dir}/{stage}-{interface}.pid"
                pcap_path = f"{capture_dir}/{stage}-{interface}.pcap"
                commands.append(
                    "start-stop-daemon -S -b -m "
                    f"-p {shlex.quote(pid_path)} -x /usr/sbin/tcpdump -- "
                    f"-U -n -i {shlex.quote(interface)} -s 0 -c 500 "
                    f"-w {shlex.quote(pcap_path)} {shlex.quote(capture_filter)}"
                )
                pid_checks.append(
                    f"kill -0 $(cat {shlex.quote(pid_path)}) 2>/dev/null"
                )
            commands.append("sleep 1")
            commands.append(" && ".join(pid_checks))
            rc, output = router_exec_rc("; ".join(commands), timeout=12)
            require(
                f"{stage} DUT抓包启动",
                rc == 0,
                output or ",".join(unique_interfaces),
            )

        def stop_capture(stage: str, interfaces: Iterable[str]) -> str:
            outputs = []
            for interface in dict.fromkeys(interfaces):
                pid_path = f"{capture_dir}/{stage}-{interface}.pid"
                pcap_path = f"{capture_dir}/{stage}-{interface}.pcap"
                output = router_exec(
                    f"test ! -f {shlex.quote(pid_path)} || "
                    f"kill -INT $(cat {shlex.quote(pid_path)}) "
                    "2>/dev/null || true; sleep 1; "
                    f"echo '[{interface}]'; "
                    f"tcpdump -nn -r {shlex.quote(pcap_path)} -A 2>&1 || true",
                    timeout=12,
                )
                outputs.append(output)
            return "\n".join(outputs)

        def start_sender(stage: str, token: str):
            ready_path = f"{remote_dir}/sender-{stage}.ready"
            log_path = f"{remote_dir}/sender-{stage}.log"
            pid_path = f"{remote_dir}/sender-{stage}.pid"
            rc, output = sender_exec(
                f"rm -f {shlex.quote(ready_path)} {shlex.quote(log_path)} "
                f"{shlex.quote(pid_path)}; "
                f"nohup python3 {shlex.quote(sender_path)} "
                f"--group {shlex.quote(group)} --port {stream_port} "
                f"--source-ip {shlex.quote(wan_source_ip)} "
                f"--token {shlex.quote(token)} --count 180 --interval 0.08 "
                f"--ready-file {shlex.quote(ready_path)} > "
                f"{shlex.quote(log_path)} 2>&1 < /dev/null & "
                f"echo $! > {shlex.quote(pid_path)}",
                timeout=10,
            )
            require(f"{stage} WAN组播发送器启动", rc == 0, output)

            def sender_ready() -> Tuple[bool, str]:
                rc, ready_output = sender_exec(
                    f"test -f {shlex.quote(ready_path)} && "
                    f"cat {shlex.quote(ready_path)} || "
                    f"cat {shlex.quote(log_path)} 2>/dev/null",
                    timeout=8,
                )
                return rc == 0 and "READY" in ready_output, ready_output

            ready, detail = _wait_for(sender_ready, timeout=6)
            require(f"{stage} WAN组播发送器就绪", ready, detail[-1200:])

        def stop_sender(stage: str) -> str:
            pid_path = f"{remote_dir}/sender-{stage}.pid"
            log_path = f"{remote_dir}/sender-{stage}.log"
            _, output = sender_exec(
                f"test ! -f {shlex.quote(pid_path)} || "
                f"kill $(cat {shlex.quote(pid_path)}) 2>/dev/null || true; "
                f"cat {shlex.quote(log_path)} 2>/dev/null || true",
                timeout=8,
            )
            return output

        def run_http_probe(
            stage: str,
            label: str,
            runner: SSHClient,
            source_ip: str,
            target_ip: str,
            capture_interfaces: Iterable[str],
            expect_stream: bool,
            send_multicast: bool,
            timeout: int = 8,
        ) -> Dict:
            assert proxy_port is not None
            token = f"IKUAI_UDPXY_{stage.upper()}_{suffix}"
            result_path = f"{remote_dir}/{stage}.json"
            interfaces = list(capture_interfaces)
            capture_output = ""
            sender_output = ""
            start_capture(stage, interfaces)
            try:
                if send_multicast:
                    start_sender(stage, token)
                rc, output = _exec_with_rc(
                    runner,
                    f"rm -f {shlex.quote(result_path)}; "
                    f"python3 {shlex.quote(probe_path)} "
                    f"--target {shlex.quote(target_ip)} "
                    f"--source-ip {shlex.quote(source_ip)} "
                    f"--proxy-port {proxy_port} "
                    f"--group {shlex.quote(group)} --stream-port {stream_port} "
                    f"--token {shlex.quote(token)} --timeout {timeout} "
                    f"--minimum {MIN_TOKEN_PACKETS} "
                    f"--result-file {shlex.quote(result_path)}",
                    timeout=timeout + 10,
                )
                require(f"{label}探针执行", rc == 0, output[-1800:])
                result = _parse_probe_result(output)
                if expect_stream:
                    passed = (
                        result["connected"] is True
                        and result["received"] is True
                        and int(result["token_count"]) >= MIN_TOKEN_PACKETS
                        and str(result["http_status"]).startswith("HTTP/1.")
                        and " 200 " in str(result["http_status"])
                    )
                    record(
                        f"{label}真实UDPXY转发",
                        passed,
                        f"{source_ip} -> http://{target_ip}:{proxy_port}/udp/"
                        f"{group}:{stream_port}/, HTTP={result['http_status']}, "
                        f"令牌={result['token_count']}个, 字节={result['bytes']}",
                    )
                else:
                    passed = result["connected"] is False
                    record(
                        f"{label}连接阻断",
                        passed,
                        f"connected={result['connected']}, "
                        f"HTTP={result['http_status'] or '无'}, "
                        f"error={result['error'] or '无'}",
                    )
                return result
            finally:
                if send_multicast:
                    sender_output = stop_sender(stage)
                capture_output = stop_capture(stage, interfaces)
                summary = _capture_summary(capture_output, token, proxy_port)
                observe(
                    f"{label}DUT抓包证据",
                    "INFO",
                    f"[发送端]\n{sender_output[-1200:]}\n[DUT]\n{summary}",
                )

        def wait_backend_state(
            enabled: str, access: int
        ) -> Tuple[bool, str]:
            assert proxy_port is not None

            def probe() -> Tuple[bool, str]:
                current = find_test_rule() or {}
                process = router_exec("ps | grep udpxy | grep -v grep")
                process_match = (
                    f"-p {proxy_port}" in process
                    and f"-m {source_interface}" in process
                )
                passed = (
                    current.get("enabled") == enabled
                    and int(current.get("access", -1)) == access
                    and int(current.get("listen_port", -1)) == proxy_port
                    and current.get("interface") == source_interface
                    and process_match == (enabled == "yes")
                )
                return passed, (
                    f"配置={json.dumps(current, ensure_ascii=False)}, "
                    f"目标进程={'运行' if process_match else '未运行'}"
                )

            return _wait_for(probe, timeout=12, interval=1)

        try:
            if backend_verifier is None:
                raise FunctionalAbort("SSH后台验证器不可用，无法执行真实功能测试")
            if not source_interface or not re.fullmatch(
                r"[A-Za-z0-9_.:-]+", source_interface
            ):
                raise FunctionalAbort(
                    f"UDPXY_SOURCE_INTERFACE无效: {source_interface}"
                )
            if not client_iface or not re.fullmatch(
                r"[A-Za-z0-9_.:-]+", client_iface
            ):
                raise FunctionalAbort(f"UDPXY_CLIENT_IFACE无效: {client_iface}")
            if not (1025 <= stream_port <= 65535):
                raise FunctionalAbort(f"UDPXY_STREAM_PORT越界: {stream_port}")

            for name, address in (
                ("UDPXY_CLIENT_IP", client_ip),
                ("UDPXY_WAN_HOST", wan_host),
                ("UDPXY_WAN_SOURCE_IP", wan_source_ip),
                ("UDPXY_LAN_TARGET", lan_target),
                ("UDPXY_WAN_TARGET", wan_target),
                ("UDPXY_GROUP", group),
            ):
                parsed = ipaddress.ip_address(address)
                if parsed.version != 4:
                    raise FunctionalAbort(f"{name}必须是IPv4地址: {address}")
            if ipaddress.ip_address(group) not in ipaddress.ip_network("239.0.0.0/8"):
                raise FunctionalAbort(
                    f"UDPXY_GROUP必须使用239.0.0.0/8管理域地址: {group}"
                )

            client = SSHClient(config.ssh.client)
            client.connect()
            wan_sender = SSHClient(
                SSHHostConfig(
                    host=wan_host,
                    username=wan_username,
                    password=wan_password,
                    port=wan_port,
                )
            )
            wan_sender.connect()
            backend_verifier.connect_router()

            existing = backend_verifier.query_udp_proxy_config() or []
            used_ports = {
                int(item.get("listen_port"))
                for item in existing
                if str(item.get("listen_port", "")).isdigit()
            }
            if requested_proxy_port:
                proxy_port = int(requested_proxy_port)
                if not (1025 <= proxy_port <= 65535):
                    raise FunctionalAbort(
                        f"UDPXY_PROXY_PORT越界: {proxy_port}"
                    )
                if proxy_port in used_ports:
                    raise FunctionalAbort(
                        f"UDPXY_PROXY_PORT已被现有规则占用: {proxy_port}"
                    )
            else:
                for _ in range(100):
                    candidate = 47000 + secrets.randbelow(1000)
                    if candidate not in used_ports:
                        proxy_port = candidate
                        break
                if proxy_port is None:
                    raise FunctionalAbort("无法找到空闲UDPXY服务端口")

            with rec.step(
                "测试环境校验",
                "确认三端拓扑、接口地址、远端工具和测试端口",
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
                    "WAN发送端独立于DUT和LAN客户端",
                    wan_host not in {DUT_MANAGEMENT_IP, config.ssh.client.host},
                    wan_host,
                )
                rc, client_address = client_exec(
                    f"ip -4 -o addr show dev {shlex.quote(client_iface)} 2>&1; "
                    "command -v python3; command -v base64; command -v tcpdump"
                )
                require(
                    "LAN客户端地址和工具",
                    rc == 0
                    and bool(
                        re.search(
                            rf"\binet\s+{re.escape(client_ip)}/\d+\b",
                            client_address,
                        )
                    )
                    and "python3" in client_address
                    and "base64" in client_address
                    and "tcpdump" in client_address,
                    client_address,
                )
                rc, sender_route = sender_exec(
                    f"ip route get {shlex.quote(wan_target)} "
                    f"from {shlex.quote(wan_source_ip)} 2>&1; "
                    "command -v python3; command -v base64; command -v curl"
                )
                require(
                    "WAN组播源与DUT直连且工具可用",
                    rc == 0
                    and (
                        f"src {wan_source_ip}" in sender_route
                        or f"from {wan_source_ip}" in sender_route
                    )
                    and " via " not in f" {sender_route} "
                    and "python3" in sender_route
                    and "base64" in sender_route,
                    sender_route,
                )
                dut_state = router_exec(
                    f"ip -4 -o addr show dev {shlex.quote(source_interface)}; "
                    "ip -4 -o addr show dev lan1; command -v tcpdump; "
                    "command -v udpxy"
                )
                require(
                    "DUT接口和UDPXY工具",
                    wan_target in dut_state
                    and lan_target in dut_state
                    and "tcpdump" in dut_state
                    and "udpxy" in dut_state,
                    dut_state,
                )
                rc, upload_output = _upload_text(
                    wan_sender, sender_path, SENDER_SCRIPT
                )
                require("下发WAN组播发送脚本", rc == 0, upload_output)
                for target, label in (
                    (client, "LAN客户端"),
                    (wan_sender, "WAN客户端"),
                ):
                    rc, upload_output = _upload_text(
                        target, probe_path, HTTP_PROBE_SCRIPT
                    )
                    require(f"下发{label}HTTP探针", rc == 0, upload_output)
                observe(
                    "本轮UDPXY参数",
                    "INFO",
                    f"组播源={wan_source_ip}, 信号接口={source_interface}, "
                    f"流={group}:{stream_port}, 服务端口={proxy_port}",
                )

            with rec.step(
                "创建UDPXY规则",
                "通过UI创建wan1信号源规则并禁止外网访问",
            ):
                page.navigate_to_udp_proxy()
                require(
                    "UI添加UDPXY规则",
                    page.add_rule(
                        tagname=rule_name,
                        interface=source_interface,
                        listen_port=str(proxy_port),
                        renew_time="0",
                        access_allow=False,
                    ),
                )
                active, detail = wait_backend_state("yes", 0)
                require("UDPXY配置和进程生效", active, detail)
                ipset_result = backend_verifier.verify_udp_proxy_ipset(
                    expect_present=True, listen_port=proxy_port
                )
                require(
                    "禁止外网访问规则生效",
                    ipset_result.passed,
                    f"{ipset_result.message}; {ipset_result.raw_output[-1200:]}",
                )

            with rec.step(
                "LAN真实流转换",
                "LAN客户端通过HTTP请求并校验WAN组播中的唯一载荷令牌",
            ):
                run_http_probe(
                    "lan_initial",
                    "LAN初次访问",
                    client,
                    client_ip,
                    lan_target,
                    [source_interface, "lan1"],
                    expect_stream=True,
                    send_multicast=True,
                )

            with rec.step(
                "外网访问禁止",
                "从WAN直连主机访问DUT服务端口，确认TCP连接被策略阻断",
            ):
                run_http_probe(
                    "wan_blocked",
                    "WAN禁止态访问",
                    wan_sender,
                    wan_source_ip,
                    wan_target,
                    [source_interface],
                    expect_stream=False,
                    send_multicast=False,
                    timeout=4,
                )

            with rec.step(
                "外网访问允许",
                "通过UI允许外网访问并从WAN侧完成真实HTTP取流",
            ):
                page.navigate_to_udp_proxy()
                require(
                    "UI允许外网访问",
                    page.edit_rule_modify(
                        actual_rule_name(), access_allow=True
                    ),
                )
                active, detail = wait_backend_state("yes", 1)
                require("允许态配置和进程生效", active, detail)
                ipset_result = backend_verifier.verify_udp_proxy_ipset(
                    expect_present=False, listen_port=proxy_port
                )
                require(
                    "允许态DROP规则已移除",
                    ipset_result.passed,
                    f"{ipset_result.message}; {ipset_result.raw_output[-1200:]}",
                )
                run_http_probe(
                    "wan_allowed",
                    "WAN允许态访问",
                    wan_sender,
                    wan_source_ip,
                    wan_target,
                    [source_interface],
                    expect_stream=True,
                    send_multicast=True,
                )

            with rec.step(
                "停用态阻断",
                "通过UI停用规则，确认进程退出且LAN新建连接失败",
            ):
                page.navigate_to_udp_proxy()
                require(
                    "UI停用UDPXY规则",
                    page.disable_rule(actual_rule_name()),
                )
                inactive, detail = wait_backend_state("no", 1)
                require("停用态配置和进程生效", inactive, detail)
                run_http_probe(
                    "disabled",
                    "停用态LAN访问",
                    client,
                    client_ip,
                    lan_target,
                    ["lan1"],
                    expect_stream=False,
                    send_multicast=False,
                    timeout=4,
                )

            with rec.step(
                "重新启用恢复",
                "重新启用同一规则并再次校验真实组播到HTTP载荷",
            ):
                page.navigate_to_udp_proxy()
                require(
                    "UI重新启用UDPXY规则",
                    page.enable_rule(actual_rule_name()),
                )
                active, detail = wait_backend_state("yes", 1)
                require("重新启用配置和进程生效", active, detail)
                run_http_probe(
                    "lan_reenabled",
                    "重新启用后LAN访问",
                    client,
                    client_ip,
                    lan_target,
                    [source_interface, "lan1"],
                    expect_stream=True,
                    send_multicast=True,
                )

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
                "停止远端进程、删除临时文件并删除本轮唯一UDPXY规则",
            ):
                if wan_sender is not None:
                    rc, output = sender_exec(
                        f"for pidfile in {shlex.quote(remote_dir)}/sender-*.pid; do "
                        "[ -e \"$pidfile\" ] || continue; "
                        "kill $(cat \"$pidfile\") 2>/dev/null || true; done; "
                        f"rm -rf {shlex.quote(remote_dir)}",
                        timeout=12,
                    )
                    if rc != 0:
                        cleanup_failures.append(
                            f"WAN临时环境清理失败: {output[-800:]}"
                        )
                if client is not None:
                    rc, output = client_exec(
                        f"rm -rf {shlex.quote(remote_dir)}", timeout=10
                    )
                    if rc != 0:
                        cleanup_failures.append(
                            f"LAN临时环境清理失败: {output[-800:]}"
                        )
                if backend_verifier is not None:
                    try:
                        router_exec(
                            f"for pidfile in {shlex.quote(capture_dir)}/*.pid; do "
                            "[ -e \"$pidfile\" ] || continue; "
                            "kill -INT $(cat \"$pidfile\") 2>/dev/null || true; "
                            "done; "
                            f"rm -rf {shlex.quote(capture_dir)}",
                            timeout=12,
                        )
                    except Exception as exc:
                        cleanup_failures.append(f"DUT抓包清理异常: {exc}")

                    try:
                        existing_rule = find_test_rule()
                        if existing_rule is not None:
                            page.navigate_to_udp_proxy()
                            actual_name = str(
                                existing_rule.get("tagname") or rule_name
                            )
                            deleted = page.delete_rule(actual_name)
                            removed, detail = _wait_for(
                                lambda: (
                                    find_test_rule() is None,
                                    str(find_test_rule()),
                                ),
                                timeout=6,
                                interval=1,
                            )
                            if not deleted or not removed:
                                # The target is constrained by this run's
                                # unique name/port match before using its ID.
                                rule_id = int(existing_rule["id"])
                                router_exec(
                                    f"/usr/ikuai/function/udp_proxy del id={rule_id}",
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
                                    f"本轮UDPXY规则后台未删除: {detail}"
                                )
                    except Exception as exc:
                        cleanup_failures.append(f"UDPXY规则清理异常: {exc}")

                if cleanup_failures:
                    for item in cleanup_failures:
                        rec.add_detail(f"  [FAIL] {item}")
                else:
                    rec.add_detail("  [OK] 测试环境已恢复，原有UDPXY规则未改动")

            if wan_sender is not None:
                wan_sender.close()
            if client is not None:
                client.close()

        all_failures = failures + cleanup_failures
        assert not all_failures, "UDPXY真实功能测试失败:\n- " + "\n- ".join(
            all_failures
        )
