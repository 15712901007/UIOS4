"""IGMP proxy real multicast data-plane test.

Topology used by default::

    10.66.0.57/enp6s0 -- DUT wan1(10.66.0.45)
                                |
                         DUT lan1(192.168.148.1)
                                |
                  10.66.0.18/ens11(192.168.148.2)

The LAN client joins an administratively scoped multicast group with a normal
UDP socket.  The independent WAN host sends packets containing a per-run
token.  Receiving that token on the LAN proves that the proxy forwards real
multicast traffic, rather than only accepting configuration.

Optional environment overrides:
    IGMP_WAN_HOST / IGMP_WAN_USERNAME / IGMP_WAN_PASSWORD / IGMP_WAN_PORT
    IGMP_WAN_SOURCE_IP / IGMP_CLIENT_IFACE / IGMP_CLIENT_IP
    IGMP_UPSTREAM / IGMP_DOWNSTREAM / IGMP_GROUP / IGMP_PORT
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
from typing import Callable, Dict, Optional, Tuple

import pytest

from config.config import Config, SSHHostConfig
from pages.network.igmp_proxy_page import IgmpProxyPage
from utils.backend_verifier import BackendVerifier, SSHClient
from utils.step_recorder import StepRecorder


DUT_MANAGEMENT_IP = "10.66.0.45"
DEFAULT_WAN_HOST = "10.66.0.57"
DEFAULT_WAN_SOURCE_IP = "10.66.0.57"
DEFAULT_CLIENT_HOST = "10.66.0.18"
DEFAULT_CLIENT_IFACE = "ens11"
DEFAULT_CLIENT_IP = "192.168.148.2"
DEFAULT_UPSTREAM = "wan1"
DEFAULT_DOWNSTREAM = "lan1"
DEFAULT_GROUP = "239.148.66.45"
DEFAULT_PORT = 46145
MIN_RECEIVED_PACKETS = 3


RECEIVER_SCRIPT = textwrap.dedent(
    r"""
    import argparse
    import json
    import socket
    import time

    parser = argparse.ArgumentParser()
    parser.add_argument("--group", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--interface-ip", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--minimum", type=int, default=3)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--result-file", required=True)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", args.port))
    membership = (
        socket.inet_aton(args.group) + socket.inet_aton(args.interface_ip)
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    sock.settimeout(0.5)

    with open(args.ready_file, "w", encoding="ascii") as stream:
        stream.write("READY")

    deadline = time.monotonic() + args.timeout
    packets = 0
    sources = []
    samples = []
    try:
        while time.monotonic() < deadline and packets < args.minimum:
            try:
                payload, source = sock.recvfrom(65535)
            except socket.timeout:
                continue
            decoded = payload.decode("utf-8", errors="replace")
            if args.token not in decoded:
                continue
            packets += 1
            sources.append(source[0])
            samples.append(decoded[:200])
    finally:
        try:
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, membership
            )
        except OSError:
            pass
        sock.close()

    result = {
        "received": packets >= args.minimum,
        "packets": packets,
        "sources": sources,
        "samples": samples,
        "group": args.group,
        "port": args.port,
        "token": args.token,
    }
    with open(args.result_file, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=True, sort_keys=True)
    """
).strip()


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
    parser.add_argument("--count", type=int, default=24)
    parser.add_argument("--interval", type=float, default=0.15)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_MULTICAST_IF,
        socket.inet_aton(args.source_ip),
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 8)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    for sequence in range(args.count):
        payload = f"{args.token}|sequence={sequence}".encode("ascii")
        sock.sendto(payload, (args.group, args.port))
        time.sleep(args.interval)
    sock.close()
    print(
        f"SENT={args.count} SOURCE={args.source_ip} "
        f"TARGET={args.group}:{args.port} TOKEN={args.token}"
    )
    """
).strip()


class FunctionalAbort(RuntimeError):
    """Stop dependent stages while still running environment restoration."""


def _exec_with_rc(
    ssh: SSHClient, command: str, timeout: int = 20
) -> Tuple[int, str]:
    """Execute a remote shell command and preserve its exit status."""
    marker = "__IGMP_TEST_RC__="
    wrapped = (
        f"{command}\n"
        "__igmp_test_rc=$?\n"
        f"printf '\\n{marker}%s\\n' \"$__igmp_test_rc\""
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
    """Poll a remote condition and return its last diagnostic output."""
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


def _parse_probe_result(output: str) -> Dict:
    """Parse the receiver JSON while rejecting incomplete remote output."""
    data = json.loads(output.strip())
    required = {"received", "packets", "sources", "token", "group", "port"}
    missing = required.difference(data)
    if missing:
        raise ValueError(f"receiver result missing fields: {sorted(missing)}")
    return data


def _capture_summary(output: str, token: str) -> str:
    """Keep only useful IGMP and token-bearing tcpdump lines for the report."""
    useful = []
    for line in output.splitlines():
        if token in line or "igmp" in line.lower() or "packets captured" in line:
            useful.append(line)
    if not useful:
        return output[-2500:]
    return "\n".join(useful[-80:])[-5000:]


@pytest.mark.igmp_proxy
@pytest.mark.network
@pytest.mark.p0
class TestIgmpProxyFunctional:
    """IGMPv3/v2 forwarding and disabled-state isolation verification."""

    def test_igmp_proxy_real_multicast(
        self,
        igmp_proxy_page_logged_in: IgmpProxyPage,
        step_recorder: StepRecorder,
        backend_verifier: Optional[BackendVerifier],
        config: Config,
    ):
        page = igmp_proxy_page_logged_in
        rec = step_recorder
        failures = []
        cleanup_failures = []
        suffix = secrets.token_hex(4)

        client_iface = os.getenv(
            "IGMP_CLIENT_IFACE", DEFAULT_CLIENT_IFACE
        ).strip()
        client_ip = os.getenv("IGMP_CLIENT_IP", DEFAULT_CLIENT_IP).strip()
        upstream = os.getenv("IGMP_UPSTREAM", DEFAULT_UPSTREAM).strip()
        downstream = os.getenv("IGMP_DOWNSTREAM", DEFAULT_DOWNSTREAM).strip()
        group = os.getenv("IGMP_GROUP", DEFAULT_GROUP).strip()
        port = int(os.getenv("IGMP_PORT", str(DEFAULT_PORT)))
        wan_host = os.getenv("IGMP_WAN_HOST", DEFAULT_WAN_HOST).strip()
        wan_source_ip = os.getenv(
            "IGMP_WAN_SOURCE_IP", wan_host or DEFAULT_WAN_SOURCE_IP
        ).strip()
        wan_username = os.getenv(
            "IGMP_WAN_USERNAME", config.ssh.client.username
        )
        wan_password = os.getenv(
            "IGMP_WAN_PASSWORD", config.ssh.client.password
        )
        wan_port = int(os.getenv("IGMP_WAN_PORT", str(config.ssh.client.port)))

        remote_dir = f"/tmp/ikuai-igmp-{suffix}"
        capture_dir = f"/tmp/ikuai-igmp-capture-{suffix}"
        receiver_path = f"{remote_dir}/receiver.py"
        sender_path = f"{remote_dir}/sender.py"

        client: Optional[SSHClient] = None
        wan_sender: Optional[SSHClient] = None
        original_ui_config: Optional[Dict] = None
        original_backend_config: Optional[Dict] = None

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

        def stop_capture(stage: str) -> str:
            wan_pid_path = f"{capture_dir}/{stage}-{upstream}.pid"
            lan_pid_path = f"{capture_dir}/{stage}-{downstream}.pid"
            wan_pcap_path = f"{capture_dir}/{stage}-{upstream}.pcap"
            lan_pcap_path = f"{capture_dir}/{stage}-{downstream}.pcap"
            return router_exec(
                f"test ! -f {shlex.quote(wan_pid_path)} || "
                f"kill -INT $(cat {shlex.quote(wan_pid_path)}) "
                "2>/dev/null || true; "
                f"test ! -f {shlex.quote(lan_pid_path)} || "
                f"kill -INT $(cat {shlex.quote(lan_pid_path)}) "
                "2>/dev/null || true; "
                "sleep 1; "
                f"echo '[{upstream}]'; "
                f"tcpdump -n -r {shlex.quote(wan_pcap_path)} -A 2>&1 || true; "
                f"echo '[{downstream}]'; "
                f"tcpdump -n -r {shlex.quote(lan_pcap_path)} -A 2>&1 || true",
                timeout=12,
            )

        def stop_client_capture(stage: str) -> str:
            pid_path = f"{remote_dir}/{stage}-client-igmp.pid"
            pcap_path = f"{remote_dir}/{stage}-client-igmp.pcap"
            _, output = client_exec(
                f"test ! -f {shlex.quote(pid_path)} || "
                f"sudo -n kill -INT $(cat {shlex.quote(pid_path)}) "
                "2>/dev/null || true; "
                "sleep 1; "
                f"sudo -n tcpdump -n -r {shlex.quote(pcap_path)} "
                "-vv 2>&1 || true",
                timeout=12,
            )
            return output

        def run_multicast_probe(
            stage: str, version_label: str, expect_receive: bool
        ) -> bool:
            token = f"IKUAI_IGMP_{stage.upper()}_{suffix}"
            ready_path = f"{remote_dir}/{stage}.ready"
            result_path = f"{remote_dir}/{stage}.json"
            log_path = f"{remote_dir}/{stage}.receiver.log"
            pid_path = f"{remote_dir}/{stage}.pid"
            wan_pcap_path = f"{capture_dir}/{stage}-{upstream}.pcap"
            lan_pcap_path = f"{capture_dir}/{stage}-{downstream}.pcap"
            wan_capture_pid = f"{capture_dir}/{stage}-{upstream}.pid"
            lan_capture_pid = f"{capture_dir}/{stage}-{downstream}.pid"
            capture_output = ""
            client_capture_output = ""

            try:
                filter_expression = (
                    f"igmp or (udp and dst host {group} and dst port {port})"
                )
                rc, capture_start = router_exec_rc(
                    f"mkdir -p {shlex.quote(capture_dir)}; "
                    "start-stop-daemon -S -b -m "
                    f"-p {shlex.quote(wan_capture_pid)} "
                    "-x /usr/sbin/tcpdump -- "
                    f"-U -n -i {shlex.quote(upstream)} -s 0 -c 160 "
                    f"-w {shlex.quote(wan_pcap_path)} "
                    f"{shlex.quote(filter_expression)}; "
                    "start-stop-daemon -S -b -m "
                    f"-p {shlex.quote(lan_capture_pid)} "
                    "-x /usr/sbin/tcpdump -- "
                    f"-U -n -i {shlex.quote(downstream)} -s 0 -c 160 "
                    f"-w {shlex.quote(lan_pcap_path)} "
                    f"{shlex.quote(filter_expression)}; "
                    "sleep 1; "
                    f"kill -0 $(cat {shlex.quote(wan_capture_pid)}) "
                    "2>/dev/null && "
                    f"kill -0 $(cat {shlex.quote(lan_capture_pid)}) 2>/dev/null",
                    timeout=12,
                )
                require(
                    f"{version_label}抓包诊断启动",
                    rc == 0,
                    capture_start
                    or f"DUT {upstream}/{downstream} -> 双接口pcap",
                )

                client_capture_path = (
                    f"{remote_dir}/{stage}-client-igmp.pcap"
                )
                client_capture_pid = (
                    f"{remote_dir}/{stage}-client-igmp.pid"
                )
                rc, client_capture_start = client_exec(
                    f"rm -f {shlex.quote(client_capture_path)} "
                    f"{shlex.quote(client_capture_pid)}; "
                    "nohup sudo -n tcpdump -U -n "
                    f"-i {shlex.quote(client_iface)} -s 0 "
                    f"-w {shlex.quote(client_capture_path)} igmp "
                    "> /dev/null 2>&1 < /dev/null & "
                    f"echo $! > {shlex.quote(client_capture_pid)}; "
                    "sleep 1; "
                    f"sudo -n kill -0 $(cat {shlex.quote(client_capture_pid)}) "
                    "2>/dev/null",
                    timeout=12,
                )
                require(
                    f"{version_label}客户端IGMP抓包启动",
                    rc == 0,
                    client_capture_start
                    or f"{client_iface} -> {client_capture_path}",
                )

                rc, receiver_start = client_exec(
                    f"rm -f {shlex.quote(ready_path)} "
                    f"{shlex.quote(result_path)} {shlex.quote(log_path)}; "
                    f"nohup python3 {shlex.quote(receiver_path)} "
                    f"--group {shlex.quote(group)} --port {port} "
                    f"--interface-ip {shlex.quote(client_ip)} "
                    f"--token {shlex.quote(token)} --timeout 6 "
                    f"--minimum {MIN_RECEIVED_PACKETS} "
                    f"--ready-file {shlex.quote(ready_path)} "
                    f"--result-file {shlex.quote(result_path)} > "
                    f"{shlex.quote(log_path)} 2>&1 < /dev/null & "
                    f"echo $! > {shlex.quote(pid_path)}",
                    timeout=12,
                )
                require(
                    f"{version_label}内网组播接收器启动",
                    rc == 0,
                    receiver_start or f"{client_ip}:{port} join {group}",
                )

                def receiver_ready() -> Tuple[bool, str]:
                    rc, output = client_exec(
                        f"test -f {shlex.quote(ready_path)} && "
                        f"cat {shlex.quote(ready_path)} || "
                        f"cat {shlex.quote(log_path)} 2>/dev/null",
                        timeout=8,
                    )
                    return rc == 0 and "READY" in output, output

                ready, ready_output = _wait_for(receiver_ready, timeout=8)
                require(
                    f"{version_label}客户端已发送入组请求",
                    ready,
                    ready_output[-1200:],
                )

                # Give the downstream report time to create the upstream join.
                time.sleep(2.0)
                _, client_membership = client_exec(
                    f"ip maddr show dev {shlex.quote(client_iface)} 2>&1; "
                    "echo '[proc/net/igmp]'; cat /proc/net/igmp 2>&1"
                )
                observe(
                    f"{version_label}LAN客户端入组表",
                    "INFO",
                    client_membership[-3000:],
                )
                pre_traffic_state = router_exec(
                    "echo '[ip_mr_vif]'; cat /proc/net/ip_mr_vif 2>/dev/null; "
                    "echo '[ip_mr_cache]'; cat /proc/net/ip_mr_cache 2>/dev/null; "
                    f"echo '[{upstream} maddr]'; "
                    f"ip maddr show dev {shlex.quote(upstream)} 2>/dev/null; "
                    f"echo '[{downstream} maddr]'; "
                    f"ip maddr show dev {shlex.quote(downstream)} 2>/dev/null",
                    timeout=12,
                )
                observe(
                    f"{version_label}发流前DUT组播状态",
                    "INFO",
                    pre_traffic_state[-5000:],
                )
                rc, sender_output = sender_exec(
                    f"python3 {shlex.quote(sender_path)} "
                    f"--group {shlex.quote(group)} --port {port} "
                    f"--source-ip {shlex.quote(wan_source_ip)} "
                    f"--token {shlex.quote(token)} --count 24 --interval 0.15",
                    timeout=15,
                )
                require(
                    f"{version_label}WAN侧发送组播流",
                    rc == 0 and "SENT=24" in sender_output,
                    sender_output[-1500:],
                )
                post_traffic_state = router_exec(
                    "echo '[ip_mr_vif]'; cat /proc/net/ip_mr_vif 2>/dev/null; "
                    "echo '[ip_mr_cache]'; cat /proc/net/ip_mr_cache 2>/dev/null",
                    timeout=12,
                )
                observe(
                    f"{version_label}发流后DUT组播路由",
                    "INFO",
                    post_traffic_state[-4000:],
                )

                def receiver_finished() -> Tuple[bool, str]:
                    rc, output = client_exec(
                        f"test -f {shlex.quote(result_path)} && "
                        f"cat {shlex.quote(result_path)} || "
                        f"cat {shlex.quote(log_path)} 2>/dev/null",
                        timeout=8,
                    )
                    return rc == 0 and output.lstrip().startswith("{"), output

                finished, result_output = _wait_for(
                    receiver_finished, timeout=9, interval=0.5
                )
                require(
                    f"{version_label}接收结果已落盘",
                    finished,
                    result_output[-1800:],
                )
                result = _parse_probe_result(result_output)
                if expect_receive:
                    passed = (
                        result["received"] is True
                        and int(result["packets"]) >= MIN_RECEIVED_PACKETS
                        and token == result["token"]
                        and wan_source_ip in result["sources"]
                    )
                    record(
                        f"{version_label}真实组播转发",
                        passed,
                        f"WAN源={wan_source_ip}, 组={group}:{port}, "
                        f"LAN收到={result['packets']}包, "
                        f"来源={result['sources']}",
                    )
                else:
                    passed = (
                        result["received"] is False
                        and int(result["packets"]) == 0
                    )
                    record(
                        f"{version_label}关闭后停止转发",
                        passed,
                        f"组={group}:{port}, LAN收到={result['packets']}包",
                    )
                return passed
            finally:
                client_exec(
                    f"test ! -f {shlex.quote(pid_path)} || "
                    f"kill $(cat {shlex.quote(pid_path)}) 2>/dev/null || true",
                    timeout=8,
                )
                client_capture_output = stop_client_capture(stage)
                capture_output = stop_capture(stage)
                summary = _capture_summary(capture_output, token)
                wan_section = capture_output.partition(f"[{upstream}]")[2]
                wan_section = wan_section.partition(f"[{downstream}]")[0]
                lan_section = capture_output.partition(f"[{downstream}]")[2]
                has_wan = token in wan_section
                has_lan = token in lan_section
                client_sent_report = (
                    group in client_capture_output
                    and "report" in client_capture_output.lower()
                )
                dut_received_report = (
                    group in lan_section and "report" in lan_section.lower()
                )
                level = "INFO" if (not expect_receive or has_wan and has_lan) else "WARN"
                observe(
                    f"{version_label}DUT抓包证据",
                    level,
                    f"客户端成员报告={'已发出' if client_sent_report else '未发现'}, "
                    f"DUT下联成员报告={'收到' if dut_received_report else '未收到'}, "
                    f"WAN令牌={'有' if has_wan else '无'}, "
                    f"LAN令牌={'有' if has_lan else '无'}\n"
                    f"[客户端IGMP]\n{client_capture_output[-2500:]}\n"
                    f"[DUT双接口]\n{summary}",
                )

        def configure_and_verify(version: str):
            page.navigate_to_igmp_proxy()
            saved = page.save_config(
                enable=True,
                version=version,
                upstream=upstream,
                downstream=downstream,
            )
            require(f"UI应用{version}代理配置", saved)

            expected_version = version.replace("IGMPv", "")

            def active_config() -> Tuple[bool, str]:
                current = backend_verifier.query_igmp_proxy_config() or {}
                passed = (
                    current.get("enabled") == "yes"
                    and str(current.get("version")) == expected_version
                    and current.get("upstream") == upstream
                    and downstream in str(current.get("downstream") or "")
                )
                return passed, json.dumps(current, ensure_ascii=False)

            active, detail = _wait_for(active_config, timeout=12, interval=1)
            require(f"{version}运行配置生效", active, detail)
            process = router_exec("ps | grep igmpproxy | grep -v grep")
            require(f"{version}代理进程运行", "igmpproxy" in process, process)

        try:
            if backend_verifier is None:
                raise FunctionalAbort("SSH后台验证器不可用，无法执行真实功能测试")
            if not (1025 <= port <= 65535):
                raise FunctionalAbort(f"IGMP_PORT越界: {port}")
            if not client_iface or not re.fullmatch(r"[A-Za-z0-9_.:-]+", client_iface):
                raise FunctionalAbort(f"IGMP_CLIENT_IFACE无效: {client_iface}")
            if not upstream or not re.fullmatch(r"[A-Za-z0-9_.:-]+", upstream):
                raise FunctionalAbort(f"IGMP_UPSTREAM无效: {upstream}")
            if not downstream or not re.fullmatch(r"[A-Za-z0-9_.:-]+", downstream):
                raise FunctionalAbort(f"IGMP_DOWNSTREAM无效: {downstream}")

            for name, address in (
                ("IGMP_CLIENT_IP", client_ip),
                ("IGMP_WAN_HOST", wan_host),
                ("IGMP_WAN_SOURCE_IP", wan_source_ip),
                ("IGMP_GROUP", group),
            ):
                parsed = ipaddress.ip_address(address)
                if parsed.version != 4:
                    raise FunctionalAbort(f"{name}必须是IPv4地址: {address}")
            if ipaddress.ip_address(group) not in ipaddress.ip_network("239.0.0.0/8"):
                raise FunctionalAbort(
                    f"IGMP_GROUP必须使用239.0.0.0/8管理域地址: {group}"
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

            page.navigate_to_igmp_proxy()
            original_ui_config = page.get_current_config()
            original_backend_config = backend_verifier.query_igmp_proxy_config()

            with rec.step(
                "测试环境校验",
                "确认DUT、WAN组播源、LAN接收端、接口地址和标准Python工具",
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
                    f"ip -4 -o addr show dev {shlex.quote(client_iface)} 2>&1"
                )
                require(
                    "LAN组播接收接口地址",
                    rc == 0
                    and bool(
                        re.search(
                            rf"\binet\s+{re.escape(client_ip)}/\d+\b",
                            client_address,
                        )
                    ),
                    client_address,
                )
                rc, sender_route = sender_exec(
                    f"ip route get {shlex.quote(DUT_MANAGEMENT_IP)} "
                    f"from {shlex.quote(wan_source_ip)} 2>&1"
                )
                require(
                    "WAN组播源与DUT直连",
                    rc == 0
                    and (
                        f"src {wan_source_ip}" in sender_route
                        or f"from {wan_source_ip}" in sender_route
                    )
                    and " via " not in f" {sender_route} ",
                    sender_route,
                )
                rc, client_tools = client_exec(
                    "command -v python3; command -v base64; "
                    "command -v tcpdump; sudo -n true"
                )
                require(
                    "LAN客户端Python3/base64/tcpdump/sudo可用",
                    rc == 0
                    and "python3" in client_tools
                    and "base64" in client_tools
                    and "tcpdump" in client_tools,
                    client_tools,
                )
                rc, sender_tools = sender_exec(
                    "command -v python3; command -v base64"
                )
                require(
                    "WAN发送端Python3/base64可用",
                    rc == 0 and "python3" in sender_tools and "base64" in sender_tools,
                    sender_tools,
                )
                tcpdump = router_exec("command -v tcpdump 2>/dev/null")
                require("DUT抓包工具可用", "tcpdump" in tcpdump, tcpdump)
                require(
                    "可读取原始IGMP配置",
                    bool(original_ui_config)
                    and bool(original_backend_config)
                    and bool(original_ui_config.get("version"))
                    and bool(original_ui_config.get("upstream"))
                    and bool(original_ui_config.get("downstream")),
                    f"UI={original_ui_config}, 后台={original_backend_config}",
                )

                rc, upload_output = _upload_text(
                    client, receiver_path, RECEIVER_SCRIPT
                )
                require("下发LAN组播接收脚本", rc == 0, upload_output)
                rc, upload_output = _upload_text(
                    wan_sender, sender_path, SENDER_SCRIPT
                )
                require("下发WAN组播发送脚本", rc == 0, upload_output)
                observe(
                    "本轮组播参数",
                    "INFO",
                    f"{wan_source_ip} -> {group}:{port} -> "
                    f"{client_ip}/{client_iface}",
                )

            with rec.step(
                "IGMPv3真实组播转发",
                "通过UI启用wan1到lan1代理并验证WAN令牌到达LAN接收socket",
            ):
                configure_and_verify("IGMPv3")
                run_multicast_probe("v3", "IGMPv3", expect_receive=True)

            with rec.step(
                "IGMPv2真实组播转发",
                "切换协议版本后重新入组并验证真实组播流仍可转发",
            ):
                configure_and_verify("IGMPv2")
                run_multicast_probe("v2", "IGMPv2", expect_receive=True)

            with rec.step(
                "关闭态阻断验证",
                "通过UI关闭代理，确认相同WAN组播流不再到达LAN",
            ):
                page.navigate_to_igmp_proxy()
                require("UI关闭IGMP代理", page.save_config(enable=False))

                def inactive_config() -> Tuple[bool, str]:
                    current = backend_verifier.query_igmp_proxy_config() or {}
                    process = router_exec("ps | grep igmpproxy | grep -v grep")
                    passed = current.get("enabled") == "no" and not process.strip()
                    return passed, f"配置={current}, 进程={process or '未运行'}"

                inactive, detail = _wait_for(
                    inactive_config, timeout=12, interval=1
                )
                require("代理配置和进程均已关闭", inactive, detail)
                time.sleep(2.0)
                run_multicast_probe(
                    "disabled", "关闭态", expect_receive=False
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
                "停止远端进程、删除临时文件并恢复测试前IGMP代理配置",
            ):
                if client is not None:
                    rc, output = client_exec(
                        f"for pidfile in {shlex.quote(remote_dir)}/*.pid; do "
                        "[ -e \"$pidfile\" ] || continue; "
                        "sudo -n kill $(cat \"$pidfile\") 2>/dev/null || "
                        "kill $(cat \"$pidfile\") 2>/dev/null || true; done; "
                        f"rm -rf {shlex.quote(remote_dir)}",
                        timeout=12,
                    )
                    if rc != 0:
                        cleanup_failures.append(
                            f"LAN临时文件清理失败: {output[-800:]}"
                        )
                if wan_sender is not None:
                    rc, output = sender_exec(
                        f"rm -rf {shlex.quote(remote_dir)}", timeout=10
                    )
                    if rc != 0:
                        cleanup_failures.append(
                            f"WAN临时文件清理失败: {output[-800:]}"
                        )
                if backend_verifier is not None:
                    try:
                        router_exec(
                            f"for pidfile in {shlex.quote(capture_dir)}/*.pid; do "
                            "[ -e \"$pidfile\" ] || continue; "
                            "kill -INT $(cat \"$pidfile\") 2>/dev/null || true; done; "
                            f"rm -rf {shlex.quote(capture_dir)}",
                            timeout=12,
                        )
                    except Exception as exc:
                        cleanup_failures.append(f"DUT抓包清理异常: {exc}")

                if original_ui_config and backend_verifier is not None:
                    try:
                        version = original_ui_config.get("version")
                        original_upstream = original_ui_config.get("upstream")
                        original_downstream = original_ui_config.get("downstream")
                        original_enabled = bool(
                            original_ui_config.get("enabled")
                        )
                        page.navigate_to_igmp_proxy()
                        restored = page.save_config(
                            enable=True,
                            version=version,
                            upstream=original_upstream,
                            downstream=original_downstream,
                        )
                        if restored and not original_enabled:
                            page.navigate_to_igmp_proxy()
                            restored = page.save_config(enable=False)
                        if not restored:
                            cleanup_failures.append("测试前IGMP页面配置恢复失败")
                        else:
                            current = (
                                backend_verifier.query_igmp_proxy_config() or {}
                            )
                            expected_enabled = "yes" if original_enabled else "no"
                            expected_version = str(
                                (original_backend_config or {}).get("version", "")
                            )
                            if (
                                current.get("enabled") != expected_enabled
                                or str(current.get("version", ""))
                                != expected_version
                                or current.get("upstream")
                                != (original_backend_config or {}).get("upstream")
                                or str(current.get("downstream", ""))
                                != str(
                                    (original_backend_config or {}).get(
                                        "downstream", ""
                                    )
                                )
                            ):
                                cleanup_failures.append(
                                    "IGMP后台配置未精确恢复: "
                                    f"期望={original_backend_config}, 实际={current}"
                                )
                    except Exception as exc:
                        cleanup_failures.append(f"IGMP原配置恢复异常: {exc}")

                if cleanup_failures:
                    for item in cleanup_failures:
                        rec.add_detail(f"  [FAIL] {item}")
                else:
                    rec.add_detail("  [OK] 测试环境已恢复")

            if wan_sender is not None:
                wan_sender.close()
            if client is not None:
                client.close()

        all_failures = failures + cleanup_failures
        assert not all_failures, "IGMP代理真实功能测试失败:\n- " + "\n- ".join(
            all_failures
        )
