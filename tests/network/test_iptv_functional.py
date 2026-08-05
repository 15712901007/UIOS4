"""IPTV port and VLAN passthrough real data-plane verification.

Default topology::

    10.66.0.57/source namespace/enp6s0 VLAN100
                         |
                 managed L2 switch
                         |
                  DUT veth5.100
                         |
                    iptv bridge
                         |
             port mode: DUT veth3 (untagged)
             VLAN mode: DUT veth3.200 (tagged)
                         |
                 managed L2 switch
                         |
    10.66.0.57/receiver namespace/enp6s0[.200]

Two network namespaces and independent macvlan interfaces prevent Linux from
short-circuiting the source and receiver locally. The endpoints use a private
test subnet plus per-run multicast tokens. A disabled-state probe first proves
there is no switch bypass. The enabled probes then require bidirectional
ARP/IP connectivity, payload delivery, exact DUT bridge members, and the
expected VLAN tags in captures.
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
from pages.network.iptv_page import IptvPage
from utils.backend_verifier import BackendVerifier, SSHClient
from utils.step_recorder import StepRecorder


DUT_MANAGEMENT_IP = "10.66.0.45"
DEFAULT_SOURCE_HOST = "10.66.0.57"
DEFAULT_SOURCE_PARENT = "enp6s0"
DEFAULT_RECEIVER_HOST = "10.66.0.57"
DEFAULT_RECEIVER_PARENT = "enp6s0"
DEFAULT_INPUT_PORT = "veth5(wan1)"
DEFAULT_OUTPUT_PORT = "veth3(wan3)"
DEFAULT_DUT_INPUT = "veth5"
DEFAULT_DUT_OUTPUT = "veth3"


def _expected_dut_management_ip() -> str:
    """Return the explicitly approved DUT target for this destructive test."""
    return os.getenv("IPTV_DUT_MANAGEMENT_IP", DUT_MANAGEMENT_IP).strip()


def _single_bridge_member(output: str, bridge: str) -> str:
    members = [line.strip() for line in (output or "").splitlines() if line.strip()]
    if len(members) != 1:
        raise ValueError(f"{bridge} expected one member, got {members}")
    return members[0]
DEFAULT_WAN_VLAN = 100
DEFAULT_LAN_VLAN = 200
DEFAULT_SOURCE_IP = "198.18.45.2"
DEFAULT_RECEIVER_IP = "198.18.45.3"
DEFAULT_PREFIX = 24
DEFAULT_GROUP = "239.148.66.47"
DEFAULT_PORT = 46347
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

    result = {
        "received": False,
        "packets": 0,
        "sources": [],
        "samples": [],
        "group": args.group,
        "port": args.port,
        "token": args.token,
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", args.port))
        membership = (
            socket.inet_aton(args.group) + socket.inet_aton(args.interface_ip)
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.settimeout(0.5)
        with open(args.ready_file, "w", encoding="ascii") as stream:
            stream.write("READY")

        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline and result["packets"] < args.minimum:
            try:
                payload, source = sock.recvfrom(65535)
            except socket.timeout:
                continue
            decoded = payload.decode("utf-8", errors="replace")
            if args.token not in decoded:
                continue
            result["packets"] += 1
            result["sources"].append(source[0])
            result["samples"].append(decoded[:200])
        result["received"] = result["packets"] >= args.minimum
        try:
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, membership
            )
        except OSError:
            pass
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        # A setup failure must still unblock the controller.
        with open(args.ready_file, "w", encoding="ascii") as stream:
            stream.write("ERROR")
    finally:
        sock.close()

    with open(args.result_file, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=True, sort_keys=True)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True), flush=True)
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
        f"TARGET={args.group}:{args.port} TOKEN={args.token}",
        flush=True,
    )
    """
).strip()


class FunctionalAbort(RuntimeError):
    """Stop dependent stages while preserving the cleanup path."""


def _exec_with_rc(
    ssh: SSHClient, command: str, timeout: int = 20
) -> Tuple[int, str]:
    """Execute a remote command and retain its shell exit status."""
    marker = "__IPTV_TEST_RC__="
    wrapped = (
        f"{command}\n"
        "__iptv_test_rc=$?\n"
        f"printf '\\n{marker}%s\\n' \"$__iptv_test_rc\""
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
    """Poll a condition and preserve its final diagnostic detail."""
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
    """Parse a receiver result while rejecting incomplete output."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        raise ValueError("IPTV receiver returned no output")
    data = json.loads(lines[-1])
    required = {
        "received",
        "packets",
        "sources",
        "samples",
        "group",
        "port",
        "token",
        "error",
    }
    missing = required.difference(data)
    if missing:
        raise ValueError(f"IPTV receiver result missing fields: {sorted(missing)}")
    return data


def _capture_summary(output: str, token: str) -> str:
    """Keep tag, IGMP, token, and packet-counter evidence for the report."""
    useful = []
    for line in output.splitlines():
        lowered = line.lower()
        if (
            token in line
            or "vlan " in lowered
            or "802.1q" in lowered
            or "igmp" in lowered
            or "packets captured" in lowered
        ):
            useful.append(line)
    return "\n".join(useful[-120:])[-8000:] if useful else output[-3000:]


def _capture_contract(
    mode: str,
    captures: Dict[str, str],
    token: str,
    dut_input: str = DEFAULT_DUT_INPUT,
    dut_output: str = DEFAULT_DUT_OUTPUT,
    wan_vlan: int = DEFAULT_WAN_VLAN,
    lan_vlan: int = DEFAULT_LAN_VLAN,
) -> Tuple[bool, str]:
    """Validate token traversal and the mode-specific output VLAN contract."""
    required = [dut_input, f"{dut_input}.{wan_vlan}", dut_output]
    if mode == "vlan":
        required.append(f"{dut_output}.{lan_vlan}")
    missing_tokens = [name for name in required if token not in captures.get(name, "")]
    input_tagged = bool(
        re.search(
            rf"\bvlan {wan_vlan}\b",
            captures.get(dut_input, ""),
            re.IGNORECASE,
        )
    )
    output_text = captures.get(dut_output, "")
    if mode == "port":
        output_tag_ok = not re.search(
            rf"\bvlan {lan_vlan}\b", output_text, re.IGNORECASE
        )
        expected = (
            f"{dut_input}带VLAN{wan_vlan}，"
            f"{dut_output}无VLAN{lan_vlan}标签"
        )
    else:
        output_tag_ok = bool(
            re.search(rf"\bvlan {lan_vlan}\b", output_text, re.IGNORECASE)
        )
        expected = (
            f"{dut_input}带VLAN{wan_vlan}，"
            f"{dut_output}带VLAN{lan_vlan}"
        )
    passed = not missing_tokens and input_tagged and output_tag_ok
    detail = (
        f"期望={expected}, 缺少令牌接口={missing_tokens or '无'}, "
        f"输入VLAN{wan_vlan}={'有' if input_tagged else '无'}, "
        f"输出标签={'符合' if output_tag_ok else '不符合'}"
    )
    return passed, detail


@pytest.mark.iptv
@pytest.mark.network
@pytest.mark.p0
class TestIptvFunctional:
    """Validate real L2 and multicast forwarding in both IPTV modes."""

    def test_iptv_real_passthrough(
        self,
        iptv_page_logged_in: IptvPage,
        step_recorder: StepRecorder,
        backend_verifier: Optional[BackendVerifier],
        config: Config,
    ):
        page = iptv_page_logged_in
        rec = step_recorder
        failures = []
        cleanup_failures = []
        suffix = secrets.token_hex(4)

        source_host = os.getenv(
            "IPTV_SOURCE_HOST", DEFAULT_SOURCE_HOST
        ).strip()
        source_parent = os.getenv(
            "IPTV_SOURCE_PARENT", DEFAULT_SOURCE_PARENT
        ).strip()
        source_username = os.getenv(
            "IPTV_SOURCE_USERNAME", config.ssh.client.username
        )
        source_password = os.getenv(
            "IPTV_SOURCE_PASSWORD", config.ssh.client.password
        )
        source_port = int(
            os.getenv("IPTV_SOURCE_PORT", str(config.ssh.client.port))
        )
        receiver_host = os.getenv(
            "IPTV_RECEIVER_HOST", DEFAULT_RECEIVER_HOST
        ).strip()
        receiver_parent = os.getenv(
            "IPTV_RECEIVER_PARENT", DEFAULT_RECEIVER_PARENT
        ).strip()
        receiver_username = os.getenv(
            "IPTV_RECEIVER_USERNAME", config.ssh.client.username
        )
        receiver_password = os.getenv(
            "IPTV_RECEIVER_PASSWORD", config.ssh.client.password
        )
        receiver_port = int(
            os.getenv("IPTV_RECEIVER_PORT", str(config.ssh.client.port))
        )
        input_port_override = os.getenv("IPTV_INPUT_PORT", "").strip()
        output_port_override = os.getenv("IPTV_OUTPUT_PORT", "").strip()
        dut_input_override = os.getenv("IPTV_DUT_INPUT", "").strip()
        dut_output_override = os.getenv("IPTV_DUT_OUTPUT", "").strip()
        input_port = input_port_override or DEFAULT_INPUT_PORT
        output_port = output_port_override or DEFAULT_OUTPUT_PORT
        dut_input = dut_input_override or DEFAULT_DUT_INPUT
        dut_output = dut_output_override or DEFAULT_DUT_OUTPUT
        wan_vlan = int(os.getenv("IPTV_WAN_VLAN", str(DEFAULT_WAN_VLAN)))
        lan_vlan = int(os.getenv("IPTV_LAN_VLAN", str(DEFAULT_LAN_VLAN)))
        source_ip = os.getenv("IPTV_SOURCE_IP", DEFAULT_SOURCE_IP).strip()
        receiver_ip = os.getenv("IPTV_RECEIVER_IP", DEFAULT_RECEIVER_IP).strip()
        prefix = int(os.getenv("IPTV_TEST_PREFIX", str(DEFAULT_PREFIX)))
        group = os.getenv("IPTV_GROUP", DEFAULT_GROUP).strip()
        stream_port = int(os.getenv("IPTV_PORT", str(DEFAULT_PORT)))

        source_namespace = f"itvsrc-{suffix}"
        receiver_namespace = f"itvrx-{suffix}"
        source_host_iface = f"is{suffix}"
        receiver_host_iface = f"ir{suffix}"
        receiver_vlan_host_iface = f"iv{suffix}"
        receiver_root_iface = "itvrx"
        source_vlan_iface = f"itvs{wan_vlan}"
        receiver_vlan_iface = f"itvr{lan_vlan}"
        source_mac = (
            f"02:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}:"
            f"{suffix[6:8]}:01"
        )
        receiver_vlan_mac = (
            f"02:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}:"
            f"{suffix[6:8]}:02"
        )
        source_cidr = f"{source_ip}/{prefix}"
        receiver_cidr = f"{receiver_ip}/{prefix}"
        remote_dir = f"/tmp/ikuai-iptv-{suffix}"
        capture_dir = f"/tmp/ikuai-iptv-capture-{suffix}"
        sender_path = f"{remote_dir}/sender.py"
        receiver_path = f"{remote_dir}/receiver.py"

        source: Optional[SSHClient] = None
        receiver: Optional[SSHClient] = None
        original_ui: Optional[Dict] = None
        original_backend: Optional[Dict] = None
        source_prepared = False
        receiver_prepared = False

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

        def source_exec(command: str, timeout: int = 20) -> Tuple[int, str]:
            assert source is not None
            return _exec_with_rc(source, command, timeout)

        def receiver_exec(command: str, timeout: int = 20) -> Tuple[int, str]:
            assert receiver is not None
            return _exec_with_rc(receiver, command, timeout)

        def source_netns_exec(
            command: str, timeout: int = 20
        ) -> Tuple[int, str]:
            return source_exec(
                f"sudo -n ip netns exec {shlex.quote(source_namespace)} "
                f"sh -c {shlex.quote(command)}",
                timeout,
            )

        def receiver_netns_exec(
            command: str, timeout: int = 20
        ) -> Tuple[int, str]:
            return receiver_exec(
                f"sudo -n ip netns exec {shlex.quote(receiver_namespace)} "
                f"sh -c {shlex.quote(command)}",
                timeout,
            )

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

        def move_receiver_address(tagged: bool):
            target = receiver_vlan_iface if tagged else receiver_root_iface
            other = receiver_root_iface if tagged else receiver_vlan_iface
            rc, output = receiver_netns_exec(
                f"ip addr del {shlex.quote(receiver_cidr)} dev "
                f"{shlex.quote(other)} 2>/dev/null || true; "
                f"ip addr replace {shlex.quote(receiver_cidr)} dev "
                f"{shlex.quote(target)}; "
                f"ip link set {shlex.quote(target)} up; "
                f"ip neigh flush dev {shlex.quote(target)} 2>/dev/null || true; "
                f"ip -4 -o addr show dev {shlex.quote(target)}",
                timeout=12,
            )
            require(
                f"接收地址切换到{target}",
                rc == 0 and receiver_ip in output,
                output,
            )

        def clear_neighbors(receiver_iface: str):
            source_netns_exec(
                f"ip neigh flush dev {shlex.quote(source_vlan_iface)} "
                "2>/dev/null || true"
            )
            receiver_netns_exec(
                f"ip neigh flush dev {shlex.quote(receiver_iface)} "
                "2>/dev/null || true"
            )

        def ping_probe(expect_connected: bool, receiver_iface: str, label: str):
            clear_neighbors(receiver_iface)
            src_rc, src_out = source_netns_exec(
                f"ping -n -I {shlex.quote(source_vlan_iface)} -c 4 -W 1 "
                f"{shlex.quote(receiver_ip)}",
                timeout=10,
            )
            rx_rc, rx_out = receiver_netns_exec(
                f"ping -n -I {shlex.quote(receiver_iface)} -c 4 -W 1 "
                f"{shlex.quote(source_ip)}",
                timeout=10,
            )
            if expect_connected:
                passed = src_rc == 0 and rx_rc == 0
                detail = (
                    f"正向rc={src_rc}, 反向rc={rx_rc}\n"
                    f"[正向]\n{src_out[-1000:]}\n[反向]\n{rx_out[-1000:]}"
                )
            else:
                passed = src_rc != 0 and rx_rc != 0
                detail = f"正向rc={src_rc}, 反向rc={rx_rc}"
            record(label, passed, detail)
            return passed

        def wait_iptv_state(
            enabled: bool, mode: int, expected_members: Iterable[str]
        ) -> Tuple[bool, str]:
            wanted = set(expected_members)

            def probe() -> Tuple[bool, str]:
                current = backend_verifier.query_iptv_config() or {}
                member_text = router_exec(
                    "ls /sys/class/net/iptv/brif 2>/dev/null"
                )
                members = set(member_text.split())
                passed = (
                    current.get("enabled") == ("yes" if enabled else "no")
                    and (not enabled or int(current.get("mode", -1)) == mode)
                    and (wanted.issubset(members) if enabled else not members)
                )
                return passed, (
                    f"配置={json.dumps(current, ensure_ascii=False)}, "
                    f"bridge成员={sorted(members)}"
                )

            return _wait_for(probe, timeout=12, interval=1)

        def configure_iptv(mode: str, enabled: bool = True):
            page.navigate_to_iptv()
            kwargs = {
                "enable": enabled,
                "mode": "网口透传" if mode == "port" else "vlan透传",
                "input_port": input_port,
                "wan_vlan_id": str(wan_vlan),
                "output_port": output_port,
            }
            if mode == "vlan":
                kwargs["lan_vlan_id"] = str(lan_vlan)
            require(
                f"UI配置{'网口' if mode == 'port' else 'VLAN'}透传",
                page.save_config(**kwargs),
            )
            members = [f"{dut_input}.{wan_vlan}"]
            members.append(
                dut_output if mode == "port" else f"{dut_output}.{lan_vlan}"
            )
            active, detail = wait_iptv_state(
                enabled=True, mode=0 if mode == "port" else 1,
                expected_members=members,
            )
            require("IPTV配置和桥接成员生效", active, detail)
            vlan_state = router_exec(
                f"ip -d link show {shlex.quote(dut_input + '.' + str(wan_vlan))}; "
                + (
                    f"ip -d link show {shlex.quote(dut_output + '.' + str(lan_vlan))}"
                    if mode == "vlan" else
                    f"ip -d link show {shlex.quote(dut_output)}"
                )
            )
            require(
                "DUT子接口运行态",
                f"{dut_input}.{wan_vlan}" in vlan_state
                and (
                    mode == "port" or f"{dut_output}.{lan_vlan}" in vlan_state
                ),
                vlan_state[-3000:],
            )

        def disable_iptv():
            page.navigate_to_iptv()
            require("UI关闭IPTV透传", page.save_config(enable=False))
            inactive, detail = wait_iptv_state(False, 0, [])
            require("IPTV桥接成员已清理", inactive, detail)

        def start_capture(
            stage: str,
            interfaces: Iterable[str],
            capture_filter: Optional[str] = None,
        ):
            commands = [f"mkdir -p {shlex.quote(capture_dir)}"]
            checks = []
            if capture_filter is None:
                capture_filter = (
                    f"(udp and dst host {group} and dst port {stream_port}) or "
                    f"(vlan and udp and dst host {group} and dst port {stream_port}) "
                    "or igmp or (vlan and igmp)"
                )
            for interface in dict.fromkeys(interfaces):
                pid_path = f"{capture_dir}/{stage}-{interface}.pid"
                pcap_path = f"{capture_dir}/{stage}-{interface}.pcap"
                commands.append(
                    "start-stop-daemon -S -b -m "
                    f"-p {shlex.quote(pid_path)} -x /usr/sbin/tcpdump -- "
                    f"-U -n -i {shlex.quote(interface)} -s 0 -c 300 "
                    f"-w {shlex.quote(pcap_path)}"
                    + (
                        f" {shlex.quote(capture_filter)}"
                        if capture_filter else ""
                    )
                )
                checks.append(
                    f"kill -0 $(cat {shlex.quote(pid_path)}) 2>/dev/null"
                )
            commands.extend(["sleep 1", " && ".join(checks)])
            rc, output = router_exec_rc("; ".join(commands), timeout=12)
            require(
                f"{stage} DUT多点抓包启动",
                rc == 0,
                output or ",".join(interfaces),
            )

        def stop_capture(stage: str, interfaces: Iterable[str]) -> Dict[str, str]:
            captures = {}
            for interface in dict.fromkeys(interfaces):
                pid_path = f"{capture_dir}/{stage}-{interface}.pid"
                pcap_path = f"{capture_dir}/{stage}-{interface}.pcap"
                captures[interface] = router_exec(
                    f"test ! -f {shlex.quote(pid_path)} || "
                    f"kill -INT $(cat {shlex.quote(pid_path)}) "
                    "2>/dev/null || true; sleep 1; "
                    f"tcpdump -e -nn -r {shlex.quote(pcap_path)} -A 2>&1 || true",
                    timeout=12,
                )
            return captures

        def start_endpoint_capture(stage: str):
            pid_path = f"{remote_dir}/{stage}-parent.pid"
            pcap_path = f"{remote_dir}/{stage}-parent.pcap"
            log_path = f"{remote_dir}/{stage}-parent.log"
            rc, output = receiver_exec(
                f"sudo -n rm -f {shlex.quote(pid_path)} "
                f"{shlex.quote(pcap_path)} {shlex.quote(log_path)}; "
                "sudo -n start-stop-daemon -S -b -m "
                f"-p {shlex.quote(pid_path)} -x /usr/bin/tcpdump -- "
                f"-U -Q in -n -e -i {shlex.quote(receiver_parent)} "
                f"-s 0 -c 5000 -w {shlex.quote(pcap_path)} "
                f"{shlex.quote('ether multicast')}; "
                "sleep 1; "
                f"sudo -n kill -0 $(cat {shlex.quote(pid_path)})",
                timeout=12,
            )
            require(f"{stage} .57物理口入方向抓包启动", rc == 0, output)

        def stop_endpoint_capture(stage: str) -> str:
            pid_path = f"{remote_dir}/{stage}-parent.pid"
            pcap_path = f"{remote_dir}/{stage}-parent.pcap"
            _, output = receiver_exec(
                f"test ! -f {shlex.quote(pid_path)} || "
                f"sudo -n kill -INT $(cat {shlex.quote(pid_path)}) "
                "2>/dev/null || true; sleep 1; "
                f"test ! -f {shlex.quote(pcap_path)} || "
                f"sudo -n tcpdump -e -nn -r {shlex.quote(pcap_path)} "
                "-A 2>&1 || true",
                timeout=15,
            )
            return output

        def run_multicast_probe(
            stage: str,
            label: str,
            mode: str,
            expect_receive: bool,
            capture_interfaces: Iterable[str],
        ) -> Dict:
            token = f"IKUAI_IPTV_{stage.upper()}_{suffix}"
            ready_path = f"{remote_dir}/{stage}.ready"
            result_path = f"{remote_dir}/{stage}.json"
            log_path = f"{remote_dir}/{stage}.log"
            pid_path = f"{remote_dir}/{stage}.pid"
            interfaces = list(capture_interfaces)
            captures = {}
            endpoint_capture = ""
            start_capture(stage, interfaces)
            start_endpoint_capture(stage)
            try:
                rc, output = receiver_netns_exec(
                    f"rm -f {shlex.quote(ready_path)} {shlex.quote(result_path)} "
                    f"{shlex.quote(log_path)} {shlex.quote(pid_path)}; "
                    f"nohup python3 {shlex.quote(receiver_path)} "
                    f"--group {shlex.quote(group)} --port {stream_port} "
                    f"--interface-ip {shlex.quote(receiver_ip)} "
                    f"--token {shlex.quote(token)} --timeout 6 "
                    f"--minimum {MIN_RECEIVED_PACKETS} "
                    f"--ready-file {shlex.quote(ready_path)} "
                    f"--result-file {shlex.quote(result_path)} > "
                    f"{shlex.quote(log_path)} 2>&1 < /dev/null & "
                    f"echo $! > {shlex.quote(pid_path)}",
                    timeout=10,
                )
                require(f"{label}接收器启动", rc == 0, output)

                def receiver_ready() -> Tuple[bool, str]:
                    ready_rc, ready_output = receiver_exec(
                        f"test -f {shlex.quote(ready_path)} && "
                        f"cat {shlex.quote(ready_path)} || "
                        f"cat {shlex.quote(log_path)} 2>/dev/null",
                        timeout=8,
                    )
                    return (
                        ready_rc == 0 and "READY" in ready_output,
                        ready_output,
                    )

                ready, marker_output = _wait_for(
                    receiver_ready, timeout=8, interval=0.5
                )
                require(f"{label}接收器就绪", ready, marker_output[-1000:])

                rc, sender_output = source_netns_exec(
                    f"python3 {shlex.quote(sender_path)} "
                    f"--group {shlex.quote(group)} --port {stream_port} "
                    f"--source-ip {shlex.quote(source_ip)} "
                    f"--token {shlex.quote(token)} --count 24 --interval 0.15",
                    timeout=12,
                )
                require(
                    f"{label}源端发送",
                    rc == 0 and "SENT=24" in sender_output,
                    sender_output,
                )

                def result_ready() -> Tuple[bool, str]:
                    rc, result_output = receiver_exec(
                        f"test -f {shlex.quote(result_path)} && "
                        f"cat {shlex.quote(result_path)} || "
                        f"cat {shlex.quote(log_path)} 2>/dev/null",
                        timeout=8,
                    )
                    return rc == 0 and result_output.lstrip().startswith("{"), result_output

                finished, result_output = _wait_for(
                    result_ready, timeout=9, interval=0.5
                )
                require(f"{label}接收结果生成", finished, result_output[-1600:])
                result = _parse_probe_result(result_output)
                if expect_receive:
                    passed = (
                        result["received"] is True
                        and int(result["packets"]) >= MIN_RECEIVED_PACKETS
                        and source_ip in result["sources"]
                        and result["token"] == token
                    )
                    record(
                        f"{label}真实组播透传",
                        passed,
                        f"{source_ip} -> {group}:{stream_port}, "
                        f"接收={result['packets']}包, 来源={result['sources']}",
                    )
                else:
                    passed = (
                        result["received"] is False
                        and int(result["packets"]) == 0
                    )
                    record(
                        f"{label}关闭态阻断",
                        passed,
                        f"接收={result['packets']}包, error={result['error'] or '无'}",
                    )
                return result
            finally:
                receiver_netns_exec(
                    f"test ! -f {shlex.quote(pid_path)} || "
                    f"kill $(cat {shlex.quote(pid_path)}) 2>/dev/null || true",
                    timeout=8,
                )
                captures = stop_capture(stage, interfaces)
                endpoint_capture = stop_endpoint_capture(stage)
                combined = "\n".join(
                    f"[{name}]\n{_capture_summary(value, token)}"
                    for name, value in captures.items()
                )
                observe(f"{label}DUT抓包证据", "INFO", combined)
                observe(
                    f"{label}.57物理口入方向证据",
                    "INFO",
                    _capture_summary(endpoint_capture, token),
                )
                if expect_receive:
                    contract_ok, contract_detail = _capture_contract(
                        mode,
                        captures,
                        token,
                        dut_input=dut_input,
                        dut_output=dut_output,
                        wan_vlan=wan_vlan,
                        lan_vlan=lan_vlan,
                    )
                    record(f"{label}VLAN封装路径", contract_ok, contract_detail)

        def verify_input_trunk():
            stage = "input_vlan_preflight"
            captures = {}
            sender_output = ""
            start_capture(stage, [dut_input], capture_filter="")
            try:
                _, sender_output = source_netns_exec(
                    f"ping -n -I {shlex.quote(source_vlan_iface)} "
                    f"-c 4 -W 1 {shlex.quote(receiver_ip)} || true",
                    timeout=10,
                )
            finally:
                captures = stop_capture(stage, [dut_input])

            capture_text = captures.get(dut_input, "")
            evidence = _capture_summary(capture_text, source_ip)
            require(
                f"源端VLAN{wan_vlan} ARP前置发包",
                "PING" in sender_output and source_ip in sender_output,
                sender_output,
            )
            arrived = source_ip in capture_text and bool(
                re.search(
                    rf"\bvlan {wan_vlan}\b",
                    capture_text,
                    re.IGNORECASE,
                )
            ) and "ARP" in capture_text.upper()
            require(
                f"VLAN{wan_vlan}已到达DUT {dut_input}",
                arrived,
                f"{evidence}\n" if arrived else (
                    f"{evidence}\nDUT未抓到带VLAN{wan_vlan}的ARP广播；"
                    f"请确认交换机GE16和DUT wan1所接端口均以Tagged方式"
                    f"放行VLAN{wan_vlan}，Native/PVID保持VLAN1"
                ),
            )
            observe("输入Trunk抓包证据", "INFO", evidence)

        def restore_original_config():
            if original_ui is None or original_backend is None:
                return
            current = backend_verifier.query_iptv_config() or {}
            keys = (
                "enabled", "mode", "wan_iface", "wan_vlanid",
                "lan_iface", "lan_vlanid",
            )
            if all(str(current.get(key)) == str(original_backend.get(key)) for key in keys):
                return

            original_enabled = bool(original_ui.get("enabled"))
            original_input = str(original_ui.get("input_port") or "")
            original_output = str(original_ui.get("output_port") or "")
            original_mode_text = str(original_ui.get("mode") or "")
            original_mode = (
                "vlan透传" if "vlan" in original_mode_text.lower() else "网口透传"
            )
            if original_input and original_output:
                page.navigate_to_iptv()
                restored = page.save_config(
                    enable=True,
                    mode=original_mode,
                    input_port=original_input,
                    wan_vlan_id=str(original_ui.get("wan_vlan_id") or "0"),
                    output_port=original_output,
                    lan_vlan_id=(
                        str(original_ui.get("lan_vlan_id") or "0")
                        if original_mode == "vlan透传" else None
                    ),
                )
                if not restored:
                    cleanup_failures.append("IPTV原配置字段恢复失败")
            if not original_enabled:
                page.navigate_to_iptv()
                if not page.save_config(enable=False):
                    cleanup_failures.append("IPTV原关闭状态恢复失败")

            def restored_probe() -> Tuple[bool, str]:
                actual = backend_verifier.query_iptv_config() or {}
                passed = all(
                    str(actual.get(key)) == str(original_backend.get(key))
                    for key in keys
                )
                return passed, json.dumps(actual, ensure_ascii=False)

            restored, detail = _wait_for(restored_probe, timeout=10, interval=1)
            if not restored:
                cleanup_failures.append(
                    f"IPTV后台配置未精确恢复: 期望={original_backend}, 实际={detail}"
                )

        try:
            if backend_verifier is None:
                raise FunctionalAbort("SSH后台验证器不可用，无法执行真实功能测试")
            expected_dut = _expected_dut_management_ip()
            if (
                config.device.ip != expected_dut
                or config.ssh.router.host != expected_dut
            ):
                raise FunctionalAbort(
                    f"IPTV_DUT_MANAGEMENT_IP显式目标为{expected_dut}: "
                    f"UI={config.device.ip}, SSH={config.ssh.router.host}"
                )
            for name in (
                source_parent, receiver_parent, input_port, output_port,
                dut_input, dut_output,
            ):
                if not name or not re.fullmatch(r"[A-Za-z0-9_.():-]+", name):
                    raise FunctionalAbort(f"接口或端口名称无效: {name}")
            for name, address in (
                ("IPTV_SOURCE_IP", source_ip),
                ("IPTV_RECEIVER_IP", receiver_ip),
                ("IPTV_SOURCE_HOST", source_host),
                ("IPTV_RECEIVER_HOST", receiver_host),
                ("IPTV_GROUP", group),
            ):
                if ipaddress.ip_address(address).version != 4:
                    raise FunctionalAbort(f"{name}必须为IPv4地址: {address}")
            if ipaddress.ip_address(group) not in ipaddress.ip_network("239.0.0.0/8"):
                raise FunctionalAbort(f"IPTV_GROUP必须使用239.0.0.0/8: {group}")
            if not (1 <= wan_vlan <= 4094 and 1 <= lan_vlan <= 4094):
                raise FunctionalAbort(
                    f"VLAN ID越界: wan={wan_vlan}, lan={lan_vlan}"
                )
            if not (1025 <= stream_port <= 65535):
                raise FunctionalAbort(f"IPTV_PORT越界: {stream_port}")

            source = SSHClient(
                SSHHostConfig(
                    host=source_host,
                    username=source_username,
                    password=source_password,
                    port=source_port,
                )
            )
            source.connect()
            receiver = SSHClient(
                SSHHostConfig(
                    host=receiver_host,
                    username=receiver_username,
                    password=receiver_password,
                    port=receiver_port,
                )
            )
            receiver.connect()
            backend_verifier.connect_router()

            if not dut_input_override:
                rc, output = router_exec_rc(
                    "ls -1 /sys/class/net/wan1/brif 2>/dev/null", timeout=10
                )
                try:
                    dut_input = _single_bridge_member(output, "wan1")
                except ValueError as exc:
                    raise FunctionalAbort(str(exc)) from exc
                if rc != 0:
                    raise FunctionalAbort(f"wan1 member query failed: {output}")
            if not dut_output_override:
                rc, output = router_exec_rc(
                    "ls -1 /sys/class/net/wan3/brif 2>/dev/null", timeout=10
                )
                try:
                    dut_output = _single_bridge_member(output, "wan3")
                except ValueError as exc:
                    raise FunctionalAbort(str(exc)) from exc
                if rc != 0:
                    raise FunctionalAbort(f"wan3 member query failed: {output}")
            if not input_port_override:
                input_port = f"{dut_input}(wan1)"
            if not output_port_override:
                output_port = f"{dut_output}(wan3)"

            page.navigate_to_iptv()
            original_ui = page.get_current_config()
            original_backend = backend_verifier.query_iptv_config()
            if not original_backend:
                raise FunctionalAbort("无法读取IPTV原始后台配置")

            with rec.step(
                "测试环境校验与准备",
                "在10.66.0.57的Trunk口创建隔离源/接收namespace并校验VLAN100输入",
            ):
                rc, source_state = source_exec(
                    f"ip -4 -o addr show dev {shlex.quote(source_parent)}; "
                    "ip netns list; "
                    f"ip link show {shlex.quote(source_host_iface)} 2>/dev/null; "
                    f"ip -4 -o addr show | grep -F {shlex.quote(source_ip)}; "
                    "command -v python3; command -v base64; command -v tcpdump; "
                    "sudo -n true",
                    timeout=12,
                )
                require(
                    "源端Trunk接口和工具",
                    rc == 0
                    and source_host in source_state
                    and "python3" in source_state
                    and source_namespace not in source_state
                    and source_host_iface not in source_state
                    and source_ip not in source_state,
                    source_state,
                )
                rc, receiver_state = receiver_exec(
                    f"ip -4 -o addr show dev {shlex.quote(receiver_parent)}; "
                    "ip netns list; "
                    f"ip link show {shlex.quote(receiver_host_iface)} 2>/dev/null; "
                    f"ip link show {shlex.quote(receiver_vlan_host_iface)} 2>/dev/null; "
                    f"ip -4 -o addr show | grep -F {shlex.quote(receiver_ip)}; "
                    "command -v python3; command -v base64; command -v tcpdump; "
                    "sudo -n true",
                    timeout=12,
                )
                require(
                    "接收端Trunk接口和工具",
                    rc == 0
                    and receiver_host in receiver_state
                    and "python3" in receiver_state
                    and receiver_namespace not in receiver_state
                    and receiver_host_iface not in receiver_state
                    and receiver_vlan_host_iface not in receiver_state
                    and receiver_ip not in receiver_state,
                    receiver_state,
                )
                dut_state = router_exec(
                    f"ip link show {shlex.quote(dut_input)}; "
                    f"ip link show {shlex.quote(dut_output)}; command -v tcpdump"
                )
                require(
                    "DUT输入输出口和抓包工具",
                    dut_input in dut_state
                    and dut_output in dut_state
                    and "tcpdump" in dut_state,
                    dut_state,
                )

                rc, output = source_exec(
                    f"sudo -n ip netns add {shlex.quote(source_namespace)}; "
                    f"sudo -n ip link add link {shlex.quote(source_parent)} "
                    f"name {shlex.quote(source_host_iface)} type vlan id {wan_vlan}; "
                    f"sudo -n ip link set {shlex.quote(source_host_iface)} "
                    f"address {shlex.quote(source_mac)}; "
                    f"sudo -n ip link set {shlex.quote(source_host_iface)} "
                    f"netns {shlex.quote(source_namespace)}; "
                    f"sudo -n ip -n {shlex.quote(source_namespace)} link set lo up; "
                    f"sudo -n ip -n {shlex.quote(source_namespace)} link set "
                    f"{shlex.quote(source_host_iface)} name {shlex.quote(source_vlan_iface)}; "
                    f"sudo -n ip -n {shlex.quote(source_namespace)} addr add "
                    f"{shlex.quote(source_cidr)} dev {shlex.quote(source_vlan_iface)}; "
                    f"sudo -n ip -n {shlex.quote(source_namespace)} link set "
                    f"{shlex.quote(source_vlan_iface)} up; "
                    f"sudo -n ip netns exec {shlex.quote(source_namespace)} "
                    f"ip -d link show {shlex.quote(source_vlan_iface)}; "
                    f"sudo -n ip netns exec {shlex.quote(source_namespace)} "
                    f"ip -4 -o addr show dev {shlex.quote(source_vlan_iface)}",
                    timeout=12,
                )
                source_prepared = (
                    source_vlan_iface in output and source_ip in output
                )
                require(
                    f"建立隔离源端namespace和VLAN{wan_vlan}",
                    rc == 0
                    and source_prepared
                    and source_ip in output
                    and f"id {wan_vlan}" in output,
                    output,
                )

                rc, output = receiver_exec(
                    f"sudo -n ip netns add {shlex.quote(receiver_namespace)}; "
                    f"sudo -n ip link add {shlex.quote(receiver_host_iface)} "
                    f"link {shlex.quote(receiver_parent)} type macvlan mode bridge; "
                    f"sudo -n ip link set {shlex.quote(receiver_host_iface)} "
                    f"netns {shlex.quote(receiver_namespace)}; "
                    f"sudo -n ip link add link {shlex.quote(receiver_parent)} "
                    f"name {shlex.quote(receiver_vlan_host_iface)} "
                    f"type vlan id {lan_vlan}; "
                    f"sudo -n ip link set {shlex.quote(receiver_vlan_host_iface)} "
                    f"address {shlex.quote(receiver_vlan_mac)}; "
                    f"sudo -n ip link set {shlex.quote(receiver_vlan_host_iface)} "
                    f"netns {shlex.quote(receiver_namespace)}; "
                    f"sudo -n ip -n {shlex.quote(receiver_namespace)} link set lo up; "
                    f"sudo -n ip -n {shlex.quote(receiver_namespace)} link set "
                    f"{shlex.quote(receiver_host_iface)} name {shlex.quote(receiver_root_iface)}; "
                    f"sudo -n ip -n {shlex.quote(receiver_namespace)} link set "
                    f"{shlex.quote(receiver_root_iface)} up; "
                    f"sudo -n ip -n {shlex.quote(receiver_namespace)} link set "
                    f"{shlex.quote(receiver_vlan_host_iface)} name "
                    f"{shlex.quote(receiver_vlan_iface)}; "
                    f"sudo -n ip -n {shlex.quote(receiver_namespace)} link set "
                    f"{shlex.quote(receiver_vlan_iface)} up; "
                    f"sudo -n ip -n {shlex.quote(receiver_namespace)} addr add "
                    f"{shlex.quote(receiver_cidr)} dev {shlex.quote(receiver_root_iface)}; "
                    f"sudo -n ip netns exec {shlex.quote(receiver_namespace)} "
                    f"ip -d link show {shlex.quote(receiver_vlan_iface)}; "
                    f"sudo -n ip netns exec {shlex.quote(receiver_namespace)} "
                    f"ip -4 -o addr show dev {shlex.quote(receiver_root_iface)}",
                    timeout=12,
                )
                receiver_prepared = (
                    receiver_vlan_iface in output and receiver_ip in output
                )
                require(
                    f"建立隔离接收端及VLAN{lan_vlan}",
                    rc == 0
                    and receiver_prepared
                    and receiver_ip in output
                    and f"id {lan_vlan}" in output,
                    output,
                )

                for ssh, path, content, label in (
                    (source, sender_path, SENDER_SCRIPT, "源端发送脚本"),
                    (receiver, receiver_path, RECEIVER_SCRIPT, "接收端探针脚本"),
                ):
                    rc, output = _upload_text(ssh, path, content)
                    require(f"下发{label}", rc == 0, output)
                observe(
                    "本轮拓扑",
                    "INFO",
                    f"{source_host}/{source_namespace}/{source_parent}."
                    f"{wan_vlan}({source_ip}) "
                    f"-> DUT {dut_input}.{wan_vlan}/iptv/{dut_output} "
                    f"-> {receiver_host}/{receiver_namespace}/"
                    f"{receiver_parent}[.{lan_vlan}]({receiver_ip})",
                )
                verify_input_trunk()

            with rec.step(
                "关闭态无旁路基线",
                "关闭IPTV并确认源端不能绕过DUT到达接收端",
            ):
                if page.is_enabled():
                    disable_iptv()
                else:
                    inactive, detail = wait_iptv_state(False, 0, [])
                    require("IPTV初始关闭且无桥接成员", inactive, detail)
                ping_probe(False, receiver_root_iface, "关闭态双向隔离")
                run_multicast_probe(
                    "baseline_disabled", "关闭态基线", "port", False,
                    [dut_input, dut_output],
                )

            with rec.step(
                "网口透传真实数据面",
                "验证VLAN100输入到wan3无标签输出及双向二层通信",
            ):
                configure_iptv("port")
                ping_probe(True, receiver_root_iface, "网口透传双向通信")
                run_multicast_probe(
                    "port_enabled", "网口透传", "port", True,
                    [dut_input, f"{dut_input}.{wan_vlan}", dut_output],
                )

            with rec.step(
                "网口透传关闭阻断",
                "关闭网口透传后确认相同物理路径不再转发",
            ):
                disable_iptv()
                ping_probe(False, receiver_root_iface, "网口透传关闭后隔离")
                run_multicast_probe(
                    "port_disabled", "网口透传关闭后", "port", False,
                    [dut_input, dut_output],
                )

            with rec.step(
                "VLAN透传真实数据面",
                "将接收地址切换到VLAN200并验证100到200标签转换",
            ):
                move_receiver_address(tagged=True)
                configure_iptv("vlan")
                ping_probe(True, receiver_vlan_iface, "VLAN透传双向通信")
                run_multicast_probe(
                    "vlan_enabled", "VLAN透传", "vlan", True,
                    [
                        dut_input, f"{dut_input}.{wan_vlan}",
                        dut_output, f"{dut_output}.{lan_vlan}",
                    ],
                )

            with rec.step(
                "VLAN透传关闭阻断",
                "关闭VLAN透传后确认VLAN200接收端不再收到业务流",
            ):
                disable_iptv()
                ping_probe(False, receiver_vlan_iface, "VLAN透传关闭后隔离")
                run_multicast_probe(
                    "vlan_disabled", "VLAN透传关闭后", "vlan", False,
                    [dut_input, dut_output],
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
                "恢复原IPTV配置并删除10.66.0.57上的临时namespace和测试文件",
            ):
                if backend_verifier is not None and original_backend is not None:
                    try:
                        restore_original_config()
                    except Exception as exc:
                        cleanup_failures.append(f"IPTV原配置恢复异常: {exc}")

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

                if receiver is not None:
                    rc, output = receiver_exec(
                        f"for pidfile in {shlex.quote(remote_dir)}/*.pid; do "
                        "[ -e \"$pidfile\" ] || continue; "
                        "sudo -n kill $(cat \"$pidfile\") 2>/dev/null || true; done; "
                        f"sudo -n ip netns del {shlex.quote(receiver_namespace)} "
                        "2>/dev/null || true; "
                        f"sudo -n ip link del {shlex.quote(receiver_host_iface)} "
                        "2>/dev/null || true; "
                        f"sudo -n ip link del {shlex.quote(receiver_vlan_host_iface)} "
                        "2>/dev/null || true; "
                        f"rm -rf {shlex.quote(remote_dir)}; "
                        "ip netns list; "
                        f"ip link show {shlex.quote(receiver_host_iface)} "
                        "2>/dev/null || true; "
                        f"ip link show {shlex.quote(receiver_vlan_host_iface)} "
                        "2>/dev/null || true",
                        timeout=15,
                    )
                    if (
                        rc != 0
                        or receiver_namespace in output
                        or receiver_host_iface in output
                        or receiver_vlan_host_iface in output
                    ):
                        cleanup_failures.append(
                            f"接收namespace未清理干净: rc={rc}, {output[-800:]}"
                        )

                if source is not None:
                    rc, output = source_exec(
                        f"sudo -n ip netns del {shlex.quote(source_namespace)} "
                        "2>/dev/null || true; "
                        f"sudo -n ip link del {shlex.quote(source_host_iface)} "
                        "2>/dev/null || true; "
                        f"rm -rf {shlex.quote(remote_dir)}; "
                        "ip netns list; "
                        f"ip link show {shlex.quote(source_host_iface)} "
                        "2>/dev/null || true",
                        timeout=15,
                    )
                    if (
                        rc != 0
                        or source_namespace in output
                        or source_host_iface in output
                    ):
                        cleanup_failures.append(
                            f"源namespace未清理干净: rc={rc}, {output[-800:]}"
                        )

                if cleanup_failures:
                    for item in cleanup_failures:
                        rec.add_detail(f"  [FAIL] {item}")
                else:
                    rec.add_detail("  [OK] DUT与10.66.0.57均已恢复测试前状态")

            if receiver is not None:
                receiver.close()
            if source is not None:
                source.close()

        all_failures = failures + cleanup_failures
        assert not all_failures, "IPTV真实功能测试失败:\n- " + "\n- ".join(
            all_failures
        )
