"""UPnP真实功能测试。

拓扑:
    10.66.0.18/ens11(192.168.148.2) -> DUT LAN1(192.168.148.1)
    10.66.0.57                      -> DUT WAN1(10.66.0.45)/WAN3(10.66.0.49)

测试通过Web UI创建临时授权规则并开启UPnP，由LAN客户端的标准miniupnpc
发起IGD端口映射，再从独立WAN主机访问映射后的端口。测试结束会删除动态
映射、临时HTTP服务和授权规则，并恢复测试前的UPnP开关状态。

环境变量可覆盖:
    UPNP_WAN_HOST / UPNP_WAN_USERNAME / UPNP_WAN_PASSWORD / UPNP_WAN_PORT
    UPNP_INTERNAL_PORT / UPNP_EXTERNAL_PORT
    UPNP_RULE_LINE=wan1 / UPNP_DEFAULT_LINE=any|wan1|wan2|wan3
    UPNP_EXPECTED_EXTERNAL_IP / UPNP_PROBE_TARGET_IP
    UPNP_ALLOW_DISCONNECTED_IGD=true  # 仅验证真实数据面时允许设备误报Disconnected
"""

import ipaddress
import os
import re
import secrets
import shlex
import time
from typing import Callable, Optional, Tuple

import pytest

from config.config import Config, SSHHostConfig
from pages.network.upnp_setting_page import UpnpSettingPage
from utils.backend_verifier import BackendVerifier, SSHClient
from utils.step_recorder import StepRecorder


CLIENT_SSH_HOST = "10.66.0.18"
CLIENT_IFACE = "ens11"
CLIENT_IP = "192.168.148.2"
ROUTER_LAN_IP = "192.168.148.1"
DUT_MANAGEMENT_IP = "10.66.0.45"
DEFAULT_EXTERNAL_IP = "10.66.0.45"
DEFAULT_WAN_PROBE_HOST = "10.66.0.57"
DENIED_EXTERNAL_PORT = 500
UPNP_CONTROL_URL = f"http://{ROUTER_LAN_IP}:1900/ctl/IPConn"
WAN_INTERFACE_IPS = {
    "wan1": "10.66.0.45",
    "wan2": "192.168.112.106",
    "wan3": "10.66.0.49",
}


class FunctionalAbort(RuntimeError):
    """停止后续数据面步骤，但仍执行finally清理。"""


def _exec_with_rc(
    ssh: SSHClient, command: str, timeout: int = 20
) -> Tuple[int, str]:
    """执行远程命令，并从stdout中取回shell退出码。"""
    marker = "__UPNP_TEST_RC__="
    wrapped = (
        f"{command}\n"
        "__upnp_test_rc=$?\n"
        f"printf '\\n{marker}%s\\n' \"$__upnp_test_rc\""
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
    """轮询远程状态，返回最后一次证据。"""
    deadline = time.monotonic() + timeout
    last_detail = ""
    while time.monotonic() < deadline:
        passed, last_detail = probe()
        if passed:
            return True, last_detail
        time.sleep(interval)
    return False, last_detail


def _reports_disconnected_igd(output: str) -> bool:
    """识别miniupnpc在普通和强制继续模式下的未连接IGD提示。"""
    return bool(
        re.search(r"Status\s*:\s*Disconnected", output, re.IGNORECASE)
        or re.search(r"Found a \(not connected\?\) IGD", output, re.IGNORECASE)
        or "No valid UPNP Internet Gateway Device found" in output
    )


@pytest.mark.upnp_setting
@pytest.mark.network
@pytest.mark.p0
class TestUpnpFunctional:
    """UPnP IGD动态端口映射端到端验证。"""

    def test_upnp_real_port_mapping(
        self,
        upnp_setting_page_logged_in: UpnpSettingPage,
        step_recorder: StepRecorder,
        backend_verifier: Optional[BackendVerifier],
        config: Config,
    ):
        page = upnp_setting_page_logged_in
        rec = step_recorder
        failures = []
        cleanup_failures = []
        suffix = secrets.token_hex(3)
        rule_name = f"upnp功能{suffix}"
        description = f"ikuai-upnp-e2e-{suffix}"
        response_token = f"IKUAI_UPNP_OK_{suffix}"
        remote_dir = f"/tmp/ikuai-upnp-{suffix}"
        internal_port = int(os.getenv("UPNP_INTERNAL_PORT", "39090"))
        external_port = int(os.getenv("UPNP_EXTERNAL_PORT", "45678"))
        rule_line = os.getenv("UPNP_RULE_LINE", "wan1").strip().lower()
        requested_default_line = os.getenv(
            "UPNP_DEFAULT_LINE", ""
        ).strip().lower()
        if requested_default_line == "任意":
            requested_default_line = "any"
        expected_external_ip = os.getenv(
            "UPNP_EXPECTED_EXTERNAL_IP",
            WAN_INTERFACE_IPS.get(rule_line, DEFAULT_EXTERNAL_IP),
        ).strip()
        probe_target_ip = os.getenv(
            "UPNP_PROBE_TARGET_IP", expected_external_ip
        ).strip()
        wan_host = os.getenv("UPNP_WAN_HOST", DEFAULT_WAN_PROBE_HOST)
        wan_username = os.getenv(
            "UPNP_WAN_USERNAME", config.ssh.client.username
        )
        wan_password = os.getenv(
            "UPNP_WAN_PASSWORD", config.ssh.client.password
        )
        wan_port = int(os.getenv("UPNP_WAN_PORT", "22"))
        allow_disconnected_igd = os.getenv(
            "UPNP_ALLOW_DISCONNECTED_IGD", "false"
        ).lower() in {"1", "true", "yes"}

        client: Optional[SSHClient] = None
        wan_probe: Optional[SSHClient] = None
        original_conf = None
        mapping_created = False
        server_started = False
        added_wan_return_route = False

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

        def wan_exec(command: str, timeout: int = 20) -> Tuple[int, str]:
            assert wan_probe is not None
            return _exec_with_rc(wan_probe, command, timeout)

        def router_exec(command: str, timeout: int = 20) -> str:
            assert backend_verifier is not None
            backend_verifier.connect_router()
            return backend_verifier._router.exec(
                command, timeout=timeout, probe_console=False
            ) or ""

        def mapping_list() -> Tuple[int, str]:
            return client_exec(
                f"upnpc -i -m {shlex.quote(CLIENT_IFACE)} -l 2>&1",
                timeout=25,
            )

        def mapping_in_client_list() -> Tuple[bool, str]:
            rc, output = mapping_list()
            exists = (
                rc == 0
                and str(external_port) in output
                and f"{CLIENT_IP}:{internal_port}" in output
            )
            return exists, output[-2000:]

        def mapping_in_router_rules() -> Tuple[bool, str]:
            output = router_exec(
                "echo '[nat MINIUPNPD]'; "
                "iptables -t nat -L MINIUPNPD -n -v -x 2>/dev/null; "
                "echo '[filter MINIUPNPD]'; "
                "iptables -L MINIUPNPD -n -v -x 2>/dev/null; "
                "cat /etc/log/upnp.leases 2>/dev/null",
                timeout=15,
            )
            exists = str(external_port) in output and CLIENT_IP in output
            return exists, output[-3000:]

        def external_http_probe() -> Tuple[int, str]:
            return wan_exec(
                "curl --noproxy '*' -sS --connect-timeout 3 --max-time 6 "
                f"http://{probe_target_ip}:{external_port}/ 2>&1",
                timeout=12,
            )

        def soap_query(action: str) -> Tuple[int, str]:
            service = "urn:schemas-upnp-org:service:WANIPConnection:1"
            envelope = (
                '<?xml version="1.0"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><u:{action} xmlns:u="{service}"></u:{action}>'
                '</s:Body></s:Envelope>'
            )
            soap_action = f'SOAPAction: "{service}#{action}"'
            return client_exec(
                "curl --noproxy '*' -sS --connect-timeout 3 --max-time 8 "
                "-H 'Content-Type: text/xml; charset=utf-8' "
                f"-H {shlex.quote(soap_action)} "
                f"--data-binary {shlex.quote(envelope)} "
                f"{shlex.quote(UPNP_CONTROL_URL)} 2>&1",
                timeout=15,
            )

        try:
            if backend_verifier is None:
                raise FunctionalAbort("SSH后台验证器不可用，无法执行真实功能测试")
            if not (1025 <= internal_port <= 65535):
                raise FunctionalAbort(f"UPNP_INTERNAL_PORT越界: {internal_port}")
            if not (1025 <= external_port <= 65535):
                raise FunctionalAbort(f"UPNP_EXTERNAL_PORT越界: {external_port}")
            if rule_line not in WAN_INTERFACE_IPS:
                raise FunctionalAbort(f"UPNP_RULE_LINE不受支持: {rule_line}")
            if requested_default_line not in {"", "any", *WAN_INTERFACE_IPS}:
                raise FunctionalAbort(
                    f"UPNP_DEFAULT_LINE不受支持: {requested_default_line}"
                )
            for env_name, address in (
                ("UPNP_WAN_HOST", wan_host),
                ("UPNP_EXPECTED_EXTERNAL_IP", expected_external_ip),
                ("UPNP_PROBE_TARGET_IP", probe_target_ip),
            ):
                try:
                    parsed_address = ipaddress.ip_address(address)
                except ValueError as exc:
                    raise FunctionalAbort(
                        f"{env_name}不是有效IP地址: {address}"
                    ) from exc
                if parsed_address.version != 4:
                    raise FunctionalAbort(f"{env_name}必须是IPv4地址: {address}")

            client = SSHClient(config.ssh.client)
            client.connect()
            wan_probe = SSHClient(
                SSHHostConfig(
                    host=wan_host,
                    username=wan_username,
                    password=wan_password,
                    port=wan_port,
                )
            )
            wan_probe.connect()
            backend_verifier.connect_router()
            original_conf = backend_verifier.query_upnpd_conf()
            desired_default_line = (
                requested_default_line
                or str((original_conf or {}).get("interface") or "any")
            )

            with rec.step(
                "测试环境校验",
                "确认LAN控制点、DUT双侧地址、独立WAN探针和miniupnpc工具",
            ):
                require(
                    "UI与SSH目标一致",
                    config.device.ip == DUT_MANAGEMENT_IP
                    and config.ssh.router.host == DUT_MANAGEMENT_IP,
                    f"UI={config.device.ip}, SSH={config.ssh.router.host}",
                )
                require(
                    "LAN客户端SSH目标",
                    config.ssh.client.host == CLIENT_SSH_HOST,
                    f"实际={config.ssh.client.host}, 期望={CLIENT_SSH_HOST}",
                )
                require(
                    "WAN探针与LAN客户端分离",
                    wan_host not in {CLIENT_SSH_HOST, DUT_MANAGEMENT_IP},
                    f"WAN探针={wan_host}",
                )
                rc, addr_output = client_exec(
                    f"ip -4 -o addr show dev {shlex.quote(CLIENT_IFACE)} 2>&1"
                )
                require(
                    "LAN数据面地址",
                    rc == 0
                    and bool(
                        re.search(
                            rf"\binet\s+{re.escape(CLIENT_IP)}/\d+\b",
                            addr_output,
                        )
                    ),
                    addr_output,
                )
                rc, route_output = client_exec(
                    f"ip route get {ROUTER_LAN_IP} from {CLIENT_IP} 2>&1"
                )
                require(
                    "LAN控制路径",
                    rc == 0
                    and f"dev {CLIENT_IFACE}" in route_output
                    and (
                        f"src {CLIENT_IP}" in route_output
                        or f"from {CLIENT_IP}" in route_output
                    ),
                    route_output,
                )
                rc, sudo_output = client_exec("sudo -n true 2>&1")
                require(
                    "LAN客户端具备免交互sudo",
                    rc == 0,
                    sudo_output or f"sudo退出码={rc}",
                )
                rc, existing_return_route = client_exec(
                    f"ip -4 route show exact {wan_host}/32 2>&1"
                )
                require(
                    "可读取WAN探针回程路由",
                    rc == 0,
                    existing_return_route or f"ip route退出码={rc}",
                )
                if not existing_return_route.strip():
                    rc, add_route_output = client_exec(
                        "sudo -n ip route add "
                        f"{wan_host}/32 via {ROUTER_LAN_IP} "
                        f"dev {CLIENT_IFACE} src {CLIENT_IP} metric 5 2>&1"
                    )
                    require(
                        "临时建立WAN探针回程路由",
                        rc == 0,
                        add_route_output or f"{wan_host}/32 via {ROUTER_LAN_IP}",
                    )
                    added_wan_return_route = True
                else:
                    observe(
                        "WAN探针专用回程路由",
                        "INFO",
                        f"沿用测试前已有路由: {existing_return_route}",
                    )
                rc, return_route = client_exec(
                    f"ip route get {wan_host} from {CLIENT_IP} 2>&1"
                )
                require(
                    "WAN响应经DUT LAN口返回",
                    rc == 0
                    and f"via {ROUTER_LAN_IP}" in return_route
                    and f"dev {CLIENT_IFACE}" in return_route
                    and (
                        f"src {CLIENT_IP}" in return_route
                        or f"from {CLIENT_IP}" in return_route
                    ),
                    return_route,
                )
                _, rp_filter_output = client_exec(
                    "printf 'all='; cat /proc/sys/net/ipv4/conf/all/rp_filter; "
                    f"printf '{CLIENT_IFACE}='; "
                    f"cat /proc/sys/net/ipv4/conf/{CLIENT_IFACE}/rp_filter"
                )
                observe("LAN客户端反向路径过滤", "INFO", rp_filter_output)
                rc, wan_route = wan_exec(
                    f"ip route get {probe_target_ip} 2>&1"
                )
                require(
                    "WAN探针直连DUT",
                    rc == 0
                    and f"src {wan_host}" in wan_route
                    and " via " not in f" {wan_route} ",
                    wan_route,
                )
                rc, tool_output = client_exec(
                    "command -v upnpc 2>&1; upnpc -h 2>&1 | tail -1",
                    timeout=15,
                )
                require(
                    "标准miniupnpc客户端",
                    rc == 0 and "/upnpc" in tool_output,
                    tool_output,
                )
                require(
                    "可读取UPnP原配置",
                    bool(original_conf),
                    str(original_conf or "无配置"),
                )
                observe(
                    "本轮线路矩阵",
                    "INFO",
                    f"默认线路={desired_default_line}, 授权线路={rule_line}, "
                    f"期望外网地址={expected_external_ip}, 探测地址={probe_target_ip}",
                )
                existing = backend_verifier.find_upnpd_ifconf(rule_name)
                require(
                    "临时规则名无冲突",
                    existing is None,
                    rule_name,
                )

            with rec.step(
                "创建UPnP授权并启动服务",
                f"仅允许{CLIENT_IP}通过{rule_line}申请动态映射",
            ):
                page.navigate_to_upnp_setting()
                require(
                    "UI创建临时授权规则",
                    page.add_rule(
                        name=rule_name,
                        ips=[CLIENT_IP],
                        lines=[rule_line],
                        remark="UPnP功能临时验证",
                    ),
                    rule_name,
                )
                db_rule = backend_verifier.find_upnpd_ifconf(rule_name)
                require(
                    "授权规则写入运行配置",
                    bool(db_rule)
                    and db_rule.get("enabled") == "yes"
                    and db_rule.get("interface") == rule_line
                    and CLIENT_IP
                    in str((db_rule.get("src_addr") or {}).get("custom", [])),
                    str(db_rule or "未找到"),
                )

                if (
                    original_conf.get("enabled") != "yes"
                    or original_conf.get("interface") != desired_default_line
                ):
                    page.navigate_to_upnp_setting()
                    require("打开UPnP设置面板", page.open_settings_drawer())
                    page.set_default_line(
                        "任意" if desired_default_line == "any"
                        else desired_default_line
                    )
                    page.toggle_upnp_service(True)
                    require("通过UI应用UPnP线路并开启服务", page.save_settings())

                active_conf = backend_verifier.query_upnpd_conf() or {}
                require(
                    "UPnP默认线路与开关生效",
                    active_conf.get("enabled") == "yes"
                    and active_conf.get("interface") == desired_default_line,
                    str(active_conf),
                )

                process_ok, process_detail = _wait_for(
                    lambda: (
                        "miniupnpd" in router_exec(
                            "ps | grep miniupnpd | grep -v grep 2>/dev/null"
                        ),
                        router_exec(
                            "ps | grep miniupnpd | grep -v grep 2>/dev/null; "
                            "cat /tmp/iktmp/miniupnpd_ifname.conf 2>/dev/null"
                        ).strip(),
                    ),
                    timeout=12,
                )
                require("miniupnpd运行", process_ok, process_detail)
                runtime_interface_evidence = router_exec(
                    "echo '[generated ext_ifname]'; "
                    "grep '^ext_ifname=' /tmp/iktmp/miniupnpd.conf 2>/dev/null; "
                    "echo '[system default_route]'; "
                    "cat /tmp/iktmp/default_route 2>/dev/null; "
                    "echo '[UPnP default ifname]'; "
                    "cat /tmp/iktmp/miniupnpd_default_ifname.conf 2>/dev/null; "
                    "echo '[per-client ifname]'; "
                    "cat /tmp/iktmp/miniupnpd_ifname.conf 2>/dev/null; "
                    "echo '[generator source]'; "
                    "grep -n -E 'extif=.*default_route|ext_ifname=\\$extif' "
                    "/usr/ikuai/script/upnpd.sh 2>/dev/null; "
                    "true",
                    timeout=15,
                )
                observe(
                    "miniupnpd外网接口生成依据",
                    "INFO",
                    runtime_interface_evidence[-3000:],
                )

                rc, root_description = client_exec(
                    "curl --noproxy '*' -sS --connect-timeout 3 --max-time 8 "
                    f"http://{ROUTER_LAN_IP}:1900/rootDesc.xml 2>&1",
                    timeout=15,
                )
                require(
                    "原始HTTP读取UPnP设备描述",
                    rc == 0 and "WANIPConnection:1" in root_description,
                    root_description[-2000:],
                )
                rc, nmap_output = client_exec(
                    "sudo -n nmap -Pn -sU -p 1900 --script upnp-info "
                    f"--script-timeout 10s {ROUTER_LAN_IP} 2>&1",
                    timeout=25,
                )
                nmap_discovered = (
                    rc == 0
                    and "1900/udp" in nmap_output
                    and (
                        "UPnP" in nmap_output
                        or "InternetGatewayDevice" in nmap_output
                    )
                )
                observe(
                    "nmap独立UPnP发现",
                    "INFO" if nmap_discovered else "WARN",
                    nmap_output[-2500:],
                )

                status_rc, soap_status_output = soap_query("GetStatusInfo")
                soap_status_match = re.search(
                    r"<NewConnectionStatus>([^<]+)</NewConnectionStatus>",
                    soap_status_output,
                )
                require(
                    "原始SOAP GetStatusInfo响应",
                    status_rc == 0 and soap_status_match is not None,
                    soap_status_output[-2000:],
                )
                soap_status = soap_status_match.group(1)
                observe(
                    "原始SOAP连接状态",
                    "WARN" if soap_status.lower() == "disconnected" else "INFO",
                    soap_status_output[-2000:],
                )

                external_rc, soap_external_output = soap_query(
                    "GetExternalIPAddress"
                )
                require(
                    "原始SOAP读取所选线路外网地址",
                    external_rc == 0
                    and expected_external_ip in soap_external_output,
                    soap_external_output[-2000:],
                )

                standard_rc, standard_output = client_exec(
                    f"upnpc -m {shlex.quote(CLIENT_IFACE)} -s 2>&1",
                    timeout=25,
                )
                standard_igd_ok = (
                    standard_rc == 0
                    and f"ExternalIPAddress = {expected_external_ip}"
                    in standard_output
                )
                disconnected_reported = _reports_disconnected_igd(
                    standard_output
                )
                if standard_igd_ok:
                    record(
                        "标准客户端识别IGD为已连接",
                        True,
                        standard_output[-2000:],
                    )
                elif allow_disconnected_igd and disconnected_reported:
                    observe(
                        "标准客户端识别IGD为已连接",
                        "WARN",
                        "设备报告Disconnected；已按环境变量仅验证真实数据面。\n"
                        + standard_output[-2000:],
                    )
                else:
                    record(
                        "标准客户端识别IGD为已连接",
                        False,
                        standard_output[-2000:],
                    )

                def discovery_probe() -> Tuple[bool, str]:
                    rc, output = client_exec(
                        f"upnpc -i -m {shlex.quote(CLIENT_IFACE)} -s 2>&1",
                        timeout=25,
                    )
                    return (
                        rc == 0
                        and f"ExternalIPAddress = {expected_external_ip}" in output,
                        output[-2000:],
                    )

                discovered, discovery_output = _wait_for(
                    discovery_probe, timeout=15, interval=1
                )
                require(
                    f"忽略错误连接状态后可识别{rule_line}地址",
                    discovered,
                    discovery_output,
                )

            with rec.step(
                "准备内网服务并验证关闭态基线",
                "LAN启动临时HTTP服务，WAN映射前不得访问外部测试端口",
            ):
                start_command = (
                    f"rm -rf {shlex.quote(remote_dir)}; "
                    f"mkdir -p {shlex.quote(remote_dir)}; "
                    f"printf %s {shlex.quote(response_token)} > "
                    f"{shlex.quote(remote_dir + '/index.html')}; "
                    "nohup python3 -m http.server "
                    f"{internal_port} --bind {CLIENT_IP} "
                    f"--directory {shlex.quote(remote_dir)} "
                    f"> {shlex.quote(remote_dir + '/server.log')} 2>&1 "
                    f"< /dev/null & echo $! > {shlex.quote(remote_dir + '/server.pid')}; "
                    "true"
                )
                rc, start_output = client_exec(start_command, timeout=15)
                require(
                    "LAN临时HTTP服务进程已启动",
                    rc == 0,
                    start_output or f"监听{CLIENT_IP}:{internal_port}",
                )

                def local_http_probe() -> Tuple[bool, str]:
                    rc, output = client_exec(
                        "curl --noproxy '*' -sS --connect-timeout 1 --max-time 3 "
                        f"http://{CLIENT_IP}:{internal_port}/ 2>&1"
                    )
                    if rc == 0 and response_token in output:
                        return True, output
                    _, diagnostics = client_exec(
                        f"ss -lntp 2>/dev/null | grep ':{internal_port} ' || true; "
                        f"cat {shlex.quote(remote_dir + '/server.log')} 2>/dev/null; "
                        "test ! -f "
                        f"{shlex.quote(remote_dir + '/server.pid')} || "
                        f"ps -fp $(cat {shlex.quote(remote_dir + '/server.pid')}) "
                        "2>/dev/null || true"
                    )
                    return False, f"{output}\n{diagnostics}".strip()

                server_started, local_response = _wait_for(
                    local_http_probe, timeout=8, interval=0.5
                )
                require(
                    "LAN临时HTTP服务可用",
                    server_started,
                    local_response[-1000:],
                )
                router_lan_response = router_exec(
                    "curl --noproxy '*' -sS --connect-timeout 2 --max-time 4 "
                    f"http://{CLIENT_IP}:{internal_port}/ 2>&1"
                )
                require(
                    "DUT经LAN口可访问内网服务",
                    response_token in router_lan_response,
                    router_lan_response[-1000:],
                )

                rc, baseline_output = external_http_probe()
                require(
                    "映射前WAN访问被拒绝",
                    rc != 0 and response_token not in baseline_output,
                    baseline_output[-1000:] or f"curl退出码={rc}",
                )

            with rec.step(
                "UPnP策略拒绝验证",
                f"默认排除端口{DENIED_EXTERNAL_PORT}不得创建映射",
            ):
                rc, denied_output = client_exec(
                    f"upnpc -i -m {shlex.quote(CLIENT_IFACE)} "
                    f"-e {shlex.quote(description + '-denied')} "
                    f"-a {CLIENT_IP} {internal_port} "
                    f"{DENIED_EXTERNAL_PORT} TCP 120 2>&1",
                    timeout=25,
                )
                _, list_after_denied = mapping_list()
                denied_absent = not re.search(
                    rf"\b{DENIED_EXTERNAL_PORT}->", list_after_denied
                )
                require(
                    "排除端口映射被拒绝",
                    rc != 0 and denied_absent,
                    denied_output[-1500:],
                )

            with rec.step(
                "创建动态映射并验证运行态",
                f"TCP {probe_target_ip}:{external_port} -> {CLIENT_IP}:{internal_port}",
            ):
                rc, add_output = client_exec(
                    f"upnpc -i -m {shlex.quote(CLIENT_IFACE)} "
                    f"-e {shlex.quote(description)} "
                    f"-a {CLIENT_IP} {internal_port} {external_port} TCP 120 2>&1",
                    timeout=25,
                )
                mapping_created = rc == 0
                require("IGD AddPortMapping成功", mapping_created, add_output[-2000:])

                listed, list_output = _wait_for(
                    mapping_in_client_list, timeout=10
                )
                require("IGD可回读动态映射", listed, list_output)

                in_kernel, kernel_output = _wait_for(
                    mapping_in_router_rules, timeout=10
                )
                require(
                    "路由器动态NAT/过滤规则生效",
                    in_kernel,
                    kernel_output,
                )
                filter_ref_match = re.search(
                    r"\[filter MINIUPNPD\].*?Chain MINIUPNPD "
                    r"\((\d+) references\)",
                    kernel_output,
                    re.DOTALL,
                )
                filter_references = (
                    int(filter_ref_match.group(1)) if filter_ref_match else 0
                )
                observe(
                    "过滤链挂入转发路径",
                    "INFO" if filter_references > 0 else "WARN",
                    f"filter MINIUPNPD references={filter_references}; "
                    "是否可转发由下一步WAN真实访问裁决",
                )

            with rec.step(
                "WAN侧真实访问验证",
                f"独立Ubuntu主机经DUT {rule_line}访问LAN临时HTTP服务",
            ):
                def http_success_probe() -> Tuple[bool, str]:
                    rc, output = external_http_probe()
                    return rc == 0 and response_token in output, output

                reachable, wan_output = _wait_for(
                    http_success_probe, timeout=12, interval=1
                )
                if reachable:
                    record(
                        "WAN到LAN端口映射数据面打通",
                        True,
                        wan_output[-1500:],
                    )
                    post_traffic_evidence = router_exec(
                        "echo '[nat MINIUPNPD after WAN request]'; "
                        "iptables -t nat -L MINIUPNPD -n -v -x "
                        "--line-numbers 2>/dev/null; "
                        "echo '[conntrack after WAN request]'; "
                        f"grep -E '{wan_host}.*dport={external_port}|"
                        f"dport={external_port}.*{wan_host}' "
                        "/proc/net/nf_conntrack 2>/dev/null | tail -10; "
                        "true",
                        timeout=15,
                    )
                    observe(
                        "WAN访问后的UPnP DNAT命中证据",
                        "INFO",
                        post_traffic_evidence[-3000:],
                    )
                else:
                    diagnostics = router_exec(
                        "echo '[nat MINIUPNPD]'; "
                        "iptables -t nat -L MINIUPNPD -n -v -x "
                        "--line-numbers 2>/dev/null; "
                        "echo '[filter MINIUPNPD]'; "
                        "iptables -L MINIUPNPD -n -v -x "
                        "--line-numbers 2>/dev/null; "
                        "echo '[chain references]'; "
                        "iptables-save 2>/dev/null | grep MINIUPNPD; "
                        "echo '[FORWARD]'; "
                        "iptables -L FORWARD -n -v -x --line-numbers "
                        "2>/dev/null | head -30; "
                        "echo '[conntrack]'; "
                        f"grep -E '{wan_host}.*dport={external_port}|"
                        f"dport={external_port}.*{wan_host}' "
                        "/proc/net/nf_conntrack 2>/dev/null | tail -10; "
                        "true",
                        timeout=20,
                    )
                    _, client_diagnostics = client_exec(
                        f"echo '[route to WAN probe]'; "
                        f"ip route get {wan_host} from {CLIENT_IP} 2>&1; "
                        "echo '[rp_filter]'; "
                        "printf 'all='; cat /proc/sys/net/ipv4/conf/all/rp_filter; "
                        f"printf '{CLIENT_IFACE}='; "
                        f"cat /proc/sys/net/ipv4/conf/{CLIENT_IFACE}/rp_filter; "
                        "echo '[listening socket]'; "
                        f"ss -lntp 2>/dev/null | grep ':{internal_port} ' || true"
                    )
                    record(
                        "WAN到LAN端口映射数据面打通",
                        False,
                        f"{wan_output[-1000:]}\n"
                        f"[DUT]\n{diagnostics[-5000:]}\n"
                        f"[LAN客户端]\n{client_diagnostics[-2500:]}",
                    )

            with rec.step(
                "删除映射并验证立即失效",
                "DeletePortMapping后列表、内核规则和WAN访问均恢复关闭态",
            ):
                rc, delete_output = client_exec(
                    f"upnpc -i -m {shlex.quote(CLIENT_IFACE)} "
                    f"-d {external_port} TCP 2>&1",
                    timeout=25,
                )
                require("IGD DeletePortMapping成功", rc == 0, delete_output[-1500:])
                mapping_created = False

                def mapping_removed_from_client() -> Tuple[bool, str]:
                    exists, output = mapping_in_client_list()
                    return not exists, output

                list_removed, list_output = _wait_for(
                    mapping_removed_from_client, timeout=10
                )
                require("IGD列表已删除映射", list_removed, list_output)

                def mapping_removed_from_router() -> Tuple[bool, str]:
                    exists, output = mapping_in_router_rules()
                    return not exists, output

                kernel_removed, kernel_output = _wait_for(
                    mapping_removed_from_router, timeout=10
                )
                require(
                    "路由器动态规则已删除",
                    kernel_removed,
                    kernel_output,
                )

                def http_closed_probe() -> Tuple[bool, str]:
                    rc, output = external_http_probe()
                    return rc != 0 and response_token not in output, output

                closed, closed_output = _wait_for(
                    http_closed_probe, timeout=10, interval=1
                )
                require(
                    "删除后WAN访问立即失效",
                    closed,
                    closed_output[-1000:] or "curl连接失败（符合预期）",
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
                "删除动态映射/临时服务/临时授权规则，并恢复UPnP开关",
            ):
                if client is not None:
                    if mapping_created:
                        rc, output = client_exec(
                            f"upnpc -i -m {shlex.quote(CLIENT_IFACE)} "
                            f"-d {external_port} TCP 2>&1",
                            timeout=25,
                        )
                        if rc != 0:
                            cleanup_failures.append(
                                f"动态映射清理失败: {output[-500:]}"
                            )
                    rc, output = client_exec(
                        "test ! -f "
                        f"{shlex.quote(remote_dir + '/server.pid')} || "
                        f"kill $(cat {shlex.quote(remote_dir + '/server.pid')}) "
                        "2>/dev/null; "
                        f"rm -rf {shlex.quote(remote_dir)}",
                        timeout=12,
                    )
                    if rc != 0 and server_started:
                        cleanup_failures.append(
                            f"LAN临时服务清理失败: {output[-500:]}"
                        )
                    if added_wan_return_route:
                        rc, output = client_exec(
                            "sudo -n ip route del "
                            f"{wan_host}/32 via {ROUTER_LAN_IP} "
                            f"dev {CLIENT_IFACE} src {CLIENT_IP} metric 5 2>&1"
                        )
                        if rc != 0:
                            cleanup_failures.append(
                                f"WAN探针临时回程路由清理失败: {output[-500:]}"
                            )

                try:
                    if backend_verifier is not None:
                        residual_rule = backend_verifier.find_upnpd_ifconf(rule_name)
                    else:
                        residual_rule = None
                    if residual_rule is not None:
                        page.navigate_to_upnp_setting()
                        if not page.delete_rule(rule_name):
                            cleanup_failures.append(
                                f"临时授权规则删除失败: {rule_name}"
                            )
                except Exception as exc:
                    cleanup_failures.append(f"临时授权规则清理异常: {exc}")

                try:
                    if original_conf and backend_verifier is not None:
                        current_conf = backend_verifier.query_upnpd_conf() or {}
                        original_enabled = original_conf.get("enabled") == "yes"
                        current_enabled = current_conf.get("enabled") == "yes"
                        original_interface = (
                            str(original_conf.get("interface") or "any")
                        )
                        current_interface = (
                            str(current_conf.get("interface") or "any")
                        )
                        if (
                            current_enabled != original_enabled
                            or current_interface != original_interface
                        ):
                            page.navigate_to_upnp_setting()
                            if not page.open_settings_drawer():
                                cleanup_failures.append(
                                    "无法打开设置面板恢复UPnP线路和开关"
                                )
                            else:
                                page.set_default_line(
                                    "任意" if original_interface == "any"
                                    else original_interface
                                )
                                page.toggle_upnp_service(original_enabled)
                                if not page.save_settings():
                                    cleanup_failures.append(
                                        "UPnP线路或开关恢复失败"
                                    )
                except Exception as exc:
                    cleanup_failures.append(f"UPnP开关恢复异常: {exc}")

                if cleanup_failures:
                    for item in cleanup_failures:
                        rec.add_detail(f"  [FAIL] {item}")
                else:
                    rec.add_detail("  [OK] 测试环境已恢复")

            if wan_probe is not None:
                wan_probe.close()
            if client is not None:
                client.close()

        all_failures = failures + cleanup_failures
        assert not all_failures, "UPnP真实功能测试失败:\n- " + "\n- ".join(
            all_failures
        )
