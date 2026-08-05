"""DHCP静态绑定L5验证动作的离线回归测试。"""

from types import SimpleNamespace

from utils.backend_verifier import BackendVerifier


def _verifier(client, router=None):
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._ssh_config = SimpleNamespace()
    verifier._client = client
    verifier._router = router
    verifier.connect_client = lambda: None
    verifier.connect_router = lambda: None
    return verifier


class _TopologyClient:
    def __init__(self, gateway_mac):
        self.gateway_mac = gateway_mac
        self.commands = []

    def exec(self, command, timeout=30):
        self.commands.append(command)
        if command.startswith("ip neigh show"):
            return (
                "192.168.148.1 dev testlan lladdr "
                f"{self.gateway_mac} REACHABLE"
            )
        return ""


class _TopologyRouter:
    def __init__(self, lan_mac):
        self.lan_mac = lan_mac
        self.commands = []

    def exec(self, command, timeout=30):
        self.commands.append(command)
        if command.startswith("ip -4 -o addr show"):
            return "lan1\n"
        if command.startswith("cat /sys/class/net/lan1/address"):
            return self.lan_mac
        return ""


def test_gateway_topology_accepts_matching_router_lan_mac():
    mac = "02:11:22:33:44:55"
    client = _TopologyClient(mac)
    router = _TopologyRouter(mac.upper())
    verifier = _verifier(client, router)

    result = verifier.verify_client_gateway_matches_router(
        "192.168.148.1",
        client_iface="testlan",
    )

    assert result.passed is True
    assert result.details["router_iface"] == "lan1"
    assert result.details["client_gateway_mac"] == mac
    assert any(command.startswith("ping ") for command in client.commands)


def test_gateway_topology_rejects_wrong_target_router():
    client = _TopologyClient("02:11:22:33:44:55")
    router = _TopologyRouter("02:11:22:33:44:66")
    verifier = _verifier(client, router)

    result = verifier.verify_client_gateway_matches_router(
        "192.168.148.1",
        client_iface="testlan",
    )

    assert result.passed is False
    assert "测试环境错配" in result.message


class _RenewClient:
    def __init__(self, acquired_ip="192.168.148.70"):
        self.acquired_ip = acquired_ip
        self.transitioned = False
        self.commands = []

    def exec(self, command, timeout=30):
        self.commands.append(command)
        if command.startswith("ip -4 -o addr show"):
            ip = self.acquired_ip if self.transitioned else "192.168.148.2"
            return f"2: testlan inet {ip}/24 scope global dynamic testlan"
        if command.startswith("cat /sys/class/net/testlan/ifindex"):
            return "2\n"
        if command.startswith("set +e;"):
            assert "networkctl down testlan" in command
            assert "networkctl up testlan" in command
            assert "/run/systemd/netif/leases/2" in command
            assert "/run/systemd/netif/leases/*" not in command
            self.transitioned = True
            return "DOWN_RC=0 ADDRESS_CLEARED=1 UP_RC=0\n"
        if command.startswith("ip route show default"):
            return (
                "default via 192.168.148.1 proto dhcp "
                f"src {self.acquired_ip} metric 200"
            )
        if command.startswith("cat /run/systemd/netif/leases/2"):
            return f"ADDRESS={self.acquired_ip}\nSERVER_ADDRESS=192.168.148.1\n"
        return ""


def test_networkd_renew_requires_address_clear_and_recreated_lease():
    client = _RenewClient()
    verifier = _verifier(client)

    result = verifier.renew_client_dhcp(
        "testlan",
        expected_ip="192.168.148.70",
        timeout=5,
    )

    assert result.passed is True
    assert result.details["old_ips"] == ["192.168.148.2"]
    assert result.details["address_cleared"] is True
    assert result.details["new_ip"] == "192.168.148.70"
    assert result.details["lease_ip"] == "192.168.148.70"


def test_networkd_renew_rejects_a_valid_but_wrong_dhcp_address():
    client = _RenewClient(acquired_ip="192.168.148.2")
    verifier = _verifier(client)

    result = verifier.renew_client_dhcp(
        "testlan",
        expected_ip="192.168.148.70",
        timeout=5,
    )

    assert result.passed is False
    assert "与期望" in result.message


def test_static_runtime_check_rejects_same_mac_with_stale_ip():
    mac = "02:11:22:33:44:55"

    class RuntimeRouter:
        def exec(self, command, timeout=30):
            if command.startswith("cat "):
                return f"lan1 192.168.148.2 {mac}\n"
            return ""

    verifier = _verifier(_RenewClient(), RuntimeRouter())

    result = verifier.verify_dhcp_static_config_file(
        ip="192.168.148.70",
        mac=mac,
        expect_in_conf=True,
    )

    assert result.passed is False
    assert "不含192.168.148.70" in result.message
