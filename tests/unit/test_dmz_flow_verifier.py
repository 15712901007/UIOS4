from utils.backend_verifier import BackendVerifier


class _State:
    packets = 7
    rule_present = True
    increment_on_curl = True


class _Router:
    def __init__(self, state):
        self.state = state
        self.commands = []

    def exec(self, command, timeout=None):
        self.commands.append(command)
        if command.startswith("iptables -t nat -L NETNAT"):
            header = (
                "num pkts bytes ccnt fcnt fastid target proto opt in out "
                "source destination\n"
            )
            if not self.state.rule_present:
                return header
            return (
                header
                + f"1 {self.state.packets} 420 0 0 0 NETMAP all -- * * "
                  "0.0.0.0/0 0.0.0.0/0 ifname match wan3 "
                  "to:192.168.148.2\n"
            )
        return ""


class _Client:
    def __init__(self, state):
        self.state = state
        self.commands = []

    def exec(self, command, timeout=None):
        self.commands.append(command)
        if command.startswith("curl ") and self.state.increment_on_curl:
            self.state.packets += 1
        return ""


def _verifier(state):
    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = _Router(state)
    verifier._client = _Client(state)
    verifier.connect_router = lambda: None
    verifier.connect_client = lambda: None
    return verifier


def test_dmz_netmap_counter_increment_is_primary_data_plane_evidence():
    state = _State()
    state.packets = 7
    state.rule_present = True
    state.increment_on_curl = True
    verifier = _verifier(state)

    result = verifier.verify_dmz_netmap_counter_increment(
        "10.66.0.49", "15201", "192.168.148.2",
        wan_interface="wan3", source_ip="10.66.0.18",
    )

    assert result.passed
    assert "匹配+3包" in result.message
    assert "--interface 10.66.0.18" in verifier._client.commands[0]


def test_dmz_netmap_counter_increment_fails_when_rule_does_not_match():
    state = _State()
    state.rule_present = False
    verifier = _verifier(state)

    result = verifier.verify_dmz_netmap_counter_increment(
        "10.66.0.49", "15201", "192.168.148.2",
        wan_interface="wan3", source_ip="10.66.0.18",
    )

    assert not result.passed
    assert "未找到精确NETMAP规则" in result.message
    assert verifier._client.commands == []


def test_dmz_netmap_counter_increment_fails_without_packet_delta():
    state = _State()
    state.packets = 9
    state.rule_present = True
    state.increment_on_curl = False
    verifier = _verifier(state)

    result = verifier.verify_dmz_netmap_counter_increment(
        "10.66.0.49", "15201", "192.168.148.2",
        wan_interface="wan3", source_ip="10.66.0.18",
    )

    assert not result.passed
    assert "计数无增量" in result.message


def test_dnat_conntrack_prefers_tool_and_accepts_protocol_at_line_start():
    class Router:
        def __init__(self):
            self.commands = []

        def exec(self, command, timeout=None):
            self.commands.append(command)
            if command.startswith("conntrack -L"):
                return (
                    "tcp 6 4 SYN_SENT src=10.66.0.18 dst=10.66.0.49 "
                    "sport=57026 dport=15201 src=192.168.148.2 "
                    "dst=10.66.0.18 sport=15201 dport=57026\n"
                )
            raise AssertionError(f"unexpected fallback command: {command}")

    verifier = BackendVerifier.__new__(BackendVerifier)
    verifier._router = Router()
    verifier.connect_router = lambda: None

    result = verifier.verify_dnat_conntrack(
        "10.66.0.49", "15201", "192.168.148.2", "15201"
    )

    assert result.passed
    assert verifier._router.commands == ["conntrack -L -p tcp 2>/dev/null"]
