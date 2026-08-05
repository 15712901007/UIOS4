from pathlib import Path
from types import SimpleNamespace

from tests.security.test_advanced_comprehensive import resolve_router_wan_ip


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class _RouterStub:
    def __init__(self, wan_ip):
        self.wan_ip = wan_ip
        self.command = ""

    def exec(self, command):
        self.command = command
        return self.wan_ip


class _BackendStub:
    def __init__(self, wan_ip):
        self._router = _RouterStub(wan_ip)
        self.connected = False

    def connect_router(self):
        self.connected = True


def test_advanced_wan_probe_uses_runtime_wan1_instead_of_stale_page_host():
    backend = _BackendStub("10.66.0.45\n")
    page = SimpleNamespace(base_url="http://10.66.0.150")

    target = resolve_router_wan_ip(page, backend)

    assert target == "10.66.0.45"
    assert backend.connected
    assert "addr show dev wan1" in backend._router.command


def test_advanced_wan_probe_falls_back_to_current_web_host_without_ssh():
    page = SimpleNamespace(base_url="http://10.66.0.45:8080/login")

    assert resolve_router_wan_ip(page) == "10.66.0.45"


def test_advanced_comprehensive_has_no_fixed_wan_probe_address():
    source = (
        PROJECT_ROOT / "tests/security/test_advanced_comprehensive.py"
    ).read_text(encoding="utf-8")

    assert 'ROUTER_WAN_IP = "10.66.0.150"' not in source
    assert "resolve_router_wan_ip(page, bv, rec)" in source
    assert "rec.fail_current_step(message)" in source
