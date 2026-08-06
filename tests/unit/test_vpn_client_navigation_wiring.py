"""新版虚拟专网五个客户端模块的 GUI 与导航接线回归。"""

from __future__ import annotations

from config.config import get_config
from gui.main_window import MainWindow
from gui.test_runner import TestRunner as GuiTestRunner
from pages.network.ike_client_page import IkeClientPage
from pages.network.l2tp_client_page import L2tpClientPage
from pages.network.openvpn_client_page import OpenvpnClientPage
from pages.network.old_ipsec_vpn_page import OldIpsecVpnPage
from pages.network.pptp_client_page import PptpClientPage
from pages.network.wireguard_page import WireguardPage


VPN_CONTRACTS = {
    "PPTP": (
        PptpClientPage,
        "/#/vpn/pptp",
        "PPTP客户端",
        "network/test_pptp_client_comprehensive.py::"
        "TestPptpClientComprehensive::test_pptp_client_comprehensive",
    ),
    "L2TP": (
        L2tpClientPage,
        "/#/vpn/l2tp",
        "L2TP客户端",
        "network/test_l2tp_client_comprehensive.py::"
        "TestL2tpClientComprehensive::test_l2tp_client_comprehensive",
    ),
    "OpenVPN": (
        OpenvpnClientPage,
        "/#/vpn/openVpn",
        "OpenVPN客户端",
        "network/test_openvpn_client_comprehensive.py::"
        "TestOpenvpnClientComprehensive::test_openvpn_client_comprehensive",
    ),
    "IKEv2/IPsec": (
        IkeClientPage,
        "/#/vpn/ikev2",
        "IKEv2/IPsec客户端",
        "network/test_ike_client_comprehensive.py::"
        "TestIkeClientComprehensive::test_ike_client_comprehensive",
    ),
    "WireGuard": (
        WireguardPage,
        "/#/vpn/wireGuard",
        "",
        "network/test_wireguard_comprehensive.py::"
        "TestWireguardComprehensive::test_wireguard_comprehensive",
    ),
}

OLD_IPSEC_NODE = (
    "network/test_old_ipsec_vpn_comprehensive.py::"
    "TestOldIpsecVpnComprehensive::test_old_ipsec_vpn_comprehensive"
)


class _PageStub:
    def __init__(self):
        self.goto_urls = []
        self.clicked_tabs = []

    def goto(self, url):
        self.goto_urls.append(url)

    def wait_for_load_state(self, *_args, **_kwargs):
        return None

    def wait_for_timeout(self, *_args, **_kwargs):
        return None

    def evaluate(self, _script, *args):
        if args:
            self.clicked_tabs.append(args[0])
            return True
        return ""


def test_gui_places_five_clients_directly_under_virtual_private_network():
    modules = MainWindow._load_test_modules(None)
    assert "VPN客户端" not in modules["网络配置"]["children"]

    vpn_children = modules["虚拟专网"]["children"]
    assert list(vpn_children)[:8] == [
        "IPsec VPN", "GRE", "PPTP", "L2TP", "OpenVPN", "旧版IPsec",
        "IKEv2/IPsec", "WireGuard",
    ]
    for label, (_page_class, _route, _tab, nodeid) in VPN_CONTRACTS.items():
        assert vpn_children[label]["testcases"] == [nodeid]
        assert vpn_children[label]["groups"]["综合测试（推荐）"] == [nodeid]

    assert vpn_children["旧版IPsec"]["testcases"] == [OLD_IPSEC_NODE]


def test_five_clients_use_exact_new_routes_and_client_tabs():
    for _label, (page_class, route, client_tab, _nodeid) in VPN_CONTRACTS.items():
        stub = _PageStub()
        page = page_class(stub, "http://router.test")

        assert page.LIST_URL == route
        assert page.CLIENT_TAB == client_tab
        assert page.navigate_to_module() is page
        assert stub.goto_urls == ["http://router.test" + route]
        assert stub.clicked_tabs == ([client_tab] if client_tab else [])


def test_gui_runner_targets_each_moved_vpn_test_node():
    for _label, (_page_class, _route, _tab, nodeid) in VPN_CONTRACTS.items():
        command = GuiTestRunner([nodeid], get_config())._build_pytest_command()
        normalized_target = command[-1].replace("\\", "/")
        assert normalized_target.endswith("tests/" + nodeid)


def test_old_ipsec_is_restored_under_its_new_name_and_route():
    stub = _PageStub()
    page = OldIpsecVpnPage(stub, "http://router.test")

    assert page.LIST_URL == "/#/vpn/oldVersionIpsecVpn"
    assert page.navigate_to_old_ipsec() is page
    assert stub.goto_urls == [
        "http://router.test/#/vpn/oldVersionIpsecVpn"
    ]

    command = GuiTestRunner([OLD_IPSEC_NODE], get_config())._build_pytest_command()
    assert command[-1].replace("\\", "/").endswith(
        "tests/" + OLD_IPSEC_NODE
    )
