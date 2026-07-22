"""
pytest配置和fixtures

提供测试所需的浏览器、页面、配置等fixtures
"""
import pytest
import os
import sys
import io
import ctypes
from datetime import datetime
from typing import Generator, Dict, List, Optional

# 解决Windows控制台GBK编码问题（全局只执行一次）
if sys.platform == 'win32':
    try:
        stdout_encoding = str(getattr(sys.stdout, "encoding", "") or "").lower()
        stderr_encoding = str(getattr(sys.stderr, "encoding", "") or "").lower()
        if (
            hasattr(sys.stdout, 'buffer') and not sys.stdout.closed
            and stdout_encoding.replace("-", "") != "utf8"
        ):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', write_through=True)
        if (
            hasattr(sys.stderr, 'buffer') and not sys.stderr.closed
            and stderr_encoding.replace("-", "") != "utf8"
        ):
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', write_through=True)
    except Exception:
        pass

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ==================== PyInstaller打包后的Playwright Fixtures ====================
# PyInstaller打包后，pytest-playwright插件无法通过entry_points自动加载
# 因此在这里直接定义必要的fixtures

from playwright.sync_api import Page, Browser, BrowserContext, Playwright, sync_playwright


@pytest.fixture(scope="session")
def playwright() -> Generator[Playwright, None, None]:
    """Playwright实例"""
    pw = sync_playwright().start()
    yield pw
    pw.stop()


@pytest.fixture(scope="session")
def browser_name() -> str:
    """浏览器名称"""
    return "chromium"


@pytest.fixture(scope="session")
def browser_type(playwright: Playwright, browser_name: str):
    """浏览器类型"""
    return getattr(playwright, browser_name)


@pytest.fixture(scope="session")
def browser_type_launch_args() -> Dict:
    """浏览器启动参数"""
    # 检查环境变量决定是否使用headless模式
    headless = os.environ.get("HEADLESS", "true").lower() == "true"
    return {"headless": headless}


@pytest.fixture(scope="session")
def browser(browser_type, browser_type_launch_args: Dict) -> Generator[Browser, None, None]:
    """浏览器实例"""
    browser = browser_type.launch(**browser_type_launch_args)
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def browser_context_args() -> Dict:
    """浏览器上下文参数"""
    return {}


def _is_threat_intelligence_item(item) -> bool:
    """Return whether a test must not emit visual/network browser artifacts.

    IOC pages can render raw indicators and external log payloads. Those
    values are not reliably redactable once captured in a PNG, video, HAR, or
    Playwright trace, so this guard is tied to the explicit marker (with a
    node-id fallback for setup failures).
    """
    try:
        marker = item.get_closest_marker("threat_intelligence")
        if marker is not None:
            return True
    except Exception:
        pass
    nodeid = str(getattr(item, "nodeid", "") or getattr(item, "name", ""))
    return "test_threat_intelligence_comprehensive" in nodeid


def _is_threat_intelligence_report(report) -> bool:
    """Marker-aware counterpart used after pytest creates a TestReport."""
    try:
        keywords = getattr(report, "keywords", {}) or {}
        if "threat_intelligence" in keywords:
            return True
    except Exception:
        pass
    return _is_threat_intelligence_item(report)


@pytest.fixture(autouse=True)
def _threat_intelligence_artifact_guard(request):
    """Disable Playwright visual/trace capture for IOC tests only.

    The pytest-playwright plugin reads these options while creating its
    artifact recorder. This autouse fixture runs before ordinary function
    fixtures, then restores the process options after teardown so unrelated
    tests retain their configured capture behavior.
    """
    if not _is_threat_intelligence_item(request.node):
        yield
        return

    option = getattr(request.config, "option", None)
    previous = {}
    for name in ("screenshot", "video", "tracing"):
        if option is None or not hasattr(option, name):
            continue
        previous[name] = getattr(option, name)
        setattr(option, name, "off")
    try:
        yield
    finally:
        for name, value in previous.items():
            setattr(option, name, value)


@pytest.fixture(scope="function")
def context(
    browser: Browser,
    browser_context_args: Dict,
    request,
) -> Generator[BrowserContext, None, None]:
    """浏览器上下文"""
    context_args = dict(browser_context_args or {})
    if _is_threat_intelligence_item(request.node):
        # Defensive cleanup for callers or plugins that provide capture args
        # through ``browser_context_args`` instead of pytest CLI options.
        for key in (
            "record_video_dir", "record_video_size", "record_har_path",
            "record_har_content", "record_har_mode", "record_har_omit_content",
        ):
            context_args.pop(key, None)
    context = browser.new_context(**context_args)
    yield context
    context.close()


@pytest.fixture(scope="function")
def page(context: BrowserContext) -> Generator[Page, None, None]:
    """页面实例"""
    page = context.new_page()
    yield page
    page.close()

from playwright.sync_api import Page, Browser, BrowserContext
from config.config import get_config, get_config_with_env, Config
from pages.login_page import LoginPage
from pages.network.vlan_page import VlanPage
from pages.network.ip_rate_limit_page import IpRateLimitPage
from pages.network.mac_rate_limit_page import MacRateLimitPage
from pages.network.static_route_page import StaticRoutePage
from pages.network.cross_layer_service_page import CrossLayerServicePage
from pages.network.multi_wan_lb_page import MultiWanLbPage
from pages.network.protocol_route_page import ProtocolRoutePage
from pages.network.ospf_page import OspfPage
from pages.network.port_route_page import PortRoutePage
from pages.network.domain_route_page import DomainRoutePage
from pages.network.updown_route_page import UpdownRoutePage
from pages.network.upnp_setting_page import UpnpSettingPage
from pages.network.igmp_proxy_page import IgmpProxyPage
from pages.network.iptv_page import IptvPage
from pages.network.udp_proxy_page import UdpProxyPage
from pages.network.nat_rule_page import NatRulePage
from pages.network.port_map_page import PortMapPage
from pages.network.dmz_host_page import DmzHostPage
from pages.network.dns_accelerate_page import DnsAcceleratePage
from pages.network.dns_multi_line_page import DnsMultiLinePage
from pages.network.stream_control_page import StreamControlPage
from pages.network.alone_limit_page import AloneLimitPage
from pages.network.layer7_qos_page import Layer7QosPage
from pages.network.high_prio_host_page import HighPrioHostPage
from pages.network.dhcp_server_page import DhcpServerPage
from pages.network.dhcp_static_page import DhcpStaticPage
from pages.network.dhcp_lease_page import DhcpLeasePage
from pages.network.dhcp_acl_mac_page import DhcpAclMacPage
from pages.network.ipv6_static_page import Ipv6StaticPage
from pages.network.ipv6_wan_page import Ipv6WanPage
from pages.network.ipv6_lan_page import Ipv6LanPage
from pages.network.interface_settings_page import InterfaceSettingsPage
from pages.network.custom_protocol_page import CustomProtocolPage, AdvancedCustomProtocolPage
from pages.network.route_object_page import (
    IpGroupPage, MacGroupPage, PortGroupPage, DomainGroupPage,
    TimePlanPage, ProtocolGroupPage,
)
from pages.network.pptp_client_page import PptpClientPage
from pages.network.l2tp_client_page import L2tpClientPage
from pages.network.openvpn_client_page import OpenvpnClientPage
from pages.network.ipsec_vpn_page import IpsecVpnPage
from pages.network.ike_client_page import IkeClientPage
from pages.network.wireguard_page import WireguardPage
from pages.security.acl_page import AclPage
from pages.security.conn_limit_page import ConnLimitPage
from pages.security.mac_access_control_page import MacAccessControlPage
from pages.security.arp_setting_page import ArpSettingPage
from pages.security.terminal_name_page import TerminalNamePage
from pages.security.threat_intelligence_page import ThreatIntelligencePage
from pages.security.app_protocol_page import AppProtocolPage
from pages.security.advanced_page import AdvancedPage
from pages.security.other_control_page import OtherControlPage
from pages.device_setting.basic_setting_page import BasicSettingPage
from pages.device_setting.alg_setting_page import AlgSettingPage
from pages.device_setting.protocol_control_page import ProtocolControlPage
from pages.advanced_service.ftp_server_page import FtpServerPage
from pages.advanced_service.samba_server_page import SambaServerPage
from pages.advanced_service.http_server_page import HttpServerPage
from pages.advanced_service.snmp_server_page import SnmpServerPage
from pages.advanced_service.virtual_machine_page import VirtualMachinePage
from pages.advanced_service.gre_tunnel_page import GreTunnelPage
from utils.report_generator import ReportGenerator
from utils.step_recorder import (
    StepRecorder,
    get_step_recorder,
    redact_sensitive_text,
    register_sensitive_values,
    get_registered_sensitive_values,
    clear_registered_sensitive_values,
)


# ==================== SSH后台验证 ====================

def _create_backend_verifier():
    """安全创建BackendVerifier（paramiko可能未安装）"""
    try:
        from utils.backend_verifier import BackendVerifier
        return BackendVerifier()
    except ImportError:
        return None


def get_system_dpi_scale() -> float:
    """
    获取Windows系统的DPI缩放因子

    Returns:
        DPI缩放因子（如1.0, 1.25, 1.5, 2.0等）
    """
    try:
        # 设置进程为DPI感知
        ctypes.windll.user32.SetProcessDPIAware()
        # 获取系统DPI
        dpi = ctypes.windll.user32.GetDpiForSystem()
        # 96 DPI = 100%缩放
        return dpi / 96.0
    except Exception:
        return 1.0


# 全局测试结果收集
_test_results = {
    'total': 0,
    'passed': 0,
    'failed': 0,
    'skipped': 0,
    'test_cases': [],
    'start_time': None,
    'end_time': None,
    'total_steps': 0  # 添加步骤统计
}

# 测试用例名称映射（英文 -> 中文）
TEST_NAME_MAPPING = {
    'test_comprehensive_flow': 'VLAN设置测试',
    'test_export_vlans': 'VLAN导出测试',
    'test_import_vlans': 'VLAN导入测试',
    'test_ip_rate_limit_comprehensive': 'IP限速综合测试',
    'test_mac_rate_limit_comprehensive': 'MAC限速综合测试',
    'test_static_route_comprehensive': '静态路由综合测试',
    'test_ospf_comprehensive': '网络配置-OSPF综合测试',
    'test_static_route_flow': '静态路由功能验证(ping环回)',
    'test_cross_layer_service_comprehensive': '跨三层服务综合测试',
    'test_multi_wan_lb_comprehensive': '多线负载综合测试',
    'test_protocol_route_comprehensive': '协议分流综合测试',
    'test_port_route_comprehensive': '端口分流综合测试',
    'test_domain_route_comprehensive': '域名分流综合测试',
    'test_updown_route_comprehensive': '上下行分离综合测试',
    'test_port_route_flow': '端口分流功能验证(命中+选路)',
    'test_protocol_route_flow': '协议分流功能验证(命中+选路)',
    'test_multi_wan_lb_flow': '多线负载功能验证(分布)',
    'test_updown_route_flow': '上下行分流功能验证(双向)',
    'test_domain_route_flow': '域名分流功能验证(选路)',
    'test_upnp_setting_comprehensive': 'UPnP/NAT设置综合测试',
    'test_igmp_proxy_comprehensive': 'IGMP代理综合测试',
    'test_iptv_comprehensive': 'IPTV透传综合测试',
    'test_udp_proxy_comprehensive': 'UDPXY设置综合测试',
    'test_nat_rule_comprehensive': 'NAT规则综合测试',
    'test_snat_flow': 'NAT规则-源地址NAT功能验证(命中打流)',
    'test_port_map_comprehensive': '端口映射综合测试',
    'test_dmz_host_comprehensive': 'DMZ主机综合测试',
    'test_port_map_flow': '端口映射功能验证(DNAT打流)',
    'test_dmz_host_flow': 'DMZ功能验证(NETMAP打流)',
    'test_dns_accelerate_comprehensive': 'DNS加速服务综合测试',
    'test_dns_multi_line_comprehensive': '多线路DNS服务综合测试',
    'test_dns_accelerate_flow': 'DNS加速功能验证(dig解析)',
    'test_dns_multi_line_flow': '多线路DNS功能验证(dig解析)',
    'test_stream_control_comprehensive': '智能流控综合测试',
    'test_alone_limit_flow': '智能流控-终端独立限速功能验证(打流实测)',
    'test_dhcp_server_comprehensive': 'DHCP服务端综合测试',
    'test_dhcp_static_comprehensive': 'DHCP静态分配综合测试',
    'test_dhcp_static_flow': 'DHCP静态分配功能验证(MAC→IP绑定生效)',
    'test_dhcp_lease_comprehensive': 'DHCP客户端综合测试',
    'test_dhcp_acl_mac_comprehensive': 'DHCP黑白名单综合测试',
    'test_dhcp_server_flow': 'DHCP服务端功能验证(dhclient获取)',
    'test_dhcp_acl_mac_flow': 'DHCP黑白名单功能验证(黑名单拒获取)',
    'test_acl_comprehensive': '安全中心-ACL规则综合测试',
    'test_acl_flow_verification': '安全中心-ACL功能验证(多协议打流+端到端drop)',
    'test_conn_limit_comprehensive': '安全中心-连接数限制综合测试',
    'test_conn_limit_concurrent_drop': '安全中心-连接数限制功能验证(并发drop阻断)',
    'test_mac_access_control_comprehensive': '安全中心-MAC访问控制综合测试',
    'test_arp_setting_comprehensive': '安全中心-ARP设置综合测试',
    'test_app_protocol_comprehensive': '安全中心-应用协议控制综合测试',
    'test_app_protocol_flow_verification': '安全中心-应用协议控制功能验证(端到端drop+停用BUG三重信号)',
    'test_advanced_comprehensive': '安全中心-高级设置综合测试',
    'test_other_control_comprehensive': '安全中心-其他控制综合测试',
    'test_terminal_name_comprehensive': '安全中心-终端名称管理综合测试',
    'test_threat_intelligence_comprehensive': '安全中心-威胁情报中心综合测试',
    'test_ipv6_static_comprehensive': 'IPv6前缀静态分配综合测试',
    'test_ipv6_wan_comprehensive': 'IPv6外网设置综合测试',
    'test_ipv6_lan_comprehensive': 'IPv6内网设置综合测试',
    'test_interface_settings_comprehensive': '内外网设置综合测试',
    'test_custom_protocol_comprehensive': '自定义协议综合测试',
    'test_advanced_custom_protocol_comprehensive': '高级自定义协议综合测试',
    'test_ip_group_comprehensive': 'IP分组综合测试',
    'test_mac_group_comprehensive': 'MAC分组综合测试',
    'test_port_group_comprehensive': '端口分组综合测试',
    'test_domain_group_comprehensive': '域名分组综合测试',
    'test_time_plan_comprehensive': '时间计划综合测试',
    'test_protocol_group_comprehensive': '协议分组综合测试',
    'test_pptp_client_comprehensive': 'PPTP客户端综合测试',
    'test_l2tp_client_comprehensive': 'L2TP客户端综合测试',
    'test_openvpn_client_comprehensive': 'OpenVPN客户端综合测试',
    'test_ipsec_vpn_comprehensive': 'IPSec VPN综合测试',
    'test_ike_client_comprehensive': 'IKEv2/IPSec客户端综合测试',
    'test_wireguard_comprehensive': 'WireGuard客户端综合测试',
    'test_ftp_server_comprehensive': '高级服务-本地服务-FTP服务',
    'test_samba_server_comprehensive': '高级服务-本地服务-Samba服务',
    'test_http_server_comprehensive': '高级服务-本地服务-HTTP服务',
    'test_snmp_server_comprehensive': '高级服务-本地服务-SNMP服务',
    'test_virtual_machine_comprehensive': '高级服务-虚拟机',
    'test_gre_tunnel_comprehensive': '虚拟专网-GRE隧道-综合测试',
    'test_gre_config_effect': '虚拟专网-GRE隧道-配置真生效(内核ip -d)',
    'test_gre_boundary': '虚拟专网-GRE隧道-边界值校验',
    'test_gre_lifecycle': '虚拟专网-GRE隧道-生命周期/残留',
    'test_gre_ui_prompts': '虚拟专网-GRE隧道-UI提示规范',
    'test_gre_dataplane_capture': '虚拟专网-GRE隧道-数据面抓包',
    'test_basic_setting_comprehensive': '设备设置-基础设置',
    'test_alg_setting_comprehensive': '设备设置-高级管理-ALG设置',
    'test_protocol_control_comprehensive': '设备设置-高级管理-协议控制',
}


def _get_chinese_test_name(test_name: str) -> str:
    """
    将英文测试名称转换为中文

    Args:
        test_name: 英文测试名称

    Returns:
        中文名称
    """
    # 移除浏览器后缀 [chromium]
    base_name = test_name.split('[')[0] if '[' in test_name else test_name

    # 查找映射
    if base_name in TEST_NAME_MAPPING:
        return TEST_NAME_MAPPING[base_name]

    # 如果没有映射，尝试提取类名和方法名
    if '::' in test_name:
        parts = test_name.split('::')
        if len(parts) >= 2:
            method_name = parts[-1].split('[')[0]
            if method_name in TEST_NAME_MAPPING:
                return TEST_NAME_MAPPING[method_name]

    return test_name


# ==================== 配置fixtures ====================

@pytest.fixture(scope="session")
def config() -> Config:
    """
    获取全局配置（支持环境变量覆盖，用于GUI传参）

    环境变量优先级高于settings.yaml，GUI修改的参数会通过环境变量传递

    Returns:
        Config对象
    """
    loaded = get_config_with_env()
    # Credentials stay in process memory only.  Register every configured
    # password before browser/SSH fixtures can place an exception or command
    # result into the shared JSON/HTML/Excel report pipeline.
    register_sensitive_values((
        loaded.device.username,
        loaded.device.password,
        loaded.ssh.router.username,
        loaded.ssh.router.password,
        loaded.ssh.router.console_username,
        loaded.ssh.router.console_password,
        loaded.ssh.client.username,
        loaded.ssh.client.password,
    ))
    return loaded


# ==================== 浏览器配置fixtures ====================

@pytest.fixture(scope="session")
def browser_type_launch_args(config: Config):
    """浏览器启动参数 - 覆盖pytest-playwright默认配置"""
    # 从环境变量读取是否启用自适应屏幕模式
    auto_adapt = os.environ.get("AUTO_ADAPT_SCREEN", "true").lower() == "true"

    if auto_adapt:
        # 自适应模式：只添加最大化参数，让浏览器使用系统DPI设置
        launch_args = [
            "--start-maximized",  # 最大化启动
            "--high-dpi-support=1",  # 启用高DPI支持
        ]
    else:
        # 固定模式：强制1倍缩放
        launch_args = [
            "--start-maximized",
            "--force-device-scale-factor=1",
        ]

    args = {
        "headless": config.browser.headless,
        "slow_mo": config.browser.slow_mo,
        "args": launch_args,
    }
    return args


@pytest.fixture(scope="session")
def browser_context_args(config: Config):
    """浏览器上下文参数 - 覆盖pytest-playwright默认配置"""
    # 从环境变量读取是否启用自适应屏幕模式
    auto_adapt = os.environ.get("AUTO_ADAPT_SCREEN", "true").lower() == "true"

    if auto_adapt and not config.browser.headless:
        # headed自适应：no_viewport=True让窗口大小决定viewport(混合子接入drawer动画需headed)
        return {
            "no_viewport": True,  # 不限制视口，让窗口大小决定viewport
            "ignore_https_errors": True,
            # 不设置device_scale_factor，让系统自动处理DPI缩放
        }
    else:
        # headless或固定模式：大viewport(1920x1080)避免Ant Table虚拟滚动漏行
        # (headless无窗口时no_viewport无效→默认小viewport→10条规则只渲染8条; 域名/端口分流曾中招)
        viewport_width = int(os.environ.get("VIEWPORT_WIDTH", 1920))
        viewport_height = int(os.environ.get("VIEWPORT_HEIGHT", 1080))

        return {
            "viewport": {"width": viewport_width, "height": viewport_height},
            "ignore_https_errors": True,
            "device_scale_factor": 1,
        }


# ==================== 页面fixtures ====================

@pytest.fixture(scope="function")
def login_page(page: Page, config: Config) -> LoginPage:
    """
    创建登录页面实例

    Args:
        page: Playwright Page对象 (由pytest-playwright插件提供)
        config: 配置对象

    Returns:
        LoginPage实例
    """
    return LoginPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def vlan_page(page: Page, config: Config) -> VlanPage:
    """
    创建VLAN页面实例

    Args:
        page: Playwright Page对象 (由pytest-playwright插件提供)
        config: 配置对象

    Returns:
        VlanPage实例
    """
    return VlanPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def ip_rate_limit_page(page: Page, config: Config) -> IpRateLimitPage:
    """
    创建IP限速页面实例

    Args:
        page: Playwright Page对象 (由pytest-playwright插件提供)
        config: 配置对象

    Returns:
        IpRateLimitPage实例
    """
    return IpRateLimitPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def mac_rate_limit_page(page: Page, config: Config) -> MacRateLimitPage:
    """
    创建MAC限速页面实例

    Args:
        page: Playwright Page对象 (由pytest-playwright插件提供)
        config: 配置对象

    Returns:
        MacRateLimitPage实例
    """
    return MacRateLimitPage(page, config.get_base_url())


# ==================== 登录fixtures ====================

@pytest.fixture(scope="function")
def logged_in_page(page: Page, login_page: LoginPage, config: Config) -> Page:
    """
    已登录状态的页面

    自动执行登录操作，返回已登录的Page对象

    Args:
        page: Playwright Page对象
        login_page: 登录页面对象
        config: 配置对象

    Returns:
        已登录的Page对象
    """
    # 先导航到登录页面
    page.goto(config.get_base_url())

    # 执行登录
    success = login_page.login(
        username=config.device.username,
        password=config.device.password
    )

    if not success:
        pytest.fail("登录失败")

    return page


@pytest.fixture(scope="function")
def vlan_page_logged_in(logged_in_page: Page, config: Config) -> VlanPage:
    """
    已登录并导航到VLAN页面的实例

    Args:
        logged_in_page: 已登录的Page对象
        config: 配置对象

    Returns:
        VlanPage实例
    """
    vlan_page = VlanPage(logged_in_page, config.get_base_url())
    vlan_page.navigate_to_vlan_settings()
    return vlan_page


@pytest.fixture(scope="function")
def ip_rate_limit_page_logged_in(logged_in_page: Page, config: Config) -> IpRateLimitPage:
    """
    已登录并导航到IP限速页面的实例

    Args:
        logged_in_page: 已登录的Page对象
        config: 配置对象

    Returns:
        IpRateLimitPage实例
    """
    ip_page = IpRateLimitPage(logged_in_page, config.get_base_url())
    ip_page.navigate_to_ip_rate_limit()
    return ip_page


@pytest.fixture(scope="function")
def mac_rate_limit_page_logged_in(logged_in_page: Page, config: Config) -> MacRateLimitPage:
    """
    已登录并导航到MAC限速页面的实例

    Args:
        logged_in_page: 已登录的Page对象
        config: 配置对象

    Returns:
        MacRateLimitPage实例
    """
    mac_page = MacRateLimitPage(logged_in_page, config.get_base_url())
    mac_page.navigate_to_mac_rate_limit()
    return mac_page


@pytest.fixture(scope="function")
def static_route_page(page: Page, config: Config) -> StaticRoutePage:
    """创建静态路由页面实例"""
    return StaticRoutePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def static_route_page_logged_in(logged_in_page: Page, config: Config) -> StaticRoutePage:
    """已登录并导航到静态路由页面的实例"""
    sr_page = StaticRoutePage(logged_in_page, config.get_base_url())
    sr_page.navigate_to_static_route()
    return sr_page


@pytest.fixture(scope="function")
def cross_layer_service_page(page: Page, config: Config) -> CrossLayerServicePage:
    """创建跨三层服务页面实例"""
    return CrossLayerServicePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def cross_layer_page_logged_in(logged_in_page: Page, config: Config) -> CrossLayerServicePage:
    """已登录并导航到跨三层服务页面的实例"""
    cls_page = CrossLayerServicePage(logged_in_page, config.get_base_url())
    cls_page.navigate_to_cross_layer_service()
    return cls_page


@pytest.fixture(scope="function")
def multi_wan_lb_page(page: Page, config: Config) -> MultiWanLbPage:
    """创建多线负载页面实例"""
    return MultiWanLbPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def multi_wan_lb_page_logged_in(logged_in_page: Page, config: Config) -> MultiWanLbPage:
    """已登录并导航到多线负载页面的实例"""
    lb_page = MultiWanLbPage(logged_in_page, config.get_base_url())
    lb_page.navigate_to_multi_wan_lb()
    return lb_page


@pytest.fixture(scope="function")
def protocol_route_page(page: Page, config: Config) -> ProtocolRoutePage:
    """创建协议分流页面实例"""
    return ProtocolRoutePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def protocol_route_page_logged_in(logged_in_page: Page, config: Config) -> ProtocolRoutePage:
    """已登录并导航到协议分流页面的实例"""
    pr_page = ProtocolRoutePage(logged_in_page, config.get_base_url())
    pr_page.navigate_to_protocol_route()
    return pr_page


@pytest.fixture(scope="function")
def port_route_page(page: Page, config: Config) -> PortRoutePage:
    """创建端口分流页面实例"""
    return PortRoutePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def port_route_page_logged_in(logged_in_page: Page, config: Config) -> PortRoutePage:
    """已登录并导航到端口分流页面的实例"""
    pt_page = PortRoutePage(logged_in_page, config.get_base_url())
    pt_page.navigate_to_port_route()
    return pt_page


# ==================== 域名分流 fixtures ====================

@pytest.fixture(scope="function")
def domain_route_page(page: Page, config: Config) -> DomainRoutePage:
    """创建域名分流页面实例"""
    return DomainRoutePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def domain_route_page_logged_in(logged_in_page: Page, config: Config) -> DomainRoutePage:
    """已登录并导航到域名分流页面的实例"""
    dr_page = DomainRoutePage(logged_in_page, config.get_base_url())
    dr_page.navigate_to_domain_route()
    return dr_page


# ==================== 上下行分离 fixtures ====================

@pytest.fixture(scope="function")
def updown_route_page(page: Page, config: Config) -> 'UpdownRoutePage':
    """创建上下行分离页面实例"""
    return UpdownRoutePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def updown_route_page_logged_in(logged_in_page: Page, config: Config) -> 'UpdownRoutePage':
    """已登录并导航到上下行分离页面的实例"""
    ud_page = UpdownRoutePage(logged_in_page, config.get_base_url())
    ud_page.navigate_to_updown_route()
    return ud_page


# ==================== UPnP/NAT设置 fixtures ====================

@pytest.fixture(scope="function")
def upnp_setting_page(page: Page, config: Config) -> 'UpnpSettingPage':
    """创建UPnP/NAT设置页面实例"""
    return UpnpSettingPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def upnp_setting_page_logged_in(logged_in_page: Page, config: Config) -> 'UpnpSettingPage':
    """已登录并导航到UPnP/NAT设置页面的实例"""
    upnp_page = UpnpSettingPage(logged_in_page, config.get_base_url())
    upnp_page.navigate_to_upnp_setting()
    return upnp_page


@pytest.fixture(scope="function")
def igmp_proxy_page(page: Page, config: Config) -> 'IgmpProxyPage':
    """创建IGMP代理页面实例"""
    return IgmpProxyPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def igmp_proxy_page_logged_in(logged_in_page: Page, config: Config) -> 'IgmpProxyPage':
    """已登录并导航到IGMP代理页面的实例"""
    igmp_page = IgmpProxyPage(logged_in_page, config.get_base_url())
    igmp_page.navigate_to_igmp_proxy()
    return igmp_page


@pytest.fixture(scope="function")
def iptv_page(page: Page, config: Config) -> 'IptvPage':
    """创建IPTV透传页面实例"""
    return IptvPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def iptv_page_logged_in(logged_in_page: Page, config: Config) -> 'IptvPage':
    """已登录并导航到IPTV透传页面的实例"""
    iptv_page = IptvPage(logged_in_page, config.get_base_url())
    iptv_page.navigate_to_iptv()
    return iptv_page


@pytest.fixture(scope="function")
def udp_proxy_page(page: Page, config: Config) -> 'UdpProxyPage':
    """创建UDPXY设置页面实例"""
    return UdpProxyPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def udp_proxy_page_logged_in(logged_in_page: Page, config: Config) -> 'UdpProxyPage':
    """已登录并导航到UDPXY设置页面的实例"""
    udp_page = UdpProxyPage(logged_in_page, config.get_base_url())
    udp_page.navigate_to_udp_proxy()
    return udp_page


# ==================== NAT规则 fixtures ====================

@pytest.fixture(scope="function")
def nat_rule_page(page: Page, config: Config) -> 'NatRulePage':
    """创建NAT规则页面实例"""
    return NatRulePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def nat_rule_page_logged_in(logged_in_page: Page, config: Config) -> 'NatRulePage':
    """已登录并导航到NAT规则页面的实例"""
    nat_page = NatRulePage(logged_in_page, config.get_base_url())
    nat_page.navigate_to_nat_rule()
    return nat_page


@pytest.fixture(scope="function")
def dns_accelerate_page(page: Page, config: Config) -> 'DnsAcceleratePage':
    """创建DNS加速服务页面实例"""
    return DnsAcceleratePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def dns_accelerate_page_logged_in(logged_in_page: Page, config: Config) -> 'DnsAcceleratePage':
    """已登录并导航到DNS加速服务页面的实例"""
    dns_page = DnsAcceleratePage(logged_in_page, config.get_base_url())
    dns_page.navigate_to_dns_accelerate()
    return dns_page


# ==================== 多线路DNS服务 fixtures ====================

@pytest.fixture(scope="function")
def dns_multi_line_page(page: Page, config: Config) -> 'DnsMultiLinePage':
    """创建多线路DNS服务页面实例"""
    return DnsMultiLinePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def dns_multi_line_page_logged_in(logged_in_page: Page, config: Config) -> 'DnsMultiLinePage':
    """已登录并导航到多线路DNS服务页面的实例"""
    ml_page = DnsMultiLinePage(logged_in_page, config.get_base_url())
    ml_page.navigate_to_dns_multi_line()
    return ml_page


# ==================== 智能流控 fixtures ====================

@pytest.fixture(scope="function")
def stream_control_page(page: Page, config: Config) -> 'StreamControlPage':
    """创建智能流控页面实例"""
    return StreamControlPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def stream_control_page_logged_in(logged_in_page: Page, config: Config) -> 'StreamControlPage':
    """已登录并导航到智能流控页面的实例

    导航到智能流控主页面(不自动开启流控, 由测试内控制开关/模式切换)
    """
    sc_page = StreamControlPage(logged_in_page, config.get_base_url())
    sc_page.navigate_to_stream_control()
    return sc_page


# ==================== 端口映射 fixtures ====================

@pytest.fixture(scope="function")
def port_map_page(page: Page, config: Config) -> 'PortMapPage':
    """创建端口映射页面实例"""
    return PortMapPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def port_map_page_logged_in(logged_in_page: Page, config: Config) -> 'PortMapPage':
    """已登录并导航到端口映射页面的实例"""
    pm_page = PortMapPage(logged_in_page, config.get_base_url())
    pm_page.navigate_to_port_map()
    return pm_page


# ==================== DMZ主机 fixtures ====================

@pytest.fixture(scope="function")
def dmz_host_page(page: Page, config: Config) -> 'DmzHostPage':
    """创建DMZ主机页面实例"""
    return DmzHostPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def dmz_host_page_logged_in(logged_in_page: Page, config: Config) -> 'DmzHostPage':
    """已登录并导航到DMZ主机页面的实例"""
    dz_page = DmzHostPage(logged_in_page, config.get_base_url())
    dz_page.navigate_to_dmz()
    return dz_page


# ==================== DHCP服务端 fixtures ====================

@pytest.fixture(scope="function")
def dhcp_server_page(page: Page, config: Config) -> 'DhcpServerPage':
    """创建DHCP服务端页面实例"""
    return DhcpServerPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def dhcp_server_page_logged_in(logged_in_page: Page, config: Config) -> 'DhcpServerPage':
    """已登录并导航到DHCP服务端页面的实例"""
    dhcp_page = DhcpServerPage(logged_in_page, config.get_base_url())
    dhcp_page.navigate_to_dhcp_server()
    return dhcp_page


@pytest.fixture(scope="function")
def dhcp_static_page(page: Page, config: Config) -> 'DhcpStaticPage':
    """创建DHCP静态分配页面实例"""
    return DhcpStaticPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def dhcp_static_page_logged_in(logged_in_page: Page, config: Config) -> 'DhcpStaticPage':
    """已登录并导航到DHCP静态分配页面的实例"""
    static_page = DhcpStaticPage(logged_in_page, config.get_base_url())
    static_page.navigate_to_dhcp_static()
    return static_page


@pytest.fixture(scope="function")
def dhcp_lease_page(page: Page, config: Config) -> 'DhcpLeasePage':
    """创建DHCP客户端页面实例"""
    return DhcpLeasePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def dhcp_lease_page_logged_in(logged_in_page: Page, config: Config) -> 'DhcpLeasePage':
    """已登录并导航到DHCP客户端页面的实例"""
    lease_page = DhcpLeasePage(logged_in_page, config.get_base_url())
    lease_page.navigate_to_dhcp_lease()
    return lease_page


@pytest.fixture(scope="function")
def dhcp_acl_mac_page(page: Page, config: Config) -> 'DhcpAclMacPage':
    """创建DHCP黑白名单页面实例"""
    return DhcpAclMacPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def dhcp_acl_mac_page_logged_in(logged_in_page: Page, config: Config) -> 'DhcpAclMacPage':
    """已登录并导航到DHCP黑白名单页面的实例"""
    acl_page = DhcpAclMacPage(logged_in_page, config.get_base_url())
    acl_page.navigate_to_dhcp_acl_mac()
    return acl_page


@pytest.fixture(scope="function")
def ipv6_static_page(page: Page, config: Config) -> 'Ipv6StaticPage':
    """创建IPv6前缀静态分配页面实例"""
    return Ipv6StaticPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def ipv6_static_page_logged_in(logged_in_page: Page, config: Config) -> 'Ipv6StaticPage':
    """已登录并导航到IPv6前缀静态分配页面的实例"""
    ipv6_page = Ipv6StaticPage(logged_in_page, config.get_base_url())
    ipv6_page.navigate_to_ipv6_static()
    return ipv6_page


@pytest.fixture(scope="function")
def ipv6_wan_page(page: Page, config: Config) -> 'Ipv6WanPage':
    """创建IPv6外网设置页面实例"""
    return Ipv6WanPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def ipv6_wan_page_logged_in(logged_in_page: Page, config: Config) -> 'Ipv6WanPage':
    """已登录并导航到IPv6外网设置页面的实例(内外网设置>IPv6设置>外网设置)"""
    pg = Ipv6WanPage(logged_in_page, config.get_base_url())
    pg.navigate_to_ipv6_wan()
    return pg


@pytest.fixture(scope="function")
def ipv6_lan_page(page: Page, config: Config) -> 'Ipv6LanPage':
    """创建IPv6内网设置页面实例"""
    return Ipv6LanPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def ipv6_lan_page_logged_in(logged_in_page: Page, config: Config) -> 'Ipv6LanPage':
    """已登录并导航到IPv6内网设置页面的实例(内外网设置>IPv6设置>内网设置)"""
    pg = Ipv6LanPage(logged_in_page, config.get_base_url())
    pg.navigate_to_ipv6_lan()
    return pg


# ==================== 内外网设置 fixtures ====================
@pytest.fixture(scope="function")
def interface_settings_page(page: Page, config: Config) -> InterfaceSettingsPage:
    """创建内外网设置页面实例"""
    return InterfaceSettingsPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def interface_settings_page_logged_in(logged_in_page: Page, config: Config) -> InterfaceSettingsPage:
    """已登录并导航到内外网设置页面(第1个tab)的实例"""
    pg = InterfaceSettingsPage(logged_in_page, config.get_base_url())
    pg.navigate_to_interface_settings()
    return pg


# ==================== 安全中心 fixtures ====================
@pytest.fixture(scope="function")
def acl_page(page: Page, config: Config) -> AclPage:
    """创建ACL规则页面实例(安全中心>ACL规则)"""
    return AclPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def acl_page_logged_in(logged_in_page: Page, config: Config) -> AclPage:
    """已登录并导航到ACL规则列表页的实例(安全中心>ACL规则)"""
    pg = AclPage(logged_in_page, config.get_base_url())
    pg.navigate_to_acl()
    return pg


@pytest.fixture(scope="function")
def conn_limit_page(page: Page, config: Config) -> ConnLimitPage:
    """创建连接数限制页面实例(安全中心>连接数限制)"""
    return ConnLimitPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def conn_limit_page_logged_in(logged_in_page: Page, config: Config) -> ConnLimitPage:
    """已登录并导航到连接数限制列表页的实例(安全中心>连接数限制)"""
    pg = ConnLimitPage(logged_in_page, config.get_base_url())
    pg.navigate_to_conn_limit()
    return pg


@pytest.fixture(scope="function")
def advanced_page(page: Page, config: Config) -> AdvancedPage:
    """创建高级设置页面实例(安全中心>高级设置)"""
    return AdvancedPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def advanced_page_logged_in(logged_in_page: Page, config: Config) -> AdvancedPage:
    """已登录并导航到高级设置页的实例(安全中心>高级设置, 纯配置类页面)"""
    pg = AdvancedPage(logged_in_page, config.get_base_url())
    pg.navigate_to_advanced()
    return pg


@pytest.fixture(scope="function")
def other_control_page_logged_in(logged_in_page: Page, config: Config) -> OtherControlPage:
    """已登录并导航到其他控制页的实例(安全中心>其他控制>网络分享控制, 配置类页面)"""
    pg = OtherControlPage(logged_in_page, config.get_base_url())
    pg.navigate_to_other_control()
    return pg


@pytest.fixture(scope="function")
def mac_access_control_page(page: Page, config: Config) -> MacAccessControlPage:
    """创建MAC访问控制页面实例(安全中心>MAC访问控制)"""
    return MacAccessControlPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def mac_access_control_page_logged_in(logged_in_page: Page, config: Config) -> MacAccessControlPage:
    """已登录并导航到MAC访问控制列表页的实例(安全中心>MAC访问控制)"""
    pg = MacAccessControlPage(logged_in_page, config.get_base_url())
    pg.navigate_to_mac_ctrl()
    return pg


@pytest.fixture(scope="function")
def arp_setting_page(page: Page, config: Config) -> ArpSettingPage:
    """创建ARP设置页面实例(安全中心>ARP设置)"""
    return ArpSettingPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def arp_setting_page_logged_in(logged_in_page: Page, config: Config) -> ArpSettingPage:
    """已登录并导航到ARP设置列表页的实例(安全中心>ARP设置)"""
    pg = ArpSettingPage(logged_in_page, config.get_base_url())
    pg.navigate_to_arp()
    return pg


@pytest.fixture(scope="function")
def terminal_name_page(page: Page, config: Config) -> TerminalNamePage:
    """创建终端名称管理页面实例(安全中心>终端名称管理)"""
    return TerminalNamePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def terminal_name_page_logged_in(logged_in_page: Page, config: Config) -> TerminalNamePage:
    """已登录并导航到终端名称管理列表页的实例(安全中心>终端名称管理)"""
    pg = TerminalNamePage(logged_in_page, config.get_base_url())
    pg.navigate_to_terminal_name()
    return pg


@pytest.fixture(scope="function")
def threat_intelligence_page(page: Page, config: Config) -> ThreatIntelligencePage:
    """创建安全中心-威胁情报中心页面实例（默认可能关闭）。"""
    return ThreatIntelligencePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def threat_intelligence_page_logged_in(
    logged_in_page: Page, config: Config
) -> ThreatIntelligencePage:
    """返回已登录并进入威胁情报中心根页面的实例。"""
    pg = ThreatIntelligencePage(logged_in_page, config.get_base_url())
    pg.navigate_to_threat_intelligence()
    return pg


@pytest.fixture(scope="function")
def app_protocol_page(page: Page, config: Config) -> AppProtocolPage:
    """创建应用协议控制页面实例(安全中心>应用协议控制)"""
    return AppProtocolPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def app_protocol_page_logged_in(logged_in_page: Page, config: Config) -> AppProtocolPage:
    """已登录并导航到应用协议控制列表页的实例(安全中心>应用协议控制)"""
    pg = AppProtocolPage(logged_in_page, config.get_base_url())
    pg.navigate_to_app_proto()
    return pg


@pytest.fixture(scope="function")
def custom_protocol_page(page: Page, config: Config) -> 'CustomProtocolPage':
    """创建自定义协议(L4)页面实例"""
    return CustomProtocolPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def custom_protocol_page_logged_in(logged_in_page: Page, config: Config) -> 'CustomProtocolPage':
    """已登录并导航到自定义协议(L4)页面的实例"""
    cp_page = CustomProtocolPage(logged_in_page, config.get_base_url())
    cp_page.navigate_to_custom_protocol()
    return cp_page


@pytest.fixture(scope="function")
def advanced_custom_protocol_page(page: Page, config: Config) -> 'AdvancedCustomProtocolPage':
    """创建高级自定义协议(L7)页面实例"""
    return AdvancedCustomProtocolPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def advanced_custom_protocol_page_logged_in(logged_in_page: Page, config: Config) -> 'AdvancedCustomProtocolPage':
    """已登录并导航到高级自定义协议(L7)页面的实例"""
    adv_page = AdvancedCustomProtocolPage(logged_in_page, config.get_base_url())
    adv_page.navigate_to_advanced_custom_protocol()
    return adv_page


# ==================== 路由对象(IP/MAC/端口/域名/时间/协议分组) fixtures ====================

@pytest.fixture(scope="function")
def ip_group_page_logged_in(logged_in_page: Page, config: Config) -> 'IpGroupPage':
    """已登录并导航到IP分组页面的实例"""
    pg = IpGroupPage(logged_in_page, config.get_base_url())
    pg.navigate_to_route_object()
    return pg


@pytest.fixture(scope="function")
def mac_group_page_logged_in(logged_in_page: Page, config: Config) -> 'MacGroupPage':
    """已登录并导航到MAC分组页面的实例"""
    pg = MacGroupPage(logged_in_page, config.get_base_url())
    pg.navigate_to_route_object()
    return pg


@pytest.fixture(scope="function")
def port_group_page_logged_in(logged_in_page: Page, config: Config) -> 'PortGroupPage':
    """已登录并导航到端口分组页面的实例"""
    pg = PortGroupPage(logged_in_page, config.get_base_url())
    pg.navigate_to_route_object()
    return pg


@pytest.fixture(scope="function")
def domain_group_page_logged_in(logged_in_page: Page, config: Config) -> 'DomainGroupPage':
    """已登录并导航到域名分组页面的实例"""
    pg = DomainGroupPage(logged_in_page, config.get_base_url())
    pg.navigate_to_route_object()
    return pg


@pytest.fixture(scope="function")
def time_plan_page_logged_in(logged_in_page: Page, config: Config) -> 'TimePlanPage':
    """已登录并导航到时间计划页面的实例"""
    pg = TimePlanPage(logged_in_page, config.get_base_url())
    pg.navigate_to_route_object()
    return pg


@pytest.fixture(scope="function")
def protocol_group_page_logged_in(logged_in_page: Page, config: Config) -> 'ProtocolGroupPage':
    """已登录并导航到协议分组页面的实例"""
    pg = ProtocolGroupPage(logged_in_page, config.get_base_url())
    pg.navigate_to_route_object()
    return pg


# ==================== VPN客户端(PPTP/L2TP/OpenVPN/IPSec/IKEv2/WireGuard) fixtures ====================

@pytest.fixture(scope="function")
def pptp_client_page_logged_in(logged_in_page: Page, config: Config) -> 'PptpClientPage':
    """已登录并导航到PPTP客户端页面的实例"""
    pg = PptpClientPage(logged_in_page, config.get_base_url())
    pg.navigate_to_pptp()
    return pg


@pytest.fixture(scope="function")
def l2tp_client_page_logged_in(logged_in_page: Page, config: Config) -> 'L2tpClientPage':
    """已登录并导航到L2TP客户端页面的实例"""
    pg = L2tpClientPage(logged_in_page, config.get_base_url())
    pg.navigate_to_l2tp()
    return pg


@pytest.fixture(scope="function")
def openvpn_client_page_logged_in(logged_in_page: Page, config: Config) -> 'OpenvpnClientPage':
    """已登录并导航到OpenVPN客户端页面的实例"""
    pg = OpenvpnClientPage(logged_in_page, config.get_base_url())
    pg.navigate_to_openvpn()
    return pg


@pytest.fixture(scope="function")
def ipsec_vpn_page_logged_in(logged_in_page: Page, config: Config) -> 'IpsecVpnPage':
    """已登录并导航到IPSec VPN页面的实例"""
    pg = IpsecVpnPage(logged_in_page, config.get_base_url())
    pg.navigate_to_ipsec()
    return pg


@pytest.fixture(scope="function")
def ike_client_page_logged_in(logged_in_page: Page, config: Config) -> 'IkeClientPage':
    """已登录并导航到IKEv2/IPSec客户端页面的实例"""
    pg = IkeClientPage(logged_in_page, config.get_base_url())
    pg.navigate_to_ike()
    return pg


@pytest.fixture(scope="function")
def wireguard_page_logged_in(logged_in_page: Page, config: Config) -> 'WireguardPage':
    """已登录并导航到WireGuard客户端页面的实例"""
    pg = WireguardPage(logged_in_page, config.get_base_url())
    pg.navigate_to_wireguard()
    return pg


@pytest.fixture(scope="function")
def basic_setting_page(page: Page, config: Config) -> BasicSettingPage:
    """创建设备设置-基础设置页面实例。"""
    return BasicSettingPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def basic_setting_page_logged_in(
    logged_in_page: Page, config: Config
) -> BasicSettingPage:
    """返回已登录并进入设备设置-基础设置的页面实例。"""
    basic_page = BasicSettingPage(logged_in_page, config.get_base_url())
    basic_page.navigate_to_basic_setting()
    return basic_page


@pytest.fixture(scope="function")
def alg_setting_page(page: Page, config: Config) -> AlgSettingPage:
    """创建设备设置-高级管理-ALG设置页面实例。"""
    return AlgSettingPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def alg_setting_page_logged_in(
    logged_in_page: Page, config: Config
) -> AlgSettingPage:
    """返回已登录并进入设备设置-高级管理-ALG设置的页面实例。"""
    alg_page = AlgSettingPage(logged_in_page, config.get_base_url())
    if not alg_page.navigate_to_alg_setting():
        pytest.fail("无法导航到设备设置-高级管理-ALG设置")
    return alg_page


@pytest.fixture(scope="function")
def protocol_control_page(page: Page, config: Config) -> ProtocolControlPage:
    """创建设备设置-高级管理-协议控制页面实例。"""
    return ProtocolControlPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def protocol_control_page_logged_in(
    logged_in_page: Page, config: Config
) -> ProtocolControlPage:
    """返回已登录并进入设备设置-高级管理-协议控制的页面实例。"""
    protocol_page = ProtocolControlPage(logged_in_page, config.get_base_url())
    if not protocol_page.navigate_to_protocol_control():
        pytest.fail("无法导航到设备设置-高级管理-协议控制")
    return protocol_page


@pytest.fixture(scope="function")
def ospf_page(page: Page, config: Config) -> OspfPage:
    """创建网络配置-OSPF页面实例。"""
    return OspfPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def ospf_page_logged_in(logged_in_page: Page, config: Config) -> OspfPage:
    """返回已登录并进入网络配置-OSPF的页面实例。"""
    ospf = OspfPage(logged_in_page, config.get_base_url())
    ospf.navigate_to_ospf()
    return ospf


@pytest.fixture(scope="function")
def ftp_server_page(page: Page, config: Config) -> FtpServerPage:
    """创建高级服务-本地服务-FTP服务页面实例"""
    return FtpServerPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def ftp_server_page_logged_in(logged_in_page: Page, config: Config) -> FtpServerPage:
    """已登录并导航到高级服务-本地服务-FTP服务页面的实例"""
    pg = FtpServerPage(logged_in_page, config.get_base_url())
    pg.navigate_to_ftp_server()
    return pg


@pytest.fixture(scope="function")
def samba_server_page(page: Page, config: Config) -> SambaServerPage:
    """创建高级服务-本地服务-Samba服务页面实例"""
    return SambaServerPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def samba_server_page_logged_in(logged_in_page: Page, config: Config) -> SambaServerPage:
    """已登录并导航到高级服务-本地服务-Samba服务页面的实例"""
    pg = SambaServerPage(logged_in_page, config.get_base_url())
    pg.navigate_to_samba_server()
    return pg


@pytest.fixture(scope="function")
def http_server_page(page: Page, config: Config) -> HttpServerPage:
    """创建高级服务-本地服务-HTTP服务页面实例"""
    return HttpServerPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def http_server_page_logged_in(logged_in_page: Page, config: Config) -> HttpServerPage:
    """已登录并导航到高级服务-本地服务-HTTP服务页面的实例"""
    pg = HttpServerPage(logged_in_page, config.get_base_url())
    pg.navigate_to_http_server()
    return pg


@pytest.fixture(scope="function")
def snmp_server_page(page: Page, config: Config) -> SnmpServerPage:
    """创建高级服务-本地服务-SNMP服务页面实例"""
    return SnmpServerPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def snmp_server_page_logged_in(logged_in_page: Page, config: Config) -> SnmpServerPage:
    """已登录并导航到高级服务-本地服务-SNMP服务页面的实例"""
    pg = SnmpServerPage(logged_in_page, config.get_base_url())
    pg.navigate_to_snmp_server()
    return pg


@pytest.fixture(scope="function")
def virtual_machine_page(page: Page, config: Config) -> VirtualMachinePage:
    """创建高级服务-虚拟机页面实例。"""
    return VirtualMachinePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def virtual_machine_page_logged_in(
    logged_in_page: Page, config: Config
) -> VirtualMachinePage:
    """返回已登录并导航到高级服务-虚拟机的页面实例。"""
    pg = VirtualMachinePage(logged_in_page, config.get_base_url())
    pg.navigate_to_virtual_machine()
    return pg


@pytest.fixture(scope="function")
def gre_tunnel_page(page: Page, config: Config) -> GreTunnelPage:
    """创建虚拟专网-GRE隧道页面实例"""
    return GreTunnelPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def gre_tunnel_page_logged_in(logged_in_page: Page, config: Config) -> GreTunnelPage:
    """已登录并导航到虚拟专网-GRE隧道页面的实例"""
    pg = GreTunnelPage(logged_in_page, config.get_base_url())
    pg.navigate_to_gre()
    return pg


# ==================== 测试数据fixtures ====================

@pytest.fixture(scope="session")
def test_data_dir() -> str:
    """测试数据目录"""
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_data")


@pytest.fixture(scope="session")
def vlan_test_data_dir(test_data_dir: str) -> str:
    """VLAN测试数据目录"""
    return os.path.join(test_data_dir, "vlan")


# ==================== SSH后台验证fixtures ====================

@pytest.fixture(scope="session")
def backend_verifier():
    """
    SSH后台验证器 (session级别复用连接)

    需要 paramiko 库: pip install paramiko
    如果未安装paramiko，此fixture返回None

    Returns:
        BackendVerifier实例或None
    """
    verifier = _create_backend_verifier()
    if verifier is None:
        yield None
        return

    try:
        verifier.connect_router()
        yield verifier
    finally:
        verifier.close()


@pytest.fixture(scope="function")
def ospf_verifier(backend_verifier):
    """OSPF L1-L5验证器，复用BackendVerifier的三端安全连接。"""
    if backend_verifier is None:
        pytest.fail("OSPF综合测试必须启用SSH backend_verifier")
    return backend_verifier.get_ospf_verifier()


@pytest.fixture(scope="function")
def ipsec_verifier(backend_verifier):
    """新版“虚拟专网 -> IPsec VPN”双端 L1-L5 验证器。"""
    if backend_verifier is None:
        pytest.fail("IPsec VPN综合测试必须启用SSH backend_verifier")
    from utils.ipsec_verifier import IpsecVerifier
    return IpsecVerifier(backend_verifier)


@pytest.fixture(scope="function")
def acl_flow_env(backend_verifier):
    """ACL打流验证环境(function级): client策略路由 + iperf3 server探活(失败skip不FAIL) + teardown清理.
    探活在加路由后(yield前FIREWALL链干净, 不受本用例待建规则干扰). 复用add_route_via_router
    确保client 192.168.148.2流量经路由器FIREWALL链(否则绕开→规则永不命中)."""
    if backend_verifier is None:
        pytest.skip("paramiko未安装, 跳过ACL打流验证")
    backend_verifier.connect_router()
    backend_verifier.connect_client()
    backend_verifier.add_route_via_router(backend_verifier._ssh_config.iperf3_server)
    probe = backend_verifier.run_iperf3(direction='upload', duration=1, port=5201)
    if "error" in probe or not probe.get("end"):
        pytest.skip(f"iperf3 server不可达或路由不通, 跳过打流: {str(probe)[:80]}")
    yield backend_verifier
    try:
        backend_verifier._client.exec("pkill -f 'iperf3 -c' 2>/dev/null")
    except Exception:
        pass


@pytest.fixture(scope="function")
def stream_control_flow_env(backend_verifier):
    """智能流控打流验证环境(function级): uname探活(6.12仅记录不skip) + client策略路由经路由器QoS链 +
    iperf3 server探活(失败skip不FAIL) + teardown清理.

    复用add_route_via_router确保client内网IP流量经路由器imq/QoS链(限速才生效).
    6.12不skip: 智能流控QoS(sch_htb)路径≠peerconns(连接跟踪宕机)≠L7 DPI(坏),
    分流5模块6.12打流全跑完未宕机→预期智能流控打流也不触发宕机."""
    if backend_verifier is None:
        pytest.skip("paramiko未安装, 跳过智能流控打流验证")
    backend_verifier.connect_router()
    backend_verifier.connect_client()
    # uname探活(6.12仅记录, 不skip: QoS路径与peerconns/DPI不同, 预期不宕机)
    try:
        kver = backend_verifier._router.exec("uname -r").strip()
        if kver:
            note = " (6.12: 留意QoS是否生效, 限速不生效则软记录)" if "6.12" in kver else ""
            print(f"[智能流控打流] 内核 {kver}{note}")
    except Exception:
        pass
    backend_verifier.add_route_via_router(backend_verifier._ssh_config.iperf3_server)
    probe = backend_verifier.run_iperf3(direction='upload', duration=1, port=5201)
    if "error" in probe or not probe.get("end"):
        try:
            backend_verifier.remove_route(backend_verifier._ssh_config.iperf3_server)
        except Exception:
            pass
        pytest.skip(f"iperf3 server不可达或路由不通, 跳过打流: {str(probe)[:80]}")
    yield backend_verifier
    try:
        backend_verifier._client.exec("pkill -f 'iperf3 -c' 2>/dev/null")
    except Exception:
        pass


@pytest.fixture(scope="function")
def app_proto_flow_env(backend_verifier):
    """应用协议控制打流环境(function级): client host路由到baidu(确保经路由器DPI) + baidu可达探活(失败skip不FAIL) + teardown删路由.
    iperf3不触发L7 DPI, 用HTTP curl baidu打流(baidu appid=5060173).
    host路由坑: curl --interface只bind源IP不强制路由, 必须ip route add via路由器LAN口."""
    if backend_verifier is None:
        pytest.skip("paramiko未安装, 跳过应用协议控制打流验证")
    baidu_ip = "110.242.69.21"
    backend_verifier.connect_router()
    backend_verifier.connect_client()
    backend_verifier.add_route_via_router(baidu_ip)
    probe = backend_verifier._client.exec(
        "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 -m 8 http://www.baidu.com/", timeout=15)
    if not any(c in probe for c in ["200", "301", "302"]):
        try:
            backend_verifier.remove_route(baidu_ip)
        except Exception:
            pass
        pytest.skip(f"baidu经路由器不可达, 跳过应用协议控制打流: {str(probe)[:80]}")
    yield backend_verifier
    try:
        backend_verifier.remove_route(baidu_ip)
    except Exception:
        pass


@pytest.fixture(scope="session")
def router_ssh():
    """
    路由器SSH直连 (session级别复用)

    Returns:
        SSHClient实例或None
    """
    verifier = _create_backend_verifier()
    if verifier is None:
        yield None
        return

    try:
        verifier.connect_router()
        yield verifier._router
    finally:
        verifier.close()


# ==================== 报告相关fixtures ====================

@pytest.fixture(scope="session")
def screenshot_dir(config: Config) -> str:
    """截图目录"""
    dir_path = config.report.screenshot_dir
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


# ==================== 步骤记录器fixture ====================

@pytest.fixture(scope="function")
def step_recorder() -> StepRecorder:
    """
    步骤记录器fixture

    每个测试函数获得一个干净的步骤记录器实例

    Returns:
        StepRecorder实例
    """
    recorder = get_step_recorder()
    recorder.clear()  # 清除之前的记录
    return recorder


@pytest.fixture(scope="function")
def screenshot_path(screenshot_dir: str, request) -> str:
    """
    生成截图保存路径

    Args:
        screenshot_dir: 截图目录
        request: pytest request对象

    Returns:
        截图保存路径
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    test_name = request.node.name
    return os.path.join(screenshot_dir, f"{test_name}_{timestamp}.png")


# ==================== Hook函数 ====================

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    测试结果报告钩子

    在测试失败时自动截图
    """
    outcome = yield
    report = outcome.get_result()

    # call/setup 失败都尽量截图；登录或页面fixture失败同样需要证据。
    if call.when in ("setup", "call") and report.failed:
        # 基础设置页面会显示原设备名称和自定义NTP地址。失败截图以
        # base64直接嵌入HTML，无法可靠逐像素脱敏，因此该高风险单例模块
        # 明确禁用截图，改用六段结构化证据、API契约与后端运行态定位。
        if (
            item.get_closest_marker("basic_setting") is not None
            or _is_threat_intelligence_item(item)
        ):
            return
        # 获取page fixture(优先用实际测试的page,而不是底层空白page)
        # 测试用例通常用 xxx_page_logged_in fixture,它内部的page才是有内容的
        screenshot_page = None
        # 策略1: 找funcargs里所有含page属性的对象(各种Page对象)
        for key, val in item.funcargs.items():
            if hasattr(val, 'page') and val.page is not None:
                try:
                    # 确保page还没关闭
                    if not val.page.is_closed():
                        screenshot_page = val.page
                        break
                except Exception:
                    pass
        # 策略2: 回退到page fixture
        if screenshot_page is None and "page" in item.funcargs:
            screenshot_page = item.funcargs["page"]

        if screenshot_page is not None:
            page = screenshot_page

            # 创建截图目录
            config = get_config()
            screenshot_dir = config.report.screenshot_dir
            os.makedirs(screenshot_dir, exist_ok=True)

            # 生成截图文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_name = f"{item.name}_{timestamp}_failure.png"
            screenshot_path = os.path.join(screenshot_dir, screenshot_name)

            # 保存截图
            try:
                page.screenshot(path=screenshot_path)
                # 将截图转为base64内嵌，避免HTML报告中路径引用失败
                import base64
                with open(screenshot_path, 'rb') as img_file:
                    img_base64 = base64.b64encode(img_file.read()).decode('utf-8')
                screenshot_data_uri = f"data:image/png;base64,{img_base64}"
                # 将base64截图添加到报告
                report.extra = getattr(report, "extra", [])
                report.extra.append({
                    "name": "Screenshot",
                    "content": screenshot_data_uri,
                    "type": "image",
                })
            except Exception as e:
                print(f"截图失败: {type(e).__name__}")


def pytest_configure(config):
    """pytest配置钩子"""
    # 注册自定义标记
    config.addinivalue_line(
        "markers", "vlan: VLAN设置模块测试"
    )
    config.addinivalue_line(
        "markers", "ip_rate_limit: IP限速模块测试"
    )
    config.addinivalue_line(
        "markers", "mac_rate_limit: MAC限速模块测试"
    )
    config.addinivalue_line(
        "markers", "static_route: 静态路由模块测试"
    )
    config.addinivalue_line(
        "markers", "cross_layer_service: 跨三层服务模块测试"
    )
    config.addinivalue_line(
        "markers", "network: 网络配置模块测试"
    )
    config.addinivalue_line(
        "markers", "interface_settings: 内外网设置模块测试"
    )
    config.addinivalue_line(
        "markers", "slow: 慢速测试"
    )
    config.addinivalue_line(
        "markers", "smoke: 冒烟测试"
    )
    config.addinivalue_line(
        "markers", "backend: 后台SSH验证测试"
    )
    config.addinivalue_line(
        "markers", "full_chain: 全链路验证测试"
    )
    config.addinivalue_line(
        "markers", "multi_wan_lb: 多线负载模块测试"
    )
    config.addinivalue_line(
        "markers", "protocol_route: 协议分流模块测试"
    )
    config.addinivalue_line(
        "markers", "port_route: 端口分流模块测试"
    )
    config.addinivalue_line(
        "markers", "domain_route: 域名分流模块测试"
    )
    config.addinivalue_line(
        "markers", "updown_route: 上下行分离模块测试"
    )
    config.addinivalue_line(
        "markers", "upnp_setting: UPnP/NAT设置模块测试"
    )
    config.addinivalue_line(
        "markers", "igmp_proxy: IGMP代理模块测试"
    )
    config.addinivalue_line(
        "markers", "iptv: IPTV透传模块测试"
    )
    config.addinivalue_line(
        "markers", "nat_rule: NAT规则模块测试"
    )
    config.addinivalue_line(
        "markers", "port_map: 端口映射模块测试"
    )
    config.addinivalue_line(
        "markers", "dmz_host: DMZ主机模块测试"
    )
    config.addinivalue_line(
        "markers", "dns_accelerate: DNS加速服务模块测试"
    )
    config.addinivalue_line(
        "markers", "dns_multi_line: 多线路DNS服务模块测试"
    )
    config.addinivalue_line(
        "markers", "stream_control: 智能流控模块测试"
    )
    config.addinivalue_line(
        "markers", "dhcp_server: DHCP服务端模块测试"
    )
    config.addinivalue_line(
        "markers", "dhcp_static: DHCP静态分配模块测试"
    )
    config.addinivalue_line(
        "markers", "dhcp_lease: DHCP客户端模块测试"
    )
    config.addinivalue_line(
        "markers", "dhcp_acl_mac: DHCP黑白名单模块测试"
    )
    config.addinivalue_line(
        "markers", "ipv6_static: IPv6前缀静态分配模块测试"
    )
    config.addinivalue_line(
        "markers", "ipv6_wan: IPv6外网设置模块测试"
    )
    config.addinivalue_line(
        "markers", "ipv6_lan: IPv6内网设置模块测试"
    )
    config.addinivalue_line(
        "markers", "custom_protocol: 自定义协议(L4)模块测试"
    )
    config.addinivalue_line(
        "markers", "advanced_custom_protocol: 高级自定义协议(L7)模块测试"
    )
    config.addinivalue_line(
        "markers", "ip_group: IP分组模块测试"
    )
    config.addinivalue_line(
        "markers", "mac_group: MAC分组模块测试"
    )
    config.addinivalue_line(
        "markers", "port_group: 端口分组模块测试"
    )
    config.addinivalue_line(
        "markers", "domain_group: 域名分组模块测试"
    )
    config.addinivalue_line(
        "markers", "time_plan: 时间计划模块测试"
    )
    config.addinivalue_line(
        "markers", "protocol_group: 协议分组模块测试"
    )
    config.addinivalue_line(
        "markers", "pptp_client: PPTP客户端模块测试"
    )
    config.addinivalue_line(
        "markers", "l2tp_client: L2TP客户端模块测试"
    )
    config.addinivalue_line(
        "markers", "openvpn_client: OpenVPN客户端模块测试"
    )
    config.addinivalue_line(
        "markers", "ipsec_vpn: IPSec VPN模块测试"
    )
    config.addinivalue_line(
        "markers", "ike_client: IKEv2/IPSec客户端模块测试"
    )
    config.addinivalue_line(
        "markers", "wireguard: WireGuard客户端模块测试"
    )
    config.addinivalue_line(
        "markers", "device_setting: 设备设置模块测试"
    )
    config.addinivalue_line(
        "markers", "basic_setting: 设备设置-基础设置模块测试"
    )
    config.addinivalue_line(
        "markers", "alg_setting: 设备设置-高级管理-ALG设置模块测试"
    )
    config.addinivalue_line(
        "markers", "advanced_service: 高级服务模块测试"
    )
    config.addinivalue_line(
        "markers", "ftp_server: 高级服务-本地服务-FTP服务模块测试"
    )
    config.addinivalue_line(
        "markers", "samba_server: 高级服务-本地服务-Samba服务模块测试"
    )
    config.addinivalue_line(
        "markers", "http_server: 高级服务-本地服务-HTTP服务模块测试"
    )
    config.addinivalue_line(
        "markers", "snmp_server: 高级服务-本地服务-SNMP服务模块测试"
    )
    config.addinivalue_line(
        "markers", "virtual_machine: 高级服务-虚拟机模块测试"
    )
    config.addinivalue_line(
        "markers", "gre_tunnel: 虚拟专网-GRE隧道模块测试"
    )
    config.addinivalue_line(
        "markers", "threat_intelligence: 安全中心-威胁情报中心模块测试"
    )
    config.addinivalue_line("markers", "p0: P0冒烟-核心CRUD/导入导出/批量(必跑)")
    config.addinivalue_line("markers", "p1: P1功能-全协议/全动作/优先级排序(常规回归)")
    config.addinivalue_line("markers", "p2: P2边界-异常输入/越界/极端值(可选)")

    # pytest.main() 在打包GUI中可能同进程重复调用，每次会话必须全量清零。
    _test_results.clear()
    _test_results.update({
        'total': 0,
        'passed': 0,
        'failed': 0,
        'skipped': 0,
        'test_cases': [],
        'start_time': datetime.now(),
        'end_time': None,
        'total_steps': 0,
    })
    clear_registered_sensitive_values()


def _dt_to_str(v):
    """datetime/字符串 -> 字符串(JSON 安全)"""
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return v.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(v)


def _artifact_log_path(path, project_root):
    """Return a portable path label without exposing the local user directory."""
    absolute = os.path.abspath(path)
    root = os.path.abspath(project_root)
    try:
        if os.path.commonpath((absolute, root)) == root:
            return os.path.relpath(absolute, root).replace(os.sep, "/")
    except (OSError, ValueError):
        pass
    return os.path.basename(absolute)


def _find_screenshot_path(screenshot_dir, original_name, project_root=None):
    """查找最新失败截图，并返回相对项目根目录的可移植路径。"""
    if not screenshot_dir or not os.path.isdir(screenshot_dir) or not original_name:
        return ""
    try:
        prefix = original_name + "_"
        matches = [f for f in os.listdir(screenshot_dir)
                   if f.startswith(prefix) and f.endswith("_failure.png")]
        if not matches:
            return ""
        matches.sort(reverse=True)  # 文件名含时间戳, 倒序取最新
        absolute_path = os.path.abspath(os.path.join(screenshot_dir, matches[0]))
        base_dir = os.path.abspath(
            project_root or os.path.dirname(os.path.dirname(__file__))
        )
        relative = os.path.relpath(absolute_path, base_dir)
        if relative == ".." or relative.startswith(".." + os.sep):
            return os.path.basename(absolute_path)
        return relative.replace(os.sep, "/")
    except Exception:
        return ""


def _is_threat_intelligence_case_name(original_name) -> bool:
    """Recognize the IOC case even when pytest appends a browser parameter."""
    return str(original_name or "").split("[", 1)[0] == (
        "test_threat_intelligence_comprehensive"
    )


def _dump_test_results_json(
    results, output_dir, screenshot_dir, project_root=None
):
    """把 _test_results dump 成 JSON(供 GUI 导出真实测试结果 Excel)。
    截图只存文件路径不存 base64, 避免文件过大。"""
    import json
    data = {
        "schema_version": 2,
        "total": results.get("total", 0),
        "passed": results.get("passed", 0),
        "failed": results.get("failed", 0),
        "skipped": results.get("skipped", 0),
        "total_steps": results.get("total_steps", 0),
        "duration": results.get("duration", ""),
        "start_time": _dt_to_str(results.get("start_time")),
        "end_time": _dt_to_str(results.get("end_time")),
        "test_cases": [],
    }
    for tc in results.get("test_cases", []):
        orig = tc.get("original_name", "")
        # 有 base64 截图才去找文件路径
        threat_case = _is_threat_intelligence_case_name(orig)
        shot_path = (
            ""
            if threat_case
            else (
                _find_screenshot_path(screenshot_dir, orig, project_root)
                if tc.get("screenshot") else ""
            )
        )
        data["test_cases"].append({
            "name": tc.get("name", ""),
            "original_name": orig,
            "status": tc.get("status", ""),
            "duration": tc.get("duration", ""),
            "error_message": tc.get("error_message"),
            "error_traceback": tc.get("error_traceback"),
            "steps": tc.get("steps", []),
            "step_count": tc.get("step_count", 0),
            "screenshot_path": "" if threat_case else shot_path,
        })
    json_path = os.path.join(output_dir, "test_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return json_path


def _sanitize_report_payload(value):
    """Apply the in-memory credential registry at the final report boundary."""
    if isinstance(value, dict):
        sanitized = {
            key: _sanitize_report_payload(item) for key, item in value.items()
        }
        if _is_threat_intelligence_case_name(sanitized.get("original_name")):
            # A caller/plugin may attach binary or network artifacts without
            # going through pytest_runtest_makereport. Never serialize those
            # fields for an IOC case, where pixel-level redaction is unsafe.
            for key in (
                "screenshot", "screenshot_path", "video", "video_path",
                "trace", "trace_path", "har", "har_path", "extra",
            ):
                if key in sanitized:
                    sanitized[key] = [] if key in {"extra", "trace"} else ""
        return sanitized
    if isinstance(value, list):
        return [_sanitize_report_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_report_payload(item) for item in value)
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def pytest_sessionfinish(session, exitstatus):
    """测试会话结束钩子 - 生成自定义报告"""
    _test_results['end_time'] = datetime.now()

    # 计算持续时间
    if _test_results['start_time'] and _test_results['end_time']:
        duration = _test_results['end_time'] - _test_results['start_time']
        _test_results['duration'] = str(duration).split('.')[0]  # 去掉毫秒
    else:
        _test_results['duration'] = '00:00:00'

    # 只有当有测试用例时才生成报告
    if _test_results['total'] > 0:
        try:
            # 获取配置
            config = get_config()
            output_dir = config.report.output_dir
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

            # 转换为绝对路径（确保路径不受工作目录影响）
            if not os.path.isabs(output_dir):
                output_dir = os.path.join(project_root, output_dir)

            os.makedirs(output_dir, exist_ok=True)

            # 生成报告
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(output_dir, f"test_report_{timestamp}.html")

            generator = ReportGenerator()
            device_info = {
                'ip': config.device.ip,
                'browser': 'Chromium',
                'version': os.environ.get('TEST_VERSION', getattr(config.report, 'version', 'v4.0')),
            }

            # 获取测试人员（优先从环境变量获取，这样GUI设置的值可以传递）
            tester = os.environ.get('TESTER', getattr(config.report, 'tester', '自动化测试'))

            safe_results = _sanitize_report_payload(_test_results)
            generator.generate_report(
                safe_results,
                output_path,
                report_title="爱快路由器4.0自动化测试报告",
                device_info=device_info,
                tester=tester
            )

            print(
                "\n[报告] 自定义HTML报告已生成: "
                + _artifact_log_path(output_path, project_root)
            )

            # 保存测试结果 JSON(供 GUI "导出测试结果" 使用)
            try:
                screenshot_dir = config.report.screenshot_dir
                if not os.path.isabs(screenshot_dir):
                    screenshot_dir = os.path.join(project_root, screenshot_dir)
                json_path = _dump_test_results_json(
                    safe_results, output_dir, screenshot_dir, project_root
                )
                print(
                    "[报告] 测试结果JSON已保存: "
                    + _artifact_log_path(json_path, project_root)
                )
                artifact_paths = [json_path, output_path]
                leaked_artifacts = []
                registered = get_registered_sensitive_values()
                for artifact_path in artifact_paths:
                    with open(artifact_path, "r", encoding="utf-8") as artifact_file:
                        artifact_text = artifact_file.read()
                    if any(secret in artifact_text for secret in registered):
                        leaked_artifacts.append(os.path.basename(artifact_path))
                if leaked_artifacts:
                    session.exitstatus = pytest.ExitCode.TESTS_FAILED
                    print(
                        "[安全失败] 报告产物命中内存登记敏感值："
                        f"文件数={len(leaked_artifacts)}"
                    )
                else:
                    print(
                        "[安全] JSON/HTML内存登记敏感值扫描通过："
                        f"登记值数={len(registered)}"
                    )
            except Exception as je:
                print(f"[警告] 保存测试结果JSON失败: {type(je).__name__}")

        except Exception as e:
            print(f"\n[警告] 生成自定义报告失败: {type(e).__name__}")
        finally:
            clear_registered_sensitive_values()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_logreport(report):
    """收集测试结果"""
    yield

    # 正常用例记录call结果；setup失败/跳过时没有call，也必须生成本次报告。
    collect_result = (
        report.when == 'call'
        or (report.when == 'setup' and (report.failed or report.skipped))
    )
    if collect_result:
        _test_results['total'] += 1

        # 提取测试用例名称
        test_name = report.nodeid
        if '::' in test_name:
            test_name = test_name.split('::')[-1]

        # 获取中文名称
        chinese_name = _get_chinese_test_name(test_name)

        # 获取步骤记录器中的步骤
        recorder = get_step_recorder()
        steps = recorder.get_steps()

        # 步骤details含FAIL/✗时, 强制step status=failed(让报告一眼看出失败步骤,
        # 原rec.step无异常自动标passed, ssh_verify的FAIL只在details不反映到status)
        for _step in steps:
            if _step.get('status') == 'passed':
                _details_text = ' '.join(_step.get('details', []))
                if 'FAIL' in _details_text or '✗' in _details_text:
                    _step['status'] = 'failed'

        # 统计步骤数
        step_count = len(steps)
        _test_results['total_steps'] += step_count

        # 构建测试用例数据
        test_case = {
            'name': chinese_name,  # 使用中文名称
            'original_name': test_name,  # 保留原始名称
            'status': report.outcome,
            'duration': f"{report.duration:.2f}s" if hasattr(report, 'duration') else '0s',
            'description': getattr(report, 'docstring', '') or '',
            'error_message': None,
            'steps': steps,
            'step_count': step_count,  # 添加步骤数
            'screenshot': None
        }
        privacy_report = _is_threat_intelligence_report(report)

        # 含BUG记录(【⚠ BUG记录】)的 passed case → status=warning,
        # 让报告顶部"警告用例"统计+用例黄色突出BUG(仅识别record_bug标记, 不影响普通软断言)
        if report.outcome == 'passed':
            _has_bug = any(
                '【⚠ BUG记录】' in ' '.join(_s.get('details', []))
                for _s in steps
            )
            if _has_bug:
                test_case['status'] = 'warning'

        # 处理失败情况
        if report.failed:
            _test_results['failed'] += 1
            if hasattr(report, 'longrepr'):
                longrepr = str(report.longrepr)
                # 提取简明错误信息：取AssertionError行或最后一行有意义的错误
                error_lines = longrepr.strip().split('\n')
                short_error = None
                for line in error_lines:
                    line_stripped = line.strip()
                    if line_stripped.startswith('E ') and ('assert' in line_stripped.lower() or 'Error' in line_stripped):
                        short_error = line_stripped[2:].strip()  # 去掉 "E " 前缀
                        break
                    if line_stripped.startswith('AssertionError:') or line_stripped.startswith('AssertionError:'):
                        short_error = line_stripped
                        break
                if short_error is None:
                    # 回退：取最后一行E开头的
                    for line in reversed(error_lines):
                        if line.strip().startswith('E '):
                            short_error = line.strip()[2:].strip()
                            break
                safe_error = redact_sensitive_text(short_error or longrepr[-500:])
                # Pytest's full longrepr embeds source lines.  Password-shaped
                # invalid test literals must not enter JSON/HTML/Excel even when
                # the test itself fails, so retain only redacted location and
                # exception evidence rather than executable source text.
                import re
                locations = []
                for match in re.finditer(
                    r"(?m)^([^\r\n]*?\.py:\d+)(?::|\s*$)", longrepr
                ):
                    location = match.group(1).strip()
                    if location and location not in locations:
                        locations.append(location)
                trace_lines = ["完整源码堆栈已按凭据安全策略隐藏。"]
                if locations:
                    trace_lines.append("定位：" + "；".join(locations[-8:]))
                trace_lines.append("异常：" + safe_error)
                test_case['error_message'] = safe_error
                test_case['error_traceback'] = "\n".join(trace_lines)
            if privacy_report:
                # A pytest longrepr can contain raw DOM/log values that are
                # unknown to the credential registry. Keep only a stable,
                # actionable statement for IOC reports; structured step
                # evidence remains the source of diagnostic detail.
                test_case['error_message'] = (
                    "威胁情报中心综合测试未通过；原始异常文本已隐藏，"
                    "请查看脱敏后的结构化步骤证据。"
                )
                test_case['error_traceback'] = (
                    "威胁情报中心报告已禁用原始 traceback、截图、视频和 trace；"
                    "仅保留脱敏后的结构化步骤证据。"
                )
        elif report.passed:
            _test_results['passed'] += 1
        else:
            _test_results['skipped'] += 1

        # 检查是否有截图
        if not privacy_report and hasattr(report, 'extra') and report.extra:
            for extra in report.extra:
                if extra.get('type') == 'image':
                    test_case['screenshot'] = extra.get('content')
                    break

        _test_results['test_cases'].append(test_case)

        # 清除步骤记录器，为下一个测试做准备
        recorder.clear()
