"""WireGuard客户端综合测试用例

网络配置→内外网设置→VPN客户端→WireGuard
SSH后台: L1数据库(wireguard表, must_pass) + L2连接(wg接口UP, 软断言)
字段映射: name(服务接口,wg开头,仅ascii)/local_address(本地地址,unique)/local_publickey/local_privatekey(自动生成)/
          interface(线路)/local_listenport(监听端口,50000)/mtu(1420)
注意: 仅本地配置, peer对端在wireguard_peers表(列表"添加隧道"按钮); local_address必须unique;
      公私钥进页面自动生成; 无comment字段; 无本地IP/状态列
"""
import pytest
from pages.network.wireguard_page import WireguardPage
from utils.step_recorder import StepRecorder
from tests.network.vpn_test_helper import run_vpn_comprehensive_test


@pytest.mark.wireguard
@pytest.mark.network
class TestWireguardComprehensive:
    """WireGuard客户端综合测试(本地配置, 本地地址唯一, 公私钥自动生成)"""

    def test_wireguard_comprehensive(self, wireguard_page_logged_in: WireguardPage,
                                      step_recorder: StepRecorder, request):
        test_rules = [
            {
                'name': 'wgauto1',
                'add_kwargs': {'name': 'wgauto1', 'local_address': '10.0.8.1/24'},
                'db_fields': {'local_address': '10.0.8.1/24'},
                'desc': '本地地址10.0.8.1/24(默认端口/MTU)',
            },
            {
                'name': 'wgport1',
                'add_kwargs': {'name': 'wgport1', 'local_address': '10.0.9.1/24',
                               'local_listenport': 50001},
                'db_fields': {'local_address': '10.0.9.1/24', 'local_listenport': '50001'},
                'desc': '自定义监听端口50001',
            },
            {
                'name': 'wgsub1',
                'add_kwargs': {'name': 'wgsub1', 'local_address': '10.0.10.1/24', 'mtu': 1280},
                'db_fields': {'local_address': '10.0.10.1/24', 'mtu': '1280'},
                'desc': '不同网段+MTU=1280',
            },
        ]

        ssh_failures = []
        ui_failures = []
        run_vpn_comprehensive_test(
            page=wireguard_page_logged_in, rec=step_recorder, request=request,
            module_key='wireguard', test_rules=test_rules,
            invalid_base_fields={'local_address': '10.0.99.1/24'},
            edit_spec={
                'target': 'wgauto1',
                'field_updates': {'mtu': '1360'},
                'db_fields': {'mtu': '1360'},
            },
            ssh_failures=ssh_failures, ui_failures=ui_failures,
        )
        all_failures = ssh_failures + ui_failures
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
