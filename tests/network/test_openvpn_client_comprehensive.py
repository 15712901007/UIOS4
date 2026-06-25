"""OpenVPN客户端综合测试用例

网络配置→内外网设置→VPN客户端→OpenVPN
SSH后台: L1数据库(openvpn_client表, must_pass) + L2连接(openvpn进程/tun接口, 软断言)
字段映射: name(ovpn开头,仅ascii)/remote_addr(服务器)/remote_port(1194)/method(认证方式)/
          username/password/ca(CA证书,textarea必填!)/cipher/proto/dev_type/tun_mtu/comment
CA证书: test_data/vpn/openvpn_ca.pem (自签名, 通过表单校验)
服务端: 10.66.0.40 (账号认证 test/test)
"""
import os
import pytest
from pages.network.openvpn_client_page import OpenvpnClientPage
from utils.step_recorder import StepRecorder
from tests.network.vpn_test_helper import run_vpn_comprehensive_test


@pytest.mark.openvpn_client
@pytest.mark.network
class TestOpenvpnClientComprehensive:
    """OpenVPN客户端综合测试(含CA证书必填校验, 账号认证)"""

    def test_openvpn_client_comprehensive(self, openvpn_client_page_logged_in: OpenvpnClientPage,
                                           step_recorder: StepRecorder, request):
        ca_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), 'test_data', 'vpn', 'openvpn_ca.pem')
        with open(ca_path, 'r', encoding='utf-8') as f:
            ca_cert = f.read().strip()

        test_rules = [
            {
                'name': 'ovpnauto1',
                'add_kwargs': {'name': 'ovpnauto1', 'remote_addr': '10.66.0.40',
                               'username': 'test', 'password': 'test', 'ca': ca_cert, 'comment': 'OpenVPN账号认证'},
                'db_fields': {'remote_addr': '10.66.0.40', 'username': 'test'},
                'desc': '连10.66.0.40(账号认证+CA证书)',
            },
            {
                'name': 'ovpnport1',
                'add_kwargs': {'name': 'ovpnport1', 'remote_addr': '10.66.0.40',
                               'username': 'test2', 'password': 'test2', 'ca': ca_cert, 'remote_port': 1195},
                'db_fields': {'remote_addr': '10.66.0.40', 'remote_port': '1195'},
                'desc': '自定义端口1195',
            },
            {
                'name': 'ovpnip1',
                'add_kwargs': {'name': 'ovpnip1', 'remote_addr': '192.168.202.1',
                               'username': 'user1', 'password': 'pass1', 'ca': ca_cert, 'comment': '测落库'},
                'db_fields': {'remote_addr': '192.168.202.1'},
                'desc': '随意服务器IP(CA证书必填, 验证落库)',
            },
        ]

        ssh_failures = []
        ui_failures = []
        run_vpn_comprehensive_test(
            page=openvpn_client_page_logged_in, rec=step_recorder, request=request,
            module_key='openvpn', test_rules=test_rules,
            invalid_base_fields={'remote_addr': '10.66.0.40', 'username': 'x',
                                 'password': 'x', 'ca': ca_cert},
            edit_spec={
                'target': 'ovpnauto1', 'new_name': 'ovpnedit1',
                'field_updates': {'comment': '编辑后备注'},
                'db_fields': {'comment': '编辑后备注'},
            },
            ssh_failures=ssh_failures, ui_failures=ui_failures,
        )
        all_failures = ssh_failures + ui_failures
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
