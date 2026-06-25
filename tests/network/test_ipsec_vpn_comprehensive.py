"""IPSec VPN综合测试用例 (site-to-site隧道)

网络配置→内外网设置→VPN客户端→IPSec VPN
SSH后台: L1数据库(ipsec_vpn表, must_pass) + L2连接(ipsec sa/charon, 软断言)
字段映射: name(ipsec开头,仅ascii)/remote_addr(对方IP,非必填)/leftsubnet(本地子网,input)/
          rightsubnet(对方子网,textarea)/authby(认证方式,预共享密钥)/secret(预共享密钥,密文)/
          keyexchange(IKE版本,IKEv2)/ikelifetime/lifetime(ESP)/dpdaction(DPD)/comment
注意: remote_addr非必填(支持对端动态IP); secret密文不验证; site-to-site状态列非本地IP
"""
import pytest
from pages.network.ipsec_vpn_page import IpsecVpnPage
from utils.step_recorder import StepRecorder
from tests.network.vpn_test_helper import run_vpn_comprehensive_test


@pytest.mark.ipsec_vpn
@pytest.mark.network
class TestIpsecVpnComprehensive:
    """IPSec VPN综合测试(site-to-site, 本地/对方子网+预共享密钥必填)"""

    def test_ipsec_vpn_comprehensive(self, ipsec_vpn_page_logged_in: IpsecVpnPage,
                                      step_recorder: StepRecorder, request):
        test_rules = [
            {
                'name': 'ipsecauto1',
                'add_kwargs': {'name': 'ipsecauto1', 'leftsubnet': '192.168.1.0/24',
                               'rightsubnet': '10.0.0.0/24', 'secret': 'ikuaipsk01',
                               'remote_addr': '10.66.0.40', 'comment': 'IPSec对端测试'},
                'db_fields': {'leftsubnet': '192.168.1.0/24', 'rightsubnet': '10.0.0.0/24'},
                'desc': 'site-to-site(对端10.66.0.40)',
            },
            {
                'name': 'ipsecnoip1',
                'add_kwargs': {'name': 'ipsecnoip1', 'leftsubnet': '192.168.2.0/24',
                               'rightsubnet': '10.0.1.0/24', 'secret': 'ikuaipsk02',
                               'leftid': 'localid2', 'rightid': 'remoteid2'},
                'db_fields': {'leftsubnet': '192.168.2.0/24', 'rightsubnet': '10.0.1.0/24'},
                'desc': '无对端IP用标识(leftid+rightid替代remote_addr)',
            },
            {
                'name': 'ipsecsub1',
                'add_kwargs': {'name': 'ipsecsub1', 'leftsubnet': '192.168.3.0/24',
                               'rightsubnet': '10.0.2.0/24', 'secret': 'ikuaipsk03',
                               'remote_addr': '10.66.0.40'},
                'db_fields': {'leftsubnet': '192.168.3.0/24', 'rightsubnet': '10.0.2.0/24'},
                'desc': '不同子网组合',
            },
        ]

        ssh_failures = []
        ui_failures = []
        run_vpn_comprehensive_test(
            page=ipsec_vpn_page_logged_in, rec=step_recorder, request=request,
            module_key='ipsec', test_rules=test_rules,
            invalid_base_fields={'leftsubnet': '192.168.99.0/24',
                                 'rightsubnet': '10.0.99.0/24', 'secret': 'sk'},
            edit_spec={
                'target': 'ipsecauto1',
                'field_updates': {'comment': '编辑后备注'},
                'db_fields': {'comment': '编辑后备注'},
            },
            ssh_failures=ssh_failures, ui_failures=ui_failures,
        )
        all_failures = ssh_failures + ui_failures
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
