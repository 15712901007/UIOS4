"""L2TP客户端综合测试用例

网络配置→内外网设置→VPN客户端→L2TP
SSH后台: L1数据库(l2tp_client表, must_pass) + L2连接(xl2tpd/ppp接口, 软断言)
字段映射: name(l2tp开头,仅ascii)/server/server_port(1701)/username/passwd/ipsec_secret(预共享密钥,密文)/
          leftid(本地标识)/rightid(对方标识)/mtu/mru/comment
服务端: 10.66.0.40 (L2TP账号 test/test, 含L2TP/IPSec)
"""
import pytest
from pages.network.l2tp_client_page import L2tpClientPage
from utils.step_recorder import StepRecorder
from tests.network.vpn_test_helper import run_vpn_comprehensive_test


@pytest.mark.l2tp_client
@pytest.mark.network
class TestL2tpClientComprehensive:
    """L2TP客户端综合测试(含L2TP/IPSec预共享密钥场景)"""

    def test_l2tp_client_comprehensive(self, l2tp_client_page_logged_in: L2tpClientPage,
                                        step_recorder: StepRecorder, request):
        test_rules = [
            {
                'name': 'l2tpauto1',
                'add_kwargs': {'name': 'l2tpauto1', 'server': '10.66.0.40',
                               'username': 'test', 'passwd': 'test', 'comment': 'L2TP真实可连'},
                'db_fields': {'server': '10.66.0.40', 'username': 'test'},
                'desc': '连10.66.0.40(test/test)',
            },
            {
                'name': 'l2tppsk1',
                'add_kwargs': {'name': 'l2tppsk1', 'server': '10.66.0.40',
                               'username': 'test', 'passwd': 'test',
                               'ipsec_secret': 'ikuai8test', 'leftid': 'l2tpcli', 'rightid': 'l2tpsrv'},
                'db_fields': {'server': '10.66.0.40', 'username': 'test'},
                'desc': 'L2TP/IPSec预共享密钥+标识(passwd/secret密文不验证)',
            },
            {
                'name': 'l2tpip1',
                'add_kwargs': {'name': 'l2tpip1', 'server': '192.168.201.1',
                               'username': 'user1', 'passwd': 'pass1', 'comment': '测落库'},
                'db_fields': {'server': '192.168.201.1'},
                'desc': '随意服务器IP(不拨号)',
            },
        ]

        ssh_failures = []
        ui_failures = []
        run_vpn_comprehensive_test(
            page=l2tp_client_page_logged_in, rec=step_recorder, request=request,
            module_key='l2tp', test_rules=test_rules,
            invalid_base_fields={'server': '10.66.0.40', 'username': 'x', 'passwd': 'x'},
            edit_spec={
                'target': 'l2tpauto1', 'new_name': 'l2tpedit1',
                'field_updates': {'comment': '编辑后备注'},
                'db_fields': {'comment': '编辑后备注'},
            },
            ssh_failures=ssh_failures, ui_failures=ui_failures,
        )
        all_failures = ssh_failures + ui_failures
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
