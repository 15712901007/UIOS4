"""IKEv2/IPSec客户端综合测试用例

网络配置→内外网设置→VPN客户端→IKEv2/IPSec
SSH后台: L1数据库(ike_client表, must_pass) + L2连接(ipsec sa/charon, 软断言)
字段映射: name(iked开头,仅ascii)/authby(类型,IKEv2/IPsec MSCHAPv2)/remote_addr(服务器)/
          username/passwd(密文)/leftid(本地标识,unique!)/rightid/comment
服务端: 10.66.0.40 (账号 test/test); leftid必须unique
"""
import pytest
from pages.network.ike_client_page import IkeClientPage
from utils.step_recorder import StepRecorder
from tests.network.vpn_test_helper import run_vpn_comprehensive_test


@pytest.mark.ike_client
@pytest.mark.network
class TestIkeClientComprehensive:
    """IKEv2/IPSec客户端综合测试(MSCHAPv2认证, leftid唯一)"""

    def test_ike_client_comprehensive(self, ike_client_page_logged_in: IkeClientPage,
                                       step_recorder: StepRecorder, request):
        test_rules = [
            {
                'name': 'ikedauto1',
                'add_kwargs': {'name': 'ikedauto1', 'remote_addr': '10.66.0.40',
                               'leftid': 'iketest01', 'username': 'test', 'passwd': 'test',
                               'comment': 'IKEv2连接测试'},
                'db_fields': {'remote_addr': '10.66.0.40', 'leftid': 'iketest01', 'username': 'test'},
                'desc': '连10.66.0.40(MSCHAPv2, leftid=iketest01)',
            },
            {
                'name': 'ikedid2',
                'add_kwargs': {'name': 'ikedid2', 'remote_addr': '10.66.0.40',
                               'leftid': 'iketest02', 'username': 'test2', 'passwd': 'test2'},
                'db_fields': {'remote_addr': '10.66.0.40', 'leftid': 'iketest02'},
                'desc': '不同leftid(iketest02)',
            },
            {
                'name': 'ikedip1',
                'add_kwargs': {'name': 'ikedip1', 'remote_addr': '192.168.203.1',
                               'leftid': 'iketest03', 'username': 'user1', 'passwd': 'pass1', 'comment': '测落库'},
                'db_fields': {'remote_addr': '192.168.203.1', 'leftid': 'iketest03'},
                'desc': '随意服务器IP(不拨号, 验证落库)',
            },
        ]

        ssh_failures = []
        ui_failures = []
        run_vpn_comprehensive_test(
            page=ike_client_page_logged_in, rec=step_recorder, request=request,
            module_key='ike', test_rules=test_rules,
            invalid_base_fields={'remote_addr': '10.66.0.40', 'leftid': 'iketestxx',
                                 'username': 'x', 'passwd': 'x'},
            edit_spec={
                'target': 'ikedauto1', 'new_name': 'ikededit1',
                'field_updates': {'comment': '编辑后备注'},
                'db_fields': {'comment': '编辑后备注'},
            },
            ssh_failures=ssh_failures, ui_failures=ui_failures,
        )
        all_failures = ssh_failures + ui_failures
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
