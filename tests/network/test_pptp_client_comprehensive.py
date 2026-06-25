"""PPTP客户端综合测试用例

网络配置→内外网设置→VPN客户端→PPTP
SSH后台: L1数据库(pptp_client表, must_pass硬断言) + L2连接(ppp接口/拨号状态, 软断言)
VPN客户端特性: 启用=自动拨号; 无segmented筛选; 无复制按钮; 本地IP列反映拨号状态
服务端: 10.66.0.40 (L2TP/PPTP账号 test/test)
字段映射: name(拨号名称,pptp开头,仅字母数字下划线≤15)/server(服务器)/username/passwd/server_port(1723)/mtu/mru/comment
注意: 拨号名称name仅支持ascii(pptp开头+字母数字_), 中文无效; comment可中文
"""
import pytest
from pages.network.pptp_client_page import PptpClientPage
from utils.step_recorder import StepRecorder
from tests.network.vpn_test_helper import run_vpn_comprehensive_test


@pytest.mark.pptp_client
@pytest.mark.network
class TestPptpClientComprehensive:
    """PPTP客户端综合测试 - 添加(多场景)+SSH验证+编辑+停用启用删除+搜索+导出+异常+批量+导入+帮助"""

    def test_pptp_client_comprehensive(self, pptp_client_page_logged_in: PptpClientPage,
                                        step_recorder: StepRecorder, request):
        test_rules = [
            {
                'name': 'pptpauto1',
                'add_kwargs': {'name': 'pptpauto1', 'server': '10.66.0.40',
                               'username': 'test', 'passwd': 'test', 'comment': 'PPTP真实可连'},
                'db_fields': {'server': '10.66.0.40', 'username': 'test'},
                'desc': '连10.66.0.40(test/test, 真实可拨号)',
            },
            {
                'name': 'pptpmtu1',
                'add_kwargs': {'name': 'pptpmtu1', 'server': '10.66.0.40',
                               'username': 'test2', 'passwd': 'test2', 'mtu': 1380, 'mru': 1380},
                'db_fields': {'server': '10.66.0.40', 'mtu': '1380', 'mru': '1380'},
                'desc': '自定义MTU/MRU=1380',
            },
            {
                'name': 'pptpip1',
                'add_kwargs': {'name': 'pptpip1', 'server': '192.168.200.1',
                               'username': 'user1', 'passwd': 'pass1', 'comment': '测落库不连'},
                'db_fields': {'server': '192.168.200.1', 'username': 'user1'},
                'desc': '随意服务器IP(不拨号, 验证落库)',
            },
        ]

        ssh_failures = []
        ui_failures = []
        run_vpn_comprehensive_test(
            page=pptp_client_page_logged_in, rec=step_recorder, request=request,
            module_key='pptp', test_rules=test_rules,
            invalid_base_fields={'server': '10.66.0.40', 'username': 'x', 'passwd': 'x'},
            edit_spec={
                'target': 'pptpauto1', 'new_name': 'pptpedit1',
                'field_updates': {'comment': '编辑后备注'},
                'db_fields': {'comment': '编辑后备注'},
            },
            ssh_failures=ssh_failures, ui_failures=ui_failures,
        )
        all_failures = ssh_failures + ui_failures
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"
