"""虚拟专网→旧版IPsec综合测试 (site-to-site隧道)。

SSH后台: L1数据库(ipsec_vpn表, must_pass) + L2连接(ipsec sa/charon, 软断言)
字段映射: name(ipsec开头,仅ascii)/remote_addr(对方IP,非必填)/leftsubnet(本地子网)/
          rightsubnet(对方子网)/authby(认证方式)/secret(预共享密钥,密文)/
          keyexchange(IKE版本)/ikelifetime/lifetime/dpdaction/comment
"""

import pytest

from pages.network.old_ipsec_vpn_page import OldIpsecVpnPage
from tests.network.vpn_test_helper import run_vpn_comprehensive_test
from utils.step_recorder import StepRecorder


@pytest.mark.old_ipsec_vpn
@pytest.mark.network
class TestOldIpsecVpnComprehensive:
    """旧版IPsec综合测试。"""

    def test_old_ipsec_vpn_comprehensive(
        self,
        old_ipsec_vpn_page_logged_in: OldIpsecVpnPage,
        step_recorder: StepRecorder,
        request,
    ):
        test_rules = [
            {
                "name": "ipsecauto1",
                "add_kwargs": {
                    "name": "ipsecauto1",
                    "leftsubnet": "192.168.1.0/24",
                    "rightsubnet": "10.0.0.0/24",
                    "secret": "ikuaipsk01",
                    "remote_addr": "10.66.0.40",
                    "comment": "旧版IPsec对端测试",
                },
                "db_fields": {
                    "leftsubnet": "192.168.1.0/24",
                    "rightsubnet": "10.0.0.0/24",
                },
                "desc": "site-to-site(对端10.66.0.40)",
            },
            {
                "name": "ipsecnoip1",
                "add_kwargs": {
                    "name": "ipsecnoip1",
                    "leftsubnet": "192.168.2.0/24",
                    "rightsubnet": "10.0.1.0/24",
                    "secret": "ikuaipsk02",
                    "leftid": "localid2",
                    "rightid": "remoteid2",
                },
                "db_fields": {
                    "leftsubnet": "192.168.2.0/24",
                    "rightsubnet": "10.0.1.0/24",
                },
                "desc": "无对端IP，使用本地/对方标识",
            },
            {
                "name": "ipsecsub1",
                "add_kwargs": {
                    "name": "ipsecsub1",
                    "leftsubnet": "192.168.3.0/24",
                    "rightsubnet": "10.0.2.0/24",
                    "secret": "ikuaipsk03",
                    "remote_addr": "10.66.0.40",
                },
                "db_fields": {
                    "leftsubnet": "192.168.3.0/24",
                    "rightsubnet": "10.0.2.0/24",
                },
                "desc": "不同子网组合",
            },
        ]

        ssh_failures = []
        ui_failures = []
        run_vpn_comprehensive_test(
            page=old_ipsec_vpn_page_logged_in,
            rec=step_recorder,
            request=request,
            module_key="ipsec",
            test_rules=test_rules,
            invalid_base_fields={
                "leftsubnet": "192.168.99.0/24",
                "rightsubnet": "10.0.99.0/24",
                "secret": "sk",
            },
            edit_spec={
                "target": "ipsecauto1",
                "field_updates": {"comment": "编辑后备注"},
                "db_fields": {"comment": "编辑后备注"},
            },
            ssh_failures=ssh_failures,
            ui_failures=ui_failures,
        )
        all_failures = ssh_failures + ui_failures
        assert not all_failures, (
            f"旧版IPsec验证失败({len(all_failures)}项): "
            f"{'; '.join(all_failures)}"
        )
