"""IPSec VPN页面类 (网络配置→内外网设置→VPN客户端→IPSec VPN, site-to-site)

数据库表: ipsec_vpn (底层脚本 ipsec-vpn.sh, strongswan/charon进程, ipsec sa隧道)
表单字段(id): name*(ipsec开头) | remote_addr(对方IP/域名,非必填) |
  leftsubnet*(本地子网,input) | rightsubnet*(对方子网,textarea) | interface*(线路,自动) |
  keyexchange*(IKE版本,select IKEv2) | ikelifetime*(IKE存活,3) |
  ike_enc/ike_auth/ike_dh(IKE提议,select自动协商) | authby*(认证方式,select预共享密钥) |
  secret*(预共享密钥) | leftid(本地标识) | rightid(对方标识) | lifetime*(ESP存活,1) |
  esp_enc/esp_auth(ESP算法,select自动协商) | compress(允许压缩,checkbox) |
  dpdaction*(DPD探测,select关闭) | comment(备注)
列表列: 拨号名称|对方IP/域名|本地子网|对方子网|认证方式|线路|状态|备注|操作 (状态列非本地IP)
"""
from pages.network.vpn_client_base import VpnClientBasePage


class IpsecVpnPage(VpnClientBasePage):
    """IPSec VPN(site-to-site隧道, 本地/对方子网+预共享密钥必填)"""

    MODULE_NAME = "ipsec_vpn"
    SUBTAB = "IPSec VPN"
    ADD_URL_TYPE = "IPestVPN"
    NAME_PREFIX = "ipsec"

    def navigate_to_ipsec(self):
        return self.navigate_to_module()

    def add_rule(self, name, leftsubnet, rightsubnet, secret,
                 remote_addr=None, leftid=None, rightid=None, comment=None):
        """添加IPSec VPN规则(site-to-site)

        必填: name(ipsec开头)/leftsubnet(本地子网)/rightsubnet(对方子网)/secret(预共享密钥)
        可选: remote_addr(对方IP/域名) 或 leftid+rightid(本地/对方标识)
        注意: 省略remote_addr时必须填leftid+rightid(对端动态IP场景用标识替代IP)
        其余用默认(IKEv2/3h/自动协商/1h/DPD关闭)
        """
        self.click_add_button()
        self.page.wait_for_timeout(1500)
        self._wait_add_form()
        self._set_input('name', name)
        if remote_addr:
            self._set_input('remote_addr', remote_addr)
        self._set_input('leftsubnet', leftsubnet)
        self._set_textarea('rightsubnet', rightsubnet)
        self._set_input('secret', secret)
        if leftid:
            self._set_input('leftid', leftid)
        if rightid:
            self._set_input('rightid', rightid)
        if comment:
            self._set_textarea('comment', comment)
        return self._save_and_verify()
