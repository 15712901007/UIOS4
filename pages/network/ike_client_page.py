"""IKEv2/IPSec客户端页面类 (网络配置→内外网设置→VPN客户端→IKEv2/IPSec)

数据库表: ike_client (底层脚本 ike_client.sh, strongswan/charon进程, ipsec sa)
表单字段(id): name*(iked开头) | authby*(类型,select "IKEv2/IPsec MSCHAPv2"=mschapv2 / 预共享密钥=secret) |
  remote_addr*(服务器地址/域名) | username*(用户名) | passwd*(密码) |
  leftid*(本地标识,unique!) | rightid(对方标识) | interface*(线路,自动) |
  check_link_mode*(HTTP+网关) | check_link_host | comment(备注)
列表列: 拨号名称|类型|服务器地址/域名|线路|本地IP|备注|操作

注意: authby=mschapv2(默认)需username/passwd/leftid; =secret需secret字段
      leftid必须unique(多人拨号不能重复)
"""
from pages.network.vpn_client_base import VpnClientBasePage


class IkeClientPage(VpnClientBasePage):
    """IKEv2/IPSec客户端(拨号名称iked开头, 默认MSCHAPv2认证, leftid唯一)"""

    MODULE_NAME = "ike_client"
    SUBTAB = "IKEv2/IPSec"
    ADD_URL_TYPE = "IKEv2IPSec"
    NAME_PREFIX = "iked"

    def navigate_to_ike(self):
        return self.navigate_to_module()

    def add_rule(self, name, remote_addr, leftid, username, passwd,
                 comment=None):
        """添加IKEv2/IPSec客户端规则(默认MSCHAPv2认证)

        必填: name(iked开头)/remote_addr(服务器)/leftid(本地标识,unique)/username/passwd
        其余用默认(MSCHAPv2认证/自动线路/HTTP+网关检测)
        """
        self.click_add_button()
        self.page.wait_for_timeout(1500)
        self._wait_add_form()
        self._set_input('name', name)
        self._set_input('remote_addr', remote_addr)
        self._set_input('username', username)
        self._set_input('passwd', passwd)
        self._set_input('leftid', leftid)
        if comment:
            self._set_textarea('comment', comment)
        return self._save_and_verify()
