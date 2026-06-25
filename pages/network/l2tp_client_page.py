"""L2TP客户端页面类 (网络配置→内外网设置→VPN客户端→L2TP)

数据库表: l2tp_client (底层脚本 l2tp_client.sh, 进程xl2tpd, 拨号生成ppp接口)
表单字段(id): name*(l2tp开头) | server_port*(1701) | server*(服务器) |
  username*(用户名) | passwd*(密码) | mtu*(1400) | mru*(1400) |
  ipsec_secret(预共享密钥) | leftid(本地标识) | rightid(对方标识) |
  interface*(线路,自动) | cycle_rst_time*(0) | timing_rst_switch(checkbox) |
  check_link_mode*(HTTP+网关) | check_link_host | comment(备注)
列表列同PPTP: 拨号名称|服务器地址/域名|用户名|密码|线路|本地IP|备注|操作
"""
from pages.network.vpn_client_base import VpnClientBasePage


class L2tpClientPage(VpnClientBasePage):
    """L2TP客户端(拨号名称l2tp开头, 默认端口1701, 可选IPSec预共享密钥)"""

    MODULE_NAME = "l2tp_client"
    SUBTAB = "L2TP"
    ADD_URL_TYPE = "L2TP"
    NAME_PREFIX = "l2tp"

    def navigate_to_l2tp(self):
        return self.navigate_to_module()

    def add_rule(self, name, server, username, passwd,
                 server_port=None, mtu=None, mru=None,
                 ipsec_secret=None, leftid=None, rightid=None,
                 comment=None):
        """添加L2TP客户端规则

        必填: name(l2tp开头)/server/username/passwd
        可选: ipsec_secret/leftid/rightid(L2TP/IPSec预共享密钥+标识)
        """
        self.click_add_button()
        self.page.wait_for_timeout(1500)
        self._wait_add_form()
        self._set_input('name', name)
        if server_port is not None:
            self._set_input('server_port', str(server_port))
        self._set_input('server', server)
        self._set_input('username', username)
        self._set_input('passwd', passwd)
        if mtu is not None:
            self._set_input('mtu', str(mtu))
        if mru is not None:
            self._set_input('mru', str(mru))
        if ipsec_secret is not None:
            self._set_input('ipsec_secret', ipsec_secret)
        if leftid is not None:
            self._set_input('leftid', leftid)
        if rightid is not None:
            self._set_input('rightid', rightid)
        if comment is not None:
            self._set_textarea('comment', comment)
        return self._save_and_verify()
