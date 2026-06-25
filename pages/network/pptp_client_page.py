"""PPTP客户端页面类 (网络配置→内外网设置→VPN客户端→PPTP)

数据库表: pptp_client (底层脚本 pptp_client.sh, 进程pppd, 拨号生成ppp接口)
表单字段(id): name*(拨号名称,pptp开头) | server_port*(1723) | server*(服务器) |
  username*(用户名) | passwd*(密码) | mtu*(1400) | mru*(1400) | interface*(线路,select自动) |
  cycle_rst_time*(间隔重拨,0) | timing_rst_switch(定时重拨,checkbox) |
  check_link_mode*(线路检测,select HTTP+网关) | check_link_host(检测域名) | comment(备注)
列表列: 拨号名称|服务器地址/域名|用户名|密码|线路|本地IP|备注|操作
"""
from pages.network.vpn_client_base import VpnClientBasePage


class PptpClientPage(VpnClientBasePage):
    """PPTP客户端(拨号名称pptp开头, 默认端口1723)"""

    MODULE_NAME = "pptp_client"
    SUBTAB = "PPTP"
    ADD_URL_TYPE = "PPTP"
    NAME_PREFIX = "pptp"

    def navigate_to_pptp(self):
        return self.navigate_to_module()

    def add_rule(self, name, server, username, passwd,
                 server_port=None, mtu=None, mru=None,
                 comment=None, check_link_host=None,
                 enable_timing=False):
        """添加PPTP客户端规则

        必填: name(pptp开头)/server/username/passwd, 其余用默认(1723/1400/自动/HTTP+网关)
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
        if enable_timing:
            self._set_checkbox('定时重拨', True)
        if check_link_host is not None:
            self._set_input('check_link_host', check_link_host)
        if comment is not None:
            self._set_textarea('comment', comment)
        return self._save_and_verify()
