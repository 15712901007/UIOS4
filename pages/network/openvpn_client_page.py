"""OpenVPN客户端页面类 (网络配置→内外网设置→VPN客户端→OpenVPN)

数据库表: openvpn_client (底层脚本 openvpn-client.sh, 进程openvpn, 拨号生成tun接口)
表单字段(id): name*(ovpn开头) | remote_addr*(服务器) | remote_port*(1194) |
  method*(认证方式,select 账号认证=0/tls-auth=1/tls-crypt=2) | username*(用户名) |
  password*(密码) | interface*(线路,自动) | proto*(隧道协议,select UDP) |
  dev_type*(隧道类型,select TUN) | cipher*(加密算法,select BF-CBC) |
  comp_lzo(LZO压缩,checkbox) | tun_mtu*(1400) | ca*(CA证书,textarea必填!) |
  cert(客户端证书,textarea) | key(客户端私钥,textarea) | extra_config(附加配置,textarea) |
  accept_push_route(服务器路由推送,checkbox) | route(添加路由,textarea) |
  timing_rst_switch(checkbox) | check_link_mode*(HTTP+网关) | check_link_host | comment(备注)
列表列: 拨号名称|服务器地址/域名|服务端口|线路|隧道协议|隧道类型|本地IP|备注|操作

注意: method=账号认证(默认)时, CA证书+用户名+密码必填; tls-auth/tls-crypt需tls_auth静态密钥
      CA证书从 test_data/vpn/openvpn_ca.pem 读取(自签名, 通过表单校验)
"""
from pages.network.vpn_client_base import VpnClientBasePage


class OpenvpnClientPage(VpnClientBasePage):
    """OpenVPN客户端(拨号名称ovpn开头, 默认1194/UDP/TUN, CA证书必填)"""

    MODULE_NAME = "openvpn_client"
    SUBTAB = "OpenVPN"
    ADD_URL_TYPE = "openvpn"
    NAME_PREFIX = "ovpn"

    def navigate_to_openvpn(self):
        return self.navigate_to_module()

    def add_rule(self, name, remote_addr, username, password, ca,
                 remote_port=None, proto=None, dev_type=None, cipher=None,
                 tun_mtu=None, cert=None, key=None, comment=None,
                 method=None):
        """添加OpenVPN客户端规则

        必填: name(ovpn开头)/remote_addr/username/password/ca(CA证书)
        可选: proto(UDP)/dev_type(TUN)/cipher(BF-CBC)/tun_mtu(1400)/cert/key/method(认证方式)
        """
        self.click_add_button()
        self.page.wait_for_timeout(1500)
        self._wait_add_form()
        self._set_input('name', name)
        self._set_input('remote_addr', remote_addr)
        if remote_port is not None:
            self._set_input('remote_port', str(remote_port))
        if method is not None and method != "账号认证":
            self._select_field('认证方式', method)
        self._set_input('username', username)
        self._set_input('password', password)
        if proto:
            self._select_field('隧道协议', proto)
        if dev_type:
            self._select_field('隧道类型', dev_type)
        if cipher:
            self._select_field('加密算法', cipher)
        if tun_mtu is not None:
            self._set_input('tun_mtu', str(tun_mtu))
        self._set_textarea('ca', ca)  # CA证书必填
        if cert:
            self._set_textarea('cert', cert)
        if key:
            self._set_textarea('key', key)
        if comment:
            self._set_textarea('comment', comment)
        return self._save_and_verify()
