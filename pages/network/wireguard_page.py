"""WireGuard客户端页面类 (网络配置→内外网设置→VPN客户端→WireGuard)

数据库表: wireguard (底层脚本 wireguard.sh, wg接口, peer在wireguard_peers表)
表单字段(id, 仅本地配置): name*(服务接口,wg开头) | local_address*(本地地址,10.0.8.1/24,unique) |
  local_publickey*(本地公钥,自动生成) | "生成本地密钥"按钮 | local_privatekey*(本地私钥,自动生成) |
  interface*(线路,自动) | local_listenport*(监听端口,50000) | mtu*(1420)
列表列: 服务接口|本地地址|监听端口|线路|操作 (无本地IP/状态/备注列, 行内有"添加隧道"按钮配peer)

注意: peer对端配置在独立wireguard_peers表(列表"添加隧道"按钮), 添加表单只配本地
      公私钥进页面默认自动生成(有值), 兜底点"生成本地密钥"按钮
      local_address必须unique(每条不同网段)
"""
from pages.network.vpn_client_base import VpnClientBasePage


class WireguardPage(VpnClientBasePage):
    """WireGuard客户端(服务接口wg开头, 本地地址唯一, 公私钥自动生成)"""

    MODULE_NAME = "wireguard"
    SUBTAB = "WireGuard"
    ADD_URL_TYPE = "WireGuard"
    NAME_PREFIX = "wg"

    def navigate_to_wireguard(self):
        return self.navigate_to_module()

    def add_rule(self, name, local_address=None, local_listenport=None,
                 mtu=None):
        """添加WireGuard规则(仅本地配置)

        必填: name(wg开头)/local_address(本地地址,unique)/local_publickey/local_privatekey(自动生成)
        可选: local_listenport(50000)/mtu(1420)
        """
        self.click_add_button()
        self.page.wait_for_timeout(1500)
        self._wait_add_form()
        self._set_input('name', name)
        if local_address:
            self._set_input('local_address', local_address)
        # 公私钥默认自动生成, 兜底: 若私钥为空则点"生成本地密钥"
        try:
            priv = self.page.locator('#local_privatekey')
            if priv.count() > 0 and not priv.first.input_value():
                gen_btn = self.page.locator("button:has-text('生成本地密钥')")
                if gen_btn.count() > 0:
                    gen_btn.first.click()
                    self.page.wait_for_timeout(800)
        except Exception:
            pass
        if local_listenport:
            self._set_input('local_listenport', str(local_listenport))
        if mtu:
            self._set_input('mtu', str(mtu))
        return self._save_and_verify()
