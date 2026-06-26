"""
IPv6外网设置页面操作类

网络配置 > 内外网设置 > IPv6设置 > 外网设置 tab
URL: /login#/networkConfiguration/internalAndExternalNetworkSettings
  (IPv6设置是顶部第2个tab, 外网设置是其第1个子tab)
添加/编辑为独立页面:
  - 添加: /login#/networkConfiguration/internalAndExternalNetworkSettings/ipv6Settings/extranetSetting/add
  - 编辑: .../ipv6Settings/extranetSetting/edit/<id>

页面特点: 表格型(IPv6 WAN线路), 添加/编辑为独立页面, 表单字段全#id定位。

实测表单结构 (2026-06-26 UI探查):
- 顶部IPv6信息条(只读, dhcp6_ip_addr/dhcp6_ip_gateway/dhcp6_prefix1/dhcp6_dns1/dhcp6_dns2)
- 名称*: id=tagname (必填)
- IPv6 启用: id=enabled (checkbox, 默认勾选=enabled:yes)
- 外网接口*: id=interface (combobox, 默认wan1, 可选wan1/wan2/wan3)
- 接入方式*: id=internet (combobox, 默认DHCPv6客户端(动态获取)=dhcp,
            可选 DHCPv6客户端(动态获取)/静态IP(固定IP)/中继模式)
- [dhcp模式可见]:
  - 请求前缀长度*: id=prefix (combobox, 默认自动, 可选自动/60/62/64)
  - 尝试固定前缀: id=prefix_hint (textbox)
  - 强行获取前缀: id=force_prefix (checkbox)
  - 客户端DUID标识*: id=force_gen_duid (combobox, 默认随机生成)
- [static模式可见]:
  - IPv6地址*: id=ipv6_addr (textbox)
  - IPv6网关*: id=ipv6_gateway (textbox)

数据库字段映射 (从后端脚本ipv6.sh wan_add/wan_edit确认):
- ipv6_wan_config表:
  id, enabled(yes/no), tagname(名称unique), interface(外网接口, unique),
  internet(dhcp/static/relay), link_addr(本地链接IPv6, 由interface自动生成),
  ipv6_addr(static模式LAN IPv6地址), ipv6_gateway(static模式IPv6网关),
  prefix(请求前缀长度auto/60/62/64), prefix_hint(尝试固定前缀),
  force_prefix(强行获取前缀0/1), force_gen_duid(客户端DUID标识)

后端关键约束 (ipv6.sh):
- wan_add/__check_param_save: enabled/interface(ifname_wan)/tagname/internet(dhcp|static|relay)
  + dhcp时prefix(auto|60|62|64)+prefix_hint(空或ipv6)
- multi_unsupport: 企业版PKG_PATH num=3, count>=num时报"已达上限"(免费版num=1)
  即WAN线路总数上限3条(当前测试设备企业版), 添加第4条会被拒
- wan_del/wan_edit/wan_up/wan_down: 启用时配置odhcp6c/ipset ipv6_prefix_$interface
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class Ipv6WanPage(IkuaiTablePage):
    """IPv6外网设置页面操作类(表格型, 独立页面表单全#id)"""

    MODULE_NAME = "ipv6_wan"
    PAGE_URL = "/login#/networkConfiguration/internalAndExternalNetworkSettings"
    ADD_URL = "/login#/networkConfiguration/internalAndExternalNetworkSettings/ipv6Settings/extranetSetting/add"

    # 接入方式 (internet) UI文案 -> 后端值
    INTERNET_DHCP = "DHCPv6客户端(动态获取)"     # internet=dhcp
    INTERNET_STATIC = "静态IP(固定IP)"           # internet=static
    INTERNET_RELAY = "中继模式"                  # internet=relay

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def _dismiss_residual_modal(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def navigate_to_ipv6_wan(self):
        """导航到 内外网设置 > IPv6设置 > 外网设置 tab"""
        self._dismiss_residual_modal()
        url = f"{self.base_url}{self.PAGE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(800)
        self._dismiss_residual_modal()
        try:
            # 点击顶部"IPv6设置"tab(第2个)
            self.page.evaluate("""() => {
                const tabs = Array.from(document.querySelectorAll('.ant-tabs-tab'));
                const t = tabs.find(x => x.textContent.trim() === 'IPv6设置');
                if (t && t.getAttribute('aria-selected') !== 'true') t.click();
            }""")
            self.page.wait_for_timeout(800)
            # 确保"外网设置"子tab选中(第1个子tab)
            self.page.evaluate("""() => {
                const subs = Array.from(document.querySelectorAll('.ant-tabs-tab'));
                const s = subs.find(x => x.textContent.trim() === '外网设置');
                if (s && s.getAttribute('aria-selected') !== 'true') s.click();
            }""")
            self.page.wait_for_timeout(500)
        except Exception as e:
            logger.warning(f"[导航] 切换IPv6外网设置tab异常: {e}")
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面回到外网设置列表"""
        return self.navigate_to_ipv6_wan()

    # ==================== 表单字段(全#id) ====================

    def _set_input(self, field_id: str, value: str):
        """用原生setter填写#id文本框(React安全, 触发onChange)"""
        try:
            self.page.evaluate("""([fid, val]) => {
                const el = document.getElementById(fid);
                if (!el) return false;
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value').set;
                setter.call(el, val);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                return true;
            }""", [field_id, value])
            self.page.wait_for_timeout(150)
        except Exception as e:
            logger.warning(f"[表单] 填写#{field_id}异常: {e}")
        return self

    def fill_name(self, name: str):
        """名称 (id=tagname)"""
        return self._set_input("tagname", name)

    def fill_prefix_hint(self, hint: str):
        """尝试固定前缀 (id=prefix_hint)"""
        return self._set_input("prefix_hint", hint)

    def fill_ipv6_addr(self, addr: str):
        """IPv6地址 (id=ipv6_addr, static模式)"""
        return self._set_input("ipv6_addr", addr)

    def fill_ipv6_gateway(self, gw: str):
        """IPv6网关 (id=ipv6_gateway, static模式)"""
        return self._set_input("ipv6_gateway", gw)

    def set_checkbox(self, field_id: str, checked: bool):
        """勾选/取消#id checkbox(enabled/force_prefix), 用Playwright真实点击触发React"""
        try:
            cb = self.page.locator(f'#{field_id}')
            if cb.count() > 0:
                # Ant checkbox: 点input或其wrapper. 先读当前状态再决定是否切换
                is_checked = cb.is_checked()
                if is_checked != checked:
                    # 点击wrapper(.ant-checkbox-wrapper)更可靠
                    wrapper = self.page.locator(f'.ant-checkbox-wrapper:has(#{field_id})')
                    if wrapper.count() > 0:
                        wrapper.first.click()
                    else:
                        cb.first.click(force=True)
                    self.page.wait_for_timeout(200)
        except Exception as e:
            logger.warning(f"[表单] 设置#{field_id}={checked}异常: {e}")
        return self

    def _select_combobox(self, field_id: str, option_text: str) -> bool:
        """选择#field_id combobox的选项(打开下拉+JS点选项)
        Ant Select的JS element.click()不触发React, 故先用Playwright点selector打开,
        再JS点击可见下拉中的选项(选项点击element.click()可靠, 同其他模块).
        """
        try:
            # 打开下拉: 点含#field_id的ant-select的selector
            sel = self.page.locator(f'.ant-select:has(#{field_id}) .ant-select-selector')
            if sel.count() == 0:
                logger.warning(f"[表单] #{field_id} combobox未找到")
                return False
            sel.first.click()
            self.page.wait_for_timeout(700)
            # JS点击可见下拉中匹配的选项
            clicked = self.page.evaluate("""(text) => {
                const dd = Array.from(document.querySelectorAll('.ant-select-dropdown'))
                    .filter(d => d.offsetHeight > 0);
                for (const d of dd) {
                    const opts = d.querySelectorAll('.ant-select-item-option');
                    for (const o of opts) {
                        if (o.textContent.trim() === text ||
                            o.getAttribute('title') === text) {
                            o.click(); return true;
                        }
                    }
                }
                return false;
            }""", option_text)
            if clicked:
                self.page.wait_for_timeout(400)
                return True
        except Exception as e:
            logger.warning(f"[表单] 选择#{field_id}={option_text}异常: {e}")
        # 关闭可能残留的下拉
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass
        return False

    def select_interface(self, iface: str = "wan2"):
        """外网接口 (id=interface, 默认wan1, 测试用wan2/wan3避开管理口wan1)"""
        return self._select_combobox("interface", iface)

    def select_internet(self, mode: str):
        """接入方式 (id=internet). mode为UI文案: DHCPv6客户端(动态获取)/静态IP(固定IP)/中继模式"""
        return self._select_combobox("internet", mode)

    def select_prefix(self, prefix: str = "自动"):
        """请求前缀长度 (id=prefix, 自动/60/62/64)"""
        return self._select_combobox("prefix", prefix)

    # ==================== 规则列表查询 ====================

    def get_rule_list(self) -> List[str]:
        """获取外网设置规则名称列表(tagname列)"""
        try:
            names = self.page.evaluate("""() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                for (const row of rows) {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length > 1) {
                        // 名称是第2列(第1列是checkbox), 取非空且非'暂无内容'
                        const name = cells[1].textContent.trim();
                        if (name && name !== '暂无内容') result.push(name);
                    }
                }
                return result;
            }""")
            return names if names else []
        except Exception:
            return []

    # ==================== 添加规则(完整流程) ====================

    def open_add_page(self):
        """进入独立添加页(直接导航ADD_URL最可靠, 避免click_add_button与tab切换时序竞争)"""
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        self.page.wait_for_load_state("networkidle")
        try:
            self.page.wait_for_selector('#tagname', timeout=10000)
        except Exception:
            self.page.wait_for_timeout(1000)
        self.page.wait_for_timeout(500)
        return self

    def _read_save_result(self) -> tuple:
        """读取保存后结果(success, message). 轮询~6s:
        成功=URL离开/add|/edit 或 .ant-message-success; 失败=错误消息.

        注意: 独立页表单保存成功后会跳转回列表(异步, 可能>1.5s), 故不能只等一次.
        """
        try:
            for _ in range(12):  # 12 x 500ms = 6s
                self.page.wait_for_timeout(500)
                # 错误消息优先(后端校验失败/上限拦截)
                err = self.page.locator(
                    '.ant-message-error:visible, .ant-message-notice .ant-message-error:visible')
                if err.count() > 0:
                    return (False, err.first.text_content().strip()[:120])
                form_err = self.page.locator('.ant-form-item-explain-error:visible')
                if form_err.count() > 0:
                    return (False, form_err.first.text_content().strip()[:120])
                # 成功: URL已离开/add|/edit(跳回列表)
                cur = self.page.url
                if "/add" not in cur and "/edit" not in cur:
                    return (True, "已返回列表")
                # 成功: success toast
                ok = self.page.locator('.ant-message-success:visible')
                if ok.count() > 0:
                    return (True, ok.first.text_content().strip()[:120])
            # 超时: 仍在表单页 -> 失败
            cur = self.page.url
            if "/add" not in cur and "/edit" not in cur:
                return (True, "已返回列表")
            return (False, "")
        except Exception:
            return (False, "")

    def add_rule(self, name: str,
                 interface: str = "wan2",
                 internet: str = "DHCPv6客户端(动态获取)",
                 enabled: bool = True,
                 prefix: str = "自动",
                 prefix_hint: str = None,
                 force_prefix: bool = False,
                 ipv6_addr: str = None,
                 ipv6_gateway: str = None) -> bool:
        """添加IPv6外网设置规则

        Args:
            name: 名称(tagname, 必填)
            interface: 外网接口(默认wan2避开管理口wan1)
            internet: 接入方式UI文案(DHCPv6客户端(动态获取)/静态IP(固定IP)/中继模式)
            enabled: 是否启用(默认True)
            prefix: 请求前缀长度(dhcp模式, 自动/60/62/64)
            prefix_hint: 尝试固定前缀(dhcp模式)
            force_prefix: 强行获取前缀(dhcp模式)
            ipv6_addr: IPv6地址(static模式, 必填)
            ipv6_gateway: IPv6网关(static模式, 必填)
        """
        try:
            self.open_add_page()
            self.fill_name(name)
            self.set_checkbox("enabled", enabled)
            self.select_interface(interface)
            self.page.wait_for_timeout(300)
            self.select_internet(internet)
            self.page.wait_for_timeout(500)

            is_static = (internet == self.INTERNET_STATIC)
            if is_static:
                if ipv6_addr:
                    self.fill_ipv6_addr(ipv6_addr)
                if ipv6_gateway:
                    self.fill_ipv6_gateway(ipv6_gateway)
            else:
                # dhcp/relay模式: 请求前缀长度等
                self.select_prefix(prefix)
                self.page.wait_for_timeout(300)
                if prefix_hint:
                    self.fill_prefix_hint(prefix_hint)
                self.set_checkbox("force_prefix", force_prefix)

            self.click_save()
            success, msg = self._read_save_result()
            print(f"  [add_rule] {name}: success={success}, msg={msg[:60]}")
            if not success:
                try:
                    self.click_cancel()
                except Exception:
                    self.page.keyboard.press("Escape")
                self.navigate_back_to_list()
                return False
            self.navigate_back_to_list()
            self.page.wait_for_timeout(500)
            return True
        except Exception as e:
            print(f"[ERROR] 添加IPv6外网设置失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 编辑/复制/停用/启用/删除 ====================

    def edit_rule(self, old_name: str, new_name: str = None,
                  prefix_hint: str = None, ipv6_addr: str = None) -> bool:
        """编辑IPv6外网设置规则"""
        try:
            clicked = self._click_rule_button(old_name, "编辑")
            if not clicked:
                print(f"[WARN] 编辑按钮未找到: {old_name}")
                return False
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector('#tagname', timeout=8000)
            except Exception:
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(800)

            if new_name is not None:
                self.fill_name(new_name)
            if prefix_hint is not None:
                self.fill_prefix_hint(prefix_hint)
            if ipv6_addr is not None:
                self.fill_ipv6_addr(ipv6_addr)

            self.click_save()
            success, msg = self._read_save_result()
            print(f"  [edit_rule] {old_name}: success={success}, msg={msg[:60]}")
            if success:
                self.navigate_back_to_list()
                return True
            try:
                self.click_cancel()
            except Exception:
                self.page.keyboard.press("Escape")
            self.navigate_back_to_list()
            return False
        except Exception as e:
            print(f"[ERROR] 编辑IPv6外网设置失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    def copy_rule(self, rule_name: str, new_name: str) -> bool:
        """复制规则(进入新增页预填, 改名保存)"""
        try:
            clicked = self._click_rule_button(rule_name, "复制")
            if not clicked:
                return False
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector('#tagname', timeout=8000)
            except Exception:
                self.page.wait_for_timeout(800)
            self.fill_name(new_name)
            self.click_save()
            success, msg = self._read_save_result()
            if success:
                self.navigate_back_to_list()
                return True
            try:
                self.click_cancel()
            except Exception:
                self.page.keyboard.press("Escape")
            self.navigate_back_to_list()
            return False
        except Exception as e:
            print(f"[ERROR] 复制IPv6外网设置失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    def delete_rule(self, rule_name: str) -> bool:
        """删除规则(有确认弹窗)"""
        return super().delete_rule(rule_name)

    # ==================== 异常输入测试 ====================

    def try_add_rule_invalid(self, name: str = "",
                             interface: str = None,
                             internet: str = None,
                             ipv6_addr: str = None,
                             ipv6_gateway: str = None,
                             expect_fail: bool = True) -> dict:
        """尝试添加无效规则, 测试表单/后端校验. 只填提供的字段.

        轮询~5s判断: 出现错误提示(可见)=被拦截; URL离开/add|/edit=已保存(未拦截).
        """
        try:
            self.open_add_page()
            self.page.wait_for_timeout(300)
            if name is not None:
                self.fill_name(name)
            if interface:
                self.select_interface(interface)
                self.page.wait_for_timeout(200)
            if internet:
                self.select_internet(internet)
                self.page.wait_for_timeout(500)
            if ipv6_addr:
                self.fill_ipv6_addr(ipv6_addr)
            if ipv6_gateway:
                self.fill_ipv6_gateway(ipv6_gateway)

            self.click_save()
            intercepted = False
            msg = ""
            for _ in range(10):  # 10 x 500ms = 5s
                self.page.wait_for_timeout(500)
                err = self.page.locator(
                    '.ant-form-item-explain-error:visible, '
                    '.ant-message-error:visible')
                if err.count() > 0:
                    intercepted = True
                    msg = err.first.text_content().strip()[:120]
                    break
                cur = self.page.url
                if "/add" not in cur and "/edit" not in cur:
                    # 已离开表单页 = 保存成功(未拦截)
                    intercepted = False
                    break
            if expect_fail:
                self._safe_back()
                return {"success": intercepted, "error_message": msg}
            return {"success": True, "error_message": ""}
        except Exception as e:
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return {"success": False, "error_message": str(e)}

    def _safe_back(self):
        try:
            self.click_cancel()
        except Exception:
            self.page.keyboard.press("Escape")
        self.page.wait_for_timeout(300)
        if "/add" in self.page.url or "/edit" in self.page.url:
            self.navigate_back_to_list()
