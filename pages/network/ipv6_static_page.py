"""
IPv6前缀静态分配页面操作类

网络配置 > DHCP服务 > IPv6前缀静态分配 页面
URL: /login#/networkConfiguration/dhcpService (IPv6前缀静态分配tab, 5个tab之一)

页面特点: 表格型(DHCPv6-PD前缀静态分配), 添加/编辑为独立页面:
- 添加页: /login#/networkConfiguration/dhcpService/ipv6Static/add
- 表格列: 名称/内网接口/外网线路/备注/操作 (无可排序列)
- 顶部: 添加/导入/导出 + 帮助

数据库: ipv6_dhcp_static_config表 (DHCPv6-PD前缀静态分配)
字段(id/enabled默认yes/tagname unique/link_addr终端本地链接IPv6/src_iface内网接口默认lan1/
      dst_iface外网线路/ipv6_addr/ipv6_addr_len/comment)
约束: tagname唯一, (src_iface,link_addr)组合唯一
后端脚本: /usr/ikuai/script/ipv6_static.sh (add/edit/del/up/down + ipv6.sh add_static/del_static生效)
__check_dst_iface: dst_iface必须在src_iface的parent(IPv6 LAN配置)里, 否则lan_prefix_error

!!环境限制: IPv6前缀静态分配需WAN有IPv6前缀+LAN IPv6配置(ipv6_lan_config)。
  当前测试设备IPv6关闭(ipv6_config.enabled=no), WAN无IPv6前缀, ipv6_lan_config空,
  添加规则会被__check_dst_iface拦截(lan_prefix_error: 内网接口没绑定外网线路)。
  故无法真实CRUD+验证前缀生效, 测试聚焦UI+前端校验+后端拦截验证。
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class Ipv6StaticPage(IkuaiTablePage):
    """IPv6前缀静态分配页面操作类(表格型, 独立页面表单全#id)"""

    MODULE_NAME = "ipv6_static"
    PAGE_URL = "/login#/networkConfiguration/dhcpService"
    ADD_URL = "/login#/networkConfiguration/dhcpService/ipv6Static/add"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def _dismiss_residual_modal(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass
        try:
            modal_btns = self.page.locator('.ant-modal-confirm .ant-btn')
            for i in range(min(modal_btns.count(), 4)):
                btn = modal_btns.nth(i)
                if btn.is_visible():
                    btn.click()
                    self.page.wait_for_timeout(300)
                    break
        except Exception:
            pass

    def navigate_to_ipv6_static(self):
        """导航到DHCP服务 > IPv6前缀静态分配tab"""
        self._dismiss_residual_modal()
        url = f"{self.base_url}{self.PAGE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        self._dismiss_residual_modal()
        try:
            tab = self.page.get_by_role("tab", name="IPv6前缀静态分配")
            if tab.count() > 0:
                selected = tab.get_attribute("aria-selected")
                if selected != "true":
                    tab.click()
                    self.page.wait_for_timeout(1000)
        except Exception as e:
            logger.warning(f"[导航] 切换IPv6前缀静态分配tab异常: {e}")
        logger.info("[导航] 已到达IPv6前缀静态分配页面")
        return self

    def navigate_back_to_list(self):
        return self.navigate_to_ipv6_static()

    # ==================== 表单字段(全#id) ====================

    def fill_name(self, name: str):
        inp = self.page.locator('#tagname')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(name)
            self.page.wait_for_timeout(150)
        return self

    def fill_link_addr(self, addr: str):
        """填写终端本地链接IPv6地址(link-local, 如fe80::1234)"""
        inp = self.page.locator('#link_addr')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(addr)
            self.page.wait_for_timeout(150)
        return self

    def fill_comment(self, comment: str):
        inp = self.page.locator('#comment')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(comment)
            self.page.wait_for_timeout(150)
        return self

    def _click_select(self, field_id: str):
        """点击#field_id的combobox打开下拉"""
        sel = self.page.locator('div.ant-select-selector').filter(
            has=self.page.locator(f'#{field_id}')
        )
        if sel.count() > 0:
            sel.first.click()
            self.page.wait_for_timeout(800)
            return True
        return False

    def _select_option_js(self, option_text: str) -> bool:
        """JS选择下拉选项(子串匹配)"""
        try:
            clicked = self.page.evaluate("""(text) => {
                const dd = document.querySelectorAll('.ant-select-dropdown');
                for (let i = dd.length - 1; i >= 0; i--) {
                    if (dd[i].offsetHeight > 0) {
                        const items = dd[i].querySelectorAll('.ant-select-item');
                        for (const item of items) {
                            if (item.textContent.trim().indexOf(text) >= 0) {
                                item.click(); return true;
                            }
                        }
                    }
                }
                return false;
            }""", option_text)
            return bool(clicked)
        except Exception:
            return False

    def select_src_iface(self, iface: str = "lan1"):
        """选择内网接口"""
        self._click_select("src_iface")
        self._select_option_js(iface)
        self.page.wait_for_timeout(400)
        return self

    def select_dst_iface(self, iface: str = "wan1"):
        """选择外网线路"""
        self._click_select("dst_iface")
        self._select_option_js(iface)
        self.page.wait_for_timeout(400)
        return self

    # ==================== 保存 ====================

    def save_form(self) -> bool:
        """点击保存, 返回(成功?, 错误信息)"""
        try:
            self.page.wait_for_timeout(500)
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() == 0:
                return False
            save_btn.click()
            self.page.wait_for_timeout(2000)
            return True
        except Exception as e:
            logger.error(f"[保存] 保存异常: {e}")
            return False

    def get_save_result(self) -> tuple:
        """读取保存后的结果(成功消息/错误消息). 返回(success, message)"""
        try:
            # 成功消息
            success_msg = self.page.locator(".ant-message-success")
            if success_msg.count() > 0 and success_msg.first.is_visible():
                return (True, success_msg.first.text_content().strip()[:100])
            # 错误消息(ant-message-error)
            error_msg = self.page.locator(".ant-message-error")
            if error_msg.count() > 0 and error_msg.first.is_visible():
                return (False, error_msg.first.text_content().strip()[:100])
            # 表单错误
            form_error = self.page.locator('.ant-form-item-explain-error')
            if form_error.count() > 0:
                return (False, form_error.first.text_content().strip()[:100])
            # 普通notice消息
            notice = self.page.locator(".ant-message-notice")
            if notice.count() > 0 and notice.first.is_visible():
                txt = notice.first.text_content().strip()
                if "成功" in txt:
                    return (True, txt[:100])
                return (False, txt[:100])
        except Exception:
            pass
        return (False, "")

    # ==================== 添加(独立页面) ====================

    def open_add_page(self):
        """点击添加进入独立添加页"""
        self.navigate_to_ipv6_static()
        self.page.wait_for_timeout(500)
        self.click_add_button()
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        return self

    # ==================== 帮助 ====================

    def click_help(self) -> bool:
        try:
            help_btn = self.page.locator('button').filter(has_text="帮助")
            if help_btn.count() > 0:
                help_btn.last.click()
                self.page.wait_for_timeout(500)
                return True
        except Exception:
            pass
        return False

    def is_help_panel_visible(self) -> bool:
        try:
            panel = self.page.locator(".ant-drawer, .ant-modal, [role='dialog']")
            return panel.count() > 0 and panel.first.is_visible()
        except Exception:
            return False

    def close_help_panel(self):
        try:
            close_btn = self.page.locator(".ant-drawer-close, .ant-modal-close")
            if close_btn.count() > 0:
                close_btn.first.click()
            else:
                self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception:
            self.page.keyboard.press("Escape")
