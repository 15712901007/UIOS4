"""
DHCP黑白名单页面操作类

网络配置 > DHCP服务 > DHCP黑白名单 页面
URL: /login#/networkConfiguration/dhcpService (DHCP黑白名单tab, 含IPv4/IPv6子tab)

页面特点: 表格型 + 模式切换(3个radio):
- 模式radio: 使用黑名单模式(0)/使用白名单模式(1)/同步MAC访问控制(2) = global_config.dhcp_acl_mac
- IPv4/IPv6子tab (本类操作IPv4)
- 添加/编辑为独立页面: /dhcpService/bwList/ipv4BWList/add, /edit
- 表格列: 名称/MAC地址(可排序)/终端名称/备注/操作
- 顶部: 搜索/添加/导入/导出/设置齿轮

数据库: dhcp_acl_mac_black(模式0)/dhcp_acl_mac_white(模式1)表
字段: id, enabled(默认'no'!), tagname(unique), ip_type(默认'4'), comment, mac(unique)
后端: add/edit/del/up/down + ipset(Linux_dhcp_aclmac_default) + iptables(DHCP_ACL链, UDP67)
__get_acl_action: dhcp_acl_mac=0→操作black表, 非0→操作white表
模式切换: set_access_mode → __seting_dhcp_acl_mac重建iptables规则
  - 0黑名单: --match-set ... DROP (黑名单内MAC禁止)
  - 1白名单: ! --match-set ... DROP (白名单外MAC禁止, !!空ipset阻止所有DHCP)
  - 2同步: 使用acl_mac(通用MAC访问控制)的黑名单

注意: 表enabled默认'no', 添加的规则默认不入ipset, 需up()启用才加入ipset。
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class DhcpAclMacPage(IkuaiTablePage):
    """DHCP黑白名单页面操作类(表格型+模式切换, 独立页面表单全#id)"""

    MODULE_NAME = "dhcp_acl_mac"
    PAGE_URL = "/login#/networkConfiguration/dhcpService"

    # 模式radio value → 描述
    MODE_BLACK = "0"   # 使用黑名单模式(操作black表)
    MODE_WHITE = "1"   # 使用白名单模式(操作white表)
    MODE_SYNC = "2"    # 同步MAC访问控制

    # 可排序列(th#id)
    COLUMN_ID_MAP = {
        "MAC地址": "mac",
    }

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

    def navigate_to_dhcp_acl_mac(self):
        """导航到DHCP服务 > DHCP黑白名单tab > IPv4子tab"""
        self._dismiss_residual_modal()
        url = f"{self.base_url}{self.PAGE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        self._dismiss_residual_modal()
        # 点DHCP黑白名单tab
        try:
            tab = self.page.get_by_role("tab", name="DHCP黑白名单")
            if tab.count() > 0:
                selected = tab.get_attribute("aria-selected")
                if selected != "true":
                    tab.click()
                    self.page.wait_for_timeout(1000)
        except Exception as e:
            logger.warning(f"[导航] 切换DHCP黑白名单tab异常: {e}")
        # 确保IPv4子tab选中(默认)
        try:
            ipv4 = self.page.get_by_role("tab", name="IPv4")
            if ipv4.count() > 0 and ipv4.first.get_attribute("aria-selected") != "true":
                ipv4.first.click()
                self.page.wait_for_timeout(800)
        except Exception:
            pass
        # 等待模式radio渲染(右侧设置面板异步加载,较慢; radio的value是property非attribute)
        try:
            self.page.wait_for_selector('input[type="radio"]', timeout=10000)
            self.page.wait_for_timeout(800)
        except Exception:
            pass
        logger.info("[导航] 已到达DHCP黑白名单页面(IPv4)")
        return self

    def navigate_back_to_list(self):
        return self.navigate_to_dhcp_acl_mac()

    # ==================== 模式切换(3个radio) ====================

    def get_mode(self) -> str:
        """获取当前模式(返回radio value: 0黑名单/1白名单/2同步), 空字符串表示未获取"""
        try:
            radios = self.page.locator('.ant-radio-wrapper input[type="radio"]')
            for i in range(min(radios.count(), 5)):
                inp = radios.nth(i)
                if inp.is_checked():
                    return inp.get_attribute("value") or ""
        except Exception as e:
            logger.warning(f"[读取] 获取模式失败: {e}")
        return ""

    def get_mode(self) -> str:
        """获取当前模式(返回radio value: 0黑名单/1白名单/2同步)"""
        try:
            # value是DOM property非attribute, 用遍历读取
            return self.page.evaluate('''() => {
                const radios = document.querySelectorAll('input[type="radio"]');
                for (const inp of radios) {
                    if (inp.checked) return inp.value;
                }
                return '';
            }''') or ""
        except Exception as e:
            logger.warning(f"[读取] 获取模式失败: {e}")
        return ""

    def select_mode(self, mode: str) -> bool:
        """选择模式(0黑名单/1白名单/2同步MAC访问控制)

        切换后后端set_access_mode → __seting_dhcp_acl_mac重建iptables规则。
        !!UI radio(右侧设置面板)异步渲染不稳定(依赖状态/慢), 用前端相同API
        (/Action/call set_access_mode, 即radio onChange调用的接口)切换更可靠。
        SSH验证后端global_config+iptables确认生效。
        """
        try:
            result = self.page.evaluate('''async (mode) => {
                const resp = await fetch('/Action/call', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({func_name: 'dhcp_acl_mac', action: 'set_access_mode', param: {mode: parseInt(mode)}})
                });
                const txt = await resp.text();
                return {status: resp.status, body: txt.slice(0,200)};
            }''', mode)
            body = result.get('body', '')
            logger.info(f"[操作] set_access_mode({mode}): {body[:80]}")
            self.page.wait_for_timeout(2500)  # 等iptables重建
            return result.get('status') == 200 and ('Success' in body or '"code":0' in body)
        except Exception as e:
            logger.warning(f"[操作] set_access_mode({mode})失败: {e}")
            return False

    # ==================== 表单字段(全#id, 独立页面) ====================

    def fill_name(self, name: str):
        inp = self.page.locator('#tagname')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(name)
            self.page.wait_for_timeout(150)
        return self

    def fill_mac(self, mac: str):
        inp = self.page.locator('#mac')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(mac)
            self.page.wait_for_timeout(150)
        return self

    def fill_termname(self, termname: str):
        inp = self.page.locator('#termname')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(termname)
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

    # ==================== 保存与高层操作 ====================

    def save_form(self, expect_success: bool = True) -> bool:
        """点击保存按钮(独立页面), 检测成功/失败"""
        try:
            self.page.wait_for_timeout(500)
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() == 0:
                logger.error("[保存] 未找到保存按钮")
                return False
            save_btn.click()
            self.page.wait_for_timeout(1500)
            if not expect_success:
                return False
            success = False
            try:
                msg = self.page.locator(".ant-message-success")
                if msg.count() > 0 and msg.first.is_visible():
                    success = True
                else:
                    success = self.wait_for_success_message(timeout=5000)
            except Exception:
                success = self.wait_for_success_message(timeout=5000)
            if success:
                logger.info("[保存] DHCP黑白名单保存成功")
            else:
                error = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if error.count() > 0:
                    logger.error(f"[保存] 保存失败: {error.first.text_content()}")
            return success
        except Exception as e:
            logger.error(f"[保存] 保存异常: {e}")
            return False

    def add_rule(self, name: str, mac: str, comment: str = "",
                 termname: str = "", enable: bool = False) -> bool:
        """添加一条DHCP黑白名单规则(独立页面)

        注意: enabled默认'no', 添加后规则不入ipset, 需启用(enable=True或后续up)。
        实际enabled状态由后端add决定(UI无enabled开关, 默认no)。
        """
        try:
            self.navigate_to_dhcp_acl_mac()
            self.page.wait_for_timeout(500)
            self.click_add_button()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1000)
            self.fill_name(name)
            self.fill_mac(mac)
            if termname:
                self.fill_termname(termname)
            if comment:
                self.fill_comment(comment)
            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            self.page.wait_for_timeout(2000)
            return ok
        except Exception as e:
            logger.error(f"[添加] 添加DHCP黑白名单异常: {e}")
            return False

    def edit_rule(self, current_name: str, **kwargs) -> bool:
        """编辑指定名称的规则(kwargs: name/mac/termname/comment)"""
        try:
            self.navigate_to_dhcp_acl_mac()
            self.page.wait_for_timeout(500)
            self.edit_rule_base(current_name)
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1200)
            if "name" in kwargs and kwargs["name"] is not None:
                self.fill_name(kwargs["name"])
            if "mac" in kwargs and kwargs["mac"]:
                self.fill_mac(kwargs["mac"])
            if "termname" in kwargs and kwargs["termname"]:
                self.fill_termname(kwargs["termname"])
            if "comment" in kwargs and kwargs["comment"]:
                self.fill_comment(kwargs["comment"])
            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            self.page.wait_for_timeout(2000)
            return ok
        except Exception as e:
            logger.error(f"[编辑] 编辑DHCP黑白名单异常: {e}")
            return False

    def edit_rule_base(self, rule_name: str):
        """点击编辑按钮进入编辑页(重命名避免与基类edit_rule冲突)"""
        self._click_rule_button(rule_name, "编辑")
        self.page.wait_for_timeout(500)
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
