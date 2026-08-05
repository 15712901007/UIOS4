"""
认证服务-认证账号管理-自助密码管理 页面类

纯配置页(单行 ppp_passwd id=1): enabled 总开关 + 6 个允许项
(allow_pppoe/pptp/l2tp/ovpn/web/quit)。即时保存(无保存按钮, 改 switch 立即写 DB)。
继承 IkuaiTablePage 复用 helper(close_modal/help 等), 不使用表格方法。

UI(Playwright 实测):
- 自助密码管理是"认证账号管理"的第3个 tab(默认套餐管理), 须主动切 tab。
- enabled: 自定义控件 span[class*=_enable_](文案"启用"/"停用")点击切换;
  状态读 span[class*=_opened_](已开启=enabled yes)/span[class*=_closed_](已关闭=no)。
- 6 个 allow: ant-switch, UI 顺序 PPPOE/L2TP/PPTP/OPENVPN/WEB修改/WEB退出。
- 即时保存: 点 switch/enabled 立即 save, 无保存按钮。
- 开启后已认证用户访问 6.6.6.6 自助改密(init 用 iptables 重定向 6.6.6.6:80→684 端口)。
"""
from pages.ikuai_table_page import IkuaiTablePage


class PppPasswdPage(IkuaiTablePage):
    """认证服务-自助密码管理页面操作类(纯配置页)"""

    MODULE_NAME = "ppp_passwd"
    LIST_URL = "/login#/authenticationService/accountCertificationManagement"

    # allow 开关中文标签 -> 后端字段(顺序即 UI switch 顺序, 实测确认)
    ALLOW_LABELS = [
        "允许PPPOE用户修改密码",       # allow_pppoe
        "允许L2TP用户修改密码",        # allow_l2tp
        "允许PPTP用户修改密码",        # allow_pptp
        "允许OPENVPN用户修改密码",     # allow_ovpn
        "允许WEB认证用户修改密码",     # allow_web
        "允许WEB认证用户退出登录",     # allow_quit
    ]
    ALLOW_KEYS = ["allow_pppoe", "allow_l2tp", "allow_pptp", "allow_ovpn", "allow_web", "allow_quit"]

    # ==================== 导航 ====================

    def navigate_to_ppp_passwd(self):
        """导航到认证账号管理并切换到"自助密码管理" tab。"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_passwd_tab()
        return self

    def _switch_to_passwd_tab(self) -> None:
        """切到"自助密码管理" tab, 并等待 active 生效。"""
        try:
            self.page.locator(".ant-tabs-tab").first.wait_for(state="visible", timeout=8000)
            tabs = self.page.locator(".ant-tabs-tab")
            target = None
            for i in range(tabs.count()):
                if (tabs.nth(i).inner_text() or "").strip() == "自助密码管理":
                    target = tabs.nth(i)
                    break
            if target is None:
                return
            if "ant-tabs-tab-active" not in (target.get_attribute("class") or ""):
                target.click()
            try:
                self.page.wait_for_function(
                    "() => { const t = Array.from(document.querySelectorAll('.ant-tabs-tab'))"
                    ".find(x => (x.textContent||'').trim() === '自助密码管理'); "
                    "return t && t.classList.contains('ant-tabs-tab-active'); }",
                    timeout=5000,
                )
            except Exception:
                pass
            self.page.wait_for_timeout(600)
        except Exception:
            pass

    def _ensure_passwd_page(self) -> None:
        """导航回自助密码管理页, 切 tab, 并确认页面特征("开启此功能后"文案)已渲染。"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_passwd_tab()
        try:
            self.page.locator("text=开启此功能后").first.wait_for(state="visible", timeout=8000)
        except Exception:
            self._switch_to_passwd_tab()
            self.page.wait_for_timeout(800)

    def _panel(self):
        return self.page.locator(".ant-tabs-tabpane-active")

    # ==================== enabled 总开关 ====================

    def is_enabled(self) -> bool:
        """功能是否已开启(span[class*=_opened_] 存在 = 已开启)。"""
        try:
            return self._panel().locator("[class*='_opened_']").count() > 0
        except Exception:
            return False

    def is_disabled(self) -> bool:
        """功能是否已关闭(span[class*=_closed_] 存在 = 已关闭)。"""
        try:
            return self._panel().locator("[class*='_closed_']").count() > 0
        except Exception:
            return False

    def toggle_enabled(self):
        """点 enabled 切换控件(span[class*=_enable_], 文案"启用"/"停用")。"""
        self._panel().locator("span[class*='_enable_']").first.click()
        self.page.wait_for_timeout(900)
        return self

    def enable(self):
        if not self.is_enabled():
            self.toggle_enabled()
        return self

    def disable(self):
        if not self.is_disabled():
            self.toggle_enabled()
        return self

    # ==================== allow 允许项开关 ====================

    def _allow_switch(self, label: str):
        """按中文标签定位 allow switch(index 映射, UI 顺序固定)。"""
        idx = self.ALLOW_LABELS.index(label)
        return self._panel().locator(".ant-switch").nth(idx)

    def get_allow_checked(self, label: str) -> bool:
        """读取某 allow 开关是否勾选。"""
        try:
            sw = self._allow_switch(label)
            return bool(sw.evaluate("el => el.classList.contains('ant-switch-checked')"))
        except Exception:
            return False

    def set_allow(self, label: str, on: bool):
        """设置某 allow 开关到目标状态(不同则点击切换, 即时保存)。"""
        sw = self._allow_switch(label)
        checked = bool(sw.evaluate("el => el.classList.contains('ant-switch-checked')"))
        if checked != on:
            sw.click()
            self.page.wait_for_timeout(700)
        return self

    def get_all_allow_states(self) -> dict:
        """读取全部 6 个 allow 开关状态 {label: bool}。"""
        return {label: self.get_allow_checked(label) for label in self.ALLOW_LABELS}

    # ==================== 帮助功能 ====================

    def test_help_functionality(self) -> dict:
        result = {"icon_clickable": False, "panel_visible": False, "has_content": False,
                  "content_text": "", "link_clickable": False, "new_page_opened": False,
                  "url_changed": False, "can_close": False}
        try:
            self._ensure_passwd_page()
            help_btn = self.page.locator('button:has-text("帮助")').first
            if help_btn.count() == 0:
                return result
            new_page = None
            try:
                with self.page.context.expect_page(timeout=4000) as np:
                    help_btn.click()
                new_page = np.value
                result["icon_clickable"] = True
                result["new_page_opened"] = True
                result["link_clickable"] = True
            except Exception:
                try:
                    help_btn.click()
                    result["icon_clickable"] = True
                except Exception:
                    pass
            try:
                popover = self.page.locator(".ant-popover").last
                if popover.count() > 0 and popover.is_visible():
                    result["panel_visible"] = True
                    txt = (popover.text_content() or "").strip()
                    result["content_text"] = txt
                    result["has_content"] = bool(txt)
            except Exception:
                pass
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)
                result["can_close"] = True
            except Exception:
                pass
            if new_page is not None:
                try:
                    new_page.close()
                except Exception:
                    pass
        except Exception:
            pass
        return result
