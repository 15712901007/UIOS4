"""
高级服务 > 本地服务 > Samba服务 Page Object。

真实页面特征：
- 列表 URL 为 /#/advancedService/localService，Samba 是 data-node-key=samba 的第二个 Tab。
- 新增和编辑使用 /samba/add、/samba/edit 独立路由。
- 设置使用自定义 vacantDrawer；共享目录使用 Ant Drawer。
- 列表和共享目录表均为虚拟表格，所有列表操作必须限定在激活的 Samba pane。
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from playwright.sync_api import Locator, Page

from pages.ikuai_table_page import IkuaiTablePage


class SambaServerPage(IkuaiTablePage):
    """Samba 服务页面操作类。"""

    MODULE_NAME = "samba_server"
    IMPORT_REQUIRES_CLEAR_GUARD = True

    LIST_URL = "/#/advancedService/localService"
    ADD_URL = "/#/advancedService/localService/samba/add"
    EDIT_FRAGMENT = "/advancedService/localService/samba/edit"
    FILE_MANAGER_FRAGMENT = "/equipmentSetting/diskManagement?tab=fileManagement"

    PERMISSION_UI = {"rw": "读写", "ro": "只读"}
    BROWSEABLE_UI = {"yes": "显示", "no": "隐藏"}
    COLUMN_ID_MAP = {
        "用户名": "username",
        "共享名": "name",
        "共享目录": "home_dir",
        "匿名访问": "guest",
        "权限": "perm",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 通用小工具 ====================
    def _wait_page(self, settle_ms: int = 800):
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(settle_ms)

    def _dismiss_transient_overlays(self):
        """只关闭可取消的浮层，不点击确认按钮。"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(150)
        except Exception:
            pass
        try:
            cancel = self.page.locator(
                ".ant-modal-wrap:visible button:has-text('取消'):visible, "
                ".ant-drawer-content[role='dialog']:visible button:has-text('取消'):visible"
            )
            if cancel.count() > 0:
                cancel.last.click(timeout=1500)
                self.page.wait_for_timeout(250)
        except Exception:
            pass

    @staticmethod
    def _control_checked(locator: Locator) -> Optional[bool]:
        try:
            return bool(locator.evaluate("""el => {
                const input = el.matches('input[type=checkbox]')
                    ? el : el.querySelector('input[type=checkbox]');
                if (input) return !!input.checked;
                const sw = el.matches('.ant-switch') ? el : el.closest('.ant-switch');
                return !!(sw && (
                    sw.getAttribute('aria-checked') === 'true' ||
                    sw.classList.contains('ant-switch-checked')
                ));
            }"""))
        except Exception:
            return None

    def _fill_input(self, selector: str, value, root: Optional[Locator] = None) -> bool:
        try:
            scope = root or self.page
            inp = scope.locator(selector).first
            if inp.count() == 0:
                return False
            inp.click()
            inp.fill("")
            if value is not None and str(value) != "":
                inp.type(str(value), delay=20)
            inp.evaluate("""el => {
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            return True
        except Exception as exc:
            print(f"[DEBUG] fill {selector}: {str(exc)[:80]}")
            return False

    def get_form_error(self, root: Optional[Locator] = None) -> Optional[str]:
        """读取当前可见表单或最近一条 API 错误，不读取密码值。"""
        scope = root or self.page
        for selector in (
            ".ant-form-item-explain-error:visible",
            ".ant-alert-error:visible",
        ):
            try:
                loc = scope.locator(selector)
                if loc.count() > 0:
                    text = (loc.first.inner_text() or "").strip()
                    if text:
                        return text[:180]
            except Exception:
                pass
        for selector in (
            ".ant-message-error:visible",
            ".ant-notification-notice-error:visible",
        ):
            try:
                loc = self.page.locator(selector)
                if loc.count() > 0:
                    text = (loc.last.inner_text() or "").strip()
                    if text:
                        return text[:180]
            except Exception:
                pass
        try:
            if scope.locator(
                ".ant-form-item-has-error:visible, .ant-input-status-error:visible"
            ).count() > 0:
                return "输入格式错误"
        except Exception:
            pass
        return None

    def _set_checkbox(self, selector: str, enabled: bool, root: Optional[Locator] = None) -> bool:
        try:
            scope = root or self.page
            ctl = scope.locator(selector).first
            if ctl.count() == 0:
                return False
            current = self._control_checked(ctl)
            if current is enabled:
                return True
            ctl.set_checked(bool(enabled), force=True)
            self.page.wait_for_timeout(250)
            return self._control_checked(ctl) is enabled
        except Exception as exc:
            print(f"[DEBUG] set checkbox {selector}: {str(exc)[:80]}")
            return False

    def _select_option(
        self,
        field_selector: str,
        ui_text: str,
        code: str = "",
        root: Optional[Locator] = None,
    ) -> bool:
        try:
            scope = root or self.page
            field = scope.locator(field_selector).first
            if field.count() == 0:
                return False
            select = field.locator(
                "xpath=ancestor::div[contains(concat(' ', normalize-space(@class), ' '), "
                "' ant-select ')][1]"
            )
            select.locator(".ant-select-selector").click(timeout=4000)
            self.page.wait_for_timeout(300)
            clicked = self.page.evaluate("""({ui, code}) => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                const dds = [...document.querySelectorAll('.ant-select-dropdown')].filter(visible);
                const dd = dds[dds.length - 1];
                if (!dd) return false;
                const target = [...dd.querySelectorAll('.ant-select-item-option')].find(o => {
                    const text = norm(o.innerText || o.textContent);
                    return text === norm(ui) || text === norm(code) ||
                        text.includes(norm(ui));
                });
                if (!target) return false;
                target.click();
                return true;
            }""", {"ui": ui_text, "code": code})
            self.page.wait_for_timeout(250)
            return bool(clicked)
        except Exception as exc:
            print(f"[DEBUG] select {field_selector}: {str(exc)[:80]}")
            return False

    # ==================== 列表导航和 Samba pane ====================
    def _samba_tab(self) -> Locator:
        tab = self.page.locator(".ant-tabs-tab[data-node-key='samba']:visible")
        if tab.count() > 0:
            return tab.first
        return self.page.locator(".ant-tabs-tab:visible").filter(has_text="Samba服务").first

    def _samba_pane(self) -> Locator:
        pane = self.page.locator(
            "div.ant-tabs-tabpane-active[role='tabpanel']"
            "[aria-labelledby$='-tab-samba']:visible"
        )
        if pane.count() > 0:
            return pane.first
        tab = self._samba_tab()
        try:
            if tab.count() > 0 and "ant-tabs-tab-active" in (tab.get_attribute("class") or ""):
                fallback = self.page.locator(".ant-tabs-tabpane-active:visible")
                if fallback.count() > 0:
                    return fallback.first
        except Exception:
            pass
        return self.page.locator("[data-samba-pane-not-found='1']")

    def switch_to_samba_tab(self) -> bool:
        try:
            tab = self._samba_tab()
            if tab.count() == 0:
                return False
            if "ant-tabs-tab-active" not in (tab.get_attribute("class") or ""):
                tab.click()
                self.page.wait_for_timeout(900)
            pane = self._samba_pane()
            return (
                pane.count() > 0
                and pane.locator("th#guest:visible").count() > 0
                and pane.locator("th#perm:visible").count() > 0
            )
        except Exception as exc:
            print(f"[DEBUG] switch_to_samba_tab: {str(exc)[:80]}")
            return False

    def navigate_to_samba_server(self):
        self._dismiss_transient_overlays()
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        self._wait_page(1300)
        self.switch_to_samba_tab()
        return self

    navigate_to_samba = navigate_to_samba_server

    def _settings_button(self) -> Locator:
        pane = self._samba_pane()
        return pane.locator("button:visible").filter(has_text="设置").first

    def get_default_structure(self) -> Dict:
        result: Dict = {
            "url_ok": "advancedService/localService" in self.page.url,
            "samba_tab_present": False,
            "samba_tab_active": False,
            "table_present": False,
            "switch_present": False,
            "settings_present": False,
            "search_present": False,
            "headers": [],
            "buttons": [],
            "username_sortable": False,
        }
        try:
            tab = self._samba_tab()
            result["samba_tab_present"] = tab.count() > 0
            result["samba_tab_active"] = (
                tab.count() > 0
                and "ant-tabs-tab-active" in (tab.get_attribute("class") or "")
            )
            pane = self._samba_pane()
            if pane.count() == 0:
                return result
            result.update(pane.evaluate("""root => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                const table = [...root.querySelectorAll('.ant-table')].find(visible);
                const th = root.querySelector('th#username');
                return {
                    table_present: !!table,
                    switch_present: [...root.querySelectorAll('button.ant-switch')].some(visible),
                    search_present: [...root.querySelectorAll(
                        "input[placeholder='请输入搜索内容']"
                    )].some(visible),
                    headers: table ? [...table.querySelectorAll('.ant-table-thead th')]
                        .filter(h => visible(h) && !h.classList.contains('ant-table-measure-cell'))
                        .map(h => norm(h.innerText)).filter(Boolean) : [],
                    buttons: [...root.querySelectorAll('button')].filter(visible)
                        .map(b => norm(b.innerText || b.textContent)).filter(Boolean),
                    username_sortable: !!(th && (
                        th.querySelector('.sortIcon, .ant-table-column-sorter') ||
                        th.hasAttribute('aria-sort')
                    ))
                };
            }"""))
            result["settings_present"] = self._settings_button().count() > 0
        except Exception:
            pass
        return result

    # ==================== 总开关 ====================
    def _global_switch(self) -> Locator:
        pane = self._samba_pane()
        switches = pane.locator("button.ant-switch[role='switch']:visible")
        if switches.count() > 0:
            return switches.first
        return pane.locator("button.ant-switch:visible").first

    def get_service_enabled(self) -> Optional[bool]:
        try:
            sw = self._global_switch()
            if sw.count() == 0:
                return None
            return self._control_checked(sw)
        except Exception:
            return None

    def set_service_enabled(self, enabled: bool) -> bool:
        """设置 Samba 总开关；当前固件关闭时没有二次确认。"""
        try:
            if self._samba_pane().count() == 0 and not self.switch_to_samba_tab():
                return False
            sw = self._global_switch()
            if sw.count() == 0:
                return False
            if self._control_checked(sw) is enabled:
                return True
            sw.click()
            self.page.wait_for_timeout(450)
            # 无工作组时，开启会转入设置 drawer，而不是直接保存。
            if self.page.locator("#workgroup:visible").count() > 0:
                self.cancel_settings()
                return False
            if self.page.locator(".ant-modal-wrap:visible").count() > 0:
                self._click_visible_confirm(timeout=2500)
            for _ in range(18):
                self.page.wait_for_timeout(300)
                if self.get_service_enabled() is enabled:
                    return True
            self.page.reload()
            self._wait_page(900)
            self.switch_to_samba_tab()
            return self.get_service_enabled() is enabled
        except Exception as exc:
            print(f"[DEBUG] set_service_enabled({enabled}): {str(exc)[:80]}")
            return False

    # ==================== 设置 drawer ====================
    def _settings_root(self) -> Locator:
        return self.page.locator("#vacantDrawer:has(input#workgroup):visible").first

    def open_settings(self) -> bool:
        try:
            if self._samba_pane().count() == 0 and not self.switch_to_samba_tab():
                return False
            button = self._settings_button()
            if button.count() == 0:
                return False
            button.click()
            field = self.page.locator("input#workgroup:visible").first
            field.wait_for(state="visible", timeout=5000)
            # 等待异步设置值稳定，空字符串也可能是待修复的真实配置。
            previous = None
            stable = 0
            for _ in range(15):
                value = field.input_value()
                if value == previous:
                    stable += 1
                else:
                    stable = 0
                previous = value
                if stable >= 2:
                    break
                self.page.wait_for_timeout(120)
            return True
        except Exception as exc:
            print(f"[DEBUG] open_settings: {str(exc)[:80]}")
            return False

    def get_settings(self) -> Dict:
        result = {"workgroup": None, "wsdd2": None, "access": None}
        try:
            root = self._settings_root()
            if root.count() == 0:
                return result
            result["workgroup"] = root.locator("input#workgroup").input_value()
            result["wsdd2"] = self._control_checked(root.locator("input#wsdd2"))
            result["access"] = self._control_checked(root.locator("input#access"))
        except Exception:
            pass
        return result

    def fill_workgroup(self, workgroup: str) -> bool:
        return self._fill_input("input#workgroup", workgroup, self._settings_root())

    def set_wsdd2(self, enabled: bool) -> bool:
        return self._set_checkbox("input#wsdd2", enabled, self._settings_root())

    def set_access(self, enabled: bool) -> bool:
        return self._set_checkbox("input#access", enabled, self._settings_root())

    set_network_discovery = set_wsdd2
    set_external_access = set_access

    def save_settings(self, timeout: int = 7000) -> Dict:
        result = {"success": False, "error": ""}
        try:
            root = self._settings_root()
            if root.count() == 0:
                result["error"] = "Samba 设置层未打开"
                return result
            save = root.locator("button:visible").filter(has_text="保存").last
            if save.count() == 0:
                result["error"] = "Samba 设置层未找到保存按钮"
                return result
            save.click()
            for _ in range(max(1, timeout // 300)):
                self.page.wait_for_timeout(300)
                error = self.get_form_error(root)
                if error:
                    result["error"] = error
                    return result
                if self.page.locator("input#workgroup:visible").count() == 0:
                    result["success"] = True
                    return result
            result["error"] = "保存后 Samba 设置层仍未关闭"
        except Exception as exc:
            result["error"] = str(exc)[:140]
        return result

    def cancel_settings(self) -> bool:
        try:
            root = self._settings_root()
            if root.count() > 0:
                cancel = root.locator("button:visible").filter(has_text="取消").last
                if cancel.count() > 0:
                    cancel.click()
                else:
                    self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(350)
            return self.page.locator("input#workgroup:visible").count() == 0
        except Exception:
            return False

    def set_settings(self, workgroup: str, wsdd2: bool, access: bool) -> Dict:
        if not self.open_settings():
            return {"success": False, "error": "打开 Samba 设置失败"}
        if not self.fill_workgroup(workgroup):
            self.cancel_settings()
            return {"success": False, "error": "填写工作组失败"}
        if not self.set_wsdd2(wsdd2):
            self.cancel_settings()
            return {"success": False, "error": "设置网络发现失败"}
        if not self.set_access(access):
            self.cancel_settings()
            return {"success": False, "error": "设置外网访问失败"}
        return self.save_settings()

    def try_invalid_workgroup(self, workgroup: str = "") -> Dict:
        result = {"blocked": False, "error": ""}
        if not self.open_settings():
            result["error"] = "打开 Samba 设置失败"
            return result
        self.fill_workgroup(workgroup)
        if len(str(workgroup)) > 15:
            actual = self._settings_root().locator("input#workgroup").input_value()
            result["blocked"] = actual != str(workgroup)
            result["error"] = "工作组被 maxlength=15 截断" if result["blocked"] else ""
            self.cancel_settings()
            return result
        saved = self.save_settings(timeout=3000)
        still_open = self.page.locator("input#workgroup:visible").count() > 0
        result["blocked"] = not saved["success"] and still_open
        result["error"] = saved.get("error", "") or (
            "非法工作组被拦截" if result["blocked"] else "非法工作组被接受"
        )
        if still_open:
            self.cancel_settings()
        return result

    try_settings_invalid = try_invalid_workgroup

    # ==================== 用户新增/编辑页 ====================
    def open_add_page(self) -> bool:
        self._dismiss_transient_overlays()
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        self._wait_page(1000)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        route_ok = (
            "/advancedService/localService/samba/add" in self.page.url
            or self.EDIT_FRAGMENT in self.page.url
        )
        try:
            return route_ok and self.page.locator("input#username:visible").count() > 0
        except Exception:
            return route_ok

    is_still_on_config_page = is_on_config_page

    def _main_form(self) -> Locator:
        return self.page.locator("form.customForm:visible").first

    def _share_table(self) -> Locator:
        return self.page.locator(
            ".ant-table-wrapper:visible:has(th#name):has(th#browseable)"
        ).first

    def get_user_form_structure(self) -> Dict:
        result = {
            "username_present": False,
            "password_present": False,
            "permission_present": False,
            "guest_present": False,
            "share_table_present": False,
            "share_add_present": False,
            "file_manager_present": False,
            "username_maxlength": None,
            "password_maxlength": None,
            "permission_value": None,
            "guest_checked": None,
            "share_headers": [],
        }
        try:
            result["username_present"] = self.page.locator("input#username:visible").count() > 0
            result["password_present"] = self.page.locator("input#passwd:visible").count() > 0
            result["permission_present"] = self.page.locator("input#perm:visible").count() > 0
            result["guest_present"] = self.page.locator("input#guest:visible").count() > 0
            result["share_table_present"] = self._share_table().count() > 0
            result["share_add_present"] = (
                self.page.locator("div.functionArea button:visible")
                .filter(has_text="添加").count() > 0
            )
            result["file_manager_present"] = (
                self.page.locator("div.functionArea button:visible")
                .filter(has_text="文件管理").count() > 0
            )
            maxlength = self.page.locator("input#username").get_attribute("maxlength")
            result["username_maxlength"] = int(maxlength) if maxlength is not None else None
            pw_max = self.page.locator("input#passwd").get_attribute("maxlength")
            result["password_maxlength"] = int(pw_max) if pw_max is not None else None
            result["permission_value"] = (
                self.page.locator(".ant-select:has(input#perm) .ant-select-selection-item")
                .first.inner_text()
            )
            result["guest_checked"] = self.page.locator("input#guest").is_checked()
            if self._share_table().count() > 0:
                result["share_headers"] = self._share_table().evaluate("""root =>
                    [...root.querySelectorAll('.ant-table-thead th')]
                        .filter(h => h.offsetParent !== null &&
                            !h.classList.contains('ant-table-measure-cell'))
                        .map(h => (h.innerText || '').replace(/\\s+/g, '').trim())
                        .filter(Boolean)
                """)
        except Exception:
            pass
        return result

    def fill_username(self, username: str) -> bool:
        return self._fill_input("input#username", username)

    def get_username_value(self) -> str:
        try:
            return self.page.locator("input#username:visible").input_value()
        except Exception:
            return ""

    def fill_password(self, password: str) -> bool:
        # 严禁打印或格式化 password。
        return self._fill_input("input#passwd", password)

    def set_permission(self, permission: str) -> bool:
        code = str(permission).lower()
        return self._select_option(
            "input#perm",
            self.PERMISSION_UI.get(code, str(permission)),
            code,
        )

    def set_guest(self, enabled: bool) -> bool:
        return self._set_checkbox("input#guest", enabled)

    # ==================== 共享目录子表 / Drawer ====================
    def _share_drawer(self) -> Locator:
        return self.page.locator(
            ".ant-drawer-content[role='dialog']:visible"
            ":has(input#name):has(input#home_dir)"
        ).last

    def open_share_add(self) -> bool:
        try:
            if self._share_drawer().count() > 0:
                return True
            button = self.page.locator("div.functionArea button:visible").filter(
                has_text="添加"
            ).first
            if button.count() == 0:
                return False
            button.click()
            self.page.locator(
                ".ant-drawer-content[role='dialog']:visible input#name"
            ).wait_for(state="visible", timeout=4000)
            return True
        except Exception as exc:
            print(f"[DEBUG] open_share_add: {str(exc)[:80]}")
            return False

    def get_share_form_structure(self) -> Dict:
        result = {
            "name_present": False,
            "home_dir_present": False,
            "browseable_present": False,
            "name_maxlength": None,
            "browseable_value": None,
        }
        try:
            drawer = self._share_drawer()
            if drawer.count() == 0:
                return result
            result["name_present"] = drawer.locator("input#name").count() > 0
            result["home_dir_present"] = drawer.locator("input#home_dir").count() > 0
            result["browseable_present"] = drawer.locator("input#browseable").count() > 0
            maxlength = drawer.locator("input#name").get_attribute("maxlength")
            result["name_maxlength"] = int(maxlength) if maxlength is not None else None
            result["browseable_value"] = (
                drawer.locator(
                    ".ant-select:has(input#browseable) .ant-select-selection-item"
                ).inner_text()
            )
        except Exception:
            pass
        return result

    def fill_share_name(self, name: str) -> bool:
        return self._fill_input("input#name", name, self._share_drawer())

    def _mark_tree_node(self, title: str) -> bool:
        try:
            return bool(self.page.evaluate("""title => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                document.querySelectorAll('[data-samba-tree-node]').forEach(
                    e => e.removeAttribute('data-samba-tree-node')
                );
                const dds = [...document.querySelectorAll(
                    '.ant-select-dropdown, .ant-tree-select-dropdown'
                )].filter(visible);
                const dd = dds[dds.length - 1];
                if (!dd) return false;
                const rows = [...dd.querySelectorAll(
                    '.ant-select-tree-treenode, .ant-tree-treenode'
                )].filter(visible);
                let row = rows.find(r => {
                    const content = r.querySelector(
                        '.ant-select-tree-node-content-wrapper, ' +
                        '.ant-tree-node-content-wrapper, [title]'
                    );
                    const attr = content ? (content.getAttribute('title') || '') : '';
                    const text = content ? (content.innerText || content.textContent || '') : '';
                    return norm(attr) === norm(title) || norm(text) === norm(title) ||
                        norm(attr).endsWith('/' + norm(title));
                });
                if (!row) return false;
                row.setAttribute('data-samba-tree-node', '1');
                return true;
            }""", title))
        except Exception:
            return False

    def select_share_home_dir(self, path: str) -> bool:
        try:
            drawer = self._share_drawer()
            field = drawer.locator("input#home_dir").first
            if field.count() == 0:
                return False
            drawer.locator(
                ".ant-select:has(input#home_dir) .ant-select-selector"
            ).click(timeout=4000)
            self.page.wait_for_timeout(450)
            parts = [p for p in str(path).replace("\\", "/").split("/") if p]
            if not parts:
                return False
            for part in parts[:-1]:
                if not self._mark_tree_node(part):
                    return False
                row = self.page.locator("[data-samba-tree-node='1']").first
                expanded = row.get_attribute("aria-expanded")
                if expanded is None:
                    nested = row.locator("[aria-expanded]").first
                    if nested.count() > 0:
                        expanded = nested.get_attribute("aria-expanded")
                if expanded != "true":
                    switcher = row.locator(
                        ".ant-select-tree-switcher, .ant-tree-switcher"
                    ).first
                    if switcher.count() == 0:
                        return False
                    switcher.click()
                    self.page.wait_for_timeout(500)
            if not self._mark_tree_node(parts[-1]):
                return False
            row = self.page.locator("[data-samba-tree-node='1']").first
            content = row.locator(
                ".ant-select-tree-node-content-wrapper, "
                ".ant-tree-node-content-wrapper, [title]"
            ).first
            (content if content.count() > 0 else row).click()
            self.page.wait_for_timeout(300)
            return True
        except Exception as exc:
            print(f"[DEBUG] select_share_home_dir: {str(exc)[:80]}")
            return False

    def set_browseable(self, browseable: str) -> bool:
        code = str(browseable).lower()
        if code in {"true", "show", "1"}:
            code = "yes"
        elif code in {"false", "hide", "0"}:
            code = "no"
        return self._select_option(
            "input#browseable",
            self.BROWSEABLE_UI.get(code, str(browseable)),
            code,
            self._share_drawer(),
        )

    def save_share(self, timeout: int = 4000) -> Dict:
        result = {"success": False, "error": ""}
        try:
            drawer = self._share_drawer()
            if drawer.count() == 0:
                result["error"] = "共享目录 Drawer 未打开"
                return result
            button = drawer.locator("button:visible").filter(has_text="保存").last
            button.click()
            for _ in range(max(1, timeout // 250)):
                self.page.wait_for_timeout(250)
                current = self._share_drawer()
                if current.count() == 0:
                    result["success"] = True
                    return result
                error = self.get_form_error(current)
                if error:
                    result["error"] = error
                    return result
            result["error"] = "保存共享目录后 Drawer 仍未关闭"
        except Exception as exc:
            result["error"] = str(exc)[:140]
        return result

    def cancel_share(self) -> bool:
        try:
            drawer = self._share_drawer()
            if drawer.count() == 0:
                return True
            button = drawer.locator("button:visible").filter(has_text="取消").last
            if button.count() > 0:
                button.click()
            else:
                drawer.locator("button.ant-drawer-close").click()
            self.page.wait_for_timeout(300)
            return self._share_drawer().count() == 0
        except Exception:
            return False

    def add_share(self, name: str, home_dir: str, browseable: str = "no") -> Dict:
        if not self.open_share_add():
            return {"success": False, "error": "打开共享目录新增 Drawer 失败"}
        if not self.fill_share_name(name):
            self.cancel_share()
            return {"success": False, "error": "填写共享名失败"}
        actual = self._share_drawer().locator("input#name").input_value()
        if actual != str(name):
            self.cancel_share()
            return {"success": False, "error": "共享名被 maxlength=15 截断"}
        if not self.select_share_home_dir(home_dir):
            self.cancel_share()
            return {"success": False, "error": "选择共享目录失败"}
        if not self.set_browseable(browseable):
            self.cancel_share()
            return {"success": False, "error": "设置隐藏目录失败"}
        return self.save_share()

    def _share_row(self, name: str) -> Locator:
        rows = self._share_table().locator("div.ant-table-row")
        try:
            for idx in range(rows.count()):
                row = rows.nth(idx)
                cells = row.locator(".ant-table-cell")
                if cells.count() > 0 and (cells.first.inner_text() or "").strip() == name:
                    return row
        except Exception:
            pass
        return rows.filter(has_text=name).first

    def get_share_names(self) -> List[str]:
        names: List[str] = []
        try:
            rows = self._share_table().locator("div.ant-table-row")
            for idx in range(rows.count()):
                cells = rows.nth(idx).locator(".ant-table-cell")
                if cells.count() > 0:
                    name = (cells.first.inner_text() or "").strip()
                    if name:
                        names.append(name)
        except Exception:
            pass
        return names

    def remove_share(self, name: str) -> bool:
        try:
            row = self._share_row(name)
            if row.count() == 0:
                return False
            button = row.locator("button:visible").filter(has_text="删除").first
            if button.count() == 0:
                return False
            button.click()
            self.page.wait_for_timeout(250)
            if not self._click_visible_confirm(timeout=3000):
                return False
            for _ in range(12):
                self.page.wait_for_timeout(250)
                if self._share_row(name).count() == 0:
                    return True
            return False
        except Exception:
            return False

    def edit_share(
        self,
        current_name: str,
        *,
        name: Optional[str] = None,
        home_dir: Optional[str] = None,
        browseable: Optional[str] = None,
    ) -> Dict:
        try:
            row = self._share_row(current_name)
            button = row.locator("button:visible").filter(has_text="编辑").first
            if button.count() == 0:
                return {"success": False, "error": "未找到共享目录编辑按钮"}
            button.click()
            self.page.locator(
                ".ant-drawer-content[role='dialog']:visible input#name"
            ).wait_for(timeout=4000)
            if name is not None and not self.fill_share_name(name):
                return {"success": False, "error": "填写共享名失败"}
            if home_dir is not None and not self.select_share_home_dir(home_dir):
                return {"success": False, "error": "选择共享目录失败"}
            if browseable is not None and not self.set_browseable(browseable):
                return {"success": False, "error": "设置隐藏目录失败"}
            return self.save_share()
        except Exception as exc:
            return {"success": False, "error": str(exc)[:140]}

    def _replace_shares(self, shares: List[Dict]) -> bool:
        for existing in list(self.get_share_names()):
            if not self.remove_share(existing):
                return False
        for share in shares:
            result = self.add_share(
                str(share.get("name", "")),
                str(share.get("home_dir", "")),
                str(share.get("browseable", "no")),
            )
            if not result.get("success"):
                return False
        return True

    def try_add_invalid_share(
        self,
        name: str = "",
        home_dir: Optional[str] = None,
        browseable: str = "no",
    ) -> Dict:
        result = {"blocked": False, "error": ""}
        if not self.is_on_config_page() and not self.open_add_page():
            result["error"] = "进入 Samba 新增页失败"
            return result
        if not self.open_share_add():
            result["error"] = "打开共享目录 Drawer 失败"
            return result
        self.fill_share_name(name)
        if len(str(name)) > 15:
            actual = self._share_drawer().locator("input#name").input_value()
            result["blocked"] = actual != str(name)
            result["error"] = "共享名被 maxlength=15 截断"
            self.cancel_share()
            return result
        if home_dir:
            self.select_share_home_dir(home_dir)
        self.set_browseable(browseable)
        saved = self.save_share(timeout=2500)
        result["blocked"] = not saved["success"] and self._share_drawer().count() > 0
        result["error"] = saved.get("error", "") or (
            "非法共享目录被拦截" if result["blocked"] else "非法共享目录被接受"
        )
        if self._share_drawer().count() > 0:
            self.cancel_share()
        return result

    # ==================== 主表单保存 ====================
    def fill_user_form(
        self,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        permission: Optional[str] = None,
        guest: Optional[bool] = None,
        shares: Optional[List[Dict]] = None,
    ) -> bool:
        checks: List[bool] = []
        if username is not None:
            checks.append(self.fill_username(username))
        if password is not None:
            checks.append(self.fill_password(password))
        if permission is not None:
            checks.append(self.set_permission(permission))
        if guest is not None:
            checks.append(self.set_guest(guest))
        if shares is not None:
            checks.append(self._replace_shares(list(shares)))
        return all(checks) if checks else True

    def save_user(self, timeout: int = 9000) -> Dict:
        result = {"success": False, "error": ""}
        try:
            if self._share_drawer().count() > 0:
                result["error"] = "共享目录 Drawer 尚未关闭"
                return result
            save = self.page.locator("div.footer button:visible").filter(
                has_text="保存"
            ).first
            if save.count() == 0:
                result["error"] = "未找到 Samba 用户保存按钮"
                return result
            save.click()
            for _ in range(max(1, timeout // 300)):
                self.page.wait_for_timeout(300)
                if not self.is_on_config_page():
                    self.switch_to_samba_tab()
                    result["success"] = True
                    return result
                error = self.get_form_error(self._main_form())
                if error:
                    result["error"] = error
                    return result
            result["error"] = "保存后仍在 Samba 用户配置页"
        except Exception as exc:
            result["error"] = str(exc)[:140]
        return result

    save_and_wait = save_user

    def cancel_user_form(self) -> bool:
        try:
            if self._share_drawer().count() > 0:
                self.cancel_share()
            cancel = self.page.locator("div.footer button:visible").filter(
                has_text="取消"
            ).first
            if cancel.count() > 0:
                cancel.click()
                self.page.wait_for_timeout(350)
                if self.page.locator(".ant-modal-wrap:visible").count() > 0:
                    self._click_visible_confirm(timeout=3000)
            else:
                self.page.goto(f"{self.base_url}{self.LIST_URL}")
            self._wait_page(400)
            if not self.is_on_config_page():
                self.switch_to_samba_tab()
                return True
        except Exception:
            pass
        return False

    def add_user(
        self,
        username: str,
        password: str,
        permission: str = "ro",
        guest: bool = False,
        shares: Optional[List[Dict]] = None,
    ) -> Dict:
        if not self.open_add_page():
            return {"success": False, "error": "进入 Samba 新增页失败"}
        if not self.fill_user_form(
            username=username,
            password=password,
            permission=permission,
            guest=guest,
            shares=list(shares or []),
        ):
            error = self.get_form_error(self._share_drawer()) or "Samba 用户表单填写失败"
            if self._share_drawer().count() > 0:
                self.cancel_share()
            return {"success": False, "error": error}
        if self.get_username_value() != str(username):
            self.cancel_user_form()
            return {"success": False, "error": "用户名被 maxlength=15 截断"}
        return self.save_user()

    add_rule = add_user

    def try_add_invalid(
        self,
        username: str,
        password: str,
        permission: str = "rw",
        guest: bool = False,
        shares: Optional[List[Dict]] = None,
        root: bool = False,
    ) -> Dict:
        result = {"blocked": False, "error": ""}
        if not self.open_add_page():
            result["error"] = "进入 Samba 新增页失败"
            return result
        actual_username = "root" if root else username
        self.fill_username(actual_username)
        self.fill_password(password)
        self.set_permission(permission)
        self.set_guest(guest)
        if self.get_username_value() != str(actual_username):
            result["blocked"] = True
            result["error"] = "用户名被 maxlength=15 截断"
            self.cancel_user_form()
            return result
        for share in list(shares or []):
            added = self.add_share(
                str(share.get("name", "")),
                str(share.get("home_dir", "")),
                str(share.get("browseable", "no")),
            )
            if not added.get("success"):
                result["blocked"] = True
                result["error"] = added.get("error", "非法共享目录被拦截")
                if self._share_drawer().count() > 0:
                    self.cancel_share()
                self.cancel_user_form()
                return result
        saved = self.save_user(timeout=3500)
        result["blocked"] = not saved["success"] and self.is_on_config_page()
        result["error"] = saved.get("error", "") or (
            "非法 Samba 用户被拦截" if result["blocked"] else "非法 Samba 用户被接受"
        )
        if self.is_on_config_page():
            self.cancel_user_form()
        return result

    # ==================== 列表行 CRUD ====================
    def _list_table(self) -> Locator:
        return self._samba_pane().locator(
            ".ant-table-wrapper:visible:has(th#username):has(th#guest)"
        ).first

    def _row_for_user(self, username: str) -> Locator:
        rows = self._list_table().locator("div.ant-table-row")
        try:
            for idx in range(rows.count()):
                row = rows.nth(idx)
                cells = row.locator(".ant-table-cell")
                for cell_idx in range(cells.count()):
                    if (cells.nth(cell_idx).inner_text() or "").strip() == username:
                        return row
        except Exception:
            pass
        return rows.filter(has_text=username).first

    def rule_exists(self, username: str) -> bool:
        try:
            row = self._row_for_user(username)
            if row.count() == 0 or not row.is_visible():
                return False
            cells = row.locator(".ant-table-cell")
            return any(
                (cells.nth(i).inner_text() or "").strip() == username
                for i in range(cells.count())
            )
        except Exception:
            return False

    user_exists = rule_exists

    def get_rule_names(self) -> List[str]:
        names: List[str] = []
        try:
            rows = self._list_table().locator("div.ant-table-row")
            for idx in range(rows.count()):
                cells = rows.nth(idx).locator(".ant-table-cell")
                for cell_idx in range(cells.count()):
                    cell = cells.nth(cell_idx)
                    if cell.locator("input[type='checkbox']").count() > 0:
                        continue
                    text = (cell.inner_text() or "").strip()
                    if text:
                        names.append(text)
                        break
        except Exception:
            pass
        return list(dict.fromkeys(names))

    def is_user_enabled(self, username: str) -> bool:
        try:
            row = self._row_for_user(username)
            return row.locator("button:visible").filter(has_text="停用").count() > 0
        except Exception:
            return False

    def is_user_disabled(self, username: str) -> bool:
        try:
            row = self._row_for_user(username)
            return row.locator("button:visible").filter(has_text="启用").count() > 0
        except Exception:
            return False

    is_rule_enabled = is_user_enabled
    is_rule_disabled = is_user_disabled

    def _click_user_action(self, username: str, action: str) -> bool:
        try:
            row = self._row_for_user(username)
            if row.count() == 0:
                return False
            buttons = row.locator("button:visible").filter(has_text=action)
            for idx in range(buttons.count()):
                button = buttons.nth(idx)
                if (button.inner_text() or "").strip() == action:
                    button.click()
                    return True
            return False
        except Exception:
            return False

    def edit_user(self, username: str) -> bool:
        if not self._click_user_action(username, "编辑"):
            return False
        for _ in range(18):
            self.page.wait_for_timeout(250)
            if self.is_on_config_page() and self.EDIT_FRAGMENT in self.page.url:
                return True
        return False

    edit_rule = edit_user

    def update_user(
        self,
        username: str,
        *,
        password: Optional[str] = None,
        permission: Optional[str] = None,
        guest: Optional[bool] = None,
        shares: Optional[List[Dict]] = None,
    ) -> Dict:
        if not self.edit_user(username):
            return {"success": False, "error": "进入 Samba 编辑页失败"}
        if not self.fill_user_form(
            password=password,
            permission=permission,
            guest=guest,
            shares=shares,
        ):
            return {"success": False, "error": "Samba 编辑表单填写失败"}
        return self.save_user()

    def disable_rule(self, username: str) -> bool:
        if not self._click_user_action(username, "停用"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        self.page.wait_for_timeout(700)
        return True

    def enable_rule(self, username: str) -> bool:
        if not self._click_user_action(username, "启用"):
            return False
        self.page.wait_for_timeout(800)
        return True

    def delete_rule(self, username: str) -> bool:
        if not self._click_user_action(username, "删除"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        for _ in range(15):
            self.page.wait_for_timeout(300)
            if not self.rule_exists(username):
                return True
        self.page.reload()
        self._wait_page(700)
        self.switch_to_samba_tab()
        return not self.rule_exists(username)

    delete_user = delete_rule

    def clean_test_rules(self, prefix: str = "smb_t_") -> int:
        """只逐条删除指定测试前缀，绝不全选存量用户。"""
        deleted = 0
        for _ in range(80):
            names = [n for n in self.get_rule_names() if n.startswith(prefix)]
            if not names:
                break
            if not self.delete_rule(names[0]):
                break
            deleted += 1
        return deleted

    # ==================== 搜索 / 排序 ====================
    def search_user(self, keyword: str):
        try:
            inp = self._samba_pane().get_by_placeholder("请输入搜索内容")
            inp.click()
            inp.fill(keyword)
            inp.press("Enter")
            self.page.wait_for_timeout(550)
        except Exception:
            pass
        return self

    def clear_user_search(self):
        try:
            inp = self._samba_pane().get_by_placeholder("请输入搜索内容")
            inp.click()
            inp.fill("")
            inp.press("Enter")
            self.page.wait_for_timeout(550)
        except Exception:
            pass
        return self

    search_rule = search_user
    clear_search = clear_user_search

    def sort_users_by_username(self) -> bool:
        """点击真实用户名排序入口；当前固件无入口时明确返回 False。"""
        try:
            th = self._samba_pane().locator("th#username:visible").first
            if th.count() == 0:
                return False
            th.hover()
            self.page.wait_for_timeout(200)
            icon = th.locator(".sortIcon .anticon svg, .ant-table-column-sorter")
            if icon.count() == 0:
                return False
            icon.first.click(force=True)
            self.page.wait_for_timeout(550)
            return True
        except Exception:
            return False

    sort_by_username = sort_users_by_username

    def sort_by_column(self, column_name: str) -> bool:
        if column_name == "用户名":
            return self.sort_users_by_username()
        return False

    # ==================== 批量操作 ====================
    def _clear_body_selection(self):
        try:
            table = self._list_table()
            table.evaluate("""root => {
                root.querySelectorAll(
                    'div.ant-table-row input[type=checkbox]:checked'
                ).forEach(cb => cb.click());
            }""")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _select_users(self, usernames: Iterable[str]) -> int:
        self._clear_body_selection()
        selected = 0
        for username in usernames:
            try:
                row = self._row_for_user(username)
                if row.count() == 0:
                    continue
                ok = row.evaluate("""row => {
                    const cb = row.querySelector('input[type=checkbox]');
                    if (!cb) return false;
                    if (!cb.checked) cb.click();
                    return true;
                }""")
                if ok:
                    selected += 1
                    self.page.wait_for_timeout(180)
            except Exception:
                pass
        self.page.wait_for_timeout(350)
        return selected

    def _click_batch_action(self, action: str) -> bool:
        try:
            pane = self._samba_pane()
            return bool(pane.evaluate("""(root, action) => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                for (const footer of root.querySelectorAll('div.footer')) {
                    if (!visible(footer)) continue;
                    const button = [...footer.querySelectorAll('button')].find(
                        b => visible(b) && norm(b.innerText || b.textContent) === action
                    );
                    if (button) {
                        button.click();
                        return true;
                    }
                }
                return false;
            }""", action))
        except Exception:
            return False

    def _after_batch(self):
        self.page.wait_for_timeout(900)
        self.page.reload()
        self._wait_page(700)
        self.switch_to_samba_tab()

    def batch_disable_users(self, usernames: Iterable[str]) -> bool:
        names = list(usernames)
        if not names or self._select_users(names) != len(names):
            return False
        if not self._click_batch_action("停用"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        self._after_batch()
        return True

    def batch_enable_users(self, usernames: Iterable[str]) -> bool:
        names = list(usernames)
        if not names or self._select_users(names) != len(names):
            return False
        if not self._click_batch_action("启用"):
            return False
        self._after_batch()
        return True

    def batch_delete_users(self, usernames: Iterable[str]) -> bool:
        names = list(usernames)
        if not names or self._select_users(names) != len(names):
            return False
        if not self._click_batch_action("删除"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        self._after_batch()
        return True

    # ==================== 导入 / 导出 ====================
    def click_import(self):
        self._samba_pane().get_by_role("button", name="导入", exact=True).click()
        return self

    def click_export(self):
        self._samba_pane().get_by_role("button", name="导出", exact=True).click()
        return self

    def export_rules(self, use_config_path: bool = True, export_format: str = "csv") -> bool:
        return super().export_rules(use_config_path, export_format)

    def import_rules(self, file_path: str, clear_existing: bool = False) -> bool:
        return super().import_rules(file_path, clear_existing)

    def attempt_import(self, file_path: str, clear_existing: bool = False) -> Dict:
        """
        提交一次 Samba CSV/TXT 导入并返回可判定的结构化结果。

        与通用 import_rules 不同，本方法不会把“弹窗关闭”直接当作成功：
        - clear_existing 必须显式设置并复读；
        - 只接受 CSV/TXT；
        - success/rejected 只由明确的成功/失败反馈决定；
        - finally 只关闭导入相关浮层，不点击任何确认型危险按钮。

        本方法不会读取、打印或拼接文件内容，导入文件可能包含明文密码。
        """
        import os

        result = {
            "submitted": False,
            "success": False,
            "rejected": False,
            "error": "",
            "clear_state": None,
        }
        modal = None

        def latest_visible_text(selector: str) -> str:
            try:
                loc = self.page.locator(selector)
                for index in range(loc.count() - 1, -1, -1):
                    item = loc.nth(index)
                    if item.is_visible():
                        text = (item.inner_text() or "").strip()
                        if text:
                            return text[:240]
            except Exception:
                pass
            return ""

        try:
            if not os.path.isfile(file_path):
                result["rejected"] = True
                result["error"] = "导入文件不存在"
                return result
            extension = os.path.splitext(file_path)[1].lower()
            if extension not in {".csv", ".txt"}:
                result["rejected"] = True
                result["error"] = "Samba导入仅支持CSV/TXT"
                return result

            if self._samba_pane().count() == 0:
                self.navigate_to_samba_server()
            if self._samba_pane().count() == 0:
                result["error"] = "Samba列表页未就绪"
                return result

            # 防止上一次操作的短暂 toast 被误认成本次反馈。
            for _ in range(20):
                if self.page.locator(
                    ".ant-message-success:visible, .ant-message-error:visible, "
                    ".ant-notification-notice-success:visible, "
                    ".ant-notification-notice-error:visible"
                ).count() == 0:
                    break
                self.page.wait_for_timeout(100)

            self.click_import()
            modal = self.page.locator(
                ".ant-modal-content:visible"
            ).filter(has_text="导入").last
            modal.wait_for(state="visible", timeout=5000)

            checkboxes = modal.locator("input[type='checkbox']")
            if checkboxes.count() != 1:
                result["error"] = (
                    f"导入弹窗清空选项数量异常: {checkboxes.count()}"
                )
                return result
            clear_box = checkboxes.first
            clear_box.set_checked(bool(clear_existing), force=True)
            self.page.wait_for_timeout(150)
            result["clear_state"] = bool(clear_box.is_checked())
            if result["clear_state"] != bool(clear_existing):
                result["error"] = "清空现有配置选项复读不一致，拒绝上传"
                return result

            file_inputs = modal.locator("input[type='file']")
            if file_inputs.count() != 1:
                result["error"] = (
                    f"导入弹窗文件输入数量异常: {file_inputs.count()}"
                )
                return result
            accept = (file_inputs.first.get_attribute("accept") or "").upper()
            if ".CSV" not in accept or ".TXT" not in accept:
                result["error"] = f"导入控件accept异常: {accept[:80]}"
                return result
            file_inputs.first.set_input_files(file_path)

            submit = modal.get_by_role("button", name="确定上传", exact=True)
            for _ in range(30):
                if submit.count() == 1 and not submit.is_disabled():
                    break
                self.page.wait_for_timeout(100)
            else:
                result["error"] = "选择文件后确定上传按钮仍不可用"
                return result

            submit.click()
            result["submitted"] = True

            error_selectors = (
                ".ant-message-error:visible, "
                ".ant-notification-notice-error:visible, "
                ".ant-alert-error:visible"
            )
            success_selectors = (
                ".ant-message-success:visible, "
                ".ant-notification-notice-success:visible, "
                ".ant-alert-success:visible"
            )
            negative_phrases = (
                "导入失败", "上传失败", "解析失败", "格式错误",
                "格式不正确", "格式不支持", "文件错误", "文件不合法",
                "导入数据有误", "导入有误", "失败原因",
            )
            positive_phrases = (
                "导入成功", "上传成功", "操作成功", "导入完成", "上传完成",
            )

            for _ in range(100):
                error_text = latest_visible_text(error_selectors)
                if error_text:
                    result["rejected"] = True
                    result["error"] = error_text
                    break
                success_text = latest_visible_text(success_selectors)
                if success_text:
                    result["success"] = True
                    break

                # 部分固件把导入结果放在第二个 modal，而不是 message toast。
                dialogs = self.page.locator(".ant-modal-content:visible")
                dialog_texts = []
                for index in range(dialogs.count()):
                    try:
                        text = (dialogs.nth(index).inner_text() or "").strip()
                        if text:
                            dialog_texts.append(text)
                    except Exception:
                        pass
                joined = "\n".join(dialog_texts)
                negative = next(
                    (phrase for phrase in negative_phrases if phrase in joined),
                    "",
                )
                if negative:
                    result["rejected"] = True
                    result["error"] = negative
                    break
                if any(phrase in joined for phrase in positive_phrases):
                    result["success"] = True
                    break
                self.page.wait_for_timeout(100)

            if not result["success"] and not result["rejected"]:
                result["error"] = "上传已提交，但未观察到明确成功或失败反馈"
            return result
        except Exception as exc:
            result["error"] = str(exc)[:180]
            return result
        finally:
            # 仅取消/关闭导入浮层。绝不点击“确定上传”或通用“确定”按钮。
            try:
                visible_modals = self.page.locator(".ant-modal-content:visible")
                for index in range(visible_modals.count() - 1, -1, -1):
                    current = visible_modals.nth(index)
                    text = (current.inner_text() or "").strip()
                    if not any(
                        token in text for token in (
                            "导入", "上传", "导入成功", "导入失败",
                        )
                    ):
                        continue
                    cancel = current.get_by_role(
                        "button", name="取消上传", exact=True
                    )
                    close = current.locator("button.ant-modal-close")
                    safe_close = current.get_by_role(
                        "button", name="关闭", exact=True
                    )
                    if cancel.count() > 0 and cancel.first.is_visible():
                        cancel.first.click()
                    elif close.count() > 0 and close.first.is_visible():
                        close.first.click()
                    elif safe_close.count() > 0 and safe_close.first.is_visible():
                        safe_close.first.click()
                    else:
                        self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(100)
            except Exception:
                try:
                    self.page.keyboard.press("Escape")
                except Exception:
                    pass

    # ==================== 文件管理 / 右下角帮助 ====================
    def open_file_manager(self, timeout: int = 6000) -> Dict:
        result = {
            "clicked": False,
            "popup_opened": False,
            "url": "",
            "no_orphan": False,
            "unsaved_confirm_seen": False,
        }
        popup = None
        context = self.page.context
        before_pages = list(context.pages)
        try:
            if not self.is_on_config_page() and not self.open_add_page():
                result["error"] = "进入 Samba 配置页失败"
                return result
            button = self.page.locator("div.functionArea button:visible").filter(
                has_text="文件管理"
            ).first
            if button.count() == 0:
                result["error"] = "未找到文件管理按钮"
                return result
            result["clicked"] = True

            button.click()
            deadline_ms = max(1000, int(timeout))
            elapsed_ms = 0
            modal = None
            while elapsed_ms < deadline_ms:
                new_pages = [
                    candidate for candidate in context.pages
                    if candidate not in before_pages
                ]
                if new_pages:
                    popup = new_pages[-1]
                    break
                candidate_modal = self.page.locator(".ant-modal-wrap:visible")
                if candidate_modal.count() > 0:
                    modal = candidate_modal.last
                    result["unsaved_confirm_seen"] = True
                    break
                self.page.wait_for_timeout(100)
                elapsed_ms += 100

            if popup is None and modal is not None:
                remaining = max(1000, deadline_ms - elapsed_ms)
                with self.page.expect_popup(timeout=remaining) as info:
                    if not self._click_visible_confirm(
                        timeout=min(2500, remaining)
                    ):
                        raise RuntimeError("未保存确认弹窗未找到可见确认按钮")
                popup = info.value

            if popup is None:
                result["error"] = "点击文件管理后未观察到popup或未保存确认弹窗"
                return result
            if popup is not None:
                result["popup_opened"] = True
                for _ in range(20):
                    if popup.url and popup.url != "about:blank":
                        break
                    popup.wait_for_timeout(150)
                result["url"] = popup.url or ""
        except Exception as exc:
            result["error"] = str(exc)[:140]
        finally:
            # 关闭且仅关闭本方法新建的页面；即使异常发生在 popup 赋值前也不留孤儿页。
            for candidate in list(context.pages):
                if candidate in before_pages:
                    continue
                try:
                    if not candidate.is_closed():
                        candidate.close()
                except Exception:
                    pass
            self.page.wait_for_timeout(250)
            result["no_orphan"] = all(
                candidate in before_pages for candidate in context.pages
            )
        return result

    def verify_help_entry(self, timeout: int = 8000) -> Dict:
        result = {
            "clicked": False,
            "popup_opened": False,
            "url": "",
            "no_orphan": False,
        }
        popup = None
        before = len(self.page.context.pages)
        try:
            # 右下角帮助是 localService 页面级浮层，不属于任何 tabpane。
            # 列表/开关/批量仍保持 Samba pane scope，仅此全局入口放宽。
            buttons = self.page.locator("button:visible").filter(has_text="帮助")
            if buttons.count() == 0:
                return result
            result["clicked"] = True
            with self.page.expect_popup(timeout=timeout) as info:
                buttons.first.click()
            popup = info.value
            result["popup_opened"] = popup is not None
            if popup is not None:
                for _ in range(20):
                    if popup.url and popup.url != "about:blank":
                        break
                    popup.wait_for_timeout(150)
                result["url"] = popup.url or ""
        except Exception as exc:
            result["error"] = str(exc)[:140]
        finally:
            try:
                if popup is not None and not popup.is_closed():
                    popup.close()
            except Exception:
                pass
            self.page.wait_for_timeout(250)
            result["no_orphan"] = len(self.page.context.pages) <= before
        return result
