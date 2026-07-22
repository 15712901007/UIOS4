"""
高级服务 > 本地服务 > HTTP服务 Page Object。

真实页面特征：
- 列表 URL 为 /#/advancedService/localService，HTTP 是 data-node-key=http 的第三个 Tab。
- 新增和编辑使用 /http/add、/http/edit 独立路由。
- 表单支持 HTTP/HTTPS、TreeSelect 目录、目录浏览、限速和外网访问。
- 列表是 Ant 虚拟表格，所有列表、搜索和批量操作必须限定在激活的 HTTP pane。
- 当前固件所有 HTTP 列头均没有排序入口，应如实返回无排序能力。
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional

from playwright.sync_api import Locator, Page

from pages.ikuai_table_page import IkuaiTablePage


class HttpServerPage(IkuaiTablePage):
    """HTTP 静态文件服务页面操作类。"""

    MODULE_NAME = "http_server"
    IMPORT_REQUIRES_CLEAR_GUARD = True

    LIST_URL = "/#/advancedService/localService"
    ADD_URL = "/#/advancedService/localService/http/add"
    EDIT_FRAGMENT = "/advancedService/localService/http/edit"
    FILE_MANAGER_FRAGMENT = "/equipmentSetting/diskManagement?tab=fileManagement"
    HELP_ARTICLE_ID = "602"
    HELP_URL = (
        "https://www.ikuai8.com/index.php?option=com_content&view=article"
        "&id=602&Itemid=472"
    )

    PROTOCOL_UI = {"0": "http", "1": "https"}
    AUTOINDEX_UI = {"0": "关闭", "1": "开启"}
    COLUMN_ID_MAP = {
        "名称": "tagname",
        "文件目录": "home_dir ",
        "访问方式": "ssl_on",
        "服务端口": "http_port",
        "服务域名": "server_name",
        "目录浏览权限": "autoindex",
        "外网访问": "access",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)
        self.last_cancel_result: Dict = {}
        self.last_fill_checks: Dict[str, bool] = {}

    # ==================== 通用小工具 ====================
    def _wait_page(self, settle_ms: int = 800):
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(settle_ms)

    def _dismiss_transient_overlays(self):
        """只关闭可取消的浮层，不点击任何确认型按钮。"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(150)
        except Exception:
            pass
        try:
            cancel = self.page.locator(
                ".ant-modal-wrap:visible button:has-text('取消'):visible, "
                ".ant-drawer-content[role='dialog']:visible "
                "button:has-text('取消'):visible"
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
                const input = el.matches('input[type=checkbox],input[type=radio]')
                    ? el : el.querySelector('input[type=checkbox],input[type=radio]');
                if (input) return !!input.checked;
                const sw = el.matches('.ant-switch') ? el : el.closest('.ant-switch');
                return !!(sw && (
                    sw.getAttribute('aria-checked') === 'true' ||
                    sw.classList.contains('ant-switch-checked')
                ));
            }"""))
        except Exception:
            return None

    def _fill_input(self, selector: str, value) -> bool:
        try:
            inp = self.page.locator(f"{selector}:visible").first
            if inp.count() == 0:
                return False
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(80)
            except Exception:
                pass
            inp.scroll_into_view_if_needed()
            inp.fill("")
            if value is not None and str(value) != "":
                inp.fill(str(value))
            inp.evaluate("""el => {
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            return True
        except Exception as exc:
            print(f"[DEBUG] fill {selector}: {str(exc)[:80]}")
            return False

    def _wait_transient_feedback_clear(self, timeout: int = 3500):
        """避免把上一次提交的短暂 toast 误判为本次结果。"""
        selectors = (
            ".ant-message-success:visible, .ant-message-error:visible, "
            ".ant-notification-notice-success:visible, "
            ".ant-notification-notice-error:visible"
        )
        for _ in range(max(1, timeout // 100)):
            try:
                if self.page.locator(selectors).count() == 0:
                    return
            except Exception:
                return
            self.page.wait_for_timeout(100)

    def get_form_error(self, root: Optional[Locator] = None) -> Optional[str]:
        """读取当前 HTTP 表单校验或最近一条 API 错误。"""
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
                        return text[:240]
            except Exception:
                pass
        for selector in (
            ".ant-message-error:visible",
            ".ant-notification-notice-error:visible",
        ):
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
        try:
            if scope.locator(
                ".ant-form-item-has-error:visible, "
                ".ant-input-status-error:visible, "
                ".ant-input-number-status-error:visible"
            ).count() > 0:
                return "输入格式错误"
        except Exception:
            pass
        return None

    def _select_option(
        self,
        field_selector: str,
        ui_text: str,
        code: str = "",
    ) -> bool:
        try:
            field = self.page.locator(f"{field_selector}:visible").first
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
                const norm = s => (s || '').replace(/\\s+/g, '').trim().toLowerCase();
                const dds = [...document.querySelectorAll('.ant-select-dropdown')]
                    .filter(visible);
                const dd = dds[dds.length - 1];
                if (!dd) return false;
                const target = [...dd.querySelectorAll('.ant-select-item-option')]
                    .find(option => {
                        const text = norm(option.innerText || option.textContent);
                        const value = norm(option.getAttribute('data-value') || '');
                        return text === norm(ui) || text === norm(code) ||
                            value === norm(code) || text.includes(norm(ui));
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

    # ==================== 列表导航和 HTTP pane ====================
    def _http_tab(self) -> Locator:
        tab = self.page.locator(".ant-tabs-tab[data-node-key='http']:visible")
        if tab.count() > 0:
            return tab.first
        return self.page.locator(".ant-tabs-tab:visible").filter(
            has_text="HTTP服务"
        ).first

    def _http_pane(self) -> Locator:
        pane = self.page.locator(
            "div.ant-tabs-tabpane-active[role='tabpanel']"
            "[aria-labelledby$='-tab-http']:visible"
        )
        if pane.count() > 0:
            return pane.first
        tab = self._http_tab()
        try:
            if (
                tab.count() > 0
                and "ant-tabs-tab-active" in (tab.get_attribute("class") or "")
            ):
                fallback = self.page.locator(".ant-tabs-tabpane-active:visible")
                if fallback.count() > 0:
                    return fallback.first
        except Exception:
            pass
        return self.page.locator("[data-http-pane-not-found='1']")

    def switch_to_http_tab(self) -> bool:
        try:
            tab = self._http_tab()
            if tab.count() == 0:
                return False
            if "ant-tabs-tab-active" not in (tab.get_attribute("class") or ""):
                tab.click()
                self.page.wait_for_timeout(900)
            pane = self._http_pane()
            return (
                pane.count() > 0
                and pane.locator("th#tagname:visible").count() > 0
                and pane.locator("th#http_port:visible").count() > 0
                and pane.locator("th#access:visible").count() > 0
            )
        except Exception as exc:
            print(f"[DEBUG] switch_to_http_tab: {str(exc)[:80]}")
            return False

    def navigate_to_http_server(self):
        self._dismiss_transient_overlays()
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        self._wait_page(1300)
        self.switch_to_http_tab()
        return self

    navigate_to_http = navigate_to_http_server

    def _list_table(self) -> Locator:
        return self._http_pane().locator(
            ".ant-table-wrapper:visible"
            ":has(th#tagname):has(th#http_port):has(th#access)"
        ).first

    def get_default_structure(self) -> Dict:
        """读取 HTTP Tab、工具栏、表头以及真实排序能力。"""
        result: Dict = {
            "url_ok": "advancedService/localService" in self.page.url,
            "http_tab_present": False,
            "http_tab_active": False,
            "http_tab_index": None,
            "table_present": False,
            "search_present": False,
            "headers": [],
            "header_ids": [],
            "buttons": [],
            "sortable_columns": [],
            "all_headers_unsortable": False,
        }
        try:
            tab = self._http_tab()
            result["http_tab_present"] = tab.count() > 0
            result["http_tab_active"] = (
                tab.count() > 0
                and "ant-tabs-tab-active" in (tab.get_attribute("class") or "")
            )
            tabs = self.page.locator(".ant-tabs-tab:visible")
            for index in range(tabs.count()):
                if tabs.nth(index).get_attribute("data-node-key") == "http":
                    result["http_tab_index"] = index
                    break
            pane = self._http_pane()
            if pane.count() == 0:
                return result
            result.update(pane.evaluate("""root => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                const table = [...root.querySelectorAll('.ant-table')].find(visible);
                const headers = table ? [...table.querySelectorAll(
                    '.ant-table-thead th'
                )].filter(h => visible(h) &&
                    !h.classList.contains('ant-table-measure-cell')) : [];
                const sortable = headers.filter(h =>
                    h.querySelector('.sortIcon, .ant-table-column-sorter') ||
                    h.hasAttribute('aria-sort')
                ).map(h => norm(h.innerText)).filter(Boolean);
                return {
                    table_present: !!table,
                    search_present: [...root.querySelectorAll(
                        "input[placeholder='请输入搜索内容']"
                    )].some(visible),
                    headers: headers.map(h => norm(h.innerText)).filter(Boolean),
                    header_ids: headers.map(h => h.id || ''),
                    buttons: [...root.querySelectorAll('button')].filter(visible)
                        .map(b => norm(b.innerText || b.textContent)).filter(Boolean),
                    sortable_columns: sortable,
                    all_headers_unsortable: sortable.length === 0
                };
            }"""))
        except Exception:
            pass
        return result

    # ==================== 新增/编辑表单 ====================
    def open_add_page(self) -> bool:
        self._dismiss_transient_overlays()
        # Ant TreeSelect 在长跑中会保留上一个配置页的虚拟树状态。每次新增先回
        # HTTP 列表销毁旧表单组件，再进入 add 路由，避免目录节点随机缺失。
        try:
            self.page.goto(f"{self.base_url}{self.LIST_URL}")
            self._wait_page(450)
            self.switch_to_http_tab()
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        self._wait_page(1300)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        route_ok = (
            "/advancedService/localService/http/add" in self.page.url
            or self.EDIT_FRAGMENT in self.page.url
        )
        try:
            return route_ok and self.page.locator("input#tagname:visible").count() > 0
        except Exception:
            return route_ok

    is_still_on_config_page = is_on_config_page

    def _main_form(self) -> Locator:
        form = self.page.locator("form.customForm:visible")
        if form.count() > 0:
            return form.first
        return self.page.locator("form:visible").first

    @staticmethod
    def _normalize_protocol(protocol) -> Optional[str]:
        if isinstance(protocol, bool):
            return "1" if protocol else "0"
        value = str(protocol).strip().lower()
        if value in {"0", "http"}:
            return "0"
        if value in {"1", "https"}:
            return "1"
        return None

    @staticmethod
    def _normalize_autoindex(autoindex) -> Optional[str]:
        if isinstance(autoindex, bool):
            return "1" if autoindex else "0"
        value = str(autoindex).strip().lower()
        if value in {"1", "true", "yes", "on", "enable", "enabled", "开启"}:
            return "1"
        if value in {"0", "false", "no", "off", "disable", "disabled", "关闭"}:
            return "0"
        return None

    def get_form_structure(self) -> Dict:
        """读取新增/编辑页字段、默认值、约束、目录根和按钮。"""
        result: Dict = {
            "url_ok": self.is_on_config_page(),
            "tagname_present": False,
            "tagname_required": False,
            "tagname_maxlength": None,
            "tagname_value": "",
            "home_dir_present": False,
            "home_dir_required": False,
            "home_dir_value": "",
            "home_dir_roots": [],
            "protocol_present": False,
            "protocol_options": [],
            "protocol_value": None,
            "http_port_present": False,
            "http_port_required": False,
            "http_port_value": "",
            "http_port_min": None,
            "http_port_max": None,
            "http_port_hint": "",
            "server_name_present": False,
            "server_name_required": False,
            "server_name_value": "",
            "autoindex_present": False,
            "autoindex_options": [],
            "autoindex_value": None,
            "download_present": False,
            "download_required": False,
            "download_value": None,
            "access_present": False,
            "access_checked": None,
            "file_manager_present": False,
            "save_present": False,
            "cancel_present": False,
        }
        try:
            form = self._main_form()
            if form.count() == 0:
                return result
            fields = form.evaluate("""root => {
                const norm = s => (s || '').replace(/\\s+/g, ' ').trim();
                const read = id => {
                    const el = root.querySelector('#' + id);
                    if (!el) return null;
                    const item = el.closest('.ant-form-item');
                    const select = el.closest('.ant-select');
                    return {
                        value: el.value || '',
                        checked: !!el.checked,
                        maxlength: el.getAttribute('maxlength'),
                        required: el.getAttribute('aria-required') === 'true' ||
                            !!(item && item.querySelector('.ant-form-item-required')),
                        select_value: select ? norm(
                            select.querySelector('.ant-select-selection-item')?.innerText
                        ) : ''
                    };
                };
                const hint = [...root.querySelectorAll('.ant-form-item-extra')]
                    .map(e => norm(e.innerText)).find(t => t.includes('1-65535')) || '';
                return {
                    tagname: read('tagname'), home_dir: read('home_dir'),
                    http_port: read('http_port'), server_name: read('server_name'),
                    autoindex: read('autoindex'), download: read('download'),
                    access: read('access'), http_port_hint: hint
                };
            }""")
            tag = fields.get("tagname")
            if tag:
                result.update({
                    "tagname_present": True,
                    "tagname_required": bool(tag.get("required")),
                    "tagname_value": tag.get("value", ""),
                })
                try:
                    result["tagname_maxlength"] = int(tag.get("maxlength"))
                except (TypeError, ValueError):
                    pass
            home = fields.get("home_dir")
            if home:
                result["home_dir_present"] = True
                result["home_dir_required"] = bool(home.get("required"))
                result["home_dir_value"] = home.get("select_value", "")
            port = fields.get("http_port")
            if port:
                result["http_port_present"] = True
                result["http_port_required"] = bool(port.get("required"))
                result["http_port_value"] = port.get("value", "")
            server = fields.get("server_name")
            if server:
                result["server_name_present"] = True
                result["server_name_required"] = bool(server.get("required"))
                result["server_name_value"] = server.get("value", "")
            auto = fields.get("autoindex")
            if auto:
                result["autoindex_present"] = True
                result["autoindex_value"] = auto.get("select_value", "")
            download = fields.get("download")
            if download:
                result["download_present"] = True
                result["download_required"] = bool(download.get("required"))
                result["download_value"] = download.get("value", "")
            access = fields.get("access")
            if access:
                result["access_present"] = True
                result["access_checked"] = bool(access.get("checked"))

            hint = fields.get("http_port_hint", "")
            result["http_port_hint"] = hint
            if "1-65535" in hint:
                result["http_port_min"] = 1
                result["http_port_max"] = 65535

            radios = form.locator("input[name='ssl_on']")
            protocol_options: List[str] = []
            for index in range(radios.count()):
                radio = radios.nth(index)
                code = radio.get_attribute("value") or ""
                if code in self.PROTOCOL_UI:
                    protocol_options.append(self.PROTOCOL_UI[code])
                if radio.is_checked():
                    result["protocol_value"] = self.PROTOCOL_UI.get(code, code)
            result["protocol_options"] = protocol_options
            result["protocol_present"] = set(protocol_options) == {"http", "https"}

            auto_field = form.locator("#autoindex").first
            if auto_field.count() > 0:
                select = auto_field.locator(
                    "xpath=ancestor::div[contains(concat(' ', normalize-space(@class), ' '), "
                    "' ant-select ')][1]"
                )
                select.locator(".ant-select-selector").click(timeout=3000)
                self.page.wait_for_timeout(200)
                result["autoindex_options"] = [
                    (text or "").strip()
                    for text in self.page.locator(
                        ".ant-select-dropdown:visible .ant-select-item-option"
                    ).all_inner_texts()
                    if (text or "").strip()
                ]
                self.page.keyboard.press("Escape")

            tree = self.get_home_dir_tree()
            result["home_dir_roots"] = tree.get("roots", [])
            button_texts: List[str] = []
            for buttons in (
                form.locator("button:visible"),
                self.page.locator("div.footer button:visible"),
            ):
                button_texts.extend(
                    (buttons.nth(i).inner_text() or "").strip()
                    for i in range(buttons.count())
                )
            result["file_manager_present"] = "文件管理" in button_texts
            result["save_present"] = "保存" in button_texts
            result["cancel_present"] = "取消" in button_texts
        except Exception:
            pass
        return result

    get_http_form_structure = get_form_structure

    def get_home_dir_tree(self) -> Dict:
        """只读打开目录 TreeSelect，返回当前可见节点并立即关闭。"""
        result = {"opened": False, "roots": [], "nodes": []}
        try:
            field = self.page.locator("#home_dir").first
            if field.count() == 0:
                return result
            selector = self.page.locator(
                ".ant-select:has(#home_dir) .ant-select-selector:visible"
            ).first
            selector.click(timeout=4000)
            self.page.wait_for_timeout(450)
            dropdown = self.page.locator(
                ".ant-select-dropdown:visible, .ant-tree-select-dropdown:visible"
            ).last
            if dropdown.count() == 0:
                return result
            result.update(dropdown.evaluate("""root => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, ' ').trim();
                const rows = [...root.querySelectorAll(
                    '.ant-select-tree-treenode, .ant-tree-treenode'
                )].filter(visible);
                const nodes = rows.map(row => {
                    const content = row.querySelector(
                        '.ant-select-tree-node-content-wrapper, ' +
                        '.ant-tree-node-content-wrapper, [title]'
                    );
                    const title = content ? (content.getAttribute('title') || '') : '';
                    const text = content ? norm(content.innerText || content.textContent) : '';
                    const expanded = row.getAttribute('aria-expanded') ||
                        row.querySelector('[aria-expanded]')?.getAttribute('aria-expanded') || '';
                    return {text, title, expanded};
                }).filter(node => node.text || node.title);
                const roots = nodes.filter((node, index) => {
                    const row = rows[index];
                    return row && !row.closest(
                        '.ant-select-tree-treenode .ant-select-tree-treenode, ' +
                        '.ant-tree-treenode .ant-tree-treenode'
                    );
                }).map(node => node.title || node.text);
                return {opened: true, nodes, roots: [...new Set(roots)]};
            }"""))
        except Exception as exc:
            result["error"] = str(exc)[:140]
        finally:
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(150)
            except Exception:
                pass
        return result

    get_directory_tree = get_home_dir_tree
    get_home_dir_tree_structure = get_home_dir_tree

    def fill_tagname(self, tagname: str) -> bool:
        return self._fill_input("#tagname", tagname)

    def get_tagname_value(self) -> str:
        try:
            return self.page.locator("#tagname:visible").first.input_value()
        except Exception:
            return ""

    def fill_http_port(self, http_port) -> bool:
        return self._fill_input("#http_port", http_port)

    def get_http_port_value(self) -> str:
        try:
            return self.page.locator("#http_port:visible").first.input_value()
        except Exception:
            return ""

    def fill_server_name(self, server_name: str) -> bool:
        return self._fill_input("#server_name", server_name)

    def get_server_name_value(self) -> str:
        try:
            return self.page.locator("#server_name:visible").first.input_value()
        except Exception:
            return ""

    def fill_download(self, download) -> bool:
        return self._fill_input("#download", download)

    def get_download_value(self) -> str:
        try:
            return self.page.locator("#download:visible").first.input_value()
        except Exception:
            return ""

    def set_protocol(self, protocol) -> bool:
        code = self._normalize_protocol(protocol)
        if code is None:
            return False
        try:
            radio = self.page.locator(
                f"input[name='ssl_on'][value='{code}']:visible"
            ).first
            if radio.count() == 0:
                return False
            if not radio.is_checked():
                radio.check(force=True)
                self.page.wait_for_timeout(250)
            return radio.is_checked()
        except Exception as exc:
            print(f"[DEBUG] set_protocol({protocol}): {str(exc)[:80]}")
            return False

    set_ssl_on = set_protocol

    def get_protocol(self) -> Optional[str]:
        try:
            radios = self.page.locator("input[name='ssl_on']:visible")
            for index in range(radios.count()):
                radio = radios.nth(index)
                if radio.is_checked():
                    code = radio.get_attribute("value") or ""
                    return self.PROTOCOL_UI.get(code, code)
        except Exception:
            pass
        return None

    def set_autoindex(self, autoindex) -> bool:
        code = self._normalize_autoindex(autoindex)
        if code is None:
            return False
        return self._select_option(
            "#autoindex", self.AUTOINDEX_UI[code], code
        )

    def get_autoindex(self) -> Optional[str]:
        try:
            value = self.page.locator(
                ".ant-select:has(#autoindex) .ant-select-selection-item"
            ).first.inner_text()
            value = (value or "").strip()
            if value in self.AUTOINDEX_UI.values():
                return value
            return value or None
        except Exception:
            return None

    def set_access(self, enabled: bool) -> bool:
        try:
            control = self.page.locator("#access:visible").first
            if control.count() == 0:
                return False
            current = self._control_checked(control)
            if current is bool(enabled):
                return True
            control.set_checked(bool(enabled), force=True)
            self.page.wait_for_timeout(250)
            return self._control_checked(control) is bool(enabled)
        except Exception as exc:
            print(f"[DEBUG] set_access({enabled}): {str(exc)[:80]}")
            return False

    set_external_access = set_access

    def get_access(self) -> Optional[bool]:
        try:
            return self._control_checked(self.page.locator("#access:visible").first)
        except Exception:
            return None

    def _mark_tree_node(self, title: str, path_hint: str = "") -> bool:
        try:
            return bool(self.page.evaluate("""({title, pathHint}) => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\\\/g, '/').replace(/\\s+/g, '').trim();
                document.querySelectorAll('[data-http-tree-node]').forEach(
                    e => e.removeAttribute('data-http-tree-node')
                );
                const dds = [...document.querySelectorAll(
                    '.ant-select-dropdown, .ant-tree-select-dropdown'
                )].filter(visible);
                const dd = dds[dds.length - 1];
                if (!dd) return false;
                const rows = [...dd.querySelectorAll(
                    '.ant-select-tree-treenode, .ant-tree-treenode'
                )].filter(visible);
                const wanted = norm(title);
                const wantedPath = norm(pathHint).replace(/^\\/+/, '');
                const candidates = rows.map(row => {
                    const content = row.querySelector(
                        '.ant-select-tree-node-content-wrapper, ' +
                        '.ant-tree-node-content-wrapper, [title]'
                    );
                    const attr = norm(content?.getAttribute('title') || '');
                    const text = norm(content?.innerText || content?.textContent || '');
                    return {row, attr, text};
                });
                let hit = candidates.find(item => wantedPath && (
                    item.attr.replace(/^\\/+/, '') === wantedPath ||
                    item.attr.replace(/^\\/+/, '').endsWith('/' + wantedPath)
                ));
                if (!hit) hit = candidates.find(item =>
                    item.attr === wanted || item.text === wanted ||
                    item.attr.endsWith('/' + wanted)
                );
                if (!hit) return false;
                hit.row.setAttribute('data-http-tree-node', '1');
                return true;
            }""", {"title": title, "pathHint": path_hint}))
        except Exception:
            return False

    def select_home_dir(self, path: str) -> bool:
        """选择目录，例如 /666/http_t_suite。"""
        try:
            field = self.page.locator("#home_dir:visible").first
            if field.count() == 0:
                return False
            selector = self.page.locator(
                ".ant-select:has(#home_dir) .ant-select-selector:visible"
            ).first
            selector.click(timeout=4000)
            self.page.wait_for_timeout(500)
            parts = [part for part in str(path).replace("\\", "/").split("/") if part]
            if not parts:
                return False
            for index, part in enumerate(parts[:-1]):
                path_hint = "/".join(parts[: index + 1])
                if not self._mark_tree_node(part, path_hint):
                    return False
                row = self.page.locator("[data-http-tree-node='1']").first
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
                    self.page.wait_for_timeout(550)
            final_hint = "/".join(parts)
            if not self._mark_tree_node(parts[-1], final_hint):
                return False
            row = self.page.locator("[data-http-tree-node='1']").first
            content = row.locator(
                ".ant-select-tree-node-content-wrapper, "
                ".ant-tree-node-content-wrapper, [title]"
            ).first
            (content if content.count() > 0 else row).click()
            self.page.wait_for_timeout(350)
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(120)
            except Exception:
                pass
            selected = self.get_home_dir_value().replace("\\", "/")
            return bool(
                selected
                and (
                    selected.rstrip("/") == str(path).replace("\\", "/").rstrip("/")
                    or selected.rstrip("/").endswith("/" + parts[-1])
                    or selected == parts[-1]
                )
            )
        except Exception as exc:
            print(f"[DEBUG] select_home_dir: {str(exc)[:80]}")
            return False

    def get_home_dir_value(self) -> str:
        try:
            item = self.page.locator(
                ".ant-select:visible:has(#home_dir) .ant-select-selection-item"
            ).first
            if item.count() == 0:
                return ""
            return (
                item.get_attribute("title")
                or item.get_attribute("data-title")
                or item.inner_text()
                or ""
            ).strip()
        except Exception:
            return ""

    def _search_home_dir(self, path: str) -> bool:
        """TreeSelect长跑状态不稳时，按最终目录名搜索并精确选择。"""
        try:
            parts = [part for part in str(path).replace("\\", "/").split("/") if part]
            if not parts:
                return False
            selector = self.page.locator(
                ".ant-select:has(#home_dir) .ant-select-selector:visible"
            ).first
            selector.click(timeout=4000)
            self.page.wait_for_timeout(250)
            field = self.page.locator("#home_dir:visible").first
            field.fill(parts[-1])
            self.page.wait_for_timeout(500)
            clicked = self.page.evaluate("""({name, fullPath}) => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\\\/g, '/').replace(/\\s+/g, '').trim();
                const dds = [...document.querySelectorAll(
                    '.ant-select-dropdown, .ant-tree-select-dropdown'
                )].filter(visible);
                const dd = dds[dds.length - 1];
                if (!dd) return false;
                const rows = [...dd.querySelectorAll(
                    '.ant-select-tree-treenode, .ant-tree-treenode'
                )].filter(visible);
                const wanted = norm(name);
                const wantedPath = norm(fullPath).replace(/^\\/+/, '');
                const hit = rows.find(row => {
                    const content = row.querySelector(
                        '.ant-select-tree-node-content-wrapper, ' +
                        '.ant-tree-node-content-wrapper, [title]'
                    );
                    if (!content) return false;
                    const title = norm(content.getAttribute('title') || '');
                    const text = norm(content.innerText || content.textContent || '');
                    const clean = title.replace(/^\\/+/, '');
                    return clean === wantedPath || clean.endsWith('/' + wantedPath) ||
                        title === wanted || text === wanted || title.endsWith('/' + wanted);
                });
                if (!hit) return false;
                const content = hit.querySelector(
                    '.ant-select-tree-node-content-wrapper, ' +
                    '.ant-tree-node-content-wrapper, [title]'
                );
                (content || hit).click();
                return true;
            }""", {"name": parts[-1], "fullPath": "/".join(parts)})
            self.page.wait_for_timeout(350)
            self.page.keyboard.press("Escape")
            selected = self.get_home_dir_value().replace("\\", "/")
            return bool(clicked and selected and (
                selected.rstrip("/") == str(path).replace("\\", "/").rstrip("/")
                or selected.rstrip("/").endswith("/" + parts[-1])
                or selected == parts[-1]
            ))
        except Exception as exc:
            print(f"[DEBUG] search_home_dir: {str(exc)[:100]}")
            return False

    def fill_rule_form(
        self,
        *,
        tagname: Optional[str] = None,
        home_dir: Optional[str] = None,
        protocol=None,
        http_port=None,
        server_name: Optional[str] = None,
        autoindex=None,
        download=None,
        access: Optional[bool] = None,
    ) -> bool:
        checks: Dict[str, bool] = {}
        if tagname is not None:
            checks["tagname"] = self.fill_tagname(tagname)
        if home_dir is not None:
            selected = self.select_home_dir(home_dir)
            if not selected:
                selected = self._search_home_dir(home_dir)
            checks["home_dir"] = selected
        if protocol is not None:
            checks["protocol"] = self.set_protocol(protocol)
        if http_port is not None:
            checks["http_port"] = self.fill_http_port(http_port)
        if server_name is not None:
            checks["server_name"] = self.fill_server_name(server_name)
        if autoindex is not None:
            checks["autoindex"] = self.set_autoindex(autoindex)
        if download is not None:
            checks["download"] = self.fill_download(download)
        if access is not None:
            checks["access"] = self.set_access(access)
        self.last_fill_checks = dict(checks)
        return all(checks.values()) if checks else True

    def save_rule(self, timeout: int = 9000) -> Dict:
        result = {
            "submitted": False,
            "success": False,
            "error": "",
            "still_on_form": self.is_on_config_page(),
            "url": self.page.url,
        }
        try:
            self.page.keyboard.press("Escape")
            self._wait_transient_feedback_clear()
            save = self.page.locator("div.footer button:visible").filter(
                has_text="保存"
            ).first
            if save.count() == 0:
                save = self.page.get_by_role("button", name="保存", exact=True).first
            if save.count() == 0:
                result["error"] = "未找到 HTTP 规则保存按钮"
                return result
            save.click()
            result["submitted"] = True
            for _ in range(max(1, timeout // 300)):
                self.page.wait_for_timeout(300)
                if not self.is_on_config_page():
                    self.switch_to_http_tab()
                    result["success"] = True
                    result["still_on_form"] = False
                    result["url"] = self.page.url
                    return result
                error = self.get_form_error(self._main_form())
                if error:
                    result["error"] = error
                    result["still_on_form"] = True
                    result["url"] = self.page.url
                    return result
            result["error"] = "保存后仍在 HTTP 规则配置页"
        except Exception as exc:
            result["error"] = str(exc)[:180]
        result["still_on_form"] = self.is_on_config_page()
        result["url"] = self.page.url
        return result

    save_and_wait = save_rule

    def cancel_rule_form(self, confirm_dirty: bool = True) -> bool:
        """取消配置页；dirty 时按参数确认退出或留在表单。"""
        self.last_cancel_result = {
            "clicked": False,
            "unsaved_confirm_seen": False,
            "message": "",
            "confirmed": False,
            "left_form": False,
        }
        try:
            if not self.is_on_config_page():
                self.last_cancel_result["left_form"] = True
                return True
            cancel = self.page.locator("div.footer button:visible").filter(
                has_text="取消"
            ).first
            if cancel.count() == 0:
                cancel = self.page.get_by_role("button", name="取消", exact=True).first
            if cancel.count() == 0:
                return False
            cancel.click()
            self.last_cancel_result["clicked"] = True
            self.page.wait_for_timeout(350)
            modal = self.page.locator(".ant-modal-content:visible").last
            if modal.count() > 0:
                message = (modal.inner_text() or "").strip()
                if "当前内容未保存" in message:
                    self.last_cancel_result["unsaved_confirm_seen"] = True
                    self.last_cancel_result["message"] = message
                button_name = "确定" if confirm_dirty else "取消"
                button = modal.get_by_role("button", name=button_name, exact=True)
                if button.count() == 0:
                    return False
                button.click()
                self.last_cancel_result["confirmed"] = bool(confirm_dirty)
                self.page.wait_for_timeout(450)
            if confirm_dirty:
                for _ in range(12):
                    if not self.is_on_config_page():
                        self.switch_to_http_tab()
                        self.last_cancel_result["left_form"] = True
                        return True
                    self.page.wait_for_timeout(250)
                return False
            self.last_cancel_result["left_form"] = not self.is_on_config_page()
            return self.is_on_config_page()
        except Exception as exc:
            self.last_cancel_result["error"] = str(exc)[:140]
            return False

    cancel_form = cancel_rule_form
    cancel_http_form = cancel_rule_form

    def verify_dirty_cancel(self, dirty_value: str = "http_dirty") -> Dict:
        """制造本地 dirty 状态，验证未保存确认后退出；不会提交规则。"""
        result = {
            "filled": False,
            "cancelled": False,
            "unsaved_confirm_seen": False,
            "message": "",
            "left_form": False,
        }
        if not self.is_on_config_page() and not self.open_add_page():
            result["error"] = "进入 HTTP 新增页失败"
            return result
        result["filled"] = self.fill_tagname(dirty_value)
        if not result["filled"]:
            result["error"] = "制造 dirty 名称失败"
            return result
        result["cancelled"] = self.cancel_rule_form(confirm_dirty=True)
        result.update({
            "unsaved_confirm_seen": bool(
                self.last_cancel_result.get("unsaved_confirm_seen")
            ),
            "message": self.last_cancel_result.get("message", ""),
            "left_form": bool(self.last_cancel_result.get("left_form")),
        })
        return result

    def add_rule(
        self,
        tagname: str,
        home_dir: str,
        protocol="http",
        http_port=None,
        server_name: str = "",
        autoindex=False,
        download=0,
        access: bool = False,
    ) -> Dict:
        filled = False
        for attempt in range(2):
            if not self.open_add_page():
                if attempt == 0:
                    continue
                return {"success": False, "error": "进入 HTTP 新增页失败"}
            filled = self.fill_rule_form(
                tagname=tagname,
                home_dir=home_dir,
                protocol=protocol,
                http_port=http_port,
                server_name=server_name,
                autoindex=autoindex,
                download=download,
                access=access,
            )
            if filled:
                break
            if attempt == 0:
                self._dismiss_transient_overlays()
        if not filled:
            failed = [key for key, ok in self.last_fill_checks.items() if not ok]
            return {
                "success": False,
                "error": "HTTP 规则表单填写不完整: " + ",".join(failed),
                "fill_checks": dict(self.last_fill_checks),
            }
        if self.get_tagname_value() != str(tagname):
            self.cancel_rule_form()
            return {"success": False, "error": "名称被 maxlength=15 截断"}
        return self.save_rule()

    def try_add_invalid(
        self,
        *,
        tagname: str = "",
        home_dir: Optional[str] = None,
        protocol="http",
        http_port=None,
        server_name: Optional[str] = "",
        autoindex=False,
        download=0,
        access: bool = False,
        timeout: int = 3500,
    ) -> Dict:
        """提交异常表单并返回 blocked/error 等结构化结果。"""
        result = {
            "submitted": False,
            "success": False,
            "blocked": False,
            "error": "",
            "still_on_form": False,
            "actual_tagname": "",
            "truncated": False,
        }
        if not self.open_add_page():
            result["error"] = "进入 HTTP 新增页失败"
            return result
        self.fill_tagname(tagname)
        result["actual_tagname"] = self.get_tagname_value()
        if result["actual_tagname"] != str(tagname):
            result["blocked"] = True
            result["truncated"] = True
            result["still_on_form"] = True
            result["error"] = "名称被 maxlength=15 截断"
            self.cancel_rule_form()
            return result
        if home_dir is not None:
            self.select_home_dir(home_dir)
        if protocol is not None:
            self.set_protocol(protocol)
        if http_port is not None:
            self.fill_http_port(http_port)
        if server_name is not None:
            self.fill_server_name(server_name)
        if autoindex is not None:
            self.set_autoindex(autoindex)
        if download is not None:
            self.fill_download(download)
        if access is not None:
            self.set_access(access)
        saved = self.save_rule(timeout=timeout)
        result["submitted"] = bool(saved.get("submitted"))
        result["success"] = bool(saved.get("success"))
        result["still_on_form"] = self.is_on_config_page()
        result["blocked"] = not result["success"] and result["still_on_form"]
        result["error"] = saved.get("error", "") or (
            "非法 HTTP 规则被拦截" if result["blocked"] else "非法 HTTP 规则被接受"
        )
        if result["still_on_form"]:
            self.cancel_rule_form()
        return result

    # ==================== 列表 CRUD ====================
    def _row_for_rule(self, tagname: str) -> Locator:
        rows = self._list_table().locator("div.ant-table-row")
        try:
            for index in range(rows.count()):
                row = rows.nth(index)
                cells = row.locator(".ant-table-cell")
                for cell_index in range(cells.count()):
                    if (cells.nth(cell_index).inner_text() or "").strip() == tagname:
                        return row
        except Exception:
            pass
        return rows.filter(has_text=tagname).first

    def rule_exists(self, tagname: str) -> bool:
        try:
            row = self._row_for_rule(tagname)
            if row.count() == 0 or not row.is_visible():
                return False
            cells = row.locator(".ant-table-cell")
            return any(
                (cells.nth(index).inner_text() or "").strip() == tagname
                for index in range(cells.count())
            )
        except Exception:
            return False

    def get_rule_names(self) -> List[str]:
        names: List[str] = []
        try:
            rows = self._list_table().locator("div.ant-table-row")
            for index in range(rows.count()):
                cells = rows.nth(index).locator(".ant-table-cell")
                for cell_index in range(cells.count()):
                    cell = cells.nth(cell_index)
                    if cell.locator("input[type='checkbox']").count() > 0:
                        continue
                    value = (cell.inner_text() or "").strip()
                    if value:
                        names.append(value)
                        break
        except Exception:
            pass
        return list(dict.fromkeys(names))

    def is_rule_enabled(self, tagname: str) -> bool:
        try:
            return self._row_for_rule(tagname).locator(
                "button:visible"
            ).filter(has_text="停用").count() > 0
        except Exception:
            return False

    def is_rule_disabled(self, tagname: str) -> bool:
        try:
            return self._row_for_rule(tagname).locator(
                "button:visible"
            ).filter(has_text="启用").count() > 0
        except Exception:
            return False

    def _click_rule_action(self, tagname: str, action: str) -> bool:
        try:
            row = self._row_for_rule(tagname)
            if row.count() == 0:
                return False
            buttons = row.locator("button:visible").filter(has_text=action)
            for index in range(buttons.count()):
                button = buttons.nth(index)
                if (button.inner_text() or "").strip() == action:
                    button.click()
                    return True
            return False
        except Exception:
            return False

    def edit_rule(self, tagname: str) -> bool:
        if not self._click_rule_action(tagname, "编辑"):
            return False
        for _ in range(20):
            self.page.wait_for_timeout(250)
            if self.is_on_config_page() and self.EDIT_FRAGMENT in self.page.url:
                return True
        return False

    def update_rule(
        self,
        tagname: str,
        *,
        new_tagname: Optional[str] = None,
        home_dir: Optional[str] = None,
        protocol=None,
        http_port=None,
        server_name: Optional[str] = None,
        autoindex=None,
        download=None,
        access: Optional[bool] = None,
    ) -> Dict:
        if not self.edit_rule(tagname):
            return {"success": False, "error": "进入 HTTP 编辑页失败"}
        if not self.fill_rule_form(
            tagname=new_tagname,
            home_dir=home_dir,
            protocol=protocol,
            http_port=http_port,
            server_name=server_name,
            autoindex=autoindex,
            download=download,
            access=access,
        ):
            failed = [key for key, ok in self.last_fill_checks.items() if not ok]
            return {
                "success": False,
                "error": "HTTP 编辑表单填写不完整: " + ",".join(failed),
                "fill_checks": dict(self.last_fill_checks),
            }
        if new_tagname is not None and self.get_tagname_value() != str(new_tagname):
            self.cancel_rule_form()
            return {"success": False, "error": "编辑后的名称被 maxlength=15 截断"}
        return self.save_rule()

    def disable_rule(self, tagname: str) -> bool:
        if not self._click_rule_action(tagname, "停用"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        self.page.wait_for_timeout(900)
        return True

    def enable_rule(self, tagname: str) -> bool:
        if not self._click_rule_action(tagname, "启用"):
            return False
        self.page.wait_for_timeout(900)
        return True

    def delete_rule(self, tagname: str) -> bool:
        if not self._click_rule_action(tagname, "删除"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        for _ in range(18):
            self.page.wait_for_timeout(300)
            if not self.rule_exists(tagname):
                return True
        self.page.reload()
        self._wait_page(700)
        self.switch_to_http_tab()
        return not self.rule_exists(tagname)

    def clean_test_rules(self, prefix: str = "http_t_") -> int:
        deleted = 0
        for _ in range(100):
            names = [name for name in self.get_rule_names() if name.startswith(prefix)]
            if not names:
                break
            if not self.delete_rule(names[0]):
                break
            deleted += 1
        return deleted

    # ==================== 搜索 / 排序能力 ====================
    def search_rule(self, keyword: str):
        try:
            field = self._http_pane().get_by_placeholder("请输入搜索内容")
            field.click()
            field.fill(str(keyword))
            field.press("Enter")
            self.page.wait_for_timeout(550)
        except Exception:
            pass
        return self

    def clear_search(self):
        return self.search_rule("")

    def sort_by_column(self, column_name: str) -> bool:
        """当前固件 HTTP 表头无 sorter；若未来新增则可在这里显式实现。"""
        column_id = self.COLUMN_ID_MAP.get(column_name)
        if not column_id:
            return False
        try:
            header = self._http_pane().locator(
                f"th#{column_id.strip()}:visible"
            ).first
            return bool(
                header.count() > 0
                and header.locator(
                    ".sortIcon, .ant-table-column-sorter, [aria-sort]"
                ).count() > 0
                and False
            )
        except Exception:
            return False

    # ==================== 批量操作 ====================
    def _clear_body_selection(self):
        try:
            self._list_table().evaluate("""root => {
                root.querySelectorAll(
                    'div.ant-table-row input[type=checkbox]:checked'
                ).forEach(input => input.click());
            }""")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _select_rules(self, tagnames: Iterable[str]) -> int:
        self._clear_body_selection()
        selected = 0
        for tagname in list(tagnames):
            try:
                row = self._row_for_rule(tagname)
                if row.count() == 0:
                    continue
                checked = row.evaluate("""row => {
                    const input = row.querySelector('input[type=checkbox]');
                    if (!input) return false;
                    if (!input.checked) input.click();
                    return !!input.checked;
                }""")
                if checked:
                    selected += 1
                    self.page.wait_for_timeout(180)
            except Exception:
                pass
        self.page.wait_for_timeout(300)
        return selected

    def _click_batch_action(self, action: str) -> bool:
        try:
            return bool(self._http_pane().evaluate("""(root, action) => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                for (const footer of root.querySelectorAll('div.footer')) {
                    if (!visible(footer)) continue;
                    const button = [...footer.querySelectorAll('button')].find(
                        item => visible(item) && norm(item.innerText) === action
                    );
                    if (button) { button.click(); return true; }
                }
                return false;
            }""", action))
        except Exception:
            return False

    def _after_batch(self):
        self.page.wait_for_timeout(1000)
        self.page.reload()
        self._wait_page(700)
        self.switch_to_http_tab()

    def batch_disable_rules(self, tagnames: Iterable[str]) -> bool:
        names = list(tagnames)
        if not names or self._select_rules(names) != len(names):
            return False
        if not self._click_batch_action("停用"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        self._after_batch()
        return True

    def batch_enable_rules(self, tagnames: Iterable[str]) -> bool:
        names = list(tagnames)
        if not names or self._select_rules(names) != len(names):
            return False
        if not self._click_batch_action("启用"):
            return False
        self._after_batch()
        return True

    def batch_delete_rules(self, tagnames: Iterable[str]) -> bool:
        names = list(tagnames)
        if not names or self._select_rules(names) != len(names):
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
        self._http_pane().get_by_role("button", name="导入", exact=True).click()
        return self

    def click_export(self):
        self._http_pane().get_by_role("button", name="导出", exact=True).click()
        return self

    def export_rules(
        self, use_config_path: bool = True, export_format: str = "csv"
    ) -> bool:
        return super().export_rules(use_config_path, export_format)

    def import_rules(self, file_path: str, clear_existing: bool = False) -> bool:
        return super().import_rules(file_path, clear_existing)

    def attempt_import(self, file_path: str, clear_existing: bool = False) -> Dict:
        """提交 CSV/TXT，并只按本次可见的明确反馈判定成功或拒绝。"""
        result = {
            "submitted": False,
            "success": False,
            "rejected": False,
            "clear_state": None,
            "feedback": "",
            "error": "",
        }
        modal = None

        def latest_visible_text(selector: str) -> str:
            try:
                items = self.page.locator(selector)
                for index in range(items.count() - 1, -1, -1):
                    item = items.nth(index)
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
            if os.path.splitext(file_path)[1].lower() not in {".csv", ".txt"}:
                result["rejected"] = True
                result["error"] = "HTTP服务仅支持CSV/TXT导入"
                return result
            self._wait_transient_feedback_clear(timeout=4000)
            self.click_import()
            modal = self.page.locator(".ant-modal-content:visible").filter(
                has_text="导入"
            ).last
            modal.wait_for(state="visible", timeout=5000)
            checkboxes = modal.locator("input[type='checkbox']")
            if checkboxes.count() != 1:
                result["error"] = f"导入清空选项数量异常: {checkboxes.count()}"
                return result
            checkbox = checkboxes.first
            checkbox.set_checked(bool(clear_existing), force=True)
            self.page.wait_for_timeout(150)
            result["clear_state"] = bool(checkbox.is_checked())
            if result["clear_state"] != bool(clear_existing):
                result["error"] = "清空现有配置选项复读不一致"
                return result
            file_input = modal.locator("input[type='file']")
            if file_input.count() != 1:
                result["error"] = "导入文件控件数量异常"
                return result
            accept = (file_input.first.get_attribute("accept") or "").upper()
            if ".CSV" not in accept or ".TXT" not in accept:
                result["error"] = f"导入控件accept异常: {accept[:80]}"
                return result
            file_input.first.set_input_files(file_path)
            submit = modal.get_by_role("button", name="确定上传", exact=True)
            for _ in range(30):
                if submit.count() == 1 and not submit.is_disabled():
                    break
                self.page.wait_for_timeout(100)
            else:
                result["error"] = "确定上传按钮未启用"
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
                "导入数据有误", "导入有误", "失败原因", "参数错误",
            )
            positive_phrases = (
                "导入成功", "上传成功", "操作成功", "导入完成", "上传完成",
            )
            for _ in range(100):
                error_text = latest_visible_text(error_selectors)
                if error_text:
                    result["rejected"] = True
                    result["feedback"] = error_text
                    result["error"] = error_text
                    break
                success_text = latest_visible_text(success_selectors)
                if success_text:
                    result["success"] = True
                    result["feedback"] = success_text
                    break

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
                    result["feedback"] = negative
                    result["error"] = negative
                    break
                positive = next(
                    (phrase for phrase in positive_phrases if phrase in joined),
                    "",
                )
                if positive:
                    result["success"] = True
                    result["feedback"] = positive
                    break
                self.page.wait_for_timeout(100)
            if not result["success"] and not result["rejected"]:
                result["error"] = "已提交但无明确成功/失败反馈"
        except Exception as exc:
            result["error"] = str(exc)[:180]
        finally:
            try:
                visible_modals = self.page.locator(".ant-modal-content:visible")
                for index in range(visible_modals.count() - 1, -1, -1):
                    current = visible_modals.nth(index)
                    text = (current.inner_text() or "").strip()
                    if not any(token in text for token in ("导入", "上传")):
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
        return result

    # ==================== 文件管理 / 帮助 ====================
    def open_file_manager(self, timeout: int = 6000) -> Dict:
        """HTTP dirty 表单实测也直接打开 popup，不虚构未保存确认。"""
        result = {
            "clicked": False,
            "popup_opened": False,
            "url": "",
            "no_orphan": False,
            "unsaved_confirm_seen": False,
        }
        context = self.page.context
        before_pages = list(context.pages)
        try:
            if not self.is_on_config_page() and not self.open_add_page():
                result["error"] = "进入 HTTP 配置页失败"
                return result
            button = self.page.get_by_role("button", name="文件管理", exact=True)
            if button.count() == 0:
                result["error"] = "未找到文件管理按钮"
                return result
            result["clicked"] = True
            button.click()
            popup = None
            for _ in range(max(10, timeout // 100)):
                new_pages = [item for item in context.pages if item not in before_pages]
                if new_pages:
                    popup = new_pages[-1]
                    break
                modal = self.page.locator(".ant-modal-content:visible")
                if modal.count() > 0 and "当前内容未保存" in (
                    modal.last.inner_text() or ""
                ):
                    result["unsaved_confirm_seen"] = True
                self.page.wait_for_timeout(100)
            if popup is None:
                result["error"] = "点击文件管理后未打开popup"
                return result
            result["popup_opened"] = True
            for _ in range(20):
                if popup.url and popup.url != "about:blank":
                    break
                popup.wait_for_timeout(150)
            result["url"] = popup.url or ""
        except Exception as exc:
            result["error"] = str(exc)[:160]
        finally:
            for candidate in list(context.pages):
                if candidate in before_pages:
                    continue
                try:
                    if not candidate.is_closed():
                        candidate.close()
                except Exception:
                    pass
            self.page.wait_for_timeout(200)
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
        context = self.page.context
        before_pages = list(context.pages)
        try:
            if "advancedService/localService" not in self.page.url:
                self.navigate_to_http_server()
            buttons = self.page.locator("button:visible").filter(has_text="帮助")
            if buttons.count() == 0:
                result["error"] = "未找到帮助按钮"
                return result
            result["clicked"] = True
            with self.page.expect_popup(timeout=timeout) as info:
                buttons.first.click()
            popup = info.value
            result["popup_opened"] = True
            for _ in range(20):
                if popup.url and popup.url != "about:blank":
                    break
                popup.wait_for_timeout(150)
            result["url"] = popup.url or ""
        except Exception as exc:
            result["error"] = str(exc)[:160]
        finally:
            for candidate in list(context.pages):
                if candidate in before_pages:
                    continue
                try:
                    if not candidate.is_closed():
                        candidate.close()
                except Exception:
                    pass
            self.page.wait_for_timeout(200)
            result["no_orphan"] = all(
                candidate in before_pages for candidate in context.pages
            )
        return result
