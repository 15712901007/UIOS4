"""
高级服务 > 本地服务 > SNMP服务 Page Object。

实机页面是 ``/#/advancedService/localService`` 下 ``data-node-key=snmp``
的单例配置表单，不是列表型 CRUD 页面。此对象因此只封装页面真实存在的
配置、启停、保存、取消和帮助操作，并通过能力矩阵如实记录列表相关功能为
不适用。

community、认证口令和加密口令不会出现在任何公开返回值或异常文本中。
结构探测只返回敏感字段是否存在、是否可见和是否已填写。
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage
from utils.step_recorder import register_sensitive_value


class SnmpServerPage(BasePage):
    """SNMP 单例服务配置页操作类。"""

    MODULE_NAME = "snmp_server"
    LIST_URL = "/#/advancedService/localService"
    TAB_KEY = "snmp"
    BACKEND_SCRIPT = "/usr/ikuai/script/netsnmp.sh"

    FIELD_NAMES: Sequence[str] = (
        "enabled",
        "listen_port",
        "syslocation",
        "syscontact",
        "sysname",
        "version",
        "community",
        "rw",
        "source",
        "username",
        "security",
        "auth_proto",
        "auth_pass",
        "password",
        "priv_proto",
        "priv_pass",
    )
    SENSITIVE_FIELDS = frozenset(
        {"community", "auth_pass", "password", "priv_pass"}
    )
    VERSION_OPTIONS = {
        "v2": ("V2C", "V2C"),
        "v2c": ("V2C", "V2C"),
        "2": ("V2C", "V2C"),
        "2c": ("V2C", "V2C"),
        "v3": ("V3", "V3"),
        "3": ("V3", "V3"),
    }
    SECURITY_OPTIONS = {
        "authnopriv": ("authNoPriv", "认证"),
        "认证": ("authNoPriv", "认证"),
        "authpriv": ("authPriv", "认证且加密"),
        "认证且加密": ("authPriv", "认证且加密"),
    }
    AUTH_PROTOCOLS = {"md5": ("MD5", "MD5"), "sha": ("SHA", "SHA")}
    PRIV_PROTOCOLS = {"des": ("DES", "DES"), "aes": ("AES", "AES")}

    _SENSITIVE_ASSIGNMENT = re.compile(
        r"(?i)(community|auth(?:entication)?[_ -]?(?:pass|password|key)|"
        r"priv(?:acy)?[_ -]?(?:pass|password|key)|password|团体名|共同体|"
        r"认证口令|认证密码|加密口令|隐私口令)"
        r"\s*[:=：]\s*([^\s,;，；]+)"
    )

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url.rstrip("/")
        self._known_secrets: List[str] = []
        self.last_fill_checks: Dict[str, bool] = {}
        self.last_cancel_result: Dict[str, Any] = {}
        self.last_navigation_api: List[Dict[str, Any]] = []

    # ==================== 通用及脱敏 ====================
    def _wait_page(self, settle_ms: int = 800):
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(settle_ms)

    def _remember_secret(self, value: Any):
        if value is None:
            return
        register_sensitive_value(value)
        text = str(value)
        for candidate in (text, text.strip()):
            if candidate and candidate not in self._known_secrets:
                self._known_secrets.append(candidate)

    def _redact(self, value: Any, limit: int = 240) -> str:
        """清除已填写密钥及常见 ``key=value`` 形式后再返回文本。"""
        text = "" if value is None else str(value)
        for secret in sorted(self._known_secrets, key=len, reverse=True):
            text = text.replace(secret, "[敏感信息已隐藏]")
        text = self._SENSITIVE_ASSIGNMENT.sub(
            lambda match: f"{match.group(1)}=[敏感信息已隐藏]", text
        )
        return text[:limit]

    @staticmethod
    def _norm(value: Any) -> str:
        return re.sub(r"\s+", "", str(value or "")).strip().lower()

    @staticmethod
    def _safe_api_metadata(request) -> Optional[Dict[str, Any]]:
        """Inspect a request in memory and retain no form parameter values."""
        try:
            payload = request.post_data_json or {}
            if not isinstance(payload, dict):
                return None
            if str(payload.get("func_name", "")).lower() != "netsnmp":
                return None
            return {
                "function": "netsnmp",
                "action": str(payload.get("action", "")),
                "method": str(request.method),
                "endpoint": request.url.split("?", 1)[0].rsplit("/", 1)[-1],
            }
        except Exception:
            return None

    def _dismiss_transient_overlays(self):
        """仅关闭下拉层，不点击任何会提交或放弃配置的确认按钮。"""
        try:
            if self.page.locator(
                ".ant-select-dropdown:visible, .ant-picker-dropdown:visible"
            ).count() > 0:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(120)
        except Exception:
            pass

    def _snmp_tab(self) -> Locator:
        tab = self.page.locator(
            ".ant-tabs-tab[data-node-key='snmp']:visible"
        )
        if tab.count() > 0:
            return tab.first
        return self.page.locator(".ant-tabs-tab:visible").filter(
            has_text="SNMP服务"
        ).first

    def _snmp_pane(self) -> Locator:
        candidates = (
            "div.ant-tabs-tabpane-active[role='tabpanel']"
            "[aria-labelledby$='-tab-snmp']:visible",
            "div.ant-tabs-tabpane-active[data-node-key='snmp']:visible",
            ".ant-tabs-tabpane-active:visible:has(#listen_port):has(#version)",
        )
        for selector in candidates:
            pane = self.page.locator(selector)
            if pane.count() > 0:
                return pane.first
        return self.page.locator("[data-snmp-pane-not-found='1']")

    def _form_root(self) -> Locator:
        pane = self._snmp_pane()
        if pane.count() > 0:
            form = pane.locator("form:visible")
            if form.count() > 0:
                return form.first
            return pane
        return self.page.locator("[data-snmp-form-not-found='1']")

    def _field(self, name: str) -> Locator:
        if name not in self.FIELD_NAMES:
            return self.page.locator("[data-snmp-field-not-found='1']")
        roots = (self._form_root(), self._snmp_pane())
        for root in roots:
            field = root.locator(f"#{name}")
            if field.count() > 0:
                return field.first
            field = root.locator(f"[name='{name}']")
            if field.count() > 0:
                return field.first
        return self.page.locator("[data-snmp-field-not-found='1']")

    @staticmethod
    def _control_checked(locator: Locator) -> Optional[bool]:
        try:
            return bool(locator.evaluate("""el => {
                const input = el.matches('input[type=checkbox],input[type=radio]')
                    ? el : el.querySelector('input[type=checkbox],input[type=radio]');
                if (input) return !!input.checked;
                const item = el.closest('.ant-form-item') || el.parentElement;
                const sw = el.matches('.ant-switch') ? el :
                    (el.closest('.ant-switch') || item?.querySelector('.ant-switch'));
                if (!sw) return false;
                return sw.getAttribute('aria-checked') === 'true' ||
                    sw.classList.contains('ant-switch-checked');
            }"""))
        except Exception:
            return None

    def _field_container(self, field: Locator, class_name: str) -> Locator:
        nearest = field.locator(
            "xpath=ancestor-or-self::*[contains(concat(' ', "
            "normalize-space(@class), ' '), ' " + class_name + " ')][1]"
        )
        if nearest.count() > 0:
            return nearest.first
        item = field.locator(
            "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), "
            "' '), ' ant-form-item ')][1]"
        )
        if item.count() > 0:
            nested = item.locator(f".{class_name}:visible")
            if nested.count() > 0:
                return nested.first
        return self.page.locator("[data-snmp-container-not-found='1']")

    # ==================== 导航与页面结构 ====================
    def switch_to_snmp_tab(self) -> bool:
        try:
            tab = self._snmp_tab()
            if tab.count() == 0:
                return False
            if "ant-tabs-tab-active" not in (tab.get_attribute("class") or ""):
                tab.click()
                self.page.wait_for_timeout(900)
            pane = self._snmp_pane()
            return (
                pane.count() > 0
                and self._field("version").count() > 0
                and self._field("listen_port").count() > 0
            )
        except Exception:
            return False

    def navigate_to_snmp_server(self):
        observations: List[Dict[str, Any]] = []

        def observe_response(response):
            metadata = self._safe_api_metadata(response.request)
            if metadata is not None:
                metadata.update({"responded": True, "status": int(response.status)})
                observations.append(metadata)

        self.page.on("response", observe_response)
        try:
            self._dismiss_transient_overlays()
            target_url = f"{self.base_url}{self.LIST_URL}"
            if "advancedService/localService" in self.page.url:
                # Navigating to an identical SPA hash does not remount the form
                # and therefore does not issue netsnmp/show.  A backend snapshot
                # restore would otherwise leave stale values in the DOM and the
                # next save could overwrite the restored singleton.
                self.page.reload(wait_until="domcontentloaded")
            else:
                self.page.goto(target_url)
            self._wait_page(1300)
            self.switch_to_snmp_tab()
            self.page.wait_for_timeout(500)
        finally:
            try:
                self.page.remove_listener("response", observe_response)
            except Exception:
                pass
        if observations:
            self.last_navigation_api = observations
        return self

    navigate_to_snmp = navigate_to_snmp_server

    def is_on_snmp_page(self) -> bool:
        try:
            return (
                "advancedService/localService" in self.page.url
                and self._snmp_tab().count() > 0
                and "ant-tabs-tab-active"
                in (self._snmp_tab().get_attribute("class") or "")
                and self._snmp_pane().count() > 0
            )
        except Exception:
            return False

    def _field_metadata(self, name: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "present": False,
            "visible": False,
            "required": False,
            "disabled": False,
            "control": "",
            "maxlength": None,
            "min": None,
            "max": None,
        }
        try:
            field = self._field(name)
            if field.count() == 0:
                return result
            data = field.evaluate("""el => {
                const item = el.closest('.ant-form-item');
                const select = el.closest('.ant-select') ||
                    item?.querySelector('.ant-select');
                const sw = el.closest('.ant-switch') ||
                    item?.querySelector('.ant-switch');
                const visible = node => !!(node && node.offsetParent !== null);
                let control = (el.tagName || '').toLowerCase();
                if (select) control = 'select';
                else if (sw) control = 'switch';
                else if (el.type) control = el.type;
                return {
                    visible: visible(el) || visible(select) || visible(sw),
                    required: el.getAttribute('aria-required') === 'true' ||
                        !!item?.querySelector('.ant-form-item-required'),
                    disabled: !!el.disabled || !!select?.classList.contains(
                        'ant-select-disabled') || !!sw?.disabled,
                    control,
                    maxlength: el.getAttribute('maxlength'),
                    min: el.getAttribute('min'),
                    max: el.getAttribute('max'),
                    populated: typeof el.value === 'string' && el.value.length > 0
                };
            }""")
            result.update({
                "present": True,
                "visible": bool(data.get("visible")),
                "required": bool(data.get("required")),
                "disabled": bool(data.get("disabled")),
                "control": data.get("control", ""),
                "maxlength": data.get("maxlength"),
                "min": data.get("min"),
                "max": data.get("max"),
            })
            if name in self.SENSITIVE_FIELDS:
                result["populated"] = bool(data.get("populated"))
        except Exception:
            pass
        return result

    def get_page_structure(self) -> Dict[str, Any]:
        """探测 SNMP 单例表单，不读取任何敏感字段值。"""
        result: Dict[str, Any] = {
            "url_ok": "advancedService/localService" in self.page.url,
            "tab_key": self.TAB_KEY,
            "tab_present": False,
            "tab_active": False,
            "tab_index": None,
            "singleton_form_present": False,
            "table_present": False,
            "search_present": False,
            "fields": {},
            "visible_fields": [],
            "version_options": [],
            "save_present": False,
            "cancel_present": False,
            "help_present": False,
        }
        try:
            tab = self._snmp_tab()
            result["tab_present"] = tab.count() > 0
            result["tab_active"] = (
                tab.count() > 0
                and "ant-tabs-tab-active" in (tab.get_attribute("class") or "")
            )
            tabs = self.page.locator(".ant-tabs-tab:visible")
            for index in range(tabs.count()):
                if tabs.nth(index).get_attribute("data-node-key") == self.TAB_KEY:
                    result["tab_index"] = index
                    break
            pane = self._snmp_pane()
            result["singleton_form_present"] = (
                pane.count() > 0
                and self._field("version").count() > 0
                and self._field("listen_port").count() > 0
            )
            if pane.count() > 0:
                result["table_present"] = pane.locator(
                    ".ant-table:visible, table:visible"
                ).count() > 0
                # Ant Design Select 自带 ``input[type=search]``，它只是下拉选项的
                # 内部检索控件，不能作为页面级搜索能力。只有记录表格存在，且有
                # 独立、带明确搜索语义的输入框时，才判定页面支持搜索。
                search_inputs = pane.locator(
                    "input[placeholder*='搜索']:visible, "
                    "input[aria-label*='搜索']:visible"
                )
                independent_search = bool(search_inputs.evaluate_all("""elements =>
                    elements.some(el => !el.closest('.ant-select') &&
                        el.getAttribute('role') !== 'combobox')
                """)) if search_inputs.count() > 0 else False
                result["search_present"] = bool(
                    result["table_present"] and independent_search
                )
            for name in self.FIELD_NAMES:
                meta = self._field_metadata(name)
                result["fields"][name] = meta
                if meta.get("visible"):
                    result["visible_fields"].append(name)
            result["version_options"] = self.probe_select_options("version")
            result["save_present"] = self._form_button("保存").count() > 0
            result["cancel_present"] = self._form_button("取消").count() > 0
            result["help_present"] = self._help_button().count() > 0
        except Exception:
            pass
        return result

    get_default_structure = get_page_structure
    get_form_structure = get_page_structure
    get_snmp_form_structure = get_page_structure

    def get_capability_matrix(self) -> Dict[str, Dict[str, Any]]:
        """根据当前 DOM 给出支持/不适用结论和可复核证据。"""
        structure = self.get_page_structure()
        pane = self._snmp_pane()
        buttons: List[str] = []
        sortable = False
        row_checks = False
        pagination = False
        try:
            if pane.count() > 0:
                buttons = [
                    re.sub(r"\s+", "", text or "")
                    for text in pane.locator("button:visible").all_inner_texts()
                ]
                sortable = pane.locator(
                    ".ant-table-column-sorter:visible, [aria-sort]:visible"
                ).count() > 0
                row_checks = pane.locator(
                    ".ant-table-tbody input[type='checkbox']:visible"
                ).count() > 0
                pagination = pane.locator(".ant-pagination:visible").count() > 0
        except Exception:
            pass

        single = bool(structure.get("singleton_form_present"))
        table = bool(structure.get("table_present"))
        search = bool(structure.get("search_present"))

        def item(supported: bool, evidence: str) -> Dict[str, Any]:
            return {
                "supported": supported,
                "result": "支持" if supported else "不适用",
                "evidence": evidence,
            }

        singleton_evidence = (
            "SNMP活动页检测到#version和#listen_port单例表单"
            if single else "SNMP活动页未检测到完整单例表单"
        )
        no_list_evidence = (
            "SNMP活动页存在记录表格"
            if table else "SNMP活动页无记录表格，页面模型为单例配置表单"
        )
        no_search_evidence = (
            "SNMP活动页检测到独立页面搜索控件"
            if search else
            "SNMP活动页无记录表格及独立搜索控件；Ant Select内部检索输入已排除"
        )
        return {
            "singleton_configuration_edit": item(single, singleton_evidence),
            "service_enable_disable": item(
                bool(structure["fields"].get("enabled", {}).get("present")),
                "检测字段#enabled" if structure["fields"].get(
                    "enabled", {}
                ).get("present") else "未检测到字段#enabled",
            ),
            "save": item(
                bool(structure.get("save_present")), "按可见按钮文本检测保存入口"
            ),
            "cancel": item(
                bool(structure.get("cancel_present")), "按可见按钮文本检测取消入口"
            ),
            "help": item(
                bool(structure.get("help_present")), "按页面级可见按钮检测帮助入口"
            ),
            "search_existing": item(search, no_search_evidence),
            "search_missing": item(search, no_search_evidence),
            "clear_search": item(search, no_search_evidence),
            "add_record": item("添加" in buttons and table, no_list_evidence),
            "edit_record": item("编辑" in buttons and table, no_list_evidence),
            "individual_enable_disable": item(
                table and any(text in buttons for text in ("启用", "停用")),
                no_list_evidence,
            ),
            "delete_record": item("删除" in buttons and table, no_list_evidence),
            "multi_select": item(row_checks, no_list_evidence),
            "select_all": item(row_checks, no_list_evidence),
            "batch_enable_disable": item(
                row_checks and any("批量" in text for text in buttons), no_list_evidence
            ),
            "batch_delete": item(
                row_checks and any("批量删除" in text for text in buttons), no_list_evidence
            ),
            "import": item("导入" in buttons, "未检测到导入按钮" if "导入" not in buttons else "检测到导入按钮"),
            "export": item("导出" in buttons, "未检测到导出按钮" if "导出" not in buttons else "检测到导出按钮"),
            "sort": item(sortable, no_list_evidence if not sortable else "检测到可排序表头"),
            "pagination": item(pagination, no_list_evidence if not pagination else "检测到分页器"),
            "refresh": item("刷新" in buttons, "未检测到页面级刷新按钮" if "刷新" not in buttons else "检测到刷新按钮"),
        }

    get_capabilities = get_capability_matrix

    # ==================== 控件读取与填写 ====================
    def _form_button(self, text: str) -> Locator:
        for root in (self._form_root(), self._snmp_pane()):
            exact = root.get_by_role("button", name=text, exact=True)
            if exact.count() > 0:
                return exact.first
            partial = root.locator("button:visible").filter(has_text=text)
            if partial.count() > 0:
                return partial.first
        return self.page.locator("[data-snmp-button-not-found='1']")

    def _help_button(self) -> Locator:
        button = self.page.get_by_role("button", name="帮助", exact=True)
        if button.count() > 0:
            return button.first
        return self.page.locator(
            "button:visible:has-text('帮助'), button[class*='helpDoc']:visible"
        ).first

    def get_field_value(self, name: str) -> Optional[str]:
        """读取非敏感字段；敏感字段始终拒绝返回值。"""
        if name in self.SENSITIVE_FIELDS:
            raise ValueError(f"敏感字段{name}的值不可读取")
        try:
            field = self._field(name)
            if field.count() == 0:
                return None
            if (field.get_attribute("type") or "").lower() in {
                "checkbox", "radio"
            }:
                checked = self._control_checked(field)
                return None if checked is None else str(checked).lower()
            return field.input_value()
        except Exception:
            return None

    def get_safe_field_observation(self, name: str) -> Dict[str, Any]:
        """返回输入约束和当前长度，任何字段都不返回实际文本。"""
        result: Dict[str, Any] = {
            "present": False,
            "control": "",
            "maxlength": None,
            "length": None,
            "populated": False,
            "native_valid": None,
        }
        if name not in self.FIELD_NAMES:
            return result
        try:
            field = self._field(name)
            if field.count() == 0:
                return result
            data = field.evaluate("""el => {
                const value = typeof el.value === 'string' ? el.value : '';
                return {
                    control: (el.type || el.tagName || '').toLowerCase(),
                    maxlength: el.getAttribute('maxlength'),
                    length: value.length,
                    populated: value.length > 0,
                    native_valid: typeof el.checkValidity === 'function'
                        ? el.checkValidity() : null
                };
            }""")
            result.update({
                "present": True,
                "control": data.get("control", ""),
                "maxlength": data.get("maxlength"),
                "length": data.get("length"),
                "populated": bool(data.get("populated")),
                "native_valid": data.get("native_valid"),
            })
        except Exception:
            pass
        return result

    def get_sensitive_field_length(self, name: str) -> Optional[int]:
        """Return only the current length for an approved secret input."""
        if name not in self.SENSITIVE_FIELDS:
            raise ValueError(f"{name}不是受保护的SNMP秘密字段")
        observation = self.get_safe_field_observation(name)
        length = observation.get("length") if observation.get("present") else None
        return int(length) if isinstance(length, int) else None

    def field_matches(self, name: str, expected: Any) -> bool:
        """在页面内比较字段，敏感值不会离开本方法。"""
        if name not in self.FIELD_NAMES:
            return False
        if name in self.SENSITIVE_FIELDS:
            self._remember_secret(expected)
        try:
            field = self._field(name)
            if field.count() == 0:
                return False
            return field.input_value() == str(expected)
        except Exception:
            return False

    def get_safe_form_state(self) -> Dict[str, Any]:
        """返回版本、开关及字段填充状态，不返回任何文本输入值。"""
        present: Dict[str, bool] = {}
        populated: Dict[str, bool] = {}
        for name in self.FIELD_NAMES:
            try:
                field = self._field(name)
                present[name] = field.count() > 0
                if field.count() > 0:
                    value = field.input_value()
                    populated[name] = bool(value)
            except Exception:
                present[name] = False
        return {
            "enabled": self.get_service_enabled(),
            "version": self.get_selected_option("version"),
            "security": self.get_selected_option("security"),
            "rw": self.get_rw(),
            "present": present,
            "populated": populated,
        }

    get_form_snapshot = get_safe_form_state

    def _fill_text(self, name: str, value: Any) -> bool:
        sensitive = name in self.SENSITIVE_FIELDS
        if sensitive:
            self._remember_secret(value)
        try:
            field = self._field(name)
            if field.count() == 0:
                return False
            field.scroll_into_view_if_needed()
            text = "" if value is None else str(value)
            maxlength_text = field.get_attribute("maxlength")
            try:
                maxlength = int(maxlength_text) if maxlength_text is not None else None
            except (TypeError, ValueError):
                maxlength = None
            if maxlength is not None and maxlength >= 0 and len(text) > maxlength:
                # ``Locator.fill`` 可通过直接赋值绕过 HTML maxlength。超界场景
                # 改用真实逐键输入，让浏览器按用户实际操作执行截断。
                field.fill("")
                field.press_sequentially(text)
            else:
                field.fill(text)
            if sensitive:
                # 同时登记浏览器实际接收的截断值，避免其出现在后续错误反馈。
                self._remember_secret(field.input_value())
            field.evaluate("""el => {
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            return True
        except Exception:
            return False

    def _set_boolean_field(self, name: str, enabled: bool) -> bool:
        try:
            field = self._field(name)
            if field.count() == 0:
                return False
            kind = (field.get_attribute("type") or "").lower()
            if kind == "checkbox":
                if field.is_checked() != bool(enabled):
                    field.set_checked(bool(enabled), force=True)
            else:
                switch = self._field_container(field, "ant-switch")
                if switch.count() == 0:
                    return False
                if self._control_checked(switch) != bool(enabled):
                    switch.click()
            self.page.wait_for_timeout(250)
            return self._control_checked(field) is bool(enabled)
        except Exception:
            return False

    def get_service_enabled(self) -> Optional[bool]:
        field = self._field("enabled")
        if field.count() == 0:
            return None
        return self._control_checked(field)

    def set_service_enabled(self, enabled: bool) -> bool:
        return self._set_boolean_field("enabled", bool(enabled))

    set_enabled = set_service_enabled

    def get_rw(self) -> Optional[bool]:
        field = self._field("rw")
        if field.count() == 0:
            return None
        checked = self._control_checked(field)
        if checked is not None and (field.get_attribute("type") or "") == "checkbox":
            return checked
        current = self.get_selected_option("rw")
        if current is None:
            return checked
        norm = self._norm(current)
        if norm in {"1", "true", "rw", "读写", "可写"}:
            return True
        if norm in {"0", "false", "ro", "只读"}:
            return False
        return checked

    def set_rw(self, writable: bool) -> bool:
        field = self._field("rw")
        if field.count() == 0:
            return False
        kind = (field.get_attribute("type") or "").lower()
        if kind == "checkbox" or self._field_container(
            field, "ant-switch"
        ).count() > 0:
            return self._set_boolean_field("rw", bool(writable))
        return self._select_field(
            "rw", "1" if writable else "0", "读写" if writable else "只读"
        )

    def probe_select_options(self, name: str) -> List[str]:
        """只读展开下拉选项后立即关闭；不得用于敏感字段。"""
        if name in self.SENSITIVE_FIELDS or name not in self.FIELD_NAMES:
            return []
        options: List[str] = []
        try:
            field = self._field(name)
            if field.count() == 0:
                return options
            if (field.evaluate("el => (el.tagName || '').toLowerCase()")) == "select":
                return [
                    (text or "").strip()
                    for text in field.locator("option").all_inner_texts()
                    if (text or "").strip()
                ]
            select = self._field_container(field, "ant-select")
            if select.count() == 0:
                return options
            select.locator(".ant-select-selector").click(timeout=3000)
            self.page.wait_for_timeout(220)
            dropdowns = self.page.locator(".ant-select-dropdown:visible")
            if dropdowns.count() > 0:
                option_locs = dropdowns.last.locator(".ant-select-item-option")
                for index in range(option_locs.count()):
                    text = (option_locs.nth(index).inner_text() or "").strip()
                    if text and text not in options:
                        options.append(text)
        except Exception:
            pass
        finally:
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(100)
            except Exception:
                pass
        return options

    def get_selected_option(self, name: str) -> Optional[str]:
        if name in self.SENSITIVE_FIELDS or name not in self.FIELD_NAMES:
            return None
        try:
            field = self._field(name)
            if field.count() == 0:
                return None
            tag = field.evaluate("el => (el.tagName || '').toLowerCase()")
            if tag == "select":
                return field.locator("option:checked").inner_text().strip()
            select = self._field_container(field, "ant-select")
            if select.count() > 0:
                selected = select.locator(
                    ".ant-select-selection-item, .ant-select-selection-placeholder"
                )
                if selected.count() > 0:
                    return (selected.first.inner_text() or "").strip()
            value = field.input_value()
            return value or None
        except Exception:
            return None

    def _select_field(self, name: str, code: str, ui_text: str) -> bool:
        try:
            field = self._field(name)
            if field.count() == 0:
                return False
            tag = field.evaluate("el => (el.tagName || '').toLowerCase()")
            if tag == "select":
                try:
                    field.select_option(value=code)
                except Exception:
                    field.select_option(label=ui_text)
                self.page.wait_for_timeout(180)
                return True

            item = field.locator(
                "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), "
                "' '), ' ant-form-item ')][1]"
            )
            radio_scope = item if item.count() > 0 else self._form_root()
            radios = radio_scope.locator("input[type='radio']")
            targets = {self._norm(code), self._norm(ui_text)}
            for index in range(radios.count()):
                radio = radios.nth(index)
                value = self._norm(radio.get_attribute("value"))
                label = radio.locator("xpath=ancestor::label[1]")
                label_text = self._norm(
                    label.inner_text() if label.count() > 0 else ""
                )
                if value in targets or label_text in targets:
                    radio.set_checked(True, force=True)
                    self.page.wait_for_timeout(220)
                    return radio.is_checked()

            select = self._field_container(field, "ant-select")
            if select.count() == 0:
                return False
            select.locator(".ant-select-selector").click(timeout=3500)
            self.page.wait_for_timeout(220)
            dropdowns = self.page.locator(".ant-select-dropdown:visible")
            if dropdowns.count() == 0:
                return False
            options = dropdowns.last.locator(".ant-select-item-option")
            exact: Optional[Locator] = None
            fallback: Optional[Locator] = None
            for index in range(options.count()):
                option = options.nth(index)
                text = self._norm(option.inner_text())
                value = self._norm(option.get_attribute("data-value"))
                if text in targets or value in targets:
                    exact = option
                    break
                if any(token and (token in text or token == value) for token in targets):
                    fallback = fallback or option
            target = exact or fallback
            if target is None:
                self.page.keyboard.press("Escape")
                return False
            target.click()
            self.page.wait_for_timeout(250)
            current = self._norm(self.get_selected_option(name))
            return current in targets or any(token and token in current for token in targets)
        except Exception:
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    def select_version(self, version: str) -> bool:
        normalized = self._norm(version)
        option = self.VERSION_OPTIONS.get(normalized)
        if option is None:
            return False
        return self._select_field("version", option[0], option[1])

    select_snmp_version = select_version
    set_version = select_version

    def select_security(self, security: str) -> bool:
        normalized = self._norm(security)
        option = self.SECURITY_OPTIONS.get(normalized)
        if option is None:
            return False
        return self._select_field("security", option[0], option[1])

    select_security_level = select_security
    set_security = select_security

    def select_auth_proto(self, protocol: str) -> bool:
        option = self.AUTH_PROTOCOLS.get(self._norm(protocol))
        return False if option is None else self._select_field(
            "auth_proto", option[0], option[1]
        )

    def select_priv_proto(self, protocol: str) -> bool:
        option = self.PRIV_PROTOCOLS.get(self._norm(protocol))
        return False if option is None else self._select_field(
            "priv_proto", option[0], option[1]
        )

    def fill_listen_port(self, value: Any) -> bool:
        return self._fill_text("listen_port", value)

    def fill_syslocation(self, value: Any) -> bool:
        return self._fill_text("syslocation", value)

    def fill_syscontact(self, value: Any) -> bool:
        return self._fill_text("syscontact", value)

    def fill_sysname(self, value: Any) -> bool:
        return self._fill_text("sysname", value)

    def fill_community(self, value: Any) -> bool:
        return self._fill_text("community", value)

    def fill_source(self, value: Any) -> bool:
        return self._fill_text("source", value)

    def fill_username(self, value: Any) -> bool:
        return self._fill_text("username", value)

    def fill_auth_pass(self, value: Any) -> bool:
        return self._fill_text("auth_pass", value)

    def fill_password(self, value: Any) -> bool:
        return self._fill_text("password", value)

    def fill_priv_pass(self, value: Any) -> bool:
        return self._fill_text("priv_pass", value)
    fill_auth_password = fill_auth_pass
    fill_priv_password = fill_priv_pass

    def fill_form(self, values: Optional[Mapping[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """按真实字段填写表单；返回值只有字段名和布尔结果。"""
        payload: Dict[str, Any] = dict(values or {})
        payload.update(kwargs)
        checks: Dict[str, bool] = {}
        handlers = {
            "enabled": self.set_service_enabled,
            "listen_port": self.fill_listen_port,
            "syslocation": self.fill_syslocation,
            "syscontact": self.fill_syscontact,
            "sysname": self.fill_sysname,
            "version": self.select_version,
            "community": self.fill_community,
            "rw": self.set_rw,
            "source": self.fill_source,
            "username": self.fill_username,
            "security": self.select_security,
            "auth_proto": self.select_auth_proto,
            "auth_pass": self.fill_auth_pass,
            "password": self.fill_password,
            "priv_proto": self.select_priv_proto,
            "priv_pass": self.fill_priv_pass,
        }
        # 版本和安全级别决定条件字段是否挂载，必须先处理。
        order = ["enabled", "version", "security"] + [
            name for name in self.FIELD_NAMES
            if name not in {"enabled", "version", "security"}
        ]
        for name in order:
            if name not in payload:
                continue
            handler = handlers[name]
            checks[name] = bool(handler(payload[name]))
        self.last_fill_checks = dict(checks)
        failed = [name for name, ok in checks.items() if not ok]
        return {
            "success": bool(checks) and not failed,
            "checks": checks,
            "failed_fields": failed,
        }

    fill_snmp_form = fill_form

    # ==================== 错误、保存与取消 ====================
    def get_error_messages(self) -> List[str]:
        messages: List[str] = []
        selectors = (
            ".ant-form-item-explain-error:visible",
            ".ant-alert-error:visible",
            ".ant-message-error:visible",
            ".ant-notification-notice-error:visible",
        )
        for selector in selectors:
            try:
                locators = self.page.locator(selector)
                for index in range(locators.count()):
                    locator = locators.nth(index)
                    sensitive_item = bool(locator.evaluate("""el => {
                        const item = el.closest('.ant-form-item');
                        if (!item) return false;
                        return ['community', 'auth_pass', 'password', 'priv_pass']
                            .some(id => !!item.querySelector('#' + id));
                    }"""))
                    text = (
                        "敏感字段校验失败（详情已隐藏）"
                        if sensitive_item
                        else self._redact(locator.inner_text())
                    )
                    if text and text not in messages:
                        messages.append(text)
            except Exception:
                continue
        if not messages:
            try:
                if self._form_root().locator(
                    ".ant-form-item-has-error:visible, "
                    ".ant-input-status-error:visible, "
                    ".ant-input-number-status-error:visible"
                ).count() > 0:
                    messages.append("输入格式错误")
            except Exception:
                pass
        return messages

    def get_form_error(self) -> Optional[str]:
        errors = self.get_error_messages()
        return errors[0] if errors else None

    def _wait_transient_feedback_clear(self, timeout: int = 3500):
        selector = (
            ".ant-message-success:visible, .ant-message-error:visible, "
            ".ant-notification-notice-success:visible, "
            ".ant-notification-notice-error:visible"
        )
        for _ in range(max(1, timeout // 100)):
            try:
                if self.page.locator(selector).count() == 0:
                    return
            except Exception:
                return
            self.page.wait_for_timeout(100)

    def save_settings(self, timeout: int = 9000) -> Dict[str, Any]:
        """提交 SNMP 配置并只返回经过脱敏的明确页面反馈。"""
        result: Dict[str, Any] = {
            "submitted": False,
            "success": False,
            "feedback": "",
            "error": "",
            "form_visible": self._form_root().count() > 0,
            "api": {
                "requested": False,
                "responded": False,
                "function": "",
                "action": "",
                "method": "",
                "endpoint": "",
                "status": None,
            },
        }

        def safe_api_request(request):
            try:
                payload = request.post_data_json or {}
                if not isinstance(payload, dict):
                    return False
                if str(payload.get("func_name", "")).lower() != "netsnmp":
                    return False
                result["api"].update({
                    "requested": True,
                    "function": "netsnmp",
                    "action": str(payload.get("action", "")),
                    "method": str(request.method),
                    "endpoint": request.url.split("?", 1)[0].rsplit("/", 1)[-1],
                })
                return True
            except Exception:
                return False

        def observe_request(request):
            safe_api_request(request)

        def observe_response(response):
            try:
                if safe_api_request(response.request):
                    result["api"].update({
                        "responded": True,
                        "status": int(response.status),
                    })
            except Exception:
                pass

        self.page.on("request", observe_request)
        self.page.on("response", observe_response)
        try:
            self._dismiss_transient_overlays()
            self._wait_transient_feedback_clear()
            button = self._form_button("保存")
            if button.count() == 0:
                result["error"] = "未找到SNMP配置保存按钮"
                return result
            button.click()
            result["submitted"] = True
            positive_selector = (
                ".ant-message-success:visible, "
                ".ant-notification-notice-success:visible"
            )
            for _ in range(max(1, timeout // 200)):
                self.page.wait_for_timeout(200)
                errors = self.get_error_messages()
                if errors:
                    result["error"] = errors[0]
                    return result
                positives = self.page.locator(positive_selector)
                if positives.count() > 0:
                    result["success"] = True
                    result["feedback"] = self._redact(
                        positives.last.inner_text() or "操作成功"
                    )
                    return result
            result["error"] = "已提交但未检测到明确的成功或失败反馈"
        except Exception:
            result["error"] = "SNMP配置保存操作异常（详情已隐藏）"
        finally:
            try:
                self.page.remove_listener("request", observe_request)
                self.page.remove_listener("response", observe_response)
            except Exception:
                pass
        result["form_visible"] = self._form_root().count() > 0
        return result

    save_and_wait = save_settings
    save_snmp_settings = save_settings

    def _cancel_dialog(self) -> Locator:
        dialogs = self.page.locator(
            ".ant-modal-content:visible, .ant-popconfirm:visible"
        )
        if dialogs.count() > 0:
            return dialogs.last
        return self.page.locator("[data-snmp-cancel-dialog-not-found='1']")

    def resolve_cancel_confirmation(self, confirm_discard: bool) -> Dict[str, Any]:
        """处理已经打开的未保存确认，覆盖关闭与确认两条分支。"""
        result: Dict[str, Any] = {
            "confirmation_seen": False,
            "confirmed_discard": False,
            "kept_editing": False,
            "dialog_closed": False,
            "message": "",
            "error": "",
        }
        try:
            dialog = self._cancel_dialog()
            if dialog.count() == 0:
                result["error"] = "未检测到取消确认弹窗"
                return result
            result["confirmation_seen"] = True
            result["message"] = self._redact(dialog.inner_text())
            names = (
                ("确定", "确认", "放弃", "离开")
                if confirm_discard else ("取消", "继续编辑", "返回")
            )
            target: Optional[Locator] = None
            for name in names:
                candidate = dialog.locator("button:visible").filter(
                    has_text=re.compile(rf"^\s*{re.escape(name)}\s*$")
                )
                if candidate.count() > 0:
                    target = candidate.first
                    break
            if target is None and not confirm_discard:
                close = dialog.locator("button.ant-modal-close:visible")
                if close.count() > 0:
                    target = close.first
            if target is None:
                result["error"] = "取消确认弹窗缺少目标按钮"
                return result
            target.click(force=True)
            for _ in range(20):
                self.page.wait_for_timeout(100)
                if self._cancel_dialog().count() == 0:
                    break
            result["dialog_closed"] = self._cancel_dialog().count() == 0
            result["confirmed_discard"] = bool(
                confirm_discard and result["dialog_closed"]
            )
            result["kept_editing"] = bool(
                not confirm_discard
                and result["dialog_closed"]
                and self._form_root().count() > 0
            )
        except Exception:
            result["error"] = "处理取消确认弹窗异常（详情已隐藏）"
        return result

    def cancel_changes(self, confirm_discard: bool = True) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "clicked": False,
            "confirmation_seen": False,
            "confirmed_discard": False,
            "kept_editing": False,
            "dialog_closed": True,
            "completed": False,
            "message": "",
            "error": "",
        }
        try:
            self._dismiss_transient_overlays()
            button = self._form_button("取消")
            if button.count() == 0:
                result["error"] = "未找到SNMP配置取消按钮"
                self.last_cancel_result = dict(result)
                return result
            button.click()
            result["clicked"] = True
            self.page.wait_for_timeout(350)
            if self._cancel_dialog().count() > 0:
                branch = self.resolve_cancel_confirmation(confirm_discard)
                result.update(branch)
                result["completed"] = bool(
                    branch.get("confirmed_discard")
                    if confirm_discard else branch.get("kept_editing")
                )
            else:
                # 当前页面可能直接重置表单；这是页面真实行为，不虚构确认弹窗。
                result["completed"] = True
                result["kept_editing"] = False
            self.last_cancel_result = dict(result)
            return result
        except Exception:
            result["error"] = "SNMP配置取消操作异常（详情已隐藏）"
            self.last_cancel_result = dict(result)
            return result

    def cancel_form(self, confirm_dirty: bool = True) -> bool:
        return bool(self.cancel_changes(confirm_discard=confirm_dirty)["completed"])

    cancel_settings = cancel_changes
    cancel_snmp_settings = cancel_changes

    def close_cancel_popup(self) -> Dict[str, Any]:
        return self.resolve_cancel_confirmation(confirm_discard=False)

    def confirm_cancel_popup(self) -> Dict[str, Any]:
        return self.resolve_cancel_confirmation(confirm_discard=True)

    # ==================== 帮助 ====================
    def verify_help_entry(
        self,
        expected_keywords: Iterable[str] = ("SNMP", "简单网络管理"),
        timeout: int = 8000,
    ) -> Dict[str, Any]:
        """打开帮助，匹配内容并关闭新 popup 或页内帮助层。"""
        keywords = [str(item) for item in expected_keywords if str(item)]
        result: Dict[str, Any] = {
            "clicked": False,
            "opened": False,
            "container": "",
            "content_matched": False,
            "all_keywords_matched": False,
            "matched_keywords": [],
            "closed": False,
            "no_orphan": False,
            "error": "",
        }
        context = self.page.context
        before_pages = list(context.pages)
        popup = None
        panel: Optional[Locator] = None
        try:
            button = self._help_button()
            if button.count() == 0:
                result["error"] = "未找到SNMP帮助入口"
                return result
            button.click()
            result["clicked"] = True
            for _ in range(max(1, timeout // 100)):
                new_pages = [item for item in context.pages if item not in before_pages]
                if new_pages:
                    popup = new_pages[-1]
                    result["container"] = "popup"
                    result["opened"] = True
                    break
                panels = self.page.locator(
                    ".ant-modal-content:visible, .ant-drawer-content:visible"
                )
                if panels.count() > 0:
                    candidate = panels.last
                    text = candidate.inner_text() or ""
                    if "帮助" in text or "SNMP" in text.upper():
                        panel = candidate
                        result["container"] = "in_page"
                        result["opened"] = True
                        break
                self.page.wait_for_timeout(100)

            searchable = ""
            if popup is not None:
                try:
                    popup.wait_for_load_state("domcontentloaded", timeout=5000)
                except Exception:
                    pass
                try:
                    searchable = " ".join(
                        (popup.url or "", popup.title(), popup.locator("body").inner_text(timeout=3000))
                    )
                except Exception:
                    searchable = popup.url or ""
            elif panel is not None:
                searchable = panel.inner_text() or ""

            matched = [
                keyword for keyword in keywords
                if self._norm(keyword) in self._norm(searchable)
            ]
            result["matched_keywords"] = matched
            result["content_matched"] = bool(matched)
            result["all_keywords_matched"] = bool(keywords) and len(matched) == len(keywords)
            if result["opened"] and not result["content_matched"]:
                result["error"] = "帮助已打开，但内容未匹配SNMP主题"
        except Exception:
            result["error"] = "SNMP帮助入口验证异常（详情已隐藏）"
        finally:
            if popup is not None:
                try:
                    if not popup.is_closed():
                        popup.close()
                    result["closed"] = popup.is_closed()
                except Exception:
                    pass
            elif panel is not None:
                try:
                    close = panel.locator(
                        "button.ant-modal-close:visible, button.ant-drawer-close:visible"
                    )
                    if close.count() == 0:
                        for name in ("关闭", "返回"):
                            candidate = panel.get_by_role("button", name=name, exact=True)
                            if candidate.count() > 0:
                                close = candidate.first
                                break
                    if close.count() > 0:
                        close.first.click()
                    else:
                        self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(250)
                    result["closed"] = not panel.is_visible()
                except Exception:
                    pass
            result["no_orphan"] = all(
                candidate in before_pages for candidate in context.pages
            )
        return result

    open_help_and_verify = verify_help_entry


__all__ = ["SnmpServerPage"]
