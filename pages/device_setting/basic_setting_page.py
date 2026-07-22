"""设备设置 > 基础设置 Page Object。

实机页面位于 ``/#/equipmentSetting/basicSetting``，是 ``basic`` 单例配置
表单，不是列表型 CRUD 页面。该对象只封装实机确认存在的功能：基础模式、
时间同步、保存、立即对时、手动设置时间和帮助入口。

所有 API 监听结果只保留 func_name/action/method/endpoint、HTTP 状态和布尔
响应语义；不会保留请求参数、响应 Data、主机名、NTP 地址或测试前字段值。
文本字段的读取通过页内布尔比较和长度/约束元数据完成，避免原值进入报告。
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage
from utils.step_recorder import register_sensitive_value


class BasicSettingPage(BasePage):
    """iKuai 4.0 基础设置单例表单。"""

    MODULE_NAME = "basic_setting"
    FUNC_NAME = "basic"
    PAGE_URL = "/#/equipmentSetting/basicSetting"
    LIST_URL = PAGE_URL
    BACKEND_SCRIPT = "/usr/ikuai/script/basic.sh"

    HOSTNAME_MAX_LENGTH = 21
    HOSTNAME_PATTERN = r"^[\u4e00-\u9fffA-Za-z0-9 :@_+\.\-]+$"
    SYNC_CYCLE_MIN = 5
    SYNC_CYCLE_MAX = 240
    TIME_ZONE_OPTION_COUNT = 38
    SUPPORT_FAST = 1

    FIELD_NAMES: Sequence[str] = (
        "hostname",
        "switch_nat",
        "lan_nat",
        "switch_dpi",
        "listen_interface",
        "wan_interface",
        "fast_nat",
        "current_time",
        "time_zone",
        "ntp_config",
        "ntpserver_builtin",
        "ntpserver_list",
        "manual_time",
        "sync_cycle",
        "switch_ntpd",
    )
    FIELD_ALIASES = {
        "link_mode": "switch_dpi",
        "ntp_server": "ntpserver_list",
        "ntp_servers": "ntpserver_list",
        "builtin_ntp_server": "ntpserver_builtin",
        "system_time": "current_time",
        "ntpd": "switch_ntpd",
        "internet_mode": "switch_nat",
        "acceleration_mode": "fast_nat",
    }
    FIELD_SELECTORS: Dict[str, Sequence[str]] = {
        "hostname": ("#hostname", "[name='hostname']"),
        "switch_nat": ("#switch_nat", "[name='switch_nat']"),
        "lan_nat": ("#lan_nat", "[name='lan_nat']"),
        # 实机字段 id 为 switch_dpi，页面文案为“链路模式”；兼容旧线索
        # link_mode，但公开逻辑字段始终按 DB/basic.sh 的 switch_dpi 命名。
        "switch_dpi": (
            "#link_mode",
            "[name='link_mode']",
            "#switch_dpi",
            "[name='switch_dpi']",
        ),
        "listen_interface": (
            "#listen_interface",
            "[name='listen_interface']",
        ),
        "wan_interface": ("#wan_interface", "[name='wan_interface']"),
        "fast_nat": ("#fast_nat", "[name='fast_nat']"),
        "current_time": ("#currentTime", "[name='currentTime']"),
        "time_zone": ("#time_zone", "[name='time_zone']"),
        "ntp_config": ("#ntp_config", "[name='ntp_config']"),
        "ntpserver_builtin": (
            "#ntpserver_builtin",
            "[name='ntpserver_builtin']",
        ),
        "ntpserver_list": (
            "#ntpserver_list",
            "[name='ntpserver_list']",
        ),
        "manual_time": ("#manual_time", "[name='manual_time']"),
        "sync_cycle": ("#sync_cycle", "[name='sync_cycle']"),
        "switch_ntpd": ("#switch_ntpd", "[name='switch_ntpd']"),
    }
    PRIVATE_VALUE_FIELDS = frozenset(
        {"hostname", "current_time", "ntpserver_list", "manual_time"}
    )

    INTERNET_MODE_OPTIONS = {
        "nat4": ("1", "NAT4"),
        "1": ("1", "NAT4"),
        "nat1": ("2", "NAT1"),
        "2": ("2", "NAT1"),
        "路由": ("0", "路由模式"),
        "路由模式": ("0", "路由模式"),
        "route": ("0", "路由模式"),
        "0": ("0", "路由模式"),
    }
    LINK_MODE_OPTIONS = {
        "主干": ("0", "主干模式"),
        "主干模式": ("0", "主干模式"),
        "trunk": ("0", "主干模式"),
        "0": ("0", "主干模式"),
        "旁路": ("1", "旁路模式"),
        "旁路模式": ("1", "旁路模式"),
        "bypass": ("1", "旁路模式"),
        "1": ("1", "旁路模式"),
        "sd-wan": ("2", "SD-WAN网桥"),
        "sdwan": ("2", "SD-WAN网桥"),
        "sd-wan网桥": ("2", "SD-WAN网桥"),
        "2": ("2", "SD-WAN网桥"),
    }
    FAST_NAT_OPTIONS = {
        "关闭": ("0", "关闭"),
        "off": ("0", "关闭"),
        "0": ("0", "关闭"),
        "软件": ("1", "软件模式"),
        "软件模式": ("1", "软件模式"),
        "software": ("1", "软件模式"),
        "1": ("1", "软件模式"),
    }
    NTP_CONFIG_OPTIONS = {
        "builtin": ("builtin", "内置NTP服务器"),
        "built-in": ("builtin", "内置NTP服务器"),
        "内置": ("builtin", "内置NTP服务器"),
        "使用内置": ("builtin", "内置NTP服务器"),
        "0": ("builtin", "内置NTP服务器"),
        "manual": ("custom", "手动配置"),
        "custom": ("custom", "手动配置"),
        "手动": ("custom", "手动配置"),
        "自定义": ("custom", "手动配置"),
        "1": ("custom", "手动配置"),
    }

    _PRIVATE_ASSIGNMENT = re.compile(
        r"(?i)(hostname|host[_ -]?name|ntp(?:server)?(?:_list)?|"
        r"主机名|NTP服务器)\s*[:=：]\s*([^\s,;，；]+)"
    )

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url.rstrip("/")
        self._known_private_values: List[str] = []
        self.last_navigation_api: List[Dict[str, Any]] = []
        self.last_fill_checks: Dict[str, bool] = {}

    # ==================== 安全及基础定位 ====================
    @staticmethod
    def _norm(value: Any) -> str:
        return re.sub(r"\s+", "", str(value or "")).strip().lower()

    def _remember_private(self, value: Any):
        if value is None:
            return
        register_sensitive_value(value)
        text = str(value)
        for candidate in (text, text.strip()):
            if candidate and candidate not in self._known_private_values:
                self._known_private_values.append(candidate)

    def _redact(self, value: Any, limit: int = 240) -> str:
        text = "" if value is None else str(value)
        for private in sorted(self._known_private_values, key=len, reverse=True):
            text = text.replace(private, "[隐私值已隐藏]")
        text = self._PRIVATE_ASSIGNMENT.sub(
            lambda match: f"{match.group(1)}=[隐私值已隐藏]", text
        )
        return text[:limit]

    @classmethod
    def _canonical_field(cls, name: str) -> str:
        raw = str(name or "")
        return cls.FIELD_ALIASES.get(raw, raw)

    @staticmethod
    def _safe_api_metadata(request) -> Optional[Dict[str, Any]]:
        """只提取 API 契约，不保留 param 或任何字段值。"""
        try:
            payload = request.post_data_json or {}
            if not isinstance(payload, dict):
                return None
            if str(payload.get("func_name", "")).lower() != "basic":
                return None
            return {
                "function": "basic",
                "action": str(payload.get("action", "")),
                "method": str(request.method),
                "endpoint": urlsplit(request.url).path,
            }
        except Exception:
            return None

    @staticmethod
    def _safe_response_semantics(response) -> Dict[str, Any]:
        """解析响应成功语义，但绝不返回响应 Data 或文案原文。"""
        result: Dict[str, Any] = {
            "json_parsed": False,
            "http_ok": 200 <= int(response.status) < 300,
            "business_success": None,
            "has_data": False,
            "result_code": None,
        }
        try:
            body = response.json()
            if not isinstance(body, dict):
                return result
            result["json_parsed"] = True
            result["has_data"] = any(key in body for key in ("Data", "data"))
            raw_code = body.get("Result", body.get("result", body.get("code")))
            if isinstance(raw_code, (int, float)) and not isinstance(raw_code, bool):
                result["result_code"] = raw_code
            elif isinstance(raw_code, str) and re.fullmatch(r"-?\d+", raw_code):
                result["result_code"] = int(raw_code)
            message = str(body.get("ErrMsg", body.get("message", ""))).strip().lower()
            explicit = body.get("success")
            if isinstance(explicit, bool):
                result["business_success"] = explicit
            elif result["result_code"] in {0, 30000}:
                result["business_success"] = True
            elif message in {"success", "ok", "成功", "操作成功"}:
                result["business_success"] = True
            elif message or result["result_code"] is not None:
                result["business_success"] = False
        except Exception:
            pass
        return result

    def _wait_page(self, settle_ms: int = 800):
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(settle_ms)

    def _missing(self, kind: str) -> Locator:
        safe = re.sub(r"[^a-z0-9_-]", "-", kind.lower())
        return self.page.locator(f"[data-basic-{safe}-not-found='1']")

    def _form_root(self) -> Locator:
        forms = self.page.locator("form:visible")
        for index in range(forms.count()):
            form = forms.nth(index)
            if form.locator("#hostname, [name='hostname']").count() > 0 and form.locator(
                "#switch_nat, [name='switch_nat']"
            ).count() > 0:
                return form
        roots = self.page.locator(
            "main:visible, .ant-layout-content:visible, [class*='basicSetting']:visible"
        )
        for index in range(roots.count()):
            root = roots.nth(index)
            if root.locator("#hostname, [name='hostname']").count() > 0:
                return root
        return self._missing("form")

    def _field(self, name: str) -> Locator:
        canonical = self._canonical_field(name)
        selectors = self.FIELD_SELECTORS.get(canonical)
        if not selectors:
            return self._missing("field")
        roots = (self._form_root(), self.page)
        first_native: Optional[Locator] = None
        first_visible: Optional[Locator] = None
        first_candidate: Optional[Locator] = None
        for root in roots:
            for selector in selectors:
                candidate = root.locator(selector)
                if candidate.count() > 0:
                    for index in range(candidate.count()):
                        node = candidate.nth(index)
                        if first_candidate is None:
                            first_candidate = node
                        try:
                            visible = node.is_visible()
                            if visible and first_visible is None:
                                first_visible = node
                            tag = node.evaluate(
                                "el => (el.tagName || '').toLowerCase()"
                            )
                            if tag in {"input", "textarea", "select", "button"}:
                                if visible:
                                    return node
                                if first_native is None:
                                    first_native = node
                        except Exception:
                            continue
        # 条件字段切换后 DOM 可能同时保留隐藏旧控件和可见新控件。只有遍历
        # 全部 selector 后才退回隐藏节点，避免把空的旧 NTP 输入当作页面回显。
        if first_visible is not None:
            return first_visible
        if first_native is not None:
            return first_native
        if first_candidate is not None:
            return first_candidate
        return self._missing("field")

    def _field_item(self, field: Locator) -> Locator:
        item = field.locator(
            "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), "
            "' '), ' ant-form-item ')][1]"
        )
        return item.first if item.count() > 0 else self._form_root()

    def _field_container(self, field: Locator, class_name: str) -> Locator:
        nearest = field.locator(
            "xpath=ancestor-or-self::*[contains(concat(' ', "
            "normalize-space(@class), ' '), ' " + class_name + " ')][1]"
        )
        if nearest.count() > 0:
            return nearest.first
        item = self._field_item(field)
        nested = item.locator(f".{class_name}:visible")
        return nested.first if nested.count() > 0 else self._missing("container")

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

    def _dismiss_transient_overlays(self):
        try:
            if self.page.locator(
                ".ant-select-dropdown:visible, .ant-picker-dropdown:visible"
            ).count() > 0:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(120)
        except Exception:
            pass

    def _button(self, texts: Iterable[str]) -> Locator:
        names = [str(text) for text in texts if str(text)]
        for root in (self._form_root(), self.page):
            for name in names:
                exact = root.get_by_role("button", name=name, exact=True)
                if exact.count() > 0 and exact.first.is_visible():
                    return exact.first
            for name in names:
                partial = root.locator("button:visible").filter(has_text=name)
                if partial.count() > 0:
                    return partial.first
        return self._missing("button")

    def _help_button(self) -> Locator:
        return self._button(("帮助",))

    # ==================== 导航、结构与能力矩阵 ====================
    def navigate_to_basic_setting(self):
        observations: List[Dict[str, Any]] = []

        def observe_response(response):
            metadata = self._safe_api_metadata(response.request)
            if metadata is None:
                return
            metadata.update(
                {
                    "responded": True,
                    "status": int(response.status),
                    "semantic": self._safe_response_semantics(response),
                }
            )
            observations.append(metadata)

        self.page.on("response", observe_response)
        try:
            self._dismiss_transient_overlays()
            target = f"{self.base_url}{self.PAGE_URL}"
            if "equipmentSetting/basicSetting" in self.page.url:
                self.page.reload(wait_until="domcontentloaded")
            else:
                self.page.goto(target, wait_until="domcontentloaded")
            self._wait_page(1200)
        finally:
            try:
                self.page.remove_listener("response", observe_response)
            except Exception:
                pass
        self.last_navigation_api = observations
        return self

    navigate_to_basic = navigate_to_basic_setting
    open = navigate_to_basic_setting

    def is_on_basic_setting_page(self) -> bool:
        try:
            return (
                "equipmentSetting/basicSetting" in self.page.url
                and self._field("hostname").count() > 0
                and self._field("switch_nat").count() > 0
            )
        except Exception:
            return False

    is_on_page = is_on_basic_setting_page

    def _field_metadata(self, name: str) -> Dict[str, Any]:
        canonical = self._canonical_field(name)
        result: Dict[str, Any] = {
            "present": False,
            "visible": False,
            "required": False,
            "disabled": False,
            "control": "",
            "maxlength": None,
            "min": None,
            "max": None,
            "length": None,
            "populated": False,
            "native_valid": None,
            "aria_invalid": False,
        }
        try:
            field = self._field(canonical)
            if field.count() == 0:
                return result
            data = field.evaluate("""el => {
                const item = el.closest('.ant-form-item');
                const select = el.closest('.ant-select') ||
                    item?.querySelector('.ant-select');
                const sw = el.closest('.ant-switch') || item?.querySelector('.ant-switch');
                const radio = el.matches('input[type=radio]') ? el :
                    item?.querySelector('input[type=radio]');
                const visible = node => !!(node && node.offsetParent !== null);
                const value = typeof el.value === 'string' ? el.value : '';
                let control = (el.type || el.tagName || '').toLowerCase();
                if (select) control = select.classList.contains('ant-select-multiple')
                    ? 'multi_select' : 'select';
                else if (sw) control = 'switch';
                else if (radio) control = 'radio_group';
                return {
                    visible: visible(el) || visible(select) || visible(sw) ||
                        visible(item?.querySelector('label')),
                    required: el.getAttribute('aria-required') === 'true' ||
                        !!item?.querySelector('.ant-form-item-required'),
                    disabled: !!el.disabled || !!select?.classList.contains(
                        'ant-select-disabled') || !!sw?.disabled,
                    control,
                    maxlength: el.getAttribute('maxlength'),
                    min: el.getAttribute('min'),
                    max: el.getAttribute('max'),
                    length: value.length,
                    populated: value.length > 0,
                    native_valid: typeof el.checkValidity === 'function'
                        ? el.checkValidity() : null,
                    aria_invalid: el.getAttribute('aria-invalid') === 'true'
                };
            }""")
            result.update(
                {
                    "present": True,
                    "visible": bool(data.get("visible")),
                    "required": bool(data.get("required")),
                    "disabled": bool(data.get("disabled")),
                    "control": data.get("control", ""),
                    "maxlength": data.get("maxlength"),
                    "min": data.get("min"),
                    "max": data.get("max"),
                    "length": data.get("length"),
                    "populated": bool(data.get("populated")),
                    "native_valid": data.get("native_valid"),
                    "aria_invalid": bool(data.get("aria_invalid")),
                }
            )
        except Exception:
            pass
        return result

    def get_safe_field_observation(self, name: str) -> Dict[str, Any]:
        """返回控件约束和长度，不返回字段文本。"""
        return self._field_metadata(name)

    def get_current_time_fingerprint(self) -> Optional[str]:
        """返回当前时间显示值的内存指纹，绝不返回或记录时间原文。

        指纹只用于同一测试进程内比较手动设时/立即对时前后是否刷新；调用方
        不应把指纹本身写入报告。读取到的原文会立即登记为敏感值。
        """
        try:
            field = self._field("current_time")
            if field.count() == 0:
                return None
            value = field.input_value()
            if not value:
                return None
            self._remember_private(value)
            return hashlib.sha256(value.encode("utf-8")).hexdigest()
        except Exception:
            return None

    def build_manual_time_candidate(self, offset_seconds: int = 35) -> Optional[str]:
        """基于路由器页面当前显示时间生成近距离候选值。

        这样不会依赖运行 pytest 的 Windows 时区，也不会把全局设备时钟意外
        跳到另一个时区。原值和候选值都只留在内存敏感值表。
        """
        try:
            field = self._field("current_time")
            if field.count() == 0:
                return None
            current_text = field.input_value().strip()
            self._remember_private(current_text)
            current = datetime.strptime(current_text, "%Y-%m-%d %H:%M:%S")
            candidate = (current + timedelta(seconds=int(offset_seconds))).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            self._remember_private(candidate)
            return candidate
        except Exception:
            return None

    def _radio_scope(self, field: Locator) -> Locator:
        item = self._field_item(field)
        return item if item.count() > 0 else self._form_root()

    def probe_select_options(self, name: str) -> List[str]:
        """只读展开真实选项并关闭；对自定义 NTP 输入不读取其文本。"""
        canonical = self._canonical_field(name)
        if canonical not in self.FIELD_NAMES:
            return []
        options: List[str] = []
        try:
            field = self._field(canonical)
            if field.count() == 0:
                return options
            tag = field.evaluate("el => (el.tagName || '').toLowerCase()")
            if tag == "select":
                return [
                    (text or "").strip()
                    for text in field.locator("option").all_inner_texts()
                    if (text or "").strip()
                ]
            radios = self._radio_scope(field).locator(
                "label.ant-radio-wrapper:visible, label:has(input[type='radio'])"
            )
            if radios.count() > 0:
                for text in radios.all_inner_texts():
                    clean = re.sub(r"\s+", " ", text or "").strip()
                    if clean and clean not in options:
                        options.append(clean)
                return options
            select = self._field_container(field, "ant-select")
            if select.count() == 0:
                return options
            select.locator(".ant-select-selector").click(timeout=3500)
            self.page.wait_for_timeout(180)
            dropdowns = self.page.locator(".ant-select-dropdown:visible")
            if dropdowns.count() == 0:
                return options
            dropdown = dropdowns.last
            holder = dropdown.locator(".rc-virtual-list-holder")
            positions: List[int] = [0]
            if holder.count() > 0:
                dimensions = holder.evaluate(
                    "el => ({height: el.clientHeight, total: el.scrollHeight})"
                )
                # Ant Select 时区列表每项约 32px。用不大于 64px 的固定步长
                # 穷举虚拟列表，避免按整页滚动时漏掉未挂载的中间选项。
                step = max(24, min(64, int(dimensions.get("height") or 64) // 4))
                total = int(dimensions.get("total") or 0)
                positions = list(range(0, total + 1, step))
                if not positions or positions[-1] != total:
                    positions.append(total)
            for position in positions:
                if holder.count() > 0:
                    holder.evaluate("""(el, top) => {
                        el.scrollTop = top;
                        el.dispatchEvent(new Event('scroll', {bubbles: true}));
                    }""", position)
                    self.page.wait_for_timeout(55)
                rendered = dropdown.locator(
                    ".ant-select-item-option:not(.ant-select-item-option-disabled)"
                )
                for index in range(rendered.count()):
                    text = re.sub(
                        r"\s+", " ", rendered.nth(index).inner_text() or ""
                    ).strip()
                    if text and text not in options:
                        options.append(text)
        except Exception:
            pass
        finally:
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(80)
            except Exception:
                pass
        return options

    get_select_options = probe_select_options

    def _selected_radio(self, field: Locator) -> Tuple[Optional[str], Optional[str]]:
        try:
            radios = self._radio_scope(field).locator("input[type='radio']")
            for index in range(radios.count()):
                radio = radios.nth(index)
                if not radio.is_checked():
                    continue
                label = radio.locator("xpath=ancestor::label[1]")
                text = (label.inner_text() or "").strip() if label.count() else ""
                return radio.get_attribute("value"), text
        except Exception:
            pass
        return None, None

    def get_selected_option(self, name: str) -> Optional[str]:
        """读取非隐私模式选项的显示文本；自定义 NTP 内容始终不返回。"""
        canonical = self._canonical_field(name)
        if canonical in self.PRIVATE_VALUE_FIELDS or canonical not in self.FIELD_NAMES:
            return None
        try:
            field = self._field(canonical)
            if field.count() == 0:
                return None
            code, label = self._selected_radio(field)
            if code is not None:
                return label or code
            tag = field.evaluate("el => (el.tagName || '').toLowerCase()")
            if tag == "select":
                checked = field.locator("option:checked")
                return (checked.inner_text() or "").strip() if checked.count() else None
            select = self._field_container(field, "ant-select")
            if select.count() > 0:
                selected = select.locator(
                    ".ant-select-selection-item, .ant-select-selection-placeholder"
                )
                if selected.count() > 0:
                    return re.sub(
                        r"\s+", " ", " ".join(selected.all_inner_texts())
                    ).strip()
            value = field.input_value()
            return value or None
        except Exception:
            return None

    def get_field_value(self, name: str) -> Optional[str]:
        """读取模式代码/开关；拒绝返回主机名和 NTP 地址原值。"""
        canonical = self._canonical_field(name)
        if canonical in self.PRIVATE_VALUE_FIELDS:
            raise ValueError(f"{canonical}原值受保护，只能使用field_matches页内比对")
        try:
            field = self._field(canonical)
            if field.count() == 0:
                return None
            code, _ = self._selected_radio(field)
            if code is not None:
                return code
            kind = (field.get_attribute("type") or "").lower()
            if kind == "checkbox" or self._field_container(
                field, "ant-switch"
            ).count() > 0:
                checked = self._control_checked(field)
                return None if checked is None else ("1" if checked else "0")
            return field.input_value()
        except Exception:
            return None

    def field_matches(self, name: str, expected: Any) -> bool:
        """在浏览器内比较字段；实际字段值不会离开此方法。"""
        canonical = self._canonical_field(name)
        if canonical not in self.FIELD_NAMES:
            return False
        if canonical in self.PRIVATE_VALUE_FIELDS:
            self._remember_private(expected)
        try:
            field = self._field(canonical)
            if field.count() == 0:
                return False
            code, label = self._selected_radio(field)
            target = self._norm(expected)
            if code is not None:
                return target in {self._norm(code), self._norm(label)}
            select = self._field_container(field, "ant-select")
            if select.count() > 0:
                if canonical in self.PRIVATE_VALUE_FIELDS:
                    # 对隐私 Select 在 DOM 内比较，不把选中文本带回 Python。
                    return bool(field.evaluate(
                        r"""(el, expected) => {
                            const item = el.closest('.ant-form-item');
                            const select = el.closest('.ant-select') ||
                                item?.querySelector('.ant-select');
                            const target = String(expected).replace(/\s+/g, '')
                                .toLowerCase();
                            return Array.from(select?.querySelectorAll(
                                '.ant-select-selection-item') || []).some(node =>
                                String(node.textContent || '').replace(/\s+/g, '')
                                    .toLowerCase() === target);
                        }""", str(expected)
                    ))
                selected_items = select.locator(".ant-select-selection-item")
                return any(
                    self._norm(text) == target
                    for text in selected_items.all_inner_texts()
                )
            kind = (field.get_attribute("type") or "").lower()
            if kind == "checkbox" or self._field_container(
                field, "ant-switch"
            ).count() > 0:
                expected_bool = target in {"1", "true", "on", "启用", "开启"}
                return self._control_checked(field) is expected_bool
            return bool(field.evaluate(
                "(el, expected) => String(el.value) === String(expected)", str(expected)
            ))
        except Exception:
            return False

    def get_safe_form_state(self) -> Dict[str, Any]:
        """返回模式/开关及文本填充状态，不返回任何原始文本。"""
        return {
            "internet_mode": {
                "nat4": self.field_matches("switch_nat", "NAT4"),
                "nat1": self.field_matches("switch_nat", "NAT1"),
                "route": self.field_matches("switch_nat", "路由模式"),
            },
            "link_mode": {
                "trunk": self.field_matches("switch_dpi", "主干模式"),
                "bypass": self.field_matches("switch_dpi", "旁路模式"),
                "sd_wan": self.field_matches("switch_dpi", "SD-WAN网桥"),
            },
            "acceleration_mode": {
                "off": self.field_matches("fast_nat", "关闭"),
                "software": self.field_matches("fast_nat", "软件模式"),
                "hardware_present": any(
                    self._norm(option) in {"硬件", "硬件加速"}
                    for option in self.probe_select_options("fast_nat")
                ),
            },
            "time_zone_selected": self.get_selected_option("time_zone") is not None,
            "ntp_config": {
                "built_in": self.field_matches("ntp_config", "builtin"),
                "manual": self.field_matches("ntp_config", "custom"),
            },
            "switch_ntpd": self.get_switch_ntpd(),
            "fields": {
                name: self._field_metadata(name) for name in self.FIELD_NAMES
            },
        }

    get_form_snapshot = get_safe_form_state

    def get_page_structure(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "url_ok": "equipmentSetting/basicSetting" in self.page.url,
            "title_matched": False,
            "singleton_form_present": False,
            "tab_present": False,
            "tab_active": False,
            "table_present": False,
            "search_present": False,
            "fields": {},
            "visible_fields": [],
            "options": {},
            "option_counts": {},
            "save_present": False,
            "cancel_present": False,
            "sync_time_present": False,
            "help_present": False,
            "constraints": {
                "hostname_maxlength": self.HOSTNAME_MAX_LENGTH,
                "hostname_pattern": self.HOSTNAME_PATTERN,
                "sync_cycle_min": self.SYNC_CYCLE_MIN,
                "sync_cycle_max": self.SYNC_CYCLE_MAX,
                "time_zone_expected_options": self.TIME_ZONE_OPTION_COUNT,
                "support_fast": self.SUPPORT_FAST,
            },
        }
        try:
            body_text = self.page.locator("body").inner_text(timeout=3000)
            result["title_matched"] = "基础设置" in body_text
            form = self._form_root()
            result["singleton_form_present"] = (
                form.count() > 0
                and self._field("hostname").count() > 0
                and self._field("switch_nat").count() > 0
            )
            tabs = self.page.locator(".ant-tabs-tab:visible")
            result["tab_present"] = tabs.count() > 0
            result["tab_active"] = self.page.locator(
                ".ant-tabs-tab-active:visible"
            ).count() > 0
            if form.count() > 0:
                result["table_present"] = form.locator(
                    ".ant-table:visible, table:visible"
                ).count() > 0
                search = form.locator(
                    "input[placeholder*='搜索']:visible, input[aria-label*='搜索']:visible"
                )
                independent = bool(search.evaluate_all("""elements =>
                    elements.some(el => !el.closest('.ant-select') &&
                        el.getAttribute('role') !== 'combobox')
                """)) if search.count() else False
                result["search_present"] = bool(
                    result["table_present"] and independent
                )
            for name in self.FIELD_NAMES:
                meta = self._field_metadata(name)
                result["fields"][name] = meta
                if meta.get("visible"):
                    result["visible_fields"].append(name)
            for name in (
                "switch_nat",
                "switch_dpi",
                "fast_nat",
                "time_zone",
                "ntp_config",
                "ntpserver_builtin",
                "ntpserver_list",
            ):
                values = self.probe_select_options(name)
                result["options"][name] = values
                result["option_counts"][name] = len(values)
            result["save_present"] = self._button(("保存",)).count() > 0
            result["cancel_present"] = self._button(("取消",)).count() > 0
            result["sync_time_present"] = self._button(("立即对时",)).count() > 0
            result["help_present"] = self._help_button().count() > 0
        except Exception:
            pass
        return result

    get_form_structure = get_page_structure
    get_default_structure = get_page_structure

    def get_capability_matrix(self) -> Dict[str, Dict[str, Any]]:
        """用 DOM 证据区分支持项与单例页不适用项。"""
        structure = self.get_page_structure()
        form = self._form_root()
        buttons: List[str] = []
        sortable = row_checks = pagination = False
        try:
            if form.count() > 0:
                buttons = [
                    re.sub(r"\s+", "", text or "")
                    for text in form.locator("button:visible").all_inner_texts()
                ]
                sortable = form.locator(
                    ".ant-table-column-sorter:visible, [aria-sort]:visible"
                ).count() > 0
                row_checks = form.locator(
                    ".ant-table-tbody input[type='checkbox']:visible"
                ).count() > 0
                pagination = form.locator(".ant-pagination:visible").count() > 0
        except Exception:
            pass

        single = bool(structure.get("singleton_form_present"))
        table = bool(structure.get("table_present"))
        no_list = (
            "基础设置页检测到记录表格"
            if table
            else "基础设置页无记录表格，真实模型为basic单例配置表单"
        )

        def item(supported: bool, evidence: str) -> Dict[str, Any]:
            return {
                "supported": bool(supported),
                "result": "支持" if supported else "不适用",
                "evidence": evidence,
            }

        fields = structure.get("fields", {})
        return {
            "singleton_configuration_edit": item(
                single,
                "检测到#hostname和#switch_nat单例表单"
                if single
                else "未检测到完整basic单例表单",
            ),
            "internet_mode": item(
                bool(fields.get("switch_nat", {}).get("present")),
                "检测字段#switch_nat",
            ),
            "link_mode": item(
                bool(fields.get("switch_dpi", {}).get("present")),
                "检测字段#switch_dpi（页面文案为链路模式）",
            ),
            "acceleration_mode": item(
                bool(fields.get("fast_nat", {}).get("present")),
                "检测字段#fast_nat；support_fast=1仅支持关闭/软件",
            ),
            "time_sync": item(
                bool(structure.get("sync_time_present")),
                "按可见按钮文本检测立即对时入口",
            ),
            "save": item(
                bool(structure.get("save_present")), "按可见按钮文本检测保存入口"
            ),
            "cancel": item(
                bool(structure.get("cancel_present")),
                "实机基础设置表单无取消按钮"
                if not structure.get("cancel_present")
                else "检测到取消按钮",
            ),
            "dirty_navigation_confirmation": item(
                False, "实机脏表单跨页导航不弹确认；由探测方法留存布尔证据"
            ),
            "help": item(
                bool(structure.get("help_present")), "按页面级可见按钮检测帮助入口"
            ),
            "search_existing": item(
                bool(structure.get("search_present")),
                "基础设置页无记录表格和独立搜索控件；Ant Select输入已排除",
            ),
            "search_missing": item(False, no_list),
            "clear_search": item(False, no_list),
            "add_record": item("添加" in buttons and table, no_list),
            "edit_record": item("编辑" in buttons and table, no_list),
            "individual_enable_disable": item(False, no_list),
            "delete_record": item("删除" in buttons and table, no_list),
            "multi_select": item(row_checks, no_list),
            "select_all": item(row_checks, no_list),
            "batch_enable_disable": item(False, no_list),
            "batch_delete": item(False, no_list),
            "import": item("导入" in buttons, "未检测到导入按钮"),
            "export": item("导出" in buttons, "未检测到导出按钮"),
            "sort": item(sortable, no_list),
            "pagination": item(pagination, no_list),
            "refresh": item("刷新" in buttons, "未检测到页面级刷新按钮"),
        }

    get_capabilities = get_capability_matrix

    # ==================== 控件填写、切换与条件字段 ====================
    def _find_dropdown_option(
        self, dropdown: Locator, targets: Sequence[str]
    ) -> Optional[Locator]:
        normalized = {self._norm(item) for item in targets if str(item)}
        fallback: Optional[Locator] = None
        holder = dropdown.locator(".rc-virtual-list-holder")
        positions: List[int] = [0]
        if holder.count() > 0:
            try:
                dimensions = holder.evaluate(
                    "el => ({height: el.clientHeight, total: el.scrollHeight})"
                )
                step = max(24, min(64, int(dimensions.get("height") or 64) // 4))
                total = int(dimensions.get("total") or 0)
                positions = list(range(0, total + 1, step))
                if not positions or positions[-1] != total:
                    positions.append(total)
            except Exception:
                positions = [0]
        for position in positions:
            if holder.count() > 0:
                try:
                    holder.evaluate("""(el, top) => {
                        el.scrollTop = top;
                        el.dispatchEvent(new Event('scroll', {bubbles: true}));
                    }""", position)
                    self.page.wait_for_timeout(55)
                except Exception:
                    pass
            options = dropdown.locator(
                ".ant-select-item-option:not(.ant-select-item-option-disabled)"
            )
            for index in range(options.count()):
                option = options.nth(index)
                text = self._norm(option.inner_text())
                value = self._norm(option.get_attribute("data-value"))
                if text in normalized or value in normalized:
                    return option
                if fallback is None and any(
                    token and len(token) >= 2 and token in text for token in normalized
                ):
                    # 模式映射传入的短标签（如“旁路”）在真实 UI 中显示为
                    # “旁路模式”。发现唯一包含项后立即返回，避免虚拟列表滚动
                    # 复用 DOM 导致暂存 Locator 指向别的选项。
                    return option
        return fallback

    def _select_field(
        self, name: str, code: str, ui_text: str, *extra_targets: str
    ) -> bool:
        canonical = self._canonical_field(name)
        targets = tuple(str(item) for item in (code, ui_text, *extra_targets) if str(item))
        normalized = {self._norm(item) for item in targets}
        try:
            field = self._field(canonical)
            if field.count() == 0 or not field.is_enabled():
                return False
            tag = field.evaluate("el => (el.tagName || '').toLowerCase()")
            if tag == "select":
                try:
                    field.select_option(value=str(code))
                except Exception:
                    field.select_option(label=str(ui_text))
                self.page.wait_for_timeout(180)
                return self.field_matches(canonical, code) or self.field_matches(
                    canonical, ui_text
                )

            radios = self._radio_scope(field).locator("input[type='radio']")
            if radios.count() > 0:
                for index in range(radios.count()):
                    radio = radios.nth(index)
                    value = self._norm(radio.get_attribute("value"))
                    label = radio.locator("xpath=ancestor::label[1]")
                    label_text = self._norm(
                        label.inner_text() if label.count() > 0 else ""
                    )
                    if value in normalized or label_text in normalized:
                        radio.set_checked(True, force=True)
                        self.page.wait_for_timeout(260)
                        return bool(
                            radio.is_checked()
                            or self._fast_nat_confirmation_dialog().count() > 0
                        )

            select = self._field_container(field, "ant-select")
            if select.count() == 0:
                return False
            selector = select.locator(".ant-select-selector")
            selector.scroll_into_view_if_needed()
            selector.click(timeout=3500)
            self.page.wait_for_timeout(180)
            dropdowns = self.page.locator(".ant-select-dropdown:visible")
            if dropdowns.count() == 0:
                return False
            target = self._find_dropdown_option(dropdowns.last, targets)
            if target is None:
                self.page.keyboard.press("Escape")
                return False
            target.click()
            self.page.wait_for_timeout(260)
            if self._fast_nat_confirmation_dialog().count() > 0:
                return True
            return self.field_matches(canonical, code) or self.field_matches(
                canonical, ui_text
            )
        except Exception:
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    @staticmethod
    def _mapping_option(
        mapping: Mapping[str, Tuple[str, str]], value: Any
    ) -> Optional[Tuple[str, str]]:
        normalized = re.sub(r"\s+", "", str(value or "")).strip().lower()
        return mapping.get(normalized)

    def _fill_text(self, name: str, value: Any) -> bool:
        canonical = self._canonical_field(name)
        if canonical in self.PRIVATE_VALUE_FIELDS:
            self._remember_private(value)
        try:
            field = self._field(canonical)
            if field.count() == 0 or not field.is_enabled():
                return False
            text = "" if value is None else str(value)
            maxlength_text = field.get_attribute("maxlength")
            try:
                maxlength = int(maxlength_text) if maxlength_text is not None else None
            except (TypeError, ValueError):
                maxlength = None
            field.scroll_into_view_if_needed()
            if maxlength is not None and maxlength >= 0 and len(text) > maxlength:
                # fill 会绕开 maxlength；逐键输入才能验证浏览器原生截断。
                field.fill("")
                field.press_sequentially(text)
            else:
                field.fill(text)
            if canonical in self.PRIVATE_VALUE_FIELDS:
                self._remember_private(field.input_value())
            field.evaluate("""el => {
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            self.page.wait_for_timeout(120)
            return True
        except Exception:
            return False

    def _set_boolean_field(self, name: str, enabled: bool) -> bool:
        canonical = self._canonical_field(name)
        try:
            field = self._field(canonical)
            if field.count() == 0:
                return False
            kind = (field.get_attribute("type") or "").lower()
            if kind == "checkbox":
                if field.is_checked() != bool(enabled):
                    field.set_checked(bool(enabled), force=True)
            else:
                switch = self._field_container(field, "ant-switch")
                if switch.count() > 0:
                    if self._control_checked(switch) != bool(enabled):
                        switch.click()
                else:
                    return self._select_field(
                        canonical,
                        "1" if enabled else "0",
                        "开启" if enabled else "关闭",
                        "启用" if enabled else "停用",
                    )
            self.page.wait_for_timeout(220)
            return self._control_checked(field) is bool(enabled)
        except Exception:
            return False

    def get_boolean_field(self, name: str) -> Optional[bool]:
        field = self._field(name)
        if field.count() == 0:
            return None
        return self._control_checked(field)

    def fill_hostname(self, value: Any) -> bool:
        return self._fill_text("hostname", value)

    set_hostname = fill_hostname

    def select_internet_mode(self, mode: Any) -> bool:
        option = self._mapping_option(self.INTERNET_MODE_OPTIONS, mode)
        return False if option is None else self._select_field(
            "switch_nat", option[0], option[1]
        )

    select_switch_nat = select_internet_mode
    set_internet_mode = select_internet_mode

    def set_lan_nat(self, enabled: bool) -> bool:
        return self._set_boolean_field("lan_nat", bool(enabled))

    def get_lan_nat(self) -> Optional[bool]:
        return self.get_boolean_field("lan_nat")

    def select_link_mode(self, mode: Any) -> bool:
        option = self._mapping_option(self.LINK_MODE_OPTIONS, mode)
        return False if option is None else self._select_field(
            "switch_dpi", option[0], option[1]
        )

    select_switch_dpi = select_link_mode
    set_link_mode = select_link_mode

    def _clear_ant_select(self, field: Locator) -> bool:
        try:
            select = self._field_container(field, "ant-select")
            if select.count() == 0:
                return False
            clear = select.locator(".ant-select-clear:visible")
            if clear.count() > 0:
                clear.click()
                self.page.wait_for_timeout(120)
                return True
            removable = select.locator(".ant-select-selection-item-remove:visible")
            while removable.count() > 0:
                removable.first.click()
                self.page.wait_for_timeout(80)
                removable = select.locator(".ant-select-selection-item-remove:visible")
            return True
        except Exception:
            return False

    def select_interface_values(
        self, name: str, values: Iterable[str], clear_existing: bool = True
    ) -> bool:
        canonical = self._canonical_field(name)
        if canonical not in {"listen_interface", "wan_interface"}:
            return False
        requested = [str(value) for value in values if str(value)]
        if not requested:
            return False
        field = self._field(canonical)
        if field.count() == 0 or not self._field_metadata(canonical).get("visible"):
            return False
        if clear_existing:
            self._clear_ant_select(field)
        checks = [
            self._select_field(canonical, value, value) for value in requested
        ]
        return bool(checks) and all(checks)

    def select_listen_interfaces(
        self, values: Iterable[str], clear_existing: bool = True
    ) -> bool:
        return self.select_interface_values(
            "listen_interface", values, clear_existing=clear_existing
        )

    def select_wan_interfaces(
        self, values: Iterable[str], clear_existing: bool = True
    ) -> bool:
        return self.select_interface_values(
            "wan_interface", values, clear_existing=clear_existing
        )

    def select_listen_interface(self, value: str) -> bool:
        return self.select_interface_values("listen_interface", (value,))

    def select_wan_interface(self, value: str) -> bool:
        return self.select_interface_values("wan_interface", (value,))

    def _fast_nat_confirmation_dialog(self) -> Locator:
        dialogs = self.page.locator(
            ".ant-modal-content:visible, .ant-popconfirm:visible, "
            "[role='dialog']:visible"
        )
        for index in range(dialogs.count() - 1, -1, -1):
            dialog = dialogs.nth(index)
            try:
                text = self._norm(dialog.inner_text())
                if any(keyword in text for keyword in ("软件", "加速", "nat", "确认")):
                    return dialog
            except Exception:
                continue
        return self._missing("fast-nat-dialog")

    def resolve_fast_nat_confirmation(self, confirm: bool) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "confirmation_seen": False,
            "prompt_about_acceleration": False,
            "confirmed": False,
            "cancelled": False,
            "dialog_closed": False,
            "error": "",
        }
        try:
            dialog = self._fast_nat_confirmation_dialog()
            if dialog.count() == 0:
                result["error"] = "未检测到软件加速确认弹窗"
                return result
            result["confirmation_seen"] = True
            prompt = self._norm(dialog.inner_text())
            result["prompt_about_acceleration"] = any(
                keyword in prompt for keyword in ("软件", "加速", "nat")
            )
            names = (
                ("确定", "确认", "继续", "启用")
                if confirm
                else ("取消", "返回", "暂不")
            )
            button: Optional[Locator] = None
            for name in names:
                candidate = dialog.get_by_role("button", name=name, exact=True)
                if candidate.count() > 0:
                    button = candidate.first
                    break
            if button is None and not confirm:
                close = dialog.locator("button.ant-modal-close:visible")
                if close.count() > 0:
                    button = close.first
            if button is None:
                result["error"] = "软件加速确认弹窗缺少目标按钮"
                return result
            button.click(force=True)
            for _ in range(30):
                self.page.wait_for_timeout(100)
                if self._fast_nat_confirmation_dialog().count() == 0:
                    break
            result["dialog_closed"] = self._fast_nat_confirmation_dialog().count() == 0
            result["confirmed"] = bool(confirm and result["dialog_closed"])
            result["cancelled"] = bool(not confirm and result["dialog_closed"])
        except Exception:
            result["error"] = "处理软件加速确认弹窗异常（详情已隐藏）"
        return result

    def select_fast_nat_with_confirmation(
        self, mode: Any, confirm_software: Optional[bool] = True
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "supported": False,
            "selection_attempted": False,
            "confirmation_seen": False,
            "confirmed": False,
            "cancelled": False,
            "selected": False,
            "success": False,
            "error": "",
        }
        option = self._mapping_option(self.FAST_NAT_OPTIONS, mode)
        if option is None:
            result["error"] = "当前实机support_fast=1，不支持硬件加速模式"
            return result
        result["supported"] = True
        result["selection_attempted"] = self._select_field(
            "fast_nat", option[0], option[1]
        )
        if option[0] == "1":
            dialog = self._fast_nat_confirmation_dialog()
            result["confirmation_seen"] = dialog.count() > 0
            if result["confirmation_seen"] and confirm_software is not None:
                branch = self.resolve_fast_nat_confirmation(bool(confirm_software))
                for key in ("confirmation_seen", "confirmed", "cancelled"):
                    result[key] = bool(branch.get(key))
                if branch.get("error"):
                    result["error"] = str(branch["error"])
            elif result["confirmation_seen"] and confirm_software is None:
                result["success"] = bool(result["selection_attempted"])
                return result
        result["selected"] = self.field_matches("fast_nat", option[0]) or self.field_matches(
            "fast_nat", option[1]
        )
        if option[0] == "1" and confirm_software is False:
            result["success"] = bool(result["selection_attempted"] and result["cancelled"])
        else:
            result["success"] = bool(result["selection_attempted"] and result["selected"])
        return result

    def select_fast_nat(
        self, mode: Any, confirm_software: Optional[bool] = True
    ) -> bool:
        return bool(
            self.select_fast_nat_with_confirmation(
                mode, confirm_software=confirm_software
            ).get("success")
        )

    select_acceleration_mode = select_fast_nat
    set_acceleration_mode = select_fast_nat
    set_fast_nat = select_fast_nat

    def select_time_zone(self, value_or_label: Any) -> bool:
        value = str(value_or_label)
        return self._select_field("time_zone", value, value)

    set_time_zone = select_time_zone

    def select_ntp_config(self, mode: Any) -> bool:
        option = self._mapping_option(self.NTP_CONFIG_OPTIONS, mode)
        return False if option is None else self._select_field(
            "ntp_config",
            option[0],
            option[1],
            "使用内置" if option[0] == "builtin" else "自定义",
        )

    set_ntp_config = select_ntp_config

    def select_builtin_ntp_server(self, option_text: Any) -> bool:
        """选择 builtin 模式下的 7 项 NTP 服务来源之一。"""
        if self._field("ntpserver_builtin").count() == 0:
            if not self.select_ntp_config("builtin"):
                return False
            self.page.wait_for_timeout(260)
        value = str(option_text)
        if self._norm(value) in {"custom", "自定义"}:
            value = "自定义"
        elif self._norm(value) in {"default", "默认"}:
            value = "默认"
        return self._select_field("ntpserver_builtin", value, value)

    def fill_custom_ntp_servers(self, values: Any) -> bool:
        """填写选择“自定义”后挂载的 ``#ntpserver_list`` 文本域。"""
        if isinstance(values, (list, tuple, set)):
            text = "\n".join(str(value) for value in values)
        else:
            text = "" if values is None else str(values)
        self._remember_private(text)
        field = self._field("ntpserver_list")
        if field.count() == 0 or not self._field_metadata("ntpserver_list").get(
            "visible"
        ):
            if not self.select_builtin_ntp_server("自定义"):
                return False
            self.page.wait_for_timeout(280)
        return self._fill_text("ntpserver_list", text)

    def set_ntp_server(self, value: Any) -> bool:
        """选择内置服务项；若传入地址则自动选“自定义”并填写文本域。"""
        requested = str(value)
        normalized = self._norm(requested)
        options = self.probe_select_options("ntpserver_builtin")
        exact = next(
            (option for option in options if self._norm(option) == normalized), None
        )
        if exact is not None:
            return self.select_builtin_ntp_server(exact)
        if normalized in {"custom", "自定义"}:
            return self.select_builtin_ntp_server("自定义")
        return self.fill_custom_ntp_servers(value)

    select_ntp_server = set_ntp_server
    fill_ntp_server = fill_custom_ntp_servers
    set_custom_ntp_servers = fill_custom_ntp_servers

    def fill_sync_cycle(self, value: Any) -> bool:
        return self._fill_text("sync_cycle", value)

    set_sync_cycle = fill_sync_cycle

    def set_switch_ntpd(self, enabled: bool) -> bool:
        return self._set_boolean_field("switch_ntpd", bool(enabled))

    set_ntpd_enabled = set_switch_ntpd

    def get_switch_ntpd(self) -> Optional[bool]:
        return self.get_boolean_field("switch_ntpd")

    get_ntpd_enabled = get_switch_ntpd

    def get_mode_condition_state(self) -> Dict[str, Any]:
        """返回条件字段挂载/可见性，不返回接口名或 NTP 地址。"""
        return {
            "internet_mode": {
                "nat4": self.field_matches("switch_nat", "NAT4"),
                "nat1": self.field_matches("switch_nat", "NAT1"),
                "route": self.field_matches("switch_nat", "路由模式"),
            },
            "link_mode": {
                "trunk": self.field_matches("switch_dpi", "主干模式"),
                "bypass": self.field_matches("switch_dpi", "旁路模式"),
                "sd_wan": self.field_matches("switch_dpi", "SD-WAN网桥"),
            },
            "ntp_config": {
                "built_in": self.field_matches("ntp_config", "builtin"),
                "manual": self.field_matches("ntp_config", "custom"),
            },
            "lan_nat": self._field_metadata("lan_nat"),
            "listen_interface": self._field_metadata("listen_interface"),
            "wan_interface": self._field_metadata("wan_interface"),
            "ntpserver_builtin": self._field_metadata("ntpserver_builtin"),
            "ntpserver_list": self._field_metadata("ntpserver_list"),
            "manual_time": self._field_metadata("manual_time"),
            "sync_cycle": self._field_metadata("sync_cycle"),
        }

    get_conditional_fields = get_mode_condition_state

    def fill_form(
        self, values: Optional[Mapping[str, Any]] = None, **kwargs
    ) -> Dict[str, Any]:
        """按依赖顺序填写；结果只含字段名和布尔，不回显传入值。"""
        payload: Dict[str, Any] = dict(values or {})
        payload.update(kwargs)
        handlers: Dict[str, Callable[[Any], bool]] = {
            "hostname": self.fill_hostname,
            "switch_nat": self.select_internet_mode,
            "lan_nat": self.set_lan_nat,
            "switch_dpi": self.select_link_mode,
            "listen_interface": lambda value: self.select_listen_interfaces(
                value if isinstance(value, (list, tuple, set)) else (value,)
            ),
            "wan_interface": lambda value: self.select_wan_interfaces(
                value if isinstance(value, (list, tuple, set)) else (value,)
            ),
            "fast_nat": self.select_fast_nat,
            "time_zone": self.select_time_zone,
            "ntp_config": self.select_ntp_config,
            "ntpserver_builtin": self.select_builtin_ntp_server,
            "ntpserver_list": self.set_ntp_server,
            "sync_cycle": self.fill_sync_cycle,
            "switch_ntpd": self.set_switch_ntpd,
        }
        normalized_payload: Dict[str, Any] = {}
        for key, value in payload.items():
            canonical = self._canonical_field(key)
            if canonical in handlers:
                normalized_payload[canonical] = value
        order = (
            "switch_nat",
            "switch_dpi",
            "fast_nat",
            "ntp_config",
            "hostname",
            "lan_nat",
            "listen_interface",
            "wan_interface",
            "time_zone",
            "ntpserver_builtin",
            "ntpserver_list",
            "sync_cycle",
            "switch_ntpd",
        )
        checks: Dict[str, bool] = {}
        for name in order:
            if name in normalized_payload:
                checks[name] = bool(handlers[name](normalized_payload[name]))
        self.last_fill_checks = dict(checks)
        failed = [name for name, ok in checks.items() if not ok]
        return {
            "success": bool(checks) and not failed,
            "checks": checks,
            "failed_fields": failed,
        }

    fill_basic_form = fill_form

    # ==================== 页面校验、保存和对时 API ====================
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
                    private_item = bool(locator.evaluate("""el => {
                        const item = el.closest('.ant-form-item');
                        return !!item && (!!item.querySelector('#hostname') ||
                            !!item.querySelector('#ntpserver_list') ||
                            !!item.querySelector('#manual_time'));
                    }"""))
                    text = (
                        "隐私字段校验失败（详情已隐藏）"
                        if private_item
                        else self._redact(locator.inner_text())
                    )
                    if text and text not in messages:
                        messages.append(text)
            except Exception:
                continue
        if not messages:
            try:
                if self._form_root().locator(
                    ".ant-form-item-has-error:visible, .ant-input-status-error:visible, "
                    ".ant-input-number-status-error:visible"
                ).count() > 0:
                    messages.append("输入格式错误")
            except Exception:
                pass
        return messages

    get_validation_messages = get_error_messages

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

    @staticmethod
    def _empty_api_result() -> Dict[str, Any]:
        return {
            "requested": False,
            "responded": False,
            "function": "",
            "action": "",
            "method": "",
            "endpoint": "",
            "status": None,
            "semantic": {
                "json_parsed": False,
                "http_ok": False,
                "business_success": None,
                "has_data": False,
                "result_code": None,
            },
        }

    def _execute_api_action(
        self,
        action: str,
        clicker: Callable[[], bool],
        operation_name: str,
        timeout: int = 9000,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "submitted": False,
            "success": False,
            "page_feedback_seen": False,
            "feedback": "",
            "error": "",
            "api": self._empty_api_result(),
        }
        expected_action = self._norm(action)

        def match_request(request) -> bool:
            metadata = self._safe_api_metadata(request)
            if metadata is None or self._norm(metadata.get("action")) != expected_action:
                return False
            result["api"].update(metadata)
            result["api"]["requested"] = True
            return True

        def observe_request(request):
            match_request(request)

        def observe_response(response):
            try:
                if match_request(response.request):
                    result["api"].update(
                        {
                            "responded": True,
                            "status": int(response.status),
                            "semantic": self._safe_response_semantics(response),
                        }
                    )
            except Exception:
                pass

        self.page.on("request", observe_request)
        self.page.on("response", observe_response)
        try:
            self._dismiss_transient_overlays()
            self._wait_transient_feedback_clear()
            if not bool(clicker()):
                result["error"] = f"未能执行{operation_name}页面操作"
            else:
                result["submitted"] = True
                positive_selector = (
                    ".ant-message-success:visible, "
                    ".ant-notification-notice-success:visible"
                )
                loops = max(1, timeout // 160)
                for index in range(loops):
                    self.page.wait_for_timeout(160)
                    errors = self.get_error_messages()
                    if errors:
                        result["error"] = errors[0]
                        break
                    semantic = result["api"].get("semantic", {})
                    if result["api"].get("responded") and semantic.get(
                        "business_success"
                    ) is False:
                        result["error"] = f"{operation_name}接口返回失败语义"
                        break
                    positives = self.page.locator(positive_selector)
                    if positives.count() > 0:
                        result["page_feedback_seen"] = True
                        result["feedback"] = self._redact(
                            positives.last.inner_text() or "操作成功"
                        )
                        # 页面提示可能早于 response 事件；继续等待接口状态，避免
                        # 仅凭 toast 产生“已保存但未捕获契约”的假成功。
                        if result["api"].get("responded"):
                            result["success"] = bool(
                                semantic.get("http_ok")
                                and semantic.get("business_success") is not False
                            )
                            break
                        continue
                    # 给页面反馈至少 640ms 的展示窗口；之后明确接口成功即可完成。
                    if (
                        index >= 4
                        and result["api"].get("responded")
                        and semantic.get("http_ok")
                        and semantic.get("business_success") is True
                    ):
                        result["success"] = True
                        break
                if not result["success"] and not result["error"]:
                    result["error"] = f"{operation_name}后未检测到明确成功或失败反馈"
        except Exception:
            result["error"] = f"{operation_name}操作异常（详情已隐藏）"
        finally:
            try:
                self.page.remove_listener("request", observe_request)
                self.page.remove_listener("response", observe_response)
            except Exception:
                pass
        return result

    def save_settings(self, timeout: int = 9000) -> Dict[str, Any]:
        def click_save() -> bool:
            button = self._button(("保存",))
            if button.count() == 0:
                return False
            button.click()
            return True

        result = self._execute_api_action("save", click_save, "保存基础设置", timeout)
        result["form_visible"] = self._form_root().count() > 0
        return result

    save_and_wait = save_settings
    save_basic_settings = save_settings

    def sync_time_now(self, timeout: int = 9000) -> Dict[str, Any]:
        def click_sync() -> bool:
            button = self._button(("立即对时",))
            if button.count() == 0:
                return False
            button.click()
            return True

        return self._execute_api_action("sync_time", click_sync, "立即对时", timeout)

    sync_time = sync_time_now
    click_sync_time = sync_time_now

    def _fill_picker(self, locator: Locator, value: str) -> bool:
        try:
            locator.scroll_into_view_if_needed()
            locator.click()
            locator.fill(str(value))
            locator.evaluate("""el => {
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            return True
        except Exception:
            return False

    def fill_manual_time_value(
        self, date_value: str, time_value: Optional[str] = None
    ) -> bool:
        """只填写 ``#manual_time``，不点击保存、不触发 ``set_time``。"""
        combined = (
            f"{date_value} {time_value}" if time_value is not None else str(date_value)
        )
        self._remember_private(combined)
        field = self._field("manual_time")
        if field.count() == 0 or not self._field_metadata("manual_time").get("visible"):
            if not self.select_ntp_config("manual"):
                return False
            self.page.wait_for_timeout(260)
            field = self._field("manual_time")
        if field.count() == 0:
            return False
        return self._fill_picker(field, combined)

    def set_manual_time(
        self,
        date_value: str,
        time_value: Optional[str] = None,
        timeout: int = 9000,
    ) -> Dict[str, Any]:
        """通过真实手动时间 UI 触发 ``basic/set_time``，不回传时间原值。"""
        self._remember_private(date_value)
        self._remember_private(time_value)

        def operate() -> bool:
            if not self.fill_manual_time_value(date_value, time_value):
                return False
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            # 实机没有独立“设置时间”按钮；手动模式复用页面唯一“保存”，
            # 前端据此发送 basic/set_time，而非 basic/save。
            button = self._button(("保存",))
            if button.count() == 0:
                return False
            button.click()
            return True

        return self._execute_api_action("set_time", operate, "手动设置时间", timeout)

    set_system_time = set_manual_time
    fill_manual_time = fill_manual_time_value

    # ==================== 无取消、脏导航和帮助 ====================
    def cancel_changes(self, *_args, **_kwargs) -> Dict[str, Any]:
        """基础设置实机无取消按钮，明确返回不适用而不虚构操作。"""
        present = self._button(("取消",)).count() > 0
        return {
            "supported": present,
            "clicked": False,
            "completed": False,
            "result": "支持" if present else "不适用",
            "evidence": "检测到取消按钮" if present else "实机基础设置表单无取消按钮",
        }

    cancel_settings = cancel_changes

    def probe_dirty_navigation(
        self,
        target_path: str = "/#/equipmentSetting/advancedSetting",
        timeout: int = 5000,
    ) -> Dict[str, Any]:
        """只改 DOM 后跨页，验证无脏表单确认，并重新加载恢复原回显。"""
        result: Dict[str, Any] = {
            "modified": False,
            "navigation_attempted": False,
            "native_confirmation_seen": False,
            "dom_confirmation_seen": False,
            "confirmation_seen": False,
            "no_confirmation": False,
            "url_changed": False,
            "save_request_seen": False,
            "returned_to_basic": False,
            "dom_value_restored": False,
            "error": "",
        }
        original = ""

        def observe_request(request):
            metadata = self._safe_api_metadata(request)
            if metadata and self._norm(metadata.get("action")) == "save":
                result["save_request_seen"] = True

        def handle_dialog(dialog):
            result["native_confirmation_seen"] = True
            try:
                # 接受只表示离开未保存 DOM；不会触发 basic/save。
                dialog.accept()
            except Exception:
                pass

        self.page.on("request", observe_request)
        self.page.on("dialog", handle_dialog)
        try:
            self.navigate_to_basic_setting()
            hostname = self._field("hostname")
            if hostname.count() == 0:
                result["error"] = "未找到主机名字段，无法探测脏导航"
                return result
            original = hostname.input_value()
            self._remember_private(original)
            if len(original) >= self.HOSTNAME_MAX_LENGTH:
                probe = original[:-1]
            elif original:
                probe = f"{original}A"
            else:
                probe = "UIProbe"
            if probe == original:
                probe = "UIProbeA"
            result["modified"] = self._fill_text("hostname", probe)
            result["navigation_attempted"] = True
            initial_url = self.page.url
            target = (
                target_path
                if target_path.startswith("http://") or target_path.startswith("https://")
                else f"{self.base_url}{target_path}"
            )
            try:
                self.page.goto(target, wait_until="domcontentloaded", timeout=timeout)
            except Exception:
                pass
            self.page.wait_for_timeout(500)
            dialogs = self.page.locator(
                ".ant-modal-content:visible, .ant-popconfirm:visible, [role='dialog']:visible"
            )
            for index in range(dialogs.count()):
                dialog = dialogs.nth(index)
                text = self._norm(dialog.inner_text())
                if any(word in text for word in ("未保存", "放弃", "继续编辑", "离开")):
                    result["dom_confirmation_seen"] = True
                    for name in ("确定", "放弃", "离开"):
                        button = dialog.get_by_role("button", name=name, exact=True)
                        if button.count() > 0:
                            button.first.click()
                            break
                    break
            result["url_changed"] = self.page.url != initial_url
        except Exception:
            result["error"] = "脏表单导航探测异常（详情已隐藏）"
        finally:
            try:
                self._dismiss_transient_overlays()
                self.page.goto(
                    f"{self.base_url}{self.PAGE_URL}",
                    wait_until="domcontentloaded",
                    timeout=max(timeout, 5000),
                )
                self._wait_page(700)
                result["returned_to_basic"] = self.is_on_basic_setting_page()
                if original or self._field("hostname").count() > 0:
                    result["dom_value_restored"] = self.field_matches(
                        "hostname", original
                    )
            except Exception:
                pass
            try:
                self.page.remove_listener("request", observe_request)
                self.page.remove_listener("dialog", handle_dialog)
            except Exception:
                pass
            result["confirmation_seen"] = bool(
                result["native_confirmation_seen"]
                or result["dom_confirmation_seen"]
            )
            result["no_confirmation"] = bool(
                result["navigation_attempted"] and not result["confirmation_seen"]
            )
        return result

    probe_dirty_navigation_behavior = probe_dirty_navigation

    def verify_help_entry(
        self,
        expected_keywords: Iterable[str] = ("基础设置", "上网模式"),
        timeout: int = 8000,
    ) -> Dict[str, Any]:
        """打开帮助、验证主题并关闭 popup/页内帮助层。"""
        keywords = [str(keyword) for keyword in expected_keywords if str(keyword)]
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
                result["error"] = "未找到基础设置帮助入口"
                return result
            button.click()
            result["clicked"] = True
            for _ in range(max(1, timeout // 100)):
                new_pages = [page for page in context.pages if page not in before_pages]
                if new_pages:
                    popup = new_pages[-1]
                    result["opened"] = True
                    result["container"] = "popup"
                    break
                panels = self.page.locator(
                    ".ant-modal-content:visible, .ant-drawer-content:visible, "
                    "[class*='help']:visible[role='dialog']"
                )
                if panels.count() > 0:
                    candidate = panels.last
                    text = candidate.inner_text() or ""
                    if "帮助" in text or any(keyword in text for keyword in keywords):
                        panel = candidate
                        result["opened"] = True
                        result["container"] = "in_page"
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
                        (
                            urlsplit(popup.url or "").path,
                            popup.title(),
                            popup.locator("body").inner_text(timeout=3000),
                        )
                    )
                except Exception:
                    searchable = urlsplit(popup.url or "").path
            elif panel is not None:
                searchable = panel.inner_text() or ""
            matched = [
                keyword
                for keyword in keywords
                if self._norm(keyword) in self._norm(searchable)
            ]
            result["matched_keywords"] = matched
            result["content_matched"] = bool(matched)
            result["all_keywords_matched"] = bool(keywords) and len(matched) == len(
                keywords
            )
            if result["opened"] and not result["content_matched"]:
                result["error"] = "帮助已打开，但内容未匹配基础设置主题"
        except Exception:
            result["error"] = "基础设置帮助验证异常（详情已隐藏）"
        finally:
            for candidate in list(context.pages):
                if candidate in before_pages:
                    continue
                try:
                    if not candidate.is_closed():
                        candidate.close()
                except Exception:
                    pass
            if panel is not None:
                try:
                    close = panel.locator(
                        "button.ant-modal-close:visible, button.ant-drawer-close:visible"
                    )
                    if close.count() == 0:
                        for name in ("关闭", "返回"):
                            candidate = panel.get_by_role(
                                "button", name=name, exact=True
                            )
                            if candidate.count() > 0:
                                close = candidate.first
                                break
                    if close.count() > 0:
                        close.first.click()
                    else:
                        self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(200)
                    result["closed"] = not panel.is_visible()
                except Exception:
                    pass
            elif popup is not None:
                try:
                    result["closed"] = popup.is_closed()
                except Exception:
                    pass
            result["no_orphan"] = all(
                candidate in before_pages for candidate in context.pages
            )
        return result

    open_help_and_verify = verify_help_entry


__all__ = ["BasicSettingPage"]
