"""网络配置 -> OSPF 页面对象。

实机页面是实例列表。区域、接口、邻居和路由引入通过实例行的计数
单元格进入详情抽屉，不使用 ``IkuaiTablePage`` 默认的“添加”按钮语义。
"""
from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from playwright.sync_api import Locator, Page

from pages.ikuai_table_page import IkuaiTablePage


class OspfPage(IkuaiTablePage):
    MODULE_NAME = "ospf"
    LIST_URL = "/#/networkConfiguration/ospf"

    INSTANCE_COLUMNS = (
        "版本", "OSPF 实例", "Router ID", "OSPF 区域数目",
        "已启用接口数目", "邻居数目", "引入外部路由数目", "操作",
    )
    DETAIL_CELL_INDEX = {
        "area": 4,
        "interface": 5,
        "neighbor": 6,
        "redistribute": 7,
    }
    DETAIL_TAB_LABEL = {
        "area": "OSPF区域",
        "interface": "OSPF接口",
        "neighbor": "OSPF邻居状态",
        "redistribute": "OSPF引入外部路由",
    }
    SECRET_FIELDS = {"password", "md5_key", "auth_key", "ipsec_key"}
    AREA_TYPE_LABELS = {
        "normal": "Normal", "stub": "Stub", "nssa": "NSSA",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)
        self._runtime_secrets: set[str] = set()

    def navigate_to_ospf(self):
        self._dismiss_overlays()
        def is_instance_show(response):
            if urlsplit(response.url).path != "/Action/call":
                return False
            try:
                payload = response.request.post_data_json
            except Exception:
                return False
            params = payload.get("param", {}) if isinstance(payload, dict) else {}
            return (
                isinstance(payload, dict)
                and payload.get("func_name") == "ospf"
                and payload.get("action") == "show"
                and isinstance(params, dict)
                and params.get("table") == "instance_list"
            )

        total = None
        target_url = f"{self.base_url}{self.LIST_URL}"

        def navigate():
            current = self.page.url.rstrip("/")
            target = target_url.rstrip("/")
            if current == target:
                self.page.reload()
            else:
                self.page.goto(target_url)

        try:
            with self.page.expect_response(is_instance_show, timeout=15000) as info:
                navigate()
            payload = info.value.json()
            total = int(((payload.get("results") or {}).get("total") or 0))
        except Exception:
            if self.page.url.rstrip("/") == target_url.rstrip("/"):
                self.page.reload()
            else:
                self.page.goto(target_url)
        self.page.wait_for_load_state("domcontentloaded")
        self.page.locator(".ant-table").first.wait_for(state="visible", timeout=15000)
        # The table shell is rendered before the asynchronous ``ospf/show``
        # response.  Waiting only for ``.ant-table`` caused a real instance to be
        # treated as absent and skipped cleanup.  A data row or the placeholder is
        # the first stable state of the list.
        if total is not None and total > 0:
            self.page.locator(
                ".ant-table-tbody .ant-table-row"
            ).first.wait_for(state="visible", timeout=15000)
        elif total == 0:
            self.page.locator(
                ".ant-table-placeholder"
            ).first.wait_for(state="visible", timeout=15000)
        else:
            self.page.locator(
                ".ant-table-tbody .ant-table-row,.ant-table-placeholder"
            ).first.wait_for(state="visible", timeout=15000)
        return self

    def _dismiss_overlays(self):
        try:
            self.page.keyboard.press("Escape")
        except Exception:
            pass
        for locator in (
            self.page.locator(".ant-modal:visible .ant-modal-close"),
            self.page.locator(".ant-drawer:visible .ant-drawer-close"),
        ):
            while locator.count():
                try:
                    locator.last.click(force=True, timeout=800)
                except Exception:
                    break

    @staticmethod
    def _visible_unique_text(locator: Locator) -> List[str]:
        values: List[str] = []
        for text in locator.all_inner_texts():
            normalized = " ".join(text.split())
            if normalized and normalized not in values:
                values.append(normalized)
        return values

    def page_structure(self) -> Dict[str, Any]:
        headers = self._visible_unique_text(
            self.page.locator(".ant-table-thead .ant-table-cell:visible")
        )
        buttons = self._visible_unique_text(self.page.locator("button:visible"))
        row_count = self.page.locator(
            ".ant-table-tbody .ant-table-row"
        ).count()
        return {
            "url_path": urlsplit(self.page.url).path + ("#" + self.page.url.split("#", 1)[1]
                                                          if "#" in self.page.url else ""),
            "headers": headers,
            "buttons": buttons,
            "empty": row_count == 0 and self.page.locator(
                ".ant-table-placeholder"
            ).count() > 0,
            "row_count": row_count,
            "pagination": self.page.locator(".ant-pagination:visible").count() > 0,
            "column_settings": self.page.locator("button.filterIcon:visible").count() > 0,
            "column_filters": self.page.locator(
                ".ant-table-filter-trigger:visible"
            ).count(),
        }

    def capability_matrix(self) -> Dict[str, bool]:
        structure = self.page_structure()
        text = " ".join(structure["buttons"])
        return {
            "create": "新建" in structure["buttons"],
            "column_settings": structure["column_settings"],
            "column_filters": structure["column_filters"] > 0,
            "pagination": structure["pagination"],
            "search_box": self.page.locator(
                "input:not([readonly])[type=search]:visible"
            ).count() > 0,
            "explicit_refresh": "刷新" in text,
            "help": "帮助" in text or self.page.locator(
                "button[aria-label*=help i]:visible,button[title*=帮助]:visible"
            ).count() > 0,
            "import": "导入" in text,
            "export": "导出" in text,
            "copy": "复制" in text,
            "batch_toolbar": self.page.locator(
                ".ant-table-selection-extra:visible,.batch-operation:visible"
            ).count() > 0,
        }

    def open_column_settings(self) -> Dict[str, Any]:
        self.page.locator("button.filterIcon:visible").first.click()
        drawer = self.page.locator(".ant-drawer:visible").last
        drawer.wait_for(state="visible")
        text = " ".join(drawer.inner_text().split())
        columns = [
            column for column in self.INSTANCE_COLUMNS[:-1]
            if column in text
        ]
        return {
            "text": text,
            "columns": columns,
            "checkbox_count": drawer.locator(
                ".ant-checkbox,input[type=checkbox]"
            ).count(),
            "reorder_control_count": drawer.locator(".anticon-up").count(),
            "has_restore_default": "恢复默认值" in text,
        }

    def close_top_drawer(self):
        drawer = self.page.locator(".ant-drawer:visible")
        if drawer.count():
            close = drawer.last.get_by_role("button", name="关闭")
            if close.count():
                # Nested detail drawers can place the close control outside the
                # Playwright viewport even though Ant marks it visible.  DOM click
                # is equivalent to the user control and avoids a fixed delay.
                close.evaluate("element => element.click()")
                drawer.last.wait_for(state="hidden", timeout=5000)

    def api_call(self, action: str, table: str,
                 params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call the authenticated OSPF endpoint without retaining request bodies.

        Only field names and response semantics are returned.  Callers must never
        pass authentication values through this helper when recording evidence.
        """
        payload = {
            "func_name": "ospf",
            "action": action,
            "param": {"table": table, **dict(params or {})},
        }
        response = self.page.evaluate(
            """async payload => {
                const response = await fetch('/Action/call', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    credentials: 'same-origin',
                    body: JSON.stringify(payload),
                });
                let body = {};
                try { body = await response.json(); } catch (_) {}
                return {
                    http_status: response.status,
                    code: body.code,
                    message: String(body.message || '').slice(0, 240),
                };
            }""",
            payload,
        )
        response["endpoint"] = "/Action/call"
        response["method"] = "POST"
        response["func_name"] = "ospf"
        response["action"] = action
        response["table"] = table
        response["parameter_fields"] = sorted((params or {}).keys())
        response["success"] = (
            response.get("http_status") == 200 and response.get("code") == 0
        )
        return response

    def open_first_column_filter(self) -> Dict[str, Any]:
        trigger = self.page.locator(".ant-table-filter-trigger:visible").first
        trigger.click()
        popup = self.page.locator(".ant-dropdown:visible").last
        popup.wait_for(state="visible")
        return {
            "text": " ".join(popup.inner_text().split()),
            "has_input": popup.locator("input:visible").count() > 0,
        }

    def open_new_instance(self) -> Locator:
        self._dismiss_overlays()
        self.page.get_by_role("button", name="新建", exact=True).first.click()
        drawer = self.page.locator(".ant-drawer:visible").last
        drawer.wait_for(state="visible")
        return drawer

    def _instance_drawer(self) -> Locator:
        drawer = self.page.locator(".ant-drawer:visible").last
        drawer.wait_for(state="visible")
        return drawer

    @staticmethod
    def _replace_input(locator: Locator, value: Any):
        locator.fill(str(value), force=True)

    @staticmethod
    def _dom_click(locator: Locator):
        locator.evaluate(
            "element => { element.scrollIntoView({block: 'center'}); element.click(); }"
        )

    def fill_instance(self, process_id: Any, router_id: str,
                      version: str = "OSPFv2"):
        drawer = self._instance_drawer()
        radio = drawer.get_by_text(version, exact=True)
        if radio.count() and radio.first.is_enabled():
            radio.first.click()
        self._replace_input(
            drawer.locator("input[placeholder*='1 - 65535']"), process_id
        )
        self._replace_input(
            drawer.locator("input[placeholder*='1.1.1.1']"), router_id
        )

    @staticmethod
    def _safe_response(response) -> Dict[str, Any]:
        result: Dict[str, Any] = {"http_status": response.status}
        try:
            payload = response.json()
        except Exception:
            return result
        if not isinstance(payload, dict):
            return result
        for key in ("code", "ErrCode", "errcode", "success", "Result"):
            value = payload.get(key)
            if isinstance(value, (str, int, float, bool)) or value is None:
                result[key] = value
        for key in ("ErrMsg", "error", "message", "msg"):
            value = payload.get(key)
            if isinstance(value, str):
                result[key] = value[:240]
        return result

    def _submit_ospf(self, button: Locator, expected_action: str,
                     timeout: int = 15000) -> Dict[str, Any]:
        def matches(response):
            if urlsplit(response.url).path != "/Action/call":
                return False
            request = response.request
            try:
                payload = request.post_data_json
            except Exception:
                return False
            return (
                isinstance(payload, dict)
                and payload.get("func_name") == "ospf"
                and payload.get("action") == expected_action
            )

        try:
            with self.page.expect_response(matches, timeout=timeout) as info:
                self._dom_click(button)
            result = self._safe_response(info.value)
            try:
                request_payload = info.value.request.post_data_json
            except Exception:
                request_payload = {}
            params = request_payload.get("param", {}) if isinstance(request_payload, dict) else {}
            result.update({
                "endpoint": urlsplit(info.value.url).path,
                "method": info.value.request.method,
                "func_name": request_payload.get("func_name") if isinstance(request_payload, dict) else None,
                "action": request_payload.get("action") if isinstance(request_payload, dict) else None,
                "table": params.get("table") if isinstance(params, dict) else None,
                "parameter_fields": sorted(params.keys()) if isinstance(params, dict) else [],
                "parameter_semantics": self._safe_parameter_semantics(params),
            })
        except Exception as exc:
            return {
                "success": False, "error": type(exc).__name__,
                "form_errors": self.form_errors(),
            }
        self.page.wait_for_timeout(120)
        errors = self.form_errors()
        code = result.get("code", result.get("Result"))
        business_ok = result.get("success") is not False and code in (None, 0, 10000, "0", "10000")
        result["success"] = result.get("http_status") == 200 and business_ok and not errors
        result["form_errors"] = errors
        return result

    @classmethod
    def _safe_parameter_semantics(cls, value: Any, field: str = "") -> Any:
        """Keep request semantics without retaining authentication values."""
        normalized = field.lower().replace("-", "_")
        if normalized in cls.SECRET_FIELDS or any(
            token in normalized for token in ("password", "auth_key", "md5_key")
        ):
            rendered = "" if value is None else str(value)
            return {"configured": bool(rendered), "length": len(rendered)}
        if isinstance(value, dict):
            return {
                str(key): cls._safe_parameter_semantics(item, str(key))
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._safe_parameter_semantics(item, field) for item in value]
        if isinstance(value, str):
            return value[:160]
        return value

    def save_instance(self) -> Dict[str, Any]:
        drawer = self._instance_drawer()
        return self._submit_ospf(
            drawer.get_by_role("button", name="保存", exact=True),
            "edit" if "编辑 OSPF 实例" in drawer.inner_text() else "add",
        )

    def cancel_current_drawer(self):
        drawer = self._instance_drawer()
        drawer.get_by_role("button", name="取消", exact=True).click(force=True)

    def form_errors(self) -> List[str]:
        return self._visible_unique_text(
            self.page.locator(
                ".ant-form-item-explain-error:visible,.ant-message-error:visible"
            )
        )

    def find_instance_row(self, process_id: Any) -> Locator:
        return self.page.locator(".ant-table-row").filter(
            has_text=str(process_id)
        ).first

    def instance_exists(self, process_id: Any) -> bool:
        row = self.find_instance_row(process_id)
        return row.count() > 0 and row.is_visible()

    def open_edit_instance(self, process_id: Any) -> Locator:
        row = self.find_instance_row(process_id)
        row.get_by_text("编辑", exact=True).click()
        return self._instance_drawer()

    def edit_instance_router_id(self, router_id: str):
        drawer = self._instance_drawer()
        self._replace_input(
            drawer.locator("input[placeholder*='1.1.1.1']"), router_id
        )

    def delete_instance(self, process_id: Any) -> Dict[str, Any]:
        row = self.find_instance_row(process_id)
        row.get_by_text("删除", exact=True).click()
        modal = self.page.locator(".ant-modal-confirm:visible,.ant-modal:visible").last
        modal.wait_for(state="visible")
        return self._submit_ospf(
            modal.get_by_role("button", name="确定", exact=True), "del"
        )

    def open_instance_detail(self, process_id: Any, tab: str = "area") -> Locator:
        row = self.find_instance_row(process_id)
        cells = row.locator(".ant-table-cell")
        index = self.DETAIL_CELL_INDEX[tab]
        cell = cells.nth(index)
        clickable = cell.locator(
            "span[class*='clickableCount'],a,button,[role=button],.ant-typography-link"
        )
        if clickable.count():
            self._dom_click(clickable.first)
        else:
            # Current OSPF build attaches the detail handler to the count cell
            # itself and renders a bare text node (for example ``0``).
            self._dom_click(cell)
        drawer = self.page.locator(".ant-drawer:visible").last
        drawer.wait_for(state="visible")
        wanted_tab = self.DETAIL_TAB_LABEL[tab]
        tab_locator = drawer.locator(".ant-tabs-tab").filter(
            has_text=wanted_tab
        ).first
        if tab_locator.count():
            self._dom_click(tab_locator)
        try:
            drawer.locator(
                ".ant-table-tbody .ant-table-row,.ant-table-placeholder"
            ).first.wait_for(state="visible", timeout=15000)
        except Exception:
            # Neighbor/runtime tabs can render a non-table empty state. Their
            # caller still inspects the drawer, while create flows below require
            # a stable table before clicking New.
            pass
        return drawer

    def detail_snapshot(self, process_id: Any, tab: str) -> Dict[str, Any]:
        drawer = self.open_instance_detail(process_id, tab)
        return {
            "tabs": self._visible_unique_text(
                drawer.locator("[role=tab]:visible,.ant-tabs-tab:visible")
            ),
            "headers": self._visible_unique_text(
                drawer.locator(".ant-table-thead .ant-table-cell:visible")
            ),
            "buttons": self._visible_unique_text(drawer.locator("button:visible")),
            "text": " ".join(drawer.inner_text().split())[:1000],
        }

    def _form_item(self, root: Locator, label: str) -> Locator:
        items = root.locator(".ant-form-item")
        for index in range(items.count()):
            item = items.nth(index)
            label_node = item.locator(".ant-form-item-label").first
            if not label_node.count():
                continue
            normalized = " ".join(label_node.inner_text().split())
            if normalized == label:
                return item
        raise AssertionError(f"表单字段不存在: {label}")

    def _select(self, root: Locator, label: str, option: str):
        item = self._form_item(root, label)
        select = item.locator(".ant-select").first
        wanted = self.AREA_TYPE_LABELS.get(option, option)
        current_node = select.locator(".ant-select-selection-item")
        if current_node.count():
            current = " ".join(current_node.first.inner_text().split()).lower()
            wanted_lower = wanted.lower()
            if current == wanted_lower or current.startswith(wanted_lower + " ("):
                return
        search = select.locator("input")
        if search.count():
            search.first.focus()
            search.first.fill(wanted, force=True)
            search.first.press("Enter")
            if current_node.count():
                current = " ".join(current_node.first.inner_text().split()).lower()
                if current == wanted_lower or current.startswith(wanted_lower + " ("):
                    return
        selector = select.locator(".ant-select-selector")
        (selector if selector.count() else select).dispatch_event("mousedown")
        candidate = self.page.locator(
            ".ant-select-item-option-content:visible"
        )
        candidate.first.wait_for(state="visible", timeout=5000)
        for index in range(candidate.count()):
            normalized = " ".join(candidate.nth(index).inner_text().split())
            normalized_lower = normalized.lower()
            wanted_lower = wanted.lower()
            if (
                normalized_lower == wanted_lower
                or normalized_lower.startswith(wanted_lower + " (")
            ):
                self._dom_click(candidate.nth(index))
                return
        observed = [
            " ".join(candidate.nth(index).inner_text().split())
            for index in range(candidate.count())
        ]
        raise AssertionError(
            f"下拉选项不存在: {label}={option}; observed={observed}"
        )

    def _input(self, root: Locator, label: str) -> Locator:
        return self._form_item(root, label).locator("input,textarea").first

    def open_new_area(self, process_id: Any) -> Locator:
        detail = self.open_instance_detail(process_id, "area")
        spinner = detail.locator(".ant-spin-spinning")
        if spinner.count():
            spinner.last.wait_for(state="hidden", timeout=15000)
        before = self.page.locator(".ant-drawer:visible").count()
        self._dom_click(
            detail.locator("button").filter(has_text="新建").last
        )
        drawer = self.page.locator(".ant-drawer:visible").nth(before)
        drawer.wait_for(state="visible")
        return drawer

    def open_edit_area(self, process_id: Any, area_id: str) -> Locator:
        detail = self.open_instance_detail(process_id, "area")
        row = detail.locator(".ant-table-tbody .ant-table-row").filter(
            has_text=str(area_id)
        ).first
        before = self.page.locator(".ant-drawer:visible").count()
        edit = row.get_by_text("编辑", exact=True)
        self._dom_click(edit)
        drawer = self.page.locator(".ant-drawer:visible").nth(before)
        drawer.wait_for(state="visible")
        return drawer

    def fill_area(self, area_id: str, area_type: str = "normal"):
        drawer = self._instance_drawer()
        self._replace_input(self._input(drawer, "区域ID"), area_id)
        self._select(drawer, "区域类型", area_type)

    def add_area_interface(self, ifname: str, network_type: str = "broadcast",
                           priority: int = 1, cost: int = 10,
                           hello: int = 10, dead: int = 40,
                           password: Optional[str] = None):
        drawer = self._instance_drawer()
        button = drawer.locator("button:visible").filter(
            has_text="添加接口"
        ).last
        self._dom_click(button)
        rows = drawer.locator("fieldset,.ant-collapse-item").filter(has_text="接口")
        scope = rows.last if rows.count() else drawer
        self._select(scope, "接口", ifname)
        self._select(scope, "接口类型", network_type)
        for label, value in (
            ("DR优先级", priority), ("协议开销", cost),
            ("Hello", hello), ("邻居失效时间", dead),
        ):
            locator = self._input(scope, label)
            if locator.count():
                self._replace_input(locator, value)
        if password is not None:
            self._runtime_secrets.add(password)
            locator = scope.locator("input[type=password],input[placeholder='请输入密码']")
            if locator.count():
                self._replace_input(locator.first, password)

    def set_existing_area_interface(
        self, ifname: str, network_type: Optional[str] = None,
        priority: Optional[int] = None, cost: Optional[int] = None,
        hello: Optional[int] = None, dead: Optional[int] = None,
        password: Optional[str] = None,
    ):
        drawer = self._instance_drawer()
        scopes = drawer.locator("fieldset,.ant-collapse-item").filter(
            has_text=ifname
        )
        scope = scopes.first if scopes.count() else drawer
        if network_type is not None:
            self._select(scope, "接口类型", network_type)
        for label, value in (
            ("DR优先级", priority), ("协议开销", cost),
            ("Hello", hello), ("邻居失效时间", dead),
        ):
            if value is not None:
                self._replace_input(self._input(scope, label), value)
        if password is not None:
            self._runtime_secrets.add(password)
            locator = scope.locator(
                "input[type=password],input[placeholder='请输入密码']"
            )
            if locator.count():
                self._replace_input(locator.first, password)

    def save_area(self) -> Dict[str, Any]:
        drawer = self._instance_drawer()
        action = "edit" if "编辑 OSPF 区域" in drawer.inner_text() else "add"
        return self._submit_ospf(
            drawer.get_by_role("button", name="保存", exact=True), action
        )

    def resolve_dirty_cancel(self, discard: bool) -> Dict[str, Any]:
        drawer = self._instance_drawer()
        drawer.get_by_role("button", name="取消", exact=True).click(force=True)
        deadline = time.monotonic() + 3.0
        modal = self.page.locator(".ant-modal:visible")
        while time.monotonic() < deadline:
            if modal.count() or not drawer.is_visible():
                break
            self.page.wait_for_timeout(50)
        if not modal.count():
            return {"dialog": False, "drawer_closed": not drawer.is_visible()}
        modal = modal.last
        text = " ".join(modal.inner_text().split())
        wanted = "确认放弃" if discard else "继续编辑"
        button = modal.get_by_role("button", name=wanted, exact=True)
        if not button.count():
            button = modal.locator("button").last if discard else modal.locator("button").first
        button.click(force=True)
        return {
            "dialog": True, "text": text, "choice": wanted,
            "drawer_closed": not drawer.is_visible(),
        }

    def open_new_redistribute(self, process_id: Any) -> Locator:
        detail = self.open_instance_detail(process_id, "redistribute")
        spinner = detail.locator(".ant-spin-spinning")
        if spinner.count():
            spinner.last.wait_for(state="hidden", timeout=15000)
        self._dom_click(
            detail.locator("button").filter(has_text="新建").last
        )
        modal = self.page.locator(".ant-modal:visible").last
        modal.wait_for(state="visible")
        return modal

    def _redistribute_modal(self) -> Locator:
        modal = self.page.locator(".ant-modal:visible").last
        modal.wait_for(state="visible")
        return modal

    def redistribute_options(self) -> List[str]:
        modal = self._redistribute_modal()
        item = self._form_item(modal, "协议类型")
        select = item.locator(".ant-select").first
        select.locator(".ant-select-selector").dispatch_event("mousedown")
        options = self._visible_unique_text(
            self.page.locator(".ant-select-item-option-content:visible")
        )
        self.page.keyboard.press("Escape")
        return options

    def cancel_redistribute(self):
        modal = self._redistribute_modal()
        modal.get_by_role("button", name="取消", exact=True).click(force=True)
        modal.wait_for(state="hidden", timeout=5000)

    def fill_redistribute(self, source: str, source_process: Optional[int] = None):
        drawer = self._redistribute_modal()
        labels = {
            "connected": "直连路由", "static": "静态路由",
            "ospf": "OSPF", "default-gw": "默认路由",
        }
        self._select(drawer, "协议类型", labels.get(source, source))
        if source_process is not None:
            try:
                process_input = self._input(drawer, "OSPF实例")
            except AssertionError:
                process_input = self._input(drawer, "OSPF 实例")
            self._replace_input(process_input, source_process)

    def save_redistribute(self) -> Dict[str, Any]:
        drawer = self._redistribute_modal()
        return self._submit_ospf(
            drawer.get_by_role("button", name="确定", exact=True), "add"
        )

    def get_safe_form_observation(self) -> Dict[str, Any]:
        drawer = self._instance_drawer()
        observations = []
        for locator in drawer.locator("input:visible,textarea:visible").all():
            input_type = locator.get_attribute("type") or "text"
            value = locator.input_value()
            observations.append({
                "type": input_type,
                "placeholder": locator.get_attribute("placeholder") or "",
                "maxlength": locator.get_attribute("maxlength"),
                "min": locator.get_attribute("min"),
                "max": locator.get_attribute("max"),
                "disabled": locator.is_disabled(),
                "has_value": bool(value),
                "value_length": len(value),
            })
        return {
            "title": " ".join(drawer.inner_text().split())[:120],
            "inputs": observations,
            "labels": self._visible_unique_text(
                drawer.locator(".ant-form-item-label:visible,label:visible")
            ),
        }
