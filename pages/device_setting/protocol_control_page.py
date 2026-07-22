"""设备设置 > 高级管理 > 协议控制 Page Object。

实机页面位于 ``/#/equipmentSetting/advancedManagement`` 的“协议控制”页签。
它是一个无保存按钮的单例双模式页面：平衡模式直接提交，性能模式先弹出
“我知道了”确认框，再调用 ``core_control/save``。页面没有列表、搜索、
新增、删除、批量、导入导出、排序或分页能力。
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Iterable, Optional

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage


class ProtocolControlPage(BasePage):
    """iKuai 4.0 协议控制单例模式页。"""

    MODULE_NAME = "protocol_control"
    FUNC_NAME = "core_control"
    PAGE_URL = "/#/equipmentSetting/advancedManagement"
    BACKEND_SCRIPT = "/usr/ikuai/script/core_control.sh"
    MODE_PERFORMANCE = 0
    MODE_BALANCED = 1
    MODE_NAMES = {
        MODE_PERFORMANCE: "性能模式",
        MODE_BALANCED: "平衡模式",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url.rstrip("/")
        self.last_save_result: Dict[str, Any] = {}

    def _tab(self) -> Locator:
        return self.page.locator(".ant-tabs-tab:visible").filter(
            has_text="协议控制"
        ).first

    def _mode_card(self, mode: int) -> Locator:
        name = self.MODE_NAMES.get(int(mode), "__协议控制模式不存在__")
        return self.page.get_by_role(
            "button", name=re.compile(rf"^{re.escape(name)}")
        ).first

    @staticmethod
    def _is_core_request(request, action: Optional[str] = None) -> bool:
        try:
            payload = json.loads(request.post_data or "{}")
        except Exception:
            return False
        if str(payload.get("func_name") or "") != "core_control":
            return False
        return action is None or str(payload.get("action") or "") == action

    def navigate_to_protocol_control(self) -> bool:
        try:
            self.page.goto(
                f"{self.base_url}{self.PAGE_URL}", wait_until="domcontentloaded"
            )
            tab = self._tab()
            tab.wait_for(state="visible", timeout=10000)
            tab.click()
            self._mode_card(self.MODE_BALANCED).wait_for(
                state="visible", timeout=10000
            )
            self._mode_card(self.MODE_PERFORMANCE).wait_for(
                state="visible", timeout=10000
            )
            self.page.wait_for_timeout(250)
            return self.is_on_protocol_control_page()
        except Exception:
            return False

    navigate_to_protocol = navigate_to_protocol_control

    def is_on_protocol_control_page(self) -> bool:
        try:
            body = self.page.locator("body").inner_text(timeout=3000)
            return bool(
                "equipmentSetting/advancedManagement" in self.page.url
                and "协议控制模式" in body
                and self._mode_card(self.MODE_BALANCED).count() == 1
                and self._mode_card(self.MODE_PERFORMANCE).count() == 1
            )
        except Exception:
            return False

    def get_mode(self) -> Optional[int]:
        for mode in (self.MODE_BALANCED, self.MODE_PERFORMANCE):
            card = self._mode_card(mode)
            if card.count() == 0:
                continue
            classes = str(card.get_attribute("class") or "")
            if "modeCardActive" in classes:
                return mode
        return None

    def get_page_structure(self) -> Dict[str, Any]:
        buttons = self.page.locator("button:visible").all_inner_texts()
        return {
            "url": self.page.url,
            "singleton": True,
            "mode_count": sum(
                self._mode_card(mode).count()
                for mode in (self.MODE_BALANCED, self.MODE_PERFORMANCE)
            ),
            "active_mode": self.get_mode(),
            "buttons": [text.strip() for text in buttons if text.strip()],
            "help_count": self.page.locator(
                "span[aria-label='question-circle']:visible"
            ).count(),
            "save_button_present": self.page.get_by_role(
                "button", name="保存", exact=True
            ).count() > 0,
            "table_present": self.page.locator("table:visible").count() > 0,
            "search_present": self.page.locator(
                "input[placeholder*='搜索']:visible, input[placeholder*='查询']:visible"
            ).count() > 0,
            "pagination_present": self.page.locator(
                ".ant-pagination:visible"
            ).count() > 0,
        }

    def get_capability_matrix(self) -> Dict[str, Dict[str, Any]]:
        structure = self.get_page_structure()

        def item(supported: bool, evidence: str) -> Dict[str, Any]:
            return {
                "supported": bool(supported),
                "result": "支持" if supported else "不适用",
                "evidence": evidence,
            }

        no_list = "实机为forward_mode_config id=1单例双模式页，无列表型入口"
        return {
            "singleton_mode_switch": item(
                structure["mode_count"] == 2,
                "检测到平衡模式和性能模式两个互斥按钮",
            ),
            "immediate_save": item(
                not structure["save_button_present"],
                "页面无保存按钮；卡片确认后直接调用core_control/save",
            ),
            "two_help_entries": item(
                structure["help_count"] == 2,
                "两个模式标题旁各有question-circle悬浮帮助",
            ),
            "search": item(bool(structure["search_present"]), no_list),
            "add_record": item(False, no_list),
            "edit_record": item(False, no_list),
            "delete_record": item(False, no_list),
            "batch_operation": item(False, no_list),
            "import": item(False, no_list),
            "export": item(False, no_list),
            "sort": item(False, no_list),
            "pagination": item(bool(structure["pagination_present"]), no_list),
        }

    get_capabilities = get_capability_matrix

    def api_show(self) -> Dict[str, Any]:
        return self.page.evaluate(
            """async () => {
                const response = await fetch('/Action/call', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        func_name: 'core_control', action: 'show', param: {}
                    })
                });
                return await response.json();
            }"""
        )

    def api_save(self, mode: Any, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        param = {"mode": mode}
        param.update(dict(extra or {}))
        return self.page.evaluate(
            """async (param) => {
                const response = await fetch('/Action/call', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        func_name: 'core_control', action: 'save', param
                    })
                });
                return await response.json();
            }""",
            param,
        )

    @staticmethod
    def api_row(payload: Dict[str, Any]) -> Dict[str, Any]:
        rows = ((payload or {}).get("results") or {}).get("data") or []
        return dict(rows[0]) if rows else {}

    def select_mode(self, mode: int, timeout: int = 25000) -> Dict[str, Any]:
        mode = int(mode)
        if mode not in self.MODE_NAMES:
            return {"saved": False, "error": "仅支持平衡模式或性能模式"}
        current = self.get_mode()
        if current == mode:
            result = {
                "saved": True,
                "noop": True,
                "mode": mode,
                "selected": True,
                "request_seen": False,
                "response_seen": False,
                "api_success": True,
            }
            self.last_save_result = result
            return result

        result: Dict[str, Any] = {
            "saved": False,
            "noop": False,
            "mode": mode,
            "confirmation_seen": False,
            "confirmation_accepted": False,
            "request_seen": False,
            "request_param": {},
            "response_seen": False,
            "http_status": None,
            "api_code": None,
            "api_success": False,
            "show_seen": False,
            "selected": False,
            "error": "",
        }

        def observe_request(request):
            if self._is_core_request(request, "save"):
                result["request_seen"] = True
                try:
                    payload = json.loads(request.post_data or "{}")
                    result["request_param"] = dict(payload.get("param") or {})
                except Exception:
                    pass

        def observe_response(response):
            if self._is_core_request(response.request, "show"):
                result["show_seen"] = True
                return
            if not self._is_core_request(response.request, "save"):
                return
            result["response_seen"] = True
            result["http_status"] = response.status
            try:
                payload = response.json()
            except Exception:
                payload = {}
            result["api_code"] = payload.get("code")
            result["api_success"] = bool(
                response.status == 200 and payload.get("code") == 0
            )

        self.page.on("request", observe_request)
        self.page.on("response", observe_response)
        try:
            self._mode_card(mode).click()
            if mode == self.MODE_PERFORMANCE:
                confirm = self.page.get_by_role(
                    "button", name="我知道了", exact=True
                )
                confirm.wait_for(state="visible", timeout=5000)
                result["confirmation_seen"] = True
                confirm.click()
                result["confirmation_accepted"] = True

            deadline = time.time() + timeout / 1000
            while time.time() < deadline:
                result["selected"] = self.get_mode() == mode
                if result["api_success"] and result["selected"]:
                    break
                self.page.wait_for_timeout(150)
            result["selected"] = self.get_mode() == mode
            result["saved"] = bool(
                result["request_seen"]
                and result["response_seen"]
                and result["api_success"]
                and result["selected"]
                and result["request_param"] == {"mode": mode}
            )
            if not result["saved"] and not result["error"]:
                result["error"] = "协议控制模式提交或回显未完成"
            return result
        except Exception as exc:
            result["error"] = f"协议控制切换异常({type(exc).__name__})"
            return result
        finally:
            try:
                self.page.remove_listener("request", observe_request)
                self.page.remove_listener("response", observe_response)
            except Exception:
                pass
            self.last_save_result = dict(result)

    save_mode = select_mode

    def reload_mode(self) -> Optional[int]:
        self.navigate_to_protocol_control()
        return self.get_mode()

    def verify_help_entries(
        self,
        expected_keywords: Iterable[str] = ("DPI", "审计"),
    ) -> Dict[str, Any]:
        keywords = [str(item) for item in expected_keywords if str(item)]
        icons = self.page.locator("span[aria-label='question-circle']:visible")
        entries = []
        for index in range(icons.count()):
            entry = {"opened": False, "text": "", "matched": [], "closed": False}
            try:
                icons.nth(index).hover()
                self.page.wait_for_timeout(300)
                tooltip = self.page.locator(
                    "[role='tooltip']:visible, .ant-tooltip:visible"
                ).last
                if tooltip.count() > 0:
                    entry["opened"] = True
                    entry["text"] = (tooltip.inner_text() or "").strip()
                    entry["matched"] = [
                        word for word in keywords if word.lower() in entry["text"].lower()
                    ]
                self.page.mouse.move(10, 10)
                self.page.wait_for_timeout(250)
                entry["closed"] = self.page.locator(
                    "[role='tooltip']:visible, .ant-tooltip:visible"
                ).count() == 0
            except Exception as exc:
                entry["error"] = type(exc).__name__
            entries.append(entry)
        return {
            "count": len(entries),
            "entries": entries,
            "all_opened": len(entries) == 2 and all(x["opened"] for x in entries),
            "all_closed": len(entries) == 2 and all(x["closed"] for x in entries),
            "content_complete": len(entries) == 2 and all(x["text"] for x in entries),
        }


__all__ = ["ProtocolControlPage"]
