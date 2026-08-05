"""设备设置 > 高级管理 > 内核设置 Page Object。

实机页面位于 ``/#/equipmentSetting/advancedManagement`` 的“内核设置”页签，
后端为单例 ``system/kernel-params``，前端调用 ``ik_sysctl`` 的
``show/save/default`` 动作。页面只提供十一个连接超时、TCP BBR、保存、
恢复默认和帮助，不存在列表型 CRUD 能力。
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Iterable, Optional

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage


class KernelSettingPage(BasePage):
    """iKuai 4.0 内核参数单例表单。"""

    MODULE_NAME = "kernel_setting"
    FUNC_NAME = "ik_sysctl"
    PAGE_URL = "/#/equipmentSetting/advancedManagement"
    BACKEND_SCRIPT = "/usr/ikuai/script/ik_sysctl.sh"

    TIMEOUT_FIELDS = (
        "syn_send_timeout",
        "syn_recv_timeout",
        "established_timeout",
        "fin_wait_timeout",
        "close_wait_timeout",
        "last_ack_timeout",
        "time_wait_timeout",
        "close_timeout",
        "udp_timeout",
        "udp_stream_timeout",
        "icmp_timeout",
    )
    BOOLEAN_FIELDS = ("bbr",)
    FIELD_NAMES = TIMEOUT_FIELDS + BOOLEAN_FIELDS
    FIELD_RANGES = {
        "syn_send_timeout": (5, 60),
        "syn_recv_timeout": (5, 60),
        "established_timeout": (600, 86400),
        "fin_wait_timeout": (5, 60),
        "close_wait_timeout": (5, 60),
        "last_ack_timeout": (5, 60),
        "time_wait_timeout": (5, 60),
        "close_timeout": (5, 60),
        "udp_timeout": (5, 60),
        "udp_stream_timeout": (30, 1800),
        "icmp_timeout": (5, 100),
    }
    DEFAULTS = {
        "bbr": False,
        "syn_send_timeout": 5,
        "syn_recv_timeout": 5,
        "established_timeout": 1800,
        "fin_wait_timeout": 10,
        "close_wait_timeout": 10,
        "last_ack_timeout": 10,
        "time_wait_timeout": 10,
        "close_timeout": 5,
        "udp_timeout": 10,
        "udp_stream_timeout": 60,
        "icmp_timeout": 20,
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url.rstrip("/")
        self.last_save_result: Dict[str, Any] = {}

    @staticmethod
    def _norm(value: Any) -> str:
        return re.sub(r"\s+", "", str(value or "")).lower()

    def _tab(self) -> Locator:
        tab = self.page.locator(".ant-tabs-tab:visible").filter(
            has_text="内核设置"
        )
        if tab.count() > 0:
            return tab.first
        return self.page.get_by_text("内核设置", exact=True).last

    def _field(self, name: str) -> Locator:
        if name not in self.FIELD_NAMES:
            return self.page.locator("[data-kernel-field-not-found='1']")
        exact = self.page.locator(f"#{name}")
        if exact.count() > 0:
            return exact.first
        return self.page.locator(f"[name='{name}']").first

    def _button(self, text: str) -> Locator:
        return self.page.locator("button:visible").filter(
            has_text=re.compile(rf"^\s*{re.escape(text)}\s*$")
        ).first

    def _is_kernel_request(self, request, action: Optional[str] = None) -> bool:
        try:
            payload = json.loads(request.post_data or "{}")
        except Exception:
            return False
        if str(payload.get("func_name") or "") != self.FUNC_NAME:
            return False
        return action is None or str(payload.get("action") or "") == action

    def navigate_to_kernel_setting(self) -> bool:
        try:
            self.page.goto(
                f"{self.base_url}{self.PAGE_URL}", wait_until="domcontentloaded"
            )
            tab = self._tab()
            tab.wait_for(state="visible", timeout=10000)
            tab.click()
            self.page.wait_for_selector("#syn_send_timeout", timeout=10000)
            self.page.wait_for_selector("#bbr", timeout=10000)
            self.page.wait_for_timeout(300)
            return self.is_on_kernel_setting_page()
        except Exception:
            return False

    navigate_to_kernel = navigate_to_kernel_setting

    def is_on_kernel_setting_page(self) -> bool:
        try:
            body = self.page.locator("body").inner_text(timeout=3000)
            return bool(
                "equipmentSetting/advancedManagement" in self.page.url
                and "连接设置" in body
                and "参数设置" in body
                and all(self._field(name).count() > 0 for name in self.FIELD_NAMES)
            )
        except Exception:
            return False

    def get_page_structure(self) -> Dict[str, Any]:
        buttons = [
            text.strip()
            for text in self.page.locator("button:visible").all_inner_texts()
            if text.strip()
        ]
        fields = {
            name: {
                "present": self._field(name).count() > 0,
                "enabled": (
                    self._field(name).is_enabled()
                    if self._field(name).count() > 0 else False
                ),
            }
            for name in self.FIELD_NAMES
        }
        return {
            "url": self.page.url,
            "singleton": True,
            "fields": fields,
            "buttons": buttons,
            "save_present": "保存" in buttons,
            "default_present": "恢复默认配置" in buttons,
            "help_present": "帮助" in buttons,
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

        no_list = "实机为sysctl id=1单例内核表单，无列表或记录级入口"
        return {
            "singleton_configuration_edit": item(
                all(field["present"] for field in structure["fields"].values()),
                "检测到十一个超时字段和TCP BBR开关",
            ),
            "save": item(structure["save_present"], "检测到保存入口"),
            "restore_default": item(
                structure["default_present"], "检测到恢复默认配置及二次确认入口"
            ),
            "help": item(structure["help_present"], "检测到帮助入口"),
            "cancel": item(False, "主表单无取消按钮；默认恢复弹窗提供取消"),
            "search": item(structure["search_present"], no_list),
            "add_record": item(False, no_list),
            "edit_record": item(False, no_list),
            "delete_record": item(False, no_list),
            "batch_operation": item(False, no_list),
            "import": item(False, no_list),
            "export": item(False, no_list),
            "sort": item(False, no_list),
            "pagination": item(structure["pagination_present"], no_list),
        }

    get_capabilities = get_capability_matrix

    def get_config(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "bbr": bool(
                self._field("bbr").count() > 0
                and self._field("bbr").is_checked()
            )
        }
        for name in self.TIMEOUT_FIELDS:
            field = self._field(name)
            if field.count() == 0:
                result[name] = None
                continue
            value = field.input_value().strip()
            try:
                result[name] = int(value)
            except (TypeError, ValueError):
                result[name] = value
        return result

    get_form_state = get_config

    def set_boolean(self, name: str, enabled: bool) -> bool:
        if name not in self.BOOLEAN_FIELDS:
            return False
        try:
            field = self._field(name)
            field.set_checked(bool(enabled), force=True)
            self.page.wait_for_timeout(80)
            return field.is_checked() is bool(enabled)
        except Exception:
            return False

    def fill_timeout(self, name: str, value: Any) -> bool:
        if name not in self.TIMEOUT_FIELDS:
            return False
        try:
            field = self._field(name)
            if field.count() == 0 or not field.is_enabled():
                return False
            expected = "" if value is None else str(value)
            field.fill(expected)
            field.evaluate(
                """el => {
                    el.dispatchEvent(new Event('input', {bubbles: true}));
                    el.dispatchEvent(new Event('change', {bubbles: true}));
                    el.dispatchEvent(new Event('blur', {bubbles: true}));
                }"""
            )
            self.page.wait_for_timeout(100)
            return field.input_value() == expected
        except Exception:
            return False

    def fill_config(self, values: Dict[str, Any]) -> Dict[str, bool]:
        checks: Dict[str, bool] = {}
        for name, value in dict(values or {}).items():
            if name in self.BOOLEAN_FIELDS:
                checks[name] = self.set_boolean(name, bool(value))
            elif name in self.TIMEOUT_FIELDS:
                checks[name] = self.fill_timeout(name, value)
        return checks

    def get_validation_errors(self) -> Dict[str, str]:
        errors: Dict[str, str] = {}
        for name in self.TIMEOUT_FIELDS:
            field = self._field(name)
            if field.count() == 0:
                continue
            item = field.locator(
                "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), "
                "' '), ' ant-form-item ')][1]"
            )
            messages = item.locator(
                ".ant-form-item-explain-error:visible, [role='alert']:visible"
            ) if item.count() > 0 else self.page.locator("[data-none='1']")
            if messages.count() > 0:
                errors[name] = (messages.first.inner_text() or "").strip()
                continue
            classes = " ".join(
                filter(None, (field.get_attribute("class"), item.get_attribute("class") if item.count() else ""))
            )
            if "status-error" in classes or "has-error" in classes:
                errors[name] = "字段校验失败（页面未提供错误文案）"
        return errors

    def save_config(
        self, values: Optional[Dict[str, Any]] = None, timeout: int = 12000
    ) -> Dict[str, Any]:
        fill_checks = self.fill_config(values or {})
        result: Dict[str, Any] = {
            "clicked": False,
            "fill_checks": fill_checks,
            "request_seen": False,
            "request_param": {},
            "response_seen": False,
            "http_status": None,
            "api_code": None,
            "api_success": False,
            "message": "",
            "validation_errors": {},
            "saved": False,
        }

        def observe_request(request):
            if not self._is_kernel_request(request, "save"):
                return
            result["request_seen"] = True
            try:
                payload = json.loads(request.post_data or "{}")
                result["request_param"] = dict(payload.get("param") or {})
            except Exception:
                pass

        def observe_response(response):
            if not self._is_kernel_request(response.request, "save"):
                return
            result["response_seen"] = True
            result["http_status"] = response.status
            try:
                payload = response.json()
            except Exception:
                payload = {}
            result["api_code"] = payload.get("code")
            result["message"] = str(payload.get("message") or "")[:240]
            result["api_success"] = bool(
                response.status == 200 and payload.get("code") == 0
            )

        self.page.on("request", observe_request)
        self.page.on("response", observe_response)
        try:
            button = self._button("保存")
            if button.count() == 0:
                result["message"] = "未找到内核设置保存按钮"
                return result
            button.click()
            result["clicked"] = True
            deadline = time.time() + timeout / 1000
            while time.time() < deadline:
                result["validation_errors"] = self.get_validation_errors()
                if result["validation_errors"] or result["response_seen"]:
                    break
                self.page.wait_for_timeout(100)
            result["validation_errors"] = self.get_validation_errors()
            result["saved"] = bool(
                result["request_seen"]
                and result["response_seen"]
                and result["api_success"]
                and not result["validation_errors"]
            )
            return result
        except Exception as exc:
            result["message"] = f"内核设置保存异常({type(exc).__name__})"
            return result
        finally:
            try:
                self.page.remove_listener("request", observe_request)
                self.page.remove_listener("response", observe_response)
            except Exception:
                pass
            self.last_save_result = dict(result)

    save_settings = save_config

    def api_show(self) -> Dict[str, Any]:
        return self.page.evaluate(
            """async () => {
                const response = await fetch('/Action/call', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        func_name: 'ik_sysctl', action: 'show',
                        param: {TYPE: 'data'}
                    })
                });
                return await response.json();
            }"""
        )

    def api_save(self, param: Dict[str, Any]) -> Dict[str, Any]:
        return self.page.evaluate(
            """async (param) => {
                const response = await fetch('/Action/call', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        func_name: 'ik_sysctl', action: 'save', param
                    })
                });
                return await response.json();
            }""",
            dict(param or {}),
        )

    @staticmethod
    def api_row(payload: Dict[str, Any]) -> Dict[str, Any]:
        rows = ((payload or {}).get("results") or {}).get("data") or []
        return dict(rows[0]) if rows else {}

    def restore_defaults(self, timeout: int = 12000) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "clicked": False,
            "confirmation_seen": False,
            "confirmation_accepted": False,
            "request_seen": False,
            "response_seen": False,
            "api_code": None,
            "api_success": False,
            "reloaded": False,
            "saved": False,
            "error": "",
        }

        def observe_request(request):
            if self._is_kernel_request(request, "default"):
                result["request_seen"] = True

        def observe_response(response):
            if not self._is_kernel_request(response.request, "default"):
                return
            result["response_seen"] = True
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
            self._button("恢复默认配置").click()
            result["clicked"] = True
            confirm = self.page.locator("button:visible").filter(
                has_text="确认"
            ).last
            confirm.wait_for(state="visible", timeout=5000)
            result["confirmation_seen"] = True
            confirm.click()
            result["confirmation_accepted"] = True
            deadline = time.time() + timeout / 1000
            while time.time() < deadline and not result["response_seen"]:
                self.page.wait_for_timeout(100)
            if result["api_success"]:
                self.page.wait_for_timeout(500)
                result["reloaded"] = self.get_config() == self.DEFAULTS
            result["saved"] = bool(
                result["confirmation_seen"]
                and result["confirmation_accepted"]
                and result["request_seen"]
                and result["api_success"]
                and result["reloaded"]
            )
            return result
        except Exception as exc:
            result["error"] = f"恢复默认配置异常({type(exc).__name__})"
            return result
        finally:
            try:
                self.page.remove_listener("request", observe_request)
                self.page.remove_listener("response", observe_response)
            except Exception:
                pass

    def reload_config(self) -> Dict[str, Any]:
        self.navigate_to_kernel_setting()
        return self.get_config()

    def verify_help_entry(
        self,
        expected_keywords: Iterable[str] = ("内核", "TCP"),
        timeout: int = 8000,
    ) -> Dict[str, Any]:
        keywords = [str(item) for item in expected_keywords if str(item)]
        result: Dict[str, Any] = {
            "clicked": False,
            "opened": False,
            "container": "",
            "matched_keywords": [],
            "all_keywords_matched": False,
            "closed": False,
            "no_orphan": False,
            "error": "",
        }
        context = self.page.context
        before_pages = list(context.pages)
        popup = None
        panel: Optional[Locator] = None
        try:
            button = self._button("帮助")
            if button.count() == 0:
                result["error"] = "未找到内核设置帮助入口"
                return result
            button.click(force=True, timeout=5000)
            result["clicked"] = True
            for _ in range(max(1, timeout // 100)):
                new_pages = [item for item in context.pages if item not in before_pages]
                if new_pages:
                    popup = new_pages[-1]
                    result.update({"opened": True, "container": "popup"})
                    break
                panels = self.page.locator(
                    ".ant-modal-content:visible, .ant-drawer-content:visible, "
                    "[role='dialog']:visible"
                )
                if panels.count() > 0:
                    panel = panels.last
                    result.update({"opened": True, "container": "in_page"})
                    break
                self.page.wait_for_timeout(100)

            searchable = ""
            if popup is not None:
                try:
                    popup.wait_for_load_state("domcontentloaded", timeout=4000)
                except Exception:
                    pass
                try:
                    searchable = " ".join(
                        (popup.url or "", popup.locator("body").inner_text(timeout=3000))
                    )
                except Exception:
                    searchable = popup.url or ""
            elif panel is not None:
                searchable = panel.inner_text() or ""
            result["matched_keywords"] = [
                word for word in keywords
                if self._norm(word) in self._norm(searchable)
            ]
            result["all_keywords_matched"] = bool(keywords) and len(
                result["matched_keywords"]
            ) == len(keywords)
        except Exception as exc:
            result["error"] = f"内核设置帮助验证异常({type(exc).__name__})"
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
                    if close.count() > 0:
                        close.first.click()
                    else:
                        self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(200)
                    result["closed"] = not panel.is_visible()
                except Exception:
                    pass
            result["no_orphan"] = all(
                candidate in before_pages for candidate in context.pages
            )
        return result


__all__ = ["KernelSettingPage"]
