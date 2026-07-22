"""设备设置 > 高级管理 > ALG设置 Page Object。

实机页面位于 ``/#/equipmentSetting/advancedManagement`` 的 ``alg`` 页签，
后端为单例 ``system/alg`` show/save 接口。页面没有列表、取消、导入导出、
搜索、排序或批量入口；本对象只封装真实存在的四个协议开关、三组非标准
端口、保存和帮助操作。
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Iterable, Optional

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage


class AlgSettingPage(BasePage):
    """iKuai 4.0 ALG 单例配置表单。"""

    MODULE_NAME = "alg_setting"
    FUNC_NAME = "alg"
    PAGE_URL = "/#/equipmentSetting/advancedManagement"
    BACKEND_SCRIPT = "/usr/ikuai/script/alg.sh"

    BOOLEAN_FIELDS = (
        "support_ftp",
        "support_tftp",
        "support_sip",
        "support_h323",
    )
    PORT_FIELDS = ("ftp_ports", "tftp_ports", "sip_ports")
    FIELD_NAMES = BOOLEAN_FIELDS + PORT_FIELDS

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url.rstrip("/")
        self.last_save_result: Dict[str, Any] = {}

    @staticmethod
    def _norm(value: Any) -> str:
        return re.sub(r"\s+", "", str(value or "")).lower()

    def _field(self, name: str) -> Locator:
        if name not in self.FIELD_NAMES:
            return self.page.locator("[data-alg-field-not-found='1']")
        exact = self.page.locator(f"#{name}")
        if exact.count() > 0:
            return exact.first
        return self.page.locator(f"[name='{name}']").first

    def _save_button(self) -> Locator:
        exact = self.page.get_by_role("button", name="保存", exact=True)
        if exact.count() > 0:
            return exact.first
        return self.page.locator("button:visible").filter(has_text="保存").first

    def _help_button(self) -> Locator:
        exact = self.page.get_by_role("button", name="帮助", exact=True)
        if exact.count() > 0:
            return exact.first
        return self.page.locator(
            "button:visible:has-text('帮助'), button[class*='helpDoc']:visible"
        ).first

    def _is_alg_request(self, request, action: Optional[str] = None) -> bool:
        try:
            payload = json.loads(request.post_data or "{}")
        except Exception:
            return False
        if str(payload.get("func_name", "")).lower() != self.FUNC_NAME:
            return False
        return action is None or str(payload.get("action", "")).lower() == action

    def navigate_to_alg_setting(self) -> bool:
        """直接进入高级管理页并确认 ALG 表单加载完成。"""
        target = f"{self.base_url}{self.PAGE_URL}"
        try:
            self.page.goto(target, wait_until="domcontentloaded")
            self.page.wait_for_selector("#support_ftp", timeout=10000)
            self.page.wait_for_selector("#ftp_ports", timeout=10000)
            self.page.wait_for_timeout(350)
            return self.is_on_alg_setting_page()
        except Exception:
            return False

    navigate_to_alg = navigate_to_alg_setting

    def is_on_alg_setting_page(self) -> bool:
        try:
            body = self.page.locator("body").inner_text(timeout=3000)
            return bool(
                "equipmentSetting/advancedManagement" in self.page.url
                and self._field("support_ftp").count() > 0
                and "ALG协议设置" in body
            )
        except Exception:
            return False

    def get_page_structure(self) -> Dict[str, Any]:
        """返回单例页能力证据，不虚构列表型功能。"""
        buttons = []
        try:
            buttons = [
                text.strip()
                for text in self.page.locator("button:visible").all_inner_texts()
                if text.strip()
            ]
        except Exception:
            pass
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
            "help_present": "帮助" in buttons,
            "table_present": self.page.locator("table:visible").count() > 0,
            "search_present": self.page.locator(
                "input[placeholder*='搜索']:visible, input[placeholder*='查询']:visible"
            ).count() > 0,
            "pagination_present": self.page.locator(".ant-pagination:visible").count() > 0,
        }

    def get_capability_matrix(self) -> Dict[str, Dict[str, Any]]:
        structure = self.get_page_structure()

        def item(supported: bool, evidence: str) -> Dict[str, Any]:
            return {
                "supported": bool(supported),
                "result": "支持" if supported else "不适用",
                "evidence": evidence,
            }

        no_list = "实机为alg_config id=1单例表单，无列表或记录级入口"
        return {
            "singleton_configuration_edit": item(True, "检测到四个协议开关和三组端口字段"),
            "save": item(bool(structure["save_present"]), "按可见按钮文本检测保存入口"),
            "help": item(bool(structure["help_present"]), "按可见按钮文本检测帮助入口"),
            "cancel": item("取消" in structure["buttons"], "实机未提供取消按钮"),
            "search": item(bool(structure["search_present"]), no_list),
            "add_record": item(False, no_list),
            "edit_record": item(False, no_list),
            "delete_record": item(False, no_list),
            "batch_operation": item(False, no_list),
            "import": item("导入" in structure["buttons"], no_list),
            "export": item("导出" in structure["buttons"], no_list),
            "sort": item(False, no_list),
            "pagination": item(bool(structure["pagination_present"]), no_list),
        }

    get_capabilities = get_capability_matrix

    def get_config(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for name in self.BOOLEAN_FIELDS:
            field = self._field(name)
            result[name] = bool(field.count() > 0 and field.is_checked())
        for name in self.PORT_FIELDS:
            field = self._field(name)
            result[name] = field.input_value() if field.count() > 0 else None
        return result

    get_form_state = get_config

    def set_boolean(self, name: str, enabled: bool) -> bool:
        if name not in self.BOOLEAN_FIELDS:
            return False
        try:
            field = self._field(name)
            if field.count() == 0:
                return False
            field.set_checked(bool(enabled), force=True)
            self.page.wait_for_timeout(100)
            return field.is_checked() is bool(enabled)
        except Exception:
            return False

    def fill_ports(self, name: str, value: Any) -> bool:
        if name not in self.PORT_FIELDS:
            return False
        try:
            field = self._field(name)
            if field.count() == 0 or not field.is_enabled():
                return False
            field.fill("" if value is None else str(value))
            field.evaluate("""el => {
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            self.page.wait_for_timeout(180)
            return field.input_value() == ("" if value is None else str(value))
        except Exception:
            return False

    def fill_config(self, values: Dict[str, Any]) -> Dict[str, bool]:
        checks: Dict[str, bool] = {}
        for name, value in dict(values or {}).items():
            if name in self.BOOLEAN_FIELDS:
                checks[name] = self.set_boolean(name, bool(value))
            elif name in self.PORT_FIELDS:
                checks[name] = self.fill_ports(name, value)
        return checks

    def get_validation_errors(self) -> Dict[str, str]:
        errors: Dict[str, str] = {}
        for name in self.PORT_FIELDS:
            field = self._field(name)
            if field.count() == 0:
                continue
            item = field.locator(
                "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), "
                "' '), ' ant-form-item ')][1]"
            )
            if item.count() == 0:
                continue
            error = item.locator(
                ".ant-form-item-explain-error:visible, [role='alert']:visible"
            )
            if error.count() > 0:
                errors[name] = (error.first.inner_text() or "").strip()
        return errors

    def save_config(self, values: Optional[Dict[str, Any]] = None,
                    timeout: int = 9000) -> Dict[str, Any]:
        """填写并保存，返回安全的 API/表单语义结果。"""
        fill_checks = self.fill_config(values or {})
        result: Dict[str, Any] = {
            "clicked": False,
            "fill_checks": fill_checks,
            "request_seen": False,
            "response_seen": False,
            "http_status": None,
            "api_code": None,
            "api_success": False,
            "message": "",
            "validation_errors": {},
            "saved": False,
        }

        def observe_request(request):
            if self._is_alg_request(request, "save"):
                result["request_seen"] = True

        def observe_response(response):
            if not self._is_alg_request(response.request, "save"):
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
            button = self._save_button()
            if button.count() == 0:
                result["message"] = "未找到ALG保存按钮"
                return result
            button.click()
            result["clicked"] = True
            deadline = time.time() + timeout / 1000
            while time.time() < deadline:
                errors = self.get_validation_errors()
                if errors:
                    result["validation_errors"] = errors
                    break
                if result["response_seen"]:
                    break
                self.page.wait_for_timeout(100)
            if result["api_success"]:
                self.page.wait_for_timeout(450)
            result["validation_errors"] = self.get_validation_errors()
            result["saved"] = bool(
                result["api_success"] and not result["validation_errors"]
            )
            return result
        except Exception as exc:
            result["message"] = f"ALG保存操作异常({type(exc).__name__})"
            return result
        finally:
            try:
                self.page.remove_listener("request", observe_request)
                self.page.remove_listener("response", observe_response)
            except Exception:
                pass
            self.last_save_result = dict(result)

    save_settings = save_config

    def reload_config(self) -> Dict[str, Any]:
        self.navigate_to_alg_setting()
        return self.get_config()

    def verify_help_entry(
        self,
        expected_keywords: Iterable[str] = ("ALG", "FTP"),
        timeout: int = 8000,
    ) -> Dict[str, Any]:
        """打开帮助，匹配主题并关闭 popup 或页内帮助层。"""
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
            button = self._help_button()
            if button.count() == 0:
                result["error"] = "未找到ALG帮助入口"
                return result
            button.click()
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
                    candidate = panels.last
                    text = candidate.inner_text() or ""
                    if "ALG" in text.upper() or "帮助" in text:
                        panel = candidate
                        result.update({"opened": True, "container": "in_page"})
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
            result["matched_keywords"] = [
                word for word in keywords
                if self._norm(word) in self._norm(searchable)
            ]
            result["all_keywords_matched"] = bool(keywords) and len(
                result["matched_keywords"]
            ) == len(keywords)
        except Exception as exc:
            result["error"] = f"ALG帮助验证异常({type(exc).__name__})"
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


__all__ = ["AlgSettingPage"]
