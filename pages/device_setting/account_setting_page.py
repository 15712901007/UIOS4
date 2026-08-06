"""设备设置 > 登录管理 > 账号设置 Page Object。

页面使用 ``webuser`` 与 ``usergroup`` 两个后端模块。新增或复制账号时先
创建同名权限组，再写入账号；编辑、启停和删除也会联动这两个对象。帮助
入口位于页面右下角并打开爱快官网的新标签页。
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Iterable, List, Optional

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage
from pages.login_page import LoginPage


class AccountSettingPage(BasePage):
    """账号设置列表、表单、批量操作和真实登录验证。"""

    MODULE_NAME = "account_setting"
    FUNC_NAME = "webuser"
    GROUP_FUNC_NAME = "usergroup"
    LIST_URL = "/#/equipmentSetting/loginManagement"
    ADD_URL = "/#/equipmentSetting/loginManagement/AccountSetting/add"
    EDIT_URL = "/#/equipmentSetting/loginManagement/AccountSetting/edit"
    HELP_ARTICLE_ID = "119"
    BACKEND_SCRIPT = "/usr/ikuai/script/webuser.sh"
    GROUP_SCRIPT = "/usr/ikuai/script/usergroup.sh"

    USERNAME_MAX_LENGTH = 128
    SESSION_TIMEOUT_RANGE = (5, 999)
    PASSWORD_CYCLE_RANGE = (1, 999)
    DEFAULT_PERMISSION_OPTIONS = {
        "新功能不可见": "none",
        "新功能可见": "r",
        "新功能可读写": "rx",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url.rstrip("/")

    @staticmethod
    def _exact(text: str) -> re.Pattern:
        return re.compile(rf"^\s*{re.escape(text)}\s*$")

    @staticmethod
    def _redact_param(param: Dict[str, Any]) -> Dict[str, Any]:
        result = {}
        for key, value in dict(param or {}).items():
            if "pass" in str(key).lower():
                result[key] = "[已隐藏]"
            elif key == "perm_config":
                result[key] = f"[{len([item for item in str(value).split(',') if item])}项权限]"
            else:
                result[key] = value
        return result

    def _button(self, text: str, root: Optional[Locator] = None) -> Locator:
        scope = root if root is not None else self.page.locator("body")
        return scope.locator("button:visible").filter(has_text=self._exact(text))

    def _field(self, field_id: str) -> Locator:
        return self.page.locator(f"#{field_id}").first

    def _rows(self) -> Locator:
        return self.page.locator(".ant-table-row:visible")

    def _row(self, username: str) -> Optional[Locator]:
        expected = str(username)
        rows = self._rows()
        for index in range(rows.count()):
            row = rows.nth(index)
            cell = row.locator("#username")
            text = (cell.inner_text() if cell.count() else row.inner_text()).strip()
            if text == expected or text.splitlines()[0].strip() == expected:
                return row
        return None

    def navigate_to_account_setting(self) -> bool:
        try:
            self.page.goto(
                f"{self.base_url}{self.LIST_URL}", wait_until="domcontentloaded"
            )
            self.page.get_by_text("账号设置", exact=True).wait_for(
                state="visible", timeout=10000
            )
            self.page.locator(".ant-table-row, .ant-empty").first.wait_for(
                state="visible", timeout=10000
            )
            self.page.wait_for_timeout(300)
            return self.is_on_account_setting_page()
        except Exception:
            return False

    navigate_to_account = navigate_to_account_setting

    def is_on_account_setting_page(self) -> bool:
        try:
            body = self.page.locator("body").inner_text(timeout=3000)
            return bool(
                "equipmentSetting/loginManagement" in self.page.url
                and "/AccountSetting/" not in self.page.url
                and "账号设置" in body
                and "用户名" in body
                and "权限组" in body
                and "允许访问IP" in body
            )
        except Exception:
            return False

    def is_on_form_page(self) -> bool:
        return "/AccountSetting/" in self.page.url and self._field("username").count() > 0

    def get_page_structure(self) -> Dict[str, Any]:
        buttons = [
            text.strip()
            for text in self.page.locator("button:visible").all_inner_texts()
            if text.strip()
        ]
        columns = [
            text.strip()
            for text in self.page.locator(".ant-table-thead:visible").all_inner_texts()
            if text.strip()
        ]
        help_button = self._button("帮助")
        help_box = help_button.first.bounding_box() if help_button.count() else None
        viewport = self.page.viewport_size or self.page.evaluate(
            "() => ({width: window.innerWidth, height: window.innerHeight})"
        )
        return {
            "url": self.page.url,
            "buttons": buttons,
            "columns": columns,
            "add_present": "添加" in buttons,
            "edit_present": "编辑" in buttons,
            "search_present": self.page.locator(
                "input[placeholder='请输入搜索内容']:visible"
            ).count() > 0,
            "selection_present": self.page.locator(
                ".ant-table-selection-column input[type='checkbox']"
            ).count() > 0,
            "help_present": help_button.count() > 0,
            "help_box": help_box,
            "viewport": viewport,
            "pagination_present": self.page.locator(
                ".ant-pagination:visible"
            ).count() > 0,
            "admin_present": self.account_exists("admin"),
        }

    def get_capability_matrix(self) -> Dict[str, Dict[str, Any]]:
        structure = self.get_page_structure()

        def item(supported: bool, evidence: str) -> Dict[str, Any]:
            return {
                "supported": bool(supported),
                "result": "支持" if supported else "不适用",
                "evidence": evidence,
            }

        return {
            "add": item(structure["add_present"], "列表提供添加入口"),
            "edit": item(structure["edit_present"], "账号行提供编辑入口"),
            "search": item(structure["search_present"], "列表提供账号搜索框"),
            "enable_disable": item(True, "普通账号行提供启用/停用入口"),
            "delete": item(True, "普通账号行提供删除入口，admin受保护"),
            "copy": item(True, "普通账号行提供复制入口"),
            "batch_operation": item(
                structure["selection_present"], "复选账号后提供批量启用/停用/删除"
            ),
            "permission": item(True, "表单提供访问/修改两级页面权限"),
            "ip_restriction": item(True, "表单提供允许访问IP"),
            "session_timeout": item(True, "表单提供5-999分钟会话超时"),
            "password_cycle": item(True, "表单提供1-999天周期修改密码"),
            "help": item(structure["help_present"], "右下角帮助打开官方文档"),
            "import": item(False, "当前4.0账号设置页面未暴露导入入口"),
            "export": item(False, "当前4.0账号设置页面未暴露导出入口"),
        }

    get_capabilities = get_capability_matrix

    def get_usernames(self) -> List[str]:
        names: List[str] = []
        rows = self._rows()
        for index in range(rows.count()):
            cell = rows.nth(index).locator("#username")
            if cell.count():
                text = cell.inner_text().strip()
                if text:
                    names.append(text)
        return names

    def account_exists(self, username: str) -> bool:
        return self._row(username) is not None

    def get_account_state(self, username: str) -> Optional[str]:
        row = self._row(username)
        if row is None:
            return None
        if row.locator("[aria-label='play-circle']").count() > 0:
            return "enabled"
        if row.locator(
            "[aria-label='pause-circle'], [aria-label='stop']"
        ).count() > 0:
            return "disabled"
        text = row.inner_text()
        if "启用" in text and "停用" not in text:
            return "disabled"
        if "停用" in text:
            return "enabled"
        return "unknown"

    def get_account_actions(self, username: str) -> List[str]:
        row = self._row(username)
        if row is None:
            return []
        return [
            item.strip() for item in row.locator("button:visible").all_inner_texts()
            if item.strip()
        ]

    def search_account(self, keyword: str) -> List[str]:
        field = self.page.locator(
            "input[placeholder='请输入搜索内容']:visible"
        ).first
        field.fill(str(keyword))
        field.press("Enter")
        self.page.wait_for_timeout(500)
        return self.get_usernames()

    def clear_search(self) -> List[str]:
        return self.search_account("")

    def open_add_page(self) -> bool:
        try:
            if not self.is_on_account_setting_page() and not self.navigate_to_account_setting():
                return False
            self._button("添加").first.click()
            self.page.wait_for_url("**/AccountSetting/add", timeout=8000)
            for field_id in (
                "username", "password", "confirm_password", "ip_addr",
                "default_permission", "session_timeout",
            ):
                self._field(field_id).wait_for(state="attached", timeout=8000)
            self.page.wait_for_timeout(250)
            return self.is_on_form_page()
        except Exception:
            return False

    def _open_row_action(self, username: str, action: str) -> bool:
        try:
            row = self._row(username)
            if row is None:
                return False
            button = self._button(action, row)
            if button.count() == 0:
                return False
            button.first.click()
            if action in {"编辑", "复制"}:
                self.page.wait_for_url("**/AccountSetting/*", timeout=8000)
                self._field("username").wait_for(state="visible", timeout=8000)
                self._field("password").wait_for(state="attached", timeout=8000)
                self._field("confirm_password").wait_for(
                    state="attached", timeout=8000
                )
                self.page.wait_for_timeout(250)
            return True
        except Exception:
            return False

    def open_edit_page(self, username: str) -> bool:
        return self._open_row_action(username, "编辑")

    def open_copy_page(self, username: str) -> bool:
        return self._open_row_action(username, "复制")

    def get_form_structure(self) -> Dict[str, Any]:
        fields = {
            field_id: self._field(field_id).count() > 0
            for field_id in (
                "username", "password", "confirm_password", "ip_addr",
                "default_permission", "session_timeout",
            )
        }
        labels = self.page.locator("label:visible").all_inner_texts()
        return {
            "url": self.page.url,
            "fields": fields,
            "save_present": self._button("保存").count() > 0,
            "cancel_present": self._button("取消").count() > 0,
            "force_present": any("开启周期修改密码" in item for item in labels),
            "permission_access_count": sum(item.strip() == "访问" for item in labels),
            "permission_modify_count": sum(item.strip() == "修改" for item in labels),
        }

    def get_form_state(self) -> Dict[str, Any]:
        def value(field_id: str) -> str:
            field = self._field(field_id)
            return field.input_value().strip() if field.count() else ""

        force = False
        force_input = self.page.locator("label:visible").filter(
            has_text=self._exact("开启周期修改密码")
        ).locator("input[type='checkbox']")
        if force_input.count():
            force = force_input.first.is_checked()
        default_text = ""
        selected = self.page.locator(
            ".ant-select:visible"
        ).filter(has=self._field("default_permission")).locator(
            ".ant-select-selection-item"
        )
        if selected.count():
            default_text = selected.first.inner_text().strip()
        return {
            "username": value("username"),
            "ip_addr": value("ip_addr"),
            "session_timeout": value("session_timeout"),
            "force": force,
            "password_cycle": value("password_cycle"),
            "default_permission": default_text,
            "password_filled": bool(value("password")),
            "confirm_password_filled": bool(value("confirm_password")),
        }

    def set_default_permission(self, option: str) -> bool:
        try:
            container = self.page.locator(".ant-select:visible").filter(
                has=self._field("default_permission")
            ).first
            container.click(force=True)
            choice = self.page.locator(
                ".ant-select-item-option:visible"
            ).filter(has_text=self._exact(option))
            choice.first.click()
            return option in self.get_form_state()["default_permission"]
        except Exception:
            return False

    def get_default_permission_options(self) -> List[str]:
        """返回默认权限下拉框中实际可选的三个兼容策略。"""
        try:
            container = self.page.locator(".ant-select:visible").filter(
                has=self._field("default_permission")
            ).first
            container.click(force=True)
            options = self.page.locator(".ant-select-item-option:visible")
            options.first.wait_for(state="visible", timeout=3000)
            values = [item.strip() for item in options.all_inner_texts() if item.strip()]
            self.page.keyboard.press("Escape")
            return values
        except Exception:
            return []

    def set_password_cycle(self, enabled: bool, days: Optional[Any] = None) -> bool:
        label = self.page.locator("label:visible").filter(
            has_text=self._exact("开启周期修改密码")
        ).first
        checkbox = label.locator("input[type='checkbox']")
        if checkbox.count() == 0:
            return False
        try:
            current = checkbox.is_checked()
            if current != bool(enabled):
                label.click()
                self.page.wait_for_timeout(150)
                modal = self.page.locator(".ant-modal-content:visible")
                if modal.count():
                    confirm = modal.locator("button.ant-btn-primary:visible")
                    if confirm.count():
                        confirm.last.click()
                        self.page.wait_for_timeout(200)
            if enabled and days is not None:
                cycle = self._field("password_cycle")
                cycle.wait_for(state="visible", timeout=3000)
                cycle.fill(str(days))
                cycle.press("Tab")
            return checkbox.is_checked() is bool(enabled)
        except Exception:
            return False

    def set_permission(self, level: str = "read") -> bool:
        """设置全页面权限。``read``=只读，``write``=可修改。"""
        level = str(level).strip().lower()
        access_labels = self.page.locator("label:visible").filter(
            has_text=self._exact("访问")
        )
        modify_labels = self.page.locator("label:visible").filter(
            has_text=self._exact("修改")
        )
        if access_labels.count() == 0 or modify_labels.count() == 0:
            return False
        try:
            access = access_labels.first.locator("input[type='checkbox']")
            modify = modify_labels.first.locator("input[type='checkbox']")
            if level in {"read", "write"} and not access.is_checked():
                access_labels.first.click()
                self.page.wait_for_timeout(150)
            if level == "write" and not modify.is_checked():
                modify_labels.first.click()
                self.page.wait_for_timeout(150)
            if level == "read" and modify.is_checked():
                modify_labels.first.click()
                self.page.wait_for_timeout(150)
            if level == "none":
                if modify.is_checked():
                    modify_labels.first.click()
                if access.is_checked():
                    access_labels.first.click()
                self.page.wait_for_timeout(150)
            return (
                (level == "read" and access.is_checked() and not modify.is_checked())
                or (level == "write" and access.is_checked() and modify.is_checked())
                or (level == "none" and not access.is_checked() and not modify.is_checked())
            )
        except Exception:
            return False

    def fill_account_form(
        self,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        confirm_password: Optional[str] = None,
        ip_addr: Optional[str] = None,
        session_timeout: Optional[Any] = None,
        force: Optional[bool] = None,
        password_cycle: Optional[Any] = None,
        permission: Optional[str] = None,
        default_permission: Optional[str] = None,
    ) -> Dict[str, bool]:
        checks: Dict[str, bool] = {}
        values = {
            "username": username,
            "password": password,
            "confirm_password": confirm_password,
            "ip_addr": ip_addr,
            "session_timeout": session_timeout,
        }
        for field_id, field_value in values.items():
            if field_value is None:
                continue
            try:
                field = self._field(field_id)
                field.fill(str(field_value))
                field.press("Tab")
                checks[field_id] = field.input_value() == str(field_value)
            except Exception:
                checks[field_id] = False
        if default_permission is not None:
            checks["default_permission"] = self.set_default_permission(
                default_permission
            )
        if force is not None:
            checks["force"] = self.set_password_cycle(force, password_cycle)
        if permission is not None:
            checks["permission"] = self.set_permission(permission)
        return checks

    def get_validation_errors(self) -> List[str]:
        errors = [
            item.strip()
            for item in self.page.locator(
                ".ant-form-item-explain-error:visible, [role='alert']:visible"
            ).all_inner_texts()
            if item.strip()
        ]
        for item in self.page.locator(
            ".ant-message-error:visible, .ant-notification-notice-error:visible"
        ).all_inner_texts():
            if item.strip() and item.strip() not in errors:
                errors.append(item.strip())
        return errors

    def save_form(self, timeout: int = 25000) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "clicked": False,
            "requests": [],
            "responses": [],
            "validation_errors": [],
            "saved": False,
            "final_url": self.page.url,
        }

        def request_handler(request):
            if request.method != "POST" or not request.post_data:
                return
            try:
                payload = json.loads(request.post_data)
            except Exception:
                return
            if payload.get("func_name") not in {self.FUNC_NAME, self.GROUP_FUNC_NAME}:
                return
            result["requests"].append({
                "func_name": payload.get("func_name"),
                "action": payload.get("action"),
                "param": self._redact_param(payload.get("param") or {}),
            })

        def response_handler(response):
            request = response.request
            if request.method != "POST" or not request.post_data:
                return
            try:
                request_payload = json.loads(request.post_data)
            except Exception:
                return
            if request_payload.get("func_name") not in {
                self.FUNC_NAME, self.GROUP_FUNC_NAME
            }:
                return
            try:
                payload = response.json()
            except Exception:
                payload = {}
            result["responses"].append({
                "func_name": request_payload.get("func_name"),
                "action": request_payload.get("action"),
                "http_status": response.status,
                "code": payload.get("code"),
                "message": str(payload.get("message") or "")[:200],
            })

        self.page.on("request", request_handler)
        self.page.on("response", response_handler)
        try:
            button = self._button("保存")
            if button.count() == 0:
                result["validation_errors"] = ["未找到保存按钮"]
                return result
            button.first.click()
            result["clicked"] = True
            deadline = time.time() + timeout / 1000
            while time.time() < deadline:
                result["validation_errors"] = self.get_validation_errors()
                if self.is_on_account_setting_page() or result["validation_errors"]:
                    break
                if any(item.get("code") not in (None, 0) for item in result["responses"]):
                    break
                self.page.wait_for_timeout(100)
            result["final_url"] = self.page.url
            result["validation_errors"] = self.get_validation_errors()
            mutating = [
                item for item in result["responses"]
                if item.get("action") in {"add", "edit"}
            ]
            result["saved"] = bool(
                self.is_on_account_setting_page()
                and len(mutating) >= 2
                and all(item.get("http_status") == 200 and item.get("code") == 0 for item in mutating)
                and not result["validation_errors"]
            )
            if result["saved"]:
                try:
                    self.page.locator(".ant-table-row, .ant-empty").first.wait_for(
                        state="visible", timeout=5000
                    )
                    self.page.wait_for_timeout(600)
                except Exception:
                    pass
            return result
        except Exception as exc:
            result["validation_errors"] = [
                f"账号保存异常({type(exc).__name__})"
            ]
            return result
        finally:
            try:
                self.page.remove_listener("request", request_handler)
                self.page.remove_listener("response", response_handler)
            except Exception:
                pass

    def add_account(self, **values) -> Dict[str, Any]:
        if not self.open_add_page():
            return {"saved": False, "validation_errors": ["无法进入新增账号页面"]}
        fill_checks = self.fill_account_form(**values)
        result = self.save_form()
        result["fill_checks"] = fill_checks
        return result

    def edit_account(self, username: str, **values) -> Dict[str, Any]:
        if not self.navigate_to_account_setting() or not self.open_edit_page(username):
            return {"saved": False, "validation_errors": ["无法进入编辑账号页面"]}
        fill_checks = self.fill_account_form(**values)
        result = self.save_form()
        result["fill_checks"] = fill_checks
        return result

    def copy_account(self, source_username: str, **values) -> Dict[str, Any]:
        if not self.navigate_to_account_setting() or not self.open_copy_page(source_username):
            return {"saved": False, "validation_errors": ["无法进入复制账号页面"]}
        result: Dict[str, Any] = {"copy_source_state": self.get_form_state()}
        result["fill_checks"] = self.fill_account_form(**values)
        result.update(self.save_form())
        return result

    def _confirm_visible_modal(self) -> bool:
        modal = self.page.locator(".ant-modal-content:visible")
        if modal.count() == 0:
            return True
        primary = modal.last.locator("button.ant-btn-primary:visible")
        if primary.count() == 0:
            return False
        primary.last.click()
        return True

    def _operation_success_toast(self) -> str:
        messages = self.page.locator(
            ".ant-message-success:visible, .ant-notification-notice-success:visible"
        )
        if messages.count() == 0:
            return ""
        return "\n".join(
            item.strip() for item in messages.all_inner_texts() if item.strip()
        )

    def account_action(self, username: str, action: str) -> Dict[str, Any]:
        result = {"clicked": False, "confirmed": False, "success": False}
        if not self.navigate_to_account_setting():
            return result
        row = self._row(username)
        if row is None:
            return result
        button = self._button(action, row)
        if button.count() == 0:
            return result
        try:
            button.first.click()
            result["clicked"] = True
            self.page.wait_for_timeout(150)
            result["confirmed"] = self._confirm_visible_modal()
            self.page.wait_for_timeout(900)
            result["success_toast"] = self._operation_success_toast()
            if action == "删除":
                result["success"] = "成功" in result["success_toast"]
                try:
                    if self.account_exists(username):
                        self.page.reload(wait_until="domcontentloaded")
                        self.page.wait_for_timeout(1800)
                    result["list_disappeared"] = not self.account_exists(username)
                    result["success"] = bool(
                        result["success"] or result["list_disappeared"]
                    )
                except Exception:
                    if not result["success"]:
                        raise
            elif action == "停用":
                result["success"] = self.get_account_state(username) == "disabled"
            elif action == "启用":
                result["success"] = self.get_account_state(username) == "enabled"
            return result
        except Exception:
            return result

    def disable_account(self, username: str) -> Dict[str, Any]:
        return self.account_action(username, "停用")

    def enable_account(self, username: str) -> Dict[str, Any]:
        return self.account_action(username, "启用")

    def delete_account(self, username: str) -> Dict[str, Any]:
        return self.account_action(username, "删除")

    def batch_action(self, usernames: Iterable[str], action: str) -> Dict[str, Any]:
        selected: List[str] = []
        result = {"selected": selected, "clicked": False, "success": False}
        if not self.navigate_to_account_setting():
            return result
        for username in usernames:
            checkbox = self.page.locator(f"input[name='{username}']")
            if checkbox.count():
                checkbox.first.check(force=True)
                selected.append(str(username))
        if not selected:
            return result
        self.page.wait_for_timeout(400)
        toolbar = self.page.locator("button:visible").filter(
            has_text=self._exact(action)
        )
        row_buttons = sum(
            self._button(action, self._row(name)).count()
            for name in selected if self._row(name) is not None
        )
        if toolbar.count() <= row_buttons:
            return result
        button = toolbar.nth(toolbar.count() - 1)
        try:
            button.click()
            result["clicked"] = True
            self.page.wait_for_timeout(150)
            self._confirm_visible_modal()
            self.page.wait_for_timeout(900)
            result["success_toast"] = self._operation_success_toast()
            if action == "删除":
                result["success"] = "成功" in result["success_toast"]
                try:
                    if any(self.account_exists(name) for name in selected):
                        self.page.reload(wait_until="domcontentloaded")
                        self.page.wait_for_timeout(1800)
                    result["list_disappeared"] = all(
                        not self.account_exists(name) for name in selected
                    )
                    result["success"] = bool(
                        result["success"] or result["list_disappeared"]
                    )
                except Exception:
                    if not result["success"]:
                        raise
            elif action == "停用":
                result["success"] = all(
                    self.get_account_state(name) == "disabled" for name in selected
                )
            elif action == "启用":
                result["success"] = all(
                    self.get_account_state(name) == "enabled" for name in selected
                )
            return result
        except Exception:
            return result

    def api_call(self, func_name: str, action: str, param: Dict[str, Any]) -> Dict[str, Any]:
        return self.page.evaluate(
            """async ({funcName, action, param}) => {
                const response = await fetch('/Action/call', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({func_name: funcName, action, param})
                });
                return await response.json();
            }""",
            {"funcName": func_name, "action": action, "param": dict(param or {})},
        )

    def api_accounts(self) -> Dict[str, Any]:
        payload = self.api_call(
            self.FUNC_NAME,
            "show",
            {"TYPE": "total,data", "limit": "0,100", "ORDER_BY": "", "ORDER": ""},
        )
        results = dict((payload or {}).get("results") or {})
        safe_rows = []
        for row in results.get("data") or []:
            safe_rows.append({
                key: value for key, value in dict(row).items()
                if key not in {"passwd", "feature_notice_state"}
            })
        return {
            "code": payload.get("code"),
            "message": payload.get("message"),
            "total": results.get("total"),
            "data": safe_rows,
        }

    def attempt_login(self, username: str, password: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "success": False,
            "api_code": None,
            "api_result": None,
            "message": "",
            "final_url": "",
        }
        browser = self.page.context.browser
        if browser is None:
            result["message"] = "当前浏览器上下文不能创建隔离登录会话"
            return result
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        login_page = context.new_page()

        def response_handler(response):
            if response.url.endswith("/Action/login"):
                try:
                    payload = response.json()
                except Exception:
                    payload = {}
                result["api_code"] = payload.get("code")
                result["api_result"] = payload.get("Result")
                result["message"] = str(payload.get("message") or "")[:200]

        login_page.on("response", response_handler)
        try:
            result["success"] = LoginPage(login_page, self.base_url).login(
                username, password
            )
            login_page.wait_for_timeout(300)
            result["final_url"] = login_page.url
            if not result["message"]:
                error = LoginPage(login_page, self.base_url).get_login_error()
                result["message"] = str(error or "")[:200]
            return result
        except Exception as exc:
            result["message"] = f"隔离登录异常({type(exc).__name__})"
            result["final_url"] = login_page.url
            return result
        finally:
            context.close()

    def verify_restricted_account(self, username: str, password: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "login_success": False,
            "list_opened": False,
            "add_hidden": False,
            "only_self_visible": False,
            "admin_api_rejected": False,
            "visible_usernames": [],
            "error": "",
        }
        browser = self.page.context.browser
        if browser is None:
            result["error"] = "当前浏览器上下文不能创建隔离权限会话"
            return result
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        target = context.new_page()
        try:
            result["login_success"] = LoginPage(target, self.base_url).login(
                username, password
            )
            if not result["login_success"]:
                return result
            target.goto(f"{self.base_url}{self.LIST_URL}", wait_until="domcontentloaded")
            target.wait_for_timeout(1200)
            body = target.locator("body").inner_text()
            result["list_opened"] = "账号设置" in body
            result["add_hidden"] = target.locator("button:visible").filter(
                has_text=self._exact("添加")
            ).count() == 0
            rows = target.locator(".ant-table-row:visible")
            names = []
            for index in range(rows.count()):
                cell = rows.nth(index).locator("#username")
                if cell.count():
                    names.append(cell.inner_text().strip())
            result["visible_usernames"] = names
            # Some permission combinations hide the account table completely;
            # others show only the current account. Both satisfy data isolation.
            result["only_self_visible"] = all(name == username for name in names)
            response = target.evaluate(
                """async () => {
                    const res = await fetch('/Action/call', {
                        method: 'POST', headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            func_name: 'usergroup', action: 'del', param: {id: 1}
                        })
                    });
                    return await res.json();
                }"""
            )
            result["admin_api_rejected"] = response.get("code") != 0
            return result
        except Exception as exc:
            result["error"] = f"受限账号验证异常({type(exc).__name__})"
            return result
        finally:
            context.close()

    def verify_help_entry(
        self,
        expected_keywords: Iterable[str] = ("账号设置", "允许访问IP", "登录状态超时时间"),
        timeout: int = 12000,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "button_present": False,
            "bottom_right": False,
            "tooltip_opened": False,
            "tooltip_text": "",
            "tooltip_matched": False,
            "opened": False,
            "url": "",
            "title": "",
            "keywords_matched": [],
            "all_keywords_matched": False,
            "closed": False,
            "no_orphan": False,
            "error": "",
        }
        if not self.navigate_to_account_setting():
            result["error"] = "无法进入账号设置列表"
            return result
        button = self._button("帮助")
        if button.count() == 0:
            result["error"] = "未找到右下角帮助入口"
            return result
        result["button_present"] = True
        box = button.first.bounding_box() or {}
        viewport = self.page.viewport_size or self.page.evaluate(
            "() => ({width: window.innerWidth, height: window.innerHeight})"
        )
        result["bottom_right"] = bool(
            box and viewport
            and box.get("x", 0) > viewport.get("width", 0) / 2
            and box.get("y", 0) > viewport.get("height", 0) / 2
        )
        context = self.page.context
        before_pages = list(context.pages)
        popup = None
        try:
            button.first.hover()
            self.page.wait_for_timeout(250)
            described_by = button.first.get_attribute("aria-describedby") or ""
            tooltip = self.page.locator(f"#{described_by}") if described_by else self.page.locator(
                ".ant-tooltip:visible"
            )
            if tooltip.count() and tooltip.first.is_visible():
                result["tooltip_opened"] = True
                result["tooltip_text"] = tooltip.first.inner_text().strip()
                result["tooltip_matched"] = all(
                    word in result["tooltip_text"] for word in ("管理", "用户", "权限")
                )
            button.first.click(no_wait_after=True)
            deadline = time.time() + timeout / 1000
            while time.time() < deadline:
                new_pages = [item for item in context.pages if item not in before_pages]
                if new_pages:
                    popup = new_pages[-1]
                    break
                self.page.wait_for_timeout(100)
            if popup is None:
                result["error"] = "帮助未打开新标签页"
                return result
            result["opened"] = True
            try:
                popup.wait_for_load_state("domcontentloaded", timeout=timeout)
            except Exception:
                pass
            result["url"] = popup.url
            result["title"] = popup.title()
            body = popup.locator("body").inner_text(timeout=8000)
            result["keywords_matched"] = [
                word for word in expected_keywords if str(word) in body
            ]
            result["all_keywords_matched"] = bool(
                self.HELP_ARTICLE_ID in popup.url
                and len(result["keywords_matched"]) == len(list(expected_keywords))
            )
            popup.close()
            result["closed"] = popup.is_closed()
            self.page.bring_to_front()
            self.page.wait_for_timeout(200)
            result["no_orphan"] = all(
                item in before_pages or item.is_closed() for item in context.pages
            )
            return result
        except Exception as exc:
            result["error"] = f"账号设置帮助验证异常({type(exc).__name__})"
            return result
        finally:
            if popup is not None and not popup.is_closed():
                try:
                    popup.close()
                except Exception:
                    pass
