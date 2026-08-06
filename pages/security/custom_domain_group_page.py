"""网址浏览控制 > 自定义网址库页面对象。"""

from typing import Any, Dict, Iterable, List

from playwright.sync_api import Page

from pages.security.url_black_page import UrlBlackPage


class CustomDomainGroupPage(UrlBlackPage):
    """自定义网址分类的列表、表单、系统网址查询和帮助入口。"""

    MODULE_NAME = "custom_domain_group"
    IMPORT_REQUIRES_CLEAR_GUARD = True
    HELP_ARTICLE_ID = "185"
    LIST_URL = "/login#/securityCenter/urlAccessControl"
    ADD_URL = "/login#/securityCenter/urlAccessControl/urlLibrary/add"
    CONFIG_PATH = "/urlAccessControl/urlLibrary/"
    COLUMN_ID_MAP = {
        "名称": "tagname",
        "类别": "type",
        "域名": "domains",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    def _switch_to_custom_tab(self) -> bool:
        try:
            return bool(self.page.evaluate(
                """target => {
                    const tabs = [...document.querySelectorAll(
                        '[role=tab], .ant-tabs-tab'
                    )];
                    const tab = tabs.find(node =>
                        node.offsetParent !== null &&
                        (node.textContent || '').trim() === target
                    );
                    if (!tab) return false;
                    if (!tab.classList.contains('ant-tabs-tab-active')) tab.click();
                    return true;
                }""",
                "自定义网址库",
            ))
        except Exception:
            return False

    def navigate_to_custom_domain_group(self):
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(1600)
        if not self._switch_to_custom_tab():
            raise RuntimeError("未找到自定义网址库页签")
        self.page.wait_for_timeout(800)
        return self

    # The inherited help verifier invokes this method dynamically.
    def navigate_to_url_black(self):
        return self.navigate_to_custom_domain_group()

    def open_add_page(self) -> bool:
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        # React does not remount when navigating from add back to the same hash.
        # Leave the form first so validation probes cannot leak controlled values.
        if self.CONFIG_PATH in self.page.url:
            self.page.goto(f"{self.base_url}{self.LIST_URL}")
            self.page.wait_for_timeout(450)
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(1400)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        return bool(
            self.CONFIG_PATH in self.page.url
            and ("/add" in self.page.url or "/edit" in self.page.url)
            and self.page.locator("#tagname").count() > 0
            and self.page.locator("#domains").count() > 0
        )

    def is_still_on_config_page(self) -> bool:
        return self.CONFIG_PATH in self.page.url

    def fill_library_name(self, name: str) -> bool:
        try:
            field = self.page.locator("#tagname")
            field.fill(str(name))
            return field.input_value() == str(name)
        except Exception:
            return False

    def fill_domains(self, domains: Iterable[str]) -> bool:
        values = [str(domain).strip() for domain in domains if str(domain).strip()]
        try:
            field = self.page.locator("#domains")
            field.fill("\n".join(values))
            return field.input_value().splitlines() == values
        except Exception:
            return False

    def _select_option(self, input_id: str, option_name: str) -> bool:
        """Select an exact Ant Select option by the form input id."""
        try:
            field = self.page.locator(f"#{input_id}")
            select = field.locator(
                "xpath=ancestor::div[contains(concat(' ',normalize-space(@class),' '),' ant-select ')][1]"
            )
            selected = select.locator(".ant-select-selection-item")
            if selected.count() > 0 and (
                selected.first.inner_text() or ""
            ).strip() == str(option_name):
                return True
            select.locator(".ant-select-selector").click()
            self.page.wait_for_timeout(250)
            # Ant Select virtualizes long menus, so options beyond the first
            # viewport do not exist in the DOM. Catalog order plus keyboard
            # navigation is stable for both rendered and virtualized options.
            catalog = self.get_category_catalog()
            if input_id == "type":
                choices = list(catalog)
            else:
                category_select = self.page.locator("#type").locator(
                    "xpath=ancestor::div[contains(concat(' ',normalize-space(@class),' '),' ant-select ')][1]"
                )
                category = (
                    category_select.locator(".ant-select-selection-item").first.inner_text()
                    or ""
                ).strip()
                choices = catalog.get(category, [])
            if str(option_name) not in choices:
                self.page.keyboard.press("Escape")
                return False
            self.page.keyboard.press("Home")
            for _ in range(choices.index(str(option_name))):
                self.page.keyboard.press("ArrowDown")
            self.page.keyboard.press("Enter")
            self.page.wait_for_timeout(450)
            if field.get_attribute("aria-expanded") == "true":
                self.page.keyboard.press("Escape")
            selected = select.locator(".ant-select-selection-item")
            return bool(
                selected.count() > 0
                and (selected.first.inner_text() or "").strip() == str(option_name)
            )
        except Exception:
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    def set_category(self, category: str, site_type: str) -> bool:
        if not self._select_option("type", category):
            return False
        self.page.wait_for_timeout(450)
        return self._select_option("name", site_type)

    def save_and_wait(self, timeout: int = 10000) -> Dict[str, Any]:
        result = {"success": False, "error": ""}
        try:
            self.click_save()
            for _ in range(max(1, int(timeout / 400))):
                self.page.wait_for_timeout(400)
                error = self.has_form_error()
                if error:
                    result["error"] = error
                    return result
                if not self.is_still_on_config_page():
                    result["success"] = True
                    return result
            result["error"] = "保存后仍停留在自定义网址库配置页"
        except Exception as exc:
            result["error"] = str(exc)[:160]
        return result

    def add_rule(
        self,
        name: str,
        category: str,
        site_type: str,
        domains: Iterable[str],
    ) -> Dict[str, Any]:
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入自定义网址库新增页失败"
                return result
            if not self.fill_library_name(name):
                result["error"] = "填写名称失败"
                return result
            if not self.set_category(category, site_type):
                result["error"] = f"选择类别失败: {category}-{site_type}"
                return result
            if not self.fill_domains(domains):
                result["error"] = "填写域名失败"
                return result
            return self.save_and_wait()
        except Exception as exc:
            result["error"] = str(exc)[:160]
            return result

    def try_add_invalid(
        self,
        *,
        name: str,
        domains: Iterable[str],
        category: str = "交通旅游",
        site_type: str = "旅游网站",
    ) -> Dict[str, Any]:
        result = {"blocked": False, "error": ""}
        try:
            if not self.open_add_page():
                return {"blocked": False, "error": "进入新增页失败"}
            if name:
                self.fill_library_name(name)
            self.set_category(category, site_type)
            values = [str(item) for item in domains]
            if values:
                self.fill_domains(values)
            self.click_save()
            self.page.wait_for_timeout(1200)
            error = self.has_form_error()
            result["blocked"] = self.is_still_on_config_page()
            result["error"] = error or (
                "保存被前端拦截" if result["blocked"] else "非法值被保存"
            )
        except Exception as exc:
            result["error"] = str(exc)[:160]
        return result

    def edit_library(
        self,
        current_name: str,
        *,
        new_name: str = "",
        category: str = "",
        site_type: str = "",
        domains: Iterable[str] = (),
    ) -> Dict[str, Any]:
        if not self.edit_rule(current_name):
            return {"success": False, "error": "进入编辑页失败"}
        if new_name and not self.fill_library_name(new_name):
            return {"success": False, "error": "修改名称失败"}
        if (category or site_type) and not (
            category and site_type and self.set_category(category, site_type)
        ):
            return {"success": False, "error": "修改类别失败"}
        domain_values = [str(item) for item in domains]
        if domain_values and not self.fill_domains(domain_values):
            return {"success": False, "error": "修改域名失败"}
        return self.save_and_wait()

    def delete_rule(self, rule_name: str) -> bool:
        """Delete from the custom tab and verify after returning to that tab."""
        try:
            if not self._click_rule_button(rule_name, "删除"):
                return False
            self.page.wait_for_timeout(500)
            if not self._click_visible_confirm(timeout=4000):
                return False
            self.page.wait_for_timeout(900)
            self.navigate_to_custom_domain_group()
            return not self.rule_exists(rule_name)
        except Exception:
            return False

    def query_system_urls(self, keyword: str) -> List[Dict[str, str]]:
        """Use the visible system URL dialog and return its rendered rows."""
        rows: List[Dict[str, str]] = []
        try:
            self.navigate_to_custom_domain_group()
            self.page.get_by_role(
                "button", name="查询系统网址", exact=True
            ).click()
            dialog = self.page.locator(".ant-modal:visible").last
            field = dialog.get_by_placeholder("请输入内容后再查询")
            field.fill(str(keyword))
            field.press("Enter")
            for _ in range(24):
                self.page.wait_for_timeout(250)
                if "Loading..." not in dialog.inner_text():
                    break
            values = dialog.locator("div.ant-table-row").evaluate_all(
                """nodes => nodes.map(row => {
                    const cells = [...row.querySelectorAll('.ant-table-cell')]
                        .map(cell => (cell.innerText || '').trim());
                    return {type: cells[0] || '', name: cells[1] || '', domain: cells[2] || ''};
                })"""
            )
            rows = [dict(item) for item in values]
            dialog.locator("button.ant-modal-close").click()
            self.page.wait_for_timeout(250)
        except Exception:
            try:
                dialog = self.page.locator(".ant-modal:visible").last
                if dialog.count() > 0:
                    dialog.locator("button.ant-modal-close").click()
            except Exception:
                pass
        return rows

    def get_category_catalog(self) -> Dict[str, List[str]]:
        try:
            payload = self.page.evaluate(
                """async () => {
                    const response = await fetch('/Action/call', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            action: 'show',
                            func_name: 'domain_group',
                            param: {TYPE: 'url_type'}
                        })
                    });
                    return await response.json();
                }"""
            )
            groups = ((payload or {}).get("results") or {}).get("url_type") or []
            return {
                str(group.get("name")): [
                    str(child.get("name"))
                    for child in (group.get("children") or [])
                    if child.get("name")
                ]
                for group in groups
                if group.get("name")
            }
        except Exception:
            return {}

    def verify_help_entry(
        self,
        expected_keywords: Iterable[str] = (
            "自定义网址库",
            "类别",
            "类型",
            "域名",
            "查询系统网址",
            "禁止娱乐网站",
        ),
        timeout: int = 12000,
    ) -> Dict[str, Any]:
        return super().verify_help_entry(expected_keywords, timeout)
