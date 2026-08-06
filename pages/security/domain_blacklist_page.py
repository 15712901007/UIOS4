"""网址浏览控制 > 禁止娱乐网站页面对象。"""

from typing import Any, Dict, Iterable, List

from playwright.sync_api import Page

from pages.security.url_black_page import UrlBlackPage


class DomainBlacklistPage(UrlBlackPage):
    """禁止娱乐网站列表、网站分类选择器和配置页。"""

    MODULE_NAME = "domain_blacklist"
    IMPORT_REQUIRES_CLEAR_GUARD = True
    HELP_ARTICLE_ID = "184"
    LIST_URL = "/login#/securityCenter/urlAccessControl"
    ADD_URL = "/login#/securityCenter/urlAccessControl/bannedSite/add"
    CONFIG_PATH = "/urlAccessControl/bannedSite/"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    def navigate_to_domain_blacklist(self):
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(1800)
        tabs = self.page.get_by_role("tab")
        target = tabs.filter(has_text="禁止娱乐网站")
        if target.count() > 0:
            target.first.click()
        elif tabs.count() >= 2:
            target = tabs.nth(1)
            target.click()
        else:
            raise RuntimeError("未找到禁止娱乐网站页签")
        self.page.wait_for_timeout(900)
        return self

    # Inherited help verification calls this method dynamically.
    def navigate_to_url_black(self):
        return self.navigate_to_domain_blacklist()

    def open_add_page(self) -> bool:
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        # React在相同hash路由间不会重新挂载表单；先离开配置页，避免上一次
        # 必填校验场景选择的网站类型泄漏到下一次新增。
        if self.CONFIG_PATH in self.page.url:
            self.page.goto(f"{self.base_url}{self.LIST_URL}")
            self.page.wait_for_timeout(500)
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(1600)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        return bool(
            self.CONFIG_PATH in self.page.url
            and ("/add" in self.page.url or "/edit" in self.page.url)
            and self.page.get_by_placeholder("请输入名称").count() > 0
        )

    def is_still_on_config_page(self) -> bool:
        return self.CONFIG_PATH in self.page.url

    def save_and_wait(self, timeout: int = 10000) -> Dict:
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
            result["error"] = "保存后仍停留在禁止娱乐网站配置页"
        except Exception as exc:
            result["error"] = str(exc)[:160]
        return result

    def _website_type_select(self):
        marked = self.page.evaluate(
            r"""() => {
                const norm = text => (text || '').replace(/[\s:*：]/g, '');
                const labels = [...document.querySelectorAll('.ant-form-item-label')]
                    .filter(node => node.offsetParent !== null);
                const label = labels.find(node => norm(node.textContent) === '网站类型');
                const item = label && label.closest('.ant-form-item');
                const select = item && item.querySelector('.ant-select');
                if (!select) return false;
                select.setAttribute('data-domain-blacklist-type', '1');
                return true;
            }"""
        )
        if not marked:
            return self.page.locator(".ant-select:visible").first
        return self.page.locator("[data-domain-blacklist-type='1']")

    @staticmethod
    def _group_parts(group: str) -> tuple:
        value = str(group).strip()
        if "-" in value:
            return tuple(value.split("-", 1))
        return value, ""

    def clear_domain_groups(self) -> bool:
        try:
            select = self._website_type_select()
            while select.locator(".ant-select-selection-item-remove").count() > 0:
                select.locator(".ant-select-selection-item-remove").first.click()
                self.page.wait_for_timeout(100)
            return True
        except Exception:
            return False

    def _tree_row(self, dialog, title: str):
        rows = dialog.locator(".ant-tree-treenode")
        for index in range(rows.count()):
            row = rows.nth(index)
            label = row.locator(".ant-tree-node-content-wrapper").first
            if label.count() and (label.get_attribute("title") or "") == title:
                return row
        return None

    def set_domain_groups(
        self,
        groups: Iterable[str],
        *,
        clear_existing: bool = True,
    ) -> bool:
        """通过网站类型传输树选择父分类或 ``父分类-子分类``。"""
        expected = [str(group).strip() for group in groups if str(group).strip()]
        if not expected:
            return False
        try:
            if clear_existing and not self.clear_domain_groups():
                return False
            select = self._website_type_select()
            select.click()
            dialog = self.page.locator(".ant-modal:visible").last
            dialog.wait_for(state="visible", timeout=5000)
            for group in expected:
                parent, child = self._group_parts(group)
                parent_row = self._tree_row(dialog, parent)
                if parent_row is None:
                    return False
                target_row = parent_row
                if child:
                    if parent_row.get_attribute("aria-expanded") == "false":
                        parent_row.locator(".ant-tree-switcher").click()
                        self.page.wait_for_timeout(250)
                    target_row = self._tree_row(dialog, child)
                    if target_row is None:
                        return False
                checkbox = target_row.locator(".ant-tree-checkbox")
                if checkbox.get_attribute("aria-checked") != "true":
                    checkbox.click()
                    self.page.wait_for_timeout(120)
            dialog.get_by_role("button", name="确定", exact=True).click()
            self.page.wait_for_timeout(350)
            selected = select.inner_text()
            return all(
                (self._group_parts(group)[1] or self._group_parts(group)[0]) in selected
                for group in expected
            )
        except Exception as exc:
            print(f"[DEBUG] set_domain_groups error: {exc}")
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    def get_domain_group_catalog(self) -> Dict[str, List[str]]:
        """打开网站类型树，并从页面同源API结构化读取完整分类。"""
        catalog: Dict[str, List[str]] = {}
        try:
            if not self.is_on_config_page() and not self.open_add_page():
                return catalog
            self._website_type_select().click()
            dialog = self.page.locator(".ant-modal:visible").last
            dialog.wait_for(state="visible", timeout=5000)
            dialog.get_by_role("button", name="取消", exact=True).click()
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
            for group in groups:
                name = str(group.get("name") or "")
                if not name:
                    continue
                catalog[name] = [
                    str(child.get("name") or "")
                    for child in (group.get("children") or [])
                    if child.get("name")
                ]
        except Exception as exc:
            print(f"[DEBUG] get_domain_group_catalog error: {exc}")
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
        return catalog

    def add_rule(
        self,
        name: str,
        domain_groups: Iterable[str],
        *,
        sources: Iterable[str] = (),
        remark: str = "",
    ) -> Dict:
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入禁止娱乐网站新增页失败"
                return result
            if not self.fill_name(name):
                result["error"] = "填写名称失败"
                return result
            if not self.set_domain_groups(domain_groups):
                result["error"] = "选择网站类型失败"
                return result
            for source in sources:
                if not self.add_source(source):
                    result["error"] = f"添加内网IP/MAC失败: {source}"
                    return result
            if remark and not self.fill_remark(remark):
                result["error"] = "填写备注失败"
                return result
            return self.save_and_wait()
        except Exception as exc:
            result["error"] = str(exc)[:160]
            return result

    def try_add_invalid(self, *, name: str, select_group: bool = False) -> Dict:
        result = {"blocked": False, "error": ""}
        try:
            if not self.open_add_page():
                return {"blocked": False, "error": "进入新增页失败"}
            if name:
                self.fill_name(name)
            if select_group:
                self.set_domain_groups(["休闲娱乐-游戏网站"])
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

    def verify_help_entry(
        self,
        expected_keywords: Iterable[str] = (
            "禁止娱乐网站",
            "网站类型",
            "内网IP",
            "周期",
            "自定义网址库",
            "网址黑白名单",
        ),
        timeout: int = 12000,
    ) -> Dict[str, Any]:
        return super().verify_help_entry(expected_keywords, timeout)
