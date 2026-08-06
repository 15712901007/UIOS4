"""网址浏览控制 > 网址黑白名单页面对象。"""

import time
from typing import Any, Dict, Iterable
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import Page

from pages.security.acl_page import AclPage


class UrlBlackPage(AclPage):
    """网址黑白名单列表、配置页和右上角全局设置。"""

    MODULE_NAME = "url_black"
    IMPORT_REQUIRES_CLEAR_GUARD = True
    HELP_ARTICLE_ID = "183"
    LIST_URL = "/login#/securityCenter/urlAccessControl"
    ADD_URL = "/login#/securityCenter/urlAccessControl/blackList/add"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    def navigate_to_url_black(self):
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2500)
        return self

    def open_add_page(self) -> bool:
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2200)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        url = self.page.url
        return (
            "/urlAccessControl/blackList/" in url
            and ("/add" in url or "/edit" in url)
            and self.page.get_by_placeholder("请输入名称").count() > 0
        )

    def is_still_on_config_page(self) -> bool:
        return "/urlAccessControl/blackList/" in self.page.url

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
            result["error"] = "保存后仍停留在网址黑白名单配置页"
        except Exception as exc:
            result["error"] = str(exc)[:160]
        return result

    def set_mode(self, mode) -> bool:
        """设置控制模式；0/black=黑名单，1/white=白名单。"""
        value = "1" if str(mode).lower() in {"1", "white", "whitelist", "白名单"} else "0"
        try:
            radio = self.page.locator(f"input[type='radio'][value='{value}']")
            if radio.count() == 0:
                return False
            radio.first.check(force=True)
            return radio.first.is_checked()
        except Exception:
            return False

    def _add_custom_value(self, section: str, value: str) -> bool:
        """在域名设置或IP/MAC设置中追加一行并填写。"""
        try:
            marked = self.page.evaluate(
                r"""({section}) => {
                    const norm = s => (s || '').replace(/[\s:*：]/g, '');
                    const labels = [...document.querySelectorAll('.ant-form-item-label')]
                        .filter(el => el.offsetParent !== null);
                    const label = labels.find(el => norm(el.textContent) === norm(section));
                    if (!label) return false;
                    let block = label.closest('.ant-form-item');
                    if (!block) block = label.parentElement && label.parentElement.parentElement;
                    if (!block) return false;
                    const add = [...block.querySelectorAll('button')].find(
                        button => button.offsetParent !== null && norm(button.textContent) === '添加'
                    );
                    if (!add) return false;
                    block.setAttribute('data-url-black-section', '1');
                    add.click();
                    return true;
                }""",
                {"section": section},
            )
            if not marked:
                return False
            self.page.wait_for_timeout(300)
            block = self.page.locator("[data-url-black-section='1']")
            inputs = block.locator("input[type='text']:visible, textarea:visible")
            if inputs.count() == 0:
                return False
            target = inputs.last
            target.fill("")
            target.fill(value)
            # React会在fill后重建整个传输列表，原节点和临时标记随即失效。
            # fill成功即表示受控表单已收到值，不能再读取旧locator复核。
            return True
        except Exception as exc:
            print(f"[DEBUG] _add_custom_value({section}) error: {exc}")
            return False

    def add_domain(self, domain: str) -> bool:
        return self._add_custom_value("域名设置", domain)

    def add_source(self, address: str) -> bool:
        return self._add_custom_value("IP/MAC设置", address)

    def add_rule(
        self,
        name: str,
        domains: Iterable[str],
        *,
        mode=0,
        sources: Iterable[str] = (),
        remark: str = "",
    ) -> Dict:
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入网址黑白名单新增页失败"
                return result
            if not self.fill_name(name):
                result["error"] = "填写名称失败"
                return result
            if not self.set_mode(mode):
                result["error"] = "设置黑白名单模式失败"
                return result
            for domain in domains:
                if not self.add_domain(domain):
                    result["error"] = f"添加域名失败: {domain}"
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

    def try_add_invalid(self, *, name: str, domain: str, source: str = "") -> Dict:
        result = {"blocked": False, "error": ""}
        try:
            if not self.open_add_page():
                return {"blocked": False, "error": "进入新增页失败"}
            if name:
                self.fill_name(name)
            if domain:
                self.add_domain(domain)
            if source:
                self.add_source(source)
            self.click_save()
            self.page.wait_for_timeout(1200)
            error = self.has_form_error()
            result["blocked"] = self.is_still_on_config_page()
            result["error"] = error or ("保存被前端拦截" if result["blocked"] else "非法值被保存")
        except Exception as exc:
            result["error"] = str(exc)[:160]
        return result

    def open_settings(self) -> bool:
        try:
            button = self.page.locator("button[class*='_setIcon_']:visible")
            if button.count() == 0:
                return False
            button.first.click()
            self.page.wait_for_timeout(700)
            return self.page.get_by_text("允许访问白名单列表中的外部链接", exact=False).count() > 0
        except Exception:
            return False

    def get_white_external_link_setting(self) -> Dict:
        try:
            return self.page.evaluate(
                """() => {
                    const wrapper = [...document.querySelectorAll('.ant-checkbox-wrapper')]
                        .find(el => el.offsetParent !== null &&
                            (el.textContent || '').includes('允许访问白名单列表中的外部链接'));
                    const input = wrapper && wrapper.querySelector('input[type=checkbox]');
                    return {
                        enabled: input ? input.checked : null,
                        http_only_hint: document.body.innerText.includes('只支持HTTP协议')
                    };
                }"""
            )
        except Exception:
            return {"enabled": None, "http_only_hint": False}

    def set_white_external_link(self, enabled: bool, *, save: bool = True) -> bool:
        try:
            changed = self.page.evaluate(
                """({enabled}) => {
                    const wrapper = [...document.querySelectorAll('.ant-checkbox-wrapper')]
                        .find(el => el.offsetParent !== null &&
                            (el.textContent || '').includes('允许访问白名单列表中的外部链接'));
                    if (!wrapper) return false;
                    const input = wrapper.querySelector('input[type=checkbox]');
                    if (!input) return false;
                    if (input.checked !== enabled) wrapper.click();
                    return true;
                }""",
                {"enabled": bool(enabled)},
            )
            if not changed:
                return False
            if save:
                self.page.get_by_role("button", name="保存", exact=True).last.click()
                self.page.wait_for_timeout(1000)
            return True
        except Exception as exc:
            print(f"[DEBUG] set_white_external_link error: {exc}")
            return False

    def verify_help_entry(
        self,
        expected_keywords: Iterable[str] = (
            "网址黑白名单",
            "控制模式",
            "控制域名",
            "允许访问白名单列表中的外部链接",
            "HTTP",
            "HTTPS",
        ),
        timeout: int = 12000,
    ) -> Dict[str, Any]:
        """验证右下角帮助按钮、官方文章主题以及新标签回收。"""
        keywords = [str(keyword) for keyword in expected_keywords if str(keyword)]
        result: Dict[str, Any] = {
            "button_present": False,
            "bottom_right": False,
            "opened": False,
            "url": "",
            "title": "",
            "official_article": False,
            "matched_keywords": [],
            "all_keywords_matched": False,
            "closed": False,
            "no_orphan": False,
            "returned_to_list": False,
            "error": "",
        }
        self.navigate_to_url_black()
        button = self.page.locator("button[class*='_helpDoc_']:visible")
        if button.count() == 0:
            button = self.page.locator("button:visible").filter(has_text="帮助")
        if button.count() == 0:
            result["error"] = "未找到右下角帮助按钮"
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
            button.first.click(no_wait_after=True)
            deadline = time.monotonic() + timeout / 1000
            while time.monotonic() < deadline:
                new_pages = [item for item in context.pages if item not in before_pages]
                if new_pages:
                    popup = new_pages[-1]
                    break
                self.page.wait_for_timeout(100)
            if popup is None:
                result["error"] = "帮助按钮未打开新标签页"
                return result
            result["opened"] = True
            try:
                popup.wait_for_load_state("domcontentloaded", timeout=timeout)
            except Exception:
                pass
            result["url"] = popup.url or ""
            try:
                result["title"] = popup.title()
            except Exception:
                result["title"] = ""
            parsed = urlsplit(result["url"])
            query = parse_qs(parsed.query)
            result["official_article"] = bool(
                (parsed.hostname or "").lower() in {"ikuai8.com", "www.ikuai8.com"}
                and query.get("id") == [self.HELP_ARTICLE_ID]
            )
            body = popup.locator("body").inner_text(timeout=timeout)
            searchable = "\n".join((result["title"], body))
            result["matched_keywords"] = [
                keyword for keyword in keywords if keyword in searchable
            ]
            result["all_keywords_matched"] = bool(keywords) and len(
                result["matched_keywords"]
            ) == len(keywords)
            if not result["official_article"]:
                result["error"] = "帮助链接不是网址黑白名单官方文章id=183"
            elif not result["all_keywords_matched"]:
                result["error"] = "帮助正文缺少网址黑白名单关键说明"
            return result
        except Exception as exc:
            result["error"] = f"帮助功能验证异常({type(exc).__name__})"
            return result
        finally:
            for candidate in list(context.pages):
                if candidate in before_pages:
                    continue
                try:
                    if not candidate.is_closed():
                        candidate.close()
                except Exception:
                    pass
            if popup is not None:
                try:
                    result["closed"] = popup.is_closed()
                except Exception:
                    pass
            self.page.bring_to_front()
            self.page.wait_for_timeout(250)
            result["no_orphan"] = all(
                candidate in before_pages for candidate in context.pages
            )
            result["returned_to_list"] = bool(
                self.LIST_URL in self.page.url
                and self.page.locator("button[class*='_helpDoc_']:visible").count() > 0
            )
