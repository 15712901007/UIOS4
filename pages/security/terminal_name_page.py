"""安全中心 > 终端名称管理 Page Object。

真实页面特征（10.66.0.150 实测）：
- 列表 URL 为 ``/#/securityCenter/terminalNameManagement``，是单页表格（无 Tab）。
- 新增/编辑使用 ``.../add``、``.../edit`` 独立路由。
- 列表表头：名称(tagname)、MAC地址(mac)、备注(comment)、操作(operate)。
- 工具栏按钮：添加、导入、导出、帮助；行内操作只有“编辑/删除”（无启用/停用）。
- 表单字段：名称(tagname, 必填, maxlength=15)、MAC地址(mac, 必填)、备注(comment, textarea, maxlength=64)。
- 前端校验：空名称“请输入名称”、空MAC“请输入MAC地址”、非法MAC“MAC地址格式输入错误”。
- 后端表 ``mac_comment``(id/mac/tagname/comment)，mac 为唯一键，有 BEFORE INSERT 触发器
  按 mac 删除旧行 —— 因此“相同 MAC 再次添加”是覆盖更新而非报错。

本类继承 :class:`IkuaiTablePage`，复用通用导入/导出/搜索骨架，并对终端名称特有的
路由、表单、精确行定位、MAC 覆盖语义、导入清空选项做稳定封装。所有面向报告的文案
均为中文。
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Optional

from playwright.sync_api import Locator, Page

from pages.ikuai_table_page import IkuaiTablePage


class TerminalNamePage(IkuaiTablePage):
    """终端名称管理页面操作类。"""

    MODULE_NAME = "terminal_name"
    IMPORT_REQUIRES_CLEAR_GUARD = True

    LIST_URL = "/#/securityCenter/terminalNameManagement"
    ADD_URL = "/#/securityCenter/terminalNameManagement/add"
    EDIT_FRAGMENT = "/securityCenter/terminalNameManagement/edit"

    # 列名 -> 表头 th 的 id（用于精确列定位与排序能力判断）
    COLUMN_ID_MAP = {
        "名称": "tagname",
        "MAC地址": "mac",
        "备注": "comment",
    }

    TAGNAME_MAX_LENGTH = 15
    COMMENT_MAX_LENGTH = 64

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)
        self.last_cancel_result: Dict = {}
        self.last_fill_checks: Dict[str, bool] = {}

    # ==================== 通用小工具 ====================
    def _wait_page(self, settle_ms: int = 800):
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(settle_ms)

    def _dismiss_transient_overlays(self):
        """只关闭可取消的浮层，不点击任何确认型按钮。"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(150)
        except Exception:
            pass
        try:
            cancel = self.page.locator(
                ".ant-modal-wrap:visible button:has-text('取消'):visible, "
                ".ant-drawer-content[role='dialog']:visible "
                "button:has-text('取消'):visible"
            )
            if cancel.count() > 0:
                cancel.last.click(timeout=1500)
                self.page.wait_for_timeout(250)
        except Exception:
            pass

    def _wait_transient_feedback_clear(self, timeout: int = 3500):
        """避免把上一次提交的短暂 toast 误判为本次结果。"""
        selectors = (
            ".ant-message-success:visible, .ant-message-error:visible, "
            ".ant-notification-notice-success:visible, "
            ".ant-notification-notice-error:visible"
        )
        for _ in range(max(1, timeout // 100)):
            try:
                if self.page.locator(selectors).count() == 0:
                    return
            except Exception:
                return
            self.page.wait_for_timeout(100)

    def _fill_field(self, field_id: str, value) -> bool:
        """填写 input 或 textarea，并用 React 原生 setter 触发 onChange。"""
        try:
            field = self.page.locator(f"#{field_id}:visible").first
            if field.count() == 0:
                return False
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(80)
            except Exception:
                pass
            field.scroll_into_view_if_needed()
            field.fill("")
            if value is not None and str(value) != "":
                field.type(str(value), delay=20)
            field.evaluate("""el => {
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            return True
        except Exception as exc:
            print(f"[DEBUG] fill #{field_id}: {str(exc)[:80]}")
            return False

    def get_form_error(self, root: Optional[Locator] = None) -> Optional[str]:
        """读取当前终端名称表单校验或最近一条 API 错误（中文）。"""
        scope = root or self.page
        for selector in (
            ".ant-form-item-explain-error:visible",
            ".ant-alert-error:visible",
        ):
            try:
                loc = scope.locator(selector)
                if loc.count() > 0:
                    text = (loc.first.inner_text() or "").strip()
                    if text:
                        return text[:240]
            except Exception:
                pass
        for selector in (
            ".ant-message-error:visible",
            ".ant-notification-notice-error:visible",
        ):
            try:
                loc = self.page.locator(selector)
                for index in range(loc.count() - 1, -1, -1):
                    item = loc.nth(index)
                    if item.is_visible():
                        text = (item.inner_text() or "").strip()
                        if text:
                            return text[:240]
            except Exception:
                pass
        try:
            if scope.locator(
                ".ant-form-item-has-error:visible, "
                ".ant-input-status-error:visible, "
                ".ant-input-number-status-error:visible"
            ).count() > 0:
                return "输入格式错误"
        except Exception:
            pass
        return None

    def get_all_field_errors(self) -> Dict[str, str]:
        """读取表单每个字段的校验错误（label -> 错误文案），供报告展示具体提示。"""
        out: Dict[str, str] = {}
        try:
            items = self.page.locator(".ant-form-item:visible")
            for index in range(items.count()):
                item = items.nth(index)
                label = (item.locator(".ant-form-item-label").first.inner_text() or "").strip().replace("*", "").strip()
                err_loc = item.locator(".ant-form-item-explain-error:visible")
                if err_loc.count() > 0:
                    err = (err_loc.first.inner_text() or "").strip()
                    if label and err:
                        out[label] = err[:120]
        except Exception:
            pass
        return out

    # ==================== 列表导航 ====================
    def navigate_to_terminal_name(self):
        self._dismiss_transient_overlays()
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        self._wait_page(1200)
        return self

    # 兼容多种调用习惯的别名
    navigate_to_terminal = navigate_to_terminal_name
    navigate = navigate_to_terminal_name

    def _list_table(self) -> Locator:
        return self.page.locator(
            ".ant-table-wrapper:visible"
            ":has(th#tagname):has(th#mac):has(th#comment)"
        ).first

    def get_default_structure(self) -> Dict:
        """读取列表 URL、工具栏按钮、表头与搜索框，供测试对结构做硬断言。"""
        result: Dict = {
            "url_ok": "securityCenter/terminalNameManagement" in self.page.url,
            "table_present": False,
            "search_present": False,
            "headers": [],
            "header_ids": [],
            "buttons": [],
            "sortable_columns": [],
            "all_headers_unsortable": False,
        }
        try:
            result.update(self.page.evaluate("""() => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                const tables = [...document.querySelectorAll('.ant-table')].filter(visible);
                const table = tables[0] || null;
                const headers = table ? [...table.querySelectorAll(
                    '.ant-table-thead th'
                )].filter(h => visible(h) &&
                    !h.classList.contains('ant-table-measure-cell')) : [];
                const sortable = headers.filter(h =>
                    h.querySelector('.sortIcon, .ant-table-column-sorter') ||
                    h.hasAttribute('aria-sort')
                ).map(h => norm(h.innerText)).filter(Boolean);
                return {
                    table_present: !!table,
                    search_present: [...document.querySelectorAll(
                        "input[placeholder='请输入搜索内容']"
                    )].some(visible),
                    headers: headers.map(h => norm(h.innerText)).filter(Boolean),
                    header_ids: headers.map(h => h.id || ''),
                    buttons: [...document.querySelectorAll('button')].filter(visible)
                        .map(b => norm(b.innerText || b.textContent)).filter(Boolean),
                    sortable_columns: sortable,
                    all_headers_unsortable: sortable.length === 0
                };
            }"""))
        except Exception:
            pass
        return result

    get_terminal_default_structure = get_default_structure

    def get_rule_count(self) -> int:
        """获取列表“共 N 条”数量。"""
        try:
            loc = self.page.locator("text=/共\\s*\\d+\\s*条/").first
            if loc.count() > 0:
                import re as _re
                m = _re.search(r"共\s*(\d+)\s*条", loc.text_content() or "")
                if m:
                    return int(m.group(1))
        except Exception:
            pass
        return 0

    # ==================== 新增/编辑表单 ====================
    def open_add_page(self) -> bool:
        self._dismiss_transient_overlays()
        # 独立路由 add 页每次直接进入最可靠（参考 HTTP page 经验）。
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        self._wait_page(1200)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        route_ok = (
            "/securityCenter/terminalNameManagement/add" in self.page.url
            or self.EDIT_FRAGMENT in self.page.url
        )
        try:
            return route_ok and self.page.locator("input#tagname:visible").count() > 0
        except Exception:
            return route_ok

    is_still_on_config_page = is_on_config_page

    def _main_form(self) -> Locator:
        form = self.page.locator("form.customForm:visible")
        if form.count() > 0:
            return form.first
        return self.page.locator("form:visible").first

    def get_form_structure(self) -> Dict:
        """读取新增/编辑页字段结构、默认值与约束（不读取已填敏感值）。"""
        result: Dict = {
            "url_ok": self.is_on_config_page(),
            "tagname_present": False,
            "tagname_required": False,
            "tagname_maxlength": None,
            "tagname_placeholder": "",
            "mac_present": False,
            "mac_required": False,
            "mac_placeholder": "",
            "comment_present": False,
            "comment_required": False,
            "comment_maxlength": None,
            "save_present": False,
            "cancel_present": False,
        }
        try:
            form = self._main_form()
            if form.count() == 0:
                return result
            data = form.evaluate("""root => {
                const norm = s => (s || '').replace(/\\s+/g, ' ').trim();
                const read = id => {
                    const el = root.querySelector('#' + id);
                    if (!el) return null;
                    const item = el.closest('.ant-form-item');
                    return {
                        placeholder: el.getAttribute('placeholder') || '',
                        maxlength: el.getAttribute('maxlength'),
                        required: el.getAttribute('aria-required') === 'true' ||
                            !!(item && item.querySelector('.ant-form-item-required'))
                    };
                };
                return {
                    tagname: read('tagname'), mac: read('mac'), comment: read('comment')
                };
            }""")
            tag = data.get("tagname") or {}
            if tag:
                result["tagname_present"] = True
                result["tagname_required"] = bool(tag.get("required"))
                result["tagname_placeholder"] = tag.get("placeholder", "")
                try:
                    result["tagname_maxlength"] = int(tag.get("maxlength"))
                except (TypeError, ValueError):
                    pass
            mac = data.get("mac") or {}
            if mac:
                result["mac_present"] = True
                result["mac_required"] = bool(mac.get("required"))
                result["mac_placeholder"] = mac.get("placeholder", "")
            comment = data.get("comment") or {}
            if comment:
                result["comment_present"] = True
                result["comment_required"] = bool(comment.get("required"))
                try:
                    result["comment_maxlength"] = int(comment.get("maxlength"))
                except (TypeError, ValueError):
                    pass
            button_texts: List[str] = []
            for buttons in (
                form.locator("button:visible"),
                self.page.locator("div.footer button:visible"),
            ):
                button_texts.extend(
                    (buttons.nth(i).inner_text() or "").strip()
                    for i in range(buttons.count())
                )
            result["save_present"] = "保存" in button_texts
            result["cancel_present"] = "取消" in button_texts
        except Exception:
            pass
        return result

    # ---- 字段读写 ----
    def fill_tagname(self, tagname: str) -> bool:
        return self._fill_field("tagname", tagname)

    def get_tagname_value(self) -> str:
        try:
            return self.page.locator("#tagname:visible").first.input_value()
        except Exception:
            return ""

    def fill_mac(self, mac: str) -> bool:
        return self._fill_field("mac", mac)

    def get_mac_value(self) -> str:
        try:
            return self.page.locator("#mac:visible").first.input_value()
        except Exception:
            return ""

    def fill_comment(self, comment: str) -> bool:
        return self._fill_field("comment", comment)

    def get_comment_value(self) -> str:
        try:
            return self.page.locator("#comment:visible").first.input_value()
        except Exception:
            return ""

    def fill_rule_form(
        self,
        *,
        tagname: Optional[str] = None,
        mac: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> bool:
        checks: Dict[str, bool] = {}
        if tagname is not None:
            checks["tagname"] = self.fill_tagname(tagname)
        if mac is not None:
            checks["mac"] = self.fill_mac(mac)
        if comment is not None:
            checks["comment"] = self.fill_comment(comment)
        self.last_fill_checks = dict(checks)
        return all(checks.values()) if checks else True

    def save_rule(self, timeout: int = 9000) -> Dict:
        result: Dict = {
            "submitted": False,
            "success": False,
            "error": "",
            "still_on_form": self.is_on_config_page(),
            "url": self.page.url,
        }
        try:
            self.page.keyboard.press("Escape")
            self._wait_transient_feedback_clear()
            save = self.page.locator("div.footer button:visible").filter(
                has_text="保存"
            ).first
            if save.count() == 0:
                save = self.page.get_by_role("button", name="保存", exact=True).first
            if save.count() == 0:
                result["error"] = "未找到终端名称保存按钮"
                return result
            save.click()
            result["submitted"] = True
            for _ in range(max(1, timeout // 300)):
                self.page.wait_for_timeout(300)
                if not self.is_on_config_page():
                    result["success"] = True
                    result["still_on_form"] = False
                    result["url"] = self.page.url
                    return result
                error = self.get_form_error(self._main_form())
                if error:
                    result["error"] = error
                    result["still_on_form"] = True
                    result["url"] = self.page.url
                    return result
            result["error"] = "保存后仍在终端名称配置页"
        except Exception as exc:
            result["error"] = str(exc)[:180]
        result["still_on_form"] = self.is_on_config_page()
        result["url"] = self.page.url
        return result

    save_and_wait = save_rule

    def cancel_rule_form(self, confirm_dirty: bool = True) -> bool:
        """取消配置页；dirty 时按参数确认退出或留在表单。"""
        self.last_cancel_result = {
            "clicked": False,
            "unsaved_confirm_seen": False,
            "message": "",
            "confirmed": False,
            "left_form": False,
        }
        try:
            if not self.is_on_config_page():
                self.last_cancel_result["left_form"] = True
                return True
            cancel = self.page.locator("div.footer button:visible").filter(
                has_text="取消"
            ).first
            if cancel.count() == 0:
                cancel = self.page.get_by_role("button", name="取消", exact=True).first
            if cancel.count() == 0:
                return False
            cancel.click()
            self.last_cancel_result["clicked"] = True
            self.page.wait_for_timeout(350)
            modal = self.page.locator(".ant-modal-content:visible").last
            if modal.count() > 0:
                message = (modal.inner_text() or "").strip()
                if "当前内容未保存" in message:
                    self.last_cancel_result["unsaved_confirm_seen"] = True
                    self.last_cancel_result["message"] = message
                button_name = "确定" if confirm_dirty else "取消"
                button = modal.get_by_role("button", name=button_name, exact=True)
                if button.count() > 0:
                    button.click()
                self.last_cancel_result["confirmed"] = bool(confirm_dirty)
                self.page.wait_for_timeout(450)
            if confirm_dirty:
                for _ in range(12):
                    if not self.is_on_config_page():
                        self.last_cancel_result["left_form"] = True
                        return True
                    self.page.wait_for_timeout(250)
                return False
            self.last_cancel_result["left_form"] = not self.is_on_config_page()
            return self.is_on_config_page()
        except Exception as exc:
            self.last_cancel_result["error"] = str(exc)[:140]
            return False

    cancel_form = cancel_rule_form

    def add_rule(self, tagname: str, mac: str, comment: str = "") -> Dict:
        """新增一条终端名称。返回 {success, error}。"""
        filled = False
        for attempt in range(2):
            if not self.open_add_page():
                if attempt == 0:
                    continue
                return {"success": False, "error": "进入终端名称新增页失败"}
            filled = self.fill_rule_form(tagname=tagname, mac=mac, comment=comment)
            if filled:
                break
            if attempt == 0:
                self._dismiss_transient_overlays()
        if not filled:
            failed = [key for key, ok in self.last_fill_checks.items() if not ok]
            return {
                "success": False,
                "error": "终端名称表单填写不完整: " + ",".join(failed),
                "fill_checks": dict(self.last_fill_checks),
            }
        if self.get_tagname_value() != str(tagname):
            self.cancel_rule_form()
            return {"success": False, "error": "名称被 maxlength=15 截断"}
        return self.save_rule()

    def try_add_invalid(
        self,
        *,
        tagname: Optional[str] = "",
        mac: Optional[str] = "",
        comment: Optional[str] = None,
        timeout: int = 3500,
    ) -> Dict:
        """提交异常表单并返回结构化结果（blocked/error 含中文提示）。"""
        result: Dict = {
            "submitted": False,
            "success": False,
            "blocked": False,
            "error": "",
            "field_errors": {},
            "still_on_form": False,
            "actual_tagname": "",
            "truncated": False,
        }
        if not self.open_add_page():
            result["error"] = "进入终端名称新增页失败"
            return result
        # 空字符串也要显式填写，以触发 required 校验。
        self.fill_tagname("" if tagname is None else tagname)
        result["actual_tagname"] = self.get_tagname_value()
        if tagname is not None and result["actual_tagname"] != str(tagname):
            result["blocked"] = True
            result["truncated"] = True
            result["still_on_form"] = True
            result["error"] = "名称被 maxlength=15 截断"
            self.cancel_rule_form()
            return result
        if mac is not None:
            self.fill_mac(mac)
        if comment is not None:
            self.fill_comment(comment)
        saved = self.save_rule(timeout=timeout)
        result["submitted"] = bool(saved.get("submitted"))
        result["success"] = bool(saved.get("success"))
        result["still_on_form"] = self.is_on_config_page()
        result["field_errors"] = self.get_all_field_errors()
        result["blocked"] = not result["success"] and result["still_on_form"]
        # 优先用字段级错误文案，否则用通用 error
        if result["field_errors"]:
            result["error"] = "; ".join(f"{k}:{v}" for k, v in result["field_errors"].items())
        else:
            result["error"] = saved.get("error", "") or (
                "非法终端名称被拦截" if result["blocked"] else "非法终端名称被接受"
            )
        if result["still_on_form"]:
            self.cancel_rule_form()
        return result

    try_add_rule_invalid = try_add_invalid

    # ==================== 列表 CRUD ====================
    def _row_for_rule(self, tagname: str) -> Locator:
        rows = self._list_table().locator("div.ant-table-row")
        try:
            for index in range(rows.count()):
                row = rows.nth(index)
                cells = row.locator(".ant-table-cell")
                for cell_index in range(cells.count()):
                    if (cells.nth(cell_index).inner_text() or "").strip() == tagname:
                        return row
        except Exception:
            pass
        return rows.filter(has_text=tagname).first

    def rule_exists(self, tagname: str) -> bool:
        try:
            row = self._row_for_rule(tagname)
            if row.count() == 0 or not row.is_visible():
                return False
            cells = row.locator(".ant-table-cell")
            return any(
                (cells.nth(index).inner_text() or "").strip() == tagname
                for index in range(cells.count())
            )
        except Exception:
            return False

    def get_rule_names(self) -> List[str]:
        """返回列表“名称”列（tagname）去重后的顺序列表。"""
        names: List[str] = []
        try:
            rows = self._list_table().locator("div.ant-table-row")
            for index in range(rows.count()):
                cells = rows.nth(index).locator(".ant-table-cell")
                for cell_index in range(cells.count()):
                    cell = cells.nth(cell_index)
                    if cell.locator("input[type='checkbox']").count() > 0:
                        continue
                    value = (cell.inner_text() or "").strip()
                    if value and value not in ("--",):
                        names.append(value)
                        break
        except Exception:
            pass
        return list(dict.fromkeys(names))

    def get_row_mac(self, tagname: str) -> str:
        """读取某名称所在行的 MAC 地址（用于覆盖语义验证）。"""
        try:
            row = self._row_for_rule(tagname)
            if row.count() == 0:
                return ""
            cells = row.locator(".ant-table-cell")
            texts = [(cells.nth(i).inner_text() or "").strip() for i in range(cells.count())]
            # MAC 形如 00:11:22:33:44:55
            import re as _re
            for text in texts:
                if _re.match(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$", text):
                    return text
        except Exception:
            pass
        return ""

    def get_row_comment(self, tagname: str) -> str:
        """读取某名称所在行的备注（“--”视为空）。"""
        try:
            row = self._row_for_rule(tagname)
            if row.count() == 0:
                return ""
            cells = row.locator(".ant-table-cell")
            texts = [(cells.nth(i).inner_text() or "").strip() for i in range(cells.count())]
            # 过滤掉名称、MAC、操作列，剩下的最长文本作为备注
            import re as _re
            candidates = [
                t for t in texts
                if t and t != "--"
                and not _re.match(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$", t)
                and "编辑" not in t and "删除" not in t
            ]
            return candidates[0] if candidates else ""
        except Exception:
            return ""

    def _click_rule_action(self, tagname: str, action: str) -> bool:
        try:
            row = self._row_for_rule(tagname)
            if row.count() == 0:
                return False
            buttons = row.locator("button:visible").filter(has_text=action)
            for index in range(buttons.count()):
                button = buttons.nth(index)
                if (button.inner_text() or "").strip() == action:
                    button.click()
                    return True
            return False
        except Exception:
            return False

    def edit_rule(self, tagname: str) -> bool:
        if not self._click_rule_action(tagname, "编辑"):
            return False
        for _ in range(20):
            self.page.wait_for_timeout(250)
            if self.is_on_config_page() and self.EDIT_FRAGMENT in self.page.url:
                return True
        return False

    def update_rule(
        self,
        tagname: str,
        *,
        new_tagname: Optional[str] = None,
        mac: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Dict:
        if not self.edit_rule(tagname):
            return {"success": False, "error": "进入终端名称编辑页失败"}
        # 编辑页会带出原值，仅覆盖传入的字段。
        if not self.fill_rule_form(tagname=new_tagname, mac=mac, comment=comment):
            failed = [key for key, ok in self.last_fill_checks.items() if not ok]
            return {
                "success": False,
                "error": "终端名称编辑表单填写不完整: " + ",".join(failed),
                "fill_checks": dict(self.last_fill_checks),
            }
        if new_tagname is not None and self.get_tagname_value() != str(new_tagname):
            self.cancel_rule_form()
            return {"success": False, "error": "编辑后的名称被 maxlength=15 截断"}
        return self.save_rule()

    def delete_rule(self, tagname: str) -> bool:
        if not self._click_rule_action(tagname, "删除"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        for _ in range(18):
            self.page.wait_for_timeout(300)
            if not self.rule_exists(tagname):
                return True
        try:
            self.page.reload()
            self._wait_page(700)
        except Exception:
            pass
        return not self.rule_exists(tagname)

    def clean_test_rules(self, prefix: str = "tn_t_") -> int:
        """只逐条删除测试前缀终端名称，绝不全选或误删存量。"""
        deleted = 0
        for _ in range(200):
            names = [name for name in self.get_rule_names() if name.startswith(prefix)]
            if not names:
                break
            if not self.delete_rule(names[0]):
                break
            deleted += 1
        return deleted

    # ==================== 搜索 ====================
    def search_rule(self, keyword: str):
        try:
            field = self.page.get_by_placeholder("请输入搜索内容")
            field.click()
            field.fill(str(keyword))
            field.press("Enter")
            self.page.wait_for_timeout(600)
        except Exception:
            pass
        return self

    def clear_search(self):
        return self.search_rule("")

    # ==================== 批量操作（终端名称无启用/停用，仅批量删除）====================
    def _clear_body_selection(self):
        try:
            self._list_table().evaluate("""root => {
                root.querySelectorAll(
                    'div.ant-table-row input[type=checkbox]:checked'
                ).forEach(input => input.click());
            }""")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _select_rules(self, tagnames: Iterable[str]) -> int:
        self._clear_body_selection()
        selected = 0
        for tagname in list(tagnames):
            try:
                row = self._row_for_rule(tagname)
                if row.count() == 0:
                    continue
                checked = row.evaluate("""row => {
                    const input = row.querySelector('input[type=checkbox]');
                    if (!input) return false;
                    if (!input.checked) input.click();
                    return !!input.checked;
                }""")
                if checked:
                    selected += 1
                    self.page.wait_for_timeout(180)
            except Exception:
                pass
        self.page.wait_for_timeout(300)
        return selected

    def _click_batch_action(self, action: str) -> bool:
        try:
            return bool(self.page.evaluate("""(action) => {
                const visible = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                for (const footer of document.querySelectorAll('div.footer')) {
                    if (!visible(footer)) continue;
                    const button = [...footer.querySelectorAll('button')].find(
                        item => visible(item) && norm(item.innerText) === action
                    );
                    if (button) { button.click(); return true; }
                }
                return false;
            }""", action))
        except Exception:
            return False

    def _after_batch(self):
        self.page.wait_for_timeout(1000)
        try:
            self.page.reload()
            self._wait_page(700)
        except Exception:
            pass

    def batch_delete_rules(self, tagnames: Iterable[str]) -> bool:
        names = list(tagnames)
        if not names or self._select_rules(names) != len(names):
            return False
        if not self._click_batch_action("删除"):
            return False
        self.page.wait_for_timeout(300)
        if not self._click_visible_confirm(timeout=3500):
            return False
        self._after_batch()
        return all(not self.rule_exists(name) for name in names)

    # ==================== 导入 / 导出 ====================
    def click_import(self):
        self.page.get_by_role("button", name="导入", exact=True).click()
        return self

    def click_export(self):
        self.page.get_by_role("button", name="导出", exact=True).click()
        return self

    def export_rules(
        self, use_config_path: bool = True, export_format: str = "csv"
    ) -> bool:
        return super().export_rules(use_config_path, export_format)

    def import_rules(self, file_path: str, clear_existing: bool = False) -> bool:
        return super().import_rules(file_path, clear_existing)

    def attempt_import(self, file_path: str, clear_existing: bool = False) -> Dict:
        """提交 CSV/TXT，并只按本次可见的明确反馈判定成功或拒绝。

        参考 HTTP 服务的导入实现：显式复述“清空现有配置数据”勾选状态、校验文件
        accept，再按成功/失败关键词给出结构化结论，避免把残留 toast 误判。
        """
        result: Dict = {
            "submitted": False,
            "success": False,
            "rejected": False,
            "clear_state": None,
            "feedback": "",
            "error": "",
        }

        def latest_visible_text(selector: str) -> str:
            try:
                items = self.page.locator(selector)
                for index in range(items.count() - 1, -1, -1):
                    item = items.nth(index)
                    if item.is_visible():
                        text = (item.inner_text() or "").strip()
                        if text:
                            return text[:240]
            except Exception:
                pass
            return ""

        try:
            if not os.path.isfile(file_path):
                result["rejected"] = True
                result["error"] = "导入文件不存在"
                return result
            if os.path.splitext(file_path)[1].lower() not in {".csv", ".txt"}:
                result["rejected"] = True
                result["error"] = "终端名称仅支持CSV/TXT导入"
                return result
            self._wait_transient_feedback_clear(timeout=4000)
            self.click_import()
            modal = self.page.locator(".ant-modal-content:visible").filter(
                has_text="导入"
            ).last
            modal.wait_for(state="visible", timeout=5000)
            checkboxes = modal.locator("input[type='checkbox']")
            if checkboxes.count() < 1:
                result["error"] = f"导入清空选项数量异常: {checkboxes.count()}"
                return result
            checkbox = checkboxes.first
            checkbox.set_checked(bool(clear_existing), force=True)
            self.page.wait_for_timeout(150)
            result["clear_state"] = bool(checkbox.is_checked())
            if result["clear_state"] != bool(clear_existing):
                result["error"] = "清空现有配置选项复读不一致"
                return result
            file_input = modal.locator("input[type='file']")
            if file_input.count() < 1:
                result["error"] = "导入文件控件数量异常"
                return result
            accept = (file_input.first.get_attribute("accept") or "").upper()
            if ".CSV" not in accept or ".TXT" not in accept:
                result["error"] = f"导入控件accept异常: {accept[:80]}"
                return result
            file_input.first.set_input_files(file_path)
            submit = modal.get_by_role("button", name="确定上传", exact=True)
            for _ in range(30):
                if submit.count() == 1 and not submit.is_disabled():
                    break
                self.page.wait_for_timeout(100)
            else:
                result["error"] = "确定上传按钮未启用"
                return result
            submit.click()
            result["submitted"] = True

            error_selectors = (
                ".ant-message-error:visible, "
                ".ant-notification-notice-error:visible, "
                ".ant-alert-error:visible"
            )
            success_selectors = (
                ".ant-message-success:visible, "
                ".ant-notification-notice-success:visible, "
                ".ant-alert-success:visible"
            )
            negative_phrases = (
                "导入失败", "上传失败", "解析失败", "格式错误",
                "格式不正确", "格式不支持", "文件错误", "文件不合法",
                "导入数据有误", "导入有误", "失败原因", "参数错误",
            )
            positive_phrases = (
                "导入成功", "上传成功", "操作成功", "导入完成", "上传完成",
            )
            for _ in range(100):
                error_text = latest_visible_text(error_selectors)
                if error_text:
                    result["rejected"] = True
                    result["feedback"] = error_text
                    result["error"] = error_text
                    break
                success_text = latest_visible_text(success_selectors)
                if success_text:
                    result["success"] = True
                    result["feedback"] = success_text
                    break
                dialogs = self.page.locator(".ant-modal-content:visible")
                dialog_texts = []
                for index in range(dialogs.count()):
                    try:
                        text = (dialogs.nth(index).inner_text() or "").strip()
                        if text:
                            dialog_texts.append(text)
                    except Exception:
                        pass
                joined = "\n".join(dialog_texts)
                negative = next(
                    (phrase for phrase in negative_phrases if phrase in joined), "")
                if negative:
                    result["rejected"] = True
                    result["feedback"] = negative
                    result["error"] = negative
                    break
                positive = next(
                    (phrase for phrase in positive_phrases if phrase in joined), "")
                if positive:
                    result["success"] = True
                    result["feedback"] = positive
                    break
                self.page.wait_for_timeout(100)
            if not result["success"] and not result["rejected"]:
                result["error"] = "已提交但无明确成功/失败反馈"
        except Exception as exc:
            result["error"] = str(exc)[:180]
        finally:
            try:
                visible_modals = self.page.locator(".ant-modal-content:visible")
                for index in range(visible_modals.count() - 1, -1, -1):
                    current = visible_modals.nth(index)
                    text = (current.inner_text() or "").strip()
                    if not any(token in text for token in ("导入", "上传")):
                        continue
                    cancel = current.get_by_role("button", name="取消上传", exact=True)
                    close = current.locator("button.ant-modal-close")
                    safe_close = current.get_by_role("button", name="关闭", exact=True)
                    if cancel.count() > 0 and cancel.first.is_visible():
                        cancel.first.click()
                    elif close.count() > 0 and close.first.is_visible():
                        close.first.click()
                    elif safe_close.count() > 0 and safe_close.first.is_visible():
                        safe_close.first.click()
                    else:
                        self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(100)
            except Exception:
                try:
                    self.page.keyboard.press("Escape")
                except Exception:
                    pass
        return result

    # ==================== 帮助入口 ====================
    def verify_help_entry(self, timeout: int = 8000) -> Dict:
        """验证右下角帮助入口打开 popup，并始终关闭避免孤儿 Tab。"""
        result: Dict = {
            "clicked": False,
            "popup_opened": False,
            "url": "",
            "no_orphan": False,
        }
        context = self.page.context
        before_pages = list(context.pages)
        try:
            if "securityCenter/terminalNameManagement" not in self.page.url:
                self.navigate_to_terminal_name()
            buttons = self.page.locator("button:visible").filter(has_text="帮助")
            if buttons.count() == 0:
                result["error"] = "未找到帮助按钮"
                return result
            result["clicked"] = True
            with self.page.expect_popup(timeout=timeout) as info:
                buttons.first.click()
            popup = info.value
            result["popup_opened"] = True
            for _ in range(20):
                if popup.url and popup.url != "about:blank":
                    break
                popup.wait_for_timeout(150)
            result["url"] = popup.url or ""
        except Exception as exc:
            result["error"] = str(exc)[:160]
        finally:
            for candidate in list(context.pages):
                if candidate in before_pages:
                    continue
                try:
                    if not candidate.is_closed():
                        candidate.close()
                except Exception:
                    pass
            self.page.wait_for_timeout(200)
            result["no_orphan"] = all(
                candidate in before_pages for candidate in context.pages
            )
        return result
