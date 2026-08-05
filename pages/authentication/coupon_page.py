"""
认证服务-认证账号管理-上网码 页面类

上网码(coupon)管理: 单个添加 + 批量生成 + 删除失效 + 状态筛选 + CRUD。
继承 IkuaiTablePage。表 coupon(config.db)。

UI(Playwright 实测):
- 上网码是认证账号管理第5 tab(默认套餐管理), 须主动切 tab。
- 工具栏: 添加/批量生成/导出/删除失效/帮助。无导入、无排序。
- 单码添加(/components/internetCode/add, 点"添加"): username(上网码, 默认随机大写)/
  expiresTmp(过期时间,空=不过期)/hour(限时,默认2)/comment。
- 批量生成(同路由, 点"批量生成"): 类型 radio(纯数字/纯字母/数字+字母) + codeNumber(个数) +
  codeLenght(长度) + expiresTmp/hour/comment。
- 状态筛选 segmented: 全部/已使用/未使用/已过期。
- 列: 上网码(username)/过期时间(expires)/限时(timeout)/使用记录(used)/备注。行内: 编辑/删除。
- 删除失效: 删所有过期码(expires<=now 且 !=0), 确认弹窗"确定要删除所有失效的上网码吗?"。
- 字段映射: expiresTmp→expires(unix,0=不过期), hour→timeout(秒, hour*3600)。
  username 大写存储(${username^^}); reload 后 tab 回套餐管理, 用 refresh_list。
"""
import re
import time
from typing import Optional, List

from playwright.sync_api import Locator
from pages.ikuai_table_page import IkuaiTablePage


class CouponPage(IkuaiTablePage):
    """认证服务-上网码页面操作类"""

    MODULE_NAME = "coupon"
    LIST_URL = "/login#/authenticationService/accountCertificationManagement"

    COLUMN_ID_MAP = {
        "上网码": "username",
        "过期时间": "expires",
        "限时": "timeout",
        "使用记录": "used",
        "备注": "comment",
    }
    STATE_FILTERS = ["全部", "已使用", "未使用", "已过期"]
    CODE_TYPES = ["纯数字", "纯字母", "数字+字母"]

    # ==================== 导航 ====================

    def navigate_to_coupon(self):
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_coupon_tab()
        return self

    def _switch_to_coupon_tab(self) -> None:
        try:
            self.page.locator(".ant-tabs-tab").first.wait_for(state="visible", timeout=8000)
            tabs = self.page.locator(".ant-tabs-tab")
            for i in range(tabs.count()):
                if (tabs.nth(i).inner_text() or "").strip() == "上网码":
                    target = tabs.nth(i)
                    if "ant-tabs-tab-active" not in (target.get_attribute("class") or ""):
                        target.click()
                    try:
                        self.page.wait_for_function(
                            "() => { const t = Array.from(document.querySelectorAll('.ant-tabs-tab'))"
                            ".find(x => (x.textContent||'').trim() === '上网码'); "
                            "return t && t.classList.contains('ant-tabs-tab-active'); }",
                            timeout=5000,
                        )
                    except Exception:
                        pass
                    self.page.wait_for_timeout(600)
                    break
        except Exception:
            pass

    def _ensure_coupon_list(self) -> None:
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_coupon_tab()
        try:
            self.page.locator("th#username").first.wait_for(state="visible", timeout=8000)
        except Exception:
            self._switch_to_coupon_tab()
            self.page.wait_for_timeout(800)

    def refresh_list(self) -> None:
        self.page.reload()
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_coupon_tab()
        try:
            self.page.locator("th#username").first.wait_for(state="visible", timeout=8000)
        except Exception:
            self._switch_to_coupon_tab()
            self.page.wait_for_timeout(800)

    def _panel(self):
        return self.page.locator(".ant-tabs-tabpane-active")

    # ==================== 行定位 ====================

    def _find_coupon_row(self, username: str) -> Optional[Locator]:
        rows = self.page.locator("div.ant-table-tbody div.ant-table-row")
        for i in range(rows.count()):
            row = rows.nth(i)
            cell = row.locator("div.ant-table-cell#username")
            if cell.count() and (cell.first.inner_text() or "").strip() == username:
                return row
        return None

    def rule_exists(self, username: str) -> bool:
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            return self._find_coupon_row(username) is not None
        except Exception:
            return False

    # ==================== 表单通用 ====================

    def _react_set(self, input_id: str, val) -> None:
        """React 表单安全赋值(触发 input/change/blur)。"""
        el = self.page.locator(f"#{input_id}")
        if el.count() == 0:
            return
        el.evaluate(
            "(el, val) => { const p = el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;"
            "Object.getOwnPropertyDescriptor(p,'value').set.call(el, val);"
            "el.dispatchEvent(new Event('input',{bubbles:true}));"
            "el.dispatchEvent(new Event('change',{bubbles:true}));"
            "el.dispatchEvent(new Event('blur',{bubbles:true})); }",
            str(val),
        )

    def _save_success(self, timeout: int = 5000) -> bool:
        success = self.wait_for_success_message(timeout=timeout)
        if not success:
            self.page.wait_for_timeout(800)
            success = self.page.locator("#username, #codeNumber").count() == 0
        return success

    # ==================== 单码添加 ====================

    def add_coupon(self, username: str = None, hour: int = 2,
                   comment: str = None, expires_tmp: str = None) -> bool:
        """添加单个上网码。username 为空则用前端默认随机码。"""
        self._ensure_coupon_list()
        self.click_add_button()
        try:
            self.page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        if username is not None:
            self._react_set("username", username)
        if expires_tmp is not None:
            self._react_set("expiresTmp", expires_tmp)
        self._react_set("hour", hour)
        if comment is not None:
            self._react_set("comment", comment)
        self.click_save()
        ok = self._save_success()
        if ok:
            self.page.wait_for_timeout(800)
        return ok

    # ==================== 批量生成 ====================

    def select_code_type(self, code_type: str) -> bool:
        """选批量生成类型 radio: 纯数字/纯字母/数字+字母。"""
        if code_type not in self.CODE_TYPES:
            return False
        try:
            wrappers = self.page.locator(".ant-radio-wrapper")
            for i in range(wrappers.count()):
                txt = (wrappers.nth(i).inner_text() or "").strip()
                if txt == code_type:
                    wrappers.nth(i).click()
                    self.page.wait_for_timeout(300)
                    return True
        except Exception:
            pass
        return False

    def batch_generate(self, code_number: int, code_length: int, code_type: str = "数字+字母",
                       hour: int = 2, comment: str = None, expires_tmp: str = None) -> bool:
        """批量生成上网码。点"批量生成"按钮进批量表单, 填参保存。"""
        self._ensure_coupon_list()
        self.page.get_by_role("button", name="批量生成").click()
        try:
            self.page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        self.select_code_type(code_type)
        self._react_set("codeNumber", code_number)
        self._react_set("codeLenght", code_length)
        if expires_tmp is not None:
            self._react_set("expiresTmp", expires_tmp)
        self._react_set("hour", hour)
        if comment is not None:
            self._react_set("comment", comment)
        self.click_save()
        ok = self._save_success()
        if ok:
            self.page.wait_for_timeout(1000)
        return ok

    # ==================== 删除失效 ====================

    def delete_invalid(self) -> bool:
        """删除所有失效(过期)上网码: 点"删除失效" + 确认弹窗。"""
        self._ensure_coupon_list()
        btn = self.page.get_by_role("button", name="删除失效")
        if btn.count() == 0:
            return False
        btn.click()
        self.page.wait_for_timeout(600)
        return self._click_visible_confirm(timeout=4000)

    # ==================== 编辑/删除 ====================

    def edit_coupon(self, username: str) -> bool:
        clicked = self._click_rule_button(username, "编辑")
        if clicked:
            self.page.wait_for_timeout(500)
        return clicked

    def delete_coupon(self, username: str) -> bool:
        return self.delete_rule(username)

    # ==================== 状态筛选 ====================

    def filter_by_state(self, state: str) -> bool:
        if state not in self.STATE_FILTERS:
            return False
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)
            seg = self.page.locator("label.ant-segmented-item", has_text=state)
            if seg.count() == 0:
                return False
            seg.first.click()
            self.page.wait_for_timeout(800)
            return True
        except Exception:
            return False

    def get_state_counts(self) -> dict:
        """读取状态筛选统计 {全部:N, 已使用:N, 未使用:N, 已过期:N}。"""
        result = {}
        try:
            for item in self.page.locator("label.ant-segmented-item").all():
                txt = (item.inner_text() or "").strip()
                m = re.match(r"(全部|已使用|未使用|已过期)\((\d+)\)", txt)
                if m:
                    result[m.group(1)] = int(m.group(2))
        except Exception:
            pass
        return result

    # ==================== 列值/列表 ====================

    def get_column_values(self, column_name: str) -> List[str]:
        col_id = self.COLUMN_ID_MAP.get(column_name)
        if not col_id:
            raise ValueError(f"未知上网码列: {column_name}")
        values: List[str] = []
        rows = self.page.locator("div.ant-table-tbody div.ant-table-row")
        if rows.count() == 0 and self.get_rule_count() > 0:
            rows.first.wait_for(state="visible", timeout=5000)
        for i in range(rows.count()):
            cell = rows.nth(i).locator(f"div.ant-table-cell#{col_id}")
            if cell.count() == 0:
                continue
            values.append((cell.first.inner_text() or "").strip())
        return values

    def get_coupon_list(self) -> List[str]:
        return self.get_column_values("上网码")

    # ==================== 帮助功能 ====================

    def test_help_functionality(self) -> dict:
        result = {"icon_clickable": False, "panel_visible": False, "has_content": False,
                  "content_text": "", "link_clickable": False, "new_page_opened": False,
                  "url_changed": False, "can_close": False}
        try:
            self._ensure_coupon_list()
            help_btn = self.page.locator('button:has-text("帮助")').first
            if help_btn.count() == 0:
                return result
            new_page = None
            try:
                with self.page.context.expect_page(timeout=4000) as np:
                    help_btn.click()
                new_page = np.value
                result["icon_clickable"] = True
                result["new_page_opened"] = True
                result["link_clickable"] = True
            except Exception:
                try:
                    help_btn.click()
                    result["icon_clickable"] = True
                except Exception:
                    pass
            try:
                popover = self.page.locator(".ant-popover").last
                if popover.count() > 0 and popover.is_visible():
                    result["panel_visible"] = True
                    txt = (popover.text_content() or "").trim()
                    result["content_text"] = txt
                    result["has_content"] = bool(txt)
            except Exception:
                pass
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)
                result["can_close"] = True
            except Exception:
                pass
            if new_page is not None:
                try:
                    new_page.close()
                except Exception:
                    pass
        except Exception:
            pass
        return result
