"""
认证服务-认证账号管理-总账管理 页面类

缴费/账单记录列表(ppp_paylog, 日志库 /etc/log/pppuser.db)。记录由账号操作
(开户/缴费)自动生成, 本页只读 + 删除 + 导出 + 搜索 + 排序。继承 IkuaiTablePage。

UI(Playwright 实测):
- 总账管理是"认证账号管理"的第4个 tab(默认套餐管理), 须主动切 tab。
- 列: 账号(username)/用户姓名(name)/收费时间(timestamp, 可排序)/收费人员(admin)/
  描述(action)/收费金额(feemoney, 可排序)/备注(comment)。
- 行内: 删除; 批量(footer 选中): 删除; 工具栏: 导出。无添加(记录自动生成)。
- 排序 .sortIcon(同 VLAN/账号); 搜索 placeholder="请输入搜索内容"(基类兼容)。
- reload 后 tab 会回套餐管理(默认), 用 refresh_list 重新切总账管理 tab。
"""
from typing import Optional, List

from playwright.sync_api import Locator
from pages.ikuai_table_page import IkuaiTablePage


class PppPaylogPage(IkuaiTablePage):
    """认证服务-总账管理页面操作类(只读记录列表)"""

    MODULE_NAME = "ppp_paylog"
    LIST_URL = "/login#/authenticationService/accountCertificationManagement"

    COLUMN_ID_MAP = {
        "账号": "username",
        "用户姓名": "name",
        "收费时间": "timestamp",
        "收费人员": "admin",
        "描述": "action",
        "收费金额": "feemoney",
        "备注": "comment",
    }
    SORTABLE_COLUMNS = ["收费时间", "收费金额"]

    # ==================== 导航 ====================

    def navigate_to_ppp_paylog(self):
        """导航到认证账号管理并切换到"总账管理" tab。"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_paylog_tab()
        return self

    def _switch_to_paylog_tab(self) -> None:
        """切到"总账管理" tab, 并等待 active 生效。"""
        try:
            self.page.locator(".ant-tabs-tab").first.wait_for(state="visible", timeout=8000)
            tabs = self.page.locator(".ant-tabs-tab")
            target = None
            for i in range(tabs.count()):
                if (tabs.nth(i).inner_text() or "").strip() == "总账管理":
                    target = tabs.nth(i)
                    break
            if target is None:
                return
            if "ant-tabs-tab-active" not in (target.get_attribute("class") or ""):
                target.click()
            try:
                self.page.wait_for_function(
                    "() => { const t = Array.from(document.querySelectorAll('.ant-tabs-tab'))"
                    ".find(x => (x.textContent||'').trim() === '总账管理'); "
                    "return t && t.classList.contains('ant-tabs-tab-active'); }",
                    timeout=5000,
                )
            except Exception:
                pass
            self.page.wait_for_timeout(600)
        except Exception:
            pass

    def _ensure_paylog_list(self) -> None:
        """导航回总账管理列表, 切 tab, 并确认表格(th#timestamp)已渲染。"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_paylog_tab()
        try:
            self.page.locator("th#timestamp").first.wait_for(state="visible", timeout=8000)
        except Exception:
            self._switch_to_paylog_tab()
            self.page.wait_for_timeout(800)

    def refresh_list(self) -> None:
        """刷新总账列表: reload 后 tab 回套餐管理(默认), 重新切总账管理 tab。"""
        self.page.reload()
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_paylog_tab()
        try:
            self.page.locator("th#timestamp").first.wait_for(state="visible", timeout=8000)
        except Exception:
            self._switch_to_paylog_tab()
            self.page.wait_for_timeout(800)

    # ==================== 行定位 ====================

    def _find_paylog_row(self, username: str) -> Optional[Locator]:
        """按 账号(username)列完整文本定位数据行(测试造的 username 唯一)。"""
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
            return self._find_paylog_row(username) is not None
        except Exception:
            return False

    def delete_paylog(self, username: str) -> bool:
        """行内删除指定 username 的记录(行内"删除"按钮 + 确认弹窗)。"""
        return self.delete_rule(username)

    # ==================== 列值/列表 ====================

    def get_column_values(self, column_name: str) -> List[str]:
        col_id = self.COLUMN_ID_MAP.get(column_name)
        if not col_id:
            raise ValueError(f"未知总账列: {column_name}")
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

    def get_paylog_usernames(self) -> List[str]:
        """当前页可见的账号列表(注意分页, >阈值只返回当前页)。"""
        return self.get_column_values("账号")

    # ==================== 帮助功能 ====================

    def test_help_functionality(self) -> dict:
        result = {"icon_clickable": False, "panel_visible": False, "has_content": False,
                  "content_text": "", "link_clickable": False, "new_page_opened": False,
                  "url_changed": False, "can_close": False}
        try:
            self._ensure_paylog_list()
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
                    txt = (popover.text_content() or "").strip()
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
