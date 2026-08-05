"""
认证服务-认证账号管理-账号管理 页面类

处理账号(pppuser)的增删改查、启用/停用、排序、状态筛选、套餐联动等操作。
继承 IkuaiTablePage 获取通用表格操作。

产品特性(Playwright实测确认):
- 账号管理是"认证账号管理"的第2个 tab(默认是套餐管理), 需主动切换。
- 表 pppuser 字段: username/passwd(加密存储)/enabled(yes|no)/ppptype(8种拨号类型)/
  packages(套餐id, 0=自定义)/expires(过期unix时间戳, 0=永不过期)/upload|download
  (上下行限速, UI 显示为 up_speed|down_speed)/share(共享数)/mac/bind_vlanid/
  auto_vlanid/bind_ifname/ip_type/src_addr/name/phone/cardid/address/comment 等。
- 行内操作: 编辑/停用(或启用)/缴费/删除; 工具栏仅 添加/导入/导出(无批量启停)。
- 可排序列: 账号(username)/用户姓名(name)/到期时间(expires)/在线离线时长(duration)。
- 状态筛选: ant-segmented 组件 全部/已启用/已停用/已过期。
- 套餐联动: packages 下拉 = "自定义"(packages=0) + 套餐管理已建套餐(packages=套餐id, 显示 packname)。
- 搜索框 placeholder="请输入搜索内容"(与基类一致, 无需覆盖)。
- 添加/编辑共用独立路由 /components/account/add(非弹窗)。
"""
import re
import time
from typing import Optional, List

from playwright.sync_api import Page, Locator
from pages.ikuai_table_page import IkuaiTablePage


# 认证类型 中文(下拉显示) <-> 后端 ppptype
_PPPTYPE_CN_TO_VAL = {
    "不限": "any", "PPPoE": "pppoe", "PPPoE透传": "pppoe_relay",
    "WEB-账号": "web", "OpenVPN": "ovpn", "L2TP": "l2tp",
    "PPTP": "pptp", "IKEv2": "ike",
}


class PppuserPage(IkuaiTablePage):
    """认证服务-账号管理页面操作类"""

    MODULE_NAME = "pppuser"

    LIST_URL = "/login#/authenticationService/accountCertificationManagement"
    ADD_URL = "/login#/authenticationService/accountCertificationManagement/components/account/add"

    # 列名 -> HTML id
    COLUMN_ID_MAP = {
        "账号": "username",
        "用户姓名": "name",
        "认证类型": "ppptype",
        "当前套餐": "packages",
        "到期时间": "expires",
        "在线/离线时长": "duration",
        "备注": "comment",
    }
    # 可排序列(实测 th.ant-table-column-has-sorters)
    SORTABLE_COLUMNS = ["账号", "用户姓名", "到期时间", "在线/离线时长"]
    # 状态筛选(ant-segmented)
    STATE_FILTERS = ["全部", "已启用", "已停用", "已过期"]

    # ==================== 导航 ====================

    def navigate_to_pppuser(self):
        """导航到认证账号管理并切换到"账号管理" tab。"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_account_tab()
        return self

    def _switch_to_account_tab(self) -> None:
        """从默认的"套餐管理" tab 切到"账号管理" tab, 并等待 active 生效。"""
        try:
            self.page.locator(".ant-tabs-tab").first.wait_for(state="visible", timeout=8000)
            tabs = self.page.locator(".ant-tabs-tab")
            target = None
            for i in range(tabs.count()):
                if (tabs.nth(i).inner_text() or "").strip() == "账号管理":
                    target = tabs.nth(i)
                    break
            if target is None:
                return
            if "ant-tabs-tab-active" not in (target.get_attribute("class") or ""):
                target.click()
            # 等待账号管理 tab 真正激活(避免点击后异步未生效读到旧 tab 数据)
            try:
                self.page.wait_for_function(
                    "() => { const t = Array.from(document.querySelectorAll('.ant-tabs-tab'))"
                    ".find(x => (x.textContent||'').trim() === '账号管理'); "
                    "return t && t.classList.contains('ant-tabs-tab-active'); }",
                    timeout=5000,
                )
            except Exception:
                pass
            self.page.wait_for_timeout(600)
        except Exception:
            pass

    def _ensure_user_list(self) -> None:
        """导航回账号管理列表, 切到账号 tab, 并确认账号表格(th#username)已渲染。"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_account_tab()
        # 确认在账号管理 tab(th#username 是账号列特征, 套餐 tab 无此列)
        try:
            self.page.locator("th#username").first.wait_for(state="visible", timeout=8000)
        except Exception:
            # tab 可能未切对, 重试一次
            self._switch_to_account_tab()
            self.page.wait_for_timeout(1000)

    def refresh_list(self) -> None:
        """刷新账号列表: reload 后默认 tab 会回到"套餐管理", 这里重新切到"账号管理"并确认表格。

        测试中所有需要刷新账号列表的场景都应用本方法替代 page.reload(),
        否则会读到套餐 tab 的数据(activeTab=套餐管理)。
        """
        self.page.reload()
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self._switch_to_account_tab()
        try:
            self.page.locator("th#username").first.wait_for(state="visible", timeout=8000)
        except Exception:
            self._switch_to_account_tab()
            self.page.wait_for_timeout(800)

    def navigate_to_add_page(self):
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        return self

    # ==================== 行定位 ====================

    def _find_user_row(self, username: str) -> Optional[Locator]:
        """按 账号(username)列完整文本定位数据行。"""
        rows = self.page.locator("div.ant-table-tbody div.ant-table-row")
        for i in range(rows.count()):
            row = rows.nth(i)
            cell = row.locator("div.ant-table-cell#username")
            if cell.count() and (cell.first.inner_text() or "").strip() == username:
                return row
        return None

    def _click_rule_button(self, username: str, button_name: str) -> bool:
        """覆盖基类: 按 username 列精确匹配行, 点行内按钮(编辑/停用/启用/缴费/删除)。"""
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(300)
        try:
            deadline = time.monotonic() + 5
            row = None
            while time.monotonic() < deadline:
                row = self._find_user_row(username)
                if row is not None:
                    break
                self.page.wait_for_timeout(200)
            if row is None:
                print(f"[DEBUG] 账号精确行不存在: {username}")
                return False
            buttons = row.locator("button")
            for i in range(buttons.count()):
                b = buttons.nth(i)
                if (b.inner_text() or "").strip() == button_name:
                    b.click()
                    return True
            print(f"[DEBUG] 账号 {username} 行未找到按钮 {button_name}")
            return False
        except Exception as exc:
            print(f"[DEBUG] 账号行按钮点击失败: {str(exc)[:80]}")
            return False

    def rule_exists(self, username: str) -> bool:
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            return self._find_user_row(username) is not None
        except Exception:
            return False

    # ==================== 表单字段 ====================

    def _select_combobox_value_by_id(self, input_id: str, value: str) -> None:
        """在指定 Ant Select 选值并复读(参考 VLAN/套餐)。"""
        combobox = self.page.locator(f"#{input_id}")
        if combobox.count() != 1:
            raise AssertionError(f"下拉框#{input_id}数量不为1: {combobox.count()}")
        selected_value = (
            "el => el.closest('.ant-select-selector')"
            "?.querySelector('.ant-select-selection-item')?.textContent?.trim() || ''"
        )
        if combobox.evaluate(selected_value) == value:
            return
        selector = combobox.locator(
            "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '), "
            "' ant-select-selector ')]"
        ).first
        if selector.count() != 1:
            raise AssertionError(f"下拉框#{input_id}缺少唯一 Ant Select 容器")
        selector.click(timeout=5000)
        dropdown = self.page.locator(".ant-select-dropdown:visible").last
        dropdown.wait_for(state="visible", timeout=5000)
        option = dropdown.get_by_title(value, exact=True)
        if option.count() != 1:
            raise AssertionError(f"下拉框#{input_id}选项{value!r}数量不为1: {option.count()}")
        option.click(force=True, timeout=5000)
        if combobox.evaluate(selected_value) != value:
            raise AssertionError(f"下拉框#{input_id}选择失败: 期望{value}")

    def fill_username(self, v): self.page.locator("#username").fill(v); return self
    def fill_passwd(self, v): self.page.locator("#passwd").fill(v); return self
    def fill_share(self, v): self.page.locator("#share").fill(str(v)); return self
    def fill_up_speed(self, v): self.page.locator("#up_speed").fill(str(v)); return self
    def fill_down_speed(self, v): self.page.locator("#down_speed").fill(str(v)); return self
    def fill_name(self, v): self.page.locator("#name").fill(v); return self
    def fill_phone(self, v): self.page.locator("#phone").fill(v); return self
    def fill_cardid(self, v): self.page.locator("#cardid").fill(v); return self
    def fill_address(self, v): self.page.locator("#address").fill(v); return self
    def fill_comment(self, v): self.page.locator("#comment").fill(v or ""); return self
    def fill_expires(self, v): self.page.locator("#expires").fill(str(v)); return self

    def select_ppptype(self, type_cn: str):
        """选择认证类型(中文): 不限/PPPoE/PPPoE透传/WEB-账号/OpenVPN/L2TP/PPTP/IKEv2"""
        if type_cn:
            self._select_combobox_value_by_id("ppptype", type_cn)
        return self

    def select_package(self, pkg_display: str):
        """选套餐: '自定义'(packages=0) 或 已建套餐名(packname, packages=套餐id)。"""
        self._select_combobox_value_by_id("packages", pkg_display)
        return self

    def _fill_user_form(self, user: dict):
        """填账号表单。user 支持字段:
        username, passwd, ppptype(中文), package(显示名: 自定义/套餐名),
        up_speed, down_speed, share, name, phone, cardid, address, comment, expires。"""
        self.fill_username(user["username"])
        self.fill_passwd(user["passwd"])
        if user.get("ppptype"):
            self.select_ppptype(user["ppptype"])
        if user.get("package"):
            self.select_package(user["package"])
        # 选套餐时上下行限速由套餐决定(input disabled), 仅自定义套餐才填
        _is_custom_pkg = (not user.get("package")) or user.get("package") == "自定义"
        if _is_custom_pkg:
            if user.get("up_speed") is not None:
                self.fill_up_speed(user["up_speed"])
            if user.get("down_speed") is not None:
                self.fill_down_speed(user["down_speed"])
        if user.get("share") is not None:
            self.fill_share(user["share"])
        for key in ("name", "phone", "cardid", "address"):
            if user.get(key):
                getattr(self, f"fill_{key}")(user[key])
        if user.get("comment") is not None:
            self.fill_comment(user["comment"])
        if user.get("expires"):
            self.fill_expires(user["expires"])
        return self

    def _save_success(self, timeout: int = 5000) -> bool:
        success = self.wait_for_success_message(timeout=timeout)
        if not success:
            self.page.wait_for_timeout(800)
            success = self.page.locator("#username").count() == 0
        return success

    # ==================== 添加/异常 ====================

    def add_user(self, user: dict) -> bool:
        """添加账号完整流程。"""
        self._ensure_user_list()
        self.click_add_button()
        try:
            self.page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        self._fill_user_form(user)
        self.click_save()
        ok = self._save_success()
        if ok:
            self.page.wait_for_timeout(800)
        return ok

    def try_add_user_invalid(self, user: dict) -> dict:
        """尝试添加不合规账号(异常测试)。"""
        result = {"success": False, "error_msg": "", "has_validation_error": False}
        try:
            self._ensure_user_list()
            self.click_add_button()
            try:
                self.page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
            self._fill_user_form(user)
            self.click_save()
            self.page.wait_for_timeout(700)
            err = self.page.locator(
                ".ant-form-item-explain-error, .ant-input-status-error, .ant-select-status-error"
            )
            if err.count() > 0:
                result["has_validation_error"] = True
                texts = self.page.locator(".ant-form-item-explain-error").all_text_contents()
                msgs = [t.strip() for t in texts if t.strip()]
                result["error_msg"] = "; ".join(msgs) if msgs else "表单验证失败"
            if not result["error_msg"]:
                msg = self.page.locator(".ant-message-error, .ant-notification-error")
                if msg.count() > 0:
                    result["error_msg"] = (msg.first.text_content() or "操作失败").strip()
                    result["has_validation_error"] = True
            form_open = self.page.locator("#username").count() > 0
            result["success"] = not result["has_validation_error"] and not form_open
        except Exception as e:
            result["error_msg"] = str(e)[:120]
        finally:
            try:
                self._ensure_user_list()
            except Exception:
                pass
        return result

    # ==================== 编辑/删除/启用/停用 ====================

    def edit_user(self, username: str) -> bool:
        clicked = self._click_rule_button(username, "编辑")
        if clicked:
            self.page.wait_for_timeout(500)
        return clicked

    def delete_user(self, username: str) -> bool:
        return self.delete_rule(username)

    def disable_user(self, username: str) -> bool:
        """停用账号(行内"停用"按钮 + 确认弹窗)。返回操作是否发起。"""
        clicked = self._click_rule_button(username, "停用")
        if not clicked:
            return False
        self.page.wait_for_timeout(500)
        self._click_visible_confirm(timeout=4000)
        try:
            self.page.wait_for_selector(".ant-message-success", timeout=3000)
        except Exception:
            pass
        return True

    def enable_user(self, username: str) -> bool:
        """启用账号(行内"启用"按钮, 无确认弹窗)。"""
        clicked = self._click_rule_button(username, "启用")
        if not clicked:
            return False
        try:
            self.page.wait_for_selector(".ant-message-success", timeout=3000)
        except Exception:
            pass
        return True

    def is_user_enabled(self, username: str) -> bool:
        """行内有"停用"按钮 = 已启用。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            row = self._find_user_row(username)
            if not row:
                return False
            btns = row.locator("button")
            for i in range(btns.count()):
                if (btns.nth(i).inner_text() or "").strip() == "停用":
                    return True
            return False
        except Exception:
            return False

    def is_user_disabled(self, username: str) -> bool:
        """行内有"启用"按钮 = 已停用。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            row = self._find_user_row(username)
            if not row:
                return False
            btns = row.locator("button")
            for i in range(btns.count()):
                if (btns.nth(i).inner_text() or "").strip() == "启用":
                    return True
            return False
        except Exception:
            return False

    # ==================== 排序(自定义 .sortIcon, 同 VLAN) ====================
    # 注: 账号管理排序 icon 是自定义 .sortIcon(非 Ant 标准 .ant-table-column-sorter),
    # 与 VLAN 完全一致, 直接继承基类 sort_by_column(hover th + 点 .sortIcon svg)即可, 无需覆盖。
    # 实测: 点 .sortIcon 触发排序(aria-sort: ascending/descending), 升序降序互逆。

    def get_column_sort_order(self, column_name: str) -> str:
        """读取列当前排序状态(aria-sort): 'ascend'/'descend'/''(未排序)。"""
        col_id = self.COLUMN_ID_MAP.get(column_name)
        if not col_id:
            return ""
        try:
            th = self.page.locator(f"th#{col_id}").first
            aria = (th.get_attribute("aria-sort") or "").lower()
            if "asc" in aria:
                return "ascend"
            if "desc" in aria:
                return "descend"
        except Exception:
            pass
        return ""

    # ==================== 状态筛选(ant-segmented) ====================

    def filter_by_state(self, state: str) -> bool:
        """切换状态筛选: 全部/已启用/已停用/已过期。"""
        if state not in self.STATE_FILTERS:
            return False
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)
            seg = self.page.locator("label.ant-segmented-item", has_text=state)
            if seg.count() == 0:
                print(f"[DEBUG] 未找到状态筛选项: {state}")
                return False
            seg.first.click()
            self.page.wait_for_timeout(800)
            return True
        except Exception as exc:
            print(f"[DEBUG] filter_by_state 异常: {str(exc)[:80]}")
            return False

    def get_active_state(self) -> str:
        """读取当前激活的状态筛选项。"""
        try:
            sel = self.page.locator("label.ant-segmented-item-selected")
            if sel.count() > 0:
                return (sel.first.inner_text() or "").strip()
        except Exception:
            pass
        return ""

    # ==================== 列值/列表/选中计数 ====================

    def get_column_values(self, column_name: str) -> List[str]:
        col_id = self.COLUMN_ID_MAP.get(column_name)
        if not col_id:
            raise ValueError(f"未知账号列: {column_name}")
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

    def get_user_list(self) -> List[str]:
        return self.get_column_values("账号")

    def get_selected_count(self) -> int:
        try:
            t = self.page.locator("text=/已选\\s*\\d+\\s*条/")
            if t.count() > 0:
                m = re.search(r"已选\s*(\d+)\s*条", t.first.inner_text())
                if m:
                    return int(m.group(1))
        except Exception:
            pass
        return 0

    # ==================== 帮助功能 ====================

    def test_help_functionality(self) -> dict:
        result = {"icon_clickable": False, "panel_visible": False, "has_content": False,
                  "content_text": "", "link_clickable": False, "new_page_opened": False,
                  "url_changed": False, "can_close": False}
        try:
            self._ensure_user_list()
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

    # ==================== 别名 ====================
    def user_exists(self, username): return self.rule_exists(username)
    def get_user_count(self): return self.get_rule_count()
