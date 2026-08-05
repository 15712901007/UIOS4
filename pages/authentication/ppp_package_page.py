"""
认证服务-认证账号管理-套餐管理 页面类

处理套餐(ppp_packages)的增删改查、复制、导入导出、批量删除等操作。
继承 IkuaiTablePage 获取通用表格操作。

产品差异(经Playwright实测确认):
- 套餐管理无启用/停用概念(ppp_packages 表无 enabled 字段),
  行内操作只有 编辑/复制/删除; 批量操作(选中后底部 footer)只有"删除"。
- 套餐时长(packtime)在 UI 上拆成 "周期类型(select: 月/天/小时)" + "有效期数字",
  提交后端时组合成 "1m"(月)/"30d"(天)/"12h"(小时) 单字段。
- 搜索框 placeholder 为 "套餐名称/备注"(与基类默认的"请输入搜索内容"不同)。
- 添加/编辑共用独立路由 Config 页(非弹窗), 与 VLAN 同模式。
"""
import re
import time
from typing import Optional, List

from playwright.sync_api import Page, Locator
from pages.ikuai_table_page import IkuaiTablePage


# 后端 packtime 后缀(m/d/h) <-> 前端周期类型下拉选项(月/天/小时)
_PACKTIME_TYPE_MAP = {"m": "月", "d": "天", "h": "小时"}


class PppPackagePage(IkuaiTablePage):
    """认证服务-套餐管理页面操作类"""

    MODULE_NAME = "ppp_package"

    # 页面 URL 路径
    LIST_URL = "/login#/authenticationService/accountCertificationManagement"
    CONFIG_URL = "/login#/authenticationService/accountCertificationManagementConfig"

    # 列名 -> HTML id 映射(用于排序/读列值)
    COLUMN_ID_MAP = {
        "套餐名称": "packname",
        "有效期": "packtime",
        "套餐价格": "price",
        "上行带宽": "up_speed",
        "下行带宽": "down_speed",
        "备注": "comment",
    }

    # 搜索框 placeholder(套餐搜索框文案与基类默认不同)
    SEARCH_PLACEHOLDER = "套餐名称/备注"

    # ==================== 导航 ====================

    def navigate_to_ppp_package(self):
        """导航到认证账号管理-套餐管理(默认即套餐管理 tab)。"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        # 兜底: 确保停留在"套餐管理" tab(默认激活, 极少需要点击)
        try:
            tab = self.page.locator(".ant-tabs-tab", has_text="套餐管理")
            if tab.count() and "ant-tabs-tab-active" not in (tab.first.get_attribute("class") or ""):
                tab.first.click()
                self.page.wait_for_timeout(300)
        except Exception:
            pass
        return self

    def _ensure_package_list(self) -> None:
        """单一导航回套餐列表, 并确认工具栏(添加按钮)已渲染。"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        try:
            self.page.get_by_role("button", name="添加").first.wait_for(
                state="visible", timeout=8000
            )
        except Exception:
            pass

    # ==================== 行定位 ====================

    def _find_package_row(self, packname: str) -> Optional[Locator]:
        """按 套餐名称(packname)列的完整文本定位数据行, 避免前缀互相命中。"""
        rows = self.page.locator("div.ant-table-tbody div.ant-table-row")
        for index in range(rows.count()):
            row = rows.nth(index)
            cell = row.locator("div.ant-table-cell#packname")
            if cell.count() and (cell.first.inner_text() or "").strip() == packname:
                return row
        return None

    def _click_rule_button(self, packname: str, button_name: str) -> bool:
        """只点击套餐精确名称所在行的操作按钮(编辑/复制/删除)。

        覆盖基类: 用 packname 列精确匹配代替 get_by_text 模糊匹配,
        避免前缀名称互相命中(如 pkg_1 命中 pkg_10)。
        """
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(300)
        try:
            deadline = time.monotonic() + 5
            row = None
            while time.monotonic() < deadline:
                row = self._find_package_row(packname)
                if row is not None:
                    break
                self.page.wait_for_timeout(200)
            if row is None:
                print(f"[DEBUG] 套餐精确行不存在: {packname}")
                return False
            buttons = row.locator("button")
            for index in range(buttons.count()):
                button = buttons.nth(index)
                if (button.inner_text() or "").strip() == button_name:
                    button.click()
                    return True
            print(f"[DEBUG] 套餐 {packname} 行中未找到按钮 {button_name}")
            return False
        except Exception as exc:
            print(f"[DEBUG] 套餐行按钮点击失败: {str(exc)[:100]}")
            return False

    def rule_exists(self, packname: str) -> bool:
        """检查套餐精确名称的数据行是否存在(覆盖基类模糊匹配)。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            return self._find_package_row(packname) is not None
        except Exception:
            return False

    # ==================== packtime 解析 ====================

    @staticmethod
    def _parse_packtime(packtime: str):
        """把后端 packtime(如 '1m'/'30d'/'12h') 解析为(周期类型中文, 数字)。

        UI 上 packtime 拆成"周期类型 select + 有效期数字", 提交时组合成单字段。
        无后缀或无法识别时默认按"月"处理。
        """
        if packtime is None or packtime == "":
            return ("月", "")
        m = re.match(r"^\s*(\d+)\s*([mdhMDH])?$", str(packtime))
        if not m:
            return ("月", str(packtime))
        num = m.group(1)
        suffix = (m.group(2) or "m").lower()
        return (_PACKTIME_TYPE_MAP.get(suffix, "月"), num)

    # ==================== 表单字段填写 ====================

    def _select_combobox_value_by_id(self, input_id: str, value: str) -> None:
        """在指定 Ant Select 上选择值, 并复读实际选择结果(参考 VLAN)。"""
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
            raise AssertionError(f"下拉框#{input_id}缺少唯一Ant Select容器")
        selector.click(timeout=5000)
        dropdown = self.page.locator(".ant-select-dropdown:visible").last
        dropdown.wait_for(state="visible", timeout=5000)
        option = dropdown.get_by_title(value, exact=True)
        if option.count() != 1:
            raise AssertionError(
                f"下拉框#{input_id}中选项{value!r}数量不为1: {option.count()}"
            )
        option.click(force=True, timeout=5000)
        actual = combobox.evaluate(selected_value)
        if actual != value:
            raise AssertionError(f"下拉框#{input_id}选择失败: 期望{value}, 实际{actual}")

    def fill_packname(self, name: str):
        self.page.locator("#packname").fill(name)
        return self

    def select_packtime_type(self, type_cn: str):
        """选择周期类型: 月/天/小时"""
        self._select_combobox_value_by_id("packtime_type", type_cn)
        return self

    def fill_packtime(self, num):
        self.page.locator("#packtime").fill(str(num))
        return self

    def fill_price(self, price):
        self.page.locator("#price").fill(str(price))
        return self

    def fill_up_speed(self, speed):
        self.page.locator("#up_speed").fill(str(speed))
        return self

    def fill_down_speed(self, speed):
        self.page.locator("#down_speed").fill(str(speed))
        return self

    def fill_comment(self, comment: str):
        self.page.locator("#comment").fill(comment or "")
        return self

    def _fill_form(self, packname, packtime, price, up_speed, down_speed, comment):
        """填完整套餐表单。packtime 用后端格式(如 1m), 内部解析为 周期类型+数字。"""
        type_cn, num = self._parse_packtime(packtime)
        self.fill_packname(packname)
        self.select_packtime_type(type_cn)
        self.fill_packtime(num)
        self.fill_price(price)
        self.fill_up_speed(up_speed)
        self.fill_down_speed(down_speed)
        if comment is not None:
            self.fill_comment(comment)
        return self

    def _save_success(self, timeout: int = 5000) -> bool:
        """判断保存是否成功: 成功提示 或 跳回列表(Config 页 #packname 消失)。"""
        success = self.wait_for_success_message(timeout=timeout)
        if not success:
            # 回退: Config 页保存成功会跳回列表, #packname 输入框消失
            self.page.wait_for_timeout(800)
            success = self.page.locator("#packname").count() == 0
        return success

    # ==================== 添加套餐 ====================

    def add_package(self, packname: str, packtime: str = "1m",
                    price=0, up_speed=0, down_speed=0,
                    comment: Optional[str] = None) -> bool:
        """添加套餐完整流程。packtime 为后端格式(1m/30d/12h)。"""
        self._ensure_package_list()
        self.click_add_button()
        try:
            self.page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        self._fill_form(packname, packtime, price, up_speed, down_speed, comment)
        self.click_save()
        success = self._save_success()
        if success:
            self.page.wait_for_timeout(1000)
        return success

    def try_add_package_invalid(self, packname: str, packtime: str = "1m",
                                price=0, up_speed=0, down_speed=0,
                                comment: Optional[str] = None) -> dict:
        """尝试添加不合规套餐(异常测试), 返回校验结果字典。

        返回:
            {"success": bool, "error_msg": str, "has_validation_error": bool}
            success=True 表示配置被写入(异常未拦截); False 表示被拦截。
        """
        result = {"success": False, "error_msg": "", "has_validation_error": False}
        try:
            self._ensure_package_list()
            self.click_add_button()
            try:
                self.page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
            self._fill_form(packname, packtime, price, up_speed, down_speed, comment)
            self.click_save()
            self.page.wait_for_timeout(700)

            # 表单校验错误(.ant-form-item-explain-error / status-error)
            err_locator = self.page.locator(
                ".ant-form-item-explain-error, .ant-input-status-error, .ant-select-status-error"
            )
            if err_locator.count() > 0:
                result["has_validation_error"] = True
                err_texts = self.page.locator(".ant-form-item-explain-error").all_text_contents()
                msgs = [t.strip() for t in err_texts if t.strip()]
                result["error_msg"] = "; ".join(msgs) if msgs else "表单验证失败"

            # 服务端/通用错误消息提示
            if not result["error_msg"]:
                msg = self.page.locator(".ant-message-error, .ant-notification-error")
                if msg.count() > 0:
                    result["error_msg"] = (msg.first.text_content() or "操作失败").strip()
                    result["has_validation_error"] = True

            # 添加是独立路由 Config 页, 保存成功会跳回列表; 表单仍在 = 未提交成功
            form_still_open = self.page.locator("#packname").count() > 0
            result["success"] = not result["has_validation_error"] and not form_still_open
        except Exception as e:
            result["error_msg"] = str(e)[:120]
            result["success"] = False
        finally:
            # 必须显式回列表; 否则停留在 Config 路由会干扰下一用例
            try:
                self._ensure_package_list()
            except Exception:
                pass
        return result

    # ==================== 编辑/复制/删除 ====================

    def edit_package(self, packname: str) -> bool:
        """点击编辑按钮进入编辑页(Config 页, 带数据回填)。"""
        clicked = self._click_rule_button(packname, "编辑")
        if clicked:
            self.page.wait_for_timeout(500)
        return clicked

    def copy_package(self, packname: str) -> bool:
        """点击复制按钮进入 Config 页(预填源套餐数据, 需改名后保存)。"""
        clicked = self._click_rule_button(packname, "复制")
        if clicked:
            self.page.wait_for_timeout(500)
        return clicked

    def delete_package(self, packname: str) -> bool:
        """删除指定套餐(行内删除 + 确认弹窗)。"""
        return self.delete_rule(packname)

    # ==================== 列值/排序/搜索 ====================

    def get_column_values(self, column_name: str) -> List[str]:
        """读取某列当前可见值(用于验证排序真实顺序而非只验证点击)。"""
        column_id = self.COLUMN_ID_MAP.get(column_name)
        if not column_id:
            raise ValueError(f"未知套餐列: {column_name}")
        values: List[str] = []
        rows = self.page.locator("div.ant-table-tbody div.ant-table-row")
        if rows.count() == 0 and self.get_rule_count() > 0:
            rows.first.wait_for(state="visible", timeout=5000)
        for index in range(rows.count()):
            cell = rows.nth(index).locator(f"div.ant-table-cell#{column_id}")
            if cell.count() == 0:
                continue
            values.append((cell.first.inner_text() or "").strip())
        return values

    def get_package_list(self) -> List[str]:
        """获取所有套餐名称列表(packname 列)。"""
        return self.get_column_values("套餐名称")

    def search_rule(self, keyword: str):
        """覆盖基类: 套餐搜索框 placeholder='套餐名称/备注'。"""
        search_input = self.page.get_by_placeholder(self.SEARCH_PLACEHOLDER)
        search_input.click()
        search_input.clear()
        search_input.fill(keyword)
        search_input.press("Enter")
        self.page.wait_for_timeout(600)
        return self

    def clear_search(self):
        """覆盖基类: 清空套餐搜索。"""
        search_input = self.page.get_by_placeholder(self.SEARCH_PLACEHOLDER)
        if search_input.count() > 0:
            search_input.click()
            search_input.clear()
            search_input.press("Enter")
            self.page.wait_for_timeout(600)
        return self

    # ==================== 帮助功能 ====================

    def test_help_functionality(self) -> dict:
        """测试右下角帮助按钮: 点击后弹出 popover(套餐设置说明) 并打开新标签页跳转文档。

        实测: 套餐页点"帮助"会同时弹出 ant-popover(文案"套餐的设置界面") 且
        打开新 tab 跳转到 ikuai8 帮助文档, 与 VLAN 等模块帮助模式一致。
        """
        result = {
            "icon_clickable": False,
            "panel_visible": False,
            "has_content": False,
            "content_text": "",
            "link_clickable": False,
            "new_page_opened": False,
            "url_changed": False,
            "can_close": False,
        }
        try:
            self._ensure_package_list()
            help_btn = self.page.locator("button:has-text(\"帮助\")").first
            if help_btn.count() == 0:
                return result
            new_page = None
            try:
                # 点帮助可能打开新标签页(外链文档)
                with self.page.context.expect_page(timeout=4000) as new_page_info:
                    help_btn.click()
                new_page = new_page_info.value
                result["icon_clickable"] = True
                result["new_page_opened"] = True
                result["link_clickable"] = True
                try:
                    new_page.wait_for_load_state("domcontentloaded", timeout=5000)
                    result["url_changed"] = "ikuai8" in (new_page.url or "") or \
                        new_page.url != self.page.url
                except Exception:
                    result["url_changed"] = True
            except Exception:
                # 未打开新页面, 仅点击
                try:
                    help_btn.click()
                    result["icon_clickable"] = True
                except Exception:
                    pass

            # 检查 popover 内容
            try:
                popover = self.page.locator(".ant-popover").last
                if popover.count() > 0 and popover.is_visible():
                    result["panel_visible"] = True
                    txt = (popover.text_content() or "").strip()
                    result["content_text"] = txt
                    result["has_content"] = bool(txt)
            except Exception:
                pass

            # 关闭 popover
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)
                result["can_close"] = True
            except Exception:
                pass
            # 关闭可能打开的新标签页
            if new_page is not None:
                try:
                    new_page.close()
                except Exception:
                    pass
        except Exception as exc:
            print(f"[DEBUG] 套餐帮助功能测试异常: {str(exc)[:80]}")
        return result

    # ==================== 选中计数 ====================

    def get_selected_count(self) -> int:
        """获取当前选中的套餐数量(从"已选 N 条"文本解析)。"""
        try:
            selected_text = self.page.locator("text=/已选\\s*\\d+\\s*条/")
            if selected_text.count() > 0:
                text = selected_text.first.inner_text()
                match = re.search(r"已选\s*(\d+)\s*条", text)
                if match:
                    return int(match.group(1))
        except Exception:
            pass
        return 0

    # ==================== 向后兼容别名 ====================

    def package_exists(self, packname: str) -> bool:
        return self.rule_exists(packname)

    def get_package_count(self) -> int:
        return self.get_rule_count()
