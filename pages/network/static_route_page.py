"""
静态路由页面类

处理静态路由配置的增删改查、启用停用、复制、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import List
import re


class StaticRoutePage(IkuaiTablePage):
    """静态路由页面操作类"""

    MODULE_NAME = "static_route"
    STATIC_ROUTE_URL = "/login#/networkConfiguration/staticRoute"

    # ==================== 导航 ====================
    def navigate_to_static_route(self):
        """导航到静态路由页面"""
        url = f"{self.base_url}{self.STATIC_ROUTE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self._ensure_static_route_tab_active()
        return self

    def _ensure_static_route_tab_active(self):
        """确保静态路由标签页处于激活状态"""
        try:
            tab = self.page.get_by_role("tab", name="静态路由")
            if tab.count() > 0:
                tab.click()
                self.page.wait_for_timeout(300)
        except Exception:
            pass

    # ==================== 表单字段填写 ====================
    def fill_name(self, name: str):
        """填写名称"""
        name_input = self.page.get_by_role("textbox", name="名称")
        name_input.click()
        name_input.fill(name)
        return self

    def select_protocol_stack(self, protocol_stack: str = "IPv4"):
        """选择协议栈（IPv4/IPv6）"""
        if protocol_stack == "IPv4":
            return self

        try:
            selector = self.page.locator(".ant-select-selector").filter(has_text="IPv4").first
            if selector.count() == 0:
                selector = self.page.locator("div").filter(has_text="协议栈").locator(".ant-select-selector").first
            selector.click()
            self.page.wait_for_timeout(300)

            option = self.page.locator(f".ant-select-item[title='{protocol_stack}']")
            if option.count() > 0:
                option.click()
            else:
                self.page.get_by_text(protocol_stack, exact=True).click()
            self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[WARN] select_protocol_stack 失败: {e}")

        return self

    def select_line(self, line: str = "自动"):
        """选择线路"""
        if line == "自动":
            return self

        try:
            line_selector = self.page.locator(".ant-select-selector").filter(has_text="自动").first
            if line_selector.count() == 0:
                line_selector = self.page.locator(".ant-select-selector").nth(2)
            line_selector.click()
            self.page.wait_for_timeout(300)

            option = self.page.locator(f".ant-select-item[title='{line}']")
            if option.count() > 0:
                option.click()
            else:
                self.page.locator(f".ant-select-dropdown .ant-select-item").filter(has_text=line).first.click()
            self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[WARN] select_line 失败: {e}")

        return self

    def fill_dest_address(self, dest_ip: str):
        """填写目的地址"""
        dest_input = self.page.get_by_role("textbox", name="目的地址")
        dest_input.click()
        dest_input.fill(dest_ip)
        return self

    def select_subnet_mask(self, mask: str = "255.255.255.0 (24)"):
        """选择子网掩码（处理虚拟滚动下拉列表）"""
        if "255.255.255.0" in mask:
            return self

        try:
            # 打开下拉菜单
            mask_combo = self.page.get_by_role("combobox").nth(2)  # 第3个combobox是子网掩码
            mask_combo.click(force=True)
            self.page.wait_for_timeout(300)

            # 尝试直接点击（选项在视口内）
            option = self.page.locator(f".ant-select-item-option[title='{mask}']")
            if option.count() > 0 and option.is_visible():
                option.click()
            else:
                # 虚拟滚动：通过键盘向下滚动找到目标选项
                # 从当前位置(/24=第8个)向下按箭头直到找到目标
                for _ in range(20):
                    self.page.keyboard.press("ArrowDown")
                    self.page.wait_for_timeout(50)
                    option = self.page.locator(f".ant-select-item-option[title='{mask}']")
                    if option.count() > 0 and option.is_visible():
                        option.click()
                        break
                else:
                    # 如果向下没找到，从头向上试
                    self.page.keyboard.press("Home")
                    self.page.wait_for_timeout(100)
                    for _ in range(33):
                        option = self.page.locator(f".ant-select-item-option[title='{mask}']")
                        if option.count() > 0 and option.is_visible():
                            option.click()
                            break
                        self.page.keyboard.press("ArrowDown")
                        self.page.wait_for_timeout(50)

            self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[WARN] select_subnet_mask 失败: {e}")

        return self

    def fill_gateway(self, gateway: str):
        """填写网关"""
        gw_input = self.page.get_by_role("textbox", name="网关")
        gw_input.click()
        gw_input.fill(gateway)
        return self

    def set_priority(self, priority: int = 1):
        """设置优先级"""
        if priority == 1:
            return self

        try:
            spinbutton = self.page.get_by_role("spinbutton", name="优先级")
            spinbutton.click()
            spinbutton.press("Control+a")
            spinbutton.type(str(priority), delay=50)
        except Exception as e:
            print(f"[WARN] set_priority 失败: {e}")

        return self

    # ==================== 添加规则完整流程 ====================
    def add_route(self, name: str,
                  protocol_stack: str = "IPv4",
                  line: str = "自动",
                  dest_address: str = "",
                  subnet_mask: str = "255.255.255.0 (24)",
                  gateway: str = "",
                  priority: int = 1,
                  remark: str = None) -> bool:
        """添加静态路由的完整流程"""
        self.click_add_button()
        self.fill_name(name)

        if protocol_stack != "IPv4":
            self.select_protocol_stack(protocol_stack)

        if line != "自动":
            self.select_line(line)

        if dest_address:
            self.fill_dest_address(dest_address)

        if subnet_mask and "255.255.255.0" not in subnet_mask:
            self.select_subnet_mask(subnet_mask)

        if gateway:
            self.fill_gateway(gateway)

        if priority != 1:
            self.set_priority(priority)

        if remark:
            self.fill_remark(remark)

        self.click_save()
        success = self.wait_for_success_message()

        if success:
            self.page.wait_for_timeout(1500)
            self.page.reload()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)

        return success

    # ==================== 静态路由特有：复制 ====================
    def copy_rule(self, rule_name: str):
        """点击复制按钮，进入新增页面（预填数据）"""
        self._click_rule_button(rule_name, "复制")
        self.page.wait_for_timeout(500)
        return self

    # ==================== 当前路由表（静态路由特有） ====================
    def switch_to_current_route_table(self):
        """切换到当前路由表标签页"""
        tab = self.page.get_by_role("tab", name="当前路由表")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def switch_to_static_route_tab(self):
        """切换回静态路由标签页"""
        tab = self.page.get_by_role("tab", name="静态路由")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def get_current_route_table_count(self) -> int:
        """获取当前路由表中的路由条数"""
        try:
            self.page.wait_for_timeout(500)
            rows = self.page.locator("[role='tabpanel'] table").locator("..").locator("> div > div")
            row_count = rows.count()
            if row_count > 0:
                return row_count

            page_text = self.page.text_content("[role='tabpanel']") or ""
            match = re.search(r"共\s*(\d+)\s*条", page_text)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return 0

    def switch_route_table_protocol(self, protocol: str = "IPv4"):
        """切换当前路由表的协议显示（IPv4/IPv6）"""
        try:
            radio = self.page.get_by_role("radio", name=protocol)
            if radio.count() > 0:
                radio.click()
                self.page.wait_for_timeout(500)
        except Exception:
            pass
        return self

    # ==================== 异常输入测试 ====================
    def try_add_route_invalid(self, name: str = "", dest_address: str = "",
                              gateway: str = "", expect_fail: bool = True):
        """尝试添加路由（用于异常输入测试）"""
        result = {"success": False, "has_validation_error": False, "error_msg": ""}

        try:
            add_btn = self.page.get_by_role("button", name="添加")
            add_btn.wait_for(state="visible", timeout=5000)
            add_btn.click()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)

            if name:
                self.fill_name(name)
            if dest_address:
                self.fill_dest_address(dest_address)
            if gateway:
                self.fill_gateway(gateway)

            self.click_save()
            self.page.wait_for_timeout(500)

            error_selectors = [
                ".ant-form-item-explain-error",
                ".ant-form-item-has-error .ant-form-item-explain",
                ".ant-message-error span",
            ]

            for selector in error_selectors:
                error_el = self.page.locator(selector)
                if error_el.count() > 0:
                    text = error_el.first.text_content()
                    if text:
                        result["has_validation_error"] = True
                        result["error_msg"] = text.strip()
                        break

            success_msg = self.page.locator(".ant-message-success")
            if success_msg.count() > 0:
                result["success"] = True

            if not result["success"]:
                self.click_cancel()

        except Exception as e:
            print(f"[DEBUG] try_add_route_invalid 异常: {e}")
            try:
                confirm_btn = self.page.locator(
                    ".ant-modal-confirm .ant-btn-primary, "
                    ".ant-modal-confirm button:has-text('确定')"
                )
                if confirm_btn.count() > 0 and confirm_btn.first.is_visible():
                    confirm_btn.first.click()
                    self.page.wait_for_timeout(500)
            except Exception:
                pass

            try:
                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click()
                    self.page.wait_for_timeout(500)
                    try:
                        confirm_btn2 = self.page.locator(".ant-modal-confirm .ant-btn-primary")
                        if confirm_btn2.count() > 0 and confirm_btn2.first.is_visible():
                            confirm_btn2.first.click()
                            self.page.wait_for_timeout(300)
                    except Exception:
                        pass
                    self.page.wait_for_load_state("networkidle")
                else:
                    self.navigate_to_static_route()
            except Exception:
                self.navigate_to_static_route()

        return result

    # ==================== 规则列表 ====================
    def get_rule_list(self) -> List[str]:
        """获取当前所有规则名称"""
        rules = []
        try:
            self.page.wait_for_timeout(500)
            name_cells = self.page.locator(
                "img[aria-label='play-circle'] + div, img[aria-label='minus-circle'] + div"
            )
            count = name_cells.count()
            for i in range(count):
                text = name_cells.nth(i).text_content()
                if text:
                    rules.append(text.strip())
        except Exception:
            pass
        return rules
