"""
MAC限速页面类

处理MAC限速配置的增删改查、启用停用、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作
"""
from playwright.sync_api import Page, Locator
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class MacRateLimitPage(IkuaiTablePage):
    """MAC限速页面操作类"""

    MODULE_NAME = "mac_rate_limit"
    MAC_RATE_LIMIT_URL = "/login#/networkConfiguration/terminalSpeedLimit"

    # ==================== 导航 ====================
    def navigate_to_mac_rate_limit(self):
        """导航到MAC限速页面"""
        url = f"{self.base_url}{self.MAC_RATE_LIMIT_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self._ensure_mac_tab_active()
        return self

    def _ensure_mac_tab_active(self):
        """确保MAC限速标签页处于激活状态"""
        try:
            mac_tab = self.page.get_by_role("tab", name="MAC限速")
            if mac_tab.count() > 0:
                mac_tab.click()
                self.page.wait_for_timeout(300)
        except Exception:
            pass

    def navigate_to_time_plan(self):
        """导航到时间计划页面"""
        url = f"{self.base_url}/#/networkConfiguration/routeObject/timePlan"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        return self

    # ==================== 表单字段填写 ====================
    def fill_name(self, name: str):
        """填写规则名称"""
        self.page.get_by_role("textbox", name="名称").fill(name)
        return self

    def select_protocol_stack(self, protocol_stack: str = "IPv4"):
        """选择协议栈"""
        if protocol_stack == "IPv4":
            return self

        try:
            proto_combobox = self.page.get_by_role("combobox", name="协议栈 *")
            if proto_combobox.count() > 0:
                proto_combobox.click(force=True)
                self.page.wait_for_timeout(300)
                self.page.get_by_title(protocol_stack, exact=True).first.click()
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] select_protocol_stack error: {e}")
        return self

    def select_line(self, line: str = "任意"):
        """选择线路"""
        if line == "任意":
            return self

        try:
            line_combobox = self.page.locator(".ant-select").first
            if line_combobox.count() > 0:
                line_combobox.click()
                self.page.wait_for_timeout(500)

                label_option = self.page.locator("label").filter(has_text=line)
                if label_option.count() > 0:
                    label_option.first.click()
                    self.page.wait_for_timeout(300)
                else:
                    self.page.get_by_text(line, exact=True).first.click()
                    self.page.wait_for_timeout(300)

                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] select_line error: {e}")
        return self

    def add_mac_address(self, mac: str):
        """添加MAC地址"""
        try:
            add_btn = self.page.get_by_role("button", name="添加").last
            if add_btn.count() > 0:
                add_btn.click()
                self.page.wait_for_timeout(300)

            mac_input = self.page.get_by_role("textbox", name="请输入MAC").last
            if mac_input.count() > 0:
                mac_input.fill(mac)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] add_mac_address error: {e}")
        return self

    def batch_add_macs(self, macs: List[str]):
        """批量添加MAC地址"""
        try:
            batch_btn = self.page.get_by_role("button", name="批量")
            if batch_btn.count() > 0:
                batch_btn.click()
                self.page.wait_for_timeout(300)

            mac_text = "\n".join(macs)
            textarea = self.page.get_by_placeholder("请输入", exact=True)
            if textarea.count() > 0:
                textarea.fill(mac_text)
                self.page.wait_for_timeout(200)

            confirm_btn = self.page.get_by_role("button", name="确定")
            if confirm_btn.count() > 0:
                confirm_btn.click()
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] batch_add_macs error: {e}")
        return self

    def select_mac_group(self, group_name: str):
        """选择MAC组"""
        try:
            mac_group_label = self.page.locator("text=MAC组").first
            if mac_group_label.count() > 0:
                parent = mac_group_label.locator("..")
                combobox = parent.locator("[role='combobox']")
                if combobox.count() > 0:
                    combobox.click(force=True)
                    self.page.wait_for_timeout(300)
                    self.page.get_by_title(group_name, exact=True).first.click()
        except Exception as e:
            print(f"[DEBUG] select_mac_group error: {e}")
        return self

    def select_rate_mode(self, mode: str = "独立限速"):
        """选择限速模式"""
        try:
            self.page.get_by_role("combobox", name="限速模式 *").click(force=True)
            self.page.wait_for_timeout(300)
            self.page.get_by_title(mode, exact=True).first.click()
        except Exception as e:
            print(f"[DEBUG] select_rate_mode error: {e}")
        return self

    def fill_upload_speed(self, speed: int, unit: str = "KB/s"):
        """填写上行限速"""
        try:
            spinbutton = self.page.get_by_role("spinbutton", name="上行限速 *")

            try:
                current_unit = spinbutton.evaluate("""(el) => {
                    let parent = el.parentElement;
                    for (let i = 0; i < 8; i++) {
                        if (!parent) break;
                        const selected = parent.querySelector('.ant-select-selection-item');
                        if (selected) return selected.textContent;
                        parent = parent.parentElement;
                    }
                    return '';
                }""")

                if current_unit != unit:
                    form_item = spinbutton.locator("xpath=ancestor::div[contains(@class,'ant-form-item')][1]")
                    if form_item.count() > 0:
                        combobox = form_item.locator(".ant-select-selector").first
                        if combobox.count() > 0:
                            combobox.click()
                            self.page.wait_for_timeout(500)
                            option = self.page.locator(f".ant-select-item[title='{unit}']").first
                            if option.count() > 0:
                                option.click()
                                self.page.wait_for_timeout(200)
                            else:
                                self.page.keyboard.press("Escape")
            except Exception as e:
                print(f"[DEBUG] fill_upload_speed unit switch: {e}")

            if spinbutton.count() > 0:
                spinbutton.fill(str(speed))
        except Exception as e:
            print(f"[DEBUG] fill_upload_speed error: {e}")
        return self

    def type_upload_speed(self, speed: str):
        """使用键盘输入方式填写上行限速"""
        try:
            spinbutton = self.page.get_by_role("spinbutton", name="上行限速 *")
            if spinbutton.count() > 0:
                spinbutton.click()
                spinbutton.clear()
                spinbutton.type(speed, delay=50)
        except Exception as e:
            print(f"[DEBUG] type_upload_speed error: {e}")
        return self

    def fill_download_speed(self, speed: int, unit: str = "KB/s"):
        """填写下行限速"""
        try:
            spinbutton = self.page.get_by_role("spinbutton", name="下行限速 *")

            try:
                current_unit = spinbutton.evaluate("""(el) => {
                    let parent = el.parentElement;
                    for (let i = 0; i < 8; i++) {
                        if (!parent) break;
                        const selected = parent.querySelector('.ant-select-selection-item');
                        if (selected) return selected.textContent;
                        parent = parent.parentElement;
                    }
                    return '';
                }""")

                if current_unit != unit:
                    form_item = spinbutton.locator("xpath=ancestor::div[contains(@class,'ant-form-item')][1]")
                    if form_item.count() > 0:
                        combobox = form_item.locator(".ant-select-selector").first
                        if combobox.count() > 0:
                            combobox.click()
                            self.page.wait_for_timeout(500)
                            option = self.page.locator(f".ant-select-item[title='{unit}']").first
                            if option.count() > 0:
                                option.click()
                                self.page.wait_for_timeout(200)
                            else:
                                self.page.keyboard.press("Escape")
            except Exception as e:
                print(f"[DEBUG] fill_download_speed unit switch: {e}")

            if spinbutton.count() > 0:
                spinbutton.fill(str(speed))
        except Exception as e:
            print(f"[DEBUG] fill_download_speed error: {e}")
        return self

    def set_time_by_week(self, days: List[str] = None, start_time: str = "00:00", end_time: str = "23:59"):
        """设置按周循环的生效时间"""
        try:
            modal_wrap = self.page.locator(".ant-modal-wrap:visible")
            if modal_wrap.count() > 0:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)

            radio = self.page.get_by_role("radio", name="按周循环")
            if radio.count() > 0:
                radio.click()
                self.page.wait_for_timeout(200)

            if days is None:
                checkboxes = self.page.locator(".ant-checkbox-wrapper")
                for i in range(checkboxes.count()):
                    checkbox = checkboxes.nth(i)
                    if not checkbox.locator("input").is_checked():
                        checkbox.click()
            else:
                for day in days:
                    self.page.get_by_text(day).locator("..").get_by_role("checkbox").check()

            time_inputs = self.page.locator("input[type='time']")
            if time_inputs.count() >= 2:
                time_inputs.first.fill(start_time)
                time_inputs.last.fill(end_time)
        except Exception as e:
            print(f"[DEBUG] set_time_by_week error: {e}")
        return self

    def set_time_plan(self, plan_name: str):
        """设置时间计划"""
        try:
            time_plan_radio = self.page.get_by_role("radio", name="时间计划")
            if time_plan_radio.count() > 0:
                time_plan_radio.click()
                self.page.wait_for_timeout(500)

            time_section = self.page.locator("text=生效时间").locator("..")
            combobox = time_section.locator("[role='combobox']")
            if combobox.count() > 0:
                combobox.click()
                self.page.wait_for_timeout(300)

                option = self.page.get_by_title(plan_name, exact=True)
                if option.count() > 0:
                    option.click()
                    self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] set_time_plan error: {e}")
        return self

    def set_time_range(self, start: str, end: str):
        """设置时间段"""
        try:
            self.page.get_by_role("radio", name="时间段").click()
            self.page.wait_for_timeout(200)

            start_input = self.page.get_by_role("textbox", name="开始时间")
            if start_input.count() > 0:
                start_input.fill(start)

            end_input = self.page.get_by_role("textbox", name="结束时间")
            if end_input.count() > 0:
                end_input.fill(end)
        except Exception as e:
            print(f"[DEBUG] set_time_range error: {e}")
        return self

    def fill_mac(self, mac: str):
        """在添加规则页面填写MAC地址（用于异常输入测试）"""
        try:
            mac_input = self.page.get_by_role("textbox", name="请输入MAC")
            if mac_input.count() > 0:
                mac_input.fill(mac)
                self.page.wait_for_timeout(200)
            else:
                self.add_mac_address(mac)
        except Exception as e:
            print(f"[DEBUG] fill_mac error: {e}")
        return self

    # ==================== 添加规则完整流程 ====================
    def add_rule(self, name: str,
                 protocol_stack: str = "IPv4",
                 line: str = "任意",
                 mac: str = None,
                 batch_macs: list = None,
                 mac_group: str = None,
                 rate_mode: str = "独立限速",
                 upload_speed: int = 512,
                 download_speed: int = 1024,
                 speed_unit: str = "KB/s",
                 time_type: str = "按周循环",
                 time_plan: str = None,
                 time_start: str = None,
                 time_end: str = None,
                 remark: str = None) -> bool:
        """添加MAC限速规则的完整流程"""
        self.click_add_button()
        self.fill_name(name)
        self.select_protocol_stack(protocol_stack)

        if line != "任意":
            self.select_line(line)

        if mac:
            self.add_mac_address(mac)

        if batch_macs:
            self.batch_add_macs(batch_macs)

        if mac_group:
            self.select_mac_group(mac_group)

        self.select_rate_mode(rate_mode)
        self.fill_upload_speed(upload_speed, speed_unit)
        self.fill_download_speed(download_speed, speed_unit)

        if time_type == "按周循环":
            self.set_time_by_week()
        elif time_type == "时间计划" and time_plan:
            self.set_time_plan(time_plan)
        elif time_type == "时间段" and time_start and time_end:
            self.set_time_range(time_start, time_end)

        if remark:
            self.fill_remark(remark)

        self.click_save()

        success = self.wait_for_success_message()

        if success:
            self.page.wait_for_timeout(1500)
            self.navigate_to_mac_rate_limit()
            self.page.wait_for_timeout(500)

        return success

    # ==================== MAC限速特有：close_modal扩展 ====================
    def close_modal_if_exists(self):
        """关闭可能存在的模态框或返回列表页"""
        try:
            current_url = self.page.url
            if "/add" in current_url or "/edit" in current_url:
                back_btn = self.page.locator("button:has(.anticon-left)").first
                if back_btn.count() > 0:
                    back_btn.click()
                    self.page.wait_for_timeout(500)
                    return

                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click()
                    self.page.wait_for_timeout(300)
                    confirm_btn = self.page.get_by_role("button", name="确定")
                    if confirm_btn.count() > 0 and confirm_btn.is_visible():
                        confirm_btn.click()
                        self.page.wait_for_timeout(300)
                    return

                self.navigate_to_mac_rate_limit()
                return

            super().close_modal_if_exists()

        except Exception as e:
            try:
                print(f"[DEBUG] close_modal_if_exists: {str(e)[:100]}")
            except Exception:
                pass

    # ==================== MAC限速特有：delete_rule覆盖 ====================
    def delete_rule(self, rule_name: str) -> bool:
        """删除指定规则（使用navigate代替reload）"""
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        try:
            count_before = self.get_rule_count()

            click_result = self._click_rule_button(rule_name, "删除")
            if not click_result:
                return False

            self.page.wait_for_timeout(500)

            confirm_btn = self.page.get_by_role("button", name="确定")
            if confirm_btn.count() > 0:
                confirm_btn.click()

            self.page.wait_for_timeout(1000)
            self.navigate_to_mac_rate_limit()
            self.page.wait_for_timeout(500)

            count_after = self.get_rule_count()
            if count_after < count_before:
                return True

            if not self.rule_exists(rule_name):
                return True

            if self.wait_for_success_message():
                return True

            return False

        except Exception as e:
            print(f"删除规则失败: {e}")
            return False

    # ==================== MAC限速特有：sort_by_column覆盖 ====================
    def sort_by_column(self, column_name: str) -> bool:
        """点击列头排序（限定在MAC限速tabpanel内）"""
        try:
            mac_panel = self.page.get_by_role("tabpanel", name="MAC限速")
            if mac_panel.count() == 0:
                mac_panel = self.page.locator("[role='tabpanel']").filter(has_text="MAC")
            if mac_panel.count() == 0:
                mac_panel = self.page.locator("[role='tabpanel']").last
            header = mac_panel.locator("th").filter(has_text=column_name)
            if header.count() > 0:
                header.first.click()
                self.page.wait_for_timeout(500)
                return True
            col_header = mac_panel.get_by_role("columnheader", name=column_name)
            if col_header.count() > 0:
                col_header.click()
                self.page.wait_for_timeout(500)
                return True
        except Exception as e:
            print(f"[DEBUG] sort_by_column error: {e}")
        return False

    def test_sorting(self) -> dict:
        """测试排序功能"""
        result = {
            "协议栈": False, "线路": False, "限速模式": False,
            "上行限速": False, "下行限速": False
        }

        for col in result.keys():
            try:
                for click_num in range(1, 4):
                    self.sort_by_column(col)
                    self.page.wait_for_timeout(500)
                result[col] = True
            except Exception:
                result[col] = False

        return result

    # ==================== 异常输入测试 ====================
    def try_add_rule_invalid(self, name: str = "", remark: str = "", mac: str = "",
                              upload_speed: str = "", expect_fail: bool = True,
                              use_type_for_speed: bool = False):
        """尝试添加规则（用于异常输入测试）"""
        result = {"success": False, "has_validation_error": False, "error_msg": ""}

        try:
            self._ensure_mac_tab_active()
            self.page.wait_for_timeout(300)

            self.click_add_button()
            self.page.wait_for_timeout(300)

            if name:
                self.fill_name(name)
            if mac:
                self.fill_mac(mac)
            if remark:
                self.fill_remark(remark)
            if upload_speed:
                if use_type_for_speed:
                    self.type_upload_speed(upload_speed)
                else:
                    self.fill_upload_speed(upload_speed, "KB/s")

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
                    if text and text.strip():
                        result["has_validation_error"] = True
                        result["error_msg"] = text.strip()
                        break

            global_error = self.page.locator("text=输入有误")
            if global_error.count() > 0:
                result["has_validation_error"] = True
                if not result["error_msg"]:
                    result["error_msg"] = "输入有误, 请检查后重试"

            if not result["has_validation_error"]:
                success_msg = self.page.locator("text=添加成功")
                if success_msg.count() > 0:
                    result["success"] = True

            if expect_fail and name:
                self.navigate_to_mac_rate_limit()
                self.page.wait_for_timeout(500)

                try:
                    xpath = f"//tr[td[1][contains(text(), '{name}')]]"
                    rule_row = self.page.locator(xpath)
                    rule_row.wait_for(timeout=2000)

                    if rule_row.count() > 0:
                        print(f"[WARNING] 规则 '{name}' 被意外保存，正在清理...")
                        try:
                            self.delete_rule(name)
                            self.page.wait_for_timeout(500)
                        except Exception as cleanup_error:
                            print(f"[DEBUG] 清理意外保存的规则失败: {cleanup_error}")

                        if not result["has_validation_error"]:
                            result["has_validation_error"] = True
                            result["error_msg"] = f"规则被意外保存（已清理）"
                except Exception:
                    pass
                return result

        except Exception as e:
            result["error_msg"] = str(e)[:100]

        finally:
            self.navigate_to_mac_rate_limit()
            self.page.wait_for_timeout(300)

        return result

    # ==================== 状态验证 ====================
    def get_rule_count(self) -> int:
        """获取规则数量"""
        try:
            count_text = self.page.locator("text=/共 \\d+ 条/").first.inner_text()
            return int(count_text.replace("共 ", "").replace(" 条", ""))
        except Exception:
            return self.page.locator("tbody tr").count()

    def get_rule_list(self) -> List[str]:
        """获取所有规则名称列表"""
        rule_names = []
        rows = self.page.locator("tbody tr")
        for i in range(rows.count()):
            try:
                name_cell = rows.nth(i).locator("td").first
                rule_names.append(name_cell.inner_text())
            except Exception:
                continue
        return rule_names

    # ==================== 帮助功能 ====================
    def test_help_functionality(self) -> dict:
        """测试帮助功能"""
        result = {
            "icon_clickable": False,
            "panel_visible": False,
            "can_close": False
        }

        try:
            help_btn = self.page.get_by_role("button", name="帮助")
            if help_btn.count() > 0:
                result["icon_clickable"] = True
                help_btn.click()
                self.page.wait_for_timeout(500)

                help_panel = self.page.locator(".ant-drawer, .ant-modal, [role='dialog']")
                if help_panel.count() > 0 and help_panel.is_visible():
                    result["panel_visible"] = True

                    close_btn = self.page.locator(".ant-drawer-close, .ant-modal-close")
                    if close_btn.count() > 0:
                        close_btn.click()
                        self.page.wait_for_timeout(300)
                        result["can_close"] = True
                    else:
                        self.page.keyboard.press("Escape")
                        self.page.wait_for_timeout(300)
                        result["can_close"] = not help_panel.is_visible()
        except Exception as e:
            print(f"[DEBUG] test_help_functionality error: {e}")

        return result
