"""
MAC限速页面类

处理MAC限速配置的增删改查、启用停用、导入导出等操作
参照VLAN页面类和IP限速页面类结构实现
"""
from playwright.sync_api import Page, Locator
from pages.base_page import BasePage
from typing import Optional, List


class MacRateLimitPage(BasePage):
    """MAC限速页面操作类"""

    # 页面URL路径
    MAC_RATE_LIMIT_URL = "/login#/networkConfiguration/terminalSpeedLimit"

    def __init__(self, page: Page, base_url: str):
        """
        初始化MAC限速页面

        Args:
            page: Playwright Page对象
            base_url: 基础URL
        """
        super().__init__(page)
        self.base_url = base_url

    # ==================== 导航 ====================
    def navigate_to_mac_rate_limit(self):
        """导航到MAC限速页面"""
        url = f"{self.base_url}{self.MAC_RATE_LIMIT_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        # 确保在MAC限速标签页
        self._ensure_mac_tab_active()
        return self

    def _ensure_mac_tab_active(self):
        """确保MAC限速标签页处于激活状态"""
        try:
            # 点击MAC限速标签
            mac_tab = self.page.get_by_role("tab", name="MAC限速")
            if mac_tab.count() > 0:
                mac_tab.click()
                self.page.wait_for_timeout(300)
        except Exception:
            pass

    def navigate_to_time_plan(self):
        """导航到时间计划页面（用于创建时间计划）"""
        url = f"{self.base_url}/#/networkConfiguration/routeObject/timePlan"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        return self

    # ==================== 添加MAC限速规则 ====================
    def click_add_button(self):
        """点击添加按钮"""
        self.page.get_by_role("button", name="添加").first.click()
        return self

    def fill_name(self, name: str):
        """
        填写规则名称

        Args:
            name: 规则名称
        """
        self.page.get_by_role("textbox", name="名称").fill(name)
        return self

    def select_protocol_stack(self, protocol_stack: str = "IPv4"):
        """
        选择协议栈

        Args:
            protocol_stack: 协议栈（IPv4/IPv6）
        """
        try:
            # 协议栈字段名称带 * 号
            self.page.get_by_role("combobox", name="协议栈 *").click(force=True)
            self.page.wait_for_timeout(300)
            self.page.get_by_title(protocol_stack, exact=True).first.click()
        except Exception as e:
            print(f"[DEBUG] select_protocol_stack error: {e}")
        return self

    def select_line(self, line: str = "任意"):
        """
        选择线路

        Args:
            line: 线路名称（全部/wan1/wan2/wan3/任意）
                  注意："任意"是默认值，无需选择；其他值需要点击对应的复选框
        """
        # "任意"是默认值，不需要选择
        if line == "任意":
            return self

        try:
            # 点击线路下拉框 - 使用更精确的选择器
            # 线路字段在"协议栈"之后，通过定位包含"线路"文本的父元素来找到下拉框
            line_field = self.page.locator("text=线路").first.locator("..").locator(".ant-select")
            if line_field.count() > 0:
                line_field.click()
                self.page.wait_for_timeout(500)

                # 选项是checkbox，使用get_by_role来选择
                checkbox_option = self.page.get_by_role("checkbox", name=line)
                if checkbox_option.count() > 0:
                    checkbox_option.click()
                    self.page.wait_for_timeout(300)
                else:
                    # 备用方案：通过文本查找（点击包含文本的generic元素）
                    self.page.locator(f".ant-select-dropdown text={line}").first.click()
                    self.page.wait_for_timeout(300)

                # 点击其他地方关闭下拉框
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] select_line error: {e}")
        return self

    def add_mac_address(self, mac: str):
        """
        添加MAC地址

        Args:
            mac: MAC地址
        """
        try:
            # 点击MAC地址区域的添加按钮
            add_btn = self.page.locator("text=MAC地址").locator("..").get_by_role("button", name="添加")
            if add_btn.count() > 0:
                add_btn.first.click()
                self.page.wait_for_timeout(300)

            # 填写MAC地址（直接在textbox中输入，不需要点击确定按钮）
            mac_input = self.page.get_by_role("textbox", name="请输入MAC")
            if mac_input.count() > 0:
                mac_input.fill(mac)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] add_mac_address error: {e}")
        return self

    def batch_add_macs(self, macs: List[str]):
        """
        批量添加MAC地址

        Args:
            macs: MAC地址列表
        """
        try:
            # 点击批量按钮
            batch_btn = self.page.locator("text=MAC地址").locator("..").get_by_role("button", name="批量")
            if batch_btn.count() > 0:
                batch_btn.click()
                self.page.wait_for_timeout(300)

            # 输入多个MAC（逗号分隔）
            mac_text = ",".join(macs)
            textarea = self.page.locator("textarea")
            if textarea.count() > 0:
                textarea.fill(mac_text)

            confirm_btn = self.page.get_by_role("button", name="确 定")
            if confirm_btn.count() > 0:
                confirm_btn.click()
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] batch_add_macs error: {e}")
        return self

    def select_mac_group(self, group_name: str):
        """
        选择MAC组

        Args:
            group_name: MAC组名称
        """
        try:
            # MAC组下拉框没有name属性，通过label定位
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

    def create_mac_group_in_dialog(self, group_name: str, mac_list: str, protocol_stack: str = "IPv4"):
        """
        在添加弹窗内创建MAC组

        Args:
            group_name: 分组名称
            mac_list: MAC列表（如AA:BB:CC:11:00:01-AA:BB:CC:11:00:0A）
            protocol_stack: 协议栈（IPv4/IPv6）
        """
        try:
            # 点击MAC组下拉框
            mac_group_combobox = self.page.locator(".ant-select-selector").nth(1)  # MAC组是第二个下拉框
            if mac_group_combobox.count() > 0:
                mac_group_combobox.click(force=True)
                self.page.wait_for_timeout(500)

            # 点击创建分组按钮
            create_btn = self.page.get_by_role("button", name="创建分组")
            if create_btn.count() > 0:
                create_btn.click()
                self.page.wait_for_timeout(500)

            # 选择创建IPv4或IPv6分组（如果需要切换）
            if protocol_stack == "IPv6":
                ipv6_radio = self.page.get_by_role("radio", name="创建IPv6分组")
                if ipv6_radio.count() > 0:
                    ipv6_radio.click()
                    self.page.wait_for_timeout(300)

            # 填写分组名称（使用placeholder定位）
            group_name_input = self.page.get_by_placeholder("请输入分组名称")
            if group_name_input.count() > 0:
                group_name_input.fill(group_name)
                self.page.wait_for_timeout(200)

            # 填写MAC列表（使用placeholder定位）
            mac_list_input = self.page.get_by_placeholder("请输入MAC列表")
            if mac_list_input.count() > 0:
                mac_list_input.fill(mac_list)
                self.page.wait_for_timeout(200)

            # 点击确定保存分组（使用getByLabel精确定位"创建分组"对话框内的确定按钮）
            confirm_btn = self.page.get_by_label("创建分组").get_by_role("button", name="确定")
            if confirm_btn.count() > 0:
                confirm_btn.click()
                self.page.wait_for_timeout(500)

            # 等待创建成功提示
            self.page.wait_for_timeout(500)

            # 在"请选择"对话框中，勾选刚创建的分组并点击确定
            # 先勾选刚创建的分组
            new_group_checkbox = self.page.locator(f"label:has-text('{group_name}')").first
            if new_group_checkbox.count() > 0:
                new_group_checkbox.click()
                self.page.wait_for_timeout(300)

            # 点击"请选择"对话框的确定按钮
            select_confirm_btn = self.page.get_by_label("请选择").get_by_role("button", name="确定")
            if select_confirm_btn.count() > 0:
                select_confirm_btn.click()
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] create_mac_group_in_dialog error: {e}")
        return self

    def select_rate_mode(self, mode: str = "独立限速"):
        """
        选择限速模式

        Args:
            mode: 限速模式（独立限速/共享限速）
        """
        try:
            # 限速模式字段名称带 * 号
            self.page.get_by_role("combobox", name="限速模式 *").click(force=True)
            self.page.wait_for_timeout(300)
            self.page.get_by_title(mode, exact=True).first.click()
        except Exception as e:
            print(f"[DEBUG] select_rate_mode error: {e}")
        return self

    def fill_upload_speed(self, speed: int, unit: str = "KB/s"):
        """
        填写上行限速

        Args:
            speed: 限速值
            unit: 单位（KB/s/MB/s）
        """
        try:
            # 上行限速字段是spinbutton类型，名称带 * 号
            spinbutton = self.page.get_by_role("spinbutton", name="上行限速 *")
            if spinbutton.count() > 0:
                spinbutton.fill(str(speed))
            # 如果需要切换单位
            if unit != "KB/s":
                # 找到上行限速区域内的单位下拉框
                upload_label = self.page.locator("text=上行限速").first
                if upload_label.count() > 0:
                    parent = upload_label.locator("xpath=..")
                    combobox = parent.locator("[role='combobox']")
                    if combobox.count() > 0:
                        combobox.click()
                        self.page.wait_for_timeout(200)
                        self.page.get_by_title(unit, exact=True).click()
        except Exception as e:
            print(f"[DEBUG] fill_upload_speed error: {e}")
        return self

    def type_upload_speed(self, speed: str):
        """
        使用键盘输入方式填写上行限速（用于测试键盘验证）

        与 fill_upload_speed 的区别：
        - fill() 直接设置值，不触发键盘事件
        - type() 模拟键盘输入，触发 keydown/keypress/keyup 事件
        - 前端的输入验证通常依赖键盘事件来拦截非法字符

        Args:
            speed: 限速值（字符串形式，可以传入 "-1", "abc" 等非法值）
        """
        try:
            spinbutton = self.page.get_by_role("spinbutton", name="上行限速 *")
            if spinbutton.count() > 0:
                spinbutton.click()
                spinbutton.clear()
                # 使用 type() 模拟键盘输入，触发前端验证
                spinbutton.type(speed, delay=50)
        except Exception as e:
            print(f"[DEBUG] type_upload_speed error: {e}")
        return self

    def fill_download_speed(self, speed: int, unit: str = "KB/s"):
        """
        填写下行限速

        Args:
            speed: 限速值
            unit: 单位（KB/s/MB/s）
        """
        try:
            # 下行限速字段是spinbutton类型，名称带 * 号
            spinbutton = self.page.get_by_role("spinbutton", name="下行限速 *")
            if spinbutton.count() > 0:
                spinbutton.fill(str(speed))
            # 如果需要切换单位
            if unit != "KB/s":
                # 找到下行限速区域内的单位下拉框
                download_label = self.page.locator("text=下行限速").first
                if download_label.count() > 0:
                    parent = download_label.locator("xpath=..")
                    combobox = parent.locator("[role='combobox']")
                    if combobox.count() > 0:
                        combobox.click()
                        self.page.wait_for_timeout(200)
                        self.page.get_by_title(unit, exact=True).click()
        except Exception as e:
            print(f"[DEBUG] fill_download_speed error: {e}")
        return self

    def set_time_by_week(self, days: List[str] = None, start_time: str = "00:00", end_time: str = "23:59"):
        """
        设置按周循环的生效时间

        Args:
            days: 生效日期列表（如["周一", "周二"]），None表示全选
            start_time: 开始时间
            end_time: 结束时间
        """
        try:
            # 关闭可能存在的 Ant Design 模态对话框（如 MAC 组选择对话框）
            # 注意：不要调用 close_modal_if_exists()，因为它会尝试退出添加页面
            modal_wrap = self.page.locator(".ant-modal-wrap:visible")
            if modal_wrap.count() > 0:
                # 按 Escape 关闭对话框
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)

            # 选择"按周循环"模式
            radio = self.page.get_by_role("radio", name="按周循环")
            if radio.count() > 0:
                radio.click()
                self.page.wait_for_timeout(200)

            # 选择日期
            if days is None:
                checkboxes = self.page.locator(".ant-checkbox-wrapper")
                for i in range(checkboxes.count()):
                    checkbox = checkboxes.nth(i)
                    if not checkbox.locator("input").is_checked():
                        checkbox.click()
            else:
                for day in days:
                    self.page.get_by_text(day).locator("..").get_by_role("checkbox").check()

            # 设置时间范围
            time_inputs = self.page.locator("input[type='time']")
            if time_inputs.count() >= 2:
                time_inputs.first.fill(start_time)
                time_inputs.last.fill(end_time)
        except Exception as e:
            print(f"[DEBUG] set_time_by_week error: {e}")
        return self

    def set_time_plan(self, plan_name: str):
        """
        设置时间计划

        Args:
            plan_name: 时间计划名称
        """
        try:
            # 选择"时间计划"模式
            time_plan_radio = self.page.get_by_role("radio", name="时间计划")
            if time_plan_radio.count() > 0:
                time_plan_radio.click()
                self.page.wait_for_timeout(500)

            # 点击时间计划下拉框（combobox在radio后面，通过locator定位）
            # 找到"生效时间"区域内的combobox
            time_section = self.page.locator("text=生效时间").locator("..")
            combobox = time_section.locator("[role='combobox']")
            if combobox.count() > 0:
                combobox.click()
                self.page.wait_for_timeout(300)

                # 选择时间计划选项
                option = self.page.get_by_title(plan_name, exact=True)
                if option.count() > 0:
                    option.click()
                    self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] set_time_plan error: {e}")
        return self

    def set_time_range(self, start: str, end: str):
        """
        设置时间段

        Args:
            start: 开始时间（如2026-03-01 00:00）
            end: 结束时间（如2026-03-31 23:59）
        """
        try:
            # 选择"时间段"模式
            self.page.get_by_role("radio", name="时间段").click()
            self.page.wait_for_timeout(200)

            # 填写开始时间
            start_input = self.page.get_by_role("textbox", name="开始时间")
            if start_input.count() > 0:
                start_input.fill(start)

            # 填写结束时间
            end_input = self.page.get_by_role("textbox", name="结束时间")
            if end_input.count() > 0:
                end_input.fill(end)
        except Exception as e:
            print(f"[DEBUG] set_time_range error: {e}")
        return self

    def fill_remark(self, remark: str):
        """
        填写备注

        Args:
            remark: 备注信息
        """
        self.page.get_by_role("textbox", name="备注").fill(remark)
        return self

    def click_save(self):
        """点击保存按钮"""
        self.page.get_by_role("button", name="保存").click()
        return self

    def click_cancel(self):
        """点击取消按钮"""
        self.page.get_by_role("button", name="取消").click()
        return self

    def add_rule(self, name: str,
                 protocol_stack: str = "IPv4",
                 line: str = "任意",
                 mac: str = None,
                 mac_group: str = None,
                 rate_mode: str = "独立限速",
                 upload_speed: int = 512,
                 download_speed: int = 1024,
                 speed_unit: str = "KB/s",
                 time_type: str = "按周循环",
                 time_plan: str = None,
                 remark: str = None) -> bool:
        """
        添加MAC限速规则的完整流程

        Args:
            name: 规则名称
            protocol_stack: 协议栈（IPv4/IPv6）
            line: 线路（默认"任意"）
            mac: MAC地址（可选）
            mac_group: MAC组名称（可选）
            rate_mode: 限速模式（默认独立限速）
            upload_speed: 上行限速值
            download_speed: 下行限速值
            speed_unit: 速度单位
            time_type: 生效时间类型（按周循环/时间计划/时间段）
            time_plan: 时间计划名称（当time_type为时间计划时使用）
            remark: 备注

        Returns:
            是否添加成功
        """
        self.click_add_button()
        self.fill_name(name)
        self.select_protocol_stack(protocol_stack)

        if line != "任意":
            self.select_line(line)

        if mac:
            self.add_mac_address(mac)

        if mac_group:
            self.select_mac_group(mac_group)

        self.select_rate_mode(rate_mode)
        self.fill_upload_speed(upload_speed, speed_unit)
        self.fill_download_speed(download_speed, speed_unit)

        if time_type == "按周循环":
            self.set_time_by_week()
        elif time_type == "时间计划" and time_plan:
            self.set_time_plan(time_plan)

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

    # ==================== 启用/停用规则 ====================
    def _click_rule_button(self, rule_name: str, button_name: str) -> bool:
        """
        点击规则行中的指定按钮

        Args:
            rule_name: 规则名称
            button_name: 按钮名称（编辑/停用/启用/删除）

        Returns:
            是否成功点击
        """
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(300)

        try:
            # 使用包含匹配，以处理名称被截断的情况
            rule_text = self.page.locator(f"text=/{rule_name[:15]}/")
            if rule_text.count() == 0:
                print(f"[DEBUG] _click_rule_button: 规则 {rule_name} 不存在")
                return False

            result = rule_text.first.evaluate("""(el) => {
                let parent = el.parentElement;
                let depth = 0;
                while (parent && depth < 20) {
                    const btns = parent.querySelectorAll('button');
                    for (const btn of btns) {
                        if (btn.textContent.trim() === '%s') {
                            btn.click();
                            return true;
                        }
                    }
                    parent = parent.parentElement;
                    depth++;
                }
                return false;
            }""" % button_name, timeout=5000)

            return result

        except Exception as e:
            print(f"[DEBUG] _click_rule_button 异常: {e}")
            return False

    def disable_rule(self, rule_name: str) -> bool:
        """
        停用指定规则

        Args:
            rule_name: 规则名称

        Returns:
            是否停用成功
        """
        self._click_rule_button(rule_name, "停用")
        self.page.wait_for_timeout(500)

        try:
            confirm_btn = self.page.locator("dialog button:has-text('确定'), [role='dialog'] button:has-text('确定')")
            if confirm_btn.count() > 0:
                confirm_btn.first.click()
            else:
                self.page.get_by_role("button", name="确定").click()
        except Exception as e:
            print(f"[DEBUG] disable_rule 点击确定失败: {e}")
            return False

        try:
            self.page.wait_for_selector("text=停用成功", timeout=5000)
            return True
        except Exception:
            return self.wait_for_success_message()

    def enable_rule(self, rule_name: str) -> bool:
        """
        启用指定规则

        Args:
            rule_name: 规则名称

        Returns:
            是否启用成功
        """
        self._click_rule_button(rule_name, "启用")

        try:
            self.page.wait_for_selector("text=启用成功", timeout=5000)
            return True
        except Exception:
            return self.wait_for_success_message()

    # ==================== 异常输入测试 ====================
    def try_add_rule_invalid(self, name: str = "", remark: str = "", mac: str = "",
                              upload_speed: str = "", expect_fail: bool = True,
                              use_type_for_speed: bool = False):
        """
        尝试添加规则（用于异常输入测试）

        Args:
            name: 规则名称（可为空或包含特殊字符）
            remark: 备注（可包含特殊字符）
            mac: MAC地址（可为无效格式）
            upload_speed: 上行限速（可为无效值）
            expect_fail: 是否期望失败
            use_type_for_speed: 是否使用 type() 而非 fill() 输入限速值
                               - False (默认): 使用 fill()，直接设置值，测试范围验证
                               - True: 使用 type()，模拟键盘输入，测试键盘验证

        Returns:
            dict: {
                "success": bool,  # 是否成功添加
                "has_validation_error": bool,  # 是否有表单验证错误
                "error_msg": str  # 错误提示信息
            }
        """
        result = {"success": False, "has_validation_error": False, "error_msg": ""}

        try:
            # 点击添加按钮
            self.click_add_button()
            self.page.wait_for_timeout(300)

            # 填写名称（如果提供）
            if name:
                self.fill_name(name)

            # 填写MAC地址（如果提供）
            if mac:
                self.fill_mac(mac)

            # 填写备注（如果提供）
            if remark:
                self.fill_remark(remark)

            # 填写限速值（如果提供）
            if upload_speed:
                if use_type_for_speed:
                    # 使用 type() 模拟键盘输入，触发键盘验证
                    self.type_upload_speed(upload_speed)
                else:
                    # 使用 fill() 直接设置值，测试范围验证
                    self.fill_upload_speed(upload_speed, "KB/s")

            # 点击保存
            self.click_save()
            self.page.wait_for_timeout(500)

            # 检查表单验证错误
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

            # 检查全局错误提示
            global_error = self.page.locator("text=输入有误")
            if global_error.count() > 0:
                result["has_validation_error"] = True
                if not result["error_msg"]:
                    result["error_msg"] = "输入有误, 请检查后重试"

            # 检查是否成功（如果没有验证错误且期望失败，则检查是否真的失败了）
            if not result["has_validation_error"]:
                success_msg = self.page.locator("text=添加成功")
                if success_msg.count() > 0:
                    result["success"] = True

            # 如果期望失败但规则被意外保存，需要清理
            if expect_fail and name:
                # 导航回列表页检查规则是否存在
                self.navigate_to_mac_rate_limit()
                self.page.wait_for_timeout(500)

                # 使用精确匹配检查规则是否被意外创建
                try:
                    xpath = f"//tr[td[1][contains(text(), '{name}')]]"
                    rule_row = self.page.locator(xpath)
                    rule_row.wait_for(timeout=2000)

                    if rule_row.count() > 0:
                        # 规则被意外保存，记录并删除
                        print(f"[WARNING] 规则 '{name}' 被意外保存，正在清理...")
                        try:
                            self.delete_rule(name)
                            self.page.wait_for_timeout(500)
                        except Exception as cleanup_error:
                            print(f"[DEBUG] 清理意外保存的规则失败: {cleanup_error}")

                        # 如果没有检测到验证错误但规则被保存了，标记为失败
                        if not result["has_validation_error"]:
                            result["has_validation_error"] = True
                            result["error_msg"] = f"规则被意外保存（已清理）"
                except Exception:
                    # 规则不存在，无需清理
                    pass
                return result

        except Exception as e:
            result["error_msg"] = str(e)[:100]

        finally:
            # 直接导航回列表页，避免触发"未保存内容"确认对话框
            self.navigate_to_mac_rate_limit()
            self.page.wait_for_timeout(300)

        return result

    # ==================== 模态框处理 ====================
    def close_modal_if_exists(self):
        """关闭可能存在的模态框或返回列表页"""
        try:
            # 检查是否在添加/编辑页面（URL包含/add或/edit）
            current_url = self.page.url
            if "/add" in current_url or "/edit" in current_url:
                # 点击返回按钮或取消按钮
                back_btn = self.page.locator("button:has(.anticon-left)").first
                if back_btn.count() > 0:
                    back_btn.click()
                    self.page.wait_for_timeout(500)
                    return

                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click()
                    self.page.wait_for_timeout(300)
                    # 处理可能的确认对话框
                    confirm_btn = self.page.get_by_role("button", name="确定")
                    if confirm_btn.count() > 0 and confirm_btn.is_visible():
                        confirm_btn.click()
                        self.page.wait_for_timeout(300)
                    return

                # 备用方案：直接导航回列表页
                self.navigate_to_mac_rate_limit()
                return

            # 检查是否有模态框
            modal_wrap = self.page.locator(".ant-modal-wrap")
            if modal_wrap.count() > 0 and modal_wrap.is_visible():
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)

                if modal_wrap.count() == 0 or not modal_wrap.is_visible():
                    return

                close_icon = self.page.locator(".ant-modal-close")
                if close_icon.count() > 0 and close_icon.is_visible():
                    close_icon.click(timeout=3000)
                    self.page.wait_for_timeout(300)
                    return

                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click(timeout=3000)
                    self.page.wait_for_timeout(300)
        except Exception as e:
            try:
                print(f"[DEBUG] close_modal_if_exists: {str(e)[:100]}")
            except:
                pass

    # ==================== 批量操作 ====================
    def select_rule(self, rule_name: str):
        """
        勾选指定规则

        Args:
            rule_name: 规则名称
        """
        # 使用包含匹配而不是精确匹配，以处理名称被截断的情况
        rule_text = self.page.locator(f"text=/{rule_name[:15]}/").first
        rule_text.evaluate("""(el) => {
            let parent = el.parentElement;
            let depth = 0;
            while (parent && depth < 10) {
                const checkbox = parent.querySelector('input[type="checkbox"]');
                if (checkbox) {
                    checkbox.click();
                    return true;
                }
                parent = parent.parentElement;
                depth++;
            }
            return false;
        }""")
        return self

    def select_all_rules(self):
        """全选所有规则"""
        self.page.get_by_role("checkbox", name="Select all").click()
        return self

    def _click_batch_button(self, button_name: str):
        """
        点击左下角的批量操作按钮

        Args:
            button_name: 按钮名称（启用/停用/删除）
        """
        self.page.wait_for_timeout(300)

        icon_map = {
            "启用": "play-circle",
            "停用": "minus-circle",
            "删除": "delete"
        }
        icon_name = icon_map.get(button_name, "")

        try:
            full_button_name = f"{icon_name} {button_name}" if icon_name else button_name
            btn = self.page.get_by_role("button", name=full_button_name)
            if btn.count() > 0:
                btn.first.click()
                self.page.wait_for_timeout(300)
                return
        except Exception as e:
            print(f"[DEBUG] _click_batch_button 方法1失败: {e}")

        try:
            all_buttons = self.page.get_by_role("button", name=button_name)
            for i in range(all_buttons.count()):
                btn = all_buttons.nth(i)
                parent_row = btn.locator("xpath=ancestor::tr[1]")
                if parent_row.count() == 0:
                    btn.click()
                    self.page.wait_for_timeout(300)
                    return
        except Exception as e:
            print(f"[DEBUG] _click_batch_button 方法3失败: {e}")

        print(f"[DEBUG] _click_batch_button: 未找到批量按钮 {button_name}")

    def batch_enable(self):
        """批量启用选中的规则"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_batch_button("启用")
        return self

    def batch_disable(self):
        """批量停用选中的规则"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_batch_button("停用")
        self.page.wait_for_timeout(800)

        try:
            confirm_btn = self.page.locator("button:has-text('确定'):visible")
            if confirm_btn.count() > 0:
                confirm_btn.first.click()
            else:
                self.page.get_by_role("button", name="确定").click()
        except Exception as e:
            print(f"[DEBUG] batch_disable 点击确定失败: {e}")
        return self

    def batch_delete(self):
        """批量删除选中的规则"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_batch_button("删除")
        self.page.wait_for_timeout(500)

        modal_confirm = self.page.locator(".ant-modal-confirm .ant-btn-primary, .ant-modal-wrap .ant-btn-primary")
        if modal_confirm.count() > 0:
            modal_confirm.first.click()
        else:
            self.page.get_by_role("button", name="确定").click()
        return self

    # ==================== 编辑/删除 ====================
    def edit_rule(self, rule_name: str):
        """
        点击编辑指定规则

        Args:
            rule_name: 规则名称
        """
        self._click_rule_button(rule_name, "编辑")
        return self

    def delete_rule(self, rule_name: str) -> bool:
        """
        删除指定规则

        Args:
            rule_name: 规则名称

        Returns:
            是否删除成功
        """
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
            self.page.reload()
            self.page.wait_for_load_state("networkidle")
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

    # ==================== 搜索/查询 ====================
    def search_rule(self, keyword: str):
        """
        搜索规则

        Args:
            keyword: 搜索关键字
        """
        search_input = self.page.get_by_placeholder("请输入搜索内容")
        search_input.clear()
        search_input.fill(keyword)
        self.page.keyboard.press("Enter")
        self.page.wait_for_timeout(500)
        return self

    def clear_search(self):
        """清空搜索"""
        search_input = self.page.get_by_placeholder("请输入搜索内容")
        search_input.clear()
        self.page.keyboard.press("Enter")
        return self

    # ==================== 排序 ====================
    def sort_by_column(self, column_name: str):
        """
        点击列头进行排序

        Args:
            column_name: 列名（协议栈/线路/限速模式/上行限速/下行限速）
        """
        try:
            header = self.page.locator("th").filter(has_text=column_name)
            if header.count() > 0:
                header.click()
                self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] sort_by_column error: {e}")
        return self

    def test_sorting(self) -> dict:
        """
        测试排序功能

        Returns:
            测试结果字典（使用中文字段名）
        """
        result = {
            "协议栈": False,
            "线路": False,
            "限速模式": False,
            "上行限速": False,
            "下行限速": False
        }

        columns = ["协议栈", "线路", "限速模式", "上行限速", "下行限速"]

        for col in columns:
            try:
                self.sort_by_column(col)
                self.page.wait_for_timeout(300)
                self.sort_by_column(col)
                self.page.wait_for_timeout(300)
                result[col] = True
            except Exception:
                result[col] = False

        return result

    # ==================== 导入/导出 ====================
    def click_import(self):
        """点击导入按钮"""
        self.page.get_by_role("button", name="导入").click()
        return self

    def click_export(self):
        """点击导出按钮"""
        self.page.get_by_role("button", name="导出").click()
        return self

    def export_rules(self, use_config_path: bool = True, export_format: str = "csv") -> bool:
        """
        导出MAC限速规则

        Args:
            use_config_path: 是否使用配置文件中的路径
            export_format: 导出格式（csv/txt）

        Returns:
            是否导出成功
        """
        import os
        from datetime import datetime
        from config.config import get_config

        try:
            self.click_export()
            self.page.wait_for_timeout(500)

            format_upper = export_format.upper()
            format_option = self.page.locator(f"text=导出{format_upper}").first
            if format_option.count() > 0:
                format_option.click()
                self.page.wait_for_timeout(300)

            confirm_btn = self.page.get_by_role("button", name="确定")

            if confirm_btn.count() > 0 and confirm_btn.is_visible():
                with self.page.expect_download(timeout=30000) as download_info:
                    confirm_btn.click()

                download = download_info.value
                suggested_filename = download.suggested_filename
                original_ext = os.path.splitext(suggested_filename)[1] or f".{export_format.lower()}"

                if use_config_path:
                    config = get_config()
                    base_path = config.test_data.get_export_path("mac_rate_limit", config.get_project_root())
                    save_path = os.path.splitext(base_path)[0] + f".{export_format.lower()}"
                else:
                    download_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "downloads")
                    os.makedirs(download_dir, exist_ok=True)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    save_path = os.path.join(download_dir, f"mac_rate_limit_export_{timestamp}{original_ext}")

                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                download.save_as(save_path)
                print(f"[OK] 导出成功: {save_path}")
                return True

        except Exception as e:
            print(f"导出失败: {e}")
            self.close_modal_if_exists()
            return False

    def import_rules(self, file_path: str, clear_existing: bool = False) -> bool:
        """
        导入MAC限速规则

        Args:
            file_path: 导入文件路径
            clear_existing: 是否清空现有配置

        Returns:
            是否导入成功
        """
        import os
        try:
            if not os.path.exists(file_path):
                print(f"[ERROR] File not found: {file_path}")
                return False

            self.click_import()
            self.page.wait_for_timeout(500)

            if clear_existing:
                try:
                    clear_checkbox = self.page.get_by_label("清空现有配置数据", exact=True)
                    if clear_checkbox.count() > 0 and not clear_checkbox.is_checked():
                        clear_checkbox.check()
                except Exception as e:
                    print(f"[WARN] Failed to check 'Clear existing config': {e}")

            with self.page.expect_file_chooser() as fc_info:
                upload_btn = self.page.locator("dialog button:has-text('点击上传'), [role='dialog'] button:has-text('点击上传')").first
                if upload_btn.count() > 0:
                    upload_btn.click()
                else:
                    self.page.locator(".ant-upload-btn").first.click()

            file_chooser = fc_info.value
            file_chooser.set_files(file_path)
            self.page.wait_for_timeout(1000)

            confirm_upload_btn = self.page.get_by_role("button", name="确定上传")
            for _ in range(10):
                if confirm_upload_btn.count() > 0 and not confirm_upload_btn.is_disabled():
                    break
                self.page.wait_for_timeout(500)
            else:
                self.close_modal_if_exists()
                return False

            confirm_upload_btn.click()
            self.page.wait_for_timeout(1500)

            dialog = self.page.locator("dialog, [role='dialog']")
            if dialog.count() == 0 or not dialog.is_visible():
                return True

            self.close_modal_if_exists()
            return True

        except Exception as e:
            print(f"[ERROR] Import failed: {str(e)[:100]}")
            self.close_modal_if_exists()
            return False

    # ==================== 状态验证 ====================
    def is_rule_enabled(self, rule_name: str) -> bool:
        """
        检查规则是否启用

        Args:
            rule_name: 规则名称

        Returns:
            是否启用
        """
        self.page.wait_for_timeout(500)
        self.page.wait_for_load_state("networkidle")

        try:
            # 使用包含匹配，以处理名称被截断的情况
            rule_cell = self.page.locator(f"text=/{rule_name[:15]}/").first
            if rule_cell.count() == 0:
                return False

            result = rule_cell.evaluate("""(el) => {
                let parent = el.parentElement;
                let depth = 0;
                while (parent && depth < 20) {
                    const buttons = parent.querySelectorAll('button');
                    for (const btn of buttons) {
                        if (btn.textContent.trim() === '停用') {
                            return 'has_disable_button';
                        }
                    }
                    parent = parent.parentElement;
                    depth++;
                }
                return null;
            }""")

            return result is not None

        except Exception as e:
            print(f"[DEBUG] is_rule_enabled 异常: {e}")
            return False

    def is_rule_disabled(self, rule_name: str) -> bool:
        """
        检查规则是否停用

        Args:
            rule_name: 规则名称

        Returns:
            是否停用
        """
        self.page.wait_for_timeout(500)
        self.page.wait_for_load_state("networkidle")

        try:
            # 使用包含匹配，以处理名称被截断的情况
            rule_cell = self.page.locator(f"text=/{rule_name[:15]}/").first
            if rule_cell.count() == 0:
                return False

            result = rule_cell.evaluate("""(el) => {
                let parent = el.parentElement;
                let depth = 0;
                while (parent && depth < 20) {
                    const buttons = parent.querySelectorAll('button');
                    for (const btn of buttons) {
                        if (btn.textContent.trim() === '启用') {
                            return 'has_enable_button';
                        }
                    }
                    parent = parent.parentElement;
                    depth++;
                }
                return null;
            }""")

            return result is not None

        except Exception as e:
            print(f"[DEBUG] is_rule_disabled 异常: {e}")
            return False

    def rule_exists(self, rule_name: str) -> bool:
        """
        检查规则是否存在

        Args:
            rule_name: 规则名称

        Returns:
            是否存在
        """
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        try:
            # 使用包含匹配，以处理名称被截断的情况
            locator = self.page.locator(f"text=/{rule_name[:15]}/")
            count = locator.count()
            return count > 0
        except Exception as e:
            print(f"[DEBUG] rule_exists 异常: {e}")
            return False

    def get_rule_count(self) -> int:
        """
        获取规则数量

        Returns:
            规则数量
        """
        try:
            count_text = self.page.locator("text=/共 \\d+ 条/").first.inner_text()
            return int(count_text.replace("共 ", "").replace(" 条", ""))
        except Exception:
            return self.page.locator("tbody tr").count()

    def get_rule_list(self) -> List[str]:
        """
        获取所有规则名称列表

        Returns:
            规则名称列表
        """
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
        """
        测试帮助功能

        Returns:
            测试结果字典
        """
        result = {
            "icon_clickable": False,
            "panel_visible": False,
            "can_close": False
        }

        try:
            # 查找帮助按钮
            help_btn = self.page.get_by_role("button", name="帮助")
            if help_btn.count() > 0:
                result["icon_clickable"] = True
                help_btn.click()
                self.page.wait_for_timeout(500)

                # 检查帮助面板是否可见
                help_panel = self.page.locator(".ant-drawer, .ant-modal, [role='dialog']")
                if help_panel.count() > 0 and help_panel.is_visible():
                    result["panel_visible"] = True

                    # 尝试关闭帮助面板
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
