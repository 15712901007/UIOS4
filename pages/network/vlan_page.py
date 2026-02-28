"""
VLAN设置页面类

处理VLAN配置的增删改查、启用停用、导入导出等操作
"""
from playwright.sync_api import Page, Locator
from pages.base_page import BasePage
from typing import Optional, List


class VlanPage(BasePage):
    """VLAN设置页面操作类"""

    # 页面URL路径
    VLAN_URL = "/login#/networkConfiguration/vlanSettings"

    def __init__(self, page: Page, base_url: str):
        """
        初始化VLAN页面

        Args:
            page: Playwright Page对象
            base_url: 基础URL
        """
        super().__init__(page)
        self.base_url = base_url

    # ==================== 导航 ====================
    def navigate_to_vlan_settings(self):
        """导航到VLAN设置页面"""
        # 直接通过URL导航（更可靠）
        vlan_url = f"{self.base_url}/#/networkConfiguration/vlanSettings"
        self.page.goto(vlan_url)
        self.page.wait_for_load_state("networkidle")
        return self

    def navigate_to_vlan_direct(self):
        """直接导航到VLAN设置页面"""
        self.page.goto(f"{self.base_url}{self.VLAN_URL}")
        self.page.wait_for_load_state("networkidle")
        return self

    # ==================== 添加VLAN ====================
    def click_add_button(self):
        """点击添加按钮"""
        self.page.get_by_role("button", name="添加").first.click()
        return self

    def fill_vlan_id(self, vlan_id: str):
        """
        填写VLAN ID

        Args:
            vlan_id: VLAN ID (1-4090)
        """
        self.page.get_by_role("textbox", name="vlanID *").fill(str(vlan_id))
        return self

    def fill_vlan_name(self, name: str):
        """
        填写VLAN名称

        Args:
            name: VLAN名称（必须以vlan开头，只支持数字、字母和'_'，长度不超过15位）
        """
        self.page.get_by_role("textbox", name="vlan名称 *").fill(name)
        return self

    def fill_mac(self, mac: str):
        """
        填写MAC地址

        Args:
            mac: MAC地址
        """
        self.page.get_by_role("textbox", name="MAC").fill(mac)
        return self

    def fill_ip(self, ip: str):
        """
        填写IP地址

        Args:
            ip: IP地址
        """
        self.page.get_by_role("textbox", name="IP").fill(ip)
        return self

    def select_subnet_mask(self, mask: str):
        """
        选择子网掩码

        Args:
            mask: 子网掩码 (如 255.255.255.0)
        """
        # 点击子网掩码下拉框
        self.page.get_by_role("combobox", name="子网掩码").click(force=True)

        # 等待下拉列表展开
        self.page.wait_for_timeout(300)

        # 点击下拉列表中的选项（nth(1)选择下拉列表中的选项，因为nth(0)是当前显示值）
        self.page.get_by_title(mask, exact=True).nth(1).click()

        return self

    def select_line(self, line: str):
        """
        选择线路

        Args:
            line: 线路名称 (如 lan1)
        """
        # 点击线路下拉框 - 找到包含线路combobox的ant-select容器
        # 使用force=True绕过元素拦截问题
        self.page.get_by_role("combobox", name="线路").click(force=True)

        # 等待下拉列表展开
        self.page.wait_for_timeout(300)

        # 点击下拉列表中的选项（使用force=True绕过拦截）
        self.page.get_by_title(line, exact=True).nth(1).click(force=True)

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

    def add_vlan(self, vlan_id: str, vlan_name: str,
                 mac: Optional[str] = None,
                 ip: Optional[str] = None,
                 subnet_mask: Optional[str] = None,
                 line: Optional[str] = "lan1",
                 remark: Optional[str] = None) -> bool:
        """
        添加VLAN的完整流程

        Args:
            vlan_id: VLAN ID (1-4090)
            vlan_name: VLAN名称（必须以vlan开头）
            mac: MAC地址（可选）
            ip: IP地址（可选）
            subnet_mask: 子网掩码（可选，默认255.255.255.0）
            line: 线路（默认lan1，后端必需要此参数）
            remark: 备注（可选）

        Returns:
            是否添加成功
        """
        self.click_add_button()
        self.fill_vlan_id(vlan_id)
        self.fill_vlan_name(vlan_name)

        if mac:
            self.fill_mac(mac)
        if ip:
            self.fill_ip(ip)
        # 子网掩码默认选择（可选但建议填写）
        if subnet_mask:
            self.select_subnet_mask(subnet_mask)
        # 线路是后端必需参数，默认使用lan1
        if line:
            self.select_line(line)
        if remark:
            self.fill_remark(remark)

        self.click_save()

        # 等待成功提示
        success = self.wait_for_success_message()

        if success:
            # 等待页面操作完成
            self.page.wait_for_timeout(2000)

            # 刷新页面确保数据同步
            self.page.reload()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)

        return success

    def try_add_vlan_invalid(self, vlan_id: str, vlan_name: str,
                              mac: str = None,
                              ip: str = None,
                              subnet_mask: str = None,
                              line: str = "lan1",
                              remark: str = None) -> dict:
        """
        尝试添加不合规的VLAN（用于异常测试）

        Args:
            vlan_id: VLAN ID
            vlan_name: VLAN名称
            mac: MAC地址（可选）
            ip: IP地址（可选）
            subnet_mask: 子网掩码（可选）
            line: 线路（默认lan1）
            remark: 备注（可选）

        Returns:
            dict: {"success": bool, "error_msg": str, "has_validation_error": bool}
        """
        result = {"success": False, "error_msg": "", "has_validation_error": False}

        try:
            self.click_add_button()
            self.fill_vlan_id(vlan_id)
            self.fill_vlan_name(vlan_name)

            if mac is not None:
                self.fill_mac(mac)
            if ip is not None:
                self.fill_ip(ip)
            if subnet_mask:
                self.select_subnet_mask(subnet_mask)
            if line:
                self.select_line(line)
            if remark:
                self.fill_remark(remark)

            self.click_save()
            self.page.wait_for_timeout(500)

            # 优先检查输入框下面的红色错误提示（更具体的错误信息）
            # 检查是否有表单验证错误（红色边框或错误提示）
            error_locator = self.page.locator(".ant-form-item-explain-error, .ant-input-status-error, .ant-select-status-error")
            if error_locator.count() > 0:
                result["has_validation_error"] = True
                # 尝试获取所有错误消息，拼接起来
                error_texts = self.page.locator(".ant-form-item-explain-error").all_text_contents()
                if error_texts:
                    # 过滤空字符串并拼接
                    error_msgs = [t.strip() for t in error_texts if t.strip()]
                    if error_msgs:
                        result["error_msg"] = "; ".join(error_msgs)
                        print(f"[DEBUG] 表单验证错误: {result['error_msg']}")
                    else:
                        result["error_msg"] = "表单验证失败"
                else:
                    result["error_msg"] = "表单验证失败"

            # 检查是否出现错误提示消息（仅在未获取到表单错误时使用）
            if not result["error_msg"]:
                error_msg = self.page.locator(".ant-message-error, .ant-notification-error")
                if error_msg.count() > 0:
                    result["error_msg"] = error_msg.first.text_content() or "操作失败"
                    result["has_validation_error"] = True
                    print(f"[DEBUG] 错误提示: {result['error_msg']}")

            # 检查对话框是否还在（如果还在说明添加失败）
            dialog = self.page.locator("dialog, [role='dialog']")
            if dialog.count() > 0 and dialog.is_visible():
                # 对话框还在，说明没有成功
                result["success"] = False
                # 如果还没有获取到错误信息，尝试获取对话框内的错误信息
                if not result["error_msg"]:
                    dialog_error = dialog.locator(".ant-form-item-explain-error, .ant-alert-error")
                    if dialog_error.count() > 0:
                        result["error_msg"] = dialog_error.first.text_content() or result["error_msg"]
                        result["has_validation_error"] = True
            else:
                # 对话框关闭了，可能成功
                result["success"] = True

        except Exception as e:
            result["error_msg"] = str(e)[:100]
            result["success"] = False

        finally:
            # 强制关闭对话框：先按ESC，再点击取消，最后刷新页面
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click()
                    self.page.wait_for_timeout(200)
            except:
                pass
            # 刷新页面清除所有残留状态
            self.page.reload()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)

        return result

    def try_add_invalid_extended_ip(self, vlan_name: str, invalid_ip: str) -> dict:
        """
        尝试添加不合规的扩展IP（用于异常测试）

        Args:
            vlan_name: 要编辑的VLAN名称
            invalid_ip: 不合规的IP地址

        Returns:
            dict: {"success": bool, "error_msg": str, "has_validation_error": bool}
        """
        result = {"success": False, "error_msg": "", "has_validation_error": False}

        try:
            # 编辑VLAN
            self.edit_vlan(vlan_name)
            self.page.wait_for_timeout(500)

            # 点击扩展IP区域的"添加"按钮（在扩展IP标签下方）
            # 注意：这是扩展IP区域的添加按钮，不是顶部的添加VLAN按钮
            add_ext_btn = self.page.get_by_role("button", name="添加").last  # 使用last获取扩展IP区域的添加按钮
            if add_ext_btn.count() > 0:
                add_ext_btn.click()
                self.page.wait_for_timeout(500)
                print(f"[DEBUG] 已点击扩展IP添加按钮")

                # 找到扩展IP输入框 - placeholder是"请输入IP地址"
                # 使用getByRole来定位，这样更可靠
                ext_ip_input = self.page.get_by_role("textbox", name="请输入IP地址")
                if ext_ip_input.count() > 0:
                    # 填写不合规的IP
                    ext_ip_input.fill(invalid_ip)
                    print(f"[DEBUG] 已填写扩展IP: {invalid_ip}")

                    # 点击保存
                    self.click_save()
                    self.page.wait_for_timeout(800)

                    # 检查扩展IP的验证错误提示
                    # 错误消息是"请输入正确的IP"，显示在输入框附近
                    error_text_locator = self.page.locator("text=请输入正确的IP")
                    if error_text_locator.count() > 0:
                        result["has_validation_error"] = True
                        result["error_msg"] = "请输入正确的IP"
                        print(f"[DEBUG] 扩展IP验证错误: {result['error_msg']}")

                    # 备用：检查.ant-form-item-explain-error
                    if not result["has_validation_error"]:
                        error_locator = self.page.locator(".ant-form-item-explain-error")
                        if error_locator.count() > 0:
                            result["has_validation_error"] = True
                            error_text = error_locator.first.text_content() or ""
                            result["error_msg"] = error_text.strip()
                            print(f"[DEBUG] 表单验证错误: {result['error_msg']}")

                    # 检查输入框是否有错误状态
                    if not result["has_validation_error"]:
                        error_input = self.page.locator(".ant-input-status-error, .ant-form-item-has-error")
                        if error_input.count() > 0:
                            result["has_validation_error"] = True
                            result["error_msg"] = "输入格式错误"
                            print(f"[DEBUG] 输入框状态错误")

                    # 检查是否出现全局错误消息
                    error_msg = self.page.locator(".ant-message-error, .ant-notification-error")
                    if error_msg.count() > 0:
                        msg_text = error_msg.first.text_content() or ""
                        if "输入有误" in msg_text:
                            result["has_validation_error"] = True
                            if not result["error_msg"]:
                                result["error_msg"] = msg_text
                            print(f"[DEBUG] 全局错误提示: {msg_text}")

                    # 检查对话框是否还在（还在说明保存失败）
                    dialog_still_open = self.page.locator("dialog, [role='dialog']").count() > 0
                    if dialog_still_open:
                        result["success"] = False
                        if not result["has_validation_error"]:
                            result["has_validation_error"] = True
                            result["error_msg"] = "保存被阻止"
                    else:
                        result["success"] = True

                    print(f"[DEBUG] 扩展IP验证结果: success={result['success']}, error={result['error_msg']}, has_error={result['has_validation_error']}")
                else:
                    result["error_msg"] = "未找到扩展IP输入框"
                    print(f"[DEBUG] {result['error_msg']}")
            else:
                result["error_msg"] = "未找到扩展IP添加按钮"
                print(f"[DEBUG] {result['error_msg']}")

        except Exception as e:
            result["error_msg"] = str(e)[:100]
            print(f"[DEBUG] try_add_invalid_extended_ip 异常: {result['error_msg']}")

        finally:
            # 强制关闭编辑页面并返回列表页面
            try:
                # 点击取消按钮（编辑页面上的取消按钮）
                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click()
                    self.page.wait_for_timeout(500)

                    # 可能会弹出"是否确定退出"的确认对话框，需要点击确定
                    confirm_btn = self.page.get_by_role("button", name="确定")
                    if confirm_btn.count() > 0 and confirm_btn.is_visible():
                        confirm_btn.click()
                        self.page.wait_for_timeout(300)
            except:
                pass

            # 直接导航回VLAN列表页面，确保状态干净
            try:
                self.page.goto(f"{self.base_url}/#/networkConfiguration/vlanSettings")
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(500)
            except:
                pass
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)

        return result

    # ==================== 启用/停用VLAN ====================
    def _click_vlan_button(self, vlan_name: str, button_name: str) -> bool:
        """
        点击VLAN行中的指定按钮

        Args:
            vlan_name: VLAN名称
            button_name: 按钮名称（编辑/停用/启用/删除）

        Returns:
            是否成功点击
        """
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(300)

        try:
            # 先检查VLAN是否存在
            vlan_text = self.page.get_by_text(vlan_name, exact=True)
            if vlan_text.count() == 0:
                print(f"[DEBUG] _click_vlan_button: VLAN {vlan_name} 不存在")
                return False

            # 使用evaluate找到并点击同一行的按钮 - 更灵活的方式
            result = vlan_text.first.evaluate("""(el) => {
                let parent = el.parentElement;
                let depth = 0;
                while (parent && depth < 20) {
                    // 直接查找所有按钮，不限制层级
                    const btns = parent.querySelectorAll('button');
                    for (const btn of btns) {
                        // 精确匹配按钮文本
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
            print(f"[DEBUG] _click_vlan_button 异常: {e}")
            return False

    def disable_vlan(self, vlan_name: str) -> bool:
        """
        停用指定VLAN

        Args:
            vlan_name: VLAN名称

        Returns:
            是否停用成功
        """
        # 点击停用按钮
        self._click_vlan_button(vlan_name, "停用")

        # 停用有确认对话框，需要点击确定
        self.page.wait_for_timeout(500)

        # 在对话框中点击确定按钮
        try:
            # 使用 dialog 角色定位确定按钮
            confirm_btn = self.page.locator("dialog button:has-text('确定'), [role='dialog'] button:has-text('确定')")
            if confirm_btn.count() > 0:
                confirm_btn.first.click()
            else:
                self.page.get_by_role("button", name="确定").click()
        except Exception as e:
            print(f"[DEBUG] disable_vlan 点击确定失败: {e}")
            return False

        # 等待成功提示
        try:
            self.page.wait_for_selector("text=停用成功", timeout=5000)
            return True
        except Exception:
            return self.wait_for_success_message()

    def enable_vlan(self, vlan_name: str) -> bool:
        """
        启用指定VLAN

        Args:
            vlan_name: VLAN名称

        Returns:
            是否启用成功
        """
        # 点击启用按钮
        self._click_vlan_button(vlan_name, "启用")

        # 启用没有确认对话框，直接等待成功提示
        try:
            self.page.wait_for_selector("text=启用成功", timeout=5000)
            return True
        except Exception:
            return self.wait_for_success_message()

    # ==================== 模态框处理 ====================
    def close_modal_if_exists(self):
        """
        关闭可能存在的模态框

        检查并关闭页面上的ant-design模态框
        """
        try:
            # 检查是否有模态框存在
            modal_wrap = self.page.locator(".ant-modal-wrap")
            if modal_wrap.count() > 0 and modal_wrap.is_visible():
                # 先尝试按ESC键关闭（最简单的方式）
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)

                # 检查是否关闭成功
                if modal_wrap.count() == 0 or not modal_wrap.is_visible():
                    print("[DEBUG] 已关闭存在的模态框（ESC）")
                    return

                # 尝试点击关闭图标
                close_icon = self.page.locator(".ant-modal-close")
                if close_icon.count() > 0 and close_icon.is_visible():
                    close_icon.click(timeout=3000)
                    self.page.wait_for_timeout(300)
                    print("[DEBUG] 已关闭存在的模态框（关闭图标）")
                    return

                # 尝试点击取消按钮
                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click(timeout=3000)
                    self.page.wait_for_timeout(300)
                    print("[DEBUG] 已关闭存在的模态框（取消按钮）")

        except Exception as e:
            # 使用安全的字符串处理避免编码错误
            try:
                error_msg = str(e)[:100]  # 截取前100个字符
                print(f"[DEBUG] close_modal_if_exists: {error_msg}")
            except:
                print("[DEBUG] close_modal_if_exists: error occurred")

    # ==================== 批量操作 ====================
    def select_vlan(self, vlan_name: str):
        """
        勾选指定VLAN

        Args:
            vlan_name: VLAN名称
        """
        vlan_text = self.page.get_by_text(vlan_name, exact=True)

        # 使用evaluate找到并点击同一行的复选框
        vlan_text.evaluate("""(el) => {
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

    def select_all_vlans(self):
        """全选所有VLAN"""
        self.page.get_by_role("checkbox", name="Select all").click()
        return self

    def _click_batch_button(self, button_name: str):
        """
        点击左下角的批量操作按钮（选中记录后出现的带图标按钮）

        Args:
            button_name: 按钮名称（启用/停用/删除）
        """
        # 批量操作按钮在选中记录后出现，带有图标（play-circle/minus-circle/delete）
        # 按钮名称格式："{icon-name} {button_name}"，例如 "minus-circle 停用"

        # 等待批量操作按钮区域出现
        self.page.wait_for_timeout(300)

        # 图标名称映射
        icon_map = {
            "启用": "play-circle",
            "停用": "minus-circle",
            "删除": "delete"
        }
        icon_name = icon_map.get(button_name, "")

        # 方法1：使用完整的按钮名称定位（最精确）
        # Playwright的getByRole会匹配包含该文字的按钮
        try:
            # 先尝试带图标的完整名称
            full_button_name = f"{icon_name} {button_name}" if icon_name else button_name
            btn = self.page.get_by_role("button", name=full_button_name)
            if btn.count() > 0:
                print(f"[DEBUG] _click_batch_button: 找到带图标按钮 '{full_button_name}'")
                btn.first.click()
                self.page.wait_for_timeout(300)
                return
        except Exception as e:
            print(f"[DEBUG] _click_batch_button 方法1失败: {e}")

        # 方法2：查找包含"已选"区域内的按钮
        try:
            # 找到显示"已选 X 条"的区域
            selected_area = self.page.locator("text=/已选.*条/")
            if selected_area.count() > 0:
                # 在同一父容器中查找按钮
                parent = selected_area.first.locator("xpath=ancestor::*[contains(@class, 'ant-table-wrapper') or contains(@class, 'batch')][1]")
                batch_btn = parent.locator(f"button:has-text('{button_name}')").first
                if batch_btn.count() > 0:
                    print(f"[DEBUG] _click_batch_button: 通过'已选'区域找到按钮 {button_name}")
                    batch_btn.click()
                    self.page.wait_for_timeout(300)
                    return
        except Exception as e:
            print(f"[DEBUG] _click_batch_button 方法2失败: {e}")

        # 方法3：查找不在表格行内的按钮（备用）
        try:
            all_buttons = self.page.get_by_role("button", name=button_name)
            for i in range(all_buttons.count()):
                btn = all_buttons.nth(i)
                # 检查是否在表格行内
                parent_row = btn.locator("xpath=ancestor::tr[1]")
                if parent_row.count() == 0:
                    print(f"[DEBUG] _click_batch_button: 找到非行内按钮 {button_name}")
                    btn.click()
                    self.page.wait_for_timeout(300)
                    return
        except Exception as e:
            print(f"[DEBUG] _click_batch_button 方法3失败: {e}")

        print(f"[DEBUG] _click_batch_button: 未找到批量按钮 {button_name}")

    def batch_enable(self):
        """批量启用选中的VLAN"""
        # 先关闭可能存在的模态框
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)

        # 点击左下角的批量启用按钮
        self._click_batch_button("启用")
        return self

    def batch_disable(self):
        """批量停用选中的VLAN"""
        # 先关闭可能存在的模态框
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)

        # 点击左下角的批量停用按钮
        self._click_batch_button("停用")

        # 停用有确认对话框，需要点击确定
        self.page.wait_for_timeout(800)

        try:
            # 等待对话框出现
            dialog = self.page.locator("dialog, [role='dialog'], .ant-modal")
            print(f"[DEBUG] batch_disable: 找到 {dialog.count()} 个对话框")

            # 使用多种方式定位确定按钮
            confirm_btn = self.page.locator("button:has-text('确定'):visible")
            if confirm_btn.count() > 0:
                print(f"[DEBUG] batch_disable: 找到 {confirm_btn.count()} 个确定按钮")
                confirm_btn.first.click()
                print("[DEBUG] batch_disable: 已点击确定按钮")
            else:
                # 备用方案
                self.page.get_by_role("button", name="确定").click()
                print("[DEBUG] batch_disable: 使用备用方案点击确定")
        except Exception as e:
            print(f"[DEBUG] batch_disable 点击确定失败: {e}")
        return self

    def batch_delete(self):
        """批量删除选中的VLAN"""
        # 先关闭可能存在的模态框
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)

        # 点击左下角的批量删除按钮
        self._click_batch_button("删除")

        # 等待确认对话框出现
        self.page.wait_for_timeout(500)

        # 在模态框内点击确定按钮
        modal_confirm = self.page.locator(".ant-modal-confirm .ant-btn-primary, .ant-modal-wrap .ant-btn-primary")
        if modal_confirm.count() > 0:
            modal_confirm.first.click()
        else:
            self.page.get_by_role("button", name="确定").click()
        return self

    def batch_enable_vlans(self, vlan_names: List[str]) -> bool:
        """
        批量启用指定名称的VLAN

        Args:
            vlan_names: VLAN名称列表

        Returns:
            是否操作成功
        """
        for name in vlan_names:
            self.select_vlan(name)

        self.batch_enable()
        return self.wait_for_success_message()

    def batch_disable_vlans(self, vlan_names: List[str]) -> bool:
        """
        批量停用指定名称的VLAN

        Args:
            vlan_names: VLAN名称列表

        Returns:
            是否操作成功
        """
        for name in vlan_names:
            self.select_vlan(name)

        self.batch_disable()
        return self.wait_for_success_message()

    def batch_delete_vlans(self, vlan_names: List[str]) -> bool:
        """
        批量删除指定名称的VLAN

        Args:
            vlan_names: VLAN名称列表

        Returns:
            是否操作成功
        """
        for name in vlan_names:
            self.select_vlan(name)

        self.batch_delete()
        return self.wait_for_success_message()

    # ==================== 编辑/删除 ====================
    def edit_vlan(self, vlan_name: str):
        """
        点击编辑指定VLAN

        Args:
            vlan_name: VLAN名称
        """
        self._click_vlan_button(vlan_name, "编辑")
        return self

    def delete_vlan(self, vlan_name: str) -> bool:
        """
        删除指定VLAN

        Args:
            vlan_name: VLAN名称

        Returns:
            是否删除成功
        """
        # 等待页面加载完成
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        try:
            # 获取删除前的条目数
            count_before = self.get_vlan_count()
            print(f"[DEBUG] 删除前条目数: {count_before}")

            # 点击删除按钮
            click_result = self._click_vlan_button(vlan_name, "删除")
            if not click_result:
                print(f"[DEBUG] 未找到删除按钮: {vlan_name}")
                return False

            # 等待确认对话框出现
            self.page.wait_for_timeout(500)

            # 确认删除 - 点击确定按钮
            confirm_btn = self.page.get_by_role("button", name="确定")
            if confirm_btn.count() > 0:
                confirm_btn.click()

            # 等待操作完成
            self.page.wait_for_timeout(1000)

            # 刷新页面确保数据同步
            self.page.reload()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)

            # 获取删除后的条目数
            count_after = self.get_vlan_count()
            print(f"[DEBUG] 删除后条目数: {count_after}")

            # 通过条目数减少来判断删除成功
            if count_after < count_before:
                print(f"[DEBUG] 删除成功，条目数从 {count_before} 减少到 {count_after}")
                return True

            # 也检查VLAN是否已不存在
            if not self.vlan_exists(vlan_name):
                print(f"[DEBUG] VLAN {vlan_name} 已不存在")
                return True

            # 尝试等待成功消息作为备用判断
            if self.wait_for_success_message():
                return True

            print(f"[DEBUG] 删除失败，条目数未变化，VLAN仍存在")
            return False

        except Exception as e:
            print(f"删除VLAN失败: {e}")
            return False

    def cancel_delete(self, vlan_name: str):
        """
        取消删除操作

        Args:
            vlan_name: VLAN名称
        """
        row = self.page.locator("tr").filter(has_text=vlan_name)
        row.get_by_role("button", name="删除").click()

        # 取消删除
        self.page.get_by_role("button", name="取消").click()
        return self

    # ==================== 搜索/查询 ====================
    def search_vlan(self, keyword: str):
        """
        搜索VLAN

        Args:
            keyword: 搜索关键字
        """
        # 使用placeholder定位搜索框
        search_input = self.page.get_by_placeholder("请输入搜索内容")
        search_input.clear()
        search_input.fill(keyword)
        # 点击搜索图标或按回车
        self.page.keyboard.press("Enter")
        self.page.wait_for_timeout(500)
        return self

    def clear_search(self):
        """清空搜索"""
        search_input = self.page.get_by_placeholder("请输入搜索内容")
        search_input.clear()
        self.page.keyboard.press("Enter")
        return self

    # ==================== 导入/导出 ====================
    def click_import(self):
        """点击导入按钮"""
        self.page.get_by_role("button", name="导入").click()
        return self

    def click_export(self):
        """点击导出按钮"""
        self.page.get_by_role("button", name="导出").click()
        return self

    def export_vlans(self, use_config_path: bool = True, export_format: str = "csv") -> bool:
        """
        导出VLAN配置

        Args:
            use_config_path: 是否使用配置文件中的路径（默认True）
            export_format: 导出格式，"csv"或"txt"（默认"csv"）

        Returns:
            是否导出成功
        """
        import os
        from datetime import datetime
        from config.config import get_config

        try:
            # 点击导出按钮
            self.click_export()

            # 等待"导出格式"对话框出现
            self.page.wait_for_timeout(500)

            # 选择导出格式（CSV或TXT）
            format_upper = export_format.upper()
            format_option = self.page.locator(f"text=导出{format_upper}").first
            if format_option.count() > 0:
                # 点击格式选项（可能需要点击其父元素或附近的单选框）
                format_option.click()
                print(f"[DEBUG] 选择了导出格式: {format_upper}")
                self.page.wait_for_timeout(300)

            # 点击确定按钮
            confirm_btn = self.page.get_by_role("button", name="确定")

            if confirm_btn.count() > 0 and confirm_btn.is_visible():
                # 监听下载事件，然后点击确定
                with self.page.expect_download(timeout=30000) as download_info:
                    confirm_btn.click()

                download = download_info.value
                # 获取原始文件名和扩展名
                suggested_filename = download.suggested_filename
                original_ext = os.path.splitext(suggested_filename)[1] or f".{export_format.lower()}"

                # 准备保存路径
                if use_config_path:
                    config = get_config()
                    base_path = config.test_data.get_export_path("vlan", config.get_project_root())
                    # 根据导出格式修改扩展名
                    save_path = os.path.splitext(base_path)[0] + f".{export_format.lower()}"
                else:
                    download_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "downloads")
                    os.makedirs(download_dir, exist_ok=True)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    save_path = os.path.join(download_dir, f"vlan_export_{timestamp}{original_ext}")

                # 确保目录存在
                os.makedirs(os.path.dirname(save_path), exist_ok=True)

                # 保存下载文件到指定路径
                download.save_as(save_path)
                print(f"[OK] 导出成功: {suggested_filename} -> {save_path}")
                return True
            else:
                # 没有确认对话框，直接等待下载
                with self.page.expect_download(timeout=30000) as download_info:
                    self.click_export()

                download = download_info.value
                suggested_filename = download.suggested_filename
                original_ext = os.path.splitext(suggested_filename)[1] or f".{export_format.lower()}"

                if use_config_path:
                    config = get_config()
                    base_path = config.test_data.get_export_path("vlan", config.get_project_root())
                    save_path = os.path.splitext(base_path)[0] + f".{export_format.lower()}"
                else:
                    download_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "downloads")
                    os.makedirs(download_dir, exist_ok=True)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    save_path = os.path.join(download_dir, f"vlan_export_{timestamp}{original_ext}")

                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                download.save_as(save_path)
                print(f"[OK] 导出成功: {save_path}")
                return True

        except Exception as e:
            print(f"导出失败: {e}")
            # 尝试关闭可能存在的对话框
            self.close_modal_if_exists()
            return False

    def import_vlans(self, file_path: str, clear_existing: bool = False) -> bool:
        """
        导入VLAN配置

        Args:
            file_path: 导入文件路径
            clear_existing: 是否清空现有配置（默认False）

        Returns:
            是否导入成功
        """
        import os
        try:
            # 检查文件是否存在
            if not os.path.exists(file_path):
                print(f"[ERROR] File not found: {file_path}")
                return False

            # 点击导入按钮打开对话框
            self.click_import()
            self.page.wait_for_timeout(500)

            # 如果需要清空现有配置，勾选复选框
            if clear_existing:
                # 使用get_by_label来勾选checkbox（更可靠）
                try:
                    clear_checkbox = self.page.get_by_label("清空现有配置数据", exact=True)
                    if clear_checkbox.count() > 0 and not clear_checkbox.is_checked():
                        clear_checkbox.check()
                        print("[DEBUG] Checked 'Clear existing config' option using get_by_label")
                    else:
                        # 备用方案：点击包含该文本的label
                        label = self.page.locator("label:has-text('清空现有配置数据')").first
                        if label.count() > 0:
                            label.click()
                            print("[DEBUG] Checked 'Clear existing config' option using label click")
                except Exception as e:
                    print(f"[WARN] Failed to check 'Clear existing config': {e}")

            # 处理文件上传 - 点击"点击上传"按钮触发文件选择器
            with self.page.expect_file_chooser() as fc_info:
                # 使用精确匹配找到对话框内的"点击上传"按钮（button元素，不是span）
                upload_btn = self.page.locator("dialog button:has-text('点击上传'), [role='dialog'] button:has-text('点击上传')").first
                if upload_btn.count() > 0:
                    upload_btn.click()
                else:
                    # 备用方案：点击上传区域
                    self.page.locator(".ant-upload-btn").first.click()

            file_chooser = fc_info.value
            file_chooser.set_files(file_path)
            print(f"[DEBUG] File selected: {file_path}")

            # 等待文件上传完成（"确定上传"按钮变为可用状态）
            self.page.wait_for_timeout(1000)

            # 等待"确定上传"按钮变为可用
            confirm_upload_btn = self.page.get_by_role("button", name="确定上传")
            for _ in range(10):
                if confirm_upload_btn.count() > 0 and not confirm_upload_btn.is_disabled():
                    break
                self.page.wait_for_timeout(500)
            else:
                print("[WARN] Upload button still disabled after timeout")
                self.close_modal_if_exists()
                return False

            # 点击"确定上传"按钮
            confirm_upload_btn.click()
            print("[DEBUG] Upload confirmed")

            # 等待导入完成（对话框关闭或出现成功消息）
            self.page.wait_for_timeout(1500)

            # 检查是否有上传成功的消息
            try:
                # 检查 "上传成功" 消息
                success_msg = self.page.locator("text=/上传成功|导入成功/")
                if success_msg.count() > 0:
                    print(f"[OK] Import successful - message detected")
            except Exception:
                pass

            # 检查对话框是否关闭（表示导入完成）
            dialog = self.page.locator("dialog, [role='dialog']")
            if dialog.count() == 0 or not dialog.is_visible():
                print("[OK] Import completed (dialog closed)")
                return True

            # 如果对话框还在，尝试关闭
            self.close_modal_if_exists()
            print("[OK] Import completed")
            return True

        except Exception as e:
            # 使用ascii编码避免编码问题
            error_msg = str(e).encode('ascii', 'ignore').decode('ascii')
            print(f"[ERROR] Import failed: {error_msg}")
            # 尝试关闭可能存在的对话框
            self.close_modal_if_exists()
            return False

    def upload_import_file(self, file_path: str):
        """
        上传导入文件

        Args:
            file_path: 文件路径
        """
        self.click_import()

        # 处理文件上传对话框
        with self.page.expect_file_chooser() as fc_info:
            self.page.click("input[type='file']")

        file_chooser = fc_info.value
        file_chooser.set_files(file_path)
        return self

    # ==================== 扩展IP操作 ====================
    def add_extended_ip(self, ip: str, subnet_mask: str = "255.255.255.0"):
        """
        添加扩展IP（在添加/编辑VLAN页面）

        Args:
            ip: 扩展IP地址
            subnet_mask: 子网掩码（暂未使用，界面可能自动填充）
        """
        print(f"[DEBUG] 正在添加扩展IP: {ip}")

        # 点击扩展IP区域的"添加"按钮（使用.last获取扩展IP区域的添加按钮）
        add_ext_btn = self.page.get_by_role("button", name="添加").last
        if add_ext_btn.count() > 0:
            add_ext_btn.click()
            self.page.wait_for_timeout(500)
            print(f"[DEBUG] 已点击扩展IP添加按钮")

        # 找到扩展IP输入框 - placeholder是"请输入IP地址"
        ext_ip_input = self.page.get_by_role("textbox", name="请输入IP地址")
        if ext_ip_input.count() > 0:
            ext_ip_input.fill(ip)
            print(f"[DEBUG] 已填写扩展IP: {ip}")
        else:
            print(f"[DEBUG] 未找到扩展IP输入框")

        return self

    def remove_extended_ip(self, index: int):
        """
        删除指定索引的扩展IP

        Args:
            index: 扩展IP索引（从0开始）
        """
        # 找到扩展IP行的删除按钮
        delete_buttons = self.page.locator(".extended-ip-item button, [class*='delete']")
        if index < delete_buttons.count():
            delete_buttons.nth(index).click()
        return self

    # ==================== 状态验证 ====================
    def is_vlan_enabled(self, vlan_name: str) -> bool:
        """
        检查VLAN是否启用

        启用状态特征：有"停用"按钮，有play-circle图标

        Args:
            vlan_name: VLAN名称

        Returns:
            是否启用
        """
        self.page.wait_for_timeout(500)
        self.page.wait_for_load_state("networkidle")

        try:
            # 方法1: 直接在页面中查找包含VLAN名称的行，然后检查是否有"停用"按钮
            # 使用 XPath 或 locator 查找包含 vlan_name 的容器
            vlan_cell = self.page.locator(f"text={vlan_name}").first
            if vlan_cell.count() == 0:
                return False

            # 使用 evaluate 向上查找父容器，然后查找按钮
            result = vlan_cell.evaluate("""(el) => {
                let parent = el.parentElement;
                let depth = 0;
                while (parent && depth < 20) {
                    // 检查是否有"停用"按钮（不包括"启用"）
                    const buttons = parent.querySelectorAll('button');
                    for (const btn of buttons) {
                        const text = btn.textContent.trim();
                        if (text === '停用') {
                            return 'has_disable_button';
                        }
                    }
                    // 检查是否有 play-circle 图标
                    const imgs = parent.querySelectorAll('img');
                    for (const img of imgs) {
                        if (img.alt && img.alt.includes('play-circle')) {
                            return 'has_play_icon';
                        }
                    }
                    parent = parent.parentElement;
                    depth++;
                }
                return null;
            }""")

            if result:
                return True

        except Exception as e:
            print(f"[DEBUG] is_vlan_enabled 异常: {e}")

        return False

    def is_vlan_disabled(self, vlan_name: str) -> bool:
        """
        检查VLAN是否停用

        停用状态特征：有"启用"按钮（不是停用），有minus-circle图标

        Args:
            vlan_name: VLAN名称

        Returns:
            是否停用
        """
        self.page.wait_for_timeout(500)
        self.page.wait_for_load_state("networkidle")

        try:
            # 方法1: 直接在页面中查找包含VLAN名称的行，然后检查是否有"启用"按钮
            vlan_cell = self.page.locator(f"text={vlan_name}").first
            if vlan_cell.count() == 0:
                print(f"[DEBUG] is_vlan_disabled - 找不到VLAN: {vlan_name}")
                return False

            # 使用 evaluate 向上查找父容器，然后查找按钮
            result = vlan_cell.evaluate("""(el) => {
                let parent = el.parentElement;
                let depth = 0;
                while (parent && depth < 20) {
                    // 检查是否有"启用"按钮（注意：是单独的"启用"，不是"停用"）
                    const buttons = parent.querySelectorAll('button');
                    for (const btn of buttons) {
                        const text = btn.textContent.trim();
                        if (text === '启用') {
                            return 'has_enable_button';
                        }
                    }
                    // 检查是否有 minus-circle 图标
                    const imgs = parent.querySelectorAll('img');
                    for (const img of imgs) {
                        if (img.alt && img.alt.includes('minus-circle')) {
                            return 'has_minus_icon';
                        }
                    }
                    parent = parent.parentElement;
                    depth++;
                }
                return null;
            }""")

            print(f"[DEBUG] is_vlan_disabled - evaluate结果: {result}")

            if result:
                return True

        except Exception as e:
            print(f"[DEBUG] is_vlan_disabled 异常: {e}")

        return False

    def vlan_exists(self, vlan_name: str) -> bool:
        """
        检查VLAN是否存在

        Args:
            vlan_name: VLAN名称

        Returns:
            是否存在
        """
        # 等待页面稳定
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        try:
            # 使用Playwright的 locator 查找包含VLAN名称的元素
            # 使用 get_by_text 精确匹配
            locator = self.page.get_by_text(vlan_name, exact=True)
            count = locator.count()
            print(f"[DEBUG] vlan_exists('{vlan_name}'): locator count = {count}")
            return count > 0

        except Exception as e:
            print(f"[DEBUG] vlan_exists 异常: {e}")
            return False

    def get_vlan_count(self) -> int:
        """
        获取VLAN数量

        Returns:
            VLAN数量
        """
        try:
            count_text = self.page.locator("text=/共 \\d+ 条/").first.inner_text()
            return int(count_text.replace("共 ", "").replace(" 条", ""))
        except Exception:
            # 统计表格行数
            return self.page.locator("tbody tr").count()

    def get_selected_count(self) -> int:
        """
        获取当前选中的VLAN数量

        Returns:
            选中的VLAN数量
        """
        try:
            selected_text = self.page.locator("text=/已选 \\d+ 条/")
            if selected_text.count() > 0:
                text = selected_text.first.inner_text()
                return int(text.replace("已选 ", "").replace(" 条", ""))
        except Exception:
            pass
        return 0

    def get_vlan_list(self) -> List[str]:
        """
        获取所有VLAN名称列表

        Returns:
            VLAN名称列表
        """
        vlan_names = []
        rows = self.page.locator("tbody tr")
        for i in range(rows.count()):
            try:
                name_cell = rows.nth(i).locator("td").nth(1)  # 第二列是VLAN名称
                vlan_names.append(name_cell.inner_text())
            except Exception:
                continue
        return vlan_names

    # ==================== 错误信息获取 ====================
    def get_error_message(self) -> Optional[str]:
        """
        获取当前显示的错误信息

        Returns:
            错误信息，如果没有则返回None
        """
        try:
            # 检查表单验证错误
            error_locators = [
                ".ant-form-item-explain-error",
                "[class*='error']",
                ".error-message",
            ]

            for selector in error_locators:
                locator = self.page.locator(selector)
                if locator.count() > 0 and locator.is_visible():
                    return locator.inner_text()

            return None
        except Exception:
            return None

    def has_validation_error(self) -> bool:
        """
        检查是否有表单验证错误

        Returns:
            是否有验证错误
        """
        return self.page.locator(".ant-form-item-explain-error, [class*='error']").count() > 0
