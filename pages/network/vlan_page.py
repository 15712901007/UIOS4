"""
VLAN设置页面类

处理VLAN配置的增删改查、启用停用、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作
"""
from playwright.sync_api import Page, Locator
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class VlanPage(IkuaiTablePage):
    """VLAN设置页面操作类"""

    MODULE_NAME = "vlan"

    # 页面URL路径
    VLAN_URL = "/login#/networkConfiguration/vlanSettings"

    # 列名到HTML id的映射（用于排序）
    COLUMN_ID_MAP = {
        "VLAN 名称": "vlan_name",
        "VLAN ID": "vlan_id",
        "MAC地址": "mac",
        "IP地址": "ip_addr_int",
        "子网掩码": "netmask",
        "线路": "interface",
        "备注": "comment",
    }

    # ==================== 导航 ====================
    def navigate_to_vlan_settings(self):
        """导航到VLAN设置页面"""
        vlan_url = f"{self.base_url}/#/networkConfiguration/vlanSettings"
        self.page.goto(vlan_url)
        self.page.wait_for_load_state("networkidle")
        return self

    def navigate_to_vlan_direct(self):
        """直接导航到VLAN设置页面"""
        self.page.goto(f"{self.base_url}{self.VLAN_URL}")
        self.page.wait_for_load_state("networkidle")
        return self

    # ==================== 表单字段填写 ====================
    def fill_vlan_id(self, vlan_id: str):
        """填写VLAN ID"""
        self.page.get_by_role("textbox", name="vlanID *").fill(str(vlan_id))
        return self

    def fill_vlan_name(self, name: str):
        """填写VLAN名称"""
        self.page.get_by_role("textbox", name="vlan名称 *").fill(name)
        return self

    def fill_mac(self, mac: str):
        """填写MAC地址"""
        self.page.get_by_role("textbox", name="MAC").fill(mac)
        return self

    def fill_ip(self, ip: str):
        """填写IP地址"""
        self.page.get_by_role("textbox", name="IP").fill(ip)
        return self

    def select_subnet_mask(self, mask: str):
        """选择子网掩码"""
        self.page.get_by_role("combobox", name="子网掩码").click(force=True)
        self.page.wait_for_timeout(300)
        self.page.get_by_title(mask, exact=True).nth(1).click()
        return self

    def select_line(self, line: str):
        """选择线路"""
        self.page.get_by_role("combobox", name="线路").click(force=True)
        self.page.wait_for_timeout(300)
        self.page.get_by_title(line, exact=True).nth(1).click(force=True)
        return self

    # ==================== 添加VLAN ====================
    def add_vlan(self, vlan_id: str, vlan_name: str,
                 mac: Optional[str] = None,
                 ip: Optional[str] = None,
                 subnet_mask: Optional[str] = None,
                 line: Optional[str] = "lan1",
                 remark: Optional[str] = None) -> bool:
        """添加VLAN的完整流程"""
        self.click_add_button()
        self.fill_vlan_id(vlan_id)
        self.fill_vlan_name(vlan_name)

        if mac:
            self.fill_mac(mac)
        if ip:
            self.fill_ip(ip)
        if subnet_mask:
            self.select_subnet_mask(subnet_mask)
        if line:
            self.select_line(line)
        if remark:
            self.fill_remark(remark)

        self.click_save()

        success = self.wait_for_success_message()

        if success:
            self.page.wait_for_timeout(2000)
            self.page.reload()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)

        return success

    # ==================== 异常输入测试 ====================
    def try_add_vlan_invalid(self, vlan_id: str, vlan_name: str,
                              mac: str = None,
                              ip: str = None,
                              subnet_mask: str = None,
                              line: str = "lan1",
                              remark: str = None) -> dict:
        """尝试添加不合规的VLAN（用于异常测试）"""
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

            # 检查表单验证错误
            error_locator = self.page.locator(".ant-form-item-explain-error, .ant-input-status-error, .ant-select-status-error")
            if error_locator.count() > 0:
                result["has_validation_error"] = True
                error_texts = self.page.locator(".ant-form-item-explain-error").all_text_contents()
                if error_texts:
                    error_msgs = [t.strip() for t in error_texts if t.strip()]
                    if error_msgs:
                        result["error_msg"] = "; ".join(error_msgs)
                    else:
                        result["error_msg"] = "表单验证失败"
                else:
                    result["error_msg"] = "表单验证失败"

            # 检查错误提示消息
            if not result["error_msg"]:
                error_msg = self.page.locator(".ant-message-error, .ant-notification-error")
                if error_msg.count() > 0:
                    result["error_msg"] = error_msg.first.text_content() or "操作失败"
                    result["has_validation_error"] = True

            # 检查对话框是否还在
            dialog = self.page.locator("dialog, [role='dialog']")
            if dialog.count() > 0 and dialog.is_visible():
                result["success"] = False
                if not result["error_msg"]:
                    dialog_error = dialog.locator(".ant-form-item-explain-error, .ant-alert-error")
                    if dialog_error.count() > 0:
                        result["error_msg"] = dialog_error.first.text_content() or result["error_msg"]
                        result["has_validation_error"] = True
            else:
                result["success"] = True

        except Exception as e:
            result["error_msg"] = str(e)[:100]
            result["success"] = False

        finally:
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click()
                    self.page.wait_for_timeout(200)
            except:
                pass
            self.page.reload()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)

        return result

    def try_add_invalid_extended_ip(self, vlan_name: str, invalid_ip: str) -> dict:
        """尝试添加不合规的扩展IP（用于异常测试）"""
        result = {"success": False, "error_msg": "", "has_validation_error": False}

        try:
            self.edit_vlan(vlan_name)
            self.page.wait_for_timeout(500)

            add_ext_btn = self.page.get_by_role("button", name="添加").last
            if add_ext_btn.count() > 0:
                add_ext_btn.click()
                self.page.wait_for_timeout(500)

                ext_ip_input = self.page.get_by_role("textbox", name="请输入IP地址")
                if ext_ip_input.count() > 0:
                    ext_ip_input.fill(invalid_ip)

                    self.click_save()
                    self.page.wait_for_timeout(800)

                    # 检查扩展IP验证错误
                    error_text_locator = self.page.locator("text=请输入正确的IP")
                    if error_text_locator.count() > 0:
                        result["has_validation_error"] = True
                        result["error_msg"] = "请输入正确的IP"

                    if not result["has_validation_error"]:
                        error_locator = self.page.locator(".ant-form-item-explain-error")
                        if error_locator.count() > 0:
                            result["has_validation_error"] = True
                            error_text = error_locator.first.text_content() or ""
                            result["error_msg"] = error_text.strip()

                    if not result["has_validation_error"]:
                        error_input = self.page.locator(".ant-input-status-error, .ant-form-item-has-error")
                        if error_input.count() > 0:
                            result["has_validation_error"] = True
                            result["error_msg"] = "输入格式错误"

                    error_msg = self.page.locator(".ant-message-error, .ant-notification-error")
                    if error_msg.count() > 0:
                        msg_text = error_msg.first.text_content() or ""
                        if "输入有误" in msg_text:
                            result["has_validation_error"] = True
                            if not result["error_msg"]:
                                result["error_msg"] = msg_text

                    dialog_still_open = self.page.locator("dialog, [role='dialog']").count() > 0
                    if dialog_still_open:
                        result["success"] = False
                        if not result["has_validation_error"]:
                            result["has_validation_error"] = True
                            result["error_msg"] = "保存被阻止"
                    else:
                        result["success"] = True
                else:
                    result["error_msg"] = "未找到扩展IP输入框"
            else:
                result["error_msg"] = "未找到扩展IP添加按钮"

        except Exception as e:
            result["error_msg"] = str(e)[:100]

        finally:
            try:
                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click()
                    self.page.wait_for_timeout(500)
                    confirm_btn = self.page.get_by_role("button", name="确定")
                    if confirm_btn.count() > 0 and confirm_btn.is_visible():
                        confirm_btn.click()
                        self.page.wait_for_timeout(300)
            except:
                pass
            try:
                self.page.goto(f"{self.base_url}/#/networkConfiguration/vlanSettings")
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(500)
            except:
                pass
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)

        return result

    # ==================== VLAN特有操作 ====================
    def cancel_delete(self, vlan_name: str):
        """取消删除操作"""
        row = self.page.locator("tr").filter(has_text=vlan_name)
        row.get_by_role("button", name="删除").click()
        self.page.get_by_role("button", name="取消").click()
        return self

    # ==================== 批量操作便捷方法 ====================
    def batch_enable_vlans(self, vlan_names: List[str]) -> bool:
        """批量启用指定名称的VLAN"""
        for name in vlan_names:
            self.select_rule(name)
        self.batch_enable()
        return self.wait_for_success_message()

    def batch_disable_vlans(self, vlan_names: List[str]) -> bool:
        """批量停用指定名称的VLAN"""
        for name in vlan_names:
            self.select_rule(name)
        self.batch_disable()
        return self.wait_for_success_message()

    def batch_delete_vlans(self, vlan_names: List[str]) -> bool:
        """批量删除指定名称的VLAN"""
        for name in vlan_names:
            self.select_rule(name)
        self.batch_delete()
        return self.wait_for_success_message()

    # ==================== 扩展IP操作 ====================
    def add_extended_ip(self, ip: str, subnet_mask: str = "255.255.255.0"):
        """添加扩展IP（在添加/编辑VLAN页面）"""
        add_ext_btn = self.page.get_by_role("button", name="添加").last
        if add_ext_btn.count() > 0:
            add_ext_btn.click()
            self.page.wait_for_timeout(500)

        ext_ip_input = self.page.get_by_role("textbox", name="请输入IP地址")
        if ext_ip_input.count() > 0:
            ext_ip_input.fill(ip)

        return self

    def remove_extended_ip(self, index: int):
        """删除指定索引的扩展IP"""
        delete_buttons = self.page.locator(".extended-ip-item button, [class*='delete']")
        if index < delete_buttons.count():
            delete_buttons.nth(index).click()
        return self

    # ==================== 状态验证 ====================
    def get_selected_count(self) -> int:
        """获取当前选中的VLAN数量"""
        try:
            selected_text = self.page.locator("text=/已选 \\d+ 条/")
            if selected_text.count() > 0:
                text = selected_text.first.inner_text()
                return int(text.replace("已选 ", "").replace(" 条", ""))
        except Exception:
            pass
        return 0

    def get_vlan_list(self) -> List[str]:
        """获取所有VLAN名称列表"""
        vlan_names = []
        rows = self.page.locator("tbody tr")
        for i in range(rows.count()):
            try:
                name_cell = rows.nth(i).locator("td").nth(1)
                vlan_names.append(name_cell.inner_text())
            except Exception:
                continue
        return vlan_names

    # ==================== 错误信息获取 ====================
    def get_error_message(self) -> Optional[str]:
        """获取当前显示的错误信息"""
        try:
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
        """检查是否有表单验证错误"""
        return self.page.locator(".ant-form-item-explain-error, [class*='error']").count() > 0

    def upload_import_file(self, file_path: str):
        """上传导入文件"""
        self.click_import()
        with self.page.expect_file_chooser() as fc_info:
            self.page.click("input[type='file']")
        file_chooser = fc_info.value
        file_chooser.set_files(file_path)
        return self

    # ==================== VLAN特有：sort_by_column覆盖 ====================
    def sort_by_column(self, column_name: str) -> bool:
        """点击列头排序

        关键发现（通过Playwright录制确认）：
        1. 排序图标默认不可见，需要先hover到th元素才能显示
        2. 点击目标是.sortIcon里面的svg图标，而不是th本身
        3. 每个可排序的列头都有特定的id属性
        4. 选择器：th#id .sortIcon .anticon svg
        """
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)

            col_id = self.COLUMN_ID_MAP.get(column_name)
            if not col_id:
                print(f"[DEBUG] 未知的列名: {column_name}")
                return False

            # 步骤1：hover到th元素，让排序图标显示
            th = self.page.locator(f"th#{col_id}")
            if th.count() == 0:
                print(f"[DEBUG] 未找到列头 th#{col_id}")
                return False

            th.hover()
            self.page.wait_for_timeout(300)

            # 步骤2：点击排序图标（使用force=True因为图标可能仍被判定为不可见）
            sort_icon = th.locator(".sortIcon .anticon svg")
            if sort_icon.count() > 0:
                sort_icon.first.click(force=True)
                self.page.wait_for_timeout(500)
                return True
            else:
                print(f"[DEBUG] 未找到 '{column_name}' 的排序图标")
                return False

        except Exception as e:
            print(f"[DEBUG] sort_by_column error: {e}")
        return False

    # ==================== 向后兼容别名 ====================
    # 测试代码中使用的VLAN特定方法名，映射到基类的通用方法名
    def disable_vlan(self, vlan_name: str) -> bool:
        return self.disable_rule(vlan_name)

    def enable_vlan(self, vlan_name: str) -> bool:
        return self.enable_rule(vlan_name)

    def edit_vlan(self, vlan_name: str):
        return self.edit_rule(vlan_name)

    def delete_vlan(self, vlan_name: str) -> bool:
        return self.delete_rule(vlan_name)

    def select_vlan(self, vlan_name: str):
        return self.select_rule(vlan_name)

    def select_all_vlans(self):
        return self.select_all_rules()

    def search_vlan(self, keyword: str):
        return self.search_rule(keyword)

    def export_vlans(self, use_config_path: bool = True, export_format: str = "csv") -> bool:
        return self.export_rules(use_config_path, export_format)

    def import_vlans(self, file_path: str, clear_existing: bool = False) -> bool:
        return self.import_rules(file_path, clear_existing)

    def is_vlan_enabled(self, vlan_name: str) -> bool:
        return self.is_rule_enabled(vlan_name)

    def is_vlan_disabled(self, vlan_name: str) -> bool:
        return self.is_rule_disabled(vlan_name)

    def vlan_exists(self, vlan_name: str) -> bool:
        return self.rule_exists(vlan_name)

    def get_vlan_count(self) -> int:
        return self.get_rule_count()
