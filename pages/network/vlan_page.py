"""
VLAN设置页面类

处理VLAN配置的增删改查、启用停用、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作
"""
import re
import time

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

    def _find_vlan_row(self, vlan_name: str) -> Optional[Locator]:
        """按 VLAN 名称列的完整文本定位数据行，避免前缀名称互相命中。"""
        rows = self.page.locator("div.ant-table-tbody div.ant-table-row")
        for index in range(rows.count()):
            row = rows.nth(index)
            name_cell = row.locator("div.ant-table-cell#vlan_name")
            if name_cell.count() and (name_cell.first.inner_text() or "").strip() == vlan_name:
                return row
        return None

    @staticmethod
    def _row_has_button(row: Locator, button_name: str) -> bool:
        buttons = row.locator("button")
        for index in range(buttons.count()):
            if (buttons.nth(index).inner_text() or "").strip() == button_name:
                return True
        return False

    def _click_rule_button(self, rule_name: str, button_name: str) -> bool:
        """只点击 VLAN 精确名称所在行的操作按钮。"""
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(300)
        try:
            deadline = time.monotonic() + 5
            row = None
            while time.monotonic() < deadline:
                row = self._find_vlan_row(rule_name)
                if row is not None:
                    break
                self.page.wait_for_timeout(200)
            if row is None:
                print(f"[DEBUG] VLAN精确行不存在: {rule_name}")
                return False
            buttons = row.locator("button")
            for index in range(buttons.count()):
                button = buttons.nth(index)
                if (button.inner_text() or "").strip() == button_name:
                    button.click()
                    return True
            print(f"[DEBUG] VLAN {rule_name} 行中未找到按钮 {button_name}")
            return False
        except Exception as exc:
            print(f"[DEBUG] VLAN精确行按钮点击失败: {str(exc)[:100]}")
            return False

    def rule_exists(self, rule_name: str) -> bool:
        """检查 VLAN 精确名称的数据行是否存在。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            return self._find_vlan_row(rule_name) is not None
        except Exception:
            return False

    def is_rule_enabled(self, rule_name: str) -> bool:
        """精确检查目标 VLAN 行是否提供“停用”操作。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            row = self._find_vlan_row(rule_name)
            return row is not None and self._row_has_button(row, "停用")
        except Exception:
            return False

    def is_rule_disabled(self, rule_name: str) -> bool:
        """精确检查目标 VLAN 行是否提供“启用”操作。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            row = self._find_vlan_row(rule_name)
            return row is not None and self._row_has_button(row, "启用")
        except Exception:
            return False

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

    def _ensure_vlan_list(self) -> None:
        """单一导航回 VLAN 列表，并确认列表操作栏已实际渲染。"""
        self.page.goto(f"{self.base_url}/#/networkConfiguration/vlanSettings")
        try:
            self.page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
        self.page.get_by_role("button", name="添加").first.wait_for(
            state="visible", timeout=8000
        )

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
        """填写IP地址(用id定位, 避免get_by_role匹配到多个含IP的textbox)"""
        ip_input = self.page.locator('#ip_addr')
        if ip_input.count() > 0:
            ip_input.first.fill(ip)
        else:
            # 回退: 用role但加.first避免歧义
            self.page.get_by_role("textbox", name="IP").first.fill(ip)
        return self

    def select_subnet_mask(self, mask: str):
        """选择子网掩码"""
        self._select_combobox_value_by_id("netmask", mask)
        return self

    def _select_combobox_value_by_id(self, input_id: str, value: str) -> None:
        """在指定 Ant Select 上选择值，并复读实际选择结果。"""
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

    def select_line(self, line: str):
        """选择线路(lan1/wan1等物理口, 或已建VLAN名用于QINQ内层).

        QINQ内层选VLAN名时下拉选项动态生成, 需真实click触发React打开下拉
        (force=True不触发→下拉不开→选不到VLAN名→VLAN55建错成lan1非QINQ).
        先Escape关残留下拉(子网掩码等), 真实click打开, 等下拉容器visible, 重试3次."""
        # 关闭可能残留的下拉(子网掩码/前次操作)
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass
        combobox = self.page.get_by_role("combobox", name="线路")
        for attempt in range(3):
            # 真实click触发React打开下拉(force=True不触发→下拉不开)
            try:
                combobox.click(timeout=3000)
            except Exception:
                combobox.click(force=True, timeout=3000)
            self.page.wait_for_timeout(600)
            # 等下拉容器渲染
            try:
                self.page.locator(".ant-select-dropdown:visible").first.wait_for(state="visible", timeout=3000)
            except Exception:
                pass
            for loc in (
                self.page.locator(f".ant-select-item-option[title='{line}']:visible"),
                self.page.get_by_role("option", name=line, exact=True),
                self.page.get_by_title(line, exact=True),
            ):
                try:
                    cnt = loc.count()
                    if cnt > 0:
                        loc.nth(cnt - 1).click(timeout=5000)
                        return self
                except Exception:
                    continue
        print(f"[DEBUG] select_line: 未能选中线路'{line}', 跳过(已重试3次)")
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
            self._ensure_vlan_list()
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

            # VLAN 添加是路由页面而不是 dialog。保存后表单仍在，或已出现明确校验错误，
            # 都不能报告 success=True。
            form_still_open = self.page.locator("#vlan_id").count() > 0
            result["success"] = not result["has_validation_error"] and not form_still_open

        except Exception as e:
            result["error_msg"] = str(e)[:100]
            result["success"] = False

        finally:
            # 必须显式回列表；刷新当前 /add 路由会让下一用例把扩展IP“添加”误当主添加按钮。
            self._ensure_vlan_list()

        return result

    def try_add_invalid_extended_ip(self, vlan_name: str, invalid_ip: str) -> dict:
        """尝试添加不合规的扩展IP（用于异常测试）"""
        result = {"success": False, "error_msg": "", "has_validation_error": False}

        try:
            self._ensure_vlan_list()
            if not self.edit_vlan(vlan_name):
                result["error_msg"] = f"未找到VLAN精确编辑行: {vlan_name}"
            else:
                inputs = self.page.locator("input[id^='ip_mask_'][id$='_ipAddress']")
                count_before = inputs.count()
                add_ext_btn = self.page.get_by_role("button", name="添加", exact=True)
                if add_ext_btn.count() != 1:
                    result["error_msg"] = f"扩展IP添加按钮数量不为1: {add_ext_btn.count()}"
                    return result
                add_ext_btn.click()
                self.page.wait_for_timeout(500)

                if inputs.count() == count_before + 1:
                    ext_ip_input = inputs.last
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

                    form_still_open = self.page.locator("#vlan_id").count() > 0
                    result["success"] = (
                        not result["has_validation_error"] and not form_still_open
                    )
                else:
                    result["error_msg"] = (
                        f"点击扩展IP添加后输入框数量未增加: "
                        f"{count_before} -> {inputs.count()}"
                    )

        except Exception as e:
            result["error_msg"] = str(e)[:100]

        finally:
            try:
                self._ensure_vlan_list()
            except Exception:
                pass

        return result

    # ==================== VLAN特有操作 ====================
    def cancel_delete(self, vlan_name: str):
        """取消删除操作(用基类_click_rule_button点删除处理图标按钮; 再点可见取消)"""
        self._click_rule_button(vlan_name, "删除")
        self.page.wait_for_timeout(500)
        # 点可见取消按钮(规避.ant-modal-confirm隐藏根的strict violation)
        cancel_btn = self.page.get_by_role("button", name="取消").locator("visible=true")
        if cancel_btn.count() > 0:
            cancel_btn.first.click(timeout=3000)
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
        inputs = self.page.locator("input[id^='ip_mask_'][id$='_ipAddress']")
        count_before = inputs.count()
        add_ext_btn = self.page.get_by_role("button", name="添加", exact=True)
        if add_ext_btn.count() != 1:
            raise AssertionError(f"扩展IP添加按钮数量不为1: {add_ext_btn.count()}")
        add_ext_btn.click()

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and inputs.count() != count_before + 1:
            self.page.wait_for_timeout(200)
        if inputs.count() != count_before + 1:
            raise AssertionError(
                f"点击扩展IP添加后输入框数量未增加: {count_before} -> {inputs.count()}"
            )

        ext_ip_input = inputs.last
        ext_ip_input.fill(ip)
        input_id = ext_ip_input.get_attribute("id") or ""
        mask_id = input_id.replace("_ipAddress", "_netmask")
        if not mask_id or mask_id == input_id:
            raise AssertionError(f"无法从扩展IP输入框推导掩码ID: {input_id}")
        self._select_combobox_value_by_id(mask_id, subnet_mask)

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
            selected_text = self.page.locator("text=/已选\\s*\\d+\\s*条/")
            if selected_text.count() > 0:
                text = selected_text.first.inner_text()
                match = re.search(r"已选\s*(\d+)\s*条", text)
                if match:
                    return int(match.group(1))
        except Exception:
            pass
        return 0

    def get_column_values(self, column_name: str) -> List[str]:
        """读取当前表格顺序下某一列的可见值，用于验证排序结果而非只验证点击。"""
        column_id = self.COLUMN_ID_MAP.get(column_name)
        if not column_id:
            raise ValueError(f"未知VLAN列: {column_name}")
        values = []
        # 4.0页面使用Ant Design虚拟表格，数据行/单元格都是div，不存在tbody/tr/td。
        # 数据单元格沿用表头列id，可按虚拟行精确读取当前显示顺序。
        rows = self.page.locator("div.ant-table-tbody div.ant-table-row")
        if rows.count() == 0 and self.get_vlan_count() > 0:
            rows.first.wait_for(state="visible", timeout=5000)
        for index in range(rows.count()):
            cell = rows.nth(index).locator(f"div.ant-table-cell#{column_id}")
            if cell.count() == 0:
                continue
            values.append((cell.first.inner_text() or "").strip())
        return values

    def get_vlan_list(self) -> List[str]:
        """获取所有VLAN名称列表"""
        return self.get_column_values("VLAN 名称")

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

    def edit_vlan(self, vlan_name: str) -> bool:
        clicked = self._click_rule_button(vlan_name, "编辑")
        if clicked:
            self.page.wait_for_timeout(500)
        return clicked

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
