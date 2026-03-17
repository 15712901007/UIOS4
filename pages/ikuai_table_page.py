"""
爱快路由器表格页面基类

所有带有表格CRUD操作的页面的中间基类，提供通用的：
- 行内按钮操作（编辑/停用/启用/删除）
- 批量操作（全选/批量启用/批量停用/批量删除）
- 搜索/排序
- 导入/导出
- 状态验证（规则启用/停用/存在性/计数）
- 模态框处理

继承层次：
  BasePage (Playwright primitives + help)
    └── IkuaiTablePage (table CRUD operations)  ← 本类
          ├── VlanPage
          ├── IpRateLimitPage
          ├── MacRateLimitPage
          └── StaticRoutePage
"""
from playwright.sync_api import Page
from pages.base_page import BasePage
from typing import Optional
import re


class IkuaiTablePage(BasePage):
    """爱快路由器表格页面基类，封装所有模块通用的表格操作"""

    # 子类必须设置，用于导出文件命名和配置路径
    MODULE_NAME = ""

    def __init__(self, page: Page, base_url: str):
        super().__init__(page)
        self.base_url = base_url

    # ==================== 按钮操作 ====================

    def click_add_button(self):
        """点击添加按钮"""
        self.page.get_by_role("button", name="添加").first.click()
        self.page.wait_for_timeout(500)
        return self

    def click_save(self):
        """点击保存按钮"""
        self.page.get_by_role("button", name="保存").click()
        return self

    def click_cancel(self):
        """点击取消按钮，处理可能出现的确认离开弹窗"""
        self.page.get_by_role("button", name="取消").click()
        self.page.wait_for_timeout(500)

        # 处理可能出现的"确认离开"弹窗
        try:
            confirm_btn = self.page.locator(
                ".ant-modal-confirm .ant-btn-primary, "
                ".ant-modal-confirm button:has-text('确定')"
            )
            if confirm_btn.count() > 0 and confirm_btn.first.is_visible():
                confirm_btn.first.click()
                self.page.wait_for_timeout(300)
        except Exception:
            pass

        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)
        return self

    def click_import(self):
        """点击导入按钮"""
        self.page.get_by_role("button", name="导入").click()
        return self

    def click_export(self):
        """点击导出按钮"""
        self.page.get_by_role("button", name="导出").click()
        return self

    # ==================== 行内按钮操作 ====================

    def _click_rule_button(self, rule_name: str, button_name: str) -> bool:
        """
        点击规则行中的指定按钮（通过JS遍历DOM树找到同行按钮）

        Args:
            rule_name: 规则名称
            button_name: 按钮名称（编辑/复制/停用/启用/删除）

        Returns:
            是否成功点击
        """
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(300)

        try:
            rule_text = self.page.get_by_text(rule_name, exact=False).first
            rule_text.wait_for(timeout=5000)

            js_code = f"""(el) => {{
                let parent = el.parentElement;
                let depth = 0;
                while (parent && depth < 20) {{
                    const buttons = parent.querySelectorAll('button');
                    for (const btn of buttons) {{
                        if (btn.textContent.includes('{button_name}')) {{
                            btn.click();
                            return true;
                        }}
                    }}
                    parent = parent.parentElement;
                    depth++;
                }}
                return false;
            }}"""

            result = rule_text.evaluate(js_code)
            if result:
                return True

            print(f"[DEBUG] _click_rule_button: 在规则 {rule_name} 行中未找到按钮 {button_name}")
            return False

        except Exception as e:
            print(f"[DEBUG] _click_rule_button 异常: {e}")
            return False

    def disable_rule(self, rule_name: str) -> bool:
        """停用指定规则（有确认弹窗）"""
        self._click_rule_button(rule_name, "停用")
        self.page.wait_for_timeout(500)

        try:
            confirm_btn = self.page.locator(
                "dialog button:has-text('确定'), [role='dialog'] button:has-text('确定')"
            )
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
        """启用指定规则（无确认弹窗）"""
        self._click_rule_button(rule_name, "启用")

        try:
            self.page.wait_for_selector("text=启用成功", timeout=5000)
            return True
        except Exception:
            return self.wait_for_success_message()

    def edit_rule(self, rule_name: str):
        """点击编辑按钮，进入编辑页面"""
        self._click_rule_button(rule_name, "编辑")
        self.page.wait_for_timeout(500)
        return self

    def delete_rule(self, rule_name: str) -> bool:
        """删除指定规则（有确认弹窗）"""
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

    # ==================== 选择操作 ====================

    def select_rule(self, rule_name: str, timeout: int = 10000):
        """
        勾选指定规则的复选框

        Args:
            rule_name: 规则名称
            timeout: 超时时间（毫秒）
        """
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)

            rule_text = self.page.get_by_text(rule_name, exact=False).first
            rule_text.wait_for(timeout=timeout)

            rule_text.evaluate("""(el) => {
                let parent = el.parentElement;
                let depth = 0;
                while (parent && depth < 10) {
                    const checkbox = parent.querySelector('input[type="checkbox"]');
                    if (checkbox) {
                        if (!checkbox.checked) {
                            checkbox.click();
                        }
                        return true;
                    }
                    parent = parent.parentElement;
                    depth++;
                }
                return false;
            }""")
            self.page.wait_for_timeout(200)

        except Exception as e:
            print(f"[WARN] select_rule '{rule_name}' 失败: {str(e)[:80]}")

        return self

    def select_all_rules(self):
        """全选规则"""
        try:
            select_all = self.page.get_by_role("checkbox", name="Select all")
            if select_all.count() > 0:
                if not select_all.is_checked():
                    select_all.click()
                    self.page.wait_for_timeout(300)
                return True
        except Exception as e:
            print(f"[DEBUG] select_all_rules 异常: {e}")
        return False

    # ==================== 批量操作 ====================

    def _click_batch_button(self, button_name: str):
        """
        点击左下角的批量操作按钮（区别于行内同名按钮）

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

        # 方法1: 使用带图标的完整按钮名称定位
        try:
            full_button_name = f"{icon_name} {button_name}" if icon_name else button_name
            btn = self.page.get_by_role("button", name=full_button_name)
            if btn.count() > 0:
                btn.first.click()
                self.page.wait_for_timeout(300)
                return
        except Exception:
            pass

        # 方法2: 找所有同名按钮，点击不在表格行中的那个
        try:
            all_buttons = self.page.get_by_role("button", name=button_name)
            for i in range(all_buttons.count()):
                btn = all_buttons.nth(i)
                parent_row = btn.locator("xpath=ancestor::tr[1]")
                if parent_row.count() == 0:
                    btn.click()
                    self.page.wait_for_timeout(300)
                    return
        except Exception:
            pass

        print(f"[DEBUG] _click_batch_button: 未找到批量按钮 {button_name}")

    def batch_enable(self):
        """批量启用选中的规则"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_batch_button("启用")
        return self

    def batch_disable(self):
        """批量停用选中的规则（有确认弹窗）"""
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
            print(f"[DEBUG] batch_disable 确认弹窗点击失败: {e}")
        return self

    def batch_delete(self):
        """批量删除选中的规则（有确认弹窗）"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_batch_button("删除")
        self.page.wait_for_timeout(500)

        try:
            modal_confirm = self.page.locator(
                ".ant-modal-confirm .ant-btn-primary, .ant-modal-wrap .ant-btn-primary"
            )
            if modal_confirm.count() > 0:
                modal_confirm.first.click()
            else:
                self.page.get_by_role("button", name="确定").click()
        except Exception as e:
            print(f"[DEBUG] batch_delete 确认弹窗点击失败: {e}")
        return self

    # ==================== 搜索 ====================

    def search_rule(self, keyword: str):
        """搜索规则"""
        search_input = self.page.get_by_placeholder("请输入搜索内容")
        search_input.click()
        search_input.clear()
        search_input.fill(keyword)
        search_input.press("Enter")
        self.page.wait_for_timeout(500)
        return self

    def clear_search(self):
        """清除搜索"""
        search_input = self.page.get_by_placeholder("请输入搜索内容")
        search_input.click()
        search_input.clear()
        search_input.press("Enter")
        self.page.wait_for_timeout(500)
        return self

    # ==================== 排序 ====================

    # 子类可覆盖此映射，提供列名到HTML id的映射
    # 示例: {"协议栈": "ip_type", "线路": "interface"}
    COLUMN_ID_MAP = {}

    def sort_by_column(self, column_name: str) -> bool:
        """
        点击列头排序

        关键发现（通过Playwright录制确认）：
        1. Ant Design Table排序图标默认不可见，需要先hover到th元素才能显示
        2. 点击目标是.sortIcon里面的svg图标，而不是th本身
        3. 子类可通过COLUMN_ID_MAP提供列名到HTML id的精确映射
        4. 选择器：th#id .sortIcon .anticon svg

        Args:
            column_name: 列名

        Returns:
            是否成功
        """
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)

            th = None

            # 优先使用COLUMN_ID_MAP精确选择
            if hasattr(self, 'COLUMN_ID_MAP') and column_name in self.COLUMN_ID_MAP:
                col_id = self.COLUMN_ID_MAP[column_name]
                th = self.page.locator(f"th#{col_id}")
                if th.count() == 0:
                    print(f"[DEBUG] 未找到列头 th#{col_id}")
                    th = None

            # 备用：通过列名文本查找
            if th is None:
                # 尝试通过columnheader role
                header = self.page.get_by_role("columnheader", name=column_name)
                if header.count() > 0:
                    th = header.first
                else:
                    # 最后尝试通过th + filter
                    th_locator = self.page.locator("th").filter(has_text=column_name)
                    if th_locator.count() > 0:
                        th = th_locator.first
                    else:
                        print(f"[DEBUG] 未找到列头: {column_name}")
                        return False

            # 步骤1：hover到th元素，让排序图标显示
            th.hover()
            self.page.wait_for_timeout(300)  # 等待图标显示动画

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

    # ==================== 导出 ====================

    def export_rules(self, use_config_path: bool = True, export_format: str = "csv") -> bool:
        """
        导出规则配置

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

            # 选择导出格式
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
                    base_path = config.test_data.get_export_path(self.MODULE_NAME, config.get_project_root())
                    save_path = os.path.splitext(base_path)[0] + f".{export_format.lower()}"
                else:
                    download_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "downloads")
                    os.makedirs(download_dir, exist_ok=True)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    save_path = os.path.join(
                        download_dir, f"{self.MODULE_NAME}_export_{timestamp}{original_ext}"
                    )

                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                download.save_as(save_path)
                print(f"[OK] 导出成功: {save_path}")
                return True

        except Exception as e:
            print(f"导出失败: {e}")
            self.close_modal_if_exists()
            return False

    # ==================== 导入 ====================

    def import_rules(self, file_path: str, clear_existing: bool = False) -> bool:
        """
        导入规则配置

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
                upload_btn = self.page.locator(
                    "dialog button:has-text('点击上传'), "
                    "[role='dialog'] button:has-text('点击上传')"
                ).first
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
        """检查规则是否启用（行内有"停用"按钮表示已启用）"""
        self.page.wait_for_timeout(500)
        self.page.wait_for_load_state("networkidle")

        try:
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

        except Exception:
            return False

    def is_rule_disabled(self, rule_name: str) -> bool:
        """检查规则是否停用（行内有"启用"按钮表示已停用）"""
        self.page.wait_for_timeout(500)
        self.page.wait_for_load_state("networkidle")

        try:
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

        except Exception:
            return False

    def rule_exists(self, rule_name: str) -> bool:
        """检查规则是否存在"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
            return self.page.get_by_text(rule_name, exact=False).count() > 0
        except Exception:
            return False

    def get_rule_count(self) -> int:
        """获取当前规则数量（从"共 N 条"文本解析）"""
        try:
            count_text = self.page.locator("text=/共 \\d+ 条/").first
            if count_text.count() > 0:
                text = count_text.text_content()
                match = re.search(r"共\s*(\d+)\s*条", text)
                if match:
                    return int(match.group(1))
        except Exception:
            pass
        return 0

    # ==================== 模态框处理 ====================

    def close_modal_if_exists(self):
        """关闭可能存在的模态框"""
        try:
            modal_wrap = self.page.locator(".ant-modal-wrap")
            if modal_wrap.count() > 0 and modal_wrap.is_visible():
                # 先尝试ESC
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)

                if modal_wrap.count() == 0 or not modal_wrap.is_visible():
                    return True

                # 尝试关闭图标
                close_icon = self.page.locator(".ant-modal-close")
                if close_icon.count() > 0 and close_icon.is_visible():
                    close_icon.click(timeout=3000)
                    self.page.wait_for_timeout(300)
                    return True

                # 尝试取消按钮
                cancel_btn = self.page.get_by_role("button", name="取消")
                if cancel_btn.count() > 0 and cancel_btn.is_visible():
                    cancel_btn.click(timeout=3000)
                    self.page.wait_for_timeout(300)
                    return True
        except Exception as e:
            try:
                print(f"[DEBUG] close_modal_if_exists: {str(e)[:100]}")
            except Exception:
                pass
        return False

    def _handle_confirm_dialog(self):
        """处理确认对话框（如"当前内容未保存"）"""
        try:
            self.page.wait_for_timeout(300)
            confirm_modal = self.page.locator(".ant-modal-confirm-centered")
            if confirm_modal.count() > 0 and confirm_modal.is_visible():
                confirm_btn = confirm_modal.get_by_role("button", name="确定")
                if confirm_btn.count() > 0:
                    confirm_btn.click()
                    self.page.wait_for_timeout(300)
        except Exception:
            pass

    # ==================== 简化的成功消息等待 ====================

    def wait_for_success_message(self, timeout: int = 5000) -> bool:
        """等待操作成功提示（简化版，检查ant-message-success）"""
        try:
            self.page.wait_for_selector(".ant-message-success", timeout=timeout)
            return True
        except Exception:
            return False

    def fill_remark(self, remark: str):
        """填写备注"""
        self.page.get_by_role("textbox", name="备注").fill(remark)
        return self
