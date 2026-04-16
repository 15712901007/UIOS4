"""
多线负载页面类

处理分流策略 > 多线负载配置的增删改查、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作

数据库字段映射 (实测确认):
- mode: 整数 0-6, 对应 LOAD_MODES 列表索引
- isp_name: 英文标识, 如 "all", "chinatelecom", "chinaunicom"
- tagname: 规则名称
- interface: 逗号分隔的线路, 如 "wan1,wan2,wan3"
- weight: 逗号分隔的比例, 如 "3,2,1"
- comment: 备注
- enabled: "yes"/"no"
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, Dict, List


class MultiWanLbPage(IkuaiTablePage):
    """多线负载页面操作类"""

    MODULE_NAME = "multi_wan_lb"
    DIVERSION_STRATEGY_URL = "/login#/networkConfiguration/diversionStrategy"

    # 负载模式选项 (注意：mode值不连续，mode=5已被隐藏/废弃)
    LOAD_MODES = [
        "源IP+目的IP+目的端口",   # mode=0 (默认)
        "源IP+目的IP",            # mode=1
        "新建连接数",              # mode=2
        "实时流量",                # mode=3
        "实时连接数",              # mode=4
        "源IP",                   # mode=6 (注意：非5)
        "源IP+源端口",             # mode=7 (注意：非6)
    ]

    # UI中文名 → 数据库isp_name值
    CARRIER_TO_DB = {
        "全部": "all",
        "中国电信": "chinatelecom",
        "中国联通": "chinaunicom",
        "中国移动": "chinamobile",
        "中国教育": "chinaeducation",
    }

    # UI负载模式 → 数据库mode值 (mode=5已废弃)
    MODE_TO_DB = {
        "源IP+目的IP+目的端口": "0",
        "源IP+目的IP": "1",
        "新建连接数": "2",
        "实时流量": "3",
        "实时连接数": "4",
        "源IP": "6",
        "源IP+源端口": "7",
    }

    # 运营商选项 (UI显示名)
    CARRIERS = list(CARRIER_TO_DB.keys())

    # 排序列映射 (与实际th#id一致)
    COLUMN_ID_MAP = {
        "名称": "tagname",
        "线路": "interface",
        "负载模式": "mode",
        "运营商": "isp_name",
        "负载比例": "weight",
        "备注": "comment",
    }

    # ==================== 导航 ====================
    def navigate_to_multi_wan_lb(self):
        """导航到分流策略 > 多线负载页面"""
        url = f"{self.base_url}{self.DIVERSION_STRATEGY_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_multi_wan_lb()
        self.page.wait_for_timeout(500)
        return self

    # ==================== 通用下拉框操作 ====================
    def _close_any_dropdown(self):
        """关闭所有可能打开的下拉框"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _select_option_via_js(self, weight_or_text: str) -> bool:
        """通过JS在当前可见的下拉框中选择指定选项（解决多下拉框干扰问题）

        Ant Design下拉框使用Portal渲染，可能同时存在多个隐藏的下拉框DOM。
        此方法只操作可见的那个，避免匹配到旧的下拉框。
        """
        try:
            clicked = self.page.evaluate("""(text) => {
                const dropdowns = document.querySelectorAll('.ant-select-dropdown');
                for (let i = dropdowns.length - 1; i >= 0; i--) {
                    const dd = dropdowns[i];
                    if (dd.offsetHeight > 0 && dd.offsetWidth > 0) {
                        const items = dd.querySelectorAll('.ant-select-item');
                        for (const item of items) {
                            if (item.textContent.trim() === text) {
                                item.click();
                                return true;
                            }
                        }
                    }
                }
                return false;
            }""", weight_or_text)
            return bool(clicked)
        except Exception:
            return False

    # ==================== 表单字段填写 ====================
    def fill_name(self, name: str):
        """填写规则名称"""
        name_input = self.page.get_by_placeholder("请输入名称")
        if name_input.count() > 0:
            name_input.click()
            name_input.fill(name)
            self.page.wait_for_timeout(200)
        return self

    def select_load_mode(self, mode: str = "源IP+目的IP+目的端口"):
        """选择负载模式"""
        try:
            self._close_any_dropdown()

            load_mode_label = self.page.locator('text=负载模式').first
            if load_mode_label.count() > 0:
                form_item = load_mode_label.locator('xpath=ancestor::div[contains(@class, "ant-form-item")]')
                if form_item.count() > 0:
                    # 检查当前值
                    current_value = form_item.locator('.ant-select-selection-item')
                    if current_value.count() > 0:
                        current_text = current_value.first.get_attribute("title") or current_value.first.text_content().strip()
                        if current_text == mode:
                            return self

                    # 点击下拉框
                    selector = form_item.locator('.ant-select-selector')
                    if selector.count() > 0:
                        selector.first.click()
                        self.page.wait_for_timeout(800)

                        # 通过JS选择可见下拉框中的选项
                        if self._select_option_via_js(mode):
                            self.page.wait_for_timeout(300)
                            return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_load_mode error: {e}")
        return self

    def select_carrier(self, carrier: str = "全部"):
        """选择运营商"""
        try:
            self._close_any_dropdown()

            carrier_label = self.page.locator('text=运营商').first
            if carrier_label.count() > 0:
                form_item = carrier_label.locator('xpath=ancestor::div[contains(@class, "ant-form-item")]')
                if form_item.count() == 0:
                    form_item = carrier_label.locator('xpath=ancestor::div[2]')

                if form_item.count() > 0:
                    current_value = form_item.locator('.ant-select-selection-item')
                    if current_value.count() > 0:
                        current_text = current_value.first.get_attribute("title") or current_value.first.text_content().strip()
                        if current_text == carrier:
                            return self

                    selector = form_item.locator('.ant-select-selector')
                    if selector.count() > 0:
                        selector.first.click()
                        self.page.wait_for_timeout(800)

                        if self._select_option_via_js(carrier):
                            self.page.wait_for_timeout(300)
                            return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_carrier error: {e}")
        return self

    def fill_remark(self, remark: str):
        """填写备注"""
        remark_input = self.page.locator('#comment')
        if remark_input.count() > 0:
            remark_input.click()
            remark_input.fill(remark)
            self.page.wait_for_timeout(200)
        return self

    def set_line_weight(self, line_name: str, weight: str = "1"):
        """设置指定线路的负载比例

        使用JS定位可见下拉框，避免多个隐藏下拉框DOM干扰。
        多线负载表格使用div.ant-table-row结构(非标准tbody/tr/td)。
        """
        try:
            self._close_any_dropdown()

            # 通过JS找到匹配线路名的行索引 (使用ant-table-row而非tbody tr)
            row_idx = self.page.evaluate("""(lineName) => {
                const rows = document.querySelectorAll('.ant-table-row');
                for (let i = 0; i < rows.length; i++) {
                    const cells = rows[i].querySelectorAll('.ant-table-cell');
                    if (cells.length >= 2 && cells[1].textContent.trim().includes(lineName)) {
                        return i;
                    }
                }
                return -1;
            }""", line_name)

            if row_idx < 0:
                return self

            # 点击该行的下拉框 (force=True解决overlay拦截问题)
            row = self.page.locator('.ant-table-row').nth(row_idx)
            select = row.locator('.ant-select-selector')
            if select.count() > 0:
                select.first.click(force=True)
                self.page.wait_for_timeout(800)

                # 通过JS在可见的下拉框中选择
                if self._select_option_via_js(weight):
                    self.page.wait_for_timeout(300)
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] set_line_weight error: {e}")
            self._close_any_dropdown()
        return self

    def set_line_weights(self, weights: Dict[str, str]):
        """批量设置多条线路的负载比例"""
        for line_name, weight in weights.items():
            self.set_line_weight(line_name, weight)
        return self

    def get_available_lines(self) -> List[str]:
        """获取当前可用的线路列表"""
        try:
            lines = self.page.evaluate("""() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                for (const row of rows) {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length >= 2) {
                        const text = cells[1].textContent.trim();
                        if (text && text !== '暂无内容') result.push(text);
                    }
                }
                return result;
            }""")
            return lines
        except Exception:
            return []

    # ==================== 添加规则（完整流程）====================
    def add_rule(self, name: str, load_mode: str = None,
                 carrier: str = None, remark: str = None,
                 weights: Dict[str, str] = None) -> bool:
        """添加多线负载规则"""
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1000)

            self.fill_name(name)
            if load_mode:
                self.select_load_mode(load_mode)
            if carrier:
                self.select_carrier(carrier)
            if remark:
                self.fill_remark(remark)
            if weights:
                self.set_line_weights(weights)

            self.click_save()
            success = self.wait_for_success_message()

            # 无论保存成功还是失败，始终导航回列表页确保状态一致
            self.page.wait_for_timeout(500)
            self.navigate_back_to_list()
            self.page.wait_for_timeout(500)

            return success

        except Exception as e:
            print(f"[ERROR] 添加规则失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 编辑规则 ====================
    def edit_rule(self, old_name: str, new_name: str = None,
                  load_mode: str = None, carrier: str = None,
                  remark: str = None, weights: Dict[str, str] = None) -> bool:
        """编辑多线负载规则"""
        try:
            clicked = self.page.evaluate("""(name) => {
                const allElements = document.querySelectorAll('.ant-table-cell');
                for (let i = 0; i < allElements.length; i++) {
                    const cell = allElements[i];
                    if (cell.textContent.trim() === name) {
                        // 支持 div.ant-table-row 和标准 tr 两种结构
                        let row = cell.closest('.ant-table-row') || cell.closest('tr');
                        if (!row) {
                            row = cell.parentElement;
                            while (row && row.tagName !== 'TR' && !row.classList.contains('ant-table-row') && row.tagName !== 'BODY') {
                                row = row.parentElement;
                            }
                        }
                        if (row) {
                            const btn = row.querySelector('button[title="编辑"], a[title="编辑"]');
                            if (btn) { btn.click(); return true; }
                            const btns = row.querySelectorAll('button, a');
                            for (const b of btns) {
                                if (b.textContent.trim() === '编辑') { b.click(); return true; }
                            }
                        }
                    }
                }
                return false;
            }""", old_name)

            if not clicked:
                print(f"[WARN] 编辑按钮未找到: {old_name}")
                return False

            self.page.wait_for_timeout(1500)

            if new_name:
                self.fill_name(new_name)
            if load_mode:
                self.select_load_mode(load_mode)
            if carrier:
                self.select_carrier(carrier)
            if remark is not None:
                self.fill_remark(remark)
            if weights:
                self.set_line_weights(weights)

            self.click_save()
            result = self.wait_for_success_message()

            if result:
                self.page.wait_for_timeout(500)
                if "multiLineLoad" in self.page.url:
                    self.navigate_back_to_list()
            else:
                try:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    self.navigate_back_to_list()
                except Exception:
                    pass

            return result

        except Exception as e:
            print(f"[ERROR] 编辑规则失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 状态验证 ====================
    def get_rule_count(self) -> int:
        """获取当前规则数量"""
        try:
            count_text = self.page.locator('text=/共 \\d+ 条/')
            if count_text.count() > 0:
                import re
                match = re.search(r'共 (\d+) 条', count_text.first.text_content())
                if match:
                    return int(match.group(1))

            # 回退: 统计ant-table-row数量
            rows = self.page.locator('.ant-table-row')
            return rows.count()
        except Exception:
            return 0

    def get_rule_list(self) -> List[str]:
        """获取所有规则名称列表 (使用ant-table-row结构)"""
        try:
            names = self.page.evaluate("""() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                for (const row of rows) {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length > 1) {
                        const name = cells[1].textContent.trim();
                        if (name && name !== '暂无内容') {
                            result.push(name);
                        }
                    }
                }
                return result;
            }""")
            return names
        except Exception:
            return []

    # ==================== 异常输入测试 ====================
    def try_add_rule_invalid(self, name: str = "",
                             expect_fail: bool = True) -> dict:
        """尝试添加无效规则，测试表单验证"""
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1000)

            if name is not None:
                self.fill_name(name)

            self.click_save()
            self.page.wait_for_timeout(1000)

            error_el = self.page.locator('.ant-form-item-explain-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    if "multiLineLoad" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            toast_error = self.page.locator('.ant-message-error')
            if toast_error.count() > 0:
                error_text = toast_error.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    if "multiLineLoad" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            # 检查是否仍在配置页面（保存被拒绝）
            still_on_config = "multiLineLoad/add" in self.page.url or "multiLineLoad/edit" in self.page.url
            if expect_fail and still_on_config:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "multiLineLoad" in self.page.url:
                    self.navigate_back_to_list()
                return {"success": True, "error_message": "保存被拒绝(后端验证)"}

            if expect_fail:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "multiLineLoad" in self.page.url:
                    self.navigate_back_to_list()
                return {"success": False, "error_message": ""}

            return {"success": True, "error_message": ""}

        except Exception as e:
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return {"success": False, "error_message": str(e)}

    # ==================== 排序 ====================
    def sort_by_column(self, column_name: str) -> bool:
        """按列排序"""
        try:
            col_id = self.COLUMN_ID_MAP.get(column_name)
            if not col_id:
                return False

            th = self.page.locator(f'th#{col_id}')
            if th.count() == 0:
                return False

            th.hover()
            self.page.wait_for_timeout(300)

            sort_icon = th.locator('.sortIcon .anticon svg')
            if sort_icon.count() > 0:
                sort_icon.first.click(force=True)
                self.page.wait_for_timeout(500)
                return True
            return False
        except Exception as e:
            print(f"[DEBUG] sort_by_column({column_name}) error: {e}")
            return False

    # ==================== 自定义运营商 ====================
    def open_custom_carrier_dialog(self) -> bool:
        """打开自定义运营商抽屉(Ant Design Drawer)"""
        try:
            btn = self.page.locator('button:has-text("自定义运营商")')
            if btn.count() > 0:
                btn.first.click()
                self.page.wait_for_timeout(1000)
                drawer = self.page.locator('.ant-drawer')
                return drawer.count() > 0
            return False
        except Exception:
            return False

    def close_custom_carrier_dialog(self):
        """关闭自定义运营商抽屉"""
        try:
            close_btn = self.page.locator('.ant-drawer-close')
            if close_btn.count() > 0:
                close_btn.first.click()
                self.page.wait_for_timeout(500)
        except Exception:
            pass

    def add_custom_carrier(self, name: str, dest_addr: str = "10.0.0.0/24") -> bool:
        """在自定义运营商抽屉中添加运营商

        点击"添加"后弹出表单抽屉，包含必填字段：运营商名称、目的地址
        dest_addr: 目的地址，默认10.0.0.0/24（CIDR格式）
        """
        try:
            drawer = self.page.locator('.ant-drawer')
            if drawer.count() == 0:
                return False

            # 点击抽屉内的添加按钮（蓝色主按钮）
            add_btn = drawer.locator('button.ant-btn-primary:has-text("添加")')
            if add_btn.count() > 0:
                add_btn.first.click()
                self.page.wait_for_timeout(2000)

            # 填写运营商名称（必填）
            name_input = self.page.locator('input#name, input[placeholder="请输入运营商名称"]')
            if name_input.count() > 0:
                name_input.first.click()
                name_input.first.fill(name)
                self.page.wait_for_timeout(300)

            # 填写目的地址（必填，CIDR格式如 10.0.0.0/24）
            addr_textarea = self.page.locator('textarea#dest_addr, textarea[placeholder="请输入目的地址"]')
            if addr_textarea.count() > 0:
                addr_textarea.first.click()
                addr_textarea.first.fill(dest_addr)
                self.page.wait_for_timeout(300)

            # 点击保存按钮
            save_btn = self.page.locator('button:has-text("保存")')
            if save_btn.count() > 0:
                save_btn.first.click()
                self.page.wait_for_timeout(1000)
                return self.wait_for_success_message()
            return False
        except Exception as e:
            print(f"[DEBUG] add_custom_carrier error: {e}")
            return False

    def delete_custom_carrier(self, name: str) -> bool:
        """在自定义运营商抽屉中删除运营商"""
        try:
            drawer = self.page.locator('.ant-drawer')
            if drawer.count() == 0:
                return False

            # 用Playwright点击删除按钮（JS click不触发React事件）
            target_row = None
            rows = drawer.locator('.ant-table-row')
            for i in range(rows.count()):
                cells = rows.nth(i).locator('.ant-table-cell')
                # 在所有列中查找包含名称的单元格（第一列可能是复选框）
                for j in range(cells.count()):
                    text = cells.nth(j).text_content().strip()
                    if text and name in text:
                        target_row = rows.nth(i)
                        break
                if target_row is not None:
                    break

            if target_row is None:
                return False

            del_btn = target_row.locator('button:has-text("删除"), a:has-text("删除")')
            if del_btn.count() > 0:
                del_btn.first.click(force=True)
                self.page.wait_for_timeout(800)

                confirm = self.page.get_by_role("button", name="确定")
                if confirm.count() > 0:
                    confirm.click()
                    self.page.wait_for_timeout(800)
                    return self.wait_for_success_message()
            return False
        except Exception as e:
            print(f"[DEBUG] delete_custom_carrier error: {e}")
            return False

    def get_custom_carrier_count(self) -> int:
        """获取自定义运营商数量"""
        try:
            drawer = self.page.locator('.ant-drawer-body')
            if drawer.count() == 0:
                return -1
            rows = drawer.locator('.ant-table-row')
            return rows.count()
        except Exception:
            return -1
