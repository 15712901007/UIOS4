"""
上下行分离页面类

处理分流策略 > 上下行分离配置的增删改查、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作

数据库字段映射 (从后端脚本stream_updown.sh确认):
- tagname: 规则名称
- upiface: 上行线路(逗号分隔WAN接口名)
- downiface: 下行线路(逗号分隔WAN接口名)
- protocol: 协议(tcp/udp/tcp+udp/icmp/any)
- src_addr: 源IP/MAC地址(JSON, base64)
- dst_addr: 目的IP/MAC地址(JSON, base64)
- src_port: 源端口(JSON, base64)
- dst_port: 目的端口(JSON, base64)
- comment: 备注(max 64)
- enabled: "yes"/"no"

与端口分流的差异:
- 双线路选择(上行/下行), checkbox多选
- 无负载模式(mode)、无分流方式(type)、无优先级(prio)
- L2用ipset(updown_src/dst/sport/dport_{id}), 不用iptables
- L3/L4用ik_cntl wans-snat内核子系统
- 源端口/目的端口条件显示(protocol为tcp/udp/tcp+udp时)
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class UpdownRoutePage(IkuaiTablePage):
    """上下行分离页面操作类"""

    MODULE_NAME = "updown_route"
    DIVERSION_STRATEGY_URL = "/login#/networkConfiguration/diversionStrategy"

    # 排序列映射
    COLUMN_ID_MAP = {
        "上行线路": "upiface",
        "下行线路": "downiface",
    }

    # ==================== 导航 ====================
    def navigate_to_updown_route(self):
        """导航到分流策略 > 上下行分离页面"""
        url = f"{self.base_url}{self.DIVERSION_STRATEGY_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        tab = self.page.get_by_role("tab", name="上下行分离")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_updown_route()
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

    # ==================== 表单字段填写 ====================
    def fill_name(self, name: str):
        """填写规则名称"""
        name_input = self.page.locator('input[placeholder="请输入名称"]')
        if name_input.count() > 0:
            name_input.click()
            name_input.fill(name)
            self.page.wait_for_timeout(200)
        return self

    def select_protocol(self, protocol: str):
        """选择协议(combobox下拉框)

        Args:
            protocol: 协议名称(tcp/udp/tcp+udp/icmp/任意)
        """
        try:
            self._close_any_dropdown()
            sel = self.page.get_by_role("combobox", name="协议")
            if sel.count() > 0:
                parent = sel.locator('xpath=ancestor::div[contains(@class,"ant-select-selector")]')
                if parent.count() > 0:
                    item = parent.first.locator('.ant-select-selection-item')
                    if item.count() > 0:
                        current = item.first.text_content().strip()
                        if current == protocol:
                            return self
                        item.first.click()
                    else:
                        sel.click(force=True)
                else:
                    sel.click(force=True)
                self.page.wait_for_timeout(800)

                option = self.page.get_by_title(protocol, exact=True)
                if option.count() > 0:
                    option.click()
                else:
                    self._select_option_via_js(protocol)
                self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] select_protocol({protocol}) error: {e}")
        return self

    def _select_option_via_js(self, option_text: str) -> bool:
        """通过JS在当前可见的下拉框中选择指定选项"""
        try:
            clicked = self.page.evaluate("""(text) => {
                const dropdowns = document.querySelectorAll('.ant-select-dropdown');
                for (let i = dropdowns.length - 1; i >= 0; i--) {
                    const dd = dropdowns[i];
                    if (dd.offsetHeight > 0 && dd.offsetWidth > 0) {
                        const items = dd.querySelectorAll('.ant-select-item');
                        for (const item of items) {
                            if (item.textContent.trim() === text || item.getAttribute('title') === text) {
                                item.click();
                                return true;
                            }
                        }
                    }
                }
                return false;
            }""", option_text)
            return bool(clicked)
        except Exception:
            return False

    def select_upload_line(self, line_name: str):
        """选择上行线路(checkbox多选下拉框)

        Args:
            line_name: 线路名称，如 "wan2", "wan3", "全部"
        """
        return self._select_line_by_label("上行线路", line_name)

    def select_download_line(self, line_name: str):
        """选择下行线路(checkbox多选下拉框)

        Args:
            line_name: 线路名称，如 "wan2", "wan3", "全部"
        """
        return self._select_line_by_label("下行线路", line_name)

    def _select_line_by_label(self, label_text: str, line_name: str):
        """通过label文本选择checkbox线路下拉框

        上下行分离有两个独立的线路选择器(上行/下行), 需要通过label区分。
        """
        for attempt in range(3):
            try:
                line_form_item = self.page.locator('.ant-form-item').filter(
                    has=self.page.locator('[class*="label"]').filter(has_text=label_text)
                )
                if line_form_item.count() > 0:
                    line_sel = line_form_item.first.locator('.ant-select').first
                else:
                    print(f"[WARN] 未找到{label_text}表单区域")
                    return self

                line_sel.wait_for(state="visible", timeout=5000)
                line_sel.click()
                self.page.wait_for_timeout(1000)

                wrapper = self.page.locator('.ant-checkbox-wrapper').filter(has_text=line_name)
                if wrapper.count() > 0:
                    wrapper.first.click(force=True)
                    self.page.wait_for_timeout(500)

                break
            except Exception as e:
                print(f"[DEBUG] _select_line_by_label({label_text}, {line_name}) attempt {attempt+1}: {e}")
                try:
                    self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(300)
                except Exception:
                    pass

        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception:
            pass
        return self

    # ==================== IP/MAC地址设置 ====================
    def fill_src_addr(self, addr: str):
        """填写源IP/MAC地址

        点击源地址区域的"添加"按钮后输入地址。

        Args:
            addr: IP地址或MAC地址
        """
        return self._fill_addr_field("源地址", "IP/MAC设置", addr)

    def fill_dst_addr(self, addr: str):
        """填写目的IP/MAC地址"""
        return self._fill_addr_field("目的地址", "IP/MAC设置", addr)

    def _fill_addr_field(self, section_label: str, sub_label: str, addr: str):
        """通用地址填写方法

        表单中"添加"按钮的顺序: [0]源地址IP/MAC [1]目的地址IP/MAC [2]源端口 [3]目的端口
        源地址用第1个添加按钮, 目的地址用第2个。
        """
        try:
            add_buttons = self.page.get_by_role('button', name='添加')

            if section_label == "源地址" and add_buttons.count() >= 1:
                add_buttons.nth(0).click()
            elif section_label == "目的地址" and add_buttons.count() >= 2:
                add_buttons.nth(1).click()
            else:
                print(f"[WARN] 未找到地址添加按钮: {section_label}")
                return self
            self.page.wait_for_timeout(500)

            addr_input = self.page.get_by_placeholder('请输入IP或MAC')
            if addr_input.count() > 0:
                addr_input.last.click()
                addr_input.last.type(addr, delay=30)
                self.page.wait_for_timeout(200)
                addr_input.last.press("Enter")
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] _fill_addr_field({section_label}, {addr}) error: {e}")
        return self

    def select_src_addr_group(self, group_name: str, group_type: str = None):
        """选择源IP/MAC分组(dialog选择)"""
        return self._select_addr_group("源地址", group_name, group_type)

    def select_dst_addr_group(self, group_name: str, group_type: str = None):
        """选择目的IP/MAC分组(dialog选择)"""
        return self._select_addr_group("目的地址", group_name, group_type)

    def _select_addr_group(self, section_label: str, group_name: str, group_type: str = None):
        """通用IP/MAC分组选择"""
        try:
            self._close_any_dropdown()

            section = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text=section_label)
            )
            if section.count() == 0:
                group_sel = self.page.get_by_role("combobox", name="IP/MAC分组")
            else:
                group_sel = section.first.locator('.ant-select').last

            if group_sel.count() > 0:
                group_sel.locator('.ant-select-selector').first.click()
                self.page.wait_for_timeout(1000)

                dialog = self.page.locator('[role="dialog"]').last
                if dialog.is_visible():
                    if group_type:
                        type_radio = dialog.get_by_role("radio", name=group_type)
                        if type_radio.count() > 0:
                            type_radio.click()
                            self.page.wait_for_timeout(300)

                    checkbox = dialog.locator('.ant-checkbox-wrapper').filter(has_text=group_name)
                    if checkbox.count() > 0:
                        checkbox.first.click(force=True)
                        self.page.wait_for_timeout(300)

                        confirm = dialog.get_by_role('button', name='确定')
                        if confirm.count() > 0 and confirm.is_visible():
                            confirm.click()
                            self.page.wait_for_timeout(500)
                            return self

                    cancel = dialog.get_by_role('button', name='取消')
                    if cancel.count() > 0 and cancel.is_visible():
                        cancel.click()
                        self.page.wait_for_timeout(300)
                    print(f"[WARN] {section_label}IP/MAC分组不存在: {group_name}")
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] _select_addr_group({section_label}, {group_name}) error: {e}")
        return self

    # ==================== 端口设置(条件显示) ====================
    def fill_src_port(self, port: str):
        """填写源端口(protocol为tcp/udp/tcp+udp时显示)

        Args:
            port: 端口号或端口范围
        """
        return self._fill_port_field("源端口", "端口设置", port)

    def fill_dst_port(self, port: str):
        """填写目的端口"""
        return self._fill_port_field("目的端口", "端口设置", port)

    def _fill_port_field(self, section_label: str, sub_label: str, port: str):
        """通用端口填写方法

        端口区域仅在protocol为tcp/udp/tcp+udp时显示。
        表单中"添加"按钮的顺序: [0]源地址 [1]目的地址 [2]源端口 [3]目的端口
        端口按钮位于第3(源端口)和第4(目的端口)个位置。
        """
        try:
            # 所有"添加"按钮
            add_buttons = self.page.get_by_role('button', name='添加')
            btn_count = add_buttons.count()

            if section_label == "源端口" and btn_count >= 3:
                add_buttons.nth(2).click()
            elif section_label == "目的端口" and btn_count >= 4:
                add_buttons.nth(3).click()
            else:
                print(f"[WARN] 未找到端口添加按钮: {section_label}, btn_count={btn_count}")
                return self
            self.page.wait_for_timeout(500)

            port_input = self.page.get_by_placeholder('端口或端口范围')
            if port_input.count() > 0:
                port_input.last.click()
                port_input.last.type(port, delay=30)
                self.page.wait_for_timeout(200)
                port_input.last.press("Enter")
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] _fill_port_field({section_label}, {port}) error: {e}")
        return self

    def select_src_port_group(self, group_name: str):
        """选择源端口分组"""
        return self._select_port_group("源端口", group_name)

    def select_dst_port_group(self, group_name: str):
        """选择目的端口分组"""
        return self._select_port_group("目的端口", group_name)

    def _select_port_group(self, section_label: str, group_name: str):
        """通用端口分组选择"""
        try:
            self._close_any_dropdown()

            section = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text=section_label)
            )
            if section.count() == 0:
                return self

            group_sel = section.first.locator('.ant-select').last
            if group_sel.count() > 0:
                group_sel.locator('.ant-select-selector').first.click()
                self.page.wait_for_timeout(1000)

                dialog = self.page.locator('[role="dialog"]').last
                if dialog.is_visible():
                    checkbox = dialog.locator('.ant-checkbox-wrapper').filter(has_text=group_name)
                    if checkbox.count() > 0:
                        checkbox.first.click(force=True)
                        self.page.wait_for_timeout(300)

                        confirm = dialog.get_by_role('button', name='确定')
                        if confirm.count() > 0 and confirm.is_visible():
                            confirm.click()
                            self.page.wait_for_timeout(500)
                            return self

                    cancel = dialog.get_by_role('button', name='取消')
                    if cancel.count() > 0 and cancel.is_visible():
                        cancel.click()
                        self.page.wait_for_timeout(300)
                    print(f"[WARN] {section_label}端口分组不存在: {group_name}")
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] _select_port_group({section_label}, {group_name}) error: {e}")
        return self

    # ==================== 备注 ====================
    def fill_remark(self, remark: str):
        """填写备注"""
        try:
            remark_input = self.page.get_by_role("textbox", name="备注")
            if remark_input.count() > 0:
                remark_input.click()
                remark_input.fill(remark)
                self.page.wait_for_timeout(200)
        except Exception:
            try:
                remark_input = self.page.locator('#comment, textarea')
                if remark_input.count() > 0:
                    remark_input.last.click()
                    remark_input.last.fill(remark)
                    self.page.wait_for_timeout(200)
            except Exception:
                pass
        return self

    # ==================== 列表操作 ====================
    def copy_rule(self, rule_name: str):
        """点击列表中的复制按钮"""
        self._click_rule_button(rule_name, "复制")
        self.page.wait_for_timeout(1500)
        return self

    # ==================== 添加规则(完整流程) ====================
    def add_rule(self, name: str,
                 upload_line: str = "wan1",
                 download_line: str = "wan1",
                 protocol: str = "任意",
                 src_addr: str = None,
                 dst_addr: str = None,
                 src_addr_group: str = None,
                 dst_addr_group: str = None,
                 src_port: str = None,
                 dst_port: str = None,
                 src_port_group: str = None,
                 dst_port_group: str = None,
                 remark: str = None) -> bool:
        """添加上下行分离规则

        Args:
            name: 规则名称
            upload_line: 上行线路
            download_line: 下行线路
            protocol: 协议(tcp/udp/tcp+udp/icmp/任意)
            src_addr: 源IP/MAC地址
            dst_addr: 目的IP/MAC地址
            src_addr_group: 源IP/MAC分组
            dst_addr_group: 目的IP/MAC分组
            src_port: 源端口(protocol为tcp/udp/tcp+udp时有效)
            dst_port: 目的端口
            src_port_group: 源端口分组
            dst_port_group: 目的端口分组
            remark: 备注
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)

            try:
                self.page.wait_for_selector('input[placeholder="请输入名称"]', timeout=10000)
            except Exception:
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(1000)
            self.page.wait_for_timeout(500)

            self.fill_name(name)
            print(f"  [add_rule] name={name}")

            # 选择协议
            if protocol and protocol != "任意":
                print(f"  [add_rule] selecting protocol={protocol}")
                self.select_protocol(protocol)

            # 选择上行线路
            if upload_line:
                print(f"  [add_rule] selecting upload_line={upload_line}")
                self.select_upload_line(upload_line)

            # 选择下行线路
            if download_line:
                print(f"  [add_rule] selecting download_line={download_line}")
                self.select_download_line(download_line)

            # 源地址
            if src_addr:
                print(f"  [add_rule] filling src_addr={src_addr}")
                self.fill_src_addr(src_addr)

            # 目的地址
            if dst_addr:
                print(f"  [add_rule] filling dst_addr={dst_addr}")
                self.fill_dst_addr(dst_addr)

            # 源IP/MAC分组
            if src_addr_group:
                print(f"  [add_rule] selecting src_addr_group={src_addr_group}")
                self.select_src_addr_group(src_addr_group)

            # 目的IP/MAC分组
            if dst_addr_group:
                print(f"  [add_rule] selecting dst_addr_group={dst_addr_group}")
                self.select_dst_addr_group(dst_addr_group)

            # 源端口(protocol为tcp/udp/tcp+udp时)
            if src_port:
                print(f"  [add_rule] filling src_port={src_port}")
                self.fill_src_port(src_port)

            # 目的端口
            if dst_port:
                print(f"  [add_rule] filling dst_port={dst_port}")
                self.fill_dst_port(dst_port)

            # 源端口分组
            if src_port_group:
                print(f"  [add_rule] selecting src_port_group={src_port_group}")
                self.select_src_port_group(src_port_group)

            # 目的端口分组
            if dst_port_group:
                print(f"  [add_rule] selecting dst_port_group={dst_port_group}")
                self.select_dst_port_group(dst_port_group)

            # 备注
            if remark:
                print(f"  [add_rule] filling remark={remark}")
                self.fill_remark(remark)

            print(f"  [add_rule] clicking save... (current URL: {self.page.url})")
            self.click_save()

            self.page.wait_for_timeout(1500)

            current_url = self.page.url
            print(f"  [add_rule] after save URL: {current_url}")

            # 检查表单错误
            error_el = self.page.locator(
                '.ant-form-item-explain-error, '
                '.ant-form-item-explain, '
                '[class*="form-item-explain"]'
            )
            if error_el.count() > 0:
                errors = [error_el.nth(i).text_content() for i in range(min(error_el.count(), 5))]
                print(f"  [add_rule] FORM ERRORS: {errors}")
                self.click_cancel()
                self.page.wait_for_timeout(500)
                self.navigate_back_to_list()
                return False

            # 检查JS错误
            if "/add" in current_url or "/edit" in current_url:
                js_errors = self.page.evaluate("""() => {
                    const errors = [];
                    document.querySelectorAll(
                        '.ant-form-item-explain-error, ' +
                        '.ant-form-item-explain, ' +
                        '[class*="explain"], ' +
                        '.ant-message-error, ' +
                        '.ant-alert-error'
                    ).forEach(el => {
                        const text = el.textContent.trim();
                        if (text) errors.push(text);
                    });
                    document.querySelectorAll('.ant-form-item-has-error .ant-form-item-label').forEach(el => {
                        errors.push('FIELD_ERROR: ' + el.textContent.trim());
                    });
                    return errors;
                }""")
                if js_errors:
                    print(f"  [add_rule] JS detected errors: {js_errors}")
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    self.navigate_back_to_list()
                    return False

            success = self.wait_for_success_message()
            print(f"  [add_rule] save result: {success}")

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
                  remark: str = None) -> bool:
        """编辑上下行分离规则"""
        try:
            clicked = self.page.evaluate("""(name) => {
                const allElements = document.querySelectorAll('.ant-table-cell');
                for (let i = 0; i < allElements.length; i++) {
                    const cell = allElements[i];
                    if (cell.textContent.trim() === name) {
                        let row = cell.closest('.ant-table-row') || cell.closest('tr');
                        if (!row) {
                            row = cell.parentElement;
                            while (row && row.tagName !== 'TR' && !row.classList.contains('ant-table-row') && row.tagName !== 'BODY') {
                                row = row.parentElement;
                            }
                        }
                        if (row) {
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
            if remark is not None:
                self.fill_remark(remark)

            self.click_save()
            result = self.wait_for_success_message()

            if result:
                self.page.wait_for_timeout(500)
                if "flowUpDown" in self.page.url:
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

            rows = self.page.locator('.ant-table-row')
            return rows.count()
        except Exception:
            return 0

    def get_rule_list(self) -> List[str]:
        """获取所有规则名称列表"""
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
                    if "flowUpDown" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            toast_error = self.page.locator('.ant-message-error')
            if toast_error.count() > 0:
                error_text = toast_error.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    if "flowUpDown" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            still_on_config = ("flowUpDown/add" in self.page.url or
                               "flowUpDown/edit" in self.page.url)
            if expect_fail and still_on_config:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "flowUpDown" in self.page.url:
                    self.navigate_back_to_list()
                return {"success": True, "error_message": "保存被拒绝(后端验证)"}

            if expect_fail:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "flowUpDown" in self.page.url:
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
