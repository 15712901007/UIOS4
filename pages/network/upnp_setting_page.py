"""
UPnP/NAT设置页面类

处理网络配置 > UPnP/NAT > UPnP设置 tab的增删改查、导入导出、设置面板等操作
继承 IkuaiTablePage 获取通用表格操作

数据库字段映射 (从后端脚本upnpd.sh确认):
- upnpd_conf表(全局配置, 单行):
  enabled, exclude_port, lan_ip, interface, check_link, check_interval, rst_switch, rst_week, rst_time
- upnpd_ifconf表(接口规则, 多行):
  id, enabled, tagname, src_addr(JSON), interface(线路), comment(备注)

页面结构:
- URL: /login#/networkConfiguration/upnpNat
- 5个tab: UPnP设置/UPnP状态/NAT规则/端口映射/DMZ主机
- UPnP设置tab: 表格(名称/内网IP/线路/备注/操作) + 工具栏(搜索/添加/导入/导出)
- 右上角齿轮按钮: 打开设置面板(aside.ant-layout-sider，非.ant-drawer)
- 添加表单: 独立页面(upnpSettings/add), 字段: 名称/内网IP(IP设置+IP分组)/线路(多选)/备注
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class UpnpSettingPage(IkuaiTablePage):
    """UPnP/NAT设置页面操作类"""

    MODULE_NAME = "upnp_setting"
    UPNP_NAT_URL = "/login#/networkConfiguration/upnpNat"

    # 排序列映射
    COLUMN_ID_MAP = {
        "线路": "interface",
    }

    # ==================== 导航 ====================

    def navigate_to_upnp_setting(self):
        """导航到UPnP/NAT > UPnP设置页面"""
        url = f"{self.base_url}{self.UPNP_NAT_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        # 点击UPnP设置 tab
        tab = self.page.get_by_role("tab", name="UPnP设置")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_upnp_setting()
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

    # IP input placeholder uses Unicode left/right double quotes: U+201C / U+201D
    _IP_INPUT_NAME = '请输入IP（IP段使用“-”分割）'

    def add_ip_entry(self, ip: str):
        """Add a single internal IP entry."""
        try:
            # Click the "添加" button in IP settings area
            add_buttons = self.page.get_by_role('button', name='添加')
            for i in range(add_buttons.count()):
                btn = add_buttons.nth(i)
                if btn.is_visible():
                    btn.click()
                    self.page.wait_for_timeout(500)
                    # Check if IP input appeared
                    ip_input = self.page.get_by_role("textbox", name=self._IP_INPUT_NAME)
                    if ip_input.count() > 0:
                        print(f"    [add_ip_entry] clicked add button #{i}")
                        break

            # Find IP input via role name with Unicode quotes
            ip_input = self.page.get_by_role("textbox", name=self._IP_INPUT_NAME)
            if ip_input.count() == 0:
                # Fallback: find by placeholder containing "IP"
                all_inputs = self.page.locator('input[placeholder]')
                for i in range(all_inputs.count()):
                    inp = all_inputs.nth(i)
                    ph = inp.get_attribute("placeholder") or ""
                    if "IP" in ph and inp.is_visible():
                        ip_input = inp
                        break

            if ip_input.count() > 0:
                ip_input.last.click()
                self.page.wait_for_timeout(200)
                ip_input.last.type(ip, delay=30)
                self.page.wait_for_timeout(500)
                print(f"    [add_ip_entry] typed IP={ip}")
            else:
                print(f"    [WARN] add_ip_entry: IP input not found")
        except Exception as e:
            print(f"[DEBUG] add_ip_entry error: {e}")
        return self

    def add_ip_batch(self, ips: List[str]):
        """批量添加内网IP

        点击"批量"按钮后在textarea中填写多个IP。

        Args:
            ips: IP地址列表
        """
        try:
            ip_section = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text="内网IP")
            )
            if ip_section.count() > 0:
                batch_btn = ip_section.first.get_by_role('button', name='批量')
                if batch_btn.count() > 0:
                    batch_btn.click()
                    self.page.wait_for_timeout(500)

            textarea = self.page.locator('textarea')
            if textarea.count() > 0:
                textarea.last.click()
                textarea.last.fill("\n".join(ips))
                self.page.wait_for_timeout(300)
                textarea.last.press("Enter")
                self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] add_ip_batch error: {e}")
        return self

    def select_ip_group(self, group_name: str):
        """选择IP分组(combobox下拉框)

        Args:
            group_name: IP分组名称
        """
        try:
            self._close_any_dropdown()

            group_sel = self.page.get_by_role("combobox", name="IP分组")
            if group_sel.count() == 0:
                group_form = self.page.locator('.ant-form-item').filter(
                    has=self.page.locator('[class*="label"]').filter(has_text="IP分组")
                )
                if group_form.count() > 0:
                    group_sel = group_form.first.locator('.ant-select').first

            if group_sel.count() > 0:
                group_sel.locator('.ant-select-selector').first.click()
                self.page.wait_for_timeout(1000)

                option = self.page.locator(f'.ant-select-item-option[title="{group_name}"]')
                if option.count() > 0:
                    option.first.click()
                    self.page.wait_for_timeout(300)
                    return self

                item = self.page.get_by_text(group_name, exact=True)
                if item.count() > 0:
                    item.first.click()
                    self.page.wait_for_timeout(300)
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_ip_group error: {e}")
        return self

    def select_line(self, line_name: str):
        """选择线路(ant-select-multiple多选下拉框)

        通过ant-select-item-option点击选项（非checkbox方式）。

        Args:
            line_name: 线路名称，如 "wan1", "wan2", "wan3"
        """
        for attempt in range(3):
            try:
                # 打开线路下拉框
                line_form = self.page.locator('.ant-form-item').filter(
                    has=self.page.locator('[class*="label"]').filter(has_text="线路")
                )
                if line_form.count() > 0:
                    line_sel = line_form.first.locator('.ant-select-selector')
                    if line_sel.count() > 0:
                        line_sel.first.click(force=True)
                        self.page.wait_for_timeout(1000)
                        print(f"    [select_line] opened dropdown via form-item selector")
                else:
                    # Fallback: combobox role
                    line_combobox = self.page.get_by_role("combobox", name="线路 *")
                    if line_combobox.count() > 0:
                        selector = line_combobox.first.locator(
                            'xpath=ancestor::div[contains(@class,"ant-select-selector")]')
                        if selector.count() > 0:
                            selector.first.click()
                        else:
                            line_combobox.first.click()
                        self.page.wait_for_timeout(1000)
                        print(f"    [select_line] opened dropdown via combobox role")

                # 策略1: 点击 .ant-select-item-option[title] (实测有效)
                option = self.page.locator(f'.ant-select-item-option[title="{line_name}"]')
                if option.count() > 0:
                    option.first.click()
                    self.page.wait_for_timeout(500)
                    print(f"    [select_line] clicked option for {line_name}")
                else:
                    # 策略2: checkbox方式
                    wrapper = self.page.locator('.ant-checkbox-wrapper').filter(has_text=line_name)
                    if wrapper.count() > 0:
                        wrapper.first.click(force=True)
                        self.page.wait_for_timeout(500)
                        print(f"    [select_line] clicked checkbox for {line_name}")

                # 验证是否已选中
                if self.page.locator('.ant-select-selection-item').count() > 0:
                    break

                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(500)
            except Exception as e:
                print(f"[DEBUG] select_line({line_name}) attempt {attempt+1}: {e}")
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

    def select_lines(self, line_names: List[str]):
        """选择多条线路

        Args:
            line_names: 线路名称列表
        """
        for line_name in line_names:
            self.select_line(line_name)
            self.page.wait_for_timeout(300)
        return self

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

    # ==================== 规则列表查询 ====================

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
            return names if names else []
        except Exception:
            return []

    # ==================== 添加规则（完整流程）====================

    def add_rule(self, name: str,
                 ips: List[str] = None,
                 ip_batch: List[str] = None,
                 ip_group: str = None,
                 lines: List[str] = None,
                 remark: str = None) -> bool:
        """添加UPnP设置规则

        Args:
            name: 规则名称(必填, 最多15字符)
            ips: 内网IP列表(逐条添加)
            ip_batch: 内网IP列表(批量添加)
            ip_group: IP分组名称
            lines: 线路列表(必填, 如["wan1"])
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

            # 内网IP(逐条添加)
            if ips:
                for ip in ips:
                    print(f"  [add_rule] adding ip={ip}")
                    self.add_ip_entry(ip)
                    self.page.wait_for_timeout(300)

            # 内网IP(批量添加)
            if ip_batch:
                print(f"  [add_rule] batch adding {len(ip_batch)} IPs")
                self.add_ip_batch(ip_batch)

            # IP分组
            if ip_group:
                print(f"  [add_rule] selecting ip_group={ip_group}")
                self.select_ip_group(ip_group)

            # 线路(必填)
            if lines:
                print(f"  [add_rule] selecting lines={lines}")
                self.select_lines(lines)

            # 备注（先清空再按需填写，防止其他操作污染备注字段）
            try:
                remark_input = self.page.get_by_role("textbox", name="备注")
                if remark_input.count() > 0:
                    remark_input.click()
                    remark_input.press("Control+a")
                    remark_input.press("Backspace")
                    self.page.wait_for_timeout(100)
            except Exception:
                pass
            if remark:
                print(f"  [add_rule] filling remark={remark}")
                self.fill_remark(remark)

            print(f"  [add_rule] clicking save... (current URL: {self.page.url})")
            self.click_save()

            self.page.wait_for_timeout(1500)

            current_url = self.page.url
            print(f"  [add_rule] after save URL: {current_url}")

            # 检查表单错误（带字段标签）
            error_el = self.page.locator(
                '.ant-form-item-explain-error, '
                '.ant-form-item-explain, '
                '[class*="form-item-explain"]'
            )
            if error_el.count() > 0:
                errors_with_labels = self.page.evaluate("""() => {
                    const result = [];
                    document.querySelectorAll('.ant-form-item-explain-error, .ant-form-item-explain, [class*="form-item-explain"]').forEach(el => {
                        const text = el.textContent.trim();
                        if (!text) return;
                        let parent = el.parentElement;
                        let depth = 0;
                        let label = '';
                        while (parent && depth < 10) {
                            const labelEl = parent.querySelector('.ant-form-item-label');
                            if (labelEl) { label = labelEl.textContent.trim(); break; }
                            parent = parent.parentElement;
                            depth++;
                        }
                        result.push(label + ': ' + text);
                    });
                    return result;
                }""")
                print(f"  [add_rule] FORM ERRORS: {errors_with_labels}")
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
        """编辑UPnP设置规则"""
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
                if "upnpSettings" in self.page.url:
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

    # ==================== 复制规则 ====================

    def copy_rule(self, rule_name: str):
        """点击列表中的复制按钮"""
        self._click_rule_button(rule_name, "复制")
        self.page.wait_for_timeout(1500)
        return self

    # ==================== 设置面板(齿轮图标 → aside.ant-layout-sider) ====================

    def _get_sider(self):
        """获取设置面板(aside.ant-layout-sider)的定位器"""
        return self.page.locator('aside.ant-layout-sider')

    def open_settings_drawer(self) -> bool:
        """打开设置面板(右上角齿轮图标，实际是ant-layout-sider非drawer)"""
        try:
            # 先检查sider是否已经打开
            sider = self._get_sider()
            if sider.count() > 0 and sider.first.is_visible():
                sider_width = sider.first.evaluate('el => el.getBoundingClientRect().width')
                if sider_width and sider_width > 100:
                    print("[DEBUG] sider already open")
                    return True

            # 使用React fiber onClick直接调用 -- Playwright click不触发React事件
            result = self.page.evaluate("""() => {
                const tablist = document.querySelector('[role="tablist"]');
                if (!tablist) return 'no tablist';
                const parent = tablist.parentElement;
                if (!parent) return 'no parent';
                const btns = parent.querySelectorAll('button.ant-btn-icon-only');
                for (const btn of btns) {
                    const fiberKey = Object.keys(btn).find(k => k.startsWith('__reactFiber'));
                    if (fiberKey) {
                        let fiber = btn[fiberKey];
                        while (fiber) {
                            if (fiber.memoizedProps && typeof fiber.memoizedProps.onClick === 'function') {
                                fiber.memoizedProps.onClick({stopPropagation: () => {}, preventDefault: () => {}});
                                return 'clicked via fiber';
                            }
                            fiber = fiber.return;
                        }
                    }
                }
                return 'no fiber onClick found';
            }""")
            self.page.wait_for_timeout(1000)

            # 验证sider是否打开: 检查保存按钮是否可见(sider宽度可能只有48但仍可见)
            sider = self._get_sider()
            if sider.count() > 0:
                save_btn = sider.get_by_role("button", name="保存")
                if save_btn.count() > 0 and save_btn.first.is_visible():
                    return True
                # 备用: 检查checkbox是否存在
                checkbox = self.page.get_by_role("checkbox", name="开启UPnP即插即用服务")
                if checkbox.count() > 0 and checkbox.is_visible():
                    return True

            print("[WARN] 设置面板未能打开")
            return False
        except Exception as e:
            print(f"[DEBUG] open_settings_drawer error: {e}")
            return False

    def close_settings_drawer(self):
        """关闭设置面板"""
        try:
            sider = self._get_sider()
            if sider.count() == 0:
                return True

            # 尝试点击sider内的关闭按钮(aria-label="close"或关闭图标)
            close_btn = sider.locator('[aria-label="close"], .ant-drawer-close, [class*="close"]').first
            if close_btn.count() > 0 and close_btn.is_visible():
                close_btn.click()
                self.page.wait_for_timeout(500)
                return True

            # 尝试取消按钮
            cancel_btn = sider.get_by_role("button", name="取消")
            if cancel_btn.count() > 0:
                cancel_btn.click()
                self.page.wait_for_timeout(500)
                return True

            # ESC关闭
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] close_settings_drawer error: {e}")
        return True

    def toggle_upnp_service(self, enable: bool):
        """开启/关闭UPnP即插即用服务"""
        try:
            checkbox = self.page.get_by_role("checkbox", name="开启UPnP即插即用服务")
            if checkbox.count() > 0:
                is_checked = checkbox.is_checked()
                if is_checked != enable:
                    checkbox.click()
                    self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] toggle_upnp_service error: {e}")
        return self

    def set_exclude_ports(self, ports: str):
        """设置排除端口"""
        try:
            # 通过placeholder定位排除端口输入框
            port_input = self.page.get_by_placeholder("请输入端口范围")
            if port_input.count() == 0:
                # 备用: 通过sider内的form-item定位
                sider = self._get_sider()
                port_form = sider.locator('.ant-form-item').filter(has_text="排除端口")
                port_input = port_form.first.locator('input').first
            if port_input.count() > 0:
                port_input.click()
                port_input.press("Control+a")
                port_input.fill(ports)
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] set_exclude_ports error: {e}")
        return self

    def set_allowed_ip(self, ip_range: str):
        """设置允许内网IP映射"""
        try:
            sider = self._get_sider()
            ip_form = sider.locator('.ant-form-item').filter(has_text="允许内网IP映射")
            if ip_form.count() > 0:
                ip_input = ip_form.first.locator('input').first
                if ip_input.count() > 0:
                    ip_input.click()
                    ip_input.press("Control+a")
                    ip_input.fill(ip_range)
                    self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] set_allowed_ip error: {e}")
        return self

    def set_default_line(self, line_name: str):
        """设置默认线路(combobox)"""
        try:
            sider = self._get_sider()
            line_form = sider.locator('.ant-form-item').filter(has_text="默认线路设置")
            if line_form.count() > 0:
                line_sel = line_form.first.locator('.ant-select').first
                if line_sel.count() > 0:
                    # 点击当前选中项或selector打开下拉
                    sel_item = line_sel.locator('.ant-select-selection-item')
                    if sel_item.count() > 0:
                        sel_item.first.click()
                    else:
                        line_sel.click()
                    self.page.wait_for_timeout(800)

                    option = self.page.locator(f'.ant-select-item-option[title="{line_name}"]')
                    if option.count() > 0:
                        option.first.click()
                    else:
                        item = self.page.get_by_text(line_name, exact=True)
                        if item.count() > 0:
                            item.first.click()
                    self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] set_default_line error: {e}")
        return self

    def toggle_disconnect_detection(self, enable: bool):
        """开启/关闭掉线检测"""
        try:
            checkbox = self.page.get_by_role("checkbox", name="开启掉线检测")
            if checkbox.count() > 0:
                is_checked = checkbox.is_checked()
                if is_checked != enable:
                    checkbox.click()
                    self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] toggle_disconnect_detection error: {e}")
        return self

    def set_check_interval(self, minutes: int):
        """设置检测周期(1-59分钟)"""
        try:
            sider = self._get_sider()
            interval_form = sider.locator('.ant-form-item').filter(has_text="检测周期")
            if interval_form.count() > 0:
                interval_input = interval_form.first.locator('input').first
                if interval_input.count() > 0:
                    interval_input.click()
                    interval_input.press("Control+a")
                    interval_input.type(str(minutes), delay=50)
                    self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] set_check_interval error: {e}")
        return self

    def toggle_scheduled_restart(self, enable: bool):
        """开启/关闭定时重启"""
        try:
            checkbox = self.page.get_by_role("checkbox", name="开启定时重启")
            if checkbox.count() > 0:
                is_checked = checkbox.is_checked()
                if is_checked != enable:
                    checkbox.click()
                    self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] toggle_scheduled_restart error: {e}")
        return self

    def set_restart_weekdays(self, days: List[str]):
        """设置重启周期(星期几)

        Args:
            days: 星期列表，如 ["一", "二", "三", "四", "五"]
        """
        try:
            all_days = ["一", "二", "三", "四", "五", "六", "日"]
            sider = self._get_sider()
            for day_text in all_days:
                day_el = sider.get_by_text(day_text, exact=True)
                if day_el.count() > 0:
                    is_active = day_el.first.evaluate(
                        'el => el.classList.contains("ant-tag-checkable-checked")'
                        ' || el.parentElement.classList.contains("ant-tag-checkable-checked")'
                        ' || el.classList.contains("active")'
                    )
                    should_select = day_text in days
                    if should_select != is_active:
                        day_el.first.click()
                        self.page.wait_for_timeout(100)
        except Exception as e:
            print(f"[DEBUG] set_restart_weekdays error: {e}")
        return self

    def set_restart_time(self, time_str: str):
        """设置重启时间

        Args:
            time_str: 时间字符串，如 "03:00"
        """
        try:
            sider = self._get_sider()
            time_form = sider.locator('.ant-form-item').filter(has_text="重启时间")
            if time_form.count() > 0:
                time_input = time_form.first.locator('input').first
                if time_input.count() > 0:
                    time_input.click()
                    time_input.press("Control+a")
                    time_input.type(time_str, delay=50)
                    self.page.wait_for_timeout(200)
                    self.page.keyboard.press("Enter")
                    self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] set_restart_time error: {e}")
        return self

    def save_settings(self) -> bool:
        """保存设置面板"""
        try:
            sider = self._get_sider()
            save_btn = sider.get_by_role("button", name="保存")
            if save_btn.count() > 0 and save_btn.is_visible():
                save_btn.click()
                self.page.wait_for_timeout(1500)
                # 检查是否有错误消息(如无效输入)
                error_msg = self.page.locator('.ant-message-error')
                if error_msg.count() > 0:
                    return False
                return self.wait_for_success_message()
        except Exception as e:
            print(f"[DEBUG] save_settings error: {e}")
        return False

    def cancel_settings(self):
        """取消设置面板"""
        try:
            sider = self._get_sider()
            cancel_btn = sider.get_by_role("button", name="取消")
            if cancel_btn.count() > 0:
                cancel_btn.click()
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] cancel_settings error: {e}")
        return self

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
                    if "upnpSettings" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            toast_error = self.page.locator('.ant-message-error')
            if toast_error.count() > 0:
                error_text = toast_error.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    if "upnpSettings" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            still_on_config = ("upnpSettings/add" in self.page.url or
                               "upnpSettings/edit" in self.page.url)
            if expect_fail and still_on_config:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "upnpSettings" in self.page.url:
                    self.navigate_back_to_list()
                return {"success": True, "error_message": "保存被拒绝(后端验证)"}

            if expect_fail:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "upnpSettings" in self.page.url:
                    self.navigate_back_to_list()
                return {"success": False, "error_message": ""}

            return {"success": True, "error_message": ""}

        except Exception as e:
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return {"success": False, "error_message": str(e)}
