"""
域名分流页面类

处理分流策略 > 域名分流配置的增删改查、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作

数据库字段映射 (从后端脚本stream_domain.sh确认):
- tagname: 规则名称
- interface: 线路(逗号分隔)
- prio: 优先级, 整数 0-63, 默认31
- enabled: "yes"/"no"
- domain: 域名列表(JSON)
- src_addr: 源IP/MAC地址(JSON)
- comment: 备注
- time: 生效时间(JSON)

与端口/协议分流的关键差异:
- 无负载模式(mode)、无协议(protocol)、无分流方式(type)
- 线路选择使用combobox下拉框
- 域名使用动态列表(添加+批量按钮)
- L2验证使用ipset(sdomain_src_{id})，不使用iptables
- L3验证使用/proc/ikuai/stats/ik_summary
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class DomainRoutePage(IkuaiTablePage):
    """域名分流页面操作类"""

    MODULE_NAME = "domain_route"
    DIVERSION_STRATEGY_URL = "/login#/networkConfiguration/diversionStrategy"

    # 排序列映射
    COLUMN_ID_MAP = {
        "线路": "interface",
        "优先级": "prio",
    }

    # ==================== 导航 ====================
    def navigate_to_domain_route(self):
        """导航到分流策略 > 域名分流页面"""
        url = f"{self.base_url}{self.DIVERSION_STRATEGY_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        tab = self.page.get_by_role("tab", name="域名分流")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_domain_route()
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
                            if (item.textContent.trim() === text) {
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

    # ==================== 表单字段填写 ====================
    def fill_name(self, name: str):
        """填写规则名称"""
        name_input = self.page.locator('input[placeholder="请输入名称"]')
        if name_input.count() > 0:
            name_input.click()
            name_input.fill(name)
            self.page.wait_for_timeout(200)
        return self

    def _click_select_by_role(self, role_name: str):
        """通过combobox role名称定位并点击打开下拉框"""
        sel = self.page.get_by_role("combobox", name=role_name)
        if sel.count() > 0:
            parent = sel.locator('xpath=ancestor::div[contains(@class,"ant-select-selector")]')
            if parent.count() > 0:
                item = parent.first.locator('.ant-select-selection-item')
                if item.count() > 0:
                    item.first.click()
                    self.page.wait_for_timeout(800)
                    return True
            sel.click(force=True)
            self.page.wait_for_timeout(800)
            return True
        return False

    def _get_current_select_value(self, role_name: str) -> str:
        """获取combobox当前选中的值"""
        try:
            sel = self.page.get_by_role("combobox", name=role_name)
            if sel.count() > 0:
                parent = sel.locator('xpath=ancestor::div[contains(@class,"ant-select-selector")]')
                item = parent.locator('.ant-select-selection-item')
                if item.count() > 0:
                    return item.first.get_attribute("title") or item.first.text_content().strip()
        except Exception:
            pass
        return ""

    def select_line(self, line_name: str):
        """选择线路(checkbox多选下拉框)

        域名分流的线路选择与端口分流相同：点击.ant-select打开下拉框，
        然后勾选checkbox。

        Args:
            line_name: 线路名称，如 "wan2", "wan3", "全部"
        """
        for attempt in range(3):
            try:
                # 定位线路区域: 通过form-item label "线路" 定位
                line_form_item = self.page.locator('.ant-form-item').filter(
                    has=self.page.locator('[class*="label"]').filter(has_text="线路"))
                if line_form_item.count() > 0:
                    line_sel = line_form_item.first.locator('.ant-select').first
                else:
                    # 备用: 第一个select
                    line_sel = self.page.locator('.ant-select').first
                line_sel.wait_for(state="visible", timeout=5000)

                line_sel.click()
                self.page.wait_for_timeout(1000)

                wrapper = self.page.locator('.ant-checkbox-wrapper').filter(has_text=line_name)
                if wrapper.count() > 0:
                    wrapper.first.click(force=True)
                    self.page.wait_for_timeout(500)

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

    def set_priority(self, priority: int):
        """设置优先级(域名分流无此字段, 自动跳过)"""
        # 域名分流表单没有优先级字段, 保留接口以兼容通用调用
        return self

    # ==================== 域名设置 ====================
    def fill_domain(self, domain: str):
        """添加单个域名

        点击"添加"按钮后在输入框中填写域名, 按Enter确认。

        Args:
            domain: 域名，如 "www.example.com"
        """
        try:
            # 找域名区域的"添加"按钮(第一个添加按钮)
            domain_section = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text="域名")
            )
            if domain_section.count() > 0:
                add_btn = domain_section.first.get_by_role('button', name='添加')
                if add_btn.count() > 0:
                    add_btn.click()
                    self.page.wait_for_timeout(500)

            domain_input = self.page.get_by_placeholder('请输入域名')
            if domain_input.count() > 0:
                domain_input.last.click()
                domain_input.last.type(domain, delay=30)
                self.page.wait_for_timeout(200)
                domain_input.last.press("Enter")
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] fill_domain error: {e}")
        return self

    def fill_domains_batch(self, domains: List[str]):
        """批量添加多个域名

        点击"批量"按钮后在textarea中填写多个域名(每行一个)。

        Args:
            domains: 域名列表
        """
        try:
            domain_section = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text="域名")
            )
            if domain_section.count() > 0:
                batch_btn = domain_section.first.get_by_role('button', name='批量')
                if batch_btn.count() > 0:
                    batch_btn.click()
                    self.page.wait_for_timeout(500)

            textarea = self.page.locator('textarea')
            if textarea.count() > 0:
                textarea.last.click()
                textarea.last.fill("\n".join(domains))
                self.page.wait_for_timeout(300)
                textarea.last.press("Enter")
                self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] fill_domains_batch error: {e}")
        return self

    def select_domain_group(self, group_name: str):
        """选择域名分组(dialog选择)

        使用域名分组combobox定位。

        Args:
            group_name: 域名分组名称
        """
        try:
            self._close_any_dropdown()

            group_sel = self.page.get_by_role("combobox", name="域名分组")
            if group_sel.count() == 0:
                # 备用: 通过form-item定位
                group_form = self.page.locator('.ant-form-item').filter(
                    has=self.page.locator('[class*="label"]').filter(has_text="域名分组")
                )
                if group_form.count() > 0:
                    group_sel = group_form.first.locator('.ant-select').first

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
                    print(f"[WARN] 域名分组不存在: {group_name}")
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_domain_group error: {e}")
        return self

    # ==================== IP/MAC地址设置 ====================
    def fill_src_addr(self, addr: str):
        """填写源IP/MAC地址

        点击IP/MAC区域的"添加"按钮后输入地址。

        Args:
            addr: IP地址或MAC地址
        """
        try:
            ipmac_section = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text="IP/MAC")
            )
            if ipmac_section.count() > 0:
                add_btn = ipmac_section.first.get_by_role('button', name='添加')
                if add_btn.count() > 0:
                    add_btn.click()
                    self.page.wait_for_timeout(500)

            src_input = self.page.get_by_placeholder('请输入IP或MAC')
            if src_input.count() > 0:
                src_input.last.click()
                src_input.last.type(addr, delay=30)
                self.page.wait_for_timeout(200)
                src_input.last.press("Enter")
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] fill_src_addr error: {e}")
        return self

    def select_src_group(self, group_name: str, group_type: str = None):
        """选择IP/MAC分组(dialog选择)

        Args:
            group_name: 分组名称
            group_type: "IP"/"MAC"/None(全部)
        """
        try:
            self._close_any_dropdown()

            group_sel = self.page.get_by_role("combobox", name="IP/MAC分组")
            if group_sel.count() == 0:
                group_form = self.page.locator('.ant-form-item').filter(
                    has=self.page.locator('[class*="label"]').filter(has_text="IP/MAC分组")
                )
                if group_form.count() > 0:
                    group_sel = group_form.first.locator('.ant-select').first

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
                    print(f"[WARN] IP/MAC分组不存在: {group_name}")
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_src_group error: {e}")
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

    # ==================== 生效时间 ====================
    def set_time_by_week(self, days: List[str] = None,
                         start_time: str = "00:00", end_time: str = "23:59"):
        """设置按周循环的生效时间"""
        try:
            radio = self.page.get_by_role("radio", name="按周循环")
            if radio.count() > 0 and not radio.is_checked():
                radio.click()
                self.page.wait_for_timeout(300)

            if days is not None:
                all_days = ["一", "二", "三", "四", "五", "六", "日"]
                for day_text in all_days:
                    day_el = self.page.get_by_text(day_text, exact=True)
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

            start_input = self.page.get_by_role("textbox", name="开始时间")
            if start_input.count() > 0:
                start_input.click()
                start_input.press("Control+a")
                start_input.type(start_time, delay=50)
                self.page.wait_for_timeout(100)

            end_input = self.page.get_by_role("textbox", name="结束时间")
            if end_input.count() > 0:
                end_input.click()
                end_input.press("Control+a")
                end_input.type(end_time, delay=50)
                self.page.wait_for_timeout(100)

        except Exception as e:
            print(f"[DEBUG] set_time_by_week error: {e}")
        return self

    def set_time_plan(self, plan_name: str):
        """设置时间计划模式"""
        try:
            radio = self.page.get_by_role("radio", name="时间计划")
            if radio.count() > 0 and not radio.is_checked():
                radio.click()
                self.page.wait_for_timeout(500)

            combobox = self.page.locator('[role="combobox"]').last
            if combobox.count() > 0:
                combobox.click()
                self.page.wait_for_timeout(500)

                option = self.page.get_by_title(plan_name, exact=True)
                if option.count() > 0:
                    option.click()
                    self.page.wait_for_timeout(300)
                    return self

                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] set_time_plan error: {e}")
        return self

    # ==================== 列表操作 ====================
    def copy_rule(self, rule_name: str):
        """点击列表中的复制按钮"""
        self._click_rule_button(rule_name, "复制")
        self.page.wait_for_timeout(1500)
        return self

    # ==================== 添加规则（完整流程）====================
    def add_rule(self, name: str,
                 line: str = "wan1",
                 priority: int = 31,
                 domains: List[str] = None,
                 domain_group: str = None,
                 src_addr: str = None,
                 src_group: str = None,
                 remark: str = None,
                 time_mode: str = None,
                 time_days: List[str] = None,
                 time_start: str = None,
                 time_end: str = None,
                 time_plan: str = None) -> bool:
        """添加域名分流规则

        Args:
            name: 规则名称
            line: 线路
            priority: 优先级(0-63)
            domains: 域名列表
            domain_group: 域名分组名称
            src_addr: 源IP/MAC地址
            src_group: IP/MAC分组名称
            remark: 备注
            time_mode: 生效时间模式
            time_days: 按周循环的星期列表
            time_start: 开始时间
            time_end: 结束时间
            time_plan: 时间计划名称
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

            # 设置优先级
            if priority is not None:
                self.set_priority(priority)

            # 选择线路
            if line:
                print(f"  [add_rule] selecting line={line}")
                self.select_line(line)

            # 域名(逐个添加)
            if domains:
                for domain in domains:
                    print(f"  [add_rule] adding domain={domain}")
                    self.fill_domain(domain)
                    self.page.wait_for_timeout(300)

            # 域名分组
            if domain_group:
                print(f"  [add_rule] selecting domain_group={domain_group}")
                self.select_domain_group(domain_group)

            # 源地址
            if src_addr:
                print(f"  [add_rule] filling src_addr={src_addr}")
                self.fill_src_addr(src_addr)

            # IP/MAC分组
            if src_group:
                print(f"  [add_rule] selecting src_group={src_group}")
                self.select_src_group(src_group)

            # 备注
            if remark:
                print(f"  [add_rule] filling remark={remark}")
                self.fill_remark(remark)

            # 生效时间
            if time_mode == "按周循环":
                print(f"  [add_rule] setting time_by_week")
                self.set_time_by_week(
                    days=time_days,
                    start_time=time_start or "00:00",
                    end_time=time_end or "23:59"
                )
            elif time_mode == "时间计划" and time_plan:
                self.set_time_plan(time_plan)

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
                  priority: int = None, remark: str = None) -> bool:
        """编辑域名分流规则"""
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
            if priority is not None:
                self.set_priority(priority)
            if remark is not None:
                self.fill_remark(remark)

            self.click_save()
            result = self.wait_for_success_message()

            if result:
                self.page.wait_for_timeout(500)
                if "domainFlow" in self.page.url or "diversionStrategy" not in self.page.url:
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
                    if "domainFlow" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            toast_error = self.page.locator('.ant-message-error')
            if toast_error.count() > 0:
                error_text = toast_error.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    if "domainFlow" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            still_on_config = ("domainFlow/add" in self.page.url or
                               "domainFlow/edit" in self.page.url)
            if expect_fail and still_on_config:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "domainFlow" in self.page.url:
                    self.navigate_back_to_list()
                return {"success": True, "error_message": "保存被拒绝(后端验证)"}

            if expect_fail:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "domainFlow" in self.page.url:
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
