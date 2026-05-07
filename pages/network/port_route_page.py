"""
端口分流页面类

处理分流策略 > 端口分流配置的增删改查、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作

数据库字段映射 (从后端脚本stream_ipport.sh确认):
- tagname: 规则名称
- type: 分流方式 0=外网线路 1=下一跳网关
- interface: 逗号分隔的线路(type=0时)
- nexthop: 下一跳网关IP(type=1时)
- iface_band: 线路绑定 0=禁用 1=启用
- prio: 优先级, 整数 0-63, 默认31
- mode: 负载模式 0/1/2/3/4/6 (mode=5已废弃)
- enabled: "yes"/"no"
- protocol: 协议 any/tcp/udp/tcp+udp/icmp
- src_addr_inv: 源地址反向匹配 0/1
- dst_addr_inv: 目的地址反向匹配 0/1
- src_addr: 源IP/MAC分组引用
- dst_addr: 目的IP/MAC分组引用
- src_port: 源端口(json_port_base64格式)
- dst_port: 目的端口(json_port_base64格式)
- dst_type: 目的地址类型 0/1
- time: 生效时间
- comment: 备注

表单下拉框顺序 (实测确认):
[0]分流方式 [1]线路 [2]负载模式 [3]协议 [4]源IP/MAC分组 [5]目的地址类型 [6]目的IP/MAC分组

负载模式选项 (实测确认):
- 新建连接数: mode=0 (默认)
- 源IP: mode=1
- 源IP+源端口: mode=2
- 源IP+目的IP: mode=3
- 源IP+目的IP+目的端口: mode=4
- 主备模式: mode=6

分流方式 (实测确认):
- 外网线路: type=0 (默认, 需选择线路)
- 下一跳网关: type=1 (需填写nexthop IP)
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class PortRoutePage(IkuaiTablePage):
    """端口分流页面操作类"""

    MODULE_NAME = "port_route"
    DIVERSION_STRATEGY_URL = "/login#/networkConfiguration/diversionStrategy"

    # UI负载模式 -> 数据库mode值
    MODE_TO_DB = {
        "新建连接数": "0",
        "源IP": "1",
        "源IP+源端口": "2",
        "源IP+目的IP": "3",
        "源IP+目的IP+目的端口": "4",
        "主备模式": "6",
    }

    # 协议选项
    PROTOCOLS = ["any", "tcp", "udp", "tcp+udp", "icmp"]

    # 排序列映射
    COLUMN_ID_MAP = {
        "线路": "interface",
        "优先级": "prio",
        "协议": "protocol",
    }

    # ==================== 导航 ====================
    def navigate_to_port_route(self):
        """导航到分流策略 > 端口分流页面"""
        url = f"{self.base_url}{self.DIVERSION_STRATEGY_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        tab = self.page.get_by_role("tab", name="端口分流")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_port_route()
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
        """通过combobox role名称定位并点击打开下拉框

        Ant Design Select中combobox input被selection-item span覆盖。
        force=True点击input不会触发dropdown打开。
        解决: 通过xpath找到ant-select-selector容器,点击其中的selection-item。
        """
        sel = self.page.get_by_role("combobox", name=role_name)
        if sel.count() > 0:
            # 定位ant-select-selector容器内的selection-item(可见元素)
            parent = sel.locator('xpath=ancestor::div[contains(@class,"ant-select-selector")]')
            if parent.count() > 0:
                item = parent.first.locator('.ant-select-selection-item')
                if item.count() > 0:
                    item.first.click()
                    self.page.wait_for_timeout(800)
                    return True
            # 备用: 直接点击combobox
            sel.click(force=True)
            self.page.wait_for_timeout(800)
            return True
        return False

    def _get_current_select_value(self, role_name: str) -> str:
        """获取combobox当前选中的值"""
        try:
            sel = self.page.get_by_role("combobox", name=role_name)
            if sel.count() > 0:
                # 获取同一ant-select容器内的selection-item
                parent = sel.locator('xpath=ancestor::div[contains(@class,"ant-select-selector")]')
                item = parent.locator('.ant-select-selection-item')
                if item.count() > 0:
                    return item.first.get_attribute("title") or item.first.text_content().strip()
        except Exception:
            pass
        return ""

    def select_diversion_type(self, div_type: str = "外网线路"):
        """选择分流方式

        Args:
            div_type: "外网线路" 或 "下一跳网关"
        """
        try:
            self._close_any_dropdown()

            current = self._get_current_select_value("分流方式")
            if current == div_type:
                return self

            if self._click_select_by_role("分流方式"):
                if self._select_option_via_js(div_type):
                    self.page.wait_for_timeout(500)
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_diversion_type error: {e}")
        return self

    def select_line(self, line_name: str):
        """选择线路(多选checkbox下拉框)

        仅在分流方式=外网线路时可见。使用线路label附近的combobox定位。

        Args:
            line_name: 线路名称，如 "wan1", "wan2", "全部"
        """
        for attempt in range(3):
            try:
                # 定位线路区域: 通过form-item label "线路" 定位
                line_form_item = self.page.locator('.ant-form-item').filter(has=self.page.locator('[class*="label"]').filter(has_text="线路"))
                if line_form_item.count() > 0:
                    line_sel = line_form_item.first.locator('.ant-select').first
                else:
                    # 备用: 固定nth
                    line_sel = self.page.locator('.ant-select').nth(1)
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

    def fill_nexthop(self, ip: str):
        """填写下一跳网关IP(仅在分流方式=下一跳网关时可见)

        Args:
            ip: 下一跳网关IP地址
        """
        try:
            nexthop_input = self.page.get_by_role("textbox", name="下一跳网关")
            if nexthop_input.count() > 0:
                nexthop_input.click()
                nexthop_input.clear()
                nexthop_input.type(ip, delay=30)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_nexthop error: {e}")
        return self

    def select_load_mode(self, mode: str = "新建连接数"):
        """选择负载模式

        仅在分流方式=外网线路时可见。使用combobox role定位。
        下一跳网关模式下此下拉框不存在, 自动跳过。

        Args:
            mode: 负载模式名称
        """
        try:
            self._close_any_dropdown()

            current = self._get_current_select_value("负载模式")
            if current == mode:
                return self

            if self._click_select_by_role("负载模式"):
                if self._select_option_via_js(mode):
                    self.page.wait_for_timeout(300)
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_load_mode error: {e}")
        return self

    def select_protocol(self, protocol: str = "any"):
        """选择协议(简单下拉框非树形)

        使用combobox role定位, 不依赖固定nth索引。

        Args:
            protocol: 协议名称 any/tcp/udp/tcp+udp/icmp
        """
        try:
            self._close_any_dropdown()

            current = self._get_current_select_value("协议")
            if current == protocol:
                return self

            if self._click_select_by_role("协议"):
                if self._select_option_via_js(protocol):
                    self.page.wait_for_timeout(300)
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_protocol error: {e}")
        return self

    def set_priority(self, priority: int):
        """设置优先级(spinbutton, 范围0-63)"""
        try:
            prio_input = self.page.locator('input#prio')
            if prio_input.count() > 0:
                prio_input.click(force=True)
                prio_input.fill("")
                prio_input.type(str(priority), delay=50)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] set_priority error: {e}")
        return self

    # ==================== 源地址设置 ====================
    def toggle_src_addr_inverse(self, enable: bool = True):
        """设置源地址反向匹配checkbox

        Args:
            enable: True启用反向匹配, False禁用
        """
        try:
            checkbox = self.page.get_by_role('checkbox', name='反向匹配')
            checkboxes = self.page.get_by_role('checkbox', name='反向匹配')
            # 取第一个(源地址区域)
            if checkboxes.count() > 0:
                cb = checkboxes.first
                if enable and not cb.is_checked():
                    cb.click()
                elif not enable and cb.is_checked():
                    cb.click()
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] toggle_src_addr_inverse error: {e}")
        return self

    def fill_src_addr(self, addr: str):
        """填写源地址(IP/MAC内联设置)

        源地址区域的"添加"按钮是表单中第一个名为"添加"的按钮(目的地址的是第二个)。
        点击后在输入框中填写IP/MAC地址, 按Enter确认。

        Args:
            addr: IP地址或MAC地址
        """
        try:
            # 源地址区域的"添加"是第一个, 目的地址的是第二个
            all_add_btns = self.page.get_by_role('button', name='添加')
            if all_add_btns.count() > 0:
                all_add_btns.first.click()
                self.page.wait_for_timeout(500)

            src_input = self.page.get_by_placeholder('请输入IP或MAC')
            if src_input.count() > 0:
                src_input.first.click()
                src_input.first.type(addr, delay=30)
                self.page.wait_for_timeout(200)
                src_input.first.press("Enter")
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] fill_src_addr error: {e}")
        return self

    def select_src_group(self, group_name: str, group_type: str = None):
        """选择源IP/MAC分组(dialog选择)

        使用IP/MAC分组label附近的combobox定位, 不依赖固定nth。

        Args:
            group_name: 分组名称
            group_type: "IP"/"MAC"/None(全部)
        """
        try:
            self._close_any_dropdown()

            # 定位源地址区域的IP/MAC分组combobox
            src_section = self.page.locator('.ant-form-item').filter(has_text="源地址").first
            group_sel = src_section.locator('.ant-select').last
            if group_sel.count() == 0:
                # 备用: 全局定位
                group_sel = self.page.locator('.ant-select').nth(4)
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
                print(f"[WARN] 源IP/MAC分组不存在: {group_name}")
                return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_src_group error: {e}")
        return self

    # ==================== 目的地址设置 ====================
    def select_dst_type(self, dst_type: str = "IP地址"):
        """选择目的地址类型

        使用combobox role定位。

        Args:
            dst_type: 目的地址类型名称
        """
        try:
            self._close_any_dropdown()

            current = self._get_current_select_value("类型")
            if current == dst_type:
                return self

            if self._click_select_by_role("类型"):
                if self._select_option_via_js(dst_type):
                    self.page.wait_for_timeout(300)
                    return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_dst_type error: {e}")
        return self

    def toggle_dst_addr_inverse(self, enable: bool = True):
        """设置目的地址反向匹配checkbox

        Args:
            enable: True启用反向匹配, False禁用
        """
        try:
            checkboxes = self.page.get_by_role('checkbox', name='反向匹配')
            # 取第二个(目的地址区域)
            if checkboxes.count() > 1:
                cb = checkboxes.nth(1)
                if enable and not cb.is_checked():
                    cb.click()
                elif not enable and cb.is_checked():
                    cb.click()
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] toggle_dst_addr_inverse error: {e}")
        return self

    def fill_dst_addr(self, addr: str):
        """填写目的地址(IP/MAC内联设置)

        目的地址区域的"添加"按钮是表单中第二个(源地址是第一个)。

        Args:
            addr: IP地址或MAC地址
        """
        try:
            all_add_btns = self.page.get_by_role('button', name='添加')
            if all_add_btns.count() >= 2:
                all_add_btns.nth(1).click()
                self.page.wait_for_timeout(500)

            dst_input = self.page.get_by_placeholder('请输入IP或MAC')
            if dst_input.count() >= 2:
                dst_input.nth(1).click()
                dst_input.nth(1).type(addr, delay=30)
                self.page.wait_for_timeout(200)
                dst_input.nth(1).press("Enter")
                self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] fill_dst_addr error: {e}")
        return self

    def select_dst_group(self, group_name: str, group_type: str = None):
        """选择目的IP/MAC分组(dialog选择)

        使用目的地址区域的最后一个combobox定位, 不依赖固定nth。

        Args:
            group_name: 分组名称
            group_type: "IP"/"MAC"/None(全部)
        """
        try:
            self._close_any_dropdown()

            # 定位目的地址区域的IP/MAC分组combobox
            dst_section = self.page.locator('.ant-form-item').filter(has_text="目的地址").first
            group_sel = dst_section.locator('.ant-select').last
            if group_sel.count() == 0:
                group_sel = self.page.locator('.ant-select').nth(6)
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
                print(f"[WARN] 目的IP/MAC分组不存在: {group_name}")
                return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_dst_group error: {e}")
        return self

    # ==================== 端口设置 ====================
    def fill_src_port(self, port: str):
        """填写源端口

        Args:
            port: 端口号或端口范围(如 "80" 或 "80-443")
        """
        try:
            src_port_input = self.page.get_by_role("textbox", name="源端口")
            if src_port_input.count() > 0:
                src_port_input.click()
                src_port_input.clear()
                src_port_input.type(port, delay=30)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_src_port error: {e}")
        return self

    def fill_dst_port(self, port: str):
        """填写目的端口

        Args:
            port: 端口号或端口范围(如 "80" 或 "80-443")
        """
        try:
            dst_port_input = self.page.get_by_role("textbox", name="目的端口")
            if dst_port_input.count() > 0:
                dst_port_input.click()
                dst_port_input.clear()
                dst_port_input.type(port, delay=30)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_dst_port error: {e}")
        return self

    # ==================== 线路绑定 ====================
    def toggle_line_binding(self, enable: bool = True):
        """设置线路绑定checkbox"""
        try:
            checkbox = self.page.get_by_role('checkbox', name='线路绑定 启用')
            if checkbox.count() > 0:
                if enable and not checkbox.is_checked():
                    checkbox.click()
                elif not enable and checkbox.is_checked():
                    checkbox.click()
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] toggle_line_binding error: {e}")
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

    def set_time_range(self, start: str, end: str):
        """设置时间段模式"""
        try:
            radio = self.page.get_by_role("radio", name="时间段")
            if radio.count() > 0 and not radio.is_checked():
                radio.click()
                self.page.wait_for_timeout(300)

            start_input = self.page.get_by_role("textbox", name="开始日期")
            if start_input.count() > 0:
                start_input.click()
                start_input.press("Control+a")
                start_input.type(start, delay=30)

            end_input = self.page.get_by_role("textbox", name="结束日期")
            if end_input.count() > 0:
                end_input.click()
                end_input.press("Control+a")
                end_input.type(end, delay=30)
        except Exception as e:
            print(f"[DEBUG] set_time_range error: {e}")
        return self

    # ==================== 列表操作 ====================
    def copy_rule(self, rule_name: str):
        """点击列表中的复制按钮，进入新增页面（预填数据）"""
        self._click_rule_button(rule_name, "复制")
        self.page.wait_for_timeout(1500)
        return self

    # ==================== 添加规则（完整流程）====================
    def add_rule(self, name: str,
                 diversion_type: str = "外网线路",
                 line: str = "wan1",
                 nexthop: str = None,
                 priority: int = 31,
                 mode: str = None,
                 protocol: str = None,
                 remark: str = None,
                 src_addr: str = None,
                 src_addr_inv: bool = None,
                 src_group: str = None,
                 dst_addr: str = None,
                 dst_addr_inv: bool = None,
                 dst_type: str = None,
                 dst_group: str = None,
                 src_port: str = None,
                 dst_port: str = None,
                 line_binding: bool = None,
                 time_mode: str = None,
                 time_days: List[str] = None,
                 time_start: str = None,
                 time_end: str = None,
                 time_plan: str = None) -> bool:
        """添加端口分流规则

        Args:
            name: 规则名称(最多15字符)
            diversion_type: 分流方式 "外网线路" 或 "下一跳网关"
            line: 线路，如 "wan1", "wan1,wan2" (diversion_type=外网线路时)
            nexthop: 下一跳网关IP (diversion_type=下一跳网关时)
            priority: 优先级(0-63)
            mode: 负载模式
            protocol: 协议 any/tcp/udp/tcp+udp/icmp
            remark: 备注
            src_addr: 源地址
            src_addr_inv: 源地址反向匹配
            src_group: 源IP/MAC分组
            dst_addr: 目的地址
            dst_addr_inv: 目的地址反向匹配
            dst_type: 目的地址类型
            dst_group: 目的IP/MAC分组
            src_port: 源端口
            dst_port: 目的端口
            line_binding: 线路绑定
            time_mode: 生效时间模式
            time_days: 按周循环的星期列表
            time_start: 开始时间/日期
            time_end: 结束时间/日期
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

            # 分流方式(决定后续表单结构)
            if diversion_type != "外网线路":
                print(f"  [add_rule] selecting diversion_type={diversion_type}")
                self.select_diversion_type(diversion_type)

            # 设置优先级(先设置不影响下拉框的字段)
            if priority is not None:
                self.set_priority(priority)

            # 分流方式=外网线路时选择线路
            if diversion_type == "外网线路" and line:
                for single_line in line.split(","):
                    print(f"  [add_rule] selecting line={single_line.strip()}")
                    self.select_line(single_line.strip())
                self.page.wait_for_timeout(300)

            # 分流方式=下一跳网关时填写IP
            if diversion_type == "下一跳网关" and nexthop:
                print(f"  [add_rule] filling nexthop={nexthop}")
                self.fill_nexthop(nexthop)

            # 负载模式
            if mode:
                print(f"  [add_rule] selecting mode={mode}")
                self.select_load_mode(mode)

            # 协议
            if protocol:
                print(f"  [add_rule] selecting protocol={protocol}")
                self.select_protocol(protocol)

            # 源地址(先填地址再toggle反向匹配, 反向匹配要求地址不为空)
            if src_addr:
                print(f"  [add_rule] filling src_addr={src_addr}")
                self.fill_src_addr(src_addr)
            if src_addr_inv is not None:
                print(f"  [add_rule] toggling src_addr_inv={src_addr_inv}")
                self.toggle_src_addr_inverse(src_addr_inv)
            if src_group:
                print(f"  [add_rule] selecting src_group={src_group}")
                self.select_src_group(src_group)

            # 目的地址(先填地址再toggle反向匹配)
            if dst_type:
                print(f"  [add_rule] selecting dst_type={dst_type}")
                self.select_dst_type(dst_type)
            if dst_addr:
                print(f"  [add_rule] filling dst_addr={dst_addr}")
                self.fill_dst_addr(dst_addr)
            if dst_addr_inv is not None:
                print(f"  [add_rule] toggling dst_addr_inv={dst_addr_inv}")
                self.toggle_dst_addr_inverse(dst_addr_inv)
            if dst_group:
                print(f"  [add_rule] selecting dst_group={dst_group}")
                self.select_dst_group(dst_group)

            # 端口
            if src_port:
                print(f"  [add_rule] filling src_port={src_port}")
                self.fill_src_port(src_port)
            if dst_port:
                print(f"  [add_rule] filling dst_port={dst_port}")
                self.fill_dst_port(dst_port)

            # 线路绑定
            if line_binding is not None:
                print(f"  [add_rule] toggling line_binding={line_binding}")
                self.toggle_line_binding(line_binding)

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
            elif time_mode == "时间段" and time_start and time_end:
                self.set_time_range(time_start, time_end)

            print(f"  [add_rule] clicking save... (current URL: {self.page.url})")
            self.click_save()

            self.page.wait_for_timeout(1500)

            # 检查是否还在添加页面
            current_url = self.page.url
            print(f"  [add_rule] after save URL: {current_url}")

            # 检查多种form error样式
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

            # 如果还在add页面, 用JS收集所有可能的错误提示
            if "/add" in current_url or "/edit" in current_url:
                js_errors = self.page.evaluate("""() => {
                    const errors = [];
                    // 查找所有可能的错误元素
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
                    // 查找input的错误状态
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
                  priority: int = None, mode: str = None,
                  protocol: str = None, remark: str = None) -> bool:
        """编辑端口分流规则"""
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
            if mode:
                self.select_load_mode(mode)
            if protocol:
                self.select_protocol(protocol)
            if remark is not None:
                self.fill_remark(remark)

            self.click_save()
            result = self.wait_for_success_message()

            if result:
                self.page.wait_for_timeout(500)
                if "portFlow" in self.page.url or "diversionStrategy" not in self.page.url:
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
                    if "portFlow" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            toast_error = self.page.locator('.ant-message-error')
            if toast_error.count() > 0:
                error_text = toast_error.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    if "portFlow" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            still_on_config = ("portFlow/add" in self.page.url or
                               "portFlow/edit" in self.page.url)
            if expect_fail and still_on_config:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "portFlow" in self.page.url:
                    self.navigate_back_to_list()
                return {"success": True, "error_message": "保存被拒绝(后端验证)"}

            if expect_fail:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "portFlow" in self.page.url:
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
