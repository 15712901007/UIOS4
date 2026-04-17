"""
协议分流页面类

处理分流策略 > 协议分流配置的增删改查、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作

数据库字段映射 (实测确认):
- tagname: 规则名称
- interface: 逗号分隔的线路, 如 "wan1,wan2"
- prio: 优先级, 整数 0-63, 默认31
- mode: 负载模式 0/1/3
- enabled: "yes"/"no"
- comment: 备注
- proto: 协议标识
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, Dict, List


class ProtocolRoutePage(IkuaiTablePage):
    """协议分流页面操作类"""

    MODULE_NAME = "protocol_route"
    DIVERSION_STRATEGY_URL = "/login#/networkConfiguration/diversionStrategy"

    # 负载模式选项
    LOAD_MODES = [
        "新建连接数",      # mode=0 (默认)
        "源IP",           # mode=1
        "源IP+目的IP",    # mode=2
    ]

    # UI负载模式 -> 数据库mode值 (实测确认)
    MODE_TO_DB = {
        "新建连接数": "0",
        "源IP": "1",
        "源IP+目的IP": "3",
    }

    # 排序列映射 (与实际th#id一致)
    COLUMN_ID_MAP = {
        "线路": "interface",
        "优先级": "prio",
    }

    # ==================== 导航 ====================
    def navigate_to_protocol_route(self):
        """导航到分流策略 > 协议分流页面"""
        url = f"{self.base_url}{self.DIVERSION_STRATEGY_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        # 点击"协议分流"tab
        tab = self.page.get_by_role("tab", name="协议分流")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_protocol_route()
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

    def select_line(self, line_name: str):
        """选择线路(多选checkbox下拉框)

        点击.ant-select打开dropdown, 然后点击checkbox的wrapper元素选择线路。
        使用force=True和多种策略应对间歇性问题。

        Args:
            line_name: 线路名称，如 "wan1", "wan2", "全部"
        """
        for attempt in range(3):
            try:
                # 确保下拉框已就绪
                line_sel = self.page.locator('.ant-select').nth(0)
                line_sel.wait_for(state="visible", timeout=5000)

                # 打开下拉框
                line_sel.click()
                self.page.wait_for_timeout(1000)

                # 策略1: 点击checkbox wrapper (force=True)
                wrapper = self.page.locator('.ant-checkbox-wrapper').filter(has_text=line_name)
                if wrapper.count() > 0:
                    wrapper.first.click(force=True)
                    self.page.wait_for_timeout(500)

                # 策略2: 如果策略1不成功, 用checkbox role
                if self.page.locator('.ant-select-selection-item').count() == 0:
                    checkbox = self.page.get_by_role('checkbox', name=line_name)
                    if checkbox.count() > 0:
                        checkbox.click(force=True)
                        self.page.wait_for_timeout(500)

                # 验证
                if self.page.locator('.ant-select-selection-item').count() > 0:
                    break

                # 关闭重试
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(500)
            except Exception as e:
                print(f"[DEBUG] select_line({line_name}) attempt {attempt+1}: {e}")
                try:
                    self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(300)
                except Exception:
                    pass

        # 关闭下拉框
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception:
            pass
        return self

    def set_priority(self, priority: int):
        """设置优先级(spinbutton, 范围0-63)

        使用force=True解决overlay拦截问题
        """
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

    def select_load_mode(self, mode: str = "新建连接数"):
        """选择负载模式(第2个.ant-select, nth(1))

        Args:
            mode: 负载模式名称
        """
        try:
            self._close_any_dropdown()

            # 检查当前值是否已经是目标值
            mode_sel = self.page.locator('.ant-select').nth(1)
            current_value = mode_sel.locator('.ant-select-selection-item')
            if current_value.count() > 0:
                current_text = current_value.first.get_attribute("title") or current_value.first.text_content().strip()
                if current_text == mode:
                    return self

            # 点击下拉框
            mode_sel.locator('.ant-select-selector').first.click()
            self.page.wait_for_timeout(800)

            # 通过JS选择可见下拉框中的选项
            if self._select_option_via_js(mode):
                self.page.wait_for_timeout(300)
                return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_load_mode error: {e}")
        return self

    # 协议树形路径映射: 协议名 -> 需要展开的父节点路径
    PROTO_TREE_PATH = {
        "DNS": ["网络协议", "基础协议"],
        "NTP": ["网络协议", "基础协议"],
        "ICMP": ["网络协议", "基础协议"],
        "网页浏览": ["网络协议", "基础协议"],
        "HTTPS": ["网络协议", "基础协议"],
        "HTTP": ["网络协议", "基础协议"],
        "QUIC": ["网络协议", "基础协议"],
        "SNMP": ["网络协议", "基础协议"],
    }

    def select_protocol(self, proto_name: str):
        """选择协议(树形对话框)

        协议选择器打开后弹出树形modal dialog。
        使用Playwright逐个展开树节点(每次展开后等待DOM更新), 再用JS选择叶节点。
        JS click对.ant-tree-checkbox有效(与Ant Design Select不同)。

        Args:
            proto_name: 协议名称，如 "DNS", "网页浏览", "HTTPS", "NTP"
        """
        try:
            self._close_any_dropdown()

            # 点击协议选择器 - 尝试多种点击方式
            proto_sel = self.page.locator('.ant-select').nth(2)

            # 方法1: 点击selector
            proto_sel.locator('.ant-select-selector').first.click(force=True)
            self.page.wait_for_timeout(1000)

            # 检查dialog是否出现
            dialog = self.page.locator('[role="dialog"]')
            if dialog.count() == 0:
                # 方法2: 直接点击整个select
                proto_sel.click(force=True)
                self.page.wait_for_timeout(1000)

            if dialog.count() == 0:
                # 方法3: 点击combobox input
                proto_sel.locator('input[role="combobox"]').click(force=True)
                self.page.wait_for_timeout(1000)

            if dialog.count() == 0:
                print(f"[DEBUG] select_protocol({proto_name}): dialog未出现")
                return self

            # 逐个展开树节点路径(每次展开后等待React重渲染)
            expand_path = self.PROTO_TREE_PATH.get(proto_name, [])
            for parent_name in expand_path:
                self._expand_tree_node(parent_name)
                self.page.wait_for_timeout(600)

            # 用JS选择协议叶节点
            result = self.page.evaluate("""(protoName) => {
                const items = document.querySelectorAll('.ant-tree-treenode');
                for (let i = items.length - 1; i >= 0; i--) {
                    const item = items[i];
                    const titleEls = item.querySelectorAll('.ant-tree-title, .ant-tree-node-content-wrapper');
                    for (const te of titleEls) {
                        if (te.textContent.trim() === protoName) {
                            const cb = item.querySelector('.ant-tree-checkbox');
                            if (cb) {
                                cb.click();
                                return 'ok: ' + protoName;
                            }
                        }
                    }
                }
                return 'not_found: ' + protoName;
            }""", proto_name)
            print(f"[DEBUG] select_protocol({proto_name}): {result}")
            self.page.wait_for_timeout(500)

            # 点击确定按钮关闭modal
            confirm = self.page.locator('button:has-text("确定")')
            clicked_confirm = False
            for i in range(confirm.count()):
                btn = confirm.nth(i)
                if btn.is_visible():
                    btn.click(force=True)
                    clicked_confirm = True
                    break
            if not clicked_confirm:
                self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(800)
        except Exception as e:
            print(f"[DEBUG] select_protocol error: {e}")
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(300)
            except Exception:
                pass
        return self

    def _expand_tree_node(self, node_title: str):
        """展开指定标题的树节点

        在当前可见的树中查找标题精确匹配的节点,
        如果是折叠状态则点击展开图标。

        Args:
            node_title: 节点标题文本
        """
        try:
            nodes = self.page.locator('.ant-tree-treenode')
            for i in range(nodes.count()):
                node = nodes.nth(i)
                # 获取节点的标题文本
                title_el = node.locator('.ant-tree-title, .ant-tree-node-content-wrapper')
                if title_el.count() > 0:
                    text = title_el.first.text_content().strip()
                    if text == node_title:
                        switcher = node.locator('.ant-tree-switcher_close')
                        if switcher.count() > 0:
                            switcher.first.click()
                            self.page.wait_for_timeout(500)
                        return
        except Exception as e:
            print(f"[DEBUG] _expand_tree_node({node_title}) error: {e}")

    def select_proto_group(self, group_name: str):
        """选择协议分组(打开dialog勾选checkbox)

        协议分组选择器打开dialog(非简单dropdown)。
        在dialog中勾选对应分组的checkbox，然后点确定。

        Args:
            group_name: 协议分组名称
        """
        try:
            self._close_any_dropdown()

            # 点击协议分组选择器(第4个.ant-select, nth(3))
            group_sel = self.page.locator('.ant-select').nth(3)
            group_sel.locator('.ant-select-selector').first.click()
            self.page.wait_for_timeout(1000)

            # 在dialog中选择分组checkbox
            dialog = self.page.locator('[role="dialog"]').last
            if dialog.is_visible():
                # 先尝试精确匹配checkbox
                checkbox = dialog.locator('.ant-checkbox-wrapper').filter(has_text=group_name)
                if checkbox.count() > 0:
                    checkbox.first.click(force=True)
                    self.page.wait_for_timeout(300)

                    # 点击确定
                    confirm = dialog.get_by_role('button', name='确定')
                    if confirm.count() > 0 and confirm.is_visible():
                        confirm.click()
                        self.page.wait_for_timeout(500)
                        return self

                # 分组不存在，关闭dialog
                cancel = dialog.get_by_role('button', name='取消')
                if cancel.count() > 0 and cancel.is_visible():
                    cancel.click()
                    self.page.wait_for_timeout(300)
                print(f"[WARN] 协议分组不存在: {group_name}")
                return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_proto_group error: {e}")
        return self

    def select_ip_mac_group(self, group_name: str, group_type: str = None):
        """选择IP/MAC分组(打开dialog勾选checkbox)

        IP/MAC分组选择器打开dialog，带segmented control(全部/IP/MAC)。
        在dialog中勾选对应分组的checkbox，然后点确定。

        Args:
            group_name: IP/MAC分组名称
            group_type: 分组类型过滤 "IP"/"MAC"/None(全部)
        """
        try:
            self._close_any_dropdown()

            # 点击IP/MAC分组选择器(第5个.ant-select, nth(4))
            group_sel = self.page.locator('.ant-select').nth(4)
            group_sel.locator('.ant-select-selector').first.click()
            self.page.wait_for_timeout(1000)

            # 在dialog中选择分组
            dialog = self.page.locator('[role="dialog"]').last
            if dialog.is_visible():
                # 可选：按类型过滤
                if group_type:
                    type_radio = dialog.get_by_role("radio", name=group_type)
                    if type_radio.count() > 0:
                        type_radio.click()
                        self.page.wait_for_timeout(300)

                # 精确匹配checkbox（截断名称也支持）
                checkbox = dialog.locator('.ant-checkbox-wrapper').filter(has_text=group_name)
                if checkbox.count() > 0:
                    checkbox.first.click(force=True)
                    self.page.wait_for_timeout(300)

                    # 点击确定
                    confirm = dialog.get_by_role('button', name='确定')
                    if confirm.count() > 0 and confirm.is_visible():
                        confirm.click()
                        self.page.wait_for_timeout(500)
                        return self

                # 分组不存在，关闭dialog
                cancel = dialog.get_by_role('button', name='取消')
                if cancel.count() > 0 and cancel.is_visible():
                    cancel.click()
                    self.page.wait_for_timeout(300)
                print(f"[WARN] IP/MAC分组不存在: {group_name}")
                return self

            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_ip_mac_group error: {e}")
        return self

    def toggle_line_binding(self, enable: bool = True):
        """设置线路绑定checkbox

        使用精确的'线路绑定 启用'选择器避免匹配到其他checkbox。

        Args:
            enable: True启用, False不启用
        """
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
            # 备用选择器
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
        """设置按周循环的生效时间

        协议分流的星期选择使用可点击标签(非checkbox)。
        先确保"按周循环"radio选中，再设置日期和时间。

        Args:
            days: 星期列表，如 ["一","二","三","四","五"]。None=保持默认全选
            start_time: 开始时间 HH:MM
            end_time: 结束时间 HH:MM
        """
        try:
            # 确保在"按周循环"模式
            radio = self.page.get_by_role("radio", name="按周循环")
            if radio.count() > 0 and not radio.is_checked():
                radio.click()
                self.page.wait_for_timeout(300)

            # 设置星期 — 协议分流使用可点击标签，点击切换选中/未选中
            if days is not None:
                all_days = ["一", "二", "三", "四", "五", "六", "日"]
                for day_text in all_days:
                    # 在生效时间区域内精确匹配
                    day_el = self.page.get_by_text(day_text, exact=True)
                    if day_el.count() > 0:
                        # 通过JS判断当前选中状态
                        is_active = day_el.first.evaluate(
                            'el => el.classList.contains("ant-tag-checkable-checked")'
                            ' || el.parentElement.classList.contains("ant-tag-checkable-checked")'
                            ' || el.classList.contains("active")'
                        )
                        should_select = day_text in days
                        if should_select != is_active:
                            day_el.first.click()
                            self.page.wait_for_timeout(100)

            # 设置开始/结束时间 — 使用press+type触发onChange
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
        """设置时间计划模式

        切换到"时间计划"radio，然后从combobox中选择预设计划。

        Args:
            plan_name: 时间计划名称
        """
        try:
            radio = self.page.get_by_role("radio", name="时间计划")
            if radio.count() > 0 and not radio.is_checked():
                radio.click()
                self.page.wait_for_timeout(500)

            # 时间计划的combobox
            combobox = self.page.locator('[role="combobox"]').last
            if combobox.count() > 0:
                combobox.click()
                self.page.wait_for_timeout(500)

                option = self.page.get_by_title(plan_name, exact=True)
                if option.count() > 0:
                    option.click()
                    self.page.wait_for_timeout(300)
                    return self

                # 未找到选项，关闭下拉
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] set_time_plan error: {e}")
        return self

    def set_time_range(self, start: str, end: str):
        """设置时间段模式

        切换到"时间段"radio，设置起止日期时间。

        Args:
            start: 开始日期时间 "2026-04-17 00:00"
            end: 结束日期时间 "2026-04-17 23:59"
        """
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
        """点击列表中的复制按钮，进入新增页面（预填数据）

        Args:
            rule_name: 要复制的规则名称
        """
        self._click_rule_button(rule_name, "复制")
        self.page.wait_for_timeout(1500)
        return self

    # ==================== 添加规则（完整流程）====================
    def add_rule(self, name: str, line: str = "wan1",
                 priority: int = 31, mode: str = None,
                 proto: str = None, remark: str = None,
                 proto_group: str = None, ip_mac_group: str = None,
                 line_binding: bool = None,
                 time_mode: str = None, time_days: List[str] = None,
                 time_start: str = None, time_end: str = None,
                 time_plan: str = None) -> bool:
        """添加协议分流规则

        Args:
            name: 规则名称(最多15字符)
            line: 线路，如 "wan1", "wan1,wan2"
            priority: 优先级(0-63)
            mode: 负载模式
            proto: 协议名称
            remark: 备注
            proto_group: 协议分组
            ip_mac_group: IP/MAC分组
            line_binding: 线路绑定
            time_mode: 生效时间模式 "按周循环"/"时间计划"/"时间段"
            time_days: 按周循环的星期列表
            time_start: 开始时间/日期
            time_end: 结束时间/日期
            time_plan: 时间计划名称(time_mode="时间计划"时使用)
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)

            # 等待添加页面加载完成 - 等待名称输入框出现
            try:
                self.page.wait_for_selector('input[placeholder="请输入名称"]', timeout=10000)
            except Exception:
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(1000)
            self.page.wait_for_timeout(500)

            self.fill_name(name)

            # 设置优先级(先设置不影响下拉框的字段)
            if priority is not None:
                self.set_priority(priority)

            # 负载模式
            if mode:
                self.select_load_mode(mode)

            # 选择线路(支持多线路逗号分隔, 放在priority之后确保表单已稳定)
            if line:
                for single_line in line.split(","):
                    self.select_line(single_line.strip())
                self.page.wait_for_timeout(300)

            # 线路绑定
            if line_binding is not None:
                self.toggle_line_binding(line_binding)

            # 协议(树形对话框) - 必填字段
            if proto:
                self.select_protocol(proto)

            # 协议分组
            if proto_group:
                self.select_proto_group(proto_group)

            # IP/MAC分组
            if ip_mac_group:
                self.select_ip_mac_group(ip_mac_group)

            # 备注
            if remark:
                self.fill_remark(remark)

            # 生效时间
            if time_mode == "按周循环":
                self.set_time_by_week(
                    days=time_days,
                    start_time=time_start or "00:00",
                    end_time=time_end or "23:59"
                )
            elif time_mode == "时间计划" and time_plan:
                self.set_time_plan(time_plan)
            elif time_mode == "时间段" and time_start and time_end:
                self.set_time_range(time_start, time_end)

            self.click_save()

            # 检查是否有表单验证错误
            self.page.wait_for_timeout(1500)
            error_el = self.page.locator('.ant-form-item-explain-error')
            if error_el.count() > 0:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                self.navigate_back_to_list()
                return False

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
                  line: str = None, priority: int = None,
                  mode: str = None, proto: str = None,
                  remark: str = None) -> bool:
        """编辑协议分流规则

        Args:
            old_name: 当前规则名称
            new_name: 新名称(可选)
            line: 新线路(可选)
            priority: 新优先级(可选)
            mode: 新负载模式(可选)
            proto: 新协议(可选)
            remark: 新备注(可选，传空字符串清空)
        """
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
            if line:
                for single_line in line.split(","):
                    self.select_line(single_line.strip())
            if priority is not None:
                self.set_priority(priority)
            if mode:
                self.select_load_mode(mode)
            if proto:
                self.select_protocol(proto)
            if remark is not None:
                self.fill_remark(remark)

            self.click_save()
            result = self.wait_for_success_message()

            if result:
                self.page.wait_for_timeout(500)
                if "protocolDiversion" in self.page.url or "diversionStrategy" not in self.page.url:
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
        """尝试添加无效规则，测试表单验证

        Args:
            name: 规则名称
            expect_fail: 是否预期失败

        Returns:
            {"success": bool, "error_message": str}
        """
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
                    if "protocolDiversion" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            toast_error = self.page.locator('.ant-message-error')
            if toast_error.count() > 0:
                error_text = toast_error.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    if "protocolDiversion" in self.page.url:
                        self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            # 检查是否仍在配置页面（保存被拒绝）
            still_on_config = ("protocolDiversion/add" in self.page.url or
                               "protocolDiversion/edit" in self.page.url)
            if expect_fail and still_on_config:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "protocolDiversion" in self.page.url:
                    self.navigate_back_to_list()
                return {"success": True, "error_message": "保存被拒绝(后端验证)"}

            if expect_fail:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                if "protocolDiversion" in self.page.url:
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
