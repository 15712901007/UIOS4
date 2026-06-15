"""
NAT规则页面类

处理网络配置 > UPnP/NAT > NAT规则 tab的增删改查、导入导出、设置面板等操作
继承 IkuaiTablePage 获取通用表格操作

实测表单结构 (2026-06-11):
- 表单标签: 名称*|动作|进接口|出接口|IP设置(源)|IP分组(源)|IP设置(目)|IP分组(目)|协议|端口设置(源)|端口分组(源)|端口设置(目)|端口分组(目)|NAT地址|备注
- 第1个"IP设置"=源地址, 第2个"IP设置"=目的地址
- 第1个"端口设置"=源端口, 第2个"端口设置"=目的端口 (协议≠任意时出现)
- 反向匹配checkbox: id=src_addr_inv(源), id=dst_addr_inv(目)
- NAT地址: id=nat_addr (snat/dnat时出现)
- 协议≠任意时显示端口设置区域

数据库字段映射 (从后端脚本nat_rule.sh确认):
- nat_rule表:
  id, enabled(yes/no), tagname(名称), comment(备注),
  ointerface(出接口), iinterface(进接口),
  src_addr(源地址,base64 JSON), src_addr_inv(源地址取反 0/1),
  dst_addr(目的地址,base64 JSON), dst_addr_inv(目的地址取反 0/1),
  nat_addr(NAT地址,plain IP), nat_port(NAT端口),
  protocol(协议 any/tcp/udp/tcp+udp),
  src_port(源端口,base64 JSON), dst_port(目的端口,base64 JSON),
  action(动作 filter/snat/dnat)

页面结构:
- URL: /login#/networkConfiguration/upnpNat (NAT规则是第3个tab)
- 表格列: 名称|动作|出接口|进接口|源地址|目的地址|源端口|目的端口|NAT地址|NAT端口|协议|备注|操作
- 工具栏: 搜索+添加+导入+导出
- 行内按钮: 编辑/停用(启用)/删除 (无复制按钮)
- 右上角齿轮按钮: 打开设置面板(aside.ant-layout-sider), 含"本地转发自动NAT(相同LAN)"开关
- 添加/编辑表单: 独立页面(natRules/add, natRules/edit/<id>), 非弹窗

动作类型与条件字段:
- 过滤(filter): 出接口✓ NAT地址✗ NAT端口✗
- 源地址NAT(snat): 出接口✓ NAT地址✓(可选) NAT端口✗
- 目的地址NAT(dnat): 出接口✗(隐藏) NAT地址✓(必填) NAT端口✓(可选)

协议条件字段:
- 任意(any): 源端口✗ 目的端口✗
- tcp/udp/tcp+udp: 源端口✓ 目的端口✓
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class NatRulePage(IkuaiTablePage):
    """NAT规则页面操作类"""

    MODULE_NAME = "nat_rule"
    UPNP_NAT_URL = "/login#/networkConfiguration/upnpNat"
    NAT_RULE_ADD_URL = "/login#/networkConfiguration/upnpNat/natRules/add"

    # 动作类型 UI标签 -> DB值
    ACTION_MAP = {
        "过滤": "filter",
        "源地址NAT": "snat",
        "目的地址NAT": "dnat",
    }

    # 排序列映射
    COLUMN_ID_MAP = {
        "动作": "action",
        "出接口": "ointerface",
        "进接口": "iinterface",
        "协议": "protocol",
    }

    # ==================== 导航 ====================

    def navigate_to_nat_rule(self):
        """导航到UPnP/NAT > NAT规则页面"""
        url = f"{self.base_url}{self.UPNP_NAT_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        # 点击NAT规则 tab (第3个tab)
        tab = self.page.get_by_role("tab", name="NAT规则")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_nat_rule()
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

    def _find_form_item_by_label(self, label_text: str, index: int = 0):
        """通过label文字查找第N个ant-form-item

        Args:
            label_text: label文字, 如 "动作", "IP设置", "端口设置"
            index: 同名label中取第几个(0-based)
        """
        items = self.page.locator('.ant-form-item')
        count = 0
        for i in range(items.count()):
            item = items.nth(i)
            label = item.locator('.ant-form-item-label')
            if label.count() > 0 and label_text in label.first.text_content():
                if count == index:
                    return item
                count += 1
        return None

    def _click_select_in_form_item(self, form_item, selector_str: str = '.ant-select-selector'):
        """在form-item内点击select下拉框"""
        if form_item is None:
            return False
        sel = form_item.locator(selector_str)
        if sel.count() > 0:
            sel.first.click(force=True)
            self.page.wait_for_timeout(800)
            return True
        return False

    def _select_dropdown_option(self, option_text: str) -> bool:
        """在已打开的下拉框中选择选项"""
        # 策略1: 按title属性匹配
        option = self.page.locator(f'.ant-select-item-option[title="{option_text}"]')
        for i in range(option.count()):
            if option.nth(i).is_visible():
                option.nth(i).click()
                self.page.wait_for_timeout(500)
                return True

        # 策略2: 按文字匹配
        items = self.page.locator('.ant-select-item-option')
        for i in range(items.count()):
            item = items.nth(i)
            if item.is_visible() and item.text_content().strip() == option_text:
                item.click()
                self.page.wait_for_timeout(500)
                return True

        # 策略3: JS click
        return self._select_option_via_js(option_text)

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
            if clicked:
                self.page.wait_for_timeout(500)
            return bool(clicked)
        except Exception:
            return False

    # ==================== 表单基础字段 ====================

    def fill_name(self, name: str):
        """填写规则名称 (id=tagname)"""
        name_input = self.page.locator('#tagname')
        if name_input.count() > 0:
            name_input.click()
            name_input.fill(name)
            self.page.wait_for_timeout(200)
        return self

    def select_action(self, action: str = "过滤"):
        """选择动作类型(过滤/源地址NAT/目的地址NAT)

        动作类型决定后续表单字段的显隐, 必须在填写条件字段之前调用。
        """
        try:
            self._close_any_dropdown()

            # 检查当前值
            form_item = self._find_form_item_by_label("动作")
            if form_item is None:
                return self

            # 检查当前选中值
            current_text = form_item.locator('.ant-select-selection-item')
            if current_text.count() > 0:
                current_val = current_text.first.text_content().strip()
                if current_val == action:
                    return self

            # 点击打开下拉框
            self._click_select_in_form_item(form_item)
            self.page.wait_for_timeout(800)

            # 选择选项
            self._select_dropdown_option(action)
            self.page.wait_for_timeout(500)
            self._close_any_dropdown()

        except Exception as e:
            print(f"[DEBUG] select_action error: {e}")
        return self

    def select_protocol(self, protocol: str = "任意"):
        """选择协议(任意/tcp/udp/tcp+udp)

        协议决定端口字段的显隐, 必须在填写端口之前调用。
        """
        try:
            self._close_any_dropdown()

            form_item = self._find_form_item_by_label("协议")
            if form_item is None:
                return self

            current_text = form_item.locator('.ant-select-selection-item')
            if current_text.count() > 0:
                current_val = current_text.first.text_content().strip()
                if current_val == protocol:
                    return self

            self._click_select_in_form_item(form_item)
            self.page.wait_for_timeout(800)
            self._select_dropdown_option(protocol)
            self.page.wait_for_timeout(500)
            self._close_any_dropdown()

        except Exception as e:
            print(f"[DEBUG] select_protocol error: {e}")
        return self

    def fill_remark(self, remark: str):
        """填写备注 (id=comment)"""
        try:
            remark_input = self.page.locator('#comment')
            if remark_input.count() > 0:
                remark_input.click()
                remark_input.fill(remark)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_remark error: {e}")
        return self

    # ==================== 接口选择(多选checkbox下拉框) ====================

    def _select_interface(self, label: str, interface_name: str):
        """通用接口选择方法

        进接口/出接口都是多选checkbox下拉框。
        label: "进接口" 或 "出接口"
        """
        for attempt in range(3):
            try:
                self._close_any_dropdown()

                form_item = self._find_form_item_by_label(label)
                if form_item is None:
                    print(f"  [WARN] _select_interface: '{label}' form-item not found")
                    break

                self._click_select_in_form_item(form_item)
                self.page.wait_for_timeout(1000)

                # 策略1: title属性匹配
                option = self.page.locator(f'.ant-select-item-option[title="{interface_name}"]')
                if option.count() > 0:
                    for i in range(option.count()):
                        opt = option.nth(i)
                        if opt.is_visible():
                            opt.click()
                            self.page.wait_for_timeout(500)
                            return self

                # 策略2: checkbox wrapper
                wrapper = self.page.locator('.ant-checkbox-wrapper').filter(has_text=interface_name)
                for i in range(wrapper.count()):
                    w = wrapper.nth(i)
                    if w.is_visible():
                        w.click(force=True)
                        self.page.wait_for_timeout(500)
                        return self

                # 策略3: 文字匹配
                all_items = self.page.locator('.ant-select-item-option')
                for i in range(all_items.count()):
                    item = all_items.nth(i)
                    if item.is_visible() and interface_name in item.text_content():
                        item.click()
                        self.page.wait_for_timeout(500)
                        return self

                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(500)
            except Exception as e:
                print(f"  [DEBUG] _select_interface({label},{interface_name}) attempt {attempt+1}: {e}")
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

    def select_inbound_interface(self, interface_name: str):
        """选择进接口(多选checkbox下拉框)"""
        return self._select_interface("进接口", interface_name)

    def select_outbound_interface(self, interface_name: str):
        """选择出接口(多选checkbox下拉框, dnat时隐藏)"""
        return self._select_interface("出接口", interface_name)

    def select_inbound_interfaces(self, interfaces: List[str]):
        """选择多个进接口"""
        for iface in interfaces:
            self.select_inbound_interface(iface)
            self.page.wait_for_timeout(300)
        return self

    def select_outbound_interfaces(self, interfaces: List[str]):
        """选择多个出接口"""
        for iface in interfaces:
            self.select_outbound_interface(iface)
            self.page.wait_for_timeout(300)
        return self

    # ==================== IP地址设置 ====================

    def _click_ip_batch_button(self, index: int):
        """点击第N个IP设置区域的"批量"按钮"""
        form_item = self._find_form_item_by_label("IP设置", index=index)
        if form_item is not None:
            batch_btn = form_item.locator('button').filter(has_text="批量")
            if batch_btn.count() > 0:
                batch_btn.first.click()
                self.page.wait_for_timeout(800)
                return True
        return False

    def _fill_value_in_form_item(self, label: str, label_index: int,
                                  value: str, input_placeholder_keyword: str):
        """在指定form-item内: 点击添加按钮, 在出现的输入框中输入值

        Args:
            label: form-item的label文字("IP设置"/"端口设置")
            label_index: 第N个同名label(0-based)
            value: 要输入的值
            input_placeholder_keyword: 输入框placeholder包含的关键字("IP"/"端口")
        """
        try:
            form_item = self._find_form_item_by_label(label, index=label_index)
            if form_item is None:
                print(f"    [WARN] _fill_value: '{label}'[{label_index}] not found")
                return False

            # 点击"添加"按钮
            add_btn = form_item.locator('button').filter(has_text="添加")
            if add_btn.count() > 0:
                add_btn.first.click()
                self.page.wait_for_timeout(800)

            # 在该form-item内查找出现的输入框
            all_inputs = form_item.locator('input')
            for i in range(all_inputs.count()):
                inp = all_inputs.nth(i)
                ph = inp.get_attribute("placeholder") or ""
                if input_placeholder_keyword in ph and inp.is_visible():
                    inp.click()
                    self.page.wait_for_timeout(200)
                    inp.type(value, delay=30)
                    self.page.wait_for_timeout(300)
                    print(f"    [_fill_value] {label}[{label_index}] typed {value}")
                    return True

            # Fallback: 用ID前缀匹配 (在该form-item内)
            if input_placeholder_keyword == "IP":
                id_prefix = "src_addr" if label_index == 0 else "dst_addr"
            else:
                id_prefix = "src_port" if label_index == 0 else "dst_port"
            fb_inputs = form_item.locator(f'input[id^="{id_prefix}_custom"]')
            for i in range(fb_inputs.count()):
                inp = fb_inputs.nth(i)
                if inp.is_visible():
                    inp.click()
                    self.page.wait_for_timeout(200)
                    inp.type(value, delay=30)
                    self.page.wait_for_timeout(300)
                    print(f"    [_fill_value] fallback {label}[{label_index}] typed {value}")
                    return True

            print(f"    [WARN] _fill_value: no input in {label}[{label_index}]")
        except Exception as e:
            print(f"  [DEBUG] _fill_value error: {e}")
        return False

    def fill_src_addr(self, addr: str):
        """填写源地址(逐条添加) - 第1个"IP设置"区域"""
        self._fill_value_in_form_item("IP设置", 0, addr, "IP")
        return self

    def fill_dst_addr(self, addr: str):
        """填写目的地址(逐条添加) - 第2个"IP设置"区域"""
        self._fill_value_in_form_item("IP设置", 1, addr, "IP")
        return self

    def fill_src_addr_batch(self, ips: List[str]):
        """批量添加源地址"""
        try:
            self._click_ip_batch_button(index=0)
            self.page.wait_for_timeout(500)
            textarea = self.page.locator('textarea').filter(has_text="")
            visible = [i for i in range(textarea.count()) if textarea.nth(i).is_visible()]
            if visible:
                ta = textarea.nth(visible[0])
                ta.click()
                ta.fill("\n".join(ips))
                self.page.wait_for_timeout(300)
                ta.press("Enter")
                self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] fill_src_addr_batch error: {e}")
        return self

    def fill_dst_addr_batch(self, ips: List[str]):
        """批量添加目的地址"""
        try:
            self._click_ip_batch_button(index=1)
            self.page.wait_for_timeout(500)
            textarea = self.page.locator('textarea').filter(has_text="")
            visible = [i for i in range(textarea.count()) if textarea.nth(i).is_visible()]
            if visible:
                ta = textarea.nth(visible[0])
                ta.click()
                ta.fill("\n".join(ips))
                self.page.wait_for_timeout(300)
                ta.press("Enter")
                self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] fill_dst_addr_batch error: {e}")
        return self

    def toggle_src_addr_inverse(self, enable: bool = True):
        """设置源地址反向匹配checkbox (id=src_addr_inv)"""
        try:
            cb = self.page.locator('#src_addr_inv')
            if cb.count() > 0:
                is_checked = cb.is_checked()
                if enable and not is_checked:
                    cb.click(force=True)
                elif not enable and is_checked:
                    cb.click(force=True)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] toggle_src_addr_inverse error: {e}")
        return self

    def toggle_dst_addr_inverse(self, enable: bool = True):
        """设置目的地址反向匹配checkbox (id=dst_addr_inv)"""
        try:
            cb = self.page.locator('#dst_addr_inv')
            if cb.count() > 0:
                is_checked = cb.is_checked()
                if enable and not is_checked:
                    cb.click(force=True)
                elif not enable and is_checked:
                    cb.click(force=True)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] toggle_dst_addr_inverse error: {e}")
        return self

    def select_src_ip_group(self, group_name: str):
        """选择源地址IP分组(第1个IP分组combobox)"""
        try:
            self._close_any_dropdown()
            form_item = self._find_form_item_by_label("IP分组", index=0)
            if form_item is not None:
                self._click_select_in_form_item(form_item)
                self._select_dropdown_option(group_name)
            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_src_ip_group error: {e}")
        return self

    def select_dst_ip_group(self, group_name: str):
        """选择目的地址IP分组(第2个IP分组combobox)"""
        try:
            self._close_any_dropdown()
            form_item = self._find_form_item_by_label("IP分组", index=1)
            if form_item is not None:
                self._click_select_in_form_item(form_item)
                self._select_dropdown_option(group_name)
            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_dst_ip_group error: {e}")
        return self

    # ==================== 端口设置(协议非"任意"时可见) ====================

    def fill_src_port(self, port: str):
        """填写源端口 - 第1个"端口设置"区域(协议非"任意"时可见)"""
        self._fill_value_in_form_item("端口设置", 0, port, "端口")
        return self

    def fill_dst_port(self, port: str):
        """填写目的端口 - 第2个"端口设置"区域(协议非"任意"时可见)"""
        self._fill_value_in_form_item("端口设置", 1, port, "端口")
        return self

    # ==================== NAT字段(snat/dnat时可见) ====================

    def fill_nat_addr(self, addr: str):
        """填写NAT地址 (id=nat_addr, snat/dnat时可见)"""
        try:
            nat_addr_input = self.page.locator('#nat_addr')
            if nat_addr_input.count() > 0 and nat_addr_input.is_visible():
                nat_addr_input.click()
                nat_addr_input.fill("")
                nat_addr_input.type(addr, delay=30)
                self.page.wait_for_timeout(200)
            else:
                # Fallback: placeholder
                nat_input = self.page.locator('input[placeholder="请输入NAT地址"]')
                if nat_input.count() > 0:
                    nat_input.click()
                    nat_input.fill("")
                    nat_input.type(addr, delay=30)
                    self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_nat_addr error: {e}")
        return self

    def fill_nat_port(self, port: str):
        """填写NAT端口(仅dnat时可见)"""
        try:
            # NAT端口可能没有固定ID, 用placeholder或name属性
            nat_port_input = self.page.locator('input[placeholder="请输入NAT端口"]')
            if nat_port_input.count() > 0 and nat_port_input.first.is_visible():
                inp = nat_port_input.first
                inp.click()
                inp.fill("")
                inp.type(port, delay=30)
                self.page.wait_for_timeout(200)
            else:
                # Fallback: name属性
                nat_port_input = self.page.locator('input[name="nat_port"], input[id="nat_port"]')
                if nat_port_input.count() > 0 and nat_port_input.first.is_visible():
                    inp = nat_port_input.first
                    inp.click()
                    inp.fill("")
                    inp.type(port, delay=30)
                    self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_nat_port error: {e}")
        return self

    # ==================== 齿轮设置面板(右上角ant-card卡片) ====================
    # 实测DOM结构(2026-06-15):
    #   div._container_xxx  (齿轮面板容器)
    #     ├── div.ant-card  (标题"本地转发自动NAT(相同LAN)" + checkbox#local_forward_nat)
    #     ├── button "保存"
    #     └── button "取消"
    # 注意: 齿轮面板不是 aside.ant-layout-sider(那是左侧主菜单), 也不是 ant-drawer

    def _get_settings_panel(self):
        """获取齿轮设置面板容器(div._container_xxx)

        通过卡片标题文字定位其父容器,避免被左侧ant-layout-sider主菜单误匹配。
        """
        # 找含"本地转发自动NAT"标题的ant-card, 返回其父容器(_container)
        return self.page.locator('.ant-card').filter(
            has_text="本地转发自动NAT"
        ).locator('xpath=..')

    def _is_settings_panel_open(self) -> bool:
        """判断齿轮设置面板是否已展开"""
        panel = self._get_settings_panel()
        if panel.count() == 0:
            return False
        # 容器可见且卡片可见
        try:
            return panel.first.is_visible()
        except Exception:
            return False

    def open_settings_drawer(self) -> bool:
        """打开齿轮设置面板(右上角齿轮图标 -> ant-card卡片)"""
        try:
            # 先检查是否已经打开
            if self._is_settings_panel_open():
                return True

            # 策略1: 用Playwright直接点击齿轮图标按钮
            gear_icon = self.page.locator('[data-icon="setting"]')
            if gear_icon.count() > 0:
                for i in range(gear_icon.count()):
                    icon = gear_icon.nth(i)
                    if icon.is_visible():
                        icon.click()
                        self.page.wait_for_timeout(1500)
                        if self._is_settings_panel_open():
                            return True

            # 策略2: 在tablist父元素中找icon-only button并点击
            tablist = self.page.locator('[role="tablist"]')
            if tablist.count() > 0:
                parent = tablist.first.locator('..')
                icon_btns = parent.locator('button.ant-btn-icon-only')
                for i in range(icon_btns.count()):
                    btn = icon_btns.nth(i)
                    if btn.is_visible():
                        btn.click()
                        self.page.wait_for_timeout(1500)
                        if self._is_settings_panel_open():
                            return True

            # 策略3: React fiber onClick
            self.page.evaluate("""() => {
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
                                try {
                                    fiber.memoizedProps.onClick({stopPropagation: () => {}, preventDefault: () => {}});
                                    return 'clicked via fiber';
                                } catch(e) {
                                    return 'fiber error: ' + e.message;
                                }
                            }
                            fiber = fiber.return;
                        }
                    }
                }
                return 'no fiber onClick found';
            }""")
            self.page.wait_for_timeout(1000)

            if self._is_settings_panel_open():
                return True

            print(f"[WARN] 齿轮设置面板未能打开")
            return False
        except Exception as e:
            print(f"[DEBUG] open_settings_drawer error: {e}")
            return False

    def close_settings_drawer(self):
        """关闭齿轮设置面板(点击取消)"""
        try:
            if not self._is_settings_panel_open():
                return True

            panel = self._get_settings_panel()
            cancel_btn = panel.first.get_by_role("button", name="取消")
            if cancel_btn.count() > 0 and cancel_btn.first.is_visible():
                cancel_btn.first.click()
                self.page.wait_for_timeout(500)
                return True

            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] close_settings_drawer error: {e}")
        return True

    def toggle_local_forward_nat(self, enable: bool):
        """开启/关闭本地转发自动NAT(相同LAN)设置(checkbox id=local_forward_nat)"""
        try:
            # 用稳定的id定位, 不依赖面板容器(checkbox在card内)
            checkbox = self.page.locator('#local_forward_nat')
            if checkbox.count() > 0:
                is_checked = checkbox.first.is_checked()
                if is_checked != enable:
                    # 点击checkbox的wrapper(label)更可靠
                    wrapper = self.page.locator('label.ant-checkbox-wrapper').filter(
                        has=self.page.locator('#local_forward_nat')
                    )
                    if wrapper.count() > 0:
                        wrapper.first.click()
                    else:
                        checkbox.first.click(force=True)
                    self.page.wait_for_timeout(500)
            else:
                # 回退: 文字匹配
                cb = self.page.get_by_role("checkbox", name="开启")
                if cb.count() > 0 and cb.first.is_visible():
                    is_checked = cb.first.is_checked()
                    if is_checked != enable:
                        cb.first.click()
                        self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] toggle_local_forward_nat error: {e}")
        return self

    def save_settings(self) -> bool:
        """保存齿轮设置面板(保存按钮是card的兄弟节点,在_container内)"""
        try:
            panel = self._get_settings_panel()
            if panel.count() == 0:
                print("[DEBUG] save_settings: 面板未打开")
                return False

            # 保存按钮是card的兄弟节点,用容器定位
            save_btn = panel.first.get_by_role("button", name="保存")
            if save_btn.count() > 0 and save_btn.first.is_visible():
                save_btn.first.click()
                self.page.wait_for_timeout(1500)
                error_msg = self.page.locator('.ant-message-error')
                if error_msg.count() > 0:
                    return False
                return self.wait_for_success_message()
            print("[DEBUG] save_settings: 未找到保存按钮")
        except Exception as e:
            print(f"[DEBUG] save_settings error: {e}")
        return False

    def cancel_settings(self):
        """取消齿轮设置面板"""
        try:
            panel = self._get_settings_panel()
            if panel.count() > 0:
                cancel_btn = panel.first.get_by_role("button", name="取消")
                if cancel_btn.count() > 0:
                    cancel_btn.first.click()
                    self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] cancel_settings error: {e}")
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

    def get_rule_count(self) -> int:
        """获取规则数量"""
        return len(self.get_rule_list())

    # ==================== 添加规则（完整流程）====================

    def add_rule(self, name: str,
                 action: str = "过滤",
                 inbound_interfaces: List[str] = None,
                 outbound_interfaces: List[str] = None,
                 src_addr: str = None,
                 src_addr_batch: List[str] = None,
                 src_ip_group: str = None,
                 src_addr_inv: bool = None,
                 dst_addr: str = None,
                 dst_addr_batch: List[str] = None,
                 dst_ip_group: str = None,
                 dst_addr_inv: bool = None,
                 protocol: str = None,
                 src_port: str = None,
                 dst_port: str = None,
                 nat_addr: str = None,
                 nat_port: str = None,
                 remark: str = None) -> bool:
        """添加NAT规则

        动作类型决定字段显隐:
        - 过滤(filter): 无NAT地址/端口
        - 源地址NAT(snat): 有NAT地址(可选)
        - 目的地址NAT(dnat): 有NAT地址(必填)+NAT端口(可选), 无出接口

        协议决定端口字段显隐:
        - 任意: 无源端口/目的端口
        - tcp/udp/tcp+udp: 有源端口/目的端口
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)

            try:
                self.page.wait_for_selector('#tagname', timeout=10000)
            except Exception:
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(1000)
            self.page.wait_for_timeout(500)

            # 1. 名称
            self.fill_name(name)
            print(f"  [add_rule] name={name}")

            # 2. 动作类型(必须在条件字段之前)
            if action and action != "过滤":
                self.select_action(action)
                self.page.wait_for_timeout(500)
                print(f"  [add_rule] action={action}")

            # 3. 进接口
            if inbound_interfaces:
                print(f"  [add_rule] inbound={inbound_interfaces}")
                self.select_inbound_interfaces(inbound_interfaces)

            # 4. 出接口(filter/snat时可见, dnat时隐藏)
            action_db = self.ACTION_MAP.get(action, "filter")
            if outbound_interfaces and action_db != "dnat":
                print(f"  [add_rule] outbound={outbound_interfaces}")
                self.select_outbound_interfaces(outbound_interfaces)

            # 5. 源地址 (先填地址, 再设置反向匹配)
            if src_addr:
                print(f"  [add_rule] src_addr={src_addr}")
                self.fill_src_addr(src_addr)
            if src_addr_batch:
                print(f"  [add_rule] src_addr_batch={len(src_addr_batch)} IPs")
                self.fill_src_addr_batch(src_addr_batch)
            if src_ip_group:
                print(f"  [add_rule] src_ip_group={src_ip_group}")
                self.select_src_ip_group(src_ip_group)
            if src_addr_inv:
                print(f"  [add_rule] src_addr_inv=True")
                self.toggle_src_addr_inverse(True)

            # 6. 目的地址
            if dst_addr:
                print(f"  [add_rule] dst_addr={dst_addr}")
                self.fill_dst_addr(dst_addr)
            if dst_addr_batch:
                print(f"  [add_rule] dst_addr_batch={len(dst_addr_batch)} IPs")
                self.fill_dst_addr_batch(dst_addr_batch)
            if dst_ip_group:
                print(f"  [add_rule] dst_ip_group={dst_ip_group}")
                self.select_dst_ip_group(dst_ip_group)
            if dst_addr_inv:
                print(f"  [add_rule] dst_addr_inv=True")
                self.toggle_dst_addr_inverse(True)

            # 7. 协议(决定端口字段显隐)
            if protocol and protocol != "任意":
                self.select_protocol(protocol)
                self.page.wait_for_timeout(500)
                print(f"  [add_rule] protocol={protocol}")

                # 8. 源端口
                if src_port:
                    print(f"  [add_rule] src_port={src_port}")
                    self.fill_src_port(src_port)

                # 9. 目的端口
                if dst_port:
                    print(f"  [add_rule] dst_port={dst_port}")
                    self.fill_dst_port(dst_port)

            # 10. NAT地址(snat/dnat时)
            if nat_addr and action_db in ("snat", "dnat"):
                print(f"  [add_rule] nat_addr={nat_addr}")
                self.fill_nat_addr(nat_addr)

            # 11. NAT端口(仅dnat时)
            if nat_port and action_db == "dnat":
                print(f"  [add_rule] nat_port={nat_port}")
                self.fill_nat_port(nat_port)

            # 12. 备注
            if remark:
                print(f"  [add_rule] remark={remark}")
                self.fill_remark(remark)

            # 13. 保存
            print(f"  [add_rule] clicking save...")
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

            # 检查是否仍在添加页面(保存失败)
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
        """编辑NAT规则"""
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
                if "natRules" in self.page.url:
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
                    self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            toast_error = self.page.locator('.ant-message-error')
            if toast_error.count() > 0:
                error_text = toast_error.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    self.navigate_back_to_list()
                    return {"success": True, "error_message": error_text}

            still_on_config = ("natRules/add" in self.page.url or
                               "natRules/edit" in self.page.url)
            if expect_fail and still_on_config:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                self.navigate_back_to_list()
                return {"success": True, "error_message": "保存被拒绝(后端验证)"}

            if expect_fail:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                self.navigate_back_to_list()
                return {"success": False, "error_message": ""}

            return {"success": True, "error_message": ""}

        except Exception as e:
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return {"success": False, "error_message": str(e)}
