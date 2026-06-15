"""
端口映射页面类

处理网络配置 > UPnP/NAT > 端口映射 tab的增删改查、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作

实测表单结构 (2026-06-15):
- 表单字段(顺序): 名称*|内网地址*|内网端口*|协议|映射类型(外网接口/外网IP)|外网地址|外网端口*|允许访问IP地址(IP设置+IP分组)|备注
- 名称: id=tagname (1-15字符)
- 内网地址: id=lan_addr (必须合法IP)
- 内网端口: id=lan_port (端口或端口范围或逗号分隔)
- 协议: id=protocol (combobox, tcp/udp/tcp+udp, 注意无"任意")
- 映射类型: name=mapping_type radio, 值 externalNetworkInterface(外网接口,默认) / externalNetworkIP(外网IP)
- 外网地址(外网接口模式): id=externalNetworkInterface_interface (多选combobox, wan1/wan2/wan3, 默认"任意")
- 外网地址(外网IP模式): id=externalNetworkIP_interface (text输入框, 必填IP)
- 外网端口: id=wan_port
- 允许访问IP地址: IP设置(逐条+批量, 同NAT规则) + IP分组combobox
- 备注: id=comment

数据库字段映射 (从后端脚本dnat.sh确认):
- dst_nat表:
  id, enabled(yes/no), tagname(名称), comment(备注),
  interface(外网地址: "all"或wan网卡名或外网IP),
  src_addr(源地址JSON, base64存储),
  lan_addr(内网地址, plain IP),
  protocol(协议 tcp/udp/tcp+udp),
  wan_port(外网端口), lan_port(内网端口)

页面结构:
- URL: /login#/networkConfiguration/upnpNat (端口映射是第4个tab)
- segmented筛选: 全部/已停用/已启用 (radio)
- 表格列: 名称|内网地址|内网端口|协议|外网地址|外网端口|允许访问IP地址|备注|操作
- 工具栏: 搜索+添加+导入+导出
- 行内按钮: 编辑/停用(启用)/删除
- 无齿轮设置按钮
- 添加/编辑表单: 独立页面(portMapping/add, portMapping/edit/<id>), 非弹窗

映射类型与外网地址字段:
- 外网接口(默认): 外网地址是多选checkbox下拉(wan1/wan2/wan3), 非必填, 默认"任意"(interface=all)
- 外网IP: 外网地址变为必填text输入框, 需填合法IP

协议选项: tcp/udp/tcp+udp (注意端口映射没有"任意"协议, 默认tcp)

端口格式支持:
- 单端口: 80
- 端口范围: 1000-2000 (外网和内网端口数量必须一致, 后端__check_ports_equal校验)
- 多端口: 80,443,8080 (逗号分隔, 数量也需一致)
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class PortMapPage(IkuaiTablePage):
    """端口映射页面操作类"""

    MODULE_NAME = "port_map"
    UPNP_NAT_URL = "/login#/networkConfiguration/upnpNat"
    PORTMAP_ADD_URL = "/login#/networkConfiguration/upnpNat/portMapping/add"

    # 映射类型 radio值
    MAP_TYPE_INTERFACE = "externalNetworkInterface"  # 外网接口
    MAP_TYPE_IP = "externalNetworkIP"                # 外网IP

    # ==================== 导航 ====================

    def navigate_to_port_map(self):
        """导航到UPnP/NAT > 端口映射页面"""
        url = f"{self.base_url}{self.UPNP_NAT_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        # 点击端口映射 tab (第4个tab)
        tab = self.page.get_by_role("tab", name="端口映射")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_port_map()
        self.page.wait_for_timeout(500)
        return self

    # ==================== 通用下拉框操作(复用NAT规则的经验) ====================

    def _close_any_dropdown(self):
        """关闭所有可能打开的下拉框"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _find_form_item_by_label(self, label_text: str, index: int = 0):
        """通过label文字查找第N个ant-form-item"""
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

    def fill_lan_addr(self, addr: str):
        """填写内网地址 (id=lan_addr, 必须合法IP)"""
        inp = self.page.locator('#lan_addr')
        if inp.count() > 0:
            inp.click()
            inp.fill("")
            inp.type(addr, delay=30)
            self.page.wait_for_timeout(200)
        return self

    def fill_lan_port(self, port: str):
        """填写内网端口 (id=lan_port, 支持单端口/范围/多端口)"""
        inp = self.page.locator('#lan_port')
        if inp.count() > 0:
            inp.click()
            inp.fill("")
            inp.type(port, delay=30)
            self.page.wait_for_timeout(200)
        return self

    def fill_wan_port(self, port: str):
        """填写外网端口 (id=wan_port)"""
        inp = self.page.locator('#wan_port')
        if inp.count() > 0:
            inp.click()
            inp.fill("")
            inp.type(port, delay=30)
            self.page.wait_for_timeout(200)
        return self

    def select_protocol(self, protocol: str = "tcp"):
        """选择协议(tcp/udp/tcp+udp, 注意端口映射无"任意")

        协议必须在表单加载时已默认tcp, 仅在需要切换时调用。
        """
        try:
            self._close_any_dropdown()
            form_item = self._find_form_item_by_label("协议")
            if form_item is None:
                return self

            # 检查当前值
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

    # ==================== 映射类型(外网接口/外网IP) ====================

    def select_map_type(self, map_type: str = "外网接口"):
        """选择映射类型(外网接口/外网IP)

        映射类型决定外网地址字段的形态:
        - 外网接口: 外网地址是多选combobox(wan1/wan2/wan3), 非必填
        - 外网IP: 外网地址变为必填text输入框
        """
        try:
            radio = self.page.locator(f'input[name="mapping_type"][value="{self.MAP_TYPE_INTERFACE if map_type == "外网接口" else self.MAP_TYPE_IP}"]')
            if radio.count() > 0:
                is_checked = radio.is_checked()
                if not is_checked:
                    # 点击radio的wrapper更可靠
                    radio.click()
                    self.page.wait_for_timeout(800)
        except Exception as e:
            print(f"[DEBUG] select_map_type error: {e}")
        return self

    # ==================== 外网地址 ====================

    def select_external_interfaces(self, interfaces: List[str]):
        """选择外网接口(多选checkbox下拉框, 外网接口模式)

        Args:
            interfaces: 接口名列表, 如 ["wan1", "wan2"]
        """
        for iface in interfaces:
            self._select_interface("外网地址", iface)
            self.page.wait_for_timeout(300)
        return self

    def fill_external_ip(self, ip: str):
        """填写外网IP地址(外网IP模式, id=externalNetworkIP_interface, 必填)"""
        try:
            inp = self.page.locator('#externalNetworkIP_interface')
            if inp.count() > 0 and inp.is_visible():
                inp.click()
                inp.fill("")
                inp.type(ip, delay=30)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_external_ip error: {e}")
        return self

    def _select_interface(self, label: str, interface_name: str):
        """通用接口选择方法(多选checkbox下拉框)"""
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

    # ==================== 允许访问IP地址(源地址, 同NAT规则) ====================

    def _fill_value_in_form_item(self, label: str, label_index: int,
                                  value: str, input_placeholder_keyword: str):
        """在指定form-item内: 点击添加按钮, 在出现的输入框中输入值"""
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
                    return True

            print(f"    [WARN] _fill_value: no input in {label}[{label_index}]")
        except Exception as e:
            print(f"  [DEBUG] _fill_value error: {e}")
        return False

    def fill_src_addr(self, addr: str):
        """填写允许访问IP地址(逐条添加) - IP设置区域"""
        self._fill_value_in_form_item("IP设置", 0, addr, "IP")
        return self

    def _click_ip_batch_button(self, index: int = 0):
        """点击第N个IP设置区域的"批量"按钮"""
        form_item = self._find_form_item_by_label("IP设置", index=index)
        if form_item is not None:
            batch_btn = form_item.locator('button').filter(has_text="批量")
            if batch_btn.count() > 0:
                batch_btn.first.click()
                self.page.wait_for_timeout(800)
                return True
        return False

    def fill_src_addr_batch(self, ips: List[str]):
        """批量添加允许访问IP地址"""
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

    # ==================== 规则列表查询 ====================

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
            return names if names else []
        except Exception:
            return []

    def get_rule_count(self) -> int:
        """获取规则数量"""
        return len(self.get_rule_list())

    # ==================== segmented筛选器(全部/已停用/已启用) ====================

    def click_segmented_filter(self, filter_name: str):
        """点击segmented筛选器(全部/已停用/已启用)

        Args:
            filter_name: "全部" / "已停用" / "已启用"
        """
        try:
            # segmented是radio group, 找包含filter_name的radio
            radio = self.page.locator(f'.ant-segmented-item:has-text("{filter_name}")').first
            if radio.count() > 0 and radio.is_visible():
                radio.click()
                self.page.wait_for_timeout(800)
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(500)
                return True
        except Exception as e:
            print(f"[DEBUG] click_segmented_filter error: {e}")
        return False

    def get_segmented_counts(self) -> dict:
        """获取segmented筛选器的计数(全部/已停用/已启用)

        Returns:
            {"全部": int, "已停用": int, "已启用": int}
        """
        try:
            counts = self.page.evaluate("""() => {
                const result = {"全部": -1, "已停用": -1, "已启用": -1};
                const items = document.querySelectorAll('.ant-segmented-item');
                items.forEach(item => {
                    const text = item.textContent.trim();
                    for (const key of Object.keys(result)) {
                        if (text.includes(key)) {
                            const m = text.match(/\\((\\d+)\\)/);
                            result[key] = m ? parseInt(m[1]) : -1;
                        }
                    }
                });
                return result;
            }""")
            return counts if counts else {"全部": -1, "已停用": -1, "已启用": -1}
        except Exception:
            return {"全部": -1, "已停用": -1, "已启用": -1}

    # ==================== 添加规则（完整流程）====================

    def add_rule(self, name: str,
                 lan_addr: str,
                 lan_port: str,
                 wan_port: str,
                 protocol: str = "tcp",
                 map_type: str = "外网接口",
                 external_interfaces: List[str] = None,
                 external_ip: str = None,
                 src_addr: str = None,
                 src_addr_batch: List[str] = None,
                 remark: str = None) -> bool:
        """添加端口映射规则

        必填字段: 名称, 内网地址, 内网端口, 外网端口, 协议(默认tcp)
        可选字段: 映射类型(默认外网接口), 外网地址, 允许访问IP地址, 备注

        映射类型:
        - 外网接口: external_interfaces可选(wan1/wan2/wan3), 不填=任意(all)
        - 外网IP: external_ip必填(合法外网IP)
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

            # 2. 内网地址
            self.fill_lan_addr(lan_addr)
            print(f"  [add_rule] lan_addr={lan_addr}")

            # 3. 内网端口
            self.fill_lan_port(lan_port)
            print(f"  [add_rule] lan_port={lan_port}")

            # 4. 协议(默认tcp, 仅在非tcp时切换)
            if protocol and protocol != "tcp":
                self.select_protocol(protocol)
                self.page.wait_for_timeout(300)
                print(f"  [add_rule] protocol={protocol}")

            # 5. 映射类型 + 外网地址
            if map_type and map_type != "外网接口":
                self.select_map_type(map_type)
                self.page.wait_for_timeout(500)
                print(f"  [add_rule] map_type={map_type}")
                # 外网IP模式: 填写外网IP
                if external_ip:
                    self.fill_external_ip(external_ip)
                    print(f"  [add_rule] external_ip={external_ip}")
            else:
                # 外网接口模式: 选择接口(可选)
                if external_interfaces:
                    self.select_external_interfaces(external_interfaces)
                    print(f"  [add_rule] external_interfaces={external_interfaces}")

            # 6. 外网端口
            self.fill_wan_port(wan_port)
            print(f"  [add_rule] wan_port={wan_port}")

            # 7. 允许访问IP地址(源地址)
            if src_addr:
                self.fill_src_addr(src_addr)
                print(f"  [add_rule] src_addr={src_addr}")
            if src_addr_batch:
                self.fill_src_addr_batch(src_addr_batch)
                print(f"  [add_rule] src_addr_batch={len(src_addr_batch)} IPs")

            # 8. 备注
            if remark:
                self.fill_remark(remark)
                print(f"  [add_rule] remark={remark}")

            # 9. 保存
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
            print(f"[ERROR] 添加端口映射失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 编辑规则 ====================

    def edit_rule(self, old_name: str, new_name: str = None,
                  remark: str = None, lan_port: str = None) -> bool:
        """编辑端口映射规则"""
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
            if lan_port is not None:
                self.fill_lan_port(lan_port)

            self.click_save()
            result = self.wait_for_success_message()

            if result:
                self.page.wait_for_timeout(500)
                if "portMapping" in self.page.url:
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
            print(f"[ERROR] 编辑端口映射失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 复制规则 ====================

    def copy_rule(self, rule_name: str, new_name: str = None) -> bool:
        """复制规则(点击列表中的复制按钮, 进入新增页面预填数据)

        复制会进入 portMapping/add 页面, 所有字段已预填, 需要修改名称后保存。

        Args:
            rule_name: 要复制的规则名称
            new_name: 复制后的新名称(必须不同于原名, 因为tagname唯一)

        Returns:
            是否复制成功
        """
        try:
            clicked = self._click_rule_button(rule_name, "复制")
            if not clicked:
                print(f"[WARN] 复制按钮未找到: {rule_name}")
                return False

            self.page.wait_for_timeout(1500)

            # 复制进入新增页面, 字段已预填, 修改名称后保存
            if new_name:
                self.fill_name(new_name)

            self.click_save()
            result = self.wait_for_success_message()

            if result:
                self.page.wait_for_timeout(500)
                if "portMapping" in self.page.url:
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
            print(f"[ERROR] 复制规则失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 异常输入测试 ====================

    def try_add_rule_invalid(self, name: str = "",
                              lan_addr: str = None,
                              lan_port: str = None,
                              wan_port: str = None,
                              expect_fail: bool = True) -> dict:
        """尝试添加无效规则，测试表单验证

        只填提供的字段, 不填的字段留空, 用于测试必填校验。
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1000)

            if name is not None:
                self.fill_name(name)
            if lan_addr is not None:
                self.fill_lan_addr(lan_addr)
            if lan_port is not None:
                self.fill_lan_port(lan_port)
            if wan_port is not None:
                self.fill_wan_port(wan_port)

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

            still_on_config = ("portMapping/add" in self.page.url or
                               "portMapping/edit" in self.page.url)
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
