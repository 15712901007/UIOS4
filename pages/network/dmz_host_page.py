"""
DMZ主机页面类

处理网络配置 > UPnP/NAT > DMZ主机 tab的增删改查、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作

实测表单结构 (2026-06-15):
- 表单字段(顺序): 名称*|映射类型(外网接口/外网IP)|外网地址|内网地址*|排除协议|备注
- 名称: id=tagname (1-15字符)
- 映射类型: name=mapping_type radio, 值 externalNetworkInterface(外网接口,默认) / externalNetworkIP(外网IP)
- 外网地址(外网接口模式): id=externalNetworkInterface_interface (多选combobox, wan1/wan2/wan3, 默认"任意")
- 外网地址(外网IP模式): id=externalNetworkIP_interface (text输入框, 必填IP)
- 内网地址: id=lan_addr (DMZ主机内网IP, 必填合法IP)
- 排除协议: id=protocol (combobox, 不限/tcp/udp/tcp+udp, 默认"不限"=any)
- 排除端口: id=excl_port (排除协议≠不限时出现, 必填)
- 备注: id=comment

重要: 排除协议的语义
- "不限"(any): 所有流量走DMZ(NETMAP), 无排除端口字段
- tcp/udp/tcp+udp: 这些协议的指定端口(excl_port)不走DMZ(放行RETURN), 其余NETMAP
  即排除端口是被保护的、不映射的端口

数据库字段映射 (从后端脚本netmap.sh确认):
- one_one_map表:
  id, enabled(yes/no), tagname(名称), comment(备注),
  interface(外网地址: "all"或wan网卡名或外网IP),
  lan_addr(内网地址, plain IP),
  protocol(排除协议 any/tcp/udp/tcp+udp),
  excl_port(排除端口, 仅protocol≠any时有值)

后端iptables实现 (netmap.sh):
- NETNAT链(nat表): -j NETMAP --to <lan_addr>/32 (注意是NETMAP全端口映射, 非DNAT)
- 排除协议≠any时: 先加 -j RETURN 放行excl_port, 再NETMAP其余流量
- 链注册: PREROUTING需引用NETNAT链(ipt_qos_other_ensure_chain)
- interface=all: -m set --match-set Linux_wan_default dst

已知产品BUG(用户反馈"重启后DMZ不生效"):
- netmap.sh init函数第30行: local qos_num=$(sqlite3 ... "select * from one_one_map")
  select *返回数据行非数字, [ "$qos_num" -gt "0" ]报"integer expression expected"
  导致ipt_qos_other_ensure_chain未执行, PREROUTING未注册NETNAT链引用
  表现: NETNAT链有规则但PREROUTING不引用, DMZ实际不生效(尤其重启后)
- 后台验证需检查PREROUTING是否引用NETNAT链, 这是发现该bug的关键

⚠️ 测试注意事项:
- 禁止用wan1作为外网接口测试(DMZ会把wan1所有流量映射走, 导致无法登录管理)
  interface=all 或 wan2/wan3 可用
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class DmzHostPage(IkuaiTablePage):
    """DMZ主机页面操作类"""

    MODULE_NAME = "dmz_host"
    UPNP_NAT_URL = "/login#/networkConfiguration/upnpNat"
    DMZ_ADD_URL = "/login#/networkConfiguration/upnpNat/dmzServer/add"

    # 映射类型 radio值
    MAP_TYPE_INTERFACE = "externalNetworkInterface"  # 外网接口
    MAP_TYPE_IP = "externalNetworkIP"                # 外网IP

    # 排除协议 UI标签 -> DB值
    PROTOCOL_MAP = {
        "不限": "any",
        "tcp": "tcp",
        "udp": "udp",
        "tcp+udp": "tcp+udp",
    }

    # ==================== 导航 ====================

    def navigate_to_dmz(self):
        """导航到UPnP/NAT > DMZ主机页面"""
        url = f"{self.base_url}{self.UPNP_NAT_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)

        # 点击DMZ主机 tab (第5个tab)
        tab = self.page.get_by_role("tab", name="DMZ主机")
        if tab.count() > 0:
            tab.click()
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页面导航回列表页"""
        self.navigate_to_dmz()
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
        option = self.page.locator(f'.ant-select-item-option[title="{option_text}"]')
        for i in range(option.count()):
            if option.nth(i).is_visible():
                option.nth(i).click()
                self.page.wait_for_timeout(500)
                return True

        items = self.page.locator('.ant-select-item-option')
        for i in range(items.count()):
            item = items.nth(i)
            if item.is_visible() and item.text_content().strip() == option_text:
                item.click()
                self.page.wait_for_timeout(500)
                return True

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
        """填写名称 (id=tagname)"""
        name_input = self.page.locator('#tagname')
        if name_input.count() > 0:
            name_input.click()
            name_input.fill(name)
            self.page.wait_for_timeout(200)
        return self

    def fill_lan_addr(self, addr: str):
        """填写内网地址(DMZ主机内网IP, id=lan_addr, 必填合法IP)"""
        inp = self.page.locator('#lan_addr')
        if inp.count() > 0:
            inp.click()
            inp.fill("")
            inp.type(addr, delay=30)
            self.page.wait_for_timeout(200)
        return self

    def fill_excl_port(self, port: str):
        """填写排除端口(id=excl_port, 排除协议≠不限时出现, 必填)

        排除端口是被保护的、不走DMZ映射的端口。
        选了排除协议后该字段会动态出现, 这里等待它可见再填写。
        """
        try:
            excl_input = self.page.locator('#excl_port')
            # 等待字段出现(选协议后动态渲染)
            if excl_input.count() == 0:
                excl_input.wait_for(state='visible', timeout=3000)
            elif not excl_input.first.is_visible():
                excl_input.first.wait_for(state='visible', timeout=3000)

            if excl_input.count() > 0 and excl_input.first.is_visible():
                excl_input.first.click()
                excl_input.first.fill("")
                excl_input.first.type(port, delay=30)
                self.page.wait_for_timeout(300)
            else:
                print(f"  [WARN] fill_excl_port: #excl_port 不可见")
        except Exception as e:
            print(f"[DEBUG] fill_excl_port error: {e}")
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

    # ==================== 映射类型 ====================

    def select_map_type(self, map_type: str = "外网接口"):
        """选择映射类型(外网接口/外网IP)"""
        try:
            value = self.MAP_TYPE_INTERFACE if map_type == "外网接口" else self.MAP_TYPE_IP
            radio = self.page.locator(f'input[name="mapping_type"][value="{value}"]')
            if radio.count() > 0:
                if not radio.is_checked():
                    radio.click()
                    self.page.wait_for_timeout(800)
        except Exception as e:
            print(f"[DEBUG] select_map_type error: {e}")
        return self

    # ==================== 外网地址 ====================

    def select_external_interfaces(self, interfaces: List[str]):
        """选择外网接口(多选checkbox下拉框, 外网接口模式)

        ⚠️ 禁止传入wan1(DMZ会把wan1所有流量映射走, 导致无法登录管理)
        多选下拉框选完选项后不会自动关闭, 必须手动关闭, 否则挡住后续字段。
        """
        for iface in interfaces:
            self._select_interface("外网地址", iface)
            self.page.wait_for_timeout(300)
        # 关键: 多选checkbox下拉框选完不会自动关, 必须手动关闭, 否则悬浮挡住#lan_addr
        # 策略1: 多次Escape
        for _ in range(3):
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
            except Exception:
                pass
        # 策略2: 点击名称输入框让下拉失焦关闭
        try:
            name_input = self.page.locator('#tagname')
            if name_input.count() > 0:
                name_input.first.click()
                self.page.wait_for_timeout(500)
        except Exception:
            pass
        return self

    def fill_external_ip(self, ip: str):
        """填写外网IP地址(外网IP模式, id=externalNetworkIP_interface)"""
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

                option = self.page.locator(f'.ant-select-item-option[title="{interface_name}"]')
                if option.count() > 0:
                    for i in range(option.count()):
                        opt = option.nth(i)
                        if opt.is_visible():
                            opt.click()
                            self.page.wait_for_timeout(500)
                            return self

                wrapper = self.page.locator('.ant-checkbox-wrapper').filter(has_text=interface_name)
                for i in range(wrapper.count()):
                    w = wrapper.nth(i)
                    if w.is_visible():
                        w.click(force=True)
                        self.page.wait_for_timeout(500)
                        return self

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

    # ==================== 排除协议 ====================

    def select_protocol(self, protocol: str = "不限"):
        """选择排除协议(不限/tcp/udp/tcp+udp, 默认"不限"=any)

        选择非"不限"后, 排除端口字段(excl_port)会出现。
        必须在 fill_excl_port 之前调用。
        """
        try:
            self._close_any_dropdown()
            form_item = self._find_form_item_by_label("排除协议")
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
            self.page.wait_for_timeout(800)  # 等待排除端口字段显隐动画
            self._close_any_dropdown()
        except Exception as e:
            print(f"[DEBUG] select_protocol error: {e}")
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

    # ==================== segmented筛选器 ====================

    def click_segmented_filter(self, filter_name: str):
        """点击segmented筛选器(全部/已停用/已启用)"""
        try:
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
        """获取segmented筛选器的计数"""
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
                 map_type: str = "外网接口",
                 external_interfaces: List[str] = None,
                 external_ip: str = None,
                 protocol: str = "不限",
                 excl_port: str = None,
                 remark: str = None) -> bool:
        """添加DMZ主机规则

        必填字段: 名称, 内网地址
        可选字段: 映射类型(默认外网接口), 外网地址, 排除协议(默认不限), 排除端口, 备注

        ⚠️ external_interfaces禁止传入wan1

        排除协议逻辑:
        - 不限(any): 全部流量NETMAP, 无排除端口
        - tcp/udp/tcp+udp: excl_port必填(这些端口RETURN放行, 其余NETMAP)
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

            # 2. 映射类型 + 外网地址
            if map_type and map_type != "外网接口":
                self.select_map_type(map_type)
                self.page.wait_for_timeout(500)
                print(f"  [add_rule] map_type={map_type}")
                if external_ip:
                    self.fill_external_ip(external_ip)
                    print(f"  [add_rule] external_ip={external_ip}")
            else:
                # 外网接口模式: 必须选择具体接口(wan2/wan3), 禁止默认"任意"(=all会劫持所有wan流量)
                # 安全校验: external_interfaces为空或含wan1时, 强制改用wan2
                safe_interfaces = list(external_interfaces) if external_interfaces else []
                safe_interfaces = [i for i in safe_interfaces if i not in ("wan1", "all", "任意")]
                if not safe_interfaces:
                    safe_interfaces = ["wan2"]
                    print(f"  [add_rule] [安全] 外网接口模式未指定安全接口, 强制用wan2(避免interface=all)")
                self.select_external_interfaces(safe_interfaces)
                print(f"  [add_rule] external_interfaces={safe_interfaces}")
                # [安全验证] 选完接口后确认选中了具体接口(wan2/wan3), 而非默认"任意"(all会NETMAP劫持所有WAN含管理流量致设备失联)
                try:
                    iface_form = self._find_form_item_by_label("外网地址")
                    if iface_form is not None:
                        sel_items = iface_form.locator('.ant-select-selection-item').all_text_contents()
                        sel_str = '|'.join(t.strip() for t in sel_items if t.strip())
                        if not sel_str or "任意" in sel_str or "all" in sel_str.lower():
                            print(f"  [add_rule][!安全阻断] 外网接口仍为'{sel_str}'(应为wan2/wan3), 取消保存避免任意DMZ劫持WAN管理")
                            try:
                                self.click_cancel()
                                self.page.wait_for_timeout(500)
                            except Exception:
                                pass
                            return False
                        print(f"  [add_rule][安全验证OK] 外网接口已选: {sel_str}")
                except Exception as e:
                    print(f"  [add_rule][安全验证] 异常(忽略,继续): {e}")

            # 3. 内网地址
            self.fill_lan_addr(lan_addr)
            print(f"  [add_rule] lan_addr={lan_addr}")

            # 4. 排除协议(决定排除端口字段显隐)
            if protocol and protocol != "不限":
                self.select_protocol(protocol)
                self.page.wait_for_timeout(1000)  # 等排除端口字段完全渲染
                print(f"  [add_rule] protocol={protocol}")

                # 5. 排除端口(排除协议≠不限时必填)
                if excl_port:
                    self.fill_excl_port(excl_port)
                    self.page.wait_for_timeout(300)
                    print(f"  [add_rule] excl_port={excl_port}")

            # 6. 备注
            if remark:
                self.fill_remark(remark)
                print(f"  [add_rule] remark={remark}")

            # 7. 保存
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
            print(f"[ERROR] 添加DMZ主机失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 编辑规则 ====================

    def edit_rule(self, old_name: str, new_name: str = None,
                  remark: str = None, lan_addr: str = None) -> bool:
        """编辑DMZ主机规则"""
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
            if lan_addr is not None:
                self.fill_lan_addr(lan_addr)

            self.click_save()
            result = self.wait_for_success_message()

            if result:
                self.page.wait_for_timeout(500)
                if "dmzServer" in self.page.url:
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
            print(f"[ERROR] 编辑DMZ主机失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 异常输入测试 ====================

    def try_add_rule_invalid(self, name: str = "",
                              lan_addr: str = None,
                              expect_fail: bool = True) -> dict:
        """尝试添加无效规则，测试表单验证

        ⚠️ DMZ安全: 强制使用外网IP模式 + 安全IP(10.66.0.250),
        即使后端接受创建了规则, 也是 -d 10.66.0.250 的安全规则, 绝不劫持管理流量。
        绝不使用默认的外网接口模式(interface=all会NETMAP所有wan流量包括管理通道)。
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1000)

            # 强制切换到外网IP模式 + 安全IP(避免误创建interface=all的危险规则)
            self.select_map_type("外网IP")
            self.page.wait_for_timeout(500)
            self.fill_external_ip("10.66.0.250")
            self.page.wait_for_timeout(300)

            if name is not None:
                self.fill_name(name)
            if lan_addr is not None:
                self.fill_lan_addr(lan_addr)

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

            still_on_config = ("dmzServer/add" in self.page.url or
                               "dmzServer/edit" in self.page.url)
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
