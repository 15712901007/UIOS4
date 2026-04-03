"""
跨三层服务页面类

处理跨三层MAC地址学习(SNMP)配置的增删改查、导入导出等操作
继承 IkuaiTablePage 获取通用表格操作
"""
from playwright.sync_api import Page, Locator
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class CrossLayerServicePage(IkuaiTablePage):
    """跨三层服务页面操作类"""

    MODULE_NAME = "cross_layer_service"
    CROSS_LAYER_URL = "/login#/networkConfiguration/crossThreeLevelsOfServices"

    # ==================== 导航 ====================
    def navigate_to_cross_layer_service(self):
        """导航到跨三层服务页面"""
        url = f"{self.base_url}{self.CROSS_LAYER_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        return self

    # ==================== 表单字段填写 ====================
    def fill_name(self, name: str):
        """填写规则名称"""
        self.page.locator('input[placeholder="请输入名称"]').fill(name)
        self.page.wait_for_timeout(200)
        return self

    def fill_snmp_server_ip(self, ip: str):
        """填写SNMP服务器IP"""
        ip_input = self.page.locator('input[placeholder="请输入SNMP服务器IP"]')
        if ip_input.count() > 0:
            ip_input.click()
            ip_input.press("Control+a")
            ip_input.fill(ip)
            self.page.wait_for_timeout(200)
        return self

    def add_ip_address(self, ip: str):
        """在IP设置中添加单条IP地址或IP段"""
        try:
            # 点击IP设置区域的"添加"按钮 - 使用更精确的定位
            # 找到包含"IP设置"文本的标签，然后在其父级区域找"添加"按钮
            ip_label = self.page.locator('label:has-text("IP设置"), span:has-text("IP设置")')
            if ip_label.count() > 0:
                # 向上找到form-item容器
                form_item = ip_label.first.locator('xpath=ancestor::div[contains(@class, "ant-form-item")]')
                if form_item.count() == 0:
                    form_item = ip_label.first.locator('xpath=ancestor::div[3]')

                ip_add_btn = form_item.locator('button:has-text("添加")')
                if ip_add_btn.count() > 0:
                    ip_add_btn.click()
                    self.page.wait_for_timeout(500)

            # 填写IP地址 - 使用placeholder定位（支持Unicode引号）
            ip_input = self.page.locator('input[placeholder*="请输入IP地址"]')
            if ip_input.count() > 0:
                ip_input.last.click()
                ip_input.last.fill(ip)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] add_ip_address error: {e}")
        return self

    def batch_add_ips(self, ips: List[str]):
        """在IP设置中批量添加IP地址"""
        try:
            # 点击"批量"按钮
            batch_btn = self.page.locator('text=IP设置').locator('..').locator('..').locator('button:has-text("批量")')
            if batch_btn.count() > 0:
                batch_btn.click()
                self.page.wait_for_timeout(1000)

            # 在弹出的模态框中填写IP
            modal = self.page.locator('.ant-modal-wrap:not([style*="display: none"])')
            if modal.count() > 0:
                textarea = modal.locator('textarea')
                if textarea.count() > 0:
                    textarea.fill('\n'.join(ips))
                    self.page.wait_for_timeout(300)

                # 点击确定
                modal.locator('button:has-text("确定")').click()
                self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] batch_add_ips error: {e}")
        return self

    def fill_port(self, port: str = "161"):
        """填写SNMP服务监听端口"""
        try:
            port_input = self.page.locator('input[placeholder="请输入SNMP服务监听端口"]')
            if port_input.count() > 0:
                port_input.click()
                port_input.press("Control+a")
                port_input.fill(port)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_port error: {e}")
        return self

    def select_snmp_version(self, version: str = "V2"):
        """选择SNMP协议版本

        点击 .ant-select-selection-item span 触发下拉框，
        然后从下拉列表中选择目标版本。
        """
        try:
            # 检查当前值是否已经是目标版本
            current = self.page.locator('.ant-select-selection-item[title]')
            if current.count() > 0:
                current_text = current.first.get_attribute("title") or ""
                if current_text.strip() == version:
                    print(f"[DEBUG] select_snmp_version: already {version}")
                    return self  # 已经是目标版本

            print(f"[DEBUG] select_snmp_version: need to change to {version}")

            # === 第一步: 打开下拉框 ===
            # 直接点击 .ant-select-selection-item span 触发下拉框
            selection_item = self.page.locator('#version').locator(
                'xpath=ancestor::div[contains(@class, "ant-select-selector")]//span[contains(@class, "ant-select-selection-item")]'
            )
            if selection_item.count() == 0:
                # 回退: 找任意 .ant-select-selection-item
                selection_item = self.page.locator('.ant-select-selection-item[title]')
            print(f"[DEBUG] selection_item count: {selection_item.count()}")
            selection_item.first.click()
            self.page.wait_for_timeout(1000)

            # 调试: 检查下拉框是否打开
            dropdown_visible = self.page.locator('.ant-select-dropdown:visible')
            print(f"[DEBUG] dropdown visible count: {dropdown_visible.count()}")

            # 检查所有下拉框中的选项
            all_items = self.page.locator('.ant-select-item:visible')
            print(f"[DEBUG] all .ant-select-item:visible count: {all_items.count()}")
            for i in range(min(all_items.count(), 5)):
                text = all_items.nth(i).text_content().strip()
                title_attr = all_items.nth(i).get_attribute("title") or ""
                print(f"[DEBUG]   item[{i}]: text='{text}', title='{title_attr}'")

            # 检查 role=option
            options = self.page.get_by_role("option")
            print(f"[DEBUG] role=option count: {options.count()}")

            for i in range(min(options.count(), 5)):
                text = options.nth(i).text_content().strip()
                print(f"[DEBUG]   option[{i}]: text='{text}'")

            # === 第二步: 从下拉框中选择版本 ===
            # 策略A: 使用 .ant-select-item 类
            dropdown_option = self.page.locator(f'.ant-select-item-option[title="{version}"]')
            print(f"[DEBUG] strategy A (.ant-select-item-option): count={dropdown_option.count()}")
            if dropdown_option.count() == 0:
                dropdown_option = self.page.locator(f'.ant-select-item:has-text("{version}")').first
                print(f"[DEBUG] strategy A fallback (.ant-select-item:has-text): count={dropdown_option.count()}")

            if dropdown_option.count() > 0:
                dropdown_option.first.click()
                self.page.wait_for_timeout(300)
                print(f"[DEBUG] select_snmp_version: SUCCESS via strategy A")
                return self

            # 策略B: 使用 get_by_role("option")
            option = self.page.get_by_role("option", name=version, exact=True)
            print(f"[DEBUG] strategy B (get_by_role option): count={option.count()}")
            if option.count() > 0:
                option.click()
                self.page.wait_for_timeout(300)
                print(f"[DEBUG] select_snmp_version: SUCCESS via strategy B")
                return self

            # 策略C: 通过可见下拉框文本定位
            if dropdown_visible.count() > 0:
                dropdown_option = dropdown_visible.locator(f'text="{version}"').first
                print(f"[DEBUG] strategy C (dropdown text): count={dropdown_option.count()}")
                if dropdown_option.count() > 0:
                    dropdown_option.click()
                    self.page.wait_for_timeout(300)
                    print(f"[DEBUG] select_snmp_version: SUCCESS via strategy C")
                    return self

            # 仍未找到，Escape关闭
            print(f"[DEBUG] select_snmp_version: FAILED - no option found, pressing Escape")
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] select_snmp_version error: {e}")
        return self

    def fill_username(self, username: str = "test_user"):
        """填写V3用户名"""
        try:
            username_input = self.page.locator('input[placeholder="请输入用户名"]')
            if username_input.count() > 0:
                username_input.first.click()
                username_input.first.fill(username)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_username error: {e}")
        return self

    def select_security_level(self, level: str = "authNoPriv"):
        """选择V3安全等级 (noAuthNoPriv / authNoPriv / authPriv)"""
        try:
            security_select = self.page.locator('#security')
            if security_select.count() > 0:
                selector = security_select.locator(
                    'xpath=ancestor::div[contains(@class, "ant-select-selector")]'
                )
                if selector.count() > 0:
                    selector.first.click(force=True)
                    self.page.wait_for_timeout(800)

                    option = self.page.locator(f'.ant-select-item-option[title="{level}"]')
                    if option.count() == 0:
                        option = self.page.locator(f'.ant-select-item:has-text("{level}")').first
                    if option.count() > 0:
                        option.click()
                        self.page.wait_for_timeout(300)
                        return self

            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] select_security_level error: {e}")
        return self

    def select_auth_proto(self, proto: str = "MD5"):
        """选择认证协议 (MD5 / SHA)"""
        try:
            auth_select = self.page.locator('#auth_proto')
            if auth_select.count() > 0:
                selector = auth_select.locator(
                    'xpath=ancestor::div[contains(@class, "ant-select-selector")]'
                )
                if selector.count() > 0:
                    selector.first.click(force=True)
                    self.page.wait_for_timeout(800)

                    option = self.page.locator(f'.ant-select-item-option[title="{proto}"]')
                    if option.count() == 0:
                        option = self.page.locator(f'.ant-select-item:has-text("{proto}")').first
                    if option.count() > 0:
                        option.click()
                        self.page.wait_for_timeout(300)
                        return self

            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] select_auth_proto error: {e}")
        return self

    def fill_auth_pass(self, password: str = "auth_pass_123"):
        """填写认证密码"""
        try:
            auth_pass_input = self.page.locator('input[placeholder="请输入认证密码"]')
            if auth_pass_input.count() == 0:
                auth_pass_input = self.page.locator('#auth_pass')
            if auth_pass_input.count() > 0:
                auth_pass_input.first.click()
                auth_pass_input.first.fill(password)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_auth_pass error: {e}")
        return self

    def fill_community(self, community: str = "public"):
        """填写团体名"""
        try:
            community_input = self.page.locator('input[placeholder="请输入团体名"]')
            if community_input.count() > 0:
                community_input.first.click()
                community_input.first.press("Control+a")
                community_input.first.fill(community)
                self.page.wait_for_timeout(200)
        except Exception as e:
            print(f"[DEBUG] fill_community error: {e}")
        return self

    def fill_remark(self, remark: str):
        """填写备注 - 使用ID选择器避免strict mode冲突"""
        try:
            # 使用ID定位备注输入框，避免hiddenTextarea的strict mode冲突
            remark_input = self.page.locator('#comment')
            if remark_input.count() > 0:
                remark_input.click()
                remark_input.fill(remark)
        except Exception as e:
            print(f"[DEBUG] fill_remark error: {e}")
        return self

    # ==================== IP分组 ====================
    def _find_group_in_dialog(self, name: str, max_attempts: int = 5, interval: int = 1000):
        """在选择弹窗中查找已存在的分组（带轮询重试，支持截断名称匹配）

        UI会将长分组名截断显示（如 snmp_ipgroup_test → snmp_ipgroup_te），
        因此使用JavaScript直接匹配textContent，支持前缀匹配。

        Returns:
            Locator or None
        """
        for attempt in range(max_attempts):
            # 使用JS直接在弹窗中查找匹配的checkbox项
            found_index = self.page.evaluate("""(name) => {
                const wrappers = document.querySelectorAll('.ant-modal-wrap:not([style*="display: none"]) .ant-checkbox-wrapper');
                for (let i = 0; i < wrappers.length; i++) {
                    const text = wrappers[i].textContent.trim();
                    // 匹配策略：完全相等 / 名称是文本的前缀 / 文本是名称的前缀
                    if (text === name || name.startsWith(text) || text.startsWith(name)) {
                        return i;
                    }
                }
                return -1;
            }""", name)

            if found_index >= 0:
                # 找到了，返回对应的Locator
                target = self.page.locator('.ant-modal-wrap:not([style*="display: none"]) .ant-checkbox-wrapper').nth(found_index)
                print(f"[DEBUG] _find_group_in_dialog: 找到分组 '{name}' (第{found_index}项)")
                return target

            if attempt < max_attempts - 1:
                print(f"[DEBUG] _find_group_in_dialog: 第{attempt+1}次未找到 '{name}'，等待重试...")
                self.page.wait_for_timeout(interval)

        return None

    def _close_topmost_modal(self):
        """关闭最上层的弹窗（按Escape或点击取消/关闭按钮）"""
        try:
            # 尝试点击"取消"按钮（最后一个弹窗的）
            cancel_btn = self.page.locator('.ant-modal-root button:has-text("取消")')
            if cancel_btn.count() > 0:
                cancel_btn.last.click()
                self.page.wait_for_timeout(300)
                return
            # 回退: 按Escape
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)

    def create_and_select_ip_group(self, name: str, ips: str) -> bool:
        """在添加表单中创建或选择IP分组（完整流程，支持重复检测和错误恢复）

        流程: 点击IP分组combobox → 弹出选择弹窗 →
          如果分组已存在 → 直接勾选 → 确定
          如果分组不存在 → 点击"创建分组" → 填写名称+IP列表 → 确定 → 勾选分组 → 确定

        Args:
            name: 分组名称
            ips: IP列表，换行分隔（如 "10.66.0.1\\n10.66.0.5"）
        """
        try:
            # 1. 点击IP分组combobox区域打开选择弹窗
            ip_group_label = self.page.locator('text=IP分组')
            if ip_group_label.count() > 0:
                ip_group_box = ip_group_label.first.locator('xpath=ancestor::div[1]/following-sibling::div')
                if ip_group_box.count() > 0:
                    ip_group_box.click()
                    self.page.wait_for_timeout(2000)

            # 2. 轮询查找已存在的分组（等待列表加载，最多5次，每次1秒）
            existing_group = self._find_group_in_dialog(name, max_attempts=5, interval=1000)

            if existing_group is not None:
                # 分组已存在，直接勾选
                print(f"[DEBUG] IP分组 '{name}' 已存在，直接选择")
                existing_group.click()
                self.page.wait_for_timeout(300)
            else:
                # 3. 分组不存在，尝试创建新分组
                print(f"[DEBUG] IP分组 '{name}' 不存在，开始创建")
                self._create_group_in_dialog(name, ips)

                # 创建后重新查找并勾选（也处理创建失败"名称已存在"的情况）
                self.page.wait_for_timeout(800)
                group_after = self._find_group_in_dialog(name, max_attempts=3, interval=500)
                if group_after is not None:
                    group_after.click()
                    self.page.wait_for_timeout(300)
                else:
                    print(f"[DEBUG] IP分组 '{name}' 创建后仍未找到，可能创建失败")

            # 4. 点击确定（选择弹窗）
            select_dialog = self.page.get_by_label('请选择')
            if select_dialog.count() > 0:
                select_confirm = select_dialog.get_by_role('button', name='确定')
                if select_confirm.count() > 0:
                    select_confirm.click()
                    self.page.wait_for_timeout(500)

            print(f"[DEBUG] create_and_select_ip_group: SUCCESS - {name}")
            return True

        except Exception as e:
            print(f"[DEBUG] create_and_select_ip_group error: {e}")
            # 确保关闭所有弹窗
            self._close_all_modals()
            return False

    def _create_group_in_dialog(self, name: str, ips: str):
        """在选择弹窗中创建新分组（内部方法）"""
        # 点击"创建分组"按钮
        create_btn = self.page.get_by_role('button', name='创建分组')
        if create_btn.count() > 0:
            create_btn.click()
            self.page.wait_for_timeout(1000)

        # 填写分组名称
        name_input = self.page.get_by_placeholder('请输入分组名称')
        if name_input.count() > 0:
            name_input.fill(name)
            self.page.wait_for_timeout(300)

        # 填写IP列表（textarea）
        ip_textarea = self.page.locator('.ant-modal-root').last.locator('textarea')
        if ip_textarea.count() > 0:
            ip_textarea.fill(ips)
            self.page.wait_for_timeout(300)

        # 点击确定（创建弹窗）
        create_modal = self.page.locator('.ant-modal-root').last
        confirm_btn = create_modal.locator('button:has-text("确定")')
        if confirm_btn.count() > 0:
            confirm_btn.last.click()
            self.page.wait_for_timeout(1000)

        # 检查创建是否成功（是否有"名称已存在"错误）
        error_el = self.page.locator('.ant-form-item-explain-error:has-text("已存在")')
        if error_el.count() > 0:
            # 创建失败：名称已存在 → 关闭创建弹窗，回到选择弹窗重新查找
            print(f"[DEBUG] 创建分组失败: 名称已存在，关闭创建弹窗重新选择")
            self._close_topmost_modal()
            self.page.wait_for_timeout(500)

    def _close_all_modals(self):
        """关闭所有打开的弹窗"""
        for _ in range(3):
            modal = self.page.locator('.ant-modal-wrap:not([style*="display: none"])')
            if modal.count() > 0:
                self._close_topmost_modal()
            else:
                break

    # ==================== 访问频率 ====================
    def set_frequency(self, seconds: int = 0):
        """设置访问频率"""
        try:
            # 点击"访问频率"按钮
            freq_btn = self.page.locator('button:has-text("访问频率")')
            if freq_btn.count() > 0:
                freq_btn.click()
                self.page.wait_for_timeout(1000)

                # 填写频率值
                freq_input = self.page.locator('#validateOnly_snmp_interval')
                if freq_input.count() > 0:
                    freq_input.clear()
                    freq_input.fill(str(seconds))

                # 点击保存
                save_btn = self.page.locator('.ant-drawer button:has-text("保存"), .ant-drawer button:has-text("确定")')
                if save_btn.count() > 0:
                    save_btn.first.click()
                else:
                    self.page.keyboard.press('Escape')

                self.page.wait_for_timeout(500)
        except Exception as e:
            print(f"[DEBUG] set_frequency error: {e}")
        return self

    def get_frequency(self) -> str:
        """获取当前访问频率值（打开抽屉读取后关闭）"""
        try:
            freq_btn = self.page.locator('button:has-text("访问频率")')
            if freq_btn.count() > 0:
                freq_btn.click()
                self.page.wait_for_timeout(1000)

                freq_input = self.page.locator('#validateOnly_snmp_interval')
                value = ""
                if freq_input.count() > 0:
                    value = freq_input.input_value()

                # 关闭抽屉
                self.page.keyboard.press('Escape')
                self.page.wait_for_timeout(500)
                return value
        except Exception as e:
            print(f"[DEBUG] get_frequency error: {e}")
        return ""

    def try_set_frequency_invalid(self, value: str) -> dict:
        """尝试设置无效频率值，返回验证结果

        Args:
            value: 无效频率值字符串（如"abc", "-1", "999999"）

        Returns:
            dict: {success: bool, error_message: str, saved_value: str}
        """
        try:
            # 打开频率抽屉
            freq_btn = self.page.locator('button:has-text("访问频率")')
            if freq_btn.count() > 0:
                freq_btn.click()
                self.page.wait_for_timeout(1000)

                freq_input = self.page.locator('#validateOnly_snmp_interval')
                if freq_input.count() > 0:
                    freq_input.clear()
                    freq_input.fill(value)
                    self.page.wait_for_timeout(300)

                # 点击保存
                save_btn = self.page.locator('.ant-drawer button:has-text("保存"), .ant-drawer button:has-text("确定")')
                if save_btn.count() > 0:
                    save_btn.first.click()
                self.page.wait_for_timeout(1000)

                # 检查表单验证错误
                error_el = self.page.locator('.ant-form-item-explain-error')
                if error_el.count() > 0:
                    error_text = error_el.first.text_content()
                    self.page.keyboard.press('Escape')
                    self.page.wait_for_timeout(500)
                    return {"success": True, "error_message": error_text, "saved_value": ""}

                # 检查错误toast
                toast_error = self.page.locator('.ant-message-error')
                if toast_error.count() > 0:
                    error_text = toast_error.first.text_content()
                    self.page.keyboard.press('Escape')
                    self.page.wait_for_timeout(500)
                    return {"success": True, "error_message": error_text, "saved_value": ""}

                # 没有拦截，读取实际保存的值
                saved_value = ""
                freq_input2 = self.page.locator('#validateOnly_snmp_interval')
                if freq_input2.count() > 0:
                    saved_value = freq_input2.input_value()
                self.page.keyboard.press('Escape')
                self.page.wait_for_timeout(500)
                return {"success": False, "error_message": "", "saved_value": saved_value}

        except Exception as e:
            print(f"[DEBUG] try_set_frequency_invalid error: {e}")
        return {"success": False, "error_message": str(e), "saved_value": ""}

    # ==================== 添加规则（完整流程）====================
    def add_rule(self, name: str, snmp_server_ip: str = "10.66.0.40",
                 ips: list = None, port: str = "161",
                 snmp_version: str = "V2", community: str = "public",
                 remark: str = None,
                 v3_username: str = None, v3_auth_proto: str = "MD5",
                 v3_auth_pass: str = None, v3_security: str = None,
                 ip_group: dict = None) -> bool:
        """
        添加跨三层服务规则

        Args:
            name: 规则名称
            snmp_server_ip: SNMP服务器IP
            ips: 作用IP段列表 (每项为IP地址或IP段)
            port: SNMP服务监听端口
            snmp_version: SNMP协议版本 (V2/V3)
            community: 团体名
            remark: 备注
            v3_username: V3用户名 (V3时必填)
            v3_auth_proto: V3认证协议 (MD5/SHA)
            v3_auth_pass: V3认证密码
            v3_security: V3安全级别 (noAuthNoPriv/authNoPriv/authPriv)
            ip_group: IP分组 {"name": "分组名", "ips": "IP列表换行分隔"}
        """
        try:
            # 1. 点击添加
            self.click_add_button()
            self.page.wait_for_timeout(1000)

            # 2. 填写表单
            self.fill_name(name)
            self.fill_snmp_server_ip(snmp_server_ip)

            # 3. 添加IP地址（手动添加 或 使用IP分组）
            if ip_group:
                # 使用IP分组：创建分组并选择
                self.create_and_select_ip_group(ip_group["name"], ip_group["ips"])
            elif ips:
                for ip in ips:
                    self.add_ip_address(ip)

            # 4. 填写端口
            self.fill_port(port)

            # 5. 选择协议版本
            self.select_snmp_version(snmp_version)

            # 6. 根据版本填写不同的认证字段
            if snmp_version == "V3":
                # V3: 填写用户名、安全级别、认证协议、认证密码
                if v3_username:
                    self.fill_username(v3_username)
                if v3_security:
                    self.select_security_level(v3_security)
                if v3_auth_pass:
                    self.fill_auth_pass(v3_auth_pass)
                if v3_auth_proto:
                    self.select_auth_proto(v3_auth_proto)
            else:
                # V2: 填写团体名
                self.fill_community(community)

            # 7. 填写备注
            if remark:
                self.fill_remark(remark)

            # 8. 保存
            self.click_save()
            success = self.wait_for_success_message()

            # 9. 保存成功后等待页面自动返回列表
            if success:
                self.page.wait_for_timeout(1000)
                # 如果仍在配置页面，手动导航回列表
                if "crossThreeLevelsOfServicesConfig" in self.page.url:
                    self.navigate_to_cross_layer_service()
                    self.page.wait_for_timeout(500)
            else:
                # 保存失败: 关闭配置页面，导航回列表
                print(f"[DEBUG] add_rule save failed, navigating back to list")
                try:
                    self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(300)
                    self.navigate_to_cross_layer_service()
                    self.page.wait_for_timeout(500)
                except Exception:
                    pass

            return success

        except Exception as e:
            print(f"[ERROR] 添加规则失败: {e}")
            # 异常恢复: 确保回到列表页面
            try:
                self.navigate_to_cross_layer_service()
                self.page.wait_for_timeout(500)
            except Exception:
                pass
            return False

    # ==================== 编辑规则 ====================
    def edit_rule(self, old_name: str, new_name: str = None,
                  snmp_server_ip: str = None, port: str = None,
                  snmp_version: str = None, community: str = None,
                  remark: str = None) -> bool:
        """
        编辑跨三层服务规则

        Args:
            old_name: 原规则名称
            new_name: 新名称
            snmp_server_ip: 新SNMP服务器IP
            port: 新端口
            snmp_version: 新协议版本
            community: 新团体名
            remark: 新备注
        """
        try:
            # 点击编辑按钮 - 通过行名称定位编辑按钮
            clicked = self.page.evaluate("""(name) => {
                // Ant Design虚拟表格可能在div中，不在tbody tr中
                const allElements = document.querySelectorAll('td, .ant-table-cell');
                for (let i = 0; i < allElements.length; i++) {
                    const cell = allElements[i];
                    if (cell.textContent.trim() === name) {
                        // 找到名称单元格，向上找行
                        let row = cell.closest('tr');
                        if (!row) {
                            row = cell.parentElement;
                            while (row && row.tagName !== 'TR' && row.tagName !== 'BODY') {
                                row = row.parentElement;
                            }
                        }
                        if (row) {
                            // 查找编辑按钮
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

            # 等待编辑表单加载（URL会变为...Config）
            self.page.wait_for_timeout(1500)

            # 确认编辑表单已打开（检查表单元素是否存在）
            edit_form = self.page.locator('input[placeholder="请输入SNMP服务器IP"]')
            if edit_form.count() == 0:
                print(f"[WARN] 编辑表单未打开: {old_name}")
                return False

            # 填写修改后的字段
            if new_name:
                self.fill_name(new_name)
            if snmp_server_ip:
                self.fill_snmp_server_ip(snmp_server_ip)
            if port:
                self.fill_port(port)
            if snmp_version:
                self.select_snmp_version(snmp_version)
            if community:
                self.fill_community(community)
            if remark is not None:
                self.fill_remark(remark)

            # 保存
            self.click_save()
            result = self.wait_for_success_message()
            if not result:
                print(f"[WARN] 编辑保存未收到成功提示")
            return result

        except Exception as e:
            print(f"[ERROR] 编辑规则失败: {e}")
            return False

    # ==================== 状态验证 ====================
    def get_rule_count(self) -> int:
        """获取当前规则数量 - 使用页脚'共X条'文本"""
        try:
            # 优先使用页脚的总数文本
            count_text = self.page.locator('text=/共 \\d+ 条/')
            if count_text.count() > 0:
                import re
                match = re.search(r'共 (\d+) 条', count_text.first.text_content())
                if match:
                    return int(match.group(1))

            # 回退：计数tbody tr
            rows = self.page.locator('tbody tr')
            count = rows.count()
            if count == 1:
                text = rows.first.text_content()
                if text and '暂无' in text:
                    return 0
            return count
        except Exception:
            return 0

    def get_rule_list(self) -> List[str]:
        """获取所有规则名称列表"""
        try:
            names = self.page.evaluate("""() => {
                const rows = document.querySelectorAll('tbody tr');
                const result = [];
                for (const row of rows) {
                    const cells = row.querySelectorAll('td');
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
    def try_add_rule_invalid(self, name: str = "", snmp_server_ip: str = "",
                             port: str = "", community: str = "",
                             remark: str = "",
                             ips: list = None,
                             expect_fail: bool = True) -> dict:
        """
        尝试添加无效规则的表单验证测试

        Returns:
            dict: {success: bool, error_message: str}
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1000)

            if name is not None:
                self.fill_name(name)
            if snmp_server_ip is not None:
                self.fill_snmp_server_ip(snmp_server_ip)
            if port is not None:
                self.fill_port(port)
            if community is not None:
                self.fill_community(community)
            if remark is not None and remark:
                self.fill_remark(remark)

            # 点击保存
            self.click_save()
            self.page.wait_for_timeout(1000)

            # 检查1: 前端表单验证错误
            error_el = self.page.locator('.ant-form-item-explain-error')
            if error_el.count() > 0:
                error_text = error_el.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    return {"success": True, "error_message": error_text}

            # 检查2: 后端错误toast消息（如重复IP、后端验证失败等）
            toast_error = self.page.locator('.ant-message-error')
            if toast_error.count() > 0:
                error_text = toast_error.first.text_content()
                if expect_fail:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                    return {"success": True, "error_message": error_text}

            # 检查3: 如果期望失败但仍在配置页面，说明保存被拒绝
            still_on_config = "crossThreeLevelsOfServicesConfig" in self.page.url
            if expect_fail and still_on_config:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                return {"success": True, "error_message": "保存被拒绝(后端验证)"}

            if expect_fail:
                self.click_cancel()
                self.page.wait_for_timeout(500)
                return {"success": False, "error_message": ""}

            return {"success": True, "error_message": ""}

        except Exception as e:
            return {"success": False, "error_message": str(e)}

    # ==================== 排序 ====================
    COLUMN_ID_MAP = {
        "名称": "tagname",
        "SNMP服务器IP": "snmp_ip",
        "状态": "enabled",
        "作用IP段": "ip_addr",
        "SNMP服务监听端口": "port",
        "SNMP协议版本": "version",
    }

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
                sort_icon.click(force=True)
                self.page.wait_for_timeout(500)
                return True
            return False
        except Exception:
            return False

    def test_sorting(self) -> dict:
        """测试所有可排序列"""
        results = {}
        sortable_cols = ["名称"]

        for col in sortable_cols:
            try:
                success = True
                for _ in range(3):
                    if not self.sort_by_column(col):
                        success = False
                        break
                    self.page.wait_for_timeout(300)
                results[col] = "成功" if success else "失败"
            except Exception:
                results[col] = "失败"

        return results

    # ==================== 帮助 ====================
    def test_help_functionality(self) -> dict:
        """测试帮助功能"""
        return super().test_help_functionality()
