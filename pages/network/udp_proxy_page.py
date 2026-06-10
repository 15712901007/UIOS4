"""
UDPXY设置页面操作类

组播管理 > UDPXY设置 页面
URL: /login#/networkConfiguration/multicastManagement (UDPXY设置tab)

页面特点: 表格型页面(多记录CRUD), 继承IkuaiTablePage
- 添加: 弹窗dialog, 字段: 名称(必填), 信号源接口(combobox), 服务端口, 订阅周期(秒), 外网访问(单选)
- 编辑: 弹窗dialog, 同添加
- 行操作: 编辑/停用/启用/删除
- 批量操作: 全选/批量启用/批量停用/批量删除
- 导入/导出

数据库: udp_proxy表
字段: id, enabled(yes/no), tagname(唯一), interface(接口名),
      renew_time(订阅周期秒, 0=不订阅), listen_port(服务端口), access(0=不允许/1=允许外网访问)

后端: /usr/ikuai/function/udp_proxy (add/del/edit/up/down/show/IMPORT/EXPORT)
脚本: /usr/ikuai/script/udp_proxy.sh
进程: udpxy -a 0.0.0.0 -p $listen_port -c 4500 -m $interface -B 1048576 [-M $renew_time]
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class UdpProxyPage(IkuaiTablePage):
    """UDPXY设置页面对象 - 表格型"""

    MODULE_NAME = "udp_proxy"
    PAGE_URL = "/login#/networkConfiguration/multicastManagement"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def navigate_to_udp_proxy(self):
        """导航到UDPXY设置页面(强制刷新确保数据同步)"""
        url = f"{self.base_url}{self.PAGE_URL}"
        current = self.page.url
        if 'multicastManagement' in current:
            # 已在组播管理页面, 用reload强制刷新
            self.page.reload()
        else:
            self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1500)

        # 点击UDPXY设置tab
        udp_tab = self.page.get_by_role("tab", name="UDPXY设置")
        try:
            udp_tab.wait_for(state="visible", timeout=10000)
        except Exception as e:
            logger.error(f"[导航] 等待UDPXY设置tab超时: {e}")
            all_tabs = self.page.locator('[role="tablist"] [role="tab"]')
            tab_texts = [all_tabs.nth(i).text_content().strip() for i in range(all_tabs.count())]
            logger.error(f"[导航] 当前可见tabs: {tab_texts}")
            raise

        selected = udp_tab.get_attribute("aria-selected")
        if selected != "true":
            udp_tab.click()
            self.page.wait_for_timeout(1000)
            logger.info("[导航] 已切换到UDPXY设置tab")
        else:
            logger.info("[导航] 已在UDPXY设置tab")

        return self

    # ==================== 弹窗表单字段 ====================

    def fill_tagname(self, name: str):
        """填写名称(必填)"""
        textbox = self.page.get_by_role("textbox", name="名称")
        if textbox.count() > 0:
            textbox.click()
            self.page.keyboard.press("Control+a")
            textbox.type(name, delay=50)
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 填写名称: {name}")

    def select_interface(self, iface: str):
        """
        选择信号源接口

        Args:
            iface: 接口名, 如 "lan1", "wan1", "wan2", "wan3"
        """
        try:
            # 点击combobox打开下拉
            combobox = self.page.get_by_role("combobox", name="信号源接口")
            if combobox.count() == 0:
                logger.warning("[操作] 未找到信号源接口combobox")
                return

            # 点击selector容器而非input(Ant Design遮挡问题)
            selector = combobox.locator("xpath=ancestor::div[contains(@class,'ant-select-selector')]")
            if selector.count() > 0:
                selector.click()
            else:
                # 备用: 点击selection-item
                item_span = combobox.locator("xpath=following-sibling::span[contains(@class,'ant-select-selection-item')]")
                if item_span.count() > 0:
                    item_span.click()
                else:
                    combobox.click(force=True)
            self.page.wait_for_timeout(600)

            # 选择选项(精确匹配或子串匹配)
            option = self.page.locator(f'.ant-select-item-option[title="{iface}"]')
            if option.count() > 0:
                for i in range(option.count()):
                    if option.nth(i).is_visible():
                        option.nth(i).click()
                        self.page.wait_for_timeout(300)
                        logger.info(f"[操作] 选择接口: {iface}")
                        return

            # 文本匹配
            all_items = self.page.locator(".ant-select-item-option")
            for i in range(min(all_items.count(), 20)):
                el = all_items.nth(i)
                if el.is_visible():
                    text = el.text_content().strip()
                    if iface in text:
                        el.click()
                        self.page.wait_for_timeout(300)
                        logger.info(f"[操作] 选择接口: {iface}(匹配: {text})")
                        return

            logger.warning(f"[操作] 未找到接口选项: {iface}")
            self.page.keyboard.press("Escape")
        except Exception as e:
            logger.error(f"[操作] 选择接口失败: {e}")
            raise

    def fill_listen_port(self, port: str):
        """填写服务端口"""
        textbox = self.page.get_by_role("textbox", name="服务端口")
        if textbox.count() > 0:
            textbox.click()
            self.page.keyboard.press("Control+a")
            textbox.type(port, delay=50)
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 填写服务端口: {port}")

    def fill_renew_time(self, seconds: str):
        """填写订阅周期(秒)"""
        textbox = self.page.get_by_role("textbox", name="订阅周期")
        if textbox.count() > 0:
            textbox.click()
            self.page.keyboard.press("Control+a")
            textbox.type(seconds, delay=50)
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 填写订阅周期: {seconds}秒")

    def set_access(self, allow: bool = True):
        """
        设置外网访问

        Args:
            allow: True=允许, False=不允许
        """
        label = "允许" if allow else "不允许"
        # exact=True避免"允许"匹配到"不允许"
        radio = self.page.get_by_role("radio", name=label, exact=True)
        if radio.count() > 0:
            if not radio.is_checked():
                radio.click()
                self.page.wait_for_timeout(300)
                logger.info(f"[操作] 外网访问: {label}")
            else:
                logger.info(f"[操作] 外网访问已是: {label}")

    # ==================== 读取当前值 ====================

    def get_interface_options(self) -> List[str]:
        """获取信号源接口可选项列表(用JS读取更可靠)"""
        options = []
        try:
            combobox = self.page.get_by_role("combobox", name="信号源接口")
            if combobox.count() == 0:
                return options

            selector = combobox.locator("xpath=ancestor::div[contains(@class,'ant-select-selector')]")
            if selector.count() > 0:
                selector.click()
            else:
                combobox.click(force=True)
            self.page.wait_for_timeout(600)

            options = self.page.evaluate('''() => {
                const items = document.querySelectorAll('.ant-select-item-option');
                const results = [];
                items.forEach(el => {
                    const rect = el.getBoundingClientRect();
                    if (rect.height > 0) {
                        const text = el.textContent?.trim();
                        if (text) results.push(text);
                    }
                });
                return results;
            }''')
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception as e:
            logger.warning(f"[读取] 获取接口选项失败: {e}")
        return options or []

    # ==================== 高层操作 ====================

    def add_rule(self, tagname: str, interface: str = "lan1",
                 listen_port: str = "9000", renew_time: str = "0",
                 access_allow: bool = True) -> bool:
        """
        添加一条UDPXY规则

        Args:
            tagname: 名称(必填)
            interface: 信号源接口, 默认"lan1"
            listen_port: 服务端口, 默认"9000"
            renew_time: 订阅周期(秒), 默认"0"(不订阅)
            access_allow: 是否允许外网访问, 默认True

        Returns:
            是否添加成功
        """
        try:
            self.click_add_button()

            # 等待弹窗
            dialog = self.page.locator("[role='dialog']")
            dialog.wait_for(state="visible", timeout=5000)
            self.page.wait_for_timeout(500)

            # 填写表单
            self.fill_tagname(tagname)
            self.select_interface(interface)
            self.fill_listen_port(listen_port)
            self.fill_renew_time(renew_time)
            self.set_access(access_allow)

            self.page.wait_for_timeout(500)

            # 点击确定
            confirm_btn = self.page.get_by_role("button", name="确定")
            if confirm_btn.count() > 0:
                confirm_btn.click()
            else:
                self.click_save()

            self.page.wait_for_timeout(2000)

            # 检测成功
            success = False
            try:
                msg = self.page.locator(".ant-message-success")
                if msg.count() > 0 and msg.first.is_visible():
                    success = True
                else:
                    success = self.wait_for_success_message()
            except Exception:
                success = self.wait_for_success_message()

            if success:
                logger.info(f"[添加] UDPXY规则添加成功: {tagname}")
            else:
                error = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if error.count() > 0:
                    logger.error(f"[添加] 添加失败: {error.first.text_content()}")
                else:
                    logger.warning("[添加] 未检测到成功/失败消息")
            return success
        except Exception as e:
            logger.error(f"[添加] 添加异常: {e}")
            self.close_modal_if_exists()
            return False

    def edit_rule_modify(self, rule_name: str, **kwargs) -> bool:
        """
        编辑规则(修改指定字段)

        Args:
            rule_name: 规则名称
            **kwargs: 要修改的字段(tagname/interface/listen_port/renew_time/access_allow)

        Returns:
            是否编辑成功
        """
        try:
            self.edit_rule(rule_name)
            self.page.wait_for_timeout(500)

            # 等待编辑弹窗
            dialog = self.page.locator("[role='dialog']")
            dialog.wait_for(state="visible", timeout=5000)
            self.page.wait_for_timeout(500)

            # 修改指定字段
            if "tagname" in kwargs:
                self.fill_tagname(kwargs["tagname"])
            if "interface" in kwargs:
                self.select_interface(kwargs["interface"])
            if "listen_port" in kwargs:
                self.fill_listen_port(kwargs["listen_port"])
            if "renew_time" in kwargs:
                self.fill_renew_time(kwargs["renew_time"])
            if "access_allow" in kwargs:
                self.set_access(kwargs["access_allow"])

            self.page.wait_for_timeout(500)

            # 点击确定
            confirm_btn = self.page.get_by_role("button", name="确定")
            if confirm_btn.count() > 0:
                confirm_btn.click()
            else:
                self.click_save()

            self.page.wait_for_timeout(2000)

            success = False
            try:
                msg = self.page.locator(".ant-message-success")
                if msg.count() > 0 and msg.first.is_visible():
                    success = True
                else:
                    success = self.wait_for_success_message()
            except Exception:
                success = self.wait_for_success_message()

            if success:
                logger.info(f"[编辑] 规则编辑成功: {rule_name}")
            return success
        except Exception as e:
            logger.error(f"[编辑] 编辑异常: {e}")
            self.close_modal_if_exists()
            return False

    def get_rule_list(self) -> List[dict]:
        """获取当前表格中的规则列表(通过JS读取)"""
        rules = []
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)

            rules = self.page.evaluate('''() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                rows.forEach(row => {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length >= 6) {
                        // cells: [checkbox] [名称+状态] [接口] [端口] [订阅周期] [外网访问] [操作]
                        const nameText = cells[1]?.textContent?.trim() || '';
                        const ifaceText = cells[2]?.textContent?.trim() || '';
                        const portText = cells[3]?.textContent?.trim() || '';
                        const renewText = cells[4]?.textContent?.trim() || '';
                        const accessText = cells[5]?.textContent?.trim() || '';
                        const opText = cells[6]?.textContent?.trim() || '';

                        result.push({
                            name: nameText,
                            interface: ifaceText,
                            listen_port: portText,
                            renew_time: renewText,
                            access: accessText,
                            enabled: opText.includes('停用')
                        });
                    }
                });
                return result;
            }''')
        except Exception as e:
            logger.warning(f"[读取] 获取规则列表失败: {e}")
        return rules or []

    # ==================== 搜索重写 ====================

    def search_rule(self, keyword: str):
        """搜索规则(重写基类, 添加networkidle等待确保过滤生效)"""
        search_input = self.page.get_by_placeholder("请输入搜索内容")
        search_input.click()
        search_input.clear()
        search_input.fill(keyword)
        self.page.wait_for_timeout(300)
        search_input.press("Enter")
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(800)
        logger.info(f"[操作] 搜索: {keyword}")
        return self

    def clear_search(self):
        """清除搜索(重写基类)"""
        search_input = self.page.get_by_placeholder("请输入搜索内容")
        if search_input.count() > 0 and search_input.is_visible():
            search_input.click()
            search_input.clear()
            self.page.wait_for_timeout(200)
            search_input.press("Enter")
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
        return self

    # ==================== 表格特殊DOM处理 ====================

    def _click_rule_button(self, rule_name: str, button_name: str) -> bool:
        """
        重写基类方法, 适配UDPXY表格DOM结构

        UDPXY表格使用div布局而非标准tr/td:
        表格行是 div class="ant-table-row"(有data-row-key属性)
        行内按钮在最后一个cell中

        Args:
            rule_name: 规则名称
            button_name: 按钮名称(编辑/停用/启用/删除)
        """
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(300)

        try:
            # 用JS遍历DOM找到包含规则名的行, 然后点击对应按钮
            js_code = f"""() => {{
                // 查找所有表格行
                const rows = document.querySelectorAll('.ant-table-row');
                for (const row of rows) {{
                    const cells = row.querySelectorAll('.ant-table-cell');
                    // cells[1]包含名称(第一个是checkbox)
                    if (cells.length >= 2 && cells[1].textContent.includes('{rule_name}')) {{
                        const buttons = row.querySelectorAll('button');
                        for (const btn of buttons) {{
                            if (btn.textContent.includes('{button_name}')) {{
                                btn.click();
                                return true;
                            }}
                        }}
                    }}
                }}
                return false;
            }}"""
            result = self.page.evaluate(js_code)
            if result:
                return True

            # 备用: 使用基类方法(通过文本定位)
            return super()._click_rule_button(rule_name, button_name)
        except Exception as e:
            logger.warning(f"[操作] 点击按钮失败 {button_name}/{rule_name}: {e}")
            return False
