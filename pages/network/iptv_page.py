"""
IPTV透传页面操作类

组播管理 > IPTV透传 页面
URL: /login#/networkConfiguration/multicastManagement (IPTV透传tab)

页面特点: 单记录配置页面(非表格), 包含:
- 开启/关闭 checkbox  (#enabled)
- 透传模式 combobox   (#mode) — 网口透传 / vlan透传
- 输入口 combobox     (#wan_iface) — 如 "eth5(wan1)"
- 业务VLAN ID textbox (#wan_vlanid) — 输入口选择后动态出现(必填)
- 输出口 combobox     (#lan_iface) — 如 "eth3(wan3)"
- 内网VLAN ID textbox (#lan_vlanid) — 仅VLAN透传模式显示
- 保存按钮
- 帮助按钮

数据库: iptv_config表, 单记录(id=1)
字段: enabled(yes/no), mode(0=网口透传,1=VLAN透传),
      wan_iface(MAC地址), wan_vlanid, lan_iface(MAC地址), lan_vlanid

注意: 后端存储MAC地址而非接口名, wan_vlanid在所有模式下都必填
"""
from playwright.sync_api import Page
from pages.base_page import BasePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class IptvPage(BasePage):
    """IPTV透传配置页面对象"""

    PAGE_URL = "/login#/networkConfiguration/multicastManagement"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url

    # ==================== 导航 ====================

    def navigate_to_iptv(self):
        """导航到IPTV透传页面(每次强制刷新,确保表单与数据库同步)"""
        url = f"{self.base_url}{self.PAGE_URL}"
        current = self.page.url
        if 'multicastManagement' in current:
            # 已在组播管理页面, 用reload强制刷新(避免goto同URL不刷新)
            self.page.reload()
        else:
            self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1500)

        # 等待tab渲染, 点击IPTV透传tab (组播管理页面有3个tab: IGMP代理/IPTV透传/UDPXY设置)
        iptv_tab = self.page.get_by_role("tab", name="IPTV透传")
        try:
            iptv_tab.wait_for(state="visible", timeout=10000)
        except Exception as e:
            logger.error(f"[导航] 等待IPTV透传tab超时: {e}")
            # 列出当前所有tab用于诊断
            all_tabs = self.page.locator('[role="tablist"] [role="tab"]')
            tab_texts = [all_tabs.nth(i).text_content().strip() for i in range(all_tabs.count())]
            logger.error(f"[导航] 当前可见tabs: {tab_texts}")
            raise

        selected = iptv_tab.get_attribute("aria-selected")
        if selected != "true":
            iptv_tab.click()
            self.page.wait_for_timeout(1000)
            logger.info("[导航] 已切换到IPTV透传tab")
        else:
            logger.info("[导航] 已在IPTV透传tab")

        # 验证IPTV特有元素存在 (#mode是IPTV透传独有的选择器)
        mode_el = self.page.locator("#mode")
        if mode_el.count() == 0:
            logger.warning("[导航] 未检测到#mode, 尝试重新点击tab")
            iptv_tab.click()
            self.page.wait_for_timeout(1500)

        logger.info("[导航] 已到达IPTV透传页面")

    # ==================== 内部辅助: Ant Design Select ====================

    def _get_select_value(self, input_id: str) -> str:
        """
        获取指定ID的Ant Design Select当前值
        通过 div.ant-select-selector 包含 #input_id 定位, 读取 .ant-select-selection-item
        """
        try:
            selector = self.page.locator("div.ant-select-selector").filter(
                has=self.page.locator(f"#{input_id}")
            )
            if selector.count() > 0:
                item = selector.locator(".ant-select-selection-item")
                if item.count() > 0:
                    return item.text_content().strip()
        except Exception as e:
            logger.warning(f"[读取] 获取#{input_id}值失败: {e}")
        return ""

    def _click_select(self, input_id: str):
        """点击指定ID的Select控件打开下拉框"""
        selector = self.page.locator("div.ant-select-selector").filter(
            has=self.page.locator(f"#{input_id}")
        )
        if selector.count() > 0:
            selector.click()

    def _select_option(self, option_text: str) -> bool:
        """
        从已打开的下拉框中选择选项(支持子串匹配)
        下拉选项格式如 "eth5(wan1)", 传入 "wan1" 也能匹配
        """
        # 先精确匹配title属性
        exact = self.page.locator(f'.ant-select-item-option[title="{option_text}"]')
        for i in range(min(exact.count(), 5)):
            el = exact.nth(i)
            if el.is_visible():
                el.click()
                return True

        # 文本包含匹配
        option = self.page.locator(".ant-select-item-option").filter(has_text=option_text)
        for i in range(min(option.count(), 20)):
            el = option.nth(i)
            if el.is_visible():
                el.click()
                return True

        # 遍历所有可见选项做子串匹配
        all_items = self.page.locator(".ant-select-item-option")
        for i in range(min(all_items.count(), 30)):
            el = all_items.nth(i)
            if el.is_visible():
                text = el.text_content().strip()
                if option_text in text:
                    el.click()
                    return True

        logger.warning(f"[操作] 下拉选项未找到: {option_text}")
        self.page.keyboard.press("Escape")
        return False

    # ==================== 读取当前配置 ====================

    def is_enabled(self) -> bool:
        """检查IPTV透传是否已开启"""
        try:
            cb = self.page.locator("#enabled")
            if cb.count() > 0:
                return cb.is_checked()
        except Exception as e:
            logger.warning(f"[读取] 检查开启状态失败: {e}")
        return False

    def get_mode(self) -> str:
        """获取当前透传模式文本"""
        return self._get_select_value("mode")

    def get_input_port(self) -> str:
        """获取当前输入口文本(如 "eth5(wan1)")"""
        return self._get_select_value("wan_iface")

    def get_output_port(self) -> str:
        """获取当前输出口文本(如 "eth3(wan3)")"""
        return self._get_select_value("lan_iface")

    def get_wan_vlan_id(self) -> str:
        """获取业务VLAN ID"""
        try:
            textbox = self.page.locator("#wan_vlanid")
            if textbox.count() > 0 and textbox.is_visible():
                return textbox.input_value().strip()
        except Exception as e:
            logger.warning(f"[读取] 获取业务VLAN ID失败: {e}")
        return ""

    def get_lan_vlan_id(self) -> str:
        """获取内网VLAN ID"""
        try:
            textbox = self.page.locator("#lan_vlanid")
            if textbox.count() > 0 and textbox.is_visible():
                return textbox.input_value().strip()
        except Exception as e:
            logger.warning(f"[读取] 获取内网VLAN ID失败: {e}")
        return ""

    def get_current_config(self) -> dict:
        """获取当前所有配置"""
        return {
            "enabled": self.is_enabled(),
            "mode": self.get_mode(),
            "input_port": self.get_input_port(),
            "output_port": self.get_output_port(),
            "wan_vlan_id": self.get_wan_vlan_id(),
            "lan_vlan_id": self.get_lan_vlan_id(),
        }

    # ==================== 表单操作 ====================

    def toggle_enable(self, enable: bool = True):
        """开启/关闭IPTV透传"""
        try:
            cb = self.page.locator("#enabled")
            if cb.count() > 0:
                current = cb.is_checked()
                if current != enable:
                    cb.click()
                    self.page.wait_for_timeout(300)
                    logger.info(f"[操作] IPTV透传: {'开启' if enable else '关闭'}")
                else:
                    logger.info(f"[操作] IPTV透传已是{'开启' if enable else '关闭'}状态，跳过")
        except Exception as e:
            logger.error(f"[操作] 切换开启状态失败: {e}")
            raise

    def select_mode(self, mode: str):
        """
        选择透传模式

        Args:
            mode: "网口透传" 或 "vlan透传"
        """
        try:
            current = self.get_mode()
            if current == mode:
                logger.info(f"[操作] 透传模式已是 {mode}, 跳过")
                return

            self._click_select("mode")
            self.page.wait_for_timeout(600)

            if self._select_option(mode):
                self.page.wait_for_timeout(500)
                logger.info(f"[操作] 选择透传模式: {mode}")
        except Exception as e:
            logger.error(f"[操作] 选择透传模式失败: {e}")
            raise

    def select_input_port(self, port: str):
        """
        选择输入口

        Args:
            port: 接口名, 如 "wan1" 或完整名 "eth5(wan1)"
        """
        try:
            current = self.get_input_port()
            # 子串匹配: 已选 "eth5(wan1)" 时传 "wan1" 也视为已选中
            if current == port or (current and port in current):
                logger.info(f"[操作] 输入口已是 {port}, 跳过")
                return

            self._click_select("wan_iface")
            self.page.wait_for_timeout(600)

            if self._select_option(port):
                self.page.wait_for_timeout(500)
                logger.info(f"[操作] 选择输入口: {port}")
        except Exception as e:
            logger.error(f"[操作] 选择输入口失败: {e}")
            raise

    def select_output_port(self, port: str):
        """
        选择输出口

        Args:
            port: 接口名, 如 "wan3" 或完整名 "eth3(wan3)"
        """
        try:
            current = self.get_output_port()
            if current == port or (current and port in current):
                logger.info(f"[操作] 输出口已是 {port}, 跳过")
                return

            self._click_select("lan_iface")
            self.page.wait_for_timeout(600)

            if self._select_option(port):
                self.page.wait_for_timeout(500)
                logger.info(f"[操作] 选择输出口: {port}")
        except Exception as e:
            logger.error(f"[操作] 选择输出口失败: {e}")
            raise

    def fill_wan_vlan_id(self, vlan_id: str):
        """填写业务VLAN ID(输入口选择后动态出现)"""
        try:
            textbox = self.page.locator("#wan_vlanid")
            if textbox.count() > 0 and textbox.is_visible():
                textbox.click()
                self.page.keyboard.press("Control+a")
                textbox.type(vlan_id, delay=50)
                self.page.wait_for_timeout(300)
                logger.info(f"[操作] 填写业务VLAN ID: {vlan_id}")
            else:
                logger.warning("[操作] 业务VLAN ID输入框不可见(可能未选择输入口)")
        except Exception as e:
            logger.error(f"[操作] 填写业务VLAN ID失败: {e}")
            raise

    def fill_lan_vlan_id(self, vlan_id: str):
        """填写内网VLAN ID(仅VLAN透传模式显示)"""
        try:
            textbox = self.page.locator("#lan_vlanid")
            if textbox.count() > 0 and textbox.is_visible():
                textbox.click()
                self.page.keyboard.press("Control+a")
                textbox.type(vlan_id, delay=50)
                self.page.wait_for_timeout(300)
                logger.info(f"[操作] 填写内网VLAN ID: {vlan_id}")
            else:
                logger.warning("[操作] 内网VLAN ID输入框不可见(可能不在VLAN透传模式)")
        except Exception as e:
            logger.error(f"[操作] 填写内网VLAN ID失败: {e}")
            raise

    def get_input_port_options(self) -> List[str]:
        """获取输入口可选项列表"""
        return self._get_port_options("wan_iface")

    def get_output_port_options(self) -> List[str]:
        """获取输出口可选项列表"""
        return self._get_port_options("lan_iface")

    def _get_port_options(self, input_id: str) -> List[str]:
        """获取指定端口下拉框的选项(用JS读取更可靠, portal渲染下拉框is_visible不准)"""
        options = []
        try:
            self._click_select(input_id)
            self.page.wait_for_timeout(800)
            # 用JS直接读取所有下拉选项(包括portal渲染到body的)
            options = self.page.evaluate('''() => {
                const items = document.querySelectorAll('.ant-select-item-option');
                const results = [];
                items.forEach(el => {
                    // 用getBoundingClientRect判断是否可见(不依赖is_visible)
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
            logger.warning(f"[读取] 获取{input_id}选项失败: {e}")
        return options or []

    # ==================== 保存 ====================

    def click_save(self) -> bool:
        """点击保存按钮"""
        try:
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() > 0:
                save_btn.click()
                self.page.wait_for_timeout(1000)
                return True
        except Exception as e:
            logger.error(f"[操作] 点击保存失败: {e}")
        return False

    def save_config(self, enable: Optional[bool] = None,
                    mode: Optional[str] = None,
                    input_port: Optional[str] = None,
                    output_port: Optional[str] = None,
                    wan_vlan_id: Optional[str] = None,
                    lan_vlan_id: Optional[str] = None) -> bool:
        """
        配置IPTV透传并保存

        Args:
            enable: 是否开启, None不修改
            mode: 透传模式("网口透传"/"vlan透传"), None不修改
            input_port: 输入口, 如 "wan1", None不修改
            output_port: 输出口, 如 "wan3", None不修改
            wan_vlan_id: 业务VLAN ID(必填, 输入口选择后出现), None不修改
            lan_vlan_id: 内网VLAN ID(VLAN透传模式必填), None不修改

        Returns:
            保存是否成功
        """
        try:
            if enable is not None:
                self.toggle_enable(enable)
            if mode is not None:
                self.select_mode(mode)
            if input_port is not None:
                self.select_input_port(input_port)
            if wan_vlan_id is not None:
                self.fill_wan_vlan_id(wan_vlan_id)
            if output_port is not None:
                self.select_output_port(output_port)
            if lan_vlan_id is not None:
                self.fill_lan_vlan_id(lan_vlan_id)

            # 等待表单状态稳定
            self.page.wait_for_timeout(800)
            self.click_save()
            self.page.wait_for_timeout(2000)

            # 双重检测成功消息
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
                logger.info("[保存] IPTV透传配置保存成功")
            else:
                error = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if error.count() > 0:
                    logger.error(f"[保存] 配置保存失败: {error.first.text_content()}")
                else:
                    logger.warning("[保存] 未检测到成功/失败消息")
            return success
        except Exception as e:
            logger.error(f"[保存] 配置保存异常: {e}")
            return False

    def restore_default(self) -> bool:
        """恢复IPTV透传默认配置(关闭)"""
        try:
            self.navigate_to_iptv()
            self.page.wait_for_timeout(500)
            if not self.is_enabled():
                logger.info("[恢复] IPTV透传已处于关闭状态,无需恢复")
                return True
            result = self.save_config(enable=False)
            if result:
                logger.info("[恢复] IPTV透传已恢复默认(关闭)")
            return result
        except Exception as e:
            logger.error(f"[恢复] 恢复默认失败: {e}")
            return False

    # ==================== 帮助 ====================

    def click_help(self) -> bool:
        """点击帮助按钮"""
        try:
            help_btn = self.page.locator('button').filter(has_text="帮助")
            if help_btn.count() > 0:
                help_btn.last.click()
                self.page.wait_for_timeout(500)
                return True
        except Exception as e:
            logger.warning(f"[帮助] 点击帮助失败: {e}")
        return False

    def is_help_panel_visible(self) -> bool:
        """检查帮助面板是否可见"""
        try:
            panel = self.page.locator(".ant-drawer, .ant-modal, [role='dialog']")
            return panel.count() > 0 and panel.is_visible()
        except Exception:
            return False

    def close_help_panel(self):
        """关闭帮助面板"""
        try:
            close_btn = self.page.locator(".ant-drawer-close, .ant-modal-close")
            if close_btn.count() > 0:
                close_btn.click()
            else:
                self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception:
            self.page.keyboard.press("Escape")
