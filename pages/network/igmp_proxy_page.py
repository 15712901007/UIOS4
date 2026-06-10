"""
IGMP代理页面操作类

组播管理 > IGMP代理 页面
URL: /login#/networkConfiguration/multicastManagement (IGMP代理tab)

页面特点: 单记录配置页面(非表格), 包含:
- 开启/关闭 checkbox
- IGMP协议版本 combobox (IGMPv2/IGMPv3)
- 上联端口 combobox (WAN接口)
- 下联端口 combobox (LAN接口, 支持多选)
- 保存按钮
- 帮助按钮
"""
from playwright.sync_api import Page
from pages.base_page import BasePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class IgmpProxyPage(BasePage):
    """IGMP代理配置页面对象"""

    PAGE_URL = "/login#/networkConfiguration/multicastManagement"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url

    # ==================== 导航 ====================

    def navigate_to_igmp_proxy(self):
        """导航到IGMP代理页面"""
        url = f"{self.base_url}{self.PAGE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        # 确保在IGMP代理tab
        try:
            igmp_tab = self.page.get_by_role("tab", name="IGMP代理")
            if igmp_tab.count() > 0 and not igmp_tab.get_attribute("aria-selected"):
                igmp_tab.click()
                self.page.wait_for_timeout(500)
        except Exception:
            pass
        logger.info("[导航] 已到达IGMP代理页面")

    # ==================== 读取当前配置 ====================

    def is_enabled(self) -> bool:
        """检查IGMP代理是否已开启"""
        try:
            checkbox = self.page.get_by_role("checkbox", name="IGMP代理 开启")
            if checkbox.count() > 0:
                checked = checkbox.get_attribute("aria-checked") == "true" or checkbox.is_checked()
                return checked
        except Exception as e:
            logger.warning(f"[读取] 检查开启状态失败: {e}")
        return False

    def _get_combobox_value(self, combobox_name: str) -> str:
        """
        获取combobox当前选中的值

        DOM结构: input > span.ant-select-selection-search > span.ant-select-selection-wrap
        .ant-select-selection-item是input父级的兄弟(在.ant-select-selection-wrap内)
        """
        try:
            combobox = self.page.get_by_role("combobox", name=combobox_name)
            if combobox.count() > 0:
                # input上溯2级到.ant-select-selection-wrap, 其子元素包含selection-item
                item = combobox.locator("xpath=../..").locator(".ant-select-selection-item")
                if item.count() > 0:
                    return item.text_content().strip()
        except Exception as e:
            logger.warning(f"[读取] 获取{combobox_name}值失败: {e}")
        return ""

    def _click_combobox_dropdown(self, combobox_name: str):
        """
        点击combobox打开下拉框

        DOM结构: input > span.selection-search > span.selection-wrap > div.ant-select-selector
        点击.ant-select-selector(上溯3级)触发React事件打开下拉
        """
        combobox = self.page.get_by_role("combobox", name=combobox_name)
        if combobox.count() > 0:
            # 上溯3级到.ant-select-selector
            selector = combobox.locator("xpath=../../..")
            selector.click()

    def _select_dropdown_option(self, option_text: str) -> bool:
        """
        选择下拉框中可见的选项

        注意: Ant Design下拉弹出层portal到body, 多个select的DOM可能同时存在
        必须只匹配当前可见(is_visible)的选项, 避免误点其他下拉框的选项
        """
        option = self.page.locator('.ant-select-item-option').filter(has_text=option_text)
        count = option.count()
        for i in range(min(count, 20)):
            el = option.nth(i)
            if el.is_visible():
                el.click()
                return True
        logger.warning(f"[操作] 可见下拉选项未找到: {option_text} (DOM中共{count}个匹配)")
        self.page.keyboard.press("Escape")
        return False

    def get_version(self) -> str:
        """获取当前IGMP协议版本"""
        return self._get_combobox_value("IGMP协议版本")

    def get_upstream(self) -> str:
        """获取当前上联端口"""
        return self._get_combobox_value("上联端口")

    def get_downstream(self) -> str:
        """获取当前下联端口"""
        return self._get_combobox_value("下联端口")

    def get_current_config(self) -> dict:
        """获取当前所有配置"""
        return {
            "enabled": self.is_enabled(),
            "version": self.get_version(),
            "upstream": self.get_upstream(),
            "downstream": self.get_downstream(),
        }

    # ==================== 表单操作 ====================

    def toggle_enable(self, enable: bool = True):
        """开启/关闭IGMP代理"""
        try:
            checkbox = self.page.get_by_role("checkbox", name="IGMP代理 开启")
            if checkbox.count() > 0:
                current = checkbox.get_attribute("aria-checked") == "true" or checkbox.is_checked()
                if current != enable:
                    checkbox.click()
                    self.page.wait_for_timeout(300)
                    logger.info(f"[操作] IGMP代理: {'开启' if enable else '关闭'}")
                else:
                    logger.info(f"[操作] IGMP代理已是{'开启' if enable else '关闭'}状态，跳过")
        except Exception as e:
            logger.error(f"[操作] 切换开启状态失败: {e}")
            raise

    def select_version(self, version: str):
        """
        选择IGMP协议版本

        Args:
            version: "IGMPv2" 或 "IGMPv3"
        """
        try:
            current = self.get_version()
            if current == version:
                logger.info(f"[操作] 版本已是 {version}, 跳过")
                return

            self._click_combobox_dropdown("IGMP协议版本")
            self.page.wait_for_timeout(600)

            if self._select_dropdown_option(version):
                self.page.wait_for_timeout(300)
                logger.info(f"[操作] 选择版本: {version}")
        except Exception as e:
            logger.error(f"[操作] 选择版本失败: {e}")
            raise

    def select_upstream(self, upstream: str):
        """
        选择上联端口(WAN接口)

        Args:
            upstream: "wan1", "wan2" 等
        """
        try:
            current = self.get_upstream()
            if current == upstream:
                logger.info(f"[操作] 上联端口已是 {upstream}, 跳过")
                return

            self._click_combobox_dropdown("上联端口")
            self.page.wait_for_timeout(600)

            if self._select_dropdown_option(upstream):
                self.page.wait_for_timeout(300)
                logger.info(f"[操作] 选择上联端口: {upstream}")
        except Exception as e:
            logger.error(f"[操作] 选择上联端口失败: {e}")
            raise

    def select_downstream(self, downstream: str):
        """
        选择下联端口(LAN接口)

        Args:
            downstream: "全部", "lan1" 等
        """
        try:
            current = self.get_downstream()
            if current == downstream:
                logger.info(f"[操作] 下联端口已是 {downstream}, 跳过")
                return

            self._click_combobox_dropdown("下联端口")
            self.page.wait_for_timeout(600)

            if self._select_dropdown_option(downstream):
                self.page.wait_for_timeout(300)
                logger.info(f"[操作] 选择下联端口: {downstream}")
        except Exception as e:
            logger.error(f"[操作] 选择下联端口失败: {e}")
            raise

    def get_upstream_options(self) -> List[str]:
        """获取上联端口可选项列表(仅可见)"""
        options = []
        try:
            self._click_combobox_dropdown("上联端口")
            self.page.wait_for_timeout(500)
            items = self.page.locator('.ant-select-item-option')
            for i in range(min(items.count(), 30)):
                el = items.nth(i)
                if el.is_visible():
                    text = el.locator('.ant-select-item-option-content').text_content().strip()
                    if text:
                        options.append(text)
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception as e:
            logger.warning(f"[读取] 获取上联端口选项失败: {e}")
        return options

    def get_downstream_options(self) -> List[str]:
        """获取下联端口可选项列表(仅可见)"""
        options = []
        try:
            self._click_combobox_dropdown("下联端口")
            self.page.wait_for_timeout(500)
            items = self.page.locator('.ant-select-item-option')
            for i in range(min(items.count(), 30)):
                el = items.nth(i)
                if el.is_visible():
                    text = el.locator('.ant-select-item-option-content').text_content().strip()
                    if text:
                        options.append(text)
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception as e:
            logger.warning(f"[读取] 获取下联端口选项失败: {e}")
        return options

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
                    version: Optional[str] = None,
                    upstream: Optional[str] = None,
                    downstream: Optional[str] = None) -> bool:
        """
        配置IGMP代理并保存

        Args:
            enable: 是否开启, None表示不修改
            version: IGMP版本, None表示不修改
            upstream: 上联端口, None表示不修改
            downstream: 下联端口, None表示不修改

        Returns:
            保存是否成功
        """
        try:
            if enable is not None:
                self.toggle_enable(enable)
            if version is not None:
                self.select_version(version)
            if upstream is not None:
                self.select_upstream(upstream)
            if downstream is not None:
                self.select_downstream(downstream)

            # 等待下拉框动画完全结束再保存
            self.page.wait_for_timeout(800)
            self.click_save()
            self.page.wait_for_timeout(2000)

            # 检查成功消息(先用CSS选择器快速检测,再用文本匹配)
            success = False
            try:
                # 方法1: 直接检查.ant-message-success
                msg = self.page.locator(".ant-message-success")
                if msg.count() > 0 and msg.first.is_visible():
                    success = True
                else:
                    # 方法2: 使用BasePage的wait_for_success_message
                    success = self.wait_for_success_message()
            except Exception as e:
                logger.warning(f"[保存] 检测成功消息异常: {e}")
                success = self.wait_for_success_message()

            if success:
                logger.info("[保存] IGMP代理配置保存成功")
            else:
                # 检查错误消息
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
        """恢复IGMP代理默认配置(关闭)"""
        try:
            self.navigate_to_igmp_proxy()
            self.page.wait_for_timeout(500)
            # 如果已经是关闭状态,无需操作
            if not self.is_enabled():
                logger.info("[恢复] IGMP代理已处于关闭状态,无需恢复")
                return True
            result = self.save_config(enable=False)
            if result:
                logger.info("[恢复] IGMP代理已恢复默认(关闭)")
            return result
        except Exception as e:
            logger.error(f"[恢复] 恢复默认失败: {e}")
            return False

    # ==================== 帮助 ====================

    def click_help(self) -> bool:
        """点击帮助按钮"""
        try:
            # 按钮名称为 "question-circle 帮助" 或包含 "帮助"
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
