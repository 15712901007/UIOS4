"""
基础页面类

所有页面对象的父类，提供通用操作方法
"""
from playwright.sync_api import Page, Locator
from typing import Optional
import time


class BasePage:
    """基础页面类"""

    def __init__(self, page: Page):
        """
        初始化页面

        Args:
            page: Playwright Page对象
        """
        self.page = page

    def navigate(self, url: str):
        """
        导航到指定URL

        Args:
            url: 目标URL
        """
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")

    def wait_for_selector(self, selector: str, timeout: int = 30000) -> Locator:
        """
        等待选择器出现

        Args:
            selector: CSS选择器
            timeout: 超时时间（毫秒）

        Returns:
            Locator对象
        """
        return self.page.wait_for_selector(selector, timeout=timeout)

    def wait_for_text(self, text: str, timeout: int = 30000):
        """
        等待文本出现

        Args:
            text: 要等待的文本
            timeout: 超时时间（毫秒）
        """
        self.page.wait_for_selector(f"text={text}", timeout=timeout)

    def click(self, selector: str):
        """
        点击元素

        Args:
            selector: CSS选择器
        """
        self.page.click(selector)

    def fill(self, selector: str, value: str):
        """
        填充输入框

        Args:
            selector: CSS选择器
            value: 要填充的值
        """
        self.page.fill(selector, value)

    def get_text(self, selector: str) -> str:
        """
        获取元素文本

        Args:
            selector: CSS选择器

        Returns:
            元素文本内容
        """
        return self.page.locator(selector).inner_text()

    def is_visible(self, selector: str) -> bool:
        """
        检查元素是否可见

        Args:
            selector: CSS选择器

        Returns:
            是否可见
        """
        return self.page.locator(selector).is_visible()

    def is_enabled(self, selector: str) -> bool:
        """
        检查元素是否可操作

        Args:
            selector: CSS选择器

        Returns:
            是否可操作
        """
        return self.page.locator(selector).is_enabled()

    def screenshot(self, path: str):
        """
        截图

        Args:
            path: 截图保存路径
        """
        self.page.screenshot(path=path)

    def wait_for_timeout(self, timeout: int):
        """
        等待指定时间

        Args:
            timeout: 等待时间（毫秒）
        """
        self.page.wait_for_timeout(timeout)

    def reload(self):
        """刷新页面"""
        self.page.reload()
        self.page.wait_for_load_state("networkidle")

    def get_url(self) -> str:
        """
        获取当前URL

        Returns:
            当前页面URL
        """
        return self.page.url

    def get_title(self) -> str:
        """
        获取页面标题

        Returns:
            页面标题
        """
        return self.page.title()

    def wait_for_success_message(self, timeout: int = 10000) -> bool:
        """
        等待成功消息出现

        Args:
            timeout: 超时时间（毫秒）

        Returns:
            是否出现成功消息
        """
        # 先检查是否有错误消息，如果有则返回False
        error_messages = [
            "输入有误",
            "请检查后重试",
            "失败",
            "错误",
            "error",
            "Error",
            "fail",
            "Fail",
            "必填",
            "不能为空",
            "格式不正确",
            "请输入",
            "请选择",
        ]

        # 等待一小段时间让消息出现
        self.page.wait_for_timeout(500)

        # 检查是否有错误消息
        for err_msg in error_messages:
            try:
                err_locator = self.page.locator(f"text={err_msg}")
                if err_locator.count() > 0:
                    # 排除一些可能出现在正常内容中的词
                    if err_msg in ["请输入", "请选择"]:
                        # 检查是否是红色错误提示（ant-form-item-explain-error）
                        error_explain = self.page.locator(".ant-form-item-explain-error")
                        if error_explain.count() > 0:
                            print(f"[DEBUG] 检测到表单验证错误: {error_explain.first.inner_text()}")
                            return False
                    else:
                        # 检查是否是错误提示框（红色背景）
                        error_box = self.page.locator(f".ant-message-error, .ant-notification-error, .ant-alert-error")
                        if error_box.count() > 0:
                            print(f"[DEBUG] 检测到错误消息: {err_msg}")
                            return False
                        # 也检查普通文本中是否有错误提示
                        if err_locator.count() > 0:
                            # 检查错误提示是否可见
                            if err_locator.first.is_visible():
                                print(f"[DEBUG] 检测到错误提示: {err_msg}")
                                return False
            except Exception:
                continue

        # 检查表单是否有红色错误提示（ant-form-item-has-error）
        try:
            form_error = self.page.locator(".ant-form-item-has-error, .ant-form-item-explain-error")
            if form_error.count() > 0:
                print(f"[DEBUG] 检测到表单验证错误状态")
                return False
        except Exception:
            pass

        success_messages = [
            "操作成功",
            "添加成功",
            "保存成功",
            "删除成功",
            "修改成功",
            "启用成功",
            "停用成功",
            "导入成功",
            "导出成功",
        ]

        for msg in success_messages:
            try:
                locator = self.page.locator(f"text={msg}")
                if locator.count() > 0:
                    return True
                # 也尝试等待
                self.page.wait_for_selector(f"text={msg}", timeout=2000)
                return True
            except Exception:
                continue

        # 检查Ant Design的成功消息组件
        try:
            success_toast = self.page.locator(".ant-message-success, .ant-notification-success")
            if success_toast.count() > 0:
                return True
        except Exception:
            pass

        return False

    def wait_for_error_message(self, timeout: int = 5000) -> Optional[str]:
        """
        等待错误消息出现

        Args:
            timeout: 超时时间（毫秒）

        Returns:
            错误消息文本，如果没有则返回None
        """
        try:
            error_locator = self.page.locator(".ant-message-error, .error-message, [class*='error']")
            error_locator.wait_for(timeout=timeout)
            return error_locator.inner_text()
        except Exception:
            return None

    def confirm_dialog(self):
        """确认对话框（点击确定按钮）"""
        self.page.get_by_role("button", name="确定").click()

    def cancel_dialog(self):
        """取消对话框（点击取消按钮）"""
        self.page.get_by_role("button", name="取消").click()

    # ==================== 帮助功能 ====================

    def click_help_icon(self) -> bool:
        """
        点击右下角帮助图标

        Returns:
            是否点击成功
        """
        try:
            # 尝试多种可能的选择器
            selectors = [
                ".anticon-question-circle",  # Ant Design 问号图标
                "[class*='help']",
                "[class*='question']",
                "svg[data-icon='question-circle']",
                ".help-icon",
            ]

            for selector in selectors:
                locator = self.page.locator(selector)
                if locator.count() > 0:
                    locator.first.click()
                    self.page.wait_for_timeout(500)
                    return True

            # 如果上述选择器都找不到，尝试查找右下角的悬浮按钮
            float_button = self.page.locator(".ant-float-button, [class*='float-btn']")
            if float_button.count() > 0:
                float_button.first.click()
                self.page.wait_for_timeout(500)
                return True

            return False
        except Exception as e:
            print(f"点击帮助图标失败: {e}")
            return False

    def is_help_panel_visible(self) -> bool:
        """
        检查帮助面板是否可见

        Returns:
            帮助面板是否可见
        """
        try:
            # 检查帮助面板/弹出框是否出现
            selectors = [
                ".ant-popover:visible",
                "[class*='help-panel']:visible",
                "[class*='help-content']:visible",
                ".ant-modal:visible",
            ]

            for selector in selectors:
                if self.page.locator(selector).count() > 0:
                    return True

            return False
        except Exception:
            return False

    def get_help_text(self) -> str:
        """
        获取帮助面板中的文本内容

        Returns:
            帮助文本内容
        """
        try:
            # 尝试获取帮助面板中的文本
            help_selectors = [
                ".ant-popover:visible .ant-popover-inner-content",
                "[class*='help-panel']:visible",
                "[class*='help-content']:visible",
                ".ant-modal:visible .ant-modal-body",
            ]

            for selector in help_selectors:
                locator = self.page.locator(selector)
                if locator.count() > 0:
                    return locator.first.inner_text()

            return ""
        except Exception as e:
            print(f"获取帮助文本失败: {e}")
            return ""

    def click_help_link(self) -> bool:
        """
        点击帮助链接跳转到帮助页面

        Returns:
            是否点击成功
        """
        try:
            # 记录当前URL
            current_url = self.page.url

            # 查找帮助链接 - 扩展选择器范围
            help_link_selectors = [
                # 帮助面板中的链接
                ".ant-popover a",
                ".ant-popover a[href]",
                "[class*='help'] a",
                "a[href*='help']",
                # 文本匹配
                "a:has-text('帮助')",
                "a:has-text('帮助文档')",
                "a:has-text('使用说明')",
                "a:has-text('查看')",
                "a:has-text('详情')",
                "a:has-text('了解更多')",
                # 可点击的元素
                "[class*='link']",
                "[class*='more']",
                # 按钮
                "button:has-text('帮助')",
            ]

            for selector in help_link_selectors:
                try:
                    locator = self.page.locator(selector)
                    if locator.count() > 0 and locator.first.is_visible():
                        locator.first.click()
                        self.page.wait_for_timeout(1000)
                        # 检查URL是否变化或是否有新页面
                        new_url = self.page.url
                        if new_url != current_url or self.has_new_page_opened():
                            print(f"[DEBUG] 通过选择器 '{selector}' 成功跳转")
                            return True
                except Exception:
                    continue

            return False
        except Exception as e:
            print(f"点击帮助链接失败: {e}")
            return False

    def has_new_page_opened(self) -> bool:
        """
        检查是否有新页面打开

        Returns:
            是否有新页面
        """
        try:
            # 获取所有页面上下文
            context = self.page.context
            return len(context.pages) > 1
        except Exception:
            return False

    def close_help_panel(self) -> bool:
        """
        关闭帮助面板

        Returns:
            是否关闭成功
        """
        try:
            # 尝试多种关闭方式
            close_selectors = [
                ".ant-popover .ant-popover-close",
                ".ant-modal-close",
                ".ant-modal .ant-modal-close",
                "[aria-label='Close']",
                "[aria-label='关闭']",
            ]

            for selector in close_selectors:
                locator = self.page.locator(selector)
                if locator.count() > 0:
                    locator.first.click()
                    self.page.wait_for_timeout(300)
                    return True

            # 如果没有关闭按钮，点击页面其他地方关闭
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
            return True
        except Exception:
            return False

    def test_help_functionality(self) -> dict:
        """
        测试帮助功能的完整流程

        Returns:
            测试结果字典
        """
        result = {
            "icon_clickable": False,
            "panel_visible": False,
            "has_content": False,
            "content_text": "",
            "link_clickable": False,
            "new_page_opened": False,
            "url_changed": False,
            "can_close": False,
        }

        try:
            # 记录初始URL
            initial_url = self.page.url

            # 1. 点击帮助图标
            result["icon_clickable"] = self.click_help_icon()
            if not result["icon_clickable"]:
                return result

            self.page.wait_for_timeout(500)

            # 2. 检查帮助面板是否显示
            result["panel_visible"] = self.is_help_panel_visible()

            # 3. 获取帮助内容
            if result["panel_visible"]:
                result["content_text"] = self.get_help_text()
                result["has_content"] = len(result["content_text"]) > 0

            # 4. 尝试点击帮助链接（如果有）
            result["link_clickable"] = self.click_help_link()

            if result["link_clickable"]:
                self.page.wait_for_timeout(1000)
                # 5. 检查是否打开了新页面
                result["new_page_opened"] = self.has_new_page_opened()

                # 检查URL是否变化
                current_url = self.page.url
                result["url_changed"] = current_url != initial_url

                # 如果打开了新页面，关闭它
                if result["new_page_opened"]:
                    context = self.page.context
                    if len(context.pages) > 1:
                        new_page = context.pages[-1]
                        new_page.close()
                        self.page.wait_for_timeout(500)

                # 如果URL变化了，返回原页面
                if result["url_changed"] and not result["new_page_opened"]:
                    self.page.goto(initial_url)
                    self.page.wait_for_load_state("networkidle")
                    self.page.wait_for_timeout(500)

            # 6. 关闭帮助面板
            result["can_close"] = self.close_help_panel()

            return result
        except Exception as e:
            print(f"测试帮助功能时出错: {e}")
            return result
