"""
登录页面类

处理爱快路由器登录相关操作
"""
from playwright.sync_api import Page
from pages.base_page import BasePage
from typing import Optional


class LoginPage(BasePage):
    """登录页面类"""

    # 页面URL
    LOGIN_URL = "/login#/login"

    def __init__(self, page: Page, base_url: str):
        """
        初始化登录页面

        Args:
            page: Playwright Page对象
            base_url: 基础URL（如 http://10.66.0.150）
        """
        super().__init__(page)
        self.base_url = base_url

    def navigate_to_login(self):
        """导航到登录页面"""
        self.page.goto(f"{self.base_url}{self.LOGIN_URL}")
        self.page.wait_for_load_state("networkidle")

    def fill_username(self, username: str):
        """
        填写用户名

        Args:
            username: 用户名
        """
        self.page.get_by_role("textbox", name="请输入用户名").fill(username)

    def fill_password(self, password: str):
        """
        填写密码

        Args:
            password: 密码
        """
        self.page.get_by_role("textbox", name="请输入密码").fill(password)

    def click_login_button(self):
        """点击登录按钮"""
        self.page.get_by_role("button", name="登录").click()

    def check_remember_password(self):
        """勾选记住密码"""
        self.page.get_by_role("checkbox", name="记住密码").check()

    def uncheck_remember_password(self):
        """取消勾选记住密码"""
        self.page.get_by_role("checkbox", name="记住密码").uncheck()

    def click_forgot_password(self):
        """点击忘记密码链接"""
        self.page.get_by_text("忘记密码?").click()

    def login(self, username: str, password: str, remember: bool = False) -> bool:
        """
        执行登录操作

        Args:
            username: 用户名
            password: 密码
            remember: 是否记住密码

        Returns:
            是否登录成功
        """
        self.navigate_to_login()

        self.fill_username(username)
        self.fill_password(password)

        if remember:
            self.check_remember_password()

        self.click_login_button()

        # 等待登录结果
        try:
            # 登录成功会跳转到系统概览页面
            self.page.wait_for_url("**/systemOverview**", timeout=10000)
            return True
        except Exception:
            # 检查是否有错误提示
            error_msg = self.get_login_error()
            if error_msg:
                print(f"登录失败: {error_msg}")
            return False

    def get_login_error(self) -> Optional[str]:
        """
        获取登录错误信息

        Returns:
            错误信息，如果没有则返回None
        """
        try:
            # 检查常见的错误提示元素
            error_selectors = [
                ".ant-message-error",
                ".login-error",
                "[class*='error']",
            ]

            for selector in error_selectors:
                locator = self.page.locator(selector)
                if locator.count() > 0 and locator.is_visible():
                    return locator.inner_text()

            return None
        except Exception:
            return None

    def is_logged_in(self) -> bool:
        """
        检查是否已登录

        Returns:
            是否已登录
        """
        # 检查URL是否包含系统页面路径
        current_url = self.page.url
        return "systemOverview" in current_url or "monitoringCenter" in current_url

    def logout(self):
        """退出登录"""
        try:
            # 点击用户头像
            self.page.locator(".user-avatar, [class*='user']").first.click()
            # 点击退出按钮
            self.page.get_by_text("退出").click()
            # 确认退出
            self.page.get_by_role("button", name="确定").click()
        except Exception:
            pass
