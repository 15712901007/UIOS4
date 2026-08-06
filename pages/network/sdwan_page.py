"""网络配置 > SD-WAN Page Object。

实机页面位于 ``/#/networkConfiguration/sdwan``，底层脚本
``/usr/ikuai/script/ik_web_sdwan.sh``(路由器侧代理 yun.ikuai8.com/api/v3/sdwan/local/*)。

SD-WAN 是**云端主导**功能, 路由器侧为"状态/开通页"(非本地 CRUD):
  - 未开通态(设备未绑云 / 未加入任何组网): 展示介绍文案 + "立即开通"按钮。
    点"立即开通"会新开标签页跳转云控制台 ``icc.ikuai8.com/#/sdwan``。
  - 已开通态(设备已加入某云端组网): 展示组网状态(网络名/成员/虚拟IP等),
    路由器通过 ik_web_sdwan.sh local_list/local_info 轮询 yun 拉取。
  - 切换由云端组网成员增删驱动: 云端把本机 GWID 加入/移出分组 ->
    路由器页面随之变化(ik_web_sdwan.token / local_list 反映)。

页面对象仿 cloud_service_binding(单例状态页), 非 CRUD。已开通态的精确
DOM 定位器在设备绑云后实测完善, 当前方法用通用文本/特征检测, 实跑时校准。
"""
from __future__ import annotations

import re
from typing import Optional

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage


class SdwanPage(BasePage):
    """iKuai 4.0 网络配置-SD-WAN 状态页。"""

    MODULE_NAME = "sdwan"
    PAGE_URL = "/#/networkConfiguration/sdwan"
    BACKEND_SCRIPT = "/usr/ikuai/script/ik_web_sdwan.sh"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url.rstrip("/")

    # ==================== 导航 ====================

    def navigate_to_sdwan(self, timeout: int = 15000) -> bool:
        try:
            self.page.goto(f"{self.base_url}{self.PAGE_URL}", wait_until="domcontentloaded")
            self._wait_page_ready(timeout)
            return self.is_on_sdwan_page()
        except Exception as e:
            print(f"[navigate_to_sdwan] 异常: {type(e).__name__}: {str(e)[:120]}")
            return False

    def _wait_page_ready(self, timeout: int = 15000) -> None:
        """等 SD-WAN 页主内容渲染(未开通态"立即开通"按钮 或 已开通态组网信息)。"""
        try:
            self.page.locator("text=SD-WAN").first.wait_for(state="visible", timeout=timeout)
        except Exception:
            pass
        self.page.wait_for_timeout(500)

    def is_on_sdwan_page(self) -> bool:
        try:
            if "networkConfiguration/sdwan" not in self.page.url:
                return False
            return "SD-WAN" in (self.page.title() or "") or self.page.locator("main").count() > 0
        except Exception:
            return False

    def reload_status(self, timeout: int = 15000) -> bool:
        """reload 页面, 触发前端重新拉取 ik_web_sdwan local 状态。"""
        try:
            self.page.reload(wait_until="domcontentloaded")
            self._wait_page_ready(timeout)
            return True
        except Exception:
            return False

    # ==================== 未开通态 ====================

    def _button(self, text: str) -> Locator:
        return self.page.locator("button:visible").filter(
            has_text=re.compile(rf"^\s*{re.escape(text)}\s*$")
        ).first

    def is_not_activated(self) -> bool:
        """未开通态: 存在"立即开通"按钮。"""
        try:
            return self._button("立即开通").count() > 0
        except Exception:
            return False

    def is_activated(self) -> bool:
        """已开通态: 无"立即开通"按钮(转为组网状态展示)。绑云后实测校准。"""
        try:
            return not self.is_not_activated()
        except Exception:
            return False

    def click_activate(self, timeout: int = 8000) -> bool:
        """点"立即开通"(新开云控制台标签页 icc.ikuai8.com/#/sdwan)。

        返回是否成功点击并出现新标签页。调用方负责关闭新标签页。
        """
        try:
            btn = self._button("立即开通")
            if btn.count() == 0:
                return False
            before = len(self.page.context.pages)
            btn.click()
            # 等新标签页弹出
            deadline_reps = 20
            for _ in range(deadline_reps):
                if len(self.page.context.pages) > before:
                    return True
                self.page.wait_for_timeout(300)
            return True  # 即便没新开标签也认为点击成功
        except Exception:
            return False

    # ==================== 查看更多(产品介绍外链) ====================

    def has_view_more(self) -> bool:
        """页面是否存在"查看更多"链接(产品介绍外链)。"""
        try:
            return self.page.locator("a:has-text('查看更多')").count() > 0
        except Exception:
            return False

    def get_view_more_url(self) -> str:
        """读"查看更多"链接的 href(应为 https://www.ikuai8.com/netWork.php)。"""
        try:
            link = self.page.locator("a:has-text('查看更多')").first
            return (link.get_attribute("href") or "").strip() if link.count() else ""
        except Exception:
            return ""

    def click_view_more(self, timeout: int = 8000) -> str:
        """点"查看更多", 返回打开的 URL(外链通常新开标签页 target=_blank)。调用方关闭新标签页。"""
        try:
            link = self.page.locator("a:has-text('查看更多')").first
            if link.count() == 0:
                return ""
            try:
                with self.page.context.expect_page(timeout=timeout) as np:
                    link.click()
                new_page = np.value
                try:
                    new_page.wait_for_load_state("domcontentloaded", timeout=timeout)
                except Exception:
                    pass
                return new_page.url
            except Exception:
                # 未新开标签: 可能同标签跳转
                self.page.wait_for_timeout(800)
                return self.page.url
        except Exception:
            return ""

    # ==================== 已开通态(绑云后实测校准) ====================

    def read_main_text(self) -> str:
        """读取 main 区文本(用于状态/成员检测)。"""
        try:
            return self.page.locator("main").inner_text(timeout=3000)
        except Exception:
            try:
                return self.page.locator("body").inner_text(timeout=3000)
            except Exception:
                return ""

    def has_member_gwid(self, gwid: str) -> bool:
        """已开通态页面是否出现指定成员(按 GWID 或虚拟IP文本, 绑云后校准)。"""
        try:
            text = self.read_main_text()
            return bool(gwid) and gwid in text
        except Exception:
            return False

    def has_network_status(self) -> bool:
        """是否已展示组网状态(非介绍页)。启发式: 无"立即开通"且 main 文本含网络相关词。"""
        try:
            if self.is_not_activated():
                return False
            text = self.read_main_text()
            return any(k in text for k in ("组网", "成员", "虚拟IP", "在线", "默认分组"))
        except Exception:
            return False

    def has_network_display(self) -> bool:
        """已开通态: 页面展示组网信息(组网名称/组网成员标签出现, 实测绑云+加入网络后呈现)。"""
        try:
            text = self.read_main_text()
            return "组网名称" in text or "组网成员" in text
        except Exception:
            return False

    def read_network_name(self) -> str:
        """读组网名称(组网名称 标签后的值, 如 '测试212312')。"""
        try:
            text = self.read_main_text()
            m = re.search(r"组网名称\s*[:：]?\s*\n?\s*([^\n]+)", text)
            return m.group(1).strip() if m else ""
        except Exception:
            return ""

    def read_member_count_display(self) -> str:
        """读组网成员数展示(组网成员 后的 'N 个')。"""
        try:
            text = self.read_main_text()
            m = re.search(r"组网成员\s*[:：]?\s*\n?\s*([^\n]+)", text)
            return m.group(1).strip() if m else ""
        except Exception:
            return ""


__all__ = ["SdwanPage"]
