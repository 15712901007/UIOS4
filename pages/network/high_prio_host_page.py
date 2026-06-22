"""
优先域名设置页面操作类(智能模式, 网页优先等预设场景)

网络配置 > 智能流控 > 优先域名设置 tab(智能模式 + auto=网页优先/游戏优先等预设场景)
URL: /login#/networkConfiguration/intelligentFlowControl (优先域名设置tab)
添加/编辑: 独立配置页 /login#/networkConfiguration/intelligentFlowControl/priorityDomainSetting/add

页面特点: 表格型页面(多记录CRUD), 继承IkuaiTablePage
- 表格列: 名称/域名/备注/操作
- 添加: 独立页面, 字段: 名称*(#tagname) / 域名*(#host) / 备注(textarea)
- 行操作: 编辑/停用/启用/删除
- 批量操作: 全选/批量启用/批量停用/批量删除
- 导入/导出

数据库: high_prio_host表
字段: id, tagname(unique,名称), host(域名,必填≤256), enabled(yes/no), comment(备注≤128)

后端生效机制(关键):
- 仅当 layer7_intell.auto=2(网页优先) 且 domain_prio_switch=1 且 domain_prio_ports非空 时,
  high_prio_host.sh __load_config 才调用 ik_cntl http_app high_prio_host on 生效
- 否则 __unload_config → ik_cntl http_app high_prio_host off(不生效, 但数据库记录仍在)
- !! domain_prio_switch 无直接UI开关, 测试时需通过SQL设置或验证不生效场景
- 生效后: protoc-c编码HostPortList → ik_cntl http_app high_prio_host_add/port_add
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class HighPrioHostPage(IkuaiTablePage):
    """优先域名设置页面对象 - 表格型(独立配置页)"""

    MODULE_NAME = "high_prio_host"
    PAGE_URL = "/login#/networkConfiguration/intelligentFlowControl"
    CONFIG_URL_FRAGMENT = "priorityDomainSetting"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def navigate_to_high_prio_host(self):
        """导航到优先域名设置tab(需智能模式 + 网页优先等预设场景)"""
        url = f"{self.base_url}{self.PAGE_URL}"
        current = self.page.url
        if "intelligentFlowControl" in current and \
                self.CONFIG_URL_FRAGMENT not in current:
            self.page.reload()
        else:
            self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1500)

        tab = self.page.locator(".ant-tabs-tab:has-text('优先域名设置')")
        try:
            tab.first.wait_for(state="visible", timeout=10000)
        except Exception as e:
            logger.error(f"[导航] 优先域名设置tab超时(可能非预设场景, 该tab仅"
                         f"auto=网页优先/游戏优先等场景显示): {e}")
            raise
        tab.first.click()
        self.page.wait_for_timeout(1000)
        logger.info("[导航] 已切换到优先域名设置tab")
        return self

    def navigate_back_to_list(self):
        self.navigate_to_high_prio_host()
        self.page.wait_for_timeout(500)
        return self

    def _on_config_page(self) -> bool:
        return self.CONFIG_URL_FRAGMENT in self.page.url

    # ==================== 表单填写 ====================

    def fill_name(self, name: str):
        """填写名称"""
        inp = self.page.locator('#tagname')
        if inp.count() == 0:
            inp = self.page.locator('input[placeholder="请输入名称"]')
        if inp.count() > 0:
            inp.click()
            self.page.keyboard.press("Control+a")
            inp.type(name, delay=40)
            self.page.wait_for_timeout(300)
        return self

    def fill_host(self, host: str):
        """填写域名"""
        inp = self.page.locator('#host')
        if inp.count() == 0:
            # 兜底: 域名label的form-item内input
            inp = self.page.locator(
                ".ant-form-item:has(.ant-form-item-label:has-text('域名')) input"
            ).first
        if inp.count() > 0:
            inp.click()
            self.page.keyboard.press("Control+a")
            inp.type(host, delay=30)
            self.page.wait_for_timeout(300)
        return self

    def fill_remark(self, remark: str):
        """填写备注"""
        try:
            ta = self.page.get_by_role("textbox", name="备注")
            if ta.count() > 0:
                ta.click()
                ta.fill(remark)
                self.page.wait_for_timeout(300)
        except Exception:
            pass
        return self

    # ==================== 添加规则 ====================

    def add_rule(self, name: str, host: str, remark: str = None) -> bool:
        """
        添加优先域名规则

        Args:
            name: 名称(必填)
            host: 域名(必填)
            remark: 备注
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector('#tagname, #host', timeout=10000)
            except Exception:
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(1000)

            self.fill_name(name)
            self.fill_host(host)
            if remark:
                self.fill_remark(remark)

            logger.info(f"[添加] {name}: host={host}")
            self.click_save()
            self.page.wait_for_timeout(1500)

            if self._has_form_error():
                logger.error(f"[添加] 表单错误: {self._get_form_error()}")
                self._safe_cancel()
                return False
            if self._on_config_page():
                self._safe_cancel()
                return False

            self.page.wait_for_timeout(800)
            if self.rule_exists(name):
                logger.info(f"[添加] 成功: {name}")
                return True
            if self.wait_for_success_message(timeout=2000):
                return True
            return False
        except Exception as e:
            logger.error(f"[添加] 异常: {e}")
            self._safe_cancel()
            return False

    def edit_rule(self, rule_name: str, **kwargs) -> bool:
        """编辑规则(修改名称/域名/备注)"""
        try:
            super().edit_rule(rule_name)
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector('#tagname, #host', timeout=10000)
            except Exception:
                self.page.wait_for_timeout(1000)

            if "name" in kwargs:
                self.fill_name(kwargs["name"])
            if "host" in kwargs:
                self.fill_host(kwargs["host"])
            if "remark" in kwargs:
                self.fill_remark(kwargs["remark"])

            self.click_save()
            self.page.wait_for_timeout(1500)

            if self._has_form_error():
                self._safe_cancel()
                return False
            if self._on_config_page():
                self._safe_cancel()
                return False

            self.page.wait_for_timeout(800)
            target = kwargs.get("name", rule_name)
            return self.rule_exists(target)
        except Exception as e:
            logger.error(f"[编辑] 异常: {e}")
            self._safe_cancel()
            return False

    # ==================== 停用/启用(重写: high_prio_host不弹确认框) ====================

    def disable_rule(self, rule_name: str) -> bool:
        """停用规则(high_prio_host停用不弹确认框, 结果导向验证)"""
        self._click_rule_button(rule_name, "停用")
        self.page.wait_for_timeout(1000)
        # 兼容: 若弹确认框则点(不强制等待)
        try:
            confirm = self.page.locator(
                ".ant-modal-confirm button:has-text('确定'):visible"
            )
            if confirm.count() > 0 and confirm.first.is_visible():
                confirm.first.click()
                self.page.wait_for_timeout(1000)
        except Exception:
            pass
        self.navigate_to_high_prio_host()
        self.page.wait_for_timeout(500)
        return self.is_rule_disabled(rule_name)

    def enable_rule(self, rule_name: str) -> bool:
        """启用规则(结果导向验证)"""
        self._click_rule_button(rule_name, "启用")
        self.page.wait_for_timeout(1000)
        try:
            confirm = self.page.locator(
                ".ant-modal-confirm button:has-text('确定'):visible"
            )
            if confirm.count() > 0 and confirm.first.is_visible():
                confirm.first.click()
                self.page.wait_for_timeout(1000)
        except Exception:
            pass
        self.navigate_to_high_prio_host()
        self.page.wait_for_timeout(500)
        return self.is_rule_enabled(rule_name)

    # ==================== 表格读取 ====================

    def get_rule_list(self) -> List[dict]:
        """获取表格规则列表

        列: 名称/域名/备注/操作
        """
        rules = []
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
            rules = self.page.evaluate('''() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                rows.forEach(row => {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length >= 4) {
                        const name = cells[0]?.textContent?.trim() || '';
                        const host = cells[1]?.textContent?.trim() || '';
                        const remark = cells[2]?.textContent?.trim() || '';
                        const op = cells[cells.length-1]?.textContent?.trim() || '';
                        if (name && name !== '暂无内容') {
                            result.push({
                                name: name, host: host, remark: remark,
                                enabled: op.includes('停用')
                            });
                        }
                    }
                });
                return result;
            }''')
        except Exception as e:
            logger.warning(f"[读取] 规则列表失败: {e}")
        return rules or []

    def find_rule_row(self, name: str) -> Optional[dict]:
        for r in self.get_rule_list():
            if r["name"] == name:
                return r
        return None

    # ==================== 异常输入测试 ====================

    def try_add_rule_invalid(self, name: str = None, host: str = None,
                             expect_fail: bool = True) -> dict:
        """尝试添加无效规则(空名称/空域名/非法域名)"""
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector('#tagname, #host', timeout=10000)
            except Exception:
                self.page.wait_for_timeout(1000)

            if name is not None:
                self.fill_name(name)
            if host is not None:
                self.fill_host(host)

            self.click_save()
            self.page.wait_for_timeout(1200)

            err_msg = self._get_form_error()
            still_on_config = self._on_config_page()

            if expect_fail and (err_msg or still_on_config):
                self._safe_cancel()
                return {"success": True, "error_message": err_msg}
            if expect_fail:
                self._safe_cancel()
                return {"success": False, "error_message": ""}
            return {"success": True, "error_message": ""}
        except Exception as e:
            self._safe_cancel()
            return {"success": False, "error_message": str(e)}

    # ==================== 辅助 ====================

    def _has_form_error(self) -> bool:
        return self.page.locator(
            '.ant-form-item-explain-error, .ant-message-error'
        ).count() > 0

    def _get_form_error(self) -> str:
        el = self.page.locator('.ant-form-item-explain-error')
        if el.count() > 0:
            return el.first.text_content().strip()
        toast = self.page.locator('.ant-message-error')
        if toast.count() > 0:
            return toast.first.text_content().strip()
        return ""

    def _safe_cancel(self):
        try:
            if self._on_config_page():
                self.click_cancel()
        except Exception:
            pass
        try:
            self.navigate_back_to_list()
        except Exception:
            pass
