"""
多线路DNS服务页面操作类

网络配置 > DNS服务 > 多线路DNS服务 页面
URL: /login#/networkConfiguration/dnsService (多线路DNS服务tab)
添加/编辑: 独立配置页面 /login#/networkConfiguration/dnsService/multiLineDnsServiceConfig

页面特点: 表格型页面(多记录CRUD), 继承IkuaiTablePage
- 添加: 独立页面, 字段: 名称*(必填), 线路(combobox: wan1/wan2/wan3), 首选DNS*(必填), 备选DNS*(必填), 备注
- 编辑: 独立页面, 同添加
- 行操作: 编辑/停用/启用/删除
- 批量操作: 全选/批量启用/批量停用/批量删除
- 导入/导出

数据库: dns_replace表 (后端脚本 /usr/ikuai/script/dns_replace.sh)
字段: id, interface(unique, 网卡名wan1/wan2/wan3), tagname(unique, 名称),
      dns1(首选DNS), dns2(备选DNS), enabled(默认'yes'), comment(备注)

后端内核机制 (与DNS加速不同, 多线路DNS是纯内核功能, 无iptables/无独立进程):
- ik_cntl multi-dns enable/disable: 启用/禁用整个多线路DNS功能
- ik_cntl multi-dns add IFNAME DNS1 [DNS2]: 添加内核规则(wan接口额外加_ad规则)
- ik_cntl multi-dns del IFNAME / clear: 删除规则
- !! ik_cntl multi-dns 无show命令, 无法直接读取内核规则列表
- dmesg日志: "[iKuai]:The iKuai multi_dns is enabled now" / "disabled now"
- 重启恢复: dns_replace.sh boot -> init()从数据库重建内核规则(实测正常, 无DMZ类bug)

四级验证策略:
- L1数据库: dns_replace表
- L3 dmesg: 最后一条multi_dns enabled/disabled日志判断功能开关状态
- L4 ik_cntl: enable/disable/clear命令
- 模拟重启: dns_replace.sh boot + dmesg验证内核规则重建
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class DnsMultiLinePage(IkuaiTablePage):
    """多线路DNS服务页面对象 - 表格型(独立配置页)"""

    MODULE_NAME = "dns_multi_line"
    PAGE_URL = "/login#/networkConfiguration/dnsService"
    # 添加/编辑独立配置页URL片段
    CONFIG_URL_FRAGMENT = "multiLineDnsServiceConfig"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def navigate_to_dns_multi_line(self):
        """导航到多线路DNS服务页面(强制刷新确保数据同步)

        DNS服务是tab页(DNS加速服务/多线路DNS服务), 已在该页面时reload+重点击tab
        """
        url = f"{self.base_url}{self.PAGE_URL}"
        current = self.page.url
        if "dnsService" in current and self.CONFIG_URL_FRAGMENT not in current:
            # 已在DNS服务tab页, 用reload强制刷新
            self.page.reload()
        else:
            self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1500)

        # 点击多线路DNS服务tab
        ml_tab = self.page.get_by_role("tab", name="多线路DNS服务")
        try:
            ml_tab.wait_for(state="visible", timeout=10000)
        except Exception as e:
            logger.error(f"[导航] 等待多线路DNS服务tab超时: {e}")
            all_tabs = self.page.locator('[role="tablist"] [role="tab"]')
            tab_texts = [all_tabs.nth(i).text_content().strip()
                         for i in range(all_tabs.count())]
            logger.error(f"[导航] 当前可见tabs: {tab_texts}")
            raise

        selected = ml_tab.get_attribute("aria-selected")
        if selected != "true":
            ml_tab.click()
            self.page.wait_for_timeout(1000)
            logger.info("[导航] 已切换到多线路DNS服务tab")
        else:
            logger.info("[导航] 已在多线路DNS服务tab")

        return self

    def navigate_back_to_list(self):
        """从添加/编辑独立页面导航回列表页"""
        self.navigate_to_dns_multi_line()
        self.page.wait_for_timeout(500)
        return self

    def _on_config_page(self) -> bool:
        """当前是否在添加/编辑独立配置页"""
        return self.CONFIG_URL_FRAGMENT in self.page.url

    # ==================== 表单字段填写 ====================

    def fill_name(self, name: str):
        """填写名称(必填)"""
        name_input = self.page.locator('input[placeholder="请输入名称"]')
        if name_input.count() > 0:
            name_input.click()
            self.page.keyboard.press("Control+a")
            name_input.type(name, delay=50)
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 填写名称: {name}")
        return self

    def select_line(self, line: str):
        """
        选择线路(combobox单选: wan1/wan2/wan3)

        Args:
            line: 线路名, 如 "wan1", "wan2", "wan3"
        """
        try:
            combobox = self.page.get_by_role("combobox", name="线路")
            if combobox.count() == 0:
                logger.warning("[操作] 未找到线路combobox")
                return self

            # 点击ant-select-selector容器触发React(Ant Design combobox input被selection-item遮挡)
            selector = combobox.locator(
                "xpath=ancestor::div[contains(@class,'ant-select-selector')]"
            )
            if selector.count() > 0:
                selector.first.click()
            else:
                combobox.click(force=True)
            self.page.wait_for_timeout(800)

            # 精确匹配选项
            option = self.page.locator(f'.ant-select-item-option[title="{line}"]')
            clicked = False
            if option.count() > 0:
                for i in range(option.count()):
                    if option.nth(i).is_visible():
                        option.nth(i).click()
                        self.page.wait_for_timeout(300)
                        clicked = True
                        break

            if not clicked:
                # 文本匹配
                all_items = self.page.locator(".ant-select-item-option")
                for i in range(min(all_items.count(), 20)):
                    el = all_items.nth(i)
                    if el.is_visible() and line in el.text_content().strip():
                        el.click()
                        self.page.wait_for_timeout(300)
                        clicked = True
                        break

            if clicked:
                logger.info(f"[操作] 选择线路: {line}")
            else:
                logger.warning(f"[操作] 未找到线路选项: {line}")
                self.page.keyboard.press("Escape")
        except Exception as e:
            logger.error(f"[操作] 选择线路失败: {e}")
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
        return self

    def fill_dns1(self, dns: str):
        """填写首选DNS(必填)"""
        dns1_input = self.page.locator('input[placeholder="请输入首选DNS"]')
        if dns1_input.count() > 0:
            dns1_input.click()
            self.page.keyboard.press("Control+a")
            dns1_input.type(dns, delay=40)
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 填写首选DNS: {dns}")
        return self

    def fill_dns2(self, dns: str):
        """填写备选DNS(必填)"""
        dns2_input = self.page.locator('input[placeholder="请输入备选DNS"]')
        if dns2_input.count() > 0:
            dns2_input.click()
            self.page.keyboard.press("Control+a")
            dns2_input.type(dns, delay=40)
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 填写备选DNS: {dns}")
        return self

    def fill_remark(self, remark: str):
        """填写备注"""
        try:
            remark_input = self.page.get_by_role("textbox", name="备注")
            if remark_input.count() > 0:
                remark_input.click()
                remark_input.fill(remark)
                self.page.wait_for_timeout(200)
        except Exception:
            # 备用: textarea
            ta = self.page.locator("#comment, textarea").last
            if ta.count() > 0:
                ta.fill(remark)
                self.page.wait_for_timeout(200)
        return self

    # ==================== 读取表单当前值(编辑页用) ====================

    def get_form_values(self) -> dict:
        """读取当前配置页表单各字段值"""
        values = {}
        try:
            name_input = self.page.locator('input[placeholder="请输入名称"]')
            if name_input.count() > 0:
                values["name"] = name_input.first.input_value()
            dns1_input = self.page.locator('input[placeholder="请输入首选DNS"]')
            if dns1_input.count() > 0:
                values["dns1"] = dns1_input.first.input_value()
            dns2_input = self.page.locator('input[placeholder="请输入备选DNS"]')
            if dns2_input.count() > 0:
                values["dns2"] = dns2_input.first.input_value()
            # 线路(读取selection-item)
            combobox = self.page.get_by_role("combobox", name="线路")
            if combobox.count() > 0:
                selector = combobox.locator(
                    "xpath=ancestor::div[contains(@class,'ant-select-selector')]"
                )
                item = selector.locator(".ant-select-selection-item")
                if item.count() > 0:
                    values["interface"] = item.first.get_attribute("title") or \
                        item.first.text_content().strip()
        except Exception as e:
            logger.warning(f"[读取] 读取表单值失败: {e}")
        return values

    # ==================== 添加规则(完整流程) ====================

    def add_rule(self, name: str, interface: str = "wan1",
                 dns1: str = "8.8.8.8", dns2: str = "8.8.4.4",
                 remark: str = None) -> bool:
        """
        添加多线路DNS规则

        Args:
            name: 名称(必填)
            interface: 线路 wan1/wan2/wan3
            dns1: 首选DNS(必填)
            dns2: 备选DNS(必填)
            remark: 备注

        Returns:
            是否添加成功(结果导向: 保存后URL跳回列表页 + 规则存在)
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)

            # 等待添加页表单加载
            try:
                self.page.wait_for_selector(
                    'input[placeholder="请输入名称"]', timeout=10000
                )
            except Exception:
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(1000)
            self.page.wait_for_timeout(500)

            self.fill_name(name)
            self.select_line(interface)
            self.fill_dns1(dns1)
            self.fill_dns2(dns2)
            if remark:
                self.fill_remark(remark)

            logger.info(f"[添加] 保存规则: {name}/{interface}/{dns1}/{dns2}")
            self.click_save()
            self.page.wait_for_timeout(1500)

            # 检测表单错误(前端校验)
            error_el = self.page.locator(
                '.ant-form-item-explain-error, .ant-message-error'
            )
            if error_el.count() > 0:
                errors = [error_el.nth(i).text_content()
                          for i in range(min(error_el.count(), 5))]
                logger.error(f"[添加] 表单错误: {errors}")
                try:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                except Exception:
                    pass
                if self._on_config_page():
                    self.navigate_back_to_list()
                return False

            # 结果导向: 保存成功应跳回列表页(URL不再含配置页片段)
            if self._on_config_page():
                # 仍在配置页, 可能有未捕获错误
                logger.warning(f"[添加] 保存后仍在配置页: {self.page.url}")
                try:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                except Exception:
                    pass
                self.navigate_back_to_list()
                return False

            # 已跳回列表页, 确认规则存在
            self.page.wait_for_timeout(800)
            if self.rule_exists(name):
                logger.info(f"[添加] 规则添加成功: {name}")
                return True

            # 兜底: 检查成功消息
            if self.wait_for_success_message(timeout=2000):
                logger.info(f"[添加] 规则添加成功(消息确认): {name}")
                return True

            logger.warning(f"[添加] 规则未确认存在: {name}")
            return False

        except Exception as e:
            logger.error(f"[添加] 添加异常: {e}")
            try:
                if self._on_config_page():
                    self.click_cancel()
            except Exception:
                pass
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 编辑规则 ====================

    def edit_rule(self, rule_name: str, **kwargs) -> bool:
        """
        编辑规则(修改指定字段), 返回是否成功

        Args:
            rule_name: 要编辑的规则名称
            **kwargs: name/interface/dns1/dns2/remark 要修改的字段
        """
        try:
            # 点击编辑按钮(基类, 跳转到独立编辑页)
            super().edit_rule(rule_name)
            self.page.wait_for_timeout(1500)

            # 等待编辑页表单加载
            try:
                self.page.wait_for_selector(
                    'input[placeholder="请输入名称"]', timeout=10000
                )
            except Exception:
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(1000)
            self.page.wait_for_timeout(500)

            # 修改指定字段
            if "name" in kwargs:
                self.fill_name(kwargs["name"])
            if "interface" in kwargs:
                self.select_line(kwargs["interface"])
            if "dns1" in kwargs:
                self.fill_dns1(kwargs["dns1"])
            if "dns2" in kwargs:
                self.fill_dns2(kwargs["dns2"])
            if "remark" in kwargs:
                self.fill_remark(kwargs["remark"])

            self.click_save()
            self.page.wait_for_timeout(1500)

            # 检测表单错误
            error_el = self.page.locator(
                '.ant-form-item-explain-error, .ant-message-error'
            )
            if error_el.count() > 0:
                logger.error(f"[编辑] 表单错误: "
                             f"{[error_el.nth(i).text_content() for i in range(min(error_el.count(),3))]}")
                try:
                    self.click_cancel()
                    self.page.wait_for_timeout(500)
                except Exception:
                    pass
                if self._on_config_page():
                    self.navigate_back_to_list()
                return False

            # 结果导向: 跳回列表页 = 成功
            if self._on_config_page():
                logger.warning(f"[编辑] 保存后仍在配置页: {self.page.url}")
                try:
                    self.click_cancel()
                except Exception:
                    pass
                self.navigate_back_to_list()
                return False

            self.page.wait_for_timeout(800)
            target = kwargs.get("name", rule_name)
            ok = self.rule_exists(target)
            logger.info(f"[编辑] 规则编辑{'成功' if ok else '失败'}: {rule_name}")
            return ok

        except Exception as e:
            logger.error(f"[编辑] 编辑异常: {e}")
            try:
                if self._on_config_page():
                    self.click_cancel()
            except Exception:
                pass
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    # ==================== 停用/启用/批量操作 ====================
    # !! 实测(2026-06-18): 多线路DNS的"启用"按钮(单条+批量)都会弹确认对话框,
    # 点"启用"后必须点"确定"确认, 后端才执行 action=up 命令(enabled→yes)。
    # 基类 enable_rule/batch_enable 不处理确认弹窗 → 启用点了按钮没点确定 → 不生效。
    # 停用(disable/batch_disable)基类已处理确认弹窗, 无需重写。
    # 此处重写 enable_rule/batch_enable 补上确认弹窗处理。

    def enable_rule(self, rule_name: str) -> bool:
        """启用指定规则(有确认弹窗, 点确定后后端执行up命令)"""
        self._click_rule_button(rule_name, "启用")
        self.page.wait_for_timeout(800)

        # 处理确认弹窗
        try:
            confirm_btn = self.page.locator(
                "[role='dialog'] button:has-text('确定'), "
                ".ant-modal-confirm button:has-text('确定')"
            )
            if confirm_btn.count() > 0 and confirm_btn.first.is_visible():
                confirm_btn.first.click()
            else:
                self.page.get_by_role("button", name="确定").click()
        except Exception as e:
            logger.warning(f"[启用] 确认弹窗点击失败: {e}")

        self.page.wait_for_timeout(1500)
        return self.wait_for_success_message(timeout=5000)

    def batch_enable(self):
        """批量启用选中的规则(有确认弹窗, 重写基类补确认处理)"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_batch_button("启用")
        self.page.wait_for_timeout(800)

        # 处理确认弹窗
        try:
            confirm_btn = self.page.locator(
                "[role='dialog'] button:has-text('确定'):visible, "
                ".ant-modal-confirm button:has-text('确定')"
            )
            if confirm_btn.count() > 0:
                confirm_btn.first.click()
            else:
                self.page.get_by_role("button", name="确定").click()
        except Exception as e:
            logger.warning(f"[批量启用] 确认弹窗点击失败: {e}")
        return self

    # ==================== 表格读取 ====================

    def get_rule_list(self) -> List[dict]:
        """获取当前表格中的规则列表(JS读取, 适配非标准DOM)

        列顺序: [checkbox][名称][线路][首选DNS][备选DNS][备注][操作]
        enabled状态: 操作列含"停用"=启用, 含"启用"=停用
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
                    if (cells.length >= 6) {
                        const nameText = cells[1]?.textContent?.trim() || '';
                        const ifaceText = cells[2]?.textContent?.trim() || '';
                        const dns1Text = cells[3]?.textContent?.trim() || '';
                        const dns2Text = cells[4]?.textContent?.trim() || '';
                        const remarkText = cells[5]?.textContent?.trim() || '';
                        const opText = cells[6]?.textContent?.trim() || '';
                        if (nameText && nameText !== '暂无内容') {
                            result.push({
                                name: nameText,
                                interface: ifaceText,
                                dns1: dns1Text,
                                dns2: dns2Text,
                                remark: remarkText,
                                enabled: opText.includes('停用')
                            });
                        }
                    }
                });
                return result;
            }''')
        except Exception as e:
            logger.warning(f"[读取] 获取规则列表失败: {e}")
        return rules or []

    def find_rule_row(self, name: str) -> Optional[dict]:
        """查找指定名称的规则行, 返回规则dict或None"""
        for r in self.get_rule_list():
            if r["name"] == name:
                return r
        return None

    # ==================== 异常输入测试 ====================

    def try_add_rule_invalid(self, name: str = None, interface: str = None,
                             dns1: str = None, dns2: str = None,
                             expect_fail: bool = True) -> dict:
        """
        尝试添加无效规则, 测试表单验证

        Args:
            name/interface/dns1/dns2: 各字段(None=不填)
            expect_fail: 是否期望失败

        Returns:
            {"success": 是否达到预期, "error_message": 错误提示}
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)

            try:
                self.page.wait_for_selector(
                    'input[placeholder="请输入名称"]', timeout=10000
                )
            except Exception:
                self.page.wait_for_timeout(1000)

            if name is not None:
                self.fill_name(name)
            if interface is not None:
                self.select_line(interface)
            if dns1 is not None:
                self.fill_dns1(dns1)
            if dns2 is not None:
                self.fill_dns2(dns2)

            self.click_save()
            self.page.wait_for_timeout(1200)

            # 检测前端校验错误
            error_el = self.page.locator('.ant-form-item-explain-error')
            err_msg = ""
            if error_el.count() > 0:
                err_msg = error_el.first.text_content().strip()

            toast_err = self.page.locator('.ant-message-error')
            if not err_msg and toast_err.count() > 0:
                err_msg = toast_err.first.text_content().strip()

            still_on_config = self._on_config_page()

            if expect_fail and (err_msg or still_on_config):
                logger.info(f"[异常测试] 预期失败已拦截: {err_msg or '保存被拒绝(仍在配置页)'}")
                try:
                    self.click_cancel()
                except Exception:
                    pass
                if self._on_config_page():
                    self.navigate_back_to_list()
                return {"success": True, "error_message": err_msg or "保存被拒绝(后端/前端验证)"}

            if expect_fail:
                logger.warning(f"[异常测试] 预期失败但未拦截: name={name}, dns1={dns1}")
                try:
                    self.click_cancel()
                except Exception:
                    pass
                if self._on_config_page():
                    self.navigate_back_to_list()
                return {"success": False, "error_message": ""}

            return {"success": True, "error_message": ""}

        except Exception as e:
            try:
                if self._on_config_page():
                    self.click_cancel()
                self.navigate_back_to_list()
            except Exception:
                pass
            return {"success": False, "error_message": str(e)}
