"""
DHCP服务端页面操作类

网络配置 > DHCP服务 > DHCP服务端 页面
URL: /login#/networkConfiguration/dhcpService (DHCP服务端tab, 5个tab之一)

页面特点: 表格型(每行一个DHCP地址池), 添加/编辑为独立配置页面(非弹窗):
- 添加页: /login#/networkConfiguration/dhcpService/server/add
- 编辑页: /login#/networkConfiguration/dhcpService/server/edit

表格列: 名称/服务接口/客户端地址/子网掩码/网关/首选DNS/备选DNS/租期/过期地址保留时间/剩余地址/操作
顶部按钮: 重启DHCP服务/添加/导入/导出 + 搜索框 + 帮助
行内按钮: 编辑/停用(或启用)/删除

数据库: dhcp_server表
字段映射 (UI标签 -> 数据库字段):
- 名称 -> tagname (unique)
- 服务接口 -> interface (lan1/vlan等)
- 客户端地址(起-止) -> addr_pool ("start-end")
- 排除地址 -> exclude_pool
- 子网掩码 -> netmask
- 网关 -> gateway
- 首选DNS -> dns1
- 备选DNS -> dns2
- 租期(分钟) -> lease (1-525600)
- 过期地址保留时间(小时) -> delay (0-2160)
- 检查接口IP有效性 -> check_addr_valid (1/0)
- 只应用于DHCP中继 -> check_relay_only (1/0)
- 关联接口 -> phy_ifnames (默认all)
- 域名 -> domain (自定义选项内)
- 主/辅助WINS -> wins1/wins2
- 下一跳服务器地址 -> next_server

后端: ik_dhcpd进程 + /tmp/iktmp/ik_dhcpd.conf + UDP67/68
重启: __delayed_restart延迟2秒重启ik_dhcpd; boot()模拟开机初始化
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class DhcpServerPage(IkuaiTablePage):
    """DHCP服务端页面操作类(表格型, 独立页面表单)"""

    MODULE_NAME = "dhcp_server"
    PAGE_URL = "/login#/networkConfiguration/dhcpService"
    ADD_URL = "/login#/networkConfiguration/dhcpService/server/add"
    EDIT_URL = "/login#/networkConfiguration/dhcpService/server/edit"

    # 列名 -> 数据库字段(用于排序, 若页面支持)
    COLUMN_ID_MAP = {
        "名称": "tagname",
        "服务接口": "interface",
        "租期": "lease",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def _dismiss_residual_modal(self):
        """关闭残留的确认弹窗(如"确认离开"), 避免遮挡后续点击"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass
        try:
            modal_btns = self.page.locator('.ant-modal-confirm .ant-btn')
            for i in range(min(modal_btns.count(), 4)):
                btn = modal_btns.nth(i)
                if btn.is_visible():
                    btn.click()
                    self.page.wait_for_timeout(300)
                    break
        except Exception:
            pass

    def navigate_to_dhcp_server(self):
        """导航到DHCP服务 > DHCP服务端tab"""
        self._dismiss_residual_modal()
        url = f"{self.base_url}{self.PAGE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        self._dismiss_residual_modal()
        # 确保在DHCP服务端tab (5个tab: DHCP服务端/DHCP静态分配/DHCP客户端/DHCP黑白名单/IPv6前缀静态分配)
        try:
            tab = self.page.get_by_role("tab", name="DHCP服务端")
            if tab.count() > 0:
                selected = tab.get_attribute("aria-selected")
                if selected != "true":
                    tab.click()
                    self.page.wait_for_timeout(800)
        except Exception as e:
            logger.warning(f"[导航] 切换DHCP服务端tab异常: {e}")
        logger.info("[导航] 已到达DHCP服务端页面")
        return self

    def navigate_back_to_list(self):
        """从添加/编辑独立页面导航回列表页"""
        return self.navigate_to_dhcp_server()

    # ==================== 通用下拉框操作(参考port_route) ====================

    def _close_any_dropdown(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _select_option_via_js(self, option_text: str) -> bool:
        """在当前可见下拉框中选择指定选项(文本完全匹配或包含)"""
        try:
            clicked = self.page.evaluate("""(text) => {
                const dropdowns = document.querySelectorAll('.ant-select-dropdown');
                for (let i = dropdowns.length - 1; i >= 0; i--) {
                    const dd = dropdowns[i];
                    if (dd.offsetHeight > 0 && dd.offsetWidth > 0) {
                        const items = dd.querySelectorAll('.ant-select-item');
                        for (const item of items) {
                            const t = item.textContent.trim();
                            if (t === text || t.indexOf(text) >= 0 || text.indexOf(t) >= 0) {
                                item.click();
                                return true;
                            }
                        }
                    }
                }
                return false;
            }""", option_text)
            return bool(clicked)
        except Exception:
            return False

    def _click_select_by_label(self, label_text: str) -> bool:
        """
        通过表单label定位Ant Design Select并打开下拉框
        Ant Select中combobox input被selection-item覆盖, 点击selector容器触发React
        """
        try:
            # 找到包含该label的form-item
            form_item = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text=label_text)
            )
            sel = form_item.first.locator('.ant-select').first
            sel.wait_for(state="visible", timeout=5000)
            # 点击.ant-select-selector打开下拉
            selector = sel.locator('.ant-select-selector').first
            selector.click()
            self.page.wait_for_timeout(800)
            return True
        except Exception as e:
            logger.warning(f"[操作] 点击下拉框({label_text})失败: {e}")
            return False

    def _get_select_value_by_label(self, label_text: str) -> str:
        """获取表单label对应Select的当前值"""
        try:
            form_item = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text=label_text)
            )
            item = form_item.first.locator('.ant-select-selection-item')
            if item.count() > 0:
                return (item.first.get_attribute("title") or item.first.text_content() or "").strip()
        except Exception:
            pass
        return ""

    # ==================== 表单字段填写(独立页面) ====================

    def fill_name(self, name: str):
        """填写名称(tagname)"""
        inp = self.page.locator('input[placeholder="请输入名称"]')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(name)
            self.page.wait_for_timeout(200)
        return self

    def fill_addr_pool(self, start: str, end: str):
        """填写客户端地址(起-止), 合成addr_pool="start-end"

        客户端地址区域两个input的placeholder均为"请输入客户端地址"(排除地址placeholder不同),
        故用placeholder直接定位: nth(0)=起始, nth(1)=结束。
        """
        pool_inps = self.page.locator('input[placeholder="请输入客户端地址"]')
        try:
            pool_inps.first.wait_for(state="visible", timeout=5000)
        except Exception:
            pass
        count = pool_inps.count()
        if count >= 2:
            s = pool_inps.nth(0)
            e = pool_inps.nth(1)
            s.click()
            s.fill("")
            s.fill(start)
            self.page.wait_for_timeout(150)
            e.click()
            e.fill("")
            e.fill(end)
            self.page.wait_for_timeout(150)
            logger.info(f"[操作] 客户端地址: {start}-{end}")
        else:
            logger.warning(f"[操作] 客户端地址input不足2个(实际{count}), 跳过")
        return self

    def fill_exclude_pool(self, text: str):
        """填写排除地址(多行)"""
        inp = self.page.locator('input[placeholder="请输入排除地址"], textarea[placeholder="请输入排除地址"]')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill(text)
            self.page.wait_for_timeout(150)
        return self

    def select_interface(self, iface: str):
        """选择服务接口(lan1/vlan等)"""
        self._close_any_dropdown()
        current = self._get_select_value_by_label("服务接口")
        if current == iface or (current and iface in current):
            return self
        if self._click_select_by_label("服务接口"):
            if self._select_option_via_js(iface):
                self.page.wait_for_timeout(400)
                logger.info(f"[操作] 服务接口: {iface}")
        self._close_any_dropdown()
        return self

    def select_netmask(self, netmask: str):
        """
        选择子网掩码
        combobox选项格式可能为"255.255.255.0"或"255.255.255.0 (24)", 用包含匹配
        """
        self._close_any_dropdown()
        current = self._get_select_value_by_label("子网掩码")
        if current == netmask or (current and netmask in current):
            return self
        if self._click_select_by_label("子网掩码"):
            if self._select_option_via_js(netmask):
                self.page.wait_for_timeout(400)
                logger.info(f"[操作] 子网掩码: {netmask}")
        self._close_any_dropdown()
        return self

    def get_netmask_options(self):
        """获取子网掩码可选项(用于确认选项格式)"""
        options = []
        try:
            self._click_select_by_label("子网掩码")
            self.page.wait_for_timeout(600)
            options = self.page.evaluate("""() => {
                const dd = document.querySelectorAll('.ant-select-dropdown');
                for (let i = dd.length - 1; i >= 0; i--) {
                    if (dd[i].offsetHeight > 0) {
                        return Array.from(dd[i].querySelectorAll('.ant-select-item-option')).map(el => el.textContent.trim());
                    }
                }
                return [];
            }""")
            self._close_any_dropdown()
        except Exception:
            self._close_any_dropdown()
        return options or []

    def fill_gateway(self, gateway: str):
        """填写网关"""
        inp = self.page.locator('input[placeholder="请输入网关"]')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(gateway)
            self.page.wait_for_timeout(150)
        return self

    def fill_dns1(self, dns: str):
        """填写首选DNS"""
        inp = self.page.locator('input[placeholder="请输入首选DNS"]')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(dns)
            self.page.wait_for_timeout(150)
        return self

    def fill_dns2(self, dns: str):
        """填写备选DNS"""
        inp = self.page.locator('input[placeholder="请输入备选DNS"]')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(dns)
            self.page.wait_for_timeout(150)
        return self

    def fill_lease(self, minutes: int):
        """填写租期(分钟, spinbutton)"""
        return self._fill_spinbutton("租期", str(minutes))

    def fill_delay(self, hours: int):
        """填写过期地址保留时间(小时, spinbutton)"""
        return self._fill_spinbutton("过期地址保留时间", str(hours))

    def _fill_spinbutton(self, label_text: str, value: str):
        """通用spinbutton填写(Ant Design InputNumber)"""
        try:
            form_item = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text=label_text)
            ).first
            spin = form_item.locator('input').first
            spin.wait_for(state="visible", timeout=5000)
            spin.click()
            self.page.keyboard.press("Control+a")
            self.page.keyboard.type(value, delay=40)
            # 触发blur确保onChange提交
            self.page.wait_for_timeout(100)
            spin.press("Tab")
            self.page.wait_for_timeout(150)
            logger.info(f"[操作] {label_text}: {value}")
        except Exception as e:
            logger.warning(f"[操作] 填写{label_text}失败: {e}")
            # 回退: 直接fill
            try:
                form_item = self.page.locator('.ant-form-item').filter(
                    has=self.page.locator('[class*="label"]').filter(has_text=label_text)
                ).first
                form_item.locator('input').first.fill(value)
            except Exception:
                pass
        return self

    def toggle_check_addr_valid(self, enable: bool):
        """勾选/取消'检查接口IP有效性'"""
        return self._toggle_checkbox("检查接口IP有效性", enable)

    def toggle_check_relay_only(self, enable: bool):
        """勾选/取消'只应用于DHCP中继'"""
        return self._toggle_checkbox("只应用于DHCP中继", enable)

    def _toggle_checkbox(self, label_text: str, enable: bool):
        """通用checkbox切换(通过label文本定位)"""
        try:
            # checkbox的label包含目标文本
            wrapper = self.page.locator('.ant-checkbox-wrapper').filter(has_text=label_text)
            if wrapper.count() > 0:
                cb = wrapper.first.locator('input[type="checkbox"]')
                if cb.count() > 0:
                    checked = cb.first.is_checked()
                    if checked != enable:
                        wrapper.first.click()
                        self.page.wait_for_timeout(200)
                        logger.info(f"[操作] {label_text}: {'开启' if enable else '关闭'}")
        except Exception as e:
            logger.warning(f"[操作] 切换{label_text}失败: {e}")
        return self

    def is_check_addr_valid(self) -> bool:
        """读取'检查接口IP有效性'勾选状态"""
        return self._is_checkbox_checked("检查接口IP有效性")

    def is_check_relay_only(self) -> bool:
        """读取'只应用于DHCP中继'勾选状态"""
        return self._is_checkbox_checked("只应用于DHCP中继")

    def _is_checkbox_checked(self, label_text: str) -> bool:
        try:
            wrapper = self.page.locator('.ant-checkbox-wrapper').filter(has_text=label_text)
            if wrapper.count() > 0:
                cb = wrapper.first.locator('input[type="checkbox"]')
                if cb.count() > 0:
                    return cb.first.is_checked()
        except Exception:
            pass
        return False

    # ==================== 表单读取(用于编辑页回显校验) ====================

    def get_form_name(self) -> str:
        try:
            inp = self.page.locator('input[placeholder="请输入名称"]')
            if inp.count() > 0:
                return inp.first.input_value().strip()
        except Exception:
            pass
        return ""

    def get_form_addr_pool(self) -> str:
        """返回'起-止'字符串"""
        try:
            form_item = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text="客户端地址")
            ).first
            inputs = form_item.locator('input')
            if inputs.count() >= 2:
                return f"{inputs.nth(0).input_value()}-{inputs.nth(1).input_value()}"
        except Exception:
            pass
        return ""

    def get_form_lease(self) -> str:
        return self._get_spinbutton_value("租期")

    def get_form_delay(self) -> str:
        return self._get_spinbutton_value("过期地址保留时间")

    def _get_spinbutton_value(self, label_text: str) -> str:
        try:
            form_item = self.page.locator('.ant-form-item').filter(
                has=self.page.locator('[class*="label"]').filter(has_text=label_text)
            ).first
            inp = form_item.locator('input').first
            if inp.count() > 0:
                return inp.input_value().strip()
        except Exception:
            pass
        return ""

    # ==================== 保存与高层操作 ====================

    def save_form(self, expect_success: bool = True) -> bool:
        """
        点击保存按钮(独立页面), 检测成功/失败消息
        保存后不会自动跳转, 调用方需navigate_back_to_list
        """
        try:
            self.page.wait_for_timeout(500)
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() == 0:
                logger.error("[保存] 未找到保存按钮")
                return False
            save_btn.click()
            self.page.wait_for_timeout(1500)

            if not expect_success:
                return False

            # 检测成功消息
            success = False
            try:
                msg = self.page.locator(".ant-message-success")
                if msg.count() > 0 and msg.first.is_visible():
                    success = True
                else:
                    success = self.wait_for_success_message(timeout=5000)
            except Exception:
                success = self.wait_for_success_message(timeout=5000)

            if success:
                logger.info("[保存] DHCP服务端配置保存成功")
            else:
                error = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if error.count() > 0:
                    logger.error(f"[保存] 保存失败: {error.first.text_content()}")
                else:
                    logger.warning("[保存] 未检测到成功/失败消息")
            return success
        except Exception as e:
            logger.error(f"[保存] 保存异常: {e}")
            return False

    def add_dhcp_server(self, name: str, interface: str = "lan1",
                        pool_start: str = "", pool_end: str = "",
                        netmask: str = "255.255.255.0", gateway: str = "",
                        dns1: str = "114.114.114.114", dns2: str = "223.5.5.5",
                        lease: int = 120, delay: int = 0,
                        check_addr_valid: Optional[bool] = None,
                        exclude_pool: str = "") -> bool:
        """
        添加一条DHCP服务端配置(独立页面表单)

        Returns:
            保存是否成功
        """
        try:
            self.navigate_to_dhcp_server()
            self.page.wait_for_timeout(500)
            self.click_add_button()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1000)

            self.fill_name(name)
            self.select_interface(interface)
            if pool_start and pool_end:
                self.fill_addr_pool(pool_start, pool_end)
            if exclude_pool:
                self.fill_exclude_pool(exclude_pool)
            self.select_netmask(netmask)
            if gateway:
                self.fill_gateway(gateway)
            self.fill_dns1(dns1)
            self.fill_dns2(dns2)
            self.fill_lease(lease)
            self.fill_delay(delay)
            if check_addr_valid is not None:
                self.toggle_check_addr_valid(check_addr_valid)

            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            # 等待__delayed_restart生效(操作后延迟2秒重启ik_dhcpd)
            self.page.wait_for_timeout(2500)
            return ok
        except Exception as e:
            logger.error(f"[添加] 添加DHCP服务端异常: {e}")
            return False

    def edit_dhcp_server(self, current_name: str, **kwargs) -> bool:
        """
        编辑指定名称的DHCP服务端配置
        kwargs支持: name/interface/pool_start/pool_end/netmask/gateway/dns1/dns2/lease/delay/check_addr_valid/exclude_pool
        """
        try:
            self.navigate_to_dhcp_server()
            self.page.wait_for_timeout(500)
            self.edit_rule(current_name)
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1200)

            if "name" in kwargs and kwargs["name"] is not None:
                self.fill_name(kwargs["name"])
            if "interface" in kwargs and kwargs["interface"]:
                self.select_interface(kwargs["interface"])
            if "pool_start" in kwargs and "pool_end" in kwargs:
                self.fill_addr_pool(kwargs["pool_start"], kwargs["pool_end"])
            if "exclude_pool" in kwargs and kwargs["exclude_pool"]:
                self.fill_exclude_pool(kwargs["exclude_pool"])
            if "netmask" in kwargs and kwargs["netmask"]:
                self.select_netmask(kwargs["netmask"])
            if "gateway" in kwargs and kwargs["gateway"]:
                self.fill_gateway(kwargs["gateway"])
            if "dns1" in kwargs and kwargs["dns1"]:
                self.fill_dns1(kwargs["dns1"])
            if "dns2" in kwargs and kwargs["dns2"]:
                self.fill_dns2(kwargs["dns2"])
            if "lease" in kwargs and kwargs["lease"] is not None:
                self.fill_lease(kwargs["lease"])
            if "delay" in kwargs and kwargs["delay"] is not None:
                self.fill_delay(kwargs["delay"])
            if "check_addr_valid" in kwargs and kwargs["check_addr_valid"] is not None:
                self.toggle_check_addr_valid(kwargs["check_addr_valid"])

            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            self.page.wait_for_timeout(2500)
            return ok
        except Exception as e:
            logger.error(f"[编辑] 编辑DHCP服务端异常: {e}")
            return False

    # ==================== 重启DHCP服务 ====================

    def click_restart_dhcp(self) -> bool:
        """点击顶部'重启DHCP服务'按钮(重启整个ik_dhcpd进程)"""
        try:
            btn = self.page.get_by_role("button", name="重启DHCP服务")
            if btn.count() > 0:
                btn.first.click()
                self.page.wait_for_timeout(500)
                # 可能有确认弹窗
                try:
                    confirm = self.page.locator(
                        ".ant-modal-confirm .ant-btn-primary, [role='dialog'] button:has-text('确定')"
                    )
                    if confirm.count() > 0 and confirm.first.is_visible():
                        confirm.first.click()
                        self.page.wait_for_timeout(500)
                except Exception:
                    pass
                # 等待重启完成
                self.wait_for_success_message(timeout=8000)
                self.page.wait_for_timeout(2500)
                logger.info("[操作] 已点击重启DHCP服务")
                return True
        except Exception as e:
            logger.warning(f"[操作] 重启DHCP服务失败: {e}")
        return False

    # ==================== 帮助 ====================

    def click_help(self) -> bool:
        try:
            help_btn = self.page.locator('button').filter(has_text="帮助")
            if help_btn.count() > 0:
                help_btn.last.click()
                self.page.wait_for_timeout(500)
                return True
        except Exception:
            pass
        return False

    def is_help_panel_visible(self) -> bool:
        try:
            panel = self.page.locator(".ant-drawer, .ant-modal, [role='dialog']")
            return panel.count() > 0 and panel.first.is_visible()
        except Exception:
            return False

    def close_help_panel(self):
        try:
            close_btn = self.page.locator(".ant-drawer-close, .ant-modal-close")
            if close_btn.count() > 0:
                close_btn.first.click()
            else:
                self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception:
            self.page.keyboard.press("Escape")
