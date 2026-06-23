"""
DHCP静态分配页面操作类

网络配置 > DHCP服务 > DHCP静态分配 页面
URL: /login#/networkConfiguration/dhcpService (DHCP静态分配tab, 5个tab之一)

页面特点: 表格型(MAC-IP绑定, 每行一条静态分配), 添加/编辑为独立页面(非弹窗):
- 添加页: /login#/networkConfiguration/dhcpService/static/add
- 编辑页: /login#/networkConfiguration/dhcpService/static/edit

表格列: 名称/终端名称/主机名称/IP地址/MAC地址/网关/绑定接口/首选DNS/备选DNS/备注/操作
顶部按钮: 添加/导入/导出 + 搜索框 + 帮助
行内按钮: 编辑/停用(或启用)/删除

数据库: dhcp_static表 (DHCP服务端子功能, 共用ik_dhcpd进程, 无独立iptables/内核)
字段映射 (UI标签 -> 数据库字段, 表单input均有id):
- 名称 -> tagname (id=tagname, unique)
- 绑定接口 -> interface (id=interface, combobox, 默认"自动"=auto; 可选auto/lan/vlan)
- IP地址 -> ip_addr (id=ip_addr, unique)
- MAC地址 -> mac (id=mac, 与interface组合唯一)
- 网关 -> gateway (id=gateway)
- 首选DNS -> dns1 (id=dns1)
- 备选DNS -> dns2 (id=dns2)
- 备注 -> comment (id=comment, textarea)
- 终端名称/主机名称 -> cl_name/hostname (show时从mac_comment/leases.db关联, 非表单字段)

后端: add/edit/del/up/down后 __dhcp_static_update(生成ik_dhcp_static_cache.conf+
      ik_dhcpd_static.conf) + dhcp_server.sh delayed_restart(重启ik_dhcpd使绑定生效)
约束: tagname唯一, ip_addr唯一, (interface,mac)组合唯一
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class DhcpStaticPage(IkuaiTablePage):
    """DHCP静态分配页面操作类(表格型, 独立页面表单, 全#id定位)"""

    MODULE_NAME = "dhcp_static"
    PAGE_URL = "/login#/networkConfiguration/dhcpService"
    ADD_URL = "/login#/networkConfiguration/dhcpService/static/add"
    EDIT_URL = "/login#/networkConfiguration/dhcpService/static/edit"

    # 可排序列(实测th#id): 主机名称/IP地址/MAC地址/绑定接口/首选DNS/备选DNS
    COLUMN_ID_MAP = {
        "主机名称": "hostname",
        "IP地址": "ip_addr_int",
        "MAC地址": "mac",
        "绑定接口": "interface",
        "首选DNS": "dns1",
        "备选DNS": "dns2",
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

    def navigate_to_dhcp_static(self):
        """导航到DHCP服务 > DHCP静态分配tab"""
        self._dismiss_residual_modal()
        url = f"{self.base_url}{self.PAGE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        self._dismiss_residual_modal()
        # 确保在DHCP静态分配tab (5个tab: DHCP服务端/DHCP静态分配/DHCP客户端/DHCP黑白名单/IPv6前缀静态分配)
        try:
            tab = self.page.get_by_role("tab", name="DHCP静态分配")
            if tab.count() > 0:
                selected = tab.get_attribute("aria-selected")
                if selected != "true":
                    tab.click()
                    self.page.wait_for_timeout(1000)
        except Exception as e:
            logger.warning(f"[导航] 切换DHCP静态分配tab异常: {e}")
        logger.info("[导航] 已到达DHCP静态分配页面")
        return self

    def navigate_back_to_list(self):
        """从添加/编辑独立页面导航回列表页"""
        return self.navigate_to_dhcp_static()

    # ==================== 通用下拉框 ====================

    def _close_any_dropdown(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _select_option_via_js(self, option_text: str) -> bool:
        """在当前可见下拉框中选择指定选项(文本完全/包含匹配)"""
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

    def select_interface(self, iface: str = "自动"):
        """选择绑定接口(id=interface combobox)

        Args:
            iface: "自动"(auto) / "lan1" / "vlanXX" 等
        """
        self._close_any_dropdown()
        try:
            # 当前值
            cur = self._get_interface_value()
            if cur == iface or (cur and iface in cur):
                return self
            # 点击#interface的selector打开下拉(Playwright click触发React)
            sel = self.page.locator('div.ant-select-selector').filter(
                has=self.page.locator('#interface')
            )
            if sel.count() > 0:
                sel.first.click()
                self.page.wait_for_timeout(800)
                if self._select_option_via_js(iface):
                    self.page.wait_for_timeout(400)
                    logger.info(f"[操作] 绑定接口: {iface}")
            self._close_any_dropdown()
        except Exception as e:
            logger.warning(f"[操作] 选择绑定接口失败: {e}")
            self._close_any_dropdown()
        return self

    def _get_interface_value(self) -> str:
        """获取绑定接口当前值"""
        try:
            sel = self.page.locator('div.ant-select-selector').filter(
                has=self.page.locator('#interface')
            )
            if sel.count() > 0:
                item = sel.first.locator('.ant-select-selection-item')
                if item.count() > 0:
                    return (item.first.get_attribute("title") or item.first.text_content() or "").strip()
        except Exception:
            pass
        return ""

    # ==================== 表单字段填写(全#id定位) ====================

    def fill_name(self, name: str):
        inp = self.page.locator('#tagname')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(name)
            self.page.wait_for_timeout(150)
        return self

    def fill_ip(self, ip: str):
        inp = self.page.locator('#ip_addr')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(ip)
            self.page.wait_for_timeout(150)
        return self

    def fill_mac(self, mac: str):
        inp = self.page.locator('#mac')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(mac)
            self.page.wait_for_timeout(150)
        return self

    def fill_gateway(self, gateway: str):
        inp = self.page.locator('#gateway')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(gateway)
            self.page.wait_for_timeout(150)
        return self

    def fill_dns1(self, dns: str):
        inp = self.page.locator('#dns1')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(dns)
            self.page.wait_for_timeout(150)
        return self

    def fill_dns2(self, dns: str):
        inp = self.page.locator('#dns2')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(dns)
            self.page.wait_for_timeout(150)
        return self

    def fill_comment(self, comment: str):
        inp = self.page.locator('#comment')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(comment)
            self.page.wait_for_timeout(150)
        return self

    # ==================== 表单读取(编辑页回显校验) ====================

    def get_form_name(self) -> str:
        try:
            inp = self.page.locator('#tagname')
            if inp.count() > 0:
                return inp.first.input_value().strip()
        except Exception:
            pass
        return ""

    def get_form_ip(self) -> str:
        try:
            inp = self.page.locator('#ip_addr')
            if inp.count() > 0:
                return inp.first.input_value().strip()
        except Exception:
            pass
        return ""

    def get_form_mac(self) -> str:
        try:
            inp = self.page.locator('#mac')
            if inp.count() > 0:
                return inp.first.input_value().strip()
        except Exception:
            pass
        return ""

    # ==================== 保存与高层操作 ====================

    def save_form(self, expect_success: bool = True) -> bool:
        """点击保存按钮(独立页面), 检测成功/失败消息"""
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
                logger.info("[保存] DHCP静态分配保存成功")
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

    def add_dhcp_static(self, name: str, ip: str, mac: str,
                        interface: str = "自动", gateway: str = "",
                        dns1: str = "", dns2: str = "", comment: str = "") -> bool:
        """添加一条DHCP静态分配(MAC-IP绑定)"""
        try:
            self.navigate_to_dhcp_static()
            self.page.wait_for_timeout(500)
            self.click_add_button()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1000)

            self.fill_name(name)
            self.select_interface(interface)
            self.fill_ip(ip)
            self.fill_mac(mac)
            if gateway:
                self.fill_gateway(gateway)
            if dns1:
                self.fill_dns1(dns1)
            if dns2:
                self.fill_dns2(dns2)
            if comment:
                self.fill_comment(comment)

            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            # 等待__dhcp_static_update + delayed_restart生效
            self.page.wait_for_timeout(3000)
            return ok
        except Exception as e:
            logger.error(f"[添加] 添加DHCP静态分配异常: {e}")
            return False

    def edit_dhcp_static(self, current_name: str, **kwargs) -> bool:
        """编辑指定名称的DHCP静态分配

        kwargs支持: name/interface/ip/mac/gateway/dns1/dns2/comment
        """
        try:
            self.navigate_to_dhcp_static()
            self.page.wait_for_timeout(500)
            self.edit_rule(current_name)
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1200)

            if "name" in kwargs and kwargs["name"] is not None:
                self.fill_name(kwargs["name"])
            if "interface" in kwargs and kwargs["interface"]:
                self.select_interface(kwargs["interface"])
            if "ip" in kwargs and kwargs["ip"]:
                self.fill_ip(kwargs["ip"])
            if "mac" in kwargs and kwargs["mac"]:
                self.fill_mac(kwargs["mac"])
            if "gateway" in kwargs and kwargs["gateway"]:
                self.fill_gateway(kwargs["gateway"])
            if "dns1" in kwargs and kwargs["dns1"]:
                self.fill_dns1(kwargs["dns1"])
            if "dns2" in kwargs and kwargs["dns2"]:
                self.fill_dns2(kwargs["dns2"])
            if "comment" in kwargs and kwargs["comment"]:
                self.fill_comment(kwargs["comment"])

            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            self.page.wait_for_timeout(3000)
            return ok
        except Exception as e:
            logger.error(f"[编辑] 编辑DHCP静态分配异常: {e}")
            return False

    # ==================== 设置面板(dhcpd_arp开关) ====================

    def click_settings(self) -> bool:
        """点击右上角设置按钮(齿轮图标, class含_setIcon_), 打开设置面板

        设置面板含"兼容ARP绑定列表为静态分配"复选框 = global_config.dhcpd_arp
        (开启后ARP表的MAC-IP自动转为DHCP静态绑定, 写入ik_dhcpd_static.conf)
        """
        try:
            btn = self.page.locator('button[class*="_setIcon_"]')
            if btn.count() > 0:
                btn.first.click()
                self.page.wait_for_timeout(1000)
                logger.info("[操作] 已点击设置按钮")
                return True
        except Exception as e:
            logger.warning(f"[操作] 点击设置按钮失败: {e}")
        return False

    def is_settings_panel_visible(self) -> bool:
        """检查设置面板(Drawer)是否可见"""
        try:
            panel = self.page.locator('.ant-drawer, [class*="Drawer"]')
            for i in range(min(panel.count(), 5)):
                if panel.nth(i).is_visible():
                    # 确认含"兼容ARP"文字
                    if "兼容ARP" in (panel.nth(i).text_content() or ""):
                        return True
            # 回退: 任何可见drawer
            return panel.count() > 0 and panel.first.is_visible()
        except Exception:
            return False

    def is_dhcpd_arp_checked(self) -> bool:
        """读取"兼容ARP绑定列表为静态分配"复选框状态"""
        try:
            cw = self.page.locator('.ant-checkbox-wrapper').filter(has_text="兼容ARP绑定列表为静态分配")
            if cw.count() > 0:
                inp = cw.first.locator('input[type="checkbox"]')
                if inp.count() > 0:
                    return inp.first.is_checked()
        except Exception:
            pass
        return False

    def toggle_dhcpd_arp(self, enable: bool):
        """勾选/取消"兼容ARP绑定列表为静态分配"(global_config.dhcpd_arp)"""
        try:
            cw = self.page.locator('.ant-checkbox-wrapper').filter(has_text="兼容ARP绑定列表为静态分配")
            if cw.count() > 0:
                inp = cw.first.locator('input[type="checkbox"]')
                if inp.count() > 0:
                    current = inp.first.is_checked()
                    if current != enable:
                        cw.first.click()
                        self.page.wait_for_timeout(300)
                        logger.info(f"[操作] 兼容ARP绑定: {'开启' if enable else '关闭'}")
        except Exception as e:
            logger.warning(f"[操作] 切换兼容ARP绑定失败: {e}")
        return self

    def save_settings(self) -> bool:
        """保存设置面板(点Drawer内的"保存"按钮)"""
        try:
            # 在Drawer内找"保存"按钮
            drawer = self.page.locator('.ant-drawer, [class*="Drawer"]')
            save_btn = None
            for i in range(min(drawer.count(), 5)):
                if drawer.nth(i).is_visible():
                    b = drawer.nth(i).locator('button').filter(has_text="保存")
                    if b.count() > 0:
                        save_btn = b.first
                        break
            if save_btn is None:
                save_btn = self.page.get_by_role("button", name="保存").first
            save_btn.click()
            self.page.wait_for_timeout(1500)
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
                logger.info("[保存] DHCP静态分配设置保存成功")
            return success
        except Exception as e:
            logger.error(f"[保存] 设置保存异常: {e}")
            return False

    def cancel_settings(self):
        """取消设置面板(点Drawer内的"取消"按钮)"""
        try:
            drawer = self.page.locator('.ant-drawer, [class*="Drawer"]')
            for i in range(min(drawer.count(), 5)):
                if drawer.nth(i).is_visible():
                    b = drawer.nth(i).locator('button').filter(has_text="取消")
                    if b.count() > 0:
                        b.first.click()
                        self.page.wait_for_timeout(500)
                        return
            # 回退: 全局取消按钮
            cancel = self.page.get_by_role("button", name="取消")
            if cancel.count() > 0:
                cancel.first.click()
                self.page.wait_for_timeout(500)
        except Exception:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)

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
