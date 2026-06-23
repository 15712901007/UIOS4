"""
DHCP客户端页面操作类

网络配置 > DHCP服务 > DHCP客户端 页面
URL: /login#/networkConfiguration/dhcpService (DHCP客户端tab, 5个tab之一)

页面特点: 只读+操作型(无add/edit/import/export, 租约是DHCP动态产生的):
- 表格显示当前DHCP租约(来自/var/db/leases.db)
- 顶部: 搜索框 + 一键回收IP地址按钮
- 行内操作: 加入静态分配 / 加入黑名单
- 列: 终端名称/IP地址/MAC地址/绑定接口/状态/有效时间/主机名称/操作

数据库: /var/db/leases.db(leases表, 动态租约)
       加入静态分配 → dhcp_static表; 加入黑名单 → dhcp_acl_mac_black表
后端脚本: /usr/ikuai/script/dhcp_lease.sh(与dhcp_static共用同一脚本)
         register_module_urls: clients只读+put/delete, static全CRUD
         recycle(): 一键回收(force=1清空leases或回收过期IP via dhcpd_recycle_ip.lua)
         __show_data(): select from leases where mac not NULL and timeout>0 and interface!='lo'

DHCP客户端是DHCP服务端子功能, 共用ik_dhcpd进程(无独立iptables/内核)。
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
import logging

logger = logging.getLogger(__name__)


class DhcpLeasePage(IkuaiTablePage):
    """DHCP客户端页面操作类(只读+操作型, 无CRUD)"""

    MODULE_NAME = "dhcp_lease"
    PAGE_URL = "/login#/networkConfiguration/dhcpService"

    # 可排序列(实测th#id): 终端名称/IP地址/MAC地址/有效时间/主机名称
    COLUMN_ID_MAP = {
        "终端名称": "termname",
        "IP地址": "ip_addr_int",
        "MAC地址": "mac",
        "有效时间": "timeout",
        "主机名称": "hostname",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def _dismiss_residual_modal(self):
        """关闭残留的确认弹窗, 避免遮挡后续点击"""
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

    def navigate_to_dhcp_lease(self):
        """导航到DHCP服务 > DHCP客户端tab"""
        self._dismiss_residual_modal()
        url = f"{self.base_url}{self.PAGE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        self._dismiss_residual_modal()
        try:
            tab = self.page.get_by_role("tab", name="DHCP客户端")
            if tab.count() > 0:
                selected = tab.get_attribute("aria-selected")
                if selected != "true":
                    tab.click()
                    self.page.wait_for_timeout(1000)
        except Exception as e:
            logger.warning(f"[导航] 切换DHCP客户端tab异常: {e}")
        # 等待租约表格渲染(异步加载dhcp_lease show, navigate后需等行出现)
        self._wait_table_render()
        logger.info("[导航] 已到达DHCP客户端页面")
        return self

    def _wait_table_render(self, timeout: int = 8000):
        """等待租约表格渲染完成(.ant-table-row出现或确认无租约)"""
        try:
            self.page.wait_for_selector('.ant-table-row', timeout=timeout)
        except Exception:
            pass  # 无租约时.ant-table-row不出现, 超时后继续
        self.page.wait_for_timeout(500)

    def navigate_back_to_list(self):
        return self.navigate_to_dhcp_lease()

    def _close_any_dropdown(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    # ==================== 租约读取 ====================

    def get_lease_count(self) -> int:
        """读取当前租约数(从'共N条'文字, 回退到表格行数)"""
        try:
            # 搜索后"共N条"可能不更新, 优先用表格行数
            rows = self.page.locator('.ant-table-row')
            if rows.count() > 0:
                return rows.count()
        except Exception:
            pass
        try:
            import re
            text = self.page.locator('body').text_content() or ''
            m = re.search(r'共\s*(\d+)\s*条', text)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return 0

    def get_lease_list(self):
        """读取租约列表(每行的IP/MAC/hostname)"""
        self._wait_table_render()
        leases = []
        try:
            rows = self.page.locator('.ant-table-row')
            cnt = rows.count()
            # 诊断: 当前表格状态
            body_text = self.page.locator('body').text_content() or ''
            import re
            m = re.search(r'共\s*(\d+)\s*条', body_text)
            total_txt = m.group(0) if m else '无'
            has_empty = '暂无内容' in body_text
            logger.warning(f"[诊断] ant-table-row={cnt}, {total_txt}, 暂无内容={has_empty}")
            for i in range(min(cnt, 50)):
                # cell可能是td或.ant-table-cell(div), 两种都匹配
                cells = rows.nth(i).locator('td, .ant-table-cell')
                logger.warning(f"[诊断] 行{i} cells={cells.count()}")
                if cells.count() >= 7:
                    leases.append({
                        "termname": cells.nth(0).text_content().strip(),
                        "ip": cells.nth(1).text_content().strip(),
                        "mac": cells.nth(2).text_content().strip(),
                        "interface": cells.nth(3).text_content().strip(),
                        "status": cells.nth(4).text_content().strip(),
                        "hostname": cells.nth(6).text_content().strip(),
                    })
        except Exception as e:
            logger.warning(f"[读取] 读取租约列表失败: {e}")
        return leases

    def lease_exists(self, identifier: str) -> bool:
        """检查指定IP或MAC的租约是否在列表中"""
        try:
            el = self.page.get_by_text(identifier, exact=False).first
            return el.count() > 0
        except Exception:
            return False

    # ==================== 一键回收IP地址 ====================

    def click_recycle_all(self) -> bool:
        """点击'一键回收IP地址'按钮(清空leases.db的租约)

        recycle(): force=1清空所有, 否则回收过期IP。点击后ik_dhcpd delayed_restart。
        注意: 会断开当前DHCP客户端, 它们会重新获取IP。
        """
        try:
            btn = self.page.get_by_role("button", name="一键回收IP地址")
            if btn.count() > 0:
                btn.first.click()
                self.page.wait_for_timeout(800)
                # 可能有确认弹窗
                try:
                    confirm = self.page.locator(
                        ".ant-modal-confirm .ant-btn-primary, "
                        "[role='dialog'] button:has-text('确定')"
                    )
                    if confirm.count() > 0 and confirm.first.is_visible():
                        confirm.first.click()
                        self.page.wait_for_timeout(500)
                except Exception:
                    pass
                # 等待成功消息
                self.wait_for_success_message(timeout=8000)
                self.page.wait_for_timeout(2500)
                logger.info("[操作] 已点击一键回收IP地址")
                return True
        except Exception as e:
            logger.warning(f"[操作] 一键回收失败: {e}")
        return False

    # ==================== 加入静态分配(行内→弹窗) ====================

    def _click_row_action(self, identifier: str, action: str) -> bool:
        """定位含identifier(IP/MAC)的行, 点击行内action按钮(3次重试)

        DHCP客户端的操作按钮(加入静态分配/加入黑名单)与IP/MAC是兄弟列(不同cell),
        不是祖先关系, 故不能用_click_rule_button(上溯找按钮), 需先定位行再找行内按钮。
        操作列按钮可能异步渲染, 用重试+等待。
        """
        for attempt in range(3):
            try:
                row = self.page.locator('.ant-table-row').filter(has_text=identifier).first
                row.wait_for(state="visible", timeout=5000)
                btn = row.locator('button').filter(has_text=action)
                # 等待按钮渲染(操作列按钮可能异步)
                try:
                    btn.first.wait_for(state="attached", timeout=3000)
                except Exception:
                    pass
                if btn.count() > 0:
                    btn.first.click()
                    self.page.wait_for_timeout(800)
                    logger.info(f"[操作] 点击行内{action}(行={identifier[:20]})")
                    return True
                # 诊断: 行内有哪些按钮(首次失败时)
                if attempt == 0:
                    all_btns = row.locator('button')
                    btn_texts = []
                    for i in range(min(all_btns.count(), 10)):
                        try:
                            btn_texts.append((all_btns.nth(i).text_content() or '').strip()[:15])
                        except Exception:
                            pass
                    logger.warning(f"[诊断] 行内按钮(尝试{attempt+1}): {btn_texts}")
                self.page.wait_for_timeout(1200)
            except Exception as e:
                logger.warning(f"[操作] 点击行内{action}尝试{attempt+1}失败: {e}")
                self.page.wait_for_timeout(500)
        logger.warning(f"[操作] 行内未找到{action}按钮(3次重试失败)")
        return False

    def click_add_to_static(self, identifier: str) -> bool:
        """点击某租约行的'加入静态分配'按钮(按IP/MAC定位行)

        点击后弹出modal(标题'确定加入静态分配'+规则名称输入框#validateOnly_tagname+取消/确定)
        """
        return self._click_row_action(identifier, "加入静态分配")

    def fill_static_rule_name(self, name: str):
        """填写加入静态分配弹窗的规则名称(#validateOnly_tagname)"""
        inp = self.page.locator('#validateOnly_tagname')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill("")
            inp.first.fill(name)
            self.page.wait_for_timeout(200)
        return self

    def confirm_dialog(self) -> bool:
        """点击弹窗内的'确定'按钮(通用, 用于加入静态分配/黑名单弹窗)"""
        try:
            # 弹窗内"确定"按钮(优先.ant-modal内的primary按钮)
            modal = self.page.locator('.ant-modal, .ant-modal-confirm')
            for i in range(min(modal.count(), 5)):
                if modal.nth(i).is_visible():
                    btn = modal.nth(i).locator('button').filter(has_text="确定")
                    if btn.count() > 0:
                        btn.first.click()
                        self.page.wait_for_timeout(1500)
                        # 检测成功消息
                        try:
                            msg = self.page.locator(".ant-message-success")
                            if msg.count() > 0 and msg.first.is_visible():
                                return True
                        except Exception:
                            pass
                        return self.wait_for_success_message(timeout=5000)
            # 回退: 全局确定
            ok = self.page.get_by_role("button", name="确定")
            if ok.count() > 0:
                ok.first.click()
                self.page.wait_for_timeout(1500)
                return self.wait_for_success_message(timeout=5000)
        except Exception as e:
            logger.warning(f"[操作] 确定弹窗失败: {e}")
        return False

    def cancel_dialog(self):
        """点击弹窗内的'取消'按钮"""
        try:
            modal = self.page.locator('.ant-modal, .ant-modal-confirm')
            for i in range(min(modal.count(), 5)):
                if modal.nth(i).is_visible():
                    btn = modal.nth(i).locator('button').filter(has_text="取消")
                    if btn.count() > 0:
                        btn.first.click()
                        self.page.wait_for_timeout(500)
                        return
            cancel = self.page.get_by_role("button", name="取消")
            if cancel.count() > 0:
                cancel.first.click()
                self.page.wait_for_timeout(500)
        except Exception:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)

    # ==================== 加入黑名单(行内) ====================

    def click_add_to_blacklist(self, identifier: str) -> bool:
        """点击某租约行的'加入黑名单'按钮(按IP/MAC定位行)

        把该MAC加入dhcp_acl_mac_black表。可能弹窗(填名称)或直接加入。
        """
        return self._click_row_action(identifier, "加入黑名单")

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
