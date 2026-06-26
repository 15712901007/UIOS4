"""
IPv6内网设置页面操作类

网络配置 > 内外网设置 > IPv6设置 > 内网设置 tab
URL: /login#/networkConfiguration/internalAndExternalNetworkSettings
  (IPv6设置顶部第2个tab, 内网设置是其第2个子tab)
添加/编辑为独立页面:
  - 添加: /login#/networkConfiguration/internalAndExternalNetworkSettings/ipv6Settings/intranetSetting/add
  - 编辑: .../ipv6Settings/intranetSetting/edit/<id>

实测表单结构 (2026-06-26 UI探查):
- 名称*: id=tagname (必填)
- 内网接口*: id=interface (combobox, 可选 doc_app_default / lan1; lan1被默认CFLAN_1占用UNIQUE)
- 配置类型*: id=internet (combobox, 默认自动获取=dhcp; 可选 自动获取/静态IP/中继)
- 绑定外网线路*: id=rc_select_14 (多选checkbox下拉, 不稳定id, 按label定位;
              选项 全部/wan1/wan2/wan3; dhcp/relay模式必填, 对应parent字段)
- 前缀分配长度*: id=prefix_len (combobox, 默认自动)
- DHCPv6: id=dhcpv6 (checkbox, 默认勾选)
- DHCPv6模式*: id=ra_flags (combobox, 默认无状态+有状态; 0无状态/1无状态+有状态/2有状态)
- RA通告绑定: id=ra_static (checkbox)
- IPv6 DNS: id=use_dns6 (checkbox; 勾选后出现ipv6_dns1/ipv6_dns2)
- 租期*: id=leasetime (spinbutton, 默认120, 单位分钟, >0且<=525600)
- RA MTU: id=ra_mtu_set (checkbox; 勾选后出现ra_mtu输入)
!!注意: 内网设置表单无enabled字段, add()默认enabled=yes(schema默认)

数据库字段映射 (ipv6.sh add/edit确认):
- ipv6_lan_config表:
  id, enabled(默认yes), tagname(名称unique), interface(内网接口, unique),
  parent(绑定外网线路, 逗号分隔wan列表; static时清空, relay时取第一个),
  internet(dhcp/static/relay), prefix_len(前缀分配长度auto), dhcpv6(0/1),
  ipv6_addr(LAN IPv6地址, static模式), use_dns6(0/1), ipv6_dns1, ipv6_dns2,
  ra_flags(0/1/2), ra_static(0/1), ra_mtu_set(0/1), ra_mtu(1000-1500),
  leasetime(租期分钟)

后端关键约束 (ipv6.sh):
- add/__check_param: enabled/interface(ifname_lan)/internet(dhcp|static|relay)
  + dhcp/relay时parent(ifnames_wan必填) + dhcpv6(0|1) + use_dns6=1时ipv6_dns1/dns2
  + ra_mtu_set=1时ra_mtu(1000-1500) + leasetime(>0且<=525600) + ra_flags(0|1|2)
- interface字段UNIQUE: lan1被默认CFLAN_1占用, 新增只能用doc_app_default(测试设备仅2个内网接口)
- 故内网设置受接口唯一约束, 最多新增1条(doc_app_default), 无批量操作意义
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class Ipv6LanPage(IkuaiTablePage):
    """IPv6内网设置页面操作类(表格型, 独立页面表单全#id)"""

    MODULE_NAME = "ipv6_lan"
    PAGE_URL = "/login#/networkConfiguration/internalAndExternalNetworkSettings"
    ADD_URL = "/login#/networkConfiguration/internalAndExternalNetworkSettings/ipv6Settings/intranetSetting/add"

    # 配置类型(internet) UI文案
    INTERNET_DHCP = "自动获取"       # internet=dhcp
    INTERNET_STATIC = "静态IP"       # internet=static
    INTERNET_RELAY = "中继"          # internet=relay

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def _dismiss_residual_modal(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def navigate_to_ipv6_lan(self):
        """导航到 内外网设置 > IPv6设置 > 内网设置 tab"""
        self._dismiss_residual_modal()
        url = f"{self.base_url}{self.PAGE_URL}"
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(800)
        self._dismiss_residual_modal()
        try:
            self.page.evaluate("""() => {
                const tabs = Array.from(document.querySelectorAll('.ant-tabs-tab'));
                const t = tabs.find(x => x.textContent.trim() === 'IPv6设置');
                if (t && t.getAttribute('aria-selected') !== 'true') t.click();
            }""")
            self.page.wait_for_timeout(800)
            self.page.evaluate("""() => {
                const subs = Array.from(document.querySelectorAll('.ant-tabs-tab'));
                const s = subs.find(x => x.textContent.trim() === '内网设置');
                if (s && s.getAttribute('aria-selected') !== 'true') s.click();
            }""")
            self.page.wait_for_timeout(500)
        except Exception as e:
            logger.warning(f"[导航] 切换IPv6内网设置tab异常: {e}")
        return self

    def navigate_back_to_list(self):
        return self.navigate_to_ipv6_lan()

    # ==================== 表单字段(全#id) ====================

    def _set_input(self, field_id: str, value: str):
        """用原生setter填写#id文本框/spinbutton(React安全)"""
        try:
            self.page.evaluate("""([fid, val]) => {
                const el = document.getElementById(fid);
                if (!el) return false;
                const proto = el.tagName === 'TEXTAREA'
                    ? window.HTMLTextAreaElement.prototype
                    : window.HTMLInputElement.prototype;
                const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
                setter.call(el, val);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                return true;
            }""", [field_id, value])
            self.page.wait_for_timeout(150)
        except Exception as e:
            logger.warning(f"[表单] 填写#{field_id}异常: {e}")
        return self

    def fill_name(self, name: str):
        return self._set_input("tagname", name)

    def fill_leasetime(self, minutes: str):
        """租期 (id=leasetime spinbutton, 单位分钟)"""
        return self._set_input("leasetime", str(minutes))

    def set_checkbox(self, field_id: str, checked: bool):
        """勾选/取消#id checkbox(dhcpv6/ra_static/use_dns6/ra_mtu_set)"""
        try:
            cb = self.page.locator(f'#{field_id}')
            if cb.count() > 0 and cb.is_checked() != checked:
                wrapper = self.page.locator(f'.ant-checkbox-wrapper:has(#{field_id})')
                if wrapper.count() > 0:
                    wrapper.first.click()
                else:
                    cb.first.click(force=True)
                self.page.wait_for_timeout(200)
        except Exception as e:
            logger.warning(f"[表单] 设置#{field_id}={checked}异常: {e}")
        return self

    def _select_combobox(self, field_id: str, option_text: str) -> bool:
        """选择#field_id combobox选项(Playwright打开+JS点选项)"""
        try:
            sel = self.page.locator(f'.ant-select:has(#{field_id}) .ant-select-selector')
            if sel.count() == 0:
                return False
            sel.first.click()
            self.page.wait_for_timeout(700)
            clicked = self.page.evaluate("""(text) => {
                const dd = Array.from(document.querySelectorAll('.ant-select-dropdown'))
                    .filter(d => d.offsetHeight > 0);
                for (const d of dd) {
                    const opts = d.querySelectorAll('.ant-select-item-option');
                    for (const o of opts) {
                        if (o.textContent.trim() === text || o.getAttribute('title') === text) {
                            o.click(); return true;
                        }
                    }
                }
                return false;
            }""", option_text)
            if clicked:
                self.page.wait_for_timeout(400)
                return True
        except Exception as e:
            logger.warning(f"[表单] 选择#{field_id}={option_text}异常: {e}")
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass
        return False

    def select_interface(self, iface: str = "doc_app_default"):
        """内网接口 (id=interface)"""
        return self._select_combobox("interface", iface)

    def select_internet(self, mode: str = "自动获取"):
        """配置类型 (id=internet)"""
        return self._select_combobox("internet", mode)

    def select_ra_flags(self, mode: str = "无状态+有状态"):
        """DHCPv6模式 (id=ra_flags)"""
        return self._select_combobox("ra_flags", mode)

    def select_parents(self, interfaces: List[str]) -> bool:
        """绑定外网线路 (parent, 多选checkbox, 弹出的是.ant-popover非select-dropdown)

        实测结构: 点.ant-select-multiple .ant-select-selector弹出.ant-popover, 内含
        .ant-checkbox-group > label.ant-checkbox-wrapper(wan1/wan2/wan3) + 独立"全部".
        Ant坑: JS element.click()不触发React勾选, 必须Playwright真实点击label.

        Args:
            interfaces: 外网线路名列表, 如 ["wan1"]
        """
        try:
            # 打开popover(用.ant-select-multiple唯一定位parent, 此表单仅parent为多选)
            sel = self.page.locator('.ant-select-multiple .ant-select-selector')
            if sel.count() == 0:
                logger.warning("[表单] 绑定外网线路(多选)selector未找到")
                return False
            sel.first.click()
            self.page.wait_for_timeout(800)
            for iface in interfaces:
                try:
                    # .ant-checkbox-group内的wrapper(排除独立"全部"), :has-text精确到wan1
                    cb = self.page.locator(
                        f'.ant-popover .ant-checkbox-group label.ant-checkbox-wrapper:has-text("{iface}")'
                    )
                    if cb.count() == 0:
                        logger.warning(f"[表单] 绑定外网线路未找到选项 {iface}")
                        continue
                    # 避免重复点击取消选中: 先看是否已checked
                    is_checked = cb.first.evaluate(
                        "el => el.classList.contains('ant-checkbox-wrapper-checked')"
                    )
                    if not is_checked:
                        cb.first.click()
                        self.page.wait_for_timeout(300)
                except Exception as e:
                    logger.warning(f"[表单] 勾选parent {iface}异常: {e}")
            # 关闭popover
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
            return True
        except Exception as e:
            logger.warning(f"[表单] 绑定外网线路异常: {e}")
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    def get_selected_parents(self) -> List[str]:
        """读取已选绑定外网线路(tag文本)"""
        try:
            return self.page.evaluate("""() => {
                const items = document.querySelectorAll(
                    '.ant-form-item:has(.ant-form-item-label:has-text("绑定外网线路")) '
                    + '.ant-select-selection-item-content, '
                    + '.ant-form-item:has(.ant-form-item-label:has-text("绑定外网线路")) '
                    + '.ant-select-selection-item');
                return Array.from(items).map(i => i.textContent.trim());
            }""")
        except Exception:
            return []

    # ==================== 规则列表查询 ====================

    def get_rule_list(self) -> List[str]:
        """获取内网设置规则名称列表(tagname列)"""
        try:
            names = self.page.evaluate("""() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                for (const row of rows) {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length > 1) {
                        const name = cells[1].textContent.trim();
                        if (name && name !== '暂无内容') result.push(name);
                    }
                }
                return result;
            }""")
            return names if names else []
        except Exception:
            return []

    # ==================== 添加/编辑/删除 ====================

    def open_add_page(self):
        """进入独立添加页(直接导航ADD_URL最可靠)"""
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        self.page.wait_for_load_state("networkidle")
        try:
            self.page.wait_for_selector('#tagname', timeout=10000)
        except Exception:
            self.page.wait_for_timeout(1000)
        self.page.wait_for_timeout(500)
        return self

    def _read_save_result(self) -> tuple:
        """读取保存后结果(success, message). 轮询~6s(保存成功后异步跳转回列表)"""
        try:
            for _ in range(12):
                self.page.wait_for_timeout(500)
                err = self.page.locator(
                    '.ant-message-error:visible, .ant-message-notice .ant-message-error:visible')
                if err.count() > 0:
                    return (False, err.first.text_content().strip()[:120])
                form_err = self.page.locator('.ant-form-item-explain-error:visible')
                if form_err.count() > 0:
                    return (False, form_err.first.text_content().strip()[:120])
                cur = self.page.url
                if "/add" not in cur and "/edit" not in cur:
                    return (True, "已返回列表")
                ok = self.page.locator('.ant-message-success:visible')
                if ok.count() > 0:
                    return (True, ok.first.text_content().strip()[:120])
            cur = self.page.url
            if "/add" not in cur and "/edit" not in cur:
                return (True, "已返回列表")
            return (False, "")
        except Exception:
            return (False, "")

    def add_rule(self, name: str,
                 interface: str = "doc_app_default",
                 internet: str = "自动获取",
                 parents: List[str] = None,
                 prefix_len: str = "自动",
                 dhcpv6: bool = True,
                 ra_flags: str = "无状态+有状态",
                 leasetime: str = "120") -> bool:
        """添加IPv6内网设置规则

        Args:
            name: 名称(tagname必填)
            interface: 内网接口(默认doc_app_default; lan1被默认占用)
            internet: 配置类型(自动获取dhcp/静态IP/中继)
            parents: 绑定外网线路列表(dhcp/relay必填, 如["wan1"])
            prefix_len: 前缀分配长度(默认自动)
            dhcpv6: DHCPv6开关(默认开)
            ra_flags: DHCPv6模式(无状态/无状态+有状态/有状态)
            leasetime: 租期分钟(默认120)
        """
        try:
            self.open_add_page()
            self.fill_name(name)
            if interface:
                self.select_interface(interface)
                self.page.wait_for_timeout(300)
            if internet:
                self.select_internet(internet)
                self.page.wait_for_timeout(400)
            if parents:
                self.select_parents(parents)
                self.page.wait_for_timeout(300)
            self.set_checkbox("dhcpv6", dhcpv6)
            if ra_flags:
                self.select_ra_flags(ra_flags)
                self.page.wait_for_timeout(300)
            self.fill_leasetime(leasetime)

            self.click_save()
            success, msg = self._read_save_result()
            print(f"  [add_rule] {name}: success={success}, msg={msg[:60]}")
            if not success:
                try:
                    self.click_cancel()
                except Exception:
                    self.page.keyboard.press("Escape")
                self.navigate_back_to_list()
                return False
            self.navigate_back_to_list()
            self.page.wait_for_timeout(500)
            return True
        except Exception as e:
            print(f"[ERROR] 添加IPv6内网设置失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    def edit_rule(self, old_name: str, new_name: str = None,
                  leasetime: str = None) -> bool:
        """编辑IPv6内网设置规则"""
        try:
            clicked = self._click_rule_button(old_name, "编辑")
            if not clicked:
                print(f"[WARN] 编辑按钮未找到: {old_name}")
                return False
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector('#tagname', timeout=8000)
            except Exception:
                self.page.wait_for_timeout(800)
            if new_name is not None:
                self.fill_name(new_name)
            if leasetime is not None:
                self.fill_leasetime(leasetime)
            self.click_save()
            success, msg = self._read_save_result()
            print(f"  [edit_rule] {old_name}: success={success}, msg={msg[:60]}")
            if success:
                self.navigate_back_to_list()
                return True
            try:
                self.click_cancel()
            except Exception:
                self.page.keyboard.press("Escape")
            self.navigate_back_to_list()
            return False
        except Exception as e:
            print(f"[ERROR] 编辑IPv6内网设置失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    def delete_rule(self, rule_name: str) -> bool:
        return super().delete_rule(rule_name)

    # ==================== 异常输入测试 ====================

    def try_add_rule_invalid(self, name: str = "",
                             interface: str = None,
                             parents: List[str] = None,
                             expect_fail: bool = True) -> dict:
        """尝试添加无效内网设置规则(测表单/后端校验). 只填提供的字段.

        轮询~5s: 出现可见错误=被拦截; URL离开/add|/edit=已保存(未拦截).
        """
        try:
            self.open_add_page()
            self.page.wait_for_timeout(300)
            if name is not None:
                self.fill_name(name)
            if interface:
                self.select_interface(interface)
                self.page.wait_for_timeout(300)
            if parents:
                self.select_parents(parents)
                self.page.wait_for_timeout(300)
            self.click_save()
            intercepted = False
            msg = ""
            for _ in range(10):
                self.page.wait_for_timeout(500)
                err = self.page.locator(
                    '.ant-form-item-explain-error:visible, .ant-message-error:visible')
                if err.count() > 0:
                    intercepted = True
                    msg = err.first.text_content().strip()[:120]
                    break
                cur = self.page.url
                if "/add" not in cur and "/edit" not in cur:
                    intercepted = False
                    break
            if expect_fail:
                self._safe_back()
                return {"success": intercepted, "error_message": msg}
            return {"success": True, "error_message": ""}
        except Exception as e:
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return {"success": False, "error_message": str(e)}

    def _safe_back(self):
        try:
            self.click_cancel()
        except Exception:
            self.page.keyboard.press("Escape")
        self.page.wait_for_timeout(300)
        if "/add" in self.page.url or "/edit" in self.page.url:
            self.navigate_back_to_list()
