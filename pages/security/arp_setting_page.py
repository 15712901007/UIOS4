"""
ARP设置页面类 (安全中心 > ARP设置)

URL: 列表 /login#/securityCenter/arpSetting, 新增 /login#/securityCenter/arpSetting/add
两个Tab: ARP绑定 / 邻居列表
ARP绑定Tab: 表格9列(名称/终端名称/IP地址/MAC地址/所属网卡/绑定类型/绑定状态/备注/操作)
  顶部按钮: 添加/清空/导入/导出/帮助; 行操作: 编辑/绑定/删除
  右上角齿轮设置按钮 → 浮层"ARP绑定设置"含2复选框(兼容DHCP静态分配/非绑定MAC不允许上网)+保存/取消
邻居列表Tab: 只读IPv6邻居(终端MAC/IPv6地址/接口/终端名称/状态/操作), 按钮 清空/删除(无添加,内核自动学习)

页面特点 (2026-07-14 Playwright+SSH探查):
- 新增/编辑是独立配置页(路由跳转arpSetting/add|edit, 非drawer/modal)
- 表单字段: 名称*/终端名称/IP地址*/MAC地址*/所属网卡*select/绑定类型*select(普通=0/唯一=1)/备注textarea
- 所属网卡select选项格式"{备注}({接口名})"或纯接口名(LAN1无备注), DB存小写接口名(lan1/wan1)
- 绑定类型select: 普通(0)/唯一(1)
- 列表含两类: 用户绑定(arp表, bind_state=1)+动态学习(/proc/net/arp, bind_state=0未绑定)
- 行操作"绑定": 动态学习项一键转绑定(arp -s 进arp_default/arpip_default)
- 顶部"清空": 清空所有用户绑定(arp表DELETE, 不删动态学习项)

后端机制(arp.sh): 表arp(id/tagname unique/ip_addr unique/mac/interface/comment/bind_type);
  global_config.arp_filter(0/1)+dhcpd_arp(0/1);
  4 ipset: Linux_arp_default(mac)+Linux_arpip_default(ip)←bind_type=0; Linux_arponly_default(mac)+Linux_iponly_default(ip)←bind_type=1;
  arp_filter=1时FORWARD→ARP链REJECT非绑定IP/MAC(白名单,只放行bind_type=0).

继承AclPage复用: fill_name/fill_remark/_select_by_label/click_save/has_form_error/delete_rule/edit_rule/
  rule_exists/get_rule_count/clean_test_rules/_click_rule_button/_dismiss_all_modals/_click_visible_confirm 等.
"""
from typing import Optional, List, Dict
from playwright.sync_api import Page
from pages.security.acl_page import AclPage


class ArpSettingPage(AclPage):
    """ARP设置页面操作类, 继承AclPage复用通用方法"""

    MODULE_NAME = "arp_setting"
    LIST_URL = "/login#/securityCenter/arpSetting"
    ADD_URL = "/login#/securityCenter/arpSetting/add"

    # 绑定类型 UI文本 → DB值
    BIND_TYPE_UI = {"0": "普通", "1": "唯一"}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================
    def navigate_to_arp(self):
        """导航到ARP设置列表页"""
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2500)
        # 清残留modal(设置弹窗/清空确认), 避免遮挡Tab点击(ant-modal-wrap intercepts pointer events)
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        # 默认在ARP绑定Tab
        self.switch_to_tab("arp")
        return self

    def open_add_page(self) -> bool:
        """直接goto新增页(ARP add是独立路由, 直接goto最可靠). 先清残留modal."""
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        try:
            self.page.evaluate(f"location.hash='{self.LIST_URL.split('#')[1]}'")
            self.page.wait_for_timeout(1000)
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2500)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        """是否在配置页(add/edit)"""
        try:
            url = self.page.url
            return ("arpSetting/add" in url or "arpSetting/edit" in url) and \
                   self.page.get_by_placeholder("请输入名称").count() > 0
        except Exception:
            url = self.page.url
            return "arpSetting/add" in url or "arpSetting/edit" in url

    def is_still_on_config_page(self) -> bool:
        """是否还在配置页(保存被阻止时停留)"""
        url = self.page.url
        return "arpSetting/add" in url or "arpSetting/edit" in url

    def save_and_wait(self, timeout: int = 8000) -> dict:
        """点保存并轮询结果. 成功=URL离开配置页(跳回列表); 失败=停留或有错误.
        重写AclPage.save_and_wait(AclPage硬编码判断aclRulesConfig)."""
        result = {"success": False, "error": ""}
        try:
            self.click_save()
            for _ in range(int(timeout / 400)):
                self.page.wait_for_timeout(400)
                err = self.has_form_error()
                if err:
                    result["error"] = err
                    return result
                if not self.is_still_on_config_page():
                    result["success"] = True
                    return result
            if not self.is_still_on_config_page():
                result["success"] = True
            else:
                result["error"] = "保存后仍在配置页"
        except Exception as e:
            result["error"] = str(e)[:80]
        return result

    # ==================== 配置页字段 ====================
    def fill_ip(self, ip: str) -> bool:
        """填IP地址(placeholder=请输入IP地址)"""
        try:
            inp = self.page.get_by_placeholder("请输入IP地址")
            if inp.count() == 0:
                return False
            inp.first.click()
            inp.first.fill("")
            inp.first.type(ip, delay=30)
            return True
        except Exception as e:
            print(f"[DEBUG] fill_ip error: {e}")
            return False

    def fill_mac(self, mac: str) -> bool:
        """填MAC地址(placeholder含'请输入MAC地址', 格式如00:11:22:33:44:55)"""
        try:
            inp = self.page.get_by_placeholder("请输入MAC地址，格式如：00:11:22:33:44:55")
            if inp.count() == 0:
                # 兜底: 模糊匹配
                inp = self.page.locator("input[placeholder*='请输入MAC地址']")
            if inp.count() == 0:
                return False
            inp.first.click()
            inp.first.fill("")
            inp.first.type(mac, delay=30)
            return True
        except Exception as e:
            print(f"[DEBUG] fill_mac error: {e}")
            return False

    def fill_termname(self, termname: str) -> bool:
        """填终端名称(placeholder=请输入终端名称, 可选)"""
        try:
            inp = self.page.get_by_placeholder("请输入终端名称")
            if inp.count() == 0:
                return False
            inp.first.click()
            inp.first.fill("")
            inp.first.type(termname, delay=20)
            return True
        except Exception as e:
            print(f"[DEBUG] fill_termname error: {e}")
            return False

    def select_interface(self, iface_ui: str) -> bool:
        """选所属网卡. iface_ui=UI显示文本(如'LAN1'/'WAN1 (wan1)'). DB存小写接口名."""
        return self._select_by_label("所属网卡", iface_ui)

    def select_bind_type(self, bind_type) -> bool:
        """选绑定类型. bind_type=0普通/1唯一"""
        ui = self.BIND_TYPE_UI.get(str(bind_type), str(bind_type))
        return self._select_by_label("绑定类型", ui)

    # ==================== 完整添加流程 ====================
    def add_rule(self, name: str, ip: str, mac: str, interface: str = "LAN1",
                 bind_type=0, termname: str = "", remark: str = "") -> dict:
        """添加ARP绑定规则. 返回 {success, error}.
        interface: UI显示文本(默认LAN1); bind_type: 0普通/1唯一."""
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            self.fill_name(name)
            # 终端名称: 空值触发前端"字段验证错误终端名称"(即使required=false), 默认用name填充避免
            self.fill_termname(termname if termname else name)
            self.fill_ip(ip)
            self.fill_mac(mac)
            self.select_interface(interface)
            self.select_bind_type(bind_type)
            if remark:
                self.fill_remark(remark)
            sv = self.save_and_wait()
            if sv["success"]:
                result["success"] = True
            else:
                result["error"] = sv["error"]
        except Exception as e:
            result["error"] = str(e)[:120]
        return result

    def try_add_rule_invalid(self, name: str = "", ip: str = "", mac: str = "") -> dict:
        """异常输入测试: 空名称/非法MAC/非法IP/重复IP, 验证前端拦截(保存被阻止=blocked=True)."""
        result = {"success": False, "error": "", "blocked": False}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            if name:
                self.fill_name(name)
            self.fill_termname("testterm")  # 填合法终端名称, 避免空值报错干扰目标异常判定
            if ip:
                self.fill_ip(ip)
            if mac:
                self.fill_mac(mac)
            self.select_interface("LAN1")
            self.select_bind_type(0)
            self.click_save()
            self.page.wait_for_timeout(1500)
            err = self.has_form_error()
            if err:
                result["blocked"] = True
                result["error"] = err
            elif self.is_still_on_config_page():
                result["blocked"] = True
                result["error"] = "保存被阻止(停留配置页)"
            if not self.is_still_on_config_page():
                result["error"] = "异常输入未被拦截(保存成功)"
        except Exception as e:
            result["error"] = str(e)[:120]
        return result

    # ==================== 设置弹窗(右上角齿轮) ====================
    def open_settings(self) -> bool:
        """点右上角齿轮设置按钮, 打开'ARP绑定设置'浮层"""
        try:
            btn = self.page.locator("[class*='_settingButton_']")
            if btn.count() == 0:
                print("[DEBUG] open_settings: 未找到设置按钮")
                return False
            btn.first.click()
            self.page.wait_for_timeout(1000)
            return True
        except Exception as e:
            print(f"[DEBUG] open_settings error: {e}")
            return False

    def close_settings(self) -> bool:
        """关闭设置浮层(Esc或点取消)"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(500)
            return True
        except Exception:
            return False

    def get_arp_setting(self) -> Dict:
        """读设置弹窗两个复选框状态. 返回 {arp_filter: bool/None, dhcpd_arp: bool/None}"""
        try:
            return self.page.evaluate("""() => {
                const get = (kw) => {
                    const cb=[...document.querySelectorAll('.ant-checkbox-wrapper')]
                        .find(e=>e.offsetParent!==null && (e.textContent||'').includes(kw));
                    if(!cb) return null;
                    const inp=cb.querySelector('input[type=checkbox]');
                    return inp ? inp.checked : (cb.querySelector('.ant-checkbox-checked')!==null);
                };
                return {arp_filter: get('非绑定'), dhcpd_arp: get('DHCP')};
            }""")
        except Exception:
            return {}

    def toggle_arp_option(self, option: str, enable: bool) -> bool:
        """切换设置弹窗复选框到指定状态. option='arp_filter'(非绑定MAC不允许上网)/'dhcpd_arp'(兼容DHCP静态分配)."""
        kw = {"arp_filter": "非绑定", "dhcpd_arp": "DHCP"}.get(option, option)
        try:
            ok = bool(self.page.evaluate("""({kw, en}) => {
                const cb=[...document.querySelectorAll('.ant-checkbox-wrapper')]
                    .find(e=>e.offsetParent!==null && (e.textContent||'').includes(kw));
                if(!cb) return false;
                const inp=cb.querySelector('input[type=checkbox]');
                const checked = inp ? inp.checked : (cb.querySelector('.ant-checkbox-checked')!==null);
                if(checked !== en){ cb.click(); }
                return true;
            }""", {"kw": kw, "en": enable}))
            self.page.wait_for_timeout(600)
            return ok
        except Exception as e:
            print(f"[DEBUG] toggle_arp_option({option}) error: {e}")
            return False

    def save_settings(self) -> bool:
        """点设置浮层内的保存按钮(定位含'ARP绑定设置'标题的浮层根内的保存按钮)"""
        try:
            clicked = bool(self.page.evaluate("""() => {
                const title=[...document.querySelectorAll('*')]
                    .find(e=>e.childNodes.length<=3 && (e.textContent||'').trim()==='ARP绑定设置');
                let root = title;
                if(root){ for(let i=0;i<6;i++){ if(root.parentElement) root=root.parentElement; } }
                else { root = document.body; }
                const btns=[...root.querySelectorAll('button')]
                    .filter(b=>b.offsetParent!==null && (b.textContent||'').trim()==='保存');
                if(btns.length){ btns[btns.length-1].click(); return true; }
                return false;
            }"""))
            self.page.wait_for_timeout(1500)
            return clicked
        except Exception as e:
            print(f"[DEBUG] save_settings error: {e}")
            return False

    # ==================== Tab切换 ====================
    def switch_to_tab(self, tab: str = "arp") -> bool:
        """切换Tab. tab='arp'(ARP绑定)/'neighbor'(邻居列表)"""
        kw = "ARP绑定" if tab == "arp" else "邻居列表"
        try:
            loc = self.page.locator(f".ant-tabs-tab:has-text('{kw}')")
            if loc.count() == 0:
                return False
            loc.first.click()
            self.page.wait_for_timeout(1500)
            return True
        except Exception as e:
            print(f"[DEBUG] switch_to_tab({tab}) error: {e}")
            return False

    # ==================== ARP特有操作: 清空/绑定 ====================
    def clear_all_arp(self) -> bool:
        """点ARP绑定Tab顶部'清空'按钮(清空所有用户绑定) + 确认弹窗.
        arp.sh clean(): DELETE FROM arp + flush 4 ipset + arp -d. 不删动态学习项."""
        try:
            btn = self.page.get_by_role("button", name="清空")
            if btn.count() == 0:
                print("[DEBUG] clear_all_arp: 未找到清空按钮")
                return False
            btn.first.click()
            self.page.wait_for_timeout(1000)
            # 清空确认弹窗按钮是"确认清空"(非通用"确定", 实测_click_visible_confirm找不到)
            try:
                self.page.get_by_role("button", name="确认清空").click(timeout=4000)
            except Exception:
                self._click_visible_confirm(timeout=3000)
            self.page.wait_for_timeout(2000)
            return True
        except Exception as e:
            print(f"[DEBUG] clear_all_arp error: {e}")
            return False

    def bind_rule(self, rule_name: str) -> bool:
        """点行操作'绑定'(动态学习项一键转绑定, bind_state=0→1, 触发arp -s)."""
        try:
            clicked = self._click_rule_button(rule_name, "绑定")
            if not clicked:
                return False
            self.page.wait_for_timeout(1500)
            # 可能有确认弹窗或成功提示
            try:
                self._click_visible_confirm(timeout=2000)
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[DEBUG] bind_rule({rule_name}) error: {e}")
            return False

    # ==================== 邻居列表Tab ====================
    def get_neighbor_count(self) -> int:
        """获取邻居列表(IPv6)行数. 切到neighbor Tab后, 当前可见table的行数."""
        try:
            cnt = self.page.evaluate("""() => {
                const tables=[...document.querySelectorAll('.ant-table')].filter(t=>t.offsetParent!==null);
                if(!tables.length) return 0;
                const t = tables[tables.length-1];
                return t.querySelectorAll('.ant-table-row').length;
            }""")
            return int(cnt or 0)
        except Exception:
            return 0

    def neighbor_exists(self, keyword: str) -> bool:
        """邻居列表是否含关键字(IPv6地址/MAC/接口)"""
        try:
            return bool(self.page.evaluate("""(kw) => {
                const tables=[...document.querySelectorAll('.ant-table')].filter(t=>t.offsetParent!==null);
                if(!tables.length) return false;
                const t = tables[tables.length-1];
                return [...t.querySelectorAll('.ant-table-row')].some(r=>(r.innerText||'').includes(kw));
            }""", keyword))
        except Exception:
            return False

    # ==================== 列表读取(覆盖, ARP绑定Tab的table) ====================
    def rule_exists(self, rule_name: str) -> bool:
        """ARP绑定Tab是否含规则名(第一个可见table, ARP绑定列表)."""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
            return bool(self.page.evaluate("""(name) => {
                const tables=[...document.querySelectorAll('.ant-table')].filter(t=>t.offsetParent!==null);
                if(!tables.length) return false;
                const t = tables[0];
                return [...t.querySelectorAll('.ant-table-row')].some(r=>(r.innerText||'').includes(name));
            }""", rule_name))
        except Exception:
            return False

    def get_rule_count(self) -> int:
        """获取ARP绑定总数(从'共 N 条')"""
        try:
            cnt = self.page.evaluate("""() => {
                const m=document.body.innerText.match(/共\\s*(\\d+)\\s*条/);
                return m?parseInt(m[1]):0;
            }""")
            return int(cnt or 0)
        except Exception:
            return 0

    def clean_test_rules(self, prefix: str = "arp_t_") -> int:
        """前端逐条删除prefix开头的ARP绑定(兜底清理). ARP列表含动态学习项, prefix过滤只删用户绑定."""
        cnt = 0
        for _ in range(50):
            try:
                names = self.page.evaluate("""(pfx) => {
                    const tables=[...document.querySelectorAll('.ant-table')].filter(t=>t.offsetParent!==null);
                    if(!tables.length) return [];
                    const t = tables[0];
                    const found=[];
                    for(const r of t.querySelectorAll('.ant-table-row')){
                        const txt=(r.innerText||'').trim();
                        const first=txt.split(/\\s|\\n/)[0]||'';
                        if(first.startsWith(pfx)) found.push(first);
                    }
                    return found;
                }""", prefix)
                if not names:
                    break
                if self.delete_rule(names[0]):
                    cnt += 1
                else:
                    break
                self.page.wait_for_timeout(500)
            except Exception:
                break
        return cnt
