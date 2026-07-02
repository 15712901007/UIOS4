"""
内外网设置页面类

网络配置 > 内外网设置 > 内外网设置(第1个tab)
URL: /#/networkConfiguration/internalAndExternalNetworkSettings
编辑: 点击"配置"→ 路由跳转 /#/.../editLanWan (独立页面, 非弹窗)
新增: 点击"新增配置"→ 弹窗选网卡+类型 → 编辑页
网卡绑定: 点击"选择网卡"→ 弹窗checkbox勾选/取消网卡

页面特点: 虚拟滚动 div.ant-table-row 表格(非tr), 行操作为链接文字.
⚠️ 安全约束: wan1(eth5=10.66.0.150测试机访问地址)绝对只读, Page层硬拒绝编辑.

数据库表 (来自 lan.sh/wan.sh 探索):
- lan_config: id/tagname/bandif(网卡mac列表)/bandeth/ip_mask/lan_visit(0关1开)/bandmode/comment
- wan_config: id/tagname/bandif/internet(0静态1DHCP2PPPoE)/ip_mask/gateway/link_time/
              check_link_mode/check_link_host/default_route/disc_auto_switch/comment

实测UI结构 (2026-06-29 Playwright探查):
- 表格列: 线路名称/网口/物理网卡/接入方式/IP地址/VLAN/工作模式/网卡速率/克隆MAC/链路聚合/DHCP服务/操作
- 行: div.ant-table-row, 操作: 选择网卡/配置/删除(lan1行额外有"新增VLAN")
- WAN编辑页字段(按placeholder/顺序):
  - 名称: placeholder=请输入名称
  - 接入方式: select(当前值含DHCP), 选项: 静态IP（固定IP）/DHCP（动态获取）/ADSL/PPPoE拨号
  - 静态IP: IP/掩码/网关/DNS1/DNS2 (按input顺序, 切到静态后出现placeholder)
  - 上线时间: 开始时间/结束时间
  - 线路检测: select(当前值含HTTP/PING), 选项HTTP+PING+网关等
  - 检测域名: placeholder=请输入检测的域名
  - 网卡速率/工作模式: select
  - 复选框: 设此条线路为默认网关 / 掉线自动切换 / 开启
  - 按钮: 断开/重拨/保存/取消
- LAN编辑页字段: 名称/IP地址/子网掩码/允许其他LAN访问(开关)/网卡速率/工作模式
"""
from typing import Optional, List, Dict
from playwright.sync_api import Page, Locator

from pages.base_page import BasePage
from pages.ikuai_table_page import IkuaiTablePage


class InterfaceSettingsPage(IkuaiTablePage):
    """内外网设置页面操作类

    继承 IkuaiTablePage 以复用混合模式二级表格的 CRUD/导入导出/启用停用/搜索排序
    (基类行操作基于'文本锚点+JS向上找按钮', 与行是tr还是div.ant-table-row无关).
    保留子类 click_save/click_cancel 覆盖基类(子类版更稳健, 带.first和超时保护).
    """
    # 导入导出存到 test_data/exports/interface_settings/ (混合模式子接入)
    MODULE_NAME = "interface_settings"

    # 6个物理网卡全分配时"新增配置"disabled; 需先解绑网卡
    # 安全: wan1 绝对只读
    READONLY_INTERFACES = {"wan1"}

    # wan_config.internet 接入方式枚举(/usr/ikuai/include/interface.sh):
    # 0=静态 1=DHCP 2=PPPoE 3=MACVLAN(基于物理网卡的混合) 4=VLAN(基于VLAN的混合)
    INTERNET_MODE = {"static": "0", "dhcp": "1", "pppoe": "2",
                     "hybrid_phy": "3", "hybrid_vlan": "4"}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)
        self.PAGE_URL = "/#/networkConfiguration/internalAndExternalNetworkSettings"
        self.EDIT_URL_SUFFIX = "/editLanWan"

    # ==================== 导航 ====================
    def navigate_to_interface_settings(self):
        """导航到内外网设置页面(第1个tab: 内外网设置)"""
        self.page.goto(f"{self.base_url}{self.PAGE_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2500)
        return self

    def back_to_list(self):
        """从编辑页返回列表页"""
        self.page.goto(f"{self.base_url}{self.PAGE_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2000)
        return self

    # ==================== 列表读取 ====================
    def _get_row(self, interface_name: str) -> Optional[Locator]:
        """获取指定接口的行(div.ant-table-row). 精确匹配开头避免wan1匹配到wan10之类."""
        try:
            # 用JS精确匹配行文本开头
            rows = self.page.locator("div.ant-table-row")
            cnt = rows.count()
            for i in range(cnt):
                txt = rows.nth(i).inner_text(timeout=2000)
                # 行文本以接口名+空格开头(如 "wan2 wan2 ..."), 排除子串误匹配
                if txt.strip().startswith(interface_name + " ") or f"\n{interface_name}\n" in txt or txt.strip() == interface_name:
                    return rows.nth(i)
            # 降级: contains
            row = rows.filter(has_text=interface_name).first
            if row.count() > 0:
                return row
        except Exception as e:
            print(f"[DEBUG] _get_row({interface_name}) error: {e}")
        return None

    def get_interface_list(self) -> List[Dict[str, str]]:
        """获取所有接口信息(从表格行解析)"""
        result = []
        try:
            rows = self.page.locator("div.ant-table-row")
            cnt = rows.count()
            for i in range(cnt):
                try:
                    txt = rows.nth(i).inner_text(timeout=2000)
                    parts = [p.strip() for p in txt.split() if p.strip()]
                    if len(parts) >= 4:
                        # 格式: 线路名称 网口 物理网卡 接入方式 IP ...
                        result.append({
                            "name": parts[0],
                            "iface": parts[1] if len(parts) > 1 else "",
                            "raw": txt.replace("\n", " "),
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"[DEBUG] get_interface_list error: {e}")
        return result

    def interface_exists(self, interface_name: str) -> bool:
        """接口是否在列表中显示"""
        return self._get_row(interface_name) is not None

    # ==================== 安全检查 ====================
    def _check_editable(self, interface_name: str):
        """检查接口是否可编辑(wan1只读)"""
        if interface_name in self.READONLY_INTERFACES:
            raise ValueError(f"[安全] {interface_name} 为只读接口(测试机访问地址), 禁止编辑")

    # ==================== 进入编辑页 ====================
    def open_edit_page(self, interface_name: str) -> bool:
        """点击接口行的"配置"按钮, 进入编辑页(路由跳转)"""
        self._check_editable(interface_name)
        row = self._get_row(interface_name)
        if row is None:
            print(f"[DEBUG] open_edit_page: 未找到接口 {interface_name}")
            return False
        try:
            cfg = row.get_by_text("配置", exact=True).first
            if cfg.count() == 0:
                print(f"[DEBUG] {interface_name} 行无'配置'按钮")
                return False
            cfg.click()
            self.page.wait_for_timeout(3500)
            # 确认进入了编辑页(URL含editLanWan 或 有保存按钮)
            if "editLanWan" in self.page.url or self.page.get_by_role("button", name="保存").count() > 0:
                return True
            self.page.wait_for_timeout(2000)
            return "editLanWan" in self.page.url
        except Exception as e:
            print(f"[DEBUG] open_edit_page({interface_name}) error: {e}")
            return False

    # ==================== 编辑页通用操作 ====================
    def click_save(self) -> bool:
        """点击保存按钮"""
        try:
            btn = self.page.get_by_role("button", name="保存")
            if btn.count() == 0:
                return False
            btn.first.click()
            self.page.wait_for_timeout(1500)
            return True
        except Exception as e:
            print(f"[DEBUG] click_save error: {e}")
            return False

    def click_cancel(self) -> bool:
        """点击取消按钮(返回列表)"""
        try:
            btn = self.page.get_by_role("button", name="取消")
            if btn.count() > 0:
                btn.first.click()
                self.page.wait_for_timeout(1000)
            return True
        except Exception:
            return False

    def has_form_error(self) -> Optional[str]:
        """检查编辑页是否有表单校验错误(异常输入拦截)"""
        try:
            # 1. ant-form 红色校验提示
            err = self.page.locator(".ant-form-item-explain-error")
            if err.count() > 0:
                txt = err.first.text_content()
                if txt and txt.strip():
                    return txt.strip()
            # 2. input 红框
            if self.page.locator(".ant-input-status-error, .ant-form-item-has-error").count() > 0:
                return "输入格式错误"
            # 3. 错误 toast
            toast = self.page.locator(".ant-message-error, .ant-notification-error")
            if toast.count() > 0:
                return (toast.first.text_content() or "操作失败").strip()
        except Exception:
            pass
        return None

    def is_still_on_edit_page(self) -> bool:
        """是否还在编辑页(保存被阻止时停留)"""
        return "editLanWan" in self.page.url or self.page.get_by_role("button", name="保存").count() > 0

    # ==================== WAN 编辑页字段操作 ====================
    def fill_tagname(self, name: str):
        """填写名称(placeholder=请输入名称)"""
        inp = self.page.get_by_placeholder("请输入名称")
        if inp.count() > 0:
            inp.first.fill("")
            inp.first.fill(name)
        return self

    def get_current_access_mode(self) -> str:
        """获取当前接入方式(select显示值)"""
        try:
            # 含DHCP/静态/PPPoE的select
            sels = self.page.locator(".ant-select")
            for i in range(sels.count()):
                item = sels.nth(i).locator(".ant-select-selection-item")
                if item.count() > 0:
                    val = item.first.text_content() or ""
                    if any(k in val for k in ["DHCP", "静态", "PPPoE", "ADSL", "混合"]):
                        return val.strip()
        except Exception:
            pass
        return ""

    def set_access_mode(self, mode: str) -> bool:
        """设置接入方式. mode: 'static'/'dhcp'/'pppoe' (内部映射中文选项)
        用Playwright真实点击选项(虚拟列表JS click文字是虚拟值0/1/2)"""
        mode_map = {
            "static": "静态",      # 静态IP（固定IP） internet=0
            "dhcp": "DHCP",        # DHCP（动态获取） internet=1
            "pppoe": "PPPoE",      # ADSL/PPPoE拨号 internet=2
            "hybrid_phy": "基于物理网卡的混合",   # internet=3 MACVLAN
            "hybrid_vlan": "基于VLAN的混合",      # internet=4 VLAN
        }
        keyword = mode_map.get(mode, mode)
        try:
            cur = self.get_current_access_mode()
            if keyword in cur:
                return True  # 已经是该模式
            # 找接入方式select并打开
            sel = None
            sels = self.page.locator(".ant-select")
            for i in range(sels.count()):
                item = sels.nth(i).locator(".ant-select-selection-item")
                if item.count() > 0:
                    val = item.first.text_content() or ""
                    if any(k in val for k in ["DHCP", "静态", "PPPoE", "ADSL", "混合"]):
                        sel = sels.nth(i)
                        break
            if sel is None:
                return False
            sel.locator(".ant-select-selector").click()
            self.page.wait_for_timeout(1000)
            # 虚拟列表有两套option: 数字标签(text=0/1/2, ariaLabel含中文) + 真实选项(text=中文, 有.ant-select-item-option-content)
            # 必须点真实选项(用title属性精确匹配, 避开数字标签)
            from playwright.sync_api import Locator as _L
            # 优先用 title 属性匹配(最精确)
            opt = self.page.locator(".ant-select-dropdown:visible").last.locator(
                f".ant-select-item[title*='{keyword}'], .ant-select-item-option-content"
            ).filter(has_text=keyword)
            clicked = False
            if opt.count() > 0:
                # 点含keyword的option-content(真实选项), 避开数字标签
                real_opt = self.page.locator(".ant-select-dropdown:visible").last.locator(
                    ".ant-select-item-option-content"
                ).filter(has_text=keyword)
                if real_opt.count() > 0:
                    real_opt.first.click()
                else:
                    opt.first.click()
                clicked = True
            else:
                # 降级: JS遍历找有title含keyword的option
                clicked = self.page.evaluate("""(kw) => {
                    let dds = [...document.querySelectorAll('.ant-select-dropdown')];
                    for (let dd of dds) {
                        let opts = dd.querySelectorAll('.ant-select-item');
                        for (let o of opts) {
                            let title = o.getAttribute('title') || '';
                            let content = o.querySelector('.ant-select-item-option-content');
                            let txt = content ? content.innerText : '';
                            if (title.includes(kw) || txt.includes(kw)) {
                                if (!content || content.innerText !== content.innerText.match(/^[0-9]+$/)) {
                                    o.click(); return true;
                                }
                            }
                        }
                    }
                    return false;
                }""", keyword)
            self.page.wait_for_timeout(1500)
            # 回读校验: 点选后 select 显示值必须确实变成目标模式, 否则视为切换失败(防假成功)
            if clicked:
                cur = self.get_current_access_mode()
                if keyword in cur:
                    return True
                print(f"[DEBUG] set_access_mode({mode}) 点选后回读不一致: 期望含'{keyword}' 实际'{cur}'")
            return False
        except Exception as e:
            print(f"[DEBUG] set_access_mode({mode}) error: {e}")
            return False

    def fill_static_ip(self, ip: str, netmask: str = "255.255.255.0",
                       gateway: str = "", dns1: str = "", dns2: str = ""):
        """填写静态IP字段(切到静态模式后). IP/网关用placeholder定位.
        实测(2026-07-01): 静态模式 IP placeholder='请输入IP地址', 网关='请输入网关',
        掩码是select(默认255.255.255.0(24)), DNS静态模式无独立字段."""
        try:
            ip_inp = self.page.get_by_placeholder("请输入IP地址")
            try:
                ip_inp.first.wait_for(timeout=3000)
                ip_inp.first.fill(ip)
            except Exception:
                print("[DEBUG] fill_static_ip: IP字段(请输入IP地址)未就绪")
            if gateway:
                gw_inp = self.page.get_by_placeholder("请输入网关")
                try:
                    gw_inp.first.wait_for(timeout=2000)
                    gw_inp.first.fill(gateway)
                except Exception:
                    pass
            # 掩码select默认255.255.255.0; 如非默认用_select_labeled("子网掩码", ...); DNS静态模式无独立字段
            self.page.wait_for_timeout(300)
        except Exception as e:
            print(f"[DEBUG] fill_static_ip error: {e}")
        return self

    def _looks_like_ip(self, s: str) -> bool:
        """判断是否像IP地址"""
        if not s:
            return False
        parts = s.split(".")
        return len(parts) == 4 and all(p.isdigit() for p in parts if p)

    def set_check_link_mode(self, mode_keyword: str) -> bool:
        """设置线路检测模式. mode_keyword: 'HTTP'/'PING'/'关闭'/'网关'等关键词
        用Playwright真实点击选项(虚拟列表)"""
        try:
            sels = self.page.locator(".ant-select")
            for i in range(sels.count()):
                item = sels.nth(i).locator(".ant-select-selection-item")
                if item.count() > 0:
                    val = item.first.text_content() or ""
                    if any(k in val for k in ["HTTP", "PING", "网关", "关闭", "检测"]):
                        if mode_keyword in val:
                            return True
                        sels.nth(i).locator(".ant-select-selector").click()
                        self.page.wait_for_timeout(1000)
                        # 用option-content精确匹配(避开数字标签)
                        real_opt = self.page.locator(".ant-select-dropdown:visible").last.locator(
                            ".ant-select-item-option-content"
                        ).filter(has_text=mode_keyword)
                        if real_opt.count() > 0:
                            real_opt.first.click()
                            self.page.wait_for_timeout(1000)
                            return True
                        # JS降级: 用title匹配
                        clicked = self.page.evaluate("""(kw) => {
                            let dds=[...document.querySelectorAll('.ant-select-dropdown')];
                            for(let dd of dds){
                                let opts=dd.querySelectorAll('.ant-select-item');
                                for(let o of opts){
                                    let title=o.getAttribute('title')||'';
                                    if(title.includes(kw)){o.click();return true;}
                                }}
                            return false;
                        }""", mode_keyword)
                        self.page.wait_for_timeout(800)
                        return bool(clicked)
        except Exception as e:
            print(f"[DEBUG] set_check_link_mode error: {e}")
        return False

    def fill_check_host(self, host: str):
        """填写检测域名(placeholder=请输入检测的域名)"""
        inp = self.page.get_by_placeholder("请输入检测的域名")
        if inp.count() > 0:
            inp.first.fill("")
            inp.first.fill(host)
        return self

    def get_check_host_value(self) -> str:
        """读取检测域名当前值"""
        inp = self.page.get_by_placeholder("请输入检测的域名")
        if inp.count() > 0:
            return inp.first.input_value()
        return ""

    def toggle_default_route(self, enable: bool) -> bool:
        """切换'设此条线路为默认网关'复选框到指定状态"""
        return self._toggle_checkbox("设此条线路为默认网关", enable)

    def toggle_disc_auto_switch(self, enable: bool) -> bool:
        """切换'掉线自动切换'复选框"""
        return self._toggle_checkbox("掉线自动切换", enable)

    def _toggle_checkbox(self, label_text: str, enable: bool) -> bool:
        """切换复选框到指定状态. label可能在.ant-checkbox-wrapper内(掉线切换,wrapper文本=label)
        或外(定时重拨/异常IP检测, wrapper文本='开启', label是兄弟元素). 等待状态稳定(React初始化延迟)再判断点击."""
        try:
            cb = self.page.locator(".ant-checkbox-wrapper", has_text=label_text)
            tmp_mark = False
            if cb.count() > 0:
                wrapper = cb.first
            else:
                # label在wrapper外: 找label文本节点, 向上找只有1个checkbox的祖先, 标记该checkbox
                found = self.page.evaluate("""(kw) => {
                    const els = [...document.querySelectorAll('*')].filter(e => e.children.length === 0 && (e.innerText||'').trim() === kw);
                    for (const el of els) {
                        let p = el.parentElement;
                        for (let d=0; d<6&&p; d++) {
                            const cbs = [...p.querySelectorAll('.ant-checkbox-wrapper')].filter(c => c.offsetParent !== null);
                            if (cbs.length === 1) { cbs[0].setAttribute('data-tmp-cb', '1'); return true; }
                            if (cbs.length > 1) break;
                            p = p.parentElement;
                        }
                    }
                    return false;
                }""", label_text)
                if not found:
                    return False
                wrapper = self.page.locator(".ant-checkbox-wrapper[data-tmp-cb='1']").first
                tmp_mark = True
            # 等待checkbox状态稳定(进编辑页初始false, 同步DB真实值需~4s)
            is_checked = wrapper.locator("input").is_checked()
            for _ in range(10):
                self.page.wait_for_timeout(500)
                new_checked = wrapper.locator("input").is_checked()
                if new_checked == is_checked:
                    break
                is_checked = new_checked
            if is_checked != enable:
                wrapper.click()
                self.page.wait_for_timeout(300)
            if tmp_mark:
                self.page.evaluate("document.querySelector(\".ant-checkbox-wrapper[data-tmp-cb='1']\")?.removeAttribute('data-tmp-cb')")
            return True
        except Exception as e:
            print(f"[DEBUG] _toggle_checkbox({label_text}) error: {e}")
            return False

    # ==================== label定位公共底座 (PPPoE/DHCP/高级等单input字段) ====================
    def _fill_labeled_input(self, label_keyword: str, value: str) -> bool:
        """按label关键词定位表单单input字段并填值(PPPoE账号/密码/MTU/服务器名/AC名/DHCP option等).
        定位策略(JS): 遍历可见input, 向上找innerText含keyword且只有1个可见input的最近祖先→精确命中单字段.
        用React原生setter触发onChange(避开'表单不触发onChange'踩坑)."""
        try:
            ok = self.page.evaluate("""({kw, val}) => {
                const sel = "input[type='text'], input[type='password'], input:not([type]), textarea";
                const inputs = [...document.querySelectorAll(sel)].filter(i => i.offsetParent !== null && !i.closest('.ant-select'));
                for (const inp of inputs) {
                    let p = inp.parentElement;
                    for (let depth = 0; depth < 6 && p; depth++) {
                        const t = p.innerText || '';
                        if (t.includes(kw)) {
                            const inps = [...p.querySelectorAll(sel)].filter(x => x.offsetParent !== null && !x.closest('.ant-select'));
                            if (inps.length === 1 && inps[0] === inp) {
                                const proto = inp.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
                                const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
                                setter.call(inp, val);
                                inp.dispatchEvent(new Event('input', {bubbles: true}));
                                inp.dispatchEvent(new Event('change', {bubbles: true}));
                                return true;
                            }
                            break;  // 含kw但多input(如静态IP区), 非目标, 停止上溯
                        }
                        p = p.parentElement;
                    }
                }
                return false;
            }""", {"kw": label_keyword, "val": value})
            if ok:
                self.page.wait_for_timeout(300)
            else:
                print(f"[DEBUG] _fill_labeled_input 未定位到字段: {label_keyword}")
            return bool(ok)
        except Exception as e:
            print(f"[DEBUG] _fill_labeled_input({label_keyword}) error: {e}")
            return False

    def _fill_labeled_input_pw(self, label_keyword: str, value: str) -> bool:
        """按label关键词定位单input字段, 用Playwright真实fill(触发完整Ant Form state).
        用于React setter不生效的组合字段(DHCP option的input+select, setter填了input.value但Form未同步).
        JS定位+data-tmp-mark标记+Playwright fill(模拟真实键盘输入)."""
        try:
            found = self.page.evaluate("""(kw) => {
                const sel = "input[type='text'], input[type='password'], input:not([type]), textarea";
                const inputs = [...document.querySelectorAll(sel)].filter(i => i.offsetParent !== null && !i.closest('.ant-select'));
                for (const inp of inputs) {
                    let p = inp.parentElement;
                    for (let depth = 0; depth < 6 && p; depth++) {
                        if ((p.innerText||'').includes(kw)) {
                            const inps = [...p.querySelectorAll(sel)].filter(x => x.offsetParent !== null && !x.closest('.ant-select'));
                            if (inps.length === 1 && inps[0] === inp) {
                                inp.setAttribute('data-tmp-mark', '1');
                                inp.scrollIntoView({block:'center'});
                                return true;
                            }
                            break;
                        }
                        p = p.parentElement;
                    }
                }
                return false;
            }""", label_keyword)
            if not found:
                print(f"[DEBUG] _fill_labeled_input_pw 未定位: {label_keyword}")
                return False
            loc = self.page.locator("[data-tmp-mark='1']")
            # textarea用type逐字符(触发React onChange; MCP验证fill对textarea只改val不更新Form state→save丢值, type逐字符才持久化); input用fill
            try:
                tag = str(loc.evaluate("el => el.tagName")).upper()
            except Exception:
                tag = "INPUT"
            if tag == "TEXTAREA":
                loc.fill("")
                loc.type(value, delay=20)
            else:
                loc.fill(value)
            # Ant Form某些字段(DHCP option/备注)要blur才更新state持久化; evaluate dispatch最可靠
            self.page.evaluate("""() => {
                const el = document.querySelector("[data-tmp-mark='1']");
                if (el) { el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('blur', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); }
            }""")
            self.page.evaluate("document.querySelector(\"[data-tmp-mark='1']\")?.removeAttribute('data-tmp-mark')")
            self.page.wait_for_timeout(300)
            return True
        except Exception as e:
            print(f"[DEBUG] _fill_labeled_input_pw({label_keyword}) error: {e}")
            return False

    def _read_labeled_input(self, label_keyword: str) -> str:
        """读label关键词对应的单input字段当前值(与_fill_labeled_input同定位, 用于恢复/校验)"""
        try:
            val = self.page.evaluate("""(kw) => {
                const sel = "input[type='text'], input[type='password'], input:not([type]), textarea";
                const inputs = [...document.querySelectorAll(sel)].filter(i => i.offsetParent !== null && !i.closest('.ant-select'));
                for (const inp of inputs) {
                    let p = inp.parentElement;
                    for (let depth = 0; depth < 6 && p; depth++) {
                        const t = p.innerText || '';
                        if (t.includes(kw)) {
                            const inps = [...p.querySelectorAll(sel)].filter(x => x.offsetParent !== null && !x.closest('.ant-select'));
                            if (inps.length === 1 && inps[0] === inp) return inp.value || '';
                            break;
                        }
                        p = p.parentElement;
                    }
                }
                return '';
            }""", label_keyword)
            return val or ""
        except Exception:
            return ""

    def expand_advanced(self) -> bool:
        """确保'高级设置'折叠面板展开 且 工作模式select可被_select_labeled定位.
        iKuai默认展开但select异步渲染(label文本先出, select后出), 轮询等待select真正可定位;
        2.5s仍不可定位则点.ant-collapse-header展开."""
        ready_js = """(kw) => {
            const sels = [...document.querySelectorAll('.ant-select')].filter(s => s.offsetParent !== null);
            for (const sel of sels) {
                let p = sel.parentElement;
                for (let d = 0; d < 6 && p; d++) {
                    if ((p.innerText||'').includes(kw)) {
                        const sub = [...p.querySelectorAll('.ant-select')].filter(x => x.offsetParent !== null);
                        if (sub.length === 1 && sub[0] === sel) return true;
                        break;
                    }
                    p = p.parentElement;
                }
            }
            return false;
        }"""
        try:
            for i in range(15):  # 等7.5秒
                if self.page.evaluate(ready_js, "工作模式"):
                    return True
                if i == 5:  # 2.5秒后仍不可定位→尝试点collapse header展开
                    header = self.page.locator(".ant-collapse-header").filter(has_text="高级设置").first
                    if header.count() > 0:
                        try:
                            header.click()
                            self.page.wait_for_timeout(1000)
                        except Exception:
                            pass
                self.page.wait_for_timeout(500)
            return self.page.evaluate(ready_js, "工作模式")
        except Exception as e:
            print(f"[DEBUG] expand_advanced error: {e}")
            return False

    def _select_labeled(self, label_keyword: str, option_keyword: str) -> bool:
        """按label关键词找关联的.ant-select并选指定option(工作模式/网卡速率/DHCP option类型).
        定位(JS): 找含keyword且只有1个可见select的祖先→打开下拉→精确选option(textContent===option)."""
        try:
            opened = self.page.evaluate("""(kw) => {
                const sels = [...document.querySelectorAll('.ant-select')].filter(s => s.offsetParent !== null);
                for (const sel of sels) {
                    let p = sel.parentElement;
                    for (let d = 0; d < 6 && p; d++) {
                        const t = p.innerText || '';
                        if (t.includes(kw)) {
                            const sub = [...p.querySelectorAll('.ant-select')].filter(x => x.offsetParent !== null);
                            if (sub.length === 1 && sub[0] === sel) {
                                const s = sel.querySelector('.ant-select-selector');
                                s.dispatchEvent(new MouseEvent('mousedown', {bubbles: true}));
                                s.click();
                                return true;
                            }
                            break;
                        }
                        p = p.parentElement;
                    }
                }
                return false;
            }""", label_keyword)
            if not opened:
                print(f"[DEBUG] _select_labeled 未定位select: {label_keyword}")
                return False
            self.page.wait_for_timeout(700)
            # 精确匹配option(textContent === kw, 避开10M/100M/1000M子串误匹配)
            clicked = self.page.evaluate("""(kw) => {
                const dds = [...document.querySelectorAll('.ant-select-dropdown')].filter(d => d.offsetParent !== null);
                const dd = dds[dds.length - 1];
                if (!dd) return false;
                const opts = [...dd.querySelectorAll('.ant-select-item-option')];
                for (const exact of [true, false]) {
                    for (const o of opts) {
                        const c = o.querySelector('.ant-select-item-option-content');
                        const txt = c ? c.innerText.trim() : '';
                        const title = o.getAttribute('title') || '';
                        if ((exact && (txt === kw || title === kw)) ||
                            (!exact && (txt.includes(kw) || title.includes(kw)))) {
                            o.click();
                            return true;
                        }
                    }
                }
                return false;
            }""", option_keyword)
            if clicked:
                self.page.wait_for_timeout(500)
            else:
                print(f"[DEBUG] _select_labeled 未找到option: {label_keyword}={option_keyword}")
            return bool(clicked)
        except Exception as e:
            print(f"[DEBUG] _select_labeled({label_keyword}) error: {e}")
            return False

    # ==================== PPPoE 字段(切到PPPoE接入方式后) ====================
    def fill_pppoe_account(self, account: str) -> bool:
        """填PPPoE账号(label='账号')"""
        return self._fill_labeled_input("账号", account)

    def fill_pppoe_password(self, password: str) -> bool:
        """填PPPoE密码(label='密码', type=password)"""
        return self._fill_labeled_input("密码", password)

    def fill_pppoe_mtu(self, mtu: str = "1492") -> bool:
        """填MTU(默认1492, label='MTU')"""
        return self._fill_labeled_input("MTU", mtu)

    def fill_pppoe_server_name(self, server_name: str) -> bool:
        """填服务器名称(label='服务器名称', 选填)"""
        return self._fill_labeled_input("服务器名称", server_name)

    def fill_pppoe_ac_name(self, ac_name: str) -> bool:
        """填AC名称(label='AC名称', 选填)"""
        return self._fill_labeled_input("AC名称", ac_name)

    def toggle_timing_redial(self, enable: bool) -> bool:
        """切'定时重拨'checkbox"""
        return self._toggle_checkbox("定时重拨", enable)

    def fill_redial_interval(self, minutes: str) -> bool:
        """填间隔时长重拨(分钟, label='间隔时长')"""
        return self._fill_labeled_input("间隔时长", minutes)

    def toggle_abnormal_ip_detect(self, enable: bool) -> bool:
        """切'异常IP检测'checkbox(PPPoE模式)"""
        return self._toggle_checkbox("异常IP", enable)

    # ==================== DHCP 选项(切到DHCP接入方式后) ====================
    def fill_dhcp_option_12(self, hostname: str) -> bool:
        """填option12(Hostname). 用Playwright fill(React setter对option的input+select组合不生效)"""
        return self._fill_labeled_input_pw("option12", hostname)

    def fill_dhcp_option_60(self, vendor_class: str) -> bool:
        """填option60(Vendor class ID)"""
        return self._fill_labeled_input_pw("option60", vendor_class)

    def fill_dhcp_option_61(self, client_id: str) -> bool:
        """填option61(Client ID)"""
        return self._fill_labeled_input_pw("option61", client_id)

    def set_lease_time(self, seconds: str) -> bool:
        """填租期时间(秒, label='租期')"""
        return self._fill_labeled_input("租期", seconds)

    # ==================== 高级设置(展开折叠面板后, 所有接入方式通用) ====================
    def set_work_mode(self, mode: str) -> bool:
        """设工作模式. mode: 'auto'自动协商/'full'全双工/'half'半双工"""
        mp = {"auto": "自动协商", "full": "全双工", "half": "半双工"}
        self.expand_advanced()
        return self._select_labeled("工作模式", mp.get(mode, mode))

    def set_nic_speed(self, speed: str) -> bool:
        """设网卡速率. speed: 'auto'自动协商/'10'/'100'/'1000'/'2500'..."""
        kw = "自动协商" if speed == "auto" else f"{speed}M"
        self.expand_advanced()
        return self._select_labeled("网卡速率", kw)

    def fill_clone_mac(self, mac: str) -> bool:
        """填克隆MAC(label='克隆MAC', 高级设置内)"""
        self.expand_advanced()
        return self._fill_labeled_input("克隆MAC", mac)

    def toggle_link_aggregation(self, enable: bool) -> bool:
        """切'链路聚合'checkbox(高级设置内)"""
        self.expand_advanced()
        return self._toggle_checkbox("链路聚合", enable)

    # ==================== 通用字段 ====================
    def fill_remark(self, remark: str) -> bool:
        """填备注(label='备注', 覆盖基类). 用_pw(Playwright fill+blur)触发Form state持久化(同DHCP option)."""
        return self._fill_labeled_input_pw("备注", remark)

    def fill_online_time_period(self, start: str = "00:00", end: str = "23:59") -> bool:
        """读/填上线时间段控制. iKuai为双input时间字段, 默认值不变即跳过(时间控件复杂, 测试仅读)."""
        # 时间字段填值易触发picker面板, 默认不主动改; 返回当前是否能读到
        return bool(self._read_labeled_input("上线时间") or self._read_labeled_input("开始时间"))

    # ==================== 混合模式二级表格(internet=3 MACVLAN物理混合/4 VLAN混合) ====================
    # 切到混合模式后, 编辑页变为二级表格: 导入/导出 + 3子tab(静态IP/DHCP动态IP/ADSL-PPPoE拨号)
    #   + 添加/启用/停用/删除 + 子表格(名称/IP/掩码/网关/MAC/备注/状态/操作).
    # 子接入存 wan_vlan表(interface=父WAN, vlan_id, vlan_name=子接入名, vlan_internet=0静/1DHCP/2PPPoE).
    # 添加=drawer抽屉表单(placeholder字段: 请输入名称/请输入IP地址/请输入MAC地址/请输入网关/请输入VLAN_ID[VLAN混合]),
    #   drawer保存→直接写wan_vlan库(实测非暂存). MAC接口内唯一校验,重复→"已存在相同内容"→drawer不关不写库.
    # 物理混合(internet=3)二级表格列无VLAN_ID(MACVLAN); VLAN混合(internet=4)列含VLAN_ID且drawer必填.
    HYBRID_SUBTAB = {"static": "静态IP", "dhcp": "DHCP", "pppoe": "PPPoE"}

    def switch_hybrid_subtab(self, subtab: str) -> bool:
        """切混合模式子tab. subtab: 'static'/'dhcp'/'pppoe'"""
        kw = self.HYBRID_SUBTAB.get(subtab, subtab)
        try:
            tab = self.page.locator(".ant-tabs-tab", has_text=kw).first
            if tab.count() == 0:
                tab = self.page.get_by_role("tab", name=kw).first
            if tab.count() == 0:
                return False
            cls = tab.get_attribute("class") or ""
            if "active" in cls:
                return True
            tab.click()
            self.page.wait_for_timeout(800)
            return True
        except Exception as e:
            print(f"[DEBUG] switch_hybrid_subtab({subtab}) error: {e}")
            return False

    def _get_hybrid_drawer(self):
        """获取混合模式添加抽屉内容容器(最后一个可见drawer)"""
        return self.page.locator(".ant-drawer-content").last

    def hybrid_open_add_drawer(self) -> bool:
        """点混合模式工具栏'添加'→打开drawer. 必须用evaluate精确选main内可见非disabled的添加按钮
        (Playwright filter().first()会选到隐藏按钮导致drawer不开)."""
        try:
            # 温和清理残留modal/确认弹窗(不强制隐藏drawer—会破坏React state导致后续drawer不开)
            try:
                self.close_modal_if_exists()
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(400)
            except Exception:
                pass
            opened = self.page.evaluate("""() => {
                const btns = [...document.querySelectorAll('main button')]
                    .filter(b => b.innerText.trim() === '添加' && !b.disabled && b.offsetParent !== null);
                if (btns.length) { btns[0].click(); return true; }
                return false;
            }""")
            if not opened:
                return False
            self.page.wait_for_timeout(1500)
            return self._get_hybrid_drawer().locator("input[placeholder='请输入名称']").count() > 0
        except Exception as e:
            print(f"[DEBUG] hybrid_open_add_drawer error: {e}")
            return False

    def hybrid_fill_drawer(self, name: str, ip: str = "", mac: str = "",
                           gateway: str = "", account: str = "", password: str = "",
                           vlan_id: str = "", mtu: str = "") -> bool:
        """在混合模式drawer内填字段(按placeholder, Playwright真实fill触发React form state).
        静态子tab: name/ip/mac/gateway; PPPoE子tab: name/account/password + MTU(必填空placeholder按label定位);
        vlan_id仅VLAN混合(internet=4)drawer有'请输入VLAN_ID'字段时填(物理混合无此字段f()跳过)."""
        try:
            dc = self._get_hybrid_drawer()
            def f(ph, val):
                if not val:
                    return False
                loc = dc.locator(f"input[placeholder='{ph}']")
                if loc.count() > 0:
                    # 用type逐字符(可靠触发React onChange; Ant input的fill对部分子tab字段不触发,
                    # 导致drawer保存时React Form认为字段空→"输入有误", 见[hybrid-fill-not-trigger-onchange])
                    loc.first.fill("")
                    loc.first.type(val, delay=40)
                    return True
                return False
            ok_name = f("请输入名称", name)
            f("请输入VLAN_ID", vlan_id)  # VLAN混合必填(物理混合drawer无此input→f()返回False跳过)
            f("请输入IP地址", ip)
            f("请输入MAC地址", mac)
            f("请输入网关", gateway)
            if account:
                loc = dc.locator("input[placeholder='请输入账号']")
                acnt = loc.count()
                if acnt > 0:
                    loc.first.fill("")
                    loc.first.type(account, delay=40)
                print(f"[DEBUG-fill_drawer] account count={acnt}")
            if password:
                pw = dc.locator("input[type='password']").first
                pcnt = pw.count()
                if pcnt > 0:
                    pw.fill("")
                    pw.type(password, delay=40)
                print(f"[DEBUG-fill_drawer] password count={pcnt}")
            # MTU(pppoe必填, 空placeholder): 按"label含MTU"的form-item内input定位
            if mtu:
                try:
                    mtu_input = dc.locator(".ant-form-item:has-text('MTU') input[type='text']").first
                    if mtu_input.count() > 0:
                        mtu_input.fill("")
                        mtu_input.type(str(mtu), delay=40)
                except Exception as e:
                    print(f"[DEBUG] fill MTU error: {e}")
            self.page.wait_for_timeout(500)
            return ok_name
        except Exception as e:
            print(f"[DEBUG] hybrid_fill_drawer error: {e}")
            return False

    def _detect_drawer_error(self) -> Optional[str]:
        """检测drawer内非标准错误提示(MAC'已存在相同内容'/名称格式/不能为空等).
        has_form_error只认.ant-form-item-explain-error标准错误, 实测MAC'已存在相同内容'用的是
        .ant-form-item-explain(无-error后缀)或自定义span→被漏检→hybrid_add_row误判success.
        本方法兜底扫描drawer内所有explain容器+含校验关键词的叶子文本."""
        try:
            txt = self.page.evaluate("""() => {
                const dcs = [...document.querySelectorAll('.ant-drawer')]
                    .filter(d => getComputedStyle(d).display !== 'none');
                if (!dcs.length) return '';
                const dc = dcs[dcs.length - 1];
                // 1. 所有explain容器(含-error和无-error后缀的)
                const explains = [...dc.querySelectorAll('[class*="explain"], .ant-form-item-explain-error')];
                for (const e of explains) { const t = (e.innerText || '').trim(); if (t) return t; }
                // 2. 兜底: 含校验关键词的叶子文本(限长防误匹配)
                const leaves = [...dc.querySelectorAll('*')].filter(e => !e.children.length && e.innerText);
                for (const e of leaves) {
                    const t = (e.innerText || '').trim();
                    if (t && t.length < 40 && /已存在|格式错误|格式不正确|输入有误|不能为空|必须|至少|重复/.test(t)) return t;
                }
                return '';
            }""")
            return txt if txt else None
        except Exception:
            return None

    def hybrid_save_drawer(self) -> dict:
        """点drawer内'保存'. 返回 {saved, error}.
        轮询drawer关闭(最多4s, 每0.5s查一次): 保存成功则drawer关闭(关闭动画2-3s); 超时未关则
        检测错误(MAC已存在等). 根因: 固定wait 2s时drawer关闭动画可能未完成→误判saved=False→
        hybrid_add_row提前cancel_drawer漏判in_table(行其实已出现). 轮询给足关闭时间, 仅真正未关才报error."""
        result = {"saved": False, "error": ""}
        try:
            dc = self._get_hybrid_drawer()
            save_btn = dc.locator("button:has-text('保存')").first
            if save_btn.count() == 0:
                result["error"] = "drawer无保存按钮"
                return result
            save_btn.click()
            # 轮询drawer关闭(最多10s: headless下Antd drawer关闭动画慢, 实测保存API已写库成功
            # 但display转none最久需8-10s; MCP headed模式2.5s即关)
            for _ in range(20):
                self.page.wait_for_timeout(500)
                # 过滤空drawer容器(innerText<5字符): Antd drawer关闭后真实drawer内容空/卸载,
                # 但页面常驻空的.ant-drawer根容器(display:block)会误判为"未关". 仅内容>5的有形drawer才算开
                drawer_open = self.page.evaluate("""() => {
                    return [...document.querySelectorAll('.ant-drawer')]
                        .filter(d => getComputedStyle(d).display !== 'none' && (d.innerText || '').replace(/\\s/g, '').length > 5).length > 0;
                }""")
                if not drawer_open:
                    result["saved"] = True
                    break
            if not result["saved"]:
                # drawer未关(headless动画未完成或真校验失败). 检测明确错误 + 强制Escape关drawer
                # (避免残留drawer连锁导致后续hybrid_open_add_drawer失败)
                err = self.has_form_error() or self._detect_drawer_error()
                try:
                    self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(800)
                except Exception:
                    pass
                result["error"] = err or "保存后drawer未关闭(已强制Escape)"
            return result
        except Exception as e:
            result["error"] = str(e)[:80]
            return result

    def hybrid_cancel_drawer(self):
        """取消/关闭drawer(异常或放弃时)"""
        try:
            dc = self._get_hybrid_drawer()
            cancel = dc.locator("button:has-text('取消')")
            if cancel.count() > 0:
                cancel.first.click()
                self.page.wait_for_timeout(500)
            else:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(400)
        except Exception:
            pass

    def hybrid_add_row(self, name: str, ip: str = "", mac: str = "", gateway: str = "",
                       subtab: str = "static", account: str = "", password: str = "",
                       vlan_id: str = "", mtu: str = "") -> dict:
        """混合模式添加子接入(完整流程): 切子tab→开drawer→填→保存.
        返回 {success, error, in_table}. in_table=drawer保存后子接入行出现在表格(direct写wan_vlan库).
        vlan_id: VLAN混合(internet=4)drawer必填; 物理混合(internet=3)无此字段忽略.
        ⚠️ MAC接口内唯一, 重复→'已存在相同内容'→success=False且error有值."""
        result = {"success": False, "error": "", "in_table": False}
        try:
            self.switch_hybrid_subtab(subtab)
            self.page.wait_for_timeout(500)
            try:
                activeTab = self.page.evaluate("() => (document.querySelector('main .ant-tabs-tab-active')||{}).innerText || ''")
                print(f"[DEBUG-add_row] {subtab}/{name}: activeTab={activeTab!r}")
            except Exception:
                pass
            if not self.hybrid_open_add_drawer():
                result["error"] = "打开drawer失败"
                print(f"[DEBUG-add_row] {subtab}/{name}: 打开drawer失败")
                return result
            self.hybrid_fill_drawer(name, ip=ip, mac=mac, gateway=gateway,
                                    account=account, password=password, vlan_id=vlan_id, mtu=mtu)
            sv = self.hybrid_save_drawer()
            print(f"[DEBUG-add_row] {subtab}/{name}: sv.saved={sv.get('saved')} sv.error={sv.get('error')!r}")
            # 仅明确校验错误(MAC已存在/格式/有误)才cancel; "drawer未关闭"时继续判行
            # (headless下drawer关闭动画慢, 但保存API已成功写库, 列表会刷新出行)
            sv_err = sv.get("error") or ""
            if sv_err and "未关闭" not in sv_err and "Escape" not in sv_err:
                result["error"] = sv_err
                self.hybrid_cancel_drawer()
                return result
            # 轮询前端行出现(写库成功列表会刷新出该行; drawer关慢时多等)
            for _ in range(8):
                self.page.wait_for_timeout(600)
                if self.hybrid_row_exists(name):
                    result["in_table"] = True
                    result["success"] = True
                    break
            print(f"[DEBUG-add_row] {subtab}/{name}: in_table={result['in_table']} success={result['success']}")
            if not result["success"]:
                result["error"] = sv_err or "添加后前端未出现行"
            return result
        except Exception as e:
            result["error"] = str(e)[:80]
            self.hybrid_cancel_drawer()
            return result

    def hybrid_is_table_empty(self) -> bool:
        """混合模式当前子tab表格是否'暂无内容'"""
        try:
            return self.page.locator("main .ant-table-placeholder").last.is_visible()
        except Exception:
            return False

    # 混合模式行操作(evaluate找可见行+scrollIntoView+click行内按钮; 基类_click_rule_button用
    # get_by_text.wait_for在子接入表格易超时—虚拟滚动/隐藏副本, 故override用evaluate按可见tr定位)
    def _hybrid_click_row_button(self, name: str, button_name: str, need_confirm: bool = False) -> bool:
        """evaluate找可见子接入行+scrollIntoView+click行内按钮(不依赖get_by_text可见性)."""
        try:
            res = self.page.evaluate("""([ruleName, btnName]) => {
                // 子接入二级表格是Antd虚拟滚动: 行是div.ant-table-row(非tr), 容器.ant-table-tbody-virtual.
                const rows = [...document.querySelectorAll('main .ant-table-row')];
                const matchRows = rows.filter(r => r.innerText.includes(ruleName));
                const visMatch = matchRows.filter(r => r.offsetParent !== null);
                if (!visMatch.length) return {clicked: false, total: rows.length, match: matchRows.length, texts: rows.slice(0,5).map(r=>(r.innerText||'').replace(/\\s+/g,' ').slice(0,30))};
                const r = visMatch[0];
                r.scrollIntoView({block: 'center'});
                const btns = r.querySelectorAll('button');
                const btnTexts = [...btns].map(b => b.textContent.trim());
                for (const b of btns) {
                    if (b.textContent.includes(btnName) && !b.disabled && b.offsetParent !== null) {
                        b.click(); return {clicked: true};
                    }
                }
                return {clicked: false, total: rows.length, match: visMatch.length, btnTexts};
            }""", [name, button_name])
            clicked = res.get("clicked") if isinstance(res, dict) else bool(res)
            if not clicked:
                print(f"[DEBUG] _hybrid_click_row_button({name},{button_name}): 未找到. res={res}")
                return False
            self.page.wait_for_timeout(500)
            if need_confirm:
                self._click_visible_confirm(timeout=4000)
                self.page.wait_for_timeout(500)
            return True
        except Exception as e:
            print(f"[DEBUG] _hybrid_click_row_button({name},{button_name}) error: {e}")
            return False

    def hybrid_edit_row(self, name: str) -> bool:
        """编辑混合模式子接入行(evaluate版, 规避基类get_by_text在子接入表格超时)"""
        return self._hybrid_click_row_button(name, "编辑")

    def hybrid_delete_row(self, name: str) -> bool:
        """删除混合模式子接入行(evaluate版+确认弹窗)"""
        return self._hybrid_click_row_button(name, "删除", need_confirm=True)

    def hybrid_enable_row(self, name: str) -> bool:
        return self._hybrid_click_row_button(name, "启用")

    def hybrid_disable_row(self, name: str) -> bool:
        return self._hybrid_click_row_button(name, "停用", need_confirm=True)

    def hybrid_row_exists(self, name: str) -> bool:
        return self.rule_exists(name)

    def hybrid_get_count(self) -> int:
        try:
            return self.get_rule_count()
        except Exception:
            return 0

    def hybrid_clean_subif(self, name_prefix: str = "vwan") -> int:
        """前端逐条删除当前子tab表格中prefix开头的子接入行(兜底清理, 不依赖batch_delete).
        根因: 子接入二级表格的select_all/batch_delete不稳定(select_all不生效+footer批量按钮找不到),
        helper清理失败→前端残留→下一子tab添加时MAC'已存在'冲突. 本方法用delete_rule逐条删, 稳定."""
        cnt = 0
        for _ in range(30):  # 最多删30条防死循环
            try:
                names = self.page.evaluate("""(prefix) => {
                    // 子接入虚拟滚动: 行是div.ant-table-row(非tr), 用innerText找prefix开头的名称词
                    const rows = [...document.querySelectorAll('main .ant-table-row')];
                    const found = [];
                    for (const r of rows) {
                      const t = (r.innerText || '').trim();
                      const words = t.split(/[\\s\\n]/);
                      for (const w of words) {
                        if (w.startsWith(prefix)) { found.push(w); break; }
                      }
                    }
                    return found;
                }""", name_prefix)
                if not names:
                    break
                deleted_any = False
                for name in names[:2]:
                    try:
                        if self.hybrid_delete_row(name):
                            cnt += 1
                            deleted_any = True
                            self.page.wait_for_timeout(500)
                            break  # 删一条后列表变化, 重新收集
                    except Exception:
                        pass
                if not deleted_any:
                    break
            except Exception:
                break
        return cnt

    def hybrid_import_rules(self, file_path: str, clear_existing: bool = False) -> bool:
        """混合模式子接入导入(evaluate处理, 规避基类import_rules在子接入的3处不适配:
        click_import的get_by_role找不到导入按钮/清空checkbox的check()被label拦截pointer/
        确定按钮是'确定上传'非'确定'). MCP实测弹窗: 点击上传(触发file chooser)+清空现有配置数据+确定上传."""
        import os
        try:
            if not os.path.exists(file_path):
                return False
            # 1. 点导入按钮(evaluate绕get_by_role)
            clicked = self.page.evaluate("""() => {
                const btns = [...document.querySelectorAll('main button')]
                    .filter(b => b.innerText.trim() === '导入' && !b.disabled && b.offsetParent !== null);
                if (btns.length) { btns[0].click(); return true; }
                return false;
            }""")
            if not clicked:
                print("[DEBUG] hybrid_import: 未找到导入按钮")
                return False
            self.page.wait_for_timeout(1000)
            # 2. 上传文件(直接set_input_files触发Antd Upload onChange, 不点击避免弹窗定位/file chooser问题)
            try:
                file_input = self.page.locator("[role='dialog'] input[type='file'], .ant-modal input[type='file']").first
                file_input.set_input_files(file_path)
            except Exception as e:
                print(f"[DEBUG] hybrid_import set_input_files error: {e}")
                return False
            self.page.wait_for_timeout(1500)
            # 3. 清空checkbox(evaluate click绕过label pointer拦截)
            if clear_existing:
                self.page.evaluate("""() => {
                    const ms = [...document.querySelectorAll('.ant-modal, [role="dialog"]')].filter(m => getComputedStyle(m).display !== 'none');
                    const m = ms[ms.length-1];
                    if (m) { const cb = m.querySelector('input[type="checkbox"]'); if (cb && !cb.checked) cb.click(); }
                }""")
                self.page.wait_for_timeout(500)
            # 4. 确定上传
            self.page.locator(".ant-modal button:has-text('确定上传')").first.click(timeout=5000)
            self.page.wait_for_timeout(2000)
            # 5. 关导入弹窗(防残留致后续close_modal_if_exists的.ant-modal-wrap strict violation:
            #   Escape + 轮询验证关闭)
            for _ in range(3):
                try:
                    modal_open = self.page.evaluate("""() => [...document.querySelectorAll('.ant-modal-wrap')].filter(m => getComputedStyle(m).display !== 'none' && (m.innerText||'').replace(/\\s/g,'').length > 5).length > 0""")
                    if not modal_open:
                        break
                    self.page.keyboard.press("Escape")
                    self.page.wait_for_timeout(500)
                except Exception:
                    break
            return True
        except Exception as e:
            print(f"[DEBUG] hybrid_import_rules error: {e}")
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(500)
            except Exception:
                pass
            return False

    # ==================== WAN 完整编辑封装 ====================
    def edit_wan(self, interface_name: str, tagname: str = None,
                 internet: str = None, static_ip: str = None, static_netmask: str = None,
                 static_gateway: str = None, static_dns1: str = None, static_dns2: str = None,
                 check_link_mode: str = None, check_host: str = None,
                 default_route: bool = None, disc_auto_switch: bool = None) -> dict:
        """编辑WAN配置(已在编辑页). 返回 {success, error}"""
        result = {"success": False, "error": ""}
        try:
            if internet:
                self.set_access_mode(internet)
            if static_ip:
                self.fill_static_ip(static_ip, static_netmask or "255.255.255.0",
                                    static_gateway or "", static_dns1 or "", static_dns2 or "")
            if tagname is not None:
                self.fill_tagname(tagname)
            if check_link_mode:
                self.set_check_link_mode(check_link_mode)
            if check_host is not None:
                self.fill_check_host(check_host)
            if default_route is not None:
                self.toggle_default_route(default_route)
            if disc_auto_switch is not None:
                self.toggle_disc_auto_switch(disc_auto_switch)

            self.click_save()
            self.page.wait_for_timeout(2000)

            err = self.has_form_error()
            if err:
                result["error"] = err
                return result
            # 保存成功会返回列表页
            if not self.is_still_on_edit_page():
                result["success"] = True
            else:
                result["error"] = "保存后仍在编辑页"
        except Exception as e:
            result["error"] = str(e)[:120]
        return result

    def try_edit_wan_invalid(self, interface_name: str, internet: str = "static",
                             static_ip: str = "999.999.999.999",
                             static_gateway: str = "") -> dict:
        """异常输入测试: 给WAN设非法IP/空网关, 验证前端拦截(保存被阻止)"""
        result = {"success": False, "error": "", "blocked": False}
        try:
            self.set_access_mode(internet)
            self.page.wait_for_timeout(800)
            if static_ip:
                self.fill_static_ip(static_ip, "255.255.255.0", static_gateway)
            self.click_save()
            self.page.wait_for_timeout(1500)
            err = self.has_form_error()
            if err:
                result["blocked"] = True
                result["error"] = err
            elif self.is_still_on_edit_page():
                result["blocked"] = True
                result["error"] = "保存被阻止(停留编辑页)"
        except Exception as e:
            result["error"] = str(e)[:120]
        return result

    # ==================== LAN 编辑页字段操作 ====================
    def toggle_lan_visit(self, enable: bool) -> bool:
        """切换'允许其他LAN访问此LAN'checkbox(LAN互访控制).
        enable=True允许互访(lan_visit=1), False禁止(lan_visit=0)
        实测: 是.ant-checkbox-wrapper, 文字'允许其他LAN访问此LAN', input.checked判断状态"""
        try:
            # 找含"允许其他LAN访问"的checkbox-wrapper
            cb = self.page.locator(".ant-checkbox-wrapper", has_text="允许其他LAN")
            if cb.count() == 0:
                # 降级: 含LAN访问或互访
                cb = self.page.locator(".ant-checkbox-wrapper", has_text="LAN访问")
            if cb.count() == 0:
                cb = self.page.locator(".ant-checkbox-wrapper", has_text="互访")
            if cb.count() == 0:
                print("[DEBUG] toggle_lan_visit: 未找到LAN访问checkbox")
                return False
            wrapper = cb.first
            inp = wrapper.locator("input[type=checkbox]")
            is_checked = inp.is_checked() if inp.count() > 0 else False
            if is_checked != enable:
                wrapper.click()
                self.page.wait_for_timeout(400)
            return True
        except Exception as e:
            print(f"[DEBUG] toggle_lan_visit error: {e}")
            return False

    def fill_lan_ip(self, ip: str, netmask: str = "255.255.255.0"):
        """填写LAN的IP/掩码(LAN编辑页)"""
        try:
            inputs = self.page.locator("input[type=text]")
            # LAN编辑页: 名称后是IP/掩码
            for i in range(inputs.count()):
                v = inputs.nth(i).input_value(timeout=1000)
                if self._looks_like_ip(v):
                    inputs.nth(i).fill("")
                    inputs.nth(i).fill(ip)
                    if i + 1 < inputs.count():
                        inputs.nth(i + 1).fill("")
                        inputs.nth(i + 1).fill(netmask)
                    break
        except Exception as e:
            print(f"[DEBUG] fill_lan_ip error: {e}")
        return self

    # ==================== 选择网卡(解绑/绑定) ====================
    def open_select_nic_dialog(self, interface_name: str) -> bool:
        """点击接口行的'选择网卡'按钮, 打开网卡选择抽屉(.ant-drawer)"""
        self._check_editable(interface_name)
        row = self._get_row(interface_name)
        if row is None:
            return False
        try:
            btn = row.get_by_text("选择网卡", exact=True).first
            if btn.count() == 0:
                return False
            btn.click()
            self.page.wait_for_timeout(2500)
            # 确认抽屉出现(是drawer不是modal)
            return self.page.locator(".ant-drawer-open .ant-drawer-content").count() > 0
        except Exception as e:
            print(f"[DEBUG] open_select_nic_dialog error: {e}")
            return False

    def _get_drawer(self) -> Locator:
        """获取打开的抽屉内容容器"""
        return self.page.locator(".ant-drawer-open .ant-drawer-content").last

    def get_nic_dialog_nics(self) -> List[str]:
        """获取网卡选择抽屉里的网卡列表(如ETH0/ETH1/ETH2)"""
        nics = []
        try:
            drawer = self._get_drawer()
            import re
            txt = drawer.inner_text(timeout=2000)
            nics = list(set(re.findall(r'(?:ETH|eth)\d+', txt)))
            nics.sort()
        except Exception as e:
            print(f"[DEBUG] get_nic_dialog_nics error: {e}")
        return nics

    def _is_nic_checked(self, nic_name: str) -> bool:
        """判断抽屉里指定网卡是否已选中(子div类含_checked)"""
        try:
            drawer = self._get_drawer()
            # 网卡项是 [class*=checkbox] 元素, 文字含网卡名
            cb = drawer.locator("[class*=checkbox]").filter(has_text=nic_name.upper()).first
            if cb.count() == 0:
                return False
            # 选中状态: 子div类含 _checked (排除 _uncheck)
            child_cls = cb.locator("div").first.get_attribute("class") or ""
            return "checked" in child_cls and "uncheck" not in child_cls
        except Exception:
            return False

    def toggle_nic_in_dialog(self, nic_name: str, check: bool) -> bool:
        """在网卡选择抽屉中勾选/取消指定网卡(ETH1等). 用Playwright真实click触发React"""
        try:
            drawer = self._get_drawer()
            cb = drawer.locator("[class*=checkbox]").filter(has_text=nic_name.upper()).first
            if cb.count() == 0:
                print(f"[DEBUG] toggle_nic_in_dialog: 未找到网卡 {nic_name}")
                return False
            is_checked = self._is_nic_checked(nic_name)
            if is_checked != check:
                # Playwright真实点击(非JS)才能触发React状态切换
                cb.click()
                self.page.wait_for_timeout(400)
            return True
        except Exception as e:
            print(f"[DEBUG] toggle_nic_in_dialog error: {e}")
            return False

    def save_nic_dialog(self) -> bool:
        """保存网卡选择抽屉(抽屉内保存按钮)"""
        try:
            drawer = self._get_drawer()
            btn = drawer.get_by_role("button", name="保存")
            if btn.count() == 0:
                btn = self.page.get_by_role("button", name="保存").last
            btn.first.click()
            self.page.wait_for_timeout(2500)
            return True
        except Exception as e:
            print(f"[DEBUG] save_nic_dialog error: {e}")
            return False

    def cancel_nic_dialog(self):
        """取消网卡选择抽屉"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(800)
        except Exception:
            pass

    def unbind_nics(self, interface_name: str, nic_names: List[str]) -> bool:
        """从接口解绑指定网卡(取消勾选). 注意: 若网卡是该接口唯一绑定,可能禁用无法解绑"""
        if not self.open_select_nic_dialog(interface_name):
            return False
        all_ok = True
        for nic in nic_names:
            # _checked_disable 表示禁用(唯一网卡不能解绑), 这种情况跳过不算失败
            try:
                drawer = self._get_drawer()
                cb = drawer.locator("[class*=checkbox]").filter(has_text=nic.upper()).first
                child_cls = cb.locator("div").first.get_attribute("class") or ""
                if "disable" in child_cls:
                    print(f"[DEBUG] {nic} 被禁用(唯一网卡), 跳过解绑")
                    continue
            except Exception:
                pass
            if not self.toggle_nic_in_dialog(nic, check=False):
                all_ok = False
        ok = self.save_nic_dialog()
        self.page.wait_for_timeout(1500)
        self.back_to_list()
        return ok and all_ok

    def bind_nics(self, interface_name: str, nic_names: List[str]) -> bool:
        """给接口绑定指定网卡(勾选)"""
        if not self.open_select_nic_dialog(interface_name):
            return False
        for nic in nic_names:
            self.toggle_nic_in_dialog(nic, check=True)
        ok = self.save_nic_dialog()
        self.page.wait_for_timeout(1500)
        self.back_to_list()
        return ok

    # ==================== 新增配置 ====================
    def is_add_button_enabled(self) -> bool:
        """新增配置按钮是否可用(网卡全分配时disabled)"""
        try:
            btn = self.page.get_by_role("button", name="新增配置")
            if btn.count() == 0:
                return False
            return btn.first.is_enabled()
        except Exception:
            return False

    def open_add_dialog(self) -> bool:
        """点击新增配置, 进入addLanWan新建页面(路由跳转)"""
        try:
            btn = self.page.get_by_role("button", name="新增配置")
            if btn.count() == 0 or not btn.first.is_enabled():
                return False
            btn.first.click()
            self.page.wait_for_timeout(2000)
            # addLanWan页面内容异步加载, 等待最多12秒
            for _ in range(20):
                self.page.wait_for_timeout(600)
                url_has = "addLanWan" in self.page.url
                # 页面内容加载标志: 出现网卡checkbox 或 内网/外网 文字 或 保存按钮
                has_content = (self.page.locator("[class*=checkbox]").count() > 0 or
                               self.page.get_by_text("内网").count() > 0 or
                               self.page.get_by_text("外网").count() > 0 or
                               self.page.get_by_role("button", name="保存").count() > 0)
                if url_has and has_content:
                    return True
            return "addLanWan" in self.page.url
        except Exception as e:
            print(f"[DEBUG] open_add_dialog error: {e}")
            return False

    def create_interface(self, nic_name: str, iftype: str = "lan") -> bool:
        """新增配置: 在addLanWan页面选网卡+类型+保存 → 进入编辑页
        iftype: 'lan'/'wan'
        返回是否真正进入 editLanWan 编辑页(新建成功). 严格判定: 保存后轮询URL跳转,
        停在 addLanWan 或出现错误提示即判失败(防'没新建却显示新建成功').
        注: addLanWan页面网卡/类型为卡片式, 用真实click触发"""
        try:
            target = nic_name.upper()
            # addLanWan页面: 网卡是卡片式checkbox(同选择网卡抽屉的_checkbox结构)
            # 1. 选类型(LAN/WAN) - radio或卡片
            type_kw = "内网" if iftype == "lan" else "外网"
            radios = self.page.locator(".ant-radio-wrapper, .ant-radio-button-wrapper")
            for i in range(min(radios.count(), 6)):
                try:
                    t = (radios.nth(i).inner_text(timeout=1000) or "").strip()
                    if type_kw in t:
                        radios.nth(i).click()
                        self.page.wait_for_timeout(400)
                        break
                except Exception:
                    continue
            # 2. 选网卡(卡片式checkbox) — 必须选中, 否则保存必失败, 不浪费保存
            nic_cb = self.page.locator("[class*=checkbox]").filter(has_text=target)
            if nic_cb.count() == 0:
                print(f"[DEBUG] create_interface: 未找到网卡 {target}, 新建失败")
                return False
            nic_cb.first.click()
            self.page.wait_for_timeout(500)
            # 3. 点保存/确定
            saved = False
            for btn_name in ["保存", "确定", "下一步"]:
                btn = self.page.get_by_role("button", name=btn_name)
                if btn.count() > 0 and btn.first.is_enabled():
                    btn.first.click()
                    saved = True
                    break
            if not saved:
                print(f"[DEBUG] create_interface: 未找到可点的保存按钮")
                return False
            # 4. 轮询≤6s判定: 进入 editLanWan=成功; 出现错误提示=失败
            for _ in range(15):
                self.page.wait_for_timeout(400)
                if "editLanWan" in self.page.url:
                    return True  # 跳转到编辑页 = 新建成功
                err = self.has_form_error()
                if err:
                    print(f"[DEBUG] create_interface: 保存报错 '{err}', 新建失败")
                    return False
            print(f"[DEBUG] create_interface: 保存后未跳转editLanWan(仍在addLanWan={('addLanWan' in self.page.url)}), 新建失败")
            return False
        except Exception as e:
            print(f"[DEBUG] create_interface error: {e}")
            return False

    # ==================== 删除接口 ====================
    def delete_interface(self, interface_name: str) -> bool:
        """删除接口(点删除→确认弹窗)"""
        self._check_editable(interface_name)
        row = self._get_row(interface_name)
        if row is None:
            return False
        try:
            btn = row.get_by_text("删除", exact=True).first
            if btn.count() == 0:
                return False
            btn.click()
            self.page.wait_for_timeout(1000)
            # 确认弹窗
            confirm = self.page.get_by_role("button", name="确定")
            if confirm.count() > 0:
                confirm.last.click()
                self.page.wait_for_timeout(2500)
            return True
        except Exception as e:
            print(f"[DEBUG] delete_interface({interface_name}) error: {e}")
            return False

    # ==================== 状态读/安全断开 + LAN扩展只读 ====================
    def get_connection_status(self) -> str:
        """读WAN编辑页状态区文本(已连接/未连接/连接中). 只读断言, 不实际断开."""
        try:
            for kw in ["已连接", "未连接", "连接中"]:
                loc = self.page.locator(f"text={kw}").first
                if loc.count() > 0 and loc.is_visible():
                    return kw
            return ""
        except Exception:
            return ""

    def click_disconnect(self, interface_name: str = None) -> bool:
        """点'断开'按钮(状态区). ⚠️ wan1由_check_editable硬拒绝; 测试中建议只用get_connection_status只读,
        实际断开会中断该接口连接."""
        if interface_name:
            self._check_editable(interface_name)
        try:
            btn = self.page.get_by_role("button", name="断开").first
            if btn.count() == 0:
                return False
            btn.click()
            self.page.wait_for_timeout(1000)
            return True
        except Exception as e:
            print(f"[DEBUG] click_disconnect error: {e}")
            return False

    def click_redial_connect(self, interface_name: str = None) -> bool:
        """点'重拨'(静态/DHCP)或'连接'(PPPoE)按钮. wan1硬拒绝."""
        if interface_name:
            self._check_editable(interface_name)
        try:
            for name in ["重拨", "连接"]:
                btn = self.page.get_by_role("button", name=name).first
                if btn.count() > 0 and btn.is_visible():
                    btn.click()
                    self.page.wait_for_timeout(1000)
                    return True
            return False
        except Exception:
            return False

    def has_lan_extend_fields(self) -> dict:
        """LAN编辑页扩展功能字段存在性(只读). 返回各字段是否可见:
        克隆MAC/扩展IP/LAN扩展模式/扩展网卡/LAN互访控制. 用于LAN扩展功能覆盖验证(不实际修改)."""
        result = {"clone_mac": False, "extend_ip": False, "extend_mode": False,
                  "extend_nic": False, "lan_visit_ctrl": False}
        try:
            checks = {"clone_mac": "克隆MAC", "extend_ip": "扩展IP",
                      "extend_mode": "扩展模式", "extend_nic": "扩展网卡",
                      "lan_visit_ctrl": "LAN互访"}
            for key, kw in checks.items():
                loc = self.page.locator(f"text={kw}").first
                result[key] = loc.count() > 0 and loc.is_visible()
        except Exception:
            pass
        return result

    # ==================== 帮助功能 ====================
    def click_help(self) -> bool:
        """点击帮助按钮"""
        try:
            help_btn = self.page.get_by_role("button", name="帮助")
            if help_btn.count() == 0:
                help_btn = self.page.locator("[class*=help], [aria-label*=help]").last
            if help_btn.count() == 0:
                return False
            help_btn.first.click()
            self.page.wait_for_timeout(1500)
            return True
        except Exception:
            return False
