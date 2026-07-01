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
            if opt.count() > 0:
                # 点含keyword的option-content(真实选项), 避开数字标签
                real_opt = self.page.locator(".ant-select-dropdown:visible").last.locator(
                    ".ant-select-item-option-content"
                ).filter(has_text=keyword)
                if real_opt.count() > 0:
                    real_opt.first.click()
                else:
                    opt.first.click()
                self.page.wait_for_timeout(1500)
                return True
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
            return bool(clicked)
        except Exception as e:
            print(f"[DEBUG] set_access_mode({mode}) error: {e}")
            return False

    def fill_static_ip(self, ip: str, netmask: str = "255.255.255.0",
                       gateway: str = "", dns1: str = "", dns2: str = ""):
        """填写静态IP字段. 切到静态模式后, IP/掩码/网关/DNS按input出现顺序.
        注意: 这些input无placeholder, 用序号定位(编辑页第3-7个text input)."""
        try:
            # 收集所有 text input(排除名称和只读)
            inputs = self.page.locator("input[type=text]")
            # 静态IP字段位置(经验值): 名称是第2个(input idx1), IP/掩码/网关/DNS1/DNS2 紧随
            # 用更稳健方式: 找值为IP格式或紧跟在接入方式后的input
            # 先尝试: 所有 text input 里值为IP的, 依次填
            vals_to_set = [v for v in [ip, netmask, gateway, dns1, dns2] if v]
            # 定位IP区: 找第一个值像IP的input作为起点
            start_idx = -1
            total = inputs.count()
            for i in range(total):
                v = inputs.nth(i).input_value(timeout=1000)
                if self._looks_like_ip(v) or v == "":
                    # 确认是IP区(紧跟名称之后)
                    start_idx = i
                    break
            if start_idx < 0:
                start_idx = 2  # 降级: 第3个
            # 依次填IP/掩码/网关/DNS1/DNS2
            fill_order = [(ip, 0), (netmask, 1), (gateway, 2), (dns1, 3), (dns2, 4)]
            for val, offset in fill_order:
                if not val:
                    continue
                idx = start_idx + offset
                if idx < total:
                    inp = inputs.nth(idx)
                    inp.fill("")
                    inp.fill(val)
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
        """切换复选框到指定状态(读当前状态决定是否点击)"""
        try:
            cb = self.page.locator(".ant-checkbox-wrapper", has_text=label_text)
            if cb.count() == 0:
                return False
            wrapper = cb.first
            is_checked = wrapper.locator("input").is_checked()
            if is_checked != enable:
                wrapper.click()
                self.page.wait_for_timeout(300)
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
                const sel = "input[type='text'], input[type='password'], input:not([type])";
                const inputs = [...document.querySelectorAll(sel)].filter(i => i.offsetParent !== null && !i.closest('.ant-select'));
                for (const inp of inputs) {
                    let p = inp.parentElement;
                    for (let depth = 0; depth < 6 && p; depth++) {
                        const t = p.innerText || '';
                        if (t.includes(kw)) {
                            const inps = [...p.querySelectorAll(sel)].filter(x => x.offsetParent !== null && !x.closest('.ant-select'));
                            if (inps.length === 1 && inps[0] === inp) {
                                const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
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
                const sel = "input[type='text'], input[type='password'], input:not([type])";
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
            self.page.locator("input[data-tmp-mark='1']").fill(value)
            self.page.evaluate("document.querySelector(\"input[data-tmp-mark='1']\")?.removeAttribute('data-tmp-mark')")
            self.page.wait_for_timeout(300)
            return True
        except Exception as e:
            print(f"[DEBUG] _fill_labeled_input_pw({label_keyword}) error: {e}")
            return False

    def _read_labeled_input(self, label_keyword: str) -> str:
        """读label关键词对应的单input字段当前值(与_fill_labeled_input同定位, 用于恢复/校验)"""
        try:
            val = self.page.evaluate("""(kw) => {
                const sel = "input[type='text'], input[type='password'], input:not([type])";
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
        """展开'高级设置'折叠面板(已展开则跳过). iKuai编辑页默认展开, 此为保险."""
        try:
            wm = self.page.locator("text=工作模式")
            if wm.count() > 0 and wm.first.is_visible():
                return True
            header = self.page.locator("text=高级设置").first
            if header.count() > 0:
                header.click()
                self.page.wait_for_timeout(800)
            return True
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
                            const sub = [...p.querySelectorAll('.ant-select')].filter(x => x.offsetParent !== null && !x.closest('.ant-select'));
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
        """填备注(label='备注', 覆盖基类以适配编辑页label结构)"""
        return self._fill_labeled_input("备注", remark)

    def fill_online_time_period(self, start: str = "00:00", end: str = "23:59") -> bool:
        """读/填上线时间段控制. iKuai为双input时间字段, 默认值不变即跳过(时间控件复杂, 测试仅读)."""
        # 时间字段填值易触发picker面板, 默认不主动改; 返回当前是否能读到
        return bool(self._read_labeled_input("上线时间") or self._read_labeled_input("开始时间"))

    # ==================== 混合模式二级表格(internet=3 MACVLAN物理混合/4 VLAN混合) ====================
    # 切到混合模式后, 编辑页变为二级表格: 导入/导出 + 3子tab(静态IP/DHCP动态IP/ADSL-PPPoE拨号)
    #   + 添加/启用/停用/删除 + 子表格(名称/IP/掩码/网关/MAC/备注/状态/操作).
    # 子接入存 wan_vlan表(interface=父WAN, vlan_id, vlan_name=子接入名, vlan_internet=0静/1DHCP/2PPPoE).
    # 添加=drawer抽屉表单(placeholder字段: 请输入名称/请输入IP地址/请输入MAC地址/请输入网关),
    #   drawer保存暂存→页面底部'保存'批量写库.
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
                           gateway: str = "", account: str = "", password: str = "") -> bool:
        """在混合模式drawer内填字段(按placeholder, Playwright真实fill触发React form state).
        静态子tab: name/ip/mac/gateway; PPPoE子tab: name/account/password."""
        try:
            dc = self._get_hybrid_drawer()
            def f(ph, val):
                if not val:
                    return False
                loc = dc.locator(f"input[placeholder='{ph}']")
                if loc.count() > 0:
                    loc.first.fill(val)
                    return True
                return False
            ok_name = f("请输入名称", name)
            f("请输入IP地址", ip)
            f("请输入MAC地址", mac)
            f("请输入网关", gateway)
            if account:
                loc = dc.locator("input[placeholder='请输入账号']")
                if loc.count() == 0:
                    loc = dc.locator("input").filter(has_text="")  # 降级占位
                if loc.count() > 0:
                    loc.first.fill(account)
            if password:
                pw = dc.locator("input[type='password']").first
                if pw.count() > 0:
                    pw.fill(password)
            self.page.wait_for_timeout(500)
            return ok_name
        except Exception as e:
            print(f"[DEBUG] hybrid_fill_drawer error: {e}")
            return False

    def hybrid_save_drawer(self) -> dict:
        """点drawer内'保存'. 返回 {saved, error}. 静态子tab可能报'输入有误'(疑产品bug), error有值."""
        result = {"saved": False, "error": ""}
        try:
            dc = self._get_hybrid_drawer()
            save_btn = dc.locator("button:has-text('保存')").first
            if save_btn.count() == 0:
                result["error"] = "drawer无保存按钮"
                return result
            save_btn.click()
            self.page.wait_for_timeout(2000)
            err = self.has_form_error()
            if err:
                result["error"] = err
                return result
            drawer_open = self.page.evaluate("""() => {
                return [...document.querySelectorAll('.ant-drawer')]
                    .filter(d => getComputedStyle(d).display !== 'none').length > 0;
            }""")
            result["saved"] = not drawer_open
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
                       subtab: str = "static", account: str = "", password: str = "") -> dict:
        """混合模式添加子接入(完整流程): 切子tab→开drawer→填→保存.
        返回 {success, error, in_table}. in_table=drawer保存后表格出现暂存行.
        ⚠️ 静态子tab添加在该环境报'输入有误'(疑产品bug), 此时success=False, error有值, 不抛异常."""
        result = {"success": False, "error": "", "in_table": False}
        try:
            self.switch_hybrid_subtab(subtab)
            self.page.wait_for_timeout(500)
            if not self.hybrid_open_add_drawer():
                result["error"] = "打开drawer失败"
                return result
            self.hybrid_fill_drawer(name, ip=ip, mac=mac, gateway=gateway,
                                    account=account, password=password)
            sv = self.hybrid_save_drawer()
            if sv.get("error"):
                result["error"] = sv["error"]
                self.hybrid_cancel_drawer()
                return result
            self.page.wait_for_timeout(1000)
            result["in_table"] = self.hybrid_row_exists(name)
            result["success"] = True
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

    # 混合模式行操作(复用IkuaiTablePage, 基于文本锚点+JS向上找按钮, 与行类型无关)
    def hybrid_delete_row(self, name: str) -> bool:
        """删除混合模式子接入行(复用基类delete_rule, 带确认弹窗)"""
        return self.delete_rule(name)

    def hybrid_enable_row(self, name: str) -> bool:
        return self.enable_rule(name)

    def hybrid_disable_row(self, name: str) -> bool:
        return self.disable_rule(name)

    def hybrid_row_exists(self, name: str) -> bool:
        return self.rule_exists(name)

    def hybrid_get_count(self) -> int:
        try:
            return self.get_rule_count()
        except Exception:
            return 0

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
        返回是否进入editLanWan编辑页(新建成功).
        注: addLanWan页面网卡/类型为卡片式, 用真实click触发"""
        try:
            target = nic_name.upper()
            # addLanWan页面: 网卡是卡片式checkbox(同选择网卡抽屉的_checkbox结构)
            # 1. 选类型(LAN/WAN) - radio或卡片
            type_kw = "内网" if iftype == "lan" else "外网"
            type_clicked = False
            radios = self.page.locator(".ant-radio-wrapper, .ant-radio-button-wrapper")
            for i in range(min(radios.count(), 6)):
                try:
                    t = (radios.nth(i).inner_text(timeout=1000) or "").strip()
                    if type_kw in t:
                        radios.nth(i).click()
                        type_clicked = True
                        self.page.wait_for_timeout(400)
                        break
                except Exception:
                    continue
            # 2. 选网卡(卡片式checkbox)
            nic_cb = self.page.locator("[class*=checkbox]").filter(has_text=target)
            if nic_cb.count() > 0:
                nic_cb.first.click()
                self.page.wait_for_timeout(500)
            # 3. 点保存/确定
            saved = False
            for btn_name in ["保存", "确定", "下一步"]:
                btn = self.page.get_by_role("button", name=btn_name)
                if btn.count() > 0 and btn.first.is_enabled():
                    btn.first.click()
                    self.page.wait_for_timeout(3500)
                    saved = True
                    break
            # 4. 新建成功→进入editLanWan编辑页
            return "editLanWan" in self.page.url or self.page.get_by_role("button", name="保存").count() > 0
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
