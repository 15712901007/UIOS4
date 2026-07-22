"""
虚拟专网 > GRE 隧道 Page Object。

真实页面特征（10.66.0.150 iKuai OS V4 企业版实测）：
- 列表 URL 为 /#/vpn/gre（菜单：虚拟专网 → GRE）。
- 列表为自定义虚拟表格（div 布局），表头：接口/状态/类型/源地址/目的地址/描述/操作。
- 工具栏：搜索 + 新建 + 右下角帮助；当前固件前端未暴露导入/导出入口
  （底层脚本 /usr/ikuai/script/gre_tunnel.sh 虽有 EXPORT/IMPORT，但列表页无按钮）。
- 新增/编辑使用同一个 ant Drawer（.ant-drawer-content._addOrEditDrawer）。
- 表单分"基础设置"（默认展开）+"高级配置"（默认折叠 Collapse）。
- 关键字段映射（实测 id）：
    protocol      radio IPv4/IPv6            （protocol: 0=IPv4, 1=IPv6）
    tagname       input#tagname              （"隧道编号"，填数字→接口名 gre+数字）
    comment       textarea#comment           （备注）
    tunnel_addr   tunnel_addr{1|2}_0 + _1    （IPv4=1，IPv6=2；IP/掩码分开输入）
    src_mode      radio 指定IP地址/使用指定接口主IP地址（src_mode: 0/1）
    src_addr      input#src_addr             （src_mode=0 时显示）
    src_iface     ant-select                 （src_mode=1 时显示，选 WAN 接口）
    dst_addr      input#dst_addr
    keepalive     switch                     （开启后显示 keepalive_interval/_count）
    gre_key       input#gre_key
    tos           input#tos
    ttl           input#ttl
    checksum      switch（报文校验和功能）
    no_fragment   switch（封装后报文不允许分片）
- tagname 规则：DB 要求 ^gre 开头且 != gre0；前端"隧道编号"只接受数字，后端组装成 gre+数字。

安全约束：tagname 取值受脚本 ^gre[%w_%-]*$ 约束，本类对外接受完整接口名（如 gre1），
内部转成数字填入；隧道地址对外用 CIDR（如 10.99.99.1/30），内部拆成 IP/掩码。
"""

from __future__ import annotations

from typing import Dict, List, Optional

from playwright.sync_api import Locator, Page

from pages.ikuai_table_page import IkuaiTablePage


class GreTunnelPage(IkuaiTablePage):
    """虚拟专网 > GRE 隧道页面操作类。"""

    MODULE_NAME = "gre_tunnel"

    LIST_URL = "/#/vpn/gre"

    # 传输协议 radio 文本 -> DB protocol 值
    PROTOCOL_TEXT = {"IPv4": 0, "IPv6": 1}
    # 源地址方式 radio 文本 -> DB src_mode 值
    SRC_MODE_TEXT = {"指定IP地址": 0, "使用指定接口主IP地址": 1}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 通用小工具 ====================
    def _wait_page(self, settle_ms: int = 800):
        try:
            self.page.wait_for_load_state("networkidle", timeout=12000)
        except Exception:
            pass
        self.page.wait_for_timeout(settle_ms)

    def _dismiss_transient_overlays(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(120)
        except Exception:
            pass

    def _drawer(self) -> Locator:
        """新增/编辑 Drawer（与 Samba 不同：GRE 是单一 ant Drawer，非 vacantDrawer）。"""
        return self.page.locator(".ant-drawer-content").last

    def is_drawer_open(self) -> bool:
        try:
            d = self._drawer()
            return d.count() > 0 and d.is_visible()
        except Exception:
            return False

    def _fill_input(self, selector: str, value, root: Optional[Locator] = None) -> bool:
        """React 安全的 input 填写：fill 清空 + 逐字符 type 触发 onChange + setter/dispatch 兜底。"""
        try:
            scope = root or self.page
            inp = scope.locator(selector).first
            if inp.count() == 0:
                return False
            # disabled 元素不可交互: 裸 click() 会 30s 超时(实测 input#ttl 在 no_fragment=0
            # 时 disabled)。先检测 disabled 快速失败, 调用方据此调整(如先开 no_fragment)。
            try:
                is_disabled = inp.evaluate("el => !!(el.disabled || el.readOnly)")
            except Exception:
                is_disabled = False
            if is_disabled:
                print(f"[DEBUG] fill {selector}: 元素 disabled/readonly, 跳过(可能需先启用联动开关)")
                return False
            # 先滚入视口再click: 高级配置展开后 keepalive 子字段出现可能把 ttl/tos 挤出可视区
            # 或被遮挡 → 裸 click() 30s 超时。
            try:
                inp.scroll_into_view_if_needed(timeout=2000)
            except Exception:
                pass
            inp.click()
            try:
                inp.fill("")
            except Exception:
                pass
            if value is not None and str(value) != "":
                inp.type(str(value), delay=20)
            inp.evaluate("""el => {
                try {
                    const setter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value').set;
                    setter.call(el, el.value);
                } catch (e) {}
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            return True
        except Exception as exc:
            print(f"[DEBUG] fill {selector}: {str(exc)[:80]}")
            return False

    def _fill_textarea(self, selector: str, value, root: Optional[Locator] = None) -> bool:
        try:
            scope = root or self.page
            ta = scope.locator(selector).first
            if ta.count() == 0:
                return False
            ta.click()
            try:
                ta.fill("")
            except Exception:
                pass
            if value is not None and str(value) != "":
                ta.type(str(value), delay=15)
            ta.evaluate("""el => {
                try {
                    const setter = Object.getOwnPropertyDescriptor(
                        window.HTMLTextAreaElement.prototype, 'value').set;
                    setter.call(el, el.value);
                } catch (e) {}
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
            }""")
            return True
        except Exception as exc:
            print(f"[DEBUG] textarea {selector}: {str(exc)[:80]}")
            return False

    def _control_checked(self, locator: Locator) -> Optional[bool]:
        try:
            return bool(locator.evaluate("""el => {
                const sw = el.matches('.ant-switch') ? el : el.closest('.ant-switch');
                if (sw) return sw.getAttribute('aria-checked') === 'true' ||
                    sw.classList.contains('ant-switch-checked');
                const cb = el.matches('input[type=checkbox]') ? el : el.querySelector('input[type=checkbox]');
                return cb ? !!cb.checked : null;
            }"""))
        except Exception:
            return None

    def _set_switch(self, selector: str, enabled: bool, root: Optional[Locator] = None) -> bool:
        """Ant Switch：用 Playwright 原生 click 切换（evaluate JS click 不触发 React）。"""
        try:
            scope = root or self.page
            sw = scope.locator(selector).first
            if sw.count() == 0:
                return False
            current = self._control_checked(sw)
            if current is enabled:
                return True
            sw.click()
            self.page.wait_for_timeout(300)
            return self._control_checked(sw) is enabled
        except Exception as exc:
            print(f"[DEBUG] switch {selector}: {str(exc)[:80]}")
            return False

    def _click_radio_in_item(self, label_text: str, radio_text: str) -> bool:
        """在含 label_text 的 form-item 内点击文本为 radio_text 的 radio（原生 click）。"""
        try:
            drawer = self._drawer()
            item = drawer.locator(".ant-form-item").filter(
                has=self.page.locator(f".ant-form-item-label:has-text('{label_text}')")
            ).first
            if item.count() == 0:
                # 回退：在 drawer 内全局找 radio
                radio = drawer.locator(".ant-radio-wrapper").filter(has_text=radio_text).first
                if radio.count() > 0:
                    radio.click()
                    self.page.wait_for_timeout(400)
                    return True
                return False
            radio = item.locator(".ant-radio-wrapper").filter(has_text=radio_text).first
            if radio.count() == 0:
                return False
            radio.click()
            self.page.wait_for_timeout(500)
            return True
        except Exception as exc:
            print(f"[DEBUG] radio {label_text}/{radio_text}: {str(exc)[:80]}")
            return False

    def get_form_error(self, root: Optional[Locator] = None) -> Optional[str]:
        scope = root or self._drawer()
        for selector in (
            ".ant-form-item-explain-error:visible",
            ".ant-alert-error:visible",
        ):
            try:
                loc = scope.locator(selector)
                if loc.count() > 0:
                    text = (loc.first.inner_text() or "").strip()
                    if text:
                        return text[:180]
            except Exception:
                pass
        for selector in (
            ".ant-message-error:visible",
            ".ant-notification-notice-error:visible",
        ):
            try:
                loc = self.page.locator(selector)
                if loc.count() > 0:
                    text = (loc.last.inner_text() or "").strip()
                    if text:
                        return text[:180]
            except Exception:
                pass
        return None

    def get_last_notification(self, kind: str = "error") -> Optional[str]:
        """读取最近一条 ant-message / ant-notification 文本(含 success/info/warning/error)。

        用途: D11 检测保存后是否把后端原始 JSON(如 {"code":...,"error":...})直接弹给用户。
        kind='any' 读全部; 指定则只读该级别。computed style 判可见(modal/message 也是 fixed)。
        """
        try:
            return self.page.evaluate(f"""(kind) => {{
                const ok = e => {{
                    if (!e) return false;
                    const cs = getComputedStyle(e);
                    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
                    return e.getClientRects().length > 0;
                }};
                const sels = (kind === 'any')
                    ? ['.ant-message-notice', '.ant-notification-notice']
                    : ['.ant-message-' + kind, '.ant-notification-notice-' + kind,
                       '.ant-message-notice', '.ant-notification-notice'];
                const seen = [];
                for (const s of sels) {{
                    const nodes = [...document.querySelectorAll(s)].filter(ok);
                    for (const n of nodes) {{
                        const t = (n.innerText || n.textContent || '').trim();
                        if (t) seen.push(t);
                    }}
                    if (seen.length) break;
                }}
                return seen.length ? seen[seen.length - 1].slice(0, 300) : '';
            }}""", kind) or None
        except Exception:
            return None

    # ==================== 列表导航 ====================
    def navigate_to_gre(self):
        self._dismiss_transient_overlays()
        self._close_all_modals()
        self._close_drawers()
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        self._wait_page(1200)
        self._close_all_modals()
        self._close_drawers()
        return self

    navigate_to_gre_tunnel = navigate_to_gre

    def get_default_structure(self) -> Dict:
        result: Dict = {
            "url_ok": "vpn/gre" in self.page.url,
            "table_present": False,
            "search_present": False,
            "add_present": False,
            "help_present": False,
            "headers": [],
            "count_text": "",
        }
        try:
            result["search_present"] = self.page.get_by_placeholder(
                "请输入搜索内容"
            ).count() > 0
            result["add_present"] = (
                self.page.locator("main button").filter(has_text="新建").count() > 0
            )
            result["help_present"] = (
                self.page.locator("main button").filter(has_text="帮助").count() > 0
            )
            headers = self.page.evaluate("""() => {
                const vis = e => !!(e && e.offsetParent !== null);
                const ths = [...document.querySelectorAll('main .ant-table-thead th')]
                    .filter(vis).filter(t => !t.classList.contains('ant-table-measure-cell'));
                return ths.map(t => (t.innerText || '').replace(/\\s+/g, '').trim()).filter(Boolean);
            }""")
            result["headers"] = headers
            result["table_present"] = len(headers) > 0
            cnt = self.page.locator("text=/共\\s*\\d+\\s*条/").first
            if cnt.count() > 0:
                result["count_text"] = (cnt.inner_text() or "").strip()
        except Exception:
            pass
        return result

    # ==================== Drawer 打开/保存/取消 ====================
    def open_add_drawer(self) -> bool:
        self._dismiss_transient_overlays()
        # 兜底先回到列表，避免残留 drawer
        if not self.is_drawer_open():
            btn = self.page.locator("main button").filter(has_text="新建").first
            if btn.count() > 0:
                btn.click()
        self.page.locator(
            ".ant-drawer-content input#tagname"
        ).wait_for(state="visible", timeout=8000)
        # 等表单稳定
        self.page.wait_for_timeout(400)
        return self.is_drawer_open()

    def open_edit_drawer(self, iface: str) -> bool:
        """点列表行内"编辑"打开编辑 drawer。"""
        self._dismiss_transient_overlays()
        clicked = self._click_row_button_native(iface, "编辑")
        if not clicked:
            return False
        try:
            self.page.locator(
                ".ant-drawer-content input#tagname"
            ).wait_for(state="visible", timeout=8000)
        except Exception:
            return False
        self.page.wait_for_timeout(400)
        return self.is_drawer_open()

    def expand_advanced(self) -> bool:
        """展开"高级配置"折叠面板（已展开则保持）。"""
        try:
            drawer = self._drawer()
            # 找"高级配置"所在的可折叠 header 并点击（若未展开）
            need = drawer.evaluate("""() => {
                const vis = e => !!(e && e.offsetParent !== null);
                const headers = [...document.querySelectorAll(
                    '.ant-drawer-content .ant-collapse-header, ' +
                    '.ant-drawer-content [role="button"], ' +
                    '.ant-drawer-content button'
                )].filter(vis);
                for (const h of headers) {
                    if ((h.innerText || '').includes('高级配置')) {
                        // 判断是否已展开：父 collapse-item 的 active 类
                        const item = h.closest('.ant-collapse-item');
                        const expanded = item ? item.classList.contains('ant-collapse-item-active') : false;
                        if (!expanded) { h.click(); return 'clicked'; }
                        return 'already';
                    }
                }
                return 'not-found';
            }""")
            if need == "clicked":
                self.page.wait_for_timeout(600)
            return need != "not-found"
        except Exception as exc:
            print(f"[DEBUG] expand_advanced: {str(exc)[:80]}")
            return False

    def save_drawer(self, timeout: int = 10000) -> Dict:
        result = {"success": False, "error": ""}
        try:
            drawer = self._drawer()
            if drawer.count() == 0:
                result["error"] = "GRE drawer 未打开"
                return result
            save = drawer.locator("button:visible").filter(has_text="保存").last
            if save.count() == 0:
                result["error"] = "未找到保存按钮"
                return result
            save.click()
            for _ in range(max(1, timeout // 300)):
                self.page.wait_for_timeout(300)
                # 错误（表单校验/接口报错）
                err = self.get_form_error(drawer)
                if err:
                    result["error"] = err
                    return result
                # 成功：drawer 关闭
                if not self.is_drawer_open():
                    result["success"] = True
                    return result
            result["error"] = "保存后 drawer 仍未关闭"
        except Exception as exc:
            result["error"] = str(exc)[:140]
        return result

    save_and_wait = save_drawer

    def cancel_drawer(self) -> bool:
        try:
            drawer = self._drawer()
            if drawer.count() == 0:
                return True
            cancel = drawer.locator("button:visible").filter(has_text="取消").last
            if cancel.count() > 0:
                cancel.click()
                self.page.wait_for_timeout(400)
                # 取消可能弹"未保存确认"，点确定放弃
                self._click_visible_confirm(timeout=2500)
            else:
                self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(400)
            return not self.is_drawer_open()
        except Exception:
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return not self.is_drawer_open()

    # ==================== 表单字段操作 ====================
    @staticmethod
    def _iface_to_number(iface: str) -> str:
        """gre1 -> 1；前端"隧道编号"只填数字。"""
        text = str(iface or "").strip()
        if text.lower().startswith("gre"):
            return text[3:]
        return text

    def fill_tagname(self, iface: str) -> bool:
        return self._fill_input("input#tagname", self._iface_to_number(iface))

    def get_tagname_value(self) -> str:
        try:
            return self.page.locator(".ant-drawer-content input#tagname").input_value()
        except Exception:
            return ""

    def fill_comment(self, text: str) -> bool:
        return self._fill_textarea("textarea#comment", text)

    def set_protocol(self, protocol) -> bool:
        """protocol: 'IPv4'/'IPv6' 或 0/1。"""
        proto = str(protocol)
        if proto in ("0", "4"):
            proto = "IPv4"
        elif proto in ("1", "6"):
            proto = "IPv6"
        return self._click_radio_in_item("传输协议", proto)

    def set_src_mode(self, mode) -> bool:
        """mode: '指定IP地址'/'使用指定接口主IP地址' 或 0/1。"""
        text = str(mode)
        if text in ("0", "ip"):
            text = "指定IP地址"
        elif text in ("1", "iface"):
            text = "使用指定接口主IP地址"
        return self._click_radio_in_item("隧道源地址", text)

    def fill_src_addr(self, addr: str) -> bool:
        return self._fill_input("input#src_addr", addr)

    def select_src_iface(self, iface_label: str) -> bool:
        """src_mode=1 时选择源接口（WAN）。iface_label 如 'wan1(外网)' 或 'wan1'。"""
        try:
            drawer = self._drawer()
            sel = drawer.locator(".ant-select:has(input#src_iface) .ant-select-selector")
            if sel.count() == 0:
                # 部分 Ant 版本 select input id 不到，回退按 form-item
                item = drawer.locator(".ant-form-item").filter(
                    has=self.page.locator(".ant-form-item-label:has-text('隧道源地址')")
                ).first
                sel = item.locator(".ant-select-selector")
            if sel.count() == 0:
                return False
            sel.click()
            self.page.wait_for_timeout(400)
            # 在最新打开的下拉里按"接口名(备注)"做 parts 精确匹配（与记忆 select 坑一致）
            clicked = self.page.evaluate("""(label) => {
                const vis = e => !!(e && e.offsetParent !== null);
                const norm = s => (s || '').replace(/\\s+/g, '').trim();
                const dds = [...document.querySelectorAll('.ant-select-dropdown')].filter(vis);
                const dd = dds[dds.length - 1];
                if (!dd) return false;
                const want = norm(label).split('(')[0];
                const target = [...dd.querySelectorAll('.ant-select-item-option')].find(o => {
                    const t = norm(o.innerText || o.textContent);
                    return t === norm(label) || t.startsWith(want) || t.includes(want);
                });
                if (!target) return false;
                target.click();
                return true;
            }""", iface_label)
            self.page.wait_for_timeout(300)
            return bool(clicked)
        except Exception as exc:
            print(f"[DEBUG] select_src_iface: {str(exc)[:80]}")
            return False

    def fill_dst_addr(self, addr: str) -> bool:
        return self._fill_input("input#dst_addr", addr)

    def fill_tunnel_addr(self, cidr: str, protocol=None) -> bool:
        """拆 CIDR 填 IP/掩码两字段。protocol 决定字段 id（1=IPv4, 2=IPv6）。"""
        proto = self._protocol_index(protocol)
        text = str(cidr or "").strip()
        ip_part, mask_part = "", ""
        if "/" in text:
            ip_part, mask_part = text.split("/", 1)
        else:
            ip_part = text
        ok_ip = self._fill_input(f"input#tunnel_addr{proto}_0", ip_part)
        ok_mask = self._fill_input(f"input#tunnel_addr{proto}_1", mask_part) if mask_part else True
        return ok_ip and ok_mask

    def _protocol_index(self, protocol) -> int:
        """读取/推断当前 protocol 对应的字段索引：IPv4=1，IPv6=2。"""
        if protocol is None:
            # 从表单当前选中推断
            try:
                drawer = self._drawer()
                item = drawer.locator(".ant-form-item").filter(
                    has=self.page.locator(".ant-form-item-label:has-text('传输协议')")
                ).first
                v6 = item.locator(".ant-radio-wrapper").filter(has_text="IPv6").first
                v6_checked = v6.locator("input[type=radio]").is_checked() if v6.count() > 0 else False
                return 2 if v6_checked else 1
            except Exception:
                return 1
        proto = str(protocol)
        if proto in ("IPv6", "1", "6"):
            return 2
        return 1

    def fill_gre_key(self, key) -> bool:
        return self._fill_input("input#gre_key", key)

    def fill_tos(self, tos) -> bool:
        return self._fill_input("input#tos", tos)

    def fill_ttl(self, ttl) -> bool:
        return self._fill_input("input#ttl", ttl)

    def set_keepalive(self, enabled: bool, interval=None, count=None) -> bool:
        """开/关 keepalive；开启时可填 interval/count（开启后才显示）。"""
        ok = self._set_switch_in_item("keepalive", enabled)
        if enabled and ok:
            self.page.wait_for_timeout(500)
            if interval is not None:
                self._fill_input("input#keepalive_interval", interval)
            if count is not None:
                self._fill_input("input#keepalive_count", count)
        return ok

    def set_checksum(self, enabled: bool) -> bool:
        return self._set_switch_in_item("报文校验和功能", enabled)

    def set_no_fragment(self, enabled: bool) -> bool:
        return self._set_switch_in_item("封装后报文不允许分片", enabled)

    def _set_switch_in_item(self, label_text: str, enabled: bool) -> bool:
        try:
            drawer = self._drawer()
            item = drawer.locator(".ant-form-item").filter(
                has=self.page.locator(f".ant-form-item-label:has-text('{label_text}')")
            ).first
            if item.count() == 0:
                return False
            sw = item.locator(".ant-switch").first
            if sw.count() == 0:
                return False
            current = self._control_checked(sw)
            if current is enabled:
                return True
            sw.click()
            self.page.wait_for_timeout(300)
            return self._control_checked(sw) is enabled
        except Exception as exc:
            print(f"[DEBUG] switch_in_item {label_text}: {str(exc)[:80]}")
            return False

    # ==================== 表单读取（编辑回显核对） ====================
    def get_form_values(self) -> Dict:
        """读取当前 drawer 表单值（用于编辑回显核对）。"""
        vals: Dict = {}
        try:
            drawer = self._drawer()
            if drawer.count() == 0:
                return vals
            vals["tagname"] = self.get_tagname_value()
            try:
                vals["comment"] = drawer.locator("textarea#comment").input_value()
            except Exception:
                vals["comment"] = ""
            proto = self._protocol_index(None)
            vals["protocol"] = "IPv6" if proto == 2 else "IPv4"
            try:
                vals["tunnel_addr_ip"] = drawer.locator(
                    f"input#tunnel_addr{proto}_0").input_value()
                vals["tunnel_addr_mask"] = drawer.locator(
                    f"input#tunnel_addr{proto}_1").input_value()
            except Exception:
                vals["tunnel_addr_ip"] = vals["tunnel_addr_mask"] = ""
            try:
                vals["dst_addr"] = drawer.locator("input#dst_addr").input_value()
            except Exception:
                vals["dst_addr"] = ""
            # src_mode 判断
            try:
                item = drawer.locator(".ant-form-item").filter(
                    has=self.page.locator(".ant-form-item-label:has-text('隧道源地址')")
                ).first
                iface_radio = item.locator(".ant-radio-wrapper").filter(
                    has_text="使用指定接口主IP地址").first
                vals["src_mode"] = 1 if (
                    iface_radio.count() > 0 and iface_radio.locator("input[type=radio]").is_checked()
                ) else 0
            except Exception:
                vals["src_mode"] = 0
            try:
                vals["src_addr"] = drawer.locator("input#src_addr").input_value()
            except Exception:
                vals["src_addr"] = ""
            try:
                vals["gre_key"] = drawer.locator("input#gre_key").input_value()
            except Exception:
                vals["gre_key"] = ""
            try:
                vals["tos"] = drawer.locator("input#tos").input_value()
            except Exception:
                vals["tos"] = ""
            try:
                vals["ttl"] = drawer.locator("input#ttl").input_value()
            except Exception:
                vals["ttl"] = ""
            for key, label in (("keepalive", "keepalive"),
                               ("checksum", "报文校验和功能"),
                               ("no_fragment", "封装后报文不允许分片")):
                try:
                    item = drawer.locator(".ant-form-item").filter(
                        has=self.page.locator(f".ant-form-item-label:has-text('{label}')")
                    ).first
                    vals[key] = self._control_checked(item.locator(".ant-switch").first)
                except Exception:
                    vals[key] = None
        except Exception:
            pass
        return vals

    # ==================== 组合：新增/编辑 ====================
    def fill_tunnel_form(self, spec: Dict) -> bool:
        """按 spec 填写表单（不保存）。spec 见模块 docstring。"""
        checks: List[bool] = []
        proto = spec.get("protocol", "IPv4")
        checks.append(self.set_protocol(proto))
        self.page.wait_for_timeout(500)
        checks.append(self.fill_tagname(spec.get("iface", "")))
        checks.append(self.fill_tunnel_addr(spec.get("tunnel_addr", ""), proto))
        src_mode = spec.get("src_mode", "指定IP地址")
        checks.append(self.set_src_mode(src_mode))
        self.page.wait_for_timeout(400)
        if str(src_mode) in ("1", "iface", "使用指定接口主IP地址"):
            if spec.get("src_iface"):
                checks.append(self.select_src_iface(spec["src_iface"]))
        else:
            if spec.get("src_addr") is not None:
                checks.append(self.fill_src_addr(spec["src_addr"]))
        checks.append(self.fill_dst_addr(spec.get("dst_addr", "")))
        if spec.get("comment") is not None:
            checks.append(self.fill_comment(spec["comment"]))
        # 高级配置
        self.expand_advanced()
        advanced_any = (
            spec.get("keepalive") is not None or
            spec.get("gre_key") not in (None, "") or
            spec.get("checksum") is not None or
            spec.get("tos") not in (None, "") or
            spec.get("ttl") not in (None, "") or
            spec.get("no_fragment") is not None
        )
        if advanced_any:
            if spec.get("keepalive") is not None:
                checks.append(self.set_keepalive(
                    bool(spec.get("keepalive")),
                    spec.get("keepalive_interval"),
                    spec.get("keepalive_count"),
                ))
            if spec.get("gre_key") not in (None, ""):
                checks.append(self.fill_gre_key(spec.get("gre_key")))
            if spec.get("checksum") is not None:
                checks.append(self.set_checksum(bool(spec.get("checksum"))))
            if spec.get("tos") not in (None, ""):
                checks.append(self.fill_tos(spec.get("tos")))
            # ⚠ 顺序关键: no_fragment 必须在 ttl 之前切换。实测 input#ttl 默认 disabled
            # (value=0), 仅当 no_fragment=1 时才 enabled(校验 [no_fragment==0]&&{ttl==0}
            # 联动: no_fragment=0 锁定 ttl=0)。先开 no_fragment 才能 fill ttl, 否则 click
            # disabled 元素 30s 超时(表单填写失败)。
            if spec.get("no_fragment") is not None:
                checks.append(self.set_no_fragment(bool(spec.get("no_fragment"))))
            if spec.get("ttl") not in (None, ""):
                checks.append(self.fill_ttl(spec.get("ttl")))
        return all(checks) if checks else True

    def add_tunnel(self, spec: Dict) -> Dict:
        if not self.open_add_drawer():
            return {"success": False, "error": "打开 GRE 新增 drawer 失败"}
        if not self.fill_tunnel_form(spec):
            err = self.get_form_error() or "表单填写失败"
            self.cancel_drawer()
            return {"success": False, "error": err}
        return self.save_drawer()

    add_rule = add_tunnel

    def edit_tunnel(self, iface: str, spec: Dict) -> Dict:
        if not self.open_edit_drawer(iface):
            return {"success": False, "error": f"打开 {iface} 编辑 drawer 失败"}
        self.expand_advanced()
        if not self.fill_tunnel_form(spec):
            err = self.get_form_error() or "编辑表单填写失败"
            self.cancel_drawer()
            return {"success": False, "error": err}
        return self.save_drawer()

    def try_add_invalid(self, spec: Dict, *, expect_block: bool = True) -> Dict:
        """提交一次（可能非法的）表单，返回是否被拦截。"""
        result = {"blocked": False, "error": ""}
        if not self.open_add_drawer():
            result["error"] = "打开新增 drawer 失败"
            return result
        # 非法场景可能部分字段不存在/无法填，忽略返回值尽量填
        try:
            self.fill_tunnel_form(spec)
        except Exception:
            pass
        saved = self.save_drawer(timeout=4000)
        still_open = self.is_drawer_open()
        result["blocked"] = (not saved.get("success")) and still_open
        result["error"] = saved.get("error") or (
            "非法配置被拦截" if result["blocked"] else "非法配置被接受/已保存"
        )
        if still_open:
            self.cancel_drawer()
        return result

    # ==================== 列表行操作（适配 GRE 虚拟表格） ====================
    def rule_exists(self, iface: str) -> bool:
        """接口名存在于列表（精确匹配单元格，避免子串误命中）。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(400)
            return bool(self.page.evaluate("""(name) => {
                const vis = e => !!(e && e.offsetParent !== null);
                const cells = [...document.querySelectorAll('main .ant-table-tbody td, main .ant-table-cell')]
                    .filter(vis);
                return cells.some(c => (c.innerText || '').trim() === name);
            }""", str(iface)))
        except Exception:
            return False

    tunnel_exists = rule_exists

    def get_rule_names(self) -> List[str]:
        """返回列表中的接口名（第一列非 checkbox 单元格）。"""
        names: List[str] = []
        try:
            rows = self.page.locator("main .ant-table-tbody div.ant-table-row, main .ant-table-row")
            for idx in range(rows.count()):
                cells = rows.nth(idx).locator(".ant-table-cell")
                for ci in range(cells.count()):
                    cell = cells.nth(ci)
                    if cell.locator("input[type=checkbox]").count() > 0:
                        continue
                    text = (cell.inner_text() or "").strip()
                    if text:
                        names.append(text)
                        break
        except Exception:
            pass
        return list(dict.fromkeys(names))

    def is_tunnel_enabled(self, iface: str) -> bool:
        """列表行内有"停用"按钮=已启用。"""
        return self._has_row_button(iface, "停用")

    def is_tunnel_disabled(self, iface: str) -> bool:
        return self._has_row_button(iface, "启用")

    is_rule_enabled = is_tunnel_enabled
    is_rule_disabled = is_tunnel_disabled

    def _click_row_button_native(self, iface: str, button_name: str) -> bool:
        """用 evaluate 定位行内按钮并打标记，再用 Playwright 原生 click 触发 React。

        根因：基类 _click_rule_button 用 evaluate(element.click())，对 GRE 行内 Ant Button
        不触发 React onClick(停用/删除/编辑均失效)。改为 evaluate 定位+标记、原生 click。
        """
        try:
            marked = self.page.evaluate("""({name, btn}) => {
                const vis = e => !!(e && e.offsetParent !== null);
                // GRE 列表为自定义 div 表格(数据行非 .ant-table-cell)：
                // 找文本精确等于接口名的叶子元素，再向上找行内按钮。
                const cells = [...document.querySelectorAll('main *')].filter(e =>
                    vis(e) && (e.innerText || '').trim() === name &&
                    [...e.children].every(c => (c.innerText || '').trim() !== name));
                if (cells.length === 0) return false;
                const cell = cells[0];
                let p = cell, depth = 0;
                while (p && depth < 15) {
                    const btns = [...p.querySelectorAll('button')].filter(vis);
                    const target = btns.find(b => (b.innerText || '').trim() === btn);
                    if (target) { target.setAttribute('data-gre-action', '1'); return true; }
                    p = p.parentElement; depth++;
                }
                return false;
            }""", {"name": str(iface), "btn": button_name})
            if not marked:
                return False
            btn = self.page.locator("main button[data-gre-action='1']").first
            btn.click()
            self.page.wait_for_timeout(400)
            try:
                self.page.evaluate(
                    "document.querySelectorAll('[data-gre-action]').forEach(e=>e.removeAttribute('data-gre-action'))")
            except Exception:
                pass
            return True
        except Exception as exc:
            print(f"[DEBUG] _click_row_button_native {iface}/{button_name}: {str(exc)[:80]}")
            return False

    def _close_all_modals(self):
        """关闭所有可见 modal 残留(避免拦截后续行内按钮点击)。

        用 computed style 判断可见(不用 offsetParent: .ant-modal-wrap 是 fixed,
        offsetParent 恒为 null); 点"取消"或关闭按钮(不点确定, 避免误执行操作)。
        """
        try:
            self.page.evaluate("""() => {
                const ok = e => {
                    if (!e) return false;
                    const cs = getComputedStyle(e);
                    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
                    return e.getClientRects().length > 0;
                };
                const wraps = [...document.querySelectorAll('.ant-modal-wrap')].filter(w => {
                    const c = w.querySelector('.ant-modal-content');
                    return ok(c);
                });
                for (const w of wraps) {
                    const btns = [...w.querySelectorAll('button')].filter(ok);
                    const cancel = btns.find(b => (b.innerText || '').trim() === '取消');
                    if (cancel) { try { cancel.click(); } catch (e) {} continue; }
                    const close = w.querySelector('.ant-modal-close');
                    if (close && ok(close)) { try { close.click(); } catch (e) {} }
                }
            }""")
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _close_drawers(self):
        """关闭所有可见 ant-drawer(编辑/批量操作残留的 drawer+mask 会拦截列表点击)。"""
        try:
            self.page.evaluate("""() => {
                const ok = e => {
                    if (!e) return false;
                    const cs = getComputedStyle(e);
                    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
                    return e.getClientRects().length > 0;
                };
                const drawers = [...document.querySelectorAll('.ant-drawer')].filter(d => ok(d));
                for (const d of drawers) {
                    const close = d.querySelector('.ant-drawer-close');
                    if (close && ok(close)) { try { close.click(); } catch (e) {} }
                }
                // 兜底: 隐藏残留 drawer mask(避免拦截列表点击)
                document.querySelectorAll('.ant-drawer-mask').forEach(m => {
                    if (ok(m)) { m.style.display = 'none'; }
                });
            }""")
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _confirm_modal_by_text(self, text: str = "确定", timeout: int = 5000) -> bool:
        """按文本在可见 modal 中找确认按钮(evaluate 定位+标记, 原生 click 触发 React)。

        GRE 停用/删除确认是 ant-modal-content(非 popconfirm)，确定按钮可能非
        .ant-btn-primary，故按文本"确定"定位，比基类 _click_visible_confirm 更稳。
        """
        for _ in range(max(1, timeout // 300)):
            marked = self.page.evaluate("""(text) => {
                // 可见性判断用 computed style + getClientRects, 不用 offsetParent:
                // Ant 的 .ant-modal-wrap 是 position:fixed, offsetParent 恒为 null,
                // offsetParent 判断会误认为弹窗不可见 → 永远点不到"确定"(停用/删除确认弹窗残留拦截)。
                const ok = e => {
                    if (!e) return false;
                    const cs = getComputedStyle(e);
                    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
                    return e.getClientRects().length > 0;
                };
                const wraps = [...document.querySelectorAll(
                    '.ant-modal-wrap, .ant-popconfirm, .ant-popover')].filter(w => {
                    const content = w.matches('.ant-modal-wrap') ? w.querySelector('.ant-modal-content') : w;
                    return ok(content);
                });
                for (const w of wraps) {
                    const btns = [...w.querySelectorAll('button')].filter(ok);
                    const target = btns.find(b => (b.innerText || '').trim() === text);
                    if (target) { target.setAttribute('data-gre-ok', '1'); return true; }
                }
                return false;
            }""", text)
            if marked:
                try:
                    self.page.locator("button[data-gre-ok='1']").first.click(timeout=2000)
                    self.page.wait_for_timeout(400)
                    self.page.evaluate(
                        "document.querySelectorAll('[data-gre-ok]').forEach(e=>e.removeAttribute('data-gre-ok'))")
                    return True
                except Exception:
                    pass
            self.page.wait_for_timeout(300)
        return False

    def disable_rule(self, iface: str) -> bool:
        """停用隧道：行内"停用"(原生click) + Modal"确定"确认。"""
        self._close_all_modals()
        if not self._click_row_button_native(iface, "停用"):
            return False
        self.page.wait_for_timeout(700)
        return self._confirm_modal_by_text("确定", timeout=5000)

    disable_tunnel = disable_rule

    def enable_rule(self, iface: str) -> bool:
        """启用隧道：行内"启用"(原生click, 无确认弹窗)。"""
        if not self._click_row_button_native(iface, "启用"):
            return False
        try:
            self.page.wait_for_selector(".ant-message-success", timeout=3000)
        except Exception:
            pass
        return True

    enable_tunnel = enable_rule

    def _has_row_button(self, iface: str, button: str) -> bool:
        try:
            return bool(self.page.evaluate("""({name, btn}) => {
                const vis = e => !!(e && e.offsetParent !== null);
                const cells = [...document.querySelectorAll('main .ant-table-tbody td, main .ant-table-cell')]
                    .filter(vis);
                const cell = cells.find(c => (c.innerText || '').trim() === name);
                if (!cell) return false;
                let p = cell, depth = 0;
                while (p && depth < 12) {
                    const bts = [...p.querySelectorAll('button')].filter(vis);
                    if (bts.some(b => (b.innerText || '').trim() === btn)) return true;
                    p = p.parentElement; depth++;
                }
                return false;
            }""", {"name": str(iface), "btn": button}))
        except Exception:
            return False

    def delete_rule(self, iface: str) -> bool:
        """删除指定隧道（行内删除 + 确认弹窗）。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(400)
            self._close_all_modals()
            clicked = self._click_row_button_native(iface, "删除")
            if not clicked:
                return False
            self.page.wait_for_timeout(500)
            self._confirm_modal_by_text("确定", timeout=4000)
            for _ in range(20):
                self.page.wait_for_timeout(300)
                if not self.rule_exists(iface):
                    return True
            self.page.reload()
            self._wait_page(600)
            return not self.rule_exists(iface)
        except Exception as exc:
            print(f"[DEBUG] delete_rule {iface}: {str(exc)[:80]}")
            return False

    delete_tunnel = delete_rule

    def clean_test_tunnels(self, prefix: str = "gre_t") -> int:
        """删除所有接口名以 prefix 开头的测试隧道。"""
        deleted = 0
        for _ in range(80):
            names = [n for n in self.get_rule_names() if n.startswith(prefix)]
            if not names:
                break
            if not self.delete_rule(names[0]):
                break
            deleted += 1
        return deleted

    # ==================== 批量操作(真实勾选 + 验证"已选X条" + 检测批量栏) ====================
    # 背景(DOM实测): GRE 列表是标准 ant-table, 每行有 checkbox(ant-table-selection-column),
    # 但 footer 只有"帮助"+"共N条", 默认无批量启用/停用/删除按钮。基础类 batch_* 通过
    # div.footer 找按钮会落空, 却返回 self(truthy)=假通过。故 GRE 必须真实勾选目标行,
    # 验证"已选X条"计数, 再检测批量动作栏是否真正出现; 无批量栏则如实返回供测试标 N/A。
    def select_tunnel(self, iface: str, check: bool = True) -> bool:
        """勾选/取消勾选指定隧道行的 checkbox(定位接口名单元格→向上找行内 checkbox→原生 click)。"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(200)
            clicked = self.page.evaluate("""({name, want}) => {
                const vis = e => { if(!e) return false; const cs=getComputedStyle(e);
                    return cs.display!=='none' && cs.visibility!=='hidden'
                        && cs.opacity!=='0' && e.getClientRects().length>0; };
                const cells = [...document.querySelectorAll('main .ant-table-tbody td, main .ant-table-cell, main *')]
                    .filter(e => vis(e) && (e.innerText||'').trim() === name
                        && [...e.children].every(c => (c.innerText||'').trim() !== name));
                if (cells.length === 0) return false;
                let p = cells[0], depth = 0;
                while (p && depth < 12) {
                    const cb = p.querySelector('input[type=checkbox]');
                    if (cb) {
                        const label = cb.closest('.ant-checkbox-wrapper');
                        if ((!!cb.checked) !== want) {
                            // 优先点 wrapper(Ant onChange), 回退点 input
                            const tgt = label || cb;
                            tgt.click();
                        }
                        return true;
                    }
                    p = p.parentElement; depth++;
                }
                return false;
            }""", {"name": str(iface), "want": bool(check)})
            if clicked:
                self.page.wait_for_timeout(300)
            return bool(clicked)
        except Exception as exc:
            print(f"[DEBUG] select_tunnel {iface}: {str(exc)[:80]}")
            return False

    def select_tunnels(self, ifaces: List[str]) -> int:
        """勾选多个隧道行, 返回实际成功勾选的数量。"""
        n = 0
        for iface in ifaces:
            if self.select_tunnel(iface, check=True):
                n += 1
        self.page.wait_for_timeout(400)
        return n

    def clear_tunnel_selection(self) -> bool:
        """取消所有已勾选(再次点已勾选行, 或点全选切换)。"""
        try:
            # 找所有 checked 的行 checkbox 并取消
            self.page.evaluate("""() => {
                [...document.querySelectorAll('main .ant-table-tbody input[type=checkbox]')]
                    .forEach(cb => { if (cb.checked) { const w = cb.closest('.ant-checkbox-wrapper')||cb; w.click(); } });
            }""")
            self.page.wait_for_timeout(300)
            return True
        except Exception:
            return False

    def get_selected_count(self) -> int:
        """读取"已选X条"计数(无则0)。批量真实勾选的硬验证锚点。"""
        try:
            txt = self.page.evaluate("""() => {
                const m = document.body.innerText.match(/已选\\s*(\\d+)\\s*条/);
                return m ? m[1] : '';
            }""")
            return int(txt) if txt else 0
        except Exception:
            return 0

    def get_visible_batch_buttons(self) -> List[str]:
        """勾选后检测可见的批量动作按钮(启用/停用/删除)。无则空列表=前端无批量栏。"""
        try:
            btns = self.page.evaluate("""() => {
                const vis = e => { if(!e) return false; const cs=getComputedStyle(e);
                    return cs.display!=='none' && cs.visibility!=='hidden'
                        && cs.opacity!=='0' && e.getClientRects().length>0; };
                const want = ['启用','停用','删除'];
                const found = [];
                // 批量栏可能在 footer 或浮动 batch-action 区; 全 main 扫可见按钮(排除行内)
                [...document.querySelectorAll('main button')].filter(vis).forEach(b => {
                    const t = (b.innerText||'').replace(/\\s+/g,'').trim();
                    // 排除表格行内按钮(行内也有同名)
                    let q=b, inRow=false;
                    for(let i=0;i<6;i++){ q=q.parentElement; if(!q) break;
                        if(q.tagName==='TR'||q.classList.contains('ant-table-row')){inRow=true;break;} }
                    if(!inRow && want.includes(t) && !found.includes(t)) found.push(t);
                });
                return found;
            }""")
            return list(btns or [])
        except Exception:
            return []

    def click_batch_button(self, name: str) -> bool:
        """点击批量动作按钮(非行内, evaluate定位+标记+原生click触发React)。"""
        try:
            marked = self.page.evaluate("""(name) => {
                const vis = e => { if(!e) return false; const cs=getComputedStyle(e);
                    return cs.display!=='none' && cs.visibility!=='hidden'
                        && cs.opacity!=='0' && e.getClientRects().length>0; };
                const btns = [...document.querySelectorAll('main button')].filter(vis);
                for (const b of btns) {
                    if ((b.innerText||'').replace(/\\s+/g,'').trim() !== name) continue;
                    let q=b, inRow=false;
                    for(let i=0;i<6;i++){ q=q.parentElement; if(!q) break;
                        if(q.tagName==='TR'||q.classList.contains('ant-table-row')){inRow=true;break;} }
                    if (!inRow) { b.setAttribute('data-gre-batch','1'); return true; }
                }
                return false;
            }""", str(name))
            if not marked:
                return False
            self.page.locator("button[data-gre-batch='1']").first.click(timeout=3000)
            self.page.wait_for_timeout(400)
            try:
                self.page.evaluate(
                    "document.querySelectorAll('[data-gre-batch]').forEach(e=>e.removeAttribute('data-gre-batch'))")
            except Exception:
                pass
            return True
        except Exception:
            return False

    def batch_operate(self, ifaces: List[str], action: str,
                      need_confirm: bool = True) -> Dict:
        """真实批量操作: 勾选目标行→验证"已选X条"==len→点批量按钮→(确认)。

        返回 {selected, selected_count, buttons_available, action_clicked, confirmed}。
        若 buttons_available 不含 action → 前端无批量栏, 调用方据此标 N/A(不假通过)。
        """
        res = {"selected": 0, "selected_count": 0, "buttons_available": [],
               "action_clicked": False, "confirmed": False}
        res["selected"] = self.select_tunnels(ifaces)
        res["selected_count"] = self.get_selected_count()
        res["buttons_available"] = self.get_visible_batch_buttons()
        if action not in res["buttons_available"]:
            return res
        res["action_clicked"] = self.click_batch_button(action)
        if res["action_clicked"] and need_confirm:
            res["confirmed"] = self._confirm_modal_by_text("确定", timeout=5000)
        self.page.wait_for_timeout(600)
        return res

    def get_iface_status_text(self, iface: str) -> str:
        """读取列表"状态"列文本（如"开启"/"关闭"，或 up/down）。"""
        try:
            return self.page.evaluate("""(name) => {
                const vis = e => !!(e && e.offsetParent !== null);
                const cells = [...document.querySelectorAll('main .ant-table-tbody td, main .ant-table-cell')]
                    .filter(vis);
                const cell = cells.find(c => (c.innerText || '').trim() === name);
                if (!cell) return '';
                let p = cell.parentElement, depth = 0;
                while (p && depth < 8) {
                    const rowCells = [...p.querySelectorAll('.ant-table-cell')].filter(vis);
                    if (rowCells.length >= 3) {
                        // 状态列一般第3列（接口/状态/类型...）
                        return (rowCells[1].innerText || '').trim();
                    }
                    p = p.parentElement; depth++;
                }
                return '';
            }""", str(iface)) or ""
        except Exception:
            return ""

    # ==================== 帮助 ====================
    def verify_help(self, timeout: int = 8000) -> Dict:
        result = {"clicked": False, "popup_opened": False, "url": "", "no_orphan": False}
        popup = None
        before = len(self.page.context.pages)
        try:
            buttons = self.page.locator("main button").filter(has_text="帮助")
            if buttons.count() == 0:
                return result
            result["clicked"] = True
            with self.page.expect_popup(timeout=timeout) as info:
                buttons.first.click()
            popup = info.value
            result["popup_opened"] = popup is not None
            if popup is not None:
                for _ in range(20):
                    if popup.url and popup.url != "about:blank":
                        break
                    popup.wait_for_timeout(150)
                result["url"] = popup.url or ""
        except Exception as exc:
            result["error"] = str(exc)[:140]
        finally:
            try:
                if popup is not None and not popup.is_closed():
                    popup.close()
            except Exception:
                pass
            self.page.wait_for_timeout(250)
            result["no_orphan"] = len(self.page.context.pages) <= before
        return result

    # ==================== 导入/导出（前端当前未暴露入口） ====================
    def has_import_export_ui(self) -> bool:
        """探测列表是否有导入/导出按钮（当前固件实测无）。"""
        try:
            has_import = self.page.locator("main button").filter(has_text="导入").count() > 0
            has_export = self.page.locator("main button").filter(has_text="导出").count() > 0
            return has_import or has_export
        except Exception:
            return False
