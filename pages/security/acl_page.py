"""
ACL规则页面类

安全中心 > ACL规则
URL: 列表 /login#/securityCenter/aclRules
     配置 /login#/securityCenter/aclRulesConfig (add/edit共用, edit通过点行"编辑"按钮进入,
     id经React state传递不在URL, 故edit必须点行按钮进入; add可直接goto CONFIG_URL)

页面特点 (2026-07-02 Playwright+SSH全链路探查):
- 列表表格 div.ant-table-row(虚拟滚动, 非tr), 行操作: 编辑/停用(启用)/复制/删除
- 添加/编辑是独立配置页(路由跳转, 非drawer/modal)
- 源/目的地址: 点区域"添加"按钮→新增空IP输入行→在行内type IP(非顶部输入框; 顶部输入框填值
  点添加会产生空行致保存报"请输入IP或MAC地址")
- 删除/停用确认弹窗: ant-modal "确定要删除当前项吗?" 确定/取消(非popconfirm)
- hash路由navigate不清表单(切换add/edit用location.hash或取消+重新添加)
- placeholder含中文引号"-"→用evaluate含'请输入IP或MAC'匹配, 不用get_by_placeholder

UI/DB值映射:
- 动作: UI允许/阻断 → DB accept/drop
- 方向: UI转发/进 → DB forward/input
- 连接方向匹配: UI关闭/原始/应答 → DB ctdir 0/1/2
- 协议: UI tcp/udp/tcp+udp/icmp/gre/任意 → DB同(any=任意)
- 协议栈: UI IPv4/IPv6 → DB ip_type 4/6

数据库表 acl (src_addr/dst_addr/time为明文JSON, 非base64; base64仅API层用):
- src_addr/dst_addr: {"object":{},"custom":["10.66.0.18"]} 或空 {"object":{},"custom":{}}
- time: {"object":{},"custom":[{"type":"weekly","weekdays":"1234567","start_time":"00:00","end_time":"23:59","comment":""}]}
- enabled: yes/no, prio: 0-63(默认31), comment, tagname(unique)

iptables落地 (acl.sh):
- dir=forward→FIREWALL链, dir=input→INPUT_ACL链 (FORWARD链引用FIREWALL)
- 规则: -j ACCEPT/DROP [-m set --match-set acl_src_{id} src] [-m set --match-set acl_dst_{id} dst]
        [-p proto --dport/--sport] timeset acl_time_{id} -m comment --comment {id}_{comment}
- ipset: acl_src_{id}/acl_dst_{id}(list:set, 含_acl_*_子集) + acl_time_{id}(ik_cntl timeset)
- enabled=yes才下发规则; down→del规则+enabled=no, up→add规则+enabled=yes
"""
from typing import Optional, List, Dict
from playwright.sync_api import Page

from pages.ikuai_table_page import IkuaiTablePage


class AclPage(IkuaiTablePage):
    """ACL规则页面操作类

    继承 IkuaiTablePage 复用 select_all/batch/export/import/_click_rule_button/delete_rule/
    disable_rule/enable_rule/search_rule/get_rule_count 等(div.ant-table-row虚拟滚动下,
    基类_click_rule_button的'文本锚点+JS向上找button'逻辑对div行同样适用).
    """

    MODULE_NAME = "acl"
    LIST_URL = "/login#/securityCenter/aclRules"
    CONFIG_URL = "/login#/securityCenter/aclRulesConfig"

    # UI选项映射(DB值 → UI显示文本)
    PROTOCOL_UI = {"any": "任意", "tcp": "tcp", "udp": "udp", "tcp_udp": "tcp+udp",
                   "icmp": "icmp", "gre": "gre"}
    ACTION_UI = {"accept": "允许", "drop": "阻断"}
    DIR_UI = {"forward": "转发", "input": "进"}
    CTDIR_UI = {0: "关闭", 1: "原始", 2: "应答"}
    STACK_UI = {"4": "IPv4", "6": "IPv6"}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================
    def navigate_to_acl(self):
        """导航到ACL规则列表页"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2500)
        return self

    def open_add_page(self) -> bool:
        """直接goto配置页进入新增模式(避开列表点添加的tab/时序竞争, 同MEMORY open_add_page直接导航最可靠).
        先清残留确认弹窗(modal/confirm) + 先回列表页清hash路由残留的配置页表单状态
        (hash路由navigate同URL不刷新SPA, 上场景残留地址行致'地址已存在'), 再goto配置页."""
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
        # 先回列表页(清配置页表单残留), 再进配置页确保干净新增页
        try:
            self.page.evaluate(f"location.hash='{self.LIST_URL.split('#')[1]}'")
            self.page.wait_for_timeout(1200)
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.CONFIG_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2500)
        # 确认进入配置页 + 名称输入框就绪
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        """是否在配置页(add/edit)"""
        try:
            return "aclRulesConfig" in self.page.url and \
                   self.page.get_by_placeholder("请输入名称").count() > 0
        except Exception:
            return "aclRulesConfig" in self.page.url

    def back_to_list(self):
        """返回列表页"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2000)
        return self

    # ==================== 通用: 区域block定位(源地址/目的地址) ====================
    def _mark_area_block(self, area: str) -> bool:
        """定位源地址/目的地址区域block并标记data-tmp-area.
        area='源地址'时block边界为'目的地址'前; area='目的地址'时为'进接口'前."""
        try:
            return bool(self.page.evaluate("""(area) => {
                const all=[...document.querySelectorAll('*')];
                const label=all.find(e=>e.offsetParent!==null && (e.textContent||'').replace(/\\s+/g,'').trim()===area);
                if(!label) return false;
                let block=label.parentElement;
                if(!block) return false;
                const stop = area==='源地址' ? '目的地址' : '进接口';
                for(let d=0;d<10;d++){
                    const pText=(block.parentElement?.innerText||'').replace(/\\s+/g,'');
                    if(pText.includes(stop)) break;
                    const np=block.parentElement;
                    if(!np) break;
                    block=np;
                }
                block.setAttribute('data-tmp-area', area);
                return true;
            }""", area))
        except Exception as e:
            print(f"[DEBUG] _mark_area_block({area}) error: {e}")
            return False

    def _clear_tmp_marks(self):
        """清理data-tmp-*标记"""
        try:
            self.page.evaluate("""() => {
                document.querySelectorAll('[data-tmp-area],[data-tmp-iprow],[data-tmp-mark],[data-tmp-save],[data-tmp-add]').forEach(e=>{
                    e.removeAttribute('data-tmp-area');e.removeAttribute('data-tmp-iprow');
                    e.removeAttribute('data-tmp-mark');e.removeAttribute('data-tmp-save');
                    e.removeAttribute('data-tmp-add');
                });
            }""")
        except Exception:
            pass

    # ==================== select通用(label关联) ====================
    def _select_by_label(self, label: str, option_text: str) -> bool:
        """按form-item-label精确匹配找select并选指定option.
        配置页select的label在.ant-form-item-label内(协议栈/协议/动作/方向/连接方向匹配/地址类型/进接口/出接口/源端口/目的端口).
        精确匹配避免'协议'误中'协议栈'(includes匹配的歧义, 实测tcp/udp/icmp设置失败根因).
        第一轮label===kw; 第二轮label含kw且长度接近(兜底)."""
        try:
            # 关闭残留dropdown(连续选不同select时)
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
            except Exception:
                pass
            found = self.page.evaluate("""(kw) => {
                const norm=s=>(s||'').replace(/[\\s:：*]/g,'');
                const sels=[...document.querySelectorAll('.ant-select')].filter(s=>s.offsetParent!==null);
                function labelOf(sel){
                    let p=sel;
                    for(let d=0;d<6&&p;d++){
                        p=p.parentElement; if(!p) break;
                        const le=p.querySelector('.ant-form-item-label');
                        if(le) return norm(le.textContent);
                    }
                    return '';
                }
                let target = sels.find(s=>labelOf(s)===kw);
                if(!target) target = sels.find(s=>{const l=labelOf(s); return l.includes(kw) && l.length<=kw.length+2 && l!==kw;});
                if(!target) return false;
                target.setAttribute('data-tmp-select','1');
                target.scrollIntoView({block:'center'});
                return true;
            }""", label)
            if not found:
                print(f"[DEBUG] _select_by_label 未定位select: {label}")
                return False
            # Playwright真实click打开dropdown(触发React, 比JS mousedown可靠: 实测协议tcp选中失败根因)
            try:
                self.page.locator("[data-tmp-select='1']").click()
            except Exception:
                self.page.evaluate("""() => {
                    const s=document.querySelector("[data-tmp-select='1'] .ant-select-selector");
                    if(s){s.dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));s.click();}
                }""")
            self.page.wait_for_timeout(900)
            clicked = self.page.evaluate("""(kw) => {
                const dds=[...document.querySelectorAll('.ant-select-dropdown')].filter(d=>d.offsetParent!==null);
                const dd=dds[dds.length-1];
                if(!dd) return false;
                const opts=[...dd.querySelectorAll('.ant-select-item-option')];
                for(const exact of [true,false]){
                    for(const o of opts){
                        const c=o.querySelector('.ant-select-item-option-content');
                        const txt=c?c.innerText.trim():'';
                        const title=o.getAttribute('title')||'';
                        if((exact && (txt===kw||title===kw)) || (!exact && (txt.includes(kw)||title.includes(kw)))){
                            o.click(); return true;
                        }
                    }
                }
                return false;
            }""", option_text)
            self.page.evaluate("document.querySelector(\"[data-tmp-select='1']\")?.removeAttribute('data-tmp-select')")
            if clicked:
                self.page.wait_for_timeout(500)
            else:
                print(f"[DEBUG] _select_by_label 未找到option: {label}={option_text}")
            return bool(clicked)
        except Exception as e:
            print(f"[DEBUG] _select_by_label({label}) error: {e}")
            return False

    # ==================== 配置页字段填充 ====================
    def fill_name(self, name: str) -> bool:
        """填名称(placeholder=请输入名称)"""
        try:
            inp = self.page.get_by_placeholder("请输入名称")
            if inp.count() == 0:
                return False
            inp.first.click()
            inp.first.fill("")
            inp.first.type(name, delay=30)
            return True
        except Exception as e:
            print(f"[DEBUG] fill_name error: {e}")
            return False

    def set_protocol_stack(self, stack: str = "4") -> bool:
        """设协议栈. stack: '4'IPv4/'6'IPv6"""
        ui = self.STACK_UI.get(stack, stack)
        return self._select_by_label("协议栈", ui)

    def set_protocol(self, protocol: str = "any") -> bool:
        """设协议. protocol: any/tcp/udp/tcp_udp/icmp/gre"""
        ui = self.PROTOCOL_UI.get(protocol, protocol)
        return self._select_by_label("协议", ui)

    def set_action(self, action: str = "accept") -> bool:
        """设动作. action: accept(允许)/drop(阻断)"""
        ui = self.ACTION_UI.get(action, action)
        return self._select_by_label("动作", ui)

    def set_dir(self, direction: str = "forward") -> bool:
        """设方向. direction: forward(转发)/input(进)"""
        ui = self.DIR_UI.get(direction, direction)
        return self._select_by_label("方向", ui)

    def set_ctdir(self, ctdir: int = 0) -> bool:
        """设连接方向匹配. ctdir: 0关闭/1原始/2应答"""
        ui = self.CTDIR_UI.get(ctdir, str(ctdir))
        return self._select_by_label("连接方向匹配", ui)

    def set_priority(self, prio: int = 31) -> bool:
        """设优先级(0-63, 默认31). spinbutton placeholder=请输入优先级"""
        try:
            inp = self.page.get_by_placeholder("请输入优先级")
            if inp.count() == 0:
                return False
            inp.first.click()
            inp.first.press("Control+a")
            inp.first.type(str(prio), delay=40)
            return True
        except Exception as e:
            print(f"[DEBUG] set_priority error: {e}")
            return False

    # ---- 源/目的地址(IP/MAC类型, 点添加新增行+type IP) ----
    def _click_addr_area_button(self, area: str, button_text: str) -> bool:
        """点源地址/目的地址区域内的指定按钮(添加/批量)"""
        try:
            if not self._mark_area_block(area):
                return False
            clicked = self.page.evaluate("""({area, btn}) => {
                const block=document.querySelector(`[data-tmp-area="${area}"]`);
                if(!block) return false;
                const btns=[...block.querySelectorAll('button')].filter(b=>b.offsetParent!==null);
                const target=btns.find(b=>(b.textContent||'').replace(/\\s+/g,'').trim()===btn);
                if(target){ target.click(); return true; }
                return false;
            }""", {"area": area, "btn": button_text})
            return bool(clicked)
        except Exception as e:
            print(f"[DEBUG] _click_addr_area_button({area},{button_text}) error: {e}")
            return False

    def _type_addr_row(self, area: str, ip: str, row_index: int = -1) -> bool:
        """在area区域第row_index个IP输入行(默认最后一个)type IP.
        IP输入行placeholder含'请输入IP或MAC'(中文引号, 用includes匹配)."""
        try:
            if not self._mark_area_block(area):
                return False
            # 标记目标行
            marked = self.page.evaluate("""({area, idx}) => {
                const block=document.querySelector(`[data-tmp-area="${area}"]`);
                if(!block) return -1;
                const inps=[...block.querySelectorAll('input, textarea')].filter(i=>i.offsetParent!==null && (i.placeholder||'').includes('请输入IP'));
                if(!inps.length) return 0;
                const target = idx<0 ? inps[inps.length-1] : (inps[idx]||inps[inps.length-1]);
                target.setAttribute('data-tmp-iprow','1');
                target.scrollIntoView({block:'center'});
                return inps.length;
            }""", {"area": area, "idx": row_index})
            if marked is None or marked == -1:
                print(f"[DEBUG] _type_addr_row({area}) 未定位block")
                return False
            if marked == 0:
                print(f"[DEBUG] _type_addr_row({area}) 无IP输入行(需先点'添加')")
                return False
            loc = self.page.locator("[data-tmp-iprow='1']")
            loc.click()
            loc.fill("")
            loc.type(ip, delay=30)
            self.page.wait_for_timeout(300)
            self.page.evaluate("document.querySelector(\"[data-tmp-iprow='1']\")?.removeAttribute('data-tmp-iprow')")
            return True
        except Exception as e:
            print(f"[DEBUG] _type_addr_row({area}) error: {e}")
            return False

    def add_src_address(self, ip: str) -> bool:
        """源地址添加一个IP: 点源地址'添加'按钮(新增空IP行) + 在行type IP.
        支持单IP/网段CIDR/IP段(10.0.0.1-10.0.0.99). 多次调用追加多行."""
        if not self._click_addr_area_button("源地址", "添加"):
            return False
        self.page.wait_for_timeout(700)
        return self._type_addr_row("源地址", ip)

    def add_dst_address(self, ip: str) -> bool:
        """目的地址添加一个IP(同add_src_address, 作用于目的地址区域)"""
        if not self._click_addr_area_button("目的地址", "添加"):
            return False
        self.page.wait_for_timeout(700)
        return self._type_addr_row("目的地址", ip)

    def toggle_src_invert(self, enable: bool) -> bool:
        """切换源地址'反向匹配'checkbox(src_addr_inv)"""
        return self._toggle_addr_checkbox("源地址", enable)

    def toggle_dst_invert(self, enable: bool) -> bool:
        """切换目的地址'反向匹配'checkbox(dst_addr_inv)"""
        return self._toggle_addr_checkbox("目的地址", enable)

    def _toggle_addr_checkbox(self, area: str, enable: bool) -> bool:
        """切换area区域'反向匹配'checkbox到指定状态"""
        try:
            if not self._mark_area_block(area):
                return False
            return bool(self.page.evaluate("""({area, en}) => {
                const block=document.querySelector(`[data-tmp-area="${area}"]`);
                if(!block) return false;
                const cbs=[...block.querySelectorAll('.ant-checkbox-wrapper')].filter(c=>c.offsetParent!==null && (c.textContent||'').includes('反向匹配'));
                if(!cbs.length) return false;
                const cb=cbs[0];
                const inp=cb.querySelector('input[type=checkbox]');
                const checked = inp ? inp.checked : cb.querySelector('.ant-checkbox-checked')!==null;
                if(checked!==en){ cb.click(); }
                return true;
            }""", {"area": area, "en": enable}))
        except Exception as e:
            print(f"[DEBUG] _toggle_addr_checkbox({area}) error: {e}")
            return False

    def get_addr_row_count(self, area: str) -> int:
        """获取area区域当前IP输入行数(用于SSH计数校验)"""
        try:
            if not self._mark_area_block(area):
                return 0
            cnt = self.page.evaluate("""(area) => {
                const block=document.querySelector(`[data-tmp-area="${area}"]`);
                if(!block) return 0;
                return [...block.querySelectorAll('input, textarea')].filter(i=>i.offsetParent!==null && (i.placeholder||'').includes('请输入IP') && (i.value||'').trim()).length;
            }""", area)
            return int(cnt or 0)
        except Exception:
            return 0

    # ---- 端口(协议tcp/udp/tcp+udp后才出现, '端口分组'multiple tags select, 共2个: 源/目的) ----
    def set_src_port(self, port: str = "") -> bool:
        """设源端口(第1个'端口分组'select). port空/任意=不设(默认任意)."""
        if not port or port == "任意":
            return True
        return self._set_port_input(0, port)

    def set_dst_port(self, port: str = "") -> bool:
        """设目的端口(第2个'端口分组'select)"""
        if not port or port == "任意":
            return True
        return self._set_port_input(1, port)

    def _set_port_input(self, port_idx: int, port: str) -> bool:
        """端口分组select(multiple tags, 协议tcp/udp后才出现). 打开第port_idx个'端口分组'select + type port + Enter添加tag.
        未打开则不type(避免keyboard.type污染地址行, 实测场景5'请填写正确IP'根因: 端口label是'端口分组'非'目的端口')."""
        try:
            found = self.page.evaluate("""(idx) => {
                const norm=s=>(s||'').replace(/[\\s:：*]/g,'');
                const sels=[...document.querySelectorAll('.ant-select')].filter(s=>s.offsetParent!==null);
                const ports = sels.filter(s=>{
                    let p=s;
                    for(let d=0;d<6&&p;d++){p=p.parentElement;if(!p)break;const le=p.querySelector('.ant-form-item-label');if(le)return norm(le.textContent)==='端口分组';}
                    return false;
                });
                const target = ports[idx];
                if(!target) return false;
                target.setAttribute('data-tmp-select','1');
                target.scrollIntoView({block:'center'});
                return true;
            }""", port_idx)
            if not found:
                print(f"[DEBUG] _set_port_input 未找到第{port_idx}个端口分组select(协议需tcp/udp)")
                return False
            try:
                self.page.locator("[data-tmp-select='1']").click()
            except Exception:
                pass
            self.page.wait_for_timeout(1500)
            self.page.evaluate("document.querySelector(\"[data-tmp-select='1']\")?.removeAttribute('data-tmp-select')")
            # 端口分组select点击弹'端口选择'modal(选端口分组, 非数字输入, 需预建路由对象端口分组).
            # 关闭modal避免遮挡后续保存(实测modal致click_save 30s超时). 当前无端口分组, 端口未设.
            self._dismiss_all_modals()
            print(f"[DEBUG] _set_port_input: 端口分组弹选择modal(需预建端口分组), 已关闭, 端口未设")
            return False
        except Exception as e:
            print(f"[DEBUG] _set_port_input error: {e}")
            return False

    def _select_by_label_open_only(self, label: str) -> bool:
        """只打开label关联的select下拉(不选), 用于端口输入. 标记+Playwright真实click."""
        try:
            try:
                self.page.keyboard.press("Escape")
                self.page.wait_for_timeout(200)
            except Exception:
                pass
            found = self.page.evaluate("""(kw) => {
                const norm=s=>(s||'').replace(/[\\s:：*]/g,'');
                const sels=[...document.querySelectorAll('.ant-select')].filter(s=>s.offsetParent!==null);
                function labelOf(sel){
                    let p=sel;
                    for(let d=0;d<6&&p;d++){
                        p=p.parentElement; if(!p) break;
                        const le=p.querySelector('.ant-form-item-label');
                        if(le) return norm(le.textContent);
                    }
                    return '';
                }
                let target = sels.find(s=>labelOf(s)===kw);
                if(!target) target = sels.find(s=>{const l=labelOf(s); return l.includes(kw) && l.length<=kw.length+2 && l!==kw;});
                if(!target) return false;
                target.setAttribute('data-tmp-select','1');
                target.scrollIntoView({block:'center'});
                return true;
            }""", label)
            if not found:
                return False
            try:
                self.page.locator("[data-tmp-select='1']").click()
            except Exception:
                self.page.evaluate("""() => {
                    const s=document.querySelector("[data-tmp-select='1'] .ant-select-selector");
                    if(s){s.dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));s.click();}
                }""")
            self.page.wait_for_timeout(700)
            return True
        except Exception:
            return False

    # ---- 备注 ----
    def fill_remark(self, remark: str) -> bool:
        """填备注(textarea). 覆盖基类, 用label关联定位textarea."""
        try:
            ok = self.page.evaluate("""(val) => {
                const tas=[...document.querySelectorAll('textarea')].filter(t=>t.offsetParent!==null);
                // 备注是配置页唯一的textarea(或最后一个)
                const ta = tas.find(t=>(t.placeholder||'').length<5 && !t.value) || tas[tas.length-1];
                if(!ta) return false;
                ta.setAttribute('data-tmp-mark','1'); ta.scrollIntoView({block:'center'}); return true;
            }""", remark)
            if not ok:
                return False
            loc = self.page.locator("[data-tmp-mark='1']")
            loc.click()
            loc.fill("")
            loc.type(remark, delay=20)
            self.page.evaluate("""() => {
                const el=document.querySelector("[data-tmp-mark='1']");
                if(el){ el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('blur',{bubbles:true})); }
            }""")
            self.page.evaluate("document.querySelector(\"[data-tmp-mark='1']\")?.removeAttribute('data-tmp-mark')")
            return True
        except Exception as e:
            print(f"[DEBUG] fill_remark error: {e}")
            return False

    # ==================== 保存/校验 ====================
    def click_save(self) -> bool:
        """点保存按钮. 先关闭可能开着的dropdown(端口'端口分组'multiple select Enter后dropdown保持开,
        遮挡保存按钮致click 30s超时, 实测场景5根因): Escape + 点页面顶部标题区关闭残留dropdown."""
        try:
            for _ in range(2):
                try:
                    self.page.keyboard.press("Escape")
                except Exception:
                    pass
            self.page.wait_for_timeout(300)
            # 点页面顶部标题区关闭残留dropdown(Antd multiple select dropdown Escape可能不关)
            try:
                self.page.locator(".ant-layout-header, header, .ant-page-header").first.click(timeout=1500)
                self.page.wait_for_timeout(300)
            except Exception:
                pass
            btn = self.page.get_by_role("button", name="保存")
            if btn.count() == 0:
                return False
            btn.first.click(timeout=8000)
            self.page.wait_for_timeout(1500)
            return True
        except Exception as e:
            print(f"[DEBUG] click_save error: {e}")
            return False

    def click_cancel(self) -> bool:
        """点取消(返回列表), 处理'确认离开'弹窗"""
        try:
            btn = self.page.get_by_role("button", name="取消")
            if btn.count() > 0:
                btn.first.click()
                self.page.wait_for_timeout(1000)
            # 处理确认离开弹窗
            self._dismiss_all_modals()
            return True
        except Exception:
            return False

    def has_form_error(self) -> Optional[str]:
        """检查配置页是否有表单校验错误(异常输入拦截)"""
        try:
            err = self.page.locator(".ant-form-item-explain-error")
            if err.count() > 0:
                txt = err.first.text_content()
                if txt and txt.strip():
                    return txt.strip()
            if self.page.locator(".ant-input-status-error, .ant-form-item-has-error").count() > 0:
                return "输入格式错误"
            toast = self.page.locator(".ant-message-error, .ant-notification-error")
            if toast.count() > 0:
                return (toast.first.text_content() or "操作失败").strip()
        except Exception:
            pass
        return None

    def is_still_on_config_page(self) -> bool:
        """是否还在配置页(保存被阻止时停留)"""
        return "aclRulesConfig" in self.page.url

    def save_and_wait(self, timeout: int = 8000) -> dict:
        """点保存并轮询结果. 返回 {success, error}.
        成功=URL离开配置页(跳回列表)且无错误; 失败=停留配置页或有错误提示.
        参考MEMORY独立页表单保存后异步跳转需轮询6s+."""
        result = {"success": False, "error": ""}
        try:
            self.click_save()
            for _ in range(int(timeout / 400)):
                self.page.wait_for_timeout(400)
                # 错误提示=失败
                err = self.has_form_error()
                if err:
                    result["error"] = err
                    return result
                # 离开配置页=成功(跳回列表)
                if "aclRulesConfig" not in self.page.url:
                    result["success"] = True
                    return result
            # 超时仍在配置页
            if "aclRulesConfig" not in self.page.url:
                result["success"] = True
            else:
                result["error"] = "保存后仍在配置页"
        except Exception as e:
            result["error"] = str(e)[:80]
        return result

    def _dismiss_all_modals(self):
        """关闭所有可见modal/confirm弹窗(确认离开/删除确认等)"""
        try:
            for _ in range(5):
                open_cnt = self.page.evaluate("""() => {
                    const ms=[...document.querySelectorAll('.ant-modal-wrap')].filter(m=>getComputedStyle(m).display!=='none' && (m.innerText||'').replace(/\\s/g,'').length>3);
                    if(!ms.length) return 0;
                    // 优先点'确定'(删除/确认离开), 次点'取消'
                    const m=ms[ms.length-1];
                    let btn=[...m.querySelectorAll('button')].find(b=>(b.textContent||'').trim()==='确定');
                    if(!btn) btn=[...m.querySelectorAll('button')].find(b=>(b.textContent||'').trim()==='取消');
                    if(btn) btn.click();
                    return ms.length;
                }""")
                if open_cnt == 0:
                    break
                self.page.wait_for_timeout(700)
        except Exception:
            pass

    # ==================== 完整添加流程 ====================
    def add_rule(self, name: str, action: str = "accept", direction: str = "forward",
                 protocol: str = "any", src_addrs: list = None, dst_addrs: list = None,
                 src_port: str = "", dst_port: str = "", priority: int = 31,
                 ctdir: int = 0, remark: str = "", enabled: bool = True) -> dict:
        """添加ACL规则完整流程. 返回 {success, error}.
        src_addrs/dst_addrs: IP列表(单IP/网段/段), 每个新增一行.
        默认enabled=True(新增即启用下发iptables)."""
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            self.fill_name(name)
            if action:
                self.set_action(action)
            if direction:
                self.set_dir(direction)
            if protocol and protocol != "any":
                self.set_protocol(protocol)
            if priority != 31:
                self.set_priority(priority)
            if ctdir:
                self.set_ctdir(ctdir)
            if src_addrs:
                for ip in src_addrs:
                    self.add_src_address(ip)
            if dst_addrs:
                for ip in dst_addrs:
                    self.add_dst_address(ip)
            if src_port:
                self.set_src_port(src_port)
            if dst_port:
                self.set_dst_port(dst_port)
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

    def try_add_rule_invalid(self, name: str = "", illegal_src: str = "") -> dict:
        """异常输入测试: 空名称/非法IP等, 验证前端拦截(保存被阻止=blocked=True).
        illegal_src: 非法源地址IP(如999.999.999.999), 验证IP行校验."""
        result = {"success": False, "error": "", "blocked": False}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            if name:
                self.fill_name(name)
            if illegal_src:
                self.add_src_address(illegal_src)
            self.click_save()
            self.page.wait_for_timeout(1500)
            err = self.has_form_error()
            if err:
                result["blocked"] = True
                result["error"] = err
            elif self.is_still_on_config_page():
                result["blocked"] = True
                result["error"] = "保存被阻止(停留配置页)"
            # 离开配置页(异常输入不应保存成功, 若成功则未拦截)
            if not self.is_still_on_config_page():
                result["error"] = "异常输入未被拦截(保存成功)"
        except Exception as e:
            result["error"] = str(e)[:120]
        return result

    # ==================== 行操作(覆盖基类以适配div.ant-table-row + ant-modal确认) ====================
    def delete_rule(self, rule_name: str) -> bool:
        """删除规则(div行+ant-modal确认). 覆盖基类."""
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(500)
        try:
            count_before = self.get_rule_count()
            if not self._click_rule_button(rule_name, "删除"):
                return False
            self.page.wait_for_timeout(800)
            # ant-modal确认(基类_click_visible_confirm匹配.ant-modal-wrap .ant-btn-primary:visible)
            self._click_visible_confirm(timeout=4000)
            self.page.wait_for_timeout(1500)
            self.page.reload()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(800)
            if self.get_rule_count() < count_before:
                return True
            return not self.rule_exists(rule_name)
        except Exception as e:
            print(f"[DEBUG] delete_rule({rule_name}) error: {e}")
            return False

    def disable_rule(self, rule_name: str) -> bool:
        """停用规则(有确认弹窗)"""
        self._click_rule_button(rule_name, "停用")
        self.page.wait_for_timeout(800)
        self._click_visible_confirm(timeout=4000)
        try:
            self.page.wait_for_selector("text=停用成功", timeout=5000)
            return True
        except Exception:
            return self.wait_for_success_message()

    def enable_rule(self, rule_name: str) -> bool:
        """启用规则(行内'启用'按钮)"""
        self._click_rule_button(rule_name, "启用")
        try:
            self.page.wait_for_selector("text=启用成功", timeout=5000)
            return True
        except Exception:
            return self.wait_for_success_message()

    def edit_rule(self, rule_name: str) -> bool:
        """点编辑进入配置页(edit模式, 带id)."""
        clicked = self._click_rule_button(rule_name, "编辑")
        if not clicked:
            return False
        self.page.wait_for_timeout(2500)
        return self.is_on_config_page()

    def copy_rule(self, rule_name: str) -> bool:
        """点复制(进入新增页预填数据)"""
        clicked = self._click_rule_button(rule_name, "复制")
        if not clicked:
            return False
        self.page.wait_for_timeout(2500)
        return self.is_on_config_page()

    # ==================== 列表读取 ====================
    def rule_exists(self, rule_name: str) -> bool:
        """规则是否在列表(div.ant-table-row)"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
            # div行内文本含规则名
            return bool(self.page.evaluate("""(name) => {
                const rows=[...document.querySelectorAll('div.ant-table-row')];
                return rows.some(r=>(r.innerText||'').includes(name));
            }""", rule_name))
        except Exception:
            return False

    def get_rule_count(self) -> int:
        """获取规则总数(从'共 N 条')"""
        try:
            cnt = self.page.evaluate("""() => {
                const m=document.body.innerText.match(/共\\s*(\\d+)\\s*条/);
                return m?parseInt(m[1]):0;
            }""")
            return int(cnt or 0)
        except Exception:
            return 0

    def get_rule_names(self) -> List[str]:
        """获取所有规则名称(div行第一个文本)"""
        try:
            return self.page.evaluate("""() => {
                const rows=[...document.querySelectorAll('div.ant-table-row')];
                return rows.map(r=>{
                    const txt=(r.innerText||'').trim();
                    return txt.split(/\\s|\\n/)[0]||'';
                }).filter(t=>t);
            }""")
        except Exception:
            return []

    def is_rule_enabled(self, rule_name: str) -> bool:
        """规则是否启用(div行内有'停用'按钮=已启用)"""
        try:
            return bool(self.page.evaluate("""(name) => {
                const rows=[...document.querySelectorAll('div.ant-table-row')];
                const row=rows.find(r=>(r.innerText||'').includes(name));
                if(!row) return false;
                return [...row.querySelectorAll('button')].some(b=>(b.textContent||'').trim()==='停用');
            }""", rule_name))
        except Exception:
            return False

    # ==================== 清理 ====================
    def clean_test_rules(self, prefix: str = "acl_t_") -> int:
        """前端删除prefix开头的规则: 优先批量(选中所有prefix行+batch_delete, 参考VLAN), 残留则逐条兜底.
        只选中prefix行(不全选), 避免误删用户已有ACL规则."""
        # 1. 批量: 选中所有prefix行(select_rule多选不互斥) + batch_delete
        try:
            names = self.page.evaluate("""(pfx) => {
                const rows=[...document.querySelectorAll('div.ant-table-row')];
                const found=[];
                for(const r of rows){
                    const txt=(r.innerText||'').trim();
                    const first=txt.split(/\\s|\\n/)[0]||'';
                    if(first.startsWith(pfx)) found.push(first);
                }
                return found;
            }""", prefix)
            if names:
                for nm in names:
                    try:
                        self.select_rule(nm)
                    except Exception:
                        pass
                self.page.wait_for_timeout(600)
                if self._wait_selection_active(timeout=2000):
                    self.batch_delete()
                    self.page.wait_for_timeout(2000)
        except Exception:
            pass
        # 2. 逐条兜底(批量后仍有残留或批量未生效时)
        cnt = 0
        for _ in range(50):
            try:
                names = self.page.evaluate("""(pfx) => {
                    const rows=[...document.querySelectorAll('div.ant-table-row')];
                    const found=[];
                    for(const r of rows){
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
