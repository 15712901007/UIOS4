"""
连接数限制页面类

安全中心 > 连接数限制
URL: 列表 /login#/securityCenter/connectionLimit
     配置 /login#/securityCenter/connectionLimit/add (add; edit点行"编辑"按钮进入, id经React state传不在URL)

页面特点 (2026-07-02 Playwright+SSH探查, 复用ACL的AclPage通用方法):
- 列表表格 div.ant-table-row(虚拟滚动); 行操作 编辑/停用(启用)/复制/删除; 工具栏 添加/导入/导出/帮助
- 配置页字段: 名称*/内网地址(源, 点区域"添加"按钮→新增空IP输入行→行type IP, 同ACL)/协议*(任意tcp/udp/icmp)/连接数*(spinbutton, 默认1000)/外网端口(端口分组, 协议tcp/udp后才出现, 需预建路由对象)/生效时间/备注
- 比ACL简单: 无动作(固定DROP超限)/方向/连接方向匹配/优先级/目的地址/反向匹配

继承AclPage复用: _select_by_label/fill_name/set_protocol/fill_remark/click_save/save_and_wait/
    _click_addr_area_button/_type_addr_row/edit_rule/disable_rule/enable_rule/delete_rule/copy_rule/clean_test_rules 等.

后端机制(conn_limit.sh):
- conn_limit表: src_addr/dst_port/time明文JSON; protocol any/tcp/udp/icmp; limits(连接数默认1000); enabled yes/no
- iptables **raw表CONNLIMIT链**(FORWARD第3条引用): -m peerconns --peerconns-above {limits} -j DROP [-m set --match-set conn_limit_src_{id} src]
  ⚠️conn_limit规则无--comment标记(ACL有), 用 match-set conn_limit_src_{id} + #conns > {limits} 定位
- ipset: conn_limit_src_{id}(源地址list:set) / conn_limit_dport_{id} / conn_limit_time_{id}
"""
from typing import Optional, List
from playwright.sync_api import Page
from pages.security.acl_page import AclPage


class ConnLimitPage(AclPage):
    """连接数限制页面操作类, 继承AclPage复用通用方法(select/地址添加/CRUD/复制/导入导出等)"""

    MODULE_NAME = "conn_limit"
    LIST_URL = "/login#/securityCenter/connectionLimit"
    CONFIG_URL = "/login#/securityCenter/connectionLimit/add"

    # 连接数限制协议选项(any/tcp/udp/icmp, 无gre/tcp+udp)
    CONN_PROTO_UI = {"any": "任意", "tcp": "tcp", "udp": "udp", "icmp": "icmp"}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================
    def navigate_to_conn_limit(self):
        """导航到连接数限制列表页"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2500)
        return self

    def is_on_config_page(self) -> bool:
        """是否在配置页(add/edit)"""
        try:
            return "connectionLimit" in self.page.url and \
                   self.page.get_by_placeholder("请输入名称").count() > 0
        except Exception:
            return "connectionLimit" in self.page.url

    def open_add_page(self) -> bool:
        """直接goto配置页进入新增模式(先回列表清SPA残留, 同ACL)"""
        try:
            self._dismiss_all_modals()
        except Exception:
            pass
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
        return self.is_on_config_page()

    # ==================== 内网地址区域(覆盖AclPage的"源地址"边界) ====================
    def _mark_area_block(self, area: str) -> bool:
        """内网地址区域定位. area='内网地址', 边界到'协议'前(连接数限制配置页: 内网地址→协议→连接数)."""
        try:
            return bool(self.page.evaluate("""(area) => {
                const all=[...document.querySelectorAll('*')];
                const label=all.find(e=>e.offsetParent!==null && (e.textContent||'').replace(/\\s+/g,'').trim()===area);
                if(!label) return false;
                let block=label.parentElement;
                if(!block) return false;
                const stop='协议';
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
            print(f"[DEBUG] ConnLimit._mark_area_block({area}) error: {e}")
            return False

    def add_src_address(self, ip: str) -> bool:
        """内网地址添加一个IP: 点'内网地址'区域'添加'按钮(新增空IP行) + 在行type IP.
        支持单IP/网段CIDR/IP段. 多次调用追加多行."""
        if not self._click_addr_area_button("内网地址", "添加"):
            return False
        self.page.wait_for_timeout(700)
        return self._type_addr_row("内网地址", ip)

    # ==================== 连接数(连接数限制特有) ====================
    def set_limits(self, limits: int = 1000) -> bool:
        """设连接数(spinbutton placeholder=请输入连接数, 默认1000)"""
        try:
            inp = self.page.get_by_placeholder("请输入连接数")
            if inp.count() == 0:
                return False
            inp.first.click()
            inp.first.press("Control+a")
            inp.first.type(str(limits), delay=40)
            return True
        except Exception as e:
            print(f"[DEBUG] set_limits error: {e}")
            return False

    def set_protocol(self, protocol: str = "any") -> bool:
        """设协议. protocol: any/tcp/udp/icmp (覆盖AclPage, 连接数限制无gre/tcp+udp)"""
        ui = self.CONN_PROTO_UI.get(protocol, protocol)
        return self._select_by_label("协议", ui)

    # ==================== 完整添加流程 ====================
    def add_rule(self, name: str, protocol: str = "any", src_addrs: list = None,
                 limits: int = 1000, dst_port: str = "", remark: str = "") -> dict:
        """添加连接数限制规则完整流程. 返回 {success, error}.
        src_addrs: 内网地址IP列表(单IP/网段/段); limits: 连接数(默认1000); dst_port: 外网端口(需预建端口分组, 超范围一般不设)."""
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            self.fill_name(name)
            if protocol and protocol != "any":
                self.set_protocol(protocol)
            if src_addrs:
                for ip in src_addrs:
                    self.add_src_address(ip)
            self.set_limits(limits)
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

    def try_add_rule_invalid(self, name: str = "", illegal_src: str = "",
                             illegal_limits: str = "") -> dict:
        """异常输入测试: 空名称/非法IP/非法连接数, 验证前端拦截(保存被阻止=blocked=True)"""
        result = {"success": False, "error": "", "blocked": False}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            if name:
                self.fill_name(name)
            if illegal_src:
                self.add_src_address(illegal_src)
            if illegal_limits:
                self.set_limits(illegal_limits) if isinstance(illegal_limits, int) else None
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

    # ==================== 列表读取(覆盖, div.ant-table-row) ====================
    def rule_exists(self, rule_name: str) -> bool:
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
            return bool(self.page.evaluate("""(name) => {
                const rows=[...document.querySelectorAll('div.ant-table-row')];
                return rows.some(r=>(r.innerText||'').includes(name));
            }""", rule_name))
        except Exception:
            return False

    def get_rule_count(self) -> int:
        try:
            cnt = self.page.evaluate("""() => {
                const m=document.body.innerText.match(/共\\s*(\\d+)\\s*条/);
                return m?parseInt(m[1]):0;
            }""")
            return int(cnt or 0)
        except Exception:
            return 0

    def clean_test_rules(self, prefix: str = "cl_t_") -> int:
        """前端逐条删除prefix开头的规则(兜底清理)"""
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
