"""
MAC访问控制页面类 (安全中心 > MAC访问控制)

URL: 列表 /login#/securityCenter/macAccessControl, 配置 /login#/securityCenter/macAccessControlConfig
两模式(左上角radio切换): 黑名单模式(global_config.acl_mac=0, 默认)/白名单模式(acl_mac=1)
  - 黑名单: ACL_MAC链 DROP匹配的黑名单MAC(acl_mac_black表)
  - 白名单: ACL_MAC链 RETURN白名单MAC放行+默认DROP非白名单(acl_mac_white表, 白名单有规则才生效)

页面特点 (2026-07-02 Playwright+SSH探查):
- 列表表格 div.ant-table-row; 工具栏 设置/添加/批量添加/导入/导出/帮助; 行操作 编辑/停用(启用)/删除(无复制)
- 配置页字段: 名称*/终端名称/MAC*/周期/备注(无协议/端口/连接数等, 比ACL/连接数限制简单)
- 模式切换: 左上角radio "使用黑名单模式"/"使用白名单模式"(ant-radio-wrapper)

后端机制(acl_mac.sh):
- 表: acl_mac_black/acl_mac_white (id/enabled默认no/tagname unique/comment/time明文JSON/expires/mac小写unique)
- iptables filter表ACL_MAC链(FORWARD第2条引用): 黑名单`-A ACL_MAC -m set --match-set acl_mac_{id} src -j DROP`/白名单`-I ACL_MAC -m set --match-set acl_mac_{id} src -j RETURN`(无--comment, 用acl_mac_{id}+acl_mac_time_{id}定位)
- ipset: acl_mac_{id}(MAC集合list:set, 含_acl_mac_{id})
- 模式: global_config.acl_mac=0黑名单/1白名单
- add按当前模式插acl_mac_${action}表, enabled=yes才下发

继承AclPage复用: fill_name/fill_remark/click_save/save_and_wait/delete_rule/disable_rule/enable_rule/edit_rule/_click_rule_button 等.
"""
from typing import Optional, List
from playwright.sync_api import Page
from pages.security.acl_page import AclPage


class MacAccessControlPage(AclPage):
    """MAC访问控制页面操作类, 继承AclPage复用通用方法"""

    MODULE_NAME = "mac_access_control"
    LIST_URL = "/login#/securityCenter/macAccessControl"
    CONFIG_URL = "/login#/securityCenter/macAccessControlConfig"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================
    def navigate_to_mac_ctrl(self):
        """导航到MAC访问控制列表页"""
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(2500)
        return self

    def is_on_config_page(self) -> bool:
        try:
            return "macAccessControlConfig" in self.page.url and \
                   self.page.get_by_placeholder("请输入名称").count() > 0
        except Exception:
            return "macAccessControlConfig" in self.page.url

    def is_still_on_config_page(self) -> bool:
        return "macAccessControlConfig" in self.page.url

    def open_add_page(self) -> bool:
        """直接goto配置页进入新增模式(先回列表清SPA残留)"""
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

    # ==================== 模式切换(黑名单/白名单, 左上角radio) ====================
    def set_mode(self, mode: str = "black") -> bool:
        """切换模式. mode: 'black'黑名单/'white'白名单. radio渲染需等待(reload后异步), evaluate定位+Playwright真实click."""
        kw = "使用黑名单模式" if mode == "black" else "使用白名单模式"
        try:
            # 等待radio渲染(reload后异步, .ant-radio-wrapper可能延迟)
            for _ in range(15):
                if self.page.locator("label.ant-radio-wrapper").count() > 0:
                    break
                self.page.wait_for_timeout(500)
            # evaluate标记目标radio + Playwright真实click
            found = self.page.evaluate("""(kw) => {
                const r=[...document.querySelectorAll('label.ant-radio-wrapper')].find(e=>e.offsetParent!==null && (e.textContent||'').includes(kw));
                if(r){r.setAttribute('data-tmp-mode','1'); r.scrollIntoView({block:'center'}); return true;}
                return false;
            }""", kw)
            if not found:
                print(f"[DEBUG] set_mode: 未找到radio {kw}")
                return False
            self.page.locator("[data-tmp-mode='1']").click()
            self.page.wait_for_timeout(3000)
            self.page.evaluate("document.querySelector(\"[data-tmp-mode='1']\")?.removeAttribute('data-tmp-mode')")
            return True
        except Exception as e:
            print(f"[DEBUG] set_mode({mode}) error: {e}")
            return False

    def get_current_mode(self) -> str:
        """获取当前模式(从radio checked判断). 返回'black'/'white'/''(未知)"""
        try:
            mode = self.page.evaluate("""() => {
                const r=[...document.querySelectorAll('.ant-radio-wrapper-checked')].filter(e=>e.offsetParent!==null && /名单/.test(e.textContent||'')).map(e=>(e.textContent||'').replace(/\\s+/g,'').trim());
                if(!r.length) return '';
                return r[0].includes('黑') ? 'black' : 'white';
            }""")
            return mode or ""
        except Exception:
            return ""

    # ==================== 配置页字段 ====================
    def fill_mac(self, mac: str) -> bool:
        """填MAC(placeholder=请输入MAC)"""
        try:
            inp = self.page.get_by_placeholder("请输入MAC")
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

    # ==================== 完整添加流程 ====================
    def add_rule(self, name: str, mac: str, termname: str = "", remark: str = "") -> dict:
        """添加MAC访问控制规则. 返回 {success, error}.
        按当前模式插入对应表(acl_mac_black/white)."""
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            self.fill_name(name)
            self.fill_mac(mac)
            if termname:
                self.fill_termname(termname)
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

    def try_add_rule_invalid(self, name: str = "", mac: str = "") -> dict:
        """异常输入测试: 空名称/非法MAC, 验证前端拦截"""
        result = {"success": False, "error": "", "blocked": False}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            if name:
                self.fill_name(name)
            if mac:
                self.fill_mac(mac)
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

    def clean_test_rules(self, prefix: str = "mac_t_") -> int:
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
