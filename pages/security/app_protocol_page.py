"""
应用协议控制页面类 (安全中心 > 应用协议控制)

URL: 列表 /login#/securityCenter/applicationProtocolControl
     配置 /login#/securityCenter/applicationProtocolControlConfig (add/edit共用, edit点行"编辑"进入)

页面特点 (2026-07-07 Playwright+SSH探查):
- 列表表格 div.ant-table-row; 工具栏 添加/导入/导出/帮助 (无批量添加/无设置/无模式切换radio)
- 行操作: 编辑/停用(启用)/删除 (无复制)
- 添加/编辑是独立配置页(路由跳转, 非drawer/modal)
- 协议字段: 点select弹 **dialog"请选择"树形选择器**(非普通dropdown):
  根"所有协议" + 13大类(网络协议/网络游戏/社交通讯/传输下载/休闲娱乐/效率工具/办公协作/
  学习教育/生活服务/金融理财/未知应用/小包数据), 每大类可展开子类(基础协议/远程协议/...)->具体应用.
  点.ant-tree-checkbox勾选+自动展开子节点, 右侧"已选N个"+清空, 确定/取消.
- 源地址/目的地址区域: 同ACL(点"添加"新增IP/MAC行+type), 但区域label下含"IP/MAC设置"+"IP/MAC分组"
- 生效时间: 3 radio(时间计划/按周循环[默认]/时间段), 默认按周循环全天00:00-23:59
- 免费版可用(有添加按钮, 非企业版专属)

后端机制(acl_l7.sh, 专业模式 global_config.parental_mode=0):
- 表 acl_l7 (id/enabled yes|no/tagname unique/comment/prio 0-63默认31/action accept|drop/
  app_proto JSON {custom:[应用名],object:[{gid}]} /src_addr/dst_addr JSON/time 必须"")
- ⚠️不走iptables/ipset! 走 ik_cntl new_tc app_rule add -> ik_core内核new_tc子系统
- app_proto.custom放应用名字符串(非appid), 脚本APPIDS[名]反查; object放分组gid
- time必须空串""(非空JSON致规则inactive永不匹配)
- 验证: ik_summary的App Rules count + ID:<id>规则状态行(active/action/appset/match);
  dpi_cache appid + host_active_apps + conntrack appid + match增量(命中铁证)

继承AclPage复用: fill_name/fill_remark/set_priority/_select_by_label/click_save/save_and_wait(覆写)/
  add_src_address/add_dst_address(复用,_mark_area_block覆写stop边界)/delete_rule/disable_rule/
  enable_rule/edit_rule/rule_exists/get_rule_count/export_rules/import_rules/search_rule等.
"""
from typing import Optional, List
from playwright.sync_api import Page
from pages.security.acl_page import AclPage


class AppProtocolPage(AclPage):
    """应用协议控制页面操作类, 继承AclPage复用通用方法"""

    MODULE_NAME = "app_protocol"
    LIST_URL = "/login#/securityCenter/applicationProtocolControl"
    CONFIG_URL = "/login#/securityCenter/applicationProtocolControlConfig"
    # URL里的配置页关键字(父类硬编码aclRulesConfig, 此处覆写用)
    CONFIG_KEYWORD = "applicationProtocolControlConfig"

    # 协议树13大类(根"所有协议"单独处理)
    PROTOCOL_CATEGORIES = ["所有协议", "网络协议", "网络游戏", "社交通讯", "传输下载",
                           "休闲娱乐", "效率工具", "办公协作", "学习教育",
                           "生活服务", "金融理财", "未知应用", "小包数据"]
    ACTION_UI = {"accept": "允许", "drop": "阻断"}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================
    def navigate_to_app_proto(self):
        """导航到应用协议控制列表页"""
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
            return self.CONFIG_KEYWORD in self.page.url and \
                   self.page.get_by_placeholder("请输入名称").count() > 0
        except Exception:
            return self.CONFIG_KEYWORD in self.page.url

    def is_still_on_config_page(self) -> bool:
        """是否还在配置页(保存被阻止时停留). 覆写父类(父类硬编码aclRulesConfig)."""
        return self.CONFIG_KEYWORD in self.page.url

    def save_and_wait(self, timeout: int = 8000) -> dict:
        """点保存并轮询结果. 覆写父类(父类硬编码"aclRulesConfig"判定离开配置页).
        成功=URL离开配置页且无错误; 失败=停留配置页或有错误提示."""
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

    # ==================== 区域block定位(覆写: 应用协议控制无"进接口", 目的地址后是"优先级") ====================
    def _mark_area_block(self, area: str) -> bool:
        """定位源地址/目的地址区域block并标记data-tmp-area.
        覆写父类stop边界: 源地址stop=目的地址, 目的地址stop=优先级(父类是进接口)."""
        try:
            return bool(self.page.evaluate("""(area) => {
                const all=[...document.querySelectorAll('*')];
                const label=all.find(e=>e.offsetParent!==null && (e.textContent||'').replace(/\\s+/g,'').trim()===area);
                if(!label) return false;
                let block=label.parentElement;
                if(!block) return false;
                const stop = area==='源地址' ? '目的地址' : '优先级';
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

    # ==================== 协议选择(树dialog, 核心新方法) ====================
    def _open_protocol_dialog(self) -> bool:
        """点协议select打开树形选择dialog. 协议是label"协议"的.ant-select(精确匹配避免误中"协议分组").
        点击弹dialog(非普通dropdown)."""
        try:
            found = self.page.evaluate("""() => {
                const norm=s=>(s||'').replace(/[\\s:*：]/g,'');
                const sels=[...document.querySelectorAll('.ant-select')].filter(s=>s.offsetParent!==null);
                function labelOf(sel){
                    let p=sel;
                    for(let d=0;d<6&&p;d++){p=p.parentElement;if(!p)break;const le=p.querySelector('.ant-form-item-label');if(le)return norm(le.textContent);}
                    return '';
                }
                const t=sels.find(s=>labelOf(s)==='协议');
                if(!t) return false;
                t.setAttribute('data-tmp-sel','1'); t.scrollIntoView({block:'center'}); return true;
            }""")
            if not found:
                print("[DEBUG] _open_protocol_dialog: 未定位协议select")
                return False
            self.page.locator("[data-tmp-sel='1']").click()
            self.page.wait_for_timeout(1200)  # dialog渲染
            self.page.evaluate("document.querySelector(\"[data-tmp-sel='1']\")?.removeAttribute('data-tmp-sel')")
            # 确认dialog出现
            has_dlg = self.page.evaluate("""() => {
                return [...document.querySelectorAll('[role="dialog"], .ant-modal')].some(d=>d.offsetParent!==null && /请选择/.test(d.textContent||''));
            }""")
            if not has_dlg:
                print("[DEBUG] _open_protocol_dialog: dialog未出现")
            return bool(has_dlg)
        except Exception as e:
            print(f"[DEBUG] _open_protocol_dialog error: {e}")
            return False

    def _find_protocol_dialog(self):
        """返回当前打开的协议选择dialog元素文本定位辅助. 返回是否有dialog."""
        try:
            return bool(self.page.evaluate("""() => {
                return [...document.querySelectorAll('[role="dialog"], .ant-modal')].some(d=>d.offsetParent!==null && /请选择/.test(d.textContent||''));
            }"""))
        except Exception:
            return False

    def _check_tree_node(self, target: str, exact: bool = True) -> str:
        """在协议dialog树里找文本==target的节点, 标记其.ant-tree-checkbox待勾选.
        exact=True精确匹配title(默认); False包含匹配(兜底). 返回'ok'或错误描述."""
        try:
            return self.page.evaluate("""({tgt, exact}) => {
                const dlg=[...document.querySelectorAll('[role="dialog"], .ant-modal')].filter(d=>d.offsetParent!==null && /请选择/.test(d.textContent||''))[0];
                if(!dlg) return 'no dialog';
                const nodes=[...dlg.querySelectorAll('.ant-tree-treenode, .ant-select-tree-treenode')];
                function titleOf(n){const t=n.querySelector('.ant-tree-title, .ant-select-tree-title');return t?(t.textContent||'').trim():'';}
                let node = exact ? nodes.find(n=>titleOf(n)===tgt) : nodes.find(n=>{const t=titleOf(n);return t.includes(tgt)||tgt.includes(t);});
                if(!node) return 'node not found: '+tgt;
                const cb=node.querySelector('.ant-tree-checkbox, .ant-select-tree-checkbox');
                if(!cb) return 'no checkbox';
                if(cb.className.includes('checked')) return 'already checked';
                cb.setAttribute('data-tmp-cb','1'); cb.scrollIntoView({block:'center'}); return 'ok';
            }""", {"tgt": target, "exact": exact})
        except Exception as e:
            return f"eval error: {e}"

    def _click_tree_checkbox(self) -> bool:
        """Playwright真实click已标记的树节点checkbox(触发React checked+展开子节点)."""
        try:
            self.page.locator("[data-tmp-cb='1']").click()
            self.page.wait_for_timeout(800)
            self.page.evaluate("document.querySelector(\"[data-tmp-cb='1']\")?.removeAttribute('data-tmp-cb')")
            return True
        except Exception as e:
            print(f"[DEBUG] _click_tree_checkbox error: {e}")
            return False

    def _click_dialog_confirm(self) -> bool:
        """点协议dialog"确定"按钮(关闭dialog, 应用选择)."""
        try:
            found = self.page.evaluate("""() => {
                const dlg=[...document.querySelectorAll('[role="dialog"], .ant-modal')].filter(d=>d.offsetParent!==null && /请选择/.test(d.textContent||''))[0];
                if(!dlg) return false;
                const btn=[...dlg.querySelectorAll('button')].find(b=>b.offsetParent!==null && (b.textContent||'').trim()==='确定');
                if(!btn) return false;
                btn.setAttribute('data-ok','1'); return true;
            }""")
            if not found:
                print("[DEBUG] _click_dialog_confirm: 未找到确定按钮")
                return False
            self.page.locator("[data-ok='1']").click()
            self.page.wait_for_timeout(1000)
            self.page.evaluate("document.querySelector(\"[data-ok='1']\")?.removeAttribute('data-ok')")
            return True
        except Exception as e:
            print(f"[DEBUG] _click_dialog_confirm error: {e}")
            return False

    def select_protocol(self, category: str = None, app: str = None) -> bool:
        """选协议(树dialog). 二选一: app=具体应用名(如"百度")优先; 否则category=大类名(如"网络协议"/"休闲娱乐").
        流程: 点协议select开dialog -> 勾选目标树节点checkbox -> 点确定.
        大类节点勾选会自动展开子类(网络协议->基础协议/远程协议/...)."""
        target = app or category
        if not target:
            print("[DEBUG] select_protocol: 未指定category或app")
            return False
        try:
            # 1. 打开dialog
            if not self._open_protocol_dialog():
                return False
            # 2. 勾选目标节点(精确优先, 失败兜底包含匹配)
            st = self._check_tree_node(target, exact=True)
            if st != "ok":
                if st == "already checked":
                    pass  # 已勾选, 跳过click
                else:
                    st2 = self._check_tree_node(target, exact=False)
                    if st2 != "ok" and st2 != "already checked":
                        print(f"[DEBUG] select_protocol: 树节点未找到({target}): {st} / {st2}")
                        self._dismiss_all_modals()
                        return False
                    if st2 == "ok":
                        if not self._click_tree_checkbox():
                            self._dismiss_all_modals()
                            return False
            else:
                if not self._click_tree_checkbox():
                    self._dismiss_all_modals()
                    return False
            self.page.wait_for_timeout(500)
            # 3. 点确定
            if not self._click_dialog_confirm():
                return False
            return True
        except Exception as e:
            print(f"[DEBUG] select_protocol({target}) error: {e}")
            try:
                self._dismiss_all_modals()
            except Exception:
                pass
            return False

    def get_selected_protocols(self) -> List[str]:
        """读取协议select当前已选项(selection-item的title/text). 用于回读校验."""
        try:
            return self.page.evaluate("""() => {
                const norm=s=>(s||'').replace(/[\\s:*：]/g,'');
                const sels=[...document.querySelectorAll('.ant-select')].filter(s=>s.offsetParent!==null);
                function labelOf(sel){let p=sel;for(let d=0;d<6&&p;d++){p=p.parentElement;if(!p)break;const le=p.querySelector('.ant-form-item-label');if(le)return norm(le.textContent);}return '';}
                const t=sels.find(s=>labelOf(s)==='协议');
                if(!t) return [];
                return [...t.querySelectorAll('.ant-select-selection-item')].map(i=>(i.title||i.textContent||'').trim()).filter(x=>x);
            }""")
        except Exception:
            return []

    # ==================== 动作 ====================
    def set_action(self, action: str = "accept") -> bool:
        """设动作. action: accept(允许)/drop(阻断). 复用_select_by_label."""
        ui = self.ACTION_UI.get(action, action)
        return self._select_by_label("动作", ui)

    # ==================== 完整添加流程 ====================
    def add_rule(self, name: str, protocol_category: str = None, protocol_app: str = None,
                 action: str = "accept", src_addrs: list = None, dst_addrs: list = None,
                 prio: int = 31, remark: str = "") -> dict:
        """添加应用协议控制规则. 返回 {success, error}.
        protocol_app优先(具体应用如"百度"); 否则protocol_category(大类如"网络协议").
        action: accept/drop. src_addrs/dst_addrs: IP/MAC列表."""
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            self.fill_name(name)
            # 选协议(必选, 否则保存报错)
            proto_target = protocol_app or protocol_category
            if proto_target:
                if not self.select_protocol(category=protocol_category, app=protocol_app):
                    result["error"] = f"选协议失败({proto_target})"
                    return result
            if action:
                self.set_action(action)
            if prio != 31:
                self.set_priority(prio)
            if src_addrs:
                for ip in src_addrs:
                    self.add_src_address(ip)
            if dst_addrs:
                for ip in dst_addrs:
                    self.add_dst_address(ip)
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

    def try_add_rule_invalid(self, name: str = "", no_protocol: bool = True) -> dict:
        """异常输入测试: 空名称/未选协议, 验证前端拦截(保存被阻止=blocked=True).
        no_protocol=True时不选协议直接保存(应被拦截, 协议是必选)."""
        result = {"success": False, "error": "", "blocked": False}
        try:
            if not self.open_add_page():
                result["error"] = "进入配置页失败"
                return result
            if name:
                self.fill_name(name)
            if not no_protocol:
                # 选一个默认协议(测空名等其他字段时, 协议已选, 只缺被测字段)
                self.select_protocol(category="网络协议")
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

    # ==================== 清理(批量勾选删除, 参考VLAN/IP限速, 非逐条) ====================
    def clean_test_rules(self, prefix: str = "appt_") -> int:
        """批量勾选删除prefix规则(参考VLAN/IP限速批量删除, 非逐条delete_rule).
        select_all(全选当前页)+batch_delete循环, 处理>10分页(reload下一页继续).
        注: select_all选当前页所有行, 应用协议控制列表通常仅测试规则, 安全;
        若混有用户规则请改用prefix逐行勾选(本场景不涉及)."""
        cnt = 0
        for _ in range(20):  # 最多20轮防死循环
            try:
                self.page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            self.page.wait_for_timeout(800)
            names = self.get_rule_names()
            prefix_names = [n for n in names if n.startswith(prefix)]
            if not prefix_names:
                break
            try:
                self.select_all_rules()
                self.page.wait_for_timeout(800)
                self.batch_delete()
                self.page.wait_for_timeout(2000)
                cnt += len(prefix_names)
            except Exception as e:
                print(f"[DEBUG] clean_test_rules批量删除异常: {e}")
                break
            try:
                self.page.reload()
                self.page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            self.page.wait_for_timeout(1000)
        return cnt
