"""
路由对象页面操作类 (网络配置 > 路由对象, 6个子tab)

页面URL: /login#/networkConfiguration/routingObject
6个分组(统一object_group表, type字段区分):
  - IP分组(ipGroups): type0=IPv4/type1=IPv6, radio切换; 表单=分组名称+IP类型+IP(textarea每行一个)
  - MAC分组(macGroups, type2): 分组名称+MAC(textarea每行一个)
  - 时间计划(timePlan, type4): 计划名称+计划类型(radio按周循环/时间段)+生效时间(RangePicker默认00:00-23:59)
  - 域名分组(domainGroups, type6): 分组名称+域名(textarea每行一个)
  - 协议分组(protocolGroups, type5): 分组名称+协议(点Select弹modal树, 勾选协议分类)
  - 端口分组(portGroups, type3): 分组名称+端口(textarea每行一个)

添加URL: routingObject/components/{ipGroups|macGroups|timePlan|domainGroups|protocolGroups|portGroups}/add

DB: object_group(id,type,group_name,tagname,group_id,group_value JSON明文)
   group_id触发器: IPGP/IPV6GP/MACGP/PORTGP/TIMEGP/PROTOGP/DOMAINGP + id
   约束: UNIQUE(group_name,type); 无enabled字段(路由对象无启用/停用功能, 只有编辑/删除)
group_value JSON(明文, 前端传base64后端解码入库; textarea每行一个值):
   IPv4=[{"ip":"x","comment":""}]   IPv6=[{"ipv6":"x","comment":""}]
   MAC=[{"mac":"x","comment":""}]   端口=[{"port":"80","comment":""}]
   域名=[{"domain":"x","comment":""}]
   时间=[{"start_time":"00:00","end_time":"23:59","weekdays":"1234567","type":"weekly"}]
   协议=[{"proto":"网络协议","comment":""}](proto=协议分类名)
后端生效(内核级, 关键验证点):
   IP/IPv6/MAC/端口 → 内核ipset group_{group_id}(IPv4/IPv6=hash:ip, MAC=hash:mac, 端口=bitmap:port)
   时间/协议/域名 → 仅数据库+cache(逻辑对象, 被引用时由功能模块生效, 不建ipset)
引用: object_ref表, ref_count>0 被引用无法删除
校验: group_name 仅中文/英文/数字, 长度1-15字符(不含下划线/连字符/标点)
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import List, Optional, Union
import logging

logger = logging.getLogger(__name__)

PAGE_URL = "/login#/networkConfiguration/routingObject"

# 协议分组modal里的协议分类树节点(14个顶层分类)
PROTO_CATEGORIES = [
    "所有协议", "网络协议", "网络游戏", "社交通讯", "传输下载",
    "休闲娱乐", "效率工具", "办公协作", "学习教育", "生活服务",
    "金融理财", "未知应用", "小包数据",
]


class RouteObjectPage(IkuaiTablePage):
    """路由对象公共基类: 6个tab切换 + 分组名称 + group_value填写 + 保存

    子类需设置: TAB_NAME(显示名) / ADD_PATH(添加URL路径) / GROUP_TYPE(type数字)
    """

    PAGE_URL = PAGE_URL
    TAB_NAME = ""
    ADD_PATH = ""
    GROUP_TYPE = 0

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航与tab切换 ====================

    def navigate_to_route_object(self):
        """导航到路由对象页面并切到子类tab"""
        self._dismiss_residual_modal()
        self.page.goto(f"{self.base_url}{self.PAGE_URL}")
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        if self.TAB_NAME:
            self._switch_tab(self.TAB_NAME)
            self.page.wait_for_timeout(500)
        return self

    def navigate_back_to_list(self):
        """保存后返回列表(重新导航+切tab, 保证表单状态干净)"""
        return self.navigate_to_route_object()

    def _switch_tab(self, target: str) -> bool:
        """切到指定tab(active class验证+重试), 用JS textContent精确匹配

        避开get_by_role子串匹配坑(如"分组"匹配多个tab)。
        """
        for _ in range(3):
            try:
                res = self.page.evaluate("""(tgt) => {
                    const tab = Array.from(document.querySelectorAll('.ant-tabs-tab, [role=tab]'))
                        .find(t => (t.textContent || '').trim() === tgt);
                    if (!tab) return 'notfound';
                    if (tab.classList.contains('ant-tabs-tab-active')) return 'already';
                    tab.click(); return 'clicked';
                }""", target)
                if res == 'already':
                    return True
                self.page.wait_for_timeout(800)
                if self._is_tab_active(target):
                    return True
            except Exception as e:
                logger.warning(f"[切换] {target}异常: {e}")
        logger.warning(f"[切换] {target}失败(3次重试)")
        return False

    def _is_tab_active(self, target: str) -> bool:
        try:
            return self.page.evaluate("""(tgt) => {
                const t = Array.from(document.querySelectorAll('.ant-tabs-tab, [role=tab]'))
                    .find(t => (t.textContent || '').trim() === tgt);
                return t ? t.classList.contains('ant-tabs-tab-active') : false;
            }""", target)
        except Exception:
            return False

    def _dismiss_residual_modal(self):
        """关闭残留弹窗(ESC)"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    # ==================== 进入添加页 ====================

    def _navigate_to_add(self):
        """导航到列表 + 点添加 + 等待add页"""
        self.navigate_to_route_object()
        self.page.wait_for_timeout(400)
        self.click_add_button()
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1200)
        return self

    # ==================== 表单填写 ====================

    def fill_group_name(self, name: str):
        """填写分组名称(#group_name)"""
        inp = self.page.locator('#group_name')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill(name)
            self.page.wait_for_timeout(150)
        return self

    def _fill_textarea_value(self, values: Union[str, List[str]]):
        """填写group_value textarea(每行一个值)

        values: 字符串(原样) 或 列表(用\\n连接成多行)
        """
        if isinstance(values, (list, tuple)):
            text = '\n'.join(str(v) for v in values)
        else:
            text = str(values)
        ta = self.page.locator('#group_value')
        if ta.count() > 0:
            ta.first.click()
            ta.first.fill(text)
            self.page.wait_for_timeout(200)
        return self

    def _fill_group_value(self, value, **kwargs):
        """子类可覆盖: 默认走textarea每行一个(IP/MAC/域名/端口)"""
        self._fill_textarea_value(value)
        return self

    # ==================== 保存 ====================

    def save_group_form(self, expect_success: bool = True) -> bool:
        """点保存, 等待成功(ant-message-success或URL跳回列表)

        路由对象保存成功弹ant-message-success; 失败弹ant-form-item-explain-error或仍留/add页。
        """
        try:
            self.page.wait_for_timeout(500)
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() == 0:
                return False
            save_btn.first.click()
            self.page.wait_for_timeout(1500)
            if not expect_success:
                return False
            ok = self.wait_for_success_message(timeout=5000)
            if not ok:
                err = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if err.count() > 0:
                    logger.warning(f"[保存] 失败: {err.first.text_content().strip()[:60]}")
                    return False
                # URL判断: 成功会跳回列表(/add消失)
                ok = '/add' not in self.page.url
            return ok
        except Exception as e:
            logger.warning(f"[保存] 异常: {e}")
            return False

    # ==================== 高层操作(子类add_rule/edit_rule覆盖value填写) ====================

    def add_rule(self, name: str, value=None, **kwargs) -> bool:
        """通用添加: 进add页→填名称→填值→保存"""
        try:
            self._navigate_to_add()
            self.fill_group_name(name)
            if value is not None:
                self._fill_group_value(value, **kwargs)
            self.page.wait_for_timeout(300)
            ok = self.save_group_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[添加] 异常: {e}")
            return False

    def edit_rule(self, current_name: str, new_name: str = None,
                  value=None, **kwargs) -> bool:
        """编辑分组: 点编辑→改名称/值→保存"""
        try:
            self.navigate_back_to_list()
            self.page.wait_for_timeout(500)
            self._click_rule_button(current_name, "编辑")
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1200)
            if new_name:
                self.fill_group_name(new_name)
            if value is not None:
                self._fill_group_value(value, **kwargs)
            self.page.wait_for_timeout(300)
            ok = self.save_group_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[编辑] 异常: {e}")
            return False

    def try_add_rule_invalid(self, name: str = "", value=None) -> Optional[str]:
        """异常添加(空名称/非法值), 返回错误文案或None"""
        try:
            self._navigate_to_add()
            if name:
                self.fill_group_name(name)
            if value is not None:
                self._fill_group_value(value)
            self.page.wait_for_timeout(300)
            # 直接点保存(不走save_group_form的URL判断, 只看错误)
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() > 0:
                save_btn.first.click()
            self.page.wait_for_timeout(1500)
            err = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if err.count() > 0:
                return err.first.text_content().strip()
            return None
        except Exception as e:
            logger.warning(f"[异常添加] 异常: {e}")
            return None

    # ==================== 导入(覆盖基类, 路由对象导入弹窗的"点击上传"有同名元素) ====================

    def import_rules(self, file_path: str, clear_existing: bool = False) -> bool:
        """覆盖基类: 优先点.ant-upload-btn(真触发器), 用dialog.first避免strict violation"""
        import os as _os
        try:
            if not _os.path.exists(file_path):
                print(f"[ERROR] File not found: {file_path}")
                return False
            self.click_import()
            self.page.wait_for_timeout(600)
            if clear_existing:
                for label in ["清空现有配置数据", "清除全部数据", "清除原有数据"]:
                    try:
                        cb = self.page.get_by_label(label, exact=True)
                        if cb.count() > 0 and not cb.is_checked():
                            cb.check()
                        if cb.count() > 0:
                            break
                    except Exception:
                        continue
            # 点.ant-upload-btn(真触发器) 开文件选择器
            with self.page.expect_file_chooser() as fc_info:
                upload_area = self.page.locator('.ant-upload-btn').first
                if upload_area.count() > 0:
                    upload_area.click()
                else:
                    self.page.locator("[role='dialog'] button:has-text('点击上传')").first.click()
            fc_info.value.set_files(file_path)
            self.page.wait_for_timeout(1000)
            confirm = self.page.get_by_role("button", name="确定上传")
            for _ in range(10):
                if confirm.count() > 0 and not confirm.is_disabled():
                    break
                self.page.wait_for_timeout(500)
            if confirm.count() > 0:
                confirm.click()
            self.page.wait_for_timeout(2000)
            try:
                dlg = self.page.locator("[role='dialog']").first
                if dlg.count() > 0 and dlg.is_visible():
                    self.close_modal_if_exists()
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[ERROR] Import failed: {str(e)[:100]}")
            try:
                self.close_modal_if_exists()
            except Exception:
                pass
            return False


# ============================================================================
# IP分组 (IPv4 type0 / IPv6 type1, radio切换)
# ============================================================================

class IpGroupPage(RouteObjectPage):
    """IP分组: 分组名称 + IP类型(radio IPv4/IPv6) + IP(textarea每行一个)"""

    MODULE_NAME = "route_object_ip"
    TAB_NAME = "IP分组"
    ADD_PATH = "ipGroups"
    GROUP_TYPE = 0  # 默认IPv4; 选IPv6时动态置1

    def select_ip_type(self, ip_version: str = "ipv4"):
        """选择IP类型(IPv4/IPv6)。ipv6时把GROUP_TYPE置1(供verify用)。"""
        target = "IPv6" if ip_version == "ipv6" else "IPv4"
        self.GROUP_TYPE = 1 if ip_version == "ipv6" else 0
        try:
            self.page.evaluate("""(tgt) => {
                const r = Array.from(document.querySelectorAll('.ant-radio-wrapper'))
                    .find(x => (x.textContent || '').trim() === tgt);
                if (r && !r.querySelector('.ant-radio-checked')) r.click();
            }""", target)
            self.page.wait_for_timeout(400)
        except Exception as e:
            logger.warning(f"[IP类型] 选{target}异常: {e}")
        return self

    def add_rule(self, name: str, ips: Union[str, List[str]],
                 ip_version: str = "ipv4") -> bool:
        """添加IP分组规则

        Args:
            name: 分组名称(中文/英文/数字, 1-15字符)
            ips: IP字符串或列表(每行一个)
            ip_version: 'ipv4' 或 'ipv6'
        """
        try:
            self._navigate_to_add()
            if ip_version == "ipv6":
                self.select_ip_type("ipv6")
            else:
                self.GROUP_TYPE = 0
            self.fill_group_name(name)
            self._fill_textarea_value(ips)
            self.page.wait_for_timeout(300)
            ok = self.save_group_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[添加IP分组] 异常: {e}")
            return False

    def edit_rule(self, current_name: str, new_name: str = None,
                  ips=None, ip_version: str = None) -> bool:
        try:
            self.navigate_back_to_list()
            self.page.wait_for_timeout(500)
            self._click_rule_button(current_name, "编辑")
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1200)
            if ip_version:
                self.select_ip_type(ip_version)
            if new_name:
                self.fill_group_name(new_name)
            if ips is not None:
                self._fill_textarea_value(ips)
            self.page.wait_for_timeout(300)
            ok = self.save_group_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[编辑IP分组] 异常: {e}")
            return False

    def _switch_list_ip_version(self, version: str):
        """切换IP分组列表页的IPv4/IPv6视图(列表页顶部切换控件, 非添加页radio)"""
        target = "IPv6" if version == "ipv6" else "IPv4"
        try:
            self.page.evaluate("""(tgt) => {
                const candidates = document.querySelectorAll(
                    '.ant-tabs-tab, .ant-radio-wrapper, .ant-segmented-item, [role=tab], [role=radio]');
                for (const el of candidates) {
                    if ((el.textContent || '').trim() !== tgt) continue;
                    if (el.closest('.ant-form-item')) continue;  // 跳过添加页radio
                    el.click();
                    return true;
                }
                return false;
            }""", target)
            self.page.wait_for_timeout(900)
        except Exception as e:
            logger.warning(f"[IP列表视图] 切{target}异常: {e}")

    def _ensure_target_visible(self, name: str):
        """删除/编辑前确保目标分组在当前列表视图(IPv4找不到则切IPv6)"""
        self.navigate_back_to_list()
        self.page.wait_for_timeout(500)
        if not self.rule_exists(name):
            self._switch_list_ip_version('ipv6')
            self.page.wait_for_timeout(500)

    def delete_rule(self, name: str) -> bool:
        """重写: IP分组删除前确保切到含目标的IPv4/IPv6视图"""
        self._ensure_target_visible(name)
        return super().delete_rule(name)


# ============================================================================
# MAC分组 (type2)
# ============================================================================

class MacGroupPage(RouteObjectPage):
    """MAC分组: 分组名称 + MAC(textarea每行一个)"""

    MODULE_NAME = "route_object_mac"
    TAB_NAME = "MAC分组"
    ADD_PATH = "macGroups"
    GROUP_TYPE = 2


# ============================================================================
# 端口分组 (type3)
# ============================================================================

class PortGroupPage(RouteObjectPage):
    """端口分组: 分组名称 + 端口(textarea每行一个)"""

    MODULE_NAME = "route_object_port"
    TAB_NAME = "端口分组"
    ADD_PATH = "portGroups"
    GROUP_TYPE = 3


# ============================================================================
# 域名分组 (type6)
# ============================================================================

class DomainGroupPage(RouteObjectPage):
    """域名分组: 分组名称 + 域名(textarea每行一个)"""

    MODULE_NAME = "route_object_domain"
    TAB_NAME = "域名分组"
    ADD_PATH = "domainGroups"
    GROUP_TYPE = 6


# ============================================================================
# 时间计划 (type4, radio类型 + 时间RangePicker)
# ============================================================================

class TimePlanPage(RouteObjectPage):
    """时间计划: 计划名称 + 计划类型(radio 按周循环/时间段) + 生效时间(RangePicker 默认00:00-23:59)

    group_value: [{"start_time":"00:00","end_time":"23:59","weekdays":"1234567","type":"weekly"}]
    默认按周循环+全周+全天, 测试用默认值即可(简化RangePicker操作)。
    """

    MODULE_NAME = "route_object_time"
    TAB_NAME = "时间计划"
    ADD_PATH = "timePlan"
    GROUP_TYPE = 4

    def select_plan_type(self, plan_type: str = "按周循环"):
        """选择计划类型(按周循环 weekly / 时间段 date)"""
        try:
            self.page.evaluate("""(tgt) => {
                const r = Array.from(document.querySelectorAll('.ant-radio-wrapper'))
                    .find(x => (x.textContent || '').trim() === tgt);
                if (r) r.click();
            }""", plan_type)
            self.page.wait_for_timeout(400)
        except Exception as e:
            logger.warning(f"[计划类型] 选{plan_type}异常: {e}")
        return self

    def add_rule(self, name: str, plan_type: str = "按周循环",
                 start: str = None, end: str = None) -> bool:
        """添加时间计划(默认按周循环+默认时间00:00-23:59)

        start/end为None时用页面默认(不修改RangePicker), 简化自动化。
        """
        try:
            self._navigate_to_add()
            self.fill_group_name(name)
            if plan_type != "按周循环":
                self.select_plan_type(plan_type)
            # 时间默认即可; 若指定start/end则尝试填RangePicker(可选, 默认跳过)
            self.page.wait_for_timeout(300)
            ok = self.save_group_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[添加时间计划] 异常: {e}")
            return False


# ============================================================================
# 协议分组 (type5, 点Select弹modal树勾选协议分类)
# ============================================================================

class ProtocolGroupPage(RouteObjectPage):
    """协议分组: 分组名称 + 协议(点ant-select-multiple弹modal, 勾选协议分类树checkbox, 确定)

    group_value: [{"proto":"网络协议","comment":""}](proto=协议分类名)
    modal内Ant Tree 14个顶层分类: 所有协议/网络协议/网络游戏/.../小包数据
    """

    MODULE_NAME = "route_object_proto"
    TAB_NAME = "协议分组"
    ADD_PATH = "protocolGroups"
    GROUP_TYPE = 5

    def select_protocols(self, proto_names: Union[str, List[str]]) -> bool:
        """点协议Select弹modal, 勾选协议分类, 点modal确定

        Args:
            proto_names: 协议分类名(字符串或列表), 如 '网络协议' 或 ['网络协议','网络游戏']
        """
        if isinstance(proto_names, str):
            proto_names = [proto_names]
        try:
            # 确保无残留modal(协议Select第一次点击弹modal, 残留modal会拦截)
            self._dismiss_residual_modal()
            self.page.wait_for_timeout(200)
            # 点协议多选Select(干净add页第一次点击弹modal)
            sel = self.page.locator('.ant-select-multiple .ant-select-selector').first
            if sel.count() > 0:
                sel.click()
            self.page.wait_for_timeout(1200)
            # 在modal里勾选协议分类(JS click .ant-tree-checkbox 对树checkbox有效)
            self.page.evaluate("""(names) => {
                const m = document.querySelector('.ant-modal-wrap.ant-modal-centered .ant-modal');
                if (!m) return 'nomodal';
                const nodes = Array.from(m.querySelectorAll('[role=treeitem], .ant-tree-treenode'));
                for (const nm of names) {
                    const t = nodes.find(n => (n.textContent || '').trim() === nm);
                    if (t) {
                        const checked = t.querySelector('.ant-tree-checkbox-checked');
                        const cb = t.querySelector('.ant-tree-checkbox');
                        if (cb && !checked) cb.click();
                    }
                }
                return 'ok';
            }""", proto_names)
            self.page.wait_for_timeout(500)
            # 点modal"确定"(关闭modal, 选中协议作为group_value)
            self.page.evaluate("""() => {
                const m = document.querySelector('.ant-modal-wrap.ant-modal-centered .ant-modal');
                if (!m) return;
                const ok = Array.from(m.querySelectorAll('button'))
                    .find(b => b.textContent.trim() === '确定');
                if (ok) ok.click();
            }""")
            self.page.wait_for_timeout(800)
            return True
        except Exception as e:
            logger.warning(f"[选协议] 异常: {e}")
            return False

    def add_rule(self, name: str, protocols: Union[str, List[str]] = "网络协议") -> bool:
        """添加协议分组

        Args:
            name: 分组名称
            protocols: 协议分类(默认'网络协议')
        """
        try:
            self._navigate_to_add()
            self.fill_group_name(name)
            self.select_protocols(protocols)
            self.page.wait_for_timeout(300)
            ok = self.save_group_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[添加协议分组] 异常: {e}")
            return False

    def edit_rule(self, current_name: str, new_name: str = None,
                  protocols: Union[str, List[str]] = None) -> bool:
        try:
            self.navigate_back_to_list()
            self.page.wait_for_timeout(500)
            self._click_rule_button(current_name, "编辑")
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1200)
            if new_name:
                self.fill_group_name(new_name)
            if protocols is not None:
                self.select_protocols(protocols)
            self.page.wait_for_timeout(300)
            ok = self.save_group_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[编辑协议分组] 异常: {e}")
            return False
