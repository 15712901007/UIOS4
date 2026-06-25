"""
VPN客户端页面基类

网络配置→内外网设置→VPN客户端 tab 下6个子模块(PPTP/L2TP/OpenVPN/IPSec VPN/IKEv2/WireGuard)共用。
继承 IkuaiTablePage 获取通用表格CRUD(行内编辑/停用/删除、批量、搜索、导入导出)。

实测UI特征(2026-06-25):
- 入口URL: /login#/networkConfiguration/internalAndExternalNetworkSettings
- 顶部第3个tab"VPN客户端" → 6个子tab(PPTP/L2TP/OpenVPN/IPSec VPN/IKEv2/IPSec/WireGuard)
- 子tab切换不改hash(组件内state), 用JS精确文字点击
- 添加URL: .../vpnClient/{TYPE}/add (TYPE见各模块ADD_URL_TYPE常量)
- 工具栏: 添加/导入/导出/帮助; 搜索框placeholder="请输入搜索内容"
- 行内按钮: 编辑/停用(启用)/删除; 底部批量栏(div.footer): 启用/停用/删除
- 表格首列为checkbox, 第2列为拨号名称(name, 规则标识)
- 无segmented筛选器(区别于端口映射)
- 表单字段用React, fill()不触发onChange → 用原生setter(HTMLInputElement/TextAreaElement)
- 行内/底部按钮操作直接复用IkuaiTablePage(_click_rule_button/select_all_rules/batch_*/search_rule)
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List


class VpnClientBasePage(IkuaiTablePage):
    """VPN客户端6子模块基类, 子类设置SUBTAB/ADD_URL_TYPE并实现add_rule"""

    VPN_URL = "/login#/networkConfiguration/internalAndExternalNetworkSettings"
    SUBTAB = ""          # 子类设置: "PPTP"/"L2TP"/"OpenVPN"/"IPSec VPN"/"IKEv2/IPSec"/"WireGuard"
    ADD_URL_TYPE = ""    # 子类设置: 路由TYPE(PPTP/L2TP/openvpn/IPestVPN/IKEv2IPSec/WireGuard)
    NAME_PREFIX = ""     # 拨号名称前缀(pptp/l2tp/ovpn/ipsec/iked/wg, 部分模块接口名需固定前缀)

    # ==================== 导航 ====================

    def navigate_to_module(self):
        """导航到本模块列表(内外网设置→VPN客户端 tab→子tab)"""
        self.page.goto(f"{self.base_url}{self.VPN_URL}")
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(800)
        self._click_tab("VPN客户端")
        self.page.wait_for_timeout(800)
        if self.SUBTAB:
            self._click_tab(self.SUBTAB)
            self.page.wait_for_timeout(800)
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页返回列表"""
        return self.navigate_to_module()

    def _click_tab(self, name: str) -> bool:
        """精确文字匹配点击tab(VPN客户端/PPTP子tab等, 用JS避开get_by_role子串匹配)"""
        try:
            return self.page.evaluate("""(name) => {
                let clicked = false;
                document.querySelectorAll('.ant-tabs-tab, [role="tab"], .ant-segmented-item').forEach(el => {
                    if (el.textContent.trim() === name && !clicked) { el.click(); clicked = true; }
                });
                return clicked;
            }""", name)
        except Exception:
            return False

    # ==================== 表单填写helper(React原生setter) ====================

    def _set_input(self, elem_id: str, value: str) -> bool:
        """填写input(React原生setter触发onChange, 避开fill不触发问题)"""
        try:
            inp = self.page.locator(f'#{elem_id}')
            if inp.count() == 0:
                return False
            el = inp.first
            el.click()
            self.page.wait_for_timeout(100)
            el.evaluate("""(el, val) => {
                const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                setter.call(el, val);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
            }""", value)
            self.page.wait_for_timeout(150)
            return True
        except Exception as e:
            print(f"[DEBUG] _set_input({elem_id}) 失败: {e}")
            return False

    def _set_textarea(self, elem_id: str, value: str) -> bool:
        """填写textarea(CA证书/子网等, React原生setter)"""
        try:
            ta = self.page.locator(f'#{elem_id}')
            if ta.count() == 0:
                return False
            ta.first.evaluate("""(el, val) => {
                const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
                setter.call(el, val);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
            }""", value)
            self.page.wait_for_timeout(200)
            return True
        except Exception as e:
            print(f"[DEBUG] _set_textarea({elem_id}) 失败: {e}")
            return False

    def _find_form_item_by_label(self, label_text: str, index: int = 0):
        """通过label文字查找第N个ant-form-item"""
        items = self.page.locator('.ant-form-item')
        count = 0
        for i in range(items.count()):
            item = items.nth(i)
            label = item.locator('.ant-form-item-label')
            if label.count() > 0 and label_text in label.first.text_content():
                if count == index:
                    return item
                count += 1
        return None

    def _select_field(self, label_text: str, option_text: str) -> bool:
        """选择下拉字段(按label找form-item→点开select→选option, 如认证方式/线路/加密)"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
            form_item = self._find_form_item_by_label(label_text)
            if form_item is None:
                return False
            cur = form_item.locator('.ant-select-selection-item')
            if cur.count() > 0 and cur.first.text_content().strip() == option_text:
                return True
            sel = form_item.locator('.ant-select-selector')
            if sel.count() > 0:
                sel.first.click(force=True)
                self.page.wait_for_timeout(700)
            return self._select_dropdown_option(option_text)
        except Exception as e:
            print(f"[DEBUG] _select_field({label_text},{option_text}) 失败: {e}")
            return False

    def _select_dropdown_option(self, option_text: str) -> bool:
        """在已打开的下拉框中选择选项(title属性优先, JS文字精确匹配兜底)"""
        try:
            opt = self.page.locator(f'.ant-select-item-option[title="{option_text}"]')
            for i in range(opt.count()):
                if opt.nth(i).is_visible():
                    opt.nth(i).click()
                    self.page.wait_for_timeout(400)
                    return True
        except Exception:
            pass
        try:
            clicked = self.page.evaluate("""(text) => {
                const dropdowns = document.querySelectorAll('.ant-select-dropdown');
                for (let i = dropdowns.length - 1; i >= 0; i--) {
                    const dd = dropdowns[i];
                    if (dd.offsetHeight > 0 && dd.offsetWidth > 0) {
                        const items = dd.querySelectorAll('.ant-select-item');
                        for (const item of items) {
                            if (item.textContent.trim() === text) { item.click(); return true; }
                        }
                    }
                }
                return false;
            }""", option_text)
            if clicked:
                self.page.wait_for_timeout(400)
                return True
        except Exception:
            pass
        self.page.keyboard.press("Escape")
        return False

    def _set_checkbox(self, label_text: str, check: bool = True) -> bool:
        """勾选/取消checkbox(定时重拨/LZO压缩/允许压缩/服务器路由推送等)"""
        try:
            form_item = self._find_form_item_by_label(label_text)
            if form_item is None:
                return False
            cb = form_item.locator('input[type="checkbox"]')
            if cb.count() > 0:
                if cb.first.is_checked() != check:
                    cb.first.click()
                    self.page.wait_for_timeout(200)
                return True
        except Exception:
            pass
        return False

    # ==================== 列表查询 ====================

    def get_rule_list(self) -> List[str]:
        """获取所有规则拨号名称(name)列表

        取每行第一个非空、非操作列的cell作为name。
        WireGuard列表前两列为空(checkbox+状态图标), name在cell[2];
        其他模块(PPTP/L2TP/OpenVPN/IPSec/IKE)name在cell[1]。智能取第一个有效cell兼容全部。
        """
        try:
            return self.page.evaluate(r"""() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                const opKeywords = ['编辑','删除','停用','启用','隧道','复制','添加'];
                for (const row of rows) {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    for (const c of cells) {
                        const t = c.textContent.replace(/\s+/g, '').trim();
                        if (!t || t === '暂无内容') continue;
                        if (opKeywords.some(k => t.includes(k))) continue;
                        result.push(t);
                        break;
                    }
                }
                return result;
            }""") or []
        except Exception:
            return []

    def get_rule_count(self) -> int:
        return len(self.get_rule_list())

    # ==================== 添加表单通用流程 ====================

    def _wait_add_form(self, timeout: int = 10000):
        """等待添加表单加载(name输入框出现)"""
        try:
            self.page.wait_for_selector('#name', timeout=timeout)
        except Exception:
            try:
                self.page.wait_for_load_state("networkidle")
            except Exception:
                pass
            self.page.wait_for_timeout(1000)

    def _check_form_errors(self) -> List[str]:
        """检查表单错误(ant-form-item-explain-error)"""
        try:
            return self.page.evaluate("""() => {
                const errors = [];
                document.querySelectorAll('.ant-form-item-explain-error, .ant-form-item-explain').forEach(el => {
                    const t = el.textContent.trim();
                    if (t) errors.push(t);
                });
                return errors;
            }""") or []
        except Exception:
            return []

    def _save_and_verify(self) -> bool:
        """点保存并校验: 检查表单错误+URL跳转+成功消息, 失败时取消回列表"""
        self.click_save()
        self.page.wait_for_timeout(1500)
        if self._check_form_errors():
            print(f"  [add_rule] 表单错误: {self._check_form_errors()}")
            try:
                self.click_cancel()
                self.navigate_back_to_list()
            except Exception:
                pass
            return False
        if "/add" in self.page.url or "/edit" in self.page.url:
            try:
                self.click_cancel()
                self.navigate_back_to_list()
            except Exception:
                pass
            return False
        success = self.wait_for_success_message(timeout=4000)
        self.page.wait_for_timeout(300)
        self.navigate_back_to_list()
        self.page.wait_for_timeout(400)
        return success

    def add_rule(self, name: str, **kwargs) -> bool:
        """子类必须实现: 填写各字段后调用 self._save_and_verify()"""
        raise NotImplementedError("子类必须实现add_rule")

    # ==================== 编辑/复制/异常输入(通用, 基于elem_id) ====================

    def _is_textarea(self, elem_id: str) -> bool:
        try:
            el = self.page.locator(f'#{elem_id}')
            return el.count() > 0 and el.first.evaluate("e => e.tagName") == "TEXTAREA"
        except Exception:
            return False

    def edit_rule(self, old_name: str, field_updates: dict = None, new_name: str = None) -> bool:
        """编辑规则: 点编辑→按{elem_id:value}改字段→保存

        Args:
            old_name: 原拨号名称
            field_updates: {elem_id: value} 要修改的input/textarea字段
            new_name: 改名称(等价field_updates={'name':new_name})
        """
        try:
            if not self._click_rule_button(old_name, "编辑"):
                print(f"[WARN] 编辑按钮未找到: {old_name}")
                return False
            self.page.wait_for_timeout(1500)
            self._wait_add_form(timeout=8000)
            updates = dict(field_updates or {})
            if new_name:
                updates['name'] = new_name
            for fid, val in updates.items():
                if self._is_textarea(fid):
                    self._set_textarea(fid, val)
                else:
                    self._set_input(fid, val)
            self.click_save()
            self.page.wait_for_timeout(1500)
            if self._check_form_errors() or "/edit" in self.page.url:
                try:
                    self.click_cancel()
                    self.navigate_back_to_list()
                except Exception:
                    pass
                return False
            ok = self.wait_for_success_message(timeout=4000)
            self.page.wait_for_timeout(300)
            self.navigate_back_to_list()
            return ok
        except Exception as e:
            print(f"[ERROR] 编辑失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    def copy_rule(self, rule_name: str, new_name: str) -> bool:
        """复制规则(点复制→进入新增页预填→改name→保存)"""
        try:
            if not self._click_rule_button(rule_name, "复制"):
                print(f"[WARN] 复制按钮未找到: {rule_name}")
                return False
            self.page.wait_for_timeout(1500)
            self._wait_add_form(timeout=8000)
            self._set_input('name', new_name)
            self.click_save()
            self.page.wait_for_timeout(1500)
            if self._check_form_errors() or "/add" in self.page.url:
                try:
                    self.click_cancel()
                    self.navigate_back_to_list()
                except Exception:
                    pass
                return False
            ok = self.wait_for_success_message(timeout=4000)
            self.navigate_back_to_list()
            return ok
        except Exception as e:
            print(f"[ERROR] 复制失败: {e}")
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return False

    def try_add_rule_invalid(self, fields: dict = None, expect_fail: bool = True) -> dict:
        """尝试添加无效规则测必填/格式校验(只填提供的字段, 测必填拦截)

        Args:
            fields: {elem_id: value} 要填的字段, 不填的留空测必填
        Returns:
            {"success": bool, "error_message": str} success=True表示被正确拦截
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1000)
            self._wait_add_form(timeout=8000)
            for fid, val in (fields or {}).items():
                if self._is_textarea(fid):
                    self._set_textarea(fid, val)
                else:
                    self._set_input(fid, val)
            self.click_save()
            self.page.wait_for_timeout(1200)
            err_el = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if err_el.count() > 0:
                msg = err_el.first.text_content()
                if expect_fail:
                    try:
                        self.click_cancel()
                        self.navigate_back_to_list()
                    except Exception:
                        pass
                    return {"success": True, "error_message": msg}
            still = "/add" in self.page.url or "/edit" in self.page.url
            if expect_fail and still:
                try:
                    self.click_cancel()
                    self.navigate_back_to_list()
                except Exception:
                    pass
                return {"success": True, "error_message": "保存被拒绝(前端/后端校验)"}
            if expect_fail:
                try:
                    self.click_cancel()
                    self.navigate_back_to_list()
                except Exception:
                    pass
                return {"success": False, "error_message": ""}
            return {"success": True, "error_message": ""}
        except Exception as e:
            try:
                self.navigate_back_to_list()
            except Exception:
                pass
            return {"success": False, "error_message": str(e)}
