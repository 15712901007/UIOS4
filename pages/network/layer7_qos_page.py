"""
手动流控策略页面操作类(手动模式)

网络配置 > 智能流控 > 流控策略设置 tab(手动模式, stream_ctl_mode=2)
URL: /login#/networkConfiguration/intelligentFlowControl (流控策略设置tab)
添加/编辑: 独立配置页 /login#/networkConfiguration/intelligentFlowControl/flowControlStrategySetting/add

页面特点: 表格型页面(多记录CRUD), 继承IkuaiTablePage
- 表格列: 名称/线路/应用协议/优先级/内网IP/单线上行/单线下行/单机上行/单机下行/生效时间/操作
- 添加: 独立页面, 字段:
    名称*(#tagname) / 线路(下拉wan1等) / 应用协议(下拉) / 应用协议分组(下拉) /
    优先级*(下拉默认0最高) / IP-MAC设置(列表) / IP-MAC分组(下拉) /
    单线上行*(占位"最低") / 单线下行*(占位"最低") / 单机上行* / 单机下行* /
    生效时间(radio:时间计划/按周循环/时间段)
- 行操作: 编辑/停用/启用/删除
- 批量操作: 全选/批量启用/批量停用/批量删除
- 导入/导出

数据库: layer7_qos表
字段: id, enabled, name(unique), tagname, interface(线路), prio(优先级),
      ip_addr(json内网IP), app_proto(json应用协议), week(周期), time(json),
      min_up(单线上行), min_down(单线下行), max_up(单机上行), max_down(单机下行),
      avg_up(单机上行备份), avg_down(单机下行备份)

后端运行时验证:
- ipset: layer7qos_src_$id(IP) + layer7qos_app_$id(应用协议) + 总集合
- iptables: STREAM_LAYER7_NEW / LAYER7_IN / LAYER7_OUT链
- ik_cntl: appset/timeset
- 启用规则后 ipset 创建, 停用后清理, killall qos + 重启 qos.sh
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class Layer7QosPage(IkuaiTablePage):
    """手动流控策略页面对象 - 表格型(独立配置页)"""

    MODULE_NAME = "layer7_qos"
    PAGE_URL = "/login#/networkConfiguration/intelligentFlowControl"
    CONFIG_URL_FRAGMENT = "flowControlStrategySetting"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def navigate_to_layer7_qos(self):
        """导航到流控策略设置tab(需先切换到手动模式)"""
        url = f"{self.base_url}{self.PAGE_URL}"
        current = self.page.url
        if "intelligentFlowControl" in current and \
                self.CONFIG_URL_FRAGMENT not in current:
            self.page.reload()
        else:
            self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1500)

        # 点击流控策略设置tab
        tab = self.page.locator(".ant-tabs-tab:has-text('流控策略设置')")
        try:
            tab.first.wait_for(state="visible", timeout=10000)
        except Exception as e:
            logger.error(f"[导航] 流控策略设置tab超时(可能未切换到手动模式): {e}")
            raise
        tab.first.click()
        self.page.wait_for_timeout(1000)
        logger.info("[导航] 已切换到流控策略设置tab")
        return self

    def navigate_back_to_list(self):
        self.navigate_to_layer7_qos()
        self.page.wait_for_timeout(500)
        return self

    def _on_config_page(self) -> bool:
        return self.CONFIG_URL_FRAGMENT in self.page.url

    # ==================== Ant Select辅助 ====================

    def _select_ant_option(self, label_text: str, option_text: str = None,
                           first_visible: bool = False) -> bool:
        """
        打开指定label的Ant Select并选择选项

        Args:
            label_text: 表单label(线路/应用协议/优先级)
            option_text: 选项文本(None时配合first_visible)
            first_visible: 选第一个可见选项(用于应用协议等动态选项)
        """
        try:
            ok = self.page.evaluate(f"""(labelText) => {{
                const labels = document.querySelectorAll('.ant-form-item-label');
                for (const lab of labels) {{
                    if (lab.textContent.includes(labelText)) {{
                        const fi = lab.closest('.ant-form-item');
                        const sel = fi && fi.querySelector('.ant-select-selector');
                        if (sel) {{ sel.click(); return true; }}
                    }}
                }}
                return false;
            }}""", label_text)
            if not ok:
                logger.warning(f"[Select] 未找到label '{label_text}'")
                return False
            self.page.wait_for_timeout(700)

            # JS click绕过虚拟滚动可见性(支持first_visible=选第一个)
            clicked = self.page.evaluate("""(args) => {
                const [optionText, firstVisible] = args;
                const opts = document.querySelectorAll('.ant-select-item-option');
                if (firstVisible) {
                    if (opts.length > 0) {
                        opts[0].scrollIntoView({block: 'nearest'});
                        opts[0].click();
                        return true;
                    }
                    return false;
                }
                const match = (t, target) => t === target ||
                    t.startsWith(target + ' ') || t.startsWith(target + '(') ||
                    t.startsWith(target + '（');
                for (const o of opts) {
                    if (match(o.textContent.trim(), optionText)) {
                        o.scrollIntoView({block: 'nearest'});
                        o.click();
                        return true;
                    }
                }
                for (const o of opts) {
                    if (o.textContent.includes(optionText)) {
                        o.scrollIntoView({block: 'nearest'});
                        o.click();
                        return true;
                    }
                }
                return false;
            }""", [option_text, first_visible])
            if clicked:
                self.page.wait_for_timeout(400)
                return True
            self.page.keyboard.press("Escape")
            return False
        except Exception as e:
            logger.warning(f"[Select] {label_text}='{option_text}' 失败: {e}")
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    def select_interface(self, interface: str = "wan1") -> bool:
        """选择线路(wan1/wan2/wan3)"""
        return self._select_ant_option("线路", interface)

    def select_app_proto(self, proto: str = None) -> bool:
        """
        选择应用协议(必填, modal树选择)

        应用协议点击后弹出modal树(所有协议>网络协议>各分类),
        勾选协议后点"确定"关闭modal。proto=None时勾选"所有协议"根节点。
        """
        try:
            # 1. 点应用协议select打开modal树
            ok = self.page.evaluate("""() => {
                const labels = document.querySelectorAll('.ant-form-item-label');
                for (const lab of labels) {
                    if (lab.textContent.includes('应用协议') && !lab.textContent.includes('分组')) {
                        const fi = lab.closest('.ant-form-item');
                        const sel = fi && fi.querySelector('.ant-select-selector');
                        if (sel) { sel.click(); return true; }
                    }
                }
                return false;
            }""")
            if not ok:
                logger.warning("[应用协议] 未找到应用协议select")
                return False
            self.page.wait_for_timeout(1000)

            # 2. 等待modal树渲染
            try:
                self.page.wait_for_selector(
                    '.ant-modal-wrap:not([style*="display: none"]) .ant-tree',
                    timeout=5000
                )
            except Exception:
                self.page.wait_for_timeout(500)

            # 3. 勾选协议(JS click树checkbox有效)
            target = proto or "所有协议"
            checked = self.page.evaluate("""(targetText) => {
                const modal = document.querySelector('.ant-modal-wrap:not([style*="display: none"]) .ant-modal');
                if (!modal) return false;
                const nodes = modal.querySelectorAll('.ant-tree-treenode');
                for (const node of nodes) {
                    const title = node.querySelector('.ant-tree-title');
                    if (title && title.textContent.trim().includes(targetText)) {
                        const cb = node.querySelector('.ant-tree-checkbox');
                        if (cb && !cb.classList.contains('ant-tree-checkbox-checked')) {
                            cb.click();
                        }
                        return true;
                    }
                }
                return false;
            }""", target)
            self.page.wait_for_timeout(500)

            # 4. 点"确定"关闭modal
            confirmed = self.page.evaluate("""() => {
                const modal = document.querySelector('.ant-modal-wrap:not([style*="display: none"]) .ant-modal');
                if (!modal) return false;
                const btn = Array.from(modal.querySelectorAll('button')).find(
                    b => b.textContent.trim() === '确定');
                if (btn) { btn.click(); return true; }
                return false;
            }""")
            self.page.wait_for_timeout(800)
            logger.info(f"[应用协议] 选择: {target} (勾选={checked}, 确定={confirmed})")
            return confirmed or checked
        except Exception as e:
            logger.warning(f"[应用协议] 选择失败: {e}")
            try:
                self.page.evaluate("""() => {
                    const modal = document.querySelector('.ant-modal-wrap:not([style*="display: none"]) .ant-modal');
                    if (modal) {
                        const cancel = Array.from(modal.querySelectorAll('button')).find(
                            b => b.textContent.trim() === '取消');
                        if (cancel) cancel.click();
                    }
                }""")
            except Exception:
                pass
            return False

    def select_priority(self, prio: int = 0) -> bool:
        """选择优先级(0最高)"""
        return self._select_ant_option("优先级", str(prio))

    # ==================== 表单填写 ====================

    def fill_name(self, name: str):
        inp = self.page.locator('input[placeholder="请输入名称"]')
        if inp.count() > 0:
            inp.click()
            self.page.keyboard.press("Control+a")
            inp.type(name, delay=40)
            self.page.wait_for_timeout(300)
        return self

    def _fill_field_by_label(self, label_text: str, value):
        """通过label定位input并填值(Playwright click+type, 兼容InputNumber受控组件)

        单线/单机上下行是InputNumber, React setter不触发onChange,
        必须用键盘type模拟输入。
        """
        try:
            inp = self.page.locator(
                f".ant-form-item:has(.ant-form-item-label:has-text('{label_text}')) input"
            ).first
            if inp.count() == 0:
                logger.warning(f"[操作] 未找到{label_text}的input")
                return self
            inp.click()
            self.page.keyboard.press("Control+a")
            self.page.keyboard.type(str(value), delay=30)
            self.page.wait_for_timeout(300)
        except Exception as e:
            logger.warning(f"[操作] 填写{label_text}失败: {e}")
        return self

    def fill_min_up(self, val):
        """单线上行(id=min_up)"""
        return self._fill_by_id("min_up", val)

    def fill_min_down(self, val):
        """单线下行(id=min_down)"""
        return self._fill_by_id("min_down", val)

    def fill_max_up(self, val):
        """单机上行(id=avg_up, UI单机上行对应数据库avg_up非max_up)"""
        return self._fill_by_id("avg_up", val)

    def fill_max_down(self, val):
        """单机下行(id=avg_down)"""
        return self._fill_by_id("avg_down", val)

    def _set_numeric_fields(self, min_up, min_down, max_up, max_down):
        """用Form.setFieldsValue直接设置数字字段(绕过input)

        !! 关键: select_app_proto的modal关闭后会破坏min_up/min_down的Form字段绑定
        (DOM input.value还在, 但Form内部state丢失, 保存校验报"请输入单线上行")。
        fill/type/evaluate-setter/onChange都无法恢复绑定。
        唯一解法: 通过React fiber找到Form实例, 调用setFieldsValue直达Form state。
        校验规则: 单机上行(avg_up) ≤ 单线最高(max_up), 故设max_up=avg_up*2。
        """
        try:
            self.page.evaluate("""(args) => {
                const [mu, md, xu, xd] = args;
                const formEl = document.querySelector('form');
                if (!formEl) return false;
                const fk = Object.keys(formEl).find(k => k.startsWith('__reactFiber$'));
                let fiber = fk ? formEl[fk] : null;
                while (fiber) {
                    if (fiber.memoizedProps && fiber.memoizedProps.form
                        && typeof fiber.memoizedProps.form.setFieldsValue === 'function') {
                        const f = fiber.memoizedProps.form;
                        f.setFieldsValue({
                            min_up: mu, max_up: Math.max(xu * 2, mu * 2),
                            min_down: md, max_down: Math.max(xd * 2, md * 2),
                            avg_up: xu, avg_down: xd
                        });
                        return true;
                    }
                    fiber = fiber.return;
                }
                return false;
            }""", [min_up, min_down, max_up, max_down])
            self.page.wait_for_timeout(300)
        except Exception as e:
            logger.warning(f"[数字字段] setFieldsValue失败: {e}")
        return self

    def _fill_by_id(self, input_id, val):
        """通过id定位input: setter设值 + 调用React fiber的onChange更新Form state

        !! Ant Form受控组件(单线/单机上下行): fill/setter只改DOM value, Form内部state
        不更新(保存校验认为必填字段空)。必须直接调用input的React props.onChange
        ({target:inp})强制Form收集字段值。
        """
        try:
            self.page.evaluate("""(args) => {
                const [id, v] = args;
                const inp = document.getElementById(id);
                if (!inp) return;
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value').set;
                setter.call(inp, v);
                const fiberKey = Object.keys(inp).find(k => k.startsWith('__reactProps$'));
                const props = fiberKey ? inp[fiberKey] : null;
                if (props && typeof props.onChange === 'function') {
                    props.onChange({target: inp, currentTarget: inp});
                }
                inp.dispatchEvent(new Event('input', {bubbles: true}));
            }""", [input_id, str(val)])
            self.page.wait_for_timeout(200)
        except Exception as e:
            logger.warning(f"[操作] 填写#{input_id}失败: {e}")
        return self

    def fill_ip_addr(self, ip: str):
        """填写IP/MAC设置(列表控件, 可选)"""
        try:
            clicked = self.page.evaluate("""() => {
                const labels = document.querySelectorAll('.ant-form-item-label');
                for (const lab of labels) {
                    if (lab.textContent.includes('IP/MAC设置')) {
                        const fi = lab.closest('.ant-form-item');
                        const addBtn = fi && Array.from(fi.querySelectorAll('button')).find(
                            b => b.textContent.trim() === '添加');
                        if (addBtn) { addBtn.click(); return true; }
                    }
                }
                return false;
            }""")
            if not clicked:
                return self
            self.page.wait_for_timeout(600)
            self.page.evaluate(f"""() => {{
                const inp = document.querySelector('input[placeholder*="IP或MAC"]');
                if (!inp) return false;
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value').set;
                setter.call(inp, '{ip}');
                inp.dispatchEvent(new Event('input', {{bubbles: true}}));
                inp.dispatchEvent(new Event('change', {{bubbles: true}}));
                return true;
            }}""")
            self.page.wait_for_timeout(400)
        except Exception as e:
            logger.warning(f"[操作] 填写IP失败: {e}")
        return self

    # ==================== 添加规则 ====================

    def add_rule(self, name: str, interface: str = "wan1",
                 proto: str = None, prio: int = 0,
                 min_up: int = 1000, min_down: int = 1000,
                 max_up: int = 2000, max_down: int = 2000,
                 ip: str = None) -> bool:
        """
        添加手动流控策略规则

        Args:
            name: 名称(必填)
            interface: 线路 wan1/wan2/wan3
            proto: 应用协议(None=选第一个)
            prio: 优先级(0最高)
            min_up/min_down: 单线上下行KB/s
            max_up/max_down: 单机上下行KB/s
            ip: 内网IP(可选)
        """
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector(
                    'input[placeholder="请输入名称"]', timeout=10000
                )
            except Exception:
                self.page.wait_for_load_state("networkidle")
                self.page.wait_for_timeout(1000)

            self.fill_name(name)
            self.select_interface(interface)
            self.select_app_proto(proto)
            self.select_priority(prio)
            # !! select_app_proto的modal破坏min_up/min_down的Form绑定
            # (DOM值在但Form state丢, 保存校验报"请输入单线上行"),
            # 用Form.setFieldsValue直达Form state绕过
            self._set_numeric_fields(min_up, min_down, max_up, max_down)
            if ip:
                self.fill_ip_addr(ip)

            logger.info(f"[添加] {name}: iface={interface}, proto={proto}, prio={prio}")
            self.click_save()
            self.page.wait_for_timeout(1500)

            if self._has_form_error():
                logger.error(f"[添加] 表单错误: {self._get_form_error()}")
                self._safe_cancel()
                return False
            if self._on_config_page():
                logger.warning(f"[添加] 保存后仍在配置页: {self.page.url}")
                self._safe_cancel()
                return False

            self.page.wait_for_timeout(800)
            if self.rule_exists(name):
                logger.info(f"[添加] 成功: {name}")
                return True
            if self.wait_for_success_message(timeout=2000):
                return True
            return False
        except Exception as e:
            logger.error(f"[添加] 异常: {e}")
            self._safe_cancel()
            return False

    def edit_rule(self, rule_name: str, **kwargs) -> bool:
        """编辑规则"""
        try:
            super().edit_rule(rule_name)
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector(
                    'input[placeholder="请输入名称"]', timeout=10000
                )
            except Exception:
                self.page.wait_for_timeout(1000)

            if "name" in kwargs:
                self.fill_name(kwargs["name"])
            if "interface" in kwargs:
                self.select_interface(kwargs["interface"])
            if "proto" in kwargs:
                self.select_app_proto(kwargs["proto"])
            if "prio" in kwargs and kwargs["prio"] is not None:
                self.select_priority(kwargs["prio"])
            field_id_map = {"min_up": "min_up", "min_down": "min_down",
                            "max_up": "avg_up", "max_down": "avg_down"}
            for fld in ["min_up", "min_down", "max_up", "max_down"]:
                if fld in kwargs and kwargs[fld] is not None:
                    self._fill_by_id(field_id_map[fld], kwargs[fld])

            self.click_save()
            self.page.wait_for_timeout(1500)

            if self._has_form_error():
                self._safe_cancel()
                return False
            if self._on_config_page():
                self._safe_cancel()
                return False

            self.page.wait_for_timeout(800)
            target = kwargs.get("name", rule_name)
            return self.rule_exists(target)
        except Exception as e:
            logger.error(f"[编辑] 异常: {e}")
            self._safe_cancel()
            return False

    # ==================== 表格读取 ====================

    def get_rule_list(self) -> List[dict]:
        """获取表格规则列表

        列: 名称/线路/应用协议/优先级/内网IP/单线上行/单线下行/单机上行/单机下行/生效时间/操作
        """
        rules = []
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
            rules = self.page.evaluate('''() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                rows.forEach(row => {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length >= 6) {
                        const name = cells[0]?.textContent?.trim() || '';
                        const iface = cells[1]?.textContent?.trim() || '';
                        const proto = cells[2]?.textContent?.trim() || '';
                        const prio = cells[3]?.textContent?.trim() || '';
                        const op = cells[cells.length-1]?.textContent?.trim() || '';
                        if (name && name !== '暂无内容') {
                            result.push({
                                name: name, interface: iface, proto: proto,
                                prio: prio, enabled: op.includes('停用')
                            });
                        }
                    }
                });
                return result;
            }''')
        except Exception as e:
            logger.warning(f"[读取] 规则列表失败: {e}")
        return rules or []

    def find_rule_row(self, name: str) -> Optional[dict]:
        for r in self.get_rule_list():
            if r["name"] == name:
                return r
        return None

    # ==================== 异常输入测试 ====================

    def try_add_rule_invalid(self, name: str = None, min_up: int = None,
                             expect_fail: bool = True) -> dict:
        """尝试添加无效规则(测试空名称/缺必填)"""
        try:
            self.click_add_button()
            self.page.wait_for_timeout(1500)
            try:
                self.page.wait_for_selector(
                    'input[placeholder="请输入名称"]', timeout=10000
                )
            except Exception:
                self.page.wait_for_timeout(1000)

            if name is not None:
                self.fill_name(name)
            if min_up is not None:
                self.fill_min_up(min_up)

            self.click_save()
            self.page.wait_for_timeout(1200)

            err_msg = self._get_form_error()
            still_on_config = self._on_config_page()

            if expect_fail and (err_msg or still_on_config):
                self._safe_cancel()
                return {"success": True, "error_message": err_msg}
            if expect_fail:
                self._safe_cancel()
                return {"success": False, "error_message": ""}
            return {"success": True, "error_message": ""}
        except Exception as e:
            self._safe_cancel()
            return {"success": False, "error_message": str(e)}

    # ==================== 辅助 ====================

    def _has_form_error(self) -> bool:
        return self.page.locator(
            '.ant-form-item-explain-error, .ant-message-error'
        ).count() > 0

    def _get_form_error(self) -> str:
        el = self.page.locator('.ant-form-item-explain-error')
        if el.count() > 0:
            return el.first.text_content().strip()
        toast = self.page.locator('.ant-message-error')
        if toast.count() > 0:
            return toast.first.text_content().strip()
        return ""

    def _safe_cancel(self):
        try:
            if self._on_config_page():
                self.click_cancel()
        except Exception:
            pass
        try:
            self.navigate_back_to_list()
        except Exception:
            pass
