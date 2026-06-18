"""
DNS加速服务页面操作类

网络配置 > DNS服务 > DNS加速服务
URL: /login#/networkConfiguration/dnsService (tab页面, 含2个tab: DNS加速服务/多线路DNS服务)

页面特点: 混合页面
1. 基础配置(单记录, dns_config表 id=1):
   - switch开关(enabled) + DNS缓存统计区(昨日/今日/累计请求次数)
   - 首选DNS(dns1*) / 备选DNS(dns2*)
   - 禁止AAAA记录(forbid_dns_4a checkbox)
   - DNS加速模式 radio(cachemode: UDP=0/DoH=3/多线分路=1/第三方代理=2)
   - 强制客户端DNS代理(proxy_force checkbox)
   - 老化时间 spinbutton(cache_ttl, 单位秒*)
   - 保存按钮
2. DNS反向代理表格(dns_reverse_proxy_new表):
   - 列: 域名/解析类型/解析地址/作用IP段/备注/操作
   - 工具栏: 添加/导入/导出/启用/停用/删除
   - 添加/编辑是独立页面(URL含 dnsSetting/add 或 /edit), 非弹窗

数据库: dns_config表(基础配置,单记录) + dns_reverse_proxy_new表(反向代理)
cachemode映射: 0=UDP, 1=多线分路, 2=第三方代理, 3=DoH (注意DoH=3非顺序)

!!! 关键交互特性 (2026-06-18实测) !!!
DNS加速页面内容区被 _container_yfjnt_2 容器内的浮层(splash page引导层 + stacking怪异)
持续拦截 Playwright pointer click, 所有 input/checkbox/radio/button 的 get_by_role/click
都会报 "intercepts pointer events" 超时30秒.
**解决方案**: 所有表单交互统一用 JS evaluate 操作, 完全绕过 Playwright actionability检测:
  - input/textarea: HTMLInputElement/HTMLTextAreaElement.prototype.value setter + dispatchEvent(input/change/blur)
  - checkbox/radio/button: el.click() 原生click(React监听原生click)
  - Ant Select: JS click .ant-select-selector 打开下拉 + JS click .ant-select-item-option
实测JS方式能正确触发React状态更新(已验证dns1/proxy_force/cachemode).

后端脚本: /usr/ikuai/script/dns.sh
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List, Dict
import logging

logger = logging.getLogger(__name__)


class DnsAcceleratePage(IkuaiTablePage):
    """DNS加速服务页面对象(混合: 基础配置单记录 + 反向代理表格)"""

    PAGE_URL = "/login#/networkConfiguration/dnsService"
    MODULE_NAME = "dns_accelerate"

    # cachemode 模式名 -> 数据库值(从DOM radio value确认)
    CACHEMODE_MAP = {
        "UDP": "0",
        "多线分路": "1",
        "第三方代理": "2",
        "DoH": "3",
    }
    # 数据库值 -> 模式名(反向)
    CACHEMODE_REVERSE = {v: k for k, v in CACHEMODE_MAP.items()}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== JS交互辅助(绕过浮层拦截) ====================

    def _js_set_value(self, element_id: str, value: str, tag: str = "input") -> bool:
        """
        JS设置input/textarea的值并触发React onChange(绕过浮层拦截)

        Args:
            element_id: 元素id
            value: 要设置的值
            tag: "input" 或 "textarea"
        """
        proto = "HTMLTextAreaElement" if tag == "textarea" else "HTMLInputElement"
        try:
            return self.page.evaluate("""([id, val, proto]) => {
                const el = document.getElementById(id);
                if (!el) return false;
                const desc = Object.getOwnPropertyDescriptor(window[proto].prototype, 'value');
                if (desc && desc.set) desc.set.call(el, val);
                else el.value = val;
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
                return true;
            }""", [element_id, str(value), proto])
        except Exception as e:
            logger.error(f"[JS] 设置#{element_id}值失败: {e}")
            return False

    def _js_click_id(self, element_id: str) -> bool:
        """JS click指定id的元素(checkbox/radio/button, 绕过浮层)"""
        try:
            return self.page.evaluate("""(id) => {
                const el = document.getElementById(id);
                if (el) { el.click(); return true; }
                return false;
            }""", element_id)
        except Exception as e:
            logger.error(f"[JS] click#{element_id}失败: {e}")
            return False

    def _js_is_checked(self, element_id: str) -> bool:
        """JS读取checkbox/radio的checked状态"""
        try:
            return self.page.evaluate(f"""() => {{
                const el = document.getElementById('{element_id}');
                return el ? el.checked : false;
            }}""")
        except Exception:
            return False

    # ==================== 导航 ====================

    def navigate_to_dns_accelerate(self):
        """导航到DNS加速服务页面(每次强制刷新确保表单与数据库同步)"""
        url = f"{self.base_url}{self.PAGE_URL}"
        current = self.page.url
        if 'dnsService' in current:
            self.page.reload()
        else:
            self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1500)

        # 确保在"DNS加速服务"tab(JS click避免tab点击被拦截)
        try:
            self.page.evaluate("""() => {
                const tabs = document.querySelectorAll('[role="tab"]');
                for (const t of tabs) {
                    if (t.textContent.trim() === 'DNS加速服务' && t.getAttribute('aria-selected') !== 'true') {
                        t.click(); return true;
                    }
                }
                return false;
            }""")
            self.page.wait_for_timeout(800)
        except Exception as e:
            logger.warning(f"[导航] 点击DNS加速服务tab失败: {e}")

        logger.info("[导航] 已到达DNS加速服务页面")

    # ==================== 基础配置: 读取 ====================

    def is_enabled(self) -> bool:
        """检查DNS加速服务是否已开启(switch aria-checked)"""
        try:
            return self.page.evaluate("""() => {
                const sw = document.querySelector('button.ant-switch');
                return sw ? sw.getAttribute('aria-checked') === 'true' : false;
            }""")
        except Exception as e:
            logger.warning(f"[读取] 检查开启状态失败: {e}")
            return False

    def get_dns1(self) -> str:
        """获取首选DNS"""
        try:
            el = self.page.locator("#dns1")
            if el.count() > 0:
                return el.input_value().strip()
        except Exception as e:
            logger.warning(f"[读取] 获取首选DNS失败: {e}")
        return ""

    def get_dns2(self) -> str:
        """获取备选DNS"""
        try:
            el = self.page.locator("#dns2")
            if el.count() > 0:
                return el.input_value().strip()
        except Exception as e:
            logger.warning(f"[读取] 获取备选DNS失败: {e}")
        return ""

    def is_forbid_aaaa(self) -> bool:
        """检查禁止AAAA记录是否开启"""
        return self._js_is_checked("forbid_dns_4a")

    def is_proxy_force(self) -> bool:
        """检查强制客户端DNS代理是否开启"""
        return self._js_is_checked("proxy_force")

    def get_cachemode(self) -> str:
        """获取当前DNS加速模式(返回模式名: UDP/DoH/多线分路/第三方代理)"""
        try:
            val = self.page.evaluate("""() => {
                const r = document.querySelector('input[name="cachemode"]:checked');
                return r ? r.value : null;
            }""")
            if val is not None:
                return self.CACHEMODE_REVERSE.get(str(val), f"未知({val})")
        except Exception as e:
            logger.warning(f"[读取] 获取加速模式失败: {e}")
        return ""

    def get_cachemode_value(self) -> str:
        """获取当前DNS加速模式的数据库值(0/1/2/3)"""
        try:
            val = self.page.evaluate("""() => {
                const r = document.querySelector('input[name="cachemode"]:checked');
                return r ? r.value : null;
            }""")
            return str(val) if val is not None else ""
        except Exception as e:
            logger.warning(f"[读取] 获取加速模式值失败: {e}")
        return ""

    def get_cache_ttl(self) -> str:
        """获取老化时间(秒)"""
        try:
            el = self.page.locator("#cache_ttl")
            if el.count() > 0:
                return el.input_value().strip()
        except Exception as e:
            logger.warning(f"[读取] 获取老化时间失败: {e}")
        return ""

    def get_basic_config(self) -> dict:
        """获取基础配置全部字段"""
        return {
            "enabled": self.is_enabled(),
            "dns1": self.get_dns1(),
            "dns2": self.get_dns2(),
            "forbid_dns_4a": self.is_forbid_aaaa(),
            "proxy_force": self.is_proxy_force(),
            "cachemode": self.get_cachemode(),
            "cachemode_value": self.get_cachemode_value(),
            "cache_ttl": self.get_cache_ttl(),
        }

    # ==================== 基础配置: 表单操作(全JS) ====================

    def toggle_enable(self, enable: bool = True) -> bool:
        """开启/关闭DNS加速服务(JS click switch, 绕过浮层)

        !! 关键 (2026-06-18实测修正): switch的原生 sw.click() 是异步生效(React状态更新有延迟),
        click后同步读取 aria-checked 会读到旧值(false). 若不轮询验证就继续, 后续 fill/save 会在
        错误的开关状态下执行——这正是步骤6/7"前端校验在关闭状态下执行→假绿"的根因.
        改为: click后轮询验证(最多2s), 失败重试最多3次, 返回是否真正切换到目标状态.

        Returns:
            是否成功切换到目标状态(供调用方检查, 失败应中止后续操作)
        """
        try:
            if self.is_enabled() == enable:
                logger.info(f"[操作] DNS加速服务已是{'开启' if enable else '关闭'}状态, 跳过")
                return True
            for attempt in range(3):
                self.page.evaluate("""() => {
                    const sw = document.querySelector('button.ant-switch');
                    if (sw) sw.click();
                }""")
                # 轮询验证: React异步更新DOM, click后aria-checked延迟变化, 最多等2秒
                for _ in range(10):
                    self.page.wait_for_timeout(200)
                    if self.is_enabled() == enable:
                        logger.info(f"[操作] DNS加速服务: {'开启' if enable else '关闭'}"
                                    f"(第{attempt + 1}次切换成功)")
                        return True
                logger.warning(f"[操作] DNS加速服务第{attempt + 1}次切换未生效, 重试...")
            logger.error(f"[操作] DNS加速服务切换到{'开启' if enable else '关闭'}失败(3次重试均未生效)")
            return False
        except Exception as e:
            logger.error(f"[操作] 切换开启状态失败: {e}")
            raise

    def fill_dns1(self, dns: str):
        """填写首选DNS(JS setter, 绕过浮层)"""
        if self._js_set_value("dns1", dns):
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 首选DNS: {dns}")
        else:
            logger.error(f"[操作] 填写首选DNS失败")

    def fill_dns2(self, dns: str):
        """填写备选DNS(JS setter, 绕过浮层)"""
        if self._js_set_value("dns2", dns):
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 备选DNS: {dns}")
        else:
            logger.error(f"[操作] 填写备选DNS失败")

    def toggle_forbid_aaaa(self, enable: bool = True):
        """开启/关闭禁止AAAA记录(JS click, 绕过浮层)"""
        current = self._js_is_checked("forbid_dns_4a")
        if current != enable:
            self._js_click_id("forbid_dns_4a")
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 禁止AAAA记录: {'开启' if enable else '关闭'}")
        else:
            logger.info(f"[操作] 禁止AAAA已是{'开启' if enable else '关闭'}, 跳过")

    def toggle_proxy_force(self, enable: bool = True):
        """开启/关闭强制客户端DNS代理(JS click, 绕过浮层)"""
        current = self._js_is_checked("proxy_force")
        if current != enable:
            self._js_click_id("proxy_force")
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 强制客户端DNS代理: {'开启' if enable else '关闭'}")
        else:
            logger.info(f"[操作] 强制代理已是{'开启' if enable else '关闭'}, 跳过")

    def select_cachemode(self, mode_name: str):
        """
        选择DNS加速模式(JS click radio, 绕过浮层)

        Args:
            mode_name: "UDP"/"DoH"/"多线分路"/"第三方代理"
        """
        target_val = self.CACHEMODE_MAP.get(mode_name)
        if target_val is None:
            logger.error(f"[操作] 未知加速模式: {mode_name}")
            return
        current = self.get_cachemode_value()
        if current == target_val:
            logger.info(f"[操作] 加速模式已是 {mode_name}, 跳过")
            return
        try:
            clicked = self.page.evaluate("""(val) => {
                const radios = document.querySelectorAll('input[name="cachemode"]');
                for (const r of radios) {
                    if (r.value === val) { r.click(); return true; }
                }
                return false;
            }""", target_val)
            if clicked:
                self.page.wait_for_timeout(500)
                logger.info(f"[操作] 选择加速模式: {mode_name}(value={target_val})")
            else:
                logger.error(f"[操作] 未找到加速模式radio: {mode_name}")
        except Exception as e:
            logger.error(f"[操作] 选择加速模式失败: {e}")
            raise

    def fill_cache_ttl(self, ttl: str):
        """填写老化时间(秒, 范围60-3600, JS setter绕过浮层)"""
        if self._js_set_value("cache_ttl", str(ttl)):
            self.page.wait_for_timeout(400)
            logger.info(f"[操作] 老化时间: {ttl}秒")
        else:
            logger.error(f"[操作] 填写老化时间失败")

    # ==================== 基础配置: 保存 ====================

    def click_save_basic(self) -> bool:
        """点击基础配置的保存按钮(JS click绕浮层)"""
        try:
            clicked = self.page.evaluate("""() => {
                const btns = Array.from(document.querySelectorAll('button'));
                for (const b of btns) {
                    if (b.textContent.trim() === '保存' && b.offsetParent !== null) {
                        b.click();
                        return true;
                    }
                }
                return false;
            }""")
            if clicked:
                self.page.wait_for_timeout(1000)
                return True
        except Exception as e:
            logger.error(f"[操作] 点击保存失败: {e}")
        return False

    def save_basic_config(self, enable: Optional[bool] = None,
                          dns1: Optional[str] = None,
                          dns2: Optional[str] = None,
                          forbid_aaaa: Optional[bool] = None,
                          proxy_force: Optional[bool] = None,
                          cachemode: Optional[str] = None,
                          cache_ttl: Optional[str] = None) -> bool:
        """
        配置DNS加速基础配置并保存(全JS操作绕过浮层)

        Args:
            enable: 是否开启, None不修改
            dns1: 首选DNS, None不修改
            dns2: 备选DNS, None不修改
            forbid_aaaa: 禁止AAAA记录, None不修改
            proxy_force: 强制客户端DNS代理, None不修改
            cachemode: 加速模式(UDP/DoH/多线分路/第三方代理), None不修改
            cache_ttl: 老化时间秒, None不修改

        Returns:
            保存是否成功
        """
        try:
            if enable is not None:
                # 开关切换必须成功, 否则在错误状态下保存→假绿(步骤6/7根因)
                if not self.toggle_enable(enable):
                    logger.error("[保存] DNS开关切换失败, 中止保存(避免在错误状态下提交)")
                    return False
            if dns1 is not None:
                self.fill_dns1(dns1)
            if dns2 is not None:
                self.fill_dns2(dns2)
            if forbid_aaaa is not None:
                self.toggle_forbid_aaaa(forbid_aaaa)
            if cachemode is not None:
                self.select_cachemode(cachemode)
            if proxy_force is not None:
                self.toggle_proxy_force(proxy_force)
            if cache_ttl is not None:
                self.fill_cache_ttl(cache_ttl)

            self.page.wait_for_timeout(800)
            self.click_save_basic()
            self.page.wait_for_timeout(2500)

            # !!! 关键 (2026-06-18实测): iKuai DNS基础配置保存成功后前端不弹任何消息
            # (ant-message/notification全空), 但/Action/call后端返回{"code":0,"message":"Success"}
            # 因此不能依赖成功消息检测, 改用结果导向验证: reload读实际值与期望值比对
            # 先快速检测前端校验错误(非法值时会有 explain-error)
            error_text = ""
            try:
                error_el = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if error_el.count() > 0:
                    error_text = (error_el.first.text_content() or "").strip()
            except Exception:
                pass
            if error_text:
                logger.error(f"[保存] 配置校验失败: {error_text}")
                return False

            # 兜底检测成功消息(部分环境可能有)
            try:
                msg = self.page.locator(".ant-message-success")
                if msg.count() > 0 and msg.first.is_visible():
                    logger.info("[保存] DNS加速基础配置保存成功(消息确认)")
                    return True
            except Exception:
                pass

            # 结果导向验证: reload读实际值与期望值比对(最可靠)
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(800)
            actual = self.get_basic_config()
            expected = {}
            if enable is not None:
                expected["enabled"] = enable
            if dns1 is not None:
                expected["dns1"] = dns1
            if dns2 is not None:
                expected["dns2"] = dns2
            if forbid_aaaa is not None:
                expected["forbid_dns_4a"] = forbid_aaaa
            if proxy_force is not None:
                expected["proxy_force"] = proxy_force
            if cachemode is not None:
                expected["cachemode"] = cachemode
            if cache_ttl is not None:
                expected["cache_ttl"] = cache_ttl

            mismatches = []
            for k, v in expected.items():
                if actual.get(k) != v:
                    mismatches.append(f"{k}:期望{v}实际{actual.get(k)}")
            if not mismatches:
                logger.info("[保存] DNS加速基础配置保存成功(结果验证)")
                return True
            logger.error(f"[保存] 配置未持久化: {'; '.join(mismatches)}")
            return False
        except Exception as e:
            logger.error(f"[保存] 配置保存异常: {e}")
            return False

    # ==================== 反向代理表格: 工具栏(JS click绕浮层) ====================

    def _click_toolbar_button(self, button_name: str) -> bool:
        """
        点击反向代理表格上方工具栏的按钮(JS click绕浮层)

        Args:
            button_name: 添加/导入/导出/启用/停用/删除
        """
        try:
            clicked = self.page.evaluate("""(name) => {
                const btns = Array.from(document.querySelectorAll('button'));
                for (const b of btns) {
                    if (b.textContent.replace(/\\s+/g, '').trim() === name && b.offsetParent !== null) {
                        b.click();
                        return true;
                    }
                }
                return false;
            }""", button_name)
            if clicked:
                self.page.wait_for_timeout(500)
                return True
            logger.warning(f"[操作] 工具栏按钮未找到: {button_name}")
        except Exception as e:
            logger.error(f"[操作] 点击工具栏按钮{button_name}失败: {e}")
        return False

    def click_add_button(self):
        """覆盖父类: 点击添加按钮(JS click绕浮层, 进入添加独立页)"""
        self._click_toolbar_button("添加")
        self.page.wait_for_timeout(800)
        return self

    def click_import(self):
        """覆盖父类: 点击导入按钮(JS click绕浮层)"""
        self._click_toolbar_button("导入")
        return self

    def click_export(self):
        """覆盖父类: 点击导出按钮(JS click绕浮层)"""
        self._click_toolbar_button("导出")
        return self

    def batch_enable(self):
        """覆盖父类: 批量启用(工具栏JS click, 工具栏在表格上方非底部footer)"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_toolbar_button("启用")
        self.page.wait_for_timeout(800)
        return self

    def batch_disable(self):
        """覆盖父类: 批量停用(工具栏JS click + 确认弹窗)"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_toolbar_button("停用")
        self.page.wait_for_timeout(800)
        try:
            confirm_btn = self.page.locator("button:has-text('确定'):visible")
            if confirm_btn.count() > 0:
                confirm_btn.first.click()
            else:
                self.page.get_by_role("button", name="确定").click()
        except Exception as e:
            logger.warning(f"[操作] 批量停用确认弹窗点击失败: {e}")
        return self

    def batch_delete(self):
        """覆盖父类: 批量删除(工具栏JS click + 确认弹窗)"""
        self.close_modal_if_exists()
        self.page.wait_for_timeout(500)
        self._click_toolbar_button("删除")
        self.page.wait_for_timeout(500)
        try:
            modal_confirm = self.page.locator(
                ".ant-modal-confirm .ant-btn-primary, .ant-modal-wrap .ant-btn-primary"
            )
            if modal_confirm.count() > 0:
                modal_confirm.first.click()
            else:
                popover_confirm = self.page.locator(
                    ".ant-popover button:has-text('确定'), .ant-popover .ant-btn-primary"
                )
                if popover_confirm.count() > 0:
                    popover_confirm.first.click()
                else:
                    self.page.get_by_role("button", name="确定").click()
        except Exception as e:
            logger.warning(f"[操作] 批量删除确认弹窗点击失败: {e}")
        return self

    # ==================== 选择/搜索(覆盖父类, JS绕浮层) ====================

    def select_rule(self, rule_name: str, timeout: int = 10000):
        """覆盖父类: 勾选指定规则复选框(JS, 绕过浮层)"""
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(300)
            self.page.evaluate("""(name) => {
                const rows = document.querySelectorAll('.ant-table-tbody .ant-table-row');
                for (const row of rows) {
                    if (row.textContent.includes(name)) {
                        const cb = row.querySelector('input[type="checkbox"]');
                        if (cb && !cb.checked) cb.click();
                        return true;
                    }
                }
                return false;
            }""", rule_name)
            self.page.wait_for_timeout(200)
        except Exception as e:
            logger.warning(f"[操作] select_rule '{rule_name}' 失败: {str(e)[:80]}")
        return self

    def select_all_rules(self):
        """覆盖父类: 全选规则(JS click表头checkbox, 绕过浮层)"""
        try:
            return self.page.evaluate("""() => {
                const cb = document.querySelector('thead input[type="checkbox"]');
                if (cb) { if (!cb.checked) cb.click(); return true; }
                return false;
            }""")
        except Exception as e:
            logger.warning(f"[操作] select_all_rules失败: {e}")
        return False

    def search_rule(self, keyword: str):
        """覆盖父类: 搜索规则(JS setter + input事件, 绕过浮层)"""
        try:
            self.page.evaluate("""(kw) => {
                const inp = document.querySelector('input[placeholder="请输入搜索内容"]');
                if (!inp) return false;
                const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                setter.call(inp, kw);
                inp.dispatchEvent(new Event('input', {bubbles: true}));
                inp.dispatchEvent(new Event('change', {bubbles: true}));
                return true;
            }""", keyword)
            self.page.wait_for_timeout(1000)
        except Exception as e:
            logger.warning(f"[操作] search_rule失败: {e}")
        return self

    def clear_search(self):
        """覆盖父类: 清除搜索(JS清空 + input事件)"""
        try:
            self.page.evaluate("""() => {
                const inp = document.querySelector('input[placeholder="请输入搜索内容"]');
                if (!inp) return false;
                const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                setter.call(inp, '');
                inp.dispatchEvent(new Event('input', {bubbles: true}));
                inp.dispatchEvent(new Event('change', {bubbles: true}));
                return true;
            }""")
            self.page.wait_for_timeout(800)
        except Exception as e:
            logger.warning(f"[操作] clear_search失败: {e}")
        return self

    # ==================== 反向代理表格: 读取规则 ====================

    def get_reverse_proxy_rules(self) -> List[Dict]:
        """
        读取反向代理表格所有规则(JS遍历标准ant-table-tbody)

        Returns:
            规则字典列表: [{domain, parse_type, dns_addr, src_addr, comment, enabled}, ...]
        """
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
            rules = self.page.evaluate("""() => {
                const rows = document.querySelectorAll('.ant-table-tbody .ant-table-row');
                const result = [];
                rows.forEach(row => {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length < 5) return;
                    const domain = cells[1]?.textContent?.trim() || '';
                    const parse_type = cells[2]?.textContent?.trim() || '';
                    const dns_addr = cells[3]?.textContent?.trim() || '';
                    const src_addr = cells[4]?.textContent?.trim() || '';
                    const comment = cells[5]?.textContent?.trim() || '';
                    const hasPlay = cells[1]?.querySelector('.anticon-play-circle, [data-icon="play-circle"]');
                    const hasMinus = cells[1]?.querySelector('.anticon-minus-circle, [data-icon="minus-circle"]');
                    let enabled = null;
                    if (hasPlay) enabled = true;
                    else if (hasMinus) enabled = false;
                    const opText = cells[6]?.textContent?.trim() || '';
                    if (enabled === null) {
                        if (opText.includes('停用')) enabled = true;
                        else if (opText.includes('启用')) enabled = false;
                    }
                    result.push({domain, parse_type, dns_addr, src_addr, comment, enabled});
                });
                return result;
            }""")
            return rules or []
        except Exception as e:
            logger.warning(f"[读取] 读取反向代理规则失败: {e}")
            return []

    def get_rule_count_by_rows(self) -> int:
        """通过实际表格行数获取规则数(比'共N条'文本更可靠)"""
        return len(self.get_reverse_proxy_rules())

    def find_rule_row(self, domain: str) -> Optional[Dict]:
        """查找指定域名的规则行"""
        for rule in self.get_reverse_proxy_rules():
            if rule["domain"] == domain:
                return rule
        return None

    # ==================== 添加/编辑反向代理表单(独立页面) ====================

    def navigate_to_add_page(self):
        """点击添加进入新增独立页(URL含 dnsSetting/add)"""
        self.click_add_button()
        try:
            self.page.locator("#domain").wait_for(timeout=8000)
        except Exception:
            try:
                self.page.wait_for_url("**/dnsSetting/add", timeout=3000)
            except Exception:
                logger.warning("[导航] 未检测到添加表单页")
        self.page.wait_for_timeout(500)

    def fill_domain(self, domain: str):
        """填写域名(JS setter绕浮层)"""
        if self._js_set_value("domain", domain):
            self.page.wait_for_timeout(300)
            logger.info(f"[表单] 域名: {domain}")
        else:
            logger.error(f"[表单] 填写域名失败")

    def get_parse_type(self) -> str:
        """获取解析类型当前值(IPv4/IPv6/代理)"""
        try:
            return self.page.evaluate("""() => {
                const sel = document.querySelector('#parse_type');
                if (!sel) return '';
                const selector = sel.closest('.ant-select')?.querySelector('.ant-select-selection-item');
                return selector ? selector.textContent.trim() : '';
            }""")
        except Exception as e:
            logger.warning(f"[表单] 获取解析类型失败: {e}")
        return ""

    def select_parse_type(self, parse_type: str):
        """
        选择解析类型(JS click selector打开下拉 + JS click option)

        Args:
            parse_type: "IPv4"/"IPv6"/"代理"
        """
        current = self.get_parse_type()
        if current == parse_type:
            logger.info(f"[表单] 解析类型已是 {parse_type}, 跳过")
            return
        try:
            # JS click .ant-select-selector 打开下拉(含#parse_type的select)
            self.page.evaluate("""() => {
                const sel = document.querySelector('#parse_type');
                if (!sel) return false;
                const selector = sel.closest('.ant-select')?.querySelector('.ant-select-selector');
                if (selector) { selector.click(); return true; }
                return false;
            }""")
            self.page.wait_for_timeout(700)

            # JS click 对应option(可见)
            clicked = self.page.evaluate("""(text) => {
                const opts = document.querySelectorAll('.ant-select-item-option');
                for (const o of opts) {
                    if (o.offsetParent !== null && o.textContent.trim() === text) {
                        o.click(); return true;
                    }
                }
                return false;
            }""", parse_type)
            if clicked:
                self.page.wait_for_timeout(400)
                logger.info(f"[表单] 解析类型: {parse_type}")
            else:
                logger.warning(f"[表单] 解析类型选项未找到: {parse_type}")
                self.page.keyboard.press("Escape")
        except Exception as e:
            logger.error(f"[表单] 选择解析类型失败: {e}")
            raise

    def fill_dns_addr(self, dns_addr: str):
        """
        填写解析地址(一行一个, JS setter绕浮层)

        Args:
            dns_addr: 解析地址, 多个用换行符\\n分隔
        """
        # 解析地址input id随类型变化(dns_addr_ipv4/ipv6/proxy), 用JS按id前缀查找
        try:
            ok = self.page.evaluate("""(val) => {
                let el = document.getElementById('dns_addr_ipv4')
                      || document.getElementById('dns_addr_ipv6')
                      || document.getElementById('dns_addr_proxy')
                      || document.querySelector('textarea[placeholder="请输入解析地址"]');
                if (!el) return false;
                const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
                setter.call(el, val);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
                return true;
            }""", dns_addr)
            if ok:
                self.page.wait_for_timeout(300)
                logger.info(f"[表单] 解析地址: {dns_addr.replace(chr(10), ',')}")
        except Exception as e:
            logger.error(f"[表单] 填写解析地址失败: {e}")
            raise

    def fill_src_addr(self, src_addr: str):
        """
        填写作用IP段(支持IP/CIDR/范围, 换行区分, JS setter绕浮层)

        Args:
            src_addr: 作用IP段, 多个用换行符\\n分隔
        """
        try:
            ok = self.page.evaluate("""(val) => {
                const el = document.getElementById('src_addr');
                if (!el) return false;
                const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
                setter.call(el, val);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
                return true;
            }""", src_addr)
            if ok:
                self.page.wait_for_timeout(300)
                logger.info(f"[表单] 作用IP段: {src_addr.replace(chr(10), ',')}")
        except Exception as e:
            logger.error(f"[表单] 填写作用IP段失败: {e}")
            raise

    def fill_comment(self, comment: str):
        """填写备注(JS setter绕浮层)"""
        try:
            ok = self.page.evaluate("""(val) => {
                const el = document.getElementById('comment');
                if (!el) return false;
                const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
                setter.call(el, val);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
                return true;
            }""", comment)
            if ok:
                self.page.wait_for_timeout(300)
                logger.info(f"[表单] 备注: {comment}")
        except Exception as e:
            logger.error(f"[表单] 填写备注失败: {e}")
            raise

    def click_save_form(self) -> bool:
        """点击添加/编辑表单的保存按钮(JS click绕浮层)"""
        try:
            clicked = self.page.evaluate("""() => {
                const btns = Array.from(document.querySelectorAll('button'));
                for (const b of btns) {
                    if (b.textContent.trim() === '保存' && b.offsetParent !== null) {
                        b.click(); return true;
                    }
                }
                return false;
            }""")
            if clicked:
                self.page.wait_for_timeout(1000)
                return True
        except Exception as e:
            logger.error(f"[表单] 点击保存失败: {e}")
        return False

    def click_cancel_form(self):
        """点击添加/编辑表单的取消按钮(JS click返回列表页)"""
        try:
            self.page.evaluate("""() => {
                const btns = Array.from(document.querySelectorAll('button'));
                for (const b of btns) {
                    if (b.textContent.trim() === '取消') { b.click(); return; }
                }
            }""")
            self.page.wait_for_timeout(500)
            self._handle_confirm_dialog()
            self.page.wait_for_load_state("networkidle")
        except Exception as e:
            logger.warning(f"[表单] 点击取消失败: {e}")

    def add_reverse_proxy(self, domain: str, parse_type: str = "IPv4",
                          dns_addr: str = "", src_addr: str = "",
                          comment: str = "") -> bool:
        """
        添加一条DNS反向代理规则

        Args:
            domain: 域名
            parse_type: 解析类型(IPv4/IPv6/代理)
            dns_addr: 解析地址(一行一个)
            src_addr: 作用IP段(IP/CIDR/范围, 换行区分)
            comment: 备注

        Returns:
            添加是否成功
        """
        try:
            self.navigate_to_add_page()
            self.fill_domain(domain)
            if parse_type:
                self.select_parse_type(parse_type)
            if dns_addr:
                self.fill_dns_addr(dns_addr)
            if src_addr:
                self.fill_src_addr(src_addr)
            if comment:
                self.fill_comment(comment)

            self.page.wait_for_timeout(500)
            self.click_save_form()
            self.page.wait_for_timeout(2500)

            # DNS反向代理保存后前端不弹消息(同基础配置), 改用结果导向验证:
            # 返回列表页确认规则已出现
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(800)
            row = self.find_rule_row(domain)
            if row:
                logger.info(f"[添加] 反向代理规则添加成功: {domain} -> {row}")
                return True
            # 添加失败, 检查校验错误
            error_el = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
            err_msg = ""
            try:
                if error_el.count() > 0:
                    err_msg = error_el.first.text_content() or ""
            except Exception:
                pass
            logger.error(f"[添加] 添加失败: {domain} 未出现在列表 {('(' + err_msg + ')') if err_msg else ''}")
            return False
        except Exception as e:
            logger.error(f"[添加] 添加反向代理异常: {e}")
            try:
                self.click_cancel_form()
                self.navigate_to_dns_accelerate()
            except Exception:
                pass
            return False

    def edit_reverse_proxy(self, domain: str, new_domain: str = None,
                           new_dns_addr: str = None, new_src_addr: str = None,
                           new_comment: str = None, new_parse_type: str = None) -> bool:
        """
        编辑指定域名的反向代理规则

        Args:
            domain: 要编辑的域名(定位规则)
            new_domain: 新域名, None不修改
            new_dns_addr: 新解析地址, None不修改
            new_src_addr: 新作用IP段, None不修改
            new_comment: 新备注, None不修改
            new_parse_type: 新解析类型, None不修改

        Returns:
            编辑是否成功
        """
        try:
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(500)
            # 行内编辑按钮(父类_click_rule_button用JS evaluate click, 不受浮层影响)
            self._click_rule_button(domain, "编辑")
            self.page.wait_for_timeout(1000)

            try:
                self.page.locator("#domain").wait_for(timeout=8000)
            except Exception:
                logger.error(f"[编辑] 未进入编辑表单页: {domain}")
                return False

            if new_domain is not None:
                self.fill_domain(new_domain)
            if new_parse_type is not None:
                self.select_parse_type(new_parse_type)
            if new_dns_addr is not None:
                self.fill_dns_addr(new_dns_addr)
            if new_src_addr is not None:
                self.fill_src_addr(new_src_addr)
            if new_comment is not None:
                self.fill_comment(new_comment)

            self.page.wait_for_timeout(500)
            self.click_save_form()
            self.page.wait_for_timeout(2500)

            # 结果导向验证: 返回列表页确认规则存在(用可能的新域名定位)
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(800)
            locate_domain = new_domain if new_domain else domain
            row = self.find_rule_row(locate_domain)
            if row:
                logger.info(f"[编辑] 反向代理规则编辑成功: {domain} -> {row}")
                return True
            error_el = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
            err_msg = ""
            try:
                if error_el.count() > 0:
                    err_msg = error_el.first.text_content() or ""
            except Exception:
                pass
            logger.error(f"[编辑] 编辑失败: {domain} 未出现在列表 {('(' + err_msg + ')') if err_msg else ''}")
            return False
        except Exception as e:
            logger.error(f"[编辑] 编辑反向代理异常: {e}")
            try:
                self.click_cancel_form()
                self.navigate_to_dns_accelerate()
            except Exception:
                pass
            return False

    def delete_reverse_proxy(self, domain: str) -> bool:
        """
        删除指定域名的反向代理规则(行内删除按钮+确认弹窗)

        Args:
            domain: 要删除的域名

        Returns:
            删除是否成功
        """
        try:
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(500)
            count_before = self.get_rule_count_by_rows()

            # 行内删除按钮(父类_click_rule_button用JS)
            self._click_rule_button(domain, "删除")
            self.page.wait_for_timeout(500)

            try:
                modal_confirm = self.page.locator(
                    ".ant-modal-confirm .ant-btn-primary, .ant-modal-wrap .ant-btn-primary"
                )
                if modal_confirm.count() > 0:
                    modal_confirm.first.click()
                else:
                    self.page.get_by_role("button", name="确定").click()
            except Exception as e:
                logger.warning(f"[删除] 确认弹窗失败: {e}")

            self.page.wait_for_timeout(1000)
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(800)

            count_after = self.get_rule_count_by_rows()
            if count_after < count_before:
                logger.info(f"[删除] 反向代理规则删除成功: {domain}")
                return True
            if not self.find_rule_row(domain):
                return True
            return False
        except Exception as e:
            logger.error(f"[删除] 删除反向代理异常: {e}")
            return False

    def disable_reverse_proxy(self, domain: str) -> bool:
        """停用指定域名的反向代理规则(行内停用按钮+确认弹窗)"""
        try:
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(500)
            self._click_rule_button(domain, "停用")
            self.page.wait_for_timeout(500)
            try:
                confirm_btn = self.page.locator(
                    "dialog button:has-text('确定'), [role='dialog'] button:has-text('确定')"
                )
                if confirm_btn.count() > 0:
                    confirm_btn.first.click()
                else:
                    self.page.get_by_role("button", name="确定").click()
            except Exception as e:
                logger.warning(f"[停用] 确认弹窗失败: {e}")
            self.page.wait_for_timeout(1500)
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(800)
            row = self.find_rule_row(domain)
            if row and row.get("enabled") is False:
                logger.info(f"[停用] 反向代理规则停用成功: {domain}")
                return True
            return self.wait_for_success_message()
        except Exception as e:
            logger.error(f"[停用] 停用反向代理异常: {e}")
            return False

    def enable_reverse_proxy(self, domain: str) -> bool:
        """启用指定域名的反向代理规则(行内启用按钮, 无确认弹窗)"""
        try:
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(500)
            self._click_rule_button(domain, "启用")
            self.page.wait_for_timeout(1500)
            self.navigate_to_dns_accelerate()
            self.page.wait_for_timeout(800)
            row = self.find_rule_row(domain)
            if row and row.get("enabled") is True:
                logger.info(f"[启用] 反向代理规则启用成功: {domain}")
                return True
            return self.wait_for_success_message()
        except Exception as e:
            logger.error(f"[启用] 启用反向代理异常: {e}")
            return False

    # ==================== 帮助 ====================

    def click_help(self) -> bool:
        """点击帮助按钮(JS click绕浮层)"""
        try:
            clicked = self.page.evaluate("""() => {
                const btns = Array.from(document.querySelectorAll('button'));
                for (const b of btns) {
                    if (b.textContent.includes('帮助') && b.offsetParent !== null) {
                        b.click(); return true;
                    }
                }
                return false;
            }""")
            if clicked:
                self.page.wait_for_timeout(500)
                return True
        except Exception as e:
            logger.warning(f"[帮助] 点击帮助失败: {e}")
        return False

    def is_help_panel_visible(self) -> bool:
        """检查帮助面板是否可见"""
        try:
            panel = self.page.locator(".ant-drawer, .ant-modal, [role='dialog']")
            return panel.count() > 0 and panel.first.is_visible()
        except Exception:
            return False

    def close_help_panel(self):
        """关闭帮助面板"""
        try:
            close_btn = self.page.locator(".ant-drawer-close, .ant-modal-close")
            if close_btn.count() > 0:
                close_btn.first.click()
            else:
                self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
        except Exception:
            self.page.keyboard.press("Escape")
