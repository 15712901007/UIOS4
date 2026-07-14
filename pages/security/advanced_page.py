"""
高级设置页面操作类

安全中心 > 高级设置
URL: /login#/securityCenter/advancedSetting

页面特点: 纯配置类(单表单, 无增删改查)
- 7个checkbox(id=字段名): noping_lan/noping_wan/notracert/hijack_ping/invalid/dos_lan/tcp_mss
- 1个数值输入: tcp_mss_num(id=tcp_mss_num, 前端范围1000-1500/后端__check_param 500-1500, 4的整数倍)
- 2个按钮: 保存/恢复默认

后端 advanced.sh: 单表advanced(id=1), save()增量更新iptables(NewOldVarl只动变化项),
reset()恢复默认(tcp_mss=1/1400, 其余=0, dos_lan_num=300).
每勾选对应iptables规则:
  noping_lan/wan → filter INPUT --icmp-type 8 + --ifaces lan/wan + DROP
  notracert      → filter CONNLIMIT --icmp-type 11 DROP
  hijack_ping    → nat PREROUTING --icmp-type 8 REDIRECT
  invalid        → filter INPUT ctstate invalid REJECT
  dos_lan        → raw CONNLIMIT peerconns-above N DROP
  tcp_mss        → mangle TCPMSS --set-mss N + ik_cntl syn_proxy set_mss N

交互: Ant Design, JS click绕浮层(同dns_accelerate_page). checkbox id=字段名, 直接JS操作.
保存前端可能不弹成功消息→用结果导向验证(reload读回对比, 同dns_accelerate_page).
"""
from typing import Dict
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
import logging

logger = logging.getLogger(__name__)


class AdvancedPage(IkuaiTablePage):
    """高级设置页面对象(纯配置类, 7勾选字段+tcp_mss_num)"""

    PAGE_URL = "/login#/securityCenter/advancedSetting"
    MODULE_NAME = "advanced"

    # 7个勾选字段(DOM id = 字段名, 实测2026-07-13)
    FIELDS = ["noping_lan", "noping_wan", "notracert", "hijack_ping", "invalid", "dos_lan", "tcp_mss"]
    TCP_MSS_NUM_ID = "tcp_mss_num"

    # reset默认值(advanced.sh reset(): tcp_mss=1/1400, 其余=0, dos_lan_num=300)
    DEFAULTS = {"noping_lan": False, "noping_wan": False, "notracert": False,
                "hijack_ping": False, "invalid": False, "dos_lan": False,
                "tcp_mss": True, "tcp_mss_num": "1400"}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== JS交互辅助(绕过浮层, 同dns_accelerate_page) ====================

    def _js_click_id(self, element_id: str) -> bool:
        """JS click指定id元素(checkbox, 绕过浮层拦截pointer events)"""
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
        """JS读checkbox checked状态"""
        try:
            return self.page.evaluate(f"""() => {{
                const el = document.getElementById('{element_id}');
                return el ? el.checked : false;
            }}""")
        except Exception:
            return False

    def _js_set_value(self, element_id: str, value: str) -> bool:
        """JS设input值并触发React onChange(原生setter+dispatch, 绕浮层)"""
        try:
            return self.page.evaluate("""([id, val]) => {
                const el = document.getElementById(id);
                if (!el) return false;
                const desc = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
                if (desc && desc.set) desc.set.call(el, val);
                else el.value = val;
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                el.dispatchEvent(new Event('blur', {bubbles: true}));
                return true;
            }""", [element_id, str(value)])
        except Exception as e:
            logger.error(f"[JS] 设#{element_id}值失败: {e}")
            return False

    def _js_click_button(self, text: str) -> bool:
        """JS click指定文本的可见button(保存/恢复默认, 绕浮层)"""
        try:
            return self.page.evaluate("""(t) => {
                const btns = Array.from(document.querySelectorAll('button'));
                for (const b of btns) {
                    if (b.textContent.trim() === t && b.offsetParent !== null) { b.click(); return true; }
                }
                return false;
            }""", text)
        except Exception as e:
            logger.error(f"[JS] click按钮[{text}]失败: {e}")
            return False

    # ==================== 导航 ====================

    def navigate_to_advanced(self):
        """导航到高级设置页面(强制reload确保表单与DB同步)"""
        url = f"{self.base_url}{self.PAGE_URL}"
        if 'advancedSetting' in self.page.url:
            self.page.reload()
        else:
            self.page.goto(url)
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(1500)
        logger.info("[导航] 已到达高级设置页面")

    # ==================== 读取配置 ====================

    def is_field_checked(self, field: str) -> bool:
        """读某勾选字段状态(True=勾选)"""
        return self._js_is_checked(field)

    def get_tcp_mss_num(self) -> str:
        """读tcp_mss_num值(字符串)"""
        try:
            val = self.page.evaluate(f"""() => {{
                const el = document.getElementById('{self.TCP_MSS_NUM_ID}');
                return el ? el.value : '';
            }}""")
            return str(val).strip() if val else ""
        except Exception:
            return ""

    def get_config(self) -> Dict:
        """读全部配置(7勾选字段 + tcp_mss_num)"""
        cfg = {f: self.is_field_checked(f) for f in self.FIELDS}
        cfg["tcp_mss_num"] = self.get_tcp_mss_num()
        return cfg

    # ==================== 表单操作 ====================

    def toggle_field(self, field: str, enable: bool = True, wait: int = 300) -> bool:
        """勾选/取消某字段(当前!=目标才click, 3次重试轮询验证). 返回是否达到目标状态."""
        current = self.is_field_checked(field)
        if current == enable:
            logger.info(f"[操作] {field}已是{'勾选' if enable else '取消'}, 跳过")
            return True
        for attempt in range(3):
            self._js_click_id(field)
            self.page.wait_for_timeout(wait)
            if self.is_field_checked(field) == enable:
                logger.info(f"[操作] {field}: {'勾选' if enable else '取消'}(第{attempt+1}次)")
                return True
        logger.error(f"[操作] {field}切换到{'勾选' if enable else '取消'}失败(3次重试)")
        return False

    def set_tcp_mss_num(self, value, wait: int = 400) -> bool:
        """设置tcp_mss_num值"""
        if self._js_set_value(self.TCP_MSS_NUM_ID, str(value)):
            self.page.wait_for_timeout(wait)
            logger.info(f"[操作] tcp_mss_num: {value}")
            return True
        logger.error("[操作] 设置tcp_mss_num失败")
        return False

    def click_save(self, wait: int = 2500) -> bool:
        """点击保存按钮(JS click绕浮层)"""
        ok = self._js_click_button("保存")
        if ok:
            self.page.wait_for_timeout(wait)
        return ok

    def click_reset(self, wait: int = 2500) -> bool:
        """点击恢复默认按钮(JS click绕浮层)"""
        ok = self._js_click_button("恢复默认")
        if ok:
            self.page.wait_for_timeout(wait)
        return ok

    def save_config(self, **fields) -> bool:
        """设置变化项+保存+结果导向验证(reload读回对比).

        kwargs: noping_lan/noping_wan/notracert/hijack_ping/invalid/dos_lan/tcp_mss(bool),
                tcp_mss_num(str/int). None不修改.
        Returns: 保存是否成功(前端不弹消息→reload读回对比, 同dns_accelerate_page)"""
        try:
            # 先toggle checkbox(启用tcp_mss后tcp_mss_num输入框才可用), 再set数值
            # (顺序反了会: tcp_mss关闭时set_tcp_mss_num因输入框禁用失败)
            for f in self.FIELDS:
                if fields.get(f) is not None:
                    self.toggle_field(f, fields[f])
            if fields.get("tcp_mss_num") is not None:
                self.set_tcp_mss_num(fields["tcp_mss_num"])
            self.page.wait_for_timeout(500)
            self.click_save()

            # 前端校验错误(非法值时会有 explain-error)
            error_text = ""
            try:
                err = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if err.count() > 0:
                    error_text = (err.first.text_content() or "").strip()
            except Exception:
                pass
            if error_text:
                logger.error(f"[保存] 校验失败: {error_text}")
                return False

            # 结果导向验证: reload读回对比(advanced保存前端可能不弹成功消息)
            self.navigate_to_advanced()
            self.page.wait_for_timeout(800)
            actual = self.get_config()
            mismatches = []
            for k, v in fields.items():
                if v is None:
                    continue
                if k == "tcp_mss_num":
                    if actual.get("tcp_mss_num") != str(v):
                        mismatches.append(f"tcp_mss_num:期望{v}实际{actual.get('tcp_mss_num')}")
                else:
                    if actual.get(k) != v:
                        mismatches.append(f"{k}:期望{v}实际{actual.get(k)}")
            if not mismatches:
                logger.info(f"[保存] advanced配置保存成功(结果验证): {fields}")
                return True
            logger.error(f"[保存] 配置未持久化: {'; '.join(mismatches)}")
            return False
        except Exception as e:
            logger.error(f"[保存] advanced配置保存异常: {e}")
            return False

    def reset_to_default(self) -> bool:
        """点击恢复默认+验证回默认值(DEFAULTS). 恢复默认可能弹确认弹窗, 已处理."""
        try:
            self.navigate_to_advanced()
            self.page.wait_for_timeout(500)
            self.click_reset()
            # 处理可能的确认弹窗(恢复默认可能需二次确认)
            try:
                confirm = self.page.locator(
                    ".ant-modal-confirm .ant-btn-primary, .ant-popover button:has-text('确定'), "
                    ".ant-modal-wrap .ant-btn-primary")
                if confirm.count() > 0:
                    confirm.first.click()
                    self.page.wait_for_timeout(1500)
            except Exception:
                pass
            self.navigate_to_advanced()
            self.page.wait_for_timeout(800)
            actual = self.get_config()
            mismatches = [f"{k}:期望{v}实际{actual.get(k)}" for k, v in self.DEFAULTS.items()
                          if actual.get(k) != v]
            if not mismatches:
                logger.info("[恢复默认] advanced已恢复默认值")
                return True
            logger.error(f"[恢复默认] 未回默认: {'; '.join(mismatches)}")
            return False
        except Exception as e:
            logger.error(f"[恢复默认] 异常: {e}")
            return False
