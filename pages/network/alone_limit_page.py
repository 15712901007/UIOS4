"""
终端独立限速页面操作类

网络配置 > 智能流控 > 终端独立限速 tab(智能模式)
URL: /login#/networkConfiguration/intelligentFlowControl (终端独立限速tab)
添加/编辑: 独立配置页 /login#/networkConfiguration/intelligentFlowControl/terminalIndependentSpeedLimit/add

页面特点: 表格型页面(多记录CRUD), 继承IkuaiTablePage
- 表格列: 名称 / IP/MAC分组 / 上行(KB/s) / 下行(KB/s) / 优先级 / 生效时间 / 备注 / 操作
- 添加: 独立页面, 字段:
    名称*(#tagname) / IP-MAC设置(列表控件,点添加按钮填IP) / IP-MAC分组(下拉) /
    上行(KB/s)*(默认1000) / 下行(KB/s)*(默认1000) / 优先级(下拉,默认0最高) /
    生效时间(radio:时间计划/按周循环/时间段) / 备注
- 行操作: 编辑/停用/启用/删除
- 批量操作: 全选/批量启用/批量停用/批量删除
- !! 无导入/导出按钮(后端alone_limit.sh未实现EXPORT/IMPORT)

数据库: alone_limit表
字段: id, tagname(unique,名称), enabled(yes/no), comment(备注),
      ip_addr(json, {"custom":["IP"],"object":{}}), upload(上行KB/s),
      download(下行KB/s), prio(优先级0-7,0最高), time(json,生效时间)

后端运行时验证:
- ipset: alone_limit_$id(list:set) + _alone_limit_$id(IP) + _alone_limit_$id_mac(MAC)
         + Linux_alone_intell(总集合)
- iptables: LAYER7_IN/LAYER7_OUT链
- 启用规则后 ipset 创建, 停用后 ipset 清理, killall qos + 重启 qos.sh
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class AloneLimitPage(IkuaiTablePage):
    """终端独立限速页面对象 - 表格型(独立配置页, 无导入导出)"""

    MODULE_NAME = "alone_limit"
    PAGE_URL = "/login#/networkConfiguration/intelligentFlowControl"
    CONFIG_URL_FRAGMENT = "terminalIndependentSpeedLimit"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 ====================

    def navigate_to_alone_limit(self):
        """导航到终端独立限速tab(需先开启智能流控)"""
        url = f"{self.base_url}{self.PAGE_URL}"
        current = self.page.url
        if "intelligentFlowControl" in current and \
                self.CONFIG_URL_FRAGMENT not in current:
            self.page.reload()
        else:
            self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1500)

        # 点击终端独立限速tab
        tab = self.page.locator(".ant-tabs-tab:has-text('终端独立限速')")
        try:
            tab.first.wait_for(state="visible", timeout=10000)
        except Exception as e:
            logger.error(f"[导航] 终端独立限速tab超时(可能未开启智能流控): {e}")
            raise
        tab.first.click()
        self.page.wait_for_timeout(1000)
        logger.info("[导航] 已切换到终端独立限速tab")
        return self

    def navigate_back_to_list(self):
        """从添加/编辑页导航回列表"""
        self.navigate_to_alone_limit()
        self.page.wait_for_timeout(500)
        return self

    def _on_config_page(self) -> bool:
        return self.CONFIG_URL_FRAGMENT in self.page.url

    # ==================== 表单填写 ====================

    def fill_name(self, name: str):
        """填写名称"""
        inp = self.page.locator('input[placeholder="请输入名称"]')
        if inp.count() > 0:
            inp.click()
            self.page.keyboard.press("Control+a")
            inp.type(name, delay=40)
            self.page.wait_for_timeout(300)
        return self

    def fill_ip_addr(self, ip: str):
        """
        填写IP/MAC设置(列表控件)

        IP/MAC设置是动态列表: 点"添加"按钮出现输入框(placeholder含Unicode引号),
        填入IP后加入列表。
        """
        try:
            # 找IP/MAC设置 form-item内的"添加"按钮(非顶部添加规则按钮)
            clicked = self.page.evaluate(f"""() => {{
                const labels = document.querySelectorAll('.ant-form-item-label');
                for (const lab of labels) {{
                    if (lab.textContent.includes('IP/MAC设置')) {{
                        const fi = lab.closest('.ant-form-item');
                        if (!fi) continue;
                        const addBtn = Array.from(fi.querySelectorAll('button')).find(
                            b => b.textContent.trim() === '添加'
                        );
                        if (addBtn) {{ addBtn.click(); return true; }}
                    }}
                }}
                return false;
            }}""")
            if not clicked:
                logger.warning("[操作] 未找到IP/MAC设置的添加按钮")
                return self
            self.page.wait_for_timeout(600)

            # 输入框出现(placeholder含Unicode引号 U+201C/U+201D)
            # 用React原生setter填值(可靠触发onChange)
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
            logger.info(f"[操作] 填写IP/MAC: {ip}")
        except Exception as e:
            logger.error(f"[操作] 填写IP/MAC失败: {e}")
        return self

    def fill_upload(self, upload: int):
        """填写上行(KB/s)"""
        inp = self.page.locator('input').filter(
            has=self.page.locator("xpath=ancestor::*[contains(.,'上行')]")
        )
        # 简化: 直接找含上行label的form-item的input
        try:
            self.page.evaluate(f"""() => {{
                const labels = document.querySelectorAll('.ant-form-item-label');
                for (const lab of labels) {{
                    if (lab.textContent.includes('上行')) {{
                        const fi = lab.closest('.ant-form-item');
                        const inp = fi && fi.querySelector('input');
                        if (inp) {{
                            const setter = Object.getOwnPropertyDescriptor(
                                window.HTMLInputElement.prototype, 'value').set;
                            setter.call(inp, '{upload}');
                            inp.dispatchEvent(new Event('input', {{bubbles: true}}));
                            inp.dispatchEvent(new Event('change', {{bubbles: true}}));
                            return true;
                        }}
                    }}
                }}
                return false;
            }}""")
            self.page.wait_for_timeout(300)
        except Exception:
            pass
        return self

    def fill_download(self, download: int):
        """填写下行(KB/s)"""
        try:
            self.page.evaluate(f"""() => {{
                const labels = document.querySelectorAll('.ant-form-item-label');
                for (const lab of labels) {{
                    if (lab.textContent.includes('下行')) {{
                        const fi = lab.closest('.ant-form-item');
                        const inp = fi && fi.querySelector('input');
                        if (inp) {{
                            const setter = Object.getOwnPropertyDescriptor(
                                window.HTMLInputElement.prototype, 'value').set;
                            setter.call(inp, '{download}');
                            inp.dispatchEvent(new Event('input', {{bubbles: true}}));
                            inp.dispatchEvent(new Event('change', {{bubbles: true}}));
                            return true;
                        }}
                    }}
                }}
                return false;
            }}""")
            self.page.wait_for_timeout(300)
        except Exception:
            pass
        return self

    def select_priority(self, prio: int) -> bool:
        """选择优先级(0-7, 0最高). prio=0时显示'0 (最高)'"""
        return self._select_ant_option("优先级", str(prio))

    def fill_remark(self, remark: str):
        """填写备注"""
        try:
            ta = self.page.get_by_role("textbox", name="备注")
            if ta.count() > 0:
                ta.click()
                ta.fill(remark)
                self.page.wait_for_timeout(300)
        except Exception:
            pass
        return self

    def _select_ant_option(self, label_text: str, option_text: str) -> bool:
        """打开指定label的Ant Select并选择选项(精确匹配+模糊兜底)"""
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
                return False
            self.page.wait_for_timeout(600)

            option = self.page.locator(f".ant-select-item-option:has-text('{option_text}')")
            # JS click绕过虚拟滚动可见性
            clicked = self.page.evaluate("""(optionText) => {
                const opts = document.querySelectorAll('.ant-select-item-option');
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
            }""", option_text)
            if clicked:
                self.page.wait_for_timeout(400)
                return True
            self.page.keyboard.press("Escape")
            return False
        except Exception as e:
            logger.warning(f"[Select] {label_text}={option_text} 失败: {e}")
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    # ==================== 添加规则 ====================

    def add_rule(self, name: str, ip: str = "192.168.148.2",
                 upload: int = 2000, download: int = 2000,
                 prio: int = None, remark: str = None) -> bool:
        """
        添加终端独立限速规则

        Args:
            name: 名称(必填)
            ip: IP/MAC地址(必填, ip_addr)
            upload: 上行KB/s(默认2000)
            download: 下行KB/s(默认2000)
            prio: 优先级0-7(None=保持默认0)
            remark: 备注

        Returns:
            是否添加成功(结果导向: 跳回列表 + 规则存在)
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
            self.fill_ip_addr(ip)
            self.fill_upload(upload)
            self.fill_download(download)
            if prio is not None:
                self.select_priority(prio)
            if remark:
                self.fill_remark(remark)

            logger.info(f"[添加] {name}: ip={ip}, up={upload}, down={download}")
            self.click_save()
            self.page.wait_for_timeout(1500)

            # 检测表单错误
            if self._has_form_error():
                logger.error(f"[添加] 表单错误: {self._get_form_error()}")
                self._safe_cancel()
                return False

            # 结果导向: 跳回列表 = 成功
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
            logger.warning(f"[添加] 未确认存在: {name}")
            return False
        except Exception as e:
            logger.error(f"[添加] 异常: {e}")
            self._safe_cancel()
            return False

    def edit_rule(self, rule_name: str, **kwargs) -> bool:
        """编辑规则(修改指定字段)"""
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
            if "ip" in kwargs:
                self.fill_ip_addr(kwargs["ip"])
            if "upload" in kwargs:
                self.fill_upload(kwargs["upload"])
            if "download" in kwargs:
                self.fill_download(kwargs["download"])
            if "prio" in kwargs and kwargs["prio"] is not None:
                self.select_priority(kwargs["prio"])
            if "remark" in kwargs:
                self.fill_remark(kwargs["remark"])

            self.click_save()
            self.page.wait_for_timeout(1500)

            if self._has_form_error():
                logger.error(f"[编辑] 表单错误: {self._get_form_error()}")
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

        列顺序: [checkbox]名称/IP-MAC分组/上行/下行/优先级/生效时间/备注/操作
        enabled: 操作列含"停用"=启用
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
                        const ipmac = cells[1]?.textContent?.trim() || '';
                        const upload = cells[2]?.textContent?.trim() || '';
                        const download = cells[3]?.textContent?.trim() || '';
                        const prio = cells[4]?.textContent?.trim() || '';
                        const time = cells[5]?.textContent?.trim() || '';
                        const op = cells[cells.length-1]?.textContent?.trim() || '';
                        if (name && name !== '暂无内容') {
                            result.push({
                                name: name,
                                ipmac: ipmac,
                                upload: upload,
                                download: download,
                                prio: prio,
                                time: time,
                                enabled: op.includes('停用')
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

    def try_add_rule_invalid(self, name: str = None, ip: str = None,
                             upload: int = None, download: int = None,
                             expect_fail: bool = True) -> dict:
        """尝试添加无效规则, 测试表单验证"""
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
            if ip is not None:
                self.fill_ip_addr(ip)
            if upload is not None:
                self.fill_upload(upload)
            if download is not None:
                self.fill_download(download)

            self.click_save()
            self.page.wait_for_timeout(1200)

            err_msg = self._get_form_error()
            still_on_config = self._on_config_page()

            if expect_fail and (err_msg or still_on_config):
                logger.info(f"[异常测试] 预期失败已拦截: {err_msg or '保存被拒绝'}")
                self._safe_cancel()
                return {"success": True, "error_message": err_msg}
            if expect_fail:
                logger.warning(f"[异常测试] 预期失败但未拦截: name={name}")
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
