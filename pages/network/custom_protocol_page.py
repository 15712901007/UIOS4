"""
自定义协议页面操作类 (网络配置 > 自定义协议, 两个子tab)

页面URL: /login#/networkConfiguration/selfDefinedProtocol
两个子模块(独立平行, 表单不同):
- 自定义协议(dprotos, L4型): 按端口/IP/协议定义, 后端iptables mangle DPROTO链 + ipset
- 高级自定义协议(dprotos_l7, L7型): 按深度包检测特征(正则)定义, 后端loadapp DPI引擎

L4表单(customProtocolConfig页): 协议分类(#class)/协议名称(#name)/IP设置+IP分组(源/目的)/
  协议(#protocol)/端口设置+端口分组(源/目的)/备注(#comment) —— 与NAT规则"IP设置/端口设置"模式一致
L7表单(advancedCustomProtocolConfig页): 协议分类(#class)/协议名称(#name)/备注(#comment)/协议特征(#rule)

DB: dprotos(id,enabled,comment,name,src_addr,dst_addr,protocol,src_port,dst_port,class,appid)
    dprotos_l7(id,enabled,comment,name,class,appid,rule[base64])
CLI: /usr/ikuai/function/dprotos show | /usr/ikuai/function/dprotos_l7 show → {"data":[...]}
后端:
  L4: ipset dproto_src/dst/sport/dport_$id(按填的字段建) + iptables mangle DPROTO链
      (-A DPROTO -p tcp -m set --match-set dproto_*_$id ... -j APPMARK--set-appid <appid>)
  L7: loadapp加载进DPI(异步, 验证以L1数据库+rule base64解码为准)
class 10类(0=网络协议自定义…9=金融理财自定义), appid由后端custom_app_get_appid按class+name派生
L7 rule格式(空格分隔, 经rule_check验证): Protocol=TCP Direction=CLIENT Data=<token>
"""
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

PAGE_URL = "/login#/networkConfiguration/selfDefinedProtocol"

# 协议分类(0-9, UI显示名 → DB class值)
CLASS_NAMES = [
    "网络协议自定义", "网络游戏自定义", "社交通讯自定义", "传输下载自定义",
    "休闲娱乐自定义", "效率工具自定义", "办公协作自定义", "学习教育自定义",
    "生活服务自定义", "金融理财自定义",
]


class _CustomProtoBase(IkuaiTablePage):
    """自定义协议公共基类: tab切换(ant-tabs-tab-active验证) + NAT风格表单helper"""

    PAGE_URL = PAGE_URL

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== tab切换 ====================

    def _switch_tab(self, target: str) -> bool:
        """切到指定tab(自定义协议/高级自定义协议), active class验证+重试

        用JS textContent精确匹配 + ant-tabs-tab-active class判断(避开DHCP踩过的
        get_by_role子串匹配/aria-selected坑)。
        """
        for _ in range(3):
            try:
                res = self.page.evaluate("""(tgt) => {
                    const tab = Array.from(document.querySelectorAll('.ant-tabs-tab'))
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
                const t = Array.from(document.querySelectorAll('.ant-tabs-tab'))
                    .find(t => (t.textContent || '').trim() === tgt);
                return t ? t.classList.contains('ant-tabs-tab-active') : false;
            }""", target)
        except Exception:
            return False

    def _dismiss_residual_modal(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    # ==================== NAT风格表单helper(L4用) ====================

    def _close_any_dropdown(self):
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass

    def _find_form_item_by_label(self, label_text: str, index: int = 0):
        """按label精确匹配第N个ant-form-item(精确匹配, 避免'协议'误命中'协议分类')"""
        items = self.page.locator('.ant-form-item')
        count = 0
        for i in range(items.count()):
            item = items.nth(i)
            label = item.locator('.ant-form-item-label')
            if label.count() > 0 and label.first.text_content().strip() == label_text:
                if count == index:
                    return item
                count += 1
        return None

    def _click_select_in_form_item(self, form_item, selector_str: str = '.ant-select-selector'):
        if form_item is None:
            return False
        sel = form_item.locator(selector_str)
        if sel.count() > 0:
            sel.first.click(force=True)
            self.page.wait_for_timeout(800)
            return True
        return False

    def _select_dropdown_option(self, option_text: str) -> bool:
        """选下拉选项: 自定义协议页的下拉容器 Playwright isVisible 误判False, 直接走JS click

        实测(2026-06-23): 下拉打开后 .ant-select-dropdown 已 h=168/!hidden, 但
        Playwright `.is_visible()` 仍返 False(可能transform/zIndex导致), 致原NAT
        三策略全跳过。改成: JS精确匹配title或textContent后直接 element.click()。
        """
        return self._select_option_via_js(option_text)

    def _select_option_via_js(self, option_text: str) -> bool:
        try:
            clicked = self.page.evaluate("""(text) => {
                const dropdowns = Array.from(document.querySelectorAll('.ant-select-dropdown'))
                    .filter(d => !d.classList.contains('ant-select-dropdown-hidden') && d.offsetHeight > 0);
                for (let i = dropdowns.length - 1; i >= 0; i--) {
                    const items = dropdowns[i].querySelectorAll('.ant-select-item-option');
                    for (const item of items) {
                        // 优先title精确匹配, 否则textContent
                        if (item.getAttribute('title') === text || item.textContent.trim() === text) {
                            item.click();
                            return true;
                        }
                    }
                }
                return false;
            }""", option_text)
            if clicked:
                self.page.wait_for_timeout(500)
            return bool(clicked)
        except Exception:
            return False

    def _select_by_label(self, label: str, option_text: str) -> bool:
        """按label定位select并选option(协议分类/协议等单select字段)"""
        try:
            self._close_any_dropdown()
            form_item = self._find_form_item_by_label(label)
            if form_item is None:
                return False
            cur = form_item.locator('.ant-select-selection-item')
            if cur.count() > 0 and cur.first.text_content().strip() == option_text:
                return True
            self._click_select_in_form_item(form_item)
            self._select_dropdown_option(option_text)
            self._close_any_dropdown()
            return True
        except Exception as e:
            logger.warning(f"[选] {label}={option_text}异常: {e}")
            return False

    def _fill_value_in_form_item(self, label: str, label_index: int,
                                 value: str, input_placeholder_keyword: str) -> bool:
        try:
            form_item = self._find_form_item_by_label(label, index=label_index)
            if form_item is None:
                return False
            add_btn = form_item.locator('button').filter(has_text="添加")
            if add_btn.count() > 0:
                add_btn.first.click()
                self.page.wait_for_timeout(800)
            all_inputs = form_item.locator('input')
            for i in range(all_inputs.count()):
                inp = all_inputs.nth(i)
                ph = inp.get_attribute("placeholder") or ""
                if input_placeholder_keyword in ph and inp.is_visible():
                    inp.click()
                    self.page.wait_for_timeout(200)
                    inp.type(value, delay=30)
                    self.page.wait_for_timeout(300)
                    return True
            # fallback: id前缀
            if input_placeholder_keyword == "IP":
                id_prefix = "src_addr" if label_index == 0 else "dst_addr"
            else:
                id_prefix = "src_port" if label_index == 0 else "dst_port"
            fb = form_item.locator(f'input[id^="{id_prefix}"]')
            for i in range(fb.count()):
                inp = fb.nth(i)
                if inp.is_visible():
                    inp.click()
                    inp.type(value, delay=30)
                    self.page.wait_for_timeout(300)
                    return True
        except Exception as e:
            logger.warning(f"[填] {label}[{label_index}]异常: {e}")
        return False

    def import_rules(self, file_path: str, clear_existing: bool = False) -> bool:
        """覆盖基类: 自定义协议导入弹窗的"点击上传"有2个同名元素(上传区.ant-upload-btn
        span + 链接button), 基类按文本点会点到链接button(不触发文件选择器)。这里优先点
        .ant-upload-btn(真正的文件选择触发器), 并用 dialog.first 避免2个dialog的strict violation。
        """
        import os as _os
        try:
            if not _os.path.exists(file_path):
                print(f"[ERROR] File not found: {file_path}")
                return False
            self.click_import()
            self.page.wait_for_timeout(600)
            if clear_existing:
                # 勾"清空现有配置数据"
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
            # 等确定上传可点
            confirm = self.page.get_by_role("button", name="确定上传")
            for _ in range(10):
                if confirm.count() > 0 and not confirm.is_disabled():
                    break
                self.page.wait_for_timeout(500)
            if confirm.count() > 0:
                confirm.click()
            self.page.wait_for_timeout(2000)
            # 关闭残留弹窗(.first 避免2个dialog的strict violation)
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


class CustomProtocolPage(_CustomProtoBase):
    """自定义协议(L4, dprotos) — 端口/IP/协议型"""

    MODULE_NAME = "custom_protocol"
    COLUMN_ID_MAP = {"协议名称": "name"}

    # ==================== 导航 ====================

    def navigate_to_custom_protocol(self):
        self._dismiss_residual_modal()
        self.page.goto(f"{self.base_url}{self.PAGE_URL}")
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        self._switch_tab("自定义协议")
        self.page.wait_for_timeout(500)
        logger.info("[导航] 已到达自定义协议页面(L4)")
        return self

    def navigate_back_to_list(self):
        return self.navigate_to_custom_protocol()

    # ==================== 表单字段 ====================

    def fill_name(self, name: str):
        inp = self.page.locator('#name')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill(name)
            self.page.wait_for_timeout(150)
        return self

    def fill_comment(self, comment: str):
        inp = self.page.locator('#comment')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill(comment)
            self.page.wait_for_timeout(150)
        return self

    def select_class(self, cls_name: str):
        """选择协议分类(网络协议自定义/…/金融理财自定义)"""
        return self._select_by_label("协议分类", cls_name)

    def select_protocol(self, protocol: str = "任意"):
        """选择协议(任意/tcp/udp/tcp+udp)。协议非任意时端口字段才可见。"""
        return self._select_by_label("协议", protocol)

    def fill_src_addr(self, addr: str):
        return self._fill_value_in_form_item("IP设置", 0, addr, "IP")

    def fill_dst_addr(self, addr: str):
        return self._fill_value_in_form_item("IP设置", 1, addr, "IP")

    def fill_src_port(self, port: str):
        return self._fill_value_in_form_item("端口设置", 0, port, "端口")

    def fill_dst_port(self, port: str):
        return self._fill_value_in_form_item("端口设置", 1, port, "端口")

    # ==================== 保存与高层操作 ====================

    def save_form(self, expect_success: bool = True) -> bool:
        try:
            self.page.wait_for_timeout(500)
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() == 0:
                return False
            save_btn.click()
            self.page.wait_for_timeout(1500)
            if not expect_success:
                return False
            # 成功: ant-message-success 或 URL跳回列表
            ok = self.wait_for_success_message(timeout=5000)
            if not ok:
                # 失败: 表单错误 或 仍在/add页
                err = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if err.count() > 0:
                    logger.warning(f"[保存] 失败: {err.first.text_content().strip()[:60]}")
                    return False
                # URL判断
                ok = '/customProtocolConfig' not in self.page.url
            return ok
        except Exception as e:
            logger.warning(f"[保存] 异常: {e}")
            return False

    def add_rule(self, name: str, cls: int = 0, protocol: str = "任意",
                 src_addr: Optional[str] = None, dst_addr: Optional[str] = None,
                 src_port: Optional[str] = None, dst_port: Optional[str] = None,
                 comment: str = "") -> bool:
        """添加一条自定义协议(L4)规则

        cls: 协议分类索引(0-9)或名称; protocol: 任意/tcp/udp/tcp+udp
        注意: 端口仅在protocol非"任意"时可填。
        """
        try:
            self.navigate_to_custom_protocol()
            self.page.wait_for_timeout(500)
            self.click_add_button()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1000)
            cls_name = cls if isinstance(cls, str) else CLASS_NAMES[cls]
            self.select_class(cls_name)
            self.page.wait_for_timeout(300)
            self.fill_name(name)
            # 协议须在端口前选
            if protocol and protocol != "任意":
                self.select_protocol(protocol)
                self.page.wait_for_timeout(500)
            if src_addr:
                self.fill_src_addr(src_addr)
            if dst_addr:
                self.fill_dst_addr(dst_addr)
            if src_port:
                self.fill_src_port(src_port)
            if dst_port:
                self.fill_dst_port(dst_port)
            if comment:
                self.fill_comment(comment)
            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[添加] 异常: {e}")
            return False

    def edit_rule(self, current_name: str, **kwargs) -> bool:
        """编辑规则(kwargs: name/comment/cls/protocol/src_addr/dst_addr/src_port/dst_port)"""
        try:
            self.navigate_to_custom_protocol()
            self.page.wait_for_timeout(500)
            self._click_rule_button(current_name, "编辑")
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1200)
            if "name" in kwargs and kwargs["name"]:
                self.fill_name(kwargs["name"])
            if "cls" in kwargs and kwargs["cls"] is not None:
                cls = kwargs["cls"]
                self.select_class(cls if isinstance(cls, str) else CLASS_NAMES[cls])
            if "protocol" in kwargs and kwargs["protocol"]:
                self.select_protocol(kwargs["protocol"])
                self.page.wait_for_timeout(500)
            if "comment" in kwargs and kwargs["comment"] is not None:
                self.fill_comment(kwargs["comment"])
            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[编辑] 异常: {e}")
            return False

    def try_add_rule_invalid(self, name: str = "") -> Optional[str]:
        """异常添加(只填name直接保存), 返回错误文案或None"""
        try:
            self.navigate_to_custom_protocol()
            self.page.wait_for_timeout(500)
            self.click_add_button()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1000)
            if name:
                self.fill_name(name)
            self.page.wait_for_timeout(300)
            self.click_save()
            self.page.wait_for_timeout(1500)
            err = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if err.count() > 0:
                return err.first.text_content().strip()
            return None
        except Exception as e:
            logger.warning(f"[异常添加] 异常: {e}")
            return None


class AdvancedCustomProtocolPage(_CustomProtoBase):
    """高级自定义协议(L7, dprotos_l7) — 深度包检测特征型"""

    MODULE_NAME = "advanced_custom_protocol"

    def navigate_to_advanced_custom_protocol(self):
        self._dismiss_residual_modal()
        self.page.goto(f"{self.base_url}{self.PAGE_URL}")
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1000)
        self._switch_tab("高级自定义协议")
        self.page.wait_for_timeout(500)
        logger.info("[导航] 已到达高级自定义协议页面(L7)")
        return self

    def navigate_back_to_list(self):
        return self.navigate_to_advanced_custom_protocol()

    # ==================== 表单字段 ====================

    def fill_name(self, name: str):
        inp = self.page.locator('#name')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill(name)
            self.page.wait_for_timeout(150)
        return self

    def fill_comment(self, comment: str):
        inp = self.page.locator('#comment')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill(comment)
            self.page.wait_for_timeout(150)
        return self

    def fill_rule(self, rule: str):
        """填写协议特征(L7规则, 空格分隔: Protocol=TCP Direction=CLIENT Data=xxx)"""
        inp = self.page.locator('#rule')
        if inp.count() > 0:
            inp.first.click()
            inp.first.fill(rule)
            self.page.wait_for_timeout(150)
        return self

    def select_class(self, cls_name: str):
        return self._select_by_label("协议分类", cls_name)

    # ==================== 保存与高层操作 ====================

    def save_form(self, expect_success: bool = True) -> bool:
        try:
            self.page.wait_for_timeout(500)
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() == 0:
                return False
            save_btn.click()
            self.page.wait_for_timeout(1500)
            if not expect_success:
                return False
            ok = self.wait_for_success_message(timeout=5000)
            if not ok:
                err = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
                if err.count() > 0:
                    logger.warning(f"[保存] L7失败: {err.first.text_content().strip()[:60]}")
                    return False
                ok = '/advancedCustomProtocolConfig' not in self.page.url
            return ok
        except Exception as e:
            logger.warning(f"[保存] L7异常: {e}")
            return False

    def add_rule(self, name: str, rule: str = "Protocol=TCP Direction=CLIENT Data=test123",
                 cls: int = 0, comment: str = "") -> bool:
        """添加一条高级自定义协议(L7)规则

        rule: L7特征(空格分隔, 经rule_check校验)。默认简单合法规则。
        """
        try:
            self.navigate_to_advanced_custom_protocol()
            self.page.wait_for_timeout(500)
            self.click_add_button()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1000)
            cls_name = cls if isinstance(cls, str) else CLASS_NAMES[cls]
            self.select_class(cls_name)
            self.page.wait_for_timeout(300)
            self.fill_name(name)
            self.fill_rule(rule)
            if comment:
                self.fill_comment(comment)
            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[添加] L7异常: {e}")
            return False

    def edit_rule(self, current_name: str, **kwargs) -> bool:
        try:
            self.navigate_to_advanced_custom_protocol()
            self.page.wait_for_timeout(500)
            self._click_rule_button(current_name, "编辑")
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1200)
            if "name" in kwargs and kwargs["name"]:
                self.fill_name(kwargs["name"])
            if "rule" in kwargs and kwargs["rule"]:
                self.fill_rule(kwargs["rule"])
            if "comment" in kwargs and kwargs["comment"] is not None:
                self.fill_comment(kwargs["comment"])
            self.page.wait_for_timeout(500)
            ok = self.save_form(expect_success=True)
            self.page.wait_for_timeout(1500)
            return ok
        except Exception as e:
            logger.error(f"[编辑] L7异常: {e}")
            return False

    def try_add_rule_invalid(self, name: str = "", rule: str = "") -> Optional[str]:
        """异常添加(空name或非法rule), 返回错误文案或None"""
        try:
            self.navigate_to_advanced_custom_protocol()
            self.page.wait_for_timeout(500)
            self.click_add_button()
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1000)
            if name:
                self.fill_name(name)
            if rule:
                self.fill_rule(rule)
            self.page.wait_for_timeout(300)
            self.click_save()
            self.page.wait_for_timeout(1500)
            err = self.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if err.count() > 0:
                return err.first.text_content().strip()
            return None
        except Exception as e:
            logger.warning(f"[异常添加] L7异常: {e}")
            return None
