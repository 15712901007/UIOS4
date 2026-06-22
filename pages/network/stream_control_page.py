"""
智能流控主控页面操作类

网络配置 > 智能流控 页面(含切换模式独立页 + 流控线路tab)
URL:
  主页: /login#/networkConfiguration/intelligentFlowControl
  切换模式: /login#/networkConfiguration/switchIntelligentFlowControlMode

页面特点: 智能流控是状态型页面(非纯表格), 继承BasePage
  - 关闭态(stream_ctl_mode=0): 介绍页 + "开启智能流控"按钮
  - 开启态(stream_ctl_mode=1智能/2手动): "关闭流控"+"切换模式"按钮 + tab页

智能模式(3 tab): 流控线路 / 优先域名设置(仅auto=网页优先等预设场景显示) / 终端独立限速
手动模式(2 tab): 流控线路 / 流控策略设置

切换模式页(stream_control.sh + layer7_intell.sh save):
  - 模式选择radio: 智能模式 / 手动模式
  - 流控场景(仅智能模式): 自定义(auto=0)/网页优先(2)/游戏优先(1)/休闲娱乐(3)/下载优先(4)
  - 网页优先端口(domain_prio_ports): 仅网页优先场景显示
  - 自定义场景: 11类应用优先级combobox(0最高~7最低)
    网页浏览Http/网络游戏Game/社交通讯Im/传输下载Transport/休闲娱乐Relax/
    效率工具Utils/办公协作Office/学习教育Education/生活服务Life/金融理财Financial/未知应用Unknown

流控线路tab(layer7_intell.sh set_iface + wan_config表):
  - 表格: 名称/线路/上行(KB/s)/下行(KB/s)/操作, 每行 编辑/启用(或停用)
  - 编辑弹窗: 上行(KB/s)/下行(KB/s) -> wan_config.qos_upload/qos_download
  - 全部启用/全部停用: 批量切换 wan_config.qos_switch

后端:
  - global_config.stream_ctl_mode: 0关闭/1智能/2手动
  - layer7_intell(id=1): auto + 11类应用优先级 + domain_prio_switch + domain_prio_ports
  - wan_config: qos_upload/qos_download/qos_switch(每线路)
  - 开启/切换/编辑都会 killall qos.sh + 重启 utils/qos.sh
  - htb_rate_est(/sys/module/sch_htb/parameters)=1 表示流控开启
"""
from playwright.sync_api import Page
from pages.base_page import BasePage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class StreamControlPage(BasePage):
    """智能流控主控页面对象(状态型: 开启/关闭/模式切换/流控线路带宽)"""

    MODULE_NAME = "stream_control"
    PAGE_URL = "/login#/networkConfiguration/intelligentFlowControl"
    SWITCH_MODE_URL = "/login#/networkConfiguration/switchIntelligentFlowControlMode"

    # 流控场景 UI文本 -> 数据库auto值
    SCENE_MAP = {
        "自定义": 0,
        "游戏优先": 1,
        "网页优先": 2,
        "休闲娱乐": 3,
        "下载优先": 4,
    }
    # 反向映射(auto值 -> UI文本)
    AUTO_TO_SCENE = {v: k for k, v in SCENE_MAP.items()}

    # 11类应用优先级 UI标签 -> 数据库字段
    APP_PRIO_FIELDS = {
        "网页浏览": "Http",
        "网络游戏": "Game",
        "社交通讯": "Im",
        "传输下载": "Transport",
        "休闲娱乐": "Relax",
        "效率工具": "Utils",
        "办公协作": "Office",
        "学习教育": "Education",
        "生活服务": "Life",
        "金融理财": "Financial",
        "未知应用": "Unknown",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url

    # ==================== 导航 ====================

    def navigate_to_stream_control(self, force_reload: bool = False):
        """导航到智能流控主页面"""
        url = f"{self.base_url}{self.PAGE_URL}"
        if force_reload or "intelligentFlowControl" not in self.page.url or \
                "switchIntelligentFlowControlMode" in self.page.url:
            self.page.goto(url)
        else:
            self.page.reload()
        self.page.wait_for_load_state("networkidle")
        self.page.wait_for_timeout(1500)
        return self

    def _on_switch_mode_page(self) -> bool:
        """当前是否在切换模式独立页"""
        return "switchIntelligentFlowControlMode" in self.page.url

    # ==================== 流控开关状态 ====================

    def is_stream_control_enabled(self) -> bool:
        """判断流控是否已开启(开启态有"关闭流控"按钮, 关闭态有"开启智能流控"按钮)"""
        try:
            # 开启态: 有"关闭流控"按钮 或 tab页
            close_btn = self.page.locator("button:has-text('关闭流控')")
            tabs = self.page.locator(".ant-tabs-tab")
            open_btn = self.page.locator("button:has-text('开启智能流控')")
            if open_btn.count() > 0 and open_btn.first.is_visible():
                return False
            if close_btn.count() > 0 or tabs.count() > 0:
                return True
            return False
        except Exception:
            return False

    def enable_stream_control(self) -> bool:
        """开启智能流控(关闭态点击"开启智能流控"按钮)

        开启后默认进入智能模式(stream_ctl_mode=1)
        """
        try:
            self.navigate_to_stream_control(force_reload=True)
            self.page.wait_for_timeout(1000)

            if self.is_stream_control_enabled():
                logger.info("[开启] 流控已处于开启状态")
                return True

            open_btn = self.page.locator("button:has-text('开启智能流控')")
            if open_btn.count() == 0:
                logger.warning("[开启] 未找到'开启智能流控'按钮")
                return False

            open_btn.first.click()
            self.page.wait_for_timeout(2000)
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1500)

            # 结果导向: 验证已进入开启态
            ok = self.is_stream_control_enabled()
            logger.info(f"[开启] 智能流控开启{'成功' if ok else '失败'}")
            return ok
        except Exception as e:
            logger.error(f"[开启] 开启智能流控异常: {e}")
            return False

    def disable_stream_control(self) -> bool:
        """关闭智能流控(点"关闭流控"按钮, 可能有确认弹窗)"""
        try:
            self.navigate_to_stream_control()
            self.page.wait_for_timeout(1000)

            if not self.is_stream_control_enabled():
                logger.info("[关闭] 流控已处于关闭状态")
                return True

            close_btn = self.page.locator("button:has-text('关闭流控')")
            if close_btn.count() == 0:
                logger.warning("[关闭] 未找到'关闭流控'按钮")
                return False

            close_btn.first.click()
            self.page.wait_for_timeout(800)

            # 处理可能的确认弹窗
            self._handle_confirm()

            self.page.wait_for_timeout(2000)
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1500)

            ok = not self.is_stream_control_enabled()
            logger.info(f"[关闭] 智能流控关闭{'成功' if ok else '失败'}")
            return ok
        except Exception as e:
            logger.error(f"[关闭] 关闭智能流控异常: {e}")
            return False

    # ==================== 切换模式 ====================

    def get_current_mode(self) -> str:
        """获取当前模式标题(智能模式/手动模式)"""
        try:
            for mode in ["智能模式", "手动模式"]:
                loc = self.page.locator(f"text={mode}")
                if loc.count() > 0:
                    # 确认是标题区的文本(非按钮)
                    return mode
            return ""
        except Exception:
            return ""

    def get_current_scene(self) -> str:
        """获取当前流控场景(从'流控场景: xxx'文本解析)"""
        try:
            import re
            body = self.page.locator("body").inner_text()
            m = re.search(r"流控场景[:：]\s*([^\s\n]+)", body)
            return m.group(1).strip() if m else ""
        except Exception:
            return ""

    def _select_ant_option(self, label_text: str, option_text: str) -> bool:
        """
        打开指定label的Ant Design Select下拉并选择选项

        Ant Design Select: JS click不触发React, 必须用Playwright click .ant-select-selector

        Args:
            label_text: 表单label文本(如"流控场景"/"优先级")
            option_text: 选项文本(如"网页优先")

        Returns:
            是否选择成功
        """
        try:
            # 找到label对应的form-item
            labels = self.page.locator(".ant-form-item-label")
            target_selector = None
            for i in range(labels.count()):
                if label_text in labels.nth(i).inner_text():
                    fi = labels.nth(i).evaluate("el => el.closest('.ant-form-item')")
                    if fi:
                        target_selector = labels.nth(i)
                        break

            if target_selector is None:
                logger.warning(f"[Select] 未找到label '{label_text}'")
                return False

            # 点击该form-item内的.ant-select-selector打开下拉
            selector_loc = target_selector.locator(
                "xpath=ancestor::div[contains(@class,'ant-form-item')]"
                "//div[contains(@class,'ant-select-selector')]"
            ).first
            if selector_loc.count() == 0:
                # 兜底: combobox role
                selector_loc = self.page.get_by_role("combobox", name=label_text)
                if selector_loc.count() == 0:
                    return False
                selector_loc = selector_loc.locator(
                    "xpath=ancestor::div[contains(@class,'ant-select-selector')]"
                ).first

            selector_loc.click()
            self.page.wait_for_timeout(600)

            # 选择选项(JS click绕过Ant Select虚拟滚动可见性问题)
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
            logger.warning(f"[Select] 未找到选项 '{option_text}'")
            return False
        except Exception as e:
            logger.error(f"[Select] 选择 '{label_text}'='{option_text}' 失败: {e}")
            try:
                self.page.keyboard.press("Escape")
            except Exception:
                pass
            return False

    def _set_app_priority(self, app_label: str, prio: int) -> bool:
        """设置自定义场景下某类应用的优先级(0-7)"""
        return self._select_ant_option(app_label, str(prio))

    def switch_mode(self, mode: str = "intelligent", scene: str = None,
                    ports: str = None, app_priorities: dict = None) -> bool:
        """
        切换流控模式(跳转切换模式独立页 -> 配置 -> 保存 -> 跳回主页)

        Args:
            mode: "intelligent"(智能) / "manual"(手动)
            scene: 流控场景(仅智能模式), 自定义/网页优先/游戏优先/休闲娱乐/下载优先
            ports: 网页优先端口(仅网页优先场景), 如 "80,443"
            app_priorities: 自定义场景的应用优先级dict, 如 {"网页浏览": 1, "网络游戏": 0}

        Returns:
            是否切换保存成功(结果导向: 跳回主页)
        """
        try:
            self.navigate_to_stream_control()
            self.page.wait_for_timeout(800)

            # 点"切换模式"按钮(确保在主页)
            if self._on_switch_mode_page():
                pass
            else:
                switch_btn = self.page.locator("button:has-text('切换模式')")
                if switch_btn.count() == 0:
                    # 可能流控未开启, 先开启
                    if not self.is_stream_control_enabled():
                        self.enable_stream_control()
                        self.navigate_to_stream_control()
                        self.page.wait_for_timeout(800)
                    switch_btn = self.page.locator("button:has-text('切换模式')")
                if switch_btn.count() == 0:
                    logger.error("[切换模式] 未找到'切换模式'按钮")
                    return False
                switch_btn.first.click()
                self.page.wait_for_timeout(1500)
                self.page.wait_for_load_state("networkidle")

            # 等待切换模式页加载
            try:
                self.page.wait_for_selector(".ant-radio-wrapper", timeout=10000)
            except Exception:
                self.page.wait_for_timeout(1000)

            # 选模式radio
            mode_text = "智能模式" if mode == "intelligent" else "手动模式"
            mode_radio = self.page.locator(f".ant-radio-wrapper:has-text('{mode_text}')")
            if mode_radio.count() > 0:
                # 检查是否已选中
                is_checked = mode_radio.first.evaluate(
                    "el => !!el.querySelector('.ant-radio-checked')"
                )
                if not is_checked:
                    mode_radio.first.click()
                    self.page.wait_for_timeout(800)
                logger.info(f"[切换模式] 选择模式: {mode_text}")
            else:
                logger.warning(f"[切换模式] 未找到模式radio '{mode_text}'")

            # 智能模式: 配置流控场景
            if mode == "intelligent" and scene:
                self.page.wait_for_timeout(500)
                if not self._select_ant_option("流控场景", scene):
                    logger.warning(f"[切换模式] 流控场景选择失败: {scene}")

                # 网页优先场景: 填端口
                if scene == "网页优先" and ports:
                    self.page.wait_for_timeout(500)
                    port_input = self.page.get_by_role("textbox", name="网页优先端口")
                    if port_input.count() > 0:
                        port_input.click()
                        self.page.keyboard.press("Control+a")
                        port_input.type(ports, delay=30)
                        self.page.wait_for_timeout(300)
                        logger.info(f"[切换模式] 网页优先端口: {ports}")

                # 自定义场景: 设置应用优先级
                # 应用优先级combobox是Ant Form字段(名=数据库字段Http/Game/Im等),
                # _select_ant_option逐个选不稳(虚拟滚动+时序), 用Form.setFieldsValue直达
                if scene == "自定义" and app_priorities:
                    self.page.wait_for_timeout(800)
                    field_map = {"网页浏览": "Http", "网络游戏": "Game", "社交通讯": "Im",
                                 "传输下载": "Transport", "休闲娱乐": "Relax", "效率工具": "Utils",
                                 "办公协作": "Office", "学习教育": "Education", "生活服务": "Life",
                                 "金融理财": "Financial", "未知应用": "Unknown"}
                    fields_to_set = {field_map[k]: v for k, v in app_priorities.items()
                                     if k in field_map}
                    self.page.evaluate("""(fs) => {
                        const formEl = document.querySelector('form');
                        if (!formEl) return;
                        const fk = Object.keys(formEl).find(k => k.startsWith('__reactFiber$'));
                        let fiber = fk ? formEl[fk] : null;
                        while (fiber) {
                            if (fiber.memoizedProps && fiber.memoizedProps.form
                                && typeof fiber.memoizedProps.form.setFieldsValue === 'function') {
                                fiber.memoizedProps.form.setFieldsValue(fs);
                                return true;
                            }
                            fiber = fiber.return;
                        }
                    }""", fields_to_set)
                    logger.info(f"[切换模式] 应用优先级setFieldsValue: {fields_to_set}")

            # 保存
            save_btn = self.page.get_by_role("button", name="保存")
            if save_btn.count() > 0:
                save_btn.first.click()
            else:
                # 兜底: evaluate点击
                self.page.evaluate(
                    "() => { const b = Array.from(document.querySelectorAll('button'))."
                    "find(x => x.textContent.trim()==='保存'); if(b) b.click(); }"
                )
            self.page.wait_for_timeout(2000)
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(1000)

            # 结果导向: 跳回主页 = 成功
            if self._on_switch_mode_page():
                logger.warning(f"[切换模式] 保存后仍在切换模式页: {self.page.url}")
                return False

            logger.info(f"[切换模式] 模式切换成功: {mode_text}")
            return True
        except Exception as e:
            logger.error(f"[切换模式] 异常: {e}")
            return False

    # ==================== 流控线路tab ====================

    def navigate_to_line_config(self):
        """点击'流控线路'tab"""
        try:
            self.navigate_to_stream_control()
            tab = self.page.get_by_role("tab", name="流控线路")
            if tab.count() > 0:
                # tab名可能含question-circle, 用locator兜底
                tab.first.click()
            else:
                self.page.locator(".ant-tabs-tab:has-text('流控线路')").first.click()
            self.page.wait_for_timeout(1000)
            self.page.wait_for_load_state("networkidle")
        except Exception as e:
            logger.warning(f"[导航] 流控线路tab点击失败: {e}")
        return self

    def get_line_list(self) -> List[dict]:
        """读取流控线路表格(名称/线路/上行/下行/启用状态)"""
        lines = []
        try:
            self.page.wait_for_load_state("networkidle")
            self.page.wait_for_timeout(500)
            lines = self.page.evaluate('''() => {
                const rows = document.querySelectorAll('.ant-table-row');
                const result = [];
                rows.forEach(row => {
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length >= 5) {
                        const name = cells[0]?.textContent?.trim() || '';
                        const iface = cells[1]?.textContent?.trim() || '';
                        const upload = cells[2]?.textContent?.trim() || '';
                        const download = cells[3]?.textContent?.trim() || '';
                        const op = cells[4]?.textContent?.trim() || '';
                        if (name && name !== '暂无内容') {
                            result.push({
                                name: name,
                                interface: iface,
                                upload: upload,
                                download: download,
                                enabled: op.includes('停用')  // 有停用按钮=已启用
                            });
                        }
                    }
                });
                return result;
            }''')
        except Exception as e:
            logger.warning(f"[读取] 流控线路列表失败: {e}")
        return lines or []

    def find_line(self, line_name: str) -> Optional[dict]:
        """查找指定线路"""
        for ln in self.get_line_list():
            if ln["name"] == line_name or ln["interface"] == line_name:
                return ln
        return None

    def edit_line_bandwidth(self, line_name: str, upload: int,
                            download: int) -> bool:
        """
        编辑指定线路的上下行带宽(编辑弹窗)

        Args:
            line_name: 线路名(wan1/wan2/wan3)
            upload: 上行KB/s
            download: 下行KB/s

        Returns:
            是否保存成功
        """
        try:
            self.navigate_to_line_config()
            self.page.wait_for_timeout(500)

            # 找到该行的"编辑"按钮
            clicked = self.page.evaluate(f"""() => {{
                const rows = document.querySelectorAll('.ant-table-row');
                for (const row of rows) {{
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length > 0 && cells[0].textContent.trim() === '{line_name}') {{
                        const editBtn = Array.from(row.querySelectorAll('button')).find(
                            b => b.textContent.trim() === '编辑'
                        );
                        if (editBtn) {{ editBtn.click(); return true; }}
                    }}
                }}
                return false;
            }}""")
            if not clicked:
                logger.warning(f"[编辑线路] 未找到线路 {line_name} 的编辑按钮")
                return False

            self.page.wait_for_timeout(1000)

            # 等待编辑弹窗
            modal = self.page.locator(".ant-modal:not([style*='display: none'])").last
            try:
                modal.wait_for(state="visible", timeout=5000)
            except Exception:
                self.page.wait_for_timeout(500)

            # 填上下行(弹窗内的input)
            inputs = modal.locator("input")
            if inputs.count() >= 2:
                # 上行
                up_input = inputs.nth(0)
                up_input.click()
                self.page.keyboard.press("Control+a")
                self.page.keyboard.type(str(upload), delay=30)
                self.page.wait_for_timeout(300)
                # 下行
                down_input = inputs.nth(1)
                down_input.click()
                self.page.keyboard.press("Control+a")
                self.page.keyboard.type(str(download), delay=30)
                self.page.wait_for_timeout(300)
            else:
                logger.warning(f"[编辑线路] 弹窗输入框不足: {inputs.count()}")
                return False

            logger.info(f"[编辑线路] {line_name}: 上行={upload}, 下行={download}")

            # 点确定
            confirm_btn = modal.locator("button:has-text('确定')")
            if confirm_btn.count() == 0:
                confirm_btn = self.page.get_by_role("button", name="确定")
            confirm_btn.first.click()
            self.page.wait_for_timeout(1500)
            self.page.wait_for_load_state("networkidle")

            # 结果导向: 验证带宽已更新(重新读取表格)
            self.navigate_to_line_config()
            self.page.wait_for_timeout(800)
            ln = self.find_line(line_name)
            if ln and str(upload) in ln["upload"] and str(download) in ln["download"]:
                logger.info(f"[编辑线路] 带宽更新成功: {line_name}")
                return True
            logger.warning(f"[编辑线路] 带宽验证失败: 期望{upload}/{download}, 实际{ln}")
            return False
        except Exception as e:
            logger.error(f"[编辑线路] 异常: {e}")
            return False

    def enable_line(self, line_name: str) -> bool:
        """启用单条线路(点该行的'启用'按钮)"""
        return self._click_line_action(line_name, "启用")

    def disable_line(self, line_name: str) -> bool:
        """停用单条线路(点该行的'停用'按钮)"""
        return self._click_line_action(line_name, "停用")

    def _click_line_action(self, line_name: str, action: str) -> bool:
        """点击指定线路行的操作按钮(启用/停用)"""
        try:
            self.navigate_to_line_config()
            self.page.wait_for_timeout(500)
            clicked = self.page.evaluate(f"""() => {{
                const rows = document.querySelectorAll('.ant-table-row');
                for (const row of rows) {{
                    const cells = row.querySelectorAll('.ant-table-cell');
                    if (cells.length > 0 && cells[0].textContent.trim() === '{line_name}') {{
                        const btn = Array.from(row.querySelectorAll('button')).find(
                            b => b.textContent.trim() === '{action}'
                        );
                        if (btn) {{ btn.click(); return true; }}
                    }}
                }}
                return false;
            }}""")
            if clicked:
                self.page.wait_for_timeout(800)
                self._handle_confirm()
                self.page.wait_for_timeout(1500)
                logger.info(f"[线路操作] {line_name} {action}")
                return True
            return False
        except Exception as e:
            logger.warning(f"[线路操作] {line_name} {action} 失败: {e}")
            return False

    def enable_all_lines(self) -> bool:
        """全部启用(点'全部启用'按钮)"""
        return self._click_batch_line_button("全部启用")

    def disable_all_lines(self) -> bool:
        """全部停用(点'全部停用'按钮)"""
        return self._click_batch_line_button("全部停用")

    def _click_batch_line_button(self, button_name: str) -> bool:
        """点击全部启用/全部停用按钮(可能有确认弹窗)"""
        try:
            self.navigate_to_line_config()
            self.page.wait_for_timeout(500)
            btn = self.page.locator(f"button:has-text('{button_name}')")
            if btn.count() == 0:
                logger.warning(f"[批量] 未找到'{button_name}'按钮")
                return False
            btn.first.click()
            self.page.wait_for_timeout(800)
            self._handle_confirm()
            self.page.wait_for_timeout(2000)
            self.page.wait_for_load_state("networkidle")
            logger.info(f"[批量] {button_name}")
            return True
        except Exception as e:
            logger.warning(f"[批量] {button_name} 失败: {e}")
            return False

    def is_line_enabled(self, line_name: str) -> bool:
        """检查线路是否启用(有'停用'按钮=已启用)"""
        ln = self.find_line(line_name)
        return ln["enabled"] if ln else False

    # ==================== 辅助 ====================

    def _handle_confirm(self):
        """处理确认弹窗(确定)"""
        try:
            confirm_btn = self.page.locator(
                ".ant-modal-confirm button:has-text('确定'):visible, "
                ".ant-modal-wrap:not([style*='display: none']) button:has-text('确定')"
            )
            if confirm_btn.count() > 0 and confirm_btn.first.is_visible():
                confirm_btn.first.click()
                self.page.wait_for_timeout(500)
                return
            # 兜底
            ok = self.page.get_by_role("button", name="确定")
            if ok.count() > 0 and ok.first.is_visible():
                ok.first.click()
                self.page.wait_for_timeout(500)
        except Exception:
            pass

    def close_modal_if_exists(self):
        """关闭可能存在的弹窗"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(300)
            modal = self.page.locator(".ant-modal-wrap:not([style*='display: none'])")
            if modal.count() > 0:
                close = self.page.locator(".ant-modal-close")
                if close.count() > 0:
                    close.first.click()
                    self.page.wait_for_timeout(300)
        except Exception:
            pass
        return self
