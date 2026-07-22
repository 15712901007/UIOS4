"""
其他控制页面操作类 (安全中心 > 其他控制 > 网络分享控制)

URL: /login#/securityCenter/otherControl
单 tab "网络分享控制", 纯配置类页面(单表单 + 保存按钮, 无增删改查表格).

字段:
- 禁止二级路由 (nol2rt, checkbox id=nol2rt): 开启后夹制 WAN→LAN 转发包 TTL, 防下游私接二级路由
- 自定义TTL (ttl_num, number id=ttl_num): 夹制目标TTL值(前端placeholder 1-64 / 后端__check_param 1-255 不一致)
- 例外地址范围 (nol2rt_ip): custom IP(id=nol2rt_ip_custom_addCustom_0_list, "添加"展开) + IP分组(Ant Select)
- 禁止时间 (time, radio三模式):
    * 时间计划: combobox引用 route_object 时间计划(type=4)
    * 按周循环: 星期按钮(一二三四五六日, Playwright原生click, _weekItemActive类检测) + 开始/结束时间RangePicker
    * 时间段: 日期RangePicker (type=date)

后端 acl_l2route.sh:
- DB表 acl_l2route(id=1): nol2rt(int) / ttl_num(int) / nol2rt_ip(base64 JSON) / time(base64 JSON)
- 规则(nol2rt=1时): iptables -t mangle -I FORWARD -m timeset --timeset acl_l2rt_time_1 -m ttl --ttl-gt 1
  <WAN in> <LAN out> [-m set ! --match-set Linux_acl_l2rt dst] -j TTL --ttl-set <ttl_num>
- 时间: object_set.sh::__format_timeset 建 acl_l2rt_time_1 timeset(引用 _acl_l2rt_time_1周期表 + 时间计划分组)
- 例外: ipset Linux_acl_l2rt (dst方向, ! match = 不在例外集才夹)

交互踩坑(实测2026-07-14):
- nol2rt checkbox / radio / ttl_num: JS click与setter均触发React(同advanced_page)
- 星期按钮: 必须Playwright原生click(先JS注入data-wd属性), JS click与原生click混用会双击抵消
  选中态=className含_weekItemActive(取消后只剩false false)
- 保存前端不弹成功消息→用结果导向验证(reload读回对比 nol2rt/ttl_num, time/例外交SSH L1验证)
"""
from typing import Dict, List, Optional
from playwright.sync_api import Page
from pages.ikuai_table_page import IkuaiTablePage
import logging

logger = logging.getLogger(__name__)

# 星期映射: iKuai DB weekdays "1234567"(1=周一...7=周日) ↔ 中文按钮
WEEKDAY_CN = ["一", "二", "三", "四", "五", "六", "日"]  # index 0→周一(weekday 1)


class OtherControlPage(IkuaiTablePage):
    """其他控制页面对象(网络分享控制: 禁止二级路由+TTL+例外+禁止时间)"""

    PAGE_URL = "/login#/securityCenter/otherControl"
    MODULE_NAME = "other_control"

    NOL2RT_ID = "nol2rt"
    TTL_ID = "ttl_num"
    EXCEPT_INPUT_ID = "nol2rt_ip_custom_addCustom_0_list"
    TIMESET_NAME = "acl_l2rt_time_1"

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== JS交互辅助(绕浮层, 同advanced_page) ====================

    def _js_click_id(self, element_id: str) -> bool:
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
        try:
            return self.page.evaluate(f"""() => {{
                const el = document.getElementById('{element_id}');
                return el ? el.checked : false;
            }}""")
        except Exception:
            return False

    def _js_set_value(self, element_id: str, value: str) -> bool:
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

    def _js_eval(self, script: str, arg=None):
        """通用JS执行(带异常保护)"""
        try:
            return self.page.evaluate(script, arg)
        except Exception as e:
            logger.warning(f"[JS] eval异常: {str(e)[:80]}")
            return None

    # ==================== 导航 ====================

    def navigate_to_other_control(self):
        """导航到其他控制页面(强制reload确保表单与DB同步)"""
        url = f"{self.base_url}{self.PAGE_URL}"
        if 'otherControl' in self.page.url:
            self.page.reload()
        else:
            self.page.goto(url)
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(1500)
        logger.info("[导航] 已到达其他控制页面")

    # ==================== 读取配置 ====================

    def is_nol2rt_checked(self) -> bool:
        """读禁止二级路由开关状态"""
        return self._js_is_checked(self.NOL2RT_ID)

    def get_ttl_num(self) -> str:
        try:
            val = self.page.evaluate(f"""() => {{
                const el = document.getElementById('{self.TTL_ID}');
                return el ? el.value : '';
            }}""")
            return str(val).strip() if val else ""
        except Exception:
            return ""

    def get_time_mode(self) -> str:
        """读当前禁止时间模式(时间计划/按周循环/时间段, 取选中radio文本)"""
        return self._js_eval("""() => {
            const r = document.querySelector('.ant-radio-wrapper.ant-radio-wrapper-checked');
            if (!r) return '';
            const span = r.querySelector('.ant-radio + span');
            return span ? span.textContent.trim() : (r.textContent || '').trim();
        }""") or ""

    def get_selected_weekdays_cn(self) -> List[str]:
        """读按周循环模式选中的星期(中文列表), 非按周循环模式返回[]"""
        res = self._js_eval("""() => {
            const wrap = Array.from(document.querySelectorAll('*')).find(e => {
                const t = (e.textContent || '');
                return t.length < 30 && t.includes('一') && t.includes('二')
                    && t.includes('日') && !t.includes('禁止');
            });
            if (!wrap) return [];
            const btns = Array.from(wrap.querySelectorAll('*')).filter(b =>
                /^[一二三四五六日]$/.test((b.textContent || '').trim()) && b.children.length === 0);
            return btns.filter(b => (b.className || '').includes('_weekItemActive'))
                       .map(b => b.textContent.trim());
        }""") or []
        return res if isinstance(res, list) else []

    def get_config(self) -> Dict:
        """读全部易读配置(nol2rt/ttl_num/时间模式/选中星期)"""
        return {
            "nol2rt": self.is_nol2rt_checked(),
            "ttl_num": self.get_ttl_num(),
            "time_mode": self.get_time_mode(),
            "weekdays": self.get_selected_weekdays_cn(),
        }

    # ==================== 表单操作 ====================

    def toggle_nol2rt(self, enable: bool = True, wait: int = 300) -> bool:
        """切换禁止二级路由开关(当前!=目标才click, 3次重试). 返回是否达到目标状态."""
        current = self.is_nol2rt_checked()
        if current == enable:
            return True
        for attempt in range(3):
            self._js_click_id(self.NOL2RT_ID)
            self.page.wait_for_timeout(wait)
            if self.is_nol2rt_checked() == enable:
                logger.info(f"[操作] nol2rt: {'开启' if enable else '关闭'}(第{attempt+1}次)")
                return True
        logger.error(f"[操作] nol2rt切换到{'开启' if enable else '关闭'}失败(3次重试)")
        return False

    def set_ttl_num(self, value, wait: int = 400) -> bool:
        """设置自定义TTL值"""
        if self._js_set_value(self.TTL_ID, str(value)):
            self.page.wait_for_timeout(wait)
            logger.info(f"[操作] ttl_num: {value}")
            return True
        logger.error("[操作] 设置ttl_num失败")
        return False

    def select_time_mode(self, mode: str = "按周循环") -> bool:
        """选择禁止时间模式(时间计划/按周循环/时间段)"""
        ok = self._js_eval("""(tgt) => {
            const r = Array.from(document.querySelectorAll('.ant-radio-wrapper'))
                .find(x => (x.textContent || '').trim() === tgt);
            if (r) { r.click(); return true; }
            return false;
        }""", mode)
        self.page.wait_for_timeout(400)
        if ok:
            logger.info(f"[操作] 时间模式: {mode}")
        else:
            logger.error(f"[操作] 选时间模式[{mode}]失败")
        return bool(ok)

    # ---------- 星期按钮(按周循环模式, Playwright原生click) ----------

    def _ensure_weekday_data_attrs(self):
        """JS注入data-wd属性到星期按钮, 便于Playwright原生定位"""
        self._js_eval("""() => {
            const wrap = Array.from(document.querySelectorAll('*')).find(e => {
                const t = (e.textContent || '');
                return t.length < 30 && t.includes('一') && t.includes('二')
                    && t.includes('日') && !t.includes('禁止');
            });
            if (!wrap) return false;
            const btns = Array.from(wrap.querySelectorAll('*')).filter(b =>
                /^[一二三四五六日]$/.test((b.textContent || '').trim()) && b.children.length === 0);
            btns.forEach(b => b.setAttribute('data-wd', b.textContent.trim()));
            return btns.length;
        }""")

    def _is_weekday_selected(self, day_cn: str) -> bool:
        """读单个星期按钮选中态(_weekItemActive类)"""
        res = self._js_eval("""(d) => {
            const el = document.querySelector('[data-wd="' + d + '"]');
            return el ? (el.className || '').includes('_weekItemActive') : null;
        }""", day_cn)
        return bool(res)

    def toggle_weekday(self, day_cn: str, enable: bool, wait: int = 200) -> bool:
        """切换单个星期选中态(Playwright原生click, 仅当前!=目标才点, 避免双击抵消)"""
        self._ensure_weekday_data_attrs()
        current = self._is_weekday_selected(day_cn)
        if current == enable:
            return True
        try:
            self.page.locator(f'[data-wd="{day_cn}"]').click()
        except Exception as e:
            logger.warning(f"[星期] click[{day_cn}]异常: {str(e)[:60]}")
            return False
        self.page.wait_for_timeout(wait)
        after = self._is_weekday_selected(day_cn)
        if after != enable:
            logger.warning(f"[星期] {day_cn}切换失败: 目标{'选' if enable else '不选'}实际{'选' if after else '不选'}")
        return after == enable

    def set_weekdays(self, target_days_cn: List[str]) -> bool:
        """设置星期选中态为目标集合(只toggle差异项, 避免双击抵消).

        target_days_cn: 应选中的星期中文列表, 如['一','二','三','四','五','六','日'](全选)"""
        self._ensure_weekday_data_attrs()
        ok = True
        for day in WEEKDAY_CN:
            want = day in target_days_cn
            if not self.toggle_weekday(day, want):
                ok = False
        logger.info(f"[操作] 星期选中: {self.get_selected_weekdays_cn()} (目标{target_days_cn})")
        return ok

    # ---------- 时间范围(按周循环模式的开始/结束时间) ----------

    def set_time_range(self, start: str = "00:00", end: str = "23:59") -> bool:
        """设置开始/结束时间(Ant TimePicker, 默认全天).

        优先用TimePicker面板输入; 复杂场景默认值00:00-23:59即可(常开)."""
        # 默认值无需改动; 仅当需指定时尝试通过面板操作(此处提供基础实现)
        try:
            starts = self.page.locator('input[placeholder="开始时间"]')
            ends = self.page.locator('input[placeholder="结束时间"]')
            if starts.count() == 0 or ends.count() == 0:
                return start == "00:00" and end == "23:59"
            # 点击→清空→输入→回车(Ant TimePicker面板交互)
            for box, val in [(starts, start), (ends, end)]:
                box.first.click()
                self.page.wait_for_timeout(200)
                self.page.keyboard.press("Control+a")
                self.page.keyboard.type(val)
                self.page.wait_for_timeout(150)
                self.page.keyboard.press("Enter")
                self.page.wait_for_timeout(200)
            logger.info(f"[操作] 时间范围: {start}-{end}")
            return True
        except Exception as e:
            logger.warning(f"[时间范围] 设置异常(默认全天可忽略): {str(e)[:60]}")
            return False

    # ---------- 时间段(date范围) ----------

    def set_date_range(self, start_date: str, end_date: str) -> bool:
        """设置时间段日期范围(Ant RangePicker, YYYY-MM-DD).

        通过面板: 点开始框→输入start→Enter→点结束框→输入end→Enter."""
        try:
            # 时间段模式的RangePicker输入框(开始/结束日期)
            inputs = self.page.locator('.ant-picker input')
            if inputs.count() < 2:
                logger.warning("[时间段] 未找到日期RangePicker输入框")
                return False
            inputs.nth(0).click()
            self.page.wait_for_timeout(300)
            self.page.keyboard.press("Control+a")
            self.page.keyboard.type(start_date)
            self.page.wait_for_timeout(200)
            self.page.keyboard.press("Enter")
            self.page.wait_for_timeout(400)
            inputs.nth(1).click()
            self.page.wait_for_timeout(300)
            self.page.keyboard.press("Control+a")
            self.page.keyboard.type(end_date)
            self.page.wait_for_timeout(200)
            self.page.keyboard.press("Enter")
            self.page.wait_for_timeout(400)
            logger.info(f"[操作] 时间段日期: {start_date} ~ {end_date}")
            return True
        except Exception as e:
            logger.warning(f"[时间段] 设置异常: {str(e)[:80]}")
            return False

    # ---------- 例外地址范围 ----------

    def _ensure_exception_input(self) -> bool:
        """确保例外custom IP输入框存在(点'添加'展开). 返回输入框是否可用."""
        try:
            has = self.page.evaluate(f"""() => {{
                const el = document.getElementById('{self.EXCEPT_INPUT_ID}');
                return el && el.offsetParent !== null;
            }}""")
            if not has:
                self._js_click_button("添加")
                self.page.wait_for_timeout(400)
            return bool(self.page.evaluate(f"""() => {{
                const el = document.getElementById('{self.EXCEPT_INPUT_ID}');
                return el && el.offsetParent !== null;
            }}"""))
        except Exception:
            return False

    def add_exception_ip(self, ip: str, wait: int = 300) -> bool:
        """添加例外custom IP(点'添加'→填输入框)"""
        if not self._ensure_exception_input():
            logger.error("[例外] 无法展开custom IP输入框")
            return False
        ok = self.page.evaluate("""([id, val]) => {
            const el = document.getElementById(id);
            if (!el) return false;
            const desc = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
            if (desc && desc.set) desc.set.call(el, val);
            else el.value = val;
            el.dispatchEvent(new Event('input', {bubbles: true}));
            el.dispatchEvent(new Event('change', {bubbles: true}));
            return el.value === val;
        }""", [self.EXCEPT_INPUT_ID, str(ip)])
        self.page.wait_for_timeout(wait)
        logger.info(f"[操作] 例外custom IP: {ip}")
        return bool(ok)

    def select_exception_ipgroup(self, group_name: str) -> bool:
        """选例外IP分组(Ant Select: 点selector→选option)"""
        try:
            sel = self.page.locator('.ant-select').first
            sel.click()
            self.page.wait_for_timeout(500)
            # option文本精确匹配(可能含组合值, 用文本定位)
            opt = self.page.locator(f'.ant-select-item-option:has-text("{group_name}")').first
            if opt.count() == 0:
                logger.warning(f"[例外] IP分组option未找到: {group_name}")
                self.page.keyboard.press("Escape")
                return False
            opt.click()
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 例外IP分组: {group_name}")
            return True
        except Exception as e:
            logger.warning(f"[例外] 选IP分组异常: {str(e)[:60]}")
            return False

    def select_time_plan(self, plan_name: str) -> bool:
        """时间计划模式: 在禁止时间combobox选时间计划(plan_name=计划的tagname).

        ⚠️两个叠加bug(2026-07-15 select_time_plan假成功确诊, 实测验证修复):
        1. 切到'时间计划'模式后, Ant Select会默认选中第一个时间计划, combobox显示
           选中值而非placeholder → 旧逻辑靠placeholder含'时间计划'定位必失败(nofind).
           改用所在form-item的label'禁止时间'定位(稳定锚点, 避开例外IP分组select).
        2. 用evaluate里的selector.click()是JS click, 不触发Ant Select打开dropdown
           (React不响应) → option永远count=0. 改用Playwright原生.locator().click().
        (save_config不检查本方法返回值, 失败会被静默吞→保存默认选中项→L1 SSH才暴露,
         故本方法必须真实成功.) option异步加载→wait_for等渲染."""
        try:
            # 靠form-item label"禁止时间"定位combobox(不依赖placeholder, 避开例外IP分组)
            combo = self.page.locator(
                '.ant-form-item:has(.ant-form-item-label:has-text("禁止时间"))'
            ).locator('.ant-select-selector').first
            try:
                combo.wait_for(state="visible", timeout=3000)
            except Exception:
                logger.warning("[时间计划] 未找到禁止时间combobox(form-item label=禁止时间)")
                return False
            combo.click()  # Playwright原生click触发React打开dropdown(JS click无效)
            self.page.wait_for_timeout(700)
            # 等option异步加载渲染后点击(wait_for避count==0时序误判)
            opt = self.page.locator(f'.ant-select-item-option:has-text("{plan_name}")').first
            try:
                opt.wait_for(state="visible", timeout=3000)
            except Exception:
                logger.warning(f"[时间计划] option未渲染: {plan_name}")
                self.page.keyboard.press("Escape")
                return False
            opt.click()
            self.page.wait_for_timeout(300)
            logger.info(f"[操作] 引用时间计划: {plan_name}")
            return True
        except Exception as e:
            logger.warning(f"[时间计划] 选combobox异常: {str(e)[:60]}")
            return False

    # ==================== 保存 ====================

    def click_save(self, wait: int = 2500) -> bool:
        """点击保存按钮(JS click绕浮层)"""
        ok = self._js_click_button("保存")
        if ok:
            self.page.wait_for_timeout(wait)
        return ok

    def save_config(self, **fields) -> bool:
        """设置变化项+保存+结果导向验证(reload读回对比 nol2rt/ttl_num).

        kwargs: nol2rt(bool)/ttl_num(str|int)/time_mode(str)/weekdays(list)/
                time_range(tuple)/date_range(tuple)/exception_ip(str)/ipgroup(str).
                None不修改. time/例外的正确性交SSH L1验证(UI读回复杂).
        Returns: 保存是否成功(校验错误返回False, nol2rt/ttl_num未持久化返回False)."""
        try:
            if fields.get("nol2rt") is not None:
                self.toggle_nol2rt(fields["nol2rt"])
            if fields.get("ttl_num") is not None:
                self.set_ttl_num(fields["ttl_num"])
            if fields.get("time_mode"):
                self.select_time_mode(fields["time_mode"])
            if fields.get("time_plan"):
                self.select_time_plan(fields["time_plan"])
            if fields.get("weekdays") is not None:
                self.set_weekdays(fields["weekdays"])
            if fields.get("time_range") is not None:
                s, e = fields["time_range"]
                self.set_time_range(s, e)
            if fields.get("date_range") is not None:
                s, e = fields["date_range"]
                self.set_date_range(s, e)
            if fields.get("exception_ip"):
                self.add_exception_ip(fields["exception_ip"])
            if fields.get("ipgroup"):
                self.select_exception_ipgroup(fields["ipgroup"])
            self.page.wait_for_timeout(500)
            self.click_save()

            # 前端校验错误(非法值/必填缺失)
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

            # 结果导向验证: reload读回 nol2rt/ttl_num(易读字段)
            self.navigate_to_other_control()
            self.page.wait_for_timeout(800)
            actual = self.get_config()
            mismatches = []
            if fields.get("nol2rt") is not None and actual.get("nol2rt") != fields["nol2rt"]:
                mismatches.append(f"nol2rt:期望{fields['nol2rt']}实际{actual.get('nol2rt')}")
            if fields.get("ttl_num") is not None and actual.get("ttl_num") != str(fields["ttl_num"]):
                mismatches.append(f"ttl_num:期望{fields['ttl_num']}实际{actual.get('ttl_num')}")
            if mismatches:
                logger.error(f"[保存] 配置未持久化: {'; '.join(mismatches)}")
                return False
            logger.info(f"[保存] other_control配置保存成功(结果验证): {list(fields.keys())}")
            return True
        except Exception as e:
            logger.error(f"[保存] other_control配置保存异常: {e}")
            return False

    def disable_all(self) -> bool:
        """关闭禁止二级路由(清理用). 不清time/例外(nol2rt=0即不生效, SSH兜底清残留)."""
        try:
            self.navigate_to_other_control()
            self.page.wait_for_timeout(500)
            self.toggle_nol2rt(False)
            self.click_save()
            self.navigate_to_other_control()
            self.page.wait_for_timeout(500)
            return not self.is_nol2rt_checked()
        except Exception as e:
            logger.error(f"[恢复] disable_all异常: {e}")
            return False
