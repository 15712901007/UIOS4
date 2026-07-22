"""威胁情报中心 Page Object。

安全中心 > 威胁情报中心包含六个一级页面。该功能在部分固件/授权状态下
默认关闭，因此本类把“页面能打开”和“功能已启用”分开报告，绝不把空白页
或没有明确反馈的点击当成成功。

已确认的路由（来自设备菜单配置）：

* ``threatSituation`` - 威胁态势
* ``threatMonitoring`` - 威胁监控
* ``iocManagement`` - IOC 管理
* ``hitAlarm`` - 命中告警（含 ``ioc_syslog`` 外界日志中心）
* ``eventResponse`` - 事件响应
* ``reportCenter`` - 报表中心（含 IOC 黑名单/白名单）

本模块的后端是设备函数脚本，而不是公开 REST API。``API_SPECS`` 保存的是
经实机/前端 chunk 确认的语义调用契约；``get_api_commands`` 只返回脱敏的
脚本描述，页面对象不会输出 IOC 值、IP、MAC、日志内容或认证信息。
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage


class ThreatIntelligencePage(BasePage):
    """威胁情报中心的导航、结构探测和通用 CRUD 操作。"""

    MODULE_NAME = "threat_intelligence"
    ROOT_PATH = "/securityCenter/threatIntelligence"

    # ``/login#/`` 是当前 Enterprise 固件入口，旧版固件使用 ``/#/``。
    ROUTES: Dict[str, str] = {
        "threatSituation": f"{ROOT_PATH}{{threatSituation}}",
        "threatMonitoring": f"{ROOT_PATH}{{threatMonitoring}}",
        "iocManagement": f"{ROOT_PATH}{{iocManagement}}",
        "hitAlarm": f"{ROOT_PATH}{{hitAlarm}}",
        "eventResponse": f"{ROOT_PATH}{{eventResponse}}",
        "reportCenter": f"{ROOT_PATH}{{reportCenter}}",
    }

    TAB_LABELS: Dict[str, str] = {
        "threatSituation": "威胁态势",
        "threatMonitoring": "威胁监控",
        "iocManagement": "IOC管理",
        "hitAlarm": "命中告警",
        "eventResponse": "事件响应",
        "reportCenter": "报表中心",
    }

    REPORT_ROUTES: Dict[str, str] = {
        "blackListManagement": f"{ROOT_PATH}{{reportCenter,blackListManagement}}",
        "whiteListManagement": f"{ROOT_PATH}{{reportCenter,whiteListManagement}}",
    }
    REPORT_LABELS: Dict[str, str] = {
        # 当前固件显示“黑名单管理/白名单管理”；兼容旧版 IOC 前缀见导航别名。
        "blackListManagement": "黑名单管理",
        "whiteListManagement": "白名单管理",
    }

    HIT_ALARM_ROUTES: Dict[str, str] = {
        "allHitAlarm": f"{ROOT_PATH}{{hitAlarm,allHitAlarm}}",
        "unprocessedHitAlarm": f"{ROOT_PATH}{{hitAlarm,unprocessedHitAlarm}}",
        "processingHitAlarm": f"{ROOT_PATH}{{hitAlarm,processingHitAlarm}}",
        "processedHitAlarm": f"{ROOT_PATH}{{hitAlarm,processedHitAlarm}}",
        "ignoreHitAlarm": f"{ROOT_PATH}{{hitAlarm,ignoreHitAlarm}}",
        "ioc_syslog": f"{ROOT_PATH}{{hitAlarm,ioc_syslog}}",
    }

    # 只记录语义参数；不要在这里加入账号、cookie、令牌或原始日志内容。
    API_SPECS: Dict[str, Tuple[Dict[str, Any], ...]] = {
        "overview": (
            {
                "function": "ioc_overview",
                "operation": "show",
                "type": "overview",
                "command": "ioc_overview show TYPE=overview",
            },
        ),
        "threatSituation": (
            {
                "function": "ioc_homepage",
                "operation": "show",
                "type": "ranking,threat_list,threat_list_total,high_processed",
                "filters": {"risk_level": "==3", "status": "==0"},
                "order": "desc",
                "order_by": "last_hit",
                "limit": "0,10",
                "time_range": "today",
                "command": (
                    "ioc_homepage show TYPE=ranking,threat_list,threat_list_total,high_processed "
                    "time_range=today limit=0,10 ORDER_BY=last_hit ORDER=desc "
                    "FILTER1=risk_level,==,3 FILTER2=status,==,0"
                ),
            },
        ),
        "threatMonitoring": (
            {
                "function": "ioc_monitor",
                "operation": "show",
                "type": "stats",
                "time_range": "today",
                "command": "ioc_monitor show TYPE=stats time_range=today",
            },
            {
                "function": "ioc_monitor",
                "operation": "show",
                "type": "threat_list,threat_list_total,processed",
                "filters": {"status": "==0"},
                "order": "desc",
                "order_by": "last_hit",
                "limit": "0,10",
                "time_range": "today",
                "command": (
                    "ioc_monitor show TYPE=threat_list,threat_list_total,processed "
                    "ORDER=desc FILTER1=status,==,0 time_range=today limit=0,10 "
                    "ORDER_BY=last_hit"
                ),
            },
        ),
        "iocManagement": (
            {
                "function": "ioc_detail",
                "operation": "show",
                "type": "search_history",
                "order": "desc",
                "order_by": "search_time",
                "command": "ioc_detail show ORDER_BY=search_time TYPE=search_history ORDER=desc",
            },
        ),
        "hitAlarm": (
            {
                "function": "ioc_alert",
                "operation": "show",
                "type": "trend",
                "time_range": "7d",
                "command": "ioc_alert show TYPE=trend time_range=7d",
            },
            {
                "function": "ioc_alert",
                "operation": "show",
                "type": "total,data",
                "order": "desc",
                "order_by": "event_time",
                "limit": "0,10",
                "command": "ioc_alert show limit=0,10 ORDER_BY=event_time TYPE=total,data ORDER=desc",
            },
            {
                "function": "ioc_alert",
                "operation": "show",
                "type": "total",
                "command": "ioc_alert show TYPE=total",
            },
            {
                "function": "ioc_alert",
                "operation": "show",
                "type": "stats",
                "command": "ioc_alert show TYPE=stats",
            },
            {
                "function": "ioc_alert",
                "operation": "show",
                "type": "status_count",
                "command": "ioc_alert show TYPE=status_count",
            },
        ),
        "ioc_syslog": (
            {
                "function": "ioc_syslog",
                "operation": "show",
                "type": "data",
                "command": "ioc_syslog show TYPE=data",
            },
        ),
        "eventResponse": (
            {
                "function": "ioc_policy",
                "operation": "show",
                "type": "total,data,member_count_total",
                "limit": "0,500",
                "command": "ioc_policy show TYPE=total,data,member_count_total limit=0,500",
            },
        ),
        "reportCenter": (
            {
                "function": "ioc_report",
                "operation": "show",
                "type": "threat_discovery",
                "time_range": "7d",
                "command": "ioc_report show TYPE=threat_discovery time_range=7d",
            },
            {
                "function": "ioc_report",
                "operation": "show",
                "type": "security_disposition",
                "time_range": "7d",
                "command": "ioc_report show TYPE=security_disposition time_range=7d",
            },
            {
                "function": "ioc_report",
                "operation": "show",
                "type": "high_risk_terminal",
                "time_range": "7d",
                "command": "ioc_report show TYPE=high_risk_terminal time_range=7d",
            },
            {
                "function": "ioc_report",
                "operation": "show",
                "type": "threat_trend",
                "time_range": "7d",
                "command": "ioc_report show TYPE=threat_trend time_range=7d",
            },
        ),
        "reportBlacklist": (
            {
                "function": "ioc_blacklist",
                "operation": "show",
                "type": "total,data",
                "limit": "0,10",
                "command": "ioc_blacklist show TYPE=total,data limit=0,10",
            },
        ),
        "reportWhitelist": (
            {
                "function": "ioc_whitelist",
                "operation": "show",
                "type": "total,data",
                "limit": "0,10",
                "command": "ioc_whitelist show TYPE=total,data limit=0,10",
            },
        ),
    }

    # 前端 chunk 中确认的语义字段。值不会从这里直接回传给报告。
    SEMANTIC_FIELDS: Dict[str, Tuple[str, ...]] = {
        "iocManagement": (
            "ioc_type", "ioc_value", "ioc_source", "ioc_ver", "malicious_family",
            "source_status", "mark_result", "first_seen", "update_time", "riskConclusion",
            "confidence", "list_status", "total_hits", "last_seen", "src_ip", "src_mac",
            "device_name", "department", "client_type", "processingStatus",
        ),
        "hitAlarm": (
            "event_time", "assetName", "behavior", "dst_ip", "deviceContent",
            "lastActiveTime", "MACAddress", "deviceType", "handleStatus", "alarmTime",
            "importantAlarm", "todayHitCount", "pendingAlarm", "currentAlarmCount",
            "highHitCount", "intelHitCount",
        ),
        "ioc_syslog": (
            "syslogServerStatus", "logServerAddress", "protocol", "port", "logFormat",
            "host", "connectionTest",
        ),
        "eventResponse": (
            "memberCountTotal", "member_count", "monitor", "block", "clear_counter",
            "alert_title", "alert_message", "category_1", "category_2", "category_3",
            "category_4", "category_5", "category_6", "category_7", "category_8",
            "category_9", "category_10", "category_11", "category_12", "category_13",
            "category_14", "category_15", "category_16", "category_17",
        ),
        "reportCenter": (
            "threat_discovery", "high_risk", "security_disposition", "auto_block",
            "add_blacklist", "manual_ban", "add_whitelist", "high_risk_terminal", "stage",
            "ongoing_hit", "isolated", "threat_trend", "phishing", "high_risk_site",
            "vs_yesterday", "vs_last_week", "vs_last_day", "this_week", "this_month",
            "this_day",
        ),
    }

    # page_structure() is consumed by reports and may be persisted for a long
    # time.  Keep this allow-list deliberately small and stable: DOM text is
    # inspected in-process, but only labels from this list are ever returned.
    # In particular, IOC values, host names, URLs, log bodies and chart data
    # must never become report text merely because they happen to be visible.
    UI_SEMANTIC_LABELS: Tuple[str, ...] = (
        # Primary tabs.
        "威胁态势", "威胁监控", "IOC管理", "命中告警", "事件响应", "报表中心",
        # Feature state and common page state.
        "开启", "开启威胁情报中心", "关闭威胁情报中心", "关闭威胁情报", "默认关闭", "未开启", "未启用",
        "功能关闭", "请开启", "已开启", "已启用", "功能开启", "加载中", "暂无数据",
        "无数据", "暂无记录", "空列表", "页面已加载", "表格", "图表",
        # Time ranges and dashboard labels.
        "今日", "昨日", "7天", "近7天", "30天", "近30天", "本周", "本月", "自定义",
        "威胁趋势", "威胁发现", "安全处置", "高风险终端", "活跃威胁", "威胁对象",
        "高危威胁", "待处理", "统计", "总数", "数量", "排名",
        # IOC management.
        "IOC", "搜索", "查询", "请输入", "IOC类型", "IOC值", "来源", "恶意家族",
        "风险结论", "置信度", "首次命中", "最近命中", "终端", "IP", "MAC", "处理状态",
        "详情", "查看", "历史记录", "搜索历史",
        # Hit alarms and its sub-pages.
        "全部告警", "未处理", "处理中", "已处理", "已忽略", "外界日志中心",
        "告警时间", "等级", "告警信息", "状态", "重要告警", "告警详情", "处理", "忽略",
        "加入黑名单", "加入白名单", "批量处理",
        # Syslog configuration.
        "Syslog", "日志服务器", "服务器状态", "日志服务器地址", "协议", "端口", "日志格式",
        "主机名", "连接测试", "连接成功", "连接失败", "未配置",
        # Event response policies.
        "情报类型", "监测", "阻断", "清除", "记录日志", "策略", "保存", "取消", "恢复默认",
        "启用", "停用",
        # Report center and blacklist/whitelist child pages.
        "黑名单管理", "白名单管理", "IOC黑名单", "IOC白名单", "对象", "生效时间",
        "添加黑名单", "添加白名单", "新增黑名单", "新增白名单", "导入", "导出", "编辑", "删除",
        "筛选", "重置", "确定", "关闭", "返回", "下一页", "上一页", "分页", "每页",
    )

    _SAFE_GENERIC_INPUT_LABELS = frozenset({"input", "textarea", "combobox", "checkbox", "radio"})

    _SENSITIVE_KEY = re.compile(
        r"(?:password|passwd|secret|token|cookie|authorization|credential|raw|original|"
        r"ioc[_-]?value|src[_-]?(?:ip|mac)|dst[_-]?ip|address|domain|url|log|message|remark)",
        re.I,
    )
    _IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = (base_url or "").rstrip("/")
        self.last_operation: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # URL and navigation
    # ------------------------------------------------------------------
    def _route_url_candidates(self, route: str) -> List[str]:
        route = route if route.startswith("/") else f"/{route}"
        base = self.base_url
        if not base:
            return [f"/login#{route}", f"/#{route.lstrip('/')}" ]
        if base.endswith("/login"):
            return [f"{base}#{route}", f"{base[:-6]}#{route.lstrip('/')}" ]
        return [f"{base}/login#{route}", f"{base}/#{route.lstrip('/')}" ]

    def _wait_settle(self, timeout: int = 15000, settle_ms: int = 800) -> None:
        try:
            self.page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception:
            # Action/message is a long poll on iKuai; networkidle is optional.
            pass
        if settle_ms:
            try:
                self.page.wait_for_timeout(settle_ms)
            except Exception:
                pass

    def _goto_route(self, route: str) -> bool:
        last_error = ""
        for url in self._route_url_candidates(route):
            try:
                self.page.goto(url, wait_until="domcontentloaded", timeout=20000)
                self._wait_settle()
                current = self.page.url or ""
                if route.split("{")[0] in current or "threatIntelligence" in current:
                    return True
                # Some SPA builds canonicalize to /login#/ and omit the route token
                # until React renders; a visible main element is still evidence.
                if self.page.locator("main:visible").count() > 0:
                    return True
            except Exception as exc:
                last_error = str(exc)[:180]
        self.last_operation = {"success": False, "error": last_error or "路由跳转失败"}
        return False

    @staticmethod
    def _key(value: str, mapping: Mapping[str, str]) -> Optional[str]:
        if value in mapping:
            return value
        norm = re.sub(r"\s+", "", str(value or "")).lower()
        for key, label in mapping.items():
            if norm == re.sub(r"\s+", "", label).lower():
                return key
        return None

    def navigate_to_threat_intelligence(self, tab: Optional[str] = None):
        """导航到根页面或指定一级页；返回 self 以兼容现有 fixture 链式调用。"""
        key = self._key(tab, self.TAB_LABELS) if tab else None
        if key:
            self.navigate_to_tab(key)
        else:
            self._goto_route(self.ROOT_PATH)
        return self

    navigate_to_threat_center = navigate_to_threat_intelligence
    navigate_to_ioc = navigate_to_threat_intelligence

    def navigate_to_landing(self):
        self.navigate_to_threat_intelligence()
        return self

    def open_landing(self) -> bool:
        self.navigate_to_landing()
        return self.ROOT_PATH in (self.page.url or "") or self.page.locator("main:visible").count() > 0

    def is_on_landing(self) -> bool:
        route = self._current_route_key()
        return route in {None, "threatIntelligence", "threatSituation"}

    def navigate_to_tab(self, tab: str):
        key = self._key(tab, self.TAB_LABELS)
        if key is None:
            raise ValueError(f"未知威胁情报页面: {tab}")
        # 六个页面是同一根路由下的 Ant Tabs。带花括号的菜单 path 只是
        # 权限配置占位符，直接 goto 会在当前固件返回 404。
        self._goto_route(self.ROOT_PATH)
        selected = self._click_ui_tab(self.TAB_LABELS[key])
        self.last_operation = {
            "success": bool(selected),
            "tab": key,
            "route": self.page.url,
            "error": "未找到或未选中目标 Tab" if not selected else "",
        }
        return self

    def open_tab(self, tab: str) -> bool:
        """打开一级页并验证路由/可见内容；未找到页面时返回 False。"""
        key = self._key(tab, self.TAB_LABELS)
        if key is None:
            return False
        self.navigate_to_tab(key)
        return self.is_tab_active(key)

    click_tab = open_tab

    def is_tab_active(self, tab: str) -> bool:
        key = self._key(tab, self.TAB_LABELS)
        if key is None:
            return False
        route_token = self.ROUTES[key].split("{")[-1].rstrip("}")
        current = self.page.url or ""
        # 仅当固件真的把 token 写入 hash 时才用 URL 作为证据；根路由本身
        # 不能证明当前选中的就是威胁态势。
        if route_token in current:
            return True
        label = self.TAB_LABELS[key]
        try:
            selected = self._main_scope().locator(
                "[role=tab][aria-selected='true'], .ant-tabs-tab-active, "
                "[role=menuitem][aria-selected='true'], [role=menuitem].ant-menu-item-selected"
            ).filter(has_text=label)
            if selected.count() > 0 and selected.first.is_visible():
                return True
            # A root route with content is not enough evidence: when the
            # feature is disabled the landing page also has content but no
            # tabs.  Do not infer a selected tab from that state.
            return False
        except Exception:
            return False

    @staticmethod
    def _make_tab_method(key: str):
        def method(self):
            return self.navigate_to_tab(key)
        method.__name__ = f"navigate_to_{key}"
        return method

    # Assigned after class definition below for readable explicit aliases.

    def navigate_to_report(self, child: Optional[str] = None):
        if child:
            return self.navigate_to_report_child(child)
        return self.navigate_to_tab("reportCenter")

    def navigate_to_report_child(self, child: str):
        aliases = {
            **self.REPORT_LABELS,
            "IOC黑名单": "黑名单管理",
            "IOC白名单": "白名单管理",
        }
        key = child if child in self.REPORT_ROUTES else None
        if key is None and child in {"IOC黑名单", "IOC白名单"}:
            key = "blackListManagement" if child == "IOC黑名单" else "whiteListManagement"
        if key is None:
            for candidate, label in self.REPORT_LABELS.items():
                if self._norm(child) == self._norm(label):
                    key = candidate
                    break
        if key is None:
            raise ValueError(f"未知报表子页: {child}")
        self.navigate_to_tab("reportCenter")
        selected = self._click_ui_tab(
            self.REPORT_LABELS[key], aliases=("IOC" + self.REPORT_LABELS[key],)
        )
        self.last_operation = {
            "success": bool(selected),
            "tab": key,
            "error": "未找到或未选中报表子页" if not selected else "",
        }
        return self

    def open_report_child(self, child: str) -> bool:
        try:
            self.navigate_to_report_child(child)
            return bool(self.last_operation.get("success"))
        except ValueError:
            return False

    def navigate_to_hit_alarm(self, view: Optional[str] = None):
        if view:
            view_aliases = {
                "全部告警": "allHitAlarm",
                "未处理": "unprocessedHitAlarm",
                "处理中": "processingHitAlarm",
                "已处理": "processedHitAlarm",
                "已忽略": "ignoreHitAlarm",
                "外界日志中心": "ioc_syslog",
            }
            key = view if view in self.HIT_ALARM_ROUTES else view_aliases.get(view)
            if key is None:
                key = next(
                    (candidate for candidate in self.HIT_ALARM_ROUTES if self._norm(candidate) == self._norm(view)),
                    None,
                )
            if key not in self.HIT_ALARM_ROUTES:
                raise ValueError(f"未知命中告警子页: {view}")
            self.navigate_to_tab("hitAlarm")
            # The current chunk renders five Ant tabs with short titles
            # ("全部", "未处理", "处理中", "已处理", "已忽略").  Older builds
            # used "全部告警", so retain it only as an alias.
            if key == "ioc_syslog":
                # menu.json marks Syslog ``isNotNav``: it is a separate child
                # route, not one of the five hit-alarm tabs.  Navigate to the
                # fixed hash and require a child-route/title read-back.  Some
                # builds render the editor inline on the hit-alarm page, so
                # that content is the first (and strongest) evidence.
                structure = self.page_structure()
                text = str(structure.get("main_text", ""))
                labels = ("日志服务器地址", "连接测试", "Syslog")
                has_content = any(label in text for label in labels)
                current = self.page.url or ""
                has_route = "ioc_syslog" in current.lower()
                has_syslog = has_content
                evidence = "embedded" if has_content else ""
                if not has_syslog:
                    self._goto_route(self.HIT_ALARM_ROUTES[key])
                    current = self.page.url or ""
                    structure = self.page_structure()
                    text = str(structure.get("main_text", ""))
                    has_content = any(label in text for label in labels)
                    has_route = "ioc_syslog" in current.lower()
                    has_syslog = has_content
                    evidence = "route" if has_content and has_route else ""
                if not has_syslog:
                    # Some builds only resolve ``isNotNav`` children through
                    # the left menu.  Try a visible menu item as a fallback,
                    # then perform the same content/route read-back.
                    try:
                        candidates = self.page.get_by_text("外界日志中心", exact=True)
                        for index in range(candidates.count()):
                            item = candidates.nth(index)
                            if not item.is_visible():
                                continue
                            item.click()
                            self._wait_settle(settle_ms=350)
                            current = self.page.url or ""
                            structure = self.page_structure()
                            text = str(structure.get("main_text", ""))
                            has_route = "ioc_syslog" in current.lower()
                            has_content = any(label in text for label in labels)
                            has_syslog = has_content
                            evidence = "menu" if has_content else ""
                            if has_syslog:
                                break
                    except Exception:
                        pass
                self.last_operation = {
                    "success": has_syslog,
                    "tab": key,
                    "route": "ioc_syslog" if has_route else "embedded",
                    "evidence": evidence or "none",
                    "error": "未取得外界日志中心子路由/页面复读" if not has_syslog else "",
                }
                return self
            labels = {
                "allHitAlarm": "全部",
                "unprocessedHitAlarm": "未处理",
                "processingHitAlarm": "处理中",
                "processedHitAlarm": "已处理",
                "ignoreHitAlarm": "已忽略",
            }
            aliases = ("全部告警",) if key == "allHitAlarm" else ()
            selected = self._click_ui_tab(labels.get(key, key), aliases=aliases)
            # If the default "全部" tab is already rendered without an
            # active-tab attribute, require its actual table content as the
            # fallback evidence rather than counting a bare DOM click.
            if key == "allHitAlarm" and not selected:
                text = str(self.page_structure().get("main_text", ""))
                selected = any(label in text for label in ("告警时间", "告警信息", "对象信息"))
            self.last_operation = {
                "success": bool(selected),
                "tab": key,
                "error": "未找到或未选中命中告警子页" if not selected else "",
            }
        else:
            self.navigate_to_tab("hitAlarm")
        return self

    def open_hit_alarm_view(self, view: str) -> bool:
        try:
            self.navigate_to_hit_alarm(view)
            return bool(self.last_operation.get("success"))
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Default-off feature switch and page structure
    # ------------------------------------------------------------------
    def _main_scope(self) -> Locator:
        main = self.page.locator("main:visible")
        return main.first if main.count() else self.page.locator("body")

    def _click_ui_tab(self, label: str, aliases: Sequence[str] = ()) -> bool:
        """在 main 内精确点击 Ant Tabs/子菜单，避免误点左侧导航。"""
        labels = [label, *aliases]
        scope = self._main_scope()
        for wanted in labels:
            try:
                for selector in (
                    "[role='tab']:visible",
                    ".ant-tabs-tab:visible",
                    "[role='menuitem']:visible",
                ):
                    loc = scope.locator(selector).filter(has_text=wanted)
                    if loc.count() == 0:
                        continue
                    chosen = None
                    for index in range(loc.count()):
                        item = loc.nth(index)
                        text = re.sub(r"\s+", "", item.inner_text() or "")
                        if text == re.sub(r"\s+", "", wanted):
                            chosen = item
                            break
                    chosen = chosen or loc.last
                    chosen.scroll_into_view_if_needed()
                    chosen.click(force=True)
                    self._wait_settle(settle_ms=400)
                    if self._selected_tab_has_text(labels):
                        return True
            except Exception:
                continue
        # 某些固件不给 role/active class，使用 DOM click 后复读。
        try:
            clicked = scope.evaluate(
                """(root, labels) => {
                    const norm=s=>(s||'').replace(/\\s+/g,'');
                    const visible=e=>!!(e && e.offsetParent!==null);
                    for (const e of root.querySelectorAll('[role=tab],.ant-tabs-tab,[role=menuitem]')) {
                        if (!visible(e)) continue;
                        if (labels.some(x=>norm(e.innerText)===norm(x))) { e.click(); return true; }
                    }
                    return false;
                }""",
                labels,
            )
            if clicked:
                self._wait_settle(settle_ms=400)
                # A DOM click only proves that an event handler ran.  It does
                # not prove that the requested view was selected; require an
                # explicit aria-selected/active-class read-back instead.
                return self._selected_tab_has_text(labels)
        except Exception:
            pass
        return False

    def _selected_tab_has_text(self, labels: Sequence[str]) -> bool:
        try:
            selected = self._main_scope().locator(
                "[role='tab'][aria-selected='true']:visible, "
                ".ant-tabs-tab-active:visible, "
                "[role='menuitem'].ant-menu-item-selected:visible"
            )
            for index in range(selected.count()):
                text = re.sub(r"\s+", "", selected.nth(index).inner_text() or "")
                if any(re.sub(r"\s+", "", label) in text for label in labels):
                    return True
        except Exception:
            pass
        return False

    def _feature_switch(self) -> Optional[Locator]:
        """只在 main 中找开关，避免误点左侧导航或用户菜单的控件。"""
        scope = self._main_scope()
        # Prefer the explicit global action.  Once the feature is enabled,
        # child pages contain many category/status switches whose ancestors
        # also mention generic threat text; selecting one of those would make
        # the reported global state incorrect.
        buttons = scope.locator("button:visible")
        for index in range(buttons.count()):
            item = buttons.nth(index)
            try:
                text = re.sub(r"\s+", "", item.inner_text() or "")
                if any(token in text for token in ("开启威胁情报中心", "关闭威胁情报中心", "关闭威胁情报")):
                    return item
            except Exception:
                continue
        candidates = scope.locator(
            ".ant-switch:visible, input[type='checkbox']:visible, input[type='radio']:visible, "
            "button:visible"
        )
        if candidates.count() == 0:
            return None
        # 优先选择同一表单项文字包含威胁/情报/监控/启用的控件。
        for index in range(candidates.count()):
            item = candidates.nth(index)
            try:
                if item.evaluate("el => el.tagName.toLowerCase() === 'button'"):
                    continue
                text = item.evaluate("""el => {
                    let p = el;
                    for (let i=0; i<6 && p; i++, p=p.parentElement) {
                        const t=(p.innerText||'').replace(/\\s+/g,'');
                        if (t) return t.slice(0,180);
                    }
                    return '';
                }""") or ""
                if re.search(r"威胁情报中心|威胁情报功能", text):
                    return item
            except Exception:
                continue
        # 默认关闭的威胁中心没有 switch，而是“开启”；启用后按钮文案为
        # “关闭威胁情报中心”。仅接受这几类明确文案，避免误点普通按钮。
        for index in range(candidates.count()):
            item = candidates.nth(index)
            try:
                text = re.sub(r"\s+", "", item.inner_text() or "")
                if text in {"开启", "开启威胁情报中心", "关闭威胁情报中心", "关闭威胁情报"}:
                    return item
            except Exception:
                continue
        return None

    @staticmethod
    def _control_state(control: Optional[Locator]) -> Optional[bool]:
        if control is None:
            return None
        try:
            return control.evaluate("""el => {
                const input = el.matches('input') ? el : el.querySelector('input');
                if (input) return !!input.checked;
                const value = el.getAttribute('aria-checked');
                if (value !== null) return value === 'true';
                if (el.tagName && el.tagName.toLowerCase()==='button') {
                    const text=(el.innerText||'').replace(/\\s+/g,'');
                    if (text.includes('关闭')) return true;
                    if (text.includes('开启')) return false;
                }
                return el.classList.contains('ant-switch-checked') ||
                    el.classList.contains('ant-checkbox-checked');
            }""")
        except Exception:
            return None

    def feature_state(self) -> Dict[str, Any]:
        """读取默认开关状态；``state`` 为 unknown 时表示页面未暴露开关。"""
        control = self._feature_switch()
        state = self._control_state(control)
        # The feature chunk is lazy-loaded after the root route.  A first
        # immediate read can therefore see an empty main element even though
        # the disabled-state switch is about to render.  Retry once after a
        # short settle; an unresolved second read remains ``unknown`` and is
        # intentionally treated as an environment/automation failure by the
        # comprehensive test.
        if control is None or state is None:
            try:
                self.page.wait_for_timeout(700)
            except Exception:
                pass
            control = self._feature_switch()
            state = self._control_state(control)
        text = ""
        try:
            text = (self._main_scope().inner_text() or "")[:1200]
        except Exception:
            pass
        if state is None:
            if re.search(r"默认关闭|未开启|未启用|功能关闭|请开启", text):
                semantic = "disabled"
            elif re.search(r"关闭威胁情报中心|已开启|已启用|功能开启", text):
                semantic = "enabled"
            else:
                semantic = "unknown"
        else:
            semantic = "enabled" if state else "disabled"
        return {
            "state": semantic,
            "enabled": state,
            "control_present": control is not None,
            "evidence": "switch" if control is not None else ("text" if semantic != "unknown" else "none"),
        }

    get_feature_state = feature_state

    def toggle_feature(self, enabled: bool) -> Dict[str, Any]:
        """切换威胁情报总开关，并复读 DOM 状态；没有明确复读则失败。"""
        before = self.feature_state()
        control = self._feature_switch()
        result: Dict[str, Any] = {
            "requested": bool(enabled),
            "before": before.get("state"),
            "success": False,
            "after": None,
            "error": "",
        }
        if control is None:
            result["error"] = "当前页面未发现威胁情报开关（可能是授权关闭或页面未加载）"
            self.last_operation = result
            return result
        current = self._control_state(control)
        if current is not None and current == bool(enabled):
            result.update(success=True, after="enabled" if current else "disabled", unchanged=True)
            self.last_operation = result
            return result
        try:
            control.scroll_into_view_if_needed()
            control.click(force=True)
            self._wait_settle(settle_ms=400)
            # 按钮切换可能弹出确认框；只有明确点击“确定”后才复读。
            confirm = self.page.locator(
                ".ant-modal-confirm:visible button:has-text('确定'), "
                ".ant-modal:visible button:has-text('确定')"
            )
            if confirm.count() > 0:
                confirm.last.click()
                self._wait_settle(settle_ms=500)
        except Exception as exc:
            result["error"] = str(exc)[:180]
            self.last_operation = result
            return result
        after = self.feature_state()
        result["after"] = after.get("state")
        result["success"] = after.get("enabled") is bool(enabled)
        if not result["success"]:
            result["error"] = "开关点击后没有观察到目标状态"
        self.last_operation = result
        return result

    def enable(self) -> bool:
        return bool(self.toggle_feature(True).get("success"))

    def disable(self) -> bool:
        return bool(self.toggle_feature(False).get("success"))

    enable_feature = enable
    disable_feature = disable
    enable_threat_intelligence = enable
    disable_threat_intelligence = disable

    @classmethod
    def _sanitize(cls, value: Any, key: str = "") -> Any:
        """把 API/DOM 值转换为可放入报告的语义摘要。"""
        if cls._SENSITIVE_KEY.search(str(key or "")):
            if value is None or value == "":
                return value
            return "<redacted>"
        if isinstance(value, Mapping):
            return {str(k): cls._sanitize(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._sanitize(v, key) for v in value[:100]]
        if isinstance(value, str):
            value = cls._IP.sub("<ip>", value)
            value = cls._MAC.sub("<mac>", value)
            return value[:240]
        return value

    @classmethod
    def _semantic_labels_from_text(cls, value: Any) -> List[str]:
        """Extract only approved UI labels from arbitrary DOM text.

        This deliberately does not return a redacted version of the source
        string.  Redaction is easy to bypass for domains, hashes, host names,
        or log payloads, whereas returning a fixed vocabulary is auditable.
        Longer labels win when they overlap (for example ``近7天`` over ``7天``).
        """
        source = re.sub(r"\s+", "", str(value or ""))
        if not source:
            return []
        lowered = source.casefold()
        candidates: List[Tuple[int, int, int, str]] = []
        for order, label in enumerate(cls.UI_SEMANTIC_LABELS):
            normalized = re.sub(r"\s+", "", label)
            if not normalized:
                continue
            if re.fullmatch(r"[A-Za-z0-9]+", normalized):
                # Avoid treating the ``ip`` in an input id/name as the UI
                # label ``IP``.  ASCII labels need word boundaries; a
                # Chinese character next to the label is intentionally fine.
                match = re.search(
                    rf"(?<![A-Za-z0-9]){re.escape(normalized.casefold())}(?![A-Za-z0-9])",
                    lowered,
                )
                start = match.start() if match else -1
            else:
                start = lowered.find(normalized.casefold())
            if start >= 0:
                # Sort by source position first, then prefer the longest
                # matching label at the same position.
                candidates.append((start, -len(normalized), order, label))
        candidates.sort()
        selected: List[Tuple[int, int, str]] = []
        for start, neg_length, _order, label in candidates:
            end = start - neg_length
            if any(start < old_end and end > old_start for old_start, old_end, _ in selected):
                continue
            selected.append((start, end, label))
        selected.sort(key=lambda item: item[0])
        result: List[str] = []
        for _start, _end, label in selected:
            if label not in result:
                result.append(label)
        return result

    @classmethod
    def _safe_label_list(
        cls,
        values: Any,
        *,
        generic_input: bool = False,
    ) -> List[str]:
        """Convert a DOM string list to a de-duplicated semantic label list."""
        if not isinstance(values, (list, tuple)):
            values = [values]
        result: List[str] = []
        for value in values:
            labels = cls._semantic_labels_from_text(value)
            if labels:
                for label in labels:
                    if label not in result:
                        result.append(label)
                continue
            if generic_input:
                raw = str(value or "").strip().casefold()
                if raw in cls._SAFE_GENERIC_INPUT_LABELS:
                    label = raw
                elif raw:
                    # Preserve only the control kind, never an id, name or
                    # placeholder that could contain a user-provided value.
                    label = "combobox" if "combo" in raw or "select" in raw else "input"
                else:
                    label = "input"
                if label not in result:
                    result.append(label)
        return result

    @classmethod
    def _safe_structure_url(cls, url: str) -> str:
        """Return a route-only identifier; never persist host/query/hash data."""
        # The route key is supplied separately by ``_current_route_key``.  A
        # constant marker here keeps the historical ``url`` field useful for
        # consumers without exposing a device address or query parameters.
        return "threat_intelligence"

    def page_structure(self) -> Dict[str, Any]:
        """读取当前页面结构和可测试能力，不把结构探测当成业务成功。"""
        try:
            data = self.page.evaluate("""() => {
                const visible=e=>!!(e && e.offsetParent!==null);
                const text=e=>(e?.innerText||e?.textContent||'').replace(/\\s+/g,' ').trim();
                const uniq=a=>[...new Set(a.filter(Boolean))].slice(0,100);
                const main=document.querySelector('main') || document.body;
                const tabs=[...document.querySelectorAll('[role=tab],.ant-tabs-tab')]
                    .filter(visible).map(text);
                const buttons=[...main.querySelectorAll('button')].filter(visible).map(text);
                const inputs=[...main.querySelectorAll('input,textarea,[role=combobox]')]
                    .filter(visible).map(e=>e.getAttribute('aria-label')||e.getAttribute('placeholder')||e.name||e.id||e.tagName.toLowerCase());
                const headers=[...main.querySelectorAll('th,[role=columnheader]')].filter(visible).map(text);
                const switches=[...main.querySelectorAll('.ant-switch,input[type=checkbox],input[type=radio]')]
                    .filter(visible).map(e=>({checked:e.checked===true || e.getAttribute('aria-checked')==='true' || e.classList.contains('ant-switch-checked')}));
                const charts=[...main.querySelectorAll('canvas,svg,[class*=chart],[class*=Chart]')].filter(visible).length;
                return {tabs:uniq(tabs),buttons:uniq(buttons),inputs:uniq(inputs),headers:uniq(headers),switches,charts,main_text:text(main).slice(0,2000)};
            }""")
        except Exception as exc:
            # Browser exceptions can embed a selector, URL or user value.
            # Keep only a stable diagnostic marker in report-facing data.
            data = {"error": "页面结构读取失败", "tabs": [], "buttons": [], "inputs": [], "headers": [], "switches": [], "charts": 0}

        # Do not rely on _sanitize() for free-form page text.  It masks a few
        # obvious patterns but cannot guarantee that a domain, hash, IOC or
        # log message is removed.  Convert every text-bearing field to the
        # fixed UI vocabulary before adding any report metadata.
        raw_tabs = data.get("tabs", []) if isinstance(data, Mapping) else []
        raw_buttons = data.get("buttons", []) if isinstance(data, Mapping) else []
        raw_inputs = data.get("inputs", []) if isinstance(data, Mapping) else []
        raw_headers = data.get("headers", []) if isinstance(data, Mapping) else []
        raw_main_text = data.get("main_text", "") if isinstance(data, Mapping) else ""
        tabs = self._safe_label_list(raw_tabs)
        buttons = self._safe_label_list(raw_buttons)
        inputs = self._safe_label_list(raw_inputs, generic_input=True)
        headers = self._safe_label_list(raw_headers)
        semantic = self._semantic_labels_from_text(raw_main_text)
        # Include labels found in the separately collected controls so a
        # virtualized table or tab strip remains testable even when its text
        # is outside the selected ``main`` element.
        for values in (tabs, buttons, inputs, headers):
            for label in values:
                if label not in semantic:
                    semantic.append(label)
        charts = data.get("charts", 0) if isinstance(data, Mapping) else 0
        if not semantic:
            if headers:
                semantic.append("表格")
            elif charts:
                semantic.append("图表")
            elif isinstance(data, Mapping) and "error" not in data:
                semantic.append("页面已加载")
        safe_data: Dict[str, Any] = {
            "tabs": tabs,
            "buttons": buttons,
            "inputs": inputs,
            "headers": headers,
            "switches": [
                {"checked": bool(item.get("checked"))}
                for item in (data.get("switches", []) if isinstance(data, Mapping) else [])
                if isinstance(item, Mapping)
            ],
            "charts": int(charts or 0) if str(charts or "0").isdigit() else 0,
            "main_text": " | ".join(semantic),
        }
        if isinstance(data, Mapping) and data.get("error"):
            safe_data["error"] = "页面结构读取失败"
        data = safe_data
        data = self._sanitize(data)
        data.update({
            "url": self._safe_structure_url(self.page.url),
            "feature": self.feature_state(),
            "route": self._current_route_key(),
        })
        data["capabilities"] = self.capabilities(data)
        return data

    get_page_structure = page_structure

    def _current_route_key(self) -> Optional[str]:
        url = self.page.url or ""
        for key, route in {**self.ROUTES, **self.REPORT_ROUTES, **self.HIT_ALARM_ROUTES}.items():
            token = route.split("{")[-1].rstrip("}")
            if token and token in url:
                return key
        if self.ROOT_PATH in url:
            return "threatIntelligence"
        return None

    def capabilities(self, structure: Optional[Mapping[str, Any]] = None) -> Dict[str, bool]:
        """以当前 DOM 证据计算能力；未渲染/授权关闭时返回 False。"""
        structure = structure or {}
        buttons = " ".join(map(str, structure.get("buttons", [])))
        inputs = " ".join(map(str, structure.get("inputs", [])))
        headers = structure.get("headers", []) or []
        return {
            "landing": self._current_route_key() in {None, "threatIntelligence", "threatSituation"},
            "feature_toggle": bool(structure.get("feature", {}).get("control_present")) if isinstance(structure.get("feature"), Mapping) else self._feature_switch() is not None,
            "tabs": len(structure.get("tabs", []) or []) >= 2,
            "search": bool(re.search(r"搜索|查询|请输入", inputs + buttons)),
            "read": bool(headers or structure.get("charts") or structure.get("main_text")),
            "create": bool(re.search(r"添加|新建", buttons)),
            "update": "编辑" in buttons,
            "delete": "删除" in buttons,
            "enable_disable": bool(re.search(r"启用|停用|开启|关闭", buttons)),
            "import_export": "导入" in buttons and "导出" in buttons,
        }

    get_capabilities = capabilities

    # ------------------------------------------------------------------
    # API contract / semantic observation
    # ------------------------------------------------------------------
    def get_api_commands(self, page: Optional[str] = None) -> List[Dict[str, Any]]:
        """返回脱敏脚本契约，不执行脚本。"""
        key = page or self._current_route_key() or "threatMonitoring"
        if key in self.REPORT_ROUTES:
            key = (
                "reportBlacklist" if key == "blackListManagement"
                else "reportWhitelist" if key == "whiteListManagement"
                else "reportCenter"
            )
        if key not in self.API_SPECS:
            key = "hitAlarm" if key in self.HIT_ALARM_ROUTES else key
        specs = self.API_SPECS.get(key, ())
        return [self._sanitize(copy.deepcopy(item)) for item in specs]

    api_contract = get_api_commands

    def api_call(
        self,
        function_or_page: Optional[str] = None,
        type: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        **params: Any,
    ) -> Dict[str, Any]:
        """返回一次 IOC 函数调用的语义结果。

        Page Object 不在浏览器中拼接或执行带认证上下文的 shell 命令；真实
        SSH 执行由后端 verifier 负责。本 helper 用于让测试/报告统一描述
        要调用的函数，并可对已经取得的响应 ``payload`` 做脱敏摘要。
        ``function_or_page`` 可以是页面 key（如 ``hitAlarm``）或函数名
        （如 ``ioc_alert``）。
        """
        requested = function_or_page or self._current_route_key() or "threatMonitoring"
        page_key = requested if requested in self.API_SPECS else None
        if page_key is None:
            for candidate, specs in self.API_SPECS.items():
                if any(item.get("function") == requested for item in specs):
                    page_key = candidate
                    break
        page_key = page_key or "threatMonitoring"
        specs = list(self.API_SPECS.get(page_key, ()))
        selected = [item for item in specs if not type or item.get("type") == type]
        if not selected:
            selected = specs[:1]
        spec = copy.deepcopy(selected[0]) if selected else {
            "function": str(requested), "operation": "show", "type": type or "unknown"
        }
        # 只保留参数名/计数，绝不回传调用参数中的敏感值。
        semantic: Dict[str, Any] = {
            "function": spec.get("function"),
            "operation": spec.get("operation", "show"),
            "type": spec.get("type", type or "unknown"),
            "page": page_key,
            "requested": True,
            "executed": False,
            "parameter_names": sorted(str(k) for k in params),
        }
        if payload is not None:
            if isinstance(payload, Mapping):
                keys = [str(k) for k in payload.keys()]
                rows = payload.get("data") or payload.get("rows") or payload.get("list")
                semantic.update({
                    "response_keys": keys[:80],
                    "row_count": len(rows) if isinstance(rows, (list, tuple)) else None,
                    "has_total": any(k in payload for k in ("total", "count", "total_count")),
                    "status": self._sanitize(payload.get("status", payload.get("code", "")), "status"),
                })
            else:
                semantic["response_type"] = payload.__class__.__name__
            semantic["executed"] = True
        return self._sanitize(semantic)

    call_api = api_call

    def semantic_api_snapshot(self, page: Optional[str] = None) -> Dict[str, Any]:
        """返回调用类型、字段名和页面计数，不返回 API 原始值。"""
        key = page or self._current_route_key() or "threatMonitoring"
        commands = self.get_api_commands(key)
        fields = self.SEMANTIC_FIELDS.get(key, ())
        structure = self.page_structure()
        return {
            "page": key,
            "functions": sorted({item.get("function", "") for item in commands}),
            "types": [item.get("type", "") for item in commands],
            "semantic_fields": list(fields),
            "row_count": len(structure.get("headers", []) or []),
            "chart_count": structure.get("charts", 0),
            "feature_state": structure.get("feature", {}).get("state"),
        }

    get_api_snapshot = semantic_api_snapshot

    # ------------------------------------------------------------------
    # Generic field/form helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _norm(value: Any) -> str:
        return re.sub(r"[\s:*：]+", "", str(value or "")).lower()

    def _field_for_label(self, label: str) -> Optional[Locator]:
        wanted = self._norm(label)
        scope = self._main_scope()
        # Playwright's accessible label is preferable when the firmware exposes it.
        for exact in (True, False):
            try:
                loc = scope.get_by_label(label, exact=exact)
                for i in range(loc.count()):
                    if loc.nth(i).is_visible():
                        return loc.nth(i)
            except Exception:
                pass
        try:
            found = scope.locator("""xpath=.//*[contains(@class,'ant-form-item')][.//*[contains(@class,'ant-form-item-label')]]""").evaluate_all(
                """(items, wanted) => {
                    const norm=s=>(s||'').replace(/[\\s:*：]+/g,'').toLowerCase();
                    for (const item of items) {
                        if (!item.offsetParent) continue;
                        const lab=item.querySelector('.ant-form-item-label');
                        if (!lab || norm(lab.innerText)!==wanted && !norm(lab.innerText).includes(wanted)) continue;
                        const control=item.querySelector('input,textarea,[role=combobox],.ant-select-selector,.ant-switch');
                        if (control) { control.setAttribute('data-ti-field','1'); return true; }
                    }
                    return false;
                }""", wanted
            )
            if found:
                return scope.locator("[data-ti-field='1']:visible").first
        except Exception:
            pass
        # Last resort: placeholder/name/id contains the requested semantic key.
        try:
            loc = scope.locator("input:visible,textarea:visible,[role=combobox]:visible")
            for i in range(loc.count()):
                item = loc.nth(i)
                attrs = " ".join((item.get_attribute(a) or "") for a in ("placeholder", "name", "id", "aria-label"))
                if wanted and wanted in self._norm(attrs):
                    return item
        except Exception:
            pass
        return None

    def fill_field(self, label: str, value: Any) -> bool:
        field = self._field_for_label(label)
        if field is None:
            return False
        try:
            tag = field.evaluate("el => el.tagName.toLowerCase()")
            role = field.get_attribute("role") or ""
            if tag == "input" and (field.get_attribute("type") or "").lower() in {"checkbox", "radio"}:
                field.set_checked(bool(value), force=True)
            elif "combobox" in role or "ant-select" in (field.get_attribute("class") or ""):
                field.click(force=True)
                self._wait_settle(settle_ms=150)
                option = self.page.locator(
                    ".ant-select-dropdown:visible .ant-select-item-option, [role=option]:visible"
                ).filter(has_text=str(value)).first
                if option.count() == 0:
                    return False
                option.click()
            else:
                field.fill("" if value is None else str(value))
                try:
                    field.press("Tab")
                except Exception:
                    pass
            return True
        except Exception:
            return False

    def fill_form(self, fields: Mapping[str, Any]) -> Dict[str, Any]:
        filled: List[str] = []
        missing: List[str] = []
        for label, value in fields.items():
            if self.fill_field(str(label), value):
                filled.append(str(label))
            else:
                missing.append(str(label))
        result = {"success": bool(filled) and not missing, "filled": filled, "missing": missing}
        self.last_operation = result
        return result

    def read_form(self, fields: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        labels = list(fields or self.SEMANTIC_FIELDS.get(self._current_route_key() or "", ()))
        result: Dict[str, Any] = {}
        for label in labels:
            field = self._field_for_label(label)
            if field is None:
                continue
            try:
                value = field.input_value() if field.evaluate("el => 'value' in el") else field.inner_text()
                result[label] = self._sanitize(value, label)
            except Exception:
                continue
        return result

    def submit_form(self, action: Optional[str] = None) -> bool:
        names = [action] if action else ["保存", "确定", "提交", "查询", "搜索"]
        before_url = self.page.url
        try:
            before_modal_count = self.page.locator(".ant-modal:visible, .ant-drawer:visible").count()
        except Exception:
            before_modal_count = 0
        for name in names:
            if not name:
                continue
            try:
                button = self._main_scope().get_by_role("button", name=name, exact=True)
                if button.count() == 0:
                    button = self._main_scope().locator(f"button:visible:has-text('{name}')")
                if button.count() == 0:
                    continue
                button.last.click()
                self._wait_settle(settle_ms=500)
                error = self._visible_error_text()
                if error:
                    self.last_operation = {"success": False, "action": name, "error": error}
                    return False
                try:
                    modal_closed = self.page.locator(".ant-modal:visible, .ant-drawer:visible").count() < before_modal_count
                except Exception:
                    modal_closed = False
                success = bool(self._feedback_text()) or self.page.url != before_url or modal_closed
                # 对没有 toast/路由变化的 SPA 提交，不能自行算作成功；调用方
                # 仍可从 last_operation 中看到“已点击但无明确反馈”。
                self.last_operation = {
                    "success": success,
                    "submitted": True,
                    "action": name,
                    "error": "已点击但无明确成功反馈" if not success else "",
                }
                return success
            except Exception:
                continue
        self.last_operation = {"success": False, "error": "未找到可提交按钮"}
        return False

    def _visible_error_text(self) -> str:
        try:
            loc = self.page.locator(
                ".ant-message-error:visible, .ant-notification-notice-error:visible, "
                ".ant-alert-error:visible, .ant-form-item-explain-error:visible"
            )
            for index in range(loc.count() - 1, -1, -1):
                text = (loc.nth(index).inner_text() or "").strip()
                if text:
                    return self._sanitize(text)
        except Exception:
            pass
        return ""

    click_submit = submit_form

    def cancel_form(self) -> bool:
        try:
            button = self._main_scope().get_by_role("button", name="取消", exact=True)
            if button.count() == 0:
                return False
            button.last.click()
            self._wait_settle(settle_ms=300)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Search, table read and CRUD
    # ------------------------------------------------------------------
    def search(self, keyword: str, field: Optional[str] = None) -> bool:
        candidates: List[Locator] = []
        if field:
            item = self._field_for_label(field)
            if item is not None:
                candidates.append(item)
        try:
            candidates.extend([
                self._main_scope().get_by_placeholder("请输入搜索内容"),
                self._main_scope().get_by_placeholder("请输入IOC"),
                self._main_scope().locator("input[type='search']:visible"),
            ])
        except Exception:
            pass
        for loc in candidates:
            try:
                if loc.count() == 0:
                    continue
                item = loc.first
                item.fill(str(keyword))
                item.press("Enter")
                self._wait_settle(settle_ms=400)
                return True
            except Exception:
                continue
        return False

    search_ioc = search

    def clear_search(self) -> bool:
        return self.search("")

    def read_rows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """读取可见表格行，仅返回列名/状态等语义摘要并脱敏。"""
        try:
            rows = self._main_scope().locator(
                ".ant-table-row:visible, tbody tr:visible, [role='row']:visible"
            )
            out: List[Dict[str, Any]] = []
            for index in range(min(rows.count(), max(0, limit))):
                row = rows.nth(index)
                cells = row.locator("td,[role='cell']")
                values = [(cells.nth(i).inner_text() or "").strip() for i in range(cells.count())]
                out.append({"index": index, "cells": [self._sanitize(v) for v in values if v != ""]})
            return out
        except Exception:
            return []

    list_rows = read_rows
    read_list = read_rows

    def _row_for_identifier(self, identifier: str) -> Optional[Locator]:
        try:
            rows = self._main_scope().locator(
                ".ant-table-row:visible, tbody tr:visible, [role='row']:visible"
            )
            for index in range(rows.count()):
                row = rows.nth(index)
                if identifier in (row.inner_text() or ""):
                    return row
        except Exception:
            pass
        return None

    def _row_action(self, identifier: str, action: str) -> bool:
        row = self._row_for_identifier(identifier)
        if row is None:
            return False
        try:
            button = row.get_by_role("button", name=action, exact=True)
            if button.count() == 0:
                button = row.locator(f"button:visible:has-text('{action}')")
            if button.count() == 0:
                return False
            button.last.click()
            self._wait_settle(settle_ms=350)
            return True
        except Exception:
            return False

    def create(self, fields: Mapping[str, Any], submit: str = "保存") -> Dict[str, Any]:
        fill = self.fill_form(fields)
        if not fill["success"]:
            return {"success": False, "stage": "fill", **fill}
        submitted = self.submit_form(submit)
        return {"success": submitted, "stage": "submit", "filled": fill["filled"], "missing": fill["missing"]}

    create_rule = create
    create_ioc = create

    def update(self, identifier: str, fields: Mapping[str, Any], submit: str = "保存") -> Dict[str, Any]:
        if not self._row_action(identifier, "编辑"):
            return {"success": False, "stage": "open_edit", "error": "未找到编辑操作"}
        return self.create(fields, submit=submit)

    update_rule = update
    update_ioc = update

    def delete(self, identifier: str) -> Dict[str, Any]:
        if not self._row_action(identifier, "删除"):
            return {"success": False, "error": "未找到删除操作"}
        try:
            confirm = self.page.locator(
                ".ant-modal-confirm:visible button:has-text('确定'), "
                ".ant-modal:visible button:has-text('确定'), "
                "button:visible:has-text('确定')"
            )
            if confirm.count() == 0:
                return {"success": False, "error": "删除后未发现确认按钮"}
            confirm.last.click()
            self._wait_settle(settle_ms=600)
            return {"success": True, "identifier": "<redacted>"}
        except Exception as exc:
            return {"success": False, "error": str(exc)[:160]}

    delete_rule = delete
    delete_ioc = delete

    def _click_semantic_action(self, names: Sequence[str]) -> bool:
        for name in names:
            try:
                button = self._main_scope().get_by_role("button", name=name, exact=True)
                if button.count() == 0:
                    button = self._main_scope().locator(f"button:visible:has-text('{name}')")
                if button.count() > 0:
                    button.last.click()
                    self._wait_settle(settle_ms=300)
                    return True
            except Exception:
                continue
        return False

    def add_to_blacklist(self, identifier: Optional[str] = None, **fields: Any) -> Dict[str, Any]:
        if identifier and not self._row_action(identifier, "加入黑名单"):
            self._click_semantic_action(("加入黑名单", "添加黑名单", "Add Blacklist"))
        else:
            self._click_semantic_action(("加入黑名单", "添加黑名单", "Add Blacklist"))
        if fields:
            fill = self.fill_form(fields)
            if not fill["success"]:
                return {"success": False, "stage": "fill", **fill}
        ok = self.submit_form("确定") or self.submit_form("保存")
        return {"success": ok, "action": "blacklist"}

    def add_to_whitelist(self, identifier: Optional[str] = None, **fields: Any) -> Dict[str, Any]:
        if identifier and not self._row_action(identifier, "加入白名单"):
            self._click_semantic_action(("加入白名单", "添加白名单", "Add Whitelist"))
        else:
            self._click_semantic_action(("加入白名单", "添加白名单", "Add Whitelist"))
        if fields:
            fill = self.fill_form(fields)
            if not fill["success"]:
                return {"success": False, "stage": "fill", **fill}
        ok = self.submit_form("确定") or self.submit_form("保存")
        return {"success": ok, "action": "whitelist"}

    add_blacklist = add_to_blacklist
    add_whitelist = add_to_whitelist

    def open_detail(self, identifier: str) -> Dict[str, Any]:
        row = self._row_for_identifier(identifier)
        if row is None:
            return {"success": False, "error": "未找到目标行"}
        try:
            # IOC 管理通常以行点击或“详情”按钮打开 drawer。
            button = row.get_by_role("button", name="详情", exact=True)
            if button.count() == 0:
                button = row.get_by_role("button", name="查看", exact=True)
            if button.count() > 0:
                button.last.click()
            else:
                row.click()
            self._wait_settle(settle_ms=350)
            drawer = self.page.locator(
                ".ant-drawer-content:visible, .ant-modal-content:visible"
            ).last
            if drawer.count() == 0:
                return {"success": False, "error": "点击后未发现详情面板"}
            text = self._sanitize(drawer.inner_text())
            return {"success": True, "detail_present": True, "text": text}
        except Exception as exc:
            return {"success": False, "error": str(exc)[:160]}

    read_detail = open_detail

    # ------------------------------------------------------------------
    # Named helpers for the six pages (kept thin so tests can use semantic names)
    # ------------------------------------------------------------------
    def navigate_to_syslog(self):
        return self.navigate_to_hit_alarm("ioc_syslog")

    navigate_to_ioc_syslog = navigate_to_syslog

    def navigate_to_blacklist(self):
        return self.navigate_to_report_child("blackListManagement")

    def navigate_to_whitelist(self):
        return self.navigate_to_report_child("whiteListManagement")

    navigate_to_ioc_blacklist = navigate_to_blacklist
    navigate_to_ioc_whitelist = navigate_to_whitelist

    def get_overview(self) -> Dict[str, Any]:
        return self.semantic_api_snapshot("overview")

    def get_threat_situation(self) -> Dict[str, Any]:
        return self.semantic_api_snapshot("threatSituation")

    def get_monitor_data(self) -> Dict[str, Any]:
        return self.semantic_api_snapshot("threatMonitoring")

    def get_alert_data(self) -> Dict[str, Any]:
        return self.semantic_api_snapshot("hitAlarm")

    def get_policy_data(self) -> Dict[str, Any]:
        return self.semantic_api_snapshot("eventResponse")

    def get_report_data(self) -> Dict[str, Any]:
        return self.semantic_api_snapshot("reportCenter")

    def get_blacklist_data(self) -> Dict[str, Any]:
        return self.semantic_api_snapshot("reportBlacklist")

    def get_whitelist_data(self) -> Dict[str, Any]:
        return self.semantic_api_snapshot("reportWhitelist")

    def configure_syslog(self, fields: Mapping[str, Any]) -> Dict[str, Any]:
        """填写外界日志中心配置；字段值只在浏览器内使用，返回摘要。"""
        self.navigate_to_syslog()
        result = self.fill_form(fields)
        if not result.get("success"):
            return result
        submitted = self.submit_form("保存")
        return {"success": submitted, "filled": result.get("filled", []), "missing": result.get("missing", [])}

    save_syslog = configure_syslog

    def test_syslog_connection(self) -> Dict[str, Any]:
        self.navigate_to_syslog()
        clicked = self._click_semantic_action(("连接测试", "测试连接", "connectionTest"))
        return {"success": clicked, "action": "connection_test", "feedback": self._feedback_text()}

    def set_policy(self, identifier: str, fields: Mapping[str, Any]) -> Dict[str, Any]:
        """编辑事件响应策略；若页面只有开关而没有行编辑，返回明确失败。"""
        return self.update(identifier, fields, submit="保存")

    update_policy = set_policy

    def clear_policy_counter(self, identifier: Optional[str] = None) -> Dict[str, Any]:
        names = ("清除计数", "清空计数", "clear_counter")
        clicked = False
        if identifier:
            clicked = self._row_action(identifier, names[0])
        if not clicked:
            clicked = self._click_semantic_action(names)
        return {"success": clicked, "action": "clear_counter", "feedback": self._feedback_text()}

    def mark_alert_important(self, identifier: str) -> Dict[str, Any]:
        clicked = self._row_action(identifier, "标记重要") or self._row_action(identifier, "取消重要")
        return {"success": clicked, "action": "mark_important", "feedback": self._feedback_text()}

    star_alert = mark_alert_important

    def handle_alert(self, identifier: str, action: str = "处理") -> Dict[str, Any]:
        aliases = {
            "process": ("处理", "标记处理"),
            "ignore": ("忽略", "标记忽略"),
            "delete": ("删除",),
        }
        names = aliases.get(action, (action,))
        clicked = any(self._row_action(identifier, name) for name in names)
        return {"success": clicked, "action": action, "feedback": self._feedback_text()}

    process_alert = handle_alert

    def _feedback_text(self) -> str:
        """读取最近一条非敏感 toast 文案。"""
        try:
            loc = self.page.locator(
                ".ant-message-success:visible, .ant-message-error:visible, "
                ".ant-notification-notice:visible"
            )
            for index in range(loc.count() - 1, -1, -1):
                text = (loc.nth(index).inner_text() or "").strip()
                if text:
                    return self._sanitize(text)
        except Exception:
            pass
        return ""


# Explicit aliases keep IDE/test discovery friendly and avoid dynamic method names.
ThreatIntelligencePage.navigate_to_threat_situation = ThreatIntelligencePage._make_tab_method("threatSituation")
ThreatIntelligencePage.navigate_to_threat_monitoring = ThreatIntelligencePage._make_tab_method("threatMonitoring")
ThreatIntelligencePage.navigate_to_ioc_management = ThreatIntelligencePage._make_tab_method("iocManagement")
ThreatIntelligencePage.navigate_to_event_response = ThreatIntelligencePage._make_tab_method("eventResponse")
ThreatIntelligencePage.navigate_to_report_center = ThreatIntelligencePage._make_tab_method("reportCenter")

# Compatibility names used by older module fixtures.
IocPage = ThreatIntelligencePage
ThreatIntelPage = ThreatIntelligencePage
ThreatIntelligenceCenterPage = ThreatIntelligencePage


__all__ = [
    "ThreatIntelligencePage",
    "ThreatIntelligenceCenterPage",
    "ThreatIntelPage",
    "IocPage",
]
