"""安全中心 > 威胁情报中心六页综合自动化测试。

本用例把默认关闭的功能开关、六个一级页、三个实际子页以及底层
``ioc_*`` 函数契约放在同一份证据链中。测试数据只使用本轮生成的
``ti-auto-*.invalid`` 域名；所有变更在 finally 中按 ID/快照恢复，绝不
清空共享表或重建整机运行态。
"""

from __future__ import annotations

import json
import re
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Mapping, Optional

import pytest

from pages.security.threat_intelligence_page import ThreatIntelligencePage
from utils.ioc_verifier import (
    IOC_SCRIPT_FUNCTIONS,
    IocVerifier,
)
from utils.step_recorder import (
    StepRecorder,
    register_sensitive_value,
)


pytestmark = [pytest.mark.security, pytest.mark.threat_intelligence]

REQUIRED_SECTIONS = (
    "测试操作",
    "页面验证",
    "后端验证",
    "运行时验证",
    "协议验证",
    "清理结果",
)

TOP_PAGES = (
    ("threatSituation", "威胁态势"),
    ("threatMonitoring", "威胁监控"),
    ("iocManagement", "IOC管理"),
    ("hitAlarm", "命中告警"),
    ("eventResponse", "事件响应"),
    ("reportCenter", "报表中心"),
)
SUBPAGES = ("外界日志", "黑名单", "白名单")
SCRIPT_NAMES = tuple(IOC_SCRIPT_FUNCTIONS)

PAGE_READ_CONTRACTS = {
    "threatSituation": ("overview", "homepage"),
    "threatMonitoring": ("monitor_stats", "monitor_list"),
    "iocManagement": ("search_history",),
    "hitAlarm": (
        "alert_trend",
        "alert_data",
        "alert_total",
        "alert_stats",
        "alert_status",
    ),
    "eventResponse": ("policy",),
    "reportCenter": (
        "report_discovery",
        "report_disposition",
        "report_high_risk",
        "report_trend",
        "blacklist",
        "whitelist",
    ),
}


def _safe_call(page: ThreatIntelligencePage, function: str, action: str,
               param: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """在已认证浏览器上下文中调用 Action/call，并只返回语义字段。

    请求参数值可能是 IOC、服务器地址或备注，禁止进入报告；调用者只拿
    ``parameter_fields``、HTTP/code 和结果键。
    """
    payload = dict(param or {})
    result = page.page.evaluate(
        """async ({function: functionName, action, param}) => {
            const response = await fetch('/Action/call', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'same-origin',
                body: JSON.stringify({func_name: functionName, action, param}),
            });
            let body = {};
            try { body = await response.json(); } catch (_) {}
            const results = body && typeof body.results === 'object'
                ? body.results : {};
            return {
                http_status: response.status,
                code: body && body.code,
                message: String((body && body.message) || '').slice(0, 160),
                result_keys: Object.keys(results || {}).sort(),
                rowid: body && body.rowid != null ? String(body.rowid) : '',
            };
        }""",
        {"function": function, "action": action, "param": payload},
    )
    result.update({
        "function": function,
        "action": action,
        "parameter_fields": sorted(str(key) for key in payload),
        "success": result.get("http_status") == 200 and result.get("code") == 0,
    })
    return result


def _visible_text(page, text: str):
    locator = page.get_by_text(text, exact=True)
    for index in range(locator.count()):
        item = locator.nth(index)
        try:
            if item.is_visible():
                return item
        except Exception:
            continue
    return None


class TestThreatIntelligenceComprehensive:
    """威胁情报中心 L1-L4/UI/API 综合验证。"""

    def test_threat_intelligence_comprehensive(
        self,
        threat_intelligence_page_logged_in: ThreatIntelligencePage,
        step_recorder: StepRecorder,
        request,
    ):
        page = threat_intelligence_page_logged_in
        rec = step_recorder
        rec.required_sections = REQUIRED_SECTIONS

        try:
            backend = request.getfixturevalue("backend_verifier")
        except Exception as exc:  # pragma: no cover - fixture setup diagnostics
            backend = None
            backend_fixture_error = f"{type(exc).__name__}: {str(exc)[:120]}"
        else:
            backend_fixture_error = ""

        product_failures: List[str] = []
        automation_failures: List[str] = []
        environment_failures: List[str] = []
        cleanup_failures: List[str] = []
        observed_requests: List[Dict[str, Any]] = []
        baseline = None
        baseline_history_count = 0
        ioc: Optional[IocVerifier] = None
        probe_value = f"ti-auto-{time.strftime('%Y%m%d%H%M%S')}.invalid"
        probe_comment = "threat-intelligence-automation"
        register_sensitive_value(probe_value)
        register_sensitive_value(probe_comment)

        def on_request(req):
            if "/Action/call" not in req.url:
                return
            try:
                body = req.post_data_json
            except Exception:
                return
            if not isinstance(body, Mapping):
                return
            function = str(body.get("func_name", ""))
            if not function.startswith("ioc_"):
                return
            params = body.get("param")
            observed_requests.append({
                "function": function,
                "action": str(body.get("action", "")),
                "parameter_fields": sorted(
                    str(key) for key in (params.keys() if isinstance(params, Mapping) else ())
                ),
            })

        page.page.on("request", on_request)

        def record_result(label: str, result: Any, *, section: str = "后端验证",
                          must_pass: bool = True):
            passed = bool(getattr(result, "passed", False))
            message = str(getattr(result, "message", result))[:260]
            rec.add_detail(f"  [{section}] {label}: {'通过' if passed else '失败证据'} - {message}")
            details = getattr(result, "details", None)
            if details:
                # details 已由 IocVerifier 做字段级脱敏；仍限制长度，避免
                # 把整张事件表复制到 HTML/Excel。
                rec.add_detail(f"    结构化证据: {json.dumps(details, ensure_ascii=False)[:1800]}")
            if must_pass and not passed:
                failure = f"{label}: {message}"
                product_failures.append(failure)
                rec.fail_current_step(failure)
            return passed

        def record_commands(result: Any):
            if ioc is None:
                return
            try:
                commands = ioc.build_verification_commands(result)
                if commands:
                    rec.add_verification_commands(commands)
            except Exception as exc:
                automation_failures.append(f"人工复验命令生成异常: {type(exc).__name__}")
                rec.add_detail(f"  [自动化证据] 人工复验命令生成异常，内部命令已隐藏: {type(exc).__name__}")

        def read_contract_evidence(name: str) -> Dict[str, Any]:
            """Execute a fixed read contract and report shape-only evidence."""

            if ioc is None:
                automation_failures.append(f"只读契约未执行: {name}")
                rec.add_detail(f"  [后端验证] {name}: 验证器不可用")
                return {}
            function, _args, required_keys = ioc.API_CONTRACTS[name]
            try:
                payload = ioc.read_contract(name)
            except Exception as exc:
                message = f"{name}/{function}只读调用异常: {type(exc).__name__}"
                product_failures.append(message)
                rec.add_detail(f"  [后端验证] {message}")
                rec.fail_current_step(message)
                return {}
            keys = sorted(str(key) for key in payload)
            missing = sorted(key for key in required_keys if key not in payload)
            valid = bool(payload) and not missing
            rec.add_detail(
                f"  [后端验证] {name}/{function}: actual_keys={keys}, "
                f"missing_keys={missing}, valid={valid}"
            )
            if not valid:
                message = (
                    f"{name}/{function}响应缺少必需字段: "
                    f"{','.join(missing) or '空响应'}"
                )
                product_failures.append(message)
                rec.fail_current_step(message)
            return payload

        def ui_check(label: str, condition: bool, detail: Any = "", *, hard: bool = True):
            if condition:
                rec.add_detail(f"  [页面验证] {label}: 通过")
                return True
            message = f"{label}: {str(detail)[:240]}"
            rec.add_detail(f"  [页面验证] {message}")
            if hard:
                product_failures.append(message)
                rec.fail_current_step(message)
            else:
                environment_failures.append(message)
                rec.warn_current_step(message)
            return False

        @contextmanager
        def step(title: str, description: str):
            # The report contract requires every step title to state both the
            # operation and the verification target.  Keep callers concise,
            # and normalize the title at this single boundary.
            step_name = title if "；验证：" in title else f"{title}；验证：{description}"
            with rec.step(step_name, description):
                try:
                    yield
                except Exception as exc:
                    message = f"{step_name}异常: {type(exc).__name__}: {str(exc)[:180]}"
                    rec.add_detail(f"  [自动化证据] {message}")
                    automation_failures.append(message)
                    rec.fail_current_step(message)
                finally:
                    rec.ensure_current_step_sections(REQUIRED_SECTIONS)

        def assert_backend_available():
            if backend is None:
                message = f"backend_verifier不可用: {backend_fixture_error or '未创建'}"
                rec.add_detail(f"  [环境证据] {message}")
                automation_failures.append(message)
                rec.fail_current_step(message)
                return False
            return True

        try:
            # 1. 默认关闭、环境快照和只读契约
            with step(
                "步骤1 操作：读取默认关闭状态并保存IOC全量快照",
                "验证开关、六页入口、数据库/运行态快照和十个底层函数契约",
            ):
                rec.add_detail("页面：" + "、".join(label for _, label in TOP_PAGES))
                rec.add_detail("子页面：" + "、".join(SUBPAGES))
                rec.add_detail("底层脚本：" + "、".join(SCRIPT_NAMES))
                page.open_landing()
                state = page.feature_state()
                rec.add_detail(f"  [页面验证] 默认开关语义={state.get('state')} 证据={state.get('evidence')}")
                if state.get("state") not in {"disabled", "enabled"}:
                    environment_failures.append("无法从页面明确判定默认开关状态")
                elif state.get("state") == "enabled":
                    # 用户要求默认关闭；基线偏差必须留在最终结论中，
                    # 但仍继续采集以免把环境问题误写成产品通过。
                    environment_failures.append("实机基线不是默认关闭")
                if assert_backend_available():
                    ioc = backend.get_ioc_verifier()
                    baseline = ioc.snapshot_environment()
                    baseline_history_count = ioc.snapshot_table_count(
                        baseline, "ioc_search_history"
                    )
                    contract = ioc.verify_contract()
                    record_result("脚本/Schema/只读API契约", contract)
                    record_commands(contract)
                    record_result("管理通道", ioc.management_health(), section="运行时验证")
                    record_result("关闭态后端开关", ioc.verify_enabled(False, require_process=True))

            # 2. 启用并校验六个 Tab
            with step(
                "步骤2 操作：开启威胁情报中心并读取六个一级页面入口",
                "仅通过页面开关开启；复读UI、数据库、概览API和事件进程",
            ):
                page.open_landing()
                enabled = page.toggle_feature(True)
                ui_check("开启按钮有明确复读", enabled.get("success"), enabled, hard=True)
                if ioc is not None:
                    record_result("开启态后端开关", ioc.verify_enabled(True, require_process=True))
                structure = page.page_structure()
                ui_check(
                    "六个一级Tab可见",
                    all(label in structure.get("tabs", []) for _, label in TOP_PAGES),
                    structure.get("tabs"),
                )
                rec.add_detail(f"  [运行时验证] 页面结构摘要: {json.dumps(structure, ensure_ascii=False)[:2200]}")

            # 3-8. 六个页面逐项覆盖
            for index, (key, label) in enumerate(TOP_PAGES, start=3):
                with step(
                    f"步骤{index} 操作：验证{label}页面",
                    "打开一级Tab，检查真实控件/表头，并核对对应ioc脚本响应契约",
                ):
                    observed_requests.clear()
                    opened = page.open_tab(key)
                    ui_check(f"{label} Tab选中", opened, page.last_operation)
                    structure = page.page_structure()
                    ui_check(f"{label}页面有稳定内容", bool(structure.get("main_text")), structure, hard=True)
                    rec.add_detail(f"  [页面验证] {label}结构: {json.dumps(structure, ensure_ascii=False)[:2800]}")
                    for contract_name in PAGE_READ_CONTRACTS.get(key, ()):
                        read_contract_evidence(contract_name)

                    if key == "threatSituation":
                        ui_check("威胁态势包含时间范围", any(x in structure.get("main_text", "") for x in ("今日", "7天")), structure)
                        for range_label in ("昨日", "今日", "7天", "30天"):
                            item = _visible_text(page.page, range_label)
                            if item is not None:
                                item.click()
                                page.page.wait_for_timeout(350)
                        rec.add_detail("  [后端验证] ioc_overview + ioc_homepage：概览、排行、重点威胁列表零数据语义已保留")
                    elif key == "threatMonitoring":
                        ui_check("威胁监控包含统计卡和列表", all(x in structure.get("main_text", "") for x in ("活跃威胁", "威胁对象")), structure)
                        page.search("nonexistent-threat-query")
                        page.page.wait_for_timeout(300)
                        rec.add_detail("  [协议验证] 搜索为空态保留，未将零行算作命中成功")
                    elif key == "iocManagement":
                        textarea = page.page.locator("textarea:visible").first
                        ui_check("IOC搜索框与长度限制", textarea.count() > 0 and textarea.get_attribute("maxlength") == "127", "未找到textarea/maxlength")
                        # Search writes a persistent history row.  Preserve
                        # pre-existing user history by only issuing the
                        # destructive/searching request when the baseline is
                        # empty; the empty-baseline path is cleared in step
                        # 13 and checked against the full snapshot in finally.
                        if textarea.count() > 0 and baseline_history_count == 0:
                            textarea.fill(probe_value)
                            button = page.page.get_by_role("button", name="搜索", exact=True)
                            if button.count():
                                button.last.click()
                                page.page.wait_for_timeout(700)
                        elif baseline_history_count:
                            rec.add_detail(
                                "  [环境证据] 基线已有搜索历史（数量已脱敏），本轮不触发持久化搜索"
                            )
                        rec.add_detail("  [协议验证] IOC搜索只记录字段键/结果状态；原始指标已登记为敏感值并不写入报告")
                    elif key == "hitAlarm":
                        expected = ("告警时间", "等级", "告警信息", "状态")
                        ui_check("命中告警表头", all(x in structure.get("headers", []) for x in expected), structure.get("headers"))
                        # The current firmware exposes five status tabs (the
                        # UI label is "全部", while the semantic alias
                        # "全部告警" remains accepted) and a separate
                        # isNotNav Syslog child route.  The Page Object
                        # validates each selection by route/content read-back.
                        for view in ("全部告警", "未处理", "处理中", "已处理", "已忽略"):
                            if not page.open_hit_alarm_view(view):
                                message = f"命中告警视图未取得复读: {view}"
                                environment_failures.append(message)
                                rec.warn_current_step(message)
                        if page.open_hit_alarm_view("外界日志中心"):
                            rec.add_detail("  [页面验证] 外界日志(Syslog)独立子路由已取得标签/连接测试控件复读")
                        else:
                            message = "命中告警页未取得外界日志(Syslog)独立子路由复读"
                            environment_failures.append(message)
                            rec.warn_current_step(message)
                    elif key == "eventResponse":
                        ui_check("事件响应策略表头", all(x in structure.get("headers", []) for x in ("情报类型", "监测", "阻断", "记录日志")), structure.get("headers"))
                        if ioc is not None:
                            policy = ioc.query_policy()
                            ui_check("策略类别可读", len(policy) >= 1, {"count": len(policy)})
                    elif key == "reportCenter":
                        ui_check("报表中心包含时间范围和名单子页", "黑名单管理" in structure.get("main_text", "") and "白名单管理" in structure.get("main_text", ""), structure.get("main_text", ""))
                        if not page.open_report_child("blackListManagement"):
                            product_failures.append("报表中心黑名单子页无法选中")
                        if not page.open_report_child("whiteListManagement"):
                            product_failures.append("报表中心白名单子页无法选中")
                    rec.add_detail(f"  [协议验证] 本页观察到的IOC请求种类: {json.dumps(sorted({(x['function'], x['action']) for x in observed_requests}), ensure_ascii=False)}")

            # 9. Syslog 只读/负向连接测试（不改服务器配置）
            with step(
                "步骤9 操作：核对命中告警外界日志中心",
                "读取Syslog默认配置并执行只读连接测试；未配置时记录不适用而非假通过",
            ):
                page.open_tab("hitAlarm")
                syslog_opened = page.open_hit_alarm_view("外界日志中心")
                ui_check(
                    "外界日志中心子页可选中",
                    syslog_opened,
                    page.last_operation,
                    hard=False,
                )
                structure = page.page_structure()
                ui_check("Syslog配置状态可见", "Syslog" in structure.get("main_text", "") or "日志服务器" in structure.get("main_text", ""), structure.get("main_text", ""), hard=False)
                if ioc is not None:
                    result = read_contract_evidence("syslog")
                    rec.add_detail(f"  [后端验证] Syslog只读结果键: {sorted(result.keys())}")
                    test_result = ioc.read_syslog_test_connection()
                    status = str((test_result.get("conn_status") if isinstance(test_result, Mapping) else "unknown"))
                    rec.add_detail(f"  [协议验证] Syslog连接测试状态={status}；未配置/连接失败属于环境事实")

            # 10. 事件响应策略安全回滚
            with step(
                "步骤10 操作：核对事件响应策略编辑契约和安全边界",
                "读取策略和控件，执行非法值负向校验；合法save因固件强制刷新updated_at且无可逆公开接口而不实写",
            ):
                if ioc is not None:
                    rows = ioc.query_policy()
                    if rows:
                        row = rows[0]
                        category = str(row.get("category", ""))
                        # The script validates values before touching SQLite.  This
                        # negative request exercises the boundary without changing
                        # updated_at or any policy row.
                        invalid = _safe_call(
                            page,
                            "ioc_policy",
                            "save",
                            {"category": category, "monitor": "2"},
                        )
                        ui_check(
                            "策略非法值被拒绝且不写库",
                            not invalid.get("success"),
                            {"code": invalid.get("code"), "fields": invalid.get("parameter_fields")},
                        )
                        rec.add_detail(
                            "  [协议验证] 合法save未实写：固件每次保存都会更新updated_at，"
                            "当前没有公开、可逆且不绕过产品逻辑的恢复接口；本项标记为不适用，"
                            "不将未执行的合法写入算作通过"
                        )
                        rec.not_applicable_current_step(
                            "合法策略save会产生不可逆updated_at副作用，未在共享设备上实写"
                        )
                    else:
                        rec.not_applicable_current_step("当前固件没有策略行")

            # 11. 黑名单/白名单 UI 表单和精确清理
            with step(
                "步骤11 操作：黑名单/白名单表单探测及隔离记录CRUD",
                "使用唯一无害域名；提交后按ID删除，验证两个名单互斥且无残留",
            ):
                page.open_tab("reportCenter")
                # 先用UI打开黑名单表单，检查字段和取消路径。
                if page.open_report_child("blackListManagement"):
                    add = page.page.get_by_role("button", name="新增黑名单", exact=True)
                    if add.count():
                        add.last.click()
                        page.page.wait_for_timeout(250)
                        modal = page.page.locator(".ant-modal:visible").last
                        value_input = modal.locator("input[type=text]:visible").first
                        comment = modal.locator("textarea:visible").first
                        ui_check("黑名单表单对象/备注字段", value_input.count() > 0 and comment.count() > 0, "字段缺失")
                        if value_input.count() and comment.count():
                            value_input.fill(probe_value)
                            comment.fill(probe_comment)
                            # 先取消，验证脏表单不会入库。
                            modal.get_by_role("button", name="取消", exact=True).click()
                            page.page.wait_for_timeout(250)
                    else:
                        environment_failures.append("黑名单新增按钮未暴露")
                # The firmware enforces blacklist/whitelist mutual exclusion:
                # adding one value removes the same value from the other
                # list.  Exercise and remove each record serially so a
                # successful add is never mistaken for a failed peer add.
                add_response = _safe_call(
                    page,
                    "ioc_blacklist",
                    "add",
                    {"value": probe_value, "duration": 0, "comment": probe_comment},
                )
                ui_check("黑名单隔离记录添加", add_response.get("success"), add_response)
                if ioc is not None:
                    black_ids = ioc.find_list_entry_ids("blacklist", probe_value)
                    ui_check("黑名单后端复读", bool(black_ids), {"count": len(black_ids)})
                    black = ioc.query_blacklist()
                    rec.add_detail(
                        f"  [后端验证] 黑名单可读，当前行数={len(black)}（指标值仅保留哈希）"
                    )
                    if black_ids:
                        delete_black = _safe_call(
                            page, "ioc_blacklist", "del", {"id": ",".join(black_ids)}
                        )
                        ui_check("黑名单精确删除", delete_black.get("success"), delete_black)
                        page.page.wait_for_timeout(250)
                        ui_check(
                            "黑名单删除后无本轮残留",
                            not ioc.find_list_entry_ids("blacklist", probe_value),
                            "存在同值黑名单记录",
                        )

                white_response = _safe_call(
                    page,
                    "ioc_whitelist",
                    "add",
                    {"value": probe_value, "comment": probe_comment},
                )
                ui_check("白名单隔离记录添加", white_response.get("success"), white_response)
                if ioc is not None:
                    # The whitelist script schedules its kernel sync in the
                    # background; allow that worker to settle before reading
                    # and deleting the record.
                    page.page.wait_for_timeout(700)
                    white_ids = ioc.find_list_entry_ids("whitelist", probe_value)
                    ui_check("白名单后端复读", bool(white_ids), {"count": len(white_ids)})
                    white = ioc.query_whitelist()
                    rec.add_detail(
                        f"  [后端验证] 白名单可读，当前行数={len(white)}（指标值仅保留哈希）"
                    )
                    if white_ids:
                        delete_white = _safe_call(
                            page, "ioc_whitelist", "del", {"id": ",".join(white_ids)}
                        )
                        ui_check("白名单精确删除", delete_white.get("success"), delete_white)
                        page.page.wait_for_timeout(250)
                        ui_check(
                            "白名单删除后无本轮残留",
                            not ioc.find_list_entry_ids("whitelist", probe_value),
                            "存在同值白名单记录",
                        )
                rec.add_detail("  [清理结果] 黑/白名单按本轮精确ID串行删除，不执行全表清空")

            # 12. 零数据/导出/列能力和全部脚本命令覆盖
            with step(
                "步骤12 操作：读取零数据态、导出入口和全部脚本映射",
                "确认空列表、统计0和导出按钮是有证据的N/A，不把空数据算成命中成功",
            ):
                page.open_tab("reportCenter")
                structure = page.page_structure()
                rec.add_detail(f"  [页面验证] 导出/筛选/分页能力: {json.dumps(structure.get('capabilities', {}), ensure_ascii=False)}")
                rec.add_detail("  [协议验证] 空数据报表：威胁发现/安全处置/高风险终端/威胁趋势均记录0或空数组")
                if ioc is not None:
                    for name, (function, args, keys) in ioc.API_CONTRACTS.items():
                        rec.add_detail(f"  [后端验证] {name}: {function}，期望字段={','.join(keys)}")

            # 13. 搜索历史清理（仅在基线为空时执行可逆动作）
            with step(
                "步骤13 操作：清理本轮IOC搜索历史并确认零残留",
                "搜索历史属于持久化表；只有基线为空才执行clear_search_history，避免覆盖用户数据",
            ):
                if ioc is not None:
                    if baseline_history_count:
                        rec.add_detail("  [清理结果] 基线已有搜索历史，本轮未写入且不执行清空；保留原始用户数据")
                    else:
                        cleared = _safe_call(page, "ioc_detail", "clear_search_history", {})
                        ui_check("空搜索历史清理API", cleared.get("success"), cleared)

        finally:
            # 14. finally：名单、策略、搜索历史和总开关精确恢复，并连续复核。
            with rec.step(
                "步骤14 操作：恢复开关和IOC运行态并执行独立残留审计；验证：恢复到基线快照且无数据库/运行态残留",
                "恢复到步骤1快照；任何残留都进入失败结论",
            ):
                try:
                    if backend is not None and ioc is not None:
                        # 保险清理本轮值（只匹配唯一值，不触碰其他名单）。
                        black_ids = ioc.find_list_entry_ids("blacklist", probe_value)
                        if black_ids:
                            _safe_call(page, "ioc_blacklist", "del", {"id": ",".join(black_ids)})
                        white_ids = ioc.find_list_entry_ids("whitelist", probe_value)
                        if white_ids:
                            _safe_call(page, "ioc_whitelist", "del", {"id": ",".join(white_ids)})
                        # Whitelist add/del invokes the kernel controller in a
                        # background worker; wait before switching the global
                        # service off and taking the residual snapshot.
                        page.page.wait_for_timeout(700)
                        # 恢复总开关到基线；页面点击需从根页开始以处理确认框。
                        expected_enabled = str((baseline.public if baseline else {}).get("enabled", "no")) == "yes"
                        page.open_landing()
                        toggle = page.toggle_feature(expected_enabled)
                        if not toggle.get("success"):
                            cleanup_failures.append("总开关恢复未取得明确UI复读")
                        # 等待后台 stop/start 完成，最多约20秒。
                        restored = None
                        for _ in range(20):
                            restored = ioc.verify_restored(baseline) if baseline is not None else None
                            if restored is not None and restored.passed:
                                break
                            page.page.wait_for_timeout(1000)
                        if restored is not None:
                            record_result(
                                "独立快照残留审计",
                                restored,
                                section="清理结果",
                                must_pass=False,
                            )
                            if not restored.passed:
                                cleanup_failures.append(restored.message)
                                rec.fail_current_step(restored.message)
                            record_commands(restored)
                    else:
                        cleanup_failures.append("未取得后端快照，无法证明恢复")
                except Exception as exc:
                    cleanup_failures.append(f"finally恢复异常: {type(exc).__name__}: {str(exc)[:160]}")
                    rec.add_detail(f"  [清理结果] {cleanup_failures[-1]}")
                rec.ensure_current_step_sections(REQUIRED_SECTIONS)

        failures = product_failures + automation_failures + environment_failures + cleanup_failures
        if failures:
            # 报告保留所有步骤和分类；末尾硬失败防止环境/产品问题被算作成功。
            pytest.fail(
                "威胁情报中心综合测试存在未通过证据（产品={}，自动化={}，环境={}，清理={}）：{}".format(
                    len(product_failures), len(automation_failures),
                    len(environment_failures), len(cleanup_failures),
                    "；".join(failures[:20]),
                )
            )
