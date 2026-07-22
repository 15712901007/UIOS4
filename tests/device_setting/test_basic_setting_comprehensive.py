"""设备设置 > 基础设置 L1-L5 单节点综合测试。

本模块是高风险全局单例配置。任何持久化操作均在完整内存快照之后执行，
每个场景结束立即恢复，最外层 finally 再独立恢复和残留审计。系统时钟采用
“路由器相对客户端时差”语义快照，并通过产品 ``basic.sh set_time`` 恢复，
避免错误地把历史绝对时间戳写回正在流逝的系统时钟。
"""

from __future__ import annotations

import secrets
import string
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

import pytest

from pages.device_setting.basic_setting_page import BasicSettingPage
from utils.step_recorder import (
    StepRecorder,
    register_sensitive_value,
    register_sensitive_values,
)
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.device_setting, pytest.mark.basic_setting]

CLIENT_GATEWAY = "192.168.148.1"
CLIENT_IFACE = "ens11"
CLIENT_SOURCE = "192.168.148.2"
ROUTER_LAN_HOST = "192.168.148.1"
ROUTER_WAN_IFACE = "wan1"

EXPECTED_LISTEN_INTERFACES = frozenset({"lan1"})
EXPECTED_WAN_INTERFACES = frozenset({"wan1", "wan2", "wan3"})
EXPECTED_BUILTIN_NTP_LABELS = frozenset(
    {
        "默认",
        "中国国家授时中心时间服务器",
        "阿里云NTP时间服务器",
        "腾讯云NTP时间服务器",
        "百度云NTP时间服务器",
        "国际NTP时间服务器",
        "自定义",
    }
)
EXPECTED_TIME_ZONE_LABELS = frozenset(
    {
        "标准时间 （格林威治标准时）",
        "标准时间+01:00 （中欧时间、安哥拉、利比亚）",
        "标准时间+02:00 （东欧时间、加里宁格勒、南非）",
        "标准时间+03:00 （巴格达、科威特、利雅得、莫斯科）",
        "标准时间+03:30 （伊朗）",
        "标准时间+04:00 （阿布扎比、马斯喀特、巴库）",
        "标准时间+04:30 （阿富汗）",
        "标准时间+05:00 （叶卡捷琳堡、孟买、卡拉奇）",
        "标准时间+05:30 （印度、斯里兰卡）",
        "标准时间+05:45 （尼泊尔）",
        "标准时间+06:00 （科伦坡、达卡、新亚伯利亚）",
        "标准时间+06:30 （缅甸）",
        "标准时间+07:00 （曼谷、河内、雅马达）",
        "北京时间+08:00 （北京、香港、新加坡、马来西亚）",
        "标准时间+09:00 （东京、汉城、大阪）",
        "标准时间+09:30 （澳大利亚（新南威尔士州的布罗肯希尔,北领地,南澳大利亚州））",
        "标准时间+10:00 （澳大利亚东部、关岛）",
        "标准时间+10:30 （澳大利亚（豪勋爵群岛））",
        "标准时间+11:00 （马加丹、索罗门群岛）",
        "标准时间+11:30 （诺福克岛）",
        "标准时间+12:00 （奥克兰、惠灵顿、堪察加半岛）",
        "标准时间+12:45 （纽西兰）",
        "标准时间+13:00 （基里巴斯、汤加、萨摩亚群岛）",
        "标准时间+14:00 （基里巴斯（莱恩群岛））",
        "标准时间-01:00 （亚速尔群岛、佛得角群岛）",
        "标准时间-02:00 （中大西洋）",
        "标准时间-03:00 （巴西、布宜诺斯艾利斯、乔治敦）",
        "标准时间-03:30 （加拿大（纽芬兰省））",
        "标准时间-04:00 大西洋时间（加拿大、加拉加斯）",
        "标准时间-05:00 东部时间（美国、加拿大、波哥大）",
        "标准时间-06:00 中部时间（美国、加拿大、墨西哥）",
        "标准时间-07:00 山地时间（美国、加拿大）",
        "标准时间-08:00 美国西部标准时间（美国、加拿大）",
        "标准时间-09:00 （阿拉斯加）",
        "标准时间-09:30 （马克萨斯群岛）",
        "标准时间-10:00 （夏威夷）",
        "标准时间-11:00 （中途岛、萨摩亚群岛）",
        "标准时间-12:00 （贝克岛、豪兰岛）",
    }
)


def _token(length: int = 7) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


class TestBasicSettingComprehensive:
    """基础设置页面、DB、脚本、运行态、真实协议和恢复综合验证。"""

    def test_basic_setting_comprehensive(
        self,
        basic_setting_page_logged_in: BasicSettingPage,
        step_recorder: StepRecorder,
        request,
    ):
        page = basic_setting_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")

        automation_failures: List[str] = []
        product_failures: List[str] = []
        cleanup_failures: List[str] = []
        environment_warnings: List[str] = []
        snapshot: Optional[Dict[str, Any]] = None
        snapshot_valid = False
        snapshot_restore_authorized = False
        mutation_started = False
        unexpected_error: Optional[str] = None
        topology_evidence: Dict[str, Any] = {
            "listen_interface_options": 0,
            "wan_interface_options": 0,
            "client_route_via_router": False,
            "baseline_exact_route_absent": False,
            "baseline_management_bypasses_test_lan": False,
            "router_lan_route_present": False,
            "router_wan1_route_present": False,
        }

        report_sections = (
            "测试操作",
            "页面验证",
            "后端验证",
            "运行时验证",
            "协议验证",
            "清理结果",
        )
        rec.required_sections = report_sections

        def add_section(section: str, status: str, label: str, detail: str):
            rec.add_detail(f"【{section}】\n{status}：{label}；{detail}")

        def _append_failure(kind: str, message: str):
            if kind == "product":
                product_failures.append(message)
            elif kind == "cleanup":
                cleanup_failures.append(message)
            else:
                automation_failures.append(message)
            rec.fail_current_step(message)

        def ui_check(
            label: str,
            condition: Any,
            detail: str = "条件不成立",
            *,
            kind: str = "automation",
        ) -> bool:
            passed = bool(condition)
            add_section(
                "页面验证",
                "通过" if passed else "失败",
                label,
                "符合预期" if passed else str(detail or "条件不成立"),
            )
            if not passed:
                _append_failure(kind, f"页面验证-{label}：{detail or '条件不成立'}")
            return passed

        def warning(section: str, label: str, detail: str):
            message = f"{label}：{detail}"
            environment_warnings.append(message)
            add_section(section, "警告", label, detail)
            rec.warn_current_step(message)

        def not_applicable(section: str, label: str, detail: str, *, whole_step=False):
            add_section(section, "不适用", label, detail)
            if whole_step:
                rec.not_applicable_current_step(f"{label}：{detail}")

        def ssh_verify(
            label: str,
            verify_func: Callable,
            *args,
            must_pass: bool = False,
            kind: str = "product",
            section: Optional[str] = None,
            **kwargs,
        ):
            label_text = str(label)
            if section is None:
                if label_text.startswith(("清理", "finally")):
                    section = "清理结果"
                elif label_text.startswith("L5"):
                    section = "协议验证"
                elif label_text.startswith(("L3", "L4")):
                    section = "运行时验证"
                else:
                    section = "后端验证"
            try:
                result = verify_func(*args, **kwargs)
                passed = bool(getattr(result, "passed", False))
                message = str(getattr(result, "message", "无验证消息"))
                if not passed and kind == "environment" and not must_pass:
                    warning(section, label_text, message)
                else:
                    add_section(
                        section, "通过" if passed else "失败", label_text, message
                    )
                    if not passed and must_pass:
                        _append_failure(kind, f"后端验证-{label_text}：{message}")
                return result
            except Exception as exc:
                safe = type(exc).__name__
                if kind == "environment" and not must_pass:
                    warning(section, label_text, f"环境调用异常({safe})")
                else:
                    add_section(
                        section,
                        "失败" if must_pass else "警告",
                        label_text,
                        f"验证调用异常({safe})",
                    )
                    if must_pass:
                        _append_failure(kind, f"后端验证-{label_text}异常({safe})")
                return None

        if backend is not None:
            ssh_verify = attach_cmd_recording_to_closure(backend, rec, ssh_verify)

        def require_safety(label: str, result: Any):
            if result is None or not bool(getattr(result, "passed", False)):
                raise RuntimeError(f"安全前置失败：{label}")
            return result

        def save_form(values: Dict[str, Any], label: str) -> Optional[Dict[str, Any]]:
            nonlocal mutation_started
            fill = page.fill_form(values) if values else {
                "success": True,
                "failed_fields": [],
            }
            if not ui_check(
                f"{label}字段操作",
                fill.get("success"),
                f"未完成字段={fill.get('failed_fields', [])}",
            ):
                return None
            mutation_started = True
            saved = page.save_settings(timeout=12000)
            ui_check(
                f"{label}保存反馈",
                saved.get("success"),
                saved.get("error") or "没有明确成功反馈",
                kind="product",
            )
            api = dict(saved.get("api") or {})
            semantic = dict(api.get("semantic") or {})
            contract_ok = bool(
                api.get("requested")
                and api.get("responded")
                and api.get("function") == "basic"
                and api.get("action") == "save"
                and api.get("method") == "POST"
                and api.get("endpoint") == "/Action/call"
                and api.get("status") == 200
                and semantic.get("http_ok")
                and semantic.get("business_success") is not False
            )
            ui_check(
                f"{label}保存接口契约",
                contract_ok,
                "basic/save 的请求、响应状态或成功语义不完整",
                kind="product",
            )
            return saved

        def action_request_contract(result: Dict[str, Any], action: str) -> bool:
            """判断公开请求/响应契约，不读取请求参数或响应私有数据。"""
            api = dict((result or {}).get("api") or {})
            semantic = dict(api.get("semantic") or {})
            return bool(
                api.get("requested")
                and api.get("responded")
                and api.get("function") == "basic"
                and api.get("action") == action
                and api.get("method") == "POST"
                and api.get("endpoint") == "/Action/call"
                and api.get("status") == 200
                and semantic.get("http_ok")
            )

        def action_contract(result: Dict[str, Any], action: str) -> bool:
            """请求契约成立且业务返回明确成功。"""
            api = dict((result or {}).get("api") or {})
            semantic = dict(api.get("semantic") or {})
            return bool(
                action_request_contract(result, action)
                and (result or {}).get("success")
                and semantic.get("business_success") is not False
            )

        def client_referenced_manual_candidate(offset_seconds: int = 35):
            """只在内存返回由客户端epoch、路由器时区格式化的近距离值。"""
            try:
                candidate = backend.get_basic_manual_time_candidate(
                    offset_seconds
                )
                value = str((candidate or {}).get("display_value") or "")
                return value if len(value) == 19 else None
            except Exception:
                return None

        def verify_layers(
            label: str,
            expected: Dict[str, Any],
            *,
            nat: Optional[Sequence[int]] = None,
            link_mode: Optional[int] = None,
            fast_nat: Optional[int] = None,
            ntp: Optional[Sequence[int]] = None,
            reinit: bool = True,
        ):
            if snapshot is None:
                _append_failure("automation", f"{label}缺少基线快照")
                return
            page.page.wait_for_timeout(900)
            ssh_verify(
                f"L1-{label}数据库与非测试字段保护",
                backend.verify_basic_database,
                expected,
                snapshot=snapshot,
                must_pass=True,
            )
            ssh_verify(
                f"L2-{label}生成配置",
                backend.verify_basic_generated_state,
                expected,
                must_pass=True,
            )
            if nat is not None:
                ssh_verify(
                    f"L3-{label}上网模式运行态",
                    backend.verify_basic_nat_runtime,
                    int(nat[0]),
                    int(nat[1]),
                    must_pass=True,
                )
            if link_mode is not None:
                ssh_verify(
                    f"L3-{label}链路模式运行态",
                    backend.verify_basic_link_runtime,
                    int(link_mode),
                    must_pass=True,
                )
            if fast_nat is not None:
                ssh_verify(
                    f"L3-{label}加速运行态",
                    backend.verify_basic_acceleration_runtime,
                    int(fast_nat),
                    must_pass=True,
                )
            if ntp is not None:
                ssh_verify(
                    f"L3-{label}NTP运行态",
                    backend.verify_basic_ntp_runtime,
                    int(ntp[0]),
                    int(ntp[1]),
                    int(ntp[2]),
                    must_pass=True,
                )
            ssh_verify(
                f"L4-{label}全链路一致性",
                backend.verify_basic_runtime_consistency,
                expected,
                snapshot=snapshot,
                must_pass=True,
            )
            if reinit:
                ssh_verify(
                    f"L4-{label}basic.sh init重建",
                    backend.verify_basic_reinit,
                    expected,
                    snapshot=snapshot,
                    must_pass=True,
                )
                ssh_verify(
                    f"L1-{label}init后数据库保护",
                    backend.verify_basic_database,
                    expected,
                    snapshot=snapshot,
                    must_pass=True,
                )

        def _restore_with_retry(environment: Dict[str, Any]):
            result = None
            for attempt in range(3):
                result = backend.restore_basic_environment(environment)
                if getattr(result, "passed", False):
                    return result
                if attempt < 2:
                    time.sleep(1.2)
            return result

        if backend is not None:
            _restore_with_retry.__report_verifier__ = (
                backend.restore_basic_environment
            )

        def restore_baseline(label: str, *, final: bool = False) -> bool:
            nonlocal mutation_started
            if snapshot is None or not snapshot_restore_authorized:
                _append_failure("cleanup", f"{label}无法恢复：缺少有效快照")
                return False
            restored = ssh_verify(
                f"清理-{label}精确恢复",
                _restore_with_retry,
                snapshot,
                must_pass=True,
                kind="cleanup",
                section="清理结果",
            )
            unchanged = ssh_verify(
                f"清理-{label}环境指纹",
                backend.verify_basic_environment_unchanged,
                snapshot,
                True,
                must_pass=True,
                kind="cleanup",
                section="清理结果",
            )
            artifacts = None
            management = None
            if final:
                management = ssh_verify(
                    f"清理-{label}管理通道健康",
                    backend.verify_basic_management_health,
                    must_pass=True,
                    kind="cleanup",
                    section="清理结果",
                )
                artifacts = ssh_verify(
                    f"清理-{label}独立残留审计",
                    backend.verify_basic_test_artifacts_absent,
                    snapshot,
                    must_pass=True,
                    kind="cleanup",
                    section="清理结果",
                )
            web_ok = False
            try:
                page.navigate_to_basic_setting()
                web_ok = page.is_on_basic_setting_page()
            except Exception:
                web_ok = False
            ui_check(
                f"{label}恢复后Web访问",
                web_ok,
                "恢复后基础设置页面不可访问",
                kind="cleanup",
            )
            passed = bool(
                getattr(restored, "passed", False)
                and getattr(unchanged, "passed", False)
                and (
                    not final
                    or (
                        getattr(management, "passed", False)
                        and getattr(artifacts, "passed", False)
                    )
                )
                and web_ok
            )
            if passed:
                mutation_started = False
            elif not final:
                # 全局配置恢复失败后禁止继续下一轮写场景；转入最外层
                # finally 再尝试恢复并做独立残留审计。
                raise RuntimeError(f"{label}恢复未通过，停止后续基础设置写操作")
            return passed

        def prepare_l5_control(label: str, phase: str = "修改前") -> bool:
            nonlocal mutation_started
            mutation_started = True
            route = ssh_verify(
                f"L5-{label}客户端经路由器路径",
                backend.prepare_basic_l5_route,
                None,
                CLIENT_GATEWAY,
                CLIENT_IFACE,
                CLIENT_SOURCE,
                must_pass=True,
                kind="automation",
            )
            if route is None or not getattr(route, "passed", False):
                return False
            topology_evidence["client_route_via_router"] = True
            control = ssh_verify(
                f"L5-{label}{phase}真实流量控制组",
                backend.run_basic_iperf_probe,
                4,
                True,
                must_pass=False,
                kind="environment",
            )
            return bool(control is not None and getattr(control, "passed", False))

        def recovery_l5_control(label: str):
            ok = prepare_l5_control(label, phase="恢复后")
            restore_baseline(f"{label}恢复控制组")
            return ok

        def changed_expected(
            allowed_fields: Iterable[str],
            *,
            required_fields: Iterable[str] = (),
            explicit: Optional[Dict[str, Any]] = None,
            label: str,
        ) -> Dict[str, Any]:
            if snapshot is None:
                return dict(explicit or {})
            post = backend.get_basic_environment_snapshot()
            baseline_row = dict(snapshot.get("row") or {})
            post_row = dict(post.get("row") or {})
            changed = {
                field
                for field in backend.BASIC_FIELDS
                if post_row.get(field) != baseline_row.get(field)
            }
            allowed: Set[str] = set(allowed_fields)
            required: Set[str] = set(required_fields)
            ui_check(
                f"{label}仅修改允许字段",
                changed.issubset(allowed),
                f"出现非预期字段变化={sorted(changed - allowed)}",
                kind="product",
            )
            if required:
                ui_check(
                    f"{label}目标字段确已变化",
                    required.issubset(changed),
                    f"未变化字段={sorted(required - changed)}",
                    kind="product",
                )
            expected = {
                field: post_row.get(field)
                for field in changed
                if field in allowed
            }
            expected.update(explicit or {})
            add_section(
                "后端验证",
                "通过" if changed.issubset(allowed) else "失败",
                f"{label}字段变化范围",
                f"变化字段数={len(changed)}，字段名={sorted(changed)}",
            )
            return expected

        def page_echo_matches_snapshot() -> bool:
            if snapshot is None:
                return False
            row = dict(snapshot.get("row") or {})
            internet = {0: "路由模式", 1: "NAT4", 2: "NAT1"}
            links = {0: "主干模式", 1: "旁路模式", 2: "SD-WAN网桥"}
            fast = {0: "关闭", 1: "软件模式", 2: "硬件模式"}
            try:
                checks = [
                    page.field_matches("hostname", row.get("hostname", "")),
                    page.field_matches(
                        "switch_nat", internet.get(int(row.get("switch_nat", 1)), "")
                    ),
                    page.field_matches(
                        "switch_dpi", links.get(int(row.get("link_mode", 0)), "")
                    ),
                    page.field_matches(
                        "fast_nat", fast.get(int(row.get("fast_nat", 0)), "")
                    ),
                    page.get_switch_ntpd() == bool(int(row.get("switch_ntpd", 0))),
                ]
                if int(row.get("switch_ntp", 1)) == 1:
                    checks.append(page.field_matches("ntp_config", "builtin"))
                    checks.append(
                        page.field_matches(
                            "sync_cycle", row.get("ntp_sync_cycle", 60)
                        )
                    )
                else:
                    checks.append(page.field_matches("ntp_config", "custom"))
                return all(checks)
            except Exception:
                return False

        try:
            if backend is None:
                raise RuntimeError("基础设置综合测试必须启用SSH backend_verifier")

            with rec.step(
                "步骤1 操作：建立完整环境快照；验证：单例契约、维护通道和无既有测试残留",
                "操作：只读采集DB、生成配置、进程、iptables、路由、内核摘要和客户端指纹；验证：任何写入前快照完整",
            ):
                snapshot = backend.get_basic_environment_snapshot()
                row = dict(snapshot.get("row") or {})
                register_sensitive_values(
                    row.get(field) for field in backend.BASIC_PRIVATE_FIELDS
                )
                snapshot_valid = bool(
                    snapshot.get("version") == 1
                    and snapshot.get("row_count") == 1
                    and set(row) == set(backend.BASIC_FIELDS)
                    and isinstance(snapshot.get("files"), dict)
                    and isinstance(snapshot.get("iptables"), dict)
                    and isinstance(snapshot.get("process"), dict)
                    and isinstance(snapshot.get("summary"), dict)
                    and isinstance(snapshot.get("routes"), dict)
                    and isinstance(snapshot.get("clock"), dict)
                    and snapshot.get("clock", {}).get("router_client_offset")
                    is not None
                    and snapshot.get("clock", {}).get("rtc_client_offset")
                    is not None
                    and isinstance(snapshot.get("integrity"), dict)
                    and all(
                        snapshot.get("integrity", {}).get(key)
                        for key in ("passwd", "crontab", "modules", "ipsets")
                    )
                    and isinstance(snapshot.get("topology"), dict)
                    and isinstance(snapshot.get("client"), dict)
                )
                ui_check("基础设置快照结构完整", snapshot_valid, "快照缺字段")
                artifact_count = len(
                    (snapshot.get("client") or {}).get("artifact_lines", [])
                )
                client_route_get = str(
                    (snapshot.get("client") or {}).get("route_get") or ""
                )
                topology_state = dict(snapshot.get("topology") or {})
                exact_route = str(
                    (snapshot.get("client") or {}).get("route") or ""
                )
                topology_evidence.update(
                    {
                        "baseline_exact_route_absent": not bool(exact_route),
                        "baseline_management_bypasses_test_lan": not all(
                            token in client_route_get
                            for token in (f"dev {CLIENT_IFACE}", f"src {CLIENT_SOURCE}")
                        ),
                        "router_lan_route_present": bool(
                            topology_state.get("router_lan_address_matches")
                            and topology_state.get("router_link_up", {}).get("lan1")
                        ),
                        "router_wan1_route_present": bool(
                            topology_state.get("management_iface") == "wan1"
                            and topology_state.get("router_link_up", {}).get("wan1")
                            and topology_state.get("router_address_present", {}).get("wan1")
                        ),
                    }
                )
                ui_check(
                    "测试前基础设置临时残留为空",
                    artifact_count == 0,
                    f"检测到{artifact_count}条既有临时残留，安全中止",
                    kind="cleanup",
                )
                ui_check(
                    "测试前客户端精确L5路由不存在",
                    topology_evidence["baseline_exact_route_absent"]
                    and topology_evidence["baseline_management_bypasses_test_lan"],
                    "测试前已存在测试/32或管理流量仍走ens11，不能建立精确恢复基线",
                    kind="automation",
                )
                ui_check(
                    "路由器LAN/WAN组网路由存在",
                    topology_evidence["router_lan_route_present"]
                    and topology_evidence["router_wan1_route_present"],
                    "未同时确认lan1客户端网段与wan1管理/上联网段路由",
                    kind="automation",
                )
                snapshot_restore_authorized = bool(
                    snapshot_valid and artifact_count == 0
                )
                contract = ssh_verify(
                    "L1/L2-basic单例与脚本API契约",
                    backend.verify_basic_singleton_contract,
                    must_pass=True,
                )
                topology_safety = ssh_verify(
                    "安全-链路模式接口与管理路径前置",
                    backend.verify_basic_link_topology_safety,
                    must_pass=True,
                    kind="automation",
                )
                baseline = ssh_verify(
                    "L4-测试前环境指纹",
                    backend.verify_basic_environment_unchanged,
                    snapshot,
                    True,
                    must_pass=True,
                    kind="cleanup",
                )
                ui_check("基础设置Web页面可访问", page.is_on_basic_setting_page())
                rec.set_actual(
                    {
                        "snapshot_valid": snapshot_valid,
                        "row_count": snapshot.get("row_count"),
                        "client_artifact_count": artifact_count,
                        "contract_passed": bool(getattr(contract, "passed", False)),
                        "baseline_passed": bool(getattr(baseline, "passed", False)),
                        "baseline_exact_route_absent": bool(
                            topology_evidence["baseline_exact_route_absent"]
                        ),
                        "router_lan_wan_routes_present": bool(
                            topology_evidence["router_lan_route_present"]
                            and topology_evidence["router_wan1_route_present"]
                        ),
                    }
                )
                if not snapshot_valid or artifact_count:
                    raise RuntimeError("基础设置快照或测试前残留不满足安全写入条件")
                require_safety("单例契约", contract)
                require_safety("链路拓扑安全前置", topology_safety)
                require_safety("测试前环境指纹", baseline)

            with rec.step(
                "步骤2 操作：调查页面真实结构与条件字段；验证：全部模式选项、show接口和不适用能力",
                "操作：只改变未提交DOM并刷新；验证：单例表单、38时区、三类模式、NTP条件字段及列表功能不适用",
            ):
                page.navigate_to_basic_setting()
                structure = page.get_page_structure()
                capabilities = page.get_capability_matrix()
                timezone_options = page.probe_select_options("time_zone")
                selected_timezone = page.get_selected_option("time_zone")
                current_time_observation = page.get_safe_field_observation(
                    "current_time"
                )
                ui_check("基础设置URL", structure.get("url_ok"), "URL不匹配")
                ui_check("基础设置标题", structure.get("title_matched"), "标题缺失")
                ui_check(
                    "首屏原始回显与DB快照一致",
                    page_echo_matches_snapshot(),
                    "页面模式、开关或私有字段布尔比较与测试前DB不一致",
                    kind="product",
                )
                ui_check(
                    "basic单例表单",
                    structure.get("singleton_form_present"),
                    "未检测到hostname/switch_nat单例表单",
                )
                ui_check(
                    "当前时间只读显示",
                    current_time_observation.get("visible")
                    and current_time_observation.get("disabled")
                    and current_time_observation.get("populated")
                    and current_time_observation.get("length") == 19,
                    "current_time不存在、可编辑、为空或显示长度异常",
                    kind="product",
                )
                ui_check(
                    "上网模式三项",
                    set(structure.get("options", {}).get("switch_nat", []))
                    == {"NAT4", "NAT1", "路由模式"},
                    "上网模式选项不完整",
                    kind="product",
                )
                ui_check(
                    "链路模式三项",
                    set(structure.get("options", {}).get("switch_dpi", []))
                    == {"主干模式", "旁路模式", "SD-WAN网桥"},
                    "链路模式选项不完整",
                    kind="product",
                )
                ui_check(
                    "加速模式仅关闭和软件",
                    set(structure.get("options", {}).get("fast_nat", []))
                    == {"关闭", "软件模式"},
                    "support_fast=1的选项与实机不一致",
                    kind="product",
                )
                ui_check(
                    "国际时区38项精确集合",
                    len(timezone_options) == 38
                    and len(set(timezone_options)) == 38
                    and all(option.strip() for option in timezone_options)
                    and selected_timezone in set(timezone_options)
                    and set(timezone_options) == EXPECTED_TIME_ZONE_LABELS,
                    "时区标签存在空值、重复、当前回显缺失或与实机捕获集合不一致",
                    kind="product",
                )

                ui_check("选择路由模式DOM", page.select_internet_mode("route"))
                route_state = page.get_mode_condition_state()
                ui_check(
                    "路由模式显示lan_nat",
                    route_state.get("lan_nat", {}).get("visible"),
                    "lan_nat条件字段未显示",
                    kind="product",
                )
                page.navigate_to_basic_setting()
                ui_check("选择旁路模式DOM", page.select_link_mode("bypass"))
                bypass_state = page.get_mode_condition_state()
                listen_options = page.probe_select_options("listen_interface")
                wan_options = page.probe_select_options("wan_interface")
                topology_evidence.update(
                    {
                        "listen_interface_options": len(listen_options),
                        "wan_interface_options": len(wan_options),
                    }
                )
                ui_check(
                    "旁路模式显示双接口字段",
                    bypass_state.get("listen_interface", {}).get("visible")
                    and bypass_state.get("wan_interface", {}).get("visible"),
                    "旁路接口条件字段不完整",
                    kind="product",
                )
                ui_check(
                    "旁路监听接口精确集合",
                    set(listen_options) == EXPECTED_LISTEN_INTERFACES,
                    "监听接口不是实机确认的lan1唯一集合",
                    kind="product",
                )
                ui_check(
                    "旁路回注接口精确集合",
                    set(wan_options) == EXPECTED_WAN_INTERFACES,
                    "回注接口不是实机确认的wan1/wan2/wan3集合",
                    kind="product",
                )
                page.navigate_to_basic_setting()
                ui_check("选择手动时间模式DOM", page.select_ntp_config("manual"))
                manual_state = page.get_mode_condition_state()
                ui_check(
                    "手动模式显示manual_time",
                    manual_state.get("manual_time", {}).get("visible"),
                    "manual_time条件字段未显示",
                    kind="product",
                )
                page.navigate_to_basic_setting()
                ui_check("选择内置NTP模式DOM", page.select_ntp_config("builtin"))
                sync_cycle_observation = page.get_safe_field_observation(
                    "sync_cycle"
                )
                ui_check(
                    "内置NTP同步周期控件存在可见",
                    sync_cycle_observation.get("present")
                    and sync_cycle_observation.get("visible")
                    and sync_cycle_observation.get("control")
                    in {"number", "text"},
                    "sync_cycle未定位到可见原生输入",
                )
                ui_check(
                    "同步周期原生边界5至240",
                    str(sync_cycle_observation.get("min")) == "5"
                    and str(sync_cycle_observation.get("max")) == "240",
                    "sync_cycle原生min/max与实机契约不一致",
                    kind="product",
                )
                builtin_options = page.probe_select_options("ntpserver_builtin")
                ui_check(
                    "内置NTP服务七项精确集合",
                    set(builtin_options) == EXPECTED_BUILTIN_NTP_LABELS
                    and len(builtin_options) == len(set(builtin_options)) == 7,
                    "内置NTP服务公开标签与本轮实机捕获集合不一致",
                    kind="product",
                )
                ui_check("选择自定义NTP项DOM", page.select_builtin_ntp_server("custom"))
                ui_check(
                    "自定义NTP显示地址文本域",
                    page.get_safe_field_observation("ntpserver_list").get("visible"),
                    "ntpserver_list条件字段未显示",
                    kind="product",
                )
                page.navigate_to_basic_setting()

                show_api = next(
                    (
                        item
                        for item in page.last_navigation_api
                        if item.get("function") == "basic"
                        and item.get("action") == "show"
                        and item.get("method") == "POST"
                        and item.get("endpoint") == "/Action/call"
                        and item.get("responded")
                        and item.get("status") == 200
                        and (item.get("semantic") or {}).get("business_success")
                        is not False
                    ),
                    None,
                )
                ui_check(
                    "basic/show接口契约",
                    show_api is not None,
                    "未捕获完整show请求与响应语义",
                    kind="product",
                )

                supported = {
                    "singleton_configuration_edit",
                    "internet_mode",
                    "link_mode",
                    "acceleration_mode",
                    "time_sync",
                    "save",
                    "help",
                }
                for name, evidence in capabilities.items():
                    if name in supported:
                        ui_check(
                            f"能力-{name}",
                            evidence.get("supported"),
                            evidence.get("evidence", "缺少DOM证据"),
                        )
                    elif name == "cancel":
                        # 这两项是全局配置页必需的安全交互，实机缺失属于产品缺陷，
                        # 不能混入普通列表能力的“不适用”。
                        add_section(
                            "页面验证",
                            "失败",
                            f"安全能力-{name}",
                            evidence.get("evidence", "安全交互缺失"),
                        )
                        _append_failure(
                            "product",
                            f"产品缺陷-基础设置缺少{name}安全能力",
                        )
                    elif name == "dirty_navigation_confirmation":
                        add_section(
                            "页面验证",
                            "通过",
                            "脏导航能力静态证据",
                            "能力矩阵未检测到确认机制；下一步骤将用真实跨页行为判定产品结果",
                        )
                    else:
                        is_na = bool(
                            not evidence.get("supported")
                            and evidence.get("result") == "不适用"
                        )
                        not_applicable(
                            "页面验证",
                            name,
                            evidence.get("evidence", "单例表单无此入口"),
                        )
                        if not is_na:
                            _append_failure(
                                "automation", f"能力矩阵-{name}不适用证据不完整"
                            )
                for name in ("重复记录", "合法导入", "畸形导入", "导出文件"):
                    not_applicable(
                        "页面验证",
                        name,
                        "页面无记录表格或导入导出入口，后端模型为basic.id=1单例",
                    )
                cancel_probe = page.cancel_changes()
                not_applicable(
                    "页面验证",
                    "取消操作",
                    cancel_probe.get("evidence", "实机无取消按钮"),
                )
                rec.set_actual(
                    {
                        "timezone_option_count": structure.get("option_counts", {}).get(
                            "time_zone"
                        ),
                        "timezone_exact_set": set(timezone_options)
                        == EXPECTED_TIME_ZONE_LABELS,
                        "timezone_unique_and_selected": len(set(timezone_options)) == 38
                        and selected_timezone in set(timezone_options),
                        "builtin_ntp_option_count": len(builtin_options),
                        "builtin_ntp_exact_set": set(builtin_options)
                        == EXPECTED_BUILTIN_NTP_LABELS,
                        "listen_interface_option_count": len(listen_options),
                        "wan_interface_option_count": len(wan_options),
                        "bypass_interface_exact_sets": set(listen_options)
                        == EXPECTED_LISTEN_INTERFACES
                        and set(wan_options) == EXPECTED_WAN_INTERFACES,
                        "current_time_readonly_visible": bool(
                            current_time_observation.get("visible")
                            and current_time_observation.get("disabled")
                        ),
                        "sync_cycle_present_visible": bool(
                            sync_cycle_observation.get("present")
                            and sync_cycle_observation.get("visible")
                        ),
                        "sync_cycle_native_bounds": bool(
                            str(sync_cycle_observation.get("min")) == "5"
                            and str(sync_cycle_observation.get("max")) == "240"
                        ),
                        "show_api_ok": show_api is not None,
                        "cancel_supported": bool(cancel_probe.get("supported")),
                        "not_applicable_count": sum(
                            1
                            for item in capabilities.values()
                            if not item.get("supported")
                        ),
                    }
                )

            with rec.step(
                "步骤3 操作：打开帮助并探测脏表单导航；验证：主题关闭、无隐式保存及产品安全行为",
                "操作：打开/关闭帮助，修改主机名DOM后跨页；验证：帮助主题正确、无basic/save，且记录缺少脏导航确认的真实产品行为",
            ):
                page.navigate_to_basic_setting()
                help_result = page.verify_help_entry(("基础设置", "上网模式"))
                ui_check("帮助入口可点击", help_result.get("clicked"))
                ui_check(
                    "帮助已打开并匹配主题",
                    help_result.get("opened") and help_result.get("content_matched"),
                    help_result.get("error") or "帮助内容未匹配",
                    kind="product",
                )
                ui_check(
                    "帮助关闭且无孤儿页",
                    help_result.get("closed") and help_result.get("no_orphan"),
                    "帮助页未关闭干净",
                )
                page.navigate_to_basic_setting()
                dirty = page.probe_dirty_navigation()
                ui_check("脏表单DOM已修改", dirty.get("modified"))
                ui_check(
                    "脏导航没有隐式保存",
                    not dirty.get("save_request_seen"),
                    "跨页时出现basic/save请求",
                    kind="product",
                )
                ui_check(
                    "脏导航返回后DOM回显恢复",
                    dirty.get("returned_to_basic") and dirty.get("dom_value_restored"),
                    "跨页后未恢复数据库回显",
                )
                # 产品当前真实行为是直接离开且无确认；按全局配置安全要求保留红灯。
                ui_check(
                    "脏表单离开确认",
                    dirty.get("confirmation_seen"),
                    "实机直接离开，无继续编辑/确认放弃分支",
                    kind="product",
                )
                if not dirty.get("confirmation_seen"):
                    not_applicable(
                        "页面验证",
                        "脏表单继续编辑分支",
                        "实机未弹出脏表单确认框，无法执行继续编辑分支",
                    )
                    not_applicable(
                        "页面验证",
                        "脏表单确认放弃分支",
                        "实机未弹出脏表单确认框，无法执行确认放弃分支",
                    )
                ssh_verify(
                    "L4-脏导航后环境未变化",
                    backend.verify_basic_environment_unchanged,
                    snapshot,
                    True,
                    must_pass=True,
                    kind="cleanup",
                )
                rec.set_actual(
                    {
                        "help_opened": bool(help_result.get("opened")),
                        "help_closed": bool(help_result.get("closed")),
                        "dirty_confirmation_seen": bool(
                            dirty.get("confirmation_seen")
                        ),
                        "save_request_seen": bool(dirty.get("save_request_seen")),
                        "dom_restored": bool(dirty.get("dom_value_restored")),
                    }
                )

            valid_hostname = f"基础测试{_token(6)}"
            boundary_hostname = "B" * page.HOSTNAME_MAX_LENGTH
            register_sensitive_values((valid_hostname, boundary_hostname))
            with rec.step(
                "步骤4 操作：保存合法设备名称及21字符边界；验证：页面回显、L1-L4和逐场景恢复",
                "操作：分别保存合法名称和maxlength边界；验证：basic/save、DB、缓存、系统hostname、init重建及非测试字段保护",
            ):
                for label, value in (
                    ("合法设备名称", valid_hostname),
                    ("21字符设备名称边界", boundary_hostname),
                ):
                    page.navigate_to_basic_setting()
                    saved = save_form({"hostname": value}, label)
                    if saved and saved.get("success"):
                        page.navigate_to_basic_setting()
                        ui_check(
                            f"{label}刷新回显",
                            page.field_matches("hostname", value),
                            "保存后页面回显不一致",
                            kind="product",
                        )
                        verify_layers(label, {"hostname": value})
                    restore_baseline(label)

            def expect_rejected(
                label: str,
                prepare: Callable[[], bool],
                *,
                observation_field: Optional[str] = None,
                expect_native_truncation: bool = False,
                allow_native_input_rejection: bool = False,
            ):
                nonlocal mutation_started
                page.navigate_to_basic_setting()
                before_observation = (
                    page.get_safe_field_observation(observation_field)
                    if observation_field
                    else {}
                )
                prepared = bool(prepare())
                observation = (
                    page.get_safe_field_observation(observation_field)
                    if observation_field
                    else {}
                )
                if observation_field:
                    control_ready = bool(
                        observation.get("present") and observation.get("visible")
                    )
                    if not ui_check(
                        f"{label}目标控件存在可见",
                        control_ready,
                        f"{observation_field}定位缺失或条件渲染后不可见",
                        kind="automation",
                    ):
                        ssh_verify(
                            f"L1/L4-{label}控件缺失后环境不变",
                            backend.verify_basic_environment_unchanged,
                            snapshot,
                            True,
                            must_pass=True,
                            kind="cleanup",
                        )
                        page.navigate_to_basic_setting()
                        return
                if not prepared:
                    native_rejected = bool(
                        allow_native_input_rejection
                        and observation.get("control") == "number"
                        and observation.get("native_valid") is True
                        and observation.get("length")
                        == before_observation.get("length")
                    )
                    if native_rejected:
                        ui_check(
                            f"{label}浏览器原生拒绝",
                            True,
                            kind="product",
                        )
                        add_section(
                            "页面验证",
                            "通过",
                            f"{label}拒绝类型",
                            "数字控件原生拒绝非数字键入，未触发保存接口",
                        )
                        ssh_verify(
                            f"L1/L4-{label}原生拒绝后环境不变",
                            backend.verify_basic_environment_unchanged,
                            snapshot,
                            True,
                            must_pass=True,
                            kind="cleanup",
                        )
                        page.navigate_to_basic_setting()
                        return
                    ui_check(
                        f"{label}输入动作完成",
                        False,
                        "目标控件存在但页面对象未完成输入，不能宣称产品拒绝",
                        kind="automation",
                    )
                    ssh_verify(
                        f"L1/L4-{label}输入失败后环境不变",
                        backend.verify_basic_environment_unchanged,
                        snapshot,
                        True,
                        must_pass=True,
                        kind="cleanup",
                    )
                    page.navigate_to_basic_setting()
                    return
                if expect_native_truncation:
                    maxlength = observation.get("maxlength")
                    length = observation.get("length")
                    rejected = bool(
                        prepared
                        and isinstance(length, int)
                        and maxlength is not None
                        and length <= int(maxlength)
                    )
                    ui_check(
                        f"{label}浏览器原生截断",
                        rejected,
                        "maxlength未按真实键入行为截断",
                        kind="product",
                    )
                    add_section(
                        "页面验证",
                        "通过" if rejected else "失败",
                        f"{label}拒绝类型",
                        "控件maxlength原生截断，未触发保存接口"
                        if rejected
                        else "未检测到预期的控件原生截断",
                    )
                    ssh_verify(
                        f"L1/L4-{label}未提交环境不变",
                        backend.verify_basic_environment_unchanged,
                        snapshot,
                        True,
                        must_pass=True,
                        kind="cleanup",
                    )
                    page.navigate_to_basic_setting()
                    return
                errors = page.get_error_messages()
                submitted = False
                result: Dict[str, Any] = {}
                if prepared and not errors:
                    mutation_started = True
                    submitted = True
                    result = page.save_settings(timeout=5000)
                rejected = bool(
                    errors or (submitted and not result.get("success"))
                )
                if errors:
                    rejection_type = "页面明确校验拒绝，未提交接口"
                elif submitted and not result.get("success"):
                    api = dict(result.get("api") or {})
                    semantic = dict(api.get("semantic") or {})
                    rejection_type = (
                        "后端接口返回失败语义"
                        if api.get("responded")
                        and semantic.get("business_success") is False
                        else "提交后未出现成功语义，按拒绝处理"
                    )
                else:
                    rejection_type = "产品接受了非法输入"
                ui_check(
                    f"{label}明确拒绝",
                    rejected,
                    "非法输入被页面报告为保存成功或没有拒绝反馈",
                    kind="product",
                )
                add_section(
                    "页面验证",
                    "通过" if rejected else "失败",
                    f"{label}拒绝类型",
                    rejection_type,
                )
                ssh_verify(
                    f"L1-{label}数据库及非测试字段不变",
                    backend.verify_basic_database,
                    {},
                    snapshot=snapshot,
                    must_pass=True,
                    kind="product",
                )
                unchanged = ssh_verify(
                    f"L1/L4-{label}后端无变化",
                    backend.verify_basic_environment_unchanged,
                    snapshot,
                    True,
                    must_pass=True,
                    kind="product",
                )
                if submitted or not getattr(unchanged, "passed", False):
                    restore_baseline(label)
                else:
                    page.navigate_to_basic_setting()

            with rec.step(
                "步骤5 操作：提交空值、空格、非法字符、超长和错误参数；验证：控件拒绝类型及DB不变",
                "操作：逐项验证主机名、同步周期、未知模式/时区、无效手动时间及自定义NTP空格/非法/超长；验证：原生截断、页面拒绝、接口拒绝和DB不变分别留证",
            ):
                invalid_hostname = "bad/host?"
                register_sensitive_value(invalid_hostname)
                expect_rejected(
                    "设备名称空值",
                    lambda: page.fill_hostname(""),
                    observation_field="hostname",
                )
                expect_rejected(
                    "设备名称纯空格",
                    lambda: page.fill_hostname("   "),
                    observation_field="hostname",
                )
                expect_rejected(
                    "设备名称非法字符",
                    lambda: page.fill_hostname(invalid_hostname),
                    observation_field="hostname",
                )
                expect_rejected(
                    "设备名称22字符",
                    lambda: page.fill_hostname("X" * 22),
                    observation_field="hostname",
                    expect_native_truncation=True,
                )
                for label, value, native_input_rejection in (
                    ("同步周期低于下限", 4, False),
                    ("同步周期高于上限", 241, False),
                    ("同步周期非法字符", "abc", True),
                    ("同步周期空值", "", False),
                ):
                    expect_rejected(
                        label,
                        lambda value=value: page.fill_sync_cycle(value),
                        observation_field="sync_cycle",
                        allow_native_input_rejection=native_input_rejection,
                    )
                expect_rejected(
                    "自定义NTP地址空值",
                    lambda: (
                        page.select_ntp_config("builtin")
                        and page.select_builtin_ntp_server("custom")
                        and page.fill_custom_ntp_servers("")
                    ),
                    observation_field="ntpserver_list",
                )

                def prepare_custom_ntp(value: str) -> bool:
                    return bool(
                        page.select_ntp_config("builtin")
                        and page.select_builtin_ntp_server("custom")
                        and page.fill_custom_ntp_servers(value)
                    )

                invalid_ntp_values = (
                    ("自定义NTP地址纯空格", "   "),
                    ("自定义NTP地址非法字符和组合", "bad host|invalid"),
                )
                register_sensitive_values(value for _, value in invalid_ntp_values)
                for label, value in invalid_ntp_values:
                    expect_rejected(
                        label,
                        lambda value=value: prepare_custom_ntp(value),
                        observation_field="ntpserver_list",
                    )

                page.navigate_to_basic_setting()
                page.select_ntp_config("builtin")
                page.select_builtin_ntp_server("custom")
                ntp_meta = page.get_safe_field_observation("ntpserver_list")
                try:
                    ntp_maxlength = int(ntp_meta.get("maxlength"))
                except (TypeError, ValueError):
                    ntp_maxlength = None
                overlong_ntp = "n" * (
                    ntp_maxlength + 1 if ntp_maxlength is not None else 2048
                )
                register_sensitive_value(overlong_ntp)
                expect_rejected(
                    "自定义NTP地址超长值",
                    lambda: prepare_custom_ntp(overlong_ntp),
                    observation_field="ntpserver_list",
                    expect_native_truncation=ntp_maxlength is not None,
                )

                invalid_manual_time = "2026-02-30 25:61:61"
                register_sensitive_value(invalid_manual_time)
                page.navigate_to_basic_setting()
                manual_prepared = page.fill_manual_time_value(invalid_manual_time)
                manual_value_retained = bool(
                    manual_prepared
                    and page.field_matches("manual_time", invalid_manual_time)
                )
                manual_observation = page.get_safe_field_observation("manual_time")
                manual_marked_invalid = bool(
                    manual_observation.get("aria_invalid")
                    or manual_observation.get("native_valid") is False
                )
                manual_errors = page.get_error_messages()
                manual_submitted = False
                invalid_manual_result: Dict[str, Any] = {}
                if manual_prepared and manual_value_retained and not manual_errors:
                    mutation_started = True
                    manual_submitted = True
                    invalid_manual_result = page.set_manual_time(
                        invalid_manual_time, timeout=5000
                    )
                manual_rejected = bool(
                    not manual_prepared
                    or not manual_value_retained
                    or manual_errors
                    or (
                        manual_submitted
                        and not invalid_manual_result.get("success")
                    )
                )
                ui_check(
                    "无效手动时间明确拒绝",
                    manual_rejected,
                    "无效日期时间触发set_time成功语义",
                    kind="product",
                )
                add_section(
                    "页面验证",
                    "通过" if manual_rejected else "失败",
                    "无效手动时间拒绝类型",
                    (
                        "日期时间控件原生拒绝，未提交set_time"
                        if not manual_prepared
                        else "日期时间组件归一化/拒绝非法值，未提交set_time"
                        if not manual_value_retained
                        else "页面明确校验拒绝，未提交set_time"
                        if manual_errors
                        else "set_time接口未返回成功语义"
                        if manual_rejected
                        else "页面已标记非法但set_time仍返回成功语义"
                        if manual_marked_invalid
                        else "产品接受了无效日期时间"
                    ),
                )
                ssh_verify(
                    "L1-无效手动时间后数据库不变",
                    backend.verify_basic_database,
                    {},
                    snapshot=snapshot,
                    must_pass=True,
                    kind="product",
                )
                invalid_time_unchanged = ssh_verify(
                    "L1/L4-无效手动时间后运行态不变",
                    backend.verify_basic_environment_unchanged,
                    snapshot,
                    True,
                    must_pass=True,
                    kind="product",
                )
                if manual_submitted or not getattr(
                    invalid_time_unchanged, "passed", False
                ):
                    restore_baseline("无效手动时间")
                else:
                    page.navigate_to_basic_setting()
                rec.set_actual(
                    {
                        "manual_invalid_value_retained": manual_value_retained,
                        "manual_invalid_marked_invalid": manual_marked_invalid,
                        "manual_invalid_native_valid": manual_observation.get(
                            "native_valid"
                        ),
                        "manual_invalid_error_count": len(manual_errors),
                        "manual_invalid_submitted": manual_submitted,
                        "manual_invalid_set_time_success": bool(
                            invalid_manual_result.get("success")
                        ),
                    }
                )

                for label, selector in (
                    ("未知上网模式", lambda: page.select_internet_mode("unknown")),
                    ("未知链路模式", lambda: page.select_link_mode("unknown")),
                    ("硬件加速参数", lambda: page.select_fast_nat("hardware")),
                    ("未知NTP配置方式", lambda: page.select_ntp_config("unknown")),
                    ("未知时区", lambda: page.select_time_zone("unknown/timezone")),
                ):
                    rejected = not bool(selector())
                    ui_check(
                        f"{label}控件拒绝",
                        rejected,
                        "页面对象接受了实机不存在的选项",
                        kind="product",
                    )
                ssh_verify(
                    "L1/L4-全部非法参数后环境不变",
                    backend.verify_basic_environment_unchanged,
                    snapshot,
                    True,
                    must_pass=True,
                    kind="cleanup",
                )

            with rec.step(
                "步骤6 操作：切换国际时区并保存；验证：38项选择、DB/文件映射、刷新回显和恢复",
                "操作：选择一个不同于当前项的真实时区；验证：仅时区字段变化，/etc/TZ与localtime链路一致",
            ):
                page.navigate_to_basic_setting()
                zones = page.probe_select_options("time_zone")
                current_zone = page.get_selected_option("time_zone")
                target_zone = next(
                    (zone for zone in zones if zone != current_zone), None
                )
                ui_check("存在可切换时区", target_zone is not None, "未找到第二个时区")
                if target_zone is not None:
                    selected = page.select_time_zone(target_zone)
                    ui_check("时区选择操作", selected)
                    saved = save_form({}, "国际时区") if selected else None
                    if saved and saved.get("success"):
                        page.navigate_to_basic_setting()
                        ui_check(
                            "时区刷新回显",
                            page.field_matches("time_zone", target_zone),
                            "保存后时区显示未保持",
                            kind="product",
                        )
                        expected = changed_expected(
                            {"time_zone", "time_zone_full"},
                            required_fields={"time_zone", "time_zone_full"},
                            label="国际时区",
                        )
                        verify_layers("国际时区", expected)
                restore_baseline("国际时区")

            def run_internet_scenario(
                step_number: int,
                label: str,
                mode_name: str,
                mode_code: int,
                *,
                expect_fullcone: Optional[bool] = None,
                route_probe: bool = False,
            ):
                with rec.step(
                    f"步骤{step_number} 操作：切换{label}；验证：L1-L5控制组、模式效果和恢复组",
                    f"操作：修改前打流→保存{label}→DB/脚本/运行态/真实协议→恢复原配置再打流；验证：switch_nat={mode_code}",
                ):
                    control_ok = prepare_l5_control(label)
                    page.navigate_to_basic_setting()
                    values: Dict[str, Any] = {"switch_nat": mode_name}
                    if mode_code == 0:
                        values["lan_nat"] = False
                    saved = save_form(values, label)
                    expected = {"switch_nat": mode_code}
                    if mode_code == 0:
                        expected["lan_nat"] = 0
                    if saved and saved.get("success"):
                        page.navigate_to_basic_setting()
                        expected_label = {
                            0: "路由模式",
                            1: "NAT4",
                            2: "NAT1",
                        }[mode_code]
                        ui_check(
                            f"{label}刷新回显",
                            page.field_matches("switch_nat", expected_label),
                            "保存后上网模式显示不一致",
                            kind="product",
                        )
                        verify_layers(
                            label,
                            expected,
                            nat=(mode_code, int(expected.get("lan_nat", 0))),
                        )
                        if control_ok:
                            if expect_fullcone is not None:
                                ssh_verify(
                                    f"L5-{label}NAT锥形真实效果",
                                    backend.run_basic_fullcone_probe,
                                    bool(expect_fullcone),
                                    must_pass=True,
                                    kind="product",
                                )
                            if route_probe:
                                ssh_verify(
                                    f"L5-{label}WAN实包源地址",
                                    backend.run_basic_route_mode_probe,
                                    None,
                                    CLIENT_SOURCE,
                                    ROUTER_WAN_IFACE,
                                    must_pass=True,
                                    kind="product",
                                )
                            ssh_verify(
                                f"L5-{label}修改后连通性",
                                backend.run_basic_iperf_probe,
                                4,
                                True,
                                must_pass=True,
                                kind="product",
                            )
                        else:
                            not_applicable(
                                "协议验证",
                                f"{label}L5效果",
                                "修改前经路由器控制组不成立，禁止把路径故障误判为模式效果",
                            )
                    restored = restore_baseline(label)
                    if control_ok and restored:
                        recovery_l5_control(label)

            run_internet_scenario(
                7, "NAT4上网模式", "nat4", 1, expect_fullcone=False
            )
            run_internet_scenario(
                8, "NAT1上网模式", "nat1", 2, expect_fullcone=True
            )

            with rec.step(
                "步骤9 操作：切换路由模式并验证lan_nat开关；验证：NONAT、WAN实包源地址和恢复组",
                "操作：修改前控制组→路由+lan_nat关闭→L1-L5→单独开启lan_nat验证→恢复；验证：不伪造NAT流量结论",
            ):
                control_ok = prepare_l5_control("路由模式")
                page.navigate_to_basic_setting()
                saved = save_form(
                    {"switch_nat": "route", "lan_nat": False},
                    "路由模式lan_nat关闭",
                )
                if saved and saved.get("success"):
                    page.navigate_to_basic_setting()
                    ui_check(
                        "路由模式刷新回显",
                        page.field_matches("switch_nat", "路由模式")
                        and page.get_lan_nat() is False,
                        "路由或lan_nat页面回显不一致",
                        kind="product",
                    )
                    verify_layers(
                        "路由模式lan_nat关闭",
                        {"switch_nat": 0, "lan_nat": 0},
                        nat=(0, 0),
                    )
                    if control_ok:
                        route_capture = ssh_verify(
                            "L5-路由模式WAN实包源地址保持",
                            backend.run_basic_route_mode_probe,
                            None,
                            CLIENT_SOURCE,
                            ROUTER_WAN_IFACE,
                            must_pass=True,
                            kind="product",
                        )
                        if route_capture is not None and getattr(
                            route_capture, "passed", False
                        ):
                            ssh_verify(
                                "L5-路由模式无NAT且无外部回程负向效果",
                                backend.run_basic_iperf_probe,
                                4,
                                False,
                                must_pass=False,
                                kind="environment",
                            )
                        else:
                            not_applicable(
                                "协议验证",
                                "路由模式无回程负向效果",
                                "WAN源地址抓包前置未成立，不把普通路径故障当作路由模式效果",
                            )
                    else:
                        not_applicable(
                            "协议验证",
                            "路由模式WAN实包",
                            "修改前经路由器控制组失败，禁止伪造无NAT结论",
                        )

                    page.navigate_to_basic_setting()
                    saved_lan_nat = save_form(
                        {"switch_nat": "route", "lan_nat": True},
                        "路由模式lan_nat开启",
                    )
                    if saved_lan_nat and saved_lan_nat.get("success"):
                        verify_layers(
                            "路由模式lan_nat开启",
                            {"switch_nat": 0, "lan_nat": 1},
                            nat=(0, 1),
                        )
                restored = restore_baseline("路由模式")
                if control_ok and restored:
                    recovery_l5_control("路由模式")

            def run_link_scenario(
                step_number: int,
                label: str,
                mode_name: str,
                mode_code: int,
            ):
                with rec.step(
                    f"步骤{step_number} 操作：切换{label}；验证：DB→basic.sh→AC/内核与init重建",
                    "操作：一次只修改链路模式并保存；验证：link_mode字段、非测试字段保护、旧态释放和新态下发",
                ):
                    topology_guard = ssh_verify(
                        f"安全-{label}接口与管理路径前置",
                        backend.verify_basic_link_topology_safety,
                        must_pass=True,
                        kind="automation",
                    )
                    require_safety(f"{label}链路拓扑", topology_guard)
                    page.navigate_to_basic_setting()
                    values: Dict[str, Any] = {"switch_dpi": mode_name}
                    expected: Dict[str, Any] = {"link_mode": mode_code}
                    if mode_code == 1:
                        ui_check("旁路模式DOM选择", page.select_link_mode("bypass"))
                        listen = page.probe_select_options("listen_interface")
                        wan = page.probe_select_options("wan_interface")
                        topology_evidence.update(
                            {
                                "listen_interface_options": len(listen),
                                "wan_interface_options": len(wan),
                            }
                        )
                        ui_check(
                            "旁路接口存在可选项",
                            bool(listen) and bool(wan),
                            "旁路监听或回注接口没有选项",
                            kind="product",
                        )
                        if listen and wan:
                            values.update(
                                {
                                    "listen_interface": [listen[0]],
                                    "wan_interface": [wan[0]],
                                }
                            )
                            expected.update(
                                {"listenport": listen[0], "backport": wan[0]}
                            )
                        page.navigate_to_basic_setting()
                    saved = save_form(values, label)
                    if saved and saved.get("success"):
                        page.navigate_to_basic_setting()
                        display = {
                            0: "主干模式",
                            1: "旁路模式",
                            2: "SD-WAN网桥",
                        }[mode_code]
                        ui_check(
                            f"{label}刷新回显",
                            page.field_matches("switch_dpi", display),
                            "链路模式保存后回显不一致",
                            kind="product",
                        )
                        verify_layers(
                            label,
                            expected,
                            link_mode=mode_code,
                        )
                    topology_detail = (
                        "安全快照确认router lan1/wan1/wan2/wan3均为UP且有地址，"
                        f"管理接口={topology_state.get('management_iface') or '未知'}，"
                        f"客户端管理与LAN路径分离={'是' if topology_state.get('client_management_separate') else '否'}，"
                        f"认证旁路前置标志={'有' if topology_state.get('auth_bypass_prerequisite_present') else '无'}；"
                        "L5控制组已确认客户端目标路由经192.168.148.1/ens11，"
                        f"该路径证据={'成立' if topology_evidence['client_route_via_router'] else '不成立'}；"
                        "路由器lan1与wan1路由证据"
                        f"={'成立' if topology_evidence['router_lan_route_present'] and topology_evidence['router_wan1_route_present'] else '不成立'}；"
                        "实机页面仅检测到"
                        f"{topology_evidence['listen_interface_options']}个监听接口和"
                        f"{topology_evidence['wan_interface_options']}个回注接口；"
                        "监听侧只有承载现有客户端的lan1，项目配置无第二个独立发流端、"
                        "回注对端或双侧抓包点，不能构造可信物理链路L5"
                    )
                    not_applicable(
                        "协议验证",
                        f"{label}物理链路L5",
                        topology_detail,
                    )
                    warning(
                        "协议验证",
                        f"{label}环境限制",
                        "已完成L1-L4和底层运行态，未伪造链路流量验证",
                    )
                    restore_baseline(label)

            run_link_scenario(10, "主干链路模式", "trunk", 0)
            run_link_scenario(11, "旁路链路模式", "bypass", 1)
            run_link_scenario(12, "SD-WAN网桥模式", "sd-wan", 2)

            with rec.step(
                "步骤13 操作：验证关闭/软件加速与确认弹窗；验证：FASTOFFLOAD、真实计数和硬件模式不适用",
                "操作：软件确认先取消再确定，保存关闭和软件模式；验证：L1-L5控制组、FLOWOFFLOAD计数及恢复组",
            ):
                page.navigate_to_basic_setting()
                page.select_fast_nat("off")
                cancelled = page.select_fast_nat_with_confirmation(
                    "software", confirm_software=False
                )
                ui_check(
                    "软件加速确认取消分支",
                    cancelled.get("supported")
                    and cancelled.get("confirmation_seen")
                    and cancelled.get("cancelled")
                    and cancelled.get("success"),
                    cancelled.get("error") or "取消分支未完成",
                    kind="product",
                )
                ssh_verify(
                    "L1/L4-软件确认取消后环境不变",
                    backend.verify_basic_environment_unchanged,
                    snapshot,
                    True,
                    must_pass=True,
                    kind="cleanup",
                )

                control_ok = prepare_l5_control("加速模式")
                page.navigate_to_basic_setting()
                saved_off = save_form({"fast_nat": "off"}, "关闭加速")
                if saved_off and saved_off.get("success"):
                    verify_layers(
                        "关闭加速", {"fast_nat": 0}, fast_nat=0
                    )
                    if control_ok:
                        ssh_verify(
                            "L5-关闭加速真实流量仍可达",
                            backend.run_basic_iperf_probe,
                            4,
                            True,
                            must_pass=True,
                            kind="product",
                        )

                page.navigate_to_basic_setting()
                saved_software = save_form(
                    {"fast_nat": "software"}, "软件加速"
                )
                if saved_software and saved_software.get("success"):
                    page.navigate_to_basic_setting()
                    ui_check(
                        "软件加速刷新回显",
                        page.field_matches("fast_nat", "软件模式"),
                        "软件加速保存后回显不一致",
                        kind="product",
                    )
                    verify_layers(
                        "软件加速", {"fast_nat": 1}, fast_nat=1
                    )
                    if control_ok:
                        ssh_verify(
                            "L5-软件加速FASTOFFLOAD计数",
                            backend.run_basic_acceleration_probe,
                            4,
                            must_pass=True,
                            kind="product",
                        )
                    else:
                        not_applicable(
                            "协议验证",
                            "软件加速L5",
                            "修改前真实流量控制组失败，禁止用全局计数器伪造效果",
                        )
                hardware_absent = "硬件模式" not in page.probe_select_options(
                    "fast_nat"
                )
                ui_check(
                    "硬件加速选项确实不存在",
                    hardware_absent and page.SUPPORT_FAST == 1,
                    "support_fast与页面选项证据不一致",
                    kind="product",
                )
                not_applicable(
                    "页面验证",
                    "硬件加速",
                    "实机support_fast=1且下拉仅关闭/软件，硬件模式不存在",
                )
                restored = restore_baseline("加速模式")
                if control_ok and restored:
                    recovery_l5_control("加速模式")

            ntp_address = "ntp.aliyun.com"
            register_sensitive_value(ntp_address)
            ntp_allowed = {
                "switch_ntp",
                "switch_ntpserver",
                "ntpserver_list",
                "ntp_sync_cycle",
                "switch_ntpd",
            }
            with rec.step(
                "步骤14 操作：验证内置/自定义NTP、周期边界和服务开关；验证：L1-L5正负控制闭环",
                "操作：内置默认+周期5/240、ntpd启停、合法自定义地址；验证：DB/进程/UDP123与SNTP正→负→正",
            ):
                page.navigate_to_basic_setting()
                saved_builtin = save_form(
                    {
                        "ntp_config": "builtin",
                        "ntpserver_builtin": "default",
                        "sync_cycle": 5,
                        "switch_ntpd": True,
                    },
                    "内置NTP周期5并启用服务",
                )
                positive_ntp = False
                if saved_builtin and saved_builtin.get("success"):
                    expected = changed_expected(
                        ntp_allowed,
                        explicit={
                            "switch_ntp": 1,
                            "switch_ntpserver": 0,
                            "ntp_sync_cycle": 5,
                            "switch_ntpd": 1,
                        },
                        label="内置NTP周期5",
                    )
                    verify_layers(
                        "内置NTP周期5",
                        expected,
                        ntp=(1, 1, 5),
                    )
                    positive = ssh_verify(
                        "L5-NTP启用正控制",
                        backend.run_basic_ntp_protocol_probe,
                        ROUTER_LAN_HOST,
                        True,
                        must_pass=True,
                        kind="product",
                    )
                    positive_ntp = bool(
                        positive is not None and getattr(positive, "passed", False)
                    )

                page.navigate_to_basic_setting()
                saved_cycle_max = save_form(
                    {
                        "ntp_config": "builtin",
                        "ntpserver_builtin": "default",
                        "sync_cycle": 240,
                        "switch_ntpd": True,
                    },
                    "内置NTP周期240边界",
                )
                if saved_cycle_max and saved_cycle_max.get("success"):
                    expected = changed_expected(
                        ntp_allowed,
                        explicit={
                            "switch_ntp": 1,
                            "switch_ntpserver": 0,
                            "ntp_sync_cycle": 240,
                            "switch_ntpd": 1,
                        },
                        label="NTP周期240边界",
                    )
                    verify_layers(
                        "NTP周期240边界",
                        expected,
                        ntp=(1, 1, 240),
                        reinit=False,
                    )

                page.navigate_to_basic_setting()
                saved_off = save_form(
                    {
                        "ntp_config": "builtin",
                        "ntpserver_builtin": "default",
                        "sync_cycle": 240,
                        "switch_ntpd": False,
                    },
                    "关闭NTP服务",
                )
                if saved_off and saved_off.get("success"):
                    expected = changed_expected(
                        ntp_allowed,
                        explicit={
                            "switch_ntp": 1,
                            "switch_ntpserver": 0,
                            "ntp_sync_cycle": 240,
                            "switch_ntpd": 0,
                        },
                        label="关闭NTP服务",
                    )
                    verify_layers(
                        "关闭NTP服务",
                        expected,
                        ntp=(1, 0, 240),
                        reinit=False,
                    )
                    if positive_ntp:
                        ssh_verify(
                            "L5-NTP关闭负向效果",
                            backend.run_basic_ntp_protocol_probe,
                            ROUTER_LAN_HOST,
                            False,
                            must_pass=True,
                            kind="product",
                        )
                    else:
                        not_applicable(
                            "协议验证",
                            "NTP关闭负向效果",
                            "启用正控制未成立，禁止把路径超时误判为服务关闭效果",
                        )

                page.navigate_to_basic_setting()
                saved_reenable = save_form(
                    {
                        "ntp_config": "builtin",
                        "ntpserver_builtin": "default",
                        "sync_cycle": 5,
                        "switch_ntpd": True,
                    },
                    "恢复NTP服务正控制",
                )
                if saved_reenable and saved_reenable.get("success") and positive_ntp:
                    ssh_verify(
                        "L5-NTP恢复正控制",
                        backend.run_basic_ntp_protocol_probe,
                        ROUTER_LAN_HOST,
                        True,
                        must_pass=True,
                        kind="product",
                    )

                custom_baseline_offset = (snapshot.get("clock") or {}).get(
                    "router_client_offset"
                )
                custom_baseline_rtc_offset = (snapshot.get("clock") or {}).get(
                    "rtc_client_offset"
                )
                page.navigate_to_basic_setting()
                custom_before_token = page.get_current_time_fingerprint()
                custom_manual_candidate = client_referenced_manual_candidate(35)
                custom_manual_delta = None
                custom_manual_rtc_delta = None
                custom_manual_token = None
                ui_check(
                    "自定义NTP实测候选时间安全生成",
                    custom_manual_candidate is not None,
                    "无法用客户端参考epoch和路由器时区生成近距离候选值",
                )
                if custom_manual_candidate is not None:
                    register_sensitive_value(custom_manual_candidate)
                    mutation_started = True
                    custom_set = page.set_manual_time(
                        custom_manual_candidate, timeout=12000
                    )
                    ui_check(
                        "自定义NTP修改前set_time控制组契约",
                        action_contract(custom_set, "set_time"),
                        custom_set.get("error") or "set_time请求或成功语义不完整",
                        kind="product",
                    )
                    page.page.wait_for_timeout(900)
                    custom_manual_state = backend.get_basic_environment_snapshot()
                    custom_manual_offset = (
                        custom_manual_state.get("clock") or {}
                    ).get("router_client_offset")
                    custom_manual_rtc_offset = (
                        custom_manual_state.get("clock") or {}
                    ).get("rtc_client_offset")
                    custom_manual_delta = (
                        abs(int(custom_manual_offset) - int(custom_baseline_offset))
                        if custom_manual_offset is not None
                        and custom_baseline_offset is not None
                        else None
                    )
                    custom_manual_rtc_delta = (
                        abs(
                            int(custom_manual_rtc_offset)
                            - int(custom_baseline_rtc_offset)
                        )
                        if custom_manual_rtc_offset is not None
                        and custom_baseline_rtc_offset is not None
                        else None
                    )
                    custom_manual_expected = changed_expected(
                        ntp_allowed,
                        required_fields={"switch_ntp"},
                        explicit={"switch_ntp": 0, "ntpserver_list": ""},
                        label="自定义NTP修改前手动模式",
                    )
                    ssh_verify(
                        "L1-自定义NTP修改前仅切换NTP字段",
                        backend.verify_basic_database,
                        custom_manual_expected,
                        snapshot=snapshot,
                        must_pass=True,
                        kind="product",
                    )
                    page.navigate_to_basic_setting()
                    custom_manual_token = page.get_current_time_fingerprint()
                    ui_check(
                        "自定义NTP修改前时差控制组",
                        custom_manual_delta is not None
                        and custom_manual_delta >= 15
                        and custom_manual_rtc_delta is not None
                        and custom_manual_rtc_delta >= 15,
                        "手动偏移未同时形成系统时钟和RTC控制组",
                        kind="product",
                    )
                    ui_check(
                        "自定义NTP修改前current_time刷新",
                        custom_before_token is not None
                        and custom_manual_token is not None
                        and custom_manual_token != custom_before_token,
                        "current_time只读显示未刷新（仅比较内存指纹）",
                        kind="product",
                    )

                page.navigate_to_basic_setting()
                saved_custom = save_form(
                    {
                        "ntp_config": "builtin",
                        "ntpserver_list": ntp_address,
                        "sync_cycle": 5,
                        "switch_ntpd": True,
                    },
                    "自定义NTP地址",
                )
                if saved_custom and saved_custom.get("success"):
                    expected = changed_expected(
                        ntp_allowed,
                        explicit={
                            "switch_ntp": 1,
                            "switch_ntpserver": 1,
                            "ntpserver_list": ntp_address,
                            "ntp_sync_cycle": 5,
                            "switch_ntpd": 1,
                        },
                        label="自定义NTP地址",
                    )
                    page.navigate_to_basic_setting()
                    ui_check(
                        "自定义NTP地址安全回显比较",
                        page.field_matches("ntpserver_list", ntp_address),
                        "自定义地址回显不一致（原文已隐藏）",
                        kind="product",
                    )
                    verify_layers(
                        "自定义NTP地址",
                        expected,
                        ntp=(1, 1, 5),
                    )
                    pre_sync_state = backend.get_basic_environment_snapshot()
                    pre_sync_offset = (pre_sync_state.get("clock") or {}).get(
                        "router_client_offset"
                    )
                    pre_sync_rtc_offset = (pre_sync_state.get("clock") or {}).get(
                        "rtc_client_offset"
                    )
                    pre_sync_delta = (
                        abs(int(pre_sync_offset) - int(custom_baseline_offset))
                        if pre_sync_offset is not None
                        and custom_baseline_offset is not None
                        else None
                    )
                    pre_sync_rtc_delta = (
                        abs(
                            int(pre_sync_rtc_offset)
                            - int(custom_baseline_rtc_offset)
                        )
                        if pre_sync_rtc_offset is not None
                        and custom_baseline_rtc_offset is not None
                        else None
                    )
                    auto_sync_effect = bool(
                        pre_sync_delta is not None
                        and pre_sync_delta <= 5
                        and pre_sync_rtc_delta is not None
                        and pre_sync_rtc_delta <= 8
                    )
                    page.navigate_to_basic_setting()
                    pre_sync_token = page.get_current_time_fingerprint()
                    ui_check(
                        "自定义NTP立即对时按钮显示",
                        page.get_page_structure().get("sync_time_present"),
                        "自定义NTP保存后未显示立即对时按钮",
                        kind="product",
                    )
                    custom_sync = page.sync_time_now(timeout=15000)
                    ui_check(
                        "自定义NTP立即对时请求契约",
                        action_request_contract(custom_sync, "sync_time"),
                        custom_sync.get("error")
                        or "sync_time请求、响应或HTTP状态不完整",
                        kind="product",
                    )
                    page.page.wait_for_timeout(1800)
                    custom_sync_state = backend.get_basic_environment_snapshot()
                    custom_sync_offset = (
                        custom_sync_state.get("clock") or {}
                    ).get("router_client_offset")
                    custom_sync_rtc_offset = (
                        custom_sync_state.get("clock") or {}
                    ).get("rtc_client_offset")
                    custom_sync_delta = (
                        abs(int(custom_sync_offset) - int(custom_baseline_offset))
                        if custom_sync_offset is not None
                        and custom_baseline_offset is not None
                        else None
                    )
                    custom_sync_rtc_delta = (
                        abs(
                            int(custom_sync_rtc_offset)
                            - int(custom_baseline_rtc_offset)
                        )
                        if custom_sync_rtc_offset is not None
                        and custom_baseline_rtc_offset is not None
                        else None
                    )
                    page.navigate_to_basic_setting()
                    custom_sync_token = page.get_current_time_fingerprint()
                    custom_sync_effect = bool(
                        custom_sync_delta is not None
                        and custom_sync_delta <= 5
                        and custom_sync_rtc_delta is not None
                        and custom_sync_rtc_delta <= 8
                    )
                    if action_contract(custom_sync, "sync_time"):
                        ui_check(
                            "自定义NTP真实同步效果",
                            custom_sync_effect,
                            "自定义NTP保存/立即对时后系统时钟或RTC未恢复",
                            kind="product",
                        )
                        ui_check(
                            "自定义NTP同步后current_time刷新",
                            pre_sync_token is not None
                            and custom_sync_token is not None
                            and custom_sync_token != pre_sync_token,
                            "同步后current_time只读显示未刷新（仅比较内存指纹）",
                            kind="product",
                        )
                    else:
                        warning(
                            "协议验证",
                            "自定义NTP外部上游链路",
                            "已真实发送basic/sync_time，但外部NTP未返回成功语义；按环境限制保留请求/HTTP/时差证据",
                        )
                    ssh_verify(
                        "L1-自定义NTP同步后配置保持",
                        backend.verify_basic_database,
                        expected,
                        snapshot=snapshot,
                        must_pass=True,
                        kind="product",
                    )
                    rec.set_actual(
                        {
                            "custom_ntp_sync_request_contract": action_request_contract(
                                custom_sync, "sync_time"
                            ),
                            "custom_ntp_business_success": action_contract(
                                custom_sync, "sync_time"
                            ),
                            "custom_ntp_control_offset_changed": bool(
                                custom_manual_delta is not None
                                and custom_manual_delta >= 15
                                and custom_manual_rtc_delta is not None
                                and custom_manual_rtc_delta >= 15
                            ),
                            "custom_ntp_auto_sync_effect": auto_sync_effect,
                            "custom_ntp_sync_offset_restored": custom_sync_effect,
                            "custom_ntp_current_time_refreshed": bool(
                                custom_sync_token is not None
                                and custom_sync_token != pre_sync_token
                            ),
                        }
                    )
                restore_baseline("NTP配置与服务")

            with rec.step(
                "步骤15 操作：真实手动设时并立即对时；验证：set_time/sync_time接口、时差效果和精确恢复",
                "操作：基于客户端参考epoch生成短时偏移→确认手动模式真实字段变化→仅在DOM切回自动模式后立即对时→精确恢复；验证：非NTP字段不变、current_time刷新和管理通道正常",
            ):
                page.navigate_to_basic_setting()
                structure = page.get_page_structure()
                ui_check(
                    "立即对时按钮存在",
                    structure.get("sync_time_present"),
                    "未检测到立即对时入口",
                    kind="product",
                )
                baseline_offset = (snapshot.get("clock") or {}).get(
                    "router_client_offset"
                )
                baseline_rtc_offset = (snapshot.get("clock") or {}).get(
                    "rtc_client_offset"
                )
                ui_check(
                    "测试前系统/RTC相对偏差可用",
                    baseline_offset is not None and baseline_rtc_offset is not None,
                    "路由器系统时钟、RTC或客户端参考时钟不可用",
                    kind="cleanup",
                )
                before_manual_token = page.get_current_time_fingerprint()
                manual_candidate = client_referenced_manual_candidate(35)
                ui_check(
                    "手动设时候选值安全生成",
                    manual_candidate is not None,
                    "无法用客户端参考epoch和路由器时区生成近距离候选值",
                )
                if manual_candidate is None:
                    raise RuntimeError("手动设时安全候选生成失败")
                register_sensitive_value(manual_candidate)

                mutation_started = True
                manual_result = page.set_manual_time(
                    manual_candidate, timeout=12000
                )
                ui_check(
                    "手动set_time接口契约",
                    action_contract(manual_result, "set_time"),
                    manual_result.get("error") or "set_time请求或响应不完整",
                    kind="product",
                )
                page.page.wait_for_timeout(900)
                manual_state = backend.get_basic_environment_snapshot()
                manual_offset = (manual_state.get("clock") or {}).get(
                    "router_client_offset"
                )
                manual_rtc_offset = (manual_state.get("clock") or {}).get(
                    "rtc_client_offset"
                )
                manual_delta = (
                    abs(int(manual_offset) - int(baseline_offset))
                    if manual_offset is not None and baseline_offset is not None
                    else None
                )
                manual_rtc_delta = (
                    abs(int(manual_rtc_offset) - int(baseline_rtc_offset))
                    if manual_rtc_offset is not None
                    and baseline_rtc_offset is not None else None
                )
                ui_check(
                    "手动设时系统/RTC时差真实变化",
                    manual_delta is not None and manual_delta >= 15
                    and manual_rtc_delta is not None and manual_rtc_delta >= 15,
                    "set_time返回成功但系统时钟或RTC相对客户端未产生可识别变化",
                    kind="product",
                )
                manual_expected = changed_expected(
                    ntp_allowed,
                    required_fields={"switch_ntp"},
                    explicit={"switch_ntp": 0, "ntpserver_list": ""},
                    label="手动set_time模式切换",
                )
                ssh_verify(
                    "L1-手动set_time仅切换NTP相关字段",
                    backend.verify_basic_database,
                    manual_expected,
                    snapshot=snapshot,
                    must_pass=True,
                    kind="product",
                )
                ssh_verify(
                    "L2-手动set_time生成配置一致",
                    backend.verify_basic_generated_state,
                    manual_expected,
                    must_pass=True,
                    kind="product",
                )

                page.navigate_to_basic_setting()
                manual_time_token = page.get_current_time_fingerprint()
                manual_time_observation = page.get_safe_field_observation(
                    "current_time"
                )
                ui_check(
                    "手动设时后current_time只读刷新",
                    before_manual_token is not None
                    and manual_time_token is not None
                    and manual_time_token != before_manual_token
                    and manual_time_observation.get("visible")
                    and manual_time_observation.get("disabled")
                    and manual_time_observation.get("length") == 19,
                    "手动设时后current_time未刷新或不再是只读显示（仅比较内存指纹）",
                    kind="product",
                )
                ui_check(
                    "立即对时前切回自动模式DOM",
                    page.select_ntp_config("builtin"),
                    "手动模式下立即对时入口隐藏，未能仅切换DOM显示自动对时控件",
                )
                ui_check(
                    "立即对时按钮条件显示",
                    page.get_page_structure().get("sync_time_present"),
                    "切回自动模式DOM后仍未显示立即对时按钮",
                    kind="product",
                )
                sync_result = page.sync_time_now(timeout=12000)
                ui_check(
                    "立即对时sync_time接口契约",
                    action_contract(sync_result, "sync_time"),
                    sync_result.get("error") or "sync_time请求或响应不完整",
                    kind="product",
                )
                page.page.wait_for_timeout(1200)
                sync_state = backend.get_basic_environment_snapshot()
                sync_offset = (sync_state.get("clock") or {}).get(
                    "router_client_offset"
                )
                sync_rtc_offset = (sync_state.get("clock") or {}).get(
                    "rtc_client_offset"
                )
                sync_delta = (
                    abs(int(sync_offset) - int(baseline_offset))
                    if sync_offset is not None and baseline_offset is not None
                    else None
                )
                sync_rtc_delta = (
                    abs(int(sync_rtc_offset) - int(baseline_rtc_offset))
                    if sync_rtc_offset is not None
                    and baseline_rtc_offset is not None else None
                )
                ui_check(
                    "立即对时恢复系统/RTC可信时差",
                    sync_delta is not None and sync_delta <= 5
                    and sync_rtc_delta is not None and sync_rtc_delta <= 8,
                    "sync_time后系统时钟或RTC相对客户端仍不符合基线语义",
                    kind="product",
                )
                page.navigate_to_basic_setting()
                sync_time_token = page.get_current_time_fingerprint()
                sync_time_observation = page.get_safe_field_observation("current_time")
                ui_check(
                    "立即对时后current_time只读刷新",
                    manual_time_token is not None
                    and sync_time_token is not None
                    and sync_time_token != manual_time_token
                    and sync_time_observation.get("visible")
                    and sync_time_observation.get("disabled")
                    and sync_time_observation.get("length") == 19,
                    "立即对时后current_time未刷新或不再是只读显示（仅比较内存指纹）",
                    kind="product",
                )
                ssh_verify(
                    "L1-立即对时后保持手动阶段NTP字段",
                    backend.verify_basic_database,
                    manual_expected,
                    snapshot=snapshot,
                    must_pass=True,
                    kind="product",
                )
                restored_time = restore_baseline("时间设置")
                if restored_time:
                    ssh_verify(
                        "L4-时间设置恢复后管理通道",
                        backend.verify_basic_management_health,
                        must_pass=True,
                        kind="cleanup",
                    )
                rec.set_actual(
                    {
                        "manual_set_time_api": action_contract(
                            manual_result, "set_time"
                        ),
                        "sync_time_api": action_contract(
                            sync_result, "sync_time"
                        ),
                        "manual_offset_changed": bool(
                            manual_delta is not None and manual_delta >= 15
                            and manual_rtc_delta is not None
                            and manual_rtc_delta >= 15
                        ),
                        "sync_offset_restored": bool(
                            sync_delta is not None and sync_delta <= 5
                            and sync_rtc_delta is not None
                            and sync_rtc_delta <= 8
                        ),
                        "manual_current_time_refreshed": bool(
                            manual_time_token is not None
                            and manual_time_token != before_manual_token
                        ),
                        "sync_current_time_refreshed": bool(
                            sync_time_token is not None
                            and sync_time_token != manual_time_token
                        ),
                        "final_time_restore": bool(restored_time),
                    }
                )

        except Exception as exc:
            unexpected_error = type(exc).__name__
            automation_failures.append(
                f"综合流程未预期异常({unexpected_error})"
            )
        finally:
            try:
                with rec.step(
                    "步骤16 操作：finally精确恢复与独立残留审计；验证：DB、文件、进程、路由、内核、客户端和Web回到测试前",
                    "操作：无条件恢复basic.id=1并执行basic.sh init、客户端精确路由恢复；验证：环境指纹、测试临时物和页面安全回显",
                ):
                    if snapshot_restore_authorized and snapshot is not None:
                        restored = restore_baseline("finally", final=True)
                        if restored:
                            page.navigate_to_basic_setting()
                            ui_check(
                                "finally恢复后页面回显匹配快照",
                                page_echo_matches_snapshot(),
                                "恢复后页面模式或私有字段布尔比较不一致",
                                kind="cleanup",
                            )
                        rec.set_actual(
                            {
                                "restored": bool(restored),
                                "mutation_started_after_cleanup": bool(
                                    mutation_started
                                ),
                                "automation_failure_count": len(
                                    automation_failures
                                ),
                                "product_failure_count": len(product_failures),
                                "cleanup_failure_count": len(cleanup_failures),
                                "environment_warning_count": len(
                                    environment_warnings
                                ),
                            }
                        )
                    elif mutation_started:
                        _append_failure(
                            "cleanup",
                            "finally无法恢复：测试前未取得有效基础设置快照",
                        )
                    else:
                        add_section(
                            "清理结果",
                            "通过",
                            "finally无需恢复",
                            "安全前置阶段未开始任何持久化或客户端路由变更",
                        )
            except Exception as cleanup_exc:
                cleanup_failures.append(
                    f"finally恢复流程异常({type(cleanup_exc).__name__})"
                )
            finally:
                # 失败截图前离开含设备名称/NTP原值的页面。about:blank 不触发
                # 任何产品保存，也不把原始私有字段留在截图DOM中。
                try:
                    page.page.goto("about:blank", wait_until="domcontentloaded")
                except Exception:
                    try:
                        page.page.set_content(
                            "<html><body><p>基础设置测试已完成安全恢复，私有字段已隐藏。</p></body></html>"
                        )
                    except Exception:
                        pass

        failures = automation_failures + product_failures + cleanup_failures
        print(
            "[基础设置断言] "
            f"自动化={len(automation_failures)}，产品={len(product_failures)}，"
            f"清理={len(cleanup_failures)}，环境警告={len(environment_warnings)}",
            flush=True,
        )
        if unexpected_error:
            print(f"[基础设置异常分类] {unexpected_error}", flush=True)
        assert not failures, (
            f"基础设置L1-L5综合验证失败({len(failures)}项；"
            f"自动化={len(automation_failures)}，产品={len(product_failures)}，"
            f"清理={len(cleanup_failures)})："
            + "; ".join(failures[:40])
        )
