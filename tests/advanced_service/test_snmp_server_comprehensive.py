"""高级服务 > 本地服务 > SNMP服务 L1-L5 单节点综合测试。

真实页面是单例 show/save 表单。列表 CRUD、搜索、批量、导入导出、排序、
分页和刷新均由 DOM + 接口注册证据明确判为不适用，不虚构对应操作。
"""

from __future__ import annotations

import secrets
import string
import time
from typing import Dict, List, Optional

import pytest

from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.advanced_service, pytest.mark.snmp_server]

LAN_HOST, LAN_IFACE = "192.168.148.1", "ens11"
WAN_HOST, WAN_IFACE = "10.66.0.150", "enp2s0"
SYSTEM_NAME_OID = "1.3.6.1.2.1.1.5.0"
SYSTEM_TREE_OID = "1.3.6.1.2.1.1"
INVALID_OID = "1.3.6.1.2.1.99999.1.0"


def _token(length: int = 6) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _wait_runtime(check, attempts: int = 18, interval: float = 0.45):
    result = None
    for _ in range(attempts):
        result = check()
        if getattr(result, "passed", False):
            return result
        time.sleep(interval)
    return result


class TestSnmpServerComprehensive:
    """SNMP V2C/V3 UI、DB、运行态与真实协议综合验证。"""

    def test_snmp_server_comprehensive(
        self, snmp_server_page_logged_in, step_recorder: StepRecorder, request
    ):
        page = snmp_server_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("SNMP服务L1-L5综合测试必须启用SSH backend_verifier")

        run_token = _token()
        prefix = f"snmp_{run_token}_"
        # The real V2C form accepts a 500-character community but rejects some
        # URL-safe punctuation (for example ``-``/``_``).  Keep the positive
        # control strictly alphanumeric so an input-data mistake cannot mask
        # the actual V2C DB/runtime/protocol chain.
        v2_community = _token(32)
        wrong_community = _token(32)
        v3_user = f"u{run_token}"
        v3_auth = secrets.token_urlsafe(18)
        v3_priv = secrets.token_urlsafe(18)
        wrong_auth = secrets.token_urlsafe(18)
        wrong_priv = secrets.token_urlsafe(18)
        community_boundary_500 = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(500)
        )
        community_boundary_501 = community_boundary_500 + secrets.choice(
            string.ascii_letters + string.digits
        )
        sysname_v2 = f"{prefix}v2"
        sysname_v3 = f"{prefix}v3"

        ui_failures: List[str] = []
        ssh_failures: List[str] = []
        product_failures: List[str] = []
        candidate_ports: List[int] = []
        snapshot: Optional[Dict] = None
        snapshot_valid = False
        mutation_started = False
        udp_guard_port: Optional[int] = None
        report_sections = (
            "测试操作", "页面验证", "后端验证", "运行时验证", "协议验证", "清理结果",
        )
        rec.required_sections = report_sections

        def add_section(section: str, status: str, label: str, detail: str):
            rec.add_detail(f"【{section}】\n{status} {label}：{detail}")

        def ui_check(label, condition, detail="", *, product=False):
            ok = bool(condition)
            conclusion = "符合预期" if ok else (str(detail) or "条件不成立")
            add_section("页面验证", "通过" if ok else "失败", label, conclusion)
            if not ok:
                failure = f"页面验证-{label}：{conclusion}"
                (product_failures if product else ui_failures).append(failure)
                rec.fail_current_step(failure)
            return ok

        def require_ui(label, condition, detail=""):
            if not ui_check(label, condition, detail):
                pytest.fail(f"安全前置失败: {label}: {detail or '条件不成立'}")

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            label_text = str(label)
            level, separator, item = label_text.partition("-")
            has_level = level.startswith("L") and any(c.isdigit() for c in level)
            if label_text.startswith(("清理", "finally")):
                section = "清理结果"
            elif has_level and "L5" in level:
                section = f"协议验证·{level}"
            elif has_level and any(token in level for token in ("L3", "L4")):
                section = f"运行时验证·{level}"
            else:
                section = f"后端验证·{level}" if has_level else "后端验证"
            check_name = item if separator and has_level else label_text
            try:
                result = verify_func(*args, **kwargs)
                passed = bool(getattr(result, "passed", False))
                message = str(getattr(result, "message", "无验证消息"))
                add_section(section, "通过" if passed else "失败", check_name, message)
                if must_pass and not passed:
                    ssh_failures.append(f"后端验证-{label_text}：{message}")
                    rec.fail_current_step(f"后端验证-{label_text}：{message}")
                return result
            except Exception as exc:
                message = str(exc)[:180]
                add_section(section, "失败" if must_pass else "警告", check_name, message)
                if must_pass:
                    ssh_failures.append(f"后端验证-{label_text}异常：{message}")
                    rec.fail_current_step(f"后端验证-{label_text}异常：{message}")
                return None

        ssh_verify = attach_cmd_recording_to_closure(backend, rec, ssh_verify)

        def verify_runtime_with_retry(expected_fields: Dict, expected_secrets: Dict):
            return _wait_runtime(lambda: backend.verify_snmp_runtime_consistency(
                expected_fields, expected_secrets
            ))

        # 报告命令生成器按公开验证器签名生成逐条复验命令，不展示等待闭包。
        verify_runtime_with_retry.__report_verifier__ = (
            backend.verify_snmp_runtime_consistency
        )

        def require_ssh(label, verify_func, *args, fatal=False, **kwargs):
            result = ssh_verify(label, verify_func, *args, must_pass=True, **kwargs)
            if fatal and (result is None or not getattr(result, "passed", False)):
                pytest.fail(f"安全前置失败: SSH-{label}")
            return result

        def save_form(values: Dict, label: str) -> bool:
            nonlocal mutation_started
            mutation_started = True
            fill = page.fill_form(values)
            ui_check(f"{label}字段填写", fill.get("success"), fill.get("failed_fields"))
            saved = page.save_settings(timeout=12000)
            ui_check(
                f"{label}保存反馈",
                saved.get("success"),
                saved.get("error"),
                product=True,
            )
            api = dict(saved.get("api") or {})
            api_contract = bool(
                api.get("requested")
                and api.get("responded")
                and api.get("function") == "netsnmp"
                and api.get("action") == "save"
                and api.get("method") == "POST"
                and api.get("endpoint") == "call"
                and api.get("status") == 200
            )
            ui_check(
                f"{label}保存接口契约",
                api_contract,
                {
                    "requested": bool(api.get("requested")),
                    "responded": bool(api.get("responded")),
                    "function": api.get("function"),
                    "action": api.get("action"),
                    "method": api.get("method"),
                    "endpoint": api.get("endpoint"),
                    "status": api.get("status"),
                },
                product=True,
            )
            return bool(
                fill.get("success") and saved.get("success") and api_contract
            )

        def report_snapshot_semantics(label: str, environment: Dict):
            row = dict(environment.get("row") or {})
            secret_fields = {"community", "auth_pass", "priv_pass"}
            expected_fields = {
                key: value for key, value in row.items()
                if key not in secret_fields
            }
            expected_secrets = {
                key: row.get(key, "") for key in secret_fields
            }
            return ssh_verify(
                label,
                verify_runtime_with_retry,
                expected_fields,
                expected_secrets,
                must_pass=False,
            )

        def expect_rejected(
            label: str,
            values: Dict,
            *,
            restore=True,
        ):
            before = backend.get_snmp_environment_snapshot(candidate_ports)
            page.navigate_to_snmp_server()
            fill_result = page.fill_form(values)
            frontend_rejections: List[str] = []
            for failed_field in fill_result.get("failed_fields", []):
                frontend_rejections.append(
                    f"{failed_field}控件在提交前拒绝输入"
                )
            for field_name, attempted in values.items():
                observation = page.get_safe_field_observation(field_name)
                if not observation.get("present"):
                    continue
                attempted_text = "" if attempted is None else str(attempted)
                maxlength = observation.get("maxlength")
                try:
                    maxlength = int(maxlength) if maxlength is not None else None
                except (TypeError, ValueError):
                    maxlength = None
                actual_length = observation.get("length")
                if (
                    maxlength is not None
                    and len(attempted_text) > maxlength
                    and isinstance(actual_length, int)
                    and actual_length <= maxlength
                    and not page.field_matches(field_name, attempted_text)
                ):
                    frontend_rejections.append(
                        f"{field_name}受maxlength={maxlength}限制，"
                        f"尝试长度={len(attempted_text)}，控件接收长度={actual_length}"
                    )
            if frontend_rejections:
                # 控件已在提交前拒绝或截断，不再点击保存，避免把保留的旧值
                # 误判成“非法值保存成功”，也避免无意义地重启活动V3服务。
                result = {"submitted": False, "success": False}
                rejected = True
            else:
                result = page.save_settings(timeout=5000)
                rejected = not result.get("success")
            strict_unchanged = ssh_verify(
                f"L1/L4-{label}环境指纹",
                backend.verify_snmp_environment_unchanged,
                before,
                True,
                must_pass=False,
            )
            strict_checks = dict(
                (getattr(strict_unchanged, "details", None) or {}).get("checks") or {}
            )
            strict_failures = {key for key, passed in strict_checks.items() if not passed}
            dynamic_only = bool(strict_failures) and strict_failures <= {
                "process", "listeners", "config"
            }
            semantic_unchanged = strict_unchanged
            if not getattr(strict_unchanged, "passed", False) and dynamic_only:
                semantic_unchanged = report_snapshot_semantics(
                    f"L4-{label}运行态语义",
                    before,
                )
            unchanged_ok = bool(
                getattr(strict_unchanged, "passed", False)
                or (
                    dynamic_only
                    and getattr(semantic_unchanged, "passed", False)
                )
            )
            rejection_detail = (
                "；".join(frontend_rejections)
                if frontend_rejections else
                (result.get("error") or "页面保存校验已拒绝")
            )
            api = dict(result.get("api") or {})
            noop_success = bool(
                label == "监听端口字符"
                and result.get("success")
                and api.get("requested")
                and api.get("responded")
                and api.get("function") == "netsnmp"
                and api.get("action") == "save"
                and api.get("method") == "POST"
                and api.get("endpoint") == "call"
                and api.get("status") == 200
                and unchanged_ok
            )
            if noop_success:
                ui_check(
                    label,
                    False,
                    "页面显示保存成功且接口返回200，但字符未进入数据库，"
                    "属于缺少非法输入反馈的产品缺陷；未发生非法值落库",
                    product=True,
                )
            else:
                ui_check(
                    label,
                    rejected and unchanged_ok,
                    rejection_detail if rejected and unchanged_ok else
                    "页面未拒绝非法输入，或DB/运行态被异常修改",
                    product=True,
                )
            add_section(
                "后端验证·L1/L4", "通过" if unchanged_ok else "失败",
                label, getattr(semantic_unchanged, "message", "无语义复验结果"),
            )
            if not getattr(strict_unchanged, "passed", False) and unchanged_ok:
                add_section(
                    "运行时验证", "警告", f"{label}动态快照差异",
                    "活动服务校验后PID、监听属主或V3配置哈希发生动态变化；"
                    "数据库、生成配置、进程数量、全部候选UDP监听和防火墙语义仍与提交前一致",
                )
            if restore:
                if not unchanged_ok:
                    restored = ssh_verify(
                        f"清理-{label}隔离恢复",
                        backend.restore_snmp_environment,
                        before,
                        must_pass=False,
                    )
                    semantic = report_snapshot_semantics(
                        f"L4-{label}恢复后运行态语义",
                        before,
                    )
                    semantic_ok = bool(
                        getattr(semantic, "passed", False)
                    )
                    add_section(
                        "清理结果", "通过" if semantic_ok else "失败",
                        f"{label}隔离恢复",
                        getattr(semantic, "message", "无语义恢复结果"),
                    )
                    if not getattr(restored, "passed", False) and semantic_ok:
                        add_section(
                            "清理结果", "警告", f"{label}动态快照差异",
                            "活动服务重建后PID、监听属主或V3运行配置哈希可变化；"
                            "DB到配置、进程、监听和防火墙语义复验已通过",
                        )
                    if not semantic_ok:
                        ssh_failures.append(
                            f"{label}异常修改后语义恢复失败："
                            f"{getattr(semantic, 'message', getattr(restored, 'message', '无恢复结果'))}"
                        )
                        rec.fail_current_step(f"{label}异常修改后语义恢复失败")
                else:
                    page.cancel_changes(confirm_discard=True)
            page.navigate_to_snmp_server()

        try:
            with rec.step(
                "步骤1 操作：保存全环境快照与唯一命名空间；验证：原始DB、配置、进程、监听和非测试数据指纹",
                "操作：动态选择四个空闲UDP端口并读取snmp_conf单例；验证：候选端口未占用且快照完整",
            ):
                candidate_ports = backend.choose_snmp_candidate_ports(4)
                require_ui(
                    "四个唯一动态UDP端口",
                    len(candidate_ports) == 4 and len(set(candidate_ports)) == 4,
                    str(candidate_ports),
                )
                snapshot = backend.get_snmp_environment_snapshot(candidate_ports)
                snapshot_valid = bool(
                    snapshot.get("version") == 1
                    and snapshot.get("row", {}).get("id") == "1"
                    and snapshot.get("candidate_ports") == candidate_ports
                )
                require_ui("SNMP全环境快照完整", snapshot_valid, "快照字段不完整")
                require_ssh(
                    "L1/L2-单例show/save契约",
                    backend.verify_snmp_singleton_contract,
                    fatal=True,
                )
                require_ssh(
                    "L4-测试前环境指纹",
                    backend.verify_snmp_environment_unchanged,
                    snapshot,
                    fatal=True,
                )
                require_ssh(
                    "L5-Net-SNMP工具",
                    backend.ensure_snmp_client_tools,
                    False,
                    fatal=True,
                )
                require_ssh(
                    "L5-安全人工复验入口",
                    backend.ensure_snmp_verify_helper,
                    fatal=True,
                )
                rec.set_actual({
                    "prefix_length": len(prefix),
                    "candidate_port_count": len(candidate_ports),
                    "snapshot_valid": snapshot_valid,
                })

            with rec.step(
                "步骤2 操作：调查SNMP页面实际能力；验证：单例表单字段、版本和不适用功能证据",
                "操作：读取活动Tab和DOM能力；验证：V2C/V3、保存/取消/帮助存在，列表CRUD类入口明确不适用",
            ):
                page.navigate_to_snmp_server()
                structure = page.get_page_structure()
                capabilities = page.get_capability_matrix()
                require_ui("SNMP为第4个Tab", structure.get("tab_index") == 3, structure)
                require_ui("SNMP单例配置表单", structure.get("singleton_form_present"), structure)
                require_ui(
                    "V2C/V3真实选项",
                    set(structure.get("version_options", [])) == {"SNMP V2C", "SNMP V3"},
                    structure.get("version_options"),
                )
                v1_backend = require_ssh(
                    "L1/L2-V1不支持证据",
                    backend.verify_snmp_v1_not_supported,
                )
                v1_not_applicable = bool(
                    "SNMP V1" not in set(structure.get("version_options", []))
                    and getattr(v1_backend, "passed", False)
                )
                add_section(
                    "不适用", "不适用" if v1_not_applicable else "失败",
                    "SNMP V1",
                    "版本下拉仅有SNMP V2C/V3，后端保存链路也仅接受版本2/3"
                    if v1_not_applicable else "V1不支持证据不完整",
                )
                if not v1_not_applicable:
                    ui_failures.append("不适用判定-SNMP V1缺少页面或后端证据")

                oid_controls = page.page.locator(
                    ".ant-tabs-tabpane-active:visible #oid, "
                    ".ant-tabs-tabpane-active:visible [name='oid'], "
                    ".ant-tabs-tabpane-active:visible input[placeholder*='OID'], "
                    ".ant-tabs-tabpane-active:visible textarea[placeholder*='OID']"
                ).count()
                oid_not_applicable = oid_controls == 0
                add_section(
                    "不适用", "不适用" if oid_not_applicable else "失败",
                    "OID输入",
                    "活动SNMP单例表单无OID控件；OID由客户端snmpget/snmpwalk选择"
                    if oid_not_applicable else f"活动表单检测到{oid_controls}个OID控件",
                )
                if not oid_not_applicable:
                    ui_failures.append("不适用判定-OID输入实际存在")

                v3_fill = page.fill_form({
                    "version": "v3", "security": "authNoPriv",
                })
                security_options = page.probe_select_options("security")
                auth_options = page.probe_select_options("auth_proto")
                v3_structure = page.get_page_structure()
                v3_hides_v2_fields = all(
                    not v3_structure.get("fields", {}).get(field, {}).get("visible")
                    for field in ("community", "source")
                )
                ui_check(
                    "V3安全级别全选项",
                    v3_fill.get("success")
                    and set(security_options) == {"认证", "认证且加密"},
                    security_options,
                    product=True,
                )
                ui_check(
                    "V3认证算法全选项",
                    set(auth_options) == {"MD5", "SHA"},
                    auth_options,
                    product=True,
                )
                ui_check(
                    "V3不显示community和source",
                    v3_hides_v2_fields,
                    {
                        field: bool(v3_structure.get("fields", {}).get(field, {}).get("visible"))
                        for field in ("community", "source")
                    },
                    product=True,
                )

                auth_priv_fill = page.fill_form({"security": "authPriv"})
                priv_options = page.probe_select_options("priv_proto")
                ui_check(
                    "V3隐私算法全选项",
                    auth_priv_fill.get("success")
                    and set(priv_options) == {"DES", "AES"},
                    priv_options,
                    product=True,
                )

                page.navigate_to_snmp_server()
                v2_fill = page.fill_form({"version": "v2c"})
                v2_structure = page.get_page_structure()
                v2_hides_v3_fields = all(
                    not v2_structure.get("fields", {}).get(field, {}).get("visible")
                    for field in (
                        "username", "security", "auth_proto", "auth_pass",
                        "password", "priv_proto", "priv_pass",
                    )
                )
                ui_check(
                    "V2C不显示V3专用字段",
                    v2_fill.get("success") and v2_hides_v3_fields,
                    {
                        field: bool(v2_structure.get("fields", {}).get(field, {}).get("visible"))
                        for field in (
                            "username", "security", "auth_proto", "auth_pass",
                            "password", "priv_proto", "priv_pass",
                        )
                    },
                    product=True,
                )

                # 上述操作只改变未提交表单；重新导航通过show接口回到DB原状态。
                page.navigate_to_snmp_server()
                navigation_api = list(page.last_navigation_api or [])
                show_api = next((
                    item for item in navigation_api
                    if item.get("function") == "netsnmp"
                    and item.get("action") == "show"
                    and item.get("method") == "POST"
                    and item.get("endpoint") == "call"
                    and item.get("responded")
                    and item.get("status") == 200
                ), None)
                ui_check(
                    "SNMP show接口契约",
                    show_api is not None,
                    navigation_api,
                    product=True,
                )
                supported = {"singleton_configuration_edit", "service_enable_disable", "save", "cancel", "help"}
                for name, evidence in capabilities.items():
                    if name in supported:
                        ui_check(f"能力{name}", evidence.get("supported"), evidence.get("evidence"))
                    else:
                        is_na = not evidence.get("supported") and evidence.get("result") == "不适用"
                        add_section(
                            "不适用", "不适用" if is_na else "失败", name,
                            evidence.get("evidence", "无证据"),
                        )
                        if not is_na:
                            ui_failures.append(f"不适用判定-{name}缺少证据")
                for name in ("合法CSV导入", "畸形CSV导入", "合法TXT导入", "畸形TXT导入", "重复记录"):
                    add_section(
                        "不适用", "不适用", name,
                        "SNMP实机页面无导入入口且后端仅注册单例show/save，不能构造文件或重复记录操作",
                    )
                rec.set_actual({
                    "tab_index": structure.get("tab_index"),
                    "v1": "不适用" if v1_not_applicable else "证据失败",
                    "oid_input": "不适用" if oid_not_applicable else "存在",
                    "security_options": security_options,
                    "auth_protocol_options": auth_options,
                    "privacy_protocol_options": priv_options,
                    "v3_hides_v2_fields": v3_hides_v2_fields,
                    "v2_hides_v3_fields": v2_hides_v3_fields,
                    "show_api": show_api or {"status": "未命中"},
                    "supported": sorted(k for k, v in capabilities.items() if v.get("supported")),
                    "not_applicable": sorted(k for k, v in capabilities.items() if not v.get("supported")),
                })

            v2_expected = {
                "enabled": "yes", "listen_port": candidate_ports[0],
                "syslocation": f"{prefix}loc", "syscontact": f"{prefix}contact",
                "sysname": sysname_v2, "version": 2, "source": "192.168.148.2",
                "rw": "ro", "username": "", "security": "",
                "auth_proto": "", "priv_proto": "",
            }
            with rec.step(
                "步骤3 操作：启用SNMP V2C只读服务；验证：L1数据库与页面回显",
                "操作：设置动态端口、系统信息、唯一community和LAN来源；验证：字段类型、值、默认/空字段及秘密只在内存比较",
            ):
                save_form({
                    "enabled": True, "listen_port": candidate_ports[0],
                    "syslocation": v2_expected["syslocation"],
                    "syscontact": v2_expected["syscontact"],
                    "sysname": sysname_v2, "version": "v2c",
                    "community": v2_community, "source": "192.168.148.2",
                    "rw": False,
                }, "V2C")
                page.navigate_to_snmp_server()
                state = page.get_safe_form_state()
                ui_check("V2C页面开关回显", state.get("enabled") is True, state)
                ui_check("V2C版本回显", "V2C" in str(state.get("version")), state)
                require_ssh(
                    "L1-V2C数据库",
                    backend.verify_snmp_database,
                    v2_expected,
                    {"community": v2_community, "auth_pass": "", "priv_pass": ""},
                )

            with rec.step(
                "步骤4 操作：等待V2C服务启动；验证：L2生成配置、L3进程/PID、UDP4/UDP6和防火墙适用性",
                "操作：读取运行态；验证：DB到netsnmp.sh、snmpd.conf、snmpd/子代理、双栈UDP及UPnP链路一致",
            ):
                require_ssh(
                    "L4-V2C全链路一致性",
                    verify_runtime_with_retry,
                    v2_expected,
                    {"community": v2_community, "auth_pass": "", "priv_pass": ""},
                )
                # Explicit calls keep each layer independently copy-verifiable.
                require_ssh(
                    "L2-V2C生成配置", backend.verify_snmp_generated_config,
                    v2_expected, {"community": v2_community, "auth_pass": "", "priv_pass": ""}, True,
                )
                require_ssh("L3-V2C进程", backend.verify_snmp_processes, True)
                require_ssh("L3-V2C监听", backend.verify_snmp_listener, candidate_ports[0], True)
                require_ssh("L3-V2C防火墙", backend.verify_snmp_firewall, candidate_ports[0], True)

            with rec.step(
                "步骤5 操作：从10.66.0.18执行真实V2C snmpget/snmpwalk；验证：正确OID与配置值",
                "操作：客户端经ens11访问192.168.148.1动态端口；验证：正确版本、OID和sysName值，并遍历system树",
            ):
                require_ssh(
                    "L5-LAN路由路径", backend.verify_snmp_client_route,
                    LAN_HOST, LAN_IFACE,
                )
                require_ssh(
                    "L5-WAN路由路径", backend.verify_snmp_client_route,
                    WAN_HOST, WAN_IFACE,
                )
                require_ssh(
                    "L5-V2C get", backend.run_snmp_probe,
                    "v2c", f"{LAN_HOST}:{candidate_ports[0]}", SYSTEM_NAME_OID,
                    operation="get", community=v2_community,
                    expect_success=True, expected_value=sysname_v2,
                )
                require_ssh(
                    "L5-V2C walk", backend.run_snmp_probe,
                    "v2c", f"{LAN_HOST}:{candidate_ports[0]}", SYSTEM_TREE_OID,
                    operation="walk", community=v2_community,
                    expect_success=True,
                )

            with rec.step(
                "步骤6 操作：执行V2C负向协议场景；验证：错误community、错误OID和无权限来源均拒绝",
                "操作：分别使用错误community、非法OID和WAN来源；验证：不得返回有效OID值，正确LAN控制组保持可用",
            ):
                require_ssh(
                    "L5-错误community拒绝", backend.run_snmp_probe,
                    "v2c", f"{LAN_HOST}:{candidate_ports[0]}", SYSTEM_NAME_OID,
                    operation="get", community=wrong_community, expect_success=False,
                    expected_failure="authentication",
                )
                require_ssh(
                    "L5-错误OID拒绝", backend.run_snmp_probe,
                    "v2c", f"{LAN_HOST}:{candidate_ports[0]}", INVALID_OID,
                    operation="get", community=v2_community, expect_success=False,
                    expected_failure="oid",
                )
                require_ssh(
                    "L5-WAN来源无权限", backend.run_snmp_probe,
                    "v2c", f"{WAN_HOST}:{candidate_ports[0]}", SYSTEM_NAME_OID,
                    operation="get", community=v2_community, expect_success=False,
                    expected_failure="source",
                )

            edited_expected = dict(v2_expected)
            edited_expected.update({
                "listen_port": candidate_ports[1], "sysname": f"{prefix}edited",
                "rw": "rw", "source": "",
            })
            with rec.step(
                "步骤7 操作：编辑V2C端口、系统名、来源和读写权限；验证：旧运行态迁移且新值生效",
                "操作：单例表单编辑并保存；验证：旧端口释放、新端口双栈监听、DB/配置无漏下发",
            ):
                page.navigate_to_snmp_server()
                save_form({
                    "listen_port": candidate_ports[1], "sysname": edited_expected["sysname"],
                    "source": "", "rw": True,
                }, "V2C编辑")
                require_ssh(
                    "L4-V2C编辑后全链路",
                    verify_runtime_with_retry,
                    edited_expected,
                    {"community": v2_community, "auth_pass": "", "priv_pass": ""},
                )
                require_ssh("L3-旧端口释放", backend.verify_snmp_listener, candidate_ports[0], False)
                require_ssh(
                    "L5-编辑后V2C值", backend.run_snmp_probe,
                    "v2c", f"{LAN_HOST}:{candidate_ports[1]}", SYSTEM_NAME_OID,
                    community=v2_community, expected_value=edited_expected["sysname"],
                )

            with rec.step(
                "步骤8 操作：停用后再启用SNMP；验证：DB、配置、进程、监听及真实协议全链路",
                "操作：关闭服务并验证拒绝，再重新开启；验证：停用无残留、启用恢复且PID有效",
            ):
                page.navigate_to_snmp_server()
                save_form({"enabled": False}, "停用")
                stopped_expected = dict(edited_expected)
                stopped_expected["enabled"] = "no"
                require_ssh(
                    "L4-停用后全链路",
                    verify_runtime_with_retry,
                    stopped_expected,
                    {"community": v2_community, "auth_pass": "", "priv_pass": ""},
                )
                require_ssh(
                    "L5-停用拒绝", backend.run_snmp_probe,
                    "v2c", f"{LAN_HOST}:{candidate_ports[1]}", SYSTEM_NAME_OID,
                    community=v2_community, expect_success=False,
                    expected_failure="stopped",
                )
                page.navigate_to_snmp_server()
                save_form({"enabled": True}, "重新启用")
                require_ssh(
                    "L4-重新启用后全链路",
                    verify_runtime_with_retry,
                    edited_expected,
                    {"community": v2_community, "auth_pass": "", "priv_pass": ""},
                )

            with rec.step(
                "步骤9 操作：执行netsnmp.sh init服务重载；验证：L4重载后配置、PID、监听和协议不丢失",
                "操作：调用实机确认的后端init入口；验证：DB到运行态仍一致且snmpget继续返回编辑后值",
            ):
                require_ssh(
                    "L4-V2C服务重载", backend.verify_snmp_reinit,
                    edited_expected,
                    {"community": v2_community, "auth_pass": "", "priv_pass": ""},
                )
                require_ssh(
                    "L5-重载后get", backend.run_snmp_probe,
                    "v2c", f"{LAN_HOST}:{candidate_ports[1]}", SYSTEM_NAME_OID,
                    community=v2_community, expected_value=edited_expected["sysname"],
                )

            v3_auth_expected = {
                "enabled": "yes", "listen_port": candidate_ports[2],
                "syslocation": f"{prefix}loc3", "syscontact": f"{prefix}contact3",
                "sysname": f"{prefix}v3auth", "version": 3, "community": "",
                "source": "", "rw": "ro", "username": v3_user,
                "security": "authNoPriv", "auth_proto": "MD5", "priv_proto": "",
            }
            v3_auth_secrets = {
                "community": "", "auth_pass": v3_auth, "priv_pass": "",
            }
            with rec.step(
                "步骤10 操作：切换并保存V3认证不加密；验证：MD5、L1-L4及旧V2端口迁移",
                "操作：选择authNoPriv、MD5和唯一认证口令；验证：页面动态字段、DB、生成配置、进程和UDP监听一致",
            ):
                page.navigate_to_snmp_server()
                save_form({
                    "enabled": True, "listen_port": candidate_ports[2],
                    "syslocation": v3_auth_expected["syslocation"],
                    "syscontact": v3_auth_expected["syscontact"],
                    "sysname": v3_auth_expected["sysname"], "version": "v3",
                    "username": v3_user, "security": "authNoPriv",
                    "auth_proto": "MD5", "auth_pass": v3_auth, "rw": False,
                }, "V3 authNoPriv")
                state = page.get_safe_form_state()
                ui_check("V3 authNoPriv动态字段出现", all(
                    state.get("present", {}).get(field)
                    for field in ("username", "security", "auth_proto", "auth_pass")
                ), state)
                add_section(
                    "不适用", "不适用", "authNoPriv隐私算法与隐私口令",
                    "当前安全级别仅认证不加密，隐私算法和隐私口令不参与保存、配置或协议命令",
                )
                require_ssh(
                    "L1-V3 authNoPriv数据库", backend.verify_snmp_database,
                    v3_auth_expected, v3_auth_secrets,
                )
                require_ssh(
                    "L2-V3 authNoPriv生成配置", backend.verify_snmp_generated_config,
                    v3_auth_expected, v3_auth_secrets, True,
                )
                require_ssh("L3-V3 authNoPriv进程", backend.verify_snmp_processes, True)
                require_ssh(
                    "L3-V3 authNoPriv监听", backend.verify_snmp_listener,
                    candidate_ports[2], True,
                )
                require_ssh(
                    "L4-V3 authNoPriv全链路", verify_runtime_with_retry,
                    v3_auth_expected, v3_auth_secrets,
                )
                require_ssh("L3-V2旧端口释放", backend.verify_snmp_listener, candidate_ports[1], False)

            with rec.step(
                "步骤11 操作：执行authNoPriv真实get/walk及错误认证；验证：MD5正向控制成功且错误口令拒绝",
                "操作：先用正确认证口令执行snmpget/snmpwalk，紧接着改用错误认证口令；验证：正确OID和值返回，错误凭据无有效数据",
            ):
                require_ssh(
                    "L5-authNoPriv正向get", backend.run_snmp_probe,
                    "v3", f"{LAN_HOST}:{candidate_ports[2]}", SYSTEM_NAME_OID,
                    username=v3_user, security="authNoPriv", auth_proto="MD5",
                    auth_pass=v3_auth, expected_value=v3_auth_expected["sysname"],
                )
                require_ssh(
                    "L5-authNoPriv正向walk", backend.run_snmp_probe,
                    "v3", f"{LAN_HOST}:{candidate_ports[2]}", SYSTEM_TREE_OID,
                    operation="walk", username=v3_user, security="authNoPriv",
                    auth_proto="MD5", auth_pass=v3_auth,
                )
                require_ssh(
                    "L5-authNoPriv错误认证拒绝", backend.run_snmp_probe,
                    "v3", f"{LAN_HOST}:{candidate_ports[2]}", SYSTEM_NAME_OID,
                    username=v3_user, security="authNoPriv", auth_proto="MD5",
                    auth_pass=wrong_auth,
                    expect_success=False,
                    expected_failure="authentication",
                )

            v3_expected = dict(v3_auth_expected)
            v3_expected.update({
                "sysname": sysname_v3,
                "security": "authPriv", "auth_proto": "SHA", "priv_proto": "AES",
            })
            v3_secrets = {
                "community": "", "auth_pass": v3_auth, "priv_pass": v3_priv,
            }
            with rec.step(
                "步骤12 操作：切换并保存V3认证且加密；验证：SHA/AES动态字段及L1-L4一致",
                "操作：选择authPriv、SHA、AES与唯一隐私口令；验证：页面、数据库、生成配置、进程和UDP监听完整下发",
            ):
                page.navigate_to_snmp_server()
                save_form({
                    "enabled": True, "listen_port": v3_expected["listen_port"],
                    "syslocation": v3_expected["syslocation"],
                    "syscontact": v3_expected["syscontact"],
                    "sysname": sysname_v3, "version": "v3",
                    "username": v3_user, "security": "authPriv",
                    "auth_proto": "SHA", "auth_pass": v3_auth,
                    "priv_proto": "AES", "priv_pass": v3_priv, "rw": False,
                }, "V3 authPriv")
                state = page.get_safe_form_state()
                ui_check("V3 authPriv动态字段出现", all(
                    state.get("present", {}).get(field)
                    for field in (
                        "username", "security", "auth_proto", "auth_pass",
                        "priv_proto", "priv_pass",
                    )
                ), state)
                require_ssh(
                    "L1-V3 authPriv数据库", backend.verify_snmp_database,
                    v3_expected, v3_secrets,
                )
                require_ssh(
                    "L2-V3 authPriv生成配置", backend.verify_snmp_generated_config,
                    v3_expected, v3_secrets, True,
                )
                require_ssh("L3-V3 authPriv进程", backend.verify_snmp_processes, True)
                require_ssh(
                    "L3-V3 authPriv监听", backend.verify_snmp_listener,
                    candidate_ports[2], True,
                )
                require_ssh(
                    "L4-V3 authPriv全链路", verify_runtime_with_retry,
                    v3_expected, v3_secrets,
                )

            with rec.step(
                "步骤13 操作：执行authPriv真实get/walk及错误隐私口令；验证：SHA/AES正向控制成功且解密失败",
                "操作：先用正确认证和隐私口令执行snmpget/snmpwalk，紧接着仅替换隐私口令；验证：正确值返回且错误隐私口令无有效数据",
            ):
                require_ssh(
                    "L5-authPriv正向get", backend.run_snmp_probe,
                    "v3", f"{LAN_HOST}:{candidate_ports[2]}", SYSTEM_NAME_OID,
                    username=v3_user, security="authPriv", auth_proto="SHA",
                    auth_pass=v3_auth, priv_proto="AES", priv_pass=v3_priv,
                    expected_value=sysname_v3,
                )
                require_ssh(
                    "L5-authPriv正向walk", backend.run_snmp_probe,
                    "v3", f"{LAN_HOST}:{candidate_ports[2]}", SYSTEM_TREE_OID,
                    operation="walk", username=v3_user, security="authPriv",
                    auth_proto="SHA", auth_pass=v3_auth, priv_proto="AES",
                    priv_pass=v3_priv,
                )
                require_ssh(
                    "L5-10.66.0.18到10.66.0.150正向get",
                    backend.run_snmp_probe,
                    "v3", f"{WAN_HOST}:{candidate_ports[2]}", SYSTEM_NAME_OID,
                    username=v3_user, security="authPriv", auth_proto="SHA",
                    auth_pass=v3_auth, priv_proto="AES", priv_pass=v3_priv,
                    expected_value=sysname_v3,
                )
                require_ssh(
                    "L5-10.66.0.18到10.66.0.150正向walk",
                    backend.run_snmp_probe,
                    "v3", f"{WAN_HOST}:{candidate_ports[2]}", SYSTEM_TREE_OID,
                    operation="walk", username=v3_user, security="authPriv",
                    auth_proto="SHA", auth_pass=v3_auth, priv_proto="AES",
                    priv_pass=v3_priv,
                )
                require_ssh(
                    "L5-authPriv错误隐私口令拒绝", backend.run_snmp_probe,
                    "v3", f"{LAN_HOST}:{candidate_ports[2]}", SYSTEM_NAME_OID,
                    username=v3_user, security="authPriv", auth_proto="SHA",
                    auth_pass=v3_auth, priv_proto="AES", priv_pass=wrong_priv,
                    expect_success=False,
                    expected_failure="privacy",
                )

            with rec.step(
                "步骤14 操作：在V3模式执行netsnmp.sh init；验证：L1-L4重建后get/walk协议仍可用",
                "操作：调用实机确认的产品init链路并重新执行真实V3协议；验证：SHA/AES配置、进程、监听、OID和值均未丢失",
            ):
                require_ssh(
                    "L4-V3服务重载", backend.verify_snmp_reinit,
                    v3_expected, v3_secrets,
                )
                require_ssh(
                    "L5-V3重载后get", backend.run_snmp_probe,
                    "v3", f"{LAN_HOST}:{candidate_ports[2]}", SYSTEM_NAME_OID,
                    username=v3_user, security="authPriv", auth_proto="SHA",
                    auth_pass=v3_auth, priv_proto="AES", priv_pass=v3_priv,
                    expected_value=sysname_v3,
                )
                require_ssh(
                    "L5-V3重载后walk", backend.run_snmp_probe,
                    "v3", f"{LAN_HOST}:{candidate_ports[2]}", SYSTEM_TREE_OID,
                    operation="walk", username=v3_user, security="authPriv",
                    auth_proto="SHA", auth_pass=v3_auth, priv_proto="AES",
                    priv_pass=v3_priv,
                )

            with rec.step(
                "步骤15 操作：验证取消确认的关闭与确定分支；验证：关闭保留编辑、确定还原且DB不变",
                "操作：临时修改系统信息后两次点击取消；验证：弹窗取消继续编辑、确定恢复上次状态，无保存请求落库",
            ):
                before = backend.get_snmp_environment_snapshot(candidate_ports)
                page.navigate_to_snmp_server()
                page.fill_sysname(f"{prefix}cancel")
                kept = page.cancel_changes(confirm_discard=False)
                ui_check("取消弹窗关闭分支", kept.get("kept_editing"), kept)
                discarded = page.cancel_changes(confirm_discard=True)
                ui_check("取消弹窗确定分支", discarded.get("confirmed_discard"), discarded)
                require_ssh(
                    "L4-取消未修改环境", backend.verify_snmp_environment_unchanged,
                    before, True,
                )

            with rec.step(
                "步骤16 操作：验证帮助入口打开、内容匹配和关闭；验证：SNMP服务端主题且无孤儿页面",
                "操作：点击帮助并读取标题/正文主题；验证：SNMP关键词命中，popup关闭并返回原页面",
            ):
                page.navigate_to_snmp_server()
                help_result = page.verify_help_entry(expected_keywords=("SNMP", "服务端"))
                ui_check("帮助已打开", help_result.get("opened"), help_result)
                ui_check("帮助内容匹配", help_result.get("all_keywords_matched"), help_result, product=True)
                ui_check("帮助已关闭且无孤儿页", help_result.get("closed") and help_result.get("no_orphan"), help_result)

            with rec.step(
                "步骤17 操作：占用空闲UDP端口后尝试保存；验证：页面拒绝且DB、配置和SNMP运行态不变",
                "操作：用精确PID守卫占用第四个候选UDP端口并提交该端口；验证：保存失败反馈明确，finally仅清理守卫进程和PID文件",
            ):
                udp_guard_port = candidate_ports[3]
                try:
                    guard_started = require_ssh(
                        "L3-启动UDP端口占用守卫",
                        backend.start_snmp_udp_port_guard,
                        udp_guard_port,
                        fatal=True,
                    )
                    if getattr(guard_started, "passed", False):
                        expect_rejected(
                            "UDP端口已被占用",
                            {"listen_port": udp_guard_port},
                        )
                finally:
                    stopped_guard = ssh_verify(
                        "清理-精确停止UDP端口占用守卫",
                        backend.stop_snmp_udp_port_guard,
                        udp_guard_port,
                        must_pass=True,
                    )
                    if getattr(stopped_guard, "passed", False):
                        udp_guard_port = None
                require_ssh(
                    "L3-占用守卫清理后端口释放",
                    backend.verify_snmp_listener,
                    candidate_ports[3],
                    False,
                )
                require_ssh(
                    "L4-占用端口拒绝后V3全链路",
                    verify_runtime_with_retry,
                    v3_expected,
                    v3_secrets,
                )

            community_boundary_expected = {
                "enabled": "yes", "listen_port": candidate_ports[0],
                "syslocation": f"{prefix}community_loc",
                "syscontact": f"{prefix}community_contact",
                "sysname": f"{prefix}community500", "version": 2,
                "source": "", "rw": "ro", "username": "", "security": "",
                "auth_proto": "", "priv_proto": "",
            }
            community_boundary_secrets = {
                "community": community_boundary_500,
                "auth_pass": "", "priv_pass": "",
            }
            with rec.step(
                "步骤18 操作：验证community空格、500和501字符边界；验证：拒绝、maxlength截断、DB和运行态一致",
                "操作：先提交纯空格，再独立保存500字符并以501字符真实逐键输入后保存；验证：秘密正文不出报告，控件截断为500且DB仅存500字符",
            ):
                community_snapshot = backend.get_snmp_environment_snapshot(candidate_ports)
                try:
                    expect_rejected(
                        "community纯空格",
                        {"version": "v2c", "community": "   "},
                    )

                    page.navigate_to_snmp_server()
                    save_form({
                        "enabled": True,
                        "listen_port": community_boundary_expected["listen_port"],
                        "syslocation": community_boundary_expected["syslocation"],
                        "syscontact": community_boundary_expected["syscontact"],
                        "sysname": community_boundary_expected["sysname"],
                        "version": "v2c", "community": community_boundary_500,
                        "source": "", "rw": False,
                    }, "community 500字符边界")
                    observation_500 = page.get_safe_field_observation("community")
                    ui_check(
                        "community 500字符合法边界",
                        observation_500.get("maxlength") in {500, "500"}
                        and observation_500.get("length") == 500
                        and page.field_matches("community", community_boundary_500),
                        {
                            "maxlength": observation_500.get("maxlength"),
                            "received_length": observation_500.get("length"),
                        },
                        product=True,
                    )
                    require_ssh(
                        "L1-community 500字符数据库",
                        backend.verify_snmp_database,
                        community_boundary_expected,
                        community_boundary_secrets,
                    )
                    require_ssh(
                        "L4-community 500字符全链路",
                        verify_runtime_with_retry,
                        community_boundary_expected,
                        community_boundary_secrets,
                    )
                    require_ssh(
                        "L2-community 500字符生成配置",
                        backend.verify_snmp_generated_config,
                        community_boundary_expected,
                        community_boundary_secrets,
                        True,
                    )
                    community_500_probe = ssh_verify(
                        "L5-community 500字符get", backend.run_snmp_probe,
                        "v2c",
                        f"{LAN_HOST}:{community_boundary_expected['listen_port']}",
                        SYSTEM_NAME_OID,
                        community=community_boundary_500,
                        expected_value=community_boundary_expected["sysname"],
                        must_pass=False,
                    )
                    ui_check(
                        "community 500字符真实协议可用",
                        getattr(community_500_probe, "passed", False),
                        "页面按maxlength=500允许保存，且DB/配置/进程/"
                        "双栈监听一致，但真实snmpget超时，生成了不可用服务",
                        product=True,
                    )

                    page.navigate_to_snmp_server()
                    fill_501 = page.fill_form({
                        "community": community_boundary_501,
                    })
                    observation_501 = page.get_safe_field_observation("community")
                    truncated_to_500 = bool(
                        fill_501.get("success")
                        and observation_501.get("maxlength") in {500, "500"}
                        and observation_501.get("length") == 500
                        and page.field_matches("community", community_boundary_500)
                        and not page.field_matches("community", community_boundary_501)
                    )
                    ui_check(
                        "community 501字符受maxlength截断",
                        truncated_to_500,
                        {
                            "maxlength": observation_501.get("maxlength"),
                            "attempted_length": 501,
                            "received_length": observation_501.get("length"),
                        },
                        product=True,
                    )
                    saved_501 = page.save_settings(timeout=12000)
                    api_501 = dict(saved_501.get("api") or {})
                    ui_check(
                        "community 501输入按500字符保存",
                        truncated_to_500
                        and saved_501.get("success")
                        and api_501.get("requested")
                        and api_501.get("responded")
                        and api_501.get("function") == "netsnmp"
                        and api_501.get("action") == "save"
                        and api_501.get("method") == "POST"
                        and api_501.get("endpoint") == "call"
                        and api_501.get("status") == 200,
                        {
                            "page_success": bool(saved_501.get("success")),
                            "api_requested": bool(api_501.get("requested")),
                            "api_responded": bool(api_501.get("responded")),
                            "api_function": api_501.get("function"),
                            "api_action": api_501.get("action"),
                            "api_method": api_501.get("method"),
                            "api_endpoint": api_501.get("endpoint"),
                            "api_status": api_501.get("status"),
                        },
                        product=True,
                    )
                    require_ssh(
                        "L1-community 501截断后数据库仍为500字符",
                        backend.verify_snmp_database,
                        community_boundary_expected,
                        community_boundary_secrets,
                    )
                    require_ssh(
                        "L4-community 501截断后全链路",
                        verify_runtime_with_retry,
                        community_boundary_expected,
                        community_boundary_secrets,
                    )
                    community_501_probe = ssh_verify(
                        "L5-community 501截断后get", backend.run_snmp_probe,
                        "v2c",
                        f"{LAN_HOST}:{community_boundary_expected['listen_port']}",
                        SYSTEM_NAME_OID,
                        community=community_boundary_500,
                        expected_value=community_boundary_expected["sysname"],
                        must_pass=False,
                    )
                    ui_check(
                        "community 501截断后真实协议可用",
                        getattr(community_501_probe, "passed", False),
                        "501字符被页面截为500并保存，真实snmpget仍超时，"
                        "与500字符上限场景为同一产品协议缺陷",
                        product=True,
                    )
                finally:
                    restored_boundary = ssh_verify(
                        "清理-community边界独立快照恢复",
                        backend.restore_snmp_environment,
                        community_snapshot,
                        must_pass=True,
                    )
                    add_section(
                        "清理结果",
                        "通过" if getattr(restored_boundary, "passed", False) else "失败",
                        "community边界独立恢复",
                        getattr(restored_boundary, "message", "无恢复结果"),
                    )
                require_ssh(
                    "L4-community边界恢复后V3全链路",
                    verify_runtime_with_retry,
                    v3_expected,
                    v3_secrets,
                )

            with rec.step(
                "步骤19 操作：提交空值、空格、非法字符、超长值和错误端口；验证：控件不接收或保存明确拒绝且DB/运行态不变",
                "操作：逐项触发表单/后端校验；验证：原生控件限制、maxlength截断或失败反馈明确，不能静默落库非法值",
            ):
                invalid_cases = [
                    ("监听端口空值", {"listen_port": ""}),
                    ("监听端口纯空格", {"listen_port": "   "}),
                    ("监听端口零", {"listen_port": "0"}),
                    ("监听端口越界", {"listen_port": "65536"}),
                    ("监听端口字符", {"listen_port": "abc"}),
                    ("错误来源地址", {
                        "version": "v2c", "community": v2_community,
                        "source": "999.999.999.999",
                    }),
                    ("community空值", {"version": "v2c", "community": ""}),
                    ("V3用户名空值", {"version": "v3", "username": "", "security": "authNoPriv", "auth_pass": v3_auth}),
                    ("认证口令短于8", {"version": "v3", "username": v3_user, "security": "authNoPriv", "auth_pass": "short"}),
                    ("隐私口令短于8", {"version": "v3", "username": v3_user, "security": "authPriv", "auth_pass": v3_auth, "priv_pass": "short"}),
                    ("系统名非法控制字符", {"sysname": "bad\nname"}),
                    ("系统名超长", {"sysname": prefix + "x" * 520}),
                ]
                for label, values in invalid_cases:
                    expect_rejected(label, values)

            with rec.step(
                "步骤20 操作：验证V3密码边界长度；验证：8与30字符合法且31字符保存明确拒绝",
                "操作：分别保存8/30字符认证与隐私口令，再提交31字符；验证：页面拒绝且DB、配置和活动运行态语义不变",
            ):
                for length in (8, 30):
                    auth_value = "A" + secrets.token_urlsafe(40)[:length - 1]
                    priv_value = "P" + secrets.token_urlsafe(40)[:length - 1]
                    boundary_expected = dict(v3_expected)
                    boundary_expected.update({
                        "security": "authPriv",
                        "auth_proto": "MD5",
                        "priv_proto": "DES",
                    })
                    boundary_secrets = {
                        "community": "",
                        "auth_pass": auth_value,
                        "priv_pass": priv_value,
                    }
                    page.navigate_to_snmp_server()
                    save_form({
                        "enabled": True, "listen_port": v3_expected["listen_port"],
                        "syslocation": v3_expected["syslocation"],
                        "syscontact": v3_expected["syscontact"],
                        "sysname": v3_expected["sysname"],
                        "version": "v3", "security": "authPriv", "username": v3_user,
                        "auth_proto": "MD5", "auth_pass": auth_value,
                        "priv_proto": "DES", "priv_pass": priv_value, "rw": False,
                    }, f"V3口令{length}字符边界")
                    require_ssh(
                        f"L1-V3口令{length}字符",
                        backend.verify_snmp_database,
                        boundary_expected,
                        boundary_secrets,
                    )
                    require_ssh(
                        f"L4-V3口令{length}字符全链路",
                        verify_runtime_with_retry,
                        boundary_expected,
                        boundary_secrets,
                    )
                    require_ssh(
                        f"L2-V3口令{length}字符生成配置",
                        backend.verify_snmp_generated_config,
                        boundary_expected,
                        boundary_secrets,
                        True,
                    )
                    require_ssh(
                        f"L5-MD5-DES口令{length}字符get",
                        backend.run_snmp_probe,
                        "v3", f"{LAN_HOST}:{v3_expected['listen_port']}",
                        SYSTEM_NAME_OID,
                        username=v3_user, security="authPriv",
                        auth_proto="MD5", auth_pass=auth_value,
                        priv_proto="DES", priv_pass=priv_value,
                        expected_value=v3_expected["sysname"],
                    )
                    require_ssh(
                        f"L5-MD5-DES口令{length}字符walk",
                        backend.run_snmp_probe,
                        "v3", f"{LAN_HOST}:{v3_expected['listen_port']}",
                        SYSTEM_TREE_OID, operation="walk",
                        username=v3_user, security="authPriv",
                        auth_proto="MD5", auth_pass=auth_value,
                        priv_proto="DES", priv_pass=priv_value,
                    )
                expect_rejected("V3认证口令31字符", {
                    "version": "v3", "security": "authNoPriv", "username": v3_user,
                    "auth_proto": "SHA", "auth_pass": "A" * 31,
                })

            with rec.step(
                "步骤21 操作：最终恢复并复验原始配置；验证：L1-L5无测试前缀、候选监听或客户端临时文件",
                "操作：精确恢复singleton快照；验证：DB、配置、进程、PID、监听、防火墙和非测试指纹回到测试前",
            ):
                if not snapshot_valid or snapshot is None:
                    pytest.fail("缺少有效快照，禁止声明恢复完成")
                restored = ssh_verify(
                    "清理-恢复SNMP原始环境", backend.restore_snmp_environment,
                    snapshot, must_pass=True,
                )
                ui_check("恢复调用成功", getattr(restored, "passed", False), getattr(restored, "message", ""))
                audit = ssh_verify(
                    "清理-恢复后残留审计", backend.verify_snmp_test_artifacts_absent,
                    prefix, candidate_ports, snapshot, must_pass=True,
                )
                fingerprint = ssh_verify(
                    "清理-恢复后全环境指纹",
                    backend.verify_snmp_environment_unchanged,
                    snapshot,
                    True,
                    must_pass=True,
                )
                mutation_started = not all(
                    getattr(result, "passed", False)
                    for result in (restored, audit, fingerprint)
                )

        finally:
            add_section("清理结果", "进行中", "finally", "开始独立残留审计与精确快照恢复")
            if udp_guard_port is not None:
                try:
                    stopped_guard = ssh_verify(
                        "finally-精确停止UDP端口占用守卫",
                        backend.stop_snmp_udp_port_guard,
                        udp_guard_port,
                        must_pass=True,
                    )
                    add_section(
                        "清理结果",
                        "通过" if getattr(stopped_guard, "passed", False) else "失败",
                        "UDP占用守卫",
                        getattr(stopped_guard, "message", "无清理结果"),
                    )
                    if getattr(stopped_guard, "passed", False):
                        udp_guard_port = None
                except Exception as exc:
                    ssh_failures.append(f"finally端口占用守卫清理异常：{str(exc)[:180]}")
            if mutation_started:
                try:
                    # Restore first because the SNMP page is a singleton: there is no
                    # independently deletable test row. Then audit prefix and all layers.
                    if snapshot_valid and snapshot is not None:
                        restored = ssh_verify(
                            "finally-精确恢复原始SNMP环境",
                            backend.restore_snmp_environment,
                            snapshot,
                            must_pass=True,
                        )
                        add_section(
                            "清理结果", "通过" if getattr(restored, "passed", False) else "失败",
                            "精确恢复", getattr(restored, "message", "无结果"),
                        )
                        ssh_verify(
                            "finally-恢复后测试残留审计",
                            backend.verify_snmp_test_artifacts_absent,
                            prefix, candidate_ports, snapshot,
                            must_pass=True,
                        )
                        ssh_verify(
                            "finally-恢复后全环境指纹",
                            backend.verify_snmp_environment_unchanged,
                            snapshot, True,
                            must_pass=True,
                        )
                    else:
                        ssh_failures.append("已开始SNMP变更但没有有效快照，无法精确恢复")
                except Exception as exc:
                    ssh_failures.append(f"finally恢复异常：{str(exc)[:180]}")
            else:
                add_section("清理结果", "通过", "finally", "设备已在主流程恢复或未开始变更")

        failures = ssh_failures + ui_failures + product_failures
        if failures:
            print(
                f"[SNMP断言] 共{len(failures)}项失败 "
                f"(后端/自动化={len(ssh_failures) + len(ui_failures)}, 产品={len(product_failures)})",
                flush=True,
            )
            for failure in failures[:60]:
                print(f"  - {failure}", flush=True)
        assert not failures, (
            f"SNMP服务L1-L5综合验证失败({len(failures)}项): "
            + "; ".join(failures[:40])
        )
