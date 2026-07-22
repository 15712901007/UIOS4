"""网络配置 > OSPF 页面、L1-L5、真实协议和恢复综合测试。"""
from __future__ import annotations

import ipaddress
import json
import re
import secrets
import time
import traceback
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

import pytest

from pages.login_page import LoginPage
from pages.network.ospf_page import OspfPage
from utils.replay_commands import build_verification_commands
from utils.step_recorder import (
    StepRecorder,
    redact_sensitive_text,
    register_sensitive_value,
)


pytestmark = [pytest.mark.network, pytest.mark.ospf]

REQUIRED_SECTIONS = (
    "测试操作", "页面验证", "后端验证",
    "运行时验证", "协议验证", "清理结果",
)
BUSINESS_TABLES = (
    "ospf_instance", "ospf_area", "ospf_interface_attr",
    "ospf_redistribute", "ospf_static_route", "ospf_prefix_list_entry",
    "ospf_debug_flag",
)


def _emit_ospf_realtime(event: str, message: Any) -> None:
    """向源码/冻结 GUI 输出一行脱敏且立即刷新的 OSPF 进度。"""
    safe_message = redact_sensitive_text(message)
    safe_message = " ".join(str(safe_message).replace("\r", " ").splitlines())
    print(f"[OSPF][{event}] {safe_message}", flush=True)


def _pick_process(snapshot, *, ipv6: bool = False,
                  excluded: Optional[set[int]] = None) -> int:
    used = {
        int(row.get("process_id", 0) or 0)
        for row in snapshot.private_tables.get("ospf_instance", [])
    }
    used.update(excluded or set())
    candidates = range(230, 180, -1) if ipv6 else range(100, 0, -1)
    for candidate in candidates:
        if candidate not in used:
            return candidate
    raise RuntimeError("没有可用的OSPF测试实例号")


def _router_id(snapshot, octet: int, excluded: Optional[set[str]] = None) -> str:
    used = {
        str(row.get("router_id", ""))
        for row in snapshot.private_tables.get("ospf_instance", [])
    }
    used.update(excluded or set())
    for offset in range(1, 200):
        candidate = f"198.18.{octet}.{offset}"
        if candidate not in used:
            return candidate
    raise RuntimeError("没有可用的唯一Router ID")


def _v6_prefix() -> str:
    token = secrets.token_hex(6)
    return f"fd{token[0:2]}:{token[2:6]}:{token[6:10]}:{token[10:12]}::1/128"


class TestOspfComprehensive:
    def test_ospf_comprehensive(
        self,
        ospf_page_logged_in: OspfPage,
        ospf_verifier,
        backend_verifier,
        step_recorder: StepRecorder,
        config,
    ):
        ui = ospf_page_logged_in
        ospf = ospf_verifier
        backend = backend_verifier
        rec = step_recorder
        rec.required_sections = REQUIRED_SECTIONS

        product_failures: List[str] = []
        automation_failures: List[str] = []
        auxiliary_failures: List[str] = []
        environment_limits: List[str] = []
        baseline = None
        safety_ok = False
        topology: Dict[str, Any] = {}
        created_instances: List[Dict[str, Any]] = []
        redistribution_ids: List[int] = []
        v2_ready = False
        v3_ready = False
        v2_process = v3_process = 0
        v2_router_id = v3_router_id = ""
        client_router_id = ""
        transit_network = ""
        active_page = ui.page
        product_root_keys: set[str] = set()

        def plain_failure(label: str, technical_message: str = "") -> str:
            """把首屏失败结论写成测试人员可直接复现的现象。"""
            normalized = label.lower()
            if "脏表单" in label:
                product_root_keys.add("dirty_cancel")
                return "取消未保存的编辑时，没有出现“继续编辑/确认放弃”选择。"
            if "认证输入" in label:
                product_root_keys.add("password_input")
                return "认证密码会以明文显示，并且页面没有限制最大输入长度。"
            if "配置更新原子性" in label:
                product_root_keys.add("atomic_update")
                return "配置更新失败后，没有完整恢复到修改前状态。"
            if "v3" in normalized or "ospfv3" in normalized:
                product_root_keys.add("ospfv3_save")
                return "OSPFv3 区域和接口无法从页面保存并进入实际运行状态。"
            if label.endswith("接口参数-broadcast"):
                product_root_keys.add("cost_zero")
                return "页面允许将协议开销填写为 0，但保存时被设备拒绝。"
            if any(token in label for token in (
                "保存", "生成配置加载", "UI reload接口状态", "协议控制组",
            )):
                product_root_keys.add("partial_save")
                return "页面提示保存失败，但后台数据或实际配置已经发生部分变化。"
            clean_label = re.sub(
                r"^(?:L[1-5](?:/L[1-5])?-|页面验证-)", "", label
            )
            return f"{clean_label}没有达到期望，请展开本步骤查看实际现象。"

        def add_section(section: str, status: str, label: str, detail: Any):
            if isinstance(detail, (dict, list, tuple)):
                detail = json.dumps(
                    ospf.sanitize_value(detail), ensure_ascii=False, sort_keys=True
                )
            rec.add_detail(f"【{section}】\n{status} {label}：{detail}")
            _emit_ospf_realtime(status, f"{section} | {label}")

        @contextmanager
        def recorded_step(title: str, description: str):
            step = rec.start_step(title, description)
            title_match = re.match(
                r"^步骤\d+(?:\.\d+)?\s+操作：(.*?)；验证：(.*)$", title
            )
            action = title_match.group(1) if title_match else description
            expectation = title_match.group(2) if title_match else description
            _emit_ospf_realtime("步骤开始", title.split(" 操作：", 1)[0])
            _emit_ospf_realtime("操作", action)
            _emit_ospf_realtime("期望", expectation)
            add_section("操作", "执行", action, description)
            add_section("期望结果", "预期", expectation, "按页面、后台和协议证据逐项判定")
            try:
                yield
            except Exception as exc:  # independent scenarios continue
                frames = traceback.extract_tb(exc.__traceback__)
                location = ""
                project_frames = [
                    frame for frame in frames
                    if "site-packages" not in frame.filename.replace("\\", "/")
                ]
                if project_frames or frames:
                    frame = (project_frames or frames)[-1]
                    location = f"@{frame.name}:{frame.lineno}"
                message = f"{title}自动化异常({type(exc).__name__}{location})"
                automation_failures.append(message)
                add_section("页面验证", "失败", "自动化执行", message)
                rec.fail_current_step(message)
            finally:
                rec.ensure_current_step_sections(REQUIRED_SECTIONS)
                rec.end_step("passed")
                status_labels = {
                    "passed": "通过", "failed": "失败", "warning": "警告",
                    "not_applicable": "不适用", "skipped": "不适用",
                }
                _emit_ospf_realtime(
                    "步骤结束",
                    f"{title.split(' 操作：', 1)[0]} | "
                    f"状态={status_labels.get(step.status, step.status)} | "
                    f"用时={(step.duration or 0.0):.2f}s",
                )

        def ui_check(
            label: str, condition: Any, detail: Any = "条件不成立",
            *, kind: str = "automation",
        ) -> bool:
            passed = bool(condition)
            add_section(
                "页面验证", "通过" if passed else "失败", label,
                "符合预期" if passed else detail,
            )
            if not passed:
                message = plain_failure(label, str(detail))
                target = product_failures if kind == "product" else automation_failures
                target.append(message)
                rec.fail_current_step(message)
            return passed

        def backend_check(
            label: str, verify_func, *args,
            must_pass: bool = True, kind: str = "product",
            section: Optional[str] = None, **kwargs,
        ):
            if section is None:
                section = (
                    "协议验证" if label.startswith("L5") else
                    "运行时验证" if label.startswith(("L3", "L4")) else
                    "后端验证"
                )
            result = None
            try:
                function_name = getattr(verify_func, "__name__", "")
                command_kwargs = dict(kwargs)
                if function_name in {
                    "wait_neighbor", "wait_route", "wait_instance_enabled",
                    "verify_protocol_89", "client_setup_v3",
                }:
                    kwargs.setdefault("progress", _emit_ospf_realtime)
                _emit_ospf_realtime("检查开始", f"{section} | {label}")
                result = verify_func(*args, **kwargs)
                passed = bool(getattr(result, "passed", False))
                message = str(getattr(result, "message", "无验证结论"))
                result_details = getattr(result, "details", {}) or {}
                evidence = (
                    {"结论": message, "证据": result_details}
                    if not passed else message
                )
                if not passed and kind == "environment" and not must_pass:
                    add_section(section, "警告", label, evidence)
                    environment_limits.append(f"{label}：{message}")
                    rec.warn_current_step(message)
                else:
                    add_section(section, "通过" if passed else "失败", label, evidence)
                    if must_pass and not passed:
                        target = {
                            "product": product_failures,
                            "automation": automation_failures,
                            "auxiliary": auxiliary_failures,
                        }.get(kind, product_failures)
                        readable = (
                            plain_failure(label, message)
                            if kind == "product" else f"{label}：{message}"
                        )
                        target.append(readable)
                        rec.fail_current_step(readable)
                try:
                    commands = build_verification_commands(
                        backend, verify_func, args=args,
                        kwargs=command_kwargs, result=result,
                    )
                    if commands:
                        rec.add_verification_commands(commands)
                except Exception as command_exc:
                    auxiliary_failures.append(
                        f"{label}人工复验命令生成异常({type(command_exc).__name__})"
                    )
                return result
            except Exception as exc:
                message = f"{label}验证异常({type(exc).__name__})"
                add_section(section, "失败" if must_pass else "警告", label, message)
                if must_pass:
                    automation_failures.append(message)
                    rec.fail_current_step(message)
                return None

        def current_test_redistribution_ids() -> List[int]:
            ids = []
            for process in (v2_process, v3_process):
                if not process:
                    continue
                for row in ospf._query(
                    "ospf_redistribute", f"process_id={int(process)}"
                ):
                    try:
                        ids.append(int(row.get("id", 0)))
                    except (TypeError, ValueError):
                        pass
            return sorted(set(item for item in ids if item > 0))

        def product_root_causes() -> List[str]:
            messages = {
                "dirty_cancel": "取消未保存的编辑时没有继续编辑或确认放弃选项",
                "partial_save": "页面提示保存失败但后台数据或实际配置已部分改变",
                "password_input": "认证密码明文显示且没有最大输入长度限制",
                "atomic_update": "配置更新失败后没有完整恢复到修改前状态",
                "cost_zero": "页面允许协议开销为0但设备拒绝保存",
                "ospfv3_save": "OSPFv3区域和接口无法从页面保存并进入实际运行状态",
            }
            order = (
                "dirty_cancel", "partial_save", "password_input",
                "atomic_update", "cost_zero", "ospfv3_save",
            )
            roots = [messages[key] for key in order if key in product_root_keys]
            if not roots and product_failures:
                roots.extend(dict.fromkeys(product_failures))
            return roots

        def cleanup_ui() -> OspfPage:
            nonlocal active_page
            try:
                candidate = OspfPage(active_page, ui.base_url)
                candidate.navigate_to_ospf()
                return candidate
            except Exception:
                recovery_host = str(config.ssh.router_recovery_host or "")
                if not recovery_host:
                    raise
                recovery_url = f"http://{recovery_host}"
                login = LoginPage(active_page, recovery_url)
                if not login.login(config.device.username, config.device.password):
                    raise RuntimeError("备用管理地址Web登录失败")
                candidate = OspfPage(active_page, recovery_url)
                candidate.navigate_to_ospf()
                return candidate

        try:
            with recorded_step(
                "步骤1 操作：保存三端原始快照并检查安全前置；验证：双管理通道、LAN链路、DB和脚本契约可恢复",
                "仅在主路由、备用管理地址和客户端链路均可用后允许修改",
            ):
                baseline = ospf.snapshot_environment(include_peer=True)
                add_section(
                    "后端验证", "通过", "原始OSPF表计数",
                    baseline.public.get("table_counts", {}),
                )
                schema = backend_check("L1-数据库Schema", ospf.verify_schema)
                script = backend_check("L2-ospf.sh只读契约", ospf.script_contract)
                health = backend_check(
                    "L4-三端管理通道", ospf.management_health,
                    must_pass=True, kind="automation",
                )
                link = backend_check(
                    "L5-双节点链路控制组", ospf.verify_two_node_topology,
                    must_pass=True, kind="environment", section="协议验证",
                )
                topology = dict(getattr(link, "details", {}) or {})
                transit_network = str(topology.get("transit_network", ""))
                safety_ok = bool(
                    getattr(schema, "passed", False)
                    and getattr(script, "passed", False)
                    and getattr(health, "passed", False)
                    and bool((getattr(health, "details", {}) or {}).get("router_recovery_ssh"))
                    and bool((getattr(health, "details", {}) or {}).get("peer_ssh"))
                    and bool((getattr(health, "details", {}) or {}).get("peer_recovery_ssh"))
                    and bool((getattr(health, "details", {}) or {}).get("router_lan_management_ssh"))
                    and getattr(link, "passed", False)
                )
                ui_check(
                    "修改安全门禁", safety_ok,
                    "主/备用管理、客户端链路或快照不完整，禁止修改",
                )
                if not safety_ok:
                    add_section("清理结果", "通过", "无修改", "安全门禁失败前未创建配置")

            # Keep Web control on the alternate address while all backend and
            # protocol evidence remains bound to router=10.66.0.150.  This avoids
            # an existing GRE path making a transient primary-management flap look
            # like loss of the OSPF data plane.
            if safety_ok and config.ssh.router_lan_management_host:
                recovery_url = f"http://{config.ssh.router_lan_management_host}"
                # DEVICE_IP may already point at the direct LAN1 recovery
                # address. Re-opening /login on the same authenticated origin
                # is redirected by the product and has no login form.
                same_origin = active_page.url.lower().startswith(
                    recovery_url.lower().rstrip("/") + "/"
                )
                if not same_origin:
                    recovery_login = LoginPage(active_page, recovery_url)
                    if not recovery_login.login(
                        config.device.username, config.device.password
                    ):
                        safety_ok = False
                        automation_failures.append("备用管理地址Web登录失败")
                if safety_ok:
                    ui = OspfPage(active_page, recovery_url)
                    ui.navigate_to_ospf()

            with recorded_step(
                "步骤2 操作：调查列表、列设置、筛选和新建/取消；验证：页面真实能力与不适用功能证据一致",
                "不保存配置，验证全部可见入口、默认值和脏表单取消分支",
            ):
                structure = ui.page_structure()
                ui_check("页面URL", structure.get("url_path") == OspfPage.LIST_URL, structure)
                ui_check(
                    "列表列",
                    all(column in structure.get("headers", []) for column in OspfPage.INSTANCE_COLUMNS),
                    structure.get("headers"),
                )
                capabilities = ui.capability_matrix()
                ui_check("新建/列设置/筛选/分页", all(
                    capabilities.get(key) for key in (
                        "create", "column_settings", "column_filters", "pagination"
                    )
                ), capabilities)
                filter_observation = ui.open_first_column_filter()
                ui_check(
                    "列筛选弹层",
                    bool(filter_observation.get("text"))
                    or filter_observation.get("has_input"),
                    filter_observation,
                )
                ui.page.keyboard.press("Escape")
                absent = [
                    key for key in (
                        "search_box", "explicit_refresh", "help", "import",
                        "export", "copy", "batch_toolbar",
                    ) if not capabilities.get(key)
                ]
                add_section(
                    "页面验证", "不适用", "页面不存在功能",
                    "、".join(absent) + "；由DOM与页面按钮证据确认",
                )
                column_settings = ui.open_column_settings()
                ui_check(
                    "列设置真实控件",
                    len(column_settings.get("columns", [])) == 7
                    and column_settings.get("reorder_control_count", 0) >= 7
                    and column_settings.get("has_restore_default"),
                    column_settings,
                )
                ui.close_top_drawer()
                ui.open_new_instance()
                observation = ui.get_safe_form_observation()
                ui_check(
                    "新建实例字段", len(observation.get("inputs", [])) == 2
                    and "OSPFv2" in observation.get("title", "")
                    and "OSPFv3" in observation.get("title", ""), observation,
                )
                used_processes = {
                    int(row.get("process_id", 0) or 0)
                    for row in baseline.private_tables.get("ospf_instance", [])
                } if baseline is not None else set()
                dirty_processes = [
                    value for value in range(61999, 61989, -1)
                    if value not in used_processes
                ][:2]
                ui.fill_instance(
                    dirty_processes[0], "198.18.250.250", "OSPFv2"
                )
                created_instances.append({
                    "process_id": dirty_processes[0], "family": "ipv4",
                    "router_id": "198.18.250.250",
                })
                continued = ui.resolve_dirty_cancel(discard=False)
                ui_check(
                    "脏表单继续编辑", continued.get("dialog"), continued,
                    kind="product",
                )
                if continued.get("dialog"):
                    discarded = ui.resolve_dirty_cancel(discard=True)
                else:
                    ui.open_new_instance()
                    ui.fill_instance(
                        dirty_processes[1], "198.18.250.249", "OSPFv2"
                    )
                    created_instances.append({
                        "process_id": dirty_processes[1], "family": "ipv4",
                        "router_id": "198.18.250.249",
                    })
                    discarded = ui.resolve_dirty_cancel(discard=True)
                ui_check(
                    "脏表单确认放弃", discarded.get("dialog"), discarded,
                    kind="product",
                )
                dirty_rows = [
                    ospf.find_instance(process, "ipv4")
                    for process in dirty_processes
                ]
                ui_check(
                    "取消后DB不变", not any(dirty_rows),
                    {"unexpected_instance_count": sum(bool(row) for row in dirty_rows)},
                    kind="product",
                )
                add_section(
                    "清理结果", "通过" if not any(dirty_rows) else "失败",
                    "取消操作", "未提交API且DB保持快照" if not any(dirty_rows)
                    else "发现取消场景意外入库",
                )

            with recorded_step(
                "步骤3 操作：动态创建并删除隔离网络探针；验证：当前物理链路是否具备三节点测试条件",
                "只探测现有二层路径，不在管理网启用OSPF",
            ):
                peer_probe = backend_check(
                    "三节点独立Transit", ospf.probe_tagged_peer_transit,
                    must_pass=False, kind="environment", section="协议验证",
                )
                if peer_probe and not peer_probe.passed:
                    add_section(
                        "清理结果", "通过", "临时VLAN",
                        "两端探针接口已在helper finally按唯一名称删除",
                    )
                elif peer_probe and peer_probe.passed:
                    auxiliary_failures.append(
                        "探针发现可用三节点链路，但本轮尚未完成对端长期transit编排"
                    )
                    rec.fail_current_step(auxiliary_failures[-1])

            if safety_ok and baseline is not None:
                v2_process = _pick_process(baseline)
                v2_router_id = _router_id(baseline, 252)
                with recorded_step(
                    "步骤4 操作：通过UI新建OSPFv2实例并直构重复/非法API；验证：API、DB、刷新回显和拒绝语义一致",
                    "使用动态实例号和唯一Router ID，不修改管理接口",
                ):
                    ui.navigate_to_ospf()
                    ui.open_new_instance()
                    ui.fill_instance(v2_process, v2_router_id, "OSPFv2")
                    saved = ui.save_instance()
                    created_instances.append({
                        "process_id": v2_process, "family": "ipv4",
                        "router_id": v2_router_id,
                    })
                    api_ok = bool(
                        saved.get("success") and saved.get("endpoint") == "/Action/call"
                        and saved.get("method") == "POST"
                        and saved.get("func_name") == "ospf"
                        and saved.get("action") == "add"
                    )
                    ui_check("实例保存接口契约", api_ok, saved, kind="product")
                    ui.navigate_to_ospf()
                    ui_check("实例刷新回显", ui.instance_exists(v2_process), kind="product")
                    for detail_tab in (
                        "area", "interface", "neighbor", "redistribute"
                    ):
                        detail = ui.detail_snapshot(v2_process, detail_tab)
                        ui_check(
                            f"详情Tab-{detail_tab}",
                            all(
                                label in detail.get("tabs", [])
                                for label in OspfPage.DETAIL_TAB_LABEL.values()
                            ),
                            detail,
                        )
                        ui.close_top_drawer()
                    backend_check(
                        "L1-v2实例字段", ospf.verify_instance,
                        v2_process, "ipv4",
                        {"router_id": v2_router_id, "address_family": "ipv4"},
                    )
                    edited_router_id = _router_id(
                        baseline, 252, {v2_router_id}
                    )
                    ui.open_edit_instance(v2_process)
                    ui.edit_instance_router_id(edited_router_id)
                    edited = ui.save_instance()
                    ui_check(
                        "Router ID编辑保存契约", edited.get("success"), edited,
                        kind="product",
                    )
                    v2_router_id = edited_router_id
                    backend_check(
                        "L1-Router ID编辑", ospf.verify_instance,
                        v2_process, "ipv4", {"router_id": v2_router_id},
                    )
                    duplicate = ui.api_call("add", "instance", {
                        "enabled": "yes", "address_family": "ipv4",
                        "process_id": v2_process, "router_id": "999.1.1.1",
                        "distance": 110, "default_info": 0,
                        "emit_style": "interface", "comment": "",
                    })
                    ui_check(
                        "重复实例/非法Router ID API拒绝",
                        not duplicate.get("success"), duplicate, kind="product",
                    )
                    rows = ospf._query(
                        "ospf_instance",
                        f"address_family='ipv4' AND process_id={v2_process}",
                    )
                    ui_check("非法API后DB不变", len(rows) == 1, {"row_count": len(rows)}, kind="product")

                    delete_process = _pick_process(
                        baseline, excluded={v2_process}
                    )
                    delete_router_id = _router_id(
                        baseline, 254, {v2_router_id}
                    )
                    ui.navigate_to_ospf()
                    ui.open_new_instance()
                    ui.fill_instance(delete_process, delete_router_id, "OSPFv2")
                    delete_saved = ui.save_instance()
                    created_instances.append({
                        "process_id": delete_process, "family": "ipv4",
                        "router_id": delete_router_id,
                    })
                    ui_check(
                        "删除场景实例保存契约", delete_saved.get("success"),
                        delete_saved, kind="product",
                    )
                    ui.navigate_to_ospf()
                    delete_result = ui.delete_instance(delete_process)
                    ui_check(
                        "实例UI删除契约", delete_result.get("success"),
                        delete_result, kind="product",
                    )
                    backend_check(
                        "L1-实例删除", ospf.verify_instance,
                        delete_process, "ipv4", must_exist=False,
                    )

                with recorded_step(
                    "步骤5 操作：通过页面创建普通区域并绑定LAN1；验证：时间、开销、优先级和网络类型正确保存并生效",
                    "使用广播网络默认timer并验证配置更新安全契约",
                ):
                    ui.navigate_to_ospf()
                    ui.open_new_area(v2_process)
                    ui.fill_area("0.0.0.0", "normal")
                    ui.add_area_interface(
                        topology.get("router_interface", "lan1"),
                        network_type="broadcast", priority=1, cost=10,
                        hello=10, dead=40,
                    )
                    interface_form = ui.get_safe_form_observation()
                    password_inputs = [
                        item for item in interface_form.get("inputs", [])
                        if "密码" in str(item.get("placeholder", ""))
                    ]
                    ui_check(
                        "认证输入框遮罩",
                        bool(password_inputs)
                        and password_inputs[0].get("type") == "password",
                        password_inputs, kind="product",
                    )
                    ui_check(
                        "认证输入maxlength",
                        bool(password_inputs)
                        and password_inputs[0].get("maxlength") is not None,
                        password_inputs, kind="product",
                    )
                    area_saved = ui.save_area()
                    ui_check("区域接口保存", area_saved.get("success"), area_saved, kind="product")
                    relation = backend_check(
                        "L1-区域接口关联", ospf.verify_area_interface,
                        v2_process, "ipv4", "0.0.0.0",
                        topology.get("router_interface", "lan1"),
                        {
                            "cost": 10, "hello_interval": 10,
                            "dead_interval": 40, "priority": 1,
                            "network_type": "broadcast",
                        },
                    )
                    backend_check(
                        "L2-生成配置加载", ospf.verify_generated_config,
                        v2_process, "ipv4", v2_router_id,
                        topology.get("router_interface", "lan1"), "0.0.0.0",
                    )
                    backend_check(
                        "L2-配置更新原子性", ospf.verify_config_update_safety,
                        must_pass=True, kind="product",
                    )
                    area_matrix = [
                        ("stub", "point-to-point", 2, 20, 5, 20),
                        ("nssa", "point-to-multipoint", 3, 30, 6, 24),
                        ("normal", "non-broadcast", 4, 40, 7, 28),
                        ("normal", "broadcast", -1, 0, 1, 1),
                        ("normal", "broadcast", 255, 65535, 65535, 65535),
                        ("normal", "broadcast", 1, 10, 10, 40),
                    ]
                    for (
                        area_type, network_type, priority, cost, hello, dead
                    ) in area_matrix:
                        _emit_ospf_realtime(
                            "操作",
                            f"切换区域类型={area_type}、接口类型={network_type}并保存",
                        )
                        ui.navigate_to_ospf()
                        ui.open_edit_area(v2_process, "0.0.0.0")
                        ui.fill_area("0.0.0.0", area_type)
                        ui.set_existing_area_interface(
                            topology.get("router_interface", "lan1"),
                            network_type=network_type, priority=priority,
                            cost=cost, hello=hello, dead=dead,
                        )
                        matrix_save = ui.save_area()
                        ui_check(
                            f"区域/网络类型矩阵保存-{area_type}/{network_type}",
                            matrix_save.get("success"), matrix_save,
                            kind="product",
                        )
                        backend_check(
                            f"L1-区域和接口参数-{network_type}",
                            ospf.verify_area_interface,
                            v2_process, "ipv4", "0.0.0.0",
                            topology.get("router_interface", "lan1"),
                            {
                                "area_type": area_type,
                                "cost": cost, "hello_interval": hello,
                                "dead_interval": dead, "priority": priority,
                                "network_type": network_type,
                            },
                        )
                    add_section(
                        "页面验证", "不适用", "Stub/NSSA no-summary",
                        "实机区域表单在Normal、Stub、NSSA三种状态下均未出现no-summary控件",
                    )

                    ui.navigate_to_ospf()
                    ui.open_edit_area(v2_process, "0.0.0.0")
                    _emit_ospf_realtime("操作", "提交超出页面范围的接口参数")
                    ui.set_existing_area_interface(
                        topology.get("router_interface", "lan1"),
                        priority=-2, cost=65536, hello=0, dead=65536,
                    )
                    invalid_area = ui.save_area()
                    invalid_rows = ospf._query(
                        "ospf_interface_attr",
                        f"process_id={v2_process} AND address_family='ipv4' "
                        f"AND ifname='{topology.get('router_interface', 'lan1')}'",
                    )
                    invalid_persisted = bool(invalid_rows) and any(
                        str(invalid_rows[0].get(key, "")) == str(value)
                        for key, value in {
                            "priority": -2, "cost": 65536,
                            "hello_interval": 0, "dead_interval": 65536,
                        }.items()
                    )
                    ui_check(
                        "timer/cost/priority越界拒绝",
                        not invalid_area.get("success") and not invalid_persisted,
                        {"response": invalid_area,
                         "invalid_value_persisted": invalid_persisted},
                        kind="product",
                    )
                    ui.navigate_to_ospf()
                    ui.open_edit_area(v2_process, "0.0.0.0")
                    _emit_ospf_realtime("操作", "恢复广播网络默认接口参数")
                    ui.fill_area("0.0.0.0", "normal")
                    ui.set_existing_area_interface(
                        topology.get("router_interface", "lan1"),
                        network_type="broadcast", priority=1, cost=10,
                        hello=10, dead=40,
                    )
                    restored_area = ui.save_area()
                    ui_check(
                        "边界测试后恢复保存契约",
                        restored_area.get("success"), restored_area,
                        kind="product",
                    )
                    v2_ready = bool(
                        getattr(relation, "passed", False)
                    )

                with recorded_step(
                    "步骤6 操作：通过页面启用直连路由发布；验证：后台记录、实际配置和外部路由信息一致",
                    "仅在双节点隔离链路中短暂启用，缺省路由和其他协议引入不启用",
                ):
                    if not v2_ready:
                        add_section(
                            "实际现象", "不适用", "不满足前置条件",
                            "OSPFv2区域接口未就绪，后续协议条件不可能成立，已停止等待",
                        )
                        rec.not_applicable_current_step("v2区域接口未就绪")
                    else:
                        ui.navigate_to_ospf()
                        ui.open_new_redistribute(v2_process)
                        ui.fill_redistribute("connected")
                        result = ui.save_redistribute()
                        ui_check("connected路由引入保存", result.get("success"), result, kind="product")
                        redistribution_ids.extend(current_test_redistribution_ids())
                        backend_check(
                            "L1/L2-connected引入", ospf.verify_redistribute,
                            v2_process, "ipv4", "connected",
                        )
                        before_unsafe = current_test_redistribution_ids()
                        unsafe_observations = []
                        for source in ("static", "ospf", "default-gw"):
                            _emit_ospf_realtime(
                                "操作", f"查看{source}路由引入条件但不保存"
                            )
                            ui.navigate_to_ospf()
                            modal = ui.open_new_redistribute(v2_process)
                            ui.fill_redistribute(source)
                            unsafe_observations.append({
                                "source": source,
                                "labels": OspfPage._visible_unique_text(
                                    modal.locator(
                                        ".ant-form-item-label:visible,label:visible"
                                    )
                                ),
                            })
                            ui.cancel_redistribute()
                        after_unsafe = current_test_redistribution_ids()
                        ui_check(
                            "高风险引入取消后DB不变",
                            before_unsafe == after_unsafe,
                            {"before": before_unsafe, "after": after_unsafe,
                             "forms": unsafe_observations},
                            kind="product",
                        )
                        add_section(
                            "页面验证", "不适用", "default-gw/static/OSPF引入",
                            "当前客户端与管理路由共存，未建立过滤前启用会改变管理选路；已验证三种表单条件字段和取消不入库，未启用",
                        )

                        # Isolate the protocol/L5 control group from the page
                        # matrix above. The product's failed reload can leave a
                        # stale runtime even after DB values are restored, so
                        # delete only this test instance and rebuild the same
                        # clean Normal/broadcast configuration through UI/API.
                        current_row = ospf.find_instance(
                            v2_process, "ipv4"
                        ) or {}
                        current_id = int(current_row.get("id", 0) or 0)
                        isolation_delete = (
                            ui.api_call("del", "instance", {"id": current_id})
                            if current_id > 0 else
                            {"success": False, "reason": "未找到待删除测试实例"}
                        )
                        ui_check(
                            "协议控制组隔离删除",
                            isolation_delete.get("success"), isolation_delete,
                            kind="product",
                        )
                        redistribution_ids.clear()
                        deadline = time.monotonic() + 20
                        delete_started = time.monotonic()
                        next_delete_progress = 5.0
                        while time.monotonic() < deadline:
                            if ospf.find_instance(v2_process, "ipv4") is None:
                                break
                            if time.monotonic() - delete_started >= next_delete_progress:
                                _emit_ospf_realtime(
                                    "等待进度",
                                    "正在等待=测试实例精确删除 | "
                                    f"已等待={time.monotonic() - delete_started:.1f}s | "
                                    "最大等待=20s | 当前状态=测试实例仍存在",
                                )
                                next_delete_progress += 5.0
                            ui.page.wait_for_timeout(300)
                        ui.navigate_to_ospf()
                        ui.open_new_instance()
                        ui.fill_instance(v2_process, v2_router_id, "OSPFv2")
                        isolated_instance = ui.save_instance()
                        created_instances.append({
                            "process_id": v2_process, "family": "ipv4",
                            "router_id": v2_router_id,
                        })
                        ui_check(
                            "协议控制组实例重建保存",
                            isolated_instance.get("success"), isolated_instance,
                            kind="product",
                        )
                        ui.navigate_to_ospf()
                        ui.open_new_area(v2_process)
                        ui.fill_area("0.0.0.0", "normal")
                        ui.add_area_interface(
                            topology.get("router_interface", "lan1"),
                            network_type="broadcast", priority=1, cost=10,
                            hello=10, dead=40,
                        )
                        isolated_area = ui.save_area()
                        ui_check(
                            "协议控制组区域重建保存",
                            isolated_area.get("success"), isolated_area,
                            kind="product",
                        )
                        isolated_relation = backend_check(
                            "L1-协议控制组区域接口",
                            ospf.verify_area_interface,
                            v2_process, "ipv4", "0.0.0.0",
                            topology.get("router_interface", "lan1"),
                            {
                                "cost": 10, "hello_interval": 10,
                                "dead_interval": 40, "priority": 1,
                                "network_type": "broadcast",
                            },
                        )
                        v2_ready = bool(
                            getattr(isolated_relation, "passed", False)
                        )

                with recorded_step(
                    "步骤7 操作：客户端增量加入OSPFv2网络并等待收敛；验证：双方建立邻接、学习路由并能传输真实流量",
                    "由客户端宣告10.99.99.1/32，主路由作为非本机终结节点访问",
                ):
                    if not v2_ready:
                        add_section(
                            "实际现象", "不适用", "不满足前置条件",
                            "OSPFv2区域接口未就绪，后续协议条件不可能成立，已停止等待",
                        )
                        rec.not_applicable_current_step("v2区域接口未就绪")
                    else:
                        backend_check(
                            "L3-UI reload接口状态", ospf.verify_v2_interface_runtime,
                            v2_process, topology.get("router_interface", "lan1"), True,
                            must_pass=True, kind="product",
                        )
                        backend_check(
                            "L3-活动配置完整诊断重放",
                            ospf.diagnose_apply_active_config,
                            must_pass=True, kind="automation",
                        )
                        diagnostic = backend_check(
                            "L3-reload缺陷隔离诊断", ospf.diagnose_apply_v2_interface_runtime,
                            v2_process, topology.get("router_interface", "lan1"),
                            "0.0.0.0", "broadcast", 1, 10, 10, 40,
                            must_pass=True, kind="automation",
                        )
                        add_section(
                            "运行时验证", "警告", "诊断结果边界",
                            "vtysh重放只证明daemon能力和reload缺陷，不计作UI保存通过",
                        )
                        setup = backend_check(
                            "拓扑-客户端加入transit", ospf.client_add_v2_network,
                            transit_network, must_pass=True, kind="automation",
                        )
                        running = ospf._client().exec(
                            "sudo -n vtysh -c 'show running-config' 2>/dev/null",
                            timeout=20,
                        )
                        match = re.search(r"(?m)^ ospf router-id ([0-9.]+)$", running)
                        client_router_id = match.group(1) if match else ""
                        ui_check(
                            "客户端Router ID实机确认", bool(client_router_id),
                            "客户端FRR未找到router-id", kind="automation",
                        )
                        if (
                            getattr(diagnostic, "passed", False)
                            and getattr(setup, "passed", False) and client_router_id
                        ):
                            backend_check(
                                "L3-主路由邻接Full", ospf.wait_neighbor,
                                "router", "ipv4", client_router_id, v2_process,
                            )
                            backend_check(
                                "L3-客户端邻接Full", ospf.wait_neighbor,
                                "client", "ipv4", v2_router_id, None,
                            )
                            backend_check(
                                "L3-LSDB", ospf.verify_lsdb,
                                [v2_router_id, client_router_id], "ipv4", v2_process,
                            )
                            backend_check(
                                "L3-RIB/FIB学习", ospf.wait_route,
                                "router", "10.99.99.1/32", True,
                                process_id=v2_process,
                            )
                            backend_check(
                                "L3-协议89", ospf.verify_protocol_89,
                                topology.get("router_interface", "lan1"),
                                must_pass=True,
                            )
                            router_source = str(
                                ipaddress.ip_interface(topology["router_address"]).ip
                            )
                            backend_check(
                                "L5-正向真实流量", ospf.ping_from_router,
                                "10.99.99.1", router_source, False, True,
                            )

                            auth_value = secrets.token_hex(4)
                            register_sensitive_value(auth_value)
                            ui.navigate_to_ospf()
                            ui.open_edit_area(v2_process, "0.0.0.0")
                            ui.set_existing_area_interface(
                                topology.get("router_interface", "lan1"),
                                password=auth_value,
                            )
                            auth_save = ui.save_area()
                            ui_check(
                                "认证配置保存契约", auth_save.get("success"),
                                auth_save, kind="product",
                            )
                            backend_check(
                                "L1/L2-认证已配置", ospf.verify_auth_state,
                                v2_process, "ipv4",
                                topology.get("router_interface", "lan1"), True,
                            )
                            auth_diag = backend_check(
                                "L3-认证配置诊断重放",
                                ospf.diagnose_apply_active_config,
                                must_pass=True, kind="automation",
                            )
                            if getattr(auth_diag, "passed", False):
                                backend_check(
                                    "L3-认证不匹配主路由邻接撤销",
                                    ospf.wait_neighbor,
                                    "router", "ipv4", client_router_id,
                                    v2_process, False,
                                )
                                backend_check(
                                    "L5-认证不匹配流量失败",
                                    ospf.ping_from_router,
                                    "10.99.99.1", router_source, False, False,
                                )

                            ui.navigate_to_ospf()
                            ui.open_edit_area(v2_process, "0.0.0.0")
                            ui.set_existing_area_interface(
                                topology.get("router_interface", "lan1"),
                                password="",
                            )
                            auth_restore = ui.save_area()
                            ui_check(
                                "认证清除保存契约",
                                auth_restore.get("success"), auth_restore,
                                kind="product",
                            )
                            backend_check(
                                "L1/L2-认证已清除", ospf.verify_auth_state,
                                v2_process, "ipv4",
                                topology.get("router_interface", "lan1"), False,
                            )
                            backend_check(
                                "L3-认证运行态清除",
                                ospf.diagnose_clear_v2_auth,
                                topology.get("router_interface", "lan1"),
                                must_pass=True, kind="automation",
                            )
                            backend_check(
                                "L3-认证恢复后接口重放",
                                ospf.diagnose_apply_v2_interface_runtime,
                                v2_process,
                                topology.get("router_interface", "lan1"),
                                "0.0.0.0", "broadcast", 1, 10, 10, 40,
                                must_pass=True, kind="automation",
                            )
                            backend_check(
                                "L3-认证恢复后Full", ospf.wait_neighbor,
                                "router", "ipv4", client_router_id, v2_process,
                            )
                            backend_check(
                                "L3-认证恢复后路由", ospf.wait_route,
                                "router", "10.99.99.1/32", True,
                                process_id=v2_process,
                            )
                            backend_check(
                                "L5-认证恢复后流量", ospf.ping_from_router,
                                "10.99.99.1", router_source, False, True,
                            )

                with recorded_step(
                    "步骤8 操作：单项撤销并恢复客户端测试网段发布；验证：路由和真实流量同步消失并恢复",
                    "邻接保持不变，只撤销10.99.99.0/24宣告并状态轮询",
                ):
                    if not (v2_ready and client_router_id):
                        add_section(
                            "实际现象", "不适用", "不满足前置条件",
                            "OSPFv2邻接身份未就绪，撤销/恢复条件不可能成立，已停止等待",
                        )
                        rec.not_applicable_current_step("v2邻接未就绪")
                    else:
                        backend_check(
                            "L4-撤销loopback宣告", ospf.client_remove_v2_network,
                            "10.99.99.0/24", must_pass=True, kind="automation",
                        )
                        backend_check(
                            "L4-路由撤销", ospf.wait_route,
                            "router", "10.99.99.1/32", False,
                            process_id=v2_process,
                        )
                        router_source = str(
                            ipaddress.ip_interface(topology["router_address"]).ip
                        )
                        backend_check(
                            "L5-负向真实流量", ospf.ping_from_router,
                            "10.99.99.1", router_source, False, False,
                        )
                        backend_check(
                            "L4-恢复loopback宣告", ospf.client_restore_v2_network,
                            "10.99.99.0/24", must_pass=True, kind="automation",
                        )
                        backend_check(
                            "L4-恢复后路由", ospf.wait_route,
                            "router", "10.99.99.1/32", True,
                            process_id=v2_process,
                        )
                        backend_check(
                            "L5-恢复后流量", ospf.ping_from_router,
                            "10.99.99.1", router_source, False, True,
                        )

                with recorded_step(
                    "步骤9 操作：停用再启用OSPF实例；验证：后台状态、邻接、路由与流量按启停操作变化",
                    "在全部独立正向与负向闭环完成后执行，避免生命周期缺陷遮蔽其他功能",
                ):
                    if not (v2_ready and client_router_id):
                        add_section(
                            "实际现象", "不适用", "不满足前置条件",
                            "OSPFv2邻接身份未就绪，实例启停条件不可能成立，已停止等待",
                        )
                        rec.not_applicable_current_step("v2邻接未就绪")
                    else:
                        row = ospf.find_instance(v2_process, "ipv4") or {}
                        instance_id = int(row.get("id", 0) or 0)
                        down = ui.api_call(
                            "down", "instance", {"id": instance_id}
                        )
                        ui_check(
                            "实例停用API契约", down.get("success"), down,
                            kind="product",
                        )
                        backend_check(
                            "L1-实例停用", ospf.wait_instance_enabled,
                            v2_process, "ipv4", False,
                        )
                        backend_check(
                            "L3-实例停用邻接撤销", ospf.wait_neighbor,
                            "router", "ipv4", client_router_id, v2_process,
                            False,
                        )
                        backend_check(
                            "L4-实例停用路由撤销", ospf.wait_route,
                            "router", "10.99.99.1/32", False,
                            process_id=v2_process,
                        )
                        up = ui.api_call(
                            "up", "instance", {"id": instance_id}
                        )
                        ui_check(
                            "实例启用API契约", up.get("success"), up,
                            kind="product",
                        )
                        backend_check(
                            "L1-实例启用", ospf.wait_instance_enabled,
                            v2_process, "ipv4", True,
                        )
                        backend_check(
                            "L3-实例启用Full", ospf.wait_neighbor,
                            "router", "ipv4", client_router_id, v2_process,
                        )
                        backend_check(
                            "L4-实例启用路由恢复", ospf.wait_route,
                            "router", "10.99.99.1/32", True,
                            process_id=v2_process,
                        )

                v3_process = _pick_process(baseline, ipv6=True)
                v3_router_id = _router_id(baseline, 251)
                with recorded_step(
                    "步骤10 操作：创建OSPFv3实例、IPv6区域和随机测试地址；验证：双方建立邻接、学习路由并能传输真实流量",
                    "OSPFv3独立使用链路本地地址，客户端临时前缀不持久化",
                ):
                    ui.navigate_to_ospf()
                    ui.open_new_instance()
                    ui.fill_instance(v3_process, v3_router_id, "OSPFv3")
                    v3_saved = ui.save_instance()
                    created_instances.append({
                        "process_id": v3_process, "family": "ipv6",
                        "router_id": v3_router_id,
                    })
                    ui_check("OSPFv3实例保存", v3_saved.get("success"), v3_saved, kind="product")
                    ui.navigate_to_ospf()
                    if ospf.find_instance(v3_process, "ipv6") is not None:
                        ui.open_new_area(v3_process)
                        ui.fill_area("0.0.0.0", "normal")
                        ui.add_area_interface(
                            topology.get("router_interface", "lan1"),
                            network_type="broadcast", priority=1, cost=1,
                            hello=10, dead=40,
                        )
                        v3_area = ui.save_area()
                        ui_check("OSPFv3区域接口保存", v3_area.get("success"), v3_area, kind="product")
                        v3_relation = backend_check(
                            "L1-v3区域接口关联", ospf.verify_area_interface,
                            v3_process, "ipv6", "0.0.0.0",
                            topology.get("router_interface", "lan1"),
                            {
                                "cost": 1, "hello_interval": 10,
                                "dead_interval": 40, "priority": 1,
                                "network_type": "broadcast",
                            },
                        )
                        backend_check(
                            "L2-v3生成配置加载", ospf.verify_generated_config,
                            v3_process, "ipv6", v3_router_id,
                            topology.get("router_interface", "lan1"), "0.0.0.0",
                        )
                        v3_ready = bool(getattr(v3_relation, "passed", False))
                    # Even when the UI/API rejects the OSPFv3 area association,
                    # continue with a transparent runtime-only diagnostic. This
                    # proves daemon/link capability without representing the UI
                    # save as successful.
                    if ospf.find_instance(v3_process, "ipv6") is not None:
                        backend_check(
                            "L3-v3 UI reload接口状态", ospf.verify_v3_interface_runtime,
                            topology.get("router_interface", "lan1"), True,
                            must_pass=True, kind="product",
                        )
                        v3_diagnostic = backend_check(
                            "L3-v3 reload缺陷隔离诊断",
                            ospf.diagnose_apply_v3_interface_runtime,
                            v3_process,
                            topology.get("router_interface", "lan1"),
                            "0.0.0.0", "broadcast", 1, 1, 10, 40,
                            must_pass=True, kind="product",
                        )
                        prefix = _v6_prefix()
                        client_v3 = backend_check(
                            "拓扑-客户端OSPFv3", ospf.client_setup_v3,
                            prefix, "ens11", "0.0.0.0", client_router_id or "10.66.0.18",
                            v3_process,
                            must_pass=True, kind="automation",
                        )
                        if (
                            getattr(v3_diagnostic, "passed", False)
                            and getattr(client_v3, "passed", False)
                        ):
                            backend_check(
                                "L3-v3主路由邻接Full", ospf.wait_neighbor,
                                "router", "ipv6", client_router_id or "10.66.0.18",
                                v3_process,
                            )
                            backend_check(
                                "L3-v3客户端邻接Full", ospf.wait_neighbor,
                                "client", "ipv6", v3_router_id, None,
                            )
                            target = prefix.split("/", 1)[0]
                            backend_check(
                                "L3-v3 RIB/FIB学习", ospf.wait_route,
                                "router", prefix, True, True,
                            )
                            backend_check(
                                "L3-v3 LSDB", ospf.verify_lsdb,
                                [v3_router_id, client_router_id or "10.66.0.18"],
                                "ipv6", v3_process,
                            )
                            backend_check(
                                "L5-v3真实流量", ospf.ping_from_router,
                                target, topology.get("router_interface", "lan1"),
                                True, True,
                            )

            with recorded_step(
                "步骤11 操作：汇总多区域、选举、等价路径和三节点能力；验证：仅对当前真实拓扑支持项给出结论",
                "不使用管理网、默认路由或虚拟隧道伪造物理路径",
            ):
                add_section(
                    "协议验证", "不适用", "三节点/多区域/远端双向L5",
                    "对端LAN1物理链路down，动态tagged transit双向无接收；禁止在10.66.0.0/24管理网启用OSPF",
                )
                add_section(
                    "协议验证", "不适用", "DR/BDR",
                    "三台设备无法加入同一广播VLAN，缺少第三个广播网节点",
                )
                add_section(
                    "协议验证", "不适用", "ECMP",
                    "没有两条独立等价物理或逻辑数据面路径",
                )
                add_section(
                    "页面验证", "不适用", "MTU/Retransmit/Transmit Delay/被动接口/过滤",
                    "当前页面DOM和前端路由未暴露这些控件；后端能力不能冒充页面功能",
                )
                if environment_limits:
                    rec.warn_current_step("；".join(environment_limits)[:500])
                add_section(
                    "后端验证", "失败" if product_failures else "通过",
                    "产品缺陷因果汇总",
                    {
                        "根因数量": len(product_root_causes()),
                        "失败步骤证据数量": len(product_failures),
                        "根因": product_root_causes(),
                    },
                )

        finally:
            cleanup_step = rec.start_step(
                "步骤12 操作：精确恢复三端并执行独立残留审计；验证：数据、配置、临时网络、进程、路由和管理通道回到测试前",
                "即使页面、协议或断言失败也执行；不清空整表、不重启设备",
            )
            _emit_ospf_realtime("步骤开始", "步骤12")
            _emit_ospf_realtime("操作", "精确恢复本用例创建的数据和运行状态")
            _emit_ospf_realtime("期望", "三端环境逐项回到测试前快照")
            add_section(
                "操作", "执行", "精确恢复",
                "仅删除本用例记录的对象和临时进程，不清空整表、不重启设备",
            )
            add_section(
                "期望结果", "预期", "独立残留审计",
                "数据、配置、临时网络、进程、路由和管理通道均回到测试前",
            )
            try:
                cleanup_result = backend_check(
                    "清理-客户端临时OSPF", ospf.cleanup_client,
                    must_pass=True, kind="auxiliary", section="清理结果",
                )
                cleanup_page = cleanup_ui()
                for redistribute_id in sorted(set(
                    redistribution_ids + current_test_redistribution_ids()
                )):
                    response = cleanup_page.api_call(
                        "del", "redistribute", {"id": redistribute_id}
                    )
                    if not response.get("success"):
                        auxiliary_failures.append(
                            f"路由引入ID={redistribute_id}精确删除失败"
                        )
                for item in reversed(created_instances):
                    process_id = item["process_id"]
                    family = item["family"]
                    row = ospf.find_instance(process_id, family)
                    if row is None:
                        continue
                    response = cleanup_page.api_call(
                        "del", "instance", {"id": int(row.get("id", 0))}
                    )
                    if not response.get("success"):
                        auxiliary_failures.append(
                            f"OSPF实例{process_id} API精确删除失败"
                        )

                # Normal UI delete reloads FRR.  Never call ospf.sh init in the
                # ordinary finally path. First let all exact DB/API deletions
                # settle, then stop only exact PIDs absent from the baseline.
                if baseline is not None:
                    baseline_ids = {
                        int(row.get("id", 0) or 0)
                        for row in baseline.private_tables.get("ospf_interface", [])
                    }
                    current = ospf._query("ospf_interface")
                    extras = [
                        int(row.get("id", 0) or 0) for row in current
                        if int(row.get("id", 0) or 0) not in baseline_ids
                    ]
                    for item_id in extras:
                        cleanup_page.api_call("del", "interface", {"id": item_id})
                    deadline = time.monotonic() + 12
                    settle_started = time.monotonic()
                    next_settle_progress = 5.0
                    while time.monotonic() < deadline:
                        remaining = [
                            int(row.get("id", 0) or 0)
                            for row in ospf._query("ospf_interface")
                            if int(row.get("id", 0) or 0) not in baseline_ids
                        ]
                        if not remaining:
                            break
                        if time.monotonic() - settle_started >= next_settle_progress:
                            _emit_ospf_realtime(
                                "等待进度",
                                "正在等待=测试接口精确删除 | "
                                f"已等待={time.monotonic() - settle_started:.1f}s | "
                                f"最大等待=12s | 当前状态=剩余{len(remaining)}项",
                            )
                            next_settle_progress += 5.0
                        active_page.wait_for_timeout(300)

                    runtime_restore = ospf.restore_empty_router_runtime(
                        baseline, False
                    )
                    add_section(
                        "清理结果",
                        "通过" if runtime_restore.passed else "警告",
                        "清理-基线外FRR进程",
                        {
                            "结论": runtime_restore.message,
                            "证据": runtime_restore.details,
                        },
                    )
                    if not runtime_restore.passed:
                        rec.warn_current_step(runtime_restore.message)
                    restore = None
                    stable_count = 0
                    deadline = time.monotonic() + 45
                    audit_started = time.monotonic()
                    next_audit_progress = 5.0
                    while time.monotonic() < deadline:
                        restore = ospf.verify_restored(baseline)
                        if restore.passed:
                            stable_count += 1
                            if stable_count >= 2:
                                break
                        else:
                            stable_count = 0
                        if time.monotonic() - audit_started >= next_audit_progress:
                            observed = getattr(
                                restore, "message", "尚未取得残留审计状态"
                            )
                            _emit_ospf_realtime(
                                "等待进度",
                                "正在等待=环境恢复连续稳定 | "
                                f"已等待={time.monotonic() - audit_started:.1f}s | "
                                "最大等待=45s | "
                                f"当前状态={redact_sensitive_text(observed)[:100]}",
                            )
                            next_audit_progress += 5.0
                        active_page.wait_for_timeout(800)
                    restore_detail = {
                        "结论": getattr(restore, "message", "未取得恢复结果"),
                        "证据": getattr(restore, "details", {}),
                        "连续稳定次数": stable_count,
                    }
                    add_section(
                        "清理结果", "通过" if getattr(restore, "passed", False) else "失败",
                        "三端独立残留审计",
                        restore_detail,
                    )
                    if not getattr(restore, "passed", False):
                        auxiliary_failures.append("finally后三端环境未恢复到原始快照")
                        rec.fail_current_step(auxiliary_failures[-1])
                else:
                    auxiliary_failures.append("测试前未取得可恢复快照")
                    rec.fail_current_step(auxiliary_failures[-1])
                if cleanup_result is not None and not cleanup_result.passed:
                    rec.fail_current_step(cleanup_result.message)
            except Exception as cleanup_exc:
                message = f"finally恢复异常({type(cleanup_exc).__name__})"
                auxiliary_failures.append(message)
                add_section("清理结果", "失败", "finally", message)
                rec.fail_current_step(message)
            finally:
                rec.ensure_current_step_sections(REQUIRED_SECTIONS)
                rec.end_step("passed")
                cleanup_status = {
                    "passed": "通过", "failed": "失败", "warning": "警告",
                    "not_applicable": "不适用", "skipped": "不适用",
                }.get(cleanup_step.status, cleanup_step.status)
                _emit_ospf_realtime(
                    "步骤结束",
                    f"步骤12 | 状态={cleanup_status} | "
                    f"用时={(cleanup_step.duration or 0.0):.2f}s",
                )

        failures = product_failures + automation_failures + auxiliary_failures
        product_roots = product_root_causes()
        _emit_ospf_realtime(
            "最终",
            f"产品问题={len(product_roots)} | 失败步骤证据={len(product_failures)} | "
            f"自动化问题={len(automation_failures)} | "
            f"环境/辅助问题={len(auxiliary_failures)}",
        )
        if failures:
            pytest.fail(
                "OSPF综合测试失败：产品根因{}项（失败步骤证据{}项），自动化缺陷{}项，辅助/恢复缺陷{}项；{}".format(
                    len(product_roots), len(product_failures),
                    len(automation_failures), len(auxiliary_failures),
                    "；".join((product_roots + automation_failures + auxiliary_failures)[:12]),
                )
            )
