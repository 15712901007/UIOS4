"""虚拟专网 -> IPsec VPN（ipsec2）单节点综合实机测试。"""
from __future__ import annotations

import base64
import json
import traceback
from contextlib import contextmanager
from dataclasses import replace
from typing import Any, Dict, List

import pytest

from pages.network.ipsec_vpn_page import IpsecVpnPage
from utils.replay_commands import build_verification_commands
from utils.step_recorder import StepRecorder, redact_sensitive_text


pytestmark = [pytest.mark.network, pytest.mark.ipsec_vpn]

REQUIRED_SECTIONS = (
    "测试操作", "页面验证", "后端验证",
    "运行时验证", "协议验证", "清理结果",
)

PROPOSAL_FIELD_LABELS = {
    "tagname": "名称",
    "auth_alg": "认证算法",
    "enc_alg": "加密算法",
    "dh_group": "DH",
    "sa_lifetime": "IKE SA生存周期",
}

POLICY_BASIC_FIELD_LABELS = {
    "tagname": "策略名称",
    "alias": "别名",
    "interface": "应用策略接口",
    "local_ip": "本端IP地址",
    "remote_addr": "对端IP地址或主机名",
    "comment": "备注",
}

POLICY_ADVANCED_FIELD_LABELS = {
    "esp_auth": "ESP认证算法",
    "esp_enc": "ESP加密算法",
    "pfs_group": "PFS密钥组",
    "ipsec_sa_time": "IPsec连接生存时间",
    "ipsec_sa_bytes": "IPsec连接流量上限",
    "ipsec_sa_idle": "IPsec连接空闲时间",
}


def _emit_ipsec_realtime(event: str, message: Any) -> None:
    """Emit one credential-safe progress line for source and frozen GUIs."""
    safe_message = redact_sensitive_text(message)
    safe_message = " ".join(str(safe_message).replace("\r", " ").splitlines())
    print(f"[IPsec][{event}] {safe_message}", flush=True)


class TestIpsecVpnComprehensive:
    def test_ipsec_vpn_comprehensive(
        self,
        ipsec_vpn_page_logged_in: IpsecVpnPage,
        ipsec_verifier,
        backend_verifier,
        step_recorder: StepRecorder,
    ):
        ui = ipsec_vpn_page_logged_in
        ipsec = ipsec_verifier
        backend = backend_verifier
        rec = step_recorder
        rec.required_sections = REQUIRED_SECTIONS
        _emit_ipsec_realtime("开始", "虚拟专网-IPsec VPN 综合测试")

        product_failures: List[str] = []
        automation_failures: List[str] = []
        environment_failures: List[str] = []
        current_step_failures: List[str] = []
        snapshot = None
        topology = None
        secret = ""
        router_policy_id = 0
        peer_policy_id = 0
        router_proposal_id = 0
        peer_proposal_id = 0
        extended_topologies: List[Any] = []
        extended_policy_ids: List[tuple[str, int, str, int]] = []

        def safe(value: Any) -> Any:
            return ipsec.sanitize_value(value)

        def add_section(section: str, status: str, label: str, detail: Any):
            if isinstance(detail, (dict, list, tuple)):
                detail = json.dumps(
                    safe(detail), ensure_ascii=False, sort_keys=True
                )
            rec.add_detail(f"【{section}】\n{status} {label}：{detail}")
            _emit_ipsec_realtime(status, f"{section} | {label}")

        def add_public_command(
            target: str, purpose: str, command: str, expected: str, *,
            actual: str = "", effect: str = "只读",
            valid_when: str = "对应步骤完成后、测试环境清理前",
        ):
            host_config = (
                backend._ssh_config.router
                if target == "router" else backend._ssh_config.client
            )
            rec.add_verification_command({
                "target": target,
                "target_label": "主路由器" if target == "router" else "测试客户端",
                "host": str(host_config.host),
                "shell": "sh",
                "purpose": purpose,
                "command": command,
                "expected": expected,
                "actual": actual,
                "effect": effect,
                "copy_ready": True,
                "contains_secret": False,
                "interactive": False,
                "valid_when": valid_when,
            })

        @contextmanager
        def recorded_step(title: str, description: str):
            nonlocal current_step_failures
            current_step_failures = []
            display_title = title
            if "操作：" in description and "验证：" in description:
                action, verification = description.split("验证：", 1)
                action = action.split("操作：", 1)[1].rstrip("；; ")
                display_title = (
                    f"{title} 操作：{action}；验证：{verification.rstrip('。 ')}"
                )
            step = rec.start_step(display_title, description)
            _emit_ipsec_realtime("步骤开始", title)
            _emit_ipsec_realtime("步骤说明", description)
            try:
                yield
            except Exception as exc:
                frames = traceback.extract_tb(exc.__traceback__)
                frame = (frames or [None])[-1]
                location = (
                    f"@{frame.name}:{frame.lineno}" if frame is not None else ""
                )
                message = (
                    f"{title}自动化异常({type(exc).__name__}{location})"
                )
                automation_failures.append(message)
                add_section("页面验证", "失败", "自动化执行", message)
                current_step_failures.append(message)
                try:
                    ui._dismiss_overlays()
                    ui.navigate_to_ipsec()
                    add_section(
                        "清理结果", "通过", "异常后页面状态恢复",
                        "已重新进入IPsec隧道策略列表",
                    )
                except Exception as recovery_exc:
                    recovery_message = (
                        f"{title}异常后页面恢复失败"
                        f"({type(recovery_exc).__name__})"
                    )
                    automation_failures.append(recovery_message)
                    current_step_failures.append(recovery_message)
                    add_section(
                        "清理结果", "失败", "异常后页面状态恢复",
                        recovery_message,
                    )
            finally:
                rec.ensure_current_step_sections(REQUIRED_SECTIONS)
                if current_step_failures:
                    rec.fail_current_step(
                        "；".join(dict.fromkeys(current_step_failures))
                    )
                rec.end_step("passed")
                status_labels = {
                    "passed": "通过",
                    "failed": "失败",
                    "warning": "警告",
                    "not_applicable": "不适用",
                    "skipped": "不适用",
                }
                status = status_labels.get(step.status, step.status)
                duration = step.duration if step.duration is not None else 0.0
                _emit_ipsec_realtime(
                    "步骤结束",
                    f"{title} | 状态={status} | 用时={duration:.2f}s",
                )

        def check(
            label: str, condition: Any, detail: Any = "条件不成立", *,
            kind: str = "product", section: str = "页面验证",
            failure_summary: str = "",
        ) -> bool:
            passed = bool(condition)
            add_section(
                section, "通过" if passed else "失败", label,
                "符合预期" if passed else detail,
            )
            if not passed:
                message = (
                    failure_summary
                    or f"{label}未通过，请展开本步骤查看详细检查证据。"
                )
                target = (
                    product_failures if kind == "product" else
                    environment_failures if kind == "environment" else
                    automation_failures
                )
                target.append(message)
                current_step_failures.append(message)
            return passed

        def verify(
            label: str, func, *args, kind: str = "product",
            section: str = "后端验证", failure_summary: str = "", **kwargs,
        ):
            try:
                result = func(*args, **kwargs)
                passed = bool(getattr(result, "passed", False))
                detail = {
                    "结论": getattr(result, "message", ""),
                    "证据": getattr(result, "details", {}) or {},
                }
                check(
                    label, passed, detail, kind=kind, section=section,
                    failure_summary=failure_summary,
                )
                try:
                    commands = build_verification_commands(
                        backend, func, args=args, kwargs=kwargs, result=result
                    )
                    if commands:
                        rec.add_verification_commands(commands)
                except Exception as command_exc:
                    message = (
                        f"{label}的人工复验命令生成失败"
                        f"（{type(command_exc).__name__}）。"
                    )
                    automation_failures.append(message)
                    current_step_failures.append(message)
                return result
            except Exception as exc:
                check(
                    label, False, f"验证异常({type(exc).__name__})",
                    kind="automation", section=section,
                    failure_summary=(
                        failure_summary
                        or f"{label}执行时发生自动化异常，请检查测试实现。"
                    ),
                )
                return None

        def fill_complete_policy(
            *, dpd_enabled: bool, scenario_topology=None,
            role: str = "spoke", proposal_name: str = "",
            encap_mode: str = "tunnel",
        ):
            selected = scenario_topology or topology
            selected_proposal = proposal_name or selected.router_proposal
            ui.open_new_policy()
            ui.fill_policy_basic(
                tagname=selected.router_policy,
                role=role,
                addr_type=selected.addr_type,
                interface=selected.router_interface,
                local_ip=selected.router_underlay,
                remote_addr=selected.router_remote_endpoint,
                alias=f"ipsec-ui-{selected.token}",
                comment="automation",
            )
            ui.fill_policy_ike(
                ike_version="ikev2",
                proposal=selected_proposal,
                secret=secret,
                local_id=selected.router_underlay,
                remote_id=selected.peer_underlay,
                prf="SHA256",
                local_id_type="IPv6地址" if selected.addr_type == "v6" else "IPv4地址",
                remote_id_type="IPv6地址" if selected.addr_type == "v6" else "IPv4地址",
            )
            if not ui.add_protected_traffic(
                src=selected.router_selector,
                dst=selected.peer_selector,
                protocol=selected.protocol,
            ):
                errors = ui._last_protected_traffic_errors
                suffix = f"：{'；'.join(errors)}" if errors else ""
                raise RuntimeError(f"保护数据流弹窗未正常关闭{suffix}")
            ui.fill_policy_advanced(
                encap_mode=encap_mode,
                pfs_group="MODP 2048（组14）",
                ipsec_sa_time=600,
                dpd_enabled=dpd_enabled,
                dpd_interval=10,
                dpd_timeout=30,
                dpd_action="重启",
            )

        def register_policy_ids(selected, router_id: int, peer_id: int):
            extended_topologies.append(selected)
            extended_policy_ids.append(
                (selected.token, int(router_id), "router", int(peer_id))
            )

        def teardown_scenario(selected, router_id: int, peer_id: int):
            if router_id and peer_id:
                ipsec.terminate_test_sas(router_id, peer_id)
            for target, policy_id in (("router", router_id), ("peer", peer_id)):
                if policy_id:
                    ipsec.policy_action(target, "del", policy_id)

        def create_scenario(
            selected, *, router_overrides=None, peer_overrides=None,
            use_ui_router: bool = True, encap_mode: str = "tunnel",
        ):
            if router_policy_id and peer_policy_id:
                ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
            prepared = ipsec.prepare_data_plane(selected)
            check(
                f"{selected.token}-数据面准备", prepared.passed,
                prepared.details, kind="automation", section="运行时验证",
            )
            if not prepared.passed:
                raise RuntimeError(f"{selected.token}数据面准备失败")
            router_id = 0
            if use_ui_router:
                fill_complete_policy(
                    dpd_enabled=True, scenario_topology=selected,
                    role=selected.router_role,
                    proposal_name=topology.router_proposal,
                    encap_mode=encap_mode,
                )
                saved = ui.save_policy()
                check(
                    f"{selected.token}-页面创建主路由策略",
                    saved.get("success"), saved, kind="product",
                )
                row = ipsec.find_policy(selected.router_policy, "router")
                router_id = int(row["id"]) if row else 0
                if router_id:
                    ipsec.register_created_object(
                        "router", "policy", router_id, selected.router_policy
                    )
            else:
                router_id = ipsec.add_policy(
                    "router", selected, router_proposal_id, secret,
                    router_overrides,
                )
            peer_id = ipsec.add_policy(
                "peer", selected, peer_proposal_id, secret, peer_overrides
            )
            check(
                f"{selected.token}-双端策略已落库",
                bool(router_id and peer_id),
                {"router_id": router_id, "peer_id": peer_id},
                section="后端验证",
            )
            register_policy_ids(selected, router_id, peer_id)
            return router_id, peer_id

        def restore_tunnel(label: str, *, failure_kind: str = "automation") -> bool:
            nonlocal router_policy_id, peer_policy_id
            if not router_policy_id or not peer_policy_id:
                return False
            withdrawn = ipsec.terminate_test_sas(
                router_policy_id, peer_policy_id
            )
            if not withdrawn.passed:
                check(
                    f"{label}-断开已有测试连接",
                    False, withdrawn.details,
                    kind=failure_kind, section="运行时验证",
                )
                return False
            cleared = verify(
                f"{label}-重新加载当前认证配置",
                ipsec.reload_current_credentials,
                kind=failure_kind, section="运行时验证",
            )
            if not cleared or not cleared.passed:
                return False
            initiated = verify(
                f"{label}-从主路由发起连接",
                ipsec.initiate_child_from_router, router_policy_id,
                kind=failure_kind, section="协议验证",
            )
            if not initiated or not initiated.passed:
                return False
            converged = verify(
                f"{label}-两端连接状态恢复",
                ipsec.wait_for_sa,
                topology, router_policy_id, peer_policy_id,
                timeout=25, kind=failure_kind, section="协议验证",
            )
            return bool(converged and converged.passed)

        def mismatch_case(
            label: str, apply_mismatch, restore_mismatch,
            *, verify_blocked_traffic: bool = False,
            allow_ike_without_child: bool = False,
        ):
            terminated = ipsec.terminate_test_sas(
                router_policy_id, peer_policy_id
            )
            check(
                f"{label}-先断开现有测试连接", terminated.passed,
                terminated.details, kind="automation", section="运行时验证",
            )
            changed = apply_mismatch()
            check(
                f"{label}-不一致配置已下发",
                bool(getattr(changed, "passed", False)),
                getattr(changed, "details", {}),
                kind="automation", section="后端验证",
            )
            ipsec.reload_current_credentials()
            rejected = ipsec.initiate_child_from_router(router_policy_id)
            check(
                f"{label}-不一致配置必须阻止连接", not rejected.passed,
                rejected.details, kind="product", section="协议验证",
            )
            absent = (
                ipsec.wait_for_child_absent(
                    router_policy_id, peer_policy_id, timeout=8
                )
                if allow_ike_without_child else
                ipsec.wait_for_sa_absent(
                    router_policy_id, peer_policy_id, timeout=8
                )
            )
            check(
                f"{label}-失败后不得残留连接", absent.passed,
                absent.details, kind="product", section="协议验证",
                failure_summary=(
                    "两端协议版本改成不一致后，连接虽然失败，"
                    "但对端仍残留未清理的连接记录。"
                    if label == "协议版本不一致" else ""
                ),
            )
            if verify_blocked_traffic:
                blocked = ipsec.verify_traffic_blocked(topology)
                check(
                    f"{label}-错误配置下双向数据必须不通", blocked.passed,
                    blocked.details, kind="product", section="协议验证",
                )
            ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
            restored = restore_mismatch()
            check(
                f"{label}-恢复正确配置",
                bool(getattr(restored, "passed", False)),
                getattr(restored, "details", {}),
                kind="automation", section="后端验证",
            )
            restore_tunnel(f"{label}-恢复后")

        try:
            with recorded_step(
                "步骤1: 保存测试前状态并确认测试环境可用",
                "操作：记录主路由和对端设备的配置、地址、路由、连接状态和管理通道；"
                "验证：测试所需的后台数据、处理脚本和备用管理通道均可用。",
            ):
                snapshot = ipsec.snapshot_environment()
                topology = ipsec.choose_topology()
                add_section("测试操作", "通过", "本次动态测试对象", {
                    "router_policy": topology.router_policy,
                    "peer_policy": topology.peer_policy,
                    "router_proposal": topology.router_proposal,
                    "peer_proposal": topology.peer_proposal,
                    "router_selector": topology.router_selector,
                    "peer_selector": topology.peer_selector,
                })
                verify("后台数据表结构", ipsec.verify_schema)
                verify("底层处理脚本", ipsec.verify_script_contract)
                verify("测试设备和备用管理通道", ipsec.management_health,
                       kind="automation", section="运行时验证")
                check(
                    "测试对象名无冲突",
                    ipsec.find_policy(topology.router_policy, "router") is None
                    and ipsec.find_policy(topology.peer_policy, "peer") is None
                    and ipsec.find_proposal(topology.router_proposal, "router") is None
                    and ipsec.find_proposal(topology.peer_proposal, "peer") is None,
                    "动态名称已被占用", kind="environment",
                    section="后端验证",
                )
                check(
                    "动态策略和提议名称符合当前1-15字符规则",
                    all(
                        1 <= len(name) <= 15
                        for name in (
                            topology.router_policy, topology.peer_policy,
                            topology.router_proposal, topology.peer_proposal,
                        )
                    ),
                    {
                        "router_policy_length": len(topology.router_policy),
                        "peer_policy_length": len(topology.peer_policy),
                        "router_proposal_length": len(topology.router_proposal),
                        "peer_proposal_length": len(topology.peer_proposal),
                    },
                    kind="automation", section="后端验证",
                )

            with recorded_step(
                "步骤2: 检查IPsec页面和新建表单是否完整",
                "操作：依次查看三个页面并打开新增提议、新增策略表单；"
                "验证：页面栏目、输入项、可选项和取消操作完整可用。",
            ):
                ui.navigate_to_ipsec()
                for tab, expected in (
                    ("policy", ui.POLICY_COLUMNS),
                    ("proposal", ui.PROPOSAL_COLUMNS),
                    ("tunnel", ui.TUNNEL_COLUMNS),
                ):
                    struct = ui.page_structure(tab)
                    check(f"{struct['tab']}-URL", "/#/vpn/ipsecVpn" in struct["url"], struct)
                    for header in expected:
                        check(
                            f"{struct['tab']}-列-{header}",
                            header in struct["headers"], struct["headers"],
                        )
                matrix = ui.capability_matrix()
                check("策略新建入口", matrix["policy_create"], matrix)
                check("IKE提议新建入口", matrix["proposal_create"], matrix)
                add_section(
                    "页面验证",
                    "通过" if matrix["tunnel_auto_refresh"] else "不适用",
                    "隧道信息自动刷新",
                    "页面提供自动刷新" if matrix["tunnel_auto_refresh"]
                    else "当前页面未暴露自动刷新按钮",
                )
                for unsupported, display_name in (
                    ("import", "导入"), ("export", "导出"),
                ):
                    check(
                        f"页面没有虚构不存在的“{display_name}”功能",
                        not matrix[unsupported],
                        matrix, kind="automation",
                    )
                add_section(
                    "页面验证", "通过", "批量能力",
                    "页面提供批量选择" if matrix["batch"] else "页面未提供批量选择",
                )

                proposal_form = ui.open_new_proposal()
                proposal_obs = ui.safe_form_observation()
                for field, field_label in PROPOSAL_FIELD_LABELS.items():
                    check(
                        f"IKE提议包含“{field_label}”",
                        any(item.get("id") == field for item in proposal_obs["fields"])
                        or any(item.get("id") == field for item in proposal_obs["selects"]),
                        proposal_obs, kind="automation",
                    )
                for field in ("auth_alg", "enc_alg", "dh_group"):
                    options = ui.select_options(proposal_form, field)
                    check(
                        f"IKE提议“{PROPOSAL_FIELD_LABELS[field]}”可选择",
                        len(options) >= 2, options,
                    )
                ui._replace_input(proposal_form.locator("#tagname"), "dirty_probe")
                cancelled = ui.cancel_proposal(discard=True)
                check("IKE提议脏表单取消", cancelled["closed"], cancelled)

                policy_form = ui.open_new_policy()
                ui.open_policy_section("basic")
                basic_obs = ui.safe_form_observation()
                for field, field_label in POLICY_BASIC_FIELD_LABELS.items():
                    check(
                        f"策略基础设置包含“{field_label}”",
                        any(item.get("id") == field for item in basic_obs["fields"])
                        or any(item.get("id") == field for item in basic_obs["selects"]),
                        basic_obs, kind="automation",
                    )
                tagname_input = policy_form.locator("#tagname")
                ui._replace_input(tagname_input, "p" * 16)
                tagname_input.press("Tab")
                ui.page.wait_for_timeout(250)
                tagname_errors = ui.field_errors("tagname")
                check(
                    "策略名称超过15字符时页面给出明确提示",
                    bool(tagname_errors),
                    {
                        "maxlength": tagname_input.get_attribute("maxlength"),
                        "field_errors": tagname_errors,
                        "backend_limit": 15,
                    },
                    kind="product",
                    failure_summary=(
                        "策略名称后端只接受1-15字符，但页面仍允许继续输入且没有字段级提示。"
                    ),
                )
                ui._replace_input(tagname_input, "")

                ui.open_policy_section("traffic")
                trigger_mode = ui.selected_radio_label("trigger_mode")
                check(
                    "保护数据流默认使用自动触发",
                    "自动触发" in trigger_mode or trigger_mode == "auto",
                    {"selected": trigger_mode},
                    kind="product",
                )
                policy_form.get_by_role("button", name="添加", exact=True).click()
                traffic_modal = ui._proposal_modal()
                protocol_options = ui.select_options(traffic_modal, "protocol")
                check(
                    "保护数据流协议使用中文“任意”",
                    "任意" in protocol_options and "any" not in protocol_options,
                    protocol_options,
                    kind="product",
                )
                traffic_modal.get_by_role(
                    "button", name="取消", exact=True
                ).click()
                traffic_modal.wait_for(state="hidden", timeout=5000)

                ui.open_policy_section("advanced")
                advanced_obs = ui.safe_form_observation()
                for field, field_label in POLICY_ADVANCED_FIELD_LABELS.items():
                    check(
                        f"策略高级配置包含“{field_label}”",
                        any(item.get("id") == field for item in advanced_obs["fields"])
                        or any(item.get("id") == field for item in advanced_obs["selects"]),
                        advanced_obs, kind="automation",
                    )
                dpd_action_visible = any(
                    item.get("id") == "dpd_action"
                    for item in advanced_obs["selects"]
                )
                add_section(
                    "页面验证", "通过", "DPD失效处理方式",
                    (
                        "页面允许用户选择失效处理方式"
                        if dpd_action_visible else
                        "当前页面使用后台默认restart；步骤6继续验证默认保存与实际落库值"
                    ),
                )
                ui._replace_input(policy_form.locator("#tagname"), "dirty_probe")
                cancelled = ui.cancel_policy(discard=True)
                check("策略脏表单取消", cancelled["closed"], cancelled)

            with recorded_step(
                "步骤3: 检查页面发出的请求能否被后台正确处理",
                "操作：打开页面并触发列表查询和地址检查；"
                "验证：页面发出的每一种请求，后台都能识别并返回有效结果。",
            ):
                for func_name, display_name, params in (
                    ("ipsec2_policy", "隧道策略列表", {}),
                    ("ipsec2_proposal", "IKE提议列表", {}),
                    ("ipsec2_tunnel", "隧道状态列表", {"TYPE": "list,list_total"}),
                ):
                    response = ui.api_call(func_name, "show", params)
                    check(
                        f"后台正确返回“{display_name}”",
                        response["success"],
                        response, kind="product", section="后端验证",
                    )
                resolve = ui.resolve_remote_address(topology.peer_underlay)
                check(
                    "真实对端地址检查成功",
                    resolve["success"]
                    and str(resolve.get("resolved_status")) in {"1", "true", "True"},
                    resolve, kind="product", section="后端验证",
                    failure_summary=(
                        "页面会自动发出地址检查请求，但后台不认识这个请求，"
                        "说明页面与后台功能没有配套。"
                    ),
                )
                unreachable = ui.resolve_remote_address("192.0.2.254")
                check(
                    "不可达对端地址不得提示检测成功",
                    str(unreachable.get("resolved_status")) not in {
                        "1", "true", "True",
                    },
                    unreachable, kind="product", section="后端验证",
                    failure_summary=(
                        "对端地址检查把明确不可达的测试网地址也判成成功，"
                        "页面的检测结果不能反映真实可达性。"
                    ),
                )
                add_public_command(
                    "router", "查看三个IPsec页面对应的后台接口注册",
                    "grep -nE 'register_module_urls|url=' /usr/ikuai/script/ipsec2_policy.sh /usr/ikuai/script/ipsec2_proposal.sh /usr/ikuai/script/ipsec2_tunnel.sh",
                    "应显示策略、IKE提议和隧道状态接口，以及各接口已经注册的查询动作",
                    actual="自动化已通过页面真实请求记录HTTP状态和后台业务码",
                )
                add_public_command(
                    "router", "确认后台是否实现页面调用的地址检查动作",
                    "grep -nE 'resolve_check|resolve_flush' /usr/ikuai/script/ipsec2_policy.sh",
                    "正常应显示resolve_check处理入口；当前缺陷只显示resolve_flush定时清理入口",
                    actual=(
                        "页面请求TYPE=resolve_check时，后台返回失败或不认识该请求"
                        if not resolve["success"] else
                        "页面地址检查请求已被后台处理；自动化同时核对了真实可达性语义"
                    ),
                )

            with recorded_step(
                "步骤4: 检查空白表单是否会被拦截且不产生无效数据",
                "操作：不填写任何内容，直接提交新增IKE提议；"
                "验证：页面显示中文提示，后台不产生无效记录。",
            ):
                before = len(ipsec.query_proposals("router"))
                form = ui.open_new_proposal()
                form.get_by_role("button", name="确定", exact=True).click()
                ui.page.wait_for_timeout(300)
                errors = ui.form_errors()
                check("页面拦截空白IKE提议", bool(errors), errors)
                check(
                    "空白提交没有产生无效提议",
                    len(ipsec.query_proposals("router")) == before,
                    ipsec.query_proposals("router"),
                    section="后端验证",
                )
                add_public_command(
                    "router", "查看IKE提议总数是否保持不变",
                    "sqlite3 /etc/mnt/ikuai/config.db -line \"SELECT count(*) AS proposal_count FROM ipsec2_proposal;\"",
                    f"proposal_count仍为操作前的{before}",
                )
                ui.cancel_proposal(discard=True)

            with recorded_step(
                "步骤5: 检查能否通过页面创建IKE提议",
                "操作：填写名称、认证算法、加密算法、DH和生存周期后保存；"
                "验证：页面提示成功，后台记录一致，重新查看列表可以找到该提议。",
            ):
                ui.open_new_proposal()
                ui.fill_proposal(tagname=topology.router_proposal)
                result = ui.save_proposal()
                check("页面创建IKE提议", result.get("success"), result)
                row = ipsec.find_proposal(topology.router_proposal, "router")
                router_proposal_id = int(row["id"]) if row else 0
                check("后台已保存IKE提议", router_proposal_id > 0, row, section="后端验证")
                if router_proposal_id:
                    ipsec.register_created_object(
                        "router", "proposal", router_proposal_id,
                        topology.router_proposal,
                    )
                check("重新查看列表可以找到IKE提议", ui.row_exists(topology.router_proposal), topology.router_proposal)
                proposal_count = len(ipsec.query_proposals("router"))
                ui.open_new_proposal()
                ui.fill_proposal(tagname=topology.router_proposal)
                duplicate = ui.save_proposal()
                duplicate_text = " ".join(
                    [str(duplicate.get("message") or "")]
                    + list(duplicate.get("form_errors") or [])
                )
                check(
                    "重复IKE提议名称显示明确原因",
                    not duplicate.get("success")
                    and any(word in duplicate_text for word in ("存在", "重复", "占用")),
                    duplicate,
                    kind="product",
                )
                check(
                    "重复IKE提议没有产生额外记录",
                    len(ipsec.query_proposals("router")) == proposal_count,
                    {"before": proposal_count,
                     "after": len(ipsec.query_proposals("router"))},
                    section="后端验证",
                )
                if ui.page.locator(".ant-modal:visible,.ant-drawer:visible").count():
                    ui.cancel_proposal(discard=True)
                add_public_command(
                    "router", "查看刚创建的IKE提议数据库字段",
                    "sqlite3 /etc/mnt/ikuai/config.db -line \"SELECT id,tagname,auth_alg,enc_alg,dh_group,sa_lifetime FROM ipsec2_proposal WHERE tagname IS '"
                    + topology.router_proposal + "';\"",
                    "记录唯一存在，名称、认证算法、加密算法、DH和生存周期与页面一致",
                )

            with recorded_step(
                "步骤6: 检查按页面默认设置能否成功保存策略",
                "操作：填写页面上所有可见的必填项，保持默认的对端失效检测开启并保存；"
                "验证：页面提示保存成功，重新进入后可以看到该策略。",
            ):
                secret = ipsec.generate_psk()
                fill_complete_policy(dpd_enabled=True)
                result = ui.save_policy()
                check(
                    "按页面默认设置保存策略", result.get("success"),
                    result, kind="product",
                    failure_summary=(
                        "所有可见必填项都已填写，但点击保存仍提示“请求参数不合法”。"
                        "请根据报告中的具体字段和请求参数核对当前前后端规则。"
                    ),
                )
                if result.get("success"):
                    row = ipsec.find_policy(topology.router_policy, "router")
                    router_policy_id = int(row["id"]) if row else 0
                    check(
                        "默认策略已写入后台", router_policy_id > 0,
                        row, section="后端验证",
                    )
                    if router_policy_id:
                        ipsec.register_created_object(
                            "router", "policy", router_policy_id,
                            topology.router_policy,
                        )
                    verify(
                        "默认DPD设置已完整落库",
                        ipsec.verify_database,
                        topology.router_policy,
                        {
                            "dpd_enabled": "yes", "dpd_interval": "10",
                            "dpd_timeout": "30", "dpd_action": "restart",
                        },
                        "router", section="后端验证",
                    )
                else:
                    check(
                        "保存失败后没有残留无效策略",
                        ipsec.find_policy(topology.router_policy, "router") is None,
                        ipsec.find_policy(topology.router_policy, "router"),
                        section="后端验证",
                    )
                    if ui.page.locator(".ant-drawer:visible").count():
                        ui.cancel_policy(discard=True)
                add_public_command(
                    "router", "查看默认设置保存后是否产生策略记录",
                    "sqlite3 /etc/mnt/ikuai/config.db -line \"SELECT id,tagname,enabled,dpd_enabled,dpd_interval,dpd_timeout,dpd_action FROM ipsec2_policy WHERE tagname IS '"
                    + topology.router_policy + "';\"",
                    "正常情况下应存在完整记录，dpd_action应使用页面值或后台明确默认值",
                )

            with recorded_step(
                "步骤7: 检查新增策略后是否立即生效且认证文件是否安全",
                "操作：在两端创建可保存的策略，并检查后台服务、运行状态和认证文件权限；"
                "验证：保存成功后连接服务自动就绪，认证文件只能由管理员读取。",
            ):
                prepared = verify(
                    "测试流量路径已隔离",
                    ipsec.prepare_data_plane, topology,
                    kind="automation", section="运行时验证",
                )
                control = verify(
                    "建立连接前测试目标不可达",
                    ipsec.verify_control_failure, topology,
                    kind="automation", section="协议验证",
                )
                if not prepared or not prepared.passed or not control or not control.passed:
                    raise RuntimeError("IPsec数据面安全前置失败")

                peer_proposal_id = ipsec.add_proposal(
                    "peer", topology.peer_proposal
                )
                peer_policy_id = ipsec.add_policy(
                    "peer", topology, peer_proposal_id, secret
                )
                peer_runtime = verify(
                    "新增对端策略后服务自动生效",
                    ipsec.verify_policy_runtime_loaded,
                    peer_policy_id, "peer",
                    kind="product", section="运行时验证",
                    failure_summary=(
                        "新增对端策略后，后台连接服务没有自动启动。"
                        "虽然配置已经保存，但隧道不能直接使用。"
                    ),
                )
                if not peer_runtime or not peer_runtime.passed:
                    harness = verify(
                        "测试程序启动对端连接服务",
                        ipsec.initialize_runtime, "peer",
                        kind="automation", section="运行时验证",
                    )
                    if not harness or not harness.passed:
                        raise RuntimeError("对端charon夹具初始化失败")

                expected_dpd = "yes"
                if not router_policy_id:
                    fill_complete_policy(dpd_enabled=False)
                    result = ui.save_policy()
                    if not check(
                        "默认保存失败后的关闭DPD兼容建链", result.get("success"),
                        result, kind="automation",
                    ):
                        raise RuntimeError("可用策略UI新增失败")
                    row = ipsec.find_policy(topology.router_policy, "router")
                    router_policy_id = int(row["id"]) if row else 0
                    expected_dpd = "no"
                    if router_policy_id:
                        ipsec.register_created_object(
                            "router", "policy", router_policy_id,
                            topology.router_policy,
                        )
                else:
                    row = ipsec.find_policy(topology.router_policy, "router")
                check("后台已保存主路由策略", router_policy_id > 0, row, section="后端验证")
                verify(
                    "页面设置与后台记录一致",
                    ipsec.verify_database,
                    topology.router_policy,
                    {
                        "role": "spoke", "interface": topology.router_interface,
                        "ike_version": "ikev2", "security_proto": "esp",
                        "pfs_group": "modp2048", "trigger_mode": "auto",
                        "dpd_enabled": expected_dpd,
                    },
                    "router", section="后端验证",
                )
                verify(
                    "新增主路由策略后服务自动生效",
                    ipsec.verify_policy_runtime_loaded,
                    router_policy_id, "router",
                    kind="product", section="运行时验证",
                    failure_summary=(
                        "新增主路由策略后，后台没有自动加载该连接。"
                        "页面显示保存成功，但隧道不能直接使用。"
                    ),
                )
                for target, policy_id, label in (
                    ("router", router_policy_id, "主路由"),
                    ("peer", peer_policy_id, "对端"),
                ):
                    permissions = ipsec.verify_secret_permissions(
                        policy_id, target
                    )
                    add_section(
                        "后端验证",
                        "通过" if permissions.passed else "安全加固提示",
                        f"{label}认证文件权限",
                        permissions.details,
                    )
                if expected_dpd == "yes":
                    router_dpd = ipsec.verify_effective_dpd(
                        router_policy_id, "router"
                    )
                    peer_dpd = ipsec.verify_effective_dpd(
                        peer_policy_id, "peer"
                    )
                    check(
                        "两端DPD保存值与实际下发值一致",
                        router_dpd.passed and peer_dpd.passed,
                        {
                            "router": router_dpd.details,
                            "peer": peer_dpd.details,
                        },
                        kind="product", section="运行时验证",
                        failure_summary=(
                            "两端页面均保存DPD 10/30秒，但strongSwan实际下发为"
                            "10/100秒，保存值被静默改写。"
                        ),
                    )

            with recorded_step(
                "步骤8: 检查两端连接和双向加密数据传输",
                "操作：重新加载当前认证配置并从主路由发起连接；"
                "验证：两端连接成功，双向各发送4个测试报文并确认加密计数增长。",
            ):
                if not restore_tunnel("首次建链"):
                    raise RuntimeError("首次IKE/Child SA未收敛")
                traffic = verify(
                    "双向加密数据传输",
                    ipsec.verify_bidirectional_traffic,
                    topology, kind="product", section="协议验证",
                )
                if not traffic or not traffic.passed:
                    raise RuntimeError("双向IPsec业务流量失败")
                observability = ipsec.query_tunnel_observability(
                    router_policy_id, "router"
                )
                check(
                    "隧道列表能找到本次已建立连接",
                    observability.get("row_found")
                    and str(observability.get("list", {}).get("status", "")).lower()
                    in {"established", "connected", "up", "已建立"},
                    observability, kind="product", section="页面验证",
                )
                list_counters = observability.get("list", {})
                check(
                    "隧道列表收发字节随真实流量增长",
                    int(list_counters.get("in_bytes") or 0) > 0
                    and int(list_counters.get("out_bytes") or 0) > 0,
                    list_counters, kind="product", section="运行时验证",
                    failure_summary=(
                        "隧道已有双向加密流量，但列表页收发字节仍为0。"
                    ),
                )
                detail = observability.get("detail", {})
                statistics = detail.get("statistics", {})
                check(
                    "隧道详情返回受保护报文和字节统计",
                    all(
                        int(statistics.get(name) or 0) > 0
                        for name in (
                            "in_protected_packets", "out_protected_packets",
                            "in_protected_bytes", "out_protected_bytes",
                        )
                    ),
                    detail, kind="product", section="运行时验证",
                )
                check(
                    "隧道日志包含标题、诊断和技术日志结构",
                    all(
                        observability.get("log", {}).get(name)
                        for name in (
                            "has_title", "has_diagnosis", "has_technical_logs",
                        )
                    ),
                    observability.get("log", {}),
                    kind="product", section="页面验证",
                )
                sa = detail.get("sa", {})
                check(
                    "SA流量上限为0时详情按不限展示",
                    str(sa.get("ipsec_sa_lifetime_bytes", "0"))
                    in {"0", "不限", "unlimited", "None"},
                    sa, kind="product", section="页面验证",
                    failure_summary=(
                        "策略配置的SA流量上限为不限，但详情页显示了虚构的固定上限。"
                    ),
                )
                rec.add_verification_commands([
                    {
                        "target": "router", "target_label": "主路由器",
                        "host": topology.router_underlay,
                        "command": "swanctl --list-sas",
                        "purpose": "查看当前IPsec连接状态",
                        "expected": "本次测试连接已经建立",
                        "effect": "只读", "copy_ready": True,
                        "contains_secret": False,
                    },
                    {
                        "target": "router", "target_label": "主路由器",
                        "host": topology.router_underlay,
                        "command": "ip -s xfrm state",
                        "purpose": "查看内核加密状态与报文计数",
                        "expected": "双向加密状态存在且报文计数增长",
                        "effect": "只读", "copy_ready": True,
                        "contains_secret": False,
                    },
                    {
                        "target": "router", "target_label": "主路由器",
                        "host": topology.router_underlay,
                        "command": f"ping -I {topology.router_service} -c 4 -W 2 {topology.peer_service}",
                        "purpose": "从主路由独立loopback发送实际加密流量",
                        "expected": "4个报文全部成功且XFRM计数增长",
                        "effect": "发送4个测试报文", "copy_ready": True,
                        "contains_secret": False,
                    },
                ])

            with recorded_step(
                "步骤9: 检查从任意一端发起连接是否都能成功",
                "操作：先断开当前连接，再分别从主路由和对端发起连接；"
                "验证：两种发起方向都能恢复隧道并正常传输数据。",
            ):
                ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                ipsec.reload_current_credentials()
                router_initiated = ipsec.initiate_child_from_router(
                    router_policy_id
                )
                check(
                    "从主路由发起连接", router_initiated.passed,
                    router_initiated.details,
                    kind="product", section="协议验证",
                    failure_summary=(
                        "相同配置下，从主路由发起连接失败，隧道无法建立。"
                    ),
                )
                if router_initiated.passed:
                    verify(
                        "主路由发起后双向数据可通过",
                        ipsec.verify_bidirectional_traffic,
                        topology, section="协议验证",
                    )
                add_public_command(
                    "router", "查看从主路由发起后的连接状态",
                    "swanctl --list-sas",
                    "正常情况下显示已建立连接；当前缺陷复现时不显示有效连接",
                    actual="自动化已记录本次发起结果",
                )
                ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                ipsec.reload_current_credentials()
                peer_initiated = ipsec.initiate_child_from_peer(peer_policy_id)
                check(
                    "从对端发起连接", peer_initiated.passed,
                    peer_initiated.details,
                    kind="product", section="协议验证",
                    failure_summary=(
                        "相同配置下，主路由发起可成功，但从对端发起返回认证失败，"
                        "连接结果错误地依赖发起方向。"
                    ),
                )
                if peer_initiated.passed:
                    verify(
                        "对端发起后双向数据可通过",
                        ipsec.verify_bidirectional_traffic,
                        topology, section="协议验证",
                    )
                ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                restore_tunnel("方向验证后恢复")

            with recorded_step(
                "步骤10: 检查策略停用后重新启用能否自动恢复连接",
                "操作：在页面停用策略，确认连接断开；再重新启用并等待恢复；"
                "验证：页面显示启用成功后，隧道和双向数据传输自动恢复。",
            ):
                disabled = ui.disable_policy(topology.router_policy)
                check("页面停用策略", disabled.get("success"), disabled)
                absent = verify(
                    "停用后连接已断开", ipsec.wait_for_sa_absent,
                    router_policy_id, peer_policy_id, timeout=20,
                    section="运行时验证",
                )
                verify(
                    "停用后数据无法通过", ipsec.verify_traffic_blocked,
                    topology, section="协议验证",
                )
                enabled = ui.enable_policy(topology.router_policy)
                check("页面重新启用策略", enabled.get("success"), enabled)
                auto = verify(
                    "重新启用后自动恢复连接",
                    ipsec.wait_for_sa,
                    topology, router_policy_id, peer_policy_id, timeout=10,
                    kind="product", section="协议验证",
                    failure_summary=(
                        "策略重新启用后，页面显示操作成功，但隧道没有自动恢复，"
                        "双向数据仍然不通。"
                    ),
                )
                if not auto or not auto.passed:
                    ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                    restore_tunnel("启用后夹具恢复")
                else:
                    verify(
                        "重新启用后双向数据可通过",
                        ipsec.verify_bidirectional_traffic,
                        topology, section="协议验证",
                    )

            with recorded_step(
                "步骤11: 检查编辑策略后连接能否正常更新和续期",
                "操作：在页面修改备注和连接生存时间并保存；"
                "验证：后台记录更新，旧连接被替换，连接续期后双向数据仍可通过。",
            ):
                ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                drawer = ui.open_policy_edit(topology.router_policy)
                ui.open_policy_section("basic")
                ui._replace_input(drawer.locator("#comment"), "automation-edited")
                ui.open_policy_section("advanced")
                ui._replace_input(drawer.locator("#ipsec_sa_time"), 900)
                edited = ui.save_policy("edit")
                check("页面编辑策略", edited.get("success"), edited)
                verify(
                    "后台已保存编辑内容",
                    ipsec.verify_database,
                    topology.router_policy,
                    {"comment": "automation-edited", "ipsec_sa_time": "900"},
                    "router", section="后端验证",
                )
                restore_tunnel("编辑后")
                rekey = verify(
                    "连接续期",
                    ipsec.rekey_child,
                    "router", router_policy_id, section="协议验证",
                )
                if rekey and rekey.passed:
                    verify(
                        "续期后双向数据仍可通过",
                        ipsec.verify_bidirectional_traffic,
                        topology, section="协议验证",
                    )

            with recorded_step(
                "步骤12: 检查两端配置不一致时能否安全失败并自动清理",
                "操作：依次制造密码、协议版本、加密参数、身份信息和业务网段不一致；"
                "验证：错误配置应阻止连接，不留下残留；恢复正确配置后连接自动恢复。",
            ):
                wrong_secret = ipsec.generate_psk()
                mismatch_case(
                    "预共享密码不一致",
                    lambda: ipsec.edit_policy(
                        "peer", topology, peer_proposal_id, wrong_secret
                    ),
                    lambda: ipsec.edit_policy(
                        "peer", topology, peer_proposal_id, secret
                    ),
                    verify_blocked_traffic=True,
                )
                mismatch_case(
                    "协议版本不一致",
                    lambda: ipsec.edit_policy(
                        "peer", topology, peer_proposal_id, secret,
                        {"ike_version": "ikev1", "prf": "", "aggressive": "0"},
                    ),
                    lambda: ipsec.edit_policy(
                        "peer", topology, peer_proposal_id, secret
                    ),
                )
                mismatch_case(
                    "加密算法不一致",
                    lambda: ipsec.edit_proposal(
                        "peer", topology.peer_proposal, enc_alg="aes128"
                    ),
                    lambda: ipsec.edit_proposal(
                        "peer", topology.peer_proposal, enc_alg="aes256"
                    ),
                )
                ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                pfs_changed = ipsec.edit_policy(
                    "peer", topology, peer_proposal_id, secret,
                    {"pfs_group": "modp1024"},
                )
                check(
                    "密钥组不一致的配置已下发", pfs_changed.passed,
                    pfs_changed.details, kind="automation", section="后端验证",
                )
                ipsec.reload_current_credentials()
                initial_child = ipsec.initiate_child_from_router(
                    router_policy_id
                )
                check(
                    "密钥组不一致时首次连接已建立",
                    initial_child.passed, initial_child.details,
                    kind="automation", section="协议验证",
                )
                pfs_rekey = ipsec.rekey_child("router", router_policy_id)
                check(
                    "两端密钥组不一致时重新建立连接必须失败",
                    not pfs_rekey.passed, pfs_rekey.details,
                    kind="product", section="协议验证",
                    failure_summary=(
                        "两端使用了不同的密钥组，本应拒绝重新建立连接，"
                        "实际却仍提示成功，安全限制没有生效。"
                    ),
                )
                ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                pfs_restored = ipsec.edit_policy(
                    "peer", topology, peer_proposal_id, secret
                )
                check(
                    "恢复一致的密钥组配置", pfs_restored.passed,
                    pfs_restored.details, kind="automation", section="后端验证",
                )
                restore_tunnel("密钥组恢复后")
                mismatch_case(
                    "对端身份信息不一致",
                    lambda: ipsec.edit_policy(
                        "peer", topology, peer_proposal_id, secret,
                        {"remote_id": "192.0.2.199"},
                    ),
                    lambda: ipsec.edit_policy(
                        "peer", topology, peer_proposal_id, secret
                    ),
                )
                wrong_traffic = base64.b64encode(json.dumps([{
                    "src": topology.peer_selector,
                    "dst": "192.0.2.200/32",
                    "protocol": "icmp", "action": "permit",
                    "src_port": "", "dst_port": "",
                }], separators=(",", ":")).encode()).decode()
                mismatch_case(
                    "业务网段不一致",
                    lambda: ipsec.edit_policy(
                        "peer", topology, peer_proposal_id, secret,
                        {"traffic": wrong_traffic},
                    ),
                    lambda: ipsec.edit_policy(
                        "peer", topology, peer_proposal_id, secret
                    ),
                    allow_ike_without_child=True,
                )
                add_public_command(
                    "router", "检查异常配置测试后是否仍有残留连接",
                    "swanctl --list-sas",
                    "每个失败场景结束后均不应残留本次异常连接",
                )
                add_public_command(
                    "router", "检查异常配置测试后的内核加密状态",
                    "ip -s xfrm state",
                    "不应残留本次异常连接对应的加密状态",
                )

            with recorded_step(
                "步骤13: 补充IPv6对等节点建链和双向流量",
                "操作：使用两台设备wan1真实IPv6外层地址，创建IPv6 /128保护流量并从主路由发起；"
                "验证：IPv6策略落库、IPv6 XFRM/Child收敛、ping6双向流量通过。",
            ):
                ui.navigate_to_ipsec()
                selected = ipsec.choose_topology(addr_type="v6")
                selected = replace(
                    selected,
                    router_proposal=topology.router_proposal,
                    peer_proposal=topology.peer_proposal,
                )
                router_id, peer_id = create_scenario(selected)
                verify(
                    "IPv6主路由策略字段",
                    ipsec.verify_database,
                    selected.router_policy,
                    {"addr_type": "v6", "role": "spoke"},
                    "router", section="后端验证",
                )
                verify(
                    "IPv6对端策略字段",
                    ipsec.verify_database,
                    selected.peer_policy,
                    {"addr_type": "v6", "role": "spoke"},
                    "peer", section="后端验证",
                )
                initiated = verify(
                    "IPv6主路由发起Child",
                    ipsec.initiate_child,
                    "router", router_id, section="协议验证",
                )
                converged = verify(
                    "IPv6双端SA/XFRM收敛",
                    ipsec.wait_for_sa,
                    selected, router_id, peer_id, timeout=35,
                    section="协议验证",
                )
                traffic = verify(
                    "IPv6 ping6双向加密流量",
                    ipsec.verify_bidirectional_traffic,
                    selected, kind="product", section="协议验证",
                )
                check(
                    "IPv6场景建链前置结果",
                    bool(initiated and initiated.passed and converged and converged.passed),
                    {"initiated": getattr(initiated, "details", {}),
                     "converged": getattr(converged, "details", {})},
                    kind="product", section="运行时验证",
                )
                teardown_scenario(selected, router_id, peer_id)
                restore_tunnel("IPv6场景结束后")

            with recorded_step(
                "步骤14: 补充域名对端解析和建链",
                "操作：给主路由临时写入唯一hosts映射，策略对端使用域名而非IP；"
                "验证：域名落库、解析文件/运行配置使用解析地址，真实隧道和双向流量通过，映射精确删除。",
            ):
                ui.navigate_to_ipsec()
                selected = ipsec.choose_topology()
                alias = f"peer-{selected.token}.test"
                marker = f"ipsec-host-{selected.token}"
                selected = replace(
                    selected,
                    router_proposal=topology.router_proposal,
                    peer_proposal=topology.peer_proposal,
                    router_remote_addr=alias,
                )
                router_id = peer_id = 0
                try:
                    installed = verify(
                        "临时域名映射",
                        ipsec.install_domain_alias,
                        "router", alias, selected.peer_underlay, marker,
                        kind="automation", section="运行时验证",
                    )
                    if installed and installed.passed:
                        router_id, peer_id = create_scenario(selected)
                        verify(
                            "域名对端字段和运行解析",
                            ipsec.verify_domain_policy_resolution,
                            router_id, alias, selected.peer_underlay,
                            "router", section="后端验证",
                        )
                        initiated = verify(
                            "域名对端主路由发起Child",
                            ipsec.initiate_child,
                            "router", router_id, section="协议验证",
                        )
                        verify(
                            "域名对端双向流量",
                            ipsec.verify_bidirectional_traffic,
                            selected, kind="product", section="协议验证",
                        )
                        check(
                            "域名对端Child已建立",
                            bool(initiated and initiated.passed),
                            getattr(initiated, "details", {}),
                            kind="product", section="运行时验证",
                        )
                finally:
                    if router_id or peer_id:
                        teardown_scenario(selected, router_id, peer_id)
                    removed = verify(
                        "唯一hosts映射精确清理",
                        ipsec.remove_domain_alias,
                        "router", marker, kind="automation",
                        section="清理结果",
                    )
                    check(
                        "域名映射清理成功",
                        bool(removed and removed.passed),
                        getattr(removed, "details", {}), kind="automation",
                        section="清理结果",
                    )
                    restore_tunnel("域名场景结束后")

            with recorded_step(
                "步骤15: 补充中心节点Hub拓扑",
                "操作：对端设备配置中心节点Hub，主路由配置spoke并发起连接；"
                "验证：Hub表单隐藏固定对端身份控件，后台使用%any/unique=never，双向流量通过。",
            ):
                ui.navigate_to_ipsec()
                probe = ui.open_new_policy()
                ui.fill_policy_basic(
                    tagname=f"hub{topology.token}", role="hub", addr_type="v4",
                    interface=topology.router_interface,
                    local_ip=topology.router_underlay, remote_addr="",
                    alias="hub-ui-probe", comment="automation",
                )
                ui.open_policy_section("ike")
                hub_form = ui.safe_form_observation()
                check(
                    "中心节点表单隐藏固定对端身份控件",
                    not any(item.get("id") == "remote_id" for item in hub_form["fields"])
                    and not any(item.get("id") == "remote_id_type" for item in hub_form["selects"]),
                    hub_form, kind="product",
                )
                ui.cancel_policy(discard=True)
                selected = ipsec.choose_topology(peer_role="hub")
                selected = replace(
                    selected,
                    router_proposal=topology.router_proposal,
                    peer_proposal=topology.peer_proposal,
                )
                router_id, peer_id = create_scenario(selected)
                verify(
                    "Hub策略运行契约",
                    ipsec.verify_hub_runtime_contract,
                    peer_id, "peer", section="运行时验证",
                )
                initiated = verify(
                    "Hub拓扑spoke发起Child",
                    ipsec.initiate_child,
                    "router", router_id, section="协议验证",
                )
                verify(
                    "Hub拓扑双向加密流量",
                    ipsec.verify_bidirectional_traffic,
                    selected, kind="product", section="协议验证",
                )
                check(
                    "Hub拓扑Child已建立",
                    bool(initiated and initiated.passed),
                    getattr(initiated, "details", {}),
                    kind="product", section="运行时验证",
                )
                teardown_scenario(selected, router_id, peer_id)
                restore_tunnel("Hub场景结束后")

            with recorded_step(
                "步骤16: 补充传输模式和非法Hub传输组合",
                "操作：使用真实外层主机/32作为唯一保护流量，创建transport模式并验证ICMP/XFRM；"
                "同时提交Hub+transport非法组合，确认后台拒绝。",
            ):
                ui.navigate_to_ipsec()
                selected = ipsec.choose_topology(encap_mode="transport")
                selected = replace(
                    selected,
                    router_proposal=topology.router_proposal,
                    peer_proposal=topology.peer_proposal,
                )
                router_id, peer_id = create_scenario(
                    selected, encap_mode="transport"
                )
                verify(
                    "主路由传输模式运行契约",
                    ipsec.verify_transport_runtime_contract,
                    router_id, selected, "router", section="运行时验证",
                )
                verify(
                    "对端传输模式运行契约",
                    ipsec.verify_transport_runtime_contract,
                    peer_id, selected, "peer", section="运行时验证",
                )
                initiated = verify(
                    "传输模式主机到主机Child",
                    ipsec.initiate_child,
                    "router", router_id, section="协议验证",
                )
                verify(
                    "传输模式双向ICMP流量",
                    ipsec.verify_bidirectional_traffic,
                    selected, kind="product", section="协议验证",
                )
                check(
                    "传输模式Child已建立",
                    bool(initiated and initiated.passed),
                    getattr(initiated, "details", {}),
                    kind="product", section="运行时验证",
                )
                teardown_scenario(selected, router_id, peer_id)
                invalid = replace(
                    ipsec.choose_topology(),
                    router_role="hub", encap_mode="transport",
                    router_proposal=topology.router_proposal,
                    peer_proposal=topology.peer_proposal,
                )
                invalid_id = 0
                rejected = False
                try:
                    invalid_id = ipsec.add_policy(
                        "router", invalid, router_proposal_id, secret
                    )
                except Exception as exc:
                    rejected = True
                    add_section(
                        "协议验证", "通过", "Hub+transport非法组合被拒绝",
                        {"exception": type(exc).__name__},
                    )
                check(
                    "Hub+transport非法组合必须拒绝",
                    rejected,
                    {"created_policy_id": invalid_id}, kind="product",
                    section="协议验证",
                )
                if invalid_id:
                    ipsec.policy_action("router", "del", invalid_id)
                restore_tunnel("传输模式场景结束后")

            with recorded_step(
                "步骤17: 补充多隧道、多Child和全量统计",
                "操作：同时创建两个不同业务选择器的隧道，分别建链、打流、连续rekey；"
                "验证：隧道列表有两个独立对象，所有Child和所有详情统计均被汇总，不取空闲Child。",
            ):
                first = replace(
                    ipsec.choose_topology(),
                    router_proposal=topology.router_proposal,
                    peer_proposal=topology.peer_proposal,
                )
                second = replace(
                    ipsec.choose_topology(),
                    router_proposal=topology.router_proposal,
                    peer_proposal=topology.peer_proposal,
                )
                first_ids = create_scenario(first, use_ui_router=False)
                second_ids = create_scenario(second, use_ui_router=False)
                for selected, (router_id, peer_id) in (
                    (first, first_ids), (second, second_ids)
                ):
                    initiated = verify(
                        f"{selected.token}-多隧道建链",
                        ipsec.initiate_child,
                        "router", router_id, section="协议验证",
                    )
                    verify(
                        f"{selected.token}-多隧道双向流量",
                        ipsec.verify_bidirectional_traffic,
                        selected, kind="product", section="协议验证",
                    )
                    check(
                        f"{selected.token}-多隧道Child建立",
                        bool(initiated and initiated.passed),
                        getattr(initiated, "details", {}),
                        kind="product", section="运行时验证",
                    )
                for _ in range(2):
                    verify("第一条隧道连续rekey", ipsec.rekey_child,
                           "router", first_ids[0], section="协议验证")
                    verify("第二条隧道连续rekey", ipsec.rekey_child,
                           "router", second_ids[0], section="协议验证")
                inventory = ipsec.query_multi_tunnel_observability(
                    [first_ids[0], second_ids[0]], "router"
                )
                aggregate = inventory.get("aggregate_statistics", {})
                check(
                    "多隧道列表包含两个独立对象",
                    inventory.get("matched_rows", 0) >= 2
                    and inventory.get("distinct_tunnel_keys", 0) >= 2,
                    inventory, kind="product", section="后端验证",
                )
                check(
                    "多Child清单和保护字节统计不为空",
                    inventory.get("child_inventory", {}).get("total_installed", 0) >= 2
                    and aggregate.get("in_protected_bytes", 0) > 0
                    and aggregate.get("out_protected_bytes", 0) > 0,
                    inventory, kind="product", section="后端验证",
                    failure_summary=(
                        "多隧道详情只返回空闲Child或保护字节统计为0，"
                        "无法证明统计覆盖全部活动Child。"
                    ),
                )
                teardown_scenario(first, first_ids[0], first_ids[1])
                teardown_scenario(second, second_ids[0], second_ids[1])
                restore_tunnel("多隧道场景结束后")

            with recorded_step(
                "步骤18: 补充长时间DPD黑洞检测和恢复",
                "操作：建立独立DPD隧道，在对端仅丢弃来自主路由的UDP500/4500和ESP，等待实际DPD收敛；"
                "验证：记录状态变化时间、撤销规则、恢复隧道并再次双向打流。",
            ):
                selected = replace(
                    ipsec.choose_topology(),
                    router_proposal=topology.router_proposal,
                    peer_proposal=topology.peer_proposal,
                )
                router_id, peer_id = create_scenario(
                    selected, use_ui_router=False,
                    router_overrides={
                        "dpd_enabled": "yes", "dpd_interval": 10,
                        "dpd_timeout": 30, "dpd_action": "restart",
                    },
                    peer_overrides={
                        "dpd_enabled": "yes", "dpd_interval": 10,
                        "dpd_timeout": 30, "dpd_action": "restart",
                    },
                )
                initiated = verify(
                    "DPD黑洞场景首次建链",
                    ipsec.initiate_child,
                    "router", router_id, section="协议验证",
                )
                verify(
                    "DPD黑洞场景双向流量基线",
                    ipsec.verify_bidirectional_traffic,
                    selected, kind="product", section="协议验证",
                )
                marker = f"ipsec-dpd-{selected.token}"
                blackhole = verify(
                    "长时间DPD黑洞识别",
                    ipsec.verify_dpd_blackhole_detection,
                    selected, router_id, peer_id, marker=marker,
                    section="协议验证",
                )
                check(
                    "DPD黑洞夹具最终撤销",
                    bool(blackhole and blackhole.details.get("blackhole_removed")),
                    getattr(blackhole, "details", {}),
                    kind="automation", section="清理结果",
                )
                ipsec.terminate_test_sas(router_id, peer_id)
                verify(
                    "DPD黑洞撤销后重载凭据",
                    ipsec.reload_current_credentials,
                    kind="product", section="运行时验证",
                )
                recovered = verify(
                    "DPD黑洞撤销后重新建链",
                    ipsec.initiate_child,
                    "router", router_id, section="协议验证",
                )
                verify(
                    "DPD黑洞恢复后双向流量",
                    ipsec.verify_bidirectional_traffic,
                    selected, kind="product", section="协议验证",
                )
                check(
                    "DPD黑洞恢复Child已建立",
                    bool(recovered and recovered.passed),
                    getattr(recovered, "details", {}),
                    kind="product", section="运行时验证",
                )
                teardown_scenario(selected, router_id, peer_id)
                restore_tunnel("DPD场景结束后", failure_kind="product")

            with recorded_step(
                "步骤19: 检查删除策略和IKE提议后数据是否清理",
                "操作：从页面删除策略，修改IKE提议生存周期后再删除提议；"
                "验证：页面和后台只删除本次目标对象，不影响其他配置。",
            ):
                ui.navigate_to_ipsec()
                ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                deleted = ui.delete_policy(topology.router_policy)
                check("页面删除策略", deleted.get("success"), deleted)
                verify(
                    "后台已删除目标策略",
                    ipsec.verify_database,
                    topology.router_policy, {}, "router", absent=True,
                    section="后端验证",
                )
                ui.open_proposal_edit(topology.router_proposal)
                modal = ui._proposal_modal()
                ui._replace_input(modal.locator("#sa_lifetime"), 43200)
                edited = ui.save_proposal("edit")
                check("页面编辑IKE提议", edited.get("success"), edited)
                row = ipsec.find_proposal(topology.router_proposal, "router")
                check(
                    "后台已更新IKE提议生存周期",
                    bool(row) and str(row.get("sa_lifetime")) == "43200",
                    row, section="后端验证",
                )
                deleted = ui.delete_proposal(topology.router_proposal)
                check("页面删除IKE提议", deleted.get("success"), deleted)
                check(
                    "后台已删除目标IKE提议",
                    ipsec.find_proposal(topology.router_proposal, "router") is None,
                    ipsec.find_proposal(topology.router_proposal, "router"),
                    section="后端验证",
                )
                add_public_command(
                    "router", "确认目标IKE提议已从数据库删除",
                    "sqlite3 /etc/mnt/ikuai/config.db -line \"SELECT id,tagname,sa_lifetime FROM ipsec2_proposal WHERE tagname IS '"
                    + topology.router_proposal + "';\"",
                    "无输出",
                )

        finally:
            with recorded_step(
                "步骤20: 恢复测试前状态并确认没有残留",
                "操作：停止本次测试连接，删除本次创建的策略、提议、路由和临时地址，"
                "恢复测试前的连接服务状态；验证：两台设备状态与测试前一致，管理通道可用。",
            ):
                for _, owned_router_id, _, owned_peer_id in list(extended_policy_ids):
                    if owned_router_id and owned_peer_id:
                        ipsec.terminate_test_sas(owned_router_id, owned_peer_id)
                if router_policy_id and peer_policy_id:
                    ipsec.terminate_test_sas(router_policy_id, peer_policy_id)
                cleanup = ipsec.cleanup(topology) if topology else None
                check(
                    "仅清理本次测试创建的对象",
                    bool(cleanup and cleanup.passed),
                    getattr(cleanup, "details", {}),
                    kind="automation", section="清理结果",
                )
                daemon = (
                    ipsec.restore_daemon_state(snapshot)
                    if snapshot is not None else None
                )
                check(
                    "恢复两端连接服务状态",
                    bool(daemon and daemon.passed),
                    getattr(daemon, "details", {}),
                    kind="automation", section="清理结果",
                )
                audit = (
                    verify(
                        "独立检查是否存在测试残留",
                        ipsec.exact_residual_audit,
                        [topology] + extended_topologies, snapshot,
                        kind="automation", section="清理结果",
                    )
                    if topology is not None else None
                )
                if snapshot is not None:
                    restored = verify(
                        "两台设备状态恢复到测试前",
                        ipsec.verify_restored, snapshot,
                        kind="environment", section="清理结果",
                        failure_summary=(
                            "测试执行期间，设备的全局路由、地址、策略规则或其他IPsec配置"
                            "发生了变化；本次测试对象是否残留已由上一项单独检查。"
                        ),
                    )

        failures = product_failures + automation_failures + environment_failures
        _emit_ipsec_realtime(
            "汇总",
            f"产品失败={len(product_failures)} | "
            f"自动化失败={len(automation_failures)} | "
            f"环境失败={len(environment_failures)}",
        )
        assert not failures, (
            f"IPsec VPN综合验证失败({len(failures)}项，"
            f"产品={len(product_failures)}，自动化={len(automation_failures)}，"
            f"环境={len(environment_failures)})："
            + "; ".join(failures[:30])
        )
