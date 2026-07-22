"""设备设置 > 高级管理 > 协议控制 L1-L5 单节点综合测试。

实机后端为 ``core_control`` Action API、``forward_mode_config`` 单例表和
``/usr/ikuai/script/core_control.sh``。L5 在配置中的 client/peer 之间发送
唯一HTTP流量，强制 ``192.168.148.2`` 经 ``192.168.148.1`` 转发，对照
平衡模式的DPI/访问记录和性能模式的无识别结果，并精确清理唯一token。
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

import pytest

from pages.device_setting.protocol_control_page import ProtocolControlPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.device_setting, pytest.mark.protocol_control]


class TestProtocolControlComprehensive:
    """协议控制页面、API、数据库、内核运行态与真实流量综合验证。"""

    def test_protocol_control_comprehensive(
        self,
        protocol_control_page_logged_in: ProtocolControlPage,
        step_recorder: StepRecorder,
        request,
    ):
        page = protocol_control_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("协议控制L1-L5综合测试必须启用SSH backend_verifier")

        failures: List[str] = []
        cleanup_failures: List[str] = []
        snapshot: Optional[Dict[str, Any]] = None
        snapshot_valid = False
        mutation_started = False
        unexpected_error = ""
        nat_failure_triggers = set()

        rec.required_sections = (
            "测试操作", "页面验证", "后端验证", "运行时验证", "协议验证", "清理结果"
        )

        def section(name: str, status: str, label: str, detail: Any):
            rec.add_detail(f"【{name}】\n{status}：{label}；{detail}")

        def fail(label: str, detail: Any, *, cleanup: bool = False):
            message = f"{label}：{detail}"
            (cleanup_failures if cleanup else failures).append(message)
            rec.fail_current_step(message)

        def ui_check(label: str, condition: Any, detail: Any = "条件不成立") -> bool:
            passed = bool(condition)
            print(f"    UI-{label}: {'[OK]' if passed else '[FAIL]'}")
            section(
                "页面验证", "通过" if passed else "失败", label,
                "符合预期" if passed else detail,
            )
            if not passed:
                fail(f"页面验证-{label}", detail)
            return passed

        def ssh_verify(
            label: str,
            verify_func: Callable,
            *args,
            must_pass: bool = True,
            cleanup: bool = False,
            **kwargs,
        ):
            try:
                result = verify_func(*args, **kwargs)
                passed = bool(getattr(result, "passed", False))
                message = str(getattr(result, "message", "无验证消息"))
                print(f"    SSH-{label}: {'[OK]' if passed else '[FAIL]'} - {message}")
                target = (
                    "清理结果" if cleanup else
                    "协议验证" if label.startswith("L5") else
                    "运行时验证" if label.startswith(("L2", "L3", "L4")) else
                    "后端验证"
                )
                section(target, "通过" if passed else "失败", label, message)
                raw = str(getattr(result, "raw_output", "") or "")
                if raw:
                    rec.add_detail(f"【后端数据】\n{raw}")
                if must_pass and not passed:
                    fail(f"后端验证-{label}", message, cleanup=cleanup)
                return result
            except Exception as exc:
                message = f"验证调用异常({type(exc).__name__})"
                print(f"    SSH-{label}: [FAIL] - {message}")
                if must_pass:
                    fail(f"后端验证-{label}", message, cleanup=cleanup)
                return None

        ssh_verify = attach_cmd_recording_to_closure(backend, rec, ssh_verify)

        def api_row() -> Dict[str, Any]:
            return page.api_row(page.api_show())

        def guard_nat(
            label: str, *, cleanup: bool = False, repair_if_failed: bool = True
        ) -> bool:
            health = ssh_verify(
                f"L4-NAT守护-{label}",
                backend.verify_protocol_control_nat_health,
                must_pass=False,
                cleanup=cleanup,
            )
            if health is not None and getattr(health, "passed", False):
                return True
            if label not in nat_failure_triggers:
                nat_failure_triggers.add(label)
                fail(
                    f"协议控制触发LAN断网-{label}",
                    getattr(health, "message", "NAT健康探测异常"),
                    cleanup=cleanup,
                )
            if not repair_if_failed:
                return False
            repaired = ssh_verify(
                f"L4-NAT自动恢复-{label}",
                backend.repair_protocol_control_nat_runtime,
                must_pass=True,
                cleanup=cleanup,
            )
            ok = bool(repaired is not None and getattr(repaired, "passed", False))
            if not ok and not cleanup:
                raise RuntimeError(f"{label}后AUTONAT自动恢复失败，停止后续持久化修改")
            return ok

        def switch_mode(mode: int, label: str, *, force_save: bool = True):
            nonlocal mutation_started
            mutation_started = True
            page.navigate_to_protocol_control()
            if force_save and page.get_mode() == mode:
                other = (
                    page.MODE_PERFORMANCE if mode == page.MODE_BALANCED
                    else page.MODE_BALANCED
                )
                precondition = page.select_mode(other)
                ui_check(
                    f"{label}-保存前置切换{page.MODE_NAMES[other]}",
                    precondition.get("saved"), precondition,
                )
                ssh_verify(
                    f"L4-{label}-前置运行态稳定",
                    backend.wait_protocol_control_runtime,
                    other,
                )
                guard_nat(f"{label}-前置切换")
                page.navigate_to_protocol_control()

            result = page.select_mode(mode)
            ui_check(f"{label}-save请求成功", result.get("saved"), result)
            ui_check(
                f"{label}-请求仅提交mode",
                result.get("noop") or result.get("request_param") == {"mode": mode},
                result,
            )
            if mode == page.MODE_PERFORMANCE and not result.get("noop"):
                ui_check(
                    f"{label}-二次确认",
                    result.get("confirmation_seen")
                    and result.get("confirmation_accepted"),
                    result,
                )
            ssh_verify(
                f"L4-{label}-核心运行态稳定",
                backend.wait_protocol_control_runtime,
                mode,
            )
            guard_nat(f"{label}-保存后")
            ssh_verify(
                f"L4-{label}-管理健康",
                backend.verify_protocol_control_management_health,
            )
            page.navigate_to_protocol_control()
            ui_check(
                f"{label}-刷新回显",
                page.get_mode() == mode,
                {"actual": page.get_mode(), "expected": mode},
            )
            current_api = api_row()
            ui_check(
                f"{label}-API回显",
                int(current_api.get("mode", -1)) == mode,
                current_api,
            )
            return result

        try:
            with rec.step(
                "步骤1 操作：保存协议控制全环境快照；验证：管理、LAN/NAT健康且无既有测试残留",
                "只读保存forward_mode_config、/proc运行态、客户端路由和三端临时文件；基线不健康时禁止修改",
            ):
                snapshot = backend.get_protocol_control_environment_snapshot()
                row = dict(snapshot.get("row") or {})
                artifacts = dict(snapshot.get("artifacts") or {})
                snapshot_valid = bool(
                    snapshot.get("version") == 1
                    and row.get("id") == 1
                    and row.get("mode") in (0, 1)
                    and snapshot.get("nat_health_passed") is True
                    and snapshot.get("management_health_passed") is True
                    and not any(artifacts.values())
                    and not snapshot.get("audit_artifacts")
                )
                ui_check("协议控制快照完整且基线健康", snapshot_valid, snapshot)
                if not snapshot_valid:
                    raise RuntimeError("协议控制基线不健康，禁止开始持久化操作")

            with rec.step(
                "步骤2 操作：分析core_control.sh与API注册；验证：校验值、表、show/save、参数校验和init契约",
                "核对function软链接、forward_mode_config默认值、模式派生字段和ik_cntl真实调用",
            ):
                contract = ssh_verify(
                    "L1-脚本/API/数据库契约",
                    backend.verify_protocol_control_script_contract,
                )
                details = dict(getattr(contract, "details", {}) or {})
                section(
                    "后端验证", "通过", "实机事实",
                    f"sha256={details.get('script_sha256')}；"
                    f"API注册={details.get('api_registration')}；"
                    f"脚本直接审计控制={details.get('audit_control_present')}",
                )

            with rec.step(
                "步骤3 操作：检查协议控制单例页面；验证：真实URL、双模式、二帮助及无CRUD矩阵",
                "页面只能切换平衡/性能模式，无保存按钮、列表、搜索、新增、删除、批量、导入导出、排序和分页",
            ):
                ui_check("协议控制页面导航成功", page.is_on_protocol_control_page(), page.page.url)
                structure = page.get_page_structure()
                matrix = page.get_capability_matrix()
                ui_check(
                    "真实URL和双模式结构",
                    structure["url"].endswith(page.PAGE_URL)
                    and structure["mode_count"] == 2
                    and structure["help_count"] == 2,
                    structure,
                )
                ui_check(
                    "单例页无虚构CRUD",
                    all(
                        not matrix[name]["supported"]
                        for name in (
                            "search", "add_record", "edit_record", "delete_record",
                            "batch_operation", "import", "export", "sort", "pagination",
                        )
                    ),
                    matrix,
                )

            with rec.step(
                "步骤4 操作：核对测试前UI、API、数据库和运行态；验证：全链路与快照模式一致",
                "刷新页面并读取core_control/show、forward_mode_config、basic.switch_dpi和/proc真实参数",
            ):
                baseline_mode = int(snapshot["row"]["mode"])
                ui_check("基线UI模式", page.get_mode() == baseline_mode, page.get_mode())
                ui_check("基线API模式", int(api_row().get("mode", -1)) == baseline_mode, api_row())
                ssh_verify(
                    "L1-基线数据库",
                    backend.verify_protocol_control_database,
                    baseline_mode,
                )
                ssh_verify(
                    "L2/L3-基线运行态",
                    backend.verify_protocol_control_runtime,
                    baseline_mode,
                )

            with rec.step(
                "步骤5 操作：提交非法mode=99；验证：API明确拒绝且原数据库/页面状态不受污染",
                "通过同一登录会话调用core_control/save，断言code非0、show和数据库仍为快照模式",
            ):
                before = api_row()
                rejected = page.api_save(99)
                after = api_row()
                ui_check(
                    "非法mode被后端拒绝",
                    int(rejected.get("code", 0)) != 0
                    and "mode" in str(rejected.get("errors") or ""),
                    rejected,
                )
                ui_check("非法提交未污染API数据", before == after, {"before": before, "after": after})
                ssh_verify(
                    "L1-非法提交后数据库未变",
                    backend.verify_protocol_control_database,
                    int(before["mode"]),
                )

            with rec.step(
                "步骤6 操作：通过页面保存平衡模式并刷新；验证：L1-L4及管理/NAT全链路一致",
                "如当前已是平衡模式，先受保护切到性能再切回，确保真实save请求得到覆盖",
            ):
                switch_mode(page.MODE_BALANCED, "平衡模式")
                ssh_verify("L1-平衡模式数据库", backend.verify_protocol_control_database, 1)
                ssh_verify("L2/L3-平衡模式运行态", backend.verify_protocol_control_runtime, 1)
                ssh_verify("L4-平衡模式全链路", backend.verify_protocol_control_full_chain, 1)

            with rec.step(
                "步骤7 操作：执行core_control.sh init；验证：平衡模式不丢失、运行态重建且LAN/NAT正常",
                "调用产品init入口后复验数据库未变、DPI/QUIC/审计参数和管理转发健康",
            ):
                ssh_verify("L4-平衡模式init重建", backend.verify_protocol_control_reinit, 1)
                guard_nat("平衡模式init后")

            with rec.step(
                "步骤8 操作：发送平衡模式唯一HTTP流量；验证：DPI、访问记录、客户端IP和SNAT正向闭环",
                "客户端192.168.148.2强制经192.168.148.1访问配置peer；每轮唯一Host/URL/端口并记录前后数量",
            ):
                ssh_verify(
                    "L5-平衡模式HTTP正向闭环",
                    backend.run_protocol_control_http_probe,
                    True,
                )
                guard_nat("平衡模式L5后")

            with rec.step(
                "步骤9 操作：读取平衡模式QUIC与解析参数；验证：DPI/审计开启且QUIC默认关闭",
                "直接读取/proc/ikuai/stats/ik_features_status，不以页面选中状态替代运行态证据",
            ):
                balanced_runtime = ssh_verify(
                    "L3-平衡模式QUIC默认关闭",
                    backend.verify_protocol_control_runtime,
                    1,
                )
                runtime_details = dict(getattr(balanced_runtime, "details", {}) or {})
                actual_features = ((runtime_details.get("state") or {}).get("features") or {})
                ui_check(
                    "QUIC真实运行态为disable",
                    actual_features.get("quic") == "disable",
                    actual_features,
                )

            with rec.step(
                "步骤10 操作：通过二次确认保存性能模式；验证：持久化、刷新及L1-L4严格契约",
                "性能模式必须关闭DPI、HTTPS/QUIC解析、应用统计、访问记录和审计；发现产品差异保持硬失败",
            ):
                switch_mode(page.MODE_PERFORMANCE, "性能模式")
                ssh_verify("L1-性能模式数据库", backend.verify_protocol_control_database, 0)
                ssh_verify("L2/L3-性能模式运行态", backend.verify_protocol_control_runtime, 0)
                ssh_verify("L4-性能模式全链路", backend.verify_protocol_control_full_chain, 0)

            with rec.step(
                "步骤11 操作：执行性能模式init并发送同类HTTP；验证：转发/SNAT正常且无DPI或访问记录",
                "排除旧记录、缓存和conntrack；使用新token、新Host、新URL和新端口形成负向闭环",
            ):
                ssh_verify("L4-性能模式init重建", backend.verify_protocol_control_reinit, 0)
                guard_nat("性能模式init后")
                ssh_verify(
                    "L5-性能模式HTTP反向闭环",
                    backend.run_protocol_control_http_probe,
                    False,
                )
                guard_nat("性能模式L5后")

            with rec.step(
                "步骤12 操作：平衡↔性能多次往返；验证：API/DB/UI无状态漂移且每次NAT健康",
                "连续切换1→0→1，每次等待真实运行态稳定、刷新回显并执行LAN/SNAT守护",
            ):
                for index, mode in enumerate((1, 0, 1), start=1):
                    switch_mode(mode, f"往返{index}-{page.MODE_NAMES[mode]}", force_save=False)
                    ssh_verify(
                        f"L1-往返{index}数据库",
                        backend.verify_protocol_control_database,
                        mode,
                    )

            with rec.step(
                "步骤13 操作：悬浮两个问号帮助并移出；验证：实际说明完整且无孤儿帮助层",
                "平衡帮助包含DPI/审计/QUIC，性能帮助包含关闭DPI、访问记录、审计及受影响功能",
            ):
                page.navigate_to_protocol_control()
                help_result = page.verify_help_entries(("DPI", "审计"))
                ui_check("两个帮助均打开", help_result.get("all_opened"), help_result)
                ui_check("帮助内容非空且主题匹配", help_result.get("content_complete"), help_result)
                ui_check("帮助均关闭且无孤儿层", help_result.get("all_closed"), help_result)

            with rec.step(
                "步骤14 操作：通过页面恢复测试前模式；验证：UI/API/数据库/运行态和LAN/NAT回到快照",
                "恢复后独立检查SSH、Web、192.168.148.2联网SNAT、192.168.148.5会话及唯一token残留",
            ):
                switch_mode(int(snapshot["row"]["mode"]), "页面恢复测试前模式")
                ssh_verify(
                    "L4-页面恢复后环境一致",
                    backend.verify_protocol_control_environment_unchanged,
                    snapshot,
                    cleanup=True,
                )

        except Exception as exc:
            unexpected_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            fail("协议控制综合流程异常", unexpected_error)
        finally:
            if snapshot_valid and snapshot is not None:
                restore = ssh_verify(
                    "finally-精确恢复协议控制快照",
                    backend.restore_protocol_control_environment,
                    snapshot,
                    must_pass=True,
                    cleanup=True,
                )
                if restore is None or not getattr(restore, "passed", False):
                    cleanup_failures.append("finally精确恢复失败")
                guard_nat("finally恢复后", cleanup=True)
                ssh_verify(
                    "finally-SSH与Web管理健康",
                    backend.verify_protocol_control_management_health,
                    cleanup=True,
                )
                ssh_verify(
                    "finally-192.168.148.5独立SNAT复核",
                    backend.verify_protocol_control_secondary_client_health,
                    cleanup=True,
                )
                final_audit = ssh_verify(
                    "finally-残留和快照独立审计",
                    backend.verify_protocol_control_environment_unchanged,
                    snapshot,
                    cleanup=True,
                )
                if final_audit is None or not getattr(final_audit, "passed", False):
                    cleanup_failures.append("finally独立残留审计失败")
                try:
                    page.navigate_to_protocol_control()
                    final_mode = page.get_mode()
                    if final_mode != int(snapshot["row"]["mode"]):
                        cleanup_failures.append("finally页面模式与快照不一致")
                        section("清理结果", "失败", "finally页面回显", final_mode)
                    else:
                        section("清理结果", "通过", "finally页面回显", final_mode)
                except Exception as exc:
                    cleanup_failures.append(f"finally页面复验异常({type(exc).__name__})")
            elif mutation_started:
                cleanup_failures.append("已开始修改但无有效协议控制快照，无法安全恢复")
            if not snapshot_valid:
                guard_nat(
                    "finally无有效快照复核", cleanup=True,
                    repair_if_failed=mutation_started,
                )

        all_failures = failures + cleanup_failures
        if unexpected_error:
            print(f"[协议控制异常] {unexpected_error}")
        if all_failures:
            print(f"[协议控制断言] 共{len(all_failures)}项失败")
            for item in all_failures:
                print(f"  - {item}")
        assert not all_failures, (
            f"协议控制L1-L5综合验证失败({len(all_failures)}项): "
            + "; ".join(all_failures[:24])
        )
