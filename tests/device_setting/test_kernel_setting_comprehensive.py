"""设备设置 > 高级管理 > 内核设置 L1-L5 单节点综合测试。

底层脚本为 ``/usr/ikuai/script/ik_sysctl.sh``。L5 在测试客户端
``10.66.0.18`` 的 ``ens11`` 上使用 ``192.168.148.2``，强制经
``192.168.148.1`` 访问 ``10.66.0.57``，以真实 TCP/UDP/ICMP 会话验证
conntrack 超时值、状态消亡、双向 UDP stream 和 TCP BBR 运行配置。
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

import pytest

from pages.device_setting.kernel_setting_page import KernelSettingPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.device_setting, pytest.mark.kernel_setting]


class TestKernelSettingComprehensive:
    """内核设置页面、数据库、运行态、脚本重建和实流综合验证。"""

    def test_kernel_setting_comprehensive(
        self,
        kernel_setting_page_logged_in: KernelSettingPage,
        step_recorder: StepRecorder,
        request,
    ):
        page = kernel_setting_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("内核设置L1-L5综合测试必须启用SSH backend_verifier")

        failures: List[str] = []
        cleanup_failures: List[str] = []
        snapshot: Optional[Dict[str, Any]] = None
        snapshot_valid = False
        mutation_started = False
        unexpected_error: Optional[str] = None
        ports: List[int] = []

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

        def to_expected(values: Dict[str, Any]) -> Dict[str, int]:
            expected = {}
            for name in page.FIELD_NAMES:
                value = values[name]
                expected[name] = int(bool(value)) if name == "bbr" else int(value)
            return expected

        def to_form(row: Dict[str, Any]) -> Dict[str, Any]:
            return {
                name: bool(int(row[name])) if name == "bbr" else int(row[name])
                for name in page.FIELD_NAMES
            }

        def state_matches(actual: Dict[str, Any], expected: Dict[str, Any]) -> bool:
            return all(actual.get(name) == expected.get(name) for name in page.FIELD_NAMES)

        def api_row() -> Dict[str, Any]:
            return page.api_row(page.api_show())

        def save_valid(values: Dict[str, Any], label: str) -> Dict[str, Any]:
            nonlocal mutation_started
            mutation_started = True
            if not page.navigate_to_kernel_setting():
                raise RuntimeError(f"{label}前无法重新进入内核设置页面")
            result = page.save_config(values)
            saved = ui_check(f"{label}-保存API成功", result.get("saved"), result)
            request_param = dict(result.get("request_param") or {})
            ui_check(
                f"{label}-请求字段完整",
                set(request_param) == set(page.FIELD_NAMES) | {"id"},
                request_param,
            )
            ui_check(
                f"{label}-单例记录ID正确",
                str(request_param.get("id")) == "1",
                request_param,
            )
            if not saved:
                raise RuntimeError(f"{label}保存失败，停止依赖该配置的后续验证")
            if not page.navigate_to_kernel_setting():
                raise RuntimeError(f"{label}保存后无法刷新页面")
            ui_check(
                f"{label}-页面刷新回显",
                state_matches(page.get_config(), values),
                {"actual": page.get_config(), "expected": values},
            )
            return result

        try:
            with rec.step(
                "步骤1 操作：保存三端全环境快照并识别内核设置页面；验证：脚本、表、范围、字段和路径基线",
                "只读保存sysctl、全部/proc值、ens11路由和三端临时文件；基线不健康时禁止修改",
            ):
                snapshot = backend.get_kernel_environment_snapshot()
                snapshot_valid = bool(
                    snapshot.get("version") == 1
                    and snapshot.get("row", {}).get("id") == 1
                    and snapshot.get("client_iface") == "ens11"
                    and snapshot.get("peer_host") == "10.66.0.57"
                    and snapshot.get("path_health_passed") is True
                    and not snapshot.get("router_artifacts")
                    and not snapshot.get("client_artifacts")
                    and not snapshot.get("peer_artifacts")
                )
                ui_check("内核设置快照完整且三端无残留", snapshot_valid, snapshot)
                if not snapshot_valid:
                    raise RuntimeError("内核设置基线不健康，禁止开始持久化操作")
                ports = backend.choose_kernel_candidate_ports(4)
                ui_check(
                    "四个L5动态端口唯一合法",
                    len(ports) == 4 and len(set(ports)) == 4
                    and all(1024 <= port <= 65535 for port in ports),
                    ports,
                )
                ui_check("内核设置页面导航成功", page.is_on_kernel_setting_page(), page.page.url)
                structure = page.get_page_structure()
                ui_check(
                    "十一个超时字段和BBR开关完整",
                    all(item["present"] and item["enabled"] for item in structure["fields"].values()),
                    structure,
                )
                ui_check(
                    "保存、默认恢复和帮助入口完整",
                    structure["save_present"]
                    and structure["default_present"]
                    and structure["help_present"],
                    structure,
                )
                capabilities = page.get_capability_matrix()
                ui_check(
                    "单例能力如实建模且无虚构CRUD",
                    capabilities["singleton_configuration_edit"]["supported"]
                    and capabilities["save"]["supported"]
                    and capabilities["restore_default"]["supported"]
                    and capabilities["help"]["supported"]
                    and all(
                        not capabilities[name]["supported"]
                        for name in (
                            "search", "add_record", "edit_record", "delete_record",
                            "batch_operation", "import", "export", "sort", "pagination",
                        )
                    ),
                    capabilities,
                )
                ssh_verify("L1/L4-脚本/API/数据库契约", backend.verify_kernel_script_contract)

            with rec.step(
                "步骤2 操作：核对测试前UI、API、数据库和运行态；验证：十二字段与快照全链路一致",
                "刷新内核页并读取ik_sysctl/show、sysctl id=1、全部conntrack超时和TCP拥塞算法",
            ):
                baseline_form = to_form(snapshot["row"])
                page.navigate_to_kernel_setting()
                ui_check(
                    "测试前页面回显等于快照",
                    state_matches(page.get_config(), baseline_form),
                    {"actual": page.get_config(), "expected": baseline_form},
                )
                ui_check(
                    "测试前API回显等于快照",
                    to_expected(to_form(api_row())) == to_expected(baseline_form),
                    api_row(),
                )
                ssh_verify("L1-测试前数据库", backend.verify_kernel_database, to_expected(baseline_form))
                ssh_verify("L2/L3-测试前运行态", backend.verify_kernel_runtime, to_expected(baseline_form))

            minimum_form = {"bbr": True}
            minimum_form.update({
                name: bounds[0] for name, bounds in page.FIELD_RANGES.items()
            })
            with rec.step(
                "步骤3 操作：通过页面保存全部最小边界并开启BBR；验证：L1-L4与ik_sysctl.sh init严格一致",
                "一次提交十二字段，验证每个/proc参数为最小值、拥塞算法为bbr且脚本重建不丢配置",
            ):
                save_valid(minimum_form, "最小边界+BBR开启")
                ssh_verify("L1-最小边界数据库", backend.verify_kernel_database, to_expected(minimum_form))
                ssh_verify("L2/L3-最小边界运行态", backend.verify_kernel_runtime, to_expected(minimum_form))
                ssh_verify("L4-最小边界脚本重建", backend.verify_kernel_reinit, to_expected(minimum_form))
                ssh_verify("L4-最小边界路径健康", backend.verify_kernel_path_health)

            with rec.step(
                "步骤4 操作：从10.66.0.18的ens11向10.66.0.57发送TCP/UDP/ICMP；验证：L5超时和状态迁移闭环",
                "强制192.168.148.2经192.168.148.1；检查ESTABLISHED=600、UDP=5、UDP stream=30、ICMP=5及到期消亡",
            ):
                l5 = ssh_verify(
                    "L5-ens11真实连接跟踪闭环",
                    backend.run_kernel_conntrack_probe,
                    ports,
                )
                l5_details = dict(getattr(l5, "details", {}) or {})
                ui_check(
                    "L5三端finally清理完成",
                    all((l5_details.get("cleanup") or {}).values()),
                    l5_details.get("cleanup"),
                )
                ssh_verify("L4-L5后路径健康", backend.verify_kernel_path_health)

            maximum_form = {"bbr": False}
            maximum_form.update({
                name: bounds[1] for name, bounds in page.FIELD_RANGES.items()
            })
            with rec.step(
                "步骤5 操作：通过页面保存全部最大边界并关闭BBR；验证：DB、全部/proc和cubic无截断或溢出",
                "覆盖60/86400/1800/100等字段独立上限并执行产品init重建",
            ):
                save_valid(maximum_form, "最大边界+BBR关闭")
                ssh_verify("L1-最大边界数据库", backend.verify_kernel_database, to_expected(maximum_form))
                ssh_verify("L2/L3-最大边界运行态", backend.verify_kernel_runtime, to_expected(maximum_form))
                ssh_verify("L4-最大边界脚本重建", backend.verify_kernel_reinit, to_expected(maximum_form))

            with rec.step(
                "步骤6 操作：逐字段提交低于下限和高于上限；验证：前端拒绝且不发送成功save、不污染DB或运行态",
                "覆盖11个超时字段共22个越界值，另测空值和非数字；每轮从最大边界刷新开始",
            ):
                for name, (minimum, maximum) in page.FIELD_RANGES.items():
                    for side, bad_value in (("低于下限", minimum - 1), ("高于上限", maximum + 1)):
                        page.navigate_to_kernel_setting()
                        rejected = page.save_config({name: bad_value}, timeout=1800)
                        ui_check(
                            f"{name}-{side}-页面拒绝",
                            not rejected.get("saved")
                            and not rejected.get("api_success")
                            and (
                                bool(rejected.get("validation_errors"))
                                or not rejected.get("request_seen")
                            ),
                            rejected,
                        )
                for label, bad_value in (("空值", ""), ("非数字", "abc")):
                    page.navigate_to_kernel_setting()
                    rejected = page.save_config(
                        {"syn_send_timeout": bad_value}, timeout=1800
                    )
                    ui_check(
                        f"syn_send_timeout-{label}-页面拒绝",
                        not rejected.get("saved")
                        and not rejected.get("api_success")
                        and (
                            bool(rejected.get("validation_errors"))
                            or not rejected.get("request_seen")
                        ),
                        rejected,
                    )
                ssh_verify("L1-前端非法矩阵后DB未变", backend.verify_kernel_database, to_expected(maximum_form))
                ssh_verify("L2/L3-前端非法矩阵后运行态未变", backend.verify_kernel_runtime, to_expected(maximum_form))

            with rec.step(
                "步骤7 操作：绕过表单提交缺字段、越界和未知字段；验证：ik_sysctl后端强制拒绝且状态不变",
                "使用同一登录会话直接调用save，证明安全边界不只依赖前端校验",
            ):
                valid_param = to_expected(maximum_form)
                missing_param = dict(valid_param)
                missing_param.pop("icmp_timeout")
                missing_result = page.api_save(missing_param)
                ui_check(
                    "API缺必填字段被拒绝",
                    int(missing_result.get("code", 0)) != 0,
                    missing_result,
                )
                out_of_range = dict(valid_param)
                out_of_range["udp_timeout"] = 61
                range_result = page.api_save(out_of_range)
                ui_check(
                    "API越界字段被拒绝",
                    int(range_result.get("code", 0)) != 0,
                    range_result,
                )
                unknown = dict(valid_param)
                unknown["unexpected_kernel_param"] = 1
                unknown_result = page.api_save(unknown)
                ui_check(
                    "API未知字段被拒绝",
                    int(unknown_result.get("code", 0)) != 0,
                    unknown_result,
                )
                ssh_verify("L1-API非法矩阵后DB未变", backend.verify_kernel_database, valid_param)
                ssh_verify("L2/L3-API非法矩阵后运行态未变", backend.verify_kernel_runtime, valid_param)

            with rec.step(
                "步骤8 操作：点击恢复默认配置并二次确认；验证：default动作、UI、L1-L4和默认值完整一致",
                "验证页面调用ik_sysctl/default而非仅回填表单，默认值与脚本default()逐字段一致",
            ):
                mutation_started = True
                page.navigate_to_kernel_setting()
                default_result = page.restore_defaults()
                ui_check("默认恢复二次确认和API成功", default_result.get("saved"), default_result)
                default_expected = to_expected(page.DEFAULTS)
                ssh_verify("L1-默认配置数据库", backend.verify_kernel_database, default_expected)
                ssh_verify("L2/L3-默认配置运行态", backend.verify_kernel_runtime, default_expected)
                ssh_verify("L4-默认配置脚本重建", backend.verify_kernel_reinit, default_expected)
                ssh_verify("L4-默认恢复后路径健康", backend.verify_kernel_path_health)

            with rec.step(
                "步骤9 操作：打开内核设置帮助并关闭；验证：主题匹配且无孤儿窗口或遮罩",
                "帮助内容应包含内核/TCP主题，关闭后页面可继续操作",
            ):
                page.navigate_to_kernel_setting()
                help_result = page.verify_help_entry(("内核", "TCP"))
                ui_check("帮助已打开", help_result.get("opened"), help_result)
                ui_check("帮助主题匹配", help_result.get("all_keywords_matched"), help_result)
                ui_check(
                    "帮助已关闭且无孤儿页",
                    help_result.get("closed") and help_result.get("no_orphan"),
                    help_result,
                )

            with rec.step(
                "步骤10 操作：通过页面恢复测试前内核配置；验证：UI、L1-L4、ens11路由及三端环境回到快照",
                "恢复后独立检查配置、全部/proc值、路径、临时文件、进程和客户端精确路由",
            ):
                baseline_form = to_form(snapshot["row"])
                save_valid(baseline_form, "页面恢复测试前配置")
                ssh_verify(
                    "L4-页面恢复后环境一致",
                    backend.verify_kernel_environment_unchanged,
                    snapshot,
                    cleanup=True,
                )

        except Exception as exc:
            unexpected_error = f"{type(exc).__name__}: {str(exc)[:220]}"
            fail("内核设置综合流程异常", unexpected_error)
        finally:
            if snapshot_valid and snapshot is not None:
                restored = ssh_verify(
                    "finally-精确恢复内核设置快照",
                    backend.restore_kernel_environment,
                    snapshot,
                    must_pass=True,
                    cleanup=True,
                )
                if restored is None or not getattr(restored, "passed", False):
                    cleanup_failures.append("finally精确恢复失败")
                final_audit = ssh_verify(
                    "finally-恢复后独立残留审计",
                    backend.verify_kernel_environment_unchanged,
                    snapshot,
                    must_pass=True,
                    cleanup=True,
                )
                if final_audit is None or not getattr(final_audit, "passed", False):
                    cleanup_failures.append("finally独立残留审计失败")
                try:
                    page.navigate_to_kernel_setting()
                    final_form = page.get_config()
                    if not state_matches(final_form, to_form(snapshot["row"])):
                        cleanup_failures.append("finally页面回显与快照不一致")
                        section("清理结果", "失败", "finally页面回显", final_form)
                    else:
                        section("清理结果", "通过", "finally页面回显", "十二字段与快照一致")
                except Exception as exc:
                    cleanup_failures.append(f"finally页面复验异常({type(exc).__name__})")
            elif mutation_started:
                cleanup_failures.append("已开始修改但无有效内核设置快照，无法安全恢复")

        all_failures = failures + cleanup_failures
        if unexpected_error:
            print(f"[内核设置异常] {unexpected_error}")
        if all_failures:
            print(f"[内核设置断言] 共{len(all_failures)}项失败")
            for item in all_failures:
                print(f"  - {item}")
        assert not all_failures, (
            f"内核设置L1-L5综合验证失败({len(all_failures)}项): "
            + "; ".join(all_failures[:28])
        )
