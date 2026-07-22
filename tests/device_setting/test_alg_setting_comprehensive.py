"""设备设置 > 高级管理 > ALG设置 L1-L5 单节点综合测试。

底层脚本为 ``/usr/ikuai/script/alg.sh``。L5 使用测试客户端
``10.66.0.18`` 上的 ``192.168.148.2``，强制经 ``192.168.148.1``
进入被测路由器，再连接 WAN 对端最小 FTP 服务；验证 PORT 载荷改写、
conntrack helper、expectation 和主动数据通道，并以关闭 FTP ALG 为反向控制。
"""

from __future__ import annotations

import itertools
from typing import Any, Callable, Dict, List, Optional

import pytest

from pages.device_setting.alg_setting_page import AlgSettingPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.device_setting, pytest.mark.alg_setting]


class TestAlgSettingComprehensive:
    """ALG 页面、数据库、内核模块、脚本重建和真实协议综合验证。"""

    def test_alg_setting_comprehensive(
        self,
        alg_setting_page_logged_in: AlgSettingPage,
        step_recorder: StepRecorder,
        request,
    ):
        page = alg_setting_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("ALG L1-L5综合测试必须启用SSH backend_verifier")

        failures: List[str] = []
        cleanup_failures: List[str] = []
        snapshot: Optional[Dict[str, Any]] = None
        snapshot_valid = False
        mutation_started = False
        candidate_ports: List[int] = []
        unexpected_error: Optional[str] = None
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
            section("页面验证", "通过" if passed else "失败", label,
                    "符合预期" if passed else detail)
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
                target_section = (
                    "清理结果" if cleanup else
                    "协议验证" if label.startswith("L5") else
                    "运行时验证" if label.startswith(("L2", "L3", "L4")) else
                    "后端验证"
                )
                section(target_section, "通过" if passed else "失败", label, message)
                raw = getattr(result, "raw_output", "")
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

        def to_form(row: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "support_ftp": bool(int(row.get("support_ftp", 0))),
                "support_tftp": bool(int(row.get("support_tftp", 0))),
                "support_sip": bool(int(row.get("support_sip", 0))),
                "support_h323": bool(int(row.get("support_h323", 0))),
                "ftp_ports": str(row.get("ftp_ports") or ""),
                "tftp_ports": str(row.get("tftp_ports") or ""),
                "sip_ports": str(row.get("sip_ports") or ""),
            }

        def to_expected(form: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "support_ftp": int(bool(form["support_ftp"])),
                "support_tftp": int(bool(form["support_tftp"])),
                "support_sip": int(bool(form["support_sip"])),
                "support_h323": int(bool(form["support_h323"])),
                "ftp_ports": str(form.get("ftp_ports") or ""),
                "tftp_ports": str(form.get("tftp_ports") or ""),
                "sip_ports": str(form.get("sip_ports") or ""),
            }

        def state_matches(actual: Dict[str, Any], expected: Dict[str, Any]) -> bool:
            return all(actual.get(name) == expected.get(name) for name in page.FIELD_NAMES)

        def save_valid(values: Dict[str, Any], label: str) -> Dict[str, Any]:
            nonlocal mutation_started
            mutation_started = True
            page.navigate_to_alg_setting()
            result = page.save_config(values)
            ui_check(f"{label}-保存API成功", result.get("saved"), result)
            if result.get("saved"):
                page.navigate_to_alg_setting()
                ui_check(
                    f"{label}-页面回显",
                    state_matches(page.get_config(), values),
                    {"actual": page.get_config(), "expected": values},
                )
            guard_nat(f"保存后-{label}")
            return result

        def verify_runtime(label: str, form: Dict[str, Any]):
            return ssh_verify(
                label, backend.verify_alg_runtime_consistency, to_expected(form)
            )

        def guard_nat(label: str, *, cleanup: bool = False,
                      repair_if_failed: bool = True) -> bool:
            """每次ALG运行态变更后实测LAN SNAT，失败时立即恢复AUTONAT。"""
            health = ssh_verify(
                f"L4-NAT守护-{label}",
                backend.verify_alg_nat_health,
                must_pass=False,
                cleanup=cleanup,
            )
            if health is not None and getattr(health, "passed", False):
                return True

            if label not in nat_failure_triggers:
                nat_failure_triggers.add(label)
                detail = str(getattr(health, "message", "NAT健康探测异常"))
                fail(f"ALG触发LAN断网-{label}", detail, cleanup=cleanup)

            if not repair_if_failed:
                return False

            repaired = ssh_verify(
                f"L4-NAT自动恢复-{label}",
                backend.repair_alg_nat_runtime,
                must_pass=True,
                cleanup=cleanup,
            )
            repaired_ok = bool(repaired is not None and getattr(repaired, "passed", False))
            if not repaired_ok and not cleanup:
                raise RuntimeError(f"{label}后AUTONAT自动恢复失败，已停止后续ALG变更")
            return repaired_ok

        try:
            with rec.step(
                "步骤1 操作：保存全环境快照并识别ALG单例页面；验证：页面能力、脚本/API/表结构和候选端口",
                "操作：只读读取alg_config、模块参数及测试支撑拓扑；验证：四开关三端口字段、保存和帮助存在，列表型能力明确不适用",
            ):
                snapshot = backend.get_alg_environment_snapshot()
                snapshot_valid = bool(
                    snapshot.get("version") == 1
                    and snapshot.get("row", {}).get("id") == 1
                    and snapshot.get("nat_health_passed") is True
                    and not snapshot.get("router_artifacts")
                    and not snapshot.get("client_artifacts")
                    and not snapshot.get("peer_artifacts")
                    and not snapshot.get("peer_firewall")
                    and not snapshot.get("router_firewall")
                    and not snapshot.get("client_peer_test_route")
                    and not snapshot.get("router_peer_test_route")
                    and not snapshot.get("peer_test_ip")
                )
                ui_check("ALG全环境快照完整且无既有测试残留", snapshot_valid, snapshot)
                candidate_ports = backend.choose_alg_candidate_ports(14)
                ui_check(
                    "14个动态候选端口唯一且合法",
                    len(candidate_ports) == 14
                    and len(set(candidate_ports)) == 14
                    and all(1024 <= port <= 65535 for port in candidate_ports),
                    candidate_ports,
                )
                ui_check("ALG页面导航成功", page.is_on_alg_setting_page(), page.page.url)
                structure = page.get_page_structure()
                ui_check(
                    "四协议开关和三端口字段完整",
                    all(item.get("present") for item in structure["fields"].values()),
                    structure,
                )
                ui_check("保存和帮助入口存在", structure["save_present"] and structure["help_present"])
                capabilities = page.get_capability_matrix()
                ui_check(
                    "单例能力如实建模",
                    capabilities["singleton_configuration_edit"]["supported"]
                    and capabilities["save"]["supported"]
                    and capabilities["help"]["supported"],
                    capabilities,
                )
                ui_check(
                    "列表/搜索/批量/导入导出/排序分页均不适用",
                    all(
                        not capabilities[name]["supported"]
                        for name in (
                            "search", "add_record", "edit_record", "delete_record",
                            "batch_operation", "import", "export", "sort", "pagination",
                        )
                    ),
                    capabilities,
                )
                ssh_verify("L1/L4-脚本和单例契约", backend.verify_alg_script_contract)

            if not snapshot_valid:
                pytest.fail("ALG环境快照无效，禁止开始持久化操作")

            baseline_form = to_form(snapshot["row"])
            control_port, tftp_port, sip_port, data_port = candidate_ports[:4]
            enabled_form = {
                "support_ftp": True,
                "support_tftp": True,
                "support_sip": True,
                "support_h323": True,
                "ftp_ports": str(control_port),
                "tftp_ports": str(tftp_port),
                "sip_ports": str(sip_port),
            }

            with rec.step(
                "步骤2 操作：核对测试前页面回显；验证：UI、L1数据库和L2-L4运行态完全一致",
                "操作：重新进入ALG页读取七个字段；验证：原始值未被探查过程改变",
            ):
                page.navigate_to_alg_setting()
                ui_check("测试前页面回显等于快照", state_matches(page.get_config(), baseline_form), {
                    "actual": page.get_config(), "expected": baseline_form,
                })
                verify_runtime("L4-测试前全链路", baseline_form)

            with rec.step(
                "步骤3 操作：关闭全部ALG协议；验证：L1四开关为0、L2八个内核模块卸载、L3端口参数消失",
                "操作：通过页面关闭FTP/TFTP/SIP/H323并保存；验证：不存在仅改DB未卸模块的假关闭",
            ):
                off_form = {
                    "support_ftp": False, "support_tftp": False,
                    "support_sip": False, "support_h323": False,
                    "ftp_ports": "", "tftp_ports": "", "sip_ports": "",
                }
                save_valid(off_form, "全部关闭")
                verify_runtime("L4-全部关闭全链路", off_form)

            with rec.step(
                "步骤4 操作：逐一隔离启用FTP/TFTP/SIP/H323；验证：每次仅目标conntrack/nat模块加载且自定义+标准端口正确",
                "操作：四次页面保存分别只开一个协议；验证：协议之间无模块串扰",
            ):
                isolated = (
                    ("FTP", "support_ftp", "ftp_ports", control_port),
                    ("TFTP", "support_tftp", "tftp_ports", tftp_port),
                    ("SIP", "support_sip", "sip_ports", sip_port),
                    ("H323", "support_h323", None, None),
                )
                for protocol, flag, port_field, port in isolated:
                    form = {
                        "support_ftp": False, "support_tftp": False,
                        "support_sip": False, "support_h323": False,
                        "ftp_ports": "", "tftp_ports": "", "sip_ports": "",
                    }
                    form[flag] = True
                    if port_field:
                        form[port_field] = str(port)
                    save_valid(form, f"仅启用{protocol}")
                    verify_runtime(f"L4-{protocol}隔离运行态", form)

            with rec.step(
                "步骤5 操作：保存四协议全开和三类非标准端口；验证：L1-L4及alg.sh init后全链路一致",
                "操作：FTP/TFTP/SIP各配置一个动态空闲端口，H323开启；验证：标准端口自动追加且脚本重载不丢配置",
            ):
                save_valid(enabled_form, "全开+非标准端口")
                verify_runtime("L4-全开自定义端口", enabled_form)
                ssh_verify("L4-alg.sh init重建", backend.verify_alg_reinit, to_expected(enabled_form))
                guard_nat("alg.sh init后")

            with rec.step(
                "步骤6 操作：从192.168.148.2执行FTP ALG真实主动模式；验证：PORT改写、helper、expectation和数据通道",
                "操作：客户端强制经192.168.148.1连接WAN对端；验证：对端收到10.66.0.150载荷且主动数据回连到客户端",
            ):
                ssh_verify(
                    "L5-FTP ALG启用正向闭环",
                    backend.run_alg_ftp_probe,
                    control_port,
                    data_port,
                    True,
                )
                guard_nat("FTP ALG启用L5后")

            with rec.step(
                "步骤7 操作：仅关闭FTP ALG并重复同一真实协议；验证：控制连接仍通但不改写、无helper/expectation、数据通道拒绝",
                "操作：保留TFTP/SIP/H323及端口配置，仅关闭FTP开关；验证：关闭前后差异来自ALG而非基础NAT或测试服务",
            ):
                disabled_ftp_form = dict(enabled_form)
                disabled_ftp_form["support_ftp"] = False
                save_valid(disabled_ftp_form, "仅关闭FTP ALG")
                verify_runtime("L4-FTP关闭运行态", disabled_ftp_form)
                ssh_verify(
                    "L5-FTP ALG关闭反向控制",
                    backend.run_alg_ftp_probe,
                    control_port,
                    data_port,
                    False,
                )
                guard_nat("FTP ALG关闭L5后")
                save_valid(enabled_form, "重新启用FTP ALG")
                verify_runtime("L4-FTP重新启用", enabled_form)

            with rec.step(
                "步骤8 操作：遍历四协议16种开关组合；验证：每次UI回显、L1数据库、L2模块和L3端口均一致",
                "操作：从0000到1111逐组合保存；验证：任意组合不存在模块漏卸载、误加载或端口串协议",
            ):
                for bits in itertools.product((False, True), repeat=4):
                    matrix_form = {
                        "support_ftp": bits[0], "support_tftp": bits[1],
                        "support_sip": bits[2], "support_h323": bits[3],
                        "ftp_ports": str(control_port),
                        "tftp_ports": str(tftp_port),
                        "sip_ports": str(sip_port),
                    }
                    label = "".join("1" if bit else "0" for bit in bits)
                    save_valid(matrix_form, f"开关组合{label}")
                    verify_runtime(f"L4-开关组合{label}", matrix_form)

            with rec.step(
                "步骤9 操作：验证每协议7个非标准端口上限；验证：L1字符串和L3八端口参数（7自定义+标准端口）完整",
                "操作：FTP写入7个互异动态端口并保存；验证：无截断、无重排、标准21端口仍自动追加",
            ):
                seven_ports = candidate_ports[4:11]
                boundary_form = dict(enabled_form)
                boundary_form.update({
                    "ftp_ports": ",".join(str(port) for port in seven_ports),
                    "tftp_ports": str(tftp_port),
                    "sip_ports": str(sip_port),
                })
                save_valid(boundary_form, "FTP七端口边界")
                verify_runtime("L4-FTP七端口边界", boundary_form)

            with rec.step(
                "步骤10 操作：提交8端口、同协议重复、0/65536/字母/空项；验证：前端明确拒绝且DB和运行态不变",
                "操作：每种非法值独立从合法边界状态开始提交；验证：不发送成功save、不污染已生效配置",
            ):
                invalid_values = (
                    ("8个端口", ",".join(str(port) for port in candidate_ports[4:12])),
                    ("同协议重复", f"{candidate_ports[4]},{candidate_ports[4]}"),
                    ("端口0", "0"),
                    ("端口65536", "65536"),
                    ("字母端口", "abc"),
                    ("空端口项", f"{candidate_ports[4]},,{candidate_ports[5]}"),
                )
                for label, bad_value in invalid_values:
                    page.navigate_to_alg_setting()
                    rejected = page.save_config({"ftp_ports": bad_value})
                    ui_check(
                        f"{label}-页面拒绝",
                        not rejected.get("saved")
                        and bool(rejected.get("validation_errors"))
                        and not rejected.get("api_success"),
                        rejected,
                    )
                    ssh_verify(
                        f"L1-{label}后DB未变",
                        backend.verify_alg_database,
                        to_expected(boundary_form),
                    )
                    verify_runtime(f"L4-{label}后运行态未变", boundary_form)

            with rec.step(
                "步骤11 操作：提交FTP/TFTP跨协议重复端口；验证：后端alg.sh返回字段级错误且DB/模块参数不变",
                "操作：两个字段各自格式合法但使用同一端口；验证：前端确实发save、后端拒绝并映射错误反馈",
            ):
                duplicate = candidate_ports[12]
                page.navigate_to_alg_setting()
                cross_result = page.save_config({
                    "ftp_ports": str(duplicate),
                    "tftp_ports": str(duplicate),
                })
                ui_check(
                    "跨协议重复-后端拒绝",
                    cross_result.get("request_seen")
                    and cross_result.get("response_seen")
                    and not cross_result.get("api_success")
                    and not cross_result.get("saved"),
                    cross_result,
                )
                ui_check(
                    "跨协议重复-字段级反馈",
                    bool(cross_result.get("validation_errors")),
                    cross_result,
                )
                ssh_verify(
                    "L1-跨协议重复后DB未变",
                    backend.verify_alg_database,
                    to_expected(boundary_form),
                )
                verify_runtime("L4-跨协议重复后运行态未变", boundary_form)

            with rec.step(
                "步骤12 操作：打开ALG帮助并关闭；验证：主题匹配且无孤儿窗口",
                "操作：点击页面帮助入口；验证：内容包含ALG/FTP主题并关闭popup或页内帮助层",
            ):
                page.navigate_to_alg_setting()
                help_result = page.verify_help_entry(("ALG", "FTP"))
                ui_check("帮助已打开", help_result.get("opened"), help_result)
                ui_check("帮助主题匹配", help_result.get("all_keywords_matched"), help_result)
                ui_check(
                    "帮助已关闭且无孤儿页",
                    help_result.get("closed") and help_result.get("no_orphan"),
                    help_result,
                )

            with rec.step(
                "步骤13 操作：通过页面恢复测试前ALG配置；验证：UI回显、L1-L4和辅助拓扑均回到快照",
                "操作：保存快照中的四开关三端口值；验证：无临时路由、进程、文件、对端防火墙和conntrack测试残留",
            ):
                save_valid(baseline_form, "页面恢复测试前配置")
                ssh_verify(
                    "L4-页面恢复后全环境一致",
                    backend.verify_alg_environment_unchanged,
                    snapshot,
                    cleanup=True,
                )

        except Exception as exc:
            unexpected_error = f"{type(exc).__name__}: {str(exc)[:180]}"
            fail("ALG综合流程异常", unexpected_error)
        finally:
            if snapshot_valid and snapshot is not None:
                restore = ssh_verify(
                    "finally-精确恢复ALG快照",
                    backend.restore_alg_environment,
                    snapshot,
                    must_pass=True,
                    cleanup=True,
                )
                if restore is None or not getattr(restore, "passed", False):
                    cleanup_failures.append("finally精确恢复失败")
                guard_nat("finally恢复后", cleanup=True)
                final_audit = ssh_verify(
                    "finally-恢复后独立残留审计",
                    backend.verify_alg_environment_unchanged,
                    snapshot,
                    must_pass=True,
                    cleanup=True,
                )
                if final_audit is None or not getattr(final_audit, "passed", False):
                    cleanup_failures.append("finally独立残留审计失败")
                try:
                    page.navigate_to_alg_setting()
                    final_form = page.get_config()
                    if not state_matches(final_form, to_form(snapshot["row"])):
                        cleanup_failures.append("finally页面回显与快照不一致")
                        section("清理结果", "失败", "finally页面回显", final_form)
                    else:
                        section("清理结果", "通过", "finally页面回显", "七字段与快照一致")
                except Exception as exc:
                    cleanup_failures.append(f"finally页面复验异常({type(exc).__name__})")
            elif mutation_started:
                cleanup_failures.append("已开始修改但无有效ALG快照，无法安全恢复")

            if not snapshot_valid:
                guard_nat(
                    "finally无有效快照复核",
                    cleanup=True,
                    repair_if_failed=mutation_started,
                )

        all_failures = failures + cleanup_failures
        if unexpected_error:
            print(f"[ALG异常] {unexpected_error}")
        if all_failures:
            print(f"[ALG断言] 共{len(all_failures)}项失败")
            for item in all_failures:
                print(f"  - {item}")
        assert not all_failures, (
            f"ALG设置L1-L5综合验证失败({len(all_failures)}项): "
            + "; ".join(all_failures[:20])
        )
