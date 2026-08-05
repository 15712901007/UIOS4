"""自定义协议(L4/L7)真实流量功能测试。

综合测试覆盖页面 CRUD 和数据库/静态运行状态；本文件补充真正的数据面验证：
L4 检查 DPROTO 规则计数，L7 发送唯一 TCP 载荷并核对 DPI appid 命中，同时
验证停用和重新启用后的正反行为。
"""

import re
import shlex
from urllib.parse import urlparse

import pytest

from pages.network.custom_protocol_page import (
    AdvancedCustomProtocolPage,
    CustomProtocolPage,
)
from utils.backend_verifier import BackendVerifier
from utils.step_recorder import StepRecorder


pytestmark = [pytest.mark.network, pytest.mark.custom_protocol, pytest.mark.p0]

PREFIX = "DPFLOW_"
RULE_NAME = f"{PREFIX}TCP_5201"
TARGET_PORT = 5201

ADVANCED_PREFIX = "ADVFLOW_"
ADVANCED_RULE_NAME = f"{ADVANCED_PREFIX}TCP"
ADVANCED_TOKEN = "IKADVFLOWTOKEN"
ADVANCED_RULE = f"Protocol=TCP Direction=CLIENT Data={ADVANCED_TOKEN}"


def _read_dproto_counter(verifier: BackendVerifier, rule_id: int):
    """读取 DPROTO 链中属于一个数据库规则的所有 iptables 计数。"""
    verifier.connect_router()
    output = verifier._router.exec(
        "iptables -t mangle -L DPROTO -n -v -x --line-numbers 2>/dev/null"
    ) or ""
    pattern = re.compile(rf"dproto_(?:src|dst|sport|dport)_{int(rule_id)}\b")
    total = 0
    matched_lines = []
    for line in output.splitlines():
        if not pattern.search(line):
            continue
        matched_lines.append(line.strip())
        fields = line.split()
        # --line-numbers 输出: num pkts bytes target ...
        if len(fields) >= 3 and fields[0].isdigit() and fields[1].isdigit():
            total += int(fields[1])
    return total, matched_lines


class TestCustomProtocolFunctional:
    """L4 自定义协议配置、命中、停用和恢复的端到端验证。"""

    def test_custom_protocol_real_tcp_flow(
        self,
        custom_protocol_page_logged_in: CustomProtocolPage,
        acl_flow_env: BackendVerifier,
        step_recorder: StepRecorder,
    ):
        page = custom_protocol_page_logged_in
        verifier = acl_flow_env
        rec = step_recorder
        failures = []
        server_ip = str(verifier._ssh_config.iperf3_server)
        client_ip = verifier.get_client_lan_info().get("ip") or "192.168.148.2"

        def record(label, passed, detail=""):
            status = "[OK]" if passed else "[FAIL]"
            message = f"{label}: {status}"
            if detail:
                message += f" {detail}"
            print(f"  {message}", flush=True)
            rec.add_detail(f"  {message}")
            if not passed:
                failures.append(f"{label}: {detail or '不符合预期'}")
            return passed

        def run_tcp_flow(stage, expect_hit):
            """清理旧连接后打一个新 TCP 流，并核对 DPROTO 计数增量。"""
            rule = verifier.find_dproto(RULE_NAME, "l4")
            if not rule:
                record(f"{stage}规则读取", False, "数据库中找不到测试规则")
                return None
            rule_id = int(rule["id"])
            before, lines_before = _read_dproto_counter(verifier, rule_id)
            verifier.clear_client_conntrack(client_ip)
            result = verifier.run_iperf3(
                direction="upload",
                server_ip=server_ip,
                bind_ip=client_ip,
                duration=2,
                port=TARGET_PORT,
                retries=1,
            )
            after = before
            lines_after = []
            for _ in range(12):
                after, lines_after = _read_dproto_counter(verifier, rule_id)
                if (after > before) == expect_hit:
                    break
                page.page.wait_for_timeout(250)
            delta = after - before
            flow_ok = not result.get("error") and bool(result.get("end"))
            hit_ok = delta > 0 if expect_hit else delta == 0
            record(
                f"{stage}真实TCP流",
                flow_ok,
                f"server={server_ip}:{TARGET_PORT}, result={str(result)[:220]}",
            )
            record(
                f"{stage}DPROTO命中",
                hit_ok,
                f"pkts_before={before}, pkts_after={after}, delta={delta}",
            )
            rec.add_detail(
                f"  {stage}规则行(before/after): "
                f"{lines_before[:2]} / {lines_after[:2]}"
            )
            return {"flow_ok": flow_ok, "hit_ok": hit_ok, "delta": delta}

        try:
            with rec.step("步骤1: 清理测试规则", "清理 DPFLOW_ 残留并确认页面可用"):
                verifier.cleanup_dproto_test(prefix=PREFIX)
                page.navigate_to_custom_protocol()
                page.page.wait_for_timeout(800)
                record("页面导航", page._is_tab_active("自定义协议"), page.page.url)

            with rec.step(
                "步骤2: 创建 TCP 自定义协议",
                f"匹配目的 {server_ip}:{TARGET_PORT}，验证数据库和后端链路",
            ):
                added = page.add_rule(
                    name=RULE_NAME,
                    cls=0,
                    protocol="tcp",
                    dst_addr=server_ip,
                    dst_port=str(TARGET_PORT),
                    comment="真实TCP流量功能验证",
                )
                record("UI保存规则", added, RULE_NAME)
                page.page.wait_for_timeout(1500)
                db_result = verifier.verify_dproto_database(
                    RULE_NAME,
                    proto_type="l4",
                    expected_fields={
                        "enabled": "yes",
                        "class": "0",
                        "protocol": "tcp",
                        "dst_addr": server_ip,
                        "dst_port": str(TARGET_PORT),
                    },
                )
                record("数据库规则", db_result.passed, db_result.message)
                backend_result = verifier.verify_dproto_backend(RULE_NAME, "l4")
                record("DPROTO后端规则", backend_result.passed, backend_result.message)

            with rec.step(
                "步骤3: 启用状态命中验证",
                "内网客户端经 DUT 向 iperf3 服务端发起真实 TCP 流",
            ):
                run_tcp_flow("启用", expect_hit=True)

            with rec.step(
                "步骤4: 停用后不命中验证",
                "停用 UI 规则，建立新连接后 DPROTO 计数不得增长",
            ):
                page.navigate_to_custom_protocol()
                disabled = page.disable_rule(RULE_NAME)
                record("UI停用规则", disabled, RULE_NAME)
                page.page.wait_for_timeout(1500)
                db_result = verifier.verify_dproto_database(
                    RULE_NAME,
                    proto_type="l4",
                    expected_fields={"enabled": "no"},
                )
                record("停用状态入库", db_result.passed, db_result.message)
                run_tcp_flow("停用", expect_hit=False)

            with rec.step(
                "步骤5: 重新启用验证",
                "重新启用规则并确认新 TCP 连接再次命中",
            ):
                page.navigate_to_custom_protocol()
                enabled = page.enable_rule(RULE_NAME)
                record("UI重新启用规则", enabled, RULE_NAME)
                page.page.wait_for_timeout(1500)
                db_result = verifier.verify_dproto_database(
                    RULE_NAME,
                    proto_type="l4",
                    expected_fields={"enabled": "yes"},
                )
                record("重新启用状态入库", db_result.passed, db_result.message)
                run_tcp_flow("重新启用", expect_hit=True)
        finally:
            with rec.step("步骤6: 清理恢复", "删除 UI 规则并重建 DPROTO 后端"):
                try:
                    page.navigate_to_custom_protocol()
                    page.page.wait_for_timeout(500)
                    if page.rule_exists(RULE_NAME):
                        page.delete_rule(RULE_NAME)
                        page.page.wait_for_timeout(1000)
                except Exception as exc:
                    rec.add_detail(f"  UI清理异常: {str(exc)[:160]}")
                verifier.cleanup_dproto_test(prefix=PREFIX)
                residual = verifier.find_dproto(RULE_NAME, "l4")
                record("清理后无测试规则", residual is None, str(residual)[:160])

        assert not failures, f"自定义协议功能验证失败({len(failures)}项): {'; '.join(failures)}"


@pytest.mark.advanced_custom_protocol
class TestAdvancedCustomProtocolFunctional:
    """高级自定义协议配置、DPI命中、停用和恢复的端到端验证。"""

    def test_advanced_custom_protocol_real_l7_flow(
        self,
        advanced_custom_protocol_page_logged_in: AdvancedCustomProtocolPage,
        backend_verifier: BackendVerifier,
        step_recorder: StepRecorder,
    ):
        if backend_verifier is None:
            pytest.skip("paramiko未安装，跳过高级自定义协议真实流量验证")

        page = advanced_custom_protocol_page_logged_in
        verifier = backend_verifier
        rec = step_recorder
        failures = []

        def record(label, passed, detail=""):
            status = "[OK]" if passed else "[FAIL]"
            message = f"{label}: {status}"
            if detail:
                message += f" {detail}"
            print(f"  {message}", flush=True)
            rec.add_detail(f"  {message}")
            if not passed:
                failures.append(f"{label}: {detail or '不符合预期'}")
            return passed

        def record_result(label, result):
            record(label, result.passed, result.message)
            if result.raw_output:
                rec.add_detail(f"    {label}证据: {result.raw_output[:1800]}")
            return result

        def wait_runtime(expect_enabled):
            result = None
            for _ in range(20):
                result = verifier.verify_dproto_l7_runtime(
                    ADVANCED_RULE_NAME, expect_enabled=expect_enabled
                )
                if result.passed:
                    return result
                page.page.wait_for_timeout(500)
            return result

        try:
            with rec.step(
                "步骤1: 核对设备并清理测试规则",
                "确认GUI与SSH指向同一设备，清理ADVFLOW_唯一前缀残留",
            ):
                verifier.connect_router()
                web_host = urlparse(page.base_url).hostname or ""
                ssh_host = str(verifier._ssh_config.router.host or "")
                record(
                    "GUI/SSH设备一致",
                    bool(web_host and web_host == ssh_host),
                    f"web={web_host}, ssh={ssh_host}",
                )
                verifier.cleanup_dproto_test(prefix=ADVANCED_PREFIX)
                page.navigate_to_advanced_custom_protocol()
                page.page.wait_for_timeout(800)
                record(
                    "高级自定义协议页签",
                    page._is_tab_active("高级自定义协议"),
                    page.page.url,
                )

            with rec.step(
                "步骤2: 创建高级TCP特征规则",
                "通过GUI保存规则，并验证数据库、规则解码和user_dpi装载",
            ):
                added = page.add_rule(
                    name=ADVANCED_RULE_NAME,
                    rule=ADVANCED_RULE,
                    cls=0,
                    comment="真实L7载荷功能验证",
                )
                record("UI保存高级规则", added, ADVANCED_RULE_NAME)
                page.page.wait_for_timeout(1500)
                db_result = verifier.verify_dproto_database(
                    ADVANCED_RULE_NAME,
                    proto_type="l7",
                    expected_fields={"enabled": "yes", "class": "0"},
                )
                record_result("L1数据库", db_result)
                decoded_result = verifier.verify_dproto_backend(
                    ADVANCED_RULE_NAME,
                    proto_type="l7",
                    expected_rule=ADVANCED_RULE,
                )
                record_result("L2规则解码", decoded_result)
                record_result("L3 DPI装载", wait_runtime(expect_enabled=True))

            with rec.step(
                "步骤3: 启用状态真实载荷命中",
                "清空DPI缓存后经DUT发送唯一特征串，必须新生成目标appid",
            ):
                result = verifier.run_dproto_l7_tcp_probe(
                    ADVANCED_RULE_NAME, ADVANCED_TOKEN, expect_hit=True
                )
                record_result("启用状态L5真实TCP流", result)

            with rec.step(
                "步骤4: 停用后不再识别",
                "通过GUI停用规则，新TCP连接仍应转发但不得产生目标appid命中",
            ):
                page.navigate_to_advanced_custom_protocol()
                disabled = page.disable_rule(ADVANCED_RULE_NAME)
                record("UI停用高级规则", disabled, ADVANCED_RULE_NAME)
                page.page.wait_for_timeout(1000)
                record_result(
                    "停用状态入库",
                    verifier.verify_dproto_database(
                        ADVANCED_RULE_NAME,
                        proto_type="l7",
                        expected_fields={"enabled": "no"},
                    ),
                )
                record_result("停用后DPI卸载", wait_runtime(expect_enabled=False))
                result = verifier.run_dproto_l7_tcp_probe(
                    ADVANCED_RULE_NAME, ADVANCED_TOKEN, expect_hit=False
                )
                record_result("停用状态L5反向对照", result)

            with rec.step(
                "步骤5: 重新启用后恢复识别",
                "通过GUI重新启用规则，新TCP连接必须再次命中目标appid",
            ):
                page.navigate_to_advanced_custom_protocol()
                enabled = page.enable_rule(ADVANCED_RULE_NAME)
                record("UI重新启用高级规则", enabled, ADVANCED_RULE_NAME)
                page.page.wait_for_timeout(1000)
                record_result(
                    "重新启用状态入库",
                    verifier.verify_dproto_database(
                        ADVANCED_RULE_NAME,
                        proto_type="l7",
                        expected_fields={"enabled": "yes"},
                    ),
                )
                record_result("重新启用DPI装载", wait_runtime(expect_enabled=True))
                result = verifier.run_dproto_l7_tcp_probe(
                    ADVANCED_RULE_NAME, ADVANCED_TOKEN, expect_hit=True
                )
                record_result("重新启用L5真实TCP流", result)
        finally:
            with rec.step(
                "步骤6: 清理并恢复环境",
                "删除ADVFLOW_规则并重新加载DPI，探针负责恢复客户端原路由",
            ):
                try:
                    page.navigate_to_advanced_custom_protocol()
                    page.page.wait_for_timeout(500)
                    if page.rule_exists(ADVANCED_RULE_NAME):
                        page.delete_rule(ADVANCED_RULE_NAME)
                        page.page.wait_for_timeout(1000)
                except Exception as exc:
                    rec.add_detail(f"  UI清理异常: {str(exc)[:160]}")
                verifier.cleanup_dproto_test(prefix=ADVANCED_PREFIX)
                verifier._router.exec("ik_cntl cache clean 2>&1")
                residual = verifier.find_dproto(ADVANCED_RULE_NAME, "l7")
                record("清理后无高级测试规则", residual is None, str(residual)[:160])
                target_host = str(verifier._ssh_config.iperf3_server or "")
                target_cache = verifier._router.exec(
                    "cat /proc/ikuai/dpi/dpi_cache 2>/dev/null | "
                    f"grep -F {shlex.quote(target_host)} | "
                    "grep -E '[[:space:]]5201[[:space:]]'"
                ).strip()
                record("清理后无测试DPI缓存", not target_cache, target_cache[:160])

        assert not failures, (
            f"高级自定义协议功能验证失败({len(failures)}项): "
            f"{'; '.join(failures)}"
        )
