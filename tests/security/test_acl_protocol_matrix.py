"""ACL协议矩阵打流测试 (安全中心>ACL规则, P1) — 范本: 数据驱动parametrize

6协议全覆盖(any/tcp/udp/tcp+udp/icmp/gre), 补全旧用例缺失的tcp+udp和gre.
每协议=独立parametrize用例(单点失败不连坐, 报告可定位到具体协议):
  建规则(dst=10.66.0.40) → L2验-p落地 → L5打流验命中
  - tcp/udp: iperf3打流, drop=连接失败+Δpkts>0, accept=连通+Δpkts>0
  - tcp+udp杀手锏: 同端口分tcp/udp两段, 两段Δpkts都>0证ik_core多协议单规则双匹配
  - icmp: ping -I内网源替代iperf3
  - gre: 无对端隧道, 仅L2 -p落地(打流skip)
  - any: 不下发-p, 用tcp打流验(any规则必匹配tcp)

数据: test_data/acl/protocol_cases.yaml. 优先级: P1(功能层). 打流依赖: acl_flow_env fixture.
后端机制: acl.sh __format_set protocol!=any时PROTO="-p $protocol"; tcp+udp是ik_core定制多协议匹配.
"""
import pytest

from tests.security.acl_test_data import load_acl_cases
from utils.step_recorder import StepRecorder

# module级加载(parametrize收集期求值, fixture此时不存在)
PROTOCOL_CASES = load_acl_cases("protocol_cases.yaml")

pytestmark = [pytest.mark.security, pytest.mark.acl, pytest.mark.p1]
PREFIX = "acl_pm_"  # protocol matrix


@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[c["id"] for c in PROTOCOL_CASES])
def test_acl_protocol_matrix(case, acl_page_logged_in, acl_flow_env,
                             step_recorder: StepRecorder, request):
    """单协议打流用例. 失败软收集+末尾硬断言(单协议FAIL不影响其他协议用例)."""
    page = acl_page_logged_in
    bv = acl_flow_env  # 已探活iperf3+加client路由
    rec = step_recorder
    proto = case["protocol"]
    action = case["action"]
    name = f"{PREFIX}{case['id']}"
    failures = []

    def ssh_verify(label, func, *args, must_pass=True, **kwargs):
        try:
            r = func(*args, **kwargs)
            rec.add_detail(f"[SSH-{label}] {'PASS' if r.passed else 'FAIL'}: {r.message}")
            rec.add_detail(f"    数据: {(r.raw_output or '')[:160]}")
            if must_pass and not r.passed:
                failures.append(f"{label}: {r.message}")
        except Exception as e:
            rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
            failures.append(f"{label}异常: {str(e)[:80]}")

    try:
        with rec.step(f"协议矩阵[{case['id']}]: {case['desc']}",
                      f"proto={proto} action={action}"):
            # 清残留(本用例+同名)
            page.navigate_to_acl()
            page.page.wait_for_timeout(800)
            page.clean_test_rules(PREFIX)
            if bv:
                bv.cleanup_acl_test(PREFIX)

            # 建规则(dst=10.66.0.40让打流命中; protocol=case协议)
            res = page.add_rule(name, action=action, protocol=proto,
                                dst_addrs=["10.66.0.40"])
            rec.add_detail(f"[UI] 建 {name} proto={proto} action={action}: "
                           f"{'成功' if res['success'] else '失败 ' + res.get('error', '')}")
            if not res["success"]:
                failures.append(f"建规则失败: {res.get('error', '')}")
            page.page.wait_for_timeout(1200)

            # L1: 数据库字段(protocol/action)
            ssh_verify(f"L1-DB-{proto}", bv.verify_acl_database, name,
                       expected_fields={"protocol": proto, "action": action})

            # L2: 验-p协议落地(any不下发-p, 方法内特殊处理返回通过)
            ssh_verify(f"L2-协议-{proto}", bv.verify_acl_protocol_iptables,
                       name, protocol=proto)

            # L5: 打流验命中(gre无对端跳过; any用tcp打流)
            if proto == "gre":
                rec.add_detail("[L5-gre] 无对端隧道, 跳过打流(仅L2 -p落地)")
            else:
                flow_proto = "tcp" if proto == "any" else proto
                flow_port = case.get("flow_port") or 5201
                ssh_verify(f"L5-打流-{proto}", bv.verify_acl_flow, name,
                           proto=flow_proto, dst_port=flow_port, action=action)
    finally:
        try:
            page.navigate_to_acl()
            page.page.wait_for_timeout(500)
            page.clean_test_rules(PREFIX)
        except Exception:
            pass
        if bv:
            try:
                bv.cleanup_acl_test(PREFIX)
            except Exception:
                pass

    assert not failures, f"协议矩阵[{case['id']}]失败({len(failures)}项): {'; '.join(failures)}"
