"""ACL优先级排序测试 (安全中心>ACL规则, P1) — 补做旧用例完全没验的核心功能

prio排序是ACL规则冲突时的核心功能, 旧用例只验DB prio字段, 没验iptables规则顺序.
后端机制(acl.sh源码铁证):
  acl.sh __exec_rule_add 把规则写 /tmp/iktmp/ipt_rule_id/acl_id_rule (格式 `id prio <iptables命令>`)
  /usr/ikuai/function/acl:574 `sort -k2,2n -k1,1n` 按prio升序(+id升序破平)后 iptables-restore 下发
  → iptables FIREWALL链规则行号顺序 = prio升序(prio小=行号小=先生效)

验证:
  故意乱序建4条规则(prio=30/10/20/5) → L2验iptables行号顺序=prio升序(5/10/20/30)而非建序
  辅证: cat acl_id_rule文件印证sort -k2,2n生效(未排序源 vs iptables实际顺序)

注意: 旧用例只verify_acl_database(prio字段), 本用例用verify_acl_priority_order验真实iptables顺序.
"""
import pytest

from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure

pytestmark = [pytest.mark.security, pytest.mark.acl, pytest.mark.p1]
PREFIX = "acl_po_"  # priority order

# 故意乱序: 建序30/10/20/5, 期望iptables行号顺序=5/10/20/30(prio升序)
RULES = [("p30", 30), ("p10", 10), ("p20", 20), ("p05", 5)]


def test_acl_priority_order(acl_page_logged_in, backend_verifier,
                            step_recorder: StepRecorder, request):
    """优先级排序: 乱序建4条不同prio规则→验iptables FIREWALL行号=prio升序."""
    page = acl_page_logged_in
    bv = backend_verifier
    rec = step_recorder
    failures = []

    def ssh_verify(label, func, *args, must_pass=True, **kwargs):
        if bv is None:
            rec.add_detail(f"[SSH-{label}] 跳过(无SSH验证器)")
            return None
        try:
            r = func(*args, **kwargs)
            rec.add_detail(f"[SSH-{label}] {'PASS' if r.passed else 'FAIL'}: {r.message}")
            if must_pass and not r.passed:
                failures.append(f"{label}: {r.message}")
            return r
        except Exception as e:
            rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
            failures.append(f"{label}异常: {str(e)[:80]}")
            return None
    ssh_verify = attach_cmd_recording_to_closure(bv, rec, ssh_verify)

    id_to_prio = {}
    try:
        with rec.step("步骤1: 清理+乱序建4条不同prio规则(30/10/20/5)",
                      "验证prio排序而非建序"):
            page.navigate_to_acl()
            page.page.wait_for_timeout(800)
            page.clean_test_rules(PREFIX)
            if bv:
                bv.cleanup_acl_test(PREFIX)
            for nm, prio in RULES:
                res = page.add_rule(f"{PREFIX}{nm}", action="accept",
                                    priority=prio, dst_addrs=["10.66.0.40"])
                rec.add_detail(f"[UI] 建 {PREFIX}{nm} prio={prio}: "
                               f"{'成功' if res['success'] else '失败 ' + res.get('error', '')}")
                page.page.wait_for_timeout(600)

        with rec.step("步骤2: L1验DB prio字段 + 收集id_to_prio映射",
                      "每条prio正确入库"):
            if bv:
                for nm, prio in RULES:
                    r = ssh_verify(f"L1-{nm}-prio={prio}", bv.verify_acl_database,
                                   f"{PREFIX}{nm}", expected_fields={"prio": str(prio)})
                    rid = bv.find_acl_rule_id(f"{PREFIX}{nm}")
                    if rid is not None:
                        id_to_prio[str(rid)] = prio

        with rec.step("步骤3: L2验iptables行号顺序=prio升序(acl.sh sort -k2,2n)",
                      "核心排序验证(5/10/20/30而非30/10/20/5)"):
            if bv and len(id_to_prio) >= 2:
                ssh_verify("L2-优先级排序", bv.verify_acl_priority_order, id_to_prio)
            else:
                rec.add_detail("[L2] id_to_prio收集不足2条, 跳过排序验证")
                failures.append("L2: 规则id收集不足, 无法验排序")
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

    assert not failures, f"优先级排序失败({len(failures)}项): {'; '.join(failures)}"
