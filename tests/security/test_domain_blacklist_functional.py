"""禁止娱乐网站HTTP/HTTPS真实阻断功能测试。"""

import os

import pytest

from pages.security.domain_blacklist_page import DomainBlacklistPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify


PREFIX = "dblk_t_"
RULE_NAME = "dblk_t_l5"
CLIENT_IP = "192.168.148.2"
TARGET_GROUP = "休闲娱乐"
GAME_DOMAIN = os.environ.get("DOMAIN_BLACKLIST_GAME_DOMAIN", "4399.com")
VIDEO_DOMAIN = os.environ.get("DOMAIN_BLACKLIST_VIDEO_DOMAIN", "iqiyi.com")
SOCIAL_DOMAIN = os.environ.get("DOMAIN_BLACKLIST_SOCIAL_DOMAIN", "weibo.com")
CONTROL_DOMAIN = os.environ.get("DOMAIN_BLACKLIST_CONTROL_DOMAIN", "www.baidu.com")


@pytest.mark.security
@pytest.mark.domain_blacklist
@pytest.mark.functional
@pytest.mark.p1
class TestDomainBlacklistFunctional:
    def test_domain_blacklist_http_https_flow(
        self,
        domain_blacklist_page_logged_in: DomainBlacklistPage,
        step_recorder: StepRecorder,
        request,
    ):
        page = domain_blacklist_page_logged_in
        rec = step_recorder
        bv = request.getfixturevalue("backend_verifier")
        failures = []
        ssh_failures = []
        created_rule_id = None
        ssh_verify = make_ssh_verify(bv, rec, ssh_failures, must_pass_default=True)

        def check(label, condition, actual=""):
            condition = bool(condition)
            rec.add_detail(
                f"【功能验证】\n{'通过' if condition else '失败'}：{label}"
                + (f"；{actual}" if actual else "")
            )
            if not condition:
                failures.append(f"{label}: {actual or '未达到预期'}")
                rec.fail_current_step(f"{label}未达到预期")
            return condition

        def flow(label, domain, protocol, allowed):
            result = ssh_verify(
                label,
                bv.verify_domain_blacklist_flow,
                domain,
                protocol=protocol,
                expect_allowed=allowed,
                iface="ens11",
            )
            check(label, result is not None and result.passed, getattr(result, "message", "无结果"))
            return result

        try:
            bv.cleanup_domain_blacklist_test(PREFIX)

            with rec.step(
                "L5公网与业务网卡基线",
                f"从10.66.0.18的ens11/{CLIENT_IP}访问三个娱乐分类代表域名及非娱乐对照域名。",
                expected="规则创建前HTTP/HTTPS均可访问，证明DNS、公网和业务路径正常。",
            ):
                results = [
                    flow("基线-游戏HTTP", GAME_DOMAIN, "http", True),
                    flow("基线-游戏HTTPS", GAME_DOMAIN, "https", True),
                    flow("基线-视频HTTP", VIDEO_DOMAIN, "http", True),
                    flow("基线-社交HTTPS", SOCIAL_DOMAIN, "https", True),
                    flow("基线-对照HTTP", CONTROL_DOMAIN, "http", True),
                    flow("基线-对照HTTPS", CONTROL_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(r.message for r in results if r))

            with rec.step(
                "休闲娱乐分类真实阻断",
                f"页面新增{TARGET_GROUP}规则，仅作用于{CLIENT_IP}，验证不同子类的HTTP和HTTPS。",
                expected="游戏HTTP/HTTPS、视频HTTP、社交HTTPS均阻断；非娱乐百度HTTP/HTTPS继续放行。",
            ):
                page.navigate_to_domain_blacklist()
                added = page.add_rule(RULE_NAME, [TARGET_GROUP], sources=[CLIENT_IP])
                check("新增L5规则", added.get("success"), added.get("error"))
                page.page.wait_for_timeout(1500)
                runtime = ssh_verify(
                    "L2十类娱乐域名已展开",
                    bv.verify_domain_blacklist_generated_rule,
                    RULE_NAME,
                    sample_domains=list(bv.ENTERTAINMENT_DOMAIN_SAMPLES.values()),
                )
                check("L2分类展开", runtime is not None and runtime.passed, getattr(runtime, "message", ""))
                ipset = ssh_verify(
                    "L3测试客户端属于源集合",
                    bv.verify_domain_blacklist_ipset,
                    RULE_NAME,
                    CLIENT_IP,
                )
                check("L3源集合", ipset is not None and ipset.passed, getattr(ipset, "message", ""))
                created = bv.find_domain_blacklist_rule(RULE_NAME)
                created_rule_id = int((created or {}).get("id", 0)) or None
                results = [
                    flow("阻断-游戏HTTP", GAME_DOMAIN, "http", False),
                    flow("阻断-游戏HTTPS", GAME_DOMAIN, "https", False),
                    flow("阻断-视频HTTP", VIDEO_DOMAIN, "http", False),
                    flow("阻断-社交HTTPS", SOCIAL_DOMAIN, "https", False),
                    flow("放行-非娱乐HTTP", CONTROL_DOMAIN, "http", True),
                    flow("放行-非娱乐HTTPS", CONTROL_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(r.message for r in (runtime, ipset, *results) if r))

            with rec.step(
                "停用后HTTP/HTTPS恢复",
                "页面停用规则，重新访问原命中的游戏、视频和社交域名。",
                expected="DPI规则撤销，原命中域名全部恢复；证明前一步失败由禁止娱乐网站规则造成。",
            ):
                page.navigate_to_domain_blacklist()
                check("页面停用L5规则", page.disable_rule(RULE_NAME))
                page.page.wait_for_timeout(1500)
                runtime = ssh_verify(
                    "停用DPI撤销",
                    bv.verify_domain_blacklist_generated_rule,
                    RULE_NAME,
                    expect_present=False,
                )
                check("停用运行态撤销", runtime is not None and runtime.passed, getattr(runtime, "message", ""))
                results = [
                    flow("停用恢复-游戏HTTP", GAME_DOMAIN, "http", True),
                    flow("停用恢复-游戏HTTPS", GAME_DOMAIN, "https", True),
                    flow("停用恢复-视频HTTP", VIDEO_DOMAIN, "http", True),
                    flow("停用恢复-社交HTTPS", SOCIAL_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(r.message for r in (runtime, *results) if r))

            with rec.step(
                "重新启用与删除恢复",
                "重新启用后复验游戏HTTPS再次阻断，再删除规则并确认访问恢复。",
                expected="启用立即恢复阻断；删除后DB/DPI/对象无残留且HTTP/HTTPS均恢复。",
            ):
                page.navigate_to_domain_blacklist()
                check("页面重新启用", page.enable_rule(RULE_NAME))
                page.page.wait_for_timeout(1500)
                blocked = flow("重新启用-游戏HTTPS", GAME_DOMAIN, "https", False)
                rule = bv.find_domain_blacklist_rule(RULE_NAME)
                rule_id = int((rule or {}).get("id", 0)) or created_rule_id
                page.navigate_to_domain_blacklist()
                check("页面删除L5规则", page.delete_rule(RULE_NAME))
                page.page.wait_for_timeout(1500)
                gone = ssh_verify("删除DB", bv.verify_domain_blacklist_not_exists, RULE_NAME)
                check("删除DB无记录", gone is not None and gone.passed, getattr(gone, "message", ""))
                if rule_id:
                    artifacts = ssh_verify(
                        "删除底层对象回收",
                        bv.verify_domain_blacklist_artifacts_absent,
                        rule_id,
                    )
                    check("删除无残留", artifacts is not None and artifacts.passed, getattr(artifacts, "message", ""))
                restored = [
                    flow("删除恢复-游戏HTTP", GAME_DOMAIN, "http", True),
                    flow("删除恢复-游戏HTTPS", GAME_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(r.message for r in (blocked, gone, *restored) if r))
        finally:
            try:
                cleanup = bv.cleanup_domain_blacklist_test(PREFIX)
                rec.add_detail(f"【清理结果】\n通过：{cleanup}")
                if created_rule_id:
                    artifacts = bv.cleanup_domain_blacklist_artifacts([created_rule_id])
                    rec.add_detail(f"【清理结果】\n通过：{artifacts}")
            except Exception as exc:
                failures.append(f"规则清理异常: {exc}")

        failures.extend(ssh_failures)
        if failures:
            pytest.fail("禁止娱乐网站L5功能测试失败:\n" + "\n".join(failures))
