"""自定义网址库与禁止娱乐网站联动的HTTP/HTTPS真实流量测试。"""

import os

import pytest

from pages.security.custom_domain_group_page import CustomDomainGroupPage
from pages.security.domain_blacklist_page import DomainBlacklistPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify


CUSTOM_PREFIX = "cdom_t_"
DOMAIN_PREFIX = "dblk_t_"
LIBRARY_NAME = "cdom_t_l5"
RULE_NAME = "dblk_t_cdom"
CLIENT_IP = "192.168.148.2"
CATEGORY = "新闻媒体"
SITE_TYPE = "新闻报刊"
TARGET_GROUP = f"{CATEGORY}-{SITE_TYPE}"
TARGET_DOMAIN = os.environ.get(
    "CUSTOM_DOMAIN_GROUP_TARGET_DOMAIN", "www.baidu.com"
)
CONTROL_DOMAIN = os.environ.get(
    "CUSTOM_DOMAIN_GROUP_CONTROL_DOMAIN", "example.com"
)


@pytest.mark.security
@pytest.mark.custom_domain_group
@pytest.mark.functional
@pytest.mark.p1
class TestCustomDomainGroupFunctional:
    def test_custom_domain_group_http_https_flow(
        self,
        custom_domain_group_page_logged_in: CustomDomainGroupPage,
        step_recorder: StepRecorder,
        request,
    ):
        custom_page = custom_domain_group_page_logged_in
        domain_page = DomainBlacklistPage(
            custom_page.page, custom_page.base_url
        )
        rec = step_recorder
        bv = request.getfixturevalue("backend_verifier")
        failures = []
        ssh_failures = []
        created_rule_id = None
        verify_ssh = make_ssh_verify(
            bv, rec, ssh_failures, must_pass_default=True
        )

        def check(label, condition, actual=""):
            passed = bool(condition)
            rec.add_detail(
                f"【功能验证】\n{'通过' if passed else '失败'}：{label}"
                + (f"；{actual}" if actual else "")
            )
            if not passed:
                failures.append(f"{label}: {actual or '未达到预期'}")
                rec.fail_current_step(f"{label}未达到预期")
            return passed

        def verify(label, func, *args, **kwargs):
            result = verify_ssh(label, func, *args, **kwargs)
            if result is None or not result.passed:
                rec.fail_current_step(
                    f"{label}: {getattr(result, 'message', '验证器无返回')}"
                )
            return result

        def flow(label, domain, protocol, allowed):
            return verify(
                label,
                bv.verify_domain_blacklist_flow,
                domain,
                protocol=protocol,
                expect_allowed=allowed,
                iface="ens11",
            )

        try:
            bv.cleanup_domain_blacklist_test(DOMAIN_PREFIX)
            bv.cleanup_custom_domain_group_test(CUSTOM_PREFIX)

            with rec.step(
                "自定义分类与客户端流量基线",
                f"确认{TARGET_DOMAIN}尚未属于{TARGET_GROUP}，并从10.66.0.18的ens11/{CLIENT_IP}访问目标和对照域名。",
                expected="分类展开不含目标域名；目标与对照域名的HTTP/HTTPS均可访问。",
            ):
                membership = verify(
                    "自定义域名不存在基线",
                    bv.verify_custom_domain_group_category_domains,
                    TARGET_GROUP,
                    [TARGET_DOMAIN],
                    expect_present=False,
                )
                results = [
                    flow("基线-目标HTTP", TARGET_DOMAIN, "http", True),
                    flow("基线-目标HTTPS", TARGET_DOMAIN, "https", True),
                    flow("基线-对照HTTP", CONTROL_DOMAIN, "http", True),
                    flow("基线-对照HTTPS", CONTROL_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(
                    result.message for result in (membership, *results) if result
                ))

            with rec.step(
                "自定义网址加入系统分类",
                f"页面新增{LIBRARY_NAME}，把{TARGET_DOMAIN}归入{TARGET_GROUP}。",
                expected="custom_domain_group字段正确，domain_group.sh分类展开立即包含目标域名。",
            ):
                custom_page.navigate_to_custom_domain_group()
                added = custom_page.add_rule(
                    LIBRARY_NAME,
                    CATEGORY,
                    SITE_TYPE,
                    [TARGET_DOMAIN],
                )
                check("页面新增自定义网址", added.get("success"), added.get("error"))
                db = verify(
                    "自定义网址L1数据库",
                    bv.verify_custom_domain_group_database,
                    LIBRARY_NAME,
                    group=TARGET_GROUP,
                    domains=[TARGET_DOMAIN],
                )
                expanded = verify(
                    "自定义网址L2分类展开",
                    bv.verify_custom_domain_group_resolution,
                    LIBRARY_NAME,
                )
                rec.set_actual("；".join(
                    result.message for result in (db, expanded) if result
                ))

            with rec.step(
                "禁止娱乐网站联动阻断",
                f"新增仅作用于{CLIENT_IP}的{TARGET_GROUP}规则，发送目标与对照HTTP/HTTPS流量。",
                expected="DPI配置包含自定义目标域名；目标HTTP/HTTPS阻断，对照HTTP/HTTPS继续放行。",
            ):
                domain_page.navigate_to_domain_blacklist()
                added = domain_page.add_rule(
                    RULE_NAME,
                    [TARGET_GROUP],
                    sources=[CLIENT_IP],
                )
                check("页面新增禁止娱乐网站规则", added.get("success"), added.get("error"))
                domain_page.page.wait_for_timeout(1500)
                rule = bv.find_domain_blacklist_rule(RULE_NAME)
                created_rule_id = int((rule or {}).get("id", 0)) or None
                check("记录联动规则ID", created_rule_id is not None, rule)
                db = verify(
                    "联动规则L1数据库",
                    bv.verify_domain_blacklist_database,
                    RULE_NAME,
                    enabled="yes",
                    # Leaf selections are persisted by domain_blacklist as the
                    # child name; TARGET_GROUP is only the UI selection path.
                    groups=[SITE_TYPE],
                    sources=[CLIENT_IP],
                )
                runtime = verify(
                    "自定义域名进入DPI",
                    bv.verify_domain_blacklist_generated_rule,
                    RULE_NAME,
                    sample_domains=[TARGET_DOMAIN],
                )
                source = verify(
                    "客户端属于源集合",
                    bv.verify_domain_blacklist_ipset,
                    RULE_NAME,
                    CLIENT_IP,
                )
                results = [
                    flow("阻断-目标HTTP", TARGET_DOMAIN, "http", False),
                    flow("阻断-目标HTTPS", TARGET_DOMAIN, "https", False),
                    flow("放行-对照HTTP", CONTROL_DOMAIN, "http", True),
                    flow("放行-对照HTTPS", CONTROL_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(
                    result.message
                    for result in (db, runtime, source, *results)
                    if result
                ))

            with rec.step(
                "停用、启用与删除恢复",
                "停用规则确认目标HTTP/HTTPS恢复；重新启用确认HTTPS再次阻断；删除规则确认两种协议恢复。",
                expected="阻断状态严格跟随禁止娱乐网站规则生命周期，删除后DB/DPI/源集合均无残留。",
            ):
                domain_page.navigate_to_domain_blacklist()
                check("页面停用联动规则", domain_page.disable_rule(RULE_NAME))
                domain_page.page.wait_for_timeout(1400)
                disabled_runtime = verify(
                    "停用DPI撤销",
                    bv.verify_domain_blacklist_generated_rule,
                    RULE_NAME,
                    expect_present=False,
                    sample_domains=[TARGET_DOMAIN],
                )
                restored_on_disable = [
                    flow("停用恢复-目标HTTP", TARGET_DOMAIN, "http", True),
                    flow("停用恢复-目标HTTPS", TARGET_DOMAIN, "https", True),
                ]
                domain_page.navigate_to_domain_blacklist()
                check("页面重新启用联动规则", domain_page.enable_rule(RULE_NAME))
                domain_page.page.wait_for_timeout(1400)
                blocked_again = flow(
                    "重新启用-目标HTTPS", TARGET_DOMAIN, "https", False
                )
                domain_page.navigate_to_domain_blacklist()
                check("页面删除联动规则", domain_page.delete_rule(RULE_NAME))
                domain_page.page.wait_for_timeout(1300)
                gone = verify(
                    "删除联动规则DB",
                    bv.verify_domain_blacklist_not_exists,
                    RULE_NAME,
                )
                artifacts = None
                if created_rule_id:
                    artifacts = verify(
                        "删除联动规则底层对象",
                        bv.verify_domain_blacklist_artifacts_absent,
                        created_rule_id,
                    )
                restored_on_delete = [
                    flow("删除恢复-目标HTTP", TARGET_DOMAIN, "http", True),
                    flow("删除恢复-目标HTTPS", TARGET_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(
                    result.message
                    for result in (
                        disabled_runtime,
                        *restored_on_disable,
                        blocked_again,
                        gone,
                        artifacts,
                        *restored_on_delete,
                    )
                    if result
                ))

            with rec.step(
                "删除自定义网址并检查分类残留",
                "从自定义网址库删除测试记录，再读取数据库和分类展开结果。",
                expected="记录从custom_domain_group消失，指定分类不再返回目标域名。",
            ):
                custom_page.navigate_to_custom_domain_group()
                check("页面删除自定义网址", custom_page.delete_rule(LIBRARY_NAME))
                gone = verify(
                    "自定义网址DB已删除",
                    bv.verify_custom_domain_group_not_exists,
                    LIBRARY_NAME,
                )
                absent = verify(
                    "自定义网址分类无残留",
                    bv.verify_custom_domain_group_category_domains,
                    TARGET_GROUP,
                    [TARGET_DOMAIN],
                    expect_present=False,
                )
                rec.set_actual("；".join(
                    result.message for result in (gone, absent) if result
                ))
        finally:
            try:
                rec.add_detail(
                    "【清理结果】\n通过："
                    + bv.cleanup_domain_blacklist_test(DOMAIN_PREFIX)
                )
                if created_rule_id:
                    rec.add_detail(
                        "【清理结果】\n通过："
                        + bv.cleanup_domain_blacklist_artifacts([created_rule_id])
                    )
                rec.add_detail(
                    "【清理结果】\n通过："
                    + bv.cleanup_custom_domain_group_test(CUSTOM_PREFIX)
                )
            except Exception as exc:
                failures.append(f"兜底清理异常: {exc}")

        failures.extend(ssh_failures)
        if failures:
            pytest.fail("自定义网址库L5功能测试失败:\n" + "\n".join(failures))
