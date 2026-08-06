"""网址黑白名单HTTP/HTTPS与白名单外链开关L5验证。"""

import os

import pytest

from pages.security.url_black_page import UrlBlackPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify


PREFIX = "urlbw_t_"
BLACK_RULE = "urlbw_t_l5blk"
WHITE_RULE = "urlbw_t_l5wht"
CLIENT_IP = "192.168.148.2"
ALLOW_DOMAIN = os.environ.get("URL_BLACK_ALLOW_DOMAIN", "www.baidu.com")
EXTERNAL_DOMAIN = os.environ.get("URL_BLACK_EXTERNAL_DOMAIN", "www.qq.com")


@pytest.mark.security
@pytest.mark.url_black
@pytest.mark.functional
@pytest.mark.p1
class TestUrlBlackFunctional:
    def test_url_black_http_https_flow(
        self,
        url_black_page_logged_in: UrlBlackPage,
        step_recorder: StepRecorder,
        request,
    ):
        page = url_black_page_logged_in
        rec = step_recorder
        bv = request.getfixturevalue("backend_verifier")
        failures = []
        ssh_failures = []
        ssh_verify = make_ssh_verify(
            bv, rec, ssh_failures, must_pass_default=True
        )
        original_setting = None

        def check(label, condition, actual=""):
            if not condition:
                failures.append(f"{label}: {actual or '未达到预期'}")
                rec.fail_current_step(f"{label}未达到预期")
            rec.add_detail(
                f"【协议验证】\n{'通过' if condition else '失败'}：{label}"
                + (f"；{actual}" if actual else "")
            )
            return bool(condition)

        def flow(label, domain, protocol, allowed, referer=None):
            result = ssh_verify(
                label,
                bv.verify_url_black_flow,
                domain,
                protocol=protocol,
                expect_allowed=allowed,
                referer=referer,
                iface="ens11",
            )
            check(label, result is not None and result.passed, getattr(result, "message", "无结果"))
            return result

        def set_external_link(enabled):
            page.navigate_to_url_black()
            check("打开外链设置", page.open_settings())
            check(f"保存外链设置={int(enabled)}", page.set_white_external_link(enabled))
            result = ssh_verify(
                f"外链设置DB={int(enabled)}",
                bv.verify_url_black_setting,
                int(enabled),
            )
            check("外链设置持久化", result is not None and result.passed, getattr(result, "message", ""))

        try:
            bv.cleanup_url_black_test(PREFIX)
            initial = bv.verify_url_black_setting()
            original_setting = bool(initial.details.get("actual"))

            with rec.step(
                "L5基线与业务网卡路由",
                f"无测试规则时，从10.66.0.18使用ens11/192.168.148.2访问{ALLOW_DOMAIN}和{EXTERNAL_DOMAIN}的HTTP/HTTPS。",
                expected="四个请求均可访问，证明公网、DNS和客户端业务路径可用；后续阻断不是环境假失败。",
            ):
                results = [
                    flow("基线-允许域名HTTP", ALLOW_DOMAIN, "http", True),
                    flow("基线-允许域名HTTPS", ALLOW_DOMAIN, "https", True),
                    flow("基线-外部域名HTTP", EXTERNAL_DOMAIN, "http", True),
                    flow("基线-外部域名HTTPS", EXTERNAL_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(r.message for r in results if r))

            with rec.step(
                "黑名单同时拦截HTTP与HTTPS",
                f"页面新增仅作用于{CLIENT_IP}的黑名单{ALLOW_DOMAIN}，分别发HTTP、HTTPS和非命中HTTP请求。",
                expected="命中域名HTTP连接被重置、HTTPS在TLS握手阶段被重置；非命中域名仍可访问。",
            ):
                page.navigate_to_url_black()
                added = page.add_rule(
                    BLACK_RULE,
                    [ALLOW_DOMAIN],
                    mode=0,
                    sources=[CLIENT_IP],
                )
                check("新增L5黑名单", added.get("success"), added.get("error"))
                page.page.wait_for_timeout(1300)
                results = [
                    flow("黑名单-HTTP", ALLOW_DOMAIN, "http", False),
                    flow("黑名单-HTTPS", ALLOW_DOMAIN, "https", False),
                    flow("黑名单-非命中域名", EXTERNAL_DOMAIN, "http", True),
                ]
                rec.set_actual("；".join(r.message for r in results if r))

            with rec.step(
                "停用黑名单后HTTP/HTTPS立即恢复",
                "在页面停用黑名单，再重复访问原命中域名。",
                expected="HTTP和HTTPS均恢复可访问，证明前一步失败由规则造成且停用真实撤销。",
            ):
                page.navigate_to_url_black()
                check("页面停用L5黑名单", page.disable_rule(BLACK_RULE))
                page.page.wait_for_timeout(1300)
                results = [
                    flow("停用后-HTTP", ALLOW_DOMAIN, "http", True),
                    flow("停用后-HTTPS", ALLOW_DOMAIN, "https", True),
                ]
                rec.set_actual("；".join(r.message for r in results if r))
                bv.cleanup_url_black_test(PREFIX)

            with rec.step(
                "白名单同时控制HTTP与HTTPS",
                f"新增白名单{ALLOW_DOMAIN}并限定{CLIENT_IP}，访问名单内和名单外域名的HTTP/HTTPS。",
                expected="名单内HTTP/HTTPS均放行；名单外HTTP/HTTPS均阻断。网址黑白名单主体并非只支持HTTP。",
            ):
                page.navigate_to_url_black()
                added = page.add_rule(
                    WHITE_RULE,
                    [ALLOW_DOMAIN],
                    mode=1,
                    sources=[CLIENT_IP],
                )
                check("新增L5白名单", added.get("success"), added.get("error"))
                page.page.wait_for_timeout(1300)
                results = [
                    flow("白名单内-HTTP", ALLOW_DOMAIN, "http", True),
                    flow("白名单内-HTTPS", ALLOW_DOMAIN, "https", True),
                    flow("白名单外-HTTP", EXTERNAL_DOMAIN, "http", False),
                    flow("白名单外-HTTPS", EXTERNAL_DOMAIN, "https", False),
                ]
                rec.set_actual("；".join(r.message for r in results if r))

            with rec.step(
                "外部链接开关关闭时HTTP Referer不放行",
                f"关闭右上角开关，访问{EXTERNAL_DOMAIN}并携带来自白名单http://{ALLOW_DOMAIN}/的Referer。",
                expected="虽然Referer来自白名单页面，外部HTTP仍被阻断。",
            ):
                set_external_link(False)
                result = flow(
                    "外链关闭-HTTP Referer",
                    EXTERNAL_DOMAIN,
                    "http",
                    False,
                    referer=f"http://{ALLOW_DOMAIN}/",
                )
                rec.set_actual(getattr(result, "message", "无结果"))

            with rec.step(
                "外部链接开关开启只放行HTTP",
                f"开启开关，用同一白名单Referer分别请求{EXTERNAL_DOMAIN}的HTTP和HTTPS。",
                expected="HTTP外链放行；HTTPS仍在握手阶段被白名单阻断，实证页面“只支持HTTP协议”的边界。",
            ):
                set_external_link(True)
                http_result = flow(
                    "外链开启-HTTP Referer",
                    EXTERNAL_DOMAIN,
                    "http",
                    True,
                    referer=f"http://{ALLOW_DOMAIN}/",
                )
                https_result = flow(
                    "外链开启-HTTPS负向边界",
                    EXTERNAL_DOMAIN,
                    "https",
                    False,
                    referer=f"http://{ALLOW_DOMAIN}/",
                )
                rec.set_actual(
                    f"HTTP：{getattr(http_result, 'message', '')}；HTTPS：{getattr(https_result, 'message', '')}"
                )
        finally:
            try:
                cleanup = bv.cleanup_url_black_test(PREFIX)
                rec.add_detail(f"【清理结果】\n通过：{cleanup}")
            except Exception as exc:
                failures.append(f"规则清理异常: {exc}")
            if original_setting is not None:
                try:
                    page.navigate_to_url_black()
                    if page.open_settings():
                        page.set_white_external_link(original_setting)
                    restored = bv.verify_url_black_setting(int(original_setting))
                    if not restored.passed:
                        failures.append("外链开关未恢复测试前值")
                except Exception as exc:
                    failures.append(f"外链开关恢复异常: {exc}")

        failures.extend(ssh_failures)
        if failures:
            pytest.fail("网址黑白名单L5功能测试失败:\n" + "\n".join(failures))

