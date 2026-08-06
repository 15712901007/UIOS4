"""设备设置 > 登录管理 > 账号设置 L1-L5 单节点综合测试。

底层脚本为 ``/usr/ikuai/script/webuser.sh``，权限组联动脚本为
``/usr/ikuai/script/usergroup.sh``。L5 使用隔离浏览器上下文执行真实登录、
错误密码、IP限制、停用拒绝及普通管理员越权验证。
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

import pytest

from pages.device_setting.account_setting_page import AccountSettingPage
from utils.step_recorder import StepRecorder, register_sensitive_values
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.device_setting, pytest.mark.account_setting]

PREFIX = "acct_l15_"
MAIN_ACCOUNT = f"{PREFIX}main"
CLONE_ACCOUNT = f"{PREFIX}clone"
PASSWORD_V1 = "IkAcct_L15#A1"
PASSWORD_V2 = "IkAcct_L15#B2"
DENIED_IP = "203.0.113.254"
DEFAULT_PERMISSION_CASES = (
    (f"{PREFIX}perm_none", "新功能不可见", "none"),
    (f"{PREFIX}perm_read", "新功能可见", "r"),
    (f"{PREFIX}perm_write", "新功能可读写", "rx"),
)


class TestAccountSettingComprehensive:
    """账号页面、数据库、权限运行态和真实鉴权综合验证。"""

    def test_account_setting_comprehensive(
        self,
        account_setting_page_logged_in: AccountSettingPage,
        step_recorder: StepRecorder,
        request,
    ):
        page = account_setting_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("账号设置L1-L5综合测试必须启用SSH backend_verifier")

        register_sensitive_values((PASSWORD_V1, PASSWORD_V2))
        failures: List[str] = []
        cleanup_failures: List[str] = []
        snapshot: Optional[Dict[str, Any]] = None
        snapshot_valid = False
        mutation_started = False
        unexpected_error: Optional[str] = None

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

        def functional_check(
            label: str, condition: Any, detail: Any = "条件不成立"
        ) -> bool:
            passed = bool(condition)
            print(f"    L5-{label}: {'[OK]' if passed else '[FAIL]'}")
            section(
                "协议验证", "通过" if passed else "失败", f"L5-{label}",
                "符合预期" if passed else detail,
            )
            if not passed:
                fail(f"L5-{label}", detail)
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

        def add_required_account() -> Dict[str, Any]:
            nonlocal mutation_started
            mutation_started = True
            return page.add_account(
                username=MAIN_ACCOUNT,
                password=PASSWORD_V1,
                confirm_password=PASSWORD_V1,
                ip_addr="0.0.0.0/0",
                session_timeout=5,
                force=False,
                permission="read",
            )

        try:
            with rec.step(
                "步骤1 操作：清理历史测试前缀并保存账号环境快照；验证：脚本、表、REST、管理员保护和页面能力完整",
                "只清理acct_l15_临时对象；admin账号、权限、密码及其他用户均保持不变",
            ):
                preclean = backend.cleanup_webuser_test(PREFIX)
                section("清理结果", "通过", "历史前缀预清理", preclean)
                snapshot = backend.get_webuser_environment_snapshot(PREFIX)
                snapshot_valid = bool(
                    snapshot.get("version") == 1
                    and str(snapshot.get("admin", {}).get("id")) == "1"
                    and not snapshot.get("test_accounts")
                    and not snapshot.get("test_groups")
                    and snapshot.get("homepage_cache_has_admin") is True
                    and snapshot.get("http_status") in {"200", "301", "302"}
                )
                ui_check("账号环境快照完整且无测试残留", snapshot_valid, snapshot)
                if not snapshot_valid:
                    raise RuntimeError("账号设置基线不健康，禁止开始持久化操作")
                ssh_verify(
                    "L1/L4-脚本/API/数据库契约",
                    backend.verify_webuser_script_contract,
                )
                ui_check("账号设置页面导航成功", page.is_on_account_setting_page(), page.page.url)
                structure = page.get_page_structure()
                ui_check(
                    "列表字段、搜索、复选、添加、编辑和帮助完整",
                    structure["add_present"]
                    and structure["edit_present"]
                    and structure["search_present"]
                    and structure["selection_present"]
                    and structure["help_present"]
                    and structure["admin_present"],
                    structure,
                )
                capabilities = page.get_capability_matrix()
                ui_check(
                    "账号能力矩阵覆盖CRUD、权限、安全与批量操作",
                    all(
                        capabilities[name]["supported"]
                        for name in (
                            "add", "edit", "search", "enable_disable", "delete",
                            "copy", "batch_operation", "permission", "ip_restriction",
                            "session_timeout", "password_cycle", "help",
                        )
                    )
                    and not capabilities["import"]["supported"]
                    and not capabilities["export"]["supported"],
                    capabilities,
                )
                ui_check(
                    "超级管理员只允许编辑",
                    page.get_account_actions("admin") == ["编辑"],
                    page.get_account_actions("admin"),
                )
                ui_check("新增表单可打开", page.open_add_page(), page.page.url)
                form = page.get_form_structure()
                ui_check(
                    "新增字段、权限矩阵、保存和取消完整",
                    all(form["fields"].values())
                    and form["save_present"] and form["cancel_present"]
                    and form["force_present"]
                    and form["permission_access_count"] >= 10
                    and form["permission_modify_count"] >= 10,
                    form,
                )
                default_options = page.get_default_permission_options()
                ui_check(
                    "默认权限三种新功能策略完整",
                    set(default_options) == set(
                        AccountSettingPage.DEFAULT_PERMISSION_OPTIONS
                    ),
                    default_options,
                )
                page._button("取消").first.click()
                page.page.wait_for_timeout(300)

            with rec.step(
                "步骤2 操作：提交空值、非法用户名、密码不一致和非法IP，检查数字边界钳制，并绕过表单调用非法API；验证：非法值拒绝、数值归界且数据库不落脏数据",
                "覆盖用户名规则、确认密码、IP语法、会话5-999分钟、周期1-999天及后端32位摘要契约",
            ):
                invalid_cases = [
                    ("空必填", {"username": "", "password": "", "confirm_password": ""}),
                    ("用户名含空格", {"username": f"{PREFIX}bad user"}),
                    ("密码不一致", {"confirm_password": "Different#2"}),
                    ("非法允许IP", {"ip_addr": "999.999.1.1"}),
                ]
                for index, (label, overrides) in enumerate(invalid_cases):
                    page.navigate_to_account_setting()
                    ui_check(f"{label}-进入新增表单", page.open_add_page(), page.page.url)
                    values = {
                        "username": f"{PREFIX}invalid{index}",
                        "password": PASSWORD_V1,
                        "confirm_password": PASSWORD_V1,
                        "ip_addr": "0.0.0.0/0",
                        "session_timeout": 5,
                        "force": False,
                        "permission": "read",
                    }
                    values.update(overrides)
                    page.fill_account_form(**values)
                    rejected = page.save_form(timeout=2500)
                    api_failed = any(
                        item.get("code") not in (None, 0)
                        for item in rejected.get("responses", [])
                    )
                    ui_check(
                        f"{label}-前端或后端拒绝",
                        not rejected.get("saved")
                        and (bool(rejected.get("validation_errors")) or api_failed),
                        rejected,
                    )

                page.navigate_to_account_setting()
                page.open_add_page()
                page.fill_account_form(session_timeout=4)
                ui_check(
                    "会话低于下限自动钳制到5",
                    page._field("session_timeout").input_value() == "5",
                    page._field("session_timeout").input_value(),
                )
                page.fill_account_form(session_timeout=1000)
                ui_check(
                    "会话高于上限自动钳制到999",
                    page._field("session_timeout").input_value() == "999",
                    page._field("session_timeout").input_value(),
                )
                page.set_password_cycle(True, 0)
                ui_check(
                    "改密周期低于下限自动钳制到1",
                    page._field("password_cycle").input_value() == "1",
                    page._field("password_cycle").input_value(),
                )
                page._field("password_cycle").fill("1000")
                page._field("password_cycle").press("Tab")
                page.page.wait_for_timeout(150)
                ui_check(
                    "改密周期高于上限自动钳制到999",
                    page._field("password_cycle").input_value() == "999",
                    page._field("password_cycle").input_value(),
                )
                page._button("取消").first.click()
                page.page.wait_for_timeout(300)

                page.navigate_to_account_setting()
                bad_account = page.api_call(
                    "webuser", "add", {
                        "enabled": "yes", "username": "System", "passwd": "short",
                        "force": 0, "interval": 30, "sesstimeout": 4, "group_id": 1,
                    },
                )
                ui_check("绕过表单的非法账号API被拒绝", bad_account.get("code") != 0, bad_account)
                bad_group = page.api_call(
                    "usergroup", "add", {
                        "group_name": f"{PREFIX}badgroup", "ip_addr": "999.1.1.1",
                        "perm_default": "rx", "perm_config": "webuser:r",
                    },
                )
                ui_check("绕过表单的非法权限组API被拒绝", bad_group.get("code") != 0, bad_group)
                remaining = backend.get_webuser_environment_snapshot(PREFIX)
                ui_check(
                    "非法矩阵后无账号或权限组残留",
                    not remaining.get("test_accounts") and not remaining.get("test_groups"),
                    remaining,
                )

            with rec.step(
                "步骤3 操作：逐项保存新功能不可见、可见、可读写三种默认权限；验证：GUI选中、请求映射、数据库值和编辑回显一致",
                "默认权限仅作用于升级后新增且尚未写入perm_config的功能；产品映射依次为none、r、rx",
            ):
                mutation_started = True
                for username, label, expected_code in DEFAULT_PERMISSION_CASES:
                    add_default = page.add_account(
                        username=username,
                        password=PASSWORD_V1,
                        confirm_password=PASSWORD_V1,
                        ip_addr="0.0.0.0/0",
                        session_timeout=5,
                        force=False,
                        permission="read",
                        default_permission=label,
                    )
                    ui_check(
                        f"{label}-GUI选择成功",
                        add_default.get("fill_checks", {}).get("default_permission"),
                        add_default,
                    )
                    ui_check(
                        f"{label}-权限组和账号保存成功",
                        add_default.get("saved"),
                        add_default,
                    )
                    if not add_default.get("saved"):
                        raise RuntimeError(f"默认权限账号新增失败: {label}")
                    group_requests = [
                        item for item in add_default.get("requests", [])
                        if item.get("func_name") == "usergroup"
                        and item.get("action") == "add"
                    ]
                    sent_code = (
                        group_requests[-1].get("param", {}).get("perm_default")
                        if group_requests else None
                    )
                    ui_check(
                        f"{label}-请求映射为{expected_code}",
                        sent_code == expected_code,
                        {"expected": expected_code, "actual": sent_code},
                    )
                    ssh_verify(
                        f"L1-{label}数据库",
                        backend.verify_webuser_default_permission,
                        username,
                        expected_code,
                    )
                    page.navigate_to_account_setting()
                    opened = page.open_edit_page(username)
                    ui_check(f"{label}-编辑页可打开", opened, page.page.url)
                    state = page.get_form_state() if opened else {}
                    ui_check(
                        f"{label}-刷新后回显一致",
                        state.get("default_permission") == label,
                        state,
                    )
                    if opened:
                        page._button("取消").first.click()
                        page.page.wait_for_timeout(250)
                    deleted_default = page.delete_account(username)
                    ui_check(
                        f"{label}-测试账号删除成功",
                        deleted_default.get("success"),
                        deleted_default,
                    )
                    ssh_verify(
                        f"L1/L4-{label}删除无残留",
                        backend.verify_webuser_not_exists,
                        username,
                    )
                default_cleanup = backend.get_webuser_environment_snapshot(PREFIX)
                ui_check(
                    "三种默认权限测试后无账号或权限组残留",
                    not default_cleanup.get("test_accounts")
                    and not default_cleanup.get("test_groups"),
                    default_cleanup,
                )

            with rec.step(
                "步骤4 操作：通过页面新增只读普通管理员并执行搜索；验证：usergroup->webuser请求、L1-L4、权限展开和刷新回显一致",
                "最小会话5分钟、全部来源IP、全页面只读；密码仅验证摘要长度，不进入报告",
            ):
                add_result = add_required_account()
                ui_check("新增字段均填写成功", all(add_result.get("fill_checks", {}).values()), add_result)
                ui_check("新增权限组和账号API均成功", add_result.get("saved"), add_result)
                if not add_result.get("saved"):
                    raise RuntimeError("主测试账号新增失败，停止依赖该账号的后续验证")
                request_actions = [
                    (item.get("func_name"), item.get("action"))
                    for item in add_result.get("requests", [])
                ]
                ui_check(
                    "新增请求顺序为usergroup.add后webuser.add",
                    request_actions[:2] == [("usergroup", "add"), ("webuser", "add")],
                    request_actions,
                )
                page.navigate_to_account_setting()
                ui_check("新增账号列表可见", page.account_exists(MAIN_ACCOUNT), page.get_usernames())
                search_rows = page.search_account(MAIN_ACCOUNT)
                ui_check("精确搜索仅返回目标账号", search_rows == [MAIN_ACCOUNT], search_rows)
                page.clear_search()
                ssh_verify(
                    "L1-新增账号数据库",
                    backend.verify_webuser_database,
                    MAIN_ACCOUNT,
                    {
                        "enabled": "yes", "force": 0, "interval": 30,
                        "sesstimeout": 5, "group_name": MAIN_ACCOUNT,
                        "ip_addr": "0.0.0.0/0", "perm_default": "rx",
                    },
                )
                ssh_verify("L2-新增账号Web运行态", backend.verify_webuser_runtime, MAIN_ACCOUNT, "yes")
                ssh_verify("L3-只读权限展开", backend.verify_webuser_permission, MAIN_ACCOUNT, "read")
                ssh_verify("L4-webuser脚本重建", backend.verify_webuser_reinit, MAIN_ACCOUNT)
                accounts_api = page.api_accounts()
                ui_check(
                    "账号列表API回显且未返回密码字段",
                    accounts_api.get("code") == 0
                    and any(item.get("username") == MAIN_ACCOUNT for item in accounts_api.get("data", []))
                    and all("passwd" not in item for item in accounts_api.get("data", [])),
                    accounts_api,
                )

            with rec.step(
                "步骤5 操作：用隔离会话执行正确密码、错误密码和只读普通管理员越权测试；验证：真实登录成功、错误凭据拒绝、仅见自身且无管理动作",
                "L5直接访问10.66.0.45 Web，不复用admin Cookie；越权探针只尝试删除受保护的group id=1，确保无副作用",
            ):
                login_ok = page.attempt_login(MAIN_ACCOUNT, PASSWORD_V1)
                functional_check(
                    "正确凭据登录成功",
                    login_ok.get("success") and "systemOverview" in login_ok.get("final_url", ""),
                    login_ok,
                )
                login_bad = page.attempt_login(MAIN_ACCOUNT, PASSWORD_V2)
                functional_check(
                    "错误密码被拒绝",
                    not login_bad.get("success") and login_bad.get("api_code") != 0,
                    login_bad,
                )
                restricted = page.verify_restricted_account(MAIN_ACCOUNT, PASSWORD_V1)
                functional_check(
                    "普通管理员只读及数据隔离",
                    restricted.get("login_success")
                    and restricted.get("list_opened")
                    and restricted.get("add_hidden")
                    and restricted.get("only_self_visible")
                    and restricted.get("admin_api_rejected"),
                    restricted,
                )

            with rec.step(
                "步骤6 操作：编辑会话上限、周期改密、IP限制和登录密码；验证：边界、未来过期时间、IP负向控制及新旧密码闭环",
                "先限制到不可达保留地址验证拒绝，再恢复0.0.0.0/0并修改密码，admin会话始终保持可用",
            ):
                mutation_started = True
                edit_restricted = page.edit_account(
                    MAIN_ACCOUNT,
                    ip_addr=DENIED_IP,
                    session_timeout=999,
                    force=True,
                    password_cycle=1,
                )
                ui_check("IP限制和周期改密保存成功", edit_restricted.get("saved"), edit_restricted)
                ssh_verify(
                    "L1-编辑后数据库边界",
                    backend.verify_webuser_database,
                    MAIN_ACCOUNT,
                    {
                        "enabled": "yes", "force": 1, "interval": 1,
                        "sesstimeout": 999, "ip_addr": DENIED_IP,
                    },
                )
                denied = page.attempt_login(MAIN_ACCOUNT, PASSWORD_V1)
                functional_check(
                    "允许访问IP负向控制生效",
                    not denied.get("success") and denied.get("api_code") != 0,
                    denied,
                )

                edit_password = page.edit_account(
                    MAIN_ACCOUNT,
                    password=PASSWORD_V2,
                    confirm_password=PASSWORD_V2,
                    ip_addr="0.0.0.0/0",
                    session_timeout=999,
                    force=False,
                )
                ui_check("恢复IP并修改密码成功", edit_password.get("saved"), edit_password)
                ssh_verify(
                    "L1-密码修改后数据库",
                    backend.verify_webuser_database,
                    MAIN_ACCOUNT,
                    {
                        "enabled": "yes", "force": 0,
                        "sesstimeout": 999, "ip_addr": "0.0.0.0/0",
                    },
                )
                old_password = page.attempt_login(MAIN_ACCOUNT, PASSWORD_V1)
                new_password = page.attempt_login(MAIN_ACCOUNT, PASSWORD_V2)
                functional_check("旧密码失效", not old_password.get("success"), old_password)
                functional_check("新密码登录成功", new_password.get("success"), new_password)

            with rec.step(
                "步骤7 操作：单条停用并重新启用账号；验证：数据库、运行缓存和真实登录分别执行负向/正向控制",
                "停用后新会话必须拒绝，启用后同一新密码必须恢复登录",
            ):
                disabled = page.disable_account(MAIN_ACCOUNT)
                ui_check("单条停用成功", disabled.get("success"), disabled)
                ssh_verify("L1-停用数据库", backend.verify_webuser_database, MAIN_ACCOUNT, {"enabled": "no"})
                ssh_verify("L2-停用运行态", backend.verify_webuser_runtime, MAIN_ACCOUNT, "no")
                disabled_login = page.attempt_login(MAIN_ACCOUNT, PASSWORD_V2)
                functional_check("停用账号拒绝登录", not disabled_login.get("success"), disabled_login)

                enabled = page.enable_account(MAIN_ACCOUNT)
                ui_check("单条启用成功", enabled.get("success"), enabled)
                ssh_verify("L1-启用数据库", backend.verify_webuser_database, MAIN_ACCOUNT, {"enabled": "yes"})
                ssh_verify("L2-启用运行态", backend.verify_webuser_runtime, MAIN_ACCOUNT, "yes")
                enabled_login = page.attempt_login(MAIN_ACCOUNT, PASSWORD_V2)
                functional_check("重新启用后恢复登录", enabled_login.get("success"), enabled_login)

            with rec.step(
                "步骤8 操作：复制账号并执行批量停用、启用、删除；验证：复制回显、关联权限组及批量状态无残留",
                "复制账号使用独立用户名和密码，批量按钮只作用于选中普通账号",
            ):
                copied = page.copy_account(
                    MAIN_ACCOUNT,
                    username=CLONE_ACCOUNT,
                    password=PASSWORD_V1,
                    confirm_password=PASSWORD_V1,
                )
                ui_check("复制表单继承IP和会话配置", copied.get("copy_source_state", {}).get("ip_addr") == "0.0.0.0/0" and copied.get("copy_source_state", {}).get("session_timeout") == "999", copied)
                ui_check("复制账号保存成功", copied.get("saved"), copied)
                ssh_verify(
                    "L1-复制账号数据库",
                    backend.verify_webuser_database,
                    CLONE_ACCOUNT,
                    {"enabled": "yes", "sesstimeout": 999, "ip_addr": "0.0.0.0/0"},
                )
                batch_down = page.batch_action([CLONE_ACCOUNT], "停用")
                ui_check("批量停用选中账号", batch_down.get("success"), batch_down)
                ssh_verify("L1-批量停用数据库", backend.verify_webuser_database, CLONE_ACCOUNT, {"enabled": "no"})
                batch_up = page.batch_action([CLONE_ACCOUNT], "启用")
                ui_check("批量启用选中账号", batch_up.get("success"), batch_up)
                batch_delete = page.batch_action([CLONE_ACCOUNT], "删除")
                ui_check("批量删除选中账号", batch_delete.get("success"), batch_delete)
                ssh_verify("L1/L4-复制账号删除无残留", backend.verify_webuser_not_exists, CLONE_ACCOUNT)

            with rec.step(
                "步骤9 操作：悬浮右下角帮助并点击跳转；验证：说明文字、位置、官方文章主题、URL及关闭返回完整",
                "帮助应说明用户/权限管理并打开article id=119的账号设置文档，新标签关闭后列表仍可操作",
            ):
                help_result = page.verify_help_entry()
                ui_check("右下角帮助入口及悬浮文字", help_result.get("button_present") and help_result.get("bottom_right") and help_result.get("tooltip_opened") and help_result.get("tooltip_matched"), help_result)
                ui_check("帮助跳转到账号设置官方文章", help_result.get("opened") and help_result.get("all_keywords_matched") and "id=119" in help_result.get("url", ""), help_result)
                ui_check("帮助标签关闭且返回列表", help_result.get("closed") and help_result.get("no_orphan") and page.is_on_account_setting_page(), help_result)

            with rec.step(
                "步骤10 操作：通过页面删除主测试账号；验证：账号、权限组、令牌、缓存和整机账号环境回到测试前快照",
                "删除普通账号不影响admin及其他账号，完成后独立执行残留审计",
            ):
                deleted = page.delete_account(MAIN_ACCOUNT)
                ui_check("主测试账号页面删除成功", deleted.get("success"), deleted)
                ssh_verify("L1/L4-主账号删除无残留", backend.verify_webuser_not_exists, MAIN_ACCOUNT)
                ssh_verify(
                    "L4-账号环境恢复",
                    backend.verify_webuser_environment_unchanged,
                    snapshot,
                    cleanup=True,
                )

        except Exception as exc:
            unexpected_error = f"{type(exc).__name__}: {str(exc)[:220]}"
            fail("账号设置综合流程异常", unexpected_error)
        finally:
            if snapshot_valid and snapshot is not None:
                try:
                    cleanup_message = backend.cleanup_webuser_test(PREFIX)
                    section("清理结果", "通过", "finally前缀清理", cleanup_message)
                except Exception as exc:
                    cleanup_failures.append(f"finally前缀清理异常({type(exc).__name__})")
                final_audit = ssh_verify(
                    "finally-恢复后独立残留审计",
                    backend.verify_webuser_environment_unchanged,
                    snapshot,
                    must_pass=True,
                    cleanup=True,
                )
                if final_audit is None or not getattr(final_audit, "passed", False):
                    cleanup_failures.append("finally账号环境独立审计失败")
                try:
                    page.navigate_to_account_setting()
                    page.page.reload(wait_until="domcontentloaded")
                    page.page.wait_for_timeout(800)
                    if page.account_exists(MAIN_ACCOUNT) or page.account_exists(CLONE_ACCOUNT):
                        cleanup_failures.append("finally页面仍显示测试账号")
                    else:
                        section("清理结果", "通过", "finally页面复验", "无测试账号")
                except Exception as exc:
                    cleanup_failures.append(f"finally页面复验异常({type(exc).__name__})")
            elif mutation_started:
                cleanup_failures.append("已开始修改但无有效账号环境快照，无法证明安全恢复")

        all_failures = failures + cleanup_failures
        if unexpected_error:
            print(f"[账号设置异常] {unexpected_error}")
        if all_failures:
            print(f"[账号设置断言] 共{len(all_failures)}项失败")
            for item in all_failures:
                print(f"  - {item}")
        assert not all_failures, (
            f"账号设置L1-L5综合验证失败({len(all_failures)}项): "
            + "; ".join(all_failures[:32])
        )
