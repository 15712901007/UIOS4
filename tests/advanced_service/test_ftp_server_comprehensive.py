"""
高级服务 > 本地服务 > FTP服务综合测试。

单用例完整覆盖：页面默认结构、端口/外网设置、总开关、RW/RO用户
CRUD、搜索、单条停启、批量停启/删除、异常与边界、CSV导出/安全追加导入、
右下角帮助入口，以及 L1(DB)-L5(真实FTP LIST/上传/下载/鉴权/外网/关闭拒绝)。

安全约束：
- 所有用户名均不超过15字符，且只清理 ``ftp_t_`` 前缀。
- 密码每次运行随机生成，不写常量、不输出到stdout/报告/断言。
- 导入仅回灌从导出CSV筛选的单个测试用户，绝不勾选“清空现有配置”。
- 无论中途失败与否，finally都恢复全局快照、清测试用户/目录/敏感CSV。
"""

from __future__ import annotations

import csv
import os
import secrets
import string
import tempfile
import time
from typing import Dict, Optional, Tuple

import pytest

from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.advanced_service, pytest.mark.ftp_server]

TEST_PORT = 2121
PARTITION = "666"
LAN_HOST, LAN_IFACE = "192.168.148.1", "ens11"
WAN_IFACE = "enp2s0"
EXPORT_HEADERS = [
    "id", "enabled", "username", "passwd", "permission", "home_dir", "upload", "download"
]


def _one_time_password(length: int = 20) -> str:
    """仅在内存中生成的一次性密码，调用方不得记录返回值。"""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _truthy(value) -> bool:
    return str(value).strip().lower() in {"1", "yes", "true", "on", "enable", "enabled"}


def _export_csv_path() -> str:
    config = get_config()
    configured = config.test_data.get_export_path("ftp_server", config.get_project_root())
    return os.path.splitext(configured)[0] + ".csv"


def _build_safe_import(export_path: str, username: str) -> Tuple[Optional[str], list, int, str]:
    """仅保留指定测试用户，不返回或打印任何行内容。"""
    try:
        with open(export_path, "r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            headers = list(reader.fieldnames or [])
            rows = [row for row in reader if row.get("username") == username]
        if headers != EXPORT_HEADERS:
            return None, headers, len(rows), "CSV表头不符合FTP导出契约"
        if len(rows) != 1:
            return None, headers, len(rows), f"筛选用户行数应为1，实际{len(rows)}"
        os.makedirs(os.path.dirname(export_path), exist_ok=True)
        fd, safe_path = tempfile.mkstemp(
            prefix="ftp_t_import_", suffix=".csv", dir=os.path.dirname(export_path)
        )
        os.close(fd)
        with open(safe_path, "w", encoding="utf-8-sig", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=headers)
            writer.writeheader()
            writer.writerow(rows[0])
        return safe_path, headers, len(rows), ""
    except Exception as exc:
        return None, [], 0, str(exc)[:120]


class TestFtpServerComprehensive:
    """FTP服务 L1-L5 综合测试。"""

    def test_ftp_server_comprehensive(
        self, ftp_server_page_logged_in, step_recorder: StepRecorder, request
    ):
        page = ftp_server_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("FTP L1-L5综合测试必须启用SSH backend_verifier")

        # 每次调用使用独立命名空间；绝不先删固定前缀或固定目录。
        run_token = secrets.token_hex(2)
        PREFIX = f"ftp_t_{run_token}_"
        RW_USER = f"{PREFIX}rw"
        RO_USER = f"{PREFIX}ro"
        DELETE_USER = f"{PREFIX}del"
        BATCH_USERS = (f"{PREFIX}b1", f"{PREFIX}b2")
        NO_PASSWORD_USER = f"{PREFIX}np"
        NO_HOME_USER = f"{PREFIX}nh"
        MAX_USER = (PREFIX + "123456789012345")[:15]
        OVERLONG_USER = MAX_USER + "0"
        DIRNAME = f"{PREFIX}suite"
        HOME_DIR = f"/{PARTITION}/{DIRNAME}"
        ABS_HOME_DIR = f"/etc/disk_user/{PARTITION}/{DIRNAME}"
        assert len(MAX_USER) == 15 and len(OVERLONG_USER) == 16

        # 一次性凭据：只传给UI和密码安全的FTP probe，绝不记录。
        rw_password = _one_time_password()
        rw_edited_password = _one_time_password()
        ro_password = _one_time_password()
        auxiliary_password = _one_time_password()
        secret_values = [
            rw_password, rw_edited_password, ro_password, auxiliary_password,
        ]

        ui_failures = []
        ssh_failures = []
        global_snapshot: Optional[Dict] = None
        non_test_snapshot: Optional[Dict] = None
        snapshot_valid = False
        mutation_started = False
        prepared_dir = None
        safe_import_path: Optional[str] = None
        export_path = _export_csv_path()
        export_existed = os.path.exists(export_path)
        export_backup = None
        if export_existed:
            try:
                with open(export_path, "rb") as existing:
                    export_backup = existing.read()
            except Exception:
                export_backup = None

        def safe_text(value) -> str:
            text = "" if value is None else str(value)
            for secret in sorted(secret_values, key=len, reverse=True):
                if secret:
                    text = text.replace(secret, "***")
            return text

        def ui_check(label, condition, detail=""):
            ok = bool(condition)
            safe_detail = safe_text(detail)
            conclusion = "符合预期" if ok else (safe_detail or "条件不成立")
            rec.add_detail(f"【页面验证】\n{'✓' if ok else '✗'} {label}：{conclusion}")
            if not ok:
                ui_failures.append(f"页面验证-{label}：{safe_detail or '条件不成立'}")
            return ok

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            label_text = str(label)
            level, separator, item = label_text.partition("-")
            has_level = level.startswith("L") and any(char.isdigit() for char in level)
            section = f"【后端验证·{level}】" if has_level else "【后端验证】"
            check_name = item if has_level and separator else label_text
            try:
                result = verify_func(*args, **kwargs)
                passed = bool(getattr(result, "passed", False))
                symbol = "✓" if passed else ("✗" if must_pass else "⚠")
                message = safe_text(getattr(result, "message", "无验证消息"))
                if not passed and not must_pass:
                    message = f"未通过（警告，不阻断测试）；{message}"
                rec.add_detail(f"{section}\n{symbol} {check_name}：{message}")
                raw = safe_text(getattr(result, "raw_output", "") or "")
                if raw:
                    rec.add_detail(f"【后端数据】\n{raw}")
                print(f"{section} {symbol} {check_name}：{message}", flush=True)
                if must_pass and not passed:
                    ssh_failures.append(f"后端验证-{label_text}：{message}")
                return result
            except Exception as exc:
                symbol = "✗" if must_pass else "⚠"
                impact = "验证异常，本项失败" if must_pass else "验证异常，仅记录警告"
                message = safe_text(exc)
                rec.add_detail(f"{section}\n{symbol} {check_name}：{impact}；{message}")
                if must_pass:
                    ssh_failures.append(f"后端验证-{label_text}异常：{message}")
                return None

        ssh_verify = attach_cmd_recording_to_closure(backend, rec, ssh_verify)

        def require_ui(label, condition, detail=""):
            ok = bool(condition)
            if not ui_check(label, ok, "" if ok else detail):
                pytest.fail(f"安全前置失败: {label}: {detail or '条件不成立'}")

        def require_ssh(label, verify_func, *args, **kwargs):
            result = ssh_verify(label, verify_func, *args, must_pass=True, **kwargs)
            if result is None or not getattr(result, "passed", False):
                pytest.fail(f"安全前置失败: SSH-{label}")
            return result

        def user_expected(permission: str, upload: str, download: str,
                          password: str = None, enabled="yes") -> Dict:
            expected = {
                "enabled": enabled,
                "permission": permission,
                "home_dir": HOME_DIR,
                "upload": upload,
                "download": download,
            }
            if password is not None:
                expected["password"] = password
            return expected

        try:
            with rec.step("步骤1: 保存FTP环境快照并准备独立测试目录", "准备：记录数据库、运行配置、防火墙和非测试用户；验证：本轮随机用户前缀与目录均未被占用，可安全开始测试"):
                backend.connect_router()
                global_snapshot = backend.get_ftp_environment_snapshot([TEST_PORT])
                snapshot_valid = bool(
                    isinstance(global_snapshot, dict) and
                    isinstance(global_snapshot.get("global"), dict) and
                    all(key in global_snapshot["global"]
                        for key in ("open_ftp", "ftp_port", "ftp_access")) and
                    isinstance(global_snapshot.get("runtime_config"), dict) and
                    isinstance(global_snapshot.get("upnp_runtime"), dict) and
                    str(TEST_PORT) in global_snapshot.get("firewall_members", {}) and
                    global_snapshot.get("firewall_set_exists") is True
                )
                require_ui("完整环境快照", snapshot_valid,
                           "DB/conf/测试端口ipset快照不完整，禁止开始变更")
                if export_existed and export_backup is None:
                    pytest.fail("既有FTP导出文件无法备份，禁止开始测试")
                non_test_snapshot = backend.snapshot_ftp_non_test_users(PREFIX)
                require_ssh("唯一前缀初始数量=0", backend.verify_ftp_user_count,
                            PREFIX, expected=0)
                backend.connect_client()
                prepared_dir = require_ssh(
                    "唯一测试目录", backend.prepare_ftp_test_directory,
                    PARTITION, DIRNAME
                )
                mutation_started = True
                require_ui("目录路径", prepared_dir.details.get("home_dir") == HOME_DIR,
                           f"backend返回目录不是{HOME_DIR}")
                page.navigate_to_ftp_server()
                require_ui("唯一前缀UI初始为空", page.clean_test_rules(PREFIX) == 0,
                           "随机前缀不应存在历史UI数据")

            with rec.step("步骤2: 检查FTP页面和新增用户表单", "操作：进入FTP页面并打开新增表单；验证：页签、总开关、设置、搜索、列表、工具按钮、表头和表单字段齐全"):
                page.navigate_to_ftp_server()
                structure = page.get_default_structure()
                ui_check("URL", structure.get("url_ok"), page.page.url)
                ui_check("FTP Tab", structure.get("ftp_tab_active"), "FTP Tab未激活")
                for key in ("switch_present", "settings_present", "search_present", "table_present"):
                    ui_check(f"结构-{key}", structure.get(key), str(structure))
                buttons = "|".join(structure.get("buttons", []))
                for name in ("添加", "导入", "导出"):
                    ui_check(f"按钮-{name}", name in buttons, buttons)
                headers = "|".join(structure.get("headers", []))
                for token in ("用户名", "FTP文件目录", "权限", "操作"):
                    ui_check(f"列-{token}", token in headers, headers)
                ui_check("打开新增表单检查字段", page.open_add_page(), "FTP新增页未打开")
                form_structure = page.get_user_form_structure()
                for field in ("upload_present", "download_present"):
                    ui_check(f"表单-{field}", form_structure.get(field), str(form_structure))
                ui_check("用户名maxlength=15",
                         form_structure.get("username_maxlength") == 15,
                         str(form_structure.get("username_maxlength")))
                ui_check("取消新增表单", page.cancel_user_form(), "未返回FTP列表")

            with rec.step("步骤3: 保存FTP设置并验证取消不生效", "操作：将端口设为2121并允许外网访问，再修改但取消；验证：保存值写入数据库，取消后端口仍为2121"):
                result = page.set_settings(TEST_PORT, True)
                require_ui("设置保存", result.get("success"), result.get("error", ""))
                require_ssh("L1-端口/外网", backend.verify_ftp_global_database,
                            {"ftp_port": TEST_PORT, "ftp_access": 1})
                ui_check("打开设置取消场景", page.open_settings(), "drawer未打开")
                page.fill_ftp_port(2022)
                page.cancel_settings()
                ui_check("重新打开设置", page.open_settings(), "drawer未打开")
                current = page.get_settings()
                ui_check("取消未保存", str(current.get("port")) == str(TEST_PORT), str(current))
                page.cancel_settings()

            with rec.step("步骤4: 启用、关闭并重新启用FTP服务", "操作：依次切换FTP总开关；验证：数据库开关、ik_ftpd进程、2121端口监听和外网防火墙状态同步变化"):
                require_ui("总开关启用", page.set_service_enabled(True), "无法启用FTP")
                require_ssh("L1-open=1", backend.verify_ftp_global_database,
                            {"open_ftp": 1, "ftp_port": TEST_PORT})
                require_ssh("L2-ik_ftpd运行", backend.verify_ftp_daemon,
                            True, port=TEST_PORT)
                require_ssh("L2-2121监听", backend.verify_ftp_listener,
                            TEST_PORT, True)
                require_ssh("L3-WAN允许", backend.verify_ftp_firewall,
                            TEST_PORT, False)
                ui_check("总开关关闭", page.set_service_enabled(False), "无法关闭FTP")
                ssh_verify("L1-open=0", backend.verify_ftp_global_database,
                           {"open_ftp": 0}, must_pass=True)
                ssh_verify("L2-ik_ftpd停止", backend.verify_ftp_daemon,
                           False, must_pass=True)
                ssh_verify("L2-2121无监听", backend.verify_ftp_listener,
                           TEST_PORT, False, must_pass=True)
                require_ui("总开关再启用", page.set_service_enabled(True), "无法恢复启用")
                require_ssh("L2-再启动", backend.verify_ftp_daemon,
                            True, port=TEST_PORT)

            with rec.step("步骤5: 添加FTP读写用户", "操作：新增读写用户并设置上下行速率；验证：列表存在该用户，数据库字段、密码状态和运行时认证配置正确"):
                added = page.add_user(RW_USER, rw_password, "rw", HOME_DIR, "128", "256")
                require_ui("添加RW", added.get("success"), added.get("error", ""))
                page.navigate_to_ftp_server()
                require_ui("RW列表存在", page.rule_exists(RW_USER), RW_USER)
                require_ssh("L1-RW", backend.verify_ftp_user_database, RW_USER,
                            user_expected("rw", "128", "256", rw_password))
                require_ssh("L2-RW运行时", backend.verify_ftp_auth_runtime, RW_USER,
                            user_expected("rw", "128", "256", rw_password), True)

            with rec.step("步骤6: 添加FTP只读用户并核对用户数量", "操作：新增只读用户；验证：列表权限、数据库字段、运行时权限映射和本轮测试用户数量均正确"):
                added = page.add_user(RO_USER, ro_password, "ro", HOME_DIR, "0", "0")
                require_ui("添加RO", added.get("success"), added.get("error", ""))
                page.navigate_to_ftp_server()
                require_ui("RO列表存在", page.rule_exists(RO_USER), RO_USER)
                require_ssh("L1-RO", backend.verify_ftp_user_database, RO_USER,
                            user_expected("ro", "0", "0", ro_password))
                require_ssh("L2-RO运行时", backend.verify_ftp_auth_runtime, RO_USER,
                            user_expected("ro", "0", "0", ro_password), True)
                ssh_verify("L1-前缀计数=2", backend.verify_ftp_user_count,
                           PREFIX, expected=2, must_pass=True)

            with rec.step("步骤7: 搜索FTP用户并清空搜索条件", "操作：分别搜索存在的用户、不存在的关键字，然后清空搜索；验证：结果只显示匹配项、无结果时为空、清空后恢复全部测试用户"):
                page.navigate_to_ftp_server()
                page.search_user(RW_USER)
                ui_check("搜索命中RW", page.rule_exists(RW_USER), RW_USER)
                ui_check("搜索排除RO", not page.rule_exists(RO_USER), RO_USER)
                page.search_user("ftp_t_not_found")
                ui_check("搜索空结果", not page.rule_exists(RW_USER), "不存在关键字仍显示行")
                page.clear_user_search()
                ui_check("清搜索恢复RW", page.rule_exists(RW_USER), RW_USER)
                ui_check("清搜索恢复RO", page.rule_exists(RO_USER), RO_USER)

            with rec.step("步骤8: 编辑FTP读写用户", "操作：更换一次性密码并修改上下行速率；验证：数据库和运行时配置已更新，旧密码失效且新密码可用"):
                rw_original_password = rw_password
                edited = page.update_user(
                    RW_USER, password=rw_edited_password, upload="512", download="768"
                )
                require_ui("编辑RW", edited.get("success"), edited.get("error", ""))
                rw_password = rw_edited_password
                ssh_verify("L1-RW编辑", backend.verify_ftp_user_database, RW_USER,
                           user_expected("rw", "512", "768", rw_password), must_pass=True)
                ssh_verify("L2-RW编辑", backend.verify_ftp_auth_runtime, RW_USER,
                           user_expected("rw", "512", "768", rw_password), True, must_pass=True)
                ssh_verify("L5-旧密码已失效", backend.run_ftp_probe,
                           RW_USER, rw_original_password, TEST_PORT, LAN_HOST, LAN_IFACE,
                           "wrong_password", control_password=rw_password, must_pass=True)

            with rec.step("步骤9: 单独停用并重新启用FTP用户", "操作：对读写用户先停用再启用；验证：列表状态、数据库enabled字段和运行时认证配置同步移除与恢复"):
                page.navigate_to_ftp_server()
                ui_check("行停用RW", page.disable_rule(RW_USER), "停用操作未发起")
                ui_check("RW行显示启用按钮", page.is_user_disabled(RW_USER), "行状态未刷新")
                ssh_verify("L1-RW已停用", backend.verify_ftp_user_database, RW_USER,
                           {"enabled": "no"}, must_pass=True)
                ssh_verify("L2-RW runtime移除", backend.verify_ftp_auth_runtime, RW_USER,
                           expect_present=False, must_pass=True)
                ui_check("行启用RW", page.enable_rule(RW_USER), "启用操作未发起")
                ui_check("RW行显示停用按钮", page.is_user_enabled(RW_USER), "行状态未刷新")
                ssh_verify("L1-RW已启用", backend.verify_ftp_user_database, RW_USER,
                           {"enabled": "yes"}, must_pass=True)
                ssh_verify("L2-RW runtime恢复", backend.verify_ftp_auth_runtime, RW_USER,
                           user_expected("rw", "512", "768", rw_password), True, must_pass=True)

            with rec.step("步骤10: 单独删除FTP用户", "操作：创建一条专用样本后执行单条删除；验证：列表、数据库和运行时认证配置中都不再存在该用户"):
                added = page.add_user(DELETE_USER, auxiliary_password, "rw", HOME_DIR, "0", "0")
                ui_check("添加删除样本", added.get("success"), added.get("error", ""))
                page.navigate_to_ftp_server()
                ui_check("单条删除", page.delete_rule(DELETE_USER), DELETE_USER)
                ssh_verify("L1-删除无数据", backend.verify_ftp_user_database,
                           DELETE_USER, must_exist=False, must_pass=True)
                ssh_verify("L2-删除无runtime", backend.verify_ftp_auth_runtime,
                           DELETE_USER, expect_present=False, must_pass=True)

            with rec.step("步骤11: 批量停用、启用并删除FTP用户", "操作：对两个独立样本依次执行批量停用、启用和删除；验证：每个阶段的列表状态、数据库和运行时配置完全一致"):
                for username in BATCH_USERS:
                    added = page.add_user(username, auxiliary_password, "rw", HOME_DIR, "0", "0")
                    ui_check(f"批量样本添加-{username}", added.get("success"), added.get("error", ""))
                page.navigate_to_ftp_server()
                ui_check("批量停用", page.batch_disable_users(BATCH_USERS), "批量停用未发起")
                for username in BATCH_USERS:
                    ui_check(f"批量停用UI-{username}", page.is_user_disabled(username), username)
                    ssh_verify(f"L1-批量停用-{username}", backend.verify_ftp_user_database,
                               username, {"enabled": "no"}, must_pass=True)
                    ssh_verify(f"L2-批量停用-{username}", backend.verify_ftp_auth_runtime,
                               username, expect_present=False, must_pass=True)
                ui_check("批量启用", page.batch_enable_users(BATCH_USERS), "批量启用未发起")
                for username in BATCH_USERS:
                    ui_check(f"批量启用UI-{username}", page.is_user_enabled(username), username)
                    ssh_verify(f"L1-批量启用-{username}", backend.verify_ftp_user_database,
                               username, {"enabled": "yes"}, must_pass=True)
                    ssh_verify(f"L2-批量启用-{username}", backend.verify_ftp_auth_runtime,
                               username, {"permission": "rw", "home_dir": HOME_DIR,
                                          "password": auxiliary_password}, True,
                               must_pass=True)
                ui_check("批量删除", page.batch_delete_users(BATCH_USERS), "批量删除未发起")
                for username in BATCH_USERS:
                    ui_check(f"批量删除UI-{username}", not page.rule_exists(username), username)
                    ssh_verify(f"L1-批量删除-{username}", backend.verify_ftp_user_database,
                               username, must_exist=False, must_pass=True)
                    ssh_verify(f"L2-批量删除-{username}", backend.verify_ftp_auth_runtime,
                               username, expect_present=False, must_pass=True)
                ssh_verify("L4-批量后一致性", backend.verify_ftp_runtime_consistency,
                           PREFIX, must_pass=True)

            with rec.step("步骤12: 验证FTP用户名边界和异常输入", "操作：提交15字符用户名，输入16字符用户名但取消，并尝试空用户名、空密码、空目录和重复用户；验证：合法边界可保存，超长输入被限制，所有非法数据均不落库"):
                boundary = page.add_user(MAX_USER, auxiliary_password, "rw", HOME_DIR, "0", "0")
                require_ui("15字符用户名", boundary.get("success"), boundary.get("error", ""))
                ssh_verify("L1-15字符", backend.verify_ftp_user_database,
                           MAX_USER, {"permission": "rw", "password": auxiliary_password},
                           must_pass=True)
                page.navigate_to_ftp_server()
                ui_check("删除边界用户", page.delete_rule(MAX_USER), MAX_USER)
                ssh_verify("L1-15字符删除", backend.verify_ftp_user_database,
                           MAX_USER, must_exist=False, must_pass=True)
                ui_check("打开16字符边界表单", page.open_add_page(), "FTP新增页未打开")
                ui_check("填写16字符用户名", page.fill_username(OVERLONG_USER), "用户名输入失败")
                truncated_username = page.get_username_value()
                ui_check("16字符被截断到15字符",
                         truncated_username == OVERLONG_USER[:15] and len(truncated_username) == 15,
                         f"实际长度={len(truncated_username)}")
                ui_check("16字符场景取消不提交", page.cancel_user_form(), "未返回FTP列表")
                ssh_verify("L1-16字符截断值未落库", backend.verify_ftp_user_database,
                           MAX_USER, must_exist=False, must_pass=True)
                invalid_cases = [
                    ("空用户名", dict(username="", password=auxiliary_password, home_dir=HOME_DIR)),
                    ("空密码", dict(username=NO_PASSWORD_USER, password="", home_dir=HOME_DIR)),
                    ("空主目录", dict(username=NO_HOME_USER, password=auxiliary_password, home_dir=None)),
                    ("重复用户", dict(username=RW_USER, password=auxiliary_password, home_dir=HOME_DIR)),
                ]
                for label, kwargs in invalid_cases:
                    invalid = page.try_add_invalid(**kwargs)
                    ui_check(f"异常拦截-{label}", invalid.get("blocked"), invalid.get("error", ""))
                    if label == "重复用户":
                        ssh_verify("L1-重复用户未改写原记录", backend.verify_ftp_user_database,
                                   RW_USER, user_expected("rw", "512", "768", rw_password),
                                   must_pass=True)
                    elif kwargs["username"]:
                        ssh_verify(f"L1-{label}未落库", backend.verify_ftp_user_database,
                                   kwargs["username"], must_exist=False, must_pass=True)
                    ssh_verify(f"L1-{label}后计数仍为2", backend.verify_ftp_user_count,
                               PREFIX, expected=2, must_pass=True)
                ssh_verify("L1-异常后计数=2", backend.verify_ftp_user_count,
                           PREFIX, expected=2, must_pass=True)

            with rec.step("步骤13: 验证FTP端口异常输入", "操作：依次输入0、系统保留端口600和超出范围的65536；验证：三个非法端口都被页面拦截且数据库不变，最后恢复为2121"):
                page.navigate_to_ftp_server()
                for bad_port in (0, 600, 65536):
                    invalid = page.try_invalid_port(bad_port)
                    ui_check(f"非法端口-{bad_port}", invalid.get("blocked"), invalid.get("error", ""))
                    ssh_verify(f"L1-非法端口{bad_port}未落库",
                               backend.verify_ftp_global_database,
                               {"ftp_port": TEST_PORT, "ftp_access": 1, "open_ftp": 1},
                               must_pass=True)
                repaired = page.set_settings(TEST_PORT, True)
                ui_check("非法端口后恢复", repaired.get("success"), repaired.get("error", ""))
                ssh_verify("L1-端口恢复2121", backend.verify_ftp_global_database,
                           {"ftp_port": TEST_PORT, "ftp_access": 1, "open_ftp": 1}, must_pass=True)

            with rec.step("步骤14: 导出FTP CSV并检查文件格式", "操作：导出CSV配置文件；验证：文件为本轮新生成、严格包含8列，并仅保留一条脱敏测试记录作为后续导入源"):
                page.navigate_to_ftp_server()
                if os.path.exists(export_path):
                    os.remove(export_path)
                export_started_at = time.time()
                exported = page.export_rules(export_format="csv")
                require_ui("CSV导出", exported, "导出弹窗/下载失败")
                fresh_export = (
                    os.path.exists(export_path) and
                    os.path.getmtime(export_path) >= export_started_at - 1
                )
                require_ui("本轮导出文件存在", fresh_export, export_path)
                safe_import_path, headers, row_count, error = _build_safe_import(export_path, RW_USER)
                require_ui("CSV表头8列", headers == EXPORT_HEADERS, str(headers))
                require_ui("安全筛选仅1行", row_count == 1 and bool(safe_import_path), error)
                rec.add_detail("导出内容未输出；安全导入文件仅含表头和1个测试用户")

            with rec.step("步骤15: 以追加方式导入FTP配置", "操作：先删除读写用户，再在不清空现有配置的前提下导入CSV；验证：读写用户恢复，只读用户仍保留，数据库和运行时配置正确"):
                page.navigate_to_ftp_server()
                ui_check("导入前删RW", page.delete_rule(RW_USER), RW_USER)
                ssh_verify("L1-导入前RW无", backend.verify_ftp_user_database,
                           RW_USER, must_exist=False, must_pass=True)
                imported = bool(safe_import_path) and page.import_rules(
                    safe_import_path, clear_existing=False
                )
                require_ui("安全追加导入", imported, "清空选项未被明确保持关闭或上传失败")
                page.navigate_to_ftp_server()
                ui_check("导入后RW可见", page.rule_exists(RW_USER), RW_USER)
                ui_check("导入保留RO", page.rule_exists(RO_USER), RO_USER)
                ssh_verify("L1-导入RW", backend.verify_ftp_user_database, RW_USER,
                           user_expected("rw", "512", "768", rw_password), must_pass=True)
                ssh_verify("L2-导入RW", backend.verify_ftp_auth_runtime, RW_USER,
                           user_expected("rw", "512", "768", rw_password), True, must_pass=True)
                ssh_verify("L1-导入后计数=2", backend.verify_ftp_user_count,
                           PREFIX, expected=2, must_pass=True)
                ssh_verify("L4-导入未影响非测试用户",
                           backend.verify_ftp_non_test_users_unchanged,
                           PREFIX, non_test_snapshot, must_pass=True)

            with rec.step("步骤16: 检查FTP页面右下角帮助入口", "操作：点击帮助按钮并关闭新打开的页面；验证：链接指向ikuai8.com的601号文章，关闭后不留下多余标签页"):
                page.navigate_to_ftp_server()
                help_result = page.verify_help_entry()
                help_url = help_result.get("url", "")
                ui_check("帮助按钮可点", help_result.get("clicked"), str(help_result.get("error", "")))
                ui_check("帮助popup打开", help_result.get("popup_opened"), help_url)
                ui_check("帮助URL域名", "ikuai8.com" in help_url, help_url)
                ui_check("帮助URL文章", "id=601" in help_url, help_url)
                ui_check("帮助无孤儿Tab", help_result.get("no_orphan"), "popup未关闭")

            with rec.step("步骤17: 综合核对FTP数据库、运行配置与服务状态", "操作：执行ftp_server.sh init重建底层配置；验证：数据库、认证与服务配置、ik_ftpd进程、2121监听和外网防火墙完全一致"):
                ssh_verify("L1-全局", backend.verify_ftp_global_database,
                           {"open_ftp": 1, "ftp_port": TEST_PORT, "ftp_access": 1}, must_pass=True)
                ssh_verify("L1-用户计数", backend.verify_ftp_user_count,
                           PREFIX, expected=2, must_pass=True)
                ssh_verify("L2-进程", backend.verify_ftp_daemon,
                           True, port=TEST_PORT, must_pass=True)
                ssh_verify("L2-监听", backend.verify_ftp_listener,
                           TEST_PORT, True, must_pass=True)
                ssh_verify("L3-外网策略", backend.verify_ftp_firewall,
                           TEST_PORT, False, must_pass=True)
                ssh_verify("L4-运行时一致性", backend.verify_ftp_runtime_consistency,
                           PREFIX, must_pass=True)
                ssh_verify("L4-脚本init重建", backend.verify_ftp_reinit,
                           RW_USER, TEST_PORT, must_pass=True)

            with rec.step("步骤18: 从内网实际访问FTP服务", "操作：读写用户执行列目录、上传、下载和删除，并测试错误密码与只读用户写入；验证：文件SHA256一致，正常操作成功，错误密码和只读写入被拒绝"):
                ssh_verify("L5-RW LIST", backend.run_ftp_probe,
                           RW_USER, rw_password, TEST_PORT, LAN_HOST, LAN_IFACE, "list",
                           must_pass=True)
                ssh_verify("L5-RW上传下载", backend.run_ftp_probe,
                           RW_USER, rw_password, TEST_PORT, LAN_HOST, LAN_IFACE,
                           "upload_download", must_pass=True)
                ssh_verify("L5-错误密码拒绝", backend.run_ftp_probe,
                           RW_USER, rw_password, TEST_PORT, LAN_HOST, LAN_IFACE,
                           "wrong_password", must_pass=True)
                ssh_verify("L5-RO LIST", backend.run_ftp_probe,
                           RO_USER, ro_password, TEST_PORT, LAN_HOST, LAN_IFACE, "list",
                           must_pass=True)
                ssh_verify("L5-RO上传拒绝", backend.run_ftp_probe,
                           RO_USER, ro_password, TEST_PORT, LAN_HOST, LAN_IFACE,
                           "upload_denied", cleanup_username=RW_USER,
                           cleanup_password=rw_password, must_pass=True)

            with rec.step("步骤19: 验证FTP外网访问开关", "操作：关闭外网访问后分别从内外网连接，再重新允许外网；验证：关闭时外网被拒绝但内网仍可用，恢复后外网可正常列目录"):
                wan_target = require_ssh(
                    "L0-WAN探测拓扑", backend.verify_local_service_wan_target,
                    WAN_IFACE,
                )
                wan_host = wan_target.details["host"]
                require_ssh(
                    "L5-WAN允许基线", backend.run_ftp_probe,
                    RW_USER, rw_password, TEST_PORT, wan_host, WAN_IFACE, "list",
                )
                page.navigate_to_ftp_server()
                restricted = page.set_settings(TEST_PORT, False)
                require_ui("关闭外网访问", restricted.get("success"), restricted.get("error", ""))
                require_ssh("L1-access=0", backend.verify_ftp_global_database,
                            {"ftp_access": 0, "open_ftp": 1})
                require_ssh("L3-WAN端口进DROP", backend.verify_ftp_firewall,
                            TEST_PORT, True)
                require_ssh("L2-限制设置后服务稳定", backend.verify_ftp_daemon,
                            True, port=TEST_PORT)
                ssh_verify("L5-限制时LAN仍通", backend.run_ftp_probe,
                           RW_USER, rw_password, TEST_PORT, LAN_HOST, LAN_IFACE, "list",
                           must_pass=True)
                ssh_verify("L5-WAN拒绝", backend.run_ftp_probe,
                           RW_USER, rw_password, TEST_PORT, wan_host, WAN_IFACE,
                           "connect_fail", must_pass=True)
                allowed = page.set_settings(TEST_PORT, True)
                require_ui("恢复外网访问", allowed.get("success"), allowed.get("error", ""))
                ssh_verify("L3-WAN端口移出DROP", backend.verify_ftp_firewall,
                           TEST_PORT, False, must_pass=True)
                require_ssh("L2-允许设置后服务稳定", backend.verify_ftp_daemon,
                            True, port=TEST_PORT)
                ssh_verify("L5-WAN LIST恢复", backend.run_ftp_probe,
                           RW_USER, rw_password, TEST_PORT, wan_host, WAN_IFACE, "list",
                           must_pass=True)

            with rec.step("步骤20: 验证FTP总开关关闭后拒绝连接", "操作：关闭FTP服务并从内网发起真实连接；验证：数据库开关关闭、ik_ftpd进程与2121监听消失，内网连接明确失败"):
                page.navigate_to_ftp_server()
                require_ui("关闭FTP服务", page.set_service_enabled(False), "总开关关闭失败")
                require_ssh("L1-总开关关", backend.verify_ftp_global_database,
                            {"open_ftp": 0})
                require_ssh("L2-ik_ftpd关", backend.verify_ftp_daemon, False)
                require_ssh("L2-2121关", backend.verify_ftp_listener,
                            TEST_PORT, False)
                ssh_verify("L5-关闭后LAN拒绝", backend.run_ftp_probe,
                           RW_USER, rw_password, TEST_PORT, LAN_HOST, LAN_IFACE,
                           "connect_fail", must_pass=True)

            with rec.step("步骤21: 删除最终FTP用户并检查无残留", "操作：重新启用服务后逐条删除读写和只读用户；验证：本轮前缀在列表、数据库和运行时配置中的数量均为0"):
                require_ui("删除前再启服务", page.set_service_enabled(True), "无法再启用")
                for username in (RW_USER, RO_USER):
                    page.navigate_to_ftp_server()
                    ui_check(f"最终删除-{username}", page.delete_rule(username), username)
                    ssh_verify(f"L1-最终删除-{username}", backend.verify_ftp_user_database,
                               username, must_exist=False, must_pass=True)
                    ssh_verify(f"L2-最终删除-{username}", backend.verify_ftp_auth_runtime,
                               username, expect_present=False, must_pass=True)
                ssh_verify("L1-最终计数=0", backend.verify_ftp_user_count,
                           PREFIX, expected=0, must_pass=True)
                ssh_verify("L4-最终无残留", backend.verify_ftp_runtime_consistency,
                           PREFIX, must_pass=True)

        finally:
            with rec.step("步骤22: 清理测试数据并恢复FTP原始环境", "清理：删除本轮用户前缀、测试目录和临时CSV；恢复与验证：还原测试前数据库、运行配置、进程、监听、防火墙和本地文件状态"):
                if mutation_started:
                    try:
                        page.navigate_to_ftp_server()
                        removed = page.clean_test_rules(PREFIX)
                        rec.add_detail(f"[finally UI清理] 删除{removed}条本轮前缀用户")
                    except Exception as exc:
                        ui_failures.append(f"finally UI清理异常: {str(exc)[:80]}")
                    try:
                        cleanup_msg = backend.cleanup_ftp_test(
                            PREFIX, test_dir=prepared_dir if prepared_dir is not None else ABS_HOME_DIR
                        )
                        rec.add_detail(f"[finally backend清理] {cleanup_msg}")
                    except Exception as exc:
                        ssh_failures.append(f"finally backend清理异常: {str(exc)[:80]}")
                    ssh_verify("finally-测试残留全清", backend.verify_ftp_test_artifacts_absent,
                               PREFIX, ABS_HOME_DIR, TEST_PORT, must_pass=True)
                    if snapshot_valid and global_snapshot:
                        ssh_verify("finally-恢复全环境快照", backend.restore_ftp_global,
                                   global_snapshot, must_pass=True)
                        ssh_verify("finally-全局DB复验", backend.verify_ftp_global_database,
                                   global_snapshot["global"], must_pass=True)
                        ssh_verify("finally-L4一致性", backend.verify_ftp_runtime_consistency,
                                   PREFIX, must_pass=True)
                        if non_test_snapshot is not None:
                            ssh_verify("finally-非测试用户未变化",
                                       backend.verify_ftp_non_test_users_unchanged,
                                       PREFIX, non_test_snapshot, must_pass=True)
                    else:
                        ssh_failures.append("已开始变更但无有效环境快照，无法原样恢复")
                else:
                    rec.add_detail("[finally] 尚未开始任何设备变更，跳过设备清理/恢复")
                try:
                    if safe_import_path and os.path.exists(safe_import_path):
                        os.remove(safe_import_path)
                    if export_existed and export_backup is not None:
                        os.makedirs(os.path.dirname(export_path), exist_ok=True)
                        with open(export_path, "wb") as target:
                            target.write(export_backup)
                    elif not export_existed and os.path.exists(export_path):
                        os.remove(export_path)
                    rec.add_detail("[finally CSV] 一次性密码文件已删除/原导出文件已恢复")
                    if safe_import_path:
                        ui_check("敏感导入CSV已删除", not os.path.exists(safe_import_path),
                                 safe_import_path)
                    expected_export_state = export_existed
                    ui_check("导出文件状态已恢复",
                             os.path.exists(export_path) == expected_export_state,
                             export_path)
                except Exception as exc:
                    ui_failures.append(f"finally CSV恢复异常: {str(exc)[:80]}")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(
                f"[FTP断言] 共{len(all_failures)}项失败 "
                f"(SSH={len(ssh_failures)}, UI={len(ui_failures)})",
                flush=True,
            )
            for failure in all_failures[:30]:
                print(f"  - {failure}", flush=True)
        assert not all_failures, (
            f"FTP服务L1-L5综合验证失败({len(all_failures)}项): "
            + "; ".join(all_failures[:20])
        )
