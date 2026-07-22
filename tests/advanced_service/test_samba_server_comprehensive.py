"""
高级服务 > 本地服务 > Samba服务 L1-L5 综合测试。

单一 GUI node 覆盖页面结构、设置/发现服务、总开关、用户与多共享 CRUD、
搜索/排序能力、异常边界、CSV/TXT 安全导入导出、文件管理/帮助 popup，及
DB→运行时文件→进程/监听→WAN 防火墙→真实 SMB 数据面的完整验证。

安全约束：
- 用户名/共享名均使用每轮随机 ``smb_t_<token>_`` 命名空间，且不超过15字符。
- 密码只在内存和秘密 stdin 脚本中传递，不写常量、不进入报告/stdout/命令日志。
- CSV/TXT 导出含解密后的明文密码；仅筛选一个测试用户用于 append=1 导入，
  畸形导入文件不含凭据，finally 覆盖删除敏感文件并按字节恢复原有导出文件。
- 任何设备变更前必须取得全环境和非测试用户快照；finally 精确清理并原样恢复。
"""

from __future__ import annotations

import csv
import os
import secrets
import string
import tempfile
import time
from typing import Dict, Iterable, List, Optional, Tuple

import pytest

from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.advanced_service, pytest.mark.samba_server]

PARTITION = "666"
LAN_HOST, LAN_IFACE = "192.168.148.1", "ens11"
WAN_HOST, WAN_IFACE = "10.66.0.150", "enp2s0"

# smbd.sh -> export_txt(config.db, smbd_dir, ...), tagname 被明确排除。
# passwd 为解密后的明文，严禁打印任何 CSV 行。
EXPORT_HEADERS = [
    "id", "enabled", "username", "passwd", "name",
    "perm", "guest", "browseable", "home_dir",
]


def _one_time_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _truthy(value) -> bool:
    return str(value).strip().lower() in {
        "1", "yes", "true", "on", "enable", "enabled",
    }


def _export_path(extension: str) -> str:
    config = get_config()
    configured = config.test_data.get_export_path(
        "samba_server", config.get_project_root()
    )
    return os.path.splitext(configured)[0] + f".{extension.lower()}"


def _export_csv_path() -> str:
    return _export_path("csv")


def _validate_txt_export(
    path: str,
    username: str,
    expected_share_names: Iterable[str],
) -> Tuple[bool, str]:
    """验证TXT的逐行 ``key=value`` 契约；任何行内容和字段值都不得返回。"""
    try:
        target_rows = 0
        row_count = 0
        expected_names = set(expected_share_names)
        with open(path, "r", encoding="utf-8-sig", newline="") as source:
            for line_number, raw_line in enumerate(source, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                row_count += 1
                row: Dict[str, str] = {}
                keys: List[str] = []
                for token in line.split():
                    if "=" not in token:
                        return False, f"第{line_number}行存在非key=value字段"
                    key, value = token.split("=", 1)
                    if key in row:
                        return False, f"第{line_number}行存在重复字段"
                    keys.append(key)
                    row[key] = value
                if keys != EXPORT_HEADERS:
                    return False, (
                        f"第{line_number}行字段契约不符: "
                        f"实际字段数={len(keys)}, 期望={len(EXPORT_HEADERS)}"
                    )
                if not row.get("passwd"):
                    return False, f"第{line_number}行密码字段为空"
                if row.get("username") == username:
                    target_rows += 1
                    names = {
                        item for item in row.get("name", "").split(",") if item
                    }
                    share_count = len(names)
                    if names != expected_names:
                        return False, "目标用户TXT多共享映射不符"
                    if len(row.get("browseable", "").split(",")) != share_count:
                        return False, "目标用户TXT browseable映射数量不符"
                    if len(row.get("home_dir", "").split(",")) != share_count:
                        return False, "目标用户TXT home_dir映射数量不符"
        if row_count == 0:
            return False, "TXT导出无数据行"
        if target_rows != 1:
            return False, f"目标测试用户行数应为1，实际={target_rows}"
        return True, f"字段数=9，导出行数={row_count}，目标用户行数=1"
    except Exception as exc:
        return False, str(exc)[:120]


def _secure_remove(path: Optional[str]) -> None:
    """尽力覆盖后删除本轮含明文密码的本地文件。"""
    if not path or not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as stream:
            chunk = b"\x00" * 65536
            remaining = size
            while remaining > 0:
                block = chunk if remaining >= len(chunk) else chunk[:remaining]
                stream.write(block)
                remaining -= len(block)
            stream.flush()
            try:
                os.fsync(stream.fileno())
            except OSError:
                pass
    except OSError:
        pass
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _build_safe_import(
    export_path: str,
    username: str,
    expected_share_names: Iterable[str],
) -> Tuple[Optional[str], List[str], int, str]:
    """只回灌一个测试用户；绝不返回、打印或记录 CSV 行内容。"""
    try:
        with open(export_path, "r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            headers = list(reader.fieldnames or [])
            rows = [row for row in reader if row.get("username") == username]
        if headers != EXPORT_HEADERS:
            return None, headers, len(rows), "CSV表头不符合Samba导出契约"
        if len(rows) != 1:
            return None, headers, len(rows), f"筛选用户行数应为1，实际{len(rows)}"
        exported_names = {
            item.strip() for item in str(rows[0].get("name", "")).split(",")
            if item.strip()
        }
        if exported_names != set(expected_share_names):
            return None, headers, len(rows), "导出行的多共享逗号映射不符合预期"
        os.makedirs(os.path.dirname(export_path), exist_ok=True)
        fd, safe_path = tempfile.mkstemp(
            prefix="smb_t_import_", suffix=".csv",
            dir=os.path.dirname(export_path),
        )
        os.close(fd)
        try:
            os.chmod(safe_path, 0o600)
        except OSError:
            pass
        with open(safe_path, "w", encoding="utf-8-sig", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=headers)
            writer.writeheader()
            writer.writerow(rows[0])
        return safe_path, headers, len(rows), ""
    except Exception as exc:  # 文件解析错误不应阻断 finally
        return None, [], 0, str(exc)[:120]


def _build_malformed_import(directory: str, extension: str) -> str:
    """创建无凭据的畸形导入文件，用于验证服务端拒绝和状态不变。"""
    os.makedirs(directory, exist_ok=True)
    fd, path = tempfile.mkstemp(
        prefix="smb_t_bad_", suffix=f".{extension.lower()}", dir=directory,
    )
    os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with open(path, "w", encoding="utf-8-sig", newline="") as target:
        target.write("NOT_A_SAMBA_HEADER\n")
    return path


class TestSambaServerComprehensive:
    """Samba 服务 UI + L1-L5 单节点综合验证。"""

    def test_samba_server_comprehensive(
        self, samba_server_page_logged_in, step_recorder: StepRecorder, request
    ):
        page = samba_server_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("Samba L1-L5综合测试必须启用SSH backend_verifier")

        token = secrets.token_hex(2)
        prefix = f"smb_t_{token}_"
        workgroup = f"SMB{token.upper()}"
        cancel_workgroup = f"TMP{token.upper()}"

        rw_user = f"{prefix}rw"
        ro_user = f"{prefix}ro"
        delete_user = f"{prefix}del"
        batch_users = (f"{prefix}b1", f"{prefix}b2")
        max_user = (prefix + "123456789012345")[:15]
        overlong_user = max_user + "0"

        invalid_users = {
            "no_password": f"{prefix}np",
            "no_share": f"{prefix}ns",
            "empty_share": f"{prefix}es",
            "empty_dir": f"{prefix}ed",
            "dup_share": f"{prefix}ds",
            "cross_share": f"{prefix}cs",
            "long_password": f"{prefix}lp",
        }

        rw_share = f"{prefix}rw"
        rw_hidden_share = f"{prefix}rh"
        edited_share = f"{prefix}re"
        ro_share = f"{prefix}ro"
        delete_share = f"{prefix}del"
        batch_shares = (f"{prefix}b1", f"{prefix}b2")
        max_share = (prefix + "m123456789012345")[:15]

        dir_names = {
            "rw": f"{prefix}rw",
            "rw_hidden": f"{prefix}rh",
            "ro": f"{prefix}ro",
            "delete": f"{prefix}del",
            "batch1": f"{prefix}b1",
            "batch2": f"{prefix}b2",
            "max": f"{prefix}max",
        }
        homes = {key: f"/{PARTITION}/{value}" for key, value in dir_names.items()}
        absolute_dirs = [
            f"/etc/disk_user/{PARTITION}/{name}" for name in dir_names.values()
        ]

        rw_shares = [
            {"name": rw_share, "home_dir": homes["rw"], "browseable": True},
            {
                "name": rw_hidden_share,
                "home_dir": homes["rw_hidden"],
                "browseable": False,
            },
        ]
        ro_shares = [
            {"name": ro_share, "home_dir": homes["ro"], "browseable": False},
        ]

        all_test_names = [
            rw_user, ro_user, delete_user, *batch_users, max_user,
            *invalid_users.values(), rw_share, rw_hidden_share, ro_share,
            edited_share, delete_share, *batch_shares, max_share,
        ]
        assert len(prefix) < 15
        assert len(max_user) == 15 and len(overlong_user) == 16
        assert len(max_share) == 15
        assert all(len(value) <= 15 for value in all_test_names)

        rw_password = _one_time_password()
        rw_edited_password = _one_time_password()
        ro_password = _one_time_password()
        auxiliary_password = _one_time_password()
        wrong_password = _one_time_password()
        overlong_password = "A" * 71
        secret_values = [
            rw_password, rw_edited_password, ro_password,
            auxiliary_password, wrong_password, overlong_password,
        ]

        ui_failures: List[str] = []
        ssh_failures: List[str] = []
        global_snapshot: Optional[Dict] = None
        non_test_snapshot: Optional[Dict] = None
        baseline_firewall_members: Dict[str, bool] = {}
        allow_uses_baseline_firewall = True
        snapshot_valid = False
        mutation_started = False
        safe_import_path: Optional[str] = None
        malformed_import_paths: List[str] = []
        prepared_absolute_dirs = list(absolute_dirs)
        prepared_resolved_dirs: List[str] = []
        page_structure: Dict = {}

        export_path = _export_csv_path()
        export_existed = os.path.exists(export_path)
        export_backup: Optional[bytes] = None
        if export_existed:
            try:
                with open(export_path, "rb") as existing:
                    export_backup = existing.read()
            except OSError:
                export_backup = None

        txt_export_path = _export_path("txt")
        txt_export_existed = os.path.exists(txt_export_path)
        txt_export_backup: Optional[bytes] = None
        if txt_export_existed:
            try:
                with open(txt_export_path, "rb") as existing:
                    txt_export_backup = existing.read()
            except OSError:
                txt_export_backup = None

        def restore_local_export(
            path: str, existed: bool, backup: Optional[bytes]
        ) -> bool:
            """覆盖删除本轮导出，并按字节恢复测试前本地文件状态。"""
            if existed and backup is None:
                return False
            _secure_remove(path)
            if not existed:
                return not os.path.exists(path)
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as target:
                    target.write(backup or b"")
                with open(path, "rb") as restored:
                    return restored.read() == (backup or b"")
            except OSError:
                return False

        def safe_text(value) -> str:
            text = "" if value is None else str(value)
            for secret in sorted(secret_values, key=len, reverse=True):
                if secret:
                    text = text.replace(secret, "***")
            return text

        def result_ok(result, key: str = "success") -> bool:
            if isinstance(result, dict):
                return bool(result.get(key))
            return bool(result)

        def result_error(result) -> str:
            if isinstance(result, dict):
                return safe_text(result.get("error", ""))
            return ""

        def ui_check(label, condition, detail=""):
            ok = bool(condition)
            safe_detail = safe_text(detail)
            conclusion = "符合预期" if ok else (safe_detail or "条件不成立")
            rec.add_detail(f"【页面验证】\n{'✓' if ok else '✗'} {label}：{conclusion}")
            if not ok:
                ui_failures.append(f"页面验证-{label}：{safe_detail or '条件不成立'}")
            return ok

        def require_ui(label, condition, detail=""):
            if not ui_check(label, condition, detail):
                pytest.fail(f"安全前置失败: {label}: {safe_text(detail) or '条件不成立'}")

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

        def require_ssh(label, verify_func, *args, **kwargs):
            result = ssh_verify(label, verify_func, *args, must_pass=True, **kwargs)
            if result is None or not getattr(result, "passed", False):
                pytest.fail(f"安全前置失败: SSH-{label}")
            return result

        def expected_user(
            permission: str,
            guest: bool,
            shares: Iterable[Dict],
            password: Optional[str] = None,
            enabled: str = "yes",
        ) -> Dict:
            expected = {
                "enabled": enabled,
                "permission": permission,
                "guest": "yes" if guest else "no",
                "shares": [
                    {
                        "name": item["name"],
                        "home_dir": item["home_dir"],
                        "browseable": (
                            "yes" if _truthy(item.get("browseable")) else "no"
                        ),
                    }
                    for item in shares
                ],
            }
            if password is not None:
                expected["password"] = password
            return expected

        def verify_runtime_consistency(prefix_value: Optional[str] = None):
            expected_members = (
                baseline_firewall_members
                if allow_uses_baseline_firewall else None
            )
            last_result = None
            # Samba add/edit/up/down all trigger an asynchronous stop -> truncate ->
            # regenerate -> start sequence.  During that short window smb.conf can
            # be syntactically valid but still miss a later share.  Require a stable
            # result, while preserving the final failure if it never converges.
            for attempt in range(5):
                last_result = backend.verify_samba_runtime_consistency(
                    prefix_value,
                    expected_firewall_members=expected_members,
                )
                if getattr(last_result, "passed", False):
                    return last_result
                if attempt < 4:
                    time.sleep(0.5)
            return last_result

        verify_runtime_consistency.__report_verifier__ = backend.verify_samba_runtime_consistency

        try:
            with rec.step(
                "步骤1: 保存Samba环境快照并准备独立测试目录",
                "准备：记录数据库、4个运行配置文件、进程、监听、8项外网端口防火墙和非测试用户；验证：随机前缀、共享名和目录均未被占用",
            ):
                backend.connect_router()
                global_snapshot = backend.get_samba_environment_snapshot()
                snapshot_valid = bool(
                    isinstance(global_snapshot, dict)
                    and isinstance(global_snapshot.get("global"), dict)
                    and all(
                        key in global_snapshot["global"]
                        for key in ("enabled", "workgroup", "wsdd2", "access")
                    )
                    and isinstance(global_snapshot.get("runtime_files"), dict)
                    and isinstance(global_snapshot.get("firewall_members"), dict)
                )
                require_ui(
                    "完整环境快照", snapshot_valid,
                    "Samba DB/runtime/firewall快照不完整，禁止开始变更",
                )
                baseline_firewall_members = dict(
                    global_snapshot.get("firewall_members") or {}
                )
                if export_existed and export_backup is None:
                    pytest.fail("既有Samba CSV导出文件无法备份，禁止开始测试")
                if txt_export_existed and txt_export_backup is None:
                    pytest.fail("既有Samba TXT导出文件无法备份，禁止开始测试")
                non_test_snapshot = backend.snapshot_samba_non_test_users(prefix)
                require_ssh(
                    "唯一前缀初始数量=0",
                    backend.verify_samba_user_count,
                    prefix,
                    expected=0,
                )
                backend.connect_client()
                mutation_started = True
                prepared = require_ssh(
                    "唯一测试目录集合",
                    backend.prepare_samba_test_directories,
                    PARTITION,
                    list(dir_names.values()),
                )
                details = getattr(prepared, "details", {}) or {}
                returned_homes = set(details.get("home_dirs") or [])
                returned_abs = list(details.get("absolute_dirs") or [])
                returned_resolved = list(details.get("resolved_dirs") or [])
                require_ui(
                    "共享目录路径集合",
                    set(homes.values()).issubset(returned_homes),
                    f"backend返回目录数={len(returned_homes)}",
                )
                if returned_abs:
                    prepared_absolute_dirs = returned_abs
                if returned_resolved:
                    prepared_resolved_dirs = returned_resolved
                page.navigate_to_samba_server()
                require_ui(
                    "唯一前缀UI初始为空",
                    page.clean_test_rules(prefix) == 0,
                    "随机前缀不应存在历史UI数据",
                )

            with rec.step(
                "步骤2: 检查Samba页面、用户表单和共享子表单",
                "操作：进入Samba页面，依次打开新增用户和新增共享表单；验证：页签、开关、设置、工具栏、6列表头、默认权限以及用户与共享字段齐全",
            ):
                page.navigate_to_samba_server()
                page_structure = page.get_default_structure()
                ui_check("URL", page_structure.get("url_ok"), page.page.url)
                ui_check(
                    "Samba Tab", page_structure.get("samba_tab_active"),
                    "Samba Tab未激活",
                )
                for key in (
                    "switch_present", "settings_present", "search_present",
                    "table_present",
                ):
                    ui_check(f"结构-{key}", page_structure.get(key), str(page_structure))
                buttons = "|".join(page_structure.get("buttons", []))
                for name in ("添加", "导入", "导出"):
                    ui_check(f"按钮-{name}", name in buttons, buttons)
                headers = "|".join(page_structure.get("headers", []))
                for token_text in (
                    "用户名", "共享名", "共享目录", "匿名访问", "权限", "操作",
                ):
                    ui_check(f"列-{token_text}", token_text in headers, headers)
                require_ui("打开新增页", page.open_add_page(), "Samba新增页未打开")
                form = page.get_user_form_structure()
                ui_check("用户名maxlength=15", form.get("username_maxlength") == 15, str(form))
                for key in (
                    "password_present", "permission_present", "guest_present",
                    "share_add_present", "file_manager_present",
                ):
                    ui_check(f"主表单-{key}", form.get(key), str(form))
                ui_check(
                    "默认权限RO",
                    str(form.get("permission_value", "")).strip().lower()
                    in {"ro", "只读"},
                    str(form.get("permission_value")),
                )
                ui_check("guest默认false", form.get("guest_checked") is False, str(form))
                require_ui("打开共享子表单", page.open_share_add(), "共享Drawer未打开")
                share_form = page.get_share_form_structure()
                ui_check("共享名maxlength=15", share_form.get("name_maxlength") == 15, str(share_form))
                ui_check("共享目录必填", share_form.get("home_dir_present"), str(share_form))
                ui_check("隐藏目录字段", share_form.get("browseable_present"), str(share_form))
                ui_check(
                    "共享默认隐藏",
                    str(share_form.get("browseable_value", "no")).strip().lower()
                    in {"no", "false", "0", "隐藏"},
                    str(share_form),
                )
                ui_check("取消共享子表单", page.cancel_share(), "共享Drawer未关闭")
                ui_check("取消新增页", page.cancel_user_form(), "未返回Samba列表")

            with rec.step(
                "步骤3: 保存Samba设置并验证取消、异常输入和设备发现开关",
                "操作：保存工作组、WSDD设备发现和外网访问设置，再测试取消、空工作组及WSDD关闭/恢复；验证：取消不落库、空值被拦截，WSDD关闭只停止发现功能而不影响Samba主服务",
            ):
                saved = page.set_settings(workgroup, True, True)
                require_ui("设置保存", result_ok(saved), result_error(saved))
                require_ssh(
                    "L1-设置保存",
                    backend.verify_samba_global_database,
                    {"workgroup": workgroup, "wsdd2": 1, "access": 1},
                )
                ui_check("打开设置取消场景", page.open_settings(), "设置Drawer未打开")
                page.fill_workgroup(cancel_workgroup)
                page.set_wsdd2(False)
                page.set_access(False)
                page.cancel_settings()
                ui_check("重新打开设置", page.open_settings(), "设置Drawer未打开")
                current = page.get_settings()
                ui_check("取消-workgroup", current.get("workgroup") == workgroup, str(current))
                ui_check("取消-wsdd2", _truthy(current.get("wsdd2")), str(current))
                ui_check("取消-access", _truthy(current.get("access")), str(current))
                page.cancel_settings()
                invalid = page.try_settings_invalid(workgroup="")
                ui_check("空工作组拦截", result_ok(invalid, "blocked"), result_error(invalid))
                require_ssh(
                    "L1-空工作组未落库",
                    backend.verify_samba_global_database,
                    {"workgroup": workgroup, "wsdd2": 1, "access": 1},
                )

                require_ui("服务启用供发现对照", page.set_service_enabled(True), "Samba启用失败")
                require_ssh(
                    "L2-wsdd2=1进程",
                    backend.verify_samba_processes,
                    True,
                    expect_wsdd2=True,
                )
                require_ssh(
                    "L2-wsdd2=1发现监听",
                    backend.verify_samba_listeners,
                    True,
                    expect_wsdd2=True,
                )
                no_discovery = page.set_settings(workgroup, False, True)
                require_ui("关闭WSDD发现", result_ok(no_discovery), result_error(no_discovery))
                require_ssh(
                    "L1-wsdd2=0",
                    backend.verify_samba_global_database,
                    {"enabled": "yes", "workgroup": workgroup, "wsdd2": 0, "access": 1},
                )
                require_ssh(
                    "L2-ik_smbd稳定且发现进程停",
                    backend.verify_samba_processes,
                    True,
                    expect_wsdd2=False,
                )
                require_ssh(
                    "L2-SMB监听保留且发现监听停",
                    backend.verify_samba_listeners,
                    True,
                    expect_wsdd2=False,
                )
                discovery_on = page.set_settings(workgroup, True, True)
                require_ui("恢复WSDD发现", result_ok(discovery_on), result_error(discovery_on))
                require_ssh(
                    "L2-发现进程恢复",
                    backend.verify_samba_processes,
                    True,
                    expect_wsdd2=True,
                )

            with rec.step(
                "步骤4: 启用、关闭并重新启用Samba服务",
                "操作：依次切换Samba总开关；验证：数据库开关、ik_smbd/nmbd/wsdd2进程、监听端口和8项外网防火墙状态同步变化",
            ):
                require_ssh(
                    "L1-enabled=yes",
                    backend.verify_samba_global_database,
                    {"enabled": "yes", "workgroup": workgroup, "wsdd2": 1, "access": 1},
                )
                require_ssh("L2-进程运行", backend.verify_samba_processes, True, expect_wsdd2=True)
                require_ssh("L2-监听运行", backend.verify_samba_listeners, True, expect_wsdd2=True)
                require_ssh(
                    "L3-WAN允许", backend.verify_samba_firewall, False,
                    expect_wsdd2=True,
                    expected_members=baseline_firewall_members,
                )
                require_ui("总开关关闭", page.set_service_enabled(False), "无法关闭Samba")
                require_ssh("L1-enabled=no", backend.verify_samba_global_database, {"enabled": "no"})
                require_ssh("L2-进程停止", backend.verify_samba_processes, False, expect_wsdd2=False)
                require_ssh("L2-监听停止", backend.verify_samba_listeners, False, expect_wsdd2=False)
                require_ui("总开关再启用", page.set_service_enabled(True), "无法恢复Samba")
                require_ssh("L2-进程再启动", backend.verify_samba_processes, True, expect_wsdd2=True)

            with rec.step(
                "步骤5: 添加非匿名读写用户和两个共享",
                "操作：新增一个需密码认证的读写用户，配置一个可见共享和一个隐藏共享；验证：列表、数据库多共享映射、密码状态和运行配置一致",
            ):
                added = page.add_user(
                    rw_user, rw_password, "rw", False, shares=rw_shares
                )
                require_ui("添加RW多共享", result_ok(added), result_error(added))
                page.navigate_to_samba_server()
                require_ui("RW列表存在", page.rule_exists(rw_user), rw_user)
                require_ssh(
                    "L1-RW多共享逗号映射",
                    backend.verify_samba_user_database,
                    rw_user,
                    expected_user("rw", False, rw_shares, rw_password),
                )
                require_ssh("L1-前缀计数=1", backend.verify_samba_user_count, prefix, expected=1)
                require_ssh("L2/L4-RW运行时", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤6: 添加只读匿名隐藏共享用户",
                "操作：新增只读用户，允许匿名访问并将共享设为不可浏览；验证：列表中用户存在，数据库的guest=yes、perm=ro、browseable=no以及运行时共享映射均正确",
            ):
                added = page.add_user(
                    ro_user, ro_password, "ro", True, shares=ro_shares
                )
                require_ui("添加RO匿名隐藏共享", result_ok(added), result_error(added))
                page.navigate_to_samba_server()
                require_ui("RO列表存在", page.rule_exists(ro_user), ro_user)
                require_ssh(
                    "L1-RO匿名隐藏",
                    backend.verify_samba_user_database,
                    ro_user,
                    expected_user("ro", True, ro_shares, ro_password),
                )
                require_ssh("L1-前缀计数=2", backend.verify_samba_user_count, prefix, expected=2)
                require_ssh("L2/L4-双用户运行时", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤7: 搜索Samba用户、清空搜索并检查排序功能",
                "操作：搜索存在和不存在的用户，清空条件，并检查用户名列排序；验证：搜索结果准确且可恢复全部列表，页面有排序入口时验证升降序，无入口时明确记录",
            ):
                page.navigate_to_samba_server()
                page.search_user(rw_user)
                ui_check("搜索命中RW", page.rule_exists(rw_user), rw_user)
                ui_check("搜索排除RO", not page.rule_exists(ro_user), ro_user)
                page.search_user("smb_t_not_found")
                ui_check("搜索空结果", not page.rule_exists(rw_user), "不存在关键字仍显示行")
                page.clear_user_search()
                ui_check("清搜索恢复RW", page.rule_exists(rw_user), rw_user)
                ui_check("清搜索恢复RO", page.rule_exists(ro_user), ro_user)
                before = [name for name in page.get_rule_names() if name.startswith(prefix)]
                sortable = bool(page_structure.get("username_sortable"))
                first_click = page.sort_by_username()
                first_order = [name for name in page.get_rule_names() if name.startswith(prefix)]
                if sortable:
                    second_click = page.sort_by_username()
                    second_order = [name for name in page.get_rule_names() if name.startswith(prefix)]
                    ui_check("用户名排序按钮可用", first_click and second_click, str(page_structure))
                    ui_check(
                        "用户名双向排序",
                        set(first_order) == set(before)
                        and set(second_order) == set(before)
                        and first_order != second_order,
                        f"before={before}, first={first_order}, second={second_order}",
                    )
                else:
                    ui_check(
                        "用户名列无排序入口事实",
                        not first_click and first_order == before,
                        f"before={before}, after={first_order}",
                    )

            with rec.step(
                "步骤8: 修改Samba读写用户密码",
                "操作：仅更换读写用户的一次性密码；验证：原有两个共享、匿名和权限设置不变，数据库与运行配置已更新，旧密码失效而新密码可用",
            ):
                old_password = rw_password
                edited = page.update_user(rw_user, password=rw_edited_password)
                require_ui("编辑RW密码", result_ok(edited), result_error(edited))
                rw_password = rw_edited_password
                require_ssh(
                    "L1-RW编辑后",
                    backend.verify_samba_user_database,
                    rw_user,
                    expected_user("rw", False, rw_shares, rw_password),
                )
                require_ssh("L2/L4-编辑后运行时", verify_runtime_consistency, prefix)
                require_ssh(
                    "L5-旧密码失效",
                    backend.run_samba_probe,
                    username=rw_user,
                    password=old_password,
                    control_password=rw_password,
                    host=LAN_HOST,
                    iface=LAN_IFACE,
                    operation="wrong_password",
                    share_name=rw_share,
                )

            with rec.step(
                "步骤8A: 编辑、删除并恢复Samba共享",
                "操作：修改共享名、目录和是否可浏览，然后删除该共享并按原配置恢复；验证：编辑、删除、恢复三个阶段的数据库与运行配置都与页面一致",
            ):
                edited_rw_shares = [
                    dict(rw_shares[0]),
                    {
                        "name": edited_share,
                        "home_dir": homes["max"],
                        "browseable": True,
                    },
                ]
                page.navigate_to_samba_server()
                require_ui("进入RW共享编辑页", page.edit_user(rw_user), rw_user)
                share_edited = page.edit_share(
                    rw_hidden_share,
                    name=edited_share,
                    home_dir=homes["max"],
                    browseable="yes",
                )
                require_ui(
                    "编辑共享名/目录/可见性",
                    result_ok(share_edited),
                    result_error(share_edited),
                )
                user_saved = page.save_user()
                require_ui("保存共享编辑", result_ok(user_saved), result_error(user_saved))
                require_ssh(
                    "L1-共享编辑映射",
                    backend.verify_samba_user_database,
                    rw_user,
                    expected_user("rw", False, edited_rw_shares, rw_password),
                )
                require_ssh("L4-共享编辑运行时", verify_runtime_consistency, prefix)

                page.navigate_to_samba_server()
                require_ui("再次进入RW编辑页", page.edit_user(rw_user), rw_user)
                require_ui("删除编辑后共享", page.remove_share(edited_share), edited_share)
                user_saved = page.save_user()
                require_ui("保存共享删除", result_ok(user_saved), result_error(user_saved))
                one_rw_share = [dict(rw_shares[0])]
                require_ssh(
                    "L1-共享删除映射",
                    backend.verify_samba_user_database,
                    rw_user,
                    expected_user("rw", False, one_rw_share, rw_password),
                )
                require_ssh("L4-共享删除运行时", verify_runtime_consistency, prefix)

                page.navigate_to_samba_server()
                require_ui("进入RW共享恢复页", page.edit_user(rw_user), rw_user)
                restored_share = page.add_share(
                    rw_hidden_share, homes["rw_hidden"], "no"
                )
                require_ui(
                    "恢复隐藏共享",
                    result_ok(restored_share),
                    result_error(restored_share),
                )
                user_saved = page.save_user()
                require_ui("保存共享恢复", result_ok(user_saved), result_error(user_saved))
                require_ssh(
                    "L1-共享恢复映射",
                    backend.verify_samba_user_database,
                    rw_user,
                    expected_user("rw", False, rw_shares, rw_password),
                )
                require_ssh("L4-共享恢复运行时", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤9: 单独停用并重新启用Samba用户",
                "操作：对读写用户先停用再启用；验证：列表状态、数据库enabled字段、4个运行配置文件和共享下发结果同步移除与恢复",
            ):
                page.navigate_to_samba_server()
                ui_check("单停RW", page.disable_rule(rw_user), "停用操作未发起")
                ui_check("RW显示已停用", page.is_user_disabled(rw_user), rw_user)
                require_ssh(
                    "L1-RW停用", backend.verify_samba_user_database,
                    rw_user, {"enabled": "no"},
                )
                require_ssh("L4-RW停用一致性", verify_runtime_consistency, prefix)
                ui_check("单启RW", page.enable_rule(rw_user), "启用操作未发起")
                ui_check("RW显示已启用", page.is_user_enabled(rw_user), rw_user)
                require_ssh(
                    "L1-RW启用", backend.verify_samba_user_database,
                    rw_user, {"enabled": "yes"},
                )
                require_ssh("L4-RW启用一致性", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤10: 单独删除Samba用户",
                "操作：创建一个专用用户和共享后执行单条删除；验证：列表、数据库和运行配置中都不再存在该用户及共享",
            ):
                share = [{"name": delete_share, "home_dir": homes["delete"], "browseable": True}]
                added = page.add_user(delete_user, auxiliary_password, "rw", False, shares=share)
                require_ui("添加删除样本", result_ok(added), result_error(added))
                page.navigate_to_samba_server()
                ui_check("单条删除", page.delete_rule(delete_user), delete_user)
                require_ssh(
                    "L1-删除样本不存在", backend.verify_samba_user_database,
                    delete_user, must_exist=False,
                )
                require_ssh("L4-单删后一致性", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤11: 批量停用、启用并删除Samba用户",
                "操作：对两个独立用户和共享依次执行批量停用、启用与删除；验证：每个阶段逐条核对页面状态、数据库和运行配置一致",
            ):
                for index, username in enumerate(batch_users):
                    share = [{
                        "name": batch_shares[index],
                        "home_dir": homes[f"batch{index + 1}"],
                        "browseable": True,
                    }]
                    added = page.add_user(
                        username, auxiliary_password, "rw", False, shares=share
                    )
                    require_ui(f"批量样本添加-{index + 1}", result_ok(added), result_error(added))
                page.navigate_to_samba_server()
                require_ui("批量停用", page.batch_disable_users(batch_users), "批量停用未发起")
                for username in batch_users:
                    ui_check(f"批停UI-{username}", page.is_user_disabled(username), username)
                    require_ssh(
                        f"L1-批停-{username}", backend.verify_samba_user_database,
                        username, {"enabled": "no"},
                    )
                require_ssh("L4-批停一致性", verify_runtime_consistency, prefix)
                require_ui("批量启用", page.batch_enable_users(batch_users), "批量启用未发起")
                for username in batch_users:
                    ui_check(f"批启UI-{username}", page.is_user_enabled(username), username)
                    require_ssh(
                        f"L1-批启-{username}", backend.verify_samba_user_database,
                        username, {"enabled": "yes"},
                    )
                require_ssh("L4-批启一致性", verify_runtime_consistency, prefix)
                require_ui("批量删除", page.batch_delete_users(batch_users), "批量删除未发起")
                for username in batch_users:
                    ui_check(f"批删UI-{username}", not page.rule_exists(username), username)
                    require_ssh(
                        f"L1-批删-{username}", backend.verify_samba_user_database,
                        username, must_exist=False,
                    )
                require_ssh("L4-批删一致性", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤12: 验证Samba用户名和共享名长度边界",
                "操作：提交15字符的用户名和共享名，再输入16字符用户名但取消；验证：15字符可正常保存，16字符被浏览器限制为15字符且不会误提交",
            ):
                shares = [{"name": max_share, "home_dir": homes["max"], "browseable": True}]
                boundary = page.add_user(
                    max_user, auxiliary_password, "rw", False, shares=shares
                )
                require_ui("15字符用户名和共享名", result_ok(boundary), result_error(boundary))
                require_ssh(
                    "L1-15字符边界", backend.verify_samba_user_database,
                    max_user, expected_user("rw", False, shares, auxiliary_password),
                )
                page.navigate_to_samba_server()
                require_ui("删除15字符边界", page.delete_rule(max_user), max_user)
                require_ssh(
                    "L1-边界用户删除", backend.verify_samba_user_database,
                    max_user, must_exist=False,
                )
                require_ui("打开16字符场景", page.open_add_page(), "新增页未打开")
                require_ui("填写16字符用户名", page.fill_username(overlong_user), "用户名输入失败")
                actual = page.get_username_value()
                ui_check(
                    "16字符截断到15",
                    actual == overlong_user[:15] and len(actual) == 15,
                    f"实际长度={len(actual)}",
                )
                ui_check("16字符取消不提交", page.cancel_user_form(), "未返回列表")
                require_ssh(
                    "L1-截断值未落库", backend.verify_samba_user_database,
                    max_user, must_exist=False,
                )

            with rec.step(
                "步骤13: 验证Samba用户表单异常输入",
                "操作：分别尝试空用户名、空密码、保留用户root、无共享、71字符密码和重复用户；验证：页面均明确拦截，数据库用户数量不变",
            ):
                valid_share = [{"name": f"{prefix}iv", "home_dir": homes["rw"], "browseable": True}]
                cases = [
                    ("空用户名", dict(username="", password=auxiliary_password, shares=valid_share)),
                    ("空密码", dict(username=invalid_users["no_password"], password="", shares=valid_share)),
                    ("root保留用户名", dict(username="root", password=auxiliary_password, shares=valid_share, root=True)),
                    ("无共享", dict(username=invalid_users["no_share"], password=auxiliary_password, shares=[])),
                    ("71字符密码", dict(username=invalid_users["long_password"], password=overlong_password, shares=valid_share)),
                    ("重复用户", dict(username=rw_user, password=auxiliary_password, shares=valid_share)),
                ]
                for label, kwargs in cases:
                    invalid = page.try_add_invalid(
                        permission="rw", guest=False, **kwargs
                    )
                    ui_check(f"异常拦截-{label}", result_ok(invalid, "blocked"), result_error(invalid))
                    username = kwargs.get("username")
                    if username == rw_user:
                        require_ssh(
                            "L1-重复用户未改写", backend.verify_samba_user_database,
                            rw_user, expected_user("rw", False, rw_shares, rw_password),
                        )
                    elif username and username.startswith(prefix):
                        require_ssh(
                            f"L1-{label}未落库", backend.verify_samba_user_database,
                            username, must_exist=False,
                        )
                    require_ssh(
                        f"L1-{label}后计数=2",
                        backend.verify_samba_user_count,
                        prefix,
                        expected=2,
                    )
                require_ssh(
                    "非测试用户未被root场景影响",
                    backend.verify_samba_non_test_users_unchanged,
                    prefix,
                    non_test_snapshot,
                )

            with rec.step(
                "步骤14: 验证Samba共享表单异常输入",
                "操作：分别尝试空共享名、空目录、同一用户重复共享和跨用户重复共享名；验证：所有非法共享都被页面拦截且不落库",
            ):
                duplicate_name = f"{prefix}dp"
                share_cases = [
                    ("空共享名", invalid_users["empty_share"], [
                        {"name": "", "home_dir": homes["rw"], "browseable": True},
                    ]),
                    ("空共享目录", invalid_users["empty_dir"], [
                        {"name": f"{prefix}ed", "home_dir": "", "browseable": True},
                    ]),
                    ("同用户重复共享", invalid_users["dup_share"], [
                        {"name": duplicate_name, "home_dir": homes["rw"], "browseable": True},
                        {"name": duplicate_name, "home_dir": homes["ro"], "browseable": False},
                    ]),
                    ("跨用户重复共享", invalid_users["cross_share"], [
                        {"name": rw_share, "home_dir": homes["ro"], "browseable": True},
                    ]),
                ]
                for label, username, shares in share_cases:
                    invalid = page.try_add_invalid(
                        username=username,
                        password=auxiliary_password,
                        permission="rw",
                        guest=False,
                        shares=shares,
                    )
                    ui_check(f"共享异常拦截-{label}", result_ok(invalid, "blocked"), result_error(invalid))
                    require_ssh(
                        f"L1-{label}用户未落库", backend.verify_samba_user_database,
                        username, must_exist=False,
                    )
                    require_ssh(
                        f"L1-{label}后计数=2", backend.verify_samba_user_count,
                        prefix, expected=2,
                    )
                require_ssh("L4-异常后运行时一致", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤15: 导出Samba CSV并检查文件与敏感信息",
                "操作：导出CSV配置文件并生成一条安全的临时导入源；验证：文件严格包含9列、多共享映射正确，报告不输出数据行或密码",
            ):
                page.navigate_to_samba_server()
                if os.path.exists(export_path):
                    _secure_remove(export_path)
                started = time.time()
                exported = page.export_rules(export_format="csv")
                require_ui("CSV导出", exported, "导出弹窗/下载失败")
                fresh = (
                    os.path.exists(export_path)
                    and os.path.getmtime(export_path) >= started - 1
                )
                require_ui("本轮导出文件存在", fresh, export_path)
                safe_import_path, headers, row_count, error = _build_safe_import(
                    export_path, rw_user, [rw_share, rw_hidden_share]
                )
                require_ui("CSV严格9列表头", headers == EXPORT_HEADERS, str(headers))
                require_ui("安全筛选仅1行", row_count == 1 and bool(safe_import_path), error)
                rec.add_detail("导出内容未输出；临时CSV仅含表头和1个本轮测试用户")

            with rec.step(
                "步骤15A: 导出Samba TXT并检查文件格式",
                "操作：导出TXT配置文件；验证：每行严格包含9个key=value字段且多共享映射正确，任何字段值和密码均不进入日志",
            ):
                page.navigate_to_samba_server()
                if os.path.exists(txt_export_path):
                    _secure_remove(txt_export_path)
                started = time.time()
                txt_exported = page.export_rules(export_format="txt")
                require_ui("TXT导出", txt_exported, "导出弹窗/下载失败")
                txt_fresh = (
                    os.path.exists(txt_export_path)
                    and os.path.getmtime(txt_export_path) >= started - 1
                    and os.path.getsize(txt_export_path) > 0
                )
                require_ui("本轮TXT导出文件新鲜且非空", txt_fresh, txt_export_path)
                txt_contract_ok, txt_contract_detail = _validate_txt_export(
                    txt_export_path,
                    rw_user,
                    [rw_share, rw_hidden_share],
                )
                require_ui(
                    "TXT严格9字段契约",
                    txt_contract_ok,
                    txt_contract_detail,
                )
                rec.add_detail(
                    "TXT仅在内存解析字段结构；任何含明文密码的数据行和字段值均未输出"
                )

            with rec.step(
                "步骤15B: 导入畸形CSV/TXT并确认原配置不受影响",
                "操作：以追加方式分别提交两个不含凭据的非法CSV/TXT文件；验证：页面明确拒绝，Samba全局设置、测试用户和非测试数据均保持不变",
            ):
                import_dir = os.path.dirname(export_path)
                for extension in ("csv", "txt"):
                    malformed_path = _build_malformed_import(import_dir, extension)
                    malformed_import_paths.append(malformed_path)
                    page.navigate_to_samba_server()
                    attempt = page.attempt_import(
                        malformed_path, clear_existing=False
                    )
                    require_ui(
                        f"畸形{extension.upper()}清空选项保持关闭",
                        attempt.get("clear_state") is False,
                        attempt.get("error", ""),
                    )
                    rejection_ok = (
                        bool(attempt.get("submitted"))
                        and bool(attempt.get("rejected"))
                        and not bool(attempt.get("success"))
                    )
                    attempt_detail = (
                        f"submitted={bool(attempt.get('submitted'))}, "
                        f"rejected={bool(attempt.get('rejected'))}, "
                        f"success={bool(attempt.get('success'))}, "
                        f"feedback={safe_text(attempt.get('error') or '无明确失败反馈')}"
                    )
                    # 这是产品行为断言，不是继续测试的安全前置。即使页面错误地
                    # 报成功，也继续用SSH证明数据库/非测试用户是否真的未变化，
                    # 最终统一失败，避免一个UI问题遮住后续导入、帮助和L5覆盖。
                    ui_check(
                        f"畸形{extension.upper()}被明确拒绝",
                        rejection_ok,
                        attempt_detail,
                    )
                    require_ssh(
                        f"L1-{extension.upper()}拒绝后计数=2",
                        backend.verify_samba_user_count,
                        prefix,
                        expected=2,
                    )
                    require_ssh(
                        f"L1-{extension.upper()}拒绝后RW未变",
                        backend.verify_samba_user_database,
                        rw_user,
                        expected_user("rw", False, rw_shares, rw_password),
                    )
                    require_ssh(
                        f"L1-{extension.upper()}拒绝后RO未变",
                        backend.verify_samba_user_database,
                        ro_user,
                        expected_user("ro", True, ro_shares, ro_password),
                    )
                    require_ssh(
                        f"{extension.upper()}拒绝后非测试用户未变",
                        backend.verify_samba_non_test_users_unchanged,
                        prefix,
                        non_test_snapshot,
                    )
                require_ssh(
                    "L1-畸形导入后全局未变",
                    backend.verify_samba_global_database,
                    {"enabled": "yes", "workgroup": workgroup, "wsdd2": 1, "access": 1},
                )
                require_ssh("L4-畸形导入后运行时一致", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤16: 以追加方式导入Samba配置",
                "操作：删除读写用户后，明确不清空现有配置并回灌安全CSV；验证：读写用户恢复，只读用户和非测试配置保留，密码重新加密且运行配置正确",
            ):
                page.navigate_to_samba_server()
                require_ui("导入前删除RW", page.delete_rule(rw_user), rw_user)
                require_ssh(
                    "L1-导入前RW无", backend.verify_samba_user_database,
                    rw_user, must_exist=False,
                )
                imported = bool(safe_import_path) and page.import_rules(
                    safe_import_path, clear_existing=False
                )
                require_ui("安全追加导入", imported, "清空选项未明确保持关闭或上传失败")
                page.navigate_to_samba_server()
                require_ui("导入后RW恢复", page.rule_exists(rw_user), rw_user)
                require_ui("追加导入保留RO", page.rule_exists(ro_user), ro_user)
                require_ssh(
                    "L1-导入RW", backend.verify_samba_user_database,
                    rw_user, expected_user("rw", False, rw_shares, rw_password),
                )
                require_ssh("L1-导入后计数=2", backend.verify_samba_user_count, prefix, expected=2)
                require_ssh(
                    "追加导入未影响非测试用户",
                    backend.verify_samba_non_test_users_unchanged,
                    prefix,
                    non_test_snapshot,
                )
                require_ssh("L4-导入后运行时", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤17: 检查Samba文件管理入口和未保存提示",
                "操作：先在新增表单中输入未保存内容，再点击文件管理并关闭弹出页；验证：未保存确认逻辑、文件管理目标路由和弹出页清理均正确",
            ):
                page.navigate_to_samba_server()
                dirty_user = f"{prefix}fm"
                require_ui("打开dirty新增页", page.open_add_page(), "无法进入新增页")
                require_ui(
                    "制造未保存用户名变更",
                    page.fill_username(dirty_user)
                    and page.get_username_value() == dirty_user,
                    dirty_user,
                )
                manager = page.open_file_manager()
                manager_url = manager.get("url", "") if isinstance(manager, dict) else ""
                ui_check("文件管理按钮可点", result_ok(manager, "clicked"), result_error(manager))
                ui_check(
                    "文件管理触发未保存确认",
                    result_ok(manager, "unsaved_confirm_seen"),
                    result_error(manager),
                )
                ui_check("文件管理popup打开", result_ok(manager, "popup_opened"), manager_url)
                ui_check(
                    "文件管理路由",
                    "equipmentSetting/diskManagement" in manager_url
                    and "tab=fileManagement" in manager_url,
                    manager_url,
                )
                ui_check("文件管理无孤儿Tab", result_ok(manager, "no_orphan"), manager_url)
                if page.is_on_config_page():
                    require_ui("退出dirty新增页", page.cancel_user_form(), "取消新增页失败")
                else:
                    page.navigate_to_samba_server()
                require_ssh(
                    "L1-dirty用户名未落库",
                    backend.verify_samba_user_database,
                    dirty_user,
                    must_exist=False,
                )
                require_ssh("L1-dirty确认后计数=2", backend.verify_samba_user_count, prefix, expected=2)

            with rec.step(
                "步骤18: 检查Samba页面右下角帮助入口",
                "操作：点击帮助按钮并关闭新打开的页面；验证：链接指向ikuai8.com，弹出页可正常关闭且不留下多余标签页",
            ):
                page.navigate_to_samba_server()
                help_result = page.verify_help_entry()
                help_url = help_result.get("url", "") if isinstance(help_result, dict) else ""
                ui_check("帮助按钮可点", result_ok(help_result, "clicked"), result_error(help_result))
                ui_check("帮助popup打开", result_ok(help_result, "popup_opened"), help_url)
                ui_check("帮助URL域名", "ikuai8.com" in help_url, help_url)
                ui_check("帮助无孤儿Tab", result_ok(help_result, "no_orphan"), help_url)

            with rec.step(
                "步骤19: 综合核对Samba数据库、运行配置与服务状态",
                "操作：执行smbd.sh init重建底层配置；验证：数据库用户与多共享映射、4个运行配置文件、3个服务进程、监听端口和8项外网防火墙状态完全一致",
            ):
                require_ssh(
                    "L1-全局", backend.verify_samba_global_database,
                    {"enabled": "yes", "workgroup": workgroup, "wsdd2": 1, "access": 1},
                )
                require_ssh("L1-用户计数", backend.verify_samba_user_count, prefix, expected=2)
                require_ssh(
                    "L1-RW最终映射", backend.verify_samba_user_database,
                    rw_user, expected_user("rw", False, rw_shares, rw_password),
                )
                require_ssh(
                    "L1-RO最终映射", backend.verify_samba_user_database,
                    ro_user, expected_user("ro", True, ro_shares, ro_password),
                )
                require_ssh("L2-进程", backend.verify_samba_processes, True, expect_wsdd2=True)
                require_ssh("L2-监听", backend.verify_samba_listeners, True, expect_wsdd2=True)
                require_ssh(
                    "L3-WAN允许", backend.verify_samba_firewall, False,
                    expect_wsdd2=True,
                    expected_members=baseline_firewall_members,
                )
                require_ssh("L4-运行时一致", verify_runtime_consistency, prefix)
                require_ssh(
                    "L4-smbd.sh init重建", backend.verify_samba_reinit,
                    rw_user,
                    expected_firewall_members=baseline_firewall_members,
                )
                require_ssh("L4-reinit后二次一致", verify_runtime_consistency, prefix)

            with rec.step(
                "步骤20: 从内网认证Samba并读写可见与隐藏共享",
                "操作：用读写账号列出共享，访问可见和隐藏共享，执行上传、下载、删除并尝试错误密码；验证：两个共享都可按名访问、文件SHA256一致，错误密码被拒绝",
            ):
                require_ssh(
                    "L5-RW可见共享LIST", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="list",
                    share_name=rw_share,
                )
                require_ssh(
                    "L5-RW隐藏共享显式访问", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="list",
                    share_name=rw_hidden_share,
                )
                require_ssh(
                    "L5-RW上传下载SHA删除", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="upload_download",
                    share_name=rw_share,
                )
                require_ssh(
                    "L5-错误密码拒绝", backend.run_samba_probe,
                    username=rw_user, password=wrong_password,
                    control_password=rw_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="wrong_password",
                    share_name=rw_share,
                )

            with rec.step(
                "步骤21: 验证Samba只读权限和匿名访问规则",
                "操作：用只读账号读取并尝试写入，再不带凭据访问允许匿名与禁止匿名的共享；验证：只读账号可读但不能写且无远端残留，guest=yes可匿名读取，guest=no明确拒绝",
            ):
                require_ssh(
                    "L5-RO认证LIST", backend.run_samba_probe,
                    username=ro_user, password=ro_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="list",
                    share_name=ro_share,
                )
                require_ssh(
                    "L5-RO写入拒绝", backend.run_samba_probe,
                    username=ro_user, password=ro_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="write_denied",
                    share_name=ro_share,
                )
                require_ssh(
                    "L5-guest匿名正向", backend.run_samba_probe,
                    host=LAN_HOST, iface=LAN_IFACE, operation="guest_list",
                    share_name=ro_share,
                )
                require_ssh(
                    "L5-guest匿名负向", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    control_password=rw_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="guest_denied",
                    share_name=rw_share,
                )

            with rec.step(
                "步骤22: 验证Samba外网访问开关",
                "操作：先在允许外网时建立访问基线，再关闭外网并分别从内外网连接，最后恢复；验证：关闭后8项端口进入阻断集合、外网连接失败但内网仍可用，恢复后外网可用",
            ):
                require_ssh(
                    "L5-WAN允许基线", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    host=WAN_HOST, iface=WAN_IFACE, operation="list",
                    share_name=rw_share,
                )
                page.navigate_to_samba_server()
                restricted = page.set_settings(workgroup, True, False)
                require_ui("关闭外网访问", result_ok(restricted), result_error(restricted))
                require_ssh(
                    "L1-access=0", backend.verify_samba_global_database,
                    {"enabled": "yes", "workgroup": workgroup, "wsdd2": 1, "access": 0},
                )
                require_ssh("L3-8项WAN端口DROP", backend.verify_samba_firewall, True, expect_wsdd2=True)
                require_ssh("L2-限制后进程稳定", backend.verify_samba_processes, True, expect_wsdd2=True)
                require_ssh(
                    "L5-限制时LAN仍通", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="list",
                    share_name=rw_share,
                )
                require_ssh(
                    "L5-WAN关闭阻断", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    host=WAN_HOST, iface=WAN_IFACE, operation="connect_fail",
                    share_name=rw_share,
                    control_host=LAN_HOST,
                    control_iface=LAN_IFACE,
                )
                allowed = page.set_settings(workgroup, True, True)
                require_ui("恢复外网访问", result_ok(allowed), result_error(allowed))
                # access=0 -> 1 会由产品脚本删除全部8项成员；从此不再使用
                # 测试前共享集合中的UDP/138基线作为运行期期望，finally会原样恢复。
                allow_uses_baseline_firewall = False
                require_ssh("L3-WAN DROP移除", backend.verify_samba_firewall, False, expect_wsdd2=True)
                require_ssh(
                    "L5-WAN恢复", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    host=WAN_HOST, iface=WAN_IFACE, operation="list",
                    share_name=rw_share,
                )

            with rec.step(
                "步骤23: 验证Samba总开关关闭后拒绝连接",
                "操作：关闭Samba服务并从内网发起真实SMB连接；验证：数据库开关关闭、相关进程和所有监听停止，内网连接明确失败",
            ):
                page.navigate_to_samba_server()
                require_ui("关闭Samba服务", page.set_service_enabled(False), "总开关关闭失败")
                require_ssh("L1-总开关关", backend.verify_samba_global_database, {"enabled": "no"})
                require_ssh("L2-进程全关", backend.verify_samba_processes, False, expect_wsdd2=False)
                require_ssh("L2-监听全关", backend.verify_samba_listeners, False, expect_wsdd2=False)
                require_ssh(
                    "L5-关闭后LAN拒绝", backend.run_samba_probe,
                    username=rw_user, password=rw_password,
                    host=LAN_HOST, iface=LAN_IFACE, operation="connect_fail",
                    share_name=rw_share,
                )

            with rec.step(
                "步骤24: 删除最终Samba用户并检查无残留",
                "操作：重新启用服务后删除读写和只读用户；验证：本轮前缀的数据库记录数为0，4个运行配置文件与进程状态符合空测试配置",
            ):
                require_ui("删除前再启服务", page.set_service_enabled(True), "无法再启用")
                for username in (rw_user, ro_user):
                    page.navigate_to_samba_server()
                    require_ui(f"最终删除-{username}", page.delete_rule(username), username)
                    require_ssh(
                        f"L1-最终删除-{username}", backend.verify_samba_user_database,
                        username, must_exist=False,
                    )
                require_ssh("L1-最终前缀计数=0", backend.verify_samba_user_count, prefix, expected=0)
                require_ssh("L4-最终空配置一致", verify_runtime_consistency, prefix)

        finally:
            with rec.step(
                "步骤25: 清理测试数据并恢复Samba原始环境",
                "清理：删除本轮随机前缀、测试目录和远端导入残留；恢复与验证：还原数据库、4个运行配置文件、进程、监听、8项防火墙以及本地CSV/TXT的测试前状态",
            ):
                all_import_paths = [
                    path for path in [safe_import_path, *malformed_import_paths]
                    if path
                ]
                import_filenames = [
                    os.path.basename(path) for path in all_import_paths
                ]
                if mutation_started:
                    try:
                        page.navigate_to_samba_server()
                        removed = page.clean_test_rules(prefix)
                        rec.add_detail(f"[finally UI清理] 删除{removed}条本轮前缀用户")
                    except Exception as exc:
                        ui_failures.append(f"finally UI清理异常: {safe_text(exc)[:100]}")
                    try:
                        cleanup_message = backend.cleanup_samba_test(
                            prefix,
                            test_dirs=prepared_absolute_dirs,
                            import_filenames=import_filenames,
                            snapshot=global_snapshot,
                        )
                        rec.add_detail(
                            f"[finally backend清理] {safe_text(cleanup_message)[:300]}"
                        )
                        if str(cleanup_message).lower().startswith("error"):
                            ssh_failures.append(
                                f"finally backend清理失败: {safe_text(cleanup_message)[:140]}"
                            )
                    except Exception as exc:
                        ssh_failures.append(f"finally backend清理异常: {safe_text(exc)[:100]}")
                    # 先独立证明 cleanup 已清掉本轮 DB/目录/运行时引用/进程/导入暂存，
                    # 再恢复基线。此处明确不传环境快照，避免 restore 掩盖 cleanup 缺陷；
                    # 即使审计失败也只累计到最终断言，后续环境恢复仍必须继续执行。
                    ssh_verify(
                        "finally-恢复前独立残留审计",
                        backend.verify_samba_test_artifacts_absent,
                        prefix,
                        test_dirs=prepared_absolute_dirs,
                        resolved_dirs=prepared_resolved_dirs,
                        import_filenames=import_filenames,
                        snapshot=None,
                        must_pass=True,
                    )
                    if snapshot_valid and global_snapshot:
                        ssh_verify(
                            "finally-恢复全环境快照",
                            backend.restore_samba_environment,
                            global_snapshot,
                            must_pass=True,
                        )
                        ssh_verify(
                            "finally-全局DB复验",
                            backend.verify_samba_global_database,
                            global_snapshot["global"],
                            must_pass=True,
                        )
                        allow_uses_baseline_firewall = True
                        ssh_verify(
                            "finally-L4一致性",
                            verify_runtime_consistency,
                            prefix,
                            must_pass=True,
                        )
                        ssh_verify(
                            "finally-测试残留全清",
                            backend.verify_samba_test_artifacts_absent,
                            prefix,
                            test_dirs=prepared_absolute_dirs,
                            resolved_dirs=prepared_resolved_dirs,
                            import_filenames=import_filenames,
                            snapshot=global_snapshot,
                            must_pass=True,
                        )
                        if non_test_snapshot is not None:
                            ssh_verify(
                                "finally-非测试用户未变化",
                                backend.verify_samba_non_test_users_unchanged,
                                prefix,
                                non_test_snapshot,
                                must_pass=True,
                            )
                    else:
                        ssh_failures.append("已开始变更但无有效Samba环境快照，无法原样恢复")
                else:
                    rec.add_detail("[finally] 尚未开始任何设备变更，跳过设备清理/恢复")

                try:
                    for local_path in all_import_paths:
                        _secure_remove(local_path)
                    safe_absent = all(
                        not os.path.exists(path) for path in all_import_paths
                    )
                    csv_state_ok = restore_local_export(
                        export_path, export_existed, export_backup
                    )
                    txt_state_ok = restore_local_export(
                        txt_export_path, txt_export_existed, txt_export_backup
                    )
                    ui_check(
                        "本地临时导入文件已删除",
                        safe_absent,
                        "安全CSV或畸形CSV/TXT仍存在",
                    )
                    ui_check("原CSV导出文件字节级恢复", csv_state_ok, export_path)
                    ui_check("原TXT导出文件字节级恢复", txt_state_ok, txt_export_path)
                    rec.add_detail(
                        "[finally本地文件] 明文密码CSV/TXT已覆盖删除，"
                        "测试前文件存在性和字节内容均已恢复"
                    )
                except Exception as exc:
                    ui_failures.append(f"finally本地文件恢复异常: {safe_text(exc)[:100]}")

        failures = ssh_failures + ui_failures
        if failures:
            print(
                f"[Samba断言] 共{len(failures)}项失败 "
                f"(SSH={len(ssh_failures)}, UI={len(ui_failures)})",
                flush=True,
            )
            for failure in failures[:40]:
                print(f"  - {safe_text(failure)}", flush=True)
        assert not failures, (
            f"Samba服务L1-L5综合验证失败({len(failures)}项): "
            + "; ".join(safe_text(item) for item in failures[:24])
        )
