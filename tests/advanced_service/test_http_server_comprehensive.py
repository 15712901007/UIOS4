"""
高级服务 > 本地服务 > HTTP服务 L1-L5 综合测试。

单一 GUI 节点覆盖 HTTP/HTTPS 静态文件服务的页面结构、CRUD、搜索、停启、
批量、异常边界、CSV/TXT 导入导出、文件管理/未保存确认/帮助，以及
DB→openresty 配置→监听→WAN ipset→真实 curl 数据面的完整验证。

安全约束：
- 每轮使用随机 ``http_t_<token>_`` 命名空间、动态空闲高位端口和独立目录。
- 只清理本轮前缀、候选端口、目录和导入暂存；绝不清空既有 HTTP 表或 ipset。
- 变更前取得 DB、static_file.conf、暂存文件和逐端口防火墙快照。
- finally 必须先证明 cleanup 独立无残留，再恢复快照并复验非测试配置。
"""

from __future__ import annotations

import csv
import os
import re
import secrets
import string
import tempfile
import time
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import pytest

from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure


pytestmark = [pytest.mark.advanced_service, pytest.mark.http_server]

PARTITION = "666"
LAN_HOST, LAN_IFACE = "192.168.148.1", "ens11"
WAN_HOST, WAN_IFACE = "10.66.0.150", "enp2s0"

EXPORT_HEADERS = [
    "id", "enabled", "tagname", "http_port", "server_name",
    "ssl_on", "autoindex", "download", "home_dir", "access",
]


def _truthy(value) -> bool:
    return str(value).strip().lower() in {
        "1", "yes", "true", "on", "enable", "enabled",
    }


def _export_path(extension: str) -> str:
    config = get_config()
    configured = config.test_data.get_export_path(
        "http_server", config.get_project_root()
    )
    return os.path.splitext(configured)[0] + f".{extension.lower()}"


def _secure_remove(path: Optional[str]) -> None:
    """尽力覆盖后删除本轮本地导出/导入文件。"""
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


def _read_backup(path: str) -> Tuple[bool, Optional[bytes]]:
    existed = os.path.exists(path)
    if not existed:
        return False, None
    try:
        with open(path, "rb") as source:
            return True, source.read()
    except OSError:
        return True, None


def _restore_local_file(
    path: str, existed: bool, backup: Optional[bytes]
) -> bool:
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


def _build_safe_import(
    export_path: str,
    tagname: str,
) -> Tuple[Optional[str], List[str], int, str]:
    """只保留一个本轮测试规则；任何数据行都不得进入日志或返回值。"""
    try:
        with open(export_path, "r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            headers = list(reader.fieldnames or [])
            rows = [row for row in reader if row.get("tagname") == tagname]
        if headers != EXPORT_HEADERS:
            return None, headers, len(rows), "CSV表头不符合HTTP服务导出契约"
        if len(rows) != 1:
            return None, headers, len(rows), f"目标规则行数应为1，实际={len(rows)}"
        directory = os.path.dirname(export_path)
        os.makedirs(directory, exist_ok=True)
        fd, safe_path = tempfile.mkstemp(
            prefix="http_t_import_", suffix=".csv", dir=directory,
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
    except Exception as exc:
        return None, [], 0, str(exc)[:120]


def _parse_txt_record(line: str) -> Tuple[List[str], Dict[str, str]]:
    """解析 export_txt 的逐行 key=value；调用方不得输出返回的字段值。"""
    key_pattern = "|".join(re.escape(key) for key in EXPORT_HEADERS)
    matches = list(re.finditer(rf"(?:^| )(?P<key>{key_pattern})=", line))
    keys: List[str] = []
    row: Dict[str, str] = {}
    for index, match in enumerate(matches):
        key = match.group("key")
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(line)
        value = line[value_start:value_end].rstrip()
        keys.append(key)
        row[key] = value
    return keys, row


def _validate_txt_export(path: str, tagname: str) -> Tuple[bool, str]:
    """验证 TXT 10字段契约和目标规则唯一性，不返回/打印任何字段值。"""
    try:
        row_count = 0
        target_count = 0
        with open(path, "r", encoding="utf-8-sig", newline="") as source:
            for line_number, raw_line in enumerate(source, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                row_count += 1
                keys, row = _parse_txt_record(line)
                if keys != EXPORT_HEADERS:
                    return False, (
                        f"第{line_number}行字段契约不符: "
                        f"实际={len(keys)}, 期望={len(EXPORT_HEADERS)}"
                    )
                if row.get("tagname") == tagname:
                    target_count += 1
        if row_count == 0:
            return False, "TXT导出无数据行"
        if target_count != 1:
            return False, f"目标规则行数应为1，实际={target_count}"
        return True, f"字段数=10，导出行数={row_count}，目标规则行数=1"
    except Exception as exc:
        return False, str(exc)[:120]


def _build_malformed_import(
    directory: str, extension: str, tagname: str
) -> str:
    """创建表头/字段齐全但多项参数非法、绝不应落库的导入文件。"""
    os.makedirs(directory, exist_ok=True)
    fd, path = tempfile.mkstemp(
        prefix="http_t_bad_", suffix=f".{extension.lower()}", dir=directory,
    )
    os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    row = {
        "id": "0",
        "enabled": "invalid",
        "tagname": tagname,
        "http_port": "0",
        "server_name": "bad name!",
        "ssl_on": "9",
        "autoindex": "9",
        "download": "-1",
        "home_dir": "",
        "access": "9",
    }
    with open(path, "w", encoding="utf-8-sig", newline="") as target:
        if extension.lower() == "csv":
            writer = csv.DictWriter(target, fieldnames=EXPORT_HEADERS)
            writer.writeheader()
            writer.writerow(row)
        else:
            target.write(" ".join(
                f"{field}={row[field]}" for field in EXPORT_HEADERS
            ) + "\n")
    return path


class TestHttpServerComprehensive:
    """HTTP服务 UI + L1-L5 单节点综合验证。"""

    def test_http_server_comprehensive(
        self, http_server_page_logged_in, step_recorder: StepRecorder, request
    ):
        page = http_server_page_logged_in
        rec = step_recorder
        backend = request.getfixturevalue("backend_verifier")
        if backend is None:
            pytest.fail("HTTP服务L1-L5综合测试必须启用SSH backend_verifier")

        alphabet = string.ascii_lowercase + string.digits
        token = "".join(secrets.choice(alphabet) for _ in range(7))
        prefix = f"http_{token}_"
        primary = f"{prefix}h"
        https_rule = f"{prefix}s"
        delete_rule = f"{prefix}d"
        renamed_rule = f"{prefix}x"
        batch_rules = (f"{prefix}b1", f"{prefix}b2")
        vhost_rules = (f"{prefix}v1", f"{prefix}v2")
        control_rule = f"{prefix}c"
        dirty_rule = f"{prefix}fm"
        max_rule = (prefix + "123456789012345")[:15]
        overlong_rule = max_rule + "0"
        invalid_names = {
            "no_home": f"{prefix}nh",
            "bad_port": f"{prefix}bp",
            "reserved": f"{prefix}rp",
            "overflow": f"{prefix}op",
            "in_use": f"{prefix}iu",
            "domain": f"{prefix}dm",
            "download": f"{prefix}dl",
            "duplicate_pair": f"{prefix}dp",
            "mixed_protocol": f"{prefix}mp",
            "malformed": f"{prefix}z",
        }
        all_names = [
            primary, https_rule, delete_rule, renamed_rule,
            *batch_rules, *vhost_rules,
            control_rule, dirty_rule, max_rule, *invalid_names.values(),
        ]
        assert len(prefix) < 15
        assert len(max_rule) == 15 and len(overlong_rule) == 16
        assert all(len(name) <= 15 for name in all_names)

        dir_names = {
            "primary": f"{prefix}h",
            "edited": f"{prefix}e",
            "https": f"{prefix}s",
            "vhost1": f"{prefix}v1",
            "vhost2": f"{prefix}v2",
        }
        homes = {
            alias: f"/{PARTITION}/{dirname}"
            for alias, dirname in dir_names.items()
        }
        fallback_environment = {
            "home_dirs": dict(homes),
            "absolute_dirs": {
                alias: f"/etc/disk_user{home}" for alias, home in homes.items()
            },
            "resolved_dirs": {},
            "payloads": {},
        }

        primary_domain = f"h{token}.test"
        https_domain = f"s{token}.test"
        renamed_domain = f"x{token}.test"
        vhost_domains = (f"a{token}.test", f"b{token}.test")
        control_domain = f"c{token}.test"

        ui_failures: List[str] = []
        ssh_failures: List[str] = []
        candidate_ports: List[int] = []
        global_snapshot: Optional[Dict] = None
        non_test_snapshot: Optional[Dict] = None
        prepared_environment: Dict = dict(fallback_environment)
        snapshot_valid = False
        mutation_started = False
        safe_import_path: Optional[str] = None
        malformed_paths: List[str] = []

        csv_path = _export_path("csv")
        txt_path = _export_path("txt")
        csv_existed, csv_backup = _read_backup(csv_path)
        txt_existed, txt_backup = _read_backup(txt_path)

        def result_ok(result, key: str = "success") -> bool:
            return bool(result.get(key)) if isinstance(result, dict) else bool(result)

        def result_error(result) -> str:
            return str(result.get("error", "")) if isinstance(result, dict) else ""

        def ui_check(label, condition, detail=""):
            ok = bool(condition)
            detail_text = "" if detail is None else str(detail)
            conclusion = "符合预期" if ok else (detail_text or "条件不成立")
            rec.add_detail(f"【页面验证】\n{'✓' if ok else '✗'} {label}：{conclusion}")
            if not ok:
                ui_failures.append(f"页面验证-{label}：{detail_text or '条件不成立'}")
            return ok

        def require_ui(label, condition, detail=""):
            if not ui_check(label, condition, detail):
                pytest.fail(f"安全前置失败: {label}: {detail or '条件不成立'}")

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
                message = str(getattr(result, "message", "无验证消息"))
                if not passed and not must_pass:
                    message = f"未通过（警告，不阻断测试）；{message}"
                rec.add_detail(f"{section}\n{symbol} {check_name}：{message}")
                raw = str(getattr(result, "raw_output", "") or "")
                if raw:
                    rec.add_detail(f"【后端数据】\n{raw}")
                print(f"{section} {symbol} {check_name}：{message}", flush=True)
                if must_pass and not passed:
                    ssh_failures.append(f"后端验证-{label_text}：{message}")
                return result
            except Exception as exc:
                symbol = "✗" if must_pass else "⚠"
                impact = "验证异常，本项失败" if must_pass else "验证异常，仅记录警告"
                message = str(exc)
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

        def expected_rule(
            tagname: str,
            home_dir: str,
            port: int,
            *,
            protocol: str = "http",
            server_name: str = "",
            autoindex: bool = False,
            download: int = 0,
            access: bool = False,
            enabled: str = "yes",
        ) -> Dict:
            return {
                "enabled": enabled,
                "tagname": tagname,
                "http_port": int(port),
                "server_name": server_name,
                "ssl_on": 1 if str(protocol).lower() == "https" else 0,
                "autoindex": 1 if autoindex else 0,
                "download": int(download),
                "home_dir": home_dir,
                "access": 1 if access else 0,
            }

        primary_expected: Dict = {}
        https_expected: Dict = {}

        try:
            with rec.step(
                "步骤1: 保存HTTP环境快照并准备独立端口与目录",
                "准备：动态选择测试端口，记录数据库、openresty配置、暂存文件、监听和防火墙状态；验证：所有候选端口在数据库、监听和防火墙中都未被占用",
            ):
                backend.connect_router()
                candidate_ports = backend.choose_http_candidate_ports(7)
                require_ui(
                    "7个唯一高位候选端口",
                    len(candidate_ports) == 7
                    and len(set(candidate_ports)) == 7
                    and all(10000 <= port <= 59999 for port in candidate_ports),
                    str(candidate_ports),
                )
                global_snapshot = backend.get_http_environment_snapshot(candidate_ports)
                snapshot_valid = bool(
                    isinstance(global_snapshot, dict)
                    and global_snapshot.get("version") == 1
                    and isinstance(global_snapshot.get("rows"), list)
                    and isinstance(global_snapshot.get("runtime_files"), dict)
                    and isinstance(global_snapshot.get("staging_files"), dict)
                    and global_snapshot.get("firewall_set_exists") is True
                    and global_snapshot.get("openresty_alive") is True
                    and all(
                        str(port) in global_snapshot.get("firewall_members", {})
                        and str(port) in global_snapshot.get("listener_members", {})
                        for port in candidate_ports
                    )
                )
                require_ui("完整HTTP环境快照", snapshot_valid, "HTTP快照字段不完整")
                if csv_existed and csv_backup is None:
                    pytest.fail("既有HTTP CSV导出文件无法备份，禁止开始测试")
                if txt_existed and txt_backup is None:
                    pytest.fail("既有HTTP TXT导出文件无法备份，禁止开始测试")
                non_test_snapshot = backend.snapshot_http_non_test_rules(prefix)
                require_ssh(
                    "唯一前缀初始计数=0",
                    backend.verify_http_rule_count,
                    prefix,
                    expected=0,
                )
                backend.connect_client()
                mutation_started = True
                prepared = require_ssh(
                    "测试目录/文件/端口二次复验",
                    backend.prepare_http_test_environment,
                    PARTITION,
                    dir_names,
                    port_count=7,
                    candidate_ports=candidate_ports,
                    prefix=prefix,
                )
                prepared_environment = dict(getattr(prepared, "details", {}) or {})
                require_ui(
                    "后端端口集合一致",
                    prepared_environment.get("ports") == candidate_ports,
                    str(prepared_environment.get("ports")),
                )
                require_ui(
                    "5个数据面目录及不同payload",
                    set(prepared_environment.get("home_dirs", {})) == set(dir_names)
                    and len({
                        item.get("sha256")
                        for item in prepared_environment.get("payloads", {}).values()
                    }) == len(dir_names),
                    "目录或payload映射不完整",
                )
                page.navigate_to_http_server()
                require_ui(
                    "唯一前缀UI初始为空",
                    page.clean_test_rules(prefix) == 0,
                    "随机前缀不应存在历史规则",
                )

            p_http, p_edit, p_https, p_delete, p_batch1, p_batch2, p_vhost = candidate_ports
            payloads = prepared_environment["payloads"]

            with rec.step(
                "步骤2: 检查HTTP页签、列表和新增表单",
                "操作：进入HTTP页面并打开新增表单；验证：HTTP位于第3个页签，8个业务列和表单字段齐全，名称列无排序入口，默认为HTTP、关闭目录浏览、0限速和禁止外网",
            ):
                page.navigate_to_http_server()
                structure = page.get_default_structure()
                require_ui("HTTP Tab存在且激活", structure.get("http_tab_active"), str(structure))
                ui_check("HTTP Tab序号=2", structure.get("http_tab_index") == 2, str(structure))
                for key in ("table_present", "search_present"):
                    ui_check(f"结构-{key}", structure.get(key), str(structure))
                buttons = set(structure.get("buttons", []))
                for label in ("添加", "导入", "导出"):
                    ui_check(f"按钮-{label}", label in buttons, str(buttons))
                headers = set(structure.get("headers", []))
                for label in (
                    "名称", "文件目录", "访问方式", "服务端口", "服务域名",
                    "目录浏览权限", "外网访问", "操作",
                ):
                    ui_check(f"列-{label}", label in headers, str(headers))
                ui_check(
                    "当前固件表头均无排序入口",
                    structure.get("all_headers_unsortable") is True,
                    str(structure.get("sortable_columns")),
                )
                require_ui("打开新增页", page.open_add_page(), "HTTP新增页未打开")
                form = page.get_form_structure()
                for key in (
                    "tagname_present", "home_dir_present", "protocol_present",
                    "http_port_present", "server_name_present", "autoindex_present",
                    "download_present", "access_present", "file_manager_present",
                    "save_present", "cancel_present",
                ):
                    ui_check(f"表单-{key}", form.get(key), str(form))
                ui_check("名称maxlength=15", form.get("tagname_maxlength") == 15, str(form))
                ui_check("默认HTTP", form.get("protocol_value") == "http", str(form))
                ui_check("默认目录浏览关闭", form.get("autoindex_value") == "关闭", str(form))
                ui_check("默认下行速率0", str(form.get("download_value")) == "0", str(form))
                ui_check("默认外网访问关闭", form.get("access_checked") is False, str(form))
                ui_check("目录树包含666", "666" in form.get("home_dir_roots", []), str(form))
                require_ui("取消空白新增页", page.cancel_rule_form(), "未返回HTTP列表")

            with rec.step(
                "步骤3: 添加允许目录浏览的HTTP规则",
                "操作：新增HTTP规则，开启目录浏览、不限速并禁止外网访问；验证：列表、数据库、openresty server配置块、端口监听和外网阻断集合都符合设置",
            ):
                primary_expected = expected_rule(
                    primary, homes["primary"], p_http,
                    autoindex=True, access=False,
                )
                added = page.add_rule(
                    primary, homes["primary"], "http", p_http,
                    server_name="", autoindex=True, download=0, access=False,
                )
                require_ui("添加HTTP规则", result_ok(added), result_error(added))
                page.navigate_to_http_server()
                require_ui("HTTP规则列表存在", page.rule_exists(primary), primary)
                require_ssh("L1-HTTP规则", backend.verify_http_rule_database,
                            primary, expected_fields=primary_expected)
                require_ssh("L2-HTTP配置", backend.verify_http_openresty_config,
                            primary, expected_fields=primary_expected)
                require_ssh("L2-HTTP监听", backend.verify_http_listener, p_http, True)
                require_ssh("L3-HTTP禁止外网", backend.verify_http_firewall, p_http, True)
                require_ssh("L4-HTTP单规则一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

            with rec.step(
                "步骤4: 添加使用内置证书的HTTPS规则",
                "操作：使用独立端口、目录和域名新增HTTPS规则，关闭目录浏览并允许外网；验证：数据库字段、SSL证书配置、server配置块和HTTPS端口监听正确",
            ):
                https_expected = expected_rule(
                    https_rule, homes["https"], p_https,
                    protocol="https", server_name=https_domain,
                    autoindex=False, access=True,
                )
                added = page.add_rule(
                    https_rule, homes["https"], "https", p_https,
                    server_name=https_domain, autoindex=False,
                    download=0, access=True,
                )
                require_ui("添加HTTPS规则", result_ok(added), result_error(added))
                require_ssh("L1-HTTPS规则", backend.verify_http_rule_database,
                            https_rule, expected_fields=https_expected)
                require_ssh("L2-HTTPS配置/证书", backend.verify_http_openresty_config,
                            https_rule, expected_fields=https_expected)
                require_ssh("L2-HTTPS监听", backend.verify_http_listener, p_https, True)
                require_ssh("L3-HTTPS允许外网", backend.verify_http_firewall, p_https, False)

            with rec.step(
                "步骤5: 搜索HTTP规则、清空搜索并确认无排序功能",
                "操作：搜索存在与不存在的规则，清空条件，并尝试点击名称排序；验证：搜索结果准确且可恢复全部列表，名称列确实没有排序入口且顺序不变",
            ):
                page.navigate_to_http_server()
                page.search_rule(primary)
                ui_check("搜索命中HTTP", page.rule_exists(primary), primary)
                ui_check("搜索排除HTTPS", not page.rule_exists(https_rule), https_rule)
                page.search_rule("http_t_not_found")
                ui_check("搜索空结果", not page.rule_exists(primary), "不存在关键字仍显示")
                page.clear_search()
                before = [name for name in page.get_rule_names() if name.startswith(prefix)]
                sorted_click = page.sort_by_column("名称")
                after = [name for name in page.get_rule_names() if name.startswith(prefix)]
                ui_check("名称列无排序入口", not sorted_click and before == after,
                         f"before={before}, after={after}")

            with rec.step(
                "步骤6: 编辑HTTP规则的目录、端口、域名、限速和外网权限",
                "操作：将主HTTP规则迁移到新端口与目录，修改域名，关闭目录浏览，设置64KB/s下载限速并允许外网；验证：新配置全部生效，旧端口在配置、监听和防火墙中完全释放",
            ):
                edited = page.update_rule(
                    primary,
                    home_dir=homes["edited"], protocol="http", http_port=p_edit,
                    server_name=primary_domain, autoindex=False,
                    download=64, access=True,
                )
                require_ui("编辑HTTP规则", result_ok(edited), result_error(edited))
                primary_expected = expected_rule(
                    primary, homes["edited"], p_edit,
                    server_name=primary_domain, autoindex=False,
                    download=64, access=True,
                )
                require_ssh("L1-编辑后字段", backend.verify_http_rule_database,
                            primary, expected_fields=primary_expected)
                require_ssh("L2-编辑后配置", backend.verify_http_openresty_config,
                            primary, expected_fields=primary_expected)
                require_ssh("L2-旧端口释放", backend.verify_http_listener, p_http, False)
                require_ssh("L3-旧端口DROP释放", backend.verify_http_firewall, p_http, False)
                require_ssh("L2-新端口监听", backend.verify_http_listener, p_edit, True)
                require_ssh("L3-新端口允许外网", backend.verify_http_firewall, p_edit, False)
                require_ssh("L4-编辑迁移一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

            with rec.step(
                "步骤7: 单独停用并重新启用HTTP规则",
                "操作：对主HTTP规则先停用再启用；验证：停用后列表状态和数据库enabled=no，server配置块与监听消失，重新启用后全部恢复",
            ):
                page.navigate_to_http_server()
                require_ui("单条停用HTTP", page.disable_rule(primary), primary)
                require_ui("列表显示已停用", page.is_rule_disabled(primary), primary)
                require_ssh("L1-单停", backend.verify_http_rule_database,
                            primary, expected_fields={"enabled": "no"})
                require_ssh("L2-单停配置移除", backend.verify_http_openresty_config,
                            primary, expect_present=False)
                require_ssh("L2-单停监听移除", backend.verify_http_listener, p_edit, False)
                require_ui("单条启用HTTP", page.enable_rule(primary), primary)
                require_ui("列表显示已启用", page.is_rule_enabled(primary), primary)
                require_ssh("L1-单启", backend.verify_http_rule_database,
                            primary, expected_fields={"enabled": "yes"})
                require_ssh("L2-单启监听恢复", backend.verify_http_listener, p_edit, True)
                require_ssh("L4-单停启一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

            with rec.step(
                "步骤8: 重命名HTTP规则、切换为HTTPS并单独删除",
                "操作：创建独立样本，修改名称并从HTTP切换为HTTPS，完成访问后执行单条删除；验证：数据库、TLS配置和真实访问正确，删除后数据库、配置、监听和防火墙无残留",
            ):
                sample_expected = expected_rule(
                    delete_rule, homes["edited"], p_delete, access=False
                )
                added = page.add_rule(
                    delete_rule, homes["edited"], "http", p_delete,
                    autoindex=False, download=0, access=False,
                )
                require_ui("添加删除样本", result_ok(added), result_error(added))
                require_ssh("L1-删除样本", backend.verify_http_rule_database,
                            delete_rule, expected_fields=sample_expected)
                switched = page.update_rule(
                    delete_rule,
                    new_tagname=renamed_rule,
                    protocol="https",
                    server_name=renamed_domain,
                )
                require_ui(
                    "编辑重命名并切换HTTPS",
                    result_ok(switched), result_error(switched),
                )
                switched_expected = expected_rule(
                    renamed_rule, homes["edited"], p_delete,
                    protocol="https", server_name=renamed_domain,
                    access=False,
                )
                require_ssh("L1-编辑旧名称消失", backend.verify_http_rule_database,
                            delete_rule, must_exist=False)
                require_ssh("L1-编辑新名称/协议", backend.verify_http_rule_database,
                            renamed_rule, expected_fields=switched_expected)
                require_ssh("L2-编辑HTTPS证书配置",
                            backend.verify_http_openresty_config,
                            renamed_rule, expected_fields=switched_expected)
                require_ssh(
                    "L5-编辑后HTTPS真实读取",
                    backend.run_http_probe,
                    p_delete, "fetch", LAN_HOST, LAN_IFACE,
                    "/payload.bin", "https", renamed_domain,
                    payloads["edited"]["sha256"], 200,
                )
                page.navigate_to_http_server()
                require_ui("单条删除样本", page.delete_rule(renamed_rule), renamed_rule)
                require_ssh("L1-删除样本无", backend.verify_http_rule_database,
                            renamed_rule, must_exist=False)
                require_ssh("L2-删除样本监听无", backend.verify_http_listener, p_delete, False)
                require_ssh("L3-删除样本DROP无", backend.verify_http_firewall, p_delete, False)

            with rec.step(
                "步骤9: 批量停用、启用并删除HTTP规则",
                "操作：对两个独立规则依次执行批量停用、启用和删除；验证：每个阶段的列表状态、数据库enabled字段、openresty配置与监听均一致，最终数量正确",
            ):
                for index, name in enumerate(batch_rules):
                    port = (p_batch1, p_batch2)[index]
                    home = (homes["edited"], homes["https"])[index]
                    added = page.add_rule(
                        name, home, "http", port,
                        autoindex=False, download=0, access=True,
                    )
                    require_ui(f"添加批量样本-{index + 1}", result_ok(added), result_error(added))
                page.navigate_to_http_server()
                require_ui("批量停用", page.batch_disable_rules(batch_rules), str(batch_rules))
                for index, name in enumerate(batch_rules):
                    require_ssh(f"L1-批停-{name}", backend.verify_http_rule_database,
                                name, expected_fields={"enabled": "no"})
                    require_ssh(f"L2-批停端口{index + 1}", backend.verify_http_listener,
                                (p_batch1, p_batch2)[index], False)
                require_ui("批量启用", page.batch_enable_rules(batch_rules), str(batch_rules))
                for index, name in enumerate(batch_rules):
                    require_ssh(f"L1-批启-{name}", backend.verify_http_rule_database,
                                name, expected_fields={"enabled": "yes"})
                    require_ssh(f"L2-批启端口{index + 1}", backend.verify_http_listener,
                                (p_batch1, p_batch2)[index], True)
                require_ui("批量删除", page.batch_delete_rules(batch_rules), str(batch_rules))
                for index, name in enumerate(batch_rules):
                    require_ssh(f"L1-批删-{name}", backend.verify_http_rule_database,
                                name, must_exist=False)
                    require_ssh(f"L2-批删端口{index + 1}", backend.verify_http_listener,
                                (p_batch1, p_batch2)[index], False)
                require_ssh("L4-批量后一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

            with rec.step(
                "步骤10: 验证HTTP规则名称边界和异常输入",
                "操作：测试15/16字符名称，并分别提交必填项缺失、非法端口、域名、限速、重复规则以及同端口HTTP/HTTPS冲突；验证：合法边界可保存，超长输入被限制，所有非法数据均被拦截且不落库",
            ):
                boundary = page.add_rule(
                    max_rule, homes["edited"], "http", p_delete,
                    autoindex=False, download=0, access=True,
                )
                require_ui("15字符名称可保存", result_ok(boundary), result_error(boundary))
                require_ssh("L1-15字符名称", backend.verify_http_rule_database,
                            max_rule, expected_fields={"tagname": max_rule})
                page.navigate_to_http_server()
                require_ui("删除边界样本", page.delete_rule(max_rule), max_rule)
                overlong = page.try_add_invalid(
                    tagname=overlong_rule, home_dir=homes["edited"],
                    http_port=p_delete,
                )
                require_ui("16字符被maxlength截断", overlong.get("truncated"), str(overlong))
                require_ssh("L1-截断名称未落库", backend.verify_http_rule_database,
                            max_rule, must_exist=False)
                invalid_cases = [
                    ("空名称", dict(tagname="", home_dir=homes["edited"], http_port=p_delete)),
                    ("空目录", dict(tagname=invalid_names["no_home"], home_dir=None, http_port=p_delete)),
                    ("端口0", dict(tagname=invalid_names["bad_port"], home_dir=homes["edited"], http_port=0)),
                    ("预留端口600", dict(tagname=invalid_names["reserved"], home_dir=homes["edited"], http_port=600)),
                    ("端口65536", dict(tagname=invalid_names["overflow"], home_dir=homes["edited"], http_port=65536)),
                    ("占用端口80", dict(tagname=invalid_names["in_use"], home_dir=homes["edited"], http_port=80)),
                    ("非法域名", dict(tagname=invalid_names["domain"], home_dir=homes["edited"], http_port=p_delete, server_name="bad name!")),
                    ("负限速", dict(tagname=invalid_names["download"], home_dir=homes["edited"], http_port=p_delete, download=-1)),
                    ("重复名称", dict(tagname=primary, home_dir=homes["edited"], http_port=p_delete)),
                    ("重复端口域名", dict(tagname=invalid_names["duplicate_pair"], home_dir=homes["edited"], http_port=p_edit, server_name=primary_domain)),
                    ("HTTP/HTTPS同端口混用", dict(
                        tagname=invalid_names["mixed_protocol"],
                        home_dir=homes["edited"], protocol="http",
                        http_port=p_https, server_name=f"m{token}.test",
                    )),
                ]
                for label, kwargs in invalid_cases:
                    invalid = page.try_add_invalid(**kwargs)
                    require_ui(f"异常拦截-{label}", invalid.get("blocked"), result_error(invalid))
                    require_ssh(f"L1-{label}后计数=2", backend.verify_http_rule_count,
                                prefix, expected=2)
                require_ssh("异常后HTTP原记录未变", backend.verify_http_rule_database,
                            primary, expected_fields=primary_expected)
                require_ssh("异常后HTTPS原记录未变", backend.verify_http_rule_database,
                            https_rule, expected_fields=https_expected)
                require_ssh("L4-异常后一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

            with rec.step(
                "步骤11: 在同一HTTP端口添加两个不同域名",
                "操作：使用相同HTTP端口、不同域名和不同目录创建两条规则；验证：页面允许保存，openresty生成两个server配置块，操作系统仅建立一个端口监听",
            ):
                for index, name in enumerate(vhost_rules):
                    expected = expected_rule(
                        name, homes[f"vhost{index + 1}"], p_vhost,
                        server_name=vhost_domains[index],
                        autoindex=index == 0, access=True,
                    )
                    added = page.add_rule(
                        name, homes[f"vhost{index + 1}"], "http", p_vhost,
                        server_name=vhost_domains[index], autoindex=index == 0,
                        download=0, access=True,
                    )
                    require_ui(f"添加vhost-{index + 1}", result_ok(added), result_error(added))
                    require_ssh(f"L1-vhost-{index + 1}", backend.verify_http_rule_database,
                                name, expected_fields=expected)
                    require_ssh(f"L2-vhost-{index + 1}", backend.verify_http_openresty_config,
                                name, expected_fields=expected)
                require_ssh("L2-vhost共享端口监听", backend.verify_http_listener, p_vhost, True)
                require_ssh("L3-vhost允许外网", backend.verify_http_firewall, p_vhost, False)
                require_ssh("L1-四条主规则", backend.verify_http_rule_count,
                            prefix, expected=4)
                require_ssh("L4-vhost聚合一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

            with rec.step(
                "步骤12: 导出HTTP CSV和TXT并检查文件格式",
                "操作：分别导出CSV和TXT配置文件，并生成一条安全的临时导入源；验证：CSV严格包含10列，TXT每行严格包含10个key=value字段，任何完整数据行均不进入日志",
            ):
                page.navigate_to_http_server()
                for path in (csv_path, txt_path):
                    if os.path.exists(path):
                        _secure_remove(path)
                started = time.time()
                require_ui("CSV导出", page.export_rules(export_format="csv"), "CSV下载失败")
                require_ui(
                    "CSV本轮文件新鲜",
                    os.path.exists(csv_path) and os.path.getmtime(csv_path) >= started - 1,
                    csv_path,
                )
                safe_import_path, headers, row_count, error = _build_safe_import(
                    csv_path, primary
                )
                require_ui("CSV严格10列表头", headers == EXPORT_HEADERS, str(headers))
                require_ui("CSV安全筛选仅1行", row_count == 1 and bool(safe_import_path), error)
                txt_started = time.time()
                require_ui("TXT导出", page.export_rules(export_format="txt"), "TXT下载失败")
                require_ui(
                    "TXT本轮文件新鲜且非空",
                    os.path.exists(txt_path)
                    and os.path.getmtime(txt_path) >= txt_started - 1
                    and os.path.getsize(txt_path) > 0,
                    txt_path,
                )
                txt_ok, txt_detail = _validate_txt_export(txt_path, primary)
                require_ui("TXT严格10字段契约", txt_ok, txt_detail)
                rec.add_detail("CSV/TXT数据行和字段值均未输出到报告")

            with rec.step(
                "步骤13: 以追加方式导入HTTP配置",
                "操作：先删除主HTTP规则，再明确不清空现有配置并导入安全CSV；验证：主HTTP规则恢复，HTTPS规则和两个同端口域名规则仍保留，数据库与运行配置正确",
            ):
                page.navigate_to_http_server()
                require_ui("导入前删除主HTTP", page.delete_rule(primary), primary)
                require_ssh("L1-导入前主HTTP无", backend.verify_http_rule_database,
                            primary, must_exist=False)
                imported = bool(safe_import_path) and page.import_rules(
                    safe_import_path, clear_existing=False
                )
                require_ui("安全追加导入", imported, "清空选项未明确保持关闭或上传失败")
                page.navigate_to_http_server()
                require_ui("导入后主HTTP恢复", page.rule_exists(primary), primary)
                for name in (https_rule, *vhost_rules):
                    ui_check(f"导入保留-{name}", page.rule_exists(name), name)
                require_ssh("L1-导入主HTTP", backend.verify_http_rule_database,
                            primary, expected_fields=primary_expected)
                require_ssh("L2-导入主HTTP配置", backend.verify_http_openresty_config,
                            primary, expected_fields=primary_expected)
                require_ssh("L1-导入后计数=4", backend.verify_http_rule_count,
                            prefix, expected=4)
                require_ssh("导入未影响非测试规则",
                            backend.verify_http_non_test_rules_unchanged,
                            prefix, non_test_snapshot)
                require_ssh("L4-导入后一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

            with rec.step(
                "步骤14: 导入畸形CSV/TXT并确认原配置不受影响",
                "操作：以追加方式分别提交表头合法但记录非法的CSV/TXT；验证：页面明确拒绝，HTTP数据库、openresty配置和非测试数据指纹均保持不变",
            ):
                import_dir = os.path.dirname(csv_path)
                for extension in ("csv", "txt"):
                    malformed = _build_malformed_import(
                        import_dir, extension, invalid_names["malformed"]
                    )
                    malformed_paths.append(malformed)
                    page.navigate_to_http_server()
                    attempt = page.attempt_import(malformed, clear_existing=False)
                    require_ui(
                        f"畸形{extension.upper()}清空选项关闭",
                        attempt.get("clear_state") is False,
                        result_error(attempt),
                    )
                    require_ui(
                        f"畸形{extension.upper()}已提交",
                        attempt.get("submitted"), result_error(attempt),
                    )
                    require_ui(
                        f"畸形{extension.upper()}明确拒绝",
                        attempt.get("rejected") is True
                        and attempt.get("success") is not True,
                        result_error(attempt) or str(attempt),
                    )
                    require_ssh(
                        f"L1-{extension.upper()}后计数=4",
                        backend.verify_http_rule_count, prefix, expected=4,
                    )
                    require_ssh(
                        f"L1-{extension.upper()}后主规则未变",
                        backend.verify_http_rule_database,
                        primary, expected_fields=primary_expected,
                    )
                    require_ssh(
                        f"{extension.upper()}后非测试规则未变",
                        backend.verify_http_non_test_rules_unchanged,
                        prefix, non_test_snapshot,
                    )
                require_ssh("L4-畸形导入后一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

            with rec.step(
                "步骤15: 检查HTTP文件管理入口和未保存表单处理",
                "操作：在新增表单输入未保存内容，点击文件管理，关闭弹出页后取消表单；验证：文件管理正确打开目标路由，取消时出现未保存确认，最终无多余页面且数据库不落入该规则",
            ):
                page.navigate_to_http_server()
                require_ui("打开dirty新增页", page.open_add_page(), "新增页失败")
                require_ui("制造dirty名称", page.fill_tagname(dirty_rule), dirty_rule)
                manager = page.open_file_manager()
                manager_url = manager.get("url", "")
                require_ui("文件管理按钮可点", manager.get("clicked"), result_error(manager))
                require_ui("文件管理popup打开", manager.get("popup_opened"), manager_url)
                ui_check(
                    "文件管理dirty场景无确认(实机事实)",
                    manager.get("unsaved_confirm_seen") is False,
                    str(manager),
                )
                ui_check(
                    "文件管理目标路由",
                    "equipmentSetting/diskManagement" in manager_url
                    and "tab=fileManagement" in manager_url,
                    manager_url,
                )
                ui_check("文件管理无孤儿Tab", manager.get("no_orphan"), manager_url)
                require_ui("dirty取消后退出", page.cancel_rule_form(confirm_dirty=True),
                           str(page.last_cancel_result))
                ui_check(
                    "dirty取消出现未保存确认",
                    page.last_cancel_result.get("unsaved_confirm_seen") is True,
                    str(page.last_cancel_result),
                )
                require_ssh("L1-dirty名称未落库", backend.verify_http_rule_database,
                            dirty_rule, must_exist=False)

            with rec.step(
                "步骤16: 检查HTTP页面右下角帮助入口",
                "操作：点击帮助按钮并关闭新打开的页面；验证：链接指向ikuai8.com的602号文章，关闭后不留下多余页面",
            ):
                page.navigate_to_http_server()
                help_result = page.verify_help_entry()
                help_url = help_result.get("url", "")
                parsed_help = urlparse(help_url)
                help_query = parse_qs(parsed_help.query)
                ui_check("帮助按钮可点", help_result.get("clicked"), result_error(help_result))
                ui_check("帮助popup打开", help_result.get("popup_opened"), help_url)
                ui_check(
                    "帮助URL域名",
                    parsed_help.scheme == "https"
                    and parsed_help.hostname == "www.ikuai8.com",
                    help_url,
                )
                ui_check(
                    "帮助文章602",
                    help_query.get("id") == ["602"],
                    help_url,
                )
                ui_check("帮助无孤儿页", help_result.get("no_orphan"), help_url)

            with rec.step(
                "步骤17: 综合核对HTTP数据库、openresty配置与服务状态",
                "操作：执行http_server.sh init重建底层配置；验证：4条规则、3个去重端口、HTTP/HTTPS/双域名配置块、openresty进程、监听和外网防火墙集合完全一致",
            ):
                require_ssh("L1-主规则", backend.verify_http_rule_database,
                            primary, expected_fields=primary_expected)
                require_ssh("L1-HTTPS", backend.verify_http_rule_database,
                            https_rule, expected_fields=https_expected)
                require_ssh("L1-总计4", backend.verify_http_rule_count,
                            prefix, expected=4)
                require_ssh("L2-openresty进程", backend.verify_http_process, True)
                for port in (p_edit, p_https, p_vhost):
                    require_ssh(f"L2-监听-{port}", backend.verify_http_listener, port, True)
                    require_ssh(f"L3-WAN允许-{port}", backend.verify_http_firewall, port, False)
                require_ssh("L4-综合一致", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)
                require_ssh("L4-http_server.sh init", backend.verify_http_reinit,
                            prefix, candidate_ports)

            with rec.step(
                "步骤18: 从内网访问HTTP文件并验证404/403返回",
                "操作：带正确Host访问主HTTP文件，再访问不存在的文件和已关闭目录浏览的根目录；验证：主文件SHA256正确，不存在的文件返回404，不可浏览的目录返回403",
            ):
                primary_sha = payloads["edited"]["sha256"]
                require_ssh(
                    "L5-HTTP payload SHA256",
                    backend.run_http_probe,
                    p_edit, "fetch", LAN_HOST, LAN_IFACE,
                    "/payload.bin", "http", primary_domain,
                    primary_sha, 200,
                )
                require_ssh(
                    "L5-HTTP 404",
                    backend.run_http_probe,
                    p_edit, "fetch", LAN_HOST, LAN_IFACE,
                    f"/missing-{token}.bin", "http", primary_domain,
                    None, 404,
                )
                require_ssh(
                    "L5-autoindex关闭403",
                    backend.run_http_probe,
                    p_edit, "fetch", LAN_HOST, LAN_IFACE,
                    "/", "http", primary_domain,
                    None, 403,
                )

            with rec.step(
                "步骤19: 通过真实TLS连接读取HTTPS文件",
                "操作：使用SNI和Host访问内置证书的HTTPS端点；验证：TLS连接建立成功，返回文件的SHA256与预期完全一致",
            ):
                require_ssh(
                    "L5-HTTPS SHA256",
                    backend.run_http_probe,
                    p_https, "fetch", LAN_HOST, LAN_IFACE,
                    "/payload.bin", "https", https_domain,
                    payloads["https"]["sha256"], 200,
                )

            with rec.step(
                "步骤20: 验证同端口双域名、目录浏览和单成员停启",
                "操作：通过两个Host访问同一端口，测试目录浏览开关，并单独停用其中一条规则；验证：两个Host返回不同的正确SHA256，目录浏览正反结果正确，停用一条后共享端口与另一Host仍可用",
            ):
                for index, domain in enumerate(vhost_domains):
                    require_ssh(
                        f"L5-vhost-{index + 1}-SHA",
                        backend.run_http_probe,
                        p_vhost, "fetch", LAN_HOST, LAN_IFACE,
                        "/payload.bin", "http", domain,
                        payloads[f"vhost{index + 1}"]["sha256"], 200,
                    )
                require_ssh(
                    "L5-autoindex开启列表",
                    backend.run_http_probe,
                    p_vhost, "autoindex", LAN_HOST, LAN_IFACE,
                    "/", "http", vhost_domains[0],
                    None, 200, ["payload.bin", "marker.txt"],
                )
                require_ssh(
                    "L5-vhost2目录浏览关闭",
                    backend.run_http_probe,
                    p_vhost, "fetch", LAN_HOST, LAN_IFACE,
                    "/", "http", vhost_domains[1],
                    None, 403,
                )
                page.navigate_to_http_server()
                require_ui(
                    "共享端口停用vhost1",
                    page.disable_rule(vhost_rules[0]), vhost_rules[0],
                )
                require_ssh(
                    "L1-vhost1已停用", backend.verify_http_rule_database,
                    vhost_rules[0], expected_fields={"enabled": "no"},
                )
                require_ssh(
                    "L2-vhost1配置移除", backend.verify_http_openresty_config,
                    vhost_rules[0], expect_present=False,
                )
                require_ssh(
                    "L2-vhost2维持共享监听",
                    backend.verify_http_listener, p_vhost, True,
                )
                require_ssh(
                    "L5-vhost1停用后vhost2仍可读",
                    backend.run_http_probe,
                    p_vhost, "fetch", LAN_HOST, LAN_IFACE,
                    "/payload.bin", "http", vhost_domains[1],
                    payloads["vhost2"]["sha256"], 200,
                )
                require_ui(
                    "共享端口重新启用vhost1",
                    page.enable_rule(vhost_rules[0]), vhost_rules[0],
                )
                require_ssh(
                    "L1-vhost1重新启用", backend.verify_http_rule_database,
                    vhost_rules[0], expected_fields={"enabled": "yes"},
                )
                require_ssh(
                    "L4-vhost停启后聚合一致",
                    backend.verify_http_runtime_consistency,
                    prefix, candidate_ports,
                )

            with rec.step(
                "步骤21: 对比HTTP下载限速规则与不限速控制组",
                "操作：用64KB/s主规则和不限速控制规则分别下载同一份文件；验证：两次下载文件SHA256都正确，限速组的耗时和平均速率与不限速组形成合理对比",
            ):
                control_expected = expected_rule(
                    control_rule, homes["edited"], p_http,
                    server_name=control_domain, download=0, access=True,
                )
                added = page.add_rule(
                    control_rule, homes["edited"], "http", p_http,
                    server_name=control_domain, autoindex=False,
                    download=0, access=True,
                )
                require_ui("添加无限速控制规则", result_ok(added), result_error(added))
                require_ssh("L1-限速控制规则", backend.verify_http_rule_database,
                            control_rule, expected_fields=control_expected)
                require_ssh(
                    "L5-64KB/s限速",
                    backend.run_http_probe,
                    p_edit, "throttle", LAN_HOST, LAN_IFACE,
                    "/payload.bin", "http", primary_domain,
                    payloads["edited"]["sha256"], 200, None,
                    control_port=p_http, control_host=LAN_HOST,
                    control_iface=LAN_IFACE, control_path="/payload.bin",
                    control_scheme="http", control_server_name=control_domain,
                    rate_limit_kbps=64, timeout_seconds=35,
                )
                page.navigate_to_http_server()
                require_ui("删除限速控制规则", page.delete_rule(control_rule), control_rule)
                require_ssh("L1-控制规则删除", backend.verify_http_rule_database,
                            control_rule, must_exist=False)

            with rec.step(
                "步骤22: 验证HTTP外网访问开关",
                "操作：关闭主规则的外网访问后分别从内外网请求同一文件，再重新允许外网；验证：关闭时端口进入阻断集合、内网仍可读取但外网超时，恢复后外网可读取正确SHA256",
            ):
                restricted = page.update_rule(primary, access=False)
                require_ui("关闭主规则外网访问", result_ok(restricted), result_error(restricted))
                primary_expected["access"] = 0
                require_ssh("L1-access=0", backend.verify_http_rule_database,
                            primary, expected_fields=primary_expected)
                require_ssh("L3-WAN端口进DROP", backend.verify_http_firewall, p_edit, True)
                require_ssh(
                    "L5-WAN DROP且LAN控制成功",
                    backend.run_http_probe,
                    p_edit, "connect_fail", WAN_HOST, WAN_IFACE,
                    "/payload.bin", "http", primary_domain,
                    payloads["edited"]["sha256"], 200, None,
                    control_port=p_edit, control_host=LAN_HOST,
                    control_iface=LAN_IFACE, control_path="/payload.bin",
                    control_scheme="http", control_server_name=primary_domain,
                    timeout_seconds=12,
                )
                allowed = page.update_rule(primary, access=True)
                require_ui("恢复主规则外网访问", result_ok(allowed), result_error(allowed))
                primary_expected["access"] = 1
                require_ssh("L3-WAN端口移出DROP", backend.verify_http_firewall, p_edit, False)
                require_ssh(
                    "L5-WAN读取恢复",
                    backend.run_http_probe,
                    p_edit, "fetch", WAN_HOST, WAN_IFACE,
                    "/payload.bin", "http", primary_domain,
                    payloads["edited"]["sha256"], 200,
                )

            with rec.step(
                "步骤23: 验证HTTP规则停用后拒绝真实连接",
                "操作：停用主端口上唯一的HTTP规则，从内网发起真实请求，然后重新启用；验证：停用后server配置块和监听消失、内网连接失败，重新启用后访问恢复",
            ):
                page.navigate_to_http_server()
                require_ui("L5前停用主规则", page.disable_rule(primary), primary)
                require_ssh("L2-停用监听消失", backend.verify_http_listener, p_edit, False)
                require_ssh(
                    "L5-停用后LAN拒绝",
                    backend.run_http_probe,
                    p_edit, "connect_fail", LAN_HOST, LAN_IFACE,
                    "/payload.bin", "http", primary_domain,
                    None, 200, None, timeout_seconds=10,
                )
                require_ui("L5后重新启用", page.enable_rule(primary), primary)
                require_ssh("L2-重新启用监听", backend.verify_http_listener, p_edit, True)

            with rec.step(
                "步骤24: 删除最终HTTP/HTTPS规则并释放全部测试端口",
                "操作：删除主HTTP和HTTPS规则，再逐条删除共享端口的两个域名规则；验证：删除第一个域名时另一个仍可读取，全部删除后候选端口在数据库、配置、监听和防火墙中均已释放",
            ):
                for name in (primary, https_rule):
                    page.navigate_to_http_server()
                    require_ui(f"最终删除-{name}", page.delete_rule(name), name)
                    require_ssh(f"L1-最终删除-{name}", backend.verify_http_rule_database,
                                name, must_exist=False)
                page.navigate_to_http_server()
                require_ui(
                    f"最终删除-{vhost_rules[0]}",
                    page.delete_rule(vhost_rules[0]), vhost_rules[0],
                )
                require_ssh(
                    f"L1-最终删除-{vhost_rules[0]}",
                    backend.verify_http_rule_database,
                    vhost_rules[0], must_exist=False,
                )
                require_ssh(
                    "L1-共享端口剩余vhost2",
                    backend.verify_http_rule_database,
                    vhost_rules[1], expected_fields={"enabled": "yes"},
                )
                require_ssh(
                    "L2-删vhost1后共享监听仍在",
                    backend.verify_http_listener, p_vhost, True,
                )
                require_ssh(
                    "L5-删vhost1后vhost2仍可读",
                    backend.run_http_probe,
                    p_vhost, "fetch", LAN_HOST, LAN_IFACE,
                    "/payload.bin", "http", vhost_domains[1],
                    payloads["vhost2"]["sha256"], 200,
                )
                page.navigate_to_http_server()
                require_ui(
                    f"最终删除-{vhost_rules[1]}",
                    page.delete_rule(vhost_rules[1]), vhost_rules[1],
                )
                require_ssh(
                    f"L1-最终删除-{vhost_rules[1]}",
                    backend.verify_http_rule_database,
                    vhost_rules[1], must_exist=False,
                )
                require_ssh(
                    "L2-共享端口最终释放",
                    backend.verify_http_listener, p_vhost, False,
                )
                require_ssh("L1-最终前缀计数0", backend.verify_http_rule_count,
                            prefix, expected=0)
                require_ssh("L4-最终运行时无规则", backend.verify_http_runtime_consistency,
                            prefix, candidate_ports)

        finally:
            with rec.step(
                "步骤25: 清理测试数据并恢复HTTP原始环境",
                "清理：删除本轮规则、测试目录、临时导入与导出文件，并先证明随机前缀无残留；恢复与验证：还原数据库、openresty配置、暂存文件、监听、防火墙和本地文件的测试前状态",
            ):
                all_local_imports = [
                    path for path in [safe_import_path, *malformed_paths] if path
                ]
                import_filenames = [os.path.basename(path) for path in all_local_imports]
                if mutation_started:
                    try:
                        page.navigate_to_http_server()
                        removed = page.clean_test_rules(prefix)
                        rec.add_detail(f"[finally UI清理] 删除{removed}条本轮HTTP规则")
                    except Exception as exc:
                        ui_failures.append(f"finally UI清理异常: {str(exc)[:120]}")
                    try:
                        cleanup_message = backend.cleanup_http_test(
                            prefix,
                            test_environment=prepared_environment or fallback_environment,
                            candidate_ports=candidate_ports,
                            import_filenames=import_filenames,
                            snapshot=global_snapshot,
                        )
                        rec.add_detail(f"[finally backend清理] {cleanup_message[:360]}")
                        if str(cleanup_message).lower().startswith("error"):
                            ssh_failures.append(cleanup_message[:180])
                    except Exception as exc:
                        ssh_failures.append(f"finally backend清理异常: {str(exc)[:160]}")
                    ssh_verify(
                        "finally-恢复前独立残留审计",
                        backend.verify_http_test_artifacts_absent,
                        prefix,
                        test_environment=prepared_environment or fallback_environment,
                        candidate_ports=candidate_ports,
                        import_filenames=import_filenames,
                        snapshot=None,
                        must_pass=True,
                    )
                    if snapshot_valid and global_snapshot:
                        ssh_verify(
                            "finally-恢复全环境快照",
                            backend.restore_http_environment,
                            global_snapshot,
                            prefix=prefix,
                            must_pass=True,
                        )
                        ssh_verify(
                            "finally-恢复后残留/基线审计",
                            backend.verify_http_test_artifacts_absent,
                            prefix,
                            test_environment=prepared_environment or fallback_environment,
                            candidate_ports=candidate_ports,
                            import_filenames=import_filenames,
                            snapshot=global_snapshot,
                            must_pass=True,
                        )
                        ssh_verify(
                            "finally-L4全局一致性",
                            backend.verify_http_runtime_consistency,
                            None,
                            candidate_ports,
                            must_pass=True,
                        )
                        if non_test_snapshot is not None:
                            ssh_verify(
                                "finally-非测试HTTP规则未变化",
                                backend.verify_http_non_test_rules_unchanged,
                                prefix,
                                non_test_snapshot,
                                must_pass=True,
                            )
                    else:
                        ssh_failures.append("已开始HTTP变更但无有效快照，无法精确恢复")
                else:
                    rec.add_detail("[finally] 未开始HTTP设备变更，跳过设备清理/恢复")

                try:
                    for local_path in all_local_imports:
                        _secure_remove(local_path)
                    imports_absent = all(
                        not os.path.exists(path) for path in all_local_imports
                    )
                    csv_restored = _restore_local_file(
                        csv_path, csv_existed, csv_backup
                    )
                    txt_restored = _restore_local_file(
                        txt_path, txt_existed, txt_backup
                    )
                    ui_check("本地临时导入文件已删除", imports_absent,
                             "安全/畸形导入文件仍存在")
                    ui_check("原CSV状态字节级恢复", csv_restored, csv_path)
                    ui_check("原TXT状态字节级恢复", txt_restored, txt_path)
                except Exception as exc:
                    ui_failures.append(f"finally本地文件恢复异常: {str(exc)[:140]}")

        failures = ssh_failures + ui_failures
        if failures:
            print(
                f"[HTTP断言] 共{len(failures)}项失败 "
                f"(SSH={len(ssh_failures)}, UI={len(ui_failures)})",
                flush=True,
            )
            for failure in failures[:50]:
                print(f"  - {failure}", flush=True)
        assert not failures, (
            f"HTTP服务L1-L5综合验证失败({len(failures)}项): "
            + "; ".join(failures[:30])
        )
