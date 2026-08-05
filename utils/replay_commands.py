"""Human-oriented, copy-ready verification commands for local services.

The automation backend deliberately uses compact shell programs with markers,
variables and secret-safe stdin scripts.  Those commands are ideal for machine
parsing but poor report content.  This module builds a separate, copy-ready set
from the public verifier call and its arguments.  Configuration checks are
read-only; L5 upload/download cleanup commands carry an explicit side-effect
label so the report never presents them as harmless queries.  SNMP protocol
commands call a root-owned helper which reads secrets from a TTY and removes
its mode-0600 temporary configuration on exit.

``None`` means the verifier is not handled here and the legacy report path may
be used.  A list (including an empty list) means the verifier was handled and
its internal commands must not be exposed as copy-ready commands.
"""

from __future__ import annotations

import inspect
import ipaddress
import re
import shlex
from typing import Any, Dict, Iterable, List, Optional


DB_PATH = "/etc/mnt/ikuai/config.db"
SNMP_VERIFY_ENTRY = "/usr/local/sbin/ikuai-snmp-verify"
SNMP_CONFIG_PATH = "/var/run/snmp/snmpd.conf"
SNMP_MINIUPNPD_CONFIG_PATH = "/tmp/iktmp/miniupnpd.conf"
BASIC_CACHE_PATH = "/tmp/iktmp/cache/config/basic"


_SNMP_SAFE_DB_FIELDS = (
    "id,enabled,listen_port,version,rw,security,auth_proto,priv_proto,"
    "length(COALESCE(syslocation,'')) AS syslocation_len,"
    "length(COALESCE(syscontact,'')) AS syscontact_len,"
    "length(COALESCE(sysname,'')) AS sysname_len,"
    "length(COALESCE(source,'')) AS source_len,"
    "length(COALESCE(username,'')) AS username_len,"
    "CASE WHEN length(COALESCE(community,''))>0 THEN 'stored' ELSE 'missing' END AS community_state,"
    "CASE WHEN length(COALESCE(auth_pass,''))>0 THEN 'stored' ELSE 'missing' END AS auth_pass_state,"
    "CASE WHEN length(COALESCE(priv_pass,''))>0 THEN 'stored' ELSE 'missing' END AS priv_pass_state"
)


_SENSITIVE_RESULT_ASSIGNMENT = re.compile(
    r"(?i)(community|auth(?:entication)?[_ -]?(?:pass(?:word)?|key)|"
    r"priv(?:acy)?[_ -]?(?:pass(?:word)?|key)|password|passwd|secret|"
    r"团体名|认证(?:口令|密码|密钥)|隐私(?:口令|密码|密钥))"
    r"\s*[:=]\s*([^,;，\r\n}\]]+)"
)
_SENSITIVE_RESULT_JSON = re.compile(
    r"(?i)([\"'](?:community|auth(?:entication)?[_ -]?(?:pass(?:word)?|key)|"
    r"priv(?:acy)?[_ -]?(?:pass(?:word)?|key)|password|passwd|secret)[\"']"
    r"\s*:\s*)([\"'])(.*?)\2"
)


def _sql_literal(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _double_quote(value: Any) -> str:
    text = str(value)
    if "\n" in text or "\r" in text:
        raise ValueError("人工复验命令参数不能包含换行")
    text = (text.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("$", "\\$")
                .replace("`", "\\`"))
    return f'"{text}"'


def _sqlite(sql: str) -> str:
    statement = " ".join(str(sql).strip().split())
    if not statement.endswith(";"):
        statement += ";"
    return f"sqlite3 {DB_PATH} -line {_double_quote(statement)}"


def _prefix_predicate(prefix: str, fields: Iterable[str]) -> str:
    prefix = str(prefix)
    literal = _sql_literal(prefix)
    length = len(prefix)
    return " OR ".join(
        f"substr(COALESCE({field},''),1,{length})={literal}"
        for field in fields
    )


def _bound_arguments(verify_func, args, kwargs) -> Dict[str, Any]:
    try:
        bound = inspect.signature(verify_func).bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except Exception:
        return {}


def _host_for(bv, target: str) -> str:
    try:
        config = getattr(bv, "_ssh_config")
        return str(getattr(config, target).host)
    except Exception:
        return ""


def _target_label(target: str) -> str:
    return "路由器" if target == "router" else "测试客户端"


def _is_basic_setting_verifier_name(name: str) -> bool:
    return str(name).startswith((
        "get_basic_",
        "verify_basic_",
        "run_basic_",
        "prepare_basic_",
        "restore_basic_",
        "cleanup_basic_",
    ))


_BANNED_COPY_PATTERNS = (
    r"\b(?:if|then|fi|for|do|done|while|case|esac)\b",
    r"\$\(",
    r"\$\{",
    r"\$(?:\?|[A-Za-z_][A-Za-z0-9_]*)",
    r"__(?:FTP|SAMBA|HTTP|SNMP)_[A-Z0-9_]+__",
    r"<redacted>",
    r"(?:^|[ ;])\[(?:router|client)\](?:$|[ ;])",
    r"\bbase64(?:\s|$)",
    r"\b(?:[A-Za-z0-9_.-]+_probe|snmp_probe)(?:\s|$)",
    r"\.\.\.|…",
    re.escape("'\"'\"'"),
)


def _validate_copy_command(command: str) -> str:
    command = str(command).strip()
    if not command or "\n" in command or "\r" in command:
        raise ValueError("人工复验命令必须是单条非空命令")
    for pattern in _BANNED_COPY_PATTERNS:
        if re.search(pattern, command):
            raise ValueError(f"人工复验命令包含机器脚本语法: {pattern}")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"人工复验命令引号不完整: {exc}") from exc
    if _has_unquoted_shell_assignment(command):
        raise ValueError("人工复验命令不能包含shell变量赋值")
    if _has_unquoted_shell_semicolon(command):
        raise ValueError("人工复验命令一次只能验证一件事，不能用分号串联")
    shell_keywords = {"if", "then", "fi", "for", "do", "done", "while", "case", "esac"}
    if any(token.lower() in shell_keywords for token in tokens):
        raise ValueError("人工复验命令不能包含shell控制语句")
    return command


def _has_unquoted_shell_assignment(command: str) -> bool:
    """Detect shell assignments while allowing SQL/grep expressions in quotes."""
    token = []
    quote = None
    escaped = False

    def is_assignment(chars):
        text = "".join(chars)
        return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", text))

    for char in str(command):
        if escaped:
            token.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            token.append(char)
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            token.append(char)
            continue
        if char in {"'", '"'}:
            quote = char
            token.append(char)
            continue
        if char.isspace() or char in ";|&":
            if is_assignment(token):
                return True
            token = []
            continue
        token.append(char)
    return is_assignment(token)


def _has_unquoted_shell_semicolon(command: str) -> bool:
    quote = None
    escaped = False
    for char in str(command):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == ";":
            return True
    return False


def _command(
    bv,
    target: str,
    purpose: str,
    command: str,
    expected: str,
    *,
    interactive: bool = False,
    interactive_hint: str = "",
    effect: str = "read_only",
    copy_ready: bool = True,
    contains_secret: bool = False,
    actual: Any = "",
    valid_when: str = "对应步骤完成后、测试环境清理前",
) -> Dict[str, Any]:
    if target not in {"router", "client"}:
        raise ValueError("人工复验命令target只能是router或client")
    return {
        "target": target,
        "target_label": _target_label(target),
        "host": _host_for(bv, target),
        "shell": "sh",
        "purpose": str(purpose),
        "command": _validate_copy_command(command),
        "expected": str(expected),
        "actual": "" if actual is None else str(actual),
        "copy_ready": bool(copy_ready),
        "effect": str(effect),
        "contains_secret": bool(contains_secret),
        "interactive": bool(interactive),
        "interactive_hint": str(interactive_hint),
        "valid_when": str(valid_when),
    }


def _deduplicate(commands: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in commands:
        key = (item.get("target"), item.get("command"), item.get("purpose"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _add_sql(bv, out, purpose, sql, expected, **kwargs):
    out.append(_command(bv, "router", purpose, _sqlite(sql), expected, **kwargs))


def _add_router(bv, out, purpose, command, expected, **kwargs):
    out.append(_command(bv, "router", purpose, command, expected, **kwargs))


def _add_client(bv, out, purpose, command, expected, **kwargs):
    out.append(_command(bv, "client", purpose, command, expected, **kwargs))


def _safe_probe_component(value: Any, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("._-")
    return (text[:48] or fallback)


def _add_client_route(bv, out, host: str, iface: str, service: str):
    _add_client(
        bv,
        out,
        f"确认{service}流量使用测试线路 {iface}",
        f"ip route get {_double_quote(host)}",
        f"输出中包含 dev {iface}，目标地址为 {host}",
    )


def _ftp_curl_prefix(username: str, iface: str) -> str:
    return (
        f"curl --interface {_double_quote(iface)} --silent --show-error "
        f"--ftp-pasv --user {_double_quote(username)} --connect-timeout 5 --max-time 20"
    )


def _smbclient_command(host: str, share: str, username: str, action: str) -> str:
    target = "//" + str(host) + "/" + str(share)
    return (
        f"smbclient {_double_quote(target)} -I {_double_quote(host)} -m SMB2 "
        f"-U {_double_quote(username)} -c {_double_quote(action)}"
    )


def _ftp_common_runtime(bv, out, prefix: str = None, port: int = None):
    if prefix:
        predicate = _prefix_predicate(prefix, ("username", "tagname"))
        _add_sql(
            bv, out, "查看本轮FTP用户数据库字段",
            "SELECT id,enabled,username,tagname,permission,home_dir,upload,download,"
            "CASE WHEN length(COALESCE(passwd,''))>0 THEN 'stored' ELSE 'missing' END "
            f"AS passwd_state FROM ftp_server WHERE {predicate} ORDER BY id",
            "仅返回本轮前缀用户；passwd_state应为stored，不输出密文",
        )
        _add_router(
            bv, out, "查看本轮FTP认证映射（密码字段已剔除）",
            f"grep -nF {_double_quote(prefix)} /tmp/iktmp/ik_ftp_user | cut -d '\"' -f1,3-",
            "每个启用用户一行，目录和读写权限与数据库一致",
        )
    _add_router(
        bv, out, "查看FTP运行配置",
        "grep -nE \"^(listen_port|ikuai_auth_file)=\" /etc/ik_ftp_user.conf",
        "listen_port和ikuai_auth_file与页面设置一致",
    )
    _add_router(bv, out, "查看FTP进程", "pidof ik_ftpd", "启用时返回ik_ftpd PID；关闭时无输出")
    if port:
        _add_router(
            bv, out, f"查看TCP/{int(port)}监听",
            f"netstat -lntp 2>/dev/null | grep -E {_double_quote(':' + str(int(port)) + '[[:space:]]')}",
            "启用时显示目标端口且进程归属ik_ftpd",
        )
        _add_router(
            bv, out, f"查看TCP/{int(port)}外网阻断成员",
            f"ipset list DROP_T_PORTS_WAN_IN 2>/dev/null | grep -x '{int(port)}'",
            "禁止外网时显示该端口；允许外网时无输出",
        )


def _samba_user_sql(username: str) -> str:
    literal = _sql_literal(username)
    return (
        "SELECT id,enabled,username,name,tagname,perm,guest,browseable,home_dir,"
        "CASE WHEN length(COALESCE(passwd,''))>0 THEN 'stored' ELSE 'missing' END "
        f"AS passwd_state FROM smbd_dir WHERE username={literal} LIMIT 1"
    )


def _samba_common_runtime(bv, out, prefix: str = None):
    _add_sql(
        bv, out, "查看Samba全局数据库字段",
        "SELECT id,enabled,workgroup,wsdd2,interface,access FROM smbd ORDER BY id LIMIT 1",
        "全局开关、工作组、发现服务和外网访问字段与页面一致",
    )
    if prefix:
        predicate = _prefix_predicate(prefix, ("username", "name", "tagname"))
        _add_sql(
            bv, out, "查看本轮Samba用户与共享映射",
            "SELECT id,enabled,username,name,tagname,perm,guest,browseable,home_dir,"
            "CASE WHEN length(COALESCE(passwd,''))>0 THEN 'stored' ELSE 'missing' END "
            f"AS passwd_state FROM smbd_dir WHERE {predicate} ORDER BY id",
            "仅返回本轮用户；共享名、目录、匿名、权限和可见性映射正确",
        )
    _add_router(
        bv, out, "查看四个Samba运行时文件元数据",
        "stat -c '%a %U:%G %s %n' /etc/samba/config /etc/samba/smb.conf /etc/samba/smbpasswd /etc/samba/is_enabled",
        "启用状态下文件存在，权限和大小合理",
    )
    _add_router(bv, out, "查看Samba全局缓存", "sed -n '1,120p' /etc/samba/config", "字段与smbd全局表一致")
    _add_router(bv, out, "查看Samba全局段和共享段", "sed -n '1,320p' /etc/samba/smb.conf", "global及本轮共享段字段与数据库一致")
    _add_router(
        bv, out, "查看Samba认证用户名（不输出LM/NT哈希）",
        "cut -d: -f1,2,6,7 /etc/samba/smbpasswd",
        "启用用户存在，停用或删除用户不存在",
    )
    for process in ("ik_smbd", "nmbd", "wsdd2"):
        _add_router(bv, out, f"查看{process}进程", f"pidof {process}", "按当前总开关/WSDD设置返回PID或无输出")
    _add_router(
        bv, out, "查看Samba监听与进程归属",
        "netstat -lntup 2>/dev/null | grep -E \":(137|138|139|445|3702|5355|5357)[[:space:]]\"",
        "端口集合与总开关/WSDD设置一致，PID归属ik_smbd、nmbd或wsdd2",
    )
    _add_router(bv, out, "查看Samba TCP WAN阻断集合", "ipset list DROP_T_PORTS_WAN_IN", "139/445及发现端口成员与外网访问设置一致")
    _add_router(bv, out, "查看Samba UDP WAN阻断集合", "ipset list DROP_U_PORTS_WAN_IN", "137/138及发现端口成员与外网访问设置一致")


def _http_rule_sql(tagname=None, rule_id=None) -> str:
    fields = (
        "id,enabled,tagname,http_port,server_name,ssl_on,autoindex,download,home_dir,access"
    )
    if tagname is not None:
        return f"SELECT {fields} FROM http_server WHERE tagname={_sql_literal(tagname)} LIMIT 1"
    return f"SELECT {fields} FROM http_server WHERE id={int(rule_id)} LIMIT 1"


def _http_common_runtime(bv, out, prefix: str = None, ports: Iterable[int] = None):
    if prefix:
        predicate = _prefix_predicate(prefix, ("tagname",))
        _add_sql(
            bv, out, "查看本轮HTTP服务数据库字段",
            "SELECT id,enabled,tagname,http_port,server_name,ssl_on,autoindex,download,home_dir,access "
            f"FROM http_server WHERE {predicate} ORDER BY id",
            "仅返回本轮规则，字段与页面设置一致",
        )
    else:
        _add_sql(
            bv, out, "查看全部HTTP服务数据库字段",
            "SELECT id,enabled,tagname,http_port,server_name,ssl_on,autoindex,download,home_dir,access FROM http_server ORDER BY id",
            "数据库规则与当前页面配置一致",
        )
    _add_router(
        bv, out, "查看openresty静态文件服务配置",
        "sed -n '1,360p' /usr/openresty/conf/static_file.conf",
        "每条启用规则有对应#sql_id、IPv4/IPv6 listen、root及功能指令",
    )
    _add_router(bv, out, "查看openresty进程", "pidof openresty", "返回openresty PID；部分固件可由下一条nginx PID补充")
    _add_router(bv, out, "查看nginx进程", "pidof nginx", "返回openresty/nginx master与worker PID")
    safe_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})
    if safe_ports:
        pattern = "|".join(str(port) for port in safe_ports)
        _add_router(
            bv, out, "查看本轮HTTP端口监听",
            f"netstat -lntp 2>/dev/null | grep -E {_double_quote(':(' + pattern + ')[[:space:]]')}",
            "仅启用规则端口在监听，进程归属nginx/openresty",
        )
        for port in safe_ports:
            _add_router(
                bv, out, f"查看TCP/{port} WAN阻断成员",
                f"ipset list DROP_T_PORTS_WAN_IN 2>/dev/null | grep -x '{port}'",
                "禁止外网时显示该端口；允许外网或规则未启用时无输出",
            )


def _curl_base(params: Dict[str, Any], *, control: bool = False):
    prefix = "control_" if control else ""
    port = int(params.get(prefix + "port") or params.get("port") or 0)
    host = str(params.get(prefix + "host") or params.get("host") or "192.168.148.1")
    iface = str(params.get(prefix + "iface") or params.get("iface") or "ens11")
    path = str(params.get(prefix + "path") or params.get("path") or "/payload.bin")
    scheme = str(params.get(prefix + "scheme") or params.get("scheme") or "http")
    server_name = params.get(prefix + "server_name") or params.get("server_name")
    display_host = str(server_name or host)
    url = f"{scheme}://{display_host}:{port}{path}"
    parts = [
        "curl", "--interface", _double_quote(iface), "--silent", "--show-error",
        "--connect-timeout", "5", "--max-time", str(int(params.get("timeout_seconds") or 35)),
    ]
    if scheme == "https":
        parts.append("--insecure")
    if server_name:
        parts.extend(["--resolve", _double_quote(f"{server_name}:{port}:{host}")])
    return parts, url


def _snmp_secret_values(params: Optional[Dict[str, Any]]) -> List[str]:
    values: List[str] = []
    params = params or {}
    for key in (
        "community", "username", "auth_pass", "priv_pass", "auth_key", "priv_key",
    ):
        value = params.get(key)
        if value not in (None, ""):
            values.append(str(value))
    expected_secrets = params.get("expected_secrets")
    if isinstance(expected_secrets, dict):
        for value in expected_secrets.values():
            if value not in (None, ""):
                values.append(str(value))
    expected_fields = params.get("expected_fields")
    if isinstance(expected_fields, dict):
        for key in (
            "username", "source", "syslocation", "syscontact", "sysname",
        ):
            value = expected_fields.get(key)
            if value not in (None, ""):
                values.append(str(value))
    snapshot = params.get("snapshot")
    if isinstance(snapshot, dict):
        row = snapshot.get("row")
        if isinstance(row, dict):
            for key in (
                "community", "username", "auth_pass", "priv_pass", "source",
                "syslocation", "syscontact", "sysname",
            ):
                value = row.get(key)
                if value not in (None, ""):
                    values.append(str(value))
    return sorted(set(values), key=len, reverse=True)


def _snmp_result_actual(
    result: Any, params: Optional[Dict[str, Any]] = None
) -> str:
    """Return a compact verifier outcome without retaining credential values."""
    if result is None:
        return "自动化执行时记录；人工复验后请对照终端输出"
    message = str(getattr(result, "message", "") or "").strip()
    message = " ".join(message.split())
    message = _SENSITIVE_RESULT_JSON.sub(
        lambda match: f'{match.group(1)}"[已隐藏]"', message
    )
    message = _SENSITIVE_RESULT_ASSIGNMENT.sub(r"\1=[已隐藏]", message)
    for secret in _snmp_secret_values(params):
        message = message.replace(secret, "[已隐藏]")
    if len(message) > 240:
        message = message[:237] + "..."
    passed = getattr(result, "passed", None)
    status = "通过" if passed is True else ("失败" if passed is False else "已执行")
    return f"{status}：{message}" if message else status


def _snmp_safe_db_sql(where: str = "") -> str:
    suffix = f" WHERE {where}" if where else ""
    return f"SELECT {_SNMP_SAFE_DB_FIELDS} FROM snmp_conf{suffix} ORDER BY id"


def _snmp_sanitized_config_command() -> str:
    """Display generated config while replacing every credential-bearing line."""
    sensitive_directives = (
        "rocommunity", "rocommunity6", "rwcommunity", "rwcommunity6",
        "createUser", "rouser", "rwuser",
        "com2sec", "authcommunity", "authuser", "trapsess",
    )
    expressions = " ".join(
        f"-e '/^[[:space:]]*{directive}[[:space:]]/s/.*/{directive} [hidden]/'"
        for directive in sensitive_directives
    )
    return f"sed {expressions} {SNMP_CONFIG_PATH}"


def _snmp_port_from(params: Dict[str, Any], result: Any = None, default: int = 161) -> int:
    values = []
    expected = params.get("expected_fields")
    if isinstance(expected, dict):
        values.extend((expected.get("listen_port"), expected.get("port")))
    snapshot = params.get("snapshot")
    if isinstance(snapshot, dict):
        row = snapshot.get("row")
        if isinstance(row, dict):
            values.extend((row.get("listen_port"), row.get("port")))
        values.extend((snapshot.get("listen_port"), snapshot.get("port")))
    values.extend((params.get("listen_port"), params.get("port")))
    if result is not None:
        details = getattr(result, "details", {}) or {}
        if isinstance(details, dict):
            values.extend((details.get("listen_port"), details.get("port")))
    for value in values:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            return port
    return int(default)


def _snmp_route_host(host: Any) -> str:
    """Return the pure IP accepted by ``ip route get`` from IP or IPv4:port."""
    text = str(host or "").strip()
    ipv4_port = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", text)
    if ipv4_port:
        text = ipv4_port.group(1)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ValueError("人工SNMP路由复验必须提供纯IP或IPv4:port") from exc


def _snmp_route_iface(host: str) -> str:
    address = ipaddress.ip_address(host)
    if address in ipaddress.ip_network("192.168.148.0/24"):
        return "ens11"
    return "enp2s0"


def _snmp_add_database(bv, out, actual: str, *, valid_when: str = None):
    kwargs = {"actual": actual}
    if valid_when:
        kwargs["valid_when"] = valid_when
    _add_sql(
        bv,
        out,
        "查看SNMP服务数据库记录（秘密字段仅显示存储状态）",
        _snmp_safe_db_sql(),
        "非敏感字段与页面一致；community、认证口令和隐私口令仅显示stored/missing",
        **kwargs,
    )


def _snmp_add_generated_config(
    bv,
    out,
    actual: str,
    *,
    expect_present: bool = True,
    valid_when: str = None,
):
    kwargs = {"actual": actual}
    if valid_when:
        kwargs["valid_when"] = valid_when
    _add_router(
        bv,
        out,
        "查看SNMP后端脚本与接口入口",
        "stat -c '%a %U:%G %s %n' /usr/ikuai/script/netsnmp.sh /usr/ikuai/function/netsnmp",
        "两个实机入口存在，权限和所有者符合固件基线",
        **kwargs,
    )
    _add_router(
        bv,
        out,
        "查看SNMP脚本的DB到运行时映射点",
        "grep -nE 'snmp_conf|snmpd.conf|snmpd.pid|subsnmpd.pid|listen_port|miniupnpd' /usr/ikuai/script/netsnmp.sh",
        "输出覆盖snmp_conf读取、配置生成、PID、监听端口和UPnP排除链路",
        **kwargs,
    )
    _add_router(
        bv,
        out,
        "查看SNMP生成配置文件元数据",
        f"stat -c '%a %U:%G %s %n' {SNMP_CONFIG_PATH}",
        ("启用时文件存在且权限正确" if expect_present else
         "停用或清理后文件不存在，命令应返回No such file or directory"),
        **kwargs,
    )
    if expect_present:
        _add_router(
            bv,
            out,
            "查看SNMP生成配置（认证相关行已整行遮蔽）",
            _snmp_sanitized_config_command(),
            "监听、系统信息长度、来源和版本映射正确；所有认证行只显示[hidden]",
            **kwargs,
        )


def _snmp_add_processes(
    bv,
    out,
    actual: str,
    *,
    expect_running: bool = True,
    valid_when: str = None,
):
    kwargs = {"actual": actual}
    if valid_when:
        kwargs["valid_when"] = valid_when
    expected_pid = (
        "启用时返回一个或多个PID；停用时无输出"
        if expect_running else "停用时无输出"
    )
    _add_router(bv, out, "查看snmpd PID", "pidof snmpd", expected_pid, **kwargs)
    _add_router(
        bv, out, "查看snmpd命令行", "ps w 2>/dev/null | grep '[s]nmpd'",
        ("启用时仅有预期snmpd实例且命令行引用生成配置" if expect_running else
         "停用时无输出"),
        **kwargs,
    )
    _add_router(
        bv, out, "查看SNMP子代理PID", "pidof ik_snmp_subagent", expected_pid,
        **kwargs,
    )
    _add_router(
        bv, out, "查看SNMP子代理命令行",
        "ps w 2>/dev/null | grep '[i]k_snmp_subagent'",
        ("启用时仅有预期ik_snmp_subagent实例" if expect_running else
         "停用时无输出"),
        **kwargs,
    )
    _add_router(
        bv, out, "查看SNMP PID文件元数据",
        "stat -c '%a %U:%G %s %n' /var/run/snmp/snmpd.pid /var/run/snmp/subsnmpd.pid",
        ("启用时两个PID文件存在且非空" if expect_running else
         "停用时文件不存在或不再指向运行进程"),
        **kwargs,
    )


def _snmp_add_listener(
    bv,
    out,
    port: int,
    actual: str,
    *,
    expect_listening: bool = True,
    valid_when: str = None,
):
    kwargs = {"actual": actual}
    if valid_when:
        kwargs["valid_when"] = valid_when
    port = int(port)
    _add_router(
        bv,
        out,
        f"查看UDP/{port}的IPv4监听",
        f"netstat -lnup 2>/dev/null | grep -E {_double_quote('^udp[[:space:]].*:' + str(port) + '[[:space:]]')}",
        ("启用时显示IPv4目标端口且PID归属snmpd" if expect_listening else
         "停用、改端口或删除后无输出"),
        **kwargs,
    )
    port_hex = f"{port:04X}"
    _add_router(
        bv,
        out,
        f"查看UDP/{port}的IPv6监听（BusyBox netstat不展示udp6）",
        f"grep -i ':{port_hex} ' /proc/net/udp6",
        (f"启用时显示本地端口十六进制{port_hex}" if expect_listening else
         "停用、改端口或删除后无输出"),
        **kwargs,
    )


def _snmp_add_firewall(
    bv,
    out,
    port: int,
    actual: str,
    *,
    expect_excluded: bool = True,
    valid_when: str = None,
):
    kwargs = {"actual": actual}
    if valid_when:
        kwargs["valid_when"] = valid_when
    port = int(port)
    deny_line = f"deny {port} 0.0.0.0/0 0-65535"
    _add_sql(
        bv,
        out,
        "查看UPnP服务开关（判定SNMP deny项是否适用）",
        "SELECT enabled FROM upnpd_conf ORDER BY id LIMIT 1",
        "enabled=yes时继续校验deny；enabled=no时deny项不适用且应无输出",
        **kwargs,
    )
    _add_router(
        bv,
        out,
        f"查看UDP/{port}的UPnP端口映射排除项",
        f"grep -nF {_double_quote(deny_line)} {SNMP_MINIUPNPD_CONFIG_PATH}",
        (f"UPnP开启且SNMP启用时精确显示{deny_line}；UPnP关闭时无输出且该项不适用"
         if expect_excluded else
         "SNMP停用或改端口后无输出；UPnP关闭时无输出且该项不适用"),
        **kwargs,
    )
    _add_router(
        bv, out, "确认SNMP无专用iptables规则（不适用项证据）",
        "iptables-save 2>/dev/null | grep -i snmp",
        "无输出；实机链路不使用专用iptables规则，因此该项不适用",
        **kwargs,
    )
    _add_router(
        bv, out, "确认SNMP无专用ipset（不适用项证据）",
        "ipset list -n 2>/dev/null | grep -i snmp",
        "无输出；实机链路不使用专用ipset，因此该项不适用",
        **kwargs,
    )


def _snmp_common_runtime(bv, out, params: Dict[str, Any], result: Any = None):
    actual = _snmp_result_actual(result, params)
    port = _snmp_port_from(params, result)
    expected_fields = params.get("expected_fields")
    enabled = None
    if isinstance(expected_fields, dict) and "enabled" in expected_fields:
        enabled = str(expected_fields.get("enabled")).strip().lower() in {
            "1", "yes", "true", "on", "enable", "enabled",
        }
    if enabled is None and result is not None:
        details = getattr(result, "details", {}) or {}
        if isinstance(details, dict) and "enabled" in details:
            enabled = bool(details.get("enabled"))
    expect_running = True if enabled is None else enabled
    _snmp_add_database(bv, out, actual)
    _snmp_add_generated_config(
        bv, out, actual, expect_present=expect_running
    )
    _snmp_add_processes(bv, out, actual, expect_running=expect_running)
    _snmp_add_listener(
        bv, out, port, actual, expect_listening=expect_running
    )
    _snmp_add_firewall(
        bv, out, port, actual, expect_excluded=expect_running
    )


def _snmp_probe_mode(params: Dict[str, Any]) -> str:
    version = str(params.get("version") or "v2c").strip().lower().replace("-", "")
    if version in {"2", "2c", "v2", "v2c", "snmpv2", "snmpv2c"}:
        return "v2c"
    if version in {"3", "v3", "snmpv3"}:
        security = str(params.get("security") or "authNoPriv").strip().lower()
        return "v3-priv" if "priv" in security and "nopriv" not in security else "v3-auth"
    raise ValueError(f"人工SNMP复验不支持协议版本: {version}")


def _snmp_probe_command(params: Dict[str, Any]) -> str:
    mode = _snmp_probe_mode(params)
    operation = str(params.get("operation") or "get").strip().lower()
    if operation not in {"get", "walk"}:
        raise ValueError(f"人工SNMP复验不支持操作: {operation}")
    host = str(params.get("host") or "")
    oid = str(params.get("oid") or "")
    if not host or not oid:
        raise ValueError("人工SNMP复验必须提供host和oid")
    parts = [
        "sudo", "-n", SNMP_VERIFY_ENTRY,
        "--mode", mode,
        "--operation", operation,
        "--host", _double_quote(host),
        "--oid", _double_quote(oid),
    ]
    if mode != "v2c":
        auth_proto = str(params.get("auth_proto") or "SHA").strip().upper()
        if auth_proto not in {"MD5", "SHA"}:
            raise ValueError(f"人工SNMP复验不支持认证算法: {auth_proto}")
        parts.extend(("--auth-proto", auth_proto))
    if mode == "v3-priv":
        priv_proto = str(params.get("priv_proto") or "AES").strip().upper()
        if priv_proto not in {"DES", "AES"}:
            raise ValueError(f"人工SNMP复验不支持隐私算法: {priv_proto}")
        parts.extend(("--priv-proto", priv_proto))
    return " ".join(parts)


_BASIC_SAFE_DB_FIELDS = (
    "id,language,time_zone,time_zone_full,switch_nat,switch_dpi,switch_ntp,"
    "switch_ntpd,switch_ntpserver,ntp_sync_cycle,link_mode,fast_nat,lan_nat,"
    "listenport,backport,"
    "length(COALESCE(hostname,'')) AS hostname_len,"
    "CASE WHEN length(COALESCE(ntpserver_list,''))>0 "
    "THEN 'configured' ELSE 'empty' END AS ntpserver_state"
)


def _basic_private_values(params: Optional[Dict[str, Any]]) -> List[str]:
    """Return private singleton values that must never enter report metadata."""
    values: List[str] = []
    params = params or {}
    expected = params.get("expected_fields")
    if isinstance(expected, dict):
        for key in ("hostname", "ntpserver_list"):
            if expected.get(key) not in (None, ""):
                values.append(str(expected[key]))
    snapshot = params.get("snapshot")
    if isinstance(snapshot, dict):
        row = snapshot.get("row")
        if isinstance(row, dict):
            for key in ("hostname", "ntpserver_list"):
                if row.get(key) not in (None, ""):
                    values.append(str(row[key]))
    return sorted(set(values), key=len, reverse=True)


def _basic_result_actual(
    result: Any, params: Optional[Dict[str, Any]] = None
) -> str:
    """Render a compact basic-setting result without private field values."""
    if result is None:
        return "自动化执行时记录；人工复验后请对照终端输出"
    message = " ".join(
        str(getattr(result, "message", "") or "").strip().split()
    )
    message = _SENSITIVE_RESULT_JSON.sub(
        lambda match: f'{match.group(1)}"[已隐藏]"', message
    )
    message = _SENSITIVE_RESULT_ASSIGNMENT.sub(r"\1=[已隐藏]", message)
    # Page objects and config fixtures register runtime-only private values at
    # capture time.  Reuse the same report-boundary sanitizer without ever
    # serializing the registry itself.
    from utils.step_recorder import redact_sensitive_text
    message = redact_sensitive_text(message)
    for private_value in _basic_private_values(params):
        message = message.replace(private_value, "[已隐藏]")
    if len(message) > 240:
        message = message[:237] + "..."
    passed = getattr(result, "passed", None)
    status = "通过" if passed is True else ("失败" if passed is False else "已执行")
    return f"{status}：{message}" if message else status


def _basic_expected(params: Dict[str, Any], key: str, default: Any = None):
    expected = params.get("expected_fields")
    if isinstance(expected, dict) and key in expected:
        return expected.get(key)
    snapshot = params.get("snapshot")
    if isinstance(snapshot, dict):
        row = snapshot.get("row")
        if isinstance(row, dict) and key in row:
            return row.get(key)
    return params.get(key, default)


def _basic_server_ip(bv, params: Dict[str, Any]) -> str:
    value = params.get("server_ip")
    snapshot = params.get("snapshot")
    if not value and isinstance(snapshot, dict):
        client = snapshot.get("client")
        if isinstance(client, dict):
            value = client.get("server_ip")
    if not value:
        try:
            value = bv._ssh_config.iperf3_server
        except Exception:
            value = "10.66.0.40"
    return str(ipaddress.ip_address(str(value)))


def _basic_add_database(bv, out, actual: str, *, valid_when: str = None):
    _add_sql(
        bv,
        out,
        "查看基础设置单例字段（主机名与NTP地址仅显示长度/状态）",
        f"SELECT {_BASIC_SAFE_DB_FIELDS} FROM basic WHERE id=1",
        "只返回id=1一行；模式、开关和周期与页面一致，私有文本不输出",
        actual=actual,
        **({"valid_when": valid_when} if valid_when else {}),
    )


def _basic_add_generated_state(
    bv, out, actual: str, *, valid_when: str = None
):
    extra = {"valid_when": valid_when} if valid_when else {}
    _add_router(
        bv,
        out,
        "查看基础设置缓存（私有文本已遮蔽）",
        "sed -E 's/(hostname|ntpserver_list)=[^ ]*/\\1=[hidden]/g' "
        + BASIC_CACHE_PATH,
        "缓存字段与basic.id=1一致；hostname和ntpserver_list不显示原值",
        actual=actual,
        **extra,
    )
    _add_router(
        bv, out, "查看系统时区文件", "cat /etc/TZ",
        "时区偏移与页面选择一致", actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看localtime链接", "readlink /tmp/localtime",
        "按basic.sh实机实现固定返回/usr/share/zoneinfo/GMT-8；页面偏移由/etc/TZ承载",
        actual=actual, **extra,
    )
    _add_router(
        bv, out, "核对主机名映射长度（不输出主机名）",
        "wc -c /etc/hosts.d/hostname",
        "文件存在且长度与本步骤记录的主机名长度相符", actual=actual, **extra,
    )


def _basic_add_nat_state(bv, out, actual: str, *, valid_when: str = None):
    extra = {"valid_when": valid_when} if valid_when else {}
    for chain, table, expected in (
        ("AUTONAT", "nat", "NAT1/NAT4显示MASQUERADE；路由模式按lan_nat显示SNAT或无规则"),
        ("PRE_FULLCONE", "nat", "仅NAT1显示一条FULLCONENAT规则"),
        ("POST_FULLCONE", "nat", "仅NAT1显示一条FULLCONENAT规则"),
        ("NONAT", "filter", "路由模式显示TCP/UDP两条REJECT；NAT模式无规则"),
    ):
        table_arg = "" if table == "filter" else f"-t {table} "
        _add_router(
            bv, out, f"查看{chain}链",
            f"iptables -w {table_arg}-S {chain} 2>/dev/null",
            expected, actual=actual, **extra,
        )


def _basic_add_link_state(bv, out, actual: str, *, valid_when: str = None):
    extra = {"valid_when": valid_when} if valid_when else {}
    _add_router(
        bv, out, "查看AC进程链路参数",
        "ps -w 2>/dev/null | grep -E '[ ]AC( |$)' | grep -v grep",
        "旁路模式在AC启用时带-b；主干/SD-WAN不带-b", actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看内核链路模式摘要",
        "grep -iE '^Bypass:|^bypass mode:' /proc/ikuai/stats/ik_summary",
        "bypass mode与主干、旁路或SD-WAN选择一致", actual=actual, **extra,
    )
    _add_sql(
        bv, out, "查看AC全局开关",
        "SELECT id,ac_server FROM global_config WHERE id=1",
        "用于解释AC进程是否应存在，不修改全局配置", actual=actual, **extra,
    )


def _basic_add_acceleration_state(
    bv, out, actual: str, *, valid_when: str = None
):
    extra = {"valid_when": valid_when} if valid_when else {}
    _add_router(
        bv, out, "查看软件/硬件加速脚本分支",
        "sed -n '/^__set_fast_nat()/,/^__not_nat()/p' "
        "/usr/ikuai/script/basic.sh",
        "显示先清空FASTOFFLOAD；fast_nat=1追加软件FLOWOFFLOAD，fast_nat=2追加--hw",
        actual=actual, **extra,
    )
    _add_router(
        bv, out, "确认FLOWOFFLOAD内核目标是否存在",
        "grep -w FLOWOFFLOAD /proc/net/ip_tables_targets",
        "支持软件加速时应输出FLOWOFFLOAD；无输出说明当前固件内核目标未加载",
        actual=actual, **extra,
    )
    _add_router(
        bv, out, "确认加速规则依赖匹配器",
        "grep -E '^(connbytes|ifaces)$' /proc/net/ip_tables_matches",
        "分别输出connbytes和ifaces；缺项会阻止脚本规则完整下发",
        actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看FASTOFFLOAD规则",
        "iptables -w -t mangle -S FASTOFFLOAD 2>/dev/null",
        "关闭时无FLOWOFFLOAD；软件加速无--hw；硬件加速带--hw",
        actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看FASTOFFLOAD包计数",
        "iptables -w -t mangle -L FASTOFFLOAD -n -v -x 2>/dev/null",
        "真实打流后FLOWOFFLOAD规则包计数增加", actual=actual, **extra,
    )


def _basic_add_ntp_state(bv, out, actual: str, *, valid_when: str = None):
    extra = {"valid_when": valid_when} if valid_when else {}
    _add_router(
        bv, out, "查看自动对时调度进程",
        "ps -w 2>/dev/null | grep '[i]ktimerd'",
        "自动对时开启时显示iktimerd", actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看NTP服务进程", "pidof ntpd",
        "NTP服务开启时返回PID；关闭时无输出", actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看UDP/123监听",
        "netstat -lnup 2>/dev/null | grep -E ':123[[:space:]]'",
        "NTP服务开启时显示ntpd监听；关闭时无输出", actual=actual, **extra,
    )


def _basic_add_compact_runtime(
    bv, out, actual: str, *, valid_when: str = None
):
    """Small L1-L4 audit set used by aggregate/recovery verifiers."""
    extra = {"valid_when": valid_when} if valid_when else {}
    _basic_add_database(bv, out, actual, valid_when=valid_when)
    _add_router(
        bv, out, "查看基础设置缓存字段名与非私有值",
        "sed -E 's/(hostname|ntpserver_list)=[^ ]*/\\1=[hidden]/g' "
        + BASIC_CACHE_PATH,
        "缓存、时区和模式字段与basic.id=1一致，私有文本已遮蔽",
        actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看基础设置相关iptables规则",
        "iptables-save 2>/dev/null | grep -E 'AUTONAT|FULLCONE|NONAT|FASTOFFLOAD'",
        "只出现当前上网与加速模式所需规则，无旧模式重复项",
        actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看基础设置相关进程",
        "ps -w 2>/dev/null | grep -E '[ ](AC|lldpd|ntpd|iktimerd)( |$)' | grep -v grep",
        "进程数量和命令行与链路、NTP设置一致", actual=actual, **extra,
    )
    _add_router(
        bv, out, "查看基础设置内核摘要",
        "grep -iE '^WansNAT:|^Bypass:|^bypass mode:' /proc/ikuai/stats/ik_summary",
        "NAT和链路摘要与页面模式一致", actual=actual, **extra,
    )


def _basic_add_client_route(
    bv,
    out,
    params: Dict[str, Any],
    actual: str,
    *,
    valid_when: str = None,
):
    server = _basic_server_ip(bv, params)
    iface = str(params.get("expected_iface") or params.get("iface") or "ens11")
    source = str(params.get("expected_source") or params.get("source_ip") or "192.168.148.2")
    gateway = str(params.get("expected_gateway") or params.get("gateway") or "192.168.148.1")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface):
        raise ValueError("人工基础设置路由复验接口格式不安全")
    source = str(ipaddress.ip_address(source))
    gateway = str(ipaddress.ip_address(gateway))
    _add_client(
        bv, out, f"确认L5目标{server}经被测路由器转发",
        f"ip route get {server}",
        f"输出包含via {gateway}、dev {iface}和src {source}，不得走客户端管理网",
        actual=actual,
        **({"valid_when": valid_when} if valid_when else {}),
    )


def _basic_add_management_health(bv, out, actual: str):
    router_host = str(ipaddress.ip_address(_host_for(bv, "router")))
    _add_router(
        bv, out, "确认路由器SSH命令通道可用",
        "printf basic-router-ssh-ok",
        "输出basic-router-ssh-ok", actual=actual,
        valid_when="finally恢复完成后",
    )
    _add_client(
        bv, out, "确认测试客户端SSH命令通道可用",
        "printf basic-client-ssh-ok",
        "输出basic-client-ssh-ok", actual=actual,
        valid_when="finally恢复完成后",
    )
    _add_client(
        bv, out, "确认路由器管理Web可达",
        "curl --silent --show-error --output /dev/null --write-out '%{http_code}' "
        f"--connect-timeout 3 --max-time 5 http://{router_host}/",
        "返回200至499之间的HTTP状态码", actual=actual,
        valid_when="finally恢复完成后",
    )


def _basic_add_recovery_fingerprint(bv, out, actual: str):
    valid_when = "finally恢复完成后，与测试前只读指纹对比"
    checks = (
        (
            "router", "查看主路由表指纹", "ip -4 route show table main",
            "排序后应与测试前主路由表一致",
        ),
        (
            "router", "查看策略路由规则指纹", "ip -4 rule show",
            "排序后应与测试前策略规则一致",
        ),
        (
            "router", "查看路由器当前纪元秒", "date +%s",
            "与客户端纪元秒差值应保持在允许偏差内",
        ),
        (
            "client", "查看客户端当前纪元秒", "date +%s",
            "作为路由器时钟恢复的独立参考",
        ),
        (
            "router", "查看路由器本地RTC时间", "hwclock -r 2>/dev/null",
            "RTC可读取，且与同一时刻系统时间/客户端epoch的相对偏差与测试前一致",
        ),
        (
            "router", "查看维护账号文件哈希", "sha256sum /etc/passwd",
            "SHA256与测试前一致",
        ),
        (
            "router", "查看维护计划任务哈希",
            "crontab -l 2>/dev/null | sha256sum",
            "SHA256与测试前一致",
        ),
        (
            "router", "查看内核模块名称哈希",
            "awk '{print $1}' /proc/modules 2>/dev/null | sort | sha256sum",
            "SHA256与测试前一致",
        ),
        (
            "router", "查看ipset名称集合哈希",
            "ipset list -n 2>/dev/null | sort | sha256sum",
            "SHA256与测试前一致",
        ),
    )
    for target, purpose, command, expected in checks:
        add = _add_router if target == "router" else _add_client
        add(
            bv, out, purpose, command, expected,
            actual=actual, valid_when=valid_when,
        )


def _basic_add_client_artifact_audit(
    bv, out, actual: str, *, valid_when: str = "测试结束后仍有效"
):
    _add_client(
        bv, out, "确认基础设置客户端临时文件已清理",
        "find /tmp -maxdepth 1 -type f -name 'ikuai-basic-*' -print",
        "无输出", actual=actual, valid_when=valid_when,
    )
    _add_client(
        bv, out, "确认基础设置客户端临时进程已清理",
        "pgrep -af 'python3 /tmp/[i]kuai-basic-'",
        "无输出", actual=actual, valid_when=valid_when,
    )


def _basic_add_iperf(
    bv,
    out,
    params: Dict[str, Any],
    actual: str,
    *,
    purpose: str = "执行经路由器的iperf3真实打流",
):
    server = _basic_server_ip(bv, params)
    duration = max(1, min(int(params.get("duration") or 4), 30))
    expect_success = bool(params.get("expect_success", True))
    _basic_add_client_route(bv, out, params, actual)
    _add_client(
        bv, out, purpose,
        f"iperf3 --bind 192.168.148.2 --client {server} --time {duration} --json",
        (
            "exit=0且JSON包含有效吞吐，路由证明流量经ens11进入被测路由器"
            if expect_success else
            "命令连接失败或无有效吞吐，符合当前负向场景"
        ),
        actual=actual,
        effect=f"向既有iperf3服务端发送约{duration}秒测试流量",
    )


def build_verification_commands(
    bv,
    verify_func,
    args=(),
    kwargs=None,
    result=None,
) -> Optional[List[Dict[str, Any]]]:
    """Return structured manual commands for migrated safe-report verifiers.

    ``None`` means this verifier is not migrated.  A list means the call is
    migrated and raw internal SSH commands must stay hidden.  This includes
    device-setting/basic as well as FTP/Samba/HTTP/SNMP local services.
    """
    kwargs = dict(kwargs or {})
    name = getattr(verify_func, "__name__", "")
    module = getattr(verify_func, "__module__", "")

    # IOC 威胁情报验证器自带固定的、脱敏的人工复验命令。必须在通用
    # 分支前截获，避免回退展示 SSHClient 内部脚本（其中可能包含原始
    # IOC、运行时变量或清理动作）。
    if module.endswith("ioc_verifier"):
        owner = getattr(verify_func, "__self__", None)
        builder = getattr(owner, "build_verification_commands", None)
        if callable(builder) and name != "build_verification_commands":
            if name.startswith(("get_", "restore_", "cleanup_", "prepare_")):
                return []
            try:
                return builder(result)
            except TypeError:
                return builder()
        return []
    # QEMU 验证器把与具体 VM/端口/磁盘绑定的只读复验命令附在结果中。
    # 一律使用其构造器，禁止回退展示下载、清理或带 VNC 口令的内部命令。
    if module.endswith("qemu_verifier"):
        owner = getattr(verify_func, "__self__", None)
        builder = getattr(owner, "build_verification_commands", None)
        if callable(builder):
            return builder(result)
        return []
    # ``netsnmpc`` is the separate cross-layer SNMP client module.  It must
    # retain its legacy command path; only the local ``snmp_*`` verifiers use
    # the credential-safe net-snmp helper below.
    if not (
        _is_basic_setting_verifier_name(name) or
        module.endswith("ipsec_verifier") or
        module.endswith("ospf_verifier") or
        "ospf" in name or
        name.startswith("verify_vlan_") or
        "alg" in name.lower() or "protocol_control" in name.lower() or
        name.startswith((
            "get_kernel_", "verify_kernel_", "run_kernel_",
            "restore_kernel_", "cleanup_kernel_", "choose_kernel_",
        )) or
        "ftp" in name or "samba" in name or "http" in name or
        ("snmp" in name and "netsnmpc" not in name)
    ):
        return None
    params = _bound_arguments(verify_func, args, kwargs)
    out: List[Dict[str, Any]] = []

    # Mutating restoration/cleanup helpers are intentionally never offered as
    # copy-ready commands.  Their separate read-only audit calls carry commands.
    if name.startswith(("get_", "restore_", "cleanup_", "prepare_")):
        return []
    if name in {"repair_alg_nat_runtime", "repair_protocol_control_nat_runtime"}:
        return []

    if module.endswith("ipsec_verifier"):
        actual = _basic_result_actual(result, params)
        internal_only = {
            "initialize_runtime", "reload_current_credentials",
            "initiate_child_from_peer", "initiate_child_from_router",
            "rekey_child_from_peer", "terminate_test_sas", "policy_action",
            "add_policy", "edit_policy", "add_proposal", "edit_proposal",
        }
        if name in internal_only:
            return []

        if name == "verify_schema":
            for table in ("ipsec2_policy", "ipsec2_proposal"):
                _add_router(
                    bv, out, f"查看{table}表结构",
                    f"sqlite3 {DB_PATH} {_double_quote('.schema ' + table)}",
                    "显示字段、默认值、索引和约束", actual=actual,
                )
        elif name == "verify_script_contract":
            _add_router(
                bv, out, "核对IPsec底层脚本校验值",
                "sha256sum /usr/ikuai/script/ipsec2_policy.sh /usr/ikuai/script/ipsec2_proposal.sh /usr/ikuai/script/ipsec2_tunnel.sh /usr/ikuai/include/ipsec2_common.sh",
                "显示四个实际生效脚本的SHA256", actual=actual,
            )
            _add_router(
                bv, out, "查看IPsec脚本的新增、启停和加载入口",
                "grep -nE '(__check_param_add|__exec_swanctl_up|__exec_swanctl_down|__exec_create_conf|swanctl[[:space:]]+--load-all)' /usr/ikuai/script/ipsec2_policy.sh /usr/ikuai/include/ipsec2_common.sh",
                "显示参数校验、配置生成、启停和加载调用位置", actual=actual,
            )
        elif name == "management_health":
            _add_router(
                bv, out, "确认主路由管理服务正在监听",
                "ss -lnt | grep -E ':(22|80|443)[[:space:]]'",
                "显示SSH或Web管理端口监听", actual=actual,
            )
            _add_client(
                bv, out, "确认客户端可以到达主路由业务接口",
                "ping -I ens11 -c 2 -W 1 192.168.148.1",
                "2个报文全部收到响应", actual=actual,
                effect="发送2个健康检查报文",
            )
        elif name in {"runtime_health", "verify_policy_runtime_loaded"}:
            target = str(params.get("target") or "router")
            if target != "router":
                return []
            _add_router(
                bv, out, "查看IPsec连接服务是否运行",
                "pidof charon",
                "输出一个正在运行的进程号", actual=actual,
            )
            _add_router(
                bv, out, "查看IPsec连接服务状态",
                "swanctl --stats",
                "命令成功并显示运行统计", actual=actual,
            )
            _add_router(
                bv, out, "查看后台已加载的IPsec连接",
                "swanctl --list-conns",
                "显示本步骤新增的连接名称", actual=actual,
            )
            policy_id = params.get("policy_id")
            if policy_id is not None:
                policy_id = int(policy_id)
                _add_router(
                    bv, out, "确认目标连接配置文件已生成",
                    f"ls -l /etc/swanctl/conf.d/ipsec2-{policy_id}.conf",
                    "文件存在且属主、权限符合预期", actual=actual,
                )
        elif name == "verify_database":
            if str(params.get("target") or "router") != "router":
                return []
            tagname = str(params.get("tagname") or "")
            expected = "无记录" if params.get("absent") else "记录存在且非敏感字段与页面一致"
            sql = (
                "SELECT id,enabled,tagname,alias,role,interface,local_ip,"
                "remote_addr,ike_version,auth_method,security_proto,esp_enc,"
                "esp_auth,pfs_group,ipsec_sa_time,dpd_enabled,trigger_mode,"
                "CASE WHEN length(COALESCE(secret,''))>0 THEN 'configured' "
                "ELSE 'empty' END AS secret_state FROM ipsec2_policy WHERE tagname IS "
                + _sql_literal(tagname)
            )
            _add_sql(
                bv, out, "查看目标IPsec策略的数据库记录（认证值不输出）",
                sql, expected, actual=actual,
            )
        elif name == "verify_secret_permissions":
            if str(params.get("target") or "router") != "router":
                return []
            policy_id = int(params.get("policy_id") or 0)
            _add_router(
                bv, out, "查看认证配置文件权限（不读取内容）",
                f"stat -c '%a %U %G %n' /etc/swanctl/secrets.d/ipsec2-{policy_id}.conf",
                "权限为600或400，仅管理员可读", actual=actual,
            )
            _add_router(
                bv, out, "查看IPsec运行缓存权限（不读取内容）",
                f"stat -c '%a %U %G %n' /tmp/iktmp/cache/ipsec2/{policy_id}",
                "权限为600或400，仅管理员可读", actual=actual,
            )
        elif name in {"wait_for_sa", "wait_for_sa_absent", "wait_for_child_absent"}:
            expected = (
                "本次连接不存在且无对应内核加密状态"
                if name != "wait_for_sa" else
                "本次连接已建立，且内核加密状态和策略均存在"
            )
            _add_router(
                bv, out, "查看当前IPsec连接状态",
                "swanctl --list-sas", expected, actual=actual,
            )
            _add_router(
                bv, out, "查看内核加密状态",
                "ip -s xfrm state", expected, actual=actual,
            )
            _add_router(
                bv, out, "查看内核加密策略",
                "ip -s xfrm policy", expected, actual=actual,
            )
        elif name in {
            "verify_control_failure", "verify_traffic_blocked",
            "verify_bidirectional_traffic",
        }:
            topology = params.get("topology")
            if topology is None:
                return []
            router_service = str(
                getattr(topology, "router_service", "")
                or getattr(topology, "client_source", "")
            )
            peer_service = str(getattr(topology, "peer_service", ""))
            try:
                ipaddress.ip_address(router_service)
                ipaddress.ip_address(peer_service)
            except ValueError:
                return []
            expect_success = name == "verify_bidirectional_traffic"
            _add_router(
                bv, out, "查看主路由测试地址到对端测试地址的选路",
                f"ip route get {peer_service} from {router_service}",
                "显示本次独立loopback业务流量的选路", actual=actual,
            )
            _add_router(
                bv, out, "从主路由loopback发送实际测试流量",
                f"ping -I {router_service} -c 4 -W 2 {peer_service}",
                "4个报文全部成功" if expect_success else "报文无法到达，符合负向场景",
                actual=actual, effect="发送4个测试报文",
            )
            _add_router(
                bv, out, "查看主路由内核加密报文计数",
                "ip -s xfrm state",
                "正向场景报文计数增长；负向场景无本次有效加密状态",
                actual=actual,
            )
        elif name == "exact_residual_audit":
            _add_router(
                bv, out, "确认测试连接已经清理",
                "swanctl --list-sas",
                "不显示本次测试连接", actual=actual,
                valid_when="finally清理完成后",
            )
            _add_router(
                bv, out, "确认内核加密状态已经清理",
                "ip -s xfrm state",
                "不显示本次测试地址或连接", actual=actual,
                valid_when="finally清理完成后",
            )
            _add_client(
                bv, out, "查看客户端是否还有临时测试路由",
                "ip -4 route show",
                "不显示本次动态测试目标的精确路由", actual=actual,
                valid_when="finally清理完成后",
            )
        elif name == "verify_restored":
            _add_router(
                bv, out, "查看主路由最终路由表",
                "ip -4 route show table main",
                "与测试前只读快照一致", actual=actual,
                valid_when="finally恢复完成后",
            )
            _add_router(
                bv, out, "查看主路由最终策略路由规则",
                "ip -4 rule show",
                "与测试前只读快照一致", actual=actual,
                valid_when="finally恢复完成后",
            )
            _add_client(
                bv, out, "查看客户端最终路由表",
                "ip -4 route show",
                "与测试前只读快照一致", actual=actual,
                valid_when="finally恢复完成后",
            )
        return _deduplicate(out)

    if module.endswith("ospf_verifier") or "ospf" in name or name in {
        "script_contract", "wait_neighbor", "wait_route", "ping_from_router",
        "management_health", "snapshot_environment", "probe_tagged_peer_transit",
        "remove_created_interface_cache",
    }:
        actual = _basic_result_actual(result, params)
        if name == "verify_schema":
            for table in (
                "ospf_instance", "ospf_area", "ospf_interface",
                "ospf_interface_attr", "ospf_redistribute",
            ):
                _add_router(
                    bv, out, f"查看{table}表结构",
                    f"sqlite3 {DB_PATH} {_double_quote('.schema ' + table)}",
                    "显示字段类型、默认值、唯一约束和关联键",
                    actual=actual,
                )
        elif name == "script_contract":
            _add_router(
                bv, out, "核对OSPF脚本校验值",
                "sha256sum /usr/ikuai/script/ospf.sh",
                "SHA256与报告记录一致", actual=actual,
            )
            _add_router(
                bv, out, "查看OSPF脚本真实动作入口",
                "grep -nE '^(add|edit|del|up|down|init|reload|start|stop)[(]' /usr/ikuai/script/ospf.sh",
                "输出脚本实际存在的动作入口", actual=actual,
            )
        elif name == "verify_config_update_safety":
            _add_router(
                bv, out, "检查FRR配置覆盖及语法检查路径",
                "grep -nE '(/tmp/ospf[.]frr|/etc/frr/frr[.]conf|c[p] .*frr[.]conf|m[v] .*frr[.]conf|vtysh.*-C|frr-reload)' /usr/ikuai/script/ospf.sh",
                "应同时证明覆盖前语法检查和原子替换；缺失即与报告失败一致",
                actual=actual,
            )
        elif name == "verify_instance":
            process_id = int(params.get("process_id") or 0)
            family = "ipv6" if params.get("address_family") == "ipv6" else "ipv4"
            _add_sql(
                bv, out, "查看目标OSPF实例DB字段",
                "SELECT id,enabled,address_family,process_id,router_id,distance,"
                "default_info,emit_style,comment FROM ospf_instance WHERE "
                f"address_family IS '{family}' AND process_id IS {process_id}",
                "记录存在性和非敏感字段与步骤期望一致", actual=actual,
            )
        elif name == "verify_area_interface":
            process_id = int(params.get("process_id") or 0)
            family = "ipv6" if params.get("address_family") == "ipv6" else "ipv4"
            area_id = str(params.get("area_id") or "0.0.0.0").replace("'", "''")
            ifname = _safe_probe_component(params.get("ifname"), "lan1")
            _add_sql(
                bv, out, "查看OSPF区域关联（认证值不输出）",
                "SELECT id,address_family,process_id,area_id,area_type,"
                "CASE WHEN authentication IS 'none' THEN 'none' ELSE 'configured' END AS auth_state "
                f"FROM ospf_area WHERE address_family IS '{family}' AND process_id IS {process_id} "
                f"AND area_id IS '{area_id}'",
                "区域唯一存在且关联目标实例", actual=actual,
            )
            _add_sql(
                bv, out, "查看OSPF接口属性（密钥值不输出）",
                "SELECT id,enabled,ifname,address_family,process_id,area_id,cost,"
                "hello_interval,dead_interval,priority,network_type,auth_type,"
                "CASE WHEN length(COALESCE(auth_key,''))+length(COALESCE(md5_key,''))+"
                "length(COALESCE(ipsec_key,''))>0 THEN 'configured' ELSE 'empty' END AS key_state "
                f"FROM ospf_interface_attr WHERE address_family IS '{family}' "
                f"AND process_id IS {process_id} AND ifname IS '{ifname}'",
                "接口、区域、timer、cost、priority和网络类型与页面一致", actual=actual,
            )
        elif name == "verify_generated_config":
            _add_router(
                bv, out, "比较生成配置和daemon活动配置校验值",
                "sha256sum /tmp/ospf.frr /etc/frr/frr.conf",
                "启用期间两个文件校验值一致", actual=actual,
            )
            _add_router(
                bv, out, "查看daemon已加载的OSPF非敏感配置",
                "vtysh -c 'show running-config' | grep -E '^(router ospf| ospf router-id|interface | ip ospf| ipv6 ospf6)'",
                "显示实例、Router ID、接口和区域；不输出认证行", actual=actual,
            )
        elif name == "wait_neighbor":
            role = str(params.get("role") or "router")
            family = str(params.get("address_family") or "ipv4")
            command = "show ipv6 ospf6 neighbor" if family == "ipv6" else "show ip ospf neighbor"
            if role == "client":
                _add_client(
                    bv, out, "查看客户端OSPF邻居状态",
                    f"sudo -n vtysh -c {_double_quote(command)}",
                    "需要交换LSDB时邻居状态为Full", actual=actual,
                )
            else:
                _add_router(
                    bv, out, "查看主路由OSPF邻居状态",
                    f"vtysh -c {_double_quote(command)}",
                    "需要交换LSDB时邻居状态为Full", actual=actual,
                )
        elif name == "wait_route":
            role = str(params.get("role") or "router")
            prefix = str(params.get("prefix") or "").replace("'", "")
            ipv6 = bool(params.get("ipv6"))
            command = f"show {'ipv6' if ipv6 else 'ip'} route {prefix}"
            if role == "client":
                _add_client(
                    bv, out, "查看客户端OSPF RIB",
                    f"sudo -n vtysh -c {_double_quote(command)}",
                    "路由存在或撤销状态与步骤期望一致", actual=actual,
                )
                _add_client(
                    bv, out, "查看客户端内核FIB",
                    f"ip {'-6 ' if ipv6 else ''}route show {prefix}",
                    "FIB存在或撤销状态与步骤期望一致", actual=actual,
                )
            else:
                _add_router(
                    bv, out, "查看主路由OSPF RIB",
                    f"vtysh -c {_double_quote(command)}",
                    "路由存在或撤销状态与步骤期望一致", actual=actual,
                )
                _add_router(
                    bv, out, "查看主路由内核FIB",
                    f"ip {'-6 ' if ipv6 else ''}route show {prefix}",
                    "FIB存在或撤销状态与步骤期望一致", actual=actual,
                )
        elif name == "verify_lsdb":
            family = str(params.get("address_family") or "ipv4")
            process_id = params.get("process_id")
            command = (
                "show ipv6 ospf6 database" if family == "ipv6"
                else f"show ip ospf {int(process_id)} database"
                if process_id is not None else "show ip ospf database"
            )
            _add_router(
                bv, out, "查看主路由OSPF LSDB",
                f"vtysh -c {_double_quote(command)}",
                "包含报告列出的本端和对端Router ID及实际存在的LSA类型", actual=actual,
            )
        elif name == "verify_protocol_89":
            ifname = _safe_probe_component(params.get("ifname"), "lan1")
            _add_router(
                bv, out, "捕获单个OSPF协议89报文",
                f"tcpdump -n -i {ifname} -c 1 'ip proto 89'",
                "活动邻接期间捕获到一个OSPF报文", actual=actual,
                effect="只读监听并在捕获1个协议报文后退出",
            )
        elif name == "ping_from_router":
            target = str(params.get("target") or "").replace("'", "")
            source = str(params.get("source") or "").replace("'", "")
            ipv6 = bool(params.get("ipv6"))
            _add_router(
                bv, out, "从主路由执行真实OSPF路径流量",
                f"{'ping6' if ipv6 else 'ping'} -I {source} -c 4 -W 1 {target}",
                "收发数量与本步骤正向或负向控制组一致", actual=actual,
                effect="发送4个ICMP测试报文",
            )
        elif name == "management_health":
            _add_router(
                bv, out, "确认主路由管理服务监听",
                "ss -lnt | grep -E ':(22|80|443)[[:space:]]'",
                "显示SSH和Web管理监听", actual=actual,
            )
            _add_client(
                bv, out, "确认客户端业务接口到主路由LAN可达",
                "ping -I ens11 -c 2 -W 1 192.168.148.1",
                "2个报文全部收到响应", actual=actual,
                effect="发送2个ICMP健康检查报文",
            )
        # Peer topology probes and all restore/cleanup helpers are internal-only.
        return _deduplicate(out)

    if name == "verify_basic_singleton_contract":
        actual = _basic_result_actual(result, params)
        _add_router(
            bv, out, "查看基础设置表结构",
            f"sqlite3 {DB_PATH} '.schema basic'",
            "显示basic单例表建表语句、字段类型和默认值",
            actual=actual,
        )
        _add_sql(
            bv, out, "确认基础设置只有id=1单例记录",
            "SELECT count(*) AS row_count FROM basic",
            "row_count=1", actual=actual,
        )
        _add_router(
            bv, out, "查看基础设置show/save与对时接口注册",
            "grep -nE 'url=system/basic/(config|ntp:sync)' /usr/ikuai/script/basic.sh",
            "包含config的get=data/put=save及ntp:sync的post=sync_time",
            actual=actual,
        )
        _add_router(
            bv, out, "查看基础设置脚本动作入口",
            "grep -nE '^(init|save|sync_time|set_time)\\(\\)' /usr/ikuai/script/basic.sh",
            "四个真实动作入口均存在", actual=actual,
        )
        _add_router(
            bv, out, "查看NTP配置到真实取时程序的映射",
            "strings /usr/sbin/ikntpget 2>/dev/null | grep -E 'switch_ntpserver|ntpserver_list|cache/config/basic'",
            "同时显示缓存路径、switch_ntpserver和ntpserver_list字段名，不输出当前地址值",
            actual=actual,
        )
    elif name == "verify_basic_database":
        _basic_add_database(bv, out, _basic_result_actual(result, params))
    elif name == "verify_basic_generated_state":
        _basic_add_generated_state(
            bv, out, _basic_result_actual(result, params)
        )
    elif name == "verify_basic_nat_runtime":
        _basic_add_nat_state(bv, out, _basic_result_actual(result, params))
    elif name == "verify_basic_link_runtime":
        _basic_add_link_state(bv, out, _basic_result_actual(result, params))
    elif name == "verify_basic_link_topology_safety":
        actual = _basic_result_actual(result, params)
        for iface in ("lan1", "wan1", "wan2", "wan3"):
            _add_router(
                bv, out, f"查看{iface}物理链路状态",
                f"ip link show dev {iface} 2>/dev/null | sed -n '1p'",
                "首行同时包含UP和LOWER_UP", actual=actual,
            )
            _add_router(
                bv, out, f"确认{iface}存在IPv4地址",
                f"ip -o -4 addr show dev {iface} 2>/dev/null | wc -l",
                "输出至少为1", actual=actual,
            )
        router_host = str(ipaddress.ip_address(_host_for(bv, "router")))
        _add_router(
            bv, out, "确认管理地址所属接口",
            f"ip -o -4 addr show 2>/dev/null | grep -F ' {router_host}/' | awk '{{print $2}}'",
            "输出wan1，证明当前SSH/Web管理地址的接口角色", actual=actual,
        )
        _add_client(
            bv, out, "确认客户端管理路径不走测试LAN网卡",
            f"ip route get {router_host}",
            "输出的dev不是ens11", actual=actual,
        )
        _add_client(
            bv, out, "确认客户端LAN路径直连路由器lan1",
            "ip route get 192.168.148.1",
            "输出包含dev ens11和src 192.168.148.2", actual=actual,
        )
        _add_router(
            bv, out, "查看链路模式脚本影响边界",
            "sed -n '282,315p' /usr/ikuai/script/basic.sh",
            "只显示notify与ik_cntl bridge切换，不出现ip link/addr/route改写",
            actual=actual,
        )
        _add_router(
            bv, out, "确认无未知链路通知处理器",
            "find /etc/basic/notify.d -maxdepth 1 -type f -perm /111 -print 2>/dev/null",
            "当前实机无输出", actual=actual,
        )
    elif name == "verify_basic_acceleration_runtime":
        _basic_add_acceleration_state(
            bv, out, _basic_result_actual(result, params)
        )
    elif name == "verify_basic_ntp_runtime":
        _basic_add_ntp_state(bv, out, _basic_result_actual(result, params))
    elif name in {"verify_basic_runtime_consistency", "verify_basic_reinit"}:
        _basic_add_compact_runtime(
            bv, out, _basic_result_actual(result, params)
        )
    elif name == "verify_basic_environment_unchanged":
        actual = _basic_result_actual(result, params)
        valid_when = "测试结束并完成finally恢复后"
        _basic_add_compact_runtime(
            bv, out, actual, valid_when=valid_when
        )
        _basic_add_client_route(
            bv, out, params, actual, valid_when=valid_when
        )
        _basic_add_client_artifact_audit(
            bv, out, actual, valid_when=valid_when
        )
        _basic_add_recovery_fingerprint(bv, out, actual)
    elif name == "verify_basic_test_artifacts_absent":
        actual = _basic_result_actual(result, params)
        valid_when = "测试结束并完成finally恢复后"
        _basic_add_database(bv, out, actual, valid_when=valid_when)
        _basic_add_client_route(
            bv, out, params, actual, valid_when=valid_when
        )
        _basic_add_client_artifact_audit(
            bv, out, actual, valid_when=valid_when
        )
        _basic_add_management_health(bv, out, actual)
        _basic_add_recovery_fingerprint(bv, out, actual)
    elif name == "verify_basic_management_health":
        _basic_add_management_health(
            bv, out, _basic_result_actual(result, params)
        )
    elif name == "verify_basic_client_route":
        _basic_add_client_route(
            bv, out, params, _basic_result_actual(result, params)
        )
    elif name == "run_basic_iperf_probe":
        _basic_add_iperf(
            bv, out, params, _basic_result_actual(result, params)
        )
    elif name == "run_basic_acceleration_probe":
        actual = _basic_result_actual(result, params)
        _basic_add_acceleration_state(bv, out, actual)
        _basic_add_iperf(
            bv, out, params, actual,
            purpose="产生并命中FASTOFFLOAD的真实iperf3流量",
        )
        _add_router(
            bv, out, "打流后复核FASTOFFLOAD包计数",
            "iptables -w -t mangle -L FASTOFFLOAD -n -v -x 2>/dev/null",
            "FLOWOFFLOAD规则包计数相对打流前增加", actual=actual,
            valid_when="本条iperf3命令完成后立即执行",
        )
    elif name == "run_basic_route_mode_probe":
        actual = _basic_result_actual(result, params)
        lan_ip = str(ipaddress.ip_address(str(params.get("lan_ip") or "192.168.148.2")))
        server = _basic_server_ip(bv, params)
        wan_iface = str(params.get("wan_iface") or "wan1")
        client_iface = str(params.get("client_iface") or "ens11")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", wan_iface):
            raise ValueError("人工路由模式复验WAN接口格式不安全")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", client_iface):
            raise ValueError("人工路由模式复验客户端接口格式不安全")
        route_params = dict(params)
        route_params["expected_iface"] = client_iface
        route_params["expected_source"] = lan_ip
        _basic_add_client_route(bv, out, route_params, actual)
        _add_router(
            bv, out, "终端1：抓取路由模式WAN侧目标ICMP请求",
            f"timeout -t 8 tcpdump -ni {wan_iface} -c 4 "
            f"'icmp and dst host {server}'",
            f"捕获请求且显示src={lan_ip}、dst={server}，证明WAN侧未做源NAT；若源地址不同则已转换",
            actual=actual,
            valid_when="先在路由器终端执行并等待，再执行下一条客户端ping",
        )
        _add_client(
            bv, out, "终端2：连续发送路由模式ICMP请求",
            f"ping -I {client_iface} -c 4 -i 0.25 -W 2 {server}",
            "仅负责触发终端1抓包；允许无回程导致ping非0，结论以终端1捕获的源地址为准",
            actual=actual,
            effect="经客户端内网接口发送四个ICMP Echo请求；不修改配置",
            valid_when="路由器终端tcpdump已进入监听后立即执行",
        )
    elif name == "run_basic_fullcone_probe":
        actual = _basic_result_actual(result, params)
        _basic_add_client_route(bv, out, params, actual)
        _basic_add_nat_state(
            bv, out, actual,
            valid_when="NAT锥形自动化探测执行期间或模式保存后",
        )
        _add_router(
            bv, out, "查看NAT锥形探测UDP连接跟踪",
            "conntrack -L -p udp 2>/dev/null | grep -F 'dport=5201' | head -10",
            "自动化探测期间显示LAN源、外部映射端口与iperf3服务端；最终锥形结论以实包结果为准",
            actual=actual,
            valid_when="NAT锥形自动化探测执行期间",
        )
        _add_router(
            bv, out, "查看NAT1入站FULLCONENAT包计数",
            "iptables -w -t nat -L PRE_FULLCONE -n -v -x 2>/dev/null",
            "NAT1探测期间FULLCONENAT规则包计数增加；NAT4模式无该规则",
            actual=actual,
            valid_when="NAT锥形自动化探测发包前后分别执行并比较",
        )
    elif name == "run_basic_ntp_protocol_probe":
        actual = _basic_result_actual(result, params)
        host = str(ipaddress.ip_address(str(params.get("host") or "192.168.148.1")))
        expect_success = bool(params.get("expect_success", True))
        _add_client(
            bv, out, "确认SNTP请求经客户端内网接口发送",
            f"ip route get {host}",
            "输出包含dev ens11和src 192.168.148.2", actual=actual,
        )
        program = (
            "import socket;"
            "print((lambda r:(len(r[0]),r[0][0]&7))((lambda s:"
            "(s.settimeout(3),"
            f"s.sendto(bytes([27])+bytes(47),({host!r},123)),"
            "s.recvfrom(512))[2])"
            "(socket.socket(socket.AF_INET,socket.SOCK_DGRAM))))"
        )
        _add_client(
            bv, out, "发送真实SNTP请求",
            "python3 -c " + _double_quote(program),
            (
                "输出长度至少48且mode=4" if expect_success else
                "命令超时或无合法服务端响应"
            ),
            actual=actual,
            effect="向被测路由器UDP/123发送一个48字节SNTP请求",
        )

    elif name == "verify_kernel_script_contract":
        _add_router(
            bv, out, "查看内核设置脚本校验值",
            "sha256sum /usr/ikuai/script/ik_sysctl.sh",
            "显示当前实机ik_sysctl.sh的SHA256",
        )
        _add_router(
            bv, out, "查看内核设置API软链接",
            "readlink -f /usr/ikuai/function/ik_sysctl",
            "输出/usr/ikuai/script/ik_sysctl.sh",
        )
        _add_router(
            bv, out, "查看内核设置单例表结构",
            f"sqlite3 {DB_PATH} {_double_quote('.schema sysctl')}",
            "显示id、bbr和11个conntrack超时字段",
        )
        _add_router(
            bv, out, "查看API、范围和运行态写入入口",
            "grep -nE '(url=system/kernel-params|__check_param|tcp_congestion_control|nf_conntrack_.*timeout)' /usr/ikuai/script/ik_sysctl.sh",
            "输出show/save/default、字段范围及每个/proc写入映射",
        )
    elif name == "verify_kernel_database":
        _add_sql(
            bv, out, "查看内核设置单例数据库",
            "SELECT id,bbr,syn_recv_timeout,syn_send_timeout,established_timeout,"
            "fin_wait_timeout,last_ack_timeout,close_wait_timeout,time_wait_timeout,"
            "close_timeout,udp_timeout,udp_stream_timeout,icmp_timeout FROM sysctl WHERE id=1",
            "十二个配置字段与报告期望一致",
        )
    elif name in {
        "verify_kernel_runtime", "verify_kernel_full_chain",
        "verify_kernel_reinit", "verify_kernel_environment_unchanged",
    }:
        _add_sql(
            bv, out, "查看内核设置单例数据库",
            "SELECT id,bbr,syn_recv_timeout,syn_send_timeout,established_timeout,"
            "fin_wait_timeout,last_ack_timeout,close_wait_timeout,time_wait_timeout,"
            "close_timeout,udp_timeout,udp_stream_timeout,icmp_timeout FROM sysctl WHERE id=1",
            "字段与报告中的当前配置一致",
        )
        proc_names = (
            "nf_conntrack_tcp_timeout_syn_recv",
            "nf_conntrack_tcp_timeout_syn_sent",
            "nf_conntrack_tcp_timeout_established",
            "nf_conntrack_tcp_timeout_fin_wait",
            "nf_conntrack_tcp_timeout_last_ack",
            "nf_conntrack_tcp_timeout_close_wait",
            "nf_conntrack_tcp_timeout_time_wait",
            "nf_conntrack_tcp_timeout_close",
            "nf_conntrack_udp_timeout",
            "nf_conntrack_udp_timeout_stream",
            "nf_conntrack_icmp_timeout",
        )
        for proc_name in proc_names:
            _add_router(
                bv, out, f"查看{proc_name}运行值",
                f"cat /proc/sys/net/netfilter/{proc_name}",
                "输出值与sysctl表对应字段一致",
            )
        _add_router(
            bv, out, "查看TCP拥塞算法",
            "cat /proc/sys/net/ipv4/tcp_congestion_control",
            "bbr=1时输出bbr，bbr=0时输出cubic",
        )
        _add_router(
            bv, out, "查看可用TCP拥塞算法",
            "cat /proc/sys/net/ipv4/tcp_available_congestion_control",
            "列表包含bbr和cubic",
        )
        if name == "verify_kernel_environment_unchanged":
            _add_router(
                bv, out, "审计路由器内核设置测试临时文件",
                "find /tmp -maxdepth 1 -name 'ikuai_kernel_*' -print",
                "无输出",
                valid_when="测试结束后仍有效",
            )
            _add_client(
                bv, out, "审计客户端内核设置测试临时文件",
                "find /tmp -maxdepth 1 -name 'ikuai_kernel_*' -print",
                "无输出",
                valid_when="测试结束后仍有效",
            )
    elif name == "verify_kernel_path_health":
        details = getattr(result, "details", {}) or {}
        target = str(details.get("target") or params.get("target") or "10.66.0.57")
        _add_client(
            bv, out, "确认内核设置L5流量走ens11",
            f"ip route get {target} from 192.168.148.2",
            "探测期间输出via 192.168.148.1、dev ens11和src 192.168.148.2",
            valid_when="自动化临时主机路由生效期间执行；测试结束后路由会恢复",
        )
        _add_client(
            bv, out, "发送L5路径健康报文",
            f"ping -I 192.168.148.2 -c 1 -W 2 {target}",
            "收到1个ICMP回包",
            effect="向L5对端发送一个ICMP健康检查报文",
        )
        _add_router(
            bv, out, "确认L5路径发生SNAT",
            f"conntrack -L -p icmp 2>/dev/null | grep 'src=192.168.148.2 dst={target}'",
            "反向元组目的地址为路由器WAN地址",
            valid_when="健康探针发出后立即执行",
        )
    elif name == "run_kernel_conntrack_probe":
        details = getattr(result, "details", {}) or {}
        peer = str(details.get("peer") or "10.66.0.57")
        ports = details.get("ports") or {}
        tcp_source = int(ports.get("tcp_source") or 30001)
        udp_source = int(ports.get("udp_source") or 30002)
        _add_client(
            bv, out, "确认L5真实流量经被测路由",
            f"ip route get {peer} from 192.168.148.2",
            "探测期间输出via 192.168.148.1、dev ens11和src 192.168.148.2",
            valid_when="自动化临时主机路由生效期间执行；测试结束后路由会恢复",
        )
        _add_router(
            bv, out, "查看本轮TCP ESTABLISHED超时",
            f"conntrack -L -p tcp 2>/dev/null | grep 'src=192.168.148.2 dst={peer}' | grep 'sport={tcp_source}'",
            "状态为ESTABLISHED，超时秒数接近页面established_timeout",
            valid_when="L5探针保持TCP连接期间执行",
        )
        _add_router(
            bv, out, "查看本轮单向UDP超时",
            f"conntrack -L -p udp 2>/dev/null | grep 'src=192.168.148.2 dst={peer}' | grep 'sport={udp_source}'",
            "初始超时不大于udp_timeout，到期后无输出",
            valid_when="L5探针发包后、udp_timeout到期前后各执行一次",
        )
        _add_router(
            bv, out, "查看本轮双向UDP stream超时",
            f"conntrack -L -p udp 2>/dev/null | grep 'src=192.168.148.2 dst={peer}' | grep 'sport={udp_source + 1}'",
            "显示[ASSURED]且超时不大于udp_stream_timeout",
            valid_when="L5对端回包后、udp_stream_timeout到期前执行",
        )
        _add_router(
            bv, out, "查看本轮ICMP超时",
            f"conntrack -L -p icmp 2>/dev/null | grep 'src=192.168.148.2 dst={peer}'",
            "初始超时不大于icmp_timeout，到期后无输出",
            valid_when="L5 ping后、icmp_timeout到期前后各执行一次",
        )
        _add_router(
            bv, out, "查看L5期间TCP拥塞算法",
            "cat /proc/sys/net/ipv4/tcp_congestion_control",
            "与报告中的bbr开关一致",
        )

    elif name == "verify_protocol_control_script_contract":
        _add_router(
            bv, out, "查看协议控制脚本校验值",
            "sha256sum /usr/ikuai/script/core_control.sh",
            "显示当前实机core_control.sh的SHA256",
        )
        _add_router(
            bv, out, "查看协议控制API注册",
            "readlink /usr/ikuai/function/core_control",
            "输出../script/core_control.sh",
        )
        _add_router(
            bv, out, "查看协议控制单例表结构",
            f"sqlite3 {DB_PATH} {_double_quote('.schema forward_mode_config')}",
            "显示mode/dpi/quic/https/appid_load字段及默认值",
        )
        _add_router(
            bv, out, "查看协议控制模式映射和参数校验",
            "grep -nE '(save\\(\\)|show\\(\\)|mode.*== 0|ik_cntl (quic|https|appid_load)|__set_switch_dpi)' /usr/ikuai/script/core_control.sh",
            "输出show/save、0/1/2/3校验及DPI/QUIC/HTTPS/appid_load调用",
        )
    elif name == "verify_protocol_control_database":
        expected_mode = int(params.get("expected_mode", -1))
        _add_sql(
            bv, out, "查看协议控制单例数据库",
            "SELECT id,mode,dpi,quic,https,appid_load FROM forward_mode_config WHERE id=1",
            f"mode={expected_mode}且派生字段与报告期望一致",
        )
    elif name in {
        "wait_protocol_control_runtime", "verify_protocol_control_runtime",
        "verify_protocol_control_full_chain", "verify_protocol_control_reinit",
        "verify_protocol_control_environment_unchanged",
    }:
        _add_sql(
            bv, out, "查看协议控制持久化字段",
            "SELECT id,mode,dpi,quic,https,appid_load FROM forward_mode_config WHERE id=1",
            "字段与报告中的当前模式一致",
        )
        _add_router(
            bv, out, "查看协议控制真实内核运行态",
            "cat /proc/ikuai/stats/ik_features_status | grep -E '^(dpi|user_dpi|l4_dpi|audit|appid_load|quic|https)'",
            "各特性enable/disable与报告中的模式契约一致",
        )
        _add_router(
            bv, out, "查看访问记录与审计进程",
            "pidof ik_url_auditd ik_stats_collect ik_host_ua; ls -l /tmp/iktmp/audit.open_* 2>/dev/null",
            "平衡模式存在访问记录运行态；性能模式应按页面说明关闭相关能力",
        )
    elif name == "verify_protocol_control_management_health":
        _add_router(
            bv, out, "确认Web管理服务存活",
            "curl -sS --max-time 4 -o /dev/null -w '%{http_code}\\n' http://127.0.0.1/",
            "输出200或302",
        )
    elif name == "verify_protocol_control_secondary_client_health":
        _add_router(
            bv, out, "确认独立终端仍有SNAT会话",
            "conntrack -L 2>/dev/null | grep -F 'src=192.168.148.5' | head -20",
            "反向元组目的地址为路由器WAN地址",
        )
    elif name == "verify_protocol_control_nat_health":
        target = str(params.get("target") or "223.5.5.5")
        _add_client(
            bv, out, "确认协议控制联网哨兵走被测路由器LAN",
            f"ip route get {target} from 192.168.148.2",
            "探测期间输出包含via 192.168.148.1、dev ens11和src 192.168.148.2",
            valid_when="自动化临时主机路由生效期间执行；测试结束后路由会恢复",
        )
        _add_client(
            bv, out, "发送协议控制联网哨兵",
            f"ping -I 192.168.148.2 -c 1 -W 2 {target}",
            "收到1个ICMP回包",
            effect="发送1个联网健康检查报文，不修改配置",
        )
        _add_router(
            bv, out, "确认联网哨兵发生SNAT",
            f"conntrack -L -p icmp 2>/dev/null | grep 'src=192.168.148.2 dst={target}'",
            "反向元组目的地址为路由器WAN地址",
        )
    elif name == "run_protocol_control_http_probe":
        actual_details = getattr(result, "details", {}) or {}
        token = str(actual_details.get("token") or "IKPC_TOKEN")
        host = str(actual_details.get("host") or token.lower() + ".example.test")
        peer = str(actual_details.get("peer") or _host_for(bv, "peer") or "10.66.0.56")
        port = int(actual_details.get("port") or 30080)
        _add_client(
            bv, out, "确认协议控制HTTP流量路由",
            f"ip route get {peer} from 192.168.148.2",
            "受控探测期间输出via 192.168.148.1、dev ens11和src 192.168.148.2",
            valid_when="在已由测试环境建立到peer的临时主机路由期间执行",
        )
        _add_router(
            bv, out, "查看本轮HTTP的DPI识别",
            f"cat /proc/ikuai/dpi/dpi_cache | grep -F {peer} | grep -E '[[:space:]]{port}[[:space:]]'",
            "平衡模式显示HTTP appid；性能模式无输出",
            valid_when="本轮唯一HTTP连接仍在DPI缓存窗口内",
        )
        _add_router(
            bv, out, "查看本轮唯一访问记录",
            f"grep -aF {host} /etc/log/audit/stream/*",
            "平衡模式记录关联192.168.148.2和唯一Host；性能模式无输出",
            valid_when="自动化精确清理本轮token前执行",
        )
        _add_router(
            bv, out, "查看本轮HTTP的SNAT元组",
            f"conntrack -L -p tcp 2>/dev/null | grep 'src=192.168.148.2 dst={peer}' | grep 'dport={port}'",
            "反向元组目的地址为路由器WAN地址",
            valid_when="本轮HTTP conntrack尚未超时",
        )
    elif name == "verify_alg_nat_health":
        target = str(params.get("target") or "223.5.5.5")
        _add_client(
            bv, out, "确认ALG联网哨兵流量走被测路由器LAN",
            f"ip route get {target} from 192.168.148.2",
            "探测期间输出包含via 192.168.148.1、dev ens11和src 192.168.148.2",
            valid_when="自动化临时主机路由生效期间执行；测试结束后路由会恢复",
        )
        _add_client(
            bv, out, "从功能客户端发送ALG联网哨兵",
            f"ping -I 192.168.148.2 -c 1 -W 2 {target}",
            "收到1个ICMP回包",
            effect="发送1个联网健康检查报文，不修改配置",
            valid_when="目标流量已明确经192.168.148.1转发",
        )
        _add_router(
            bv, out, "确认ALG联网哨兵发生SNAT",
            f"conntrack -L -p icmp 2>/dev/null | grep 'src=192.168.148.2 dst={target}'",
            "正向元组为192.168.148.2，反向元组目的地址为路由器WAN地址而非192.168.148.2",
            valid_when="哨兵ping发出后立即执行",
        )
    elif name == "verify_alg_script_contract":
        _add_router(
            bv, out, "查看ALG脚本校验值",
            "sha256sum /usr/ikuai/script/alg.sh",
            "显示当前实际生效alg.sh的SHA256",
        )
        _add_router(
            bv, out, "查看ALG单例表结构",
            f"sqlite3 {DB_PATH} {_double_quote('.schema alg_config')}",
            "显示id、四协议开关和三组非标准端口字段",
        )
        _add_router(
            bv, out, "查看ALG API、端口校验和模块装卸入口",
            "grep -nE '(url=system/alg|__check_port_repeat|port_count|port_repeat|modprobe nf_|rmmod nf_)' /usr/ikuai/script/alg.sh",
            "输出覆盖show/save API、每协议7端口上限、跨协议重复校验和模块装卸",
        )
    elif name == "verify_alg_database":
        _add_sql(
            bv, out, "查看ALG单例数据库字段",
            "SELECT id,support_ftp,support_tftp,support_sip,support_h323,ftp_ports,tftp_ports,sip_ports FROM alg_config WHERE id=1",
            "七个配置字段与当前页面保存值一致",
        )
    elif name == "verify_alg_modules":
        _add_router(
            bv, out, "查看ALG conntrack/NAT模块",
            "lsmod | grep -E 'nf_(conntrack|nat)_(ftp|tftp|sip|h323)'",
            "每个已开启协议各显示nf_conntrack和nf_nat模块；关闭协议无对应行",
        )
    elif name == "verify_alg_ports":
        for protocol in ("ftp", "tftp", "sip"):
            _add_router(
                bv, out, f"查看{protocol.upper()} ALG内核端口参数",
                f"cat /sys/module/nf_conntrack_{protocol}/parameters/ports",
                "启用时为页面自定义端口加协议标准端口；关闭时文件不存在",
            )
    elif name in {
        "verify_alg_runtime_consistency", "verify_alg_reinit",
        "verify_alg_environment_unchanged",
    }:
        _add_sql(
            bv, out, "查看ALG单例数据库字段",
            "SELECT id,support_ftp,support_tftp,support_sip,support_h323,ftp_ports,tftp_ports,sip_ports FROM alg_config WHERE id=1",
            "字段与报告中的期望配置一致",
        )
        _add_router(
            bv, out, "查看ALG conntrack/NAT模块",
            "lsmod | grep -E 'nf_(conntrack|nat)_(ftp|tftp|sip|h323)'",
            "模块集合与四个开关一致",
        )
        for protocol in ("ftp", "tftp", "sip"):
            _add_router(
                bv, out, f"查看{protocol.upper()} ALG端口",
                f"cat /sys/module/nf_conntrack_{protocol}/parameters/ports",
                "启用时包含全部自定义端口并以标准端口结尾；关闭时文件不存在",
            )
        if name == "verify_alg_environment_unchanged":
            _add_router(
                bv, out, "审计路由器ALG测试临时文件",
                "find /tmp -maxdepth 1 -name 'ikuai_alg_ftp_*' -print",
                "无输出",
                valid_when="测试结束后仍有效",
            )
            _add_client(
                bv, out, "审计客户端ALG测试临时文件",
                "find /tmp -maxdepth 1 -name 'ikuai_alg_ftp_*' -print",
                "无输出",
                valid_when="测试结束后仍有效",
            )
            _add_router(
                bv, out, "审计路由器ALG测试标记规则",
                "iptables-save 2>/dev/null | grep -F 'IKUAI_ALG_FTP_'",
                "无输出",
                valid_when="测试结束后仍有效",
            )
    elif name == "run_alg_ftp_probe":
        control_port = int(params.get("control_port") or 2121)
        data_port = int(params.get("data_port") or 50000)
        expect_enabled = bool(params.get("expect_enabled", True))
        peer_host = _host_for(bv, "peer") or "10.66.0.56"
        _add_client(
            bv, out, "确认FTP ALG控制流量经过被测路由器LAN",
            f"ip route get {peer_host}",
            "输出包含via 192.168.148.1、dev ens11和src 192.168.148.2",
        )
        _add_router(
            bv, out, "查看FTP ALG控制连接helper",
            f"conntrack -L -p tcp 2>/dev/null | grep 'dport={control_port}' | grep 'helper=ftp-{control_port}'",
            (
                "启用时显示helper=ftp及LAN源/WAN对端；关闭时无输出"
                if expect_enabled else "关闭场景无输出"
            ),
            valid_when="手工保持FTP控制连接后立即执行",
        )
        _add_router(
            bv, out, "查看FTP主动数据通道expectation",
            f"conntrack -L expect 2>/dev/null | grep 'dport={data_port}' | grep 'helper=ftp-{control_port}'",
            (
                "启用时显示由PORT命令创建的目标数据端口expectation"
                if expect_enabled else "关闭场景无输出"
            ),
            valid_when="手工发送PORT命令后、数据连接建立前立即执行",
        )
        _add_router(
            bv, out, "抓取FTP控制流量中的PORT载荷",
            f"tcpdump -ni wan1 -s0 -A -c 12 'tcp and dst host {peer_host} and dst port {control_port}'",
            (
                "启用时PORT地址为路由器WAN地址；关闭时仍为192,168,148,2"
                if expect_enabled else "PORT地址保持192,168,148,2且无ALG改写"
            ),
            effect="抓取最多12个FTP控制流量数据包，不修改配置",
            valid_when="先启动抓包，再从192.168.148.2发起FTP主动模式控制连接",
        )
    elif name == "verify_ftp_global_database":
        _add_sql(bv, out, "查看FTP全局数据库字段",
                 "SELECT id,open_ftp,ftp_port,ftp_access FROM remote_control ORDER BY id LIMIT 1",
                 "开关、端口和外网访问字段与页面设置一致")
    elif name == "verify_ftp_user_database":
        username = str(params.get("username", ""))
        _add_sql(bv, out, f"查看FTP用户 {username}",
                 "SELECT id,enabled,username,tagname,permission,home_dir,upload,download,"
                 "CASE WHEN length(COALESCE(passwd,''))>0 THEN 'stored' ELSE 'missing' END AS passwd_state "
                 f"FROM ftp_server WHERE username={_sql_literal(username)} LIMIT 1",
                 "存在场景返回1行且字段正确；删除场景无输出")
    elif name == "verify_ftp_user_count":
        prefix = params.get("prefix")
        sql = "SELECT count(*) AS cnt FROM ftp_server"
        if prefix is not None:
            sql += " WHERE " + _prefix_predicate(str(prefix), ("username", "tagname"))
        _add_sql(bv, out, "统计FTP用户", sql, "cnt等于报告中的期望数量")
    elif name == "verify_ftp_auth_runtime":
        username = str(params.get("username", ""))
        _add_router(bv, out, f"查看FTP认证映射 {username}（不输出密码）",
                    f"grep -nF {_double_quote(username + ' ')} /tmp/iktmp/ik_ftp_user | cut -d '\"' -f1,3-",
                    "存在场景显示1行且权限/目录正确；停用或删除场景无输出")
        _add_router(bv, out, "查看FTP认证文件配置",
                    "grep -nE \"^(listen_port|ikuai_auth_file)=\" /etc/ik_ftp_user.conf",
                    "ikuai_auth_file指向/tmp/iktmp/ik_ftp_user")
    elif name == "verify_ftp_listener":
        port = int(params.get("port"))
        _add_router(bv, out, f"查看TCP/{port}监听",
                    f"netstat -lntp 2>/dev/null | grep -E {_double_quote(':' + str(port) + '[[:space:]]')}",
                    "启用时显示目标端口；关闭时无输出")
    elif name == "verify_ftp_daemon":
        _add_router(bv, out, "查看ik_ftpd进程", "ps w 2>/dev/null | grep '[i]k_ftpd'",
                    "启用时显示使用/etc/ik_ftp_user.conf的ik_ftpd；关闭时无输出")
        if params.get("port"):
            _ftp_common_runtime(bv, out, port=int(params["port"]))
    elif name == "verify_ftp_firewall":
        port = int(params.get("port"))
        _add_router(bv, out, f"查看TCP/{port} WAN阻断成员",
                    f"ipset list DROP_T_PORTS_WAN_IN 2>/dev/null | grep -x '{port}'",
                    "禁止外网时显示该端口；允许外网时无输出")
    elif name in {"verify_ftp_runtime_consistency", "verify_ftp_reinit"}:
        prefix = params.get("prefix") or params.get("username")
        port = params.get("port")
        if port is None and result is not None:
            port = (getattr(result, "details", {}) or {}).get("port")
        _ftp_common_runtime(bv, out, prefix=str(prefix) if prefix else None,
                            port=int(port) if port else None)
    elif name == "verify_ftp_test_artifacts_absent":
        prefix = str(params.get("prefix", ""))
        predicate = _prefix_predicate(prefix, ("username", "tagname"))
        _add_sql(bv, out, "确认FTP测试用户已清空",
                 f"SELECT count(*) AS cnt FROM ftp_server WHERE {predicate}", "cnt=0",
                 valid_when="测试结束后仍有效")
        test_dir = params.get("test_dir")
        if test_dir:
            _add_router(bv, out, "确认FTP测试目录不存在", f"ls -ld {_double_quote(test_dir)}",
                        "应提示No such file or directory", valid_when="测试结束后仍有效")
        if params.get("port"):
            port = int(params["port"])
            _add_router(bv, out, f"确认TCP/{port}无测试监听",
                        f"netstat -lntp 2>/dev/null | grep -E {_double_quote(':' + str(port) + '[[:space:]]')}",
                        "测试专用端口应无输出", valid_when="测试结束后仍有效")
        _add_client(bv, out, "确认FTP客户端临时文件已清理",
                    "find /tmp -maxdepth 1 -name 'ftp_probe_*' -print",
                    "无输出", valid_when="测试结束后仍有效")
    elif name == "verify_ftp_non_test_users_unchanged":
        prefix = str(params.get("prefix", ""))
        predicate = _prefix_predicate(prefix, ("username", "tagname"))
        _add_sql(bv, out, "查看非测试FTP用户",
                 "SELECT id,enabled,username,tagname,permission,home_dir,upload,download "
                 f"FROM ftp_server WHERE NOT ({predicate}) ORDER BY id",
                 "应与测试前快照一致")
    elif name == "run_ftp_probe":
        username = str(params.get("username") or "anonymous")
        host = str(params.get("host") or "192.168.148.1")
        iface = str(params.get("iface") or "ens11")
        port = int(params.get("port") or 21)
        operation = str(params.get("operation") or "list").strip().lower()
        token = _safe_probe_component(username, "ftp_user")
        remote_name = _safe_probe_component(
            params.get("remote_name"), f"ikuai_ftp_manual_{token}.txt"
        )
        source_path = f"/tmp/ikuai_ftp_manual_{token}.txt"
        download_path = f"/tmp/ikuai_ftp_manual_{token}.download"
        base_url = f"ftp://{host}:{port}/"
        file_url = base_url + remote_name
        curl = _ftp_curl_prefix(username, iface)

        _add_client_route(bv, out, host, iface, "FTP")
        if operation == "list":
            _add_client(
                bv, out, "列出FTP目录（终端会提示输入密码）",
                f"{curl} --list-only {_double_quote(base_url)}",
                "返回目录列表且命令成功结束",
                interactive=True,
                interactive_hint="输入该测试用户的正确密码",
            )
        elif operation == "wrong_password":
            _add_client(
                bv, out, "使用错误密码验证FTP认证拒绝",
                f"{curl} --list-only {_double_quote(base_url)}",
                "返回530/Login denied等认证拒绝，不能列出目录",
                interactive=True,
                interactive_hint="本条故意输入错误密码",
            )
            _add_client(
                bv, out, "使用正确密码确认FTP服务本身可用",
                f"{curl} --list-only {_double_quote(base_url)}",
                "正确密码可列出目录，排除服务停机造成的假阳性",
                interactive=True,
                interactive_hint="本条输入该测试用户的正确密码",
            )
        elif operation == "connect_fail":
            _add_client(
                bv, out, "验证目标FTP地址连接失败",
                f"{curl} --list-only {_double_quote(base_url)}",
                "外网阻断时连接超时；服务关闭时提示无法连接，均不能返回目录",
                interactive=True,
                interactive_hint="若终端在连接前提示密码，可输入该用户正确密码",
            )
            server_mode = (getattr(result, "details", {}) or {}).get("server_mode")
            if server_mode == "wan_drop":
                control_host = str(params.get("control_host") or "192.168.148.1")
                control_iface = str(params.get("control_iface") or "ens11")
                control_curl = _ftp_curl_prefix(username, control_iface)
                _add_client_route(bv, out, control_host, control_iface, "FTP内网控制组")
                _add_client(
                    bv, out, "从内网控制地址确认FTP仍可用",
                    f"{control_curl} --list-only {_double_quote(f'ftp://{control_host}:{port}/')}",
                    "内网控制组可列出目录，证明外网失败来自访问策略",
                    interactive=True,
                    interactive_hint="输入该测试用户的正确密码",
                )
        elif operation in {"upload_download", "upload_denied"}:
            _add_client(
                bv, out, "1. 创建固定FTP人工复验文件",
                f"printf 'ikuai ftp manual probe\\n' > {_double_quote(source_path)}",
                f"生成客户端临时文件 {source_path}",
                effect="写入测试客户端临时文件",
            )
            _add_client(
                bv, out, "2. 上传FTP人工复验文件",
                f"{curl} --upload-file {_double_quote(source_path)} {_double_quote(file_url)}",
                ("读写用户上传成功" if operation == "upload_download" else
                 "只读用户返回550/Permission denied，上传必须失败"),
                interactive=True,
                interactive_hint="输入该测试用户的正确密码",
                effect=("写入远端测试文件" if operation == "upload_download" else
                        "尝试写入远端测试文件"),
            )
            if operation == "upload_download":
                _add_client(
                    bv, out, "3. 下载刚上传的FTP文件",
                    f"{curl} --output {_double_quote(download_path)} {_double_quote(file_url)}",
                    f"下载成功并生成 {download_path}",
                    interactive=True,
                    interactive_hint="输入该测试用户的正确密码",
                    effect="写入测试客户端下载文件",
                )
                _add_client(
                    bv, out, "4. 比较上传前后文件SHA256",
                    f"sha256sum {_double_quote(source_path)} {_double_quote(download_path)}",
                    "两行SHA256完全相同",
                )
                _add_client(
                    bv, out, "5. 删除远端FTP人工复验文件",
                    f"{curl} --quote {_double_quote('DELE ' + remote_name)} {_double_quote(base_url)}",
                    "服务器返回250删除成功，随后目录中不再存在该文件",
                    interactive=True,
                    interactive_hint="输入该测试用户的正确密码",
                    effect="删除远端测试文件",
                )
            else:
                _add_client(
                    bv, out, "3. 确认只读上传未留下远端文件",
                    f"{curl} --list-only {_double_quote(base_url)} | grep -Fx {_double_quote(remote_name)}",
                    "无输出；若意外显示文件名，说明只读限制失效",
                    interactive=True,
                    interactive_hint="输入只读测试用户的正确密码",
                )
                cleanup_username = params.get("cleanup_username")
                if cleanup_username:
                    cleanup_curl = _ftp_curl_prefix(str(cleanup_username), iface)
                    _add_client(
                        bv, out, "4. 仅在发现异常残留时用读写账号清理",
                        f"{cleanup_curl} --quote {_double_quote('DELE ' + remote_name)} {_double_quote(base_url)}",
                        "正常产品行为下返回文件不存在；若有异常残留则将其删除",
                        interactive=True,
                        interactive_hint="仅发现异常残留时执行，并输入读写清理账号密码",
                        effect="条件性删除远端测试文件",
                    )
            _add_client(
                bv, out, "清理FTP客户端人工复验文件",
                f"rm -f {_double_quote(source_path)} {_double_quote(download_path)}",
                "两个固定/tmp文件均被删除",
                effect="删除测试客户端临时文件",
            )

    elif name == "verify_samba_global_database":
        _add_sql(bv, out, "查看Samba全局数据库字段",
                 "SELECT id,enabled,workgroup,wsdd2,interface,access FROM smbd ORDER BY id LIMIT 1",
                 "字段与页面设置一致")
    elif name == "verify_samba_user_database":
        username = str(params.get("username", ""))
        _add_sql(bv, out, f"查看Samba用户 {username}", _samba_user_sql(username),
                 "存在场景返回1行且字段正确；删除场景无输出；不显示密码密文")
    elif name == "verify_samba_user_count":
        prefix = params.get("prefix")
        sql = "SELECT count(*) AS cnt FROM smbd_dir"
        if prefix is not None:
            sql += " WHERE " + _prefix_predicate(str(prefix), ("username", "name", "tagname"))
        _add_sql(bv, out, "统计Samba用户", sql, "cnt等于报告中的期望数量")
    elif name == "verify_samba_processes":
        for process in ("ik_smbd", "nmbd", "wsdd2"):
            _add_router(bv, out, f"查看{process}进程", f"pidof {process}",
                        "按当前总开关/WSDD设置返回PID或无输出")
    elif name == "verify_samba_listeners":
        _add_router(bv, out, "查看Samba监听与进程归属",
                    "netstat -lntup 2>/dev/null | grep -E \":(137|138|139|445|3702|5355|5357)[[:space:]]\"",
                    "端口和PID归属与当前总开关/WSDD设置一致")
    elif name == "verify_samba_firewall":
        _add_router(bv, out, "查看Samba TCP WAN阻断集合", "ipset list DROP_T_PORTS_WAN_IN",
                    "TCP/139、445及发现端口成员与报告期望一致")
        _add_router(bv, out, "查看Samba UDP WAN阻断集合", "ipset list DROP_U_PORTS_WAN_IN",
                    "UDP/137、138及发现端口成员与报告期望一致")
    elif name in {"verify_samba_runtime_consistency", "verify_samba_reinit"}:
        prefix = params.get("prefix") or params.get("username")
        _samba_common_runtime(bv, out, str(prefix) if prefix else None)
    elif name == "verify_samba_test_artifacts_absent":
        prefix = str(params.get("prefix", ""))
        predicate = _prefix_predicate(prefix, ("username", "name", "tagname"))
        _add_sql(bv, out, "确认Samba测试用户已清空",
                 f"SELECT count(*) AS cnt FROM smbd_dir WHERE {predicate}", "cnt=0",
                 valid_when="测试结束后仍有效")
        _add_router(bv, out, "确认smb.conf不含测试前缀",
                    f"grep -nF {_double_quote(prefix)} /etc/samba/smb.conf", "无输出",
                    valid_when="测试结束后仍有效")
        _add_router(bv, out, "确认smbpasswd不含测试用户名",
                    f"cut -d: -f1 /etc/samba/smbpasswd | grep -F {_double_quote(prefix)}", "无输出",
                    valid_when="测试结束后仍有效")
        _add_router(bv, out, "查找残留Samba测试目录",
                    f"find /etc/disk_user -maxdepth 3 -type d -name {_double_quote(prefix + '*')} -print",
                    "无输出", valid_when="测试结束后仍有效")
    elif name == "verify_samba_non_test_users_unchanged":
        prefix = str(params.get("prefix", ""))
        predicate = _prefix_predicate(prefix, ("username", "name", "tagname"))
        _add_sql(bv, out, "查看非测试Samba用户",
                 "SELECT id,enabled,username,name,tagname,perm,guest,browseable,home_dir "
                 f"FROM smbd_dir WHERE NOT ({predicate}) ORDER BY id",
                 "应与测试前快照一致")
    elif name == "run_samba_probe":
        host = str(params.get("host") or "192.168.148.1")
        iface = str(params.get("iface") or "ens11")
        username = str(params.get("username") or "")
        share = str(params.get("share_name") or "")
        operation = str(params.get("operation") or "list").strip().lower()
        token = _safe_probe_component(username or share, "samba_user")
        remote_name = _safe_probe_component(
            params.get("remote_name"), f"ikuai_samba_manual_{token}.txt"
        )
        source_path = f"/tmp/ikuai_samba_manual_{token}.txt"
        download_path = f"/tmp/ikuai_samba_manual_{token}.download"

        _add_client_route(bv, out, host, iface, "Samba")
        if operation == "connect_fail":
            _add_client(
                bv, out, "验证目标Samba TCP/445连接失败",
                f"nc -vz -w 5 {_double_quote(host)} 445",
                "外网阻断时连接超时；服务关闭时连接被拒绝，不能显示succeeded",
            )
            control_host = params.get("control_host")
            if control_host and share and username:
                control_host = str(control_host)
                control_iface = str(params.get("control_iface") or "ens11")
                _add_client_route(
                    bv, out, control_host, control_iface, "Samba内网控制组"
                )
                _add_client(
                    bv, out, "从内网控制地址确认Samba仍可用",
                    _smbclient_command(control_host, share, username, "ls"),
                    "正确密码可列出共享内容，证明外网失败来自访问策略",
                    interactive=True,
                    interactive_hint="输入该测试用户的正确密码",
                )
        elif operation == "list":
            _add_client(
                bv, out, "使用认证用户列出Samba共享内容",
                _smbclient_command(host, share, username, "ls"),
                "正确密码可列出共享内容；隐藏共享也可按明确共享名访问",
                interactive=True,
                interactive_hint="输入该测试用户的正确密码",
            )
        elif operation == "wrong_password":
            command = _smbclient_command(host, share, username, "ls")
            _add_client(
                bv, out, "使用错误密码验证Samba认证拒绝",
                command,
                "返回NT_STATUS_LOGON_FAILURE/认证拒绝，不能列出共享内容",
                interactive=True,
                interactive_hint="本条故意输入错误密码",
            )
            _add_client(
                bv, out, "使用正确密码确认Samba服务本身可用",
                command,
                "正确密码可列出共享内容，排除服务停机造成的假阳性",
                interactive=True,
                interactive_hint="本条输入该测试用户的正确密码",
            )
        elif operation in {"guest_list", "guest_denied"}:
            guest_command = _smbclient_command(
                host, share, "smb_guest_probe", "ls"
            )
            _add_client(
                bv, out,
                ("用未知账号验证guest共享可访问" if operation == "guest_list" else
                 "用未知账号验证非guest共享拒绝访问"),
                guest_command,
                ("输入任意非空测试密码后可列出共享内容" if operation == "guest_list" else
                 "返回NT_STATUS_ACCESS_DENIED/LOGON_FAILURE，不能列出内容"),
                interactive=True,
                interactive_hint="用户名已固定为未知账号smb_guest_probe；输入任意非空测试密码",
            )
            if operation == "guest_denied" and username:
                _add_client(
                    bv, out, "使用认证用户确认非guest共享本身可用",
                    _smbclient_command(host, share, username, "ls"),
                    "正确密码可列出共享内容",
                    interactive=True,
                    interactive_hint="输入该测试用户的正确密码",
                )
        elif operation in {"upload_download", "write_denied"}:
            _add_client(
                bv, out, "1. 创建固定Samba人工复验文件",
                f"printf 'ikuai samba manual probe\\n' > {_double_quote(source_path)}",
                f"生成客户端临时文件 {source_path}",
                effect="写入测试客户端临时文件",
            )
            _add_client(
                bv, out, "2. 上传Samba人工复验文件",
                _smbclient_command(
                    host, share, username, f"put {source_path} {remote_name}"
                ),
                ("读写用户上传成功" if operation == "upload_download" else
                 "只读用户返回NT_STATUS_ACCESS_DENIED，上传必须失败"),
                interactive=True,
                interactive_hint="输入该测试用户的正确密码",
                effect=("写入远端测试文件" if operation == "upload_download" else
                        "尝试写入远端测试文件"),
            )
            if operation == "upload_download":
                _add_client(
                    bv, out, "3. 下载刚上传的Samba文件",
                    _smbclient_command(
                        host, share, username, f"get {remote_name} {download_path}"
                    ),
                    f"下载成功并生成 {download_path}",
                    interactive=True,
                    interactive_hint="输入该测试用户的正确密码",
                    effect="写入测试客户端下载文件",
                )
                _add_client(
                    bv, out, "4. 比较上传前后文件SHA256",
                    f"sha256sum {_double_quote(source_path)} {_double_quote(download_path)}",
                    "两行SHA256完全相同",
                )
                _add_client(
                    bv, out, "5. 删除远端Samba人工复验文件",
                    _smbclient_command(host, share, username, f"del {remote_name}"),
                    "删除成功，远端共享中不再存在该文件",
                    interactive=True,
                    interactive_hint="输入该测试用户的正确密码",
                    effect="删除远端测试文件",
                )
            else:
                _add_client(
                    bv, out, "3. 确认只读写入未留下远端文件",
                    _smbclient_command(host, share, username, f"ls {remote_name}"),
                    "不显示目标文件；若显示文件名，说明只读限制失效",
                    interactive=True,
                    interactive_hint="输入只读测试用户的正确密码",
                )
            _add_client(
                bv, out, "清理Samba客户端人工复验文件",
                f"rm -f {_double_quote(source_path)} {_double_quote(download_path)}",
                "两个固定/tmp文件均被删除",
                effect="删除测试客户端临时文件",
            )

    elif name == "verify_snmp_singleton_contract":
        actual = _snmp_result_actual(result, params)
        _add_router(
            bv,
            out,
            "查看SNMP单例表结构",
            f"sqlite3 {DB_PATH} '.schema snmp_conf'",
            "显示snmp_conf建表语句及实机全部字段",
            actual=actual,
        )
        _add_sql(
            bv,
            out,
            "确认SNMP配置表只有单例记录",
            "SELECT count(*) AS row_count FROM snmp_conf",
            "row_count=1",
            actual=actual,
        )
        _add_router(
            bv,
            out,
            "查看SNMP页面接口show/save注册证据",
            "grep -nF 'url=advanced-service/snmpd-config' /usr/ikuai/script/netsnmp.sh",
            "注册行包含get=data和put=save，不含add、del、IMPORT或EXPORT",
            actual=actual,
        )
    elif name == "verify_snmp_v1_not_supported":
        actual = _snmp_result_actual(result, params)
        _add_router(
            bv,
            out,
            "确认SNMP保存校验仅接受V2C和V3",
            "grep -nF 'version' /usr/ikuai/script/netsnmp.sh",
            "__check_param片段仅允许version=2或3，页面下拉同时无V1",
            actual=actual,
        )
    elif name in {"start_snmp_udp_port_guard", "stop_snmp_udp_port_guard"}:
        actual = _snmp_result_actual(result, params)
        port = _snmp_port_from(params, result)
        expect_present = name == "start_snmp_udp_port_guard"
        _add_router(
            bv,
            out,
            f"查看UDP/{port}占用控制监听",
            f"netstat -lnup 2>/dev/null | grep -E {_double_quote(':' + str(port) + '[[:space:]]')}",
            "占用场景中显示非snmpd属主的UDP监听" if expect_present else
            "精确清理后无输出",
            actual=actual,
            valid_when="端口占用异常场景执行时",
        )
    elif name == "verify_snmp_database":
        actual = _snmp_result_actual(result, params)
        _snmp_add_database(bv, out, actual)
    elif name == "verify_snmp_generated_config":
        actual = _snmp_result_actual(result, params)
        expected_fields = params.get("expected_fields")
        enabled = None
        if isinstance(expected_fields, dict) and "enabled" in expected_fields:
            enabled = str(expected_fields.get("enabled")).strip().lower() in {
                "1", "yes", "true", "on", "enable", "enabled",
            }
        expect_present = params.get("expect_present")
        if expect_present is None:
            expect_present = True if enabled is None else enabled
        _snmp_add_generated_config(
            bv, out, actual, expect_present=bool(expect_present)
        )
    elif name == "verify_snmp_processes":
        actual = _snmp_result_actual(result, params)
        expect_running = bool(params.get("expect_running", True))
        _snmp_add_processes(bv, out, actual, expect_running=expect_running)
    elif name == "verify_snmp_listener":
        actual = _snmp_result_actual(result, params)
        port = _snmp_port_from(params, result)
        _snmp_add_listener(
            bv, out, port, actual,
            expect_listening=bool(params.get("expect_listening", True)),
        )
    elif name == "verify_snmp_firewall":
        actual = _snmp_result_actual(result, params)
        port = _snmp_port_from(params, result)
        _snmp_add_firewall(
            bv, out, port, actual,
            expect_excluded=bool(params.get("expect_excluded", True)),
        )
    elif name in {
        "verify_snmp_runtime_consistency",
        "verify_snmp_reinit",
    }:
        _snmp_common_runtime(bv, out, params, result)
    elif name == "verify_snmp_environment_unchanged":
        actual = _snmp_result_actual(result, params)
        # The snapshot may contain credentials; only use its integer port hint.
        port = _snmp_port_from(params, result)
        snapshot = params.get("snapshot")
        baseline_enabled = True
        if isinstance(snapshot, dict):
            db_snapshot = (
                snapshot.get("row") or snapshot.get("database") or
                snapshot.get("db") or snapshot
            )
            if isinstance(db_snapshot, dict) and "enabled" in db_snapshot:
                baseline_enabled = str(db_snapshot.get("enabled")).strip().lower() in {
                    "1", "yes", "true", "on", "enable", "enabled",
                }
        config_present = baseline_enabled
        process_running = baseline_enabled
        listener_present = baseline_enabled
        upnp_excluded = baseline_enabled
        if isinstance(snapshot, dict):
            config_snapshot = snapshot.get("config")
            if isinstance(config_snapshot, dict) and "exists" in config_snapshot:
                config_present = bool(config_snapshot.get("exists"))
            process_snapshot = snapshot.get("process") or snapshot.get("processes")
            if isinstance(process_snapshot, dict):
                if "main_pid_matches" in process_snapshot:
                    process_running = bool(process_snapshot.get("main_pid_matches"))
                elif "main_pid" in process_snapshot:
                    process_running = bool(process_snapshot.get("main_pid"))
            listener_snapshot = snapshot.get("listeners")
            if isinstance(listener_snapshot, dict):
                listener_item = listener_snapshot.get(str(port)) or {}
                if isinstance(listener_item, dict):
                    listener_present = bool(
                        listener_item.get("ipv4") or listener_item.get("ipv6")
                    )
            firewall_snapshot = snapshot.get("firewall")
            if isinstance(firewall_snapshot, dict):
                firewall_item = firewall_snapshot.get(str(port)) or {}
                if isinstance(firewall_item, dict) and "upnp_excluded" in firewall_item:
                    upnp_excluded = bool(firewall_item.get("upnp_excluded"))
        _snmp_add_database(bv, out, actual, valid_when="测试结束后仍有效")
        _snmp_add_generated_config(
            bv, out, actual, expect_present=config_present,
            valid_when="测试结束后仍有效"
        )
        _snmp_add_processes(
            bv, out, actual, expect_running=process_running,
            valid_when="测试结束后仍有效"
        )
        _snmp_add_listener(
            bv, out, port, actual, expect_listening=listener_present,
            valid_when="测试结束后仍有效",
        )
        _snmp_add_firewall(
            bv, out, port, actual, expect_excluded=upnp_excluded,
            valid_when="测试结束后仍有效",
        )
    elif name == "verify_snmp_test_artifacts_absent":
        actual = _snmp_result_actual(result, params)
        prefix = str(params.get("prefix") or "")
        valid_when = "测试结束后仍有效"
        if prefix:
            length = len(prefix)
            literal = _sql_literal(prefix)
            where = (
                f"substr(COALESCE(sysname,''),1,{length})={literal} OR "
                f"substr(COALESCE(syslocation,''),1,{length})={literal} OR "
                f"substr(COALESCE(syscontact,''),1,{length})={literal} OR "
                f"substr(COALESCE(source,''),1,{length})={literal} OR "
                f"substr(COALESCE(username,''),1,{length})={literal}"
            )
            _add_sql(
                bv, out, "确认SNMP测试前缀未残留（秘密字段仅计数）",
                f"SELECT count(*) AS cnt FROM snmp_conf WHERE {where}",
                "cnt=0",
                actual=actual,
                valid_when=valid_when,
            )
            sanitized = _snmp_sanitized_config_command()
            _add_router(
                bv, out, "确认SNMP生成配置不含测试前缀（敏感行已遮蔽）",
                f"{sanitized} | grep -nF {_double_quote(prefix)}",
                "无输出",
                actual=actual,
                valid_when=valid_when,
            )
        ports = set()
        for item in params.get("candidate_ports") or []:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                ports.add(port)
        for raw_port in sorted(ports):
            _snmp_add_listener(
                bv, out, raw_port, actual, expect_listening=False,
                valid_when=valid_when,
            )
        _add_client(
            bv, out, "确认SNMP客户端没有临时凭据或探测文件",
            "find /tmp -maxdepth 1 -type f -name 'ikuai-snmp-verify.*' -print",
            "无输出；助手不应把凭据或协议响应落盘",
            actual=actual,
            valid_when=valid_when,
        )
    elif name == "verify_snmp_client_route":
        actual = _snmp_result_actual(result, params)
        route_host = _snmp_route_host(params.get("host"))
        expected_iface = str(params.get("expected_iface") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", expected_iface):
            raise ValueError("人工SNMP路由复验必须提供安全的expected_iface")
        _add_client(
            bv,
            out,
            f"确认SNMP目标{route_host}使用客户端接口{expected_iface}",
            f"ip route get {route_host}",
            f"输出包含dev {expected_iface}和有效src地址",
            actual=actual,
        )
    elif name == "run_snmp_probe":
        actual = _snmp_result_actual(result, params)
        host = str(params.get("host") or "")
        if not host:
            raise ValueError("人工SNMP复验必须提供host")
        route_host = _snmp_route_host(host)
        route_iface = _snmp_route_iface(route_host)
        _add_client(
            bv,
            out,
            f"确认SNMP流量使用测试线路{route_iface}",
            f"ip route get {route_host}",
            f"输出包含dev {route_iface}和有效src地址；目标为{route_host}",
            actual=actual,
        )
        _add_client(
            bv,
            out,
            "确认SNMP安全助手权限",
            f"stat -c '%U:%G %a %n' {SNMP_VERIFY_ENTRY}",
            "输出root:root 755；助手可执行且不会把凭据写入固定文件",
            actual=actual,
        )
        command = _snmp_probe_command(params)
        operation = str(params.get("operation") or "get").strip().lower()
        expect_success = bool(params.get("expect_success", True))
        version = str(params.get("version") or "v2c").strip().upper()
        _add_client(
            bv,
            out,
            f"执行真实SNMP{version} {operation}协议复验（秘密由助手安全读取）",
            command,
            ("命令成功并返回目标OID和值；协议版本、OID和值与步骤期望一致"
             if expect_success else
             "命令应失败并返回认证拒绝、无权限、停用或不可达；不得返回有效OID值"),
            actual=actual,
            interactive=True,
            effect="创建并清理客户端0600临时配置；SNMP协议只读查询",
            interactive_hint=(
                "助手从权限受控配置/终端安全读取community或认证、隐私口令；" +
                ("本条按步骤输入错误凭据" if not expect_success else
                 "按提示输入本步骤授权凭据")
            ),
        )
        _add_client(
            bv,
            out,
            "确认SNMP安全助手临时文件已清理",
            "find /tmp -maxdepth 1 -name 'ikuai-snmp-verify.*' -print",
            "无输出",
            actual=actual,
            valid_when="本条协议命令完成后",
        )

    elif name.startswith("verify_vlan_"):
        actual = _basic_result_actual(result, params)

        def safe_iface(value, label):
            raw = str(value or "").strip()
            safe = _safe_probe_component(raw, "invalid")
            if not raw or safe != raw:
                raise ValueError(f"人工VLAN复验必须提供安全的{label}")
            return safe

        if name in {"verify_vlan_database", "verify_vlan_database_absent"}:
            vlan_name = safe_iface(params.get("vlan_name"), "VLAN名称")
            expected = (
                "返回JSON，目标VLAN不存在"
                if name.endswith("_absent") else
                "返回JSON，目标VLAN存在且全部期望字段与页面一致"
            )
            _add_router(
                bv, out, f"查看VLAN {vlan_name} 的数据库配置",
                '/usr/ikuai/function/vlan show "limit=0,500" "TYPE=total,data"',
                expected, actual=actual,
            )
        elif name in {"verify_vlan_interface", "verify_vlan_interface_absent"}:
            vlan_name = safe_iface(params.get("vlan_name"), "VLAN名称")
            absent = name.endswith("_absent")
            expected_state = str(params.get("expected_state") or "UP").upper()
            for iface in (f"_{vlan_name}", vlan_name):
                _add_router(
                    bv, out, f"查看VLAN接口 {iface}",
                    f"ip -d link show dev {iface}",
                    ("命令提示接口不存在" if absent else
                     f"实际使用的候选接口存在，flags/state明确为{expected_state}，父接口及同名bridge状态正确"),
                    actual=actual,
                )
        elif name in {"verify_vlan_proc", "verify_vlan_proc_absent"}:
            vlan_name = safe_iface(params.get("vlan_name"), "VLAN名称")
            _add_router(
                bv, out, f"查看内核802.1Q映射中的 {vlan_name}",
                "cat /proc/net/vlan/config",
                (f"首列无精确名称_{vlan_name}或{vlan_name}" if name.endswith("_absent") else
                 "首列精确名称、VLAN ID和父接口均与页面一致"),
                actual=actual,
            )
        elif name == "verify_client_vlan_subinterface":
            iface = safe_iface(params.get("iface"), "客户端接口名")
            _add_client(
                bv, out, f"查看客户端VLAN接口 {iface}",
                f"ip -d -o link show dev {iface}",
                "接口UP，父接口和VLAN ID与本步骤一致", actual=actual,
            )
            _add_client(
                bv, out, f"查看客户端VLAN接口 {iface} 的IPv4地址",
                f"ip -o -4 addr show dev {iface}",
                "地址和掩码与本步骤一致", actual=actual,
            )

    elif name == "verify_http_rule_database":
        tagname, rule_id = params.get("tagname"), params.get("rule_id")
        _add_sql(bv, out, "查看HTTP服务规则", _http_rule_sql(tagname, rule_id),
                 "存在场景返回1行且字段正确；删除场景无输出")
    elif name == "verify_http_rule_count":
        prefix = params.get("prefix")
        sql = "SELECT count(*) AS cnt FROM http_server"
        if prefix is not None:
            sql += " WHERE " + _prefix_predicate(str(prefix), ("tagname",))
        _add_sql(bv, out, "统计HTTP服务规则", sql, "cnt等于报告中的期望数量")
    elif name == "verify_http_openresty_config":
        _add_router(bv, out, "查看openresty静态文件服务配置",
                    "sed -n '1,360p' /usr/openresty/conf/static_file.conf",
                    "目标#sql_id配置块的端口、域名、协议、目录、浏览和限速指令正确")
    elif name == "verify_http_process":
        _add_router(bv, out, "查看openresty进程", "pidof openresty", "返回openresty PID")
        _add_router(bv, out, "查看nginx进程", "pidof nginx", "返回nginx master/worker PID")
    elif name == "verify_http_listener":
        port = int(params.get("port"))
        _add_router(bv, out, f"查看TCP/{port}监听",
                    f"netstat -lntp 2>/dev/null | grep -E {_double_quote(':' + str(port) + '[[:space:]]')}",
                    "启用时显示目标端口且归属nginx/openresty；停用/删除时无输出")
    elif name == "verify_http_firewall":
        port = int(params.get("port"))
        _add_router(bv, out, f"查看TCP/{port} WAN阻断成员",
                    f"ipset list DROP_T_PORTS_WAN_IN 2>/dev/null | grep -x '{port}'",
                    "禁止外网时显示该端口；允许外网或规则未启用时无输出")
    elif name in {"verify_http_runtime_consistency", "verify_http_reinit"}:
        prefix = params.get("prefix")
        ports = params.get("candidate_ports") or []
        _http_common_runtime(bv, out, str(prefix) if prefix else None, ports)
    elif name == "verify_http_test_artifacts_absent":
        prefix = str(params.get("prefix", ""))
        predicate = _prefix_predicate(prefix, ("tagname",))
        _add_sql(bv, out, "确认HTTP测试规则已清空",
                 f"SELECT count(*) AS cnt FROM http_server WHERE {predicate}", "cnt=0",
                 valid_when="测试结束后仍有效")
        _add_router(bv, out, "确认openresty配置不含测试前缀",
                    f"grep -nF {_double_quote(prefix)} /usr/openresty/conf/static_file.conf", "无输出",
                    valid_when="测试结束后仍有效")
        ports = params.get("candidate_ports") or []
        for port in sorted({int(item) for item in ports}):
            _add_router(bv, out, f"确认TCP/{port}无测试监听",
                        f"netstat -lntp 2>/dev/null | grep -E {_double_quote(':' + str(port) + '[[:space:]]')}",
                        "无输出", valid_when="测试结束后仍有效")
        _add_client(bv, out, "确认HTTP客户端临时文件已清理",
                    "find /tmp -maxdepth 1 -name 'http_probe_*' -print", "无输出",
                    valid_when="测试结束后仍有效")
    elif name == "verify_http_non_test_rules_unchanged":
        prefix = str(params.get("prefix", ""))
        predicate = _prefix_predicate(prefix, ("tagname",))
        _add_sql(bv, out, "查看非测试HTTP规则",
                 "SELECT id,enabled,tagname,http_port,server_name,ssl_on,autoindex,download,home_dir,access "
                 f"FROM http_server WHERE NOT ({predicate}) ORDER BY id",
                 "应与测试前快照一致")
    elif name == "run_http_probe":
        operation = str(params.get("operation") or "fetch").strip().lower()
        host = str(params.get("host") or "192.168.148.1")
        iface = str(params.get("iface") or "ens11")
        _add_client_route(bv, out, host, iface, "HTTP")
        base, url = _curl_base(params)
        status_command = " ".join(base + [
            "--output", "/dev/null", "--write-out",
            _double_quote("HTTP %{http_code} bytes=%{size_download} speed=%{speed_download} time=%{time_total}\\n"),
            _double_quote(url),
        ])
        _add_client(
            bv, out,
            ("验证目标HTTP地址连接失败" if operation == "connect_fail" else
             "复验HTTP状态、字节数、速率和耗时"),
            status_command,
            ("连接超时/拒绝，curl返回非0且HTTP状态通常为000" if operation == "connect_fail" else
             "状态码和传输指标与本步骤期望一致"),
        )
        if params.get("expected_sha256") and operation != "connect_fail":
            sha_command = " ".join(base + [_double_quote(url), "|", "sha256sum"])
            _add_client(bv, out, "复验HTTP响应体SHA256", sha_command,
                        f"SHA256={params.get('expected_sha256')}")
        if operation == "autoindex":
            list_command = " ".join(base + [_double_quote(url), "|", "sed", "-n", "'1,40p'"])
            _add_client(bv, out, "查看目录浏览响应", list_command,
                        "响应包含报告列出的目标文件名")
        if params.get("control_port"):
            control_host = str(params.get("control_host") or host)
            control_iface = str(params.get("control_iface") or "ens11")
            _add_client_route(
                bv, out, control_host, control_iface, "HTTP控制组"
            )
            control_base, control_url = _curl_base(params, control=True)
            control_command = " ".join(control_base + [
                "--output", "/dev/null", "--write-out",
                _double_quote("HTTP %{http_code} speed=%{speed_download} time=%{time_total}\\n"),
                _double_quote(control_url),
            ])
            _add_client(
                bv, out,
                ("从内网控制地址确认HTTP仍可用" if operation == "connect_fail" else
                 "复验无限速控制组"),
                control_command,
                ("控制组返回预期HTTP状态，证明目标失败来自外网访问策略" if operation == "connect_fail" else
                 "控制组速度显著高于限速规则"),
            )

    # Migrated functions are handled even when the safest representation is an
    # empty list (for example a mutating restore/cleanup/prepare helper).
    return _deduplicate(out)


__all__ = ["build_verification_commands"]
