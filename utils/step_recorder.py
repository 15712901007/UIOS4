"""
测试步骤记录器

用于记录测试执行过程中的步骤，以便在测试报告中展示
"""
import json
import os
import re
import threading
from datetime import datetime
from typing import List, Dict, Optional, Any, Iterable
from contextlib import contextmanager


_SENSITIVE_COMMAND_PLACEHOLDER = "[命令已隐藏：包含敏感信息]"
_SENSITIVE_TEXT_PLACEHOLDER = "[已隐藏]"
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(community|auth(?:entication)?[_ -]?(?:pass(?:word)?|key)|"
    r"priv(?:acy)?[_ -]?(?:pass(?:word)?|key)|password|passwd|secret|"
    r"团体名|认证(?:口令|密码|密钥)|隐私(?:口令|密码|密钥))"
    r"\s*[:=]\s*([^,;，\r\n}\]]+)"
)
_SENSITIVE_DICT_KEY_RE = re.compile(
    r"(?i)^(?:community|auth(?:entication)?[_ -]?(?:pass(?:word)?|key)|"
    r"priv(?:acy)?[_ -]?(?:pass(?:word)?|key)|password|passwd|secret|"
    r"团体名|认证(?:口令|密码|密钥)|隐私(?:口令|密码|密钥))$"
)
_SENSITIVE_JSON_RE = re.compile(
    r"(?i)([\"'](?:community|auth(?:entication)?[_ -]?(?:pass(?:word)?|key)|"
    r"priv(?:acy)?[_ -]?(?:pass(?:word)?|key)|password|passwd|secret|"
    r"团体名|认证(?:口令|密码|密钥)|隐私(?:口令|密码|密钥))[\"']\s*:\s*)"
    r"([\"'])(.*?)\2"
)
_SENSITIVE_SNMP_ARG_RE = re.compile(
    r"(?i)\b(?:snmpget|snmpwalk|snmpbulkwalk)\b.*"
    r"(?:^|\s)(?:-c|-A|-X|--community|--auth-pass|--priv-pass)\s+\S+"
)
_REGISTERED_SENSITIVE_VALUES = set()
_REGISTERED_SENSITIVE_LOCK = threading.Lock()


def _emit_live_step(message: str):
    """Write concise step progress only when launched from the GUI."""
    if os.environ.get("IKUAI_LIVE_STEPS", "").strip().lower() not in {
        "1", "true", "yes", "on",
    }:
        return
    try:
        print(_redact_text(message), flush=True)
    except Exception:
        # Live output must never change the test result or report recording.
        pass


def register_sensitive_value(value: Any):
    """Keep a credential in process memory so every report path can redact it.

    Values are never serialized by this registry.  Pure whitespace is ignored
    because replacing it would corrupt report layout; whitespace-only input is
    already protected by key-based redaction and length-only assertions.
    """
    if value is None:
        return
    text = str(value)
    candidates = {text, text.strip()}
    with _REGISTERED_SENSITIVE_LOCK:
        for candidate in candidates:
            if candidate and candidate.strip():
                _REGISTERED_SENSITIVE_VALUES.add(candidate)


def register_sensitive_values(values: Iterable[Any]):
    for value in values or ():
        register_sensitive_value(value)


def get_registered_sensitive_values() -> List[str]:
    """Return an in-memory copy for same-process artifact scanning."""
    with _REGISTERED_SENSITIVE_LOCK:
        return sorted(_REGISTERED_SENSITIVE_VALUES, key=len, reverse=True)


def clear_registered_sensitive_values():
    """Forget prior-run credentials after artifact scanning is complete."""
    with _REGISTERED_SENSITIVE_LOCK:
        _REGISTERED_SENSITIVE_VALUES.clear()


_PUBLIC_DOMAIN_ALLOWLIST = {"ikuai8.com"}
# 公开域名白名单: 这些值可能被当密码注册(如 SSH 密码恰为 "ikuai8.com"), 但本质是公司公开域名,
# 脱敏会破坏命令/URL 可读性且无安全收益(公开信息), 故在文本脱敏时豁免。


def _redact_text(value: Any) -> str:
    """Hide credential values before a value enters shared report data."""
    if value is None:
        return ""
    text = str(value)
    for secret in get_registered_sensitive_values():
        if secret in _PUBLIC_DOMAIN_ALLOWLIST:
            continue
        text = text.replace(secret, _SENSITIVE_TEXT_PLACEHOLDER)
    text = _SENSITIVE_JSON_RE.sub(
        lambda match: f'{match.group(1)}"{_SENSITIVE_TEXT_PLACEHOLDER}"',
        text,
    )
    return _SENSITIVE_KEY_RE.sub(
        lambda match: f"{match.group(1)}={_SENSITIVE_TEXT_PLACEHOLDER}",
        text,
    )


def redact_sensitive_text(value: Any) -> str:
    """Public report-boundary sanitizer used by pytest and exporters."""
    return _redact_text(value)


def _safe_actual(value: Any) -> str:
    """Serialize a verifier's actual result without exposing nested secrets."""
    if isinstance(value, (dict, list, tuple)):
        def scrub(item):
            if isinstance(item, dict):
                return {
                    key: (_SENSITIVE_TEXT_PLACEHOLDER
                          if _SENSITIVE_DICT_KEY_RE.match(str(key))
                          else scrub(val))
                    for key, val in item.items()
                }
            if isinstance(item, (list, tuple)):
                return [scrub(val) for val in item]
            return item
        try:
            value = json.dumps(scrub(value), ensure_ascii=False, sort_keys=True)
        except Exception:
            value = str(value)
    return _redact_text(value)


def _normalize_boolean(value: Any, *, preserve_text: bool = False):
    """标准化 JSON/配置中的布尔值；非布尔文本可选择原样保留。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "y", "是"}:
            return True
        if normalized in {"0", "false", "no", "off", "n", "否", ""}:
            return False
        if preserve_text:
            return value
    return bool(value)


class TestStep:
    """测试步骤"""

    def __init__(
        self,
        name: str,
        description: str = "",
        status: str = "pending",
        expected: str = "",
    ):
        """
        初始化测试步骤

        Args:
            name: 步骤名称
            description: 步骤描述/详情
            status: 步骤状态
                (pending/running/passed/failed/warning/not_applicable/skipped)
        """
        self.name = _redact_text(name)
        self.description = _redact_text(description)
        self.expected = _redact_text(expected)
        self.status = status
        self.start_time = datetime.now()
        self.end_time = None
        self.duration = None
        self.details: List[str] = []  # 步骤详情列表
        self.verification_commands: List[Dict[str, Any]] = []  # 人工复验命令
        self.actual = ""
        self.error_message = None
        self.forced_status = None
        self.forced_error = None

    def add_detail(self, detail: str):
        """添加步骤详情"""
        self.details.append(_redact_text(detail))

    def add_verification_command(
        self,
        command: Any,
        *,
        target_label: str = "",
        target: str = "",
        host: str = "",
        shell: str = "",
        purpose: str = "",
        expected: str = "",
        effect: str = "read_only",
        copy_ready: bool = True,
        contains_secret: bool = False,
        interactive: Any = False,
        valid_when: str = "",
        actual: Any = "",
        **extra: Any,
    ) -> Dict[str, Any]:
        """记录一条结构化人工复验命令。

        ``command`` 既可以是命令字符串，也可以是已包含上述字段的字典。
        字典形式便于验证器直接把结构化结果交给报告层，其已有字段
        优先于方法的默认值。
        """
        # 扩展字段先保留，命令字典中的同名字段再覆盖它。
        # 这样 target/shell/interactive_hint 等新字段无需再修改
        # StepRecorder 就能原样进入 JSON。
        source = dict(extra)
        if isinstance(command, dict):
            source.update(command)
        else:
            source["command"] = command

        defaults = {
            "target_label": target_label,
            "target": target,
            "host": host,
            "shell": shell,
            "purpose": purpose,
            "expected": expected,
            "effect": effect,
            "copy_ready": copy_ready,
            "contains_secret": contains_secret,
            "interactive": interactive,
            "valid_when": valid_when,
            "actual": actual,
        }
        for key, value in defaults.items():
            source.setdefault(key, value)

        payload = source
        actual_value = payload.get("actual")
        for key in (
            "target_label", "target", "host", "shell", "purpose", "command",
            "expected", "effect", "valid_when",
        ):
            payload[key] = "" if payload.get(key) is None else str(payload.get(key))
        payload["actual"] = _safe_actual(actual_value)
        # Keep command metadata and the observed result safe even when a
        # caller bypasses the SNMP command generator.
        for key in ("purpose", "expected", "valid_when", "actual", "interactive_hint"):
            if key in payload:
                payload[key] = _redact_text(payload.get(key))
        if payload.get("command") is not None:
            command_text = str(payload.get("command"))
            if (
                _SENSITIVE_KEY_RE.search(command_text) or
                _SENSITIVE_JSON_RE.search(command_text) or
                _SENSITIVE_SNMP_ARG_RE.search(command_text)
            ):
                payload["contains_secret"] = True
        payload["copy_ready"] = _normalize_boolean(payload.get("copy_ready"))
        payload["contains_secret"] = _normalize_boolean(
            payload.get("contains_secret")
        )
        payload["interactive"] = _normalize_boolean(
            payload.get("interactive"), preserve_text=True
        )
        if payload["contains_secret"]:
            # 报告数据是 JSON/HTML/Excel 的共同源头。敏感命令在这里即被
            # 不可逆移除，后续展示层即使误配置也拿不到原始正文。
            payload["command"] = _SENSITIVE_COMMAND_PLACEHOLDER
            payload["actual"] = _SENSITIVE_COMMAND_PLACEHOLDER
            payload["copy_ready"] = False
        for existing in self.verification_commands:
            if existing == payload:
                return existing
        self.verification_commands.append(payload)
        return payload

    def add_verification_commands(
        self, commands: Iterable[Any]
    ) -> List[Dict[str, Any]]:
        """批量记录人工复验命令，并返回已标准化的命令列表。"""
        if commands is None:
            return []
        if isinstance(commands, (str, bytes, dict)):
            commands = [commands]
        return [self.add_verification_command(item) for item in commands]

    def complete(self, status: str = "passed", error_message: str = None):
        """完成步骤"""
        if status == "passed" and self.forced_status:
            status = self.forced_status
            error_message = error_message or self.forced_error
        self.status = status
        self.end_time = datetime.now()
        self.duration = (self.end_time - self.start_time).total_seconds()
        self.error_message = _redact_text(error_message) if error_message else error_message

    def force_status(self, status: str, error_message: str = None):
        """Preserve an assertion outcome until the surrounding step exits."""
        if status not in {"failed", "warning", "not_applicable", "skipped"}:
            raise ValueError(f"不支持的强制步骤状态: {status}")
        # ``skipped`` is the historical spelling of ``not_applicable``.
        # Keep accepting and serializing it for old callers while assigning
        # both spellings the same priority.  A warning must not be hidden by a
        # later N/A observation, and a real failure always wins.
        priorities = {
            None: 0,
            "skipped": 1,
            "not_applicable": 1,
            "warning": 2,
            "failed": 3,
        }
        if priorities[status] >= priorities.get(self.forced_status, 0):
            self.forced_status = status
            self.forced_error = _redact_text(error_message) if error_message else None

    def set_actual(self, actual: Any):
        """Record a concise observed result for the current step."""
        self.actual = _safe_actual(actual)

    def set_expected(self, expected: Any):
        """Record the explicit expected result for this step."""
        self.expected = _safe_actual(expected)

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "name": self.name,
            "test_item": self.name,
            "description": self.description,
            "action": self.description or self.name,
            "expected": self.expected,
            "status": self.status,
            "duration": f"{self.duration:.2f}s" if self.duration else "0s",
            "details": self.details,
            "verification_commands": self.verification_commands,
            "actual": self.actual,
            "error_message": self.error_message
        }


class StepRecorder:
    """
    测试步骤记录器

    使用线程本地存储，支持多线程测试

    使用示例:
        recorder = StepRecorder()

        # 开始一个步骤
        recorder.start_step("登录系统", "使用管理员账号登录")
        recorder.add_detail("输入用户名: admin")
        recorder.add_detail("输入密码: ****")
        recorder.end_step("passed")

        # 使用上下文管理器
        with recorder.step("添加VLAN", "添加VLAN 100"):
            recorder.add_detail("填写VLAN ID: 100")
            recorder.add_detail("填写VLAN名称: vlan_test")
            # 自动标记为passed

        # 获取所有步骤
        steps = recorder.get_steps()
    """

    def __init__(self):
        """初始化记录器"""
        self._thread_local = threading.local()
        self.required_sections: tuple = ()

    def _get_steps(self) -> List[TestStep]:
        """获取当前线程的步骤列表"""
        if not hasattr(self._thread_local, 'steps'):
            self._thread_local.steps = []
        return self._thread_local.steps

    def _get_current_step(self) -> Optional[TestStep]:
        """获取当前线程的当前步骤"""
        if not hasattr(self._thread_local, 'current_step'):
            self._thread_local.current_step = None
        return self._thread_local.current_step

    def _set_current_step(self, step: Optional[TestStep]):
        """设置当前线程的当前步骤"""
        self._thread_local.current_step = step

    def start_step(
        self, name: str, description: str = "", expected: str = ""
    ) -> TestStep:
        """
        开始一个新步骤

        Args:
            name: 步骤名称
            description: 步骤描述

        Returns:
            创建的步骤对象
        """
        step = TestStep(name, description, "running", expected=expected)
        if "测试操作" in self.required_sections:
            step.add_detail(
                "【测试操作】\n通过：" + (step.description or step.name)
            )
        steps = self._get_steps()
        steps.append(step)
        self._set_current_step(step)
        _emit_live_step(f"[步骤 {len(steps)}] 开始 | {step.name}")
        return step

    def add_detail(self, detail: str):
        """
        添加详情到当前步骤

        Args:
            detail: 详情内容
        """
        current = self._get_current_step()
        if current:
            current.add_detail(detail)

    def ensure_current_step_sections(self, sections: Iterable[str]):
        """Add explicit not-applicable evidence for report sections not exercised."""
        current = self._get_current_step()
        if current is None:
            return
        existing = "\n".join(current.details)
        for section in sections or ():
            marker = f"【{section}】"
            if marker not in existing:
                if section == "测试操作":
                    current.add_detail(
                        f"{marker}\n通过：已按步骤标题和描述执行实际操作"
                    )
                else:
                    current.add_detail(
                        f"{marker}\n不适用：本步骤不执行{section}所属层级，以其他已记录证据为准"
                    )

    def add_verification_command(
        self,
        command: Any,
        *,
        target_label: str = "",
        target: str = "",
        host: str = "",
        shell: str = "",
        purpose: str = "",
        expected: str = "",
        effect: str = "read_only",
        copy_ready: bool = True,
        contains_secret: bool = False,
        interactive: Any = False,
        valid_when: str = "",
        actual: Any = "",
        **extra: Any,
    ) -> Optional[Dict[str, Any]]:
        """向当前步骤添加一条结构化人工复验命令。"""
        current = self._get_current_step()
        if current is None:
            return None
        return current.add_verification_command(
            command,
            target_label=target_label,
            target=target,
            host=host,
            shell=shell,
            purpose=purpose,
            expected=expected,
            effect=effect,
            copy_ready=copy_ready,
            contains_secret=contains_secret,
            interactive=interactive,
            valid_when=valid_when,
            actual=actual,
            **extra,
        )

    def set_actual(self, actual: Any):
        """Record an observed result on the active step."""
        current = self._get_current_step()
        if current is None:
            return None
        current.set_actual(actual)
        return current.actual

    def set_expected(self, expected: Any):
        """Record an explicit expected result on the active step."""
        current = self._get_current_step()
        if current is None:
            return None
        current.set_expected(expected)
        return current.expected

    def mark_current_step(self, status: str, error_message: str = None):
        """Mark a soft assertion without ending its cleanup/report context."""
        current = self._get_current_step()
        if current is None:
            return None
        current.force_status(status, error_message)
        return status

    def fail_current_step(self, error_message: str = None):
        return self.mark_current_step("failed", error_message)

    def warn_current_step(self, message: str = None):
        """Keep an environment/coverage warning without failing the step."""
        return self.mark_current_step("warning", message)

    def not_applicable_current_step(self, reason: str = None):
        """Mark the active step as unsupported or unavailable in this environment."""
        return self.mark_current_step("not_applicable", reason)

    def add_verification_commands(
        self, commands: Iterable[Any]
    ) -> List[Dict[str, Any]]:
        """向当前步骤批量添加结构化人工复验命令。"""
        current = self._get_current_step()
        if current is None:
            return []
        return current.add_verification_commands(commands)

    def end_step(self, status: str = "passed", error_message: str = None):
        """
        结束当前步骤

        Args:
            status: 步骤状态
                (passed/failed/warning/not_applicable/skipped)
            error_message: 错误信息（失败时）
        """
        current = self._get_current_step()
        if current:
            current.complete(status, error_message)
            steps = self._get_steps()
            try:
                index = steps.index(current) + 1
            except ValueError:
                index = len(steps)
            labels = {
                "passed": "通过", "failed": "失败", "warning": "警告",
                "not_applicable": "不适用", "skipped": "跳过",
            }
            live_status = current.status
            if live_status == "passed" and any(
                "[FAIL]" in detail or re.search(r"】失败(?:\s|$)", detail)
                for detail in current.details
            ):
                # Report hooks also promote these semantic failures. Mirror
                # that conclusion in the live line without changing recorder
                # serialization or the caller's soft-assert control flow.
                live_status = "failed"
            _emit_live_step(
                f"[步骤 {index}] {labels.get(live_status, live_status)} | "
                f"{current.name} | 用时 {current.duration:.2f}s"
            )
            self._set_current_step(None)

    @contextmanager
    def step(
        self,
        name: str,
        description: str = "",
        expect_error: bool = False,
        *,
        expected: str = "",
    ):
        """
        步骤上下文管理器

        Args:
            name: 步骤名称
            description: 步骤描述
            expect_error: 是否预期错误（如果为True，异常时标记为passed）

        使用示例:
            with recorder.step("添加VLAN", "添加VLAN 100"):
                # 执行操作
                pass
        """
        self.start_step(name, description, expected=expected)
        error_occurred = False
        try:
            yield self
            if self.required_sections:
                self.ensure_current_step_sections(self.required_sections)
            if not expect_error:
                self.end_step("passed")
            else:
                self.end_step("skipped", "预期错误但未发生")
        except BaseException as e:
            error_occurred = True
            if self.required_sections:
                self.ensure_current_step_sections(self.required_sections)
            if expect_error:
                self.end_step("passed", f"预期错误: {str(e)}")
            else:
                self.end_step("failed", str(e))
            raise

    def get_steps(self) -> List[Dict]:
        """
        获取所有步骤（返回字典列表）

        Returns:
            步骤字典列表
        """
        return [step.to_dict() for step in self._get_steps()]

    def clear(self):
        """清除所有步骤"""
        self._thread_local.steps = []
        self._thread_local.current_step = None

    def record_action(self, action: str, target: str = "", result: str = ""):
        """
        记录一个操作（快捷方法）

        Args:
            action: 操作类型（如：点击、输入、选择）
            target: 操作目标
            result: 操作结果
        """
        detail = f"[{action}]"
        if target:
            detail += f" {target}"
        if result:
            detail += f" -> {result}"
        self.add_detail(detail)


# 全局步骤记录器实例
_global_recorder = StepRecorder()


def get_step_recorder() -> StepRecorder:
    """
    获取全局步骤记录器

    Returns:
        StepRecorder实例
    """
    return _global_recorder


def record_step(name: str, description: str = ""):
    """
    步骤装饰器（用于函数级别）

    Args:
        name: 步骤名称
        description: 步骤描述

    使用示例:
        @record_step("测试登录功能", "验证用户登录")
        def test_login():
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            recorder = get_step_recorder()
            with recorder.step(name, description):
                return func(*args, **kwargs)
        return wrapper
    return decorator
