"""
测试执行器

在后台线程中执行pytest测试
"""
import os
import sys
import subprocess
import re
import json
import glob
import threading
import queue
import time
import io
from datetime import datetime
from typing import List, Dict, Optional

from PySide6.QtCore import QThread, Signal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.config import Config
from utils.step_recorder import redact_sensitive_text


FTP_TESTCASE = (
    "advanced_service/test_ftp_server_comprehensive.py::"
    "TestFtpServerComprehensive::test_ftp_server_comprehensive"
)
SAMBA_TESTCASE = (
    "advanced_service/test_samba_server_comprehensive.py::"
    "TestSambaServerComprehensive::test_samba_server_comprehensive"
)
HTTP_TESTCASE = (
    "advanced_service/test_http_server_comprehensive.py::"
    "TestHttpServerComprehensive::test_http_server_comprehensive"
)
SNMP_TESTCASE = (
    "advanced_service/test_snmp_server_comprehensive.py::"
    "TestSnmpServerComprehensive::test_snmp_server_comprehensive"
)
BASIC_SETTING_TESTCASE = (
    "device_setting/test_basic_setting_comprehensive.py::"
    "TestBasicSettingComprehensive::test_basic_setting_comprehensive"
)
ALG_SETTING_TESTCASE = (
    "device_setting/test_alg_setting_comprehensive.py::"
    "TestAlgSettingComprehensive::test_alg_setting_comprehensive"
)
PROTOCOL_CONTROL_TESTCASE = (
    "device_setting/test_protocol_control_comprehensive.py::"
    "TestProtocolControlComprehensive::test_protocol_control_comprehensive"
)
OSPF_TESTCASE = (
    "network/test_ospf_comprehensive.py::"
    "TestOspfComprehensive::test_ospf_comprehensive"
)
IPSEC_TESTCASE = (
    "network/test_ipsec_vpn_comprehensive.py::"
    "TestIpsecVpnComprehensive::test_ipsec_vpn_comprehensive"
)
PACKAGED_FTP_COLLECT_FLAG = "--collect-ftp-smoke"
PACKAGED_SAMBA_COLLECT_FLAG = "--collect-samba-smoke"
PACKAGED_HTTP_COLLECT_FLAG = "--collect-http-smoke"
PACKAGED_SNMP_COLLECT_FLAG = "--collect-snmp-smoke"
PACKAGED_BASIC_SETTING_COLLECT_FLAG = "--collect-basic-setting-smoke"
PACKAGED_ALG_SETTING_COLLECT_FLAG = "--collect-alg-setting-smoke"
PACKAGED_PROTOCOL_CONTROL_COLLECT_FLAG = "--collect-protocol-control-smoke"
PACKAGED_OSPF_COLLECT_FLAG = "--collect-ospf-smoke"
PACKAGED_IPSEC_COLLECT_FLAG = "--collect-ipsec-smoke"


def get_bundle_root() -> str:
    """Return the read-only resource root used by tests and templates."""
    if is_frozen():
        return os.path.abspath(sys._MEIPASS)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_runtime_root() -> str:
    """Return a persistent, writable root for reports and screenshots."""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return get_bundle_root()


def _resolve_runtime_path(path: str) -> str:
    if os.path.isabs(path):
        return os.path.abspath(path)
    return os.path.abspath(os.path.join(get_runtime_root(), path))


def redact_user_paths(value) -> str:
    """Hide local paths and credential-shaped values from public metadata."""
    text = redact_sensitive_text(value)
    roots = []
    for label, getter in (
        ("[包目录]", get_bundle_root),
        ("[运行目录]", get_runtime_root),
    ):
        try:
            root = os.path.abspath(getter())
        except (AttributeError, OSError):
            continue
        if root:
            roots.append((root, label))

    try:
        home = os.path.abspath(os.path.expanduser("~"))
    except (AttributeError, OSError):
        home = ""
    if home:
        roots.append((home, "[用户目录]"))

    for root, label in sorted(roots, key=lambda item: len(item[0]), reverse=True):
        variants = {
            root,
            root.replace("\\", "/"),
            root.replace("/", "\\"),
        }
        for variant in sorted(variants, key=len, reverse=True):
            text = re.sub(re.escape(variant), label, text, flags=re.IGNORECASE)

    # Also cover paths supplied by a test/frozen launcher which are outside the
    # current process home directory.
    text = re.sub(
        r"(?i)[a-z]:[\\/]+users[\\/]+[^\\/\s\"'<>]+",
        "[用户目录]",
        text,
    )
    text = re.sub(
        r"(?i)/(?:home|users)/[^/\s\"'<>]+",
        "[用户目录]",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:username|user|login|token|cookie|api[_ -]?key|psk|"
        r"xauth[_ -]?password|eap[_ -]?password|private[_ -]?key)\b"
        r"\s*[:=]\s*)([^,;，\s\r\n}\]]+)",
        r"\1[已隐藏]",
        text,
    )
    text = re.sub(
        r"(?i)([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@\s/]+@",
        r"\1[凭据已隐藏]@",
        text,
    )
    return text


def _summarize_pytest_output(output: str) -> tuple[str, int]:
    """Return a short, path-redacted collect summary for the smoke JSON."""
    lines = [line.strip() for line in redact_user_paths(output).splitlines() if line.strip()]
    keywords = (
        "collected",
        "error",
        "failed",
        "passed",
        "warning",
        "no tests ran",
    )
    summary_lines = [
        line for line in lines if any(keyword in line.lower() for keyword in keywords)
    ]
    if not summary_lines:
        summary_lines = lines[-8:]
    return "\n".join(summary_lines[-20:])[-4000:], len(lines)


def get_python_executable() -> str:
    """获取Python解释器路径

    PyInstaller打包后，sys.executable指向exe文件。
    我们使用 --run-tests 参数来区分运行模式。
    """
    return sys.executable


def is_frozen() -> bool:
    """检查是否在PyInstaller打包环境中运行"""
    return getattr(sys, 'frozen', False)


class RealtimeStdoutCapture:
    """实时stdout捕获器

    用于在GUI线程中直接运行pytest时，捕获输出并实时发送到GUI
    """
    def __init__(self, log_callback, parse_callback=None):
        """
        Args:
            log_callback: 日志回调函数，接收(level, message)参数
            parse_callback: 可选的解析回调函数，接收(line)参数
        """
        self.log_callback = log_callback
        self.parse_callback = parse_callback
        self._original_stdout = None
        self._original_stderr = None
        self._buffer = io.StringIO()
        self._line_buffer = ""
        self._encoding = 'utf-8'
        self._closed = False

    def write(self, text):
        """写入文本并实时回调"""
        if self._closed or not text:
            return 0
        # 同时写入缓冲区
        self._buffer.write(text)
        # pytest can write one logical line in several chunks. Emit complete
        # lines so the GUI does not show fragmented or reordered text.
        self._line_buffer += text
        while "\n" in self._line_buffer:
            line, self._line_buffer = self._line_buffer.split("\n", 1)
            line = line.rstrip("\r")
            if line:
                self.log_callback("INFO", line)
                if self.parse_callback:
                    self.parse_callback(line)
        return len(text)

    def flush(self):
        """刷新缓冲区"""
        if self._line_buffer:
            line = self._line_buffer.rstrip("\r")
            self._line_buffer = ""
            if line:
                self.log_callback("INFO", line)
                if self.parse_callback:
                    self.parse_callback(line)
        if self._original_stdout and not self._original_stdout.closed:
            self._original_stdout.flush()

    def fileno(self):
        """返回文件描述符（兼容性）"""
        if self._original_stdout and not self._original_stdout.closed:
            return self._original_stdout.fileno()
        return 1

    def isatty(self):
        """返回False，因为这不是真正的终端"""
        return False

    def readable(self):
        """不可读"""
        return False

    def writable(self):
        """可写"""
        return True

    def seekable(self):
        """不可seek"""
        return False

    @property
    def encoding(self):
        """返回编码"""
        return self._encoding

    @property
    def closed(self):
        """返回是否已关闭"""
        return self._closed

    def close(self):
        """关闭流"""
        self._closed = True

    def __enter__(self):
        """进入上下文，替换sys.stdout/stderr"""
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文，恢复sys.stdout/stderr"""
        self.flush()
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr
        return False

    def get_output(self):
        """获取所有捕获的输出"""
        return self._buffer.getvalue()


def _read_output_stream(stream, output_queue):
    """线程函数：从输出流读取数据并放入队列"""
    try:
        for line in iter(stream.readline, ''):
            if line:
                output_queue.put(line)
            else:
                break
    except Exception:
        pass
    finally:
        stream.close()


# pytest -v -s 输出: 测试开始时先打印节点行 "tests/...::test_xxx[chromium] ",
# 测试结束后在新行单独打印结果词 PASSED/FAILED/SKIPPED/ERROR.
# 只匹配"整行就是结果词"的行, 避开 traceback 与 short summary 段的 "FAILED tests/...".
_RESULT_WORD_RE = re.compile(r"^\s*(PASSED|FAILED|SKIPPED|ERROR)\s*(?:\[\s*\d+%\])?\s*$")


class TestRunner(QThread):
    """测试执行线程"""

    # 信号定义
    log_signal = Signal(str, str)  # (日志级别, 日志内容)
    progress_signal = Signal(int, int, int, int)  # (总数, 通过, 失败, 跳过)
    finished_signal = Signal(str)  # 报告路径
    error_signal = Signal(str)  # 错误信息

    def __init__(self, testcases: List[str], config: Config):
        """
        初始化测试执行器

        Args:
            testcases: 要执行的测试用例列表
            config: 配置对象
        """
        super().__init__()
        self.testcases = testcases
        self.config = config
        self._is_running = True

        # 统计信息
        self.total = len(testcases)
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        # short test summary info 段已开始的标志(该段会重复列出每个FAILED, 不能再计数)
        self._summary_started = False
        # 运行前JSON快照，防止本次未产出新结果时读到上次报告。
        self._result_json_state_before = {}
        self._last_log_activity = time.monotonic()
        self._heartbeat_stop = threading.Event()

        # 开始时间
        self.start_time = None

    def _emit_log(self, level: str, message) -> None:
        """Emit a GUI-safe log message without local absolute user paths."""
        self._last_log_activity = time.monotonic()
        self.log_signal.emit(level, redact_user_paths(message))

    def _heartbeat_loop(self):
        """Report liveness when a browser/QEMU operation is silent."""
        while not self._heartbeat_stop.wait(5):
            if not self._is_running:
                return
            if time.monotonic() - self._last_log_activity < 15:
                continue
            elapsed = datetime.now() - self.start_time if self.start_time else None
            elapsed_text = str(elapsed).split(".", 1)[0] if elapsed else "--:--:--"
            self._emit_log(
                "INFO", f"测试仍在执行，当前操作尚未返回（已用时 {elapsed_text}）"
            )

    def run(self):
        """执行测试"""
        self.start_time = datetime.now()
        # 重置计数与标志(支持线程复用/重跑)
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self._summary_started = False
        self._emit_log("INFO", f"开始执行 {self.total} 个测试用例...")
        self._heartbeat_stop.clear()
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="test-log-heartbeat", daemon=True
        )
        heartbeat_thread.start()

        # 打包后资源位于 _MEIPASS/_internal，但报告必须写到 exe 旁的持久目录。
        report_dir = _resolve_runtime_path(self.config.report.output_dir)
        if is_frozen():
            # conftest 与 GUI 共享同一个 Config 实例；改成绝对路径可保证报告、
            # JSON、截图及 GUI 的“打开/导出报告”都指向同一个持久目录。
            self.config.report.output_dir = report_dir
            self.config.report.screenshot_dir = _resolve_runtime_path(
                self.config.report.screenshot_dir
            )
        os.makedirs(report_dir, exist_ok=True)
        self._result_json_state_before = self._snapshot_result_json_state(report_dir)

        try:
            # 设置环境变量
            self._setup_env_variables()

            # PyInstaller打包后：直接在当前进程中运行pytest（解决实时日志问题）
            # 源码模式：使用subprocess运行pytest
            if is_frozen():
                self._run_pytest_in_process(report_dir)
            else:
                self._run_pytest_subprocess(report_dir)

        except Exception as e:
            safe_error = redact_user_paths(e)
            self._emit_log("ERROR", f"执行测试时发生错误: {safe_error}")
            self.error_signal.emit(safe_error)
        finally:
            self._heartbeat_stop.set()
            heartbeat_thread.join(timeout=1)

    def _setup_env_variables(self):
        """设置环境变量"""
        env = os.environ
        env["DEVICE_IP"] = self.config.device.ip
        env["DEVICE_USERNAME"] = self.config.device.username
        env["DEVICE_PASSWORD"] = self.config.device.password
        env["HEADLESS"] = "true" if self.config.browser.headless else "false"
        # 传递测试人员和版本信息
        env["TESTER"] = getattr(self.config.report, 'tester', '自动化测试')
        env["TEST_VERSION"] = getattr(self.config.report, 'version', 'v4.0')
        # 传递浏览器分辨率（仅在非自适应模式下使用）
        env["VIEWPORT_WIDTH"] = str(getattr(self.config.browser, 'viewport_width', 1400))
        env["VIEWPORT_HEIGHT"] = str(getattr(self.config.browser, 'viewport_height', 850))
        # 自适应屏幕模式（让浏览器像原生浏览器一样自动适应屏幕大小和DPI缩放）
        auto_adapt = getattr(self.config.browser, 'auto_adapt_screen', True)
        env["AUTO_ADAPT_SCREEN"] = "true" if auto_adapt else "false"
        # SSH配置（供后台验证使用）
        # 同步设备IP到SSH路由器地址（确保SSH验证连接的是同一台设备）
        if hasattr(self.config, 'ssh') and self.config.ssh:
            ssh_router_host = self.config.device.ip or self.config.ssh.router.host
            env["SSH_ROUTER_HOST"] = ssh_router_host
            env["SSH_ROUTER_USERNAME"] = self.config.ssh.router.username or ""
            env["SSH_ROUTER_PASSWORD"] = self.config.ssh.router.password or ""
            env["SSH_ROUTER_PORT"] = str(self.config.ssh.router.port)
            # SSH控制台登录凭据（当控制台密码开启时使用）
            env["SSH_CONSOLE_USERNAME"] = getattr(self.config.ssh.router, 'console_username', '') or ""
            env["SSH_CONSOLE_PASSWORD"] = getattr(self.config.ssh.router, 'console_password', '') or ""
            env["SSH_CLIENT_HOST"] = self.config.ssh.client.host or ""
            env["SSH_CLIENT_USERNAME"] = self.config.ssh.client.username or ""
            env["SSH_CLIENT_PASSWORD"] = self.config.ssh.client.password or ""
            env["SSH_CLIENT_PORT"] = str(self.config.ssh.client.port)
            env["SSH_OSPF_PEER_HOST"] = getattr(self.config.ssh, 'ospf_peer_host', '') or ""
            env["SSH_OSPF_PEER_PORT"] = str(getattr(self.config.ssh, 'ospf_peer_port', 22))
            env["SSH_OSPF_PEER_RECOVERY_HOST"] = getattr(self.config.ssh, 'ospf_peer_recovery_host', '') or ""
            env["SSH_OSPF_PEER_RECOVERY_PORT"] = str(getattr(self.config.ssh, 'ospf_peer_recovery_port', 22))
            env["SSH_ROUTER_RECOVERY_HOST"] = getattr(self.config.ssh, 'router_recovery_host', '') or ""
            env["SSH_ROUTER_RECOVERY_PORT"] = str(getattr(self.config.ssh, 'router_recovery_port', 22))
            env["SSH_ROUTER_LAN_MANAGEMENT_HOST"] = getattr(self.config.ssh, 'router_lan_management_host', '') or ""
            env["SSH_ROUTER_LAN_MANAGEMENT_PORT"] = str(getattr(self.config.ssh, 'router_lan_management_port', 22))
            env["IPERF3_SERVER"] = self.config.ssh.iperf3_server or ""
            env["IPERF3_DURATION"] = str(self.config.ssh.iperf3_duration)
            env["IPERF3_TOLERANCE"] = str(self.config.ssh.iperf3_tolerance)
        # 设置Python输出编码为UTF-8，解决中文乱码问题
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        env["IKUAI_LIVE_STEPS"] = "1"
        if is_frozen():
            # Frozen apps do not have a normal site-packages environment. The
            # project conftest provides the Playwright fixtures itself, so
            # third-party pytest entry-point autoload is both unnecessary and
            # a common source of packaged-only import failures.
            env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    def _run_pytest_in_process(self, report_dir: str):
        """在当前进程中直接运行pytest（打包模式）

        通过直接调用pytest.main()并捕获stdout/stderr来实时显示日志
        """
        import pytest

        # 构建pytest参数
        pytest_args = self._build_pytest_args()

        self._emit_log("INFO", f"直接运行pytest: {' '.join(pytest_args)}")

        # 创建实时stdout捕获器
        def log_callback(level, message):
            self._emit_log(level, message)

        def parse_callback(line):
            self._parse_output(line)

        capture = RealtimeStdoutCapture(log_callback, parse_callback)

        # 保存原始sys.argv
        original_argv = sys.argv.copy()

        try:
            # 设置sys.argv供pytest使用
            sys.argv = ['pytest'] + pytest_args

            # 使用捕获器运行pytest
            with capture:
                exit_code = pytest.main(pytest_args)

            # 测试完成
            if self._is_running:
                self._read_final_stats(report_dir)  # 用conftest权威JSON校正统计(与HTML报告一致)
                duration = datetime.now() - self.start_time
                self._emit_log("INFO", f"测试执行完成，用时: {duration}")
                self._emit_log("INFO", f"总计: {self.total}, 通过: {self.passed}, 失败: {self.failed}, 跳过: {self.skipped}")
                self.finished_signal.emit(report_dir)
            else:
                self.error_signal.emit("测试被用户终止")

        finally:
            # 恢复sys.argv
            sys.argv = original_argv

    def _run_pytest_subprocess(self, report_dir: str):
        """使用subprocess运行pytest（源码模式）"""
        # 构建pytest命令
        pytest_cmd = self._build_pytest_command()

        self._emit_log("INFO", f"执行命令: {' '.join(pytest_cmd)}")

        # 设置工作目录
        work_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 使用PIPE读取输出
        process = subprocess.Popen(
            pytest_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=work_dir,
            env=os.environ.copy(),
            bufsize=0,
        )

        # 使用阻塞readline()在线程中读取
        def read_process_output(stream, log_callback, parse_func):
            try:
                while True:
                    line_bytes = stream.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode('utf-8', errors='replace').rstrip('\n\r')
                    if line:
                        parse_func(line)
                        log_callback("INFO", line)
            except Exception as exc:
                log_callback("WARNING", f"读取pytest输出流失败: {exc}")
            finally:
                stream.close()

        reader_thread = threading.Thread(
            target=read_process_output,
            args=(process.stdout, self._emit_log, self._parse_output),
            daemon=True
        )
        reader_thread.start()

        process.wait()
        reader_thread.join(timeout=10)
        if reader_thread.is_alive():
            self._emit_log("WARNING", "pytest已退出，但输出流10秒内未结束；报告文件仍将完整保存")

        if self._is_running:
            self._read_final_stats(report_dir)  # 用conftest权威JSON校正统计(与HTML报告一致)
            duration = datetime.now() - self.start_time
            self._emit_log("INFO", f"测试执行完成，用时: {duration}")
            self._emit_log("INFO", f"总计: {self.total}, 通过: {self.passed}, 失败: {self.failed}, 跳过: {self.skipped}")
            self.finished_signal.emit(report_dir)
        else:
            self.error_signal.emit("测试被用户终止")

    def _build_pytest_args(self) -> List[str]:
        """构建pytest参数列表（用于直接调用pytest.main）"""
        args = [
            "-v",  # 详细输出
            "-s",  # 显示print输出
            "--tb=short",  # 简短的traceback
            "--capture=no",  # 禁用pytest输出捕获
            "-p", "no:allure",  # 禁用allure插件
            "-p", "no:faulthandler",  # windowed exe没有可用stderr文件描述符
            "-o", "addopts=",  # 覆盖pytest.ini中的addopts
        ]

        # 获取测试文件根目录
        tests_root = get_bundle_root()

        # 添加测试用例
        for tc in self.testcases:
            if ".py::" in tc:
                # tc可能含子目录前缀(security/test_xxx.py::...)或纯文件名(test_xxx.py::...)
                file_part = tc.split("::")[0]
                if "/" in file_part or "\\" in file_part:
                    # 带子目录前缀(如security/), 拼到 tests/ 下对应子目录
                    args.append(os.path.join(tests_root, "tests", tc.replace("\\", "/")))
                else:
                    # 旧格式纯文件名, 默认 tests/network/
                    args.append(os.path.join(tests_root, "tests", "network", tc))
            else:
                args.append(os.path.join(tests_root, "tests", "network", f"test_vlan.py::{tc}"))

        return args

    def _build_pytest_command(self) -> List[str]:
        """构建pytest命令

        测试用例格式支持:
        - "test_function" -> tests/network/test_vlan.py::test_function (旧格式，不推荐)
        - "test_file.py::TestClass::test_method" -> tests/network/test_file.py::TestClass::test_method (推荐)
        - "test_file.py::test_function" -> tests/network/test_file.py::test_function

        注意: 不使用pytest-html，而是使用conftest.py中的自定义Jinja2报告生成器
        """
        # 获取正确的Python解释器路径
        python_exe = get_python_executable()

        if is_frozen():
            # PyInstaller打包后，使用 --run-tests 参数
            # 使用 -o 覆盖pytest.ini中的addopts设置（避免allure等未打包插件的问题）
            cmd = [
                python_exe, "--run-tests",
                "-v",  # 详细输出
                "-s",  # 显示print输出
                "--tb=short",  # 简短的traceback
                "-o", "addopts=",  # 覆盖pytest.ini中的addopts
                "-p", "no:allure",  # 禁用allure插件
                "-p", "no:faulthandler",  # windowed exe没有可用stderr文件描述符
            ]
        else:
            # 源码运行，使用正常的 pytest 命令
            cmd = [
                python_exe, "-m", "pytest",
                "-v",  # 详细输出
                "-s",  # 显示print输出
                "--tb=short",  # 简短的traceback
                "-o", "addopts=",  # 不依赖本机的pytest.ini插件
                "-p", "no:allure",
            ]

        # 注意: 如需使用--timeout参数，请先安装pytest-timeout插件
        # pip install pytest-timeout
        # timeout_sec = self.config.browser.timeout // 1000
        # cmd.append(f"--timeout={timeout_sec}")

        # 获取测试文件的根目录
        tests_root = get_bundle_root()

        # 添加测试用例（使用绝对路径）
        for tc in self.testcases:
            # 判断测试用例格式
            if ".py::" in tc:
                # tc可能含子目录前缀(security/test_xxx.py::...)或纯文件名(test_xxx.py::...)
                file_part = tc.split("::")[0]
                if "/" in file_part or "\\" in file_part:
                    # 带子目录前缀(如security/), 拼到 tests/ 下对应子目录
                    cmd.append(os.path.join(tests_root, "tests", tc.replace("\\", "/")))
                else:
                    # 旧格式纯文件名, 默认 tests/network/
                    cmd.append(os.path.join(tests_root, "tests", "network", tc))
            else:
                # 旧格式: 只有函数名，假设在 test_vlan.py 中（兼容处理）
                cmd.append(os.path.join(tests_root, "tests", "network", f"test_vlan.py::{tc}"))

        return cmd

    def _parse_output(self, line: str):
        """解析pytest输出.

        只匹配"整行就是结果词"的行(PASSED/FAILED/SKIPPED/ERROR), 避免纯子串计数——
        pytest -v 末尾的 'short test summary info' 段会把每个FAILED再列一遍(形如
        'FAILED tests/...::test_x'), 纯子串计数会把失败数翻倍(真实2个被数成4个).
        叠加 summary 段停计标志, 双保险.
        """
        # 进入 short test summary info 段后停止计数(该段重复列出每个FAILED)
        if "short test summary info" in line:
            self._summary_started = True
            return
        if self._summary_started:
            return
        m = _RESULT_WORD_RE.match(line)
        if m:
            outcome = m.group(1)
            if outcome == "PASSED":
                self.passed += 1
            elif outcome == "FAILED":
                self.failed += 1
            elif outcome == "SKIPPED":
                self.skipped += 1
            elif outcome == "ERROR":
                # setup/teardown/collect error 也算未通过(并入failed, progress信号4参数不变)
                self.failed += 1
                self._emit_log("ERROR", line)
            self._emit_progress()

    @staticmethod
    def _result_json_candidates(report_dir: str) -> List[str]:
        """返回报告目录中可能的test_results.json（去重、绝对路径）。"""
        paths = [os.path.join(report_dir, "test_results.json")]
        paths.extend(glob.glob(
            os.path.join(report_dir, "**", "test_results.json"), recursive=True
        ))
        return list(dict.fromkeys(
            os.path.abspath(path) for path in paths if os.path.isfile(path)
        ))

    @staticmethod
    def _result_json_file_state(path: str):
        """获取足以判断文件是否被本轮改写的轻量状态。"""
        stat = os.stat(path)
        return stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size

    @classmethod
    def _snapshot_result_json_state(cls, report_dir: str) -> Dict[str, tuple]:
        """记录运行前已有JSON，供完成后排除旧结果。"""
        state = {}
        for path in cls._result_json_candidates(report_dir):
            try:
                state[path] = cls._result_json_file_state(path)
            except OSError:
                continue
        return state

    def _read_final_stats(self, report_dir: str):
        """测试结束后读 conftest 落盘的 test_results.json(权威统计)校正计数.

        conftest.py 的 pytest_sessionfinish 把 _test_results(由 pytest_runtest_logreport
        的 when=='call' 精确累加)写到 reports/output/test_results.json, 与HTML报告同一
        数据源, 最权威. 读不到(JSON未生成/异常)时保留 _parse_output 的实时计数, 不阻断.
        """
        try:
            candidates = self._result_json_candidates(report_dir)
            if not candidates:
                self._emit_log("WARNING", "未找到 test_results.json, 保留实时计数")
                self._emit_progress()
                return
            fresh_candidates = []
            for path in candidates:
                try:
                    current_state = self._result_json_file_state(path)
                except OSError:
                    continue
                previous_state = self._result_json_state_before.get(path)
                if previous_state is None or current_state != previous_state:
                    fresh_candidates.append(path)
            if not fresh_candidates:
                self._emit_log(
                    "WARNING", "本次测试未生成新的 test_results.json, 已忽略旧报告统计"
                )
                self._emit_progress()
                return
            json_path = max(fresh_candidates, key=os.path.getmtime)
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            # conftest自定义格式: 顶层 total/passed/failed/skipped
            if isinstance(data, dict) and "total" in data:
                self.total = int(data.get("total", self.total))
                self.passed = int(data.get("passed", self.passed))
                self.failed = int(data.get("failed", self.failed))
                self.skipped = int(data.get("skipped", self.skipped))
                self._emit_log("INFO",
                    f"已用 {os.path.basename(json_path)} 校正统计: "
                    f"总计{self.total} 通过{self.passed} 失败{self.failed} 跳过{self.skipped}")
            else:
                self._emit_log("WARNING", f"{os.path.basename(json_path)} 格式不符, 保留实时计数")
        except Exception as e:
            self._emit_log("WARNING", f"读取test_results.json失败({e}), 保留实时计数")

        # 校正(或读失败保留实时值)后, 统一再推一次进度, 确保GUI显示权威统计
        # (实时计数_parse_output可能漏算个别用例, 例: 39例实时34通过、JSON权威35通过)
        self._emit_progress()

    def _emit_progress(self):
        """发送进度信号"""
        self.progress_signal.emit(self.total, self.passed, self.failed, self.skipped)

    def stop(self):
        """停止测试"""
        self._is_running = False
        self._heartbeat_stop.set()

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "duration": str(datetime.now() - self.start_time) if self.start_time else "00:00:00"
        }


def _run_packaged_collect_smoke(
    testcase: str,
    page_module: str,
    service_name: str,
    default_result_name: str,
    result_path: Optional[str] = None,
    result_env_name: Optional[str] = None,
) -> int:
    """Collect one packaged service node without browser or device I/O."""
    if not is_frozen():
        raise RuntimeError(
            f"packaged {service_name} collect smoke requires a frozen executable"
        )

    import importlib
    import pytest

    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    if result_path is None:
        result_path = (
            (os.environ.get(result_env_name) if result_env_name else None)
            or os.environ.get("IKUAI_PACKAGED_SMOKE_RESULT")
            or os.path.join(get_runtime_root(), default_result_name)
        )
    elif not os.path.isabs(result_path):
        result_path = os.path.join(get_runtime_root(), result_path)
    result_path = os.path.abspath(result_path)

    bundle_root = get_bundle_root()
    runtime_root = get_runtime_root()
    relative_test_target = "tests/" + testcase.replace("\\", "/")
    test_target = os.path.join(bundle_root, "tests", testcase)
    expected_suffix = testcase.replace("\\", "/")
    dependency_status = {}
    for module_name in (
        "pytest",
        "playwright.sync_api",
        "paramiko",
        "jinja2",
        "yaml",
        "openpyxl",
        page_module,
        "utils.backend_verifier",
    ):
        try:
            importlib.import_module(module_name)
            dependency_status[module_name] = "ok"
        except Exception as exc:
            dependency_status[module_name] = redact_user_paths(
                f"{type(exc).__name__}: {exc}"
            )

    class _Collector:
        nodeids = []

        def pytest_collection_finish(self, session):
            self.nodeids = [item.nodeid for item in session.items]

    collector = _Collector()
    payload = {
        "frozen": True,
        "service": service_name,
        "bundle_root": os.path.isdir(bundle_root),
        "runtime_root": os.path.isdir(runtime_root),
        "test_target": relative_test_target,
        "test_file_exists": os.path.isfile(test_target.split("::", 1)[0]),
        "dependencies": dependency_status,
        "nodeids": [],
        "collected": 0,
        "expected_node_found": False,
        "pytest_exit_code": None,
        "error": "",
    }

    original_stdout, original_stderr = sys.stdout, sys.stderr
    smoke_output = io.StringIO()
    try:
        # A windowed PyInstaller executable has no stdout/stderr handles.
        sys.stdout = smoke_output
        sys.stderr = smoke_output
        exit_code = int(pytest.main([
            "--collect-only",
            "-v",
            "-s",
            "--tb=short",
            "--capture=no",
            "-p", "no:allure",
            "-p", "no:faulthandler",
            "-o", "addopts=",
            test_target,
        ], plugins=[collector]))
        payload["pytest_exit_code"] = exit_code
        payload["nodeids"] = [redact_user_paths(nodeid) for nodeid in collector.nodeids]
        payload["collected"] = len(collector.nodeids)
        payload["expected_node_found"] = any(
            nodeid.replace("\\", "/").endswith(expected_suffix)
            for nodeid in collector.nodeids
        )
    except BaseException as exc:
        payload["error"] = redact_user_paths(
            f"{type(exc).__name__}: {exc}"
        )
    finally:
        output_summary, output_line_count = _summarize_pytest_output(
            smoke_output.getvalue()
        )
        payload["pytest_output"] = output_summary
        payload["pytest_output_line_count"] = output_line_count
        sys.stdout, sys.stderr = original_stdout, original_stderr

    success = (
        payload["pytest_exit_code"] == 0
        and payload["collected"] == 1
        and payload["expected_node_found"]
        and all(value == "ok" for value in dependency_status.values())
    )
    payload["success"] = success
    os.makedirs(os.path.dirname(result_path), exist_ok=True)
    with open(result_path, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)
    return 0 if success else 1


def run_packaged_samba_collect_smoke(result_path: Optional[str] = None) -> int:
    """Collect the packaged Samba node via ``--collect-samba-smoke``.

    The existing flag and ``IKUAI_PACKAGED_SMOKE_RESULT`` environment variable
    remain supported for backward compatibility.
    """
    return _run_packaged_collect_smoke(
        testcase=SAMBA_TESTCASE,
        page_module="pages.advanced_service.samba_server_page",
        service_name="samba",
        default_result_name="samba_collect_smoke.json",
        result_path=result_path,
    )


def run_packaged_ftp_collect_smoke(result_path: Optional[str] = None) -> int:
    """Collect the packaged FTP node via ``--collect-ftp-smoke``."""
    return _run_packaged_collect_smoke(
        testcase=FTP_TESTCASE,
        page_module="pages.advanced_service.ftp_server_page",
        service_name="ftp",
        default_result_name="ftp_collect_smoke.json",
        result_path=result_path,
        result_env_name="IKUAI_PACKAGED_FTP_SMOKE_RESULT",
    )


def run_packaged_http_collect_smoke(result_path: Optional[str] = None) -> int:
    """Collect the packaged HTTP node via ``--collect-http-smoke``."""
    return _run_packaged_collect_smoke(
        testcase=HTTP_TESTCASE,
        page_module="pages.advanced_service.http_server_page",
        service_name="http",
        default_result_name="http_collect_smoke.json",
        result_path=result_path,
        result_env_name="IKUAI_PACKAGED_HTTP_SMOKE_RESULT",
    )


def run_packaged_snmp_collect_smoke(result_path: Optional[str] = None) -> int:
    """Collect the packaged SNMP node via ``--collect-snmp-smoke``."""
    return _run_packaged_collect_smoke(
        testcase=SNMP_TESTCASE,
        page_module="pages.advanced_service.snmp_server_page",
        service_name="snmp",
        default_result_name="snmp_collect_smoke.json",
        result_path=result_path,
        result_env_name="IKUAI_PACKAGED_SNMP_SMOKE_RESULT",
    )


def run_packaged_basic_setting_collect_smoke(
    result_path: Optional[str] = None,
) -> int:
    """Collect the packaged basic-setting node without device I/O."""
    return _run_packaged_collect_smoke(
        testcase=BASIC_SETTING_TESTCASE,
        page_module="pages.device_setting.basic_setting_page",
        service_name="basic_setting",
        default_result_name="basic_setting_collect_smoke.json",
        result_path=result_path,
        result_env_name="IKUAI_PACKAGED_BASIC_SETTING_SMOKE_RESULT",
    )


def run_packaged_alg_setting_collect_smoke(
    result_path: Optional[str] = None,
) -> int:
    """Collect the packaged ALG-setting node without browser or device I/O."""
    return _run_packaged_collect_smoke(
        testcase=ALG_SETTING_TESTCASE,
        page_module="pages.device_setting.alg_setting_page",
        service_name="alg_setting",
        default_result_name="alg_setting_collect_smoke.json",
        result_path=result_path,
        result_env_name="IKUAI_PACKAGED_ALG_SETTING_SMOKE_RESULT",
    )


def run_packaged_protocol_control_collect_smoke(
    result_path: Optional[str] = None,
) -> int:
    """Collect the packaged protocol-control node without device I/O."""
    return _run_packaged_collect_smoke(
        testcase=PROTOCOL_CONTROL_TESTCASE,
        page_module="pages.device_setting.protocol_control_page",
        service_name="protocol_control",
        default_result_name="protocol_control_collect_smoke.json",
        result_path=result_path,
        result_env_name="IKUAI_PACKAGED_PROTOCOL_CONTROL_SMOKE_RESULT",
    )


def run_packaged_ospf_collect_smoke(result_path: Optional[str] = None) -> int:
    """Collect the packaged OSPF node without browser or device I/O."""
    return _run_packaged_collect_smoke(
        testcase=OSPF_TESTCASE,
        page_module="pages.network.ospf_page",
        service_name="ospf",
        default_result_name="ospf_collect_smoke.json",
        result_path=result_path,
        result_env_name="IKUAI_PACKAGED_OSPF_SMOKE_RESULT",
    )


def run_packaged_ipsec_collect_smoke(result_path: Optional[str] = None) -> int:
    """Collect the packaged IPsec VPN node without browser or device I/O."""
    return _run_packaged_collect_smoke(
        testcase=IPSEC_TESTCASE,
        page_module="pages.network.ipsec_vpn_page",
        service_name="ipsec",
        default_result_name="ipsec_collect_smoke.json",
        result_path=result_path,
        result_env_name="IKUAI_PACKAGED_IPSEC_SMOKE_RESULT",
    )


if is_frozen():
    if PACKAGED_PROTOCOL_CONTROL_COLLECT_FLAG in sys.argv:
        raise SystemExit(run_packaged_protocol_control_collect_smoke())
    if PACKAGED_ALG_SETTING_COLLECT_FLAG in sys.argv:
        raise SystemExit(run_packaged_alg_setting_collect_smoke())
    if PACKAGED_FTP_COLLECT_FLAG in sys.argv:
        raise SystemExit(run_packaged_ftp_collect_smoke())
    if PACKAGED_SAMBA_COLLECT_FLAG in sys.argv:
        raise SystemExit(run_packaged_samba_collect_smoke())
    if PACKAGED_HTTP_COLLECT_FLAG in sys.argv:
        raise SystemExit(run_packaged_http_collect_smoke())
    if PACKAGED_SNMP_COLLECT_FLAG in sys.argv:
        raise SystemExit(run_packaged_snmp_collect_smoke())
    if PACKAGED_OSPF_COLLECT_FLAG in sys.argv:
        raise SystemExit(run_packaged_ospf_collect_smoke())
    if PACKAGED_IPSEC_COLLECT_FLAG in sys.argv:
        raise SystemExit(run_packaged_ipsec_collect_smoke())
