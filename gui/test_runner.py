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
        self._encoding = 'utf-8'
        self._closed = False

    def write(self, text):
        """写入文本并实时回调"""
        if self._closed or not text:
            return 0
        # 同时写入缓冲区
        self._buffer.write(text)
        # 实时发送到GUI
        text_stripped = text.rstrip('\n\r')
        if text_stripped:
            self.log_callback("INFO", text_stripped)
            if self.parse_callback:
                self.parse_callback(text_stripped)
        return len(text)

    def flush(self):
        """刷新缓冲区"""
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

        # 开始时间
        self.start_time = None

    def run(self):
        """执行测试"""
        self.start_time = datetime.now()
        # 重置计数与标志(支持线程复用/重跑)
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self._summary_started = False
        self.log_signal.emit("INFO", f"开始执行 {self.total} 个测试用例...")

        # 获取项目根目录（动态计算，不受项目路径变化影响）
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 确保报告目录存在（转换为绝对路径）
        report_dir = self.config.report.output_dir
        if not os.path.isabs(report_dir):
            report_dir = os.path.join(project_root, report_dir)
        os.makedirs(report_dir, exist_ok=True)

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
            self.log_signal.emit("ERROR", f"执行测试时发生错误: {str(e)}")
            self.error_signal.emit(str(e))

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
            env["IPERF3_SERVER"] = self.config.ssh.iperf3_server or ""
            env["IPERF3_DURATION"] = str(self.config.ssh.iperf3_duration)
            env["IPERF3_TOLERANCE"] = str(self.config.ssh.iperf3_tolerance)
        # 设置Python输出编码为UTF-8，解决中文乱码问题
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["PYTHONUNBUFFERED"] = "1"

    def _run_pytest_in_process(self, report_dir: str):
        """在当前进程中直接运行pytest（打包模式）

        通过直接调用pytest.main()并捕获stdout/stderr来实时显示日志
        """
        import pytest

        # 构建pytest参数
        pytest_args = self._build_pytest_args()

        self.log_signal.emit("INFO", f"直接运行pytest: {' '.join(pytest_args)}")

        # 创建实时stdout捕获器
        def log_callback(level, message):
            self.log_signal.emit(level, message)

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
                self.log_signal.emit("INFO", f"测试执行完成，用时: {duration}")
                self.log_signal.emit("INFO", f"总计: {self.total}, 通过: {self.passed}, 失败: {self.failed}, 跳过: {self.skipped}")
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

        self.log_signal.emit("INFO", f"执行命令: {' '.join(pytest_cmd)}")

        # 设置工作目录
        work_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 使用PIPE读取输出
        process = subprocess.Popen(
            pytest_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=work_dir,
            env=os.environ.copy(),
        )

        # 使用阻塞readline()在线程中读取
        def read_process_output(stream, log_signal, parse_func):
            try:
                while True:
                    line_bytes = stream.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode('utf-8', errors='replace').rstrip('\n\r')
                    if line:
                        parse_func(line)
                        log_signal.emit("INFO", line)
            except Exception:
                pass
            finally:
                stream.close()

        reader_thread = threading.Thread(
            target=read_process_output,
            args=(process.stdout, self.log_signal, self._parse_output),
            daemon=True
        )
        reader_thread.start()

        process.wait()
        reader_thread.join(timeout=3)

        if self._is_running:
            self._read_final_stats(report_dir)  # 用conftest权威JSON校正统计(与HTML报告一致)
            duration = datetime.now() - self.start_time
            self.log_signal.emit("INFO", f"测试执行完成，用时: {duration}")
            self.log_signal.emit("INFO", f"总计: {self.total}, 通过: {self.passed}, 失败: {self.failed}, 跳过: {self.skipped}")
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
            "-o", "addopts=",  # 覆盖pytest.ini中的addopts
        ]

        # 获取测试文件根目录
        if is_frozen():
            tests_root = sys._MEIPASS
        else:
            tests_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 添加测试用例
        for tc in self.testcases:
            if ".py::" in tc:
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
            ]
        else:
            # 源码运行，使用正常的 pytest 命令
            cmd = [
                python_exe, "-m", "pytest",
                "-v",  # 详细输出
                "-s",  # 显示print输出
                "--tb=short",  # 简短的traceback
            ]

        # 注意: 如需使用--timeout参数，请先安装pytest-timeout插件
        # pip install pytest-timeout
        # timeout_sec = self.config.browser.timeout // 1000
        # cmd.append(f"--timeout={timeout_sec}")

        # 获取测试文件的根目录
        if is_frozen():
            # 打包后，测试文件在_MEIPASS目录中
            tests_root = sys._MEIPASS
        else:
            # 源码运行，使用项目根目录
            tests_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 添加测试用例（使用绝对路径）
        for tc in self.testcases:
            # 判断测试用例格式
            if ".py::" in tc:
                # 新格式: 包含文件名和类名，如 "test_vlan.py::TestVlanAdd::test_add_min_vlan_id"
                # 或 "test_vlan_comprehensive.py::TestVlanComprehensive::test_comprehensive_flow"
                cmd.append(os.path.join(tests_root, "tests", "network", tc))
            else:
                # 旧格式: 只有函数名，假设在 test_vlan.py 中（兼容处理）
                # 但这种格式不支持类内的测试函数，建议使用新格式
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
                self.log_signal.emit("ERROR", line)
            self._emit_progress()

    def _read_final_stats(self, report_dir: str):
        """测试结束后读 conftest 落盘的 test_results.json(权威统计)校正计数.

        conftest.py 的 pytest_sessionfinish 把 _test_results(由 pytest_runtest_logreport
        的 when=='call' 精确累加)写到 reports/output/test_results.json, 与HTML报告同一
        数据源, 最权威. 读不到(JSON未生成/异常)时保留 _parse_output 的实时计数, 不阻断.
        """
        try:
            candidates = glob.glob(os.path.join(report_dir, "test_results.json"))
            if not candidates:
                candidates = glob.glob(os.path.join(report_dir, "**", "test_results.json"), recursive=True)
            if not candidates:
                self.log_signal.emit("WARNING", "未找到 test_results.json, 保留实时计数")
                return
            json_path = max(candidates, key=os.path.getmtime)
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            # conftest自定义格式: 顶层 total/passed/failed/skipped
            if isinstance(data, dict) and "total" in data:
                self.total = int(data.get("total", self.total))
                self.passed = int(data.get("passed", self.passed))
                self.failed = int(data.get("failed", self.failed))
                self.skipped = int(data.get("skipped", self.skipped))
                self.log_signal.emit("INFO",
                    f"已用 {os.path.basename(json_path)} 校正统计: "
                    f"总计{self.total} 通过{self.passed} 失败{self.failed} 跳过{self.skipped}")
            else:
                self.log_signal.emit("WARNING", f"{os.path.basename(json_path)} 格式不符, 保留实时计数")
        except Exception as e:
            self.log_signal.emit("WARNING", f"读取test_results.json失败({e}), 保留实时计数")

    def _emit_progress(self):
        """发送进度信号"""
        self.progress_signal.emit(self.total, self.passed, self.failed, self.skipped)

    def stop(self):
        """停止测试"""
        self._is_running = False

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "duration": str(datetime.now() - self.start_time) if self.start_time else "00:00:00"
        }
