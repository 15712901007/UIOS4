"""
测试执行器

在后台线程中执行pytest测试
"""
import os
import sys
import subprocess
import re
from datetime import datetime
from typing import List, Dict, Optional

from PySide6.QtCore import QThread, Signal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.config import Config


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

        # 开始时间
        self.start_time = None

    def run(self):
        """执行测试"""
        self.start_time = datetime.now()
        self.log_signal.emit("INFO", f"开始执行 {self.total} 个测试用例...")

        # 获取项目根目录（动态计算，不受项目路径变化影响）
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 确保报告目录存在（转换为绝对路径）
        report_dir = self.config.report.output_dir
        if not os.path.isabs(report_dir):
            report_dir = os.path.join(project_root, report_dir)
        os.makedirs(report_dir, exist_ok=True)

        # 构建pytest命令（不生成pytest-html，使用conftest.py中的自定义Jinja2报告）
        pytest_cmd = self._build_pytest_command()

        self.log_signal.emit("INFO", f"执行命令: {' '.join(pytest_cmd)}")

        try:
            # 设置环境变量
            env = os.environ.copy()
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
            if hasattr(self.config, 'ssh') and self.config.ssh:
                env["SSH_ROUTER_HOST"] = self.config.ssh.router.host or ""
                env["SSH_ROUTER_USERNAME"] = self.config.ssh.router.username or ""
                env["SSH_ROUTER_PASSWORD"] = self.config.ssh.router.password or ""
                env["SSH_ROUTER_PORT"] = str(self.config.ssh.router.port)
                env["SSH_CLIENT_HOST"] = self.config.ssh.client.host or ""
                env["SSH_CLIENT_USERNAME"] = self.config.ssh.client.username or ""
                env["SSH_CLIENT_PASSWORD"] = self.config.ssh.client.password or ""
                env["SSH_CLIENT_PORT"] = str(self.config.ssh.client.port)
                env["IPERF3_SERVER"] = self.config.ssh.iperf3_server or ""
                env["IPERF3_DURATION"] = str(self.config.ssh.iperf3_duration)
                env["IPERF3_TOLERANCE"] = str(self.config.ssh.iperf3_tolerance)
            # 设置Python输出编码为UTF-8，解决中文乱码问题
            env["PYTHONIOENCODING"] = "utf-8"
            # 设置控制台代码页为UTF-8（Windows）
            env["PYTHONUTF8"] = "1"
            # 禁用Python输出缓冲，实现实时日志显示
            env["PYTHONUNBUFFERED"] = "1"

            # 执行pytest
            process = subprocess.Popen(
                pytest_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                env=env,
                encoding='utf-8',
                errors='replace'
            )

            # 实时读取输出
            for line in process.stdout:
                if not self._is_running:
                    process.terminate()
                    self.log_signal.emit("WARNING", "测试被用户终止")
                    break

                line = line.strip()
                if line:
                    self._parse_output(line)
                    self.log_signal.emit("INFO", line)

            process.wait()

            # 测试完成
            if self._is_running:
                duration = datetime.now() - self.start_time
                self.log_signal.emit("INFO", f"测试执行完成，用时: {duration}")
                self.log_signal.emit("INFO", f"总计: {self.total}, 通过: {self.passed}, 失败: {self.failed}, 跳过: {self.skipped}")
                # 传递报告目录，让GUI自动查找最新报告
                self.finished_signal.emit(report_dir)
            else:
                self.error_signal.emit("测试被用户终止")

        except Exception as e:
            self.log_signal.emit("ERROR", f"执行测试时发生错误: {str(e)}")
            self.error_signal.emit(str(e))

    def _build_pytest_command(self) -> List[str]:
        """构建pytest命令

        测试用例格式支持:
        - "test_function" -> tests/network/test_vlan.py::test_function (旧格式，不推荐)
        - "test_file.py::TestClass::test_method" -> tests/network/test_file.py::TestClass::test_method (推荐)
        - "test_file.py::test_function" -> tests/network/test_file.py::test_function

        注意: 不使用pytest-html，而是使用conftest.py中的自定义Jinja2报告生成器
        """
        cmd = [
            sys.executable, "-m", "pytest",
            "-v",  # 详细输出
            "-s",  # 显示print输出
            "--tb=short",  # 简短的traceback
            # 不使用pytest-html，使用conftest.py中的自定义Jinja2报告
        ]

        # 注意: 如需使用--timeout参数，请先安装pytest-timeout插件
        # pip install pytest-timeout
        # timeout_sec = self.config.browser.timeout // 1000
        # cmd.append(f"--timeout={timeout_sec}")

        # 添加测试用例
        for tc in self.testcases:
            # 判断测试用例格式
            if ".py::" in tc:
                # 新格式: 包含文件名和类名，如 "test_vlan.py::TestVlanAdd::test_add_min_vlan_id"
                # 或 "test_vlan_comprehensive.py::TestVlanComprehensive::test_comprehensive_flow"
                cmd.append(f"tests/network/{tc}")
            else:
                # 旧格式: 只有函数名，假设在 test_vlan.py 中（兼容处理）
                # 但这种格式不支持类内的测试函数，建议使用新格式
                cmd.append(f"tests/network/test_vlan.py::{tc}")

        return cmd

    def _parse_output(self, line: str):
        """解析pytest输出"""
        # 解析 PASSED
        if "PASSED" in line:
            self.passed += 1
            self._emit_progress()

        # 解析 FAILED
        elif "FAILED" in line:
            self.failed += 1
            self._emit_progress()

        # 解析 SKIPPED
        elif "SKIPPED" in line:
            self.skipped += 1
            self._emit_progress()

        # 解析错误
        elif "ERROR" in line:
            self.log_signal.emit("ERROR", line)

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
