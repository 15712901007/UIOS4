"""
测试步骤记录器

用于记录测试执行过程中的步骤，以便在测试报告中展示
"""
import threading
from datetime import datetime
from typing import List, Dict, Optional, Any
from contextlib import contextmanager


class TestStep:
    """测试步骤"""

    def __init__(self, name: str, description: str = "", status: str = "pending"):
        """
        初始化测试步骤

        Args:
            name: 步骤名称
            description: 步骤描述/详情
            status: 步骤状态 (pending/running/passed/failed/skipped)
        """
        self.name = name
        self.description = description
        self.status = status
        self.start_time = datetime.now()
        self.end_time = None
        self.duration = None
        self.details: List[str] = []  # 步骤详情列表
        self.error_message = None

    def add_detail(self, detail: str):
        """添加步骤详情"""
        self.details.append(detail)

    def complete(self, status: str = "passed", error_message: str = None):
        """完成步骤"""
        self.status = status
        self.end_time = datetime.now()
        self.duration = (self.end_time - self.start_time).total_seconds()
        self.error_message = error_message

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "duration": f"{self.duration:.2f}s" if self.duration else "0s",
            "details": self.details,
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

    def start_step(self, name: str, description: str = "") -> TestStep:
        """
        开始一个新步骤

        Args:
            name: 步骤名称
            description: 步骤描述

        Returns:
            创建的步骤对象
        """
        step = TestStep(name, description, "running")
        self._get_steps().append(step)
        self._set_current_step(step)
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

    def end_step(self, status: str = "passed", error_message: str = None):
        """
        结束当前步骤

        Args:
            status: 步骤状态 (passed/failed/skipped)
            error_message: 错误信息（失败时）
        """
        current = self._get_current_step()
        if current:
            current.complete(status, error_message)
            self._set_current_step(None)

    @contextmanager
    def step(self, name: str, description: str = "", expect_error: bool = False):
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
        self.start_step(name, description)
        error_occurred = False
        try:
            yield self
            if not expect_error:
                self.end_step("passed")
            else:
                self.end_step("skipped", "预期错误但未发生")
        except Exception as e:
            error_occurred = True
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
