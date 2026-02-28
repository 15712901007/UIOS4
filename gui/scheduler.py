"""
定时任务管理器

管理测试的定时执行
"""
import os
import sys
import json
from datetime import datetime
from typing import Dict, List, Optional

from PySide6.QtCore import QObject, Signal, QDateTime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from apscheduler.schedulers.qt import QtScheduler
    from apscheduler.triggers.cron import CronTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False
    QtScheduler = None
    CronTrigger = None


class ScheduleManager(QObject):
    """定时任务管理器"""

    # 信号
    task_started = Signal(str)  # 任务开始
    task_finished = Signal(str, bool)  # 任务完成(任务名, 是否成功)
    task_log = Signal(str, str)  # 日志(任务名, 日志内容)

    def __init__(self):
        super().__init__()

        if APSCHEDULER_AVAILABLE:
            self.scheduler = QtScheduler()
        else:
            self.scheduler = None

        self.tasks: Dict[str, dict] = {}  # 任务配置
        self.test_runner = None

    def start(self):
        """启动调度器"""
        if self.scheduler:
            self.scheduler.start()

    def shutdown(self):
        """关闭调度器"""
        if self.scheduler:
            self.scheduler.shutdown()

    def is_available(self) -> bool:
        """检查APScheduler是否可用"""
        return APSCHEDULER_AVAILABLE

    def add_task(self, task_name: str, cron_expr: str,
                 testcases: List[str], config) -> bool:
        """
        添加定时任务

        Args:
            task_name: 任务名称
            cron_expr: Cron表达式 (如 "0 2 * * *" 表示每天凌晨2点)
            testcases: 要执行的测试用例列表
            config: 测试配置

        Returns:
            是否添加成功
        """
        if not self.scheduler:
            return False

        try:
            # 创建Cron触发器
            trigger = CronTrigger.from_crontab(cron_expr)

            # 添加任务
            job = self.scheduler.add_job(
                self._execute_task,
                trigger,
                id=task_name,
                args=[task_name, testcases, config],
                name=task_name
            )

            # 保存任务配置
            self.tasks[task_name] = {
                "cron_expr": cron_expr,
                "testcases": testcases,
                "config": config,
                "job": job,
                "last_run": None,
                "next_run": str(job.next_run_time) if job.next_run_time else ""
            }

            return True

        except Exception as e:
            print(f"添加定时任务失败: {e}")
            return False

    def remove_task(self, task_name: str):
        """移除定时任务"""
        if task_name in self.tasks:
            if self.scheduler:
                self.scheduler.remove_job(task_name)
            del self.tasks[task_name]

    def update_task(self, task_name: str, cron_expr: str,
                    testcases: List[str], config) -> bool:
        """更新定时任务"""
        self.remove_task(task_name)
        return self.add_task(task_name, cron_expr, testcases, config)

    def _execute_task(self, task_name: str, testcases: List[str], config):
        """执行定时任务"""
        self.task_started.emit(task_name)
        self.task_log.emit(task_name, f"开始执行定时任务: {task_name}")

        try:
            # 动态导入避免循环依赖
            from gui.test_runner import TestRunner

            self.test_runner = TestRunner(testcases, config)

            # 连接信号
            self.test_runner.log_signal.connect(
                lambda level, msg: self.task_log.emit(task_name, msg)
            )
            self.test_runner.finished_signal.connect(
                lambda report: self._on_task_finished(task_name, True, report)
            )
            self.test_runner.error_signal.connect(
                lambda err: self._on_task_finished(task_name, False, err)
            )

            # 执行测试
            self.test_runner.run()  # 同步执行

        except Exception as e:
            self.task_log.emit(task_name, f"任务执行失败: {str(e)}")
            self.task_finished.emit(task_name, False)

    def _on_task_finished(self, task_name: str, success: bool, result: str):
        """任务完成回调"""
        if success:
            self.task_log.emit(task_name, f"任务执行完成，报告: {result}")
        else:
            self.task_log.emit(task_name, f"任务执行失败: {result}")

        self.task_finished.emit(task_name, success)

        # 更新任务状态
        if task_name in self.tasks:
            self.tasks[task_name]["last_run"] = QDateTime.currentDateTime().toString()
            job = self.tasks[task_name].get("job")
            if job and job.next_run_time:
                self.tasks[task_name]["next_run"] = str(job.next_run_time)

    def get_task_list(self) -> List[dict]:
        """获取所有任务列表"""
        result = []
        for name, task in self.tasks.items():
            result.append({
                "name": name,
                "cron_expr": task["cron_expr"],
                "testcases": task["testcases"],
                "last_run": task.get("last_run", "从未执行"),
                "next_run": task.get("next_run", "")
            })
        return result

    def get_task(self, task_name: str) -> Optional[dict]:
        """获取指定任务"""
        return self.tasks.get(task_name)

    def save_tasks(self, filepath: str):
        """保存任务配置到文件"""
        data = []
        for name, task in self.tasks.items():
            # 不保存job对象和config对象
            data.append({
                "name": name,
                "cron_expr": task["cron_expr"],
                "testcases": task["testcases"],
            })

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load_tasks(self, filepath: str, config):
        """从文件加载任务配置"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for task in data:
                self.add_task(
                    task["name"],
                    task["cron_expr"],
                    task["testcases"],
                    config
                )
        except FileNotFoundError:
            pass  # 文件不存在时忽略
        except Exception as e:
            print(f"加载任务配置失败: {e}")


def parse_cron_from_ui(freq: str, time_str: str, weekday: int = None) -> str:
    """
    从UI输入解析Cron表达式

    Args:
        freq: 频率 (每天/每周/每小时/自定义)
        time_str: 时间字符串 (HH:MM)
        weekday: 星期几 (0=周一, 6=周日)

    Returns:
        Cron表达式
    """
    hour, minute = 0, 0
    if time_str:
        parts = time_str.split(":")
        if len(parts) >= 2:
            hour = int(parts[0])
            minute = int(parts[1])

    if freq == "每天":
        return f"{minute} {hour} * * *"
    elif freq == "每周":
        # Cron的星期: 0=周日, 1=周一, ..., 6=周六
        # 我们的weekday: 0=周一, ..., 6=周日
        cron_weekday = (weekday + 1) % 7 if weekday is not None else "*"
        return f"{minute} {hour} * * {cron_weekday}"
    elif freq == "每小时":
        return f"{minute} * * * *"
    else:
        # 自定义，直接返回
        return time_str
