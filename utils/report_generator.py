"""
测试报告生成器

使用Jinja2模板生成中文HTML测试报告
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Optional
from jinja2 import Environment, FileSystemLoader


class ReportGenerator:
    """测试报告生成器"""

    def __init__(self, template_dir: str = None):
        """
        初始化报告生成器

        Args:
            template_dir: 模板目录路径
        """
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "templates")

        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_report(
        self,
        test_results: Dict,
        output_path: str,
        report_title: str = "自动化测试报告",
        device_info: Dict = None,
        tester: str = "自动化测试"
    ) -> str:
        """
        生成测试报告

        Args:
            test_results: 测试结果数据
            output_path: 输出文件路径
            report_title: 报告标题
            device_info: 设备信息
            tester: 测试人员

        Returns:
            生成的报告文件路径
        """
        # 获取模板
        template = self.env.get_template("report_template.html")

        # 准备模板数据
        data = self._prepare_template_data(test_results, report_title, device_info, tester)

        # 渲染模板
        html_content = template.render(**data)

        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # 写入文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path

    def _prepare_template_data(
        self,
        test_results: Dict,
        report_title: str,
        device_info: Dict,
        tester: str
    ) -> Dict:
        """准备模板数据"""
        # 统计信息
        total = test_results.get('total', 0)
        passed = test_results.get('passed', 0)
        failed = test_results.get('failed', 0)
        skipped = test_results.get('skipped', 0)
        total_steps = test_results.get('total_steps', 0)  # 获取步骤总数

        # 测试用例列表
        test_cases = test_results.get('test_cases', [])

        # 计算步骤总数（如果没有在test_results中，则从test_cases中计算）
        if total_steps == 0:
            for case in test_cases:
                total_steps += case.get('step_count', len(case.get('steps', [])))

        # 设备信息
        device_ip = device_info.get('ip', 'N/A') if device_info else 'N/A'
        device_username = device_info.get('username', 'N/A') if device_info else 'N/A'
        browser = device_info.get('browser', 'Chromium') if device_info else 'Chromium'
        version = device_info.get('version', 'v4.0') if device_info else 'v4.0'

        # 时间信息
        generated_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        duration = test_results.get('duration', '00:00:00')

        # 环境信息
        environment = f"http://{device_ip}"

        return {
            'report_title': report_title,
            'generated_time': generated_time,
            'duration': duration,
            'environment': environment,
            'device_ip': device_ip,
            'device_username': device_username,
            'browser': browser,
            'version': version,
            'tester': tester,
            'total': total,
            'passed': passed,
            'failed': failed,
            'skipped': skipped,
            'total_steps': total_steps,  # 添加步骤总数
            'test_cases': test_cases
        }

    def generate_from_pytest_json(self, json_path: str, output_path: str, device_info: Dict = None) -> str:
        """
        从pytest-json报告生成HTML报告

        Args:
            json_path: pytest-json报告路径
            output_path: 输出HTML路径
            device_info: 设备信息

        Returns:
            生成的报告文件路径
        """
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)

        # 解析pytest-json数据
        test_results = self._parse_pytest_json(json_data)

        return self.generate_report(test_results, output_path, device_info=device_info)

    def _parse_pytest_json(self, json_data: Dict) -> Dict:
        """解析pytest-json报告数据"""
        test_cases = []
        passed = 0
        failed = 0
        skipped = 0

        tests = json_data.get('tests', [])

        for test in tests:
            # 解析测试用例名称
            name = test.get('name', test.get('nodeid', 'Unknown'))
            outcome = test.get('outcome', 'unknown')

            # 统计
            if outcome == 'passed':
                passed += 1
            elif outcome == 'failed':
                failed += 1
            else:
                skipped += 1

            # 提取错误信息
            error_message = None
            if outcome == 'failed':
                call = test.get('call', {})
                error_message = call.get('crash', {}).get('message', '')
                if not error_message:
                    error_message = call.get('longrepr', '')

            # 构建测试用例数据
            test_case = {
                'name': name,
                'status': outcome,
                'duration': test.get('duration', '0s'),
                'description': test.get('description', ''),
                'error_message': error_message,
                'steps': [],
                'screenshot': None
            }

            test_cases.append(test_case)

        return {
            'total': len(test_cases),
            'passed': passed,
            'failed': failed,
            'skipped': skipped,
            'test_cases': test_cases,
            'duration': json_data.get('duration', '00:00:00')
        }


def generate_test_report(
    test_results: Dict,
    output_dir: str = None,
    report_name: str = None,
    device_info: Dict = None
) -> str:
    """
    生成测试报告的便捷函数

    Args:
        test_results: 测试结果数据
        output_dir: 输出目录
        report_name: 报告名称
        device_info: 设备信息

    Returns:
        报告文件路径
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "output")

    if report_name is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"test_report_{timestamp}.html"

    output_path = os.path.join(output_dir, report_name)

    generator = ReportGenerator()
    return generator.generate_report(test_results, output_path, device_info=device_info)
