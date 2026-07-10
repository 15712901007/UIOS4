"""
测试报告生成器

使用Jinja2模板生成中文HTML测试报告
"""
import os
import json
import re
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
        self.env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

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

    def _analyze_failure(self, case: Dict) -> Dict:
        """
        根据错误信息自动归类失败原因，生成中文解读（用于报告展示，让失败"看得懂"）。

        只对 failed 用例调用。匹配规则按优先级从上到下，命中即返回。

        Args:
            case: 单条测试用例数据（含 error_message / error_traceback / name）

        Returns:
            {'category': 中文失败类型标签, 'reason': 可能原因, 'suggestion': 排查建议}
        """
        err = (case.get('error_message') or '').strip()
        tb = (case.get('error_traceback') or '').strip()
        name = case.get('name') or case.get('original_name') or ''
        text = f"{err}\n{tb}"
        lower = text.lower()

        # 1. 保存接口报错 code2006（磁盘满典型表现）
        if '2006' in text or '写入数据失败' in text or '写入失败' in text:
            return {
                'category': '保存接口报错（疑似磁盘满）',
                'reason': f"【{name}】保存接口返回错误码 2006（写入数据失败）。测试机 10.66.0.150 反复出现过该问题的根因是 /etc/mnt 分区磁盘满（ik_dhcpd 的 version 表暴增 + leases.db 每5分钟备份撑满 43MB 分区）→ sqlite 写 config.db 失败 → 任何 save 都报 2006。",
                'suggestion': '① SSH 到路由器执行 df -h 查看 /etc/mnt 占用；② 若满，清理：sqlite3 /tmp/db/leases.db "DELETE FROM version; VACUUM;" && cp /tmp/db/leases.db /etc/mnt/ikuai/leases.db && rm -f /etc/mnt/ikuai/leases.db.tmp；③ 清理后重跑本用例。',
            }

        # 2. Playwright 定位"添加"按钮超时（add_rule 第一步卡住）
        if 'timeout' in lower and 'locator' in lower and ('添加' in text or '"添加"' in text):
            return {
                'category': '添加按钮定位超时',
                'reason': f"【{name}】add_rule 第一步点击“添加”按钮 30 秒未找到。常见原因：页面未进入列表页（导航 URL 失效 / SPA 未加载完）、前端按钮文案或结构改版、或被残留弹窗 / 遮罩 / 上一步未关闭的抽屉遮挡。",
                'suggestion': '① 查看本用例失败截图，确认页面实际显示（是登录页？空白？列表但无"添加"按钮？有弹窗遮挡？）；①+ 若截图提示"此功能只企业版支持"或类似授权字样，则根因是测试机固件非企业版、该功能受授权限制（非测试/产品bug），需换企业版固件或在测试开头检测后 skip；② 检查该模块 navigate_to_xxx 的导航 URL 是否仍有效；③ 对比同族通过的模块（如 PPTP/L2TP）的导航与 add 逻辑差异；④ headless 下加载慢可加 wait_for_load_state 或适当加大超时。',
            }

        # 3. add_rule 返回 False（断言"添加规则 XXX 失败"）
        if ('添加规则' in text and '失败' in text) or ('assert false is true' in lower):
            return {
                'category': '添加规则失败（前端保存未成功）',
                'reason': f"【{name}】add_rule() 返回 False，前端保存环节未成功。常见原因：① 保存接口报错（磁盘满 code2006，见上条）；② 表单必填项校验失败（红色提示）；③ 保存后未出现成功消息或 URL 未跳转（_read_save_result 轮询超时判失败）；④ 字段格式被前端拦截，根本没发请求。",
                'suggestion': '① 查看失败截图有无红色错误提示 / 弹窗 / 字段红框；② SSH df -h 查 /etc/mnt 是否磁盘满（最常见）；③ 检查测试数据的必填项与字段格式是否符合前端要求；④ 手动在页面单步复现，F12 看保存接口的请求与响应。',
            }

        # 4. 一般元素定位超时
        if 'timeout' in lower and 'locator' in lower:
            m = re.search(r'get_by_role\([^)]*name=([^)]+?)\)', text) or re.search(r'get_by_\w+\([^)]*\)', text)
            loc_hint = f"（目标元素: {m.group(0)[:80]}）" if m else ''
            return {
                'category': '页面元素定位超时',
                'reason': f"【{name}】操作超时 30 秒未找到目标元素{loc_hint}。页面未加载完、元素已改版、或操作时序竞争。",
                'suggestion': '查看失败截图确认页面实际状态；检查定位器是否仍匹配当前前端版本；增加 wait_for 等待或加入重试。',
            }

        # 4.5 产品bug: 6.12内核xt_set模块坏(带地址规则iptables下发失败errno=22不生效, 连接数限制/NAT等)
        if any(k in text for k in ['xt_set', 'errno=22', 'match-set', 'set模块', 'xt_set模块坏']):
            return {
                'category': '产品bug: 6.12内核xt_set模块坏(带地址规则不生效)',
                'reason': f"【{name}】6.12内核iptables set模块(xt_set)损坏, `-m set --match-set` 报errno=22失败, "
                          f"导致带源地址/地址分组的规则(连接数限制/NAT等)iptables下发失败→规则不生效。"
                          f"这是路由器内核产品bug(已报禅道), 非测试问题——带源IP规则不生效如实FAIL体现, 不应掩盖为通过。",
                'suggestion': '① 确认内核为6.12(xt_set已知bug, uname -r); ② 功能机制本身正常(全局规则/仅接口规则的验证通过); '
                              '③ 该bug修复(固件升级修xt_set)后, 带地址规则验证会自动恢复通过; ④ 跟进禅道该bug修复进度。',
            }

        # 5. 后端 SSH 验证失败
        if any(k in text for k in ['iptables', 'ipset', 'must_pass', 'SSH-[FAIL]', '后端', 'sqlite', '数据库']):
            return {
                'category': '后端 SSH 验证失败',
                'reason': f"【{name}】前端操作可能已成功，但后端（数据库 / iptables / ipset / 内核）验证未通过。可能是后端下发延迟、验证逻辑过严，也可能是真实产品 bug。",
                'suggestion': '查看报告步骤里的 SSH-[FAIL] 详情；手动 SSH 到路由器核对后端实际状态；区分是测试验证逻辑问题还是产品 bug（必要时报禅道）。',
            }

        # 6. 网络 / 连接异常
        if any(k in lower for k in ['connection', 'err_', 'net::', 'socket', 'econnrefused', 'timeout connecting']):
            return {
                'category': '网络/连接异常',
                'reason': f"【{name}】浏览器或 SSH 连接异常。路由器 Web 服务未响应、网络中断、或登录会话过期。",
                'suggestion': '确认路由器可达（ping 10.66.0.150 / telnet 80）；确认登录会话未过期；环境恢复后重试。',
            }

        # 7. 兜底
        return {
            'category': '测试断言失败',
            'reason': f"【{name}】{err or '测试未通过'}",
            'suggestion': '查看下方完整错误堆栈与失败截图进一步定位。',
        }

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

        # 为失败用例自动注入"失败原因分析"（中文解读，让报告看得懂）
        for case in test_cases:
            if isinstance(case, dict) and case.get('status') == 'failed' and not case.get('failure_analysis'):
                try:
                    case['failure_analysis'] = self._analyze_failure(case)
                except Exception:
                    pass

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
