"""
pytest配置和fixtures

提供测试所需的浏览器、页面、配置等fixtures
"""
import pytest
import os
import sys
import io
import ctypes
from datetime import datetime
from typing import Generator, Dict, List, Optional

# 解决Windows控制台GBK编码问题（全局只执行一次）
if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'buffer') and not sys.stdout.closed:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', write_through=True)
        if hasattr(sys.stderr, 'buffer') and not sys.stderr.closed:
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', write_through=True)
    except Exception:
        pass

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ==================== PyInstaller打包后的Playwright Fixtures ====================
# PyInstaller打包后，pytest-playwright插件无法通过entry_points自动加载
# 因此在这里直接定义必要的fixtures

from playwright.sync_api import Page, Browser, BrowserContext, Playwright, sync_playwright


@pytest.fixture(scope="session")
def playwright() -> Generator[Playwright, None, None]:
    """Playwright实例"""
    pw = sync_playwright().start()
    yield pw
    pw.stop()


@pytest.fixture(scope="session")
def browser_name() -> str:
    """浏览器名称"""
    return "chromium"


@pytest.fixture(scope="session")
def browser_type(playwright: Playwright, browser_name: str):
    """浏览器类型"""
    return getattr(playwright, browser_name)


@pytest.fixture(scope="session")
def browser_type_launch_args() -> Dict:
    """浏览器启动参数"""
    # 检查环境变量决定是否使用headless模式
    headless = os.environ.get("HEADLESS", "true").lower() == "true"
    return {"headless": headless}


@pytest.fixture(scope="session")
def browser(browser_type, browser_type_launch_args: Dict) -> Generator[Browser, None, None]:
    """浏览器实例"""
    browser = browser_type.launch(**browser_type_launch_args)
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def browser_context_args() -> Dict:
    """浏览器上下文参数"""
    return {}


@pytest.fixture(scope="function")
def context(browser: Browser, browser_context_args: Dict) -> Generator[BrowserContext, None, None]:
    """浏览器上下文"""
    context = browser.new_context(**browser_context_args)
    yield context
    context.close()


@pytest.fixture(scope="function")
def page(context: BrowserContext) -> Generator[Page, None, None]:
    """页面实例"""
    page = context.new_page()
    yield page
    page.close()

from playwright.sync_api import Page, Browser, BrowserContext
from config.config import get_config, get_config_with_env, Config
from pages.login_page import LoginPage
from pages.network.vlan_page import VlanPage
from pages.network.ip_rate_limit_page import IpRateLimitPage
from pages.network.mac_rate_limit_page import MacRateLimitPage
from pages.network.static_route_page import StaticRoutePage
from pages.network.cross_layer_service_page import CrossLayerServicePage
from utils.report_generator import ReportGenerator
from utils.step_recorder import StepRecorder, get_step_recorder


# ==================== SSH后台验证 ====================

def _create_backend_verifier():
    """安全创建BackendVerifier（paramiko可能未安装）"""
    try:
        from utils.backend_verifier import BackendVerifier
        return BackendVerifier()
    except ImportError:
        return None


def get_system_dpi_scale() -> float:
    """
    获取Windows系统的DPI缩放因子

    Returns:
        DPI缩放因子（如1.0, 1.25, 1.5, 2.0等）
    """
    try:
        # 设置进程为DPI感知
        ctypes.windll.user32.SetProcessDPIAware()
        # 获取系统DPI
        dpi = ctypes.windll.user32.GetDpiForSystem()
        # 96 DPI = 100%缩放
        return dpi / 96.0
    except Exception:
        return 1.0


# 全局测试结果收集
_test_results = {
    'total': 0,
    'passed': 0,
    'failed': 0,
    'skipped': 0,
    'test_cases': [],
    'start_time': None,
    'end_time': None,
    'total_steps': 0  # 添加步骤统计
}

# 测试用例名称映射（英文 -> 中文）
TEST_NAME_MAPPING = {
    'test_comprehensive_flow': 'VLAN设置测试',
    'test_export_vlans': 'VLAN导出测试',
    'test_import_vlans': 'VLAN导入测试',
    'test_ip_rate_limit_comprehensive': 'IP限速综合测试',
    'test_mac_rate_limit_comprehensive': 'MAC限速综合测试',
    'test_static_route_comprehensive': '静态路由综合测试',
    'test_cross_layer_service_comprehensive': '跨三层服务综合测试',
}


def _get_chinese_test_name(test_name: str) -> str:
    """
    将英文测试名称转换为中文

    Args:
        test_name: 英文测试名称

    Returns:
        中文名称
    """
    # 移除浏览器后缀 [chromium]
    base_name = test_name.split('[')[0] if '[' in test_name else test_name

    # 查找映射
    if base_name in TEST_NAME_MAPPING:
        return TEST_NAME_MAPPING[base_name]

    # 如果没有映射，尝试提取类名和方法名
    if '::' in test_name:
        parts = test_name.split('::')
        if len(parts) >= 2:
            method_name = parts[-1].split('[')[0]
            if method_name in TEST_NAME_MAPPING:
                return TEST_NAME_MAPPING[method_name]

    return test_name


# ==================== 配置fixtures ====================

@pytest.fixture(scope="session")
def config() -> Config:
    """
    获取全局配置（支持环境变量覆盖，用于GUI传参）

    环境变量优先级高于settings.yaml，GUI修改的参数会通过环境变量传递

    Returns:
        Config对象
    """
    return get_config_with_env()


# ==================== 浏览器配置fixtures ====================

@pytest.fixture(scope="session")
def browser_type_launch_args(config: Config):
    """浏览器启动参数 - 覆盖pytest-playwright默认配置"""
    # 从环境变量读取是否启用自适应屏幕模式
    auto_adapt = os.environ.get("AUTO_ADAPT_SCREEN", "true").lower() == "true"

    if auto_adapt:
        # 自适应模式：只添加最大化参数，让浏览器使用系统DPI设置
        launch_args = [
            "--start-maximized",  # 最大化启动
            "--high-dpi-support=1",  # 启用高DPI支持
        ]
    else:
        # 固定模式：强制1倍缩放
        launch_args = [
            "--start-maximized",
            "--force-device-scale-factor=1",
        ]

    args = {
        "headless": config.browser.headless,
        "slow_mo": config.browser.slow_mo,
        "args": launch_args,
    }
    return args


@pytest.fixture(scope="session")
def browser_context_args(config: Config):
    """浏览器上下文参数 - 覆盖pytest-playwright默认配置"""
    # 从环境变量读取是否启用自适应屏幕模式
    auto_adapt = os.environ.get("AUTO_ADAPT_SCREEN", "true").lower() == "true"

    if auto_adapt:
        # 自适应模式：使用 no_viewport=True 让窗口大小决定viewport
        # 这是让Playwright浏览器像原生浏览器一样自适应屏幕的关键
        return {
            "no_viewport": True,  # 不限制视口，让窗口大小决定viewport
            "ignore_https_errors": True,
            # 不设置device_scale_factor，让系统自动处理DPI缩放
        }
    else:
        # 固定分辨率模式：从环境变量读取分辨率（GUI传递）
        viewport_width = int(os.environ.get("VIEWPORT_WIDTH", getattr(config.browser, 'viewport_width', 1400)))
        viewport_height = int(os.environ.get("VIEWPORT_HEIGHT", getattr(config.browser, 'viewport_height', 850)))

        return {
            "viewport": {"width": viewport_width, "height": viewport_height},
            "ignore_https_errors": True,
            "device_scale_factor": 1,
        }


# ==================== 页面fixtures ====================

@pytest.fixture(scope="function")
def login_page(page: Page, config: Config) -> LoginPage:
    """
    创建登录页面实例

    Args:
        page: Playwright Page对象 (由pytest-playwright插件提供)
        config: 配置对象

    Returns:
        LoginPage实例
    """
    return LoginPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def vlan_page(page: Page, config: Config) -> VlanPage:
    """
    创建VLAN页面实例

    Args:
        page: Playwright Page对象 (由pytest-playwright插件提供)
        config: 配置对象

    Returns:
        VlanPage实例
    """
    return VlanPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def ip_rate_limit_page(page: Page, config: Config) -> IpRateLimitPage:
    """
    创建IP限速页面实例

    Args:
        page: Playwright Page对象 (由pytest-playwright插件提供)
        config: 配置对象

    Returns:
        IpRateLimitPage实例
    """
    return IpRateLimitPage(page, config.get_base_url())


@pytest.fixture(scope="function")
def mac_rate_limit_page(page: Page, config: Config) -> MacRateLimitPage:
    """
    创建MAC限速页面实例

    Args:
        page: Playwright Page对象 (由pytest-playwright插件提供)
        config: 配置对象

    Returns:
        MacRateLimitPage实例
    """
    return MacRateLimitPage(page, config.get_base_url())


# ==================== 登录fixtures ====================

@pytest.fixture(scope="function")
def logged_in_page(page: Page, login_page: LoginPage, config: Config) -> Page:
    """
    已登录状态的页面

    自动执行登录操作，返回已登录的Page对象

    Args:
        page: Playwright Page对象
        login_page: 登录页面对象
        config: 配置对象

    Returns:
        已登录的Page对象
    """
    # 先导航到登录页面
    page.goto(config.get_base_url())

    # 执行登录
    success = login_page.login(
        username=config.device.username,
        password=config.device.password
    )

    if not success:
        pytest.fail("登录失败")

    return page


@pytest.fixture(scope="function")
def vlan_page_logged_in(logged_in_page: Page, config: Config) -> VlanPage:
    """
    已登录并导航到VLAN页面的实例

    Args:
        logged_in_page: 已登录的Page对象
        config: 配置对象

    Returns:
        VlanPage实例
    """
    vlan_page = VlanPage(logged_in_page, config.get_base_url())
    vlan_page.navigate_to_vlan_settings()
    return vlan_page


@pytest.fixture(scope="function")
def ip_rate_limit_page_logged_in(logged_in_page: Page, config: Config) -> IpRateLimitPage:
    """
    已登录并导航到IP限速页面的实例

    Args:
        logged_in_page: 已登录的Page对象
        config: 配置对象

    Returns:
        IpRateLimitPage实例
    """
    ip_page = IpRateLimitPage(logged_in_page, config.get_base_url())
    ip_page.navigate_to_ip_rate_limit()
    return ip_page


@pytest.fixture(scope="function")
def mac_rate_limit_page_logged_in(logged_in_page: Page, config: Config) -> MacRateLimitPage:
    """
    已登录并导航到MAC限速页面的实例

    Args:
        logged_in_page: 已登录的Page对象
        config: 配置对象

    Returns:
        MacRateLimitPage实例
    """
    mac_page = MacRateLimitPage(logged_in_page, config.get_base_url())
    mac_page.navigate_to_mac_rate_limit()
    return mac_page


@pytest.fixture(scope="function")
def static_route_page(page: Page, config: Config) -> StaticRoutePage:
    """创建静态路由页面实例"""
    return StaticRoutePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def static_route_page_logged_in(logged_in_page: Page, config: Config) -> StaticRoutePage:
    """已登录并导航到静态路由页面的实例"""
    sr_page = StaticRoutePage(logged_in_page, config.get_base_url())
    sr_page.navigate_to_static_route()
    return sr_page


@pytest.fixture(scope="function")
def cross_layer_service_page(page: Page, config: Config) -> CrossLayerServicePage:
    """创建跨三层服务页面实例"""
    return CrossLayerServicePage(page, config.get_base_url())


@pytest.fixture(scope="function")
def cross_layer_page_logged_in(logged_in_page: Page, config: Config) -> CrossLayerServicePage:
    """已登录并导航到跨三层服务页面的实例"""
    cls_page = CrossLayerServicePage(logged_in_page, config.get_base_url())
    cls_page.navigate_to_cross_layer_service()
    return cls_page


# ==================== 测试数据fixtures ====================

@pytest.fixture(scope="session")
def test_data_dir() -> str:
    """测试数据目录"""
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_data")


@pytest.fixture(scope="session")
def vlan_test_data_dir(test_data_dir: str) -> str:
    """VLAN测试数据目录"""
    return os.path.join(test_data_dir, "vlan")


# ==================== SSH后台验证fixtures ====================

@pytest.fixture(scope="session")
def backend_verifier():
    """
    SSH后台验证器 (session级别复用连接)

    需要 paramiko 库: pip install paramiko
    如果未安装paramiko，此fixture返回None

    Returns:
        BackendVerifier实例或None
    """
    verifier = _create_backend_verifier()
    if verifier is None:
        yield None
        return

    try:
        verifier.connect_router()
        yield verifier
    finally:
        verifier.close()


@pytest.fixture(scope="session")
def router_ssh():
    """
    路由器SSH直连 (session级别复用)

    Returns:
        SSHClient实例或None
    """
    verifier = _create_backend_verifier()
    if verifier is None:
        yield None
        return

    try:
        verifier.connect_router()
        yield verifier._router
    finally:
        verifier.close()


# ==================== 报告相关fixtures ====================

@pytest.fixture(scope="session")
def screenshot_dir(config: Config) -> str:
    """截图目录"""
    dir_path = config.report.screenshot_dir
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


# ==================== 步骤记录器fixture ====================

@pytest.fixture(scope="function")
def step_recorder() -> StepRecorder:
    """
    步骤记录器fixture

    每个测试函数获得一个干净的步骤记录器实例

    Returns:
        StepRecorder实例
    """
    recorder = get_step_recorder()
    recorder.clear()  # 清除之前的记录
    return recorder


@pytest.fixture(scope="function")
def screenshot_path(screenshot_dir: str, request) -> str:
    """
    生成截图保存路径

    Args:
        screenshot_dir: 截图目录
        request: pytest request对象

    Returns:
        截图保存路径
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    test_name = request.node.name
    return os.path.join(screenshot_dir, f"{test_name}_{timestamp}.png")


# ==================== Hook函数 ====================

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    测试结果报告钩子

    在测试失败时自动截图
    """
    outcome = yield
    report = outcome.get_result()

    # 只在测试调用阶段（非setup/teardown）且失败时处理
    if call.when == "call" and report.failed:
        # 获取page fixture
        if "page" in item.funcargs:
            page = item.funcargs["page"]

            # 创建截图目录
            config = get_config()
            screenshot_dir = config.report.screenshot_dir
            os.makedirs(screenshot_dir, exist_ok=True)

            # 生成截图文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_name = f"{item.name}_{timestamp}_failure.png"
            screenshot_path = os.path.join(screenshot_dir, screenshot_name)

            # 保存截图
            try:
                page.screenshot(path=screenshot_path)
                # 将截图转为base64内嵌，避免HTML报告中路径引用失败
                import base64
                with open(screenshot_path, 'rb') as img_file:
                    img_base64 = base64.b64encode(img_file.read()).decode('utf-8')
                screenshot_data_uri = f"data:image/png;base64,{img_base64}"
                # 将base64截图添加到报告
                report.extra = getattr(report, "extra", [])
                report.extra.append({
                    "name": "Screenshot",
                    "content": screenshot_data_uri,
                    "type": "image",
                })
            except Exception as e:
                print(f"截图失败: {e}")


def pytest_configure(config):
    """pytest配置钩子"""
    # 注册自定义标记
    config.addinivalue_line(
        "markers", "vlan: VLAN设置模块测试"
    )
    config.addinivalue_line(
        "markers", "ip_rate_limit: IP限速模块测试"
    )
    config.addinivalue_line(
        "markers", "mac_rate_limit: MAC限速模块测试"
    )
    config.addinivalue_line(
        "markers", "static_route: 静态路由模块测试"
    )
    config.addinivalue_line(
        "markers", "cross_layer_service: 跨三层服务模块测试"
    )
    config.addinivalue_line(
        "markers", "network: 网络配置模块测试"
    )
    config.addinivalue_line(
        "markers", "slow: 慢速测试"
    )
    config.addinivalue_line(
        "markers", "smoke: 冒烟测试"
    )
    config.addinivalue_line(
        "markers", "backend: 后台SSH验证测试"
    )
    config.addinivalue_line(
        "markers", "full_chain: 全链路验证测试"
    )

    # 记录开始时间
    _test_results['start_time'] = datetime.now()


def pytest_sessionfinish(session, exitstatus):
    """测试会话结束钩子 - 生成自定义报告"""
    _test_results['end_time'] = datetime.now()

    # 计算持续时间
    if _test_results['start_time'] and _test_results['end_time']:
        duration = _test_results['end_time'] - _test_results['start_time']
        _test_results['duration'] = str(duration).split('.')[0]  # 去掉毫秒
    else:
        _test_results['duration'] = '00:00:00'

    # 只有当有测试用例时才生成报告
    if _test_results['total'] > 0:
        try:
            # 获取配置
            config = get_config()
            output_dir = config.report.output_dir

            # 转换为绝对路径（确保路径不受工作目录影响）
            if not os.path.isabs(output_dir):
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                output_dir = os.path.join(project_root, output_dir)

            os.makedirs(output_dir, exist_ok=True)

            # 生成报告
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(output_dir, f"test_report_{timestamp}.html")

            generator = ReportGenerator()
            device_info = {
                'ip': config.device.ip,
                'username': config.device.username,
                'browser': 'Chromium',
                'version': os.environ.get('TEST_VERSION', getattr(config.report, 'version', 'v4.0')),
            }

            # 获取测试人员（优先从环境变量获取，这样GUI设置的值可以传递）
            tester = os.environ.get('TESTER', getattr(config.report, 'tester', '自动化测试'))

            generator.generate_report(
                _test_results,
                output_path,
                report_title="爱快路由器4.0自动化测试报告",
                device_info=device_info,
                tester=tester
            )

            print(f"\n[报告] 自定义HTML报告已生成: {output_path}")

        except Exception as e:
            print(f"\n[警告] 生成自定义报告失败: {e}")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_logreport(report):
    """收集测试结果"""
    yield

    # 只处理测试调用阶段的结果
    if report.when == 'call':
        _test_results['total'] += 1

        # 提取测试用例名称
        test_name = report.nodeid
        if '::' in test_name:
            test_name = test_name.split('::')[-1]

        # 获取中文名称
        chinese_name = _get_chinese_test_name(test_name)

        # 获取步骤记录器中的步骤
        recorder = get_step_recorder()
        steps = recorder.get_steps()

        # 统计步骤数
        step_count = len(steps)
        _test_results['total_steps'] += step_count

        # 构建测试用例数据
        test_case = {
            'name': chinese_name,  # 使用中文名称
            'original_name': test_name,  # 保留原始名称
            'status': report.outcome,
            'duration': f"{report.duration:.2f}s" if hasattr(report, 'duration') else '0s',
            'description': getattr(report, 'docstring', '') or '',
            'error_message': None,
            'steps': steps,
            'step_count': step_count,  # 添加步骤数
            'screenshot': None
        }

        # 处理失败情况
        if report.failed:
            _test_results['failed'] += 1
            if hasattr(report, 'longrepr'):
                longrepr = str(report.longrepr)
                # 提取简明错误信息：取AssertionError行或最后一行有意义的错误
                error_lines = longrepr.strip().split('\n')
                short_error = None
                for line in error_lines:
                    line_stripped = line.strip()
                    if line_stripped.startswith('E ') and ('assert' in line_stripped.lower() or 'Error' in line_stripped):
                        short_error = line_stripped[2:].strip()  # 去掉 "E " 前缀
                        break
                    if line_stripped.startswith('AssertionError:') or line_stripped.startswith('AssertionError:'):
                        short_error = line_stripped
                        break
                if short_error is None:
                    # 回退：取最后一行E开头的
                    for line in reversed(error_lines):
                        if line.strip().startswith('E '):
                            short_error = line.strip()[2:].strip()
                            break
                test_case['error_message'] = short_error or longrepr[-500:]
                test_case['error_traceback'] = longrepr  # 保留完整traceback备用
        elif report.passed:
            _test_results['passed'] += 1
        else:
            _test_results['skipped'] += 1

        # 检查是否有截图
        if hasattr(report, 'extra') and report.extra:
            for extra in report.extra:
                if extra.get('type') == 'image':
                    test_case['screenshot'] = extra.get('content')
                    break

        _test_results['test_cases'].append(test_case)

        # 清除步骤记录器，为下一个测试做准备
        recorder.clear()
