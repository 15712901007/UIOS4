"""
全局配置模块

管理设备连接、浏览器、测试等配置
"""
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import yaml


@dataclass
class DeviceConfig:
    """设备配置"""
    ip: str = "10.66.0.150"
    username: str = "admin"
    password: str = "admin123"
    port: int = 80
    timeout: int = 30000  # 毫秒


@dataclass
class BrowserConfig:
    """浏览器配置"""
    browser_type: str = "chromium"  # chromium, firefox, webkit
    headless: bool = False
    slow_mo: int = 0  # 毫秒，用于调试时减慢操作
    timeout: int = 30000
    screenshot_on_failure: bool = True
    video_on_failure: bool = False
    # 浏览器视口分辨率（仅在auto_adapt_screen=False时使用）
    viewport_width: int = 1400
    viewport_height: int = 850
    # 自适应屏幕模式（启用后浏览器会像原生浏览器一样自动适应屏幕大小和DPI缩放）
    auto_adapt_screen: bool = True


@dataclass
class ReportConfig:
    """报告配置"""
    output_dir: str = "reports/output"
    template_dir: str = "reports/templates"
    screenshot_dir: str = "reports/screenshots"
    report_name_prefix: str = "test_report"
    tester: str = "自动化测试"  # 测试人员
    version: str = "v4.0"  # 测试版本


@dataclass
class ModuleDataConfig:
    """单个模块的数据配置"""
    export_filename: str = ""
    import_filename: str = ""


@dataclass
class TestDataConfig:
    """测试数据配置"""
    export_dir: str = "test_data/exports"
    import_dir: str = "test_data/imports"
    modules: Dict[str, ModuleDataConfig] = field(default_factory=dict)

    def get_export_path(self, module: str, project_root: str = None) -> str:
        """获取指定模块的导出文件完整路径"""
        filename = self.modules.get(module, ModuleDataConfig()).export_filename or f"{module}_config.xlsx"
        path = os.path.join(self.export_dir, module, filename)
        if project_root:
            path = os.path.join(project_root, path)
        return path

    def get_import_path(self, module: str, project_root: str = None) -> str:
        """获取指定模块的导入文件完整路径"""
        filename = self.modules.get(module, ModuleDataConfig()).import_filename or f"{module}_import.xlsx"
        path = os.path.join(self.import_dir, module, filename)
        if project_root:
            path = os.path.join(project_root, path)
        return path


@dataclass
class SSHHostConfig:
    """单个SSH主机配置"""
    host: str = ""
    username: str = ""
    password: str = ""
    port: int = 22
    # 控制台登录凭据（用于交互式菜单登录）
    console_username: str = ""
    console_password: str = ""


@dataclass
class SSHConfig:
    """SSH后台验证配置"""
    router: SSHHostConfig = field(default_factory=SSHHostConfig)
    client: SSHHostConfig = field(default_factory=SSHHostConfig)
    iperf3_server: str = "10.66.0.40"
    iperf3_duration: int = 10
    iperf3_tolerance: float = 0.20


@dataclass
class Config:
    """全局配置类"""
    device: DeviceConfig = field(default_factory=DeviceConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    test_data: TestDataConfig = field(default_factory=TestDataConfig)
    ssh: SSHConfig = field(default_factory=SSHConfig)

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "Config":
        """从YAML文件加载配置"""
        if not os.path.exists(yaml_path):
            return cls()

        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        config = cls()

        if "device" in data:
            config.device = DeviceConfig(**data["device"])
        if "browser" in data:
            browser_data = data["browser"]
            config.browser = BrowserConfig(
                browser_type=browser_data.get("browser_type", "chromium"),
                headless=browser_data.get("headless", False),
                slow_mo=browser_data.get("slow_mo", 0),
                timeout=browser_data.get("timeout", 30000),
                screenshot_on_failure=browser_data.get("screenshot_on_failure", True),
                video_on_failure=browser_data.get("video_on_failure", False),
                viewport_width=browser_data.get("viewport_width", 1400),
                viewport_height=browser_data.get("viewport_height", 850),
                auto_adapt_screen=browser_data.get("auto_adapt_screen", True),
            )
        if "report" in data:
            report_data = data["report"]
            config.report = ReportConfig(
                output_dir=report_data.get("output_dir", "reports/output"),
                template_dir=report_data.get("template_dir", "reports/templates"),
                screenshot_dir=report_data.get("screenshot_dir", "reports/screenshots"),
                report_name_prefix=report_data.get("report_name_prefix", "test_report"),
                tester=report_data.get("tester", "自动化测试"),
                version=report_data.get("version", "v4.0"),
            )
        if "test_data" in data:
            test_data_config = TestDataConfig()
            test_data_info = data["test_data"]
            if "export_dir" in test_data_info:
                test_data_config.export_dir = test_data_info["export_dir"]
            if "import_dir" in test_data_info:
                test_data_config.import_dir = test_data_info["import_dir"]
            if "modules" in test_data_info:
                for module_name, module_config in test_data_info["modules"].items():
                    test_data_config.modules[module_name] = ModuleDataConfig(
                        export_filename=module_config.get("export_filename", ""),
                        import_filename=module_config.get("import_filename", "")
                    )
            config.test_data = test_data_config

        if "ssh" in data:
            ssh_data = data["ssh"]
            ssh_config = SSHConfig()
            if "router" in ssh_data:
                ssh_config.router = SSHHostConfig(**ssh_data["router"])
            if "client" in ssh_data:
                ssh_config.client = SSHHostConfig(**ssh_data["client"])
            ssh_config.iperf3_server = ssh_data.get("iperf3_server", "10.66.0.40")
            ssh_config.iperf3_duration = ssh_data.get("iperf3_duration", 10)
            ssh_config.iperf3_tolerance = ssh_data.get("iperf3_tolerance", 0.20)
            config.ssh = ssh_config

        return config

    def to_yaml(self, yaml_path: str):
        """保存配置到YAML文件"""
        data = {
            "device": {
                "ip": self.device.ip,
                "username": self.device.username,
                "password": self.device.password,
                "port": self.device.port,
                "timeout": self.device.timeout,
            },
            "browser": {
                "browser_type": self.browser.browser_type,
                "headless": self.browser.headless,
                "slow_mo": self.browser.slow_mo,
                "timeout": self.browser.timeout,
                "screenshot_on_failure": self.browser.screenshot_on_failure,
                "video_on_failure": self.browser.video_on_failure,
                "viewport_width": self.browser.viewport_width,
                "viewport_height": self.browser.viewport_height,
                "auto_adapt_screen": self.browser.auto_adapt_screen,
            },
            "report": {
                "output_dir": self.report.output_dir,
                "template_dir": self.report.template_dir,
                "screenshot_dir": self.report.screenshot_dir,
                "report_name_prefix": self.report.report_name_prefix,
                "tester": self.report.tester,
                "version": self.report.version,
            },
            "test_data": {
                "export_dir": self.test_data.export_dir,
                "import_dir": self.test_data.import_dir,
                "modules": {
                    name: {
                        "export_filename": mod.export_filename,
                        "import_filename": mod.import_filename
                    }
                    for name, mod in self.test_data.modules.items()
                }
            },
            "ssh": {
                "router": {
                    "host": self.ssh.router.host,
                    "username": self.ssh.router.username,
                    "password": self.ssh.router.password,
                    "port": self.ssh.router.port,
                    "console_username": self.ssh.router.console_username,
                    "console_password": self.ssh.router.console_password,
                },
                "client": {
                    "host": self.ssh.client.host,
                    "username": self.ssh.client.username,
                    "password": self.ssh.client.password,
                    "port": self.ssh.client.port,
                },
                "iperf3_server": self.ssh.iperf3_server,
                "iperf3_duration": self.ssh.iperf3_duration,
                "iperf3_tolerance": self.ssh.iperf3_tolerance,
            }
        }

        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True, default_flow_style=False)

    def get_base_url(self) -> str:
        """获取设备基础URL"""
        port_part = f":{self.device.port}" if self.device.port != 80 else ""
        return f"http://{self.device.ip}{port_part}"

    def get_project_root(self) -> str:
        """获取项目根目录"""
        return os.path.dirname(os.path.dirname(__file__))


# 全局配置实例
_config: Optional[Config] = None


def get_config() -> Config:
    """获取全局配置实例"""
    global _config
    if _config is None:
        config_path = os.path.join(os.path.dirname(__file__), "settings.yaml")
        _config = Config.from_yaml(config_path)
    return _config


def set_config(config: Config):
    """设置全局配置"""
    global _config
    _config = config


def reload_config(config_path: str = None):
    """重新加载配置"""
    global _config
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "settings.yaml")
    _config = Config.from_yaml(config_path)
    return _config


def get_test_data_config() -> TestDataConfig:
    """获取测试数据配置"""
    return get_config().test_data


def apply_env_overrides(config: Config) -> Config:
    """用环境变量覆盖配置（支持GUI传参）

    环境变量映射:
    - DEVICE_IP / DEVICE_USERNAME / DEVICE_PASSWORD / DEVICE_PORT: 设备配置
    - SSH_ROUTER_HOST / SSH_ROUTER_USERNAME / SSH_ROUTER_PASSWORD / SSH_ROUTER_PORT: SSH路由器配置
    - SSH_CONSOLE_USERNAME / SSH_CONSOLE_PASSWORD: 控制台登录凭据
    - TESTER / TEST_VERSION: 报告配置
    """
    # 设备配置覆盖
    if os.environ.get("DEVICE_IP"):
        config.device.ip = os.environ["DEVICE_IP"]
    if os.environ.get("DEVICE_USERNAME"):
        config.device.username = os.environ["DEVICE_USERNAME"]
    if os.environ.get("DEVICE_PASSWORD"):
        config.device.password = os.environ["DEVICE_PASSWORD"]
    if os.environ.get("DEVICE_PORT"):
        config.device.port = int(os.environ["DEVICE_PORT"])

    # SSH路由器配置覆盖
    if os.environ.get("SSH_ROUTER_HOST"):
        config.ssh.router.host = os.environ["SSH_ROUTER_HOST"]
    if os.environ.get("SSH_ROUTER_USERNAME"):
        config.ssh.router.username = os.environ["SSH_ROUTER_USERNAME"]
    if os.environ.get("SSH_ROUTER_PASSWORD"):
        config.ssh.router.password = os.environ["SSH_ROUTER_PASSWORD"]
    if os.environ.get("SSH_ROUTER_PORT"):
        config.ssh.router.port = int(os.environ["SSH_ROUTER_PORT"])

    # 控制台登录凭据覆盖
    if os.environ.get("SSH_CONSOLE_USERNAME"):
        config.ssh.router.console_username = os.environ["SSH_CONSOLE_USERNAME"]
    if os.environ.get("SSH_CONSOLE_PASSWORD"):
        config.ssh.router.console_password = os.environ["SSH_CONSOLE_PASSWORD"]

    # 报告配置覆盖
    if os.environ.get("TESTER"):
        config.report.tester = os.environ["TESTER"]
    if os.environ.get("TEST_VERSION"):
        config.report.version = os.environ["TEST_VERSION"]

    return config


def get_config_with_env() -> Config:
    """获取配置并应用环境变量覆盖"""
    config = get_config()
    return apply_env_overrides(config)
