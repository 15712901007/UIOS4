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
class Config:
    """全局配置类"""
    device: DeviceConfig = field(default_factory=DeviceConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    test_data: TestDataConfig = field(default_factory=TestDataConfig)

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
