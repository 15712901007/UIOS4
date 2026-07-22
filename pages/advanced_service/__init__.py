"""高级服务页面对象。"""

from pages.advanced_service.ftp_server_page import FtpServerPage
from pages.advanced_service.samba_server_page import SambaServerPage
from pages.advanced_service.http_server_page import HttpServerPage
from pages.advanced_service.snmp_server_page import SnmpServerPage
from pages.advanced_service.virtual_machine_page import VirtualMachinePage

__all__ = [
    "FtpServerPage", "SambaServerPage", "HttpServerPage", "SnmpServerPage",
    "VirtualMachinePage",
]
