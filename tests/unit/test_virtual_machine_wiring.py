from pathlib import Path

from pages.advanced_service import VirtualMachinePage


ROOT = Path(__file__).resolve().parents[2]
NODE = (
    "advanced_service/test_virtual_machine_comprehensive.py::"
    "TestVirtualMachineComprehensive::test_virtual_machine_comprehensive"
)


def test_virtual_machine_page_is_exported_and_routes_are_exact():
    assert VirtualMachinePage.LIST_URL == "/#/advancedService/virtualMachine"
    assert VirtualMachinePage.ADD_URL.endswith("/advancedService/virtualMachine/add")
    assert VirtualMachinePage.BACKEND_SCRIPT == "/usr/ikuai/script/qemu.sh"


def test_gui_node_marker_name_and_excel_mapping_are_wired_once():
    gui = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    pytest_ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    excel = (ROOT / "utils" / "test_results_to_excel.py").read_text(encoding="utf-8")

    assert gui.count(NODE) == 2
    assert "'test_virtual_machine_comprehensive': '高级服务-虚拟机'" in conftest
    assert "virtual_machine: 高级服务-虚拟机模块测试" in pytest_ini
    assert '"virtual_machine": "高级服务-虚拟机"' in excel

