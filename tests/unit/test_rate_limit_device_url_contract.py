from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RATE_LIMIT_TESTS = (
    PROJECT_ROOT / "tests/network/test_ip_rate_limit_comprehensive.py",
    PROJECT_ROOT / "tests/network/test_mac_rate_limit_comprehensive.py",
)


def test_rate_limit_navigation_uses_gui_configured_device_url():
    for test_path in RATE_LIMIT_TESTS:
        source = test_path.read_text(encoding="utf-8")

        assert "base_url_part = page.base_url.rstrip('/')" in source
        assert 'else "http://10.66.0.150"' not in source


def test_starting_gui_test_refreshes_displayed_device_ip(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QListWidgetItem
    import gui.main_window as main_window_module

    app = QApplication.instance() or QApplication([])
    started = {}

    class SignalStub:
        def connect(self, callback):
            self.callback = callback

    class FakeRunner:
        def __init__(self, testcases, config):
            started["device_ip"] = config.device.ip
            self.log_signal = SignalStub()
            self.progress_signal = SignalStub()
            self.finished_signal = SignalStub()

        def start(self):
            started["started"] = True

        def isRunning(self):
            return False

    monkeypatch.setattr(main_window_module, "TestRunner", FakeRunner)
    window = main_window_module.MainWindow()
    try:
        item = QListWidgetItem("network/test_ip_rate_limit_comprehensive.py")
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(Qt.Checked)
        window.testcase_list.addItem(item)
        window.ip_input.setText("10.66.0.45")

        window._start_tests()

        assert started == {"device_ip": "10.66.0.45", "started": True}
        assert window.device_status_label.text() == "设备: 10.66.0.45"
    finally:
        window.close()
        app.processEvents()
