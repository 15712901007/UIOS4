"""账号设置页面、后端、报告、GUI和打包接线离线回归。"""

from pathlib import Path

import pytest

from pages.device_setting.account_setting_page import AccountSettingPage
from utils.backend_verifier import BackendVerifier, VerifyResult
from utils.replay_commands import build_verification_commands
from utils.report_generator import ReportGenerator
from utils.step_recorder import StepRecorder


ROOT = Path(__file__).resolve().parents[2]
NODE = (
    "device_setting/test_account_setting_comprehensive.py::"
    "TestAccountSettingComprehensive::test_account_setting_comprehensive"
)


def test_account_setting_page_matches_real_device_contract():
    assert AccountSettingPage.LIST_URL == "/#/equipmentSetting/loginManagement"
    assert AccountSettingPage.ADD_URL.endswith("/AccountSetting/add")
    assert AccountSettingPage.FUNC_NAME == "webuser"
    assert AccountSettingPage.GROUP_FUNC_NAME == "usergroup"
    assert AccountSettingPage.BACKEND_SCRIPT == "/usr/ikuai/script/webuser.sh"
    assert AccountSettingPage.GROUP_SCRIPT == "/usr/ikuai/script/usergroup.sh"
    assert AccountSettingPage.HELP_ARTICLE_ID == "119"
    assert AccountSettingPage.USERNAME_MAX_LENGTH == 128
    assert AccountSettingPage.SESSION_TIMEOUT_RANGE == (5, 999)
    assert AccountSettingPage.PASSWORD_CYCLE_RANGE == (1, 999)
    assert AccountSettingPage.DEFAULT_PERMISSION_OPTIONS == {
        "新功能不可见": "none",
        "新功能可见": "r",
        "新功能可读写": "rx",
    }


def test_account_setting_is_wired_to_fixture_gui_report_and_packaging():
    conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    pytest_ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    config = (ROOT / "config" / "settings.yaml").read_text(encoding="utf-8")
    gui = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    runner = (ROOT / "gui" / "test_runner.py").read_text(encoding="utf-8")
    main = (ROOT / "main.py").read_text(encoding="utf-8")
    excel = (ROOT / "utils" / "test_results_to_excel.py").read_text(
        encoding="utf-8"
    )
    guide = (ROOT / "docs" / "PyInstaller打包指南.md").read_text(
        encoding="utf-8"
    )

    assert "def account_setting_page_logged_in(" in conftest
    assert "test_account_setting_comprehensive': '设备设置-登录管理-账号设置'" in conftest
    assert "account_setting: 设备设置-登录管理-账号设置模块测试" in pytest_ini
    assert "account_setting:" in config
    assert gui.count(NODE) == 2
    assert '"account_setting": "设备设置-登录管理-账号设置"' in excel
    assert "ACCOUNT_SETTING_TESTCASE" in runner
    assert "pages.device_setting.account_setting_page" in runner
    assert "IKUAI_PACKAGED_ACCOUNT_SETTING_SMOKE_RESULT" in runner
    assert "run_packaged_account_setting_collect_smoke" in main
    assert "--collect-account-setting-smoke" in guide


def test_account_setting_gui_tree_exposes_exact_node(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        device = next(
            window.module_tree.topLevelItem(index)
            for index in range(window.module_tree.topLevelItemCount())
            if window.module_tree.topLevelItem(index).text(0) == "设备设置"
        )
        login = next(
            device.child(index)
            for index in range(device.childCount())
            if device.child(index).text(0) == "登录管理"
        )
        account = next(
            login.child(index)
            for index in range(login.childCount())
            if login.child(index).text(0) == "账号设置"
        )
        assert account.data(0, Qt.UserRole) == [NODE]
        account.setCheckState(0, Qt.Checked)
        window._update_testcase_list()
        assert window.testcase_list.count() == 1
        assert window.testcase_list.item(0).text() == NODE
    finally:
        window.close()
        app.processEvents()


def test_account_backend_exposes_l1_l4_snapshot_and_exact_cleanup():
    backend = BackendVerifier()
    for method in (
        "find_webuser_account",
        "get_webuser_environment_snapshot",
        "verify_webuser_script_contract",
        "verify_webuser_database",
        "verify_webuser_default_permission",
        "verify_webuser_permission",
        "verify_webuser_runtime",
        "verify_webuser_reinit",
        "verify_webuser_not_exists",
        "cleanup_webuser_test",
        "verify_webuser_environment_unchanged",
    ):
        assert callable(getattr(backend, method))

    source = (ROOT / "utils" / "backend_verifier.py").read_text(encoding="utf-8")
    block = source.split(
        "# ==================== 账号设置 (设备设置 > 登录管理 > 账号设置)", 1
    )[1]
    assert "length(w.passwd) AS passwd_len" in block
    assert "SELECT w.id,w.comment,w.enabled" in block
    assert "DELETE FROM api_tokens WHERE user_id IN" in block
    assert "DELETE FROM webuser WHERE id IN" in block
    assert "DELETE FROM usergroup WHERE id IN" in block
    assert "/usr/ikuai/script/webuser.sh init" in block
    assert "passwd,w.passwd" not in block


def test_account_comprehensive_contains_functional_and_help_closures():
    source = (
        ROOT / "tests" / "device_setting" / "test_account_setting_comprehensive.py"
    ).read_text(encoding="utf-8")
    for token in (
        "正确凭据登录成功",
        "错误密码被拒绝",
        "允许访问IP负向控制生效",
        "旧密码失效",
        "停用账号拒绝登录",
        "普通管理员只读及数据隔离",
        "默认权限三种新功能策略完整",
        "新功能不可见",
        "新功能可见",
        "新功能可读写",
        "请求映射为{expected_code}",
        "批量停用选中账号",
        "批量删除选中账号",
        "右下角帮助入口及悬浮文字",
        "帮助跳转到账号设置官方文章",
        "finally-恢复后独立残留审计",
    ):
        assert token in source


def test_account_report_commands_are_real_single_line_and_copy_ready():
    backend = BackendVerifier()
    result = VerifyResult(
        "L1-L4", True, "账号验证通过", details={"checks": {"ok": True}}
    )
    snapshot = {
        "prefix": "acct_l15_",
        "counts": {
            "webuser_count": "1", "usergroup_count": "1", "token_count": "0",
        },
    }
    calls = (
        (backend.verify_webuser_script_contract, (), {}),
        (
            backend.verify_webuser_database,
            ("acct_l15_main", {"enabled": "yes", "perm_default": "rx"}),
            {},
        ),
        (
            backend.verify_webuser_default_permission,
            ("acct_l15_main", "rx"),
            {},
        ),
        (backend.verify_webuser_permission, ("acct_l15_main", "read"), {}),
        (backend.verify_webuser_runtime, ("acct_l15_main", "yes"), {}),
        (backend.verify_webuser_reinit, ("acct_l15_main",), {}),
        (backend.verify_webuser_not_exists, ("acct_l15_main",), {}),
        (backend.verify_webuser_environment_unchanged, (snapshot,), {}),
    )
    commands = []
    for verify_func, args, kwargs in calls:
        built = build_verification_commands(
            backend, verify_func, args=args, kwargs=kwargs, result=result
        )
        assert built is not None
        assert built
        commands.extend(built)

    assert any("perm_default" in item["command"] for item in commands)
    assert any("webuser.sh init" in item["command"] for item in commands)
    for item in commands:
        command = item["command"]
        assert command.strip() == command
        assert "\n" not in command and "\r" not in command
        assert item["target"] == "router"
        assert item["copy_ready"] is True
        assert item["contains_secret"] is False
        assert item["purpose"] and item["expected"] and item["valid_when"]
        assert "SELECT w.passwd" not in command
        if "w.passwd" in command:
            assert "length(COALESCE(w.passwd,''))" in command
        assert "SELECT *" not in command


def test_account_report_renders_one_copy_button_per_command(tmp_path):
    backend = BackendVerifier()
    result = VerifyResult("L1", True, "默认权限策略正确(rx)")
    commands = build_verification_commands(
        backend,
        backend.verify_webuser_default_permission,
        args=("acct_l15_main", "rx"),
        result=result,
    )
    recorder = StepRecorder()
    recorder.start_step(
        "步骤1 操作：核对账号默认权限；验证：命令逐条可复制",
        "生成真实可执行的账号数据库复验命令",
    )
    recorder.add_verification_commands(commands)
    recorder.end_step("passed")
    data = {
        "total": 1, "passed": 1, "failed": 0, "skipped": 0,
        "duration": "0:00:01",
        "test_cases": [{
            "name": "设备设置-登录管理-账号设置",
            "original_name": "test_account_setting_comprehensive",
            "status": "passed", "duration": "1.00s",
            "steps": recorder.get_steps(), "step_count": 1,
            "error_message": None, "screenshot_path": "",
        }],
    }
    report_path = tmp_path / "account_report.html"
    ReportGenerator().generate_report(data, str(report_path))
    html = report_path.read_text(encoding="utf-8")
    assert html.count('class="verification-command-card"') == len(commands)
    assert html.count('class="copy-verification-command"') == len(commands)
    assert "后端人工复验命令（逐条复制执行）" in html
    assert "复制命令" in html
