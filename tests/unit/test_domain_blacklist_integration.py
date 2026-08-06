"""禁止娱乐网站页面、后端、GUI、导出解析和报告接线回归。"""

import csv
import json
from pathlib import Path

from pages.security.domain_blacklist_page import DomainBlacklistPage
from tests.security.test_domain_blacklist_comprehensive import (
    CLIENT_IP,
    EDIT_GROUP,
    RULE_NAME,
    _assert_domain_blacklist_export_matches,
)
from utils.backend_verifier import BackendVerifier, VerifyResult
from utils.replay_commands import build_verification_commands


ROOT = Path(__file__).resolve().parents[2]
COMPREHENSIVE_NODE = (
    "security/test_domain_blacklist_comprehensive.py::"
    "TestDomainBlacklistComprehensive::test_domain_blacklist_comprehensive"
)
FUNCTIONAL_NODE = (
    "security/test_domain_blacklist_functional.py::"
    "TestDomainBlacklistFunctional::test_domain_blacklist_http_https_flow"
)


def test_domain_blacklist_page_and_backend_match_device_contract():
    assert DomainBlacklistPage.MODULE_NAME == "domain_blacklist"
    assert DomainBlacklistPage.IMPORT_REQUIRES_CLEAR_GUARD is True
    assert DomainBlacklistPage.HELP_ARTICLE_ID == "184"
    assert DomainBlacklistPage.LIST_URL.endswith("/securityCenter/urlAccessControl")
    assert DomainBlacklistPage.ADD_URL.endswith("/urlAccessControl/bannedSite/add")
    backend = BackendVerifier()
    for method in (
        "find_domain_blacklist_rule",
        "verify_domain_blacklist_database",
        "verify_domain_blacklist_not_exists",
        "verify_domain_blacklist_rule_set",
        "verify_domain_blacklist_script_contract",
        "verify_domain_blacklist_group_catalog",
        "verify_domain_blacklist_generated_rule",
        "verify_domain_blacklist_ipset",
        "verify_domain_blacklist_consistency",
        "verify_domain_blacklist_artifacts_absent",
        "verify_domain_blacklist_flow",
        "cleanup_domain_blacklist_test",
        "cleanup_domain_blacklist_artifacts",
    ):
        assert callable(getattr(backend, method))
    assert len(backend.ENTERTAINMENT_DOMAIN_SAMPLES) == 10


def test_domain_blacklist_is_wired_to_all_entry_points():
    conftest = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    pytest_ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    gui = (ROOT / "gui" / "main_window.py").read_text(encoding="utf-8")
    settings = (ROOT / "config" / "settings.yaml").read_text(encoding="utf-8")
    excel = (ROOT / "utils" / "test_results_to_excel.py").read_text(encoding="utf-8")

    assert "def domain_blacklist_page_logged_in(" in conftest
    assert "test_domain_blacklist_comprehensive': '安全中心-网址浏览控制-禁止娱乐网站综合测试(L1-L4)'" in conftest
    assert "test_domain_blacklist_http_https_flow': '安全中心-禁止娱乐网站功能测试(HTTP/HTTPS真实阻断L5)'" in conftest
    assert "domain_blacklist: 网址浏览控制-禁止娱乐网站模块测试" in pytest_ini
    assert "domain_blacklist_config.csv" in settings
    assert gui.count(COMPREHENSIVE_NODE) == 3
    assert gui.count(FUNCTIONAL_NODE) == 3
    assert '"domain_blacklist": "安全中心-网址浏览控制-禁止娱乐网站综合测试(L1-L4)"' in excel
    assert '"domain_blacklist_http_https": "安全中心-禁止娱乐网站功能测试(HTTP/HTTPS真实阻断L5)"' in excel


def test_domain_blacklist_gui_tree_selects_both_scripts(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    import pytest

    pytest.importorskip("PySide6")
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        security = next(
            window.module_tree.topLevelItem(index)
            for index in range(window.module_tree.topLevelItemCount())
            if window.module_tree.topLevelItem(index).text(0) == "安全中心"
        )
        node = next(
            security.child(index)
            for index in range(security.childCount())
            if security.child(index).text(0) == "网址浏览控制-禁止娱乐网站"
        )
        assert node.data(0, Qt.UserRole) == [COMPREHENSIVE_NODE, FUNCTIONAL_NODE]
        node.setCheckState(0, Qt.Checked)
        window._update_testcase_list()
        selected = [
            window.testcase_list.item(index).text()
            for index in range(window.testcase_list.count())
        ]
        assert selected == [COMPREHENSIVE_NODE, FUNCTIONAL_NODE]
    finally:
        window.close()
        app.processEvents()


def test_domain_blacklist_csv_and_txt_exports_are_parsed_structurally(tmp_path):
    nested_source = {"custom": [CLIENT_IP], "object": {}}
    nested_time = {
        "custom": [{
            "type": "weekly",
            "weekdays": "1234567",
            "start_time": "00:00",
            "end_time": "23:59",
            "comment": "",
        }],
        "object": {},
    }
    row = {
        "id": "7",
        "enabled": "yes",
        "domain_group": EDIT_GROUP,
        "comment": "游戏子类",
        "tagname": RULE_NAME,
        "src_addr": json.dumps(nested_source, ensure_ascii=False, separators=(",", ":")),
        "time": json.dumps(nested_time, ensure_ascii=False, separators=(",", ":")),
    }
    csv_path = tmp_path / "domain_blacklist_config.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    txt_path = tmp_path / "domain_blacklist_config.txt"
    txt_path.write_text(
        " ".join(f"{field}={value}" for field, value in row.items()) + "\n",
        encoding="utf-8",
    )

    csv_row = _assert_domain_blacklist_export_matches(str(csv_path))
    txt_row = _assert_domain_blacklist_export_matches(str(txt_path))
    assert csv_row["domain_group"] == txt_row["domain_group"] == EDIT_GROUP
    assert csv_row["src_addr"] == txt_row["src_addr"] == nested_source
    assert csv_row["time"] == txt_row["time"] == nested_time


def test_domain_blacklist_manual_commands_cover_l1_l5(monkeypatch):
    backend = BackendVerifier()
    monkeypatch.setattr(
        backend,
        "find_domain_blacklist_rule",
        lambda _tagname: {"id": 7, "domain_group": "游戏网站"},
    )
    result = VerifyResult("L1-L5", True, "符合预期")
    calls = (
        (backend.verify_domain_blacklist_database, (RULE_NAME,), {}),
        (backend.verify_domain_blacklist_rule_set, ([RULE_NAME],), {}),
        (backend.verify_domain_blacklist_script_contract, (), {}),
        (backend.verify_domain_blacklist_group_catalog, (), {}),
        (backend.verify_domain_blacklist_generated_rule, (RULE_NAME,), {}),
        (backend.verify_domain_blacklist_ipset, (RULE_NAME, CLIENT_IP), {}),
        (backend.verify_domain_blacklist_consistency, ("dblk_t_",), {}),
        (backend.verify_domain_blacklist_artifacts_absent, (7,), {}),
        (
            backend.verify_domain_blacklist_flow,
            ("4399.com",),
            {"protocol": "https", "expect_allowed": False, "iface": "ens11"},
        ),
    )
    commands = []
    for verify_func, args, kwargs in calls:
        built = build_verification_commands(
            backend, verify_func, args=args, kwargs=kwargs, result=result
        )
        assert built, verify_func.__name__
        commands.extend(built)

    text = "\n".join(item["command"] for item in commands)
    assert "FROM domain_blacklist" in text
    assert "/usr/ikuai/script/domain_blacklist.sh" in text
    assert "/usr/libproto/domaingroup" in text
    assert "05-01-domain_blacklist.txt" in text
    assert "ipset test _domain_blacklist_src_7" in text
    assert "--interface ens11" in text
    assert "https://4399.com/" in text
    assert all(item["copy_ready"] is True for item in commands)
    assert all(item["purpose"] and item["expected"] for item in commands)
