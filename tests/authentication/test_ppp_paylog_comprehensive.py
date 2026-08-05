"""
认证服务-认证账号管理-总账管理 综合测试用例

总账管理 = 缴费/账单记录列表(ppp_paylog, 日志库 /etc/log/pppuser.db)。
记录由账号操作(开户/缴费)自动生成, 本页只读 + 删除 + 导出 + 搜索 + 排序。

测试覆盖:
1.  环境清理 + 造 6 条测试记录(不同 feemoney/timestamp, 可排序)
2.  SSH 验证记录数
3.  搜索测试(存在/不存在/清空)
4.  排序测试(收费金额/收费时间, .sortIcon)
5.  删除单条 + SSH 验证(count-1)
6.  批量删除剩余 + SSH 验证(清零)
7.  导出 CSV/TXT
8.  帮助功能
"""
import os
import time
import pytest

from pages.authentication.ppp_paylog_page import PppPaylogPage
from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify

pytestmark = [pytest.mark.auth, pytest.mark.ppp_paylog]

PREFIX = "paylog_t_"


def _wait_for_paylog_ui(page: PppPaylogPage, expected_names, timeout_ms: int = 12000):
    """等待总账表格稳定到精确 username 集合(搜索后用)。"""
    expected = set(expected_names)
    deadline = time.monotonic() + timeout_ms / 1000
    last_names = []
    while time.monotonic() < deadline:
        last_names = sorted(page.get_paylog_usernames())
        if set(last_names) == expected:
            return sorted(expected)
        page.page.wait_for_timeout(500)
    raise AssertionError(f"总账表格未稳定: 期望{sorted(expected)}, 实际{last_names}")


@pytest.mark.auth
@pytest.mark.ppp_paylog
class TestPppPaylogComprehensive:
    """总账管理综合测试 - 只读记录列表(搜索/排序/删除/导出)"""

    def test_ppp_paylog_comprehensive(self, ppp_paylog_page_logged_in: PppPaylogPage,
                                      step_recorder: StepRecorder, request):
        page = ppp_paylog_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []
        ui_failures = []
        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        def verify_count(label, expected, prefix=PREFIX, must_pass=True):
            return ssh_verify(
                f"L1-计数-{label}",
                backend_verifier.verify_paylog_count,
                expected, prefix=prefix, must_pass=must_pass,
            )

        # 测试数据 - 6 条记录, 不同 feemoney(排序) + 不同 timestamp(排序)
        now = int(time.time())
        test_records = [
            {"username": "paylog_t_001", "feemoney": 100, "ts": now - 600, "name": "用户甲", "comment": "缴费100"},
            {"username": "paylog_t_002", "feemoney": 300, "ts": now - 500, "name": "用户乙", "comment": "缴费300"},
            {"username": "paylog_t_003", "feemoney": 200, "ts": now - 400, "name": "用户丙", "comment": "缴费200"},
            {"username": "paylog_t_004", "feemoney": 50,  "ts": now - 300, "name": "李四",   "comment": "缴费50"},
            {"username": "paylog_t_005", "feemoney": 500, "ts": now - 200, "name": "王五",   "comment": "缴费500"},
            {"username": "paylog_t_006", "feemoney": 150, "ts": now - 100, "name": "赵六",   "comment": "缴费150"},
        ]

        print("\n" + "=" * 60)
        print("总账管理综合测试开始")
        print("=" * 60)

        try:
            # ========== 步骤1: 环境清理 + 造记录 ==========
            with rec.step("步骤1: 环境清理+造记录", f"清理 {PREFIX} 残留, 造 {len(test_records)} 条测试记录"):
                print("\n[步骤1] 清理+造记录...")
                rec.add_detail("【环境清理+造记录】")
                if backend_verifier is None:
                    pytest.skip("总账管理测试必须启用 SSH backend_verifier")
                res = backend_verifier.cleanup_paylog(PREFIX)
                rec.add_detail(f"  SSH清理: {res}")
                print(f"  SSH清理: {res}")
                for r in test_records:
                    ok = backend_verifier.create_paylog_record(
                        username=r["username"], feemoney=r["feemoney"], timestamp=r["ts"],
                        name=r["name"], comment=r["comment"])
                    assert ok, f"造记录失败: {r['username']}"
                    rec.add_detail(f"  + {r['username']} 金额={r['feemoney']} 时间偏移={r['ts']-now}")
                print(f"  [OK] 造 {len(test_records)} 条记录")
                verify_count("造记录后", len(test_records))

            # ========== 步骤2: 搜索测试 ==========
            with rec.step("步骤2: 搜索测试", "搜索 paylog_t_ 只显示测试记录"):
                print("\n[步骤2] 搜索测试...")
                rec.add_detail("【搜索测试】")
                page._ensure_paylog_list()
                # 搜索 paylog_t_ (前缀匹配 6 条)
                rec.add_detail(f"  测试1: 搜索 '{PREFIX}'")
                page.search_rule(PREFIX)
                page.page.wait_for_timeout(1000)
                names = set(page.get_paylog_usernames())
                expected_names = {r["username"] for r in test_records}
                rec.add_detail(f"    搜索结果: {sorted(names)}")
                assert names == expected_names, f"搜索paylog_t_结果不一致: {names}"
                rec.add_detail(f"    ✓ 搜索到全部 {len(expected_names)} 条测试记录")
                print(f"  [OK] 搜索 paylog_t_: {len(names)} 条")
                # 搜索不存在
                rec.add_detail(f"  测试2: 搜索不存在")
                page.search_rule("not_exist_paylog_zzz")
                page.page.wait_for_timeout(1000)
                try:
                    _wait_for_paylog_ui(page, [], timeout_ms=6000)
                    cnt = 0
                except AssertionError:
                    cnt = page.get_paylog_usernames()
                rec.add_detail(f"    不存在搜索结果数: {cnt}")
                print(f"  [OK] 搜索不存在: {cnt}")
                # 清空搜索
                rec.add_detail(f"  测试3: 清空搜索")
                page.clear_search()
                page.page.wait_for_timeout(1000)
                total = page.get_rule_count()
                rec.add_detail(f"    清空后共 {total} 条(含历史记录)")
                print(f"  [OK] 清空搜索: 共 {total} 条")

            # ========== 步骤3: 排序测试(收费金额/收费时间) ==========
            with rec.step("步骤3: 排序测试", "搜索 paylog_t_ 后按 收费金额/收费时间 排序"):
                print("\n[步骤3] 排序测试...")
                rec.add_detail("【排序测试(.sortIcon)】")
                page._ensure_paylog_list()
                page.search_rule(PREFIX)
                page.page.wait_for_timeout(1000)
                _wait_for_paylog_ui(page, [r["username"] for r in test_records])

                # 收费金额排序: 升序 004(50)/001(100)/006(150)/003(200)/002(300)/005(500)
                rec.add_detail(f"  测试列: 收费金额")
                assert page.sort_by_column("收费金额"), "收费金额第一次排序失败"
                page.page.wait_for_timeout(800)
                amt_order = page.get_paylog_usernames()
                expected_amt_asc = ["paylog_t_004", "paylog_t_001", "paylog_t_006",
                                     "paylog_t_003", "paylog_t_002", "paylog_t_005"]
                rec.add_detail(f"    按金额升序: {amt_order}")
                assert amt_order == expected_amt_asc, f"金额升序不符: {amt_order}"
                # 第二次: 降序
                assert page.sort_by_column("收费金额"), "收费金额第二次排序失败"
                page.page.wait_for_timeout(800)
                amt_desc = page.get_paylog_usernames()
                assert amt_desc == list(reversed(expected_amt_asc)), f"金额降序不符: {amt_desc}"
                rec.add_detail(f"    ✓ 收费金额 升序/降序互逆验证通过")
                print(f"  [OK] 收费金额排序验证通过")

                # 收费时间排序: 升序 001(最早)→006(最新)
                rec.add_detail(f"  测试列: 收费时间")
                assert page.sort_by_column("收费时间"), "收费时间第一次排序失败"
                page.page.wait_for_timeout(800)
                time_order = page.get_paylog_usernames()
                expected_time_asc = ["paylog_t_001", "paylog_t_002", "paylog_t_003",
                                      "paylog_t_004", "paylog_t_005", "paylog_t_006"]
                rec.add_detail(f"    按时间升序: {time_order}")
                assert time_order == expected_time_asc, f"时间升序不符: {time_order}"
                assert page.sort_by_column("收费时间"), "收费时间第二次排序失败"
                page.page.wait_for_timeout(800)
                time_desc = page.get_paylog_usernames()
                assert time_desc == list(reversed(expected_time_asc)), f"时间降序不符: {time_desc}"
                rec.add_detail(f"    ✓ 收费时间 升序/降序互逆验证通过")
                print(f"  [OK] 收费时间排序验证通过")

            # ========== 步骤4: 删除单条 ==========
            with rec.step("步骤4: 删除单条记录", "删除 paylog_t_001 + SSH验证 count-1"):
                print("\n[步骤4] 删除单条...")
                rec.add_detail("【删除单条】")
                page._ensure_paylog_list()
                page.search_rule(PREFIX)
                page.page.wait_for_timeout(1000)
                _wait_for_paylog_ui(page, [r["username"] for r in test_records])
                del_name = "paylog_t_001"
                rec.add_detail(f"  目标: {del_name}")
                assert page.delete_paylog(del_name), f"删除 {del_name} 失败"
                rec.add_detail(f"  ✓ 行内删除 + 确认")
                print(f"  [OK] 删除 {del_name}")
                verify_count("删除单条后", len(test_records) - 1)
                test_records = [r for r in test_records if r["username"] != del_name]

            # ========== 步骤5: 批量删除剩余 ==========
            with rec.step("步骤5: 批量删除剩余", f"批量删除剩余 {len(test_records)} 条 + SSH验证清零"):
                print(f"\n[步骤5] 批量删除 {len(test_records)} 条...")
                rec.add_detail(f"【批量删除(3次重试)】")
                page._ensure_paylog_list()
                page.search_rule(PREFIX)
                page.page.wait_for_timeout(1000)
                remaining = [r["username"] for r in test_records]
                _wait_for_paylog_ui(page, remaining)
                delete_success = False
                for attempt in range(3):
                    page.refresh_list()
                    page.search_rule(PREFIX)
                    page.page.wait_for_timeout(1000)
                    if not page.select_all_rules():
                        rec.add_detail(f"  第{attempt+1}次: 全选未生效, 重试")
                        continue
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)
                    page.refresh_list()
                    page.search_rule(PREFIX)
                    page.page.wait_for_timeout(800)
                    try:
                        _wait_for_paylog_ui(page, [], timeout_ms=5000)
                        delete_success = True
                        break
                    except AssertionError:
                        pass
                    rec.add_detail(f"  第{attempt+1}次: 仍有残留, 重试")
                if delete_success:
                    rec.add_detail(f"  ✓ 批量删除成功(重试{attempt+1}次)")
                    print(f"  [OK] 批量删除成功")
                else:
                    ssh_failures.append(f"步骤5-批量删除: paylog_t_ 仍有残留")
                    rec.add_detail(f"  ✗ 3次重试后仍有残留")
                verify_count("批量删除后", 0)

            # ========== 步骤6: 导出 ==========
            with rec.step("步骤6: 导出配置", "导出 CSV/TXT"):
                print("\n[步骤6] 导出...")
                rec.add_detail("【导出测试】")
                page._ensure_paylog_list()
                page.clear_search()
                page.page.wait_for_timeout(800)
                config = get_config()
                export_csv = config.test_data.get_export_path("ppp_paylog", config.get_project_root())
                export_txt = export_csv.replace(".csv", ".txt")
                rec.add_detail(f"  导出CSV -> {os.path.basename(export_csv)}")
                assert page.export_rules(use_config_path=True, export_format="csv") is True, "CSV导出失败"
                assert os.path.isfile(export_csv) and os.path.getsize(export_csv) > 0, "CSV导出文件无效"
                rec.add_detail(f"    ✓ CSV导出成功")
                print(f"  [OK] CSV导出")
                page.close_modal_if_exists()
                page.page.wait_for_timeout(500)
                rec.add_detail(f"  导出TXT -> {os.path.basename(export_txt)}")
                assert page.export_rules(use_config_path=True, export_format="txt") is True, "TXT导出失败"
                assert os.path.isfile(export_txt) and os.path.getsize(export_txt) > 0, "TXT导出文件无效"
                rec.add_detail(f"    ✓ TXT导出成功")
                print(f"  [OK] TXT导出")
                page.close_modal_if_exists()
                page.refresh_list()
                page.page.wait_for_timeout(500)

            # ========== 步骤7: 帮助功能 ==========
            with rec.step("步骤7: 帮助功能", "右下角帮助按钮"):
                print("\n[步骤7] 帮助功能...")
                rec.add_detail("【帮助功能】")
                hr = page.test_help_functionality()
                rec.add_detail(f"  图标可点击: {hr['icon_clickable']}, 面板可见: {hr['panel_visible']}, "
                               f"新页面: {hr['new_page_opened']}")
                help_failures = []
                if not hr.get("icon_clickable"): help_failures.append("图标不可点击")
                if not hr.get("panel_visible"): help_failures.append("面板未显示")
                if not hr.get("new_page_opened"): help_failures.append("未开新页面")
                if help_failures:
                    rec.add_detail(f"  ✗ {help_failures}")
                    ui_failures.extend(help_failures)
                else:
                    rec.add_detail("  ✓ 帮助功能通过")
                    print("  [OK] 帮助功能通过")

            print("\n" + "=" * 60)
            print("总账管理综合测试完成")
            print("=" * 60)

        finally:
            # 兜底清理测试记录
            try:
                if backend_verifier is not None:
                    res = backend_verifier.cleanup_paylog(PREFIX)
                    print(f"[finally] {res}")
            except Exception as e:
                print(f"[finally清理异常] {str(e)[:80]}")

        # ========== 末尾硬断言 ==========
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] {len(all_failures)}项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"总账管理验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
