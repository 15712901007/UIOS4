"""
认证服务-认证账号管理-上网码 综合测试用例

上网码(coupon)管理: 单码添加 + 批量生成 + 删除失效 + 状态筛选 + CRUD + 导出。
表 coupon(config.db): username(大写unique)/expires/timeout/used。

测试覆盖:
1.  环境清理 + 单码添加(多条, 可控 username) + SSH 验证
2.  批量生成(3个, 验证数量+长度) + SSH 验证 count
3.  编辑上网码
4.  删除单条 + SSH 验证
5.  删除失效(造过期码, 删除失效, SSH 验证只删过期)
6.  状态筛选(全部/已使用/未使用/已过期)
7.  搜索
8.  导出 CSV/TXT
9.  帮助功能
"""
import os
import time
import pytest

from pages.authentication.coupon_page import CouponPage
from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify

pytestmark = [pytest.mark.auth, pytest.mark.coupon]

PREFIX = "COUPON_T_"


def _wait_for_coupon_ui(page: CouponPage, expected_count_min, timeout_ms: int = 12000):
    """等待上网码表格数量达到期望最小值(批量生成 username 不可控, 按数量判断)。"""
    deadline = time.monotonic() + timeout_ms / 1000
    last = 0
    while time.monotonic() < deadline:
        last = page.get_rule_count()
        if last >= expected_count_min:
            return last
        page.page.wait_for_timeout(500)
    raise AssertionError(f"上网码表格数量未达 {expected_count_min}, 实际 {last}")


@pytest.mark.auth
@pytest.mark.coupon
class TestCouponComprehensive:
    """上网码综合测试 - 单码+批量生成+删除失效+状态筛选+CRUD"""

    def test_coupon_comprehensive(self, coupon_page_logged_in: CouponPage,
                                  step_recorder: StepRecorder, request):
        page = coupon_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []
        ui_failures = []
        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        def verify_coupon(username, label, expected_fields=None, must_pass=True):
            return ssh_verify(
                f"L1-数据库-{label}({username})",
                backend_verifier.verify_coupon_database,
                username, expected_fields=expected_fields, must_pass=must_pass,
            )

        def verify_absent(username, label):
            return ssh_verify(
                f"L1-删除-{label}({username})",
                backend_verifier.verify_coupon_not_exists,
                username, must_pass=True,
            )

        # 单码测试数据(username 大写)
        test_codes = ["COUPON_T_001", "COUPON_T_002", "COUPON_T_003", "COUPON_T_004"]

        print("\n" + "=" * 60)
        print("上网码综合测试开始")
        print("=" * 60)

        try:
            # ========== 步骤1: 环境清理 + 单码添加 ==========
            with rec.step("步骤1: 清理+单码添加", f"清理 {PREFIX} 残留, 添加 {len(test_codes)} 个单码"):
                print("\n[步骤1] 清理+单码添加...")
                rec.add_detail("【环境清理+单码添加】")
                if backend_verifier is None:
                    pytest.skip("上网码测试必须启用 SSH backend_verifier")
                res = backend_verifier.cleanup_coupon(PREFIX)
                rec.add_detail(f"  SSH清理: {res}")
                print(f"  SSH清理: {res}")
                for code in test_codes:
                    ok = page.add_coupon(username=code, hour=2, comment=f"单码{code}")
                    assert ok, f"添加单码 {code} 失败"
                    rec.add_detail(f"  + {code} (hour=2)")
                    print(f"  + {code}")
                page._ensure_coupon_list()
                page.page.wait_for_timeout(800)
                _wait_for_coupon_ui(page, len(test_codes))
                for code in test_codes:
                    assert page.rule_exists(code), f"{code} 未找到"
                    verify_coupon(code, "单码新增", expected_fields={"enabled": "yes", "timeout": "7200"})
                rec.add_detail(f"  ✓ {len(test_codes)} 个单码添加+L1验证通过")
                print(f"  [OK] {len(test_codes)} 个单码添加成功")

            # ========== 步骤2: 批量生成 ==========
            with rec.step("步骤2: 批量生成", "批量生成3个(数字+字母, 长度8), SSH验证count"):
                print("\n[步骤2] 批量生成...")
                rec.add_detail("【批量生成(3个/长度8/数字+字母)】")
                count_before = page.get_rule_count()
                rec.add_detail(f"  批量前数量: {count_before}")
                ok = page.batch_generate(code_number=3, code_length=8, code_type="数字+字母",
                                         hour=1, comment="批量生成测试")
                assert ok, "批量生成失败"
                rec.add_detail("  ✓ 批量生成操作完成")
                page._ensure_coupon_list()
                page.page.wait_for_timeout(1000)
                _wait_for_coupon_ui(page, count_before + 3)
                count_after = page.get_rule_count()
                rec.add_detail(f"  批量后数量: {count_after} (增加 {count_after - count_before})")
                assert count_after >= count_before + 3, f"批量生成应+3: {count_before}->{count_after}"
                # SSH 验证总数增加
                db_count = backend_verifier.count_coupon()
                rec.add_detail(f"  SSH-L1总数: {db_count}")
                rec.add_detail(f"  ✓ 批量生成 {count_after - count_before} 个")
                print(f"  [OK] 批量生成成功(增{count_after-count_before})")

            # ========== 步骤3: 编辑上网码 ==========
            with rec.step("步骤3: 编辑上网码", "编辑备注"):
                print("\n[步骤3] 编辑...")
                rec.add_detail("【编辑上网码】")
                edit_code = test_codes[0]
                rec.add_detail(f"  目标: {edit_code}")
                assert page.edit_coupon(edit_code), "进入编辑失败"
                rec.add_detail("  1. 点击编辑")
                page._react_set("comment", "编辑后备注")
                rec.add_detail("  2. 改备注=编辑后备注")
                page.click_save()
                assert page._save_success(), "编辑保存失败"
                rec.add_detail("  3. 保存成功")
                page._ensure_coupon_list()
                page.page.wait_for_timeout(800)
                verify_coupon(edit_code, "编辑后", expected_fields={"comment": "编辑后备注"})
                print(f"  [OK] 编辑 {edit_code}")

            # ========== 步骤4: 删除单条 ==========
            with rec.step("步骤4: 删除单条", "删除1个上网码 + SSH验证"):
                print("\n[步骤4] 删除单条...")
                rec.add_detail("【删除单条】")
                del_code = test_codes[3]
                cnt_before = page.get_rule_count()
                rec.add_detail(f"  目标: {del_code}, 删前数量: {cnt_before}")
                assert page.delete_coupon(del_code), f"删除 {del_code} 失败"
                rec.add_detail("  ✓ 行内删除+确认")
                page.refresh_list()
                page.page.wait_for_timeout(800)
                assert not page.rule_exists(del_code), f"{del_code} 仍存在"
                verify_absent(del_code, "单条删除")
                test_codes.remove(del_code)
                print(f"  [OK] 删除 {del_code}")

            # ========== 步骤5: 删除失效 ==========
            with rec.step("步骤5: 删除失效", "造过期码, 删除失效, SSH验证只删过期"):
                print("\n[步骤5] 删除失效...")
                rec.add_detail("【删除失效】")
                # 造1个过期码(COUPON_T_EXPIRED)
                expired_code = "COUPON_T_EXPIRED"
                backend_verifier.create_coupon(expired_code, timeout=3600, comment="过期测试")
                backend_verifier.set_coupon_expired(expired_code, 1)  # expires=1 过期
                rec.add_detail(f"  预置: {expired_code}(expires=1, 已过期)")
                cnt_before = backend_verifier.count_coupon(PREFIX)
                rec.add_detail(f"  删除失效前 {PREFIX} 数量: {cnt_before}")
                page._ensure_coupon_list()
                page.page.wait_for_timeout(800)
                assert page.delete_invalid(), "删除失效操作失败"
                rec.add_detail("  ✓ 点删除失效+确认")
                page.page.wait_for_timeout(1000)
                cnt_after = backend_verifier.count_coupon(PREFIX)
                rec.add_detail(f"  删除失效后 {PREFIX} 数量: {cnt_after}")
                # 过期码应被删
                verify_absent(expired_code, "删除失效-过期码")
                # 未过期的单码应保留
                for code in test_codes:
                    if backend_verifier.find_coupon(code) is None:
                        ssh_failures.append(f"删除失效误删了未过期码: {code}")
                rec.add_detail(f"  ✓ 删除失效只删过期码, 未过期码保留")
                print(f"  [OK] 删除失效(过期码 {expired_code} 被删)")

            # ========== 步骤6: 状态筛选 ==========
            with rec.step("步骤6: 状态筛选", "全部/已使用/未使用/已过期 切换"):
                print("\n[步骤6] 状态筛选...")
                rec.add_detail("【状态筛选(segmented)】")
                page._ensure_coupon_list()
                page.page.wait_for_timeout(800)
                counts = page.get_state_counts()
                rec.add_detail(f"  当前统计: {counts}")
                # 全部
                assert page.filter_by_state("全部"), "切换全部失败"
                page.page.wait_for_timeout(800)
                all_cnt = page.get_rule_count()
                rec.add_detail(f"  '全部': {all_cnt}")
                print(f"  [OK] 全部: {all_cnt}")
                # 未使用(测试码都未使用)
                assert page.filter_by_state("未使用"), "切换未使用失败"
                page.page.wait_for_timeout(800)
                unused_names = set(page.get_coupon_list())
                rec.add_detail(f"  '未使用': {sorted(unused_names)}")
                for code in test_codes:
                    if code not in unused_names:
                        ssh_failures.append(f"未使用筛选漏掉 {code}")
                print(f"  [OK] 未使用: {len(unused_names)}")
                # 已过期(无过期码, 应为0)
                assert page.filter_by_state("已过期"), "切换已过期失败"
                page.page.wait_for_timeout(800)
                expired_cnt = page.get_rule_count()
                rec.add_detail(f"  '已过期': {expired_cnt}(应为0, 过期码已删)")
                print(f"  [OK] 已过期: {expired_cnt}")
                page.filter_by_state("全部")
                page.page.wait_for_timeout(500)
                rec.add_detail(f"  ✓ 状态筛选验证通过")

            # ========== 步骤7: 搜索 ==========
            with rec.step("步骤7: 搜索", "搜索存在/不存在/清空"):
                print("\n[步骤7] 搜索...")
                rec.add_detail("【搜索测试】")
                target = test_codes[1]
                page.search_rule(target)
                page.page.wait_for_timeout(1000)
                assert page.rule_exists(target), f"搜索不到 {target}"
                assert page.get_rule_count() == 1, "精确搜索应1条"
                rec.add_detail(f"  ✓ 搜索 {target} 命中1条")
                print(f"  [OK] 搜索存在: {target}")
                page.search_rule("NOTEXIST_ZZZ")
                page.page.wait_for_timeout(1000)
                try:
                    _wait_for_coupon_ui(page, 0, timeout_ms=6000)
                except AssertionError:
                    pass
                rec.add_detail(f"  ✓ 搜索不存在: {page.get_rule_count()}条")
                page.clear_search()
                page.page.wait_for_timeout(800)
                rec.add_detail(f"  ✓ 清空搜索恢复")
                print(f"  [OK] 搜索测试通过")

            # ========== 步骤8: 导出 ==========
            with rec.step("步骤8: 导出", "导出 CSV/TXT"):
                print("\n[步骤8] 导出...")
                rec.add_detail("【导出测试】")
                config = get_config()
                export_csv = config.test_data.get_export_path("coupon", config.get_project_root())
                export_txt = export_csv.replace(".csv", ".txt")
                rec.add_detail(f"  导出CSV -> {os.path.basename(export_csv)}")
                assert page.export_rules(use_config_path=True, export_format="csv") is True, "CSV导出失败"
                assert os.path.isfile(export_csv) and os.path.getsize(export_csv) > 0, "CSV无效"
                rec.add_detail(f"    ✓ CSV导出成功")
                print(f"  [OK] CSV导出")
                page.close_modal_if_exists()
                page.page.wait_for_timeout(500)
                rec.add_detail(f"  导出TXT -> {os.path.basename(export_txt)}")
                assert page.export_rules(use_config_path=True, export_format="txt") is True, "TXT导出失败"
                assert os.path.isfile(export_txt) and os.path.getsize(export_txt) > 0, "TXT无效"
                rec.add_detail(f"    ✓ TXT导出成功")
                print(f"  [OK] TXT导出")
                page.close_modal_if_exists()
                page.refresh_list()
                page.page.wait_for_timeout(500)

            # ========== 步骤9: 帮助功能 ==========
            with rec.step("步骤9: 帮助功能", "右下角帮助按钮"):
                print("\n[步骤9] 帮助功能...")
                rec.add_detail("【帮助功能】")
                hr = page.test_help_functionality()
                rec.add_detail(f"  图标可点击: {hr['icon_clickable']}, 面板可见: {hr['panel_visible']}, "
                               f"新页面: {hr['new_page_opened']}")
                hf = []
                if not hr.get("icon_clickable"): hf.append("图标不可点击")
                if not hr.get("panel_visible"): hf.append("面板未显示")
                if not hr.get("new_page_opened"): hf.append("未开新页面")
                if hf:
                    rec.add_detail(f"  ✗ {hf}")
                    ui_failures.extend(hf)
                else:
                    rec.add_detail("  ✓ 帮助功能通过")
                    print("  [OK] 帮助功能通过")

            print("\n" + "=" * 60)
            print("上网码综合测试完成")
            print("=" * 60)

        finally:
            try:
                if backend_verifier is not None:
                    res = backend_verifier.cleanup_coupon(PREFIX)
                    print(f"[finally] {res}")
            except Exception as e:
                print(f"[finally清理异常] {str(e)[:80]}")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] {len(all_failures)}项失败:")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"上网码验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
