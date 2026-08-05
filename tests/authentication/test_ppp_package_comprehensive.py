"""
认证服务-认证账号管理-套餐管理 综合测试用例

一次测试覆盖套餐(ppp_packages)全部功能:
1.  添加8条套餐(覆盖 月/天/小时周期、边界值、仅上/下行限速、长备注、中文名)
2.  SSH L1 数据库全字段验证(tagname=packname 同步、packtime 组合、price/up/down_speed)
3.  编辑套餐(改价格/限速/备注) + SSH 验证
4.  复制功能(套餐特有: 复制→改名→保存)
5.  删除套餐 + SSH 删除验证
6.  搜索测试(存在/不存在/清空)
7.  导出 CSV/TXT
8.  异常输入拦截(名称重复/超长/空、有效期空、价格/限速超范围)
    + packname 前后端字符限制不一致 BUG(前端1-24, 后端≤15, 16字符静默拒绝)软记录
9.  批量删除(选中→底部footer删除)
10. 导入 CSV(不清空)/TXT(清空) + SSH 验证
11. 帮助功能(右下角帮助按钮→popover+新标签页跳转文档)

产品差异(实测确认): 套餐管理无启用/停用、无排序列、无批量启用/停用
(ppp_packages 表无 enabled 字段, 行内操作仅 编辑/复制/删除, 批量操作仅删除)。
"""
import os
import re
import csv
import time
import pytest

from pages.authentication.ppp_package_page import PppPackagePage
from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify

pytestmark = [pytest.mark.auth, pytest.mark.ppp_package]

PREFIX = "pkg_t_"


def _expected_package_fields(pkg: dict) -> dict:
    """页面输入 -> 后端 ppp_packages 记录期望字段(tagname=packname 同步)."""
    return {
        "packname": pkg["packname"],
        "tagname": pkg["packname"],
        "packtime": pkg["packtime"],
        "price": str(pkg["price"]),
        "up_speed": str(pkg["up_speed"]),
        "down_speed": str(pkg["down_speed"]),
        "comment": pkg.get("comment") or "",
    }


def _decode_export_file(file_path: str) -> str:
    with open(file_path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    raise AssertionError(f"导出文件编码无法识别: {file_path}")


def _read_package_export(file_path: str) -> list:
    """解析套餐导出 CSV/TXT, 返回每条配置字典列表."""
    text = _decode_export_file(file_path)
    if file_path.lower().endswith(".csv"):
        return [dict(row) for row in csv.DictReader(text.splitlines())]
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = {
            m.group(1): m.group(2).strip()
            for m in re.finditer(
                r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=(.*?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
                line,
            )
        }
        rows.append(row)
    return rows


def _assert_export_matches(file_path: str, expected_pkgs: list) -> None:
    assert os.path.isfile(file_path), f"导出文件不存在: {file_path}"
    assert os.path.getsize(file_path) > 0, f"导出文件为空: {file_path}"
    rows = _read_package_export(file_path)
    names = {r.get("packname") for r in rows}
    expected_names = {p["packname"] for p in expected_pkgs}
    assert names == expected_names, (
        f"导出packname集合不一致: 期望{sorted(expected_names)}, 实际{sorted(names)}"
    )


def _wait_for_package_ui(page: PppPackagePage, expected_names, timeout_ms: int = 12000):
    """等待套餐表格稳定到精确集合, 避免加载瞬间"共0条"假通过。"""
    expected = set(expected_names)
    deadline = time.monotonic() + timeout_ms / 1000
    last_count, last_names = -1, []
    while time.monotonic() < deadline:
        last_count = page.get_package_count()
        last_names = sorted(page.get_package_list())
        if last_count == len(expected) and len(last_names) == len(expected) and set(last_names) == expected:
            return sorted(expected)
        page.page.wait_for_timeout(400)
    raise AssertionError(
        f"套餐表格未稳定到期望集合: 期望{sorted(expected)}, count={last_count}, names={last_names}"
    )


@pytest.mark.auth
@pytest.mark.ppp_package
class TestPppPackageComprehensive:
    """套餐管理综合测试 - 一次测试覆盖所有功能"""

    def test_ppp_package_comprehensive(self, ppp_package_page_logged_in: PppPackagePage,
                                       step_recorder: StepRecorder, request):
        """综合测试: 添加 -> 编辑 -> 复制 -> 删除 -> 搜索 -> 导出 -> 异常 -> 批量删除 -> 导入 -> 帮助"""
        page = ppp_package_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []
        ui_failures = []
        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        def verify_package_active(pkg, label):
            return ssh_verify(
                f"L1-数据库-{label}({pkg['packname']})",
                backend_verifier.verify_ppp_package_database,
                pkg["packname"], must_pass=True,
                expected_fields=_expected_package_fields(pkg),
            )

        def verify_package_absent(packname, label):
            return ssh_verify(
                f"L1-删除-{label}({packname})",
                backend_verifier.verify_ppp_package_not_exists,
                packname, must_pass=True,
            )

        # 测试数据 - 8条套餐, 覆盖各种 packtime/price/限速 组合(后端 packname≤15 字符)
        test_packages = [
            {"packname": "pkg_t_min_m", "packtime": "1m", "price": 0, "up_speed": 0,
             "down_speed": 0, "comment": "", "desc": "最小套餐-1月/全0"},
            {"packname": "pkg_t_day_d", "packtime": "30d", "price": 10, "up_speed": 512,
             "down_speed": 1024, "comment": "包月30天", "desc": "天周期-30天"},
            {"packname": "pkg_t_hour_h", "packtime": "12h", "price": 5, "up_speed": 1024,
             "down_speed": 2048, "comment": "12小时", "desc": "小时周期-12h"},
            {"packname": "pkg_t_max_m", "packtime": "999m", "price": 999, "up_speed": 999999,
             "down_speed": 999999, "comment": "边界最大值", "desc": "边界-999月/最大价/最大速"},
            {"packname": "pkg_t_uponly", "packtime": "1m", "price": 20, "up_speed": 2048,
             "down_speed": 0, "comment": "仅限上行", "desc": "仅上行限速"},
            {"packname": "pkg_t_downonly", "packtime": "1m", "price": 20, "up_speed": 0,
             "down_speed": 4096, "comment": "仅限下行", "desc": "仅下行限速"},
            {"packname": "pkg_t_longcmt", "packtime": "6m", "price": 100, "up_speed": 8192,
             "down_speed": 8192, "comment": "长备注测试用于验证备注字段边界情况abc", "desc": "长备注"},
            {"packname": "pkg_t_中文", "packtime": "1m", "price": 50, "up_speed": 1024,
             "down_speed": 1024, "comment": "中文套餐名", "desc": "中文套餐名"},
        ]

        print("\n" + "=" * 60)
        print("套餐管理综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_packages)} 条套餐")
        for p in test_packages:
            print(f"  - {p['packname']}({p['packtime']},¥{p['price']},"
                  f"↑{p['up_speed']}/↓{p['down_speed']}) - {p['desc']}")

        try:
            # ========== 步骤1: 环境清理(SSH + UI 删除 pkg_t_ 前缀残留) ==========
            with rec.step("步骤1: 检查并清理环境", "清理 pkg_t_ 前缀的套餐残留数据"):
                print("\n[步骤1] 清理环境...")
                rec.add_detail("【环境清理】")
                if backend_verifier is not None:
                    res = backend_verifier.cleanup_ppp_package_test(PREFIX)
                    rec.add_detail(f"  SSH清理: {res}")
                    print(f"  SSH清理: {res}")
                # UI 侧清理残留(非 pkg_t_ 前缀的测试数据兜底)
                page._ensure_package_list()
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(500)
                current = page.get_package_count()
                rec.add_detail(f"  当前套餐数量: {current}")
                if current > 0:
                    leftovers = page.get_package_list()
                    rec.add_detail(f"  残留套餐: {leftovers}")
                    for nm in leftovers:
                        try:
                            page.delete_package(nm)
                            rec.add_detail(f"    删除残留: {nm}")
                        except Exception as e:
                            rec.add_detail(f"    删除残留失败 {nm}: {str(e)[:60]}")
                    page.page.reload()
                    page.page.wait_for_timeout(500)
                _wait_for_package_ui(page, [])
                assert page.get_package_count() == 0, "步骤1清理后页面仍有套餐"
                rec.add_detail("  ✓ 环境干净(0条)")

            # ========== 步骤2: 批量添加8条套餐 ==========
            with rec.step("步骤2: 批量添加套餐", f"添加 {len(test_packages)} 条套餐, 覆盖各种数据组合"):
                print(f"\n[步骤2] 批量添加 {len(test_packages)} 条套餐...")
                rec.add_detail(f"【添加计划】共 {len(test_packages)} 条")
                rec.add_detail("  场景: 月/天/小时周期|边界最大值|仅上行|仅下行|长备注|中文名")
                for pkg in test_packages:
                    rec.add_detail(f"【添加 {pkg['packname']}】")
                    rec.add_detail(f"  有效期: {pkg['packtime']}, 价格: {pkg['price']}, "
                                   f"上行: {pkg['up_speed']}, 下行: {pkg['down_speed']}")
                    if pkg.get("comment"):
                        rec.add_detail(f"  备注: {pkg['comment']}")
                    rec.add_detail(f"  场景: {pkg['desc']}")
                    ok = page.add_package(
                        packname=pkg["packname"], packtime=pkg["packtime"],
                        price=pkg["price"], up_speed=pkg["up_speed"],
                        down_speed=pkg["down_speed"], comment=pkg.get("comment"),
                    )
                    assert ok is True, f"添加套餐 {pkg['packname']} 失败"
                    rec.add_detail(f"  ✓ 添加成功")
                    print(f"  + {pkg['packname']} - {pkg['desc']}")
                # 验证全部添加成功
                page._ensure_package_list()
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(800)
                _wait_for_package_ui(page, [p["packname"] for p in test_packages])
                for pkg in test_packages:
                    assert page.package_exists(pkg["packname"]), f"套餐 {pkg['packname']} 未找到"
                rec.add_detail(f"【验证结果】✓ 所有 {len(test_packages)} 条套餐添加成功")
                print(f"  [OK] 所有 {len(test_packages)} 条套餐添加成功")

            # ========== 步骤3: SSH L1 数据库全字段验证 ==========
            if backend_verifier is not None:
                with rec.step("步骤3: 后台数据验证(SSH L1)", "SSH验证每条套餐的数据库字段"):
                    print("\n[步骤3] 后台数据验证(SSH L1)...")
                    rec.add_detail("【SSH后台L1数据库验证】")
                    passed = 0
                    for pkg in test_packages:
                        rec.add_detail(f"  ── 验证: {pkg['packname']} ──")
                        r = verify_package_active(pkg, "新增")
                        if r is not None and r.passed:
                            passed += 1
                    rec.add_detail(f"  ── 汇总: {passed}/{len(test_packages)} 条套餐L1验证通过 ──")
                    print(f"  [OK] L1验证: {passed}/{len(test_packages)} 通过")
            else:
                print("\n[步骤3] 后台验证: 跳过(未配置SSH)")

            # ========== 步骤4: 编辑套餐 ==========
            with rec.step("步骤4: 编辑套餐", "编辑第1条套餐的价格/限速/备注"):
                print("\n[步骤4] 编辑套餐...")
                edit_pkg = test_packages[0]
                rec.add_detail(f"【编辑操作】目标: {edit_pkg['packname']}")
                assert page.edit_package(edit_pkg["packname"]), "进入编辑页失败"
                rec.add_detail("  1. 点击编辑进入Config页(数据回填)")
                # 修改价格/限速/备注(packname/packtime 保持)
                edit_pkg["price"] = 888
                edit_pkg["up_speed"] = 4096
                edit_pkg["down_speed"] = 8192
                edit_pkg["comment"] = "编辑后备注"
                page.fill_price(edit_pkg["price"])
                page.fill_up_speed(edit_pkg["up_speed"])
                page.fill_down_speed(edit_pkg["down_speed"])
                page.fill_comment(edit_pkg["comment"])
                rec.add_detail(f"  2. 改价格={edit_pkg['price']}/上行={edit_pkg['up_speed']}/"
                               f"下行={edit_pkg['down_speed']}/备注={edit_pkg['comment']}")
                page.click_save()
                assert page._save_success(), "编辑保存失败"
                rec.add_detail("  3. 保存成功")
                page._ensure_package_list()
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(500)
                _wait_for_package_ui(page, [p["packname"] for p in test_packages])
                assert page.package_exists(edit_pkg["packname"]), "编辑后套餐未找到"
                rec.add_detail(f"  ✓ 编辑成功: {edit_pkg['packname']}")
                print(f"  [OK] 编辑成功: {edit_pkg['packname']}")
                if backend_verifier is not None:
                    verify_package_active(edit_pkg, "编辑后")

            # ========== 步骤5: 复制功能(套餐特有) ==========
            with rec.step("步骤5: 复制功能", "复制一条套餐→改名→保存→验证新套餐"):
                print("\n[步骤5] 复制功能...")
                rec.add_detail("【复制操作】")
                src_pkg = test_packages[2]  # pkg_t_hour_h
                copy_name = "pkg_t_copy1"
                rec.add_detail(f"  源套餐: {src_pkg['packname']}")
                rec.add_detail(f"  新名称: {copy_name}")
                # 清理可能残留的同名
                if page.package_exists(copy_name):
                    page.delete_package(copy_name)
                assert page.copy_package(src_pkg["packname"]), "进入复制页失败"
                rec.add_detail("  1. 点击复制进入Config页(预填源套餐数据)")
                # 改名后保存(其余字段沿用源套餐)
                page.fill_packname(copy_name)
                rec.add_detail(f"  2. 改名: {src_pkg['packname']} → {copy_name}")
                page.click_save()
                assert page._save_success(), "复制保存失败"
                rec.add_detail("  3. 保存成功")
                page._ensure_package_list()
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(500)
                expected_after_copy = [p["packname"] for p in test_packages] + [copy_name]
                _wait_for_package_ui(page, expected_after_copy)
                assert page.package_exists(copy_name), "复制的新套餐未找到"
                rec.add_detail(f"  ✓ 复制成功: {copy_name}(字段同源套餐)")
                print(f"  [OK] 复制成功: {copy_name}")
                if backend_verifier is not None:
                    copied = dict(src_pkg)
                    copied["packname"] = copy_name
                    verify_package_active(copied, "复制")
                # 复制产生的套餐计入待清理(后续批量删除会带上)
                copy_pkg = dict(src_pkg)
                copy_pkg["packname"] = copy_name
                test_packages.append(copy_pkg)

            # ========== 步骤6: 删除1条套餐 ==========
            with rec.step("步骤6: 删除套餐", "删除1条套餐 + SSH删除验证"):
                print("\n[步骤6] 删除套餐...")
                del_pkg = test_packages[3]  # pkg_t_max_m
                del_name = del_pkg["packname"]
                rec.add_detail(f"【删除操作】目标: {del_name}")
                count_before = page.get_package_count()
                rec.add_detail(f"  删除前数量: {count_before}")
                assert page.delete_package(del_name), f"删除 {del_name} 失败"
                rec.add_detail("  1. 点击删除 + 确认弹窗")
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(500)
                survivors = [p for p in test_packages if p is not del_pkg]
                _wait_for_package_ui(page, [p["packname"] for p in survivors])
                count_after = page.get_package_count()
                rec.add_detail(f"  删除后数量: {count_after}")
                assert count_after == count_before - 1, (
                    f"删除应只减1条: {count_before}->{count_after}"
                )
                assert not page.package_exists(del_name), f"删除目标仍存在: {del_name}"
                test_packages.remove(del_pkg)
                rec.add_detail(f"  ✓ 删除成功: {del_name}")
                print(f"  [OK] 删除成功: {del_name}")
                if backend_verifier is not None:
                    verify_package_absent(del_name, "单条删除")

            # ========== 步骤7: 搜索测试 ==========
            with rec.step("步骤7: 搜索功能测试", "搜索存在/不存在/清空"):
                print("\n[步骤7] 搜索测试...")
                rec.add_detail("【搜索测试】")
                # 7.1 搜索存在的套餐
                target = test_packages[1]["packname"]
                rec.add_detail(f"  测试1: 搜索存在套餐 {target}")
                page.search_rule(target)
                page.page.wait_for_timeout(800)
                _wait_for_package_ui(page, [target])
                assert page.package_exists(target), f"搜索不到存在的套餐: {target}"
                assert page.get_package_count() == 1, "精确搜索结果不止1条"
                rec.add_detail(f"    ✓ 搜索成功, 精确1条")
                print(f"  [OK] 搜索存在: {target}")
                # 7.2 搜索不存在
                rec.add_detail(f"  测试2: 搜索不存在套餐")
                page.search_rule("not_exist_pkg_xxx")
                page.page.wait_for_timeout(800)
                _wait_for_package_ui(page, [], timeout_ms=8000)
                assert page.get_package_count() == 0, "搜索不存在应显示0条"
                rec.add_detail(f"    ✓ 显示0条")
                print(f"  [OK] 搜索不存在: 0条")
                # 7.3 清空搜索
                rec.add_detail(f"  测试3: 清空搜索")
                page.clear_search()
                page.page.wait_for_timeout(800)
                _wait_for_package_ui(page, [p["packname"] for p in test_packages])
                remaining = page.get_package_count()
                assert remaining == len(test_packages), (
                    f"清空后应{len(test_packages)}条, 实际{remaining}条"
                )
                rec.add_detail(f"    ✓ 清空成功, 显示 {remaining} 条")
                print(f"  [OK] 清空搜索: {remaining}条")

            # ========== 步骤8: 导出 CSV/TXT ==========
            with rec.step("步骤8: 导出套餐配置", "导出 CSV 和 TXT 两种格式"):
                print("\n[步骤8] 导出配置...")
                rec.add_detail("【导出测试】")
                config = get_config()
                export_csv = config.test_data.get_export_path("ppp_package", config.get_project_root())
                export_txt = export_csv.replace(".csv", ".txt")
                # CSV
                rec.add_detail(f"  测试1: 导出CSV -> {os.path.basename(export_csv)}")
                assert page.export_rules(use_config_path=True, export_format="csv") is True, "CSV导出失败"
                _assert_export_matches(export_csv, test_packages)
                rec.add_detail(f"    ✓ CSV导出成功, {len(test_packages)}条packname一致")
                print(f"  [OK] CSV导出: {export_csv}")
                page.page.wait_for_timeout(500)
                # TXT
                rec.add_detail(f"  测试2: 导出TXT -> {os.path.basename(export_txt)}")
                assert page.export_rules(use_config_path=True, export_format="txt") is True, "TXT导出失败"
                _assert_export_matches(export_txt, test_packages)
                rec.add_detail(f"    ✓ TXT导出成功, {len(test_packages)}条packname一致")
                print(f"  [OK] TXT导出: {export_txt}")
                page.close_modal_if_exists()
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(500)

            # ========== 步骤9: 异常输入测试 ==========
            with rec.step("步骤9: 异常输入拦截", "测试各种不合规输入的前端校验拦截"):
                print("\n[步骤9] 异常输入测试...")
                validation_failures = []

                def record_rejection(result, value, desc, target_name, already_exists=False):
                    """异常用例必须是明确校验拒绝, 普通异常不算通过。

                    already_exists: target_name 本来就存在(如"名称重复"用例复用已建套餐名),
                        此时 created/verify_absent 判断无意义(目标合法存在), 只看前端是否拦截。
                    """
                    rejected = bool(result.get("has_validation_error")) and not result.get("success")
                    error_msg = result.get("error_msg") or "未返回校验提示"
                    created = False
                    if not already_exists:
                        created = page.package_exists(target_name)
                        if created:
                            page.delete_package(target_name)
                            validation_failures.append(f"{desc}: 非法配置被写入({target_name})")
                    if not rejected:
                        validation_failures.append(
                            f"{desc}: 未得到明确校验拒绝(success={result.get('success')}, "
                            f"has_validation_error={result.get('has_validation_error')})"
                        )
                    if backend_verifier is not None and not already_exists:
                        verify_package_absent(target_name, f"异常输入-{desc}")
                    if rejected and not created:
                        rec.add_detail(f"  ✓ 输入'{value}' ({desc})")
                        rec.add_detail(f"    提示: {error_msg}")
                        print(f"    [OK] {desc}: 拦截 - {error_msg}")
                        return True
                    rec.add_detail(f"  ✗ 输入'{value}' ({desc}): 未被可靠拦截")
                    print(f"    [FAIL] {desc}: 未拦截")
                    return False

                # 9.1 套餐名称重复
                rec.add_detail("【9.1 名称重复】")
                dup_src = test_packages[0]["packname"]
                r = page.try_add_package_invalid(packname=dup_src, packtime="1m",
                                                 price=1, up_speed=1, down_speed=1)
                record_rejection(r, dup_src, "名称重复", dup_src, already_exists=True)
                page.page.wait_for_timeout(300)

                # 9.2 套餐名称超长(>24字符, 前端校验上限)
                rec.add_detail("【9.2 名称超长(>24)】")
                long_name = "pkg_t_way_too_long_name_xxxxx"
                r = page.try_add_package_invalid(packname=long_name, packtime="1m",
                                                 price=1, up_speed=1, down_speed=1)
                record_rejection(r, long_name, "名称超长>24", long_name)
                page.page.wait_for_timeout(300)

                # 9.3 套餐名称为空
                rec.add_detail("【9.3 名称为空】")
                r = page.try_add_package_invalid(packname="", packtime="1m",
                                                 price=1, up_speed=1, down_speed=1)
                record_rejection(r, "(空)", "名称为空", "")
                page.page.wait_for_timeout(300)

                # 9.4 有效期为空
                rec.add_detail("【9.4 有效期为空】")
                r = page.try_add_package_invalid(packname="pkg_t_badtime", packtime="",
                                                 price=1, up_speed=1, down_speed=1)
                record_rejection(r, "(空)", "有效期为空", "pkg_t_badtime")
                page.page.wait_for_timeout(300)

                # 9.5 价格超范围(>99999)
                rec.add_detail("【9.5 价格超范围(>99999)】")
                r = page.try_add_package_invalid(packname="pkg_t_badprice", packtime="1m",
                                                 price=100000, up_speed=1, down_speed=1)
                record_rejection(r, "100000", "价格超范围", "pkg_t_badprice")
                page.page.wait_for_timeout(300)

                # 9.6 上行带宽超范围(>999999)
                rec.add_detail("【9.6 上行带宽超范围(>999999)】")
                r = page.try_add_package_invalid(packname="pkg_t_badup", packtime="1m",
                                                 price=1, up_speed=1000000, down_speed=1)
                record_rejection(r, "1000000", "上行超范围", "pkg_t_badup")
                page.page.wait_for_timeout(300)

                # 9.7 下行带宽超范围(>999999)
                rec.add_detail("【9.7 下行带宽超范围(>999999)】")
                r = page.try_add_package_invalid(packname="pkg_t_baddown", packtime="1m",
                                                 price=1, up_speed=1, down_speed=1000000)
                record_rejection(r, "1000000", "下行超范围", "pkg_t_baddown")
                page.page.wait_for_timeout(300)

                # 9.8 ⚠ BUG诊断: packname 16字符(后端脚本≤15, 前端文案称1-24)
                # 直接操控表单 + SSH权威查DB, 不依赖 try_add_package_invalid(其 status-error 样式会干扰判断)
                rec.add_detail("【9.8 packname 16字符-前后端字符限制一致性】")
                name16 = "pkg_t_16chars_xx"  # 16字符(超后端15/在前端文案24内, 字符均合法)
                page._ensure_package_list()
                page.click_add_button()
                try:
                    page.page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                page._fill_form(name16, "1m", 1, 1, 1, "")
                page.click_save()
                page.page.wait_for_timeout(1200)
                # 前端明确文案提示(.ant-form-item-explain-error, 不受 status-error 样式干扰)
                explain_texts = page.page.locator(".ant-form-item-explain-error").all_text_contents()
                explain_msg = "; ".join(t.strip() for t in explain_texts if t.strip())
                form_open = page.page.locator("#packname").count() > 0
                # SSH 权威查 DB 是否写入
                db_exists = False
                if backend_verifier is not None:
                    db_exists = backend_verifier.find_ppp_package_rule(name16) is not None
                page._ensure_package_list()
                ui_exists = page.package_exists(name16)
                print(f"    [9.8] name16={name16} 前端提示='{explain_msg}' "
                      f"表单仍开={form_open} UI存在={ui_exists} DB存在={db_exists}")
                rec.add_detail(f"  [诊断] 前端提示='{explain_msg or '(无)'}' 表单仍开={form_open} "
                               f"UI存在={ui_exists} DB存在={db_exists}")
                if db_exists:
                    rec.add_detail("  【⚠ BUG记录】packname 16字符被后端接受写入DB(超出脚本≤15限制), "
                                   "前后端长度校验均未生效")
                    print("    [BUG] 16字符被写入DB(超限)")
                    page.delete_package(name16)
                elif not explain_msg and form_open:
                    # DB未写入 + 无明确提示 + 表单仍开 = 静默失败(Playwright探索确认的现象)
                    rec.add_detail(
                        "  【⚠ BUG记录】packname 16字符: 前端校验文案为'仅支持中文、英文、数字,"
                        "长度限制1-24字符'(放行16字符无提示), 但后端 ppp_package.sh 限制 "
                        "unicode_length<=15 静默拒绝, 数据库未写入, 前端既不跳转也不报错——"
                        "用户无任何反馈。建议前端校验上限改为15与后端一致, 或后端拒绝时前端给出提示。"
                    )
                    print("    [BUG] packname 16字符静默失败(前端无提示/后端≤15拒绝/DB未写入)")
                else:
                    rec.add_detail(f"  [OK] 16字符被明确拦截: {explain_msg or '表单已关闭'}")
                    print(f"    [OK] 16字符拦截: {explain_msg or 'form closed'}")
                if ui_exists:
                    try:
                        page.delete_package(name16)
                    except Exception:
                        pass

                assert not validation_failures, (
                    f"异常输入验证失败({len(validation_failures)}项): {validation_failures}"
                )
                rec.add_detail(f"  ── 异常输入汇总: 7/7 项明确校验拦截 + 1项BUG软记录 ──")
                _wait_for_package_ui(page, [p["packname"] for p in test_packages])
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(500)

            # ========== 步骤10: 批量删除(3次重试) ==========
            with rec.step("步骤10: 批量删除套餐", f"批量删除剩余 {len(test_packages)} 条套餐"):
                print(f"\n[步骤10] 批量删除 {len(test_packages)} 条套餐...")
                rec.add_detail("【批量删除(3次重试)】")
                delete_success = False
                for attempt in range(3):
                    page.page.reload()
                    page.page.wait_for_timeout(500)
                    if not page.select_all_rules():
                        rec.add_detail(f"  第{attempt+1}次: 全选未生效, 重试")
                        continue
                    selected = page.get_selected_count()
                    if selected != len(test_packages):
                        rec.add_detail(f"  第{attempt+1}次: 全选数量{selected}≠{len(test_packages)}, 重试")
                        page.page.wait_for_timeout(500)
                        continue
                    rec.add_detail(f"  第{attempt+1}次: 已精确选中 {selected} 条")
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)
                    page.page.reload()
                    page.page.wait_for_timeout(500)
                    try:
                        _wait_for_package_ui(page, [], timeout_ms=5000)
                        delete_success = True
                        break
                    except AssertionError:
                        pass
                    rec.add_detail(f"  第{attempt+1}次: 仍有残留, 重试")
                if delete_success:
                    rec.add_detail(f"  ✓ 批量删除成功(重试{attempt+1}次)")
                    print(f"  [OK] 批量删除成功(重试{attempt+1}次)")
                else:
                    still = [p["packname"] for p in test_packages if page.package_exists(p["packname"])]
                    ssh_failures.append(f"步骤10-批量删除: {still} 仍存在")
                    rec.add_detail(f"  ✗ 3次重试后仍存在: {still}")
                    print(f"  [WARN] 仍存在: {still}")
                if backend_verifier is not None:
                    deleted_passed = sum(
                        1 for p in test_packages if verify_package_absent(p["packname"], "批量删除")
                    )
                    rec.add_detail(f"  ── 批量删除后台汇总: {deleted_passed}/{len(test_packages)}条无残留 ──")
                assert page.get_package_count() == 0, "步骤10批量删除后数量不为0"

            # ========== 步骤11: 导入 CSV(不清空) ==========
            with rec.step("步骤11: 导入CSV配置", "使用导出的CSV文件导入(不清空现有)"):
                print("\n[步骤11] 导入CSV...")
                rec.add_detail("【导入CSV(不清空)】")
                assert os.path.exists(export_csv), f"CSV文件不存在: {export_csv}"
                rec.add_detail(f"  导入文件: {os.path.basename(export_csv)}")
                rec.add_detail(f"  导入前数量: {page.get_package_count()}")
                rec.add_detail("  清空现有数据: 否")
                result = page.import_rules(export_csv, clear_existing=False)
                assert result is True, "CSV导入失败"
                rec.add_detail(f"  ✓ 导入操作完成")
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(800)
                # 导入的是步骤8导出时的8条(不含复制/已删), 用导出文件packname集合校验
                exported_names = {p["packname"] for p in _read_package_export(export_csv)}
                _wait_for_package_ui(page, exported_names)
                count_after = page.get_package_count()
                assert count_after == len(exported_names), (
                    f"CSV导入后应有{len(exported_names)}条, 实际{count_after}条"
                )
                rec.add_detail(f"  导入后数量: {count_after}, 集合精确一致")
                print(f"  [OK] CSV导入 {count_after} 条")
                if backend_verifier is not None:
                    # 用导出文件内容重建期望(字段值与原始test_packages一致)
                    imported_passed = 0
                    for row in _read_package_export(export_csv):
                        nm = row.get("packname")
                        if not nm:
                            continue
                        pkg = {"packname": nm, "packtime": row.get("packtime", ""),
                               "price": row.get("price", "0"), "up_speed": row.get("up_speed", "0"),
                               "down_speed": row.get("down_speed", "0"), "comment": row.get("comment", "")}
                        r = verify_package_active(pkg, "CSV导入")
                        if r is not None and r.passed:
                            imported_passed += 1
                    rec.add_detail(f"  ── CSV导入后台汇总: {imported_passed}条L1验证通过 ──")

            # ========== 步骤12: 导入 TXT(清空) ==========
            with rec.step("步骤12: 导入TXT配置", "使用导出的TXT文件清空后导入"):
                print("\n[步骤12] 导入TXT(清空)...")
                rec.add_detail("【导入TXT(清空现有)】")
                assert os.path.exists(export_txt), f"TXT文件不存在: {export_txt}"
                rec.add_detail(f"  导入文件: {os.path.basename(export_txt)}")
                rec.add_detail(f"  导入前数量: {page.get_package_count()}")
                rec.add_detail("  清空现有数据: 是")
                result = page.import_rules(export_txt, clear_existing=True)
                assert result is True, "TXT清空导入失败"
                rec.add_detail(f"  ✓ 导入操作完成")
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(800)
                exported_names = {p["packname"] for p in _read_package_export(export_txt)}
                _wait_for_package_ui(page, exported_names)
                count_after = page.get_package_count()
                assert count_after == len(exported_names), (
                    f"TXT清空导入后应有{len(exported_names)}条, 实际{count_after}条"
                )
                rec.add_detail(f"  导入后数量: {count_after}, 集合精确一致且无重复")
                print(f"  [OK] TXT清空导入 {count_after} 条")

            # ========== 步骤13: 清理环境 ==========
            with rec.step("步骤13: 清理环境", "清理导入产生的套餐数据"):
                print("\n[步骤13] 清理环境...")
                rec.add_detail("【环境清理】")
                page._ensure_package_list()
                page.page.reload()
                page.page.wait_for_load_state("networkidle")
                page.page.wait_for_timeout(800)
                current = page.get_package_count()
                rec.add_detail(f"  当前套餐数量: {current}")
                if current > 0:
                    if page.select_all_rules():
                        sel = page.get_selected_count()
                        rec.add_detail(f"  全选 {sel} 条, 批量删除")
                        page.batch_delete()
                        page.page.wait_for_timeout(1500)
                        page.page.reload()
                        page.page.wait_for_load_state("networkidle")
                        page.page.wait_for_timeout(500)
                    # 逐个兜底
                    for nm in list(page.get_package_list()):
                        if page.package_exists(nm):
                            page.delete_package(nm)
                _wait_for_package_ui(page, [])
                final_count = page.get_package_count()
                assert final_count == 0, f"清理后仍有{final_count}条"
                rec.add_detail(f"  ✓ 清理完成, 剩余 {final_count} 条")
                print(f"  [OK] 清理完成, 剩余 {final_count} 条")
                if backend_verifier is not None:
                    cnt = backend_verifier.verify_ppp_package_count()
                    rec.add_detail(f"  SSH-L1计数: {cnt.message}")
                    # 兜底SSH清理
                    res = backend_verifier.cleanup_ppp_package_test(PREFIX)
                    rec.add_detail(f"  SSH兜底清理: {res}")

            # ========== 步骤14: 帮助功能 ==========
            with rec.step("步骤14: 帮助功能测试", "右下角帮助按钮→popover+新标签页跳转文档"):
                print("\n[步骤14] 帮助功能...")
                rec.add_detail("【帮助功能测试】")
                help_result = page.test_help_functionality()
                rec.add_detail(f"  帮助图标可点击: {help_result['icon_clickable']}")
                rec.add_detail(f"  帮助面板可见: {help_result['panel_visible']}")
                if help_result["has_content"]:
                    preview = help_result["content_text"][:80]
                    rec.add_detail(f"  帮助内容: {preview}")
                rec.add_detail(f"  跳转新页面: {help_result['new_page_opened']}")
                rec.add_detail(f"  面板可关闭: {help_result['can_close']}")
                help_failures = []
                if not help_result.get("icon_clickable"):
                    help_failures.append("帮助图标不可点击")
                if not help_result.get("panel_visible"):
                    help_failures.append("帮助面板未显示")
                if not help_result.get("has_content"):
                    help_failures.append("帮助面板无内容")
                if not help_result.get("new_page_opened"):
                    help_failures.append("点击帮助未打开新页面")
                if not help_result.get("can_close"):
                    help_failures.append("帮助面板无法关闭")
                if help_failures:
                    rec.add_detail(f"  ✗ 帮助功能问题: {help_failures}")
                    ui_failures.extend(help_failures)
                else:
                    rec.add_detail("  ✓ 帮助功能测试通过")
                    print("  [OK] 帮助功能通过")
                assert not help_failures, f"帮助功能验证失败: {help_failures}"

            print("\n" + "=" * 60)
            print("套餐管理综合测试完成")
            print("覆盖: 添加8条/编辑/复制/删除/搜索/导出CSV+TXT/异常输入7+1BUG/批量删除/导入CSV+TXT/清理/帮助")
            print("=" * 60)

        finally:
            # 兜底清理: 无论测试是否中途失败, 都清理 pkg_t_ 前缀的套餐
            try:
                if backend_verifier is not None:
                    res = backend_verifier.cleanup_ppp_package_test(PREFIX)
                    print(f"[finally SSH清理] {res}")
            except Exception as e:
                print(f"[finally SSH清理异常] {str(e)[:80]}")
            try:
                page._ensure_package_list()
                page.page.reload()
                page.page.wait_for_timeout(800)
                for nm in list(page.get_package_list()):
                    if nm.startswith(PREFIX) or nm.startswith("pkg_t_"):
                        try:
                            page.delete_package(nm)
                        except Exception:
                            pass
            except Exception as e:
                print(f"[finally UI清理异常] {str(e)[:80]}")

        # ========== 末尾硬断言 ==========
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, (
            f"套餐管理验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
        )
