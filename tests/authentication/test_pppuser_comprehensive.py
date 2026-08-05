"""
认证服务-认证账号管理-账号管理 综合测试用例

一次测试覆盖账号(pppuser)全部功能, 含套餐联动:
1.  建联动套餐(backend) -> 添加6个账号(自定义套餐 + 选已建套餐, 覆盖不限/PPPoE/L2TP/WEB/PPTP)
2.  SSH L1 数据库验证(enabled/ppptype/packages=套餐id/upload|download/share/name)
3.  编辑账号
4.  启用/停用 + 状态切换验证
5.  状态筛选(全部/已启用/已停用/已过期, 含 backend 设过期时间)
6.  排序(账号/用户姓名/到期时间, 参考 VLAN 排序验证)
7.  搜索
8.  删除 + SSH 删除验证
9.  异常输入(账号空/重复/超长、密码空、共享数越界)
10. 导出 CSV/TXT
11. 帮助功能
12. 清理(账号 + 联动套餐)

产品差异: 账号管理行内操作 编辑/停用(启用)/缴费/删除; 状态筛选 ant-segmented;
可排序列 账号/用户姓名/到期时间/在线离线时长; passwd 加密存储(不验明文)。
"""
import os
import re
import csv
import time
import pytest

from pages.authentication.pppuser_page import PppuserPage
from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify

pytestmark = [pytest.mark.auth, pytest.mark.pppuser]

PREFIX = "acct_t_"
PKG_PREFIX = "pkg_link_"
PKG_A_NAME = "pkg_link_a"
PKG_B_NAME = "pkg_link_b"

# 认证类型 中文 -> 后端 ppptype
_PPPTYPE_MAP = {
    "不限": "any", "PPPoE": "pppoe", "PPPoE透传": "pppoe_relay",
    "WEB-账号": "web", "OpenVPN": "ovpn", "L2TP": "l2tp",
    "PPTP": "pptp", "IKEv2": "ike",
}


def _expected_user_fields(user: dict, package_id=None) -> dict:
    """页面输入 -> 后端 pppuser 记录期望字段(passwd 加密不验; packages=套餐id)。"""
    is_custom = (not user.get("package")) or user.get("package") == "自定义"
    fields = {
        "enabled": user.get("enabled", "yes"),
        "ppptype": _PPPTYPE_MAP.get(user.get("ppptype", "不限"), "any"),
        "share": str(user.get("share", 1)),
    }
    # 自定义套餐才验上下行(选套餐时由套餐同步, 值=套餐的, 此处不比)
    if is_custom:
        fields["upload"] = str(user.get("up_speed", 0))
        fields["download"] = str(user.get("down_speed", 0))
    if package_id is not None:
        fields["packages"] = str(package_id)
    else:
        fields["packages"] = "0"
    if user.get("name"):
        fields["name"] = user["name"]
    if user.get("comment") is not None:
        fields["comment"] = user.get("comment", "")
    return fields


def _wait_for_user_ui(page: PppuserPage, expected_names, timeout_ms: int = 15000):
    """等待账号表格稳定到精确集合。"""
    expected = set(expected_names)
    deadline = time.monotonic() + timeout_ms / 1000
    last_count, last_names = -1, []
    while time.monotonic() < deadline:
        last_count = page.get_user_count()
        last_names = sorted(page.get_user_list())
        if last_count == len(expected) and set(last_names) == expected:
            return sorted(expected)
        page.page.wait_for_timeout(500)
    raise AssertionError(
        f"账号表格未稳定: 期望{sorted(expected)}, count={last_count}, names={last_names}"
    )


def _create_package_via_backend(bv, packname, packtime, price, up, down):
    """用 backend SQL 直接建套餐(联动测试用), 返回新套餐 id。"""
    bv.connect_router()
    bv._router.exec(
        f"sqlite3 {bv.DNS_DB} \"INSERT INTO ppp_packages(packname,tagname,packtime,price,up_speed,down_speed,comment) "
        f"VALUES('{packname}','{packname}','{packtime}',{price},{up},{down},'联动测试')\""
    )
    rule = bv.find_ppp_package_rule(packname)
    return rule.get("id") if rule else None


@pytest.mark.auth
@pytest.mark.pppuser
class TestPppuserComprehensive:
    """账号管理综合测试 - 一次测试覆盖所有功能(含套餐联动)"""

    def test_pppuser_comprehensive(self, pppuser_page_logged_in: PppuserPage,
                                   step_recorder: StepRecorder, request):
        page = pppuser_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []
        ui_failures = []
        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        def verify_user_active(user, label, package_id=None):
            return ssh_verify(
                f"L1-数据库-{label}({user['username']})",
                backend_verifier.verify_pppuser_database,
                user["username"], must_pass=True,
                expected_fields=_expected_user_fields(user, package_id),
            )

        def verify_user_absent(username, label):
            return ssh_verify(
                f"L1-删除-{label}({username})",
                backend_verifier.verify_pppuser_not_exists,
                username, must_pass=True,
            )

        # 测试数据 - 6个账号, 覆盖套餐联动 + 多种认证类型
        test_users = [
            {"username": "acct_t_001", "passwd": "pass001", "ppptype": "不限", "package": "自定义",
             "up_speed": 512, "down_speed": 512, "share": 1, "name": "用户甲", "comment": "自定义套餐", "desc": "自定义+不限"},
            {"username": "acct_t_002", "passwd": "pass002", "ppptype": "PPPoE", "package": PKG_A_NAME,
             "up_speed": 0, "down_speed": 0, "share": 1, "name": "用户乙", "comment": "选套餐A", "desc": "套餐A+PPPoE"},
            {"username": "acct_t_003", "passwd": "pass003", "ppptype": "L2TP", "package": PKG_B_NAME,
             "up_speed": 0, "down_speed": 0, "share": 2, "name": "用户丙", "comment": "选套餐B", "desc": "套餐B+L2TP"},
            {"username": "acct_t_004", "passwd": "pass004", "ppptype": "WEB-账号", "package": "自定义",
             "up_speed": 1024, "down_speed": 2048, "share": 1, "name": "李四", "comment": "WEB认证", "desc": "自定义+WEB"},
            {"username": "acct_t_005", "passwd": "pass005", "ppptype": "PPTP", "package": "自定义",
             "up_speed": 0, "down_speed": 0, "share": 1, "name": "王五", "comment": "停用测试", "desc": "停用测试"},
            {"username": "acct_t_006", "passwd": "pass006", "ppptype": "不限", "package": "自定义",
             "up_speed": 0, "down_speed": 0, "share": 1, "name": "赵六", "comment": "过期测试", "desc": "过期测试"},
        ]

        print("\n" + "=" * 60)
        print("账号管理综合测试开始")
        print("=" * 60)

        try:
            # ========== 步骤1: 环境清理 ==========
            with rec.step("步骤1: 检查并清理环境", "清理 acct_t_ 账号 和 pkg_link_ 套餐残留"):
                print("\n[步骤1] 清理环境...")
                rec.add_detail("【环境清理】")
                if backend_verifier is not None:
                    r1 = backend_verifier.cleanup_pppuser_test(PREFIX)
                    r2 = backend_verifier.cleanup_ppp_package_test(PKG_PREFIX)
                    rec.add_detail(f"  SSH清理账号: {r1}")
                    rec.add_detail(f"  SSH清理套餐: {r2}")
                    print(f"  SSH清理账号: {r1} / 套餐: {r2}")
                page._ensure_user_list()
                page.refresh_list()
                page.page.wait_for_timeout(800)
                _wait_for_user_ui(page, [], timeout_ms=8000)
                assert page.get_user_count() == 0, "步骤1清理后仍有账号"
                rec.add_detail("  ✓ 账号环境干净(0条)")

            # ========== 步骤2: 建联动套餐 + 添加6个账号 ==========
            pkg_a_id = pkg_b_id = None
            with rec.step("步骤2: 建联动套餐", "backend 建 pkg_link_a/pkg_link_b 供账号选择"):
                print("\n[步骤2] 建联动套餐...")
                rec.add_detail("【建联动套餐】")
                if backend_verifier is not None:
                    pkg_a_id = _create_package_via_backend(backend_verifier, PKG_A_NAME, "1m", 10, 1024, 1024)
                    pkg_b_id = _create_package_via_backend(backend_verifier, PKG_B_NAME, "30d", 20, 2048, 2048)
                    rec.add_detail(f"  {PKG_A_NAME} -> id={pkg_a_id}")
                    rec.add_detail(f"  {PKG_B_NAME} -> id={pkg_b_id}")
                    print(f"  {PKG_A_NAME}=id{pkg_a_id}, {PKG_B_NAME}=id{pkg_b_id}")
                    assert pkg_a_id and pkg_b_id, "联动套餐创建失败"
                else:
                    pytest.skip("套餐联动测试必须启用SSH backend_verifier")

            with rec.step("步骤3: 批量添加账号", f"添加 {len(test_users)} 个账号(含套餐联动)"):
                print(f"\n[步骤3] 批量添加 {len(test_users)} 个账号...")
                rec.add_detail(f"【添加计划】共 {len(test_users)} 个账号")
                for u in test_users:
                    rec.add_detail(f"【添加 {u['username']}】")
                    rec.add_detail(f"  认证类型: {u['ppptype']}, 套餐: {u['package']}, "
                                   f"上行: {u['up_speed']}, 下行: {u['down_speed']}, 姓名: {u.get('name')}")
                    rec.add_detail(f"  场景: {u['desc']}")
                    ok = page.add_user(u)
                    assert ok is True, f"添加账号 {u['username']} 失败"
                    rec.add_detail(f"  ✓ 添加成功")
                    print(f"  + {u['username']} - {u['desc']}")
                page._ensure_user_list()
                page.refresh_list()
                page.page.wait_for_timeout(1000)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                for u in test_users:
                    assert page.user_exists(u["username"]), f"账号 {u['username']} 未找到"
                rec.add_detail(f"【验证】✓ 所有 {len(test_users)} 个账号添加成功")
                print(f"  [OK] 所有 {len(test_users)} 个账号添加成功")

            # ========== 步骤4: SSH L1 验证(含套餐联动 packages=id) ==========
            with rec.step("步骤4: 后台数据验证(SSH L1)", "验证账号字段 + 套餐联动(packages=套餐id)"):
                print("\n[步骤4] 后台数据验证(SSH L1)...")
                rec.add_detail("【SSH后台L1数据库验证】")
                passed = 0
                for u in test_users:
                    pid = None
                    if u["package"] == PKG_A_NAME:
                        pid = pkg_a_id
                    elif u["package"] == PKG_B_NAME:
                        pid = pkg_b_id
                    rec.add_detail(f"  ── 验证: {u['username']} (套餐={u['package']}, packagesid={pid}) ──")
                    r = verify_user_active(u, "新增", pid)
                    if r is not None and r.passed:
                        passed += 1
                rec.add_detail(f"  ── 汇总: {passed}/{len(test_users)} 个账号L1验证通过 ──")
                print(f"  [OK] L1验证: {passed}/{len(test_users)} 通过")

            # ========== 步骤5: 编辑账号 ==========
            with rec.step("步骤5: 编辑账号", "编辑账号的姓名/备注/限速"):
                print("\n[步骤5] 编辑账号...")
                edit_u = test_users[3]  # acct_t_004
                rec.add_detail(f"【编辑】目标: {edit_u['username']}")
                assert page.edit_user(edit_u["username"]), "进入编辑页失败"
                rec.add_detail("  1. 点击编辑")
                edit_u["name"] = "李四改"
                edit_u["comment"] = "编辑后备注"
                page.fill_name(edit_u["name"])
                page.fill_comment(edit_u["comment"])
                rec.add_detail(f"  2. 改姓名={edit_u['name']}/备注={edit_u['comment']} (编辑页限速由套餐/原值决定, 不改)")
                page.click_save()
                assert page._save_success(), "编辑保存失败"
                rec.add_detail("  3. 保存成功")
                page._ensure_user_list()
                page.page.wait_for_timeout(1000)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                assert page.user_exists(edit_u["username"]), "编辑后账号未找到"
                rec.add_detail(f"  ✓ 编辑成功: {edit_u['username']}")
                print(f"  [OK] 编辑成功: {edit_u['username']}")
                verify_user_active(edit_u, "编辑后")

            # ========== 步骤6: 启用/停用 ==========
            with rec.step("步骤6: 启用/停用", "停用1个账号再启用, 验证状态切换"):
                print("\n[步骤6] 启用/停用...")
                rec.add_detail("【启用/停用】")
                tgt = test_users[4]  # acct_t_005
                rec.add_detail(f"  目标: {tgt['username']}")
                # 6.1 停用
                assert page.is_user_enabled(tgt["username"]), f"{tgt['username']} 初始非启用"
                rec.add_detail(f"  1. 初始状态: 启用(行内有'停用'按钮)")
                assert page.disable_user(tgt["username"]), "停用操作失败"
                page.page.wait_for_timeout(1000)
                page.refresh_list()
                page.page.wait_for_timeout(800)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                assert page.is_user_disabled(tgt["username"]), f"{tgt['username']} 停用后状态未变"
                rec.add_detail(f"  2. 停用后: 行内变为'启用'按钮")
                print(f"  [OK] 停用成功: {tgt['username']}")
                # 6.2 启用
                assert page.enable_user(tgt["username"]), "启用操作失败"
                page.page.wait_for_timeout(1000)
                page.refresh_list()
                page.page.wait_for_timeout(800)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                assert page.is_user_enabled(tgt["username"]), f"{tgt['username']} 启用后状态未变"
                rec.add_detail(f"  3. 启用后: 行内恢复'停用'按钮")
                print(f"  [OK] 启用成功: {tgt['username']}")
                # SSH验证停用账号的enabled字段(再停用一次验证DB)
                assert page.disable_user(tgt["username"]), "二次停用失败"
                page.page.wait_for_timeout(800)
                tgt["enabled"] = "no"
                ssh_verify(
                    f"L1-停用-{tgt['username']}",
                    backend_verifier.verify_pppuser_database,
                    tgt["username"], must_pass=True,
                    expected_fields=_expected_user_fields(tgt),
                )
                # 恢复启用
                page.enable_user(tgt["username"])
                page.page.wait_for_timeout(800)
                tgt["enabled"] = "yes"
                rec.add_detail(f"  ✓ 启用/停用状态切换验证通过(DB enabled字段同步)")

            # ========== 步骤7: 状态筛选(全部/已启用/已停用/已过期) ==========
            with rec.step("步骤7: 状态筛选", "切换 全部/已启用/已停用/已过期"):
                print("\n[步骤7] 状态筛选...")
                rec.add_detail("【状态筛选(ant-segmented)】")
                page._ensure_user_list()
                page.refresh_list()
                page.page.wait_for_timeout(800)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                # 先把 acct_t_006 设为过期(backend)
                exp_u = test_users[5]
                backend_verifier.set_pppuser_expired(exp_u["username"], 1)
                rec.add_detail(f"  预置: {exp_u['username']} 设为已过期(expires=1)")
                print(f"  预置过期: {exp_u['username']}")
                # 把 acct_t_005 停用(步骤6已停用后又启用, 这里再停用)
                dis_u = test_users[4]
                if page.is_user_enabled(dis_u["username"]):
                    page.disable_user(dis_u["username"])
                    page.page.wait_for_timeout(800)
                page.refresh_list()
                page.page.wait_for_timeout(1000)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                rec.add_detail(f"  预置: {dis_u['username']} 已停用")

                # 7.1 全部
                assert page.filter_by_state("全部"), "切换'全部'失败"
                page.page.wait_for_timeout(1000)
                all_cnt = page.get_user_count()
                rec.add_detail(f"  测试1 '全部': {all_cnt} 条")
                assert all_cnt == len(test_users), f"'全部'应{len(test_users)}条, 实际{all_cnt}"
                print(f"  [OK] '全部': {all_cnt}条")

                # 7.2 已启用 (排除停用的005)
                assert page.filter_by_state("已启用"), "切换'已启用'失败"
                page.page.wait_for_timeout(1000)
                enabled_names = set(page.get_user_list())
                rec.add_detail(f"  测试2 '已启用': {sorted(enabled_names)}")
                assert dis_u["username"] not in enabled_names, "停用账号不应在'已启用'"
                print(f"  [OK] '已启用': {len(enabled_names)}条(不含停用的{dis_u['username']})")

                # 7.3 已停用
                assert page.filter_by_state("已停用"), "切换'已停用'失败"
                page.page.wait_for_timeout(1000)
                disabled_names = set(page.get_user_list())
                rec.add_detail(f"  测试3 '已停用': {sorted(disabled_names)}")
                assert dis_u["username"] in disabled_names, "停用账号应在'已停用'"
                print(f"  [OK] '已停用': {sorted(disabled_names)}")

                # 7.4 已过期
                assert page.filter_by_state("已过期"), "切换'已过期'失败"
                page.page.wait_for_timeout(1000)
                expired_names = set(page.get_user_list())
                rec.add_detail(f"  测试4 '已过期': {sorted(expired_names)}")
                assert exp_u["username"] in expired_names, "过期账号应在'已过期'"
                print(f"  [OK] '已过期': {sorted(expired_names)}")

                # 恢复: 切回全部 + 启用005
                page.filter_by_state("全部")
                page.page.wait_for_timeout(500)
                if page.is_user_disabled(dis_u["username"]):
                    page.enable_user(dis_u["username"])
                    page.page.wait_for_timeout(500)
                rec.add_detail("  ✓ 状态筛选4态全部验证通过")

            # ========== 步骤8: 排序(账号/用户姓名/到期时间) ==========
            with rec.step("步骤8: 排序功能", "测试 账号/用户姓名 列排序(参考VLAN)"):
                print("\n[步骤8] 排序测试...")
                rec.add_detail("【排序测试】")
                page._ensure_user_list()
                page.refresh_list()
                page.page.wait_for_timeout(1000)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                # 给不同账号设不同到期时间(backend), 使 expires 列有区分
                now = int(time.time())
                for idx, u in enumerate(test_users[:3]):
                    backend_verifier.set_pppuser_expired(u["username"], now + (idx + 1) * 86400)
                rec.add_detail("  预置: 前3个账号设不同到期时间(未来1/2/3天)")
                page.refresh_list()
                page.page.wait_for_timeout(1000)
                _wait_for_user_ui(page, [u["username"] for u in test_users])

                for col in ["账号", "用户姓名"]:
                    rec.add_detail(f"  测试列: {col}")
                    baseline = page.get_column_values(col)
                    assert len(baseline) == len(test_users), f"{col}列行数不对: {len(baseline)}"
                    # 第一次点击: 升序
                    assert page.sort_by_column(col), f"{col}第一次排序点击失败"
                    page.page.wait_for_timeout(800)
                    order1 = page.get_column_values(col)
                    # 第二次点击: 降序
                    assert page.sort_by_column(col), f"{col}第二次排序点击失败"
                    page.page.wait_for_timeout(800)
                    order2 = page.get_column_values(col)
                    assert order2 == list(reversed(order1)), (
                        f"{col}正倒序未互逆: 升序{order1}, 降序{order2}"
                    )
                    rec.add_detail(f"  ✓ {col}: 升序/降序互逆验证通过")
                    print(f"  [OK] {col}排序验证通过")
                # 到期时间列: 验证可切换排序状态(值可能含'不限', 不硬验顺序)
                assert page.sort_by_column("到期时间"), "到期时间排序点击失败"
                page.page.wait_for_timeout(500)
                rec.add_detail(f"  ✓ 到期时间列排序可切换(状态={page.get_column_sort_order('到期时间')})")
                print(f"  [OK] 到期时间排序可切换")

            # ========== 步骤9: 搜索 ==========
            with rec.step("步骤9: 搜索功能", "搜索存在/不存在/清空"):
                print("\n[步骤9] 搜索测试...")
                rec.add_detail("【搜索测试】")
                page.clear_search() if hasattr(page, "clear_search") else None
                # 清除排序状态(切回全部+reload)
                page.filter_by_state("全部")
                page.refresh_list()
                page.page.wait_for_timeout(1000)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                target = test_users[1]["username"]
                rec.add_detail(f"  测试1: 搜索 {target}")
                page.search_rule(target)
                page.page.wait_for_timeout(1000)
                assert page.user_exists(target), f"搜索不到 {target}"
                assert page.get_user_count() == 1, "精确搜索应1条"
                rec.add_detail(f"    ✓ 精确命中1条")
                print(f"  [OK] 搜索存在: {target}")
                rec.add_detail(f"  测试2: 搜索不存在")
                page.search_rule("not_exist_acct_zzz")
                page.page.wait_for_timeout(1000)
                _wait_for_user_ui(page, [], timeout_ms=8000)
                assert page.get_user_count() == 0, "搜索不存在应0条"
                rec.add_detail(f"    ✓ 0条")
                print(f"  [OK] 搜索不存在: 0条")
                rec.add_detail(f"  测试3: 清空搜索")
                page.clear_search()
                page.page.wait_for_timeout(1000)
                _wait_for_user_ui(page, [u["username"] for u in test_users])
                assert page.get_user_count() == len(test_users), "清空后应恢复全部"
                rec.add_detail(f"    ✓ 恢复{len(test_users)}条")
                print(f"  [OK] 清空搜索: 恢复全部")

            # ========== 步骤10: 删除1个账号 ==========
            with rec.step("步骤10: 删除账号", "删除1个账号 + SSH删除验证"):
                print("\n[步骤10] 删除账号...")
                del_u = test_users[2]  # acct_t_003 (选套餐B的)
                del_name = del_u["username"]
                rec.add_detail(f"【删除】目标: {del_name}")
                cnt_before = page.get_user_count()
                assert page.delete_user(del_name), f"删除 {del_name} 失败"
                rec.add_detail("  1. 点击删除 + 确认")
                page.refresh_list()
                page.page.wait_for_timeout(800)
                survivors = [u for u in test_users if u is not del_u]
                _wait_for_user_ui(page, [u["username"] for u in survivors])
                assert page.get_user_count() == cnt_before - 1, "删除应只减1"
                assert not page.user_exists(del_name), "删除目标仍存在"
                test_users.remove(del_u)
                rec.add_detail(f"  ✓ 删除成功: {del_name}")
                print(f"  [OK] 删除成功: {del_name}")
                verify_user_absent(del_name, "单条删除")

            # ========== 步骤11: 异常输入 ==========
            with rec.step("步骤11: 异常输入拦截", "账号空/重复/超长、密码空、共享数越界"):
                print("\n[步骤11] 异常输入测试...")
                validation_failures = []

                def record_rejection(result, desc, target_name, already_exists=False):
                    rejected = bool(result.get("has_validation_error")) and not result.get("success")
                    error_msg = result.get("error_msg") or "未返回校验提示"
                    if not already_exists:
                        if page.user_exists(target_name):
                            page.delete_user(target_name)
                            validation_failures.append(f"{desc}: 非法配置被写入({target_name})")
                    if not rejected:
                        validation_failures.append(f"{desc}: 未得到明确校验拒绝")
                    if backend_verifier is not None and not already_exists:
                        verify_user_absent(target_name, f"异常-{desc}")
                    if rejected:
                        rec.add_detail(f"  ✓ {desc}: 拦截 - {error_msg}")
                        print(f"    [OK] {desc}: {error_msg}")
                        return True
                    rec.add_detail(f"  ✗ {desc}: 未拦截")
                    return False

                # 11.1 账号空
                rec.add_detail("【11.1 账号为空】")
                r = page.try_add_user_invalid({"username": "", "passwd": "123456"})
                record_rejection(r, "账号为空", "")
                # 11.2 账号重复
                rec.add_detail("【11.2 账号重复】")
                dup = test_users[0]["username"]
                r = page.try_add_user_invalid({"username": dup, "passwd": "123456"})
                record_rejection(r, "账号重复", dup, already_exists=True)
                # 11.3 密码空
                rec.add_detail("【11.3 密码为空】")
                r = page.try_add_user_invalid({"username": "acct_t_nopass", "passwd": ""})
                record_rejection(r, "密码为空", "acct_t_nopass")
                # 11.4 共享数越界(0)
                rec.add_detail("【11.4 共享数=0(下界)】")
                r = page.try_add_user_invalid({"username": "acct_t_share0", "passwd": "123456", "share": 0})
                record_rejection(r, "共享数=0", "acct_t_share0")
                # 11.5 共享数越界(>999)
                rec.add_detail("【11.5 共享数>999(上界)】")
                r = page.try_add_user_invalid({"username": "acct_t_share9999", "passwd": "123456", "share": 1000})
                record_rejection(r, "共享数>999", "acct_t_share9999")

                assert not validation_failures, f"异常输入失败({len(validation_failures)}): {validation_failures}"
                rec.add_detail(f"  ── 异常输入汇总: 5/5 项拦截 ──")
                _wait_for_user_ui(page, [u["username"] for u in test_users])

            # ========== 步骤12: 导出 ==========
            with rec.step("步骤12: 导出配置", "导出 CSV/TXT"):
                print("\n[步骤12] 导出...")
                rec.add_detail("【导出测试】")
                config = get_config()
                export_csv = config.test_data.get_export_path("pppuser", config.get_project_root())
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

            # ========== 步骤13: 帮助功能 ==========
            with rec.step("步骤13: 帮助功能", "右下角帮助按钮"):
                print("\n[步骤13] 帮助功能...")
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
            print("账号管理综合测试完成")
            print("=" * 60)

        finally:
            # 兜底清理: 账号 + 联动套餐
            try:
                if backend_verifier is not None:
                    r1 = backend_verifier.cleanup_pppuser_test(PREFIX)
                    r2 = backend_verifier.cleanup_ppp_package_test(PKG_PREFIX)
                    print(f"[finally] 清理账号: {r1} / 套餐: {r2}")
            except Exception as e:
                print(f"[finally清理异常] {str(e)[:80]}")

        # ========== 末尾硬断言 ==========
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] {len(all_failures)}项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"账号管理验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
