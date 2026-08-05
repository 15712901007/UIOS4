"""
认证服务-认证账号管理-自助密码管理 综合测试用例

纯配置页测试(单行 ppp_passwd id=1): enabled 总开关 + 6 个 allow 允许项。
即时保存(无保存按钮), 改 switch 立即写 DB。

测试覆盖:
1.  读取初始配置 + 恢复默认
2.  开启 enabled + SSH 验证
3.  逐个切换 6 个 allow(关→验0, 开→验1)
4.  全部 allow 关 + SSH 验证全 0
5.  全部 allow 开 + SSH 验证全 1
6.  关闭 enabled + SSH 验证(allow 保持)
7.  enabled=no 下 allow 仍可配置(验证配置独立性)
8.  帮助功能
"""
import pytest

from pages.authentication.ppp_passwd_page import PppPasswdPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify

pytestmark = [pytest.mark.auth, pytest.mark.ppp_passwd]


def _allow_all(value: int) -> dict:
    """生成 6 个 allow 字段全为 value 的期望字典。"""
    keys = PppPasswdPage.ALLOW_KEYS
    return {k: value for k in keys}


@pytest.mark.auth
@pytest.mark.ppp_passwd
class TestPppPasswdComprehensive:
    """自助密码管理综合测试 - 配置页(enabled + 6 allow)"""

    def test_ppp_passwd_comprehensive(self, ppp_passwd_page_logged_in: PppPasswdPage,
                                      step_recorder: StepRecorder, request):
        page = ppp_passwd_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []
        ui_failures = []
        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        def verify_config(label, enabled=None, allow=None, must_pass=True):
            return ssh_verify(
                f"L1-配置-{label}",
                backend_verifier.verify_ppp_passwd_config,
                enabled=enabled, allow=allow, must_pass=must_pass,
            )

        labels = PppPasswdPage.ALLOW_LABELS
        keys = PppPasswdPage.ALLOW_KEYS

        print("\n" + "=" * 60)
        print("自助密码管理综合测试开始")
        print("=" * 60)

        try:
            # ========== 步骤1: 恢复默认 + 读取初始配置 ==========
            with rec.step("步骤1: 恢复默认配置", "恢复 enabled=no/allow全1, 读取初始状态"):
                print("\n[步骤1] 恢复默认...")
                rec.add_detail("【恢复默认】")
                if backend_verifier is not None:
                    res = backend_verifier.restore_ppp_passwd_default()
                    rec.add_detail(f"  SSH恢复: {res}")
                    print(f"  SSH恢复: {res}")
                page._ensure_passwd_page()
                assert page.is_disabled(), "恢复后 enabled 应为关闭(已关闭)"
                rec.add_detail("  ✓ enabled=已关闭(UI)")
                # 读取 allow 初始状态
                states = page.get_all_allow_states()
                rec.add_detail(f"  allow 初始状态: {states}")
                print(f"  allow 初始: {states}")
                verify_config("初始默认", enabled="no", allow=_allow_all(1))

            # ========== 步骤2: 开启 enabled ==========
            with rec.step("步骤2: 开启 enabled", "点击启用, SSH验证 enabled=yes"):
                print("\n[步骤2] 开启 enabled...")
                rec.add_detail("【开启 enabled】")
                rec.add_detail("  1. 点击'启用'按钮")
                page.enable()
                rec.add_detail("  2. 等待即时保存")
                assert page.is_enabled(), "开启后应为'已开启'"
                rec.add_detail("  ✓ UI 状态: 已开启")
                print("  [OK] enabled 已开启")
                verify_config("开启enabled", enabled="yes", allow=_allow_all(1))

            # ========== 步骤3: 逐个切换 allow(关→验0→开→验1) ==========
            with rec.step("步骤3: 逐个切换 allow", "6个allow逐个 关→SSH验0→开→SSH验1"):
                print("\n[步骤3] 逐个切换 allow...")
                rec.add_detail("【逐个切换 allow(关→0/开→1)】")
                for label, key in zip(labels, keys):
                    # 关
                    page.set_allow(label, False)
                    assert page.get_allow_checked(label) is False, f"{label} 关闭失败(UI)"
                    rec.add_detail(f"  {label}: 关 → UI=False")
                    verify_config(f"关{label}", allow={key: 0})
                    # 开
                    page.set_allow(label, True)
                    assert page.get_allow_checked(label) is True, f"{label} 开启失败(UI)"
                    rec.add_detail(f"  {label}: 开 → UI=True")
                    verify_config(f"开{label}", allow={key: 1})
                    print(f"  [OK] {label} 关/开 切换+SSH验证通过")
                rec.add_detail(f"  ── 6/6 allow 逐个切换验证通过 ──")

            # ========== 步骤4: 全部 allow 关 ==========
            with rec.step("步骤4: 全部 allow 关", "6个allow全关, SSH验证全0"):
                print("\n[步骤4] 全部 allow 关...")
                rec.add_detail("【全部 allow 关】")
                for label in labels:
                    page.set_allow(label, False)
                states = page.get_all_allow_states()
                rec.add_detail(f"  全关后 UI 状态: {states}")
                assert all(v is False for v in states.values()), "全关后仍有 allow 开启"
                print("  [OK] 全部 allow 已关(UI)")
                verify_config("全关", allow=_allow_all(0))

            # ========== 步骤5: 全部 allow 开 ==========
            with rec.step("步骤5: 全部 allow 开", "6个allow全开, SSH验证全1"):
                print("\n[步骤5] 全部 allow 开...")
                rec.add_detail("【全部 allow 开】")
                for label in labels:
                    page.set_allow(label, True)
                states = page.get_all_allow_states()
                rec.add_detail(f"  全开后 UI 状态: {states}")
                assert all(v is True for v in states.values()), "全开后仍有 allow 关闭"
                print("  [OK] 全部 allow 已开(UI)")
                verify_config("全开", allow=_allow_all(1))

            # ========== 步骤6: 关闭 enabled (allow 保持) ==========
            with rec.step("步骤6: 关闭 enabled", "停用功能, SSH验证 enabled=no(allow保持全1)"):
                print("\n[步骤6] 关闭 enabled...")
                rec.add_detail("【关闭 enabled】")
                rec.add_detail("  1. 点击'停用'按钮")
                page.disable()
                assert page.is_disabled(), "停用后应为'已关闭'"
                rec.add_detail("  ✓ UI 状态: 已关闭")
                print("  [OK] enabled 已关闭")
                verify_config("关闭enabled", enabled="no", allow=_allow_all(1))

            # ========== 步骤7: enabled=no 下 allow 仍可配置(独立性) ==========
            with rec.step("步骤7: enabled关闭下 allow 配置独立性", "enabled=no时仍可改allow并保存"):
                print("\n[步骤7] enabled=no 下 allow 配置...")
                rec.add_detail("【enabled=no 下 allow 配置独立性】")
                test_label = labels[0]  # PPPOE
                test_key = keys[0]
                page.set_allow(test_label, False)
                assert page.get_allow_checked(test_label) is False, f"{test_label} 关闭失败"
                rec.add_detail(f"  enabled=no 下关 {test_label}: UI=False")
                verify_config("关allow_PPPOE(enabled=no)", allow={test_key: 0})
                # 恢复
                page.set_allow(test_label, True)
                verify_config("恢复allow_PPPOE", allow={test_key: 1})
                rec.add_detail(f"  ✓ enabled=no 下 allow 仍可配置(配置项独立于总开关)")
                print("  [OK] allow 配置独立于 enabled")

            # ========== 步骤8: 帮助功能 ==========
            with rec.step("步骤8: 帮助功能", "右下角帮助按钮"):
                print("\n[步骤8] 帮助功能...")
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
            print("自助密码管理综合测试完成")
            print("=" * 60)

        finally:
            # 兜底恢复默认配置
            try:
                if backend_verifier is not None:
                    res = backend_verifier.restore_ppp_passwd_default()
                    print(f"[finally] {res}")
            except Exception as e:
                print(f"[finally恢复异常] {str(e)[:80]}")

        # ========== 末尾硬断言 ==========
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] {len(all_failures)}项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"自助密码管理验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
