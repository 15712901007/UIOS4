"""
VLAN综合测试用例

一次测试多个功能，提高效率：
1. 添加8条VLAN（覆盖各种数据组合场景）
2. 编辑其中1条
3. 停用其中1条
4. 删除其中1条
5. 搜索测试
6. 导出测试
7. 批量启用剩余的
8. 批量停用剩余的
9. 批量删除剩余的
10. 导入测试（使用导出的文件）

数据场景覆盖：
- 最小/最大VLAN ID
- 只填必填项
- 填MAC不填IP
- 填IP不填MAC
- 填MAC+IP
- 填MAC+IP+子网掩码
- 填MAC+IP+备注
- 填MAC+IP+扩展IP
- 完整信息
"""
import csv
import pytest
import os
import re
import time
from pages.network.vlan_page import VlanPage
from config.config import get_config
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify, make_kernel_check


def _expected_vlan_fields(vlan: dict, enabled: str = "yes") -> dict:
    """把页面输入转换成后台 VLAN 记录的完整期望字段。"""
    subnet = vlan.get("subnet") or "255.255.255.0"
    ext_ip = vlan.get("ext_ip") or ""
    return {
        "enabled": enabled,
        "tagname": vlan["name"],
        "vlan_name": vlan["name"],
        "vlan_id": vlan["id"],
        "interface": vlan.get("line") or "lan1",
        "mac": vlan.get("mac") or "",
        "ip_addr": vlan.get("ip") or "",
        "netmask": subnet,
        "ip_mask": f"{ext_ip}/{subnet}" if ext_ip else "",
        "comment": vlan.get("remark") or "",
    }


def _decode_export_file(file_path: str) -> str:
    with open(file_path, "rb") as export_file:
        raw = export_file.read()
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise AssertionError(f"导出文件编码无法识别: {file_path}")


def _read_vlan_export(file_path: str) -> list:
    """结构化解析 VLAN CSV/TXT 导出，返回每条配置字典。"""
    text = _decode_export_file(file_path)
    if file_path.lower().endswith(".csv"):
        return [dict(row) for row in csv.DictReader(text.splitlines())]

    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = {
            match.group(1): match.group(2).strip()
            for match in re.finditer(
                r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=(.*?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
                line,
            )
        }
        rows.append(row)
    return rows


def _assert_export_matches(file_path: str, expected_vlans: list) -> None:
    assert os.path.isfile(file_path), f"导出文件不存在: {file_path}"
    assert os.path.getsize(file_path) > 0, f"导出文件为空: {file_path}"
    rows = _read_vlan_export(file_path)
    by_name = {row.get("vlan_name"): row for row in rows}
    expected_names = {vlan["name"] for vlan in expected_vlans}
    assert set(by_name) == expected_names, (
        f"导出VLAN集合不一致: 期望{sorted(expected_names)}, 实际{sorted(set(by_name))}"
    )
    for vlan in expected_vlans:
        expected = _expected_vlan_fields(vlan)
        row = by_name[vlan["name"]]
        for field in ("enabled", "vlan_name", "vlan_id", "interface", "mac",
                      "ip_addr", "netmask", "ip_mask", "comment"):
            assert str(row.get(field, "")) == str(expected[field]), (
                f"{os.path.basename(file_path)}中{vlan['name']}.{field}不一致: "
                f"期望{expected[field]!r}, 实际{row.get(field, '')!r}"
            )


def _wait_for_vlan_ui(page: VlanPage, expected_names, timeout_ms: int = 12000):
    """等待异步表格稳定到精确集合，避免加载瞬间“共0条”造成假通过。"""
    expected = set(expected_names)
    deadline = time.monotonic() + timeout_ms / 1000
    last_count, last_names = -1, []
    while time.monotonic() < deadline:
        last_count = page.get_vlan_count()
        last_names = sorted(page.get_vlan_list())
        # 数量和 VLAN 名称列的完整集合都必须一致，不接受页面其他区域的同名文本。
        if last_count == len(expected) and len(last_names) == len(expected) and set(last_names) == expected:
            return sorted(expected)
        page.page.wait_for_timeout(400)
    raise AssertionError(
        f"VLAN表格未稳定到期望集合: 期望{sorted(expected)}, "
        f"实际count={last_count}, names={last_names}"
    )


@pytest.mark.vlan
@pytest.mark.network
class TestVlanComprehensive:
    """VLAN综合测试 - 一次测试覆盖所有功能"""

    def test_comprehensive_flow(self, vlan_page_logged_in: VlanPage, step_recorder: StepRecorder, request):
        """
        综合测试: 添加8种场景 -> 编辑 -> 停用 -> 删除 -> 搜索 -> 导出 -> 批量操作

        测试步骤:
        1. 批量添加8条VLAN（覆盖各种数据组合）
        2. 验证添加成功
        3. 编辑第1条VLAN的名称
        4. 停用第2条VLAN
        5. 删除第3条VLAN
        6. 搜索测试（存在/不存在）
        7. 导出VLAN配置
        8. 批量启用剩余的
        9. 批量停用剩余的
        10. 批量删除剩余的
        """
        page = vlan_page_logged_in
        rec = step_recorder  # 简化变量名

        # 动态获取backend_verifier fixture（可选，未配置SSH时为None）
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ssh_failures = []
        ui_failures = []  # 收集must_pass=True但验证失败的项

        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        def verify_vlan_active(vlan, label: str):
            """逐条验证启用 VLAN 的数据库、接口和内核映射。"""
            parent = vlan.get("line") or "lan1"
            results = [
                ssh_verify(
                    f"L1-数据库-{label}({vlan['name']})",
                    backend_verifier.verify_vlan_database,
                    vlan["name"], must_pass=True,
                    expected_fields=_expected_vlan_fields(vlan, "yes"),
                ),
                ssh_verify(
                    f"L2-网络接口-{label}({vlan['name']})",
                    backend_verifier.verify_vlan_interface,
                    vlan["name"], must_pass=True, expected_parent=parent,
                ),
                ssh_verify(
                    f"L3-proc-{label}({vlan['name']})",
                    backend_verifier.verify_vlan_proc,
                    vlan["name"], must_pass=True,
                    expected_vlan_id=vlan["id"], expected_parent=parent,
                ),
            ]
            return all(result is not None and result.passed for result in results)

        def verify_vlan_disabled(vlan, label: str):
            """停用后配置、接口和/proc映射保留，但接口必须明确为DOWN。"""
            parent = vlan.get("line") or "lan1"
            results = [
                ssh_verify(
                    f"L1-数据库-{label}({vlan['name']})",
                    backend_verifier.verify_vlan_database,
                    vlan["name"], must_pass=True,
                    expected_fields=_expected_vlan_fields(vlan, "no"),
                ),
                ssh_verify(
                    f"L2-接口DOWN-{label}({vlan['name']})",
                    backend_verifier.verify_vlan_interface,
                    vlan["name"], must_pass=True,
                    expected_state="DOWN", expected_parent=parent,
                ),
                ssh_verify(
                    f"L3-proc保留-{label}({vlan['name']})",
                    backend_verifier.verify_vlan_proc,
                    vlan["name"], must_pass=True,
                    expected_vlan_id=vlan["id"], expected_parent=parent,
                ),
            ]
            return all(result is not None and result.passed for result in results)

        def verify_vlan_absent(vlan_name: str, label: str):
            """删除后逐层确认数据库、接口和/proc都无残留。"""
            results = [
                ssh_verify(
                    f"L1-数据库删除-{label}({vlan_name})",
                    backend_verifier.verify_vlan_database_absent,
                    vlan_name, must_pass=True,
                ),
                ssh_verify(
                    f"L2-接口删除-{label}({vlan_name})",
                    backend_verifier.verify_vlan_interface_absent,
                    vlan_name, must_pass=True,
                ),
                ssh_verify(
                    f"L3-proc删除-{label}({vlan_name})",
                    backend_verifier.verify_vlan_proc_absent,
                    vlan_name, must_pass=True,
                ),
            ]
            return all(result is not None and result.passed for result in results)

        # 测试数据 - 8条VLAN，覆盖各种数据组合场景
        test_vlans = [
            # 场景1: 普通VLAN ID + 最少信息
            {"id": "100", "name": "vlan_min_100", "desc": "普通ID+最少信息"},
            # 场景2: 最大VLAN ID + 最少信息
            {"id": "4090", "name": "vlan_max_4090", "desc": "最大ID+最少信息"},
            # 场景3: 填写MAC不填IP
            {"id": "101", "name": "vlan_mac", "mac": "00:11:22:33:44:01", "desc": "有MAC无IP"},
            # 场景4: 填写IP不填MAC（需要子网掩码）
            {"id": "102", "name": "vlan_ip", "ip": "192.168.102.1", "subnet": "255.255.255.0", "desc": "无MAC有IP"},
            # 场景5: 填写MAC+IP
            {"id": "103", "name": "vlan_mac_ip", "mac": "00:11:22:33:44:03", "ip": "192.168.103.1", "subnet": "255.255.255.0", "desc": "MAC+IP"},
            # 场景6: 填写MAC+IP+备注
            {"id": "104", "name": "vlan_remark", "mac": "00:11:22:33:44:04", "ip": "192.168.104.1", "subnet": "255.255.255.0", "remark": "测试备注", "desc": "MAC+IP+备注"},
            # 场景7: 填写MAC+IP+扩展IP
            {"id": "105", "name": "vlan_ext", "mac": "00:11:22:33:44:05", "ip": "192.168.105.1", "subnet": "255.255.255.0", "ext_ip": "192.168.105.2", "desc": "MAC+IP+扩展IP"},
            # 场景8: 完整信息（MAC+IP+备注+扩展IP）
            {"id": "106", "name": "vlan_complete", "mac": "00:11:22:33:44:06", "ip": "192.168.106.1", "subnet": "255.255.255.0", "remark": "完整信息测试", "ext_ip": "192.168.106.2", "desc": "完整信息"},
        ]

        print("\n" + "=" * 60)
        print("VLAN综合测试开始")
        print("=" * 60)
        print(f"测试数据: {len(test_vlans)} 条VLAN")
        for v in test_vlans:
            print(f"  - ID={v['id']}, 名称={v['name']}, 场景={v['desc']}")

        # ========== 步骤1: 确保环境干净（批量删除所有数据） ==========
        with rec.step("步骤1: 检查并清理环境", "检查当前VLAN数量并清理残留数据"):
            print("\n[步骤1] 检查并清理环境...")
            current_count = page.get_vlan_count()
            cleanup_vlan_names = set(page.get_vlan_list())
            if backend_verifier is not None:
                rules_before_cleanup = backend_verifier.query_vlan_rules(strict=True)
                cleanup_vlan_names.update(
                    str(rule.get("tagname")) for rule in rules_before_cleanup
                    if rule.get("tagname")
                )
            print(f"  当前VLAN数量: {current_count}")
            rec.add_detail(f"【环境检查】")
            rec.add_detail(f"  当前VLAN数量: {current_count}")

            if current_count > 0:
                print("  检测到残留数据，执行批量清理...")
                rec.add_detail(f"【清理操作】")
                rec.add_detail("  检测到残留数据，执行批量清理")
                # 使用带选中数量复读的全选功能
                if page.select_all_rules():
                    selected_count = page.get_selected_count()
                    assert selected_count == current_count, (
                        f"步骤1全选数量错误: 期望{current_count}, 实际{selected_count}"
                    )
                    rec.add_detail("  1. 点击全选复选框")
                    rec.add_detail(f"     已精确选中 {selected_count} 条")
                    rec.add_detail("  2. 点击批量删除按钮")
                    # 批量删除
                    page.batch_delete()
                    page.page.wait_for_timeout(1500)
                    rec.add_detail("  3. 确认删除对话框")
                    # 验证清理结果
                    page.page.reload()
                    page.page.wait_for_timeout(500)
                    final_count = page.get_vlan_count()
                    print(f"  [OK] 环境清理完成，剩余 {final_count} 条VLAN")
                    rec.add_detail(f"【清理结果】")
                    rec.add_detail(f"  清理完成，剩余 {final_count} 条VLAN")
                else:
                    print("  [WARN] 无法全选，尝试逐个清理...")
                    rec.add_detail("  无法全选，尝试逐个清理")
                    # 逐个删除清理前实际发现的精确名称
                    for vlan_name in sorted(cleanup_vlan_names):
                        if page.vlan_exists(vlan_name):
                            page.delete_vlan(vlan_name)
                            print(f"    - 已删除: {vlan_name}")
                            rec.add_detail(f"  已删除: {vlan_name}")
            else:
                print("  [OK] 环境干净，无需清理")
                rec.add_detail("  环境干净，无需清理")

            page.clear_search()
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            _wait_for_vlan_ui(page, [])
            assert page.get_vlan_count() == 0, "步骤1清理后页面仍有VLAN"
            if backend_verifier is not None:
                backend_rules = backend_verifier.query_vlan_rules(strict=True)
                assert backend_rules == [], f"步骤1清理后数据库仍有VLAN: {backend_rules}"
                rec.add_detail("  SSH-L1-环境清理: [OK] 数据库VLAN数量=0")
                for vlan_name in sorted(cleanup_vlan_names):
                    verify_vlan_absent(vlan_name, "步骤1环境清理")

        # ========== 步骤2: 清理已存在的测试数据（备用检查） ==========
        with rec.step("步骤2: 二次检查测试数据", "确保测试数据已清理"):
            print("\n[步骤2] 检查测试数据是否已清理...")
            rec.add_detail(f"【二次检查】")
            cleaned_count = 0
            for vlan in test_vlans:
                if page.vlan_exists(vlan["name"]):
                    rec.add_detail(f"  发现残留: {vlan['name']}，执行删除")
                    page.delete_vlan(vlan["name"])
                    print(f"  - 已删除: {vlan['name']}")
                    cleaned_count += 1
            if cleaned_count == 0:
                rec.add_detail("  无需清理，数据已干净")
            else:
                rec.add_detail(f"  共清理 {cleaned_count} 条残留数据")
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            _wait_for_vlan_ui(page, [])
            for vlan in test_vlans:
                assert not page.vlan_exists(vlan["name"]), f"二次清理后仍存在: {vlan['name']}"
                if backend_verifier is not None:
                    verify_vlan_absent(vlan["name"], "步骤2环境检查")

        # ========== 步骤3: 批量添加8条VLAN ==========
        with rec.step("步骤3: 批量添加VLAN", f"添加 {len(test_vlans)} 条VLAN，覆盖各种数据组合场景"):
            print("\n[步骤3] 批量添加8条VLAN（覆盖各种数据组合场景）...")
            rec.add_detail(f"【添加计划】共 {len(test_vlans)} 条VLAN")
            rec.add_detail("  场景覆盖: 普通ID/最大ID/有MAC无IP/无MAC有IP/MAC+IP/MAC+IP+备注/MAC+IP+扩展IP/完整信息")
            added_count = 0
            for vlan in test_vlans:
                rec.add_detail(f"【添加 {vlan['name']}】")
                rec.add_detail(f"  VLAN ID: {vlan['id']}")
                if vlan.get("mac"):
                    rec.add_detail(f"  MAC地址: {vlan['mac']}")
                if vlan.get("ip"):
                    rec.add_detail(f"  IP地址: {vlan['ip']}")
                if vlan.get("subnet"):
                    rec.add_detail(f"  子网掩码: {vlan['subnet']}")
                if vlan.get("remark"):
                    rec.add_detail(f"  备注: {vlan['remark']}")
                rec.add_detail(f"  场景: {vlan['desc']}")

                result = page.add_vlan(
                    vlan_id=vlan["id"],
                    vlan_name=vlan["name"],
                    mac=vlan.get("mac"),
                    ip=vlan.get("ip"),
                    subnet_mask=vlan.get("subnet"),
                    remark=vlan.get("remark")
                )
                assert result is True, f"添加VLAN {vlan['name']} 失败"
                print(f"  + 已添加: {vlan['name']} (ID: {vlan['id']}) - {vlan['desc']}")
                rec.add_detail(f"  ✓ 添加成功")
                added_count += 1

                # 如果有扩展IP，添加扩展IP
                if vlan.get("ext_ip"):
                    rec.add_detail(f"【添加扩展IP】")
                    rec.add_detail(f"  扩展IP: {vlan['ext_ip']}")
                    # 重新编辑添加扩展IP
                    assert page.edit_vlan(vlan["name"]), (
                        f"未能进入VLAN {vlan['name']} 的精确编辑行"
                    )
                    page.add_extended_ip(vlan["ext_ip"], vlan.get("subnet", "255.255.255.0"))
                    page.click_save()
                    assert page.wait_for_success_message(), (
                        f"VLAN {vlan['name']} 扩展IP保存失败"
                    )
                    page.page.reload()
                    page.page.wait_for_load_state("networkidle")
                    _wait_for_vlan_ui(
                        page, [item["name"] for item in test_vlans[:added_count]]
                    )
                    print(f"    + 扩展IP: {vlan['ext_ip']}")
                    rec.add_detail(f"  ✓ 扩展IP添加成功")

            # 验证所有VLAN都已添加
            rec.add_detail(f"【验证结果】")
            page.clear_search()  # 清空搜索条件
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)
            for vlan in test_vlans:
                assert page.vlan_exists(vlan["name"]), f"VLAN {vlan['name']} 未找到"
            print("  [OK] 所有8条VLAN添加成功")
            rec.add_detail(f"  ✓ 所有 {len(test_vlans)} 条VLAN添加成功")

        # ========== 步骤3.5: 后台数据验证（SSH全链路） ==========
        if backend_verifier is not None:
            with rec.step("步骤3.5: 后台数据验证（SSH全链路）", "SSH验证每条VLAN的数据库/网络接口/proc"):
                print("\n[步骤3.5] 后台数据验证（SSH全链路）...")
                rec.add_detail("【SSH后台全链路验证】")

                verify_passed = 0
                for vlan in test_vlans:
                    vlan_name = vlan["name"]
                    rec.add_detail(f"  ── 验证VLAN: {vlan_name} ──")
                    print(f"  验证VLAN: {vlan_name}")

                    if verify_vlan_active(vlan, "新增"):
                        verify_passed += 1

                print(f"  [OK] 后台验证完成: {verify_passed}/{len(test_vlans)} 条VLAN验证通过")
                rec.add_detail(f"  ── 验证汇总: {verify_passed}/{len(test_vlans)} 条VLAN验证通过 ──")
        else:
            print("\n[步骤3.5] 后台数据验证: 跳过（未配置SSH或paramiko未安装）")

        # ========== 步骤4: 编辑第1条VLAN ==========
        with rec.step("步骤4: 编辑VLAN", "编辑第1条VLAN的名称"):
            print("\n[步骤4] 编辑第1条VLAN...")
            edit_vlan = test_vlans[0]
            old_name = edit_vlan["name"]
            new_name = "vlan_edit_1"
            rec.add_detail(f"【编辑操作】")
            rec.add_detail(f"  目标VLAN: {edit_vlan['name']} (ID: {edit_vlan['id']})")
            rec.add_detail(f"  新名称: {new_name}")

            # 先删除可能存在的新名称VLAN
            if page.vlan_exists(new_name):
                page.delete_vlan(new_name)
                rec.add_detail(f"  预处理: 删除已存在的同名VLAN")

            rec.add_detail(f"  1. 点击编辑按钮")
            page.edit_vlan(edit_vlan["name"])
            rec.add_detail(f"  2. 修改名称: {edit_vlan['name']} → {new_name}")
            # 修改名称
            page.page.get_by_role("textbox", name="vlan名称").fill(new_name)
            rec.add_detail(f"  3. 点击保存按钮")
            page.page.get_by_role("button", name="保存").click()
            page.wait_for_success_message()

            # 验证编辑成功
            page.page.reload()
            page.page.wait_for_timeout(500)
            expected_names = {vlan["name"] for vlan in test_vlans}
            expected_names.remove(old_name)
            expected_names.add(new_name)
            _wait_for_vlan_ui(page, expected_names)
            assert page.vlan_exists(new_name), "编辑后的VLAN未找到"
            assert not page.vlan_exists(old_name), "编辑后旧VLAN名称仍存在"
            test_vlans[0]["name"] = new_name  # 更新测试数据
            print(f"  [OK] VLAN编辑成功: {old_name} -> {new_name}")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ 编辑成功，新名称已生效")

            # SSH验证编辑后数据库更新
            if backend_verifier is not None:
                verify_vlan_active(edit_vlan, "编辑后新名称")
                verify_vlan_absent(old_name, "编辑后旧名称")

        # ========== 步骤5: 停用第2条VLAN ==========
        with rec.step("步骤5: 停用VLAN", "停用第2条VLAN"):
            print("\n[步骤5] 停用第2条VLAN...")
            disable_vlan = test_vlans[1]
            rec.add_detail(f"【停用操作】")
            rec.add_detail(f"  目标VLAN: {disable_vlan['name']} (ID: {disable_vlan['id']})")
            rec.add_detail(f"  1. 点击停用按钮")
            result = page.disable_vlan(disable_vlan["name"])
            assert result is True, f"停用VLAN {disable_vlan['name']} 失败"
            rec.add_detail(f"  2. 确认停用对话框")

            # 等待页面稳定后刷新验证状态
            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

            assert page.is_vlan_disabled(disable_vlan["name"]), f"VLAN {disable_vlan['name']} 状态未变为停用"
            print(f"  [OK] VLAN停用成功: {disable_vlan['name']}")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ VLAN状态已变为停用")

            # SSH验证停用后数据库字段
            if backend_verifier is not None:
                verify_vlan_disabled(disable_vlan, "单条停用")

        # ========== 步骤6: 单独启用第2条VLAN ==========
        with rec.step("步骤6: 启用VLAN", "单独启用第2条VLAN（测试启用功能）"):
            print("\n[步骤6] 单独启用第2条VLAN（测试启用功能）...")
            rec.add_detail(f"【启用操作】")
            rec.add_detail(f"  目标VLAN: {disable_vlan['name']} (ID: {disable_vlan['id']})")
            rec.add_detail(f"  1. 点击启用按钮")
            result = page.enable_vlan(disable_vlan["name"])
            assert result is True, f"启用VLAN {disable_vlan['name']} 失败"
            rec.add_detail(f"  2. 确认启用对话框")

            # 验证启用成功
            page.page.wait_for_timeout(1000)
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

            assert page.is_vlan_enabled(disable_vlan["name"]), f"VLAN {disable_vlan['name']} 启用后状态未变为启用"
            print(f"  [OK] VLAN启用成功: {disable_vlan['name']}")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ VLAN状态已变为启用")

            # SSH验证启用后数据库字段
            if backend_verifier is not None:
                verify_vlan_active(disable_vlan, "单条启用")

        # ========== 步骤7: 删除第3条VLAN ==========
        with rec.step("步骤7: 删除VLAN", "删除第3条VLAN"):
            print("\n[步骤7] 删除第3条VLAN...")
            delete_vlan = test_vlans[2]
            rec.add_detail(f"【删除操作】")
            rec.add_detail(f"  目标VLAN: {delete_vlan['name']} (ID: {delete_vlan['id']})")

            # 获取删除前的条目数
            count_before_delete = page.get_vlan_count()
            print(f"  删除前条目数: {count_before_delete}")
            rec.add_detail(f"  删除前条目数: {count_before_delete}")
            rec.add_detail(f"  1. 点击删除按钮")

            result = page.delete_vlan(delete_vlan["name"])
            assert result is True, f"删除VLAN {delete_vlan['name']} 失败"
            rec.add_detail(f"  2. 确认删除对话框")

            # 精确验证只删除目标一条；加载瞬间的“共0条”不能算成功。
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            surviving_vlans = [vlan for vlan in test_vlans if vlan is not delete_vlan]
            _wait_for_vlan_ui(page, [vlan["name"] for vlan in surviving_vlans])
            count_after_delete = page.get_vlan_count()
            print(f"  删除后条目数: {count_after_delete}")
            rec.add_detail(f"  删除后条目数: {count_after_delete}")

            assert count_after_delete == count_before_delete - 1, (
                f"删除必须且只能减少1条: {count_before_delete} -> {count_after_delete}"
            )
            assert not page.vlan_exists(delete_vlan["name"]), f"删除目标仍存在: {delete_vlan['name']}"
            for vlan in surviving_vlans:
                assert page.vlan_exists(vlan["name"]), f"误删了非目标VLAN: {vlan['name']}"

            test_vlans.remove(delete_vlan)  # 从测试数据中移除
            print(f"  [OK] VLAN删除成功: {delete_vlan['name']}")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ 删除成功，条目数减少 {count_before_delete - count_after_delete}")

            # SSH逐层验证数据库、接口、/proc均无残留
            if backend_verifier is not None:
                verify_vlan_absent(delete_vlan["name"], "单条删除")

        # ========== 步骤8: 搜索测试 ==========
        with rec.step("步骤8: 搜索功能测试", "测试搜索存在的VLAN和不存在的VLAN"):
            print("\n[步骤8] 搜索测试...")
            rec.add_detail(f"【搜索测试】")

            # 8.1 搜索存在的VLAN（按名称）
            search_target = test_vlans[2]["name"]  # vlan_ip (注意索引变了，因为删除了第3条)
            rec.add_detail(f"  测试1: 搜索存在的VLAN")
            rec.add_detail(f"    搜索关键词: {search_target}")
            page.search_vlan(search_target)
            _wait_for_vlan_ui(page, [search_target])
            assert page.vlan_exists(search_target), f"搜索不到存在的VLAN: {search_target}"
            assert page.get_vlan_count() == 1, "精确名称搜索结果不止1条"
            print(f"  [OK] 搜索存在VLAN成功: {search_target}")
            rec.add_detail(f"    ✓ 搜索成功，VLAN已找到")

            # 8.2 搜索不存在的VLAN
            rec.add_detail(f"  测试2: 搜索不存在的VLAN")
            rec.add_detail(f"    搜索关键词: not_exist_vlan_xxx")
            page.search_vlan("not_exist_vlan_xxx")
            _wait_for_vlan_ui(page, [])
            count = page.get_vlan_count()
            assert count == 0, f"搜索不存在的数据时，应该显示0条记录，实际显示{count}条"
            print("  [OK] 搜索不存在VLAN验证成功，显示0条记录")
            rec.add_detail(f"    ✓ 验证成功，显示0条记录")

            # 8.3 清空搜索，验证数据恢复
            rec.add_detail(f"  测试3: 清空搜索条件")
            page.clear_search()
            _wait_for_vlan_ui(page, [vlan["name"] for vlan in test_vlans])
            remaining_count = page.get_vlan_count()
            assert remaining_count == len(test_vlans), (
                f"清空搜索后应恢复{len(test_vlans)}条，实际{remaining_count}条"
            )
            print(f"  [OK] 清空搜索成功，当前显示 {remaining_count} 条记录")
            rec.add_detail(f"    ✓ 清空成功，显示 {remaining_count} 条记录")

        # ========== 步骤8.5: 排序测试 ==========
        with rec.step("步骤8.5: 排序功能测试", "测试VLAN名称和IP地址列的排序功能"):
            print("\n[步骤8.5] 排序测试...")
            rec.add_detail(f"【排序测试】")
            rec.add_detail(f"  测试字段: VLAN 名称、IP地址")

            sortable_columns = ["VLAN 名称", "IP地址"]
            for col in sortable_columns:
                baseline = page.get_column_values(col)
                assert len(baseline) == len(test_vlans), (
                    f"{col}排序前行数不正确: {len(baseline)}/{len(test_vlans)}"
                )
                assert page.sort_by_column(col), f"{col}第一次排序点击失败"
                first_order = page.get_column_values(col)
                assert page.sort_by_column(col), f"{col}第二次排序点击失败"
                second_order = page.get_column_values(col)
                assert second_order == list(reversed(first_order)), (
                    f"{col}正倒序未互为反序: 第一次{first_order}, 第二次{second_order}"
                )
                assert page.sort_by_column(col), f"{col}恢复默认排序点击失败"
                default_order = page.get_column_values(col)
                assert default_order == baseline, (
                    f"{col}第三次点击未恢复默认顺序: 期望{baseline}, 实际{default_order}"
                )
                rec.add_detail(f"  ✓ {col}: 正序/倒序互逆，第三次恢复默认，共{len(baseline)}条")
                print(f"  [OK] {col}排序顺序验证通过")

            print(f"  [OK] 排序测试完成: {len(sortable_columns)}/{len(sortable_columns)} 个字段通过")
            rec.add_detail(f"  ── 汇总: {len(sortable_columns)}/{len(sortable_columns)} 个字段真实顺序验证通过 ──")

        # ========== 步骤9: 导出VLAN配置（两次导出：CSV和TXT） ==========
        with rec.step("步骤9: 导出VLAN配置", "导出CSV和TXT两种格式的配置文件"):
            print("\n[步骤9] 导出VLAN配置...")
            rec.add_detail(f"【导出测试】")
            config = get_config()
            export_file_csv = config.test_data.get_export_path("vlan", config.get_project_root())
            export_file_txt = export_file_csv.replace(".csv", ".txt")

            # 第一次导出：CSV文件
            rec.add_detail(f"  测试1: 导出CSV格式")
            rec.add_detail(f"    目标文件: {os.path.basename(export_file_csv)}")
            export_result_csv = page.export_vlans(export_format="csv")
            assert export_result_csv is True, "CSV导出操作失败"
            _assert_export_matches(export_file_csv, test_vlans)
            print(f"  [OK] 导出CSV成功且内容一致: {export_file_csv}")
            rec.add_detail(f"    ✓ CSV导出成功，{len(test_vlans)}条记录字段一致")

            page.page.wait_for_timeout(500)

            # 第二次导出：TXT文件
            rec.add_detail(f"  测试2: 导出TXT格式")
            rec.add_detail(f"    目标文件: {os.path.basename(export_file_txt)}")
            export_result_txt = page.export_vlans(export_format="txt")
            assert export_result_txt is True, "TXT导出操作失败"
            _assert_export_matches(export_file_txt, test_vlans)
            print(f"  [OK] 导出TXT成功且内容一致: {export_file_txt}")
            rec.add_detail(f"    ✓ TXT导出成功，{len(test_vlans)}条记录字段一致")

            # 确保关闭可能存在的模态框，刷新页面确保状态干净
            page.close_modal_if_exists()
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

        # ========== 步骤10: 异常输入测试 ==========
        with rec.step("步骤10: 异常输入测试", "测试各种不合规输入的验证拦截"):
            print("\n[步骤10] 异常输入测试...")
            validation_failures = []

            def record_rejection(result, value, desc, target_name):
                """异常用例必须是明确的表单/服务端校验拒绝，普通自动化异常不算通过。"""
                rejected = bool(result.get("has_validation_error")) and not result.get("success")
                error_msg = result.get("error_msg") or "未返回校验提示"
                created = page.vlan_exists(target_name)
                if created:
                    page.delete_vlan(target_name)
                    validation_failures.append(f"{desc}: 非法配置被写入页面({target_name})")
                if not rejected:
                    validation_failures.append(
                        f"{desc}: 未得到明确校验拒绝(success={result.get('success')}, "
                        f"has_validation_error={result.get('has_validation_error')})"
                    )
                if backend_verifier is not None:
                    verify_vlan_absent(target_name, f"异常输入-{desc}")
                if rejected and not created:
                    print(f"    [OK] {desc}: 正确拦截 - {error_msg}")
                    rec.add_detail(f"  ✓ 输入'{value}' ({desc})")
                    rec.add_detail(f"    提示: {error_msg}")
                    return True
                print(f"    [FAIL] {desc}: {error_msg}")
                rec.add_detail(f"  ✗ 输入'{value}' ({desc}): 未被可靠拦截")
                return False

            # 10.1 MAC地址不合规测试（其他字段正常）
            print("\n  [10.1] MAC地址不合规测试...")
            rec.add_detail("【10.1 MAC地址验证】")
            mac_test_cases = [
                ("00:11:22", "MAC格式错误-少段"),
                ("00:11:22:33:44:55:66", "MAC格式错误-多段"),
                ("00:11:22:33:44:GG", "MAC非法字符"),
            ]
            mac_passed = 0
            for index, (mac_value, desc) in enumerate(mac_test_cases):
                target_name = f"vlan_bad_mac_{index}"
                result = page.try_add_vlan_invalid(
                    vlan_id=str(201 + index),
                    vlan_name=target_name,
                    mac=mac_value,  # 不合规的MAC
                    ip="192.168.201.1",  # 正常的IP
                    subnet_mask="255.255.255.0"  # 正常的子网掩码
                )
                if record_rejection(result, mac_value, desc, target_name):
                    mac_passed += 1
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → MAC地址验证结果: {mac_passed}/{len(mac_test_cases)} 通过")

            # 10.2 IP地址不合规测试（其他字段正常）
            print("\n  [10.2] IP地址不合规测试...")
            rec.add_detail("【10.2 IP地址验证】")
            ip_test_cases = [
                ("192.168.1", "IP格式错误-少段"),
                ("192.168.1.256", "IP超出范围"),
                ("192.168.1.abc", "IP非法字符"),
            ]
            ip_passed = 0
            for index, (ip_value, desc) in enumerate(ip_test_cases):
                target_name = f"vlan_bad_ip_{index}"
                result = page.try_add_vlan_invalid(
                    vlan_id=str(211 + index),
                    vlan_name=target_name,
                    mac="00:11:22:33:44:02",  # 正常的MAC
                    ip=ip_value,  # 不合规的IP
                    subnet_mask="255.255.255.0"
                )
                if record_rejection(result, ip_value, desc, target_name):
                    ip_passed += 1
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → IP地址验证结果: {ip_passed}/{len(ip_test_cases)} 通过")

            # 10.3 VLAN名称不规范测试（其他字段正常）
            print("\n  [10.3] VLAN名称不规范测试...")
            rec.add_detail("【10.3 VLAN名称验证】")
            name_test_cases = [
                ("test_vlan", "名称不以vlan开头"),
                ("vlan-name", "名称包含连字符"),
            ]
            name_passed = 0
            for index, (name_value, desc) in enumerate(name_test_cases):
                result = page.try_add_vlan_invalid(
                    vlan_id=str(221 + index),  # 正常的ID
                    vlan_name=name_value,  # 不合规的名称
                    mac="00:11:22:33:44:03",  # 正常的MAC
                    ip="192.168.203.1",  # 正常的IP
                    subnet_mask="255.255.255.0"
                )
                if record_rejection(result, name_value, desc, name_value):
                    name_passed += 1
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → VLAN名称验证结果: {name_passed}/{len(name_test_cases)} 通过")

            # 10.4 VLAN ID不规范测试（其他字段正常）
            print("\n  [10.4] VLAN ID不规范测试...")
            rec.add_detail("【10.4 VLAN ID验证】")
            id_test_cases = [
                ("0", "VLAN ID为0"),
                ("4096", "VLAN ID超出范围"),
                ("-1", "VLAN ID为负数"),
                ("abc", "VLAN ID非数字"),
            ]
            id_passed = 0
            for index, (id_value, desc) in enumerate(id_test_cases):
                target_name = f"vlan_bad_id_{index}"
                result = page.try_add_vlan_invalid(
                    vlan_id=id_value,  # 不合规的ID
                    vlan_name=target_name,  # 正常的名称
                    mac="00:11:22:33:44:04",  # 正常的MAC
                    ip="192.168.204.1",  # 正常的IP
                    subnet_mask="255.255.255.0"
                )
                if record_rejection(result, id_value, desc, target_name):
                    id_passed += 1
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → VLAN ID验证结果: {id_passed}/{len(id_test_cases)} 通过")

            # 10.5 VLAN ID冲突测试（所有字段都合规，但ID冲突）
            print("\n  [10.5] VLAN ID冲突测试...")
            rec.add_detail("【10.5 VLAN ID冲突验证】")
            # 先确保有一个存在的VLAN
            existing_vlan = test_vlans[0]  # vlan_edit_1, ID=100
            rec.add_detail(f"  使用已存在的VLAN ID: {existing_vlan['id']}")
            result = page.try_add_vlan_invalid(
                vlan_id=existing_vlan["id"],  # 使用已存在的ID（冲突）
                vlan_name="vlan_test_conflict",  # 正常的名称（不同于已存在的）
                mac="00:11:22:33:44:05",  # 正常的MAC
                ip="192.168.205.1",  # 正常的IP
                subnet_mask="255.255.255.0"
            )
            conflict_passed = record_rejection(
                result, existing_vlan["id"], "VLAN ID冲突", "vlan_test_conflict"
            )

            # 10.6 扩展IP不合规测试（其他字段正常）
            print("\n  [10.6] 扩展IP不合规测试...")
            rec.add_detail("【10.6 扩展IP验证】")
            ext_ip_test_cases = [
                ("192.168.1", "扩展IP格式错误"),
                ("192.168.1.256", "扩展IP超出范围"),
            ]
            ext_ip_passed = 0
            for ip_value, desc in ext_ip_test_cases:
                result = page.try_add_invalid_extended_ip(existing_vlan["name"], ip_value)
                rejected = bool(result.get("has_validation_error")) and not result.get("success")
                if rejected:
                    error_msg = result.get('error_msg', '验证失败') or '验证失败'
                    print(f"    [OK] {desc}: 正确拦截 - {error_msg}")
                    rec.add_detail(f"  ✓ 输入'{ip_value}' ({desc})")
                    rec.add_detail(f"    提示: {error_msg}")
                    ext_ip_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{ip_value}' ({desc}): 拦截失败")
                    validation_failures.append(
                        f"{desc}: 未得到明确校验拒绝"
                        f"(success={result.get('success')}, "
                        f"has_validation_error={result.get('has_validation_error')}, "
                        f"error={result.get('error_msg')!r})"
                    )
                if backend_verifier is not None:
                    verify_vlan_active(existing_vlan, f"非法扩展IP拦截后-{desc}")
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → 扩展IP验证结果: {ext_ip_passed}/{len(ext_ip_test_cases)} 通过")

            print("\n  [OK] 异常输入测试完成")

            expected_total = (
                len(mac_test_cases) + len(ip_test_cases) + len(name_test_cases) +
                len(id_test_cases) + 1 + len(ext_ip_test_cases)
            )
            actual_total = mac_passed + ip_passed + name_passed + id_passed + int(conflict_passed) + ext_ip_passed
            assert actual_total == expected_total and not validation_failures, (
                f"异常输入验证仅{actual_total}/{expected_total}可靠通过: {validation_failures}"
            )
            _wait_for_vlan_ui(page, [vlan["name"] for vlan in test_vlans])

            # 刷新页面确保状态干净
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

        # ========== 步骤11: 批量停用所有VLAN(3次重试, 参照限速模块) ==========
        with rec.step("步骤11: 批量停用VLAN", f"批量停用剩余的 {len(test_vlans)} 条VLAN"):
            print("\n[步骤11] 批量停用所有VLAN...")
            rec.add_detail(f"【批量停用操作(3次重试)】")
            disable_success = False
            for attempt in range(3):
                page.page.reload(); page.page.wait_for_timeout(500)
                # 用基类select_all_rules(等待渲染+is_checked判断+等"已选X条"确认选中生效),
                # 替代裸点thead checkbox: 重试时若checkbox保持上次勾选态, 裸click会反向取消全选
                # →底部"已选X条"操作栏不显示→batch_disable找不到footer按钮静默空操作→假成功0/7
                if not page.select_all_rules():
                    print(f"  第{attempt+1}次全选未生效(select_all_rules), 重试...")
                    rec.add_detail(f"  第{attempt+1}次: 全选未生效, 重试")
                    page.page.wait_for_timeout(500)
                    continue
                selected_count = page.get_selected_count()
                if selected_count != len(test_vlans):
                    rec.add_detail(
                        f"  第{attempt+1}次: 全选数量错误，期望{len(test_vlans)}，实际{selected_count}"
                    )
                    page.page.wait_for_timeout(500)
                    continue
                rec.add_detail(f"  第{attempt+1}次: 已精确选中{selected_count}条")
                page.batch_disable(); page.page.wait_for_timeout(1500)
                page.page.reload(); page.page.wait_for_timeout(500)
                if all(page.is_vlan_disabled(v["name"]) for v in test_vlans):
                    disable_success = True; break
                print(f"  第{attempt+1}次批量停用后仍有启用, 重试...")
                rec.add_detail(f"  第{attempt+1}次: 仍有启用, 重试")
            if disable_success:
                print(f"  [OK] 批量停用成功(重试{attempt+1}次)")
                rec.add_detail(f"  ✓ 所有VLAN已停用(重试{attempt+1}次)")
            else:
                still_enabled = [v["name"] for v in test_vlans if not page.is_vlan_disabled(v["name"])]
                ssh_failures.append(f"步骤11-批量停用: {still_enabled} 仍启用")
                print(f"  [WARN] 3次重试后仍启用: {still_enabled}")
                rec.add_detail(f"  ✗ 3次重试后仍启用: {still_enabled}")
            if backend_verifier is not None:
                disabled_passed = sum(
                    1 for vlan in test_vlans
                    if verify_vlan_disabled(vlan, "批量停用")
                )
                rec.add_detail(
                    f"  ── 批量停用后台汇总: {disabled_passed}/{len(test_vlans)}条三层验证通过 ──"
                )

        # ========== 步骤12: 批量启用所有VLAN(3次重试) ==========
        with rec.step("步骤12: 批量启用VLAN", f"批量启用剩余的 {len(test_vlans)} 条VLAN"):
            print("\n[步骤12] 批量启用所有VLAN...")
            rec.add_detail(f"【批量启用操作(3次重试)】")
            enable_success = False
            for attempt in range(3):
                page.page.reload(); page.page.wait_for_timeout(500)
                # 用基类select_all_rules替代裸点thead checkbox(同步骤11, 避免反向取消全选致假成功)
                if not page.select_all_rules():
                    print(f"  第{attempt+1}次全选未生效(select_all_rules), 重试...")
                    rec.add_detail(f"  第{attempt+1}次: 全选未生效, 重试")
                    page.page.wait_for_timeout(500)
                    continue
                selected_count = page.get_selected_count()
                if selected_count != len(test_vlans):
                    rec.add_detail(
                        f"  第{attempt+1}次: 全选数量错误，期望{len(test_vlans)}，实际{selected_count}"
                    )
                    page.page.wait_for_timeout(500)
                    continue
                rec.add_detail(f"  第{attempt+1}次: 已精确选中{selected_count}条")
                page.batch_enable(); page.page.wait_for_timeout(1500)
                page.page.reload(); page.page.wait_for_timeout(500)
                if all(page.is_vlan_enabled(v["name"]) for v in test_vlans):
                    enable_success = True; break
                print(f"  第{attempt+1}次批量启用后仍有停用, 重试...")
                rec.add_detail(f"  第{attempt+1}次: 仍有停用, 重试")
            if enable_success:
                print(f"  [OK] 批量启用成功(重试{attempt+1}次)")
                rec.add_detail(f"  ✓ 所有VLAN已启用(重试{attempt+1}次)")
            else:
                still_disabled = [v["name"] for v in test_vlans if not page.is_vlan_enabled(v["name"])]
                ssh_failures.append(f"步骤12-批量启用: {still_disabled} 仍停用")
                print(f"  [WARN] 3次重试后仍停用: {still_disabled}")
                rec.add_detail(f"  ✗ 3次重试后仍停用: {still_disabled}")
            if backend_verifier is not None:
                enabled_passed = sum(
                    1 for vlan in test_vlans
                    if verify_vlan_active(vlan, "批量启用")
                )
                rec.add_detail(
                    f"  ── 批量启用后台汇总: {enabled_passed}/{len(test_vlans)}条三层验证通过 ──"
                )

        # ========== 步骤13: 批量删除所有VLAN(3次重试) ==========
        with rec.step("步骤13: 批量删除VLAN", f"批量删除剩余的 {len(test_vlans)} 条VLAN"):
            print("\n[步骤13] 批量删除所有VLAN...")
            rec.add_detail(f"【批量删除操作(3次重试)】")
            delete_success = False
            for attempt in range(3):
                page.page.reload(); page.page.wait_for_timeout(500)
                # 用基类select_all_rules替代裸点thead checkbox(同步骤11/12, 避免反向取消全选致假成功)
                if not page.select_all_rules():
                    print(f"  第{attempt+1}次全选未生效(select_all_rules), 重试...")
                    rec.add_detail(f"  第{attempt+1}次: 全选未生效, 重试")
                    page.page.wait_for_timeout(500)
                    continue
                selected_count = page.get_selected_count()
                if selected_count != len(test_vlans):
                    rec.add_detail(
                        f"  第{attempt+1}次: 全选数量错误，期望{len(test_vlans)}，实际{selected_count}"
                    )
                    page.page.wait_for_timeout(500)
                    continue
                rec.add_detail(f"  第{attempt+1}次: 已精确选中{selected_count}条")
                page.batch_delete(); page.page.wait_for_timeout(1500)
                page.page.reload(); page.page.wait_for_timeout(500)
                try:
                    _wait_for_vlan_ui(page, [], timeout_ms=4000)
                    delete_success = True
                    break
                except AssertionError:
                    pass
                print(f"  第{attempt+1}次批量删除后仍有残留, 重试...")
                rec.add_detail(f"  第{attempt+1}次: 仍有残留, 重试")
            if delete_success:
                print(f"  [OK] 批量删除成功(重试{attempt+1}次)")
                rec.add_detail(f"  ✓ 所有VLAN已删除(重试{attempt+1}次)")
            else:
                still_exist = [v["name"] for v in test_vlans if page.vlan_exists(v["name"])]
                ssh_failures.append(f"步骤13-批量删除: {still_exist} 仍存在")
                print(f"  [WARN] 3次重试后仍存在: {still_exist}")
                rec.add_detail(f"  ✗ 3次重试后仍存在: {still_exist}")
            if backend_verifier is not None:
                deleted_passed = sum(
                    1 for vlan in test_vlans
                    if verify_vlan_absent(vlan["name"], "批量删除")
                )
                rec.add_detail(
                    f"  ── 批量删除后台汇总: {deleted_passed}/{len(test_vlans)}条三层无残留 ──"
                )
            assert page.get_vlan_count() == 0, "步骤13批量删除后页面数量不为0"

        # ========== 步骤14: 导入VLAN配置测试 ==========
        with rec.step("步骤14: 导入VLAN配置", "使用导出的CSV和TXT文件进行导入测试"):
            print("\n[步骤14] 导入VLAN配置测试...")
            rec.add_detail(f"【导入测试】")
            import_file_csv = export_file_csv  # 使用步骤9导出的文件
            import_file_txt = export_file_txt

            # ========== 14.1: CSV文件导入（无数据，不需要勾选清空） ==========
            print("\n[步骤14.1] CSV file import test (no existing data)...")
            rec.add_detail(f"  测试1: CSV文件导入（不清空现有数据）")
            assert os.path.exists(import_file_csv), f"CSV文件不存在: {import_file_csv}"
            count_before = page.get_vlan_count()
            assert count_before == 0, f"CSV导入前应无VLAN，实际{count_before}条"
            print(f"  CSV file: {import_file_csv}")
            rec.add_detail(f"    导入文件: {os.path.basename(import_file_csv)}")
            rec.add_detail(f"    导入前VLAN数量: {count_before}")
            rec.add_detail(f"    清空现有数据: 否")
            rec.add_detail(f"    1. 点击导入按钮")
            rec.add_detail(f"    2. 选择CSV文件")
            result = page.import_vlans(import_file_csv, clear_existing=False)
            assert result is True, "CSV导入操作失败"
            rec.add_detail(f"    3. 确认导入: {result}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            _wait_for_vlan_ui(page, [vlan["name"] for vlan in test_vlans])
            count_after = page.get_vlan_count()
            assert count_after == len(test_vlans), (
                f"CSV导入后应有{len(test_vlans)}条，实际{count_after}条"
            )
            rec.add_detail(f"    导入后VLAN数量: {count_after}")
            rec.add_detail(f"    ✓ CSV导入{count_after}条，页面集合精确一致")
            if backend_verifier is not None:
                csv_passed = sum(
                    1 for vlan in test_vlans if verify_vlan_active(vlan, "CSV导入")
                )
                rec.add_detail(
                    f"  ── CSV导入后台汇总: {csv_passed}/{len(test_vlans)}条三层验证通过 ──"
                )

            # ========== 14.2: TXT文件导入（有数据，需要勾选清空） ==========
            print("\n[步骤14.2] TXT file import test (with existing data, clear first)...")
            rec.add_detail(f"  测试2: TXT文件导入（清空现有数据后导入）")
            assert os.path.exists(import_file_txt), f"TXT文件不存在: {import_file_txt}"
            count_before = page.get_vlan_count()
            assert count_before == len(test_vlans), (
                f"TXT导入前应保留CSV导入的{len(test_vlans)}条，实际{count_before}条"
            )
            print(f"  TXT file: {import_file_txt}")
            rec.add_detail(f"    导入文件: {os.path.basename(import_file_txt)}")
            rec.add_detail(f"    导入前VLAN数量: {count_before}")
            rec.add_detail(f"    清空现有数据: 是")
            rec.add_detail(f"    1. 点击导入按钮")
            rec.add_detail(f"    2. 选择TXT文件")
            rec.add_detail(f"    3. 勾选'清空现有配置'")

            result = page.import_vlans(import_file_txt, clear_existing=True)
            assert result is True, "TXT清空导入操作失败"
            rec.add_detail(f"    4. 确认导入: {result}")

            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            _wait_for_vlan_ui(page, [vlan["name"] for vlan in test_vlans])
            count_after = page.get_vlan_count()
            assert count_after == len(test_vlans), (
                f"TXT清空导入后应有{len(test_vlans)}条，实际{count_after}条"
            )
            rec.add_detail(f"    导入后VLAN数量: {count_after}")
            rec.add_detail(f"    ✓ TXT清空导入完成，页面集合精确一致且无重复")
            if backend_verifier is not None:
                txt_passed = sum(
                    1 for vlan in test_vlans if verify_vlan_active(vlan, "TXT清空导入")
                )
                rec.add_detail(
                    f"  ── TXT导入后台汇总: {txt_passed}/{len(test_vlans)}条三层验证通过 ──"
                )

        # ========== 步骤15: 清理导入的VLAN ==========
        with rec.step("步骤15: 清理环境", "清理导入测试产生的VLAN数据"):
            print("\n[步骤15] 清理导入的VLAN...")
            rec.add_detail(f"【环境清理】")
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(1000)

            # 检查是否有VLAN需要清理
            current_count = page.get_vlan_count()
            print(f"  当前VLAN数量: {current_count}")
            rec.add_detail(f"  当前VLAN数量: {current_count}")

            if current_count > 0:
                rec.add_detail(f"【清理操作】")
                # 使用带选中数量复读的全选功能
                if page.select_all_rules():
                    selected_count = page.get_selected_count()
                    assert selected_count == current_count, (
                        f"步骤15全选数量错误: 期望{current_count}, 实际{selected_count}"
                    )
                    rec.add_detail(f"  1. 点击全选复选框")
                    rec.add_detail(f"     已精确选中 {selected_count} 条")
                    rec.add_detail(f"  2. 点击批量删除按钮")
                    # 批量删除
                    page.batch_delete()
                    rec.add_detail(f"  3. 确认删除对话框")
                    page.page.wait_for_timeout(1500)

                    # 验证删除
                    page.page.reload()
                    page.page.wait_for_load_state("networkidle")
                    _wait_for_vlan_ui(page, [])
                    final_count = page.get_vlan_count()
                    assert final_count == 0, f"步骤15清理后仍有{final_count}条VLAN"
                    print(f"  [OK] 清理完成，剩余 {final_count} 条VLAN")
                    rec.add_detail(f"【清理结果】")
                    rec.add_detail(f"  ✓ 清理完成，剩余 {final_count} 条VLAN")
                else:
                    print("  [WARN] 无法全选，逐个删除...")
                    rec.add_detail(f"  无法全选，尝试逐个删除")
                    # 逐个删除
                    deleted_count = 0
                    for vlan in ["vlan_edit_1", "vlan_max_4090", "vlan_ip", "vlan_mac_ip", "vlan_remark", "vlan_ext", "vlan_complete"]:
                        if page.vlan_exists(vlan):
                            page.delete_vlan(vlan)
                            rec.add_detail(f"    删除: {vlan}")
                            deleted_count += 1
                    print("  [OK] 逐个删除完成")
                    rec.add_detail(f"  ✓ 共删除 {deleted_count} 条VLAN")
            else:
                print("  [OK] 没有需要清理的VLAN")
                rec.add_detail(f"  ✓ 环境已干净，无需清理")

            _wait_for_vlan_ui(page, [])
            assert page.get_vlan_count() == 0, "步骤15结束时页面仍有VLAN"
            if backend_verifier is not None:
                backend_rules = backend_verifier.query_vlan_rules(strict=True)
                assert backend_rules == [], f"步骤15结束时数据库仍有VLAN: {backend_rules}"
                cleanup_passed = sum(
                    1 for vlan in test_vlans
                    if verify_vlan_absent(vlan["name"], "导入后清理")
                )
                rec.add_detail(
                    f"  ── 清理后台汇总: {cleanup_passed}/{len(test_vlans)}条三层无残留 ──"
                )

        # ========== 步骤16: 帮助功能测试 ==========
        with rec.step("步骤16: 帮助功能测试", "测试右下角帮助图标的显示和跳转功能"):
            print("\n[步骤16] 帮助功能测试...")
            rec.add_detail(f"【帮助功能测试】")

            # 执行帮助功能测试
            help_result = page.test_help_functionality()

            rec.add_detail(f"  测试1: 帮助图标点击")
            print(f"  帮助图标可点击: {help_result['icon_clickable']}")
            if help_result['icon_clickable']:
                rec.add_detail(f"    ✓ 帮助图标可点击")
            else:
                rec.add_detail(f"    ✗ 帮助图标不可点击")

            rec.add_detail(f"  测试2: 帮助面板显示")
            if help_result['panel_visible']:
                print(f"  帮助面板可见: {help_result['panel_visible']}")
                rec.add_detail(f"    ✓ 帮助面板可见")

                if help_result['has_content']:
                    content_preview = help_result['content_text'][:100] + "..." if len(help_result['content_text']) > 100 else help_result['content_text']
                    print(f"  帮助内容: {content_preview}")
                    rec.add_detail(f"    帮助内容: {content_preview}")

            rec.add_detail(f"  测试3: 帮助链接跳转")
            if help_result['link_clickable']:
                print(f"  帮助链接可点击: {help_result['link_clickable']}")
                rec.add_detail(f"    ✓ 帮助链接可点击")
                if help_result.get('new_page_opened'):
                    print(f"  新页面打开: {help_result['new_page_opened']}")
                    rec.add_detail(f"    ✓ 点击后打开新页面")
                elif help_result.get('url_changed'):
                    print(f"  URL变化: {help_result['url_changed']}")
                    rec.add_detail(f"    ✓ 点击后页面跳转（URL变化）")
                else:
                    rec.add_detail(f"    - 点击成功但未检测到跳转")
            else:
                rec.add_detail(f"    - 未找到帮助链接（可能帮助面板中无链接）")

            rec.add_detail(f"  测试4: 帮助面板关闭")
            print(f"  帮助面板可关闭: {help_result['can_close']}")
            if help_result['can_close']:
                rec.add_detail(f"    ✓ 帮助面板可关闭")
            else:
                rec.add_detail(f"    ✗ 帮助面板无法关闭")

            # 验证基本功能
            if help_result['icon_clickable']:
                print("  [OK] 帮助功能测试通过")
                rec.add_detail("帮助功能测试通过")
            else:
                print("  [WARN] 帮助图标未找到或不可点击")
                rec.add_detail("帮助图标未找到或不可点击（可能页面结构不同）")

            help_failures = []
            if not help_result.get("icon_clickable"):
                help_failures.append("帮助图标不可点击")
            if not help_result.get("panel_visible"):
                help_failures.append("帮助面板未显示")
            if not help_result.get("has_content"):
                help_failures.append("帮助面板无内容")
            if not help_result.get("link_clickable"):
                help_failures.append("帮助链接不可点击")
            elif not (help_result.get("new_page_opened") or help_result.get("url_changed")):
                help_failures.append("点击帮助链接后未发生跳转")
            if not help_result.get("can_close"):
                help_failures.append("帮助面板无法关闭")
            assert not help_failures, f"帮助功能验证失败: {help_failures}"

        print("\n" + "=" * 60)
        print("VLAN综合测试完成")
        print("=" * 60)
        print("测试覆盖功能:")
        print("  - 环境清理: 测试前检查并批量清理")
        print("  - 添加: 8条（普通ID/最大ID/有MAC无IP/无MAC有IP/MAC+IP/MAC+IP+备注/MAC+IP+扩展IP/完整信息）")
        print("  - 编辑: 1条")
        print("  - 停用: 1条")
        print("  - 启用: 1条（单独启用）")
        print("  - 删除: 1条")
        print("  - 搜索: 存在/不存在/清空")
        print("  - 导出: CSV和TXT两个文件")
        print("  - 异常测试: MAC不合规/IP不合规/名称不规范/ID不规范/扩展IP不合规/ID冲突")
        print("  - 批量停用: 7条")
        print("  - 批量启用: 7条")
        print("  - 批量删除: 7条")
        print("  - 导入CSV: 1次（无数据，不需要清空）")
        print("  - 导入TXT: 1次（有数据，需要清空现有配置）")
        print("  - 清理: 导入后删除所有VLAN")
        print("  - 帮助功能: 右下角帮助图标/面板显示/链接跳转")

        # SSH后台验证最终断言
        # ========== 步骤17: 普通VLAN功能验证（client打VLAN tag实测连通性） ==========
        # 建VLAN54(lan1) → client ens11.54打tag → ping路由器VLAN接口IP, 验证VLAN真实生效
        with rec.step("步骤17: 普通VLAN功能验证", "建VLAN54(lan1)→client ens11.54→ping路由器VLAN接口IP验证连通"):
            print("\n[步骤17] 普通VLAN功能验证...")
            rec.add_detail("【普通VLAN连通性实测】client ens11.54 ping路由器VLAN54接口")
            fv_id, fv_name, fv_ip = "54", "vlan_func_54", "192.168.154.1"
            c_ip, c_sub = "192.168.154.100/24", "ens11.54"
            rule_added = subif_added = False
            if backend_verifier is None:
                rec.add_detail("  SSH未配置，跳过VLAN功能验证")
                print("  [SKIP] SSH未配置")
            else:
                try:
                    page.navigate_to_vlan_settings()
                    page.page.wait_for_timeout(500)
                    if page.vlan_exists(fv_name):
                        page.delete_vlan(fv_name)
                        page.page.wait_for_timeout(500)
                    ok = page.add_vlan(vlan_id=fv_id, vlan_name=fv_name, ip=fv_ip, subnet_mask="255.255.255.0", line="lan1")
                    if not ok:
                        rec.add_detail("  ✗ 建VLAN失败")
                        print("  [FAIL] 建VLAN失败")
                        ui_failures.append("步骤17-普通VLAN: 页面建VLAN失败")
                    else:
                        rule_added = True
                        rec.add_detail(f"  ✓ 建VLAN: {fv_name}(id={fv_id}, ip={fv_ip}, line=lan1)")
                        page.page.wait_for_timeout(1500)
                        feature_vlan = {
                            "id": fv_id, "name": fv_name, "ip": fv_ip,
                            "subnet": "255.255.255.0", "line": "lan1",
                        }
                        verify_vlan_active(feature_vlan, "普通VLAN功能")
                        created_subif = backend_verifier.client_add_vlan_subif(54, ip_cidr=c_ip)
                        if created_subif != c_sub:
                            ui_failures.append(
                                f"步骤17-普通VLAN: 客户端子接口名期望{c_sub}实际{created_subif}"
                            )
                        subif_added = True
                        rec.add_detail(f"  client建 {c_sub} + {c_ip}")
                        ssh_verify(
                            f"L4-客户端子接口({c_sub})",
                            backend_verifier.verify_client_vlan_subinterface,
                            c_sub, 54, "ens11", must_pass=True,
                            expected_ip_cidr=c_ip,
                        )
                        pr = backend_verifier.client_ping(c_sub, fv_ip)
                        if pr["connected"] and pr["received"] == 4:
                            rec.add_detail(f"  ✓ ping {fv_ip} 通: {pr['received']}/4 received, rtt={pr['detail']}")
                            print(f"  [OK] 普通VLAN连通: ping {fv_ip} {pr['received']}/4")
                        else:
                            rec.add_detail(f"  ✗ ping {fv_ip} 不通: {pr['raw'][:100]}")
                            print(f"  [FAIL] 普通VLAN不通")
                            ssh_failures.append(
                                f"VLAN功能验证-普通VLAN: ping {fv_ip}仅收到{pr['received']}/4"
                            )
                finally:
                    if subif_added:
                        backend_verifier.client_del_iface(c_sub)
                    if rule_added:
                        try:
                            page.navigate_to_vlan_settings()
                            page.page.wait_for_timeout(500)
                            if page.vlan_exists(fv_name):
                                deleted = page.delete_vlan(fv_name)
                                if not deleted:
                                    ui_failures.append("步骤17清理: 普通VLAN删除失败")
                            verify_vlan_absent(fv_name, "普通VLAN功能清理")
                        except Exception as exc:
                            ui_failures.append(f"步骤17清理异常: {str(exc)[:100]}")

        # ========== 步骤18: QINQ VLAN功能验证（client双层tag实测连通性） ==========
        # 建VLAN54(lan1外层) + VLAN55(line=vlan54内层QINQ) → client ens11.54.55双层tag → ping内层VLAN接口IP
        with rec.step("步骤18: QINQ VLAN功能验证", "建VLAN54(外层)+VLAN55(line=vlan54内层)→client双层tag→ping内层VLAN接口IP"):
            print("\n[步骤18] QINQ VLAN功能验证...")
            rec.add_detail("【QINQ连通性实测】client ens11.54.55 ping路由器VLAN55接口")
            o_id, i_id = "54", "55"
            o_name, i_name = "vlan_qinq_54", "vlan_qinq_55"
            o_ip, i_ip = "192.168.154.1", "192.168.155.1"
            ci_ip, ci_sub = "192.168.155.100/24", "ens11.54.55"
            o_added = i_added = subif_added = False
            if backend_verifier is None:
                rec.add_detail("  SSH未配置，跳过QINQ验证")
            else:
                try:
                    page.navigate_to_vlan_settings()
                    page.page.wait_for_timeout(500)
                    for nm in (i_name, o_name):
                        if page.vlan_exists(nm):
                            page.delete_vlan(nm)
                            page.page.wait_for_timeout(400)
                    if page.add_vlan(vlan_id=o_id, vlan_name=o_name, ip=o_ip, subnet_mask="255.255.255.0", line="lan1"):
                        o_added = True
                        rec.add_detail(f"  ✓ 外层VLAN: {o_name}(id={o_id}, lan1, ip={o_ip})")
                        page.page.wait_for_timeout(1500)
                        if page.add_vlan(vlan_id=i_id, vlan_name=i_name, ip=i_ip, subnet_mask="255.255.255.0", line=o_name):
                            i_added = True
                            rec.add_detail(f"  ✓ 内层VLAN(QINQ): {i_name}(id={i_id}, line={o_name}, ip={i_ip})")
                            page.page.wait_for_timeout(1500)
                            outer_vlan = {
                                "id": o_id, "name": o_name, "ip": o_ip,
                                "subnet": "255.255.255.0", "line": "lan1",
                            }
                            inner_vlan = {
                                "id": i_id, "name": i_name, "ip": i_ip,
                                "subnet": "255.255.255.0", "line": o_name,
                            }
                            verify_vlan_active(outer_vlan, "QINQ外层")
                            verify_vlan_active(inner_vlan, "QINQ内层")
                            created_subif = backend_verifier.client_add_qinq_subif(54, 55, ip_cidr=ci_ip)
                            if created_subif != ci_sub:
                                ui_failures.append(
                                    f"步骤18-QINQ: 客户端子接口名期望{ci_sub}实际{created_subif}"
                                )
                            subif_added = True
                            rec.add_detail(f"  client建双层tag {ci_sub} + {ci_ip}")
                            ssh_verify(
                                "L4-客户端QINQ外层(ens11.54)",
                                backend_verifier.verify_client_vlan_subinterface,
                                "ens11.54", 54, "ens11", must_pass=True,
                            )
                            ssh_verify(
                                f"L4-客户端QINQ内层({ci_sub})",
                                backend_verifier.verify_client_vlan_subinterface,
                                ci_sub, 55, "ens11.54", must_pass=True,
                                expected_ip_cidr=ci_ip,
                            )
                            pr = backend_verifier.client_ping(ci_sub, i_ip)
                            if pr["connected"] and pr["received"] == 4:
                                rec.add_detail(f"  ✓ QINQ ping {i_ip} 通: {pr['received']}/4, rtt={pr['detail']}")
                                print(f"  [OK] QINQ连通: ping {i_ip} {pr['received']}/4")
                            else:
                                rec.add_detail(f"  ✗ QINQ ping {i_ip} 不通: {pr['raw'][:100]}")
                                print(f"  [FAIL] QINQ不通")
                                ssh_failures.append(
                                    f"VLAN功能验证-QINQ: ping {i_ip}仅收到{pr['received']}/4"
                                )
                        else:
                            rec.add_detail("  ✗ 内层VLAN(QINQ)建失败")
                            ui_failures.append("步骤18-QINQ: 内层VLAN创建失败")
                    else:
                        rec.add_detail("  ✗ 外层VLAN建失败")
                        ui_failures.append("步骤18-QINQ: 外层VLAN创建失败")
                finally:
                    if subif_added:
                        backend_verifier.client_del_iface("ens11.54.55")
                        backend_verifier.client_del_iface("ens11.54")
                    try:
                        page.navigate_to_vlan_settings()
                        page.page.wait_for_timeout(500)
                        for nm in (i_name, o_name):
                            if page.vlan_exists(nm):
                                deleted = page.delete_vlan(nm)
                                if not deleted:
                                    ui_failures.append(f"步骤18清理: {nm}删除失败")
                                page.page.wait_for_timeout(400)
                            verify_vlan_absent(nm, "QINQ功能清理")
                    except Exception as exc:
                        ui_failures.append(f"步骤18清理异常: {str(exc)[:100]}")

        # ========== SSH后台验证汇总断言 ==========
        all_failures = ssh_failures + ui_failures
        if ssh_failures:
            print(f"\n[断言] 共 {len(ssh_failures)} 项后台验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        assert not all_failures, f"验证失败({len(all_failures)}项): {'; '.join(all_failures)}"


@pytest.mark.vlan
@pytest.mark.network
class TestVlanImportExport:
    """VLAN导入导出测试"""

    def test_export_vlans(self, vlan_page_logged_in: VlanPage):
        """
        测试导出VLAN配置
        """
        page = vlan_page_logged_in

        # 先添加一条测试数据
        test_vlan = {"id": "901", "name": "vlan_export_t"}

        if page.vlan_exists(test_vlan["name"]):
            page.delete_vlan(test_vlan["name"])

        page.add_vlan(vlan_id=test_vlan["id"], vlan_name=test_vlan["name"])

        # 导出
        export_result = page.export_vlans()

        # 清理
        page.delete_vlan(test_vlan["name"])

        assert export_result is True, "导出VLAN失败"
        print("[OK] VLAN导出测试通过")

    def test_import_vlans(self, vlan_page_logged_in: VlanPage):
        """
        测试导入VLAN配置
        """
        page = vlan_page_logged_in

        # 准备导入文件（如果有）
        import_file = os.path.join(os.path.dirname(__file__), "test_data", "vlan_import.xlsx")

        if os.path.exists(import_file):
            result = page.import_vlans(import_file)
            assert result is True, "导入VLAN失败"
            print("[OK] VLAN导入测试通过")
        else:
            print("[WARN] 导入测试文件不存在，跳过导入测试")
            pytest.skip("导入测试文件不存在")
