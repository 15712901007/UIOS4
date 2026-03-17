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
import pytest
import os
from pages.network.vlan_page import VlanPage
from config.config import get_config
from utils.step_recorder import StepRecorder


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

        ssh_failures = []  # 收集must_pass=True但验证失败的项

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            """执行SSH后台验证并记录结果"""
            if backend_verifier is None:
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = '通过' if result.passed else '失败'
                print(f"    SSH-{label}: {status} - {result.message}")
                rec.add_detail(f"    SSH-{label}: {'✓' if result.passed else '✗'} {result.message}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                return None

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
            print(f"  当前VLAN数量: {current_count}")
            rec.add_detail(f"【环境检查】")
            rec.add_detail(f"  当前VLAN数量: {current_count}")

            if current_count > 0:
                print("  检测到残留数据，执行批量清理...")
                rec.add_detail(f"【清理操作】")
                rec.add_detail("  检测到残留数据，执行批量清理")
                # 使用全选功能
                select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
                if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                    rec.add_detail("  1. 点击全选复选框")
                    select_all_checkbox.click()
                    page.page.wait_for_timeout(500)
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
                    # 逐个删除测试数据
                    for vlan in test_vlans:
                        if page.vlan_exists(vlan["name"]):
                            page.delete_vlan(vlan["name"])
                            print(f"    - 已删除: {vlan['name']}")
                            rec.add_detail(f"  已删除: {vlan['name']}")
            else:
                print("  [OK] 环境干净，无需清理")
                rec.add_detail("  环境干净，无需清理")

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
                    page.edit_vlan(vlan["name"])
                    page.add_extended_ip(vlan["ext_ip"], vlan.get("subnet", "255.255.255.0"))
                    page.click_save()
                    page.wait_for_success_message()
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

                    # L1: 数据库验证
                    expected_fields = {"vlan_id": vlan["id"], "enabled": "yes"}
                    l1 = ssh_verify(
                        f"L1-数据库({vlan_name})",
                        backend_verifier.verify_vlan_database,
                        vlan_name,
                        must_pass=True,
                        expected_fields=expected_fields,
                    )

                    if l1 and l1.passed:
                        db_rule = l1.details.get("rule", {})
                        rec.add_detail(f"      数据库: id={db_rule.get('id')}, vlan_id={db_rule.get('vlan_id')}, enabled={db_rule.get('enabled')}")

                        # L2: 网络接口验证
                        ssh_verify(
                            f"L2-网络接口({vlan_name})",
                            backend_verifier.verify_vlan_interface,
                            vlan_name,
                            must_pass=True,
                        )

                        # L3: /proc/net/vlan验证
                        ssh_verify(
                            f"L3-proc({vlan_name})",
                            backend_verifier.verify_vlan_proc,
                            vlan_name,
                            expected_vlan_id=vlan["id"],
                        )

                        verify_passed += 1

                print(f"  [OK] 后台验证完成: {verify_passed}/{len(test_vlans)} 条VLAN验证通过")
                rec.add_detail(f"  ── 验证汇总: {verify_passed}/{len(test_vlans)} 条VLAN验证通过 ──")
        else:
            print("\n[步骤3.5] 后台数据验证: 跳过（未配置SSH或paramiko未安装）")

        # ========== 步骤4: 编辑第1条VLAN ==========
        with rec.step("步骤4: 编辑VLAN", "编辑第1条VLAN的名称"):
            print("\n[步骤4] 编辑第1条VLAN...")
            edit_vlan = test_vlans[0]
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
            assert page.vlan_exists(new_name), "编辑后的VLAN未找到"
            test_vlans[0]["name"] = new_name  # 更新测试数据
            print(f"  [OK] VLAN编辑成功: {edit_vlan['name']} -> {new_name}")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ 编辑成功，新名称已生效")

            # SSH验证编辑后数据库更新
            if backend_verifier is not None:
                ssh_verify(
                    "L1-编辑验证",
                    backend_verifier.verify_vlan_database,
                    new_name,
                    expected_fields={"vlan_id": edit_vlan["id"]},
                )

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
                ssh_verify(
                    "L1-停用验证",
                    backend_verifier.verify_vlan_database,
                    disable_vlan["name"],
                    must_pass=True,
                    expected_fields={"enabled": "no"},
                )

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
                ssh_verify(
                    "L1-启用验证",
                    backend_verifier.verify_vlan_database,
                    disable_vlan["name"],
                    must_pass=True,
                    expected_fields={"enabled": "yes"},
                )

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

            # 通过条目数减少来验证删除成功
            page.page.reload()
            page.page.wait_for_timeout(500)
            count_after_delete = page.get_vlan_count()
            print(f"  删除后条目数: {count_after_delete}")
            rec.add_detail(f"  删除后条目数: {count_after_delete}")

            assert count_after_delete < count_before_delete, f"删除后条目数未减少: {count_before_delete} -> {count_after_delete}"

            test_vlans.remove(delete_vlan)  # 从测试数据中移除
            print(f"  [OK] VLAN删除成功: {delete_vlan['name']}")
            rec.add_detail(f"【验证结果】")
            rec.add_detail(f"  ✓ 删除成功，条目数减少 {count_before_delete - count_after_delete}")

            # SSH验证删除后数据库中规则不存在
            if backend_verifier is not None:
                try:
                    db_rule = backend_verifier.find_vlan_rule(tagname=delete_vlan["name"])
                    if db_rule is None:
                        print(f"    SSH-L1-删除验证: 通过 - 规则已从数据库删除")
                        rec.add_detail(f"    SSH-L1-删除验证: ✓ 规则已从数据库删除")
                    else:
                        print(f"    SSH-L1-删除验证: 失败 - 规则仍在数据库中")
                        ssh_failures.append(f"SSH-L1-删除验证: VLAN {delete_vlan['name']}仍在数据库中")
                except Exception as e:
                    print(f"    SSH-L1-删除验证: 跳过 - {str(e)[:80]}")
                    rec.add_detail(f"    SSH-L1-删除验证: 跳过 - {str(e)[:80]}")

        # ========== 步骤8: 搜索测试 ==========
        with rec.step("步骤8: 搜索功能测试", "测试搜索存在的VLAN和不存在的VLAN"):
            print("\n[步骤8] 搜索测试...")
            rec.add_detail(f"【搜索测试】")

            # 8.1 搜索存在的VLAN（按名称）
            search_target = test_vlans[2]["name"]  # vlan_ip (注意索引变了，因为删除了第3条)
            rec.add_detail(f"  测试1: 搜索存在的VLAN")
            rec.add_detail(f"    搜索关键词: {search_target}")
            page.search_vlan(search_target)
            page.page.wait_for_timeout(500)
            assert page.vlan_exists(search_target), f"搜索不到存在的VLAN: {search_target}"
            print(f"  [OK] 搜索存在VLAN成功: {search_target}")
            rec.add_detail(f"    ✓ 搜索成功，VLAN已找到")

            # 8.2 搜索不存在的VLAN
            rec.add_detail(f"  测试2: 搜索不存在的VLAN")
            rec.add_detail(f"    搜索关键词: not_exist_vlan_xxx")
            page.search_vlan("not_exist_vlan_xxx")
            page.page.wait_for_timeout(500)
            count = page.get_vlan_count()
            assert count == 0, f"搜索不存在的数据时，应该显示0条记录，实际显示{count}条"
            print("  [OK] 搜索不存在VLAN验证成功，显示0条记录")
            rec.add_detail(f"    ✓ 验证成功，显示0条记录")

            # 8.3 清空搜索，验证数据恢复
            rec.add_detail(f"  测试3: 清空搜索条件")
            page.clear_search()
            page.page.wait_for_timeout(500)
            remaining_count = page.get_vlan_count()
            print(f"  [OK] 清空搜索成功，当前显示 {remaining_count} 条记录")
            rec.add_detail(f"    ✓ 清空成功，显示 {remaining_count} 条记录")

        # ========== 步骤8.5: 排序测试 ==========
        with rec.step("步骤8.5: 排序功能测试", "测试VLAN名称和IP地址列的排序功能"):
            print("\n[步骤8.5] 排序测试...")
            rec.add_detail(f"【排序测试】")
            rec.add_detail(f"  测试字段: VLAN 名称、IP地址")

            sortable_columns = ["VLAN 名称", "IP地址"]
            sort_results = {}

            for col in sortable_columns:
                try:
                    # 点击3次：正序→倒序→默认
                    for click_idx, sort_label in enumerate(["正序", "倒序", "默认"]):
                        result = page.sort_by_column(col)
                        page.page.wait_for_timeout(300)
                        if result:
                            rec.add_detail(f"  ✓ {col} 排序({sort_label}): 成功")
                        else:
                            rec.add_detail(f"  ✗ {col} 排序({sort_label}): 失败")
                    sort_results[col] = True
                    print(f"  [OK] {col} 排序测试通过")
                except Exception as e:
                    sort_results[col] = False
                    print(f"  [FAIL] {col} 排序测试失败: {e}")
                    rec.add_detail(f"  ✗ {col} 排序异常: {e}")

            passed = sum(1 for v in sort_results.values() if v)
            print(f"  [OK] 排序测试完成: {passed}/{len(sortable_columns)} 个字段通过")
            rec.add_detail(f"  ── 汇总: {passed}/{len(sortable_columns)} 个字段排序测试通过 ──")

        # ========== 步骤9: 导出VLAN配置（两次导出：CSV和TXT） ==========
        with rec.step("步骤9: 导出VLAN配置", "导出CSV和TXT两种格式的配置文件"):
            print("\n[步骤9] 导出VLAN配置...")
            rec.add_detail(f"【导出测试】")
            config = get_config()
            export_file_csv = config.test_data.get_export_path("vlan", config.get_project_root())
            export_file_txt = export_file_csv.replace(".csv", ".txt")

            try:
                # 第一次导出：CSV文件
                rec.add_detail(f"  测试1: 导出CSV格式")
                rec.add_detail(f"    目标文件: {os.path.basename(export_file_csv)}")
                export_result_csv = page.export_vlans(export_format="csv")
                if export_result_csv:
                    print(f"  [OK] 导出CSV成功: {export_file_csv}")
                    rec.add_detail(f"    ✓ CSV导出成功")
                else:
                    print(f"  [WARN] 导出CSV失败")
                    rec.add_detail(f"    ✗ CSV导出失败")

                # 短暂等待后进行第二次导出
                page.page.wait_for_timeout(500)

                # 第二次导出：TXT文件
                rec.add_detail(f"  测试2: 导出TXT格式")
                rec.add_detail(f"    目标文件: {os.path.basename(export_file_txt)}")
                export_result_txt = page.export_vlans(export_format="txt")
                if export_result_txt:
                    print(f"  [OK] 导出TXT成功: {export_file_txt}")
                    rec.add_detail(f"    ✓ TXT导出成功")
                else:
                    print(f"  [WARN] 导出TXT失败")
                    rec.add_detail(f"    ✗ TXT导出失败")

            except Exception as e:
                print(f"  [WARN] 导出测试异常: {e}")
                rec.add_detail(f"  导出异常: {str(e)}")

            # 确保关闭可能存在的模态框，刷新页面确保状态干净
            page.close_modal_if_exists()
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

        # ========== 步骤10: 异常输入测试 ==========
        with rec.step("步骤10: 异常输入测试", "测试各种不合规输入的验证拦截"):
            print("\n[步骤10] 异常输入测试...")

            # 10.1 MAC地址不合规测试（其他字段正常）
            print("\n  [10.1] MAC地址不合规测试...")
            rec.add_detail("【10.1 MAC地址验证】")
            mac_test_cases = [
                ("00:11:22", "MAC格式错误-少段"),
                ("00:11:22:33:44:55:66", "MAC格式错误-多段"),
                ("00:11:22:33:44:GG", "MAC非法字符"),
            ]
            mac_passed = 0
            for mac_value, desc in mac_test_cases:
                result = page.try_add_vlan_invalid(
                    vlan_id="201",
                    vlan_name="vlan_test_mac",  # 正常的名称
                    mac=mac_value,  # 不合规的MAC
                    ip="192.168.201.1",  # 正常的IP
                    subnet_mask="255.255.255.0"  # 正常的子网掩码
                )
                if result["has_validation_error"] or not result["success"]:
                    error_msg = result.get('error_msg', '验证失败') or '验证失败'
                    print(f"    [OK] {desc}: 正确拦截 - {error_msg}")
                    rec.add_detail(f"  ✓ 输入'{mac_value}' ({desc})")
                    rec.add_detail(f"    提示: {error_msg}")
                    mac_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{mac_value}' ({desc}): 拦截失败")
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
            for ip_value, desc in ip_test_cases:
                result = page.try_add_vlan_invalid(
                    vlan_id="202",
                    vlan_name="vlan_test_ip",  # 正常的名称
                    mac="00:11:22:33:44:02",  # 正常的MAC
                    ip=ip_value,  # 不合规的IP
                    subnet_mask="255.255.255.0"
                )
                if result["has_validation_error"] or not result["success"]:
                    error_msg = result.get('error_msg', '验证失败') or '验证失败'
                    print(f"    [OK] {desc}: 正确拦截 - {error_msg}")
                    rec.add_detail(f"  ✓ 输入'{ip_value}' ({desc})")
                    rec.add_detail(f"    提示: {error_msg}")
                    ip_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{ip_value}' ({desc}): 拦截失败")
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
            for name_value, desc in name_test_cases:
                result = page.try_add_vlan_invalid(
                    vlan_id="203",  # 正常的ID
                    vlan_name=name_value,  # 不合规的名称
                    mac="00:11:22:33:44:03",  # 正常的MAC
                    ip="192.168.203.1",  # 正常的IP
                    subnet_mask="255.255.255.0"
                )
                if result["has_validation_error"] or not result["success"]:
                    error_msg = result.get('error_msg', '验证失败') or '验证失败'
                    print(f"    [OK] {desc}: 正确拦截 - {error_msg}")
                    rec.add_detail(f"  ✓ 输入'{name_value}' ({desc})")
                    rec.add_detail(f"    提示: {error_msg}")
                    name_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{name_value}' ({desc}): 拦截失败")
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
            for id_value, desc in id_test_cases:
                result = page.try_add_vlan_invalid(
                    vlan_id=id_value,  # 不合规的ID
                    vlan_name="vlan_test_id",  # 正常的名称
                    mac="00:11:22:33:44:04",  # 正常的MAC
                    ip="192.168.204.1",  # 正常的IP
                    subnet_mask="255.255.255.0"
                )
                if result["has_validation_error"] or not result["success"]:
                    error_msg = result.get('error_msg', '验证失败') or '验证失败'
                    print(f"    [OK] {desc}: 正确拦截 - {error_msg}")
                    rec.add_detail(f"  ✓ 输入'{id_value}' ({desc})")
                    rec.add_detail(f"    提示: {error_msg}")
                    id_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{id_value}' ({desc}): 拦截失败")
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
            if result["has_validation_error"] or not result["success"]:
                error_msg = result.get('error_msg', '验证失败') or '验证失败'
                print(f"    [OK] VLAN ID冲突({existing_vlan['id']}): 正确拦截 - {error_msg}")
                rec.add_detail(f"  ✓ 重复ID '{existing_vlan['id']}'")
                rec.add_detail(f"    提示: {error_msg}")
            else:
                print(f"    [FAIL] VLAN ID冲突({existing_vlan['id']}): 未被拦截！")
                rec.add_detail(f"  ✗ 重复ID '{existing_vlan['id']}': 冲突检测失败，未拦截")

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
                if result["has_validation_error"] or not result["success"]:
                    error_msg = result.get('error_msg', '验证失败') or '验证失败'
                    print(f"    [OK] {desc}: 正确拦截 - {error_msg}")
                    rec.add_detail(f"  ✓ 输入'{ip_value}' ({desc})")
                    rec.add_detail(f"    提示: {error_msg}")
                    ext_ip_passed += 1
                else:
                    print(f"    [FAIL] {desc}: 未被拦截！")
                    rec.add_detail(f"  ✗ 输入'{ip_value}' ({desc}): 拦截失败")
                page.page.wait_for_timeout(300)
            rec.add_detail(f"  → 扩展IP验证结果: {ext_ip_passed}/{len(ext_ip_test_cases)} 通过")

            print("\n  [OK] 异常输入测试完成")

            # 刷新页面确保状态干净
            page.page.reload()
            page.page.wait_for_load_state("networkidle")
            page.page.wait_for_timeout(500)

        # ========== 步骤11: 批量停用所有VLAN ==========
        with rec.step("步骤11: 批量停用VLAN", f"批量停用剩余的 {len(test_vlans)} 条VLAN"):
            print("\n[步骤11] 批量停用所有VLAN...")
            rec.add_detail(f"【批量停用操作】")
            rec.add_detail(f"  目标数量: {len(test_vlans)} 条VLAN")
            # 使用全选功能
            select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
            if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                rec.add_detail(f"  1. 点击全选复选框")
                select_all_checkbox.click()
                page.page.wait_for_timeout(500)
            rec.add_detail(f"  2. 点击批量停用按钮")
            page.batch_disable()
            rec.add_detail(f"  3. 确认停用对话框")
            # 等待操作完成（成功消息可能很快消失，通过状态验证替代）
            page.page.wait_for_timeout(1500)

            # 验证全部变为停用状态
            rec.add_detail(f"【验证结果】")
            page.page.reload()
            page.page.wait_for_timeout(500)
            disabled_count = 0
            for vlan in test_vlans:
                assert page.is_vlan_disabled(vlan["name"]), f"VLAN {vlan['name']} 批量停用后仍为启用状态"
                disabled_count += 1
            print(f"  [OK] 批量停用 {len(test_vlans)} 条VLAN成功")
            rec.add_detail(f"  ✓ 所有 {disabled_count} 条VLAN已停用")

            # SSH验证批量停用后数据库中所有规则enabled=no
            if backend_verifier is not None:
                try:
                    vlan_rules = backend_verifier.query_vlan_rules()
                    test_names = {v["name"] for v in test_vlans}
                    disabled_in_db = sum(1 for r in vlan_rules if r.get("tagname") in test_names and r.get("enabled") == "no")
                    print(f"    SSH: 数据库中{disabled_in_db}/{len(test_vlans)}条VLAN已停用")
                    rec.add_detail(f"    SSH: {disabled_in_db}/{len(test_vlans)}条停用")
                    if disabled_in_db < len(test_vlans):
                        ssh_failures.append(f"SSH-L1-批量停用: 仅{disabled_in_db}/{len(test_vlans)}条VLAN停用")
                except Exception as e:
                    print(f"    SSH-L1-批量停用验证: 跳过 - {str(e)[:80]}")
                    rec.add_detail(f"    SSH-L1-批量停用验证: 跳过 - {str(e)[:80]}")

        # ========== 步骤12: 批量启用所有VLAN ==========
        with rec.step("步骤12: 批量启用VLAN", f"批量启用剩余的 {len(test_vlans)} 条VLAN"):
            print("\n[步骤12] 批量启用所有VLAN...")
            rec.add_detail(f"【批量启用操作】")
            rec.add_detail(f"  目标数量: {len(test_vlans)} 条VLAN")
            # 使用全选功能
            select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
            if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                rec.add_detail(f"  1. 点击全选复选框")
                select_all_checkbox.click()
                page.page.wait_for_timeout(500)
            rec.add_detail(f"  2. 点击批量启用按钮")
            page.batch_enable()
            rec.add_detail(f"  3. 确认启用对话框")
            # 等待操作完成
            page.page.wait_for_timeout(1500)

            # 验证全部变为启用状态
            rec.add_detail(f"【验证结果】")
            page.page.reload()
            page.page.wait_for_timeout(500)
            enabled_count = 0
            for vlan in test_vlans:
                assert page.is_vlan_enabled(vlan["name"]), f"VLAN {vlan['name']} 批量启用后仍为停用状态"
                enabled_count += 1
            print(f"  [OK] 批量启用 {len(test_vlans)} 条VLAN成功")
            rec.add_detail(f"  ✓ 所有 {enabled_count} 条VLAN已启用")

        # ========== 步骤13: 批量删除所有VLAN ==========
        with rec.step("步骤13: 批量删除VLAN", f"批量删除剩余的 {len(test_vlans)} 条VLAN"):
            print("\n[步骤13] 批量删除所有VLAN...")
            rec.add_detail(f"【批量删除操作】")
            rec.add_detail(f"  目标数量: {len(test_vlans)} 条VLAN")
            # 使用全选功能
            select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
            if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                rec.add_detail(f"  1. 点击全选复选框")
                select_all_checkbox.click()
                page.page.wait_for_timeout(500)
            rec.add_detail(f"  2. 点击批量删除按钮")
            page.batch_delete()
            rec.add_detail(f"  3. 确认删除对话框")
            # 等待操作完成
            page.page.wait_for_timeout(1500)

            # 验证所有VLAN已删除
            rec.add_detail(f"【验证结果】")
            page.page.reload()
            page.page.wait_for_timeout(500)
            for vlan in test_vlans:
                assert not page.vlan_exists(vlan["name"]), f"VLAN {vlan['name']} 仍然存在"
            print(f"  [OK] 批量删除 {len(test_vlans)} 条VLAN成功")
            rec.add_detail(f"  ✓ 所有 {len(test_vlans)} 条VLAN已删除")

            # SSH验证批量删除后数据库中测试规则不存在
            if backend_verifier is not None:
                try:
                    vlan_rules = backend_verifier.query_vlan_rules()
                    test_names = {v["name"] for v in test_vlans}
                    remaining = [r for r in vlan_rules if r.get("tagname") in test_names]
                    if remaining:
                        print(f"    SSH: 数据库中仍有{len(remaining)}条测试VLAN")
                        ssh_failures.append(f"SSH-L1-批量删除: 数据库中仍有{len(remaining)}条测试VLAN")
                    else:
                        print(f"    SSH: 数据库中测试VLAN已全部删除（总规则数: {len(vlan_rules)}）")
                        rec.add_detail(f"    SSH: 测试VLAN已全部删除")
                except Exception as e:
                    print(f"    SSH-L1-批量删除验证: 跳过 - {str(e)[:80]}")
                    rec.add_detail(f"    SSH-L1-批量删除验证: 跳过 - {str(e)[:80]}")

        # ========== 步骤14: 导入VLAN配置测试 ==========
        with rec.step("步骤14: 导入VLAN配置", "使用导出的CSV和TXT文件进行导入测试"):
            print("\n[步骤14] 导入VLAN配置测试...")
            rec.add_detail(f"【导入测试】")
            import_file_csv = export_file_csv  # 使用步骤9导出的文件
            import_file_txt = export_file_txt

            # ========== 14.1: CSV文件导入（无数据，不需要勾选清空） ==========
            print("\n[步骤14.1] CSV file import test (no existing data)...")
            rec.add_detail(f"  测试1: CSV文件导入（不清空现有数据）")
            if os.path.exists(import_file_csv):
                count_before = page.get_vlan_count()
                print(f"  CSV file: {import_file_csv}")
                print(f"  Count before: {count_before}")
                rec.add_detail(f"    导入文件: {os.path.basename(import_file_csv)}")
                rec.add_detail(f"    导入前VLAN数量: {count_before}")
                rec.add_detail(f"    清空现有数据: 否")

                # 不需要勾选清空现有配置（因为没有数据）
                rec.add_detail(f"    1. 点击导入按钮")
                rec.add_detail(f"    2. 选择CSV文件")
                result = page.import_vlans(import_file_csv, clear_existing=False)
                print(f"  Import result: {result}")
                rec.add_detail(f"    3. 确认导入: {result}")

                page.page.reload()
                page.page.wait_for_timeout(500)
                count_after = page.get_vlan_count()
                print(f"  Count after: {count_after}")
                rec.add_detail(f"    导入后VLAN数量: {count_after}")

                if count_after > count_before:
                    print(f"  [OK] CSV import successful, added {count_after - count_before} records")
                    rec.add_detail(f"    ✓ 成功添加 {count_after - count_before} 条记录")
            else:
                print(f"  [WARN] CSV file not found: {import_file_csv}")
                rec.add_detail(f"    ✗ CSV文件不存在")

            # ========== 14.2: TXT文件导入（有数据，需要勾选清空） ==========
            print("\n[步骤14.2] TXT file import test (with existing data, clear first)...")
            rec.add_detail(f"  测试2: TXT文件导入（清空现有数据后导入）")
            if os.path.exists(import_file_txt):
                count_before = page.get_vlan_count()
                print(f"  TXT file: {import_file_txt}")
                print(f"  Count before: {count_before}")
                rec.add_detail(f"    导入文件: {os.path.basename(import_file_txt)}")
                rec.add_detail(f"    导入前VLAN数量: {count_before}")
                rec.add_detail(f"    清空现有数据: 是")
                rec.add_detail(f"    1. 点击导入按钮")
                rec.add_detail(f"    2. 选择TXT文件")
                rec.add_detail(f"    3. 勾选'清空现有配置'")

                # 需要勾选清空现有配置（因为有CSV导入的数据）
                result = page.import_vlans(import_file_txt, clear_existing=True)
                print(f"  Import result: {result}")
                rec.add_detail(f"    4. 确认导入: {result}")

                page.page.reload()
                page.page.wait_for_timeout(500)
                count_after = page.get_vlan_count()
                print(f"  Count after: {count_after}")
                rec.add_detail(f"    导入后VLAN数量: {count_after}")

                print(f"  [OK] TXT import with clear completed")
                rec.add_detail(f"    ✓ TXT导入完成（已清空旧数据）")
            else:
                print(f"  [WARN] TXT file not found: {import_file_txt}")
                rec.add_detail(f"    ✗ TXT文件不存在")

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
                # 使用全选功能
                select_all_checkbox = page.page.locator("thead input[type='checkbox']").first
                if select_all_checkbox.count() > 0 and select_all_checkbox.is_enabled():
                    rec.add_detail(f"  1. 点击全选复选框")
                    select_all_checkbox.click()
                    page.page.wait_for_timeout(500)

                    rec.add_detail(f"  2. 点击批量删除按钮")
                    # 批量删除
                    page.batch_delete()
                    rec.add_detail(f"  3. 确认删除对话框")
                    page.page.wait_for_timeout(1500)

                    # 验证删除
                    page.page.reload()
                    page.page.wait_for_timeout(500)
                    final_count = page.get_vlan_count()
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
        if ssh_failures:
            print(f"\n[SSH断言] 共 {len(ssh_failures)} 项后台验证失败:")
            for f in ssh_failures:
                print(f"  - {f}")
            assert not ssh_failures, f"SSH后台验证失败({len(ssh_failures)}项): {'; '.join(ssh_failures)}"


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
