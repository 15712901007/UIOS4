"""VPN客户端6模块综合测试通用流程(数据驱动)

6模块(PPTP/L2TP/OpenVPN/IPSec VPN/IKEv2/WireGuard)UI/后端验证逻辑同构,
本helper封装完整测试流程, 各test文件只需提供test_rules数据+module_key+page实例。

流程(参照端口映射27步, 适配VPN客户端特性):
1.清理 → 2~N.添加多条(SSH L1) → 总数+全链路(L2连接软断言) → 编辑 → 停用 → 启用 → 删除 →
搜索 → 导出CSV/TXT → 异常输入 → 批量停用/启用/删除 → 导入追加CSV/清空TXT → 清理 → 帮助

VPN客户端特性: 启用=自动拨号; 无segmented筛选; 无复制按钮; 本地IP/状态列反映连接
后端: L1数据库(must_pass=True硬断言) + L2连接状态(软断言, 拨号依赖服务端10.66.0.40)
"""
import os


def run_vpn_comprehensive_test(*, page, rec, request,
                                module_key, test_rules, invalid_base_fields,
                                edit_spec, ssh_failures, ui_failures):
    """运行VPN客户端模块综合测试(6模块共用)

    Args:
        page: VPN page实例(已登录导航到本模块)
        rec: StepRecorder
        request: pytest request(动态获取backend_verifier)
        module_key: pptp/l2tp/openvpn/ipsec/ike/wireguard (映射verify_xxx_*方法)
        test_rules: list[{name, add_kwargs, db_fields, desc}] 添加规则数据
        invalid_base_fields: dict 异常输入时除name外的必填字段(填合法值)
        edit_spec: dict {target, new_name, field_updates, db_fields}
        ssh_failures: list 传入累积SSH硬失败
        ui_failures: list 传入累积UI失败
    """
    try:
        backend_verifier = request.getfixturevalue('backend_verifier')
    except Exception:
        backend_verifier = None

    verify_db = getattr(backend_verifier, f'verify_{module_key}_database', None) if backend_verifier else None
    verify_full = getattr(backend_verifier, f'verify_{module_key}_full_chain', None) if backend_verifier else None
    query_rules = getattr(backend_verifier, f'query_{module_key}_rules', None) if backend_verifier else None

    def ssh_verify(label, func, *args, must_pass=False, **kwargs):
        if func is None or backend_verifier is None:
            return None
        try:
            result = func(*args, **kwargs)
            status = '[OK]' if result.passed else '[FAIL]'
            print(f"    SSH-{label}: {status} - {result.message}")
            rec.add_detail(f"    SSH-{label}: {status} {result.message}")
            if getattr(result, 'raw_output', ''):
                rec.add_detail(f"      SSH数据: {result.raw_output}")
            if must_pass and not result.passed:
                ssh_failures.append(f"SSH-{label}: {result.message}")
            return result
        except Exception as e:
            print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
            rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
            if must_pass:
                ssh_failures.append(f"SSH-{label}: 异常被吞 - {str(e)[:80]}")
            return None

    name_prefix = page.NAME_PREFIX
    module_name = page.MODULE_NAME
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    export_csv = os.path.join(project_root, "test_data", "exports", module_name, f"{module_name}_config.csv")
    export_txt = os.path.join(project_root, "test_data", "exports", module_name, f"{module_name}_config.txt")

    def clean_all(rounds=3):
        """批量清理直到为空(或3轮)"""
        for _ in range(rounds):
            page.navigate_to_module()
            page.page.wait_for_timeout(800)
            if page.get_rule_count() == 0:
                return
            sel = page.page.locator("thead input[type='checkbox']").first
            if sel.count() > 0 and sel.is_enabled():
                sel.click()
                page.page.wait_for_timeout(500)
                page.batch_delete()
                page.page.wait_for_timeout(2000)
                page.wait_for_success_message(timeout=3000)

    def fill_fields_by_id(fields_dict):
        """按{elem_id:value}填表(input/textarea自适应), 用于异常输入重复/超长"""
        for fid, val in (fields_dict or {}).items():
            if page._is_textarea(fid):
                page._set_textarea(fid, val)
            else:
                page._set_input(fid, val)

    print("\n" + "=" * 60)
    print(f"{page.SUBTAB}客户端综合测试开始 (module={module_key})")
    print("=" * 60)
    print(f"测试数据: {len(test_rules)} 条规则")
    for r in test_rules:
        print(f"  - {r['name']}: {r['desc']}")

    # ===== 步骤1: 清理环境 =====
    with rec.step("步骤1: 检查并清理环境", "清理残留规则"):
        print("\n[步骤1] 清理环境...")
        page.navigate_to_module()
        page.page.wait_for_timeout(1000)
        current = page.get_rule_count()
        rec.add_detail(f"当前规则数: {current}")
        clean_all()
        page.navigate_to_module()
        page.page.wait_for_timeout(800)
        final = page.get_rule_count()
        print(f"  [OK] 清理完成, 剩余 {final} 条")
        rec.add_detail(f"清理后剩余: {final}")

    # ===== 步骤2~N: 逐条添加 + SSH L1 =====
    for idx, rule in enumerate(test_rules):
        with rec.step(f"步骤{idx+2}: 添加 {rule['name']}", rule['desc']):
            print(f"\n[步骤{idx+2}] 添加: {rule['name']}")
            rec.add_detail(f"场景: {rule['desc']}")
            result = page.add_rule(**rule['add_kwargs'])
            assert result, f"添加 {rule['name']} 失败"
            print(f"  + 已添加: {rule['name']}")
            rec.add_detail("[OK] 添加成功")
            if verify_db:
                exp = {"enabled": "yes"}
                exp.update(rule.get('db_fields', {}))
                ssh_verify(f"L1({rule['name']})", verify_db, rule['name'],
                           must_pass=True, expected_fields=exp)

    # ===== 总数 + 全链路 =====
    total_step = len(test_rules) + 2
    with rec.step(f"步骤{total_step}: 总数+全链路", f"{len(test_rules)}条 + SSH L1+L2"):
        print(f"\n[步骤{total_step}] 总数+全链路...")
        page.navigate_to_module()
        page.page.wait_for_timeout(1000)
        page.clear_search()
        page.page.wait_for_timeout(500)
        all_names = page.get_rule_list()
        rec.add_detail(f"列表({len(all_names)}): {all_names}")
        for rule in test_rules:
            assert rule['name'] in all_names, f"{rule['name']} 未找到, 列表: {all_names}"
        total = page.get_rule_count()
        assert total >= len(test_rules), f"总数应≥{len(test_rules)}, 实际{total}"
        print(f"  [OK] 总数: {total}")
        rec.add_detail(f"[OK] 总数验证: {total}")
        if verify_full:
            rec.add_detail("[全链路] L1=数据库 L2=连接(软断言)")
            for rule in test_rules:
                exp = dict(rule.get('db_fields', {}))
                full = ssh_verify(f"全链路({rule['name']})", verify_full, rule['name'],
                                  must_pass=False, expect_enabled=True, expected_fields=exp)
                if full:
                    for r in full.results:
                        tag = '[OK]' if r.passed else '[软断言]'
                        rec.add_detail(f"    {r.level}: {tag} {r.message}")

    cur = total_step + 1

    # ===== 编辑 =====
    es = edit_spec
    with rec.step(f"步骤{cur}: 编辑规则", f"{es['target']}->{es.get('new_name', '改字段')}"):
        print(f"\n[步骤{cur}] 编辑 {es['target']}")
        ok = page.edit_rule(es['target'], field_updates=es.get('field_updates'),
                            new_name=es.get('new_name'))
        if ok:
            target_name = es.get('new_name') or es['target']
            page.navigate_to_module()
            page.page.wait_for_timeout(500)
            if page.rule_exists(target_name):
                print(f"  [OK] 编辑成功 -> {target_name}")
                rec.add_detail(f"[OK] 编辑成功 -> {target_name}")
            if es.get('new_name'):
                for r in test_rules:
                    if r['name'] == es['target']:
                        r['name'] = es['new_name']
                        r['add_kwargs']['name'] = es['new_name']
                        break
            if verify_db and es.get('db_fields'):
                ssh_verify(f"L1编辑后({target_name})", verify_db, target_name,
                           must_pass=True, expected_fields=dict(es['db_fields'], enabled='yes'))
        else:
            print("  [WARN] 编辑失败")
            rec.add_detail("[WARN] 编辑失败")
            ui_failures.append("编辑规则失败")
    cur += 1

    # ===== 停用 =====
    dis_target = test_rules[1]['name'] if len(test_rules) > 1 else test_rules[0]['name']
    with rec.step(f"步骤{cur}: 停用规则", f"{dis_target}+SSH"):
        print(f"\n[步骤{cur}] 停用 {dis_target}")
        page.disable_rule(dis_target)
        page.page.wait_for_timeout(1000)
        if page.is_rule_disabled(dis_target):
            print("  [OK] 停用成功"); rec.add_detail("[OK] 停用成功")
        else:
            rec.add_detail("[WARN] 停用状态未确认")
        if verify_db:
            ssh_verify(f"L1停用({dis_target})", verify_db, dis_target,
                       must_pass=True, expected_fields={"enabled": "no"})
    cur += 1

    # ===== 启用 =====
    with rec.step(f"步骤{cur}: 启用规则", f"{dis_target}+SSH"):
        print(f"\n[步骤{cur}] 启用 {dis_target}")
        page.enable_rule(dis_target)
        page.page.wait_for_timeout(1000)
        if page.is_rule_enabled(dis_target):
            print("  [OK] 启用成功"); rec.add_detail("[OK] 启用成功")
        else:
            rec.add_detail("[WARN] 启用状态未确认")
        if verify_db:
            ssh_verify(f"L1启用({dis_target})", verify_db, dis_target,
                       must_pass=True, expected_fields={"enabled": "yes"})
    cur += 1

    # ===== 删除 =====
    del_target = test_rules[-1]['name']
    with rec.step(f"步骤{cur}: 删除规则", f"{del_target}+SSH"):
        print(f"\n[步骤{cur}] 删除 {del_target}")
        page.delete_rule(del_target)
        page.page.wait_for_timeout(1500)
        page.page.reload()
        page.page.wait_for_load_state("networkidle")
        page.page.wait_for_timeout(500)
        page.navigate_to_module()
        page.page.wait_for_timeout(500)
        assert not page.rule_exists(del_target), f"{del_target} 仍存在"
        print(f"  [OK] 删除成功")
        rec.add_detail("[OK] 删除成功")
        test_rules = [r for r in test_rules if r['name'] != del_target]
        if verify_db:
            ssh_verify(f"L1删除({del_target})", verify_db, del_target,
                       must_pass=True, expect_absent=True)
    cur += 1

    # ===== 搜索 =====
    with rec.step(f"步骤{cur}: 搜索测试", "精确/部分/不存在/清空"):
        print(f"\n[步骤{cur}] 搜索...")
        rec.add_detail("[搜索测试]")
        target = test_rules[0]['name']
        page.search_rule(target)
        page.page.wait_for_timeout(1000)
        if page.rule_exists(target):
            print("  [OK] 精确搜索找到"); rec.add_detail("[OK] 精确搜索")
        else:
            rec.add_detail("[WARN] 精确搜索未找到")
        page.clear_search()
        page.page.wait_for_timeout(300)
        page.search_rule(name_prefix)
        page.page.wait_for_timeout(1000)
        partial = page.get_rule_list()
        rec.add_detail(f"部分匹配'{name_prefix}': {len(partial)}条")
        print(f"  [OK] 部分匹配: {len(partial)}条")
        page.clear_search()
        page.page.wait_for_timeout(300)
        page.search_rule("不存在的VPN名称xyz")
        page.page.wait_for_timeout(1000)
        if page.get_rule_count() == 0:
            print("  [OK] 不存在搜索: 0条"); rec.add_detail("[OK] 不存在0条")
        else:
            rec.add_detail(f"[WARN] 不存在搜索非0")
        page.clear_search()
        page.page.wait_for_timeout(500)
        allc = page.get_rule_count()
        print(f"  [OK] 清空后: {allc}条"); rec.add_detail(f"清空后: {allc}条")
    cur += 1

    # ===== 导出 =====
    with rec.step(f"步骤{cur}: 导出测试", "CSV+TXT"):
        print(f"\n[步骤{cur}] 导出...")
        rec.add_detail("[导出测试]")
        for fmt in ['csv', 'txt']:
            try:
                ok = page.export_rules(export_format=fmt)
                path = export_csv if fmt == 'csv' else export_txt
                if ok and os.path.exists(path):
                    size = os.path.getsize(path)
                    print(f"  [OK] {fmt.upper()}: {size}B"); rec.add_detail(f"[OK] {fmt.upper()}: {size}B")
                else:
                    print(f"  [WARN] {fmt.upper()}导出失败"); rec.add_detail(f"[WARN] {fmt.upper()}失败")
            except Exception as e:
                print(f"  [WARN] {fmt.upper()}异常: {e}"); rec.add_detail(f"[WARN] {fmt.upper()}: {e}")
    cur += 1

    # ===== 异常输入 =====
    with rec.step(f"步骤{cur}: 异常输入测试", "缺必填/重复/超长/特殊字符"):
        print(f"\n[步骤{cur}] 异常输入...")
        rec.add_detail("[异常输入测试]")
        # 缺必填(name用合法ascii, 其他必填项留空, 测"请输入xxx"必填拦截)
        miss_kw = {'name': f"{name_prefix}nodata"}
        for k in invalid_base_fields:
            miss_kw[k] = ''
        res = page.try_add_rule_invalid(miss_kw)
        miss_msg = res.get('error_message', '') or '(未拦截)'
        rec.add_detail(f"缺必填拦截: {miss_msg}")
        print(f"  缺必填: success={res.get('success')} 提示={miss_msg[:50]}")
        # 重复名称
        existing = test_rules[0]['name']
        try:
            page.click_add_button(); page.page.wait_for_timeout(1000)
            page._wait_add_form(timeout=8000)
            page._set_input('name', existing)
            fill_fields_by_id(invalid_base_fields)
            page.click_save(); page.page.wait_for_timeout(1500)
            err = page.page.locator('.ant-form-item-explain-error, .ant-message-error')
            if err.count() > 0:
                dup_msg = err.first.text_content().strip()
                rec.add_detail(f"重复名称拦截: {dup_msg}")
                print(f"  重复名称: 提示={dup_msg[:50]}")
            else:
                rec.add_detail("[WARN] 重复名称未拦截")
                print("  [WARN] 重复名称未拦截")
            page.click_cancel(); page.navigate_back_to_list(); page.page.wait_for_timeout(300)
        except Exception as e:
            rec.add_detail(f"重复名称异常: {e}")
            try:
                page.navigate_back_to_list()
            except Exception:
                pass
        # 超长name
        try:
            page.click_add_button(); page.page.wait_for_timeout(1000)
            page._wait_add_form(timeout=8000)
            page._set_input('name', 'a' * 40)
            fill_fields_by_id(invalid_base_fields)
            page.click_save(); page.page.wait_for_timeout(1200)
            err = page.page.locator('.ant-form-item-explain-error')
            if err.count() > 0:
                long_msg = err.first.text_content().strip()
                rec.add_detail(f"超长拦截: {long_msg}")
                print(f"  超长name: 提示={long_msg[:50]}")
            else:
                rec.add_detail("[INFO] 超长可能截断")
                print("  [INFO] 超长可能截断")
            page.click_cancel(); page.navigate_back_to_list(); page.page.wait_for_timeout(300)
        except Exception as e:
            rec.add_detail(f"超长异常: {e}")
            try:
                page.navigate_back_to_list()
            except Exception:
                pass
        # 特殊字符
        spec_kw = {'name': '<script>x</script>'}
        spec_kw.update(invalid_base_fields)
        res = page.try_add_rule_invalid(spec_kw)
        spec_msg = res.get('error_message', '') or '(未拦截)'
        rec.add_detail(f"特殊字符拦截: {spec_msg}")
        print(f"  特殊字符: success={res.get('success')} 提示={spec_msg[:50]}")
        page.page.reload(); page.page.wait_for_load_state("networkidle"); page.page.wait_for_timeout(500)
        page.navigate_to_module(); page.page.wait_for_timeout(500)
    cur += 1

    # ===== 批量停用/启用/删除 =====
    def _batch_op(op_name, batch_func, enabled_val):
        """批量操作(停用/启用) + SSH计数验证"""
        names = {r['name'] for r in test_rules}
        total = len(test_rules)
        cnt = 0
        for attempt in range(3):
            page.select_all_rules(); page.page.wait_for_timeout(800)
            batch_func(); page.page.wait_for_timeout(1500)
            page.page.reload(); page.page.wait_for_timeout(500)
            page.navigate_to_module(); page.page.wait_for_timeout(500)
            if query_rules:
                db = query_rules() or []
                cnt = sum(1 for r in db if r.get('name') in names and r.get('enabled') == enabled_val)
            else:
                check = page.is_rule_disabled if enabled_val == 'no' else page.is_rule_enabled
                cnt = sum(1 for r in test_rules if check(r['name']))
            if total == 0 or cnt >= total:
                break
            print(f"  第{attempt+1}次: {cnt}/{total}")
        return cnt, total

    with rec.step(f"步骤{cur}: 批量停用", f"{len(test_rules)}条"):
        print(f"\n[步骤{cur}] 批量停用 {len(test_rules)}条")
        cnt, total = _batch_op('停用', page.batch_disable, 'no')
        if cnt >= total:
            print(f"  [OK] 批量停用: {cnt}/{total}"); rec.add_detail(f"[OK] {cnt}/{total}")
        else:
            print(f"  [WARN] 批量停用: {cnt}/{total}"); rec.add_detail(f"[WARN] {cnt}/{total}")
            ui_failures.append(f"批量停用仅{cnt}/{total}")
        if query_rules and total > 0 and cnt < total:
            ssh_failures.append(f"SSH-批量停用: 仅{cnt}/{total}")
    cur += 1

    with rec.step(f"步骤{cur}: 批量启用", f"{len(test_rules)}条"):
        print(f"\n[步骤{cur}] 批量启用 {len(test_rules)}条")
        cnt, total = _batch_op('启用', page.batch_enable, 'yes')
        if cnt >= total:
            print(f"  [OK] 批量启用: {cnt}/{total}"); rec.add_detail(f"[OK] {cnt}/{total}")
        else:
            print(f"  [WARN] 批量启用: {cnt}/{total}"); rec.add_detail(f"[WARN] {cnt}/{total}")
            ui_failures.append(f"批量启用仅{cnt}/{total}")
        if query_rules and total > 0 and cnt < total:
            ssh_failures.append(f"SSH-批量启用: 仅{cnt}/{total}")
    cur += 1

    with rec.step(f"步骤{cur}: 批量删除", f"{len(test_rules)}条"):
        print(f"\n[步骤{cur}] 批量删除 {len(test_rules)}条")
        sel = page.page.locator("thead input[type='checkbox']").first
        if sel.count() > 0 and sel.is_enabled():
            sel.click(); page.page.wait_for_timeout(500)
        page.batch_delete(); page.page.wait_for_timeout(1500)
        page.page.reload(); page.page.wait_for_timeout(500)
        page.navigate_to_module(); page.page.wait_for_timeout(500)
        for r in test_rules:
            if page.rule_exists(r['name']):
                ui_failures.append(f"批量删除后{r['name']}仍存在")
        print(f"  [OK] 批量删除完成"); rec.add_detail("[OK] 批量删除")
        if query_rules:
            try:
                db = query_rules() or []
                names = {r['name'] for r in test_rules}
                remain = [r for r in db if r.get('name') in names]
                if remain:
                    ssh_failures.append(f"SSH-批量删除: 仍{len(remain)}条")
                else:
                    rec.add_detail("[OK] SSH: 全部删除")
            except Exception as e:
                ssh_failures.append(f"SSH-批量删除验证异常: {str(e)[:60]}")
    cur += 1

    # ===== 导入追加(CSV) =====
    with rec.step(f"步骤{cur}: 导入(追加CSV)", "导出CSV追加"):
        print(f"\n[步骤{cur}] 导入追加CSV...")
        rec.add_detail("[导入-追加CSV]")
        if os.path.exists(export_csv):
            before = page.get_rule_count()
            rec.add_detail(f"导入前: {before}")
            page.import_rules(export_csv, clear_existing=False)
            page.page.reload(); page.page.wait_for_timeout(500)
            page.navigate_to_module(); page.page.wait_for_timeout(500)
            after = page.get_rule_count()
            rec.add_detail(f"导入后: {after}")
            if after > before:
                print(f"  [OK] 追加 +{after-before}"); rec.add_detail(f"[OK] +{after-before}")
            else:
                rec.add_detail("[WARN] 未增加")
        else:
            print("  [WARN] CSV不存在"); rec.add_detail("CSV不存在")
    cur += 1

    # ===== 导入清空(TXT) =====
    with rec.step(f"步骤{cur}: 导入(清空TXT)", "TXT清空现有"):
        print(f"\n[步骤{cur}] 导入清空TXT...")
        rec.add_detail("[导入-清空TXT]")
        if os.path.exists(export_txt):
            before = page.get_rule_count()
            rec.add_detail(f"导入前: {before}")
            page.import_rules(export_txt, clear_existing=True)
            page.page.reload(); page.page.wait_for_timeout(1000)
            page.navigate_to_module(); page.page.wait_for_timeout(500)
            after = page.get_rule_count()
            rec.add_detail(f"导入后: {after}")
            if after > 0:
                print(f"  [OK] 清空导入后: {after}条"); rec.add_detail(f"[OK] {after}条")
            else:
                print("  [WARN] 清空导入后0条"); rec.add_detail("[WARN] 0条")
        else:
            print("  [WARN] TXT不存在"); rec.add_detail("TXT不存在")
    cur += 1

    # ===== 最终清理 =====
    with rec.step(f"步骤{cur}: 最终清理", "清空测试数据"):
        print(f"\n[步骤{cur}] 清理...")
        page.page.reload(); page.page.wait_for_load_state("networkidle"); page.page.wait_for_timeout(800)
        clean_all()
        page.navigate_to_module(); page.page.wait_for_timeout(500)
        final = page.get_rule_count()
        print(f"  [OK] 清理后: {final}条"); rec.add_detail(f"清理后: {final}")
    cur += 1

    # ===== 帮助功能 =====
    with rec.step(f"步骤{cur}: 帮助功能", "测试帮助图标"):
        print(f"\n[步骤{cur}] 帮助...")
        rec.add_detail("[帮助测试]")
        try:
            page.navigate_to_module(); page.page.wait_for_timeout(500)
            help_result = page.test_help_functionality()
            if help_result.get('icon_clickable'):
                if help_result.get('panel_visible'):
                    print("  [OK] 帮助面板显示"); rec.add_detail("[OK] 面板显示")
                else:
                    panel = page.page.locator(
                        ".ant-drawer:visible,.ant-modal:visible,[role='dialog']:visible,.ant-popover:visible")
                    if panel.count() > 0:
                        print("  [OK] 帮助面板(补充)"); rec.add_detail("[OK] 面板(补充)")
                    else:
                        rec.add_detail("[WARN] 面板未显示")
                    page.page.keyboard.press("Escape"); page.page.wait_for_timeout(300)
            else:
                hb = page.page.get_by_role("button", name="帮助")
                if hb.count() > 0:
                    hb.click(); page.page.wait_for_timeout(1000)
                    panel = page.page.locator(
                        ".ant-drawer:visible,.ant-modal:visible,[role='dialog']:visible,.ant-popover:visible")
                    if panel.count() > 0:
                        print("  [OK] 帮助按钮"); rec.add_detail("[OK] 帮助按钮")
                    page.page.keyboard.press("Escape"); page.page.wait_for_timeout(300)
                else:
                    rec.add_detail("[WARN] 帮助图标未找到")
        except Exception as e:
            print(f"  [WARN] 帮助异常: {e}"); rec.add_detail(f"帮助异常: {e}")

    print("\n" + "=" * 60)
    print(f"{page.SUBTAB}客户端综合测试完成 (共{cur}步)")
    print("=" * 60)
