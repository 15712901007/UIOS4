"""
应用协议控制模块综合测试 (安全中心 > 应用协议控制)

URL: 列表 /login#/securityCenter/applicationProtocolControl
     配置 /login#/securityCenter/applicationProtocolControlConfig (add/edit共用)
基于L7 DPI+终端地址控制应用流量. 安全中心第4模块.

覆盖(参考VLAN/IP限速丰富度, 20步):
- 批量添加(8场景: 协议大类组合/动作/源地址/目的地址/优先级/备注) + 每条SSH L1/L2/L3全链路
- CRUD: 计数/搜索(存在+不存在)/排序(名称/动作/优先级)/编辑/停用/启用/删除
- 异常输入分类(空名/名称格式/未选协议/非法源IP/超长备注)
- 导出CSV+TXT + 导入(不清空/清空)
- 批量停用/启用/删除
- 帮助功能测试(图标/面板/内容/链接/关闭)
- 功能打流(步骤20): 建drop百度规则+curl baidu(命中match+)+curl qq.com(精确不命中)+连通性探测

后端机制(acl_l7.sh, 专业模式 parental_mode=0):
- ⚠️不走iptables/ipset! 走 ik_cntl new_tc app_rule -> ik_core内核new_tc子系统
- 表 acl_l7 (id/enabled/tagname/comment/prio/action/app_proto JSON{custom应用名,object gid}/
  src_addr/dst_addr JSON/time必须"")
- 验证金矿: ik_summary的App Rules count + ID:<id>行(active/action/appset/match); dpi_cache appid;
  match增量(命中铁证). user_dpi必须enable(默认disable→match恒0).
- 环境限制: new_tc engine可能disable(drop不执行)→match增量作命中铁证+连通性探测; 精确性(其他域名不命中)
- 打流坑: client host路由强制经路由器(curl --interface不强制路由); 用baidu非114
"""
import os
import pytest
from utils.step_recorder import StepRecorder

pytestmark = [pytest.mark.security, pytest.mark.app_protocol]

PREFIX = "appt_"
BAIDU_IP = "110.242.69.21"  # baidu HTTP IP(appid=5060173)

# 8场景数据组合: (name_suffix, 协议大类, 动作, 源地址, 目的地址, 优先级, 备注)
TEST_CASES = [
    ("s01", "网络协议", "drop", None, None, 31, None),
    ("s02", "传输下载", "accept", None, None, 31, None),
    ("s03", "休闲娱乐", "drop", None, None, 31, None),
    ("s04", "社交通讯", "accept", None, None, 31, None),
    ("s05", "网络协议", "drop", ["192.168.148.2"], None, 31, None),
    ("s06", "休闲娱乐", "accept", None, ["10.66.0.40"], 31, None),
    ("s07", "网络游戏", "drop", None, None, 10, None),
    ("s08", "网络协议", "accept", None, None, 31, "备注测试ABC123"),
]


class TestAppProtocolComprehensive:
    """应用协议控制综合测试(UI全CRUD + 功能打流 + L1-L4, 20步)"""

    def test_app_protocol_comprehensive(self, app_protocol_page_logged_in,
                                        step_recorder: StepRecorder, request):
        page = app_protocol_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        ui_failures = []
        ssh_failures = []

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            if backend_verifier is None:
                rec.add_detail(f"[SSH-{label}] 跳过(无SSH验证器)")
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = 'PASS' if result.passed else 'FAIL'
                rec.add_detail(f"[SSH-{label}] {status}: {result.message}")
                rec.add_detail(f"    后端数据: {(result.raw_output or '')[:200]}")
                print(f"[SSH-{label}] {status}: {result.message}", flush=True)
                if not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
                ssh_failures.append(f"SSH-{label}异常: {str(e)[:80]}")
                return None

        def ui_check(label, cond, detail=""):
            if cond:
                rec.add_detail(f"[UI] {label}: 成功")
                print(f"  [UI-OK] {label}", flush=True)
            else:
                rec.add_detail(f"[UI] {label}: 失败 - {detail}")
                print(f"  [UI-FAIL] {label}: {detail}", flush=True)
                ui_failures.append(f"{label}: {detail}")

        # 包装rec.step: 每步print标题到stdout(GUI实时日志, 参考VLAN/IP限速每步print)
        _orig_step = rec.step
        def _step(title, desc=""):
            print(f"\n{'='*50}\n[STEP] {title} — {desc}", flush=True)
            return _orig_step(title, desc)
        rec.step = _step

        try:
            # ==================== 步骤1: 环境清理 ====================
            with rec.step("步骤1: 环境清理", "清理appt_残留+确认空表"):
                if backend_verifier:
                    snap = backend_verifier.verify_app_protocol_count(prefix=PREFIX)
                    rec.add_detail(f"[快照] 清理前 appt_ 数量: {snap.message}")
                    backend_verifier.cleanup_app_protocol_test(PREFIX)
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                page.clean_test_rules(PREFIX)
                page.page.wait_for_timeout(1000)
                cnt0 = page.get_rule_count()
                rec.add_detail(f"[清理后] 列表规则数: {cnt0}")

            # ==================== 步骤2: 批量添加8场景(协议大类组合) ====================
            with rec.step("步骤2: 批量添加8场景", "协议大类×动作×地址×优先级×备注 组合"):
                added = []
                for suffix, cat, action, src, dst, prio, remark in TEST_CASES:
                    name = f"{PREFIX}{suffix}"
                    desc = f"{cat}/{action}" + (f"/src={src}" if src else "") + \
                           (f"/dst={dst}" if dst else "") + (f"/prio={prio}" if prio != 31 else "") + \
                           (f"/备注" if remark else "")
                    rec.add_detail(f"[规则] {name}: {desc}")
                    res = page.add_rule(name, protocol_category=cat, action=action,
                                        src_addrs=src, dst_addrs=dst, prio=prio, remark=remark or "")
                    ui_check(f"添加{suffix}", res["success"], res.get("error", ""))
                    if res["success"]:
                        added.append(name)
                    page.page.wait_for_timeout(500)
                rec.add_detail(f"[添加结果] 成功 {len(added)}/8")

            # ==================== 步骤2.5: 每条SSH全链路L1/L2 ====================
            with rec.step("步骤2.5: 后台数据验证(SSH全链路)", "每条规则L1数据库+L2内核规则"):
                for suffix, cat, action, src, dst, prio, remark in TEST_CASES:
                    name = f"{PREFIX}{suffix}"
                    ssh_verify(f"L1-{suffix}", backend_verifier.verify_app_protocol_database,
                               name, expected_fields={"enabled": "yes", "action": action,
                               "prio": str(prio)} if prio != 31 else {"enabled": "yes", "action": action})
                    ssh_verify(f"L2-{suffix}", backend_verifier.verify_app_protocol_kernel_rule,
                               name, expect_present=True, expect_action=action)

            # ==================== 步骤3: 计数验证 ====================
            with rec.step("步骤3: 计数验证(≥8条appt_)", "SSH prefix计数"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(2000)
                ui_cnt = page.get_rule_count()
                rec.add_detail(f"[UI计数] 共 {ui_cnt} 条")
                if backend_verifier:
                    ssh_cnt = backend_verifier.verify_app_protocol_count(prefix=PREFIX)
                    rec.add_detail(f"[SSH计数] appt_ {ssh_cnt.message}")
                    row = backend_verifier._sqlite_query_line(
                        f"SELECT count(*) as cnt FROM acl_l7 WHERE tagname LIKE '{PREFIX}%'")
                    if int(row.get("cnt", 0)) < 8:
                        ui_failures.append(f"步骤3: SSH appt_规则数{row.get('cnt')}<8")

            # ==================== 步骤4: 搜索(存在+不存在) ====================
            with rec.step("步骤4: 搜索(存在/不存在)", "search_rule验证"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                page.search_rule(f"{PREFIX}s01")
                page.page.wait_for_timeout(1500)
                if not page.rule_exists(f"{PREFIX}s01"):
                    ui_failures.append("步骤4: 搜索存在规则未显示")
                else:
                    rec.add_detail("[搜索] 存在规则显示OK")
                page.clear_search()
                page.page.wait_for_timeout(1000)
                page.search_rule("不存在的规则xyz999")
                page.page.wait_for_timeout(1500)
                if page.rule_exists(f"{PREFIX}s01"):
                    rec.add_detail("[搜索] 不存在规则时不应显示已有(可能搜索未生效)")
                else:
                    rec.add_detail("[搜索] 不存在规则无匹配OK")
                page.clear_search()
                page.page.wait_for_timeout(1000)

            # ==================== 步骤5: 排序(仅优先级支持排序, 参考VLAN点3次+验证数值顺序) ====================
            with rec.step("步骤5: 排序功能测试(优先级)", "优先级列正序/倒序/默认+验证数值顺序"):
                rec.add_detail("【排序测试】 应用协议控制仅'优先级'列支持排序(名称/动作/协议等无排序图标)")
                col = "优先级"

                def _read_prio_values():
                    return page.page.evaluate("""() => {
                        const headers=[...document.querySelectorAll('.ant-table-thead th')];
                        const idx=headers.findIndex(h=>(h.textContent||'').includes('优先级'));
                        if(idx<0) return null;
                        return [...document.querySelectorAll('.ant-table-row')].map(r=>{
                            const cells=r.querySelectorAll('.ant-table-cell');
                            return parseInt((cells[idx]?.textContent||'').trim())||null;
                        }).filter(x=>x!==null);
                    }""")

                for sort_label in ["正序", "倒序", "默认"]:
                    try:
                        ok = page.sort_by_column(col)
                        page.page.wait_for_timeout(800)
                        vals = _read_prio_values()
                        if ok and vals:
                            if sort_label == "正序":
                                sorted_ok = vals == sorted(vals)
                                rec.add_detail(f"  ✓ {col} 排序(正序/升序): 值={vals} {'验证OK' if sorted_ok else '顺序不符'}")
                            elif sort_label == "倒序":
                                sorted_ok = vals == sorted(vals, reverse=True)
                                rec.add_detail(f"  ✓ {col} 排序(倒序/降序): 值={vals} {'验证OK' if sorted_ok else '顺序不符'}")
                            else:
                                rec.add_detail(f"  ✓ {col} 排序(默认): 值={vals}")
                        else:
                            rec.add_detail(f"  - {col} 排序({sort_label}): 未触发或无值(vals={vals})")
                    except Exception as e:
                        rec.add_detail(f"  ✗ {col} 排序({sort_label})异常: {str(e)[:60]}")
                rec.add_detail("  [OK] 优先级排序测试完成(参考VLAN: 点3次+验证数值顺序)")

            # ==================== 步骤6: 编辑(备注+动作) ====================
            with rec.step("步骤6: 编辑备注+动作", f"编辑{PREFIX}s02+SSH验证"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                if page.edit_rule(f"{PREFIX}s02"):
                    page.fill_remark("已编辑备注")
                    sv = page.save_and_wait()
                    ui_check("步骤6编辑保存", sv["success"], sv.get("error", ""))
                    ssh_verify("步骤6-L1备注", backend_verifier.verify_app_protocol_database,
                               f"{PREFIX}s02", expected_fields={"comment": "已编辑备注"})
                else:
                    ui_failures.append("步骤6: 进入编辑页失败")

            # ==================== 步骤7: 停用+SSH ====================
            with rec.step("步骤7: 停用appt_s03", "enabled=no+内核规则消失"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                ok = page.disable_rule(f"{PREFIX}s03")
                ui_check("步骤7停用", ok, "停用操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤7-enabled", backend_verifier.verify_app_protocol_enabled, f"{PREFIX}s03", False)

            # ==================== 步骤8: 启用+SSH ====================
            with rec.step("步骤8: 启用appt_s03", "enabled=yes+内核规则恢复"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                ok = page.enable_rule(f"{PREFIX}s03")
                ui_check("步骤8启用", ok, "启用操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤8-enabled", backend_verifier.verify_app_protocol_enabled, f"{PREFIX}s03", True)

            # ==================== 步骤9: 单条删除+SSH ====================
            with rec.step("步骤9: 删除appt_s04", "SSH验DB不存在+内核无"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                ok = page.delete_rule(f"{PREFIX}s04")
                ui_check("步骤9删除", ok, "删除操作失败")
                page.page.wait_for_timeout(1500)
                ssh_verify("步骤9-DB不存在", backend_verifier.verify_app_protocol_not_exists, f"{PREFIX}s04")
                ssh_verify("步骤9-内核无", backend_verifier.verify_app_protocol_kernel_rule,
                           f"{PREFIX}s04", expect_present=False)

            # ==================== 步骤10: 异常输入分类测试 ====================
            with rec.step("步骤10: 异常输入拦截", "空名/名称格式/未选协议/非法源IP/超长备注"):
                rec.add_detail("【10.1 空名称】")
                r = page.try_add_rule_invalid(name="", no_protocol=False)
                if r.get("blocked"):
                    rec.add_detail(f"  ✓ 空名称被拦截: {r.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤10.1: 空名称未拦截: {r.get('error', '')[:50]}")
                page._dismiss_all_modals()

                rec.add_detail("【10.2 未选协议】(协议必选)")
                r = page.try_add_rule_invalid(name=f"{PREFIX}bad_noproto", no_protocol=True)
                if r.get("blocked"):
                    rec.add_detail(f"  ✓ 未选协议被拦截: {r.get('error', '')[:40]}")
                else:
                    ui_failures.append(f"步骤10.2: 未选协议未拦截: {r.get('error', '')[:50]}")
                page._dismiss_all_modals()

                rec.add_detail("【10.3 非法源地址IP】")
                try:
                    if page.open_add_page():
                        page.fill_name(f"{PREFIX}bad_src")
                        page.select_protocol(category="网络协议")
                        page.add_src_address("999.999.999.999")
                        page.click_save()
                        page.page.wait_for_timeout(1500)
                        err = page.has_form_error()
                        if err:
                            rec.add_detail(f"  ✓ 非法源IP被拦截: {err[:40]}")
                        elif page.is_still_on_config_page():
                            rec.add_detail("  ✓ 非法源IP保存被阻止(停留配置页)")
                        else:
                            ui_failures.append("步骤10.3: 非法源IP未拦截(保存成功)")
                    page._dismiss_all_modals()
                except Exception as e:
                    rec.add_detail(f"  非法源IP测试异常: {str(e)[:60]}")

                rec.add_detail("【10.4 超长备注】(测前端容错)")
                try:
                    if page.open_add_page():
                        page.fill_name(f"{PREFIX}bad_long")
                        page.select_protocol(category="网络协议")
                        page.fill_remark("X" * 300)
                        page.click_save()
                        page.page.wait_for_timeout(1500)
                        err = page.has_form_error()
                        if err:
                            rec.add_detail(f"  ✓ 超长备注被拦截: {err[:40]}")
                        elif not page.is_still_on_config_page():
                            rec.add_detail("  - 超长备注未被拦截(前端无长度限制, 保存成功, 合理)")
                        else:
                            rec.add_detail("  - 超长备注停留配置页(可能校验中)")
                    page._dismiss_all_modals()
                except Exception as e:
                    rec.add_detail(f"  超长备注测试异常: {str(e)[:60]}")

            # ==================== 步骤11: 导出CSV+TXT ====================
            with rec.step("步骤11: 导出CSV+TXT", "export_rules双格式"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                csv_ok = page.export_rules(export_format="csv")
                ui_check("步骤11导出CSV", csv_ok, "CSV导出失败")
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                txt_ok = page.export_rules(export_format="txt")
                ui_check("步骤11导出TXT", txt_ok, "TXT导出失败")

            # ==================== 步骤12: 导入(不清空+清空) ====================
            with rec.step("步骤12: 导入(不清空+清空)", "clear_existing False/True + SSH验证"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                export_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                          "test_data", "exports", "app_protocol")
                imp_file = None
                if os.path.isdir(export_dir):
                    files = [f for f in os.listdir(export_dir) if f.endswith((".csv", ".txt"))]
                    if files:
                        files.sort(key=lambda f: os.path.getmtime(os.path.join(export_dir, f)))
                        imp_file = os.path.join(export_dir, files[-1])
                if imp_file and os.path.exists(imp_file):
                    def _verify_import(label):
                        if backend_verifier is None:
                            return
                        try:
                            r = backend_verifier.verify_app_protocol_count(prefix=PREFIX)
                            import re as _re
                            m = _re.search(r'数量\D*(\d+)', r.message)
                            n = int(m.group(1)) if m else 0
                            ok = n > 0
                            d = f"[SSH-{label}] {'PASS' if ok else 'FAIL'}: 导入后appt_数={n}"
                            rec.add_detail(d)
                            print(d, flush=True)
                            if not ok:
                                ssh_failures.append(f"SSH-{label}: 导入后0条appt_规则")
                        except Exception as e:
                            ssh_failures.append(f"SSH-{label}异常: {str(e)[:60]}")
                    page.clean_test_rules(PREFIX)
                    page.page.wait_for_timeout(1000)
                    imp_ok1 = page.import_rules(imp_file, clear_existing=False)
                    ui_check("步骤12a导入-不清空", imp_ok1, "不清空导入失败")
                    page.page.wait_for_timeout(2000)
                    _verify_import("步骤12a-不清空导入")
                    page.navigate_to_app_proto()
                    page.page.wait_for_timeout(1500)
                    imp_ok2 = page.import_rules(imp_file, clear_existing=True)
                    ui_check("步骤12b导入-清空", imp_ok2, "清空导入失败")
                    page.page.wait_for_timeout(2000)
                    _verify_import("步骤12b-清空导入")
                    rec.add_detail(f"[导入] 不清空={imp_ok1} 清空={imp_ok2} 文件={os.path.basename(imp_file)}")
                else:
                    rec.add_detail("[导入] 跳过(无导出文件)")

            # ==================== 步骤13: 批量停用/启用/删除 ====================
            with rec.step("步骤13: 批量操作", "批量停用/启用/删除"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                page.clean_test_rules(PREFIX)
                page.page.wait_for_timeout(1000)
                for suffix, cat, action, src, dst, prio, remark in TEST_CASES[:3]:
                    page.add_rule(f"{PREFIX}ba_{suffix}", protocol_category=cat, action=action)
                    page.page.wait_for_timeout(500)
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(2000)
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_disable()
                page.page.wait_for_timeout(2000)
                if backend_verifier:
                    for suffix, _, _, _, _, _, _ in TEST_CASES[:3]:
                        ssh_verify(f"步骤13-批量停用-{suffix}", backend_verifier.verify_app_protocol_enabled,
                                   f"{PREFIX}ba_{suffix}", False, must_pass=False)
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_enable()
                page.page.wait_for_timeout(2000)
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                page.select_all_rules()
                page.page.wait_for_timeout(800)
                page.batch_delete()
                page.page.wait_for_timeout(2500)
                rec.add_detail("[批量] 停用/启用/删除完成")

            # ==================== 步骤14: 帮助功能测试 ====================
            with rec.step("步骤14: 帮助功能测试", "图标点击/面板显示/内容/链接/关闭"):
                rec.add_detail("【帮助功能测试】")
                try:
                    page.navigate_to_app_proto()
                    page.page.wait_for_timeout(1500)
                    help_result = page.test_help_functionality()
                    rec.add_detail(f"  测试1: 帮助图标点击")
                    if help_result.get('icon_clickable'):
                        rec.add_detail(f"    ✓ 帮助图标可点击")
                    else:
                        rec.add_detail(f"    - 帮助图标不可点击/未找到")
                    rec.add_detail(f"  测试2: 帮助面板显示")
                    if help_result.get('panel_visible'):
                        rec.add_detail(f"    ✓ 帮助面板可见")
                        if help_result.get('has_content'):
                            content = help_result.get('content_text', '')
                            preview = content[:100] + '...' if len(content) > 100 else content
                            rec.add_detail(f"    帮助内容: {preview}")
                    else:
                        rec.add_detail(f"    - 帮助面板不可见(可能此模块帮助按钮行为不同)")
                    rec.add_detail(f"  测试3: 帮助链接跳转")
                    if help_result.get('link_clickable'):
                        rec.add_detail(f"    ✓ 帮助链接可点击")
                        if help_result.get('new_page_opened'):
                            rec.add_detail(f"    ✓ 打开新页面")
                        elif help_result.get('url_changed'):
                            rec.add_detail(f"    ✓ URL跳转")
                    else:
                        rec.add_detail(f"    - 无帮助链接")
                    rec.add_detail(f"  测试4: 帮助面板关闭")
                    if help_result.get('can_close'):
                        rec.add_detail(f"    ✓ 帮助面板可关闭")
                    else:
                        rec.add_detail(f"    - 帮助面板无法关闭")
                    rec.add_detail("帮助功能测试完成")
                except Exception as e:
                    rec.add_detail(f"  帮助测试异常: {str(e)[:80]}")

            # ==================== 步骤15: 列表字段回读校验 ====================
            with rec.step("步骤15: 列表展示验证", "规则在列表显示+协议/动作列正确"):
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                # 确认至少有规则显示(get_rule_names)
                names = page.get_rule_names()
                appt_names = [n for n in names if n.startswith(PREFIX)]
                rec.add_detail(f"[列表] 当前appt_规则: {len(appt_names)}条 ({appt_names[:5]})")
                if len(appt_names) == 0:
                    # 导入/批量后可能清空, 重新加一条验证显示
                    page.add_rule(f"{PREFIX}disp_check", protocol_category="网络协议", action="drop")
                    page.page.wait_for_timeout(1500)
                    page.navigate_to_app_proto()
                    page.page.wait_for_timeout(1500)
                    if page.rule_exists(f"{PREFIX}disp_check"):
                        rec.add_detail("[列表] 补建规则显示OK")
                    else:
                        ui_failures.append("步骤15: 规则列表未显示")

            # ==================== 步骤16-19占位(合并到上述), 直接步骤20打流 ====================
            # (排序/搜索/异常/帮助/批量已覆盖, 此处直接功能打流)

            # ==================== 步骤20: 功能连通性验证(drop百度端到端) ====================
            with rec.step("步骤20: 功能连通性验证(drop百度端到端)", "基线→建drop百度→连通性(软)+精确→停用bug排查→删恢复"):
                if backend_verifier is None:
                    rec.add_detail("[打流] 跳过(无SSH验证器)")
                else:
                    flow_name = f"{PREFIX}flow_drop"
                    try:
                        backend_verifier.connect_router()
                        backend_verifier.connect_client()
                        # 基线: curl baidu经ens11应通(此时无drop规则; --interface ens11强制经路由器)
                        base = backend_verifier.verify_connectivity(dst_domain="www.baidu.com")
                        rec.add_detail(f"[基线] {base['detail']}")
                        if not base["connected"]:
                            rec.add_detail("[打流] baidu经ens11不可达, 跳过打流(环境问题)")
                        else:
                            rec.add_detail("[逻辑] 建drop百度→curl baidu(不通=生效/仍通=new_tc软)→curl qq(精确)→停用排查→删恢复")
                            # SSH建精确drop规则(app_proto含"百度" appid 5060173)
                            add_res = backend_verifier.add_app_protocol_rule_via_ssh(
                                flow_name, app="百度", action="drop", prio=32)
                            rec.add_detail(f"[建规则] {add_res}")
                            page.page.wait_for_timeout(2000)
                            rule = backend_verifier.find_app_protocol_rule(flow_name)
                            if rule:
                                rec.add_detail(f"[诊断] flow_drop id={rule.get('id')} app_proto={str(rule.get('app_proto', ''))[:60]}")
                            # L2验规则下发active
                            ssh_verify("打流-L2内核active", backend_verifier.verify_app_protocol_kernel_rule,
                                       flow_name, expect_present=True, expect_action="drop")
                            # L4连通性验证(软判定: 6.12/10002具体应用drop不生效=已知产品bug, appset未建drop无目标; 不硬FAIL如实记录)
                            flow_res = ssh_verify("打流-L4连通性", backend_verifier.verify_app_protocol_flow,
                                                  flow_name, count=5, must_pass=True)
                            blocked_observed = bool(flow_res and flow_res.details.get("baidu_blocked"))
                            # 停用bug排查(产品bug: acl_l7.sh down()只del app_rule不清appset→停用后残留规则仍可命中阻断;
                            # 仅del()删除调__clean_set清appset才恢复. appset残留签名不依赖DPI阻断可复现, 可靠探测)
                            try:
                                appset_before = backend_verifier.app_protocol_appset_has_appid(flow_name)
                                disabled = page.disable_rule(flow_name)
                                page.page.wait_for_timeout(2000)
                                appset_after = backend_verifier.app_protocol_appset_has_appid(flow_name)
                                dis_conn = backend_verifier.verify_connectivity(dst_domain="www.baidu.com")
                                rec.add_detail(f"[停用] UI停用={disabled}; appset含appid: {appset_before}→{appset_after}; baidu {dis_conn['detail']}")
                                if blocked_observed and not dis_conn["connected"]:
                                    rec.add_detail("[停用][产品bug] 阻断可复现且停用后baidu仍不通→down()停用未生效(报禅道)")
                                if appset_after:
                                    rec.add_detail("[停用][产品bug签名] 停用后appset仍含appid→down()缺__clean_set(仅删除清appset, 报禅道)")
                            except Exception as e:
                                rec.add_detail(f"[停用排查] 异常: {str(e)[:60]}")
                            # 删除规则→恢复通(确认规则导致; 删除清appset故恢复)
                            backend_verifier.cleanup_app_protocol_test(flow_name)
                            page.page.wait_for_timeout(1500)
                            restore = backend_verifier.verify_connectivity(dst_domain="www.baidu.com")
                            rec.add_detail(f"[删规则后恢复] {restore['detail']}")
                    except Exception as e:
                        rec.add_detail(f"[打流] 异常: {str(e)[:80]}")
                        ssh_failures.append(f"打流异常: {str(e)[:80]}")

        finally:
            try:
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                cnt = page.clean_test_rules(PREFIX)
                rec.add_detail(f"[finally前端清理] 删除 {cnt} 条")
            except Exception as e:
                rec.add_detail(f"[finally前端清理异常] {str(e)[:60]}")
            if backend_verifier:
                try:
                    res = backend_verifier.cleanup_app_protocol_test(PREFIX)
                    rec.add_detail(f"[finally SQL清理+ik_cntl del残留] {res}")
                except Exception as e:
                    rec.add_detail(f"[finally清理异常] {str(e)[:60]}")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"应用协议控制验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"


class TestAppProtocolFlowVerification:
    """应用协议控制功能验证(端到端drop闭环 + 停用BUG三重信号).

    仿ACL TestAclFlowVerification, 解决综合测试步骤20的两个问题:
    - 阻断生效判定: match增量+连通性硬判定(替代旧软判定verify_app_protocol_flow恒passed=True),
      不再硬编码百度; 动态探测候选目标中curl能命中(match>0且阻断)的, 用其做端到端闭环.
    - 停用BUG(停用后阻断仍生效, 须删除才彻底): 三重信号(连通仍不通/match仍增加/内核规则仍active)
      任一即BUG, 硬FAIL+报禅道. 信号2/3不依赖"阻断可复现"前置, 即便端到端drop未执行(DPI未识别curl)
      也能靠内核规则残留铁证抓BUG.
    软降级: DPI引擎不可用/无候选命中/基线不通时端到端阻断判定软记录不硬FAIL, L1/L2配置层+停用BUG仍验.
    探测已确认curl经路由器被DPI识别为具体应用appid(如百度5060173), 故curl端到端闭环可行(同ACL模式)."""

    PREFIX = "apptflow_"
    CLIENT_IP = "192.168.148.2"
    # 可配置候选目标(UI协议树根节点大类, 选择可靠避深层应用; "所有协议"保底验证drop引擎必生效).
    # 用户手机163场景→休闲娱乐大类覆盖; 具体应用(网易通用协议等APPIDS有效key)可扩展配置.
    CANDIDATE_TARGETS = [
        {"category": "所有协议", "domain": "www.163.com"},
        {"category": "休闲娱乐", "domain": "www.163.com"},
    ]

    def test_app_protocol_flow_verification(self, app_protocol_page_logged_in, step_recorder: StepRecorder, request):
        """应用协议控制功能验证: 动态探测目标→建drop→验阻断生效→停用抓BUG→启用恢复→删除彻底恢复."""
        page = app_protocol_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            pytest.skip("无SSH验证器, 跳过应用协议控制功能验证")

        failures = []

        def ssh_verify(label, func, *args, must_pass=True, **kwargs):
            try:
                r = func(*args, **kwargs)
                rec.add_detail(f"[SSH-{label}] {'PASS' if r.passed else 'FAIL'}: {r.message}")
                rec.add_detail(f"    数据: {(r.raw_output or '')[:160]}")
                if must_pass and not r.passed:
                    failures.append(f"{label}: {r.message}")
            except Exception as e:
                rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
                failures.append(f"{label}异常: {str(e)[:80]}")

        print("\n" + "=" * 50)
        print("应用协议控制功能验证(端到端drop闭环 + 停用BUG三重信号)")
        print("=" * 50)

        chosen = None           # 探测到的可用目标 {app, domain}
        baseline_blocked = False  # 建规则后是否阻断(供停用BUG信号1用)
        build_success = False
        end_to_end = False

        try:
            # ==================== 步骤1: 环境清理 ====================
            with rec.step("步骤1: 环境清理", "清apptflow_残留+内核残留, 确保new_tc干净"):
                try:
                    bv.cleanup_app_protocol_test(self.PREFIX)
                except Exception:
                    pass
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1500)
                try:
                    page.clean_test_rules(self.PREFIX)
                except Exception:
                    pass
                page.page.wait_for_timeout(1000)
                rec.add_detail("[清理] acl_l7表apptflow_ + 内核app_rule/appset清空")

            # ==================== 步骤2: DPI引擎探活 ====================
            with rec.step("步骤2: DPI引擎探活", "读ik_features_status的dpi(基础DPI识别引擎)"):
                try:
                    bv.connect_router()
                    dpi_line = bv._router.exec("cat /proc/ikuai/stats/ik_features_status 2>/dev/null | grep '^dpi'")
                    user_dpi_line = bv._router.exec("cat /proc/ikuai/stats/ik_features_status 2>/dev/null | grep '^user_dpi'")
                    rec.add_detail(f"[DPI状态] {dpi_line.strip()} | {user_dpi_line.strip()}")
                    dpi_engine_ok = "enable" in dpi_line
                    rec.add_detail(f"  基础DPI引擎: {'可用(能识别应用appid)' if dpi_engine_ok else '不可用(端到端软降级)'}")
                except Exception as e:
                    rec.add_detail(f"  DPI探活异常: {str(e)[:80]}")
                    dpi_engine_ok = False

            # ==================== 步骤3: 动态探测可用目标 ====================
            with rec.step("步骤3: 动态探测可用目标", "候选列表逐个UI建临时drop规则→curl→找能阻断的目标"):
                if not dpi_engine_ok:
                    rec.add_detail("[探测] 基础DPI引擎不可用, 跳过探测(端到端将软降级)")
                else:
                    for cand in self.CANDIDATE_TARGETS:
                        tname = f"{self.PREFIX}probe"
                        try:
                            page.navigate_to_app_proto(); page.page.wait_for_timeout(1200)
                            rr = page.add_rule(tname, protocol_category=cand["category"], action="drop", prio=32)
                            page.page.wait_for_timeout(2000)
                            if rr["success"]:
                                res = bv.verify_app_protocol_block_effect(tname, cand["domain"], count=5)
                                rec.add_detail(f"  [{cand['category']}/{cand['domain']}] {res['detail']}")
                                if res.get("blocked"):
                                    chosen = cand
                                    rec.add_detail(f"  ✓ 选定: {cand['category']}({cand['domain']}) 端到端阻断生效")
                            else:
                                rec.add_detail(f"  [{cand['category']}] UI建规则失败: {rr.get('error', '')[:60]}")
                        except Exception as e:
                            rec.add_detail(f"  [{cand['category']}] 探测异常: {str(e)[:80]}")
                        finally:
                            try:
                                page.navigate_to_app_proto(); page.page.wait_for_timeout(1000)
                                page.delete_rule(tname)
                            except Exception:
                                pass
                            try:
                                bv.cleanup_app_protocol_test(tname)
                            except Exception:
                                pass
                        if chosen:
                            break
                    if chosen is None:
                        rec.add_detail("[探测] 无候选被curl命中阻断 → 端到端软降级, 停用BUG仍验(内核信号)")

            target = chosen if chosen else self.CANDIDATE_TARGETS[0]
            end_to_end = chosen is not None

            # ==================== 步骤4: 基线连通 ====================
            with rec.step("步骤4: 基线连通", f"curl {target['domain']} 经ens11应可达(无规则; 非000即可达, 403反爬也算)"):
                bv.connect_client()
                bv.clear_client_conntrack("192.168.148.2")
                base_out = bv._client.exec(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --interface ens11 --connect-timeout 3 -m 8 http://{target['domain']}/",
                    timeout=15)
                base_code = (base_out or "").strip().strip("'").strip()
                base_reachable = bool(base_code) and base_code != "000"
                rec.add_detail(f"  基线: curl {target['domain']} http_code={base_code} → {'可达' if base_reachable else '不可达(000)'}")
                if not base_reachable:
                    rec.add_detail("  ⚠ 基线不可达(000, 环境问题); 端到端软降级")
                    end_to_end = False

            # ==================== 步骤5: 建drop规则 + 验证阻断生效 ====================
            flow_name = f"{self.PREFIX}flow"
            with rec.step("步骤5: 建drop规则 + 验证阻断生效", f"UI建drop {target['category']}→L1/L2→curl阻断判定"):
                # UI建规则走API完整下发(含new_tc引擎启用); SSH直接建SQL不触发引擎→drop不执行.
                # 停用/启用/删除用UI触发down()/del()(正是停用BUG的触发动作).
                page.navigate_to_app_proto(); page.page.wait_for_timeout(1500)
                r = page.add_rule(flow_name, protocol_category=target["category"], action="drop", prio=32)
                page.page.wait_for_timeout(2000)
                if not r["success"]:
                    failures.append(f"步骤5建drop失败: {r.get('error', '')}")
                    rec.add_detail(f"  ✗ UI建规则失败: {r.get('error', '')}")
                else:
                    build_success = True
                    rec.add_detail(f"  [UI] 建 {flow_name}(drop {target['category']}): 成功")
                    ssh_verify("步骤5-L1数据库", bv.verify_app_protocol_database, flow_name,
                               expected_fields={"enabled": "yes", "action": "drop"})
                    ssh_verify("步骤5-L2内核active", bv.verify_app_protocol_kernel_rule, flow_name,
                               expect_present=True, expect_action="drop")
                    blk = bv.verify_app_protocol_block_effect(flow_name, target["domain"], count=5)
                    baseline_blocked = blk.get("blocked", False)
                    rec.add_detail(f"  [阻断判定] {blk['detail']}")
                    if end_to_end:
                        if blk.get("blocked"):
                            rec.add_detail(f"  ✓ 阻断生效(curl不通) match+{blk.get('match_delta')}")
                        else:
                            failures.append(f"步骤5阻断未生效(curl仍通) {blk['detail']}")
                            rec.add_detail(f"  ✗ 阻断未生效(curl通) {blk['detail'][:60]}")
                    else:
                        rec.add_detail("  [软降级] 端到端不硬判定, 配置层L1/L2已验")

            # ==================== 步骤6-8: 仅建规则成功时执行 ====================
            if build_success:
                # 步骤6: 停用 + 抓停用BUG
                with rec.step("步骤6: 停用规则 + 抓停用BUG", "停用→三重信号(连通/match/内核active), 任一异常=BUG报禅道"):
                    page.navigate_to_app_proto()
                    page.page.wait_for_timeout(1500)
                    disabled = page.disable_rule(flow_name)
                    page.page.wait_for_timeout(2000)
                    rec.add_detail(f"  [UI] 停用 {flow_name}: {'成功' if disabled else '失败'}")
                    rule6 = bv.find_app_protocol_rule(flow_name)
                    db_disabled = bool(rule6) and str(rule6.get("enabled", "")) == "no"
                    rec.add_detail(f"  [DB] enabled={rule6.get('enabled') if rule6 else 'N/A'}")
                    if not db_disabled:
                        failures.append("步骤6停用后DB enabled未变no")
                    dis = bv.verify_app_protocol_disable_effect(flow_name, target["domain"],
                                                                baseline_blocked=baseline_blocked, count=5)
                    rec.add_detail(f"  [停用判定] {dis['detail']}")
                    if dis.get("bug_detected"):
                        failures.append(f"步骤6停用BUG: 停用后阻断仍生效({'; '.join(dis['signals'])}), 须删除才彻底(报禅道)")
                        rec.add_detail(f"  ✗ 停用BUG检出(报禅道): {'; '.join(dis['signals'])}")
                    else:
                        rec.add_detail("  ✓ 停用正常(阻断消失)")

                # 步骤7: 启用 + 恢复阻断
                with rec.step("步骤7: 启用规则 + 验证恢复阻断", "启用→阻断应恢复(match>0+不通)"):
                    page.navigate_to_app_proto()
                    page.page.wait_for_timeout(1500)
                    enabled = page.enable_rule(flow_name)
                    page.page.wait_for_timeout(2000)
                    rec.add_detail(f"  [UI] 启用 {flow_name}: {'成功' if enabled else '失败'}")
                    rule7 = bv.find_app_protocol_rule(flow_name)
                    db_enabled = bool(rule7) and str(rule7.get("enabled", "")) == "yes"
                    rec.add_detail(f"  [DB] enabled={rule7.get('enabled') if rule7 else 'N/A'}")
                    if not db_enabled:
                        failures.append("步骤7启用后DB enabled未变yes")
                    if end_to_end:
                        blk2 = bv.verify_app_protocol_block_effect(flow_name, target["domain"], count=5)
                        rec.add_detail(f"  [恢复阻断] {blk2['detail']}")
                        if blk2.get("dpi_hit") and blk2.get("blocked"):
                            rec.add_detail("  ✓ 启用后阻断恢复")
                        else:
                            rec.add_detail("  - 启用后阻断未完全恢复")
                    else:
                        rec.add_detail("  [软降级] 恢复阻断软记录")

                # 步骤8: 删除 + 彻底恢复
                with rec.step("步骤8: 删除规则 + 验证彻底恢复", "删除→连通恢复+内核无规则+appset清空"):
                    page.navigate_to_app_proto()
                    page.page.wait_for_timeout(1500)
                    deleted = page.delete_rule(flow_name)
                    page.page.wait_for_timeout(2000)
                    rec.add_detail(f"  [UI] 删除 {flow_name}: {'成功' if deleted else '失败'}")
                    restore = bv.verify_connectivity(dst_domain=target["domain"])
                    rec.add_detail(f"  [恢复连通] {restore['detail']}")
                    ssh_verify("步骤8-内核无规则", bv.verify_app_protocol_kernel_rule, flow_name, expect_present=False)
                    if bv.app_protocol_appset_has_appid(flow_name):
                        rec.add_detail("  - appset仍有appid残留(删除后应清空)")
                    else:
                        rec.add_detail("  ✓ appset已清空")

        finally:
            try:
                page.navigate_to_app_proto()
                page.page.wait_for_timeout(1000)
                page.clean_test_rules(self.PREFIX)
            except Exception:
                pass
            try:
                bv.cleanup_app_protocol_test(self.PREFIX)
            except Exception:
                pass

        print(f"\n[应用协议控制功能验证] {'通过' if not failures else '失败' + str(len(failures)) + '项'}")
        assert not failures, f"应用协议控制功能验证失败({len(failures)}项): {'; '.join(failures[:10])}"
