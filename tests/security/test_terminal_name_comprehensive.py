"""终端名称管理模块综合测试 (安全中心 > 终端名称管理)

URL: 列表 /login#/securityCenter/terminalNameManagement
      新增 /login#/securityCenter/terminalNameManagement/add
      编辑 /login#/securityCenter/terminalNameManagement/edit
单页表格(无Tab). 列表表头: 名称(tagname)/MAC地址(mac)/备注(comment)/操作.
工具栏: 添加/导入/导出/帮助. 行操作仅"编辑/删除"(无启用/停用).
表单: 名称(tagname,必填,maxlength15)/MAC地址(mac,必填)/备注(comment,textarea,maxlength64).

本测试取长补短, 融合多个参考实现:
- 结构/SSH全链路/finally清理/末尾硬断言 → 参考 ARP设置综合测试(安全中心范本)
- 异常输入拦截每个用例打印"提示: xxx"具体文案 → 参考 VLAN设置(错误提示展示)
- 导入(勾选/不勾选"清空现有配置数据"两种)+明确反馈判定 → 参考 FTP/HTTP服务(attempt_import)
- 全程中文文案进报告(禁止英文占位)

后端机制:
- 表 mac_comment(id/mac/tagname/comment), mac 唯一键
- 有 BEFORE INSERT 触发器: 按 mac 删旧行 → 相同 MAC 再次添加是"覆盖更新"(非报错, 本测试专设步骤验证)
- 无 ipset/iptables, 仅 DB 层(L1)验证

实测校验文案(中文):
- 空名称: "请输入名称"
- 空MAC: "请输入MAC地址"
- 非法MAC: "MAC地址格式输入错误"
- 名称超15字符: 浏览器 maxlength=15 截断
- 备注超64字符: 浏览器 maxlength=64 截断
"""
import os
import re
import csv as _csv
import pytest
from utils.step_recorder import StepRecorder
from utils.verify_helper import attach_cmd_recording_to_closure

pytestmark = [pytest.mark.security, pytest.mark.terminal_name]

PREFIX = "tn_t_"
# 测试终端(虚拟MAC, 高端段避开真实设备). (tagname, mac, comment)
TEST_TERMINALS = [
    ("tn_t_001", "aa:bb:cc:dd:00:01", "测试终端一"),
    ("tn_t_002", "aa:bb:cc:dd:00:02", "测试终端二"),
    ("tn_t_003", "aa:bb:cc:dd:00:03", ""),
]
FULL_TERMINAL = ("tn_t_full", "aa:bb:cc:dd:00:10", "全字段终端备注")
# 导入测试数据(独立MAC段, 避免与上面覆盖)
IMPORT_TERMINALS = [
    ("tn_t_imp01", "aa:bb:cc:dd:10:01", "导入测试一"),
    ("tn_t_imp02", "aa:bb:cc:dd:10:02", "导入测试二"),
    ("tn_t_imp03", "aa:bb:cc:dd:10:03", ""),
]
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _write_import_csv(path: str, rows) -> str:
    """按导出格式(id,mac,tagname,comment, 带引号)生成导入CSV(UTF-8)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("id,mac,tagname,comment\n")
        for idx, (tagname, mac, comment) in enumerate(rows, start=1):
            f.write(f'{idx},"{mac}","{tagname}","{comment}"\n')
    return path


class TestTerminalNameComprehensive:
    """终端名称管理综合测试"""

    def test_terminal_name_comprehensive(self, terminal_name_page_logged_in,
                                         step_recorder: StepRecorder, request):
        page = terminal_name_page_logged_in
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
                status = '通过' if result.passed else '失败'
                rec.add_detail(f"[SSH-{label}] {status}: {result.message}")
                rec.add_detail(f"    后端数据: {(result.raw_output or '')[:180]}")
                print(f"[SSH-{label}] {status}: {result.message}", flush=True)
                if not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                rec.add_detail(f"[SSH-{label}] 异常: {str(e)[:80]}")
                ssh_failures.append(f"SSH-{label}异常: {str(e)[:80]}")
                return None
        ssh_verify = attach_cmd_recording_to_closure(backend_verifier, rec, ssh_verify)

        def ui_check(label, cond, detail=""):
            if cond:
                rec.add_detail(f"[UI] {label}: 成功")
            else:
                rec.add_detail(f"[UI] {label}: 失败 - {detail}")
                ui_failures.append(f"{label}: {detail}")

        def expect_blocked(label, result):
            """断言异常输入被拦截, 并把具体中文提示写进报告(参考VLAN错误提示写法)."""
            blocked = bool(result.get("blocked"))
            hint = result.get("error", "") or "; ".join(
                f"{k}:{v}" for k, v in (result.get("field_errors") or {}).items()
            ) or "无提示"
            if blocked:
                rec.add_detail(f"    [OK] {label}: 正确拦截 - 提示: {hint[:60]}")
            else:
                rec.add_detail(f"    [FAIL] {label}: 未被拦截!")
                ui_failures.append(f"{label}: 未被拦截(提示:{hint[:40]})")

        try:
            # ==================== 步骤1: 环境快照+清理 ====================
            with rec.step("步骤1: 环境快照+清理", "清理tn_t_残留(前端+SSH)"):
                if backend_verifier:
                    snap = backend_verifier.verify_terminal_name_count(prefix=PREFIX)
                    rec.add_detail(f"[快照] 清理前 {PREFIX} 数量: {snap.message}")
                    backend_verifier.cleanup_terminal_name_test(PREFIX)
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                cnt = page.clean_test_rules(PREFIX)
                rec.add_detail(f"[前端清理] 删除 {cnt} 条")

            # ==================== 步骤2: 默认结构验证 ====================
            with rec.step("步骤2: 列表默认结构验证", "URL/表头/按钮/搜索框"):
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                struct = page.get_default_structure()
                rec.add_detail(f"[结构] url_ok={struct.get('url_ok')} "
                               f"表头={struct.get('headers')} 按钮={struct.get('buttons')}")
                ui_check("步骤2-URL正确", struct.get("url_ok"), str(struct.get("headers")))
                ui_check("步骤2-表头含名称/MAC地址/备注",
                         {"名称", "MAC地址", "备注"}.issubset(set(struct.get("headers", []))),
                         str(struct.get("headers")))
                ui_check("步骤2-工具栏含添加/导入/导出",
                         {"添加", "导入", "导出"}.issubset(set(struct.get("buttons", []))),
                         str(struct.get("buttons")))
                ui_check("步骤2-搜索框存在", struct.get("search_present"), "无搜索框")
                # 终端名称表头无排序能力(如实记录)
                rec.add_detail(f"[排序] 表头可排序列: {struct.get('sortable_columns')} "
                               f"(全部不可排序={'是' if struct.get('all_headers_unsortable') else '否'})")

            # ==================== 步骤3: 新增表单结构验证 ====================
            with rec.step("步骤3: 新增表单结构验证", "字段/必填/maxlength/placeholder"):
                page.open_add_page()
                page.page.wait_for_timeout(800)
                form = page.get_form_structure()
                rec.add_detail(f"[表单] 名称(必填={form.get('tagname_required')}, "
                               f"maxlength={form.get('tagname_maxlength')}, "
                               f"placeholder={form.get('tagname_placeholder')})")
                rec.add_detail(f"[表单] MAC(必填={form.get('mac_required')}, "
                               f"placeholder={form.get('mac_placeholder')})")
                rec.add_detail(f"[表单] 备注(必填={form.get('comment_required')}, "
                               f"maxlength={form.get('comment_maxlength')})")
                ui_check("步骤3-名称字段存在且必填",
                         form.get("tagname_present") and form.get("tagname_required"), "名称缺失或非必填")
                ui_check("步骤3-名称maxlength=15",
                         form.get("tagname_maxlength") == 15, f"maxlength={form.get('tagname_maxlength')}")
                ui_check("步骤3-MAC字段存在且必填",
                         form.get("mac_present") and form.get("mac_required"), "MAC缺失或非必填")
                ui_check("步骤3-备注maxlength=64",
                         form.get("comment_maxlength") == 64, f"maxlength={form.get('comment_maxlength')}")
                ui_check("步骤3-保存/取消按钮",
                         form.get("save_present") and form.get("cancel_present"), "缺少保存/取消")
                page.cancel_rule_form(confirm_dirty=False)
                page.page.wait_for_timeout(500)

            # ==================== 步骤4: 单条添加(普通) L1 ====================
            with rec.step("步骤4: 单条添加(普通) L1", "添加+SSH L1数据库"):
                nm, mac, comment = TEST_TERMINALS[0]
                rec.add_detail(f"[规则] {nm}: mac={mac} comment={comment!r}")
                res = page.add_rule(nm, mac, comment)
                ui_check("步骤4添加", res["success"], res.get("error", ""))
                ssh_verify("步骤4-L1数据库", backend_verifier.verify_terminal_name_database,
                           mac, tagname=nm, comment=comment)

            # ==================== 步骤5: 多条添加 ====================
            with rec.step("步骤5: 多条添加(002/003)", "批量添加+SSH L1"):
                for nm, mac, comment in TEST_TERMINALS[1:]:
                    rec.add_detail(f"[规则] {nm}: mac={mac} comment={comment!r}")
                    res = page.add_rule(nm, mac, comment)
                    ui_check(f"步骤5添加{nm}", res["success"], res.get("error", ""))
                    ssh_verify(f"步骤5-L1-{nm}", backend_verifier.verify_terminal_name_database,
                               mac, tagname=nm, comment=comment)

            # ==================== 步骤6: 全字段添加(含备注) L1 ====================
            with rec.step("步骤6: 全字段添加(名称+MAC+备注) L1", "全字段+SSH L1"):
                nm, mac, comment = FULL_TERMINAL
                rec.add_detail(f"[规则] {nm}: mac={mac} comment={comment!r}")
                res = page.add_rule(nm, mac, comment)
                ui_check("步骤6添加", res["success"], res.get("error", ""))
                ssh_verify("步骤6-L1", backend_verifier.verify_terminal_name_database,
                           mac, tagname=nm, comment=comment)

            # ==================== 步骤7: 计数验证 ====================
            with rec.step("步骤7: 计数验证(前端 vs SSH)", "前端存在 vs SSH计数"):
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1500)
                all_names = TEST_TERMINALS + [FULL_TERMINAL]
                for nm, _, _ in all_names:
                    if not page.rule_exists(nm):
                        ui_failures.append(f"步骤7: 列表未显示规则 {nm}")
                if backend_verifier:
                    cnt = backend_verifier.verify_terminal_name_count(prefix=PREFIX)
                    rec.add_detail(f"[SSH计数] {PREFIX} {cnt.message}")
                    m = re.search(r'数量:\s*(\d+)', cnt.message)
                    n = int(m.group(1)) if m else 0
                    if n < len(all_names):
                        ui_failures.append(f"步骤7: SSH {PREFIX} 数量{n}<{len(all_names)}")

            # ==================== 步骤8: 编辑(改名称+备注) L1 ====================
            with rec.step("步骤8: 编辑(改名称+备注) L1", "编辑+SSH L1"):
                nm, mac, _ = TEST_TERMINALS[0]
                new_nm, new_comment = "tn_t_001_ed", "编辑后备注"
                rec.add_detail(f"[编辑] {nm} -> 名称={new_nm} 备注={new_comment!r} (mac={mac}不变)")
                res = page.update_rule(nm, new_tagname=new_nm, comment=new_comment)
                ui_check("步骤8编辑", res["success"], res.get("error", ""))
                # 更新本地的引用名称(后续步骤用新名)
                TEST_TERMINALS[0] = (new_nm, mac, new_comment)
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                ui_check("步骤8列表显示新名称", page.rule_exists(new_nm), f"列表未显示 {new_nm}")
                ssh_verify("步骤8-L1编辑后", backend_verifier.verify_terminal_name_database,
                           mac, tagname=new_nm, comment=new_comment)

            # ==================== 步骤9: 搜索验证 ====================
            with rec.step("步骤9: 搜索验证", "搜索tn_t_能命中"):
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                keyword = "tn_t_001"
                page.search_rule(keyword)
                page.page.wait_for_timeout(1000)
                names = page.get_rule_names()
                hit = any(keyword in n for n in names)
                ui_check("步骤9搜索命中", hit, f"搜索'{keyword}'未命中, 当前={names}")
                rec.add_detail(f"[搜索] 关键词'{keyword}' 命中={hit} 当前列表={names[:10]}")
                page.clear_search()
                page.page.wait_for_timeout(800)

            # ==================== 步骤10: 异常输入拦截(参考VLAN错误提示) ====================
            with rec.step("步骤10: 异常输入拦截(空名称/空MAC/非法MAC/超长)", "前端校验应阻止保存并给出中文提示"):
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1000)
                # 空名称(MAC合法)
                r = page.try_add_invalid(tagname="", mac="aa:bb:cc:dd:00:F1", comment="")
                expect_blocked("空名称", r)
                page._dismiss_transient_overlays() if hasattr(page, "_dismiss_transient_overlays") else None
                # 空MAC(名称合法)
                r = page.try_add_invalid(tagname="tn_t_badmac1", mac="", comment="")
                expect_blocked("空MAC", r)
                # 非法MAC(字母越界)
                r = page.try_add_invalid(tagname="tn_t_badmac2", mac="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", comment="")
                expect_blocked("非法MAC(ZZ)", r)
                # 非法MAC(纯文字)
                r = page.try_add_invalid(tagname="tn_t_badmac3", mac="不是mac地址", comment="")
                expect_blocked("非法MAC(文字)", r)
                # 非法MAC(位数不足)
                r = page.try_add_invalid(tagname="tn_t_badmac4", mac="00:11:22:33:44", comment="")
                expect_blocked("非法MAC(位数不足)", r)
                # 名称超15字符(maxlength截断)
                long_name = "tn_t_超长名称abcdefghij"  # 超过15字符
                r = page.try_add_invalid(tagname=long_name, mac="aa:bb:cc:dd:00:F2", comment="")
                expect_blocked("名称超长截断", r)
                # 备注超64字符(maxlength截断, 备注非必填, 截断后仍可保存->验证被截断即拦截成立)
                long_comment = "备" * 80
                r = page.try_add_invalid(tagname="tn_t_lc", mac="aa:bb:cc:dd:00:F3",
                                         comment=long_comment, timeout=4000)
                # 备注截断后通常允许保存(非必填), 这里验证名称未被超长comment影响, 记录行为
                rec.add_detail(f"    [备注超长] 被截断={r.get('truncated')} blocked={r.get('blocked')} "
                               f"提示: {r.get('error','')[:50]}")
                # 清理可能因备注测试成功写入的脏数据
                if r.get("success"):
                    try:
                        page.navigate_to_terminal_name()
                        page.page.wait_for_timeout(800)
                        page.delete_rule("tn_t_lc")
                    except Exception:
                        pass

            # ==================== 步骤11: MAC覆盖语义验证(产品行为亮点) ====================
            with rec.step("步骤11: MAC覆盖语义验证", "相同MAC再次添加=覆盖旧记录(非报错)"):
                # 添加 tn_t_cov1 (mac=M)
                cov_mac = "aa:bb:cc:dd:00:C0"
                res1 = page.add_rule("tn_t_cov1", cov_mac, "覆盖前")
                ui_check("步骤11-添加cov1", res1["success"], res1.get("error", ""))
                ssh_verify("步骤11-L1-cov1", backend_verifier.verify_terminal_name_database,
                           cov_mac, tagname="tn_t_cov1", comment="覆盖前")
                # 再用相同mac添加 tn_t_cov2 (不同名称)
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1000)
                res2 = page.add_rule("tn_t_cov2", cov_mac, "覆盖后")
                ui_check("步骤11-添加cov2(相同MAC)", res2["success"], res2.get("error", ""))
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                cov1_gone = not page.rule_exists("tn_t_cov1")
                cov2_exists = page.rule_exists("tn_t_cov2")
                rec.add_detail(f"[覆盖] cov1消失={cov1_gone} cov2存在={cov2_exists}")
                ui_check("步骤11-旧名称cov1被覆盖消失", cov1_gone, "cov1仍存在(未覆盖)")
                ui_check("步骤11-新名称cov2存在", cov2_exists, "cov2不存在")
                ssh_verify("步骤11-L1-cov2覆盖", backend_verifier.verify_terminal_name_database,
                           cov_mac, tagname="tn_t_cov2", comment="覆盖后")
                # 清理cov2
                try:
                    page.delete_rule("tn_t_cov2")
                except Exception:
                    pass

            # ==================== 步骤11B: MAC大小写归一化(大写输入→小写存储) ====================
            with rec.step("步骤11B: MAC大小写归一化(大写输入自动转小写)", "填大写MAC保存后UI/DB均为小写"):
                up_mac = "AA:BB:CC:DD:00:CA"
                lo_mac = "aa:bb:cc:dd:00:ca"
                res = page.add_rule("tn_t_case", up_mac, "大小写归一化")
                ui_check("步骤11B-添加大写MAC", res["success"], res.get("error", ""))
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                ui_mac = page.get_row_mac("tn_t_case")
                rec.add_detail(f"[归一化] 输入大写={up_mac} UI显示={ui_mac}")
                ui_check("步骤11B-UI显示小写", ui_mac == lo_mac, f"UI MAC={ui_mac}")
                if backend_verifier:
                    row = backend_verifier.find_terminal_name_rule(up_mac)
                    db_mac = (row or {}).get("mac", "")
                    rec.add_detail(f"[归一化-SSH] DB存储mac={db_mac}")
                    if db_mac != lo_mac:
                        ssh_failures.append(f"SSH-步骤11B: 大写MAC未归一化为小写, DB={db_mac}")
                try:
                    page.delete_rule("tn_t_case")
                except Exception:
                    pass

            # ==================== 步骤12: 删除(单条)+SSH删除验证+残留检测 ====================
            with rec.step("步骤12: 删除(单条)+SSH删除验证", "删除+SSH L1删除验证+无残留"):
                nm, mac, _ = FULL_TERMINAL
                rec.add_detail(f"[删除] {nm}(mac={mac})")
                ok = page.delete_rule(nm)
                ui_check("步骤12删除", ok, f"删除 {nm} 失败")
                ssh_verify("步骤12-L1已删除", backend_verifier.verify_terminal_name_not_exists, mac)

            # ==================== 步骤13: 批量删除+SSH计数 ====================
            with rec.step("步骤13: 批量删除+SSH计数", "勾选多条批量删除"):
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                remaining = [n for n, _, _ in TEST_TERMINALS if page.rule_exists(n)]
                rec.add_detail(f"[批量] 待删除: {remaining}")
                if remaining:
                    ok = page.batch_delete_rules(remaining)
                    ui_check("步骤13批量删除", ok, f"批量删除 {remaining} 失败")
                    page.navigate_to_terminal_name()
                    page.page.wait_for_timeout(1200)
                    leftover = [n for n in remaining if page.rule_exists(n)]
                    if leftover:
                        ui_failures.append(f"步骤13: 批量删除后仍存在 {leftover}")
                else:
                    rec.add_detail("[批量] 无待删除规则(跳过)")
                # SSH计数应为0(测试前缀全部清完)
                ssh_verify("步骤13-L1计数清零", backend_verifier.verify_terminal_name_count, prefix=PREFIX)

            # ==================== 步骤14: 导出CSV+TXT ====================
            with rec.step("步骤14: 导出CSV+TXT", "export_rules双格式"):
                # 先添加一条保证导出有内容
                page.add_rule("tn_t_exp", "aa:bb:cc:dd:00:E1", "导出测试")
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                csv_ok = page.export_rules(export_format="csv")
                ui_check("步骤14导出CSV", csv_ok, "CSV导出失败")
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                txt_ok = page.export_rules(export_format="txt")
                ui_check("步骤14导出TXT", txt_ok, "TXT导出失败")
                if csv_ok or txt_ok:
                    rec.add_detail("[导出] CSV+TXT完成")
                try:
                    page.navigate_to_terminal_name()
                    page.page.wait_for_timeout(800)
                    page.delete_rule("tn_t_exp")
                except Exception:
                    pass

            # ==================== 步骤15: 导入(不清空+清空两种) ← 重点 ====================
            # ==================== 步骤15: 导入(不清空+清空两种) ← 重点 ====================
            # 前置: 准备干净环境 + 生成导入测试文件(平铺, 避免嵌套step致父步骤状态异常)
            page.navigate_to_terminal_name()
            page.page.wait_for_timeout(1200)
            page.clean_test_rules(PREFIX)  # 确保干净起点
            page.page.wait_for_timeout(800)
            imp_file = os.path.join(PROJECT_ROOT, "test_data", "exports",
                                    "terminal_name", "tn_import_test.csv")
            _write_import_csv(imp_file, IMPORT_TERMINALS)

            def _verify_import_rows(label, expect_existing_extra=None):
                """SSH验证导入的3条都在DB; expect_existing_extra=额外应保留的(tagname,mac)列表(不清空场景)."""
                if backend_verifier is None:
                    return
                for nm, mac, comment in IMPORT_TERMINALS:
                    ssh_verify(f"{label}-{nm}", backend_verifier.verify_terminal_name_database,
                               mac, tagname=nm, comment=comment)
                if expect_existing_extra:
                    for nm, mac, _c in expect_existing_extra:
                        ssh_verify(f"{label}-保留{nm}", backend_verifier.verify_terminal_name_database,
                                   mac, tagname=nm)

            # ---- 步骤15a: 不勾选"清空现有配置"(追加保留) ----
            with rec.step("步骤15a: 导入-不勾选清空(保留现有+追加导入)", "不清空=保留现有数据并追加导入"):
                rec.add_detail(f"[导入] 测试文件: {os.path.basename(imp_file)} ({len(IMPORT_TERMINALS)}条)")
                keep = ("tn_t_keep", "aa:bb:cc:dd:30:01", "不清空应保留")
                page.add_rule(keep[0], keep[1], keep[2])
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1000)
                imp_a = page.attempt_import(imp_file, clear_existing=False)
                rec.add_detail(f"[导入-不清空] submitted={imp_a.get('submitted')} "
                               f"success={imp_a.get('success')} rejected={imp_a.get('rejected')} "
                               f"清空选项={imp_a.get('clear_state')} 反馈={imp_a.get('feedback','')[:40]}")
                ui_check("步骤15a导入-不勾选清空", imp_a.get("success"), imp_a.get("error", ""))
                page.page.wait_for_timeout(1500)
                _verify_import_rows("步骤15a", expect_existing_extra=[keep])
                # 清理keep, 为15b准备干净环境
                try:
                    page.navigate_to_terminal_name()
                    page.page.wait_for_timeout(800)
                    page.delete_rule(keep[0])
                except Exception:
                    pass

            # ---- 步骤15b: 勾选"清空现有配置"(先清空再导入) ----
            with rec.step("步骤15b: 导入-勾选清空(先清空现有+再导入)", "清空=删除全部现有数据后导入"):
                preexist = ("tn_t_pre", "aa:bb:cc:dd:40:01", "清空应删除")
                page.add_rule(preexist[0], preexist[1], preexist[2])
                ssh_verify("步骤15b-清空前存在", backend_verifier.verify_terminal_name_database,
                           preexist[1], tagname=preexist[0])
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1000)
                imp_b = page.attempt_import(imp_file, clear_existing=True)
                rec.add_detail(f"[导入-清空] submitted={imp_b.get('submitted')} "
                               f"success={imp_b.get('success')} rejected={imp_b.get('rejected')} "
                               f"清空选项={imp_b.get('clear_state')} 反馈={imp_b.get('feedback','')[:40]}")
                ui_check("步骤15b导入-勾选清空", imp_b.get("success"), imp_b.get("error", ""))
                ui_check("步骤15b-清空选项已勾选", imp_b.get("clear_state") is True, "清空选项未勾选")
                page.page.wait_for_timeout(1500)
                _verify_import_rows("步骤15b")
                # preexist 应被清空(不在了)
                ssh_verify("步骤15b-preexist已被清空", backend_verifier.verify_terminal_name_not_exists,
                           preexist[1])

            # ==================== 步骤16: 帮助入口 ====================
            with rec.step("步骤16: 帮助入口", "点击帮助打开popup并关闭"):
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1000)
                help_r = page.verify_help_entry()
                rec.add_detail(f"[帮助] clicked={help_r.get('clicked')} "
                               f"popup={help_r.get('popup_opened')} url={help_r.get('url','')[:60]} "
                               f"无孤儿={help_r.get('no_orphan')}")
                ui_check("步骤16帮助popup打开", help_r.get("popup_opened"), help_r.get("error", ""))

        finally:
            # 1. 前端清理: 删tn_t_前缀
            try:
                page.navigate_to_terminal_name()
                page.page.wait_for_timeout(1200)
                cnt = page.clean_test_rules(PREFIX)
                rec.add_detail(f"[finally前端清理] 删除 {cnt} 条")
            except Exception as e:
                rec.add_detail(f"[finally前端清理异常] {str(e)[:60]}")
            # 2. SSH清理: DELETE mac_comment prefix
            if backend_verifier:
                try:
                    res = backend_verifier.cleanup_terminal_name_test(PREFIX)
                    rec.add_detail(f"[finally SSH清理] {res}")
                except Exception as e:
                    rec.add_detail(f"[finally SSH清理异常] {str(e)[:60]}")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"终端名称管理验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
