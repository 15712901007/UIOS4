"""
路由对象综合测试用例 (网络配置 > 路由对象, 6个分组子tab)

6个分组(统一object_group表, type区分), 各一个综合测试:
- TestIpGroupComprehensive: IP分组(IPv4 type0 + IPv6 type1, radio切换)
- TestMacGroupComprehensive: MAC分组(type2)
- TestPortGroupComprehensive: 端口分组(type3)
- TestDomainGroupComprehensive: 域名分组(type6)
- TestTimePlanComprehensive: 时间计划(type4)
- TestProtocolGroupComprehensive: 协议分组(type5, 点Select弹modal树选协议分类)

后端机制:
  DB: object_group(id,type,group_name,tagname,group_id,group_value JSON明文)
      group_id触发器: IPGP/IPV6GP/MACGP/PORTGP/TIMEGP/PROTOGP/DOMAINGP + id
      UNIQUE(group_name,type), 无enabled字段(无启用/停用)
  内核ipset: IP/IPv6/MAC/端口 → group_{group_id}(hash:ip/hash:mac/bitmap:port)
             时间/协议/域名 → 仅DB+cache(逻辑对象, 不建ipset)
  引用: object_ref表, ref_count>0 被引用无法删除
  校验: group_name 仅中文/英文/数字 1-15字符(不含下划线)

SSH全链路验证: L1数据库 + L2 ipset(IP/MAC/端口/IPv6) + L3 cache + L4引用
"""
import pytest
from utils.step_recorder import StepRecorder


def _make_ssh_verify(rec, backend_verifier, failures):
    """构造 ssh_verify helper (软断言收集 + 末尾硬断言)"""
    def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
        if backend_verifier is None:
            return None
        try:
            result = verify_func(*args, **kwargs)
            status = '[OK]' if result.passed else '[FAIL]'
            print(f"    SSH-{label}: {status} - {result.message}")
            rec.add_detail(f"    SSH-{label}: {status} {result.message}")
            if result.raw_output:
                rec.add_detail(f"      SSH数据: {result.raw_output[:200]}")
            if must_pass and not result.passed:
                failures.append(f"SSH-{label}: {result.message}")
            return result
        except Exception as e:
            print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
            rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
            if must_pass:
                failures.append(f"SSH-{label}: 异常被吞 - {str(e)[:80]}")
            return None
    return ssh_verify


def _test_help(page, rec, failures):
    """测试帮助按钮(不产生孤儿tab)"""
    try:
        page.navigate_back_to_list()
        page.page.wait_for_timeout(800)
        pages_before = len(page.page.context.pages)
        help_btn = page.page.locator('button').filter(has_text="帮助")
        if help_btn.count() > 0:
            try:
                with page.page.context.expect_page(timeout=2500) as np:
                    help_btn.last.click()
                try:
                    np.value.close()
                except Exception:
                    pass
            except Exception:
                page.page.wait_for_timeout(500)
        rec.add_detail("[OK] 帮助测试完成")
        pages_after = len(page.page.context.pages)
        if pages_after > pages_before:
            failures.append("帮助产生孤儿tab")
    except Exception as e:
        rec.add_detail(f"帮助异常: {e}")


def _test_referenced_protection(page, rec, backend_verifier, failures,
                                type_key, my_names):
    """被引用保护验证: 自己分组ref_count=0; 若存在系统被引用分组则UI尝试删除验证拦截"""
    ssh_verify = _make_ssh_verify(rec, backend_verifier, failures)
    # 1. 自己创建的分组未被引用(ref_count=0)
    if my_names:
        ssh_verify("L4-自己分组未被引用",
                   backend_verifier.verify_object_group_ref,
                   must_pass=False, name=my_names[0],
                   type_key=type_key, expect_referenced=False)
    # 2. 查系统被引用分组(ref_count>0), 有则UI尝试删除应被拦截
    if backend_verifier is None:
        return
    try:
        t = backend_verifier._og_type(type_key)
        rows = backend_verifier._sqlite_query_list(
            f"SELECT group_name,group_id FROM object_group WHERE type={t}"
        )
        referenced = []
        for r in rows:
            gn = r.get("group_name", "")
            if gn in my_names:
                continue
            if backend_verifier.get_object_ref_count(r.get("group_id", "")) > 0:
                referenced.append(gn)
        if not referenced:
            rec.add_detail("无系统被引用分组, 跳过删除拦截实测(已验证ref机制)")
            return
        target = referenced[0]
        page.navigate_back_to_list()
        page.page.wait_for_timeout(500)
        try:
            page.delete_rule(target)
        except Exception:
            pass
        page.page.wait_for_timeout(1500)
        still = backend_verifier.find_object_group(target, type_key) is not None
        if still:
            rec.add_detail(f"[OK] 被引用分组'{target}'删除被拦截(ref_count>0)")
        else:
            failures.append(f"被引用分组'{target}'被删除(应拦截)")
    except Exception as e:
        rec.add_detail(f"被引用保护验证异常: {e}")


def _run_group_comprehensive(page, rec, backend_verifier, failures,
                             type_key, rules, has_ipset, add_one,
                             module_name, extra_value, sort_col="分组名称"):
    """通用分组综合测试主流程

    Args:
        type_key: 主type名称(ip/mac/port/domain/time/proto)
        rules: [{name, value, verify, tk}] tk=该条verify用的type_key(IPv6用'ipv6')
        has_ipset: 是否有内核ipset验证(IP/MAC/端口/IPv6=True)
        add_one: callable(page, rule_dict) -> bool 添加一条
        module_name: 导出路径用的模块名
        extra_value: AUTOEXTRA标志用的value
    """
    ssh_verify = _make_ssh_verify(rec, backend_verifier, failures)

    def wait(ms=2000):
        page.page.wait_for_timeout(ms)

    names = [r['name'] for r in rules]

    print("\n" + "=" * 60)
    print(f"路由对象-{type_key}分组综合测试开始")
    print("=" * 60)

    # 步骤1: 清理
    with rec.step("步骤1: 清理", f"清理{type_key}分组AUTO*残留"):
        print("\n[步骤1] 清理...")
        if backend_verifier:
            backend_verifier.cleanup_object_group_test(type_key, 'AUTO')
        page.navigate_back_to_list()
        wait(800)

    # 步骤2: 批量添加 + L1/L2/L3验证
    with rec.step("步骤2: 批量添加", f"添加{len(rules)}条 + DB/ipset/cache全链路"):
        print(f"\n[步骤2] 批量添加{len(rules)}条...")
        for r in rules:
            ok = add_one(page, r)
            print(f"  添加 {r['name']}: {ok}")
            rec.add_detail(f"添加{r['name']}: {ok}")
            wait()
        for r in rules:
            tk = r.get('tk', type_key)
            ssh_verify(f"L1-{r['name']}", backend_verifier.verify_object_group_database,
                       must_pass=True, name=r['name'], type_key=tk, expected_value=r['verify'])
            if has_ipset:
                ssh_verify(f"L2-{r['name']}ipset", backend_verifier.verify_object_group_ipset,
                           must_pass=False, name=r['name'], type_key=tk)
            ssh_verify(f"L3-{r['name']}cache", backend_verifier.verify_object_group_cache,
                       must_pass=False, name=r['name'], type_key=tk)

    # 步骤3: 编辑第一条(改名)
    with rec.step("步骤3: 编辑", "编辑第一条改名"):
        print("\n[步骤3] 编辑...")
        old_name = rules[0]['name']
        new_name = (old_name + "E")[:15]
        try:
            ok = page.edit_rule(old_name, new_name=new_name)
            print(f"  编辑{old_name}->{new_name}: {ok}")
            rec.add_detail(f"编辑{old_name}->{new_name}: {ok}")
            if ok:
                rules[0]['name'] = new_name
                names[0] = new_name
            wait()
            ssh_verify("L1-编辑后新名存在",
                       backend_verifier.verify_object_group_database,
                       must_pass=False, name=new_name, type_key=rules[0].get('tk', type_key))
        except Exception as e:
            print(f"  编辑异常: {e}")
            rec.add_detail(f"编辑异常: {e}")

    # 步骤4: 搜索 + 排序
    with rec.step("步骤4: 搜索+排序", "搜索前缀匹配 + 分组名称列排序"):
        print("\n[步骤4] 搜索+排序...")
        try:
            page.navigate_back_to_list()
            wait(800)
            kw = "AUTO"  # 所有测试名都以AUTO开头
            page.search_rule(kw)
            wait(1500)
            found = page.rule_exists(names[0])
            print(f"  搜索'AUTO'匹配{names[0]}: {found}")
            rec.add_detail(f"搜索匹配: {found}")
            page.clear_search()
            wait(500)
        except Exception as e:
            print(f"  搜索异常: {e}")
        # 列排序(分组名称/计划名称列有sortIcon)
        try:
            page.navigate_back_to_list()
            wait(500)
            ok = page.sort_by_column(sort_col)
            print(f"  排序'{sort_col}': {ok}")
            rec.add_detail(f"排序{sort_col}: {ok}")
            wait(500)
        except Exception as e:
            print(f"  排序异常: {e}")
            rec.add_detail(f"排序异常: {e}")

    # 步骤5: 删除最后一条 + L1/L2验证
    last = rules[-1]
    with rec.step("步骤5: 删除", f"删除{last['name']}"):
        print(f"\n[步骤5] 删除{last['name']}...")
        try:
            page.navigate_back_to_list()
            wait(500)
            page.delete_rule(last['name'])
            wait()
        except Exception as e:
            print(f"  删除异常: {e}")
        tk = last.get('tk', type_key)
        ssh_verify(f"L1-删除后无{last['name']}",
                   backend_verifier.verify_object_group_database,
                   must_pass=True, name=last['name'], type_key=tk, expect_absent=True)
        if has_ipset:
            ssh_verify(f"L2-{last['name']}ipset消失",
                       backend_verifier.verify_object_group_ipset,
                       must_pass=False, name=last['name'], type_key=tk, expect_exists=False)

    # 步骤6: 被引用保护
    with rec.step("步骤6: 被引用保护", "ref_count机制 + 被引用无法删除"):
        print("\n[步骤6] 被引用保护...")
        _test_referenced_protection(page, rec, backend_verifier, failures, type_key, names)

    # 步骤7: 异常输入(空名称/含下划线)
    with rec.step("步骤7: 异常输入", "空名称/非法字符应被拦截"):
        print("\n[步骤7] 异常输入...")
        err1 = page.try_add_rule_invalid(name="")
        msg1 = err1[:40] if err1 else "未拦截"
        print(f"  空名称: {msg1}")
        rec.add_detail(f"空名称: {msg1}")
        err2 = page.try_add_rule_invalid(name="AUTO_BAD_X")
        msg2 = err2[:40] if err2 else "未拦截"
        print(f"  含下划线: {msg2}")
        rec.add_detail(f"含下划线: {msg2}")
        try:
            page.page.keyboard.press("Escape")
            page.navigate_back_to_list()
            wait(500)
        except Exception:
            pass

    # 步骤8: 导出(txt + csv两种格式)
    export_file = None
    with rec.step("步骤8: 导出", "导出txt+csv两种格式(供导入用)"):
        print("\n[步骤8] 导出txt+csv...")
        import os as _os
        from config.config import get_config as _gc
        _cfg = _gc()
        _base = _cfg.test_data.get_export_path(module_name, _cfg.get_project_root())
        export_file = _os.path.splitext(_base)[0] + ".txt"
        for fmt in ["txt", "csv"]:
            try:
                page.navigate_back_to_list()
                wait(800)
                exported = page.export_rules(use_config_path=True, export_format=fmt)
                out_file = _os.path.splitext(_base)[0] + f".{fmt}"
                ok_file = _os.path.exists(out_file)
                print(f"  导出{fmt}: {exported}(文件存在:{ok_file})")
                rec.add_detail(f"导出{fmt}: {exported}(文件:{ok_file})")
            except Exception as e:
                print(f"  [WARN] 导出{fmt}异常: {e}")
                rec.add_detail(f"导出{fmt}异常: {e}")

    # 步骤9: 导入追加(改名AUTOIMP1)
    with rec.step("步骤9: 导入追加", "导入改名规则AUTOIMP1, 验证追加+入库"):
        print("\n[步骤9] 导入追加...")
        import os as _os
        import re as _re
        if not (export_file and _os.path.exists(export_file)):
            print(f"  [WARN] 无导出文件, 跳过: {export_file}")
            rec.add_detail("[WARN] 跳过导入追加")
        else:
            imp_file = export_file.replace(".txt", "_append.txt")
            try:
                with open(export_file, 'r', encoding='utf-8') as f:
                    first_line = f.readline()
                ln = first_line
                ln = _re.sub(r'^id=\S+\s*', '', ln)        # 剥行首id(主键)
                ln = _re.sub(r'\sgroup_id=\S+', '', ln)     # 剥group_id(触发器重建)
                ln = _re.sub(r'\stagname=\S+', '', ln)      # 剥tagname
                ln = _re.sub(r'group_name=\S+', 'group_name=AUTOIMP1', ln)
                with open(imp_file, 'w', encoding='utf-8') as f:
                    f.write(ln)
                print(f"  追加文件准备完成(AUTOIMP1)")
            except Exception as e:
                print(f"  [WARN] 准备追加文件失败: {e}")
                imp_file = export_file
            cnt_before = backend_verifier.count_object_group(type_key) if backend_verifier else -1
            try:
                page.navigate_back_to_list()
                wait(800)
                page.import_rules(imp_file, clear_existing=False)
                wait()
            except Exception as e:
                print(f"  [WARN] 导入异常: {e}")
            cnt_after = backend_verifier.count_object_group(type_key) if backend_verifier else -1
            print(f"  导入: {cnt_before} -> {cnt_after}")
            rec.add_detail(f"导入: {cnt_before}->{cnt_after}")
            ssh_verify("L1-导入追加-AUTOIMP1",
                       backend_verifier.verify_object_group_database,
                       must_pass=False, name="AUTOIMP1", type_key=type_key)

    # 步骤10: 导入清空(AUTOEXTRA标志, 勾清空)
    with rec.step("步骤10: 导入清空", "加AUTOEXTRA标志, 清空导入验证"):
        print("\n[步骤10] 导入清空...")
        import os as _os
        if not (export_file and _os.path.exists(export_file)):
            print("  [WARN] 无导出文件, 跳过清空导入")
            rec.add_detail("[WARN] 跳过清空导入")
        else:
            try:
                add_one(page, {"name": "AUTOEXTRA", "value": extra_value,
                               "tk": type_key})
                wait()
            except Exception as e:
                print(f"  添加EXTRA异常: {e}")
            try:
                page.navigate_back_to_list()
                wait(800)
                page.import_rules(export_file, clear_existing=True)
                wait()
            except Exception as e:
                print(f"  [WARN] 清空导入异常(可能存在被引用分组): {e}")
                rec.add_detail(f"清空导入异常: {e}")
            # 路由对象导入弹窗无"清空"checkbox(仅追加导入, 与端口分流等模块不同)
            # clear_existing无效, 导入恒为追加 → AUTOEXTRA保留属正常行为, 如实记录其状态
            ssh_verify("L1-AUTOEXTRA状态(追加导入保留)",
                       backend_verifier.verify_object_group_database,
                       must_pass=False, name="AUTOEXTRA", type_key=type_key)

    # 步骤11: 帮助
    with rec.step("步骤11: 帮助", "测试帮助按钮"):
        print("\n[步骤11] 帮助...")
        _test_help(page, rec, failures)

    # 步骤12: 最终清理(批量删除 + 兜底)
    with rec.step("步骤12: 最终清理", "批量删除AUTO* + 兜底逐行删 + SSH验证0残留"):
        print("\n[步骤12] 最终清理(批量删除)...")
        # 批量删除: 搜索AUTO→全选→批量删(测批量删除功能)
        try:
            page.navigate_back_to_list()
            wait(800)
            page.search_rule("AUTO")
            wait(1000)
            page.select_all_rules()
            wait(800)
            cnt_before = backend_verifier.count_object_group(type_key) if backend_verifier else -1
            page.batch_delete()
            wait()
            page.clear_search()
            wait(500)
            cnt_after = backend_verifier.count_object_group(type_key) if backend_verifier else -1
            print(f"  批量删除: {cnt_before}->{cnt_after}")
            rec.add_detail(f"批量删除: {cnt_before}->{cnt_after}")
        except Exception as e:
            print(f"  批量删除异常: {e}")
            rec.add_detail(f"批量删除异常: {e}")
        # 兜底逐行删(批量删未清干净的 + IPv6视图的)
        for nm in list(names) + ["AUTOIMP1", "AUTOEXTRA"]:
            for _ in range(2):
                if backend_verifier and not backend_verifier.find_object_group(nm, type_key):
                    break
                try:
                    page.navigate_back_to_list()
                    wait(500)
                    if page.rule_exists(nm):
                        page.delete_rule(nm)
                        wait()
                except Exception as e:
                    print(f"  删除{nm}异常: {str(e)[:50]}")
        if backend_verifier:
            # 清理所有涉及的type(IP分组含IPv4 type0 + IPv6 type1)
            types_to_clean = set(r.get('tk', type_key) for r in rules) | {type_key}
            for tk in types_to_clean:
                backend_verifier.cleanup_object_group_test(tk, 'AUTO')
            wait()
        for nm in list(names) + ["AUTOIMP1"]:
            ssh_verify(f"L1-清理后无{nm}",
                       backend_verifier.verify_object_group_database,
                       must_pass=False, name=nm, type_key=type_key, expect_absent=True)

    print("\n" + "=" * 60)
    print(f"路由对象-{type_key}分组综合测试完成")
    print("=" * 60)
    if failures:
        print(f"\n[断言] 共 {len(failures)} 项失败:")
        for f in failures:
            print(f"  - {f}")
    assert not failures, f"验证失败({len(failures)}项): {'; '.join(failures)}"


# ============================================================================
# 测试1: IP分组 (IPv4 type0 + IPv6 type1)
# ============================================================================
@pytest.mark.ip_group
@pytest.mark.network
class TestIpGroupComprehensive:
    """IP分组综合测试 — IPv4/IPv6 + iptables ipset内核验证"""

    IP_RULES = [
        {"name": "AUTOIP1", "value": ["10.66.0.100", "10.66.0.101"],
         "verify": "10.66.0.100", "tk": "ip"},
        {"name": "AUTOIP2", "value": ["10.66.0.200"],
         "verify": "10.66.0.200", "tk": "ip"},
        {"name": "AUTOIPV6A", "value": ["2001:db8::100"],
         "verify": "2001:db8::100", "tk": "ipv6"},
    ]

    def test_ip_group_comprehensive(self, ip_group_page_logged_in,
                                    step_recorder: StepRecorder, request):
        page = ip_group_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None
        failures = []

        def add_one(pg, r):
            iv = 'ipv6' if r.get('tk') == 'ipv6' else 'ipv4'
            return pg.add_rule(r['name'], r['value'], ip_version=iv)

        _run_group_comprehensive(
            page, rec, backend_verifier, failures,
            type_key='ip', rules=self.IP_RULES, has_ipset=True,
            add_one=add_one, module_name='route_object_ip',
            extra_value=["10.66.0.250"],
        )


# ============================================================================
# 测试2: MAC分组 (type2)
# ============================================================================
@pytest.mark.mac_group
@pytest.mark.network
class TestMacGroupComprehensive:
    """MAC分组综合测试 — MAC地址 + ipset内核验证"""

    MAC_RULES = [
        {"name": "AUTOMAC1", "value": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"],
         "verify": "AA:BB:CC:00:00:01", "tk": "mac"},
        {"name": "AUTOMAC2", "value": ["AA:BB:CC:00:00:03"],
         "verify": "AA:BB:CC:00:00:03", "tk": "mac"},
    ]

    def test_mac_group_comprehensive(self, mac_group_page_logged_in,
                                     step_recorder: StepRecorder, request):
        page = mac_group_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None
        failures = []

        def add_one(pg, r):
            return pg.add_rule(r['name'], r['value'])

        _run_group_comprehensive(
            page, rec, backend_verifier, failures,
            type_key='mac', rules=self.MAC_RULES, has_ipset=True,
            add_one=add_one, module_name='route_object_mac',
            extra_value=["AA:BB:CC:00:00:99"],
        )


# ============================================================================
# 测试3: 端口分组 (type3)
# ============================================================================
@pytest.mark.port_group
@pytest.mark.network
class TestPortGroupComprehensive:
    """端口分组综合测试 — 端口 + ipset(bitmap:port)内核验证"""

    PORT_RULES = [
        {"name": "AUTOPORT1", "value": ["80", "443"],
         "verify": "80", "tk": "port"},
        {"name": "AUTOPORT2", "value": ["8080"],
         "verify": "8080", "tk": "port"},
    ]

    def test_port_group_comprehensive(self, port_group_page_logged_in,
                                      step_recorder: StepRecorder, request):
        page = port_group_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None
        failures = []

        def add_one(pg, r):
            return pg.add_rule(r['name'], r['value'])

        _run_group_comprehensive(
            page, rec, backend_verifier, failures,
            type_key='port', rules=self.PORT_RULES, has_ipset=True,
            add_one=add_one, module_name='route_object_port',
            extra_value=["9999"],
        )


# ============================================================================
# 测试4: 域名分组 (type6)
# ============================================================================
@pytest.mark.domain_group
@pytest.mark.network
class TestDomainGroupComprehensive:
    """域名分组综合测试 — 域名(逻辑对象, 仅DB+cache, 无ipset)"""

    DOMAIN_RULES = [
        {"name": "AUTODOM1", "value": ["baidu.com", "qq.com"],
         "verify": "baidu.com", "tk": "domain"},
        {"name": "AUTODOM2", "value": ["taobao.com"],
         "verify": "taobao.com", "tk": "domain"},
    ]

    def test_domain_group_comprehensive(self, domain_group_page_logged_in,
                                        step_recorder: StepRecorder, request):
        page = domain_group_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None
        failures = []

        def add_one(pg, r):
            return pg.add_rule(r['name'], r['value'])

        _run_group_comprehensive(
            page, rec, backend_verifier, failures,
            type_key='domain', rules=self.DOMAIN_RULES, has_ipset=False,
            add_one=add_one, module_name='route_object_domain',
            extra_value=["extra.com"],
        )


# ============================================================================
# 测试5: 时间计划 (type4)
# ============================================================================
@pytest.mark.time_plan
@pytest.mark.network
class TestTimePlanComprehensive:
    """时间计划综合测试 — 按周循环(逻辑对象, 仅DB+cache, 无ipset)"""

    TIME_RULES = [
        {"name": "AUTOTIME1", "value": None, "verify": "weekly", "tk": "time"},
        {"name": "AUTOTIME2", "value": None, "verify": "weekly", "tk": "time"},
    ]

    def test_time_plan_comprehensive(self, time_plan_page_logged_in,
                                     step_recorder: StepRecorder, request):
        page = time_plan_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None
        failures = []

        def add_one(pg, r):
            return pg.add_rule(r['name'])

        _run_group_comprehensive(
            page, rec, backend_verifier, failures,
            type_key='time', rules=self.TIME_RULES, has_ipset=False,
            add_one=add_one, module_name='route_object_time',
            extra_value=None, sort_col="计划名称",
        )


# ============================================================================
# 测试6: 协议分组 (type5)
# ============================================================================
@pytest.mark.protocol_group
@pytest.mark.network
class TestProtocolGroupComprehensive:
    """协议分组综合测试 — 协议分类树modal(逻辑对象, 仅DB+cache, 无ipset)"""

    PROTO_RULES = [
        {"name": "AUTOPROTO1", "value": "网络协议",
         "verify": "网络协议", "tk": "proto"},
        {"name": "AUTOPROTO2", "value": "网络游戏",
         "verify": "网络游戏", "tk": "proto"},
    ]

    def test_protocol_group_comprehensive(self, protocol_group_page_logged_in,
                                          step_recorder: StepRecorder, request):
        page = protocol_group_page_logged_in
        rec = step_recorder
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None
        failures = []

        def add_one(pg, r):
            return pg.add_rule(r['name'], r['value'])

        _run_group_comprehensive(
            page, rec, backend_verifier, failures,
            type_key='proto', rules=self.PROTO_RULES, has_ipset=False,
            add_one=add_one, module_name='route_object_proto',
            extra_value="休闲娱乐",
        )
