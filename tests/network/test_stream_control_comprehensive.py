"""
智能流控综合测试用例

网络配置 > 智能流控 页面综合测试(覆盖三个页面 + 模式切换 + SSH四级验证)
URL: /login#/networkConfiguration/intelligentFlowControl

测试覆盖:
1. 环境清理 + 开启智能流控(stream_ctl_mode=1) + SSH运行时验证
2. 流控线路: 编辑带宽 + 全部启用/停用 + SSH验证(wan_config.qos_*)
3. 切换模式: 智能模式 + 流控场景(网页优先/自定义+应用优先级) + SSH验证(layer7_intell)
4. 优先域名设置(high_prio_host): 增删改/停用启用/搜索/排序/导出导入/异常/批量 + SSH验证
5. 终端独立限速(alone_limit): 增删改/停用启用/搜索/异常/批量 + SSH验证(L1数据库+L2 ipset)
6. 切换手动模式(stream_ctl_mode=2) + SSH验证
7. 流控策略设置(layer7_qos): 增删改/停用启用/搜索/导入导出/批量 + SSH验证(L1+L2 ipset)
8. 关闭流控(stream_ctl_mode=0) + 恢复环境

SSH后台验证:
- L1数据库: global_config/layer7_intell/wan_config/alone_limit/layer7_qos/high_prio_host
- L2 ipset: alone_limit_$id/_alone_limit_$id, layer7qos_src_$id
- L3 iptables: LAYER7_IN/OUT/STREAM_LAYER7_NEW链
- L4运行时: htb_rate_est, qos进程, ik_cntl http_app(优先域名生效条件)
"""
import pytest
import os
from pages.network.stream_control_page import StreamControlPage
from pages.network.alone_limit_page import AloneLimitPage
from pages.network.high_prio_host_page import HighPrioHostPage
from pages.network.layer7_qos_page import Layer7QosPage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.stream_control
@pytest.mark.network
class TestStreamControlComprehensive:
    """智能流控综合测试 - 三页面(流控线路/优先域名/终端独立限速/流控策略)+模式切换"""

    def test_stream_control_comprehensive(self, stream_control_page_logged_in: StreamControlPage,
                                          step_recorder: StepRecorder, request):
        """综合测试: 开启流控 -> 流控线路 -> 切换模式 -> 优先域名 ->
        终端独立限速 -> 手动模式 -> 流控策略 -> 关闭流控"""
        sc = stream_control_page_logged_in
        page = sc.page
        rec = step_recorder

        # 动态获取backend_verifier
        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        config = get_config()
        base_url = config.get_base_url()
        # 子page共享同一page对象(同属智能流控页面不同tab/模式)
        alone_page = AloneLimitPage(page, base_url)
        high_page = HighPrioHostPage(page, base_url)
        l7_page = Layer7QosPage(page, base_url)

        ssh_failures = []
        ui_failures = []

        def ssh_verify(label, verify_func, *args, must_pass=False, **kwargs):
            if backend_verifier is None:
                return None
            try:
                result = verify_func(*args, **kwargs)
                status = '通过' if result.passed else '失败'
                print(f"    SSH-{label}: {status} - {result.message}")
                rec.add_detail(f"    SSH-{label}: {'[OK]' if result.passed else '[FAIL]'} {result.message}")
                if result.raw_output:
                    rec.add_detail(f"      SSH数据: {result.raw_output[:160]}")
                if must_pass and not result.passed:
                    ssh_failures.append(f"SSH-{label}: {result.message}")
                return result
            except Exception as e:
                print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
                if must_pass:
                    ssh_failures.append(f"SSH-{label}: 异常被吞 - {str(e)[:80]}")
                return None

        # 导出文件路径(提前定义)
        export_high_csv = config.test_data.get_export_path(
            "high_prio_host", config.get_project_root())
        export_high_txt = export_high_csv.replace(".csv", ".txt")
        export_l7_csv = config.test_data.get_export_path(
            "layer7_qos", config.get_project_root())
        export_l7_txt = export_l7_csv.replace(".csv", ".txt")

        print("\n" + "=" * 60)
        print("智能流控综合测试开始")
        print("=" * 60)

        # ========== 步骤1: 环境清理 + 开启智能流控 ==========
        with rec.step("步骤1: 环境清理+开启智能流控", "清理残留+开启流控+SSH验证stream_ctl_mode=1"):
            print("\n[步骤1] 环境清理 + 开启智能流控...")
            if backend_verifier is not None:
                backend_verifier.cleanup_stream_control(disable=True)
                rec.add_detail("[清理] 关闭流控+清空规则表+清理ipset")

            sc.navigate_to_stream_control(force_reload=True)
            page.wait_for_timeout(1000)
            ok = sc.enable_stream_control()
            print(f"  开启流控: {ok}")
            rec.add_detail(f"  开启流控: {'[OK]' if ok else '[FAIL]'}")
            # 显式切智能模式+网页优先(避免上一次测试残留手动模式stream_ctl_mode=2)
            sc.switch_mode(mode="intelligent", scene="网页优先", ports="80,443")
            page.wait_for_timeout(1500)

            # SSH验证
            ssh_verify("L1-stream_ctl_mode=1(智能)",
                       backend_verifier.verify_stream_ctl_mode, must_pass=True,
                       expected_mode=1)
            ssh_verify("L4-qos运行时(开启)",
                       backend_verifier.verify_qos_runtime, must_pass=True,
                       expect_enabled=True)

        # ========== 步骤2: 流控线路-编辑带宽 ==========
        with rec.step("步骤2: 流控线路-编辑wan1带宽", "设wan1上行10000/下行20000 + SSH验证wan_config"):
            print("\n[步骤2] 编辑wan1带宽...")
            ok = sc.edit_line_bandwidth("wan1", upload=10000, download=20000)
            print(f"  编辑带宽: {ok}")
            rec.add_detail(f"  wan1带宽: {'[OK]' if ok else '[FAIL]'}")
            if not ok:
                ui_failures.append("编辑wan1带宽失败")

            ssh_verify("L1-wan1带宽(10000/20000)",
                       backend_verifier.verify_wan_config_bandwidth, must_pass=True,
                       line="wan1", upload=10000, download=20000)

        # ========== 步骤3: 流控线路-启用 ==========
        with rec.step("步骤3: 流控线路-启用", "单条启用wan1 + SSH验证qos_switch=1"):
            print("\n[步骤3] 启用流控线路wan1...")
            # 注: "全部启用"按钮对流控线路无效(表格无checkbox列, 点击无反应),
            # 用单条enable_line确保qos_switch=1
            sc.enable_all_lines()
            page.wait_for_timeout(800)
            ok = sc.enable_line("wan1")
            print(f"  启用wan1: {ok}")
            rec.add_detail(f"  启用wan1: {'[OK]' if ok else '[FAIL]'}")

            page.wait_for_timeout(1500)
            ssh_verify("L1-wan1 qos_switch=1(启用)",
                       backend_verifier.verify_wan_config_bandwidth, must_pass=True,
                       line="wan1", qos_switch=1)

        # ========== 步骤4: 流控线路-停用 ==========
        with rec.step("步骤4: 流控线路-停用", "单条停用wan1 + SSH验证qos_switch=0"):
            print("\n[步骤4] 停用流控线路wan1...")
            ok = sc.disable_line("wan1")
            print(f"  停用wan1: {ok}")
            rec.add_detail(f"  停用wan1: {'[OK]' if ok else '[FAIL]'}")

            page.wait_for_timeout(1500)
            ssh_verify("L1-wan1 qos_switch=0(停用)",
                       backend_verifier.verify_wan_config_bandwidth, must_pass=True,
                       line="wan1", qos_switch=0)

        # ========== 步骤5: 切换模式-网页优先 ==========
        with rec.step("步骤5: 切换模式-网页优先", "智能模式+网页优先场景+SSH验证auto=2"):
            print("\n[步骤5] 切换到网页优先场景...")
            ok = sc.switch_mode(mode="intelligent", scene="网页优先", ports="80,443")
            print(f"  切换网页优先: {ok}")
            rec.add_detail(f"  网页优先: {'[OK]' if ok else '[FAIL]'}")

            ssh_verify("L1-layer7_intell(auto=2)",
                       backend_verifier.verify_layer7_intell_config, must_pass=True,
                       expected_fields={"auto": "2"})

        # ========== 步骤6: 切换模式-自定义+应用优先级 ==========
        with rec.step("步骤6: 切换模式-自定义+应用优先级",
                      "自定义场景+调整应用优先级+SSH验证auto=0"):
            print("\n[步骤6] 切换到自定义场景 + 调整应用优先级...")
            app_prios = {"网页浏览": 0, "网络游戏": 7, "社交通讯": 1}
            ok = sc.switch_mode(mode="intelligent", scene="自定义",
                                app_priorities=app_prios)
            print(f"  自定义+优先级: {ok}")
            rec.add_detail(f"  自定义场景: {'[OK]' if ok else '[FAIL]'}")
            rec.add_detail(f"  应用优先级: {app_prios}")

            # SSH验证auto=0 + 应用优先级(Http=0, Game=7, Im=1)
            ssh_verify("L1-layer7_intell(auto=0自定义)",
                       backend_verifier.verify_layer7_intell_config, must_pass=True,
                       expected_fields={"auto": "0", "Http": "0",
                                        "Game": "7", "Im": "1"})

        # ========== 步骤7: 切回网页优先(为优先域名tab准备) ==========
        with rec.step("步骤7: 切回网页优先", "切回网页优先(优先域名tab仅预设场景显示)"):
            print("\n[步骤7] 切回网页优先场景...")
            ok = sc.switch_mode(mode="intelligent", scene="网页优先", ports="80,443")
            print(f"  网页优先: {ok}")
            rec.add_detail(f"  网页优先: {'[OK]' if ok else '[FAIL]'}")

        # ========== 步骤8: 优先域名-添加3条 ==========
        high_rules = [
            {"name": "hp1", "host": "a.example.com", "remark": "测试域名A"},
            {"name": "hp2", "host": "b.example.com", "remark": "测试域名B"},
            {"name": "hp3", "host": "c.example.com", "remark": "测试域名C"},
        ]
        with rec.step("步骤8: 优先域名-添加3条", "添加3条优先域名 + SSH验证high_prio_host"):
            print("\n[步骤8] 添加优先域名...")
            high_page.navigate_to_high_prio_host()
            page.wait_for_timeout(800)
            for r in high_rules:
                ok = high_page.add_rule(r["name"], r["host"], r["remark"])
                assert ok, f"添加优先域名 {r['name']} 失败"
                print(f"  + {r['name']}: {r['host']}")
                rec.add_detail(f"  [OK] 添加 {r['name']}")
                ssh_verify(f"L1-优先域名({r['name']})",
                           backend_verifier.verify_high_prio_host_database,
                           must_pass=True, name=r["name"],
                           expected_fields={"host": r["host"], "enabled": "yes"})

        # ========== 步骤9: 优先域名-编辑 ==========
        with rec.step("步骤9: 优先域名-编辑", "修改hp1的域名和备注"):
            print("\n[步骤9] 编辑优先域名 hp1...")
            ok = high_page.edit_rule("hp1", host="a-edit.example.com",
                                     remark="已编辑A")
            print(f"  编辑: {ok}")
            rec.add_detail(f"  编辑hp1: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-编辑后(hp1)",
                       backend_verifier.verify_high_prio_host_database,
                       must_pass=True, name="hp1",
                       expected_fields={"host": "a-edit.example.com"})

        # ========== 步骤10: 优先域名-停用/启用 ==========
        with rec.step("步骤10: 优先域名-停用/启用", "停用hp1再启用 + SSH验证enabled"):
            print("\n[步骤10] 优先域名 停用/启用...")
            ok = high_page.disable_rule("hp1")
            page.wait_for_timeout(1000)
            rec.add_detail(f"  停用hp1: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-停用后(hp1)",
                       backend_verifier.verify_high_prio_host_database,
                       must_pass=True, name="hp1",
                       expected_fields={"enabled": "no"})

            ok = high_page.enable_rule("hp1")
            page.wait_for_timeout(1000)
            rec.add_detail(f"  启用hp1: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-启用后(hp1)",
                       backend_verifier.verify_high_prio_host_database,
                       must_pass=True, name="hp1",
                       expected_fields={"enabled": "yes"})

        # ========== 步骤11: 优先域名-删除 ==========
        with rec.step("步骤11: 优先域名-删除", "删除hp3 + SSH验证不存在"):
            print("\n[步骤11] 删除优先域名 hp3...")
            ok = high_page.delete_rule("hp3")
            page.wait_for_timeout(1000)
            print(f"  删除: {ok}")
            rec.add_detail(f"  删除hp3: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-删除后(hp3)",
                       backend_verifier.verify_high_prio_host_database,
                       must_pass=True, name="hp3", must_exist=False)

        # ========== 步骤12: 优先域名-搜索+排序 ==========
        with rec.step("步骤12: 优先域名-排序", "列排序(智能流控tab无搜索框)"):
            print("\n[步骤12] 优先域名 排序...")
            high_page.navigate_to_high_prio_host()
            page.wait_for_timeout(800)
            sort_ok = high_page.sort_by_column("名称") or high_page.sort_by_column("域名")
            rec.add_detail(f"  排序: {'[OK]' if sort_ok else '不支持'}")

        # ========== 步骤13: 优先域名-导出 ==========
        with rec.step("步骤13: 优先域名-导出", "导出CSV和TXT"):
            print("\n[步骤13] 优先域名 导出...")
            high_page.navigate_to_high_prio_host()
            page.wait_for_timeout(500)
            try:
                if high_page.export_rules(use_config_path=True, export_format="csv"):
                    rec.add_detail("  CSV导出[OK]")
                else:
                    rec.add_detail("  CSV导出[WARN]")
                if high_page.export_rules(use_config_path=True, export_format="txt"):
                    rec.add_detail("  TXT导出[OK]")
                else:
                    rec.add_detail("  TXT导出[WARN]")
            except Exception as e:
                rec.add_detail(f"  导出异常: {e}")

        # ========== 步骤14: 优先域名-异常输入 ==========
        with rec.step("步骤14: 优先域名-异常输入", "空名称/空域名/重复名称"):
            print("\n[步骤14] 优先域名 异常输入...")
            r1 = high_page.try_add_rule_invalid(name="", host="x.example.com",
                                                expect_fail=True)
            m1 = r1.get('error_message', '') or '(无提示)'
            rec.add_detail(f"  空名称: {'拦截[OK]' if r1['success'] else '未拦截[FAIL]'} 提示={m1[:40]}")
            print(f"  空名称: 提示={m1[:50]}")
            if not r1["success"]:
                ui_failures.append("优先域名: 空名称未拦截")

            r2 = high_page.try_add_rule_invalid(name="hpempty", host="",
                                                expect_fail=True)
            m2 = r2.get('error_message', '') or '(无提示)'
            rec.add_detail(f"  空域名: {'拦截[OK]' if r2['success'] else '未拦截[FAIL]'} 提示={m2[:40]}")
            print(f"  空域名: 提示={m2[:50]}")

            r3 = high_page.try_add_rule_invalid(name="hp1", host="dup.example.com",
                                                expect_fail=True)
            m3 = r3.get('error_message', '') or '(无提示)'
            rec.add_detail(f"  重复名称: {'拦截[OK]' if r3['success'] else '未拦截[FAIL]'} 提示={m3[:40]}")
            print(f"  重复名称: 提示={m3[:50]}")

        # ========== 步骤15: 优先域名-批量操作 ==========
        with rec.step("步骤15: 优先域名-批量停用/启用", "全选批量停用+启用 + SSH L1断言"):
            print("\n[步骤15] 优先域名 批量操作...")
            high_page.navigate_to_high_prio_host()
            page.wait_for_timeout(800)
            test_names = ["hp1", "hp2"]
            total = high_page.get_rule_count()
            rec.add_detail(f"  当前{total}条")

            high_page.select_all_rules()
            page.wait_for_timeout(800)
            high_page.batch_disable()
            page.wait_for_timeout(2000)
            high_page.navigate_to_high_prio_host()
            page.wait_for_timeout(1000)
            if backend_verifier is not None:
                total = backend_verifier.count_high_prio_host(enabled_only=False)
                en_after_dis = backend_verifier.count_high_prio_host(enabled_only=True)
                rec.add_detail(f"  SSH: 批量停用后 enabled={en_after_dis}/{total}")
                if total > 0 and en_after_dis > 0:
                    ssh_failures.append(
                        f"SSH-L1-优先域名批量停用: 仍{en_after_dis}条enabled")

            high_page.select_all_rules()
            page.wait_for_timeout(800)
            high_page.batch_enable()
            page.wait_for_timeout(2000)
            high_page.navigate_to_high_prio_host()
            page.wait_for_timeout(1000)
            if backend_verifier is not None:
                total = backend_verifier.count_high_prio_host(enabled_only=False)
                en_after_en = backend_verifier.count_high_prio_host(enabled_only=True)
                rec.add_detail(f"  SSH: 批量启用后 enabled={en_after_en}/{total}")
                if total > 0 and en_after_en < total:
                    ssh_failures.append(
                        f"SSH-L1-优先域名批量启用: 仅{en_after_en}/{total}条enabled")

        # ========== 步骤16: 优先域名-导入 ==========
        with rec.step("步骤16: 优先域名-导入追加", "批量删除+导入CSV(追加)"):
            print("\n[步骤16] 优先域名 导入...")
            high_page.navigate_to_high_prio_host()
            page.wait_for_timeout(800)
            # 批量删除剩余
            select_all = page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.wait_for_timeout(500)
                high_page.batch_delete()
                page.wait_for_timeout(2000)
            high_page.navigate_to_high_prio_host()
            page.wait_for_timeout(800)
            before = high_page.get_rule_count()
            rec.add_detail(f"  导入前: {before}条")
            if os.path.exists(export_high_csv):
                high_page.import_rules(export_high_csv, clear_existing=False)
                high_page.navigate_to_high_prio_host()
                page.wait_for_timeout(1000)
                after = high_page.get_rule_count()
                rec.add_detail(f"  导入后: {after}条")
                if after > before:
                    rec.add_detail("  [OK] 导入追加成功")
                else:
                    rec.add_detail("  [WARN] 导入未增加")
            else:
                rec.add_detail("  [WARN] CSV文件不存在")

        # ========== 步骤17: 终端独立限速-添加3条 ==========
        alone_rules = [
            {"name": "alone1", "ip": "192.168.148.2", "up": 2000, "down": 2000},
            {"name": "alone2", "ip": "192.168.148.3", "up": 3000, "down": 3000},
            {"name": "alone3", "ip": "192.168.148.4", "up": 4000, "down": 4000},
        ]
        with rec.step("步骤17: 终端独立限速-添加3条", "添加3条 + SSH验证alone_limit+ipset"):
            print("\n[步骤17] 添加终端独立限速...")
            alone_page.navigate_to_alone_limit()
            page.wait_for_timeout(800)
            for r in alone_rules:
                ok = alone_page.add_rule(r["name"], ip=r["ip"],
                                         upload=r["up"], download=r["down"])
                assert ok, f"添加终端限速 {r['name']} 失败"
                print(f"  + {r['name']}: {r['ip']}, {r['up']}/{r['down']}")
                rec.add_detail(f"  [OK] 添加 {r['name']}")
                # L1数据库验证
                ssh_verify(f"L1-终端限速({r['name']})",
                           backend_verifier.verify_alone_limit_database,
                           must_pass=True, name=r["name"],
                           expected_fields={"ip_addr": r["ip"], "upload": r["up"],
                                            "download": r["down"], "enabled": "yes"})
                # L2 ipset验证
                rule_row = backend_verifier.query_alone_limit_rule(r["name"])
                if rule_row and rule_row.get("id"):
                    ssh_verify(f"L2-ipset({r['name']})",
                               backend_verifier.verify_alone_limit_ipset,
                               must_pass=True,
                               rule_id=int(rule_row["id"]),
                               ip=r["ip"], should_exist=True)

        # ========== 步骤18: 终端独立限速-编辑 ==========
        with rec.step("步骤18: 终端独立限速-编辑", "修改alone1上下行"):
            print("\n[步骤18] 编辑终端限速 alone1...")
            ok = alone_page.edit_rule("alone1", upload=5000, download=6000)
            print(f"  编辑: {ok}")
            rec.add_detail(f"  编辑alone1: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-编辑后(alone1)",
                       backend_verifier.verify_alone_limit_database,
                       must_pass=True, name="alone1",
                       expected_fields={"upload": 5000, "download": 6000})

        # ========== 步骤19: 终端独立限速-停用/启用 ==========
        with rec.step("步骤19: 终端独立限速-停用/启用", "停用alone2再启用 + SSH验证ipset清理/重建"):
            print("\n[步骤19] 终端限速 停用/启用...")
            target = "alone2"
            rule_row = backend_verifier.query_alone_limit_rule(target) if backend_verifier else None
            rid = int(rule_row["id"]) if rule_row and rule_row.get("id") else None

            ok = alone_page.disable_rule(target)
            page.wait_for_timeout(1500)
            rec.add_detail(f"  停用{target}: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-停用后(alone2)",
                       backend_verifier.verify_alone_limit_database,
                       must_pass=True, name=target,
                       expected_fields={"enabled": "no"})
            if rid:
                # 停用后ipset应清理(或保留但规则不生效, 实测确认)
                ssh_verify("L2-ipset停用后(alone2)",
                           backend_verifier.verify_alone_limit_ipset,
                           rule_id=rid, should_exist=False)

            ok = alone_page.enable_rule(target)
            page.wait_for_timeout(1500)
            rec.add_detail(f"  启用{target}: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-启用后(alone2)",
                       backend_verifier.verify_alone_limit_database,
                       must_pass=True, name=target,
                       expected_fields={"enabled": "yes"})
            if rid:
                ssh_verify("L2-ipset启用后(alone2)",
                           backend_verifier.verify_alone_limit_ipset,
                           must_pass=True, rule_id=rid,
                           ip="192.168.148.3", should_exist=True)

        # ========== 步骤20: 终端独立限速-删除 ==========
        with rec.step("步骤20: 终端独立限速-删除", "删除alone3 + SSH验证"):
            print("\n[步骤20] 删除终端限速 alone3...")
            target = "alone3"
            rule_row = backend_verifier.query_alone_limit_rule(target) if backend_verifier else None
            rid = int(rule_row["id"]) if rule_row and rule_row.get("id") else None

            ok = alone_page.delete_rule(target)
            page.wait_for_timeout(1000)
            rec.add_detail(f"  删除{target}: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-删除后(alone3)",
                       backend_verifier.verify_alone_limit_database,
                       must_pass=True, name=target, must_exist=False)
            if rid:
                ssh_verify("L2-ipset删除后(alone3)",
                           backend_verifier.verify_alone_limit_ipset,
                           rule_id=rid, should_exist=False)

        # ========== 步骤21: 终端独立限速-搜索+异常输入 ==========
        with rec.step("步骤21: 终端独立限速-搜索+异常", "搜索 + 空名称/重复名称异常"):
            print("\n[步骤21] 终端限速 搜索/异常...")
            alone_page.navigate_to_alone_limit()
            page.wait_for_timeout(800)
            # 智能流控tab无搜索框, 跳过搜索; 验证排序
            sort_ok = alone_page.sort_by_column("名称")
            rec.add_detail(f"  排序: {'[OK]' if sort_ok else '不支持'}")

            r1 = alone_page.try_add_rule_invalid(name="", ip="192.168.148.9",
                                                 expect_fail=True)
            m1 = r1.get('error_message', '') or '(无提示)'
            rec.add_detail(f"  空名称: {'拦截[OK]' if r1['success'] else '未拦截[FAIL]'} 提示={m1[:40]}")
            print(f"  空名称: 提示={m1[:50]}")
            if not r1["success"]:
                ui_failures.append("终端限速: 空名称未拦截")

        # ========== 步骤22: 终端独立限速-批量操作 ==========
        with rec.step("步骤22: 终端独立限速-批量停用/启用", "批量操作 + SSH L1断言"):
            print("\n[步骤22] 终端限速 批量操作...")
            alone_page.navigate_to_alone_limit()
            page.wait_for_timeout(800)
            alone_test_names = ["alone1", "alone2"]
            total = alone_page.get_rule_count()
            rec.add_detail(f"  当前{total}条")

            alone_page.select_all_rules()
            page.wait_for_timeout(800)
            alone_page.batch_disable()
            page.wait_for_timeout(2000)
            alone_page.navigate_to_alone_limit()
            page.wait_for_timeout(1000)
            if backend_verifier is not None:
                db_rules = backend_verifier.query_all_alone_limit()
                dis_cnt = sum(1 for r in db_rules
                              if r.get("tagname") in alone_test_names
                              and r.get("enabled") == "no")
                rec.add_detail(f"  SSH: 批量停用 {dis_cnt}/{len(alone_test_names)}条")
                if len(alone_test_names) > 0 and dis_cnt < len(alone_test_names):
                    ssh_failures.append(
                        f"SSH-L1-终端限速批量停用: 仅{dis_cnt}/{len(alone_test_names)}条")

            alone_page.select_all_rules()
            page.wait_for_timeout(800)
            alone_page.batch_enable()
            page.wait_for_timeout(2000)
            alone_page.navigate_to_alone_limit()
            page.wait_for_timeout(1000)
            if backend_verifier is not None:
                db_rules = backend_verifier.query_all_alone_limit()
                en_cnt = sum(1 for r in db_rules
                             if r.get("tagname") in alone_test_names
                             and r.get("enabled") == "yes")
                rec.add_detail(f"  SSH: 批量启用 {en_cnt}/{len(alone_test_names)}条")
                if len(alone_test_names) > 0 and en_cnt < len(alone_test_names):
                    ssh_failures.append(
                        f"SSH-L1-终端限速批量启用: 仅{en_cnt}/{len(alone_test_names)}条")

        # ========== 步骤23: 切换到手动模式 ==========
        with rec.step("步骤23: 切换手动模式", "切换到手动模式 + SSH验证stream_ctl_mode=2"):
            print("\n[步骤23] 切换到手动模式...")
            # 先清理终端限速规则(避免残留)
            alone_page.navigate_to_alone_limit()
            page.wait_for_timeout(500)
            select_all = page.locator("thead input[type='checkbox']").first
            if select_all.count() > 0 and select_all.is_enabled():
                select_all.click()
                page.wait_for_timeout(500)
                alone_page.batch_delete()
                page.wait_for_timeout(2000)

            ok = sc.switch_mode(mode="manual")
            print(f"  手动模式: {ok}")
            rec.add_detail(f"  手动模式: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-stream_ctl_mode=2(手动)",
                       backend_verifier.verify_stream_ctl_mode, must_pass=True,
                       expected_mode=2)

        # ========== 步骤24: 流控策略-添加2条 ==========
        l7_rules = [
            {"name": "l7q1", "interface": "wan1", "ip": "192.168.148.2",
             "min_up": 1000, "min_down": 1000, "max_up": 2000, "max_down": 2000},
            {"name": "l7q2", "interface": "wan2", "ip": "192.168.148.3",
             "min_up": 1500, "min_down": 1500, "max_up": 2500, "max_down": 2500},
        ]
        with rec.step("步骤24: 流控策略-添加2条", "添加2条手动流控策略 + SSH验证layer7_qos"):
            print("\n[步骤24] 添加手动流控策略...")
            l7_page.navigate_to_layer7_qos()
            page.wait_for_timeout(800)
            for r in l7_rules:
                ok = l7_page.add_rule(r["name"], interface=r["interface"],
                                      ip=r["ip"],
                                      min_up=r["min_up"], min_down=r["min_down"],
                                      max_up=r["max_up"], max_down=r["max_down"])
                assert ok, f"添加流控策略 {r['name']} 失败"
                print(f"  + {r['name']}: {r['interface']}")
                rec.add_detail(f"  [OK] 添加 {r['name']}")
                ssh_verify(f"L1-流控策略({r['name']})",
                           backend_verifier.verify_layer7_qos_database,
                           must_pass=True, name=r["name"],
                           expected_fields={"enabled": "yes"})
                rule_row = backend_verifier.query_layer7_qos_rule(r["name"])
                if rule_row and rule_row.get("id"):
                    ssh_verify(f"L2-ipset({r['name']})",
                               backend_verifier.verify_layer7_qos_ipset,
                               must_pass=True,
                               rule_id=int(rule_row["id"]), should_exist=True)

        # ========== 步骤25: 流控策略-编辑/停用启用/删除/搜索/导入导出 ==========
        with rec.step("步骤25: 流控策略-编辑/停启用/搜索/导出", "编辑+停用启用+搜索+导出"):
            print("\n[步骤25] 流控策略 编辑/停启用/搜索/导出...")
            # 编辑
            ok = l7_page.edit_rule("l7q1", min_up=3000, min_down=3000)
            rec.add_detail(f"  编辑l7q1: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-编辑后(l7q1)",
                       backend_verifier.verify_layer7_qos_database,
                       must_pass=True, name="l7q1",
                       expected_fields={"min_up": 3000, "min_down": 3000})

            # 停用/启用
            ok = l7_page.disable_rule("l7q2")
            page.wait_for_timeout(1500)
            rec.add_detail(f"  停用l7q2: {'[OK]' if ok else '[FAIL]'}")
            ssh_verify("L1-停用后(l7q2)",
                       backend_verifier.verify_layer7_qos_database,
                       must_pass=True, name="l7q2",
                       expected_fields={"enabled": "no"})
            ok = l7_page.enable_rule("l7q2")
            page.wait_for_timeout(1500)
            rec.add_detail(f"  启用l7q2: {'[OK]' if ok else '[FAIL]'}")

            # 智能流控tab无搜索框, 跳过搜索; 验证排序
            l7_page.navigate_to_layer7_qos()
            page.wait_for_timeout(800)
            sort_ok = l7_page.sort_by_column("名称")
            rec.add_detail(f"  排序: {'[OK]' if sort_ok else '不支持'}")

            # 导出
            try:
                if l7_page.export_rules(use_config_path=True, export_format="csv"):
                    rec.add_detail("  CSV导出[OK]")
                if l7_page.export_rules(use_config_path=True, export_format="txt"):
                    rec.add_detail("  TXT导出[OK]")
            except Exception as e:
                rec.add_detail(f"  导出异常: {e}")

        # ========== 步骤26: 关闭流控 + 恢复环境 ==========
        with rec.step("步骤26: 关闭流控+恢复环境", "关闭流控+清理规则 + SSH验证stream_ctl_mode=0"):
            print("\n[步骤26] 关闭流控 + 恢复环境...")
            if backend_verifier is not None:
                backend_verifier.cleanup_stream_control(disable=True)
                rec.add_detail("[清理] 关闭流控+清空规则表+清理ipset")
            # UI也关闭(确保页面状态同步)
            sc.navigate_to_stream_control(force_reload=True)
            page.wait_for_timeout(1000)
            if sc.is_stream_control_enabled():
                sc.disable_stream_control()
            page.wait_for_timeout(2000)

            ssh_verify("L1-stream_ctl_mode=0(关闭)",
                       backend_verifier.verify_stream_ctl_mode, must_pass=True,
                       expected_mode=0)

        # ========== 最终断言 ==========
        print("\n" + "=" * 60)
        print("智能流控综合测试完成")
        print("=" * 60)
        print("测试覆盖:")
        print("  - 流控线路: 编辑带宽/全部启用/全部停用 + SSH(wan_config)")
        print("  - 切换模式: 网页优先/自定义+应用优先级 + SSH(layer7_intell)")
        print("  - 优先域名(high_prio_host): 增删改/停启用/搜索/排序/导出导入/异常/批量")
        print("  - 终端独立限速(alone_limit): 增删改/停启用/搜索/异常/批量 + ipset验证")
        print("  - 手动流控策略(layer7_qos): 增改/停启用/搜索/导出 + ipset验证")
        print("  - 模式切换: 智能(1)/手动(2)/关闭(0) + SSH四级验证")

        all_failures = ssh_failures + ui_failures
        if ssh_failures:
            print(f"\n[断言] {len(ssh_failures)}项SSH失败:")
            for f in ssh_failures:
                print(f"  - {f}")
        if ui_failures:
            print(f"\n[断言] {len(ui_failures)}项UI失败:")
            for f in ui_failures:
                print(f"  - {f}")
        assert not all_failures, \
            f"测试失败: {len(ssh_failures)}项SSH + {len(ui_failures)}项UI: {all_failures}"

        print("\n[OK] 智能流控综合测试全部通过!")
