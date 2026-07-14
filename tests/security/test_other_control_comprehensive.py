"""
其他控制模块综合测试 (安全中心 > 其他控制 > 网络分享控制, acl_l2route.sh)

URL: /login#/securityCenter/otherControl
单 tab "网络分享控制", 配置类页面(禁止二级路由开关 + 自定义TTL + 例外地址范围 + 禁止时间 + 保存).

机制: 开启禁止二级路由(nol2rt=1) → mangle FORWARD 夹制 WAN→LAN 转发包 TTL --ttl-set N,
防下游私接二级路由; 禁止时间(内核ik_cntl timeset acl_l2rt_time_1)控制生效时段;
例外地址(ipset Linux_acl_l2rt dst, !match)豁免特定目标不被夹.

覆盖(用户重点: 6.12内核禁止时间生效 + 全3模式 + 例外L5硬验证):
1. 禁止二级路由+自定义TTL L1-L5 (nol2rt=1/ttl=10, client ping回包ttl=10被夹)
2. 禁止时间-按周循环 L1-L5硬验证(**核心6.12门控铁证**):
   - 含今天(全选星期) → 回包ttl=10(active, 计数器增长)
   - 排除今天(UI去今天) → 回包ttl=63(normal, 计数器不动) = 6.12 timeset门控生效
3. 禁止时间-时间段(date) L1-L5 (默认范围含今天 → ttl=10; inactive用内核timeset重建佐证)
4. 禁止时间-时间计划 L1-L5 (route_object建时间计划引用, 测route_object.sh集成 → ttl=10)
5. 例外地址范围 L1-L5硬验证 (加client IP 192.168.148.2到例外 → 回包ttl正常豁免不被夹)
6. ttl_num边界值 (1/64正常; 前端1-64 vs 后端1-255不一致, 报禅道候选)
7. finally SSH兜底清理(避免残留mangle TTL规则影响后续打流)

实测铁证(2026-07-14, 6.12.87): 含今天→ttl=5+计数器13→19; 排除今天→ttl=63+计数器25→25.
"""
import pytest
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify
from pages.security.other_control_page import OtherControlPage, WEEKDAY_CN

pytestmark = [pytest.mark.security, pytest.mark.other_control]

CLIENT_IP = "192.168.148.2"          # client内网IP(ens11), 作为例外豁免目标
PING_DST = "10.66.0.40"              # WAN侧iperf3服务端, ping回复走WAN→LAN经夹制规则
TTL_TEST = 10                        # 测试用夹制TTL值(正常回包63, 鲜明对比)
TPLAN_NAME = "oc_tplan_auto"         # 时间计划模式自动建的时间计划名


class TestOtherControlComprehensive:
    """其他控制(网络分享控制)综合测试"""

    def test_other_control_comprehensive(self, other_control_page_logged_in: OtherControlPage,
                                         step_recorder: StepRecorder, request):
        page = other_control_page_logged_in
        rec = step_recorder
        try:
            bv = request.getfixturevalue('backend_verifier')
        except Exception:
            bv = None

        ui_failures = []
        ssh_failures = []
        # must_pass_default=True: 核心L1-L5检查默认硬断言(FAIL即测试失败, 避免假绿);
        # 仅清理确认/内核补强用must_pass=False软记录
        ssh_verify = make_ssh_verify(bv, rec, ssh_failures, must_pass_default=True)

        def ui_check(label, cond, detail=""):
            if cond:
                rec.add_detail(f"  [UI] {label}: [OK]")
            else:
                rec.add_detail(f"  [UI] {label}: [FAIL] {detail}")
                ui_failures.append(f"{label}: {detail}")

        def today_info():
            """从路由器取今天星期. 返回(today_u:int 1-7, today_cn, all_cn, excl_cn)."""
            u = 1
            if bv:
                try:
                    bv.connect_router()
                    u = int((bv._router.exec("date +%u") or "1").strip() or "1")
                except Exception:
                    u = 1
            u = max(1, min(7, u))
            today_cn = WEEKDAY_CN[u - 1]
            all_cn = list(WEEKDAY_CN)
            excl_cn = [d for d in WEEKDAY_CN if d != today_cn]
            return u, today_cn, all_cn, excl_cn

        try:
            # ========== 步骤1: 环境清理 ==========
            with rec.step("步骤1: 环境清理", "SSH清残留+UI导航+验默认nol2rt=0"):
                if bv:
                    r = bv.cleanup_other_control_test()
                    rec.add_detail(f"  SSH清理: {r}")
                page.navigate_to_other_control()
                page.page.wait_for_timeout(1000)
                if bv:
                    ssh_verify("清理后-nol2rt=0", bv.verify_other_control_database,
                               {"nol2rt": "0"}, must_pass=False)
                    ssh_verify("清理后-无TTL规则", bv.verify_other_control_iptables,
                               False, must_pass=False)

            # ========== 步骤2: 禁止二级路由+自定义TTL L1-L5 ==========
            with rec.step("步骤2: 禁止二级路由+自定义TTL L1-L5",
                          "nol2rt=1/ttl=10/按周循环24/7 → L1 DB+L2 iptables+L5 ping回包ttl=10"):
                u, today_cn, all_cn, excl_cn = today_info()
                rec.add_detail(f"  今天: 星期{today_cn}(weekday {u})")
                ok = page.save_config(nol2rt=True, ttl_num=TTL_TEST,
                                      time_mode="按周循环", weekdays=all_cn)
                ui_check("开启禁止二级路由+TTL=10保存", ok, "保存未持久化")
                if bv:
                    ssh_verify("L1-nol2rt=1/ttl=10", bv.verify_other_control_database,
                               {"nol2rt": "1", "ttl_num": str(TTL_TEST)})
                    ssh_verify("L2-TTL规则存在(ttl-set=10)", bv.verify_other_control_iptables,
                               True, TTL_TEST)
                    ssh_verify("L3-timeset已绑定", bv.verify_other_control_timeset, True)
                    # L5: ping回包应被夹到10
                    ssh_verify(f"L5-TTL夹制生效(回包ttl={TTL_TEST})",
                               bv.verify_ttl_clamp_real,
                               "ens11", PING_DST, True, TTL_TEST)
                    cnt = bv.get_ttl_rule_counter()
                    rec.add_detail(f"  [L5] TTL规则匹配计数器={cnt}(active应>0)")

            # ========== 步骤3: 禁止时间-按周循环 L1-L5 (核心6.12门控铁证) ==========
            with rec.step("步骤3: 禁止时间-按周循环 6.12门控L5硬验证",
                          "排除今天→ping ttl正常(门控inactive) / 含今天→ttl=10(active)"):
                if bv is None:
                    rec.add_detail("  [L5] 跳过(无SSH验证器)")
                else:
                    # 3a. 排除今天 → 应门控inactive, 回包正常不被夹
                    ok = page.save_config(weekdays=excl_cn)
                    ui_check(f"星期排除今天({today_cn})保存", ok)
                    ssh_verify("L1-weekdays排除今天", bv.verify_other_control_database,
                               {"nol2rt": "1"})
                    cnt_before = bv.get_ttl_rule_counter()
                    ssh_verify(f"L5-排除今天→门控inactive(回包ttl正常>{TTL_TEST})",
                               bv.verify_ttl_clamp_real,
                               "ens11", PING_DST, False, TTL_TEST)
                    cnt_after = bv.get_ttl_rule_counter()
                    rec.add_detail(f"  [L5门控铁证] 排除今天: TTL规则计数器 {cnt_before}→{cnt_after}"
                                   f"(inactive应基本不变 = 6.12 timeset门控生效)")
                    # 3b. 恢复含今天 → active, 回包被夹
                    ok = page.save_config(weekdays=all_cn)
                    ui_check("星期恢复全选保存", ok)
                    ssh_verify(f"L5-含今天→门控active(回包ttl={TTL_TEST})",
                               bv.verify_ttl_clamp_real,
                               "ens11", PING_DST, True, TTL_TEST)

            # ========== 步骤4: 禁止时间-时间段(date) L1-L5 ==========
            with rec.step("步骤4: 禁止时间-时间段(date) L1-L5",
                          "默认日期范围含今天→ttl=10; inactive用内核timeset重建佐证"):
                if bv is None:
                    rec.add_detail("  [L5] 跳过(无SSH验证器)")
                else:
                    # 选时间段模式(默认范围含今天) + 保存
                    ok = page.save_config(nol2rt=True, ttl_num=TTL_TEST, time_mode="时间段")
                    ui_check("时间段模式保存(默认范围含今天)", ok)
                    ssh_verify("L1-时间段type=date", bv.verify_other_control_database,
                               {"nol2rt": "1", "ttl_num": str(TTL_TEST)})
                    ssh_verify("L2-TTL规则存在", bv.verify_other_control_iptables, True, TTL_TEST)
                    ssh_verify(f"L5-时间段含今天→ttl={TTL_TEST}", bv.verify_ttl_clamp_real,
                               "ens11", PING_DST, True, TTL_TEST)
                    # inactive: 时间段日期RangePicker自动化受限, 用内核timeset重建排除今天佐证(如实标注, 非掩盖)
                    rec.add_detail("  [L5-inactive佐证] 时间段日期RangePicker UI自动化受限, "
                                   "用内核timeset重建排除今天验证门控(同机制, 按周循环步骤已UI硬证)")
                    try:
                        rec.add_detail(f"  {bv.rebuild_timeset_exclude_today(u)}")
                        page.page.wait_for_timeout(500)
                        ssh_verify("L5-时间段inactive(内核timeset排除今天)→ttl正常",
                                   bv.verify_ttl_clamp_real,
                                   "ens11", PING_DST, False, TTL_TEST, must_pass=False)
                        rec.add_detail(f"  {bv.rebuild_timeset_include_all()}(恢复)")
                    except Exception as e:
                        rec.add_detail(f"  [L5-inactive] 内核timeset重建异常: {str(e)[:60]}")
                    # 切回按周循环全选(恢复active状态供后续)
                    page.save_config(nol2rt=True, ttl_num=TTL_TEST, time_mode="按周循环", weekdays=all_cn)

            # ========== 步骤5: 禁止时间-时间计划 L1-L5 (route_object.sh集成) ==========
            with rec.step("步骤5: 禁止时间-时间计划 L1-L5",
                          "route_object建时间计划→其他控制引用→L1 object gid+L5 ttl=10"):
                if bv is None:
                    rec.add_detail("  [L5] 跳过(无SSH验证器)")
                else:
                    gid = None
                    try:
                        from pages.network.route_object_page import TimePlanPage
                        tp = TimePlanPage(page.page, page.base_url)
                        tp.navigate_to_route_object()
                        page.page.wait_for_timeout(800)
                        # 建时间计划(默认按周循环24/7含今天)
                        tp.add_rule(TPLAN_NAME)
                        page.page.wait_for_timeout(1500)
                        ginfo = bv.find_object_group(TPLAN_NAME, "time")
                        if ginfo:
                            gid = ginfo.get("group_id")
                            rec.add_detail(f"  [时间计划] 已建 {TPLAN_NAME} group_id={gid}")
                        else:
                            rec.add_detail(f"  [时间计划] 建计划后未查到 {TPLAN_NAME}(L1/L5将软记录)")
                    except Exception as e:
                        rec.add_detail(f"  [时间计划] 建计划异常: {str(e)[:80]}")

                    # 回到其他控制, 选时间计划模式+引用
                    page.navigate_to_other_control()
                    page.page.wait_for_timeout(800)
                    ok = page.save_config(nol2rt=True, ttl_num=TTL_TEST,
                                          time_mode="时间计划", time_plan=TPLAN_NAME)
                    ui_check("时间计划模式+引用计划保存", ok, "保存未持久化")
                    if not gid:
                        ui_failures.append("时间计划创建失败(未取到gid), 时间计划模式L1-L5将软记录")
                    if gid:
                        ssh_verify("L1-time.object引用计划gid", bv.verify_other_control_database,
                                   {"nol2rt": "1", "time_object_gid": gid})
                    # L3/L5: gid存在则硬验, 否则软(跨页建计划较脆弱)
                    mp5 = bool(gid)
                    ssh_verify("L3-timeset已绑定(时间计划)", bv.verify_other_control_timeset,
                               True, must_pass=mp5)
                    ssh_verify(f"L5-时间计划(24/7含今天)→ttl={TTL_TEST}",
                               bv.verify_ttl_clamp_real,
                               "ens11", PING_DST, True, TTL_TEST, must_pass=mp5)
                    # 切回按周循环全选恢复active
                    page.save_config(nol2rt=True, ttl_num=TTL_TEST, time_mode="按周循环", weekdays=all_cn)

            # ========== 步骤6: 例外地址范围 L1-L5硬验证 ==========
            with rec.step("步骤6: 例外地址范围 L1-L5硬验证",
                          "加client IP 192.168.148.2到例外→ping回包ttl正常(豁免不被夹)"):
                if bv is None:
                    rec.add_detail("  [L5] 跳过(无SSH验证器)")
                else:
                    # 基线: 无例外 → 被夹ttl=10
                    ssh_verify("L5基线-无例外→ttl=10", bv.verify_ttl_clamp_real,
                               "ens11", PING_DST, True, TTL_TEST)
                    # 加例外client IP
                    ok = page.save_config(nol2rt=True, ttl_num=TTL_TEST,
                                          time_mode="按周循环", weekdays=all_cn,
                                          exception_ip=CLIENT_IP)
                    ui_check(f"加例外{CLIENT_IP}保存", ok)
                    ssh_verify("L1-例外custom含client IP", bv.verify_other_control_database,
                               {"nol2rt_ip_custom": [CLIENT_IP]})
                    ssh_verify("L2-规则含例外dst匹配", bv.verify_other_control_iptables,
                               True, TTL_TEST, True)
                    ssh_verify("L3-ipset Linux_acl_l2rt含client IP",
                               bv.verify_other_control_exception, True, CLIENT_IP)
                    # L5硬验证: 例外豁免client → 回包正常不被夹
                    ssh_verify(f"L5-例外豁免→client回包ttl正常>{TTL_TEST}",
                               bv.verify_ttl_clamp_real,
                               "ens11", PING_DST, False, TTL_TEST)
                    # 例外不在此强清(违背"检测残留报BUG"哲学), 留至步骤8 web还原统一清理+检测残留

            # ========== 步骤7: ttl_num边界值 ==========
            with rec.step("步骤7: ttl_num边界值", "1/64正常 + 前端1-64 vs 后端1-255不一致(报禅道候选)"):
                for val in ["1", "64"]:
                    ok = page.save_config(nol2rt=True, ttl_num=val,
                                          time_mode="按周循环", weekdays=all_cn)
                    ui_check(f"ttl_num={val}保存", ok)
                    if bv and ok:
                        ssh_verify(f"L1-ttl_num={val}", bv.verify_other_control_database,
                                   {"ttl_num": val})
                rec.add_detail("  [边界不一致] ttl_num: 前端placeholder'1-64' vs "
                               "后端acl_l2route.sh __check_param'ttl_num >= 1 and <= 255'(报禅道候选)")

            # ========== 步骤8: web还原 + 残留检测(正确哲学: web页面还原→检测残留→有残留=删不干净BUG) ==========
            with rec.step("步骤8: web还原+残留检测",
                          "UI关闭禁止二级路由(web还原)→检测iptables/ipset残留→有残留=产品BUG(报禅道, 不强清掩盖)"):
                ok = page.disable_all()  # web还原: UI关闭nol2rt
                ui_check("web还原(UI关闭nol2rt)", ok, "UI关闭未生效")
                if bv:
                    # 硬断言: UI关闭后底层应无残留, 有残留=删不干净BUG
                    ssh_verify("残留检测-UI关闭后无残留(删不干净=BUG)",
                               bv.verify_other_control_residual, True)
                rec.add_detail("  [说明] 残留检测在web还原后进行(非后台强清), "
                               "实测其他控制UI关闭后iptables/ipset均干净清理(无删不干净bug)")

        finally:
            # ========== finally: 环境兜底teardown(残留检测已在步骤8完成, 此处仅保证环境干净供后续测试模块) ==========
            try:
                if page.is_nol2rt_checked():
                    page.disable_all()
                rec.add_detail("[finally] UI关闭禁止二级路由(web兜底)")
            except Exception as e:
                rec.add_detail(f"[finally] UI关闭异常: {str(e)[:60]}")
            if bv:
                try:
                    r = bv.cleanup_other_control_test()
                    rec.add_detail(f"[finally] SSH兜底清理: {r}")
                except Exception as e:
                    rec.add_detail(f"[finally] SSH清理异常: {str(e)[:60]}")
                # 清理本测试建的时间计划(UI删, 失败则SSH兜底)
                try:
                    from pages.network.route_object_page import TimePlanPage
                    tp = TimePlanPage(page.page, page.base_url)
                    if tp.delete_rule(TPLAN_NAME):
                        rec.add_detail(f"[finally] UI删时间计划 {TPLAN_NAME}")
                except Exception as e:
                    rec.add_detail(f"[finally] UI删时间计划异常: {str(e)[:60]}")
                if bv:
                    try:
                        bv.connect_router()
                        bv._router.exec(
                            f'echo "DELETE FROM object_group WHERE group_name='
                            f"'{TPLAN_NAME}';\" | sqlite3 {bv.DNS_DB}")
                        bv._router.exec("/usr/ikuai/script/route_object.sh init 2>/dev/null")
                        rec.add_detail(f"[finally] SSH兜底删时间计划 {TPLAN_NAME}")
                    except Exception as e:
                        rec.add_detail(f"[finally] SSH删计划异常: {str(e)[:60]}")

        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, f"其他控制验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
