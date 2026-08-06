"""网络配置-SD-WAN 综合测试用例

SD-WAN 是**云端主导**功能(被测设备 10.66.0.45): 路由器侧 SD-WAN 页是状态/开通页,
组网成员增删发生在爱快云(business/sd/group/update)。本测试覆盖全链路:
1.  环境准备: 确保绑云(复用云服务绑定) + ICC 登录 + 选可用组网 + 清理残留成员
2.  未开通态: 路由器 SD-WAN 页"立即开通" + 底层 ik_web_sdwan.token 空
3.  立即开通: 点"立即开通"跳云控制台(若有) + 页面状态
4.  云端加成员: business/sd/group/update 加入本机 GWID -> 云端+路由器 local_list+页面 三方铁证
5.  云端删成员: 移出 -> 三方验证还原
6.  异常路径: 重复加成员/空成员等云端拦截
7.  清理: 确保成员移除 + (本用例绑定的)解绑设备

底层脚本 /usr/ikuai/script/ik_web_sdwan.sh; 云端 utils/icc_cloud.py。
云端成员增删是真实云操作(动到账号下组网成员), finally 兜底移除成员 + 解绑还原。
命令记录: 云端操作记为可复制 curl 卡(响应入 actual), 路由器 SSH 走 mark_io 附真实输出。
"""
import json
import time

import pytest

from utils.step_recorder import StepRecorder, register_sensitive_value
from utils.verify_helper import make_ssh_verify
from utils.icc_cloud import IccCloudHelper
from pages.device_setting.cloud_service_binding_page import CloudServiceBindingPage

pytestmark = [pytest.mark.network, pytest.mark.sdwan]

ICC_ACCOUNT = "sxrong@ikuai8.com"
ICC_PASSWORD = "rsx890426"
# 绑云前置: 复用"云服务绑定"绑定码(若设备已绑云则跳过)。bind code 可在 ICC 云端生成。
BIND_CODE = "1190bc8d1bf05eba3016e1e1615f515e"
TEST_COMMENT = "autotest_sdwan"
ROUTER_HOST = "10.66.0.45"


def _cloud_curl(method: str, path: str, params: dict = None, body: dict = None) -> str:
    """构造可复制的云端 curl 串(token 用 <token> 占位, 避免泄漏/过期)。"""
    url = "https://yun.ikuai8.com/api/v3/" + path.lstrip("/")
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    parts = [
        f"curl '{url}'",
        "-X " + method.upper(),
        "-H 'Authorization: Bearer <token>'",
        "-H 'Content-Type: application/json'",
        "-H 'Referer: https://icc.ikuai8.com/'",
        "-s",
    ]
    if body is not None:
        parts.append(f"--data '{json.dumps(body, ensure_ascii=False)}'")
    return " \\\n  ".join(parts)


@pytest.mark.network
@pytest.mark.sdwan
class TestSdwanComprehensive:
    """网络配置-SD-WAN 综合测试 - 一次测试覆盖云端组网全链路"""

    def test_sdwan_comprehensive(
        self, sdwan_page_logged_in, step_recorder: StepRecorder, request
    ):
        """综合测试: 绑云 -> 未开通态 -> 立即开通 -> 云端加成员 -> 云端删成员 -> 异常 -> 清理解绑"""
        page = sdwan_page_logged_in  # SdwanPage
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        register_sensitive_value(ICC_PASSWORD)
        register_sensitive_value(BIND_CODE)

        ssh_failures = []
        ui_failures = []
        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        # 云端助手(借用被测页面 context 新开 page 登录 ICC, 不干扰路由器页面)
        icc = IccCloudHelper(page.page, account=ICC_ACCOUNT, password=ICC_PASSWORD)
        # 云服务绑定页(绑云前置/解绑, 复用现成实现)
        bind_page = CloudServiceBindingPage(page.page, page.base_url)

        # ---- 记录辅助: 云端 curl+响应 / 路由器 SSH+真实输出 ----
        def rec_cloud(label, result, curl_str, purpose, must_pass=True, write=False):
            """记录云端操作 curl 卡(响应入 actual) + 判定。"""
            raw = result.get("raw") if isinstance(result, dict) else result
            actual = json.dumps(raw, ensure_ascii=False)[:500] if raw else json.dumps(result, ensure_ascii=False)[:500]
            rec.add_verification_command(
                command=curl_str, target_label="云端", target="cloud", host="yun.ikuai8.com",
                shell="curl", purpose=purpose, expected="code:2000/0",
                actual=actual, effect="write" if write else "read_only",
                copy_ready=True, valid_when="对应步骤执行时(token 需替换为有效值)",
            )
            ok = bool(isinstance(result, dict) and result.get("ok"))
            rec.add_detail(
                f"  【云端】{label}: {'[OK]' if ok else '[FAIL]'} "
                f"code={result.get('code') if isinstance(result, dict) else '?'} "
                f"msg={result.get('message') if isinstance(result, dict) else ''}"
            )
            if must_pass and not ok:
                ssh_failures.append(f"云端-{label}: {result.get('message') if isinstance(result, dict) else result}")
            return ok

        def rec_ssh(label, verify_func, purpose, must_pass=True):
            """路由器 SSH 验证 + mark_io 捕获真实命令输出, 记为可复制命令卡。"""
            if backend_verifier is None:
                rec.add_detail(f"  【后端】{label}: 跳过(无 SSH)")
                return None
            mark = backend_verifier.mark_io_start()
            try:
                result = verify_func()
            except Exception as e:
                rec.add_detail(f"  【后端】{label}: 异常 {str(e)[:80]}")
                if must_pass:
                    ssh_failures.append(f"SSH-{label}: 异常 {str(e)[:60]}")
                return None
            for p in backend_verifier.collect_io_since_mark(mark):
                rec.add_verification_command(
                    command=p.get("command", ""), target_label="路由器",
                    target=p.get("role", "router"), host=ROUTER_HOST, shell="sh",
                    purpose=purpose, expected="见步骤预期",
                    actual=(p.get("output") or "")[:600],
                    effect="read_only", copy_ready=True, valid_when="对应步骤完成后、清理前",
                )
            passed = bool(getattr(result, "passed", False))
            rec.add_detail(f"  【后端】{label}: {'[OK]' if passed else '[FAIL]'} {getattr(result, 'message', '')}")
            if must_pass and not passed:
                ssh_failures.append(f"SSH-{label}: {getattr(result, 'message', '')}")
            return result

        icc_token = None
        gwid = ""
        sdwan_id = None
        group_id = None
        group_meta = {}          # {group_name, topology_type, layer2_network, access_type, ...}
        existing_members = []    # 加成员前的原始成员(还原用)
        bound_by_us = False      # 是否由本用例完成绑云(finally 决定是否解绑)

        try:
            # ========== 步骤0: 环境准备 ==========
            with rec.step("步骤0: 环境准备", "读GWID, 确保绑云, ICC登录, 选可用组网, 清理残留成员"):
                if backend_verifier is not None:
                    gwid = backend_verifier.get_gwid()
                rec.add_detail(f"  设备 GWID: {gwid}")
                if not gwid:
                    ui_failures.append("环境: 未取到设备 GWID")

                # ICC 登录(带重试应对滑块风控)
                try:
                    icc_token = icc.login(max_retries=3)
                    rec.add_detail(f"  ICC 登录获取 token: {'成功' if icc_token else '失败'}")
                except Exception as e:
                    rec.add_detail(f"  ICC 登录异常: {str(e)[:80]}")
                if not icc_token:
                    ssh_failures.append("环境: ICC 登录失败, 无法进行云端操作")

                # 确保绑云(未绑则用云服务绑定 bind_via_code)
                if backend_verifier is not None:
                    reg = backend_verifier.find_register()
                    rec.add_detail(f"  当前 register 表: {reg}")
                    already_bound = bool(reg and (reg.get("code") or "").strip())
                    if not already_bound:
                        rec.add_detail("  [环境] 设备未绑云, 用云服务绑定(绑定码)绑云")
                        if bind_page.navigate_to_cloud_service_binding():
                            r = bind_page.bind_via_code(BIND_CODE, TEST_COMMENT)
                            rec.add_detail(
                                f"    绑云: clicked={r.get('clicked')} api_success={r.get('api_success')} "
                                f"code={r.get('api_code')} msg={r.get('message')}"
                            )
                            if r.get("api_success"):
                                bound_by_us = True
                                # 等 register_status=1(异步, SD-WAN 页据它判断绑云态, 不等会显示"立即开通")
                                backend_verifier.wait_register_status("1", timeout=15)
                                rec.add_detail(f"    register_status={backend_verifier.read_register_status()}(期望1)")
                            else:
                                ui_failures.append(f"环境: 绑云失败({r.get('message') or r.get('error_toast')}), 后续SD-WAN操作可能受限")
                        else:
                            ui_failures.append("环境: 无法导航到云服务绑定页")
                    else:
                        rec.add_detail("  [环境] 设备已绑云, 跳过绑云")

                # SD-WAN 是否开通 + 列组网 + 选可用网络
                if icc_token:
                    opened = icc.is_sdwan_opened()
                    rec_cloud("账号SD-WAN是否开通", opened,
                              _cloud_curl("get", "sdwan/isOpened"),
                              "查询账号是否开通 SD-WAN", must_pass=False)
                    pick = icc.pick_usable_network(gwid) if gwid else {"ok": False}
                    rec.add_detail(f"  选网结果: {pick}")
                    if pick.get("ok"):
                        sdwan_id = pick.get("sdwan_id")
                        rec.add_detail(f"  选定网络: sdwan_id={sdwan_id} name={pick.get('sdwan_name')} "
                                       f"路由{pick.get('used_router_num')}/{pick.get('router_num')}")
                    else:
                        ssh_failures.append(f"环境: 无可用 SD-WAN 网络({pick.get('message')})")

                    if sdwan_id:
                        g = icc.get_default_group(sdwan_id)
                        rec_cloud(f"网络{sdwan_id}默认分组", g,
                                  _cloud_curl("get", "business/sd/network/show", params={"sdwan_id": sdwan_id}),
                                  "取网络默认分组与成员", must_pass=True)
                        if g.get("ok"):
                            group_id = g.get("group_id")
                            existing_members = g.get("members") or []
                            group_meta = {
                                "group_name": g.get("group_name") or "默认分组",
                                "topology_type": g.get("topology_type", 1),
                                "layer2_network": g.get("layer2_network", 0),
                            }
                            rec.add_detail(f"  分组: group_id={group_id} name={group_meta['group_name']} 现有成员{len(existing_members)}个")
                            # 若本机已在成员(残留), 先移除还原到干净态
                            if gwid and any(str(m.get("id")) == str(gwid) for m in existing_members):
                                rec.add_detail("  [清理] 本机已在分组(残留), 先移除还原")
                                rm = icc.remove_sdwan_member(
                                    sdwan_id, group_id, gwid, existing_members,
                                    token=icc_token, **group_meta)
                                rec_cloud("清理残留成员", rm,
                                          _cloud_curl("post", "business/sd/group/update",
                                                      body={"sdwan_id": sdwan_id, "group_id": group_id,
                                                            "members": [{"id": m["id"]} for m in existing_members
                                                                        if str(m.get("id")) != str(gwid)]}),
                                          "移出残留成员还原干净态", must_pass=False, write=True)
                                time.sleep(2)
                                existing_members = [m for m in existing_members
                                                    if str(m.get("id")) != str(gwid)]

            # ========== 步骤1: 未开通态 ==========
            with rec.step("步骤1: 未开通态验证", "路由器SD-WAN页'立即开通' + ik_web_sdwan.token 空 + 未加入组网"):
                page.navigate_to_sdwan()
                page.page.wait_for_timeout(800)
                not_act = page.is_not_activated()
                rec.add_detail(f"  路由器SD-WAN页 未开通态('立即开通'按钮存在): {not_act}")
                txt = page.read_main_text()[:160].replace("\n", " ")
                rec.add_detail(f"  页面文本摘要: {txt}")
                if backend_verifier is not None:
                    rec_ssh("ik_web_sdwan.token 空", backend_verifier.verify_sdwan_token_empty,
                            "查 SD-WAN token 文件是否为空(未开通)", must_pass=False)
                    rec_ssh("本设备未加入组网", backend_verifier.verify_sdwan_device_not_in_network,
                            "local_list 查本设备是否未加入任何组网", must_pass=False)

            # ========== 步骤2: 立即开通 + 查看更多 ==========
            with rec.step("步骤2: 立即开通 + 查看更多", "点'立即开通'(开云控制台); 验证'查看更多'外链; token 状态"):
                page.navigate_to_sdwan()
                page.page.wait_for_timeout(500)
                if page.is_not_activated():
                    clicked = page.click_activate()
                    rec.add_detail(f"  点'立即开通': {clicked}")
                    page.page.wait_for_timeout(1200)
                    # 关闭可能新开的云控制台标签页
                    try:
                        for p_extra in list(page.page.context.pages)[1:]:
                            p_extra.close()
                    except Exception:
                        pass
                else:
                    rec.add_detail("  页面无'立即开通'(可能已开通态), 跳过点击")

                # "查看更多"外链(产品介绍页 https://www.ikuai8.com/netWork.php)
                vm_href = page.get_view_more_url()
                rec.add_detail(f"  '查看更多'链接href: {vm_href}")
                if "ikuai8.com/netWork" not in vm_href and "netWork.php" not in vm_href:
                    ui_failures.append(f"步骤2: '查看更多'链接异常(href={vm_href})")
                if page.has_view_more():
                    opened = page.click_view_more()
                    rec.add_detail(f"  点'查看更多'打开: {opened}")
                    if opened and "netWork" not in opened:
                        ui_failures.append(f"步骤2: '查看更多'打开页异常(url={opened})")
                    # 关闭新开的外链标签页
                    try:
                        for p_extra in list(page.page.context.pages)[1:]:
                            p_extra.close()
                    except Exception:
                        pass

                # token 状态(走 rec_ssh 带复制按钮命令卡)
                if backend_verifier is not None:
                    rec_ssh("ik_web_sdwan.token 状态", backend_verifier.verify_sdwan_token_empty,
                            "查 SD-WAN token 文件状态", must_pass=False)

            # ========== 步骤3: 云端加成员(核心) ==========
            with rec.step("步骤3: 云端加成员", "business/sd/group/update 加入本机GWID -> 云端+路由器local_list铁证"):
                if not (icc_token and sdwan_id and group_id and gwid):
                    rec.add_detail("  [跳过] 前置不全(ICC/网络/分组/GWID), 无法加成员")
                    ssh_failures.append("步骤3: 前置不全, 未执行加成员")
                else:
                    # 取最新成员(GET-then-update, 不扰动其它成员)
                    g = icc.get_default_group(sdwan_id, token=icc_token)
                    cur_members = g.get("members") if g.get("ok") else existing_members
                    add_body_members = [{"id": m.get("id")} for m in cur_members] + [{"id": gwid}]
                    res = icc.add_sdwan_member(
                        sdwan_id, group_id, gwid, cur_members,
                        token=icc_token, **group_meta)
                    rec_cloud(
                        f"加入成员{gwid[:8]}..", res,
                        _cloud_curl("post", "business/sd/group/update",
                                    body={"sdwan_id": sdwan_id, "group_id": group_id,
                                          "members": add_body_members, **group_meta}),
                        "把本机GWID加入默认分组", must_pass=True, write=True,
                    )
                    # 轮询: 云端 member_in_group + 路由器 local_list
                    ok_cloud = False
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        chk = icc.member_in_group(sdwan_id, gwid, token=icc_token)
                        if chk.get("in_group"):
                            ok_cloud = True
                            break
                        time.sleep(2)
                    rec.add_detail(f"  云端确认成员已加入: {ok_cloud}")
                    if not ok_cloud:
                        ssh_failures.append("步骤3: 云端轮询未确认成员加入")
                    # 路由器 local_list 铁证(轮询等反映, 云端确认后 local_list 可能略延迟)
                    if backend_verifier is not None:
                        _dl = time.time() + 25
                        while time.time() < _dl:
                            if backend_verifier.verify_sdwan_device_in_network().passed:
                                break
                            time.sleep(2)
                    rec_ssh("本设备已加入组网(local_list)", backend_verifier.verify_sdwan_device_in_network,
                            "local_list 查本设备是否已加入云端组网", must_pass=True)
                    # UI 反映(主验证): 路由器SD-WAN页展示组网名称/成员(绑云+加入网络即呈现, 无需SMS开通)
                    # ⚠ 用 reload() 强制刷新: goto 同 hash URL 不触发 SPA 重载, 页面会停在旧态
                    shown = False
                    net_name = ""
                    page.navigate_to_sdwan()
                    _dl_ui = time.time() + 40
                    while time.time() < _dl_ui:
                        try:
                            page.page.reload(wait_until="domcontentloaded")
                            try:
                                page.page.wait_for_load_state("networkidle", timeout=8000)
                            except Exception:
                                pass
                            page.page.wait_for_timeout(2500)
                        except Exception:
                            pass
                        if page.has_network_display():
                            shown = True
                            net_name = page.read_network_name()
                            break
                        time.sleep(1)
                    rec.add_detail(f"  【页面】路由器SD-WAN页展示组网: {'[OK]' if shown else '[FAIL]'} "
                                   f"名称={net_name} 成员={page.read_member_count_display()}")
                    if not shown:
                        ui_failures.append("步骤3: 路由器SD-WAN页未展示组网(期望显示组网名称/成员)")

            # ========== 步骤4: 云端删成员 ==========
            with rec.step("步骤4: 云端删成员", "移出本机GWID -> 云端+路由器local_list验证还原"):
                if not (icc_token and sdwan_id and group_id and gwid):
                    rec.add_detail("  [跳过] 前置不全, 无法删成员")
                else:
                    g = icc.get_default_group(sdwan_id, token=icc_token)
                    cur_members = g.get("members") if g.get("ok") else []
                    del_body_members = [{"id": m.get("id")} for m in cur_members
                                        if str(m.get("id")) != str(gwid)]
                    res = icc.remove_sdwan_member(
                        sdwan_id, group_id, gwid, cur_members,
                        token=icc_token, **group_meta)
                    rec_cloud(
                        f"移出成员{gwid[:8]}..", res,
                        _cloud_curl("post", "business/sd/group/update",
                                    body={"sdwan_id": sdwan_id, "group_id": group_id,
                                          "members": del_body_members, **group_meta}),
                        "把本机GWID移出默认分组", must_pass=True, write=True,
                    )
                    ok_gone = False
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        chk = icc.member_in_group(sdwan_id, gwid, token=icc_token)
                        if not chk.get("in_group"):
                            ok_gone = True
                            break
                        time.sleep(2)
                    rec.add_detail(f"  云端确认成员已移出: {ok_gone}")
                    if not ok_gone:
                        ssh_failures.append("步骤4: 云端轮询未确认成员移出")
                    # 路由器 local_list 铁证(轮询等移除反映)
                    if backend_verifier is not None:
                        _dl = time.time() + 25
                        while time.time() < _dl:
                            if backend_verifier.verify_sdwan_device_not_in_network().passed:
                                break
                            time.sleep(2)
                    rec_ssh("本设备已移出组网(local_list)", backend_verifier.verify_sdwan_device_not_in_network,
                            "local_list 查本设备是否已移出云端组网", must_pass=True)
                    # UI 反映: 路由器SD-WAN页不再展示组网(reload 强制刷新)
                    gone = False
                    page.navigate_to_sdwan()
                    _dl_ui = time.time() + 40
                    while time.time() < _dl_ui:
                        try:
                            page.page.reload(wait_until="domcontentloaded")
                            try:
                                page.page.wait_for_load_state("networkidle", timeout=8000)
                            except Exception:
                                pass
                            page.page.wait_for_timeout(2500)
                        except Exception:
                            pass
                        if not page.has_network_display():
                            gone = True
                            break
                        time.sleep(1)
                    rec.add_detail(f"  【页面】路由器SD-WAN页组网已消失: {'[OK]' if gone else '[FAIL]'}")
                    if not gone:
                        ui_failures.append("步骤4: 路由器SD-WAN页仍展示组网(期望成员移除后消失)")

            # ========== 步骤5: 异常路径(可选) ==========
            with rec.step("步骤5: 异常路径", "重复移出/幂等性云端验证(命令带复制按钮)"):
                if icc_token and sdwan_id and group_id and gwid:
                    # 重复删(本机已不在) -> 应 ok 或无害(幂等)
                    g = icc.get_default_group(sdwan_id, token=icc_token)
                    cur = g.get("members") if g.get("ok") else []
                    res = icc.remove_sdwan_member(
                        sdwan_id, group_id, gwid, cur, token=icc_token, **group_meta)
                    rec_cloud(
                        "重复移出(幂等)", res,
                        _cloud_curl("post", "business/sd/group/update",
                                    body={"sdwan_id": sdwan_id, "group_id": group_id,
                                          "members": [{"id": m["id"]} for m in cur
                                                      if str(m.get("id")) != str(gwid)],
                                          **group_meta}),
                        "重复移出成员(测云端幂等性, 期望 ok/无害)", must_pass=False, write=True,
                    )
                    rec.add_detail("  [说明] 云端 group/update 为全量提交, 重复移出等价于提交当前成员(幂等)")

            # ========== 步骤6: 清理 ==========
            with rec.step("步骤6: 清理", "确保成员移除 + (本用例绑定的)解绑设备(命令带复制按钮)"):
                if icc_token and sdwan_id and group_id and gwid:
                    try:
                        g = icc.get_default_group(sdwan_id, token=icc_token)
                        cur = g.get("members") if g.get("ok") else []
                        if any(str(m.get("id")) == str(gwid) for m in cur):
                            rec.add_detail("  [清理] 成员仍在, 移除")
                            rm = icc.remove_sdwan_member(sdwan_id, group_id, gwid, cur,
                                                         token=icc_token, **group_meta)
                            rec_cloud(
                                "清理-移除成员", rm,
                                _cloud_curl("post", "business/sd/group/update",
                                            body={"sdwan_id": sdwan_id, "group_id": group_id,
                                                  "members": [{"id": m["id"]} for m in cur
                                                              if str(m.get("id")) != str(gwid)],
                                                  **group_meta}),
                                "清理: 移出本机成员", must_pass=False, write=True,
                            )
                    except Exception as e:
                        rec.add_detail(f"  [清理] 成员移除异常: {str(e)[:80]}")
                # 若由本用例绑云, 解绑还原; 否则保留原绑云状态
                if bound_by_us and backend_verifier is not None and gwid:
                    rec.add_detail("  [清理] 本用例绑云, 执行解绑还原")
                    try:
                        ur = icc.unbind_device(gwid, token=icc_token)
                        rec_cloud(
                            "清理-ICC解绑", ur,
                            f"curl 'https://api.icc.ikuai8.com/v4/dm/devices/{gwid}/unbind' \\\n  -X POST "
                            "-H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' --data '{}'",
                            "清理: ICC 云端解绑设备", must_pass=False, write=True,
                        )
                    except Exception:
                        pass
                    backend_verifier.local_unbind()
                    backend_verifier.cleanup_sdwan_router_state()
                    rec_ssh("清理后register表清空", backend_verifier.verify_register_unbound,
                            "查 register 表是否已清空(解绑成功)", must_pass=False)
                else:
                    rec.add_detail("  [清理] 设备原已绑云(非本用例绑定), 保留绑云状态, 仅清SD-WAN残留")
                    if backend_verifier is not None:
                        backend_verifier.cleanup_sdwan_router_state()

            print("\n" + "=" * 60)
            print("网络配置-SD-WAN 综合测试完成")
            print("覆盖: 环境准备/未开通态/立即开通/云端加成员/云端删成员/异常/清理")
            print("=" * 60)

        finally:
            # ========== 兜底还原(无论中途是否失败) ==========
            try:
                if icc_token and sdwan_id and group_id and gwid:
                    try:
                        g = icc.get_default_group(sdwan_id, token=icc_token)
                        cur = g.get("members") if g.get("ok") else []
                        if any(str(m.get("id")) == str(gwid) for m in cur):
                            icc.remove_sdwan_member(sdwan_id, group_id, gwid, cur,
                                                    token=icc_token, **group_meta)
                    except Exception:
                        pass
                if bound_by_us and backend_verifier is not None and gwid:
                    try:
                        if icc_token:
                            icc.unbind_device(gwid, token=icc_token)
                    except Exception:
                        pass
                    backend_verifier.local_unbind()
                    backend_verifier.cleanup_sdwan_router_state()
            except Exception as e:
                print(f"[finally还原异常] {str(e)[:80]}")

        # ========== 末尾硬断言 ==========
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, (
            f"SD-WAN 验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
        )
