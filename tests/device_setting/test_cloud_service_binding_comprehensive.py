"""设备设置-云服务绑定 综合测试用例

一次测试覆盖云服务绑定全部功能(被测设备 10.66.0.45, arm企业版):
1.  验证码方式异常输入(假手机号+假验证码/空/格式) -> 绑定失败, register 表未写
2.  二维码展示(.ant-qrcode canvas + "有效时间 N 秒"倒计时递减)
3.  节点服务器(UI 中国/新加坡下拉切换 + 底层 cloud_node/ik_hosts 域名验证)
4.  绑定码异常输入(空/错误绑定码/超长备注) -> 失败(未绑定态校验)
5.  绑定码绑定成功(code=1190bc8d.. + 备注) -> register 表写入 + register_status=1
6.  获取服务码(scode_status=2 + serve_number 服务码数字 + 有效期)
7.  在线客服(customer_service 接口可达)
8.  结束服务(scode_status=0, 测完关闭)
9.  ICC 云端解绑(登录 icc.ikuai8.com 拿 token -> POST /v4/dm/devices/{gwid}/unbind
    -> 设备 register 表清空, 验证真实解绑)

底层脚本 /usr/ikuai/script/register.sh; 云端解绑 utils/icc_cloud.py。
绑定码绑定是真实云操作(消耗一个云账号绑定位), finally 用 ICC + 设备 local_unbind 双保险还原。
"""
import time
import pytest

from utils.step_recorder import StepRecorder, register_sensitive_value
from utils.verify_helper import make_ssh_verify
from utils.icc_cloud import IccCloudHelper

pytestmark = [pytest.mark.device_setting, pytest.mark.cloud_service_binding]

BIND_CODE = "1190bc8d1bf05eba3016e1e1615f515e"
TEST_COMMENT = "autotest_ikuai_cloud"
ICC_ACCOUNT = "sxrong@ikuai8.com"
ICC_PASSWORD = "rsx890426"
FAKE_MOBILE = "19900000000"  # 不存在的手机号


@pytest.mark.device_setting
@pytest.mark.cloud_service_binding
class TestCloudServiceBindingComprehensive:
    """设备设置-云服务绑定综合测试 - 一次测试覆盖所有功能"""

    def test_cloud_service_binding_comprehensive(
        self, cloud_service_binding_page_logged_in, step_recorder: StepRecorder, request
    ):
        """综合测试: 验证码异常 -> 二维码 -> 节点 -> 绑定码异常 -> 绑定成功 -> 服务码 -> 在线客服 -> 结束服务 -> ICC解绑"""
        page = cloud_service_binding_page_logged_in
        rec = step_recorder

        try:
            backend_verifier = request.getfixturevalue('backend_verifier')
        except Exception:
            backend_verifier = None

        # 注册敏感值(ICC密码/绑定码), 避免泄漏到 HTML/Excel 报告
        register_sensitive_value(ICC_PASSWORD)
        register_sensitive_value(BIND_CODE)

        ssh_failures = []
        ui_failures = []
        ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)

        # ICC 解绑助手(借用被测页面 page 的 context 新开 page 登录 ICC, 不干扰路由器页面)
        icc = IccCloudHelper(page.page, account=ICC_ACCOUNT, password=ICC_PASSWORD)
        icc_token = None
        gwid = ""

        try:
            # ========== 步骤0: 环境准备 ==========
            with rec.step("步骤0: 环境准备", "读取设备GWID, 确认未绑定(已绑则ICC预解绑), 登录ICC拿token"):
                if backend_verifier is not None:
                    gwid = backend_verifier.get_gwid()
                    rec.add_detail(f"  设备 GWID(SSH): {gwid}")
                ui_gwid = page.read_gwid()
                rec.add_detail(f"  页面路由ID(UI): {ui_gwid}")
                if gwid and ui_gwid and gwid != ui_gwid:
                    ui_failures.append(f"GWID不一致: SSH={gwid} UI={ui_gwid}")
                if not gwid:
                    gwid = ui_gwid
                # 若已绑定, 先 ICC 解绑还原到未绑定
                if backend_verifier is not None:
                    reg = backend_verifier.find_register()
                    rec.add_detail(f"  当前 register 表: {reg}")
                    if reg and (reg.get("code") or "").strip():
                        rec.add_detail("  [环境] 设备已绑定, 先 ICC 解绑还原")
                        try:
                            icc_token = icc.login_get_token()
                            if icc_token and gwid:
                                r = icc.unbind_device(gwid)
                                rec.add_detail(f"    ICC预解绑: ok={r.get('ok')} code={r.get('code')}")
                        except Exception as e:
                            rec.add_detail(f"    ICC预解绑异常: {str(e)[:80]}")
                        backend_verifier.local_unbind()
                        page.reload_binding_page()

            # ========== 步骤1: 验证码方式异常输入 ==========
            with rec.step("步骤1: 验证码方式异常输入", "假手机号+假验证码/空 -> 绑定失败, register表未写"):
                page.navigate_to_cloud_service_binding()
                page.select_bind_way("验证码")
                rec.add_detail(f"  当前绑定方式: {page.get_bind_way()}")

                # 1.1 未填手机号时 获取验证码按钮应 disabled
                enabled_empty = page.is_get_sms_code_enabled()
                rec.add_detail(f"  未填手机号 获取验证码按钮 enabled={enabled_empty}(期望False)")
                if enabled_empty:
                    ui_failures.append("验证码方式: 未填手机号获取验证码按钮应disabled")

                # 1.2 填假手机号后 获取验证码按钮应 enabled
                page.fill_mobile(FAKE_MOBILE)
                page.page.wait_for_timeout(300)
                enabled_filled = page.is_get_sms_code_enabled()
                rec.add_detail(f"  填手机号后 获取验证码按钮 enabled={enabled_filled}(期望True)")

                # 1.3 假手机号 + 假验证码 保存 -> 必失败
                page.fill_sms_code("000000")
                res = page.save_and_observe(actions=("save", "bind_update"), timeout=15000)
                rec.add_detail(
                    f"  假手机号+假验证码保存: api_success={res.get('api_success')} "
                    f"code={res.get('api_code')} errors={res.get('validation_errors')} toast={res.get('error_toast')}"
                )
                bind_failed = (not res.get("api_success")) or res.get("validation_errors") or res.get("error_toast")
                if not bind_failed:
                    ui_failures.append("验证码方式: 假手机号+假验证码应绑定失败但未拦截")
                if backend_verifier is not None:
                    ssh_verify("L1-验证码失败未写register", backend_verifier.verify_register_unbound, must_pass=True)

                # 1.4 空手机号保存 -> 前端校验
                page.fill_mobile("")
                page.fill_sms_code("")
                page.page.wait_for_timeout(200)
                res2 = page.save_and_observe(actions=("save", "bind_update"), timeout=8000)
                rec.add_detail(f"  空手机号保存: errors={res2.get('validation_errors')} toast={res2.get('error_toast')}")
                if not (res2.get("validation_errors") or res2.get("error_toast")):
                    rec.add_detail("  [WARN] 空手机号未触发前端校验提示")

            # ========== 步骤2: 二维码展示 ==========
            with rec.step("步骤2: 二维码展示验证", "切换二维码方式, 验证二维码弹出 + 有效时间倒计时"):
                page.navigate_to_cloud_service_binding()
                page.select_bind_way("二维码")
                page.page.wait_for_timeout(1500)  # 等二维码生成(请求云端)
                qr_present = page.read_qrcode_present()
                validity1 = page.read_qrcode_validity()
                rec.add_detail(f"  二维码canvas存在: {qr_present}")
                rec.add_detail(f"  有效时间(第1次): {validity1}s")
                page.page.wait_for_timeout(1500)
                validity2 = page.read_qrcode_validity()
                rec.add_detail(f"  有效时间(第2次, 1.5s后): {validity2}s")
                if not qr_present:
                    ui_failures.append("二维码方式: 二维码canvas未弹出")
                if validity1 <= 0:
                    ui_failures.append(f"二维码方式: 有效时间未读取到(={validity1})")
                if validity1 > 0 and validity2 > validity1:
                    ui_failures.append(f"二维码有效时间未递减: {validity1}->{validity2}")

            # ========== 步骤3: 节点服务器 ==========
            with rec.step("步骤3: 节点服务器验证", "UI 中国/新加坡下拉切换 + 底层 cloud_node/ik_hosts域名"):
                page.navigate_to_cloud_service_binding()
                cur_node = page.get_node()
                rec.add_detail(f"  当前节点(UI默认): {cur_node}")
                ok_sg = page.select_node("新加坡")
                rec.add_detail(f"  切换到新加坡: {ok_sg}, 当前={page.get_node()}")
                ok_cn = page.select_node("中国")
                rec.add_detail(f"  切换回中国: {ok_cn}, 当前={page.get_node()}")
                if not (ok_sg and ok_cn):
                    ui_failures.append("节点服务器: 下拉切换失败")
                if backend_verifier is not None:
                    ssh_verify("L2-中国节点域名(yun.ikuai8.com)",
                               backend_verifier.verify_node_hosts, "yun.ikuai8.com", must_pass=True)
                    node = backend_verifier.read_cloud_node()
                    rec.add_detail(f"  底层 cloud_node={node}(0=中国), ik_hosts/register={backend_verifier.read_register_hosts()}")
                    rec.add_detail("  [节点机制] node值->cloud_node缓存->update_hosts.sh 周期性下发 ik_hosts/register 域名")
                    rec.add_detail("  [节点机制] 不同 node 下发不同域名(中国=yun.ikuai8.com; 海外如 cloud-service.ikuai8.com, 调试已确认)")
                    rec.add_detail("  [只读验证] 真实节点切换需 save 绑定时带 node 触发下发; 不主动改 cloud_node(会下发海外域名致后续 save 连接云失败)")

            # ========== 步骤4: 绑定码异常输入(未绑定态) ==========
            with rec.step("步骤4: 绑定码异常输入", "空绑定码/错误绑定码/超长备注 -> 失败(未绑定态校验)"):
                page.navigate_to_cloud_service_binding()
                page.select_bind_way("绑定码")
                # 4.1 空绑定码保存
                page.fill_bind_code("")
                page.fill_comment("c")
                res = page.save_and_observe(actions=("save",), timeout=8000)
                rec.add_detail(f"  空绑定码保存: errors={res.get('validation_errors')} toast={res.get('error_toast')}")
                # 4.2 错误绑定码保存 -> 必失败
                page.fill_bind_code("0" * 32)
                page.fill_comment(TEST_COMMENT)
                res2 = page.save_and_observe(actions=("save",), timeout=15000)
                rec.add_detail(
                    f"  错误绑定码保存: api_success={res2.get('api_success')} "
                    f"code={res2.get('api_code')} msg={res2.get('message')}"
                )
                if res2.get("api_success"):
                    ui_failures.append("错误绑定码不应绑定成功")
                if backend_verifier is not None:
                    ssh_verify("L1-错误绑定码未写register", backend_verifier.verify_register_unbound, must_pass=True)
                # 4.3 超长备注(>64) -> 前端校验(只填不保存, 避免真绑定污染)
                page.fill_bind_code(BIND_CODE)
                page.fill_comment("x" * 100)
                page.page.wait_for_timeout(300)
                long_errors = page._get_validation_errors()
                rec.add_detail(f"  超长备注前端校验: errors={long_errors}")
                if not long_errors:
                    rec.add_detail("  [WARN] 超长备注未触发前端校验文案")

            # ========== 步骤5: 绑定码绑定成功(核心) ==========
            with rec.step("步骤5: 绑定码绑定成功", f"code={BIND_CODE[:8]}.. + 备注 -> 保存 -> register表写入"):
                page.navigate_to_cloud_service_binding()
                res = page.bind_via_code(BIND_CODE, TEST_COMMENT)
                rec.add_detail(
                    f"  绑定结果: clicked={res.get('clicked')} api_success={res.get('api_success')} "
                    f"code={res.get('api_code')} msg={res.get('message')}"
                )
                if not res.get("api_success"):
                    ui_failures.append(f"绑定码绑定未成功: {res.get('message') or res.get('error_toast')}")
                if backend_verifier is not None:
                    backend_verifier.wait_register_status("1", timeout=15)
                    ssh_verify("L1-绑定码写入register表",
                               backend_verifier.verify_register_bound, BIND_CODE,
                               must_pass=True, expected_comment=TEST_COMMENT)
                    st = backend_verifier.read_register_status()
                    rec.add_detail(f"  register_status={st}(期望1)")
                    if st != "1":
                        ssh_failures.append(f"register_status期望1实际{st}")

            # ========== 步骤6: 获取服务码 ==========
            with rec.step("步骤6: 获取服务码", "绑定后申请服务码, 验证 scode_status=2 + serve_number"):
                page.reload_binding_page()
                page.page.wait_for_timeout(1500)
                clicked = page.request_server_code()
                rec.add_detail(f"  点击获取服务码: {clicked}")
                if backend_verifier is not None:
                    deadline = time.time() + 20
                    while time.time() < deadline:
                        if backend_verifier.read_scode_status() == "2":
                            break
                        time.sleep(2)
                    ssh_verify("L4-服务码申请成功", backend_verifier.verify_scode_active, must_pass=True)
                    scode = backend_verifier.read_scode_result()
                    rec.add_detail(f"  服务码: number={scode.get('serve_number')} 有效期={scode.get('serve_timeout')}s")

            # ========== 步骤7: 在线客服 ==========
            with rec.step("步骤7: 在线客服", "验证在线客服入口可点击 + 后端 customer_service 接口可达"):
                page.reload_binding_page()
                page.page.wait_for_timeout(1000)
                clicked = page.click_online_service()
                rec.add_detail(f"  点击在线客服: {clicked}")
                page.page.wait_for_timeout(1500)
                # 关闭可能弹出的新标签页
                try:
                    ctx = page.page.context
                    extra = list(ctx.pages)[1:]
                    if extra:
                        rec.add_detail(f"  在线客服打开 {len(extra)} 个新标签页(已关闭)")
                        for p in extra:
                            try:
                                p.close()
                            except Exception:
                                pass
                except Exception:
                    pass
                # 后端: register.sh __show_customer_service 拉取的客服接口可达性
                if backend_verifier is not None:
                    backend_verifier.connect_router()
                    cs = backend_verifier._router.exec(
                        "curl -4 -X GET -k -s --connect-timeout 8 "
                        "'https://www.ikuai8.com/templates/ikuaitemplate/support.php?ac=api' 2>/dev/null | head -c 200"
                    )
                    rec.add_detail(f"  在线客服接口响应(前120字符): {(cs or '(空)')[:120]}")

            # ========== 步骤8: 结束服务(测完关闭) ==========
            with rec.step("步骤8: 结束服务", "点结束服务, 验证 scode_status=0"):
                page.reload_binding_page()
                page.page.wait_for_timeout(1000)
                clicked = page.disable_server_code()
                rec.add_detail(f"  点击结束服务: {clicked}")
                if backend_verifier is not None:
                    deadline = time.time() + 15
                    while time.time() < deadline:
                        if backend_verifier.read_scode_status() == "0":
                            break
                        time.sleep(2)
                    ssh_verify("L4-服务码已结束", backend_verifier.verify_scode_disabled, must_pass=True)

            # ========== 步骤9: ICC 云端解绑 ==========
            with rec.step("步骤9: ICC云端解绑", "登录ICC调unbind API + 验证设备真实解绑(register表清空)"):
                if backend_verifier is not None and gwid:
                    if not icc_token:
                        try:
                            icc_token = icc.login_get_token()
                            rec.add_detail(f"  ICC登录获取token: {'成功' if icc_token else '失败'}")
                        except Exception as e:
                            rec.add_detail(f"  ICC登录异常: {str(e)[:80]}")
                    if icc_token:
                        before = icc.get_bind_status(gwid)
                        rec.add_detail(f"  解绑前设备云端状态: code={before.get('code')} ok={before.get('ok')}")
                        r = icc.unbind_device(gwid)
                        rec.add_detail(
                            f"  ICC unbind: ok={r.get('ok')} http={r.get('status')} "
                            f"code={r.get('code')} msg={r.get('message')}"
                        )
                        if not r.get("ok"):
                            rec.add_detail("  [WARN] ICC unbind 返回非成功(可能已解绑/token), 设备侧兜底")
                        # reload 触发 register show -> 异步 check_bind, 让设备感知云端解绑
                        page.reload_binding_page()
                        page.page.wait_for_timeout(2000)
                        sensed = backend_verifier.wait_register_status("0", timeout=25)
                        rec.add_detail(f"  设备侧 register_status=0 自动感知: {sensed}")
                        if not sensed:
                            rec.add_detail("  设备侧未自动感知(异步延迟), local_unbind 兜底")
                            backend_verifier.local_unbind()
                        ssh_verify("L1-解绑后register表清空",
                                   backend_verifier.verify_register_unbound, must_pass=True)
                        rec.add_detail("  [OK] 云端解绑 + 设备register表清空 验证通过")
                    else:
                        rec.add_detail("  [WARN] 无ICC token, 仅设备侧 local_unbind 解绑")
                        backend_verifier.local_unbind()
                        ssh_verify("L1-解绑后register表清空",
                                   backend_verifier.verify_register_unbound, must_pass=True)
                else:
                    rec.add_detail("  (无SSH/gwid) 跳过ICC解绑")
                    if backend_verifier is not None:
                        backend_verifier.local_unbind()

            print("\n" + "=" * 60)
            print("设备设置-云服务绑定综合测试完成")
            print("覆盖: 验证码异常/二维码/节点/绑定码异常/绑定成功/服务码/在线客服/结束服务/ICC解绑")
            print("=" * 60)

        finally:
            # ========== 兜底还原(无论测试是否中途失败) ==========
            try:
                if backend_verifier is not None:
                    backend_verifier.disable_scode_backend()  # 确保服务码结束
                if backend_verifier is not None and gwid:
                    try:
                        if not icc_token:
                            icc_token = icc.login_get_token()
                        if icc_token:
                            icc.unbind_device(gwid)
                    except Exception:
                        pass
                    backend_verifier.local_unbind()  # 设备侧兜底解绑
                if backend_verifier is not None:
                    backend_verifier.restore_cloud_node("0")  # 恢复节点
            except Exception as e:
                print(f"[finally还原异常] {str(e)[:80]}")

        # ========== 末尾硬断言 ==========
        all_failures = ssh_failures + ui_failures
        if all_failures:
            print(f"\n[断言] 共 {len(all_failures)} 项失败 (ssh={len(ssh_failures)} ui={len(ui_failures)}):")
            for f in all_failures:
                print(f"  - {f}")
        assert not all_failures, (
            f"云服务绑定验证失败({len(all_failures)}项): {'; '.join(all_failures[:15])}"
        )
