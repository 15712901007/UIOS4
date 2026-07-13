"""共享 ssh_verify / kernel_check 工厂(+验证命令录制显示进报告)。

从 36 个测试文件的复制粘贴闭包提取而来。闭包逻辑与原版一致, 新增一点:
在 finally 里把本次验证实际执行的 SSH 命令(经 BackendVerifier.mark_cmd_start /
collect_cmds_since_mark 差量捕获, 命令在 SSHClient.exec 咽喉点录制)显示进测试报告,
方便工程师看报告就能自己登路由器复验。

用法(测试文件内, 替换原 def ssh_verify / def kernel_check):
    from utils.verify_helper import make_ssh_verify, make_kernel_check
    ssh_verify = make_ssh_verify(backend_verifier, rec, ssh_failures)
    kernel_check = make_kernel_check(backend_verifier, rec, ssh_failures, module="stream_updown")

特化闭包(mac_access 的 PASS/FAIL格式 / ipv6_lan/wan 的自定义count对比)不套工厂,
用 attach_cmd_recording_to_closure 包一层即可获得命令显示, 逻辑零改动。
"""
from typing import Callable, List


def _format_cmds(cmds: List[str], per_limit: int = 200) -> str:
    """合并命令列表为单行字符串(每条截断per_limit字符避免超长命令撑爆报告行)。"""
    if not cmds:
        return ""
    return "; ".join(c[:per_limit] for c in cmds)


def make_ssh_verify(bv, rec, failures, *, soft_assert: bool = False,
                    must_pass_default: bool = False):
    """构造 ssh_verify 闭包(标准版, 覆盖大多数测试文件)。

    Args:
        bv: BackendVerifier 实例(None 时闭包直接返回 None, 兼容无 SSH 环境)
        rec: StepRecorder(rec.add_detail 写报告)
        failures: 失败收集列表(各文件 ssh_failures 或 failures)
        soft_assert: True=VPN 软断言变体, FAIL 显示[软断言]而非[FAIL](must_pass=False 时)
        must_pass_default: must_pass 参数默认值(原闭包默认 False;
            acl_priority_order / acl第二处 / app_protocol第二处 = True)

    覆盖约 35 个标准/变体文件。不覆盖 mac_access(PASS/FAIL 格式+无 must_pass 判断, 用包装器)。
    闭包签名 ssh_verify(label, verify_func, *args, must_pass=None, **kwargs) 与原版一致, 调用点零改动。
    """
    def ssh_verify(label, verify_func, *args, must_pass=None, **kwargs):
        if bv is None or verify_func is None:
            return None
        mp = must_pass_default if must_pass is None else must_pass
        mark = bv.mark_cmd_start()
        try:
            result = verify_func(*args, **kwargs)
            if soft_assert:
                status = '[OK]' if result.passed else ('[软断言]' if not mp else '[FAIL]')
            else:
                status = '[OK]' if result.passed else '[FAIL]'
            print(f"    SSH-{label}: {status} - {result.message}")
            rec.add_detail(f"    SSH-{label}: {status} {result.message}")
            raw = getattr(result, 'raw_output', '')
            if raw:
                # 软断言(soft_assert=True且非must_pass)未通过时, raw_output里的[FAIL]→[软断言],
                # 避免裸[FAIL]泄漏到details被conftest步骤扫描('FAIL' in details误判步骤失败, conftest.py:1602)
                # 6个VPN模块步骤5全链路L2连接软断言(拨号依赖服务端,未连接属预期)均受益
                if soft_assert and not mp and not result.passed:
                    raw = raw.replace('[FAIL]', '[软断言]')
                rec.add_detail(f"      SSH数据: {raw}")
            if mp and not result.passed:
                failures.append(f"SSH-{label}: {result.message}")
            return result
        except Exception as e:
            print(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
            rec.add_detail(f"    SSH-{label}: 跳过 - {str(e)[:80]}")
            if mp:
                failures.append(f"SSH-{label}: 异常被吞 - {str(e)[:80]}")
            return None
        finally:
            cmds = bv.collect_cmds_since_mark(mark)
            txt = _format_cmds(cmds)
            if txt:
                rec.add_detail(f"      验证命令({len(cmds)}): {txt}")
    return ssh_verify


def make_kernel_check(bv, rec, failures, *, default_module: str = None,
                      module_fn: Callable[[], str] = None):
    """构造 kernel_check 闭包(调 verify_module_kernel_consistency 做底层一致性校验)。

    Args:
        default_module: 静态模块默认值(stream_updown/acl/conn_limit/stream_layer7/... 照抄原闭包默认)
        module_fn: 动态模块解析函数(mac_access 按 global_config.acl_mac 选 black/white); 优先于 default_module

    覆盖 16 个文件(15 静态 default_module + mac_access 动态 module_fn)。
    不覆盖 ipv6_lan/wan(自定义 count 对比逻辑, 非 verify_module_kernel_consistency; 用包装器)。
    闭包签名 kernel_check(label, fail_on_residual=True, module=None) 与原版一致(调用可传 module 覆盖默认)。
    """
    def kernel_check(label, fail_on_residual=True, module=None):
        if bv is None:
            return None
        mark = bv.mark_cmd_start()
        try:
            bv.connect_router()
            mod = module or (module_fn() if module_fn else default_module)
            res = bv.verify_module_kernel_consistency(mod, label)
            rec.add_detail(f"  [底层一致性-{label}] {res['detail']}")
            for rd in res['residual_detail']:
                rec.add_detail(f"    ✗残留 {rd}")
            if res['residual'] or res.get('count_overflow'):
                ovf = '/'.join(f"{c['chain']}累加{c['dup']}条" for c in res.get('count_overflow', []))
                rec.add_detail(f"    ✗ {mod}底层残留(删不干净,报禅道): id={res['residual']}{'; ' + ovf if ovf else ''}")
                if fail_on_residual:
                    failures.append(f"底层残留-{label}: {mod} id {res['residual']} {ovf} 底层有DB无(报禅道)")
            elif res['missing']:
                rec.add_detail(f"    ⚠ 漏下发(DB有底层无): {res['missing']}")
            else:
                rec.add_detail(f"    ✓ 底层与DB一致(无残留)")
            return res
        except Exception as e:
            rec.add_detail(f"  [底层一致性-{label}] 异常: {str(e)[:80]}")
            return None
        finally:
            cmds = bv.collect_cmds_since_mark(mark)
            txt = _format_cmds(cmds)
            if txt:
                rec.add_detail(f"      验证命令({len(cmds)}): {txt}")
    return kernel_check


def attach_cmd_recording_to_closure(bv, rec, closure):
    """给保留的特化闭包(mac_access / ipv6_lan / ipv6_wan 的 kernel_check 等)包装命令录制。

    特化闭包逻辑与标准不同(无法用工厂替换), 用此函数包一层加命令显示, 逻辑零改动:
        kernel_check = attach_cmd_recording_to_closure(bv, rec, kernel_check)
    调用方式不变, 仅在报告多一行"验证命令(N): ..."。
    """
    def wrapper(*args, **kwargs):
        mark = bv.mark_cmd_start() if bv is not None else None
        try:
            return closure(*args, **kwargs)
        finally:
            if bv is not None and mark is not None:
                cmds = bv.collect_cmds_since_mark(mark)
                txt = _format_cmds(cmds)
                if txt:
                    rec.add_detail(f"      验证命令({len(cmds)}): {txt}")
    return wrapper
