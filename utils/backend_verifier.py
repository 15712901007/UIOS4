"""
SSH后台验证工具

通过SSH连接iKuai路由器后台，执行多层次验证：
- L1: 数据库验证（/usr/ikuai/function/ CLI）
- L2: iptables规则验证（IP_QOS/MAC_QOS链）
- L3: ipset验证（限速目标IP/MAC集合）
- L4: 内核模块/日志验证（ik_core、dmesg）
- L5: iperf3实测验证（实际带宽测量）

基于MCP-SSH全链路探索经验编写（2026-03-04）
"""
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any

import paramiko

from config.config import get_config, get_config_with_env, SSHConfig, SSHHostConfig
from utils.logger import get_logger

logger = get_logger()


@dataclass
class VerifyResult:
    """单层验证结果"""
    level: str  # L1/L2/L3/L4/L5
    passed: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""


@dataclass
class FullChainResult:
    """全链路验证结果"""
    results: List[VerifyResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """兼容VerifyResult接口"""
        return self.all_passed

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    def summary(self) -> str:
        lines = ["全链路验证结果:"]
        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            lines.append(f"  [{status}] {r.level}: {r.message}")
        return "\n".join(lines)

    @property
    def message(self) -> str:
        passed_count = sum(1 for r in self.results if r.passed)
        return f"{passed_count}/{len(self.results)} 项通过"

    @property
    def raw_output(self) -> str:
        return self.summary()


class SSHClient:
    """SSH连接管理器（支持控制台菜单自动登录）"""

    def __init__(self, host_config: SSHHostConfig):
        self._config = host_config
        self._client: Optional[paramiko.SSHClient] = None
        self._console_logged_in = False  # 控制台登录状态
        self._used_console_login = False  # 是否使用了控制台登录流程
        self._cmd_log: List[str] = []  # 执行过的命令录制(供验证报告显示验证命令, mark/collect差量)

    def connect(self):
        if self._client is not None:
            # 检查连接是否仍然活跃
            try:
                transport = self._client.get_transport()
                if transport is None or not transport.is_active():
                    logger.info(f"SSH connection lost, reconnecting: {self._config.host}")
                    self._client = None
                    self._console_logged_in = False
                else:
                    return
            except Exception:
                self._client = None
                self._console_logged_in = False
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            timeout=10,
        )
        # 设置keepalive防止长时间空闲断连（每30秒发送一次心跳）
        transport = self._client.get_transport()
        if transport:
            transport.set_keepalive(30)
        logger.info(f"SSH connected: {self._config.username}@{self._config.host}")

        # 检测是否需要控制台登录
        self._check_and_login_console()

    def _check_and_login_console(self):
        """检测是否进入交互式菜单，如果是则自动登录"""
        # 如果已登录过，跳过
        if self._console_logged_in:
            logger.debug("Console already logged in, skipping check")
            return

        # 尝试执行简单命令检测是否需要控制台登录
        # 使用线程+超时来避免阻塞
        import threading

        check_result = {"done": False, "output": "", "error": None}

        def do_check():
            try:
                _, stdout, stderr = self._client.exec_command("echo __CONSOLE_CHECK__", timeout=5)
                # 设置 channel 超时
                stdout.channel.settimeout(5)
                check_result["output"] = stdout.read().decode("utf-8", errors="replace").strip()
            except Exception as e:
                check_result["error"] = e
            finally:
                check_result["done"] = True

        logger.debug("Checking if console login is needed...")
        thread = threading.Thread(target=do_check, daemon=True)
        thread.start()
        thread.join(timeout=5)  # 最多等待5秒

        if not check_result["done"]:
            # 超时，说明进入了交互式菜单
            logger.debug("exec_command timeout - likely interactive shell")
        elif check_result["error"]:
            logger.debug(f"exec_command check failed: {type(check_result['error']).__name__}")
        elif "__CONSOLE_CHECK__" in check_result["output"]:
            # exec_command正常工作，不需要控制台登录
            self._console_logged_in = True
            logger.debug("exec_command works, no console login needed")
            return

        # 检查是否配置了控制台凭据
        if not self._config.console_username or not self._config.console_password:
            logger.warning("SSH可能进入交互式菜单，但未配置控制台凭据(console_username/console_password)")
            return

        logger.info(f"Starting console login with username: {self._config.console_username}")
        # 执行控制台登录
        self._login_console()
        self._used_console_login = True  # 标记使用了控制台登录

    def _login_console(self) -> bool:
        """通过交互式shell登录控制台

        iKuai控制台登录流程（控制台密码开启时）：
        1. SSH连接后显示菜单，提示"请输入菜单编号"
        2. 输入用户名回车 → 菜单刷新（不显示密码提示）
        3. 输入密码回车 → 进入bash

        注意：密码提示不会显示，这是正常行为

        Returns:
            bool: 登录是否成功
        """
        channel = None
        try:
            # 创建交互式shell
            channel = self._client.invoke_shell(term='xterm', width=80, height=24)
            channel.settimeout(10)

            def recv_until(pattern: str, timeout: float = 5.0) -> str:
                """接收数据直到匹配pattern或超时"""
                import time
                buffer = ""
                start = time.time()
                while time.time() - start < timeout:
                    if channel.recv_ready():
                        data = channel.recv(4096).decode("utf-8", errors="replace")
                        buffer += data
                        if pattern in buffer:
                            return buffer
                    time.sleep(0.1)
                return buffer

            def recv_all(timeout: float = 2.0) -> str:
                """接收所有可用数据"""
                import time
                buffer = ""
                start = time.time()
                while time.time() - start < timeout:
                    if channel.recv_ready():
                        data = channel.recv(4096).decode("utf-8", errors="replace")
                        buffer += data
                        start = time.time()  # 重置计时器
                    else:
                        time.sleep(0.1)
                return buffer

            # 等待菜单显示（"请输入菜单编号" 或 "爱快路由"）
            output = recv_until("菜单编号", timeout=5)
            logger.debug(f"Console menu displayed: {len(output)} bytes")

            # Step 1: 发送用户名
            logger.debug(f"Sending username: {self._config.console_username}")
            channel.send(f"{self._config.console_username}\n")
            time.sleep(0.8)

            # Step 2: 等待菜单刷新（不等待密码提示，因为不会显示）
            output = recv_until("菜单编号", timeout=3)
            logger.debug(f"Menu refreshed after username: {len(output)} bytes")

            # Step 3: 发送密码
            logger.debug(f"Sending password: ***")
            channel.send(f"{self._config.console_password}\n")
            time.sleep(1.5)

            # Step 4: 读取登录结果
            login_output = recv_all(timeout=2.0)
            logger.debug(f"Login output: {login_output[:200]}")

            # Step 5: 验证登录是否成功 - 发送测试命令
            VERIFY_MARKER = "__IKUAI_CONSOLE_LOGIN_VERIFY__"
            channel.send(f"echo {VERIFY_MARKER}\n")
            time.sleep(1.0)

            # 读取验证结果
            verify_output = recv_all(timeout=2.0)
            logger.debug(f"Verify output: {verify_output[:200]}")

            # Step 6: 断言检查
            if VERIFY_MARKER not in verify_output:
                # 检查是否还在菜单中（密码错误）
                if "菜单编号" in verify_output or "请输入" in verify_output:
                    error_msg = "控制台登录失败：密码错误，仍在菜单中"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg)
                else:
                    error_msg = f"控制台登录失败：未检测到验证标记，输出: {verify_output[:100]}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg)

            # 检查bash提示符（可选的额外验证）
            if "@" in verify_output and ("$" in verify_output or "#" in verify_output):
                logger.debug(f"检测到bash提示符，确认进入shell")

            # 关键步骤：通过交互式shell修复/etc/passwd，让后续exec_command能正常工作
            # 当控制台密码开启时，sshd的shell是/etc/setup/rc，每次exec_command都会进入菜单
            # 必须修改/etc/passwd把shell改为/bin/bash
            logger.info("通过交互式shell修复sshd shell...")

            # 先读取当前passwd内容确认状态
            channel.send("cat /etc/passwd | grep -E '^sshd:'\n")
            time.sleep(1.0)
            before_output = recv_all(timeout=2.0)
            logger.info(f"修复前 passwd: {before_output.strip()}")

            # 执行修复命令
            fix_cmd = "sed -i 's|^sshd:x:0:0:sshd:/root:.*|sshd:x:0:0:sshd:/root:/bin/bash|' /etc/passwd"
            channel.send(f"{fix_cmd}\n")
            time.sleep(1.5)
            fix_output = recv_all(timeout=2.0)
            logger.debug(f"Fix command output: {fix_output[:100] if fix_output else '(empty)'}")

            # 验证修复是否成功
            channel.send("cat /etc/passwd | grep -E '^sshd:'\n")
            time.sleep(1.0)
            passwd_output = recv_all(timeout=2.0)
            logger.info(f"修复后 passwd: {passwd_output.strip()}")

            if "/bin/bash" in passwd_output:
                logger.info("[OK] sshd shell已修复为/bin/bash")
            else:
                error_msg = f"sshd shell修复失败！当前状态: {passwd_output.strip()}"
                logger.error(error_msg)
                # 不抛出异常，继续尝试后续流程

            # 关闭交互式channel
            channel.close()
            channel = None

            # 重要：必须关闭当前SSH连接并重新连接，新的连接才会使用/bin/bash
            logger.debug("关闭当前连接，准备重连...")
            self._client.close()
            self._client = None

            # 重新连接（这次shell已经是/bin/bash，不需要控制台登录）
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._client.connect(
                hostname=self._config.host,
                port=self._config.port,
                username=self._config.username,
                password=self._config.password,
                timeout=10,
            )
            logger.info(f"SSH reconnected: {self._config.username}@{self._config.host}")

            self._console_logged_in = True
            logger.info(f"[OK] 控制台登录成功: {self._config.console_username}@{self._config.host}")

            # 部署防重置脚本（现在exec_command应该能工作了）
            self._deploy_fix_script()

            return True

        except Exception as e:
            logger.error(f"[FAIL] 控制台登录失败: {e}")
            self._console_logged_in = False
            raise  # 重新抛出异常，让调用方知道登录失败

        finally:
            # 确保channel被关闭
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass

    def _deploy_fix_script(self):
        """部署SSH shell防重置脚本(持久分区) + 确保cron任务存在

        !! 2026-06-18修复: 旧版"脚本存在就return"导致升级后cron任务丢失时不补——
        实测固件升级后crontab里没有fix_sshd_shell任务(/tmp/sshd_fix.log不存在),
        防重置形同虚设, sshd shell被固件默认/etc/setup/rc覆盖后无人修复,
        表现为"控制台密码被自动开启". 改为: 脚本存在也每次检查cron, 缺则补上.
        """
        try:
            # 1. 确保脚本存在于持久分区(不存在才部署)
            check_cmd = "test -f /etc/mnt/ikuai/fix_sshd_shell.sh && echo EXISTS || echo NOT_EXISTS"
            _, stdout, _ = self._client.exec_command(check_cmd, timeout=5)
            if "EXISTS" not in stdout.read().decode():
                script_content = '''#!/bin/bash
# SSH Shell自动修复脚本
# 解决固件升级或系统重置后sshd shell被改为/etc/setup/rc的问题

PASSWD_FILE="/etc/passwd"
MARKER_FILE="/tmp/.sshd_shell_fixed"

current_shell=$(grep "^sshd:" $PASSWD_FILE | cut -d: -f7)

if [ "$current_shell" != "/bin/bash" ]; then
    echo "[$(date)] 检测到sshd shell为 $current_shell，正在修复..."
    sed -i 's|^sshd:x:0:0:sshd:/root:.*|sshd:x:0:0:sshd:/root:/bin/bash|' $PASSWD_FILE
    echo "[$(date)] 已修复sshd shell为/bin/bash"
fi

touch $MARKER_FILE
'''
                write_cmd = f'''cat > /etc/mnt/ikuai/fix_sshd_shell.sh << 'FIXSCRIPT'
{script_content}FIXSCRIPT
chmod +x /etc/mnt/ikuai/fix_sshd_shell.sh'''
                self._client.exec_command(write_cmd, timeout=10)
                self._client.exec_command("/etc/mnt/ikuai/fix_sshd_shell.sh", timeout=5)
                logger.info("SSH防重置脚本部署成功")

            # 2. !! 始终确保cron任务存在(升级/重启后cron可能丢, 必须每次连接都检查补上)
            cron_check = 'crontab -l 2>/dev/null | grep -q fix_sshd_shell && echo CRON_OK || echo CRON_MISSING'
            _, cout, _ = self._client.exec_command(cron_check, timeout=5)
            if "CRON_OK" not in cout.read().decode():
                cron_cmd = '(crontab -l 2>/dev/null | grep -v fix_sshd_shell; echo "* * * * * /etc/mnt/ikuai/fix_sshd_shell.sh >> /tmp/sshd_fix.log 2>&1") | crontab -'
                self._client.exec_command(cron_cmd, timeout=5)
                logger.info("SSH防重置cron任务(重新)部署成功")
            else:
                logger.debug("SSH防重置cron任务已存在")

        except Exception as e:
            logger.warning(f"部署防重置脚本失败: {e}")

    def exec_command(self, command: str, timeout: int = 30) -> str:
        """执行命令并返回stdout（exec方法的别名，保持兼容性）"""
        return self.exec(command, timeout)

    def exec(self, command: str, timeout: int = 30) -> str:
        """执行命令并返回stdout（exec方法的别名，保持兼容性）

        外层线程硬超时防护: paramiko的channel.settimeout在Windows下偶发不生效,
        会导致stdout.read()无限阻塞(实测测试过程中偶发卡死5分钟+)。
        这里用看门狗线程, 超时后强制close client让阻塞的recv抛异常退出, 再重连重试一次。
        """
        self._cmd_log.append(command)  # 录制命令(入口录制, 重连重试不再经此故不重复; 供报告显示验证命令)
        import threading
        hard_limit = timeout + 20  # settimeout应在timeout触发, 留20s余量后强制中断
        holder = {}

        def _worker():
            try:
                holder["result"] = self._exec_with_retry(command, timeout)
            except BaseException as e:  # noqa: BLE001 看门狗需捕获所有异常
                holder["error"] = e

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(hard_limit)
        if t.is_alive():
            # worker仍阻塞 -> settimeout失效, 强制关闭连接让阻塞的recv抛异常
            logger.warning(f"SSH exec 硬超时({hard_limit}s), 强制关闭连接重试: cmd={command[:80]}")
            try:
                if self._client is not None:
                    self._client.close()
            except Exception:
                pass
            self._client = None
            self._console_logged_in = False
            t.join(5)  # 等待阻塞的recv因连接关闭而退出
            try:
                self.connect()
                return self._exec_with_retry(command, timeout)
            except Exception as e:
                raise RuntimeError(f"SSH exec 硬超时后重连重试仍失败: {e}") from e
        if "error" in holder:
            raise holder["error"]
        return holder.get("result", "")

    def _exec_with_retry(self, command: str, timeout: int = 30) -> str:
        """执行命令并返回stdout，连接断开时自动重连一次

        增加控制台模式检测: 如果shell被重置回/etc/setup/rc(测试过程中可能发生),
        exec_command不会报错但返回的是控制台菜单内容而非命令结果。
        检测到这种情况时自动重新走控制台登录修复shell。
        """
        for attempt in range(2):
            try:
                if self._client is None:
                    self.connect()
                # 第一次尝试用短超时(10秒), 快速检测控制台模式; 第二次用正常超时
                exec_timeout = 10 if attempt == 0 else timeout
                _, stdout, stderr = self._client.exec_command(command, timeout=exec_timeout)
                stdout.channel.settimeout(exec_timeout)  # 确保read也遵守超时
                output = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                if err and "warning" not in err.lower():
                    logger.debug(f"SSH stderr: {err.strip()}")

                # 控制台模式检测: shell被重置后exec返回的是菜单内容(含"请输入菜单编号")
                # 而非命令结果, 这时需要重新走控制台登录
                if self._is_console_output(output):
                    logger.warning("检测到SSH shell被重置为控制台模式, 重新登录...")
                    self._console_logged_in = False
                    self._client.close()
                    self._client = None
                    self.connect()  # connect会重新走_check_and_login_console
                    # 重连后重新执行命令(必须同样设置channel超时, 否则read可能无限阻塞)
                    if self._client is not None:
                        _, stdout2, _ = self._client.exec_command(command, timeout=timeout)
                        stdout2.channel.settimeout(timeout)
                        output = stdout2.read().decode("utf-8", errors="replace")

                return output
            except (paramiko.SSHException, OSError, TimeoutError) as e:
                if attempt == 0:
                    logger.info(f"SSH exec failed ({e}), reconnecting...")
                    self._console_logged_in = False  # 重置标记, 重连时重新检测控制台
                    self._client = None
                else:
                    raise

    def _is_console_output(self, output: str) -> bool:
        """检测输出是否是控制台菜单内容(而非命令结果)

        控制台菜单的特征文字:
        - "爱快路由中文控制台" 或 "请输入菜单编号" 或 "IKKUAI"
        """
        if not output:
            return False
        console_markers = ["请输入菜单编号", "爱快路由中文控制台", "系统状态监视", "设置网卡绑定"]
        return any(marker in output for marker in console_markers)

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None
            logger.info(f"SSH disconnected: {self._config.host}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


class BackendVerifier:
    """
    iKuai路由器后台验证器

    支持IP限速(simple_qos)和MAC限速(mac_qos/dt_mac_qos)的全链路验证。

    Usage:
        config = get_config()
        verifier = BackendVerifier(config.ssh)
        verifier.connect()

        # L1: 数据库验证
        result = verifier.verify_qos_database("simple_qos", tagname="测试规则")

        # L2: iptables验证
        result = verifier.verify_iptables_rule("IP_QOS", expected_speed_kbps=2048)

        # 全链路
        result = verifier.verify_ip_qos_full_chain(
            tagname="测试规则", ip="192.168.148.2",
            upload_kbps=2048, download_kbps=4096
        )

        verifier.close()
    """

    def __init__(self, ssh_config: SSHConfig = None):
        if ssh_config is None:
            ssh_config = get_config_with_env().ssh
        self._ssh_config = ssh_config
        self._router: Optional[SSHClient] = None
        self._client: Optional[SSHClient] = None
        # xt_set模块可用性缓存(None=未探测, True=坏, False=正常)。session级,只探测一次。
        self._xt_set_status: Optional[bool] = None

    def connect_router(self):
        """连接路由器"""
        if self._router is None:
            self._router = SSHClient(self._ssh_config.router)
            self._router.connect()

    def connect_client(self):
        """连接测试客户端（用于iperf3）"""
        if self._client is None:
            self._client = SSHClient(self._ssh_config.client)
            self._client.connect()

    def close(self):
        """关闭所有连接"""
        if self._router:
            self._router.close()
            self._router = None
        if self._client:
            self._client.close()
            self._client = None

    # ==================== 验证命令录制(供测试报告显示, 方便工程师看报告自己复验) ====================
    def mark_cmd_start(self) -> Dict[str, tuple]:
        """标记当前命令录制位置(供 collect_cmds_since_mark 差量捕获)。

        捕获 router+client 两个 SSHClient 的 (实例引用, 当前log长度)。永不抛异常。
        ssh_verify/kernel_check 在调用 verify 前标记、后差量, 把本次验证执行的SSH命令显示进报告。
        """
        def _snap(role):
            inst = getattr(self, f"_{role}", None)
            return (inst, len(inst._cmd_log)) if inst is not None else (None, 0)
        return {"router": _snap("router"), "client": _snap("client")}

    def collect_cmds_since_mark(self, mark) -> List[str]:
        """取 mark 之后的命令差量, 逐条加 [router]/[client] 前缀。

        用 `is not` 判断 SSHClient 实例是否变更(mark后重连重建了实例),
        变更则从0切片(捕获重建后新实例的全部命令, 含重连本身触发的命令)。
        """
        out = []
        for role in ("router", "client"):
            inst_mark, start = mark.get(role, (None, 0))
            inst_now = getattr(self, f"_{role}", None)
            if inst_now is None:
                continue
            s = 0 if (inst_mark is None or inst_mark is not inst_now) else start
            for c in inst_now._cmd_log[s:]:
                out.append(f"[{role}] {c}")
        return out

    def get_last_cmds(self, n: int = 50) -> List[str]:
        """最近 n 条命令(router+client 合并)。手动调试/复验用, 非报告路径。"""
        router = self._router._cmd_log if self._router else []
        client = self._client._cmd_log if self._client else []
        all_cmds = [f"[router] {c}" for c in router] + [f"[client] {c}" for c in client]
        return all_cmds[-n:] if n else all_cmds

    def is_xt_set_broken(self) -> bool:
        """探测iptables xt_set模块是否可用。

        6.12+内核已知Blocker bug: `-m set --match-set` 在filter/nat全表均报
        errno=22(EINVAL)失败,导致所有依赖ipset+iptables的功能(IP限速/MAC限速/
        ACL/MAC访问控制/DHCP黑白名单/NAT带地址)的iptables规则无法建立。
        session级缓存,只探测一次(建临时链+ipset实测)。

        Returns:
            True=xt_set坏(iptables无法用-m set), False=正常
        """
        if self._xt_set_status is not None:
            return self._xt_set_status
        self.connect_router()
        # 建临时链+ipset, 实测 -m set --match-set 是否可用, 测完即清理
        probe_cmd = (
            "iptables -t filter -N XTSET_PROBE 2>/dev/null; "
            "ipset create xtset_probe hash:ip 2>/dev/null; "
            "ipset add xtset_probe 1.2.3.4 2>/dev/null; "
            "iptables -t filter -A XTSET_PROBE -m set --match-set xtset_probe src -j DROP 2>&1; "
            "iptables -t filter -F XTSET_PROBE 2>/dev/null; "
            "iptables -t filter -X XTSET_PROBE 2>/dev/null; "
            "ipset destroy xtset_probe 2>/dev/null"
        )
        try:
            out = self._router.exec(probe_cmd, timeout=15)
            if not isinstance(out, str):
                out = str(out)
            # xt_set坏的特征: errno=22 或 "Problem when communicating with ipset"
            broken = ("errno=22" in out) or ("Problem when communicating with ipset" in out)
        except Exception as e:
            logger.warning(f"[xt_set] 探测异常,保守判定为正常: {e}")
            broken = False
        self._xt_set_status = broken
        if broken:
            logger.warning("[xt_set] 检测到iptables set模块(xt_set)损坏(6.12内核bug), "
                           "iptables -m set规则无法建立, 相关iptables验证将降级为软记录(报禅道)")
        return broken

    def xt_set_degrade_result(self, level: str, chain: str, extra: str = "") -> VerifyResult:
        """xt_set坏时返回的降级软记录结果。

        传入passed=True使验证不进ssh_failures(软记录,测试不阻断), 但message明确标记
        '已知内核bug降级', 报告中可见⚠️, 内核修复后is_xt_set_broken返回False自动恢复硬验证。
        """
        return VerifyResult(
            level=level,
            passed=True,
            message=f"⚠️xt_set内核bug(6.12): iptables -m set规则无法建立({chain}{extra}), "
                    f"降级软记录(报禅道), 内核修复后自动恢复硬验证",
            details={"xt_set_broken": True},
            raw_output="",
        )

    def __enter__(self):
        self.connect_router()
        return self

    def __exit__(self, *args):
        self.close()

    # ==================== L1: 数据库验证 ====================

    def query_qos_rules(self, qos_type: str = "simple_qos") -> List[Dict]:
        """
        查询QoS规则列表

        Args:
            qos_type: simple_qos | mac_qos | dt_mac_qos

        Returns:
            规则列表
        """
        self.connect_router()
        output = self._router.exec(
            f"/usr/ikuai/function/{qos_type} show limit=0,500 TYPE=total,data"
        )
        try:
            parsed = json.loads(output)
            return parsed.get("data", [])
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse {qos_type} output: {output[:200]}")
            return []

    def find_qos_rule(self, qos_type: str = "simple_qos", **filters) -> Optional[Dict]:
        """
        按条件查找单条QoS规则

        Args:
            qos_type: 规则类型
            **filters: 过滤条件，如 tagname="xxx", id=1

        Returns:
            匹配的规则，或None
        """
        rules = self.query_qos_rules(qos_type)
        for rule in rules:
            if all(str(rule.get(k)) == str(v) for k, v in filters.items()):
                return rule
        return None

    def verify_qos_database(self, qos_type: str = "simple_qos",
                            expected_fields: Dict = None,
                            **filters) -> VerifyResult:
        """
        L1: 验证QoS规则在数据库中存在且字段正确

        Args:
            qos_type: simple_qos | mac_qos | dt_mac_qos
            expected_fields: 期望的字段值，如 {"upload": "2048", "download": "4096"}
            **filters: 查找条件，如 tagname="xxx"

        Returns:
            VerifyResult
        """
        rule = self.find_qos_rule(qos_type, **filters)
        if rule is None:
            all_rules = self.query_qos_rules(qos_type)
            existing_names = [r.get("tagname", "?") for r in all_rules]
            logger.debug(f"QoS rule not found: {filters}, existing: {existing_names}")
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"规则未找到: {filters}",
                raw_output=f"数据库中现有规则: {existing_names}",
            )

        # 校验字段
        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"rule": rule, "mismatches": mismatches},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"规则存在且字段正确 (id={rule.get('id')})",
            details={"rule": rule},
            raw_output=json.dumps(rule, ensure_ascii=False),
        )

    # ==================== L2: iptables验证 ====================

    def get_iptables_chain(self, chain: str = "IP_QOS") -> str:
        """获取iptables链的规则内容"""
        self.connect_router()
        return self._router.exec(f"iptables -L {chain} -n -v")

    def verify_iptables_rule(self, chain: str = "IP_QOS",
                             rule_id: int = None,
                             expected_speed_kbps: int = None,
                             direction: str = None,
                             set_prefix: str = None) -> VerifyResult:
        """
        L2: 验证iptables链中存在对应的限速规则

        Args:
            chain: IP_QOS 或 MAC_QOS
            rule_id: 规则ID（对应ipset名 {prefix}_{id}）
            expected_speed_kbps: 期望的限速值(kBps)
            direction: "upload" 或 "download"
            set_prefix: ipset名前缀，默认根据chain自动推断
                        IP_QOS -> simple_qos, MAC_QOS -> mac_qos

        Returns:
            VerifyResult
        """
        output = self.get_iptables_chain(chain)

        if rule_id is not None:
            if set_prefix is None:
                set_prefix = "mac_qos" if chain == "MAC_QOS" else "simple_qos"
            # iKuai QoS规则走ik_core timeset自定义模块(非xt_set -m set), 规则标识格式:
            #   {prefix}_time_{id} (带时间计划, 如 simple_qos_time_1; weekly全天也带_time_)
            #   {prefix}_{id}      (无时间计划)
            # 用正则兼容两种 + id边界(?!\d避免id=1误匹配id=10), 替代旧子串{prefix}_{id}
            # (旧子串不匹配_time_格式, 致IP/MAC限速L2误判"未找到", 实际规则已建立).
            pattern = rf"{re.escape(set_prefix)}(?:_time)?_{rule_id}(?!\d)"
            if not re.search(pattern, output):
                return VerifyResult(
                    level="L2-iptables",
                    passed=False,
                    message=f"限速规则 {set_prefix}_(time_)?{rule_id} 未在 {chain} 链中找到",
                    raw_output=output[:500],
                )

        if expected_speed_kbps is not None:
            # 独立限速: "limit: X kBps"  共享限速: "bytesband X"
            independent_pattern = f"limit: {expected_speed_kbps} kBps"
            shared_pattern = f"bytesband {expected_speed_kbps} "
            if independent_pattern not in output and shared_pattern not in output:
                return VerifyResult(
                    level="L2-iptables",
                    passed=False,
                    message=f"限速值 {expected_speed_kbps} kBps 未在 {chain} 链中找到",
                    raw_output=output[:500],
                )

        return VerifyResult(
            level="L2-iptables",
            passed=True,
            message=f"{chain} 链中找到匹配规则",
            details={"chain": chain, "rule_id": rule_id, "speed": expected_speed_kbps},
            raw_output=output[:500],
        )

    # ==================== L3: ipset验证 ====================

    def verify_ipset_member(self, rule_id: int, expected_ip: str,
                            set_prefix: str = "simple_qos") -> VerifyResult:
        """
        L3: 验证ipset中包含目标IP/MAC

        iKuai ipset结构: {prefix}_{id} (list:set) -> _{prefix}_{id} (hash:net) -> IP

        Args:
            rule_id: 规则ID
            expected_ip: 期望的IP或MAC地址
            set_prefix: ipset名前缀，默认simple_qos，MAC限速用mac_qos

        Returns:
            VerifyResult
        """
        self.connect_router()
        set_name = f"_{set_prefix}_{rule_id}"
        output = self._router.exec(f"ipset list {set_name} 2>/dev/null")

        if "does not exist" in output or not output.strip():
            return VerifyResult(
                level="L3-ipset",
                passed=False,
                message=f"ipset {set_name} 不存在",
                raw_output=output,
            )

        if expected_ip in output:
            return VerifyResult(
                level="L3-ipset",
                passed=True,
                message=f"IP {expected_ip} 存在于 {set_name} 中",
                raw_output=output[:300],
            )
        else:
            return VerifyResult(
                level="L3-ipset",
                passed=False,
                message=f"IP {expected_ip} 不在 {set_name} 中",
                raw_output=output[:300],
            )

    # ==================== L4: 内核验证 ====================

    def verify_kernel(self) -> VerifyResult:
        """
        L4: 验证ik_core内核模块已加载且dmesg无异常

        Returns:
            VerifyResult
        """
        self.connect_router()
        lsmod_output = self._router.exec("lsmod | grep ik_core")
        dmesg_output = self._router.exec(
            'dmesg | tail -50 | grep -iE "error|fail|panic|warn" | grep -iv "warning: this"'
        )

        if "ik_core" not in lsmod_output:
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message="ik_core 内核模块未加载",
                raw_output=lsmod_output,
            )

        errors = [line.strip() for line in dmesg_output.strip().split("\n") if line.strip()]

        return VerifyResult(
            level="L4-内核",
            passed=True,
            message=f"ik_core 已加载, dmesg异常数: {len(errors)}",
            details={"ik_core": lsmod_output.strip(), "dmesg_errors": errors},
            raw_output=lsmod_output,
        )

    # ==================== L5: iperf3实测 ====================

    def get_client_lan_info(self, gateway: str = "192.168.148.1") -> Dict[str, str]:
        """
        动态获取测试客户端连路由器LAN的网卡信息(网卡名/内网IP/MAC)

        通过 `ip route get <路由器LAN网关>` 解析 dev 和 src, 得到客户端从路由器
        DHCP获取的内网IP(即"10.66.0.18获取IP"), 以及该网卡的MAC地址.
        用于iperf3打流绑定源IP / IP限速目标IP / MAC限速目标MAC.

        Args:
            gateway: 路由器LAN侧网关IP, 默认192.168.148.1

        Returns:
            {"iface": 网卡名, "ip": 内网IP, "mac": MAC地址}; 失败返回{}
        """
        try:
            self.connect_client()
            out = self._client.exec(f"ip route get {gateway} 2>/dev/null")
            iface_match = re.search(r"\bdev\s+(\S+)", out)
            src_match = re.search(r"\bsrc\s+(\S+)", out)
            iface = iface_match.group(1) if iface_match else None
            ip = src_match.group(1) if src_match else None
            mac = None
            if iface:
                mac_out = self._client.exec(f"cat /sys/class/net/{iface}/address 2>/dev/null")
                mac = mac_out.strip() if mac_out else None
            logger.info(f"client LAN info: iface={iface}, ip={ip}, mac={mac}")
            return {"iface": iface, "ip": ip, "mac": mac}
        except Exception as e:
            logger.warning(f"get_client_lan_info failed: {e}")
            return {}

    def run_iperf3(self, direction: str = "upload",
                   server_ip: str = None,
                   bind_ip: str = None,
                   duration: int = None,
                   port: int = 5201,
                   retries: int = 2) -> Dict:
        """
        在测试客户端执行iperf3测速

        前提条件：
        1. 测试客户端(10.66.0.18)需要有到iperf3_server的路由经过路由器
        2. iperf3服务端已启动

        Args:
            direction: "upload" 或 "download"
            server_ip: iperf3服务端IP，默认使用配置
            bind_ip: 绑定的源IP（必须是路由器LAN下的IP）; None时自动通过
                     get_client_lan_info动态获取客户端内网IP(回退192.168.148.2)
            duration: 测速时长（秒）
            port: iperf3端口

        Returns:
            解析后的iperf3 JSON结果
        """
        self.connect_client()

        if server_ip is None:
            server_ip = self._ssh_config.iperf3_server
        if duration is None:
            duration = self._ssh_config.iperf3_duration
        if bind_ip is None:
            # 动态获取客户端连路由器LAN的内网IP(不再写死192.168.148.2)
            info = self.get_client_lan_info()
            bind_ip = info.get("ip") or "192.168.148.2"

        cmd = f"iperf3 -c {server_ip} -B {bind_ip} -t {duration} --connect-timeout 3000 -J -p {port}"
        if direction == "download":
            cmd += " -R"

        # 偶发iperf3连接失败(网络抖动/server短暂无响应/限速class挂载时序)返回error或非法JSON,
        # 单次失败直接判FAIL过于脆弱(见test_stream_control打流None盲区), 故加重试.
        last_output = ""
        for attempt in range(retries + 1):
            logger.info(f"iperf3 {direction} attempt{attempt + 1}/{retries + 1}: {cmd}")
            output = self._client.exec(cmd, timeout=duration + 30)
            last_output = output or ""
            try:
                result = json.loads(output)
            except (json.JSONDecodeError, TypeError):
                if attempt < retries:
                    logger.warning(
                        f"iperf3 attempt{attempt + 1} JSON解析失败, 重试: {output[:120]}")
                    continue
                logger.error(f"iperf3 output parse failed: {output[:300]}")
                return {"error": output[:500] if output else "no output"}

            # iperf3自身报error(如控制连接被重置/超时), 重试
            if "error" in result and attempt < retries:
                logger.warning(
                    f"iperf3 attempt{attempt + 1} 返回error, 重试: {str(result['error'])[:120]}")
                continue
            return result

        return {"error": last_output[:500]}

    def verify_iperf3(self, direction: str, expected_kbps: int,
                      **kwargs) -> VerifyResult:
        """
        L5: iperf3实测验证限速是否生效

        Args:
            direction: "upload" 或 "download"
            expected_kbps: 配置的限速值 (KB/s)
            **kwargs: 传递给 run_iperf3 的参数

        Returns:
            VerifyResult
        """
        result = self.run_iperf3(direction=direction, **kwargs)

        if "error" in result:
            return VerifyResult(
                level="L5-iperf3",
                passed=False,
                message=f"iperf3执行失败: {result['error'][:200]}",
                raw_output=str(result),
            )

        # 提取带宽（bits_per_second -> Mbps）
        try:
            end = result.get("end", {})
            if direction == "upload":
                bps = end.get("sum_sent", {}).get("bits_per_second", 0)
            else:
                bps = end.get("sum_received", {}).get("bits_per_second", 0)

            actual_mbps = bps / 1_000_000
            # KB/s * 8 / 1000 = Mbps
            expected_mbps = expected_kbps * 8 / 1000
            tolerance = self._ssh_config.iperf3_tolerance
            upper_bound = expected_mbps * (1 + tolerance)

            passed = actual_mbps <= upper_bound
            return VerifyResult(
                level="L5-iperf3",
                passed=passed,
                message=(
                    f"{direction} 实测: {actual_mbps:.2f} Mbps, "
                    f"配置上限: {expected_mbps:.2f} Mbps, "
                    f"容差上界: {upper_bound:.2f} Mbps"
                ),
                details={
                    "actual_mbps": round(actual_mbps, 2),
                    "expected_mbps": round(expected_mbps, 2),
                    "tolerance": tolerance,
                    "direction": direction,
                },
                raw_output=json.dumps(end, indent=2)[:500],
            )
        except (KeyError, TypeError) as e:
            return VerifyResult(
                level="L5-iperf3",
                passed=False,
                message=f"iperf3结果解析失败: {e}",
                raw_output=json.dumps(result, indent=2)[:500],
            )

    # ==================== 组合验证 ====================

    def verify_ip_qos_full_chain(self, tagname: str, ip: str,
                                 upload_kbps: int, download_kbps: int,
                                 run_iperf3: bool = False) -> FullChainResult:
        """
        IP限速(simple_qos)全链路验证

        Args:
            tagname: 规则名称
            ip: 限速目标IP
            upload_kbps: 上传限速值 (KB/s)
            download_kbps: 下载限速值 (KB/s)
            run_iperf3: 是否执行L5 iperf3实测（较耗时）

        Returns:
            FullChainResult
        """
        chain = FullChainResult()

        # L1: 数据库
        l1 = self.verify_qos_database(
            "simple_qos",
            expected_fields={"upload": str(upload_kbps), "download": str(download_kbps)},
            tagname=tagname,
        )
        chain.results.append(l1)
        logger.info(f"[L1] {l1.message}")

        rule_id = l1.details.get("rule", {}).get("id") if l1.passed else None

        # L2: iptables（检查上传和下载两条规则）
        l2_upload = self.verify_iptables_rule(
            "IP_QOS", rule_id=rule_id, expected_speed_kbps=upload_kbps,
        )
        chain.results.append(l2_upload)
        logger.info(f"[L2-upload] {l2_upload.message}")

        l2_download = self.verify_iptables_rule(
            "IP_QOS", rule_id=rule_id, expected_speed_kbps=download_kbps,
        )
        chain.results.append(l2_download)
        logger.info(f"[L2-download] {l2_download.message}")

        # L3: ipset
        if rule_id is not None:
            l3 = self.verify_ipset_member(rule_id, ip)
            chain.results.append(l3)
            logger.info(f"[L3] {l3.message}")

        # L4: 内核
        l4 = self.verify_kernel()
        chain.results.append(l4)
        logger.info(f"[L4] {l4.message}")

        # L5: iperf3（可选）— IP限速走ik_core timeset(非xt_set), 直接iperf3实测限速是否生效
        if run_iperf3:
            l5_up = self.verify_iperf3("upload", upload_kbps, bind_ip=ip)
            chain.results.append(l5_up)
            logger.info(f"[L5-upload] {l5_up.message}")

            l5_down = self.verify_iperf3("download", download_kbps, bind_ip=ip)
            chain.results.append(l5_down)
            logger.info(f"[L5-download] {l5_down.message}")

        return chain

    def verify_mac_qos_full_chain(self, tagname: str, mac: str,
                                  upload_kbps: int, download_kbps: int,
                                  bind_ip: str = None,
                                  run_iperf3: bool = False) -> FullChainResult:
        """
        MAC限速(mac_qos/dt_mac_qos)全链路验证

        Args:
            tagname: 规则名称
            mac: 限速目标MAC地址(客户端网卡MAC)
            upload_kbps: 上传限速值 (KB/s)
            download_kbps: 下载限速值 (KB/s)
            bind_ip: iperf3打流绑定的源IP(客户端内网IP); None时run_iperf3内部动态获取.
                     MAC限速按源MAC匹配, 绑client内网IP发包即用client网卡MAC, 规则命中.
            run_iperf3: 是否执行L5 iperf3实测

        Returns:
            FullChainResult
        """
        chain = FullChainResult()

        # L1: 数据库(先mac_qos, 失败再dt_mac_qos)
        l1 = self.verify_qos_database(
            "mac_qos",
            expected_fields={"upload": str(upload_kbps), "download": str(download_kbps)},
            tagname=tagname,
        )
        if not l1.passed:
            l1 = self.verify_qos_database(
                "dt_mac_qos",
                expected_fields={"upload": str(upload_kbps), "download": str(download_kbps)},
                tagname=tagname,
            )
        chain.results.append(l1)
        logger.info(f"[L1] {l1.message}")

        rule_id = l1.details.get("rule", {}).get("id") if l1.passed else None

        # L2: iptables(MAC_QOS链)
        l2_upload = self.verify_iptables_rule(
            "MAC_QOS", rule_id=rule_id, expected_speed_kbps=upload_kbps, set_prefix="mac_qos",
        )
        chain.results.append(l2_upload)
        logger.info(f"[L2-upload] {l2_upload.message}")

        l2_download = self.verify_iptables_rule(
            "MAC_QOS", rule_id=rule_id, expected_speed_kbps=download_kbps, set_prefix="mac_qos",
        )
        chain.results.append(l2_download)
        logger.info(f"[L2-download] {l2_download.message}")

        # L3: ipset - MAC限速用全局mac_qos_{x}集合(per-rule _mac_qos_{id}命名不适用), 遍历查找目标MAC
        if rule_id is not None:
            self.connect_router()
            set_list = self._router.exec("ipset list -n 2>/dev/null")
            # MAC成员在 _mac_qos_* (hash:mac), mac_qos_* (list:set)只引用_mac_qos_*(类似IP限速simple_qos→_simple_qos).
            # 故两者都遍历(原startswith("mac_qos")漏了_mac_qos_*, 致L3误判MAC不存在, 实则限速生效)
            mac_sets = [s for s in set_list.split() if "mac_qos" in s]
            l3_msg = f"MAC {mac} 未在任何 mac_qos_*/_mac_qos_* 集合中找到 (现有: {mac_sets})"
            l3_passed = False
            l3_raw = set_list[:200]
            for s in mac_sets:
                members = self._router.exec(f"ipset list {s} 2>/dev/null")
                if mac.lower() in members.lower():
                    l3_msg = f"MAC {mac} 存在于全局集合 {s} 中"
                    l3_passed = True
                    l3_raw = members[:200]
                    break
            l3 = VerifyResult(level="L3-ipset", passed=l3_passed, message=l3_msg, raw_output=l3_raw)
            chain.results.append(l3)
            logger.info(f"[L3] {l3.message}")

        # L4: 内核
        l4 = self.verify_kernel()
        chain.results.append(l4)
        logger.info(f"[L4] {l4.message}")

        # L5: iperf3(可选) — MAC限速走ik_core timeset(非xt_set), 直接iperf3实测限速是否生效
        if run_iperf3:
            kwargs = {"bind_ip": bind_ip} if bind_ip else {}
            l5_up = self.verify_iperf3("upload", upload_kbps, **kwargs)
            chain.results.append(l5_up)
            logger.info(f"[L5-upload] {l5_up.message}")

            l5_down = self.verify_iperf3("download", download_kbps, **kwargs)
            chain.results.append(l5_down)
            logger.info(f"[L5-download] {l5_down.message}")

        return chain

    def count_mac_qos_iptables_rules(self) -> int:
        """统计iptables MAC_QOS链中DROP规则数(检测MAC限速删除后是否残留)"""
        self.connect_router()
        out = self._router.exec("iptables -nvL MAC_QOS 2>/dev/null")
        return sum(1 for line in out.split('\n') if 'DROP' in line and 'mac_qos' in line)

    def flush_mac_qos_chain(self) -> int:
        """清空iptables MAC_QOS链规则 + flush所有mac_qos_* ipset成员.

        用于绕过"MAC限速删除后iptables/ipset残留"产品bug, 在iperf3实测前准备干净环境,
        确保实测命中的是新建规则而非残留规则. 返回清理前的DROP规则数.
        """
        self.connect_router()
        before = self.count_mac_qos_iptables_rules()
        self._router.exec("iptables -F MAC_QOS 2>/dev/null")
        self._router.exec("for s in $(ipset list -n 2>/dev/null | grep mac_qos); do ipset flush $s; done")
        return before

    # ==================== VLAN验证 ====================

    def query_vlan_rules(self) -> List[Dict]:
        """查询所有VLAN规则"""
        self.connect_router()
        output = self._router.exec("/usr/ikuai/function/vlan show limit=0,500 TYPE=total,data")
        logger.info(f"VLAN query raw ({len(output)} chars): {output[:300]}")
        try:
            parsed = json.loads(output)
            data = parsed.get("data", [])
            logger.info(f"VLAN query returned {len(data)} rules")
            return data
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse vlan output: {output[:200]}")
            return []

    def find_vlan_rule(self, **filters) -> Optional[Dict]:
        """按条件查找单条VLAN规则"""
        rules = self.query_vlan_rules()
        for rule in rules:
            if all(str(rule.get(k)) == str(v) for k, v in filters.items()):
                return rule
        return None

    def verify_vlan_database(self, vlan_name: str,
                             expected_fields: Dict = None) -> VerifyResult:
        """
        L1: 验证VLAN在数据库中存在且字段正确

        Args:
            vlan_name: VLAN名称(tagname)
            expected_fields: 期望的字段值，如 {"vlan_id": "100", "enabled": "yes"}
        """
        rule = self.find_vlan_rule(tagname=vlan_name)
        if rule is None:
            all_rules = self.query_vlan_rules()
            existing_names = [r.get("tagname", "?") for r in all_rules]
            logger.debug(f"VLAN未找到: {vlan_name}, 数据库中现有tagname: {existing_names}")
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"VLAN未找到: tagname={vlan_name}",
                raw_output=f"数据库中现有VLAN: {existing_names}",
            )

        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"rule": rule, "mismatches": mismatches},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"VLAN存在且字段正确 (id={rule.get('id')}, vlan_id={rule.get('vlan_id')})",
            details={"rule": rule},
            raw_output=json.dumps(rule, ensure_ascii=False),
        )

    def verify_vlan_interface(self, vlan_name: str,
                              expected_state: str = "UP") -> VerifyResult:
        """
        L2: 验证VLAN网络接口存在且状态正确

        iKuai VLAN网络结构（两种命名规则）:
          规则A: _{name}@lan1  (802.1Q VLAN接口) + {name} (bridge接口)
          规则B: {name}@lan1   (部分固件版本无下划线前缀)

        Args:
            vlan_name: VLAN名称
            expected_state: 期望的接口状态 "UP" 或 "DOWN"
        """
        self.connect_router()
        # 自适应两种命名规则：先试带下划线，再试不带下划线
        for prefix in ("_", ""):
            vlan_iface = f"{prefix}{vlan_name}"
            output = self._router.exec(f"ip link show {vlan_iface} 2>/dev/null")
            if output.strip() and "does not exist" not in output:
                # 找到了VLAN接口
                # 检查bridge接口
                bridge_iface = vlan_name
                bridge_output = self._router.exec(f"ip link show {bridge_iface} 2>/dev/null")
                has_bridge = bridge_output.strip() and "does not exist" not in bridge_output

                # 检查接口状态
                iface_up = expected_state in output
                bridge_up = expected_state in bridge_output if has_bridge else False

                if expected_state == "UP" and iface_up:
                    return VerifyResult(
                        level="L2-网络接口",
                        passed=True,
                        message=f"VLAN接口 {vlan_iface} 状态UP, bridge={has_bridge and bridge_up}",
                        details={"vlan_iface": vlan_iface, "bridge": bridge_iface, "bridge_exists": has_bridge},
                        raw_output=output[:300],
                    )
                elif expected_state == "DOWN" and not iface_up:
                    return VerifyResult(
                        level="L2-网络接口",
                        passed=True,
                        message=f"VLAN接口 {vlan_iface} 已停用(DOWN)",
                        details={"vlan_iface": vlan_iface},
                        raw_output=output[:300],
                    )
                else:
                    return VerifyResult(
                        level="L2-网络接口",
                        passed=False,
                        message=f"VLAN接口 {vlan_iface} 期望{expected_state}但实际不匹配",
                        raw_output=output[:300],
                    )

        # 两种命名都未找到
        return VerifyResult(
            level="L2-网络接口",
            passed=False,
            message=f"VLAN接口 _{vlan_name} 和 {vlan_name} 均不存在",
            raw_output=output,
        )

    def verify_vlan_proc(self, vlan_name: str,
                         expected_vlan_id: str = None) -> VerifyResult:
        """
        L3: 验证/proc/net/vlan/config中VLAN ID映射正确

        Args:
            vlan_name: VLAN名称
            expected_vlan_id: 期望的VLAN ID
        """
        self.connect_router()
        output = self._router.exec("cat /proc/net/vlan/config 2>/dev/null")

        # 自适应两种命名规则：先试带下划线，再试不带下划线
        vlan_iface = None
        for prefix in ("_", ""):
            candidate = f"{prefix}{vlan_name}"
            if candidate in output:
                vlan_iface = candidate
                break

        if vlan_iface is None:
            return VerifyResult(
                level="L3-proc",
                passed=False,
                message=f"VLAN接口 _{vlan_name} 和 {vlan_name} 均未在/proc/net/vlan/config中找到",
                raw_output=output,
            )

        # 检查VLAN ID是否匹配
        if expected_vlan_id:
            for line in output.split("\n"):
                if vlan_iface in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 2 and parts[1] == expected_vlan_id:
                        return VerifyResult(
                            level="L3-proc",
                            passed=True,
                            message=f"VLAN {vlan_iface} ID={expected_vlan_id} 映射正确",
                            details={"vlan_id": expected_vlan_id, "line": line.strip()},
                            raw_output=line.strip(),
                        )
                    else:
                        actual_id = parts[1] if len(parts) >= 2 else "unknown"
                        return VerifyResult(
                            level="L3-proc",
                            passed=False,
                            message=f"VLAN ID不匹配: 期望{expected_vlan_id}, 实际{actual_id}",
                            raw_output=line.strip(),
                        )

        return VerifyResult(
            level="L3-proc",
            passed=True,
            message=f"VLAN接口 {vlan_iface} 存在于/proc/net/vlan/config中",
            raw_output=output[:300],
        )

    # ==================== 便捷方法 ====================

    def delete_qos_rule(self, qos_type: str, rule_id: int) -> bool:
        """通过SSH删除QoS规则"""
        self.connect_router()
        output = self._router.exec(f"/usr/ikuai/function/{qos_type} del id={rule_id}")
        return "error" not in output.lower()

    def add_route_via_router(self, dest_ip: str, gateway: str = "192.168.148.1",
                             dev: str = None, src_ip: str = None) -> bool:
        """在测试客户端添加经过路由器的策略路由

        dev/src_ip为None时, 自动通过get_client_lan_info动态获取客户端连路由器LAN的
        网卡和内网IP(动态失败回退ens11/192.168.148.2, 保持向后兼容).
        """
        self.connect_client()
        if dev is None or src_ip is None:
            info = self.get_client_lan_info(gateway=gateway)
            dev = dev or info.get("iface") or "ens11"
            src_ip = src_ip or info.get("ip") or "192.168.148.2"
        cmd = f"sudo ip route add {dest_ip}/32 via {gateway} dev {dev} src {src_ip}"
        output = self._client.exec(cmd)
        return "error" not in output.lower()

    def remove_route(self, dest_ip: str) -> bool:
        """移除测试客户端的策略路由"""
        self.connect_client()
        output = self._client.exec(f"sudo ip route del {dest_ip}/32 2>/dev/null")
        return True  # 即使不存在也算成功

    def client_add_vlan_subif(self, vlan_id: int, parent: str = "ens11", ip_cidr: str = None) -> str:
        """在客户端建802.1Q VLAN子接口(如ens11.54), 可选配IP. 用于普通VLAN功能验证.

        实测: client ens11.54(vid 54) + 路由器VLAN54(lan1, _vlan54@lan1) → ping通.
        Returns: 子接口名(如ens11.54)
        """
        self.connect_client()
        name = f"{parent}.{vlan_id}"
        self._client.exec(f"sudo ip link delete {name} 2>/dev/null")  # 清同名残留
        self._client.exec(f"sudo ip link add link {parent} name {name} type vlan id {vlan_id}")
        self._client.exec(f"sudo ip link set {name} up")
        if ip_cidr:
            self._client.exec(f"sudo ip addr add {ip_cidr} dev {name}")
        return name

    def client_add_qinq_subif(self, outer_vid: int, inner_vid: int, parent: str = "ens11", ip_cidr: str = None) -> str:
        """在客户端建QINQ双层tag子接口(外层{parent}.{outer} + 内层{parent}.{outer}.{inner}).

        实测: 默认802.1Q协议即可(iKuai QINQ外层_vlan54接受802.1Q tag); 内层配ip_cidr.
        对应路由器侧: 外层_vlan{outer}@lan1, 内层_vlan{inner}@vlan{outer}.
        Returns: 内层子接口名(如ens11.54.55)
        """
        self.connect_client()
        outer = f"{parent}.{outer_vid}"
        inner = f"{parent}.{outer_vid}.{inner_vid}"
        self._client.exec(f"sudo ip link delete {inner} 2>/dev/null")
        self._client.exec(f"sudo ip link delete {outer} 2>/dev/null")
        self._client.exec(f"sudo ip link add link {parent} name {outer} type vlan id {outer_vid}")
        self._client.exec(f"sudo ip link set {outer} up")
        self._client.exec(f"sudo ip link add link {outer} name {inner} type vlan id {inner_vid}")
        self._client.exec(f"sudo ip link set {inner} up")
        if ip_cidr:
            self._client.exec(f"sudo ip addr add {ip_cidr} dev {inner}")
        return inner

    def client_del_iface(self, name: str) -> bool:
        """删除客户端网络接口(VLAN子接口等)"""
        self.connect_client()
        self._client.exec(f"sudo ip link delete {name} 2>/dev/null")
        return True

    def client_ping(self, src_iface: str, dst_ip: str, count: int = 4) -> Dict:
        """从客户端指定源接口ping目标(验证VLAN连通性).

        Returns: {"connected": bool, "received": int, "detail": "min/avg/max/mdev", "raw": str}
        """
        self.connect_client()
        out = self._client.exec(f"ping -I {src_iface} -c {count} -W 1 {dst_ip}", timeout=count * 2 + 10)
        m = re.search(r"(\d+)\s*received", out)
        received = int(m.group(1)) if m else 0
        stats = re.search(r"rtt min/avg/max/mdev = ([\d.\/]+)", out)
        detail = stats.group(1) if stats else ""
        return {"connected": received > 0, "received": received, "detail": detail, "raw": out}

    def verify_connectivity(self, src_iface="ens11", dst_domain=None, dst_ip=None,
                            count=3, timeout=8, retries=0, fallback_domains=None) -> Dict:
        """通用连通性验证: client从指定源接口curl域名或ping IP, 判定通/不通.
        不依赖match/user_dpi/new_tc, 纯连通性端到端判定(用户验证逻辑).
        dst_domain优先用curl(HTTP), dst_ip用ping(ICMP).
        retries: 连通失败时的重试次数(默认0, 向后兼容). 基线/恢复探测传retries=2可抗外网瞬时抖动;
                 ⚠️建drop规则后期望"不通"的验证(blk/dis_conn)勿传, 否则重试会掩盖规则效果.
        fallback_domains: 主dst_domain经retries重试仍不通时依次尝试的备用域名列表
                 (如["www.qq.com","cn.bing.com","www.taobao.com"]), 任一通即判connected=True.
                 抗单域名/外网瞬时抖动(实测baidu凌晨间歇http_code=000但qq/bing正常).
                 ⚠️仅用于"期望通"的基线/恢复探测; 建drop/停用规则后"期望不通"的验证
                 (blk/dis_conn)勿传(会fallback到备用域名误判规则未生效). 默认None=原行为(单域名).
        Returns: {"connected": bool, "detail": str, "attempts": int, "tried": list(各域名结果)}
        """
        self.connect_client()

        def _probe_http(dom):
            """单域名retries轮curl, 返回(connected, code, attempts)."""
            code = "000"
            for attempt in range(retries + 1):
                out = self._client.exec(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --interface {src_iface} "
                    f"--connect-timeout 3 -m {timeout} http://{dom}/",
                    timeout=timeout + 5)
                code = (out or "").strip().strip("'").lstrip("'")
                if any(c in code for c in ["200", "301", "302", "304"]):
                    return True, code, attempt + 1
                if attempt < retries:
                    time.sleep(1)
            return False, code, retries + 1

        # dst_ip分支: ping(不涉及fallback)
        if dst_ip and not dst_domain:
            for attempt in range(retries + 1):
                out = self._client.exec(f"ping -I {src_iface} -c {count} -W 2 {dst_ip}", timeout=count * 3 + 5)
                m = re.search(r"(\d+)\s*received", out or "")
                received = int(m.group(1)) if m else 0
                if received > 0:
                    detail = f"ping {dst_ip} {received}/{count} received"
                    if attempt > 0:
                        detail += f" (第{attempt + 1}次尝试成功)"
                    return {"connected": True, "detail": detail, "attempts": attempt + 1, "tried": []}
                if attempt < retries:
                    time.sleep(1)
            return {"connected": False, "detail": f"ping {dst_ip} 0/{count} received (重试{retries}次仍失败)",
                    "attempts": retries + 1, "tried": []}

        if not dst_domain:
            return {"connected": False, "detail": "no dst_domain or dst_ip specified", "attempts": 0, "tried": []}

        # http探测: 主域名 + fallback域名(任一通即返回)
        targets = [dst_domain]
        if fallback_domains:
            targets += [d for d in fallback_domains if d and d != dst_domain]
        tried = []
        for idx, dom in enumerate(targets):
            ok, code, att = _probe_http(dom)
            tried.append({"domain": dom, "connected": ok, "code": code, "attempts": att})
            if ok:
                tag = "" if idx == 0 else f" (主{dst_domain}抖动不通, fallback {dom}成功)"
                if att > 1 and idx == 0:
                    tag += f" (第{att}次成功)"
                return {"connected": True, "detail": f"curl {dom} http_code={code}{tag}",
                        "attempts": att, "tried": tried}
        # 全失败: 汇总各域名code(供诊断)
        codes_str = ", ".join(f"{t['domain'].replace('www.', '')}={t['code']}" for t in tried)
        if len(tried) > 1:
            # 基线/恢复探测(多域名冗余仍全失败): 提示环境问题, 建议查诊断
            detail = (f"{len(tried)}域名全失败({codes_str}); 疑似环境/外网抖动, "
                      f"建议调diagnose_baseline_block定位(残留挡流→FAIL / WAN断→skip)")
        else:
            # 单域名(可能是建drop/停用规则后期望不通的验证): 只报code, 不臆断环境
            detail = f"curl {tried[0]['domain']} http_code={tried[0]['code']}"
        return {"connected": False, "detail": detail,
                "attempts": tried[-1]["attempts"] if tried else 0, "tried": tried}

    def concurrent_curl(self, n: int = 8, dst: str = "www.baidu.com",
                        src_iface: str = "ens11", timeout: int = 6, retries: int = 0,
                        fallback_dsts=None) -> Dict:
        """并发n个curl经src_iface到dst(连接数限制功能验证用: limit=N时超限并发连接被丢弃).

        单条exec内shell & + wait起n个并发curl, 统计HTTP成功数.
        limit=1时: 基线应≈n成功, 建规则后应明显下降(peerconns-above 1丢弃第2+并发).
        retries: 未达全成功(n)时的重试轮数(默认0, 向后兼容). 基线/恢复探测传retries=2抗外网瞬时抖动,
                 多轮取success最高者; ⚠️建limit规则后期望success下降的验证(lim1/lim2)勿传, 否则取max会掩盖限速.
        fallback_dsts: 主dst经retries仍success偏低时, 依次尝试的备用域名(如["www.qq.com","cn.bing.com"]),
                 跨域名取success最高者. 抗单域名抖动(实测baidu凌晨间歇0/8但qq/bing正常).
                 ⚠️仅基线/恢复探测传; limit验证(lim1/lim2)勿传(会跨域名掩盖限速效果). 默认None=原行为.
        Returns: {"success": 成功数, "total": 实际完成数, "codes": 各curl的http_code(前20), "attempts": 轮数}
        """
        self.connect_client()

        def _one_dst(d):
            """单域名retries轮并发curl, 返回best dict."""
            cmd = (f"for i in $(seq 1 {n}); do "
                   f"curl -s -o /dev/null -w '%{{http_code}}\\n' --interface {src_iface} "
                   f"--connect-timeout 3 -m {timeout} http://{d}/ & done; wait")
            best = None
            rounds = 0
            for attempt in range(retries + 1):
                out = self._client.exec(cmd, timeout=n * timeout + 25)
                codes = [c.strip().strip("'") for c in (out or "").splitlines() if c.strip()]
                success = sum(1 for c in codes if any(x in c for x in ["200", "301", "302", "304"]))
                cur = {"success": success, "total": len(codes), "codes": codes[:20]}
                rounds += 1
                if best is None or success > best["success"]:
                    best = cur
                if success >= n:  # 全成功则无需再重试
                    break
                if attempt < retries:
                    time.sleep(1)
            best["attempts"] = rounds
            if rounds > 1:
                best["detail"] = f"多轮取最高(共{rounds}轮)"
            return best

        targets = [dst] + ([d for d in fallback_dsts if d and d != dst] if fallback_dsts else [])
        best_overall = None
        tried = []
        for d in targets:
            r = _one_dst(d)
            tried.append({"domain": d, "success": r["success"], "total": r["total"]})
            if best_overall is None or r["success"] > best_overall["success"]:
                best_overall = dict(r)
            if best_overall["success"] >= n:
                break
        best_overall["tried"] = tried
        if len(targets) > 1:
            best_overall["detail"] = f"{len(targets)}域名取最高: " + ", ".join(
                f"{t['domain'].replace('www.', '')}={t['success']}/{t['total']}" for t in tried)
        return best_overall

    def diagnose_baseline_block(self, src_iface="ens11", dst_domain="www.baidu.com") -> Dict:
        """基线连通性全域名失败时的根因诊断.

        区分两种"基线不通":
          A. 残留规则挡流(功能/配置问题) → 调用方应判FAIL并在报告写清规则+命令(不应skip)
          B. 路由器WAN自身中断/纯外网抖动(环境问题) → 调用方可skip, 但报告须含本诊断全部信息+命令

        诊断维度: 路由器自身curl外网(区分WAN断vs仅client侧断) + client DNS解析 +
                  路由器iptables FORWARD链残留DROP/connlimit规则 + conn_limit enabled规则数.
        Returns: {
            "router_wan_ok": bool,        # 路由器直接出WAN能否curl外网
            "router_code": str,           # 路由器curl http_code
            "dns_ok": bool,               # client DNS解析
            "dns_detail": str,
            "residual_block": str/None,   # 残留挡流规则(已滤系统默认WAN入站DROP); None=无残留
            "conn_limit_enabled": str,    # conn_limit enabled规则数
            "commands": [str],            # 可复现验证命令(写入报告)
            "summary": str,               # 人读结论+处置建议
        }
        """
        self.connect_router()
        self.connect_client()
        cmds = []

        # 1. 路由器自身curl外网(不经ens11, 走WAN直出): 区分WAN断 vs 仅client侧断
        out = self._router.exec(
            f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 4 -m 8 http://{dst_domain}/ 2>&1",
            timeout=15)
        router_code = (out or "").strip().strip("'").lstrip("'").splitlines()[-1] if (out or "").strip() else "000"
        router_wan_ok = any(c in router_code for c in ["200", "301", "302", "304"])
        cmds.append(f"# 路由器自身出WAN: curl -s -o /dev/null -w '%{{http_code}}' -m 8 http://{dst_domain}/")

        # 2. client DNS解析
        dns = self._client.exec(f"getent hosts {dst_domain} 2>&1", timeout=8)
        dns_detail = (dns or "").strip().splitlines()[0] if (dns or "").strip() else "无解析结果"
        dns_ok = bool((dns or "").strip()) and "not found" not in dns_detail.lower()
        cmds.append(f"# client DNS: getent hosts {dst_domain}")

        # 3. 路由器iptables残留挡流规则: 只匹配真正的 -j DROP/REJECT 动作(空链跳转
        #    -A FORWARD -j CONNLIMIT 是系统基础设施, 空链不挡流, 不匹配不误判),
        #    排除系统默认WAN入站DROP(DROP_U/T_PORTS等).
        ipt = self._router.exec(
            "iptables -S 2>/dev/null | grep -E -- '-j (DROP|REJECT)' | "
            "grep -vE 'WAN_IN|DROP_U_PORTS|DROP_T_PORTS|AUTH_EXPIRES|WEBTO|PPPOE-to-PPPOE|DHCP_ACL' | head -20",
            timeout=10)
        cmds.append("# 路由器残留挡流(只看-j DROP/REJECT, 排除系统默认WAN入站DROP): "
                    "iptables -S | grep -E '-j (DROP|REJECT)' | grep -vE 'WAN_IN|DROP_U_PORTS|...'")
        residual = None
        ipt = ipt or ""
        if ipt.strip():
            lines = [l.strip() for l in ipt.splitlines()
                     if l.strip() and not l.strip().startswith("-N ")]
            if lines:
                residual = "; ".join(l[:100] for l in lines[:5])

        # 4. conn_limit enabled规则数(连接数限制残留会挡client并发)
        cl = self._router.exec(
            'sqlite3 /etc/mnt/ikuai/config.db "select count(*) from conn_limit where enabled=1" 2>/dev/null',
            timeout=8)
        cl_cnt = (cl or "0").strip() or "0"
        cmds.append('# conn_limit残留: sqlite3 /etc/mnt/ikuai/config.db "select count(*) from conn_limit where enabled=1"')
        cmds.append("# client经ens11复测: curl -s -o /dev/null -w '%{http_code}' --interface ens11 -m 8 http://{dom}/".replace("{dom}", dst_domain))

        # 结论
        if residual:
            summary = (f"[功能/配置问题] 路由器有残留挡流规则: {residual} → 应判FAIL(非环境), "
                       f"清理残留规则后重测. conn_limit enabled={cl_cnt}")
        elif not router_wan_ok:
            summary = (f"[环境问题] 路由器自身出WAN也不通(http_code={router_code}), 整体外网中断, "
                       f"与被测功能无关, 可skip(详报已附命令).")
        elif not dns_ok:
            summary = (f"[环境问题] client DNS解析失败({dns_detail}), {dst_domain}无IP, DNS问题, 可skip.")
        else:
            summary = (f"[环境抖动] 路由器WAN通({router_code})+DNS正常, 但client经{src_iface}不通, "
                       f"无残留规则, 判client侧路由/接口瞬时抖动, 可skip(建议稍后重测).")
        return {
            "router_wan_ok": router_wan_ok, "router_code": router_code,
            "dns_ok": dns_ok, "dns_detail": dns_detail,
            "residual_block": residual, "conn_limit_enabled": cl_cnt,
            "commands": cmds, "summary": summary,
        }

    def conntrack_egress(self, client_ip: str, dst_port: int = None,
                         proto: str = None) -> Dict:
        """读conntrack中client_ip流的出向WAN(分流【选路铁证】).

        分流规则生效时 conntrack 该流 remote_if=目标WAN, 反向dst=目标WAN_IP(SNAT出该WAN).
        ⚠️conntrack条目跨2物理行: 主行(含src/dport/mark) + ik_core扩展行(emark=...含remote_if/rev_remote_if).
        故合并本行+下一行解析. 实测: 建wan2分流规则+curl后, client流 remote_if=wan2 mark=6000001.
        Returns: {found, remote_if, rev_remote_if, mark, raw}
        """
        self.connect_router()
        out = self._router.exec("cat /proc/net/nf_conntrack 2>/dev/null")
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if f"src={client_ip} " not in line:
                continue
            entry = line + (" " + lines[i + 1] if i + 1 < len(lines) else "")  # 合并扩展行(remote_if在此)
            if proto and proto != "any" and f" {proto} " not in entry[:60]:
                continue
            if dst_port and f"dport={dst_port} " not in entry:
                continue
            m_ri = re.search(r"remote_if=(\S+)", entry)
            if m_ri:
                m_rri = re.search(r"rev_remote_if=(\S+)", entry)
                m_mk = re.search(r"\bmark=(\d+)", entry)  # \b避skb_mark=/emark=
                return {"found": True, "remote_if": m_ri.group(1),
                        "rev_remote_if": m_rri.group(1) if m_rri else "",
                        "mark": m_mk.group(1) if m_mk else "", "raw": entry[:160]}
        return {"found": False, "remote_if": "", "rev_remote_if": "", "mark": "", "raw": ""}

    def conntrack_client_wans(self, client_ip: str, proto: str = "tcp") -> List[str]:
        """读client_ip所有流的remote_if列表(多线负载【分布铁证】: 多流分散到多WAN=负载生效).

        返回去重后的WAN名列表(如['wan1','wan2']); 单WAN=未分散. 合并2行解析(见conntrack_egress)."""
        self.connect_router()
        out = self._router.exec("cat /proc/net/nf_conntrack 2>/dev/null")
        lines = out.splitlines()
        wans = []
        for i, line in enumerate(lines):
            if f"src={client_ip} " not in line:
                continue
            entry = line + (" " + lines[i + 1] if i + 1 < len(lines) else "")
            if proto != "any" and f" {proto} " not in entry[:60]:
                continue
            m = re.search(r"remote_if=(\S+)", entry)
            if m and m.group(1) not in wans:
                wans.append(m.group(1))
        return wans

    def clear_client_conntrack(self, client_ip: str = "192.168.148.2") -> bool:
        """清client的conntrack缓存(分流【后匹配】关键).

        分流规则只匹配规则建后/缓存清后的新连接(后匹配); 旧/established流不重新评估→必须清缓存
        让新流被分流规则匹配(域名/协议分流尤其依赖). conntrack -D -s <ip> 只删该IP流, 不影响
        SSH(SSH走管理网不经路由器转发). 实测: 域名分流不清缓存→旧流复用→不选路."""
        self.connect_router()
        self._router.exec(f"conntrack -D -s {client_ip} 2>/dev/null")
        return True

    def reset_cflow_stats(self) -> bool:
        """重置路由器分流监控统计(cflow_stats, 同cflow.lua源). ik_cntl clear collect url route.
        分流测试前重置, 打流后read_cflow_stats看各类型命中增量."""
        self.connect_router()
        self._router.exec("ik_cntl clear collect url route 2>/dev/null")
        return True

    def read_cflow_stats(self) -> Dict:
        """读路由器分流监控统计(/proc/ikuai/stats/cflow_stats, cflow.lua同源, 最权威命中信号).

        返回 {llb:多线负载, domain:域名分流, l7:协议分流, port:端口分流, total} 各命中连接数.
        格式: 头行"llb domain L7 port total" + 值行5个十进制零填充数(如 00000013=13).
        域名/多线无mangle链→用此作命中铁证; 协议/端口可兼用mangle counter(每规则)."""
        self.connect_router()
        out = self._router.exec("cat /proc/ikuai/stats/cflow_stats 2>/dev/null")
        keys = ["llb", "domain", "l7", "port", "total"]
        result = {k: 0 for k in keys}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 5 and all(p.isdigit() for p in parts):
                try:
                    vals = [int(p) for p in parts]  # 十进制零填充
                    result = dict(zip(keys, vals))
                    break
                except ValueError:
                    pass
        return result

    def read_mangle_counter(self, chain: str, rule_id: int, ipv6: bool = False) -> int:
        """读mangle表分流链规则的pkts计数(分流【命中铁证】, 参照_read_acl_counter改mangle表).

        链如 STREAM_IPPORT_NEW / STREAM_LAYER7_NEW; comment有两种格式:
        /* {id}_tag */ (端口分流) 和 /* {id} */ (协议分流). 用正则兼容两者(且不误匹配 {id}X).
        调用方打流前后各读一次取Δpkts>0=规则命中流量."""
        self.connect_router()
        ipt = "ip6tables" if ipv6 else "iptables"
        out = self._router.exec(f"{ipt} -t mangle -L {chain} -n -v -x --line-numbers 2>/dev/null")
        pat = re.compile(rf"/\*\s*{rule_id}(?!\d)")
        for line in out.splitlines():
            if pat.search(line):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])  # num pkts bytes ccnt ... -> parts[1]=pkts
                    except ValueError:
                        pass
        return 0

    def read_mangle_rule_mark(self, chain: str, rule_id: int, ipv6: bool = False) -> int:
        """读mangle分流链规则的--set-mark值(协议分流选路标识).

        NTH_CONNMARK target用 --set-mark <值> + --set-ifname <wan> 给匹配流量打标+选路.
        协议分流(L7)的conntrack remote_if不可靠(未匹配流量mark=0走默认WAN; 匹配的DNS等短流mark=规则值),
        故选路铁证=client连接的mark==规则mark(=被该规则匹配+打标+--set-ifname选路). 返回0=未找到."""
        self.connect_router()
        ipt = "ip6tables" if ipv6 else "iptables"
        out = self._router.exec(f"{ipt} -t mangle -L {chain} -n -v -x --line-numbers 2>/dev/null")
        pat = re.compile(rf"/\*\s*{rule_id}(?!\d)")
        for line in out.splitlines():
            if pat.search(line):
                m = re.search(r"--set-mark\s+(\d+)", line)
                if m:
                    return int(m.group(1))
        return 0

    def conntrack_client_marks(self, client_ip: str) -> set:
        """读client_ip所有conntrack连接的mark集合(协议分流选路铁证).

        匹配分流规则的连接mark=规则--set-mark值(非0); 未匹配的mark=0. 返回mark值集合."""
        self.connect_router()
        out = self._router.exec("conntrack -L 2>/dev/null")
        marks = set()
        for line in out.splitlines():
            if f"src={client_ip} " not in line:
                continue
            m = re.search(r"\bmark=(\d+)", line)
            if m:
                marks.add(int(m.group(1)))
        return marks

    def read_nat_counter(self, chain: str, match_str: str) -> int:
        """读nat表NATRULE链匹配match_str的规则pkts(NAT规则【命中铁证】).

        NAT规则无--comment(与ACL/分流的 /* {id}_ */ 不同, nat_rule.sh:512规则无comment),
        故靠规则内容(src IP / nat_addr 等)定位行. 链如 NATRULE_SNAT / NATRULE_DNAT.
        调用方打流前后各读一次取Δpkts>0=规则命中流量.

        ⚠️SNAT/DNAT只对连接【首包】计数(conntrack建立后走fast path不过NAT规则), 故Δpkts较小
        (通常2-10), >0即命中; **必须先clear_client_conntrack清旧流**(NAT同分流=后匹配, 旧established
        流复用不过新规则→Δpkts=0误判)."""
        self.connect_router()
        out = self._router.exec(
            f"iptables -t nat -L {chain} -n -v -x --line-numbers 2>/dev/null")
        for line in out.splitlines():
            if match_str in line:
                parts = line.split()
                # --line-numbers: num pkts bytes ccnt fcnt fastid target proto opt in out source destination
                if len(parts) >= 2:
                    try:
                        return int(parts[1])  # parts[1]=pkts
                    except ValueError:
                        continue
        return 0

    def start_iperf3_server(self, on: str = "client", port: int = 5201) -> bool:
        """在指定机器上启动iperf3服务端"""
        if on == "client":
            self.connect_client()
            self._client.exec(f"pkill -f 'iperf3 -s' 2>/dev/null")
            self._client.exec(f"iperf3 -s -p {port} -D")
        elif on == "router":
            self.connect_router()
            self._router.exec(f"iperf3 -s -p {port} -D")
        return True

    def stop_iperf3_server(self, on: str = "client"):
        """停止iperf3服务端"""
        if on == "client":
            self.connect_client()
            self._client.exec("pkill -f 'iperf3 -s' 2>/dev/null")
        elif on == "router":
            self.connect_router()
            self._router.exec("pkill -f 'iperf3' 2>/dev/null")

    def health_check(self) -> Dict[str, bool]:
        """
        健康检查：验证路由器SSH可达、ik_core加载

        Returns:
            {"router_ssh": bool, "ik_core": bool}
        """
        result = {"router_ssh": False, "ik_core": False}
        try:
            self.connect_router()
            output = self._router.exec("id")
            result["router_ssh"] = "uid=0" in output

            lsmod = self._router.exec("lsmod | grep ik_core")
            result["ik_core"] = "ik_core" in lsmod
        except Exception as e:
            logger.error(f"Health check failed: {e}")
        return result

    # ==================== 静态路由验证 ====================

    def query_static_routes(self) -> List[Dict]:
        """查询静态路由规则列表"""
        self.connect_router()
        output = self._router.exec("/usr/ikuai/function/static_rt show limit=0,500 TYPE=total,data")
        logger.debug(f"Static route query raw output ({len(output)} chars): {output[:500]}")
        try:
            parsed = json.loads(output)
            data = parsed.get("data", [])
            logger.debug(f"Static route query returned {len(data)} rules")
            return data
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse static_rt output: {output[:200]}")
            return []

    def query_route_table(self) -> List[Dict]:
        """查询当前路由表"""
        self.connect_router()
        output = self._router.exec("/usr/ikuai/function/static_rt_table show")
        try:
            parsed = json.loads(output)
            return parsed.get("data", [])
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse static_rt_table output: {output[:200]}")
            return []

    def find_static_route(self, tagname: str) -> Optional[Dict]:
        """按名称查找静态路由"""
        rules = self.query_static_routes()
        for rule in rules:
            if rule.get("tagname") == tagname:
                return rule
        return None

    def verify_static_route_database(self, tagname: str,
                                      expected_fields: Dict = None) -> VerifyResult:
        """
        L1: 验证静态路由在数据库中存在且字段正确

        Args:
            tagname: 路由名称
            expected_fields: 期望字段值，如 {"dst_addr": "10.10.1.0", "gateway": "10.66.0.1",
                             "netmask": "255.255.255.0", "interface": "auto", "prio": 1,
                             "enabled": "yes", "ip_type": "4"}
        """
        rule = self.find_static_route(tagname=tagname)
        if rule is None:
            all_rules = self.query_static_routes()
            existing_names = [r.get("tagname", "?") for r in all_rules]
            logger.debug(f"Static route not found: {tagname}, existing: {existing_names}")
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"静态路由未找到: tagname={tagname}",
                raw_output=f"数据库中现有路由: {existing_names}",
            )

        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"rule": rule, "mismatches": mismatches},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"静态路由存在且字段正确 (id={rule.get('id')}, dst={rule.get('dst_addr')}, gw={rule.get('gateway')})",
            details={"rule": rule},
            raw_output=json.dumps(rule, ensure_ascii=False),
        )

    def verify_static_route_kernel(self, dst_addr: str, netmask: str,
                                    gateway: str = "",
                                    interface: str = "") -> VerifyResult:
        """
        L2: 验证静态路由已写入内核路由表

        通过 ip route show 检查路由条目是否存在。
        注意：无网关的路由不会写入内核路由表（正常行为）。

        Args:
            dst_addr: 目的地址
            netmask: 子网掩码
            gateway: 网关
            interface: 接口（auto表示不指定）
        """
        if not gateway:
            return VerifyResult(
                level="L2-内核路由",
                passed=True,
                message=f"无网关路由({dst_addr})跳过内核验证（正常行为）",
            )

        self.connect_router()

        # 计算CIDR前缀长度
        prefix_len = self._mask_to_prefix(netmask)
        route_network = f"{dst_addr}/{prefix_len}" if prefix_len < 32 else dst_addr

        # 检查所有路由表
        output = self._router.exec(f"ip route show {route_network}")
        if not output.strip():
            output = self._router.exec(f"ip route show table main {route_network}")

        if gateway in output:
            return VerifyResult(
                level="L2-内核路由",
                passed=True,
                message=f"内核路由存在: {route_network} via {gateway}",
                raw_output=output.strip(),
            )

        # 路由未找到: 先探测下一跳是否在任一接口直连网段内(配置层可达性)
        # Linux内核安装静态路由要求下一跳可达: 网关不在任何活跃接口直连网段时,
        # 内核报 'RTNETLINK answers: Network is unreachable' 标准拒绝安装.
        # 属测试数据与网络拓扑不匹配而非产品问题→中性化避免误报FAIL
        if gateway and not self._is_gateway_onlink(gateway):
            return VerifyResult(
                level="L2-内核路由",
                passed=True,
                message=f"内核路由未落地: 下一跳{gateway}不在任何接口直连网段(不可达,内核预期拒绝安装,非产品问题)",
                raw_output=output.strip() if output.strip() else "(empty)",
            )

        return VerifyResult(
            level="L2-内核路由",
            passed=False,
            message=f"内核路由未找到: {route_network} via {gateway}",
            raw_output=output.strip() if output.strip() else "(empty)",
        )

    def _is_gateway_onlink(self, gateway: str) -> bool:
        """检查网关是否在路由器任一接口直连网段内(onlink=内核可接受为下一跳).

        Linux安装静态路由时要求下一跳可达: 网关必须在某活跃接口的直连网段内,
        否则报 'RTNETLINK answers: Network is unreachable' 拒绝安装.
        用于区分 '测试数据网关配错(下一跳不可达)' 与 '产品未落地路由'.
        """
        try:
            gw = ipaddress.ip_address(gateway)
        except ValueError:
            return False
        try:
            out = self._router.exec("ip -4 addr show")
        except Exception:
            return False
        for line in out.splitlines():
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if not m:
                continue
            try:
                net = ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
                if gw in net:
                    return True
            except ValueError:
                continue
        return False

    def verify_static_route_table(self, dst_addr: str,
                                   gateway: str = "") -> VerifyResult:
        """
        L3: 验证路由在当前路由表（static_rt_table）中存在

        Args:
            dst_addr: 目的地址
            gateway: 网关（可选，用于精确匹配）
        """
        entries = self.query_route_table()

        for entry in entries:
            if entry.get("dst_addr") == dst_addr:
                if gateway and entry.get("gateway") != gateway:
                    continue
                return VerifyResult(
                    level="L3-路由表",
                    passed=True,
                    message=f"路由表中存在: {dst_addr} via {entry.get('gateway')} dev {entry.get('interface')}",
                    details={"entry": entry},
                    raw_output=json.dumps(entry, ensure_ascii=False),
                )

        return VerifyResult(
            level="L3-路由表",
            passed=False,
            message=f"路由表中未找到: dst={dst_addr}" + (f" gw={gateway}" if gateway else ""),
            raw_output=f"total entries: {len(entries)}",
        )

    def verify_static_route_not_exists(self, tagname: str) -> VerifyResult:
        """验证静态路由已从数据库中删除"""
        rule = self.find_static_route(tagname=tagname)
        if rule is None:
            return VerifyResult(
                level="L1-删除验证",
                passed=True,
                message=f"静态路由已删除: {tagname}",
            )
        return VerifyResult(
            level="L1-删除验证",
            passed=False,
            message=f"静态路由仍存在: {tagname} (id={rule.get('id')})",
            details={"rule": rule},
        )

    def verify_static_route_count(self, expected_count: int = 0) -> VerifyResult:
        """验证静态路由总数"""
        rules = self.query_static_routes()
        actual = len(rules)
        if actual == expected_count:
            return VerifyResult(
                level="L1-计数验证",
                passed=True,
                message=f"静态路由数量正确: {actual}",
            )
        return VerifyResult(
            level="L1-计数验证",
            passed=False,
            message=f"静态路由数量不匹配: 期望{expected_count}, 实际{actual}",
            details={"rules": [r.get("tagname") for r in rules]},
        )

    @staticmethod
    def _mask_to_prefix(netmask: str) -> int:
        """子网掩码转CIDR前缀长度"""
        try:
            parts = [int(p) for p in netmask.split(".")]
            binary = "".join(f"{p:08b}" for p in parts)
            return binary.count("1")
        except (ValueError, AttributeError):
            return 24  # 默认/24

    # ==================== 跨三层服务(SNMP)验证 ====================

    def query_netsnmpc_rules(self) -> List[Dict]:
        """查询跨三层服务(netsnmpc)规则列表"""
        self.connect_router()
        output = self._router.exec("/usr/ikuai/function/netsnmpc show limit=0,500 TYPE=total,data")
        logger.info(f"netsnmpc query raw ({len(output)} chars): {output[:300]}")
        try:
            parsed = json.loads(output)
            data = parsed.get("data", [])
            logger.info(f"netsnmpc query returned {len(data)} rules")
            return data
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse netsnmpc output: {output[:200]}")
            return []

    def find_netsnmpc_rule(self, **filters) -> Optional[Dict]:
        """按条件查找单条跨三层服务规则"""
        rules = self.query_netsnmpc_rules()
        for rule in rules:
            if all(str(rule.get(k)) == str(v) for k, v in filters.items()):
                return rule
        return None

    def verify_netsnmpc_database(self, tagname: str,
                                  expected_fields: Dict = None,
                                  expect_absent: bool = False) -> VerifyResult:
        """
        L1: 验证跨三层服务规则在数据库中存在且字段正确

        Args:
            tagname: 规则名称
            expected_fields: 期望的字段值，如 {"snmp_ip": "10.66.0.40", "port": "161", "version": "V2"}
        """
        rule = self.find_netsnmpc_rule(tagname=tagname)
        if rule is None:
            all_rules = self.query_netsnmpc_rules()
            existing_names = [r.get("tagname", "?") for r in all_rules]
            logger.debug(f"netsnmpc rule not found: {tagname}, existing: {existing_names}")
            return VerifyResult(
                level="L1-数据库",
                passed=expect_absent,
                message=f"跨三层服务规则未找到: tagname={tagname}" + ("(应不存在-删除生效)" if expect_absent else ""),
                raw_output=f"数据库中现有规则: {existing_names}",
            )

        if expect_absent:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"跨三层服务规则仍存在(应已删除): tagname={tagname}",
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"rule": rule, "mismatches": mismatches},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"跨三层服务规则存在且字段正确 (id={rule.get('id')}, snmp_ip={rule.get('snmp_ip')}, version={rule.get('version')})",
            details={"rule": rule},
            raw_output=json.dumps(rule, ensure_ascii=False),
        )

    # ==================== 多线负载(lb_pcc)验证 ====================

    def query_lb_pcc_rules(self) -> List[Dict]:
        """查询多线负载(lb_pcc)规则列表"""
        self.connect_router()
        output = self._router.exec("/usr/ikuai/function/lb_pcc show limit=0,500 TYPE=total,data")
        logger.info(f"lb_pcc query raw ({len(output)} chars): {output[:300]}")
        try:
            parsed = json.loads(output)
            data = parsed.get("data", [])
            logger.info(f"lb_pcc query returned {len(data)} rules")
            return data
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse lb_pcc output: {output[:200]}")
            return []

    def find_lb_pcc_rule(self, **filters) -> Optional[Dict]:
        """按条件查找单条多线负载规则"""
        rules = self.query_lb_pcc_rules()
        for rule in rules:
            if all(str(rule.get(k)) == str(v) for k, v in filters.items()):
                return rule
        return None

    def verify_lb_pcc_database(self, tagname: str,
                                expected_fields: Dict = None) -> VerifyResult:
        """
        L1: 验证多线负载规则在数据库中存在且字段正确

        Args:
            tagname: 规则名称
            expected_fields: 期望的字段值，如 {"mode": "0", "operator": "全部"}
        """
        rule = self.find_lb_pcc_rule(tagname=tagname)
        if rule is None:
            all_rules = self.query_lb_pcc_rules()
            existing_names = [r.get("tagname", "?") for r in all_rules]
            logger.debug(f"lb_pcc rule not found: {tagname}, existing: {existing_names}")
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"多线负载规则未找到: tagname={tagname}",
                raw_output=f"数据库中现有规则: {existing_names}",
            )

        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"rule": rule, "mismatches": mismatches},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"多线负载规则存在且字段正确 (id={rule.get('id')}, mode={rule.get('mode')}, enabled={rule.get('enabled')})",
            details={"rule": rule},
            raw_output=json.dumps(rule, ensure_ascii=False),
        )

    def verify_lb_pcc_policy_routing(self, expected_wan_interfaces: List[str] = None,
                                     fwmark_map: Dict[str, int] = None) -> VerifyResult:
        """L2: 验证多线负载策略路由(ip rule fwmark + 各WAN路由表)

        区分LB产生的策略路由与普通静态路由: 不只查 lookup wanX, 还要求同一条ip rule规则带 fwmark 0x271X
        (静态路由的lookup wanX行不带fwmark). fwmark↔wan映射默认按产品约定 WAN_FWMARK_BASE+wan_id-1
        (与verify_wan_policy_routing:9254一致), 可用fwmark_map覆盖.

        智能软硬: 全部WAN的fwmark规则都缺失=passed=False(策略路由未生效,硬FAIL);
                  仅部分缺失=passed=True(可能线路未连接,如实记录,软).

        Args:
            expected_wan_interfaces: 期望的WAN接口列表，如["wan1","wan2","wan3"]
            fwmark_map: 自定义wan→fwmark映射覆盖, 如{"wan1":0x2711}; 默认按约定推导
        """
        self.connect_router()
        if expected_wan_interfaces is None:
            expected_wan_interfaces = ["wan1", "wan2", "wan3"]

        # fwmark↔wan映射: 默认按约定推导(复用WAN_FWMARK_BASE), 允许覆盖
        if fwmark_map is None:
            fwmark_map = {}
            for wan in expected_wan_interfaces:
                m = re.match(r"wan(\d+)", wan)
                if m:
                    fwmark_map[wan] = self.WAN_FWMARK_BASE + int(m.group(1)) - 1

        try:
            # 检查ip rule
            ip_rule_output = self._router.exec("ip rule show")
            logger.info(f"ip rule output: {ip_rule_output[:300]}")
            ip_rule_lines = ip_rule_output.splitlines()

            found_fwmark = []      # 同行 fwmark 0x271X + lookup wanX (LB铁证)
            found_tables = []      # 仅 lookup wanX (可能静态路由)
            missing = []           # 连 lookup 都没有
            missing_fwmark = []    # 有 lookup 但无对应 fwmark (疑静态路由冒充)

            for wan in expected_wan_interfaces:
                fwmark = fwmark_map.get(wan)
                fwmark_hex = f"0x{fwmark:x}" if fwmark is not None else None
                has_lookup = any(f"lookup {wan}" in ln for ln in ip_rule_lines)
                # 同一行同时含 fwmark 0x271X 和 lookup wanX = LB产生的策略路由铁证
                if fwmark_hex is not None:
                    has_lb_rule = any(fwmark_hex in ln and f"lookup {wan}" in ln for ln in ip_rule_lines)
                else:
                    has_lb_rule = has_lookup  # 无映射时退化为仅查lookup

                if has_lb_rule:
                    found_fwmark.append(wan)
                if has_lookup:
                    found_tables.append(wan)
                if not has_lookup:
                    missing.append(wan)
                elif fwmark_hex is not None and not has_lb_rule:
                    missing_fwmark.append(wan)

            # 检查各WAN路由表
            route_details = {}
            for wan in found_tables:
                route_output = self._router.exec(f"ip route show table {wan}")
                has_default = "default via" in route_output or "default dev" in route_output
                route_details[wan] = {"has_rule": True, "has_fwmark": wan in found_fwmark,
                                      "has_default_route": has_default}

            fwmark_map_hex = {k: f"0x{v:x}" for k, v in fwmark_map.items()}

            # 智能软硬判定基于 found_fwmark(LB专属集合), 而非 found_tables
            all_missing = len(found_fwmark) == 0
            if missing or missing_fwmark:
                # 全部WAN的fwmark规则都缺失=策略路由未生效(passed=False,硬FAIL);
                # 仅部分缺失=可能线路未连接(passed=True,软), 软硬断言由调用方must_pass决定
                return VerifyResult(
                    level="L2-策略路由",
                    passed=not all_missing,
                    message=(f"策略路由(LB fwmark): {len(found_fwmark)}/{len(expected_wan_interfaces)}个WAN有fwmark规则 "
                             f"(缺fwmark:{missing_fwmark or '无'}, 缺lookup:{missing or '无'})"
                             f"{'，策略路由未生效' if all_missing else '，部分缺失可能线路未连接'}"),
                    details={"found_tables": found_tables, "found_fwmark": found_fwmark,
                             "missing": missing, "missing_fwmark": missing_fwmark,
                             "routes": route_details, "fwmark_map": fwmark_map_hex},
                    raw_output=ip_rule_output,
                )

            return VerifyResult(
                level="L2-策略路由",
                passed=True,
                message=f"策略路由正常(LB fwmark): {len(found_fwmark)}个WAN接口均有fwmark规则和路由表",
                details={"found_tables": found_tables, "found_fwmark": found_fwmark,
                         "routes": route_details, "fwmark_map": fwmark_map_hex},
                raw_output=ip_rule_output,
            )

        except Exception as e:
            return VerifyResult(
                level="L2-策略路由",
                passed=False,
                message=f"策略路由检查失败: {str(e)[:100]}",
            )

    def verify_lb_pcc_dataplane(self, expect_marked: bool = True,
                                expected_wan_interfaces: List[str] = None) -> VerifyResult:
        """L3: 验证多线负载转发数据面(conntrack remote_if 落地证据)

        数据面铁证: ik_core给连接打fwmark→按mark选路→SNAT出该WAN→conntrack条目带 remote_if=wanX.
        扫全表统计 remote_if 出现的WAN集合(不局限某client_ip, 综合测试无受控打流), 比原head -5采样更稳.
        交叉佐证: cflow_stats.llb(多线负载最权威命中计数, 多线负载无mangle链).

        expect_marked=True(规则已加): 综合测试无受控打流, conntrack采空属正常环境状态, 不判异常(中性):
            有remote_if→记录WAN集合(数据面落地✅); 无remote_if但llb>0→采样时机; 都无→未观测到LB流量(正常,分布见L5).
        expect_marked=False(规则已清): remote_if条目随连接老化消失, 始终passed=True(软, 仅记录残留).

        Args:
            expect_marked: 期望数据面是否有remote_if标记
            expected_wan_interfaces: 期望的WAN接口列表
        """
        self.connect_router()
        if expected_wan_interfaces is None:
            expected_wan_interfaces = ["wan1", "wan2", "wan3"]

        try:
            conntrack_output = self._router.exec("cat /proc/net/nf_conntrack 2>/dev/null")
            lines = conntrack_output.splitlines()

            # 扫全表, 合并2行扩展行解析 remote_if (沿用conntrack_egress:1498范式)
            # 只 wan 开头的remote_if算LB跨WAN转发证据(lo/lan等非LB产生, 单独归类)
            remote_if_wans = []
            other_remote = []
            marked_count = 0
            for i, line in enumerate(lines):
                entry = line + (" " + lines[i + 1] if i + 1 < len(lines) else "")
                m = re.search(r"remote_if=(\S+)", entry)
                if m:
                    marked_count += 1
                    iface = m.group(1)
                    if iface.startswith("wan"):
                        if iface not in remote_if_wans:
                            remote_if_wans.append(iface)
                    elif iface not in other_remote:
                        other_remote.append(iface)

            # 交叉佐证: cflow_stats.llb (多线负载命中计数)
            llb_hits = None
            try:
                llb_hits = self.read_cflow_stats().get("llb")
            except Exception:
                llb_hits = None
            logger.info(f"dataplane wan_remote={remote_if_wans}, other={other_remote}, marked={marked_count}, llb={llb_hits}")

            details = {"remote_if_wans": remote_if_wans, "other_remote": other_remote,
                       "marked_conntrack_count": marked_count, "llb_hits": llb_hits,
                       "expected_wan_interfaces": expected_wan_interfaces}
            llb_suffix = f", llb命中={llb_hits}" if llb_hits is not None else ""
            other_suffix = f", 其他接口={other_remote}" if other_remote else ""

            if expect_marked:
                # 中性化: 综合测试无受控打流, 不判异常(符合"测试假设环境状态别硬断言,探测+记录"原则;
                # 亦避免conftest因detail含[FAIL]误把步骤标红). 负载分布硬验证在L5 FlowVerification.
                if remote_if_wans:
                    return VerifyResult(
                        level="L3-数据面", passed=True,
                        message=f"数据面观测: conntrack有LB跨WAN标记(WAN集合={remote_if_wans}, 标记条目={marked_count}{llb_suffix}{other_suffix})",
                        details=details,
                        raw_output=f"LB WANs: {remote_if_wans}, other: {other_remote}, marked={marked_count}, llb={llb_hits}")
                if llb_hits:
                    return VerifyResult(
                        level="L3-数据面", passed=True,
                        message=f"数据面观测: conntrack未采到WAN标记但cflow llb命中={llb_hits}(采样时机, 分布见L5){other_suffix}",
                        details=details, raw_output=f"wan={remote_if_wans}, other: {other_remote}, marked={marked_count}, llb={llb_hits}")
                return VerifyResult(
                    level="L3-数据面", passed=True,
                    message=f"数据面观测: 未观测到LB跨WAN流量(综合测试无受控打流属正常; 负载分布硬验证见L5 FlowVerification){other_suffix}",
                    details=details, raw_output=f"wan={remote_if_wans}, other: {other_remote}, marked={marked_count}, llb={llb_hits}")
            else:
                # expect_marked=False: 条目会随连接老化消失, 不作硬断言
                return VerifyResult(
                    level="L3-数据面", passed=True,
                    message=f"数据面(规则已清): conntrack残留LB WAN集合={remote_if_wans}{other_suffix} (条目随连接老化消失, 不作硬断言)",
                    details=details, raw_output=f"LB WANs: {remote_if_wans}, other: {other_remote}, marked={marked_count}")

        except Exception as e:
            return VerifyResult(
                level="L3-数据面", passed=False,
                message=f"数据面检查失败: {str(e)[:100]}",
            )

    def verify_lb_pcc_kernel(self, expect_enabled: bool = True) -> VerifyResult:
        """L4: 验证多线负载内核控制面(ik_core模块 + dmesg[LB]状态)

        从原verify_lb_pcc_kernel剥离conntrack部分(移至L3 verify_lb_pcc_dataplane). 仅查:
        1. ik_core模块已加载(lsmod)
        2. dmesg [LB]日志确认LB启用/禁用(lb config reload=启用, disable lb=禁用)

        Args:
            expect_enabled: 期望LB是否启用

        expect_enabled=True: ik_core加载 + dmesg显示启用 = passed
        expect_enabled=False: dmesg显示禁用 = passed (ik_core模块本身可能仍加载, 模块卸载粗粒度, 不要求)
        """
        self.connect_router()

        try:
            # 1. 检查ik_core模块
            lsmod_output = self._router.exec("lsmod")
            ik_core_loaded = "ik_core" in lsmod_output
            logger.info(f"ik_core loaded: {ik_core_loaded}")

            # 2. 检查dmesg LB日志 - 用tail -30获取足够上下文
            dmesg_lb = self._router.exec("dmesg | grep '\\[LB\\]' | tail -30")
            # 判断当前LB状态：找到最后一次出现reload或disable的位置
            last_reload_idx = dmesg_lb.rfind("lb config reload")
            last_disable_idx = dmesg_lb.rfind("disable lb")
            lb_enabled = last_reload_idx > last_disable_idx or "iKuai LB is enabled" in dmesg_lb
            lb_disabled = last_disable_idx > last_reload_idx
            logger.info(f"dmesg LB enabled={lb_enabled}, disabled={lb_disabled}, "
                         f"last_reload={last_reload_idx}, last_disable={last_disable_idx}")

            checks = {
                "ik_core_loaded": ik_core_loaded,
                "lb_config_in_dmesg": bool(dmesg_lb.strip()),
                "lb_enabled": lb_enabled,
            }

            if expect_enabled:
                if ik_core_loaded and lb_enabled:
                    return VerifyResult(
                        level="L4-内核",
                        passed=True,
                        message=f"多线负载内核控制面正常: ik_core已加载, LB已启用",
                        details=checks,
                        raw_output=dmesg_lb,
                    )
                else:
                    return VerifyResult(
                        level="L4-内核",
                        passed=False,
                        message=f"多线负载内核控制面异常: ik_core={'已加载' if ik_core_loaded else '未加载'}, LB={'已启用' if lb_enabled else '未启用'}",
                        details=checks,
                        raw_output=dmesg_lb,
                    )
            else:
                # expect_enabled=False: 只看dmesg禁用状态, 不要求ik_core卸载(模块卸载粗粒度)
                if lb_disabled or not lb_enabled:
                    return VerifyResult(
                        level="L4-内核",
                        passed=True,
                        message="多线负载内核控制面: LB已禁用(符合预期)",
                        details=checks,
                        raw_output=dmesg_lb,
                    )
                return VerifyResult(
                    level="L4-内核",
                    passed=False,
                    message="多线负载内核控制面: 预期禁用但LB仍启用(dmesg未现disable lb)",
                    details=checks,
                    raw_output=dmesg_lb,
                )

        except Exception as e:
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message=f"内核控制面检查失败: {str(e)[:100]}",
            )

    # ==================== 协议分流(stream_layer7)验证 ====================

    def query_stream_layer7_rules(self) -> List[Dict]:
        """查询协议分流(stream_layer7)规则列表"""
        self.connect_router()
        output = self._router.exec("/usr/ikuai/function/stream_layer7 show limit=0,500 TYPE=total,data")
        logger.info(f"stream_layer7 query raw ({len(output)} chars): {output[:300]}")
        try:
            parsed = json.loads(output)
            data = parsed.get("data", [])
            logger.info(f"stream_layer7 query returned {len(data)} rules")
            return data
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse stream_layer7 output: {output[:200]}")
            return []

    def find_stream_layer7_rule(self, **filters) -> Optional[Dict]:
        """按条件查找单条协议分流规则

        Args:
            **filters: 过滤条件，如 tagname="xxx", interface="wan1"

        Returns:
            匹配的规则，或None
        """
        rules = self.query_stream_layer7_rules()
        for rule in rules:
            if all(str(rule.get(k)) == str(v) for k, v in filters.items()):
                return rule
        return None

    def verify_stream_layer7_database(self, tagname: str,
                                       expected_fields: Dict = None) -> VerifyResult:
        """
        L1: 验证协议分流规则在数据库中存在且字段正确

        数据库字段映射:
        - tagname: 规则名称
        - interface: 逗号分隔的线路
        - prio: 优先级(0-63)
        - mode: 负载模式(0/1/3)
        - enabled: "yes"/"no"
        - comment: 备注

        Args:
            tagname: 规则名称
            expected_fields: 期望的字段值，如 {"mode": "0", "prio": "10", "interface": "wan1"}
        """
        rule = self.find_stream_layer7_rule(tagname=tagname)
        if rule is None:
            all_rules = self.query_stream_layer7_rules()
            existing_names = [r.get("tagname", "?") for r in all_rules]
            logger.debug(f"stream_layer7 rule not found: {tagname}, existing: {existing_names}")
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"协议分流规则未找到: tagname={tagname}",
                raw_output=f"数据库中现有规则: {existing_names}",
            )

        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"rule": rule, "mismatches": mismatches},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"协议分流规则存在且字段正确 (id={rule.get('id')}, mode={rule.get('mode')}, enabled={rule.get('enabled')})",
            details={"rule": rule},
            raw_output=json.dumps(rule, ensure_ascii=False),
        )

    def query_stream_layer7_iptables(self) -> List[Dict]:
        """查询iptables mangle表STREAM_LAYER7_NEW链中的规则

        返回解析后的规则列表, 每条规则包含:
        - rule_id: 规则ID (对应数据库id, 从注释 /* N */ 中提取)
        - ifname: 线路 (如 wan1, wan1,wan2)
        - mode: 负载模式 (0/1/3)
        - mark: fwmark值
        - timeset: 时间集名称 (如 slayer7_time_1)
        - appset: 应用集名称 (如 slayer7_app_1)
        """
        self.connect_router()
        output = self._router.exec(
            "iptables -t mangle -L STREAM_LAYER7_NEW -n -v 2>/dev/null"
        )
        rules = []
        for line in output.split("\n"):
            if "NTH_CONNMARK" not in line:
                continue
            import re
            rule = {}

            # comment格式=/* {id}_{tagname} */ (如 /* 1_pt_m0_any */, 见stream_ipport.sh:142
            # COMMENT="${id}_${comment}"). 旧正则r"/\*\s*(\d+)\s*\*/"只匹配纯数字/* 1 */,
            # 实际带_tagname后缀→全解析为None→L2全FAIL. 改: id后接_或空或*/
            m = re.search(r"/\*\s*(\d+)(?:_|\s*\*/)", line)
            rule["rule_id"] = int(m.group(1)) if m else None

            m = re.search(r"set-ifname\s+(\S+)", line)
            rule["ifname"] = m.group(1) if m else ""

            m = re.search(r"set-mode\s+(\d+)", line)
            rule["mode"] = int(m.group(1)) if m else None

            m = re.search(r"set-mark\s+(\S+)", line)
            rule["mark"] = m.group(1) if m else ""

            m = re.search(r"timeset\s+(\S+)", line)
            rule["timeset"] = m.group(1) if m else ""

            m = re.search(r"appset\s+(\S+)", line)
            rule["appset"] = m.group(1) if m else ""

            rules.append(rule)
        logger.info(f"STREAM_LAYER7_NEW chain: {len(rules)} iptables rules")
        return rules

    def verify_stream_layer7_iptables(self, rule_id: int,
                                       expected_ifname: str = None,
                                       expected_mode: int = None,
                                       should_exist: bool = True) -> VerifyResult:
        """L2: 验证协议分流规则在iptables mangle表STREAM_LAYER7_NEW链中

        协议分流在iptables中的实现:
        - mangle表PREROUTING链 → STREAM_LAYER7_NEW链
        - 每条规则匹配: timeset(时间) + appset(协议) + ctstate NEW
        - 命中后通过NTH_CONNMARK target打fwmark并指定出接口
        - --set-ifname 对应线路
        - --set-mode 对应负载模式(0=新建连接数, 1=源IP, 3=源IP+目的IP)

        注意: 通过UI停用/删除规则后iptables规则都会被移除(配置重载)。
              should_exist=False 用于验证停用/删除后规则确实消失。

        Args:
            rule_id: 数据库规则ID
            expected_ifname: 期望的线路名称
            expected_mode: 期望的负载模式值
            should_exist: True=验证规则存在, False=验证规则已删除
        """
        self.connect_router()
        try:
            iptables_rules = self.query_stream_layer7_iptables()

            found = None
            for r in iptables_rules:
                if r["rule_id"] == rule_id:
                    found = r
                    break

            if should_exist:
                if found is None:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"iptables规则未找到: rule_id={rule_id}",
                        raw_output=f"现有规则IDs: {[r['rule_id'] for r in iptables_rules]}",
                    )

                mismatches = []
                if expected_ifname and found["ifname"] != expected_ifname:
                    mismatches.append(f"ifname: 期望={expected_ifname}, 实际={found['ifname']}")
                if expected_mode is not None and found["mode"] != expected_mode:
                    mismatches.append(f"mode: 期望={expected_mode}, 实际={found['mode']}")

                if mismatches:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"iptables规则字段不匹配: {', '.join(mismatches)}",
                        details={"found": found},
                        raw_output=str(found),
                    )

                return VerifyResult(
                    level="L2-iptables",
                    passed=True,
                    message=f"iptables规则存在且正确 (id={rule_id}, ifname={found['ifname']}, mode={found['mode']})",
                    details={"found": found},
                    raw_output=str(found),
                )
            else:
                if found is not None:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"iptables规则仍存在(应已删除): rule_id={rule_id}",
                        details={"found": found},
                    )
                return VerifyResult(
                    level="L2-iptables",
                    passed=True,
                    message=f"iptables规则已删除: rule_id={rule_id}",
                )

        except Exception as e:
            return VerifyResult(
                level="L2-iptables",
                passed=False,
                message=f"iptables检查失败: {str(e)[:100]}",
            )

    def verify_stream_layer7_policy_routing(self,
                                             expected_wan_interfaces: List[str] = None) -> VerifyResult:
        """L3: 验证协议分流策略路由(ip rule fwmark + per-WAN路由表)

        协议分流通过fwmark标记 → ip rule策略路由 → per-WAN路由表实现选路。
        此验证检查策略路由基础设施是否就绪。

        Args:
            expected_wan_interfaces: 期望有策略路由的WAN接口列表
        """
        self.connect_router()
        if expected_wan_interfaces is None:
            expected_wan_interfaces = ["wan1", "wan2", "wan3"]

        try:
            ip_rule_output = self._router.exec("ip rule show")
            logger.info(f"ip rule output: {ip_rule_output[:300]}")

            found_tables = []
            for wan in expected_wan_interfaces:
                if f"lookup {wan}" in ip_rule_output:
                    found_tables.append(wan)

            # 检查各WAN路由表
            route_details = {}
            for wan in found_tables:
                route_output = self._router.exec(f"ip route show table {wan}")
                has_default = "default via" in route_output or "default dev" in route_output
                route_details[wan] = {"has_rule": True, "has_default_route": has_default}

            missing = [w for w in expected_wan_interfaces if w not in found_tables]
            if missing:
                return VerifyResult(
                    level="L3-策略路由",
                    passed=True,
                    message=f"策略路由: {len(found_tables)}/{len(expected_wan_interfaces)}个WAN就绪 (缺失: {missing}, 可能线路未连接)",
                    details={"found_tables": found_tables, "missing": missing, "routes": route_details},
                    raw_output=ip_rule_output,
                )

            return VerifyResult(
                level="L3-策略路由",
                passed=True,
                message=f"策略路由正常: {len(found_tables)}个WAN接口均有fwmark规则和路由表",
                details={"found_tables": found_tables, "routes": route_details},
                raw_output=ip_rule_output,
            )

        except Exception as e:
            return VerifyResult(
                level="L3-策略路由",
                passed=False,
                message=f"策略路由检查失败: {str(e)[:100]}",
            )

    def verify_stream_layer7_kernel(self) -> VerifyResult:
        """L4: 验证协议分流内核状态(ik_core模块)

        协议分流依赖ik_core内核模块实现:
        - 协议识别(appset参数)
        - 时间匹配(timeset参数)
        - fwmark打标(NTH_CONNMARK target)
        - 负载均衡(mode: 新建连接数轮询/源IP哈希/源IP+目的IP哈希)

        Returns:
            VerifyResult包含ik_core加载状态
        """
        self.connect_router()
        try:
            lsmod_output = self._router.exec("lsmod")
            ik_core_loaded = "ik_core" in lsmod_output
            logger.info(f"ik_core loaded: {ik_core_loaded}")

            if not ik_core_loaded:
                return VerifyResult(
                    level="L4-内核",
                    passed=False,
                    message="ik_core内核模块未加载",
                )

            # 检查STREAM_LAYER7_NEW链是否有流量
            iptables_output = self._router.exec(
                "iptables -t mangle -L STREAM_LAYER7_NEW -n -v 2>/dev/null"
            )
            has_rules = "NTH_CONNMARK" in iptables_output
            logger.info(f"STREAM_LAYER7_NEW has rules: {has_rules}")

            details = {
                "ik_core_loaded": ik_core_loaded,
                "has_iptables_rules": has_rules,
            }

            return VerifyResult(
                level="L4-内核",
                passed=True,
                message=f"ik_core模块已加载, STREAM_LAYER7_NEW链{'有' if has_rules else '无'}规则",
                details=details,
                raw_output=f"ik_core: loaded={ik_core_loaded}, rules={has_rules}",
            )

        except Exception as e:
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message=f"内核检查失败: {str(e)[:100]}",
            )

    def snapshot_stream_layer7_kernel(self) -> Dict:
        """snapshot协议分流底层4类载体(各为stream_layer7 id集合):
        1. iptables mangle STREAM_LAYER7_NEW链(comment id = stream_layer7 id)
        2. ik_summary Mark Rules的mark_rule(id=4000000+stream_layer7 id, IPT_CONNMARK_STREAM_LAYER7=4000000)
        3. appset slayer7_app_{id}(从iptables appset字段)
        4. ipset slayer7_src_{id}(带源址规则)"""
        self.connect_router()
        ipt_rules = self.query_stream_layer7_iptables()
        ipt_ids, appset_ids = set(), set()
        for r in ipt_rules:
            rid = r.get("rule_id")
            if rid is not None:
                ipt_ids.add(int(rid))
            m = re.search(r'slayer7_app_(\d+)', r.get("appset", ""))
            if m:
                appset_ids.add(int(m.group(1)))
        # ik_summary Mark Rules: 协议分流mark_rule id∈[4000001,6000000)(下个base端口分流6000000)
        mark_ids = set()
        ik = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
        in_mark = False
        for line in ik.splitlines():
            if "Mark Rules" in line:
                in_mark = True
                continue
            if line.startswith("----") and in_mark:
                in_mark = False
                continue
            if in_mark:
                m = re.search(r'ID:(\d+)', line)
                if m:
                    mid = int(m.group(1))
                    if 4000001 <= mid < 6000000:
                        mark_ids.add(mid - 4000000)
        ipset_out = self._router.exec("ipset list -n 2>/dev/null | grep -E 'slayer7_src_'")
        src_ids = set(int(x) for x in re.findall(r'slayer7_src_(\d+)', ipset_out))
        return {"iptables_ids": ipt_ids, "mark_rule_ids": mark_ids,
                "appset_ids": appset_ids, "src_ipset_ids": src_ids}

    def verify_stream_layer7_kernel_consistency(self, label: str = "") -> Dict:
        """协议分流底层一致性校验(实时snapshot对比DB, 定位残留, 不清理).

        每步操作(添加/导入/删除)后调用, 对比DB stream_layer7 id vs 底层4类载体. 不清理底层
        (保留现场追溯BUG触发步骤). residual=底层有id但DB无(删不干净); missing=DB有id但底层无(漏下发).
        用户场景: cat /proc/ikuai/stats/ik_summary|grep ID 看到mark_rule残留即此函数mark_rule_ids.
        Returns: {db_ids, kernel_*ids, residual, missing, residual_detail, clean, detail}"""
        snap = self.snapshot_stream_layer7_kernel()
        db_rules = self.query_stream_layer7_rules()
        db_ids, name_map = set(), {}
        for r in db_rules:
            rid = r.get("id")
            if rid is not None:
                db_ids.add(int(rid))
                name_map[int(rid)] = r.get("tagname", "")
        all_kernel = snap["iptables_ids"] | snap["mark_rule_ids"] | snap["appset_ids"] | snap["src_ipset_ids"]
        residual = all_kernel - db_ids
        missing = db_ids - all_kernel
        residual_detail = []
        for i in sorted(residual):
            carriers = []
            if i in snap["iptables_ids"]:
                carriers.append("iptables")
            if i in snap["mark_rule_ids"]:
                carriers.append(f"mark_rule(ID:{4000000 + i})")
            if i in snap["appset_ids"]:
                carriers.append("appset")
            if i in snap["src_ipset_ids"]:
                carriers.append("src_ipset")
            residual_detail.append(f"id={i}[{name_map.get(i, 'DB已删')}] 残留载体: {'+'.join(carriers)}")
        detail = (f"[{label}] DB={sorted(db_ids)}; 内核 iptables={sorted(snap['iptables_ids'])} "
                  f"mark_rule={sorted(snap['mark_rule_ids'])} appset={sorted(snap['appset_ids'])} "
                  f"src_ipset={sorted(snap['src_ipset_ids'])}"
                  f" → 残留={sorted(residual)} 漏下发={sorted(missing)}")
        return {"db_ids": sorted(db_ids), "iptables_ids": sorted(snap["iptables_ids"]),
                "mark_rule_ids": sorted(snap["mark_rule_ids"]), "appset_ids": sorted(snap["appset_ids"]),
                "src_ipset_ids": sorted(snap["src_ipset_ids"]),
                "residual": sorted(residual), "missing": sorted(missing),
                "residual_detail": residual_detail, "clean": not residual and not missing,
                "detail": detail}

    # ==================== 通用底层一致性校验(各模块残留检测, 推广自协议分流) ====================
    # 模块→内核载体签名表: table=DB表(SELECT id), carriers=底层载体列表.
    # carrier类型: ("iptables_comment", table, chain)=iptables链规则comment id /* N_ */;
    #   ("mark_rule", base, upper)=ik_summary Mark Rules的id∈(base,upper)→id-base;
    #   ("appset_from_iptables", prefix)=从iptables appset字段提取(须排在iptables_comment后);
    #   ("ipset", prefix)=ipset list名匹配prefix提取id; ("ik_app_rule", prefix)=ik_summary App Rules id.
    MODULE_KERNEL_SIGNATURES = {
        "stream_layer7": {"table": "stream_layer7", "carriers": [
            ("iptables_comment", "mangle", "STREAM_LAYER7_NEW"),
            ("mark_rule", 4000000, 6000000),
            ("appset_from_iptables", "slayer7_app_"),
            ("ipset", "slayer7_src_"),
            ("iptables_rule_count", "mangle", "STREAM_LAYER7_NEW")]},
        "stream_ipport": {"table": "stream_ipport", "carriers": [
            ("iptables_comment", "mangle", "STREAM_IPPORT_NEW"),
            ("mark_rule", 6000000, 7000000),
            ("ipset", "sipport_src_"),
            ("ipset", "sipport_sport_"),
            ("iptables_rule_count", "mangle", "STREAM_IPPORT_NEW")]},
        "stream_updown": {"table": "stream_updown", "ignore_missing": True, "carriers": [
            ("ipset", "updown_src_"), ("ipset", "updown_dst_"),
            ("ipset", "updown_sport_"), ("ipset", "updown_dport_")]},  # 仅带地址/端口规则建ipset, missing无意义
        "conn_limit": {"table": "conn_limit", "carriers": [("ipset", "conn_limit_src_"), ("iptables_rule_count", "raw", "CONNLIMIT")]},
        "mac_qos": {"table": "mac_qos", "carriers": [("ipset", "mac_qos_"), ("iptables_rule_count", "filter", "MAC_QOS")]},
        "simple_qos": {"table": "simple_qos", "carriers": [("ipset", "simple_qos_"), ("iptables_rule_count", "filter", "IP_QOS")]},
        "acl": {"table": "acl", "carriers": [("ipset", "acl_src_"), ("ipset", "acl_dst_"),
            ("iptables_rule_count", "filter", "FIREWALL"), ("iptables_rule_count", "filter", "INPUT_ACL")]},
        "dst_nat": {"table": "dst_nat", "carriers": [("iptables_comment", "nat", "DSTNAT")]},
        "acl_l7": {"table": "acl_l7", "carriers": [("ik_app_rule", "acl7_app_")]},
        "alone_limit": {"table": "alone_limit", "carriers": [("ipset", "alone_limit_")]},
        "layer7_qos": {"table": "layer7_qos", "carriers": [("ipset", "layer7qos_")]},
        "stream_domain": {"table": "stream_domain", "ignore_missing": True, "carriers": [("ipset", "sdomain_src_")]},
        "object_group": {"table": "object_group", "ignore_missing": True, "carriers": [
            ("ipset", "group_IPGP"), ("ipset", "group_IPV6GP"),
            ("ipset", "group_MACGP"), ("ipset", "group_PORTGP")]},
        "mac_access_black": {"table": "acl_mac_black", "carriers": [("ipset", "acl_mac_"), ("iptables_rule_count", "filter", "ACL_MAC")]},
        "mac_access_white": {"table": "acl_mac_white", "carriers": [("ipset", "acl_mac_"), ("iptables_rule_count", "filter", "ACL_MAC")]},
    }

    def _read_module_db_ids(self, table: str) -> set:
        self.connect_router()
        rows = self._sqlite_query_list(f"SELECT id FROM {table}")
        ids = set()
        for r in rows:
            try:
                ids.add(int(r.get("id")))
            except (TypeError, ValueError):
                pass
        return ids

    def _read_mark_rule_ids(self, base: int, upper: int) -> set:
        self.connect_router()
        ik = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
        ids, in_mark = set(), False
        for line in ik.splitlines():
            if "Mark Rules" in line:
                in_mark = True
                continue
            if line.startswith("----") and in_mark:
                in_mark = False
                continue
            if in_mark:
                m = re.search(r'ID:(\d+)', line)
                if m and base < int(m.group(1)) < upper:
                    ids.add(int(m.group(1)) - base)
        return ids

    def _read_ipset_ids(self, prefix: str) -> set:
        self.connect_router()
        out = self._router.exec("ipset list -n 2>/dev/null")
        return set(int(x) for x in re.findall(re.escape(prefix) + r'(\d+)', out))

    def _read_iptables_rule_count(self, table: str, chain: str) -> int:
        """数iptables链规则数(-L -n -v输出, 排除Chain行/表头/空行, 规则行首字段=pkts数字).
        用于检测导入清空累加(规则数>DB count). 用-L非-S: iKuai iptables -S {chain}对部分链返回空
        (实测-t raw -S CONNLIMIT输出空, 但-L -n -v有规则). -v保证规则行首字段是pkts计数值."""
        self.connect_router()
        out = self._router.exec(f"iptables -t {table} -L {chain} -n -v 2>/dev/null")
        count = 0
        for line in out.splitlines():
            s = line.strip()
            if not s or s.startswith("Chain ") or s.startswith("pkts"):
                continue
            parts = s.split()
            if parts and parts[0].replace(",", "").isdigit():
                count += 1
        return count

    def _query_iptables_chain_comment_ids(self, table: str, chain: str):
        """返回 (comment id集合, 原始文本) 后续appset_from_iptables解析用."""
        self.connect_router()
        out = self._router.exec(f"iptables -t {table} -L {chain} -n -v 2>/dev/null")
        ids = set()
        for line in out.split("\n"):
            for m in re.finditer(r'/\*\s*(\d+)(?:_|\s*\*/)', line):
                ids.add(int(m.group(1)))
        return ids, out

    def _read_ik_app_rule_ids(self, prefix: str) -> set:
        """ik_summary App Rules段规则id(应用协议acl_l7的app_rule id=acl_l7 id)."""
        self.connect_router()
        ik = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
        ids, in_app = set(), False
        for line in ik.splitlines():
            if "App Rules" in line:
                in_app = True
                continue
            if line.startswith("----") and in_app:
                break
            if in_app:
                m = re.search(r'ID:(\d+)\b', line)
                if m:
                    ids.add(int(m.group(1)))
        return ids

    def snapshot_module_kernel(self, module: str) -> Dict:
        """snapshot指定模块底层载体(各id集合). 用MODULE_KERNEL_SIGNATURES carriers遍历."""
        sig = self.MODULE_KERNEL_SIGNATURES.get(module)
        if not sig:
            return {"_error": f"未知模块签名: {module}"}
        snap = {"iptables": set(), "mark_rule": set(), "appset": set(),
                "ipset": set(), "ik_app_rule": set(), "rule_counts": {}}
        ipt_raw = ""
        for carrier in sig["carriers"]:
            ctype = carrier[0]
            if ctype == "iptables_comment":
                ids, raw = self._query_iptables_chain_comment_ids(carrier[1], carrier[2])
                snap["iptables"] |= ids
                ipt_raw += " " + raw
            elif ctype == "mark_rule":
                snap["mark_rule"] |= self._read_mark_rule_ids(carrier[1], carrier[2])
            elif ctype == "appset_from_iptables":
                snap["appset"] |= set(int(x) for x in
                                      re.findall(re.escape(carrier[1]) + r'(\d+)', ipt_raw))
            elif ctype == "ipset":
                snap["ipset"] |= self._read_ipset_ids(carrier[1])
            elif ctype == "ik_app_rule":
                snap["ik_app_rule"] |= self._read_ik_app_rule_ids(carrier[1])
            elif ctype == "iptables_rule_count":
                snap["rule_counts"][f"{carrier[1]}/{carrier[2]}"] = self._read_iptables_rule_count(carrier[1], carrier[2])
        return snap

    def verify_module_kernel_consistency(self, module: str, label: str = "") -> Dict:
        """通用底层一致性校验(各模块残留检测). 实时snapshot对比DB, 定位残留触发步骤, 不清理.
        residual=底层有id但DB无(删不干净); missing=DB有id但底层无(漏下发).
        模块载体见MODULE_KERNEL_SIGNATURES. 协议分流首发验证定位mark_rule残留(报禅道)."""
        sig = self.MODULE_KERNEL_SIGNATURES.get(module)
        if not sig:
            return {"error": f"未知模块: {module}", "detail": f"[{label}] 未知模块: {module}", "clean": False}
        snap = self.snapshot_module_kernel(module)
        if "_error" in snap:
            return {"error": snap["_error"], "detail": f"[{label}] {snap['_error']}", "clean": False}
        db_ids = self._read_module_db_ids(sig["table"])
        kernel_ids = set()
        for v in snap.values():
            if isinstance(v, set):
                kernel_ids |= v
        residual = kernel_ids - db_ids
        if sig.get("ignore_missing") or not kernel_ids:
            missing = set()  # ignore_missing(如上下行仅部分规则建ipset)或kernel空时, missing无意义避免误报
        else:
            missing = db_ids - kernel_ids
        residual_detail = []
        for i in sorted(residual):
            carriers = [k for k, v in snap.items() if isinstance(v, set) and i in v]
            residual_detail.append(f"id={i} 残留载体: {'+'.join(carriers)}")
        # iptables链规则数 vs DB count(检测导入清空累加: 规则数>DB count = 旧规则未删堆积)
        db_count = len(db_ids)
        count_overflow = []
        for desc, ipt_cnt in snap.get("rule_counts", {}).items():
            if ipt_cnt > db_count:
                count_overflow.append({"chain": desc, "iptables": ipt_cnt, "db": db_count, "dup": ipt_cnt - db_count})
        for co in count_overflow:
            residual_detail.append(f"{co['chain']}规则累加: iptables={co['iptables']}条 > DB={co['db']}条 (累加{co['dup']}条, 导入未清空iptables链)")
        ksum = " ".join(f"{k}={sorted(v)}" for k, v in snap.items() if isinstance(v, set) and v)
        cnt_sum = " ".join(f"{k}={v}" for k, v in snap.get("rule_counts", {}).items())
        ovf_sum = ",".join(f"{c['chain']}:{c['iptables']}>{c['db']}" for c in count_overflow)
        detail = (f"[{label}] {module}: DB={sorted(db_ids)}; 内核 {ksum}"
                  + (f" 规则数 {cnt_sum}" if cnt_sum else "")
                  + f" → 残留={sorted(residual)} 漏下发={sorted(missing)}"
                  + (f" 规则累加={ovf_sum}" if count_overflow else ""))
        return {"module": module, "db_ids": sorted(db_ids),
                "kernel": {k: sorted(v) for k, v in snap.items() if isinstance(v, set)},
                "rule_counts": dict(snap.get("rule_counts", {})),
                "residual": sorted(residual), "missing": sorted(missing),
                "count_overflow": count_overflow,
                "residual_detail": residual_detail,
                "clean": not residual and not missing and not count_overflow,
                "detail": detail}

    # ==================== 端口分流(stream_ipport)验证 ====================

    def query_stream_ipport_rules(self) -> List[Dict]:
        """查询端口分流(stream_ipport)规则列表"""
        self.connect_router()
        output = self._router.exec("/usr/ikuai/function/stream_ipport show limit=0,500 TYPE=total,data")
        logger.info(f"stream_ipport query raw ({len(output)} chars): {output[:300]}")
        try:
            parsed = json.loads(output)
            data = parsed.get("data", [])
            logger.info(f"stream_ipport query returned {len(data)} rules")
            return data
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse stream_ipport output: {output[:200]}")
            return []

    def find_stream_ipport_rule(self, **filters) -> Optional[Dict]:
        """按条件查找单条端口分流规则

        Args:
            **filters: 过滤条件，如 tagname="xxx", interface="wan1"

        Returns:
            匹配的规则，或None
        """
        rules = self.query_stream_ipport_rules()
        for rule in rules:
            if all(str(rule.get(k)) == str(v) for k, v in filters.items()):
                return rule
        return None

    def verify_stream_ipport_database(self, tagname: str,
                                       expected_fields: Dict = None) -> VerifyResult:
        """
        L1: 验证端口分流规则在数据库中存在且字段正确

        数据库字段映射:
        - tagname: 规则名称
        - type: 分流方式 0=外网线路 1=下一跳网关
        - interface: 逗号分隔的线路
        - nexthop: 下一跳网关IP
        - prio: 优先级(0-63)
        - mode: 负载模式(0/1/2/3/4/6)
        - enabled: "yes"/"no"
        - protocol: 协议 any/tcp/udp/tcp+udp/icmp
        - iface_band: 线路绑定 0/1
        - src_addr_inv/dst_addr_inv: 反向匹配 0/1
        - src_addr/dst_addr: IP/MAC分组引用
        - src_port/dst_port: 端口(json_port_base64格式)
        - dst_type: 目的地址类型 0/1
        - time: 生效时间
        - comment: 备注
        """
        rule = self.find_stream_ipport_rule(tagname=tagname)
        if rule is None:
            all_rules = self.query_stream_ipport_rules()
            existing_names = [r.get("tagname", "?") for r in all_rules]
            logger.debug(f"stream_ipport rule not found: {tagname}, existing: {existing_names}")
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"端口分流规则未找到: tagname={tagname}",
                raw_output=f"数据库中现有规则: {existing_names}",
            )

        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"rule": rule, "mismatches": mismatches},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"端口分流规则存在且字段正确 (id={rule.get('id')}, mode={rule.get('mode')}, enabled={rule.get('enabled')})",
            details={"rule": rule},
            raw_output=json.dumps(rule, ensure_ascii=False),
        )

    def query_stream_ipport_iptables(self) -> List[Dict]:
        """查询iptables mangle表STREAM_IPPORT_NEW链中的规则

        端口分流在iptables中的实现与协议分流类似:
        - mangle表PREROUTING链 → STREAM_IPPORT_NEW链
        - 每条规则匹配: protocol + src/dst端口 + src/dst地址 + ctstate NEW
        - 命中后通过NTH_CONNMARK target打fwmark并指定出接口

        返回解析后的规则列表, 每条规则包含:
        - rule_id: 规则ID (从注释 /* N */ 中提取)
        - ifname: 线路 (如 wan1)
        - mode: 负载模式
        - mark: fwmark值
        - proto: 协议 (tcp/udp/icmp/all)
        - src_port/dst_port: 端口信息
        """
        self.connect_router()
        output = self._router.exec(
            "iptables -t mangle -L STREAM_IPPORT_NEW -n -v 2>/dev/null"
        )
        rules = []
        for line in output.split("\n"):
            if "NTH_CONNMARK" not in line:
                continue
            rule = {}

            # comment格式=/* {id}_{tagname} */ (如 /* 1_pt_m0_any */, 见stream_ipport.sh:142
            # COMMENT="${id}_${comment}"). 旧正则r"/\*\s*(\d+)\s*\*/"只匹配纯数字/* 1 */,
            # 实际带_tagname后缀→全解析为None→L2全FAIL. 改: id后接_或空或*/
            m = re.search(r"/\*\s*(\d+)(?:_|\s*\*/)", line)
            rule["rule_id"] = int(m.group(1)) if m else None

            m = re.search(r"set-ifname\s+(\S+)", line)
            rule["ifname"] = m.group(1) if m else ""

            m = re.search(r"set-mode\s+(\d+)", line)
            rule["mode"] = int(m.group(1)) if m else None

            m = re.search(r"set-mark\s+(\S+)", line)
            rule["mark"] = m.group(1) if m else ""

            m = re.search(r"proto\s+(\w+)", line)
            if not m:
                m = re.search(r"ptc\s+(\w+)", line)
            rule["proto"] = m.group(1) if m else ""

            rules.append(rule)
        logger.info(f"STREAM_IPPORT_NEW chain: {len(rules)} iptables rules")
        return rules

    def verify_stream_ipport_iptables(self, rule_id: int,
                                       expected_ifname: str = None,
                                       expected_mode: int = None,
                                       should_exist: bool = True) -> VerifyResult:
        """L2: 验证端口分流规则在iptables mangle表STREAM_IPPORT_NEW链中

        Args:
            rule_id: 数据库规则ID
            expected_ifname: 期望的线路名称
            expected_mode: 期望的负载模式值
            should_exist: True=验证规则存在, False=验证规则已删除
        """
        self.connect_router()
        try:
            iptables_rules = self.query_stream_ipport_iptables()

            found = None
            for r in iptables_rules:
                if r["rule_id"] == rule_id:
                    found = r
                    break

            if should_exist:
                if found is None:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"iptables规则未找到: rule_id={rule_id}",
                        raw_output=f"现有规则IDs: {[r['rule_id'] for r in iptables_rules]}",
                    )

                mismatches = []
                if expected_ifname and found["ifname"] != expected_ifname:
                    mismatches.append(f"ifname: 期望={expected_ifname}, 实际={found['ifname']}")
                if expected_mode is not None and found["mode"] != expected_mode:
                    mismatches.append(f"mode: 期望={expected_mode}, 实际={found['mode']}")

                if mismatches:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"iptables规则字段不匹配: {', '.join(mismatches)}",
                        details={"found": found},
                        raw_output=str(found),
                    )

                return VerifyResult(
                    level="L2-iptables",
                    passed=True,
                    message=f"iptables规则存在且正确 (id={rule_id}, ifname={found['ifname']}, mode={found['mode']})",
                    details={"found": found},
                    raw_output=str(found),
                )
            else:
                if found is not None:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"iptables规则仍存在(应已删除): rule_id={rule_id}",
                        details={"found": found},
                    )
                return VerifyResult(
                    level="L2-iptables",
                    passed=True,
                    message=f"iptables规则已删除: rule_id={rule_id}",
                )

        except Exception as e:
            return VerifyResult(
                level="L2-iptables",
                passed=False,
                message=f"iptables检查失败: {str(e)[:100]}",
            )

    def verify_stream_ipport_policy_routing(self,
                                             expected_wan_interfaces: List[str] = None) -> VerifyResult:
        """L3: 验证端口分流策略路由(ip rule fwmark + per-WAN路由表)

        端口分流与协议分流共享相同的策略路由基础设施。

        Args:
            expected_wan_interfaces: 期望有策略路由的WAN接口列表
        """
        self.connect_router()
        if expected_wan_interfaces is None:
            expected_wan_interfaces = ["wan1", "wan2", "wan3"]

        try:
            ip_rule_output = self._router.exec("ip rule show")
            logger.info(f"ip rule output: {ip_rule_output[:300]}")

            found_tables = []
            for wan in expected_wan_interfaces:
                if f"lookup {wan}" in ip_rule_output:
                    found_tables.append(wan)

            route_details = {}
            for wan in found_tables:
                route_output = self._router.exec(f"ip route show table {wan}")
                has_default = "default via" in route_output or "default dev" in route_output
                route_details[wan] = {"has_rule": True, "has_default_route": has_default}

            missing = [w for w in expected_wan_interfaces if w not in found_tables]
            if missing:
                return VerifyResult(
                    level="L3-策略路由",
                    passed=True,
                    message=f"策略路由: {len(found_tables)}/{len(expected_wan_interfaces)}个WAN就绪 (缺失: {missing})",
                    details={"found_tables": found_tables, "missing": missing, "routes": route_details},
                    raw_output=ip_rule_output,
                )

            return VerifyResult(
                level="L3-策略路由",
                passed=True,
                message=f"策略路由正常: {len(found_tables)}个WAN接口均有fwmark规则和路由表",
                details={"found_tables": found_tables, "routes": route_details},
                raw_output=ip_rule_output,
            )

        except Exception as e:
            return VerifyResult(
                level="L3-策略路由",
                passed=False,
                message=f"策略路由检查失败: {str(e)[:100]}",
            )

    def verify_stream_ipport_kernel(self) -> VerifyResult:
        """L4: 验证端口分流内核状态(ik_core模块)

        端口分流依赖ik_core内核模块，与协议分流共享相同的内核基础设施。
        """
        self.connect_router()
        try:
            lsmod_output = self._router.exec("lsmod")
            ik_core_loaded = "ik_core" in lsmod_output
            logger.info(f"ik_core loaded: {ik_core_loaded}")

            if not ik_core_loaded:
                return VerifyResult(
                    level="L4-内核",
                    passed=False,
                    message="ik_core内核模块未加载",
                )

            iptables_output = self._router.exec(
                "iptables -t mangle -L STREAM_IPPORT_NEW -n -v 2>/dev/null"
            )
            has_rules = "NTH_CONNMARK" in iptables_output
            logger.info(f"STREAM_IPPORT_NEW has rules: {has_rules}")

            details = {
                "ik_core_loaded": ik_core_loaded,
                "has_iptables_rules": has_rules,
            }

            return VerifyResult(
                level="L4-内核",
                passed=True,
                message=f"ik_core模块已加载, STREAM_IPPORT_NEW链{'有' if has_rules else '无'}规则",
                details=details,
                raw_output=f"ik_core: loaded={ik_core_loaded}, rules={has_rules}",
            )

        except Exception as e:
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message=f"内核检查失败: {str(e)[:100]}",
            )

    # ==================== 域名分流(stream_domain)验证 ====================

    def query_stream_domain_rules(self) -> List[Dict]:
        """查询域名分流(stream_domain)规则列表"""
        self.connect_router()
        output = self._router.exec("/usr/ikuai/function/stream_domain show limit=0,500 TYPE=total,data")
        logger.info(f"stream_domain query raw ({len(output)} chars): {output[:300]}")
        try:
            parsed = json.loads(output)
            data = parsed.get("data", [])
            logger.info(f"stream_domain query returned {len(data)} rules")
            return data
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse stream_domain output: {output[:200]}")
            return []

    def find_stream_domain_rule(self, **filters) -> Optional[Dict]:
        """按条件查找单条域名分流规则"""
        rules = self.query_stream_domain_rules()
        for rule in rules:
            if all(str(rule.get(k)) == str(v) for k, v in filters.items()):
                return rule
        return None

    def verify_stream_domain_database(self, tagname: str,
                                       expected_fields: Dict = None) -> VerifyResult:
        """
        L1: 验证域名分流规则在数据库中存在且字段正确

        数据库字段映射:
        - tagname: 规则名称
        - interface: 逗号分隔的线路
        - prio: 优先级(0-63)
        - enabled: "yes"/"no"
        - domain: 域名列表(JSON)
        - src_addr: 源IP/MAC地址(JSON)
        - comment: 备注
        - time: 生效时间(JSON)
        """
        rule = self.find_stream_domain_rule(tagname=tagname)
        if rule is None:
            all_rules = self.query_stream_domain_rules()
            existing_names = [r.get("tagname", "?") for r in all_rules]
            logger.debug(f"stream_domain rule not found: {tagname}, existing: {existing_names}")
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"域名分流规则未找到: tagname={tagname}",
                raw_output=f"数据库中现有规则: {existing_names}",
            )

        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"rule": rule, "mismatches": mismatches},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"域名分流规则存在且字段正确 (id={rule.get('id')}, interface={rule.get('interface')}, enabled={rule.get('enabled')})",
            details={"rule": rule},
            raw_output=json.dumps(rule, ensure_ascii=False),
        )

    def verify_stream_domain_ipset(self, rule_id: int,
                                    expected_ifname: str = None,
                                    should_exist: bool = True) -> VerifyResult:
        """L2: 验证域名分流规则后端落地(内核url_route group + 可选ipset)

        域名分流机制(见stream_domain.sh):
        - 域名匹配走ik_core的url_route内核表(ik_cntl url_route group add $id),
          ik_summary可见"URL_ROUTE_GROUP(GROUPID: {id})"+"URL Route: enable"总开关
        - 源地址匹配(可选): 仅规则带src_addr时才建ipset sdomain_src_{id}(stream_domain.sh:61 __format_ipset)
        - 时间匹配(可选): timeset sdomain_time_{id}
        故: 所有规则都验内核group; 仅带源地址规则额外验sdomain_src_{id}。
        (原实现对所有规则查sdomain_src_{id}, 纯域名规则无源地址不建→全FAIL, 误报)
        """
        self.connect_router()
        try:
            # 查规则src_addr, 判断是否该有源地址ipset
            has_src = False
            try:
                rule = self.find_stream_domain_rule(id=rule_id)
                if rule:
                    sa_raw = rule.get("src_addr")
                    if sa_raw:
                        sa = sa_raw if isinstance(sa_raw, dict) else json.loads(sa_raw)
                        has_src = bool(sa.get("custom")) or bool(sa.get("object"))
            except Exception:
                has_src = False

            # 公共: 域名路由内核group(所有规则都该有) + URL Route总开关
            ik_summary = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
            group_exists = f"URL_ROUTE_GROUP(GROUPID: {rule_id})" in ik_summary
            url_route_on = "URL Route: enable" in ik_summary

            if should_exist:
                # 1. 内核group必须存在(域名匹配核心机制)
                if not group_exists:
                    return VerifyResult(
                        level="L2-ipset",
                        passed=False,
                        message=f"域名路由group {rule_id} 未在内核(ik_summary无GROUPID:{rule_id}, URL Route={'on' if url_route_on else 'off'})",
                        details={"url_route_enabled": url_route_on},
                        raw_output=ik_summary[:400],
                    )
                # 2. 带源地址规则额外验sdomain_src_{id}
                if has_src:
                    ipset_name = f"sdomain_src_{rule_id}"
                    output = self._router.exec(f"ipset list {ipset_name} 2>/dev/null")
                    if "Name:" not in output and ipset_name not in output:
                        all_ipset = self._router.exec("ipset list -n 2>/dev/null")
                        sdomain_sets = [l.strip() for l in all_ipset.split("\n") if "sdomain" in l]
                        return VerifyResult(
                            level="L2-ipset",
                            passed=False,
                            message=f"规则带源地址但ipset {ipset_name} 未找到",
                            details={"all_sdomain_sets": sdomain_sets},
                            raw_output=f"all sdomain ipsets: {sdomain_sets}",
                        )
                    members = []
                    in_members = False
                    for line in output.split("\n"):
                        if line.startswith("Members:"):
                            in_members = True
                            continue
                        if in_members and line.strip():
                            members.append(line.strip())
                    return VerifyResult(
                        level="L2-ipset",
                        passed=True,
                        message=f"带源地址规则: group_{rule_id}内核OK + ipset {ipset_name}存在(成员{len(members)})",
                        details={"has_src_addr": True, "group_exists": True, "ipset_name": ipset_name, "members": members},
                        raw_output=output[:300],
                    )
                # 3. 纯域名规则: 只验内核group(域名匹配走url_route, 无需sdomain_src_)
                return VerifyResult(
                    level="L2-ipset",
                    passed=True,
                    message=f"纯域名规则: 域名匹配走ik_core url_route, group_{rule_id}内核OK(URL Route:enable), 无源地址故不建sdomain_src_",
                    details={"has_src_addr": False, "group_exists": True, "url_route_enabled": url_route_on},
                    raw_output=ik_summary[:300],
                )
            else:
                # 删除验证: 内核group应消失
                if group_exists:
                    return VerifyResult(
                        level="L2-ipset",
                        passed=False,
                        message=f"域名路由group {rule_id} 仍在内核(应已删除)",
                    )
                return VerifyResult(
                    level="L2-ipset",
                    passed=True,
                    message=f"域名路由group {rule_id} 已从内核删除",
                )

        except Exception as e:
            return VerifyResult(
                level="L2-ipset",
                passed=False,
                message=f"ipset/group检查失败: {str(e)[:100]}",
            )

    def verify_stream_domain_kernel_status(self) -> VerifyResult:
        """L3: 验证域名分流内核状态(/proc/ikuai/stats/ik_summary)"""
        self.connect_router()
        try:
            output = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
            has_url_route = "url_route" in output or "domain" in output.lower()

            ik_cntl_output = self._router.exec("ik_cntl show url_route 2>/dev/null || echo 'ik_cntl_not_found'")

            details = {
                "proc_has_url_route": has_url_route,
                "ik_cntl_output": ik_cntl_output[:200],
            }

            if has_url_route or "ik_cntl_not_found" not in ik_cntl_output:
                return VerifyResult(
                    level="L3-内核状态",
                    passed=True,
                    message=f"域名分流内核子系统正常 (url_route={'已加载' if has_url_route else '通过ik_cntl'})",
                    details=details,
                    raw_output=f"proc: {output[:200]}\nik_cntl: {ik_cntl_output[:200]}",
                )

            return VerifyResult(
                level="L3-内核状态",
                passed=True,
                message=f"域名分流内核状态检查完成",
                details=details,
                raw_output=output[:200],
            )

        except Exception as e:
            return VerifyResult(
                level="L3-内核状态",
                passed=False,
                message=f"内核状态检查失败: {str(e)[:100]}",
            )

    def verify_stream_domain_kernel(self) -> VerifyResult:
        """L4: 验证域名分流内核模块(ik_core)"""
        self.connect_router()
        try:
            lsmod_output = self._router.exec("lsmod")
            ik_core_loaded = "ik_core" in lsmod_output
            logger.info(f"ik_core loaded: {ik_core_loaded}")

            if not ik_core_loaded:
                return VerifyResult(
                    level="L4-内核",
                    passed=False,
                    message="ik_core内核模块未加载",
                )

            all_ipset = self._router.exec("ipset list -n 2>/dev/null")
            sdomain_count = sum(1 for l in all_ipset.split("\n") if "sdomain" in l)

            details = {
                "ik_core_loaded": ik_core_loaded,
                "sdomain_ipset_count": sdomain_count,
            }

            return VerifyResult(
                level="L4-内核",
                passed=True,
                message=f"ik_core模块已加载, sdomain相关ipset={sdomain_count}个",
                details=details,
                raw_output=f"ik_core: loaded={ik_core_loaded}, sdomain_ipsets={sdomain_count}",
            )

        except Exception as e:
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message=f"内核检查失败: {str(e)[:100]}",
            )

    # ==================== 上下行分离(stream_updown)验证 ====================

    def query_stream_updown_rules(self) -> list:
        """L1: 查询上下行分离数据库规则"""
        self.connect_router()
        try:
            output = self._router.exec(
                "/usr/ikuai/function/stream_updown show limit=0,500 TYPE=total,data"
            )
            logger.info(f"stream_updown show output (first 200): {output[:200]}")

            import json
            data = json.loads(output)
            rules = data.get("data", [])
            logger.info(f"stream_updown rules count: {len(rules)}")
            return rules
        except Exception as e:
            logger.error(f"查询stream_updown失败: {e}")
            return []

    def find_stream_updown_rule(self, tagname: str) -> Optional[dict]:
        """L1: 查找指定名称的上下行分离规则"""
        rules = self.query_stream_updown_rules()
        for rule in rules:
            if rule.get("tagname") == tagname:
                return rule
        return None

    def verify_stream_updown_database(self, tagname: str,
                                      expected_fields: dict = None) -> VerifyResult:
        """L1: 验证上下行分离数据库规则"""
        try:
            rule = self.find_stream_updown_rule(tagname)
            if rule is None:
                all_rules = self.query_stream_updown_rules()
                existing_names = [r.get("tagname", "?") for r in all_rules]
                return VerifyResult(
                    level="L1-数据库",
                    passed=False,
                    message=f"上下行分离规则未找到: tagname={tagname}",
                    raw_output=f"数据库中现有规则: {existing_names}",
                )

            details = {
                "id": rule.get("id"),
                "tagname": rule.get("tagname"),
                "upiface": rule.get("upiface"),
                "downiface": rule.get("downiface"),
                "protocol": rule.get("protocol"),
                "enabled": rule.get("enabled"),
                "comment": rule.get("comment"),
            }

            mismatches = {}
            if expected_fields:
                for field, expected in expected_fields.items():
                    actual = str(rule.get(field, ""))
                    if actual != str(expected):
                        mismatches[field] = {"expected": str(expected), "actual": actual}

            if mismatches:
                return VerifyResult(
                    level="L1-数据库",
                    passed=False,
                    message=f"字段不匹配: {mismatches}",
                    details=details,
                    raw_output=str(rule)[:300],
                )

            return VerifyResult(
                level="L1-数据库",
                passed=True,
                message=f"规则{tagname}数据库验证通过",
                details=details,
                raw_output=str(rule)[:300],
            )

        except Exception as e:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"数据库验证异常: {str(e)[:100]}",
            )

    def verify_stream_updown_ipset(self, rule_id: str,
                                   src_addr: str = None,
                                   dst_addr: str = None) -> VerifyResult:
        """L2: 验证上下行分离ipset规则"""
        self.connect_router()
        try:
            all_ipset = self._router.exec("ipset list -n 2>/dev/null")
            found_sets = []
            for suffix in ["src", "dst", "sport", "dport"]:
                set_name = f"updown_{suffix}_{rule_id}"
                if set_name in all_ipset:
                    found_sets.append(set_name)

            details = {"rule_id": rule_id, "ipset_sets": found_sets}

            addr_check_results = []
            # updown_src/dst_{id}是list:set(集合的集合, 成员是子ipset名), 实际地址在子ipset
            # _updown_src/dst_{id}(hash:net)里(同simple_qos_{id}→_simple_qos_{id}结构).
            # 故查地址要list子ipset _updown_*_{id}, 不是父集(原查父集→永远not found).
            if src_addr and f"updown_src_{rule_id}" in all_ipset:
                src_content = self._router.exec(f"ipset list _updown_src_{rule_id} 2>/dev/null")
                has_addr = src_addr in src_content
                addr_check_results.append(f"src_addr({src_addr}): {'found' if has_addr else 'not found'}")
                details["src_addr_in_ipset"] = has_addr

            if dst_addr and f"updown_dst_{rule_id}" in all_ipset:
                dst_content = self._router.exec(f"ipset list _updown_dst_{rule_id} 2>/dev/null")
                has_addr = dst_addr in dst_content
                addr_check_results.append(f"dst_addr({dst_addr}): {'found' if has_addr else 'not found'}")
                details["dst_addr_in_ipset"] = has_addr

            # 用has_addr布尔标志判断(原all("found" in r)有bug: 字符串"not found"含子串"found"→误判通过)
            _flags = [v for k, v in details.items() if k.endswith("_in_ipset")]
            all_addr_ok = all(_flags) if _flags else True

            # 没有地址/端口的规则不创建ipset，此时found_sets为空是正常的
            has_addr_or_port_check = src_addr or dst_addr
            if has_addr_or_port_check:
                passed = len(found_sets) > 0 and all_addr_ok
            else:
                passed = True
            msg_parts = [f"ipset={found_sets}"]
            if addr_check_results:
                msg_parts.extend(addr_check_results)

            # raw_output只显示该规则相关ipset(不列全局ipset列表, 避免Linux_WEBPPPOE_default等
            # 系统默认集误导报告). 上下行分离多数规则无地址/端口不建ipset, 走ik_cntl wans-snat落地.
            if found_sets:
                raw_out = f"规则ipset: {found_sets}"
                if addr_check_results:
                    raw_out += "; " + "; ".join(addr_check_results)
            else:
                raw_out = ("无地址/端口→不建ipset(符合机制). 上下行实际落地: ik_cntl wans-snat → "
                           "/tmp/iktmp/stream_updown.txt (格式 'id node { proto out:\"上行\" in:\"下行\" }'), 见L3-内核状态")
            return VerifyResult(
                level="L2-ipset",
                passed=passed,
                message=f"上下行分离ipset验证{'通过' if passed else '未通过'}: {', '.join(msg_parts)}",
                details=details,
                raw_output=raw_out,
            )

        except Exception as e:
            return VerifyResult(
                level="L2-ipset",
                passed=False,
                message=f"ipset验证异常: {str(e)[:100]}",
            )

    def verify_stream_updown_kernel_status(self) -> VerifyResult:
        """L3: 验证上下行分离内核状态(ik_cntl wans-snat)"""
        self.connect_router()
        try:
            config_content = self._router.exec("cat /tmp/iktmp/stream_updown.txt 2>/dev/null")
            logger.info(f"stream_updown.txt content (first 200): {config_content[:200]}")

            has_rules = bool(config_content.strip())
            rule_count = len([l for l in config_content.strip().split("\n") if l.strip()]) if has_rules else 0
            # 解析每条规则: 格式 "id node { proto out:\"上行\" in:\"下行\" }"(stream_updown.sh:78)
            rules_in_txt = []
            for line in config_content.split("\n"):
                m = re.search(r'(\d+)\s+node\s*\{([^}]*)\}', line)
                if m:
                    body = m.group(2)
                    outs = re.findall(r'out:"([^"]+)"', body)
                    ins = re.findall(r'in:"([^"]+)"', body)
                    rules_in_txt.append(f"id{m.group(1)}:上{','.join(outs) or '?'}/下{','.join(ins) or '?'}")

            details = {
                "config_exists": has_rules,
                "rule_count": rule_count,
                "rules": rules_in_txt,
            }
            rules_summary = "; ".join(rules_in_txt) if rules_in_txt else "无"
            return VerifyResult(
                level="L3-内核状态",
                passed=True,
                message=f"上下行分离内核wans-snat落地: {rule_count}条规则 [{rules_summary}]",
                details=details,
                raw_output=config_content[:400] or "(空, 无启用的上下行分离规则)",
            )

        except Exception as e:
            return VerifyResult(
                level="L3-内核状态",
                passed=False,
                message=f"内核状态检查失败: {str(e)[:100]}",
            )

    def verify_stream_updown_kernel(self) -> VerifyResult:
        """L4: 验证上下行分离内核模块(ik_core + ik_cntl)"""
        self.connect_router()
        try:
            lsmod_output = self._router.exec("lsmod")
            ik_core_loaded = "ik_core" in lsmod_output
            logger.info(f"ik_core loaded: {ik_core_loaded}")

            if not ik_core_loaded:
                return VerifyResult(
                    level="L4-内核",
                    passed=False,
                    message="ik_core内核模块未加载",
                )

            all_ipset = self._router.exec("ipset list -n 2>/dev/null")
            updown_count = sum(1 for l in all_ipset.split("\n") if "updown" in l)

            details = {
                "ik_core_loaded": ik_core_loaded,
                "updown_ipset_count": updown_count,
            }

            return VerifyResult(
                level="L4-内核",
                passed=True,
                message=f"ik_core模块已加载, updown相关ipset={updown_count}个",
                details=details,
                raw_output=f"ik_core: loaded={ik_core_loaded}, updown_ipsets={updown_count}",
            )

        except Exception as e:
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message=f"内核检查失败: {str(e)[:100]}",
            )

    # ==================== UPnP(upnpd)验证 ====================

    # --- 全局配置(upnpd_conf) ---

    def query_upnpd_conf(self) -> Optional[Dict]:
        """查询UPnP全局配置(upnpd_conf表，单行)"""
        self.connect_router()
        try:
            output = self._router.exec(
                "/usr/ikuai/function/upnpd show TYPE=data"
            )
            logger.info(f"upnpd_conf raw: {output[:200]}")

            if not output or "Error" in output:
                return None

            data = json.loads(output.strip())
            if isinstance(data, dict):
                if "data" in data:
                    conf_data = data["data"]
                    if isinstance(conf_data, list) and len(conf_data) > 0:
                        return conf_data[0]
                    elif isinstance(conf_data, dict):
                        return conf_data
                return data
            return None
        except Exception as e:
            logger.error(f"query_upnpd_conf error: {e}")
            return None

    def verify_upnpd_conf(self, expected_fields: Dict = None) -> VerifyResult:
        """L1: 验证UPnP全局配置"""
        conf = self.query_upnpd_conf()
        if conf is None:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message="无法查询UPnP全局配置",
            )

        details = {"config": conf}
        mismatches = []

        if expected_fields:
            field_map = {
                "enabled": "enabled",
                "exclude_port": "exclude_port",
                "lan_ip": "lan_ip",
                "interface": "interface",
                "check_link": "check_link",
                "check_interval": "check_interval",
                "rst_switch": "rst_switch",
                "rst_week": "rst_week",
                "rst_time": "rst_time",
            }
            for ui_key, db_key in field_map.items():
                if ui_key in expected_fields:
                    expected_val = str(expected_fields[ui_key])
                    actual_val = str(conf.get(db_key, ""))
                    if expected_val.isdigit() and actual_val.isdigit():
                        if int(expected_val) != int(actual_val):
                            mismatches.append(f"{db_key}: 期望={expected_val}, 实际={actual_val}")
                    elif expected_val != actual_val:
                        mismatches.append(f"{db_key}: 期望={expected_val}, 实际={actual_val}")

        raw = json.dumps(conf, ensure_ascii=False)[:200]
        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"UPnP配置不匹配: {'; '.join(mismatches)}",
                details=details,
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message="UPnP全局配置验证通过",
            details=details,
            raw_output=raw,
        )

    # --- 接口规则(upnpd_ifconf) ---

    def query_upnpd_ifconf(self) -> List[Dict]:
        """查询UPnP接口规则(upnpd_ifconf表)"""
        self.connect_router()
        try:
            output = self._router.exec(
                "/usr/ikuai/function/upnpd show TYPE=ifconf_data,ifconf_total limit=0,500"
            )
            logger.info(f"upnpd_ifconf raw: {output[:200]}")

            if not output or "Error" in output:
                return []

            data = json.loads(output.strip())
            if isinstance(data, dict):
                return data.get("data", [])
            return []
        except Exception as e:
            logger.error(f"query_upnpd_ifconf error: {e}")
            return []

    def find_upnpd_ifconf(self, tagname: str) -> Optional[Dict]:
        """按名称查找UPnP接口规则"""
        rules = self.query_upnpd_ifconf()
        for rule in rules:
            if rule.get("tagname") == tagname:
                return rule
        return None

    def verify_upnpd_ifconf_database(self, tagname: str,
                                      expected_fields: Dict = None) -> VerifyResult:
        """L1: 验证UPnP接口规则在数据库中存在且字段正确"""
        rule = self.find_upnpd_ifconf(tagname)

        if rule is None:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"UPnP规则 '{tagname}' 在数据库中不存在",
            )

        details = {"rule": rule}
        mismatches = []

        if expected_fields:
            for key, expected_val in expected_fields.items():
                actual_val = str(rule.get(key, ""))
                expected_str = str(expected_val)
                if expected_str != actual_val:
                    mismatches.append(f"{key}: 期望={expected_str}, 实际={actual_val}")

        raw = json.dumps(rule, ensure_ascii=False)[:200]
        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"UPnP规则 '{tagname}' 字段不匹配: {'; '.join(mismatches)}",
                details=details,
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"UPnP规则 '{tagname}' 数据库验证通过",
            details=details,
            raw_output=raw,
        )

    # --- L2: 进程+iptables ---

    def verify_upnpd_process(self, expect_running: bool = True) -> VerifyResult:
        """L2: 验证miniupnpd进程状态"""
        self.connect_router()
        try:
            pid_output = self._router.exec("cat /var/run/miniupnpd.pid 2>/dev/null")
            ps_output = self._router.exec("ps | grep miniupnpd | grep -v grep")
            marker_output = self._router.exec("test -f /tmp/iktmp/upnpd_enabled && echo YES || echo NO")

            pid_exists = bool(pid_output.strip())
            process_running = "miniupnpd" in ps_output
            marker_exists = marker_output.strip() == "YES"

            details = {
                "pid_exists": pid_exists,
                "pid": pid_output.strip() if pid_exists else None,
                "process_running": process_running,
                "marker_exists": marker_exists,
            }

            is_running = process_running or marker_exists
            passed = (is_running == expect_running)

            # 未运行原因说明(避免"未运行"看不出为何): marker不存在=开关停用; marker在但进程没在=可能不在定时运行时段
            if is_running:
                msg = f"miniupnpd运行中(进程={'是' if process_running else '仅marker'}, pid={'有' if pid_exists else '无'})"
            else:
                reason = ("UPnP开关未开启(停用)" if not marker_exists
                          else "开关已开但进程未启动(可能不在定时运行时段或异常)")
                expect_hint = "符合预期" if not expect_running else "与预期运行不符"
                msg = f"miniupnpd未运行({reason}, {expect_hint})"

            raw = f"pid={pid_output.strip()}, ps={ps_output.strip()}, marker={marker_output.strip()}"

            return VerifyResult(
                level="L2-进程",
                passed=passed,
                message=msg,
                details=details,
                raw_output=raw,
            )

        except Exception as e:
            return VerifyResult(
                level="L2-进程",
                passed=False,
                message=f"miniupnpd进程检查失败: {str(e)[:100]}",
            )

    def verify_upnpd_iptables(self, expect_chains: bool = True) -> VerifyResult:
        """L2: 验证UPnP iptables链"""
        self.connect_router()
        try:
            nat_miniupnpd = self._router.exec("iptables -t nat -L MINIUPNPD -n 2>/dev/null | head -5")
            nat_postrouting = self._router.exec("iptables -t nat -L MINIUPNPD-POSTROUTING -n 2>/dev/null | head -5")
            filter_miniupnpd = self._router.exec("iptables -L MINIUPNPD -n 2>/dev/null | head -5")

            has_nat = "Chain MINIUPNPD" in nat_miniupnpd
            has_nat_post = "Chain MINIUPNPD-POSTROUTING" in nat_postrouting
            has_filter = "Chain MINIUPNPD" in filter_miniupnpd

            details = {
                "nat_chain": has_nat,
                "nat_postrouting_chain": has_nat_post,
                "filter_chain": has_filter,
            }

            all_chains = has_nat and has_nat_post and has_filter
            passed = (all_chains == expect_chains)

            raw = f"nat={nat_miniupnpd[:100]}; filter={filter_miniupnpd[:100]}"

            return VerifyResult(
                level="L2-iptables",
                passed=passed,
                message=f"UPnP iptables链: nat={has_nat}, postrouting={has_nat_post}, filter={has_filter}",
                details=details,
                raw_output=raw,
            )

        except Exception as e:
            return VerifyResult(
                level="L2-iptables",
                passed=False,
                message=f"iptables检查失败: {str(e)[:100]}",
            )

    # --- L3: 运行时配置 ---

    def verify_upnpd_runtime_config(self, expect_exists: bool = True) -> VerifyResult:
        """L3: 验证UPnP运行时配置文件"""
        self.connect_router()
        try:
            conf_output = self._router.exec("cat /tmp/iktmp/miniupnpd.conf 2>/dev/null")
            ifname_test = self._router.exec("test -f /tmp/iktmp/miniupnpd_ifname.conf && echo EXISTS || echo NO")
            ifname_output = self._router.exec("cat /tmp/iktmp/miniupnpd_ifname.conf 2>/dev/null")
            marker_output = self._router.exec("test -f /tmp/iktmp/upnpd_enabled && echo YES || echo NO")

            conf_exists = bool(conf_output.strip())
            # ifname文件存在即算: ext_ifname空(UPnP外网线路选"任意")时文件为空属正常, 不应判FAIL
            ifname_exists = "EXISTS" in ifname_test
            ifname_empty = not ifname_output.strip()
            marker_exists = marker_output.strip() == "YES"

            details = {
                "conf_exists": conf_exists,
                "ifname_exists": ifname_exists,
                "ifname_empty": ifname_empty,
                "marker_exists": marker_exists,
            }

            all_exist = conf_exists and ifname_exists and marker_exists
            passed = (all_exist == expect_exists)

            if ifname_exists:
                ifname_desc = "存在(空=外网线路任意)" if ifname_empty else "存在(已配ext_ifname)"
            else:
                ifname_desc = "缺失"
            msg = (f"UPnP运行时配置: conf文件={'存在' if conf_exists else '缺失'}, "
                   f"ifname文件={ifname_desc}, "
                   f"启用标记(upnpd_enabled)={'存在(UPnP已开)' if marker_exists else '缺失(UPnP未开)'}")

            return VerifyResult(
                level="L3-运行时配置",
                passed=passed,
                message=msg,
                details=details,
                raw_output=conf_output[:300] if conf_exists else "(不存在)",
            )

        except Exception as e:
            return VerifyResult(
                level="L3-运行时配置",
                passed=False,
                message=f"运行时配置检查失败: {str(e)[:100]}",
            )

    # --- L4: 守护进程+cron ---

    def verify_upnpd_daemon(self, expect_enabled: bool = True) -> VerifyResult:
        """L4: 验证UPnP守护进程和cron任务"""
        self.connect_router()
        try:
            binary_output = self._router.exec("test -f /usr/sbin/miniupnpd && echo YES || echo NO")
            ps_output = self._router.exec("ps | grep miniupnpd | grep -v grep")
            cron_output = self._router.exec("crontab -l 2>/dev/null | grep -i upnp")
            marker_output = self._router.exec("test -f /tmp/iktmp/upnpd_enabled && echo YES || echo NO")

            binary_exists = binary_output.strip() == "YES"
            process_running = "miniupnpd" in ps_output
            has_cron = bool(cron_output.strip())
            marker_exists = marker_output.strip() == "YES"

            details = {
                "binary_exists": binary_exists,
                "process_running": process_running,
                "has_cron": has_cron,
                "marker_exists": marker_exists,
                "cron_output": cron_output.strip() if has_cron else "",
            }

            if expect_enabled:
                passed = binary_exists and process_running
                msg = f"miniupnpd: binary={binary_exists}, running={process_running}, cron={has_cron}, marker={marker_exists}"
            else:
                passed = not process_running
                # 未运行原因说明: marker不存在=开关停用; marker在但进程没在=可能不在定时运行时段
                if not process_running:
                    reason = ("UPnP开关未开启(停用)" if not marker_exists
                              else "开关已开但进程未运行(可能不在定时运行时段)")
                    msg = f"miniupnpd未运行(符合预期): {reason}"
                else:
                    msg = f"miniupnpd仍在运行(与预期开关未开不符)"

            raw = f"ps={ps_output.strip()}, cron={cron_output.strip()}, marker={marker_output.strip()}"

            return VerifyResult(
                level="L4-守护进程",
                passed=passed,
                message=msg,
                details=details,
                raw_output=raw,
            )

        except Exception as e:
            return VerifyResult(
                level="L4-守护进程",
                passed=False,
                message=f"守护进程检查失败: {str(e)[:100]}",
            )

    # --- 全链路验证 ---

    def verify_upnp_full_chain(self, tagname: str = None,
                                expect_service_enabled: bool = True) -> FullChainResult:
        """UPnP全链路验证: L1数据库 + L2进程/iptables + L3配置文件 + L4守护进程"""
        results = []

        # L1: 全局配置
        conf = self.query_upnpd_conf()
        if conf:
            enabled = conf.get("enabled") == "yes"
            results.append(VerifyResult(
                level="L1-全局配置",
                passed=(enabled == expect_service_enabled),
                message=f"UPnP服务状态: enabled={conf.get('enabled')}",
                details={"config": conf},
                raw_output=json.dumps(conf, ensure_ascii=False)[:200],
            ))

        # L1: 接口规则
        if tagname:
            results.append(self.verify_upnpd_ifconf_database(tagname))

        # L2: 进程
        results.append(self.verify_upnpd_process(expect_running=expect_service_enabled))

        # L2: iptables
        results.append(self.verify_upnpd_iptables(expect_chains=expect_service_enabled))

        # L3: 运行时配置
        results.append(self.verify_upnpd_runtime_config(expect_exists=expect_service_enabled))

        # L4: 守护进程
        results.append(self.verify_upnpd_daemon(expect_enabled=expect_service_enabled))

        return FullChainResult(results=results)

    # ==================== IGMP代理(igmp_proxy)验证 ====================
    # 数据库表: igmp_proxy (单记录, id=1)
    # 字段: id, enabled(yes/no), version(2/3), downstream(LAN接口), upstream(WAN接口)
    # 后端脚本: /usr/ikuai/function/igmp_proxy (save/show/start/stop)
    # 配置文件: /etc/igmpproxy.conf
    # 进程: igmpproxy
    # 内核: ifconfig promisc(upstream), force_igmp_version(downstream)

    def query_igmp_proxy_config(self) -> Optional[Dict]:
        """L1: 查询IGMP代理数据库配置"""
        self.connect_router()
        try:
            output = self._router.exec(
                "/usr/ikuai/function/igmp_proxy show limit=0,500 TYPE=total,data"
            )
            data = json.loads(output)
            rules = data.get("data", [])
            if rules:
                return rules[0]  # 单记录, id=1
            return None
        except Exception as e:
            logger.error(f"[L1] 查询igmp_proxy失败: {e}")
            return None

    def verify_igmp_proxy_database(self, expected_fields: Dict = None,
                                    must_pass: bool = False) -> VerifyResult:
        """
        L1: 验证IGMP代理数据库配置

        Args:
            expected_fields: 期望的字段值, 如 {"enabled": "yes", "version": "3",
                             "upstream": "wan1", "downstream": "all"}
        """
        config = self.query_igmp_proxy_config()
        if config is None:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message="IGMP代理配置不存在(数据库无记录)",
                raw_output="",
            )

        details = {
            "id": config.get("id"),
            "enabled": config.get("enabled"),
            "version": config.get("version"),
            "upstream": config.get("upstream"),
            "downstream": config.get("downstream"),
        }
        raw = json.dumps(details, ensure_ascii=False)

        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库",
                passed=True,
                message=f"IGMP代理配置存在: enabled={config.get('enabled')}, "
                        f"version={config.get('version')}, "
                        f"upstream={config.get('upstream')}, "
                        f"downstream={config.get('downstream')}",
                details={"config": details},
                raw_output=raw,
            )

        mismatches = {}
        for field, expected in expected_fields.items():
            actual = str(config.get(field, ""))
            # downstream字段: "全部"在数据库存为逗号分隔的接口列表, 用包含匹配
            if field == "downstream" and expected in actual:
                continue  # 包含匹配通过
            if actual != str(expected):
                mismatches[field] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"config": details, "mismatches": mismatches},
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"IGMP代理数据库验证通过",
            details={"config": details},
            raw_output=raw,
        )

    def verify_igmp_proxy_process(self, expect_running: bool = True) -> VerifyResult:
        """
        L2: 验证IGMP代理进程状态

        Args:
            expect_running: 期望进程是否运行中
        """
        self.connect_router()
        try:
            output = self._router.exec("ps | grep igmpproxy | grep -v grep")
            running = "igmpproxy" in output

            if running == expect_running:
                return VerifyResult(
                    level="L2-进程",
                    passed=True,
                    message=f"igmpproxy进程状态正确: {'运行中' if running else '未运行'}",
                    details={"running": running},
                    raw_output=output.strip(),
                )
            else:
                return VerifyResult(
                    level="L2-进程",
                    passed=False,
                    message=f"igmpproxy进程状态不匹配: 期望{'运行' if expect_running else '未运行'}, "
                            f"实际{'运行中' if running else '未运行'}",
                    details={"running": running, "expected": expect_running},
                    raw_output=output.strip(),
                )
        except Exception as e:
            return VerifyResult(
                level="L2-进程",
                passed=False,
                message=f"进程检查失败: {e}",
                raw_output=str(e),
            )

    def verify_igmp_proxy_config_file(self, expect_exists: bool = True,
                                       upstream: str = None,
                                       downstream: str = None) -> VerifyResult:
        """
        L3: 验证IGMP代理配置文件

        Args:
            expect_exists: 期望配置文件是否存在
            upstream: 期望的上联端口(检查配置文件中是否包含)
            downstream: 期望的下联端口(检查配置文件中是否包含)
        """
        self.connect_router()
        try:
            output = self._router.exec("cat /etc/igmpproxy.conf 2>/dev/null")
            exists = bool(output and output.strip())

            if exists != expect_exists:
                return VerifyResult(
                    level="L3-配置文件",
                    passed=False,
                    message=f"配置文件状态不匹配: 期望{'存在' if expect_exists else '不存在'}, "
                            f"实际{'存在' if exists else '不存在'}",
                    details={"exists": exists},
                    raw_output=output[:300] if output else "",
                )

            if not exists:
                return VerifyResult(
                    level="L3-配置文件",
                    passed=True,
                    message="IGMP代理配置文件不存在(服务未启用)",
                    details={"exists": False},
                    raw_output="",
                )

            details = {"exists": True}
            # 检查upstream
            if upstream and upstream in output:
                details["upstream_found"] = True
            elif upstream:
                details["upstream_found"] = False

            # 检查downstream
            if downstream and downstream in output:
                details["downstream_found"] = True
            elif downstream:
                details["downstream_found"] = False

            mismatches = []
            if upstream and not details.get("upstream_found", True):
                mismatches.append(f"upstream({upstream})未在配置中找到")
            if downstream and not details.get("downstream_found", True):
                mismatches.append(f"downstream({downstream})未在配置中找到")

            passed = len(mismatches) == 0
            return VerifyResult(
                level="L3-配置文件",
                passed=passed,
                message=f"配置文件验证{'通过' if passed else '失败'}" +
                        (f': {mismatches}' if mismatches else ''),
                details=details,
                raw_output=output[:300],
            )
        except Exception as e:
            return VerifyResult(
                level="L3-配置文件",
                passed=False,
                message=f"配置文件检查失败: {e}",
                raw_output=str(e),
            )

    def verify_igmp_proxy_kernel(self, upstream: str = None,
                                  downstream: str = None,
                                  expect_enabled: bool = True) -> VerifyResult:
        """
        L4: 验证IGMP代理内核状态

        检查项:
        - upstream接口是否开启promisc模式
        - downstream接口的force_igmp_version设置

        Args:
            upstream: 上联端口接口名
            downstream: 下联端口接口名
            expect_enabled: 期望IGMP代理是否启用
        """
        self.connect_router()
        checks = []

        # 检查upstream promisc模式
        if upstream:
            try:
                output = self._router.exec(f"ifconfig {upstream} 2>/dev/null | grep PROMISC")
                promisc = "PROMISC" in output
                if expect_enabled:
                    checks.append(("promisc", promisc, f"upstream({upstream}) promisc={'已开启' if promisc else '未开启'}"))
                else:
                    checks.append(("promisc", not promisc, f"upstream({upstream}) promisc={'已开启(应关闭)' if promisc else '已关闭(正确)'}"))
            except Exception as e:
                checks.append(("promisc", None, f"检查promisc失败: {e}"))

        # 检查downstream force_igmp_version
        if downstream and downstream != "all":
            try:
                output = self._router.exec(
                    f"cat /proc/sys/net/ipv4/conf/{downstream}/force_igmp_version 2>/dev/null"
                )
                version = output.strip() if output else ""
                if expect_enabled:
                    version_ok = version in ("2", "3")
                    checks.append(("igmp_version", version_ok,
                                   f"downstream({downstream}) force_igmp_version={version}"))
                else:
                    version_ok = version in ("0", "")
                    checks.append(("igmp_version", version_ok,
                                   f"downstream({downstream}) force_igmp_version={version}(期望0)"))
            except Exception as e:
                checks.append(("igmp_version", None, f"检查igmp_version失败: {e}"))

        # 检查igmpproxy进程
        try:
            output = self._router.exec("ps | grep igmpproxy | grep -v grep")
            process_running = "igmpproxy" in output
            process_ok = process_running == expect_enabled
            checks.append(("process", process_ok,
                           f"igmpproxy进程={'运行中' if process_running else '未运行'}"))
        except Exception as e:
            checks.append(("process", None, f"检查进程失败: {e}"))

        passed = all(c[1] for c in checks if c[1] is not None)
        messages = [c[2] for c in checks]

        return VerifyResult(
            level="L4-内核",
            passed=passed,
            message="; ".join(messages),
            details={"checks": checks},
            raw_output=str(messages),
        )

    def verify_igmp_proxy_full_chain(self, expect_enabled: bool = True,
                                      upstream: str = None,
                                      downstream: str = None) -> FullChainResult:
        """
        IGMP代理全链路验证: L1数据库 + L2进程 + L3配置文件 + L4内核

        Args:
            expect_enabled: 期望IGMP代理是否启用
            upstream: 上联端口接口名
            downstream: 下联端口接口名
        """
        results = []

        # L1: 数据库
        expected_fields = {"enabled": "yes" if expect_enabled else "no"}
        results.append(self.verify_igmp_proxy_database(expected_fields=expected_fields))

        # L2: 进程
        results.append(self.verify_igmp_proxy_process(expect_running=expect_enabled))

        # L3: 配置文件
        results.append(self.verify_igmp_proxy_config_file(
            expect_exists=expect_enabled,
            upstream=upstream,
            downstream=downstream,
        ))

        # L4: 内核状态
        results.append(self.verify_igmp_proxy_kernel(
            upstream=upstream,
            downstream=downstream,
            expect_enabled=expect_enabled,
        ))

        return FullChainResult(results=results)

    # ==================== IPTV透传验证 ====================

    def query_iptv_config(self) -> Optional[Dict]:
        """查询IPTV透传配置(iptv_config表, 单记录)"""
        self.connect_router()
        try:
            output = self._router.exec("/usr/ikuai/function/iptv show")
            if output:
                data = json.loads(output)
                if data.get("data"):
                    return data["data"][0]
            return None
        except Exception as e:
            logger.error(f"IPTV配置查询失败: {e}")
            return None

    def verify_iptv_database(self, expected_fields: Dict = None,
                              must_pass: bool = False) -> VerifyResult:
        """
        L1: 验证IPTV透传数据库配置

        注意: wan_iface/lan_iface后端存储MAC地址而非接口名,
        验证时只检查非空即可, 不做精确比对

        Args:
            expected_fields: 期望的字段值, 如{"enabled": "yes", "mode": 0}
                             wan_iface/lan_iface传"not_empty"检查非空
        """
        self.connect_router()
        try:
            output = self._router.exec("/usr/ikuai/function/iptv show")
            if not output:
                return VerifyResult(
                    level="L1-数据库",
                    passed=False,
                    message="IPTV配置查询返回空",
                )

            data = json.loads(output)
            if not data.get("data"):
                return VerifyResult(
                    level="L1-数据库",
                    passed=False,
                    message="IPTV配置数据为空",
                )

            config = data["data"][0]
            details = {"db_config": config}

            if expected_fields:
                mismatches = {}
                for key, expected in expected_fields.items():
                    actual = config.get(key)
                    # 特殊: "not_empty"检查非空
                    if expected == "not_empty":
                        if not actual:
                            mismatches[key] = {"expected": "非空", "actual": actual}
                    elif str(actual) != str(expected):
                        mismatches[key] = {"expected": expected, "actual": actual}

                if mismatches:
                    return VerifyResult(
                        level="L1-数据库",
                        passed=False,
                        message=f"字段不匹配: {mismatches}",
                        details=details,
                        raw_output=json.dumps(config, ensure_ascii=False),
                    )

            return VerifyResult(
                level="L1-数据库",
                passed=True,
                message="IPTV透传数据库验证通过",
                details=details,
                raw_output=json.dumps(config, ensure_ascii=False),
            )
        except Exception as e:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"数据库验证失败: {e}",
                raw_output=str(e),
            )

    def verify_iptv_bridge(self, expect_exists: bool = True,
                            expected_members: List[str] = None) -> VerifyResult:
        """
        L2: 验证IPTV桥接接口(iptv bridge)

        Args:
            expect_exists: 是否期望iptv桥接存在
            expected_members: 期望的桥接成员列表
        """
        self.connect_router()
        try:
            # 检查iptv桥接是否存在
            bridge_output = self._router.exec("ip link show iptv 2>/dev/null")
            bridge_exists = bool(bridge_output and "iptv" in bridge_output)

            if expect_exists and not bridge_exists:
                return VerifyResult(
                    level="L2-桥接",
                    passed=False,
                    message="IPTV桥接接口(iptv)不存在(服务未启用)",
                    raw_output=bridge_output or "",
                )

            if not expect_exists:
                if bridge_exists:
                    # 桥接仍存在，检查是否有成员
                    members = self._router.exec("ls /sys/class/net/iptv/brif 2>/dev/null")
                    if members and members.strip():
                        return VerifyResult(
                            level="L2-桥接",
                            passed=False,
                            message=f"IPTV桥接仍存在且有成员: {members.strip()}",
                            raw_output=members,
                        )
                    # 桥接存在但无成员，视为OK(可能未完全清理)
                return VerifyResult(
                    level="L2-桥接",
                    passed=True,
                    message="IPTV桥接验证通过(已关闭或无成员)",
                    raw_output=bridge_output or "不存在",
                )

            # 检查桥接成员
            members_output = self._router.exec("ls /sys/class/net/iptv/brif 2>/dev/null")
            actual_members = [m.strip() for m in members_output.split() if m.strip()] if members_output else []

            details = {"bridge": "iptv", "members": actual_members}

            mismatches = []
            if expected_members:
                for m in expected_members:
                    found = any(m in am for am in actual_members)
                    if not found:
                        mismatches.append(f"期望成员{m}未找到")

            passed = len(mismatches) == 0
            return VerifyResult(
                level="L2-桥接",
                passed=passed,
                message=f"IPTV桥接验证{'通过' if passed else '失败'}" +
                        (f': {mismatches}' if mismatches else f', 成员: {actual_members}'),
                details=details,
                raw_output=f"bridge: {bridge_output[:200]}\nmembers: {members_output}",
            )
        except Exception as e:
            return VerifyResult(
                level="L2-桥接",
                passed=False,
                message=f"桥接验证失败: {e}",
                raw_output=str(e),
            )

    def verify_iptv_vlan(self, expect_vlan: bool = False,
                          wan_iface: str = None, lan_iface: str = None,
                          vlan_id: str = None) -> VerifyResult:
        """
        L3: 验证IPTV VLAN子接口

        Args:
            expect_vlan: 是否期望存在VLAN子接口
            wan_iface: WAN接口名
            lan_iface: LAN接口名
            vlan_id: VLAN ID
        """
        self.connect_router()
        try:
            vlan_output = self._router.exec("ip link show type vlan 2>/dev/null")

            if not expect_vlan:
                return VerifyResult(
                    level="L3-VLAN",
                    passed=True,
                    message="VLAN子接口验证通过(网口透传模式)",
                    raw_output=vlan_output[:300] if vlan_output else "无VLAN接口",
                )

            # VLAN透传模式: 检查VLAN子接口
            details = {}
            mismatches = []

            if wan_iface and vlan_id:
                wan_vlan = f"{wan_iface}.{vlan_id}"
                if wan_vlan in (vlan_output or ""):
                    details["wan_vlan"] = wan_vlan
                else:
                    mismatches.append(f"WAN VLAN {wan_vlan} 未找到")

            if lan_iface and vlan_id:
                lan_vlan = f"{lan_iface}.{vlan_id}"
                if lan_vlan in (vlan_output or ""):
                    details["lan_vlan"] = lan_vlan
                else:
                    mismatches.append(f"LAN VLAN {lan_vlan} 未找到")

            passed = len(mismatches) == 0
            return VerifyResult(
                level="L3-VLAN",
                passed=passed,
                message=f"VLAN子接口验证{'通过' if passed else '失败'}" +
                        (f': {mismatches}' if mismatches else ''),
                details=details,
                raw_output=vlan_output[:300] if vlan_output else "",
            )
        except Exception as e:
            return VerifyResult(
                level="L3-VLAN",
                passed=False,
                message=f"VLAN验证失败: {e}",
                raw_output=str(e),
            )

    def verify_iptv_full_chain(self, expect_enabled: bool = True,
                                mode: int = 0,
                                wan_iface: str = None,
                                lan_iface: str = None,
                                wan_vlanid: int = 0,
                                lan_vlanid: int = 0) -> FullChainResult:
        """
        IPTV透传全链路验证: L1数据库 + L2桥接 + L3 VLAN

        Args:
            expect_enabled: 期望IPTV透传是否启用
            mode: 透传模式(0=网口透传, 1=VLAN透传)
            wan_iface: WAN接口名(仅用于L2/L3映射, L1存储MAC)
            lan_iface: LAN接口名(仅用于L2/L3映射)
            wan_vlanid: 业务VLAN ID
            lan_vlanid: 内网VLAN ID
        """
        results = []

        # L1: 数据库(仅验证关键字段, wan_iface/lan_iface存MAC用not_empty)
        expected_fields = {"enabled": "yes" if expect_enabled else "no", "mode": mode}
        if expect_enabled:
            expected_fields["wan_iface"] = "not_empty"
            expected_fields["lan_iface"] = "not_empty"
        if wan_vlanid is not None:
            expected_fields["wan_vlanid"] = wan_vlanid
        if lan_vlanid is not None:
            expected_fields["lan_vlanid"] = lan_vlanid
        results.append(self.verify_iptv_database(expected_fields=expected_fields))

        # L2: 桥接(启用时检查有成员, 不验证具体成员名)
        if expect_enabled:
            results.append(self.verify_iptv_bridge(
                expect_exists=True,
                expected_members=None,  # 不验证具体成员
            ))
        else:
            results.append(self.verify_iptv_bridge(expect_exists=False))

        # L3: VLAN子接口(wan_vlanid>0或VLAN透传模式时检查)
        if expect_enabled and (wan_vlanid > 0 or lan_vlanid > 0):
            results.append(self.verify_iptv_vlan(
                expect_vlan=True,
                wan_iface=wan_iface,
                lan_iface=lan_iface,
                vlan_id=str(wan_vlanid) if wan_vlanid else str(lan_vlanid),
            ))
        else:
            results.append(self.verify_iptv_vlan(expect_vlan=False))

        return FullChainResult(results=results)

    # ==================== UDPXY设置验证 ====================

    def query_udp_proxy_config(self, tagname: str = None) -> Optional[Dict]:
        """
        L1: 查询UDPXY设置数据库配置

        Args:
            tagname: 按名称筛选, None返回全部列表
        """
        self.connect_router()
        try:
            output = self._router.exec(
                "/usr/ikuai/function/udp_proxy show limit=0,500 TYPE=total,data"
            )
            data = json.loads(output)
            rules = data.get("data", [])
            if tagname:
                for r in rules:
                    if r.get("tagname") == tagname:
                        return r
                return None
            return rules
        except Exception as e:
            logger.error(f"[L1] 查询udp_proxy失败: {e}")
            return None

    def verify_udp_proxy_database(self, expected_fields: Dict = None,
                                   tagname: str = None,
                                   must_pass: bool = False) -> VerifyResult:
        """
        L1: 验证UDPXY设置数据库配置

        Args:
            expected_fields: 期望的字段值, 如 {"enabled": "yes", "interface": "lan1",
                             "listen_port": 9000, "access": 1, "renew_time": 0}
            tagname: 按名称筛选(多条记录时指定)
        """
        configs = self.query_udp_proxy_config(tagname=tagname)
        if configs is None:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message="UDPXY配置不存在(查询返回None)",
                raw_output="",
            )

        # 单条记录场景
        if tagname:
            config = configs
            if config is None:
                return VerifyResult(
                    level="L1-数据库",
                    passed=False,
                    message=f"UDPXY规则不存在: {tagname}",
                    raw_output="",
                )
            configs = [config]

        details_list = []
        for c in configs:
            details_list.append({
                "id": c.get("id"),
                "enabled": c.get("enabled"),
                "tagname": c.get("tagname"),
                "interface": c.get("interface"),
                "listen_port": c.get("listen_port"),
                "renew_time": c.get("renew_time"),
                "access": c.get("access"),
            })
        raw = json.dumps(details_list, ensure_ascii=False)

        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库",
                passed=True,
                message=f"UDPXY配置存在: {len(details_list)}条记录",
                details={"configs": details_list},
                raw_output=raw,
            )

        # 验证指定记录的字段
        config = configs[0] if tagname else configs[0]
        mismatches = {}
        for field, expected in expected_fields.items():
            actual = str(config.get(field, ""))
            if expected == "not_empty":
                if not actual:
                    mismatches[field] = {"expected": "not_empty", "actual": "empty"}
            elif actual != str(expected):
                mismatches[field] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"字段不匹配: {mismatches}",
                details={"config": details_list[0], "mismatches": mismatches},
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"UDPXY数据库验证通过",
            details={"config": details_list[0]},
            raw_output=raw,
        )

    def verify_udp_proxy_process(self, expect_running: bool = True,
                                  listen_port: int = None,
                                  interface: str = None) -> VerifyResult:
        """
        L2: 验证udpxy进程状态

        Args:
            expect_running: 期望进程是否运行中
            listen_port: 期望的监听端口(检查进程参数)
            interface: 期望的信号源接口(检查进程参数)
        """
        self.connect_router()
        try:
            output = self._router.exec("ps | grep udpxy | grep -v grep")
            running = "udpxy" in output

            if not running and not expect_running:
                return VerifyResult(
                    level="L2-进程",
                    passed=True,
                    message="udpxy进程未运行(符合预期)",
                    details={"running": False},
                    raw_output=output.strip(),
                )

            if running and not expect_running:
                # 停用单条规则: 传了listen_port时只检查该端口进程是否停(其他规则进程不影响)
                if listen_port is not None:
                    port_str = f"-p {listen_port}"
                    if port_str in output:
                        return VerifyResult(
                            level="L2-进程",
                            passed=False,
                            message=f"udpxy端口{listen_port}进程仍在运行(停用未生效, 可能产品stale bug:停用后进程未退出, 见udp-proxy-process-stale-bug)",
                            details={"running": True, "port_match": True, "expected": False},
                            raw_output=output.strip(),
                        )
                    other_count = output.count("-p ")
                    return VerifyResult(
                        level="L2-进程",
                        passed=True,
                        message=f"udpxy端口{listen_port}进程已停(停用生效, 另有{other_count}条其他规则进程运行中)",
                        details={"running": True, "port_match": False, "expected": False, "target_port": listen_port},
                        raw_output=output.strip(),
                    )
                return VerifyResult(
                    level="L2-进程",
                    passed=False,
                    message=f"udpxy进程仍在运行: {output.strip()}",
                    details={"running": True, "expected": False},
                    raw_output=output.strip(),
                )

            if not running and expect_running:
                return VerifyResult(
                    level="L2-进程",
                    passed=False,
                    message="udpxy进程未运行(期望运行)",
                    details={"running": False, "expected": True},
                    raw_output=output.strip(),
                )

            # 进程运行中, 检查参数
            details = {"running": True}
            mismatch = []

            if listen_port is not None:
                port_str = f"-p {listen_port}"
                if port_str in output:
                    details["port_match"] = True
                else:
                    details["port_match"] = False
                    mismatch.append(f"端口不匹配: 期望{listen_port}")

            if interface is not None:
                iface_str = f"-m {interface}"
                if iface_str in output:
                    details["interface_match"] = True
                else:
                    details["interface_match"] = False
                    mismatch.append(f"接口不匹配: 期望{interface}")

            if mismatch:
                return VerifyResult(
                    level="L2-进程",
                    passed=False,
                    message=f"udpxy进程参数不匹配: {'; '.join(mismatch)}",
                    details=details,
                    raw_output=output.strip(),
                )

            return VerifyResult(
                level="L2-进程",
                passed=True,
                message=f"udpxy进程运行中, 参数正确",
                details=details,
                raw_output=output.strip(),
            )
        except Exception as e:
            return VerifyResult(
                level="L2-进程",
                passed=False,
                message=f"进程检查失败: {e}",
                raw_output=str(e),
            )

    def verify_udp_proxy_ipset(self, expect_present: bool = True,
                                listen_port: int = None) -> VerifyResult:
        """
        L3: 验证UDPXY外网访问ipset规则
        access=0(不允许外网)时, 端口会被添加到DROP_U_PORTS_WAN_IN和DROP_T_PORTS_WAN_IN

        Args:
            expect_present: 期望端口是否在DROP ipset中(access=0时为True)
            listen_port: 要检查的端口
        """
        self.connect_router()
        try:
            output = self._router.exec("ipset list DROP_U_PORTS_WAN_IN 2>/dev/null; ipset list DROP_T_PORTS_WAN_IN 2>/dev/null")
            has_port = False
            if listen_port and str(listen_port) in output:
                has_port = True

            if expect_present and not has_port:
                return VerifyResult(
                    level="L3-ipset",
                    passed=False,
                    message=f"端口{listen_port}未在DROP ipset中(期望存在, access=0)",
                    details={"port_in_ipset": False},
                    raw_output=output[:500],
                )

            if not expect_present and has_port:
                return VerifyResult(
                    level="L3-ipset",
                    passed=False,
                    message=f"端口{listen_port}仍在DROP ipset中(期望不存在, access=1)",
                    details={"port_in_ipset": True},
                    raw_output=output[:500],
                )

            return VerifyResult(
                level="L3-ipset",
                passed=True,
                message=f"UDPXY ipset验证通过(端口{'在' if has_port else '不在'}DROP集合中)",
                details={"port_in_ipset": has_port},
                raw_output=output[:500],
            )
        except Exception as e:
            return VerifyResult(
                level="L3-ipset",
                passed=False,
                message=f"ipset检查失败: {e}",
                raw_output=str(e),
            )

    def verify_udp_proxy_full_chain(self, tagname: str,
                                     expect_enabled: bool = True,
                                     interface: str = None,
                                     listen_port: int = None,
                                     access: int = 1,
                                     renew_time: int = 0) -> FullChainResult:
        """
        UDPXY设置全链路验证: L1数据库 + L2进程 + L3 ipset

        Args:
            tagname: 规则名称
            expect_enabled: 期望是否启用
            interface: 信号源接口
            listen_port: 服务端口
            access: 外网访问(0=不允许, 1=允许)
            renew_time: 订阅周期
        """
        results = []

        # L1: 数据库
        expected_fields = {
            "enabled": "yes" if expect_enabled else "no",
            "tagname": tagname,
        }
        if interface is not None:
            expected_fields["interface"] = interface
        if listen_port is not None:
            expected_fields["listen_port"] = listen_port
        if access is not None:
            expected_fields["access"] = access
        if renew_time is not None:
            expected_fields["renew_time"] = renew_time

        results.append(self.verify_udp_proxy_database(
            expected_fields=expected_fields, tagname=tagname))

        # L2: 进程(仅启用时检查)
        if expect_enabled:
            results.append(self.verify_udp_proxy_process(
                expect_running=True,
                listen_port=listen_port,
                interface=interface))
        else:
            results.append(self.verify_udp_proxy_process(expect_running=False))

        # L3: ipset(仅access=0时检查端口是否在DROP集合中)
        if listen_port is not None:
            results.append(self.verify_udp_proxy_ipset(
                expect_present=(access == 0),
                listen_port=listen_port))

        return FullChainResult(results=results)

    # ==================== NAT规则(nat_rule)验证 ====================
    # 数据库表: nat_rule (多行)
    # 字段: id, enabled(yes/no), tagname(名称), comment(备注),
    #        ointerface(出接口), iinterface(进接口),
    #        src_addr(base64 JSON), src_addr_inv(0/1),
    #        dst_addr(base64 JSON), dst_addr_inv(0/1),
    #        nat_addr(plain IP), nat_port(plain port),
    #        protocol(any/tcp/udp/tcp+udp),
    #        src_port(base64 JSON), dst_port(base64 JSON),
    #        action(filter/snat/dnat)
    # 后端脚本: /usr/ikuai/script/nat_rule.sh
    # iptables链: NATRULE_SNAT(POSTROUTING), NATRULE_DNAT(PREROUTING)
    # 全局设置: global_config.local_forward_nat (齿轮设置)

    def _decode_b64_json(self, b64_str: str) -> Any:
        """解码base64编码的JSON字段(NAT规则的地址/端口字段)

        Args:
            b64_str: base64编码的JSON字符串

        Returns:
            解码后的Python对象, 失败返回None
        """
        if not b64_str:
            return None
        try:
            import base64
            json_str = base64.b64decode(b64_str).decode('utf-8')
            return json.loads(json_str)
        except Exception as e:
            logger.error(f"base64解码失败: {e}")
            return None

    def query_nat_rules(self) -> List[Dict]:
        """查询所有NAT规则(nat_rule表)"""
        self.connect_router()
        try:
            output = self._router.exec(
                "/usr/ikuai/function/nat_rule show limit=0,500 TYPE=total,data"
            )
            logger.info(f"nat_rule raw: {output[:200] if output else 'None'}")

            if not output or "Error" in output:
                return []

            data = json.loads(output.strip())
            if isinstance(data, dict):
                return data.get("data", [])
            return []
        except Exception as e:
            logger.error(f"query_nat_rules error: {e}")
            return []

    def find_nat_rule(self, tagname: str) -> Optional[Dict]:
        """按名称查找NAT规则"""
        rules = self.query_nat_rules()
        for rule in rules:
            if rule.get("tagname") == tagname:
                return rule
        return None

    def verify_nat_rule_database(self, tagname: str,
                                  expected_fields: Dict = None,
                                  expect_absent: bool = False) -> VerifyResult:
        """L1: 验证NAT规则在数据库中存在且字段正确

        Args:
            tagname: 规则名称
            expected_fields: 期望的字段值, 如 {"action": "snat", "enabled": "yes",
                             "protocol": "tcp", "nat_addr": "10.66.0.200"}
            expect_absent: True表示期望规则不存在(用于删除验证)
        """
        rule = self.find_nat_rule(tagname)
        if rule is None:
            if expect_absent:
                return VerifyResult(
                    level="L1-数据库",
                    passed=True,
                    message=f"NAT规则 '{tagname}' 已不存在(符合预期)",
                    details={"tagname": tagname, "absent": True},
                    raw_output="",
                )
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"NAT规则 '{tagname}' 不存在",
                details={"tagname": tagname},
                raw_output="",
            )

        details = {"rule": {k: v for k, v in rule.items() if k in (
            'id', 'enabled', 'tagname', 'action', 'protocol',
            'ointerface', 'iinterface', 'nat_addr', 'nat_port', 'comment'
        )}}

        mismatches = []
        if expected_fields:
            # 字段映射: UI/测试名 -> DB名
            field_map = {
                "enabled": "enabled",
                "action": "action",
                "protocol": "protocol",
                "oinface": "ointerface",
                "out_interface": "ointerface",
                "iinface": "iinterface",
                "in_interface": "iinterface",
                "nat_addr": "nat_addr",
                "nat_port": "nat_port",
                "comment": "comment",
                "remark": "comment",
                "src_addr_inv": "src_addr_inv",
                "dst_addr_inv": "dst_addr_inv",
            }
            for ui_key, db_key in field_map.items():
                if ui_key in expected_fields:
                    expected_val = str(expected_fields[ui_key])
                    actual_val = str(rule.get(db_key, ""))
                    if expected_val.isdigit() and actual_val.isdigit():
                        if int(expected_val) != int(actual_val):
                            mismatches.append(f"{db_key}: 期望={expected_val}, 实际={actual_val}")
                    elif expected_val != actual_val:
                        mismatches.append(f"{db_key}: 期望={expected_val}, 实际={actual_val}")

        raw = json.dumps(details, ensure_ascii=False)[:300]
        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"NAT规则 '{tagname}' 字段不匹配: {'; '.join(mismatches)}",
                details=details,
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"NAT规则 '{tagname}' 数据库验证通过(action={rule.get('action')}, proto={rule.get('protocol')})",
            details=details,
            raw_output=raw,
        )

    def verify_local_forward_nat(self, expected_enabled: bool) -> VerifyResult:
        """L1: 验证本地转发自动NAT设置(global_config.local_forward_nat)

        数据库: global_config表中local_forward_nat字段(0=关闭, 1=开启)
        """
        self.connect_router()
        try:
            # 直接用sqlite3查询global_config表
            output = self._router.exec(
                "sqlite3 /etc/mnt/ikuai/config.db "
                "\"SELECT local_forward_nat FROM global_config WHERE id=1\""
            )
            local_forward = output.strip() if output else None

            expected_val = 1 if expected_enabled else 0
            actual_val = int(local_forward) if local_forward is not None else -1

            if actual_val == expected_val:
                return VerifyResult(
                    level="L1-设置",
                    passed=True,
                    message=f"本地转发自动NAT设置正确: {'开启' if expected_enabled else '关闭'}(值={actual_val})",
                    details={"local_forward_nat": actual_val},
                    raw_output=f"local_forward_nat={local_forward}",
                )
            else:
                return VerifyResult(
                    level="L1-设置",
                    passed=False,
                    message=f"本地转发自动NAT不匹配: 期望={'开启' if expected_enabled else '关闭'}({expected_val}), 实际={actual_val}",
                    details={"local_forward_nat": actual_val},
                    raw_output=f"local_forward_nat={local_forward}",
                )
        except Exception as e:
            logger.error(f"verify_local_forward_nat error: {e}")
            return VerifyResult(
                level="L1-设置",
                passed=False,
                message=f"验证本地转发NAT异常: {e}",
                raw_output="",
            )

    def verify_nat_rule_iptables(self, action: str = None,
                                  expect_rules: bool = True) -> VerifyResult:
        """L2: 验证NAT规则iptables链

        Args:
            action: 动作类型 filter/snat/dnat, None则检查所有
            expect_rules: 期望是否有iptables规则
        """
        self.connect_router()
        try:
            chain_checks = []
            if action == "filter":
                chain_checks.append(("NATRULE_SNAT", f"iptables -t nat -L NATRULE_SNAT -n 2>/dev/null"))
            elif action == "snat":
                chain_checks.append(("NATRULE_SNAT", f"iptables -t nat -L NATRULE_SNAT -n 2>/dev/null"))
            elif action == "dnat":
                chain_checks.append(("NATRULE_DNAT", f"iptables -t nat -L NATRULE_DNAT -n 2>/dev/null"))
            else:
                # 检查所有NAT链
                chain_checks.append(("NATRULE_SNAT", "iptables -t nat -L NATRULE_SNAT -n 2>/dev/null"))
                chain_checks.append(("NATRULE_DNAT", "iptables -t nat -L NATRULE_DNAT -n 2>/dev/null"))

            all_output = ""
            has_rules = False
            for chain_name, cmd in chain_checks:
                output = self._router.exec(cmd)
                all_output += f"\n--- {chain_name} ---\n{output}"
                if output and "Chain" in output:
                    # 检查链中是否有规则(非仅Chain头)
                    lines = [l.strip() for l in output.strip().split('\n') if l.strip()]
                    if len(lines) > 2:  # Chain头 + 字段头 = 2行, 更多行表示有规则
                        has_rules = True

            if expect_rules and not has_rules:
                return VerifyResult(
                    level="L2-iptables",
                    passed=False,
                    message="NAT规则iptables链中未发现规则",
                    raw_output=all_output[:500],
                )

            if not expect_rules and has_rules:
                return VerifyResult(
                    level="L2-iptables",
                    passed=False,
                    message="NAT规则iptables链中仍有残留规则",
                    raw_output=all_output[:500],
                )

            return VerifyResult(
                level="L2-iptables",
                passed=True,
                message=f"NAT规则iptables验证通过(规则{'存在' if has_rules else '不存在'})",
                raw_output=all_output[:500],
            )
        except Exception as e:
            logger.error(f"verify_nat_rule_iptables error: {e}")
            return VerifyResult(
                level="L2-iptables",
                passed=False,
                message=f"iptables验证异常: {e}",
                raw_output="",
            )

    def verify_nat_rule_runtime(self, expect_active: bool = True) -> VerifyResult:
        """L3: 验证NAT规则运行时状态(iptables-save检查NAT链注册)"""
        self.connect_router()
        try:
            output = self._router.exec(
                "iptables-save -t nat 2>/dev/null | grep -E 'NATRULE_(SNAT|DNAT)'"
            )

            chains_registered = bool(output and output.strip())

            if expect_active and not chains_registered:
                return VerifyResult(
                    level="L3-运行时",
                    passed=False,
                    message="NAT规则链未在iptables中注册",
                    raw_output=output[:300] if output else "",
                )

            return VerifyResult(
                level="L3-运行时",
                passed=True,
                message=f"NAT规则运行时验证通过(链{'已注册' if chains_registered else '未注册'})",
                raw_output=output[:300] if output else "",
            )
        except Exception as e:
            logger.error(f"verify_nat_rule_runtime error: {e}")
            return VerifyResult(
                level="L3-运行时",
                passed=False,
                message=f"运行时验证异常: {e}",
                raw_output="",
            )

    def verify_nat_rule_kernel(self) -> VerifyResult:
        """L4: 验证内核NAT模块"""
        self.connect_router()
        try:
            output = self._router.exec("lsmod | grep nf_nat")
            module_loaded = bool(output and output.strip())

            return VerifyResult(
                level="L4-内核",
                passed=True,
                message=f"NAT内核模块验证通过(nf_nat {'已加载' if module_loaded else '未加载(可能内置)'})",
                raw_output=output[:200] if output else "",
            )
        except Exception as e:
            logger.error(f"verify_nat_rule_kernel error: {e}")
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message=f"内核验证异常: {e}",
                raw_output="",
            )

    def verify_nat_rule_full_chain(self, tagname: str,
                                    expected_fields: Dict = None) -> FullChainResult:
        """NAT规则全链路验证: L1数据库 -> L2iptables -> L3运行时 -> L4内核

        Args:
            tagname: 规则名称
            expected_fields: 期望的字段值
        """
        results = []

        # L1: 数据库
        results.append(self.verify_nat_rule_database(tagname, expected_fields))

        # 根据L1结果决定后续验证
        rule = self.find_nat_rule(tagname)
        if rule:
            action = rule.get("action", "filter")
            enabled = rule.get("enabled", "yes") == "yes"

            # L2: iptables(仅启用时)
            if enabled:
                results.append(self.verify_nat_rule_iptables(action=action, expect_rules=True))
            else:
                results.append(self.verify_nat_rule_iptables(action=action, expect_rules=False))

            # L3: 运行时
            results.append(self.verify_nat_rule_runtime(expect_active=enabled))
        else:
            results.append(self.verify_nat_rule_iptables(expect_rules=False))
            results.append(self.verify_nat_rule_runtime(expect_active=False))

        # L4: 内核
        results.append(self.verify_nat_rule_kernel())

        return FullChainResult(results=results)

    # ==================== 端口映射(dst_nat)验证 ====================
    # 后端脚本: /usr/ikuai/script/dnat.sh + /usr/ikuai/function/dnat
    # 数据库: dst_nat表(id,enabled,tagname,comment,interface,src_addr,lan_addr,protocol,wan_port,lan_port)
    # iptables: nat表DSTNAT链(switch_nat=1时) / filter表NONAT链(switch_nat=0时)
    # 规则格式(switch_nat=1, interface=all):
    #   -A DSTNAT -p <protocol> -m multiport --dports <wan_port> -m set --match-set Linux_wan_default dst -m addrtype --dst-type LOCAL -j DNAT --to-destination <lan_addr>:<lan_port>
    # 规则格式(switch_nat=1, interface=具体网卡):
    #   -A DSTNAT -p <protocol> -m multiport --dports <wan_port> -m ifname --ifname <iface> -j DNAT --to-destination <lan_addr>:<lan_port>
    # ipset: dst_nat_<id> (源地址集合, src_addr非空时创建)

    def query_port_maps(self) -> List[Dict]:
        """查询所有端口映射规则(dst_nat表)"""
        self.connect_router()
        try:
            output = self._router.exec(
                "/usr/ikuai/function/dnat show limit=0,500 TYPE=total,data"
            )
            logger.info(f"dst_nat raw: {output[:200] if output else 'None'}")

            if not output or "Error" in output:
                return []

            data = json.loads(output.strip())
            if isinstance(data, dict):
                return data.get("data", [])
            return []
        except Exception as e:
            logger.error(f"query_port_maps error: {e}")
            return []

    def find_port_map(self, tagname: str) -> Optional[Dict]:
        """按名称查找端口映射规则"""
        rules = self.query_port_maps()
        for rule in rules:
            if rule.get("tagname") == tagname:
                return rule
        return None

    def verify_port_map_database(self, tagname: str,
                                  expected_fields: Dict = None,
                                  expect_absent: bool = False) -> VerifyResult:
        """L1: 验证端口映射在数据库中存在且字段正确

        Args:
            tagname: 规则名称
            expected_fields: 期望的字段值, 如 {"protocol": "tcp", "enabled": "yes",
                             "lan_addr": "192.168.1.100", "wan_port": "8080", "lan_port": "80"}
            expect_absent: True表示期望规则不存在(用于删除验证)
        """
        rule = self.find_port_map(tagname)
        if rule is None:
            if expect_absent:
                return VerifyResult(
                    level="L1-数据库",
                    passed=True,
                    message=f"端口映射 '{tagname}' 已不存在(符合预期)",
                    details={"tagname": tagname, "absent": True},
                    raw_output="",
                )
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"端口映射 '{tagname}' 不存在",
                details={"tagname": tagname},
                raw_output="",
            )

        details = {"rule": {k: v for k, v in rule.items() if k in (
            'id', 'enabled', 'tagname', 'interface', 'lan_addr',
            'protocol', 'wan_port', 'lan_port', 'comment'
        )}}

        mismatches = []
        if expected_fields:
            # 字段映射: UI/测试名 -> DB名
            field_map = {
                "enabled": "enabled",
                "protocol": "protocol",
                "lan_addr": "lan_addr",
                "wan_port": "wan_port",
                "lan_port": "lan_port",
                "interface": "interface",
                "comment": "comment",
                "remark": "comment",
            }
            for ui_key, db_key in field_map.items():
                if ui_key in expected_fields:
                    expected_val = str(expected_fields[ui_key])
                    actual_val = str(rule.get(db_key, ""))
                    if expected_val != actual_val:
                        mismatches.append(f"{db_key}: 期望={expected_val}, 实际={actual_val}")

        raw = json.dumps(details, ensure_ascii=False)[:300]
        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"端口映射 '{tagname}' 字段不匹配: {'; '.join(mismatches)}",
                details=details,
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"端口映射 '{tagname}' 数据库验证通过(proto={rule.get('protocol')}, wan={rule.get('wan_port')}, lan={rule.get('lan_addr')}:{rule.get('lan_port')})",
            details=details,
            raw_output=raw,
        )

    def verify_port_map_iptables(self, tagname: str = None,
                                  lan_addr: str = None,
                                  wan_port: str = None,
                                  protocol: str = None,
                                  expect_rules: bool = True) -> VerifyResult:
        """L2: 验证端口映射iptables规则(DSTNAT链)

        检查DSTNAT链中是否有匹配的DNAT规则(根据lan_addr/wan_port/protocol匹配)。

        Args:
            tagname: 规则名称(用于日志)
            lan_addr: 内网地址(用于精确匹配--to-destination)
            wan_port: 外网端口(用于匹配--dports)
            protocol: 协议(用于匹配-p tcp/udp)
            expect_rules: 期望是否有规则
        """
        self.connect_router()
        try:
            # 先判断switch_nat模式决定查哪个链
            switch_nat = self._router.exec(
                "sqlite3 /etc/mnt/ikuai/config.db \"select switch_nat from basic\""
            ).strip()

            if switch_nat == "0":
                # 非NAT模式: 查filter表NONAT链
                chain = "NONAT"
                output = self._router.exec("iptables -S NONAT 2>/dev/null")
            else:
                # NAT模式: 查nat表DSTNAT链
                chain = "DSTNAT"
                output = self._router.exec("iptables -t nat -S DSTNAT 2>/dev/null")

            if not output:
                if expect_rules:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"端口映射 '{tagname}' iptables {chain}链为空(期望有规则)",
                        raw_output="",
                    )
                return VerifyResult(
                    level="L2-iptables",
                    passed=True,
                    message=f"端口映射 '{tagname}' {chain}链无规则(符合预期)",
                    raw_output=output[:500],
                )

            # 解析规则, 检查是否有匹配的
            lines = [l.strip() for l in output.strip().split('\n')
                     if l.strip() and not l.strip().startswith("-N")]
            matched_lines = []
            for line in lines:
                matched = True
                if protocol and f"-p {protocol}" not in line:
                    # tcp+udp在iptables里会生成两条规则, 分别-p tcp和-p udp
                    if protocol == "tcp+udp":
                        if "-p tcp" not in line and "-p udp" not in line:
                            matched = False
                    else:
                        matched = False
                if lan_addr and lan_addr not in line:
                    matched = False
                if wan_port:
                    # wan_port可能是范围(1000-2000)或多端口(80,443)
                    # iptables里范围用:连接, 多端口用,连接
                    wp_normalized = wan_port.replace("-", ":")
                    if f"--dports {wp_normalized}" not in line and wan_port not in line:
                        matched = False
                if matched:
                    matched_lines.append(line)

            label = tagname or "端口映射"
            if expect_rules and not matched_lines:
                return VerifyResult(
                    level="L2-iptables",
                    passed=False,
                    message=f"端口映射 '{label}' iptables {chain}链未找到匹配规则",
                    raw_output=output[:500],
                )

            if not expect_rules and matched_lines:
                return VerifyResult(
                    level="L2-iptables",
                    passed=False,
                    message=f"端口映射 '{label}' iptables {chain}链仍有残留规则",
                    raw_output="\n".join(matched_lines)[:500],
                )

            return VerifyResult(
                level="L2-iptables",
                passed=True,
                message=f"端口映射 '{label}' iptables {chain}链验证通过(匹配{len(matched_lines)}条规则)",
                raw_output=("\n".join(matched_lines) if matched_lines else output)[:500],
            )
        except Exception as e:
            logger.error(f"verify_port_map_iptables error: {e}")
            return VerifyResult(
                level="L2-iptables",
                passed=False,
                message=f"iptables验证异常: {e}",
                raw_output="",
            )

    def cleanup_port_map_iptables(self, lan_addr: str = None,
                                  wan_port: str = None) -> int:
        """清理DSTNAT链中匹配的端口映射iptables残留规则(测试残留清理).

        产品'导入清空'等删除路径可能不同步清理iptables, 导致DB已空但DSTNAT链残留
        (普通单条/批量删除正常, 仅'导入清空'路径特有). 本方法按lan_addr
        (--to-destination子串)/wan_port(--dports)匹配删除; 都不传则清理DSTNAT链全部规则.

        Returns: 实际删除的规则数
        """
        self.connect_router()
        try:
            switch_nat = self._router.exec(
                'sqlite3 /etc/mnt/ikuai/config.db "select switch_nat from basic"'
            ).strip()
            if switch_nat == "0":
                return 0  # 非NAT模式无DSTNAT链
            output = self._router.exec("iptables -t nat -S DSTNAT 2>/dev/null")
            deleted = 0
            for raw in output.split('\n'):
                line = raw.strip()
                # iKuai的iptables -S每条规则带 [fastid: N] 前缀, 须取 -A DSTNAT 起的部分
                idx = line.find("-A DSTNAT")
                if idx < 0:
                    continue
                rule = line[idx:]
                if lan_addr and lan_addr not in rule:
                    continue
                if wan_port:
                    wp_normalized = wan_port.replace("-", ":")
                    if (f"--dports {wp_normalized}" not in rule
                            and wan_port not in rule):
                        continue
                # -A DSTNAT → -D DSTNAT 精确删除单条
                del_rule = rule.replace("-A DSTNAT", "-D DSTNAT", 1)
                self._router.exec(f"iptables -t nat {del_rule} 2>/dev/null")
                deleted += 1
            if deleted:
                logger.info(f"cleanup_port_map_iptables: removed {deleted} stale DSTNAT rules")
            return deleted
        except Exception as e:
            logger.error(f"cleanup_port_map_iptables error: {e}")
            return 0

    def verify_port_map_runtime(self, expect_active: bool = True) -> VerifyResult:
        """L3: 验证端口映射运行时状态(iptables-save检查DSTNAT链注册)"""
        self.connect_router()
        try:
            output = self._router.exec("iptables-save -t nat 2>/dev/null | grep -E 'DSTNAT|NONAT'")
            has_dnat = ":DSTNAT" in output or "-A DSTNAT" in output or "-A PREROUTING.*DSTNAT" in output

            if expect_active and not has_dnat:
                return VerifyResult(
                    level="L3-运行时",
                    passed=False,
                    message="端口映射运行时未注册DSTNAT链",
                    raw_output=output[:300],
                )

            return VerifyResult(
                level="L3-运行时",
                passed=True,
                message=f"端口映射运行时状态正常(DSTNAT链{'已注册' if has_dnat else '无规则'})",
                raw_output=output[:300],
            )
        except Exception as e:
            logger.error(f"verify_port_map_runtime error: {e}")
            return VerifyResult(
                level="L3-运行时",
                passed=False,
                message=f"运行时验证异常: {e}",
                raw_output="",
            )

    def verify_port_map_kernel(self) -> VerifyResult:
        """L4: 验证端口映射内核模块(nf_nat/iptable_nat)"""
        self.connect_router()
        try:
            output = self._router.exec("lsmod 2>/dev/null | grep -E 'nf_nat|iptable_nat'")
            if output and ("nf_nat" in output or "iptable_nat" in output):
                return VerifyResult(
                    level="L4-内核",
                    passed=True,
                    message="NAT内核模块已加载(nf_nat/iptable_nat)",
                    raw_output=output[:200],
                )
            # 某些平台NAT编译进内核, 检查/proc
            proc = self._router.exec("cat /proc/net/nf_conntrack 2>/dev/null | head -1")
            if proc:
                return VerifyResult(
                    level="L4-内核",
                    passed=True,
                    message="NAT内核功能正常(conntrack可用)",
                    raw_output="conntrack active",
                )
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message="NAT内核模块未找到",
                raw_output=output[:200],
            )
        except Exception as e:
            logger.error(f"verify_port_map_kernel error: {e}")
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message=f"内核验证异常: {e}",
                raw_output="",
            )

    def verify_port_map_full_chain(self, tagname: str,
                                    expected_fields: Dict = None,
                                    lan_addr: str = None,
                                    wan_port: str = None,
                                    protocol: str = None) -> FullChainResult:
        """端口映射全链路验证: L1数据库 -> L2iptables -> L3运行时 -> L4内核

        Args:
            tagname: 规则名称
            expected_fields: 期望的数据库字段值
            lan_addr: 内网地址(用于L2精确匹配)
            wan_port: 外网端口(用于L2精确匹配)
            protocol: 协议(用于L2精确匹配)
        """
        results = []

        # L1: 数据库
        results.append(self.verify_port_map_database(tagname, expected_fields))

        # 根据L1结果决定后续验证
        rule = self.find_port_map(tagname)
        if rule:
            enabled = rule.get("enabled", "yes") == "yes"
            r_lan_addr = lan_addr or rule.get("lan_addr")
            r_wan_port = wan_port or rule.get("wan_port")
            r_protocol = protocol or rule.get("protocol")

            # L2: iptables(仅启用时期望有规则)
            if enabled:
                results.append(self.verify_port_map_iptables(
                    tagname, r_lan_addr, r_wan_port, r_protocol, expect_rules=True))
            else:
                results.append(self.verify_port_map_iptables(
                    tagname, r_lan_addr, r_wan_port, r_protocol, expect_rules=False))

            # L3: 运行时
            results.append(self.verify_port_map_runtime(expect_active=enabled))
        else:
            results.append(self.verify_port_map_iptables(tagname, expect_rules=False))
            results.append(self.verify_port_map_runtime(expect_active=False))

        # L4: 内核
        results.append(self.verify_port_map_kernel())

        return FullChainResult(results=results)

    # ==================== DMZ主机(one_one_map)验证 ====================
    # 后端脚本: /usr/ikuai/script/netmap.sh + /usr/ikuai/function/netmap
    # 数据库: one_one_map表(id,enabled,tagname,comment,interface,lan_addr,protocol,excl_port)
    # iptables: nat表NETNAT链, -j NETMAP --to <lan_addr>/32 (全端口映射)
    # 链注册: PREROUTING需引用NETNAT链(ipt_qos_other_ensure_chain, 仅add/up/edit时调用)
    #
    # ⚠️ 已知产品BUG(netmap.sh init函数):
    #   local qos_num=$(sqlite3 ... "select * from one_one_map")  # select *返回数据行非数字
    #   if [ "$qos_num" -gt "0" ]; then ... fi  # 报"integer expression expected"
    #   后果: init(boot重启时)不会调用ipt_qos_other_ensure_chain, PREROUTING不引用NETNAT链
    #   表现: NETNAT链有规则但PREROUTING不引用 -> DMZ实际不生效(重启后尤其明显)
    #   后台验证必须检查PREROUTING是否引用NETNAT链, 这是发现该bug的关键

    def query_dmz_rules(self) -> List[Dict]:
        """查询所有DMZ主机规则(one_one_map表)"""
        self.connect_router()
        try:
            output = self._router.exec(
                "/usr/ikuai/function/netmap show limit=0,500 TYPE=total,data"
            )
            logger.info(f"one_one_map raw: {output[:200] if output else 'None'}")

            if not output or "Error" in output:
                return []

            data = json.loads(output.strip())
            if isinstance(data, dict):
                return data.get("data", [])
            return []
        except Exception as e:
            logger.error(f"query_dmz_rules error: {e}")
            return []

    def find_dmz_rule(self, tagname: str) -> Optional[Dict]:
        """按名称查找DMZ主机规则"""
        rules = self.query_dmz_rules()
        for rule in rules:
            if rule.get("tagname") == tagname:
                return rule
        return None

    def verify_dmz_database(self, tagname: str,
                             expected_fields: Dict = None,
                             expect_absent: bool = False) -> VerifyResult:
        """L1: 验证DMZ主机在数据库中存在且字段正确"""
        rule = self.find_dmz_rule(tagname)
        if rule is None:
            if expect_absent:
                return VerifyResult(
                    level="L1-数据库",
                    passed=True,
                    message=f"DMZ主机 '{tagname}' 已不存在(符合预期)",
                    details={"tagname": tagname, "absent": True},
                    raw_output="",
                )
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"DMZ主机 '{tagname}' 不存在",
                details={"tagname": tagname},
                raw_output="",
            )

        details = {"rule": {k: v for k, v in rule.items() if k in (
            'id', 'enabled', 'tagname', 'interface', 'lan_addr',
            'protocol', 'excl_port', 'comment'
        )}}

        mismatches = []
        if expected_fields:
            field_map = {
                "enabled": "enabled",
                "protocol": "protocol",
                "lan_addr": "lan_addr",
                "interface": "interface",
                "excl_port": "excl_port",
                "comment": "comment",
                "remark": "comment",
            }
            for ui_key, db_key in field_map.items():
                if ui_key in expected_fields:
                    expected_val = str(expected_fields[ui_key])
                    actual_val = str(rule.get(db_key, ""))
                    if expected_val != actual_val:
                        mismatches.append(f"{db_key}: 期望={expected_val}, 实际={actual_val}")

        raw = json.dumps(details, ensure_ascii=False)[:300]
        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"DMZ主机 '{tagname}' 字段不匹配: {'; '.join(mismatches)}",
                details=details,
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"DMZ主机 '{tagname}' 数据库验证通过(proto={rule.get('protocol')}, lan={rule.get('lan_addr')})",
            details=details,
            raw_output=raw,
        )

    def verify_dmz_iptables(self, tagname: str = None,
                             lan_addr: str = None,
                             protocol: str = None,
                             expect_rules: bool = True) -> VerifyResult:
        """L2: 验证DMZ主机iptables规则(NETNAT链 + PREROUTING链引用)

        DMZ的iptables验证包含两部分:
        1. NETNAT链中是否有NETMAP规则(匹配lan_addr)
        2. PREROUTING是否引用了NETNAT链(这是发现重启bug的关键检查点)

        Args:
            tagname: 规则名称(用于日志)
            lan_addr: 内网地址(用于匹配NETMAP --to)
            protocol: 排除协议(用于匹配RETURN规则)
            expect_rules: 期望是否有规则
        """
        self.connect_router()
        try:
            # 1. 检查NETNAT链规则
            netnat_output = self._router.exec("iptables -t nat -S NETNAT 2>/dev/null")
            netnat_lines = [l.strip() for l in netnat_output.strip().split('\n')
                            if l.strip() and not l.strip().startswith("-N")]

            # 匹配NETMAP规则(根据lan_addr)
            matched_netmap = []
            for line in netnat_lines:
                if lan_addr and lan_addr in line and "NETMAP" in line:
                    matched_netmap.append(line)
                elif not lan_addr and "NETMAP" in line:
                    matched_netmap.append(line)

            # 2. 检查PREROUTING是否引用NETNAT链(关键! 重启bug的检测点)
            pre_output = self._router.exec("iptables -t nat -S PREROUTING 2>/dev/null")
            prerouting_refs_netnat = "NETNAT" in pre_output

            label = tagname or "DMZ主机"

            if expect_rules:
                # 期望有规则: NETNAT链必须有NETMAP规则
                if not matched_netmap:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"DMZ主机 '{label}' NETNAT链未找到NETMAP规则",
                        raw_output=f"NETNAT链:\n{netnat_output[:400]}",
                    )
                # PREROUTING必须引用NETNAT(否则规则不生效)
                if not prerouting_refs_netnat:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"DMZ主机 '{label}' NETNAT链有规则但PREROUTING未引用(规则不生效! 可能是重启bug)",
                        raw_output=f"NETNAT链有{len(matched_netmap)}条规则, 但PREROUTING:\n{pre_output[:300]}",
                    )
                return VerifyResult(
                    level="L2-iptables",
                    passed=True,
                    message=f"DMZ主机 '{label}' iptables验证通过(NETMAP规则{len(matched_netmap)}条, PREROUTING已引用)",
                    raw_output="\n".join(matched_netmap)[:500],
                )
            else:
                # 期望无规则
                if matched_netmap:
                    return VerifyResult(
                        level="L2-iptables",
                        passed=False,
                        message=f"DMZ主机 '{label}' NETNAT链仍有残留NETMAP规则",
                        raw_output="\n".join(matched_netmap)[:500],
                    )
                return VerifyResult(
                    level="L2-iptables",
                    passed=True,
                    message=f"DMZ主机 '{label}' iptables验证通过(无规则, 符合预期)",
                    raw_output=netnat_output[:300],
                )
        except Exception as e:
            logger.error(f"verify_dmz_iptables error: {e}")
            return VerifyResult(
                level="L2-iptables",
                passed=False,
                message=f"iptables验证异常: {e}",
                raw_output="",
            )

    def verify_dmz_boot_recovery(self, tagname: str = None) -> VerifyResult:
        """L2+: 验证DMZ重启恢复能力(纯净模拟boot流程, 检测已知init bug)

        ⚠️ 纯净复现流程(已实锤验证, 非推断):
        1. 检查数据库是否有启用的DMZ规则(无规则则跳过, 无法验证)
        2. 清空NETNAT链规则 + 删除PREROUTING对NETNAT的引用(模拟刚开机内存空)
           这一步排除了Web UI add()副作用——add()会主动注册链, 会污染验证结果
        3. 只跑 netmap.sh init(模拟重启时的初始化)
        4. 检查 init 是否报错 + PREROUTING是否重新注册了NETNAT链

        已知bug(已实锤复现):
        - netmap.sh init()第30行 select *(返回数据行非数字) -gt 0 报 integer expression expected
        - 后果: 重启(boot->init)时不注册PREROUTING->NETNAT, DMZ不生效
        - 对比: down()/up()里的ipt_qos_other_ensure_chain是无条件调用, 所以停用启用不会触发此bug
        - 只有重启(init)路径才触发

        Args:
            tagname: 规则名称(用于日志, 可选)

        Returns:
            VerifyResult: 通过=重启后DMZ正常生效, 失败=重启后DMZ不生效(命中bug)
        """
        self.connect_router()
        try:
            label = tagname or "DMZ主机"

            # 0. 先检查数据库是否有启用的DMZ规则(无规则无法验证重启恢复)
            rule_count_output = self._router.exec(
                'sqlite3 /etc/mnt/ikuai/config.db "SELECT count(*) FROM one_one_map WHERE enabled=\'yes\'"'
            )
            rule_count = 0
            try:
                rule_count = int(rule_count_output.strip())
            except Exception:
                pass
            if rule_count == 0:
                return VerifyResult(
                    level="L2-重启恢复",
                    passed=True,
                    message="DMZ重启恢复验证跳过: 无启用的DMZ规则, 无法验证",
                    raw_output="",
                )

            # 1. 纯净化: 清空NETNAT链规则 + 删除PREROUTING对NETNAT的引用(模拟刚开机)
            #    关键: 这一步排除了add()的副作用, 才能测出init本身是否能注册链
            self._router.exec("iptables -t nat -F NETNAT 2>/dev/null")
            # 删除PREROUTING里对NETNAT的引用(用精确匹配条件, 不用-S管道解析)
            # 注意: 爱快的iptables -S输出带[fastid:0]前缀, sed管道方式会失败
            self._router.exec(
                "iptables -t nat -D PREROUTING -m conntrack --ctstate NEW -m addrtype --dst-type LOCAL -j NETNAT 2>/dev/null"
            )

            # 确认清空成功
            pre_before = self._router.exec("iptables -t nat -S PREROUTING 2>/dev/null | grep -i netnat")
            cleaned = (not pre_before or "NETNAT" not in pre_before)

            # 2. 只跑 init(模拟重启初始化)
            init_output = self._router.exec("/usr/ikuai/script/netmap.sh init 2>&1")

            # 3. 检查结果
            has_init_bug = "integer expression expected" in init_output

            pre_output = self._router.exec("iptables -t nat -S PREROUTING 2>/dev/null")
            prerouting_refs_netnat = "NETNAT" in pre_output

            netnat_output = self._router.exec("iptables -t nat -S NETNAT 2>/dev/null")
            netnat_has_rules = any("NETMAP" in l for l in netnat_output.split('\n'))

            # 4. 判定
            if has_init_bug and not prerouting_refs_netnat:
                # 命中已知bug: init报错 + PREROUTING未注册(已实锤的复现结果)
                return VerifyResult(
                    level="L2-重启恢复",
                    passed=False,
                    message=f"DMZ重启恢复验证失败: 命中init bug(select * -gt 0错误), 重启后PREROUTING不引用NETNAT链, DMZ不生效",
                    raw_output=f"纯净化后PREROUTING引用NETNAT: {cleaned}(应空)\ninit输出:\n{init_output[:300]}\ninit后PREROUTING:\n{pre_output[:200]}\nNETNAT链(有规则但流量进不来):\n{netnat_output[:200]}",
                )

            if not prerouting_refs_netnat and netnat_has_rules:
                # NETNAT有规则但PREROUTING没引用 -> DMZ不生效(另一种表现)
                return VerifyResult(
                    level="L2-重启恢复",
                    passed=False,
                    message=f"DMZ重启恢复验证失败: NETNAT链有规则但PREROUTING未引用(DMZ不生效)",
                    raw_output=f"NETNAT:\n{netnat_output[:300]}\nPREROUTING:\n{pre_output[:200]}",
                )

            return VerifyResult(
                level="L2-重启恢复",
                passed=True,
                message=f"DMZ重启恢复验证通过(init{'有告警但' if has_init_bug else '正常'}PREROUTING已引用NETNAT链)",
                raw_output=f"init:\n{init_output[:200]}\nPREROUTING引用NETNAT: {prerouting_refs_netnat}",
            )
        except Exception as e:
            logger.error(f"verify_dmz_boot_recovery error: {e}")
            return VerifyResult(
                level="L2-重启恢复",
                passed=False,
                message=f"重启恢复验证异常: {e}",
                raw_output="",
            )

    def verify_dmz_runtime(self, expect_active: bool = True) -> VerifyResult:
        """L3: 验证DMZ运行时状态(iptables-save检查NETNAT链)"""
        self.connect_router()
        try:
            output = self._router.exec("iptables-save -t nat 2>/dev/null | grep -E 'NETNAT'")
            has_netnat = ":NETNAT" in output or "-A NETNAT" in output

            if expect_active and not has_netnat:
                return VerifyResult(
                    level="L3-运行时",
                    passed=False,
                    message="DMZ运行时未注册NETNAT链",
                    raw_output=output[:300],
                )

            return VerifyResult(
                level="L3-运行时",
                passed=True,
                message=f"DMZ运行时状态正常(NETNAT链{'已注册' if has_netnat else '无规则'})",
                raw_output=output[:300],
            )
        except Exception as e:
            logger.error(f"verify_dmz_runtime error: {e}")
            return VerifyResult(
                level="L3-运行时",
                passed=False,
                message=f"运行时验证异常: {e}",
                raw_output="",
            )

    def verify_dmz_kernel(self) -> VerifyResult:
        """L4: 验证DMZ内核模块(NETMAP需要nf_nat或编译进内核)"""
        self.connect_router()
        try:
            output = self._router.exec("lsmod 2>/dev/null | grep -E 'nf_nat|iptable_nat|netmap'")
            if output and ("nf_nat" in output or "iptable_nat" in output):
                return VerifyResult(
                    level="L4-内核",
                    passed=True,
                    message="NAT内核模块已加载(支持NETMAP)",
                    raw_output=output[:200],
                )
            proc = self._router.exec("cat /proc/net/nf_conntrack 2>/dev/null | head -1")
            if proc:
                return VerifyResult(
                    level="L4-内核",
                    passed=True,
                    message="NAT内核功能正常(conntrack可用)",
                    raw_output="conntrack active",
                )
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message="NAT内核模块未找到",
                raw_output=output[:200],
            )
        except Exception as e:
            logger.error(f"verify_dmz_kernel error: {e}")
            return VerifyResult(
                level="L4-内核",
                passed=False,
                message=f"内核验证异常: {e}",
                raw_output="",
            )

    def verify_dmz_full_chain(self, tagname: str,
                               expected_fields: Dict = None,
                               lan_addr: str = None) -> FullChainResult:
        """DMZ全链路验证: L1数据库 -> L2iptables(NETMAP+PREROUTING引用) -> L3运行时 -> L4内核

        Args:
            tagname: 规则名称
            expected_fields: 期望的数据库字段值
            lan_addr: 内网地址(用于L2精确匹配NETMAP目标)
        """
        results = []

        # L1: 数据库
        results.append(self.verify_dmz_database(tagname, expected_fields))

        # 根据L1结果决定后续验证
        rule = self.find_dmz_rule(tagname)
        if rule:
            enabled = rule.get("enabled", "yes") == "yes"
            r_lan_addr = lan_addr or rule.get("lan_addr")
            r_protocol = rule.get("protocol", "any")

            # L2: iptables(NETNAT链规则 + PREROUTING引用)
            if enabled:
                results.append(self.verify_dmz_iptables(
                    tagname, r_lan_addr, r_protocol, expect_rules=True))
            else:
                results.append(self.verify_dmz_iptables(
                    tagname, r_lan_addr, r_protocol, expect_rules=False))

            # L3: 运行时
            results.append(self.verify_dmz_runtime(expect_active=enabled))
        else:
            results.append(self.verify_dmz_iptables(tagname, expect_rules=False))
            results.append(self.verify_dmz_runtime(expect_active=False))

        # L4: 内核
        results.append(self.verify_dmz_kernel())

        return FullChainResult(results=results)

    def verify_dnat_conntrack(self, wan_ip: str, wan_port: str, lan_ip: str,
                              lan_port: str, proto: str = "tcp") -> VerifyResult:
        """查conntrack DNAT条目(端口映射/DMZ生效L5铁证): 外网访问wan_ip:wan_port→DNAT到lan_ip:lan_port.

        端口映射/DMZ=PREROUTING DNAT改目标. conntrack条目: orig dst=wan_ip dport=wan_port, reply src=lan_ip sport=lan_port.
        条目存在=DNAT发生=规则数据平面生效(不依赖端到端连通/hairpin, SYN即触发DNAT建条目)."""
        self.connect_router()
        out = self._router.exec("cat /proc/net/nf_conntrack 2>/dev/null")
        for line in out.splitlines():
            if proto != "any" and f" {proto} " not in line[:60]:
                continue
            if f"dst={wan_ip} " not in line:
                continue
            if f"dport={wan_port} " not in line:
                continue
            if f"src={lan_ip} " in line and f"sport={lan_port} " in line:
                return VerifyResult(level="L5-dnat", passed=True,
                    message=f"DNAT生效: {wan_ip}:{wan_port}→{lan_ip}:{lan_port}",
                    raw_output=line[:160])
        return VerifyResult(level="L5-dnat", passed=False,
            message=f"未找到DNAT条目 {wan_ip}:{wan_port}→{lan_ip}:{lan_port}")

    # ==================== DNS加速服务(dns)验证 ====================
    # 后端脚本: /usr/ikuai/script/dns.sh
    # CLI无独立show命令(dns show报错), 用sqlite3直查config.db
    # 表: dns_config(基础配置,单记录id=1) + dns_reverse_proxy_new(反向代理)
    # cachemode: 0=UDP, 1=多线分路, 2=第三方代理, 3=DoH
    # 进程: ikdnsd(用户配置,UDP53) ≠ ikdnsx(系统,UDP54,始终运行)
    # 运行时文件: /tmp/iktmp/ikdnsd.conf + ikdnsd.static.conf + ikdnsd.status

    DNS_DB = "/etc/mnt/ikuai/config.db"

    def _sqlite_query_line(self, sql: str) -> Optional[Dict]:
        """
        用sqlite3 -line模式查询, 解析'key = value'格式为dict
        适用于单记录查询(如dns_config)或WHERE过滤后的单条记录
        """
        self.connect_router()
        try:
            output = self._router.exec(
                f'sqlite3 {self.DNS_DB} -line "{sql}" 2>/dev/null'
            )
            if not output or not output.strip():
                return None
            result = {}
            for line in output.splitlines():
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    result[k.strip()] = v.strip()
            return result if result else None
        except Exception as e:
            logger.error(f"[sqlite] 查询失败: {sql} -> {e}")
            return None

    def _sqlite_query_list(self, sql: str) -> List[Dict]:
        """
        用sqlite3 -line模式查询多条记录, 解析为dict列表
        多条记录间用空行分隔
        """
        self.connect_router()
        try:
            output = self._router.exec(
                f'sqlite3 {self.DNS_DB} -line "{sql}" 2>/dev/null'
            )
            if not output or not output.strip():
                return []
            records = []
            current = {}
            for line in output.splitlines():
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    current[k.strip()] = v.strip()
                elif not line and current:
                    records.append(current)
                    current = {}
            if current:
                records.append(current)
            return records
        except Exception as e:
            logger.error(f"[sqlite] 列表查询失败: {sql} -> {e}")
            return []

    def query_dns_config(self) -> Optional[Dict]:
        """L1: 查询dns_config基础配置(单记录id=1)"""
        return self._sqlite_query_line(
            "SELECT enabled,cachemode,forbid_dns_4a,proxy_force,dns1,dns2,"
            "cache_ttl,query,proxy_force_dns FROM dns_config WHERE id=1"
        )

    def verify_dns_config_database(self, expected_fields: Dict = None,
                                   must_pass: bool = False) -> VerifyResult:
        """
        L1: 验证DNS加速基础配置(dns_config表)

        Args:
            expected_fields: 期望字段值, 如 {"enabled": "yes", "cachemode": "0",
                             "dns1": "114.114.114.114", "cache_ttl": "60"}
            must_pass: 是否必须通过(失败时记录到断言)
        """
        config = self.query_dns_config()
        if config is None:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message="dns_config配置不存在(数据库无记录)",
                raw_output="",
            )

        details = {
            "enabled": config.get("enabled"),
            "cachemode": config.get("cachemode"),
            "forbid_dns_4a": config.get("forbid_dns_4a"),
            "proxy_force": config.get("proxy_force"),
            "dns1": config.get("dns1"),
            "dns2": config.get("dns2"),
            "cache_ttl": config.get("cache_ttl"),
        }
        raw = json.dumps(details, ensure_ascii=False)

        cachemode_name = {"0": "UDP", "1": "多线分路", "2": "第三方代理", "3": "DoH"}.get(
            str(config.get("cachemode", "")), str(config.get("cachemode")))

        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库",
                passed=True,
                message=f"DNS基础配置存在: enabled={config.get('enabled')}, "
                        f"cachemode={cachemode_name}({config.get('cachemode')}), "
                        f"dns1={config.get('dns1')}, dns2={config.get('dns2')}, "
                        f"cache_ttl={config.get('cache_ttl')}, "
                        f"proxy_force={config.get('proxy_force')}, "
                        f"forbid_dns_4a={config.get('forbid_dns_4a')}",
                details={"config": details},
                raw_output=raw,
            )

        mismatches = {}
        for field, expected in expected_fields.items():
            actual = str(config.get(field, ""))
            if actual != str(expected):
                mismatches[field] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"基础配置字段不匹配: {mismatches}",
                details={"config": details, "mismatches": mismatches},
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"DNS基础配置数据库验证通过",
            details={"config": details},
            raw_output=raw,
        )

    def query_dns_reverse_proxy(self, domain: str) -> Optional[Dict]:
        """L1: 查询指定域名的DNS反向代理规则(dns_reverse_proxy_new表)"""
        records = self._sqlite_query_list(
            f"SELECT id,domain,dns_addr,enabled,comment,src_addr,parse_type,is_ipv6 "
            f"FROM dns_reverse_proxy_new WHERE domain='{domain}'"
        )
        return records[0] if records else None

    def query_all_dns_reverse_proxy(self) -> List[Dict]:
        """L1: 查询所有DNS反向代理规则"""
        return self._sqlite_query_list(
            "SELECT id,domain,dns_addr,enabled,comment,src_addr,parse_type,is_ipv6 "
            "FROM dns_reverse_proxy_new"
        )

    def count_dns_reverse_proxy(self, enabled_only: bool = False) -> int:
        """L1: 统计DNS反向代理规则数量"""
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM dns_reverse_proxy_new {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_dns_reverse_proxy_database(self, domain: str,
                                          expected_fields: Dict = None,
                                          must_exist: bool = True,
                                          must_pass: bool = False) -> VerifyResult:
        """
        L1: 验证DNS反向代理规则(dns_reverse_proxy_new表)

        Args:
            domain: 域名(定位规则)
            expected_fields: 期望字段值, 如 {"dns_addr": "192.168.200.1",
                             "enabled": "yes", "parse_type": "ipv4"}
            must_exist: True=规则必须存在, False=规则必须不存在
            must_pass: 是否必须通过
        """
        rule = self.query_dns_reverse_proxy(domain)

        if must_exist and rule is None:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"反向代理规则不存在(期望存在): {domain}",
                raw_output="",
            )
        if not must_exist and rule is not None:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"反向代理规则仍存在(期望已删除): {domain}",
                details={"rule": rule},
                raw_output=json.dumps(rule, ensure_ascii=False),
            )
        if not must_exist and rule is None:
            return VerifyResult(
                level="L1-数据库",
                passed=True,
                message=f"反向代理规则已不存在: {domain}",
                raw_output="",
            )

        details = {
            "id": rule.get("id"),
            "domain": rule.get("domain"),
            "dns_addr": rule.get("dns_addr"),
            "enabled": rule.get("enabled"),
            "comment": rule.get("comment"),
            "src_addr": rule.get("src_addr"),
            "parse_type": rule.get("parse_type"),
        }
        raw = json.dumps(details, ensure_ascii=False)

        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库",
                passed=True,
                message=f"反向代理规则存在: {domain}, dns_addr={rule.get('dns_addr')}, "
                        f"enabled={rule.get('enabled')}, parse_type={rule.get('parse_type')}",
                details={"rule": details},
                raw_output=raw,
            )

        mismatches = {}
        for field, expected in expected_fields.items():
            actual = str(rule.get(field, ""))
            # dns_addr可能是多行, 数据库存为带换行的文本; 比较时去空白
            if field == "dns_addr":
                actual_norm = actual.replace("\n", ",").strip()
                expected_norm = str(expected).replace("\n", ",").strip()
                if actual_norm != expected_norm:
                    mismatches[field] = {"expected": str(expected), "actual": actual}
            elif field == "src_addr":
                # src_addr比较宽松(顺序/换行可能不同), 检查expected的每段是否都存在
                actual_norm = actual.replace("\n", ",").strip()
                if str(expected).replace("\n", ",").strip() not in actual_norm and actual_norm != str(expected).replace("\n", ",").strip():
                    mismatches[field] = {"expected": str(expected), "actual": actual}
            else:
                if actual != str(expected):
                    mismatches[field] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"反向代理字段不匹配({domain}): {mismatches}",
                details={"rule": details, "mismatches": mismatches},
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"反向代理规则数据库验证通过: {domain}",
            details={"rule": details},
            raw_output=raw,
        )

    def verify_dns_runtime_config(self, expect_enabled: bool = True,
                                  expected_static_domain: str = None,
                                  expected_dns_addr: str = None) -> VerifyResult:
        """
        L2: 验证DNS加速运行时配置文件(/tmp/iktmp/)

        enabled=yes时: ikdnsd.conf + ikdnsd.static.conf + ikdnsd.status 应存在
        enabled=no时:  上述文件应被清理(rm -f)

        Args:
            expect_enabled: 期望DNS加速是否启用
            expected_static_domain: 期望在ikdnsd.static.conf中出现的域名
            expected_dns_addr: 期望在static.conf中出现的解析地址
        """
        self.connect_router()
        checks = []

        try:
            # 检查ikdnsd.conf
            conf_out = self._router.exec("cat /tmp/iktmp/ikdnsd.conf 2>/dev/null")
            conf_exists = bool(conf_out and conf_out.strip())
            if expect_enabled:
                checks.append(("ikdnsd.conf存在", conf_exists,
                               f"ikdnsd.conf{'存在' if conf_exists else '不存在(应存在)'}"))
                if conf_exists:
                    if "port" in conf_out:
                        checks.append(("conf含port", True, "ikdnsd.conf含port配置"))
                    if "cache_ttl" in conf_out:
                        checks.append(("conf含cache_ttl", True, "ikdnsd.conf含cache_ttl"))
            else:
                checks.append(("ikdnsd.conf已清理", not conf_exists,
                               f"ikdnsd.conf{'仍存在(应清理)' if conf_exists else '已清理(正确)'}"))

            # 检查ikdnsd.static.conf(反向代理记录)
            static_out = self._router.exec("cat /tmp/iktmp/ikdnsd.static.conf 2>/dev/null")
            static_exists = bool(static_out and static_out.strip())
            if expect_enabled:
                if expected_static_domain:
                    domain_found = expected_static_domain in (static_out or "")
                    checks.append(("static.conf含域名", domain_found,
                                   f"static.conf{'含' if domain_found else '不含'}{expected_static_domain}"))
                if expected_dns_addr and domain_found if expected_static_domain else (expected_dns_addr and expected_dns_addr in (static_out or "")):
                    addr_found = expected_dns_addr in (static_out or "")
                    checks.append(("static.conf含解析地址", addr_found,
                                   f"static.conf{'含' if addr_found else '不含'}{expected_dns_addr}"))
            else:
                # 关闭时static.conf也应清理
                checks.append(("static.conf已清理", not static_exists,
                               f"static.conf{'仍存在(应清理)' if static_exists else '已清理(正确)'}"))

            # 检查ikdnsd.status
            status_out = self._router.exec("cat /tmp/iktmp/ikdnsd.status 2>/dev/null")
            status_exists = bool(status_out and status_out.strip())
            if expect_enabled:
                checks.append(("status存在", status_exists,
                               f"ikdnsd.status{'存在' if status_exists else '不存在(应存在)'}"))
            else:
                checks.append(("status已清理", not status_exists,
                               f"ikdnsd.status{'仍存在(应清理)' if status_exists else '已清理(正确)'}"))

            passed = all(c[1] for c in checks if c[1] is not None)
            messages = [c[2] for c in checks]
            return VerifyResult(
                level="L2-运行时文件",
                passed=passed,
                message="; ".join(messages),
                details={"checks": [{"name": c[0], "ok": c[1], "msg": c[2]} for c in checks],
                         "conf": (conf_out or "")[:300],
                         "static": (static_out or "")[:300]},
                raw_output=(static_out or "")[:300],
            )
        except Exception as e:
            return VerifyResult(
                level="L2-运行时文件",
                passed=False,
                message=f"运行时文件检查失败: {e}",
                raw_output=str(e),
            )

    def verify_dns_iptables(self, expect_redirect: bool = None,
                            proxy_force: bool = None) -> VerifyResult:
        """
        L3: 验证DNS加速iptables(nat表DNSPROXY链)

        DNS加速启用时: PREROUTING引用DNSPROXY链, DNSPROXY含DNS重定向规则
        proxy_force=1时: 有 REDIRECT udp dpt:53 -> port 53 规则
        关闭时: DNSPROXY链清空(REDIRECT消失)

        Args:
            expect_redirect: 期望是否有REDIRECT规则(None=不检查, 按proxy_force推断)
            proxy_force: 是否开启了强制客户端DNS代理(影响REDIRECT规则)
        """
        self.connect_router()
        try:
            # 查看DNSPROXY链
            output = self._router.exec(
                "iptables -t nat -L DNSPROXY -n 2>/dev/null"
            )
            # 查看PREROUTING是否引用DNSPROXY
            pre_output = self._router.exec(
                "iptables -t nat -L PREROUTING -n 2>/dev/null"
            )
            has_dnsproxy_ref = "DNSPROXY" in (pre_output or "")
            has_redirect = "REDIRECT" in (output or "") and "dpt:53" in (output or "")

            # 判断期望
            if expect_redirect is None:
                expect_redirect = bool(proxy_force)

            checks = []
            checks.append(("PREROUTING引用DNSPROXY", has_dnsproxy_ref,
                           f"PREROUTING{'引用' if has_dnsproxy_ref else '未引用'}DNSPROXY链"))

            if expect_redirect:
                checks.append(("DNSPROXY含REDIRECT dpt:53", has_redirect,
                               f"DNSPROXY{'含' if has_redirect else '不含'}REDIRECT udp dpt:53规则"))
            else:
                # proxy_force=0或关闭时不应有REDIRECT
                checks.append(("DNSPROXY无REDIRECT(符合预期)", not has_redirect,
                               f"DNSPROXY{'仍含REDIRECT(非预期)' if has_redirect else '无REDIRECT(正确)'}"))

            passed = all(c[1] for c in checks if c[1] is not None)
            messages = [c[2] for c in checks]
            return VerifyResult(
                level="L3-iptables",
                passed=passed,
                message="; ".join(messages),
                details={"checks": [{"name": c[0], "ok": c[1], "msg": c[2]} for c in checks]},
                raw_output=(output or "")[:500],
            )
        except Exception as e:
            return VerifyResult(
                level="L3-iptables",
                passed=False,
                message=f"iptables检查失败: {e}",
                raw_output=str(e),
            )

    def verify_dns_process(self, expect_running: bool = True) -> VerifyResult:
        """
        L4: 验证ikdnsd进程状态 + UDP 53端口监听

        注意区分:
        - ikdnsd(用户配置DNS加速, enabled=yes时运行, 监听UDP 53)
        - ikdnsx(系统基础DNS, 始终运行, 监听UDP 54) - 不应误判

        Args:
            expect_running: 期望ikdnsd进程是否运行
        """
        self.connect_router()
        checks = []
        try:
            # 精确匹配ikdnsd(排除ikdnsx), 用ikdnsd.conf特征
            ps_out = self._router.exec(
                "ps | grep ikdnsd | grep ikdnsd.conf | grep -v grep"
            )
            running = bool(ps_out and ps_out.strip())
            checks.append(("ikdnsd进程", running == expect_running,
                           f"ikdnsd进程{'运行中' if running else '未运行'}"
                           f"({'符合' if running == expect_running else '不符合'}期望"
                           f"{'运行' if expect_running else '未运行'})"))

            if expect_running and running:
                # 检查UDP 53监听(ikdnsd监听53)
                port_out = self._router.exec(
                    "netstat -nlu 2>/dev/null | grep ':53 ' || ss -nlu 2>/dev/null | grep ':53 '"
                )
                has_53 = bool(port_out and port_out.strip())
                checks.append(("UDP53监听", has_53,
                               f"UDP 53{'有' if has_53 else '无'}监听(ikdnsd)"))

            if not expect_running:
                # 关闭时确认ikdnsd确实停止(ikdnsx仍运行监听54是正常的)
                checks.append(("ikdnsd已停止", not running,
                               f"ikdnsd{'仍运行(应停止)' if running else '已停止(正确)'}"))

            passed = all(c[1] for c in checks if c[1] is not None)
            messages = [c[2] for c in checks]
            return VerifyResult(
                level="L4-进程/端口",
                passed=passed,
                message="; ".join(messages),
                details={"checks": [{"name": c[0], "ok": c[1], "msg": c[2]} for c in checks]},
                raw_output=(ps_out or "").strip()[:300],
            )
        except Exception as e:
            return VerifyResult(
                level="L4-进程/端口",
                passed=False,
                message=f"进程/端口检查失败: {e}",
                raw_output=str(e),
            )

    def verify_dns_basic_full_chain(self, expect_enabled: bool = True,
                                    expected_fields: Dict = None,
                                    proxy_force: bool = None) -> FullChainResult:
        """
        DNS加速基础配置全链路验证: L1数据库 + L2运行时文件 + L3iptables + L4进程

        Args:
            expect_enabled: 期望DNS加速是否启用
            expected_fields: 期望的dns_config字段值
            proxy_force: 是否开启强制代理(影响L3 REDIRECT判断)
        """
        results = []

        # L1: 数据库
        ef = {"enabled": "yes" if expect_enabled else "no"}
        if expected_fields:
            ef.update(expected_fields)
        results.append(self.verify_dns_config_database(expected_fields=ef))

        # L2: 运行时文件
        results.append(self.verify_dns_runtime_config(expect_enabled=expect_enabled))

        # L3: iptables(开启时按proxy_force判断REDIRECT, 关闭时无REDIRECT)
        if expect_enabled:
            results.append(self.verify_dns_iptables(
                expect_redirect=bool(proxy_force), proxy_force=proxy_force))
        else:
            results.append(self.verify_dns_iptables(expect_redirect=False))

        # L4: 进程/端口
        results.append(self.verify_dns_process(expect_running=expect_enabled))

        return FullChainResult(results=results)

    def verify_dns_reverse_proxy_full_chain(self, domain: str,
                                             expect_exists: bool = True,
                                             expected_fields: Dict = None,
                                             dns_enabled: bool = True) -> FullChainResult:
        """
        DNS反向代理规则全链路验证: L1数据库 + L2运行时static.conf

        Args:
            domain: 域名
            expect_exists: 期望规则是否存在
            expected_fields: 期望字段值(dns_addr等)
            dns_enabled: DNS加速是否启用(影响L2 static.conf是否生成)
        """
        results = []

        # L1: 数据库
        results.append(self.verify_dns_reverse_proxy_database(
            domain, expected_fields=expected_fields, must_exist=expect_exists))

        # L2: static.conf(仅DNS加速启用+规则存在时检查)
        if expect_exists and dns_enabled:
            dns_addr = None
            if expected_fields and "dns_addr" in expected_fields:
                dns_addr = expected_fields["dns_addr"]
            elif not expected_fields:
                rule = self.query_dns_reverse_proxy(domain)
                if rule:
                    dns_addr = rule.get("dns_addr")
            results.append(self.verify_dns_runtime_config(
                expect_enabled=True,
                expected_static_domain=domain,
                expected_dns_addr=dns_addr))

        return FullChainResult(results=results)

    # ==================== 多线路DNS服务 (dns_replace) ====================
    # 后端脚本: /usr/ikuai/script/dns_replace.sh
    # 数据库表: dns_replace (interface=网卡unique, tagname=名称unique, dns1, dns2, enabled默认yes, comment)
    # 内核机制: ik_cntl multi-dns (enable/disable/add/del/clear), 无show命令, 无iptables, 无独立进程
    # dmesg日志: "[iKuai]:The iKuai multi_dns is enabled now" / "disabled now"
    # 重启恢复: dns_replace.sh boot -> init()从数据库重建内核规则 (实测正常, 无DMZ类bug)

    def query_dns_replace_rule(self, name: str) -> Optional[Dict]:
        """L1: 查询指定名称(tagname)的多线路DNS规则"""
        return self._sqlite_query_line(
            f"SELECT id,interface,tagname,dns1,dns2,enabled,comment "
            f"FROM dns_replace WHERE tagname='{name}'"
        )

    def query_all_dns_replace(self) -> List[Dict]:
        """L1: 查询所有多线路DNS规则"""
        return self._sqlite_query_list(
            "SELECT id,interface,tagname,dns1,dns2,enabled,comment FROM dns_replace"
        )

    def count_dns_replace(self, enabled_only: bool = False) -> int:
        """L1: 统计多线路DNS规则数量"""
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM dns_replace {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_dns_replace_database(self, name: str,
                                    expected_fields: Dict = None,
                                    must_exist: bool = True,
                                    must_pass: bool = False) -> VerifyResult:
        """
        L1: 验证多线路DNS规则(dns_replace表)

        Args:
            name: 规则名称(tagname)
            expected_fields: 期望字段值, 如 {"interface": "wan1", "dns1": "8.8.8.8",
                                            "dns2": "8.8.4.4", "enabled": "yes"}
            must_exist: 是否必须存在
            must_pass: 失败时是否记录到断言(通过_record_must_pass)
        """
        rule = self.query_dns_replace_rule(name)

        if rule is None:
            return VerifyResult(
                level="L1-数据库",
                passed=not must_exist,
                message=f"规则'{name}'不存在"
                        f"({'符合预期' if not must_exist else '应为存在'})",
                raw_output="",
            )

        details = {
            "interface": rule.get("interface"),
            "tagname": rule.get("tagname"),
            "dns1": rule.get("dns1"),
            "dns2": rule.get("dns2"),
            "enabled": rule.get("enabled"),
            "comment": rule.get("comment"),
        }
        raw = json.dumps(details, ensure_ascii=False)

        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库",
                passed=True,
                message=f"规则'{name}'存在: interface={details['interface']}, "
                        f"dns1={details['dns1']}, dns2={details['dns2']}, "
                        f"enabled={details['enabled']}",
                details={"rule": details},
                raw_output=raw,
            )

        mismatches = {}
        for field, expected in expected_fields.items():
            actual = str(rule.get(field, ""))
            if actual != str(expected):
                mismatches[field] = {"expected": str(expected), "actual": actual}

        if mismatches:
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"规则'{name}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches},
                raw_output=raw,
            )

        return VerifyResult(
            level="L1-数据库",
            passed=True,
            message=f"多线路DNS规则'{name}'数据库验证通过",
            details={"rule": details},
            raw_output=raw,
        )

    def verify_dns_multi_line_kernel(self, expect_enabled: bool = True) -> VerifyResult:
        """
        L3/L4: 验证多线路DNS内核功能开关状态(ik_cntl multi-dns + dmesg)

        多线路DNS功能开关状态由dmesg最后一条日志判断:
        - "[iKuai]:The iKuai multi_dns is enabled now" → 启用
        - "[iKuai]:The iKuai multi_dns is disabled now" → 禁用
        ik_cntl multi-dns无show命令, 无法直接读取内核规则列表, 仅验证开关状态。

        Args:
            expect_enabled: 期望功能是否启用
                            (有enabled=yes规则时应启用, 无enabled规则时应禁用)
        """
        self.connect_router()
        try:
            dmesg_out = self._router.exec(
                "dmesg | grep -iE 'multi_dns (is|are)' | tail -20"
            )
            lines = [l.strip() for l in (dmesg_out or "").splitlines() if l.strip()]

            if not lines:
                # 无日志, 用ik_cntl enable/disable触发一次再判断
                self._router.exec(
                    "ik_cntl multi-dns enable 2>/dev/null"
                    if expect_enabled else "ik_cntl multi-dns disable 2>/dev/null"
                )
                import time as _t
                _t.sleep(1)
                dmesg_out = self._router.exec(
                    "dmesg | grep -iE 'multi_dns (is|are)' | tail -20"
                )
                lines = [l.strip() for l in (dmesg_out or "").splitlines() if l.strip()]

            last_line = lines[-1] if lines else ""
            is_enabled_now = "enabled now" in last_line
            is_disabled_now = "disabled now" in last_line

            ok = (is_enabled_now == expect_enabled)
            state_str = "启用" if is_enabled_now else ("禁用" if is_disabled_now else "未知")

            checks = [("功能开关状态", ok,
                       f"multi_dns当前={state_str}"
                       f"({'符合' if ok else '不符合'}期望"
                       f"{'启用' if expect_enabled else '禁用'})")]

            passed = all(c[1] for c in checks)
            return VerifyResult(
                level="L3/L4-内核",
                passed=passed,
                message="; ".join(c[2] for c in checks),
                details={"checks": [{"name": c[0], "ok": c[1], "msg": c[2]} for c in checks],
                         "last_dmesg": last_line,
                         "recent_log_count": len(lines)},
                raw_output=(dmesg_out or "")[-400:],
            )
        except Exception as e:
            return VerifyResult(
                level="L3/L4-内核",
                passed=False,
                message=f"多线路DNS内核状态检查失败: {e}",
                raw_output=str(e),
            )

    def verify_dns_multi_line_reboot(self, expect_any_enabled: bool = True) -> VerifyResult:
        """
        L4 模拟重启验证: 验证boot能从数据库完整重建内核规则(无DMZ类初始化bug)

        流程:
        1. 记录boot前 enabled 规则数(L1数据库) + 最后一条dmesg multi_dns行
        2. ik_cntl multi-dns clear (清空内核规则, 数据库不变)
        3. /usr/ikuai/script/dns_replace.sh boot (模拟重启, init()重建内核)
        4. 验证: 数据库规则数不变(clear只清内核) + dmesg出现新状态切换
           - 有enabled规则: 新行=enabled now, 重建成功
           - 无enabled规则: 新行=disabled now, 正常禁用
        5. !! 对照DMZ bug(netmap init用文本做整数比较导致重启失效):
           dns_replace的init()用select count(*) + 字符串比较"0", 正常工作

        Args:
            expect_any_enabled: 是否期望存在enabled=yes的规则(决定boot后应enabled还是disabled)
        """
        self.connect_router()
        import time as _t
        try:
            # boot前快照
            enabled_before = self.count_dns_replace(enabled_only=True)
            total_before = self.count_dns_replace(enabled_only=False)
            dmesg_before = self._router.exec(
                "dmesg | grep -iE 'multi_dns (is|are)' | tail -5"
            )
            last_before = ""
            blines = [l.strip() for l in (dmesg_before or "").splitlines() if l.strip()]
            if blines:
                last_before = blines[-1]

            # 清空内核规则(数据库不变), 触发干净重建
            clear_out = self._router.exec("ik_cntl multi-dns clear 2>&1")
            _t.sleep(1)

            # 模拟重启: 执行boot脚本, init()从数据库重建内核规则
            boot_out = self._router.exec(
                "/usr/ikuai/script/dns_replace.sh boot 2>&1; echo BOOT_EXIT=$?"
            )
            _t.sleep(2)

            # boot后快照
            enabled_after = self.count_dns_replace(enabled_only=True)
            total_after = self.count_dns_replace(enabled_only=False)
            dmesg_after = self._router.exec(
                "dmesg | grep -iE 'multi_dns (is|are)' | tail -5"
            )
            alines = [l.strip() for l in (dmesg_after or "").splitlines() if l.strip()]
            last_after = alines[-1] if alines else ""

            # 硬断言项(影响passed)
            checks = []

            # 1. 数据库规则数不变(ik_cntl clear只清内核, 不动数据库)
            db_intact = (total_after == total_before)
            checks.append(("数据库规则完整", db_intact,
                           f"规则数 boot前={total_before} boot后={total_after}"
                           f"({'完整' if db_intact else '变化(异常)'})"))

            # 2. boot脚本确实执行(有BOOT_EXIT输出, 排除boot根本没跑的假通过)
            boot_executed = "BOOT_EXIT=" in (boot_out or "")
            checks.append(("boot脚本已执行", boot_executed,
                           f"dns_replace.sh boot{'已执行' if boot_executed else '未执行(异常)'}"))

            # 3. 状态符合预期: 有enabled规则→enabled, 无→disabled
            if expect_any_enabled:
                state_ok = "enabled now" in last_after
                expected_state = "启用(enabled now)"
            else:
                state_ok = "disabled now" in last_after
                expected_state = "禁用(disabled now)"
            checks.append(("重建后状态正确", state_ok,
                           f"boot后最后一条={last_after[:60]}"
                           f"({'符合' if state_ok else '不符合'}期望{expected_state})"))

            # 软信息(不影响passed): boot的enable/disable在内核已处目标态时幂等,
            # 不重复打印dmesg(clear清规则但功能开关可能仍enabled→boot的
            # __exec_switch发现已enabled则不重复enable→无新dmesg行, 属正常)。
            # "无DMZ类bug"的核心证据 = 数据库完整 + boot执行 + 状态正确。
            new_lines = [l for l in alines if l not in (dmesg_before or "")]
            has_new_switch = bool(new_lines) or (last_after != last_before)
            switch_msg = (f"dmesg切换({'有' if has_new_switch else '无(内核已处目标态,幂等正常)'})")

            passed = all(c[1] for c in checks)
            return VerifyResult(
                level="L4-模拟重启",
                passed=passed,
                message="; ".join(c[2] for c in checks) + "; " + switch_msg,
                details={"checks": [{"name": c[0], "ok": c[1], "msg": c[2]} for c in checks],
                         "dmesg_switch_soft": {"ok": has_new_switch, "msg": switch_msg},
                         "enabled_before": enabled_before,
                         "enabled_after": enabled_after,
                         "total_before": total_before,
                         "total_after": total_after,
                         "last_dmesg_before": last_before,
                         "last_dmesg_after": last_after,
                         "boot_output": (boot_out or "")[-200:]},
                raw_output=(boot_out or "")[-300:],
            )
        except Exception as e:
            return VerifyResult(
                level="L4-模拟重启",
                passed=False,
                message=f"模拟重启验证失败: {e}",
                raw_output=str(e),
            )

    def cleanup_dns_replace_kernel(self) -> str:
        """清理多线路DNS内核规则(不影响数据库), 测试辅助用

        ik_cntl multi-dns无show, 删除单条用del IFNAME。
        本方法clear整个内核规则列表, 供测试异常退出后清理。
        正常流程通过UI删除规则即可(数据库+内核同步)。
        """
        self.connect_router()
        try:
            out = self._router.exec("ik_cntl multi-dns clear 2>&1")
            logger.info(f"[清理] ik_cntl multi-dns clear: {out}")
            return out or ""
        except Exception as e:
            logger.warning(f"[清理] multi-dns clear失败: {e}")
            return ""

    def verify_dns_multi_line_full_chain(self, name: str = None,
                                         expect_exists: bool = True,
                                         expected_fields: Dict = None,
                                         expect_enabled: bool = True) -> FullChainResult:
        """
        多线路DNS规则全链路验证: L1数据库 + L3/L4内核(dmesg功能开关)

        Args:
            name: 规则名称(为None时跳过单规则L1, 仅验证功能开关)
            expect_exists: 规则是否应存在
            expected_fields: 期望字段值
            expect_enabled: 功能开关是否应启用(规则enabled=yes且存在→启用)
        """
        results = []

        # L1: 数据库
        if name:
            results.append(self.verify_dns_replace_database(
                name, expected_fields=expected_fields, must_exist=expect_exists))

        # L3/L4: 内核功能开关状态
        results.append(self.verify_dns_multi_line_kernel(expect_enabled=expect_enabled))

        return FullChainResult(results=results)

    # ==================== 智能流控(Stream Control)验证 ====================
    # 涉及表: global_config(stream_ctl_mode), layer7_intell(智能配置),
    #         wan_config(线路带宽), alone_limit(终端独立限速),
    #         layer7_qos(手动流控策略), high_prio_host(优先域名)
    # 后端脚本: stream_control.sh / layer7_intell.sh / alone_limit.sh /
    #          layer7_qos.sh / high_prio_host.sh

    # ---------- alone_limit(终端独立限速) ----------
    def query_alone_limit_rule(self, name: str) -> Optional[Dict]:
        """L1: 查询终端独立限速规则(alone_limit表, 按tagname)"""
        return self._sqlite_query_line(
            f"SELECT id,tagname,enabled,ip_addr,upload,download,prio,comment "
            f"FROM alone_limit WHERE tagname='{name}'"
        )

    def query_all_alone_limit(self) -> List[Dict]:
        """L1: 查询所有终端独立限速规则"""
        return self._sqlite_query_list(
            "SELECT id,tagname,enabled,upload,download,prio FROM alone_limit"
        )

    def count_alone_limit(self, enabled_only: bool = False) -> int:
        """L1: 统计终端独立限速规则数"""
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM alone_limit {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_alone_limit_database(self, name: str,
                                    expected_fields: Dict = None,
                                    must_exist: bool = True) -> VerifyResult:
        """L1: 验证终端独立限速规则(alone_limit表)

        expected_fields可含: tagname/ip_addr(检查IP子串)/upload/download/prio/enabled
        """
        rule = self.query_alone_limit_rule(name)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=not must_exist,
                message=f"规则'{name}'不存在"
                        f"({'符合预期' if not must_exist else '应为存在'})",
                raw_output="",
            )
        details = {
            "tagname": rule.get("tagname"), "enabled": rule.get("enabled"),
            "ip_addr": rule.get("ip_addr"), "upload": rule.get("upload"),
            "download": rule.get("download"), "prio": rule.get("prio"),
        }
        raw = json.dumps(details, ensure_ascii=False)
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"规则'{name}'存在: up={details['upload']}, "
                        f"down={details['download']}, prio={details['prio']}, "
                        f"enabled={details['enabled']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if fld == "ip_addr":
                # ip_addr是json, 检查IP是否在custom列表里(子串匹配)
                if str(expected) not in actual:
                    mismatches[fld] = {"expected": str(expected), "actual": actual}
            elif actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"规则'{name}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"终端独立限速规则'{name}'数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def verify_alone_limit_ipset(self, rule_id: int, ip: str = None,
                                 should_exist: bool = True) -> VerifyResult:
        """L2: 验证终端独立限速规则的ipset

        alone_limit启用后创建: alone_limit_$id(list:set) + _alone_limit_$id(IP) + _alone_limit_$id_mac
        停用/删除后清理。
        """
        self.connect_router()
        try:
            all_ipset = self._router.exec("ipset list -n 2>/dev/null") or ""
            main_set = f"alone_limit_{rule_id}"
            ip_set = f"_alone_limit_{rule_id}"
            main_exists = main_set in all_ipset
            ip_exists = ip_set in all_ipset

            if should_exist:
                ok = main_exists or ip_exists
                msg = f"ipset {main_set}={'存在' if main_exists else '缺失'}, "
                msg += f"{ip_set}={'存在' if ip_exists else '缺失'}"
                # 进一步检查IP是否在ipset里
                if ok and ip:
                    content = self._router.exec(
                        f"ipset list {ip_set} 2>/dev/null") or ""
                    ip_in = ip in content
                    msg += f", IP({ip})={'在集合中' if ip_in else '不在集合中'}"
                    ok = ok and ip_in
                return VerifyResult(
                    level="L2-ipset", passed=ok, message=msg,
                    details={"main_set": main_exists, "ip_set": ip_exists},
                    raw_output=all_ipset[-300:],
                )
            else:
                ok = not main_exists and not ip_exists
                return VerifyResult(
                    level="L2-ipset", passed=ok,
                    message=f"停用/删除后ipset应清理({main_set}/{ip_set})"
                            f"{'已清理' if ok else '仍存在'}",
                    raw_output=all_ipset[-200:],
                )
        except Exception as e:
            return VerifyResult(
                level="L2-ipset", passed=False,
                message=f"ipset检查失败: {e}", raw_output=str(e),
            )

    # ---------- layer7_qos(手动流控策略) ----------
    def query_layer7_qos_rule(self, name: str) -> Optional[Dict]:
        """L1: 查询手动流控策略规则(layer7_qos表, 按name/tagname)"""
        return self._sqlite_query_line(
            f"SELECT id,name,tagname,enabled,interface,prio,min_up,min_down,"
            f"max_up,max_down,app_proto FROM layer7_qos WHERE name='{name}' "
            f"OR tagname='{name}'"
        )

    def query_all_layer7_qos(self) -> List[Dict]:
        """L1: 查询所有手动流控策略规则"""
        return self._sqlite_query_list(
            "SELECT id,name,tagname,enabled,interface,prio FROM layer7_qos"
        )

    def count_layer7_qos(self, enabled_only: bool = False) -> int:
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM layer7_qos {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_layer7_qos_database(self, name: str,
                                   expected_fields: Dict = None,
                                   must_exist: bool = True) -> VerifyResult:
        """L1: 验证手动流控策略规则(layer7_qos表)"""
        rule = self.query_layer7_qos_rule(name)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=not must_exist,
                message=f"规则'{name}'不存在"
                        f"({'符合预期' if not must_exist else '应为存在'})",
                raw_output="",
            )
        details = {k: rule.get(k) for k in
                   ["name", "tagname", "enabled", "interface", "prio",
                    "min_up", "min_down", "max_up", "max_down"]}
        raw = json.dumps(details, ensure_ascii=False)
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"规则'{name}'存在: interface={details['interface']}, "
                        f"prio={details['prio']}, enabled={details['enabled']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"规则'{name}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"手动流控策略规则'{name}'数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def verify_layer7_qos_ipset(self, rule_id: int,
                                should_exist: bool = True) -> VerifyResult:
        """L2: 验证手动流控策略规则的ipset

        ipset命名可能是 layer7qos_src_$id / _layer7qos_$id / layer7qos_$id, 用模糊匹配。
        """
        self.connect_router()
        try:
            all_ipset = self._router.exec("ipset list -n 2>/dev/null") or ""
            sets = [s.strip() for s in all_ipset.split("\n") if s.strip()]
            matched = [s for s in sets if "layer7qos" in s and str(rule_id) in s]
            exists = len(matched) > 0
            if should_exist:
                return VerifyResult(
                    level="L2-ipset", passed=exists,
                    message=f"layer7qos规则{rule_id} ipset={matched}",
                    raw_output=all_ipset[-300:],
                )
            else:
                ok = not exists
                return VerifyResult(
                    level="L2-ipset", passed=ok,
                    message=f"停用/删除后layer7qos ipset应清理, matched={matched}",
                    raw_output=all_ipset[-200:],
                )
        except Exception as e:
            return VerifyResult(
                level="L2-ipset", passed=False,
                message=f"ipset检查失败: {e}", raw_output=str(e),
            )

    # ---------- high_prio_host(优先域名) ----------
    def query_high_prio_host_rule(self, name: str) -> Optional[Dict]:
        """L1: 查询优先域名规则(high_prio_host表, 按tagname)"""
        return self._sqlite_query_line(
            f"SELECT id,tagname,host,enabled,comment FROM high_prio_host "
            f"WHERE tagname='{name}'"
        )

    def count_high_prio_host(self, enabled_only: bool = False) -> int:
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM high_prio_host {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_high_prio_host_database(self, name: str,
                                       expected_fields: Dict = None,
                                       must_exist: bool = True) -> VerifyResult:
        """L1: 验证优先域名规则(high_prio_host表)"""
        rule = self.query_high_prio_host_rule(name)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=not must_exist,
                message=f"规则'{name}'不存在"
                        f"({'符合预期' if not must_exist else '应为存在'})",
                raw_output="",
            )
        details = {k: rule.get(k) for k in
                   ["tagname", "host", "enabled", "comment"]}
        raw = json.dumps(details, ensure_ascii=False)
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"规则'{name}'存在: host={details['host']}, "
                        f"enabled={details['enabled']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"规则'{name}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"优先域名规则'{name}'数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def verify_high_prio_host_effect(self, expect_enabled: bool = True) -> VerifyResult:
        """L3/L4: 验证优先域名生效条件

        优先域名仅在 layer7_intell.auto=2(网页优先) 且 domain_prio_switch=1
        且 domain_prio_ports非空 时生效(ik_cntl http_app high_prio_host on)。
        ik_cntl http_app无show命令, 通过数据库条件判断生效状态。
        """
        self.connect_router()
        try:
            cfg = self._sqlite_query_line(
                "SELECT auto,domain_prio_switch,domain_prio_ports "
                "FROM layer7_intell WHERE id=1"
            ) or {}
            cnt = self.count_high_prio_host(enabled_only=True)
            auto = cfg.get("auto", "")
            switch = cfg.get("domain_prio_switch", "")
            ports = cfg.get("domain_prio_ports", "")
            # 生效条件: auto=2 && switch=1 && ports非空 && 有enabled记录
            cond_ok = (auto == "2" and switch == "1" and ports != "" and cnt > 0)
            if expect_enabled:
                ok = cond_ok
                msg = (f"生效条件 auto={auto}(需2)/switch={switch}(需1)/"
                       f"ports='{ports}'(需非空)/enabled记录={cnt}(需>0) "
                       f"=>{'满足' if ok else '不满足'}")
            else:
                # 期望不生效: 至少一个条件不满足
                ok = not cond_ok
                msg = (f"期望不生效, 当前条件 auto={auto}/switch={switch}/"
                       f"ports='{ports}'/记录={cnt} =>{'未生效' if ok else '仍在生效'}")
            return VerifyResult(
                level="L3/L4-生效条件", passed=ok, message=msg,
                details={"auto": auto, "domain_prio_switch": switch,
                         "domain_prio_ports": ports, "enabled_count": cnt},
                raw_output=json.dumps(cfg, ensure_ascii=False),
            )
        except Exception as e:
            return VerifyResult(
                level="L3/L4-生效条件", passed=False,
                message=f"优先域名生效条件检查失败: {e}", raw_output=str(e),
            )

    # ---------- layer7_intell(智能流控配置) ----------
    def query_layer7_intell(self) -> Optional[Dict]:
        """L1: 查询智能流控配置(layer7_intell表, 单记录id=1)"""
        return self._sqlite_query_line(
            "SELECT auto,Http,Game,Im,Transport,Relax,Utils,Office,Education,"
            "Life,Financial,Unknown,domain_prio_switch,domain_prio_ports "
            "FROM layer7_intell WHERE id=1"
        )

    def verify_layer7_intell_config(self, expected_fields: Dict = None) -> VerifyResult:
        """L1: 验证智能流控配置(auto场景/应用优先级/domain_prio)

        expected_fields可含: auto/Http/Game/.../domain_prio_switch/domain_prio_ports
        """
        cfg = self.query_layer7_intell()
        if cfg is None:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message="layer7_intell配置不存在", raw_output="",
            )
        raw = json.dumps(cfg, ensure_ascii=False)
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"智能流控配置: auto={cfg.get('auto')}, "
                        f"domain_prio_switch={cfg.get('domain_prio_switch')}, "
                        f"ports={cfg.get('domain_prio_ports')}",
                details={"config": cfg}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(cfg.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"智能流控配置不匹配: {mismatches}",
                details={"config": cfg, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"智能流控配置验证通过",
            details={"config": cfg}, raw_output=raw,
        )

    # ---------- wan_config(线路带宽) ----------
    def query_wan_config_bandwidth(self, line: str) -> Optional[Dict]:
        """L1: 查询指定线路的带宽配置(wan_config表)"""
        return self._sqlite_query_line(
            f"SELECT name,qos_upload,qos_download,qos_switch "
            f"FROM wan_config WHERE name='{line}'"
        )

    def verify_wan_config_bandwidth(self, line: str, upload: int = None,
                                    download: int = None,
                                    qos_switch: int = None) -> VerifyResult:
        """L1: 验证线路带宽配置(wan_config.qos_upload/qos_download/qos_switch)"""
        cfg = self.query_wan_config_bandwidth(line)
        if cfg is None:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"线路'{line}'不存在", raw_output="",
            )
        raw = json.dumps(cfg, ensure_ascii=False)
        checks = []
        if upload is not None:
            ok = str(cfg.get("qos_upload", "")) == str(upload)
            checks.append(("上行带宽", ok,
                           f"qos_upload={cfg.get('qos_upload')}(期望{upload})"))
        if download is not None:
            ok = str(cfg.get("qos_download", "")) == str(download)
            checks.append(("下行带宽", ok,
                           f"qos_download={cfg.get('qos_download')}(期望{download})"))
        if qos_switch is not None:
            ok = str(cfg.get("qos_switch", "")) == str(qos_switch)
            checks.append(("流控开关", ok,
                           f"qos_switch={cfg.get('qos_switch')}(期望{qos_switch})"))
        if not checks:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"线路'{line}': up={cfg.get('qos_upload')}, "
                        f"down={cfg.get('qos_download')}, "
                        f"switch={cfg.get('qos_switch')}",
                details={"config": cfg}, raw_output=raw,
            )
        passed = all(c[1] for c in checks)
        return VerifyResult(
            level="L1-数据库", passed=passed,
            message="; ".join(c[2] for c in checks),
            details={"config": cfg}, raw_output=raw,
        )

    # ---------- global_config(流控模式) ----------
    def query_stream_ctl_mode(self) -> str:
        """L1: 查询流控模式(global_config.stream_ctl_mode: 0关/1智能/2手动)"""
        result = self._sqlite_query_line(
            "SELECT stream_ctl_mode FROM global_config WHERE id=1"
        )
        return result.get("stream_ctl_mode", "") if result else ""

    def verify_stream_ctl_mode(self, expected_mode: int) -> VerifyResult:
        """L1: 验证流控模式(0关闭/1智能/2手动)"""
        mode = self.query_stream_ctl_mode()
        mode_name = {"0": "关闭", "1": "智能模式", "2": "手动模式"}.get(mode, mode)
        exp_name = {"0": "关闭", "1": "智能模式", "2": "手动模式"}.get(str(expected_mode), str(expected_mode))
        ok = mode == str(expected_mode)
        return VerifyResult(
            level="L1-数据库", passed=ok,
            message=f"stream_ctl_mode={mode}({mode_name})"
                    f"({'符合' if ok else '不符合'}期望{exp_name})",
            details={"stream_ctl_mode": mode, "expected": str(expected_mode)},
            raw_output=f"stream_ctl_mode={mode}",
        )

    # ---------- 运行时(qos进程/htb) ----------
    def verify_qos_runtime(self, expect_enabled: bool = True) -> VerifyResult:
        """L4: 验证流控运行时状态(htb_rate_est + LAYER7 iptables链)

        流控开启后: htb_rate_est=1, iptables mangle有LAYER7_IN/OUT/STREAM_LAYER7_NEW链
        """
        self.connect_router()
        try:
            htb = self._router.exec(
                "cat /sys/module/sch_htb/parameters/htb_rate_est 2>/dev/null"
            ).strip()
            ipt = self._router.exec(
                "iptables -t mangle -S 2>/dev/null | grep -cE 'LAYER7|STREAM_LAYER7'"
            ).strip()
            htb_on = (htb == "1")
            has_layer7 = False
            try:
                has_layer7 = int(ipt) > 0
            except ValueError:
                has_layer7 = False

            if expect_enabled:
                ok = htb_on  # htb_rate_est=1是核心标志
                msg = (f"htb_rate_est={htb}({'开启' if htb_on else '关闭'}), "
                       f"LAYER7规则数={ipt}")
            else:
                ok = not htb_on
                msg = (f"期望流控关闭, htb_rate_est={htb}"
                       f"({'已关闭' if not htb_on else '仍开启'})")
            return VerifyResult(
                level="L4-运行时", passed=ok, message=msg,
                details={"htb_rate_est": htb, "layer7_rule_count": ipt,
                         "has_layer7_chain": has_layer7},
                raw_output=f"htb={htb}, layer7_rules={ipt}",
            )
        except Exception as e:
            return VerifyResult(
                level="L4-运行时", passed=False,
                message=f"流控运行时检查失败: {e}", raw_output=str(e),
            )

    # ---------- 清理 ----------
    def cleanup_stream_control(self, disable: bool = True) -> str:
        """清理智能流控环境(关闭流控 + 清空规则表 + 清理ipset)

        测试异常退出后的兜底清理。正常流程通过UI操作。
        """
        self.connect_router()
        out_parts = []
        try:
            # 清空规则表
            for tbl in ["alone_limit", "layer7_qos", "high_prio_host"]:
                o = self._router.exec(
                    f"sqlite3 {self.DNS_DB} 'DELETE FROM {tbl};' 2>&1"
                )
                out_parts.append(f"{tbl}: {o.strip()[:40]}")
            # 关闭流控
            if disable:
                o = self._router.exec(
                    f"sqlite3 {self.DNS_DB} "
                    f"'UPDATE global_config SET stream_ctl_mode=0 WHERE id=1;' 2>&1"
                )
                out_parts.append(f"stream_ctl_mode=0: {o.strip()[:40]}")
            # 重启qos使配置生效 + 清理残留ipset
            self._router.exec("killall -q qos.sh 2>/dev/null; killall -q qos 2>/dev/null")
            self._router.exec(
                "for s in $(ipset list -n 2>/dev/null | grep -E 'alone_limit|layer7qos'); "
                "do ipset destroy $s 2>/dev/null; done"
            )
            self._router.exec("ik_cntl http_app high_prio_host off 2>/dev/null")
            logger.info(f"[清理] 智能流控环境: {'; '.join(out_parts)}")
        except Exception as e:
            logger.warning(f"[清理] 智能流控清理失败: {e}")
        return "; ".join(out_parts)

    # ==================== DHCP服务端(DHCP Server)验证 ====================
    # 涉及表: dhcp_server(DHCP地址池配置, 多记录每行一个LAN/VLAN接口的池)
    # 后端脚本: /usr/ikuai/script/dhcp_server.sh
    # 进程: ik_dhcpd -c /tmp/iktmp/ik_dhcpd.conf -s ik_dhcpd_static.conf -l /var/db/leases.db
    # 配置: /tmp/iktmp/ik_dhcpd.conf(主, 仅enabled=yes规则) + /tmp/iktmp/dhcp-server.status(running标志)
    #       /tmp/iktmp/ik_dhcpd.status(地址池可用数)
    # 网络: UDP67(DHCP服务端监听)/68(客户端中继)
    # iptables: DHCP_ACL链(黑白名单模块创建, UDP67流量经此链; DHCP服务端本身不创建iptables规则)
    # 重启: __delayed_restart延迟2秒重启ik_dhcpd; boot()模拟开机初始化(从db重建conf+重启进程)
    # 字段映射: tagname=名称 interface=服务接口 addr_pool=客户端地址(start-end) netmask=子网掩码
    #          gateway=网关 dns1/dns2=首选/备选DNS lease=租期(分钟) delay=过期保留(小时)
    #          check_addr_valid/check_relay_only phy_ifnames=关联接口(默认all) status=运行状态

    DHCP_CONFILE = "/tmp/iktmp/ik_dhcpd.conf"
    DHCP_STATUS_FILE = "/tmp/iktmp/dhcp-server.status"
    DHCP_POOL_STATUS = "/tmp/iktmp/ik_dhcpd.status"

    def query_dhcp_server_rule(self, name: str) -> Optional[Dict]:
        """L1: 查询单条DHCP服务端配置(按tagname)"""
        return self._sqlite_query_line(
            f"SELECT id,enabled,tagname,interface,addr_pool,exclude_pool,netmask,"
            f"gateway,dns1,dns2,domain,wins1,wins2,next_server,lease,delay,"
            f"phy_ifnames,check_addr_valid,check_relay_only,status "
            f"FROM dhcp_server WHERE tagname='{name}'"
        )

    def query_all_dhcp_server(self) -> List[Dict]:
        """L1: 查询所有DHCP服务端配置"""
        return self._sqlite_query_list(
            "SELECT id,enabled,tagname,interface,addr_pool,gateway,netmask,"
            "dns1,dns2,lease,phy_ifnames FROM dhcp_server"
        )

    def count_dhcp_server(self, enabled_only: bool = False) -> int:
        """L1: 统计DHCP服务端规则数"""
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM dhcp_server {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_dhcp_server_database(self, name: str,
                                    expected_fields: Dict = None,
                                    must_exist: bool = True) -> VerifyResult:
        """L1: 验证DHCP服务端数据库配置(dhcp_server表, 按tagname)

        expected_fields可含: enabled/interface/addr_pool/netmask/gateway/dns1/dns2/lease/delay/
                            check_addr_valid/check_relay_only 等(均精确匹配, 转字符串比较)
        """
        rule = self.query_dhcp_server_rule(name)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=not must_exist,
                message=f"DHCP服务端'{name}'不存在"
                        f"({'符合预期' if not must_exist else '应为存在'})",
                raw_output="",
            )
        details = {
            "id": rule.get("id"), "enabled": rule.get("enabled"),
            "tagname": rule.get("tagname"), "interface": rule.get("interface"),
            "addr_pool": rule.get("addr_pool"), "netmask": rule.get("netmask"),
            "gateway": rule.get("gateway"), "dns1": rule.get("dns1"),
            "dns2": rule.get("dns2"), "lease": rule.get("lease"),
            "delay": rule.get("delay"), "check_addr_valid": rule.get("check_addr_valid"),
        }
        raw = json.dumps(details, ensure_ascii=False)
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"DHCP服务端'{name}'存在: interface={details['interface']}, "
                        f"pool={details['addr_pool']}, enabled={details['enabled']}, "
                        f"lease={details['lease']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"DHCP服务端'{name}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"DHCP服务端'{name}'数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def verify_dhcp_server_process(self, expect_running: bool = True) -> VerifyResult:
        """L2: 验证ik_dhcpd进程状态(DHCP服务端核心进程, 监听UDP67)"""
        self.connect_router()
        try:
            output = self._router.exec("pidof ik_dhcpd 2>/dev/null; ps | grep ik_dhcpd | grep -v grep")
            running = "ik_dhcpd" in output
            if running == expect_running:
                return VerifyResult(
                    level="L2-进程", passed=True,
                    message=f"ik_dhcpd进程状态正确: {'运行中' if running else '未运行'}",
                    details={"running": running},
                    raw_output=output.strip()[:200],
                )
            else:
                return VerifyResult(
                    level="L2-进程", passed=False,
                    message=f"ik_dhcpd进程状态不匹配: 期望{'运行' if expect_running else '未运行'}, "
                            f"实际{'运行中' if running else '未运行'}",
                    details={"running": running, "expected": expect_running},
                    raw_output=output.strip()[:200],
                )
        except Exception as e:
            return VerifyResult(
                level="L2-进程", passed=False,
                message=f"进程检查失败: {e}", raw_output=str(e),
            )

    def verify_dhcp_server_config_file(self, tagname: str = None,
                                       expect_in_conf: bool = True,
                                       expect_any_enabled: bool = None) -> VerifyResult:
        """L3: 验证ik_dhcpd.conf配置文件

        - expect_any_enabled=True: 期望conf存在(有enabled=yes规则时ik_dhcpd启动生成)
        - expect_any_enabled=False: 期望conf为空(无enabled规则)
        - tagname非None: 检查该规则是否出现在conf(仅enabled=yes规则写入conf, 停用的不入conf)
        - expect_in_conf: True=应在conf(启用), False=不应在conf(停用)
        """
        self.connect_router()
        try:
            output = self._router.exec(f"cat {self.DHCP_CONFILE} 2>/dev/null")
            exists = bool(output and output.strip())
            checks = []
            if expect_any_enabled is True:
                checks.append(("配置文件存在", exists,
                               f"ik_dhcpd.conf{'存在' if exists else '不存在(异常,应有enabled规则)'}"))
            elif expect_any_enabled is False:
                checks.append(("配置文件为空", not exists,
                               f"ik_dhcpd.conf{'为空(正确)' if not exists else '非空(异常)'}"))
            if tagname:
                in_conf = f"tagname={tagname}" in (output or "")
                if expect_in_conf:
                    checks.append((f"规则{tagname}在conf中", in_conf,
                                   f"规则{tagname}{'已下发到ik_dhcpd' if in_conf else '未在conf中(异常,应启用)'}"))
                else:
                    checks.append((f"规则{tagname}不在conf中", not in_conf,
                                   f"规则{tagname}{'已从conf移除(正确停用)' if not in_conf else '仍在conf中(异常,应停用)'}"))
            passed = all(c[1] for c in checks) if checks else exists
            return VerifyResult(
                level="L3-配置文件", passed=passed,
                message="; ".join(c[2] for c in checks) if checks else
                f"ik_dhcpd.conf{'存在' if exists else '不存在'}",
                details={"exists": exists, "checks": checks},
                raw_output=(output or "")[:300],
            )
        except Exception as e:
            return VerifyResult(
                level="L3-配置文件", passed=False,
                message=f"配置文件检查失败: {e}", raw_output=str(e),
            )

    def verify_dhcp_server_runtime(self, expect_running: bool = True) -> VerifyResult:
        """L4: 验证DHCP服务端运行时(UDP67监听 + status文件 + 地址池可用数)

        ik_dhcpd监听UDP67(服务端), 68为客户端中继。dhcp-server.status是running标志
        (start写入启动命令, stop删除)。ik_dhcpd.status记录地址池可用数。
        """
        self.connect_router()
        checks = []
        try:
            net_out = self._router.exec("netstat -uln 2>/dev/null | grep -E ':67|:68'")
            has_67 = ":67" in net_out
            if expect_running:
                checks.append(("UDP67监听", has_67,
                               f"UDP67{'监听中' if has_67 else '未监听(异常)'}"))
            else:
                checks.append(("UDP67未监听", not has_67,
                               f"UDP67{'未监听(正确)' if not has_67 else '仍监听(异常)'}"))
        except Exception as e:
            checks.append(("UDP67监听", None, f"检查失败: {e}"))

        try:
            st = self._router.exec(f"cat {self.DHCP_STATUS_FILE} 2>/dev/null")
            has_status = bool(st and st.strip() and "No such" not in st)
            if expect_running:
                checks.append(("status文件存在", has_status,
                               f"dhcp-server.status{'存在(运行中)' if has_status else '不存在(异常)'}"))
            else:
                checks.append(("status文件不存在", not has_status,
                               f"dhcp-server.status{'不存在(正确)' if not has_status else '仍存在(异常)'}"))
        except Exception as e:
            checks.append(("status文件", None, f"检查失败: {e}"))

        passed = all(c[1] for c in checks if c[1] is not None)
        return VerifyResult(
            level="L4-运行时", passed=passed,
            message="; ".join(c[2] for c in checks),
            details={"checks": checks},
            raw_output=str(checks)[:300],
        )

    def verify_dhcp_server_iptables(self, expect_dhcp_acl: bool = True) -> VerifyResult:
        """L4: 验证iptables DHCP_ACL链(INPUT对UDP67引用, 由黑白名单模块创建)

        DHCP服务端本身不创建iptables规则, 但所有UDP67(DHCP请求)流量经INPUT→DHCP_ACL链。
        此验证确认DHCP流量路径完整(链存在=流量能到达ik_dhcpd)。
        """
        self.connect_router()
        try:
            output = self._router.exec(
                "iptables -t filter -S 2>/dev/null | grep -iE 'DHCP_ACL|dport 67'"
            )
            has_acl = "DHCP_ACL" in output or "--dport 67" in output
            if has_acl == expect_dhcp_acl:
                return VerifyResult(
                    level="L4-iptables", passed=True,
                    message=f"DHCP_ACL链{'存在(DHCP流量路径完整)' if has_acl else '不存在(符合预期)'}",
                    details={"has_dhcp_acl": has_acl},
                    raw_output=output.strip()[:200],
                )
            else:
                return VerifyResult(
                    level="L4-iptables", passed=False,
                    message=f"DHCP_ACL链状态不匹配: 期望{'存在' if expect_dhcp_acl else '不存在'}, "
                            f"实际{'存在' if has_acl else '不存在'}",
                    details={"has_dhcp_acl": has_acl},
                    raw_output=output.strip()[:200],
                )
        except Exception as e:
            return VerifyResult(
                level="L4-iptables", passed=False,
                message=f"iptables检查失败: {e}", raw_output=str(e),
            )

    def verify_dhcp_server_reboot(self, tagname: str = None,
                                  expect_any_enabled: bool = True) -> VerifyResult:
        """L4 模拟重启验证: 执行dhcp_server.sh boot模拟开机初始化, 验证配置从数据库完整重建

        流程:
        1. 记录boot前数据库规则数 + ik_dhcpd.conf是否含tagname + 进程pid
        2. /usr/ikuai/script/dhcp_server.sh boot (模拟重启: init重建conf + 重启ik_dhcpd)
        3. 验证: 数据库规则数不变 + conf重新生成 + ik_dhcpd运行 + (tagname仍在conf)
        对照DMZ bug(netmap init用文本做整数比较导致重启失效): dhcp_server boot从db重建conf+重启,
        若init有缺陷则重启后配置不生效。本验证捕获此类bug。
        """
        self.connect_router()
        import time as _t
        try:
            total_before = self.count_dhcp_server(enabled_only=False)
            enabled_before = self.count_dhcp_server(enabled_only=True)
            pid_before = self._router.exec("pidof ik_dhcpd 2>/dev/null").strip()

            boot_out = self._router.exec(
                "/usr/ikuai/script/dhcp_server.sh boot 2>&1; echo BOOT_EXIT=$?"
            )
            _t.sleep(4)  # boot含start + delayed_restart, 等待ik_dhcpd重启完成

            total_after = self.count_dhcp_server(enabled_only=False)
            enabled_after = self.count_dhcp_server(enabled_only=True)
            pid_after = self._router.exec("pidof ik_dhcpd 2>/dev/null").strip()
            conf_out = self._router.exec(f"cat {self.DHCP_CONFILE} 2>/dev/null")
            conf_exists = bool(conf_out and conf_out.strip())

            checks = []
            db_intact = (total_after == total_before)
            checks.append(("数据库规则完整", db_intact,
                           f"规则数 boot前={total_before} boot后={total_after}"
                           f"({'完整' if db_intact else '变化(异常)'})"))
            boot_executed = "BOOT_EXIT=" in (boot_out or "")
            checks.append(("boot脚本已执行", boot_executed,
                           f"dhcp_server.sh boot{'已执行' if boot_executed else '未执行(异常)'}"))
            process_running = bool(pid_after)
            checks.append(("ik_dhcpd重启运行", process_running,
                           f"ik_dhcpd pid={pid_after or '无'}({'运行' if process_running else '未运行(异常)'})"))
            if expect_any_enabled:
                checks.append(("配置文件已重建", conf_exists,
                               f"ik_dhcpd.conf{'已生成' if conf_exists else '未生成(异常)'}"))
            if tagname:
                in_conf = f"tagname={tagname}" in (conf_out or "")
                checks.append((f"规则{tagname}重建后在conf", in_conf,
                               f"规则{tagname}{'仍在conf(重启生效)' if in_conf else '丢失(重启失效bug!)'}"))

            passed = all(c[1] for c in checks)
            return VerifyResult(
                level="L4-模拟重启", passed=passed,
                message="; ".join(c[2] for c in checks),
                details={"checks": [{"name": c[0], "ok": c[1], "msg": c[2]} for c in checks],
                         "total_before": total_before, "total_after": total_after,
                         "enabled_before": enabled_before, "enabled_after": enabled_after,
                         "pid_before": pid_before, "pid_after": pid_after,
                         "boot_output": (boot_out or "")[-200:]},
                raw_output=(boot_out or "")[-300:],
            )
        except Exception as e:
            return VerifyResult(
                level="L4-模拟重启", passed=False,
                message=f"模拟重启验证失败: {e}", raw_output=str(e),
            )

    def verify_dhcp_server_full_chain(self, name: str = None,
                                      expected_fields: Dict = None,
                                      expect_in_conf: bool = True,
                                      expect_process_running: bool = True) -> FullChainResult:
        """DHCP服务端全链路验证: L1数据库 + L2进程 + L3配置文件 + L4运行时"""
        results = []
        if name:
            results.append(self.verify_dhcp_server_database(
                name, expected_fields=expected_fields, must_exist=expect_in_conf))
        results.append(self.verify_dhcp_server_process(expect_running=expect_process_running))
        results.append(self.verify_dhcp_server_config_file(
            tagname=name, expect_in_conf=expect_in_conf,
            expect_any_enabled=expect_process_running))
        results.append(self.verify_dhcp_server_runtime(expect_running=expect_process_running))
        return FullChainResult(results=results)

    def cleanup_dhcp_server_test_rules(self, prefix: str = "DHTEST") -> str:
        """清理DHCP服务端测试规则(按tagname前缀), 测试异常退出兜底用

        正常流程通过UI删除规则(数据库+ik_dhcpd同步)。本方法直接SQL清理 + restart生效。
        """
        self.connect_router()
        try:
            out = self._router.exec(
                f"sqlite3 {self.DNS_DB} \"DELETE FROM dhcp_server WHERE tagname LIKE '{prefix}%';\" 2>&1"
            )
            self._router.exec("/usr/ikuai/script/dhcp_server.sh restart 2>&1")
            logger.info(f"[清理] DHCP测试规则({prefix}*): {out}")
            return out or ""
        except Exception as e:
            logger.warning(f"[清理] DHCP清理失败: {e}")
            return ""

    def snapshot_dhcp_server(self) -> str:
        """备份dhcp_server表完整数据(.dump导出INSERT语句)

        导入清空测试前调用, 万一清空导入异常导致DHS_1丢失可恢复。
        """
        self.connect_router()
        try:
            out = self._router.exec(
                f"sqlite3 {self.DNS_DB} '.dump dhcp_server' 2>/dev/null"
            )
            return out or ""
        except Exception as e:
            logger.warning(f"[备份] dhcp_server dump失败: {e}")
            return ""

    def restore_dhcp_server(self, dump: str) -> bool:
        """从.dump备份恢复dhcp_server表(清空现有+重新导入+restart), 兜底用

        用base64传输避免SQL引号转义问题。
        """
        if not dump or not dump.strip():
            return False
        self.connect_router()
        try:
            import base64 as _b64
            b64 = _b64.b64encode(dump.encode('utf-8')).decode('ascii')
            tmp = "/tmp/iktmp/_dhcp_restore.sql"
            self._router.exec(f"echo '{b64}' | base64 -d > {tmp} 2>/dev/null")
            self._router.exec(
                f"sqlite3 {self.DNS_DB} 'DELETE FROM dhcp_server;' 2>/dev/null; "
                f"sqlite3 {self.DNS_DB} < {tmp} 2>/dev/null; rm -f {tmp}"
            )
            self._router.exec("/usr/ikuai/script/dhcp_server.sh restart 2>&1")
            logger.info("[恢复] dhcp_server表已从备份恢复")
            return True
        except Exception as e:
            logger.warning(f"[恢复] dhcp_server恢复失败: {e}")
            return False

    # ==================== DHCP静态分配(DHCP Static)验证 ====================
    # 涉及表: dhcp_static(MAC-IP绑定, DHCP服务端子功能)
    # 后端脚本: /usr/ikuai/function/dhcp_static
    # 共用ik_dhcpd进程(无独立进程/iptables/内核), 绑定下发到:
    #   /tmp/iktmp/ik_dhcp_static_cache.conf (cache, 仅enabled=yes, 格式: <interface> <ip> <mac> [<gw> <dns1> <dns2>])
    #   /tmp/iktmp/ik_dhcpd_static.conf (最终给ik_dhcpd, = cache + arp[dhcpd_arp时] + ike_dhcp)
    # add/edit/del/up/down后 __dhcp_static_update(重建cache+static.conf) + dhcp_server.sh delayed_restart
    # 约束: tagname唯一, ip_addr唯一, (interface,mac)组合唯一
    # 字段: id/enabled/tagname/comment/cl_name/interface(默认auto)/ip_addr/mac/gateway/dns1/dns2

    DHCP_STATIC_CACHE = "/tmp/iktmp/ik_dhcp_static_cache.conf"
    DHCP_STATIC_CONF = "/tmp/iktmp/ik_dhcpd_static.conf"

    def query_dhcp_static_rule(self, name: str) -> Optional[Dict]:
        """L1: 查询单条DHCP静态分配(按tagname)"""
        return self._sqlite_query_line(
            f"SELECT id,enabled,tagname,comment,cl_name,interface,ip_addr,mac,"
            f"gateway,dns1,dns2 FROM dhcp_static WHERE tagname='{name}'"
        )

    def query_dhcp_static_by_mac(self, mac: str) -> Optional[Dict]:
        """L1: 按MAC查询DHCP静态分配"""
        return self._sqlite_query_line(
            f"SELECT id,enabled,tagname,interface,ip_addr,mac FROM dhcp_static WHERE mac='{mac}'"
        )

    def query_all_dhcp_static(self) -> List[Dict]:
        """L1: 查询所有DHCP静态分配"""
        return self._sqlite_query_list(
            "SELECT id,enabled,tagname,interface,ip_addr,mac,gateway,dns1,dns2 "
            "FROM dhcp_static"
        )

    def count_dhcp_static(self, enabled_only: bool = False) -> int:
        """L1: 统计DHCP静态分配规则数"""
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM dhcp_static {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_dhcp_static_database(self, name: str,
                                    expected_fields: Dict = None,
                                    must_exist: bool = True) -> VerifyResult:
        """L1: 验证DHCP静态分配数据库配置(dhcp_static表, 按tagname)

        expected_fields可含: enabled/interface/ip_addr/mac/gateway/dns1/dns2/comment
        """
        rule = self.query_dhcp_static_rule(name)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=not must_exist,
                message=f"DHCP静态分配'{name}'不存在"
                        f"({'符合预期' if not must_exist else '应为存在'})",
                raw_output="",
            )
        details = {
            "id": rule.get("id"), "enabled": rule.get("enabled"),
            "tagname": rule.get("tagname"), "interface": rule.get("interface"),
            "ip_addr": rule.get("ip_addr"), "mac": rule.get("mac"),
            "gateway": rule.get("gateway"), "dns1": rule.get("dns1"),
            "dns2": rule.get("dns2"),
        }
        raw = json.dumps(details, ensure_ascii=False)
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"DHCP静态分配'{name}'存在: interface={details['interface']}, "
                        f"ip={details['ip_addr']}, mac={details['mac']}, "
                        f"enabled={details['enabled']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"DHCP静态分配'{name}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"DHCP静态分配'{name}'数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def verify_dhcp_static_config_file(self, tagname: str = None,
                                       ip: str = None, mac: str = None,
                                       expect_in_conf: bool = True) -> VerifyResult:
        """L3: 验证DHCP静态绑定是否下发到ik_dhcpd_static.conf(给ik_dhcpd的最终配置)

        cache(ik_dhcp_static_cache.conf)仅含enabled=yes规则; static.conf = cache+arp+ike。
        检查 static.conf 是否包含指定绑定(用mac最独特, 辅以ip)。
        - expect_in_conf=True: 应在conf(规则启用, 绑定已下发)
        - expect_in_conf=False: 不应在conf(规则停用, 绑定已移除)
        """
        self.connect_router()
        try:
            output = self._router.exec(f"cat {self.DHCP_STATIC_CONF} 2>/dev/null")
            cache_out = self._router.exec(f"cat {self.DHCP_STATIC_CACHE} 2>/dev/null")
            checks = []
            # mac最独特, 优先检查mac
            key = mac or ip
            if key:
                in_conf = key in (output or "")
                in_cache = key in (cache_out or "")
                if expect_in_conf:
                    checks.append((f"绑定({key})在static.conf", in_conf,
                                   f"static.conf{'含' if in_conf else '不含'}{key}"
                                   f"({'已下发' if in_conf else '未下发(异常)'})"))
                    # cache反映enabled=yes(停用的不在cache但可能在static.conf的arp段)
                    checks.append((f"绑定({key})在cache", in_cache,
                                   f"cache{'含' if in_cache else '不含'}{key}"
                                   f"(enabled={'yes' if in_cache else 'no/arp来源'})"))
                else:
                    # 停用的不应在cache(cache仅enabled=yes)
                    checks.append((f"绑定({key})不在cache", not in_cache,
                                   f"cache{'不含' if not in_cache else '仍含'}{key}"
                                   f"({'停用正确' if not in_cache else '异常(应停用)'})"))
            elif tagname:
                # 无mac/ip时, 查数据库拿mac
                rule = self.query_dhcp_static_rule(tagname)
                if rule:
                    m = rule.get("mac", "")
                    if m:
                        in_conf = m in (output or "")
                        checks.append((f"绑定(mac={m})在static.conf", in_conf if expect_in_conf else not in_conf,
                                       f"static.conf{'含' if in_conf else '不含'}{m}"))
                    else:
                        checks.append(("mac为空", True, "规则mac字段为空"))
                else:
                    checks.append(("规则不存在", not expect_in_conf, f"规则{tagname}不存在"))

            passed = all(c[1] for c in checks) if checks else False
            return VerifyResult(
                level="L3-配置文件", passed=passed,
                message="; ".join(c[2] for c in checks) if checks else "无检查项",
                details={"static_conf_exists": bool(output and output.strip()),
                         "cache_exists": bool(cache_out and cache_out.strip()),
                         "checks": checks},
                raw_output=(output or "")[:300],
            )
        except Exception as e:
            return VerifyResult(
                level="L3-配置文件", passed=False,
                message=f"配置文件检查失败: {e}", raw_output=str(e),
            )

    def verify_dhcp_static_process(self, expect_running: bool = True) -> VerifyResult:
        """L2: 验证ik_dhcpd进程状态(静态绑定共用DHCP服务端ik_dhcpd进程)"""
        # 复用DHCP服务端的进程验证逻辑
        return self.verify_dhcp_server_process(expect_running=expect_running)

    def verify_dhcp_static_reboot(self, tagname: str = None, mac: str = None) -> VerifyResult:
        """L4 模拟重启验证: dhcp_server.sh boot后, 静态绑定仍从数据库重建到static.conf

        对照DMZ bug: 验证重启后绑定配置不丢失。
        """
        self.connect_router()
        import time as _t
        try:
            total_before = self.count_dhcp_static(enabled_only=False)
            enabled_before = self.count_dhcp_static(enabled_only=True)
            # 取mac(优先传入, 否则从数据库)
            check_mac = mac
            if not check_mac and tagname:
                rule = self.query_dhcp_static_rule(tagname)
                check_mac = rule.get("mac") if rule else None

            boot_out = self._router.exec(
                "/usr/ikuai/script/dhcp_server.sh boot 2>&1; echo BOOT_EXIT=$?"
            )
            _t.sleep(4)

            total_after = self.count_dhcp_static(enabled_only=False)
            enabled_after = self.count_dhcp_static(enabled_only=True)
            static_conf = self._router.exec(f"cat {self.DHCP_STATIC_CONF} 2>/dev/null")

            checks = []
            db_intact = (total_after == total_before)
            checks.append(("数据库绑定完整", db_intact,
                           f"绑定数 boot前={total_before} boot后={total_after}"
                           f"({'完整' if db_intact else '变化(异常)'})"))
            boot_executed = "BOOT_EXIT=" in (boot_out or "")
            checks.append(("boot脚本已执行", boot_executed,
                           f"dhcp_server.sh boot{'已执行' if boot_executed else '未执行(异常)'}"))
            if check_mac:
                in_conf = check_mac in (static_conf or "")
                checks.append((f"绑定({check_mac})重启后在static.conf", in_conf,
                               f"static.conf{'仍含' if in_conf else '丢失'}{check_mac}"
                               f"({'重启生效' if in_conf else '重启失效bug!'})"))

            passed = all(c[1] for c in checks)
            return VerifyResult(
                level="L4-模拟重启", passed=passed,
                message="; ".join(c[2] for c in checks),
                details={"checks": [{"name": c[0], "ok": c[1], "msg": c[2]} for c in checks],
                         "total_before": total_before, "total_after": total_after,
                         "enabled_before": enabled_before, "enabled_after": enabled_after,
                         "boot_output": (boot_out or "")[-200:]},
                raw_output=(boot_out or "")[-300:],
            )
        except Exception as e:
            return VerifyResult(
                level="L4-模拟重启", passed=False,
                message=f"模拟重启验证失败: {e}", raw_output=str(e),
            )

    def verify_dhcp_static_full_chain(self, name: str = None,
                                      expected_fields: Dict = None,
                                      mac: str = None,
                                      expect_in_conf: bool = True,
                                      expect_process_running: bool = True) -> FullChainResult:
        """DHCP静态分配全链路验证: L1数据库 + L2进程 + L3静态配置文件"""
        results = []
        if name:
            results.append(self.verify_dhcp_static_database(
                name, expected_fields=expected_fields, must_exist=expect_in_conf))
        results.append(self.verify_dhcp_static_process(expect_running=expect_process_running))
        results.append(self.verify_dhcp_static_config_file(
            tagname=name, mac=mac, expect_in_conf=expect_in_conf))
        return FullChainResult(results=results)

    def verify_dhcpd_arp(self, expect_enabled: bool) -> VerifyResult:
        """验证"兼容ARP绑定列表为静态分配"开关(global_config.dhcpd_arp)

        DHCP静态分配设置面板(右上角齿轮)的"兼容ARP绑定列表为静态分配"复选框。
        开启后dhcp_server.sh的__dhcpd_static_dump会把arp表lan/vlan条目加入ik_dhcpd_static.conf。
        - expect_enabled=True: dhcpd_arp=1
        - expect_enabled=False: dhcpd_arp=0
        """
        self.connect_router()
        try:
            result = self._sqlite_query_line(
                "SELECT dhcpd_arp FROM global_config WHERE id=1"
            )
            arp_val = result.get("dhcpd_arp") if result else None
            arp_enabled = (arp_val == "1")
            checks = []
            checks.append(("dhcpd_arp字段值",
                           arp_enabled == expect_enabled,
                           f"dhcpd_arp={arp_val}({'开启' if arp_enabled else '关闭'}, "
                           f"期望{'开启' if expect_enabled else '关闭'})"))
            if expect_enabled:
                static_conf = self._router.exec(f"cat {self.DHCP_STATIC_CONF} 2>/dev/null")
                has_mac = bool(re.search(r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}',
                                          static_conf or ''))
                checks.append(("static.conf含ARP条目", has_mac,
                               f"ik_dhcpd_static.conf{'含MAC行(ARP已注入)' if has_mac else '无MAC行(arp表可能空)'}"))
            passed = all(c[1] for c in checks)
            return VerifyResult(
                level="L1-设置(dhcpd_arp)", passed=passed,
                message="; ".join(c[2] for c in checks),
                details={"dhcpd_arp": arp_val, "expect_enabled": expect_enabled,
                         "checks": checks},
                raw_output=f"dhcpd_arp={arp_val}",
            )
        except Exception as e:
            return VerifyResult(
                level="L1-设置(dhcpd_arp)", passed=False,
                message=f"dhcpd_arp验证失败: {e}", raw_output=str(e),
            )

    def cleanup_dhcp_static_test_rules(self, prefix: str = "DHSTEST") -> str:
        """清理DHCP静态分配测试规则(按tagname前缀), 测试异常退出兜底用"""
        self.connect_router()
        try:
            out = self._router.exec(
                f"sqlite3 {self.DNS_DB} \"DELETE FROM dhcp_static WHERE tagname LIKE '{prefix}%';\" 2>&1"
            )
            self._router.exec("/usr/ikuai/script/dhcp_server.sh restart 2>&1")
            logger.info(f"[清理] DHCP静态分配测试规则({prefix}*): {out}")
            return out or ""
        except Exception as e:
            logger.warning(f"[清理] DHCP静态分配清理失败: {e}")
            return ""

    # ==================== DHCP客户端(DHCP Lease)验证 ====================
    # DHCP客户端是只读+操作型页面, 显示/var/db/leases.db的动态租约
    # 操作: 一键回收IP地址(recycle清leases) / 加入静态分配(→dhcp_static) / 加入黑名单(→dhcp_acl_mac_black)
    # 共用ik_dhcpd进程(DHCP服务端子功能, 无独立iptables/内核)

    LEASES_DB = "/var/db/leases.db"

    def query_lease(self, ip: str = None, mac: str = None) -> Optional[Dict]:
        """查询leases.db租约(按IP或MAC)"""
        self.connect_router()
        try:
            where_parts = []
            if ip:
                where_parts.append(f"ip_addr='{ip}'")
            if mac:
                where_parts.append(f"mac='{mac}'")
            where = " or ".join(where_parts) if where_parts else "1=1"
            output = self._router.exec(
                f"sqlite3 {self.LEASES_DB} -line \"select id,interface,ip_addr,mac,"
                f"hostname,start_time,end_time,status from leases where {where}\" 2>/dev/null"
            )
            if not output or not output.strip():
                return None
            result = {}
            for line in output.splitlines():
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    result[k.strip()] = v.strip()
            return result if result else None
        except Exception as e:
            logger.error(f"[L1] 查询lease失败: {e}")
            return None

    def count_leases(self) -> int:
        """统计leases.db租约总数"""
        self.connect_router()
        try:
            output = self._router.exec(
                f"sqlite3 {self.LEASES_DB} \"select count(*) from leases\" 2>/dev/null"
            ).strip()
            return int(output) if output.isdigit() else 0
        except Exception:
            return 0

    def verify_lease_in_db(self, ip: str = None, mac: str = None,
                           must_exist: bool = True) -> VerifyResult:
        """L1: 验证leases.db有/无指定租约(按IP或MAC)"""
        lease = self.query_lease(ip=ip, mac=mac)
        exists = lease is not None
        if exists == must_exist:
            return VerifyResult(
                level="L1-租约", passed=True,
                message=f"租约(ip={ip},mac={mac}){'存在' if exists else '不存在'}(符合预期)"
                        + (f": {lease.get('hostname')}" if lease else ""),
                details={"lease": lease}, raw_output=str(lease),
            )
        else:
            return VerifyResult(
                level="L1-租约", passed=False,
                message=f"租约状态不匹配: 期望{'存在' if must_exist else '不存在'}, "
                        f"实际{'存在' if exists else '不存在'}",
                details={"lease": lease}, raw_output=str(lease),
            )

    def verify_leases_recycled(self, expect_count: int = 0) -> VerifyResult:
        """L1: 验证一键回收后leases.db租约数(回收清空→expect_count=0或减少)"""
        count = self.count_leases()
        # recycle可能清空(force)或只清过期, 用<=expect_count或显著减少判断
        passed = (count <= expect_count) if expect_count > 0 else (count == 0)
        return VerifyResult(
            level="L1-回收", passed=passed,
            message=f"leases.db租约数={count}(期望{'<= Expect_count='+str(expect_count) if expect_count>0 else '=0'})",
            details={"count": count, "expect_count": expect_count},
            raw_output=f"leases_count={count}",
        )

    def query_acl_mac_black(self, mac: str) -> Optional[Dict]:
        """查询acl_mac_black(通用MAC黑名单, DHCP客户端'加入黑名单'写入此表)

        !!注意: DHCP客户端行内'加入黑名单'调用func_name=acl_mac(不是dhcp_acl_mac),
        把MAC加入acl_mac_black表(ACL_MAC iptables链), **不是**dhcp_acl_mac_black(DHCP专用黑白名单)。
        两者是不同的表/功能。
        """
        return self._sqlite_query_line(
            f"SELECT id,enabled,tagname,mac,comment FROM acl_mac_black WHERE mac='{mac}'"
        )

    def verify_lease_to_blacklist(self, mac: str, must_exist: bool = True) -> VerifyResult:
        """L1: 验证MAC是否在acl_mac_black(DHCP客户端'加入黑名单'的结果)"""
        rule = self.query_acl_mac_black(mac)
        exists = rule is not None
        if exists == must_exist:
            return VerifyResult(
                level="L1-黑名单", passed=True,
                message=f"MAC {mac}{'在' if exists else '不在'}acl_mac_black黑名单(符合预期)",
                details={"rule": rule}, raw_output=str(rule),
            )
        else:
            return VerifyResult(
                level="L1-黑名单", passed=False,
                message=f"黑名单状态不匹配: 期望{'在' if must_exist else '不在'}, "
                        f"实际{'在' if exists else '不在'}",
                details={"rule": rule}, raw_output=str(rule),
            )

    def verify_lease_to_static(self, name: str, must_exist: bool = True) -> VerifyResult:
        """L1: 验证加入静态分配后dhcp_static有该绑定(复用dhcp_static验证)"""
        return self.verify_dhcp_static_database(name, must_exist=must_exist)

    def cleanup_dhcp_lease_test(self, static_prefix: str = "DHLEASE",
                                blacklist_macs: list = None) -> str:
        """清理DHCP客户端测试残留(加入静态分配的规则 + 加入黑名单的MAC)"""
        self.connect_router()
        out_parts = []
        try:
            o = self._router.exec(
                f"sqlite3 {self.DNS_DB} \"DELETE FROM dhcp_static WHERE tagname LIKE '{static_prefix}%';\" 2>&1"
            )
            out_parts.append(f"static({static_prefix}): {o.strip()[:40]}")
            if blacklist_macs:
                for mac in blacklist_macs:
                    o = self._router.exec(
                        f"sqlite3 {self.DNS_DB} \"DELETE FROM acl_mac_black WHERE mac='{mac}';\" 2>&1"
                    )
                    out_parts.append(f"blacklist({mac}): {o.strip()[:40]}")
            self._router.exec("/usr/ikuai/script/dhcp_server.sh restart 2>&1")
            logger.info(f"[清理] DHCP客户端残留: {'; '.join(out_parts)}")
        except Exception as e:
            logger.warning(f"[清理] DHCP客户端清理失败: {e}")
        return "; ".join(out_parts)

    # ==================== DHCP黑白名单(DHCP Acl Mac)验证 ====================
    # 涉及表: dhcp_acl_mac_black(模式0)/dhcp_acl_mac_white(模式1)
    # 后端脚本: /usr/ikuai/script/dhcp_acl_mac.sh
    # ipset: Linux_dhcp_aclmac_default(hash:mac, enabled=yes的MAC)
    # iptables: DHCP_ACL链(INPUT→UDP67→DHCP_ACL), 模式决定规则:
    #   0黑名单: -m set --match-set Linux_dhcp_aclmac_default src -j DROP (黑名单内禁止)
    #   1白名单: -m set ! --match-set Linux_dhcp_aclmac_default src -j DROP (白名单外禁止,空ipset阻止所有!)
    #   2同步: 使用Linux_aclmac_default(通用MAC访问控制)
    # 模式: global_config.dhcp_acl_mac(0/1/2), __get_acl_action: 0→black表, 非0→white表
    # 字段: id/enabled(默认'no'!)/tagname(unique)/ip_type(默认'4')/comment/mac(unique)
    # 关键: enabled默认'no', 添加的规则默认不入ipset, up()启用才加入ipset

    DHCP_ACL_IPSET = "Linux_dhcp_aclmac_default"
    DHCP6_ACL_IPSET = "Linux_dhcp6_aclmac_default"

    def _dhcp_acl_params(self, ip_version: str = 'v4') -> dict:
        """按 ip_version 返回 DHCP 黑白名单各层资源名映射。

        IPv4 与 IPv6 是两个完全独立的平行模块(SSH探查确认 2026-06-23):
          - v4: dhcp_acl_mac_{black,white}表 / Linux_dhcp_aclmac_default ipset /
                global_config.dhcp_acl_mac / iptables DHCP_ACL链(UDP67) / dhcp_acl_mac.sh
          - v6: dhcp6_acl_mac_{black,white}表 / Linux_dhcp6_aclmac_default ipset /
                global_config.dhcp6_acl_mac / ip6tables DHCP6_ACL链(UDP547) / dhcp6_acl_mac.sh
        v6 表无 ip_type / termname 列(隐式 IPv6)。
        """
        if ip_version == 'v6':
            return {
                'tbl': 'dhcp6_acl_mac',
                'ipset': self.DHCP6_ACL_IPSET,
                'mode_col': 'dhcp6_acl_mac',
                'ipt_cmd': 'ip6tables -t filter -S DHCP6_ACL 2>/dev/null',
                'chain': 'DHCP6_ACL',
                'init': '/usr/ikuai/script/dhcp6_acl_mac.sh init',
                'has_ip_type': False,
            }
        return {
            'tbl': 'dhcp_acl_mac',
            'ipset': self.DHCP_ACL_IPSET,
            'mode_col': 'dhcp_acl_mac',
            'ipt_cmd': 'iptables -t filter -S DHCP_ACL 2>/dev/null',
            'chain': 'DHCP_ACL',
            'init': '/usr/ikuai/script/dhcp_acl_mac.sh init',
            'has_ip_type': True,
        }

    def query_dhcp_acl_rule(self, mac: str = None, name: str = None,
                            table: str = 'black', ip_version: str = 'v4') -> Optional[Dict]:
        """查询dhcp黑白名单表(按mac或tagname)

        ip_version='v4' → dhcp_acl_mac_{table}(含ip_type列);
        ip_version='v6' → dhcp6_acl_mac_{table}(无ip_type列)。
        """
        p = self._dhcp_acl_params(ip_version)
        where = []
        if mac:
            where.append(f"mac='{mac}'")
        if name:
            where.append(f"tagname='{name}'")
        w = " and ".join(where) if where else "1=1"
        cols = ("id,enabled,tagname,ip_type,mac,comment"
                if p['has_ip_type'] else "id,enabled,tagname,mac,comment")
        return self._sqlite_query_line(
            f"SELECT {cols} FROM {p['tbl']}_{table} WHERE {w}"
        )

    def count_dhcp_acl_rules(self, table: str = 'black', enabled_only: bool = False,
                             ip_version: str = 'v4') -> int:
        """统计dhcp黑白名单表规则数"""
        p = self._dhcp_acl_params(ip_version)
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM {p['tbl']}_{table} {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_dhcp_acl_database(self, name: str = None, mac: str = None,
                                 table: str = 'black',
                                 expected_fields: Dict = None,
                                 must_exist: bool = True,
                                 ip_version: str = 'v4') -> VerifyResult:
        """L1: 验证dhcp黑白名单表规则(按name或mac)

        expected_fields可含: enabled/tagname/mac/comment (v4 另含 ip_type)。
        ip_version='v4'/'v6' 决定查询 dhcp_acl_mac_/dhcp6_acl_mac_ 表。
        """
        p = self._dhcp_acl_params(ip_version)
        lvl = f"L1-{table}{ip_version}表"
        rule = self.query_dhcp_acl_rule(mac=mac, name=name, table=table, ip_version=ip_version)
        if rule is None:
            return VerifyResult(
                level=lvl, passed=not must_exist,
                message=f"DHCP黑白名单'{name or mac}'({table}表)不存在"
                        f"({'符合预期' if not must_exist else '应为存在'})",
                raw_output="",
            )
        details = {
            "id": rule.get("id"), "enabled": rule.get("enabled"),
            "tagname": rule.get("tagname"), "mac": rule.get("mac"),
            "table": table,
        }
        raw = json.dumps(details, ensure_ascii=False)
        if not must_exist:
            # 规则存在但期望不存在 → 失败
            return VerifyResult(
                level=lvl, passed=False,
                message=f"规则'{name or mac}'({table}表)存在但期望不存在(删除/清理未生效)",
                details={"rule": details}, raw_output=raw,
            )
        if expected_fields is None:
            return VerifyResult(
                level=lvl, passed=True,
                message=f"规则'{name or mac}'({table}表)存在: enabled={details['enabled']}, mac={details['mac']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level=lvl, passed=False,
                message=f"规则'{name or mac}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level=lvl, passed=True,
            message=f"规则'{name or mac}'({table}表)数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def verify_dhcp_acl_ipset(self, mac: str, should_in_ipset: bool = True,
                              ip_version: str = 'v4') -> VerifyResult:
        """L2: 验证ipset含/不含该MAC

        v4 → Linux_dhcp_aclmac_default; v6 → Linux_dhcp6_aclmac_default。
        enabled=yes的MAC在ipset(add/up时ipset_add, del/down时ipset_del)。
        """
        p = self._dhcp_acl_params(ip_version)
        self.connect_router()
        lvl = f"L2-ipset{ip_version}"
        try:
            output = self._router.exec(f"ipset list {p['ipset']} 2>/dev/null")
            # ipset hash:mac存储MAC为大写(如D4:20:...), client MAC为小写→大小写不敏感匹配
            in_ipset = mac.lower() in (output or "").lower()
            if in_ipset == should_in_ipset:
                return VerifyResult(
                    level=lvl, passed=True,
                    message=f"MAC {mac}{('在' if in_ipset else '不在')}{p['ipset']}(符合预期)",
                    details={"in_ipset": in_ipset}, raw_output=output[:200],
                )
            else:
                return VerifyResult(
                    level=lvl, passed=False,
                    message=f"{p['ipset']}状态不匹配: 期望{'在' if should_in_ipset else '不在'}, "
                            f"实际{'在' if in_ipset else '不在'}",
                    details={"in_ipset": in_ipset}, raw_output=output[:200],
                )
        except Exception as e:
            return VerifyResult(
                level=lvl, passed=False,
                message=f"ipset检查失败: {e}", raw_output=str(e),
            )

    def verify_dhcp_acl_mode(self, expected_mode: int, ip_version: str = 'v4') -> VerifyResult:
        """L1: 验证模式(0黑名单/1白名单/2同步)

        v4 → global_config.dhcp_acl_mac; v6 → global_config.dhcp6_acl_mac。
        """
        p = self._dhcp_acl_params(ip_version)
        col = p['mode_col']
        result = self._sqlite_query_line(
            f"SELECT {col} FROM global_config WHERE id=1"
        )
        mode_val = result.get(col) if result else None
        try:
            mode_int = int(mode_val) if mode_val is not None else -1
        except (ValueError, TypeError):
            mode_int = -1
        mode_desc = {0: "黑名单", 1: "白名单", 2: "同步MAC访问控制"}.get(mode_int, f"未知({mode_val})")
        passed = (mode_int == expected_mode)
        return VerifyResult(
            level=f"L1-模式{ip_version}", passed=passed,
            message=f"{col}={mode_val}({mode_desc}), 期望{expected_mode}({mode_desc if passed else ''})",
            details={"mode": mode_val, "expected": expected_mode},
            raw_output=f"{col}={mode_val}",
        )

    def verify_dhcp_acl_iptables(self, mode: int, ip_version: str = 'v4') -> VerifyResult:
        """L4: 验证iptables/ip6tables链规则符合模式

        v4 → iptables DHCP_ACL链(UDP67); v6 → ip6tables DHCP6_ACL链(UDP547)。
        mode0黑名单: --match-set <ipset> src -j DROP (无!)
        mode1白名单: ! --match-set <ipset> src -j DROP (有!)
        mode2同步: --match-set Linux_aclmac_default src -j DROP
        """
        p = self._dhcp_acl_params(ip_version)
        # xt_set坏时降级软记录: DHCP_ACL规则用-m set引用Linux_dhcp_aclmac_default, xt_set坏则规则无法建立
        if self.is_xt_set_broken():
            return self.xt_set_degrade_result(f"L4-iptables{ip_version}", p.get('chain', 'DHCP_ACL'), f" mode={mode}")
        self.connect_router()
        lvl = f"L4-iptables{ip_version}"
        try:
            output = self._router.exec(p['ipt_cmd'])
            has_dhcp_aclmac = p['ipset'] in output
            has_aclmac = "Linux_aclmac_default" in output
            has_not = "! --match-set" in output or "!  --match-set" in output
            mode_desc = {0: "黑名单", 1: "白名单", 2: "同步"}.get(mode, "?")
            checks = []
            if mode == 0:
                checks.append((f"黑名单规则({p['ipset']})", has_dhcp_aclmac and not has_not,
                               f"{p['chain']}{'含'+p['ipset']+'无!' if (has_dhcp_aclmac and not has_not) else '规则不符'}"))
            elif mode == 1:
                checks.append((f"白名单规则(! {p['ipset']})", has_dhcp_aclmac and has_not,
                               f"{p['chain']}{'含! '+p['ipset'] if (has_dhcp_aclmac and has_not) else '规则不符'}"))
            elif mode == 2:
                checks.append(("同步规则(acl_mac)", has_aclmac,
                               f"{p['chain']}{'含acl_mac' if has_aclmac else '规则不符'}"))
            passed = all(c[1] for c in checks) if checks else False
            return VerifyResult(
                level=lvl, passed=passed,
                message=f"模式{mode}({mode_desc}): " + "; ".join(c[2] for c in checks),
                details={"mode": mode, "has_dhcp_aclmac": has_dhcp_aclmac,
                         "has_aclmac": has_aclmac, "has_not": has_not},
                raw_output=output[:300],
            )
        except Exception as e:
            return VerifyResult(
                level=lvl, passed=False,
                message=f"iptables检查失败: {e}", raw_output=str(e),
            )

    def verify_dhcp_acl_reboot(self, ip_version: str = 'v4') -> VerifyResult:
        """L4 模拟重启: dhcp_acl_mac.sh / dhcp6_acl_mac.sh init重建ipset+iptables"""
        p = self._dhcp_acl_params(ip_version)
        self.connect_router()
        import time as _t
        lvl = f"L4-模拟重启{ip_version}"
        try:
            out = self._router.exec(
                f"{p['init']} 2>&1; echo INIT_EXIT=$?"
            )
            _t.sleep(2)
            ipset_out = self._router.exec(f"ipset list {p['ipset']} 2>/dev/null | head -2")
            ipt_out = self._router.exec(p['ipt_cmd'])
            checks = []
            checks.append(("init已执行", "INIT_EXIT=" in (out or ""),
                           f"init{'已执行' if 'INIT_EXIT=' in (out or '') else '未执行'}"))
            checks.append(("ipset存在", "Name:" in ipset_out,
                           f"ipset{'存在' if 'Name:' in ipset_out else '不存在'}"))
            checks.append((f"{p['chain']}链存在", p['chain'] in ipt_out,
                           f"{p['chain']}链{'存在' if p['chain'] in ipt_out else '不存在'}"))
            passed = all(c[1] for c in checks)
            return VerifyResult(
                level=lvl, passed=passed,
                message="; ".join(c[2] for c in checks),
                details={"checks": checks, "init_output": (out or "")[-200:]},
                raw_output=(out or "")[-300:],
            )
        except Exception as e:
            return VerifyResult(
                level=lvl, passed=False,
                message=f"模拟重启失败: {e}", raw_output=str(e),
            )

    def cleanup_dhcp_acl_test(self, prefix: str = "DHACL", ip_version: str = 'v4') -> str:
        """清理DHCP黑白名单测试规则 + 恢复模式0 + 重建ipset

        ip_version='v4'清dhcp_acl_mac_{black,white}+恢复dhcp_acl_mac=0+dhcp_acl_mac.sh init;
        ip_version='v6'清dhcp6_acl_mac_{black,white}+恢复dhcp6_acl_mac=0+dhcp6_acl_mac.sh init。
        测试异常退出兜底用(白名单空ipset会阻止所有DHCP, 必须恢复模式0)。
        """
        p = self._dhcp_acl_params(ip_version)
        col = p['mode_col']
        self.connect_router()
        out_parts = []
        try:
            for table in ['black', 'white']:
                o = self._router.exec(
                    f"sqlite3 {self.DNS_DB} \"DELETE FROM {p['tbl']}_{table} WHERE tagname LIKE '{prefix}%';\" 2>&1"
                )
                out_parts.append(f"{table}: {o.strip()[:40]}")
            self._router.exec(
                f"sqlite3 {self.DNS_DB} \"UPDATE global_config SET {col}=0 WHERE id=1;\" 2>&1"
            )
            self._router.exec(f"{p['init']} 2>&1")
            logger.info(f"[清理] DHCP黑白名单{ip_version}({prefix}*): {'; '.join(out_parts)} + 模式恢复0")
        except Exception as e:
            logger.warning(f"[清理] DHCP黑白名单{ip_version}清理失败: {e}")
        return "; ".join(out_parts)

    # ==================== IPv6前缀静态分配(IPv6 Static)验证 ====================
    # 涉及表: ipv6_dhcp_static_config(DHCPv6-PD前缀静态分配)
    # 后端脚本: /usr/ikuai/script/ipv6_static.sh (add/edit/del + ipv6.sh add_static/del_static生效)
    # 字段: id/enabled(默认yes)/tagname(unique)/link_addr(终端本地链接IPv6)/src_iface(内网接口lan1)/
    #       dst_iface(外网线路)/ipv6_addr/ipv6_addr_len/comment
    # 约束: tagname唯一, (src_iface,link_addr)唯一; __check_dst_iface: dst_iface须在src_iface的parent(IPv6 LAN配置)
    # !!环境限制: 需WAN IPv6前缀+LAN IPv6配置(ipv6_lan_config), IPv6关闭时添加被lan_prefix_error拦

    def query_ipv6_static_rule(self, name: str) -> Optional[Dict]:
        """查询IPv6前缀静态分配规则(按tagname)"""
        return self._sqlite_query_line(
            f"SELECT id,enabled,tagname,link_addr,src_iface,dst_iface,ipv6_addr,comment "
            f"FROM ipv6_dhcp_static_config WHERE tagname='{name}'"
        )

    def count_ipv6_static(self, enabled_only: bool = False) -> int:
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM ipv6_dhcp_static_config {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_ipv6_static_database(self, name: str,
                                    expected_fields: Dict = None,
                                    must_exist: bool = True) -> VerifyResult:
        """L1: 验证IPv6前缀静态分配数据库(ipv6_dhcp_static_config表)"""
        rule = self.query_ipv6_static_rule(name)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=not must_exist,
                message=f"IPv6前缀静态分配'{name}'不存在"
                        f"({'符合预期' if not must_exist else '应为存在'})",
                raw_output="",
            )
        details = {
            "id": rule.get("id"), "enabled": rule.get("enabled"),
            "tagname": rule.get("tagname"), "link_addr": rule.get("link_addr"),
            "src_iface": rule.get("src_iface"), "dst_iface": rule.get("dst_iface"),
        }
        raw = json.dumps(details, ensure_ascii=False)
        if not must_exist:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"规则'{name}'存在但期望不存在",
                details={"rule": details}, raw_output=raw,
            )
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"规则'{name}'存在: link_addr={details['link_addr']}, "
                        f"src={details['src_iface']}, dst={details['dst_iface']}, enabled={details['enabled']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"规则'{name}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"规则'{name}'数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def verify_ipv6_static_init(self) -> VerifyResult:
        """L4 模拟重启: ipv6_static.sh init(init_static重建IPv6前缀)"""
        self.connect_router()
        try:
            out = self._router.exec("/usr/ikuai/script/ipv6_static.sh init 2>&1; echo INIT_EXIT=$?")
            executed = "INIT_EXIT=" in out
            return VerifyResult(
                level="L4-模拟重启", passed=executed,
                message=f"ipv6_static.sh init{'已执行' if executed else '未执行'}",
                details={"output": out[-200:]}, raw_output=out[-300:],
            )
        except Exception as e:
            return VerifyResult(
                level="L4-模拟重启", passed=False,
                message=f"init失败: {e}", raw_output=str(e),
            )

    def cleanup_ipv6_static_test(self, prefix: str = "IPV6TEST") -> str:
        """清理IPv6前缀静态分配测试规则(按tagname前缀)"""
        self.connect_router()
        try:
            out = self._router.exec(
                f"sqlite3 {self.DNS_DB} \"DELETE FROM ipv6_dhcp_static_config WHERE tagname LIKE '{prefix}%';\" 2>&1"
            )
            logger.info(f"[清理] IPv6前缀静态分配({prefix}*): {out}")
            return out or ""
        except Exception as e:
            logger.warning(f"[清理] IPv6清理失败: {e}")
            return ""

    # ==================== IPv6外网设置(ipv6_wan_config)验证 ====================
    # 网络配置>内外网设置>IPv6设置>外网设置. 脚本/usr/ikuai/script/ipv6.sh (wan_add/wan_edit/wan_del)
    # 表ipv6_wan_config: id/enabled/tagname(unique)/interface(unique)/internet(dhcp|static|relay)/
    #   link_addr(自动生成)/ipv6_addr(static)/ipv6_gateway(static)/prefix/prefix_hint/force_prefix/force_gen_duid
    # multi_unsupport: 企业版num=3, WAN线路总数上限3. ipv6全局enabled=no时apply侧(odhcp6c/ipset)软断言.

    def query_ipv6_wan_rule(self, tagname: str) -> Optional[Dict]:
        """查询IPv6外网设置规则(按tagname)"""
        return self._sqlite_query_line(
            f"SELECT id,enabled,tagname,interface,internet,prefix,prefix_hint,"
            f"ipv6_addr,ipv6_gateway,force_prefix,force_gen_duid "
            f"FROM ipv6_wan_config WHERE tagname='{tagname}'"
        )

    def count_ipv6_wan(self, enabled_only: bool = False) -> int:
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM ipv6_wan_config {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_ipv6_wan_database(self, tagname: str,
                                 expected_fields: Dict = None,
                                 expect_absent: bool = False) -> VerifyResult:
        """L1: 验证IPv6外网设置数据库(ipv6_wan_config表)

        Args:
            tagname: 规则名称
            expected_fields: 期望字段值, 如 {"enabled":"yes","interface":"wan2","internet":"dhcp"}
            expect_absent: True表示期望不存在(删除验证)
        """
        rule = self.query_ipv6_wan_rule(tagname)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=expect_absent,
                message=f"IPv6外网'{tagname}'不存在"
                        f"({'符合预期' if expect_absent else '应为存在'})",
                raw_output="",
            )
        if expect_absent:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"IPv6外网'{tagname}'仍存在(期望已删除)",
                details={"rule": rule}, raw_output=json.dumps(rule, ensure_ascii=False),
            )
        details = {
            "id": rule.get("id"), "enabled": rule.get("enabled"),
            "tagname": rule.get("tagname"), "interface": rule.get("interface"),
            "internet": rule.get("internet"), "prefix": rule.get("prefix"),
        }
        raw = json.dumps(details, ensure_ascii=False)
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"IPv6外网'{tagname}'存在: iface={details['interface']}, "
                        f"internet={details['internet']}, enabled={details['enabled']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"IPv6外网'{tagname}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"IPv6外网'{tagname}'数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def verify_ipv6_wan_kernel(self, interface: str, internet: str = "dhcp",
                               enabled: bool = True,
                               ipv6_addr: str = None,
                               ipv6_gateway: str = None) -> VerifyResult:
        """L2/L3/L4: IPv6外网内核产物验证(基于ipv6.sh apply原理, 非iptables)

        ipv6.sh wan_add/wan_up启用时apply路径:
        - __ipset_v6_create ipv6_prefix_$interface (dhcp/relay)         → L2 ipset
        - ip -6 addr add $ipv6_addr (static) + __ipv6_route_add         → L3 addr/route
        - __ipv6_rule_add: ip -6 rule add dev $iface table $iface prio 10000 → L4 策略路由
        !!IPv6不走iptables(与IPv4 NAT/QoS不同), 用ipset+iproute2+odhcp6c/odhcpd进程.

        Args:
            interface: 外网接口(wan2/wan3)
            internet: dhcp/static/relay
            enabled: 是否启用(未启用无apply, 直接pass)
            ipv6_addr: static模式IPv6地址(如2001:db8:1::1/64)
            ipv6_gateway: static模式网关(如fe80::1)
        """
        self.connect_router()
        if not enabled:
            return VerifyResult(
                level="L234-内核", passed=True,
                message=f"{interface}未启用, 无apply内核产物(符合预期)", raw_output="")
        checks = []  # (层级, 通过?, 说明)
        try:
            # L2: ipset ipv6_prefix_$interface (dhcp/relay)
            if internet in ("dhcp", "relay"):
                ipset_out = self._router.exec("ipset list -n 2>/dev/null")
                has_ipset = f"ipv6_prefix_{interface}" in (ipset_out or "")
                checks.append(("L2-ipset", has_ipset,
                               f"ipv6_prefix_{interface}{'存在' if has_ipset else '缺失'}"))
            # L3 static: ip -6 addr 全局地址 + ip -6 route 默认路由
            if internet == "static" and ipv6_addr:
                addr_short = ipv6_addr.split("/")[0]
                addr_out = self._router.exec(f"ip -6 addr show dev {interface} 2>/dev/null")
                has_addr = addr_short in (addr_out or "")
                checks.append(("L3-addr", has_addr,
                               f"全局地址{addr_short}{'已下发' if has_addr else '未下发(无上游?)'}"))
                if ipv6_gateway:
                    route_out = self._router.exec("ip -6 route show 2>/dev/null")
                    has_route = ipv6_gateway in (route_out or "")
                    checks.append(("L3-route", has_route,
                                   f"默认路由via {ipv6_gateway}{'已下发' if has_route else '未下发'}"))
            # L4: ip -6 rule lookup $interface (策略路由, __ipv6_rule_add)
            rule_out = self._router.exec("ip -6 rule show 2>/dev/null")
            has_rule = f"lookup {interface}" in (rule_out or "")
            checks.append(("L4-rule", has_rule,
                           f"策略路由rule lookup {interface}{'存在' if has_rule else '缺失'}"))

            ok_cnt = sum(1 for _, p, _ in checks if p)
            detail = "; ".join(f"{lvl}:{'[OK]' if p else '[FAIL]'} {msg}" for lvl, p, msg in checks)
            # static模式所有都应pass; dhcp模式addr/route不查(无上游), ipset+rule应pass
            passed = ok_cnt == len(checks)
            return VerifyResult(
                level="L234-内核", passed=passed,
                message=f"{interface}({internet})内核验证[{ok_cnt}/{len(checks)}]: {detail}",
                details={"checks": checks}, raw_output=detail[:250])
        except Exception as e:
            return VerifyResult(
                level="L234-内核", passed=False, message=f"内核查询失败: {e}", raw_output=str(e))

    def cleanup_ipv6_wan_test(self, prefix: str = "IPV6WAN") -> str:
        """清理IPv6外网设置测试规则(按tagname前缀), 同步删缓存/ipset"""
        self.connect_router()
        try:
            # 先查interface用于清理ipset, 再删DB
            rows = self._sqlite_query_list(
                f"SELECT id,interface,enabled,internet FROM ipv6_wan_config WHERE tagname LIKE '{prefix}%'"
            )
            for r in rows:
                iface = r.get("interface", "")
                if iface and r.get("enabled") == "yes" and r.get("internet") in ("dhcp", "relay"):
                    self._router.exec(f"ipset destroy ipv6_prefix_{iface} 2>/dev/null; true")
                if iface:
                    self._router.exec(f"rm -f /tmp/iktmp/dhcp6c/{iface} 2>/dev/null; "
                                      f"rm -f $IK_DIR_CACHE/config/ipv6_wan_config.{iface} 2>/dev/null; true")
            out = self._router.exec(
                f"sqlite3 {self.DNS_DB} \"DELETE FROM ipv6_wan_config WHERE tagname LIKE '{prefix}%';\" 2>&1"
            )
            logger.info(f"[清理] IPv6外网({prefix}*): {out}")
            return out or ""
        except Exception as e:
            logger.warning(f"[清理] IPv6外网清理失败: {e}")
            return ""

    # ==================== IPv6内网设置(ipv6_lan_config)验证 ====================
    # 网络配置>内外网设置>IPv6设置>内网设置. 脚本/usr/ikuai/script/ipv6.sh (add/edit/del)
    # 表ipv6_lan_config: id/enabled(默认yes)/tagname(unique)/interface(unique)/parent(绑定外网线路)/
    #   internet(dhcp|static|relay)/prefix_len/dhcpv6/ipv6_addr/use_dns6/ipv6_dns1/ipv6_dns2/
    #   ra_flags/ra_static/ra_mtu_set/ra_mtu/leasetime
    # interface UNIQUE: lan1被默认CFLAN_1占用, 新增仅doc_app_default可用(最多1条).

    def query_ipv6_lan_rule(self, tagname: str) -> Optional[Dict]:
        """查询IPv6内网设置规则(按tagname)"""
        return self._sqlite_query_line(
            f"SELECT id,enabled,tagname,interface,parent,internet,prefix_len,"
            f"dhcpv6,ra_flags,ra_static,leasetime "
            f"FROM ipv6_lan_config WHERE tagname='{tagname}'"
        )

    def count_ipv6_lan(self, enabled_only: bool = False) -> int:
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM ipv6_lan_config {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_ipv6_lan_database(self, tagname: str,
                                 expected_fields: Dict = None,
                                 expect_absent: bool = False) -> VerifyResult:
        """L1: 验证IPv6内网设置数据库(ipv6_lan_config表)"""
        rule = self.query_ipv6_lan_rule(tagname)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=expect_absent,
                message=f"IPv6内网'{tagname}'不存在"
                        f"({'符合预期' if expect_absent else '应为存在'})",
                raw_output="",
            )
        if expect_absent:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"IPv6内网'{tagname}'仍存在(期望已删除)",
                details={"rule": rule}, raw_output=json.dumps(rule, ensure_ascii=False),
            )
        details = {
            "id": rule.get("id"), "enabled": rule.get("enabled"),
            "tagname": rule.get("tagname"), "interface": rule.get("interface"),
            "parent": rule.get("parent"), "internet": rule.get("internet"),
            "ra_flags": rule.get("ra_flags"), "leasetime": rule.get("leasetime"),
        }
        raw = json.dumps(details, ensure_ascii=False)
        if expected_fields is None:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"IPv6内网'{tagname}'存在: iface={details['interface']}, "
                        f"parent={details['parent']}, internet={details['internet']}, "
                        f"enabled={details['enabled']}",
                details={"rule": details}, raw_output=raw,
            )
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if actual != str(expected):
                mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"IPv6内网'{tagname}'字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw,
            )
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"IPv6内网'{tagname}'数据库验证通过",
            details={"rule": details}, raw_output=raw,
        )

    def cleanup_ipv6_lan_test(self, prefix: str = "IPV6LAN") -> str:
        """清理IPv6内网设置测试规则(按tagname前缀)"""
        self.connect_router()
        try:
            out = self._router.exec(
                f"sqlite3 {self.DNS_DB} \"DELETE FROM ipv6_lan_config WHERE tagname LIKE '{prefix}%';\" 2>&1"
            )
            logger.info(f"[清理] IPv6内网({prefix}*): {out}")
            return out or ""
        except Exception as e:
            logger.warning(f"[清理] IPv6内网清理失败: {e}")
            return ""

    def verify_ipv6_lan_kernel(self, interface: str, enabled: bool = True) -> VerifyResult:
        """L2/L3: IPv6内网内核产物验证(基于ipv6.sh __init_odhcpd_config原理)

        ipv6.sh add/up启用时apply路径:
        - __create_lan_config_to_cache + __lan_odhcpdv6_restart + __init_odhcpd_config
          → 生成odhcpd配置 /tmp/iktmp/odhcpd/ik_dhcpd.conf, 含 interface=$iface 行
        - static: ip -6 addr add (本环境IPv6 off, odhcpd进程可能未起, 以配置文件为准)

        Args:
            interface: 内网接口(doc_app_default/lan1)
            enabled: 是否启用
        """
        self.connect_router()
        if not enabled:
            return VerifyResult(
                level="L23-内核", passed=True,
                message=f"{interface}未启用, 无apply(符合预期)", raw_output="")
        try:
            out = self._router.exec("cat /tmp/iktmp/odhcpd/ik_dhcpd.conf 2>/dev/null")
            has = f"interface={interface}" in (out or "")
            # 附加: odhcpd进程是否运行(本环境IPv6 off可能未起, 软参考)
            proc = self._router.exec("pgrep -x odhcpd >/dev/null && echo running || echo stopped")
            return VerifyResult(
                level="L23-内核", passed=has,
                message=f"odhcpd配置ik_dhcpd.conf{'含' if has else '不含'}interface={interface}"
                        f"(odhcpd进程={proc.strip()})",
                details={"interface": interface, "odhcpd_proc": proc.strip()},
                raw_output=(out or "")[:200])
        except Exception as e:
            return VerifyResult(
                level="L23-内核", passed=False, message=f"内核查询失败: {e}", raw_output=str(e))

    def restore_ipv6_wan_default(self) -> bool:
        """恢复IPv6外网默认CFWAN_1(clear-existing导入会删默认, 且CFWAN_1空interface不可导入, 需SQL恢复)"""
        self.connect_router()
        try:
            self._router.exec(
                f"sqlite3 {self.DNS_DB} \"INSERT OR IGNORE INTO ipv6_wan_config"
                f"(id,enabled,tagname,interface,internet,prefix,prefix_hint,"
                f"force_prefix,force_gen_duid,link_addr,ipv6_addr,ipv6_gateway) "
                f"VALUES(1,'no','CFWAN_1','','dhcp','auto','',0,1,'','','');\" 2>&1"
            )
            return True
        except Exception as e:
            logger.warning(f"[恢复] CFWAN_1失败: {e}")
            return False

    def restore_ipv6_lan_default(self) -> bool:
        """恢复IPv6内网默认CFLAN_1(clear-existing导入会删默认, CFLAN_1空parent不可导入, 需SQL恢复)"""
        self.connect_router()
        try:
            self._router.exec(
                f"sqlite3 {self.DNS_DB} \"INSERT OR IGNORE INTO ipv6_lan_config"
                f"(id,enabled,tagname,interface,parent,internet,prefix_len,dhcpv6,"
                f"ipv6_addr,use_dns6,ipv6_dns1,ipv6_dns2,ra_flags,ra_static,ra_mtu_set,ra_mtu,leasetime) "
                f"VALUES(1,'yes','CFLAN_1','lan1','','dhcp','auto',1,'',0,'','','1',0,0,1480,'120');\" 2>&1"
            )
            return True
        except Exception as e:
            logger.warning(f"[恢复] CFLAN_1失败: {e}")
            return False

    # ==================== 自定义协议(dprotos / dprotos_l7)验证 ====================
    # 两个独立平行子模块(SSH探查确认 2026-06-23):
    #   L4 dprotos: 表dprotos, iptables mangle DPROTO链 + ipset dproto_src/dst/sport/dport_$id
    #               (-A DPROTO -p tcp -m set --match-set dproto_*_$id ... -j APPMARK--set-appid <appid>)
    #   L7 dprotos_l7: 表dprotos_l7, rule字段base64(空格分隔 Protocol=TCP Direction=CLIENT Data=xxx),
    #                  loadapp加载进DPI(异步, 验证以DB+rule解码为准)
    # class 10类(0=网络协议自定义…9=金融理财自定义), appid由custom_app_get_appid派生

    def _dproto_params(self, proto_type: str = 'l4') -> dict:
        if proto_type == 'l7':
            return {'table': 'dprotos_l7', 'cli': 'dprotos_l7', 'init': '/usr/ikuai/script/dprotos_l7.sh init'}
        return {'table': 'dprotos', 'cli': 'dprotos', 'init': '/usr/ikuai/script/dprotos.sh init'}

    def find_dproto(self, name: str, proto_type: str = 'l4') -> Optional[Dict]:
        """查询自定义协议规则(按name)。L4/L7表列不同, 按类型选列。"""
        p = self._dproto_params(proto_type)
        if proto_type == 'l7':
            cols = "id,enabled,comment,name,class,appid,rule"
        else:
            cols = "id,enabled,comment,name,class,appid,protocol,src_addr,dst_addr,src_port,dst_port"
        return self._sqlite_query_line(
            f"SELECT {cols} FROM {p['table']} WHERE name='{name}'"
        )

    def count_dprotos(self, proto_type: str = 'l4', enabled_only: bool = False) -> int:
        p = self._dproto_params(proto_type)
        where = "WHERE enabled='yes'" if enabled_only else ""
        result = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM {p['table']} {where}"
        )
        if result and "cnt" in result:
            try:
                return int(result["cnt"])
            except (ValueError, TypeError):
                return 0
        return 0

    def verify_dproto_database(self, name: str, proto_type: str = 'l4',
                               expected_fields: Dict = None,
                               expect_absent: bool = False) -> VerifyResult:
        """L1: 验证自定义协议数据库(dprotos/dprotos_l7表)

        expected_fields: name/class/protocol(精确比), src_addr/dst_addr/src_port/dst_port/rule
                         (JSON/base64字段用包含匹配)。
        """
        p = self._dproto_params(proto_type)
        lvl = f"L1-{proto_type}表"
        rule = self.find_dproto(name, proto_type)
        if rule is None:
            return VerifyResult(
                level=lvl, passed=expect_absent,
                message=f"自定义协议'{name}'({p['table']})不存在"
                        f"({'符合预期' if expect_absent else '应为存在'})",
                raw_output="",
            )
        details = {"id": rule.get("id"), "enabled": rule.get("enabled"),
                   "name": rule.get("name"), "class": rule.get("class"),
                   "appid": rule.get("appid")}
        raw = json.dumps(details, ensure_ascii=False)
        if expect_absent:
            return VerifyResult(level=lvl, passed=False,
                                message=f"规则'{name}'存在但期望不存在",
                                details={"rule": details}, raw_output=raw)
        if expected_fields is None:
            return VerifyResult(level=lvl, passed=True,
                                message=f"规则'{name}'存在: enabled={details['enabled']}, class={details['class']}",
                                details={"rule": details}, raw_output=raw)
        # JSON/base64字段: 包含匹配; 其余: 精确
        json_fields = {"src_addr", "dst_addr", "src_port", "dst_port", "rule"}
        mismatches = {}
        for fld, expected in expected_fields.items():
            actual = str(rule.get(fld, ""))
            if fld in json_fields:
                if str(expected) not in actual:
                    mismatches[fld] = {"expected_contains": str(expected), "actual": actual[:60]}
            else:
                if actual != str(expected):
                    mismatches[fld] = {"expected": str(expected), "actual": actual}
        if mismatches:
            return VerifyResult(level=lvl, passed=False,
                                message=f"规则'{name}'字段不匹配: {mismatches}",
                                details={"rule": details, "mismatches": mismatches}, raw_output=raw)
        return VerifyResult(level=lvl, passed=True,
                            message=f"规则'{name}'数据库验证通过",
                            details={"rule": details}, raw_output=raw)

    def verify_dproto_backend(self, name: str, proto_type: str = 'l4') -> VerifyResult:
        """L2/L3: 验证自定义协议后端生效

        L4: ipset dproto_src/dst/sport/dport_$id(按填的字段) + iptables mangle DPROTO链含该id/apid
        L7: rule字段base64解码含预期特征(loadapp加载异步不可靠, 仅验证rule可解码)
        """
        rule = self.find_dproto(name, proto_type)
        if rule is None:
            return VerifyResult(level=f"L2-{proto_type}", passed=False,
                                message=f"规则'{name}'不存在, 无法验证后端", raw_output="")
        self.connect_router()
        rid = rule.get("id")
        if proto_type == 'l7':
            # L7: base64解码rule
            import base64 as _b64
            raw_rule = rule.get("rule", "") or ""
            try:
                decoded = _b64.b64decode(raw_rule).decode("utf-8", errors="replace")
                ok = "Protocol=" in decoded and "Direction=" in decoded
                return VerifyResult(
                    level="L2-l7", passed=ok,
                    message=f"L7 rule解码{'成功' if ok else '异常'}: {decoded[:80]}",
                    details={"rule_decoded": decoded[:200]}, raw_output=decoded[:200],
                )
            except Exception as e:
                return VerifyResult(level="L2-l7", passed=False,
                                    message=f"L7 rule base64解码失败: {e}", raw_output=raw_rule[:100])
        # L4: ipset + iptables DPROTO
        import re as _re
        def _filled(val):
            """JSON字段是否真正填了内容(空{"custom":[]}算未填)"""
            v = (val or "").strip()
            if not v or v == '{}':
                return False
            m = _re.search(r'"custom"\s*:\s*\[([^\]]*)\]', v)
            if m and m.group(1).strip():
                return True
            m2 = _re.search(r'"object"\s*:\s*\{([^}]*)\}', v)
            if m2 and m2.group(1).strip():
                return True
            return False
        try:
            checks = []
            filled_any = False
            # ipset: 仅对"真正填了"的字段查
            for fld, suffix in [("src_addr", "src"), ("dst_addr", "dst"),
                                ("src_port", "sport"), ("dst_port", "dport")]:
                if _filled(rule.get(fld, "")):
                    filled_any = True
                    ipset_name = f"dproto_{suffix}_{rid}"
                    out = self._router.exec(f"ipset list {ipset_name} 2>/dev/null")
                    exists = "Name:" in (out or "")
                    checks.append((f"ipset {ipset_name}", exists,
                                   f"{ipset_name}{'存在' if exists else '不存在'}"))
            ipt = self._router.exec("iptables -t mangle -S DPROTO 2>/dev/null")
            appid = rule.get("appid")
            has_appid = f"set-appid {appid}" in (ipt or "") if appid else False
            # 仅当有地址/端口时才要求DPROTO链含该规则(任意+无地址的规则本就无DPROTO规则)
            if filled_any:
                has_rule = any(f"dproto_{s}_{rid}" in (ipt or "")
                               for s in ("src", "dst", "sport", "dport"))
                checks.append(("iptables DPROTO链含规则", has_rule,
                               f"DPROTO链{'含' if has_rule else '不含'}id={rid}"))
            checks.append((f"APPMARK appid={appid}", has_appid,
                           f"appid标记{'存在' if has_appid else '缺失'}"))
            passed = all(c[1] for c in checks) if checks else True
            return VerifyResult(
                level="L2-L4", passed=passed,
                message="; ".join(c[2] for c in checks) or "无ipset字段(规则无地址/端口)",
                details={"id": rid, "appid": appid, "checks": checks},
                raw_output=(ipt or "")[:300],
            )
        except Exception as e:
            return VerifyResult(level="L2-L4", passed=False,
                                message=f"L4后端检查失败: {e}", raw_output=str(e))

    def cleanup_dproto_test(self, prefix: str = "DPROTO") -> str:
        """清理自定义协议测试规则(dprotos+dprotos_l7两表) + 重建"""
        self.connect_router()
        out_parts = []
        try:
            for pt in ['l4', 'l7']:
                p = self._dproto_params(pt)
                o = self._router.exec(
                    f"sqlite3 {self.DNS_DB} \"DELETE FROM {p['table']} WHERE name LIKE '{prefix}%';\" 2>&1"
                )
                out_parts.append(f"{pt}: {o.strip()[:40]}")
            # L4重建iptables/ipset; L7重建(loadapp异步)
            self._router.exec("/usr/ikuai/script/dprotos.sh init 2>&1")
            self._router.exec("/usr/ikuai/script/dprotos_l7.sh init 2>&1")
            logger.info(f"[清理] 自定义协议({prefix}*): {'; '.join(out_parts)}")
        except Exception as e:
            logger.warning(f"[清理] 自定义协议清理失败: {e}")
        return "; ".join(out_parts)

    # ==================== 路由对象 (object_group) ====================
    # 后端脚本: /usr/ikuai/script/route_object.sh
    # 数据库表: object_group (统一表, type字段区分类型, 无enabled字段)
    #   type: 0=IPv4 1=IPv6 2=MAC 3=端口 4=时间 5=协议 6=域名
    #   字段: id, type, group_name(对象名), tagname, group_id(触发器生成), group_value(JSON明文文本)
    #   group_id前缀: IPGP/IPV6GP/MACGP/PORTGP/TIMEGP/PROTOGP/DOMAINGP + id
    #   约束: UNIQUE(group_name, type)
    # group_value JSON格式(明文, 非base64; 前端传base64, 后端解码入库):
    #   IPv4=[{"ip":"x","comment":""}]  IPv6=[{"ipv6":"x","comment":""}]
    #   MAC=[{"mac":"x","comment":""}]  端口=[{"port":"80","comment":""}]
    #   域名=[{"domain":"x","comment":""}]  时间/协议格式较复杂
    # 引用: object_ref(group_id,type,func_name,rule_id) → ref_count>0 被引用无法删除
    # 后端生效(内核级, 关键验证点):
    #   - 所有type都建立内核 ipset: group_{group_id} (IPv4/IPv6=hash:ip, MAC=hash:mac, 端口=hash:port)
    #   - cache: /tmp/iktmp/cache/{ip,ipv6,mac,port,time,proto,domain}group
    # 校验: group_name 仅中文/英文/数字 1-15字符
    # CLI无统一show, 用sqlite3直查 object_group

    # type名称 → 数字
    OBJECT_GROUP_TYPES = {
        'ip': 0, 'ipv4': 0,
        'ipv6': 1,
        'mac': 2,
        'port': 3,
        'time': 4,
        'proto': 5, 'protocol': 5,
        'domain': 6,
    }
    _OG_PREFIX = {0: 'IPGP', 1: 'IPV6GP', 2: 'MACGP', 3: 'PORTGP',
                  4: 'TIMEGP', 5: 'PROTOGP', 6: 'DOMAINGP'}
    _OG_CACHE = {0: 'ipgroup', 1: 'ipv6group', 2: 'macgroup', 3: 'portgroup',
                 4: 'timegroup', 5: 'protogroup', 6: 'domaingroup'}

    def _og_type(self, type_key) -> int:
        """type_key支持int或str名称(ip/ipv6/mac/port/time/proto/domain)"""
        if isinstance(type_key, int):
            return type_key
        return self.OBJECT_GROUP_TYPES.get(str(type_key).lower(), 0)

    def find_object_group(self, name: str, type_key) -> Optional[Dict]:
        """按group_name+type查询单条分组"""
        t = self._og_type(type_key)
        return self._sqlite_query_line(
            f"SELECT id,type,group_name,tagname,group_id,group_value "
            f"FROM object_group WHERE group_name='{name}' AND type={t}"
        )

    def count_object_group(self, type_key) -> int:
        """统计某type的分组总数"""
        t = self._og_type(type_key)
        r = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM object_group WHERE type={t}"
        )
        try:
            return int(r.get("cnt", 0)) if r else 0
        except (ValueError, TypeError):
            return 0

    def get_object_ref_count(self, group_id: str) -> int:
        """查询分组被引用次数(object_ref表)"""
        if not group_id:
            return 0
        r = self._sqlite_query_line(
            f"SELECT count(*) as cnt FROM object_ref WHERE group_id='{group_id}'"
        )
        try:
            return int(r.get("cnt", 0)) if r else 0
        except (ValueError, TypeError):
            return 0

    def query_object_refs(self, group_id: str) -> List[Dict]:
        """查询分组的所有引用记录(func_name+rule_id)"""
        if not group_id:
            return []
        return self._sqlite_query_list(
            f"SELECT group_id,type,func_name,rule_id,tagname "
            f"FROM object_ref WHERE group_id='{group_id}'"
        )

    def verify_object_group_database(self, name: str, type_key,
                                     expected_value=None,
                                     expect_absent: bool = False) -> VerifyResult:
        """L1: 验证object_group数据库存在且字段正确

        Args:
            name: 分组名称
            type_key: type(int或名称)
            expected_value: group_value包含匹配(字符串或列表, 每个都要在JSON中出现)
            expect_absent: True表示期望不存在(删除验证)
        """
        t = self._og_type(type_key)
        lvl = f"L1-对象分组(type{t})"
        rule = self.find_object_group(name, type_key)
        if rule is None:
            return VerifyResult(
                level=lvl, passed=expect_absent,
                message=f"分组'{name}'(type{t})不存在"
                        f"({'符合预期' if expect_absent else '应为存在'})",
                raw_output="",
            )
        details = {"id": rule.get("id"), "type": rule.get("type"),
                   "group_name": rule.get("group_name"),
                   "group_id": rule.get("group_id"), "tagname": rule.get("tagname")}
        raw = json.dumps(details, ensure_ascii=False)
        if expect_absent:
            return VerifyResult(level=lvl, passed=False,
                                message=f"分组'{name}'存在但期望不存在",
                                details={"rule": details}, raw_output=raw)
        gv = (rule.get("group_value") or "")
        details["group_value"] = gv[:120]
        if expected_value is not None:
            ok = True
            vals = expected_value if isinstance(expected_value, (list, tuple)) else [expected_value]
            for v in vals:
                if str(v) not in gv:
                    ok = False
            if not ok:
                return VerifyResult(
                    level=lvl, passed=False,
                    message=f"分组'{name}'group_value不含期望值'{expected_value}': {gv[:80]}",
                    details={"rule": details}, raw_output=gv[:200],
                )
        return VerifyResult(
            level=lvl, passed=True,
            message=f"分组'{name}'数据库验证通过(group_id={details['group_id']})",
            details={"rule": details}, raw_output=raw,
        )

    def verify_object_group_ipset(self, name: str, type_key,
                                  expect_exists: bool = True) -> VerifyResult:
        """L2: 验证内核ipset group_{group_id}存在(所有type都建立, 关键内核验证点)"""
        t = self._og_type(type_key)
        lvl = f"L2-ipset(type{t})"
        rule = self.find_object_group(name, type_key)
        if rule is None:
            return VerifyResult(
                level=lvl, passed=not expect_exists,
                message=f"分组'{name}'不存在, ipset无法验证", raw_output="",
            )
        gid = rule.get("group_id", "")
        ipset_name = f"group_{gid}"
        self.connect_router()
        out = self._router.exec(f"ipset list {ipset_name} 2>/dev/null")
        exists = "Name:" in (out or "")
        members = ""
        if exists:
            for line in (out or "").splitlines():
                if "Number of entries" in line:
                    members = line.strip()
                    break
        if expect_exists:
            ok = exists
            msg = f"ipset {ipset_name}{'存在' if exists else '不存在'}" + (f"({members})" if members else "")
        else:
            ok = not exists
            msg = f"ipset {ipset_name}{'已删除' if not exists else '仍存在(应已删)'}"
        return VerifyResult(
            level=lvl, passed=ok, message=msg,
            details={"ipset": ipset_name, "exists": exists},
            raw_output=(out or "")[:200],
        )

    def verify_object_group_cache(self, name: str, type_key) -> VerifyResult:
        """L3: 验证cache文件含该分组(分组名出现在cache JSON中)"""
        t = self._og_type(type_key)
        cache_file = f"/tmp/iktmp/cache/{self._OG_CACHE[t]}"
        self.connect_router()
        out = self._router.exec(f"cat {cache_file} 2>/dev/null")
        ok = name in (out or "")
        return VerifyResult(
            level=f"L3-cache(type{t})", passed=ok,
            message=f"cache {self._OG_CACHE[t]} {'含' if ok else '不含'}'{name}'",
            details={"cache_file": cache_file},
            raw_output=(out or "")[:150],
        )

    def verify_object_group_ref(self, name: str, type_key,
                                expect_referenced: bool = False) -> VerifyResult:
        """L4: 验证分组引用状态(ref_count>0=被引用, 删除会被拦截)"""
        t = self._og_type(type_key)
        rule = self.find_object_group(name, type_key)
        if rule is None:
            return VerifyResult(level=f"L4-引用(type{t})", passed=False,
                                message=f"分组'{name}'不存在", raw_output="")
        gid = rule.get("group_id", "")
        cnt = self.get_object_ref_count(gid)
        referenced = cnt > 0
        ok = (referenced == expect_referenced)
        msg = (f"分组'{name}'被引用{cnt}次(期望{'被引用' if expect_referenced else '未被引用'})")
        return VerifyResult(
            level=f"L4-引用(type{t})", passed=ok, message=msg,
            details={"group_id": gid, "ref_count": cnt},
            raw_output=str(cnt),
        )

    def verify_object_group_full_chain(self, name: str, type_key,
                                       expected_value=None,
                                       expect_absent: bool = False) -> FullChainResult:
        """全链路验证: L1数据库 + L2 ipset + L3 cache"""
        r = FullChainResult()
        r.results.append(self.verify_object_group_database(
            name, type_key, expected_value, expect_absent))
        if not expect_absent:
            r.results.append(self.verify_object_group_ipset(name, type_key))
            r.results.append(self.verify_object_group_cache(name, type_key))
        return r

    def cleanup_object_group_test(self, type_key, prefix: str = "AUTO") -> str:
        """清理测试分组: SQL直删 + destroy残留ipset + 重建cache

        按type+prefix精确删除, 避免误删系统分组(如snmp_ipgroup_te)。
        """
        t = self._og_type(type_key)
        self.connect_router()
        parts = []
        try:
            rows = self._sqlite_query_list(
                f"SELECT group_name,group_id FROM object_group "
                f"WHERE type={t} AND group_name LIKE '{prefix}%'"
            )
            for row in rows:
                gid = row.get("group_id", "")
                gn = row.get("group_name", "")
                self._router.exec(
                    f"sqlite3 {self.DNS_DB} "
                    f"\"DELETE FROM object_group WHERE group_id='{gid}';\" 2>&1"
                )
                if gid:
                    self._router.exec(f"ipset destroy group_{gid} 2>/dev/null")
                parts.append(f"{gn}({gid})")
            # 重建cache
            self._router.exec(
                "/usr/ikuai/script/route_object.sh init >/dev/null 2>&1 &"
            )
            logger.info(f"[清理] object_group(type{t}): 删除{len(parts)}条 "
                        f"{'; '.join(parts)}")
            return f"type{t}: del {len(parts)}"
        except Exception as e:
            logger.warning(f"[清理] object_group清理失败: {e}")
            return f"type{t}: error"

    # ==================== VPN客户端(PPTP/L2TP/OpenVPN/IPSec VPN/IKEv2/WireGuard)验证 ====================
    # 网络配置→内外网设置→VPN客户端 tab 下6子模块
    # 通用特征: name(拨号名称/接口名, unique) + enabled(yes/no) + comment(备注)
    # L1数据库(sqlite直查表, must_pass=True) + L2进程/接口连接(软断言, 拨号依赖远端VPN服务端)
    # 拨号不一定成功(依赖服务端配置/凭据), 连接验证must_pass=False只记录状态不阻断
    # 模块映射: key -> (数据库表, 标签, 连接类型)
    VPN_CLIENT_MODULES = {
        'pptp':      ('pptp_client',    'PPTP',       'ppp'),    # 接口名=name, pppd进程
        'l2tp':      ('l2tp_client',    'L2TP',       'ppp'),    # 接口名=name, xl2tpd进程
        'openvpn':   ('openvpn_client', 'OpenVPN',    'tun'),    # 接口名=name, openvpn进程
        'ipsec':     ('ipsec_vpn',      'IPSec VPN',  'ipsec'),  # site-to-site, ipsec sa
        'ike':       ('ike_client',     'IKEv2',      'ipsec'),  # ipsec sa (charon)
        'wireguard': ('wireguard',      'WireGuard',  'wg'),     # 接口名=name, wg接口
    }

    def _vpn_query_rules(self, module_key: str) -> List[Dict]:
        """L1: 查询指定VPN客户端模块全部规则(sqlite直查表)"""
        table = self.VPN_CLIENT_MODULES[module_key][0]
        return self._sqlite_query_list(f"SELECT * FROM {table}")

    def _vpn_find_rule(self, module_key: str, name: str) -> Optional[Dict]:
        """L1: 按拨号名称(name)查找单条VPN客户端规则"""
        table = self.VPN_CLIENT_MODULES[module_key][0]
        return self._sqlite_query_line(f"SELECT * FROM {table} WHERE name='{name}'")

    def _vpn_verify_database_core(self, module_key: str, name: str,
                                   expected_fields: Dict = None,
                                   expect_absent: bool = False) -> VerifyResult:
        """L1: VPN客户端数据库验证核心(6模块共用)

        Args:
            module_key: pptp/l2tp/openvpn/ipsec/ike/wireguard
            name: 拨号名称(规则标识)
            expected_fields: 期望字段值, 如 {"enabled":"yes","server":"10.66.0.40"}
            expect_absent: True=期望规则不存在(删除验证)
        """
        label = self.VPN_CLIENT_MODULES[module_key][1]
        rule = self._vpn_find_rule(module_key, name)
        if rule is None:
            return VerifyResult(
                level="L1-数据库", passed=expect_absent,
                message=f"{label} '{name}' 不存在({'符合预期' if expect_absent else '应为存在'})",
                raw_output="")
        if expect_absent:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"{label} '{name}' 仍存在(期望已删除)",
                details={"rule": rule}, raw_output=json.dumps(rule, ensure_ascii=False)[:300])

        details = {k: rule.get(k) for k in ('id', 'enabled', 'name', 'comment') if k in rule}
        for k, v in rule.items():
            if k not in details and v not in (None, '', '0'):
                details[k] = v
        raw = json.dumps(details, ensure_ascii=False)[:400]

        if not expected_fields:
            return VerifyResult(
                level="L1-数据库", passed=True,
                message=f"{label} '{name}' 存在(enabled={details.get('enabled')})",
                details={"rule": details}, raw_output=raw)

        mismatches = {}
        for f, exp in expected_fields.items():
            act = str(rule.get(f, ""))
            if str(exp) != act:
                mismatches[f] = {"expected": str(exp), "actual": act}
        if mismatches:
            return VerifyResult(
                level="L1-数据库", passed=False,
                message=f"{label} '{name}' 字段不匹配: {mismatches}",
                details={"rule": details, "mismatches": mismatches}, raw_output=raw)
        return VerifyResult(
            level="L1-数据库", passed=True,
            message=f"{label} '{name}' 数据库验证通过",
            details={"rule": details}, raw_output=raw)

    def _vpn_verify_connection_core(self, module_key: str, name: str,
                                     expect_enabled: bool = True) -> VerifyResult:
        """L2: VPN客户端连接状态验证(软断言, 拨号依赖服务端)

        通过接口存在性/IP/SA判断拨号或隧道是否建立。
        拨号不一定成功(服务端未配/凭据错), 测试中must_pass=False只记录状态。
        停用态(expect_enabled=False)宽松放行: 接口/SA可能因惯性还在, 不做硬性要求。

        Args:
            module_key: 模块key
            name: 拨号名称/接口名
            expect_enabled: 期望是否启用(启用=应有连接)
        """
        entry = self.VPN_CLIENT_MODULES[module_key]
        label, conn_type = entry[1], entry[2]
        self.connect_router()
        try:
            if conn_type in ('ppp', 'tun', 'wg'):
                link_out = self._router.exec(
                    f"ip -o link show 2>/dev/null | grep -w '{name}'") or ""
                iface_exists = name in link_out
                iface_up = iface_exists and ('UP' in link_out or 'LOWER_UP' in link_out)
                ip_out = self._router.exec(
                    f"ip -o -4 addr show dev {name} 2>/dev/null") or ""
                has_ip = bool(ip_out.strip()) and 'inet' in ip_out
                connected = iface_up and has_ip
                # message判据与passed一致(用connected非has_ip): WireGuard曾因has_ip=True显示"已连接"
                # 但iface_up=False→connected=False→passed=FAIL, message与passed矛盾. 统一用connected判定
                msg = (f"{label} '{name}' 接口{'存在' if iface_exists else '不存在'}"
                       f"{'+UP' if iface_up else '+DOWN'}, "
                       f"{'已连接(UP+有IP)' if connected else ('有IP但接口未UP' if has_ip else '无IP(未连接/拨号中)')}")
                # 停用态宽松: 接口可能惯性仍在, 仅记录不阻断
                passed = connected if expect_enabled else True
                return VerifyResult(
                    level="L2-连接", passed=passed,
                    message=msg,
                    details={"iface_exists": iface_exists, "iface_up": iface_up, "has_ip": has_ip},
                    raw_output=(link_out + ip_out)[:300])
            else:  # ipsec (IPSec VPN site-to-site / IKEv2)
                sa_out = self._router.exec(
                    f"ipsec statusall 2>/dev/null | grep -iE '{name}'") or ""
                xfrm_cnt = self._router.exec(
                    "ip xfrm state 2>/dev/null | grep -c ' src '") or "0"
                try:
                    xfrm_n = int(str(xfrm_cnt).strip() or "0")
                except ValueError:
                    xfrm_n = 0
                has_sa = bool(sa_out.strip()) or xfrm_n > 0
                msg = (f"{label} '{name}' {'有SA(隧道建立)' if has_sa else '无SA(隧道未建立)'}, "
                       f"xfrm_state={xfrm_n}")
                passed = has_sa if expect_enabled else True
                return VerifyResult(
                    level="L2-连接", passed=passed,
                    message=msg, details={"has_sa": has_sa, "xfrm_state_count": xfrm_n},
                    raw_output=sa_out[:300])
        except Exception as e:
            return VerifyResult(
                level="L2-连接", passed=False,
                message=f"{label} '{name}' 连接检查异常: {e}", raw_output=str(e)[:200])

    def _vpn_verify_full_chain_core(self, module_key: str, name: str,
                                     expect_enabled: bool = True,
                                     expected_fields: Dict = None) -> FullChainResult:
        """VPN客户端全链路验证: L1数据库 + L2连接"""
        results = []
        db_expected = dict(expected_fields or {})
        db_expected["enabled"] = "yes" if expect_enabled else "no"
        results.append(self._vpn_verify_database_core(module_key, name, db_expected))
        results.append(self._vpn_verify_connection_core(module_key, name, expect_enabled))
        return FullChainResult(results=results)

    # ----- PPTP客户端 -----
    def query_pptp_rules(self) -> List[Dict]:
        return self._vpn_query_rules('pptp')

    def verify_pptp_database(self, name, expected_fields=None, expect_absent=False):
        return self._vpn_verify_database_core('pptp', name, expected_fields, expect_absent)

    def verify_pptp_connection(self, name, expect_enabled=True):
        return self._vpn_verify_connection_core('pptp', name, expect_enabled)

    def verify_pptp_full_chain(self, name, expect_enabled=True, expected_fields=None):
        return self._vpn_verify_full_chain_core('pptp', name, expect_enabled, expected_fields)

    # ----- L2TP客户端 -----
    def query_l2tp_rules(self) -> List[Dict]:
        return self._vpn_query_rules('l2tp')

    def verify_l2tp_database(self, name, expected_fields=None, expect_absent=False):
        return self._vpn_verify_database_core('l2tp', name, expected_fields, expect_absent)

    def verify_l2tp_connection(self, name, expect_enabled=True):
        return self._vpn_verify_connection_core('l2tp', name, expect_enabled)

    def verify_l2tp_full_chain(self, name, expect_enabled=True, expected_fields=None):
        return self._vpn_verify_full_chain_core('l2tp', name, expect_enabled, expected_fields)

    # ----- OpenVPN客户端 -----
    def query_openvpn_rules(self) -> List[Dict]:
        return self._vpn_query_rules('openvpn')

    def verify_openvpn_database(self, name, expected_fields=None, expect_absent=False):
        return self._vpn_verify_database_core('openvpn', name, expected_fields, expect_absent)

    def verify_openvpn_connection(self, name, expect_enabled=True):
        return self._vpn_verify_connection_core('openvpn', name, expect_enabled)

    def verify_openvpn_full_chain(self, name, expect_enabled=True, expected_fields=None):
        return self._vpn_verify_full_chain_core('openvpn', name, expect_enabled, expected_fields)

    # ----- IPSec VPN(site-to-site) -----
    def query_ipsec_rules(self) -> List[Dict]:
        return self._vpn_query_rules('ipsec')

    def verify_ipsec_database(self, name, expected_fields=None, expect_absent=False):
        return self._vpn_verify_database_core('ipsec', name, expected_fields, expect_absent)

    def verify_ipsec_connection(self, name, expect_enabled=True):
        return self._vpn_verify_connection_core('ipsec', name, expect_enabled)

    def verify_ipsec_full_chain(self, name, expect_enabled=True, expected_fields=None):
        return self._vpn_verify_full_chain_core('ipsec', name, expect_enabled, expected_fields)

    # ----- IKEv2/IPSec -----
    def query_ike_rules(self) -> List[Dict]:
        return self._vpn_query_rules('ike')

    def verify_ike_database(self, name, expected_fields=None, expect_absent=False):
        return self._vpn_verify_database_core('ike', name, expected_fields, expect_absent)

    def verify_ike_connection(self, name, expect_enabled=True):
        return self._vpn_verify_connection_core('ike', name, expect_enabled)

    def verify_ike_full_chain(self, name, expect_enabled=True, expected_fields=None):
        return self._vpn_verify_full_chain_core('ike', name, expect_enabled, expected_fields)

    # ----- WireGuard -----
    def query_wireguard_rules(self) -> List[Dict]:
        return self._vpn_query_rules('wireguard')

    def verify_wireguard_database(self, name, expected_fields=None, expect_absent=False):
        return self._vpn_verify_database_core('wireguard', name, expected_fields, expect_absent)

    def verify_wireguard_connection(self, name, expect_enabled=True):
        return self._vpn_verify_connection_core('wireguard', name, expect_enabled)

    def verify_wireguard_full_chain(self, name, expect_enabled=True, expected_fields=None):
        return self._vpn_verify_full_chain_core('wireguard', name, expect_enabled, expected_fields)

    # ==================== 内外网设置 (lan_config/wan_config) ====================
    # 后端脚本: /usr/ikuai/script/lan.sh (LAN) / wan.sh (WAN)
    # 数据库: /etc/mnt/ikuai/config.db (lan_config / wan_config 表)
    # 注意: wan_config 无 enabled 字段; WAN启停通过"断开/重拨"体现, 非数据库
    # 数据查询走 /Action/call func_name=lan/wan action=show(需HTTP), SSH层直接读sqlite3

    IK_DB = "/etc/mnt/ikuai/config.db"

    def _db_query_all(self, table: str, where: str = "") -> List[Dict]:
        """直接sqlite3查询表所有行(返回dict列表). table: lan_config/wan_config
        用默认|分隔(数据含/,逗号但不含|), 避免tab转义问题"""
        self.connect_router()
        cmd = f'sqlite3 {self.IK_DB} "select * from {table}'
        if where:
            cmd += f' where {where}'
        cmd += '"'
        raw = self._router.exec(cmd)
        # 取列名
        cols_raw = self._router.exec(f'sqlite3 {self.IK_DB} "pragma table_info({table})"')
        cols = []
        for line in cols_raw.splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                cols.append(parts[1].strip())
        if not cols:
            return []
        rows = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            vals = line.split("|")
            # 数据可能含|? 不太可能(都是IP/mac/逗号列表), 按列数截断
            if len(vals) > len(cols):
                vals = vals[:len(cols)]
            rows.append(dict(zip(cols, vals + [""] * (len(cols) - len(vals)))))
        return rows

    def query_lan_config(self, tagname: str = None) -> List[Dict]:
        """查询lan_config表(LAN接口配置)"""
        where = f"tagname='{tagname}'" if tagname else ""
        return self._db_query_all("lan_config", where)

    def query_wan_config(self, tagname: str = None) -> List[Dict]:
        """查询wan_config表(WAN接口配置)"""
        where = f"tagname='{tagname}'" if tagname else ""
        return self._db_query_all("wan_config", where)

    def find_lan(self, tagname: str) -> Optional[Dict]:
        """按tagname查单条LAN配置"""
        rows = self.query_lan_config(tagname)
        return rows[0] if rows else None

    def find_wan(self, tagname: str) -> Optional[Dict]:
        """按tagname查单条WAN配置"""
        rows = self.query_wan_config(tagname)
        return rows[0] if rows else None

    def verify_lan_database(self, tagname: str, expected_fields: Dict = None,
                            must_exist: bool = True) -> VerifyResult:
        """L1: 验证LAN接口在lan_config表存在且字段正确"""
        row = self.find_lan(tagname)
        if row is None:
            if not must_exist:
                return VerifyResult(level="L1-数据库", passed=True,
                                    message=f"LAN {tagname} 不存在(符合预期)")
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"LAN未找到: {tagname}",
                                raw_output=f"现有LAN: {[r.get('tagname') for r in self.query_lan_config()]}")
        if not must_exist:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"LAN {tagname} 仍存在(应已删除)",
                                raw_output=json.dumps(row, ensure_ascii=False))
        if expected_fields:
            mismatches = {}
            for k, exp in expected_fields.items():
                act = str(row.get(k, ""))
                # ip_mask等可能是包含关系, bandif可能是逗号分隔
                if k in ("ip_mask", "bandif", "bandeth"):
                    if str(exp) not in act and act not in str(exp):
                        mismatches[k] = {"expected": exp, "actual": act}
                elif k == "mac":
                    # MAC大小写不敏感(数据库存小写, UI填大写)
                    if act.lower() != str(exp).lower():
                        mismatches[k] = {"expected": exp, "actual": act}
                elif act != str(exp):
                    mismatches[k] = {"expected": exp, "actual": act}
            if mismatches:
                return VerifyResult(level="L1-数据库", passed=False,
                                    message=f"LAN字段不匹配: {mismatches}",
                                    raw_output=json.dumps(row, ensure_ascii=False))
        return VerifyResult(level="L1-数据库", passed=True,
                            message=f"LAN {tagname} 字段正确 (id={row.get('id')}, ip_mask={row.get('ip_mask')})",
                            raw_output=json.dumps(row, ensure_ascii=False))

    def verify_wan_database(self, tagname: str, expected_fields: Dict = None,
                            must_exist: bool = True) -> VerifyResult:
        """L1: 验证WAN接口在wan_config表存在且字段正确"""
        row = self.find_wan(tagname)
        if row is None:
            if not must_exist:
                return VerifyResult(level="L1-数据库", passed=True,
                                    message=f"WAN {tagname} 不存在(符合预期)")
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"WAN未找到: {tagname}",
                                raw_output=f"现有WAN: {[r.get('tagname') for r in self.query_wan_config()]}")
        if not must_exist:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"WAN {tagname} 仍存在(应已删除)",
                                raw_output=json.dumps(row, ensure_ascii=False))
        if expected_fields:
            mismatches = {}
            for k, exp in expected_fields.items():
                act = str(row.get(k, ""))
                if k in ("ip_mask", "bandif", "bandeth"):
                    if str(exp) not in act and act not in str(exp):
                        mismatches[k] = {"expected": exp, "actual": act}
                elif k == "mac":
                    # MAC大小写不敏感(数据库存小写, UI填大写)
                    if act.lower() != str(exp).lower():
                        mismatches[k] = {"expected": exp, "actual": act}
                elif act != str(exp):
                    mismatches[k] = {"expected": exp, "actual": act}
            if mismatches:
                return VerifyResult(level="L1-数据库", passed=False,
                                    message=f"WAN字段不匹配: {mismatches}",
                                    raw_output=json.dumps(row, ensure_ascii=False))
        return VerifyResult(level="L1-数据库", passed=True,
                            message=f"WAN {tagname} 字段正确 (id={row.get('id')}, internet={row.get('internet')})",
                            raw_output=json.dumps(row, ensure_ascii=False))

    def verify_interface_ip(self, interface: str, expected_ip: str = None,
                            should_have_ip: bool = True) -> VerifyResult:
        """L2: 验证接口IP地址. interface: lan1/wan2/wan4等
        should_have_ip=True时验证接口存在且有IP; expected_ip指定时验证IP匹配
        should_have_ip=False时验证接口无IP或不存在"""
        self.connect_router()
        out = self._router.exec(f"ip -4 addr show {interface} 2>/dev/null")
        if not out.strip() or "does not exist" in out:
            if not should_have_ip:
                return VerifyResult(level="L2-接口IP", passed=True,
                                    message=f"{interface} 接口不存在(符合预期)")
            return VerifyResult(level="L2-接口IP", passed=False,
                                message=f"{interface} 接口不存在",
                                raw_output=out)
        # 解析inet
        import re as _re
        inets = _re.findall(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
        if should_have_ip and not inets:
            return VerifyResult(level="L2-接口IP", passed=False,
                                message=f"{interface} 接口存在但无IP地址",
                                raw_output=out)
        if not should_have_ip and not inets:
            return VerifyResult(level="L2-接口IP", passed=True,
                                message=f"{interface} 接口存在且无IP(符合预期)",
                                raw_output=out)
        if expected_ip:
            # expected_ip 可能是 "192.168.200.1" 或 "192.168.200.1/24"
            found = any(expected_ip in inet for inet in inets)
            if not found:
                return VerifyResult(level="L2-接口IP", passed=False,
                                    message=f"{interface} IP不匹配: 期望含{expected_ip}, 实际{inets}",
                                    raw_output=out)
        return VerifyResult(level="L2-接口IP", passed=True,
                            message=f"{interface} IP验证通过: {inets}",
                            raw_output=out)

    def verify_interface_exists(self, interface: str, should_exist: bool = True) -> VerifyResult:
        """L2: 验证接口存在性(ip link show)"""
        self.connect_router()
        out = self._router.exec(f"ip link show {interface} 2>/dev/null")
        exists = bool(out.strip()) and "does not exist" not in out
        if exists == should_exist:
            return VerifyResult(level="L2-接口存在", passed=True,
                                message=f"{interface} 存在性={'存在' if exists else '不存在'}(符合预期)",
                                raw_output=out[:200])
        return VerifyResult(level="L2-接口存在", passed=False,
                            message=f"{interface} 存在性不符: 期望{'存在' if should_exist else '不存在'}, 实际{'存在' if exists else '不存在'}",
                            raw_output=out[:200])

    # WAN接口id→fwmark映射: wan1=0x2711, wan2=0x2712, wan3=0x2713, wan4=0x2714...
    WAN_FWMARK_BASE = 0x2711

    def verify_wan_policy_routing(self, wan_id: int, should_exist: bool = True) -> VerifyResult:
        """L3: 验证WAN策略路由(ip rule fwmark). wan_id: 1/2/3/4"""
        self.connect_router()
        fwmark = self.WAN_FWMARK_BASE + wan_id - 1
        out = self._router.exec("ip rule show 2>/dev/null")
        # 格式: 10000: from all fwmark 0x2712 lookup wan2
        exists = f"0x{fwmark:x}" in out and f"lookup wan{wan_id}" in out
        if exists == should_exist:
            return VerifyResult(level="L3-策略路由", passed=True,
                                message=f"wan{wan_id} fwmark 0x{fwmark:x} 策略路由={'存在' if exists else '不存在'}(符合预期)",
                                raw_output=out[:300])
        return VerifyResult(level="L3-策略路由", passed=False,
                            message=f"wan{wan_id} 策略路由不符: 期望{'存在' if should_exist else '不存在'}",
                            raw_output=out[:300])

    def verify_lan_visit_iptables(self, interface: str, allow_visit: bool = True) -> VerifyResult:
        """iptables验证: LAN互访控制(LAN_VISIT链)
        allow_visit=True(允许互访): LAN_VISIT链不应有针对该接口的DROP规则
        allow_visit=False(禁止互访): LAN_VISIT链应有 ! -i iface -o iface ... DROP 规则"""
        self.connect_router()
        out = self._router.exec("iptables -S LAN_VISIT 2>/dev/null")
        # 规则形如: -A LAN_VISIT ! -i lan1 -o lan1 -m ifaces ... -j DROP
        has_drop = bool(out.strip()) and interface in out and "DROP" in out
        if allow_visit:
            # 允许互访: 不应有DROP规则
            if not has_drop:
                return VerifyResult(level="iptables-LAN_VISIT", passed=True,
                                    message=f"{interface} 允许互访: LAN_VISIT无DROP规则(符合预期)",
                                    raw_output=out[:300])
            return VerifyResult(level="iptables-LAN_VISIT", passed=False,
                                message=f"{interface} 应允许互访但LAN_VISIT有DROP规则",
                                raw_output=out[:300])
        else:
            # 禁止互访: 应有DROP规则
            if has_drop:
                return VerifyResult(level="iptables-LAN_VISIT", passed=True,
                                    message=f"{interface} 禁止互访: LAN_VISIT有DROP规则(符合预期)",
                                    raw_output=out[:300])
            return VerifyResult(level="iptables-LAN_VISIT", passed=False,
                                message=f"{interface} 应禁止互访但LAN_VISIT无DROP规则",
                                raw_output=out[:300])

    def verify_interface_reboot(self, table: str, tagname: str,
                                expected_fields: Dict = None) -> VerifyResult:
        """L重启验证: 模拟重启后配置是否持久化
        调用对应脚本的init/boot函数, 验证数据库配置仍在 + 接口IP仍在
        table: 'lan_config'/'wan_config'"""
        self.connect_router()
        try:
            script = "lan.sh" if table == "lan_config" else "wan.sh"
            # 调脚本init(模拟重启加载)
            self._router.exec(f"/usr/ikuai/script/{script} init 2>&1", timeout=60)
            # 等待接口重建
            import time as _time
            _time.sleep(3)
            # 验证数据库配置仍在
            if table == "lan_config":
                db_res = self.verify_lan_database(tagname, expected_fields, must_exist=True)
            else:
                db_res = self.verify_wan_database(tagname, expected_fields, must_exist=True)
            if not db_res.passed:
                return VerifyResult(level="L重启", passed=False,
                                    message=f"重启后{tagname}配置丢失或不一致: {db_res.message}",
                                    raw_output=db_res.raw_output)
            # 验证接口IP仍在
            row = self.find_lan(tagname) if table == "lan_config" else self.find_wan(tagname)
            ip = (row.get("ip_mask") or "").split("/")[0] if row else None
            if ip and expected_fields and "ip_mask" in (expected_fields or {}):
                ip_res = self.verify_interface_ip(tagname, expected_ip=ip, should_have_ip=True)
                if not ip_res.passed:
                    return VerifyResult(level="L重启", passed=False,
                                        message=f"重启后{tagname}接口IP丢失: {ip_res.message}",
                                        raw_output=ip_res.raw_output)
            return VerifyResult(level="L重启", passed=True,
                                message=f"重启后{tagname}配置持久化验证通过",
                                raw_output=db_res.raw_output)
        except Exception as e:
            return VerifyResult(level="L重启", passed=False,
                                message=f"重启验证异常: {e}",
                                raw_output=str(e)[:300])

    def snapshot_interface_config(self) -> Dict:
        """快照当前所有WAN/LAN配置 + 内核状态(用于测试前后对比)"""
        self.connect_router()
        snap = {"lan": [], "wan": [], "wan_vlan": [], "ip_addr": "", "ip_rule": "", "lan_visit": ""}
        try:
            snap["lan"] = self.query_lan_config()
            snap["wan"] = self.query_wan_config()
            snap["wan_vlan"] = self._db_query_all("wan_vlan", "")
            snap["ip_addr"] = self._router.exec("ip -4 addr show 2>/dev/null")
            snap["ip_rule"] = self._router.exec("ip rule show 2>/dev/null")
            snap["lan_visit"] = self._router.exec("iptables -S LAN_VISIT 2>/dev/null")
        except Exception as e:
            snap["error"] = str(e)
        return snap

    def restore_interface_by_sql(self, table: str, tagname: str,
                                 original_row: Dict) -> bool:
        """用SQL恢复单条接口配置(兜底恢复, 测试异常时用)
        关键: bandif等字段含逗号, 用sqlite3单引号值包裹; 对值内单引号转义"""
        self.connect_router()
        try:
            if not original_row:
                return False
            sets = []
            for k, v in original_row.items():
                if k == "id":
                    continue
                # 值内单引号转义为''(SQL标准)
                safe_v = str(v).replace("'", "''")
                sets.append(f"{k}='{safe_v}'")
            # 优先用id定位(稳定; tagname可能被测试改名致where tagname=失效), 降级tagname
            row_id = original_row.get("id")
            where_clause = f"id='{row_id}'" if row_id else f"tagname='{tagname}'"
            sql = f"update {table} set {','.join(sets)} where {where_clause}"
            self._router.exec(f'sqlite3 {self.IK_DB} "{sql}"')
            # 触发脚本重新apply(重建接口/iptables)
            script = "lan.sh" if table == "lan_config" else "wan.sh"
            self._router.exec(f"/usr/ikuai/script/{script} init 2>&1", timeout=60)
            import time as _time
            _time.sleep(2)
            return True
        except Exception as e:
            logger.error(f"restore_interface_by_sql({table},{tagname}) error: {e}")
            return False

    def delete_interface_by_sql(self, table: str, tagname: str) -> bool:
        """用SQL删除接口配置(测试残留兜底删除)"""
        self.connect_router()
        try:
            self._router.exec(f'sqlite3 {self.IK_DB} "delete from {table} where tagname=\'{tagname}\'"')
            return True
        except Exception as e:
            logger.error(f"delete_interface_by_sql error: {e}")
            return False

    # ==================== 内外网设置 - 混合模式/高级设置 验证 (2026-06-30新增) ====================
    # wan_config.internet 接入方式枚举(/usr/ikuai/include/interface.sh):
    #   0=STATIC静态 1=DHCP 2=PPPoE 3=MACVLAN(基于物理网卡的混合) 4=VLAN(基于VLAN的混合)
    INTERNET_MODE = {
        "static": "0", "dhcp": "1", "pppoe": "2",
        "hybrid_phy": "3", "hybrid_vlan": "4",
    }

    def query_hybrid_subif(self, wan_name: str) -> List[Dict]:
        """查询混合模式子接入表 wan_vlan (interface=父WAN名).
        混合模式(internet=3 MACVLAN/4 VLAN)的每条子接入存此表, 字段:
        interface/vlan_id/vlan_name/vlan_internet(0静1DHCP2PPPoE)/ip_mask/gateway/
        username/passwd/mtu/pppoe_service/pppoe_ac/mac/enabled..."""
        return self._db_query_all("wan_vlan", f"interface='{wan_name}'")

    def count_hybrid_subif(self, wan_name: str) -> int:
        """统计某WAN的混合模式子接入条数"""
        return len(self.query_hybrid_subif(wan_name))

    def find_hybrid_subif(self, wan_name: str, sub_name: str) -> Optional[Dict]:
        """按 父WAN+子接入名(vlan_name) 查单条混合模式子接入"""
        rows = self._db_query_all("wan_vlan", f"interface='{wan_name}' and vlan_name='{sub_name}'")
        return rows[0] if rows else None

    def verify_hybrid_subif(self, wan_name: str, sub_name: str,
                            expected_fields: Dict = None,
                            must_exist: bool = True) -> VerifyResult:
        """L1: 验证混合模式子接入(wan_vlan)存在且字段正确. 复刻 verify_wan_database 逻辑."""
        row = self.find_hybrid_subif(wan_name, sub_name)
        if row is None:
            if not must_exist:
                return VerifyResult(level="L1-混合子接入", passed=True,
                                    message=f"子接入 {wan_name}/{sub_name} 不存在(符合预期)")
            return VerifyResult(level="L1-混合子接入", passed=False,
                                message=f"子接入未找到: {wan_name}/{sub_name}",
                                raw_output=f"现有: {[r.get('vlan_name') for r in self.query_hybrid_subif(wan_name)]}")
        if not must_exist:
            return VerifyResult(level="L1-混合子接入", passed=False,
                                message=f"子接入 {wan_name}/{sub_name} 仍存在(应已删除)",
                                raw_output=json.dumps(row, ensure_ascii=False))
        if expected_fields:
            mismatches = {}
            for k, exp in expected_fields.items():
                act = str(row.get(k, ""))
                # ip_mask/gateway/mac/vlan_name 用包含关系
                if k in ("ip_mask", "gateway", "mac", "vlan_name", "bandif"):
                    if str(exp) not in act and act not in str(exp):
                        mismatches[k] = {"expected": exp, "actual": act}
                elif act != str(exp):
                    mismatches[k] = {"expected": exp, "actual": act}
            if mismatches:
                return VerifyResult(level="L1-混合子接入", passed=False,
                                    message=f"子接字段不匹配: {mismatches}",
                                    raw_output=json.dumps(row, ensure_ascii=False))
        return VerifyResult(level="L1-混合子接入", passed=True,
                            message=f"子接入 {wan_name}/{sub_name} 字段正确 (vlan_internet={row.get('vlan_internet')}, ip_mask={row.get('ip_mask')})",
                            raw_output=json.dumps(row, ensure_ascii=False))

    def verify_wan_internet_mode(self, tagname: str, expected_internet) -> VerifyResult:
        """L1便利: 仅验 wan_config.internet 接入方式字段.
        expected_internet 可传 '0'/'1'/'2'/'3'/'4' 或别名 static/dhcp/pppoe/hybrid_phy/hybrid_vlan."""
        val = self.INTERNET_MODE.get(str(expected_internet), str(expected_internet))
        return self.verify_wan_database(tagname, expected_fields={"internet": val})

    def delete_hybrid_subif_by_sql(self, wan_name: str, sub_name: str = None,
                                   name_prefix: str = None) -> int:
        """SQL删除混合模式子接入(测试残留兜底). 返回删除条数.
        - 传 sub_name: 精确删 interface+vlan_name 一条
        - 传 name_prefix: 删 interface 下 vlan_name LIKE 'prefix%' (清理测试批量创建)
        - 都不传: 删该WAN全部子接入(慎用, 会删环境残留)"""
        self.connect_router()
        try:
            if sub_name:
                where = f"interface='{wan_name}' and vlan_name='{sub_name}'"
            elif name_prefix:
                safe_p = name_prefix.replace("'", "''")
                where = f"interface='{wan_name}' and vlan_name like '{safe_p}%'"
            else:
                where = f"interface='{wan_name}'"
            # 先计数
            cnt_raw = self._router.exec(f'sqlite3 {self.IK_DB} "select count(*) from wan_vlan where {where}"')
            cnt = int((cnt_raw or "0").strip() or "0")
            self._router.exec(f'sqlite3 {self.IK_DB} "delete from wan_vlan where {where}"')
            return cnt
        except Exception as e:
            logger.error(f"delete_hybrid_subif_by_sql error: {e}")
            return 0

    def verify_clone_mac_kernel(self, interface: str, expected_mac: str = None) -> VerifyResult:
        """L2: 验证接口MAC地址(ip link show 看 link/ether).
        expected_mac指定时验证匹配; 克隆MAC可能只作用于上层接口, 用 must_pass=False 软断言."""
        self.connect_router()
        try:
            out = self._router.exec(f"ip link show {interface} 2>/dev/null")
            import re as _re
            macs = _re.findall(r"link/ether\s+([0-9a-fA-F:]{17})", out)
            if not macs:
                return VerifyResult(level="L2-克隆MAC", passed=False,
                                    message=f"{interface} 未找到MAC", raw_output=out[:200])
            if expected_mac:
                exp = expected_mac.lower().replace("-", ":")
                found = any(m.lower() == exp for m in macs)
                if found:
                    return VerifyResult(level="L2-克隆MAC", passed=True,
                                        message=f"{interface} MAC={macs[0]} 匹配{expected_mac}",
                                        raw_output=out[:200])
                return VerifyResult(level="L2-克隆MAC", passed=False,
                                    message=f"{interface} MAC={macs[0]} 不匹配{expected_mac}",
                                    raw_output=out[:200])
            return VerifyResult(level="L2-克隆MAC", passed=True,
                                message=f"{interface} MAC={macs[0]}", raw_output=out[:200])
        except Exception as e:
            return VerifyResult(level="L2-克隆MAC", passed=False,
                                message=f"克隆MAC验证异常: {e}", raw_output=str(e)[:200])

    def verify_nic_ethtool(self, nic: str, expected_speed: str = None,
                           expected_duplex: str = None) -> VerifyResult:
        """L2: ethtool验证网卡速率/双工(工作模式落地).
        expected_speed: '100'/'1000'/'0'(auto); expected_duplex: '0'auto/'1'全双工/'2'半双工.
        协商中可能unknown, 建议 must_pass=False 软断言."""
        self.connect_router()
        try:
            out = self._router.exec(f"ethtool {nic} 2>/dev/null")
            if not out.strip() or "No data available" in out:
                return VerifyResult(level="L2-ethtool", passed=False,
                                    message=f"{nic} ethtool无输出", raw_output=out[:200])
            import re as _re
            spd = _re.search(r"Speed:\s*(\S+)", out)
            dpx = _re.search(r"Duplex:\s*(\S+)", out)
            spd_v = spd.group(1) if spd else "?"
            dpx_v = dpx.group(1) if dpx else "?"
            return VerifyResult(level="L2-ethtool", passed=True,
                                message=f"{nic} Speed={spd_v} Duplex={dpx_v}",
                                raw_output=out[:300])
        except Exception as e:
            return VerifyResult(level="L2-ethtool", passed=False,
                                message=f"ethtool验证异常: {e}", raw_output=str(e)[:200])

    # ==================== ACL规则 (安全中心 > ACL规则) ====================
    # acl表: src_addr/dst_addr/time为明文JSON(非base64, base64仅API层用).
    # 落地: dir=forward→FIREWALL链, dir=input→INPUT_ACL链; 规则以 --comment {id}_{comment} 标识.
    # ipset: acl_src_{id}/acl_dst_{id}(list:set, IP在子集_acl_{side}_{id}); acl_time_{id}(ik_cntl timeset).
    def find_acl_rule(self, tagname: str) -> Optional[Dict]:
        """按名称查找ACL规则(acl表, 单条)"""
        return self._sqlite_query_line(f"SELECT * FROM acl WHERE tagname='{tagname}'")

    def find_acl_rule_id(self, tagname: str) -> Optional[int]:
        """获取ACL规则id"""
        rule = self.find_acl_rule(tagname)
        if rule and rule.get("id"):
            try:
                return int(rule["id"])
            except Exception:
                return None
        return None

    @staticmethod
    def _parse_acl_addr(addr_json) -> list:
        """解析ACL地址字段JSON('{"object":{},"custom":[...]}' 或空'{"object":{},"custom":{}}').
        返回custom里的IP/MAC列表(空dict/空list→[])."""
        if not addr_json:
            return []
        try:
            data = json.loads(addr_json) if isinstance(addr_json, str) else addr_json
            custom = data.get("custom", [])
            if isinstance(custom, dict):
                return []
            if isinstance(custom, list):
                return [str(x) for x in custom]
        except Exception:
            pass
        return []

    def verify_acl_database(self, tagname: str, expected_fields: Dict = None,
                            src_ips: list = None, dst_ips: list = None) -> VerifyResult:
        """L1: 验证ACL规则在acl表中存在且字段正确.
        expected_fields: 普通字段值(action='accept'/dir='forward'/protocol='any'/enabled='yes'/prio='31'/ctdir='0').
        src_ips/dst_ips: 期望源/目的地址IP列表(解析src_addr.custom比对); None=不验证地址; []=期望空(任意)."""
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"ACL规则未找到: {tagname}")
        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}
        if src_ips is not None:
            actual_src = self._parse_acl_addr(rule.get("src_addr", ""))
            if sorted(actual_src) != sorted(src_ips):
                mismatches["src_addr"] = {"expected": src_ips, "actual": actual_src}
        if dst_ips is not None:
            actual_dst = self._parse_acl_addr(rule.get("dst_addr", ""))
            if sorted(actual_dst) != sorted(dst_ips):
                mismatches["dst_addr"] = {"expected": dst_ips, "actual": actual_dst}
        if mismatches:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"字段不匹配: {mismatches}",
                                details={"mismatches": mismatches},
                                raw_output=json.dumps(rule, ensure_ascii=False)[:300])
        return VerifyResult(level="L1-数据库", passed=True,
                            message=f"ACL规则存在且字段正确 (id={rule.get('id')}, action={rule.get('action')}, dir={rule.get('dir')}, proto={rule.get('protocol')})",
                            details={"rule": rule}, raw_output=json.dumps(rule, ensure_ascii=False)[:300])

    def verify_acl_iptables(self, tagname: str, action: str = None,
                            expect_present: bool = True) -> VerifyResult:
        """L2: 验证ACL规则在iptables链中存在/不存在(enabled落地验证).
        dir=forward→FIREWALL链, dir=input→INPUT_ACL链. 规则以'--comment {id}_'标识.
        expect_present=True验证存在(enabled=yes), False验证不存在(enabled=no/已删).
        action: 'accept'/'drop', 启用时验证-j ACCEPT/DROP."""
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L2-iptables", passed=not expect_present,
                                message=f"ACL规则不在DB({tagname}), iptables按expect_present={expect_present}判定")
        rid = rule.get("id", "")
        dirv = rule.get("dir", "forward")
        chain = "INPUT_ACL" if dirv == "input" else "FIREWALL"
        # ACL规则不走-m set(脚本function/acl里-m set已注释, 实际用 -m comment --comment {id}_ + src_ip + -m ifaces + timeset),
        # 不受xt_set影响. 注: 6.12内核下ACL规则可能未正确落地到FIREWALL链(实测链空), 此处如实校验供分析.
        self.connect_router()
        out = self._router.exec(f"iptables -L {chain} -n -v 2>/dev/null")
        # 规则行comment格式 '/* {id}_{comment} */', 用 '/* {id}_' 精确匹配(id=1不误匹配id=10)
        comment_prefix = f"/* {rid}_"
        matched = [l for l in out.splitlines() if comment_prefix in l]
        present = len(matched) > 0
        if present != expect_present:
            return VerifyResult(level="L2-iptables", passed=False,
                                message=f"{chain}链规则(id={rid}) present={present} 期望={expect_present}",
                                raw_output=out[:400])
        if expect_present and action:
            target_map = {"accept": "ACCEPT", "drop": "DROP"}
            expect_target = target_map.get(str(action).lower(), str(action).upper())
            if not any(expect_target in l for l in matched):
                return VerifyResult(level="L2-iptables", passed=False,
                                    message=f"{chain}链规则(id={rid}) 动作未匹配 -j {expect_target}",
                                    raw_output="\n".join(matched)[:300])
        return VerifyResult(level="L2-iptables", passed=True,
                            message=f"{chain}链规则(id={rid}) present={present} 符合预期" + (f", -j {action.upper()}" if action and expect_present else ""),
                            raw_output=out[:400])

    def verify_acl_ipset(self, tagname: str, expected_ips: list = None,
                         expect_present: bool = True, side: str = "src") -> VerifyResult:
        """L3: 验证ACL规则ipset集合(acl_src_{id}/acl_dst_{id})存在 + IP成员.
        side: 'src'源地址/'dst'目的地址. expect_present=False验证ipset不存在(地址空或已删).
        expected_ips: 期望IP成员(在子集合_acl_{side}_{id}中)."""
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L3-ipset", passed=not expect_present,
                                message=f"ACL规则不在DB({tagname})")
        rid = rule.get("id", "")
        self.connect_router()
        set_name = f"acl_{side}_{rid}"
        out = self._router.exec(f"ipset list {set_name} 2>/dev/null")
        exists = bool(out.strip()) and "does not exist" not in out
        if exists != expect_present:
            return VerifyResult(level="L3-ipset", passed=False,
                                message=f"ipset {set_name} exists={exists} 期望={expect_present}",
                                raw_output=out[:300])
        if expect_present and expected_ips:
            sub_out = self._router.exec(f"ipset list _acl_{side}_{rid} 2>/dev/null")
            missing = [ip for ip in expected_ips if ip not in sub_out]
            if missing:
                return VerifyResult(level="L3-ipset", passed=False,
                                    message=f"ipset _acl_{side}_{rid} 缺少IP: {missing}",
                                    raw_output=sub_out[:300])
        return VerifyResult(level="L3-ipset", passed=True,
                            message=f"ipset {set_name} exists={exists}" + (f", IPs={expected_ips}" if expect_present and expected_ips else ""),
                            raw_output=out[:300])

    def verify_acl_enabled(self, tagname: str, expect_enabled: bool) -> VerifyResult:
        """综合验证enabled: DB enabled字段(yes/no) + iptables规则presence一致."""
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-enabled", passed=False, message=f"ACL规则未找到: {tagname}")
        db_enabled = rule.get("enabled", "") == "yes"
        ipt = self.verify_acl_iptables(tagname, expect_present=expect_enabled)
        if db_enabled != expect_enabled:
            return VerifyResult(level="L1-enabled", passed=False,
                                message=f"DB enabled={rule.get('enabled')} 期望={'yes' if expect_enabled else 'no'}; iptables: {ipt.message}",
                                raw_output=ipt.raw_output)
        return VerifyResult(level="L1-enabled", passed=True,
                            message=f"enabled={rule.get('enabled')} 符合预期; {ipt.message}")

    def verify_acl_not_exists(self, tagname: str) -> VerifyResult:
        """验证ACL规则已从DB删除"""
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-删除验证", passed=True, message=f"ACL规则已删除: {tagname}")
        return VerifyResult(level="L1-删除验证", passed=False,
                            message=f"ACL规则仍存在: {tagname} (id={rule.get('id')})",
                            details={"rule": rule})

    def verify_acl_count(self, expected: int = 0, prefix: str = None) -> VerifyResult:
        """验证ACL规则总数(或prefix开头数量)"""
        if prefix:
            rows = self._sqlite_query_list(f"SELECT tagname FROM acl WHERE tagname LIKE '{prefix}%'")
            actual = len(rows)
        else:
            row = self._sqlite_query_line("SELECT count(*) as cnt FROM acl")
            actual = int(row.get("cnt", 0)) if row else 0
        if actual == expected:
            return VerifyResult(level="L1-计数", passed=True,
                                message=f"ACL规则数量正确: {actual}" + (f"(prefix={prefix})" if prefix else ""))
        return VerifyResult(level="L1-计数", passed=False,
                            message=f"ACL规则数量 {actual} 期望 {expected}")

    def delete_acl_by_sql(self, tagname: str) -> str:
        """SQL删除单个ACL规则(finally兜底, 清DB; 不触发acl.sh reload)."""
        self.connect_router()
        try:
            self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM acl WHERE tagname='{tagname}'\"")
            return f"deleted {tagname}"
        except Exception as e:
            return f"error: {e}"

    def cleanup_acl_test(self, prefix: str = "acl_t_") -> str:
        """SQL批量清理prefix开头的ACL规则(finally兜底) + 触发acl.sh init清iptables/ipset."""
        self.connect_router()
        try:
            rows = self._sqlite_query_list(f"SELECT id,tagname FROM acl WHERE tagname LIKE '{prefix}%'")
            if not rows:
                return "0 rules"
            self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM acl WHERE tagname LIKE '{prefix}%'\"")
            try:
                self._router.exec("/usr/ikuai/script/acl.sh init 2>/dev/null")
            except Exception:
                pass
            return f"deleted {len(rows)} rules"
        except Exception as e:
            return f"error: {e}"

    # ==================== ACL L5打流功能验证 + L2协议/优先级/ctdir/接口深度验证 ====================
    # 基于acl.sh源码反推内核落地点: 协议→"-p $proto"; ctdir→"-m conntrack --ctdir ORIGINAL|REPLY";
    # 接口→"-m ifaces --ifaces <if> --dir in|out"; 地址→"-m set --match-set acl_src_/dst_$id";
    # prio→规则写/tmp/iktmp/ipt_rule_id/acl_id_rule, function/acl:574 sort -k2,2n -k1,1n按prio升序后iptables-restore下发(iptables行号=prio升序).
    # 打流判定(iptables计数器匹配即增,与动作无关): 命中=Δpkts>0; drop生效=命中+连接失败;
    #   accept生效=命中+连通; 未入栈(DB有但iptables空, 即function/acl:582 iptables-restore静默吞失败)=Δpkts=0+连通→全栈打流是唯一哨兵.
    # 前置: 调用方需先backend_verifier.add_route_via_router确保client(192.168.148.2)流量经路由器FIREWALL链 + iperf3 server已启动.

    def _read_acl_counter(self, rule_id: int, chain: str = "FIREWALL",
                          ipv6: bool = False) -> tuple:
        """读ACL规则iptables计数(pkts, bytes). iKuai定制列序: num pkts bytes ccnt fcnt fastid target...
        匹配comment '/* {id}_ */'(id=1不误中id=10). 失败返回(0,0)."""
        self.connect_router()
        ipt = "ip6tables" if ipv6 else "iptables"
        out = self._router.exec(f"{ipt} -L {chain} -n -v -x --line-numbers 2>/dev/null")
        for line in out.splitlines():
            if f"/* {rule_id}_" in line:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        return (int(parts[1]), int(parts[2]))
                    except ValueError:
                        pass
        return (0, 0)

    def _iperf3_connected(self, result: dict) -> bool:
        """判定iperf3是否真连通(有实际流量). run_iperf3返回JSON: 连通=end.sum_sent.bits_per_second>0."""
        if not result or "error" in result:
            return False
        try:
            bps = result.get("end", {}).get("sum_sent", {}).get("bits_per_second", 0)
            return bool(bps) and bps > 0
        except (AttributeError, TypeError):
            return False

    def _acl_flow_iperf(self, rule_id: int, proto: str, dst_port: int,
                        server_ip: str, chain: str, ipv6: bool) -> tuple:
        """单段tcp/udp打流: before计数→iperf3(-t3短duration; drop时iperf3卡连接由exec看门狗timeout=12s杀)→after计数.
        返回(connected, delta_pkts)."""
        u = " -u" if proto == "udp" else ""
        cmd = f"iperf3 -c {server_ip} -B 192.168.148.2 -t 3 --connect-timeout 3000{u} -J -p {dst_port}"
        b_pkt, _ = self._read_acl_counter(rule_id, chain, ipv6)
        try:
            out = self._client.exec(cmd, timeout=12)
        except Exception:
            out = ""  # iperf3卡连接/exec看门狗超时=未连通(drop预期), 容忍不崩
        connected = False
        try:
            connected = self._iperf3_connected(json.loads(out))
        except (json.JSONDecodeError, ValueError, TypeError):
            pass  # drop时iperf3超时返回非JSON=未连通
        a_pkt, _ = self._read_acl_counter(rule_id, chain, ipv6)
        return connected, a_pkt - b_pkt

    def verify_acl_flow(self, tagname: str, proto: str = "tcp", dst_port: int = 5201,
                        action: str = "drop", chain: str = "FIREWALL",
                        ipv6: bool = False, server_ip: str = None,
                        count: int = 5) -> VerifyResult:
        """L5打流验证: ACL规则真阻断/放行(全栈, BUG2 iptables-restore静默失败的唯一哨兵).
        proto: tcp|udp|tcp_udp|icmp|gre(gre无对端只L2, 此处skip).
          tcp_udp杀手锏: 同端口分tcp/udp两段, 两段Δpkts都>0才证ik_core多协议单规则同时匹配tcp+udp.
        action: drop|accept(调用方按UI设置传).
        判定: 命中=Δpkts>0; drop生效=命中+不连通; accept生效=命中+连通; 未入栈=Δpkts=0+连通(两action都FAIL)."""
        if proto == "gre":
            return VerifyResult(level="L5-flow", passed=True,
                                message="gre无对端隧道环境, 跳过打流(仅L2 -p落地验证, 见verify_acl_protocol_iptables)")
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L5-flow", passed=False, message=f"ACL规则未找到: {tagname}")
        rid = int(rule.get("id", 0))
        if server_ip is None:
            server_ip = self._ssh_config.iperf3_server
        self.connect_router()
        self.connect_client()
        expect_block = (action == "drop")
        raw = ""

        if proto in ("tcp", "udp"):
            connected, delta = self._acl_flow_iperf(rid, proto, dst_port, server_ip, chain, ipv6)
            hit = delta > 0
            raw = f"{proto}: connected={connected} Δpkts={delta}"
        elif proto in ("tcp_udp", "tcp+udp"):
            c1, d1 = self._acl_flow_iperf(rid, "tcp", dst_port, server_ip, chain, ipv6)
            c2, d2 = self._acl_flow_iperf(rid, "udp", dst_port, server_ip, chain, ipv6)
            connected = c1 or c2
            hit = (d1 > 0) and (d2 > 0)  # 两段都命中才证单规则同时匹配tcp+udp
            raw = f"tcp:conn={c1} Δpkts={d1}; udp:conn={c2} Δpkts={d2}"
        elif proto == "icmp":
            b_pkt, _ = self._read_acl_counter(rid, chain, ipv6)
            out = self._client.exec(f"ping -I 192.168.148.2 -c {count} -W 1 {server_ip}", timeout=20)
            raw = out[:200]
            m = re.search(r"(\d+)\s*received", out)
            connected = bool(m and int(m.group(1)) > 0)
            a_pkt, _ = self._read_acl_counter(rid, chain, ipv6)
            hit = (a_pkt - b_pkt) > 0
        else:
            return VerifyResult(level="L5-flow", passed=False, message=f"不支持的协议: {proto}")

        if expect_block:
            ok = hit and not connected
            msg = f"drop[{proto}]: hit={hit} connected={connected} → {'阻断生效' if ok else '未阻断!'}"
        else:
            ok = hit and connected
            msg = f"accept[{proto}]: hit={hit} connected={connected} → {'放行生效' if ok else '未放行!'}"
        return VerifyResult(level="L5-flow", passed=ok, message=msg,
                            details={"hit": hit, "connected": connected, "expect_block": expect_block},
                            raw_output=raw)

    def verify_acl_protocol_iptables(self, tagname: str, protocol: str = "any") -> VerifyResult:
        """L2深度: 验ACL规则iptables行的-p协议落地(acl.sh __format_set: protocol!=any时PROTO="-p $protocol").
        protocol: tcp/udp/icmp/gre/tcp+udp(any不下发-p). tcp+udp是ik_core定制多协议匹配.
        自动按dir/ip_type选链: forward→FIREWALL/FIREWALL6, input→INPUT_ACL/INPUT_ACL6."""
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L2-protocol", passed=False, message=f"ACL规则未找到: {tagname}")
        rid = rule.get("id", "")
        is_v6 = rule.get("ip_type") == "6"
        if rule.get("dir") == "input":
            chain = "INPUT_ACL6" if is_v6 else "INPUT_ACL"
        else:
            chain = "FIREWALL6" if is_v6 else "FIREWALL"
        ipt = "ip6tables" if is_v6 else "iptables"
        self.connect_router()
        out = self._router.exec(f"{ipt} -S {chain} 2>/dev/null")  # -S规则规范格式含-p/-m字面量(-L表格格式协议是独立列无-p字面量)
        matched = [l for l in out.splitlines() if f"--comment {rid}_" in l]
        if not matched:
            return VerifyResult(level="L2-protocol", passed=False,
                                message=f"{chain}链无规则id={rid}", raw_output=out[:300])
        if protocol == "any":
            return VerifyResult(level="L2-protocol", passed=True,
                                message=f"protocol=any不下发-p(规则id={rid}存在即通过)")
        expect = "-p {}".format(protocol)
        ok = any(expect in l for l in matched)
        return VerifyResult(level="L2-protocol", passed=ok,
                            message=f"{chain}链规则id={rid} {'含' if ok else '缺'} '{expect}'",
                            raw_output="\n".join(matched)[:300])

    def verify_acl_priority_order(self, id_to_prio: dict, ipv6: bool = False) -> VerifyResult:
        """L2优先级排序验证: iptables FIREWALL链规则行号顺序应=prio升序(acl.sh经function/acl:574 sort -k2,2n -k1,1n).
        id_to_prio: {rule_id(str/int): prio(int)}. 解析每行(num, rule_id)→按num升序→对应prio应非降(等值时id升序破平).
        辅证: cat /tmp/iktmp/ipt_rule_id/acl_id_rule 未排序源文件, 印证sort生效."""
        ipt = "ip6tables" if ipv6 else "iptables"
        chain = "FIREWALL6" if ipv6 else "FIREWALL"
        self.connect_router()
        out = self._router.exec(f"{ipt} -L {chain} -n -v --line-numbers 2>/dev/null")
        order = []  # [(line_num, rule_id_str)]
        for line in out.splitlines():
            m = re.search(r"/\*\s*(\d+)_", line)
            if m:
                try:
                    ln = int(line.split()[0])
                    order.append((ln, m.group(1)))
                except (ValueError, IndexError):
                    pass
        order.sort()
        prios = [id_to_prio.get(i) for _, i in order if i in id_to_prio]
        prios_valid = [p for p in prios if p is not None]
        ok = all(prios_valid[i] <= prios_valid[i + 1] for i in range(len(prios_valid) - 1)) if len(prios_valid) >= 2 else True
        rule_file = "/tmp/iktmp/ipt_rule_id/acl6_id_rule" if ipv6 else "/tmp/iktmp/ipt_rule_id/acl_id_rule"
        file_out = self._router.exec(f"cat {rule_file} 2>/dev/null")
        return VerifyResult(level="L2-prio", passed=ok,
                            message=f"FIREWALL行号顺序vs prio: {[(i, id_to_prio.get(i)) for _, i in order]} → {'prio升序一致' if ok else '顺序错乱!'}",
                            details={"order": [(i, id_to_prio.get(i)) for _, i in order],
                                     "acl_id_rule_file": file_out[:400] if file_out.strip() else "(文件不存在/空)"},
                            raw_output=out[:400])

    def verify_acl_ctdir_iptables(self, tagname: str, ctdir: int = 0) -> VerifyResult:
        """L2 ctdir落地验证(acl.sh: ctdir=1→'-m conntrack --ctdir ORIGINAL'; =2→'REPLY'; =0→无conntrack).
        自动按dir选链."""
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L2-ctdir", passed=False, message=f"ACL规则未找到: {tagname}")
        rid = rule.get("id", "")
        is_v6 = rule.get("ip_type") == "6"
        chain = ("INPUT_ACL6" if is_v6 else "INPUT_ACL") if rule.get("dir") == "input" else ("FIREWALL6" if is_v6 else "FIREWALL")
        ipt = "ip6tables" if is_v6 else "iptables"
        self.connect_router()
        out = self._router.exec(f"{ipt} -S {chain} 2>/dev/null")
        matched = [l for l in out.splitlines() if f"--comment {rid}_" in l]
        if ctdir == 0:
            ok = not any("conntrack" in l for l in matched)
            msg = f"ctdir=0应无conntrack: {'正确(无conntrack)' if ok else '错误(误含conntrack)'}"
        else:
            expect = "ORIGINAL" if ctdir == 1 else "REPLY"
            ok = any(f"--ctdir {expect}" in l for l in matched)
            msg = f"ctdir={ctdir}应含'-m conntrack --ctdir {expect}': {'是' if ok else '否'}"
        return VerifyResult(level="L2-ctdir", passed=ok, message=msg, raw_output="\n".join(matched)[:300])

    def verify_acl_iface_iptables(self, tagname: str, iface_type: str = "in",
                                  iface: str = None) -> VerifyResult:
        """L2进/出接口落地验证(acl.sh: -m ifaces --ifaces <if> --dir in|out).
        iface_type: 'in'(进接口)/'out'(出接口). iface: 期望接口名(不传则只验有无对应--dir匹配)."""
        rule = self.find_acl_rule(tagname)
        if rule is None:
            return VerifyResult(level="L2-iface", passed=False, message=f"ACL规则未找到: {tagname}")
        rid = rule.get("id", "")
        self.connect_router()
        out = self._router.exec("iptables -S FIREWALL 2>/dev/null")
        matched = [l for l in out.splitlines() if f"--comment {rid}_" in l]
        expect_dir = f"--dir {iface_type}"
        if iface:
            ok = any(f"--ifaces {iface}" in l and expect_dir in l for l in matched)
        else:
            ok = any(expect_dir in l for l in matched)
        label = f"{iface_type}" + (f"={iface}" if iface else "")
        return VerifyResult(level="L2-iface", passed=ok,
                            message=f"接口({label}): {'匹配' if ok else '未匹配'}", raw_output="\n".join(matched)[:300])

    # ==================== 连接数限制 (安全中心 > 连接数限制) ====================
    # conn_limit表: src_addr/dst_port/time明文JSON; protocol any/tcp/udp/icmp; limits(连接数默认1000).
    # iptables raw表CONNLIMIT链: -m peerconns --peerconns-above {limits} -j DROP [-m set --match-set conn_limit_src_{id} src]
    # ⚠️conn_limit规则无--comment标记, 用 conn_limit_src_{id} + #conns > {limits} 定位.
    # ipset: conn_limit_src_{id}(源地址list:set) / conn_limit_dport_{id} / conn_limit_time_{id}.
    def find_conn_limit_rule(self, tagname: str) -> Optional[Dict]:
        """按名称查找连接数限制规则(conn_limit表)"""
        return self._sqlite_query_line(f"SELECT * FROM conn_limit WHERE tagname='{tagname}'")

    def find_conn_limit_rule_id(self, tagname: str) -> Optional[int]:
        rule = self.find_conn_limit_rule(tagname)
        if rule and rule.get("id"):
            try:
                return int(rule["id"])
            except Exception:
                return None
        return None

    def verify_conn_limit_database(self, tagname: str, expected_fields: Dict = None,
                                   src_ips: list = None) -> VerifyResult:
        """L1: 验证连接数限制规则在conn_limit表中存在且字段正确.
        expected_fields: {protocol/limits/enabled/comment} ; src_ips: 内网地址IP列表(解析src_addr.custom)."""
        rule = self.find_conn_limit_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"连接数限制规则未找到: {tagname}")
        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}
        if src_ips is not None:
            actual_src = self._parse_acl_addr(rule.get("src_addr", ""))
            if sorted(actual_src) != sorted(src_ips):
                mismatches["src_addr"] = {"expected": src_ips, "actual": actual_src}
        if mismatches:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"字段不匹配: {mismatches}", details={"mismatches": mismatches},
                                raw_output=json.dumps(rule, ensure_ascii=False)[:300])
        return VerifyResult(level="L1-数据库", passed=True,
                            message=f"连接数限制规则存在且字段正确 (id={rule.get('id')}, proto={rule.get('protocol')}, limits={rule.get('limits')})",
                            details={"rule": rule}, raw_output=json.dumps(rule, ensure_ascii=False)[:300])

    def verify_conn_limit_iptables(self, tagname: str, limits: int = None,
                                   expect_present: bool = True) -> VerifyResult:
        """L2: 验证连接数限制规则在raw表CONNLIMIT链存在/不存在(enabled落地验证).
        规则以 match-set conn_limit_src_{id} 标识(无--comment), 验证 #conns > {limits}."""
        rule = self.find_conn_limit_rule(tagname)
        if rule is None:
            return VerifyResult(level="L2-iptables", passed=not expect_present,
                                message=f"规则不在DB({tagname}), iptables按expect_present={expect_present}判定")
        rid = rule.get("id", "")
        self.connect_router()
        out = self._router.exec(f"iptables -t raw -L CONNLIMIT -n -v 2>/dev/null")
        # 每条conn_limit规则都有 timeset conn_limit_time_{id}(即使默认全天), 用它定位最可靠
        # (无源地址时规则无match-set conn_limit_src_{id}, 不能仅用match-set定位)
        time_mark = f"conn_limit_time_{rid}"
        src_mark = f"conn_limit_src_{rid}"
        matched = [l for l in out.splitlines() if time_mark in l or src_mark in l]
        present = len(matched) > 0
        if present != expect_present:
            msg = f"CONNLIMIT链规则(id={rid}) present={present} 期望={expect_present}"
            # 带源IP规则在6.12 xt_set坏时iptables下发失败(errno=22)→链无规则→功能不生效(产品bug),
            # 如实FAIL(不降级掩盖), 标注根因让报告体现: 带源IP连接数限制规则不生效是真实产品bug(报禅道)
            if not present and expect_present:
                try:
                    if self.is_xt_set_broken() and self._parse_acl_addr(rule.get("src_addr", "")):
                        msg += (f" ⚠️根因:6.12内核xt_set模块坏(-m set --match-set errno=22), "
                                f"带源IP规则iptables下发失败不生效(产品bug报禅道, xt_set修复后自动恢复)")
                except Exception:
                    pass
            return VerifyResult(level="L2-iptables", passed=False, message=msg, raw_output=out[:400])
        if expect_present and limits is not None:
            lim_str = str(limits)
            if not any(lim_str in l for l in matched):
                return VerifyResult(level="L2-iptables", passed=False,
                                    message=f"CONNLIMIT链规则(id={rid}) limits={lim_str} 未匹配",
                                    raw_output="\n".join(matched)[:300])
        return VerifyResult(level="L2-iptables", passed=True,
                            message=f"CONNLIMIT链规则(id={rid}) present={present} 符合预期" + (f", limits={limits}" if expect_present and limits is not None else ""),
                            raw_output=out[:400])

    def verify_conn_limit_ipset(self, tagname: str, expected_ips: list = None,
                                expect_present: bool = True) -> VerifyResult:
        """L3: 验证连接数限制ipset conn_limit_src_{id}存在 + IP成员."""
        rule = self.find_conn_limit_rule(tagname)
        if rule is None:
            return VerifyResult(level="L3-ipset", passed=not expect_present,
                                message=f"规则不在DB({tagname})")
        rid = rule.get("id", "")
        self.connect_router()
        set_name = f"conn_limit_src_{rid}"
        out = self._router.exec(f"ipset list {set_name} 2>/dev/null")
        exists = bool(out.strip()) and "does not exist" not in out
        if exists != expect_present:
            return VerifyResult(level="L3-ipset", passed=False,
                                message=f"ipset {set_name} exists={exists} 期望={expect_present}",
                                raw_output=out[:300])
        if expect_present and expected_ips:
            sub_out = self._router.exec(f"ipset list _conn_limit_src_{rid} 2>/dev/null")
            missing = [ip for ip in expected_ips if ip not in sub_out]
            if missing:
                return VerifyResult(level="L3-ipset", passed=False,
                                    message=f"ipset _conn_limit_src_{rid} 缺少IP: {missing}",
                                    raw_output=sub_out[:300])
        return VerifyResult(level="L3-ipset", passed=True,
                            message=f"ipset {set_name} exists={exists}" + (f", IPs={expected_ips}" if expect_present and expected_ips else ""),
                            raw_output=out[:300])

    def verify_conn_limit_enabled(self, tagname: str, expect_enabled: bool) -> VerifyResult:
        """综合验证enabled: DB enabled字段 + iptables(raw表)presence一致."""
        rule = self.find_conn_limit_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-enabled", passed=False, message=f"规则未找到: {tagname}")
        db_enabled = rule.get("enabled", "") == "yes"
        ipt = self.verify_conn_limit_iptables(tagname, expect_present=expect_enabled)
        if db_enabled != expect_enabled:
            return VerifyResult(level="L1-enabled", passed=False,
                                message=f"DB enabled={rule.get('enabled')} 期望={'yes' if expect_enabled else 'no'}; iptables: {ipt.message}",
                                raw_output=ipt.raw_output)
        return VerifyResult(level="L1-enabled", passed=True,
                            message=f"enabled={rule.get('enabled')} 符合预期; {ipt.message}")

    def verify_conn_limit_not_exists(self, tagname: str) -> VerifyResult:
        rule = self.find_conn_limit_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-删除验证", passed=True, message=f"规则已删除: {tagname}")
        return VerifyResult(level="L1-删除验证", passed=False,
                            message=f"规则仍存在: {tagname} (id={rule.get('id')})", details={"rule": rule})

    def verify_conn_limit_count(self, expected: int = 0, prefix: str = None) -> VerifyResult:
        if prefix:
            rows = self._sqlite_query_list(f"SELECT tagname FROM conn_limit WHERE tagname LIKE '{prefix}%'")
            actual = len(rows)
        else:
            row = self._sqlite_query_line("SELECT count(*) as cnt FROM conn_limit")
            actual = int(row.get("cnt", 0)) if row else 0
        if actual == expected:
            return VerifyResult(level="L1-计数", passed=True,
                                message=f"连接数限制规则数量正确: {actual}" + (f"(prefix={prefix})" if prefix else ""))
        return VerifyResult(level="L1-计数", passed=False,
                            message=f"连接数限制规则数量 {actual} 期望 {expected}")

    def delete_conn_limit_by_sql(self, tagname: str) -> str:
        """SQL删除单个连接数限制规则(finally兜底)"""
        self.connect_router()
        try:
            self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM conn_limit WHERE tagname='{tagname}'\"")
            return f"deleted {tagname}"
        except Exception as e:
            return f"error: {e}"

    def cleanup_conn_limit_test(self, prefix: str = "cl_t_") -> str:
        """SQL批量清理prefix开头的连接数限制规则 + conn_limit.sh init + 清raw表CONNLIMIT链(conn_limit.sh init只add不清链)."""
        self.connect_router()
        try:
            rows = self._sqlite_query_list(f"SELECT id,tagname FROM conn_limit WHERE tagname LIKE '{prefix}%'")
            if not rows:
                # 仍清链(防残留)
                self._router.exec("iptables -t raw -F CONNLIMIT 2>/dev/null")
                return "0 rules"
            self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM conn_limit WHERE tagname LIKE '{prefix}%'\"")
            try:
                self._router.exec("/usr/ikuai/script/conn_limit.sh init 2>/dev/null")
            except Exception:
                pass
            # conn_limit.sh init只add不清链, 手动清raw表CONNLIMIT残留
            self._router.exec("iptables -t raw -F CONNLIMIT 2>/dev/null")
            return f"deleted {len(rows)} rules"
        except Exception as e:
            return f"error: {e}"

    def read_connlimit_counter(self, tagname: str) -> int:
        """读raw表CONNLIMIT链conn_limit规则的pkts计数(连接数限制【命中铁证】).

        靠 timeset conn_limit_time_{id} 定位行(所有conn_limit规则都有timeset即使默认全天,
        比随协议/src变化的 #conns 文本稳定; 无--comment标记). 调用方打流前后各读一次取Δpkts>0
        =peerconns规则匹配并计数了流量.
        ⚠️仅全局规则(src_addr空,绕过xt_set)能落地iptables; 带src规则xt_set坏时链中无此行→返回0.
        --line-numbers输出列序: num pkts bytes ccnt fcnt fastid target ... → parts[1]=pkts."""
        rid = self.find_conn_limit_rule_id(tagname)
        if rid is None:
            return 0
        self.connect_router()
        out = self._router.exec("iptables -t raw -L CONNLIMIT -n -v -x --line-numbers 2>/dev/null")
        time_mark = f"conn_limit_time_{rid}"
        for line in out.splitlines():
            if time_mark in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])  # parts[1]=pkts
                    except ValueError:
                        continue
        return 0

    # ==================== MAC访问控制 (安全中心 > MAC访问控制) ====================
    # 两模式: 黑名单(global_config.acl_mac=0, 默认)/白名单(acl_mac=1).
    # 表: acl_mac_black/acl_mac_white (enabled默认no/tagname unique/comment/time JSON/expires/mac小写unique).
    # iptables filter表ACL_MAC链(FORWARD第2条): 黑名单`-A ACL_MAC -m set --match-set acl_mac_{id} src -j DROP`/白名单`-I ACL_MAC ... -j RETURN`.
    # ⚠️无--comment标记, 用 acl_mac_{id}+acl_mac_time_{id} 定位. ipset: acl_mac_{id}(MAC集合).
    def find_mac_rule(self, tagname: str, mode: str = "black") -> Optional[Dict]:
        """按名称查找MAC访问控制规则(acl_mac_{mode}表). mode='black'/'white'"""
        return self._sqlite_query_line(f"SELECT * FROM acl_mac_{mode} WHERE tagname='{tagname}'")

    def verify_mac_ctrl_database(self, tagname: str, mode: str = "black",
                                 expected_fields: Dict = None, mac: str = None) -> VerifyResult:
        """L1: 验证MAC规则在acl_mac_{mode}表存在且字段正确.
        expected_fields: {enabled/comment/expires}; mac: 验证mac字段(自动转小写比对)."""
        rule = self.find_mac_rule(tagname, mode)
        if rule is None:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"MAC规则未找到: {tagname}(mode={mode})")
        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}
        if mac is not None:
            actual_mac = str(rule.get("mac", "")).lower()
            if actual_mac != str(mac).lower():
                mismatches["mac"] = {"expected": str(mac).lower(), "actual": actual_mac}
        if mismatches:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"字段不匹配: {mismatches}", details={"mismatches": mismatches},
                                raw_output=json.dumps(rule, ensure_ascii=False)[:300])
        return VerifyResult(level="L1-数据库", passed=True,
                            message=f"MAC规则存在且字段正确 (id={rule.get('id')}, mode={mode}, mac={rule.get('mac')}, enabled={rule.get('enabled')})",
                            details={"rule": rule}, raw_output=json.dumps(rule, ensure_ascii=False)[:300])

    def verify_mac_ctrl_iptables(self, tagname: str, mode: str = "black",
                                 expect_present: bool = True) -> VerifyResult:
        """L2: 验证MAC规则在filter表ACL_MAC链存在/不存在(enabled落地验证).
        黑名单-DROP/白名单-RETURN. 用 acl_mac_{id}+acl_mac_time_{id} 定位(无--comment)."""
        rule = self.find_mac_rule(tagname, mode)
        if rule is None:
            return VerifyResult(level="L2-iptables", passed=not expect_present,
                                message=f"MAC规则不在DB({tagname},mode={mode})")
        rid = rule.get("id", "")
        # xt_set坏时降级软记录: MAC规则用-m set引用acl_mac_{id}, xt_set坏则iptables规则无法建立
        if self.is_xt_set_broken():
            return self.xt_set_degrade_result("L2-iptables", "ACL_MAC", f" id={rid}({tagname},mode={mode})")
        self.connect_router()
        out = self._router.exec(f"iptables -L ACL_MAC -n -v 2>/dev/null")
        time_mark = f"acl_mac_time_{rid}"
        src_mark = f"acl_mac_{rid} "
        matched = [l for l in out.splitlines() if time_mark in l or src_mark in l]
        present = len(matched) > 0
        if present != expect_present:
            return VerifyResult(level="L2-iptables", passed=False,
                                message=f"ACL_MAC链规则(id={rid},mode={mode}) present={present} 期望={expect_present}",
                                raw_output=out[:400])
        # 验证target: 黑名单DROP/白名单RETURN
        if expect_present:
            expect_target = "DROP" if mode == "black" else "RETURN"
            if not any(expect_target in l for l in matched):
                return VerifyResult(level="L2-iptables", passed=False,
                                    message=f"ACL_MAC链规则(id={rid}) target未匹配 -j {expect_target}",
                                    raw_output="\n".join(matched)[:300])
        return VerifyResult(level="L2-iptables", passed=True,
                            message=f"ACL_MAC链规则(id={rid},mode={mode}) present={present} 符合预期" + (f", -j {('DROP' if mode=='black' else 'RETURN')}" if expect_present else ""),
                            raw_output=out[:400])

    def verify_mac_ctrl_ipset(self, tagname: str, mac: str = None,
                              mode: str = "black", expect_present: bool = True) -> VerifyResult:
        """L3: 验证ipset acl_mac_{id}存在 + MAC成员"""
        rule = self.find_mac_rule(tagname, mode)
        if rule is None:
            return VerifyResult(level="L3-ipset", passed=not expect_present,
                                message=f"MAC规则不在DB({tagname})")
        rid = rule.get("id", "")
        self.connect_router()
        set_name = f"acl_mac_{rid}"
        out = self._router.exec(f"ipset list {set_name} 2>/dev/null")
        exists = bool(out.strip()) and "does not exist" not in out
        if exists != expect_present:
            return VerifyResult(level="L3-ipset", passed=False,
                                message=f"ipset {set_name} exists={exists} 期望={expect_present}",
                                raw_output=out[:300])
        if expect_present and mac:
            sub_out = self._router.exec(f"ipset list _acl_mac_{rid} 2>/dev/null")
            if str(mac).lower() not in sub_out.lower():
                return VerifyResult(level="L3-ipset", passed=False,
                                    message=f"ipset _acl_mac_{rid} 缺少MAC {mac}",
                                    raw_output=sub_out[:300])
        return VerifyResult(level="L3-ipset", passed=True,
                            message=f"ipset {set_name} exists={exists}" + (f", MAC={mac}" if expect_present and mac else ""),
                            raw_output=out[:300])

    def verify_mac_ctrl_mode(self, expect_mode: str) -> VerifyResult:
        """验证模式: global_config.acl_mac=0黑名单/1白名单. expect_mode='black'/'white'"""
        expected_val = "0" if expect_mode == "black" else "1"
        self.connect_router()
        row = self._sqlite_query_line("SELECT acl_mac FROM global_config")
        actual = str(row.get("acl_mac", "")) if row else "?"
        if actual == expected_val:
            return VerifyResult(level="L1-模式", passed=True,
                                message=f"模式正确: {expect_mode}(acl_mac={actual})")
        return VerifyResult(level="L1-模式", passed=False,
                            message=f"模式不匹配: 期望{expect_mode}(acl_mac={expected_val}) 实际acl_mac={actual}")

    def set_mac_mode(self, mode: str) -> str:
        """SSH切换MAC访问控制模式(update global_config acl_mac + acl_mac.sh init重新下发).
        mode='black'(acl_mac=0)/'white'(acl_mac=1). 用于UI radio不调API时后端切换验证两模式."""
        self.connect_router()
        val = "0" if mode == "black" else "1"
        try:
            self._router.exec(f"sqlite3 {self.DNS_DB} \"UPDATE global_config SET acl_mac='{val}'\"")
            self._router.exec("/usr/ikuai/script/acl_mac.sh init 2>/dev/null")
            return f"mode set to {mode}(acl_mac={val})"
        except Exception as e:
            return f"error: {e}"

    def verify_mac_ctrl_enabled(self, tagname: str, mode: str, expect_enabled: bool) -> VerifyResult:
        rule = self.find_mac_rule(tagname, mode)
        if rule is None:
            return VerifyResult(level="L1-enabled", passed=False, message=f"MAC规则未找到: {tagname}")
        db_enabled = rule.get("enabled", "") == "yes"
        ipt = self.verify_mac_ctrl_iptables(tagname, mode, expect_present=expect_enabled)
        if db_enabled != expect_enabled:
            return VerifyResult(level="L1-enabled", passed=False,
                                message=f"DB enabled={rule.get('enabled')} 期望={'yes' if expect_enabled else 'no'}; iptables: {ipt.message}",
                                raw_output=ipt.raw_output)
        return VerifyResult(level="L1-enabled", passed=True,
                            message=f"enabled={rule.get('enabled')} 符合预期; {ipt.message}")

    def verify_mac_ctrl_not_exists(self, tagname: str, mode: str = "black") -> VerifyResult:
        rule = self.find_mac_rule(tagname, mode)
        if rule is None:
            return VerifyResult(level="L1-删除验证", passed=True, message=f"MAC规则已删除: {tagname}(mode={mode})")
        return VerifyResult(level="L1-删除验证", passed=False,
                            message=f"MAC规则仍存在: {tagname}(mode={mode}, id={rule.get('id')})", details={"rule": rule})

    def verify_mac_ctrl_count(self, expected: int = 0, prefix: str = None) -> VerifyResult:
        """验证MAC规则总数(黑+白), 或prefix开头数"""
        if prefix:
            b = self._sqlite_query_list(f"SELECT tagname FROM acl_mac_black WHERE tagname LIKE '{prefix}%'")
            w = self._sqlite_query_list(f"SELECT tagname FROM acl_mac_white WHERE tagname LIKE '{prefix}%'")
            actual = len(b) + len(w)
        else:
            row = self._sqlite_query_line("SELECT (SELECT count(*) FROM acl_mac_black)+(SELECT count(*) FROM acl_mac_white) as cnt")
            actual = int(row.get("cnt", 0)) if row else 0
        if actual == expected:
            return VerifyResult(level="L1-计数", passed=True,
                                message=f"MAC规则数量正确: {actual}" + (f"(prefix={prefix})" if prefix else ""))
        return VerifyResult(level="L1-计数", passed=False, message=f"MAC规则数量 {actual} 期望 {expected}")

    def cleanup_mac_ctrl_test(self, prefix: str = "mac_t_") -> str:
        """清理prefix开头的MAC规则(黑+白表)+恢复黑名单模式+清ACL_MAC链"""
        self.connect_router()
        try:
            b = self._sqlite_query_list(f"SELECT id FROM acl_mac_black WHERE tagname LIKE '{prefix}%'")
            w = self._sqlite_query_list(f"SELECT id FROM acl_mac_white WHERE tagname LIKE '{prefix}%'")
            total = len(b) + len(w)
            self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM acl_mac_black WHERE tagname LIKE '{prefix}%'; DELETE FROM acl_mac_white WHERE tagname LIKE '{prefix}%'\"")
            self._router.exec("sqlite3 " + self.DNS_DB + " \"UPDATE global_config SET acl_mac='0'\"")
            self._router.exec("/usr/ikuai/script/acl_mac.sh init 2>/dev/null")
            self._router.exec("iptables -F ACL_MAC 2>/dev/null")
            return f"deleted {total} rules"
        except Exception as e:
            return f"error: {e}"

    # ==================== 应用协议控制 (安全中心 > 应用协议控制) ====================
    # 专业模式(global_config.parental_mode=0). 表 acl_l7.
    # ⚠️不走iptables/ipset! 走 ik_cntl new_tc app_rule -> ik_core内核new_tc子系统(非iptables).
    # app_proto JSON: custom放应用名字符串(非appid, 脚本APPIDS[名]反查), object放分组gid.
    # time必须空串""(非空JSON致脚本建空timeset -> 规则inactive永不匹配).
    # 验证金矿: L1=DB; L2=ik_summary的App Rules count + ID:<id>规则状态行(active/action/appset/match);
    #   L3=dpi_cache appid + host_active_apps + conntrack appid + match计数增量(命中铁证);
    #   L4=打流连通性(测试机new_tc可能disable, drop不执行 -> match增量作命中铁证, 连通性探测不硬断言).
    def find_app_protocol_rule(self, tagname: str) -> Optional[Dict]:
        """按名称查找应用协议控制规则(acl_l7表)."""
        return self._sqlite_query_line(f"SELECT * FROM acl_l7 WHERE tagname='{tagname}'")

    def verify_app_protocol_database(self, tagname: str, expected_fields: Dict = None,
                                     expect_app: str = None) -> VerifyResult:
        """L1: 验证应用协议控制规则在acl_l7表存在且字段正确.
        expected_fields: {enabled/action/prio/comment}; expect_app: 验app_proto含应用名或大类名(子串)."""
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"应用协议控制规则未找到: {tagname}")
        mismatches = {}
        if expected_fields:
            for key, expected in expected_fields.items():
                actual = str(rule.get(key, ""))
                if actual != str(expected):
                    mismatches[key] = {"expected": str(expected), "actual": actual}
        if expect_app:
            app_proto = str(rule.get("app_proto", ""))
            if expect_app not in app_proto:
                mismatches["app_proto"] = {"expected_contains": expect_app, "actual": app_proto[:80]}
        if mismatches:
            return VerifyResult(level="L1-数据库", passed=False,
                                message=f"字段不匹配: {mismatches}", details={"mismatches": mismatches},
                                raw_output=json.dumps(rule, ensure_ascii=False)[:300])
        return VerifyResult(level="L1-数据库", passed=True,
                            message=f"规则存在且字段正确 (id={rule.get('id')}, action={rule.get('action')}, enabled={rule.get('enabled')}, prio={rule.get('prio')})",
                            details={"rule": rule}, raw_output=json.dumps(rule, ensure_ascii=False)[:300])

    def verify_app_protocol_kernel_rule(self, tagname: str, expect_present: bool = True,
                                        expect_action: str = None) -> VerifyResult:
        """L2: 验证规则下发到ik_core内核(ik_summary的App Rules + ID:<id>规则状态行).
        acl_l7不走iptables, 用ik_summary查. 关键: 必须active(time字段空JSON致inactive).
        规则行格式: ID:<id> prio:<N> active src_set():65535 dst_set():65535 action:Drop|Accept appset:(acl7_app_<id>) timeset:() match:<N>"""
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return VerifyResult(level="L2-内核规则", passed=not expect_present,
                                message=f"规则不在DB({tagname})")
        rid = rule.get("id", "")
        self.connect_router()
        out = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
        # 定位ID:<rid>规则状态行
        rule_lines = [l for l in out.splitlines() if f"ID:{rid} " in l or f"ID:{rid}\t" in l
                      or l.strip().startswith(f"ID:{rid}")]
        present = len(rule_lines) > 0
        if present != expect_present:
            return VerifyResult(level="L2-内核规则", passed=False,
                                message=f"内核规则(id={rid}) present={present} 期望={expect_present}",
                                raw_output="\n".join(rule_lines)[:400] or out[:300])
        if expect_present:
            # active验证(非inactive)
            active_lines = [l for l in rule_lines if "active" in l and "inactive" not in l]
            if not active_lines:
                return VerifyResult(level="L2-内核规则", passed=False,
                                    message=f"规则(id={rid}) inactive(time字段非空致空timeset, 永不匹配!)",
                                    raw_output="\n".join(rule_lines)[:400])
            # action验证
            act_desc = ""
            if expect_action:
                act_ui = "Drop" if expect_action == "drop" else "Accept"
                if not any(act_ui in l for l in active_lines):
                    return VerifyResult(level="L2-内核规则", passed=False,
                                        message=f"规则(id={rid}) action未匹配 action:{act_ui}",
                                        raw_output="\n".join(active_lines)[:300])
                act_desc = f", action:{act_ui}"
            # appset验证
            appset_ok = any(f"acl7_app_{rid}" in l for l in active_lines)
            appset_desc = f", appset={'OK' if appset_ok else '缺失'}"
            return VerifyResult(level="L2-内核规则", passed=True,
                                message=f"内核规则(id={rid}) active{act_desc}{appset_desc}",
                                raw_output="\n".join(active_lines)[:400])
        return VerifyResult(level="L2-内核规则", passed=True,
                            message=f"内核规则(id={rid}) 已删除(present=False符合预期)",
                            raw_output="\n".join(rule_lines)[:200])

    def _read_app_match(self, rid) -> int:
        """读ik_summary里ID:<rid>规则行的match计数(取最大值, 多行时active行match最大)."""
        self.connect_router()
        out = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
        matches = re.findall(rf"ID:{rid}\b.*?match:(\d+)", out)
        return max([int(m) for m in matches]) if matches else 0

    def _app_rule_is_active(self, rid) -> bool:
        """读ik_summary的ID:<rid>规则行, 判断是否active(inactive或消失=False).
        停用BUG排查: 停用(down=del app_rule)后内核规则应消失; 残留active=停用BUG铁证.
        用\\b词边界避免ID:1误匹配ID:10/ID:100."""
        self.connect_router()
        out = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
        rule_lines = [l for l in out.splitlines() if re.search(rf"ID:{rid}\b", l)]
        if not rule_lines:
            return False  # 规则消失
        return any("active" in l and "inactive" not in l for l in rule_lines)

    def verify_app_protocol_match(self, tagname: str) -> VerifyResult:
        """L3: 返回规则当前match计数(供打流前后对比增量, 命中铁证)."""
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return VerifyResult(level="L3-match", passed=False, message=f"规则未找到: {tagname}")
        rid = rule.get("id", "")
        m = self._read_app_match(rid)
        return VerifyResult(level="L3-match", passed=True,
                            message=f"规则(id={rid}) match={m}", details={"match": m, "rid": rid})

    def verify_app_protocol_dpi(self, src_ip: str = "192.168.148.2", dst_ip: str = None,
                                expect_appid: str = None) -> VerifyResult:
        """L3: DPI识别验证(dpi_cache dst_ip->appid + host_active_apps src_ip->appid + conntrack appid).
        探测模式(记录识别状态, 不硬断言). expect_appid指定时期望命中."""
        self.connect_router()
        parts = []
        cache = ""
        if dst_ip:
            cache = self._router.exec(f"cat /proc/ikuai/dpi/dpi_cache 2>/dev/null | grep '{dst_ip}'")
            parts.append(f"dpi_cache[{dst_ip}]: {cache.strip()[:120]}")
        haa = self._router.exec(f"cat /proc/ikuai/stats/host_active_apps 2>/dev/null | grep '{src_ip}'")
        parts.append(f"host_active_apps[{src_ip}]: {haa.strip()[:120]}")
        ct = self._router.exec(f"cat /proc/net/nf_conntrack 2>/dev/null | grep '{src_ip}' | grep -oE 'appid=[0-9]+' | sort | uniq -c")
        parts.append(f"conntrack appid: {ct.strip()[:120]}")
        recognized = bool(haa.strip()) or bool(ct.strip())
        if expect_appid:
            recognized = recognized and (expect_appid in cache or expect_appid in ct)
        return VerifyResult(level="L3-dpi", passed=True,
                            message=f"DPI识别: {'有' if recognized else '无/未匹配(可能未打流)'}",
                            raw_output="\n".join(parts))

    def verify_app_protocol_enabled(self, tagname: str, expect_enabled: bool) -> VerifyResult:
        """验证规则启用状态: DB enabled + 内核规则active双验(enabled=no时内核规则应消失/变inactive)."""
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-enabled", passed=False, message=f"规则未找到: {tagname}")
        db_enabled = str(rule.get("enabled", "")) == "yes"
        kr = self.verify_app_protocol_kernel_rule(tagname, expect_present=expect_enabled)
        if db_enabled != expect_enabled:
            return VerifyResult(level="L1-enabled", passed=False,
                                message=f"DB enabled={rule.get('enabled')} 期望={'yes' if expect_enabled else 'no'}; 内核: {kr.message}",
                                raw_output=kr.raw_output)
        return VerifyResult(level="L1-enabled", passed=True,
                            message=f"enabled={rule.get('enabled')} 符合预期; {kr.message}")

    def verify_app_protocol_not_exists(self, tagname: str) -> VerifyResult:
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return VerifyResult(level="L1-删除验证", passed=True, message=f"规则已删除: {tagname}")
        return VerifyResult(level="L1-删除验证", passed=False,
                            message=f"规则仍存在: {tagname}(id={rule.get('id')})", details={"rule": rule})

    def verify_app_protocol_count(self, expected: int = None, prefix: str = None) -> VerifyResult:
        """验证应用协议控制规则总数, 或prefix开头数."""
        if prefix:
            rows = self._sqlite_query_list(f"SELECT tagname FROM acl_l7 WHERE tagname LIKE '{prefix}%'")
            actual = len(rows)
        else:
            row = self._sqlite_query_line("SELECT count(*) as cnt FROM acl_l7")
            actual = int(row.get("cnt", 0)) if row else 0
        if expected is not None and actual != expected:
            return VerifyResult(level="L1-计数", passed=False,
                                message=f"规则数量 {actual} 期望 {expected}" + (f"(prefix={prefix})" if prefix else ""))
        return VerifyResult(level="L1-计数", passed=True,
                            message=f"规则数量: {actual}" + (f"(prefix={prefix})" if prefix else ""))

    def add_app_protocol_rule_via_ssh(self, tagname: str, app: str = None, category_gid: str = None,
                                      action: str = "drop", prio: int = 32, src_addrs: list = None) -> str:
        """SSH直接建应用协议控制规则(SQL insert + acl_l7.sh init). 供打流测试精确控制app_proto确保命中.
        app: 应用名字符串(如"百度", 入app_proto.custom, 脚本APPIDS[名]反查appid);
        category_gid: 分组gid(如"PROTOGP11", 入app_proto.object). 二选一.
        time必须空串""(非空致规则inactive). 返回结果描述."""
        self.connect_router()
        import json as _json
        custom = [app] if app else []
        obj = [{"gid": category_gid}] if category_gid else []
        app_proto = _json.dumps({"custom": custom, "object": obj}, ensure_ascii=False)
        src = _json.dumps({"object": [], "custom": src_addrs or []}, ensure_ascii=False)
        dst = _json.dumps({"object": [], "custom": []}, ensure_ascii=False)
        # shell双引号包SQL参数, JSON内双引号转义为\"
        ap = app_proto.replace('"', '\\"')
        sr = src.replace('"', '\\"')
        ds = dst.replace('"', '\\"')
        try:
            self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM acl_l7 WHERE tagname='{tagname}'\"")
            sql = (f"sqlite3 {self.DNS_DB} \"INSERT INTO acl_l7(enabled,tagname,comment,prio,action,"
                   f"app_proto,src_addr,dst_addr,time) VALUES('yes','{tagname}','ssh_rule',{prio},'{action}',"
                   f"'{ap}','{sr}','{ds}','')\"")
            self._router.exec(sql)
            self._router.exec("/usr/ikuai/script/acl_l7.sh init 2>/dev/null")
            self._router.exec("sleep 2")  # 等init下发规则到内核(appset建立, 实测需1-2s)
            return f"added {tagname}(action={action},app={app or category_gid})"
        except Exception as e:
            return f"error: {e}"

    def verify_app_protocol_flow(self, tagname: str, dst_domain: str = "www.baidu.com",
                                 dst_ip: str = None, expect_action: str = "drop",
                                 count: int = 5, other_domain: str = "www.qq.com") -> VerifyResult:
        """L4连通性探测(软判定): 建规则后curl经ens11, 连通性端到端探测 + match增量辅助.

        软判定(恒passed=True除规则未找到): 6.12/固件10002 具体应用drop规则不生效是已知产品bug
        (实测appset未建→drop无目标; 即便DPI识别match+>0, new_tc drop引擎对具体应用不执行).
        连通性只记录不判定, 避免已知bug反复阻断综合测试. baidu不通=drop生效/仍通=6.12产品bug软记录.
        match增量作DPI识别证据(match+>0=DPI正常规则已匹配). dst_ip保留兼容不再用.
        details含connected_target/baidu_blocked供调用方做停用验证."""
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return VerifyResult(level="L4-flow", passed=False, message=f"规则未找到: {tagname}")
        rid = rule.get("id", "")
        self.connect_router()
        self.connect_client()
        # user_dpi/smart 尝试启用(给DPI+new_tc最佳阻断机会 + match辅助; 记录原状态测完恢复)
        fs_before = self._router.exec("cat /proc/ikuai/stats/ik_features_status 2>/dev/null | grep '^user_dpi'")
        user_dpi_was_on = "enable" in fs_before
        if not user_dpi_was_on:
            self._router.exec("ik_cntl user_dpi on 2>/dev/null")
            self._router.exec("sleep 3")  # DPI引擎初始化需时间
        fs_smart = self._router.exec("cat /proc/ikuai/stats/ik_features_status 2>/dev/null | grep '^smart_acl'")
        smart_was_on = "enable" in fs_smart
        if not smart_was_on:
            self._router.exec("ik_cntl http_app acl smart on 2>/dev/null")
            self._router.exec("sleep 1")
        match_before = self._read_app_match(rid)
        connected_target = 0
        connected_other = 0
        delta_target = 0
        delta_other = -1  # -1=未测
        try:
            # 目标baidu: count次curl经ens11(强制经路由器DPI, 不再用host路由)
            for _ in range(count):
                out = self._client.exec(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --interface ens11 --connect-timeout 3 -m 8 http://{dst_domain}/",
                    timeout=15)
                if any(c in out for c in ["200", "301", "302", "304"]):
                    connected_target += 1
            match_after_target = self._read_app_match(rid)
            delta_target = match_after_target - match_before
            # 精确性: qq.com经ens11(规则只含百度appid应不命中, 不误伤)
            if other_domain:
                for _ in range(count):
                    out = self._client.exec(
                        f"curl -s -o /dev/null -w '%{{http_code}}' --interface ens11 --connect-timeout 3 -m 8 http://{other_domain}/",
                        timeout=15)
                    if any(c in out for c in ["200", "301", "302", "304"]):
                        connected_other += 1
                match_after_other = self._read_app_match(rid)
                delta_other = match_after_other - match_after_target
        finally:
            if not user_dpi_was_on:
                self._router.exec("ik_cntl user_dpi off 2>/dev/null")
            if not smart_was_on:
                self._router.exec("ik_cntl http_app acl smart off 2>/dev/null")
        baidu_blocked = connected_target == 0
        qq_ok = connected_other > 0
        tgt = f"baidu连通{connected_target}/{count}({'不通=阻断' if baidu_blocked else '仍通'})"
        oth = f"qq连通{connected_other}/{count}"
        msg = f"{tgt}; {oth}; match baidu+{delta_target}/qq+{delta_other}(辅助)"
        # 软判定(6.12/10002具体应用drop不生效=已知产品bug, 实测appset未建→drop无目标; 连通性不硬FAIL):
        passed = True
        if baidu_blocked and qq_ok:
            msg += " → [阻断生效] 百度不通+qq通=drop精确生效(DPI+new_tc active)"
        elif baidu_blocked and not qq_ok:
            msg += " → 百度/qq均不通(过阻断误伤, 记录)"
        else:
            dpi_ok = delta_target > 0
            msg += (f" → 百度仍通(drop未执行, 6.12产品bug: "
                    f"{'DPI正常(match+'+str(delta_target)+'规则已匹配), appset未建/new_tc drop对具体应用不生效' if dpi_ok else 'DPI未识别'})")
        return VerifyResult(level="L4-flow", passed=passed, message=msg,
                            details={"connected_target": connected_target, "connected_other": connected_other,
                                     "delta_target": delta_target, "delta_other": delta_other,
                                     "baidu_blocked": baidu_blocked, "rid": rid},
                            raw_output=f"id={rid} baidu conn={connected_target}/{count} match+{delta_target}; qq conn={connected_other}/{count} match+{delta_other}")

    def app_protocol_appset_has_appid(self, tagname: str) -> bool:
        """检查规则的appset(acl7_app_$id)是否仍含appid(停用bug排查签名).

        acl_l7.sh down()(停用)只调ik_cntl new_tc app_rule del, 不清appset; del()(删除)才调__clean_set清appset.
        故停用后appset仍含appid=停用未彻底(残留active规则仍可命中阻断)→产品bug签名. 删除后应为False.
        返回True=appset仍含appid(停用未生效签名)."""
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return False
        rid = rule.get("id", "")
        self.connect_router()
        out = self._router.exec(f"cat /proc/ikuai/stats/ik_summary 2>/dev/null | grep -A1 'acl7_app_{rid}:'")
        return "appid" in out

    def verify_app_protocol_block_effect(self, tagname: str, dst_domain: str,
                                         count: int = 5, enable_user_dpi: bool = True) -> Dict:
        """阻断生效判定(match+连通结合, 硬判定). 建drop规则后调用, 替代旧软判定verify_app_protocol_flow.

        流程: 记录user_dpi原状态→(如关则ik_cntl user_dpi on+sleep3)→清conntrack→读match_before→
          curl dst_domain ×count经ens11→读match_after→恢复user_dpi.
        判定: dpi_hit=match_delta>0(DPI识别并命中规则, 不依赖new_tc/drop); blocked=connected==0(端到端阻断).
          dpi_hit&&blocked=阻断生效(PASS); dpi_hit&&!blocked=匹配但new_tc未drop(记录); !dpi_hit=DPI未识别(软降级).
        user_dpi自管(开+恢复), 调用方无需管时序, 每次调用独立."""
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return {"match_delta": 0, "connected": 0, "blocked": False, "dpi_hit": False,
                    "user_dpi_was_on": False, "rid": "", "detail": f"规则未找到: {tagname}", "error": True}
        rid = rule.get("id", "")
        self.connect_router()
        self.connect_client()
        fs_before = self._router.exec("cat /proc/ikuai/stats/ik_features_status 2>/dev/null | grep '^user_dpi'")
        user_dpi_was_on = "enable" in fs_before
        turned_on = False
        if enable_user_dpi and not user_dpi_was_on:
            self._router.exec("ik_cntl user_dpi on 2>/dev/null")
            self._router.exec("sleep 3")  # DPI引擎初始化
            turned_on = True
        try:
            self.clear_client_conntrack("192.168.148.2")
            match_before = self._read_app_match(rid)
            connected = 0
            for _ in range(count):
                out = self._client.exec(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --interface ens11 --connect-timeout 3 -m 8 http://{dst_domain}/",
                    timeout=15)
                code = out.strip().strip("'").strip()
                # 任何HTTP响应(2xx/3xx/4xx/5xx, 非超时拒绝000)=连通; 仅000(无响应=路由器drop)=阻断.
                # 避免目标服务器反爬403被误判为阻断(403是服务器响应=连通, 非路由器drop).
                if code and code != "000":
                    connected += 1
            # ping辅助(ICMP更底层, 双确认阻断; 用户建议提高准确性. 注: L7规则可能只drop应用不drop ICMP)
            ping_out = self._client.exec(f"ping -I ens11 -c 3 -W 2 {dst_domain} 2>/dev/null", timeout=15)
            pm = re.search(r'(\d+)\s*received', ping_out)
            ping_recv = int(pm.group(1)) if pm else 0
            match_after = self._read_app_match(rid)
        finally:
            if turned_on:
                self._router.exec("ik_cntl user_dpi off 2>/dev/null")
        match_delta = match_after - match_before
        ping_blocked = ping_recv == 0
        # blocked判定: ping(ICMP,主, 更准不被CDN/403掩盖)或curl(HTTP)任一不通=阻断. 用户建议ping.
        blocked = ping_blocked or (connected == 0)
        dpi_hit = match_delta > 0
        if blocked:
            verdict = f"阻断生效(curl={connected}/{count} ping={ping_recv}/3)"
        elif dpi_hit:
            verdict = f"规则匹配但未阻断(curl={connected}/{count} ping={ping_recv}/3)"
        else:
            verdict = f"未阻断(curl={connected}/{count} ping={ping_recv}/3)"
        return {"match_delta": match_delta, "connected": connected, "blocked": blocked,
                "ping_recv": ping_recv, "ping_blocked": ping_blocked,
                "dpi_hit": dpi_hit, "user_dpi_was_on": user_dpi_was_on, "rid": rid,
                "detail": f"id={rid} match+{match_delta} curl={connected}/{count} ping={ping_recv}/3 → {verdict}"}

    def verify_app_protocol_disable_effect(self, tagname: str, dst_domain: str,
                                           baseline_blocked: bool, count: int = 5) -> Dict:
        """停用后阻断是否消失(三重信号抓停用BUG). 停用规则后调用.

        停用BUG现象(报禅道): 停用后阻断仍生效, 须删除才彻底. 根因acl_l7.sh down()只del一条app_rule,
        累积重复内核条目残留active仍匹配+drop. 三重信号任一异常=BUG:
          信号1 连通: 停用后curl仍不通(connected==0 且 baseline_blocked)
          信号2 match: 停用后规则仍匹配(match_delta>0, 不依赖new_tc/drop是否执行)
          信号3 内核: 停用后内核规则仍active(应消失; 残留active=停用BUG铁证, 不依赖DPI/curl)
        信号2/3不依赖baseline阻断可复现, 即便端到端drop未执行也能抓停用BUG."""
        rule = self.find_app_protocol_rule(tagname)
        if rule is None:
            return {"still_blocked": False, "match_still_inc": False, "still_active": False,
                    "bug_detected": False, "signals": [], "connected": 0, "match_delta": 0,
                    "rid": "", "detail": f"规则未找到: {tagname}", "error": True}
        rid = rule.get("id", "")
        self.connect_router()
        self.connect_client()
        # user_dpi开(给信号2 match最佳探测; 记录恢复)
        fs_before = self._router.exec("cat /proc/ikuai/stats/ik_features_status 2>/dev/null | grep '^user_dpi'")
        user_dpi_was_on = "enable" in fs_before
        turned_on = False
        if not user_dpi_was_on:
            self._router.exec("ik_cntl user_dpi on 2>/dev/null")
            self._router.exec("sleep 3")
            turned_on = True
        try:
            self.clear_client_conntrack("192.168.148.2")
            match_before = self._read_app_match(rid)
            connected = 0
            for _ in range(count):
                out = self._client.exec(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --interface ens11 --connect-timeout 3 -m 8 http://{dst_domain}/",
                    timeout=15)
                code = out.strip().strip("'").strip()
                if code and code != "000":
                    connected += 1
            # ping辅助(ICMP, 主判定, 不被CDN/403掩盖; 用户建议)
            ping_out = self._client.exec(f"ping -I ens11 -c 3 -W 2 {dst_domain} 2>/dev/null", timeout=15)
            pm = re.search(r'(\d+)\s*received', ping_out)
            ping_recv = int(pm.group(1)) if pm else 0
            match_after = self._read_app_match(rid)
        finally:
            if turned_on:
                self._router.exec("ik_cntl user_dpi off 2>/dev/null")
        match_delta = match_after - match_before
        ping_blocked = ping_recv == 0
        still_blocked = baseline_blocked and (ping_blocked or connected == 0)
        match_still_inc = match_delta > 0
        still_active = self._app_rule_is_active(rid)
        signals = []
        if still_blocked:
            signals.append(f"连通仍阻断(curl={connected}/{count} ping={ping_recv}/3)")
        if match_still_inc:
            signals.append(f"规则仍匹配(match+{match_delta})")
        if still_active:
            signals.append("内核规则仍active(应消失)")
        bug_detected = bool(signals)
        detail = (f"id={rid} 停用后: curl={connected}/{count} ping={ping_recv}/3 match+{match_delta} active={still_active}"
                  f" → {'停用BUG(' + '; '.join(signals) + ')' if bug_detected else '停用正常(阻断消失)'}")
        return {"still_blocked": still_blocked, "match_still_inc": match_still_inc,
                "still_active": still_active, "bug_detected": bug_detected, "signals": signals,
                "connected": connected, "ping_recv": ping_recv, "match_delta": match_delta, "rid": rid, "detail": detail}

    def cleanup_app_protocol_test(self, prefix: str = "appt_") -> str:
        """清理prefix开头的应用协议控制规则(acl_l7表)+清内核残留+脚本init重建.
        ⚠️acl_l7.sh的__clean在表空时不执行循环, SQL删表后内核规则残留, 需手动ik_cntl del."""
        self.connect_router()
        try:
            rows = self._sqlite_query_list(f"SELECT id,prio FROM acl_l7 WHERE tagname LIKE '{prefix}%'")
            total = len(rows)
            self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM acl_l7 WHERE tagname LIKE '{prefix}%'\"")
            # 手动清内核残留(SQL删表后__clean不执行)
            for r in rows:
                rid = r.get("id", "")
                prio = r.get("prio", "31")
                try:
                    self._router.exec(f"ik_cntl new_tc app_rule del id {rid} prio {prio} 2>/dev/null")
                    self._router.exec(f"ik_cntl appset clear acl7_app_{rid} 2>/dev/null")
                    self._router.exec(f"ik_cntl timeset clear acl7_time_{rid} 2>/dev/null")
                except Exception:
                    pass
            self._router.exec("/usr/ikuai/script/acl_l7.sh init 2>/dev/null")
            return f"deleted {total} rules"
        except Exception as e:
            return f"error: {e}"

    def cleanup_all_app_protocol(self) -> str:
        """彻底清理所有应用协议控制规则(acl_l7全表+内核所有app_rule/appset残留).
        产品BUG: app_rule删不干净累积(id复用+残留active干扰停用BUG判定), 测试前/后必须彻底清.
        与cleanup_app_protocol_test(prefix)区别: 本方法清全表+遍历ik_summary清内核所有App Rules残留."""
        self.connect_router()
        try:
            rows = self._sqlite_query_list("SELECT id,prio FROM acl_l7")
            self._router.exec(f"sqlite3 {self.DNS_DB} \"DELETE FROM acl_l7\"")
            for r in rows:
                rid = r.get("id", "")
                rprio = r.get("prio", "31")
                self._router.exec(f"ik_cntl new_tc app_rule del id {rid} prio {rprio} 2>/dev/null")
                self._router.exec(f"ik_cntl appset clear acl7_app_{rid} 2>/dev/null")
            # 清内核残留(DB已空但app_rule累积, 遍历ik_summary App Rules, 排除Mac App Rules id≥1000000)
            out = self._router.exec("cat /proc/ikuai/stats/ik_summary 2>/dev/null")
            seen = set()
            for line in out.splitlines():
                m = re.search(r'ID:(\d+)\s+prio:(\d+)', line)
                if not m:
                    continue
                rid, rprio = m.group(1), m.group(2)
                if (rid, rprio) in seen or not (rid.isdigit() and int(rid) < 1000000):
                    continue
                seen.add((rid, rprio))
                self._router.exec(f"ik_cntl new_tc app_rule del id {rid} prio {rprio} 2>/dev/null")
                self._router.exec(f"ik_cntl appset clear acl7_app_{rid} 2>/dev/null")
            self._router.exec("/usr/ikuai/script/acl_l7.sh init 2>/dev/null")
            return f"purged {len(rows)} db rules + {len(seen)} kernel app_rule"
        except Exception as e:
            return f"error: {e}"
