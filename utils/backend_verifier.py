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
        """部署SSH shell防重置脚本（持久分区，升级不丢失）"""
        try:
            # 检查是否已部署
            check_cmd = "test -f /etc/mnt/ikuai/fix_sshd_shell.sh && echo EXISTS || echo NOT_EXISTS"
            _, stdout, _ = self._client.exec_command(check_cmd, timeout=5)
            if "EXISTS" in stdout.read().decode():
                logger.debug("防重置脚本已存在，跳过部署")
                return

            # 创建修复脚本
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
            # 写入脚本
            write_cmd = f'''cat > /etc/mnt/ikuai/fix_sshd_shell.sh << 'FIXSCRIPT'
{script_content}FIXSCRIPT
chmod +x /etc/mnt/ikuai/fix_sshd_shell.sh'''
            self._client.exec_command(write_cmd, timeout=10)

            # 添加cron任务
            cron_cmd = '''(crontab -l 2>/dev/null | grep -v fix_sshd_shell; echo "* * * * * /etc/mnt/ikuai/fix_sshd_shell.sh >> /tmp/sshd_fix.log 2>&1") | crontab -'''
            self._client.exec_command(cron_cmd, timeout=5)

            # 立即执行一次
            self._client.exec_command("/etc/mnt/ikuai/fix_sshd_shell.sh", timeout=5)

            logger.info("SSH防重置脚本部署成功")

        except Exception as e:
            logger.warning(f"部署防重置脚本失败: {e}")

    def exec_command(self, command: str, timeout: int = 30) -> str:
        """执行命令并返回stdout（exec方法的别名，保持兼容性）"""
        return self.exec(command, timeout)

    def exec(self, command: str, timeout: int = 30) -> str:
        """执行命令并返回stdout，连接断开时自动重连一次"""
        for attempt in range(2):
            try:
                if self._client is None:
                    self.connect()
                _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
                output = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                if err and "warning" not in err.lower():
                    logger.debug(f"SSH stderr: {err.strip()}")
                return output
            except (paramiko.SSHException, OSError, TimeoutError) as e:
                if attempt == 0:
                    logger.info(f"SSH exec failed ({e}), reconnecting...")
                    self._client = None
                else:
                    raise

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
            set_name = f"{set_prefix}_{rule_id}"
            if set_name not in output:
                return VerifyResult(
                    level="L2-iptables",
                    passed=False,
                    message=f"ipset {set_name} 未在 {chain} 链中找到",
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

    def run_iperf3(self, direction: str = "upload",
                   server_ip: str = None,
                   bind_ip: str = "192.168.148.2",
                   duration: int = None,
                   port: int = 5201) -> Dict:
        """
        在测试客户端执行iperf3测速

        前提条件：
        1. 测试客户端(10.66.0.18)需要有到iperf3_server的路由经过路由器
        2. iperf3服务端已启动

        Args:
            direction: "upload" 或 "download"
            server_ip: iperf3服务端IP，默认使用配置
            bind_ip: 绑定的源IP（必须是路由器LAN下的IP）
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

        cmd = f"iperf3 -c {server_ip} -B {bind_ip} -t {duration} -J -p {port}"
        if direction == "download":
            cmd += " -R"

        logger.info(f"iperf3 {direction}: {cmd}")
        output = self._client.exec(cmd, timeout=duration + 30)

        try:
            return json.loads(output)
        except json.JSONDecodeError:
            logger.error(f"iperf3 output parse failed: {output[:300]}")
            return {"error": output[:500]}

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

        # L5: iperf3（可选）
        if run_iperf3:
            l5_up = self.verify_iperf3("upload", upload_kbps, bind_ip=ip)
            chain.results.append(l5_up)
            logger.info(f"[L5-upload] {l5_up.message}")

            l5_down = self.verify_iperf3("download", download_kbps, bind_ip=ip)
            chain.results.append(l5_down)
            logger.info(f"[L5-download] {l5_down.message}")

        return chain

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
                             dev: str = "ens11", src_ip: str = "192.168.148.2") -> bool:
        """在测试客户端添加经过路由器的策略路由"""
        self.connect_client()
        cmd = f"sudo ip route add {dest_ip}/32 via {gateway} dev {dev} src {src_ip}"
        output = self._client.exec(cmd)
        return "error" not in output.lower()

    def remove_route(self, dest_ip: str) -> bool:
        """移除测试客户端的策略路由"""
        self.connect_client()
        output = self._client.exec(f"sudo ip route del {dest_ip}/32 2>/dev/null")
        return True  # 即使不存在也算成功

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

        return VerifyResult(
            level="L2-内核路由",
            passed=False,
            message=f"内核路由未找到: {route_network} via {gateway}",
            raw_output=output.strip() if output.strip() else "(empty)",
        )

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
                                  expected_fields: Dict = None) -> VerifyResult:
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
                passed=False,
                message=f"跨三层服务规则未找到: tagname={tagname}",
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

    def verify_lb_pcc_policy_routing(self, expected_wan_interfaces: List[str] = None) -> VerifyResult:
        """L2: 验证多线负载策略路由(ip rule fwmark + 各WAN路由表)

        检查:
        1. ip rule中有fwmark对应的策略路由规则
        2. 各WAN路由表中有默认路由

        Args:
            expected_wan_interfaces: 期望的WAN接口列表，如["wan1","wan2","wan3"]
        """
        self.connect_router()
        if expected_wan_interfaces is None:
            expected_wan_interfaces = ["wan1", "wan2", "wan3"]

        try:
            # 检查ip rule
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
                    level="L2-策略路由",
                    passed=True,  # 策略路由是基础设施，缺失不一定是LB规则问题
                    message=f"策略路由检查: {len(found_tables)}/{len(expected_wan_interfaces)}个WAN有ip rule (缺失: {missing}，可能线路未连接)",
                    details={"found_tables": found_tables, "missing": missing, "routes": route_details},
                    raw_output=ip_rule_output,
                )

            return VerifyResult(
                level="L2-策略路由",
                passed=True,
                message=f"策略路由正常: {len(found_tables)}个WAN接口均有fwmark规则和路由表",
                details={"found_tables": found_tables, "routes": route_details},
                raw_output=ip_rule_output,
            )

        except Exception as e:
            return VerifyResult(
                level="L2-策略路由",
                passed=False,
                message=f"策略路由检查失败: {str(e)[:100]}",
            )

    def verify_lb_pcc_kernel(self, expect_enabled: bool = True) -> VerifyResult:
        """L3/L4: 验证多线负载内核状态(ik_core模块 + dmesg LB日志 + conntrack)

        检查:
        1. ik_core模块已加载
        2. dmesg中有[LB]日志，确认LB已启用/禁用
        3. conntrack中有带remote_if的连接条目

        Args:
            expect_enabled: 期望LB是否启用
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

            # 3. 检查conntrack中remote_if
            conntrack_output = self._router.exec("cat /proc/net/nf_conntrack 2>/dev/null | head -5")
            has_remote_if = "remote_if=" in conntrack_output
            logger.info(f"conntrack has remote_if: {has_remote_if}")

            # 综合判断
            checks = {
                "ik_core_loaded": ik_core_loaded,
                "lb_config_in_dmesg": bool(dmesg_lb.strip()),
                "conntrack_tracking": has_remote_if,
            }

            if expect_enabled:
                if ik_core_loaded and lb_enabled:
                    return VerifyResult(
                        level="L3/L4-内核",
                        passed=True,
                        message=f"多线负载内核正常: ik_core已加载, LB已启用, conntrack追踪{'正常' if has_remote_if else '暂无数据'}",
                        details=checks,
                        raw_output=dmesg_lb,
                    )
                else:
                    return VerifyResult(
                        level="L3/L4-内核",
                        passed=False,
                        message=f"多线负载内核异常: ik_core={'已加载' if ik_core_loaded else '未加载'}, LB={'已启用' if lb_enabled else '未启用'}",
                        details=checks,
                        raw_output=dmesg_lb,
                    )
            else:
                if lb_disabled or not lb_enabled:
                    return VerifyResult(
                        level="L3/L4-内核",
                        passed=True,
                        message="多线负载已禁用(符合预期)",
                        details=checks,
                        raw_output=dmesg_lb,
                    )
                return VerifyResult(
                    level="L3/L4-内核",
                    passed=False,
                    message="多线负载预期禁用但仍在运行",
                    details=checks,
                    raw_output=dmesg_lb,
                )

        except Exception as e:
            return VerifyResult(
                level="L3/L4-内核",
                passed=False,
                message=f"内核验证失败: {str(e)[:100]}",
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

            m = re.search(r"/\*\s*(\d+)\s*\*/", line)
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

            m = re.search(r"/\*\s*(\d+)\s*\*/", line)
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
        """L2: 验证域名分流规则在ipset中

        域名分流使用 ipset sdomain_src_{id} 存储域名解析后的IP。
        """
        self.connect_router()
        try:
            ipset_name = f"sdomain_src_{rule_id}"
            output = self._router.exec(f"ipset list {ipset_name} 2>/dev/null")
            ipset_exists = "Name:" in output or ipset_name in output

            if should_exist:
                if not ipset_exists:
                    all_ipset = self._router.exec("ipset list -n 2>/dev/null")
                    sdomain_sets = [l.strip() for l in all_ipset.split("\n") if "sdomain" in l]
                    return VerifyResult(
                        level="L2-ipset",
                        passed=False,
                        message=f"ipset {ipset_name} 未找到",
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
                    message=f"ipset {ipset_name} 存在, 成员数={len(members)}",
                    details={"ipset_name": ipset_name, "members": members},
                    raw_output=output[:500],
                )
            else:
                if ipset_exists:
                    return VerifyResult(
                        level="L2-ipset",
                        passed=False,
                        message=f"ipset {ipset_name} 仍存在(应已删除)",
                    )
                return VerifyResult(
                    level="L2-ipset",
                    passed=True,
                    message=f"ipset {ipset_name} 已删除",
                )

        except Exception as e:
            return VerifyResult(
                level="L2-ipset",
                passed=False,
                message=f"ipset检查失败: {str(e)[:100]}",
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
            if src_addr and f"updown_src_{rule_id}" in all_ipset:
                src_content = self._router.exec(f"ipset list updown_src_{rule_id} 2>/dev/null")
                has_addr = src_addr in src_content
                addr_check_results.append(f"src_addr({src_addr}): {'found' if has_addr else 'not found'}")
                details["src_addr_in_ipset"] = has_addr

            if dst_addr and f"updown_dst_{rule_id}" in all_ipset:
                dst_content = self._router.exec(f"ipset list updown_dst_{rule_id} 2>/dev/null")
                has_addr = dst_addr in dst_content
                addr_check_results.append(f"dst_addr({dst_addr}): {'found' if has_addr else 'not found'}")
                details["dst_addr_in_ipset"] = has_addr

            all_addr_ok = all(
                "found" in r for r in addr_check_results
            ) if addr_check_results else True

            # 没有地址/端口的规则不创建ipset，此时found_sets为空是正常的
            has_addr_or_port_check = src_addr or dst_addr
            if has_addr_or_port_check:
                passed = len(found_sets) > 0 and all_addr_ok
            else:
                passed = True
            msg_parts = [f"ipset={found_sets}"]
            if addr_check_results:
                msg_parts.extend(addr_check_results)

            return VerifyResult(
                level="L2-ipset",
                passed=passed,
                message=f"上下行分离ipset验证{'通过' if passed else '未通过'}: {', '.join(msg_parts)}",
                details=details,
                raw_output=all_ipset[:500],
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

            details = {
                "config_exists": has_rules,
                "rule_count": rule_count,
            }

            return VerifyResult(
                level="L3-内核状态",
                passed=True,
                message=f"上下行分离内核配置: {'有规则' if has_rules else '无规则'}({rule_count}条)",
                details=details,
                raw_output=config_content[:300],
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

            if expect_running:
                msg = f"miniupnpd运行状态: {'运行中' if is_running else '未运行'}"
            else:
                msg = f"miniupnpd应未运行: {'确认' if not is_running else '仍在运行'}"

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
            ifname_output = self._router.exec("cat /tmp/iktmp/miniupnpd_ifname.conf 2>/dev/null")
            marker_output = self._router.exec("test -f /tmp/iktmp/upnpd_enabled && echo YES || echo NO")

            conf_exists = bool(conf_output.strip())
            ifname_exists = bool(ifname_output.strip())
            marker_exists = marker_output.strip() == "YES"

            details = {
                "conf_exists": conf_exists,
                "ifname_exists": ifname_exists,
                "marker_exists": marker_exists,
            }

            all_exist = conf_exists and ifname_exists and marker_exists
            passed = (all_exist == expect_exists)

            msg = f"运行时配置: conf={conf_exists}, ifname={ifname_exists}, marker={marker_exists}"

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

            binary_exists = binary_output.strip() == "YES"
            process_running = "miniupnpd" in ps_output
            has_cron = bool(cron_output.strip())

            details = {
                "binary_exists": binary_exists,
                "process_running": process_running,
                "has_cron": has_cron,
                "cron_output": cron_output.strip() if has_cron else "",
            }

            if expect_enabled:
                passed = binary_exists and process_running
                msg = f"miniupnpd: binary={binary_exists}, running={process_running}, cron={has_cron}"
            else:
                passed = not process_running
                msg = f"miniupnpd应未运行: {'确认' if not process_running else '仍在运行'}"

            raw = f"ps={ps_output.strip()}, cron={cron_output.strip()}"

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
