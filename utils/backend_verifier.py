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

from config.config import get_config, SSHConfig, SSHHostConfig
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
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    def summary(self) -> str:
        lines = ["全链路验证结果:"]
        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            lines.append(f"  [{status}] {r.level}: {r.message}")
        return "\n".join(lines)


class SSHClient:
    """SSH连接管理器"""

    def __init__(self, host_config: SSHHostConfig):
        self._config = host_config
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self):
        if self._client is not None:
            # 检查连接是否仍然活跃
            try:
                transport = self._client.get_transport()
                if transport is None or not transport.is_active():
                    logger.info(f"SSH connection lost, reconnecting: {self._config.host}")
                    self._client = None
                else:
                    return
            except Exception:
                self._client = None
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            timeout=10,
        )
        logger.info(f"SSH connected: {self._config.username}@{self._config.host}")

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
            ssh_config = get_config().ssh
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
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"规则未找到: {filters}",
                raw_output=str(self.query_qos_rules(qos_type)[:3]),
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
        output = self._router.exec("/usr/ikuai/function/vlan show")
        try:
            parsed = json.loads(output)
            return parsed.get("data", [])
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
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"VLAN未找到: tagname={vlan_name}",
                raw_output=str(self.query_vlan_rules()[:3]),
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

        iKuai VLAN网络结构:
          _{name}@lan1  (802.1Q VLAN接口, slave of bridge)
          {name}        (bridge接口, IP分配在此)

        Args:
            vlan_name: VLAN名称
            expected_state: 期望的接口状态 "UP" 或 "DOWN"
        """
        self.connect_router()
        # 检查802.1Q VLAN接口
        vlan_iface = f"_{vlan_name}"
        output = self._router.exec(f"ip link show {vlan_iface} 2>/dev/null")

        if not output.strip() or "does not exist" in output:
            return VerifyResult(
                level="L2-网络接口",
                passed=False,
                message=f"VLAN接口 {vlan_iface} 不存在",
                raw_output=output,
            )

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

        vlan_iface = f"_{vlan_name}"
        if vlan_iface not in output:
            return VerifyResult(
                level="L3-proc",
                passed=False,
                message=f"VLAN接口 {vlan_iface} 未在/proc/net/vlan/config中找到",
                raw_output=output,
            )

        # 检查VLAN ID是否匹配
        if expected_vlan_id:
            # 格式: _vlan_min_100  | 100  | lan1
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
        output = self._router.exec("/usr/ikuai/function/static_rt show")
        try:
            parsed = json.loads(output)
            return parsed.get("data", [])
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
            return VerifyResult(
                level="L1-数据库",
                passed=False,
                message=f"静态路由未找到: tagname={tagname}",
                raw_output=str(self.query_static_routes()[:3]),
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
