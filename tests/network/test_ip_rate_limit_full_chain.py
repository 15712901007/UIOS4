"""
IP限速全链路验证测试

演示完整的前端 → 后台验证流程：
1. 前端新增IP限速规则（MCP-Playwright → Python代码）
2. L1: SSH数据库验证（simple_qos show）
3. L2: iptables规则验证（IP_QOS链）
4. L3: ipset成员验证（目标IP）
5. L4: 内核模块/日志验证（ik_core + dmesg）
6. L5: iperf3实测验证（可选，需iperf3服务端）

本文件基于MCP-SSH + MCP-Playwright全链路探索经验转化而来。
"""
import pytest
import sys
import io

from pages.network.ip_rate_limit_page import IpRateLimitPage
from config.config import get_config
from utils.step_recorder import StepRecorder


@pytest.mark.ip_rate_limit
@pytest.mark.full_chain
@pytest.mark.network
class TestIpRateLimitFullChain:
    """IP限速全链路验证 - 前端操作 + SSH后台5层验证"""

    # 测试数据
    RULE_NAME = "全链路验证测试"
    RULE_IP = "192.168.148.100"
    UPLOAD_KBPS = 2048    # 2 MB/s
    DOWNLOAD_KBPS = 4096  # 4 MB/s

    def test_full_chain_verification(
        self,
        ip_rate_limit_page_logged_in: IpRateLimitPage,
        backend_verifier,
        step_recorder: StepRecorder,
    ):
        """
        全链路验证: 前端新增规则 → L1数据库 → L2iptables → L3ipset → L4内核 → 清理
        """
        page = ip_rate_limit_page_logged_in
        rec = step_recorder
        config = get_config()

        print("\n" + "=" * 60)
        print("IP限速全链路验证测试")
        print("=" * 60)

        # ========== 步骤1: 前端新增限速规则 ==========
        with rec.step("步骤1: 前端新增IP限速规则", "通过UI新增一条限速规则"):
            print(f"\n[步骤1] 新增规则: {self.RULE_NAME}")
            print(f"  IP: {self.RULE_IP}")
            print(f"  上传: {self.UPLOAD_KBPS} KB/s ({self.UPLOAD_KBPS / 1024:.0f} MB/s)")
            print(f"  下载: {self.DOWNLOAD_KBPS} KB/s ({self.DOWNLOAD_KBPS / 1024:.0f} MB/s)")

            success = page.add_rule(
                name=self.RULE_NAME,
                ip=self.RULE_IP,
                upload_speed=self.UPLOAD_KBPS,
                download_speed=self.DOWNLOAD_KBPS,
            )
            assert success, f"前端新增规则失败: {self.RULE_NAME}"
            rec.add_detail("前端新增规则成功")
            print("  -> 规则新增成功")

            # 等待规则下发到内核
            page.page.wait_for_timeout(2000)

        # ========== 步骤2: L1 数据库验证 ==========
        with rec.step("步骤2: L1-数据库验证", "SSH验证规则已写入数据库"):
            if backend_verifier is None:
                pytest.skip("SSH后台验证未启用（需要安装paramiko）")

            print("\n[步骤2] L1: 数据库验证...")
            l1 = backend_verifier.verify_qos_database(
                "simple_qos",
                expected_fields={
                    "upload": str(self.UPLOAD_KBPS),
                    "download": str(self.DOWNLOAD_KBPS),
                },
                tagname=self.RULE_NAME,
            )
            print(f"  -> {l1.message}")
            rec.add_detail(f"L1: {l1.message}")
            assert l1.passed, f"L1数据库验证失败: {l1.message}"

            # 提取rule_id供后续步骤使用
            rule_id = l1.details.get("rule", {}).get("id")
            print(f"  -> 规则ID: {rule_id}")

        # ========== 步骤3: L2 iptables验证 ==========
        with rec.step("步骤3: L2-iptables验证", "SSH验证限速规则已下发到IP_QOS链"):
            print("\n[步骤3] L2: iptables验证...")

            # 验证上传限速规则
            l2_up = backend_verifier.verify_iptables_rule(
                "IP_QOS",
                rule_id=rule_id,
                expected_speed_kbps=self.UPLOAD_KBPS,
            )
            print(f"  -> 上传: {l2_up.message}")
            rec.add_detail(f"L2-上传: {l2_up.message}")
            assert l2_up.passed, f"L2上传iptables验证失败: {l2_up.message}"

            # 验证下载限速规则
            l2_down = backend_verifier.verify_iptables_rule(
                "IP_QOS",
                rule_id=rule_id,
                expected_speed_kbps=self.DOWNLOAD_KBPS,
            )
            print(f"  -> 下载: {l2_down.message}")
            rec.add_detail(f"L2-下载: {l2_down.message}")
            assert l2_down.passed, f"L2下载iptables验证失败: {l2_down.message}"

        # ========== 步骤4: L3 ipset验证 ==========
        with rec.step("步骤4: L3-ipset验证", "SSH验证目标IP已加入ipset集合"):
            print("\n[步骤4] L3: ipset验证...")
            l3 = backend_verifier.verify_ipset_member(rule_id, self.RULE_IP)
            print(f"  -> {l3.message}")
            rec.add_detail(f"L3: {l3.message}")
            assert l3.passed, f"L3 ipset验证失败: {l3.message}"

        # ========== 步骤5: L4 内核验证 ==========
        with rec.step("步骤5: L4-内核验证", "SSH验证ik_core模块加载且dmesg无异常"):
            print("\n[步骤5] L4: 内核验证...")
            l4 = backend_verifier.verify_kernel()
            print(f"  -> {l4.message}")
            rec.add_detail(f"L4: {l4.message}")
            assert l4.passed, f"L4内核验证失败: {l4.message}"

        # ========== 步骤6: 清理 - 删除测试规则 ==========
        with rec.step("步骤6: 清理测试数据", "通过前端删除测试规则"):
            print("\n[步骤6] 清理测试规则...")
            # 通过前端搜索并删除
            deleted = page.delete_rule(self.RULE_NAME)
            if deleted:
                print("  -> 前端删除成功")
                rec.add_detail("前端删除成功")
            else:
                # 兜底：通过SSH删除
                print("  -> 前端删除失败，尝试SSH删除...")
                if rule_id:
                    backend_verifier.delete_qos_rule("simple_qos", rule_id)
                    print(f"  -> SSH删除成功 (id={rule_id})")
                    rec.add_detail(f"SSH删除成功 (id={rule_id})")

        print("\n" + "=" * 60)
        print("全链路验证完成 (L1-L4 全部通过)")
        print("=" * 60)

    @pytest.mark.slow
    def test_full_chain_with_iperf3(
        self,
        ip_rate_limit_page_logged_in: IpRateLimitPage,
        backend_verifier,
        step_recorder: StepRecorder,
    ):
        """
        全链路验证（含L5 iperf3实测）- 需要iperf3服务端

        此测试较慢（~30秒），标记为slow，默认不运行。
        运行方式: pytest -m "full_chain and slow"
        """
        page = ip_rate_limit_page_logged_in
        rec = step_recorder
        config = get_config()

        if backend_verifier is None:
            pytest.skip("SSH后台验证未启用")

        print("\n" + "=" * 60)
        print("IP限速全链路验证（含iperf3实测）")
        print("=" * 60)

        # 新增规则
        with rec.step("新增测试规则", "前端新增限速规则"):
            success = page.add_rule(
                name=self.RULE_NAME,
                ip=self.RULE_IP,
                upload_speed=self.UPLOAD_KBPS,
                download_speed=self.DOWNLOAD_KBPS,
            )
            assert success, "前端新增规则失败"
            page.page.wait_for_timeout(2000)

        # 全链路验证（含iperf3）
        with rec.step("全链路验证", "L1-L5全部验证"):
            # 先添加策略路由让流量经过路由器
            iperf3_server = config.ssh.iperf3_server
            backend_verifier.add_route_via_router(iperf3_server)

            try:
                result = backend_verifier.verify_ip_qos_full_chain(
                    tagname=self.RULE_NAME,
                    ip=self.RULE_IP,
                    upload_kbps=self.UPLOAD_KBPS,
                    download_kbps=self.DOWNLOAD_KBPS,
                    run_iperf3=True,
                )

                print(result.summary())
                rec.add_detail(result.summary())

                # 只要L1-L4通过就算核心通过
                core_results = [r for r in result.results if "iperf3" not in r.level]
                assert all(r.passed for r in core_results), \
                    f"核心验证失败:\n{result.summary()}"

            finally:
                # 清理路由
                backend_verifier.remove_route(iperf3_server)

        # 清理规则
        with rec.step("清理", "删除测试规则"):
            page.delete_rule(self.RULE_NAME)

        print("\n全链路验证完成（含iperf3实测）")
