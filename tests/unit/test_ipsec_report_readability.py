"""IPsec 报告中文可读性与人工复验命令契约。"""

from __future__ import annotations

import re
from pathlib import Path

from utils.backend_verifier import BackendVerifier, VerifyResult
from utils.ipsec_verifier import (
    IpsecEnvironmentSnapshot,
    IpsecTopology,
    IpsecVerifier,
)
from utils.replay_commands import build_verification_commands
from utils.report_generator import ReportGenerator


UNSAFE_COMMAND = re.compile(
    r"\b(?:if|then|fi|for|do|done|while|case|esac|base64)\b|"
    r"\$\(|\$\{|\$(?:\?|[A-Za-z_][A-Za-z0-9_]*)|"
    r"\b(?:delete|insert|update|drop|truncate)\b|"
    r"\bip\s+(?:addr|route|rule|link|xfrm)\s+(?:add|del|delete|flush|set)\b|"
    r"\bswanctl\s+--(?:initiate|terminate|rekey|load)\b",
)


def _topology() -> IpsecTopology:
    return IpsecTopology(
        token="abc123",
        router_policy="ipsec_t_r_abc123",
        peer_policy="ipsec_t_p_abc123",
        router_proposal="ike_t_r_abc123",
        peer_proposal="ike_t_p_abc123",
        client_source="10.99.99.1",
        peer_service="198.18.1.2",
        client_iface="ens11",
        client_gateway="192.168.148.1",
        router_underlay="192.0.2.1",
        peer_underlay="192.0.2.2",
        router_interface="wan1",
        peer_interface="wan1",
    )


def _result(message: str = "自动化检查已完成") -> VerifyResult:
    return VerifyResult("IPsec", True, message)


def test_ipsec_backend_checks_generate_copy_ready_public_commands():
    backend = BackendVerifier()
    ipsec = IpsecVerifier(backend)
    topology = _topology()
    snapshot = IpsecEnvironmentSnapshot(public={})
    samples = (
        (ipsec.verify_schema, (), {}),
        (ipsec.verify_script_contract, (), {}),
        (ipsec.management_health, (), {}),
        (ipsec.verify_policy_runtime_loaded, (7, "router"), {}),
        (ipsec.verify_database, (topology.router_policy, {}, "router"), {}),
        (ipsec.verify_secret_permissions, (7, "router"), {}),
        (ipsec.wait_for_sa, (topology, 7, 9), {}),
        (ipsec.verify_bidirectional_traffic, (topology,), {}),
        (ipsec.exact_residual_audit, (topology, snapshot), {}),
        (ipsec.verify_restored, (snapshot,), {}),
    )

    all_commands = []
    for verify_func, args, kwargs in samples:
        commands = build_verification_commands(
            backend, verify_func, args=args, kwargs=kwargs,
            result=_result(),
        )
        assert commands, verify_func.__name__
        all_commands.extend(commands)

    assert len(all_commands) >= 20
    for item in all_commands:
        assert item["target"] in {"router", "client"}
        assert item["copy_ready"] is True
        assert item["contains_secret"] is False
        assert "\n" not in item["command"]
        assert UNSAFE_COMMAND.search(item["command"]) is None
        assert "peer" not in item["target"]


def test_ipsec_peer_internal_checks_never_publish_peer_commands():
    backend = BackendVerifier()
    ipsec = IpsecVerifier(backend)

    assert build_verification_commands(
        backend, ipsec.verify_policy_runtime_loaded,
        args=(7, "peer"), result=_result(),
    ) == []
    assert build_verification_commands(
        backend, ipsec.verify_secret_permissions,
        args=(7, "peer"), result=_result(),
    ) == []
    assert build_verification_commands(
        backend, ipsec.initiate_child_from_peer,
        args=(7,), result=_result(),
    ) == []


def test_ipsec_report_uses_page_labels_and_plain_chinese_failure_summaries():
    from tests.network.test_ipsec_vpn_comprehensive import (
        POLICY_ADVANCED_FIELD_LABELS,
        POLICY_BASIC_FIELD_LABELS,
        PROPOSAL_FIELD_LABELS,
    )

    root = Path(__file__).resolve().parents[2]
    source = (
        root / "tests" / "network" / "test_ipsec_vpn_comprehensive.py"
    ).read_text(encoding="utf-8")

    for internal_label in (
        "IKE提议字段-tagname",
        "IKE提议字段-auth_alg",
        "IKE提议选项-enc_alg",
        "策略基础字段-local_ip",
        "策略高级字段-ipsec_sa_time",
        "DPD动作控件应存在",
        "API-resolve_check应被后端识别",
    ):
        assert internal_label not in source

    assert PROPOSAL_FIELD_LABELS == {
        "tagname": "名称",
        "auth_alg": "认证算法",
        "enc_alg": "加密算法",
        "dh_group": "DH",
        "sa_lifetime": "IKE SA生存周期",
    }
    assert POLICY_BASIC_FIELD_LABELS["local_ip"] == "本端IP地址"
    assert POLICY_BASIC_FIELD_LABELS["remote_addr"] == "对端IP地址或主机名"
    assert POLICY_ADVANCED_FIELD_LABELS["ipsec_sa_time"] == "IPsec连接生存时间"
    assert 'f"IKE提议包含“{field_label}”"' in source
    assert 'f"策略基础设置包含“{field_label}”"' in source
    assert 'f"策略高级配置包含“{field_label}”"' in source

    for plain_summary in (
        "用户无法完成一套完整配置",
        "页面与后台功能没有配套",
        "所有可见必填项都已填写",
        "虽然配置已经保存，但隧道不能直接使用",
        "连接结果错误地依赖发起方向",
        "双向数据仍然不通",
        "安全限制没有生效",
    ):
        assert plain_summary in source


def test_ipsec_product_failure_analysis_is_not_misclassified_as_ssh():
    analysis = ReportGenerator()._analyze_failure({
        "name": "IPsec VPN综合测试",
        "error_message": (
            "AssertionError: IPsec VPN综合验证失败(10项，"
            "产品=10，自动化=0，环境=0)：页面保存失败"
        ),
        "error_traceback": "",
    })

    assert analysis["category"] == "IPsec产品功能缺陷"
    assert "失败步骤摘要" in analysis["suggestion"]
    assert "SSH" not in analysis["category"]


def test_ipsec_restore_diff_reports_changed_lines_instead_of_only_hashes(monkeypatch):
    backend = BackendVerifier()
    ipsec = IpsecVerifier(backend)
    baseline = IpsecEnvironmentSnapshot(
        public={
            "router": {"route_hash": "same", "rule_hash": "same", "address_hash": "same"},
            "peer": {"route_hash": "before", "rule_hash": "same", "address_hash": "same"},
            "client": {"route_hash": "same", "rule_hash": "same", "address_hash": "same"},
            "router_policy_count": 0,
            "router_proposal_count": 0,
            "peer_policy_count": 0,
            "peer_proposal_count": 0,
        },
        private={
            "router": {},
            "peer": {"route_lines": ["default via 192.0.2.1 dev wan1"]},
            "client": {},
        },
    )
    current = IpsecEnvironmentSnapshot(
        public={
            **baseline.public,
            "peer": {"route_hash": "after", "rule_hash": "same", "address_hash": "same"},
        },
        private={
            "router": {},
            "peer": {"route_lines": ["198.51.100.0/24 dev wan2"]},
            "client": {},
        },
    )
    monkeypatch.setattr(ipsec, "snapshot_environment", lambda: current)
    monkeypatch.setattr(
        ipsec,
        "management_health",
        lambda: VerifyResult("管理通道", True, "六条管理通道均可用", details={}),
    )

    result = ipsec.verify_restored(baseline)

    assert result.passed is False
    evidence = result.details["mismatches"]["对端设备路由表"]
    assert evidence["新增条目"] == ["198.51.100.0/24 dev wan2"]
    assert evidence["减少条目"] == ["default via 192.0.2.1 dev wan1"]
    assert "route_hash" not in str(result.details)


def test_failed_report_steps_expand_backend_commands_by_default():
    root = Path(__file__).resolve().parents[2]
    template = (
        root / "reports" / "templates" / "report_template.html"
    ).read_text(encoding="utf-8")

    assert "后端人工复验命令（逐条复制执行）" in template
    assert "step.status in ['failed', 'error'] %} open" in template
