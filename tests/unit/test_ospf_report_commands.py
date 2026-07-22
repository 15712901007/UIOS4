from __future__ import annotations

import re

from utils.backend_verifier import BackendVerifier
from utils.ospf_verifier import OspfCheckResult
from utils.replay_commands import build_verification_commands


UNSAFE = re.compile(
    r"\b(?:if|then|fi|for|do|done|base64)\b|\$\(|\$\{|"
    r"(?:^|[ ;])\[(?:router|client)\](?:$|[ ;])|(?:^|[ ;])rc\s*="
)


def test_all_public_ospf_verifiers_generate_safe_targets_and_commands():
    backend = BackendVerifier()
    ospf = backend.get_ospf_verifier()
    samples = (
        (ospf.verify_schema, (), {}),
        (ospf.script_contract, (), {}),
        (ospf.verify_config_update_safety, (), {}),
        (ospf.verify_instance, (62000, "ipv4"), {}),
        (ospf.verify_area_interface, (62000, "ipv4", "0.0.0.0", "lan1"), {}),
        (ospf.verify_generated_config, (62000, "ipv4", "198.18.252.1"), {}),
        (ospf.wait_neighbor, ("router", "ipv4", "10.66.0.18"), {}),
        (ospf.wait_route, ("router", "10.99.99.1/32", True), {}),
        (ospf.verify_lsdb, (["198.18.252.1"],), {}),
        (ospf.verify_protocol_89, ("lan1",), {}),
        (ospf.ping_from_router, ("10.99.99.1",), {}),
        (ospf.management_health, (), {}),
    )
    for verify_func, args, kwargs in samples:
        commands = build_verification_commands(
            backend, verify_func, args=args, kwargs=kwargs,
            result=OspfCheckResult("L", True, "自动化实际语义"),
        )
        assert commands is not None
        for item in commands:
            assert item["target"] in {"router", "client"}
            assert item["copy_ready"] is True
            assert item["contains_secret"] is False
            assert not UNSAFE.search(item["command"])
            assert "\n" not in item["command"]


def test_peer_probe_and_cleanup_never_create_manual_peer_commands():
    backend = BackendVerifier()
    ospf = backend.get_ospf_verifier()
    for verify_func in (
        ospf.probe_tagged_peer_transit,
        ospf.cleanup_client,
        ospf.restore_empty_router_runtime,
    ):
        commands = build_verification_commands(
            backend, verify_func, result=OspfCheckResult("L", True, "完成")
        )
        assert commands == []
