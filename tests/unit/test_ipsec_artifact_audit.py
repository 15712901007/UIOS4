from __future__ import annotations

import json
from html import escape

import pytest

from utils.ipsec_artifact_audit import audit_ipsec_artifacts
from utils.test_results_to_excel import export_results_to_excel


SECTIONS = (
    "【测试操作】", "【页面验证】", "【后端验证】",
    "【运行时验证】", "【协议验证】", "【清理结果】",
)


def _command(text="swanctl --list-sas"):
    return {
        "target": "router", "target_label": "主路由器",
        "host": "192.0.2.1", "shell": "sh",
        "purpose": "查看IPsec SA", "command": text,
        "expected": "IKE和Child已建立", "actual": "自动化观察到已建立",
        "copy_ready": True, "effect": "只读",
        "contains_secret": False, "interactive": False,
        "valid_when": "建链后、清理前",
    }


def _data(command=None):
    details = [f"{section}\n不适用：审计夹具" for section in SECTIONS]
    return {
        "total": 1, "passed": 1, "failed": 0, "skipped": 0,
        "test_cases": [{
            "name": "虚拟专网-IPsec VPN综合测试",
            "original_name": "test_ipsec_vpn_comprehensive",
            "status": "passed", "duration": "1.00s",
            "steps": [{
                "name": "步骤1: 审计IPsec产物", "description": "审计",
                "status": "passed", "duration": "1.00s",
                "details": details,
                "verification_commands": [command or _command()],
            }],
        }],
    }


def _write(tmp_path, data):
    json_path = tmp_path / "ipsec.json"
    html_path = tmp_path / "ipsec.html"
    xlsx_path = tmp_path / "ipsec.xlsx"
    json_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    commands = [
        item["command"]
        for step in data["test_cases"][0]["steps"]
        for item in step["verification_commands"]
    ]
    html_path.write_text(
        "<html><body>" + "".join(
            f'<code id="verification-command-0-0-{i}">{escape(command)}</code>'
            for i, command in enumerate(commands)
        ) + "</body></html>",
        encoding="utf-8",
    )
    ok, message = export_results_to_excel(str(json_path), str(xlsx_path))
    assert ok, message
    return json_path, html_path, xlsx_path


def test_ipsec_artifact_audit_accepts_consistent_secret_safe_outputs(tmp_path):
    paths = _write(tmp_path, _data())
    assert audit_ipsec_artifacts(
        *paths, sensitive_values=["runtime-only-psk"]
    ) == {"cases": 1, "steps": 1, "commands": 1}


@pytest.mark.parametrize("target", ["peer", "server", ""])
def test_ipsec_artifact_audit_rejects_non_public_targets(tmp_path, target):
    command = _command()
    command["target"] = target
    paths = _write(tmp_path, _data(command))
    with pytest.raises(AssertionError, match="目标不合规"):
        audit_ipsec_artifacts(*paths)


@pytest.mark.parametrize("unsafe", [
    "swanctl --initiate --child ipsec2-spoke-1-esp",
    "ip xfrm state flush",
    "for x in a; do echo $x; done",
])
def test_ipsec_artifact_audit_rejects_mutating_or_internal_commands(tmp_path, unsafe):
    paths = _write(tmp_path, _data(_command(unsafe)))
    with pytest.raises(AssertionError, match="内部脚本|危险动作"):
        audit_ipsec_artifacts(*paths)


def test_ipsec_artifact_audit_rejects_secret_and_hardware_address(tmp_path):
    data = _data()
    data["test_cases"][0]["steps"][0]["details"].append(
        "PSK=runtime-only-psk aa:bb:cc:dd:ee:ff"
    )
    paths = _write(tmp_path, data)
    with pytest.raises(AssertionError, match="硬件地址|敏感值|认证明文"):
        audit_ipsec_artifacts(*paths, sensitive_values=["runtime-only-psk"])
