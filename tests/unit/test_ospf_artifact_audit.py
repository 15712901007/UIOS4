from __future__ import annotations

import json
from html import escape

import pytest

from utils.ospf_artifact_audit import audit_ospf_artifacts
from utils.test_results_to_excel import export_results_to_excel


SECTIONS = (
    "【测试操作】", "【页面验证】", "【后端验证】",
    "【运行时验证】", "【协议验证】", "【清理结果】",
)


def _command(text="vtysh -c 'show ip ospf neighbor'"):
    return {
        "target": "router", "target_label": "路由器",
        "host": "192.0.2.1", "shell": "sh",
        "purpose": "查看OSPF邻居", "command": text,
        "expected": "邻居为Full", "actual": "自动化观察到Full",
        "copy_ready": True, "effect": "read_only",
        "contains_secret": False, "interactive": False,
        "valid_when": "邻接建立后、清理前",
    }


def _data(command=None):
    details = [f"{section}\n不适用：审计夹具" for section in SECTIONS]
    return {
        "total": 1, "passed": 1, "failed": 0, "skipped": 0,
        "test_cases": [{
            "name": "网络配置-OSPF综合测试",
            "original_name": "test_ospf_comprehensive", "status": "passed",
            "duration": "1.00s", "steps": [{
                "name": "步骤1 操作：执行审计；验证：三产物一致",
                "description": "审计", "status": "passed", "duration": "1.00s",
                "details": details,
                "verification_commands": [command or _command()],
            }],
        }],
    }


def _write(tmp_path, data):
    json_path = tmp_path / "ospf.json"
    html_path = tmp_path / "ospf.html"
    xlsx_path = tmp_path / "ospf.xlsx"
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
        ) + "</body></html>", encoding="utf-8",
    )
    ok, message = export_results_to_excel(str(json_path), str(xlsx_path))
    assert ok, message
    return json_path, html_path, xlsx_path


def test_ospf_artifact_audit_accepts_safe_consistent_reports(tmp_path):
    paths = _write(tmp_path, _data())
    assert audit_ospf_artifacts(*paths, sensitive_values=["runtime-only-value"]) == {
        "cases": 1, "steps": 1, "commands": 1,
    }


@pytest.mark.parametrize("unsafe", [
    "for x in a; do echo $x; done",
    "rc=$?",
    "ip link del ospf-test",
    "sqlite3 /tmp/db 'DELETE FROM ospf_instance'",
])
def test_ospf_artifact_audit_rejects_internal_or_mutating_commands(tmp_path, unsafe):
    paths = _write(tmp_path, _data(_command(unsafe)))
    with pytest.raises(AssertionError, match="内部脚本|危险动作"):
        audit_ospf_artifacts(*paths)


def test_ospf_artifact_audit_rejects_hardware_address_and_runtime_secret(tmp_path):
    data = _data()
    data["test_cases"][0]["steps"][0]["details"].append(
        "运行证据 aa:bb:cc:dd:ee:ff runtime-only-value"
    )
    paths = _write(tmp_path, data)
    with pytest.raises(AssertionError, match="硬件地址|敏感值"):
        audit_ospf_artifacts(*paths, sensitive_values=["runtime-only-value"])
