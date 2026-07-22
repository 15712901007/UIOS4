from types import SimpleNamespace

import pytest

from utils.qemu_verifier import QemuVerifier
from utils.replay_commands import build_verification_commands
from utils.verify_helper import _is_safe_report_verifier


class _FakeBackend:
    def __init__(self):
        self.queries = []
        self._ssh_config = SimpleNamespace(
            router=SimpleNamespace(host="192.0.2.10"),
            client=SimpleNamespace(host="192.0.2.20"),
        )

    def _sqlite_query_list(self, query):
        self.queries.append(query)
        return []


class _OrphanRouter:
    def __init__(self):
        self.pids = {321}
        self.taps = {"qtap17_lan1_1"}
        self.commands = []

    def exec(self, command, timeout=30):
        self.commands.append(command)
        if command.startswith("ps w | awk"):
            return "\n".join(map(str, sorted(self.pids)))
        if command.startswith("kill -TERM"):
            self.pids.clear()
            return ""
        if "SELECT count(*) FROM qemu_new_config WHERE id=17" in command:
            return "0"
        if "ip -o link show" in command and "^qtap17_" in command:
            self.taps.clear()
            return ""
        return ""


class _OrphanBackend(_FakeBackend):
    def __init__(self):
        super().__init__()
        self._router = _OrphanRouter()

    def connect_router(self):
        return None


def test_report_queries_never_select_plaintext_vnc_password():
    backend = _FakeBackend()
    verifier = QemuVerifier(backend)

    assert verifier.find_vm("qvm_test_main") is None
    query = backend.queries[-1]

    assert "length(vnc_pwd) AS vnc_pwd_len" in query
    selected = query.split(" FROM ", 1)[0]
    assert ",vnc_pwd," not in selected
    assert not selected.rstrip().endswith("vnc_pwd")


@pytest.mark.parametrize(
    "value",
    ["", "../vm", "vm;reboot", "vm name", "vm' OR 1=1 --", "x" * 65],
)
def test_untrusted_names_are_rejected_before_shell_or_sql(value):
    verifier = QemuVerifier(_FakeBackend())
    with pytest.raises(ValueError):
        verifier.find_vm(value)


def test_vdisk_and_nic_parsers_cover_supported_non_destructive_types():
    disks = QemuVerifier._parse_vdisk(
        "create@1@system@virtio,bootimg@--@/888/ref.img@virtio,partname@--@sdb1@none"
    )
    nics = QemuVerifier._parse_nics(
        "lan1@52:54:00:00:00:01@none,lan1@52:54:00:00:00:02@virtio,"
        "lan1@52:54:00:00:00:03@e1000e,lan1@52:54:00:00:00:04@vmxnet3"
    )

    assert [item["type"] for item in disks] == ["create", "bootimg", "partname"]
    assert [item["method"] for item in nics] == ["none", "virtio", "e1000e", "vmxnet3"]
    assert [item["index"] for item in nics] == ["1", "2", "3", "4"]


def test_qemu_results_use_semantic_manual_commands_and_hide_internal_fallback():
    verifier = QemuVerifier(_FakeBackend())
    command = verifier._manual(
        "router", "查看测试记录", "sqlite3 /tmp/config.db '.tables'", "显示qemu表"
    )
    result = verifier._result("L1", True, "ok", commands=[command])

    assert _is_safe_report_verifier(verifier.verify_database)
    assert build_verification_commands(
        verifier.backend, verifier.verify_database, result=result
    ) == [command]
    serialized = str(result.details)
    assert "vnc_pwd=" not in serialized
    assert "password" not in serialized.lower()


def test_fixed_test_image_contract_is_stable():
    assert QemuVerifier.TEST_IMAGE_NAME == "CorePure64-16.2.iso"
    assert QemuVerifier.TEST_IMAGE_URL.startswith("http://tinycorelinux.net/")
    assert len(QemuVerifier.TEST_IMAGE_MD5) == 32
    assert len(QemuVerifier.TEST_IMAGE_SHA256) == 64


def test_cleanup_removes_orphan_qemu_without_db_or_runtime_record():
    backend = _OrphanBackend()
    verifier = QemuVerifier(backend)

    result = verifier.cleanup_test("qvm_deadbe_", owned_ids=[17])

    assert result["rows_deleted"] == 0
    assert result["processes"] == {
        "term_pids": [321], "kill_pids": [], "remaining_pids": [],
    }
    assert result["taps_cleaned"] == [17]
    assert result["runtimes_cleaned"] == [17]
    assert backend._router.pids == set()
    assert backend._router.taps == set()
    assert any(command == "kill -TERM 321" for command in backend._router.commands)
    assert any("^qtap17_" in command for command in backend._router.commands)
