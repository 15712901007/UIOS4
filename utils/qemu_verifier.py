"""QEMU virtual-machine backend verification for iKuai 4.0.

The web UI stores virtual machines in ``qemu_new_config`` and delegates all
runtime work to ``/usr/ikuai/script/qemu.sh``.  This verifier keeps the five
test layers explicit and, importantly, never reads the plaintext ``vnc_pwd``
column into a report-facing value.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from utils.backend_verifier import VerifyResult


class QemuVerifier:
    """L1-L5 verifier bound to an existing :class:`BackendVerifier`."""

    DB = "/etc/mnt/ikuai/config.db"
    TABLE = "qemu_new_config"
    SCRIPT = "/usr/ikuai/script/qemu.sh"
    DATA_ROOT = "/etc/disk_user"
    RUNTIME_ROOT = "/tmp/iktmp/qemu"
    CGROUP_ROOT = "/sys/fs/cgroup/cpu/ik_apps"
    TEST_IMAGE_NAME = "CorePure64-16.2.iso"
    TEST_IMAGE_URL = (
        "http://tinycorelinux.net/16.x/x86_64/release/CorePure64-16.2.iso"
    )
    TEST_IMAGE_MD5 = "9625854d8ac6156f89e20cfa6d69cc24"
    TEST_IMAGE_SHA256 = (
        "c954b2900fbbd38c2da156525819de8c80c4cc7a7ffde61a89b10f4a99985ebc"
    )

    SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    SAFE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,31}$")
    SAFE_PART = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
    SAFE_SNAPSHOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    SAFE_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

    REPORT_FIELDS: Sequence[str] = (
        "id", "enabled", "partname", "tagname", "name", "system", "accel",
        "brname", "mem_size", "cpu_usage", "cpu_cores", "vdisk", "iso",
        "usb", "uefi", "vnc_port", "vnc_acl", "auto_start",
    )

    def __init__(self, backend_verifier):
        self.backend = backend_verifier

    # -------------------- connection and report helpers --------------------
    def _router(self):
        self.backend.connect_router()
        return self.backend._router

    def _client(self):
        self.backend.connect_client()
        return self.backend._client

    def _exec(self, command: str, timeout: int = 30) -> str:
        return self._router().exec(command, timeout=timeout)

    @staticmethod
    def _sql_literal(value: Any) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    @classmethod
    def _require_name(cls, value: str) -> str:
        value = str(value or "")
        if not cls.SAFE_NAME.fullmatch(value):
            raise ValueError(f"unsafe virtual-machine name: {value!r}")
        return value

    @classmethod
    def _require_prefix(cls, value: str) -> str:
        value = str(value or "")
        if not cls.SAFE_PREFIX.fullmatch(value):
            raise ValueError(f"unsafe virtual-machine prefix: {value!r}")
        return value

    @classmethod
    def _require_part(cls, value: str) -> str:
        value = str(value or "")
        if not cls.SAFE_PART.fullmatch(value):
            raise ValueError(f"unsafe disk partition name: {value!r}")
        return value

    @staticmethod
    def _short(value: Any, limit: int = 1200) -> str:
        text = str(value or "").replace("\x00", " ")
        return text[:limit]

    def _manual(
        self,
        target: str,
        purpose: str,
        command: str,
        expected: str,
        *,
        actual: str = "",
        effect: str = "read_only",
        valid_when: str = "对应步骤完成后、测试环境清理前",
    ) -> Dict[str, Any]:
        config = (
            self.backend._ssh_config.router
            if target == "router"
            else self.backend._ssh_config.client
        )
        return {
            "target": target,
            "target_label": "被测路由器" if target == "router" else "测试客户端",
            "host": str(config.host),
            "shell": "sh",
            "purpose": purpose,
            "command": command,
            "expected": expected,
            "actual": self._short(actual, 300),
            "copy_ready": True,
            "contains_secret": False,
            "interactive": False,
            "interactive_hint": "",
            "effect": effect,
            "valid_when": valid_when,
        }

    def _result(
        self,
        level: str,
        passed: bool,
        message: str,
        *,
        raw: Any = "",
        details: Optional[Mapping[str, Any]] = None,
        commands: Optional[Iterable[Dict[str, Any]]] = None,
    ) -> VerifyResult:
        payload = dict(details or {})
        payload["verification_commands"] = list(commands or [])
        return VerifyResult(
            level=level,
            passed=bool(passed),
            message=str(message),
            details=payload,
            raw_output=self._short(raw),
        )

    def build_verification_commands(self, result=None) -> List[Dict[str, Any]]:
        """Return the fixed, secret-free commands attached to a result."""
        if result is None:
            return []
        details = getattr(result, "details", {}) or {}
        return list(details.get("verification_commands") or [])

    # ------------------------------ snapshots ------------------------------
    def _select_rows(self, where: str = "1=1") -> List[Dict[str, Any]]:
        fields = ",".join(self.REPORT_FIELDS) + ",length(vnc_pwd) AS vnc_pwd_len"
        return self.backend._sqlite_query_list(
            f"SELECT {fields} FROM {self.TABLE} WHERE {where} ORDER BY id"
        )

    def find_vm(self, name: str) -> Optional[Dict[str, Any]]:
        name = self._require_name(name)
        rows = self._select_rows(f"name={self._sql_literal(name)}")
        return rows[0] if rows else None

    def snapshot_non_test_state(self, prefix: str) -> Dict[str, Any]:
        prefix = self._require_prefix(prefix)
        rows = self._select_rows(
            f"name NOT LIKE {self._sql_literal(prefix + '%')}"
        )
        serialized = json.dumps(rows, ensure_ascii=True, sort_keys=True)
        return {
            "rows": rows,
            "fingerprint": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            "count": len(rows),
        }

    def verify_non_test_state(self, prefix: str, snapshot: Mapping[str, Any]) -> VerifyResult:
        current = self.snapshot_non_test_state(prefix)
        expected = str(snapshot.get("fingerprint", ""))
        passed = current["fingerprint"] == expected
        sql = (
            "SELECT id,enabled,partname,name,system,accel,brname,mem_size,"
            "cpu_usage,cpu_cores,vdisk,iso,usb,uefi,vnc_port,vnc_acl,auto_start "
            f"FROM {self.TABLE} WHERE name NOT LIKE "
            f"{self._sql_literal(prefix + '%')} ORDER BY id"
        )
        cmd = self._manual(
            "router", "复核非测试虚拟机未被改动",
            f"sqlite3 -header -column {self.DB} {json.dumps(sql)}",
            f"行数和字段与测试前快照一致，当前应为 {snapshot.get('count', 0)} 行",
            actual=f"fingerprint={current['fingerprint']}; rows={current['count']}",
            valid_when="测试结束后仍有效",
        )
        return self._result(
            "L4-环境隔离", passed,
            (
                f"非测试虚拟机保持不变 ({current['count']} 行)"
                if passed else
                "非测试虚拟机状态与测试前快照不一致"
            ),
            raw=f"expected={expected}\nactual={current['fingerprint']}",
            commands=[cmd],
        )

    # ---------------------------- setup helpers ----------------------------
    def reserve_vnc_port(self, preferred_start: int = 5999) -> int:
        used_db = {
            int(row.get("vnc_port", 0) or 0)
            for row in self._select_rows()
        }
        listeners = self._exec("netstat -lnt 2>/dev/null | awk 'NR>2 {print $4}'")
        used_listen = {
            int(match.group(1))
            for match in re.finditer(r":(59\d\d)(?:\s|$)", listeners)
        }
        start = max(5901, min(int(preferred_start), 5999))
        for port in range(start, 5900, -1):
            if port not in used_db and port not in used_listen:
                return port
        raise RuntimeError("no free VNC port in 5901-5999")

    def ensure_test_image(self, partname: str = "888") -> VerifyResult:
        """Ensure the fixed Tiny Core ISO exists, downloading atomically if needed."""
        partname = self._require_part(partname)
        image = f"{self.DATA_ROOT}/{partname}/{self.TEST_IMAGE_NAME}"
        tmp = f"{self.DATA_ROOT}/{partname}/.{self.TEST_IMAGE_NAME}.download"
        current = self._exec(
            f"test -f {image} && md5sum {image} | awk '{{print $1}}'",
            timeout=30,
        ).strip()
        downloaded = False
        if current != self.TEST_IMAGE_MD5:
            downloaded = True
            command = (
                f"rm -f {tmp}; "
                f"wget -O {tmp} {self.TEST_IMAGE_URL} && "
                f"test \"$(md5sum {tmp} | awk '{{print $1}}')\" = "
                f"{self.TEST_IMAGE_MD5} && mv {tmp} {image}"
            )
            self._exec(command, timeout=240)
        proof = self._exec(
            f"ls -ln {image}; md5sum {image}; sha256sum {image}", timeout=40
        )
        passed = self.TEST_IMAGE_MD5 in proof and self.TEST_IMAGE_SHA256 in proof
        cmd = self._manual(
            "router", "核对虚拟机 L5 启动镜像完整性",
            f"md5sum {image}",
            f"输出 {self.TEST_IMAGE_MD5}  {image}",
            actual=proof,
            valid_when="测试结束后仍有效",
        )
        return self._result(
            "测试准备-镜像", passed,
            f"Tiny Core 镜像{'已下载并' if downloaded else '已'}通过双摘要校验",
            raw=proof,
            details={"image": f"/{partname}/{self.TEST_IMAGE_NAME}", "downloaded": downloaded},
            commands=[cmd],
        )

    def prepare_reference_image(self, prefix: str, partname: str = "888") -> Dict[str, str]:
        prefix = self._require_prefix(prefix)
        partname = self._require_part(partname)
        directory = f"{self.DATA_ROOT}/{partname}/.ikuai_vm_test/{prefix}"
        marker = f"{directory}/.owner"
        image = f"{directory}/reference.img"
        self._exec(
            f"mkdir -p {directory}; printf '%s\\n' {prefix} > {marker}; "
            f"test -f {image} || qemu-img create -f qcow2 {image} 64M >/dev/null; "
            f"qemu-img check {image}",
            timeout=40,
        )
        return {
            "directory": directory,
            "image": image,
            "ui_path": f"/{partname}/.ikuai_vm_test/{prefix}/reference.img",
            "marker": marker,
        }

    def verify_environment(self, partname: str = "888") -> VerifyResult:
        partname = self._require_part(partname)
        command = (
            "printf 'script='; sha256sum /usr/ikuai/script/qemu.sh; "
            "printf 'qemu='; qemu-system-x86_64 --version | head -1; "
            "printf 'img='; qemu-img --version | head -1; "
            "printf 'kvm='; test -c /dev/kvm && echo yes || echo no; "
            "printf 'module='; test -d /sys/module/kvm_intel -o -d /sys/module/kvm_amd && echo yes || echo no; "
            f"printf 'disk='; test -L {self.DATA_ROOT}/{partname} && readlink {self.DATA_ROOT}/{partname}; "
            f"printf 'free_kb='; df -k {self.DATA_ROOT}/{partname} | awk 'NR==2 {{print $4}}'"
        )
        output = self._exec(command, timeout=40)
        free_match = re.search(r"free_kb=(\d+)", output)
        free_kb = int(free_match.group(1)) if free_match else 0
        passed = (
            "QEMU emulator version" in output
            and "qemu-img version" in output
            and "kvm=yes" in output
            and "module=yes" in output
            and "disk=/etc/disk/" in output
            and free_kb >= 512 * 1024
        )
        commands = [
            self._manual(
                "router", "确认 QEMU/KVM 运行环境",
                "qemu-system-x86_64 --version",
                "显示 QEMU 版本且 /dev/kvm 可另行确认存在",
                actual=output,
                valid_when="测试结束后仍有效",
            ),
            self._manual(
                "router", "查看 qemu.sh 的数据库与启动入口",
                r"grep -nE 'QEMU_TABLE=|^add\(\)|^edit\(\)|^up\(\)|^down\(\)|^snapshot\(\)' /usr/ikuai/script/qemu.sh",
                "显示 qemu_new_config 及 add/edit/up/down/snapshot 入口",
                actual=output,
                valid_when="测试结束后仍有效",
            ),
        ]
        return self._result(
            "环境前置", passed,
            f"QEMU/KVM/脚本/磁盘环境{'满足' if passed else '不满足'}，可用空间 {free_kb // 1024} MB",
            raw=output,
            details={"free_kb": free_kb},
            commands=commands,
        )

    # ------------------------------- L1 DB ---------------------------------
    def verify_database(
        self,
        name: str,
        expected_fields: Optional[Mapping[str, Any]] = None,
        *,
        expect_present: bool = True,
    ) -> VerifyResult:
        name = self._require_name(name)
        row = self.find_vm(name)
        if not expect_present:
            passed = row is None
            message = f"虚拟机 {name} 已从数据库删除" if passed else f"虚拟机 {name} 仍在数据库"
        elif row is None:
            passed = False
            message = f"数据库未找到虚拟机 {name}"
        else:
            mismatches = {}
            for field, expected in dict(expected_fields or {}).items():
                actual = row.get(field)
                if str(actual) != str(expected):
                    mismatches[field] = {"expected": expected, "actual": actual}
            passed = not mismatches
            message = (
                f"数据库记录及 {len(expected_fields or {})} 个字段正确 (id={row.get('id')})"
                if passed else f"数据库字段不匹配: {mismatches}"
            )
        fields = ",".join(self.REPORT_FIELDS) + ",length(vnc_pwd) AS vnc_pwd_len"
        sql = f"SELECT {fields} FROM {self.TABLE} WHERE name={self._sql_literal(name)}"
        cmd = self._manual(
            "router", "核对虚拟机数据库记录（口令仅显示长度）",
            f"sqlite3 -header -column {self.DB} {json.dumps(sql)}",
            "存在一行且字段与页面配置一致" if expect_present else "无输出",
            actual=json.dumps(row or {}, ensure_ascii=False),
        )
        return self._result(
            "L1-数据库", passed, message,
            raw=json.dumps(row or {}, ensure_ascii=False, sort_keys=True),
            details={"rule": row or {}}, commands=[cmd],
        )

    # -------------------------- L2 process/storage --------------------------
    def _runtime_values(self, row: Mapping[str, Any]) -> Dict[str, Any]:
        qid = int(row["id"])
        pid_text = self._exec(f"cat {self.RUNTIME_ROOT}/{qid}/pid 2>/dev/null").strip()
        pid = int(pid_text) if pid_text.isdigit() else 0
        cmdline = self._exec(
            f"test -r /proc/{pid}/cmdline && tr '\\000' ' ' < /proc/{pid}/cmdline",
        ) if pid else ""
        config = self._exec(f"cat {self.RUNTIME_ROOT}/{qid}/config 2>/dev/null")
        quota = self._exec(
            f"cat {self.CGROUP_ROOT}/qemu_{qid}/cpu.cfs_quota_us 2>/dev/null"
        ).strip()
        tasks = self._exec(
            f"cat {self.CGROUP_ROOT}/qemu_{qid}/tasks 2>/dev/null"
        ).split()
        return {
            "id": qid, "pid": pid, "cmdline": cmdline, "config": config,
            "quota": quota, "tasks": tasks,
        }

    def verify_runtime(
        self,
        name: str,
        *,
        expect_running: bool = True,
        wait_timeout: int = 0,
    ) -> VerifyResult:
        name = self._require_name(name)
        row = self.find_vm(name)
        if not row:
            return self._result("L2-QEMU运行态", False, f"数据库未找到 {name}")
        deadline = time.time() + max(0, int(wait_timeout))
        values = self._runtime_values(row)
        while wait_timeout and time.time() < deadline:
            running_now = bool(
                values["pid"] and f"-name {name}" in values["cmdline"]
            )
            if running_now == bool(expect_running):
                break
            time.sleep(1)
            row = self.find_vm(name) or row
            values = self._runtime_values(row)
        pid = values["pid"]
        actual_running = bool(
            pid and "qemu-system-x86_64" in values["cmdline"]
            and f"-name {name}" in values["cmdline"]
        )
        expected_quota = 1000000 * int(row.get("cpu_usage", 0) or 0) // 100
        if expect_running:
            checks = {
                "db_enabled": row.get("enabled") == "yes",
                "process": actual_running,
                "config": "#qemu config" in values["config"],
                "memory": f'size = "{row.get("mem_size")}"' in values["config"],
                "cores": f'cores = "{row.get("cpu_cores")}"' in values["config"],
                "quota": values["quota"] == str(expected_quota),
                "cgroup_task": str(pid) in values["tasks"],
                "kvm_mode": (
                    ('accel = "kvm"' in values["config"] and "-cpu host" in values["cmdline"])
                    if str(row.get("accel")) == "1" else
                    ('accel = "kvm"' not in values["config"] and "-cpu host" not in values["cmdline"])
                ),
            }
        else:
            checks = {
                "db_disabled": row.get("enabled") == "no",
                "process_absent": not actual_running,
                "pid_absent": pid == 0,
            }
        failed = [key for key, ok in checks.items() if not ok]
        passed = not failed
        qemu_log = ""
        if failed:
            qemu_log = self._exec(f"tail -n 80 /tmp/qemu_{int(row['id'])}.log 2>/dev/null")
        raw = (
            f"id={values['id']} pid={pid} quota={values['quota']} tasks={values['tasks']}\n"
            f"checks={checks}\nqemu_log={qemu_log or '(无输出)'}\n"
            f"cmdline={values['cmdline']}\nconfig={values['config']}"
        )
        qid = int(row["id"])
        commands = [
            self._manual(
                "router", "核对 QEMU 进程和启动参数",
                f"ps w | grep '[q]emu-system-x86_64.*-name {name}'",
                f"输出包含 qemu-system-x86_64 -name {name}",
                actual=f"pid={pid}; running={actual_running}",
            ),
            self._manual(
                "router", "查看虚拟机生成配置",
                f"sed -n '1,240p' {self.RUNTIME_ROOT}/{qid}/config",
                "内存、CPU、磁盘、网卡、VNC 与数据库一致",
                actual=values["config"],
            ),
            self._manual(
                "router", "核对虚拟机 CPU 配额",
                f"cat {self.CGROUP_ROOT}/qemu_{qid}/cpu.cfs_quota_us",
                f"输出 {expected_quota}", actual=values["quota"],
            ),
        ]
        if failed:
            commands.append(self._manual(
                "router", "查看 QEMU 启动或退出错误日志",
                f"tail -n 80 /tmp/qemu_{qid}.log",
                "无启动报错；若进程缺失，日志应直接给出失败原因",
                actual=qemu_log or "(无输出：QEMU尚未进入可记录错误的启动阶段)",
            ))
        return self._result(
            "L2-QEMU运行态", passed,
            f"QEMU {'运行' if expect_running else '停止'}态{'一致' if passed else '不一致'}"
            + ("" if passed else f": {failed}"),
            raw=raw,
            details={
                "pid": pid,
                "checks": checks,
                "qemu_log": self._short(qemu_log, 300) if failed else "",
            },
            commands=commands,
        )

    @staticmethod
    def _parse_vdisk(vdisk: Any) -> List[Dict[str, str]]:
        result = []
        for index, entry in enumerate(str(vdisk or "").split(",")):
            if not entry:
                continue
            parts = entry.split("@")
            if len(parts) < 4:
                result.append({"index": str(index), "raw": entry, "type": "invalid"})
                continue
            result.append({
                "index": str(index), "type": parts[0], "size": parts[1],
                "name": parts[2], "method": parts[3], "raw": entry,
            })
        return result

    def verify_storage(self, name: str) -> VerifyResult:
        name = self._require_name(name)
        row = self.find_vm(name)
        if not row:
            return self._result("L2-存储载体", False, f"数据库未找到 {name}")
        part = self._require_part(str(row["partname"]))
        qid = int(row["id"])
        config = self._exec(f"cat {self.RUNTIME_ROOT}/{qid}/config 2>/dev/null")
        evidence: List[str] = []
        checks: Dict[str, bool] = {}
        iso = str(row.get("iso") or "")
        if iso:
            iso_path = f"{self.DATA_ROOT}{iso}"
            iso_proof = self._exec(f"test -f {iso_path} && sha256sum {iso_path}")
            evidence.append(iso_proof)
            checks["iso_exists"] = bool(iso_proof.strip())
            checks["iso_in_config"] = f'file = "{iso_path}"' in config
        disks = self._parse_vdisk(row.get("vdisk"))
        for disk in disks:
            dtype = disk.get("type")
            dname = disk.get("name", "")
            key = f"disk_{disk.get('index')}"
            if dtype == "create":
                path = f"{self.DATA_ROOT}/{part}/KVM/{name}/{dname}.img"
            elif dtype == "bootimg":
                path = f"{self.DATA_ROOT}{dname}"
            elif dtype in {"partname", "partname_virtio"}:
                path = f"/dev/{dname}"
            else:
                checks[key] = False
                continue
            proof = self._exec(f"qemu-img info {path} 2>&1", timeout=30)
            evidence.append(f"{path}\n{proof}")
            checks[key] = (
                ("file format: qcow2" in proof if dtype != "partname" else bool(proof))
                and f'file\t= "{path}"' in config.replace("    ", "\t")
                or f'file = "{path}"' in config
            )
        checks["has_boot_media"] = bool(iso or disks)
        failed = [key for key, ok in checks.items() if not ok]
        commands = [
            self._manual(
                "router", "查看测试虚拟机磁盘镜像信息",
                f"find {self.DATA_ROOT}/{part}/KVM/{name} -maxdepth 1 -type f -name '*.img' -exec qemu-img info {{}} \\;",
                "新建盘均为 qcow2，虚拟大小与页面配置一致",
                actual="\n".join(evidence),
            )
        ]
        return self._result(
            "L2-存储载体", not failed,
            f"ISO/新建盘/引用盘{'均已落地' if not failed else '存在异常: ' + str(failed)}",
            raw="\n".join(evidence), details={"checks": checks, "disks": disks},
            commands=commands,
        )

    # ---------------------------- L3 networking ----------------------------
    @staticmethod
    def _parse_nics(brname: Any) -> List[Dict[str, str]]:
        result = []
        for index, entry in enumerate(str(brname or "").split(","), start=1):
            if not entry:
                continue
            parts = entry.split("@")
            if len(parts) >= 2:
                result.append({
                    "index": str(index), "bridge": parts[0], "mac": parts[1],
                    "method": parts[2] if len(parts) > 2 else "none",
                })
        return result

    def verify_network(self, name: str, *, expect_running: bool = True) -> VerifyResult:
        name = self._require_name(name)
        row = self.find_vm(name)
        if not row:
            return self._result("L3-TAP桥接", False, f"数据库未找到 {name}")
        qid = int(row["id"])
        nics = self._parse_nics(row.get("brname"))
        config = self._exec(f"cat {self.RUNTIME_ROOT}/{qid}/config 2>/dev/null")
        pid = self._runtime_values(row)["pid"]
        cmdline = self._exec(
            f"test -r /proc/{pid}/cmdline && tr '\\000' ' ' < /proc/{pid}/cmdline"
        ) if pid else ""
        checks: Dict[str, bool] = {}
        evidence = []
        for nic in nics:
            tap = f"qtap{qid}_{nic['bridge']}_{nic['index']}"
            link = self._exec(f"ip link show {tap} 2>/dev/null")
            bridge = self._exec(f"brctl show {nic['bridge']} 2>/dev/null")
            evidence.append(f"{tap}\n{link}\n{bridge}")
            if expect_running:
                checks[f"{tap}_link"] = "state UP" in link or "UP," in link
                checks[f"{tap}_bridge"] = tap in bridge
                checks[f"{tap}_mac"] = (
                    nic["mac"].lower() in (config + cmdline).lower()
                )
            else:
                checks[f"{tap}_absent"] = not link.strip() and tap not in bridge
        failed = [key for key, ok in checks.items() if not ok]
        commands = []
        for nic in nics[:4]:
            tap = f"qtap{qid}_{nic['bridge']}_{nic['index']}"
            commands.append(self._manual(
                "router", f"核对 {tap} 已接入 {nic['bridge']}",
                f"brctl show {nic['bridge']}",
                f"输出包含 {tap}" if expect_running else f"输出不包含 {tap}",
                actual="\n".join(evidence),
            ))
        return self._result(
            "L3-TAP桥接", not failed,
            f"{len(nics)} 块虚拟网卡与桥接{'一致' if not failed else '不一致: ' + str(failed)}",
            raw="\n".join(evidence), details={"checks": checks, "nics": nics},
            commands=commands,
        )

    def verify_vnc(self, name: str, *, expect_external: bool) -> VerifyResult:
        name = self._require_name(name)
        row = self.find_vm(name)
        if not row:
            return self._result("L3-VNC监听", False, f"数据库未找到 {name}")
        port = int(row.get("vnc_port", 0) or 0)
        qid = int(row["id"])
        listener = self._exec(
            f"netstat -lnt 2>/dev/null | grep ':{port} ' || true"
        )
        config = self._exec(f"cat {self.RUNTIME_ROOT}/{qid}/config 2>/dev/null")
        client_rfb = self._client().exec(
            f"timeout 3 nc {self.backend._ssh_config.router.host} {port} | head -c 12",
            timeout=8,
        )
        external_ok = client_rfb.startswith("RFB ")
        acl_ok = int(row.get("vnc_acl", -1)) == (0 if expect_external else 1)
        display = port - 5900
        config_ok = (
            f'vnc = ":{display}"' in config
            if expect_external else f'vnc = "127.0.0.1:{display}"' in config
        )
        listener_ok = True if expect_external else f"127.0.0.1:{port}" in listener
        passed = acl_ok and config_ok and listener_ok and external_ok == expect_external
        commands = [
            self._manual(
                "router", "核对 VNC 监听地址",
                f"netstat -lnt | grep ':{port} '",
                "监听所有地址" if expect_external else "仅监听 127.0.0.1",
                actual=listener,
            ),
            self._manual(
                "client", "从测试客户端验证 VNC 外部访问策略",
                f"timeout 3 nc {self.backend._ssh_config.router.host} {port}",
                "首行以 RFB 开头" if expect_external else "连接失败或无 RFB 握手",
                actual=client_rfb,
                effect="向虚拟机 VNC 端口建立一次协议握手连接",
            ),
        ]
        return self._result(
            "L3-VNC监听", passed,
            f"VNC {port} 配置已生成，外部访问{'允许' if expect_external else '阻断'}策略"
            f"{'正确' if passed else '异常'}",
            raw=f"listener={listener}\nconfig={config}\nclient={client_rfb!r}",
            details={"port": port, "external_rfb": external_ok}, commands=commands,
        )

    # -------------------------- L4 consistency -----------------------------
    def verify_consistency(self, prefix: str) -> VerifyResult:
        prefix = self._require_prefix(prefix)
        rows = self._select_rows(f"name LIKE {self._sql_literal(prefix + '%')}")
        checks: Dict[str, bool] = {}
        evidence = []
        for row in rows:
            name = str(row["name"])
            qid = int(row["id"])
            runtime = self._runtime_values(row)
            running = bool(runtime["pid"] and f"-name {name}" in runtime["cmdline"])
            should_run = row.get("enabled") == "yes"
            checks[f"{qid}_process"] = running == should_run
            checks[f"{qid}_runtime_dir"] = bool(
                self._exec(f"test -d {self.RUNTIME_ROOT}/{qid} && echo yes").strip()
            )
            for nic in self._parse_nics(row.get("brname")):
                tap = f"qtap{qid}_{nic['bridge']}_{nic['index']}"
                exists = bool(self._exec(f"ip link show {tap} 2>/dev/null").strip())
                checks[f"{qid}_{tap}"] = exists == should_run
            evidence.append(
                f"id={qid} name={name} enabled={row.get('enabled')} pid={runtime['pid']}"
            )
        failed = [key for key, ok in checks.items() if not ok]
        sql = (
            f"SELECT id,enabled,name,partname,brname,vnc_port FROM {self.TABLE} "
            f"WHERE name LIKE {self._sql_literal(prefix + '%')} ORDER BY id"
        )
        command = self._manual(
            "router", "核对测试虚拟机 DB 与运行态一致",
            f"sqlite3 -header -column {self.DB} {json.dumps(sql)}",
            "enabled=yes 的行有对应 QEMU/TAP；enabled=no 的行无 QEMU/TAP",
            actual="\n".join(evidence),
        )
        return self._result(
            "L4-全链路一致性", not failed,
            f"DB→QEMU→TAP 一致性{'通过' if not failed else '失败: ' + str(failed)}",
            raw="\n".join(evidence), details={"checks": checks}, commands=[command],
        )

    # ------------------------------ L5 guest -------------------------------
    def wait_guest_network(
        self,
        name: str,
        mac: str,
        *,
        timeout: int = 60,
        client_iface: str = "ens11",
    ) -> VerifyResult:
        name = self._require_name(name)
        if not self.SAFE_MAC.fullmatch(str(mac or "")):
            raise ValueError("invalid guest MAC")
        mac = str(mac).lower()
        deadline = time.time() + max(5, int(timeout))
        lease = ""
        guest_ip = ""
        ping = ""
        route = ""
        passed = False
        while time.time() < deadline:
            sql = (
                "SELECT interface,ip_addr,mac,hostname,end_time FROM leases "
                f"WHERE lower(mac)='{mac}' ORDER BY id DESC LIMIT 1"
            )
            lease = self._exec(
                "sqlite3 -separator '|' /tmp/db/leases.db " + json.dumps(sql)
            ).strip()
            parts = lease.split("|") if lease else []
            guest_ip = parts[1] if len(parts) >= 2 else ""
            if re.fullmatch(r"192\.168\.148\.\d{1,3}", guest_ip):
                route = self._client().exec(f"ip route get {guest_ip}", timeout=10)
                ping = self._client().exec(
                    f"ping -I {client_iface} -c 3 -W 2 {guest_ip}", timeout=15
                )
                passed = (
                    parts[0] == "lan1" and "dev ens11" in route
                    and ("3 packets received" in ping or "3 received" in ping)
                )
                if passed:
                    break
            time.sleep(2)
        commands = []
        if guest_ip:
            commands.extend([
                self._manual(
                    "router", "查看来宾系统 DHCP 租约",
                    f"sqlite3 -header -column /tmp/db/leases.db \"SELECT interface,ip_addr,mac,hostname,end_time FROM leases WHERE lower(mac)='{mac}' ORDER BY id DESC LIMIT 1\"",
                    f"interface=lan1，ip_addr={guest_ip}，mac={mac}",
                    actual=lease,
                ),
                self._manual(
                    "client", "经 ens11 实际访问虚拟机来宾系统",
                    f"ping -I {client_iface} -c 3 -W 2 {guest_ip}",
                    "3 个 ICMP 报文全部收到回复",
                    actual=ping,
                    effect="从测试客户端向来宾系统发送3个ICMP报文",
                ),
            ])
        return self._result(
            "L5-来宾数据面", passed,
            (
                f"Tiny Core 来宾获得 {guest_ip}，ens11 三次 ping 全部成功"
                if passed else
                f"来宾 DHCP/ens11 ping 未形成完整证据 (lease={lease!r})"
            ),
            raw=f"lease={lease}\nroute={route}\nping={ping}",
            details={"guest_ip": guest_ip, "mac": mac}, commands=commands,
        )

    # -------------------------- snapshots and cleanup ----------------------
    def _first_snapshot_image(self, row: Mapping[str, Any]) -> str:
        name = str(row["name"])
        part = str(row["partname"])
        for disk in self._parse_vdisk(row.get("vdisk")):
            if disk.get("type") == "create":
                return f"{self.DATA_ROOT}/{part}/KVM/{name}/{disk['name']}.img"
            if disk.get("type") == "bootimg":
                return f"{self.DATA_ROOT}{disk['name']}"
        return ""

    def verify_snapshot(self, name: str, snapshot_name: str, *, expect_present: bool) -> VerifyResult:
        name = self._require_name(name)
        if not self.SAFE_SNAPSHOT.fullmatch(str(snapshot_name or "")):
            raise ValueError("invalid snapshot name")
        row = self.find_vm(name)
        if not row:
            return self._result("L2-磁盘快照", False, f"数据库未找到 {name}")
        image = self._first_snapshot_image(row)
        output = self._exec(f"qemu-img snapshot -l {image} 2>&1") if image else ""
        present = bool(re.search(rf"(?:^|\s){re.escape(snapshot_name)}(?:\s|$)", output))
        passed = bool(image) and present == bool(expect_present)
        cmd = self._manual(
            "router", "核对虚拟机磁盘快照",
            f"qemu-img snapshot -l {image}",
            f"列表{'包含' if expect_present else '不包含'} {snapshot_name}",
            actual=output,
        ) if image else None
        return self._result(
            "L2-磁盘快照", passed,
            f"快照 {snapshot_name} {'存在' if present else '不存在'}，符合预期={expect_present}",
            raw=output, details={"image": image, "present": present},
            commands=[cmd] if cmd else [],
        )

    def audit_cleanup(
        self,
        prefix: str,
        *,
        owned_ids: Sequence[int] = (),
        reference_directory: str = "",
    ) -> VerifyResult:
        prefix = self._require_prefix(prefix)
        ids = sorted({int(value) for value in owned_ids if int(value) > 0})
        db_count = int(self._exec(
            f"sqlite3 {self.DB} \"SELECT count(*) FROM {self.TABLE} "
            f"WHERE name LIKE '{prefix}%'\""
        ).strip() or 0)
        process = self._exec(
            f"ps w | awk '$5 ~ /qemu-system-x86_64/ && $7 ~ /^{prefix}/ {{print}}'"
        )
        artifacts: Dict[str, Any] = {"db_count": db_count, "process": process.strip()}
        for qid in ids:
            artifacts[f"runtime_{qid}"] = bool(self._exec(
                f"test -e {self.RUNTIME_ROOT}/{qid} && echo present"
            ).strip())
            artifacts[f"tap_{qid}"] = bool(self._exec(
                f"ip link show 2>/dev/null | grep 'qtap{qid}_'"
            ).strip())
            artifacts[f"cgroup_{qid}"] = bool(self._exec(
                f"test -d {self.CGROUP_ROOT}/qemu_{qid} && echo present"
            ).strip())
        artifacts["disk_dirs"] = self._exec(
            f"for d in {self.DATA_ROOT}/*/KVM/{prefix}*; do test -d \"$d\" && echo \"$d\"; done"
        ).strip()
        if reference_directory:
            artifacts["reference_directory"] = bool(self._exec(
                f"test -e {reference_directory} && echo present"
            ).strip())
        residual = [
            key for key, value in artifacts.items()
            if (key == "db_count" and value != 0)
            or (key != "db_count" and bool(value))
        ]
        sql = f"SELECT id,name,enabled FROM {self.TABLE} WHERE name LIKE '{prefix}%'"
        commands = [
            self._manual(
                "router", "测试结束后复核数据库无虚拟机残留",
                f"sqlite3 -header -column {self.DB} {json.dumps(sql)}",
                "无输出", actual=f"count={db_count}", valid_when="测试结束后仍有效",
            ),
            self._manual(
                "router", "测试结束后复核无 QEMU 测试进程",
                f"ps w | grep '[q]emu-system-x86_64.*-name {prefix}'",
                "无输出", actual=process, valid_when="测试结束后仍有效",
            ),
        ]
        return self._result(
            "L4-残留审计", not residual,
            "虚拟机测试数据、进程、TAP、运行目录、cgroup、磁盘目录均无残留"
            if not residual else f"检测到残留: {residual}",
            raw=json.dumps(artifacts, ensure_ascii=False, sort_keys=True),
            details={"artifacts": artifacts, "residual": residual}, commands=commands,
        )

    def cleanup_test(
        self,
        prefix: str,
        *,
        owned_ids: Sequence[int] = (),
        reference_directory: str = "",
    ) -> Dict[str, Any]:
        """Remove only objects proven to belong to this randomized test prefix."""
        prefix = self._require_prefix(prefix)
        rows = self._select_rows(f"name LIKE {self._sql_literal(prefix + '%')}")
        ids = {int(row["id"]) for row in rows}
        ids.update(int(value) for value in owned_ids if int(value) > 0)
        owned_names = [str(row["name"]) for row in rows]
        for row in rows:
            self._exec(f"{self.SCRIPT} del id={int(row['id'])}", timeout=70)
        # qemu.sh del launches __qemu_clear in the background. A guest without
        # ACPI can require the full 30-second graceful-stop window. Only wait
        # when this call actually submitted rows for deletion; an already
        # orphaned process has no product-side worker left to wait for.
        if rows:
            deadline = time.time() + 45
            while time.time() < deadline:
                process_left = any(bool(self._exec(
                    f"ps w | grep '[q]emu-system-x86_64.*-name {name}'"
                ).strip()) for name in owned_names)
                runtime_left = any(bool(self._exec(
                    f"test -e {self.RUNTIME_ROOT}/{qid} && echo present"
                ).strip()) for qid in ids)
                if not process_left and not runtime_left:
                    break
                time.sleep(1)

        # The init/del race can remove both the DB row and runtime directory,
        # then start QEMU afterwards. Discover that state from the process
        # command line itself. The random prefix is validated before it enters
        # awk, and every returned PID is parsed as an integer before signalling.
        pid_command = (
            "ps w | awk '$5 ~ /qemu-system-x86_64$/ "
            f"&& $6 == \"-name\" && $7 ~ /^{prefix}/ {{print $1}}'"
        )

        def process_pids() -> List[int]:
            output = self._exec(pid_command)
            return sorted({
                int(value) for value in output.split()
                if value.isdigit() and int(value) > 1
            })

        term_pids = process_pids()
        if term_pids:
            self._exec("kill -TERM " + " ".join(map(str, term_pids)))
            deadline = time.time() + 8
            while time.time() < deadline and process_pids():
                time.sleep(1)
        kill_pids = process_pids()
        if kill_pids:
            self._exec("kill -KILL " + " ".join(map(str, kill_pids)))
            deadline = time.time() + 4
            while time.time() < deadline and process_pids():
                time.sleep(0.5)
        remaining_pids = process_pids()

        # IDs come from this run's observed DB rows. Guard against ID reuse
        # before removing exact qtap<ID>_* and runtime paths.
        taps_cleaned = []
        runtimes_cleaned = []
        for qid in sorted(ids):
            db_count = int(self._exec(
                f"sqlite3 {self.DB} 'SELECT count(*) FROM {self.TABLE} WHERE id={qid}'"
            ).strip() or 0)
            if db_count:
                continue
            self._exec(
                "for tap in $(ip -o link show | awk -F': ' "
                f"'$2 ~ /^qtap{qid}_/ {{sub(/@.*/, \"\", $2); print $2}}'); "
                "do ip link del \"$tap\" 2>/dev/null; done"
            )
            taps_cleaned.append(qid)
            self._exec(f"rm -rf {self.RUNTIME_ROOT}/{qid}")
            runtimes_cleaned.append(qid)

        # Recover disk directories whose add/del transaction lost its DB row.
        # The fixed glob remains contained under KVM and the validated prefix.
        self._exec(
            f"for d in {self.DATA_ROOT}/*/KVM/{prefix}*; do "
            "test -d \"$d\" || continue; rm -rf \"$d\"; done",
            timeout=40,
        )
        if reference_directory:
            expected = f"{self.DATA_ROOT}/888/.ikuai_vm_test/{prefix}"
            if reference_directory != expected:
                raise ValueError("reference directory is outside the owned test path")
            marker = f"{reference_directory}/.owner"
            owner = self._exec(f"cat {marker} 2>/dev/null").strip()
            if owner == prefix:
                self._exec(f"rm -rf {reference_directory}")
        removed_cgroups = []
        for qid in sorted(ids):
            command = (
                f"test \"$(sqlite3 {self.DB} 'SELECT count(*) FROM {self.TABLE} WHERE id={qid}')\" = 0 "
                f"&& test ! -s {self.CGROUP_ROOT}/qemu_{qid}/tasks "
                f"&& rmdir {self.CGROUP_ROOT}/qemu_{qid} 2>/dev/null || true"
            )
            self._exec(command)
            if not self._exec(
                f"test -d {self.CGROUP_ROOT}/qemu_{qid} && echo present"
            ).strip():
                removed_cgroups.append(qid)
        return {
            "rows_deleted": len(rows),
            "ids": sorted(ids),
            "processes": {
                "term_pids": term_pids,
                "kill_pids": kill_pids,
                "remaining_pids": remaining_pids,
            },
            "taps_cleaned": taps_cleaned,
            "runtimes_cleaned": runtimes_cleaned,
            "cgroups_removed": removed_cgroups,
        }


__all__ = ["QemuVerifier"]
