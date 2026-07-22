"""Advanced Service > Virtual Machine L1-L5 comprehensive test.

This is intentionally one report node: every user operation is paired with
its expected result and the DB/runtime/data-plane evidence needed to reproduce
the conclusion manually.
"""

from __future__ import annotations

import json
import secrets
import time

import pytest

from utils.step_recorder import StepRecorder, register_sensitive_value
from utils.verify_helper import make_ssh_verify


pytestmark = [
    pytest.mark.advanced_service,
    pytest.mark.virtual_machine,
    pytest.mark.p1,
]


def _mac(suffix: int) -> str:
    """Return a deterministic locally administered QEMU MAC for this run."""
    return f"52:54:00:7a:{(suffix // 256) & 0xff:02x}:{suffix & 0xff:02x}"


class TestVirtualMachineComprehensive:
    def test_virtual_machine_comprehensive(
        self,
        virtual_machine_page_logged_in,
        backend_verifier,
        step_recorder: StepRecorder,
    ):
        page = virtual_machine_page_logged_in
        rec = step_recorder
        qv = backend_verifier.get_qemu_verifier()

        token = secrets.token_hex(3)
        prefix = f"qvm_{token}_"
        vm_name = f"{prefix}main"
        aux_name = f"{prefix}aux"
        batch_names = [f"{prefix}batch1", f"{prefix}batch2"]
        disk_name = "system"
        snapshot_name = f"snap_{token}"
        # The product accepts letters and digits only for VNC passwords.
        vnc_password = "Qv9" + secrets.token_hex(6)
        register_sensitive_value(vnc_password)

        failures = []
        product_failures = []
        owned_ids = []
        baseline = None
        reference = {}
        vnc_port = None
        second_vnc_port = None
        primary_mac = ""

        ssh_verify = make_ssh_verify(
            backend_verifier, rec, failures, must_pass_default=True
        )

        def section(area, status, operation, expected, actual):
            rec.add_detail(f"【{area}】{status}")
            rec.add_detail(f"  操作：{operation}")
            rec.add_detail(f"  预期：{expected}")
            rec.add_detail(f"  实际：{actual}")

        def ui_check(label, condition, actual, expected="满足测试用例预期", *, product=False):
            ok = bool(condition)
            section(
                "页面验证", "通过" if ok else "失败", label, expected,
                actual if isinstance(actual, str) else json.dumps(actual, ensure_ascii=False),
            )
            if not ok:
                target = product_failures if product else failures
                target.append(f"页面-{label}: {actual}")
            return ok

        def backend_section(label, result):
            if result is None:
                return False
            section(
                f"后端验证·{result.level}",
                "通过" if result.passed else "失败",
                label,
                "页面配置必须在数据库、QEMU运行态和真实数据面一致",
                result.message,
            )
            return bool(result.passed)

        def require_backend(label, method, *args, **kwargs):
            result = ssh_verify(label, method, *args, must_pass=True, **kwargs)
            backend_section(label, result)
            return result

        def observe_product_backend(label, method, *args, **kwargs):
            result = ssh_verify(label, method, *args, must_pass=False, **kwargs)
            backend_section(label, result)
            if result is not None and not result.passed:
                product_failures.append(f"{label}: {result.message}")
            return result

        try:
            with rec.step(
                "步骤1 操作：建立随机命名空间与测试前快照；验证：只清理本轮前缀且非测试虚拟机有稳定指纹",
                "操作：生成唯一 qvm_* 前缀、动态VNC端口并读取qemu_new_config；验证：不会覆盖现有虚拟机",
            ):
                qv.cleanup_test(prefix)
                baseline = qv.snapshot_non_test_state(prefix)
                vnc_port = qv.reserve_vnc_port(5999)
                ui_check(
                    "随机前缀与动态端口隔离",
                    prefix.startswith("qvm_") and 5901 <= vnc_port <= 5999,
                    {"prefix": prefix, "vnc_port": vnc_port, "non_test_rows": baseline["count"]},
                    "前缀唯一、VNC端口在5901-5999且未被DB/监听占用",
                )
                state = require_backend(
                    "L4-测试前非测试数据指纹", qv.verify_non_test_state,
                    prefix, baseline,
                )
                rec.set_actual({
                    "prefix": prefix,
                    "vnc_port": vnc_port,
                    "baseline_count": baseline["count"],
                    "baseline_ok": bool(state and state.passed),
                })

            with rec.step(
                "步骤2 操作：检查qemu.sh、KVM、QEMU与888磁盘；验证：脚本入口、硬件虚拟化和空间满足启动条件",
                "操作：只读检查/usr/ikuai/script/qemu.sh、/dev/kvm、QEMU版本与888挂载；验证：至少512MB可用空间",
            ):
                env_result = require_backend("环境前置", qv.verify_environment, "888")
                image_result = require_backend(
                    "L5-TinyCore镜像", qv.ensure_test_image, "888"
                )
                reference = qv.prepare_reference_image(prefix, "888")
                ui_check(
                    "隔离引用盘准备",
                    bool(reference.get("ui_path", "").startswith("/888/.ikuai_vm_test/")),
                    {"ui_path": reference.get("ui_path", "")},
                    "在888的随机测试目录创建独立64MB qcow2，不复用用户镜像",
                )
                rec.set_actual({
                    "environment": getattr(env_result, "passed", False),
                    "test_image": getattr(image_result, "passed", False),
                    "reference_image": reference.get("ui_path", ""),
                })

            with rec.step(
                "步骤3 操作：调查虚拟机列表；验证：表头、添加、帮助和不适用能力与真实页面一致",
                "操作：读取列表DOM能力矩阵；验证：无伪造的搜索、导入导出、批量或排序用例",
            ):
                page.navigate_to_virtual_machine()
                structure = page.inspect_list_structure()
                capabilities = page.capability_matrix()
                expected_headers = {
                    "虚拟机名称", "安装磁盘", "CPU核心", "虚拟机内存",
                    "VNC端口", "开机自启", "运行时长", "运行状态", "操作",
                }
                ui_check(
                    "列表九类核心列",
                    expected_headers.issubset(set(structure["headers"])),
                    structure,
                    "列表包含名称、磁盘、CPU、内存、VNC、自启、时长、状态和操作",
                )
                ui_check(
                    "搜索入口",
                    capabilities["search"]["supported"], capabilities["search"],
                    "列表工具栏提供搜索输入框，功能在新增后执行",
                )
                ui_check(
                    "批量删除入口",
                    capabilities["batch"]["supported"], capabilities["batch"],
                    "表格提供选择列，选中行后出现删除按钮，最终清理时实测",
                )
                for key in ("import", "export", "sorting"):
                    supported = bool(capabilities[key]["supported"])
                    section(
                        "不适用", "不适用" if not supported else "失败",
                        key,
                        "页面和qemu后端均未提供该入口时应标记不适用",
                        "页面无入口" if not supported else "检测到入口，需补充执行用例",
                    )
                    if supported:
                        failures.append(f"能力调查-{key}出现新入口但用例未执行")
                help_result = page.inspect_help()
                ui_check(
                    "帮助入口",
                    help_result.get("opened") and "ikuai8.com" in help_result.get("url", ""),
                    help_result,
                    "打开爱快官方虚拟机帮助页",
                )
                rec.set_actual({"structure": structure, "capabilities": capabilities})

            with rec.step(
                "步骤4 操作：检查添加表单；验证：磁盘、系统类型、默认值和全部核心控件",
                "操作：进入添加页并展开安装磁盘/系统类型；验证：888、Linux/Windows/其他及默认CPU/VNC/自启",
            ):
                ui_check("进入添加虚拟机", page.open_add_page(), page.page.url)
                form = page.inspect_add_form()
                ui_check(
                    "核心字段完整",
                    all(form["fields"].values()), form["fields"],
                    "安装盘、名称、CPU、内存、光驱、VNC、自启、UEFI、硬件加速控件全部存在",
                )
                ui_check(
                    "安装磁盘包含888",
                    "888" in form["disk_options"], form["disk_options"],
                )
                ui_check(
                    "系统类型全集",
                    set(form["os_options"]) == {"Linux", "Windows", "其他"},
                    form["os_options"],
                )
                ui_check(
                    "默认值",
                    form["defaults"]["cpu_usage"] == "100"
                    and form["defaults"]["cpu_cores"] == "1"
                    and form["defaults"]["vnc_port"] == "5901"
                    and form["defaults"]["auto_start"],
                    form["defaults"],
                    "CPU=100%、核心=1、VNC=5901、开机自启默认开启",
                )
                page.select_install_disk("888")
                file_manager = page.inspect_iso_file_manager()
                ui_check(
                    "ISO文件管理",
                    file_manager.get("opened")
                    and "/equipmentSetting/diskManagement" in file_manager.get("url", ""),
                    file_manager,
                    "文件管理新窗口打开磁盘管理；888和镜像由安装盘下拉及L2继续验证",
                )
                rec.set_actual({"form": form, "file_manager": file_manager})

            with rec.step(
                "步骤5 操作：枚举磁盘/网卡/USB设备；验证：三种磁盘、五种网卡模式和共享DUT安全边界",
                "操作：逐一切换设备类型并读取选项；验证：物理分区和PCI直通有入口但不在共享设备执行",
            ):
                devices = page.inspect_device_capabilities()
                ui_check(
                    "三种磁盘类型",
                    {"新建设备", "引用磁盘", "引用分区"}.issubset(
                        set(devices["disk"].get("disk_types", []))
                    ),
                    devices["disk"],
                )
                ui_check(
                    "五种网卡模式",
                    {"默认", "半虚拟化模式", "e1000e", "vmxnet3", "PCI直通"}.issubset(
                        set(devices["network"].get("modes", []))
                    ),
                    devices["network"],
                )
                ui_check(
                    "lan1桥接可选",
                    any("lan1" in option for option in devices["network"].get("bridges", [])),
                    devices["network"].get("bridges", []),
                )
                usb_options = devices["usb"].get("available_options", [])
                section(
                    "不适用", "不适用" if not usb_options else "通过",
                    "USB直通",
                    "无可用USB时记录环境不适用；有设备时必须显示候选项",
                    "当前无可用USB设备" if not usb_options else usb_options,
                )
                section(
                    "不适用", "不适用", "物理分区直通",
                    "共享DUT不得卸载系统/数据分区",
                    "qemu.sh对partname执行umount；仅验证入口，不执行破坏性动作",
                )
                section(
                    "不适用", "不适用", "PCI物理网卡直通",
                    "不得解绑管理或业务网卡",
                    "qemu.sh会绑定vfio-pci；仅验证PCI直通选项，不执行",
                )
                rec.set_actual(devices)

            with rec.step(
                "步骤6 操作：执行必填和数值边界；验证：名称、CPU、内存、VNC端口均在前端阻断非法值",
                "操作：提交空表单并测试64/65字符、CPU 0/101/字符、内存63、VNC 5900/6000；验证：不发起有效新增",
            ):
                page.navigate_to_virtual_machine()
                page.open_add_page()
                required = page.required_validation()
                ui_check(
                    "空表单必填阻断",
                    required["blocked"] and len(required["errors"]) >= 3,
                    required,
                    "停留添加页并显示安装盘、名称、内存等必填错误",
                )
                rejected_boundaries = [
                    page.validate_field("vm_name", "n" * 65),
                    page.validate_field("cpu_usage", "0"),
                    page.validate_field("cpu_usage", "101"),
                    page.validate_field("cpu_usage", "abc"),
                    page.validate_field("mem_size", "63"),
                ]
                vnc_boundaries = [
                    page.validate_field("vnc_port", "5900"),
                    page.validate_field("vnc_port", "6000"),
                ]
                ui_check(
                    "五组非法边界全部拒绝",
                    all(item["rejected"] for item in rejected_boundaries),
                    rejected_boundaries,
                    "名称>64、CPU非1-100/非数字、内存<64均显示字段错误",
                )
                ui_check(
                    "VNC端口边界归一化",
                    [item["actual_value"] for item in vnc_boundaries] == ["5901", "5999"],
                    vnc_boundaries,
                    "Ant InputNumber 将5900钳制为5901、6000钳制为5999",
                )
                # Produce a dirty form and prove both the warning and discard branch.
                page._fill("vm_name", f"{prefix}dirty")
                cancel = page.cancel_form(discard=True)
                ui_check(
                    "未保存退出确认",
                    cancel["prompted"] and page.is_list_page(), cancel,
                    "修改表单后取消必须提示，确认后回到列表且不新增",
                )
                rec.set_actual({
                    "required": required, "rejected_boundaries": rejected_boundaries,
                    "vnc_boundaries": vnc_boundaries, "cancel": cancel,
                })

            with rec.step(
                "步骤7 操作：创建最小Linux虚拟机；验证：TinyCore ISO与默认lan1网卡一次落库",
                "操作：888+TinyCore ISO+默认网卡；验证：先形成可启动控制组，磁盘和多网卡在后续停机编辑中加入",
            ):
                ui_check("重新进入添加页", page.open_add_page(), page.page.url)
                page.fill_vm_form(
                    name=vm_name,
                    partname="888",
                    system="Linux",
                    cpu_usage=50,
                    cpu_cores=1,
                    memory_mb=256,
                    iso_path="/888/CorePure64-16.2.iso",
                    vnc_port=vnc_port,
                    vnc_external=True,
                    vnc_password=vnc_password,
                    auto_start=False,
                    uefi=False,
                    hardware_accel=True,
                )
                default_rows = page.default_device_rows()
                primary_mac = default_rows[0]["mac"] if default_rows else ""
                device_rows = page.default_device_rows()
                save = page.save_form(timeout=45000)
                ui_check(
                    "添加Linux虚拟机",
                    save.get("success") and page.wait_rule_exists(vm_name), save,
                    "显示添加成功、返回列表且出现唯一测试行",
                )
                if not save.get("success"):
                    raise AssertionError(f"主虚拟机添加失败，停止后续级联验证: {save.get('error', save)}")
                ui_check(
                    "最小启动设备",
                    bool(primary_mac) and len(device_rows) == 1,
                    {"primary_mac": primary_mac, "rows": device_rows},
                    "保存前仅有默认lan1网卡，ISO由光驱字段提供",
                )
                db = require_backend(
                    "L1-新增记录", qv.verify_database, vm_name,
                    {
                        "enabled": "yes", "partname": "888", "system": "Linux",
                        "accel": "1", "mem_size": "256", "cpu_usage": "50",
                        "cpu_cores": "1", "iso": "/888/CorePure64-16.2.iso",
                        "uefi": "0", "vnc_port": str(vnc_port), "vnc_acl": "0",
                        "auto_start": "0",
                    },
                )
                if db and db.details.get("rule", {}).get("id"):
                    owned_ids.append(int(db.details["rule"]["id"]))
                row = db.details.get("rule", {}) if db else {}
                ui_check(
                    "L1最小设备序列化",
                    not str(row.get("vdisk", "")) and primary_mac in str(row.get("brname", "")),
                    {"vdisk": row.get("vdisk"), "brname": row.get("brname")},
                    "vdisk为空且brname包含默认网卡MAC",
                )
                rec.set_actual({
                    "save": save, "primary_mac": primary_mac,
                    "device_count": len(device_rows), "id": owned_ids[-1] if owned_ids else None,
                })

            with rec.step(
                "步骤8 操作：验证启动后的L2/L3/L4；验证：QEMU、ISO、cgroup、TAP、bridge和VNC一致",
                "操作：读取pid/config/cgroup/netstat/brctl；验证：最小启动控制组的DB→进程→网络无断链",
            ):
                runtime = require_backend("L2-QEMU进程/cgroup", qv.verify_runtime, vm_name)
                storage = require_backend("L2-ISO与磁盘", qv.verify_storage, vm_name)
                network = require_backend("L3-TAP/bridge", qv.verify_network, vm_name)
                vnc = require_backend(
                    "L3-VNC外部访问", qv.verify_vnc, vm_name,
                    expect_external=True,
                )
                consistency = require_backend(
                    "L4-DB到运行态", qv.verify_consistency, prefix
                )
                rec.set_actual({
                    "runtime": getattr(runtime, "passed", False),
                    "storage": getattr(storage, "passed", False),
                    "network": getattr(network, "passed", False),
                    "vnc": getattr(vnc, "passed", False),
                    "consistency": getattr(consistency, "passed", False),
                })

            with rec.step(
                "步骤9 操作：进入noVNC并从ens11访问来宾；验证：非黑帧、DHCP租约和3次ICMP真实流量",
                "操作：完成RFB认证、读取canvas像素、按MAC找lan1租约并ping；验证：操作系统和来宾网络已启动",
            ):
                frame = page.inspect_novnc_framebuffer(vnc_port, vnc_password, timeout=25000)
                ui_check(
                    "noVNC真实帧",
                    frame.get("connected") and frame.get("non_black", 0) > 500,
                    frame,
                    "canvas尺寸大于0且至少500个非黑像素，排除空白代理页",
                )
                guest = require_backend(
                    "L5-TinyCore DHCP+ping", qv.wait_guest_network,
                    vm_name, primary_mac, timeout=70,
                )
                rec.set_actual({
                    "frame": frame,
                    "guest_ip": guest.details.get("guest_ip") if guest else "",
                    "ping_ok": getattr(guest, "passed", False),
                })

            with rec.step(
                "步骤10 操作：搜索、重复约束、四机并存、单删与批删；验证：多虚拟机管理路径互不干扰",
                "操作：搜索和重复提交后新增其他/Linux/Windows三台辅助机；验证：四机并存、一台单删、两台真实多选批删",
            ):
                page.navigate_to_virtual_machine()
                search = page.search(vm_name)
                ui_check(
                    "按完整名称搜索",
                    search.get("supported") and search.get("matched") and search.get("rows") == 1,
                    search,
                    "搜索结果仅保留主测试虚拟机",
                )
                page.clear_search()
                page.open_add_page()
                page.fill_vm_form(
                    name=vm_name, partname="888", system="Linux", cpu_usage=20,
                    cpu_cores=1, memory_mb=128,
                    iso_path="/888/CorePure64-16.2.iso", vnc_port=vnc_port,
                    vnc_external=False, auto_start=False, uefi=False,
                    hardware_accel=True,
                )
                duplicate = page.save_form(timeout=15000)
                ui_check(
                    "重复名称/端口拒绝",
                    not duplicate.get("success") and "/add" in page.page.url,
                    duplicate,
                    "字段显示唯一约束错误且不会返回列表",
                    product=True,
                )
                if "/add" in page.page.url:
                    page.cancel_form(discard=True)
                else:
                    page.navigate_to_virtual_machine()
                db = require_backend(
                    "L1-重复提交后原记录", qv.verify_database, vm_name,
                    {"vnc_port": str(vnc_port), "enabled": "yes"},
                )
                auxiliary_specs = [
                    (aux_name, "其他", "Other"),
                    (batch_names[0], "Linux", "Linux"),
                    (batch_names[1], "Windows", "Windows"),
                ]
                auxiliary_results = {}
                next_port = vnc_port - 1
                for name, ui_system, db_system in auxiliary_specs:
                    port = qv.reserve_vnc_port(next_port)
                    next_port = port - 1
                    page.open_add_page()
                    page.fill_vm_form(
                        name=name, partname="888", system=ui_system,
                        cpu_usage=20, cpu_cores=1, memory_mb=128,
                        iso_path="/888/CorePure64-16.2.iso", vnc_port=port,
                        vnc_external=False, auto_start=False, uefi=False,
                        hardware_accel=True,
                    )
                    save_result = page.save_form(timeout=30000)
                    ui_check(
                        f"创建{ui_system}辅助虚拟机",
                        save_result.get("success") and page.wait_rule_exists(name),
                        save_result,
                    )
                    if not save_result.get("success"):
                        raise AssertionError(f"辅助虚拟机{name}创建失败: {save_result}")
                    db_result = require_backend(
                        f"L1-{ui_system}辅助记录", qv.verify_database, name,
                        {
                            "system": db_system, "vnc_port": str(port),
                            "enabled": "yes",
                        },
                    )
                    if db_result and db_result.details.get("rule", {}).get("id"):
                        owned_ids.append(int(db_result.details["rule"]["id"]))
                    auxiliary_results[name] = {
                        "port": port,
                        "save": save_result,
                        "db": getattr(db_result, "passed", False),
                    }

                page.navigate_to_virtual_machine()
                simultaneous = page.search(prefix)
                ui_check(
                    "四台虚拟机同时存在",
                    simultaneous.get("supported") and simultaneous.get("rows") == 4,
                    simultaneous,
                    "主虚拟机与3台异构辅助虚拟机同时出现在列表",
                )
                page.clear_search()

                aux_stop = page.shutdown(aux_name, force=True)
                aux_delete = page.delete_vm(aux_name)
                ui_check(
                    "单条删除辅助虚拟机",
                    aux_stop.get("success") and aux_delete.get("success"),
                    {"stop": aux_stop, "delete": aux_delete},
                )
                require_backend(
                    "L1-辅助记录删除", qv.verify_database, aux_name,
                    expect_present=False,
                )

                batch_stops = {
                    name: page.shutdown(name, force=True) for name in batch_names
                }
                batch_delete = page.batch_delete(batch_names)
                ui_check(
                    "两台辅助虚拟机多选批量删除",
                    batch_delete.get("success")
                    and set(batch_delete.get("selected", [])) == set(batch_names),
                    {"stops": batch_stops, "delete": batch_delete},
                    "两行均被勾选且一次确认后同时从列表消失",
                    product=True,
                )
                for name in batch_names:
                    observe_product_backend(
                        f"L1-批量删除-{name.rsplit('_', 1)[-1]}",
                        qv.verify_database, name, expect_present=False,
                    )

                # Preserve the bulk-delete failure above, then restore an
                # isolated list state so it cannot corrupt later shutdown/edit
                # scenarios for the primary VM.
                recovery = {}
                if not batch_delete.get("success"):
                    page.navigate_to_virtual_machine()
                    for name in batch_names:
                        if page.rule_exists(name):
                            recovery[name] = page.delete_vm(name)
                    recovered = all(
                        not page.rule_exists(name) for name in batch_names
                    )
                    ui_check(
                        "批量删除失败后的逐台隔离恢复",
                        recovered
                        and all(item.get("success") for item in recovery.values()),
                        recovery,
                        "保留产品失败证据后逐台删除残留辅助机，主虚拟机不受影响",
                    )
                    for name in batch_names:
                        require_backend(
                            f"L1-隔离恢复-{name.rsplit('_', 1)[-1]}",
                            qv.verify_database, name, expect_present=False,
                        )
                    page.navigate_to_virtual_machine()
                rec.set_actual({
                    "search": search, "duplicate": duplicate,
                    "original_intact": getattr(db, "passed", False),
                    "simultaneous_rows": simultaneous.get("rows"),
                    "auxiliary": auxiliary_results,
                    "single_delete": aux_delete,
                    "batch_delete": batch_delete,
                    "batch_recovery": recovery,
                })

            with rec.step(
                "步骤11 操作：正常关机；验证：DB停用、QEMU/PID/TAP/VNC释放且配置记录保留",
                "操作：点击关机并确认；验证：状态变为已关机，L1保留、L2/L3无运行载体",
            ):
                page.navigate_to_virtual_machine()
                stopped = page.shutdown(vm_name, force=False)
                ui_check("正常关机", stopped.get("success"), stopped, "50秒内显示已关机")
                require_backend(
                    "L1-关机状态", qv.verify_database, vm_name, {"enabled": "no"}
                )
                require_backend(
                    "L2-进程停止", qv.verify_runtime, vm_name, expect_running=False
                )
                require_backend(
                    "L3-TAP释放", qv.verify_network, vm_name, expect_running=False
                )
                rec.set_actual(stopped)

            with rec.step(
                "步骤12 操作：编辑为Windows/UEFI/TCG并收紧VNC；验证：字段迁移、旧端口释放和新运行配置",
                "操作：CPU37%、2核、384MB、Windows、UEFI、关闭KVM、VNC仅本机、自启开启；验证：编辑后自动启动",
            ):
                second_vnc_port = qv.reserve_vnc_port(vnc_port - 1)
                ui_check("进入编辑页", page.open_edit(vm_name), page.page.url)
                page.edit_values(
                    save=False,
                    system="Windows", cpu_usage=37, cpu_cores=2, memory_mb=384,
                    vnc_port=second_vnc_port, vnc_external=False,
                    auto_start=True, uefi=True, hardware_accel=False,
                )
                suffix = int(token[-4:], 16)
                extra_macs = [_mac(suffix + index) for index in range(1, 4)]
                page.add_new_disk(1, disk_name, virtio=True)
                page.add_reference_disk(reference["ui_path"], virtio=True)
                page.add_network("lan1", extra_macs[0], mode="virtio")
                page.add_network("lan1", extra_macs[1], mode="e1000e")
                page.add_network("lan1", extra_macs[2], mode="vmxnet3")
                edit = page.save_form(timeout=45000)
                ui_check(
                    "编辑并重启",
                    edit.get("success") and page.rule_exists(vm_name), edit,
                    "返回列表，原名称保留并以新参数运行",
                )
                require_backend(
                    "L1-编辑字段", qv.verify_database, vm_name,
                    {
                        "enabled": "yes", "system": "Windows", "accel": "0",
                        "mem_size": "384", "cpu_usage": "37", "cpu_cores": "2",
                        "uefi": "1", "vnc_port": str(second_vnc_port),
                        "vnc_acl": "1", "auto_start": "1",
                    },
                )
                edited_db = qv.find_vm(vm_name) or {}
                ui_check(
                    "编辑加入两类磁盘和三种扩展网卡",
                    all(value in str(edited_db.get("vdisk", "")) for value in ("create@1@system@virtio", "bootimg@--@"))
                    and all(value in str(edited_db.get("brname", "")) for value in ("@virtio", "@e1000e", "@vmxnet3")),
                    {"vdisk": edited_db.get("vdisk"), "brname": edited_db.get("brname")},
                    "vdisk包含新建/引用盘，brname包含virtio/e1000e/vmxnet3",
                )
                runtime = require_backend("L2-TCG/UEFI运行态", qv.verify_runtime, vm_name)
                storage = require_backend("L2-编辑后存储", qv.verify_storage, vm_name)
                network = require_backend("L3-编辑后TAP", qv.verify_network, vm_name)
                vnc = require_backend(
                    "L3-VNC仅本机", qv.verify_vnc, vm_name,
                    expect_external=False,
                )
                rec.set_actual({
                    "edit": edit,
                    "new_vnc_port": second_vnc_port,
                    "runtime": getattr(runtime, "passed", False),
                    "storage": getattr(storage, "passed", False),
                    "network": getattr(network, "passed", False),
                    "vnc": getattr(vnc, "passed", False),
                })

            with rec.step(
                "步骤13 操作：创建、应用、删除磁盘快照；验证：qemu-img快照表与页面逐次一致",
                "操作：运行中创建快照、应用快照、删除快照；验证：每次操作后虚拟机恢复运行且快照状态正确",
            ):
                page.navigate_to_virtual_machine()
                opened = page.open_snapshot(vm_name)
                ui_check("进入快照页", opened, page.page.url)
                created = page.create_snapshot(snapshot_name)
                ui_check("创建快照", created.get("success"), created)
                require_backend(
                    "L2-快照存在", qv.verify_snapshot, vm_name, snapshot_name,
                    expect_present=True,
                )
                applied = page.snapshot_action(snapshot_name, "apply")
                ui_check("应用快照", applied.get("success"), applied)
                require_backend(
                    "L2-应用后快照仍存在", qv.verify_snapshot, vm_name,
                    snapshot_name, expect_present=True,
                )
                deleted = page.snapshot_action(snapshot_name, "delete")
                ui_check("删除快照", deleted.get("success"), deleted)
                require_backend(
                    "L2-快照已删除", qv.verify_snapshot, vm_name,
                    snapshot_name, expect_present=False,
                )
                page.back_to_list()
                require_backend("L4-快照后全链路", qv.verify_consistency, prefix)
                rec.set_actual({"created": created, "applied": applied, "deleted": deleted})

            with rec.step(
                "步骤14 操作：强制关机与手动开机；验证：强制停止立即释放资源，开机后重新生成全部载体",
                "操作：点击强制关机后再点击开机；验证：L2进程、L3 TAP/VNC和L4一致性均可重建",
            ):
                forced = page.shutdown(vm_name, force=True)
                ui_check("强制关机", forced.get("success"), forced)
                require_backend(
                    "L2-强制关机", qv.verify_runtime, vm_name, expect_running=False
                )
                powered = page.power_on(vm_name)
                ui_check("手动开机", powered.get("success"), powered)
                require_backend("L2-重新启动", qv.verify_runtime, vm_name)
                require_backend("L3-重新桥接", qv.verify_network, vm_name)
                require_backend(
                    "L3-本机VNC策略保持", qv.verify_vnc, vm_name,
                    expect_external=False,
                )
                require_backend("L4-重启后一致性", qv.verify_consistency, prefix)
                rec.set_actual({"forced": forced, "powered": powered})

            with rec.step(
                "步骤15 操作：验证开机自启脚本；验证：仅在无非测试虚拟机时执行qemu.sh init并拉起auto_start=1记录",
                "操作：强制关机后调用底层init模拟系统启动；验证：enabled恢复yes且QEMU/TAP重建",
            ):
                page.navigate_to_virtual_machine()
                stopped = page.shutdown(vm_name, force=True)
                ui_check("自启前关机", stopped.get("success"), stopped)
                if baseline.get("count", 0) == 0:
                    qv._exec(f"{qv.SCRIPT} init", timeout=80)
                    time.sleep(3)
                    require_backend("L1-自启恢复", qv.verify_database, vm_name, {"enabled": "yes", "auto_start": "1"})
                    auto_runtime = observe_product_backend(
                        "L2-自启进程", qv.verify_runtime, vm_name,
                        wait_timeout=25,
                    )
                    auto_network = observe_product_backend(
                        "L3-自启网络", qv.verify_network, vm_name
                    )
                    section(
                        "后端验证·开机自启",
                        "通过" if getattr(auto_runtime, "passed", False)
                        and getattr(auto_network, "passed", False) else "失败",
                        "qemu.sh init",
                        "auto_start=1的测试虚拟机被重新启动",
                        "测试前无非测试虚拟机；DB、进程与TAP结果见本步骤证据",
                    )
                else:
                    rec.not_applicable_current_step(
                        "测试前已有非测试虚拟机，qemu.sh init会改变其他记录运行态，按隔离原则不执行"
                    )
                    section(
                        "不适用", "不适用", "qemu.sh init实启",
                        "不得改变非测试虚拟机运行态",
                        f"测试前存在{baseline.get('count')}条非测试记录；仅L1验证auto_start=1",
                    )
                    page.power_on(vm_name)
                rec.set_actual({"baseline_non_test": baseline.get("count", 0)})

            with rec.step(
                "步骤16 操作：最终关机并删除；验证：列表消失、L1删除、L2/L3/L4无本轮运行载体",
                "操作：强制关机后点击删除；验证：qemu_new_config、进程、运行目录、TAP、磁盘目录同步清理",
            ):
                page.navigate_to_virtual_machine()
                if page.rule_exists(vm_name) and "运行" in page.row_status(vm_name):
                    page.shutdown(vm_name, force=True)
                deleted = page.delete_vm(vm_name)
                ui_check("最终单条删除主虚拟机", deleted.get("success"), deleted)
                require_backend(
                    "L1-记录删除", qv.verify_database, vm_name,
                    expect_present=False,
                )
                # qemu.sh del performs __qemu_clear in the background; wait for
                # the documented graceful-stop window before judging residuals.
                time.sleep(35)
                # Audit before the test-side safety cleanup so product residuals remain visible.
                audit = ssh_verify(
                    "L4-产品清理审计", qv.audit_cleanup, prefix,
                    owned_ids=owned_ids,
                    reference_directory="",
                    must_pass=False,
                )
                backend_section("L4-产品清理审计", audit)
                if audit and not audit.passed:
                    product_failures.append(f"产品删除残留: {audit.message}")
                rec.set_actual({
                    "delete": deleted,
                    "product_cleanup": getattr(audit, "message", "未执行"),
                })

        finally:
            with rec.step(
                "步骤17 操作：finally隔离清理；验证：本轮DB、QEMU、TAP、cgroup、磁盘和引用资产全部归零",
                "操作：按随机前缀和已登记ID兜底清理；验证：不使用全表删除，不触碰已有镜像和非测试行",
            ):
                cleanup_error = ""
                cleanup_result = {}
                try:
                    cleanup_result = qv.cleanup_test(
                        prefix,
                        owned_ids=owned_ids,
                        reference_directory=reference.get("directory", ""),
                    )
                except Exception as exc:
                    cleanup_error = f"{type(exc).__name__}: {str(exc)[:180]}"
                    failures.append(f"finally清理异常: {cleanup_error}")
                post = ssh_verify(
                    "L4-finally无残留", qv.audit_cleanup, prefix,
                    owned_ids=owned_ids,
                    reference_directory=reference.get("directory", ""),
                    must_pass=True,
                )
                backend_section("L4-finally无残留", post)
                if baseline is not None:
                    unchanged = ssh_verify(
                        "L4-非测试状态恢复", qv.verify_non_test_state,
                        prefix, baseline, must_pass=True,
                    )
                    backend_section("L4-非测试状态恢复", unchanged)
                section(
                    "清理结果", "通过" if not cleanup_error and getattr(post, "passed", False) else "失败",
                    "随机命名空间兜底清理",
                    "DB/进程/TAP/runtime/cgroup/测试磁盘目录为0，非测试指纹不变",
                    cleanup_error or cleanup_result,
                )
                current_failures = failures + product_failures
                rec.add_detail("【测试结论】" + ("通过" if not current_failures else "失败"))
                rec.add_detail(f"  自动化/环境失败：{len(failures)}")
                rec.add_detail(f"  产品行为失败：{len(product_failures)}")
                if current_failures:
                    rec.add_detail("  失败项：" + " | ".join(current_failures))
                rec.set_actual({
                    "cleanup": cleanup_result,
                    "cleanup_error": cleanup_error,
                    "post_audit": getattr(post, "message", "未执行"),
                })

        all_failures = failures + product_failures
        assert not all_failures, "虚拟机综合测试失败：\n" + "\n".join(all_failures)
