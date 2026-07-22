# 高级服务-虚拟机自动化开发记忆

> 最后实机确认：2026-07-20（Asia/Shanghai）。本文记录“高级服务 -> 虚拟机”的页面、底层脚本、L1-L5 验证、测试资产、安全边界和最终实测结论。不得在代码、JSON、HTML、Excel 或本文中记录 VNC 明文口令。

## 1. 入口与底层契约

- 列表 URL：`/#/advancedService/virtualMachine`。
- 添加 URL：`/#/advancedService/virtualMachine/add`。
- 后端功能名：`qemu`；页面操作经 `/Action/call` 调用产品接口。
- 产品脚本：`/usr/ikuai/script/qemu.sh`。
- 数据库：`/etc/mnt/ikuai/config.db`，表 `qemu_new_config`。
- 运行目录：`/tmp/iktmp/qemu/<id>`。
- CPU cgroup：`/sys/fs/cgroup/cpu/ik_apps/qemu_<id>`。
- 磁盘根：`/etc/disk_user/<partname>`；新建虚拟盘位于 `KVM/<vm_name>`。
- TAP 命名：`qtap<id>_<bridge>_<index>`。
- 实机 QEMU/qemu-img 版本为 3.1.0，`/dev/kvm` 和 KVM 内核模块可用。
- `888` 是指向独立数据分区的链接，本轮只在随机 owner 目录中创建引用盘，不修改已有用户镜像。

报告查询字段不读取 `vnc_pwd`，只读取 `length(vnc_pwd) AS vnc_pwd_len`。noVNC 登录所需口令只存在测试进程内存，已登记到统一敏感值清理器。

## 2. 页面能力

- 列表核心列：虚拟机名称、安装磁盘、CPU 核心、虚拟机内存、VNC 端口、开机自启、运行时长、运行状态、操作。
- 列表支持添加、搜索、帮助、单条操作和勾选后批量删除。
- 页面不提供导入、导出或列排序，测试按真实能力记录“不适用”，不伪造入口。
- 添加/编辑覆盖安装磁盘、系统类型、名称、CPU 使用率、核心数、内存、ISO、VNC、开机自启、UEFI、KVM/TCG 和设备抽屉。
- 系统类型实测覆盖 Linux、Windows、其他。
- 磁盘覆盖新建 qcow2、引用 qcow2、ISO；物理分区能力只枚举，不在共享 DUT 执行。
- 网卡覆盖默认模式、virtio、e1000e、vmxnet3；PCI 物理网卡只枚举，不执行解绑。
- 快照覆盖创建、应用和删除，并用 `qemu-img snapshot -l` 复核。
- noVNC 覆盖登录、连接状态、画布尺寸和非黑帧像素证据。

## 3. L1-L5 验证定义

- L1 数据层：`qemu_new_config` 的新增、编辑、启停、自启、重复约束和删除；口令只验证长度。
- L2 系统层：QEMU PID/命令行、生成配置、CPU cgroup 配额与 tasks、ISO、新建盘、引用盘、BIOS/UEFI、KVM/TCG、快照。
- L3 网络层：每块 TAP 的存在、UP 状态、MAC、bridge 接入，以及 VNC 内外访问策略。
- L4 一致性层：DB -> QEMU -> runtime -> TAP 的关联一致性；非测试行指纹；删除和 finally 残留审计。
- L5 用户效果层：noVNC 720x400 画布非黑帧；Tiny Core DHCP 租约；独立客户端从 `ens11` 对来宾地址执行 3 次真实 ICMP，要求 3/3 回复。

## 4. 综合用例的 17 个步骤

1. 建立随机 `qvm_<token>_` 命名空间、动态 VNC 端口和非测试行指纹。
2. 核对 `qemu.sh`、QEMU/KVM、888 空间、ISO 双摘要并准备隔离引用盘。
3. 验证列表列、添加、搜索、帮助、批量入口及真实不支持能力。
4. 验证添加表单、系统类型、磁盘选择、默认 CPU/VNC/自启等控件。
5. 枚举磁盘、网卡、USB 与高风险直通能力，记录安全边界。
6. 验证必填、名称、CPU、内存和 VNC 端口的前端边界。
7. 创建最小 Linux/Tiny Core 虚拟机，验证默认网卡和 L1 字段。
8. 验证 QEMU/cgroup、ISO/磁盘、TAP/bridge、VNC 和 L4 一致性。
9. 验证 noVNC 非黑帧、来宾 DHCP 和客户端 3 次 ICMP。
10. 验证搜索、重复约束，建立主机 + 其他/Linux/Windows 三台辅助机的四机并存状态，再验证一台单删、两台真实多选批删及失败后的隔离恢复。
11. 验证正常关机后的 DB 停用、进程/PID/TAP/VNC 释放。
12. 编辑为 Windows + UEFI + TCG + VNC 仅本机，添加 4 种网卡并验证迁移。
13. 创建、应用、删除磁盘快照并复核运行态。
14. 强制关机、手动开机，验证全部运行载体重新建立。
15. 在测试前无非测试虚拟机时执行 `qemu.sh init`，验证开机自启。
16. 最终单条删除主虚拟机，并在产品 35 秒清理窗口后独立审计残留。
17. 按随机前缀和已登记 ID 做 finally 兜底清理，验证所有测试载体归零且非测试指纹不变。

报告的每一步均包含操作、预期、实际、分层 SSH 证据和可复制人工复验命令，结构接近人工测试用例。

## 5. 测试镜像

- 路径：`/etc/disk_user/888/CorePure64-16.2.iso`。
- 来源：`http://tinycorelinux.net/16.x/x86_64/release/CorePure64-16.2.iso`。
- MD5：`9625854d8ac6156f89e20cfa6d69cc24`。
- SHA256：`c954b2900fbbd38c2da156525819de8c80c4cc7a7ffde61a89b10f4a99985ebc`。
- 下载采用隐藏临时文件、摘要通过后原子改名；摘要不匹配时测试失败。
- 引用盘位于 `/888/.ikuai_vm_test/<random_prefix>/reference.img`，带 `.owner` 标记，finally 只删除 owner 匹配的本轮目录。

## 6. 安全不适用项

- 物理分区直通：`qemu.sh` 可能卸载所选分区，共享 DUT 不执行破坏性实挂载。
- PCI 网卡直通：会解绑物理网卡，可能中断管理链路，不执行。
- USB 直通：本轮实机没有可用 USB 设备，记录为环境不适用。
- `qemu.sh init`：仅当测试前非测试虚拟机数量为 0 时实跑，避免改变用户虚拟机运行态。
- 清理禁止全表删除、通配删除全部 QEMU/TAP 或修改用户镜像，只允许已验证随机前缀和本轮登记 ID。

## 7. 已确认产品问题

最终轮报告有 5 个产品失败断言，对应 3 组产品问题，不是自动化或环境失败。

1. 多选批量删除不完整。
   - 主虚拟机和其他/Linux/Windows 三台辅助虚拟机可同时创建，列表按随机前缀搜索精确显示 4 行。
   - 两台待删辅助机都已关机，两个复选框的 `selection_state` 均为 `true`，批量删除按钮和确认流程正常执行。
   - 产品只删除第一台，第二台 DB 记录仍存在；另一轮还出现两台均未删除，说明结果不稳定。
   - 记录产品失败后，测试逐台单删残留辅助机并复核 DB，使后续主虚拟机测试不被级联污染。
2. 开机自启没有形成完整运行态。
   - `qemu.sh init` 后 L1 已把 `enabled` 恢复为 `yes`，`auto_start=1` 保持正确。
   - 25 秒内 PID 仍为 0，cgroup tasks 为空，CPU quota 为 20000，未达到配置 37% 对应的 370000。
   - 4 个 TAP 存在但均为 DOWN，未接入 `lan1`，MAC 也不符合配置。
   - 失败观察时 `/tmp/qemu_1.log` 无输出，说明尚未进入能记录 QEMU 错误的启动阶段；后续退出/清理阶段日志出现 `/etc/qemu-ifdown failed with status 256`。
   - 同一配置通过页面“开机”可以正常建立 QEMU、cgroup、TAP 和 bridge，排除镜像/配置本身不可启动。
3. 删除后 cgroup 残留。
   - 页面删除成功，DB、QEMU 进程、runtime、TAP 和磁盘目录均已消失。
   - 等待 35 秒后本轮 `qemu_1` 到 `qemu_4` cgroup 目录仍存在，产品清理审计失败。

早期实测还观察到 `init` 与删除的竞态：DB/runtime 已删除后测试前缀 QEMU 和 TAP 又出现。兜底清理已修复为直接从 `ps` 的 `-name <random_prefix>` 发现孤儿 PID，先 TERM、超时后 KILL，再按本轮 ID 删除 TAP，最后移除空 cgroup。该场景已有离线单测。

## 8. 代码与接入

新增核心文件：

- `pages/advanced_service/virtual_machine_page.py`
- `utils/qemu_verifier.py`
- `tests/advanced_service/test_virtual_machine_comprehensive.py`
- `tests/unit/test_qemu_verifier.py`
- `tests/unit/test_virtual_machine_wiring.py`
- `tests/unit/test_gui_realtime_logging.py`

已接入 `BackendVerifier`、验证命令重放、安全验证白名单、fixture、marker、GUI 树、settings 和 Excel 模块映射。

GUI 日志链路采用 50 ms 批量渲染，禁用自动换行和撤销历史；pytest 文本先做 HTML 转义，避免 `<...>` 或 `&` 被富文本解析吞掉。GUI 启动时会输出每个测试步骤的开始、结束、状态和用时；连续 15 秒没有子进程输出时显示运行心跳。日志级别过滤使用完整内存历史一次重建，不会因切换过滤条件丢行。

GUI/pytest 精确节点：

```text
advanced_service/test_virtual_machine_comprehensive.py::TestVirtualMachineComprehensive::test_virtual_machine_comprehensive
```

实机运行命令：

```powershell
$env:PYTHONIOENCODING='utf-8'
$env:HEADLESS='true'
python -m pytest tests\advanced_service\test_virtual_machine_comprehensive.py::TestVirtualMachineComprehensive::test_virtual_machine_comprehensive -s -q -o addopts=
```

## 9. 最终实测与产物

- 最终实测：`1 failed in 405.94s`。这是预期保留的产品缺陷红灯。
- 17 步中 14 步通过；步骤 10 批量删除、步骤 15 自启和步骤 16 产品删除审计失败，步骤 17 finally 通过。
- 结论分类：自动化/环境失败 0，产品行为失败 5。
- L5 来宾地址为 `192.168.148.5`，客户端 `ens11` 的 3 次 ICMP 全部成功。
- 四台虚拟机并存验证通过；批量删除时两台均确认勾选，但只删除一台，随后逐台隔离恢复通过。
- 最终独立审计：本轮 DB=0，QEMU=0，TAP=0，runtime=0，cgroup=0，磁盘目录=0；非测试虚拟机指纹不变。
- ISO 最终 MD5 再次确认正确，测试镜像保留供后续虚拟机回归使用。
- 离线专项回归：17 项通过，包含 GUI 实时步骤日志、批量渲染契约、四机并存接线和无 DB/runtime 的孤儿 QEMU 清理测试；Qt 离屏富文本/过滤恢复检查通过。
- JSON：`reports/output/test_results.json`。
- HTML：`reports/output/test_report_20260720_141250.html`。
- Excel：`reports/output/virtual_machine_test_report_20260720_141250.xlsx`。
- Excel 包含汇总、测试结果明细、步骤明细、复验命令 4 个工作表。
- JSON/HTML/Excel 未发现 VNC 明文或已登记随机口令。

后续产品修复后应直接重跑精确节点。预期步骤 10、15、16 转绿，pytest 才应整体通过；不得通过跳过或弱化断言隐藏产品问题。
