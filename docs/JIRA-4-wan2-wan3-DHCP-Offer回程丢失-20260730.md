# JIRA：wan2/wan3 自动获取 IP 失败

| 项 | 值 |
|---|---|
| 设备/固件 | IK-G2606-MXP / 4.0.303 x64 Build202607281258 |
| 设备IP | 10.66.0.45（wan1 管理地址） |
| 上游DHCP | 10.66.0.1 |
| 模块 | 网络配置 → 内外网设置 → wan2 / wan3 |
| 严重程度建议 | Major / P1（2 条 WAN 无法获得 IPv4 地址） |
| 复现率 | 当前故障状态持续必现；重绑定触发条件待开发复测确认 |
| 提交人 | 戎士显 |
| 日期 | 2026-07-30 |

## 标题

【IK-G2606-MXP 4.0.303】有线 WAN 子口重绑定后 DHCP Offer 回程丢失，wan2/wan3 无法自动获取 IPv4 地址

## 问题描述

wan2、wan3 在「网络配置 → 内外网设置」中配置为 DHCP（自动获取）并保存后，两个接口持续无法获得 IPv4 地址。页面及 `/tmp/iktmp/monitor-link/wan2|wan3` 均显示 DHCP 获取失败。

双端同步抓包确认：

- wan2/wan3 的 `udhcpc` 正常运行，并持续发出 DHCP Discover。
- 上游 DHCP 服务器 `10.66.0.1` 能收到 Discover，并立即返回 Offer：wan2 为 `10.66.0.48`，wan3 为 `10.66.0.49`。
- DHCP XID、客户端 MAC 均匹配，但 DUT 所有接口抓包均看不到返回的 Offer，客户端因此不会进入 DHCP Request/ACK 阶段。
- wan1 在同一上游正常获得 `10.66.0.45/24`，可以排除上游 DHCP 服务整体异常。

故障边界已收敛到 **DUT 物理 WAN 子口回程、交换芯片 VLAN 映射或接口重绑定应用层**，不是前端显示问题，也不是 `udhcpc` 未运行或上游 DHCP 未响应。

## 相关时间线

设备本次启动后的内核日志显示：

| 时间 | 事件 |
|---|---|
| 启动初始 | wan2 绑定 `veth6`，wan3 绑定 `veth4` |
| 约 11:53 | wan3 原 `veth4` 被移除，重新绑定到 `veth3` |
| 约 11:54 | wan2 原 `veth6` 被移除，重新绑定到 `veth4` |
| 约 12:15 | wan2/wan3 曾正常获得 `10.66.0.48/24`、`10.66.0.49/24` 及对应默认路由 |
| 约 12:23～12:24 | wan2/wan3 IPv4 地址及默认路由消失，状态变为 DHCP 获取失败 |
| 12:41～12:48 | 数据库、运行态、交换芯片状态及双端抓包复核，故障持续存在 |

现象发生前执行过内外网接口解绑、新增、删除、接入方式切换和恢复操作。时间线与 WAN 子口重绑定高度相关，但是否为唯一触发条件仍需开发在干净环境复现。

## 复现步骤

1. 将 wan2、wan3 的有线端口接入可用 DHCP 网络，本次上游为 `10.66.0.1/24`。
2. 登录设备 Web 管理页面，进入「网络配置 → 内外网设置」。
3. 对有线 WAN 接口执行网卡解绑/重新绑定，或完成新增、删除临时 LAN/WAN 接口后恢复原 WAN 绑定。
4. 分别配置 wan2、wan3 的接入方式为「DHCP（自动获取）」并保存。
5. 等待 30 秒以上，观察接口 IPv4 地址与连接状态。
6. 在 DUT 与上游同时抓取 DHCP 报文，核对 Discover、Offer、Request、ACK 四阶段。

当前故障状态下，直接执行步骤 4～6 即持续必现；步骤 3 的最小触发组合需要开发进一步缩减。

## 实际结果

- wan2、wan3 均无 IPv4 地址，只有 IPv6 link-local 地址。
- `udhcpc` 进程存在，运行态状态文件显示“DHCP获取失败”。
- wan2、wan3 持续发送 Discover；上游持续返回 Offer；DUT 收不到 Offer。
- 两个接口均无法形成对应的直连路由和默认路由。
- wan1 在同一 DHCP 服务端工作正常。

当前运行态：

```text
wan1  UP  10.66.0.45/24
wan2  UP  仅 fe80::/64，无 IPv4
wan3  UP  仅 fe80::/64，无 IPv4

udhcpc -i wan1 ...
udhcpc -i wan2 ...
udhcpc -i wan3 ...

wan1 ... DHCP ... success ... 线路检测成功
wan2 ... DHCP ... DHCP获取失败
wan3 ... DHCP ... DHCP获取失败
```

## 预期结果

- wan2、wan3 保存 DHCP 配置后应完成 Discover → Offer → Request → ACK。
- wan2 应获得 `10.66.0.48/24`，wan3 应获得 `10.66.0.49/24`（以当前上游租约为准）。
- 地址、网关、DNS、租期及对应策略/默认路由应完整应用。
- WAN 网卡解绑、重绑、临时接口新增/删除及 `wan.sh init` 后，物理端口、S-VLAN、Linux 子接口和 WAN bridge 的映射应保持一致。

## 双端抓包证据

### wan2

客户端 MAC：`08:9e:4b:10:26:39`

```text
DUT：
0.0.0.0:68 > 255.255.255.255:67
xid 0x58d61038, DHCP Discover

上游 10.66.0.1：
收到 xid 0x58d61038 Discover
约 1 ms 后发出 DHCP Offer，Your-IP 10.66.0.48
Ethernet dst = 08:9e:4b:10:26:39

DUT：Offer=0，Request=0，ACK=0
```

12 秒复核样本中，上游 `lan1` 对同一 wan2 MAC 抓到 2 个 Discover、2 个 Offer；DUT `wan2` 抓到 2 个 Discover、0 个 Offer。

### wan3

客户端 MAC：`08:9d:4b:10:26:39`

```text
DUT：
0.0.0.0:68 > 255.255.255.255:67
xid 0x5899d603（另一次为 0x0aa97e57），DHCP Discover

上游 10.66.0.1：
收到相同 xid Discover
约 1 ms 后发出 DHCP Offer，Your-IP 10.66.0.49

DUT：Offer=0，Request=0，ACK=0
```

35 秒 DUT 全接口样本共抓到 49 个 DHCP 报文，均为 Discover，没有 Offer/Request/ACK。

## 配置与底层状态

数据库 `/etc/mnt/ikuai/config.db`：

| 接口 | bandif | bandeth | internet | wifi_wisp | IPv4 |
|---|---|---|---:|---:|---|
| wan1 | `08:9f:4b:10:26:39` | `veth5` | 1（DHCP） | 0 | `10.66.0.45/24` |
| wan2 | `08:9e:4b:10:26:39` | `veth4` | 1（DHCP） | 1 | 空 |
| wan3 | `08:9d:4b:10:26:39` | `veth3` | 1（DHCP） | 1 | 空 |

Linux bridge/子接口：

```text
wan2 <- veth4@eth0，802.1ad VLAN 4081
wan3 <- veth3@eth0，802.1ad VLAN 4082
```

交换芯片状态：

```text
VLAN 4081: CPU port 3t <-> physical port 4
VLAN 4082: CPU port 3t <-> physical port 5
Port 4: link up 1000M
Port 5: link down
```

同时，抓包能观察到 wan2 的广播 Discover 从上游回灌到 wan3（VLAN 4082），wan3 的广播 Discover 回灌到 wan2（VLAN 4081），说明两个物理 WAN 位于同一上游广播域。广播能双向到达，但服务端发出的单播 Offer 未进入对应 WAN bridge。

`wifi_wisp=1` 与当前有线 `bandeth=veth3/veth4` 不一致，是需要清理/核查的残留状态。但 `wan.sh` 仅在 `wifi_ssid` 非空且 `bandif` 映射到 Wi-Fi 设备时启动 APCLI，因此目前不能仅凭该字段认定它是 Offer 丢失的直接根因。

## 根因范围（开发参考）

### 已确认

- DHCP 客户端进程正常，Discover 能发出。
- 上游 DHCP 服务正常，能按相同 XID/MAC 返回正确 Offer。
- Offer 在到达 DUT 的 WAN bridge/协议栈之前丢失。
- 故障发生在 WAN 物理子口重绑定及地址失效之后。

### 待开发确认

1. `bandif/bandeth` 更新后，`veth3/veth4` 与交换芯片 VLAN 4081/4082、物理 Port 4/5 是否同步重建。
2. 交换芯片单播 FDB、端口隔离及 S-VLAN ingress/egress 规则是否仍保留重绑定前的映射，导致广播可达而单播 Offer 被送错端口或丢弃。
3. Port 5 报告 link down 与当前 wan3 Discover 能到达上游之间为何不一致。
4. `wan.sh init` 在接口交换绑定后是否完整清理旧 bridge/FDB/VLAN 状态，而非仅创建新 Linux bridge 关系。
5. 有线 WAN 保存时为何写入 `wifi_wisp=1`，以及该字段是否参与其它未检出的底层分支。

建议优先检查交换芯片/FDB 和 VLAN apply 差异；不要只重启 `udhcpc`，因为服务端 Offer 已发出且 DUT 抓不到。

## 自动化测试关联问题

自动化用例 `tests/network/test_interface_settings_comprehensive.py` 的 finally 恢复存在独立缺陷，会放大或保留该问题：

- 测试前已对 wan2/wan3 全行做快照。
- finally 是否触发整行 SQL 恢复，只比较 `tagname/internet/check_link_*/default_route/PPPoE/MTU/MAC/speed/DHCP option` 等字段。
- 变化检测未包含 `bandif`、`bandeth`、`wifi_wisp`、`wifi_bssid`、`wifi_ssid`、`wifi_psk`。
- 如果仅网卡绑定或 WISP 字段变化，`changed=False`，整行恢复和 `wan.sh init` 都不会执行。
- 步骤 22 的恢复校验同样没有校验 wan2/wan3 的物理绑定、WISP 字段、IPv4、网关、租期和 DORA 完整性，因此测试可能报告恢复成功，但设备已无法重新获取地址。

该脚本缺陷应与产品侧回程丢包同时修复：脚本负责保证测试环境可恢复，产品负责保证合法重绑定后运行态一致。

## 建议修复方向

1. WAN 重绑定时原子化更新 `wan_config`、Linux bridge、802.1ad 子接口、交换芯片 VLAN/FDB/隔离规则。
2. apply 前清理旧物理口对应的动态/静态 FDB 及旧 VLAN 映射，apply 后校验 `bandeth -> S-VLAN -> switch port` 一致性。
3. 对有线 WAN 强制归一化 `wifi_wisp=0` 及 Wi-Fi 关联字段，避免跨接入类型残留。
4. 自动化恢复改为对快照全字段做白名单排除式比较，至少补充 `bandif/bandeth/wifi_*`；恢复后必须等待 DHCP ACK，而不是只断言 `internet=1`。

## 复测要求

1. 在干净启动环境记录 wan1/wan2/wan3 的 DB、bridge、S-VLAN、switch port、FDB 基线。
2. wan2、wan3 分别单口接入 DHCP 网络，验证完整 DORA、地址、网关、DNS、租期和路由。
3. 两口同时接入同一广播域，验证连续续租和单播 Offer/ACK 都进入正确 bridge。
4. 覆盖绑定交换矩阵：wan2/wan3 解绑、互换物理口、恢复原口、创建并删除临时 wan4/lan2。
5. 每次操作后执行 `wan.sh init`，再次验证 DORA 和交换芯片映射，不得依赖设备重启恢复。
6. 重启设备后再次验证配置持久化和 DHCP 自动恢复。
7. 确认有线 WAN 的 `wifi_wisp=0`，旧 `bandif/bandeth`、bridge、VLAN、FDB 无残留。
8. 自动化报告必须把“仅接入方式字段正确”和“真正获得 DHCP 地址”分开呈现；未获得 ACK/IPv4 时用例必须失败。

## 人工复验命令

```bash
# DUT：数据库和运行态
sqlite3 -header -separator '|' /etc/mnt/ikuai/config.db \
  "select id,tagname,bandif,bandeth,internet,wifi_wisp,ip_mask,gateway from wan_config where tagname in ('wan1','wan2','wan3');"
ip -br addr show wan1
ip -br addr show wan2
ip -br addr show wan3
ps w | grep '[u]dhcpc.*wan[123]'
cat /tmp/iktmp/monitor-link/wan2
cat /tmp/iktmp/monitor-link/wan3
brctl show
ip -d link show veth3
ip -d link show veth4
swconfig dev switch0 show

# DUT 与 10.66.0.1 同时执行，按 XID/MAC 对齐报文
tcpdump -ni any -e -vvv 'udp port 67 or 68'
```
