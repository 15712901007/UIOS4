# DPDK、dperf、TRex 双机性能测试环境报告

> 测试日期：2026-07-31（Asia/Shanghai）  
> 管理节点：`10.66.0.57`、`10.66.0.67`  
> 测试范围：DPDK 绑定、1G/2.5G 物理链路、dperf CPS/CC、TRex STL 功能、路由器性能测试可行性

## 1. 结论

1. 当前两根数据线接法本身正确：1G 对 1G、2.5G 对 2.5G，两个物理链路都已实测为 `UP / full-duplex`，速率分别为 `1000 Mbps` 和 `2500 Mbps`。
2. 两台主机的 `03:00.0`（1G I210）和 `07:00.0`（2.5G I226-V）当前都已绑定 `vfio-pci`；管理口 `06:00.0 / enp6s0` 保持内核 `igb` 驱动，SSH 不受影响。
3. dperf 双机直连测试通过：
   - 1G 链路稳定达到 `100,000 CPS`；
   - 2.5G 链路稳定达到 `250,000 CPS`；
   - 2.5G 链路达到并保持 `1,000,000` 条并发 TCP 连接；
   - 稳定采样窗口内无 `ierrors/oerrors/imissed/skErr`。
4. TRex 3.08 功能正常：双 I210、双 I226-V 均能初始化；2.5G STL smoke 实测发送 `100,000` 包、回收 `100,000` 包，丢包和错误均为 0。
5. 当前“一张 1G + 一张 2.5G”不能作为同一个 TRex 端口对。TRex 明确拒绝混用 `net_e1000_igb` 与 `net_igc`，正式测试必须在同一台发生器上使用两张同型号、同速率网卡。
6. 当前直连拓扑适合验证压测机和建立基线，但没有 DUT（被测路由器），所以本报告中的数值不是路由器性能。测试路由器时需要按第 9 节重新接线。

## 2. 当前物理拓扑

```text
管理网络 10.66.0.0/24
        |
        +-- 10.66.0.57 enp6s0 / 06:00.0（管理口，不绑定 DPDK）
        |
        +-- 10.66.0.67 enp6s0 / 06:00.0（管理口，不绑定 DPDK）

数据线 A（1G）
10.66.0.57 03:00.0 / I210  <================>  03:00.0 / I210 10.66.0.67

数据线 B（2.5G）
10.66.0.57 07:00.0 / I226  <================>  07:00.0 / I226 10.66.0.67
```

普通双绞线即可，Intel 网卡支持自动 MDI/MDI-X，不要求交叉线。2.5G 建议使用质量正常的 Cat5e 或 Cat6 线缆。

## 3. 主机环境

| 项目 | 10.66.0.57 | 10.66.0.67 |
|---|---|---|
| 主机名 | `iktest` | `iktest` |
| 系统 | Ubuntu 24.04.4 LTS | Ubuntu 24.04.4 LTS |
| 内核 | `6.8.0-136-generic` | `6.8.0-136-generic` |
| CPU | Intel Core i3-N305 | Intel Core i3-N305 |
| 核心 | 8 核、1 线程/核、单 NUMA | 8 核、1 线程/核、单 NUMA |
| CPU governor | `performance` | `performance` |
| HugePage | 2048 x 2 MB，共 4 GB | 2048 x 2 MB，共 4 GB |
| 管理口 | `enp6s0 / 10.66.0.57` | `enp6s0 / 10.66.0.67` |
| 管理 PCI | `0000:06:00.0` | `0000:06:00.0` |

测试结束时，两端 `HugePages_Free=2048`、`HugePages_Rsvd=0`，没有残留 dperf、testpmd 或 TRex 进程。

### 软件版本

| 软件 | 已安装版本 | 安装位置/验证方式 |
|---|---:|---|
| DPDK | `26.07.0` | `/opt/dpdk`，`pkg-config --modversion libdpdk` |
| dperf | `1.9.0` | `dperf --version` |
| TRex | `3.08` | `/opt/trex -> /opt/trex-v3.08` |

上述版本是在 2026-07-31 部署时核对的最新稳定版本。后续升级前应再次检查官方发布页：

- DPDK：<https://core.dpdk.org/download/>
- dperf：<https://github.com/baidu/dperf/releases>
- TRex：<https://trex-tgn.cisco.com/trex/doc/trex_manual.html>

TRex 使用其发行包内置的 DPDK，不会直接使用系统 `/opt/dpdk` 的 26.07 库，这是正常设计。

## 4. 网卡清单

### 10.66.0.57

| PCI | Linux 名称 | 型号/速率 | MAC | 最终驱动 | 用途 |
|---|---|---|---|---|---|
| `03:00.0` | `enp3s0`（绑定后不可见） | Intel I210 / 1G | `a8:b8:e0:00:5a:99` | `vfio-pci` | 当前 1G 数据线 |
| `04:00.0` | `enp4s0` | Intel I210 / 1G | `a8:b8:e0:00:5a:9a` | `igb` | 可作为第二个 1G TRex 口 |
| `05:00.0` | `enp5s0` | Intel I210 / 1G | `a8:b8:e0:00:5a:9b` | `igb` | 备用 |
| `06:00.0` | `enp6s0` | Intel I210 / 1G | `a8:b8:e0:00:5a:9c` | `igb` | 管理口，禁止绑定 |
| `07:00.0` | `enp7s0`（绑定后不可见） | Intel I226-V / 2.5G | `a8:b8:e0:09:fe:bd` | `vfio-pci` | 当前 2.5G 数据线 |
| `08:00.0` | `enp8s0` | Intel I226-V / 2.5G | `a8:b8:e0:09:fe:be` | `igc` | 可作为第二个 2.5G TRex 口 |
| `09:00.0` | `enp9s0` | Intel I226-V / 2.5G | `a8:b8:e0:09:fe:bf` | `igc` | 备用 |
| `0a:00.0` | `enp10s0` | Intel I226-V / 2.5G | `a8:b8:e0:09:fe:c0` | `igc` | 备用 |

### 10.66.0.67

| PCI | Linux 名称 | 型号/速率 | MAC | 最终驱动 | 用途 |
|---|---|---|---|---|---|
| `03:00.0` | `enp3s0`（绑定后不可见） | Intel I210 / 1G | `a8:b8:e0:00:5b:bd` | `vfio-pci` | 当前 1G 数据线 |
| `04:00.0` | `enp4s0` | Intel I210 / 1G | `a8:b8:e0:00:5b:be` | `igb` | 可作为第二个 1G 口 |
| `05:00.0` | `enp5s0` | Intel I210 / 1G | `a8:b8:e0:00:5b:bf` | `igb` | 备用 |
| `06:00.0` | `enp6s0` | Intel I210 / 1G | `a8:b8:e0:00:5b:c0` | `igb` | 管理口，禁止绑定 |
| `07:00.0` | `enp7s0`（绑定后不可见） | Intel I226-V / 2.5G | `a8:b8:e0:09:fe:a1` | `vfio-pci` | 当前 2.5G 数据线 |
| `08:00.0` | `enp8s0` | Intel I226-V / 2.5G | `a8:b8:e0:09:fe:a2` | `igc` | 可作为第二个 2.5G 口 |
| `09:00.0` | `enp9s0` | Intel I226-V / 2.5G | `a8:b8:e0:09:fe:a3` | `igc` | 备用 |
| `0a:00.0` | `enp10s0` | Intel I226-V / 2.5G | `a8:b8:e0:09:fe:a4` | `igc` | 备用 |

## 5. 为什么曾看到一个端口没有 UP

这不是线序接错，原因由两个状态叠加造成：

1. `.57` 的测试口已经绑定 `vfio-pci`，Linux 内核不再为它创建普通网络接口，因此 `ip link` 看不到该口，也不能用 Linux 的 `UP/DOWN` 判断它。
2. `.67` 重启后，测试口恢复为 `igb/igc`，因为本环境故意不在开机时自动绑定业务网卡。
3. 绑定 VFIO 后，如果没有 DPDK 应用打开端口，部分网卡不会持续拉起 PHY，交换机灯或对端可能暂时显示 Down。

在两端同时运行 DPDK `testpmd` 后得到：

| 链路 | .57 状态 | .67 状态 | 速率 | 双工 | 硬件错误 |
|---|---|---|---:|---|---|
| `03:00.0 <-> 03:00.0` | UP | UP | 1000 Mbps | Full | 0 |
| `07:00.0 <-> 07:00.0` | UP | UP | 2500 Mbps | Full | 0 |

所以判断 DPDK 口是否正常，应使用 `testpmd show port info/status`、dperf 或 TRex，而不是只看 `ip link`。

## 6. dperf 直连实测

### 测试地址

| 链路 | .57 客户端 | .67 服务端 | 配置中的虚拟网关 |
|---|---|---|---|
| 1G | `198.18.1.10` | `198.18.1.3` | `198.18.1.1` |
| 2.5G | `198.18.2.10` | `198.18.2.3` | `198.18.2.1` |

直连配置使用独立的虚拟网关地址，并显式指定真实对端 MAC。不能把业务对端 IP 同时写成 dperf 网关，否则会触发 dperf 的网关处理逻辑，表现为 ARP 正常但 TCP SYN 到不了服务端。

### CPS 稳定采样

| 指标 | 1G | 2.5G |
|---|---:|---:|
| 目标 CPS | 100,000 | 250,000 |
| 实测 SYN/CPS | 100,004 | 250,008 |
| RX 包/秒 | 300,018 | 750,016 |
| TX 包/秒 | 300,012 | 750,020 |
| RX bit/s | 145,608,704 | 364,007,808 |
| TX bit/s | 136,805,472 | 342,009,216 |
| dperf CPU usage | 10% | 18% |
| RTT | 204.2 us | 168.8 us |
| `dropTx/tcpDrop/skErr` | 0 | 0 |
| `ierrors/oerrors/imissed` | 0 | 0 |

### CPS 全程累计

| 指标 | 1G | 2.5G |
|---|---:|---:|
| 客户端 TCP 请求 | 1,931,844 | 3,580,732 |
| 客户端 TCP 响应 | 1,931,784 | 3,580,636 |
| 服务端 TCP 请求/响应 | 1,931,792 / 1,931,792 | 3,580,660 / 3,580,660 |
| 客户端 `ierrors/oerrors/imissed` | 0 / 0 / 0 | 0 / 0 / 0 |

CPS 运行使用了短时功能配置。客户端进入停止和连接回收阶段后仍会处理未完成连接，因此全程累计中出现了重传、`dropTx` 和服务端 `imissed`。稳定采样窗口没有这些错误，但该轮只能作为功能和能力基线，不能当作 RFC 2544 零丢包结果。正式出报告时应统一两端持续时间、丢弃升速/降速阶段，并至少重复三轮。

### 1,000,000 并发连接

有效 CC 配置在客户端和服务端都设置了 `keepalive 30s`。只在客户端设置 `keepalive` 会导致服务端立即关闭连接，不能形成并发。

| 指标 | 2.5G CC 结果 |
|---|---:|
| 目标并发 | 1,000,000 |
| 实测峰值 `skCon` | 1,000,000 |
| 保持阶段请求/秒 | 50,000 |
| 保持阶段响应/秒 | 50,000 |
| 全程 TCP 请求 | 1,994,992 |
| 全程 TCP 响应 | 1,994,992 |
| `skErr/tcpDrop` | 0 / 0 |
| `ierrors/oerrors/imissed` | 0 / 0 / 0 |

测试结束时尚有 `994,992` 条连接处于建立状态，是测试时长结束后的正常快照，不是建连失败。

## 7. TRex 验证

### 混合网卡限制

当前接线对应 `.57` 上的一张 I210 和一张 I226。TRex 启动时能识别两张卡，但拒绝把两种驱动组成端口对：

```text
set driver name net_igc
Number of ports found: 2
ERROR all device should have the same type net_igc != net_e1000_igb
```

`--software` 模式仍有相同限制，`--limit-ports 1` 也不可用，因为 TRex 要求端口数为偶数。这是 TRex 的端口对约束，不是 DPDK 绑定失败。

### 同型号端口对启动

- `03:00.0 + 04:00.0`：TRex 使用 `net_e1000_igb` 成功初始化 2 个端口。
- `07:00.0 + 08:00.0`：TRex 使用 `net_igc` 成功初始化 2 个端口，已接线端在对端 testpmd 拉起后显示 `2500 Mbps full-duplex`。
- 未接线的第二端口显示 Link Down，符合现场接线情况。

### 2.5G STL 回环 smoke

```text
.57 TRex 07:00.0
        |
        | 2.5G 现有网线
        |
.67 testpmd 07:00.0（macswap 原口回送）
```

`.57` 的 `08:00.0` 在本测试中只用于满足 TRex 同型号端口对初始化，不承载流量。

| 指标 | 结果 |
|---|---:|
| 发送速率 | 10,000 pps |
| 持续时间 | 10 s |
| TRex TX | 100,000 |
| TRex RX | 100,000 |
| 丢包 | 0 |
| TX/RX errors | 0 / 0 |
| 对端 testpmd RX/TX | 100,000 / 100,000 |

结论：TRex STL 控制面、2.5G I226 驱动、发包、回包和统计功能正常。

## 8. 当前环境能测什么

| 目标 | 当前接线 | 是否可做 | 说明 |
|---|---|---|---|
| 验证 1G/2.5G DPDK 链路 | 双机两根直连线 | 可以 | 已完成 |
| dperf 新建连接 CPS | 双机同速直连 | 可以 | 已完成 100k/250k 基线 |
| dperf 并发连接 CC | 双机同速直连 | 可以 | 已完成 100 万基线 |
| TRex 单口 smoke | 同型号端口对初始化 + 一根有效链路 | 可以 | 已完成 100k 包零丢失 |
| TRex 路由器 PPS/NDR/PDR | 当前 1G+2.5G 混合线 | 不可以 | 要改为一台主机的两个同型号、同速率口 |
| 路由器真实性能 | 当前双机直连、无 DUT | 不可以 | 必须把路由器插入数据路径 |

理论最小帧线速约为：1G `1.488 Mpps`，2.5G `3.720 Mpps`。这只是链路线速上限，不是本次路由器实测结果。

## 9. 路由器正式测试接线

### 方案 A：dperf 测 CPS、CC、NAT/路由状态能力

推荐使用两台发生器，各占路由器一侧：

```text
管理网络：两台测试机 enp6s0 继续接 10.66.0.0/24

10.66.0.57 dperf client
        07:00.0（2.5G）
                |
                | DUT LAN：198.18.0.1/24
          [ 被测路由器 ]
                | DUT WAN：198.19.0.1/24
                |
        07:00.0（2.5G）
10.66.0.67 dperf server
```

测 1G 时把两端都换成 `03:00.0`。不要一侧 1G、另一侧 2.5G 后宣称 2.5G 性能；整条路径一定受最慢端口限制。

- 新建连接数：使用 dperf CPS 配置。
- 并发连接数：使用 dperf CC 配置，并确保客户端和服务端 `keepalive` 一致。
- NAT 测试：服务端配置中的 client 地址范围应匹配 DUT NAT 后看到的源地址。
- 纯路由测试：LAN/WAN 使用不同 RFC 2544 网段，网关分别指向 DUT 两侧地址。

### 方案 B：TRex 测包转发率、吞吐、时延、NDR/PDR

TRex 推荐由同一台主机的两个同型号端口夹住 DUT：

```text
                  07:00.0 / I226 / 2.5G
                +------------------------> DUT LAN
10.66.0.57      |
TRex generator  |
                +------------------------> DUT WAN
                  08:00.0 / I226 / 2.5G
```

1G 测试使用 `.57` 的 `03:00.0 + 04:00.0`，2.5G 测试使用 `07:00.0 + 08:00.0`。需要再增加一根同速网线；`.67` 在这种 TRex 拓扑中不是必需的。

建议至少测试这些帧长：`64/128/256/512/1024/1518` 字节，并分别记录：

- 单向和双向 PPS、bit/s；
- 丢包率；
- NDR（零丢包最大速率）；
- PDR（允许指定小丢包率时的最大速率）；
- 平均、P50、P99、最大时延；
- DUT CPU、内存、连接跟踪表占用。

## 10. 常用命令

### 查看和绑定

重启后测试网卡会恢复内核驱动，这是为了避免误绑定管理口。开始测试前执行：

```bash
sudo dpdk-bind-lab 0000:03:00.0 0000:07:00.0
sudo /opt/dpdk/bin/dpdk-devbind.py --status-dev net
```

绑定脚本会检查默认路由所在 PCI，并拒绝绑定管理口 `06:00.0`。

恢复内核驱动：

```bash
sudo dpdk-unbind-lab 0000:03:00.0 0000:07:00.0
```

### 清理 HugePage 映射

```bash
sudo dpdk-hugepage-clean
```

脚本会先确认没有 dperf、TRex、testpmd 进程且没有打开的大页文件，再清理所有残留映射。不要在 DPDK 应用运行时手工删除 `/dev/hugepages` 文件。

### dperf 当前直连 CPS

先在 `.67` 启动服务端：

```bash
sudo dperf -c /opt/dpdk-lab/config/direct-1g-server-cps.conf
# 或
sudo dperf -c /opt/dpdk-lab/config/direct-2g5-server-cps.conf
```

再在 `.57` 启动客户端：

```bash
sudo dperf -c /opt/dpdk-lab/config/direct-1g-client-cps.conf
# 或
sudo dperf -c /opt/dpdk-lab/config/direct-2g5-client-cps.conf
```

### dperf 当前直连 100 万 CC

`.67`：

```bash
sudo dperf -c /opt/dpdk-lab/config/direct-2g5-server-cc.conf
```

`.57`：

```bash
sudo dperf -c /opt/dpdk-lab/config/direct-2g5-client-cc.conf
```

### TRex 当前 2.5G smoke

`.57` 临时绑定同型号端口对：

```bash
sudo dpdk-bind-lab 0000:07:00.0 0000:08:00.0
cd /opt/trex
sudo ./t-rex-64 -i --cfg /opt/dpdk-lab/config/trex-direct-2g5-smoke.yaml --no-scapy-server
```

`.67` 用已接线端口原口回送：

```bash
sudo /opt/dpdk/bin/dpdk-testpmd -l 0-2 -a 0000:07:00.0 \
  --file-prefix=trex_smoke_peer -- \
  --portmask=0x1 --forward-mode=macswap --auto-start
```

在 `.57` 的另一个 SSH 会话运行：

```bash
sudo env PYTHONPATH=/opt/trex/automation/trex_control_plane/interactive \
  python3 /opt/dpdk-lab/trex-stl-smoke.py
```

### TRex 正式夹路由器

2.5G 示例：

```bash
sudo dpdk-bind-lab 0000:07:00.0 0000:08:00.0
cd /opt/trex
sudo ./t-rex-64 -i --cfg /opt/dpdk-lab/config/trex-2g5.yaml
```

1G 时改用 `03:00.0 + 04:00.0` 和 `trex-1g.yaml`。

## 11. 文件和日志

两台 Ubuntu 主机：

```text
/opt/dpdk                         DPDK 26.07
/opt/trex                         TRex 3.08 软链接
/opt/dpdk-lab/config              dperf/TRex 配置
/opt/dpdk-lab/results             实测日志
/usr/local/sbin/dpdk-bind-lab     安全绑定脚本
/usr/local/sbin/dpdk-unbind-lab   恢复内核驱动脚本
/usr/local/sbin/dpdk-hugepage-clean
```

有效结果日志：

```text
# .57
/opt/dpdk-lab/results/direct-1g-client.log
/opt/dpdk-lab/results/direct-2g5-client.log
/opt/dpdk-lab/results/direct-2g5-client-cc-valid.log
/opt/dpdk-lab/results/trex-direct-2g5-smoke-client.log
/opt/dpdk-lab/results/trex-direct-2g5-smoke-server.log

# .67
/opt/dpdk-lab/results/direct-1g-server.log
/opt/dpdk-lab/results/direct-2g5-server.log
/opt/dpdk-lab/results/direct-2g5-server-cc-valid.log
```

本地工作区配置位于 `tools/dpdk_lab/`。没有 `-valid` 后缀的 `direct-2g5-*-cc.log` 是修正服务端 keepalive 之前的诊断运行，不应用于性能结论。

## 12. 最终状态

截至报告完成时，两台机器状态一致：

```text
03:00.0  vfio-pci   当前 1G DPDK 口
04:00.0  igb        备用 1G 口
06:00.0  igb        管理口，UP
07:00.0  vfio-pci   当前 2.5G DPDK 口
08:00.0  igc        备用 2.5G 口
HugePages_Total=2048
HugePages_Free=2048
HugePages_Rsvd=0
DPDK applications=none
```

当前环境已经可以直接用于双机 dperf 基线和单链路 TRex smoke。要得到路由器的 CPS、CC、PPS、NDR/PDR 结论，按第 9 节接入 DUT 后重新执行正式测试。
