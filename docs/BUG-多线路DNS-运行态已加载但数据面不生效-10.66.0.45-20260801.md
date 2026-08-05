# 多线路DNS运行态已加载但数据面不生效

## 结论

- 被测设备：`10.66.0.45`，IK-G2606-MXP，4.0.303 x64 Build202607281258，Linux 5.10.194。
- 打流客户端：`10.66.0.18` 的 `ens11 / 192.168.148.2`。
- 测试线路：`wan2`，设备地址 `192.168.112.106`，网关 `192.168.112.1`。
- 规则：`wan2 -> 223.5.5.5 / 223.6.6.6`。
- 结果一：数据库和 `ik_core` 运行态均正确，但真实 DNS 请求仍发往原目标 `114.114.114.114`，启用和重新启用后均稳定复现。
- 结果二：停用唯一规则后接口映射已删除，但全局状态仍为 `Multi Dns: enable`；删除规则后才变为 `disable`。

## 前置条件

1. DNS加速保持关闭，避免本地DNS代理改变数据路径。
2. 客户端将 `114.114.114.114/32` 临时固定经 `192.168.148.1 dev ens11`。
3. 被测设备将同一目标临时固定经 `wan2`，保证探针出口唯一。
4. 测试前确认 `dns_replace` 无其他规则，`Multi Dns Info` 为空。

客户端探针：

```bash
dig @114.114.114.114 www.qq.com A +short +time=4 +tries=1 -b 192.168.148.2
```

## 期望结果

规则启用时，客户端请求从 `wan2` 发出前，目的 DNS 应由 `114.114.114.114:53` 改写为 `223.5.5.5:53` 或 `223.6.6.6:53`。停用唯一规则后，接口映射应撤销且全局多线路DNS开关应变为 `disable`。

## 实际结果

### 缺陷一：运行态映射存在，数据面未改写

L2 数据库验证通过：

```text
tagname=mldns_flow
interface=wan2
dns1=223.5.5.5
dns2=223.6.6.6
enabled=yes
```

`/proc/ikuai/stats/ik_summary` 同时存在普通WAN和广告接口映射：

```text
Multi Dns: enable
====================== Multi Dns Info ======================
1. wan2    223.5.5.5    223.6.6.6
2. wan2_ad 223.5.5.5    223.6.6.6
```

连接跟踪确认客户端请求出口为 `wan2`：

```text
src=192.168.148.2 dport=53 remote_if=wan2
```

但 `wan2` 抓包显示启用态仍访问原DNS：

```text
192.168.112.106.59855 > 114.114.114.114.53:
6237+ A? www.jd.com.
```

自动化在初次启用和停用后重新启用两次检查，WAN目标均为：

```text
WAN目标=['114.114.114.114']
期望=['223.5.5.5', '223.6.6.6']
```

DNS查询均能返回A记录，因此不是WAN不可达或探针未发出，而是多线路DNS目的地址改写未生效。

### 缺陷二：停用唯一规则后全局开关未关闭

停用规则后：

- 数据库 `enabled=no`，正确。
- `wan2`、`wan2_ad` 两条运行态映射均消失，正确。
- `Multi Dns: enable`，错误，期望为 `disable`。

设备脚本 `/usr/ikuai/script/dns_replace.sh` 中，`down()` 和 `up()` 只增删接口映射，没有调用 `__exec_switch`；`del()`、`clean()` 和 `init()` 会调用该函数。这与“停用后开关残留、删除后开关恢复”的实测现象一致。

## 分层结果

| 验证项 | 结果 | 证据 |
|---|---|---|
| L2 数据库加载 | 通过 | `wan2 / 223.5.5.5 / 223.6.6.6 / enabled=yes` |
| L2 内核运行态 | 通过 | `wan2` 与 `wan2_ad` 映射均存在 |
| L3 基线 | 通过 | 无规则时原DNS经 `wan2` 发出并正常解析 |
| L3 启用态改写 | 失败 | WAN目标仍为 `114.114.114.114` |
| L2 停用映射撤销 | 通过 | 两条接口映射均消失 |
| L2 停用全局开关 | 失败 | 唯一规则停用后仍为 `Multi Dns: enable` |
| L3 停用透传 | 通过 | 恢复访问原DNS并正常解析 |
| L3 重新启用改写 | 失败 | WAN目标仍为 `114.114.114.114` |
| 删除及清理 | 通过 | 数据库、运行态映射和全局开关均恢复 |

## 修复建议

1. 检查 `ik_multi_dns_nat` 对LAN转发DNS流量的匹配和目的地址改写路径，重点核对 `remote_if=wan2` 时是否查询了 `wan2` 或 `wan2_ad` 映射。
2. 在 `dns_replace.sh` 的 `up()`、`down()` 完成数据库和映射变更后调用 `__exec_switch`。
3. 保留WAN抓包硬断言，不能仅以数据库成功或 `Multi Dns Info` 存在作为功能通过依据。

## 自动化与报告

独立功能脚本：

```text
tests/network/test_dns_multi_line_functional.py
```

运行命令：

```powershell
pytest -v -s --tb=short tests/network/test_dns_multi_line_functional.py
```

两次独立实机复现报告：

```text
reports/output/test_report_20260801_082211.html
reports/output/test_report_20260801_083155.html
```

## 清理确认

2026-08-01 实机验证结束后已确认：

- `dns_replace` 数据库无测试规则。
- `Multi Dns: disable`，`Multi Dns Info` 为空。
- DNS加速恢复为原始关闭状态，`ikdnsd` 无运行残留。
- 路由器和客户端均无 `114.114.114.114/32` 测试路由。
- 无 `/tmp/dns-multi-functional-*` 文件或抓包进程。
