# OSPF 自动化事实记忆

更新时间：2026-07-16。本文只记录页面、API、DB、脚本、进程和实机测试已确认的事实。

## 管理身份与安全通道

- 主路由器身份：`10.66.0.150`；备用外网管理：`10.66.0.27`。
- 电脑直连主路由 LAN1：`192.168.148.1`；可作为 Web/SSH 恢复与诊断通道。
- 持久配置中的 `device.ip` 和 `ssh.router.host` 保持 `10.66.0.150`；实机定位通过进程级 `DEVICE_IP=192.168.148.1` 覆盖 Web 地址。
- OSPF 客户端：`10.66.0.18`，业务接口 `ens11=192.168.148.2/22`，loopback `10.99.99.1/32`。
- OSPF 对端主/备用管理地址：`10.66.0.56`、`10.66.0.57`。
- 人工复验命令 target 只有 `router` 和 `client`，分别严格表示 `10.66.0.150`、`10.66.0.18`。

## 页面真实能力

- URL：`/#/networkConfiguration/ospf`。
- 列：版本、OSPF 实例、Router ID、OSPF 区域数目、已启用接口数目、邻居数目、引入外部路由数目、操作。
- 存在：新建、编辑、删除、列设置、各列筛选、分页，以及区域、接口、邻居、重分发四个详情 Tab。
- 不存在：独立搜索、刷新、帮助、复制、批量工具栏、导入、导出。
- 实例支持 OSPFv2、OSPFv3、实例号和 Router ID。
- 区域类型支持 Normal、Stub、NSSA；三种状态均未显示 no-summary 控件。
- 接口类型支持 broadcast、non-broadcast、point-to-multipoint、point-to-point。
- 接口字段包含接口、密码、DR 优先级、协议开销、Hello、Dead。
- 页面占位约束：priority `-1..255`、cost `0..65535`、Hello/Dead `1..65535`。
- 密码输入框实机为明文 `text` 且没有 `maxlength`。
- 脏表单取消会直接关闭 Drawer，不出现“继续编辑/确认放弃”弹窗；取消没有 API 请求且 DB 不变。

## API、DB 和脚本契约

- API：`POST /Action/call`，`func_name=ospf`。
- 动作：`show/add/edit/del/up/down`。
- 主要 table：`instance`、`area_interface`、`redistribute`，列表查询使用 `instance_list`。
- 11 张相关表：`ospf_basic`、`ospf_instance`、`ospf_area`、`ospf_interface`、`ospf_interface_attr`、`ospf_redistribute`、`ospf_static_route`、`ospf_prefix_list_entry`、`ospf_log_target`、`ospf_debug_flag`、`ospf_vty_line`。
- 脚本：`/usr/ikuai/script/ospf.sh`；临时生成配置 `/tmp/ospf.frr`；活动配置 `/etc/frr/frr.conf`。
- 主路由使用 FRR 7.5，实际 daemon 包含 watchfrr、zebra、ospfd、ospf6d、staticd。
- OSPFv3 接口参数在 interface 模式配置；区域绑定在 `router ospf6` 下使用 `interface <ifname> area <area>`；process_id 映射到接口 instance-id。
- 客户端 FRR 10.6.1 的 ospf6d 基线未运行；测试仅临时启动精确 ospf6d PID，finally 后停止并恢复原始配置。

## 已确认产品根因

正式综合用例保留 29 个失败步骤证据，按因果去重为 6 类产品根因：

1. 脏表单取消没有继续编辑/确认放弃分支。
2. 多个 add/edit 保存返回 HTTP 200、业务码 2031/reload failed，但 DB 或活动配置已部分变化；没有回滚，daemon 未完整加载接口命令。
3. 认证输入框未遮罩且没有 maxlength。
4. 配置更新缺少原子替换与 DB 回滚保证。
5. 页面声明 cost=0 合法，但 API 以 `参数错误: cost` 拒绝。
6. OSPFv3 实例可写入，但区域接口 API 返回 3001，DB 不产生区域/接口关联，UI 到运行态链路失败。

透明 vtysh 诊断只用于证明 daemon/拓扑能力，不计作 UI 保存通过。

## L3-L5 实机结论

- OSPFv2：主路由与客户端双向 Full；LSDB 包含双方 Router-LSA 语义；主路由安装 `10.99.99.1/32` 的 `proto ospf` 路由；协议 89 抓包成功；4/4 真实流量成功。
- OSPFv2 认证：短运行时 message-digest 值写入 DB；对端不匹配后邻接撤销、流量失败；清除认证后 Full、路由和流量恢复。报告不保存认证值。
- OSPFv2 撤销：仅撤销客户端 loopback 宣告后路由与流量消失；恢复宣告后路由和流量恢复。
- 实例 down/up：DB enabled、邻接和路由均按状态轮询完成撤销与恢复。
- OSPFv3：透明运行态诊断下双方 Full、LSDB 包含双方 Router ID、主路由安装随机 `/128` 的 `proto ospf` IPv6 路由，`ping6` 4/4 成功；UI 区域保存仍按产品缺陷失败。

## 三节点物理边界

- 两台 iKuai 管理父接口创建未占用 tagged VLAN 后，两端接口均 UP，但双向定向 ping 均 0 接收。
- `10.66.0.56` 的 LAN1 物理链路为 down。
- 当前交换路径不承载额外 tag；禁止在 `10.66.0.0/24` 管理网启用 OSPF。
- 三节点端到端、多区域 ABR、同广播域 DR/BDR、ECMP 当前为环境不适用；`.57` 只作备用管理，不能冒充数据面。

## 正式产物与恢复

- 正式归档：`reports/archive/ospf_final_20260716_230655/`。
- JSON/HTML/Excel 一致性审计：1 个用例、12 步、54 条复验命令。
- 桌面 1440x900、移动 390x844 布局通过；54/54 复制按钮通过。
- PyInstaller 构建成功；冻结 OSPF 精确 collect：exit=0、collected=1；源码和冻结 GUI offscreen 启动均未提前退出。
- 正式 finally 和独立复核均通过：OSPF 业务表为空；活动配置哈希恢复为 `cb59219095d9bb886049d075da076405da5465a0f72bff27a65bc4511bac7816`；watchfrr/zebra/staticd 数量恢复；ospfd/ospf6d 为 0；无协议 89 规则、OSPF 路由、测试 VLAN、客户端临时 IPv6 前缀或临时 ospf6d 残留。

## 2026-07-17 实时日志与耗时复核

- OSPF 综合用例新增专用单行安全日志，使用进程内敏感值登记表脱敏并 `flush=True`；GUI 实机链路已验证为 `TestRunner -> pytest 子进程 -> log_signal -> MainWindow._log -> log_text`。
- 用例开始、步骤操作/期望、页面/后台/运行时/协议检查、步骤状态/耗时和最终分类统计均实时输出。邻居、路由、实例、临时进程、协议抓包和恢复等待每约 5 秒输出已等待时间、最大等待和当前非敏感状态。
- 优化前 354.17 秒；最终验收轮 395.33 秒。总时长增加来自实例重新启用后真实邻接本轮约 41 秒收敛（优化前该轮仅 1.418 秒），不是日志或 SSH 阻塞。关键项：步骤5 `79.50 -> 84.45` 秒，步骤6 `36.66 -> 34.67` 秒，步骤7 `119.39 -> 119.36` 秒，OSPFv3 `41.68 -> 33.11` 秒。
- 首次 Full 为 44.69/约 45 秒、认证不匹配撤邻为 36.06/约 36 秒，符合 Hello/Dead 定时器；对端邻接检查约 0.1 秒，证明没有重复完整等待。保留 55/45 秒上限及真实收敛标准。
- OSPFv3 客户端临时 `ospf6d` 启动改为重定向全部标准流，最终验收无 `SSH exec failed`/重连；2026-07-17 18:16:16 的一次重连属于后台进程继承 SSH stdout 导致的额外约 10 秒等待。
- 最终报告：`reports/output/test_report_20260717_195756.html`；同源归档 JSON/Excel 分别为 `test_results_20260717_195756.json`、`test_report_20260717_195756.xlsx`。三产物审计为 1 用例、12 连续步骤、54 条一致的只读复验命令，统计保持产品根因 6、失败证据 29、自动化 0、辅助/恢复 0。
- 最终 GUI 时间戳日志：`reports/output/ospf_gui_realtime_acceptance_20260717.log`，359 条时间戳记录，最大静默 17 秒；协议轮询约 4-6 秒，不再存在数分钟空白。
- PyInstaller 6.11.1 最终构建成功；程序为 `dist/iKuai自动化测试工具/iKuai自动化测试工具.exe`。冻结 OSPF collect=1、依赖检查通过，冻结 GUI 离屏启动 6 秒未提前退出。
- 最终独立只读审计再次确认：表/配置/客户端哈希一致，OSPF 路由与协议 89 规则为 0，两端测试 VLAN、客户端临时 IPv6 和临时 ospf6d 均为 0。
