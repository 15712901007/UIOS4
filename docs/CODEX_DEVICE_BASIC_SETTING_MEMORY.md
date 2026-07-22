# 设备设置-基础设置实机记忆

> 最后实机确认：2026-07-16。本文只记录本轮页面、接口、数据库、脚本、运行态和真实流量已经确认的事实。不得写入设备名称、自定义 NTP 原值、账号、密码、硬件地址或认证数据。

## 页面与接口

- 菜单为“设备设置 -> 基础设置”，页面 URL 为 `/#/equipmentSetting/basicSetting`。
- 页面是 `basic.id=1` 单例表单，不是列表页。没有搜索、增删改查、多选、批量、导入、导出、排序、分页或独立刷新按钮。
- 页面存在基础设置 Tab、帮助入口、保存、立即对时和手动设时条件入口。
- 页面没有取消按钮；修改脏表单后离开页面不会出现“继续编辑/确认放弃”确认框，也不会产生隐式保存请求。
- `currentTime` 是 19 字符只读显示。
- 主机名 `maxlength=21`。同步周期是可见原生数字输入，`min=5`、`max=240`。
- 时区下拉有 38 个唯一选项；内置 NTP 下拉有 7 个选项。
- 旁路模式监听接口实机仅 `lan1`，回注接口为 `wan1/wan2/wan3`。
- 保存和动作统一使用 `POST /Action/call`。实机动作契约为 `func_name=basic`，动作包括 `show`、`save`、`sync_time`、`set_time`。
- 页面请求证据只允许记录方法、endpoint、func/action、HTTP 状态和业务成功布尔，禁止记录请求参数或响应私有数据。

## 数据库与脚本

- 产品脚本为 `/usr/ikuai/script/basic.sh`，NTP 辅助脚本为 `/usr/ikuai/script/utils/ntp.sh`。
- 数据表为 `config.db.basic`，固定 `id=1` 单例。本轮测试前后均只有 1 行。
- 已确认字段：`id`、`hostname`、`language`、`time_zone`、`time_zone_full`、`switch_nat`、`switch_dpi`、`switch_ntp`、`switch_ntpd`、`switch_ntpserver`、`ntpserver_list`、`ntp_sync_cycle`、`link_mode`、`fast_nat`、`lan_nat`、`listenport`、`backport`。
- 生成缓存为 `/tmp/iktmp/cache/config/basic`。时区同时映射到 `/etc/TZ` 和 localtime 链接；主机名同时映射到缓存、hostname 和 hosts 文件。
- `basic.sh` 存在 `init`、`save`、`sync_time`、`set_time` 入口；没有独立 `start`、`stop`、`reload` 生命周期入口。保存后由产品 init 链重建运行态。
- 最终基线模式代码为 `switch_nat=1`、`lan_nat=0`、`link_mode=0`、`fast_nat=0`。私有文本基线只保存在测试进程内存快照中。

## 上网模式

- NAT4 对应 `switch_nat=1`。基线运行态为 2 条 AUTONAT 规则，无 PRE/POST_FULLCONE 和 NONAT 规则。
- NAT1 对应 `switch_nat=2`。运行态存在 PRE_FULLCONE、POST_FULLCONE 各 1 条及精确 UDP conntrack 映射。
- 路由模式对应 `switch_nat=0`；`lan_nat` 是该模式的独立本机流量 SNAT 开关。
- NAT4/NAT1 L5 使用同一严格控制模型：LAN 网卡建立映射，独立管理网卡作为不同外部源发包，同时验证路由器 WAN 入站、LAN 转发、精确 conntrack 映射和 FULLCONENAT 计数。
- NAT4 实测为 WAN 入站可见、LAN 不转发、FULLCONENAT 增量 0；NAT1 实测为 WAN 入站可见、LAN 转发可见、FULLCONENAT 计数增加。两种模式均完成修改前、修改后和恢复后真实连通性控制。
- 同一双网卡客户端的应用 socket 接收受本机自源地址语义影响，不作为 NAT 锥形判据，明确标记不适用；路由器数据平面证据仍为真实 L5。
- 路由模式在 tcpdump 明确进入监听后连续发包，WAN 实包保持客户端 LAN 源地址，证明未做源 NAT。
- 产品缺陷：路由模式 `add_no_nat_default` 追加前不清理 NONAT。独立 init 后规则由 2 条累积为 4 条，`basic.sh init` 不幂等。

## 链路模式

- 页面支持主干 `link_mode=0`、旁路 `link_mode=1`、SD-WAN 网桥 `link_mode=2`。
- 三种模式的页面保存、DB、缓存、`basic.sh init`、内核摘要和旧态释放均已完成 L1-L4 验证。
- `basic.sh` 的链路函数触发 `notify.d` 和桥模式控制；当前实机可执行通知处理器数量为 0。
- 产品脚本和 AC 启动入口不存在 `link_mode -> AC -b` 映射。AC 只按全局服务开关验证存在性，不能虚构 `-b` 参数断言。
- 当前 router 的 `lan1/wan1/wan2/wan3` 均 UP 且有地址，客户端 LAN 网卡和管理路径分离，管理通道切换期间保持可用。
- 当前拓扑只有承载现有客户端的单个监听侧，没有第二个独立发流端、回注对端或双侧物理抓包点。因此三种链路模式 L5 均为“受环境限制/不适用”；只报告完整 L1-L4 和底层运行态，禁止伪造流量。

## 加速模式

- `support_fast=1` 的实机页面只显示“关闭”和“软件模式”；硬件模式不存在，页面与 L5 均不适用。
- 关闭模式 `fast_nat=0` 正常：DB、缓存、脚本清链和无 FASTOFFLOAD 规则一致。
- 软件模式保存后 DB 和缓存均为 `fast_nat=1`，页面刷新也回显软件模式。
- 产品/固件缺陷：产品 init 的运行分支没有形成 FASTOFFLOAD 规则；当前内核没有加载 FLOWOFFLOAD target，虽然 connbytes 和 ifaces 匹配器存在。
- 软件模式真实 iperf 流量可达，但 FASTOFFLOAD 规则数和计数增量均为 0，不能宣称软件加速生效。对应 L3、L4、init 和 L5 必须失败。

## 时间与 NTP

- 内置 NTP 周期 5 和 240 边界均通过保存、DB、生成配置、运行态和刷新验证。
- NTP 服务启用时真实 SNTP 正控制通过；关闭后负向控制通过；再次启用后的恢复正控制通过。
- 合法自定义 NTP 已通过 DB、生成缓存、运行态、`basic.sh init`、立即同步请求契约、系统时钟/RTC 效果和同步后配置保持验证。
- 产品缺陷：合法自定义 NTP 已在 DB/缓存持久化且真实同步成功，但重新进入页面后地址控件缺失，不能回显已保存地址。
- 手动设时会进入手动模式，并按前端组合契约更新 NTP 相关字段；不能错误要求 `set_time` 后整行 basic 完全不变。
- 产品缺陷：日期组件保留无效日期时间，页面无错误提示，控件 `aria-invalid=true` 仍可提交；`set_time` 返回成功并实际改变 NTP 字段、系统时钟和 RTC。
- 合法短时偏移手动设时、立即对时、系统/RTC 相对客户端时差恢复均通过。恢复依据是相对可信时钟偏差，不回写历史绝对时间。

## 已确认产品缺陷

1. 页面缺少取消按钮。
2. 脏表单离开没有继续编辑/确认放弃机制。
3. 无效手动日期时间仍被成功提交并改变运行态。
4. 路由模式 NONAT 规则在重复 init 后累积。
5. 软件加速被页面支持但没有形成 FASTOFFLOAD 运行态和计数效果。
6. 自定义 NTP 后端持久化和同步成功后，页面重新进入时不回显地址控件。

最终综合报告包含 14 个产品失败断言，它们是上述缺陷在页面、L1-L5 和重建链路上的分层证据，不代表 14 个独立产品缺陷。

## 最终恢复与产物

- 最终综合用例自动化失败 0、清理失败 0、产品失败 14、环境警告 3；finally 步骤通过。
- 最终独立审计：DB 单例和基线模式匹配，DB 到配置及当前运行态一致，Web、路由器 SSH、客户端 SSH、系统时钟和 RTC 均健康。
- 最终主路由 8 条、策略规则 26 条、ipset 65 个、内核模块 27 个；这些数量仅是本轮恢复后的实机指纹。
- 最终 AUTONAT 2 条；PRE/POST_FULLCONE、NONAT、FASTOFFLOAD 均为 0。客户端精确测试路由不存在。
- router/client 的 `ikuai-basic-*` 文件和探针进程、相关 tcpdump、精确测试 conntrack 残留均为 0。
- 最终 JSON、HTML、Excel 为同一 1 个用例、16 步、600 条人工复验命令；三产物内容和顺序一致，敏感值、硬件地址和本机用户路径扫描通过。
- 最终冻结包 collect smoke 为 `collected=1`、pytest exit 0、进程 exit 0；源码 GUI 和冻结 GUI 启动 smoke 均通过。

