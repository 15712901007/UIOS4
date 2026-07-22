# 爱快 OS 4.0 网络配置-OSPF 功能实测 BUG 汇总（JIRA）

**测试日期**：2026-07-19
**测试人**：戎士显（sxrong@ikuai8.com）
**测试方式**：Playwright UI 实操 + API 抓包 + SSH 后端验证（DB / FRR 配置 / daemon 进程 / 运行态），**手动独立实测，非自动化代码**
**与既有文档关系**：本报告独立于 `OSPF测试BUG汇总-JIRA.md`（2026-07-17，自动化产物）。本次实测复现了既有的 5 类问题，并**新定位 reload 根因、发现 5 个新缺陷、给出临时绕过方案**。

---

## 一、测试环境

| 项目 | 实测确认值 |
|---|---|
| 被测路由 | 10.66.0.150（**企业版**，Web admin/admin123，SSH sshd/ikuai8.com） |
| 内核 | 5.10.194（uname -r） |
| 协议实现 | FRRouting 7.5 (iKuai) |
| daemon | watchfrr / zebra / staticd 常驻；ospfd / ospf6d 按实例启停 |
| transit 接口 | lan1 = 192.168.148.1/22 |
| 页面路径 | `http://10.66.0.150/#/networkConfiguration/ospf` |
| 页面 API | `POST /Action/call`，`func_name=ospf`，action=show/add/edit/del/up/down |
| 底层脚本 | `/usr/ikuai/script/ospf.sh`（124411 字节，Jul 16 修改） |
| 配置文件 | 生成 `/tmp/ospf.frr`，活动 `/etc/frr/frr.conf` |
| OSPF DB | `/etc/mnt/ikuai/config.db`，11 张 ospf_* 表 |
| 测试前基线 | ospf 业务表全 0；frr.conf SHA = `cb59219095d9bb886049d075da076405da5465a0f72bff27a65bc4511bac7816`；ospfd/ospf6d 均未运行 |
| 测试后恢复 | 业务表全 0；frr.conf SHA 与基线**完全一致**；ospfd/ospf6d 均已停止（见文末恢复审计） |

---

## 二、问题清单（按严重级排序）

---

### OSPF-MCP-1【阻断 / Blocker】ospf reload 失败，区域接口与编辑类配置无法生效（核心根因）

**严重级**：阻断（OSPF 功能基本不可用）

**现象**：
通过页面/API 新建区域并绑定接口、编辑 Router ID、修改接口参数（cost/hello/dead/priority/network_type）、新增路由引入后，接口返回 HTTP 200、业务码 `2031`、`"操作失败" / "ospf reload failed"`。**DB 和 frr.conf 文件已正确写入，但 ospfd 运行态（running-config）未应用新配置**，OSPF 不会在接口启用。

**核心证据（新建区域 + 绑定 lan1，broadcast/cost10/hello10/dead40/priority1）**：

1. API 响应：
```json
{"code":2031,"message":"操作失败","errors":"ospf reload failed","details":[]}
```

2. DB 已正确写入（ospf_interface_attr）：
```
ifname=lan1 process_id=100 area_id=0.0.0.0 cost=10 hello_interval=10
dead_interval=40 priority=1 network_type=broadcast auth_type=none
```

3. frr.conf 已正确生成（含完整接口配置）：
```
interface lan1
 ip address 192.168.148.1/22
 ip ospf 100 area 0.0.0.0
 ip ospf cost 10
 ip ospf hello-interval 10
 ip ospf dead-interval 40
 ip ospf priority 1
 ip ospf network broadcast
!
```

4. **但 ospfd running-config 未应用**：
```
# show ip ospf 100 interface lan1
lan1 is up
  ...
  OSPF not enabled on this interface     <<< 接口未启用 OSPF
```

**reload 失败根因（本次实测新定位）**：
`/tmp/ospf_watchfrr.log` 日志：
```
reload_config=/usr/sbin/frr-reload --reload /etc/frr/frr.conf
vtysh mark text failed status=2 command=/usr/bin/vtysh --config_dir /etc/frr -m -f -
vtysh mark text output: line 1: % Unknown command: Parsing /var/run/frr, client limit(10) reached!
```
`ospf.sh` 的 `__run_frr_reload()` 调用 `frr-reload --reload`，其内部 vtysh 连接 daemon 时 **vtysh 客户端连接数已达上限（10）**，连接被拒 → reload 失败 → 新配置无法应用到运行中的 ospfd。

**失效边界（重要）**：
- **失效**：ospfd 运行中编辑任何配置（Router ID / 区域 / 接口参数 / 重分发），靠 reload 应用 → reload 失败 → 不生效。
- **生效**：触发 ospfd 进程**重启**的操作（新建实例、删除实例、down/up 实例）。重启时 ospfd 重新读取 frr.conf → 配置生效。
- 实测反证：对实例执行 down→up 后，`show ip ospf 100 interface lan1` 立即显示 `Area 0.0.0.0, Network POINTOPOINT, Cost 10, Hello 10s, Dead 40s`——**接口 OSPF 启用了**。证明 frr.conf 一直正确，只是 reload 没把它推进去。
- **间歇性**：reload 失败是间歇的（vtysh 连接数动态变化）。实测中删除某实例时 reload 恰好成功，顺带把之前编辑未生效的 Router ID 也应用了。

**复现步骤**：
1. UI 新建 OSPFv2 实例（process_id=100, router_id=198.18.252.1）。
2. 进入实例详情→OSPF区域→新建区域 0.0.0.0（normal）。
3. 编辑区域，添加接口 lan1，broadcast/cost10/hello10/dead40/priority1，保存。
4. 观察 API 返回 `2031 ospf reload failed`。
5. SSH 执行 `vtysh -c 'show ip ospf 100 interface lan1'`，显示 `OSPF not enabled on this interface`。
6. `cat /tmp/ospf_watchfrr.log`，见 `client limit(10) reached`。

**影响**：
- OSPF 接口永远无法进入协议运行态，**无法建立任何邻接、无法学习/宣告路由**。
- 用户在页面上看到"保存失败"，但 DB 和配置文件已变，状态不一致；下次 reload 成功时可能突然生效，行为不可预测。
- 这是 OSPF 模块的**核心阻断缺陷**，等于功能不可用。

**开发定位建议**：
1. 排查 vtysh client limit(10) 的来源——是 frr vtysh 套接字监听队列上限（`vtysh` 连接 backlog）还是存在 vtysh 连接泄漏（watchfrr/其他进程长期占用连接未释放）。
2. `__run_frr_reload` 失败时应有重试 + 失败后明确报错码（不能让 DB 已提交、daemon 未应用的不一致状态静默存在）。
3. 区分"DB 已提交 / 配置已生成 / reload 已应用"三态，API 返回值须准确反映；UI 不得把 reload 失败的 2031 当作可忽略。

**临时绕过方案（用户侧）**：
**每次编辑 OSPF 配置（区域/接口/重分发/Router ID）后，对该实例执行一次"停用→启用"（down→up），或保存后手动重启 ospfd，配置才会生效。** 仅新建/删除实例无需额外操作。

---

### OSPF-MCP-2【阻断 / Blocker】保存返回 reload failed 但实际已部分生效，缺少原子回滚

**严重级**：阻断（数据一致性）

**现象**：
新建/编辑实例、区域接口、重分发时，API 返回 `2031 reload failed`，但：
- DB 已写入（实例/区域/接口属性/重分发记录已入库）；
- frr.conf 已更新；
- 部分场景 daemon 已启动（新建实例时 ospfd 被拉起）。

失败后系统**不会回滚** DB 和配置文件，造成 API 响应、DB、frr.conf、daemon 运行态四层不一致。

**核心证据（新建 OSPFv2 实例）**：
- API：`code=2031 "ospf reload failed"`
- DB ospf_instance：已新增 1 行（process_id=100, router_id=198.18.252.1, enabled=yes）
- ospfd 进程：已启动（pid 15839）
- frr.conf：已含 `router ospf 100` + `ospf router-id`
- frr.conf SHA：从基线 `cb5921...` 变为 `08180e3d...`

**reload 失败时的部分回滚不一致（实测）**：
连续编辑接口参数矩阵后发现：reload 失败时，**部分字段已提交、部分字段被回滚**——例如 `network_type=point-to-point` 的 edit 入库了，但 `area_type=stub/nssa` 的 edit 未入库（DB area_type 仍为 normal）。同一事务内字段级提交行为不一致，进一步证明缺少原子性保证。

**影响 / 预期 / 建议**：见 OSPF-MCP-1。要求：reload 失败时 DB 与配置必须整体回滚到操作前；或全程成功才提交；API 必须准确区分"已提交/已回滚"。

---

### OSPF-MCP-3【严重 / Major】保存失败后前端列表不刷新，且 Router ID 显示与后端不一致

**严重级**：严重（前端状态污染，本次实测新发现）

**现象**：
保存实例返回 `2031 reload failed` 后：
1. **前端列表不显示新实例**（rowCount=0，"共 0 条"），尽管 DB 已入库、API `instance_list` 已返回该实例。
2. **必须手动刷新页面（或清 storage 重新加载前端）后，列表才显示**。
3. 编辑 Router ID 后，**前端列表显示的 Router ID 是旧值**，与 DB/API 不一致。

**核心证据**：
- 新建实例 100 保存（2031）后，前端列表 evaluate：`rowCount=0, has198=false`。
- 直接调 `instance_list` API：返回 `data` 含 process_id=100（**API 数据正确**）。
- 清 localStorage 重新加载前端后：`rowCount=1, "ipv4 100 198.18.252.1 ..."`（显示出来了）。
- 编辑 Router ID `.1→.2`（2031）后：前端列表仍显示 `.1`；但 `instance_list` API 返回 `router_id=198.18.252.2`（**前端显示与 API 不一致**）。

**根因推断**：
前端在收到 2031 失败响应后，未用最新 API 数据刷新列表 store（可能误把"reload 失败"当作"整体失败"而保留旧 store 状态），navigate 路由切换也不强制重新请求 `instance_list`，导致列表长期停留在过期视图。

**影响**：
- 用户保存后看不到实例，以为没创建成功，反复重试 → 重复创建。
- Router ID 等字段前端显示与实际不符，运维误判。
- 配合 OSPF-MCP-2（实际已生效），用户完全无法判断真实状态。

**预期**：保存（无论成功/失败）后，前端必须用最新 `instance_list` 数据刷新列表；或失败时明确提示并保持列表与后端一致。

---

### OSPF-MCP-4【阻断 / Blocker】OSPFv3 区域接口 API 返回 3001，OSPFv3 功能不可用

**严重级**：阻断（OSPFv3 完全不可用）

**现象**：
OSPFv3 实例可以新建（ospf6d 启动），但**新建 OSPFv3 区域并绑定接口时，API 返回 `3001 "请求参数不合法" / "operation failed"`**，DB 不产生 IPv6 区域和接口关联，OSPFv3 无法形成可运行配置。

**核心证据**：
- 新建 OSPFv3 实例（process_id=200, ipv6, router_id=1.1.1.200）：返回 2031 reload failed，但 DB 入库、ospf6d 启动（pid 8460）、running-config 有 `router ospf6 / ospf6 router-id 1.1.1.200`——**实例本身生效**。
- 新建 v3 区域接口（area_interface, address_family=ipv6）：
```json
{"code":3001,"message":"请求参数不合法","errors":"operation failed"}
```
- DB：`ospf_area where address_family='ipv6'` 为空；`ospf_interface_attr where address_family='ipv6'` 为空。
- `show ipv6 ospf6 interface lan1`：`OSPF not enabled on this interface`。

**复现步骤**：UI/API 新建 OSPFv3 实例 → 进入区域详情 → 新建区域 0.0.0.0 + 绑定 lan1 → 保存 → 3001。

**影响**：OSPFv3（IPv6 OSPF）从页面完全无法配置，功能不可用。

**开发定位建议**：核对 `address_family=ipv6` 的 area_interface 参数解析、OSPFv3 process_id→instance-id 映射、FRR 7.5 的 `router ospf6` 下 `interface <if> area <id>` 语法生成。3001 错误应指明具体字段。

---

### OSPF-MCP-5【高 / Major·Security】认证密码输入框明文显示且无 maxlength

**严重级**：高（信息安全）

**现象**：
区域接口编辑表单的"密码"输入框 DOM 为 `type="text"`（**明文显示**），且无 `maxlength` 属性。

**核心证据（DOM 采集）**：
```js
{ type:"text", placeholder:"请输入密码", maxlength:null }
```
截图证据：`reports/screenshots/ospf_04_area_iface_form_password_plaintext.png`（本次实测，密码框可见明文输入）。

**影响**：现场旁观、录屏、截图、DOM 采集均可直接获取认证密码；无 maxlength 易导致 UI/API 长度约束不一致。

**预期**：密码框默认 `type=password` 遮罩（可提供"显示/隐藏"开关但默认隐藏）；maxlength 与 API/daemon 一致；错误提示、日志、报告均不得回显密码原值。

---

### OSPF-MCP-6【中 / Major】前端 placeholder 范围与后端校验不一致（cost=0 / priority=-1）

**严重级**：中（契约不一致，本次实测扩展发现 priority=-1）

**现象**：
接口参数输入框 placeholder 宣传的范围/默认值，后端 API 实际拒绝：

| 字段 | placeholder 宣传 | API 实际响应 |
|---|---|---|
| 协议开销 cost | `0-65535（默认0）` | **cost=0 → 3001 拒绝**（即默认值 0 不可保存） |
| DR优先级 priority | `-1-255（默认-1）` | **priority=-1 → 3001 拒绝**（即默认值 -1 不可保存） |
| cost | 0-65535 | cost=65536 → 3001 拒绝（正确） |
| priority | -1-255 | priority=256 → 3001 拒绝（正确） |
| Hello | 1-65535 | hello=0 → 3001 拒绝（正确） |

**核心矛盾**：placeholder 把 `0` 和 `-1` 标为"默认值"，但后端拒绝这两个值。用户按页面提示填默认值会被拒，且只能在提交后才知道。

**预期**：页面范围/默认值与 API/DB/FRR 语义严格一致。若 cost 最小为 1，placeholder 应为 `1-65535`；若 priority 范围 0-255，placeholder 应为 `0-255`。

---

### OSPF-MCP-7【中 / Major】路由引入（redistribute）重复添加不拒绝，DB 产生重复记录

**严重级**：中（数据完整性，本次实测新发现）

**现象**：
对同一 OSPF 实例重复添加相同 `source` 的路由引入（如连续两次 add connected），API **不拒绝**（返回 2031 reload failed），DB **产生重复记录**。

**核心证据**：
连续 add：connected、static、default-gw、再次 connected。DB 结果：
```
id=1 source=connected process_id=100
id=2 source=static    process_id=100
id=3 source=default-gw process_id=100
id=4 source=connected process_id=100   <<< 重复
```
count=4（connected 出现两次）。

**影响**：同一引入源多条记录，前端列表会出现重复行；配置语义混乱；可能引发重复引入路由。

**预期**：同一 (process_id, address_family, source) 应唯一；重复 add 应返回明确错误（如 3001 已存在），不入库。

---

### OSPF-MCP-8【中 / Major】Router ID 为空被接受入库

**严重级**：中（输入校验，本次实测新发现）

**现象**：
新建实例时 Router ID 字段**非必填**（无 `*`），留空保存时 API 返回 2031 reload failed，**但实例仍入库（router_id 为空）**。OSPF 协议要求 Router ID 唯一标识设备，空值属非法。

**核心证据**：
```
add instance process_id=102 router_id='' → code=2031
DB: id=2 process_id=102 router_id=''（空）
```

**影响**：空 Router ID 的实例无协议意义，可能导致 ospfd 自动选 ID 与 DB 不一致；用户以为失败但实例已建。

**预期**：Router ID 必填，前端加 `*` 校验，后端空值直接 3001 拒绝（而非入库后 reload failed）。

---

### OSPF-MCP-9【中 / Major】脏表单取消无"继续编辑/确认放弃"二次确认

**严重级**：中（交互体验）

**现象**：
在新建/编辑实例表单中填写数据后点"取消"，Drawer **直接关闭并丢弃全部输入**，不弹出"继续编辑/确认放弃"二次确认。

**核心证据**：
填入实例号 100 + Router ID 198.18.250.250 后点取消：
```js
{ drawer_visible:false, confirm_dialog_visible:false }   // 直接关闭，无确认弹窗
```
（取消后 DB 未变，未发 API——这点正常；问题在于用户输入不可恢复。）

**影响**：复杂 OSPF 区域/接口/认证参数可能因误点取消全部丢失，重新填写成本高。

**预期**：已修改表单关闭时应弹二次确认；"继续编辑"保留输入返回表单，"确认放弃"才关闭。

---

### OSPF-MCP-10【低 / Minor】数值输入框无 HTML min/max 约束

**严重级**：低（前端校验缺失）

**现象**：
实例号（1-65535）、DR优先级、协议开销、Hello、邻居失效时间等数值字段均为 `type="text"`，**无 HTML `min`/`max` 属性**，仅靠 placeholder 文字提示范围。前端不做输入范围校验，完全依赖后端 API 拒绝（且后端拒绝又表现为 reload failed/参数不合法，提示不友好）。

**预期**：数值字段应使用 `type="number"` + `min`/`max` + `step`，前端即时校验越界/非法字符，给出明确提示，减少无效 API 请求。

---

## 三、本次实测确认"正常工作"的功能

| 功能 | 结论 | 证据 |
|---|---|---|
| 页面结构 | 正常 | 8 列齐全（版本/实例/Router ID/区域数/接口数/邻居数/引入数/操作）；新建/列设置/筛选/分页可用；无搜索/刷新/帮助/导入/导出（设计如此） |
| 实例新建（v2/v3） | 生效 | DB 入库 + ospfd/ospf6d 启动 + running-config 含 router-id（daemon 重启读 frr.conf 生效） |
| 实例删除 | 生效 | del 返回 code=0；DB 清除；daemon 停止；级联清理 area/interface_attr |
| 实例 down/up | 生效 | down→enabled=no + ospfd 停；up→enabled=yes + ospfd 重启；**up 后接口 OSPF 启用**（反证 reload 是唯一阻断点） |
| 重复实例号拒绝 | 正常 | code=3001 |
| 非法 Router ID（999.1.1.1）拒绝 | 正常 | code=3001 |
| process_id 边界（0 / 70000）拒绝 | 正常 | code=3001 |
| cost 超界（65536）、priority 超界（256）、hello=0 拒绝 | 正常 | code=3001 |
| 删除级联清理 | 正常 | 删实例后 area/interface_attr 自动清零 |

---

## 四、临时绕过方案（修复前供运维/测试使用）

**核心结论**：OSPF 配置能否生效，取决于是否触发 ospfd 进程重启。

1. **新建 / 删除实例**：自动触发 daemon 重启，**无需额外操作**，配置生效（受 OSPF-MCP-2 部分生效问题影响，状态需 SSH 复核）。
2. **编辑类操作**（改 Router ID、区域类型、接口参数、加路由引入、加认证）：保存后**必须对该实例执行一次 down→up**（或 SSH 手动 `kill <ospfd-pid>` 让 watchfrr 拉起），配置才会被 ospfd 重新加载生效。
3. **OSPFv3 区域接口**：当前**无法配置**（3001），无绕过方案，需修复。
4. **判断真实状态**：不要信任前端列表（OSPF-MCP-3），一律用 SSH：
   - `vtysh -c 'show ip ospf <pid> interface <if>'`（看接口是否 enabled）
   - `vtysh -c 'show running-config' | grep -A10 'router ospf'`（看运行配置）
   - `sqlite3 /etc/mnt/ikuai/config.db "select * from ospf_instance"`（看 DB）

---

## 五、reload 根因与修复优先级建议

**所有 reload 相关问题（MCP-1/2/3/5 生效层面）的统一根因**：
`/tmp/ospf_watchfrr.log` 显示 `frr-reload` 调用 vtysh 时报 `client limit(10) reached`。建议开发：

1. **首要**：排查 vtysh 客户端连接上限——是 frr vtysh 监听 backlog 限制，还是存在 vtysh 连接泄漏（某进程长期占用未释放）。若为泄漏，定位占用方并修复；若为 backlog 不足，评估提升上限。
2. `ospf.sh` 的 `__run_frr_reload` 失败应重试，并区分"配置生成成功/reload 失败"两态，失败时回滚 DB + 配置（解决 MCP-2 原子性）。
3. 前端把 reload 失败（2031）的语义正确传递给用户，并刷新列表（解决 MCP-3）。
4. **独立修复** OSPFv3 area_interface 的 3001（MCP-4，与 reload 无关）。
5. 输入校验/前端约束类（MCP-5/6/8/9/10）按优先级排期。

---

## 六、测试后环境恢复审计

清理（删除全部测试实例/区域/接口/重分发）后：

```
ospf_instance         : 0
ospf_area             : 0
ospf_interface_attr   : 0
ospf_redistribute     : 0
ospfd     : NONE
ospf6d    : NONE
frr.conf SHA = cb59219095d9bb886049d075da076405da5465a0f72bff27a65bc4511bac7816  (与测试前基线完全一致)
proto89规则 = 0
ospf路由 = 0
ospf_interface预置 = 4（lan1/wan1/wan2/wan3，未受影响）
```

环境已干净恢复，未遗留任何测试残留，未重启设备，未清空整表。

---

## 附：本次实测关键截图/证据文件

- `reports/screenshots/ospf_01_list_empty.png` — 空列表
- `reports/screenshots/ospf_02_new_instance_form.png` — 新建实例表单
- `reports/screenshots/ospf_03_list_with_instance.png` — 列表显示实例（刷新后）
- `reports/screenshots/ospf_04_area_iface_form_password_plaintext.png` — 区域接口表单（密码明文）
- reload 根因日志：路由器 `/tmp/ospf_watchfrr.log`
