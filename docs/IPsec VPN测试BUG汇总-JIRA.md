# 爱快 OS 4.0 虚拟专网-IPsec VPN 测试 BUG 汇总

测试日期：2026-07-17  
页面：`虚拟专网 -> IPsec VPN`  
URL：`/#/vpn/ipsecVpn`  
最终自动化结果：产品失败 10，自动化失败 0，环境失败 0。

本次 GUI 复现报告：
`reports/output/test_report_20260717_174524.html`。执行时间约 187 秒，
共 14 个测试步骤，其中 7 个步骤包含产品失败；报告附有 66 条逐条可复制的
后端人工复验命令，最终清理和独立残留审计通过。

提交建议：以下每个二级标题单独创建一个 JIRA Bug，不要把 10 个问题合并为一单。

通用前置条件：

1. 进入爱快 OS 4.0 的“虚拟专网 → IPsec VPN”。
2. 使用两端可达的合法 IKEv2、PSK、proposal、ID 和 selector 配置。
3. 认证值只在页面遮罩输入框和运行时内存中使用，JIRA 附件不得包含认证明文。

## BUG-IPSEC-001 对端失效检测默认开启，但页面缺少“失效后如何处理”选项，策略无法保存

- 组件：IPsec VPN 前端表单 / `ipsec2_policy` 参数校验
- 优先级：P0
- 严重程度：阻断
- 复现步骤：新建隧道策略，保持页面默认 DPD 开启，填写其余全部必填项后保存。
- 期望结果：页面提交完整 DPD 参数并成功创建策略；或页面明确要求选择 DPD 动作。
- 实际结果：页面没有 `dpd_action` 控件且请求不包含该字段，保存返回
  `code=3001 请求参数不合法`。
- 现象：页面显示 DPD 已开启，并提交 `dpd_enabled/dpd_interval/dpd_timeout`，但没有 `dpd_action` 控件，也不提交该字段；后端返回 `code=3001 请求参数不合法`。
- 对照：在同一安全化请求中仅补 `dpd_action=restart` 后 API 成功；仅补隐藏的 `ah_auth` 仍失败。
- 影响：用户无法用页面默认 DPD 配置创建策略。
- 建议：前端补充 DPD 动作控件和默认值；后端对 DPD 关闭场景明确忽略，对开启场景返回具体字段错误。
- 验收标准：使用页面默认值可保存；API、DB 和重新打开后的 UI 值一致；缺失字段时返回具体字段名。

## BUG-IPSEC-002 页面会发出地址检查请求，但后台没有实现该请求

- 组件：IPsec VPN 前端请求 / `ipsec2_policy.sh show`
- 优先级：P1
- 严重程度：一般
- 复现步骤：进入隧道策略页并打开新增/地址相关表单，观察页面发出的
  `ipsec2_policy/show` 请求。
- 期望结果：`TYPE=resolve_check` 被后端识别并返回结构化校验结果，或前端不发送未注册 TYPE。
- 实际结果：HTTP 200，但业务码为 `2007`，消息为
  `unknown TYPE (resolve_check)`。
- 现象：`ipsec2_policy/show` 携带 `TYPE=resolve_check` 时返回
  `code=2007, unknown TYPE (resolve_check)`。
- 影响：域名/地址解析预检查链路失效，页面无法得到预期校验结果。
- 建议：后端实现 `resolve_check`，或前端删除该调用并统一到已注册 TYPE。
- 验收标准：页面加载和表单操作不再产生 unknown TYPE；错误地址仍能得到明确校验结果。

## BUG-IPSEC-003 页面提示新增成功，但后台连接服务没有启动，隧道无法使用

- 组件：`ipsec2_policy.sh` / charon 生命周期 / VICI 加载
- 优先级：P0
- 严重程度：阻断
- 复现步骤：在 charon 未运行的基线下新增合法策略，随后检查进程、VICI、监听端口、生成文件和已加载连接。
- 期望结果：新增成功前自动启动 daemon、完成加载并确认连接可见；任一步失败则保存失败并回滚。
- 实际结果：DB、cache、conf、secrets 已创建且操作返回成功，但 daemon、VICI、UDP 500/4500 和连接加载均未就绪。
- 现象：charon 关闭时新增策略，DB、cache、conf、secrets 均创建成功，脚本返回成功，但 charon 未启动、VICI 不可用、连接未加载。
- 根因：`ipsec2_policy.sh add()` 不调用 `__init_main_service`；`__exec_swanctl_up` 直接执行 `swanctl --load-all` 并丢弃结果。
- 影响：UI 显示成功但无 IKE/Child SA，典型“控制面成功、运行面失败”。
- 建议：add/edit/up 前确保 daemon/VICI ready；检查每次 load/up 返回码，失败时回滚 DB 和生成文件并向 UI 返回失败。
- 验收标准：停止 daemon 后从 UI 新增策略，返回成功时 daemon/VICI/连接必须全部就绪；故意制造加载失败时 DB 和文件保持原状。

## BUG-IPSEC-004 认证配置和运行 cache 权限为 0644

- 组件：IPsec secrets/cache 文件生成
- 优先级：P0
- 严重程度：安全
- 复现步骤：创建 PSK 策略后仅检查 secrets 和 cache 文件的权限、属主和存在性，不读取文件内容。
- 期望结果：认证文件不可被非特权用户读取，目录和文件使用最小权限。
- 实际结果：主路由和对端的 secrets、cache 文件均为 `0644`。
- 现象：双端 `/etc/swanctl/secrets.d/ipsec2-*.conf` 和 `/tmp/iktmp/cache/ipsec2/*` 实测均为 `0644`。
- 影响：同机非特权进程可读取 PSK 或认证字段。
- 建议：创建前设置 `umask 077`，最终文件使用 `0600/0400`，目录使用最小权限；增加升级修复和权限自检。
- 验收标准：新建、编辑和升级后的认证文件均为 `0600` 或更严格；自动化只检查权限，不输出内容。

## BUG-IPSEC-005 保存或启停中途失败时，后台可能留下不完整配置且不能自动恢复

- 组件：IPsec 配置生成 / DB 与 daemon 事务
- 优先级：P0
- 严重程度：严重
- 复现步骤：审查新增、编辑、启停、删除脚本，并在 daemon 加载失败时观察 DB、conf、secrets、cache 和运行态。
- 期望结果：配置原子替换；DB、文件和 daemon 加载构成可回滚事务；失败原因返回调用方。
- 实际结果：直接重定向覆盖文件，先修改 DB/文件再调用 daemon，加载输出被丢弃且没有统一回滚。
- 证据：conf、secrets、cache 使用直接 `>` 重定向；`swanctl --load-all` 输出普遍重定向到 `/dev/null`；新增、编辑、启停、删除先改 DB/文件后调用 daemon，没有事务回滚。
- 影响：进程中断或 daemon 拒绝时可能出现半文件、DB 与运行状态不一致、UI 假成功。
- 建议：同目录临时文件 + fsync + rename；保存旧 DB/文件快照；daemon 加载成功后提交，否则恢复旧状态。
- 验收标准：对写入中断、语法错误、VICI 不可用分别注入故障，操作均明确失败且所有层恢复到操作前。

## BUG-IPSEC-006 同一对称配置存在发起方向差异

- 组件：IKE proposal/connection 匹配 / 主动发起
- 优先级：P0
- 严重程度：阻断
- 复现步骤：使用同一双端合法配置清除现有 SA，先从主路由发起，再清除并从对端发起。
- 期望结果：两端作为合法 spoke 发起方时都能建立 IKE SA 和 Child SA。
- 实际结果：对端发起成功；主路由发起收到 `NO_PROPOSAL_CHOSEN`。
- 现象：对端发起可建立 IKE/Child；主路由发起相同 proposal/ID/PSK/selector 时收到 `NO_PROPOSAL_CHOSEN`。
- 影响：主动连接、自动重连和双向容灾不可用。
- 建议：检查主路由已有 L2TP/其他 IKE 连接的 proposal/credential 选择、连接匹配优先级和 responder proposal 过滤；增加双向发起回归。
- 验收标准：相同配置连续执行双向发起均成功，双端算法、ID、selector 和 Child 状态一致。

## BUG-IPSEC-007 停用后启用不能自动重连

- 组件：IPsec 策略启停 / 自动发起
- 优先级：P1
- 严重程度：严重
- 复现步骤：已建立双端 SA 和加密流量后，在 UI 停用策略，确认 SA/流量撤销；随后重新启用并轮询收敛。
- 期望结果：启用成功后按 auto 策略自动恢复 IKE/Child、XFRM 和流量。
- 实际结果：启用 API 返回成功，但双端无 IKE/Child、XFRM selector/state 和业务流量；手工从对端发起后可恢复。
- 现象：UI 停用/启用 API 返回成功，但双端 SA 在轮询超时内未自动恢复；测试夹具从对端显式发起后可以恢复。
- 影响：链路恢复、配置编辑后恢复和故障自愈不可靠。
- 建议：启用/编辑成功后验证 `start_action` 实际发起结果；失败应返回具体错误并按策略调度重试。
- 验收标准：连续停用/启用多轮均能在规定时间内自动收敛，失败时 UI 显示具体协商原因。

## BUG-IPSEC-008 两端协议版本不一致后，失败连接没有完全清理

- 组件：IKE 失败清理 / 半开 SA 生命周期
- 优先级：P1
- 严重程度：一般
- 复现步骤：正常链路上仅把一端改为不同 IKE 版本，发起协商并等待失败与清理超时。
- 期望结果：协商失败后双端均无本次 IKE/Child SA 和对应 XFRM state。
- 实际结果：主路由已无 SA，但对端仍保留本次单侧 IKE SA。
- 现象：单独把对端改为 IKEv1、主路由保持 IKEv2 后，协商失败符合预期，但对端仍保留同名 IKE SA，另一端已无 SA。
- 影响：反复失败会积累半开状态并干扰后续重连、凭据重载和诊断。
- 建议：失败/超时路径精确清理本次 IKE SA；按唯一 IKE ID 做残留回收。
- 验收标准：版本、proposal、ID 和认证失败均在超时后无双端残留，且不影响其他连接。

## BUG-IPSEC-009 两端密钥组不一致时，连接续期仍错误地提示成功

- 组件：Child SA proposal / CREATE_CHILD_SA rekey
- 优先级：P1
- 严重程度：严重
- 复现步骤：两端配置不同 PFS 组，允许首个 IKE_AUTH Child 建立，然后显式执行 Child SA rekey。
- 期望结果：CREATE_CHILD_SA 因 PFS proposal 不匹配而失败，旧 Child 的处理符合生命周期策略。
- 实际结果：CLI 返回 `rekey completed successfully`。
- 现象：双端分别配置 `modp2048` 与 `modp1024`，首个 Child SA 建立后执行 rekey，CLI 返回 `rekey completed successfully`。
- 说明：首个 Child 位于 IKE_AUTH，不以此判定 PFS；本缺陷是在 CREATE_CHILD/rekey 阶段复现。
- 影响：页面宣称的 PFS 约束没有形成预期安全边界。
- 建议：确认生成的 `esp_proposals`、运行连接更新和 rekey 使用的 child config；增加 PFS 不匹配的 CREATE_CHILD 负向测试。
- 验收标准：不同 PFS 组的 rekey 稳定失败；恢复一致后 rekey 成功且双端算法与配置一致。

## BUG-IPSEC-010 页面允许输入的范围和后台实际接受范围不一致

- 组件：IPsec 前后端 schema / 表单校验
- 优先级：P1
- 严重程度：一般
- 复现步骤：分别测试备注长度、SA 流量上限、PSK 字符/长度边界和安全协议选项，并对照后端参数校验。
- 期望结果：前端可输入范围、选项和后端接受范围完全一致，错误信息指出具体字段。
- 实际结果：多个字段上下限和协议能力不一致，导致页面可输入但保存失败，或后端能力无法从 UI 使用。
- 已确认：
  - 前端 IPsec SA 流量上限 `42949667295`，后端 `4294967295`；
  - 前端备注 maxlength 255，后端长度 80；
  - PSK 字符和长度规则不一致；
  - 页面只暴露 ESP/AH，后端还接受 `ah-esp`。
- 影响：页面可输入但保存失败，或后端存在页面不可达能力。
- 建议：以共享 schema 生成前后端校验和选项；错误响应返回具体字段、期望范围和实际值。
- 验收标准：边界值、边界外值和页面选项自动化全部通过，前后端共享同一字段约束来源。

## 验证通过项

- `ipsec2_tunnel/show + TYPE=list,list_total` 正常。
- DPD 关闭的合法 UI 策略可保存。
- 对端发起时双端 IKE/Child、XFRM 和双向真实流量通过。
- 正常 PFS 一致场景的 Child SA rekey 通过。
- PSK、proposal、ID、selector 不匹配能够阻止对应协商/Child 建立并可恢复。
- 最终精确清理、daemon 基线恢复和六管理通道审计通过。

## 最终证据

- 本次 GUI 报告：`reports/output/test_report_20260717_174524.html`
- JSON：`reports/archive/ipsec_testcase_report_20260717_174524/ipsec_test_results_20260717_174524.json`
- HTML：`reports/archive/ipsec_testcase_report_20260717_174524/ipsec_test_report_20260717_174524.html`
- Excel：`reports/archive/ipsec_testcase_report_20260717_174524/ipsec_test_results_20260717_174524.xlsx`
- 结果：产品问题 10，自动化问题 0，环境问题 0；14 个步骤、7 个失败步骤、66 条后端人工复验命令。
