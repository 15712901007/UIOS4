# 爱快 OS 4.0 GRE 隧道「配置生效 / 边界 / 生命周期」测试 BUG 汇总（JIRA 简洁版）

> 本篇为 **2026-07-17 配置真生效 + 边界值 + 生命周期自动化测试** 新发现 / 复核的 BUG，与《GRE隧道测试BUG汇总-JIRA》（多 WAN / 数据面 / UI 篇）**互补**。
> 核心方法：UI 保存后不只看 DB，**SSH 查 `ip -d link show` 验内核实际下发参数**，暴露"UI/DB 成功但内核没生效"类问题。

## 测试环境

| 项目 | 信息 |
|---|---|
| 被测设备 | 10.66.0.150（iKuai OS V4 企业版，内核 6.12） |
| GRE 对端 | 10.66.0.56（同凭据） |
| 底层脚本 | `/usr/ikuai/script/gre_tunnel.sh`；DB 表 `gre_tunnel` |
| 验证方法 | Playwright UI + SSH `ip -d link show` 内核参数解析 + tcpdump 抓包 |
| 自动化用例 | `tests/advanced_service/test_gre_tunnel_comprehensive.py`（config_effect / boundary / lifecycle / ui_prompts / dataplane_capture 5 聚焦测试，全 PASS，BUG 软断言进报告） |

> 共 **8 条**：6 条新发现（BUG-1~6），2 条复核确认旧条目（BUG-7~8）。按严重度排序。**BUG-1/2/3 建议优先处理（核心参数形同虚设 / 语义反转）。**

---

## BUG-1【Major】GRE 高级配置 keepalive 完全不生效（DB 开启但内核无字段）

- **模块**：虚拟专网 → GRE → 高级配置「keepalive 发送周期 / 最大传输次数」
- **复现**：
  1. 新建 GRE，高级配置开启 keepalive（周期 10、次数 3），保存
  2. SSH：`ip -d link show gre<编号>`
- **预期**：`ip -d` 输出含 `keepalive 10 3`，隧道周期发探测包，对端不可达时因探测失败而 down
- **实际**：`ip -d` **无 keepalive 字段**；wan 口抓 proto 47 无周期探测包；keepalive 形同虚设，对端失联隧道不会 down
- **根因**：脚本 `gre_tunnel.sh:489/509` 用 `ip tunnel change <iface> keepalive <间隔> <次数> >/dev/null 2>&1` 下发，但 **iproute2 5.15 / 内核 ip_gre 不支持 keepalive 参数**（主线 Linux 无此特性，属 Cisco/H3C 扩展）→ 命令必然失败，`2>&1` 吞错，DB 仍 keepalive=1 用户无感
- **证据**：手动 `ip tunnel change greXXX keepalive 10 3` 报 `Error: ... "keepalive" is a garbage`
- **建议**：要么改用户态周期 ping + 联动 up/down 实现探测；要么下发失败时明确报错 / 前端禁用该选项，勿静默吞错

---

## BUG-2【Major】GRE TOS 进制不一致（前端十进制 → 内核按十六进制解释）

- **模块**：GRE 高级配置「Tos」
- **复现**：
  1. 新建 GRE，Tos 填 `16`（十进制），保存
  2. SSH：`ip -d link show gre<编号> | grep tos`
  3. 再建一条 Tos 填 `100`
- **预期**：Tos=16 → `ip -d` 显示 `tos 0x10`（=16）；Tos=100 → `tos 0x64`（=100）
- **实际**：Tos=16 → `ip -d` 显示 **`tos 0x16`（=22）**；Tos=100 → **无 tos 字段**（未下发）
- **根因**（独立 SSH 定性实锤）：iproute2 `ip tunnel change tos <N>` **把裸数字当十六进制解析**：
  - `ip tunnel change greXXX tos 16` → `tos 0x16`（rc=0）
  - `ip tunnel change greXXX tos 100` → `Error: bad TOS value`（0x100=256>255）rc=255，**被脚本 `2>&1` 吞错 → tos 不下发**
  - `ip tunnel change greXXX tos 0x10` → `tos 0x10`（正确）
  - 前端存十进制，脚本 `gre_tunnel.sh:507` `ip tunnel change tos "$tos"` 传十进制裸值 → 内核按 hex 解释
- **建议**：脚本传 `0x` 前缀（如 `printf '0x%x' "$tos"`）或显式 dec→hex 转换后再下发

---

## BUG-3【Major】GRE「封装后报文不允许分片」(no_fragment) 文案与行为反转

- **模块**：GRE 高级配置「封装后报文不允许分片」开关
- **复现**：
  1. 新建 GRE，开启「封装后报文不允许分片」（no_fragment=1，ttl 需填 0），保存
  2. SSH：`ip -d link show gre<编号>`
- **预期**：开启"不允许分片"= 外层报文置 DF 位 / 启用 PMTU 发现（nopmtudisc **不应**出现）
- **实际**：`ip -d` 含 **`nopmtudisc`**（禁用 PMTU 发现 = **允许分片**），与"不允许分片"语义**相反**
- **根因**：脚本 `gre_tunnel.sh:480/500` `[ "$no_fragment" = "1" ] && cmd+=" nopmtudisc"` —— no_fragment=1 下发的是 `nopmtudisc`，语义反转
- **建议**：修正下发逻辑（"不允许分片"应置 DF / 不加 nopmtudisc），或修正 UI 文案与实际行为一致

---

## BUG-4【Minor】GRE gre_key 范围少校验一位（上限 429496729，应为 4294967295）

- **模块**：GRE 高级配置「GRE key」
- **复现**：
  1. 新建 GRE，GRE key 填 `429496730`，保存 → 被拒
  2. GRE key 填 `429496729`，保存 → 成功
- **预期**：GRE key 为 32 位，合法范围 0 ~ 4294967295（10 位）
- **实际**：脚本校验上限 **429496729（9 位）**，合法值 `429496730` 被拒
- **根因**：脚本校验段 `'gre_key == "" or ( >= 0 and <= 429496729 )'`，少一位
- **建议**：上限改为 `4294967295`

---

## BUG-5【Minor】GRE Tos 越界值 256 被接受落库（前端/后端校验失效）

- **模块**：GRE 高级配置「Tos」
- **复现**：新建 GRE，Tos 填 `256`（>255），保存
- **预期**：Tos 范围 0~255，`256` 越界应被前端 / 后端拦截
- **实际**：`256` **被接受并落库**（DB tos=256）
- **根因**：脚本校验段 `'tos >= 0 and <= 255'` 未生效，或前端未拦即提交；与 BUG-2（TOS 进制）叠加，tos=256 入库后内核也无法下发
- **建议**：前端输入校验 + 后端 `__check_param` 双重拦截越界值

---

## BUG-6【Minor】GRE 源地址冲突错误提示开头多逗号（提示文案异常）

- **模块**：GRE 新增表单「接口 IPv4 地址」与「隧道源地址」冲突时的提示
- **复现**：新建 GRE，接口 IPv4 地址与隧道源地址填同一 IP，保存
- **预期**：弹出规范错误提示，如「GRE 隧道下发失败，请检查内核模块和地址配置」
- **实际**：提示文本为 **`,GRE隧道下发失败，请检查内核模块和地址配置`** —— **开头多一个逗号**
- **根因**：后端拼错误信息时多拼了前导逗号（疑似 join 逻辑对首元素未去分隔符）
- **建议**：修正错误信息拼接，去掉前导逗号

---

## BUG-7【Major·复核确认】GRE 停用/删除不清策略路由 rule / rt_tables / iface_band（残留累积）

- **关联**：同已记录《GRE隧道测试BUG汇总-JIRA》BUG-3，本次自动化（lifecycle 测试 `audit_gre_residual` 删前/删后对比）**再次确认**
- **实测证据**（2026-07-17）：删除 gre<编号> 后残留 `ip rule=1`、`rt_tables=1`（max_id 持续递增）、`ik_cntl iface_band` 仍绑
- **根因**：脚本 `iproute_ipt_rule_del` 只算 mark 不执行 `ip rule del` / `ik_cntl iface_band del` / 清 rt_tables
- **建议**：停用/删除时同步清 ip rule + rt_tables + iface_band（详见旧条目）

---

## BUG-8【Major·复核确认】GRE 停用后 UI 操作按钮不刷新为"启用"，无法 UI 启用

- **关联**：同已记录《GRE隧道测试BUG汇总-JIRA》BUG-4，本次自动化（lifecycle 测试）**再次确认**
- **实测证据**（2026-07-17）：UI 停用后 DB `enabled=no` 已生效，但行内操作按钮仍显示"停用"，找不到"启用"可点；测试改走脚本 `init` 验证产品启用流程
- **建议**：停用成功后列表行按钮 / 状态列自动刷新（详见旧条目）

---

## 附：本次未复现 / 表现正常项（如实记录）

| 项 | 结论 |
|---|---|
| TTL 内核下发 | ✓ 正常（ip -d `ttl 128` 与配置一致） |
| checksum / GRE key 内核下发 | ✓ 正常（ip -d `icsum ocsum` + `ikey/okey`） |
| no_fragment=1 要求 ttl=0 约束 | ✓ 正常（no_fragment=1 + ttl=64 被正确拦截） |
| 接口名重复 | ✓ 正常（友好拦截，未泄露后端原始 JSON） |
| 停用→启用接口重建（src_mode=0 + 脚本 init 路径） | ✓ 接口有重建（注：旧手工记录的"不重建"复现于 src_mode=1，本次 src_mode=0 未复现） |
| IPv6 GRE 数据面 | ✓ 正常打通 |
| IPv4 数据面 | 偶发不通（多 WAN 环境，软记录） |

## 测试方法说明（供复现）

- **配置真生效铁证 = `ip -d link show dev gre<编号>`**（IPv4 字段：`ttl` / `tos 0xNN` / `nopmtudisc` / `keepalive N M` / `ikey` / `okey` / `icsum` / `ocsum`；IPv6 ip6gre：`hoplimit` / `tclass`）
- **DB 查询**：`sqlite3 /etc/mnt/ikuai/config.db "select * from gre_tunnel" -line`
- **删除残留审计**：`ip rule show | grep gre` / `grep gre /etc/iproute2/rt_tables` / `cat /proc/ikuai/stats/ik_summary | grep gre`
- **严禁** `ip -6 tunnel show`（会卡死 SSH session），IPv6 一律用 `ip -d link show`
- **外层抓包限制**：本环境 GRE 外层 proto47 报文不可见于任何口（疑硬件 FLOWOFFLOAD / ik_core offload），故外层 tos/ttl/DF/keepalive 探测以 `ip -d` 内核参数为准，抓包仅作参考
- 测试报告：`reports/output/test_report_*.html`（BUG 以【⚠ BUG记录】黄色高亮，SSH 验证命令带 `[router]/[client]/[peer]` 标注可复制重跑）
