# 爱快 OS 4.0 虚拟专网-GRE 隧道 功能测试 BUG 汇总

## 测试环境

| 项目 | 信息 |
|---|---|
| 被测设备 | 10.66.0.150（iKuai OS V4 企业版，内核 6.12） |
| 设备 WAN | 多线负载 3 个 WAN：wan1=10.66.0.150、wan2=192.168.112.108、wan3=10.66.0.27（fwmark 选路 0x2711/0x2712/0x2713） |
| GRE 对端 | 10.66.0.56（同凭据，wan1=10.66.0.56、wan2=10.66.0.57） |
| 前端页面 | 虚拟专网 → GRE（URL: `/#/vpn/gre`） |
| 底层脚本 | `/usr/ikuai/script/gre_tunnel.sh`（789 行），DB 表 `gre_tunnel` |
| 测试方式 | Playwright UI + SSH 后端 L1-L5 全链路验证（DB→ip tunnel→iptables/ip6tables→路由表→策略 rule→双端数据面） |

> 共发现 **10 个 BUG**，按严重程度排序。BUG-1、BUG-2 为严重问题（影响设备可用性/核心功能），建议优先处理。

---

## BUG-1【严重·Blocker】GRE 操作触发 WAN 路由消失，导致设备对外完全失联

### 问题现象
在多线负载环境（多 WAN + fwmark 选路）下，对 GRE 隧道执行新增/编辑/停用/启用/删除操作后，设备的 WAN 路由会从 main 路由表消失，导致设备**对外完全无法访问**（Web/SSH/外网全断），且不影响该设备的下行业务也会因选路坍塌中断。**WAN 接口本身仍 UP（没有 down），是路由表里的 WAN 路由没了**，外观像"wan1 接口消失了"。

### 复现步骤
1. 设备配置多线负载（wan1/wan2/wan3 三个 WAN，fwmark 选路）
2. 进入 虚拟专网 → GRE，新建一条 GRE 隧道（源用任一 WAN 口，目的填对端 WAN IP），保存
3. 或对该 GRE 执行 编辑 / 停用 / 启用 / 删除 任一操作
4. 操作完成后，从外部（其它网段/外网）ping 设备 WAN IP 或访问 Web/SSH

### 实际结果
- 设备 WAN 接口仍 UP（`ip addr show wan1` 正常，IP 在），但 `ip route show`（main 表）里 WAN 的 default 路由和直连路由**消失**
- 设备对外完全失联：外部 ping 不通、Web/SSH 不可达
- 多线选路坍塌，下行业务中断
- **临时恢复方法**：进入 内外网设置 → 重新保存任一 WAN（触发重新生成路由表），路由恢复，设备重新可达

### 预期结果
GRE 隧道的增删改停用启用操作不应影响设备 main 路由表的 WAN 路由，设备应始终保持对外可达。

### 根因定位（供开发参考）
- GRE 远端在对端 WAN 网段，GRE 隧道路由**依赖 WAN 可达**（递归依赖）
- GRE 建隧道时 `iproute_ipt_rule_add` → `iproute_get_markid` 为 gre 接口分配 mark（>10000）并执行：
  - `ip rule add from all fwmark <mark> table <iface> prio 10000`
  - `ik_cntl iface_band add <iface> <mark>`
- 该 mark 与 iKuai **多线负载 fwmark 选路（0x2711/0x2712/0x2713）处于同一个 10000+ mark 空间**，且 rule 优先级同为 prio 10000
- GRE 建/删/停用时，路由依赖关系被破坏 → **GRE 递归路由（Recursive Routing）** → main 表 WAN 路由消失 → 多线选路坍塌
- 这是 Linux GRE 经典的递归路由问题（参考：https://networklessons.com/ip-routing/gre-tunnel-recursive-routing-error ）

### 规避建议
- 多 WAN 设备：管理访问口与 GRE 隧道源口分开（如管理走 LAN 或非 GRE 源 WAN），失联时通过备用口重新保存 WAN 恢复
- 单 WAN 环境：GRE 对端应为真正异地（跨网络）设备，避免同网段对端触发递归路由

---

## BUG-2【严重·Critical】GRE 隧道源用多线负载主线路（wan1）时数据面不通

### 问题现象
GRE 隧道的"隧道源地址"选择多线负载主线路 wan1 时，隧道虽能建立（接口 UP、tunnel_addr 配置成功、运行时对象齐全），但**数据面完全不通**：本端 ping 不通对端隧道地址，client 经隧道端到端不通。改用备份线路 wan3 作为源则数据面正常。

### 复现步骤
1. 设备多线负载（wan1 主线路 + wan3 备份线路）
2. 新建 GRE 隧道，传输协议 IPv4，隧道源地址选"指定 IP 地址"= wan1 的 IP（10.66.0.150），目的=对端，保存
3. 在对端对称建立 GRE 指向本端 wan1
4. 本端 `ping <对端隧道地址>`，或 client 经隧道访问对端

### 实际结果
- GRE 隧道建立成功（`ip tunnel show`/`ip addr`/NAT/路由表/策略 rule 齐全，接口 UP）
- 但本端 ping 对端隧道地址 100% 丢包，client 经隧道端到端不通
- 改用 wan3（备份线路）作为源，同样配置数据面正常打通

### 预期结果
GRE 隧道源用任一 WAN 口（主线路或备份线路）数据面均应正常打通。

### 根因定位（供开发参考）
- 多线负载主线路 wan1 的出向流量经 fwmark 选路（connmark + fwmark 0x2711）
- GRE 封装外层包（IP 协议 47）从 wan1 发出时，疑似被多线选路的 mark 机制干扰，与 GRE 自身策略路由 mark 冲突，导致封装包路由错误/丢失
- 备份线路 wan3 选路逻辑简单，不触发该冲突

---

## BUG-3【中等】GRE 隧道停用/删除不清除策略路由 rule（mark/iface_band 残留）

### 问题现象
对 GRE 隧道执行停用（down）或删除（del）后，其策略路由 rule（`ip rule`）和 iface_band 绑定不清除，长期累积导致 `ip rule show` 和 `/etc/iproute2/rt_tables` 越来越多残留条目，mark id 不断递增。

### 复现步骤
1. 新建 GRE 隧道（如 gre1），启用
2. `ip rule show` 可见 `from all fwmark <mark> lookup gre1`，`/etc/iproute2/rt_tables` 可见 `<mark> gre1`，`ik_cntl iface_band` 有 gre1 绑定
3. 停用或删除该 GRE 隧道
4. 再次 `ip rule show` / 查看 rt_tables / ik_cntl

### 实际结果
- GRE 接口、NAT、路由表项已清除
- 但 `ip rule` 里 `fwmark <mark> lookup greX` **仍残留**
- `/etc/iproute2/rt_tables` 里 `<mark> greX` 条目**仍残留**
- `ik_cntl iface_band` 的 greX 绑定**仍残留**
- 多次增删后 mark id 持续递增（10004、10005、10006...），rule/rt_tables 不断膨胀

### 预期结果
停用/删除 GRE 隧道时，应同步清除对应的 ip rule、rt_tables 条目、ik_cntl iface_band 绑定，无残留。

### 根因定位（供开发参考）
- 脚本 `iproute_ipt_rule_del` → `__iproute_ipt_rule del` 实际只调用 `iproute_get_markid` 算 mark，**没有执行 `ip rule del` / `ik_cntl iface_band del` / 清 rt_tables**（见 `/usr/ikuai/include/iproute.sh` `__iproute_ipt_rule()` 函数体）
- 正确清理应为：`ip rule del fwmark <mark> lookup <iface>` + `ik_cntl iface_band del <iface>` + 从 rt_tables 删除条目

---

## BUG-4【中等】GRE 隧道停用后 UI 操作按钮不刷新为"启用"，无法通过 UI 启用

### 问题现象
在 GRE 列表对隧道执行"停用"后，数据库 enabled 已变为 no（停用生效），但**列表行的操作按钮仍显示"停用"，未切换为"启用"**，导致用户无法通过 UI 点击"启用"来重新启用隧道。

### 复现步骤
1. 新建并启用一条 GRE 隧道（列表显示"开启"，操作按钮"停用"）
2. 点击该行"停用"按钮，确认弹窗点"确定"
3. 刷新页面（F5 / 重新进入 GRE 页面）
4. 查看该隧道行的状态列和操作按钮

### 实际结果
- 数据库 `gre_tunnel.enabled = 'no'`（停用已生效，SSH 查询确认）
- 后端运行时已拆除（接口/NAT/路由清除）
- 但 UI 列表该行**操作按钮仍为"停用"**（应为"启用"），状态列显示也可能未及时更新为"关闭"
- 用户无法通过 UI 启用该隧道（找不到"启用"按钮可点）

### 预期结果
停用生效后（enabled=no），UI 列表该行操作按钮应刷新为"启用"，状态列显示"关闭"，用户可点击"启用"重新启用。

---

## BUG-5【中等】GRE 隧道删除后 UI 列表不自动刷新，需手动刷新页面

### 问题现象
在 GRE 列表对隧道执行"删除"并确认后，**列表不立即移除被删除的项**，仍显示已删除的隧道，用户需手动刷新页面（F5）才能看到该项消失。

### 复现步骤
1. GRE 列表有一条隧道
2. 点击该行"删除"按钮，确认弹窗点"确定"
3. 删除请求完成后（不手动刷新），查看列表

### 实际结果
- 数据库已删除（SSH 查询 `gre_tunnel` 表该项不存在）
- 但 UI 列表**仍显示被删除的隧道项**，未自动移除
- 用户需手动 F5 刷新页面才看到列表更新

### 预期结果
删除确认后，UI 列表应自动刷新，立即移除被删除的项。

---

## BUG-6【中等】GRE 隧道批量新增时部分下发失败（"隧道下发失败，请检查内核模块和地址配置"）

### 问题现象
在已有 GRE 隧道的基础上，批量新增多条 GRE 隧道时，部分隧道下发失败，提示"GRE 隧道下发失败，请检查内核模块和地址配置"。逐条新增相同配置则可能成功，疑似多 GRE 并发/累积时下发不稳定。

### 复现步骤
1. 设备已有 1 条以上 GRE 隧道（如 gre1）
2. 连续新建第 2、3 条 GRE 隧道（配置均合法：tagname 不冲突、tunnel_addr 不同网段、dst 可达）
3. 观察保存结果

### 实际结果
- 部分隧道（如第 3 条）保存时报错"GRE 隧道下发失败，请检查内核模块和地址配置"
- 数据库未写入该条（回滚）
- 但其它隧道正常，配置本身无问题（逐条重试可能成功）

### 预期结果
批量新增多条合法 GRE 隧道时，每条均应成功下发，不应出现"隧道下发失败"。

### 根因定位（供开发参考）
- 疑似多 GRE 隧道并发建立时，内核 gre 模块/ik_cntl iface_band 资源竞争或时序问题
- 与 BUG-3（rule/iface_band 不清理）累积可能相关，rt_tables/iface_band 残留过多加剧下发失败

---

## BUG-7【轻微】GRE 列表搜索功能不生效（搜索后不显示结果）

### 问题现象
在 GRE 列表顶部搜索框输入接口名搜索，列表不显示匹配结果（搜索无响应/未过滤）。

### 复现步骤
1. GRE 列表有若干隧道（如 gre1、gre2）
2. 在搜索框输入"gre1"，回车
3. 查看列表

### 实际结果
- 搜索后列表未过滤显示 gre1，搜索功能无效果

### 预期结果
搜索应过滤显示匹配的隧道（输入 gre1 只显示 gre1）。

### 备注
GRE 列表为自定义虚拟表格（非标准 Ant Table），搜索适配可能需单独处理。

---

## BUG-8【轻微】GRE 列表清空搜索后不恢复全部列表

### 问题现象
执行搜索后（即便搜索无效果），清空搜索框内容，列表不恢复显示全部隧道，需刷新页面。

### 复现步骤
1. GRE 列表有隧道，搜索框输入内容
2. 清空搜索框，回车
3. 查看列表

### 实际结果
- 清空搜索后列表未恢复全部隧道

### 预期结果
清空搜索应恢复显示全部隧道。

---

## BUG-9【轻微】GRE 页面帮助按钮点击后无反应（帮助文档 popup 未打开）

### 问题现象
点击 GRE 页面右下角"帮助"按钮，无帮助文档页面弹出（popup 未打开）。

### 复现步骤
1. 进入 虚拟专网 → GRE 页面
2. 点击右下角"帮助"按钮

### 实际结果
- 帮助按钮可点击，但无帮助文档 popup 打开（超时无反应）

### 预期结果
点击帮助应打开帮助文档页面（指向 ikuai8.com 帮助链接）。

---

## BUG-10【轻微】GRE 双端数据面偶发不通（多线负载环境下不稳定）

### 问题现象
GRE 双端隧道建立后（两端对称配置），本端 ping 对端隧道地址的数据面验证偶发不通（多数情况正常打通，偶发 100% 丢包）。疑似多线负载环境下 GRE 选路不稳定。

### 复现步骤
1. 本端 + 对端对称建立 GRE 隧道（源用备份线路 wan3）
2. 本端 `ping <对端隧道地址>`
3. 多次重复建/删 GRE 后再 ping

### 实际结果
- 多数情况数据面正常打通（router ping 对端 + client 经隧道端到端均通）
- 偶发出现 ping 100% 丢包（数据面不通），重试或重建后恢复

### 预期结果
GRE 双端隧道建立后数据面应稳定打通，不应偶发不通。

### 备注
与 BUG-1（多线负载路由交互）、BUG-2（多线 mark 冲突）同源，均为 GRE 与多线负载选路交互不稳定。

---

## 附：测试覆盖情况

GRE 隧道 L1-L5 全链路自动化测试已覆盖（17 步）：
- **L1 数据库**：gre_tunnel 表 18 字段全验证
- **L2 运行时**：ip tunnel / ip addr / 自动 NAT(MASQUERADE) / 路由表 / 策略 rule / 链路状态 / mangle fwmark（源接口主 IP 时）
- **L3 连通性**：IPv4 + IPv6 双栈底层可达
- **L4 一致性**：编辑/停用/启用后运行时重建一致
- **L5 数据面**：IPv4 + IPv6 双协议双端 GRE 隧道（router ping 对端 + client 经隧道端到端）

测试报告：`reports/output/test_report_*.html`（用例显示 warning 状态，BUG 以【⚠ BUG记录】黄色高亮）
