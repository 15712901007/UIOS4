# 内外网设置模块自动化测试设计文档

**日期**: 2026-06-29
**模块**: 网络配置 → 内外网设置 → 内外网设置(tab)

## 1. 背景与目标

iKuai 路由器"内外网设置"页面管理所有物理网卡到 WAN/LAN 接口的绑定与配置。
本设计实现该模块的 UI + SSH 全链路自动化测试，对齐项目其他模块（VLAN/IP限速/DMZ等）的 20+ 步综合测试 + 四级 SSH 验证标准。

## 2. 后端机制（lan.sh / wan.sh 探索结论）

### 2.1 数据库表
- **lan_config**: LAN 接口配置
  - 关键字段: `id` / `tagname`(名称) / `bandif`(绑定网卡mac列表) / `bandeth`(网卡名列表) / `ip_mask`(IP/掩码) / `lan_visit`(允许其他LAN访问,0关1开) / `bandmode`(0网桥/1汇聚) / `comment`
- **wan_config**: WAN 接口配置
  - 关键字段: `id` / `tagname` / `bandif` / `bandeth` / `internet`(接入方式:0静态/1DHCP/2PPPoE) / `ip_mask` / `gateway`(网关) / `link_time`(上线时间) / `check_link_mode`(线路检测) / `check_link_host`(检测域名) / `default_route`(默认网关) / `disc_auto_switch`(掉线自动切换) / `comment`
  - **注意**: 无 `enabled` 字段（启停机制见 2.4）

### 2.2 接口配置原理（lan.sh `__set_ipmask` / `__set_bandif`）
- `ip addr add $ip brd + dev $interface` —— 配置接口 IP
- `brctl addbr` / `br_add_eth_member` —— 创建/桥接接口与网卡
- 修改 `bandif`(绑定网卡) 时，会重建桥接关系

### 2.3 LAN 互访控制（lan.sh `__set_lan_visit`，**唯一的 iptables 联动**）
```
ipt_qos_ensure_chain: FORWARD 链注册 LAN_VISIT 链
lan_visit=0(关闭互访): iptables -A LAN_VISIT ! -i lan1 -o lan1 ... -j DROP
lan_visit=1(允许互访): iptables -D LAN_VISIT ...(删除DROP规则)
```

### 2.4 WAN 策略路由（wan.sh `iproute_ipt_rule_add`）
```
ip rule: fwmark 0x2711 lookup wan1 / 0x2712 lookup wan2 / 0x2713 lookup wan3 ...
每个 WAN 接口一个独立路由表(wanN)
```
- WAN 启停/断开: 通过详情页"断开/重拨"按钮 + 接口 IP 的存在性体现，非数据库 enabled 字段

### 2.5 写接口（统一 /Action/call）
- 查询: `func_name=wan/lan, action=show, TYPE=data,support_wisp/snapshoot/ether_info`
- 保存: `func_name=wan/lan, action=save`
- 新建线路: `func_name=wan/lan, action=line_create`
- 删除线路: `func_name=wan/lan, action=line_delete`
- 重启模拟: `func_name=lan/wan, action=boot` 或直接调脚本 `init`/`down`/`up`

## 3. Web 页面结构（Playwright 探索结论）

- **路径**: `/#/networkConfiguration/internalAndExternalNetworkSettings`
- **布局**: 表格(虚拟滚动 `div.ant-table-row`)
  - 列: 线路名称/网口/物理网卡/接入方式/IP地址/VLAN/工作模式/网卡速率/克隆MAC/链路聚合/DHCP服务/操作
  - 行操作: 选择网卡 / 配置 / 删除（lan1行额外有"新增VLAN"）
- **"配置"** → 路由跳转 `/editLanWan` 详情页（非弹窗）
  - WAN 详情页字段: 名称(input) / 接入方式(select) / 静态IP(IP+掩码+网关) / 上线时间 / 线路检测(select) / 检测域名 / 网卡速率 / 工作模式 / 复选框(默认网关/掉线自动切换/开启流控) / 按钮(断开/重拨/保存/取消)
  - LAN 详情页字段: 名称 / IP地址 / 子网掩码 / 允许其他LAN访问(开关) / 网卡速率 / 工作模式 / 保存/取消
- **"新增配置"** → 弹窗选网卡(ETH0-5)+类型(LAN扩展模式)，6网卡全分配时按钮 disabled
- **"选择网卡"** → 弹窗显示该接口已绑网卡(checkbox)，取消勾选=解绑，勾选=绑定

## 4. 环境与安全约束（关键！）

| 接口 | 网卡 | IP | 操作权限 |
|------|------|-----|---------|
| wan1 | eth5 | 10.66.0.150 | **🔴 绝对只读**（测试机访问地址） |
| lan1 | eth0(+eth1,eth2) | 192.168.148.1 | 内网，基础配置不动；eth1/eth2可解绑 |
| wan2 | eth4 | DHCP | ✅ 可编辑配置后恢复 |
| wan3 | eth3 | 静态 | ✅ 可编辑配置后恢复 |
| **lan2(新建)** | eth1 | 新建 | ✅ 新建→配置→删除 |
| **wan4(新建)** | eth2 | 新建 | ✅ 新建→配置→删除 |

**eth1/eth2 当前 link=0（未接线）**，从 lan1 解绑不影响实际网络（lan1 靠 eth0 工作），测试结束恢复绑定。

## 5. 测试用例设计（约 24 步）

### 测试流程（编辑为主 + 新建闭环 + LAN互访 + 四级SSH + 重启验证）

```
Step 1:  环境快照（SSH备份 wan2/wan3/lan1 的原始配置 + ip addr/ip rule/iptables状态）
Step 2:  导航到内外网设置页，验证 wan1/wan2/wan3/lan1 四个接口显示正确
Step 3:  【编辑 wan3】改为DHCP接入 → SSH L1(数据库internet=1)+L2(ip addr)验证 → Step4恢复
Step 4:  【恢复 wan3】改回静态IP(原值) → SSH验证恢复
Step 5:  【编辑 wan2】修改线路检测模式(HTTP→PING) → SSH L1(check_link_mode)验证
Step 6:  【编辑 wan2】修改检测域名(www.baidu.com→www.qq.com) → SSH L1验证
Step 7:  【编辑 wan2】切换默认网关开关 → SSH L1(default_route)验证
Step 8:  【恢复 wan2】所有改动恢复原值 → SSH验证
Step 9:  【编辑 wan3 异常输入】非法IP/空网关 → 验证前端拦截(保存被阻止)
Step 10: 【LAN互访-关闭】编辑lan1，关闭"允许其他LAN访问" → SSH iptables验证(LAN_VISIT有DROP规则)
Step 11: 【LAN互访-恢复】重新开启 → SSH iptables验证(LAN_VISIT无DROP规则)
Step 12: 【解绑网卡】lan1"选择网卡"取消eth1/eth2 → SSH L1验证(bandif只剩eth0)
Step 13: 【新建lan2】点"新增配置"，选eth1建lan2 → SSH L1(lan_config多1行)+L2(lan2接口存在)
Step 14: 【配置lan2】给lan2设IP(192.168.200.1/24) → SSH L1(ip_mask)+L2(ip addr含192.168.200.1)
Step 15: 【新建wan4】点"新增配置"，选eth2建wan4 → SSH L1+L2验证
Step 16: 【配置wan4】设静态IP/网关/接入方式 → SSH L1+L2验证
Step 17: 【异常】给wan4设冲突IP/非法值 → 前端拦截验证
Step 18: 【重启验证】SSH调用 lan.sh boot 模拟重启 → 验证配置持久化(lan2/wan4仍存在,ip仍在)
Step 19: 【删除lan2】→ SSH验证(lan_config少1行,lan2接口消失)
Step 20: 【删除wan4】→ SSH验证(wan_config少1行,wan4接口消失)
Step 21: 【恢复网卡绑定】lan1"选择网卡"重新勾选eth1/eth2 → SSH验证恢复
Step 22: 【全局恢复校验】SSH对比Step1快照,确认 wan2/wan3/lan1 全部恢复原状
Step 23: SSH四级总结断言(L1数据库+L2 ip addr+L3 ip rule+iptables LAN_VISIT)
Step 24: 帮助功能测试
```

### SSH 四级验证矩阵
| 层 | 验证内容 | 适用场景 |
|----|---------|---------|
| L1 数据库 | `wan_config`/`lan_config` 字段值(internet/ip_mask/gateway/check_link_mode/default_route/lan_visit/bandif) | 所有编辑操作 must_pass |
| L2 接口 | `ip addr show lanN/wanN` 含目标IP; 接口存在/消失 | IP变更/新建删除 must_pass |
| L3 路由 | `ip rule show` 含 fwmark 0x2712(wan2)/0x2713(wan3)/新wan4 | 新建/删除WAN must_pass |
| iptables | `iptables -S LAN_VISIT` DROP规则有无 | LAN互访控制 must_pass |
| 重启 | SSH调 `lan.sh boot`/`wan.sh boot` 后配置仍在 | 持久化 must_pass |

## 6. 实现清单

### 6.1 新增文件
1. `pages/network/interface_settings_page.py` —— 内外网设置 Page Object
   - 导航 / 读取接口列表 / 进入编辑页 / 修改各字段 / 保存 / 选择网卡(解绑/绑定) / 新增配置(选网卡建接口) / 删除接口 / 异常输入
2. `tests/network/test_interface_settings_comprehensive.py` —— 24步综合测试
3. `test_data/exports/interface_settings/` —— 导出测试数据目录

### 6.2 修改文件
4. `utils/backend_verifier.py` —— 新增方法:
   - `query_lan_config()` / `query_wan_config()` / `find_lan_by_name()` / `find_wan_by_name()`
   - `verify_lan_database()` / `verify_wan_database()` (L1)
   - `verify_interface_ip()` (L2 ip addr)
   - `verify_wan_policy_routing()` (L3 ip rule fwmark)
   - `verify_lan_visit_iptables()` (iptables LAN_VISIT)
   - `verify_interface_exists()` / `verify_interface_not_exists()`
   - `verify_reboot_persistence()` (模拟重启)
   - `snapshot_interface_config()` / `restore_interface_config()` (环境快照/恢复)
5. `tests/conftest.py` —— 新增 `interface_settings_page` + `interface_settings_page_logged_in` fixture + marker + TEST_NAME_MAPPING
6. `gui/main_window.py` —— 网络配置下新增"内外网设置"节点
7. `config/settings.yaml` —— 新增 interface_settings 导出导入配置
8. `pytest.ini` —— 新增 marker(如需要)
9. `docs/CHANGELOG.md` + `docs/PROGRESS.md`

## 7. 风险与安全设计

1. **wan1 绝对只读**: Page Object 的所有编辑方法对 wan1 硬拒绝(`if interface=='wan1': raise`)
2. **环境恢复**: Step1 快照所有原始值; 测试主体放 try/finally, 任何异常都执行 Step22 全局恢复
3. **lan1 谨慎**: 只解绑 eth1/eth2(link=0未接线), 不动 eth0; Step21 必恢复
4. **新建接口清理**: Step19/20 删除 lan2/wan4; 若删除失败 finally 用 SSH SQL 兜底删除
5. **SSH 验证 must_pass**: 关键点(L1/L2/L3/iptables/重启)收集到 failures 末尾统一断言, 不中断流程

## 8. 验收标准
- [ ] 24步全部执行
- [ ] SSH四级验证通过(L1+L2+L3+iptables)
- [ ] 重启验证通过(配置持久化)
- [ ] 测试结束 wan2/wan3/lan1 完全恢复原状(快照对比)
- [ ] lan2/wan4 被删除, 无残留
- [ ] GUI 模块树可勾选运行, 报告显示中文用例名
