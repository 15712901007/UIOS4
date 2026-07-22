# FTP / Samba / HTTP / SNMP 报告与人工复验命令记忆

更新时间：2026-07-15

## 本轮完成内容

- FTP、Samba、HTTP 综合测试报告统一为中文分区：
  - `【页面验证】`
  - `【后端验证·L1/L2/L3/L4/L5】`
  - `【后端数据】`（HTML 默认折叠）
- 每个步骤新增结构化 `verification_commands`，不再把自动化内部 SSH
  脚本拼成一行显示。
- HTML 命令区默认折叠；展开后每条命令独立显示目标、IP、Shell、用途、
  有效时机、交互提示、预期结果、影响和复制按钮。
- Excel 新增“步骤明细”和“复验命令”工作表；JSON、HTML、Excel 中命令
  文本逐字符一致。
- 报告 JSON schema 已升级为 `schema_version: 2`，旧 JSON 仍兼容。

## 人工复验命令硬约束

- 自动化内部命令与人工命令完全分离。
- 人工命令中不得出现 `[router]`、`[client]`、`rc=$?`、shell 变量、
  `if/for` 脚本、内部 marker、`<redacted>` 或 `*_probe` 伪命令。
- FTP/Samba 密码不进入命令、JSON、HTML、Excel；认证命令依赖 curl 或
  smbclient 的终端原生密码提示。
- L1-L4 配置核验默认只读。
- L5 上传、下载、删除和清理命令必须明确标注副作用，不能伪装为只读。
- `contains_secret=true` 时，StepRecorder 在进入 JSON 前不可逆替换正文为
  `[命令已隐藏：包含敏感信息]` 并强制禁止复制；HTML、Excel还有二次防御。
- 对应步骤完成后会执行 finally 清理，因此普通步骤命令的有效时机是
  “对应步骤完成后、测试环境清理前”；最终残留命令标为测试结束后仍有效。

## 关键实现文件

- `utils/replay_commands.py`：FTP/Samba/HTTP 高层验证器 → 人工命令。
- `utils/verify_helper.py`：隐藏本地服务内部脚本并记录人工命令。
- `utils/step_recorder.py`：结构化字段、去重、敏感命令阻断。
- `reports/templates/report_template.html`：中文卡片、折叠、复制、失败/警告配色。
- `utils/test_results_to_excel.py`：步骤明细和复验命令工作表。
- `tests/unit/test_local_service_report_commands.py`：报告链路离线回归。

## 2026-07-15 实机结果

合并总报告（3用例、75步、2通过、1失败）：

- HTML：`reports/output/local_services_test_report_20260715_151117.html`
- JSON：`reports/output/local_services_test_results_20260715_151117.json`
- Excel：`reports/output/local_services_test_results_20260715_151117.xlsx`
- `reports/output/test_results.json` 已指向这份合并真实结果，GUI可直接导出。

### FTP

- 结果：通过，22/22 步，`1 passed in 262.57s`。
- HTML：`reports/output/test_report_20260715_151117.html`
- JSON：`reports/output/ftp_server_test_results_20260715_151117.json`
- Excel：`reports/output/ftp_server_test_results_20260715_151117.xlsx`
- L1-L5、上传下载SHA、错误密码、RO拒写、WAN开关、总开关、finally恢复均通过。

### HTTP

- 结果：通过，25/25 步，`1 passed in 326.81s`。
- HTML：`reports/output/test_report_20260715_144732.html`
- JSON：`reports/output/http_server_test_results_20260715_144732.json`
- Excel：`reports/output/http_server_test_results_20260715_144732.xlsx`
- TLS、404/403、双域名、目录浏览、64KB/s限速、WAN阻断、finally恢复均通过。

### Samba

- 结果：28 步全部执行；L1-L5、正常导入、SMB2读写SHA、guest、RO拒写、
  WAN隔离、总开关和 finally 恢复全部通过。
- 最终用例因两项页面反馈问题如实失败：
  1. 畸形 CSV 被页面报告为成功。
  2. 畸形 TXT 提交后没有明确成功或失败反馈。
- 两种畸形导入后，数据库计数、RW/RO用户、全局配置、非测试用户和运行时
  均已证明未变化；这是产品/UI反馈问题，不是环境污染或恢复失败。
- HTML：`reports/output/test_report_20260715_145741.html`
- JSON：`reports/output/samba_server_test_results_20260715_145741.json`
- Excel：`reports/output/samba_server_test_results_20260715_145741.xlsx`

## 测试客户端与冻结包

- `10.66.0.18` 已安装 Ubuntu 官方 `smbclient` 4.15.13，用于报告中可直接
  复制的 Samba CLI 命令；`nc`、`curl`、`sha256sum` 均已确认存在。
- PyInstaller 最终构建成功。
- 冻结包 FTP、Samba、HTTP collect smoke 均为：
  `exit=0`、`collected=1`、`expected_node_found=true`、`success=true`。
- 冻结 GUI 在 `QT_QPA_PLATFORM=offscreen` 下启动 6 秒未退出。

## 2026-07-15 SNMP 服务实机确认

页面与能力：

- 路径为“高级服务 → 本地服务 → SNMP服务”，URL 为
  `/#/advancedService/localService`，SNMP 是第 4 个 Tab。
- 页面是单例配置表单，不是列表。实际支持服务启停、编辑保存、取消和帮助。
- 搜索、添加/删除记录、单条/批量操作、导入导出、排序、分页、页面级刷新、
  重复记录均无真实入口；DOM 与后端仅 show/save 的证据已在报告中标为“不适用”。
- 页面版本仅有 V2C、V3；V1 不适用。页面无 OID 输入，OID 由客户端选择。
- V3 实际选项：`authNoPriv` / `authPriv`，认证算法 MD5 / SHA，隐私算法
  DES / AES。

后端与运行时：

- 实机脚本：`/usr/ikuai/script/netsnmp.sh`。
- 页面请求：`func_name=netsnmp`，动作 `show/save`，`POST call`；脚本注册的
  单例接口为 `advanced-service/snmpd-config`，仅 `get=data`、`put=save`。
- DB：`/etc/mnt/ikuai/config.db` 表 `snmp_conf`，固定 `id=1` 单例；字段类型、
  默认值以及保存结果已由 L1 验证。
- 生成配置：`/var/run/snmp/snmpd.conf`；PID 文件：
  `/var/run/snmp/snmpd.pid`、`/var/run/snmp/subsnmpd.pid`。
- 运行进程为 `snmpd` 和子代理；命令行、PID、数量以及 IPv4/IPv6 UDP
  监听均已验证。
- SNMP 无独立 iptables/ipset 规则；启用端口会进入 miniupnpd 的 deny 配置，
  报告按“不适用专用防火墙 + UPnP端口排除正确”记录。
- L5 客户端是 `10.66.0.18`；LAN 使用 `ens11 → 192.168.148.1`，管理网
  使用 `enp2s0 → 10.66.0.150`。

最终综合测试：

- 精确节点共 21 步，`19 passed / 2 failed`，pytest 为
  `1 failed in 452.15s`。失败是保留真实产品缺陷后的预期红灯。
- 自动化/后端失败为 0；产品失败为 3 项：
  1. 页面允许 500 字符 community 保存，DB、生成配置、进程和双栈监听一致，
     但真实 `snmpget` 超时，生成的服务不可用。
  2. 501 字符输入被 `maxlength=500` 截为 500 后保存，真实协议仍不可用，
     与上一项是同一长度上限缺陷的第二条边界证据。
  3. 监听端口输入字符后页面显示保存成功、接口返回 HTTP 200，但 DB 未变化，
     且页面没有非法输入反馈。
- V2C L1-L5、正确 get/walk、错误 community、错误 OID、无权限来源、编辑、
  停启、旧端口释放和 `netsnmp.sh init` 重载均通过。
- V3 `authNoPriv+MD5`、`authPriv+SHA/AES`、`authPriv+MD5/DES` 的 L1-L5
  和真实 get/walk 均通过；错误认证、错误隐私口令均被拒绝。
- `10.66.0.18 → 10.66.0.150` 的真实 V3 `snmpget/snmpwalk` 通过。
- 帮助打开/内容匹配/关闭、取消弹窗两分支、UDP端口占用保护、空值/空格/
  非法地址/错误端口/超长值、口令 8/30/31 字符边界均已执行。
- 早期 V2C 正向值使用 URL-safe 标点导致页面校验失败，已确认属于自动化测试
  数据缺陷并改为纯字母数字唯一值；最终报告中不再有该级联失败。

最终产物与安全审计：

- HTML：`reports/output/snmp_server_test_report_20260715_202825.html`
- JSON：`reports/output/snmp_server_test_results_20260715_202825.json`
- Excel：`reports/output/snmp_server_test_results_20260715_202825.xlsx`
- JSON schema 为 2；21/21 步具备六段中文证据；JSON、HTML、Excel 中
  435 条复验命令数量、内容和顺序一致。
- 435 条命令的 target 均为纯 `router/client`，无 `[router]/[client]` 文本、
  内部 marker、变量脚本、base64 或秘密参数；失败 traceback 已隐藏完整源码。
- 测试进程登记的 14 个随机协议秘密经 JSON/HTML 扫描为 0 泄漏；Excel 来源于
  同一安全 JSON，结构化审计通过。
- 最终 HTML 在 1440×900 与 390×844 下无页面/卡片横向溢出；原生 clipboard
  和 `file://` fallback 两条复制路径均为 `435/435` 逐字符一致。

GUI、冻结包与恢复：

- 离线/GUI/报告回归：49 passed；SNMP 精确 collect 为 1 个节点。
- GUI 树中“高级服务 → 本地服务 → SNMP服务”nodeid 唯一；勾选、启动 wiring、
  报告打开和 Excel 导出均通过，源码 pytest 命令隔离了 Allure 配置。
- PyInstaller onedir 重建成功。冻结包 SNMP collect：`exit=0`、
  `success=true`、`collected=1`、`expected_node_found=true`，关键依赖均为 `ok`。
- 源码 GUI 与冻结 GUI 在 `QT_QPA_PLATFORM=offscreen` 下启动 6 秒均未提前退出。
- 主流程恢复、finally 兜底及独立复验均通过：4 个候选 UDP 端口无监听，
  测试前缀在 DB/配置中为 0，UDP 守卫 PID 为 0，客户端临时文件为 0，
  当前 DB→配置→进程→监听→防火墙一致且环境指纹稳定。

当前工作区仍包含用户和此前任务的大量未提交修改，禁止
`git reset`、`git checkout`、`git clean` 或回退无关文件。
