# iKuai 4.0 虚拟专网-IPsec VPN 自动化事实记忆

更新时间：2026-07-17

## 1. 唯一真实入口

- 菜单：`虚拟专网 -> IPsec VPN`
- URL：`/#/vpn/ipsecVpn`
- 页签：`隧道策略`、`IKE提议`、`隧道信息`
- GUI 唯一 node：
  `network/test_ipsec_vpn_comprehensive.py::TestIpsecVpnComprehensive::test_ipsec_vpn_comprehensive`
- 旧的 `网络配置 -> VPN客户端 -> IPSec VPN` 通用 CRUD 模板已经移除，不得复用。

## 2. 真实 API、DB 和脚本

### API

- `ipsec2_policy`
- `ipsec2_proposal`
- `ipsec2_tunnel`
- `ipsec2_tunnel/show` 必须传 `TYPE=list,list_total`；空 TYPE 会被通用层改成 `data`，脚本不接受。
- 前端还会请求 `ipsec2_policy/show + TYPE=resolve_check`，当前后端返回
  `code=2007, unknown TYPE (resolve_check)`。

### DB

- `/etc/mnt/ikuai/config.db`
- `ipsec2_policy`
- `ipsec2_proposal`

### 生效脚本

- `/usr/ikuai/script/ipsec2_policy.sh`
- `/usr/ikuai/script/ipsec2_proposal.sh`
- `/usr/ikuai/script/ipsec2_tunnel.sh`
- `/usr/ikuai/include/ipsec2_common.sh`

旧单体 `ipsec2.sh` 的字段模型已经落后，不能作为新版自动化依据。

## 3. 实机拓扑和安全约束

- 主路由、对端、客户端及三条恢复管理通道全部从项目配置读取。
- underlay 使用两台路由器已有可达 WAN 管理地址，但该可达性不能作为 L5 结果。
- 客户端内层源固定使用已确认的 `10.99.99.1/32`。
- 对端业务地址每次从 `198.18.0.0/15` 动态选择未占用 `/32`。
- 客户端仅添加到该 `/32` 的精确路由；主路由仅添加到客户端源的精确返回路由；对端仅给 lo 添加本次 `/32`。
- PSK 只存在于 Python 内存、浏览器遮罩输入框和 SSH stdin；不得进入命令行、报告、截图、文件名或异常。
- peer 内部发起/清理命令不能进入人工复验命令；报告 target 只能是 `router` 或 `client`。

## 4. 已完成的真实 L1-L5 证明

- 双端 IKE SA：`ESTABLISHED`
- 双端 Child SA：`INSTALLED/established`
- 双端 XFRM state/policy 存在，outer endpoint 和 selector 一致。
- 客户端到对端业务 `/32`：4/4 包成功。
- 对端到客户端业务源：4/4 包成功。
- 双端 XFRM packet counter 各增长 16。
- 正常 Child SA rekey 已实测成功。
- DPD 关闭的合法 UI 策略可以保存，DB/API/UI 一致，并可完成真实数据面。
- PSK、IKE 版本、IKE proposal、ID、selector 等单变量不匹配已纳入综合用例；恢复后重新建链。

## 5. 关键产品事实

1. DPD 默认开启，但页面没有 `dpd_action` 控件，也不提交该字段；后端参数层要求该字段，保存返回 3001。
2. `add()` 不调用 `__init_main_service`。charon 未运行时，DB、缓存和配置文件仍会创建，UI/脚本仍可能返回成功。
3. `__exec_swanctl_up/down` 的 `swanctl --load-all` 输出被重定向丢弃，daemon/VICI 失败不向 UI 传播。
4. secrets 文件和包含认证字段的 cache 文件实测均为 `0644`。
5. 配置、secrets 和 cache 使用直接重定向写入，没有临时文件原子替换。
6. 新增、编辑、启停、删除缺少 DB/文件/daemon 的事务回滚。
7. 对端发起可成功，主路由发起同一对称配置返回 `NO_PROPOSAL_CHOSEN`，存在方向性协商问题。
8. UI 停用后再启用不能自动恢复双端 SA，需要测试夹具从对端显式发起。
9. IKE 版本不匹配失败后可留下单侧 IKE SA。
10. 双端 PFS 配置不一致时 rekey 仍成功，PFS 约束没有按预期生效。
11. 前端 IPsec SA 流量上限为 `42949667295`，后端上限为 `4294967295`。
12. 前端备注允许 255，后端仅允许 80。
13. 前后端 PSK 字符和长度规则不一致。
14. 页面只暴露 ESP/AH，后端还接受 `ah-esp`；该模式不能计入 UI 覆盖。

## 6. 自动化实现

- `pages/network/ipsec_vpn_page.py`
  - 新版三页签 Page Object
  - Ant Design select 真实鼠标事件、动画有界重试
  - hub/spoke 条件字段
  - 策略/提议脏表单取消
  - 新增、编辑、启停、删除及安全 API 语义
- `utils/ipsec_verifier.py`
  - 三端快照、冲突检查、动态拓扑
  - SSH stdin 安全传 PSK
  - 双端策略/提议控制
  - daemon/VICI/加载状态验证
  - 双向发起、SA、XFRM、流量、rekey
  - 同名多 SA 按唯一 IKE ID 精确撤销
  - daemon 基线恢复和精确残留审计
- `utils/ipsec_artifact_audit.py`
  - JSON/HTML/Excel 一致性
  - 六段中文证据
  - 敏感值、硬件地址、公式注入和人工命令审计

## 7. 最终执行结果

- `py_compile`：通过。
- IPsec/OSPF 报告交叉回归：`34 passed`（含冻结接线、实时 GUI 日志、
  中文可读性、人工复验命令和产物安全契约）。
- 源码 collect-only：`1 test collected`。
- 最终实机唯一 node：自动化失败 `0`、环境失败 `0`、产品失败 `10`，用例按要求为失败。
- 最终产物：
  - `reports/archive/ipsec_testcase_report_20260717_174524/ipsec_test_results_20260717_174524.json`
  - `reports/archive/ipsec_testcase_report_20260717_174524/ipsec_test_report_20260717_174524.html`
  - `reports/archive/ipsec_testcase_report_20260717_174524/ipsec_test_results_20260717_174524.xlsx`
- 产物审计：`cases=1, steps=14, commands=66`，通过；7 个失败步骤使用
  测试用例式中文摘要，失败步骤默认展开后端人工复验命令。
- finally 后独立审计：双端策略/提议为 0、无测试 SA、无基准网段残留地址/路由、六管理通道全部可用、peer daemon 恢复为测试前关闭状态。

## 8. 后续回归原则

- 不得把上述产品失败降级为 warning 或 expected-pass。
- 产品修复后，应删除夹具绕过并验证正常 UI 路径自行启动 daemon、加载配置和自动重连。
- 不得用清空 DB、flush 全部 XFRM、重启整机或重启无关服务掩盖残留。
- 每次实机运行后立即归档 JSON/HTML/Excel，并再次执行独立残留审计。

## 9. GUI 与冻结包最终收口（2026-07-17）

- `gui/test_runner.py` 已增加 `--collect-ipsec-smoke`、唯一 IPsec nodeid 和
  `run_packaged_ipsec_collect_smoke()`；公开 smoke 元数据同时脱敏本机路径与
  凭据形态文本。
- `main.py` 在导入 PySide6 和主窗口前分发冻结 IPsec collect。
- `tests/unit/test_ipsec_gui_freeze_wiring.py` 覆盖 GUI 唯一节点、TestRunner 精确
  nodeid、预 GUI 分发、冻结 collected=1，以及路径/凭据不泄露。
- IPsec 综合用例会实时输出步骤开始、说明、各验证点状态、步骤结束/耗时和
  产品/自动化/环境失败汇总；证据详情与认证数据不进入 GUI 实时日志。源码
  `TestRunner -> pytest 子进程 -> log_signal` 中文日志链路已实际烟测通过。
- 源码综合 node collect-only 仍为 `1 test collected`；通用报告桌面/移动布局、
  全部复制按钮及 GUI 回归为 `4 passed`。
- 源码 GUI 在 `QT_QPA_PLATFORM=offscreen` 下运行 6 秒未提前退出。
- 使用 PyInstaller 6.11.1 和 `build/ikuai_test.spec --clean --noconfirm`
  完整重建成功。
- 冻结包 IPsec 精确 collect：pytest exit 0、`collected=1`、
  唯一 node 命中、页面模块/后台验证/openpyxl 依赖均为 `ok`。结果归档：
  `reports/archive/ipsec_freeze_report_20260717_175336/ipsec_collect_smoke_20260717_175336.json`。
- 冻结 GUI 离屏运行 6 秒未提前退出，并仅终止本次启动 PID。
- 构建和 GUI smoke 后再次执行只读独立审计：双端策略/提议计数为 0，无测试
  命名文件、SA、XFRM、客户端精确路由、对端临时 lo 地址或主路由返回路由；
  主路由 daemon 运行、对端 daemon 停止，六条管理/恢复通道全部可用。
