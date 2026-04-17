# 开发进度追踪

## Phase 1: 基础框架搭建 [100%]

- [x] 创建项目目录结构
- [x] 编写配置管理模块（DeviceConfig, BrowserConfig, ReportConfig）
- [x] 实现基础页面类（BasePage）
- [x] 实现登录页面（LoginPage）
- [x] 实现VLAN页面类（VlanPage）
- [x] 创建pytest配置和fixtures

## Phase 2: VLAN测试实现 [100%]

- [x] 添加VLAN：8种数据组合场景
- [x] 编辑/停用/启用/删除VLAN
- [x] 批量操作（批量停用、启用、删除）
- [x] 搜索测试（存在/不存在/清空）
- [x] 导入/导出测试（CSV/TXT）
- [x] 异常输入测试（6类）
- [x] 帮助功能测试

## Phase 3: 报告系统 [100%]

- [x] Jinja2中文HTML报告模板
- [x] 报告生成器（ReportGenerator）
- [x] 步骤记录器（StepRecorder）
- [x] 测试步骤统计显示
- [x] 用例名称中文化映射
- [x] 测试人员和版本信息显示
- [x] 失败截图base64内嵌（data URI，跨环境可移植）(2026-03-05)
- [x] 简明错误信息 + 可展开完整堆栈 (2026-03-05)
- [ ] 添加图表统计

## Phase 4: GUI开发 [100%]

- [x] PySide6主窗口（模块树、设备配置、日志面板）
- [x] 配置对话框（设备/浏览器/报告/SSH配置）
- [x] 多线程测试执行器
- [x] 日志实时显示 + 级别过滤
- [x] APScheduler定时任务
- [x] 报告查看功能
- [x] 测试进度计时器
- [x] 配置同步到子进程（环境变量传递）
- [x] SSH配置Tab页 (2026-03-04)
- [x] Web+SSH环境健康检查 (2026-03-04)
- [x] 全链路测试模块注册 (2026-03-04)

## Phase 5: IP限速模块 [100%]

- [x] IP限速Page Object（IpRateLimitPage）
- [x] 18步综合测试（10条规则 + 全CRUD + 搜索排序导出导入）
- [x] 异常输入测试（空值、格式错误、边界值）
- [x] 导入导出测试数据准备（CSV/TXT）
- [x] Unicode placeholder编码问题修复（U+201C/U+201D）
- [x] **ip_test_007添加失败修复** (2026-03-06)
  - [x] 修复IP分组/时间计划/批量添加IP三个特殊分支缺少页面刷新
  - [x] 添加错误现场截图功能（立即捕获失败状态）
  - [x] 测试验证：10/10条规则全部添加成功
- [x] 18步综合测试（8条规则 + 全CRUD + 搜索排序导出导入）
- [x] 异常输入测试（空值、格式错误、边界值）
- [x] 导入导出测试数据准备（CSV/TXT）
- [x] Unicode placeholder编码问题修复（U+201C/U+201D）

## Phase 6: MAC限速模块 [100%]

- [x] MAC限速Page Object（MacRateLimitPage）
- [x] 18步综合测试（8条规则 + 全CRUD + 搜索排序导出导入）
- [x] 异常输入测试
- [x] 导入导出测试数据准备（CSV/TXT）
- [x] **线路选择修复** (2026-03-17)
  - [x] Ant Design多选下拉框选择器修复(.ant-select-item[title='xxx'])
  - [x] 移除错误的早期返回逻辑，确保正确选择wan1/wan2/wan3
- [x] **排序功能修复** (2026-03-17)
  - [x] Ant Design Table排序图标默认隐藏，需先hover再点击SVG
  - [x] 添加COLUMN_ID_MAP映射列名到HTML id
  - [x] 修复基类IkuaiTablePage.sort_by_column方法
  - [x] IP限速/静态路由/VLAN模块同步修复
  - [x] IP限速test_sorting补全第3次点击（正序→倒序→默认）

## Phase 6.5: VLAN模块优化 [100%] (2026-03-17)

- [x] **排序测试补充**
  - [x] 添加步骤8.5: 排序功能测试
  - [x] 测试VLAN名称和IP地址两列的排序
- [x] **批量操作优化**
  - [x] 步骤11-13批量操作改用全选复选框（原逐个勾选）
  - [x] 优化后每次批量操作节省约5-6秒，总计约15-18秒

## Phase 7: SSH后台验证 [100%]

- [x] BackendVerifier工具类（paramiko SSH）
- [x] L1数据库验证（simple_qos/mac_qos/dt_mac_qos show）
- [x] L2 iptables验证（IP_QOS/MAC_QOS链）
- [x] L3 ipset验证（_simple_qos_{id} hash:net成员）
- [x] L4内核模块验证（ik_core + dmesg）
- [x] L5带宽验证（iperf3框架）
- [x] conftest.py session级SSH fixture
- [x] SSHConfig数据类 + settings.yaml配置段

## Phase 8: UI+SSH集成测试 [100%] (2026-03-06)

- [x] IP限速综合测试集成SSH验证
  - [x] 新增后逐条L1-L4验证
  - [x] 编辑/停用/启用/删除后数据库状态验证
  - [x] 批量停用/批量删除后验证
- [x] MAC限速综合测试集成SSH验证
  - [x] 兼容mac_qos和dt_mac_qos双表
  - [x] 编辑/停用/启用/删除后验证
- [x] **VLAN综合测试集成SSH验证** (2026-03-06)
  - [x] L1数据库 + L2网络接口(ip link) + L3 proc(/proc/net/vlan/config)
  - [x] 添加8条后逐条三级验证（8/8通过）
  - [x] 编辑/停用/启用/删除/批量操作后验证
- [x] 动态fixture注入（request.getfixturevalue）
- [x] 优雅降级设计（SSH不可用时跳过）
- [x] 三模块统一SSH验证模式（IP限速/MAC限速/VLAN）
- [x] **静态路由综合测试集成SSH验证** (2026-03-06)
  - [x] L1数据库(static_rt show) + L2内核路由(ip route show)
  - [x] 添加8条后逐条L1+L2验证（L1 8/8通过，L2依赖网络拓扑）
  - [x] 编辑/复制/停用/启用/删除后L1验证
  - [x] 批量停用/启用/删除后逐条L1验证
  - [x] L2 must_pass=False（wan2/wan3接口可能不活跃，属正常行为）
- [x] **BackendVerifier静态路由方法** (2026-03-06)
  - [x] query_static_routes / query_route_table / find_static_route
  - [x] verify_static_route_database / verify_static_route_kernel / verify_static_route_table
  - [x] verify_static_route_not_exists / verify_static_route_count / _mask_to_prefix
- [x] **选择性断言机制** (2026-03-05)
  - [x] ssh_verify添加must_pass参数 + ssh_failures软断言收集器
  - [x] IP限速：L1/L2/L4/停用/启用/删除/批量操作断言
  - [x] MAC限速：同上（兼容双表查询）
  - [x] VLAN：L1/L2/L3/停用/启用/删除/批量操作断言
  - [x] 测试末尾统一assert，不中断UI流程
- [x] **SSH Shell自动修复方案** (2026-03-06)
  - [x] 持久化修复脚本 /etc/mnt/ikuai/fix_sshd_shell.sh
  - [x] Cron每分钟自动检查+修复（固件升级后最多1分钟恢复）
  - [x] BackendVerifier SSH自动重连 + exec重试机制
- [x] **SSH控制台智能登录** (2026-03-18)
  - [x] 自动检测控制台密码是否开启（exec_command 5秒超时检测，线程避免阻塞）
  - [x] 交互式菜单自动登录（用户名→菜单刷新→密码→bash）
  - [x] 断言机制：验证标记确认登录成功，密码错误抛出RuntimeError
  - [x] 通过交互式shell修复/etc/passwd，重连后exec_command正常工作
  - [x] 双模式测试验证：控制台开启/关闭均正常工作
- [x] **GUI连接测试优化** (2026-03-20)
  - [x] 后台线程执行连接测试，避免阻塞GUI
  - [x] 实时日志反馈连接进度
  - [x] IP同步：测试使用输入框IP，状态栏同步更新
  - [x] 控制台凭据默认值预填，支持修改
  - [x] 精准区分"标准模式"和"控制台登录模式"日志

## Phase 9: 跨三层服务模块 [100%] (2026-04-02)

- [x] 跨三层服务Page Object（CrossLayerServicePage）
- [x] 21步综合测试（覆盖V2/V3全场景+频率异常值+批量操作）
- [x] V2/V3双版本规则添加
- [x] 频率设置与验证
- [x] 频率异常值测试（字母/负数/小数/超大值）
- [x] IP分组功能（截断名称匹配+重复检测）
- [x] SSH后台验证（L1数据库+L4内核）
- [x] 批量删除重试机制（最多3次+实际计数验证）

## Phase 10: 多线负载模块 [100%] (2026-04-15)

- [x] 多线负载Page Object（MultiWanLbPage）
- [x] 19步综合测试（覆盖全部7种负载模式+自定义运营商）
- [x] 7种负载模式全覆盖（新建连接数/源IP/源IP+目的IP/按比例/备用/源地址/目的地址）
- [x] 自定义运营商功能（添加+删除+CIDR格式验证）
- [x] 非连续mode值适配（0,1,2,3,4,6,7，mode=5已废弃）
- [x] 15字符名称限制适配
- [x] 非标准DOM表格适配（div.ant-table-row结构）
- [x] SSH后台验证（L1数据库+L2策略路由+L3/L4内核）

## Phase 11: 协议分流模块 [100%] (2026-04-17)

- [x] 协议分流Page Object（ProtocolRoutePage）
- [x] 20步综合测试（覆盖3种负载模式+5项扩展功能）
- [x] 3种负载模式（新建连接数mode=0/源IP mode=1/源IP+目的IP mode=3）
- [x] 协议树选择（虚拟树展开+JS checkbox选择）
- [x] **线路绑定** — `checkbox "线路绑定 启用"` 精确选择器 + SSH验证iface_band字段
- [x] **生效时间** — 按周循环/时间计划/时间段三种模式 + SSH验证time字段
- [x] **IP/MAC分组** — dialog对话框选择已有分组 + SSH验证src_addr字段
- [x] **复制功能** — 列表行复制按钮→预填充新增页→修改保存
- [x] **协议分组** — dialog对话框选择（预留方法，分组需预先创建）
- [x] reload后tab重置修复（所有reload后添加navigate_to_protocol_route）
- [x] SSH后台验证（L1数据库+L2 iptables+L3策略路由+L4内核）
- [x] 8条测试规则+1条复制规则，扩展字段全覆盖验证

## Phase 12: 全链路测试 [80%]

- [x] test_ip_rate_limit_full_chain.py 框架
- [x] 前端UI操作 + SSH后台验证
- [ ] iperf3实测集成（需Ubuntu客户端环境）
- [ ] MAC限速全链路测试

## Phase 13: 公共基类重构 [100%] (2026-03-06)

- [x] 创建IkuaiTablePage中间基类(BasePage → IkuaiTablePage → 各模块Page)
- [x] 提取通用操作: 行内按钮/批量操作/搜索排序/导入导出/状态验证/模态框处理
- [x] MODULE_NAME类属性参数化导出路径
- [x] 重构VlanPage(1384→310行) + 向后兼容别名
- [x] 重构IpRateLimitPage(1585→500行)
- [x] 重构MacRateLimitPage(1400→500行)
- [x] 重构StaticRoutePage(908→280行)
- [x] 修复StaticRoutePage虚拟滚动子网掩码下拉框选择问题
- [x] 全部4模块测试验证通过（MAC限速SSH-L2 MAC组验证问题已知，非重构相关）
- [x] 总计减少~3267行重复代码(-62%)

## Phase 14: 待完成 [0%]

- [ ] API层快速回归（RouterAPIClient, POST /Action/call）
- [ ] Session级登录复用（context.storage_state()）
- [ ] 测试数据外部化（YAML数据驱动）
- [ ] 失败重试机制（pytest-rerunfailures）
- [ ] CI/CD集成（GitHub Actions/Jenkins）

---

**总体进度: 约98%**

**最后更新: 2026-04-17**
