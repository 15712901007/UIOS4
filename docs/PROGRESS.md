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

## Phase 9: 全链路测试 [80%]

- [x] test_ip_rate_limit_full_chain.py 框架
- [x] 前端UI操作 + SSH后台验证
- [ ] iperf3实测集成（需Ubuntu客户端环境）
- [ ] MAC限速全链路测试

## Phase 10: 公共基类重构 [100%] (2026-03-06)

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

## Phase 11: 待完成 [0%]

- [ ] API层快速回归（RouterAPIClient, POST /Action/call）
- [ ] Session级登录复用（context.storage_state()）
- [ ] 测试数据外部化（YAML数据驱动）
- [ ] 失败重试机制（pytest-rerunfailures）
- [ ] CI/CD集成（GitHub Actions/Jenkins）

---

**总体进度: 约95%**

**最后更新: 2026-03-17**
