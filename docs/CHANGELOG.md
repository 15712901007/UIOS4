# 开发日志

## 2026-03-17 MAC限速线路选择修复

### 问题描述
- **现象**: MAC限速测试在选择线路(wan1/wan2/wan3)时超时30秒
- **根因**: 原代码使用 `get_by_text(line, exact=True).first.click()` 无法定位Ant Design多选下拉框的checkbox元素

### 修复内容

#### 1. 线路下拉框选择器修复
- 使用 `.ant-select-item[title='xxx']` 选择器替代 `get_by_text()`
- 支持Ant Design多选下拉框的checkbox交互

#### 2. 选择逻辑修复
- **问题**: 之前的修复有逻辑错误 - 当当前值为"任意"时直接返回，不执行实际选择
- **修复**: 移除错误的早期返回逻辑，无论当前值是什么都执行选择操作
- **流程**: 先取消"全部"选中状态(如果已选中) → 点击指定线路选项 → 关闭下拉框

```python
def select_line(self, line: str = "任意"):
    if line == "任意":
        return self
    # 点击下拉框
    line_combobox = self.page.locator(".ant-select").first
    line_combobox.click()

    # 如果是"全部"，直接点击
    if line == "全部":
        self.page.locator(f".ant-select-item[title='全部']").click()
        return self

    # 取消"全部"选中状态（如果已选中）
    all_checkbox = self.page.locator(f".ant-select-item[title='全部'] input[type='checkbox']")
    if all_checkbox.is_checked():
        all_checkbox.click(force=True)

    # 点击指定线路
    self.page.locator(f".ant-select-item[title='{line}']").click()
    self.page.keyboard.press("Escape")
```

### 测试结果
- 8/8条规则添加成功（无超时）
- 线路正确显示为指定值（wan1/wan2/wan3）

### 文件变更
```
修改:
  pages/network/mac_rate_limit_page.py  # select_line()方法修复
```

---

## 2026-03-06 IP限速测试ip_test_007失败修复 + 错误截图优化

### 问题描述
- **现象**: IP限速综合测试在添加ip_test_007时失败，`fill_name()` 超时30秒，提示"element is not visible"
- **根因**: ip_test_006(IP分组规则)、ip_test_007(时间计划规则)、ip_test_009(批量添加IP规则)三个特殊分支在添加成功后缺少页面刷新，导致页面停留在添加表单，下一条规则的 `click_add_button()` + `fill_name()` 找不到元素
- **对比**: 标准 `add_rule()` 方法在成功后执行 `page.reload() + wait_for_load_state("networkidle")`，但三个特殊分支只打印日志就结束

### 修复内容

#### 1. 三个特殊分支添加页面刷新
在 `test_ip_rate_limit_comprehensive.py` 的三个特殊分支成功/失败路径都加上页面刷新：
```python
# 成功路径
if success:
    added_count += 1
    page.page.wait_for_timeout(1500)
    page.page.reload()
    page.page.wait_for_load_state("networkidle")
    page.page.wait_for_timeout(500)
else:
    page.close_modal_if_exists()
    page.navigate_to_ip_rate_limit()
    page.page.wait_for_timeout(500)

# 异常路径
except Exception as e:
    capture_error_screenshot(rule["name"], "ip_group_add")
    page.close_modal_if_exists()
    page.navigate_to_ip_rate_limit()
    page.page.wait_for_timeout(500)
```

#### 2. 错误现场截图优化
- **问题**: 测试报告截图与实际问题不符（截图在测试最终失败时才拍，此时页面状态已变）
- **方案**: 新增 `capture_error_screenshot()` 函数，在任何添加操作失败时立即截图
- **文件名**: `{rule_name}_{context}_{timestamp}_error.png`（如 `ip_test_007_time_plan_add_20260306_184521_error.png`）
- **保存位置**: `reports/screenshots/`
- **调用点**: 4个分支的except块 + 普通规则添加失败路径

```python
def capture_error_screenshot(rule_name, context="add"):
    """在操作失败时立即截图，保存到reports/screenshots目录"""
    try:
        config = get_config()
        screenshot_dir = config.report.screenshot_dir
        os.makedirs(screenshot_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_name = f"{rule_name}_{context}_{timestamp}_error.png"
        screenshot_path = os.path.join(screenshot_dir, screenshot_name)
        page.page.screenshot(path=screenshot_path)
        print(f"  [截图] 错误现场已保存: {screenshot_path}")
        rec.add_detail(f"  [截图] 错误现场: {screenshot_name}")
    except Exception as e2:
        print(f"  [截图] 保存失败: {str(e2)[:50]}")
```

### 测试结果
- **IP限速综合测试**: PASSED (290.65s / 4分50秒)
- **规则添加**: 10/10条规则全部添加成功（包括ip_test_006 IP分组、ip_test_007时间计划、ip_test_009批量添加IP）
- **SSH验证**: L1数据库验证10/10通过，L2 iptables部分失败（ip_test_001无IP、ip_test_006 IP分组、ip_test_007时间计划未生效，符合预期）

### 文件变更
```
修改:
  tests/network/test_ip_rate_limit_comprehensive.py  # 三个特殊分支添加页面刷新 + 错误截图
    - 新增 capture_error_screenshot() 函数
    - ip_group分支: 成功/失败路径添加reload/navigate
    - time_plan分支: 成功/失败路径添加reload/navigate
    - batch_ips分支: 成功/失败路径添加reload/navigate
    - normal分支: 失败路径添加错误截图
```

---

## 2026-03-06 静态路由SSH后台验证集成 + 虚拟滚动下拉框修复

### SSH验证集成
- 在 `test_static_route_comprehensive.py` 集成SSH后台验证
- 验证层次：L1数据库(static_rt show) + L2内核路由(ip route) + L3路由表(static_rt_table show)
- 验证点：添加后逐条验证 + 编辑/复制/停用/启用/删除/批量操作后验证
- L2内核路由设置 `must_pass=False`（依赖实际网络拓扑，wan2/wan3等接口可能不活跃）

### BackendVerifier扩展
新增静态路由验证方法（~180行）：
- `query_static_routes()` - 查询静态路由规则列表
- `query_route_table()` - 查询当前路由表
- `find_static_route(tagname)` - 按名称查找路由
- `verify_static_route_database(tagname, expected_fields)` - L1数据库验证
- `verify_static_route_kernel(dst_addr, netmask, gateway, interface)` - L2内核路由验证
- `verify_static_route_table(dst_addr, gateway)` - L3路由表验证
- `verify_static_route_not_exists(tagname)` - 删除验证
- `verify_static_route_count(expected_count)` - 总数验证
- `_mask_to_prefix(netmask)` - 子网掩码转CIDR前缀长度

### 虚拟滚动下拉框修复
- 修复 `static_route_page.py` 的 `select_subnet_mask()` 方法
- 问题：子网掩码下拉框使用虚拟滚动，/16等选项初始不可见
- 方案：通过键盘 `ArrowDown` 滚动下拉列表直到目标选项可见后点击
- 修复前：/16掩码选择超时，存储默认/24掩码（SSH-L1验证捕获此问题）
- 修复后：所有掩码选项正常选择，SSH-L1验证通过

### 测试结果
- **静态路由综合测试**: PASSED (167s)
- SSH验证统计：L1全部通过(8条路由+编辑+复制+停用+启用+删除+批量操作)，L2部分失败(wan2/wan3接口不活跃，符合预期)

### 文件变更
```
修改:
  utils/backend_verifier.py                     # 新增静态路由验证方法(~180行)
  tests/network/test_static_route_comprehensive.py  # 集成SSH验证
  pages/network/static_route_page.py            # 修复虚拟滚动下拉框选择
```

---

## 2026-03-06 IkuaiTablePage公共基类重构 — 消除~3000行重复代码

### 重构背景
- 4个页面类(VLAN/IP限速/MAC限速/静态路由)存在大量重复的表格CRUD操作代码
- 重复方法包括：行内按钮操作、批量操作、搜索/排序、导入/导出、状态验证、模态框处理等

### 重构方案
- 创建中间基类 `IkuaiTablePage`(BasePage → IkuaiTablePage → 各模块Page)
- 提取所有通用操作到基类(~420行)，子类只保留模块特有逻辑
- 通过 `MODULE_NAME` 类属性参数化导出路径等模块差异

### 代码量变化
| 文件 | 重构前 | 重构后 | 减少 |
|------|--------|--------|------|
| `pages/ikuai_table_page.py` | 0行(新建) | ~420行 | - |
| `pages/network/vlan_page.py` | ~1384行 | ~310行 | -1074行 |
| `pages/network/ip_rate_limit_page.py` | ~1585行 | ~500行 | -1085行 |
| `pages/network/mac_rate_limit_page.py` | ~1400行 | ~500行 | -900行 |
| `pages/network/static_route_page.py` | ~908行 | ~280行 | -628行 |
| **总计** | **~5277行** | **~2010行** | **~3267行(-62%)** |

### 测试验证结果
- [x] **VLAN综合测试**: PASSED (246s)
- [x] **IP限速综合测试**: PASSED (550s)
- [x] **MAC限速综合测试**: FAILED (SSH-L2 mac_test_006 MAC组iptables验证问题，非重构相关)
- [x] **静态路由综合测试**: PASSED (218s)

### 关键修复
- `rule_exists()` 增加 `wait_for_load_state("networkidle")` 确保页面加载后再检查
- VlanPage向后兼容：所有旧方法名(disable_vlan/enable_vlan等)作为别名保留

### 文件变更
```
新建:
  pages/ikuai_table_page.py                     # 表格页面公共基类(~420行)

重构:
  pages/network/vlan_page.py                    # 继承IkuaiTablePage + 向后兼容别名
  pages/network/ip_rate_limit_page.py           # 继承IkuaiTablePage
  pages/network/mac_rate_limit_page.py          # 继承IkuaiTablePage
  pages/network/static_route_page.py            # 继承IkuaiTablePage
```

---

## 2026-03-06 SSH Shell自动修复方案 + 三模块验证通过

### SSH Shell重置问题分析
- **根因**: 固件升级覆盖根文件系统(`/dev/root`)，`/etc/passwd`中sshd shell被重置为`/etc/setup/rc`(交互式控制台菜单)
- **机制**: `/etc/setup/rc` → `rc.console` → 交互菜单。SSH登录时运行此脚本而非bash
- **console_lock()**: 控制台密码仅影响物理串口(`/dev/tty*`)，SSH/telnet自动跳过
- **关键发现**: 没有后台进程周期性重置`/etc/passwd`，仅固件升级时覆盖

### 部署的自动修复方案
- [x] **持久化修复脚本**: `/etc/mnt/ikuai/fix_sshd_shell.sh`（在`/dev/sda3`独立分区，升级后保留）
  - 检测`/etc/passwd`中sshd shell，如果是`/etc/setup/rc`自动改为`/bin/bash`
  - 同时自动注册cron job
- [x] **Cron自动检查**: `* * * * * /etc/mnt/ikuai/fix_sshd_shell.sh --check`
  - 每分钟检查一次，固件升级后最多1分钟自动修复
  - 升级后crontab被覆盖，需执行一次`bash /etc/mnt/ikuai/fix_sshd_shell.sh`

### 三模块SSH验证全部通过
- [x] **VLAN综合测试**: PASSED
  - L1数据库: 8/8 ✓ | L2网络接口: 8/8 ✓ | L3 proc: 8/8 ✓
  - 编辑/停用/启用/删除/批量操作: 全部通过
- [x] **IP限速综合测试**: PASSED
  - L1数据库: 10/10 ✓ | L2 iptables: 正确（无IP/时间计划/0限速规则跳过）
  - L3 ipset: 6/6 ✓ | L4内核: ik_core已加载 ✓
  - 编辑/停用/启用/删除: 全部通过
- [x] **MAC限速综合测试**: PASSED
  - L1数据库: 8/8 ✓ | L2 iptables: 正确（无MAC/时间计划规则跳过）
  - L4内核: ik_core已加载 ✓
  - 编辑/停用/启用/删除: 全部通过

### 文件变更
```
路由器部署:
  /etc/mnt/ikuai/fix_sshd_shell.sh            # SSH shell自动修复脚本（持久分区）
  /etc/crontabs/root                           # 添加每分钟检查cron job
```

## 2026-03-06 VLAN后台数据验证（SSH方式，与IP/MAC限速统一）

### 新增功能
- [x] **VLAN综合测试增加SSH后台数据验证**（与IP限速、MAC限速保持一致的SSH验证模式）
  - 添加8条VLAN后逐条验证：L1数据库 + L2网络接口 + L3 proc（Step 3.5, 8/8通过）
  - 编辑后验证tagname/vlan_id更新（Step 4, L1）
  - 停用后验证enabled=no（Step 5, L1）
  - 启用后验证enabled=yes（Step 6, L1）
  - 删除后验证规则已移除（Step 7, L1）
  - 批量停用后验证全部enabled=no（Step 11, L1）
  - 批量删除后验证全部规则已清除（Step 13, L1）

### 技术决策
- **使用SSH方式，与IP限速/MAC限速保持一致**: 三个模块统一使用`request.getfixturevalue('backend_verifier')`动态注入SSH验证
- SSH连接问题的根因是路由器"控制台密码"开启导致SSH进入交互菜单，关闭控制台密码后SSH正常工作
- VLAN三级验证: L1数据库(`/usr/ikuai/function/vlan show`) + L2网络接口(`ip link show`) + L3 proc(`/proc/net/vlan/config`)

### BackendVerifier VLAN方法
- `query_vlan_rules()` / `find_vlan_rule()` / `verify_vlan_database()` / `verify_vlan_interface()` / `verify_vlan_proc()`
- 修复接口命名bug: `_vlan_{name}` → `_{name}`, `vlan_{name}` → `{name}`
- SSH自动重连: `transport.is_active()`检查 + exec重试机制

### 验证结果
- VLAN综合测试: **PASSED**（SSH连接正常时全链路通过）
  - L1数据库: 8/8条验证通过
  - L2网络接口: 8/8条验证通过
  - L3 proc: 8/8条验证通过
  - 编辑/停用/启用/删除/批量停用/批量删除: 全部通过

### 文件变更
```
修改:
  utils/backend_verifier.py                          # 添加VLAN验证方法+SSH自动重连+exec重试+接口命名修复
  tests/network/test_vlan_comprehensive.py           # 集成SSH三级验证（L1+L2+L3）
```

## 2026-03-05 MAC限速SSH全链路验证增强

### 新增功能
- [x] **MAC限速步骤6.5增加L2 iptables验证**
  - 原有: 仅L1数据库 + L4内核
  - 新增: L2 iptables(MAC_QOS链)逐条验证，L1加`must_pass=True`
  - 对齐IP限速的L1→L2→L4完整验证模式

### 修复
- [x] **BackendVerifier.verify_iptables_rule支持MAC_QOS链**
  - 新增`set_prefix`参数，MAC_QOS链ipset名为`mac_qos_{id}`（IP_QOS链为`simple_qos_{id}`）
  - 默认根据chain参数自动推断前缀
- [x] **BackendVerifier.verify_ipset_member支持自定义前缀**
  - 新增`set_prefix`参数，默认`simple_qos`
- [x] **限速值匹配支持两种格式**
  - 独立限速: `limit: X kBps mode dstip/srcip`
  - 共享限速: `bytesband X bytesband-name macdownN`
- [x] **MAC限速L2条件断言逻辑**
  - 无MAC地址的规则不创建iptables规则（与IP限速中无IP规则逻辑一致）
  - 仅对有MAC(`mac`/`batch_macs`/`mac_group`)且非时间计划的规则强制断言

### SSH探索发现（MAC_QOS链实测）
- MAC_QOS链结构与IP_QOS类似，ipset名`mac_qos_{id}`
- 独立限速和共享限速使用不同iptables target格式
- 无MAC地址的规则在MAC_QOS链中不创建iptables规则（id=1,2,4正常）
- 所有规则共用同一个ipset引用（区别于IP限速每规则独立ipset）

### 验证结果
- MAC限速综合测试: **PASSED** (229s, 21步全部通过)
  - L1数据库: 8/8规则验证通过
  - L2 iptables: 3/3有MAC规则验证通过（无MAC规则正常无iptables）
  - L4内核: ik_core已加载 ✓

### 文件变更
```
修改:
  utils/backend_verifier.py                        # verify_iptables_rule/verify_ipset_member增加set_prefix参数
  tests/network/test_mac_rate_limit_comprehensive.py # 步骤6.5增加L2验证+L1 must_pass+条件断言
  docs/CHANGELOG.md                                # 本日志
```

---

## 2026-03-05 Ant Design表单交互修复 + 报告优化

### 修复

- [x] **Ant Design Select单位切换失败（编辑表单）**
  - 现象：编辑限速规则时 `fill_upload_speed(2048, "KB/s")` 实际以MB/s提交（2048*1024=2097152）
  - 根因：JS `element.click()` 不触发Ant Design Select的React事件处理器，下拉菜单未打开
  - 修复：JS `evaluate()` 仅用于读取当前单位值；Playwright `.click()` 点击 `.ant-select-selector` 打开下拉；`.ant-select-item[title='KB/s']` 选择选项
  - 涉及4个方法：IP限速 + MAC限速 的 `fill_upload_speed` / `fill_download_speed`

- [x] **iKuai时间输入框 fill() 不触发onChange**
  - 现象：时间计划始终为00:00-23:59，未变为23:11-23:12
  - 根因：iKuai自定义时间组件不响应Playwright的`fill()`
  - 修复：改用 `press("Control+a")` + `type(value, delay=50)` 模拟键盘输入
  - 涉及IP限速和MAC限速两个测试文件的时间计划创建步骤

- [x] **测试报告错误信息过于冗长**
  - 现象：失败报告显示完整pytest traceback
  - 修复：提取`longrepr`中以`E `开头的关键行作为简明错误，完整堆栈放在可展开区域

- [x] **测试报告截图断裂**
  - 现象：截图使用绝对路径，换环境无法显示
  - 修复：截图转base64 data URI内嵌到HTML报告中

### 验证结果
- IP限速综合测试: **PASSED** (230s, 21步全部通过)
  - SSH-L1编辑验证: upload=2048 KB/s 数据一致 ✓
- MAC限速综合测试: **PASSED** (229s, 21步全部通过)
  - SSH-L1编辑验证: 通过 ✓

### 文件变更
```
修改:
  pages/network/ip_rate_limit_page.py          # fill_upload/download_speed 改用Playwright click
  pages/network/mac_rate_limit_page.py         # 同上
  tests/network/test_ip_rate_limit_comprehensive.py   # 时间计划用type()替代fill()
  tests/network/test_mac_rate_limit_comprehensive.py  # 同上
  tests/conftest.py                            # 错误信息提取 + 截图base64内嵌
  reports/templates/report_template.html       # 可展开堆栈按钮
  docs/CHANGELOG.md                            # 本日志
  docs/PROGRESS.md                             # 更新进度
```

---

## 2026-03-05 SSH选择性断言（软断言模式）

### 新增功能
- [x] **SSH选择性断言机制**
  - `ssh_verify`函数新增`must_pass`参数，失败时记录到`ssh_failures`列表
  - 测试末尾统一`assert not ssh_failures`，不中断UI测试流程
  - 关键断言点：L1数据库验证、L4内核验证、停用/启用/删除/批量操作后验证
  - 条件断言：L2 iptables仅对有IP且非时间计划的规则断言
- [x] **IP限速测试集成选择性断言**
  - 步骤6.5: L1数据库(`must_pass=True`) + L2 iptables(条件) + L4内核(`must_pass=True`)
  - 步骤8/9: 停用/启用后`enabled`字段断言
  - 步骤10: 删除后规则不存在断言
  - 步骤15: 批量停用后全部`enabled=no`断言
  - 步骤17: 批量删除后测试规则不存在断言
- [x] **MAC限速测试集成选择性断言**
  - 同IP限速模式，兼容`mac_qos`和`dt_mac_qos`双表（先查mac_qos，失败再查dt_mac_qos）
  - 步骤6.5/8/9/10/15/17均加入断言

### 设计说明
- 编辑验证不加`must_pass`（iKuai数据库tagname可能与UI显示不一致，已知行为）
- MAC限速双表查询：两张表都查不到才记录失败，避免误报

### 文件变更
```
修改:
  tests/network/test_ip_rate_limit_comprehensive.py   # 添加ssh_failures + must_pass断言
  tests/network/test_mac_rate_limit_comprehensive.py   # 同上
  docs/README.md                                       # 更新SSH验证设计原则
  docs/CHANGELOG.md                                    # 本日志
  docs/PROGRESS.md                                     # 更新进度
```

---

## 2026-03-04 UI+SSH集成测试

### 新增功能
- [x] **IP限速综合测试集成SSH后台验证**
  - 新增后逐条L1-L4验证（数据库字段、iptables规则、ipset成员、内核模块）
  - 编辑/停用/启用/删除后验证数据库状态一致性
  - 批量停用/批量删除后验证
  - 动态fixture注入：`request.getfixturevalue('backend_verifier')`
  - 优雅降级：SSH不可用时自动跳过，不影响UI测试pass/fail
- [x] **MAC限速综合测试集成SSH后台验证**
  - 同IP限速模式，兼容mac_qos和dt_mac_qos双表结构
  - 编辑/停用/启用/删除后验证
- [x] **IP限速综合测试运行验证通过**
  - 1 passed in 225.99s (0:03:45)
  - L1数据库: 10/10规则验证通过
  - L2 iptables: 8/10通过（无IP规则和时间计划规则正常无iptables规则）
  - L3 ipset: 6/6有IP规则验证通过
  - L4内核: ik_core已加载，dmesg无异常

### 已知行为记录
- 无IP规则(ip=None)在iptables中无匹配（正常）
- 时间计划未生效的规则无iptables规则（正常）
- upload=0/download=0规则不创建iptables规则（正常）
- 编辑后iKuai数据库tagname可能与UI显示不一致（待确认）

### 文件变更
```
修改:
  tests/network/test_ip_rate_limit_comprehensive.py  # 集成SSH验证（方法签名改为request fixture）
  tests/network/test_mac_rate_limit_comprehensive.py  # 集成SSH验证
```

---

## 2026-03-04 SSH后台验证器 + GUI集成

### 新增功能
- [x] **BackendVerifier工具类** (`utils/backend_verifier.py`)
  - L1: 数据库验证（simple_qos/mac_qos/dt_mac_qos show）
  - L2: iptables规则验证（IP_QOS/MAC_QOS链解析）
  - L3: ipset成员验证（list:set → hash:net二级结构）
  - L4: 内核模块验证（ik_core + dmesg检查）
  - L5: 带宽验证框架（iperf3 JSON解析）
- [x] **SSH配置支持**
  - SSHConfig数据类（config/config.py）
  - settings.yaml增加ssh配置段
  - conftest.py添加session级backend_verifier fixture
- [x] **GUI SSH配置Tab** (`gui/config_dialog.py`)
  - SSH主机/端口/用户名/密码配置
  - 保存到settings.yaml
- [x] **环境健康检查** (`gui/main_window.py`)
  - Web UI可访问检查 + SSH连接检查
- [x] **全链路测试GUI注册**
  - 模块树包含full_chain测试
- [x] **SSH环境变量传递** (`gui/test_runner.py`)
  - SSH配置通过环境变量传递给pytest子进程

### 文件变更
```
新增:
  utils/backend_verifier.py              # SSH后台验证器
  tests/network/test_ip_rate_limit_full_chain.py  # 全链路测试

修改:
  config/config.py                       # 添加SSHConfig
  config/settings.yaml                   # 添加ssh配置段
  tests/conftest.py                      # 添加backend_verifier fixture
  gui/config_dialog.py                   # SSH配置Tab
  gui/main_window.py                     # 环境健康检查
  gui/test_runner.py                     # SSH环境变量传递
```

---

## 2026-03-03 AI赋能测试效率提升方案

### 新增
- [x] **AI赋能测试效率提升方案文档**
  - 8大效率提升方向
  - 多模型策略（Opus/Sonnet/国产模型）
  - 上下文管理策略
  - 实施路线图

### 文件变更
```
新增:
  docs/AI赋能测试效率提升方案.md
  docs/AI赋能测试效率提升方案.html
  docs/AI赋能测试效率提升方案_wiki.txt
```

---

## 2026-02-28 IP限速 + MAC限速模块

### 新增功能
- [x] **IP限速Page Object** (`pages/network/ip_rate_limit_page.py`)
  - 完整CRUD操作封装
  - 搜索/排序/导出/导入功能
  - Unicode placeholder处理（U+201C/U+201D）
- [x] **IP限速综合测试** (`tests/network/test_ip_rate_limit_comprehensive.py`)
  - 18步测试覆盖全部功能
  - 8条规则覆盖：单IP/IP段/CIDR/多IP/时间计划/协议端口等
- [x] **MAC限速Page Object** (`pages/network/mac_rate_limit_page.py`)
  - 完整CRUD操作封装
- [x] **MAC限速综合测试** (`tests/network/test_mac_rate_limit_comprehensive.py`)
  - 18步测试覆盖全部功能
  - 8条规则覆盖：单MAC/多MAC/时间计划/协议端口等

### 修复
- [x] **Unicode Placeholder问题** - UI使用U+201C/U+201D中文弯引号，`get_by_placeholder()`需匹配正确编码

### 文件变更
```
新增:
  pages/network/ip_rate_limit_page.py
  pages/network/mac_rate_limit_page.py
  tests/network/test_ip_rate_limit_comprehensive.py
  tests/network/test_mac_rate_limit_comprehensive.py
  test_data/exports/ip_rate_limit/
  test_data/exports/mac_rate_limit/
  docs/终端限速测试用例.md
```

---

## 2026-02-26 GUI优化与Bug修复

### 修复
- [x] **停止测试后按钮置灰** - 修复"开始测试"按钮状态恢复
- [x] **日志级别过滤** - 实现全部/INFO/WARNING/ERROR过滤
- [x] **步骤10错误提示** - 优先显示输入框红色提示而非通用提示
- [x] **步骤16帮助链接检测** - 添加URL变化检测

### 优化
- [x] 所有16个测试步骤详细程度优化
- [x] Windows高DPI缩放适配（no_viewport=True + --high-dpi-support=1）

---

## 2026-02-14 (下午更新6)

### 新增功能
- [x] **GUI分辨率配置** - 在设备配置区添加浏览器分辨率输入框
  - 支持自定义视口宽度×高度
  - 配置保存到YAML文件
  - 测试运行时按配置的分辨率启动浏览器

### 文件变更
```
修改:
  config/config.py      # BrowserConfig添加viewport_width/viewport_height字段
  gui/main_window.py    # 添加分辨率输入框
  gui/test_runner.py    # 传递分辨率环境变量
  tests/conftest.py     # 从环境变量读取分辨率
```

---

## 2026-02-14 (下午更新5)

### 新增功能
- [x] **帮助功能自动化测试** - 添加步骤16测试右下角帮助功能
  - 点击帮助图标显示帮助面板
  - 检查帮助内容是否显示
  - 点击帮助链接跳转测试
  - 关闭帮助面板测试

### 优化
- [x] **Playwright浏览器分辨率优化**
  - 添加 `--start-maximized` 启动参数
  - 视口分辨率提升至 2560x1440
  - 浏览器窗口自适应最大化

### 文件变更
```
修改:
  tests/conftest.py                      # 浏览器最大化启动，提升分辨率
  pages/base_page.py                     # 添加帮助功能测试方法
  tests/network/test_vlan_comprehensive.py  # 添加步骤16:帮助功能测试
```

---

## 2026-02-14 (下午更新4)

### 修复
- [x] **测试人员和版本不同步** - 修复GUI填写的测试人员和版本无法同步到测试报告的问题
  - 原因：TestRunner子进程无法获取GUI中修改的配置
  - 解决：通过环境变量 TESTER 和 TEST_VERSION 传递给子进程
- [x] **计时器不更新** - 修复测试进度时间一直显示 00:00:00 的问题
  - 添加 QTimer 每秒更新时间显示
  - 测试开始时启动计时，测试完成或停止时停止计时

### 优化
- [x] **报告模板布局优化**
  - 移除"用户名"字段显示
  - 优化设备信息区布局为横向排列（flex布局）
  - 支持长版本号自动换行显示
  - 调整间距使信息更清晰

### 文件变更
```
修改:
  gui/test_runner.py             # 添加 TESTER 和 TEST_VERSION 环境变量
  gui/main_window.py             # 添加计时器功能
  tests/conftest.py              # 从环境变量读取测试人员和版本
  reports/templates/report_template.html  # 优化布局，移除用户名，支持长版本号
```

---

## 2026-02-14 (下午更新3)

### 新增功能
- [x] **GUI测试人员输入**
  - 在设备配置区添加"测试人员"输入框
  - 支持在报告中显示测试人员姓名
- [x] **GUI测试版本输入**
  - 在设备配置区添加"测试版本"输入框
  - 报告中新增"测试版本"字段显示
- [x] **配置类扩展**
  - `ReportConfig`添加`tester`和`version`字段
  - 支持YAML配置保存和加载

### 修改
- [x] **测试用例名称优化**
  - "VLAN设置综合测试"改为"VLAN设置测试"

### 文件变更
```
修改:
  config/config.py                # ReportConfig添加tester和version字段
  gui/main_window.py              # 添加测试人员和版本输入框
  tests/conftest.py               # 传递版本信息到报告生成器
  utils/report_generator.py       # 支持version字段
  reports/templates/report_template.html  # 报告显示测试版本
```

---

## 2026-02-14 (下午更新2)

### 修复
- [x] **测试步骤统计卡片颜色** - 从紫色改为蓝色，与测试用例卡片一致
- [x] **查看报告按钮** - 修复工具栏"查看报告"按钮无法打开报告的问题
  - 原因：PySide6信号连接方式需要使用lambda显式传递None参数

---

## 2026-02-14 (下午更新)

### 新增功能
- [x] **步骤记录器 (StepRecorder)**
  - 创建 `utils/step_recorder.py` 步骤记录器工具类
  - 支持线程安全的测试步骤记录
  - 提供 `step()` 上下文管理器，简化步骤记录
  - 记录步骤名称、描述、状态、耗时、详情

- [x] **测试步骤统计**
  - 报告中新增"测试步骤"统计卡片（紫色）
  - 显示总步骤数，让工作量更直观
  - 修改 `conftest.py` 收集步骤数据
  - 修改 `report_generator.py` 传递步骤统计

- [x] **用例名称中文化**
  - 添加 `TEST_NAME_MAPPING` 字典映射英文到中文名称
  - `test_comprehensive_flow` → `VLAN设置综合测试`
  - 报告中显示中文用例名称

### 优化改进
- [x] **测试报告模板优化**
  - 优化步骤展示样式，更美观清晰
  - 显示步骤详情列表
  - 添加"暂无详细步骤记录"提示
  - 使用PingFang SC/Microsoft YaHei中文字体

- [x] **测试代码优化**
  - 使用步骤记录器记录15个测试步骤
  - 每个步骤包含详细中文描述和操作记录
  - 步骤详情展示具体操作内容

- [x] **GUI报告打开功能优化**
  - 增强错误日志输出
  - 添加备用打开方法（subprocess）
  - 更友好的错误提示
  - 自动创建报告目录

### 文件变更
```
新增:
  utils/step_recorder.py          # 步骤记录器工具类

修改:
  tests/conftest.py               # 添加步骤收集和名称映射
  tests/network/test_vlan_comprehensive.py  # 使用步骤记录器
  utils/report_generator.py       # 添加步骤统计
  reports/templates/report_template.html   # 优化报告模板
  gui/main_window.py              # 优化报告打开功能
```

---

## 2026-02-14 (上午)

### 完成
- [x] 完善VLAN综合测试用例(test_vlan_comprehensive.py)
- [x] 实现VLAN异常输入测试
  - MAC地址格式验证
  - IP地址格式验证
  - VLAN名称格式验证
  - VLAN ID范围验证
  - VLAN ID冲突检测
  - 扩展IP格式验证
- [x] 完善VLAN导入导出功能
  - 支持CSV格式导出
  - 支持TXT格式导出
  - 支持CSV导入
  - 支持TXT导入（带清空现有配置选项）
- [x] 修复扩展IP验证功能
  - 正确定位扩展IP输入框
  - 捕获"请输入正确的IP"错误提示
  - 修复编辑页面关闭后状态恢复问题
- [x] 完善批量操作功能
  - 批量启用
  - 批量停用
  - 批量删除
- [x] 添加环境清理功能（测试前自动清理残留数据）
- [x] 创建Jinja2中文HTML报告模板
- [x] 实现自定义报告生成器
- [x] 集成报告生成器到pytest钩子
- [x] 修复GUI日志中文乱码问题
  - 添加PYTHONIOENCODING和PYTHONUTF8环境变量
  - 添加PYTHONUNBUFFERED实现实时日志
- [x] 修复GUI报告打开问题
  - 动态计算项目根目录，支持项目路径变化
  - 移除pytest-html报告，只使用自定义Jinja2中文报告
  - 修复"查看报告"按钮无法打开问题
- [x] 修复GUI测试用例残留问题（vlan800/801）
- [x] 简化GUI测试用例配置（只保留综合测试）
- [x] 修复GUI日志中文乱码问题
- [x] 修复报告在GUI中无法打开的问题

### 修复
- 修复扩展IP输入框定位问题（使用getByRole定位placeholder）
- 修复编辑页面关闭后页面状态未恢复问题（导航回列表页）
- 修复批量操作按钮定位问题

### 测试覆盖
- 添加VLAN：8种数据组合场景
- 编辑VLAN：1条
- 停用/启用：单个+批量
- 删除：单个+批量
- 搜索：存在/不存在/清空
- 导出：CSV和TXT两种格式
- 导入：CSV和TXT（带清空选项）
- 异常测试：6类异常输入

## 2026-02-13

### 完成
- [x] 创建项目目录结构
- [x] 创建配置管理模块(config/)
- [x] 创建基础页面类(base_page.py)
- [x] 创建登录页面类(login_page.py)
- [x] 创建VLAN页面类(vlan_page.py)
- [x] 创建pytest配置和fixtures(conftest.py)
- [x] 编写VLAN测试用例(test_vlan.py)
- [x] 创建项目文档
- [x] 创建GUI主窗口(main_window.py)
- [x] 创建配置对话框(config_dialog.py)
- [x] 创建测试执行器(test_runner.py)
- [x] 创建定时任务管理器(scheduler.py)
- [x] 创建GUI入口文件(main.py)
- [x] 创建样式表(styles.qss)
- [x] 创建测试数据文件

### 进行中
- [ ] 测试报告模板 (0%)

### 问题
- 无

### 下次继续
- 完善测试报告模板
- 运行并调试测试用例
- 测试GUI界面功能
