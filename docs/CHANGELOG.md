# 开发日志

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
