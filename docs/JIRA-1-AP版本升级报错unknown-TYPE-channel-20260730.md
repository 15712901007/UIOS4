# JIRA：AP版本升级页面报错 unknown TYPE (channel)

| 项 | 值 |
|---|---|
| 设备/固件 | IK-G2606-MXP / 4.0.303 x64 Build202607281258 |
| 设备IP | 10.66.0.45 |
| 模块 | 无线服务 → AP管理（AC智能控制模式）→ AP版本升级 |
| 提交人 | 戎士显 |
| 日期 | 2026-07-30 |

## 标题
【IK-G2606-MXP 4.0.303】AC智能控制模式 AP管理-AP版本升级 页面加载即报错 `unknown TYPE (channel)`，AP最新版本无法获取

## 问题描述
进入「无线服务 → AP管理」（页面自动切换为 AC 智能控制模式视图）后，点击「AP版本升级」标签页，页面顶部立即弹出红色错误提示 `unknown TYPE (channel)`，每次进入必现；同时 AP 列表的「最新版本」列始终为 `--`。

经抓包与后端代码确认，属**前后端接口协议不一致**：前端多发了一个后端从未实现的接口请求
```
POST /Action/call
{"func_name":"ac_upgrade","action":"show","param":{"TYPE":"channel"}}
```
后端返回
```
{"code":2007,"message":"unknown TYPE (channel)"}
```
前端将该 code:2007 当作错误用 message.error 弹窗，即为用户看到的红色提示。

后端 `/usr/ikuai/script/ac_upgrade.sh` 的 `show()` 经框架 `Show` 宏分发 TYPE，**仅注册了 4 个 TYPE：`total` / `data` / `on_upgrade` / `upgrade_status`**（对应 `__show_total/__show_data/__show_on_upgrade/__show_upgrade_status`），**没有 `channel` 分支**，故框架直接返回 `unknown TYPE (channel)`。同接口其它 TYPE 均正常：
- `TYPE=upgrade_status` → 正常返回升级状态
- `TYPE=total,data` → 正常返回 AP 列表（但 `new_version` 为空，故「最新版本」列显示 `--`）

全局搜索：`channel` 关键字仅出现在 `ac_group.sh`（且语义是无线 SSID 射频信道 channel:int 0-13 / channel_5g 0-165），与升级通道无关。

## 复现步骤
1. 浏览器登录 http://10.66.0.45（admin/admin123）
2. 左侧菜单点击「无线服务」（页面进入 AC 智能控制模式，顶部出现"AC智能控制模式 / 关闭AC"）
3. 进入「AP管理」，点击「AP版本升级」标签页
4. 观察页面顶部提示与 AP 列表

## 实际结果
- 页面顶部弹出红色错误：`unknown TYPE (channel)`（每次进入必现）
- AP 列表「最新版本」列显示 `--`（IK-X2 当前版本 1.7.5，最新版本取不到）
- 接口层：`ac_upgrade show TYPE=channel` 返回 `{"code":2007,"message":"unknown TYPE (channel)"}`
- 浏览器控制台无 JS error；AC 控制器底层日志 /tmp/log/ac.log.txt 也无此条（属上层接口层错误，非 CAPWAP 守护进程层）

## 预期结果
- 进入 AP版本升级 页面不应有任何错误提示
- 后端应正确处理 `TYPE=channel`（返回升级通道/Beta检测状态），或前端移除该多余调用
- AP 列表「最新版本」列能正确显示该 AP 型号对应的最新可用固件版本

## 根因（开发参考）
- 前端：AP版本升级 页面组件加载时调用 `ac_upgrade action=show param.TYPE=channel`（疑似为"Beta升级检测/升级通道"功能预留）
- 后端：`ac_upgrade.sh show()` 的 `Show` 宏分发 TYPE，无 `channel` 分支 → 框架返回 `unknown TYPE`
- 修复方向：① 前端去掉 `TYPE=channel` 调用；或 ② 后端 ac_upgrade 补充 `channel` 分支实现
- 数据接口均为 `POST /Action/call`，靠 body 的 func_name/action/param 区分（非 /api 路径）
