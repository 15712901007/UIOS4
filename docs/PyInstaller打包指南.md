# PyInstaller 打包与冻结包验证指南

> 适用于当前项目的 onedir 构建。旧的 `ikuai_test_onefile.spec` 含机器绝对路径和固定浏览器版本，不再用于交付。

## 1. 推荐构建方式

在项目根目录执行：

```powershell
python -m pip install -r requirements.txt
python -m pip install pyinstaller
python -m playwright install chromium
python -m PyInstaller build\ikuai_test.spec --clean --noconfirm
```

也可以运行 `build\build.bat`。输出目录为：

```text
dist\iKuai自动化测试工具\
```

当前 `build/ikuai_test.spec` 会按已安装 Playwright 的 manifest 动态收集：

- Chromium
- Chromium headless shell
- ffmpeg
- `pytest.ini`
- `pages/`、`tests/`、`utils/`
- GUI 资源、报告模板和导入测试数据
- pytest 动态导入所需的项目模块及依赖

浏览器已随包内置，目标机不需要另装 Python 或再次执行 `playwright install`。

## 2. 冻结包精确收集烟测

本地服务和设备基础设置均提供独立的 collect-only 入口：

| 服务 | 参数 | 结果环境变量 |
|---|---|---|
| FTP | `--collect-ftp-smoke` | `IKUAI_PACKAGED_FTP_SMOKE_RESULT` |
| Samba | `--collect-samba-smoke` | `IKUAI_PACKAGED_SMOKE_RESULT` |
| HTTP | `--collect-http-smoke` | `IKUAI_PACKAGED_HTTP_SMOKE_RESULT` |
| SNMP | `--collect-snmp-smoke` | `IKUAI_PACKAGED_SNMP_SMOKE_RESULT` |
| 设备设置-基础设置 | `--collect-basic-setting-smoke` | `IKUAI_PACKAGED_BASIC_SETTING_SMOKE_RESULT` |
| 设备设置-高级管理-ALG设置 | `--collect-alg-setting-smoke` | `IKUAI_PACKAGED_ALG_SETTING_SMOKE_RESULT` |
| 设备设置-高级管理-协议控制 | `--collect-protocol-control-smoke` | `IKUAI_PACKAGED_PROTOCOL_CONTROL_SMOKE_RESULT` |
| 设备设置-高级管理-内核设置 | `--collect-kernel-setting-smoke` | `IKUAI_PACKAGED_KERNEL_SETTING_SMOKE_RESULT` |
| 网络配置-OSPF | `--collect-ospf-smoke` | `IKUAI_PACKAGED_OSPF_SMOKE_RESULT` |
| 虚拟专网-IPsec VPN | `--collect-ipsec-smoke` | `IKUAI_PACKAGED_IPSEC_SMOKE_RESULT` |

构建完成后执行：

```powershell
$bundle = (Resolve-Path 'dist\iKuai自动化测试工具').Path
$exe = Join-Path $bundle 'iKuai自动化测试工具.exe'
$out = Join-Path $bundle 'http_collect_smoke.json'

$env:IKUAI_PACKAGED_HTTP_SMOKE_RESULT = $out
try {
    $proc = Start-Process -FilePath $exe `
        -ArgumentList '--collect-http-smoke' `
        -Wait -PassThru -WindowStyle Hidden
} finally {
    Remove-Item Env:IKUAI_PACKAGED_HTTP_SMOKE_RESULT -ErrorAction SilentlyContinue
}

$result = Get-Content -LiteralPath $out -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    $proc.ExitCode -ne 0 -or
    -not $result.success -or
    $result.service -ne 'http' -or
    $result.collected -ne 1 -or
    -not $result.expected_node_found -or
    -not $result.test_file_exists -or
    $result.dependencies.'pages.advanced_service.http_server_page' -ne 'ok' -or
    $result.dependencies.'utils.backend_verifier' -ne 'ok' -or
    $result.dependencies.openpyxl -ne 'ok'
) {
    throw ($result | ConvertTo-Json -Depth 8)
}

$result | ConvertTo-Json -Depth 8
```

FTP、Samba、SNMP、基础设置、OSPF、IPsec VPN 可复用同一段脚本，只需替换参数、结果环境变量、
输出文件名、`service` 期望值和页面模块依赖名。基础设置的 `service` 为
`basic_setting`，页面模块依赖为 `pages.device_setting.basic_setting_page`；OSPF 的
`service` 为 `ospf`，页面模块依赖为 `pages.network.ospf_page`；IPsec VPN 的
`service` 为 `ipsec`，页面模块依赖为 `pages.network.ipsec_vpn_page`。

基础设置烟测成功条件包括 `exit=0`、`collected=1`、唯一 nodeid 命中，以及
`pages.device_setting.basic_setting_page`、`utils.backend_verifier`、`openpyxl`
均可导入。烟测 JSON 的 `test_target` 使用包内相对路径，pytest 输出仅保留路径
脱敏摘要，`bundle_root` 与 `runtime_root` 只记录布尔可用性。

## 3. GUI 启动烟测

冻结包 collect 通过后，还应短暂启动 GUI，确认窗口进程不会立即崩溃：

```powershell
$bundle = (Resolve-Path 'dist\iKuai自动化测试工具').Path
$exe = Join-Path $bundle 'iKuai自动化测试工具.exe'
$env:QT_QPA_PLATFORM = 'offscreen'
try {
    $proc = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 6
    $proc.Refresh()
    if ($proc.HasExited) {
        throw "GUI提前退出，exit=$($proc.ExitCode)"
    }
    Stop-Process -Id $proc.Id -Force
} finally {
    Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue
}
```

只终止本命令刚启动的 PID，不要按进程名批量结束用户正在运行的 GUI 或 pytest。

## 4. 常见问题

| 现象 | 检查项 |
|---|---|
| spec 报浏览器目录缺失 | 先执行 `python -m playwright install chromium` |
| 冻结包 collect 找不到 HTTP 测试 | 确认使用 `build/ikuai_test.spec`，并检查 smoke JSON 的 `test_file_exists` 与依赖项 |
| GUI 能开但测试无法收集 | 检查包内 `_internal/pytest.ini`、`tests/`、`pages/`、`utils/` |
| Excel 导出失败 | 确认 `openpyxl` 已通过 `requirements.txt` 安装并被 smoke 标记为 `ok` |
| 浏览器 executable 不存在 | 检查包内 `_internal/playwright/chromium-*`、`chromium_headless_shell-*`、`ffmpeg-*` |

## 5. 2026-07-15 本地服务构建实测

- PyInstaller 6.11.1、Python 3.13.5。
- `build/ikuai_test.spec` 构建成功。
- FTP、Samba、HTTP 冻结包精确 collect 均为：`exit=0`、`collected=1`、`success=true`。
- GUI 离屏启动 6 秒保持运行。
- 包内存在三个本地服务 Page Object、综合测试、报告命令生成器、`pytest.ini`
  和三类 Playwright 资源。
