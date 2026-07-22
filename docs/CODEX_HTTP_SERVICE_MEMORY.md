# Codex HTTP 服务自动化开发记忆

> 用途：插件、窗口或上下文重启后，从本文件继续“高级服务 → 本地服务 → HTTP服务”开发。
> 最后更新：2026-07-15（Asia/Shanghai）。事实以真实设备、源码和本文件后续更新为准。

## 1. 已完成目标

已为“高级服务 → 本地服务 → HTTP服务”实现 GUI 可执行的单节点综合测试，覆盖深度超过原 FTP/Samba 范本：

- 完整页面结构、添加、编辑、搜索、停用/启用、单删、批量操作。
- CSV/TXT 导入导出、异常输入、文件管理、未保存确认、右下角帮助。
- L1 数据库、L2 openresty 配置/进程/监听、L3 WAN ipset、L4 DB→运行时一致性与脚本重建。
- L5 从 `10.66.0.18` 发起真实 HTTP/HTTPS 请求，覆盖 LAN/WAN、目录浏览、虚拟主机、数据完整性和限速。
- 测试前全环境快照；finally 先独立证明 cleanup 无残留，再精确恢复测试前状态并复验。
- 接入 fixture、marker、GUI 树、settings、HTML/JSON/Excel 报告和 PyInstaller。

底层脚本：`/usr/ikuai/script/http_server.sh`。

## 2. 已确认的底层事实

脚本共 412 行，已完整只读检查。核心事实：

- API：`advanced-service/http-users`，动作 `show/add/edit/del/up/down/IMPORT/EXPORT`。
- DB：`/etc/mnt/ikuai/config.db` 表 `http_server`。
- 字段：`id, enabled, tagname, http_port, server_name, ssl_on, autoindex, download, home_dir, access`。
- 唯一约束：`tagname`；以及 `(http_port, server_name)`。
- 运行配置：`/usr/openresty/conf/static_file.conf`。
- 根目录：`/etc/disk_user` + DB `home_dir`，例如 `/etc/disk_user/666/http_<token>_h`。
- 生效方式：`http_server.sh init` 重建 `static_file.conf`，随后 `openresty -s reload`。
- HTTP/HTTPS 共用 openresty；不会为每条规则启动独立进程。
- 配置块包含 `#sql_id = <id>`、IPv4/IPv6 listen、root、try_files、charset。
- `ssl_on=1` 使用内置 `ssl/server.crt` 和 `ssl/server.key`。
- `autoindex=1` 下发目录浏览；`download>0` 下发 `limit_rate <N>k`。
- `access=0` 且规则启用时，把端口加入 `DROP_T_PORTS_WAN_IN`；`access=1` 不加入。
- 停用/删除 access=0 规则时会删除该端口 ipset 成员。
- 同端口、不同 `server_name`、相同 SSL 模式允许复用；同端口 HTTP/HTTPS 混用拒绝。
- `/`、不存在目录、包含 `..` 的目录拒绝；端口占用拒绝。
- 导入导出支持 CSV/TXT，远端暂存为 `/tmp/iktmp/{import,export}/http_server.{csv,txt}`。

2026-07-15 09:19 的只读基线：

- `http_server` 表为空。
- `static_file.conf` 存在且为 0 字节。
- openresty/nginx 主进程正常，管理端口 80/443 等由其监听。
- `DROP_T_PORTS_WAN_IN` 有其他模块的既有端口，HTTP 测试只能逐端口快照/恢复，严禁清空整个 ipset。

## 3. 已确认的真实 UI

- 列表 URL：`/#/advancedService/localService`。
- Tab：`data-node-key="http"`，位于 FTP、Samba 之后的第 3 个 Tab。
- 配置 URL：`/#/advancedService/localService/http/add`；编辑路由包含 `/advancedService/localService/http/edit`。
- 列表按钮：添加、导入、导出、帮助。
- 列：选择框、名称、文件目录、访问方式、服务端口、服务域名、目录浏览权限、外网访问、操作。
- 当前表头均无排序入口，应按“无 sorter 的真实能力”验证。
- 添加表单：
  - `#tagname`，maxlength=15，必填。
  - `#home_dir`，TreeSelect，当前磁盘根为 `666`，必填。
  - `input[name=ssl_on]`：值 `0=http`（默认）、`1=https`。
  - `#http_port`，InputNumber，1–65535；页面提示 600–800、1234–1241、12345、34567 为预留端口。
  - `#server_name`，可空。
  - `#autoindex`，选项值 1/0，文案开启/关闭，默认关闭。
  - `#download`，InputNumber，默认 0，必填。
  - `#access`，checkbox，文案开启，默认未勾选；实测保存为 DB `access=0`。
  - 文件管理、保存、取消。
- dirty 表单取消会出现：`当前内容未保存，是否确定退出？`。
- 导出弹窗：CSV/TXT + 取消/确定。
- 导入弹窗：accept `.CSV,.TXT`，唯一“清空现有配置数据”checkbox 默认关闭。
- 帮助 URL：`https://www.ikuai8.com/index.php?option=com_content&view=article&id=602&Itemid=472`。

## 4. 建议 L1–L5 场景

最终实现使用 `http_<7位小写字母数字>_`（约 36-bit 熵）、高位动态空闲端口和 `/666/<prefix>...` 目录；名称仍满足 15 字符上限。

1. 全环境/非测试行/配置文件/远端暂存/候选端口 ipset 快照，准备目录和测试文件。
2. 页面/表单/默认值/无排序能力。
3. 添加 HTTP 规则，验证 DB、server block、nginx listener、WAN ipset。
4. 添加 HTTPS 规则。
5. 搜索、清空；编辑名称/目录/端口/域名/autoindex/download/access，验证旧端口和新端口迁移。
6. 单条停启、单删、批量停启删。
7. 名称 15/16 字符边界；空字段、非法端口、预留/占用端口、负限速、非法域名、重复名称、重复 `(port,server_name)`、HTTP/HTTPS 冲突。
8. 同端口 + 不同 Host 的 HTTP 虚拟主机复用，并用不同目录文件做真实区分。
9. CSV/TXT 正向导出；安全筛选本轮行；明确 append 导入；畸形导入后 DB/运行时不变。
10. dirty form 文件管理确认、帮助 popup、无孤儿页。
11. `http_server.sh init` 重建与 L4 全一致性。
12. L5：LAN HTTP 文件 SHA256/404/autoindex；LAN HTTPS `curl -k`；WAN access=0 阻断、access=1 恢复；Host 虚拟主机；下载限速与无限速对照。
13. 最终删除；finally cleanup 独立审计；精确恢复并复验非测试数据。

## 5. 实际代码文件

新增：

- `pages/advanced_service/http_server_page.py`
- `tests/advanced_service/test_http_server_comprehensive.py`

修改：

- `utils/backend_verifier.py`
- `pages/advanced_service/__init__.py`
- `tests/conftest.py`
- `pytest.ini`
- `config/settings.yaml`
- `gui/main_window.py`
- `utils/test_results_to_excel.py`
- 必要时 `gui/test_runner.py`、`build/ikuai_test.spec`

建议命名：

- Page：`HttpServerPage`
- 测试类：`TestHttpServerComprehensive`
- 测试函数：`test_http_server_comprehensive`
- fixture：`http_server_page` / `http_server_page_logged_in`
- marker：`http_server`
- GUI node：`advanced_service/test_http_server_comprehensive.py::TestHttpServerComprehensive::test_http_server_comprehensive`

## 6. 最终实测环境

- Web/路由器：`10.66.0.150`；L5 客户端：`10.66.0.18`。
- 最终增强轮随机前缀：`http_hz43y0d_`；动态候选端口：`21455–21461`。
- 测试完成后独立 SSH 复核：`http_server` 总数 0，`static_file.conf` 0 字节。
- 7 个候选端口均无 listener/ipset 残留；测试目录、导入导出前缀文件、client 临时进程和 `.ikuai_http_test_owner` 均为 0。
- openresty 进程正常，DB→配置→监听→WAN ipset 全局一致。

## 7. 工作区保护

当前工作树包含大量 FTP/Samba 未提交改动，禁止 reset/checkout/clean；只在相关位置做增量补丁。

Samba 状态说明：历史主体版本曾 25/25 通过；后续新增共享/TXT/畸形导入深度场景后，当前最新增量在“畸形CSV被明确拒绝”反馈识别处失败，但 finally 的恢复前审计、快照恢复和恢复后审计均 PASS。HTTP 中间开发只跑 HTTP 精确 node，不要用“高级服务全选”判断 HTTP 是否通过。HTTP 完成后再单独收口 Samba 增量。

## 8. 最终完成状态（2026-07-15）

最终精确节点：

```powershell
$env:PYTHONIOENCODING='utf-8'
$env:HEADLESS='true'
python -m pytest tests\advanced_service\test_http_server_comprehensive.py::TestHttpServerComprehensive::test_http_server_comprehensive -s -q
```

结果：`1 passed in 349.03s`，JSON 为 1/1 通过、25/25 步通过、0 失败。

最终产物：

- HTML：`reports/output/test_report_20260715_130151.html`
- JSON：`reports/output/test_results.json`
- Excel：`reports/output/http_server_test_results_20260715_130151.xlsx`
- 冻结包：`dist/iKuai自动化测试工具/`
- 冻结包 smoke：`http_collect_smoke_20260715_130151.json`

关键增强验证均 PASS：

- 保存/取消位于表单外 footer；帮助页面级 popup、精确 HTTPS hostname 和 query `id=602`。
- 重命名 + HTTP→HTTPS 编辑，并用真实 TLS/SHA256 读取验证。
- 同端口 HTTP/HTTPS 混用明确拒绝。
- 双 Host 同端口分别取得不同 SHA；停用/删除其中一条时另一条仍监听且可读，最后一条删除后端口才释放。
- 合法表头但非法字段的 CSV/TXT 均有明确拒绝反馈，DB/运行时/非测试指纹不变。
- openresty 每个 server block 必须为 `listen <port>`（隐式 IPv4）和 `listen [::]:<port>`（IPv6）各一条。
- 64 KiB/s 限速、无限速控制组、WAN DROP/LAN 控制、停用拒绝、HTTP/HTTPS、404/403/autoindex 均真实打流。
- 测试目录使用 256-bit owner marker；写入前防碰撞/防 symlink，cleanup 必须复验 canonical containment 与 marker SHA。
- cleanup 后先独立证明 DB/config/目录/端口/ipset/标准 staging/client/owner marker 无残留，再精确恢复快照。
- Excel 新增“步骤明细”sheet，504 条详情、25 个步骤完整保留，无 32767 字符静默截断。
- GUI 源码树 nodeid 唯一正确；PyInstaller 构建成功；冻结包 HTTP collect 为 `exit=0, collected=1, success=true`；GUI 离屏启动 6 秒正常。

HTTP 服务任务已完成。后续若继续其他模块，不应修改或重跑 HTTP，除非相关公共基类/BackendVerifier/GUI/报告代码发生影响 HTTP 的变更。
