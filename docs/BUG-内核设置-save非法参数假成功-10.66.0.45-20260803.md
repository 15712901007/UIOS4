# 内核设置 save 非法参数返回假成功

## 结论

- 被测设备：`10.66.0.45`
- 模块：设备设置 -> 高级管理 -> 内核设置
- 后端：`ik_sysctl/save`、`/usr/ikuai/script/ik_sysctl.sh`
- 结果：缺少必填字段、字段越界、携带未知字段三类非法请求均返回
  `{"code":0,"message":"Success"}`，但数据库和运行态没有变化。
- 影响：调用方无法根据返回码判断保存失败，GUI 之外的 API 调用、自动化和运维平台会记录假成功。
- 建议级别：中。正常 GUI 有前端校验，但后端返回契约不可靠。

## 复现方法

先读取 `ik_sysctl/show` 的合法单例数据，再向 `/Action/call` 提交以下请求结构：

```json
{
  "func_name": "ik_sysctl",
  "action": "save",
  "param": {}
}
```

分别构造三类 `param`：

1. 从完整合法参数中删除 `icmp_timeout`。
2. 将 `udp_timeout` 设置为 `61`，其合法范围为 `5-60`。
3. 在完整合法参数中增加 `unexpected_kernel_param=1`。

## 期望结果

三类请求均应返回非零 `code` 和可定位的错误信息；数据库和运行态保持不变。

## 实际结果

| 场景 | API 返回 | 数据库 | 运行态 |
|---|---|---|---|
| 缺少 `icmp_timeout` | `code=0, Success` | 未变化 | 未变化 |
| `udp_timeout=61` | `code=0, Success` | 未变化 | 未变化 |
| 未知字段 | `code=0, Success` | 未变化 | 未变化 |

这说明后端实际执行了拒绝或无操作，但仍统一返回成功。

## 自动化证据

测试节点：

```text
tests/device_setting/test_kernel_setting_comprehensive.py::TestKernelSettingComprehensive::test_kernel_setting_comprehensive
```

完整报告：

```text
reports/output/test_report_20260803_203909.html
```

报告中的其余 L1-L5 验证均通过，包括 GUI 最小/最大边界、11 个 conntrack
运行参数、BBR/cubic、`ik_sysctl.sh init`、`ens11` 真实 TCP/UDP/ICMP 流量、
默认恢复和三端残留审计。自动化保留三项硬失败，不将假成功降级为通过。

## 清理确认

测试结束后已确认：

- `sysctl` 单例数据库恢复为测试前值。
- 11 个 `/proc/sys/net/netfilter/*` 参数和拥塞算法恢复一致。
- `10.66.0.18` 的 `ens11` 无测试专用路由残留。
- 路由器、客户端和 `10.66.0.57` 均无 `ikuai_kernel_*` 文件或进程。
