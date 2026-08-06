# 禁止娱乐网站删除规则残留源 ipset

## 环境

- 路由器：`10.66.0.45`
- 客户端：`10.66.0.18`，业务网卡 `ens11/192.168.148.2`
- 发现用例：`test_custom_domain_group_http_https_flow`
- 复现次数：2/2

## 复现步骤

1. 在自定义网址库中把 `www.baidu.com` 加入“新闻媒体-新闻报刊”。
2. 新增禁止娱乐网站规则，选择“新闻媒体-新闻报刊”，源地址填写 `192.168.148.2`。
3. 确认 HTTP/HTTPS 均被阻断。
4. 在页面删除该禁止娱乐网站规则。
5. 检查数据库、DPI 配置和规则源地址集合。

## 预期结果

规则删除后，数据库记录、DPI 配置、`domain_blacklist_src_<id>`、
`_domain_blacklist_src_<id>` 和 MAC 集合均被回收。

## 实际结果

- 数据库记录已删除。
- `/tmp/iktmp/url_filter/05-01-domain_blacklist.txt` 中规则块已删除。
- 客户端 HTTP/HTTPS 访问已恢复。
- `domain_blacklist_src_1` 仍出现在 `ipset list -n` 中。

自动化失败信息：

```text
删除联动规则底层对象: 残留集合=['domain_blacklist_src_1']，运行态=
```

测试 teardown 已通过 `cleanup_domain_blacklist_artifacts` 回收该集合，测试设备未保留残留。

## 影响

反复增删规则会积累无引用的 ipset 对象；虽然本次流量在删除后恢复，但运行态资源与数据库不一致。
