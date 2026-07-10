# ACL 规则测试范本规范（iKuai 4.0 UI 自动化）

> 2026-07-03 定稿。ACL 模块作为**全模块测试范本**，落地「数据驱动 + 协议全覆盖 + 优先级排序 + 5 层后端验证 + 打流功能验证」。其他模块照抄本规范。
>
> **2026-07-10 变更**：ACL 功能验证由原 `test_acl_protocol_matrix`（6 协议 parametrize）+ `test_acl_flow_drop`（端到端 curl drop 闭环）**合并为单测试** `TestAclFlowVerification::test_acl_flow_verification`——6 协议矩阵循环 + 端到端 drop 闭环合一，单协议失败软收集不连坐、末尾聚合硬断言，iperf3 不可达时矩阵 L5 软降级（curl 闭环照跑）。ACL 模块由此收敛为「1 综合(L1-L4) + 1 功能验证」双测试（对齐连接数限制节点）。下文 parametrize/数据驱动范本理念仍适用于其他模块。

## 1. 范本定位与成果

| 维度 | 旧用例 | 范本（新） |
|---|---|---|
| 协议覆盖 | tcp/udp/icmp（缺 tcp+udp/gre） | **6 协议全覆盖**（any/tcp/udp/tcp+udp/icmp/gre） |
| 优先级排序 | 只验 DB prio 字段 | **验 iptables 行号=prio 升序**（acl.sh `sort -k2,2n`） |
| 后端验证 | L1 库 + L2 残缺 + L3 ipset | **L1-L5**（含 `-p`/`-m conntrack --ctdir`/`-m ifaces`/规则顺序/打流） |
| 用例组织 | 1 个 21 步巨型函数 | **parametrize + 外部 YAML**，一场景一用例 |
| 优先级体系 | 无 | **P0/P1/P2 marker**（`-m p0` 单跑冒烟） |

**实跑结果（2026-07-03）**：6 协议矩阵 `6 passed`（268s）+ 优先级排序 `1 passed`（102s）。

## 2. 测试用例组织（数据驱动 + 优先级分级）

- **parametrize + 外部 YAML**：用例数据存 `test_data/<module>/<xxx>.yaml`，换环境/加场景只改 YAML 不改代码。
- **一个场景一个用例**：单点失败不连坐，HTML 报告能定位到具体场景（如 `test_acl_protocol_matrix[chromium-tcp]`）。
- **P0/P1/P2 优先级 marker**：
  - P0 冒烟（核心 CRUD/导入导出/批量，必跑）
  - P1 功能（全协议/全动作/优先级排序，常规回归）
  - P2 边界（异常输入/越界/极端值，可选）
- **YAML 加载器** `tests/<module>/<module>_test_data.py`：`lru_cache` 缓存，**module 级加载**（parametrize 收集期求值，fixture 此时不存在，不能放 conftest）。

```python
# tests/security/acl_test_data.py
@lru_cache(maxsize=None)
def load_acl_cases(filename: str) -> list:
    path = os.path.join(_ACL_DATA_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f).get("cases", [])

# tests/security/test_acl_protocol_matrix.py
PROTOCOL_CASES = load_acl_cases("protocol_cases.yaml")  # module级
@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[c["id"] for c in PROTOCOL_CASES])
@pytest.mark.p1
def test_acl_protocol_matrix(case, acl_page_logged_in, acl_flow_env, step_recorder, request):
    ...
```

## 3. 5 层检验逻辑（反推 acl.sh 源码的内核落地点）

| 层 | 验证点 | backend_verifier 方法 | acl.sh 对应 |
|---|---|---|---|
| L1 数据库 | 字段值（protocol/prio/ctdir/ip_type/enabled/地址JSON） | `verify_acl_database` | acl 表 |
| **L2 iptables** | `-p协议`、`-m conntrack --ctdir`、`-m ifaces --dir`、`-m set --match-set`、**规则行号顺序(prio)** | `verify_acl_protocol_iptables`/`verify_acl_ctdir_iptables`/`verify_acl_iface_iptables`/`verify_acl_priority_order` | `__format_set`/`__exec_rule_add` |
| L3 ipset | acl_src_/dst_/sport_/dport_/time_ 成员 | `verify_acl_ipset` | `__format_ipset/portset/timeset` |
| L4 内核 | ip6tables(IPv6)、dmesg、lsmod、**acl_id_rule 文件 prio 排序** | `verify_acl_priority_order`（含文件辅证） | `__exec_rule_commit` sort |
| **L5 打流** | iperf3/ping Δpkts 计数判定命中 + 连通性 | `verify_acl_flow` | 全栈 |

**关键**：L2 验字面量（`-p`/`-m`）必须用 `iptables -S`（规则规范格式），**不是** `iptables -L`（表格格式协议是独立列无 `-p` 字面量）。计数器用 `iptables -L -n -v -x`（`-x` 关闭 K/M 缩写，否则增量算不准）。iKuai 定制列序：`num pkts bytes ccnt fcnt fastid target...`，pkts=split[1]。

## 4. 打流验证方案（L5，BUG2 唯一哨兵）

**原理**：iptables `-j DROP/ACCEPT` 规则的 pkts 计数器**匹配即增，与动作无关**。

| 判定 | 条件 | 含义 |
|---|---|---|
| 命中 | Δpkts > 0 | 规则匹配了流量 |
| drop 生效 | 命中 + iperf3/ping 不连通 | 阻断成功 |
| accept 生效 | 命中 + 连通 | 放行成功 |
| **未入栈（BUG2）** | Δpkts=0 + 连通 | DB 有规则但 iptables 空（`iptables-restore` 静默失败）→ 两种 action 都 FAIL |

- **iperf3 加 `--connect-timeout 3000`**：drop 时 iperf3 卡在连接建立（-t 不计时），靠 connect-timeout 3s 自行退出，避免 exec 看门狗超时崩。
- **tcp+udp 双匹配杀手锏**：同端口分 tcp/udp 两段打流，两段 Δpkts 都 >0 才证 ik_core 多协议单规则同时匹配。
- **前置**：`acl_flow_env` fixture 探活 iperf3 server + `add_route_via_router` 确保 client(192.168.148.2) 流量经路由器 FIREWALL 链（否则绕开→规则永不命中）。

## 5. 后端机制反推（acl.sh / function/acl 源码铁证）

```
协议    : protocol != any → PROTO="-p $protocol"（tcp+udp 是 ik_core 定制多协议匹配）
端口    : tcp/udp/tcp+udp → acl_sport_$id/acl_dport_$id ipset
ctdir   : 1→"-m conntrack --ctdir ORIGINAL", 2→"REPLY", 0→无
接口    : -m ifaces --ifaces <if> --dir in|out
地址    : -m set --match-set acl_src_/dst_$id（list:set 含子集 _acl_{side}_{id}）
优先级  : 规则写 /tmp/iktmp/ipt_rule_id/acl_id_rule（格式 `id prio <cmd>`）
          function/acl:574 sort -k2,2n -k1,1n 按 prio 升序 → iptables-restore 下发
          → iptables 行号 = prio 升序（prio 小=先生效）
IPv6    : ip_type=6 → acl6_id_rule + ip6tables（FIREWALL6/INPUT_ACL6 链）
时间坑  : time='' → 不下发 timeset（全天）; time='{"object":{},"custom":{}}' → 下发空 timeset（永不命中）
```

## 6. 推广要点（其他模块照抄清单）

1. **建数据驱动**：`test_data/<mod>/cases.yaml` + `tests/<mod>/<mod>_test_data.py`（lru_cache loader）。
2. **parametrize 矩阵 + P0/P1/P2 marker**：每个场景独立用例，`pytest -m p0` 单跑冒烟。
3. **后端验证 5 层**：先 `cat /usr/ikuai/script/<mod>.sh` + `/usr/ikuai/function/<mod>` 反推内核落地点，再写 verify 方法。
4. **打流验证**：复用 `run_iperf3` + `acl_flow_env` fixture 模式（探活→路由→打流→计数判定）。
5. **值映射坑**：page 层 key ≠ DB/iptables 值时（如 ACL `tcp_udp` vs `tcp+udp`），verify 用 DB 实际值，add_rule 靠 `PROTOCOL_UI.get(key, 兜底原值)` 兼容。

## 7. 范本文件清单

```
utils/backend_verifier.py     +6方法(verify_acl_flow/protocol_iptables/priority_order/ctdir_iptables/iface_iptables/_read_acl_counter)
tests/conftest.py             +acl_flow_env fixture +p0/p1/p2 marker
pytest.ini                    +p0/p1/p2 marker
test_data/acl/protocol_cases.yaml    数据外置范本
tests/security/acl_test_data.py      YAML loader
tests/security/test_acl_comprehensive.py::TestAclFlowVerification   ACL功能验证(6协议矩阵循环+端到端drop闭环, 2026-07-10合并旧test_acl_protocol_matrix+test_acl_flow_drop)
tests/security/test_acl_priority_order.py    优先级排序(P1)
tests/security/test_acl_comprehensive.py     综合CRUD(P0, 现有保留未重构)
```

## 8. 已知 TODO / 取舍

- **helper 重构**：现有 `test_acl_comprehensive`(21步, 27 PASS) 工作正常，**不重构**（风险高收益低，仅风格统一）。如需统一风格，照 `tests/network/vpn_test_helper.py` 抽 `run_acl_comprehensive_test`。
- **IPv6 用例**（`test_acl_ipv6.py`）：需 IPv6 环境 + `acl_page` 补 IPv6 字段（src6_addr/dst6_addr + set_protocol_stack），标 TODO。
- **边界用例**（`test_acl_edge_cases.py`）：空名/非法 IP/prio 越界(63+1)/ctdir/反向匹配/进·出接口，标 TODO（现有 test_acl_comprehensive 步骤18 已覆盖部分异常输入）。
- **2026-07-03 实测推翻"2 个 BUG"判断（重要修正）**：基于代码逻辑曾判断 `function/acl:570` `iptable -F` 笔误致 FIREWALL 累积 + `:582` `iptables-restore 2>&1` 静默吞致整批失败，但**端到端实测两个都没复现出用户功能故障**：
  1. BUG1 `iptable -F` 笔误：实测 edit ACL 规则 3 次（drop→accept→drop），FIREWALL 链每次正确保持 1 条（**不累积**），`iptables-restore -n` 兜底了。无影响，不必报禅道。
  2. BUG2 restore 静默吞 stderr：实测含空格 comment 的规则**仍下发**（iptables 里有规则），仅 comment 被截断（`bad rule`→`2_bad`，因 acl.sh 拼 `-m comment --comment ${id}_$comment` 未加引号，shell 分词）。**防火墙功能正常**，Web 备注从 DB 读仍完整，仅运维 `iptables -L` 看 comment 截断。
  - **唯一低优先级问题**（可报禅道，代码质量类）：acl.sh 拼 comment 未加引号，含空格备注在 iptables 里被截断。非功能 BUG。
  - **教训**：不能只看代码逻辑下 BUG 结论，必须端到端实测（看 `iptables -S FIREWALL` 完整输出）；判断规则下发不能 `grep tagname`（comment 格式是 `id_commentname` 不含 tagname，会误判 0）。
