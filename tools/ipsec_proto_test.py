"""IPsec 保护数据流：协议类型(any/icmp/tcp/udp) × 动作(permit/不保护) 组合测试。
铁证 = XFRM 加密计数变化（进隧道则计数+，不进则+0）+ 连通性。
"""
from __future__ import annotations
import sys, re, time, json, base64
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import logging
logging.getLogger("ikua_test").setLevel(logging.WARNING)
from utils.backend_verifier import BackendVerifier
from utils.ipsec_verifier import IpsecVerifier, IpsecTopology

b = BackendVerifier()
iv = IpsecVerifier(b)
r = iv._router(); p = iv._peer(); c = iv._client()
topo = IpsecTopology(token='t59638d', router_policy='trt59638d', peer_policy='tpt59638d',
    router_proposal='ikeRt59638d', peer_proposal='ikePt59638d',
    client_source='198.18.200.1', peer_service='198.18.200.2',
    client_iface='ens11', client_gateway='192.168.148.1',
    router_underlay='10.66.0.150', peer_underlay='10.66.0.56',
    router_interface='wan1', peer_interface='wan1')

LAN_R = "192.168.148.0/24"   # 本端内网
LAN_P = "192.168.56.0/24"    # 对端内网
PEER_LAN_GW = "192.168.56.1" # 对端内网网关（测试目标）

def xfrm_packets():
    xf = r.exec("ip -s xfrm state 2>/dev/null", timeout=10)
    return sum(int(n) for n in re.findall(r"(\d+)\(packets\)", xf))

def edit_traffic(protocol, action="permit"):
    """改保护数据流：单条 148->56，指定协议+动作，双端对称。"""
    item = {"src": LAN_R, "dst": LAN_P, "protocol": protocol,
            "action": action, "src_port": "", "dst_port": ""}
    traffic_b64 = base64.b64encode(json.dumps([item], separators=(",", ":")).encode()).decode()
    # peer 端反过来
    item_p = {"src": LAN_P, "dst": LAN_R, "protocol": protocol,
              "action": action, "src_port": "", "dst_port": ""}
    traffic_p_b64 = base64.b64encode(json.dumps([item_p], separators=(",", ":")).encode()).decode()
    # 用脚本 edit（保留其他字段）
    iv.edit_policy("router", topo, 1, _get_secret(), {"traffic": traffic_b64})
    iv.edit_policy("peer", topo, 1, _get_secret(), {"traffic": traffic_p_b64})
    iv.reload_current_credentials()
    # 重建 SA 让新 traffic 生效
    for ssh in (r, p):
        sas = ssh.exec("swanctl --list-sas 2>/dev/null", timeout=12)
        for cn in sorted(set(re.findall(r"(ipsec2-[a-z]+-\d+):", sas))):
            ssh.exec(f"swanctl --terminate --ike {cn} --timeout 10 2>&1", timeout=20)
    time.sleep(2)
    iv.initiate_child_from_peer(1)
    time.sleep(3)

def _get_secret():
    # 重新生成对称 PSK（原 secret 没存），保证两端一致
    s = iv.generate_psk()
    iv.edit_policy("peer", topo, 1, s)
    iv.edit_policy("router", topo, 1, s)
    return s

def test_proto(protocol_label, protocol, action="permit"):
    print(f"\n===== 测试: 协议={protocol_label}, 动作={action} =====")
    edit_traffic(protocol, action)
    # 确认 XFRM policy 下发
    pol = r.exec("ip xfrm policy 2>/dev/null | grep -A1 '192.168.148' | head -2", timeout=10)
    print(f"  XFRM policy: {pol.strip().replace(chr(10),' | ')}")
    # 三种协议各发一拨，看 XFRM 计数
    results = {}
    for proto_send, send_fn in [
        ("ICMP", lambda: c.exec(f"ping -c 3 -W 2 {PEER_LAN_GW} 2>&1 | tail -1", timeout=12)),
        ("TCP", lambda: c.exec(f"timeout 3 bash -c 'echo > /dev/tcp/{PEER_LAN_GW}/22' 2>&1; echo done", timeout=8)),
        ("UDP", lambda: c.exec(f"echo test | timeout 2 nc -u -w1 {PEER_LAN_GW} 53 2>&1; echo done", timeout=8)),
    ]:
        b0 = xfrm_packets()
        out = send_fn()
        time.sleep(1)
        b1 = xfrm_packets()
        delta = b1 - b0
        encrypted = delta > 0
        results[proto_send] = {"encrypted": encrypted, "delta_pkts": delta, "out": out.strip()[:50]}
        tag = "进隧道加密" if encrypted else "未进隧道"
        print(f"  发{proto_send}: XFRM +{delta}包 -> {tag} | 输出: {out.strip()[:45]}")
    return results

print("===== 前置: client 路由诊断 =====")
print("client route to 192.168.56.1:", c.exec("ip route get 192.168.56.1 2>&1", timeout=8).strip())
print("client route add 56.0/24 via router LAN gw（确保经 router）:")
print(" ", c.exec("sudo -n ip route add 192.168.56.0/24 via 192.168.148.1 dev ens11 2>&1; echo rc=$?", timeout=8).strip())
print("client route now:", c.exec("ip route get 192.168.56.1 2>&1", timeout=8).strip())

# 跑测试矩阵
all_results = {}
for label, proto in [("any(任意)", "any"), ("icmp", "icmp"), ("tcp", "tcp"), ("udp", "udp")]:
    all_results[f"{label}/permit"] = test_proto(label, proto, "permit")

# 不保护动作测试（deny / 不加密）
print("\n===== 测试: 动作=不保护（deny）看是否真的不加密但放行 =====")
all_results["icmp/不保护"] = test_proto("icmp", "icmp", "deny")

print("\n===== 汇总 =====")
for k, v in all_results.items():
    print(f"  {k}: " + " ".join(f"{p}={'加密' if d['encrypted'] else '未加密'}" for p,d in v.items()))
