import ipaddress

import pytest

from tests.network.test_dhcp_server_comprehensive import (
    baseline_mismatches,
    build_dhcp_test_context,
    find_serving_rule,
)


def _rule(name, start, end, *, enabled="yes", gateway="192.168.148.1",
          netmask="255.255.255.0", interface="lan1", rule_id="1"):
    return {
        "id": rule_id,
        "enabled": enabled,
        "tagname": name,
        "interface": interface,
        "addr_pool": f"{start}-{end}",
        "gateway": gateway,
        "netmask": netmask,
        "dns1": "114.114.114.114",
        "dns2": "223.5.5.5",
        "lease": "120",
        "phy_ifnames": "all",
    }


def test_dynamic_pools_fit_device_subnet_and_avoid_baseline_pool():
    baseline = _rule("DHS_fa632e", "192.168.148.2", "192.168.148.200")

    context = build_dhcp_test_context([baseline])

    network = ipaddress.ip_network("192.168.148.0/24")
    baseline_ips = set(range(
        int(ipaddress.ip_address("192.168.148.2")),
        int(ipaddress.ip_address("192.168.148.200")) + 1,
    ))
    allocated = set()
    for rule in context.test_rules:
        start = int(ipaddress.ip_address(rule["pool_start"]))
        end = int(ipaddress.ip_address(rule["pool_end"]))
        assert ipaddress.ip_address(start) in network
        assert ipaddress.ip_address(end) in network
        assert not (set(range(start, end + 1)) & baseline_ips)
        assert not (set(range(start, end + 1)) & allocated)
        allocated.update(range(start, end + 1))

    extra_start = int(ipaddress.ip_address(context.extra_pool[0]))
    extra_end = int(ipaddress.ip_address(context.extra_pool[1]))
    assert not (set(range(extra_start, extra_end + 1)) & allocated)
    assert context.interface == "lan1"
    assert context.netmask == "255.255.255.0"


def test_dynamic_pools_reserve_existing_test_ranges_until_cleanup():
    baseline = _rule("DHS_main", "10.0.0.2", "10.0.0.100",
                     gateway="10.0.0.1")
    stale = _rule("DHTEST_old", "10.0.0.220", "10.0.0.254",
                  gateway="10.0.0.1", rule_id="2")

    context = build_dhcp_test_context([baseline, stale])

    for rule in context.test_rules:
        assert int(ipaddress.ip_address(rule["pool_end"])) < int(
            ipaddress.ip_address("10.0.0.220")
        )
    assert [rule["tagname"] for rule in context.baseline_rules] == ["DHS_main"]


def test_dynamic_pool_generation_rejects_too_small_environment():
    baseline = _rule(
        "DHS_small", "192.0.2.2", "192.0.2.5",
        gateway="192.0.2.1", netmask="255.255.255.248",
    )

    with pytest.raises(ValueError, match="至少有14个可用地址"):
        build_dhcp_test_context([baseline])


def test_baseline_comparison_ignores_database_id_but_detects_field_changes():
    expected = _rule("DHS_main", "192.168.148.2", "192.168.148.200")
    reimported = dict(expected, id="99")
    assert baseline_mismatches([expected], [reimported]) == []

    changed = dict(reimported, netmask="255.255.252.0")
    mismatches = baseline_mismatches([expected], [changed])
    assert len(mismatches) == 1
    assert "netmask" in mismatches[0]


def test_serving_rule_prefers_exact_pool_over_same_subnet_fallback():
    first = _rule("DHS_first", "192.168.148.2", "192.168.148.100")
    second = _rule(
        "DHS_second", "192.168.148.150", "192.168.148.200", rule_id="2"
    )

    assert find_serving_rule([first, second], "192.168.148.160") is second
    assert find_serving_rule([first, second], "192.168.148.120") is first
    assert find_serving_rule([first, second], "198.51.100.10") is None
