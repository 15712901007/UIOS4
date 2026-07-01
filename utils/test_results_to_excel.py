# -*- coding: utf-8 -*-
"""
真实测试结果 -> Excel 导出器

读取 conftest 在 sessionfinish dump 的 reports/output/test_results.json,
生成 8 列 Excel(复用 VLAN 更新版样式)。

内容来自真实测试执行: 每步标题+状态+SSH验证输出、用例真实 PASS/FAIL、
失败错误信息、失败截图文件路径。比手写 YAML 用例更全面、更真实。

用法:
  python utils/test_results_to_excel.py                       # 读最新 test_results.json
  python utils/test_results_to_excel.py -i xxx.json -o y.xlsx  # 指定输入输出
"""
import os
import json
import logging
import argparse

logger = logging.getLogger(__name__)

try:
    from openpyxl import Workbook
    from openpyxl.utils import get_column_letter
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    _HAS_OPENPYXL = True
except ImportError:  # pragma: no cover
    _HAS_OPENPYXL = False

# 8 列表头与列宽(与 VLAN 更新版对齐; 内联以保持本模块独立可运行)
HEADERS = ["模块", "测试项", "前提条件", "测试场景", "测试步骤", "预期结果", "测试结果", "备注"]
COL_WIDTHS = [28, 22, 55, 45, 55, 60, 12, 35]
_COL_ALIGN = {
    1: ("center", "center"), 2: ("center", "center"),
    3: ("left", "top"), 4: ("left", "top"), 5: ("left", "top"),
    6: ("left", "top"), 7: ("left", "top"), 8: ("left", "top"),
}


def _build_styles():
    thin = Side(style="thin", color="000000")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    header_fill = PatternFill("solid", fgColor="4472C4")
    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    header_align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    data_font = Font(name="Calibri", size=11, bold=False)
    data_aligns = {c: Alignment(horizontal=h, vertical=v, wrap_text=True)
                   for c, (h, v) in _COL_ALIGN.items()}
    return border, header_fill, header_font, header_align, data_font, data_aligns

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
_DEFAULT_JSON = os.path.join(_PROJECT_ROOT, "reports", "output", "test_results.json")

# module_key -> 中文名(从 original_name 推 key 后查)
_MODULE_NAMES = {
    "vlan": "VLAN设置", "nat_rule": "NAT规则", "port_map": "端口映射", "dmz_host": "DMZ主机",
    "upnp_setting": "UPnP/NAT设置", "static_route": "静态路由", "cross_layer_service": "跨三层服务",
    "multi_wan_lb": "多线负载", "protocol_route": "协议分流", "port_route": "端口分流",
    "domain_route": "域名分流", "updown_route": "上下行分离", "ip_rate_limit": "IP限速",
    "mac_rate_limit": "MAC限速", "stream_control": "智能流控", "ipv6_static": "IPv6前缀静态分配",
    "custom_protocol": "自定义协议", "advanced_custom_protocol": "高级自定义协议",
    "dhcp_server": "DHCP服务端", "dhcp_static": "DHCP静态分配", "dhcp_lease": "DHCP客户端",
    "dhcp_acl_mac": "DHCP黑白名单", "dns_accelerate": "DNS加速服务", "dns_multi_line": "多线路DNS服务",
    "igmp_proxy": "IGMP代理", "iptv": "IPTV透传", "udp_proxy": "UDPXY设置",
    "ip_group": "IP分组", "mac_group": "MAC分组", "port_group": "端口分组",
    "domain_group": "域名分组", "time_plan": "时间计划", "protocol_group": "协议分组",
}

_STATUS_CN = {"passed": "通过", "failed": "失败", "skipped": "跳过", "error": "错误"}
_STATUS_MARK = {"passed": "✓", "failed": "✗", "skipped": "○"}


def _module_key(original_name: str) -> str:
    """test_nat_rule_comprehensive[chromium] -> nat_rule"""
    base = original_name.split("[")[0]
    if base.startswith("test_"):
        base = base[5:]
    for suf in ("_comprehensive_flow", "_comprehensive", "_flow"):
        if base.endswith(suf):
            return base[: -len(suf)]
    return base


def _module_cn(original_name: str, name: str) -> str:
    key = _module_key(original_name)
    return _MODULE_NAMES.get(key, name or key or "未分类")


def _render_steps(steps) -> str:
    """测试步骤列: 每步 [✓/✗] 标题(用时) + details(SSH验证输出) + 步骤错误"""
    lines = []
    for i, st in enumerate(steps or [], 1):
        status = st.get("status", "")
        mark = _STATUS_MARK.get(status, "·")
        title = st.get("name", f"步骤{i}")
        dur = st.get("duration", "")
        head = f"{i}. [{mark}] {title}"
        if dur:
            head += f"  ({dur})"
        lines.append(head)
        for d in st.get("details", []):
            lines.append(f"      {d}")
        if st.get("error_message"):
            lines.append(f"      [步骤错误] {st['error_message']}")
    return "\n".join(lines)


def _render_result(tc) -> str:
    status = tc.get("status", "")
    text = _STATUS_CN.get(status, status)
    err = tc.get("error_message")
    if err:
        text += f"\n错误: {err}"
    return text


def _merge_module_col(ws, col: str, first_row: int, keys):
    n = len(keys)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and keys[j + 1] == keys[i] and keys[i]:
            j += 1
        if j > i:
            ws.merge_cells(f"{col}{first_row + i}:{col}{first_row + j}")
        i = j + 1


def _write_summary(ws, data, styles):
    """汇总 sheet: 统计卡片 + 用例简表"""
    border, hfill, hfont, halign, dfon, daligns = styles
    from openpyxl.styles import Font
    ws.cell(1, 1, "测试结果汇总").font = Font(bold=True, size=13)
    stats = [
        ("总计", data.get("total", 0)),
        ("通过", data.get("passed", 0)),
        ("失败", data.get("failed", 0)),
        ("跳过", data.get("skipped", 0)),
        ("总步骤", data.get("total_steps", 0)),
        ("用时", data.get("duration", "")),
        ("开始", data.get("start_time", "")),
        ("结束", data.get("end_time", "")),
    ]
    for i, (k, v) in enumerate(stats, start=3):
        ws.cell(i, 1, k).font = dfon
        ws.cell(i, 2, v).font = dfon

    # 用例简表
    headers = ["用例", "模块", "状态", "用时", "步骤数", "错误信息"]
    start = 3 + len(stats) + 1
    for ci, h in enumerate(headers, 1):
        c = ws.cell(start, ci, h)
        c.fill = hfill; c.font = hfont; c.alignment = halign; c.border = border
    for idx, tc in enumerate(data.get("test_cases", []), start=start + 1):
        vals = [
            tc.get("name", ""),
            _module_cn(tc.get("original_name", ""), tc.get("name", "")),
            _STATUS_CN.get(tc.get("status", ""), tc.get("status", "")),
            tc.get("duration", ""),
            tc.get("step_count", 0),
            tc.get("error_message") or "",
        ]
        for ci, v in enumerate(vals, 1):
            cell = ws.cell(idx, ci, v)
            cell.font = dfon
            cell.alignment = daligns[ci]
            cell.border = border
    ws.column_dimensions["A"].width = 30
    for c in "BCDEF":
        ws.column_dimensions[c].width = 18
    ws.freeze_panes = f"A{start + 1}"


def export_results_to_excel(json_path: str, output_path: str):
    """返回 (success: bool, message: str)"""
    if not _HAS_OPENPYXL:
        return False, "缺少 openpyxl 依赖, 请执行: pip install openpyxl"
    if not os.path.exists(json_path):
        return False, f"测试结果文件不存在: {json_path}\n请先运行测试(会自动生成该JSON)"
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, f"读取结果JSON失败: {e}"

    cases = data.get("test_cases", [])
    if not cases:
        return False, "结果JSON中无测试用例"

    wb = Workbook()
    wb.remove(wb.active)
    styles = _build_styles()
    border, hfill, hfont, halign, dfon, daligns = styles

    # 主表: 8 列每用例一行
    ws = wb.create_sheet("测试结果明细")
    for ci, title in enumerate(HEADERS, 1):
        c = ws.cell(1, ci, title)
        c.fill = hfill; c.font = hfont; c.alignment = halign; c.border = border
        ws.column_dimensions[get_column_letter(ci)].width = COL_WIDTHS[ci - 1]
    ws.freeze_panes = "A2"

    module_keys = []
    row = 2
    for tc in cases:
        orig = tc.get("original_name", "")
        name = tc.get("name", "")
        module_cn = _module_cn(orig, name)
        scenario = f"{name}（用时 {tc.get('duration', '')}，共 {tc.get('step_count', 0)} 步）"
        steps_text = _render_steps(tc.get("steps", []))
        result_text = _render_result(tc)
        shot = tc.get("screenshot_path", "")
        remark = f"失败截图: {shot}" if shot else ""
        values = [module_cn, name, "", scenario, steps_text, "", result_text, remark]
        for ci, val in enumerate(values, 1):
            cell = ws.cell(row, ci, val)
            cell.font = dfon
            cell.alignment = daligns[ci]
            cell.border = border
        module_keys.append(module_cn)
        row += 1
    _merge_module_col(ws, "A", 2, module_keys)

    # 汇总 sheet(放最前)
    ws_summary = wb.create_sheet("汇总", 0)
    _write_summary(ws_summary, data, styles)

    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        wb.save(output_path)
    except Exception as e:
        return False, f"保存失败: {e}"

    return True, f"已导出 {len(cases)} 条用例 → {output_path}（含汇总sheet + 明细sheet）"


def _main():
    ap = argparse.ArgumentParser(description="把真实测试结果(test_results.json)导出为 Excel")
    ap.add_argument("-i", "--input", default=_DEFAULT_JSON, help="test_results.json 路径")
    ap.add_argument("-o", "--output", default=None, help="输出 xlsx 路径")
    args = ap.parse_args()
    out = args.output or os.path.join(
        _PROJECT_ROOT, "reports",
        f"测试结果_{os.path.basename(os.path.dirname(args.input))}.xlsx",
    )
    ok, msg = export_results_to_excel(args.input, out)
    print(("[OK] " if ok else "[FAIL] ") + msg)
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    _main()
