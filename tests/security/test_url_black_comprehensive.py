"""网址黑白名单UI、导入导出与L1-L4综合验证。"""

import csv
import json
import os
import re

import pytest

from config.config import Config
from pages.security.url_black_page import UrlBlackPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify


PREFIX = "urlbw_t_"
RULE_NAME = "urlbw_t_black"
DOMAIN = "www.baidu.com"
CLIENT_IP = "192.168.148.2"
SENTINEL_NAME = "urlbw_t_keep"
SENTINEL_DOMAIN = "www.qq.com"


def _decode_export_file(file_path: str) -> str:
    with open(file_path, "rb") as export_file:
        raw = export_file.read()
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise AssertionError(f"导出文件编码无法识别: {file_path}")


def _decode_export_json(value):
    if not isinstance(value, str):
        return value
    candidate = value.strip()
    if not candidate.startswith(("{", "[")):
        return value
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"导出JSON字段格式错误: {candidate[:160]}") from exc


def _read_url_black_export(file_path: str) -> list:
    """结构化解析网址黑白名单CSV/TXT，避免仅凭文件非空判定通过。"""
    text = _decode_export_file(file_path)
    if file_path.lower().endswith(".csv"):
        rows = [dict(row) for row in csv.DictReader(text.splitlines())]
    else:
        fields = "id|enabled|tagname|comment|domain|src_addr|time|mode"
        rows = []
        for line in text.splitlines():
            if not line.strip():
                continue
            row = {
                match.group(1): match.group(2).strip()
                for match in re.finditer(
                    rf"(?:^|\s)({fields})=(.*?)(?=\s+(?:{fields})=|$)",
                    line,
                )
            }
            rows.append(row)
    for row in rows:
        for field in ("domain", "src_addr", "time"):
            row[field] = _decode_export_json(row.get(field, ""))
    return rows


def _assert_url_black_export_matches(file_path: str) -> dict:
    assert os.path.isfile(file_path), f"导出文件不存在: {file_path}"
    assert os.path.getsize(file_path) > 0, f"导出文件为空: {file_path}"
    rows = _read_url_black_export(file_path)
    assert len(rows) == 1, f"导出应只有1条测试规则，实际{len(rows)}条: {rows}"
    row = rows[0]
    expected_scalars = {
        "enabled": "yes",
        "tagname": RULE_NAME,
        "comment": "",
        "mode": "1",
    }
    for field, expected in expected_scalars.items():
        assert str(row.get(field, "")) == expected, (
            f"{os.path.basename(file_path)}字段{field}不一致: "
            f"期望{expected!r}，实际{row.get(field)!r}"
        )
    assert str(row.get("id", "")).isdigit(), f"导出id无效: {row.get('id')!r}"
    assert row.get("domain") == {"custom": [DOMAIN], "object": {}}, (
        f"导出domain不一致: {row.get('domain')!r}"
    )
    assert row.get("src_addr") == {"custom": [CLIENT_IP], "object": {}}, (
        f"导出src_addr不一致: {row.get('src_addr')!r}"
    )
    schedules = (row.get("time") or {}).get("custom", [])
    assert len(schedules) == 1, f"导出time条目不一致: {row.get('time')!r}"
    schedule = schedules[0]
    assert (
        str(schedule.get("type")) == "weekly"
        and str(schedule.get("weekdays")) == "1234567"
        and str(schedule.get("start_time")) == "00:00"
        and str(schedule.get("end_time")) == "23:59"
    ), f"导出全周时间不一致: {schedule!r}"
    return row


@pytest.mark.security
@pytest.mark.url_black
@pytest.mark.p1
class TestUrlBlackComprehensive:
    def test_url_black_comprehensive(
        self,
        url_black_page_logged_in: UrlBlackPage,
        step_recorder: StepRecorder,
        config: Config,
        request,
    ):
        page = url_black_page_logged_in
        rec = step_recorder
        bv = request.getfixturevalue("backend_verifier")
        failures = []
        ssh_failures = []
        ssh_verify = make_ssh_verify(
            bv, rec, ssh_failures, must_pass_default=True
        )
        original_setting = None
        created_rule_id = None
        created_rule_ids = set()

        def check(label, condition, actual=""):
            condition = bool(condition)
            rec.add_detail(
                f"【页面验证】\n{'通过' if condition else '失败'}：{label}"
                + (f"；实际={actual}" if actual else "")
            )
            if not condition:
                failures.append(f"{label}: {actual or '未达到预期'}")
                rec.fail_current_step(f"{label}未达到预期")
            return condition

        def verify(label, func, *args, **kwargs):
            result = ssh_verify(label, func, *args, **kwargs)
            if result is None or not result.passed:
                rec.fail_current_step(
                    f"{label}: {getattr(result, 'message', '验证器无返回')}"
                )
            return result

        try:
            bv.cleanup_url_black_test(PREFIX)

            with rec.step(
                "清空导入安全基线",
                "清理本测试前缀后读取url_black全表，确认专用测试设备没有非测试规则。",
                expected="url_black表为空；只有满足此前置条件，后续才允许勾选清空现有数据。",
            ):
                baseline = verify(
                    "清空导入安全基线",
                    bv.verify_url_black_rule_set,
                    [],
                )
                rec.set_actual(getattr(baseline, "message", "验证器无返回"))
                if baseline is None or not baseline.passed:
                    pytest.fail("检测到非测试网址规则，已拒绝执行清空导入")

            with rec.step(
                "页面结构与HTTP-only能力提示",
                "进入安全中心-网址浏览控制-网址黑白名单，检查三个页签、列表列、右上角设置及协议提示。",
                expected="默认位于网址黑白名单页签；设置项存在，并明确标注只有外链Referer放行只支持HTTP。",
            ):
                body = page.page.locator("body").inner_text()
                check("网址黑白名单页签", "网址黑白名单" in body)
                check("黑/白模式列表列", "控制模式" in body and "控制域名" in body)
                check("右上角设置可打开", page.open_settings())
                setting = page.get_white_external_link_setting()
                check("HTTP-only提示", setting.get("http_only_hint"), setting)
                original_setting = bool(setting.get("enabled"))
                rec.set_actual(
                    f"页面字段完整；外链开关初始值={int(original_setting)}；提示=只支持HTTP协议"
                )
                page.page.keyboard.press("Escape")

            with rec.step(
                "右下角帮助文档",
                "确认帮助按钮位于页面右下角，点击后打开官方网址黑白名单文章，核对主题内容并关闭新标签页。",
                expected="按钮位置正确；打开ikuai8.com文章id=183；正文包含控制模式、控制域名、外部链接和HTTP/HTTPS说明；关闭后无孤儿页且返回列表。",
            ):
                help_result = page.verify_help_entry()
                check(
                    "帮助按钮存在且位于右下角",
                    help_result.get("button_present")
                    and help_result.get("bottom_right"),
                    help_result,
                )
                check(
                    "帮助打开官方文章id=183",
                    help_result.get("opened")
                    and help_result.get("official_article"),
                    help_result.get("url") or help_result.get("error"),
                )
                check(
                    "帮助正文主题完整",
                    help_result.get("all_keywords_matched"),
                    help_result.get("matched_keywords") or help_result.get("error"),
                )
                check(
                    "帮助标签关闭并返回列表",
                    help_result.get("closed")
                    and help_result.get("no_orphan")
                    and help_result.get("returned_to_list"),
                    help_result,
                )
                rec.add_detail(
                    "【后端验证】\n不适用：帮助入口只打开官方文档，不修改路由器配置"
                )
                rec.set_actual(
                    f"URL={help_result.get('url')}；标题={help_result.get('title')}；"
                    f"命中关键词={help_result.get('matched_keywords')}；"
                    f"已关闭={help_result.get('closed')}；无孤儿页={help_result.get('no_orphan')}"
                )

            with rec.step(
                "输入边界校验",
                "分别提交空名称和带协议/路径的URL，检查页面不得把它们当作合法域名规则保存。",
                expected="空名称被必填校验拦截；https://host/path被域名格式校验拦截；数据库无测试规则。",
            ):
                empty = page.try_add_invalid(name="", domain=DOMAIN)
                check("空名称被拦截", empty.get("blocked"), empty.get("error"))
                invalid = page.try_add_invalid(
                    name="urlbw_t_bad", domain="https://www.baidu.com/path"
                )
                check("URL格式不能冒充域名", invalid.get("blocked"), invalid.get("error"))
                deleted = verify(
                    "边界数据未落库",
                    bv.verify_url_black_not_exists,
                    "urlbw_t_bad",
                )
                rec.set_actual(
                    f"空名称blocked={empty.get('blocked')}；URL格式blocked={invalid.get('blocked')}；"
                    f"落库={not bool(deleted and deleted.passed)}"
                )

            with rec.step(
                "新增黑名单并验证L1-L4",
                f"通过页面新增黑名单：名称={RULE_NAME}，域名={DOMAIN}，内网IP={CLIENT_IP}，默认全周生效。",
                expected="页面保存成功；L1数据库、L2 BLACK_DOMAIN、L3源IP ipset、L4 DB/DPI/集合一致性全部通过。",
            ):
                page.navigate_to_url_black()
                added = page.add_rule(
                    RULE_NAME,
                    [DOMAIN],
                    mode=0,
                    sources=[CLIENT_IP],
                )
                check("新增黑名单", added.get("success"), added.get("error"))
                page.navigate_to_url_black()
                check("列表显示新增规则", page.rule_exists(RULE_NAME))
                created_rule = bv.find_url_black_rule(RULE_NAME)
                created_rule_id = int((created_rule or {}).get("id", 0)) or None
                if created_rule_id is not None:
                    created_rule_ids.add(created_rule_id)
                check("记录新增规则ID", created_rule_id is not None, created_rule)
                results = [
                    verify(
                        "L1数据库",
                        bv.verify_url_black_database,
                        RULE_NAME,
                        mode=0,
                        enabled="yes",
                        domains=[DOMAIN],
                        sources=[CLIENT_IP],
                    ),
                    verify(
                        "L2-DPI黑名单",
                        bv.verify_url_black_generated_rule,
                        RULE_NAME,
                        mode=0,
                        domains=[DOMAIN],
                    ),
                    verify(
                        "L3-源IP集合",
                        bv.verify_url_black_ipset,
                        RULE_NAME,
                        CLIENT_IP,
                    ),
                    verify(
                        "L4-一致性",
                        bv.verify_url_black_consistency,
                        PREFIX,
                    ),
                ]
                rec.set_actual("；".join(r.message for r in results if r))

            with rec.step(
                "重复名称唯一性",
                "保留已存在规则，再用相同名称提交另一域名。",
                expected="前端或后端返回名称重复错误，url_black表中该名称始终只有一条。",
            ):
                duplicate = page.add_rule(
                    RULE_NAME,
                    ["www.qq.com"],
                    mode=0,
                    sources=[CLIENT_IP],
                )
                check("重复名称被拦截", not duplicate.get("success"), duplicate.get("error"))
                db = verify(
                    "重复后原记录不变",
                    bv.verify_url_black_database,
                    RULE_NAME,
                    mode=0,
                    domains=[DOMAIN],
                    sources=[CLIENT_IP],
                )
                rec.set_actual(
                    f"重复保存success={duplicate.get('success')}；{getattr(db, 'message', '')}"
                )

            with rec.step(
                "停用与启用下发",
                "在列表停用规则，确认DB状态和DPI块撤销；再启用并确认恢复。",
                expected="停用时enabled=no且BLACK_DOMAIN块不存在；启用时enabled=yes且块重新出现，无旧块重复。",
            ):
                page.navigate_to_url_black()
                check("页面停用", page.disable_rule(RULE_NAME))
                page.page.wait_for_timeout(1300)
                disabled_db = verify(
                    "停用DB",
                    bv.verify_url_black_database,
                    RULE_NAME,
                    enabled="no",
                    mode=0,
                    domains=[DOMAIN],
                    sources=[CLIENT_IP],
                )
                disabled_runtime = verify(
                    "停用DPI撤销",
                    bv.verify_url_black_generated_rule,
                    RULE_NAME,
                    expect_present=False,
                    mode=0,
                    domains=[DOMAIN],
                )
                page.navigate_to_url_black()
                check("页面启用", page.enable_rule(RULE_NAME))
                page.page.wait_for_timeout(1300)
                enabled_db = verify(
                    "启用DB",
                    bv.verify_url_black_database,
                    RULE_NAME,
                    enabled="yes",
                    mode=0,
                    domains=[DOMAIN],
                    sources=[CLIENT_IP],
                )
                enabled_runtime = verify(
                    "启用DPI恢复",
                    bv.verify_url_black_generated_rule,
                    RULE_NAME,
                    mode=0,
                    domains=[DOMAIN],
                )
                rec.set_actual("；".join(
                    r.message for r in (
                        disabled_db, disabled_runtime, enabled_db, enabled_runtime
                    ) if r
                ))

            with rec.step(
                "黑名单编辑为白名单",
                "从列表进入编辑页，将控制模式从黑名单切换为白名单并保存。",
                expected="同一规则ID保留，DB mode由0变1，DPI动作由BLACK_DOMAIN变为WHITE_DOMAIN。",
            ):
                page.navigate_to_url_black()
                check("进入编辑页", page.edit_rule(RULE_NAME))
                check("切换白名单", page.set_mode(1))
                saved = page.save_and_wait()
                check("保存白名单模式", saved.get("success"), saved.get("error"))
                db = verify(
                    "白名单DB",
                    bv.verify_url_black_database,
                    RULE_NAME,
                    enabled="yes",
                    mode=1,
                    domains=[DOMAIN],
                    sources=[CLIENT_IP],
                )
                runtime = verify(
                    "白名单DPI",
                    bv.verify_url_black_generated_rule,
                    RULE_NAME,
                    mode=1,
                    domains=[DOMAIN],
                )
                edited_rule = bv.find_url_black_rule(RULE_NAME)
                check(
                    "编辑保留同一规则ID",
                    created_rule_id is not None
                    and int((edited_rule or {}).get("id", 0)) == created_rule_id,
                    edited_rule,
                )
                rec.set_actual("；".join(r.message for r in (db, runtime) if r))

            with rec.step(
                "白名单外部链接设置持久化",
                "把右上角外链开关切换到相反值并保存、核对数据库，再恢复测试前值。",
                expected="global_config.url_white_refer在0/1间准确切换并恢复；页面持续显示只支持HTTP协议。",
            ):
                page.navigate_to_url_black()
                check("打开设置", page.open_settings())
                target = not bool(original_setting)
                check("切换并保存设置", page.set_white_external_link(target))
                changed = verify(
                    "设置切换持久化",
                    bv.verify_url_black_setting,
                    int(target),
                )
                page.navigate_to_url_black()
                check("重新打开设置", page.open_settings())
                reopened = page.get_white_external_link_setting()
                check("设置回读", reopened.get("enabled") is target, reopened)
                check("恢复原设置", page.set_white_external_link(bool(original_setting)))
                restored = verify(
                    "设置恢复",
                    bv.verify_url_black_setting,
                    int(bool(original_setting)),
                )
                rec.set_actual(
                    f"切换后={int(target)}，回读={int(bool(reopened.get('enabled')))}，"
                    f"恢复={int(bool(original_setting))}；{getattr(changed, 'message', '')}；"
                    f"{getattr(restored, 'message', '')}"
                )

            with rec.step(
                "搜索与CSV/TXT双格式导出",
                "按完整名称搜索；分别选择CSV和TXT导出，并结构化解析全部字段。",
                expected="搜索只显示目标规则；CSV/TXT各含1条规则，名称、状态、模式、域名、源IP和时间字段均与页面一致。",
            ):
                page.navigate_to_url_black()
                page.search_rule(RULE_NAME)
                check("搜索命中", page.rule_exists(RULE_NAME))
                page.clear_search()
                export_base = config.test_data.get_export_path(
                    "url_black", config.get_project_root()
                )
                export_path_csv = os.path.splitext(export_base)[0] + ".csv"
                export_path_txt = os.path.splitext(export_base)[0] + ".txt"

                exported_csv = page.export_rules(
                    use_config_path=True, export_format="csv"
                )
                check("CSV导出操作", exported_csv, export_path_csv)
                csv_row = _assert_url_black_export_matches(export_path_csv)

                page.navigate_to_url_black()
                exported_txt = page.export_rules(
                    use_config_path=True, export_format="txt"
                )
                check("TXT导出操作", exported_txt, export_path_txt)
                txt_row = _assert_url_black_export_matches(export_path_txt)
                check(
                    "CSV/TXT关键字段一致",
                    all(
                        csv_row.get(field) == txt_row.get(field)
                        for field in (
                            "enabled", "tagname", "comment", "domain",
                            "src_addr", "time", "mode",
                        )
                    ),
                    {"csv": csv_row, "txt": txt_row},
                )
                rec.set_actual(
                    f"CSV={export_path_csv}，TXT={export_path_txt}；"
                    "两种格式均为1条且关键字段一致"
                )

            with rec.step(
                "CSV导入（不清空现有数据）",
                "删除已导出的目标规则，新增保留哨兵规则，再导入CSV且明确不勾选清空现有数据。",
                expected="导入成功；哨兵规则保留，目标规则恢复且不重复；两条规则的DB、DPI、ipset和L4一致性均正确。",
            ):
                page.navigate_to_url_black()
                check("导入准备-删除目标规则", page.delete_rule(RULE_NAME))
                page.page.wait_for_timeout(1300)
                verify("导入准备-目标已删除", bv.verify_url_black_not_exists, RULE_NAME)
                if created_rule_id is not None:
                    cleanup = bv.cleanup_url_black_artifacts([created_rule_id])
                    rec.add_detail(f"【清理结果】\n通过：导入准备阶段{cleanup}")

                page.navigate_to_url_black()
                sentinel_added = page.add_rule(
                    SENTINEL_NAME,
                    [SENTINEL_DOMAIN],
                    mode=0,
                    sources=[CLIENT_IP],
                )
                check("新增保留哨兵", sentinel_added.get("success"), sentinel_added.get("error"))
                sentinel_rule = bv.find_url_black_rule(SENTINEL_NAME)
                sentinel_id = int((sentinel_rule or {}).get("id", 0)) or None
                if sentinel_id is not None:
                    created_rule_ids.add(sentinel_id)

                page.navigate_to_url_black()
                imported_csv = page.import_rules(
                    export_path_csv, clear_existing=False
                )
                check("CSV不清空导入操作", imported_csv, export_path_csv)
                page.navigate_to_url_black()
                check("CSV导入后目标规则恢复", page.rule_exists(RULE_NAME))
                check("CSV导入后哨兵规则保留", page.rule_exists(SENTINEL_NAME))
                csv_set = verify(
                    "CSV导入规则集合",
                    bv.verify_url_black_rule_set,
                    [RULE_NAME, SENTINEL_NAME],
                )
                csv_db = verify(
                    "CSV导入目标DB",
                    bv.verify_url_black_database,
                    RULE_NAME,
                    mode=1,
                    enabled="yes",
                    domains=[DOMAIN],
                    sources=[CLIENT_IP],
                )
                csv_runtime = verify(
                    "CSV导入目标DPI",
                    bv.verify_url_black_generated_rule,
                    RULE_NAME,
                    mode=1,
                    domains=[DOMAIN],
                )
                csv_ipset = verify(
                    "CSV导入目标源IP集合",
                    bv.verify_url_black_ipset,
                    RULE_NAME,
                    CLIENT_IP,
                )
                csv_consistency = verify(
                    "CSV导入后L4一致性",
                    bv.verify_url_black_consistency,
                    PREFIX,
                )
                imported_rule = bv.find_url_black_rule(RULE_NAME)
                created_rule_id = int((imported_rule or {}).get("id", 0)) or None
                if created_rule_id is not None:
                    created_rule_ids.add(created_rule_id)
                rec.set_actual("；".join(
                    result.message for result in (
                        csv_set, csv_db, csv_runtime, csv_ipset, csv_consistency
                    ) if result
                ))

            with rec.step(
                "TXT导入（清空现有数据）",
                "复读当前全表仅含两条测试规则，导入TXT并明确勾选清空现有数据。",
                expected="清空导入成功；哨兵规则消失，目标规则仅保留1条；DB、DPI、ipset和L4一致性全部通过。",
            ):
                safety = verify(
                    "清空导入即时安全检查",
                    bv.verify_url_black_rule_set,
                    [RULE_NAME, SENTINEL_NAME],
                )
                if safety is None or not safety.passed:
                    pytest.fail("清空导入前出现非测试规则，已拒绝执行")
                pre_clear_rule_ids = {
                    rule_id for rule_id in (created_rule_id, sentinel_id)
                    if rule_id is not None
                }
                page.navigate_to_url_black()
                imported_txt = page.import_rules(
                    export_path_txt, clear_existing=True
                )
                check("TXT清空导入操作", imported_txt, export_path_txt)
                page.navigate_to_url_black()
                check("TXT清空导入后目标存在", page.rule_exists(RULE_NAME))
                check("TXT清空导入后哨兵消失", not page.rule_exists(SENTINEL_NAME))
                txt_set = verify(
                    "TXT清空导入规则集合",
                    bv.verify_url_black_rule_set,
                    [RULE_NAME],
                )
                sentinel_gone = verify(
                    "TXT清空导入移除哨兵",
                    bv.verify_url_black_not_exists,
                    SENTINEL_NAME,
                )
                txt_db = verify(
                    "TXT清空导入目标DB",
                    bv.verify_url_black_database,
                    RULE_NAME,
                    mode=1,
                    enabled="yes",
                    domains=[DOMAIN],
                    sources=[CLIENT_IP],
                )
                txt_runtime = verify(
                    "TXT清空导入目标DPI",
                    bv.verify_url_black_generated_rule,
                    RULE_NAME,
                    mode=1,
                    domains=[DOMAIN],
                )
                txt_ipset = verify(
                    "TXT清空导入目标源IP集合",
                    bv.verify_url_black_ipset,
                    RULE_NAME,
                    CLIENT_IP,
                )
                txt_consistency = verify(
                    "TXT清空导入后L4一致性",
                    bv.verify_url_black_consistency,
                    PREFIX,
                )
                imported_rule = bv.find_url_black_rule(RULE_NAME)
                created_rule_id = int((imported_rule or {}).get("id", 0)) or None
                if created_rule_id is not None:
                    created_rule_ids.add(created_rule_id)
                retired_artifacts = []
                for retired_id in sorted(pre_clear_rule_ids - {created_rule_id}):
                    retired_artifacts.append(verify(
                        f"TXT清空导入旧ID={retired_id}的ipset回收",
                        bv.verify_url_black_artifacts_absent,
                        retired_id,
                    ))
                rec.set_actual("；".join(
                    result.message for result in (
                        safety, txt_set, sentinel_gone, txt_db, txt_runtime,
                        txt_ipset, txt_consistency, *retired_artifacts,
                    ) if result
                ))

            with rec.step(
                "删除及残留检查",
                "通过列表删除测试规则，再核对数据库、DPI配置和urlblack源地址集合。",
                expected="规则从UI和DB消失，WHITE_DOMAIN块撤销，L4一致性无测试残留。",
            ):
                page.navigate_to_url_black()
                check("页面删除", page.delete_rule(RULE_NAME))
                page.page.wait_for_timeout(1300)
                page.navigate_to_url_black()
                check("列表已删除", not page.rule_exists(RULE_NAME))
                db = verify(
                    "删除DB",
                    bv.verify_url_black_not_exists,
                    RULE_NAME,
                )
                runtime = verify(
                    "删除DPI",
                    bv.verify_url_black_generated_rule,
                    RULE_NAME,
                    expect_present=False,
                    mode=1,
                    domains=[DOMAIN],
                )
                consistency = verify(
                    "删除后L4一致性",
                    bv.verify_url_black_consistency,
                    PREFIX,
                )
                artifacts = verify(
                    "删除后ipset回收",
                    bv.verify_url_black_artifacts_absent,
                    created_rule_id,
                ) if created_rule_id is not None else None
                rec.set_actual("；".join(
                    r.message for r in (db, runtime, consistency, artifacts) if r
                ))
        finally:
            try:
                cleanup = bv.cleanup_url_black_test(PREFIX)
                rec.add_detail(f"【清理结果】\n通过：{cleanup}")
                if created_rule_id is not None:
                    artifact_cleanup = bv.cleanup_url_black_artifacts(
                        created_rule_ids
                    )
                    rec.add_detail(f"【清理结果】\n通过：{artifact_cleanup}")
            except Exception as exc:
                failures.append(f"兜底清理异常: {exc}")
            if original_setting is not None:
                try:
                    page.navigate_to_url_black()
                    if page.open_settings():
                        page.set_white_external_link(bool(original_setting))
                except Exception as exc:
                    failures.append(f"设置恢复异常: {exc}")

        failures.extend(ssh_failures)
        if failures:
            pytest.fail("网址黑白名单综合测试失败:\n" + "\n".join(failures))
