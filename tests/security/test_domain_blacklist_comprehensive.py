"""禁止娱乐网站UI、分类库、导入导出与L1-L4综合验证。"""

import csv
import json
import os
import re

import pytest

from config.config import Config
from pages.security.domain_blacklist_page import DomainBlacklistPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify


PREFIX = "dblk_t_"
RULE_NAME = "dblk_t_main"
SENTINEL_NAME = "dblk_t_keep"
PARENT_GROUP = "休闲娱乐"
EDIT_SELECTION = "休闲娱乐-游戏网站"
EDIT_GROUP = "游戏网站"
SENTINEL_SELECTION = "论坛门户-搜索引擎"
SENTINEL_GROUP = "搜索引擎"
CLIENT_IP = "192.168.148.2"
GAME_DOMAIN = "4399.com"
EXPECTED_CATALOG = {
    "交通旅游": 4,
    "休闲娱乐": 10,
    "体育健身": 5,
    "医疗健康": 2,
    "新闻媒体": 2,
    "生活服务": 4,
    "论坛门户": 4,
    "购物网站": 4,
    "金融理财": 4,
}


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


def _read_domain_blacklist_export(file_path: str) -> list:
    """结构化解析domain_blacklist的CSV/TXT导出内容。"""
    text = _decode_export_file(file_path)
    if file_path.lower().endswith(".csv"):
        rows = [dict(row) for row in csv.DictReader(text.splitlines())]
    else:
        fields = "id|enabled|domain_group|src_addr|time|comment|tagname"
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
        for field in ("src_addr", "time"):
            row[field] = _decode_export_json(row.get(field, ""))
    return rows


def _assert_domain_blacklist_export_matches(file_path: str) -> dict:
    assert os.path.isfile(file_path), f"导出文件不存在: {file_path}"
    assert os.path.getsize(file_path) > 0, f"导出文件为空: {file_path}"
    rows = _read_domain_blacklist_export(file_path)
    assert len(rows) == 1, f"导出应只有1条测试规则，实际{len(rows)}条: {rows}"
    row = rows[0]
    expected_scalars = {
        "enabled": "yes",
        "domain_group": EDIT_GROUP,
        "comment": "游戏子类",
        "tagname": RULE_NAME,
    }
    for field, expected in expected_scalars.items():
        assert str(row.get(field, "")) == expected, (
            f"{os.path.basename(file_path)}字段{field}不一致: "
            f"期望{expected!r}，实际{row.get(field)!r}"
        )
    assert str(row.get("id", "")).isdigit(), f"导出id无效: {row.get('id')!r}"
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
@pytest.mark.domain_blacklist
@pytest.mark.p1
class TestDomainBlacklistComprehensive:
    def test_domain_blacklist_comprehensive(
        self,
        domain_blacklist_page_logged_in: DomainBlacklistPage,
        step_recorder: StepRecorder,
        config: Config,
        request,
    ):
        page = domain_blacklist_page_logged_in
        rec = step_recorder
        bv = request.getfixturevalue("backend_verifier")
        failures = []
        ssh_failures = []
        ssh_verify = make_ssh_verify(bv, rec, ssh_failures, must_pass_default=True)
        created_ids = set()
        current_rule_id = None

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
            bv.cleanup_domain_blacklist_test(PREFIX)

            with rec.step(
                "清空导入安全基线",
                "清理本测试前缀后读取domain_blacklist全表，确认专用设备没有非测试规则。",
                expected="domain_blacklist表为空；满足此前置条件后才允许执行清空导入。",
            ):
                baseline = verify(
                    "清空导入安全基线",
                    bv.verify_domain_blacklist_rule_set,
                    [],
                )
                rec.set_actual(getattr(baseline, "message", "验证器无返回"))
                if baseline is None or not baseline.passed:
                    pytest.fail("检测到非测试禁止娱乐网站规则，已拒绝执行清空导入")

            with rec.step(
                "页面、分类树与底层脚本契约",
                "检查三个页签、列表字段、网站类型全部九个父分类及休闲娱乐十个子类，并审计domain_blacklist.sh。",
                expected="页面字段和分类数完整；脚本包含REST注册、DB、分类展开、BLACK_DOMAIN、src/time及完整生命周期入口。",
            ):
                body = page.page.locator("body").inner_text()
                check("三个网址浏览控制页签", all(
                    text in body for text in ("网址黑白名单", "禁止娱乐网站", "自定义网址库")
                ))
                check("禁止娱乐网站列表字段", all(
                    text in body for text in ("名称", "网站类型", "内网IP", "周期", "备注", "操作")
                ))
                catalog = page.get_domain_group_catalog()
                check("网站父分类无遗漏", set(catalog) == set(EXPECTED_CATALOG), catalog)
                for group, count in EXPECTED_CATALOG.items():
                    check(f"{group}子类数量={count}", len(catalog.get(group, [])) == count, catalog.get(group))
                check(
                    "休闲娱乐十个子类名称完整",
                    set(catalog.get("休闲娱乐", [])) == {
                        "动漫网站", "娱乐时尚", "小说网站", "幽默笑话", "收藏爱好",
                        "星座运势", "游戏网站", "社交网站", "视频电影", "音乐网站",
                    },
                    catalog.get("休闲娱乐"),
                )
                script = verify(
                    "domain_blacklist.sh契约",
                    bv.verify_domain_blacklist_script_contract,
                )
                groups = verify(
                    "休闲娱乐分类库",
                    bv.verify_domain_blacklist_group_catalog,
                )
                rec.set_actual("；".join(r.message for r in (script, groups) if r))

            with rec.step(
                "右下角帮助文档",
                "点击帮助，核对官方禁止娱乐网站文章id=184的字段、使用说明和注意事项，随后关闭新标签。",
                expected="帮助位于右下角，打开ikuai8.com文章184，主题关键词完整，关闭后无孤儿页并返回列表。",
            ):
                result = page.verify_help_entry()
                check("帮助按钮存在且位于右下角", result.get("button_present") and result.get("bottom_right"), result)
                check("帮助打开官方文章id=184", result.get("opened") and result.get("official_article"), result.get("url"))
                check("帮助正文主题完整", result.get("all_keywords_matched"), result.get("matched_keywords"))
                check("帮助标签关闭并返回列表", result.get("closed") and result.get("no_orphan") and result.get("returned_to_list"), result)
                rec.set_actual(f"URL={result.get('url')}；命中关键词={result.get('matched_keywords')}；已关闭={result.get('closed')}")

            with rec.step(
                "必填项边界校验",
                "分别提交空名称和未选择网站类型的配置。",
                expected="名称和网站类型均由前端必填校验拦截，非法记录不落库。",
            ):
                empty_name = page.try_add_invalid(name="", select_group=True)
                empty_group = page.try_add_invalid(name="dblk_t_bad", select_group=False)
                check("空名称被拦截", empty_name.get("blocked"), empty_name.get("error"))
                check("空网站类型被拦截", empty_group.get("blocked"), empty_group.get("error"))
                gone = verify("边界数据未落库", bv.verify_domain_blacklist_not_exists, "dblk_t_bad")
                rec.set_actual(f"空名称={empty_name}；空分类={empty_group}；{getattr(gone, 'message', '')}")

            with rec.step(
                "新增休闲娱乐父分类并验证L1-L4",
                f"新增{RULE_NAME}，选择整个{PARENT_GROUP}，仅控制{CLIENT_IP}，默认全周生效。",
                expected="DB字段正确；十个娱乐子类均展开到BLACK_DOMAIN；源IP ipset、timeset和全局一致性正确。",
            ):
                page.navigate_to_domain_blacklist()
                added = page.add_rule(RULE_NAME, [PARENT_GROUP], sources=[CLIENT_IP])
                check("新增父分类规则", added.get("success"), added.get("error"))
                page.navigate_to_domain_blacklist()
                check("列表显示新增规则", page.rule_exists(RULE_NAME))
                rule = bv.find_domain_blacklist_rule(RULE_NAME)
                current_rule_id = int((rule or {}).get("id", 0)) or None
                if current_rule_id:
                    created_ids.add(current_rule_id)
                check("记录新增规则ID", current_rule_id is not None, rule)
                results = (
                    verify(
                        "L1数据库",
                        bv.verify_domain_blacklist_database,
                        RULE_NAME,
                        enabled="yes",
                        groups=[PARENT_GROUP],
                        sources=[CLIENT_IP],
                    ),
                    verify(
                        "L2十类娱乐域名展开",
                        bv.verify_domain_blacklist_generated_rule,
                        RULE_NAME,
                        sample_domains=list(bv.ENTERTAINMENT_DOMAIN_SAMPLES.values()),
                    ),
                    verify("L3源IP集合", bv.verify_domain_blacklist_ipset, RULE_NAME, CLIENT_IP),
                    verify("L4一致性", bv.verify_domain_blacklist_consistency, PREFIX),
                )
                rec.set_actual("；".join(r.message for r in results if r))

            with rec.step(
                "重复名称唯一性",
                "保留现有规则，再用同一名称提交另一网站分类。",
                expected="重复名称被拒绝，原规则仍只有一条且分类未改变。",
            ):
                duplicate = page.add_rule(RULE_NAME, ["新闻媒体"])
                check("重复名称被拦截", not duplicate.get("success"), duplicate.get("error"))
                exact = verify(
                    "重复后原记录不变",
                    bv.verify_domain_blacklist_database,
                    RULE_NAME,
                    enabled="yes",
                    groups=[PARENT_GROUP],
                    sources=[CLIENT_IP],
                )
                rec.set_actual(f"重复保存success={duplicate.get('success')}；{getattr(exact, 'message', '')}")

            with rec.step(
                "停用与启用下发",
                "在列表停用规则并核对DPI撤销，再启用并核对分类规则恢复。",
                expected="停用时enabled=no且专属timeset/DPI块撤销；启用后DB、DPI、ipset与timeset全部恢复一致。",
            ):
                page.navigate_to_domain_blacklist()
                check("页面停用", page.disable_rule(RULE_NAME))
                page.page.wait_for_timeout(1300)
                disabled = (
                    verify("停用DB", bv.verify_domain_blacklist_database, RULE_NAME, enabled="no", groups=[PARENT_GROUP], sources=[CLIENT_IP]),
                    verify("停用DPI撤销", bv.verify_domain_blacklist_generated_rule, RULE_NAME, expect_present=False),
                    verify("停用L4一致性", bv.verify_domain_blacklist_consistency, PREFIX),
                )
                page.navigate_to_domain_blacklist()
                check("页面启用", page.enable_rule(RULE_NAME))
                page.page.wait_for_timeout(1300)
                enabled = (
                    verify("启用DB", bv.verify_domain_blacklist_database, RULE_NAME, enabled="yes", groups=[PARENT_GROUP], sources=[CLIENT_IP]),
                    verify("启用DPI恢复", bv.verify_domain_blacklist_generated_rule, RULE_NAME, sample_domains=[GAME_DOMAIN]),
                    verify("启用源IP集合", bv.verify_domain_blacklist_ipset, RULE_NAME, CLIENT_IP),
                    verify("启用L4一致性", bv.verify_domain_blacklist_consistency, PREFIX),
                )
                rec.set_actual("；".join(r.message for r in (*disabled, *enabled) if r))

            with rec.step(
                "编辑为游戏网站子分类",
                f"从列表编辑同一规则，将网站类型改为{EDIT_GROUP}并填写备注。",
                expected="规则ID不变，domain_group精确改为游戏网站，运行态仍包含4399.com。",
            ):
                page.navigate_to_domain_blacklist()
                check("进入编辑页", page.edit_rule(RULE_NAME))
                check("切换游戏网站子分类", page.set_domain_groups([EDIT_SELECTION]))
                check("填写备注", page.fill_remark("游戏子类"))
                saved = page.save_and_wait()
                check("保存编辑", saved.get("success"), saved.get("error"))
                edited = bv.find_domain_blacklist_rule(RULE_NAME)
                check("编辑保留规则ID", current_rule_id and int((edited or {}).get("id", 0)) == current_rule_id, edited)
                db = verify(
                    "编辑后DB",
                    bv.verify_domain_blacklist_database,
                    RULE_NAME,
                    enabled="yes",
                    groups=[EDIT_GROUP],
                    sources=[CLIENT_IP],
                )
                runtime = verify(
                    "编辑后游戏域名DPI",
                    bv.verify_domain_blacklist_generated_rule,
                    RULE_NAME,
                    sample_domains=[GAME_DOMAIN],
                )
                rec.set_actual("；".join(r.message for r in (db, runtime) if r))

            with rec.step(
                "搜索与CSV/TXT双格式导出",
                "搜索存在/不存在名称；分别导出CSV和TXT并结构化解析全部字段。",
                expected="搜索结果准确；两种导出各含一条规则，分类、源IP、时间、备注、状态完全一致。",
            ):
                page.navigate_to_domain_blacklist()
                page.search_rule(RULE_NAME)
                check("存在名称搜索命中", page.rule_exists(RULE_NAME))
                page.search_rule("dblk_t_none")
                check("不存在名称搜索为空", not page.rule_exists(RULE_NAME) and page.get_rule_count() == 0)
                page.clear_search()
                export_base = config.test_data.get_export_path("domain_blacklist", config.get_project_root())
                csv_path = os.path.splitext(export_base)[0] + ".csv"
                txt_path = os.path.splitext(export_base)[0] + ".txt"
                check("CSV导出操作", page.export_rules(use_config_path=True, export_format="csv"), csv_path)
                csv_row = _assert_domain_blacklist_export_matches(csv_path)
                page.navigate_to_domain_blacklist()
                check("TXT导出操作", page.export_rules(use_config_path=True, export_format="txt"), txt_path)
                txt_row = _assert_domain_blacklist_export_matches(txt_path)
                check("CSV/TXT关键字段一致", all(
                    csv_row.get(field) == txt_row.get(field)
                    for field in ("enabled", "domain_group", "src_addr", "time", "comment", "tagname")
                ), {"csv": csv_row, "txt": txt_row})
                rec.set_actual(f"CSV={csv_path}；TXT={txt_path}；均结构化解析为一条完整规则")

            with rec.step(
                "CSV导入保留数据与批量启停",
                "删除目标后新增哨兵，CSV不清空导入；随后对两条规则执行批量停用和批量启用。",
                expected="导入保留哨兵且目标不重复；批量启停同步改变两条DB记录和DPI块。",
            ):
                page.navigate_to_domain_blacklist()
                check("删除导入目标", page.delete_rule(RULE_NAME))
                page.page.wait_for_timeout(1100)
                verify("导入准备目标已删除", bv.verify_domain_blacklist_not_exists, RULE_NAME)
                page.navigate_to_domain_blacklist()
                sentinel = page.add_rule(SENTINEL_NAME, [SENTINEL_SELECTION], sources=[CLIENT_IP])
                check("新增保留哨兵", sentinel.get("success"), sentinel.get("error"))
                sentinel_rule = bv.find_domain_blacklist_rule(SENTINEL_NAME)
                sentinel_id = int((sentinel_rule or {}).get("id", 0)) or None
                if sentinel_id:
                    created_ids.add(sentinel_id)
                page.navigate_to_domain_blacklist()
                check("CSV不清空导入", page.import_rules(csv_path, clear_existing=False), csv_path)
                page.navigate_to_domain_blacklist()
                imported_set = verify(
                    "CSV导入规则集合",
                    bv.verify_domain_blacklist_rule_set,
                    [RULE_NAME, SENTINEL_NAME],
                )
                imported = bv.find_domain_blacklist_rule(RULE_NAME)
                current_rule_id = int((imported or {}).get("id", 0)) or None
                if current_rule_id:
                    created_ids.add(current_rule_id)
                page.navigate_to_domain_blacklist()
                check("全选两条规则", page.select_all_rules())
                page.batch_disable()
                page.page.wait_for_timeout(1300)
                batch_down = (
                    verify("批量停用目标", bv.verify_domain_blacklist_database, RULE_NAME, enabled="no", groups=[EDIT_GROUP]),
                    verify("批量停用哨兵", bv.verify_domain_blacklist_database, SENTINEL_NAME, enabled="no", groups=[SENTINEL_GROUP]),
                    verify("批量停用一致性", bv.verify_domain_blacklist_consistency, PREFIX),
                )
                page.navigate_to_domain_blacklist()
                check("再次全选两条规则", page.select_all_rules())
                page.batch_enable()
                page.page.wait_for_timeout(1300)
                batch_up = (
                    verify("批量启用目标", bv.verify_domain_blacklist_database, RULE_NAME, enabled="yes", groups=[EDIT_GROUP]),
                    verify("批量启用哨兵", bv.verify_domain_blacklist_database, SENTINEL_NAME, enabled="yes", groups=[SENTINEL_GROUP]),
                    verify("批量启用一致性", bv.verify_domain_blacklist_consistency, PREFIX),
                )
                rec.set_actual("；".join(r.message for r in (imported_set, *batch_down, *batch_up) if r))

            with rec.step(
                "TXT清空导入",
                "复核全表仅有两条测试规则后，导入TXT并明确清空现有数据。",
                expected="哨兵消失，目标规则只保留一条；DB、DPI、ipset、timeset和旧ID回收均正确。",
            ):
                safety = verify(
                    "清空导入即时安全检查",
                    bv.verify_domain_blacklist_rule_set,
                    [RULE_NAME, SENTINEL_NAME],
                )
                if safety is None or not safety.passed:
                    pytest.fail("清空导入前出现非测试规则，已拒绝执行")
                retired_ids = {item for item in (current_rule_id, sentinel_id) if item}
                page.navigate_to_domain_blacklist()
                check("TXT清空导入", page.import_rules(txt_path, clear_existing=True), txt_path)
                page.navigate_to_domain_blacklist()
                exact = verify("TXT导入规则集合", bv.verify_domain_blacklist_rule_set, [RULE_NAME])
                verify("哨兵已清除", bv.verify_domain_blacklist_not_exists, SENTINEL_NAME)
                imported = bv.find_domain_blacklist_rule(RULE_NAME)
                current_rule_id = int((imported or {}).get("id", 0)) or None
                if current_rule_id:
                    created_ids.add(current_rule_id)
                checks = (
                    verify("TXT导入DB", bv.verify_domain_blacklist_database, RULE_NAME, enabled="yes", groups=[EDIT_GROUP], sources=[CLIENT_IP]),
                    verify("TXT导入DPI", bv.verify_domain_blacklist_generated_rule, RULE_NAME, sample_domains=[GAME_DOMAIN]),
                    verify("TXT导入ipset", bv.verify_domain_blacklist_ipset, RULE_NAME, CLIENT_IP),
                    verify("TXT导入一致性", bv.verify_domain_blacklist_consistency, PREFIX),
                )
                retired = []
                for rule_id in sorted(retired_ids - {current_rule_id}):
                    retired.append(verify(
                        f"清空导入旧ID={rule_id}残留",
                        bv.verify_domain_blacklist_artifacts_absent,
                        rule_id,
                    ))
                rec.set_actual("；".join(r.message for r in (safety, exact, *checks, *retired) if r))

            with rec.step(
                "删除及底层残留检查",
                "从列表删除最终规则，核对数据库、DPI、源地址集合与时间计划。",
                expected="UI和DB无规则，DPI块撤销，ipset/timeset无旧ID残留，全局一致性为零。",
            ):
                page.navigate_to_domain_blacklist()
                check("页面删除最终规则", page.delete_rule(RULE_NAME))
                page.page.wait_for_timeout(1200)
                page.navigate_to_domain_blacklist()
                check("列表已无最终规则", not page.rule_exists(RULE_NAME))
                results = (
                    verify("删除DB", bv.verify_domain_blacklist_not_exists, RULE_NAME),
                    verify("删除DPI", bv.verify_domain_blacklist_generated_rule, RULE_NAME, expect_present=False, sample_domains=[GAME_DOMAIN]),
                    verify("删除一致性", bv.verify_domain_blacklist_consistency, PREFIX),
                    verify("删除对象回收", bv.verify_domain_blacklist_artifacts_absent, current_rule_id) if current_rule_id else None,
                )
                rec.set_actual("；".join(r.message for r in results if r))
        finally:
            try:
                cleanup = bv.cleanup_domain_blacklist_test(PREFIX)
                rec.add_detail(f"【清理结果】\n通过：{cleanup}")
                if created_ids:
                    artifacts = bv.cleanup_domain_blacklist_artifacts(created_ids)
                    rec.add_detail(f"【清理结果】\n通过：{artifacts}")
            except Exception as exc:
                failures.append(f"兜底清理异常: {exc}")

        failures.extend(ssh_failures)
        if failures:
            pytest.fail("禁止娱乐网站综合测试失败:\n" + "\n".join(failures))
