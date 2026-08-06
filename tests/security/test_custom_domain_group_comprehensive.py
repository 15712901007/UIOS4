"""自定义网址库UI、导入导出与domain_group.sh综合验证。"""

import csv
import os
import re

import pytest

from config.config import Config
from pages.security.custom_domain_group_page import CustomDomainGroupPage
from utils.step_recorder import StepRecorder
from utils.verify_helper import make_ssh_verify


PREFIX = "cdom_t_"
RULE_NAME = "cdom_t_main"
EDITED_NAME = "cdom_t_edit"
SENTINEL_NAME = "cdom_t_keep"
INITIAL_CATEGORY = "交通旅游"
INITIAL_TYPE = "旅游网站"
INITIAL_GROUP = f"{INITIAL_CATEGORY}-{INITIAL_TYPE}"
EDIT_CATEGORY = "新闻媒体"
EDIT_TYPE = "新闻报刊"
EDIT_GROUP = f"{EDIT_CATEGORY}-{EDIT_TYPE}"
INITIAL_DOMAINS = ["www.baidu.com", "example.com"]
EDIT_DOMAINS = ["www.baidu.com", "www.qq.com"]
SENTINEL_DOMAINS = ["example.org"]
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
    with open(file_path, "rb") as stream:
        raw = stream.read()
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise AssertionError(f"导出文件编码无法识别: {file_path}")


def _read_custom_domain_export(file_path: str) -> list:
    text = _decode_export_file(file_path)
    if file_path.lower().endswith(".csv"):
        return [dict(row) for row in csv.DictReader(text.splitlines())]
    fields = "id|name|domains|tagname"
    return [
        {
            match.group(1): match.group(2).strip()
            for match in re.finditer(
                rf"(?:^|\s)({fields})=(.*?)(?=\s+(?:{fields})=|$)",
                line,
            )
        }
        for line in text.splitlines()
        if line.strip()
    ]


def _assert_custom_domain_export(file_path: str) -> dict:
    assert os.path.isfile(file_path), f"导出文件不存在: {file_path}"
    assert os.path.getsize(file_path) > 0, f"导出文件为空: {file_path}"
    rows = _read_custom_domain_export(file_path)
    assert len(rows) == 1, f"导出应只有1条测试记录，实际={rows}"
    row = rows[0]
    assert str(row.get("id", "")).isdigit(), f"导出id无效: {row}"
    assert row.get("tagname") == EDITED_NAME, f"导出名称错误: {row}"
    assert row.get("name") == EDIT_GROUP, f"导出类别错误: {row}"
    assert str(row.get("domains", "")).split(",") == EDIT_DOMAINS, (
        f"导出域名错误: {row}"
    )
    return row


@pytest.mark.security
@pytest.mark.custom_domain_group
@pytest.mark.p1
class TestCustomDomainGroupComprehensive:
    def test_custom_domain_group_comprehensive(
        self,
        custom_domain_group_page_logged_in: CustomDomainGroupPage,
        step_recorder: StepRecorder,
        config: Config,
        request,
    ):
        page = custom_domain_group_page_logged_in
        rec = step_recorder
        bv = request.getfixturevalue("backend_verifier")
        failures = []
        ssh_failures = []
        verify_ssh = make_ssh_verify(
            bv, rec, ssh_failures, must_pass_default=True
        )

        def check(label, condition, actual=""):
            passed = bool(condition)
            rec.add_detail(
                f"【页面验证】\n{'通过' if passed else '失败'}：{label}"
                + (f"；实际={actual}" if actual else "")
            )
            if not passed:
                failures.append(f"{label}: {actual or '未达到预期'}")
                rec.fail_current_step(f"{label}未达到预期")
            return passed

        def verify(label, func, *args, **kwargs):
            result = verify_ssh(label, func, *args, **kwargs)
            if result is None or not result.passed:
                rec.fail_current_step(
                    f"{label}: {getattr(result, 'message', '验证器无返回')}"
                )
            return result

        try:
            bv.cleanup_custom_domain_group_test(PREFIX)

            with rec.step(
                "清空导入安全基线",
                "通过domain_group.sh只清理本测试前缀，再读取custom_domain_group全表。",
                expected="专用测试设备的自定义网址库为空，满足后续清空导入的安全前置条件。",
            ):
                baseline = verify(
                    "自定义网址库安全基线",
                    bv.verify_custom_domain_group_rule_set,
                    [],
                )
                rec.set_actual(getattr(baseline, "message", "验证器无返回"))
                if baseline is None or not baseline.passed:
                    pytest.fail("检测到非测试自定义网址记录，已拒绝执行清空导入")

            with rec.step(
                "页面结构、分类目录与脚本契约",
                "检查三个网址控制页签、列表列、九个父分类及domain_group.sh生命周期入口。",
                expected="页面结构完整；九类共39个子类；脚本具备查询、分类展开、CRUD和导入导出入口。",
            ):
                body = page.page.locator("body").inner_text()
                check("三个网址浏览控制页签", all(
                    item in body
                    for item in ("网址黑白名单", "禁止娱乐网站", "自定义网址库")
                ))
                check("自定义网址库列表字段", all(
                    item in body for item in ("查询系统网址", "名称", "类别", "域名", "操作")
                ))
                catalog = page.get_category_catalog()
                check("网站父分类完整", set(catalog) == set(EXPECTED_CATALOG), catalog)
                for category, count in EXPECTED_CATALOG.items():
                    check(
                        f"{category}子类数量={count}",
                        len(catalog.get(category, [])) == count,
                        catalog.get(category),
                    )
                script = verify(
                    "domain_group.sh契约",
                    bv.verify_custom_domain_group_script_contract,
                )
                rec.set_actual(
                    f"父分类={len(catalog)}，子类={sum(map(len, catalog.values()))}；"
                    f"{getattr(script, 'message', '')}"
                )

            with rec.step(
                "右下角帮助文档",
                "打开官方自定义网址库帮助文章，核对字段、系统网址查询和联动说明后关闭标签页。",
                expected="帮助位于右下角，打开ikuai8.com文章id=185，主题完整且关闭后无孤儿标签页。",
            ):
                result = page.verify_help_entry()
                check(
                    "帮助按钮存在且位于右下角",
                    result.get("button_present") and result.get("bottom_right"),
                    result,
                )
                check(
                    "帮助打开官方文章id=185",
                    result.get("opened") and result.get("official_article"),
                    result.get("url") or result.get("error"),
                )
                check(
                    "帮助正文主题完整",
                    result.get("all_keywords_matched"),
                    result.get("matched_keywords") or result.get("error"),
                )
                check(
                    "帮助标签关闭并返回列表",
                    result.get("closed")
                    and result.get("no_orphan")
                    and result.get("returned_to_list"),
                    result,
                )
                rec.set_actual(
                    f"URL={result.get('url')}；命中={result.get('matched_keywords')}；"
                    f"已关闭={result.get('closed')}"
                )

            with rec.step(
                "必填项与域名格式边界",
                "依次提交空名称、空域名和带协议路径的URL。",
                expected="三种非法输入均停留新增页并出现表单错误，数据库不产生边界测试记录。",
            ):
                empty_name = page.try_add_invalid(
                    name="", domains=["www.baidu.com"]
                )
                empty_domains = page.try_add_invalid(
                    name="cdom_t_empty", domains=[]
                )
                invalid_url = page.try_add_invalid(
                    name="cdom_t_badurl", domains=["https://www.baidu.com/path"]
                )
                check("空名称被拦截", empty_name.get("blocked"), empty_name)
                check("空域名被拦截", empty_domains.get("blocked"), empty_domains)
                check("URL格式被拦截", invalid_url.get("blocked"), invalid_url)
                absent = [
                    verify(
                        f"边界数据未落库-{name}",
                        bv.verify_custom_domain_group_not_exists,
                        name,
                    )
                    for name in ("cdom_t_empty", "cdom_t_badurl")
                ]
                rec.set_actual(
                    f"空名称={empty_name}；空域名={empty_domains}；"
                    f"非法URL={invalid_url}；"
                    + "；".join(result.message for result in absent if result)
                )

            with rec.step(
                "新增网址库并验证L1-L2",
                f"新增{RULE_NAME}，归类到{INITIAL_GROUP}，填写两个域名。",
                expected="页面列表出现记录；DB字段顺序一致；retrieve_domain_groups能展开两个自定义域名。",
            ):
                added = page.add_rule(
                    RULE_NAME,
                    INITIAL_CATEGORY,
                    INITIAL_TYPE,
                    INITIAL_DOMAINS,
                )
                check("页面新增成功", added.get("success"), added.get("error"))
                page.navigate_to_custom_domain_group()
                check("列表显示新增记录", page.rule_exists(RULE_NAME))
                db = verify(
                    "L1数据库",
                    bv.verify_custom_domain_group_database,
                    RULE_NAME,
                    group=INITIAL_GROUP,
                    domains=INITIAL_DOMAINS,
                )
                expanded = verify(
                    "L2分类展开",
                    bv.verify_custom_domain_group_resolution,
                    RULE_NAME,
                )
                consistent = verify(
                    "L1-L2一致性",
                    bv.verify_custom_domain_group_consistency,
                    PREFIX,
                )
                rec.set_actual("；".join(
                    result.message for result in (db, expanded, consistent) if result
                ))

            with rec.step(
                "重复名称唯一性",
                "保留现有记录，再以同名提交不同类别和域名。",
                expected="保存被唯一性校验拒绝，原记录类别和域名保持不变且仍只有一条。",
            ):
                duplicate = page.add_rule(
                    RULE_NAME,
                    EDIT_CATEGORY,
                    EDIT_TYPE,
                    ["example.org"],
                )
                check("重复名称被拦截", not duplicate.get("success"), duplicate)
                exact = verify(
                    "重复后原记录不变",
                    bv.verify_custom_domain_group_database,
                    RULE_NAME,
                    group=INITIAL_GROUP,
                    domains=INITIAL_DOMAINS,
                )
                names = verify(
                    "重复后集合无重复",
                    bv.verify_custom_domain_group_rule_set,
                    [RULE_NAME],
                    prefix=PREFIX,
                )
                rec.set_actual("；".join(
                    result.message for result in (exact, names) if result
                ))

            with rec.step(
                "编辑名称、类别和域名",
                f"将{RULE_NAME}编辑为{EDITED_NAME}，类别改为{EDIT_GROUP}并替换域名列表。",
                expected="记录ID保持不变；旧名称消失；新字段落库且新分类可展开两个域名。",
            ):
                before = bv.find_custom_domain_group(RULE_NAME)
                page.navigate_to_custom_domain_group()
                edited = page.edit_library(
                    RULE_NAME,
                    new_name=EDITED_NAME,
                    category=EDIT_CATEGORY,
                    site_type=EDIT_TYPE,
                    domains=EDIT_DOMAINS,
                )
                check("页面编辑成功", edited.get("success"), edited.get("error"))
                after = bv.find_custom_domain_group(EDITED_NAME)
                check(
                    "编辑保留记录ID",
                    before and after and int(before["id"]) == int(after["id"]),
                    {"before": before, "after": after},
                )
                verify(
                    "旧名称已消失",
                    bv.verify_custom_domain_group_not_exists,
                    RULE_NAME,
                )
                db = verify(
                    "编辑后数据库",
                    bv.verify_custom_domain_group_database,
                    EDITED_NAME,
                    group=EDIT_GROUP,
                    domains=EDIT_DOMAINS,
                )
                expanded = verify(
                    "编辑后分类展开",
                    bv.verify_custom_domain_group_resolution,
                    EDITED_NAME,
                )
                rec.set_actual("；".join(
                    result.message for result in (db, expanded) if result
                ))

            with rec.step(
                "系统网址查询、搜索与列能力",
                "查询系统库中的4399.com，再分别搜索存在/不存在名称并核对列表未提供排序控件。",
                expected="系统查询返回4399.com及其类别；存在搜索命中、不存在搜索为空；列表列与产品无排序能力的设计一致。",
            ):
                query_rows = page.query_system_urls("4399.com")
                check(
                    "系统网址查询命中",
                    any(row.get("domain") == "4399.com" for row in query_rows),
                    query_rows[:5],
                )
                check(
                    "系统网址查询返回类别",
                    any("休闲娱乐-游戏网站" in row.get("type", "") for row in query_rows),
                    query_rows[:5],
                )
                page.navigate_to_custom_domain_group()
                page.search_rule(EDITED_NAME)
                check("存在名称搜索命中", page.rule_exists(EDITED_NAME))
                page.search_rule("cdom_t_none")
                check(
                    "不存在名称搜索为空",
                    not page.rule_exists(EDITED_NAME) and page.get_rule_count() == 0,
                )
                page.clear_search()
                check(
                    "名称列未暴露排序控件",
                    page.page.locator("th#tagname .sortIcon").count() == 0,
                )
                rec.set_actual(
                    f"系统查询{len(query_rows)}条；存在/不存在搜索符合预期；页面无排序控件"
                )

            with rec.step(
                "CSV/TXT双格式导出",
                "分别导出CSV和TXT并结构化解析id、名称、组合类别及逗号分隔域名。",
                expected="两种格式各只有一条记录，四个字段与编辑后配置完全一致。",
            ):
                page.navigate_to_custom_domain_group()
                export_base = config.test_data.get_export_path(
                    "custom_domain_group", config.get_project_root()
                )
                csv_path = os.path.splitext(export_base)[0] + ".csv"
                txt_path = os.path.splitext(export_base)[0] + ".txt"
                check(
                    "CSV导出操作",
                    page.export_rules(use_config_path=True, export_format="csv"),
                    csv_path,
                )
                csv_row = _assert_custom_domain_export(csv_path)
                page.navigate_to_custom_domain_group()
                check(
                    "TXT导出操作",
                    page.export_rules(use_config_path=True, export_format="txt"),
                    txt_path,
                )
                txt_row = _assert_custom_domain_export(txt_path)
                check(
                    "CSV/TXT字段一致",
                    all(
                        csv_row.get(field) == txt_row.get(field)
                        for field in ("tagname", "name", "domains")
                    ),
                    {"csv": csv_row, "txt": txt_row},
                )
                rec.set_actual(f"CSV={csv_path}；TXT={txt_path}；结构化字段一致")

            with rec.step(
                "CSV追加导入",
                "删除导出目标，新增保留哨兵，再导入CSV且明确不清空现有数据。",
                expected="哨兵保留，导出目标恢复，两条记录均能通过DB和分类展开验证。",
            ):
                page.navigate_to_custom_domain_group()
                check("删除导入目标", page.delete_rule(EDITED_NAME))
                verify(
                    "导入准备目标已删除",
                    bv.verify_custom_domain_group_not_exists,
                    EDITED_NAME,
                )
                sentinel = page.add_rule(
                    SENTINEL_NAME,
                    INITIAL_CATEGORY,
                    INITIAL_TYPE,
                    SENTINEL_DOMAINS,
                )
                check("新增保留哨兵", sentinel.get("success"), sentinel.get("error"))
                page.navigate_to_custom_domain_group()
                check("CSV不清空导入", page.import_rules(csv_path, clear_existing=False))
                page.navigate_to_custom_domain_group()
                exact = verify(
                    "追加导入集合",
                    bv.verify_custom_domain_group_rule_set,
                    [EDITED_NAME, SENTINEL_NAME],
                )
                imported = verify(
                    "追加导入目标",
                    bv.verify_custom_domain_group_database,
                    EDITED_NAME,
                    group=EDIT_GROUP,
                    domains=EDIT_DOMAINS,
                )
                consistent = verify(
                    "追加导入分类展开",
                    bv.verify_custom_domain_group_consistency,
                    PREFIX,
                )
                rec.set_actual("；".join(
                    result.message for result in (exact, imported, consistent) if result
                ))

            with rec.step(
                "TXT清空导入",
                "即时复核全表只有两条测试记录后，导入TXT并明确清空现有数据。",
                expected="哨兵消失，只保留TXT中的编辑后记录，数据库及分类展开一致。",
            ):
                safety = verify(
                    "清空导入即时安全检查",
                    bv.verify_custom_domain_group_rule_set,
                    [EDITED_NAME, SENTINEL_NAME],
                )
                if safety is None or not safety.passed:
                    pytest.fail("清空导入前出现非测试记录，已拒绝执行")
                page.navigate_to_custom_domain_group()
                check("TXT清空导入", page.import_rules(txt_path, clear_existing=True))
                page.navigate_to_custom_domain_group()
                exact = verify(
                    "TXT导入集合",
                    bv.verify_custom_domain_group_rule_set,
                    [EDITED_NAME],
                )
                verify(
                    "哨兵已清除",
                    bv.verify_custom_domain_group_not_exists,
                    SENTINEL_NAME,
                )
                db = verify(
                    "TXT导入数据库",
                    bv.verify_custom_domain_group_database,
                    EDITED_NAME,
                    group=EDIT_GROUP,
                    domains=EDIT_DOMAINS,
                )
                expanded = verify(
                    "TXT导入分类展开",
                    bv.verify_custom_domain_group_resolution,
                    EDITED_NAME,
                )
                rec.set_actual("；".join(
                    result.message for result in (safety, exact, db, expanded) if result
                ))

            with rec.step(
                "批量删除与最终残留检查",
                "新增第二条测试记录，全选后执行批量删除；若产品未显示批量栏则逐条删除兜底。",
                expected="两条记录均从页面和custom_domain_group消失，分类展开不再返回测试域名。",
            ):
                second = page.add_rule(
                    SENTINEL_NAME,
                    INITIAL_CATEGORY,
                    INITIAL_TYPE,
                    SENTINEL_DOMAINS,
                )
                check("新增批量删除记录", second.get("success"), second.get("error"))
                page.navigate_to_custom_domain_group()
                selected = page.select_all_rules()
                check("全选两条记录", selected)
                page.batch_delete()
                page.page.wait_for_timeout(1200)
                page.navigate_to_custom_domain_group()
                for name in (EDITED_NAME, SENTINEL_NAME):
                    if bv.find_custom_domain_group(name):
                        page.delete_rule(name)
                        page.navigate_to_custom_domain_group()
                exact = verify(
                    "最终记录集合为空",
                    bv.verify_custom_domain_group_rule_set,
                    [],
                )
                target_absent = verify(
                    "编辑分类测试域名无残留",
                    bv.verify_custom_domain_group_category_domains,
                    EDIT_GROUP,
                    EDIT_DOMAINS,
                    expect_present=False,
                )
                sentinel_absent = verify(
                    "初始分类哨兵域名无残留",
                    bv.verify_custom_domain_group_category_domains,
                    INITIAL_GROUP,
                    SENTINEL_DOMAINS,
                    expect_present=False,
                )
                rec.set_actual("；".join(
                    result.message
                    for result in (exact, target_absent, sentinel_absent)
                    if result
                ))
        finally:
            try:
                cleanup = bv.cleanup_custom_domain_group_test(PREFIX)
                rec.add_detail(f"【清理结果】\n通过：{cleanup}")
            except Exception as exc:
                failures.append(f"兜底清理异常: {exc}")

        failures.extend(ssh_failures)
        if failures:
            pytest.fail("自定义网址库综合测试失败:\n" + "\n".join(failures))
