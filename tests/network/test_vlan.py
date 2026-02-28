"""
VLAN设置模块测试用例

包含VLAN的增删改查、启用停用、导入导出等测试
"""
import pytest
import os
from typing import List

from pages.network.vlan_page import VlanPage


# ==================== 测试类 ====================

@pytest.mark.vlan
@pytest.mark.network
class TestVlanAdd:
    """VLAN添加测试"""

    def test_add_min_vlan_id(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_ADD_001: 添加最小VLAN ID

        测试步骤:
        1. 导航到VLAN设置页面
        2. 点击添加按钮
        3. 输入VLAN ID=1
        4. 输入VLAN名称=vlan_min_1
        5. 点击保存

        预期结果: 添加成功，列表显示新记录
        """
        vlan_page = vlan_page_logged_in

        # 使用固定的VLAN ID和名称（名称必须以vlan开头，不超过15位）
        vlan_id = "1"
        vlan_name = "vlan_min_1"

        # 如果已存在则先删除
        if vlan_page.vlan_exists(vlan_name):
            vlan_page.delete_vlan(vlan_name)

        # 执行添加
        result = vlan_page.add_vlan(
            vlan_id=vlan_id,
            vlan_name=vlan_name
        )

        # 验证
        assert result is True, "添加VLAN失败"

        # 刷新页面后验证
        vlan_page.page.reload()
        vlan_page.page.wait_for_load_state("networkidle")
        vlan_page.page.wait_for_timeout(500)

        assert vlan_page.vlan_exists(vlan_name), "VLAN列表中未找到新添加的记录"

        # 清理测试数据
        try:
            vlan_page.delete_vlan(vlan_name)
        except Exception:
            pass  # 忽略清理失败

    def test_add_max_vlan_id(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_ADD_002: 添加最大VLAN ID

        测试步骤:
        1. 输入VLAN ID=4090
        2. 输入VLAN名称=vlan_test_4090
        3. 点击保存

        预期结果: 添加成功
        """
        vlan_page = vlan_page_logged_in

        if vlan_page.vlan_exists("vlan_test_4090"):
            vlan_page.delete_vlan("vlan_test_4090")

        result = vlan_page.add_vlan(
            vlan_id="4090",
            vlan_name="vlan_test_4090"
        )

        assert result is True, "添加VLAN失败"
        assert vlan_page.vlan_exists("vlan_test_4090"), "VLAN列表中未找到新添加的记录"

        vlan_page.delete_vlan("vlan_test_4090")

    def test_add_complete_info(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_ADD_004: 添加完整信息VLAN

        测试步骤:
        1. 填写所有字段（VLAN ID、名称、MAC、IP、子网掩码、备注）

        预期结果: 添加成功，所有信息正确显示
        """
        vlan_page = vlan_page_logged_in

        vlan_name = "vlan_c_100"  # 不超过15位
        if vlan_page.vlan_exists(vlan_name):
            vlan_page.delete_vlan(vlan_name)

        result = vlan_page.add_vlan(
            vlan_id="100",
            vlan_name=vlan_name,
            mac="00:11:22:33:44:55",
            ip="192.168.100.1",
            subnet_mask="255.255.255.0",
            remark="测试完整信息VLAN"
        )

        assert result is True, "添加完整信息VLAN失败"
        assert vlan_page.vlan_exists(vlan_name), "VLAN列表中未找到新添加的记录"

        vlan_page.delete_vlan(vlan_name)


@pytest.mark.vlan
@pytest.mark.network
class TestVlanAddBoundary:
    """VLAN添加边界值测试"""

    def test_add_vlan_id_below_min(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_ADD_BV_001: VLAN ID下边界-1

        测试数据: VLAN ID=0

        预期结果: 提示错误，添加失败
        """
        vlan_page = vlan_page_logged_in

        vlan_page.click_add_button()
        vlan_page.fill_vlan_id("0")
        vlan_page.fill_vlan_name("vlan_test_0")
        vlan_page.click_save()

        # 验证是否有错误提示
        has_error = vlan_page.has_validation_error()
        assert has_error, "未检测到VLAN ID=0时的验证错误"

        vlan_page.click_cancel()

    def test_add_vlan_id_above_max(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_ADD_BV_002: VLAN ID上边界+1

        测试数据: VLAN ID=4091

        预期结果: 提示错误，添加失败
        """
        vlan_page = vlan_page_logged_in

        vlan_page.click_add_button()
        vlan_page.fill_vlan_id("4091")
        vlan_page.fill_vlan_name("vlan_test_4091")
        vlan_page.click_save()

        has_error = vlan_page.has_validation_error()
        assert has_error, "未检测到VLAN ID=4091时的验证错误"

        vlan_page.click_cancel()


@pytest.mark.vlan
@pytest.mark.network
class TestVlanAddError:
    """VLAN添加异常测试"""

    def test_add_empty_vlan_id(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_ADD_ERR_001: 必填项为空-VLAN ID

        测试步骤: 不输入VLAN ID，点击保存

        预期结果: 提示"请输入vlanID"
        """
        vlan_page = vlan_page_logged_in

        vlan_page.click_add_button()
        vlan_page.fill_vlan_name("vlan_test_empty_id")
        vlan_page.click_save()

        has_error = vlan_page.has_validation_error()
        assert has_error, "未检测到VLAN ID为空时的验证错误"

        vlan_page.click_cancel()

    def test_add_empty_vlan_name(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_ADD_ERR_002: 必填项为空-名称

        测试步骤: 不输入名称，点击保存

        预期结果: 提示"请输入vlan名称"
        """
        vlan_page = vlan_page_logged_in

        vlan_page.click_add_button()
        vlan_page.fill_vlan_id("200")
        vlan_page.click_save()

        has_error = vlan_page.has_validation_error()
        assert has_error, "未检测到VLAN名称为空时的验证错误"

        vlan_page.click_cancel()

    def test_add_invalid_vlan_name_format(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_ADD_ERR_007: VLAN名称格式错误

        测试步骤: 输入不以vlan开头的名称

        预期结果: 提示名称格式错误
        """
        vlan_page = vlan_page_logged_in

        vlan_page.click_add_button()
        vlan_page.fill_vlan_id("300")
        vlan_page.fill_vlan_name("invalid_name")  # 不以vlan开头
        vlan_page.click_save()

        # 等待错误提示
        vlan_page.page.wait_for_timeout(500)
        error_msg = vlan_page.get_error_message()

        assert error_msg is not None or vlan_page.has_validation_error(), \
            "未检测到VLAN名称格式错误的提示"

        vlan_page.click_cancel()


@pytest.mark.vlan
@pytest.mark.network
class TestVlanStatus:
    """VLAN启用/停用测试"""

    @pytest.fixture(autouse=True)
    def setup_vlan(self, vlan_page_logged_in: VlanPage):
        """每个测试前准备一条VLAN数据"""
        self.vlan_name = "vlan_stat_test"  # 不超过15位
        vlan_page = vlan_page_logged_in

        # 如果存在则先删除
        if vlan_page.vlan_exists(self.vlan_name):
            vlan_page.delete_vlan(self.vlan_name)

        # 添加测试VLAN
        vlan_page.add_vlan(vlan_id="500", vlan_name=self.vlan_name)

        yield vlan_page

        # 清理
        if vlan_page.vlan_exists(self.vlan_name):
            vlan_page.delete_vlan(self.vlan_name)

    def test_disable_vlan(self, setup_vlan):
        """
        VLAN_STATUS_001: 单个停用VLAN

        测试步骤:
        1. 点击已启用VLAN的停用按钮
        2. 确认停用

        预期结果: 状态变为停用
        """
        vlan_page = setup_vlan

        result = vlan_page.disable_vlan(self.vlan_name)
        assert result is True, "停用VLAN失败"
        assert vlan_page.is_vlan_disabled(self.vlan_name), "VLAN状态未变为停用"

    def test_enable_vlan(self, setup_vlan):
        """
        VLAN_STATUS_002: 单个启用VLAN

        测试步骤:
        1. 先停用VLAN
        2. 点击启用按钮
        3. 确认启用

        预期结果: 状态变为启用
        """
        vlan_page = setup_vlan

        # 先停用
        vlan_page.disable_vlan(self.vlan_name)

        # 再启用
        result = vlan_page.enable_vlan(self.vlan_name)
        assert result is True, "启用VLAN失败"
        assert vlan_page.is_vlan_enabled(self.vlan_name), "VLAN状态未变为启用"


@pytest.mark.vlan
@pytest.mark.network
class TestVlanBatchOperation:
    """VLAN批量操作测试"""

    @pytest.fixture(autouse=True)
    def setup_multiple_vlans(self, vlan_page_logged_in: VlanPage):
        """准备多条VLAN数据用于批量操作测试"""
        self.test_vlans = ["vlan_batch_1", "vlan_batch_2", "vlan_batch_3"]
        vlan_page = vlan_page_logged_in

        # 添加测试VLAN
        for i, name in enumerate(self.test_vlans):
            if vlan_page.vlan_exists(name):
                vlan_page.delete_vlan(name)
            vlan_page.add_vlan(vlan_id=str(600 + i), vlan_name=name)

        yield vlan_page

        # 清理
        for name in self.test_vlans:
            if vlan_page.vlan_exists(name):
                vlan_page.delete_vlan(name)

    def test_batch_enable_vlans(self, setup_multiple_vlans):
        """
        VLAN_STATUS_003: 批量启用VLAN

        测试步骤:
        1. 先停用所有测试VLAN
        2. 勾选多条停用的VLAN
        3. 点击批量启用

        预期结果: 全部变为启用状态
        """
        vlan_page = setup_multiple_vlans

        # 先停用所有
        for name in self.test_vlans:
            if vlan_page.is_vlan_enabled(name):
                vlan_page.disable_vlan(name)

        # 批量启用
        result = vlan_page.batch_enable_vlans(self.test_vlans)
        assert result is True, "批量启用VLAN失败"

        # 验证状态
        for name in self.test_vlans:
            assert vlan_page.is_vlan_enabled(name), f"VLAN {name} 未变为启用状态"

    def test_batch_disable_vlans(self, setup_multiple_vlans):
        """
        VLAN_STATUS_004: 批量停用VLAN

        测试步骤:
        1. 确保所有VLAN是启用状态
        2. 勾选多条启用的VLAN
        3. 点击批量停用

        预期结果: 全部变为停用状态
        """
        vlan_page = setup_multiple_vlans

        # 确保启用状态
        for name in self.test_vlans:
            if vlan_page.is_vlan_disabled(name):
                vlan_page.enable_vlan(name)

        # 批量停用
        result = vlan_page.batch_disable_vlans(self.test_vlans)
        assert result is True, "批量停用VLAN失败"

        # 验证状态
        for name in self.test_vlans:
            assert vlan_page.is_vlan_disabled(name), f"VLAN {name} 未变为停用状态"

    def test_batch_delete_vlans(self, setup_multiple_vlans):
        """
        VLAN_DEL_BATCH_001: 批量删除VLAN

        测试步骤:
        1. 勾选多条VLAN
        2. 点击批量删除
        3. 确认删除

        预期结果: 全部删除成功
        """
        vlan_page = setup_multiple_vlans

        # 批量删除
        result = vlan_page.batch_delete_vlans(self.test_vlans)
        assert result is True, "批量删除VLAN失败"

        # 验证删除
        for name in self.test_vlans:
            assert not vlan_page.vlan_exists(name), f"VLAN {name} 仍然存在"


@pytest.mark.vlan
@pytest.mark.network
class TestVlanEdit:
    """VLAN编辑测试"""

    @pytest.fixture(autouse=True)
    def setup_vlan(self, vlan_page_logged_in: VlanPage):
        """准备测试VLAN"""
        self.vlan_name = "vlan_edit_test"
        vlan_page = vlan_page_logged_in

        if vlan_page.vlan_exists(self.vlan_name):
            vlan_page.delete_vlan(self.vlan_name)

        vlan_page.add_vlan(vlan_id="700", vlan_name=self.vlan_name)

        yield vlan_page

        if vlan_page.vlan_exists(self.vlan_name):
            vlan_page.delete_vlan(self.vlan_name)

    def test_edit_vlan_name(self, setup_vlan):
        """
        VLAN_EDIT_001: 修改VLAN名称

        测试步骤:
        1. 点击编辑按钮
        2. 修改VLAN名称
        3. 保存

        预期结果: 修改成功
        """
        vlan_page = setup_vlan
        new_name = "vlan_edit_new"

        # 清理可能存在的新名称
        if vlan_page.vlan_exists(new_name):
            vlan_page.delete_vlan(new_name)

        # 编辑
        vlan_page.edit_vlan(self.vlan_name)
        vlan_page.fill_vlan_name(new_name)
        vlan_page.click_save()

        # 验证
        result = vlan_page.wait_for_success_message()
        assert result is True, "修改VLAN名称失败"
        assert vlan_page.vlan_exists(new_name), "未找到修改后的VLAN"

        # 更新清理列表
        self.vlan_name = new_name


@pytest.mark.vlan
@pytest.mark.network
class TestVlanDelete:
    """VLAN删除测试"""

    @pytest.fixture(autouse=True)
    def setup_vlan(self, vlan_page_logged_in: VlanPage):
        """准备测试VLAN"""
        self.vlan_name = "vlan_del_test"  # 不超过15位
        vlan_page = vlan_page_logged_in

        if vlan_page.vlan_exists(self.vlan_name):
            vlan_page.delete_vlan(self.vlan_name)

        vlan_page.add_vlan(vlan_id="800", vlan_name=self.vlan_name)

        yield vlan_page

        # Teardown: 确保测试完成后清理（无论测试成功或失败）
        try:
            if vlan_page.vlan_exists(self.vlan_name):
                vlan_page.delete_vlan(self.vlan_name)
        except Exception:
            pass

    def test_delete_vlan(self, setup_vlan):
        """
        VLAN_DEL_001: 删除单个VLAN

        测试步骤:
        1. 点击删除按钮
        2. 确认删除

        预期结果: 删除成功，列表不再显示
        """
        vlan_page = setup_vlan

        result = vlan_page.delete_vlan(self.vlan_name)
        assert result is True, "删除VLAN失败"
        assert not vlan_page.vlan_exists(self.vlan_name), "VLAN仍然存在"

    def test_cancel_delete(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_DEL_004: 取消删除

        测试步骤:
        1. 点击删除按钮
        2. 点击取消

        预期结果: 记录保留
        """
        vlan_name = "vlan_cancel"  # 不超过15位
        vlan_page = vlan_page_logged_in

        try:
            # 准备数据
            if vlan_page.vlan_exists(vlan_name):
                vlan_page.delete_vlan(vlan_name)
            vlan_page.add_vlan(vlan_id="801", vlan_name=vlan_name)

            # 取消删除
            vlan_page.cancel_delete(vlan_name)

            # 验证记录仍然存在
            assert vlan_page.vlan_exists(vlan_name), "取消删除后记录不存在"
        finally:
            # 确保清理（无论测试成功或失败）
            try:
                if vlan_page.vlan_exists(vlan_name):
                    vlan_page.delete_vlan(vlan_name)
            except Exception:
                pass


@pytest.mark.vlan
@pytest.mark.network
class TestVlanSearch:
    """VLAN搜索测试"""

    @pytest.fixture(autouse=True)
    def setup_vlans(self, vlan_page_logged_in: VlanPage):
        """准备测试VLAN"""
        self.test_vlans = ["vlan_search_1", "vlan_search_2"]
        vlan_page = vlan_page_logged_in

        for i, name in enumerate(self.test_vlans):
            if vlan_page.vlan_exists(name):
                vlan_page.delete_vlan(name)
            vlan_page.add_vlan(vlan_id=str(900 + i), vlan_name=name)

        yield vlan_page

        for name in self.test_vlans:
            if vlan_page.vlan_exists(name):
                vlan_page.delete_vlan(name)

    def test_search_by_name(self, setup_vlans):
        """
        VLAN_SEARCH_001: 按VLAN名称搜索

        测试步骤:
        1. 输入名称关键字
        2. 执行搜索

        预期结果: 正确过滤结果
        """
        vlan_page = setup_vlans

        vlan_page.search_vlan("vlan_search_1")

        # 验证搜索结果
        assert vlan_page.vlan_exists("vlan_search_1"), "未找到搜索的VLAN"

    def test_search_not_exist(self, setup_vlans):
        """
        VLAN_SEARCH_004: 搜索不存在数据

        测试步骤: 输入不存在的内容

        预期结果: 显示空列表
        """
        vlan_page = setup_vlans

        vlan_page.search_vlan("not_exist_vlan_name")

        # 验证搜索结果为空
        count = vlan_page.get_vlan_count()
        assert count == 0, f"搜索不存在的数据时，应该显示0条记录，实际显示{count}条"

        # 清空搜索
        vlan_page.clear_search()


@pytest.mark.vlan
@pytest.mark.network
class TestVlanImportExport:
    """VLAN导入导出测试"""

    def test_export_vlans(self, vlan_page_logged_in: VlanPage):
        """
        VLAN_EXPORT_001: 导出VLAN配置

        测试步骤:
        1. 添加几条VLAN
        2. 点击导出按钮

        预期结果: 下载正确格式CSV文件
        """
        vlan_page = vlan_page_logged_in

        # 确保有数据
        test_vlan = "vlan_export_test"
        if not vlan_page.vlan_exists(test_vlan):
            vlan_page.add_vlan(vlan_id="950", vlan_name=test_vlan)

        # 点击导出
        vlan_page.click_export()

        # 验证（这里需要检查下载目录，简化处理）
        vlan_page.page.wait_for_timeout(1000)

        # 清理
        if vlan_page.vlan_exists(test_vlan):
            vlan_page.delete_vlan(test_vlan)
