"""设备设置 > 云服务绑定 Page Object。

实机页面位于 ``/#/equipmentSetting/cloudServiceBinding``，后端为
``/usr/ikuai/script/register.sh``，前端通过 ``/Action/call`` 调用
``func_name=register`` 的 ``show/save/request_scode/disable_scode/cloud_async`` 动作。

三种绑定方式(绑定方式 combobox ``#bindWay``):
  - 验证码(默认): 手机号 ``#mobile`` + 短信验证码(placeholder=请输入验证码, 无id) +
                  获取验证码按钮 + 备注 ``#comment``
  - 二维码: ``.ant-qrcode canvas`` + "有效时间 N 秒"倒计时(无保存, 扫码绑定)
  - 绑定码: 绑定码 ``#code`` + 备注 ``#comment`` + 一键跳转云平台
公共字段: 节点服务器 ``#node``(中国/新加坡) + 路由ID ``#gwid``(disabled=GWID)。

绑定成功(save, account_code=绑定码)后写 config.db register 表(id/node/code/comment)
+ /tmp/iktmp/register_status=1，页面切换到"已绑定"状态(显示设备信息 + 获取服务码/
在线客服/结束服务/解绑 等入口)。

节点服务器: node(0中国/1·2海外)->/tmp/iktmp/cache/cloud_node->update_hosts.sh 动态下发
/tmp/iktmp/ik_hosts/register 域名(中国=yun.ikuai8.com); 真实切换只在 save 绑定时生效。

⚠ 已绑定状态 UI(服务码/在线客服/结束服务/解绑)的选择器在首次绑定后实测完善，
   方法用通用按钮文本定位，实跑时按实际 DOM 调整。
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Optional

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage


class CloudServiceBindingPage(BasePage):
    """iKuai 4.0 设备设置-云服务绑定页面。"""

    MODULE_NAME = "cloud_service_binding"
    FUNC_NAME = "register"
    PAGE_URL = "/#/equipmentSetting/cloudServiceBinding"
    BACKEND_SCRIPT = "/usr/ikuai/script/register.sh"

    BIND_WAYS = ("验证码", "二维码", "绑定码")
    NODES = ("中国", "新加坡")

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = base_url.rstrip("/")
        self.last_save_result: Dict[str, Any] = {}

    # ==================== 导航 ====================

    def navigate_to_cloud_service_binding(self, timeout: int = 15000) -> bool:
        try:
            self.page.goto(f"{self.base_url}{self.PAGE_URL}", wait_until="domcontentloaded")
            self._wait_binding_page_ready(timeout)
            return self.is_on_binding_page()
        except Exception as e:
            print(f"[navigate_cloud_service_binding] 异常: {type(e).__name__}: {str(e)[:120]}")
            return False

    def _wait_binding_page_ready(self, timeout: int = 15000) -> None:
        """等绑定页主内容渲染(兼容未绑定态 #bindWay 与已绑定态绑定信息)。"""
        try:
            self.page.locator("text=云管理平台绑定").first.wait_for(state="visible", timeout=timeout)
        except Exception:
            pass
        self.page.wait_for_timeout(500)

    navigate_to_cloud_service = navigate_to_cloud_service_binding

    def is_on_binding_page(self) -> bool:
        try:
            if "equipmentSetting/cloudServiceBinding" not in self.page.url:
                return False
            body = self.page.locator("main").inner_text(timeout=3000)
            return "云管理平台绑定" in body
        except Exception:
            return False

    def reload_binding_page(self, timeout: int = 15000) -> bool:
        """reload 页面(触发前端 show -> register 异步 check_bind, 解绑后让设备感知)。"""
        try:
            self.page.reload(wait_until="domcontentloaded")
            self._wait_binding_page_ready(timeout)
            return True
        except Exception:
            return False

    # ==================== 公共字段 ====================

    def read_gwid(self) -> str:
        """读取路由ID(=GWID, #gwid disabled 输入框的值)。"""
        try:
            el = self.page.locator("#gwid")
            if el.count() > 0:
                return (el.first.input_value() or "").strip()
        except Exception:
            pass
        return ""

    def _select_combobox(self, input_id: str, value: str, timeout: int = 5000) -> bool:
        """Ant Select 选值: 点开 #input_id 下拉 -> 点 title=value 选项(原生 click, 非 JS)."""
        try:
            selector = self.page.locator(f".ant-select:has(#{input_id}) .ant-select-selector")
            selector.first.click()
            self.page.wait_for_timeout(250)
            opt = self.page.locator(f".ant-select-item-option[title='{value}']")
            opt.first.wait_for(state="visible", timeout=timeout)
            opt.first.click()
            self.page.wait_for_timeout(250)
            item = self.page.locator(f".ant-select:has(#{input_id}) .ant-select-selection-item")
            return item.count() > 0 and (item.first.inner_text() or "").strip() == value
        except Exception:
            return False

    def select_bind_way(self, way: str) -> bool:
        """选择绑定方式: 验证码/二维码/绑定码。切换后等对应特征元素渲染完成。"""
        if way not in self.BIND_WAYS:
            return False
        ok = self._select_combobox("bindWay", way)
        if ok:
            self._wait_for_bind_way_ready(way)
        return ok

    def _wait_for_bind_way_ready(self, way: str, timeout: int = 6000) -> None:
        """切换绑定方式后, 等对应方式特征元素渲染完成(SPA 异步, 避免 fill 扑空)。"""
        try:
            if way == "绑定码":
                self.page.locator("#code").first.wait_for(state="visible", timeout=timeout)
            elif way == "验证码":
                self.page.locator("#mobile").first.wait_for(state="visible", timeout=timeout)
            elif way == "二维码":
                self.page.locator(".ant-qrcode canvas").first.wait_for(state="visible", timeout=timeout)
        except Exception:
            pass
        self.page.wait_for_timeout(200)

    def select_node(self, node: str) -> bool:
        """选择节点服务器: 中国/新加坡。"""
        if node not in self.NODES:
            return False
        return self._select_combobox("node", node)

    def get_bind_way(self) -> str:
        try:
            item = self.page.locator(".ant-select:has(#bindWay) .ant-select-selection-item")
            return (item.first.inner_text() or "").strip() if item.count() else ""
        except Exception:
            return ""

    def get_node(self) -> str:
        try:
            item = self.page.locator(".ant-select:has(#node) .ant-select-selection-item")
            return (item.first.inner_text() or "").strip() if item.count() else ""
        except Exception:
            return ""

    # ==================== 表单填写 ====================

    def _react_set(self, input_id: str, val) -> None:
        el = self.page.locator(f"#{input_id}")
        if el.count() == 0:
            return
        el.evaluate(
            "(el, val) => { const p = el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;"
            "Object.getOwnPropertyDescriptor(p,'value').set.call(el, val);"
            "el.dispatchEvent(new Event('input',{bubbles:true}));"
            "el.dispatchEvent(new Event('change',{bubbles:true}));"
            "el.dispatchEvent(new Event('blur',{bubbles:true})); }",
            str(val),
        )

    def _react_set_placeholder(self, placeholder: str, val) -> None:
        el = self.page.locator(f"input[placeholder='{placeholder}']")
        if el.count() == 0:
            return
        el.first.evaluate(
            "(el, val) => { const p = HTMLInputElement.prototype;"
            "Object.getOwnPropertyDescriptor(p,'value').set.call(el, val);"
            "el.dispatchEvent(new Event('input',{bubbles:true}));"
            "el.dispatchEvent(new Event('change',{bubbles:true}));"
            "el.dispatchEvent(new Event('blur',{bubbles:true})); }",
            str(val),
        )

    def fill_mobile(self, mobile: str) -> None:
        self._react_set("mobile", mobile)

    def fill_bind_code(self, code: str) -> None:
        self._react_set("code", code)

    def fill_comment(self, comment: str) -> None:
        self._react_set("comment", comment)

    def fill_sms_code(self, sms_code: str) -> None:
        """填短信验证码(验证码框无 id, 用 placeholder=请输入验证码 锚点)。"""
        self._react_set_placeholder("请输入验证码", sms_code)

    def get_bind_code_value(self) -> str:
        try:
            el = self.page.locator("#code")
            return (el.first.input_value() or "").strip() if el.count() else ""
        except Exception:
            return ""

    # ==================== 按钮 ====================

    def _button(self, text: str) -> Locator:
        return self.page.locator("button:visible").filter(
            has_text=re.compile(rf"^\s*{re.escape(text)}\s*$")
        ).first

    def click_save(self) -> bool:
        try:
            btn = self._button("保存")
            if btn.count() == 0:
                return False
            btn.click()
            return True
        except Exception:
            return False

    def click_help(self) -> bool:
        try:
            btn = self._button("帮助")
            if btn.count() == 0:
                return False
            btn.click()
            return True
        except Exception:
            return False

    def is_get_sms_code_enabled(self) -> bool:
        """获取验证码按钮是否可用(未填手机号时 disabled)。"""
        try:
            btn = self.page.locator("button:has-text('获取验证码'):visible").first
            if btn.count() == 0:
                return False
            return btn.is_enabled()
        except Exception:
            return False

    def click_get_sms_code(self) -> bool:
        try:
            btn = self.page.locator("button:has-text('获取验证码'):visible").first
            if btn.count() == 0:
                return False
            btn.click()
            return True
        except Exception:
            return False

    # ==================== API 监听(保存/绑定结果判定) ====================

    def _get_validation_errors(self) -> Dict[str, str]:
        errors: Dict[str, str] = {}
        try:
            for item in self.page.locator(".ant-form-item-explain-error:visible").all():
                txt = (item.inner_text() or "").strip()
                if txt:
                    errors[txt] = txt
        except Exception:
            pass
        return errors

    def _get_error_toast(self) -> str:
        for sel in (".ant-message-error:visible", ".ant-notification-error:visible"):
            try:
                el = self.page.locator(sel)
                if el.count() > 0:
                    return (el.first.inner_text() or "").strip()
            except Exception:
                pass
        return ""

    def save_and_observe(self, actions=("save", "bind_update"), timeout: int = 20000) -> Dict[str, Any]:
        """点保存并用 expect_response 等 register 响应，判定绑定/换绑结果。

        Args:
            actions: 视为保存类请求的 action 集合(save=绑定码绑定, bind_update=验证码换绑)。
            timeout: 等待响应超时(ms)。
        Returns:
            {clicked, request_seen, response_seen, http_status, api_code, api_success,
             message, validation_errors, error_toast, success_ui}
        """
        result: Dict[str, Any] = {
            "clicked": False, "request_seen": False, "response_seen": False,
            "http_status": None, "api_code": None, "api_success": False,
            "message": "", "validation_errors": {}, "error_toast": "", "success_ui": False,
        }
        actions_set = set(actions)
        func_name = self.FUNC_NAME

        def _is_save_response(resp):
            try:
                payload = json.loads(resp.request.post_data or "{}")
            except Exception:
                return False
            return (str(payload.get("func_name")) == func_name
                    and str(payload.get("action")) in actions_set)

        try:
            btn = self._button("保存")
            if btn.count() == 0:
                result["message"] = "未找到保存按钮(当前绑定方式可能无保存, 如二维码)"
                return result
            try:
                with self.page.expect_response(_is_save_response, timeout=timeout) as resp_info:
                    btn.click()
                    result["clicked"] = True
                resp = resp_info.value
                result["request_seen"] = True
                result["response_seen"] = True
                result["http_status"] = resp.status
                try:
                    body = resp.json()
                except Exception:
                    body = {}
                result["api_code"] = body.get("code")
                result["message"] = str(body.get("message") or body.get("errmsg") or "")[:200]
                result["api_success"] = bool(resp.status == 200 and body.get("code") == 0)
            except Exception as e:
                # 超时(无匹配 save 响应): 可能前端校验拦截不发请求, 或请求未到达
                if not result["message"]:
                    result["message"] = f"等待响应超时/异常({type(e).__name__})"
        except Exception as exc:
            result["message"] = f"保存异常({type(exc).__name__}): {str(exc)[:120]}"
        finally:
            try:
                result["validation_errors"] = self._get_validation_errors()
                result["error_toast"] = self._get_error_toast()
                ok_toast = self.page.locator(".ant-message-success:visible, .ant-message-notice:visible")
                result["success_ui"] = ok_toast.count() > 0
            except Exception:
                pass
            self.last_save_result = dict(result)
        return result

    # ==================== 二维码 ====================

    def read_qrcode_present(self) -> bool:
        """二维码方式: .ant-qrcode canvas 是否存在(二维码已弹出)。"""
        try:
            return self.page.locator(".ant-qrcode canvas").count() > 0
        except Exception:
            return False

    def read_qrcode_validity(self) -> int:
        """二维码方式: 解析"有效时间 N 秒"倒计时数字, 返回秒数(0=未找到/已过期)。"""
        try:
            body = self.page.locator("main").inner_text(timeout=3000)
            m = re.search(r"有效时间\s*0*(\d+)\s*秒", body)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return 0

    # ==================== 高层操作 ====================

    def bind_via_code(self, code: str, comment: str = "") -> Dict[str, Any]:
        """绑定码方式绑定: 选绑定码 -> 填绑定码+备注 -> 保存 -> 观察响应。"""
        self.select_bind_way("绑定码")
        self.fill_bind_code(code)
        if comment:
            self.fill_comment(comment)
        return self.save_and_observe(actions=("save",))

    def is_bound(self) -> bool:
        """判断当前是否已绑定。未绑定态保留 #bindWay 绑定方式选择; 已绑定态切换为
        已绑定信息展示(不再有绑定方式选择)。实跑时按实际 DOM 校准。"""
        try:
            if self.page.locator("#bindWay").count() > 0:
                return False
            return True
        except Exception:
            return False

    # ==================== 已绑定状态操作(首次绑定后实测完善选择器) ====================

    def click_bound_button(self, text: str, timeout: int = 4000) -> bool:
        """点击已绑定状态下的按钮(获取服务码/在线客服/结束服务/解绑 等), 通用文本定位。"""
        try:
            btn = self.page.locator(f"button:has-text('{text}'):visible").first
            btn.wait_for(state="visible", timeout=timeout)
            btn.click()
            return True
        except Exception:
            return False

    def request_server_code(self) -> bool:
        """点'获取服务码'(调 register request_scode, 异步)。实跑时按实际按钮文本调整。"""
        return self.click_bound_button("获取服务码")

    def disable_server_code(self) -> bool:
        """点'结束服务'(调 register disable_scode)。实跑时按实际按钮文本调整。"""
        return self.click_bound_button("结束服务")

    def click_online_service(self) -> bool:
        """点'在线客服'。实跑时按实际元素调整(可能是链接/按钮/新标签)。"""
        return self.click_bound_button("在线客服")


__all__ = ["CloudServiceBindingPage"]
