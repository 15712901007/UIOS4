"""虚拟专网 -> IPsec VPN 新版页面对象。

实机入口为 ``/#/vpn/ipsecVpn``。页面由三个页签组成：隧道策略、IKE提议、
隧道信息。后端分别由 ``ipsec2_policy``、``ipsec2_proposal`` 和
``ipsec2_tunnel`` 分派，不再复用旧版 VPN 客户端 ``ipsec_vpn`` 页面。
"""
from __future__ import annotations

import unicodedata
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from playwright.sync_api import Locator, Page

from pages.ikuai_table_page import IkuaiTablePage
from utils.step_recorder import register_sensitive_value


class IpsecVpnPage(IkuaiTablePage):
    """新版 IPsec VPN 页面、表单和真实 API 语义封装。"""

    MODULE_NAME = "ipsec2"
    LIST_URL = "/#/vpn/ipsecVpn"
    TABS = {
        "policy": "隧道策略",
        "proposal": "IKE提议",
        "tunnel": "隧道信息",
    }
    POLICY_SECTIONS = {
        "basic": "基础设置",
        "ike": "IKE策略",
        "traffic": "保护数据流",
        "advanced": "高级配置",
    }
    POLICY_COLUMNS = (
        "策略名称", "设备角色", "IP地址类型", "应用策略接口",
        "本端IP地址", "对端IP地址/主机名", "别名", "操作",
    )
    PROPOSAL_COLUMNS = (
        "名称", "认证算法", "加密算法", "DH", "IKE SA生存周期", "操作",
    )
    TUNNEL_COLUMNS = (
        "本端地址", "对端地址", "安全协议", "受保护数据流", "接口",
        "网络类型", "别名", "状态", "操作",
    )
    SECRET_FIELDS = {
        "secret", "password", "passwd", "psk", "privatekey", "private_key",
        "certificate_private_key", "token", "cookie",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)
        self._runtime_secrets: set[str] = set()
        self._last_protected_traffic_errors: List[str] = []

    @staticmethod
    def _visible_unique_text(locator: Locator) -> List[str]:
        values: List[str] = []
        for index in range(locator.count()):
            item = locator.nth(index)
            try:
                if not item.is_visible():
                    continue
                text = " ".join((item.inner_text() or "").split())
            except Exception:
                continue
            if text and text not in values:
                values.append(text)
        return values

    @staticmethod
    def _dom_click(locator: Locator):
        locator.evaluate(
            "element => { element.scrollIntoView({block: 'center'}); element.click(); }"
        )

    @staticmethod
    def _replace_input(locator: Locator, value: Any):
        locator.fill(str(value), force=True)

    def _dismiss_overlays(self) -> bool:
        """Best-effort close modal/drawer state left by an interrupted step."""
        try:
            self.page.keyboard.press("Escape")
        except Exception:
            pass

        for _ in range(4):
            changed = False
            for selector in (
                ".ant-modal:visible .ant-modal-close",
                ".ant-modal:not(.ant-modal-confirm):visible "
                "button:has-text('取消')",
                ".ant-drawer:visible .ant-drawer-close",
            ):
                locator = self.page.locator(selector)
                if not locator.count():
                    continue
                try:
                    locator.last.click(force=True, timeout=800)
                    changed = True
                    self.page.wait_for_timeout(120)
                except Exception:
                    continue

            # Closing a dirty policy drawer opens a discard confirmation.
            confirm = self.page.locator(".ant-modal-confirm:visible")
            if confirm.count():
                button = confirm.last.get_by_role(
                    "button", name="确定", exact=True
                )
                try:
                    button.click(force=True, timeout=800)
                    changed = True
                    self.page.wait_for_timeout(120)
                except Exception:
                    pass
            if not changed:
                break

        return not self.page.locator(
            ".ant-modal:visible,.ant-drawer:visible"
        ).count()

    @staticmethod
    def _response_matches(response, func_name: str, action: str) -> bool:
        if urlsplit(response.url).path != "/Action/call":
            return False
        try:
            payload = response.request.post_data_json
        except Exception:
            return False
        return (
            isinstance(payload, dict)
            and payload.get("func_name") == func_name
            and payload.get("action") == action
        )

    def navigate_to_ipsec(self):
        self._dismiss_overlays()
        target = f"{self.base_url}{self.LIST_URL}"
        try:
            with self.page.expect_response(
                lambda response: self._response_matches(
                    response, "ipsec2_policy", "show"
                ),
                timeout=15000,
            ):
                if self.page.url.rstrip("/") == target.rstrip("/"):
                    self.page.reload()
                else:
                    self.page.goto(target)
        except Exception:
            if self.page.url.rstrip("/") == target.rstrip("/"):
                self.page.reload()
            else:
                self.page.goto(target)
        self.page.wait_for_load_state("domcontentloaded")
        self.page.locator(".ant-tabs-tab:visible").first.wait_for(
            state="visible", timeout=15000
        )
        self.select_tab("policy")
        self.page.locator(
            ".ant-table-tbody .ant-table-row,.ant-table-placeholder"
        ).first.wait_for(state="visible", timeout=15000)
        return self

    def select_tab(self, tab: str) -> bool:
        label = self.TABS.get(tab, tab)
        tabs = self.page.locator(".ant-tabs-tab:visible")
        for index in range(tabs.count()):
            item = tabs.nth(index)
            if " ".join((item.inner_text() or "").split()) == label:
                self._dom_click(item)
                self.page.wait_for_timeout(400)
                return True
        return False

    def page_structure(self, tab: str = "policy") -> Dict[str, Any]:
        self.select_tab(tab)
        headers = self._visible_unique_text(
            self.page.locator(".ant-table-thead .ant-table-cell:visible")
        )
        buttons = self._visible_unique_text(self.page.locator("button:visible"))
        rows = self.page.locator(".ant-table-tbody .ant-table-row:visible")
        return {
            "url": self.page.url,
            "title": self.page.title(),
            "tab": self.TABS.get(tab, tab),
            "headers": headers,
            "buttons": buttons,
            "row_count": rows.count(),
            "empty": rows.count() == 0 and self.page.locator(
                ".ant-table-placeholder:visible"
            ).count() > 0,
            "pagination": self.page.locator(".ant-pagination:visible").count() > 0,
            "search": self.page.locator("input[type=search]:visible").count() > 0,
            "column_settings": self.page.locator(
                "button.filterIcon:visible,.ant-table-column-sorters:visible"
            ).count() > 0,
        }

    def capability_matrix(self) -> Dict[str, bool]:
        policy = self.page_structure("policy")
        proposal = self.page_structure("proposal")
        tunnel = self.page_structure("tunnel")
        self.select_tab("policy")
        all_buttons = set(policy["buttons"] + proposal["buttons"] + tunnel["buttons"])
        return {
            "policy_create": "新建" in policy["buttons"],
            "proposal_create": "新建" in proposal["buttons"],
            "tunnel_auto_refresh": "自动刷新" in tunnel["buttons"],
            "search": any(x["search"] for x in (policy, proposal, tunnel)),
            "pagination": any(x["pagination"] for x in (policy, proposal, tunnel)),
            "import": "导入" in all_buttons,
            "export": "导出" in all_buttons,
            "batch": self.page.locator(
                ".ant-table-selection-column:visible,.batch-operation:visible"
            ).count() > 0,
            "explicit_help_button": "帮助" in all_buttons,
        }

    def api_call(self, func_name: str, action: str,
                 params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = {
            "func_name": func_name,
            "action": action,
            "param": dict(params or {}),
        }
        response = self.page.evaluate(
            """async payload => {
                const result = await fetch('/Action/call', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    credentials: 'same-origin',
                    body: JSON.stringify(payload),
                });
                let body = {};
                try { body = await result.json(); } catch (_) {}
                return {
                    http_status: result.status,
                    code: body.code,
                    message: String(body.message || '').slice(0, 240),
                    result_keys: body.results && typeof body.results === 'object'
                        ? Object.keys(body.results).sort() : [],
                };
            }""",
            payload,
        )
        response.update({
            "endpoint": "/Action/call",
            "method": "POST",
            "func_name": func_name,
            "action": action,
            "parameter_fields": sorted((params or {}).keys()),
            "success": response.get("http_status") == 200 and response.get("code") == 0,
        })
        return response

    def resolve_remote_address(
        self, remote_addr: str, interface: str = "auto"
    ) -> Dict[str, Any]:
        """Call the same address-check endpoint used by the policy form."""
        result = self.page.evaluate(
            """async args => {
                const response = await fetch('/Action/call', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    credentials: 'same-origin',
                    body: JSON.stringify({
                        func_name: 'ipsec2_policy',
                        action: 'show',
                        param: {
                            TYPE: 'resolve_check',
                            remote_addr: args.remote_addr,
                            iface: args.interface,
                        },
                    }),
                });
                let body = {};
                try { body = await response.json(); } catch (_) {}
                const results = body && typeof body.results === 'object'
                    ? body.results : {};
                return {
                    http_status: response.status,
                    code: body.code,
                    message: String(body.message || '').slice(0, 240),
                    resolved_status: results.status,
                    result_keys: Object.keys(results).sort(),
                };
            }""",
            {"remote_addr": str(remote_addr), "interface": str(interface)},
        )
        result.update({
            "endpoint": "/Action/call",
            "func_name": "ipsec2_policy",
            "action": "show",
            "type": "resolve_check",
            "remote_addr": str(remote_addr),
            "interface": str(interface),
            "success": (
                result.get("http_status") == 200
                and result.get("code") in (0, "0", None)
            ),
        })
        return result

    @classmethod
    def _safe_parameter_semantics(cls, value: Any, field: str = "") -> Any:
        normalized = field.lower().replace("-", "_")
        if normalized in cls.SECRET_FIELDS or any(
            token in normalized
            for token in ("password", "passwd", "secret", "psk", "private_key")
        ):
            rendered = "" if value is None else str(value)
            return {"configured": bool(rendered), "length": len(rendered)}
        if isinstance(value, dict):
            return {
                str(key): cls._safe_parameter_semantics(item, str(key))
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._safe_parameter_semantics(item, field) for item in value]
        if isinstance(value, str):
            return value[:180]
        return value

    @staticmethod
    def _safe_response(response) -> Dict[str, Any]:
        result: Dict[str, Any] = {"http_status": response.status}
        try:
            payload = response.json()
        except Exception:
            return result
        if not isinstance(payload, dict):
            return result
        for key in ("code", "success", "Result", "ErrCode", "errno"):
            value = payload.get(key)
            if isinstance(value, (str, int, float, bool)) or value is None:
                result[key] = value
        for key in ("message", "msg", "ErrMsg", "error"):
            value = payload.get(key)
            if isinstance(value, str):
                result[key] = value[:240]
        results = payload.get("results")
        if isinstance(results, dict):
            result["result_keys"] = sorted(results.keys())
            for key in ("id", "total", "list_total"):
                value = results.get(key)
                if isinstance(value, (str, int, float, bool)) or value is None:
                    result[key] = value
        return result

    def _submit(self, button: Locator, func_name: str, action: str,
                timeout: int = 15000) -> Dict[str, Any]:
        try:
            with self.page.expect_response(
                lambda response: self._response_matches(response, func_name, action),
                timeout=timeout,
            ) as info:
                self._dom_click(button)
            result = self._safe_response(info.value)
            try:
                request_payload = info.value.request.post_data_json
            except Exception:
                request_payload = {}
            params = (
                request_payload.get("param", {})
                if isinstance(request_payload, dict) else {}
            )
            result.update({
                "endpoint": urlsplit(info.value.url).path,
                "method": info.value.request.method,
                "func_name": request_payload.get("func_name")
                if isinstance(request_payload, dict) else None,
                "action": request_payload.get("action")
                if isinstance(request_payload, dict) else None,
                "parameter_fields": sorted(params.keys())
                if isinstance(params, dict) else [],
                "parameter_semantics": self._safe_parameter_semantics(params),
            })
        except Exception as exc:
            return {
                "success": False,
                "error": type(exc).__name__,
                "form_errors": self.form_errors(),
            }
        self.page.wait_for_timeout(150)
        errors = self.form_errors()
        code = result.get("code", result.get("Result"))
        result["success"] = (
            result.get("http_status") == 200
            and code in (0, "0", None)
            and result.get("success") is not False
            and not errors
        )
        result["form_errors"] = errors
        return result

    def _policy_drawer(self) -> Locator:
        drawer = self.page.locator(".ant-drawer:visible").last
        drawer.wait_for(state="visible", timeout=5000)
        return drawer

    def _proposal_modal(self) -> Locator:
        modal = self.page.locator(".ant-modal:visible")
        if modal.count():
            modal.last.wait_for(state="visible", timeout=5000)
            return modal.last
        drawer = self.page.locator(".ant-drawer:visible").last
        drawer.wait_for(state="visible", timeout=5000)
        return drawer

    def open_new_policy(self) -> Locator:
        self.select_tab("policy")
        self.page.locator(".ant-table:visible").first.wait_for(state="visible")
        self.page.get_by_role("button", name="新建", exact=True).click()
        return self._policy_drawer()

    def open_policy_section(self, section: str) -> Locator:
        label = self.POLICY_SECTIONS.get(section, section)
        drawer = self._policy_drawer()
        headers = drawer.locator(".ant-collapse-header:visible")
        for index in range(headers.count()):
            header = headers.nth(index)
            if label in " ".join((header.inner_text() or "").split()):
                item = header.locator("xpath=ancestor::*[contains(@class,'ant-collapse-item')][1]")
                if item.count() and "ant-collapse-item-active" not in (
                    item.get_attribute("class") or ""
                ):
                    self._dom_click(header)
                    self.page.wait_for_timeout(120)
                return drawer
        return drawer

    def _click_exact_text(self, root: Locator, text: str) -> bool:
        locator = root.get_by_text(text, exact=True)
        for index in range(locator.count()):
            item = locator.nth(index)
            try:
                if item.is_visible() and item.is_enabled():
                    self._dom_click(item)
                    self.page.wait_for_timeout(80)
                    return True
            except Exception:
                continue
        return False

    @staticmethod
    def _option_key(value: Any) -> str:
        """Normalize display typography without weakening value matching."""
        return " ".join(
            unicodedata.normalize("NFKC", str(value or "")).split()
        ).casefold()

    def _select_by_id(self, root: Locator, field_id: str,
                      option_text: str) -> bool:
        input_locator = root.locator(f"#{field_id}")
        if not input_locator.count():
            return False
        selector = input_locator.first.locator(
            "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '),"
            " ' ant-select-selector ')][1]"
        )
        if not selector.count():
            selector = input_locator.first.locator(
                "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '),"
                " ' ant-select ')][1]"
            ).locator(".ant-select-selector")
        if not selector.count():
            return False
        # rc-select opens on a real mouse/pointer event.  Calling the DOM
        # ``element.click()`` method does not run its selector ``mousedown``
        # handler and therefore leaves ``aria-expanded`` false.
        opened = False
        for _ in range(3):
            try:
                selector.first.click(force=True, timeout=1500)
            except Exception:
                try:
                    selector.first.dispatch_event("mousedown")
                except Exception:
                    pass
            self.page.wait_for_timeout(120)
            if (
                input_locator.first.get_attribute("aria-expanded") == "true"
                or self.page.locator(".ant-select-dropdown:visible").count() > 0
            ):
                opened = True
                break

        # ``aria-controls`` points at the inner virtual listbox.  Resolve its
        # popup ancestor so a closing popup from the previous field cannot be
        # mistaken for the current one.
        popup_id = input_locator.first.get_attribute("aria-controls") or ""
        if popup_id:
            dropdown = self.page.locator(f"#{popup_id}").locator(
                "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '),"
                " ' ant-select-dropdown ')][1]"
            )
        else:
            dropdown = self.page.locator(".ant-select-dropdown:visible").last
        try:
            dropdown.wait_for(state="visible", timeout=3000)
        except Exception as exc:
            fallback = self.page.locator(".ant-select-dropdown:visible")
            if fallback.count():
                dropdown = fallback.last
                opened = True
            else:
                expanded = input_locator.first.get_attribute("aria-expanded")
                raise RuntimeError(
                    f"IPsec下拉框未展开: {field_id}, aria-expanded={expanded}"
                ) from exc
        if not opened and not dropdown.is_visible():
            expanded = input_locator.first.get_attribute("aria-expanded")
            raise RuntimeError(
                f"IPsec下拉框未展开: {field_id}, aria-expanded={expanded}"
            )
        self.page.wait_for_timeout(180)
        options = dropdown.locator(".ant-select-item-option:visible")
        expected_key = self._option_key(option_text)
        for index in range(options.count()):
            option = options.nth(index)
            rendered = " ".join((option.inner_text() or "").split())
            rendered_key = self._option_key(rendered)
            if (
                rendered_key == expected_key
                # The interface selector renders value and device together,
                # for example ``wan1(wan1)``.
                or rendered_key.startswith(f"{expected_key}(")
            ):
                option.click(force=True, timeout=3000)
                try:
                    dropdown.wait_for(state="hidden", timeout=1500)
                except Exception:
                    pass
                self.page.wait_for_timeout(100)
                return True
        self.page.keyboard.press("Escape")
        available = [
            " ".join((options.nth(i).inner_text() or "").split())
            for i in range(options.count())
        ]
        raise RuntimeError(
            f"IPsec下拉选项不存在: {field_id}; available={available[:12]}"
        )

    def _require_select(self, root: Locator, field_id: str,
                        option_text: str):
        try:
            selected = self._select_by_id(root, field_id, option_text)
        except Exception as exc:
            raise RuntimeError(
                f"IPsec字段选择失败: {field_id}; {exc}"
            ) from exc
        if not selected:
            raise RuntimeError(f"IPsec字段选择失败: {field_id}")

    def select_options(self, root: Locator, field_id: str) -> List[str]:
        """Return the visible options for a select without changing its value."""
        input_locator = root.locator(f"#{field_id}")
        if not input_locator.count():
            return []
        selector = input_locator.first.locator(
            "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '),"
            " ' ant-select-selector ')][1]"
        )
        if not selector.count():
            return []
        selector.first.click(force=True, timeout=3000)
        dropdown = self.page.locator(".ant-select-dropdown:visible").last
        dropdown.wait_for(state="visible", timeout=3000)
        self.page.wait_for_timeout(120)
        values = self._visible_unique_text(
            dropdown.locator(".ant-select-item-option:visible")
        )
        self.page.keyboard.press("Escape")
        return values

    def _set_switch(self, root: Locator, label: str, enabled: bool) -> bool:
        items = root.locator(".ant-form-item:visible")
        for index in range(items.count()):
            item = items.nth(index)
            labels = self._visible_unique_text(item.locator(".ant-form-item-label"))
            if not labels or label not in labels[0]:
                continue
            switch = item.locator(".ant-switch:visible,[role=switch]:visible")
            if not switch.count():
                return False
            checked = (
                switch.first.get_attribute("aria-checked") == "true"
                or "ant-switch-checked" in (switch.first.get_attribute("class") or "")
            )
            if checked != enabled:
                self._dom_click(switch.first)
                self.page.wait_for_timeout(100)
            return True
        return False

    def fill_policy_basic(self, *, tagname: str, role: str, addr_type: str,
                          interface: str, remote_addr: str,
                          local_ip: str = "", alias: str = "",
                          comment: str = ""):
        drawer = self.open_policy_section("basic")
        self._replace_input(drawer.locator("#tagname"), tagname)
        if drawer.locator("#alias").count():
            self._replace_input(drawer.locator("#alias"), alias)
        self._click_exact_text(
            drawer, "中心节点" if role == "hub" else "对等/分支节点"
        )
        self._click_exact_text(drawer, "IPv6" if addr_type == "v6" else "IPv4")
        self._require_select(drawer, "interface", interface)
        if drawer.locator("#local_ip").count():
            self._replace_input(drawer.locator("#local_ip"), local_ip)
        if drawer.locator("#remote_addr").count():
            self._replace_input(drawer.locator("#remote_addr"), remote_addr)
        if drawer.locator("#comment").count():
            self._replace_input(drawer.locator("#comment"), comment)

    def fill_policy_ike(self, *, ike_version: str, proposal: str, secret: str,
                        local_id: str, remote_id: str,
                        aggressive: str = "0", prf: Optional[str] = None,
                        local_id_type: str = "IPv4地址",
                        remote_id_type: str = "IPv4地址"):
        drawer = self.open_policy_section("ike")
        register_sensitive_value(secret)
        self._runtime_secrets.add(secret)
        self._click_exact_text(drawer, "V2" if ike_version == "ikev2" else "V1")
        if ike_version == "ikev1":
            self._require_select(
                drawer, "aggressive", "野蛮模式" if aggressive == "1" else "主模式"
            )
        self._replace_input(drawer.locator("#secret"), secret)
        self._require_select(drawer, "ike_proposals", proposal)
        if ike_version == "ikev2" and prf:
            self._require_select(drawer, "prf", prf)
        self._require_select(drawer, "local_id_type", local_id_type)
        self._replace_input(drawer.locator("#local_id"), local_id)
        # Hub mode intentionally hides the remote-ID controls; spoke mode
        # exposes and requires them.
        if drawer.locator("#remote_id_type").count():
            self._require_select(drawer, "remote_id_type", remote_id_type)
        if drawer.locator("#remote_id").count():
            self._replace_input(drawer.locator("#remote_id"), remote_id)

    def add_protected_traffic(self, *, src: str, dst: str,
                              protocol: str = "any",
                              src_port: str = "", dst_port: str = "") -> bool:
        self._last_protected_traffic_errors = []
        drawer = self.open_policy_section("traffic")
        drawer.get_by_role("button", name="添加", exact=True).click()
        modal = self.page.locator(".ant-modal:visible").last
        modal.wait_for(state="visible", timeout=5000)
        self.page.wait_for_timeout(180)
        self._replace_input(modal.locator("#src"), src)
        self._replace_input(modal.locator("#dst"), dst)
        protocol_labels = {
            "any": ("任意", "any"), "ip": ("IP",), "tcp": ("TCP",),
            "udp": ("UDP",), "icmp": ("ICMP",),
        }
        selected = False
        last_error: Optional[Exception] = None
        for label in protocol_labels.get(protocol, (protocol,)):
            try:
                self._require_select(modal, "protocol", label)
                selected = True
                break
            except Exception as exc:
                last_error = exc
        if not selected:
            raise RuntimeError("IPsec保护数据流协议选择失败") from last_error
        if protocol in {"tcp", "udp"}:
            if modal.locator("#src_port").count():
                self._replace_input(modal.locator("#src_port"), src_port)
            if modal.locator("#dst_port").count():
                self._replace_input(modal.locator("#dst_port"), dst_port)
        confirm = modal.get_by_role("button", name="确定", exact=True)
        for _ in range(3):
            try:
                confirm.click(force=True, timeout=1500)
                modal.wait_for(state="hidden", timeout=2500)
                return True
            except Exception:
                self._last_protected_traffic_errors = self._visible_unique_text(
                    modal.locator(".ant-form-item-explain-error:visible")
                )
                if self._last_protected_traffic_errors:
                    break
                self.page.wait_for_timeout(250)

        self._dismiss_overlays()
        return False

    def fill_policy_advanced(self, *, trigger_mode: str = "auto",
                             encap_mode: str = "tunnel",
                             security_proto: str = "esp",
                             esp_auth: str = "SHA256",
                             esp_enc: str = "AES256",
                             ah_auth: str = "SHA256",
                             pfs_group: str = "None",
                             ipsec_sa_time: int = 3600,
                             ipsec_sa_bytes: int = 0,
                             ipsec_sa_idle: int = 0,
                             dpd_enabled: bool = True,
                             dpd_interval: int = 30,
                             dpd_timeout: int = 150,
                             dpd_action: str = "重启"):
        drawer = self.open_policy_section("traffic")
        self._click_exact_text(
            drawer, "自动触发" if trigger_mode == "auto" else "流量触发"
        )
        drawer = self.open_policy_section("advanced")
        self._click_exact_text(
            drawer, "传输模式" if encap_mode == "transport" else "隧道模式"
        )
        self._click_exact_text(drawer, "AH" if security_proto == "ah" else "ESP")
        if security_proto != "ah":
            self._require_select(drawer, "esp_auth", esp_auth)
            self._require_select(drawer, "esp_enc", esp_enc)
        if security_proto != "esp" and drawer.locator("#ah_auth").count():
            self._require_select(drawer, "ah_auth", ah_auth)
        self._require_select(drawer, "pfs_group", pfs_group)
        self._replace_input(drawer.locator("#ipsec_sa_time"), ipsec_sa_time)
        self._replace_input(drawer.locator("#ipsec_sa_bytes"), ipsec_sa_bytes)
        self._replace_input(drawer.locator("#ipsec_sa_idle"), ipsec_sa_idle)
        self._set_switch(drawer, "DPD检测", dpd_enabled)
        if dpd_enabled:
            self._replace_input(drawer.locator("#dpd_interval"), dpd_interval)
            self._replace_input(drawer.locator("#dpd_timeout"), dpd_timeout)
            if drawer.locator("#dpd_action").count():
                self._require_select(drawer, "dpd_action", dpd_action)

    def save_policy(self, action: str = "add") -> Dict[str, Any]:
        drawer = self._policy_drawer()
        return self._submit(
            drawer.get_by_role("button", name="确定", exact=True),
            "ipsec2_policy", action,
        )

    def open_policy_edit(self, tagname: str) -> Locator:
        self.select_tab("policy")
        row = self.find_row(tagname)
        row.get_by_text("编辑", exact=True).click()
        return self._policy_drawer()

    def cancel_policy(self, discard: bool = True) -> Dict[str, Any]:
        drawer = self._policy_drawer()
        drawer.get_by_role("button", name="取消", exact=True).click()
        self.page.wait_for_timeout(100)
        modal = self.page.locator(".ant-modal-confirm:visible,.ant-modal:visible")
        prompted = modal.count() > 0
        if prompted:
            target = "确定" if discard else "取消"
            modal.last.get_by_role("button", name=target, exact=True).click()
        if discard:
            try:
                drawer.wait_for(state="hidden", timeout=5000)
            except Exception:
                pass
        return {
            "discard_prompt": prompted,
            "closed": self.page.locator(".ant-drawer:visible").count() == 0,
        }

    def open_new_proposal(self) -> Locator:
        self.select_tab("proposal")
        self.page.locator(".ant-table:visible").first.wait_for(state="visible")
        self.page.get_by_role("button", name="新建", exact=True).click()
        return self._proposal_modal()

    def fill_proposal(self, *, tagname: str, auth_alg: str = "SHA256",
                      enc_alg: str = "AES256",
                      dh_group: str = "MODP 2048（组14）",
                      sa_lifetime: int = 86400):
        modal = self._proposal_modal()
        self._replace_input(modal.locator("#tagname"), tagname)
        self._require_select(modal, "auth_alg", auth_alg)
        self._require_select(modal, "enc_alg", enc_alg)
        self._require_select(modal, "dh_group", dh_group)
        self._replace_input(modal.locator("#sa_lifetime"), sa_lifetime)

    def save_proposal(self, action: str = "add") -> Dict[str, Any]:
        modal = self._proposal_modal()
        return self._submit(
            modal.get_by_role("button", name="确定", exact=True),
            "ipsec2_proposal", action,
        )

    def open_proposal_edit(self, tagname: str) -> Locator:
        self.select_tab("proposal")
        row = self.find_row(tagname)
        row.get_by_text("编辑", exact=True).click()
        return self._proposal_modal()

    def cancel_proposal(self, discard: bool = True) -> Dict[str, Any]:
        """Cancel a proposal form, including its dirty-form confirmation."""
        root = self._proposal_modal()
        root.get_by_role("button", name="取消", exact=True).click()
        self.page.wait_for_timeout(100)
        confirm = self.page.locator(
            ".ant-modal-confirm:visible,.ant-modal:visible"
        )
        prompted = confirm.count() > 0
        if prompted:
            target = "确定" if discard else "取消"
            confirm.last.get_by_role(
                "button", name=target, exact=True
            ).click()
        if discard:
            try:
                root.wait_for(state="hidden", timeout=5000)
            except Exception:
                pass
        return {
            "discard_prompt": prompted,
            "closed": not root.is_visible(),
        }

    def form_errors(self) -> List[str]:
        return self._visible_unique_text(self.page.locator(
            ".ant-form-item-explain-error:visible,.ant-message-error:visible,"
            ".ant-notification-notice-message:visible"
        ))

    def field_errors(self, field_id: str) -> List[str]:
        field = self.page.locator(f"#{field_id}:visible").first
        if not field.count():
            return []
        item = field.locator(
            "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '),"
            " ' ant-form-item ')][1]"
        )
        return self._visible_unique_text(
            item.locator(".ant-form-item-explain-error:visible")
        )

    def selected_radio_label(self, field_id: str) -> str:
        root = self._policy_drawer()
        radios = root.locator(f"input#{field_id},input[name='{field_id}']")
        for index in range(radios.count()):
            radio = radios.nth(index)
            try:
                if not radio.is_checked():
                    continue
                wrapper = radio.locator(
                    "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '),"
                    " ' ant-radio-wrapper ')][1]"
                )
                if wrapper.count():
                    return " ".join((wrapper.inner_text() or "").split())
                return str(radio.get_attribute("value") or "")
            except Exception:
                continue
        label_hint = {"trigger_mode": "触发模式"}.get(field_id, "")
        if label_hint:
            items = root.locator(".ant-form-item:visible")
            for index in range(items.count()):
                item = items.nth(index)
                labels = self._visible_unique_text(
                    item.locator(".ant-form-item-label:visible")
                )
                if not labels or label_hint not in labels[0]:
                    continue
                selected = item.locator(
                    ".ant-radio-wrapper-checked:visible,"
                    ".ant-segmented-item-selected:visible,"
                    "[role=radio][aria-checked=true]:visible"
                )
                if selected.count():
                    return " ".join((selected.first.inner_text() or "").split())
        return ""

    def find_row(self, value: str) -> Locator:
        return self.page.locator(".ant-table-tbody .ant-table-row").filter(
            has_text=value
        ).first

    def row_exists(self, value: str) -> bool:
        row = self.find_row(value)
        return row.count() > 0 and row.is_visible()

    def row_action(self, value: str, action_text: str,
                   func_name: str, action: str) -> Dict[str, Any]:
        row = self.find_row(value)
        if not row.count() or not row.is_visible():
            return {
                "success": False,
                "error": "row_not_found",
                "value": value,
                "action": action,
            }
        row.get_by_text(action_text, exact=True).click()
        modal = self.page.locator(".ant-modal-confirm:visible,.ant-modal:visible")
        button = (
            modal.last.get_by_role("button", name="确定", exact=True)
            if modal.count() else row.get_by_text(action_text, exact=True)
        )
        if modal.count():
            return self._submit(button, func_name, action)
        return {"success": True, "form_opened": True}

    def delete_policy(self, tagname: str) -> Dict[str, Any]:
        return self.row_action(tagname, "删除", "ipsec2_policy", "del")

    def disable_policy(self, tagname: str) -> Dict[str, Any]:
        return self.row_action(tagname, "停用", "ipsec2_policy", "down")

    def enable_policy(self, tagname: str) -> Dict[str, Any]:
        return self.row_action(tagname, "启用", "ipsec2_policy", "up")

    def delete_proposal(self, tagname: str) -> Dict[str, Any]:
        self.select_tab("proposal")
        return self.row_action(tagname, "删除", "ipsec2_proposal", "del")

    def safe_form_observation(self) -> Dict[str, Any]:
        root = self.page.locator(
            ".ant-modal:visible,.ant-drawer:visible"
        ).last
        fields = []
        for index in range(root.locator("input:visible,textarea:visible").count()):
            item = root.locator("input:visible,textarea:visible").nth(index)
            field_id = item.get_attribute("id") or item.get_attribute("name") or ""
            field_type = item.get_attribute("type") or item.evaluate("e => e.tagName")
            value = ""
            if field_type not in {"radio", "checkbox"}:
                raw = item.input_value()
                value = (
                    {"configured": bool(raw), "length": len(raw)}
                    if field_id.lower() in self.SECRET_FIELDS else raw[:120]
                )
            fields.append({
                "id": field_id,
                "type": field_type,
                "placeholder": item.get_attribute("placeholder") or "",
                "maxlength": item.get_attribute("maxlength"),
                "value": value,
            })
        selects = []
        select_inputs = root.locator("input[role=combobox]")
        for index in range(select_inputs.count()):
            item = select_inputs.nth(index)
            field_id = item.get_attribute("id") or ""
            selector = item.locator(
                "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '),"
                " ' ant-select-selector ')][1]"
            )
            current = ""
            if selector.count():
                selected = selector.first.locator(".ant-select-selection-item")
                if selected.count():
                    current = " ".join((selected.first.inner_text() or "").split())
            selects.append({
                "id": field_id,
                "current": current[:120],
                "expanded": item.get_attribute("aria-expanded") == "true",
            })
        return {
            "labels": self._visible_unique_text(
                root.locator(".ant-form-item-label:visible,label:visible")
            ),
            "fields": fields,
            "selects": selects,
            "radios": self._visible_unique_text(
                root.locator(".ant-radio-wrapper:visible")
            ),
            "switch_labels": self._visible_unique_text(
                root.locator(".ant-form-item:visible").filter(
                    has=root.locator(".ant-switch,[role=switch]")
                ).locator(".ant-form-item-label")
            ),
            "buttons": self._visible_unique_text(root.locator("button:visible")),
        }
