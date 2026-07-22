"""Page object for Advanced Service > Virtual Machine."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from playwright.sync_api import Locator, Page

from pages.base_page import BasePage
from utils.step_recorder import register_sensitive_value


class VirtualMachinePage(BasePage):
    """Operate the real iKuai QEMU list, editor, snapshot, and noVNC pages."""

    MODULE_NAME = "virtual_machine"
    LIST_URL = "/#/advancedService/virtualMachine"
    ADD_URL = "/#/advancedService/virtualMachine/add"
    BACKEND_SCRIPT = "/usr/ikuai/script/qemu.sh"

    OS_OPTIONS = ("Linux", "Windows", "其他")
    NETWORK_MODES = {
        "default": "默认",
        "virtio": "半虚拟化模式",
        "e1000e": "e1000e",
        "vmxnet3": "vmxnet3",
        "passthrough": "PCI直通",
    }
    DISK_TYPES = {
        "new": "新建设备",
        "reference": "引用磁盘",
        "partition": "引用分区",
    }

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page)
        self.base_url = str(base_url or "").rstrip("/")
        self.last_form_error = ""

    # ------------------------------ basics ---------------------------------
    def _wait(self, settle_ms: int = 600):
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(settle_ms)

    @staticmethod
    def _safe_text(value: Any, limit: int = 600) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]

    def _messages(self) -> List[str]:
        selectors = (
            ".ant-message-notice:visible, .ant-notification-notice:visible, "
            ".ant-form-item-explain-error:visible"
        )
        values = []
        for text in self.page.locator(selectors).all_inner_texts():
            cleaned = self._safe_text(text)
            if cleaned and cleaned not in values:
                values.append(cleaned)
        return values

    def _field(self, field_id: str) -> Locator:
        return self.page.locator(f"#{field_id}:visible").first

    def _fill(self, field_id: str, value: Any):
        field = self._field(field_id)
        field.fill(str(value))
        return field

    def _set_checked(self, field_id: str, checked: bool):
        field = self._field(field_id)
        if field.is_checked() != bool(checked):
            field.click(force=True)
            self.page.wait_for_timeout(120)

    def _select(self, field_id: str, option_text: str):
        try:
            self.page.keyboard.press("Escape")
        except Exception:
            pass
        field = self._field(field_id)
        field.click(force=True)
        self.page.wait_for_timeout(120)
        list_id = field.get_attribute("aria-controls") or f"{field_id}_list"
        dropdowns = self.page.locator(".ant-select-dropdown:visible")
        scoped = dropdowns.filter(has=self.page.locator(f"#{list_id}"))
        root = scoped.last if scoped.count() else dropdowns.last
        option = root.locator(".ant-select-item-option").filter(
            has_text=str(option_text)
        )
        if option.count() == 0:
            raise AssertionError(f"select option not found: {field_id} -> {option_text}")
        option.first.click(force=True)
        self.page.wait_for_timeout(120)

    def _select_in(self, root: Locator, field_id: str, option_text: str):
        field = root.locator(f"#{field_id}:visible") if field_id else None
        if field is None or field.count() == 0:
            # Dynamic disk-type select has a generated id.
            select = root.locator(".ant-select:visible").first
            select.click(force=True)
        else:
            field.first.click(force=True)
        self.page.wait_for_timeout(120)
        dropdown = self.page.locator(".ant-select-dropdown:visible").last
        option = dropdown.locator(".ant-select-item-option").filter(
            has_text=str(option_text)
        )
        if option.count() == 0:
            raise AssertionError(f"drawer option not found: {option_text}")
        option.first.click(force=True)
        self.page.wait_for_timeout(120)

    def _visible_overlay(self) -> Locator:
        overlay = self.page.locator(
            ".ant-drawer:visible, .ant-modal:visible"
        )
        return overlay.last

    def _confirm_overlay(self, root: Optional[Locator] = None):
        root = root or self._visible_overlay()
        for label in ("确定", "保存", "确认"):
            button = root.get_by_role("button", name=label, exact=True)
            if button.count() > 0 and button.last.is_visible():
                button.last.click(force=True)
                return
        primary = root.locator("button.ant-btn-primary:visible")
        if primary.count() == 0:
            raise AssertionError("visible confirm button not found")
        primary.last.click(force=True)

    def navigate_to_virtual_machine(self):
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        self._wait(900)
        return self

    def is_list_page(self) -> bool:
        return "/advancedService/virtualMachine" in self.page.url and not any(
            suffix in self.page.url for suffix in ("/add", "/edit", "/snapshot")
        )

    # ------------------------ structure/capabilities -----------------------
    def inspect_list_structure(self) -> Dict[str, Any]:
        headers = [self._safe_text(text) for text in self.page.locator(
            ".ant-table-thead th:visible"
        ).all_inner_texts()]
        buttons = [self._safe_text(text) for text in self.page.locator(
            "button:visible"
        ).all_inner_texts() if self._safe_text(text)]
        return {
            "url": self.page.url,
            "headers": headers,
            "buttons": buttons,
            "row_count": self.page.locator(".ant-table-tbody .ant-table-row:visible").count(),
            "empty_visible": self.page.get_by_text("暂无内容", exact=True).count() > 0,
            "has_pagination": self.page.locator(".ant-pagination:visible").count() > 0,
        }

    def capability_matrix(self) -> Dict[str, Dict[str, Any]]:
        body = self.page.locator("body").inner_text()
        header = " ".join(self.page.locator(".ant-table-thead").all_inner_texts())
        return {
            "add": {"supported": self.page.get_by_role("button", name="添加", exact=True).count() > 0},
            "help": {"supported": self.page.get_by_text("帮助", exact=True).count() > 0},
            "search": {"supported": self.page.locator("input[placeholder='请输入搜索内容']:visible").count() > 0},
            "import": {"supported": "导入" in body},
            "export": {"supported": "导出" in body},
            "batch": {
                "supported": self.page.locator(".ant-table-selection-column:visible").count() > 0,
                "action": "选中行后显示删除按钮",
            },
            "sorting": {"supported": self.page.locator(".ant-table-column-sorters:visible").count() > 0},
            "snapshot": {"supported": True, "available_after_create": True},
            "partition_passthrough": {
                "supported": True,
                "executed": False,
                "reason": "qemu.sh 会 umount 所选物理分区，共享DUT禁止执行",
            },
            "pci_passthrough": {
                "supported": "网卡" in header or True,
                "executed": False,
                "reason": "会解绑物理网卡并可能中断管理链路",
            },
        }

    def inspect_help(self) -> Dict[str, Any]:
        button = self.page.get_by_text("帮助", exact=True)
        if button.count() == 0:
            return {"opened": False, "url": "", "error": "帮助按钮不存在"}
        popup = None
        try:
            with self.page.expect_popup(timeout=5000) as info:
                button.click()
            popup = info.value
            popup.wait_for_load_state("domcontentloaded", timeout=10000)
            return {"opened": True, "url": popup.url}
        except Exception as exc:
            return {"opened": False, "url": "", "error": self._safe_text(exc)}
        finally:
            if popup is not None:
                try:
                    popup.close()
                except Exception:
                    pass

    # ----------------------------- add/edit --------------------------------
    def open_add_page(self) -> bool:
        if not self.is_list_page():
            self.navigate_to_virtual_machine()
        button = self.page.get_by_role("button", name="添加", exact=True)
        if button.count() > 0:
            button.click()
        else:
            self.page.goto(f"{self.base_url}{self.ADD_URL}")
        self._wait(700)
        return self.page.url.endswith("/advancedService/virtualMachine/add")

    def _read_options(self, field_id: str) -> List[str]:
        field = self._field(field_id)
        field.click(force=True)
        self.page.wait_for_timeout(100)
        list_id = field.get_attribute("aria-controls") or f"{field_id}_list"
        listbox = self.page.locator(f"#{list_id}")
        root = listbox.locator("xpath=..") if listbox.count() else self.page.locator(
            ".ant-select-dropdown:visible"
        ).last
        options = [self._safe_text(value) for value in root.locator(
            ".ant-select-item-option"
        ).all_inner_texts()]
        self.page.keyboard.press("Escape")
        return options

    def inspect_add_form(self) -> Dict[str, Any]:
        required_ids = (
            "install_disk", "vm_name", "cpu_usage", "cpu_cores", "mem_size",
            "cdrom_path", "vnc_enabled", "vnc_port", "auto_start",
            "uefi_boot", "hw_accel",
        )
        present = {field: self._field(field).count() > 0 for field in required_ids}
        return {
            "url": self.page.url,
            "fields": present,
            "disk_options": self._read_options("install_disk"),
            "os_options": self._read_options("os_type"),
            "defaults": {
                "os_type": self.page.locator("#os_type").locator("xpath=../..").inner_text(),
                "cpu_usage": self._field("cpu_usage").input_value(),
                "cpu_cores": self._field("cpu_cores").input_value(),
                "vnc_port": self._field("vnc_port").input_value(),
                "auto_start": self._field("auto_start").is_checked(),
                "uefi": self._field("uefi_boot").is_checked(),
            },
        }

    def select_install_disk(self, partname: str):
        self._select("install_disk", partname)

    def default_device_rows(self) -> List[Dict[str, str]]:
        rows = []
        for text in self.page.locator(".ant-table-tbody .ant-table-row:visible").all_inner_texts():
            mac = re.search(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", text, re.I)
            if "网卡" in text and mac:
                cells = [part.strip() for part in text.splitlines() if part.strip()]
                rows.append({"type": "network", "text": " | ".join(cells), "mac": mac.group(0)})
            elif "磁盘" in text:
                rows.append({"type": "disk", "text": self._safe_text(text), "mac": ""})
        return rows

    def _open_device_drawer(self) -> Locator:
        # The form has one solid "添加" button above the device table.
        closing = self.page.locator(".ant-drawer:visible")
        if closing.count() > 0:
            try:
                closing.last.wait_for(state="hidden", timeout=2500)
            except Exception:
                pass
        button = self.page.locator("button.ant-btn-primary:visible").filter(has_text="添加")
        if button.count() == 0:
            raise AssertionError("device add button not found")
        button.first.click()
        self.page.locator(".ant-drawer.ant-drawer-open:visible").wait_for(timeout=5000)
        self.page.wait_for_timeout(180)
        return self.page.locator(".ant-drawer.ant-drawer-open:visible").last

    def _choose_device_type(self, drawer: Locator, device_type: str):
        radio = drawer.locator(f"input[type=radio][value={device_type}]")
        if radio.count() == 0:
            raise AssertionError(f"device type not found: {device_type}")
        radio.evaluate("element => element.click()")
        self.page.wait_for_timeout(150)

    def _wait_drawer_closed(self):
        drawer = self.page.locator(".ant-drawer.ant-drawer-open:visible")
        if drawer.count() > 0:
            try:
                drawer.last.wait_for(state="hidden", timeout=3500)
            except Exception:
                self.page.wait_for_timeout(500)

    def inspect_device_capabilities(self) -> Dict[str, Any]:
        drawer = self._open_device_drawer()
        result: Dict[str, Any] = {}
        for device_type in ("disk", "network", "usb"):
            self._choose_device_type(drawer, device_type)
            result[device_type] = {
                "text": self._safe_text(drawer.inner_text(), 1200),
                "fields": [
                    value for value in drawer.locator("input:visible").evaluate_all(
                        "els=>els.map(e=>e.id||e.value).filter(Boolean)"
                    )
                ],
            }
            if device_type == "usb":
                result[device_type]["available_options"] = self._drawer_options(
                    drawer, "usbDevice"
                )
            elif device_type == "network":
                result[device_type]["modes"] = self._drawer_options(drawer, "networkMode")
                result[device_type]["bridges"] = self._drawer_options(drawer, "bridgeInterface")
            else:
                result[device_type]["disk_types"] = self._drawer_options(drawer, "")
        drawer.get_by_role("button", name="取消", exact=True).click()
        self._wait_drawer_closed()
        return result

    def _drawer_options(self, drawer: Locator, field_id: str) -> List[str]:
        target = drawer.locator(f"#{field_id}:visible") if field_id else drawer.locator(
            ".ant-select:visible"
        ).first
        if target.count() == 0:
            return []
        target.first.click(force=True)
        self.page.wait_for_timeout(100)
        values = [self._safe_text(value) for value in self.page.locator(
            ".ant-select-dropdown:visible .ant-select-item-option"
        ).all_inner_texts()]
        self.page.keyboard.press("Escape")
        return values

    def add_new_disk(self, size_gb: int, disk_name: str, *, virtio: bool = True):
        drawer = self._open_device_drawer()
        self._choose_device_type(drawer, "disk")
        self._select_in(drawer, "", self.DISK_TYPES["new"])
        virt = drawer.locator("#virtio")
        if virt.count() and virt.is_checked() != bool(virtio):
            virt.click(force=True)
        drawer.locator("#diskSpace").fill(str(size_gb))
        drawer.locator("#diskName").fill(str(disk_name))
        self._confirm_overlay(drawer)
        self._wait_drawer_closed()

    def add_reference_disk(self, path: str, *, virtio: bool = True):
        drawer = self._open_device_drawer()
        self._choose_device_type(drawer, "disk")
        self._select_in(drawer, "", self.DISK_TYPES["reference"])
        virt = drawer.locator("#virtio")
        if virt.count() and virt.is_checked() != bool(virtio):
            virt.click(force=True)
        drawer.locator("#diskPath").fill(str(path))
        self._confirm_overlay(drawer)
        self._wait_drawer_closed()

    def add_network(self, bridge: str, mac: str, *, mode: str = "virtio"):
        drawer = self._open_device_drawer()
        self._choose_device_type(drawer, "network")
        self._select_in(drawer, "networkMode", self.NETWORK_MODES[mode])
        self._select_in(drawer, "bridgeInterface", bridge)
        drawer.locator("#mac").fill(mac)
        self._confirm_overlay(drawer)
        self._wait_drawer_closed()

    def inspect_iso_file_manager(self) -> Dict[str, Any]:
        button = self.page.get_by_text("文件管理", exact=True)
        if button.count() == 0:
            return {"opened": False, "text": "", "has_test_image": False}
        popup = None
        try:
            with self.page.expect_popup(timeout=5000) as info:
                button.last.click(force=True)
            popup = info.value
            popup.wait_for_load_state("domcontentloaded", timeout=10000)
            popup.wait_for_timeout(2200)
            text = popup.locator("body").inner_text()
            return {
                "opened": True,
                "url": popup.url,
                "text": self._safe_text(text, 1800),
                "has_888": "888" in text,
                # The disk-management popup proves the file browser route;
                # the ISO itself is verified by qemu-img/SHA in L2.
                "has_test_image": "CorePure64-16.2.iso" in text,
            }
        except Exception as exc:
            return {"opened": False, "text": "", "error": self._safe_text(exc)}
        finally:
            if popup is not None:
                try:
                    popup.close()
                except Exception:
                    pass

    def fill_vm_form(
        self,
        *,
        name: str,
        partname: str = "888",
        system: str = "Linux",
        cpu_usage: int = 50,
        cpu_cores: int = 1,
        memory_mb: int = 256,
        iso_path: str = "",
        vnc_port: int = 5901,
        vnc_external: bool = True,
        vnc_password: str = "",
        auto_start: bool = False,
        uefi: bool = False,
        hardware_accel: bool = True,
    ):
        self.select_install_disk(partname)
        self._fill("vm_name", name)
        self._select("os_type", system)
        self._fill("cpu_usage", cpu_usage)
        self._fill("cpu_cores", cpu_cores)
        self._fill("mem_size", memory_mb)
        self._fill("cdrom_path", iso_path)
        self._fill("vnc_port", vnc_port)
        self._set_checked("vnc_enabled", vnc_external)
        if vnc_external:
            register_sensitive_value(vnc_password)
            password = self.page.locator("#vnc_password:visible")
            if password.count() > 0:
                password.fill(vnc_password)
        self._set_checked("auto_start", auto_start)
        self._set_checked("uefi_boot", uefi)
        accel = self._field("hw_accel")
        if accel.is_enabled():
            self._set_checked("hw_accel", hardware_accel)

    def save_form(self, timeout: int = 30000) -> Dict[str, Any]:
        self.last_form_error = ""
        self.page.get_by_role("button", name="保存", exact=True).click()
        deadline = time.time() + timeout / 1000
        while time.time() < deadline:
            self.page.wait_for_timeout(250)
            messages = self._messages()
            if self.is_list_page():
                self._wait(900)
                return {"success": True, "messages": messages, "url": self.page.url}
            errors = self.page.locator(".ant-form-item-explain-error:visible").all_inner_texts()
            notices = self.page.locator(
                ".ant-message-error:visible, .ant-notification-notice-error:visible"
            ).all_inner_texts()
            if errors or notices:
                self.last_form_error = self._safe_text(" | ".join(errors + notices))
                return {
                    "success": False, "messages": messages,
                    "error": self.last_form_error, "url": self.page.url,
                }
        self.last_form_error = self._safe_text(" | ".join(self._messages())) or "保存超时"
        return {"success": False, "error": self.last_form_error, "url": self.page.url}

    def required_validation(self) -> Dict[str, Any]:
        self.page.get_by_role("button", name="保存", exact=True).click()
        self.page.wait_for_timeout(350)
        errors = [self._safe_text(text) for text in self.page.locator(
            ".ant-form-item-explain-error:visible"
        ).all_inner_texts()]
        return {"blocked": not self.is_list_page(), "errors": errors}

    def validate_field(self, field_id: str, value: Any) -> Dict[str, Any]:
        field = self._field(field_id)
        field.fill(str(value))
        field.press("Tab")
        self.page.wait_for_timeout(200)
        item = self.page.locator(".ant-form-item:visible").filter(has=field)
        errors = [self._safe_text(text) for text in item.locator(
            ".ant-form-item-explain-error:visible"
        ).all_inner_texts()]
        return {
            "field": field_id, "value": str(value), "rejected": bool(errors),
            "errors": errors, "actual_value": field.input_value(),
        }

    def cancel_form(self, *, discard: bool = True) -> Dict[str, Any]:
        cancel = self.page.get_by_role("button", name="取消", exact=True)
        if cancel.count() == 0:
            return {
                "prompted": False, "prompt": "", "discarded": False,
                "url": self.page.url, "error": "当前页面无取消按钮",
            }
        cancel.last.click()
        self.page.wait_for_timeout(250)
        modal = self.page.locator(".ant-modal:visible")
        prompted = modal.count() > 0
        prompt_text = self._safe_text(modal.last.inner_text()) if prompted else ""
        if prompted:
            label = "确定" if discard else "取消"
            target = modal.last.get_by_role("button", name=label, exact=True)
            if target.count():
                target.last.click(force=True)
        self.page.wait_for_timeout(450)
        return {"prompted": prompted, "prompt": prompt_text, "discarded": discard, "url": self.page.url}

    # ---------------------------- list actions -----------------------------
    def _row(self, name: str) -> Locator:
        rows = self.page.locator(".ant-table-tbody .ant-table-row:visible").filter(
            has_text=name
        )
        for index in range(rows.count()):
            row = rows.nth(index)
            cells = row.locator(".ant-table-cell")
            if cells.count() and any(
                cell.inner_text().strip() == name for cell in cells.all()
            ):
                return row
        return rows.first

    def rule_exists(self, name: str) -> bool:
        row = self._row(name)
        return row.count() > 0 and row.is_visible()

    def wait_rule_exists(self, name: str, timeout: int = 12000) -> bool:
        deadline = time.time() + timeout / 1000
        while time.time() < deadline:
            if self.rule_exists(name):
                return True
            self.page.wait_for_timeout(300)
        return False

    def search(self, keyword: str) -> Dict[str, Any]:
        field = self.page.locator("input[placeholder='请输入搜索内容']:visible")
        if field.count() == 0:
            return {"supported": False, "matched": False}
        field.first.fill(str(keyword))
        field.first.press("Enter")
        self.page.wait_for_timeout(650)
        return {
            "supported": True,
            "keyword": str(keyword),
            "matched": self.rule_exists(str(keyword)),
            "rows": self.page.locator(".ant-table-tbody .ant-table-row:visible").count(),
        }

    def clear_search(self):
        field = self.page.locator("input[placeholder='请输入搜索内容']:visible")
        if field.count():
            field.first.fill("")
            field.first.press("Enter")
            self.page.wait_for_timeout(500)

    def batch_delete(self, names: Sequence[str]) -> Dict[str, Any]:
        selected = []
        selection_state = {}
        for name in names:
            row = self._row(name)
            checkbox = row.locator("input[type=checkbox]") if row.count() else None
            if checkbox is not None and checkbox.count():
                checkbox.first.click(force=True)
                self.page.wait_for_timeout(80)
                checked = checkbox.first.is_checked()
                selection_state[name] = checked
                if checked:
                    selected.append(name)
            else:
                selection_state[name] = False
        self.page.wait_for_timeout(180)
        if set(selected) != set(names):
            return {
                "success": False,
                "selected": selected,
                "selection_state": selection_state,
                "error": "未能勾选全部目标行",
            }
        candidates = self.page.locator("button:visible").filter(has_text="删除")
        button = None
        for index in range(candidates.count()):
            candidate = candidates.nth(index)
            if not candidate.evaluate("element => Boolean(element.closest('tr'))"):
                button = candidate
                break
        if button is None:
            return {
                "success": False, "selected": selected,
                "selection_state": selection_state,
                "error": "批量删除按钮未出现",
            }
        button.click(force=True)
        self._confirm_if_present()
        deadline = time.time() + 45
        while time.time() < deadline:
            self.page.wait_for_timeout(500)
            if all(not self.rule_exists(name) for name in names):
                return {
                    "success": True, "selected": selected,
                    "selection_state": selection_state,
                }
        return {
            "success": False, "selected": selected,
            "selection_state": selection_state,
            "error": "批量删除后行仍存在",
        }

    def row_text(self, name: str) -> str:
        row = self._row(name)
        return row.inner_text() if row.count() else ""

    def row_status(self, name: str) -> str:
        row = self._row(name)
        if row.count() == 0:
            return ""
        headers = [self._safe_text(text) for text in self.page.locator(
            ".ant-table-thead th:visible"
        ).all_inner_texts()]
        try:
            index = headers.index("运行状态")
        except ValueError:
            return ""
        cells = row.locator(".ant-table-cell")
        return self._safe_text(cells.nth(index).inner_text()) if cells.count() > index else ""

    def _click_row_action(self, name: str, action: str):
        row = self._row(name)
        if row.count() == 0:
            raise AssertionError(f"virtual-machine row not found: {name}")
        button = row.get_by_role("button", name=action, exact=True)
        if button.count() == 0:
            button = row.locator("button:visible").filter(has_text=action)
        if button.count() == 0:
            raise AssertionError(f"row action not found: {name} -> {action}; row={row.inner_text()}")
        button.first.click(force=True)
        self.page.wait_for_timeout(180)

    def _confirm_if_present(self):
        modal = self.page.locator(".ant-modal:visible")
        if modal.count() > 0:
            self._confirm_overlay(modal.last)

    def wait_row_state(self, name: str, expected: Iterable[str], timeout: int = 45000) -> bool:
        expected = tuple(expected)
        deadline = time.time() + timeout / 1000
        attempt = 0
        while time.time() < deadline:
            text = self.row_status(name)
            if text and any(value in text for value in expected):
                return True
            self.page.wait_for_timeout(700)
            attempt += 1
            # The list does not always poll after graceful shutdown.  Reloading
            # the same read-only route refreshes qemu status without changing it.
            if attempt % 10 == 0:
                self.page.reload()
                self._wait(350)
        return False

    def shutdown(self, name: str, *, force: bool = False) -> Dict[str, Any]:
        action = "强制关机" if force else "关机"
        self._click_row_action(name, action)
        self._confirm_if_present()
        stopped = self.wait_row_state(name, ("已关机", "未运行", "停止"), 50000)
        return {"success": stopped, "status": self.row_status(name), "row": self._safe_text(self.row_text(name))}

    def power_on(self, name: str) -> Dict[str, Any]:
        self._click_row_action(name, "开机")
        self._confirm_if_present()
        running = self.wait_row_state(name, ("运行中", "运行"), 25000)
        return {"success": running, "status": self.row_status(name), "row": self._safe_text(self.row_text(name))}

    def delete_vm(self, name: str) -> Dict[str, Any]:
        self._click_row_action(name, "删除")
        self._confirm_if_present()
        deadline = time.time() + 45
        while time.time() < deadline:
            self.page.wait_for_timeout(500)
            if not self.rule_exists(name):
                return {"success": True}
        return {"success": False, "row": self._safe_text(self.row_text(name))}

    def open_edit(self, name: str) -> bool:
        self._click_row_action(name, "编辑")
        self._wait(600)
        return self.page.url.endswith("/advancedService/virtualMachine/edit")

    def edit_values(self, *, save: bool = True, **values: Any) -> Dict[str, Any]:
        mapping = {
            "name": "vm_name", "cpu_usage": "cpu_usage", "cpu_cores": "cpu_cores",
            "memory_mb": "mem_size", "iso_path": "cdrom_path", "vnc_port": "vnc_port",
        }
        if "system" in values:
            self._select("os_type", str(values["system"]))
        for key, field in mapping.items():
            if key in values and self._field(field).is_enabled():
                self._fill(field, values[key])
        for key, field in (
            ("vnc_external", "vnc_enabled"), ("auto_start", "auto_start"),
            ("uefi", "uefi_boot"), ("hardware_accel", "hw_accel"),
        ):
            if key in values and self._field(field).is_enabled():
                self._set_checked(field, bool(values[key]))
        if values.get("vnc_external") and "vnc_password" in values:
            register_sensitive_value(values["vnc_password"])
            password = self.page.locator("#vnc_password:visible")
            if password.count():
                password.fill(str(values["vnc_password"]))
        if save:
            return self.save_form()
        return {"success": True, "saved": False, "url": self.page.url}

    # ----------------------------- snapshots -------------------------------
    def open_snapshot(self, name: str) -> bool:
        self._click_row_action(name, "快照")
        self._wait(500)
        return self.page.url.endswith("/advancedService/virtualMachine/snapshot")

    def create_snapshot(self, snapshot_name: str) -> Dict[str, Any]:
        buttons = self.page.locator("button:visible").filter(
            has_text=re.compile("添加|创建|新建")
        )
        if buttons.count() == 0:
            return {"success": False, "error": "未找到创建快照按钮"}
        buttons.first.click(force=True)
        self.page.wait_for_timeout(250)
        modal = self.page.locator(".ant-modal:visible")
        if modal.count() == 0:
            return {"success": False, "error": "创建快照弹窗未出现"}
        # afterOpenChange fills a generated default name after mount.  Wait for
        # that callback before replacing it with the requested deterministic name.
        self.page.wait_for_timeout(800)
        field = modal.last.locator("input:visible").first
        field.fill(snapshot_name)
        self._confirm_overlay(modal.last)
        try:
            modal.last.wait_for(state="hidden", timeout=50000)
        except Exception:
            pass
        self.page.reload()
        self._wait(800)
        return {
            "success": self.page.get_by_text(snapshot_name, exact=True).count() > 0,
            "messages": self._messages(),
        }

    def snapshot_action(self, snapshot_name: str, action: str) -> Dict[str, Any]:
        row = self.page.locator(".ant-table-tbody .ant-table-row:visible").filter(
            has_text=snapshot_name
        ).first
        if row.count() == 0:
            return {"success": False, "error": "快照行不存在"}
        labels = ("应用", "开机") if action == "apply" else ("删除",)
        button = row.locator("button[data-snapshot-action-not-found='1']")
        for label in labels:
            candidate = row.get_by_role("button", name=label, exact=True)
            if candidate.count() == 0:
                candidate = row.locator("button:visible").filter(has_text=label)
            if candidate.count():
                button = candidate
                break
        if button.count() == 0:
            return {"success": False, "error": f"未找到快照操作按钮: {labels}"}
        button.first.click(force=True)
        self._confirm_if_present()
        # Applying/deleting a snapshot invokes qemu.sh normal-stop and can take
        # up to 30 seconds before the API promise resolves.
        try:
            self.page.locator(".ant-modal:visible").last.wait_for(
                state="hidden", timeout=50000
            )
        except Exception:
            pass
        self.page.reload()
        self._wait(800)
        exists = self.page.get_by_text(snapshot_name, exact=True).count() > 0
        return {"success": exists if action == "apply" else not exists, "messages": self._messages()}

    def back_to_list(self):
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        self._wait(600)

    # ------------------------------- noVNC ---------------------------------
    def inspect_novnc_framebuffer(
        self,
        port: int,
        password: str,
        *,
        timeout: int = 20000,
    ) -> Dict[str, Any]:
        register_sensitive_value(password)
        console = self.page.context.new_page()
        try:
            console.goto(f"{self.base_url}/vnc/index.html?{int(port)}")
            console.wait_for_timeout(1200)
            password_input = console.locator("#noVNC_password_input")
            if password_input.count() and password_input.is_visible():
                password_input.fill(password)
                console.locator("#noVNC_password_button").click()
            deadline = time.time() + timeout / 1000
            while time.time() < deadline and console.locator("canvas").count() == 0:
                console.wait_for_timeout(300)
            canvas = console.locator("canvas").first
            if canvas.count() == 0:
                status = console.locator("#noVNC_status").inner_text()
                return {"connected": False, "status": self._safe_text(status), "non_black": 0}
            stats = {}
            while time.time() < deadline:
                stats = canvas.evaluate(
                    """canvas => {
                    const ctx = canvas.getContext('2d');
                    const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
                    let nonBlack = 0, sum = 0;
                    for (let i = 0; i < data.length; i += 4) {
                        sum += data[i] + data[i + 1] + data[i + 2];
                        if (data[i] || data[i + 1] || data[i + 2]) nonBlack++;
                    }
                    return {width: canvas.width, height: canvas.height,
                            non_black: nonBlack,
                            average_rgb: sum / Math.max(1, data.length / 4 * 3)};
                    }"""
                )
                if stats.get("non_black", 0) > 500:
                    break
                console.wait_for_timeout(500)
            status = console.locator("#noVNC_status").inner_text()
            return {
                "connected": stats["width"] > 0 and stats["height"] > 0,
                "status": self._safe_text(status),
                **stats,
            }
        finally:
            console.close()


__all__ = ["VirtualMachinePage"]
