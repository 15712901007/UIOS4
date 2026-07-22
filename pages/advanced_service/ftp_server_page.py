"""
高级服务 > 本地服务 > FTP服务 Page Object。

页面特点：
- 列表 ``/#/advancedService/localService``，默认为 FTP Tab。
- 新增/编辑是独立路由 ``.../ftp/add|edit``。
- 列表顶部有 FTP 总开关；设置是自定义 drawer，含端口和外网访问开关。
- 用户表是虚拟表格 ``div.ant-table-row``，支持 CRUD、搜索、导入导出和批量操作。
- ``home_dir`` 是 Ant TreeSelect，需先展开分区根节点再选目录。

本类直接继承 :class:`IkuaiTablePage`，保留通用导入/导出行为，
并对 FTP 特有路由、drawer、TreeSelect、精确行定位和批量操作做稳定封装。
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from playwright.sync_api import Page

from pages.ikuai_table_page import IkuaiTablePage


class FtpServerPage(IkuaiTablePage):
    """FTP 服务页面操作类。"""

    MODULE_NAME = "ftp_server"
    IMPORT_REQUIRES_CLEAR_GUARD = True
    LIST_URL = "/#/advancedService/localService"
    ADD_URL = "/#/advancedService/localService/ftp/add"
    EDIT_FRAGMENT = "/advancedService/localService/ftp/edit"

    PERMISSION_UI = {"rw": "读写", "ro": "只读"}

    def __init__(self, page: Page, base_url: str = ""):
        super().__init__(page, base_url)

    # ==================== 导航 / 默认结构 ====================
    def _wait_page(self, settle_ms: int = 800):
        try:
            self.page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        self.page.wait_for_timeout(settle_ms)

    def _dismiss_transient_overlays(self):
        """只关闭可取消的浮层，不自动点危险的确认按钮。"""
        try:
            self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(200)
        except Exception:
            pass
        try:
            cancel = self.page.locator(
                ".ant-modal-wrap:visible button:has-text('取消'):visible, "
                ".ant-drawer:visible button:has-text('取消'):visible"
            )
            if cancel.count() > 0:
                cancel.last.click(timeout=1500)
                self.page.wait_for_timeout(300)
        except Exception:
            pass

    def navigate_to_ftp_server(self):
        """导航到本地服务列表并确保 FTP Tab 激活。"""
        self._dismiss_transient_overlays()
        self.page.goto(f"{self.base_url}{self.LIST_URL}")
        self._wait_page(1500)
        self.switch_to_ftp_tab()
        return self

    # 简短别名，便于交互式调试。
    navigate_to_ftp = navigate_to_ftp_server

    def switch_to_ftp_tab(self) -> bool:
        """切换到 FTP 服务 Tab。新固件默认已在该 Tab，无 Tab DOM 时按页面特征判定。"""
        try:
            tabs = self.page.locator(".ant-tabs-tab:visible").filter(has_text="FTP")
            if tabs.count() > 0:
                tab = tabs.first
                classes = tab.get_attribute("class") or ""
                if "ant-tabs-tab-active" not in classes:
                    tab.click()
                    self.page.wait_for_timeout(1000)
                return True
            return (
                "advancedService/localService" in self.page.url
                and self.page.locator("button.ant-switch:visible").count() > 0
                and self.page.get_by_placeholder("请输入搜索内容").count() > 0
            )
        except Exception as exc:
            print(f"[DEBUG] switch_to_ftp_tab: {str(exc)[:80]}")
            return False

    def _settings_button(self):
        candidates = self.page.locator(
            "button[class*='settingButton']:visible, "
            "[class*='_settingButton_']:visible, "
            "button[title*='设置']:visible, "
            "button[aria-label*='设置']:visible"
        )
        if candidates.count() > 0:
            return candidates.first
        try:
            self.page.evaluate("""() => {
                document.querySelectorAll('[data-ftp-settings-button]').forEach(e => e.removeAttribute('data-ftp-settings-button'));
                const buttons=[...document.querySelectorAll('button')].filter(b=>b.offsetParent!==null);
                const btn=buttons.find(b =>
                    b.querySelector("svg[data-icon='setting'], .anticon-setting") ||
                    /\u8bbe\u7f6e/.test((b.title||'')+(b.getAttribute('aria-label')||'')+(b.textContent||''))
                );
                if(btn) btn.setAttribute('data-ftp-settings-button','1');
            }""")
        except Exception:
            pass
        return self.page.locator("[data-ftp-settings-button='1']").first

    def get_default_structure(self) -> Dict:
        """读取列表默认结构，供测试对 URL/Tab/按钮/表头/开关做硬断言。"""
        try:
            data = self.page.evaluate("""() => {
                const visible=e=>!!(e && e.offsetParent!==null);
                const buttons=[...document.querySelectorAll('button')]
                    .filter(visible).map(b=>(b.innerText||b.textContent||'').replace(/\\s+/g,'').trim()).filter(Boolean);
                const tables=[...document.querySelectorAll('.ant-table')].filter(visible);
                const table=tables[0]||null;
                const headers=table ? [...table.querySelectorAll('.ant-table-thead .ant-table-cell, thead th')]
                    .map(h=>(h.innerText||'').replace(/\\s+/g,'').trim()).filter(Boolean) : [];
                const ftpTabs=[...document.querySelectorAll('.ant-tabs-tab')]
                    .filter(visible).filter(t=>(t.innerText||'').toUpperCase().includes('FTP'));
                return {
                    buttons, headers,
                    table_present: !!table,
                    switch_present: [...document.querySelectorAll('button.ant-switch')].some(visible),
                    search_present: [...document.querySelectorAll("input[placeholder='请输入搜索内容']")].some(visible),
                    ftp_tab_present: ftpTabs.length > 0,
                    ftp_tab_active: ftpTabs.some(t=>t.classList.contains('ant-tabs-tab-active'))
                };
            }""")
        except Exception:
            data = {}
        data["url_ok"] = "advancedService/localService" in self.page.url
        try:
            data["settings_present"] = self._settings_button().count() > 0
        except Exception:
            data["settings_present"] = False
        # 个别固件 FTP 是页内默认内容，不渲染 tabs DOM。
        if not data.get("ftp_tab_present"):
            data["ftp_tab_active"] = bool(data.get("switch_present") and data.get("search_present"))
        return data

    # ==================== 总开关 ====================
    def _global_switch(self):
        try:
            self.page.evaluate("""() => {
                document.querySelectorAll('[data-ftp-global-switch]').forEach(e=>e.removeAttribute('data-ftp-global-switch'));
                const switches=[...document.querySelectorAll('button.ant-switch')].filter(e=>e.offsetParent!==null);
                const sw=switches.find(e=>!e.closest('.ant-drawer,.ant-modal,.ant-table-row,form')) || switches[0];
                if(sw) sw.setAttribute('data-ftp-global-switch','1');
            }""")
        except Exception:
            pass
        return self.page.locator("[data-ftp-global-switch='1']").first

    @staticmethod
    def _switch_checked(locator) -> Optional[bool]:
        try:
            return bool(locator.evaluate("""el => {
                const sw=el.matches('.ant-switch') ? el : el.closest('.ant-switch');
                const input=el.matches('input[type=checkbox]') ? el : el.querySelector('input[type=checkbox]');
                if(input) return !!input.checked;
                if(sw) return sw.getAttribute('aria-checked')==='true' || sw.classList.contains('ant-switch-checked');
                return false;
            }"""))
        except Exception:
            return None

    def get_service_enabled(self) -> Optional[bool]:
        sw = self._global_switch()
        if sw.count() == 0:
            return None
        return self._switch_checked(sw)

    def set_service_enabled(self, enabled: bool) -> bool:
        """将 FTP 总开关设到指定状态，并兼容关闭确认弹窗。"""
        try:
            sw = self._global_switch()
            if sw.count() == 0:
                return False
            current = self._switch_checked(sw)
            if current is enabled:
                return True
            sw.click()
            self.page.wait_for_timeout(500)
            # 有些版本关闭服务有二次确认。
            if self.page.locator(".ant-modal-wrap:visible").count() > 0:
                self._click_visible_confirm(timeout=2500)
            for _ in range(15):
                self.page.wait_for_timeout(300)
                state = self.get_service_enabled()
                if state is enabled:
                    return True
            return False
        except Exception as exc:
            print(f"[DEBUG] set_service_enabled({enabled}): {str(exc)[:80]}")
            return False

    # ==================== FTP 设置 drawer ====================
    def open_settings(self) -> bool:
        try:
            btn = self._settings_button()
            if btn.count() == 0:
                return False
            btn.click()
            port = self.page.locator("#ftp_port").first
            port.wait_for(state="visible", timeout=5000)
            # Drawer 先渲染空表单，再异步写入 ftp_status；仅等 visible 会把
            # port="" / access=False 误当真实快照。等端口值落稳后再返回。
            for _ in range(15):
                try:
                    if (port.input_value() or "").strip():
                        break
                except Exception:
                    pass
                self.page.wait_for_timeout(150)
            return True
        except Exception as exc:
            print(f"[DEBUG] open_settings: {str(exc)[:80]}")
            return False

    def _access_control(self):
        return self.page.locator("#ftp_access").first

    def get_settings(self) -> Dict:
        result = {"port": None, "access": None}
        try:
            port = self.page.locator("#ftp_port").first
            if port.count() > 0:
                result["port"] = port.input_value()
            access = self._access_control()
            if access.count() > 0:
                result["access"] = self._switch_checked(access)
        except Exception:
            pass
        return result

    def fill_ftp_port(self, port) -> bool:
        try:
            inp = self.page.locator("#ftp_port").first
            if inp.count() == 0:
                return False
            inp.click()
            inp.fill("")
            if str(port) != "":
                inp.type(str(port), delay=30)
            inp.evaluate("el=>{el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('blur',{bubbles:true}));}")
            return True
        except Exception as exc:
            print(f"[DEBUG] fill_ftp_port: {str(exc)[:80]}")
            return False

    def set_ftp_access(self, enabled: bool) -> bool:
        try:
            ctl = self._access_control()
            if ctl.count() == 0:
                return False
            current = self._switch_checked(ctl)
            if current is enabled:
                return True
            ctl.evaluate("""el => {
                const target=el.matches('.ant-switch') ? el :
                    (el.closest('.ant-switch') || el.closest('label') || el.parentElement || el);
                target.click();
            }""")
            self.page.wait_for_timeout(400)
            return self._switch_checked(ctl) is enabled
        except Exception as exc:
            print(f"[DEBUG] set_ftp_access({enabled}): {str(exc)[:80]}")
            return False

    def get_form_error(self) -> Optional[str]:
        """读取当前配置页/drawer 的校验或 API 错误。"""
        selectors = [
            ".ant-form-item-explain-error:visible",
            ".ant-message-error:visible",
            ".ant-notification-notice-error:visible",
            ".ant-alert-error:visible",
        ]
        for selector in selectors:
            try:
                loc = self.page.locator(selector)
                if loc.count() > 0:
                    text = (loc.first.inner_text() or "").strip()
                    if text:
                        return text[:160]
            except Exception:
                continue
        try:
            if self.page.locator(".ant-form-item-has-error:visible, .ant-input-status-error:visible").count() > 0:
                return "输入格式错误"
        except Exception:
            pass
        return None

    def save_settings(self, timeout: int = 7000) -> Dict:
        result = {"success": False, "error": ""}
        try:
            save = self.page.locator("button:visible").filter(has_text="保存")
            if save.count() == 0:
                result["error"] = "设置层未找到保存按钮"
                return result
            save.last.click()
            for _ in range(max(1, timeout // 300)):
                self.page.wait_for_timeout(300)
                err = self.get_form_error()
                if err:
                    result["error"] = err
                    return result
                port = self.page.locator("#ftp_port")
                if port.count() == 0 or not port.first.is_visible():
                    result["success"] = True
                    return result
            result["error"] = "保存后设置层仍未关闭"
        except Exception as exc:
            result["error"] = str(exc)[:120]
        return result

    def cancel_settings(self) -> bool:
        try:
            cancel = self.page.locator("button:visible").filter(has_text="取消")
            if cancel.count() > 0:
                cancel.last.click()
            else:
                self.page.keyboard.press("Escape")
            self.page.wait_for_timeout(400)
            return True
        except Exception:
            return False

    def set_settings(self, port: int, access: bool) -> Dict:
        result = {"success": False, "error": ""}
        # 上一个非法端口保存会留下短暂 ant-message-error；若立即打开新 drawer，
        # save_settings 会把旧 toast 误判成这次合法保存失败。
        for _ in range(14):
            try:
                transient = self.page.locator(
                    ".ant-message-error:visible, "
                    ".ant-notification-notice-error:visible"
                )
                if transient.count() == 0:
                    break
            except Exception:
                break
            self.page.wait_for_timeout(250)
        if not self.open_settings():
            result["error"] = "打开 FTP 设置失败"
            return result
        if not self.fill_ftp_port(port):
            result["error"] = "填写 FTP 端口失败"
            self.cancel_settings()
            return result
        if not self.set_ftp_access(access):
            result["error"] = "设置外网访问失败"
            self.cancel_settings()
            return result
        return self.save_settings()

    def try_invalid_port(self, value) -> Dict:
        """尝试保存非法端口；留在 drawer/显示错误即视为被拦截。"""
        result = {"blocked": False, "error": ""}
        if not self.open_settings():
            result["error"] = "打开设置失败"
            return result
        self.fill_ftp_port(value)
        save = self.save_settings(timeout=2500)
        still_open = False
        try:
            still_open = self.page.locator("#ftp_port:visible").count() > 0
        except Exception:
            pass
        result["blocked"] = bool((not save["success"]) and still_open)
        result["error"] = save.get("error", "") or ("保存被阻止" if still_open else "非法端口被接受")
        if still_open:
            self.cancel_settings()
        return result

    # ==================== 新增/编辑配置页 ====================
    def open_add_page(self) -> bool:
        self._dismiss_transient_overlays()
        try:
            self.page.goto(f"{self.base_url}{self.LIST_URL}")
            self._wait_page(500)
        except Exception:
            pass
        self.page.goto(f"{self.base_url}{self.ADD_URL}")
        self._wait_page(1200)
        return self.is_on_config_page()

    def is_on_config_page(self) -> bool:
        url = self.page.url
        route_ok = "/advancedService/localService/ftp/add" in url or self.EDIT_FRAGMENT in url
        try:
            return route_ok and self.page.locator("#username").count() > 0
        except Exception:
            return route_ok

    def is_still_on_config_page(self) -> bool:
        return self.is_on_config_page()

    def get_user_form_structure(self) -> Dict:
        """读取新增/编辑页关键字段结构，不读取密码等表单值。"""
        result = {
            "username_present": False,
            "password_present": False,
            "permission_present": False,
            "home_dir_present": False,
            "upload_present": False,
            "download_present": False,
            "username_maxlength": None,
        }
        for field in ("username", "passwd", "permission", "home_dir", "upload", "download"):
            try:
                locator = self.page.locator(f"#{field}").first
                present = locator.count() > 0 and locator.is_visible()
            except Exception:
                present = False
            key = "password_present" if field == "passwd" else f"{field}_present"
            result[key] = present
        try:
            maxlength = self.page.locator("#username").first.get_attribute("maxlength")
            result["username_maxlength"] = int(maxlength) if maxlength is not None else None
        except (TypeError, ValueError):
            result["username_maxlength"] = None
        except Exception:
            pass
        return result

    def get_username_value(self) -> str:
        """读取用户名输入框当前值，用于验证浏览器 ``maxlength`` 截断。"""
        try:
            return self.page.locator("#username").first.input_value()
        except Exception:
            return ""

    def cancel_user_form(self) -> bool:
        """取消新增/编辑，不提交表单，并确认回到 FTP 列表。"""
        try:
            cancel = self.page.get_by_role("button", name="取消", exact=True)
            if cancel.count() > 0:
                cancel.first.click()
                self.page.wait_for_timeout(500)
                if self.page.locator(".ant-modal-wrap:visible").count() > 0:
                    self._click_visible_confirm(timeout=3000)
                    self.page.wait_for_timeout(500)
            else:
                self.page.goto(f"{self.base_url}{self.LIST_URL}")
                self._wait_page(500)
            return not self.is_still_on_config_page()
        except Exception:
            try:
                self.page.goto(f"{self.base_url}{self.LIST_URL}")
                self._wait_page(500)
                return not self.is_still_on_config_page()
            except Exception:
                return False

    def _fill_by_id(self, field_id: str, value) -> bool:
        try:
            inp = self.page.locator(f"#{field_id}").first
            if inp.count() == 0:
                return False
            inp.click()
            inp.fill("")
            if value is not None and str(value) != "":
                # type 比单纯 fill 更稳定地触发 React onChange。
                inp.type(str(value), delay=20)
            inp.evaluate("el=>{el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));el.dispatchEvent(new Event('blur',{bubbles:true}));}")
            return True
        except Exception as exc:
            print(f"[DEBUG] fill #{field_id}: {str(exc)[:80]}")
            return False

    def fill_username(self, username: str) -> bool:
        return self._fill_by_id("username", username)

    def fill_password(self, password: str) -> bool:
        # 严禁在此方法打印/format password。
        return self._fill_by_id("passwd", password)

    def set_permission(self, permission: str) -> bool:
        ui_text = self.PERMISSION_UI.get(permission, permission)
        try:
            ctl = self.page.locator("#permission").first
            if ctl.count() == 0:
                return False
            # Ant Select 的透明 search input 会被当前 selection item 覆盖；直接点
            # input 会等满 Playwright 默认 30s 后才回退。点击 selector 才是稳定入口。
            selector = self.page.locator(
                ".ant-select:has(#permission) .ant-select-selector:visible"
            ).first
            selector.click(timeout=4000)
            self.page.wait_for_timeout(500)
            clicked = self.page.evaluate("""({ui, code}) => {
                const dds=[...document.querySelectorAll('.ant-select-dropdown')].filter(d=>d.offsetParent!==null);
                const dd=dds[dds.length-1]; if(!dd) return false;
                const opts=[...dd.querySelectorAll('.ant-select-item-option')];
                const target=opts.find(o=>{
                    const t=(o.innerText||o.textContent||'').replace(/\\s+/g,'').trim();
                    return t===ui || t.includes(ui) || t.toLowerCase()===code || t.toLowerCase().includes('('+code+')');
                });
                if(!target) return false; target.click(); return true;
            }""", {"ui": ui_text, "code": permission})
            self.page.wait_for_timeout(350)
            return bool(clicked)
        except Exception as exc:
            print(f"[DEBUG] set_permission({permission}): {str(exc)[:80]}")
            return False

    def _mark_tree_node(self, title: str) -> bool:
        try:
            return bool(self.page.evaluate("""title => {
                document.querySelectorAll('[data-ftp-tree-node]').forEach(e=>e.removeAttribute('data-ftp-tree-node'));
                const dds=[...document.querySelectorAll('.ant-select-dropdown')].filter(d=>d.offsetParent!==null);
                const dd=dds[dds.length-1]; if(!dd) return false;
                const rows=[...dd.querySelectorAll('.ant-select-tree-treenode,.ant-tree-treenode')].filter(e=>e.offsetParent!==null);
                const norm=s=>(s||'').replace(/\\s+/g,'').trim();
                let row=rows.find(r=>{
                    const c=r.querySelector('.ant-select-tree-node-content-wrapper,.ant-tree-node-content-wrapper,[title]');
                    const attr=c?.getAttribute('title')||'';
                    const txt=c?.innerText||c?.textContent||'';
                    return attr===title || norm(txt)===norm(title);
                });
                if(!row) row=rows.find(r=>norm(r.innerText)===norm(title));
                if(!row) return false;
                row.setAttribute('data-ftp-tree-node','1'); return true;
            }""", title))
        except Exception:
            return False

    def select_home_dir(self, path: str) -> bool:
        """选择目录，例如 ``/666/ftp_t_suite``。"""
        try:
            ctl = self.page.locator("#home_dir").first
            if ctl.count() == 0:
                return False
            # 编辑页已有选中项时 search input 同样会被 selection item 覆盖。
            selector = self.page.locator(
                ".ant-select:has(#home_dir) .ant-select-selector:visible"
            ).first
            selector.click(timeout=4000)
            self.page.wait_for_timeout(700)
            parts = [p for p in str(path).replace("\\", "/").split("/") if p]
            if not parts:
                return False
            for part in parts[:-1]:
                if not self._mark_tree_node(part):
                    return False
                row = self.page.locator("[data-ftp-tree-node='1']").first
                expanded = row.get_attribute("aria-expanded")
                if expanded is None:
                    try:
                        expanded = row.locator("[aria-expanded]").first.get_attribute("aria-expanded")
                    except Exception:
                        expanded = None
                if expanded != "true":
                    switcher = row.locator(".ant-select-tree-switcher, .ant-tree-switcher").first
                    if switcher.count() > 0:
                        switcher.click()
                        self.page.wait_for_timeout(700)
            if not self._mark_tree_node(parts[-1]):
                return False
            row = self.page.locator("[data-ftp-tree-node='1']").first
            content = row.locator(".ant-select-tree-node-content-wrapper, .ant-tree-node-content-wrapper, [title]").first
            if content.count() > 0:
                content.click()
            else:
                row.click()
            self.page.wait_for_timeout(500)
            return True
        except Exception as exc:
            print(f"[DEBUG] select_home_dir: {str(exc)[:80]}")
            return False

    def fill_upload(self, value) -> bool:
        return self._fill_by_id("upload", value)

    def fill_download(self, value) -> bool:
        return self._fill_by_id("download", value)

    def fill_user_form(
        self,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        permission: Optional[str] = None,
        home_dir: Optional[str] = None,
        upload: Optional[str] = None,
        download: Optional[str] = None,
    ) -> bool:
        checks: List[bool] = []
        if username is not None:
            checks.append(self.fill_username(username))
        if password is not None:
            checks.append(self.fill_password(password))
        if permission is not None:
            checks.append(self.set_permission(permission))
        if home_dir is not None:
            checks.append(self.select_home_dir(home_dir))
        if upload is not None:
            checks.append(self.fill_upload(upload))
        if download is not None:
            checks.append(self.fill_download(download))
        return bool(checks) and all(checks)

    def save_user(self, timeout: int = 9000) -> Dict:
        result = {"success": False, "error": ""}
        try:
            self.page.keyboard.press("Escape")
            save = self.page.get_by_role("button", name="保存")
            if save.count() == 0:
                result["error"] = "未找到保存按钮"
                return result
            save.first.click()
            for _ in range(max(1, timeout // 300)):
                self.page.wait_for_timeout(300)
                err = self.get_form_error()
                if err:
                    result["error"] = err
                    return result
                if not self.is_still_on_config_page():
                    result["success"] = True
                    self.page.wait_for_timeout(500)
                    return result
            result["error"] = "保存后仍在 FTP 用户配置页"
        except Exception as exc:
            result["error"] = str(exc)[:120]
        return result

    save_and_wait = save_user

    def add_user(
        self,
        username: str,
        password: str,
        permission: str,
        home_dir: str,
        upload: str = "0",
        download: str = "0",
    ) -> Dict:
        result = {"success": False, "error": ""}
        try:
            if not self.open_add_page():
                result["error"] = "进入 FTP 新增页失败"
                return result
            if not self.fill_user_form(
                username=username,
                password=password,
                permission=permission,
                home_dir=home_dir,
                upload=upload,
                download=download,
            ):
                result["error"] = "FTP 用户表单填写不完整"
                return result
            return self.save_user()
        except Exception as exc:
            result["error"] = str(exc)[:120]
            return result

    # 兼容项目中其他表格 Page Object 的命名。
    add_rule = add_user

    def try_add_invalid(
        self,
        *,
        username: str,
        password: str,
        permission: Optional[str] = "rw",
        home_dir: Optional[str] = None,
        upload: Optional[str] = "0",
        download: Optional[str] = "0",
    ) -> Dict:
        result = {"blocked": False, "error": ""}
        if not self.open_add_page():
            result["error"] = "进入新增页失败"
            return result
        # 空字符串也要显式填写，以触发 required 校验。
        self.fill_username(username)
        self.fill_password(password)
        if permission is not None:
            self.set_permission(permission)
        if home_dir is not None:
            self.select_home_dir(home_dir)
        if upload is not None:
            self.fill_upload(upload)
        if download is not None:
            self.fill_download(download)
        save = self.save_user(timeout=3000)
        result["blocked"] = not save["success"] and self.is_still_on_config_page()
        result["error"] = save.get("error", "") or ("保存被阻止" if result["blocked"] else "非法数据被接受")
        return result

    # ==================== 精确行 CRUD ====================
    def _row_for_user(self, username: str):
        rows = self.page.locator("div.ant-table-row")
        try:
            for idx in range(rows.count()):
                row = rows.nth(idx)
                cells = row.locator(".ant-table-cell")
                texts = [(cells.nth(i).inner_text() or "").strip() for i in range(cells.count())]
                if username in texts:
                    return row
        except Exception:
            pass
        return self.page.locator("div.ant-table-row").filter(has_text=username).first

    def rule_exists(self, username: str) -> bool:
        try:
            self.page.wait_for_timeout(300)
            row = self._row_for_user(username)
            if row.count() == 0 or not row.is_visible():
                return False
            cells = row.locator(".ant-table-cell")
            return any((cells.nth(i).inner_text() or "").strip() == username for i in range(cells.count()))
        except Exception:
            return False

    user_exists = rule_exists

    def is_user_enabled(self, username: str) -> bool:
        """行内有“停用”按钮表示当前已启用。"""
        try:
            row = self._row_for_user(username)
            if row.count() == 0:
                return False
            return any(
                (row.locator("button:visible").nth(i).inner_text() or "").strip() == "停用"
                for i in range(row.locator("button:visible").count())
            )
        except Exception:
            return False

    def is_user_disabled(self, username: str) -> bool:
        """行内有“启用”按钮表示当前已停用。"""
        try:
            row = self._row_for_user(username)
            if row.count() == 0:
                return False
            return any(
                (row.locator("button:visible").nth(i).inner_text() or "").strip() == "启用"
                for i in range(row.locator("button:visible").count())
            )
        except Exception:
            return False

    is_rule_enabled = is_user_enabled
    is_rule_disabled = is_user_disabled

    def get_rule_names(self) -> List[str]:
        try:
            return self.page.evaluate("""() => {
                const out=[];
                for(const row of document.querySelectorAll('div.ant-table-row')){
                    const cells=[...row.querySelectorAll('.ant-table-cell')]
                        .map(c=>(c.innerText||'').trim()).filter(Boolean);
                    const name=cells.find(t=>/^[A-Za-z0-9_.-]{1,15}$/.test(t));
                    if(name) out.push(name);
                }
                return [...new Set(out)];
            }""")
        except Exception:
            return []

    def _click_user_action(self, username: str, action: str) -> bool:
        try:
            row = self._row_for_user(username)
            if row.count() == 0:
                return False
            buttons = row.locator("button:visible").filter(has_text=action)
            for idx in range(buttons.count()):
                btn = buttons.nth(idx)
                if (btn.inner_text() or "").strip() == action:
                    btn.click()
                    return True
            return bool(self._click_rule_button(username, action))
        except Exception as exc:
            print(f"[DEBUG] {username} {action}: {str(exc)[:80]}")
            return False

    def edit_user(self, username: str) -> bool:
        if not self._click_user_action(username, "编辑"):
            return False
        for _ in range(15):
            self.page.wait_for_timeout(300)
            if self.is_on_config_page() and self.EDIT_FRAGMENT in self.page.url:
                return True
        return False

    edit_rule = edit_user

    def update_user(
        self,
        username: str,
        *,
        password: Optional[str] = None,
        permission: Optional[str] = None,
        home_dir: Optional[str] = None,
        upload: Optional[str] = None,
        download: Optional[str] = None,
    ) -> Dict:
        if not self.edit_user(username):
            return {"success": False, "error": "进入编辑页失败"}
        if not self.fill_user_form(
            password=password,
            permission=permission,
            home_dir=home_dir,
            upload=upload,
            download=download,
        ):
            return {"success": False, "error": "编辑表单填写失败"}
        return self.save_user()

    def disable_rule(self, username: str) -> bool:
        if not self._click_user_action(username, "停用"):
            return False
        self.page.wait_for_timeout(500)
        if self.page.locator(".ant-modal-wrap:visible").count() > 0:
            if not self._click_visible_confirm(timeout=3500):
                return False
        self.page.wait_for_timeout(1000)
        return True

    def enable_rule(self, username: str) -> bool:
        if not self._click_user_action(username, "启用"):
            return False
        self.page.wait_for_timeout(1000)
        return True

    def delete_rule(self, username: str) -> bool:
        if not self._click_user_action(username, "删除"):
            return False
        self.page.wait_for_timeout(500)
        if not self._click_visible_confirm(timeout=3500):
            return False
        for _ in range(12):
            self.page.wait_for_timeout(350)
            if not self.rule_exists(username):
                return True
        try:
            self.page.reload()
            self._wait_page(900)
            self.switch_to_ftp_tab()
        except Exception:
            pass
        return not self.rule_exists(username)

    delete_user = delete_rule

    def clean_test_rules(self, prefix: str = "ftp_t_") -> int:
        """只逐条删除测试前缀用户，绝不全选或误删存量用户。"""
        deleted = 0
        for _ in range(50):
            names = [n for n in self.get_rule_names() if n.startswith(prefix)]
            if not names:
                break
            if not self.delete_rule(names[0]):
                break
            deleted += 1
            self.page.wait_for_timeout(300)
        return deleted

    # ==================== 搜索 / 批量 ====================
    def search_user(self, keyword: str):
        return self.search_rule(keyword)

    def clear_user_search(self):
        return self.clear_search()

    def _clear_body_selection(self):
        try:
            self.page.evaluate("""() => {
                for(const cb of document.querySelectorAll('div.ant-table-row input[type=checkbox]:checked')) cb.click();
            }""")
            self.page.wait_for_timeout(250)
        except Exception:
            pass

    def _select_users(self, usernames: Iterable[str]) -> int:
        self._clear_body_selection()
        selected = 0
        for username in usernames:
            try:
                row = self._row_for_user(username)
                if row.count() == 0:
                    continue
                ok = bool(row.evaluate("""row => {
                    const cb=row.querySelector('input[type=checkbox]');
                    if(!cb) return false; if(!cb.checked) cb.click(); return true;
                }"""))
                if ok:
                    selected += 1
                    self.page.wait_for_timeout(200)
            except Exception:
                continue
        self.page.wait_for_timeout(500)
        return selected

    def _click_batch_action(self, action: str) -> bool:
        try:
            return bool(self.page.evaluate("""action => {
                const visible=e=>e.offsetParent!==null;
                const exact=b=>(b.innerText||b.textContent||'').replace(/\\s+/g,'').trim()===action;
                const footers=[...document.querySelectorAll('div.footer')].filter(visible);
                for(const f of footers){
                    const b=[...f.querySelectorAll('button')].find(x=>visible(x)&&exact(x));
                    if(b){b.click();return true;}
                }
                const buttons=[...document.querySelectorAll('button')].filter(b=>visible(b)&&exact(b));
                const b=buttons.find(x=>!x.closest('.ant-table-row,.ant-drawer,.ant-modal'));
                if(!b) return false; b.click(); return true;
            }""", action))
        except Exception:
            return False

    def _after_batch(self):
        self.page.wait_for_timeout(1200)
        try:
            self.page.reload()
            self._wait_page(900)
            self.switch_to_ftp_tab()
        except Exception:
            pass

    def batch_disable_users(self, usernames: Iterable[str]) -> bool:
        names = list(usernames)
        if self._select_users(names) != len(names):
            return False
        if not self._click_batch_action("停用"):
            return False
        self.page.wait_for_timeout(500)
        if not self._click_visible_confirm(timeout=3500):
            return False
        self._after_batch()
        return True

    def batch_enable_users(self, usernames: Iterable[str]) -> bool:
        names = list(usernames)
        if self._select_users(names) != len(names):
            return False
        if not self._click_batch_action("启用"):
            return False
        self._after_batch()
        return True

    def batch_delete_users(self, usernames: Iterable[str]) -> bool:
        names = list(usernames)
        if self._select_users(names) != len(names):
            return False
        if not self._click_batch_action("删除"):
            return False
        self.page.wait_for_timeout(500)
        if not self._click_visible_confirm(timeout=3500):
            return False
        self._after_batch()
        return True

    # ==================== 右下角帮助 ====================
    def verify_help_entry(self, timeout: int = 8000) -> Dict:
        """
        验证右下角帮助入口。

        真实 UI 会打开新 popup，外网正文是否加载不影响入口验收；
        本方法断言所需的 URL 信息并始终关闭 popup，避免 GUI 长跑产生孤儿 Tab。
        """
        result = {"clicked": False, "popup_opened": False, "url": "", "no_orphan": False}
        before = len(self.page.context.pages)
        popup = None
        try:
            buttons = self.page.locator("button:visible").filter(has_text="帮助")
            if buttons.count() == 0:
                return result
            result["clicked"] = True
            with self.page.expect_popup(timeout=timeout) as info:
                buttons.first.click()
            popup = info.value
            result["popup_opened"] = popup is not None
            if popup is not None:
                for _ in range(20):
                    url = popup.url or ""
                    if url and url != "about:blank":
                        break
                    popup.wait_for_timeout(200)
                result["url"] = popup.url or ""
        except Exception as exc:
            result["error"] = str(exc)[:120]
        finally:
            try:
                if popup is not None and not popup.is_closed():
                    popup.close()
            except Exception:
                pass
            self.page.wait_for_timeout(300)
            result["no_orphan"] = len(self.page.context.pages) <= before
        return result
